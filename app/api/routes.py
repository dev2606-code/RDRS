import os
import csv
import io
import hmac
import xml.etree.ElementTree as ET
from threading import Lock

from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, Request, Response

from app.attribution.windows import WindowsProcessAttributionProvider
from app.core.rdrs_service import RDRSService
from app.core.auth import (
    create_session,
    set_session_cookie,
    clear_session_cookie,
    verify_password,
    require_auth,
    check_origin,
    login_rate_limited,
    record_login_failure,
    clear_login_failures,
)

router = APIRouter(prefix="/api", tags=["RDRS"])

sysmon_provider = WindowsProcessAttributionProvider()
sysmon_ingest_lock = Lock()

service = RDRSService(
    attribution_provider=sysmon_provider,
)
class SysmonEventRequest(BaseModel):
    xml_event: str = Field(min_length=1, max_length=65536)


class IncidentUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=32)
    notes: str = Field(default="", max_length=2000)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)

def _parse_record_id(value):
    if value is None:
        return None

    try:
        record_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid Sysmon EventRecordID") from exc

    if record_id < 0:
        raise ValueError("Invalid Sysmon EventRecordID")

    return record_id
def parse_sysmon_event(xml_event: str):
    try:
        root = ET.fromstring(xml_event)
    except ET.ParseError as exc:
        raise ValueError("Invalid Sysmon event XML") from exc

    system = next(
        (
            element
            for element in root.iter()
            if element.tag.rsplit("}", 1)[-1] == "System"
        ),
        None,
    )

    if system is None:
        raise ValueError("Sysmon event is missing its System element")

    values = {
        element.tag.rsplit("}", 1)[-1]: element.text
        for element in system
    }

    event_id = values.get("EventID")
    if not event_id:
        raise ValueError("Sysmon event is missing EventID")

    try:
        event_id = int(event_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid Sysmon EventID") from exc

    # RDRS currently supports Sysmon Event IDs 1 and 11 only.
    if event_id not in (1, 11):
        return None

    return {
        "event_id": event_id,
        "computer": values.get("Computer"),
        "channel": values.get("Channel"),
        "record_id": (
            int(values["EventRecordID"])
            if values.get("EventRecordID") is not None
            else None
        ),
    }


@router.post("/login")
def login(data: LoginRequest, request: Request, response: Response):
    check_origin(request)

    if login_rate_limited(data.username):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": "900"},
        )

    expected_username = os.getenv("RDRS_USERNAME", "")
    password_hash = os.getenv("RDRS_PASSWORD_HASH", "")

    if not expected_username or not password_hash:
        raise HTTPException(
            status_code=503,
            detail="Authentication is not configured",
        )

    username_valid = hmac.compare_digest(
        data.username,
        expected_username,
    )
    password_valid = verify_password(
        data.password,
        password_hash,
    )

    if not username_valid or not password_valid:
        record_login_failure(data.username)
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    clear_login_failures(data.username)
    token = create_session(data.username)
    set_session_cookie(response, token)

    return {"message": "Login successful"}


@router.post("/logout")
def logout(request: Request, response: Response):
    check_origin(request)
    clear_session_cookie(response)
    return {"message": "Logged out successfully"}


@router.get("/health")
def health():
    return {"status": "healthy", "service": "RDRS"}


@router.get("/status")
def status(request: Request):
    require_auth(request)
    return {
        "service": "RDRS",
        "monitoring": "running" if service._running else "stopped",
        "sandbox": str(service.sandbox),
        "mode": "sandbox_only",
    }


@router.get("/events")
def events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
):
    require_auth(request)
    return {"events": service.list_events(limit)}


def create_test_event(request: Request):
    check_origin(request)
    require_auth(request)

    test_file = (service.sandbox / "rdrs_safe_test.txt").resolve()

    if not test_file.is_relative_to(service.sandbox):
        raise HTTPException(
            status_code=400,
            detail="Test file must stay inside the sandbox",
        )

    try:
        test_file.write_text(
            "Harmless RDRS sandbox test data.",
            encoding="utf-8",
        )

        result = service.process_event({
            "action": "created",
            "path": str(test_file),
        })

        return {
            "message": "Safe sandbox test event recorded",
            **result,
        }

    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


if os.getenv("RDRS_ENABLE_TEST_ENDPOINT", "").lower() == "true":
    router.add_api_route(
        "/test-event",
        create_test_event,
        methods=["POST"],
    )


@router.get("/alerts")
def alerts(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
):
    require_auth(request)
    records = service.list_events(limit)
    alert_records = []

    for record in records:
        score = record.get("risk_score", 0)

        if score < 20:
            continue

        if score >= 70:
            severity = "critical"
            recommendation = "Investigate immediately and verify the file."
        elif score >= 40:
            severity = "high"
            recommendation = "Review the file activity and related events."
        else:
            severity = "medium"
            recommendation = "Review the event and confirm it is expected."

        alert_records.append({
            **record,
            "severity": severity,
            "confidence_score": record.get("confidence_score", 10),
            "confidence_level": record.get("confidence_level", "low"),
            "recommendation": recommendation,
        })

    return {"alerts": alert_records}


@router.post("/monitor/start")
def start_monitor(request: Request):
    check_origin(request)
    require_auth(request)

    try:
        service.start()
        return {"message": "Sandbox monitoring started"}
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


@router.post("/monitor/stop")
def stop_monitor(request: Request):
    check_origin(request)
    require_auth(request)
    service.stop()
    return {"message": "Sandbox monitoring stopped"}


@router.get("/incidents")
def list_incidents(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
):
    require_auth(request)
    return {"incidents": service.database.list_incidents(limit)}


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    request: Request,
):
    check_origin(request)
    require_auth(request)

    try:
        incident = service.database.update_incident(
            incident_id=incident_id,
            status=update.status,
            notes=update.notes,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "message": "Incident updated successfully",
        "incident": incident,
    }


@router.post("/sysmon/events")
def ingest_sysmon_event(
    payload: SysmonEventRequest,
    request: Request,
):
    check_origin(request)
    require_auth(request)

    try:
        parsed = parse_sysmon_event(payload.xml_event)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    if parsed is None:
        return {
            "accepted": False,
            "duplicate": False,
            "message": "Unsupported Sysmon event ID",
        }

    computer = parsed.get("computer")
    channel = parsed.get("channel")
    record_id = parsed.get("record_id")

    if not computer or not channel or record_id is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "Sysmon event is missing required identity fields: "
                "Computer, Channel, EventRecordID"
            ),
        )

    with sysmon_ingest_lock:
        if service.database.has_sysmon_event(
            computer,
            channel,
            record_id,
        ):
            return {
                "accepted": True,
                "duplicate": True,
                "event_id": parsed["event_id"],
                "message": "Sysmon event already processed",
                "correlated_metadata": None,
            }

        try:
            result = sysmon_provider.ingest_sysmon_event(
                payload.xml_event
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail=str(exc),
            ) from exc


        try:
            recorded = service.database.record_sysmon_event(
                computer=computer,
                channel=channel,
                record_id=record_id,
                event_id=parsed["event_id"],
            )
        except RuntimeError as exc:
            raise HTTPException(
                status_code=500,
                detail="Failed to record Sysmon event receipt",
            ) from exc

        if not recorded:
            return {
                "accepted": True,
                "duplicate": True,
                "event_id": parsed["event_id"],
                "message": "Sysmon event already processed",
                "correlated_metadata": None,
            }

    return {
        "accepted": True,
        "duplicate": False,
        "event_id": parsed["event_id"],
        "message": "Sysmon event processed successfully",
        "correlated_metadata": result,
    }

@router.get("/reports")
def generate_report(
    request: Request,
    report_format: str = Query(default="json", alias="format"),
):
    require_auth(request)

    if report_format not in ("json", "csv"):
        raise HTTPException(
            status_code=400,
            detail="Format must be json or csv",
        )

    incidents = service.database.list_incidents(limit=1000)

    if report_format == "json":
        return {
            "report": "RDRS Incident Report",
            "total_incidents": len(incidents),
            "incidents": incidents,
        }

    output = io.StringIO()
    fields = [
        "incident_id", "incident_status", "event_id",
        "timestamp", "path", "action", "risk_score",
        "severity", "confidence_score", "confidence_level",
        "process_id", "process_name", "process_path",
        "username", "reasons", "indicators", "notes",
    ]

    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(incidents)

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rdrs_report.csv"},
    )
