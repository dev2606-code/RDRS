
import os
from pathlib import Path
from threading import Lock

from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query

from app.attribution.windows import WindowsProcessAttributionProvider
from app.core.rdrs_service import RDRSService


router = APIRouter(prefix="/api", tags=["RDRS"])

sysmon_provider = WindowsProcessAttributionProvider()
sysmon_ingest_lock = Lock()

service = RDRSService(
    attribution_provider=sysmon_provider,
)


class SysmonEventRequest(BaseModel):
    xml_event: str

@router.get("/health")
def health():
    return {"status": "healthy", "service": "RDRS"}


@router.get("/status")
def status():
    return {
        "service": "RDRS",
        "monitoring": "running" if service._running else "stopped",
        "sandbox": str(service.sandbox),
        "mode": "sandbox_only",
    }

@router.get("/events")
def events(limit: int = Query(default=100, ge=1, le=1000)):
    return {"events": service.list_events(limit)}

@router.post("/test-event")
def create_test_event():
    # Keep this endpoint disabled in production unless explicitly enabled.
    if os.getenv("RDRS_ENABLE_TEST_ENDPOINT") != "true":
        raise HTTPException(
            status_code=404,
            detail="Test endpoint is disabled",
        )

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



@router.get("/alerts")
def alerts(limit: int = Query(default=100, ge=1, le=1000)):
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
def start_monitor():
    try:
        service.start()
        return {"message": "Sandbox monitoring started"}
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/monitor/stop")
def stop_monitor():
    service.stop()
    return {"message": "Sandbox monitoring stopped"}

@router.get("/incidents")
def list_incidents(limit: int = Query(default=100, ge=1, le=1000)):
    return {"incidents": service.database.list_incidents(limit)}


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, update: IncidentUpdate):
    try:
        incident = service.database.update_incident(
            incident_id=incident_id,
            status=update.status,
            notes=update.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {"message": "Incident updated successfully", "incident": incident}

@router.post("/sysmon/events")
def ingest_sysmon_event(payload: SysmonEventRequest):
    from app.attribution.sysmon_parser import parse_sysmon_event

    try:
        parsed = parse_sysmon_event(payload.xml_event)

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

            result = sysmon_provider.ingest_sysmon_event(
                payload.xml_event
            )

            recorded = service.database.record_sysmon_event(
                computer=computer,
                channel=channel,
                record_id=record_id,
                event_id=parsed["event_id"],
            )

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

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
