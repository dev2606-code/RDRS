import os
from pathlib import Path
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query

from app.core.rdrs_service import RDRSService

router = APIRouter(prefix="/api", tags=["RDRS"])

service = RDRSService()

class IncidentUpdate(BaseModel):
    status: str
    notes: str = ""


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
