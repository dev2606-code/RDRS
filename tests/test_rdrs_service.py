
def test_service_analyzes_and_stores_sandbox_event(tmp_path):
    from app.core.rdrs_service import RDRSService

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "sample.txt"
    sample.write_text("Harmless RDRS test data.", encoding="utf-8")

    service = RDRSService(
        sandbox_directory=str(sandbox),
        database_path=str(tmp_path / "events.db"),
    )

    result = service.process_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["event_id"] == 1
    assert result["status"] == "needs_review"
    assert len(service.list_events()) == 1
