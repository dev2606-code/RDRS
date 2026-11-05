
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


def test_service_uses_null_provider_by_default(tmp_path):
    from app.core.rdrs_service import RDRSService

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "sample.txt"
    sample.write_text("Harmless test data.", encoding="utf-8")

    service = RDRSService(
        sandbox_directory=str(sandbox),
        database_path=str(tmp_path / "events.db"),
    )

    result = service.process_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["process_id"] is None
    assert result["process_name"] is None
    assert result["process_path"] is None
    assert result["username"] is None


def test_service_uses_injected_attribution_provider(tmp_path):
    from app.core.rdrs_service import RDRSService

    class TestProvider:
        def get_process_metadata(self, event):
            return {
                "process_id": 1234,
                "process_name": "test-process",
                "process_path": "/test/process",
                "username": "test-user",
            }

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "sample.txt"
    sample.write_text("Harmless test data.", encoding="utf-8")

    service = RDRSService(
        sandbox_directory=str(sandbox),
        database_path=str(tmp_path / "events.db"),
        attribution_provider=TestProvider(),
    )

    result = service.process_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["process_id"] == 1234
    assert result["process_name"] == "test-process"
    assert result["process_path"] == "/test/process"
    assert result["username"] == "test-user"


def test_service_continues_when_attribution_provider_fails(tmp_path):
    from app.core.rdrs_service import RDRSService

    class FailingProvider:
        def get_process_metadata(self, event):
            raise RuntimeError("Synthetic provider failure")

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    sample = sandbox / "sample.txt"
    sample.write_text("Harmless test data.", encoding="utf-8")

    service = RDRSService(
        sandbox_directory=str(sandbox),
        database_path=str(tmp_path / "events.db"),
        attribution_provider=FailingProvider(),
    )

    result = service.process_event({
        "path": str(sample),
        "action": "created",
    })

    assert result["event_id"] == 1
    assert result["status"] == "needs_review"
    assert result["process_id"] is None
    assert result["process_name"] is None
    assert result["process_path"] is None
    assert result["username"] is None
    assert len(service.list_events()) == 1
