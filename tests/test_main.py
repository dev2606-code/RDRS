import importlib
import app.main


def test_docs_enabled_in_local_mode(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)

    importlib.reload(app.main)

    assert app.main.app.docs_url == "/docs"
    assert app.main.app.redoc_url == "/redoc"
    assert app.main.app.openapi_url == "/openapi.json"


def test_docs_disabled_in_production_mode(monkeypatch):
    monkeypatch.setenv("RENDER", "true")

    importlib.reload(app.main)

    assert app.main.app.docs_url is None
    assert app.main.app.redoc_url is None
    assert app.main.app.openapi_url is None

    # Restore local mode for any later tests.
    monkeypatch.delenv("RENDER", raising=False)
    importlib.reload(app.main)
