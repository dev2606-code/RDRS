import time

import pytest
from fastapi import HTTPException
from fastapi.responses import Response
from starlette.requests import Request

from app.core import auth


@pytest.fixture(autouse=True)
def isolated_auth(monkeypatch):
    monkeypatch.setenv(
        "RDRS_SESSION_SECRET",
        "test-secret-key-for-rdrs-authentication-123456789",
    )
    with auth._login_lock:
        auth._login_failures.clear()

    yield

    with auth._login_lock:
        auth._login_failures.clear()


def make_request(headers=None, cookies=None):
    headers = dict(headers or {})

    if cookies:
        headers["cookie"] = "; ".join(
            f"{key}={value}" for key, value in cookies.items()
        )

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (key.lower().encode(), value.encode())
            for key, value in headers.items()
        ],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "scheme": "https",
    }

    return Request(scope)


# PASSWORD TESTS

def test_password_verification():
    hashed = auth.password_hasher.hash("CorrectPassword123!")

    assert auth.verify_password("CorrectPassword123!", hashed) is True
    assert auth.verify_password("wrong-password", hashed) is False
    assert auth.verify_password("anything", "invalid-hash") is False


# SESSION TESTS

def test_create_and_verify_session():
    token = auth.create_session("test-user")

    assert auth.verify_session(token) is True

    request = make_request(
        cookies={auth.SESSION_COOKIE: token}
    )

    assert auth.require_auth(request) == "test-user"


def test_session_rejects_colon_in_username():
    with pytest.raises(ValueError):
        auth.create_session("invalid:user")


def test_session_rejects_tampered_signature():
    token = auth.create_session("test-user")
    parts = token.split(":", 3)

    parts[-1] = (
        "0" if parts[-1][0] != "0" else "1"
    ) + parts[-1][1:]

    tampered_token = ":".join(parts)

    assert auth.verify_session(tampered_token) is False


def test_session_rejects_expired_token():
    token = auth.create_session("test-user")
    username, expires, nonce, signature = token.split(":", 3)

    expired = str(int(time.time()) - 1)
    payload = f"{username}:{expired}:{nonce}"
    expired_token = f"{payload}:{auth._sign(payload)}"

    assert auth.verify_session(expired_token) is False


@pytest.mark.parametrize(
    "token",
    [
        "",
        "bad",
        "user:abc:nonce:signature",
        "user:123:nonce:short",
        "user:123::" + "a" * 64,
        "x" * 2049,
        None,
    ],
)
def test_session_rejects_malformed_tokens(token):
    assert auth.verify_session(token) is False


def test_require_auth_rejects_missing_session():
    with pytest.raises(HTTPException) as exc:
        auth.require_auth(make_request())

    assert exc.value.status_code == 401


def test_require_auth_rejects_invalid_session():
    request = make_request(
        cookies={auth.SESSION_COOKIE: "invalid-token"}
    )

    with pytest.raises(HTTPException) as exc:
        auth.require_auth(request)

    assert exc.value.status_code == 401


# RATE LIMIT TESTS

def test_login_rate_limit_and_clear():
    username = "test-user"

    assert auth.login_rate_limited(username) is False

    for _ in range(auth.LOGIN_MAX_ATTEMPTS):
        auth.record_login_failure(username)

    assert auth.login_rate_limited(username) is True

    auth.clear_login_failures(username)

    assert auth.login_rate_limited(username) is False


def test_login_rate_limit_expires(monkeypatch):
    now = [1000.0]

    monkeypatch.setattr(
        auth.time,
        "monotonic",
        lambda: now[0],
    )

    auth.record_login_failure("test-user")

    now[0] += auth.LOGIN_WINDOW_SECONDS + 1

    assert auth.login_rate_limited("test-user") is False


# ORIGIN TESTS

def test_origin_check_allows_missing_origin():
    auth.check_origin(make_request())


def test_origin_check_allows_trusted_origin():
    trusted_origin = next(iter(auth.ALLOWED_ORIGINS))

    request = make_request(
        headers={"origin": trusted_origin}
    )

    auth.check_origin(request)


def test_origin_check_rejects_unknown_origin():
    request = make_request(
        headers={"origin": "https://evil.example"}
    )

    with pytest.raises(HTTPException) as exc:
        auth.check_origin(request)

    assert exc.value.status_code == 403


# COOKIE TESTS

def test_session_cookie_security_flags():
    token = auth.create_session("test-user")
    response = Response()

    auth.set_session_cookie(response, token)

    header = response.headers["set-cookie"].lower()

    assert "httponly" in header
    assert "secure" in header
    assert "samesite=lax" in header
    assert "path=/" in header


def test_clear_session_cookie():
    response = Response() 

    auth.clear_session_cookie(response)

    header = response.headers["set-cookie"].lower()

    assert "rdrs_session=" in header
    assert "httponly" in header
    assert "secure" in header
    assert "samesite=lax" in header