import os
from dotenv import load_dotenv

load_dotenv()
import hmac
import hashlib
import secrets
import time

from collections import OrderedDict, deque
from threading import Lock

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import HTTPException, Request, status
from fastapi.responses import Response


SESSION_COOKIE = "rdrs_session"
SESSION_DURATION = 8 * 60 * 60

password_hasher = PasswordHasher()
ALLOWED_ORIGINS = {
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5501",
    "http://127.0.0.1:5502",
    "http://localhost:5502",
    "https://rdas-frontend.onrender.com",
}
# Login rate limiting
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_TRACKED_USERNAMES = 10_000

_login_failures = OrderedDict()
_login_lock = Lock()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, ValueError, TypeError):
        return False


def check_origin(request: Request) -> None:
    origin = request.headers.get("origin")

    # Allow clients that do not send Origin.
    if origin and origin not in ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=403,
            detail="Origin not allowed",
        )


def _prune_failures(now: float) -> None:
    """Remove expired username entries and expired attempts."""
    expired_keys = []

    for key, failures in _login_failures.items():
        while failures and now - failures[0] > LOGIN_WINDOW_SECONDS:
            failures.popleft()

        if not failures:
            expired_keys.append(key)

    for key in expired_keys:
        _login_failures.pop(key, None)


def login_rate_limited(username: str) -> bool:
    key = username.strip().lower()
    now = time.monotonic()

    with _login_lock:
        failures = _login_failures.get(key)

        if not failures:
            return False

        while failures and now - failures[0] > LOGIN_WINDOW_SECONDS:
            failures.popleft()

        if not failures:
            _login_failures.pop(key, None)
            return False

        return len(failures) >= LOGIN_MAX_ATTEMPTS


def record_login_failure(username: str) -> None:
    key = username.strip().lower()
    now = time.monotonic()

    with _login_lock:
        _prune_failures(now)

        failures = _login_failures.get(key)

        if failures is None:
            # Prevent unbounded username-based memory growth.
            if len(_login_failures) >= MAX_TRACKED_USERNAMES:
                _login_failures.popitem(last=False)

            failures = deque()
            _login_failures[key] = failures
        else:
            # Keep recently used usernames toward the end.
            _login_failures.move_to_end(key)

        failures.append(now)


def clear_login_failures(username: str) -> None:
    key = username.strip().lower()

    with _login_lock:
        _login_failures.pop(key, None)


def _get_secret() -> str:
    secret = os.getenv("RDRS_SESSION_SECRET", "")

    if len(secret) < 32:
        raise RuntimeError(
            "RDRS_SESSION_SECRET must be at least 32 characters"
        )

    return secret


def _sign(data: str) -> str:
    return hmac.new(
        _get_secret().encode(),
        data.encode(),
        hashlib.sha256,
    ).hexdigest()


def create_session(username: str) -> str:
    if not username or ":" in username:
        raise ValueError("Invalid session username")

    expires = int(time.time()) + SESSION_DURATION
    nonce = secrets.token_urlsafe(16)

    payload = f"{username}:{expires}:{nonce}"
    signature = _sign(payload)

    return f"{payload}:{signature}"


def verify_session(token: str) -> bool:
    try:
        if not isinstance(token, str) or len(token) > 2048:
            return False

        username, expires, nonce, signature = token.split(":", 3)

        if not username or not nonce or not signature:
            return False

        if not expires.isdigit():
            return False

        if len(signature) != 64:
            return False

        if int(expires) <= int(time.time()):
            return False

        payload = f"{username}:{expires}:{nonce}"
        expected_signature = _sign(payload)

        return hmac.compare_digest(
            signature,
            expected_signature,
        )

    except (ValueError, TypeError):
        return False


def require_auth(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE)

    if not token or not verify_session(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return token.split(":", 1)[0]


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_DURATION,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )