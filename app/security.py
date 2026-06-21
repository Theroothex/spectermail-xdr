import secrets
import time
from pathlib import Path
from typing import Iterable

from flask import abort, current_app, request, session
from werkzeug.utils import secure_filename


_RATE_BUCKETS: dict[str, list[float]] = {}


def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf() -> None:
    expected = session.get("_csrf_token")
    supplied = request.form.get("_csrf_token", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        current_app.logger.warning(
            "CSRF validation failed from %s",
            request.remote_addr,
        )
        abort(400, "Invalid form token")


def enforce_rate_limit(limit: int = 20, window_seconds: int = 300) -> None:
    identity = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    identity = identity.split(",", 1)[0].strip()
    now = time.time()
    window_start = now - window_seconds
    bucket = [
        timestamp
        for timestamp in _RATE_BUCKETS.get(identity, [])
        if timestamp > window_start
    ]
    if len(bucket) >= limit:
        current_app.logger.warning("Rate limit exceeded for %s", identity)
        abort(429, "Too many analysis requests. Please wait and try again.")
    bucket.append(now)
    _RATE_BUCKETS[identity] = bucket


def safe_upload_name(raw_filename: str, allowed_extensions: Iterable[str]) -> str:
    filename = secure_filename(raw_filename or "")
    suffix = Path(filename).suffix.lower()
    if not filename or suffix not in set(allowed_extensions):
        abort(400, "Unsupported or invalid upload filename")
    return filename


def ensure_child_path(parent: str, child_name: str) -> Path:
    parent_path = Path(parent).resolve()
    parent_path.mkdir(parents=True, exist_ok=True)
    child_path = (parent_path / child_name).resolve()
    if parent_path not in child_path.parents and child_path != parent_path:
        abort(400, "Invalid filesystem path")
    return child_path
