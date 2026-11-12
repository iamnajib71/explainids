"""Console sign-in: salted password hashes, signed session tokens and a login rate limit.

Standard library only. Accounts come from the environment (`EXPLAINIDS_USERS`, one `name:hash` pair per comma),
hashes from `python scripts/hash_password.py`; nothing is stored in the repository.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

ITERATIONS = 310_000  # OWASP Password Storage Cheat Sheet figure for PBKDF2-HMAC-SHA256
SESSION_SECONDS = 8 * 3600


def hash_password(password: str, iterations: int = ITERATIONS) -> str:
    """`pbkdf2_sha256$iterations$salt$digest`, salt and digest URL-safe base64."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, digest = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), _unb64(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, _unb64(digest))


def parse_users(spec: str | None) -> dict[str, str]:
    """`alice:pbkdf2_sha256$...,bob:...` -> {name: hash}. Malformed entries are ignored."""
    users = {}
    for entry in (spec or "").split(","):
        name, _, stored = entry.strip().partition(":")
        if name and stored.startswith("pbkdf2_sha256$"):
            users[name] = stored
    return users


def issue_token(user: str, secret: bytes, now: float | None = None, ttl: int = SESSION_SECONDS) -> str:
    expires = int((time.time() if now is None else now) + ttl)
    body = _b64(f"{user}|{expires}".encode())
    return f"{body}.{_sign(body, secret)}"


def read_token(token: str | None, secret: bytes, now: float | None = None) -> str | None:
    """The signed-in user, or None if the token is missing, forged or expired."""
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(body, secret)):
        return None
    try:
        user, expires = _unb64(body).decode().rsplit("|", 1)
        alive = int(expires) > (time.time() if now is None else now)
    except (ValueError, UnicodeDecodeError):
        return None
    return user if alive else None


class LoginLimiter:
    """At most `limit` failed sign-ins per client within `window` seconds."""

    def __init__(self, limit: int = 5, window: float = 300.0):
        self.limit, self.window = limit, window
        self._fails: dict[str, list[float]] = {}

    def blocked(self, client: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        recent = [t for t in self._fails.get(client, []) if now - t < self.window]
        self._fails[client] = recent
        return len(recent) >= self.limit

    def fail(self, client: str, now: float | None = None) -> None:
        self._fails.setdefault(client, []).append(time.time() if now is None else now)

    def clear(self, client: str) -> None:
        self._fails.pop(client, None)


def _sign(body: str, secret: bytes) -> str:
    return _b64(hmac.new(secret, body.encode(), hashlib.sha256).digest())


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
