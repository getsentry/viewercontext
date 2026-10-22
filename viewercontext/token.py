"""Signed transport for ViewerContext: an HS256 JWT carried in the ``X-Viewer-Context`` header."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Iterable
from typing import Any

import jwt

from viewercontext.model import ViewerContext

HEADER = "X-Viewer-Context"
ISSUER = "sentry"
ALGORITHM = "HS256"
DEFAULT_TTL = 900
SUPERUSER_ACCESS_TTL = 300


def key_id(key: str) -> str:
    """``kid`` header value: lets receivers pick the right key during rotation."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def encode_jwt(ctx: ViewerContext, *, key: str, ttl: int = DEFAULT_TTL) -> str:
    now = int(time.time())
    expires_at = now + ttl
    if ctx.actor.superuser is not None:
        expires_at = min(expires_at, now + SUPERUSER_ACCESS_TTL, ctx.actor.superuser.expires_at)
    claims = {**ctx.serialize(), "iat": now, "exp": expires_at, "iss": ISSUER}
    return jwt.encode(claims, key, algorithm=ALGORITHM, headers={"kid": key_id(key)})


def verify_jwt(token: str, *, keys: Iterable[str], leeway: int = 5) -> dict[str, Any]:
    """Verify signature, ``kid``, issuer and expiry; return all claims.

    Raises ``jwt.InvalidTokenError`` on any failure.
    """
    kid = jwt.get_unverified_header(token).get("kid")
    key = next((k for k in keys if kid is not None and key_id(k) == kid), None)
    if key is None:
        raise jwt.InvalidTokenError(f"No verification key matches kid={kid!r}")
    return jwt.decode(
        token,
        key,
        algorithms=[ALGORITHM],
        options={"require": ["iat", "exp", "iss"]},
        issuer=ISSUER,
        leeway=leeway,
    )


def decode_jwt(token: str, *, keys: Iterable[str], leeway: int = 5) -> ViewerContext:
    """Raises ``jwt.InvalidTokenError`` for bad tokens and ``ValueError`` for bad payloads."""
    return ViewerContext.deserialize(verify_jwt(token, keys=keys, leeway=leeway))


def is_jwt(value: str) -> bool:
    try:
        jwt.get_unverified_header(value)
    except jwt.DecodeError:
        return False
    return True
