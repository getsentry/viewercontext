"""Regenerate fixtures/tokens.json.

Signs with PyJWT directly rather than this package, so both implementations are
checked against an independent producer.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any
from unittest import mock

import jwt

from viewercontext import ViewerContext, encode_jwt, key_id

KEY = "fixture-shared-secret-0123456789abcdef"
OTHER_KEY = "fixture-other-secret-0123456789abcdef"
IAT = 1700000000
FAR_FUTURE = 4102444800  # 2100-01-01
CONTEXT = {"version": 2, "actor": {"type": "user", "id": 42}, "organization_id": 1}


def sign(claims: dict[str, Any], key: str = KEY, **headers: Any) -> str:
    headers.setdefault("kid", key_id(key))
    if headers["kid"] is None:
        del headers["kid"]
    return jwt.encode(claims, key, algorithm=headers.pop("alg", "HS256"), headers=headers)


def standard(**overrides: Any) -> dict[str, Any]:
    return {**CONTEXT, "iat": IAT, "exp": FAR_FUTURE, "iss": "sentry", **overrides}


def encode_python() -> str:
    # Frozen clock keeps the output stable, so CI can check fixtures match the generator.
    with mock.patch("time.time", return_value=IAT):
        return encode_jwt(ViewerContext.deserialize(CONTEXT), key=KEY, ttl=FAR_FUTURE - IAT)


def main() -> None:
    # Fixture keys are short on purpose; the HS512 wrong-algorithm case trips this.
    warnings.filterwarnings("ignore", category=jwt.warnings.InsecureKeyLengthWarning)
    no_iat = standard()
    del no_iat["iat"]
    cases = [
        {"name": "valid", "token": sign(standard()), "context": CONTEXT},
        # Sentry before this library wrote float timestamps; readers must keep accepting them.
        {
            "name": "valid_float_timestamps",
            "token": sign(standard(iat=IAT + 0.5, exp=FAR_FUTURE + 0.5)),
            "context": CONTEXT,
        },
        # This package's own encoder, so Rust is checked against the Python producer too.
        {
            "name": "valid_python_encoder",
            "token": encode_python(),
            "context": CONTEXT,
        },
        {"name": "expired", "token": sign(standard(exp=IAT + 900))},
        {"name": "wrong_issuer", "token": sign(standard(iss="seer"))},
        {"name": "missing_iat", "token": sign(no_iat)},
        {"name": "missing_kid", "token": sign(standard(), kid=None)},
        {"name": "unknown_kid", "token": sign(standard(), OTHER_KEY)},
        {"name": "kid_mismatch_signature", "token": sign(standard(), OTHER_KEY, kid=key_id(KEY))},
        {"name": "wrong_algorithm", "token": sign(standard(), alg="HS512")},
        {"name": "invalid_payload", "token": sign(standard(version=1))},
    ]
    out = {"key": KEY, "kid": key_id(KEY), "cases": cases}
    path = Path(__file__).resolve().parent.parent / "fixtures" / "tokens.json"
    path.write_text(json.dumps(out, indent=2) + "\n")


if __name__ == "__main__":
    main()
