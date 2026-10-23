"""Shared fixtures; rust/tests/conformance.rs runs the same cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jwt
import pytest

from sentry_viewercontext import ViewerContext, decode_jwt

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CONTEXTS = json.loads((FIXTURES / "contexts.json").read_text())
TOKENS = json.loads((FIXTURES / "tokens.json").read_text())


def _ids(cases: list[dict[str, Any]]) -> list[str]:
    return [c["name"] for c in cases]


@pytest.mark.parametrize("case", CONTEXTS["valid"], ids=_ids(CONTEXTS["valid"]))
def test_valid_round_trips(case: dict[str, Any]) -> None:
    assert ViewerContext.deserialize(case["wire"]).serialize() == case["wire"]


@pytest.mark.parametrize("case", CONTEXTS["ignored_keys"], ids=_ids(CONTEXTS["ignored_keys"]))
def test_ignored_keys_canonicalize(case: dict[str, Any]) -> None:
    assert ViewerContext.deserialize(case["wire"]).serialize() == case["canonical"]


@pytest.mark.parametrize("case", CONTEXTS["invalid"], ids=_ids(CONTEXTS["invalid"]))
def test_invalid_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 -- any ValueError is the contract
        ViewerContext.deserialize(case["wire"])


@pytest.mark.parametrize("case", TOKENS["cases"], ids=_ids(TOKENS["cases"]))
def test_tokens(case: dict[str, Any]) -> None:
    keys = [TOKENS["key"]]
    if "context" in case:
        assert decode_jwt(case["token"], keys=keys).serialize() == case["context"]
    else:
        with pytest.raises((jwt.InvalidTokenError, ValueError)):
            decode_jwt(case["token"], keys=keys)
