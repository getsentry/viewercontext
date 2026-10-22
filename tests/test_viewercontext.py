from __future__ import annotations

import time

import jwt
import pytest

from viewercontext import (
    SUPERUSER_ACCESS_TTL,
    Actor,
    ActorId,
    ActorType,
    SuperuserAccess,
    ViewerContext,
    decode_jwt,
    encode_jwt,
    get_viewer_context,
    is_jwt,
    key_id,
    verify_jwt,
    viewer_context_scope,
)

KEY = "test-shared-secret-0123456789abcdef"


def test_actor_id() -> None:
    assert Actor(ActorType.SERVICE_ACCOUNT, actor_id=9).id == ActorId(ActorType.SERVICE_ACCOUNT, 9)


def test_actor_user_id() -> None:
    assert Actor(ActorType.USER, actor_id=1).user_id == 1
    assert Actor(ActorType.AGENT, actor_id=5, delegated_user_id=1).user_id == 1
    assert Actor(ActorType.SERVICE_ACCOUNT, actor_id=9).user_id is None


def test_round_trip_through_jwt() -> None:
    ctx = ViewerContext(Actor(ActorType.USER, actor_id=42), organization_id=1, project_id=7)
    assert decode_jwt(encode_jwt(ctx, key=KEY), keys=["rotated-out", KEY]) == ctx


def test_encode_writes_integer_timestamps_and_kid() -> None:
    token = encode_jwt(ViewerContext(Actor(ActorType.SYSTEM)), key=KEY, ttl=60)
    claims = verify_jwt(token, keys=[KEY])
    assert type(claims["iat"]) is int
    assert claims["exp"] - claims["iat"] == 60
    assert jwt.get_unverified_header(token)["kid"] == key_id(KEY)


def test_superuser_caps_expiry() -> None:
    soon = int(time.time()) + 30
    actor = Actor(ActorType.USER, actor_id=1, superuser=SuperuserAccess(expires_at=soon))
    claims = verify_jwt(encode_jwt(ViewerContext(actor, organization_id=1), key=KEY), keys=[KEY])
    assert claims["exp"] == soon

    later = int(time.time()) + 10_000
    actor = Actor(ActorType.USER, actor_id=1, superuser=SuperuserAccess(expires_at=later))
    claims = verify_jwt(encode_jwt(ViewerContext(actor, organization_id=1), key=KEY), keys=[KEY])
    assert claims["exp"] - claims["iat"] == SUPERUSER_ACCESS_TTL


def test_is_jwt() -> None:
    assert is_jwt(encode_jwt(ViewerContext(Actor(ActorType.SYSTEM)), key=KEY))
    assert not is_jwt('{"version": 2}')
    assert not is_jwt("")


def test_no_matching_key() -> None:
    token = encode_jwt(ViewerContext(Actor(ActorType.SYSTEM)), key=KEY)
    with pytest.raises(jwt.InvalidTokenError):
        verify_jwt(token, keys=["some-other-secret-0123456789abcdef"])


def test_scope_restores_previous() -> None:
    outer = ViewerContext(Actor(ActorType.SYSTEM))
    inner = ViewerContext(Actor(ActorType.USER, actor_id=1), organization_id=1)
    seen = []

    def fail_inside_inner() -> None:
        with viewer_context_scope(inner):
            seen.append(get_viewer_context())
            raise RuntimeError

    with viewer_context_scope(outer):
        with pytest.raises(RuntimeError):
            fail_inside_inner()
        assert get_viewer_context() == outer
    assert seen == [inner]
    assert get_viewer_context() is None
