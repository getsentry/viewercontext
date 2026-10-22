from __future__ import annotations

import dataclasses
import enum
from typing import Any, NamedTuple

WIRE_VERSION = 2
# V1 identity fields; rejected so a downgraded producer fails loudly instead of losing identity.
_V1_FIELDS = frozenset({"user_id", "actor_type", "superuser", "token"})


class ActorType(enum.StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    SYSTEM = "system"
    INTEGRATION = "integration"
    AGENT = "agent"
    UNKNOWN = "unknown"


class ActorId(NamedTuple):
    type: ActorType
    id: int | None


@dataclasses.dataclass(frozen=True)
class SuperuserAccess:
    """Read-only elevation for a human actor, granted and enforced by Sentry."""

    expires_at: int


@dataclasses.dataclass(frozen=True)
class Actor:
    """Typed caller identity, separate from any human delegating its work."""

    type: ActorType
    actor_id: int | None = None
    delegated_user_id: int | None = None
    superuser: SuperuserAccess | None = dataclasses.field(default=None, repr=False)

    @property
    def id(self) -> ActorId:
        return ActorId(self.type, self.actor_id)

    @property
    def user_id(self) -> int | None:
        """The human behind this actor: the user itself, or the user an agent acts for."""
        return self.actor_id if self.type == ActorType.USER else self.delegated_user_id

    def serialize(self) -> dict[str, Any]:
        result: dict[str, Any] = {"type": self.type.value}
        if self.actor_id is not None:
            result["id"] = self.actor_id
        if self.delegated_user_id is not None:
            result["delegated_user_id"] = self.delegated_user_id
        if self.superuser is not None:
            result["superuser"] = {"expires_at": self.superuser.expires_at}
        return result

    @classmethod
    def deserialize(cls, data: Any) -> Actor:
        if not isinstance(data, dict) or "type" not in data:
            raise ValueError("Actor must be an object with a type")
        superuser = data.get("superuser")
        if superuser is not None:
            if not isinstance(superuser, dict):
                raise ValueError("superuser must be an object")
            superuser = SuperuserAccess(expires_at=_int(superuser.get("expires_at"), "expires_at"))
        return cls(
            type=ActorType(data["type"]),
            actor_id=_opt_int(data.get("id"), "id"),
            delegated_user_id=_opt_int(data.get("delegated_user_id"), "delegated_user_id"),
            superuser=superuser,
        )


@dataclasses.dataclass(frozen=True)
class ViewerContext:
    """Caller identity and organization/project scope for the current unit of work."""

    actor: Actor
    organization_id: int | None = None
    project_id: int | None = None
    organization_is_early_adopter: bool = False

    def serialize(self) -> dict[str, Any]:
        result: dict[str, Any] = {"version": WIRE_VERSION, "actor": self.actor.serialize()}
        if self.organization_id is not None:
            result["organization_id"] = self.organization_id
        if self.project_id is not None:
            result["project_id"] = self.project_id
        if self.organization_is_early_adopter:
            result["organization_is_early_adopter"] = True
        return result

    @classmethod
    def deserialize(cls, data: Any) -> ViewerContext:
        """Parse the wire shape. Unknown keys (e.g. JWT registered claims) are ignored."""
        if not isinstance(data, dict):
            raise ValueError("Viewer context must be an object")
        if type(data.get("version")) is not int or data["version"] != WIRE_VERSION:
            raise ValueError(f"Expected a V{WIRE_VERSION} viewer context")
        if _V1_FIELDS.intersection(data):
            raise ValueError("V2 contexts cannot carry V1 identity or credentials")
        early_adopter = data.get("organization_is_early_adopter", False)
        if type(early_adopter) is not bool:
            raise ValueError("organization_is_early_adopter must be a boolean")
        return cls(
            actor=Actor.deserialize(data.get("actor")),
            organization_id=_opt_int(data.get("organization_id"), "organization_id"),
            project_id=_opt_int(data.get("project_id"), "project_id"),
            organization_is_early_adopter=early_adopter,
        )


# Type checks match what serde enforces in the Rust crate, so both reject the same payloads.
def _int(value: Any, name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    return value


def _opt_int(value: Any, name: str) -> int | None:
    return None if value is None else _int(value, name)
