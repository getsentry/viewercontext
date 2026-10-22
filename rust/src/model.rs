use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Error;

/// The only wire version this crate reads or writes.
pub const WIRE_VERSION: i64 = 2;
/// V1 identity fields; rejected so a downgraded producer fails loudly instead of losing identity.
const V1_FIELDS: [&str; 4] = ["user_id", "actor_type", "superuser", "token"];

/// What kind of principal is acting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// A human Sentry user.
    User,
    /// An organization-owned service account.
    ServiceAccount,
    /// Sentry itself, e.g. a scheduled task.
    System,
    /// A third-party integration.
    Integration,
    /// An AI agent, optionally acting for a delegating user.
    Agent,
    /// Identity could not be determined.
    Unknown,
}

/// Composite identity key: `(type, id)` is unique where `id` alone is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ActorId {
    /// The actor's type.
    pub actor_type: ActorType,
    /// The actor's ID within its type.
    pub id: Option<i64>,
}

/// Read-only elevation for a human actor, granted and enforced by Sentry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperuserAccess {
    /// Unix timestamp after which the elevation is void.
    pub expires_at: i64,
}

/// Typed caller identity, separate from any human delegating its work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// The actor's type.
    #[serde(rename = "type")]
    pub actor_type: ActorType,
    /// The actor's ID within its type.
    #[serde(rename = "id", default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<i64>,
    /// The user an agent acts on behalf of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_user_id: Option<i64>,
    /// Read-only superuser elevation, if granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superuser: Option<SuperuserAccess>,
}

impl Actor {
    /// An actor with no delegation or elevation.
    #[must_use]
    pub fn new(actor_type: ActorType, actor_id: Option<i64>) -> Self {
        Self {
            actor_type,
            actor_id,
            delegated_user_id: None,
            superuser: None,
        }
    }

    /// The `(type, id)` identity key.
    #[must_use]
    pub fn id(&self) -> ActorId {
        ActorId {
            actor_type: self.actor_type,
            id: self.actor_id,
        }
    }

    /// The human behind this actor: the user itself, or the user an agent acts for.
    #[must_use]
    pub fn user_id(&self) -> Option<i64> {
        match self.actor_type {
            ActorType::User => self.actor_id,
            _ => self.delegated_user_id,
        }
    }
}

/// Caller identity and organization/project scope for the current unit of work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "Wire", try_from = "Map<String, Value>")]
pub struct ViewerContext {
    /// Who is acting.
    pub actor: Actor,
    /// Organization scope; `None` for global contexts.
    pub organization_id: Option<i64>,
    /// Project scope within the organization.
    pub project_id: Option<i64>,
    /// Set by Sentry when encoding, for feature evaluation downstream.
    pub organization_is_early_adopter: bool,
}

impl ViewerContext {
    /// A global (unscoped) context for `actor`.
    #[must_use]
    pub fn new(actor: Actor) -> Self {
        Self {
            actor,
            organization_id: None,
            project_id: None,
            organization_is_early_adopter: false,
        }
    }
}

/// Unknown keys (e.g. JWT registered claims) are ignored.
#[derive(Serialize, Deserialize)]
struct Wire {
    version: i64,
    actor: Actor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    organization_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_id: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    organization_is_early_adopter: bool,
}

impl From<ViewerContext> for Wire {
    fn from(ctx: ViewerContext) -> Self {
        Wire {
            version: WIRE_VERSION,
            actor: ctx.actor,
            organization_id: ctx.organization_id,
            project_id: ctx.project_id,
            organization_is_early_adopter: ctx.organization_is_early_adopter,
        }
    }
}

impl TryFrom<Map<String, Value>> for ViewerContext {
    type Error = Error;

    fn try_from(data: Map<String, Value>) -> Result<Self, Error> {
        if V1_FIELDS.iter().any(|field| data.contains_key(*field)) {
            return Err(Error::InvalidContext(
                "V2 contexts cannot carry V1 identity or credentials".into(),
            ));
        }
        let wire: Wire = serde_json::from_value(Value::Object(data))
            .map_err(|e| Error::InvalidContext(e.to_string()))?;
        if wire.version != WIRE_VERSION {
            return Err(Error::InvalidContext(format!(
                "Expected a V{WIRE_VERSION} viewer context"
            )));
        }
        Ok(ViewerContext {
            actor: wire.actor,
            organization_id: wire.organization_id,
            project_id: wire.project_id,
            organization_is_early_adopter: wire.organization_is_early_adopter,
        })
    }
}
