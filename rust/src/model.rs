use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::Error;

pub const WIRE_VERSION: i64 = 2;
/// V1 identity fields; rejected so a downgraded producer fails loudly instead of losing identity.
const V1_FIELDS: [&str; 4] = ["user_id", "actor_type", "superuser", "token"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    ServiceAccount,
    System,
    Integration,
    Agent,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ActorId {
    pub actor_type: ActorType,
    pub id: Option<i64>,
}

/// Read-only elevation for a human actor, granted and enforced by Sentry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuperuserAccess {
    pub expires_at: i64,
}

/// Typed caller identity, separate from any human delegating its work.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    #[serde(rename = "type")]
    pub actor_type: ActorType,
    #[serde(rename = "id", default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_user_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superuser: Option<SuperuserAccess>,
}

impl Actor {
    pub fn new(actor_type: ActorType, actor_id: Option<i64>) -> Self {
        Self {
            actor_type,
            actor_id,
            delegated_user_id: None,
            superuser: None,
        }
    }

    pub fn id(&self) -> ActorId {
        ActorId {
            actor_type: self.actor_type,
            id: self.actor_id,
        }
    }

    /// The human behind this actor: the user itself, or the user an agent acts for.
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
    pub actor: Actor,
    pub organization_id: Option<i64>,
    pub project_id: Option<i64>,
    pub organization_is_early_adopter: bool,
}

impl ViewerContext {
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
