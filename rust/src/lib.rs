//! Caller identity propagated between Sentry services.
//!
//! Mirrors the `viewercontext` Python package; `fixtures/` keeps the two in agreement.

mod model;
mod token;

pub use model::{Actor, ActorId, ActorType, SuperuserAccess, ViewerContext, WIRE_VERSION};
pub use token::{
    DEFAULT_LEEWAY, DEFAULT_TTL, HEADER, ISSUER, SUPERUSER_ACCESS_TTL, decode_jwt, encode_jwt,
    key_id, verify_jwt,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid viewer context: {0}")]
    InvalidContext(String),
    #[error("no verification key matches kid={0:?}")]
    UnknownKey(Option<String>),
    #[error("missing or non-numeric `{0}` claim")]
    MissingClaim(&'static str),
    #[error("token is not yet valid (iat)")]
    NotYetValid,
    #[error("token has expired")]
    Expired,
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
