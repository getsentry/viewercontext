//! Caller identity propagated between Sentry services.
//!
//! Mirrors the `sentry_viewercontext` Python package; `fixtures/` keeps the two in agreement.

mod model;
mod token;

pub use model::{Actor, ActorId, ActorType, SuperuserAccess, ViewerContext, WIRE_VERSION};
pub use token::{
    DEFAULT_LEEWAY, DEFAULT_TTL, HEADER, ISSUER, SUPERUSER_ACCESS_TTL, decode_jwt, encode_jwt,
    key_id, verify_jwt,
};

/// Everything that can go wrong parsing, signing or verifying a context.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The payload is not a valid V2 context.
    #[error("invalid viewer context: {0}")]
    InvalidContext(String),
    /// No configured key matches the token's `kid`.
    #[error("no verification key matches kid={0:?}")]
    UnknownKey(Option<String>),
    /// A required timestamp claim is absent or not a number.
    #[error("missing or non-numeric `{0}` claim")]
    MissingClaim(&'static str),
    /// `iat` is in the future.
    #[error("token is not yet valid (iat)")]
    NotYetValid,
    /// `exp` has passed.
    #[error("token has expired")]
    Expired,
    /// Malformed token, bad signature, wrong algorithm or issuer.
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// Serialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
