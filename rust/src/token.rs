//! Signed transport for `ViewerContext`: an HS256 JWT carried in the `X-Viewer-Context` header.

use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{Error, ViewerContext};

/// HTTP header carrying the token.
pub const HEADER: &str = "X-Viewer-Context";
/// Required `iss` claim.
pub const ISSUER: &str = "sentry";
/// Token lifetime in seconds.
pub const DEFAULT_TTL: i64 = 900;
/// Maximum lifetime in seconds of a token carrying superuser access.
pub const SUPERUSER_ACCESS_TTL: i64 = 300;
/// Clock skew tolerance in seconds.
pub const DEFAULT_LEEWAY: u32 = 5;

/// `kid` header value: lets receivers pick the right key during rotation.
#[must_use]
pub fn key_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    digest[..4].iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn since_epoch() -> std::time::Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
}

/// Sign `ctx` as an HS256 JWT valid for `ttl` seconds.
///
/// # Errors
///
/// Fails only if serialization or signing fails.
///
/// # Panics
///
/// If the system clock is before 1970.
pub fn encode_jwt(ctx: &ViewerContext, key: &str, ttl: i64) -> Result<String, Error> {
    let now = i64::try_from(since_epoch().as_secs()).expect("timestamp fits in i64");
    let mut expires_at = now + ttl;
    if let Some(superuser) = ctx.actor.superuser {
        expires_at = expires_at
            .min(now + SUPERUSER_ACCESS_TTL)
            .min(superuser.expires_at);
    }
    let Value::Object(mut claims) = serde_json::to_value(ctx)? else {
        unreachable!("ViewerContext serializes to an object")
    };
    claims.insert("iat".into(), now.into());
    claims.insert("exp".into(), expires_at.into());
    claims.insert("iss".into(), ISSUER.into());

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(key_id(key));
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )?)
}

/// Verify signature, `kid`, issuer and expiry; return all claims.
///
/// # Errors
///
/// Fails if no key matches the `kid`, or the token is malformed, mis-signed, expired or not yet
/// valid.
pub fn verify_jwt<K: AsRef<str>>(
    token: &str,
    keys: &[K],
    leeway: u32,
) -> Result<Map<String, Value>, Error> {
    let kid = jsonwebtoken::decode_header(token)?.kid;
    let key = keys
        .iter()
        .map(AsRef::as_ref)
        .find(|k| kid.as_deref() == Some(key_id(k).as_str()))
        .ok_or_else(|| Error::UnknownKey(kid.clone()))?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["iss"]);
    // jsonwebtoken only accepts integer timestamps; producers predating this crate wrote floats.
    validation.validate_exp = false;
    let claims: Map<String, Value> = jsonwebtoken::decode(
        token,
        &DecodingKey::from_secret(key.as_bytes()),
        &validation,
    )?
    .claims;

    let timestamp = |name: &'static str| {
        claims
            .get(name)
            .and_then(Value::as_f64)
            .map(f64::trunc)
            .ok_or(Error::MissingClaim(name))
    };
    let (now, leeway) = (since_epoch().as_secs_f64(), f64::from(leeway));
    if timestamp("iat")? > now + leeway {
        return Err(Error::NotYetValid);
    }
    if timestamp("exp")? <= now - leeway {
        return Err(Error::Expired);
    }
    Ok(claims)
}

/// [`verify_jwt`], then parse the claims as a [`ViewerContext`].
///
/// # Errors
///
/// Fails as [`verify_jwt`] does, or if the claims are not a valid context.
pub fn decode_jwt<K: AsRef<str>>(
    token: &str,
    keys: &[K],
    leeway: u32,
) -> Result<ViewerContext, Error> {
    ViewerContext::try_from(verify_jwt(token, keys, leeway)?)
}
