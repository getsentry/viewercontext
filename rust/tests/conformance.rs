//! Shared fixtures; `tests/test_conformance.py` runs the same cases.

use sentry_viewercontext::{
    Actor, ActorType, DEFAULT_LEEWAY, SUPERUSER_ACCESS_TTL, SuperuserAccess, ViewerContext,
    decode_jwt, encode_jwt, verify_jwt,
};
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cases<'a>(fixtures: &'a Value, group: &str) -> &'a Vec<Value> {
    fixtures[group].as_array().unwrap()
}

#[test]
fn valid_round_trips() {
    let fixtures = fixture("contexts.json");
    for case in cases(&fixtures, "valid") {
        let ctx: ViewerContext = serde_json::from_value(case["wire"].clone())
            .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(
            serde_json::to_value(&ctx).unwrap(),
            case["wire"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn ignored_keys_canonicalize() {
    let fixtures = fixture("contexts.json");
    for case in cases(&fixtures, "ignored_keys") {
        let ctx: ViewerContext = serde_json::from_value(case["wire"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&ctx).unwrap(),
            case["canonical"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn invalid_rejected() {
    let fixtures = fixture("contexts.json");
    for case in cases(&fixtures, "invalid") {
        let parsed = serde_json::from_value::<ViewerContext>(case["wire"].clone());
        assert!(parsed.is_err(), "{} should be rejected", case["name"]);
    }
}

#[test]
fn tokens() {
    let fixtures = fixture("tokens.json");
    let keys = [fixtures["key"].as_str().unwrap()];
    for case in cases(&fixtures, "cases") {
        let token = case["token"].as_str().unwrap();
        let decoded = decode_jwt(token, &keys, DEFAULT_LEEWAY);
        match case.get("context") {
            Some(expected) => {
                let ctx = decoded.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
                assert_eq!(
                    &serde_json::to_value(&ctx).unwrap(),
                    expected,
                    "{}",
                    case["name"]
                );
            }
            None => assert!(decoded.is_err(), "{} should be rejected", case["name"]),
        }
    }
}

#[test]
fn round_trip_through_jwt() {
    let key = "test-shared-secret-0123456789abcdef";
    let mut ctx = ViewerContext::new(Actor::new(ActorType::ServiceAccount, Some(9)));
    ctx.organization_id = Some(1);
    let token = encode_jwt(&ctx, key, 60).unwrap();
    assert_eq!(
        decode_jwt(&token, &["rotated-out", key], DEFAULT_LEEWAY).unwrap(),
        ctx
    );

    let claims = verify_jwt(&token, &[key], DEFAULT_LEEWAY).unwrap();
    assert!(claims["iat"].is_i64());
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        60
    );
    assert_eq!(claims["iss"], json!("sentry"));
}

#[test]
fn superuser_caps_expiry() {
    let key = "test-shared-secret-0123456789abcdef";
    let mut actor = Actor::new(ActorType::User, Some(1));
    actor.superuser = Some(SuperuserAccess {
        expires_at: i64::MAX,
    });
    let token = encode_jwt(&ViewerContext::new(actor), key, 900).unwrap();
    let claims = verify_jwt(&token, &[key], DEFAULT_LEEWAY).unwrap();
    let ttl = claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap();
    assert_eq!(ttl, SUPERUSER_ACCESS_TTL);
}

#[test]
fn actor_identity() {
    let agent = Actor {
        delegated_user_id: Some(42),
        ..Actor::new(ActorType::Agent, Some(5))
    };
    assert_eq!(agent.id().id, Some(5));
    assert_eq!(agent.user_id(), Some(42));
    assert_eq!(
        Actor::new(ActorType::ServiceAccount, Some(9)).user_id(),
        None
    );
    for actor_type in [
        ActorType::ServiceAccount,
        ActorType::System,
        ActorType::Integration,
    ] {
        let actor = Actor {
            delegated_user_id: Some(1),
            ..Actor::new(actor_type, Some(9))
        };
        assert_eq!(actor.user_id(), None);
    }
}
