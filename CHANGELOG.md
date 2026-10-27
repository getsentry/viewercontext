# Changelog

## Unreleased

- Remove `ActorType.UNKNOWN` (Rust: `ActorType::Unknown`). Callers must pick a real actor type, or
  set no context. Contexts with `"type": "unknown"` are rejected like any other unrecognised type.

## 0.2.0

- `Actor.user_id` returns `delegated_user_id` only for agents; other non-user actors return `None`.

## 0.1.0

- Initial release: actor-based ViewerContext (wire V2), HS256 JWT transport, Python and Rust.

