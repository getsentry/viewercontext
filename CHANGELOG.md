# Changelog

## 0.3.0

### New Features ✨

- Remove the unknown actor type by @gricha in [#9](https://github.com/getsentry/viewercontext/pull/9)

## 0.2.0

- `Actor.user_id` returns `delegated_user_id` only for agents; other non-user actors return `None`.

## 0.1.0

- Initial release: actor-based ViewerContext (wire V2), HS256 JWT transport, Python and Rust.

