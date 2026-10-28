# viewercontext

Caller identity propagated between Sentry services: who is acting (an `Actor`), and for which
organization and project. Sentry mints it; other services verify it and pass it along.

One repo, two native implementations released together under one version:

| | Package | Import |
|---|---|---|
| Python | `sentry-viewercontext` (PyPI, internal PyPI) | `import sentry_viewercontext` |
| Rust | `sentry-viewercontext` (crates.io) | `use sentry_viewercontext::...` |

`fixtures/` holds the wire contract. Both test suites run every case in it, so a change that
makes the implementations disagree fails CI.

## Python

```python
from sentry_viewercontext import (
    Actor,
    ActorType,
    ViewerContext,
    decode_jwt,
    encode_jwt,
    viewer_context_scope,
)

ctx = ViewerContext(Actor(ActorType.SERVICE_ACCOUNT, actor_id=9), organization_id=1)
token = encode_jwt(ctx, key=secret)  # value for the X-Viewer-Context header
ctx = decode_jwt(token, keys=[current, previous])  # picks the key by `kid`

with viewer_context_scope(ctx):
    ...  # get_viewer_context() returns ctx here
```

## Rust

```rust
use sentry_viewercontext::{Actor, ActorType, ViewerContext, decode_jwt, encode_jwt, DEFAULT_LEEWAY, DEFAULT_TTL};

let mut ctx = ViewerContext::new(Actor::new(ActorType::ServiceAccount, Some(9)));
ctx.organization_id = Some(1);
let token = encode_jwt(&ctx, secret, DEFAULT_TTL)?;
let ctx = decode_jwt(&token, &[current, previous], DEFAULT_LEEWAY)?;
```

Rust has no ambient context; carry the `ViewerContext` in request extensions or task-locals.

## Wire format (version 2)

```json
{
  "version": 2,
  "actor": {"type": "agent", "id": 5, "delegated_user_id": 42, "superuser": {"expires_at": 1800000000}},
  "organization_id": 1,
  "project_id": 7,
  "organization_is_early_adopter": true
}
```

Only `version` and `actor.type` are required. Actor types: `user`, `service_account`, `system`,
`integration`, `agent`, `unknown`. As a JWT it is signed HS256 with `iat`, `exp`, `iss: "sentry"`
and a `kid` header (first 8 hex chars of the key's SHA-256). Superuser access caps `exp` at
5 minutes and at `superuser.expires_at`.

What a service does with a context (required org scope, permission checks, metrics, where
signing keys come from) stays in that service.

## Development

```sh
uv sync
uvx prek install                                   # or pre-commit; runs ruff, mypy, rustfmt, clippy, zizmor
uv run pytest --cov                                # 100% branch coverage required
cargo test
uv run python scripts/generate_token_fixtures.py  # after changing token cases
```

CI additionally runs Python 3.13 and 3.14 (Sentry's and Seer's versions), Rust on latest
stable, `cargo doc` with warnings denied, and `cargo publish --dry-run`.

## Releasing

Run the **Release** workflow with the new version. Craft bumps both manifests
(`scripts/bump-version.sh`) and publishes to GitHub, PyPI, internal PyPI and crates.io.

## License

[FSL-1.1-ALv2](LICENSE.md), the same license as [getsentry/sentry](https://github.com/getsentry/sentry).
