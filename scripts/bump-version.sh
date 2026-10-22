#!/bin/bash
set -euo pipefail

NEW_VERSION="${2}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

perl -i -pe "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml Cargo.toml
cargo metadata --format-version 1 > /dev/null
uv lock
