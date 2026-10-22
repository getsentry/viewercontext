#!/bin/bash
# Craft preReleaseCommand. Runs without uv on the release runner, so lockfiles are edited in place.
set -euo pipefail

NEW_VERSION="${2}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

perl -i -pe "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml Cargo.toml
perl -0pi -e "s/(name = \"sentry-viewercontext\"\nversion = )\"[^\"]*\"/\${1}\"$NEW_VERSION\"/" Cargo.lock uv.lock

grep -q "^version = \"$NEW_VERSION\"" pyproject.toml
grep -q "^version = \"$NEW_VERSION\"" Cargo.toml
for lock in Cargo.lock uv.lock; do
    perl -0ne "exit !/name = \"sentry-viewercontext\"\nversion = \"\Q$NEW_VERSION\E\"/" "$lock"
done
