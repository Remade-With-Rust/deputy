#!/usr/bin/env bash
# Publish the Deputy workspace to crates.io in dependency order.
#
# Usage:
#   ./scripts/publish.sh --dry-run   # cargo package + verify each crate, upload nothing
#   ./scripts/publish.sh             # publish for real, in order
#
# Requires `cargo login` (or CARGO_REGISTRY_TOKEN) with publish scope. See RELEASING.md.
set -euo pipefail

DRY=""
if [ "${1:-}" = "--dry-run" ]; then
  DRY="--dry-run"
fi

# Dependency order: a crate is published only after all of its deps are on crates.io.
CRATES=(
  deputy-alloc
  deputy-core
  deputy-crypto
  deputy-id
  deputy-ecosystem
  deputy-store
  deputy-analyze
  deputy-scan
  deputy-acquire
  deputy-deploy
  deputy-api
  deputy-cli
)
# deputy-ui is a wasm app (publish = false) and is deliberately omitted.

for c in "${CRATES[@]}"; do
  echo ">>> cargo publish -p ${c} ${DRY}"
  cargo publish -p "${c}" ${DRY}
  if [ -z "${DRY}" ]; then
    echo "    waiting ~20s for crates.io to index ${c} before the next crate depends on it..."
    sleep 20
  fi
done

echo "done."
