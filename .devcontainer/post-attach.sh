#!/usr/bin/env bash
# Install the Construct Test Console extension into this VS Code session (idempotent).
# `code` only exists when a VS Code client is attached, never in CI or a plain shell.
set -euo pipefail
cd "$(dirname "$0")/.."
if command -v code >/dev/null 2>&1; then
  code --install-extension tools/test-console/construct-test-console.vsix --force >/dev/null 2>&1 || true
fi
