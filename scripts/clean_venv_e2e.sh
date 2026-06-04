#!/usr/bin/env bash
# Clean-venv end-to-end release gate (V15).
#
# Builds the current tree into a wheel, installs it into a FRESH virtualenv that
# has no OpenWright on the path, and runs `openwright demo` — which exits non-zero
# unless every acceptance check (signed report, offline verify, tamper-evidence)
# is green. This is the "on every release, a clean `pip install` + demo is green"
# check; run it in CI before publishing.
#
# Usage: scripts/clean_venv_e2e.sh [BASE_PYTHON]
#   BASE_PYTHON: interpreter used to create the clean venv (default: python3.11).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BASE_PYTHON="${1:-python3.11}"
if ! command -v "$BASE_PYTHON" >/dev/null 2>&1; then
  # Fall back to the poetry venv's interpreter (same minor as the build target).
  BASE_PYTHON="$(poetry -C "$REPO" env info -p 2>/dev/null)/bin/python"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "== building wheel from current tree =="
poetry -C "$REPO" build -f wheel -o "$WORK/dist" >/dev/null
WHEEL="$(ls "$WORK"/dist/openwright_core-*.whl | head -1)"
echo "   built: $(basename "$WHEEL")"

echo "== creating clean venv with $BASE_PYTHON =="
"$BASE_PYTHON" -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install --quiet --upgrade pip
echo "== pip install the wheel (pulls deps from PyPI) =="
"$WORK/venv/bin/pip" install --quiet "$WHEEL"

echo "== sanity: openwright is the installed one, not the repo =="
"$WORK/venv/bin/python" -c "import openwright, sys; assert 'site-packages' in openwright.__file__, openwright.__file__; print('openwright', openwright.__version__, 'from', openwright.__file__)"

echo "== openwright demo (exits non-zero unless all AC checks pass) =="
"$WORK/venv/bin/openwright" demo --no-browser
echo "== CLEAN-VENV E2E: PASS =="
