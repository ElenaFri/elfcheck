#!/usr/bin/env bash
set -euo pipefail

: "${KCOV_BIN:?KCOV_BIN must be set}"
: "${KCOV_INCLUDE_PATH:?KCOV_INCLUDE_PATH must be set}"
: "${KCOV_OUTPUT_DIR:?KCOV_OUTPUT_DIR must be set}"
: "${ELFCHECK_REAL_BIN:?ELFCHECK_REAL_BIN must be set}"

exec "$KCOV_BIN" \
    --include-path="$KCOV_INCLUDE_PATH" \
    "$KCOV_OUTPUT_DIR" \
    "$ELFCHECK_REAL_BIN" \
    "$@"
