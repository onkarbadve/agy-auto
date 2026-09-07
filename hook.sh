#!/bin/sh
# agy-auto PreToolUse hook. Reads the tool call on stdin, prints {"decision": ...}.
# Fail-closed: if the engine cannot start, deny (agy also aborts the call on non-JSON output).
DIR=$(cd "$(dirname "$0")" && pwd)
PY=${AGY_AUTO_PYTHON:-python3}
if ! command -v "$PY" >/dev/null 2>&1; then
  printf '%s\n' '{"decision":"deny","reason":"[agy-auto] python3 not found; policy engine cannot run (fail-closed)"}'
  exit 0
fi
exec "$PY" "$DIR/engine/main.py"
