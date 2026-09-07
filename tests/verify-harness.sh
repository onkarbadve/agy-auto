#!/bin/bash
# Re-verify the agy hook surface after an `agy update`. Installs a temporary probe hook
# next to agy-auto's, runs three headless calls, removes the probe, prints a table.
# Compare the table with HARNESS-BEHAVIORS.md. Costs three agy model calls.
set -uo pipefail
HOOKS_JSON="$HOME/.gemini/config/hooks.json"
PROBE_NAME="agy-auto-verify-probe"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/agy-auto-verify.XXXXXX")
WS="$TMP/ws"; mkdir -p "$WS"
PROBE="$TMP/probe.sh"
cat > "$PROBE" <<PEOF
#!/bin/sh
cat >> "$TMP/hook-input.jsonl"
cat "$TMP/mode"
PEOF
chmod +x "$PROBE"
cleanup() {
  python3 - "$HOOKS_JSON" "$PROBE_NAME" <<'PY'
import json, os, sys
p, n = sys.argv[1:3]
if os.path.exists(p):
    d = json.load(open(p)); d.pop(n, None)
    json.dump(d, open(p, "w"), indent=2); open(p, "a").write("\n")
PY
  rm -rf "$TMP"
}
trap cleanup EXIT
python3 - "$HOOKS_JSON" "$PROBE_NAME" "$PROBE" <<'PY'
import json, os, sys
p, n, cmd = sys.argv[1:4]
d = json.load(open(p)) if os.path.exists(p) else {}
d[n] = {"enabled": True, "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 5}]}]}
json.dump(d, open(p, "w"), indent=2); open(p, "a").write("\n")
PY
echo "agy version: $(agy --version | head -1)"
echo "toolPermission: $(agy -p '/config' 2>/dev/null | awk -F'\t' '$1=="toolPermission"{print $2}')"
echo "hooks listed: $(agy -p '/hooks' 2>/dev/null | cut -f1 | tr '\n' ' ')"
run() { # name decision-json file
  printf '%s' "$2" > "$TMP/mode"; : > "$TMP/hook-input.jsonl"; rm -f "$WS/$3"
  cd "$WS"
  local out; out=$(timeout 200 agy --add-dir "$WS" --print-timeout 150s --output-format json -p "Run exactly this shell command and nothing else, then stop: touch $3. If it is blocked or denied, reply with the exact denial reason text you received, verbatim. Do not retry." 2>/dev/null)
  local fired; fired=$(wc -l < "$TMP/hook-input.jsonl" | tr -d ' ')
  local created; [ -f "$WS/$3" ] && created=yes || created=no
  local ws; ws=$(head -1 "$TMP/hook-input.jsonl" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("workspacePaths"))' 2>/dev/null)
  printf '%-10s probe=%-42s fired=%s executed=%s workspacePaths=%s\n' "$1" "$2" "$fired" "$created" "$ws"
  printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("           response:", d.get("response","")[:160].replace("\n"," "))' 2>/dev/null
}
run allow     '{"decision":"allow"}' v_allow.txt
run deny      '{"decision":"deny","reason":"VERIFY-PROBE-DENY"}' v_deny.txt
run force_ask '{"decision":"force_ask","reason":"VERIFY-PROBE-ASK"}' v_ask.txt
echo
echo "Expected on 1.1.27: allow fired=1 executed=yes | deny fired=1 executed=no | force_ask fired=1 executed=YES (no-op under always-proceed)."
echo "If force_ask now shows executed=no, the build honors it: you may set escalation.decision = \"force_ask\" in the policy."
