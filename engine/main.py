"""agy-auto PreToolUse hook entrypoint.

stdin:  agy hook payload {"toolCall": {"name", "args"}, "conversationId", "workspacePaths", "transcriptPath", ...}
stdout: {"decision": "allow"} or {"decision": "deny", "reason": "..."}

Layers, first match wins: hard deny -> fast allow -> classifier (cached) -> escalation.
Fail-closed: any error -> deny.  Dry-run: log the decision, emit allow.

CLI for tests:  main.py --check "<command>" [--cwd DIR] [--ws DIR] [--tool NAME --args JSON]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import tomllib
from datetime import datetime, timezone

ENGINE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(ENGINE_DIR)
sys.path.insert(0, ENGINE_DIR)

from classifier import ClassifierError, classify as llm_classify  # noqa: E402
from policy import Decision, Engine  # noqa: E402
from store import Store  # noqa: E402

DEFAULT_POLICY = os.path.join(ROOT_DIR, "policy", "default.toml")
USER_POLICY = os.path.expanduser("~/.gemini/config/agy-auto/policy.toml")
WS_POLICY_REL = os.path.join(".agents", "agy-auto.toml")
WS_ALLOWED_SECTIONS = {"hard_deny", "fast_allow", "paths", "workspace", "tools"}


# --------------------------------------------------------------------------- policy loading
def _merge(base, layer):
    if isinstance(base, dict) and isinstance(layer, dict):
        out = dict(base)
        for k, v in layer.items():
            out[k] = _merge(base[k], v) if k in base else v
        return out
    if isinstance(base, list) and isinstance(layer, list):
        seen = {json.dumps(x, sort_keys=True) for x in base}
        return list(base) + [x for x in layer if json.dumps(x, sort_keys=True) not in seen]
    return layer


def load_policy(ws_roots: list[str]) -> tuple[dict, str, list[str]]:
    sources = [DEFAULT_POLICY]
    with open(DEFAULT_POLICY, "rb") as fh:
        cfg = tomllib.load(fh)
    extra = os.environ.get("AGY_AUTO_POLICY")
    for path in [USER_POLICY] + ([extra] if extra else []):
        if path and os.path.exists(path):
            with open(path, "rb") as fh:
                cfg = _merge(cfg, tomllib.load(fh))
            sources.append(path)
    for ws in ws_roots:
        p = os.path.join(ws, WS_POLICY_REL)
        if os.path.exists(p):
            with open(p, "rb") as fh:
                layer = tomllib.load(fh)
            layer = {k: v for k, v in layer.items() if k in WS_ALLOWED_SECTIONS}
            cfg = _merge(cfg, layer)
            sources.append(p)
    if os.environ.get("AGY_AUTO_DRY_RUN") == "1":
        cfg["mode"] = "dry-run"
    if os.environ.get("AGY_AUTO_CLASSIFIER_ENDPOINT"):
        cfg.setdefault("classifier", {})["endpoint"] = os.environ["AGY_AUTO_CLASSIFIER_ENDPOINT"]
    version = str(cfg.get("version", "0")) + "-" + hashlib.sha256(json.dumps(cfg, sort_keys=True, default=str).encode()).hexdigest()[:12]
    return cfg, version, sources


# --------------------------------------------------------------------------- context
def read_context(transcript_path: str | None, max_chars: int) -> str:
    """Recent user requests and model messages only. Never tool results (type GENERIC)."""
    if not transcript_path or not os.path.exists(transcript_path):
        return ""
    try:
        with open(transcript_path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 200_000))
            lines = fh.read().decode("utf-8", "replace").splitlines()[-80:]
    except OSError:
        return ""
    items = []
    for ln in lines:
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        t = rec.get("type")
        if t == "USER_INPUT":
            c = rec.get("content") or ""
            m = re.search(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", c, flags=re.S)
            c = m.group(1) if m else re.sub(r"<[A-Z_]+>.*?</[A-Z_]+>", "", c, flags=re.S)
            c = c.strip()
            if c:
                items.append(("user", c))
        elif t == "PLANNER_RESPONSE":
            c = (rec.get("content") or "").strip()
            if c:
                items.append(("model", c))
    items = items[-6:]
    out = []
    budget = max_chars
    for role, c in reversed(items):
        c = c[:600]
        if len(c) + 12 > budget:
            break
        out.append(f"[{role}] {c}")
        budget -= len(c) + 12
    return "\n".join(reversed(out))


# --------------------------------------------------------------------------- core
def normalize_cmd(cmd: str) -> str:
    return re.sub(r"\s+", " ", cmd.strip())


def resolve_cwd(args: dict, ws_roots: list[str]) -> str | None:
    cwd = args.get("Cwd")
    if isinstance(cwd, str) and cwd:
        if os.path.isabs(cwd):
            return os.path.normpath(cwd)
        if ws_roots:
            return os.path.normpath(os.path.join(ws_roots[0], cwd))
        return None
    return ws_roots[0] if ws_roots else None


def is_dangerously_skip_active(pid: int | None = None) -> bool:
    """Walks process ancestry to check if an ancestor is agy with --dangerously-skip-permissions."""
    if os.environ.get("AGY_AUTO_HONOR_DANGEROUSLY_SKIP") == "0":
        return False
    if os.environ.get("AGY_AUTO_FORCE_DANGEROUSLY_SKIP") == "1":
        return True
    try:
        curr = pid if pid is not None else os.getppid()
        for _ in range(10):
            if curr <= 1:
                break
            cmdline_path = f"/proc/{curr}/cmdline"
            if os.path.exists(cmdline_path):
                try:
                    with open(cmdline_path, "rb") as f:
                        raw = f.read()
                    args = [a for a in raw.decode("utf-8", "replace").split("\0") if a]
                    if args:
                        prog = os.path.basename(args[0])
                        if "agy" in prog or any("agy" in a for a in args):
                            if "--dangerously-skip-permissions" in args:
                                return True
                except (OSError, IOError):
                    pass
            stat_path = f"/proc/{curr}/stat"
            if not os.path.exists(stat_path):
                break
            with open(stat_path, "r") as f:
                stat = f.read()
            rparen = stat.rfind(")")
            if rparen == -1:
                break
            fields = stat[rparen + 2 :].split()
            curr = int(fields[1])
    except Exception:
        pass
    return False


def get_target_script_hash(tool: str, args: dict, cwd: str | None) -> str:
    """Computes SHA256 content hash of the target script if command executes a local script file."""
    if tool != "run_command":
        return ""
    cmd = args.get("CommandLine")
    if not isinstance(cmd, str) or not cmd.strip():
        return ""
    parts = cmd.strip().split()
    if not parts:
        return ""
    script_candidates = []
    base0 = os.path.basename(parts[0])
    if base0 in ("python", "python3", "bash", "sh", "zsh", "node", "perl", "ruby"):
        for tok in parts[1:]:
            if not tok.startswith("-"):
                script_candidates.append(tok)
                break
    elif parts[0].startswith("./") or parts[0].startswith("../") or "/" in parts[0]:
        script_candidates.append(parts[0])

    for target in script_candidates:
        resolved = os.path.normpath(os.path.join(cwd, target)) if cwd and not os.path.isabs(target) else os.path.abspath(target)
        if os.path.isfile(resolved):
            try:
                with open(resolved, "rb") as fh:
                    return hashlib.sha256(fh.read()).hexdigest()[:16]
            except OSError:
                pass
    return ""


def check_recent_user_approval(transcript_path: str | None, conv: str, tool: str, norm: str, cwd: str | None, store: Store | None) -> bool:
    """Checks if the user explicitly provided an action approval token in chat ('> agy-approve <token>').
    Binds the approval to the specific command, working directory, and conversation, eliminating ambient authority.
    """
    if not transcript_path or not os.path.exists(transcript_path):
        return False
    try:
        with open(transcript_path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 100_000))
            lines = fh.read().decode("utf-8", "replace").splitlines()[-40:]
    except OSError:
        return False
    last_user_msg = ""
    for ln in lines:
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if rec.get("type") == "USER_INPUT":
            c = rec.get("content") or ""
            m = re.search(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", c, flags=re.S)
            c = m.group(1) if m else re.sub(r"<[A-Z_]+>.*?</[A-Z_]+>", "", c, flags=re.S)
            last_user_msg = c.strip()
    if not last_user_msg:
        return False
    m = re.search(r"(?:^|\s|>)\s*agy-approve\s+([0-9a-fA-F]{6,12})\b", last_user_msg)
    if not m:
        return False
    token = m.group(1).lower()
    if store:
        return store.consume_approval(token, conv, tool, norm, cwd)
    return False


def decide(payload: dict, cfg: dict, version: str, store: Store | None, use_classifier: bool) -> tuple[Decision, dict]:
    """Returns the final Decision (allow/deny/force_ask) plus audit details."""
    tool_call = payload.get("toolCall") or {}
    tool = tool_call.get("name") or ""
    args = tool_call.get("args") or {}
    ws_roots = [w for w in (payload.get("workspacePaths") or []) if isinstance(w, str)]
    conv = payload.get("conversationId") or ""
    details: dict = {"cache_hit": False, "classifier": None, "escalation": 0}

    if tool == "run_command":
        cwd = resolve_cwd(args, ws_roots)
        details["cwd"] = cwd
    else:
        cwd = None

    if cfg.get("honor_dangerously_skip_permissions", True) and is_dangerously_skip_active():
        return Decision("allow", "dangerously_skip", "bypassed: agy started with --dangerously-skip-permissions"), details

    engine = Engine(cfg, ws_roots)

    if tool == "run_command":
        cmd = args.get("CommandLine")
        if not isinstance(cmd, str) or not cmd.strip():
            d = Decision("deny", "engine", "run_command without a CommandLine", "invalid", "invalid")
        else:
            d = engine.decide_command(cmd, cwd)
        norm = normalize_cmd(cmd or "")
    else:
        d = engine.decide_tool(tool, args if isinstance(args, dict) else {})
        norm = json.dumps(args, sort_keys=True, default=str)[:4000]

    if d.decision == "classify":
        why = d.reason
        transcript_path = payload.get("transcriptPath")

        # Conversational chat approval: check if user provided valid agy-approve <token>
        if check_recent_user_approval(transcript_path, conv, tool, norm, cwd, store):
            return Decision("allow", "user_approval", f"explicit user approval in chat: {why}"), details

        token = store.create_approval(conv, tool, norm, cwd) if store else "TOKEN"

        if not use_classifier:
            d = Decision("deny", "classifier", f"needs classification ({why}) and no classifier is available; reply '> agy-approve {token}' in chat to proceed or allow in policy", d.category, d.intent or "classify")
        else:
            ccfg = cfg.get("classifier", {})
            script_hash = get_target_script_hash(tool, args, cwd)
            key = store.cache_key(tool, norm, cwd, engine.ws_roots, extra_hash=script_hash) if store else None
            cached = store.cache_get(key) if store else None
            if cached:
                details["cache_hit"] = True
                d = Decision(cached["decision"], "cache", cached["reason"], d.category, d.intent or "classifier")
            else:
                call = {
                    "tool": tool,
                    "command": args.get("CommandLine") if tool == "run_command" else None,
                    "args": None if tool == "run_command" else {k: (v[:800] if isinstance(v, str) else v) for k, v in (args or {}).items() if k not in ("toolAction", "toolSummary")},
                    "cwd": cwd,
                    "workspace": engine.ws_roots,
                    "why": why,
                    "context": read_context(transcript_path, int(ccfg.get("max_context_chars", 1500))),
                }
                t0 = time.time()
                try:
                    cd, creason, meta = llm_classify(ccfg, call)
                    meta["latency_ms"] = int((time.time() - t0) * 1000)
                    details["classifier"] = meta
                    if cd == "ask":
                        d = Decision("deny", "classifier", f"needs human approval: {creason}. Reply '> agy-approve {token}' in chat to proceed.", "classifier-ask", d.intent or "classifier")
                    elif cd == "deny":
                        d = Decision("deny", "classifier", creason or "classifier denied", "classifier-deny", d.intent or "classifier")
                    else:
                        d = Decision("allow", "classifier", creason or "classifier allowed", d.category, d.intent)
                    if store and d.decision in ("allow", "deny"):
                        store.cache_put(key, d.decision, d.reason)
                except ClassifierError as e:
                    details["classifier"] = {"error": str(e)[:300], "latency_ms": int((time.time() - t0) * 1000)}
                    on_err = ccfg.get("on_error", "deny")
                    err_msg = f"policy classifier unavailable ({str(e)[:120]}); reply '> agy-approve {token}' in chat to proceed or allow in policy"
                    d = Decision("force_ask" if on_err == "force_ask" else "deny", "classifier-error", err_msg, "classifier-error", "classifier-error")

    # escalation: repeated denials of the same intent
    if d.decision == "deny" and store is not None:
        esc = cfg.get("escalation", {})
        threshold = int(esc.get("threshold", 3))
        key = f"{tool}:{d.category}:{d.intent}"
        n = store.bump_denial(conv, key)
        details["escalation"] = n
        if n >= threshold:
            policy_hint = USER_POLICY
            d = Decision(
                esc.get("decision", "deny") if esc.get("decision") in ("deny", "force_ask") else "deny",
                d.layer,
                f"ESCALATED after {n} blocked attempts: {d.reason}. Stop retrying variations of this action. "
                f"Tell the user exactly what you wanted to run and why, and ask them to run it themselves or to allow it in the agy-auto policy ({policy_hint}).",
                d.category,
                d.intent,
            )
    return d, details


def run(payload: dict) -> dict:
    t0 = time.time()
    ws_roots = [w for w in (payload.get("workspacePaths") or []) if isinstance(w, str)]
    tool_call = payload.get("toolCall") or {}
    tool = tool_call.get("name") or ""
    args = tool_call.get("args") or {}
    conv = payload.get("conversationId") or ""
    record: dict = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "conversation_id": conv,
        "step_idx": payload.get("stepIdx"),
        "tool": tool,
        "args": {k: (v[:500] + "..." if isinstance(v, str) and len(v) > 500 else v) for k, v in args.items()} if isinstance(args, dict) else args,
        "workspace": ws_roots,
        "model": payload.get("modelName"),
    }
    store = None
    try:
        cfg, version, sources = load_policy(ws_roots)
        record["policy_version"] = version
        record["policy_sources"] = sources
        state_dir = os.environ.get("AGY_AUTO_STATE_DIR") or cfg.get("cache", {}).get("dir", "~/.gemini/config/agy-auto/state")
        audit_dir = os.environ.get("AGY_AUTO_AUDIT_DIR") or cfg.get("audit", {}).get("dir", "~/.gemini/config/agy-auto/audit")
        store = Store(state_dir, audit_dir, float(cfg.get("cache", {}).get("ttl_hours", 24)), version)
        use_classifier = bool(cfg.get("classifier", {}).get("endpoint")) and os.environ.get("AGY_AUTO_NO_CLASSIFIER") != "1"
        d, details = decide(payload, cfg, version, store, use_classifier)
        record.update(details)
        dry = cfg.get("mode") == "dry-run"
    except Exception as e:  # fail closed
        d = Decision("deny", "engine", f"policy engine error: {type(e).__name__}: {str(e)[:200]}", "engine-error", "engine-error")
        record["engine_error"] = repr(e)[:500]
        dry = False
    record["layer"] = d.layer
    record["would_decision"] = d.decision
    record["reason"] = d.reason
    record["dry_run"] = dry
    final = "allow" if dry else d.decision
    record["decision"] = final
    record["latency_ms"] = int((time.time() - t0) * 1000)
    if store is not None:
        try:
            store.audit(conv, record)
        except Exception as e:  # audit failure must not change the decision
            sys.stderr.write(f"agy-auto: audit write failed: {e}\n")
    out = {"decision": final}
    if final != "allow":
        out["reason"] = f"[agy-auto/{d.layer}] {d.reason}"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", help="run the deterministic layers on a command and print the Decision (no agy, no classifier)")
    ap.add_argument("--cwd")
    ap.add_argument("--ws", action="append", default=[])
    ap.add_argument("--tool", default="run_command")
    ap.add_argument("--args", help="JSON args for --check with a non-run_command tool")
    ap.add_argument("--payload", help="JSON file with a full hook payload (instead of stdin)")
    ns = ap.parse_args(argv)
    if ns.check is not None or ns.args:
        cfg, version, _ = load_policy(ns.ws)
        eng = Engine(cfg, ns.ws)
        if ns.tool == "run_command":
            d = eng.decide_command(ns.check, ns.cwd)
        else:
            d = eng.decide_tool(ns.tool, json.loads(ns.args or "{}"))
        print(json.dumps({"decision": d.decision, "layer": d.layer, "reason": d.reason, "category": d.category, "intent": d.intent}))
        return 0
    if ns.payload:
        with open(ns.payload) as fh:
            payload = json.load(fh)
    else:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as e:
            print(json.dumps({"decision": "deny", "reason": f"[agy-auto/engine] invalid hook payload: {e}"}))
            return 0
    out = run(payload)
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:  # absolutely fail closed
        sys.stdout.write(json.dumps({"decision": "deny", "reason": f"[agy-auto/engine] fatal: {type(e).__name__}: {str(e)[:200]}"}) + "\n")
        sys.stdout.flush()
        sys.exit(0)
