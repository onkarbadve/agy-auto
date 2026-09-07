"""Unit tests for the agy-auto policy engine. No agy, no LLM involved.

Run:  python3 -m unittest -v tests/test_engine.py   (from agy-auto/)
"""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "engine"))

import main as engine_main  # noqa: E402
import shparse  # noqa: E402
from policy import Engine  # noqa: E402

HOME = os.path.expanduser("~")
WS = os.path.join(HOME, "proj")
CORPUS = os.path.join(HERE, "corpus.jsonl")


USER = os.path.basename(HOME)


def load_corpus():
    with open(CORPUS) as fh:
        raw = fh.read().replace("/home/user", HOME).replace("rm -rf user", f"rm -rf {USER}")
    return [json.loads(l) for l in raw.splitlines() if l.strip()]


def run_case(eng: Engine, case: dict):
    if "tool" in case:
        return eng.decide_tool(case["tool"], case["args"])
    return eng.decide_command(case["cmd"], case.get("cwd", WS))


class CorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg, version, _ = engine_main.load_policy([WS])
        cls.eng = Engine(cfg, [WS])
        cls.cases = load_corpus()

    def test_corpus_size(self):
        self.assertGreaterEqual(len(self.cases), 60)
        buckets = {c["bucket"] for c in self.cases}
        self.assertEqual(buckets, {"safe", "destructive", "adversarial"})

    def test_every_case(self):
        failures = []
        false_allows = []
        for c in self.cases:
            d = run_case(self.eng, c)
            exp = c["expect"]
            ok = (d.decision == exp) if exp != "not_allow" else (d.decision != "allow")
            if c["bucket"] in ("destructive", "adversarial") and d.decision == "allow":
                false_allows.append((c["id"], c.get("cmd") or c.get("tool"), d.reason))
            if not ok:
                failures.append(f"{c['id']}: expected {exp}, got {d.decision} [{d.layer}] {d.reason} :: {c.get('cmd') or c.get('tool')}")
        report = ["", "=== corpus results ===", f"cases: {len(self.cases)}  failures: {len(failures)}  FALSE ALLOWS: {len(false_allows)}"]
        report += ["FALSE ALLOW: " + " | ".join(map(str, fa)) for fa in false_allows]
        report += failures
        print("\n".join(report))
        self.assertEqual(false_allows, [], "false allows are unacceptable")
        self.assertEqual(failures, [])


class ParserTest(unittest.TestCase):
    def names(self, cmd):
        return [s.name for s in shparse.iter_simple(shparse.parse(cmd))]

    def test_shapes(self):
        self.assertEqual(self.names("a | b && c; d || e"), ["a", "b", "c", "d", "e"])
        self.assertEqual(self.names("echo \"$(rm x)\" `ls`"), ["echo", "rm", "ls"])
        self.assertEqual(self.names("for f in *; do rm $f; done"), ["rm"])
        self.assertEqual(self.names("f() { rm x; }; f"), ["rm", "f"])
        self.assertEqual(self.names("cat <<EOF\nrm -rf /\nEOF"), ["cat"])
        self.assertTrue(shparse.parse("if true; then ls; fi").complex)

    def test_unterminated_raises(self):
        with self.assertRaises(shparse.ParseError):
            shparse.parse("echo 'unterminated")
        with self.assertRaises(shparse.ParseError):
            shparse.parse("echo $(ls")

    def test_static_and_dynamic(self):
        sc = shparse.parse("cp \"a b\" $X 'c'")
        words = list(shparse.iter_simple(sc))[0].words
        self.assertEqual(words[1].static(), "a b")
        self.assertIsNone(words[2].static())
        self.assertTrue(words[2].dynamic)
        self.assertEqual(words[3].static(), "c")

    def test_ansi_c_decoding(self):
        w = list(shparse.iter_simple(shparse.parse("echo $'\\x72\\x6d'")))[0].words[1]
        self.assertEqual(w.static(), "rm")


class _Handler(http.server.BaseHTTPRequestHandler):
    response = {"decision": "allow", "reason": "mock"}
    calls = 0
    last_auth_header = None

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        _Handler.calls += 1
        _Handler.last_auth_header = self.headers.get("Authorization")
        body = json.dumps({"choices": [{"message": {"content": json.dumps(_Handler.response)}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}, "model": "mock"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class RunTest(unittest.TestCase):
    """main.run() with a mock classifier: cache, escalation, fail-closed, dry-run, audit."""

    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agy-auto-test-")
        os.environ["AGY_AUTO_STATE_DIR"] = os.path.join(self.tmp, "state")
        os.environ["AGY_AUTO_AUDIT_DIR"] = os.path.join(self.tmp, "audit")
        os.environ["AGY_AUTO_CLASSIFIER_ENDPOINT"] = f"http://127.0.0.1:{self.port}/v1/chat/completions"
        os.environ.pop("AGY_AUTO_DRY_RUN", None)
        os.environ["AGY_AUTO_HONOR_DANGEROUSLY_SKIP"] = "0"
        os.environ.pop("AGY_AUTO_FORCE_DANGEROUSLY_SKIP", None)
        _Handler.response = {"decision": "allow", "reason": "mock allow"}
        _Handler.calls = 0

    def payload(self, cmd, conv="conv-1", step=1):
        return {"toolCall": {"name": "run_command", "args": {"CommandLine": cmd, "Cwd": WS}}, "conversationId": conv, "stepIdx": step, "workspacePaths": [WS]}

    def audit_records(self, conv="conv-1"):
        with open(os.path.join(self.tmp, "audit", f"{conv}.jsonl")) as fh:
            return [json.loads(l) for l in fh]

    def test_fast_allow_no_classifier_call(self):
        out = engine_main.run(self.payload("ls -la"))
        self.assertEqual(out, {"decision": "allow"})
        self.assertEqual(_Handler.calls, 0)
        rec = self.audit_records()[-1]
        self.assertEqual(rec["layer"], "fast_allow")
        self.assertLess(rec["latency_ms"], 1500)

    def test_hard_deny_has_reason(self):
        out = engine_main.run(self.payload(f"rm -rf {HOME}/Documents"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])
        self.assertEqual(_Handler.calls, 0)

    def test_classifier_allow_and_cache(self):
        out1 = engine_main.run(self.payload("pip install requests"))
        out2 = engine_main.run(self.payload("pip   install requests"))
        self.assertEqual(out1["decision"], "allow")
        self.assertEqual(out2["decision"], "allow")
        self.assertEqual(_Handler.calls, 1, "second call must hit the cache (normalized whitespace)")
        recs = self.audit_records()
        self.assertEqual(recs[0]["layer"], "classifier")
        self.assertEqual(recs[0]["classifier"]["model"], "mock")
        self.assertEqual(recs[0]["classifier"]["prompt_tokens"], 10)
        self.assertTrue(recs[1]["cache_hit"])

    def test_classifier_ask_becomes_deny(self):
        _Handler.response = {"decision": "ask", "reason": "unsure"}
        out = engine_main.run(self.payload("pip install requests"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("needs human approval", out["reason"])

    def test_classifier_unreachable_fails_closed(self):
        os.environ["AGY_AUTO_CLASSIFIER_ENDPOINT"] = "http://127.0.0.1:1/v1/chat/completions"
        out = engine_main.run(self.payload("pip install requests"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("classifier unavailable", out["reason"])
        self.assertEqual(self.audit_records()[-1]["layer"], "classifier-error")

    def test_cloud_classifier_missing_api_key(self):
        os.environ["AGY_AUTO_CLASSIFIER_ENDPOINT"] = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        os.environ.pop("GEMINI_API_KEY", None)
        out = engine_main.run(self.payload("pip install requests"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("API key missing", out["reason"])
        self.assertIn("GEMINI_API_KEY", out["reason"])
        self.assertEqual(self.audit_records()[-1]["layer"], "classifier-error")

    def test_classifier_auth_header_forwarded(self):
        os.environ["GEMINI_API_KEY"] = "test-secret-key"
        policy_file = os.path.join(self.tmp, "auth.toml")
        with open(policy_file, "w") as fh:
            fh.write(f'[classifier]\nendpoint = "http://127.0.0.1:{self.port}/v1/chat/completions"\napi_key_env = "GEMINI_API_KEY"\n')
        os.environ["AGY_AUTO_POLICY"] = policy_file
        try:
            out = engine_main.run(self.payload("pip install requests"))
            self.assertEqual(out["decision"], "allow")
            self.assertEqual(_Handler.last_auth_header, "Bearer test-secret-key")
        finally:
            os.environ.pop("AGY_AUTO_POLICY", None)
            os.environ.pop("GEMINI_API_KEY", None)

    def test_escalation_after_threshold(self):
        reasons = []
        for i in range(4):
            out = engine_main.run(self.payload(f"rm -rf {HOME}/Documents", step=i))
            reasons.append(out["reason"])
        self.assertNotIn("ESCALATED", reasons[0])
        self.assertNotIn("ESCALATED", reasons[1])
        self.assertIn("ESCALATED after 3", reasons[2])
        self.assertIn("ESCALATED after 4", reasons[3])
        self.assertTrue(all(r.startswith("[agy-auto/") for r in reasons))

    def test_escalation_is_per_intent(self):
        _Handler.response = {"decision": "ask", "reason": "unsure"}
        r = []
        for cmd in ("pip install requests", "git push origin dev", "ssh pi uptime", "pip install requests"):
            r.append(engine_main.run(self.payload(cmd))["reason"])
        self.assertTrue(all("ESCALATED" not in x for x in r), r)
        rec = self.audit_records()
        self.assertEqual([x["escalation"] for x in rec], [1, 1, 1, 1])

    def test_dry_run_allows_but_logs(self):
        os.environ["AGY_AUTO_DRY_RUN"] = "1"
        out = engine_main.run(self.payload(f"rm -rf {HOME}/Documents"))
        self.assertEqual(out, {"decision": "allow"})
        rec = self.audit_records()[-1]
        self.assertTrue(rec["dry_run"])
        self.assertEqual(rec["would_decision"], "deny")
        self.assertEqual(rec["decision"], "allow")

    def test_garbage_payload_denies(self):
        out = engine_main.run({"toolCall": {"name": "run_command", "args": {}}})
        self.assertEqual(out["decision"], "deny")

    def test_hook_script_end_to_end(self):
        env = dict(os.environ)
        env["AGY_AUTO_NO_CLASSIFIER"] = "1"
        p = subprocess.run([os.path.join(ROOT, "hook.sh")], input=json.dumps(self.payload("git push --force origin main")), capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(p.returncode, 0)
        out = json.loads(p.stdout)
        self.assertEqual(out["decision"], "deny")
        p = subprocess.run([os.path.join(ROOT, "hook.sh")], input="not json", capture_output=True, text=True, env=env, timeout=20)
        self.assertEqual(json.loads(p.stdout)["decision"], "deny")

    def test_no_workspace_headless_shape(self):
        pl = {"toolCall": {"name": "run_command", "args": {"CommandLine": "rm -rf x", "Cwd": "."}}, "conversationId": "c2", "workspacePaths": []}
        out = engine_main.run(pl)
        self.assertEqual(out["decision"], "deny")
        pl["toolCall"]["args"]["CommandLine"] = "ls"
        self.assertEqual(engine_main.run(pl)["decision"], "allow")

    def test_dangerously_skip_bypasses_when_active(self):
        os.environ["AGY_AUTO_HONOR_DANGEROUSLY_SKIP"] = "1"
        os.environ["AGY_AUTO_FORCE_DANGEROUSLY_SKIP"] = "1"
        out = engine_main.run(self.payload(f"rm -rf {HOME}/Documents"))
        self.assertEqual(out, {"decision": "allow"})
        rec = self.audit_records()[-1]
        self.assertEqual(rec["layer"], "dangerously_skip")
        self.assertEqual(rec["decision"], "allow")
        self.assertIn("dangerously-skip-permissions", rec["reason"])

    def test_dangerously_skip_disabled_by_config(self):
        os.environ["AGY_AUTO_HONOR_DANGEROUSLY_SKIP"] = "1"
        os.environ["AGY_AUTO_FORCE_DANGEROUSLY_SKIP"] = "1"
        policy_file = os.path.join(self.tmp, "no_skip.toml")
        with open(policy_file, "w") as fh:
            fh.write("honor_dangerously_skip_permissions = false\n")
        os.environ["AGY_AUTO_POLICY"] = policy_file
        try:
            out = engine_main.run(self.payload(f"rm -rf {HOME}/Documents"))
            self.assertEqual(out["decision"], "deny")
            self.assertIn("[agy-auto/hard_deny]", out["reason"])
        finally:
            os.environ.pop("AGY_AUTO_POLICY", None)


if __name__ == "__main__":
    unittest.main()
