"""Dedicated adversarial bypass test suite for agy-auto.

Tests the gate's resilience against:
1. Self-protection tampering (modifying or deleting hook.sh, engine/*.py, hooks.json, policy.toml)
2. Ambient authority leakage (reusing approvals, conversational fuzzy matches, parameter tampering)
3. Sub-invocation escapes (calling agy with --dangerously-skip-permissions)
4. TOCTOU cache poisoning (modifying scripts across cached decisions)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "engine"))

import main as engine_main  # noqa: E402
from paths import HOME  # noqa: E402


class AdversarialBypassTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agy_auto_bypass_")
        self.state_dir = os.path.join(self.tmp, "state")
        self.audit_dir = os.path.join(self.tmp, "audit")
        self.policy_file = os.path.join(self.tmp, "policy.toml")
        with open(self.policy_file, "w") as fh:
            fh.write(
                f'[cache]\ndir = "{self.state_dir}"\n'
                f'[audit]\ndir = "{self.audit_dir}"\n'
            )
        os.environ["AGY_AUTO_POLICY"] = self.policy_file
        os.environ["AGY_AUTO_CLASSIFIER_ENDPOINT"] = "http://127.0.0.1:1"  # Fail-closed offline by default
        os.environ["AGY_AUTO_HONOR_DANGEROUSLY_SKIP"] = "0"
        os.environ.pop("AGY_AUTO_FORCE_DANGEROUSLY_SKIP", None)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("AGY_AUTO_POLICY", None)
        os.environ.pop("AGY_AUTO_CLASSIFIER_ENDPOINT", None)
        os.environ.pop("AGY_AUTO_HONOR_DANGEROUSLY_SKIP", None)

    def payload(self, cmd: str, ws: str = ROOT, cwd: str = ROOT, conv: str = "bypass_conv") -> dict:
        return {
            "toolCall": {"name": "run_command", "args": {"CommandLine": cmd, "Cwd": cwd}},
            "conversationId": conv,
            "workspacePaths": [ws],
        }

    # =========================================================================
    # 1. GATE SELF-PROTECTION
    # =========================================================================
    def test_overwrite_hook_sh_via_redirection(self):
        hook_path = os.path.join(ROOT, "hook.sh")
        out = engine_main.run(self.payload(f"echo 'exit 0' > {hook_path}"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])
        self.assertIn("self-protection", out["reason"])

    def test_append_to_engine_main_via_redirection(self):
        main_path = os.path.join(ROOT, "engine", "main.py")
        out = engine_main.run(self.payload(f"echo '# exploit' >> {main_path}"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])

    def test_write_to_file_tool_against_policy_file(self):
        pol_path = os.path.join(ROOT, "policy", "default.toml")
        pl = {
            "toolCall": {"name": "write_to_file", "args": {"TargetFile": pol_path, "CodeContent": "mode='dry-run'"}},
            "conversationId": "c_self",
            "workspacePaths": [ROOT],
        }
        out = engine_main.run(pl)
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])

    def test_delete_hook_via_rm(self):
        hook_path = os.path.join(ROOT, "hook.sh")
        out = engine_main.run(self.payload(f"rm {hook_path}"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])

    def test_delete_global_hooks_json_via_rm(self):
        hooks_json = os.path.expanduser("~/.gemini/config/hooks.json")
        out = engine_main.run(self.payload(f"rm {hooks_json}", ws=HOME))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])

    def test_find_delete_over_engine_root(self):
        out = engine_main.run(self.payload("find . -name '*.py' -delete", ws=ROOT, cwd=ROOT))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("[agy-auto/hard_deny]", out["reason"])

    # =========================================================================
    # 2. AMBIENT AUTHORITY & APPROVAL BOUNDING
    # =========================================================================
    def test_conversational_words_do_not_authorize(self):
        transcript_file = os.path.join(self.tmp, "transcript.jsonl")
        with open(transcript_file, "w") as fh:
            fh.write(json.dumps({"type": "USER_INPUT", "content": "Sure, yes, I approve and confirm, please proceed!"}) + "\n")

        pl = self.payload("pip install untrusted-package", ws=self.tmp, cwd=self.tmp)
        pl["transcriptPath"] = transcript_file
        out = engine_main.run(pl)
        self.assertEqual(out["decision"], "deny")
        self.assertIn("reply '> agy-approve", out["reason"])

    def test_approval_token_cannot_be_reused_single_use(self):
        transcript_file = os.path.join(self.tmp, "transcript.jsonl")
        pl = self.payload("pip install requests", ws=self.tmp, cwd=self.tmp)
        pl["transcriptPath"] = transcript_file

        # Step 1: Initial denial produces token
        out1 = engine_main.run(pl)
        m = re.search(r"agy-approve\s+([0-9a-fA-F]{6,12})", out1["reason"])
        self.assertIsNotNone(m)
        token = m.group(1)

        # Step 2: Approve the action
        with open(transcript_file, "w") as fh:
            fh.write(json.dumps({"type": "USER_INPUT", "content": f"> agy-approve {token}"}) + "\n")

        # First execution succeeds
        out2 = engine_main.run(pl)
        self.assertEqual(out2["decision"], "allow")

        # Subsequent execution with the same transcript MUST fail (consumed token)
        out3 = engine_main.run(pl)
        self.assertEqual(out3["decision"], "deny")

    def test_approval_token_bound_to_exact_command(self):
        transcript_file = os.path.join(self.tmp, "transcript.jsonl")
        pl1 = self.payload("pip install requests", ws=self.tmp, cwd=self.tmp)
        pl1["transcriptPath"] = transcript_file

        # Generate token for pl1
        out1 = engine_main.run(pl1)
        m = re.search(r"agy-approve\s+([0-9a-fA-F]{6,12})", out1["reason"])
        token = m.group(1)

        # User approves token for pl1
        with open(transcript_file, "w") as fh:
            fh.write(json.dumps({"type": "USER_INPUT", "content": f"> agy-approve {token}"}) + "\n")

        # Attacker tries to use token to execute a different command (pl2)
        pl2 = self.payload("pip install malicious-pkg", ws=self.tmp, cwd=self.tmp)
        pl2["transcriptPath"] = transcript_file
        out2 = engine_main.run(pl2)
        self.assertEqual(out2["decision"], "deny")

    def test_approval_token_bound_to_cwd(self):
        transcript_file = os.path.join(self.tmp, "transcript.jsonl")
        dir_a = os.path.join(self.tmp, "dir_a")
        dir_b = os.path.join(self.tmp, "dir_b")
        os.makedirs(dir_a, exist_ok=True)
        os.makedirs(dir_b, exist_ok=True)

        pl1 = self.payload("git status", ws=self.tmp, cwd=dir_a)
        pl1["transcriptPath"] = transcript_file

        out1 = engine_main.run(pl1)
        pl_classify = self.payload("pip install requests", ws=self.tmp, cwd=dir_a)
        pl_classify["transcriptPath"] = transcript_file
        out_c = engine_main.run(pl_classify)
        m = re.search(r"agy-approve\s+([0-9a-fA-F]{6,12})", out_c["reason"])
        token = m.group(1)

        with open(transcript_file, "w") as fh:
            fh.write(json.dumps({"type": "USER_INPUT", "content": f"> agy-approve {token}"}) + "\n")

        # Same command in dir_b must not inherit approval
        pl_diff_cwd = self.payload("pip install requests", ws=self.tmp, cwd=dir_b)
        pl_diff_cwd["transcriptPath"] = transcript_file
        out_diff = engine_main.run(pl_diff_cwd)
        self.assertEqual(out_diff["decision"], "deny")

    # =========================================================================
    # 3. SUBPROCESS & CLI ESCAPES
    # =========================================================================
    def test_agy_dangerously_skip_denied(self):
        out = engine_main.run(self.payload("agy -p 'echo 123' --dangerously-skip-permissions"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("nested agy invocation with permission bypass", out["reason"])

    def test_antigravity_cli_dangerously_skip_denied(self):
        out = engine_main.run(self.payload("antigravity-cli --dangerously-skip-permissions -p 'test'"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("nested agy invocation with permission bypass", out["reason"])

    def test_antigravity_dangerously_skip_denied(self):
        out = engine_main.run(self.payload("antigravity -p 'test' --dangerously-skip-permissions"))
        self.assertEqual(out["decision"], "deny")
        self.assertIn("nested agy invocation with permission bypass", out["reason"])

    # =========================================================================
    # 4. TOCTOU SCRIPT CACHE POISONING
    # =========================================================================
    def test_toctou_script_content_change_invalidates_cache(self):
        script_file = os.path.join(self.tmp, "task.py")
        with open(script_file, "w") as fh:
            fh.write("print('safe task')\n")

        # Fake classifier cache entry for script v1
        store = engine_main.Store(self.state_dir, self.audit_dir, 24, "test_v")
        hash_v1 = engine_main.get_target_script_hash("run_command", {"CommandLine": f"python3 {script_file}"}, self.tmp)
        key_v1 = store.cache_key("run_command", f"python3 {script_file}", self.tmp, [self.tmp], extra_hash=hash_v1)
        store.cache_put(key_v1, "allow", "v1 safe")

        # Check that v1 gets cache hit
        cached_result = store.cache_get(key_v1)
        self.assertIsNotNone(cached_result)
        self.assertEqual(cached_result["decision"], "allow")

        # Now script is rewritten with attacker payload
        with open(script_file, "w") as fh:
            fh.write("import os; os.remove('/tmp/victim')\n")

        hash_v2 = engine_main.get_target_script_hash("run_command", {"CommandLine": f"python3 {script_file}"}, self.tmp)
        key_v2 = store.cache_key("run_command", f"python3 {script_file}", self.tmp, [self.tmp], extra_hash=hash_v2)

        # Keys MUST differ
        self.assertNotEqual(key_v1, key_v2)
        # Looking up v2 in cache MUST be a cache miss
        self.assertIsNone(store.cache_get(key_v2))


if __name__ == "__main__":
    unittest.main()
