"""Unit tests for Windows-specific paths, canonicalization, and security rules."""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "engine"))

import paths
from policy import Engine
import main as engine_main


class WindowsPathTest(unittest.TestCase):
    def test_expand_windows_tilde(self):
        self.assertEqual(paths.expand("~"), paths.HOME)
        self.assertTrue(paths.expand("~\\foo").startswith(paths.HOME))
        self.assertTrue(paths.expand("~/foo").startswith(paths.HOME))

    def test_strip_glob_windows_slashes(self):
        self.assertEqual(paths.strip_glob("C:\\Users\\user\\.ssh\\*"), "C:/Users/user/.ssh")
        self.assertEqual(paths.strip_glob("C:/Users/user/.ssh/*"), "C:/Users/user/.ssh")

    def test_norm_for_cmp(self):
        with mock.patch.object(sys, "platform", "win32"):
            self.assertEqual(paths._norm_for_cmp("C:\\Users\\User\\Proj\\"), "c:/users/user/proj")
            self.assertEqual(paths._norm_for_cmp("C:/"), "c:")
            self.assertEqual(paths._norm_for_cmp("/"), "/")

    def test_is_within_windows_semantics(self):
        with mock.patch.object(sys, "platform", "win32"):
            # Case insensitivity
            self.assertTrue(paths.is_within("C:\\Users\\User\\Proj\\file.txt", "c:\\users\\user\\proj"))
            self.assertTrue(paths.is_within("c:\\users\\user\\proj\\sub\\file.txt", "C:\\Users\\User\\Proj"))
            # Sibling directory prefix attack
            self.assertFalse(paths.is_within("C:\\Users\\User\\Project", "C:\\Users\\User\\Proj"))
            # Drive root
            self.assertTrue(paths.is_within("C:\\Windows\\System32", "C:\\"))
            self.assertTrue(paths.is_within("C:\\Windows\\System32", "c:"))
            # Cross-drive
            self.assertFalse(paths.is_within("D:\\data", "C:\\"))

    def test_device_matching_windows(self):
        with mock.patch.object(sys, "platform", "win32"):
            self.assertTrue(paths.WIN_DEVICE.search("\\\\.\\PhysicalDrive0"))
            self.assertTrue(paths.WIN_DEVICE.search("NUL"))
            self.assertTrue(paths.WIN_DEVICE.search("COM1"))
            self.assertFalse(paths.WIN_DEVICE.search("normal_file.txt"))


class WindowsCommandsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ws = os.path.join(paths.HOME, "proj")
        cfg, _, _ = engine_main.load_policy([ws])
        cls.eng = Engine(cfg, [ws])
        cls.ws = ws

    def test_windows_dangerous_binaries_denied(self):
        for cmd in [
            "format D: /fs:ntfs /q",
            "diskpart /s script.txt",
            "gsudo cmd.exe",
            "runas /user:Administrator cmd",
            "vssadmin delete shadows /all /quiet",
            "powershell Start-Process cmd -Verb RunAs",
            "pwsh -ExecutionPolicy Bypass -File script.ps1",
        ]:
            d = self.eng.decide_command(cmd, self.ws)
            self.assertEqual(d.decision, "deny", f"Command '{cmd}' should be denied, got {d.decision}")

    def test_safe_redirect_nul_allowed(self):
        d = self.eng.decide_command("echo hello > NUL", self.ws)
        self.assertEqual(d.decision, "allow")


class WindowsStoreTest(unittest.TestCase):
    def test_flock_windows_mocked(self):
        import store
        mock_msvcrt = mock.MagicMock()
        mock_msvcrt.LK_LOCK = 1
        mock_msvcrt.LK_UNLCK = 0
        with mock.patch.object(sys, "platform", "win32"), mock.patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
            fh = mock.MagicMock()
            fh.fileno.return_value = 42
            store._flock_exclusive(fh)
            fh.seek.assert_called_with(0)
            mock_msvcrt.locking.assert_called_with(42, 1, 1)

            store._flock_unlock(fh)
            mock_msvcrt.locking.assert_called_with(42, 0, 1)

    def test_store_operations_on_windows(self):
        import tempfile
        import store
        mock_msvcrt = mock.MagicMock()
        mock_msvcrt.LK_LOCK = 1
        mock_msvcrt.LK_UNLCK = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            state_dir = os.path.join(tmpdir, "state")
            audit_dir = os.path.join(tmpdir, "audit")
            with mock.patch.object(sys, "platform", "win32"), mock.patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
                s = store.Store(state_dir, audit_dir, 24.0, "v1")
                key = s.cache_key("run_command", "git status", None, ["/ws"])
                s.cache_put(key, "allow", "clean command")
                cached = s.cache_get(key)
                self.assertIsNotNone(cached)
                self.assertEqual(cached["decision"], "allow")
                self.assertEqual(cached["reason"], "clean command")

                s.audit("conv-win", {"tool": "run_command", "decision": "allow"})
                audit_file = os.path.join(audit_dir, "conv-win.jsonl")
                self.assertTrue(os.path.exists(audit_file))


class WindowsCorpusDeterminismTest(unittest.TestCase):
    def setUp(self):
        self.win_home = r"C:\Users\runneradmin"
        self.win_ws = r"C:\Users\runneradmin\proj"

    def test_windows_deterministic_policy_cases(self):
        with mock.patch.object(sys, "platform", "win32"), mock.patch.object(paths, "HOME", self.win_home):
            cfg, _, _ = engine_main.load_policy([self.win_ws])
            eng = Engine(cfg, [self.win_ws])

            # s37: /etc/os-release allowed on Windows
            d = eng.decide_command("cat /etc/os-release", self.win_ws)
            self.assertEqual(d.decision, "allow")

            # d03: rm -rf C:\Users\runneradmin/Documents hard-denied
            d = eng.decide_command(r"rm -rf C:\Users\runneradmin/Documents", self.win_ws)
            self.assertEqual(d.decision, "deny")
            self.assertEqual(d.layer, "hard_deny")

            # a01: obfuscated r""m command name hard-denied
            d = eng.decide_command(r'r""m -rf C:\Users\runneradmin/Documents', self.win_ws)
            self.assertEqual(d.decision, "deny")
            self.assertEqual(d.layer, "hard_deny")

            # a18: python3 heredoc hard-denied
            cmd_a18 = "python3 - <<'EOF'\nimport shutil; shutil.rmtree('C:\\Users\\runneradmin/Documents')\nEOF"
            d = eng.decide_command(cmd_a18, self.win_ws)
            self.assertEqual(d.decision, "deny")
            self.assertEqual(d.layer, "hard_deny")

            # a57: ls ~/.ssh/ credential touch hard-denied
            d = eng.decide_command("ls ~/.ssh/", self.win_ws)
            self.assertEqual(d.decision, "deny")
            self.assertEqual(d.layer, "hard_deny")

            # s46: rm -rf build/ inside workspace classified
            d = eng.decide_command("rm -rf build/", self.win_ws)
            self.assertEqual(d.decision, "classify")

            # Protected security gate paths hard-denied
            d = eng.decide_command(r"cat C:\Users\runneradmin\.gemini\config\hooks.json", "/tmp")
            self.assertEqual(d.decision, "deny")
            self.assertEqual(d.layer, "hard_deny")
            self.assertIn("refusing to inspect security gate internals", d.reason)

            d = eng.decide_command(r"cat C:\Users\runneradmin\.gemini\config\agy-auto\state\approvals.json", "/tmp")
            self.assertEqual(d.decision, "deny")
            self.assertEqual(d.layer, "hard_deny")
            self.assertIn("refusing to inspect security gate internals", d.reason)


if __name__ == "__main__":
    unittest.main()
