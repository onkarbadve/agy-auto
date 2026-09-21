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


if __name__ == "__main__":
    unittest.main()
