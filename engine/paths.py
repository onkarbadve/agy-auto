"""Path resolution and classification against the policy's path lists."""
from __future__ import annotations

import os
import re
import sys

HOME = os.path.expanduser("~")
GLOB_CHARS = re.compile(r"[*?\[{]")
WIN_DEVICE = re.compile(r"^(?:\\\\(?:\.|\?)\\|(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$))", re.IGNORECASE)


def expand(p: str) -> str:
    if p == "~":
        return HOME
    if p.startswith("~/") or p.startswith("~\\"):
        return HOME + p[1:]
    return p


def _get_long_path_name(p: str) -> str:
    if sys.platform != "win32":
        return p
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        res = ctypes.windll.kernel32.GetLongPathNameW(p, buf, 1024)
        if 0 < res < 1024:
            return buf.value
    except Exception:
        pass
    return p


def _realpath_lenient(p: str) -> str:
    try:
        if sys.platform == "win32":
            p = _get_long_path_name(p)
        if os.path.lexists(p):
            return os.path.realpath(p)
        parent, name = os.path.split(p)
        if parent == p or not parent:
            return p
        return os.path.join(_realpath_lenient(parent), name)
    except OSError:
        return p


def resolve(p: str, cwd: str | None) -> str | None:
    """Absolute, normalized, symlink-resolved (where it exists) path, or None."""
    if not p:
        return None
    p = expand(p)
    if not os.path.isabs(p):
        if not cwd or not os.path.isabs(cwd):
            return None
        p = os.path.join(cwd, p)
    return _realpath_lenient(os.path.normpath(p))


def strip_glob(p: str) -> str:
    """Return the literal directory prefix of a glob pattern ('~/.ssh/*' -> '~/.ssh')."""
    m = GLOB_CHARS.search(p)
    if not m:
        return p
    head = p[:m.start()].replace("\\", "/")
    return head.rsplit("/", 1)[0] if "/" in head else "."


def _norm_for_cmp(p: str) -> str:
    p = p.replace("\\", "/").rstrip("/")
    if sys.platform == "win32":
        p = p.lower()
    return p or "/"


def is_within(path: str, root: str) -> bool:
    p = _norm_for_cmp(path)
    r = _norm_for_cmp(root)
    if r == "/" or (sys.platform == "win32" and re.match(r"^[a-z]:/?$", r)):
        return p == r or p.startswith(r.rstrip("/") + "/")
    return p == r or p.startswith(r + "/")


def glob_to_regex(pat: str) -> re.Pattern:
    pat = expand(pat)
    out = ""
    i = 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i) or (sys.platform == "win32" and pat.startswith("**\\", i)):
            out += "(?:.*[/\\\\])?" if sys.platform == "win32" else "(?:.*/)?"
            i += 3
            continue
        if pat.startswith("**", i):
            out += ".*"
            i += 2
            continue
        if c == "*":
            out += "[^/\\\\]*" if sys.platform == "win32" else "[^/]*"
        elif c == "?":
            out += "[^/\\\\]" if sys.platform == "win32" else "[^/]"
        elif sys.platform == "win32" and c in ("/", "\\"):
            out += "[/\\\\]"
        else:
            out += re.escape(c)
        i += 1
    flags = re.IGNORECASE if sys.platform == "win32" else 0
    if pat.endswith("/**") or (sys.platform == "win32" and pat.endswith("**")):
        base = re.escape(pat[:-3])
        return re.compile(f"^(?:{out}|{base})$", flags)
    return re.compile(f"^{out}$", flags)


class PathPolicy:
    def __init__(self, cfg: dict, ws_roots: list[str]):
        paths = cfg.get("paths", {})
        wsc = cfg.get("workspace", {})
        self.ws_roots = [r for r in (resolve(w, None) for w in ws_roots) if r]
        if os.environ.get("AGY_AUTO_DISABLE_SELF_PROTECTION") == "1":
            self.self_root = None
        else:
            self.self_root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
        self.is_self_workspace = (
            any(is_within(r, self.self_root) for r in self.ws_roots)
            if self.self_root
            else False
        )
        self.gate_paths = [
            expand("~/.gemini/config/agy-auto"),
            expand("~/.gemini/config/hooks.json"),
        ]
        cache_dir = cfg.get("cache", {}).get("dir")
        if cache_dir:
            self.gate_paths.append(expand(cache_dir))
        audit_dir = cfg.get("audit", {}).get("dir")
        if audit_dir:
            self.gate_paths.append(expand(audit_dir))
        self.gate_paths = [resolve(gp, None) or expand(gp) for gp in self.gate_paths if gp]
        self.credential = [glob_to_regex(p) for p in paths.get("credential", [])]
        self.credential_exc = [glob_to_regex(p) for p in paths.get("credential_exceptions", [])]
        self.system_write = [glob_to_regex(p) for p in paths.get("system_write", [])]
        self.system_write_exc = [glob_to_regex(p) for p in paths.get("system_write_exceptions", [])]
        self.device = [glob_to_regex(p) for p in paths.get("device", [])]
        self.scratch = [resolve(s, None) for s in wsc.get("scratch", [])]
        self.protected = list(wsc.get("protected", []))
        self.sensitive = list(wsc.get("sensitive", []))
        # literal prefixes of credential patterns, for "ancestor" checks
        self.cred_prefixes = []
        for p in paths.get("credential", []):
            p = expand(p)
            if p.startswith("**") or not (p.startswith("/") or (sys.platform == "win32" and re.match(r"^[a-zA-Z]:", p))):
                continue
            self.cred_prefixes.append(strip_glob(p).rstrip("/\\"))

    # -- primitives
    def is_self_path(self, path: str) -> bool:
        if not self.self_root:
            return False
        return is_within(path, self.self_root)

    def is_gate_internal(self, path: str) -> bool:
        if os.environ.get("AGY_AUTO_DISABLE_SELF_PROTECTION") == "1":
            return False
        if self.self_root and not self.is_self_workspace and is_within(path, self.self_root):
            return True
        for gp in self.gate_paths:
            if gp and is_within(path, gp):
                return True
        return False

    def is_credential(self, path: str) -> bool:
        if any(r.match(path) for r in self.credential_exc):
            return False
        return any(r.match(path) for r in self.credential)

    def is_credential_ancestor(self, path: str) -> bool:
        path = path.rstrip("/") or "/"
        return any(is_within(pref, path) and pref != path for pref in self.cred_prefixes)

    def is_device(self, path: str) -> bool:
        if sys.platform == "win32" and WIN_DEVICE.search(path):
            return True
        return any(r.match(path) for r in self.device)

    def is_system_write(self, path: str) -> bool:
        if any(r.match(path) for r in self.system_write_exc):
            return False
        if self.is_self_path(path) or self.is_gate_internal(path):
            return True
        return any(r.match(path) for r in self.system_write)

    def ws_root_of(self, path: str) -> str | None:
        for r in self.ws_roots:
            if is_within(path, r):
                return r
        return None

    def is_scratch(self, path: str) -> bool:
        return any(s and is_within(path, s) for s in self.scratch)

    def ws_relative_flag(self, path: str, names: list[str]) -> bool:
        root = self.ws_root_of(path)
        if not root:
            return False
        rel = os.path.relpath(path, root)
        if sys.platform == "win32":
            rel = rel.replace("\\", "/").lower()
            names = [n.replace("\\", "/").lower() for n in names]
        else:
            rel = rel.replace("\\", "/")
        for n in names:
            if rel == n or rel.startswith(n.rstrip("/") + "/"):
                return True
        return False

    def is_protected_ws(self, path: str) -> bool:
        return self.ws_relative_flag(path, self.protected)

    def is_sensitive_ws(self, path: str) -> bool:
        return self.ws_relative_flag(path, self.sensitive)

    def is_ws_root(self, path: str) -> bool:
        norm = _norm_for_cmp(path)
        return any(norm == _norm_for_cmp(r) for r in self.ws_roots)

    def classify(self, path: str) -> set[str]:
        """Tags for an absolute path."""
        tags = set()
        if self.is_device(path):
            tags.add("device")
        if self.is_credential(path):
            tags.add("credential")
        if self.is_self_path(path):
            tags.add("self_path")
        if self.is_gate_internal(path):
            tags.add("gate_internal")
        if self.is_system_write(path):
            tags.add("system_write")
        root = self.ws_root_of(path)
        if root:
            tags.add("inside_ws")
            if self.is_ws_root(path):
                tags.add("ws_root")
            if self.is_protected_ws(path):
                tags.add("protected_ws")
            if self.is_sensitive_ws(path):
                tags.add("sensitive_ws")
        elif self.is_scratch(path):
            tags.add("scratch")
        else:
            tags.add("outside_ws")
            if is_within(path, HOME):
                tags.add("home")
        is_root = (re.match(r"^[a-zA-Z]:/?$", path) is not None) if sys.platform == "win32" else (path == "/")
        if is_root or path == HOME or self.is_credential_ancestor(path):
            tags.add("cred_ancestor")
        return tags
