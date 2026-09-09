"""Policy engine: deterministic hard-deny and fast-allow layers over parsed commands.

decide_*() return a Decision whose .decision is "allow", "deny" or "classify".
"classify" means neither deterministic layer matched; main.py sends it to the
LLM classifier (or denies if that fails).
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass

from paths import HOME, PathPolicy, is_within, resolve, strip_glob
from shparse import Compound, ParseError, Pipeline, Script, Simple, Word, parse


@dataclass
class Decision:
    decision: str  # allow | deny | classify
    layer: str
    reason: str = ""
    category: str = ""
    intent: str = ""


def deny(reason: str, category: str, intent: str = "") -> Decision:
    return Decision("deny", "hard_deny", reason, category, intent)


def classify(reason: str, category: str = "unmatched", intent: str = "") -> Decision:
    return Decision("classify", "classifier", reason, category, intent)


ALLOW = Decision("allow", "fast_allow", "read-only / workspace-scoped")

WRAPPERS_SIMPLE = {"nohup", "time", "setsid", "chronic", "unbuffer", "caffeinate", "stdbuf", "nice", "ionice", "chrt", "taskset", "command", "builtin", "exec", "strace", "ltrace", "valgrind", "ulimit"}
DANGEROUS_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "BASH_ENV", "ENV", "PROMPT_COMMAND", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_EDITOR", "PYTHONSTARTUP", "PYTHONPATH", "NODE_OPTIONS", "PERL5OPT", "RUBYOPT", "DYLD_INSERT_LIBRARIES", "SSH_ASKPASS", "GIT_ASKPASS", "SUDO_ASKPASS", "IFS", "HOME", "SHELL", "EDITOR", "VISUAL", "PAGER"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox"}
DELETERS = {"rm", "unlink", "rmdir", "shred", "srm", "wipe", "trash", "trash-put", "gio"}
COPY_LIKE = {"cp", "mv", "install", "ln", "rsync", "scp"}
CURL_DATA = {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "-F", "--form", "--form-string", "-T", "--upload-file", "--json"}
CURL_DATA_PREFIX = ("--data", "--form", "--upload-file=", "--json=")
GH_READONLY = ["pr list", "pr view", "pr status", "pr checks", "pr diff", "issue list", "issue view", "issue status", "repo view", "run list", "run view", "release list", "release view", "auth status", "status", "--version", "search", "api", "gist view", "label list", "workflow list", "workflow view", "browse --no-browser"]
WRITE_REDIRECT_SAFE = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"}


class Engine:
    def __init__(self, cfg: dict, ws_roots: list[str]):
        self.cfg = cfg
        self.hd = cfg.get("hard_deny", {})
        self.fa = cfg.get("fast_allow", {})
        self.tools = cfg.get("tools", {})
        self.pp = PathPolicy(cfg, ws_roots)
        self.ws_roots = self.pp.ws_roots
        self.env = {k: v for k, v in (("HOME", HOME), ("PWD", None), ("USER", os.environ.get("USER", "")), ("LOGNAME", os.environ.get("USER", "")), ("SHELL", "/bin/bash"), ("TERM", "xterm"), ("LANG", "C"), ("LC_ALL", "C"), ("PATH", os.environ.get("PATH", "")), ("HOSTNAME", ""), ("TMPDIR", "/tmp"), ("EDITOR", ""), ("PAGER", ""), ("OLDPWD", None)) if k in set(self.fa.get("env_whitelist", [])) and v is not None}
        self.deny_cmds = set(self.hd.get("commands", []))
        self.patterns = [(p["name"], re.compile(p["args"]) if p.get("args") else None, p.get("reason", ""), p.get("scope", "")) for p in self.hd.get("command_patterns", [])]
        self.raw_patterns = [(re.compile(p["pattern"]), p.get("reason", "")) for p in self.hd.get("raw_patterns", [])]
        self.network = set(self.hd.get("network_commands", []))
        self.interpreters = set(self.hd.get("interpreters", []))
        self.bulk_readers = set(self.hd.get("bulk_readers", []))
        self.key_consumers = set(self.hd.get("key_consumers", []))
        self.readonly = set(self.fa.get("readonly", []))
        self.allowed_domains = [d.lower() for d in self.fa.get("allowed_domains", [])]
        from paths import glob_to_regex
        self.readable_outside = [glob_to_regex(p) for p in cfg.get("paths", {}).get("readable_outside", [])]

    # ------------------------------------------------------------------ helpers
    def _resolve(self, p: str, cwd: str | None) -> str | None:
        if p.startswith("~") or p.startswith("/") or cwd:
            return resolve(p, cwd)
        return None

    def _tags(self, p: str, cwd: str | None) -> tuple[str | None, set[str]]:
        base = strip_glob(p) if re.search(r"[*?\[]", p) else p
        r = self._resolve(base, cwd)
        if r is None:
            return None, {"unresolved"}
        return r, self.pp.classify(r)

    @staticmethod
    def _basename(name: str) -> str:
        return name.rsplit("/", 1)[-1] if "/" in name else name

    def _static(self, w: Word) -> str | None:
        return w.static_env(self.env)

    def _argv(self, words: list[Word]) -> list[str]:
        """Static values where possible, raw text otherwise (for regex matching)."""
        return [self._static(w) if self._static(w) is not None else w.raw for w in words]

    @staticmethod
    def _looks_like_path(tok: str) -> bool:
        return "/" in tok or tok.startswith("~") or tok in (".", "..") or tok.startswith("./") or tok.startswith("../")

    def _path_candidates(self, argv: list[str], skip_after: set[str] = frozenset()) -> list[str]:
        out = []
        skip_next = False
        for tok in argv[1:]:
            if skip_next:
                skip_next = False
                continue
            if tok in skip_after:
                skip_next = True
                continue
            if tok == "--":
                continue
            if tok.startswith("-") and len(tok) > 1:
                if "=" in tok:
                    val = tok.split("=", 1)[1]
                    if self._looks_like_path(val):
                        out.append(val)
                else:
                    m = re.search(r"(~|/).*", tok)
                    if m and "/" in tok:
                        out.append(m.group())
                continue
            if self._looks_like_path(tok) or not tok.startswith("-"):
                out.append(tok)
        return out

    # ------------------------------------------------------------------ entry points
    def decide_command(self, cmdline: str, cwd: str | None) -> Decision:
        for rx, reason in self.raw_patterns:
            if rx.search(cmdline):
                return deny(f"{reason}", "raw-pattern", "raw")
        try:
            script = parse(cmdline)
        except ParseError as e:
            return deny(f"command could not be parsed safely ({e}); rewrite it as a simpler command", "unparseable", "unparseable")
        except RecursionError:
            return deny("command nesting too deep", "unparseable", "unparseable")
        entries: list[dict] = []
        try:
            self._walk(script, {"cwd": cwd}, entries, 0)
        except ParseError as e:
            return deny(f"nested command could not be parsed safely ({e})", "unparseable", "unparseable")
        for e in entries:
            d = self._hard_check(e)
            if d:
                return d
        # escalation intent: the distinct command names in this line
        names = []
        for e in entries:
            s = e.get("simple")
            if s is not None and s.name and self._basename(s.name) not in names:
                names.append(self._basename(s.name))
        sig = "+".join(names[:4]) or "?"
        if script.complex:
            return classify("control flow / function definitions are never fast-allowed", "complex", sig)
        if any(pl.background for pl in script.pipelines()):
            return classify("background job", "background", sig)
        why = self._fast_allow(entries)
        if why is None:
            return ALLOW
        return classify(why, "unmatched", sig)

    def decide_tool(self, name: str, args: dict) -> Decision:
        tcfg = self.tools
        read_args = tcfg.get("read_path_args", {})
        write_args = tcfg.get("write_path_args", {})
        url_args = tcfg.get("url_args", {})
        if name in write_args:
            target = args.get(write_args[name])
            if not isinstance(target, str) or not target:
                return classify("file write with no target path", "write-unknown", f"{name}")
            r, tags = self._tags(target, None)
            if "unresolved" in tags:
                return classify("write target not resolvable", "write-unknown", name)
            if "credential" in tags:
                return deny(f"refusing to write credential material: {target}", "credential-write", f"{name}:cred")
            if "device" in tags or "system_write" in tags:
                return deny(f"refusing to write outside user-space project files: {target} (system, persistence or self-protection path)", "system-write", f"{name}:sys")
            if "protected_ws" in tags:
                return deny(f"refusing to write a protected workspace path: {target}", "protected-write", f"{name}:protected")
            if "sensitive_ws" in tags:
                return classify("write to CI/hook configuration inside the workspace", "sensitive-write", name)
            if "inside_ws" in tags or "scratch" in tags:
                return Decision("allow", "fast_allow", "workspace file write")
            return classify(f"file write outside the workspace: {target}", "outside-write", name)
        if name in read_args:
            target = args.get(read_args[name])
            if isinstance(target, str) and target:
                r, tags = self._tags(target, None)
                if "credential" in tags:
                    return deny(f"refusing to read credential material: {target}", "credential-read", f"{name}:cred")
            return Decision("allow", "fast_allow", "file read")
        if name in url_args:
            url = args.get(url_args[name])
            if not isinstance(url, str) or not url:
                return classify("browser/URL tool without a URL", "url-unknown", name)
            d = self._check_url(url)
            if d:
                return d
            return Decision("allow", "fast_allow", "URL read")
        if name in set(tcfg.get("allow", [])):
            return Decision("allow", "fast_allow", "harmless tool")
        mode = self.cfg.get("unknown_tool", "classify")
        if mode == "allow":
            return Decision("allow", "fast_allow", "unknown tool (policy: allow)")
        if mode == "deny":
            return deny(f"tool {name} is not covered by policy", "unknown-tool", name)
        return classify(f"tool {name} has no deterministic rule", "unknown-tool", name)

    def _check_url(self, url: str) -> Decision | None:
        try:
            u = urllib.parse.urlsplit(url.strip())
        except ValueError:
            return deny("malformed URL", "url", "url")
        host = (u.hostname or "").lower()
        if u.scheme not in ("http", "https", ""):
            return deny(f"URL scheme {u.scheme!r} is not allowed", "url-scheme", "url")
        if host in set(h.lower() for h in self.tools.get("denied_hosts", [])) or host.startswith("169.254.") or host.startswith("fe80:"):
            return deny(f"URL host {host} is a metadata/link-local address", "url-metadata", "url")
        if u.username or u.password:
            return deny("URL carries embedded credentials", "url-credential", "url")
        q = (u.query or "") + (u.fragment or "")
        if len(q) > int(self.tools.get("max_url_query_chars", 300)):
            return deny("URL query string is unusually long; possible data exfiltration", "url-exfil", "url")
        if re.search(r"[A-Za-z0-9+/=_-]{64,}", q) or re.search(r"[A-Za-z0-9+/=_-]{80,}", u.path or ""):
            return deny("URL carries a long opaque blob; possible data exfiltration", "url-exfil", "url")
        return None

    # ------------------------------------------------------------------ walking
    def _walk(self, script: Script, cwd_state: dict, entries: list, depth: int, pipeline_ctx=None):
        for _, pl in script.items:
            n = len(pl.cmds)
            for idx, cmd in enumerate(pl.cmds):
                if isinstance(cmd, Compound):
                    sub_state = dict(cwd_state) if cmd.kind == "subshell" or n > 1 else cwd_state
                    for w in cmd.all_words():
                        for sub in w.subs():
                            self._walk(sub, dict(cwd_state), entries, depth + 1)
                    self._walk(cmd.body, sub_state, entries, depth + 1)
                    for r in cmd.redirects:
                        entries.append({"redirect_only": r, "cwd": cwd_state["cwd"], "pipeline": pl, "idx": idx, "n": n})
                    continue
                entry = {"simple": cmd, "cwd": cwd_state["cwd"], "pipeline": pl, "idx": idx, "n": n, "depth": depth}
                entries.append(entry)
                for w in cmd.all_words():
                    for sub in w.subs():
                        self._walk(sub, dict(cwd_state), entries, depth + 1)
                for r in cmd.redirects:
                    if r.heredoc is not None:
                        entry.setdefault("heredocs", []).append(r.heredoc[0])
                # cwd tracking only for single-command pipelines
                if n == 1 and cmd.name in ("cd", "pushd", "popd"):
                    argv = [self._static(w) for w in cmd.words[1:]]
                    if cmd.name == "popd":
                        cwd_state["cwd"] = None
                    elif not argv:
                        cwd_state["cwd"] = HOME
                    elif argv[0] is None or argv[0] == "-":
                        cwd_state["cwd"] = None
                    else:
                        cwd_state["cwd"] = resolve(argv[0], cwd_state["cwd"])

    # ------------------------------------------------------------------ hard deny
    def _hard_check(self, e: dict) -> Decision | None:
        cwd = e["cwd"]
        if "redirect_only" in e:
            return self._check_redirect(e["redirect_only"], cwd)
        s: Simple = e["simple"]
        for r in s.redirects:
            d = self._check_redirect(r, cwd)
            if d:
                return d
        for name, w in s.assigns:
            if name in DANGEROUS_ENV:
                return deny(f"setting {name} can hijack later commands; run the command without it", "env-hijack", f"env:{name}")
        if not s.words:
            return None
        return self._check_cmd(s.words, e, s)

    def _check_redirect(self, r, cwd) -> Decision | None:
        if r.target is None or r.op in ("<<", "<<-", "<<<"):
            return None
        tgt = self._static(r.target)
        if r.op in (">&", "<&") and (tgt is None or re.fullmatch(r"\d+|-", tgt or "")):
            return None
        if tgt is None:
            if r.is_write:
                return deny("redirect to a computed path", "redirect-dynamic", "redirect")
            return None
        if r.is_write:
            if tgt in WRITE_REDIRECT_SAFE:
                return None
            rp, tags = self._tags(tgt, cwd)
            if "device" in tags:
                return deny(f"refusing to write to device {tgt}", "device-write", "redirect")
            if "credential" in tags:
                return deny(f"refusing to write credential path {tgt}", "credential-write", "redirect")
            if "system_write" in tags:
                return deny(f"refusing to write {tgt}: system, persistence or self-protection path", "system-write", "redirect")
            if "protected_ws" in tags:
                return deny(f"refusing to write protected workspace path {tgt}", "protected-write", "redirect")
        else:
            rp, tags = self._tags(tgt, cwd)
            if "credential" in tags:
                return deny(f"refusing to read credential material {tgt}", "credential-read", "redirect")
        return None

    def _unwrap(self, words: list[Word]) -> tuple[list[Word], bool]:
        """Strip wrapper commands. Returns (words, dynamic_args)."""
        dynamic = False
        guard = 0
        while words and guard < 10:
            guard += 1
            name = self._static(words[0])
            if name is None:
                return words, dynamic
            base = self._basename(name)
            if base == "env":
                i = 1
                while i < len(words):
                    st = self._static(words[i])
                    if st is None:
                        return words[i:], dynamic
                    if st in ("-i", "--ignore-environment", "-0", "--null", "-v", "--debug"):
                        i += 1
                    elif st in ("-u", "--unset", "-C", "--chdir", "-S", "--split-string"):
                        i += 2
                    elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", st):
                        nm = st.split("=", 1)[0]
                        if nm in DANGEROUS_ENV:
                            return [words_from_static("__env_hijack__:" + nm)], dynamic
                        i += 1
                    elif st.startswith("-"):
                        i += 1
                    else:
                        break
                words = words[i:]
                continue
            if base in WRAPPERS_SIMPLE:
                i = 1
                if base in ("command",) and len(words) > 1 and self._static(words[1]) in ("-v", "-V"):
                    return words, dynamic
                while i < len(words) and (self._static(words[i]) or "").startswith("-"):
                    st = self._static(words[i])
                    if base in ("nice", "ionice", "chrt", "taskset", "stdbuf", "strace", "ltrace") and st in ("-n", "-c", "-p", "-o", "-e", "-i", "-a", "-f", "-E"):
                        i += 2
                    else:
                        i += 1
                if base == "taskset" and i < len(words) and not (self._static(words[i]) or "").startswith("-"):
                    i += 1
                words = words[i:]
                continue
            if base == "timeout":
                i = 1
                while i < len(words) and (self._static(words[i]) or "").startswith("-"):
                    st = self._static(words[i])
                    i += 2 if st in ("-s", "--signal", "-k", "--kill-after") else 1
                i += 1  # duration
                words = words[i:]
                continue
            if base == "flock":
                i = 1
                while i < len(words) and (self._static(words[i]) or "").startswith("-"):
                    st = self._static(words[i])
                    i += 2 if st in ("-w", "--timeout", "-E", "--conflict-exit-code") else 1
                i += 1  # lock file
                words = words[i:]
                continue
            if base == "xargs":
                i = 1
                while i < len(words) and (self._static(words[i]) or "").startswith("-"):
                    st = self._static(words[i])
                    if st in ("-a", "--arg-file"):
                        return [words_from_static("__xargs_file__")], True
                    i += 2 if st in ("-n", "-I", "-L", "-P", "-s", "-d", "-E", "--max-args", "--max-procs", "--delimiter", "--max-lines", "--replace", "--eof") else 1
                words = words[i:] if i < len(words) else [words_from_static("echo")]
                dynamic = True
                continue
            return words, dynamic
        return words, dynamic

    def _check_cmd(self, words: list[Word], e: dict, s: Simple) -> Decision | None:
        cwd = e["cwd"]
        words, dynamic_args = self._unwrap(words)
        if not words:
            return None
        name0 = self._static(words[0])
        if name0 is None:
            return deny("command name is computed at runtime (variable or substitution); write the command literally", "dynamic-command", "dynamic-command")
        if name0.startswith("__env_hijack__"):
            return deny("environment override that can hijack the command", "env-hijack", "env")
        if name0 == "__xargs_file__":
            return deny("xargs reading arguments from a file cannot be checked", "opaque-args", "xargs")
        base = self._basename(name0)
        argv = self._argv(words)
        arg_words = words[1:]
        args_joined = " ".join(argv[1:])
        any_dynamic = any(w.dynamic and self._static(w) is None for w in arg_words)

        if base in self.deny_cmds:
            return deny(f"'{base}' is on the hard-deny list", "denied-command", base)
        if base == "sudo" or name0.endswith("/sudo"):
            return deny("sudo is never allowed", "denied-command", "sudo")

        # command_patterns
        for pname, rx, reason, scope in self.patterns:
            if pname != base:
                continue
            if rx is not None and not rx.search(args_joined):
                continue
            if scope == "outside_ws":
                if not self._any_path_outside(argv, cwd):
                    continue
            return deny(f"{reason} ({base})", "pattern", f"{base}:{reason[:24]}")

        # interpreters and code execution
        if base in self.interpreters:
            d = self._check_interpreter(base, words, e, s, dynamic_args)
            if d:
                return d
        if base in ("source", "."):
            if any(p.kind == "procsub" for w in arg_words for p in w.parts):
                return deny("sourcing a process substitution executes unknown code", "pipe-to-shell", "source")
            if any_dynamic:
                return deny("sourcing a computed path", "opaque-exec", "source")
        if base == "eval":
            return deny("eval executes computed text; run the command directly", "opaque-exec", "eval")
        if base in ("export", "declare", "typeset", "readonly", "alias", "unalias", "trap", "enable"):
            if base in ("alias", "unalias", "trap", "enable"):
                return deny(f"{base} changes how later commands run; call the command directly", "env-hijack", base)
            for tok in argv[1:]:
                if tok.split("=", 1)[0].lstrip("-") in DANGEROUS_ENV:
                    return deny(f"{base} of {tok.split('=',1)[0]} can hijack later commands", "env-hijack", f"env:{tok.split('=',1)[0]}")

        # pipeline: interpreter reading stdin from an upstream command
        if e["idx"] > 0 and base in self.interpreters and not self._has_script_arg(base, argv):
            return deny("piping data into an interpreter (pipe-to-shell) is not allowed; write the script to a file in the workspace and run it", "pipe-to-shell", base)

        # deletion
        if base in DELETERS:
            d = self._check_delete(base, argv, arg_words, cwd, dynamic_args or any_dynamic)
            if d:
                return d
        if base == "find":
            d = self._check_find(argv, arg_words, cwd, e, s)
            if d:
                return d
        if base == "git" and re.search(r"(^|\s)rm\s", args_joined) and re.search(r"(^|\s)rm\s.*(-r\b|-[a-zA-Z]*r)", args_joined):
            if self._any_path_outside(argv, cwd):
                return deny("git rm -r outside the workspace", "recursive-delete", "git-rm")

        # credential reads / bulk reads
        skip = {"-i", "-o", "--identity", "-F"} if base in self.key_consumers else set()
        for tok in self._path_candidates(argv, skip_after=skip):
            rp, tags = self._tags(tok, cwd)
            if "credential" in tags:
                return deny(f"refusing to touch credential material: {tok}", "credential-read", f"{base}:cred")
            if base in self.bulk_readers and "cred_ancestor" in tags:
                return deny(f"{base} over {tok} would sweep up credential directories", "credential-read", f"{base}:bulk")
        if base in ("cat", "head", "tail", "less", "more", "strings", "xxd", "od", "hexdump", "base64", "grep", "rg", "awk", "sed", "cut", "sort", "uniq", "wc", "cp", "scp", "rsync", "tar", "zip") and dynamic_args:
            pass  # args from xargs: fall through; the classifier sees it

        # writes to system/credential/device paths via copy-like commands
        if base in COPY_LIKE or base in ("tee", "truncate", "touch", "mkdir", "chmod", "chown", "chgrp", "sed", "dd", "install", "patch", "ed", "sponge"):
            d = self._check_writes(base, argv, cwd)
            if d:
                return d

        # network commands
        if base in self.network:
            d = self._check_network(base, argv, arg_words, e, any_dynamic or dynamic_args, cwd)
            if d:
                return d

        # crontab/at via stdin
        if base == "crontab" and e["idx"] > 0:
            return deny("piping into crontab modifies scheduled tasks", "scheduled-task", "crontab")
        return None

    def _has_script_arg(self, base: str, argv: list[str]) -> bool:
        for tok in argv[1:]:
            if tok == "-":
                return False
            if tok in ("-c", "-e", "-s", "--stdin"):
                return tok in ("-c", "-e")
            if not tok.startswith("-"):
                return True
        return False

    def _check_interpreter(self, base: str, words: list[Word], e: dict, s: Simple, dynamic_args: bool) -> Decision | None:
        argv = self._argv(words)
        arg_words = words[1:]
        cwd = e["cwd"]
        # -c / -e code
        for i, tok in enumerate(argv[1:], start=1):
            if tok in ("-c", "-e", "--eval", "-p", "--print") or (base in SHELLS and re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", tok)):
                if i + 1 >= len(words):
                    return deny(f"{base} {tok} without code", "opaque-exec", base)
                code_w = words[i + 1]
                code = self._static(code_w)
                if code is None:
                    return deny(f"{base} {tok} with computed code; write the script literally", "opaque-exec", base)
                if base in SHELLS:
                    sub = parse(code)
                    entries: list = []
                    self._walk(sub, {"cwd": cwd}, entries, e.get("depth", 0) + 1)
                    for se in entries:
                        d = self._hard_check(se)
                        if d:
                            return d
                else:
                    for rx, reason in self.raw_patterns:
                        if rx.search(code):
                            return deny(f"{reason} (inside {base} {tok})", "raw-pattern", base)
                    if re.search(r"(?i)(subprocess|os\.system|os\.popen|child_process|exec\(|spawn\(|Runtime\.getRuntime)", code) and re.search(r"(rm\s+-r|sudo|mkfs|dd\s+if=|/etc/|\.ssh|curl|wget|socket)", code):
                        return deny(f"inline {base} code shells out to a dangerous command", "opaque-exec", base)
                return None
        # stdin sources
        for r in s.redirects:
            if r.op in ("<<", "<<-") and r.heredoc is not None and base not in SHELLS:
                body = r.heredoc[0]
                for rx, reason in self.raw_patterns:
                    if rx.search(body):
                        return deny(f"{reason} (inside {base} heredoc)", "raw-pattern", base)
                if re.search(r"(?i)(subprocess|os\.system|os\.popen|child_process|shutil\.rmtree|os\.remove|unlink|rmdir|socket|urllib|requests\.|http\.client|fetch\(|open\(.*[\"']w)", body) and re.search(r"(rm\s+-r|sudo|mkfs|dd\s+if=|/etc/|\.ssh|/home/|~|curl|wget|socket|connect\()", body):
                    return deny(f"{base} heredoc script does file deletion, system or network access; write it to a workspace file so it can be reviewed", "opaque-exec", base)
            if r.op in ("<<", "<<-") and r.heredoc is not None and base in SHELLS:
                sub = parse(r.heredoc[0])
                entries: list = []
                self._walk(sub, {"cwd": cwd}, entries, e.get("depth", 0) + 1)
                for se in entries:
                    d = self._hard_check(se)
                    if d:
                        return d
            if r.op == "<<<" and r.target is not None:
                code = self._static(r.target)
                if code is None:
                    return deny("here-string with computed code fed to an interpreter", "opaque-exec", base)
                if base in SHELLS:
                    sub = parse(code)
                    entries = []
                    self._walk(sub, {"cwd": cwd}, entries, e.get("depth", 0) + 1)
                    for se in entries:
                        d = self._hard_check(se)
                        if d:
                            return d
            if r.op == "<" and r.target is not None:
                for p in r.target.parts:
                    if p.kind == "procsub":
                        return deny("interpreter reading a process substitution executes unknown code", "pipe-to-shell", base)
        for w in arg_words:
            if any(p.kind == "procsub" for p in w.parts):
                return deny("interpreter given a process substitution executes unknown code", "pipe-to-shell", base)
            if w.dynamic and self._static(w) is None and base in SHELLS:
                st = w.raw
                if any(p.kind == "cmdsub" for p in w.parts):
                    return deny(f"{base} executing the output of another command", "pipe-to-shell", base)
        return None

    def _any_path_outside(self, argv: list[str], cwd: str | None) -> bool:
        for tok in self._path_candidates(argv):
            rp, tags = self._tags(tok, cwd)
            if "inside_ws" not in tags and "scratch" not in tags:
                return True
        return False

    def _check_delete(self, base: str, argv: list[str], arg_words: list[Word], cwd: str | None, dynamic: bool) -> Decision | None:
        flags = [a for a in argv[1:] if a.startswith("-") and a != "--"]
        recursive = base in ("rmdir", "shred", "wipe") or any(a in ("-r", "-R", "--recursive") or (re.fullmatch(r"-[a-zA-Z]+", a) and ("r" in a or "R" in a)) for a in flags)
        if base == "gio" and (not argv[1:] or argv[1] != "trash"):
            return None
        targets = [t for t in argv[1:] if not (t.startswith("-") and t != "-") and t != "--"]
        if base in ("shred", "wipe", "srm"):
            recursive = True
        if dynamic or any(w.dynamic and self._static(w) is None for w in arg_words):
            if recursive:
                return deny(f"recursive delete with computed targets cannot be verified", "recursive-delete", f"{base}:dynamic")
            return deny("delete with computed targets cannot be verified; use literal paths", "delete-dynamic", f"{base}:dynamic")
        for t in targets:
            rp, tags = self._tags(t, cwd)
            if "unresolved" in tags:
                return deny(f"delete target {t} cannot be resolved (unknown working directory)", "delete-unresolved", f"{base}:unresolved")
            if rp in ("/", HOME) or "ws_root" in tags or any(rp == (sc or "").rstrip("/") for sc in self.pp.scratch) or ("cred_ancestor" in tags and rp.count("/") <= 2):
                return deny(f"refusing to delete {t}: root, home or workspace root", "recursive-delete", f"{base}:root")
            if "system_write" in tags:
                return deny(f"refusing to delete {t}: system, persistence or self-protection path", "system-write", f"{base}:sys")
            if "protected_ws" in tags:
                return deny(f"refusing to delete protected workspace path {t}", "protected-write", f"{base}:protected")
            if "credential" in tags:
                return deny(f"refusing to delete credential material {t}", "credential-write", f"{base}:cred")
            if "inside_ws" in tags or "scratch" in tags:
                if recursive and re.search(r"[*?\[]", t) and ".." in t:
                    return deny("recursive glob delete with parent traversal", "recursive-delete", f"{base}:traversal")
                continue
            if recursive:
                return deny(f"recursive delete outside the workspace: {t}", "recursive-delete", f"{base}:outside")
            return deny(f"delete outside the workspace: {t}", "delete-outside", f"{base}:outside")
        if not targets and recursive:
            return deny("recursive delete with no literal target", "recursive-delete", f"{base}:none")
        return None

    def _check_find(self, argv: list[str], arg_words: list[Word], cwd: str | None, e: dict, s: Simple) -> Decision | None:
        roots = []
        i = 1
        while i < len(argv) and not argv[i].startswith("-") and argv[i] not in ("(", "!", ","):
            roots.append(argv[i])
            i += 1
        if not roots:
            roots = ["."]
        outside = False
        for r in roots:
            rp, tags = self._tags(r, cwd)
            if "credential" in tags:
                return deny(f"find over credential path {r}", "credential-read", "find:cred")
            if "system_write" in tags and "-delete" in argv:
                return deny(f"find -delete over system or self-protection path {r}", "system-write", "find:sys")
            if "inside_ws" not in tags and "scratch" not in tags:
                outside = True
        rest = argv[i:]
        if "-delete" in rest and outside:
            return deny("find -delete outside the workspace", "recursive-delete", "find:delete")
        for j, tok in enumerate(rest):
            if tok in ("-fprint", "-fprintf", "-fls", "-fprint0") and j + 1 < len(rest):
                d = self._check_write_target(rest[j + 1], cwd, "find")
                if d:
                    return d
            if tok in ("-exec", "-execdir", "-ok", "-okdir"):
                k = j + 1
                sub = []
                while k < len(rest) and rest[k] not in (";", "+"):
                    sub.append(rest[k])
                    k += 1
                if not sub:
                    return deny("find -exec without a command", "opaque-exec", "find")
                sub_words = [Word(t, []) for t in sub]
                # rebuild static words so the checks see literal text
                sub_words = [words_from_static(t) for t in sub]
                base = self._basename(sub[0])
                if base in DELETERS and outside:
                    return deny(f"find -exec {base} outside the workspace", "recursive-delete", "find:exec-rm")
                sub_e = dict(e)
                sub_e["idx"] = 0
                sub_e["n"] = 1
                d = self._check_cmd(sub_words, sub_e, Simple([], sub_words, []))
                if d and d.category not in ("delete-dynamic", "recursive-delete") or (d and outside):
                    return d
        return None

    def _check_write_target(self, tok: str, cwd: str | None, base: str) -> Decision | None:
        rp, tags = self._tags(tok, cwd)
        if "device" in tags:
            return deny(f"{base} writing to device {tok}", "device-write", f"{base}:device")
        if "credential" in tags:
            return deny(f"{base} writing credential path {tok}", "credential-write", f"{base}:cred")
        if "system_write" in tags:
            return deny(f"{base} writing {tok}: system, persistence or self-protection path", "system-write", f"{base}:sys")
        if "protected_ws" in tags:
            return deny(f"{base} writing protected workspace path {tok}", "protected-write", f"{base}:protected")
        if "ws_root" in tags and base in ("mv", "rm", "chmod", "chown"):
            return deny(f"{base} on the workspace root itself", "protected-write", f"{base}:root")
        return None

    def _check_writes(self, base: str, argv: list[str], cwd: str | None) -> Decision | None:
        toks = [t for t in argv[1:] if t != "--"]
        targets: list[str] = []
        if base in ("cp", "mv", "install", "ln", "rsync", "scp"):
            paths = [t for t in toks if not t.startswith("-")]
            if base == "mv":
                for src in paths[:-1]:
                    rp, tags = self._tags(src, cwd)
                    if "unresolved" in tags:
                        return deny(f"mv source {src} cannot be resolved (unknown working directory)", "delete-unresolved", "mv:unresolved")
                    if "inside_ws" not in tags and "scratch" not in tags:
                        return deny(f"mv would move {src} away from outside the workspace", "delete-outside", "mv:outside")
                    if "ws_root" in tags or "protected_ws" in tags:
                        return deny(f"mv of the workspace root or a protected path {src}", "protected-write", "mv:protected")
            for j, t in enumerate(toks):
                if t in ("-t", "--target-directory") and j + 1 < len(toks):
                    targets.append(toks[j + 1])
                elif t.startswith("--target-directory="):
                    targets.append(t.split("=", 1)[1])
            if paths and not targets:
                targets.append(paths[-1])
            if base in ("rsync", "scp"):
                targets = [t for t in targets if ":" not in t.split("/")[0]]
        elif base == "dd":
            targets = [t[3:] for t in toks if t.startswith("of=")]
            if not targets:
                return deny("dd without of= (writes stdout) is not checkable", "device-write", "dd")
        elif base == "sed":
            if any(t == "-i" or t.startswith("-i") and not t.startswith("-in") or t.startswith("--in-place") or (re.fullmatch(r"-[a-zA-Z]+", t) and "i" in t) for t in toks):
                targets = [t for t in toks if not t.startswith("-") and self._looks_like_path(t)]
        elif base in ("chmod", "chown", "chgrp"):
            paths = [t for t in toks if not t.startswith("-")]
            targets = paths[1:]
            for t in targets:
                rp, tags = self._tags(t, cwd)
                if "inside_ws" not in tags and "scratch" not in tags:
                    return deny(f"{base} outside the workspace: {t}", "system-write", f"{base}:outside")
        else:
            targets = [t for t in toks if not t.startswith("-") and (self._looks_like_path(t) or base in ("tee", "touch", "mkdir", "truncate", "sponge"))]
        for t in targets:
            d = self._check_write_target(t, cwd, base)
            if d:
                return d
        return None

    def _check_network(self, base: str, argv: list[str], arg_words: list[Word], e: dict, dynamic: bool, cwd: str | None) -> Decision | None:
        if dynamic:
            return deny(f"{base} with a computed argument (variable or command substitution) could carry local data; use literal values", "network-dynamic", f"{base}:dynamic")
        toks = argv[1:]
        if base == "curl":
            for j, t in enumerate(toks):
                key = t.split("=", 1)[0] if t.startswith("--") and "=" in t else t
                val = t.split("=", 1)[1] if t.startswith("--") and "=" in t else (toks[j + 1] if j + 1 < len(toks) else "")
                if key in CURL_DATA or (t.startswith("-d") and len(t) > 2 and not t.startswith("--")):
                    if key in ("-T", "--upload-file"):
                        return deny("curl --upload-file sends a local file", "exfil", "curl:upload")
                    v = t[2:] if (t.startswith("-d") and len(t) > 2 and not t.startswith("--")) else val
                    if v.startswith("@") or v.startswith("=@") or "=@" in v:
                        return deny("curl sending local file contents (@file)", "exfil", "curl:data-file")
                if t in ("-o", "--output") and j + 1 < len(toks):
                    d = self._check_write_target(toks[j + 1], cwd, "curl")
                    if d:
                        return d
                if t.startswith("--output="):
                    d = self._check_write_target(t.split("=", 1)[1], cwd, "curl")
                    if d:
                        return d
            if e["idx"] > 0 and any(t in ("-d", "--data", "--data-binary", "--data-raw", "-T", "--upload-file", "-F", "--form") for t in toks) and any(v in ("@-", "-", ".") for v in toks):
                return deny("curl uploading piped data", "exfil", "curl:stdin")
        if base == "wget":
            for j, t in enumerate(toks):
                if t in ("-O", "--output-document", "-P", "--directory-prefix") and j + 1 < len(toks):
                    d = self._check_write_target(toks[j + 1], cwd, "wget")
                    if d:
                        return d
                if t.startswith("--output-document=") or t.startswith("--directory-prefix="):
                    d = self._check_write_target(t.split("=", 1)[1], cwd, "wget")
                    if d:
                        return d
        if base in ("nc", "ncat", "netcat", "socat", "telnet") and (e["idx"] > 0 or any(r.op == "<" for r in e["simple"].redirects)):
            return deny(f"{base} sending local data to the network", "exfil", f"{base}:stdin")
        if base == "ssh" and e["idx"] > 0:
            return deny("piping local data into ssh", "exfil", "ssh:stdin")
        if base in ("gh",) and e["idx"] > 0 and any(t in ("--input", "-F", "-f") for t in toks):
            return deny("gh api uploading piped data", "exfil", "gh:stdin")
        if base == "aws" and e["idx"] > 0:
            return deny("piping local data into aws", "exfil", "aws:stdin")
        if base == "ssh":
            remote = self._ssh_remote_command(arg_words)
            if remote:
                try:
                    sub = parse(remote)
                except ParseError as ex:
                    return deny(f"remote command could not be parsed ({ex})", "unparseable", "ssh")
                entries: list = []
                self._walk(sub, {"cwd": None}, entries, e.get("depth", 0) + 1)
                for se in entries:
                    d = self._hard_check(se)
                    if d:
                        d.reason = "in remote ssh command: " + d.reason
                        return d
        return None

    @staticmethod
    def _ssh_remote_command(arg_words: list[Word]) -> str | None:
        toks = [w.raw for w in arg_words]
        i = 0
        host_seen = False
        with_val = {"-i", "-o", "-p", "-l", "-F", "-L", "-R", "-D", "-J", "-W", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S", "-w", "-B"}
        while i < len(toks):
            t = toks[i]
            if not host_seen:
                if t in with_val:
                    i += 2
                    continue
                if t.startswith("-"):
                    i += 1
                    continue
                host_seen = True
                i += 1
                continue
            rest = toks[i:]
            # strip one layer of quotes for a single quoted argument
            if len(rest) == 1 and len(rest[0]) >= 2 and rest[0][0] in "'\"" and rest[0][-1] == rest[0][0]:
                return rest[0][1:-1]
            return " ".join(rest)
        return None

    # ------------------------------------------------------------------ fast allow
    def _fast_allow(self, entries: list[dict]) -> str | None:
        """Return None if every entry is fast-allowable, else the reason it is not."""
        for e in entries:
            if "redirect_only" in e:
                why = self._redirects_ok([e["redirect_only"]], e["cwd"])
                if why:
                    return why
                continue
            s: Simple = e["simple"]
            for name, w in s.assigns:
                if self._static(w) is None:
                    return f"computed assignment {name}"
            why = self._redirects_ok(s.redirects, e["cwd"])
            if why:
                return why
            if not s.words:
                continue
            words, dynamic = self._unwrap(s.words)
            if dynamic:
                return "xargs / dynamic arguments"
            if not words:
                continue
            for w in words:
                if self._static(w) is None:
                    return f"unresolved expansion in {w.raw!r}"
                if w.has_brace:
                    return "brace expansion"
            argv = self._argv(words)
            base = self._basename(argv[0])
            if argv[0] != base and not argv[0].startswith("/"):
                return f"relative script/executable {argv[0]}"
            if argv[0].startswith("/") and base not in self.readonly:
                return f"absolute executable {argv[0]}"
            if base not in self.readonly:
                return f"'{base}' is not in the read-only allow list"
            why = self._tool_rules(base, argv, e)
            if why:
                return why
            skip = {"-i", "-o", "--identity", "-F"} if base in self.key_consumers else set()
            for tok in self._path_candidates(argv, skip_after=skip):
                if tok == "-" or tok in WRITE_REDIRECT_SAFE:
                    continue
                rp, tags = self._tags(tok, e["cwd"])
                if "inside_ws" in tags or "scratch" in tags:
                    if "system_write" in tags:
                        return f"touches system or self-protection path {tok}"
                    if "sensitive_ws" in tags and base in ("cp", "mv", "tee", "touch", "mkdir", "sed"):
                        return f"touches CI/hook config {tok}"
                    continue
                if rp and base not in ("cp", "mv", "tee", "touch", "mkdir", "sed", "cd") and any(r.match(rp) for r in self.readable_outside):
                    continue
                return f"path {tok} is outside the workspace"
        return None

    def _redirects_ok(self, redirects, cwd) -> str | None:
        for r in redirects:
            if r.op in ("<<", "<<-"):
                continue
            if r.target is None:
                continue
            tgt = self._static(r.target)
            if tgt is None:
                return "computed redirect target"
            if r.op in (">&", "<&") and re.fullmatch(r"\d+|-", tgt):
                continue
            if r.op == "<<<":
                continue
            if r.is_write:
                if tgt in WRITE_REDIRECT_SAFE:
                    continue
                rp, tags = self._tags(tgt, cwd)
                if ("inside_ws" in tags or "scratch" in tags) and "sensitive_ws" not in tags and "protected_ws" not in tags and "system_write" not in tags:
                    continue
                return f"redirect to {tgt} outside the workspace"
            else:
                rp, tags = self._tags(tgt, cwd)
                if "inside_ws" in tags or "scratch" in tags:
                    continue
                return f"reads {tgt} outside the workspace"
        return None

    def _prefix_match(self, args: list[str], prefixes: list[str]) -> bool:
        joined = " ".join(args)
        for p in prefixes:
            if joined == p or joined.startswith(p + " "):
                return True
        return False

    def _tool_rules(self, base: str, argv: list[str], e: dict) -> str | None:
        args = argv[1:]
        joined = " ".join(args)
        fa = self.fa
        if e["n"] > 1 and base in ("cd", "export", "unset", "set", "alias", "source", "."):
            return "shell builtin inside a pipeline"
        if base in ("source", "."):
            return "source executes a file"
        if base == "sed":
            if any(t == "-i" or t.startswith("--in-place") or (re.fullmatch(r"-[a-zA-Z]+", t) and "i" in t) for t in args):
                return "sed -i edits files in place"
            scripts = []
            j = 0
            while j < len(args):
                t = args[j]
                if t in ("-e", "--expression") and j + 1 < len(args):
                    scripts.append(args[j + 1])
                    j += 2
                    continue
                if t in ("-f", "--file"):
                    return "sed -f script file"
                if t.startswith("-"):
                    j += 1
                    continue
                scripts.append(t)
                break
            for sc in scripts:
                for expr in re.split(r";|\n", sc):
                    expr = expr.strip()
                    if not expr:
                        continue
                    if not re.fullmatch(r"(\d+|\$|/(\\/|[^/])*/|\\.)?(,(\d+|\$|/(\\/|[^/])*/|\+\d+|~\d+))?!?\s*(p|d|=|l|q|Q|n|N|h|H|g|G|x|D|P|F|z|s(.)(?:\\.|(?!\7).)*\7(?:\\.|(?!\7).)*\7[gIimp0-9]*|y(.)(?:\\.|(?!\8).)*\8(?:\\.|(?!\8).)*\8|\{[^}]*\}|[abic]\\?.*)", expr):
                        return f"sed expression {expr!r} is not in the read-only subset"
                    if re.fullmatch(r".*s(.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[gIimp0-9]*[we].*", expr):
                        return "sed s///w or s///e"
            return None
        if base in ("awk", "gawk"):
            prog = None
            j = 0
            while j < len(args):
                t = args[j]
                if t in ("-f", "--file"):
                    return "awk -f program file"
                if t in ("-v", "-F") and j + 1 < len(args):
                    j += 2
                    continue
                if t.startswith("-"):
                    j += 1
                    continue
                prog = t
                break
            if prog is None or re.search(r"system\s*\(|\|\s*&?|getline|>\s*\"|>>|/inet|ENVIRON|@load|print\s*>|printf\s*>|close\s*\(|fflush", prog):
                return "awk program is not read-only"
            return None
        if base == "find":
            if any(t in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls", "-fprint0") for t in args):
                return "find with side effects"
            return None
        if base == "git":
            return self._git_rules(args)
        if base in ("npm",):
            return None if self._prefix_match(args, fa.get("npm_readonly", [])) else f"npm {joined} is not read-only"
        if base == "npx":
            return None if self._prefix_match(args, fa.get("npx_readonly", [])) else f"npx {joined} is not read-only"
        if base == "cargo":
            return None if self._prefix_match(args, fa.get("cargo_readonly", [])) else f"cargo {joined} is not read-only"
        if base == "go":
            return None if self._prefix_match(args, fa.get("go_readonly", [])) else f"go {joined} is not read-only"
        if base in ("python", "python3"):
            if args and args[0] in ("--version", "-V", "-VV"):
                return None
            if len(args) >= 2 and args[0] == "-m" and self._prefix_match(args[1:], fa.get("python_readonly_modules", [])):
                return None
            return f"{base} {joined} executes code"
        if base == "node":
            return None if args and args[0] in ("--version", "-v") else "node executes code"
        if base == "make":
            targets = [t for t in args if not t.startswith("-") and "=" not in t]
            if any(t in set(fa.get("make_forbidden_targets", [])) for t in targets):
                return "make target with side effects"
            if any(t in ("-f", "--file", "-C", "--directory") for t in args):
                return "make with -f/-C"
            return None
        if base in ("podman", "docker"):
            return None if self._prefix_match(args, fa.get("podman_readonly", [])) else f"{base} {joined} is not read-only"
        if base == "systemctl":
            a = [t for t in args if not t.startswith("-")]
            return None if a and self._prefix_match(a, fa.get("systemctl_readonly", [])) else f"systemctl {joined} is not read-only"
        if base == "journalctl":
            return "journalctl maintenance" if any(t.startswith("--vacuum") or t in ("--rotate", "--flush", "--sync", "--relinquish-var") for t in args) else None
        if base == "dnf":
            return None if self._prefix_match(args, fa.get("dnf_readonly", [])) else f"dnf {joined} is not read-only"
        if base in ("pip", "pip3"):
            return None if self._prefix_match(args, fa.get("pip_readonly", [])) else f"{base} {joined} is not read-only"
        if base == "ip":
            return "ip configuration change" if any(t in ("add", "del", "delete", "set", "change", "replace", "flush", "up", "down") for t in args) else None
        if base in ("ping", "ping6"):
            if "-c" not in args and not any(t.startswith("-c") for t in args):
                return "ping without -c would run forever"
            return None
        if base == "curl":
            return self._curl_rules(args)
        if base == "wget":
            return self._wget_rules(args)
        if base == "gh":
            if not self._prefix_match(args, GH_READONLY):
                return f"gh {joined} is not read-only"
            if args and args[0] == "api" and any(t in ("-X", "--method", "-f", "-F", "--field", "--raw-field", "--input") for t in args):
                return "gh api with a mutating method"
        if base == "agy":
            agy_ro = fa.get("agy_readonly", ["--help", "-h", "--version", "-v", "version", "help", "changelog", "hooks", "skills", "rules", "models"])
            return None if self._prefix_match(args, agy_ro) else f"agy {joined} is not read-only"
        if base == "sleep":
            try:
                n = float(re.sub(r"[smh]$", "", args[0])) if args else 0
            except ValueError:
                return "sleep with non-numeric duration"
            return "sleep too long" if n > float(fa.get("max_sleep_seconds", 300)) else None
        if base == "sort" and any(t in ("-o", "--output") or t.startswith("--output=") or t.startswith("-o") for t in args):
            return "sort -o writes a file"
        if base == "tee":
            return None
        if base == "cd":
            if not args:
                return "cd to home leaves the workspace"
            rp, tags = self._tags(args[-1], e["cwd"])
            return None if "inside_ws" in tags else f"cd {args[-1]} leaves the workspace"
        if base == "xargs":
            return "xargs"
        if base == "timeout":
            return "timeout wrapper"
        if base in ("export", "set", "unset", "alias"):
            if base == "export" and any(t.split("=", 1)[0] in DANGEROUS_ENV for t in args):
                return "export of a hijacking variable"
            return None
        if base == "crontab":
            return None if args == ["-l"] else "crontab modifies scheduled tasks"
        if base == "date":
            return "date -s" if any(t in ("-s", "--set") or t.startswith("--set=") for t in args) else None
        if base == "jq":
            return None
        return None

    def _git_rules(self, args: list[str]) -> str | None:
        fa = self.fa
        i = 0
        while i < len(args) and args[i].startswith("-"):
            if args[i] in ("-C", "--git-dir", "--work-tree", "-c", "--namespace", "--exec-path"):
                if args[i] == "-c":
                    return "git -c inline config"
                i += 2
                continue
            if args[i].startswith("--git-dir=") or args[i].startswith("--work-tree="):
                i += 1
                continue
            i += 1
        if i >= len(args):
            return "bare git"
        sub = args[i]
        rest = args[i + 1:]
        if sub not in set(fa.get("git_readonly", [])):
            return f"git {sub} is not read-only"
        forbidden = set(fa.get("git_readonly_forbidden_flags", []))
        if sub == "stash":
            if rest and rest[0] not in set(fa.get("git_stash_readonly", [])):
                return f"git stash {rest[0]} modifies state"
            if not rest:
                return "git stash (push) modifies state"
            return None
        if sub == "config":
            if not any(t in set(fa.get("git_config_readonly", [])) for t in rest):
                return "git config write"
            if any(t in forbidden for t in rest):
                return "git config write flag"
            return None
        if sub == "remote":
            return None if (not rest or rest[0] in ("-v", "--verbose", "show", "get-url")) else f"git remote {rest[0]} modifies state"
        if sub == "worktree":
            return None if rest and rest[0] == "list" else "git worktree modifies state"
        if sub == "reflog":
            return None if (not rest or rest[0] == "show" or rest[0].startswith("-")) else "git reflog modifies state"
        if sub == "notes":
            return None if rest and rest[0] in ("list", "show") else "git notes modifies state"
        if sub == "bisect":
            return None if rest and rest[0] in ("log", "visualize", "view") else "git bisect modifies state"
        if sub == "tag" and rest and not all(t.startswith("-l") or t in ("--list", "-n", "--contains", "--points-at", "--sort", "--format") or not t.startswith("-") for t in rest):
            return "git tag with flags"
        if sub == "tag" and rest and not any(t in ("-l", "--list") for t in rest) and any(not t.startswith("-") for t in rest):
            return "git tag creation"
        if sub == "branch" and rest and any(not t.startswith("-") for t in rest) and not any(t in ("-l", "--list", "--contains", "--merged", "--no-merged", "-a", "-r", "-v", "-vv", "--show-current", "--points-at") for t in rest):
            return "git branch creation"
        if sub == "fetch" and any(t in ("-p", "--prune", "--prune-tags") for t in rest):
            return "git fetch --prune"
        if any(t in forbidden for t in rest):
            return f"git {sub} with a mutating flag"
        return None

    def _host_allowed(self, url: str) -> bool:
        try:
            h = (urllib.parse.urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()
        except ValueError:
            return False
        return any(h == d or h.endswith("." + d) for d in self.allowed_domains)

    def _curl_rules(self, args: list[str]) -> str | None:
        urls = []
        j = 0
        with_val = {"-o", "--output", "-H", "--header", "-A", "--user-agent", "-m", "--max-time", "--connect-timeout", "-w", "--write-out", "-e", "--referer", "-b", "--cookie", "--retry", "-r", "--range", "-x", "--proxy", "--cacert", "-X", "--request", "--url", "-u", "--user"}
        while j < len(args):
            t = args[j]
            if t in CURL_DATA or t.startswith(CURL_DATA_PREFIX) or (t.startswith("-d") and not t.startswith("--")):
                return "curl sends data"
            if t in ("-u", "--user", "-n", "--netrc", "-K", "--config", "-c", "--cookie-jar", "-b", "--cookie", "-E", "--cert", "--key", "-x", "--proxy"):
                return f"curl {t} involves credentials or state"
            if t in ("-X", "--request") and j + 1 < len(args) and args[j + 1].upper() not in ("GET", "HEAD"):
                return f"curl -X {args[j+1]}"
            if t.startswith("--request=") and t.split("=", 1)[1].upper() not in ("GET", "HEAD"):
                return "curl mutating method"
            if t in ("-H", "--header") and j + 1 < len(args) and re.match(r"(?i)\s*(authorization|cookie|x-api-key|api-key)\s*:", args[j + 1]):
                return "curl sends an auth header"
            if t in with_val and j + 1 < len(args):
                if t == "--url":
                    urls.append(args[j + 1])
                j += 2
                continue
            if t.startswith("-"):
                j += 1
                continue
            urls.append(t)
            j += 1
        if not urls:
            return "curl without a URL"
        for u in urls:
            if not self._host_allowed(u):
                return f"curl to {u} is not an allow-listed host"
        return None

    def _wget_rules(self, args: list[str]) -> str | None:
        urls = []
        j = 0
        while j < len(args):
            t = args[j]
            if t.startswith("--post") or t.startswith("--body") or t.startswith("--method") or t in ("--user", "--password", "--http-user", "--http-password", "--load-cookies", "--save-cookies", "-e", "--execute", "--config", "-r", "--recursive", "-m", "--mirror"):
                return f"wget {t}"
            if t in ("-O", "--output-document", "-P", "--directory-prefix", "-o", "--output-file", "-a", "--append-output", "-T", "--timeout", "-t", "--tries", "-U", "--user-agent", "--header") and j + 1 < len(args):
                j += 2
                continue
            if t.startswith("-"):
                j += 1
                continue
            urls.append(t)
            j += 1
        if not urls:
            return "wget without a URL"
        for u in urls:
            if not self._host_allowed(u):
                return f"wget to {u} is not an allow-listed host"
        return None


def words_from_static(text: str) -> Word:
    from shparse import Part
    return Word(text, [Part("sq", text, True)])
