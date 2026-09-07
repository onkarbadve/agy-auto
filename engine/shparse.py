"""Small bash parser for policy analysis.

Fail-closed by construction: anything it cannot parse raises ParseError, and the
policy layer treats ParseError as a deny.  It understands quoting, escapes,
pipelines, lists (&& || ; &), subshells, groups, command substitution ($(..) and
backticks), process substitution, ${..}, $((..)), redirections with fd prefixes,
heredocs / herestrings, and the common control keywords (if/for/while/case/
function).  Control structures are parsed loosely: their bodies are walked so
every simple command is visible to the rules, and the script is marked
`complex` so it can never be fast-allowed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

MAX_DEPTH = 8


class ParseError(Exception):
    pass


@dataclass
class Part:
    kind: str  # lit | sq | dq | var | cmdsub | arith | procsub
    text: str
    quoted: bool = False
    subs: list = field(default_factory=list)  # nested Scripts


@dataclass
class Word:
    raw: str
    parts: list

    def static(self) -> Optional[str]:
        out = []
        for p in self.parts:
            if p.kind in ("lit", "sq", "dq"):
                out.append(p.text)
            else:
                return None
        return "".join(out)

    def static_env(self, env: dict) -> Optional[str]:
        """Like static() but expands variables present in `env` (a whitelist)."""
        out = []
        for p in self.parts:
            if p.kind in ("lit", "sq", "dq"):
                out.append(p.text)
            elif p.kind == "var" and p.text in env and not p.subs:
                out.append(env[p.text])
            else:
                return None
        return "".join(out)

    @property
    def dynamic(self) -> bool:
        return any(p.kind in ("var", "cmdsub", "arith", "procsub") for p in self.parts)

    @property
    def has_glob(self) -> bool:
        return any(p.kind == "lit" and re.search(r"[*?\[]", p.text) for p in self.parts)

    @property
    def has_brace(self) -> bool:
        return any(p.kind == "lit" and re.search(r"\{[^{}]*(,|\.\.)[^{}]*\}", p.text) for p in self.parts)

    def subs(self) -> list:
        out = []
        for p in self.parts:
            out.extend(p.subs)
        return out

    def vars(self) -> list:
        return [p.text for p in self.parts if p.kind == "var"]

    def __str__(self) -> str:
        return self.raw


@dataclass
class Redirect:
    op: str
    fd: Optional[int]
    target: Optional[Word]
    heredoc: Optional[list] = None  # [body] filled in by the lexer

    @property
    def is_write(self) -> bool:
        return self.op in (">", ">>", ">|", "&>", "&>>", ">&")

    @property
    def is_read(self) -> bool:
        return self.op in ("<", "<&", "<<", "<<-", "<<<")


@dataclass
class Simple:
    assigns: list  # (name, Word)
    words: list  # Words, words[0] is the command
    redirects: list

    @property
    def name(self) -> Optional[str]:
        if not self.words:
            return None
        return self.words[0].static()

    def all_words(self) -> list:
        out = [w for _, w in self.assigns] + list(self.words)
        out += [r.target for r in self.redirects if r.target is not None]
        return out


@dataclass
class Compound:
    kind: str  # subshell | group | if | while | until | for | select | case | function | arith | test
    body: "Script"
    words: list = field(default_factory=list)
    redirects: list = field(default_factory=list)

    def all_words(self) -> list:
        return list(self.words) + [r.target for r in self.redirects if r.target is not None]


@dataclass
class Pipeline:
    cmds: list  # Simple | Compound
    negated: bool = False
    timed: bool = False
    background: bool = False


@dataclass
class Script:
    items: list  # (connector | None, Pipeline)
    complex: bool = False

    def pipelines(self):
        return [pl for _, pl in self.items]


# --------------------------------------------------------------------------- lexer

OPS = ["&>>", "<<<", "<<-", ">>", "<<", "&&", "||", "|&", ";;", "<&", ">&", "&>", ">|", "|", ";", "&", "<", ">", "(", ")"]
REDIR_OPS = {"<", ">", ">>", "<<", "<<-", "<<<", "<&", ">&", "&>", "&>>", ">|"}
WORD_BREAK = set(" \t\n|&;<>()")
ANSI_ESC = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "v": "\v", "0": "\0"}


def _ansi_c(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x":
                m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2:])
                if m:
                    out.append(chr(int(m.group(), 16)))
                    i += 2 + m.end()
                    continue
            if n in "01234567":
                m = re.match(r"[0-7]{1,3}", s[i + 1:])
                out.append(chr(int(m.group(), 8)))
                i += 1 + m.end()
                continue
            if n == "u":
                m = re.match(r"[0-9a-fA-F]{1,4}", s[i + 2:])
                if m:
                    out.append(chr(int(m.group(), 16)))
                    i += 2 + m.end()
                    continue
            out.append(ANSI_ESC.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


class Lexer:
    def __init__(self, s: str, depth: int = 0):
        if depth > MAX_DEPTH:
            raise ParseError("nesting too deep")
        self.s = s
        self.n = len(s)
        self.i = 0
        self.depth = depth
        self.pending_heredocs: list = []

    # -- helpers
    def _skip_blank(self):
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c in " \t":
                self.i += 1
            elif c == "\\" and self.i + 1 < n and s[self.i + 1] == "\n":
                self.i += 2
            else:
                break

    def _read_heredoc_bodies(self):
        s = self.s
        for red in self.pending_heredocs:
            delim = red.target.static() if red.target else None
            if delim is None:
                delim = red.target.raw if red.target else ""
            strip_tabs = red.op == "<<-"
            lines = []
            while self.i < self.n:
                j = s.find("\n", self.i)
                line = s[self.i:] if j < 0 else s[self.i:j]
                self.i = self.n if j < 0 else j + 1
                cmp = line.lstrip("\t") if strip_tabs else line
                if cmp == delim:
                    break
                lines.append(line)
            red.heredoc[0] = "\n".join(lines)
        self.pending_heredocs = []

    def _match_paren(self, open_ch: str, close_ch: str) -> str:
        """self.i is just after the opening char; return inner text, leave i after the close."""
        s, n = self.s, self.n
        start = self.i
        depth = 1
        while self.i < n:
            c = s[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == "'":
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise ParseError("unterminated single quote")
                self.i = j + 1
                continue
            if c == '"':
                self.i += 1
                while self.i < n and s[self.i] != '"':
                    if s[self.i] == "\\":
                        self.i += 1
                    self.i += 1
                self.i += 1
                continue
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth == 0:
                    inner = s[start:self.i]
                    self.i += 1
                    return inner
            self.i += 1
        raise ParseError(f"unbalanced {open_ch}")

    def _read_backtick(self) -> str:
        s, n = self.s, self.n
        start = self.i
        while self.i < n:
            c = s[self.i]
            if c == "\\":
                self.i += 2
                continue
            if c == "`":
                inner = s[start:self.i]
                self.i += 1
                return re.sub(r"\\([`$\\])", r"\1", inner)
            self.i += 1
        raise ParseError("unterminated backtick")

    def _sub(self, text: str) -> Script:
        return parse(text, self.depth + 1)

    def _read_dollar(self, parts: list, quoted: bool):
        s, n = self.s, self.n
        # self.i at '$'
        if s.startswith("$((", self.i):
            self.i += 3
            inner = self._match_paren("(", ")")
            # _match_paren consumed one ')', there must be a second
            if self.i < n and s[self.i] == ")":
                self.i += 1
            else:
                raise ParseError("unbalanced $((")
            parts.append(Part("arith", inner, quoted, _embedded_subs(inner, self.depth + 1)))
            return
        if s.startswith("$(", self.i):
            self.i += 2
            inner = self._match_paren("(", ")")
            parts.append(Part("cmdsub", inner, quoted, [self._sub(inner)]))
            return
        if s.startswith("${", self.i):
            self.i += 2
            inner = self._match_paren("{", "}")
            name = re.match(r"[#!]?[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!\-]", inner)
            parts.append(Part("var", name.group() if name else inner, quoted, _embedded_subs(inner, self.depth + 1)))
            return
        if not quoted and s.startswith("$'", self.i):
            j = self.i + 2
            buf = []
            while j < n and s[j] != "'":
                if s[j] == "\\" and j + 1 < n:
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                buf.append(s[j])
                j += 1
            if j >= n:
                raise ParseError("unterminated $'")
            parts.append(Part("sq", _ansi_c("".join(buf)), True))
            self.i = j + 1
            return
        if not quoted and s.startswith('$"', self.i):
            self.i += 1  # treat as ordinary double quote
            return
        m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*|[0-9]|[@*#?$!\-_])", s[self.i:])
        if m:
            parts.append(Part("var", m.group(1), quoted))
            self.i += m.end()
            return
        parts.append(Part("dq" if quoted else "lit", "$", quoted))
        self.i += 1

    def _read_dq(self, parts: list):
        s, n = self.s, self.n
        buf = []

        def flush():
            parts.append(Part("dq", "".join(buf), True))
            buf.clear()

        started = len(parts)
        while self.i < n:
            c = s[self.i]
            if c == '"':
                self.i += 1
                if buf or len(parts) == started:
                    flush()
                return
            if c == "\\" and self.i + 1 < n:
                nx = s[self.i + 1]
                if nx in '"\\$`':
                    buf.append(nx)
                    self.i += 2
                    continue
                if nx == "\n":
                    self.i += 2
                    continue
                buf.append(c)
                self.i += 1
                continue
            if c == "$":
                if buf:
                    flush()
                self._read_dollar(parts, quoted=True)
                continue
            if c == "`":
                if buf:
                    flush()
                self.i += 1
                inner = self._read_backtick()
                parts.append(Part("cmdsub", inner, True, [self._sub(inner)]))
                continue
            buf.append(c)
            self.i += 1
        raise ParseError("unterminated double quote")

    def read_word(self) -> Word:
        s, n = self.s, self.n
        start = self.i
        parts: list = []
        buf: list = []

        def flush():
            if buf:
                parts.append(Part("lit", "".join(buf)))
                buf.clear()

        while self.i < n:
            c = s[self.i]
            if c in " \t\n":
                break
            if c in "|&;()":
                break
            if c in "<>":
                if s.startswith(c + "(", self.i):
                    flush()
                    self.i += 2
                    inner = self._match_paren("(", ")")
                    parts.append(Part("procsub", c + "(" + inner + ")", False, [self._sub(inner)]))
                    continue
                break
            if c == "\\":
                if self.i + 1 < n:
                    buf.append(s[self.i + 1])
                    self.i += 2
                else:
                    self.i += 1
                continue
            if c == "'":
                flush()
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise ParseError("unterminated single quote")
                parts.append(Part("sq", s[self.i + 1:j], True))
                self.i = j + 1
                continue
            if c == '"':
                flush()
                self.i += 1
                self._read_dq(parts)
                continue
            if c == "`":
                flush()
                self.i += 1
                inner = self._read_backtick()
                parts.append(Part("cmdsub", inner, False, [self._sub(inner)]))
                continue
            if c == "$":
                flush()
                self._read_dollar(parts, quoted=False)
                continue
            buf.append(c)
            self.i += 1
        flush()
        if self.i == start:
            raise ParseError(f"empty word at {start}")
        return Word(s[start:self.i], parts)

    def next_token(self):
        s, n = self.s, self.n
        self._skip_blank()
        if self.i >= n:
            return None
        c = s[self.i]
        if c == "#":
            while self.i < n and s[self.i] != "\n":
                self.i += 1
            return self.next_token()
        if c == "\n":
            self.i += 1
            if self.pending_heredocs:
                self._read_heredoc_bodies()
            return ("nl", "\n", None)
        m = re.match(r"\d+(?=[<>])", s[self.i:])
        if m:
            fd = int(m.group())
            self.i += m.end()
            for op in OPS:
                if s.startswith(op, self.i):
                    self.i += len(op)
                    return self._maybe_heredoc(op, fd)
            raise ParseError("bad redirect")
        if s.startswith("<(", self.i) or s.startswith(">(", self.i):
            return ("word", self.read_word(), None)
        if s.startswith("((", self.i):
            self.i += 2
            inner = self._match_paren("(", ")")
            if self.i < n and s[self.i] == ")":
                self.i += 1
                return ("arith", inner, None)
            raise ParseError("unbalanced ((")
        for op in OPS:
            if s.startswith(op, self.i):
                self.i += len(op)
                return self._maybe_heredoc(op, None)
        return ("word", self.read_word(), None)

    def _maybe_heredoc(self, op: str, fd):
        if op in ("<<", "<<-"):
            self._skip_blank()
            if self.i >= self.n:
                raise ParseError("heredoc without delimiter")
            delim = self.read_word()
            red = Redirect(op, fd, delim, [""])
            self.pending_heredocs.append(red)
            return ("heredoc", red, None)
        return ("op", op, fd)

    def tokens(self) -> list:
        out = []
        while True:
            t = self.next_token()
            if t is None:
                break
            out.append(t)
        if self.pending_heredocs:  # heredoc at end of input without trailing newline
            self._read_heredoc_bodies()
        return out


def _embedded_subs(text: str, depth: int) -> list:
    """Find $(..) / `..` inside parameter expansions or arithmetic and parse them."""
    if "$(" not in text and "`" not in text:
        return []
    try:
        lx = Lexer(text, depth)
        subs = []
        while lx.i < lx.n:
            lx._skip_blank()
            if lx.i >= lx.n:
                break
            if lx.s[lx.i] in "|&;()<>\n":
                lx.i += 1
                continue
            w = lx.read_word()
            subs.extend(w.subs())
        return subs
    except ParseError:
        raise
    except Exception as e:  # pragma: no cover
        raise ParseError(f"bad expansion: {e}")


# --------------------------------------------------------------------------- parser

OPENERS = {"if": "fi", "while": "done", "until": "done", "for": "done", "select": "done", "case": "esac"}
INTERNAL_KW = {"then", "elif", "else", "do", "in"}
CLOSERS = {"fi", "done", "esac", "}"}
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")


class Parser:
    def __init__(self, toks: list, depth: int):
        self.toks = toks
        self.p = 0
        self.depth = depth
        self.complex = False

    def peek(self, k: int = 0):
        j = self.p + k
        return self.toks[j] if j < len(self.toks) else None

    def _is_word(self, t, text: str) -> bool:
        return t is not None and t[0] == "word" and t[1].static() == text

    def _skip_nl(self):
        while self.peek() and self.peek()[0] == "nl":
            self.p += 1

    def parse_script(self, stop_ops=(), stop_words=()) -> Script:
        items = []
        conn = None
        while True:
            t = self.peek()
            if t is None:
                break
            if t[0] == "nl" or (t[0] == "op" and t[1] == ";"):
                self.p += 1
                conn = None
                continue
            if t[0] == "op" and t[1] in stop_ops:
                break
            if t[0] == "word":
                st = t[1].static()
                if st in stop_words:
                    break
                if st in INTERNAL_KW:
                    self.p += 1
                    self.complex = True
                    conn = None
                    continue
            pl = self.parse_pipeline(stop_words)
            items.append((conn, pl))
            conn = None
            t = self.peek()
            if t is None:
                break
            if t[0] == "op" and t[1] in ("&&", "||"):
                conn = t[1]
                self.p += 1
                self._skip_nl()
                continue
            if t[0] == "op" and t[1] == "&":
                pl.background = True
                self.p += 1
                continue
            if t[0] == "op" and t[1] == ";":
                self.p += 1
                continue
            if t[0] == "nl":
                self.p += 1
                continue
            if t[0] == "op" and t[1] in stop_ops:
                break
            if t[0] == "word" and t[1].static() in stop_words:
                break
            raise ParseError(f"unexpected token {t[1]!r}")
        return Script(items, self.complex)

    def parse_pipeline(self, stop_words) -> Pipeline:
        pl = Pipeline([])
        while self._is_word(self.peek(), "!") or self._is_word(self.peek(), "time"):
            if self.peek()[1].static() == "!":
                pl.negated = True
            else:
                pl.timed = True
            self.p += 1
            # `time -p`
            if self._is_word(self.peek(), "-p"):
                self.p += 1
        pl.cmds.append(self.parse_command(stop_words))
        while True:
            t = self.peek()
            if t and t[0] == "op" and t[1] in ("|", "|&"):
                self.p += 1
                self._skip_nl()
                pl.cmds.append(self.parse_command(stop_words))
            else:
                break
        return pl

    def _trailing_redirects(self, redirects: list):
        while True:
            t = self.peek()
            if t and t[0] == "op" and t[1] in REDIR_OPS:
                redirects.append(self._redirect())
            elif t and t[0] == "heredoc":
                self.p += 1
                redirects.append(t[1])
            else:
                return

    def _redirect(self) -> Redirect:
        t = self.peek()
        self.p += 1
        op, fd = t[1], t[2]
        tgt = self.peek()
        if tgt is None or tgt[0] != "word":
            raise ParseError(f"redirect {op} without target")
        self.p += 1
        return Redirect(op, fd, tgt[1])

    def parse_command(self, stop_words):
        t = self.peek()
        if t is None:
            raise ParseError("expected command")
        if t[0] == "op" and t[1] == "(":
            self.p += 1
            body = self.parse_script(stop_ops=(")",))
            if not (self.peek() and self.peek()[0] == "op" and self.peek()[1] == ")"):
                raise ParseError("unbalanced (")
            self.p += 1
            c = Compound("subshell", body)
            self._trailing_redirects(c.redirects)
            return c
        if t[0] == "arith":
            self.p += 1
            self.complex = True
            return Compound("arith", Script([], True), [Word(t[1], [Part("arith", t[1], False, _embedded_subs(t[1], self.depth + 1))])])
        if t[0] == "word":
            st = t[1].static()
            if st == "{":
                self.p += 1
                body = self.parse_script(stop_words=("}",))
                if not self._is_word(self.peek(), "}"):
                    raise ParseError("unbalanced {")
                self.p += 1
                c = Compound("group", body)
                self._trailing_redirects(c.redirects)
                return c
            if st == "[[":
                return self._parse_test()
            if st in OPENERS:
                return self._parse_control(st)
            if st == "function":
                self.p += 1
                name = self.peek()
                if not name or name[0] != "word":
                    raise ParseError("function without name")
                self.p += 1
                if self.peek() and self.peek()[0] == "op" and self.peek()[1] == "(":
                    self.p += 1
                    if not (self.peek() and self.peek()[0] == "op" and self.peek()[1] == ")"):
                        raise ParseError("bad function syntax")
                    self.p += 1
                self._skip_nl()
                body = self.parse_command(stop_words)
                self.complex = True
                return Compound("function", Script([(None, Pipeline([body]))], True), [name[1]])
            # name () compound
            t1, t2 = self.peek(1), self.peek(2)
            if t1 and t1[0] == "op" and t1[1] == "(" and t2 and t2[0] == "op" and t2[1] == ")":
                self.p += 3
                self._skip_nl()
                body = self.parse_command(stop_words)
                self.complex = True
                return Compound("function", Script([(None, Pipeline([body]))], True), [t[1]])
            if st in CLOSERS or st in INTERNAL_KW:
                raise ParseError(f"unexpected keyword {st}")
        return self._parse_simple(stop_words)

    def _parse_test(self) -> Compound:
        words = []
        self.p += 1
        while True:
            t = self.peek()
            if t is None or t[0] == "nl":
                raise ParseError("unterminated [[")
            self.p += 1
            if t[0] == "word":
                if t[1].static() == "]]":
                    break
                words.append(t[1])
            elif t[0] == "op":
                words.append(Word(t[1], [Part("lit", t[1])]))
            elif t[0] == "heredoc":
                raise ParseError("heredoc inside [[")
        self.complex = True
        c = Compound("test", Script([], True), words)
        self._trailing_redirects(c.redirects)
        return c

    def _parse_control(self, kw: str) -> Compound:
        self.complex = True
        closer = OPENERS[kw]
        self.p += 1
        head_words = []
        if kw in ("for", "select"):
            # for NAME [in words...] ; do
            while True:
                t = self.peek()
                if t is None:
                    raise ParseError("unterminated for")
                if t[0] == "nl" or (t[0] == "op" and t[1] == ";"):
                    self.p += 1
                    break
                if t[0] == "word" and t[1].static() == "do":
                    break
                if t[0] == "arith":
                    self.p += 1
                    head_words.append(Word(t[1], [Part("arith", t[1], False, _embedded_subs(t[1], self.depth + 1))]))
                    continue
                if t[0] != "word":
                    raise ParseError("bad for header")
                head_words.append(t[1])
                self.p += 1
            body = self.parse_script(stop_words=(closer,))
        elif kw == "case":
            t = self.peek()
            if not t or t[0] != "word":
                raise ParseError("bad case")
            head_words.append(t[1])
            self.p += 1
            self._skip_nl()
            if not self._is_word(self.peek(), "in"):
                raise ParseError("case without in")
            self.p += 1
            items = []
            while True:
                self._skip_nl()
                t = self.peek()
                if t is None:
                    raise ParseError("unterminated case")
                if self._is_word(t, "esac"):
                    break
                if t[0] == "op" and t[1] == "(":
                    self.p += 1
                # pattern words until ')'
                while True:
                    t = self.peek()
                    if t is None:
                        raise ParseError("unterminated case pattern")
                    if t[0] == "op" and t[1] == ")":
                        self.p += 1
                        break
                    if t[0] == "word":
                        head_words.append(t[1])
                    self.p += 1
                sub = self.parse_script(stop_ops=(";;",), stop_words=("esac",))
                items.extend(sub.items)
                if self.peek() and self.peek()[0] == "op" and self.peek()[1] == ";;":
                    self.p += 1
            body = Script(items, True)
        else:
            body = self.parse_script(stop_words=(closer,))
        if not self._is_word(self.peek(), closer):
            raise ParseError(f"missing {closer}")
        self.p += 1
        c = Compound(kw, body, head_words)
        self._trailing_redirects(c.redirects)
        return c

    def _parse_simple(self, stop_words) -> Simple:
        assigns, words, redirects = [], [], []
        while True:
            t = self.peek()
            if t is None:
                break
            if t[0] == "op":
                if t[1] in REDIR_OPS:
                    redirects.append(self._redirect())
                    continue
                break
            if t[0] == "heredoc":
                self.p += 1
                redirects.append(t[1])
                continue
            if t[0] == "nl":
                break
            if t[0] == "arith":
                raise ParseError("unexpected ((")
            w = t[1]
            st = w.static()
            if not words:
                if st in stop_words or st in CLOSERS:
                    break
                raw = w.raw
                if ASSIGN_RE.match(raw) and not raw.startswith("="):
                    name, _, _ = raw.partition("=")
                    assigns.append((name.rstrip("+"), w))
                    self.p += 1
                    continue
            else:
                if st in stop_words and st in CLOSERS:
                    break
            words.append(w)
            self.p += 1
        if not words and not assigns and not redirects:
            raise ParseError("empty command")
        return Simple(assigns, words, redirects)


def parse(text: str, depth: int = 0) -> Script:
    if depth > MAX_DEPTH:
        raise ParseError("nesting too deep")
    if len(text) > 200_000:
        raise ParseError("command too long")
    toks = Lexer(text, depth).tokens()
    p = Parser(toks, depth)
    sc = p.parse_script()
    if p.peek() is not None:
        raise ParseError(f"trailing token {p.peek()[1]!r}")
    return sc


def iter_simple(script: Script):
    """Yield every Simple command in the script, including nested ones (no cwd tracking)."""
    for _, pl in script.items:
        for cmd in pl.cmds:
            yield from _iter_cmd(cmd)


def _iter_cmd(cmd):
    if isinstance(cmd, Compound):
        for w in cmd.all_words():
            for sub in w.subs():
                yield from iter_simple(sub)
        yield from iter_simple(cmd.body)
    else:
        yield cmd
        for w in cmd.all_words():
            for sub in w.subs():
                yield from iter_simple(sub)
