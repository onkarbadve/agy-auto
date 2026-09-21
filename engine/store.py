"""Decision cache, per-conversation escalation counters, and the JSONL audit log."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time


def _flock_exclusive(fh) -> None:
    if sys.platform == "win32":
        try:
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        except Exception:
            pass
    else:
        try:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
        except Exception:
            pass


def _flock_unlock(fh) -> None:
    if sys.platform == "win32":
        try:
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
    else:
        try:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_UN)
        except Exception:
            pass


def _ensure_dir(d: str) -> None:
    os.makedirs(d, mode=0o700, exist_ok=True)


class _Locked:
    def __init__(self, path: str):
        self.path = path
        self.fh = None

    def __enter__(self):
        _ensure_dir(os.path.dirname(self.path))
        self.fh = open(self.path, "a+")
        _flock_exclusive(self.fh)
        self.fh.seek(0)
        try:
            self.data = json.load(self.fh)
        except (json.JSONDecodeError, ValueError):
            self.data = {}
        return self

    def save(self):
        self.fh.seek(0)
        self.fh.truncate()
        json.dump(self.data, self.fh)
        self.fh.flush()

    def __exit__(self, *a):
        try:
            _flock_unlock(self.fh)
        finally:
            self.fh.close()


class Store:
    def __init__(self, state_dir: str, audit_dir: str, ttl_hours: float, policy_version: str):
        self.state_dir = os.path.expanduser(state_dir)
        self.audit_dir = os.path.expanduser(audit_dir)
        self.ttl = ttl_hours * 3600
        self.policy_version = policy_version

    # ---- cache (classifier decisions only)
    def cache_key(self, tool: str, normalized: str, cwd: str | None, ws: list[str], extra_hash: str = "") -> str:
        h = hashlib.sha256()
        h.update("|".join([self.policy_version, tool, normalized, cwd or "", ",".join(ws), extra_hash]).encode())
        return h.hexdigest()[:32]

    def cache_get(self, key: str):
        path = os.path.join(self.state_dir, "cache.json")
        if not os.path.exists(path):
            return None
        with _Locked(path) as lk:
            ent = lk.data.get(key)
            if not ent:
                return None
            if time.time() - ent.get("ts", 0) > self.ttl:
                del lk.data[key]
                lk.save()
                return None
            return ent

    def cache_put(self, key: str, decision: str, reason: str) -> None:
        path = os.path.join(self.state_dir, "cache.json")
        with _Locked(path) as lk:
            now = time.time()
            # opportunistic expiry
            if len(lk.data) > 2000:
                lk.data = {k: v for k, v in lk.data.items() if now - v.get("ts", 0) <= self.ttl}
            lk.data[key] = {"decision": decision, "reason": reason, "ts": now}
            lk.save()

    # ---- conversational single-use approvals
    def create_approval(self, conversation_id: str, tool: str, normalized: str, cwd: str | None, ttl_s: int = 300) -> str:
        token = hashlib.sha256(f"{conversation_id}:{tool}:{normalized}:{cwd}:{time.time()}".encode()).hexdigest()[:6]
        path = os.path.join(self.state_dir, "approvals.json")
        with _Locked(path) as lk:
            now = time.time()
            # opportunistic cleanup of expired records (>1 hr)
            if len(lk.data) > 50:
                lk.data = {k: v for k, v in lk.data.items() if now - v.get("created_at", 0) <= 3600}
            lk.data[token] = {
                "conv": conversation_id,
                "tool": tool,
                "norm": normalized,
                "cwd": cwd,
                "created_at": now,
                "expires_at": now + ttl_s,
                "consumed": False,
            }
            lk.save()
        return token

    def consume_approval(self, token: str, conversation_id: str, tool: str, normalized: str, cwd: str | None) -> bool:
        path = os.path.join(self.state_dir, "approvals.json")
        if not os.path.exists(path):
            return False
        with _Locked(path) as lk:
            rec = lk.data.get(token)
            if not rec or rec.get("consumed"):
                return False
            now = time.time()
            if now > rec.get("expires_at", 0):
                return False
            if rec.get("conv") and conversation_id and rec.get("conv") != conversation_id:
                return False
            if rec.get("tool") != tool or rec.get("norm") != normalized or rec.get("cwd") != cwd:
                return False
            rec["consumed"] = True
            lk.save()
            return True

    # ---- escalation counters
    def bump_denial(self, conversation_id: str, intent: str) -> int:
        path = os.path.join(self.state_dir, "sessions", f"{conversation_id or 'no-conversation'}.json")
        with _Locked(path) as lk:
            n = int(lk.data.get(intent, 0)) + 1
            lk.data[intent] = n
            lk.data["_updated"] = time.time()
            lk.save()
            return n

    # ---- audit
    def audit(self, conversation_id: str, record: dict) -> None:
        _ensure_dir(self.audit_dir)
        path = os.path.join(self.audit_dir, f"{conversation_id or 'no-conversation'}.jsonl")
        line = json.dumps(record, ensure_ascii=False, default=str)
        with open(path, "a", encoding="utf-8") as fh:
            _flock_exclusive(fh)
            try:
                fh.write(line + "\n")
            finally:
                _flock_unlock(fh)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
