"""全局账本 global.jsonl。"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .locks import FileLock
from .paths import budget_dir


class Ledger:
    def __init__(self, home: str | Path | None = None):
        d = Path(home) / "budget" if home else budget_dir()
        d.mkdir(parents=True, exist_ok=True)
        self.dir = d
        self.path = d / "global.jsonl"
        self.lock_path = d / "global.lock"
        self.cap_path = d / "cap.json"

    def _append(self, rec: dict) -> dict:
        with FileLock(self.lock_path, blocking=True):
            return self._append_locked(rec)

    def _append_locked(self, rec: dict) -> dict:
        rec.setdefault("ts", time.time())
        need_lf = False
        try:
            if self.path.exists() and self.path.stat().st_size > 0:
                with open(self.path, "rb") as fh:
                    fh.seek(-1, os.SEEK_END)
                    need_lf = fh.read(1) != b"\n"
        except OSError:
            need_lf = False
        with open(self.path, "a", encoding="utf-8") as fh:
            if need_lf:
                fh.write("\n")
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return rec

    def records(self) -> list[dict]:
        with FileLock(self.lock_path, blocking=True):
            return self._records_locked()

    def _records_locked(self) -> list[dict]:
        out = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        return out

    def cap(self) -> int:
        try:
            return int(json.loads(self.cap_path.read_text())["tokens"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return int(os.environ.get("NUWA_GLOBAL_CAP", "20000000"))

    def set_cap(self, tokens: int) -> None:
        tmp = self.cap_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"tokens": int(tokens)}), encoding="utf-8")
        os.replace(tmp, self.cap_path)

    def summary(self) -> dict:
        with FileLock(self.lock_path, blocking=True):
            return self._summary_locked()

    def _summary_locked(self) -> dict:
        settled_total = 0
        outstanding: dict[str, dict] = {}
        for rec in self._records_locked():
            t = rec.get("type")
            rid = rec.get("rid")
            if t == "opening_balance":
                settled_total += int(rec.get("tokens", 0))
            elif t == "reserve" and rid:
                outstanding[rid] = {
                    "project": rec.get("project"),
                    "tokens": int(rec.get("tokens", 0)),
                    "dispatches": int(rec.get("dispatches", 0)),
                    "expires_at": rec.get("expires_at", 0),
                }
            elif t == "settle" and rid:
                settled_total += int(rec.get("tokens_actual", 0))
                outstanding.pop(rid, None)
            elif t == "reclaim" and rid:
                outstanding.pop(rid, None)
        reserved = sum(v["tokens"] for v in outstanding.values())
        remaining = self.cap() - settled_total - int(reserved * 1.05)
        return {
            "cap": self.cap(),
            "settled_total": settled_total,
            "reserved": reserved,
            "remaining_global": remaining,
            "outstanding": outstanding,
        }

    def reserve(self, rid: str, project: str, tokens: int, dispatches: int = 1, ttl: int = 600) -> dict:
        return self._append({
            "type": "reserve", "rid": rid, "project": project,
            "tokens": int(tokens), "dispatches": int(dispatches),
            "expires_at": time.time() + ttl,
        })

    def renew(self, rid: str, ttl: int = 600) -> dict:
        """只续当前仍打开的预留；已 settle/reclaim 的 rid 报错，避免幽灵预留。"""
        with FileLock(self.lock_path, blocking=True):
            state = None
            for rec in self._records_locked():
                if rec.get("rid") != rid:
                    continue
                if rec.get("type") in ("reserve", "renew"):
                    state = "reserve"
                elif rec.get("type") in ("settle", "reclaim"):
                    state = "closed"
            if state != "reserve":
                raise ValueError(f"renew 无有效预留: {rid}")
            return self._append_locked({"type": "renew", "rid": rid,
                                        "expires_at": time.time() + ttl})

    def settle(self, rid: str, tokens_actual: int, status: str = "ok") -> dict:
        """按 rid 幂等：同一预留重复结算不重复扣账。"""
        with FileLock(self.lock_path, blocking=True):
            last = None
            for rec in self._records_locked():
                if rec.get("rid") == rid:
                    last = rec
            if last is not None and last.get("type") == "settle":
                return last
            return self._append_locked({"type": "settle", "rid": rid,
                                        "tokens_actual": int(tokens_actual), "status": status})

    def has_reserve(self, rid: str) -> bool:
        """该 rid 的最后一条账本事件是否为未关闭的 reserve/renew。"""
        with FileLock(self.lock_path, blocking=True):
            recs = self._records_locked()
        state = None
        for rec in recs:
            if rec.get("rid") != rid:
                continue
            if rec.get("type") in ("reserve", "renew"):
                state = "reserve"
            elif rec.get("type") in ("settle", "reclaim"):
                state = "closed"
        return state == "reserve"

    def admit_reserve(self, rid: str, project: str, tokens: int,
                      dispatches: int = 1, ttl: int = 600,
                      project_remaining: int | None = None) -> tuple[bool, int]:
        """准入与预留同一把锁：并发 dispatch 不会各自基于旧余额获准。"""
        with FileLock(self.lock_path, blocking=True):
            s = self._summary_locked()
            want = int(tokens * 1.05)
            if want > s["remaining_global"]:
                return False, s["remaining_global"]
            if project_remaining is not None and tokens > project_remaining:
                return False, project_remaining
            self._append_locked({"type": "reserve", "rid": rid, "project": project,
                                 "tokens": int(tokens), "dispatches": int(dispatches),
                                 "expires_at": time.time() + ttl})
            return True, s["remaining_global"]

    def reclaim(self, rid: str, reason: str = "expired") -> dict:
        return self._append({"type": "reclaim", "rid": rid, "reason": reason})

    def opening_balance(self, project: str, tokens: int = 0, estimated: bool = True) -> dict:
        return self._append({"type": "opening_balance", "project": project,
                             "tokens": int(tokens), "estimated": estimated})

    def admit(self, tokens: int, project_remaining: int | None = None) -> tuple[bool, int]:
        """返回 (是否准入, 可用额度)。"""
        s = self.summary()
        want = int(tokens * 1.05)
        if want > s["remaining_global"]:
            return False, s["remaining_global"]
        if project_remaining is not None and tokens > project_remaining:
            return False, project_remaining
        return True, s["remaining_global"]
