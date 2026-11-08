"""权威事件流 journal.jsonl。"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .locks import FileLock, LockTimeout


class Journal:
    def __init__(self, root: str | Path):
        self.dir = Path(root) / ".nuwa"
        self.path = self.dir / "journal.jsonl"
        self.lock_path = self.dir / "journal.lock"
        self.dir.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, **fields) -> dict:
        rec = {"ts": time.time(), "event": event, **fields}
        with FileLock(self.lock_path, blocking=True):
            rec["seq"] = self.last_seq() + 1
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return rec

    def last_seq(self) -> int:
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - 8192))
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return 0
        for line in reversed(lines):
            try:
                return int(json.loads(line).get("seq", 0))
            except (json.JSONDecodeError, ValueError, TypeError):
                continue
        return 0

    def read(self, since_seq: int = 0) -> list[dict]:
        out: list[dict] = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if int(rec.get("seq", 0)) > since_seq:
                        out.append(rec)
        except FileNotFoundError:
            pass
        return out

    def write_checkpoint(self, payload: dict) -> Path:
        """写 checkpoint.<gen>.json，原子更新 CURRENT 指针。"""
        gen = self.current_gen() + 1
        ck = self.dir / f"checkpoint.{gen}.json"
        tmp = ck.with_suffix(".tmp")
        body = {"checkpoint_schema": 1, "gen": gen, "seq": self.last_seq(), **payload}
        tmp.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, ck)
        cur = self.dir / "CURRENT"
        cur_tmp = cur.with_suffix(".tmp")
        cur_tmp.write_text(str(gen), encoding="utf-8")
        os.replace(cur_tmp, cur)
        return ck

    def current_gen(self) -> int:
        try:
            return int((self.dir / "CURRENT").read_text().strip())
        except (OSError, ValueError):
            return 0


def replay_state(root: str | Path) -> dict:
    """从 journal 重放到最后一条终态，返回恢复所需摘要。"""
    j = Journal(root)
    state: dict = {"inflight": {}, "settled": set(), "committed": set(), "last_seq": 0}
    for rec in j.read():
        ev = rec.get("event")
        state["last_seq"] = rec.get("seq", state["last_seq"])
        txn = rec.get("txn")
        if ev == "executing_prepare":
            state["inflight"][txn] = {"intent": rec.get("intent"), "state": "prepare"}
        elif ev == "executing":
            state["inflight"].setdefault(txn, {})["state"] = "executing"
        elif ev in ("executed", "commit_done"):
            state["inflight"].pop(txn, None)
        if ev == "ledger_settle":
            state["settled"].add(rec.get("rid"))
        if ev in ("commit_done", "done_apply"):
            state["committed"].add(rec.get("txn"))
    return state
