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

    @staticmethod
    def _tail_seq(path: Path) -> int:
        try:
            with open(path, "rb") as fh:
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

    def last_seq(self) -> int:
        """跨代取最大 seq：compact 后新文件若从 0 重数会与归档代撞号。"""
        best = 0
        for path in self._files():
            best = max(best, self._tail_seq(path))
        return best

    def _files(self) -> list[Path]:
        files = [self.path] if self.path.exists() else []
        files += sorted(self.dir.glob("journal.*.jsonl"))
        return files

    def read(self, since_seq: int = 0) -> list[dict]:
        recs: list[dict] = []
        for path in self._files():
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if int(rec.get("seq", 0)) > since_seq:
                            recs.append(rec)
            except FileNotFoundError:
                continue
        recs.sort(key=lambda r: int(r.get("seq", 0)))
        seen: set[int] = set()
        out: list[dict] = []
        for r in recs:
            seq = int(r.get("seq", 0))
            if seq in seen:
                continue
            seen.add(seq)
            out.append(r)
        return out

    def compact(self, keep: int | None = None) -> Path:
        """把当前 journal 归档为 journal.<gen>.jsonl，开新文件。

        seq 必须在 os.replace 之前取：替换后当前文件为空，last_seq() 会返回 0，
        checkpoint 丢失基线，后续 append 也会从 1 重新计数。归档后按 keep 做代际
        GC（默认取 NUWA_JOURNAL_KEEP，缺省 2），只删「当前代 - keep」之前的文件。
        """
        gen = self.current_gen() + 1
        seq = self.last_seq()
        if self.path.exists() and self.path.stat().st_size > 0:
            os.replace(self.path, self.dir / f"journal.{gen}.jsonl")
        self.path.touch()
        ck = self.dir / f"checkpoint.{gen}.json"
        tmp = ck.with_suffix(".tmp")
        tmp.write_text(json.dumps({"checkpoint_schema": 1, "gen": gen, "seq": seq},
                                  ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, ck)
        cur = self.dir / "CURRENT"
        cur_tmp = cur.with_suffix(".tmp")
        cur_tmp.write_text(str(gen), encoding="utf-8")
        os.replace(cur_tmp, cur)
        self.gc(keep=self._keep_default() if keep is None else keep)
        return ck

    @staticmethod
    def _keep_default() -> int:
        try:
            return int(os.environ.get("NUWA_JOURNAL_KEEP", "2"))
        except ValueError:
            return 2

    def gc(self, keep: int = 2) -> list[Path]:
        """删除早于「当前代 - keep」的代际文件；keep<=0 表示不删。

        保留 CURRENT 指向的当前代与上一代，确保回退上一代仍可用。
        """
        keep = int(keep)
        if keep <= 0:
            return []
        cur = self.current_gen()
        cutoff = cur - max(1, keep)
        removed: list[Path] = []
        for gen in range(1, cutoff + 1):
            for name in (f"journal.{gen}.jsonl", f"checkpoint.{gen}.json"):
                p = self.dir / name
                if p.exists():
                    p.unlink()
                    removed.append(p)
        return removed

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
