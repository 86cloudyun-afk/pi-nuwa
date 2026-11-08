"""权威事件流 journal.jsonl。

一致性约定：

- `append` / `compact` / `gc` / `read` 共用 `.nuwa/journal.lock`；`compact` 内部调用
  `_gc_locked`，避免同进程重复拿 flock 造成自锁。
- seq 高水位同时取 journal 尾部与 `checkpoint.*.json` 的 `seq`。这样 GC 删掉旧代后
  序号不会回落到 0，`since_seq` 的调用者不会被静默跳过。
- `compact` 的代号取 `max(CURRENT, 现有 journal/checkpoint 代号) + 1`，并在 rename 前
  检查目标文件；崩溃导致 CURRENT 未发布时也不会覆盖已有归档。
- `gc` 保留近 `keep` 代，并额外保护「含未决事务的代」；删除前写 `recovery.json`
  保存 committed/settled/inflight 摘要，replay/recover 从该摘要起算。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .locks import FileLock, LockTimeout  # noqa: F401  (LockTimeout 供调用方复用)

PENDING_EVENTS = (
    "reserve_pending",
    "reserve_committed",
    "executing_prepare",
    "executing",
    "executed",
    "commit_prepare",
    "done_apply",
    "ledger_settle",
)
FINAL_EVENTS = ("commit_done", "ack")
DONE_EVENTS = ("commit_done", "ack", "reserve_rejected", "recovered_crashed")


class Journal:
    def __init__(self, root: str | Path):
        self.dir = Path(root) / ".nuwa"
        self.path = self.dir / "journal.jsonl"
        self.lock_path = self.dir / "journal.lock"
        self.recovery_path = self.dir / "recovery.json"
        self.dir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- 写
    def append(self, event: str, **fields) -> dict:
        rec = {"ts": time.time(), "event": event, **fields}
        with FileLock(self.lock_path, blocking=True):
            rec["seq"] = self._last_seq_locked() + 1
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

    # ---------------------------------------------------------------- seq
    @staticmethod
    def _tail_seq(path: Path) -> int:
        """从尾部找最后一条合法记录；窗口不足或切在 UTF-8 中间时继续向前扩。"""
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                window = 8192
                while True:
                    start = max(0, size - window)
                    fh.seek(start)
                    data = fh.read()
                    if start > 0:
                        cut = data.find(b"\n")
                        if cut < 0:
                            window *= 2
                            continue
                        data = data[cut + 1:]
                    for raw in reversed(data.split(b"\n")):
                        try:
                            line = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not isinstance(obj, dict):
                            continue
                        seq = obj.get("seq")
                        if isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
                            return seq
                        continue
                    if start == 0:
                        return 0
                    window *= 2
        except FileNotFoundError:
            return 0

    def _checkpoint_high(self) -> int:
        best = 0
        for p in self.dir.glob("checkpoint.*.json"):
            try:
                best = max(best, int(json.loads(p.read_text(encoding="utf-8")).get("seq", 0)))
            except (OSError, json.JSONDecodeError, TypeError, ValueError):
                continue
        return best

    def _last_seq_locked(self) -> int:
        best = self._checkpoint_high()
        for path in self._files():
            best = max(best, self._tail_seq(path))
        return best

    def last_seq(self) -> int:
        """跨代 + checkpoint 取最大 seq；GC 之后也不回退。"""
        with FileLock(self.lock_path, blocking=True):
            return self._last_seq_locked()

    # ---------------------------------------------------------------- 读
    def _files(self) -> list[Path]:
        # 归档按代号数字升序，当前活动文件最后：旧代不能覆盖新代的终态。
        files = sorted(self.dir.glob("journal.*.jsonl"), key=self._gen_of)
        if self.path.exists():
            files.append(self.path)
        return files

    def _gen_of(self, path: Path) -> int:
        if path == self.path:
            return self.current_gen()
        parts = path.name.split(".")
        try:
            return int(parts[1])
        except (IndexError, ValueError):
            return 0

    @staticmethod
    def _iter_records(path: Path):
        try:
            fh = open(path, "rb")
        except FileNotFoundError:
            return
        with fh:
            for raw in fh:
                try:
                    line = raw.decode("utf-8").strip(" \t\r\n")
                except UnicodeDecodeError:
                    # 与 _tail_seq 同一口径：坏编码整行跳过，不能被 replace 洗成合法事件。
                    continue
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    yield rec

    def _read_locked(self, since_seq: int = 0) -> list[dict]:
        recs: list[dict] = []
        for path in self._files():
            for rec in self._iter_records(path):
                seq = rec.get("seq")
                if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
                    continue
                if seq > since_seq:
                    recs.append(rec)
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

    def read(self, since_seq: int = 0) -> list[dict]:
        with FileLock(self.lock_path, blocking=True):
            return self._read_locked(since_seq)

    def snapshot(self) -> tuple[dict | None, list[dict]]:
        """锁内一次性取 recovery 摘要与全量记录，避免 GC 插入造成半新半旧。"""
        with FileLock(self.lock_path, blocking=True):
            return self.read_recovery(), self._all_records_locked()

    def _all_records_locked(self) -> list[dict]:
        """按文件顺序返回全部记录；无 seq 的记录也保留，供状态归并使用。"""
        out: list[dict] = []
        seen: set[int] = set()
        for path in self._files():
            for rec in self._iter_records(path):
                seq = rec.get("seq")
                if isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
                    if seq in seen:
                        continue
                    seen.add(seq)
                out.append(rec)
        return out

    def read_recovery(self) -> dict | None:
        try:
            data = json.loads(self.recovery_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    # ---------------------------------------------------------------- 压缩
    def _next_gen_locked(self) -> int:
        best = self.current_gen()
        for p in list(self.dir.glob("journal.*.jsonl")) + list(self.dir.glob("checkpoint.*.json")):
            parts = p.name.split(".")
            if len(parts) >= 3:
                try:
                    best = max(best, int(parts[1]))
                except ValueError:
                    continue
        return best + 1

    def compact(self, keep: int | None = None) -> Path:
        """把当前 journal 归档为 journal.<gen>.jsonl，开新文件并按 keep 做代际 GC。"""
        with FileLock(self.lock_path, blocking=True):
            gen = self._next_gen_locked()
            seq = self._last_seq_locked()
            if self.path.exists() and self.path.stat().st_size > 0:
                dest = self.dir / f"journal.{gen}.jsonl"
                if dest.exists():
                    raise RuntimeError(f"journal gen 冲突，拒绝覆盖: {dest}")
                os.replace(self.path, dest)
            self.path.touch()
            ck = self.dir / f"checkpoint.{gen}.json"
            tmp = ck.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"checkpoint_schema": 1, "gen": gen, "seq": seq},
                                    ensure_ascii=False, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, ck)
            cur = self.dir / "CURRENT"
            cur_tmp = cur.with_suffix(".tmp")
            with open(cur_tmp, "w", encoding="utf-8") as fh:
                fh.write(str(gen))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(cur_tmp, cur)
            self._fsync_dir()
            self._gc_locked(keep=self._keep_default() if keep is None else keep)
            return ck

    @staticmethod
    def _keep_default() -> int:
        try:
            return int(os.environ.get("NUWA_JOURNAL_KEEP", "2"))
        except ValueError:
            return 2

    def _fsync_dir(self) -> None:
        try:
            fd = os.open(self.dir, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _pending_floor_locked(self) -> int:
        """返回含未决事务的最早代；终态优先于后续的 ledger_settle。"""
        last: dict[str, tuple[int, str]] = {}
        done: set[str] = set()
        for path in self._files():
            gen = self._gen_of(path)
            for rec in self._iter_records(path):
                txn = rec.get("txn")
                if not txn:
                    continue
                txn = str(txn)
                ev = str(rec.get("event", ""))
                if ev in DONE_EVENTS:
                    done.add(txn)
                    last.pop(txn, None)
                elif ev in PENDING_EVENTS and txn not in done:
                    last[txn] = (gen, ev)
        floor = 0
        for gen, _ev in last.values():
            floor = gen if floor == 0 else min(floor, gen)
        return floor

    def _summarize_locked(self) -> dict:
        state: dict = {"inflight": {}, "settled": [], "committed": [],
                       "ended": [], "last_seq": 0}
        settled: set[str] = set()
        committed: set[str] = set()
        ended: set[str] = set()
        # 按文件顺序扫描而非 _read_locked：缺 seq 的终态记录也要参与状态归并。
        for path in self._files():
            for rec in self._iter_records(path):
                seq = rec.get("seq")
                if isinstance(seq, int) and not isinstance(seq, bool):
                    state["last_seq"] = max(int(state["last_seq"]), seq)
                ev = rec.get("event")
                txn = rec.get("txn")
                if ev == "executing_prepare":
                    state["inflight"][txn] = {
                        "intent": rec.get("intent"), "state": "prepare",
                        "rid": rec.get("rid"), "tokens": rec.get("tokens"),
                    }
                elif ev == "executing":
                    state["inflight"].setdefault(txn, {})["state"] = "executing"
                elif ev in ("executed", "commit_done", "ack", "recovered_crashed"):
                    state["inflight"].pop(txn, None)
                if ev in ("ack", "recovered_crashed") and txn:
                    ended.add(str(txn))
                if ev == "ledger_settle" and rec.get("rid"):
                    settled.add(str(rec.get("rid")))
                if ev == "commit_done" and txn:
                    committed.add(str(txn))
        state["settled"] = sorted(settled)
        state["committed"] = sorted(committed)
        state["ended"] = sorted(ended)
        return state

    def _write_recovery_locked(self) -> None:
        old = self.read_recovery() or {}
        cur = self._summarize_locked()
        committed = set(old.get("committed", [])) | set(cur["committed"])
        ended = set(old.get("ended", [])) | set(cur.get("ended", []))
        inflight = {**old.get("inflight", {}), **cur["inflight"]}
        # 终态删除信息不能被旧摘要的并集复活；ack 同样是终态。
        inflight = {k: v for k, v in inflight.items()
                    if k not in committed and k not in ended}
        try:
            old_last = int(old.get("last_seq", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            old_last = 0
        try:
            cur_last = int(cur["last_seq"] or 0)
        except (TypeError, ValueError, OverflowError):
            cur_last = 0
        merged = {
            "recovery_schema": 1,
            "gen": self.current_gen(),
            "last_seq": max(old_last, cur_last),
            "settled": sorted(set(old.get("settled", [])) | set(cur["settled"])),
            "committed": sorted(committed),
            "ended": sorted(ended),
            "inflight": inflight,
        }
        tmp = self.recovery_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(merged, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.recovery_path)
        self._fsync_dir()

    def _gc_locked(self, keep: int) -> list[Path]:
        keep = int(keep)
        if keep <= 0:
            return []
        cur = self.current_gen()
        cutoff = cur - max(1, keep)
        floor = self._pending_floor_locked()
        if floor:
            cutoff = min(cutoff, floor - 1)
        if cutoff < 1:
            return []
        self._write_recovery_locked()
        removed: list[Path] = []
        for gen in range(1, cutoff + 1):
            for name in (f"journal.{gen}.jsonl", f"checkpoint.{gen}.json"):
                p = self.dir / name
                if p.exists():
                    p.unlink()
                    removed.append(p)
        self._fsync_dir()
        return removed

    def gc(self, keep: int = 2) -> list[Path]:
        """删除早于「当前代 - keep」的代际文件；keep<=0 表示不删。

        保留近 keep 代（keep=2 为当前代与上一代；keep=1 仅当前代）与含未决事务的代；
        删除前写 recovery.json。
        """
        with FileLock(self.lock_path, blocking=True):
            return self._gc_locked(keep)

    # ---------------------------------------------------------------- 检查点
    def write_checkpoint(self, payload: dict) -> Path:
        """写 checkpoint.<gen>.json，原子更新 CURRENT 指针。"""
        with FileLock(self.lock_path, blocking=True):
            gen = self._next_gen_locked()
            ck = self.dir / f"checkpoint.{gen}.json"
            tmp = ck.with_suffix(".tmp")
            body = {"checkpoint_schema": 1, "gen": gen, "seq": self._last_seq_locked(), **payload}
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(body, ensure_ascii=False, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, ck)
            cur = self.dir / "CURRENT"
            cur_tmp = cur.with_suffix(".tmp")
            with open(cur_tmp, "w", encoding="utf-8") as fh:
                fh.write(str(gen))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(cur_tmp, cur)
            self._fsync_dir()
            return ck

    def current_gen(self) -> int:
        try:
            return int((self.dir / "CURRENT").read_text().strip())
        except (OSError, ValueError):
            return 0


def replay_state(root: str | Path) -> dict:
    """从 recovery 摘要 + journal 重放到最后一条终态，返回恢复所需摘要。"""
    j = Journal(root)
    state: dict = {"inflight": {}, "settled": set(), "committed": set(), "last_seq": 0}
    base, records = j.snapshot()
    if base:
        state["settled"] = set(base.get("settled", []))
        state["committed"] = set(base.get("committed", []))
        ended = set(base.get("ended", []))
        state["inflight"] = {k: v for k, v in base.get("inflight", {}).items()
                             if k not in ended}
        try:
            state["last_seq"] = int(base.get("last_seq", 0) or 0)
        except (TypeError, ValueError, OverflowError):
            state["last_seq"] = 0
    for rec in records:
        ev = rec.get("event")
        seq = rec.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
            state["last_seq"] = max(int(state["last_seq"]), seq)
        txn = rec.get("txn")
        if ev == "executing_prepare":
            state["inflight"][txn] = {"intent": rec.get("intent"), "state": "prepare"}
        elif ev == "executing":
            state["inflight"].setdefault(txn, {})["state"] = "executing"
        elif ev in ("executed", "commit_done", "ack"):
            state["inflight"].pop(txn, None)
        if ev == "ledger_settle":
            state["settled"].add(rec.get("rid"))
        if ev == "commit_done":
            state["committed"].add(rec.get("txn"))
    return state
