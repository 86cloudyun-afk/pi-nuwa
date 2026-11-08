"""R1 runner：round、reason、并行 dispatch、证据闸门、run.json。"""
from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import dispatch as dispatch_mod
from . import graph, txn
from .engine import EngineError, call
from .journal import Journal
from .locks import FileLock, LockTimeout
from .paths import ensure_nuwa


def _ids(root: Path) -> list[str]:
    r = graph.sapper(root, ["frontier"])
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("i") and line[1:4].isdigit():
            out.append(line.split("\t")[0])
    return out


def _project_status(root: Path) -> str:
    return (graph.project(root).get("status") or "unknown")


def _evidence(root: Path) -> bool:
    return any(f.get("kind") in ("flag", "vuln", "loot") for f in graph.facts(root))


def _revert(root: Path, why: str) -> None:
    p = Path(root) / ".sapper" / "project.json"
    data = graph._load(p) or {}
    if data.get("status") != "completed":
        return
    data["status"] = "active"
    data.pop("completed_at", None)
    data.pop("completed_from", None)
    graph._atomic_json(p, data)
    hp = Path(root) / ".sapper" / "hints.json"
    hints = graph._load(hp) or []
    hints.append({"content": f"完成被拒绝：{why}", "creator": "nuwa",
                  "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    graph._atomic_json(hp, hints)


def _write_run(root: Path, **fields) -> None:
    p = Path(root) / ".nuwa" / "run.json"
    data = {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    data.update({"run_schema": 1, "updated_at": time.time(), **fields})
    graph._atomic_json(p, data)


def _annotate_intent(root: Path, intent_id: str, key: str) -> None:
    p = Path(root) / ".sapper" / "intents" / f"{intent_id}.json"
    data = graph._load(p) or {}
    data["x-nuwa-intent-key"] = key
    graph._atomic_json(p, data)


def _apply_reason(root: Path, payload: dict, round_no: int, journal: Journal) -> int:
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    intents = data.get("intents") if isinstance(data, dict) else None
    if not isinstance(intents, list):
        journal.append("reason_noop", round=round_no)
        return 0
    project = root.name
    created = 0
    for idx, item in enumerate(intents):
        if not isinstance(item, dict) or not item.get("description"):
            continue
        desc = str(item["description"])
        from_ids = item.get("from") or ["f001"]
        title = item.get("title") or desc[:40]
        key = "sha256:" + hashlib.sha256(
            f"{project}|reason|{round_no}|{idx}|{desc}".encode()).hexdigest()
        existing = [i for i in graph.intents(root) if i.get("x-nuwa-intent-key") == key]
        if existing:
            continue
        before = {i["id"] for i in graph.intents(root)}
        args = ["intent", "--from", ",".join(map(str, from_ids)), desc]
        if title:
            args += ["-t", str(title)]
        r = graph.sapper(root, args)
        if r.returncode != 0:
            journal.append("reason_intent_failed", round=round_no, error=(r.stdout + r.stderr)[:200])
            continue
        after = [i for i in graph.intents(root) if i["id"] not in before]
        if after:
            _annotate_intent(root, after[0]["id"], key)
            created += 1
    journal.append("reason_applied", round=round_no, created=created)
    return created


def _reason(root: Path, model: str, round_no: int, journal: Journal) -> None:
    r = graph.sapper(root, ["dispatch", "reason", "--dry-run"])
    if r.returncode != 0:
        journal.append("reason_render_failed", round=round_no)
        return
    try:
        raw = call(r.stdout, model=model, timeout=240)
        payload = dispatch_mod.parse_engine_stdout(raw)
    except (EngineError, dispatch_mod.DispatchError) as exc:
        journal.append("reason_failed", round=round_no, error=str(exc)[:200])
        return
    _apply_reason(root, payload, round_no, journal)


def run(root: str | Path, minutes: int = 60, parallel: int = 2,
        model: str = "deepseek-flash", resume: bool = False,
        max_stall: int = 5) -> int:
    root = Path(root).resolve()
    nd = ensure_nuwa(root)
    try:
        lock = FileLock(nd / "run.lock", blocking=False)
        lock.__enter__()
    except LockTimeout:
        return 5

    journal = Journal(root)
    journal.append("run_start", project=root.name, resume=resume,
                   minutes=minutes, parallel=parallel)
    txn.adopt(root)
    txn.repair(root)
    prev = {}
    if resume:
        try:
            prev = json.loads((nd / "run.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prev = {}
    _write_run(root, status="running", pid=os.getpid(),
               round=int(prev.get("round", 0)), turns=int(prev.get("turns", 0)),
               deadline=time.time() + minutes * 60)
    deadline = time.time() + minutes * 60
    max_rounds = int(os.environ.get("NUWA_MAX_ROUNDS", "0"))
    round_no = int(prev.get("round", 0))
    turns = int(prev.get("turns", 0))
    stall = 0
    last_sig = ""
    exit_code = 0
    try:
        while time.time() < deadline:
            round_no += 1
            ids = _ids(root)
            if not ids:
                _reason(root, model, round_no, journal)
                ids = _ids(root)
            if not ids:
                journal.append("frontier_empty", round=round_no)
                break
            batch = ids[: max(1, parallel * 2)]
            with ThreadPoolExecutor(max_workers=parallel) as ex:
                futs = [ex.submit(dispatch_mod.dispatch, root, i, model=model) for i in batch]
                for f in futs:
                    try:
                        f.result()
                        turns += 1
                    except Exception as exc:  # noqa: BLE001
                        journal.append("dispatch_failed", error=str(exc)[:200])

            status = _project_status(root)
            if status == "completed":
                if _evidence(root):
                    journal.append("project_completed", round=round_no)
                    break
                _revert(root, "没有任何 flag/vuln/loot 事实")
                journal.append("completion_rejected", round=round_no)

            facts = graph.facts(root)
            sig = "|".join(str(x) for x in (
                _project_status(root),
                sum(1 for i in graph.intents(root) if i.get("status") == "open"),
                sum(1 for i in graph.intents(root) if i.get("status") == "done"),
                sum(1 for f in facts if f.get("kind") not in (None, "note")),
                sum(1 for f in facts if f.get("kind") == "flag"),
            ))
            if sig == last_sig:
                stall += 1
            else:
                stall = 0
                last_sig = sig
            _write_run(root, status="running", round=round_no, turns=turns,
                       stall=stall, deadline=deadline)
            journal.append("round_end", round=round_no, turns=turns, stall=stall, sig=sig)
            if max_rounds and round_no >= max_rounds:
                journal.append("max_rounds", round=round_no)
                break
            if stall >= max_stall:
                journal.append("stall_stop", round=round_no, stall=stall)
                break
    finally:
        _write_run(root, status="stopped", round=round_no, turns=turns,
                   deadline=deadline)
        journal.append("run_stop", round=round_no, turns=turns)
        lock.__exit__(None, None, None)
    return exit_code
