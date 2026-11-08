"""R1 事务：幂等提交与恢复。"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from . import graph
from .journal import Journal
from .ledger import Ledger
from .locks import FileLock, is_locked
from .paths import ensure_nuwa


def dispatch_key(project: str, intent: str, attempt_seq: int) -> str:
    raw = f"{project}|{intent}|{attempt_seq}".encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class CommitError(RuntimeError):
    pass


def commit(root: str | Path, intent_id: str, fact_text: str, key: str,
           kind: str = "note", doc: str | None = None, worker: str = "nuwa") -> dict:
    """幂等提交：同 key 只产生一个 fact。"""
    root = Path(root).resolve()
    nd = ensure_nuwa(root)
    journal = Journal(root)
    project_name = root.name

    with FileLock(nd / "txn.lock", blocking=True):
        intent = graph.get_intent(root, intent_id)
        if not intent:
            raise CommitError(f"intent 不存在: {intent_id}")

        existing = graph.find_fact_by_key(root, key)
        reused = existing is not None

        if not reused and intent.get("status") == "done" and intent.get("to"):
            fact = graph.get_fact(root, intent["to"])
            if fact:
                graph.annotate_fact(root, fact["id"], key)
                existing = fact
                reused = True

        if reused:
            fact_id = existing["id"]
            graph.patch_intent(root, intent_id, fact_id, worker=worker)
        else:
            desc = f"{fact_text} [nuwa:{key}]"
            args = ["done", intent_id, "--fact", desc, "-k", kind, "--worker", worker]
            if doc:
                args += ["--doc", doc]
            r = graph.sapper(root, args)
            if r.returncode != 0:
                raise CommitError((r.stdout + r.stderr).strip()[:500])
            fact = graph.find_fact_by_key(root, key)
            if not fact:
                raise CommitError("sapper done 成功但未找到带 key 的 fact")
            fact_id = fact["id"]
            graph.patch_intent(root, intent_id, fact_id, worker=worker)

        ok, msg = graph.validate(root)
        if not ok:
            raise CommitError(f"validate 失败: {msg}")

        journal.append("commit_done", txn=key, intent=intent_id, fact=fact_id,
                       reused=reused, project=project_name)
        return {"intent": intent_id, "fact": fact_id, "reused": reused, "key": key}


def recover(root: str | Path) -> dict:
    """从 journal 汇总未完成事务；返回待处理清单（不自动重派）。"""
    root = Path(root).resolve()
    j = Journal(root)
    pending: dict[str, dict] = {}
    for rec in j.read():
        txn = rec.get("txn")
        ev = rec.get("event")
        if not txn:
            continue
        if ev in ("reserve", "executing_prepare", "executing", "executed",
                  "commit_prepare", "done_apply"):
            pending[txn] = {"txn": txn, "state": ev, "intent": rec.get("intent"),
                            "seq": rec.get("seq")}
        elif ev in ("commit_done", "ack"):
            pending.pop(txn, None)
    return {"pending": list(pending.values()), "last_seq": j.last_seq()}


def repair(root: str | Path, ledger: Ledger | None = None) -> dict:
    """恢复未完成事务：锁空闲且无成功结果时释放 intent 并结算为 crashed。"""
    root = Path(root).resolve()
    nd = ensure_nuwa(root)
    journal = Journal(root)
    led = ledger or Ledger()
    pending: dict[str, dict] = {}
    for rec in journal.read():
        txn_id = rec.get("txn")
        ev = rec.get("event")
        if not txn_id:
            continue
        if ev in ("reserve_pending", "reserve_committed", "executing_prepare",
                  "executing", "executed", "commit_prepare", "done_apply"):
            pending[txn_id] = {
                "txn": txn_id, "intent": rec.get("intent"), "rid": rec.get("rid"),
                "tokens": rec.get("tokens", 4000), "state": ev,
            }
        elif ev in ("commit_done", "ack"):
            pending.pop(txn_id, None)

    repaired = []
    for txn_id, info in pending.items():
        intent = info.get("intent")
        lock = nd / "inflight" / f"{intent}.lock"
        if intent and is_locked(lock):
            continue
        if intent:
            it = graph.get_intent(root, intent)
            if it and it.get("status") == "claimed":
                graph.sapper(root, ["release", intent])
        rid = info.get("rid")
        if rid:
            led.settle(rid, info.get("tokens", 4000), status="crashed")
        journal.append("recovered_crashed", txn=txn_id, intent=intent, rid=rid)
        repaired.append(txn_id)
    return {"repaired": repaired, "count": len(repaired)}


def adopt(root: str | Path, ledger: Ledger | None = None) -> dict:
    """0.3.x 项目接管：写 adopt 与一次性 opening_balance。"""
    root = Path(root).resolve()
    journal = Journal(root)
    led = ledger or Ledger()
    already = any(r.get("event") == "adopt" for r in journal.read())
    if already:
        return {"adopted": False, "reason": "already_adopted"}
    facts = graph.facts(root)
    intents = graph.intents(root)
    journal.append("adopt", project=root.name, facts=len(facts), intents=len(intents))
    led.opening_balance(root.name, 0, estimated=True)
    return {"adopted": True, "facts": len(facts), "intents": len(intents)}
