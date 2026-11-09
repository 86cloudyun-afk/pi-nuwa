"""R1 事务：幂等提交与恢复。"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from . import graph
from .journal import Journal
from .ledger import Ledger
from .locks import FileLock, is_locked
from .paths import ensure_nuwa


def attempt_of(intent: dict) -> int:
    """严格读取 x-nuwa-attempt：只接受非负整数或其十进制字符串，其余报错。"""
    raw = intent.get("x-nuwa-attempt", 0)
    if isinstance(raw, bool):
        raise CommitError(f"x-nuwa-attempt 非法: {raw!r}")
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        value = int(raw.strip())
    else:
        raise CommitError(f"x-nuwa-attempt 非法: {raw!r}")
    if value < 0:
        raise CommitError(f"x-nuwa-attempt 为负: {value}")
    return value


def _bind_source(root: str | Path, fact_id: str, intent_id: str) -> None:
    if not graph._safe_id(fact_id):
        raise CommitError(f"非法 fact id: {fact_id}")
    fp = Path(root) / ".sapper" / "facts" / f"{fact_id}.json"
    data = json.loads(fp.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("id") != fact_id:
        raise CommitError(f"fact 身份不匹配: {fact_id}")
    data["source_intent"] = intent_id
    tmp = fp.with_name(fp.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, fp)


def _unbind_source(root: str | Path, fact_id: str) -> None:
    if not graph._safe_id(fact_id):
        return
    fp = Path(root) / ".sapper" / "facts" / f"{fact_id}.json"
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if isinstance(data, dict) and data.get("id") == fact_id:
        data["source_intent"] = None
        tmp = fp.with_name(fp.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, fp)


def dispatch_key(project: str, intent: str, attempt_seq: int) -> str:
    raw = f"{project}|{intent}|{attempt_seq}".encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class CommitError(RuntimeError):
    pass


TXN_PENDING = (
    "reason_reserve",
    "reserve_pending", "reserve_committed", "executing_prepare", "executing",
    "executed", "commit_prepare", "done_apply", "ledger_settle",
)
TXN_DONE = ("commit_done", "ack", "reserve_rejected", "dispatch_rejected",
            "recovered_crashed", "reason_rejected", "reason_skipped")


def _crash(point: str) -> None:
    if os.environ.get("NUWA_CRASH_POINT") == point:
        os._exit(137)


def commit(root: str | Path, intent_id: str, fact_text: str, key: str | None,
           kind: str = "note", doc: str | None = None, worker: str = "nuwa") -> dict:
    """幂等提交：同 key 只产生一个 fact；key=None 时在事务锁内按 attempt 生成。"""
    root = Path(root).resolve()
    nd = ensure_nuwa(root)
    journal = Journal(root)
    project_name = root.name

    with FileLock(nd / "txn.lock", blocking=True):
        intent = graph.get_intent(root, intent_id)
        if not intent:
            raise CommitError(f"intent 不存在: {intent_id}")
        if key is None:
            key = dispatch_key(project_name, intent_id, attempt_of(intent))

        before = json.loads(json.dumps(intent, ensure_ascii=False))
        done_to = intent.get("to") if intent.get("status") == "done" else None
        if done_to:
            done_fact = graph.get_fact(root, done_to)
            if done_fact:
                done_keys = set(re.findall(r"\[nuwa:([^\]]+)\]",
                                           done_fact.get("description") or ""))
                aux = done_fact.get("x-nuwa-key")
                if isinstance(aux, str) and aux:
                    done_keys.add(aux)
                if done_keys and key not in done_keys:
                    raise CommitError(
                        f"intent 已由其他键完成: {sorted(done_keys)[0]}")

        existing = graph.find_fact_by_key(root, key)
        if existing and done_to and existing.get("id") != done_to:
            raise CommitError("intent 已完成于其他 fact，拒绝改指")
        reused = existing is not None

        if not reused and done_to:
            graph.annotate_fact(root, done_to, key)
            existing = graph.get_fact(root, done_to)
            reused = existing is not None

        bound_fact = None
        if reused:
            fact_id = existing["id"]
            src = existing.get("source_intent")
            if src not in (None, intent_id):
                raise CommitError(f"fact 已绑定其他意图: {src} != {intent_id}")
            if not src:
                _bind_source(root, fact_id, intent_id)
                bound_fact = fact_id
            try:
                graph.patch_intent(root, intent_id, fact_id, worker=worker)
            except Exception:
                if not src:
                    _unbind_source(root, fact_id)
                raise
        else:
            desc = f"{fact_text} [nuwa:{key}]"
            args = ["done", intent_id, "--fact", desc, "-k", kind, "--worker", worker]
            if doc:
                args += ["--doc", doc]
            r = graph.sapper(root, args, allow_submit=True)
            if r.returncode != 0:
                raise CommitError((r.stdout + r.stderr).strip()[:500])
            fact = graph.find_fact_by_key(root, key)
            if not fact:
                raise CommitError("sapper done 成功但未找到带 key 的 fact")
            fact_id = fact["id"]
            if (graph.get_fact(root, fact_id) or {}).get("source_intent") == intent_id:
                bound_fact = fact_id
            graph.patch_intent(root, intent_id, fact_id, worker=worker)

        _crash("after_done")
        try:
            ok, msg = graph.validate(root)
        except Exception:
            _restore_intent(root, intent_id, before)
            if bound_fact:
                _unbind_source(root, bound_fact)
            raise
        if not ok:
            _restore_intent(root, intent_id, before)
            if bound_fact:
                _unbind_source(root, bound_fact)
            raise CommitError(f"validate 失败: {msg}")
        _crash("after_validate")

        journal.append("commit_done", txn=key, intent=intent_id, fact=fact_id,
                       reused=reused, project=project_name)
        return {"intent": intent_id, "fact": fact_id, "reused": reused, "key": key}


def _restore_intent(root: Path, intent_id: str, data: dict) -> None:
    p = root / ".sapper" / "intents" / f"{intent_id}.json"
    restored = dict(data)
    cur = None
    try:
        cur = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    if isinstance(cur, dict):
        for k in ("done_at", "worker"):
            if k in restored:
                continue
            restored.pop(k, None)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(restored, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def _snapshot_state(j: Journal) -> tuple[dict | None, list[dict], set[str]]:
    base, records = j.snapshot()
    finished: set[str] = set()
    if base:
        finished |= set(base.get("committed", []))
        finished |= set(base.get("ended", []))
    return base, records, finished


def recover(root: str | Path) -> dict:
    """从 recovery 摘要 + journal 汇总未完成事务；不自动重派。"""
    root = Path(root).resolve()
    j = Journal(root)
    base, records, finished = _snapshot_state(j)
    pending: dict[str, dict] = {}
    if base:
        for txn, info in (base.get("inflight") or {}).items():
            if txn not in finished:
                pending[txn] = {"txn": txn, "state": info.get("state", "recovered"),
                                "intent": info.get("intent"), "rid": info.get("rid"),
                                "tokens": info.get("tokens")}
    try:
        last = int(base.get("last_seq", 0) or 0) if base else 0
    except (TypeError, ValueError, OverflowError):
        last = 0
    for rec in records:
        seq = rec.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
            last = max(last, seq)
        txn = rec.get("txn")
        ev = rec.get("event")
        if not txn or txn in finished:
            continue
        if ev in TXN_PENDING:
            pending[txn] = {"txn": txn, "state": ev, "intent": rec.get("intent"),
                            "seq": rec.get("seq")}
        elif ev in TXN_DONE:
            pending.pop(txn, None)
    return {"pending": list(pending.values()), "last_seq": last}


def repair(root: str | Path, ledger: Ledger | None = None) -> dict:
    """恢复未完成事务：只结算真实存在且未结算的预留，并写 ack 终态。"""
    root = Path(root).resolve()
    nd = ensure_nuwa(root)
    journal = Journal(root)
    led = ledger or Ledger()
    _base, records, finished = _snapshot_state(journal)
    pending: dict[str, dict] = {}
    if _base:
        for txn, info in (_base.get("inflight") or {}).items():
            if txn in finished:
                continue
            pending[txn] = {
                "txn": txn, "intent": info.get("intent"), "rid": info.get("rid"),
                "tokens": info.get("tokens", 4000),
                "state": info.get("state", "recovered"),
            }
    for rec in records:
        txn_id = rec.get("txn")
        ev = rec.get("event")
        if not txn_id or txn_id in finished:
            continue
        if ev in TXN_PENDING:
            prev = pending.get(txn_id, {})
            rec_tokens = rec.get("tokens")
            pending[txn_id] = {
                "txn": txn_id,
                "intent": rec.get("intent") or prev.get("intent"),
                "rid": rec.get("rid") or prev.get("rid"),
                "tokens": rec_tokens if rec_tokens is not None
                else prev.get("tokens", 4000),
                "state": ev,
            }
        elif ev in TXN_DONE:
            pending.pop(txn_id, None)

    usage = {}
    for rec in records:
        if rec.get("event") == "reason_usage" and rec.get("txn"):
            try:
                usage[str(rec["txn"])] = int(rec.get("tokens", 0))
            except (TypeError, ValueError):
                pass
    repaired = []
    for txn_id, info in pending.items():
        intent = info.get("intent")
        result_path = nd / "artifacts" / txn_id / "result.json"
        succeeded = False
        if result_path.exists():
            try:
                res = json.loads(result_path.read_text(encoding="utf-8"))
                out_path = nd / "artifacts" / txn_id / "stdout.txt"
                text = (out_path.read_text(encoding="utf-8", errors="replace").strip()
                        if out_path.exists() else "")
                empty_obj = False
                if text.startswith(("{", "[")):
                    try:
                        empty_obj = not bool(json.loads(text))
                    except (ValueError, TypeError):
                        empty_obj = True
                succeeded = (isinstance(res, dict) and res.get("exit_code") == 0
                             and bool(text) and not empty_obj)
            except (OSError, json.JSONDecodeError, ValueError):
                succeeded = False
        if succeeded:
            rid = info.get("rid")
            tokens = info.get("tokens")
            if tokens is None:
                tokens = 4000
            if rid and led.has_reserve(rid):
                led.settle(rid, tokens, status="ok")
                journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent,
                               tokens=tokens, status="ok")
            journal.append("recovered_ok", txn=txn_id, intent=intent,
                           rid=rid, artifact=str(result_path))
            journal.append("ack", txn=txn_id, intent=intent, status="ok")
            repaired.append(txn_id)
            continue
        lock = nd / "inflight" / f"{intent}.lock"
        if intent and is_locked(lock):
            continue
        if intent:
            it = graph.get_intent(root, intent)
            if it and it.get("status") == "claimed":
                graph.sapper(root, ["release", intent])
        rid = info.get("rid")
        reserved = info.get("tokens")
        if reserved is None:
            reserved = 4000
        tokens = usage.get(txn_id, reserved)
        if info.get("state") == "reason_reserve" and rid and not led.has_reserve(rid):
            if tokens > reserved * 1.05:
                try:
                    (nd / "reason.freeze").write_text(
                        f"overrun {tokens}>{reserved}\n", encoding="utf-8")
                except OSError:
                    pass
            journal.append("recovered_skipped", txn=txn_id, intent=intent, rid=rid)
            continue
        if info.get("state") == "reason_reserve" and tokens > reserved * 1.05:
            try:
                (nd / "reason.freeze").write_text(
                    f"overrun {tokens}>{reserved}\n", encoding="utf-8")
            except OSError:
                pass
        if rid and led.has_reserve(rid):
            led.settle(rid, tokens, status="crashed")
            journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent,
                           tokens=tokens, status="crashed")
        journal.append("recovered_crashed", txn=txn_id, intent=intent, rid=rid)
        journal.append("ack", txn=txn_id, intent=intent, status="crashed")
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
