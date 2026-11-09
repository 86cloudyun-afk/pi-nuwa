"""dispatch：渲染提示、调用引擎、写入 executed、幂等提交。"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import graph, txn, policy
from .journal import Journal
from .ledger import Ledger
from .locks import FileLock, is_locked
from .paths import ensure_nuwa

REPO = Path(__file__).resolve().parents[1]
WORKER = REPO / "nuwa" / "worker.py"
DEFAULT_TOKENS = 4000


class DispatchError(RuntimeError):
    pass


def _crash(point: str) -> None:
    if os.environ.get("NUWA_CRASH_POINT") == point:
        os._exit(137)


def _balanced_json(text: str) -> dict | None:
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text[i:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def parse_engine_stdout(raw: str) -> dict:
    """兼容 claude envelope 与裸 payload；返回 explore payload。"""
    try:
        env = json.loads(raw)
    except json.JSONDecodeError:
        env = None
    text = raw
    if isinstance(env, dict) and isinstance(env.get("result"), str):
        text = env["result"]
    payload = _balanced_json(text)
    if not payload:
        raise DispatchError("引擎输出中没有 JSON payload")
    return payload


def render_prompt(root: Path, intent_id: str, timeout: int = 60) -> str:
    r = graph.sapper(root, ["dispatch", intent_id, "--dry-run"], timeout=timeout)
    if r.returncode != 0:
        raise DispatchError((r.stdout + r.stderr).strip()[:400])
    return r.stdout


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _unbind_source(root: str | Path, fact_id: str) -> None:
    if not graph._safe_id(fact_id):
        return
    fp = Path(root) / ".sapper" / "facts" / f"{fact_id}.json"
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if isinstance(data, dict) and data.get("id") == fact_id:
        data.pop("source_intent", None)
        _write_json(fp, data)


def _restore_intent(root: str | Path, intent_id: str, prev: dict) -> None:
    if not graph._safe_id(intent_id):
        return
    fp = Path(root) / ".sapper" / "intents" / f"{intent_id}.json"
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    data["status"] = prev.get("status")
    if prev.get("to") is None:
        data.pop("to", None)
    else:
        data["to"] = prev["to"]
    _write_json(fp, data)


def _bind_source(root: str | Path, fact_id: str, intent_id: str) -> None:
    if not graph._safe_id(fact_id):
        raise DispatchError(f"非法 fact id: {fact_id}")
    fp = Path(root) / ".sapper" / "facts" / f"{fact_id}.json"
    data = json.loads(fp.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("id") != fact_id:
        raise DispatchError(f"fact 身份不匹配: {fact_id}")
    data["source_intent"] = intent_id
    _write_json(fp, data)


def dispatch(root: str | Path, intent_id: str, model: str = "deepseek-flash",
             timeout: int = 300, engine: str | None = None,
             tokens: int = DEFAULT_TOKENS) -> dict:
    root = Path(root).resolve()
    nd = ensure_nuwa(root)
    journal = Journal(root)
    ledger = Ledger()
    project = root.name
    intent = graph.get_intent(root, intent_id)
    if not intent:
        raise DispatchError(f"intent 不存在: {intent_id}")
    if is_locked(nd / "inflight" / f"{intent_id}.lock"):
        raise DispatchError(f"intent 正在执行: {intent_id}")
    if intent.get("status") == "done" and intent.get("to"):
        done_fact = graph.get_fact(root, intent["to"])
        if done_fact:
            keys = re.findall(r"\[nuwa:([^\]]+)\]", done_fact.get("description") or "")
            aux = done_fact.get("x-nuwa-key")
            if isinstance(aux, str) and aux:
                keys.append(aux)
            key = keys[0] if keys else txn.dispatch_key(
                project, intent_id, txn.attempt_of(intent))
            return {"intent": intent_id, "fact": done_fact["id"], "reused": True,
                    "key": key}

    attempt = txn.attempt_of(intent)
    key = txn.dispatch_key(project, intent_id, attempt)
    existing = graph.find_fact_by_key(root, key)
    if existing:
        if (intent.get("status") == "done" and intent.get("to")
                and intent["to"] != existing["id"]):
            raise DispatchError(
                f"intent 已由其他 fact 完成: {intent['to']} != {existing['id']}")
        prev_source = existing.get("source_intent")
        prev_intent = graph.get_intent(root, intent_id) or {}
        try:
            with FileLock(nd / "txn.lock", blocking=True):
                if prev_source not in (None, intent_id):
                    raise DispatchError(
                        f"fact 已绑定其他意图: {prev_source} != {intent_id}")
                if not prev_source:
                    _bind_source(root, existing["id"], intent_id)
                graph.patch_intent(root, intent_id, existing["id"])
                ok, msg = graph.validate(root)
                if not ok:
                    raise DispatchError(f"复用后图校验失败: {msg}")
                journal.append("commit_done", txn=key, intent=intent_id,
                               fact=existing["id"], reused=True, project=project)
        except Exception:
            if prev_source is None:
                _unbind_source(root, existing["id"])
            _restore_intent(root, intent_id, prev_intent)
            raise
        return {"intent": intent_id, "fact": existing["id"], "reused": True, "key": key}

    txn_id = f"t-{uuid.uuid4().hex[:12]}"
    rid = f"r-{uuid.uuid4().hex[:12]}"
    _crash("before_reserve")
    # 准入标记与 pending 检查在同一把 txn.lock 内：先写者赢，后到者直接拒绝。
    with FileLock(nd / "txn.lock", blocking=True):
        pending_intents = {p.get("intent") for p in txn.recover(root)["pending"]
                           if p.get("txn") != txn_id}
        if intent_id in pending_intents:
            journal.append("dispatch_rejected", txn=txn_id, rid=rid,
                           intent=intent_id, why="pending_txn")
            journal.append("ack", txn=txn_id, intent=intent_id, status="rejected")
            raise DispatchError(f"intent 有未终态事务: {intent_id}")
        journal.append("reserve_pending", txn=txn_id, rid=rid, intent=intent_id,
                       attempt_seq=attempt, tokens=tokens, project=project)
        journal.append("executing_prepare", txn=txn_id, rid=rid, intent=intent_id,
                       attempt_seq=attempt, key=key, tokens=tokens)
        # attempt 持久递增：迟到的 worker 拿锁后会因版本不符直接退出。
        graph.set_intent_field(root, intent_id, "x-nuwa-attempt", attempt + 1)

    ok, remaining = ledger.admit_reserve(rid, project, tokens)
    if not ok:
        journal.append("reserve_rejected", txn=txn_id, rid=rid, intent=intent_id,
                       remaining=remaining)
        journal.append("ack", txn=txn_id, intent=intent_id, status="rejected")
        raise DispatchError(f"预算不足: remaining={remaining} need={tokens}")
    _crash("after_reserve")
    journal.append("reserve_committed", txn=txn_id, rid=rid, intent=intent_id,
                   tokens=tokens)

    art = nd / "artifacts" / txn_id
    art.mkdir(parents=True, exist_ok=True)
    ready = art / "ready.json"
    result = art / "result.json"
    out = art / "stdout.txt"
    err = art / "stderr.txt"

    try:
        prompt = render_prompt(root, intent_id)
    except Exception as exc:  # noqa: BLE001
        ledger.settle(rid, 0, status="crashed")
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=0, status="crashed")
        journal.append("ack", txn=txn_id, intent=intent_id, status="crashed")
        raise DispatchError(f"渲染提示失败: {exc}") from exc
    ok, rule = policy.check_prompt(prompt)
    if not ok:
        journal.append("policy_block", txn=txn_id, intent=intent_id, rule=rule)
        ledger.settle(rid, 0, status="blocked")
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=0, status="blocked")
        journal.append("ack", txn=txn_id, intent=intent_id, status="blocked")
        raise DispatchError(f"策略拦截: {rule}")
    _crash("after_prepare")
    eng = engine or os.environ.get("NUWA_ENGINE", "omp-claude")
    worker_cmd = [sys.executable, str(WORKER),
                  "--lock", str(nd / "inflight" / f"{intent_id}.lock"),
                  "--ready", str(ready), "--result", str(result),
                  "--stdout", str(out), "--stderr", str(err),
                  "--intent", intent_id, "--attempt", str(attempt),
                  "--", eng, "-p", "--output-format", "json", "--model", model,
                  "--append-system-prompt",
                  "You are the nuwa executor. Follow the rendered intent prompt and return one JSON payload."]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO) + (":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

    t0 = time.time()
    status = "ok"
    try:
        proc = subprocess.run(worker_cmd, input=prompt, text=True,
                              capture_output=True, timeout=timeout, cwd=str(root), env=env)
        rc = proc.returncode
        if proc.returncode == 124:
            status = "timeout"
    except subprocess.TimeoutExpired:
        rc = 124
        status = "timeout"
    except Exception:  # noqa: BLE001  引擎缺失/权限错误同样要落 executed 与结算
        rc = -1
        status = "crashed"
    dur = int((time.time() - t0) * 1000)

    if status == "ok":
        try:
            ok_result = result.exists() and json.loads(
                result.read_text(encoding="utf-8")).get("exit_code") == 0
        except (OSError, json.JSONDecodeError):
            ok_result = False
        if not ok_result:
            status = "crashed"
    _crash("after_execute")
    journal.append("executed", txn=txn_id, rid=rid, intent=intent_id,
                   status=status, exit_code=rc, artifact=str(art), duration_ms=dur,
                   tokens=tokens, settled=False)
    if status != "ok":
        ledger.settle(rid, tokens, status=status)
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=tokens, status=status)
        journal.append("ack", txn=txn_id, intent=intent_id, status=status)
        raise DispatchError(f"dispatch 失败: status={status} rc={rc}")

    try:
        payload = parse_engine_stdout(out.read_text(encoding="utf-8", errors="replace"))
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        desc = data.get("description") if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001  解析异常同样要结算并写终态
        ledger.settle(rid, tokens, status="crashed")
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=tokens, status="crashed")
        journal.append("ack", txn=txn_id, intent=intent_id, status="crashed")
        raise
    if not desc:
        ledger.settle(rid, tokens, status="crashed")
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=tokens, status="crashed")
        journal.append("ack", txn=txn_id, intent=intent_id, status="crashed")
        raise DispatchError("payload 缺少 description")

    try:
        res = txn.commit(root, intent_id, desc, key,
                         kind=str(data.get("kind") or "note"),
                         doc=data.get("doc") if isinstance(data.get("doc"), str) else None)
    except Exception:  # noqa: BLE001  提交异常同样要结算，不能留悬挂预留
        ledger.settle(rid, tokens, status="crashed")
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=tokens, status="crashed")
        journal.append("ack", txn=txn_id, intent=intent_id, status="crashed")
        raise
    ledger.settle(rid, tokens, status="ok")
    _crash("after_settle")
    journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                   tokens=tokens, status="ok")
    journal.append("ack", txn=txn_id, intent=intent_id)
    return {**res, "txn": txn_id, "status": "ok"}
