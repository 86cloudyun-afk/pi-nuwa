"""dispatch：渲染提示、调用引擎、写入 executed、幂等提交。"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import graph, txn, policy
from .journal import Journal
from .ledger import Ledger
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

    attempt = int(intent.get("x-nuwa-attempt", 0))
    key = txn.dispatch_key(project, intent_id, attempt)
    existing = graph.find_fact_by_key(root, key)
    if existing:
        graph.patch_intent(root, intent_id, existing["id"])
        journal.append("commit_done", txn=key, intent=intent_id,
                       fact=existing["id"], reused=True, project=project)
        return {"intent": intent_id, "fact": existing["id"], "reused": True, "key": key}

    ok, remaining = ledger.admit(tokens)
    if not ok:
        raise DispatchError(f"预算不足: remaining={remaining} need={tokens}")

    txn_id = f"t-{uuid.uuid4().hex[:12]}"
    rid = f"r-{uuid.uuid4().hex[:12]}"
    _crash("before_reserve")
    journal.append("reserve_pending", txn=txn_id, rid=rid, intent=intent_id,
                   attempt_seq=attempt, tokens=tokens, project=project)
    ledger.reserve(rid, project, tokens)
    _crash("after_reserve")
    journal.append("reserve_committed", txn=txn_id, rid=rid, intent=intent_id)
    journal.append("executing_prepare", txn=txn_id, rid=rid, intent=intent_id,
                   attempt_seq=attempt, key=key)

    art = nd / "artifacts" / txn_id
    art.mkdir(parents=True, exist_ok=True)
    ready = art / "ready.json"
    result = art / "result.json"
    out = art / "stdout.txt"
    err = art / "stderr.txt"

    prompt = render_prompt(root, intent_id)
    ok, rule = policy.check_prompt(prompt)
    if not ok:
        journal.append("policy_block", txn=txn_id, intent=intent_id, rule=rule)
        ledger.settle(rid, 0, status="blocked")
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
    dur = int((time.time() - t0) * 1000)

    if status == "ok" and (not result.exists() or json.loads(result.read_text()).get("exit_code") != 0):
        status = "crashed"
    _crash("after_execute")
    journal.append("executed", txn=txn_id, rid=rid, intent=intent_id,
                   status=status, exit_code=rc, artifact=str(art), duration_ms=dur,
                   tokens=tokens, settled=False)
    if status != "ok":
        ledger.settle(rid, tokens, status=status)
        journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                       tokens=tokens, status=status)
        raise DispatchError(f"dispatch 失败: status={status} rc={rc}")

    payload = parse_engine_stdout(out.read_text(encoding="utf-8", errors="replace"))
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    desc = data.get("description") if isinstance(data, dict) else None
    if not desc:
        ledger.settle(rid, tokens, status="crashed")
        raise DispatchError("payload 缺少 description")

    res = txn.commit(root, intent_id, desc, key,
                     kind=str(data.get("kind") or "note"),
                     doc=data.get("doc") if isinstance(data.get("doc"), str) else None)
    ledger.settle(rid, tokens, status="ok")
    journal.append("ledger_settle", txn=txn_id, rid=rid, intent=intent_id,
                   tokens=tokens, status="ok")
    journal.append("ack", txn=txn_id, intent=intent_id)
    return {**res, "txn": txn_id, "status": "ok"}
