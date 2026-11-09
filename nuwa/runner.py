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
from .ledger import Ledger
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
    facts = {}
    try:
        for fp in (Path(root) / ".sapper" / "facts").glob("*.json"):
            if fp.name == "goal.json":
                continue
            f = graph._load(fp)
            if not isinstance(f, dict) or f.get("id") != fp.stem:
                return False
            facts[f["id"]] = f
    except OSError:
        return False
    goal = graph.get_fact(root, "goal")
    proj = graph.project(root)
    if (not isinstance(goal, dict) or goal.get("id") != "goal"
            or not proj.get("goal") or goal.get("description") != proj.get("goal")):
        return False
    edges = []
    try:
        for ip in (Path(root) / ".sapper" / "intents").glob("*.json"):
            it = graph._load(ip)
            if not isinstance(it, dict) or it.get("id") != ip.stem:
                return False
            if it.get("to") == "goal":
                edges.append(it)
    except OSError:
        return False
    if not edges:
        # 无完成边的 completed 是异常状态，不能用整图历史事实兜底。
        return False
    for edge in edges:
        if edge.get("status") != "complete":
            return False
        raw_refs = edge.get("from") or []
        if not isinstance(raw_refs, list) or not all(isinstance(x, str) for x in raw_refs):
            return False
        refs = list(raw_refs)
        if not refs:
            return False
        if not all(facts.get(fid, {}).get("kind") in ("flag", "vuln", "loot")
                   for fid in refs):
            return False
    return True


def _revert(root: Path, why: str) -> str:
    p = Path(root) / ".sapper" / "project.json"
    from .locks import FileLock
    with FileLock(Path(root) / ".sapper" / ".lock", blocking=True):
        data = graph._load(p) or {}
        if data.get("status") != "completed":
            return "noop"
        if _evidence(root):
            # 等待锁期间可能已有新的有效完成，不能误删。
            return "noop"
        # 与真实 sapper 共用 .sapper/.lock：删边、写 active、hint 都在锁内。
        edges = []
        for ipath in sorted((Path(root) / ".sapper" / "intents").glob("*.json")):
            it = graph._load(ipath) or {}
            if it.get("to") == "goal":
                try:
                    edges.append((ipath, ipath.read_text(encoding="utf-8")))
                except OSError:
                    return "failed"
        removed = []
        for ipath, body in edges:
            try:
                ipath.unlink()
                removed.append((ipath, body))
            except FileNotFoundError:
                removed.append((ipath, body))
            except OSError:
                for p2, b2 in removed:
                    try:
                        p2.write_text(b2, encoding="utf-8")
                    except OSError:
                        pass
                return "failed"
        data["status"] = "active"
        data.pop("completed_at", None)
        data.pop("completed_from", None)
        try:
            graph._atomic_json(p, data)
        except Exception:
            for p2, b2 in removed:
                try:
                    p2.write_text(b2, encoding="utf-8")
                except OSError:
                    pass
            return "failed"
        hp = Path(root) / ".sapper" / "hints.json"
        hints = graph._load(hp) or []
        hints.append({"content": f"完成被拒绝：{why}", "creator": "nuwa",
                      "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        graph._atomic_json(hp, hints)
    return "reverted"


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
    complete = data.get("complete") if isinstance(data, dict) else None
    if not isinstance(intents, list):
        intents = []
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
        r = graph.sapper(root, args, allow_submit=True)
        if r.returncode != 0:
            journal.append("reason_intent_failed", round=round_no, error=(r.stdout + r.stderr)[:200])
            continue
        after = [i for i in graph.intents(root) if i["id"] not in before]
        if after:
            _annotate_intent(root, after[0]["id"], key)
            created += 1
    if isinstance(complete, dict):
        from_ids = [str(x) for x in (complete.get("from") or []) if x]
        facts = {f.get("id"): f for f in graph.facts(root)}
        if from_ids and all(facts.get(fid, {}).get("kind") in ("flag", "vuln", "loot")
                            for fid in from_ids):
            r = graph.sapper(root, ["complete", "--from", ",".join(from_ids),
                                    "--note", str(complete.get("description") or "reason complete")],
                             allow_submit=True)
            if r.returncode == 0:
                journal.append("reason_complete", round=round_no, facts=from_ids)
            else:
                journal.append("reason_complete_failed", round=round_no,
                               error=(r.stdout + r.stderr)[:200])
        else:
            journal.append("reason_complete_rejected", round=round_no, facts=from_ids)
    journal.append("reason_applied", round=round_no, created=created)
    return created


def _reason(root: Path, model: str, round_no: int, journal: Journal,
            timeout: int = 240) -> None:
    freeze_failed = False
    nd = ensure_nuwa(root)
    if (nd / "reason.freeze").exists():
        journal.append("reason_frozen", round=round_no)
        return
    led = Ledger()
    rid = f"r-reason-{time.time_ns()}"
    render = graph.sapper(root, ["dispatch", "reason", "--dry-run"])
    prompt_len = len(render.stdout or "")
    if render.returncode != 0:
        journal.append("reason_render_failed", round=round_no)
        return
    need = max(4000, prompt_len // 4 + 2000)
    rlock = FileLock(nd / "inflight" / "reason.lock", blocking=False)
    try:
        rlock.__enter__()
    except LockTimeout:
        journal.append("reason_busy", round=round_no, rid=rid)
        return
    try:
        journal.append("reason_reserve", txn=rid, rid=rid, intent="reason", tokens=need)
        ok, remaining = led.admit_reserve(rid, str(root), need)
    except BaseException:
        try:
            rlock.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass
        raise
    if not ok:
        try:
            journal.append("reason_rejected", txn=rid, rid=rid, remaining=remaining)
        finally:
            try:
                rlock.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
        return
    tokens_actual = 0
    settle_status = "ok"
    try:
        try:
            raw = call(render.stdout, model=model, timeout=timeout,
                       pass_fds=(rlock.fd,))
            tokens_actual = max(0, (prompt_len + len(raw)) // 4)
            payload = dispatch_mod.parse_engine_stdout(raw)
        except KeyboardInterrupt:
            settle_status = "error"
            tokens_actual = max(tokens_actual, prompt_len // 4)
            if tokens_actual > need * 1.05:
                try:
                    (nd / "reason.freeze").write_text(
                        f"overrun {tokens_actual}>{need}\n", encoding="utf-8")
                except OSError as exc:
                    freeze_failed = True
                    try:
                        journal.append("reason_freeze_failed", round=round_no, rid=rid,
                                       error=str(exc)[:200])
                    except Exception:  # noqa: BLE001
                        pass
                    raise RuntimeError("reason 超支但冻结失败") from exc
            raise
        except OSError as exc:
            settle_status = "error"
            tokens_actual = max(tokens_actual, prompt_len // 4)
            journal.append("reason_usage", txn=rid, rid=rid, tokens=tokens_actual)
            journal.append("reason_failed", round=round_no, error=str(exc)[:200])
            return
        except (EngineError, dispatch_mod.DispatchError) as exc:
            settle_status = "error"
            partial = getattr(exc, "partial", "") or ""
            tokens_actual = max(tokens_actual,
                                (prompt_len + len(partial)) // 4)
            if tokens_actual > need * 1.05:
                try:
                    (nd / "reason.freeze").write_text(
                        f"overrun {tokens_actual}>{need}\n", encoding="utf-8")
                except OSError as fexc:
                    freeze_failed = True
                    try:
                        journal.append("reason_freeze_failed", round=round_no, rid=rid,
                                       error=str(fexc)[:200])
                    except Exception:  # noqa: BLE001
                        pass
                    raise RuntimeError("reason 超支但冻结失败") from fexc
            journal.append("reason_usage", txn=rid, rid=rid, tokens=tokens_actual)
            journal.append("reason_failed", round=round_no, error=str(exc)[:200])
            return
        overrun = tokens_actual > need * 1.05
        try:
            journal.append("reason_usage", txn=rid, rid=rid, tokens=tokens_actual)
        finally:
            if overrun:
                try:
                    (nd / "reason.freeze").write_text(
                        f"overrun {tokens_actual}>{need}\n", encoding="utf-8")
                except OSError as exc:
                    freeze_failed = True
                    try:
                        journal.append("reason_freeze_failed", round=round_no, rid=rid,
                                       error=str(exc)[:200])
                    except Exception:  # noqa: BLE001
                        pass
                    raise RuntimeError("reason 超支但冻结失败") from exc
                journal.append("reason_overrun", round=round_no, rid=rid,
                               tokens=tokens_actual, reserved=need)
                raise RuntimeError("reason 超支，暂停派发")
        _apply_reason(root, payload, round_no, journal)
    finally:
        try:
            if freeze_failed:
                try:
                    journal.append("reason_usage", txn=rid, rid=rid, tokens=tokens_actual)
                except Exception:  # noqa: BLE001
                    pass
                raise RuntimeError("reason 冻结失败，保留待恢复")
            led.settle(rid, tokens_actual, status=settle_status)
            journal.append("ack", txn=rid, intent="reason", status=settle_status)
            if tokens_actual > need * 1.05:
                journal.append("reason_overrun", round=round_no, rid=rid,
                               tokens=tokens_actual, reserved=need)
                try:
                    (nd / "reason.freeze").write_text(
                        f"overrun {tokens_actual}>{need}\n", encoding="utf-8")
                except OSError:
                    pass
                raise RuntimeError("reason 超支，暂停派发")
            journal.append("reason_budget_settled", round=round_no, rid=rid)
        finally:
            try:
                rlock.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass


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

    try:
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
    except BaseException:
        try:
            lock.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass
        raise
    try:
        while time.time() < deadline:
            round_no += 1
            ids = _ids(root)
            if not ids:
                _reason(root, model, round_no, journal)
                ids = _ids(root)
            if not ids:
                status = _project_status(root)
                if status == "completed":
                    if _evidence(root):
                        journal.append("project_completed", round=round_no)
                        break
                    _rev = _revert(root, "没有任何 flag/vuln/loot 事实")
                    if _rev == "reverted":
                        journal.append("completion_rejected", round=round_no)
                    elif _rev == "failed":
                        journal.append("revert_failed", round=round_no)
                        exit_code = 1
                    else:
                        journal.append("revert_noop", round=round_no)
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
                _rev = _revert(root, "没有任何 flag/vuln/loot 事实")
                if _rev == "reverted":
                    journal.append("completion_rejected", round=round_no)
                elif _rev == "failed":
                    journal.append("revert_failed", round=round_no)
                    exit_code = 1
                else:
                    journal.append("revert_noop", round=round_no)

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
        try:
            _write_run(root, status="stopped", round=round_no, turns=turns,
                       deadline=deadline)
            journal.append("run_stop", round=round_no, turns=turns)
        finally:
            lock.__exit__(None, None, None)
    return exit_code
