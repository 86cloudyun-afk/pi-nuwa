"""事实-意图图的读写适配。"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def project(root: str | Path) -> dict:
    return _load(Path(root) / ".sapper" / "project.json") or {}


def intents(root: str | Path) -> list[dict]:
    d = Path(root) / ".sapper" / "intents"
    out = []
    if d.exists():
        for p in sorted(d.glob("*.json")):
            rec = _load(p)
            if rec:
                out.append(rec)
    return out


def facts(root: str | Path) -> list[dict]:
    d = Path(root) / ".sapper" / "facts"
    out = []
    if d.exists():
        for p in sorted(d.glob("*.json")):
            if p.name == "goal.json":
                continue
            rec = _load(p)
            if rec:
                out.append(rec)
    return out


def get_intent(root: str | Path, intent_id: str) -> dict | None:
    return _load(Path(root) / ".sapper" / "intents" / f"{intent_id}.json")


def get_fact(root: str | Path, fact_id: str) -> dict | None:
    return _load(Path(root) / ".sapper" / "facts" / f"{fact_id}.json")


def find_fact_by_key(root: str | Path, key: str) -> dict | None:
    marker = f"[nuwa:{key}]"
    for f in facts(root):
        if marker in (f.get("description") or ""):
            return f
        # 辅助字段与正文 marker 必须同权，否则旧 fact 会被当成未提交而重复执行。
        if f.get("x-nuwa-key") == key:
            return f
    return None


def _atomic_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def set_intent_field(root: str | Path, intent_id: str, field: str, value) -> bool:
    p = Path(root) / ".sapper" / "intents" / f"{intent_id}.json"
    data = _load(p)
    if not data:
        return False
    data[field] = value
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)
    return True


def patch_intent(root: str | Path, intent_id: str, fact_id: str, worker: str = "nuwa") -> dict:
    p = Path(root) / ".sapper" / "intents" / f"{intent_id}.json"
    data = _load(p)
    if not data:
        raise FileNotFoundError(f"intent {intent_id} not found")
    data["status"] = "done"
    data["to"] = fact_id
    data["done_at"] = data.get("done_at") or __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).isoformat(timespec="milliseconds")
    data["worker"] = data.get("worker") or worker
    _atomic_json(p, data)
    return data


def annotate_fact(root: str | Path, fact_id: str, key: str) -> None:
    p = Path(root) / ".sapper" / "facts" / f"{fact_id}.json"
    data = _load(p)
    if not data:
        return
    data["x-nuwa-key"] = key
    _atomic_json(p, data)


def sapper(root: str | Path, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    return subprocess.run(["sapper", *args], cwd=str(root), env=env,
                          capture_output=True, text=True, timeout=timeout)


def validate(root: str | Path) -> tuple[bool, str]:
    r = sapper(root, ["validate"])
    return r.returncode == 0, (r.stdout + r.stderr).strip()
