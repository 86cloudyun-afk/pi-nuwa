"""项目注册表 registry.json（缓存，可重建）。"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .locks import is_locked
from .paths import registry_path, sapper_home


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def scan(home: str | Path | None = None) -> list[dict]:
    base = Path(home) if home else sapper_home()
    items: list[dict] = []
    if not base.exists():
        return items
    for d in sorted(base.iterdir()):
        if not d.is_dir() or d.name == "budget":
            continue
        if not (d / ".sapper" / "project.json").exists():
            continue
        run = _read_json(d / ".nuwa" / "run.json") or {}
        lock = d / ".nuwa" / "run.lock"
        items.append({
            "name": d.name,
            "root": str(d.resolve()),
            "running": is_locked(lock),
            "round": run.get("round", 0),
            "turns": run.get("turns", 0),
            "status": run.get("status", "unknown"),
            "updated_at": run.get("updated_at", 0),
            "heartbeat": time.time() if is_locked(lock) else run.get("updated_at", 0),
        })
    return items


def write(items: list[dict], path: str | Path | None = None) -> Path:
    p = Path(path) if path else registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"registry_schema": 1, "items": items}, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    os.replace(tmp, p)
    return p


def load(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else registry_path()
    data = _read_json(p)
    if not data or not isinstance(data.get("items"), list):
        return scan()
    return data["items"]


def rebuild(path: str | Path | None = None) -> list[dict]:
    items = scan()
    write(items, path)
    return items


def find(name: str, path: str | Path | None = None) -> dict | None:
    for it in load(path):
        if it["name"] == name or it["root"] == str(Path(name).expanduser().resolve()):
            return it
    return None
