"""R6 状态迁移：loop_schema 2 → 3。"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .paths import agent_home


def loop_state_dir(home: Path | None = None) -> Path:
    return (home or agent_home()) / "cache" / "nuwa-loop"


def migrate_loop_state(write: bool = False, home: Path | None = None) -> dict:
    d = loop_state_dir(home)
    migrated, skipped, failed = [], [], []
    if not d.exists():
        return {"dir": str(d), "migrated": [], "skipped": [], "failed": []}
    for p in sorted(d.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            failed.append(p.name)
            continue
        schema = int(data.get("schema", 0))
        if schema >= 3:
            skipped.append(p.name)
            continue
        if schema != 2:
            failed.append(p.name)
            continue
        data["schema"] = 3
        data.setdefault("evidence_refs", [])
        if write:
            backup = p.with_suffix(".json.bak")
            shutil.copy2(p, backup)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(p)
        migrated.append(p.name)
    return {"dir": str(d), "migrated": migrated, "skipped": skipped, "failed": failed}
