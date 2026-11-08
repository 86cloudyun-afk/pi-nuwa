"""R7 夜跑：准备项目、跑 soak、落报告。"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

from . import graph, soak


def prepare(base: str | Path, projects: int) -> list[str]:
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    roots: list[str] = []
    for i in range(projects):
        root = base / f"s{i}"
        root.mkdir(parents=True, exist_ok=True)
        if not (root / ".sapper" / "project.json").exists():
            graph.sapper(root, ["setup", "--goal", f"soak-night {i}", "--agents"])
            graph.sapper(root, ["fact", f"靶标 s{i} 可达", "-k", "host"])
            graph.sapper(root, ["intent", "--from", "f001", "探测"])
        roots.append(str(root))
    return roots


def _commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                              text=True, timeout=5).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def run(base: str | Path, minutes: float, projects: int, interval: float = 30,
        model: str = "deepseek-flash") -> dict:
    base = Path(base)
    roots = prepare(base, projects)
    res = soak.soak(roots, minutes=minutes, interval=interval, parallel=2, model=model)
    res["mode"] = "soak"
    res["base"] = str(base)
    res["started_at"] = time.time()
    res["commit"] = _commit()
    (base / "REPORT.json").write_text(json.dumps(res, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    (base / "MODE").write_text("soak\n", encoding="utf-8")
    (base / "COMMIT").write_text(res["commit"] + "\n", encoding="utf-8")
    return res


def verify(base: str | Path) -> dict:
    """校验夜跑产物：REPORT.json / MODE / COMMIT 必须一致且判据全绿。

    72h 长跑由自托管 runner 执行，本函数是收工时的唯一判据入口：
    没有 MODE 与 COMMIT 的报告一律视为不可采信。
    """
    base = Path(base)
    rep_path = base / "REPORT.json"
    try:
        rep = json.loads(rep_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"REPORT.json 不可读: {exc}", "checks": {}}

    def _read(name: str) -> str:
        try:
            return (base / name).read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    mode = _read("MODE")
    commit = _read("COMMIT")
    verdict = rep.get("verdict") or {}
    checks = {
        "mode": rep.get("mode") == "soak" and mode == "soak",
        "commit": bool(rep.get("commit")) and rep.get("commit") == commit,
        "minutes": float(rep.get("minutes") or 0) > 0,
        "samples": int(rep.get("samples") or 0) >= 2,
        "verdict": bool(verdict) and all(bool(v) for v in verdict.values()),
    }
    return {"ok": all(checks.values()), "checks": checks, "mode": mode,
            "commit": commit, "report": str(rep_path)}
