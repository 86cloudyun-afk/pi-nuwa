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
    started = time.time()
    res = soak.soak(roots, minutes=minutes, interval=interval, parallel=2, model=model)
    res["mode"] = "soak"
    res["base"] = str(base)
    res["started_at"] = started
    res["finished_at"] = time.time()
    res["duration_seconds"] = res["finished_at"] - started
    res["commit"] = _commit()
    (base / "REPORT.json").write_text(json.dumps(res, ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    (base / "MODE").write_text("soak\n", encoding="utf-8")
    (base / "COMMIT").write_text(res["commit"] + "\n", encoding="utf-8")
    return res


def _number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} 不是数值: {value!r}")
    return float(value)


def verify(base: str | Path, expect_commit: str | None = None) -> dict:
    """校验夜跑产物：REPORT.json / MODE / COMMIT 必须一致且判据全绿。

    72h 长跑由自托管 runner 执行，本函数是收工时的唯一判据入口：
    缺 MODE/COMMIT、判据键不齐、判据值不是布尔真、实际时长短于请求时长，
    任一情况都判失败。`expect_commit` 用于把报告钉死在期望的提交上。
    """
    base = Path(base)
    rep_path = base / "REPORT.json"
    try:
        rep = json.loads(rep_path.read_text(encoding="utf-8"))
        if not isinstance(rep, dict):
            raise ValueError("REPORT 顶层不是对象")

        def _read(name: str) -> str:
            try:
                return (base / name).read_text(encoding="utf-8").strip()
            except OSError:
                return ""

        mode = _read("MODE")
        commit = _read("COMMIT")
        verdict = rep.get("verdict")
        if not isinstance(verdict, dict):
            raise ValueError("verdict 不是对象")
        required = {"all_zero", "rss_ok", "fd_ok", "facts_ok"}
        missing = sorted(required - set(verdict))
        if missing:
            raise ValueError(f"verdict 缺少判据: {missing}")
        if not all(isinstance(v, bool) and v for v in verdict.values()):
            raise ValueError("verdict 存在非布尔或假值")

        minutes = _number(rep.get("minutes"), "minutes")
        samples = _number(rep.get("samples"), "samples")
        duration = _number(rep.get("duration_seconds"), "duration_seconds")
        started = _number(rep.get("started_at"), "started_at")
        finished = _number(rep.get("finished_at"), "finished_at")

        checks = {
            "mode": rep.get("mode") == "soak" and mode == "soak",
            "commit": bool(rep.get("commit")) and rep.get("commit") == commit
            and (expect_commit is None or commit == expect_commit),
            "minutes": minutes > 0,
            "samples": samples >= 2,
            "verdict": True,
            "duration": finished >= started and duration >= minutes * 60 * 0.9,
        }
        return {"ok": all(checks.values()), "checks": checks, "mode": mode,
                "commit": commit, "report": str(rep_path),
                "duration_seconds": duration, "expected_minutes": minutes}
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        return {"ok": False, "error": f"报告校验失败: {exc}", "checks": {}}
