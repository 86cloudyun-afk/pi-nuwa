#!/usr/bin/env python3
"""崩溃矩阵：7 个提交点 × N 轮，验证崩溃后 repair + 重派只产生一个 fact。

快速：--fake-repeat 2 --real-repeat 1
全量：--full  → fake 6 点 ×20、real 4 点 ×5
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from nuwa import graph, txn  # noqa: E402

FAKE_POINTS = ["before_reserve", "after_reserve", "after_prepare",
               "after_execute", "after_done", "after_validate"]
REAL_POINTS = ["after_prepare", "after_execute", "after_done", "after_settle"]


def project(base: Path, name: str, env: dict) -> Path:
    root = base / name
    root.mkdir(parents=True)
    for cmd in (["sapper", "setup", "--goal", name],
                ["sapper", "fact", "alive", "-k", "host"],
                ["sapper", "intent", "--from", "f001", "probe"]):
        subprocess.run(cmd, cwd=root, env=env, check=True, capture_output=True)
    return root


def one(base: Path, name: str, point: str, env: dict) -> None:
    root = project(base, name, env)
    crash_env = {**env, "NUWA_CRASH_POINT": point, "PYTHONPATH": str(REPO)}
    proc = subprocess.run(
        [sys.executable, "-m", "nuwa.cli", "dispatch", "i001", "--model", "fake",
         "--root", str(root)],
        env=crash_env, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 137:
        raise AssertionError(f"{point}: 未在注入点退出 rc={proc.returncode} {proc.stderr[:200]}")
    txn.repair(root)
    subprocess.run(
        [sys.executable, "-m", "nuwa.cli", "dispatch", "i001", "--model", "fake",
         "--root", str(root)],
        env={**env, "PYTHONPATH": str(REPO)}, check=True, capture_output=True, text=True,
        timeout=60,
    )
    facts = [f for f in graph.facts(root) if "[nuwa:" in (f.get("description") or "")]
    if len(facts) != 1:
        raise AssertionError(f"{point}: facts={len(facts)}")
    intent = graph.get_intent(root, "i001")
    if intent["status"] != "done" or intent["to"] != facts[0]["id"]:
        raise AssertionError(f"{point}: intent={intent}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fake-repeat", type=int, default=2)
    ap.add_argument("--real-repeat", type=int, default=1)
    ap.add_argument("--full", action="store_true")
    args = ap.parse_args()
    fr, rr = (20, 5) if args.full else (args.fake_repeat, args.real_repeat)

    tmp = Path(tempfile.mkdtemp(prefix="nuwa-crash-matrix-"))
    env = dict(os.environ)
    env["PATH"] = f"{HERE}:{env.get('PATH', '')}"
    env["SAPPER_HOME"] = str(tmp / "lab")
    env["PI_AGENT_HOME"] = str(tmp / "agent")
    env["NUWA_ENGINE"] = "fake-claude"
    os.environ.update(env)

    total = 0
    try:
        for point in FAKE_POINTS:
            for i in range(fr):
                one(tmp, f"f-{point}-{i}", point, env)
                total += 1
        for point in REAL_POINTS:
            for i in range(rr):
                one(tmp, f"r-{point}-{i}", point, env)
                total += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"crash-matrix OK: {total} runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
