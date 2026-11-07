#!/usr/bin/env python3
"""
压力测试：并发 N 个 nuwa 实例跑同一套 fake-sapper 靶场，采集可分析数据。

不做的事：不用真模型，不碰真实目标。
做的事：把 bin/nuwa 的锁、预算、frontier、dispatch 并发路径压到极限，
        产出 events.jsonl / calls.jsonl / metrics.json 供 analyze.py 出报告。

用法：
  python3 stress.py --instances 8 --minutes 1
  python3 stress.py --instances 4 --inject empty_frontier
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SANDBOX = Path(os.environ.get("NUWA_SANDBOX", "/tmp/nuwa-sandbox"))
WORK = Path(os.environ.get("NUWA_WORK", "/tmp/nuwa-work"))
NUWA = WORK / "bin" / "nuwa"
LAYER_A = SANDBOX / "layer-a"


def run_one(idx: int, root: Path, minutes: int, inject: dict) -> dict:
    lab = root / f"lab-{idx}"
    agent = root / f"agent-{idx}"
    lab.mkdir(parents=True, exist_ok=True)
    agent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = f"{LAYER_A}:{env.get('PATH', '')}"
    env["SAPPER_HOME"] = str(lab)
    env["PI_AGENT_HOME"] = str(agent)
    env["NUWA_ENV"] = "/dev/null"
    env["SAPPER_TIMEOUT"] = "20"
    env.update({k: str(v) for k, v in inject.items()})

    t0 = time.time()
    p = subprocess.run(
        [str(NUWA), f"http://127.0.0.1:{18080 + idx}", f"p{idx}",
         "--no-view", "--minutes", str(minutes), "--parallel", "3"],
        cwd=str(root), env=env, capture_output=True, text=True, timeout=minutes * 60 + 120,
    )
    dur = time.time() - t0

    proj = lab / f"p{idx}"
    calls = []
    calls_path = proj / ".sapper" / "calls.jsonl"
    if calls_path.exists():
        for line in calls_path.read_text().splitlines():
            try:
                calls.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    events = []
    ev_path = proj / "events.jsonl"
    if ev_path.exists():
        for line in ev_path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    dispatches = [c for c in calls if c.get("argv") and c["argv"][0] == "dispatch"]
    reasons = [c for c in dispatches if len(c["argv"]) > 1 and c["argv"][1] == "reason"]
    return {
        "idx": idx,
        "rc": p.returncode,
        "dur": round(dur, 2),
        "stdout_tail": p.stdout[-400:],
        "stderr_tail": p.stderr[-400:],
        "calls": len(calls),
        "dispatch": len(dispatches),
        "reason": len(reasons),
        "events": len(events),
        "event_kinds": sorted({e.get("event") for e in events}),
        "project_status": json.loads((proj / ".sapper" / "project.json").read_text()).get("status")
        if (proj / ".sapper" / "project.json").exists() else None,
        "lock_left": (proj / ".nuwa.lock").exists(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instances", type=int, default=4)
    ap.add_argument("--minutes", type=int, default=1)
    ap.add_argument("--inject", default="")
    ap.add_argument("--out", default=str(SANDBOX / "reports" / "stress"))
    args = ap.parse_args()

    inject = {}
    if args.inject == "empty_frontier":
        inject["FAKE_EMPTY_FRONTIER"] = "1"
    elif args.inject == "noop":
        inject["FAKE_NOOP_DISPATCH"] = "1"
    elif args.inject == "slow":
        inject["FAKE_SLOW"] = "2"
    elif args.inject == "error":
        inject["FAKE_ERROR"] = "1"

    root = Path(tempfile.mkdtemp(prefix="nuwa-stress-"))
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.instances) as ex:
        futs = [ex.submit(run_one, i, root, args.minutes, inject) for i in range(args.instances)]
        rows = [f.result() for f in futs]
    wall = round(time.time() - t0, 2)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "raw.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2))
    (out / "metrics.json").write_text(json.dumps({
        "instances": args.instances,
        "minutes": args.minutes,
        "inject": args.inject or "none",
        "wall_sec": wall,
        "ok": sum(1 for r in rows if r["rc"] == 0),
        "failed": sum(1 for r in rows if r["rc"] != 0),
        "dispatches": sum(r["dispatch"] for r in rows),
        "reasons": sum(r["reason"] for r in rows),
        "avg_dur": round(sum(r["dur"] for r in rows) / len(rows), 2),
        "max_dur": max(r["dur"] for r in rows),
        "lock_left": sum(1 for r in rows if r["lock_left"]),
    }, ensure_ascii=False, indent=2))

    print(json.dumps({
        "wall_sec": wall,
        "ok": sum(1 for r in rows if r["rc"] == 0),
        "failed": sum(1 for r in rows if r["rc"] != 0),
        "dispatches": sum(r["dispatch"] for r in rows),
        "avg_dur": round(sum(r["dur"] for r in rows) / len(rows), 2),
        "max_dur": max(r["dur"] for r in rows),
    }, ensure_ascii=False, indent=2))
    shutil.rmtree(root, ignore_errors=True)
    return 0 if all(r["rc"] == 0 for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
