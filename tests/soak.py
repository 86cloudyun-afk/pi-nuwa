#!/usr/bin/env python3
"""
小长测（soak）：跑 N 分钟，周期采样，抓内存/FD/状态文件的慢性增长。

用法：
  python3 soak.py --minutes 10 --interval 5 --instances 2
  python3 soak.py --minutes 5  --interval 2 --instances 2 --mode noop

输出：
  reports/soak-<ts>/samples.csv
  reports/soak-<ts>/summary.json

判定：
  - 所有实例退出码 0
  - RSS 斜率 < 2 MB/min（单实例）
  - FD 增长 <= 2
  - 状态文件不随轮数线性膨胀（< 64 KB）
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SANDBOX = Path(os.environ.get("NUWA_SANDBOX", "/tmp/nuwa-sandbox"))
WORK = Path(os.environ.get("NUWA_WORK", "/tmp/nuwa-work"))
NUWA = WORK / "bin" / "nuwa"
LAYER_A = SANDBOX / "layer-a"


def rss_kb(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def descendants(pid: int) -> list[int]:
    out = [pid]
    try:
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                stat = (p / "stat").read_text().split()
                ppid = int(stat[3])
            except (OSError, ValueError, IndexError):
                continue
            if ppid == pid:
                out.extend(descendants(int(p.name)))
    except OSError:
        pass
    return out


def tree_metrics(pid: int) -> tuple[int, int]:
    pids = descendants(pid)
    return sum(rss_kb(p) for p in pids), sum(fd_count(p) for p in pids)


def path_metrics(root: Path) -> tuple[int, int]:
    """返回 (events 行数, 状态文件总字节)。"""
    lines = 0
    size = 0
    for proj in root.glob("lab-*/p*"):
        ev = proj / "events.jsonl"
        if ev.exists():
            try:
                lines += len(ev.read_text().splitlines())
                size += ev.stat().st_size
            except OSError:
                pass
        for f in (proj / ".sapper").glob("**/*.json") if (proj / ".sapper").exists() else []:
            try:
                size += f.stat().st_size
            except OSError:
                pass
    return lines, size


def slope(points: list[tuple[float, float]]) -> float:
    """最小二乘斜率，单位 per minute。"""
    if len(points) < 2:
        return 0.0
    n = len(points)
    sx = sum(p[0] for p in points)
    sy = sum(p[1] for p in points)
    sxx = sum(p[0] * p[0] for p in points)
    sxy = sum(p[0] * p[1] for p in points)
    den = n * sxx - sx * sx
    if abs(den) < 1e-9:
        return 0.0
    return (n * sxy - sx * sy) / den


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=10)
    ap.add_argument("--interval", type=float, default=5)
    ap.add_argument("--instances", type=int, default=2)
    ap.add_argument("--mode", default="normal", choices=["normal", "noop", "slow"])
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    root = Path(tempfile.mkdtemp(prefix="nuwa-soak-"))
    out = Path(args.out) if args.out else SANDBOX / "reports" / f"soak-{time.strftime('%H%M%S')}"
    out.mkdir(parents=True, exist_ok=True)

    procs = []
    for i in range(args.instances):
        lab = root / f"lab-{i}"
        agent = root / f"agent-{i}"
        lab.mkdir(parents=True)
        agent.mkdir(parents=True)
        env = dict(os.environ)
        env["PATH"] = f"{LAYER_A}:{env.get('PATH', '')}"
        env["SAPPER_HOME"] = str(lab)
        env["PI_AGENT_HOME"] = str(agent)
        env["NUWA_ENV"] = "/dev/null"
        env["FAKE_COMPLETE_AFTER"] = "999999"
        if args.mode == "noop":
            env["FAKE_NOOP_DISPATCH"] = "1"
        elif args.mode == "slow":
            env["FAKE_SLOW"] = "1"
            env["FAKE_COMPLETE_AFTER"] = "3"
        p = subprocess.Popen(
            [str(NUWA), f"http://127.0.0.1:{18080 + i}", f"p{i}",
             "--no-view", "--minutes", str(int(args.minutes) + 1), "--parallel", "2"],
            cwd=str(root), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        procs.append((p, lab / f"p{i}"))

    samples = []
    t0 = time.time()
    while time.time() - t0 < args.minutes * 60:
        alive = sum(1 for p, _ in procs if p.poll() is None)
        rss = 0
        fds = 0
        for p, _ in procs:
            if p.poll() is None:
                r, f = tree_metrics(p.pid)
                rss += r
                fds += f
        lines, size = path_metrics(root)
        samples.append({
            "t": round(time.time() - t0, 1),
            "alive": alive,
            "rss_kb": rss,
            "fds": fds,
            "event_lines": lines,
            "state_bytes": size,
        })
        time.sleep(args.interval)

    codes = []
    for p, _ in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
        try:
            codes.append(p.wait(timeout=20))
        except subprocess.TimeoutExpired:
            p.kill()
            codes.append(-9)

    with open(out / "samples.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(samples[0].keys()) if samples else ["t"])
        w.writeheader()
        w.writerows(samples)

    rss_points = [(s["t"] / 60.0, s["rss_kb"]) for s in samples]
    fd_points = [(s["t"] / 60.0, s["fds"]) for s in samples]
    rss_slope = slope(rss_points)
    fd_slope = slope(fd_points)
    max_state = max((s["state_bytes"] for s in samples), default=0)
    summary = {
        "minutes": args.minutes,
        "interval": args.interval,
        "instances": args.instances,
        "mode": args.mode,
        "samples": len(samples),
        "exit_codes": codes,
        "all_ok": all(c == 0 for c in codes),
        "rss_start_kb": samples[0]["rss_kb"] if samples else 0,
        "rss_end_kb": samples[-1]["rss_kb"] if samples else 0,
        "rss_slope_kb_per_min": round(rss_slope, 2),
        "fd_slope_per_min": round(fd_slope, 3),
        "max_state_bytes": max_state,
        "event_lines": samples[-1]["event_lines"] if samples else 0,
        "verdict": {
            "exit_ok": all(c == 0 for c in codes),
            "rss_ok": rss_slope < 2048,
            "fd_ok": fd_slope <= 2,
            "state_ok": max_state < 65536,
        },
    }
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    shutil.rmtree(root, ignore_errors=True)
    ok = all(summary["verdict"].values())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
