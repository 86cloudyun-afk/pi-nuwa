#!/usr/bin/env python3
"""
小长测（soak）：跑 N 分钟，周期采样，抓内存/FD/状态文件的慢性增长。

用法：
  python3 soak.py --minutes 10 --interval 5 --instances 2
  python3 soak.py --minutes 5  --interval 2 --instances 2 --mode noop

判定口径（避免把正常增长当泄漏）：
  - 退出码：0，或 143/SIGTERM（由采样器主动收工时）
  - RSS：只测主进程，跳过前 20% 预热样本后做最小二乘，< 2 MB/min
  - FD：只测主进程，斜率 <= 2/min
  - 状态体积：按「每 fact 字节数」算，< 4 KB/fact（图本来就会长）
  - 事件日志：< 512 KB/min
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
if not (LAYER_A / "fake-sapper").exists():
    LAYER_A = Path(__file__).resolve().parent

RSS_LIMIT_KB_PER_MIN = 2048
FD_LIMIT_PER_MIN = 2.0
STATE_BYTES_PER_FACT = 4096
EVENT_KB_PER_MIN = 512


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
    out = []
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
                out.append(int(p.name))
                out.extend(descendants(int(p.name)))
    except OSError:
        pass
    return out


def graph_metrics(root: Path) -> tuple[int, int, int]:
    """返回 (facts 总数, 图 JSON 总字节, events 行数)。"""
    facts = 0
    size = 0
    lines = 0
    for proj in root.glob("lab-*/p*"):
        s = proj / ".sapper"
        if s.exists():
            for f in s.glob("facts/*.json"):
                if f.name != "goal.json":
                    facts += 1
            for f in s.glob("**/*.json"):
                try:
                    size += f.stat().st_size
                except OSError:
                    pass
        ev = proj / "events.jsonl"
        if ev.exists():
            try:
                lines += len(ev.read_text().splitlines())
            except OSError:
                pass
    return facts, size, lines


def slope(points: list[tuple[float, float]]) -> float:
    if len(points) < 3:
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
    ap.add_argument("--terminate-ok", action="store_true", default=True)
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
        procs.append(p)

    samples = []
    t0 = time.time()
    while time.time() - t0 < args.minutes * 60:
        alive = sum(1 for p in procs if p.poll() is None)
        rss = 0
        fds = 0
        kids = 0
        for p in procs:
            if p.poll() is None:
                rss += rss_kb(p.pid)          # 只算主进程
                fds += fd_count(p.pid)
                kids += len(descendants(p.pid))
        facts, size, lines = graph_metrics(root)
        samples.append({
            "t": round(time.time() - t0, 1),
            "alive": alive,
            "rss_kb": rss,
            "fds": fds,
            "descendants": kids,
            "facts": facts,
            "state_bytes": size,
            "event_lines": lines,
        })
        time.sleep(args.interval)

    codes = []
    for p in procs:
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

    # 预热样本跳过：前 20%（至少跳过 2 个）
    warm = max(2, int(len(samples) * 0.2))
    steady = samples[warm:] or samples
    rss_points = [(s["t"] / 60.0, s["rss_kb"]) for s in steady]
    fd_points = [(s["t"] / 60.0, s["fds"]) for s in steady]
    rss_slope = slope(rss_points)
    fd_slope = slope(fd_points)

    max_state = max((s["state_bytes"] for s in samples), default=0)
    max_facts = max((s["facts"] for s in samples), default=0)
    bytes_per_fact = max_state / max_facts if max_facts else 0
    duration_min = args.minutes or 1
    event_kb_per_min = (samples[-1]["event_lines"] * 120 / 1024) / duration_min if samples else 0

    accepted = {0, 143, -15}
    summary = {
        "minutes": args.minutes,
        "interval": args.interval,
        "instances": args.instances,
        "mode": args.mode,
        "samples": len(samples),
        "warmup_skipped": warm,
        "exit_codes": codes,
        "all_ok": all(c in accepted for c in codes),
        "rss_start_kb": samples[0]["rss_kb"] if samples else 0,
        "rss_end_kb": samples[-1]["rss_kb"] if samples else 0,
        "rss_slope_kb_per_min": round(rss_slope, 2),
        "fd_slope_per_min": round(fd_slope, 3),
        "max_facts": max_facts,
        "max_state_bytes": max_state,
        "bytes_per_fact": round(bytes_per_fact, 1),
        "event_lines": samples[-1]["event_lines"] if samples else 0,
        "event_kb_per_min": round(event_kb_per_min, 1),
        "verdict": {
            "exit_ok": all(c in accepted for c in codes),
            "rss_ok": rss_slope < RSS_LIMIT_KB_PER_MIN,
            "fd_ok": fd_slope <= FD_LIMIT_PER_MIN,
            "state_ok": bytes_per_fact < STATE_BYTES_PER_FACT,
            "events_ok": event_kb_per_min < EVENT_KB_PER_MIN,
        },
    }
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    shutil.rmtree(root, ignore_errors=True)
    return 0 if all(summary["verdict"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
