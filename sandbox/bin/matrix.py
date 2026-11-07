#!/usr/bin/env python3
"""
多类型同时压测（matrix）。

A 段 编排矩阵：8 个目标 × N 副本，同时起 nuwa（fake-sapper），测 URL 解析、
   锁、预算、退出码在不同目标类型下是否一致。

B 段 HTTP 矩阵：8 个目标各开 C 个并发 worker 打 D 秒，按目标类型断言状态码，
   统计 p50/p95 延迟与错误率。

用法：
  python3 matrix.py --replicas 2 --minutes 1
  python3 matrix.py --http-workers 4 --http-seconds 10 --skip-orchestration
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SANDBOX = Path(os.environ.get("NUWA_SANDBOX", "/tmp/nuwa-sandbox"))
WORK = Path(os.environ.get("NUWA_WORK", "/tmp/nuwa-work"))
NUWA = WORK / "bin" / "nuwa"
LAYER_A = SANDBOX / "layer-a"
if not (LAYER_A / "fake-sapper").exists():
    LAYER_A = Path(__file__).resolve().parent

TARGETS = {
    "t1": {"port": 18081, "mode": "static", "expect": 200},
    "t2": {"port": 18082, "mode": "dvwa", "expect": [200, 302]},
    "t3": {"port": 18083, "mode": "slow", "expect": "timeout"},
    "t4": {"port": 18084, "mode": "deny", "expect": 403},
    "t5": {"port": 18085, "mode": "redirect", "expect": 302},
    "t6": {"port": 18086, "mode": "basicauth", "expect": 401},
    "t7": {"port": 18087, "mode": "notfound", "expect": 404},
    "t8": {"port": 18088, "mode": "gzip", "expect": 200},
}


def orchestration_run(tag: str, replica: int, root: Path, minutes: int) -> dict:
    port = TARGETS[tag]["port"]
    lab = root / f"lab-{tag}-{replica}"
    agent = root / f"agent-{tag}-{replica}"
    lab.mkdir(parents=True, exist_ok=True)
    agent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PATH"] = f"{LAYER_A}:{env.get('PATH', '')}"
    env["SAPPER_HOME"] = str(lab)
    env["PI_AGENT_HOME"] = str(agent)
    env["NUWA_ENV"] = "/dev/null"
    env["FAKE_COMPLETE_AFTER"] = "999"
    t0 = time.time()
    p = subprocess.run(
        [str(NUWA), f"http://127.0.0.1:{port}", f"{tag}r{replica}",
         "--no-view", "--minutes", str(minutes), "--parallel", "2"],
        cwd=str(root), env=env, capture_output=True, text=True,
        timeout=minutes * 60 + 120,
    )
    dur = round(time.time() - t0, 2)
    proj = lab / f"{tag}r{replica}"
    calls = 0
    calls_path = proj / ".sapper" / "calls.jsonl"
    if calls_path.exists():
        calls = len(calls_path.read_text().splitlines())
    return {
        "target": tag, "mode": TARGETS[tag]["mode"], "replica": replica,
        "rc": p.returncode, "dur": dur, "calls": calls,
        "lock_left": (proj / ".nuwa.lock").exists(),
    }


def http_once(port: int, timeout: float) -> tuple[int | str, float]:
    url = f"http://127.0.0.1:{port}/"
    t0 = time.time()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            r.read(64)
            return r.status, (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        return e.code, (time.time() - t0) * 1000
    except Exception:
        return "timeout", (time.time() - t0) * 1000


def http_worker(port: int, seconds: float, timeout: float, out: list, lock: threading.Lock):
    end = time.time() + seconds
    while time.time() < end:
        code, ms = http_once(port, timeout)
        with lock:
            out.append((code, ms))


def http_matrix(seconds: float, workers: int, timeout: float) -> dict:
    results = {}
    for tag, spec in TARGETS.items():
        out: list[tuple[int | str, float]] = []
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(http_worker, spec["port"], seconds, timeout, out, lock)
                    for _ in range(workers)]
            for f in futs:
                f.result()
        codes = [c for c, _ in out]
        lat = [m for _, m in out]
        if isinstance(spec["expect"], list):
            ok_codes = sum(1 for c in codes if c in spec["expect"])
        elif spec["expect"] == "timeout":
            ok_codes = codes.count("timeout")
        else:
            ok_codes = codes.count(spec["expect"])
        results[tag] = {
            "mode": spec["mode"],
            "requests": len(codes),
            "expected": spec["expect"],
            "matched": ok_codes,
            "match_rate": round(ok_codes / len(codes), 3) if codes else 0,
            "p50_ms": round(statistics.median(lat), 1) if lat else 0,
            "p95_ms": round(sorted(lat)[int(len(lat) * 0.95) - 1], 1) if lat else 0,
            "codes": {str(k): v for k, v in sorted(
                {c: codes.count(c) for c in set(codes)}.items(), key=lambda x: -x[1])},
        }
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--replicas", type=int, default=2)
    ap.add_argument("--minutes", type=int, default=1)
    ap.add_argument("--http-workers", type=int, default=4)
    ap.add_argument("--http-seconds", type=float, default=10)
    ap.add_argument("--http-timeout", type=float, default=2)
    ap.add_argument("--skip-orchestration", action="store_true")
    ap.add_argument("--skip-http", action="store_true")
    ap.add_argument("--out", default=str(SANDBOX / "reports" / "matrix"))
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report = {"targets": list(TARGETS)}

    if not args.skip_orchestration:
        root = Path(tempfile.mkdtemp(prefix="nuwa-matrix-"))
        jobs = [(t, r) for t in TARGETS for r in range(args.replicas)]
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futs = [ex.submit(orchestration_run, t, r, root, args.minutes) for t, r in jobs]
            rows = [f.result() for f in futs]
        report["orchestration"] = {
            "wall_sec": round(time.time() - t0, 2),
            "instances": len(rows),
            "ok": sum(1 for r in rows if r["rc"] == 0),
            "failed": sum(1 for r in rows if r["rc"] != 0),
            "lock_left": sum(1 for r in rows if r["lock_left"]),
            "by_target": {
                t: {
                    "runs": sum(1 for r in rows if r["target"] == t),
                    "ok": sum(1 for r in rows if r["target"] == t and r["rc"] == 0),
                    "calls": sum(r["calls"] for r in rows if r["target"] == t),
                } for t in TARGETS
            },
        }
        shutil.rmtree(root, ignore_errors=True)

    if not args.skip_http:
        report["http"] = http_matrix(args.http_seconds, args.http_workers, args.http_timeout)

    (out / "matrix.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))

    print(json.dumps({k: v for k, v in report.items() if k != "http"}, ensure_ascii=False, indent=2))
    if "http" in report:
        print("\nHTTP 矩阵:")
        for tag, r in report["http"].items():
            print(f"  {tag} {r['mode']:<10} req={r['requests']:<4} "
                  f"match={r['match_rate']:.0%} p50={r['p50_ms']}ms p95={r['p95_ms']}ms")

    ok = True
    if "orchestration" in report:
        ok = ok and report["orchestration"]["failed"] == 0 and report["orchestration"]["lock_left"] == 0
    if "http" in report:
        ok = ok and all(r["match_rate"] >= 0.99 for r in report["http"].values())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
