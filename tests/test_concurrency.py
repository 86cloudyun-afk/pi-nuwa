#!/usr/bin/env python3
"""
并发测试：验证项目锁、并行 dispatch、跨项目隔离。

用例：
  1. 同一项目 5 个实例同时起 → 恰好 1 个跑，其余退出码 5
  2. 5 个不同项目同时起 → 全部成功
  3. 正常退出后锁被清理
  4. SIGTERM 后锁被清理
  5. 单实例并行 dispatch 不重复派发同一 intent
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _paths import LAYER_A, WORK, NUWA  # noqa: E402


def env_for(tmp: Path, extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env["PATH"] = f"{LAYER_A}:{env.get('PATH', '')}"
    env["SAPPER_HOME"] = str(tmp / "lab")
    env["PI_AGENT_HOME"] = str(tmp / "agent")
    env["NUWA_ENV"] = "/dev/null"
    if extra:
        env.update(extra)
    return env


def bootstrap(tmp: Path, name: str, env: dict) -> Path:
    d = tmp / "lab" / name
    d.mkdir(parents=True, exist_ok=True)
    subprocess.run(["sapper", "setup", "--goal", f"conc {name}"], cwd=d, env=env,
                   capture_output=True)
    subprocess.run(["sapper", "fact", "target alive", "-k", "host"], cwd=d,
                   env=env, capture_output=True)
    return d


class Concurrency(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nuwa-conc-"))
        (self.tmp / "lab").mkdir()
        (self.tmp / "agent").mkdir()
        self.base_env = env_for(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def spawn(self, name: str, env: dict, minutes: str = "1"):
        return subprocess.Popen(
            [str(NUWA), "http://127.0.0.1:19999", name, "--no-view",
             "--minutes", minutes, "--parallel", "2"],
            cwd=str(self.tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    # ---------------------------------------------------------------- 1
    def test_same_project_single_winner(self):
        bootstrap(self.tmp, "shared", self.base_env)
        env = {**self.base_env, "FAKE_SLOW": "2", "FAKE_COMPLETE_AFTER": "999"}
        procs = [self.spawn("shared", env) for _ in range(5)]
        out = [p.communicate(timeout=120) for p in procs]
        codes = [p.returncode for p in procs]
        winners = [c for c in codes if c == 0]
        losers = [c for c in codes if c == 5]
        self.assertEqual(len(winners), 1, f"应恰好 1 个赢家，实际 {codes}")
        self.assertEqual(len(losers), 4, f"其余应退出 5，实际 {codes}")

    # ---------------------------------------------------------------- 2
    def test_distinct_projects_all_run(self):
        env = {**self.base_env, "FAKE_COMPLETE_AFTER": "3"}
        for i in range(5):
            bootstrap(self.tmp, f"p{i}", self.base_env)
        procs = [self.spawn(f"p{i}", env) for i in range(5)]
        for p in procs:
            p.communicate(timeout=120)
        codes = [p.returncode for p in procs]
        self.assertEqual(codes, [0] * 5, f"不同项目应全部成功，实际 {codes}")

    # ---------------------------------------------------------------- 3
    def test_lock_removed_after_exit(self):
        d = bootstrap(self.tmp, "p1", self.base_env)
        p = self.spawn("p1", {**self.base_env, "FAKE_COMPLETE_AFTER": "2"})
        p.communicate(timeout=90)
        self.assertEqual(p.returncode, 0)
        lock = d / ".nuwa.lock"
        self.assertTrue(not lock.exists() or not lock.read_text().strip(),
                        "正常退出后锁应被清空")

    # ---------------------------------------------------------------- 4
    def test_lock_removed_after_sigterm(self):
        d = bootstrap(self.tmp, "p1", self.base_env)
        env = {**self.base_env, "FAKE_SLOW": "5", "FAKE_COMPLETE_AFTER": "999"}
        p = self.spawn("p1", env)
        time.sleep(3)
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=30)
        time.sleep(1)
        lock = d / ".nuwa.lock"
        if lock.exists():
            raw = lock.read_text().strip()
            pid = int(raw) if raw.isdigit() else 0
            alive = pid > 0
            if alive:
                try:
                    os.kill(pid, 0)
                except OSError:
                    alive = False
            self.assertFalse(alive, "SIGTERM 后锁里不应是活进程")
        # 下一次必须能接管
        r = subprocess.run(
            [str(NUWA), "http://127.0.0.1:19999", "p1", "--no-view", "--no-run"],
            cwd=str(self.tmp), env={**self.base_env, "FAKE_EMPTY_FRONTIER": "1"},
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(r.returncode, 0, f"{r.stdout}\n{r.stderr}")

    # ---------------------------------------------------------------- 5
    def test_no_duplicate_dispatch(self):
        d = bootstrap(self.tmp, "p1", self.base_env)
        subprocess.run(["sapper", "dispatch", "reason"], cwd=d, env=self.base_env,
                       capture_output=True)
        p = subprocess.run(
            [str(NUWA), "http://127.0.0.1:19999", "p1", "--no-view",
             "--minutes", "1", "--parallel", "4"],
            cwd=str(self.tmp), env={**self.base_env, "FAKE_COMPLETE_AFTER": "999"},
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(p.returncode, 0)
        calls = []
        cp = d / ".sapper" / "calls.jsonl"
        for line in cp.read_text().splitlines():
            try:
                calls.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        disp = [c["argv"][1] for c in calls
                if c.get("argv") and c["argv"][0] == "dispatch"
                and len(c["argv"]) > 1 and c["argv"][1].startswith("i")]
        dup = {x for x in disp if disp.count(x) > 1}
        self.assertEqual(dup, set(), f"同一 intent 被重复派发: {dup}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
