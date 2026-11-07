#!/usr/bin/env python3
"""
混沌测试：故意把环境和状态弄坏，看 bin/nuwa 是优雅失败还是挂死。

每个用例都要求：
  - 在超时内退出（不挂）
  - 退出码符合约定（0/2/3/4/5）
  - 不留下无法恢复的残留
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import unittest
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


class Chaos(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nuwa-chaos-"))
        (self.tmp / "lab").mkdir()
        (self.tmp / "agent").mkdir()
        self.env = env_for(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_nuwa(self, *args, timeout=45, env=None):
        return subprocess.run(
            [str(NUWA), *args], cwd=str(self.tmp), env=env or self.env,
            capture_output=True, text=True, timeout=timeout,
        )

    def make_project(self, name="p1") -> Path:
        d = self.tmp / "lab" / name
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run(["sapper", "setup", "--goal", "chaos"], cwd=d, env=self.env,
                       capture_output=True)
        subprocess.run(["sapper", "fact", "target alive", "-k", "host"], cwd=d,
                       env=self.env, capture_output=True)
        return d

    # ---------------------------------------------------------------- 1
    def test_corrupted_project_json(self):
        d = self.make_project()
        (d / ".sapper" / "project.json").write_text("{ this is not json")
        r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--no-run")
        self.assertNotEqual(r.returncode, 0, "损坏的图应导致非零退出")
        self.assertLess(r.returncode, 10, "应是约定退出码，不是崩溃")
        self.assertNotIn("Traceback", r.stderr, "不应把 Python traceback 抛给用户")

    # ---------------------------------------------------------------- 2
    def test_stale_lock_is_recoverable(self):
        d = self.make_project()
        lock = d / ".nuwa.lock"
        lock.write_text("99999999\n")  # 不存在的 pid
        r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--no-run",
                          env={**self.env, "FAKE_EMPTY_FRONTIER": "1"})
        self.assertEqual(r.returncode, 0, f"陈旧锁应被忽略:\n{r.stdout}\n{r.stderr}")
        self.assertFalse(lock.exists(), "正常退出后应清理自己的锁")

    # ---------------------------------------------------------------- 3
    def test_live_lock_blocks(self):
        d = self.make_project()
        lock = d / ".nuwa.lock"
        lock.write_text("1\n")
        # 真正持有 flock 才是活锁；只写 pid 不构成互斥
        holder = subprocess.Popen(["flock", "-x", str(lock), "sleep", "30"])
        try:
            time.sleep(0.5)
            r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--no-run")
            self.assertEqual(r.returncode, 5, f"活锁应返回 5:\n{r.stdout}\n{r.stderr}")
        finally:
            holder.terminate()
            holder.wait(timeout=5)

    # ---------------------------------------------------------------- 4
    def test_non_sapper_dir_refused(self):
        d = self.tmp / "lab" / "dirty"
        d.mkdir(parents=True)
        (d / "important.txt").write_text("do not overwrite")
        r = self.run_nuwa("http://127.0.0.1:19999", "dirty", "--no-view", "--no-run")
        self.assertEqual(r.returncode, 4, f"非 sapper 非空目录应拒绝:\n{r.stdout}\n{r.stderr}")
        self.assertEqual((d / "important.txt").read_text(), "do not overwrite")

    # ---------------------------------------------------------------- 5
    def test_sigkill_then_recover(self):
        d = self.make_project()
        env = {**self.env, "FAKE_SLOW": "2", "FAKE_COMPLETE_AFTER": "999"}
        p = subprocess.Popen(
            [str(NUWA), "http://127.0.0.1:19999", "p1", "--no-view",
             "--minutes", "5", "--parallel", "1"],
            cwd=str(self.tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)
        p.kill()
        p.wait(timeout=10)
        # 锁里是死 pid，下一次必须能接管
        r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--minutes", "1",
                          env={**self.env, "FAKE_EMPTY_FRONTIER": "1"})
        self.assertEqual(r.returncode, 0, f"SIGKILL 后应可恢复:\n{r.stdout}\n{r.stderr}")

    # ---------------------------------------------------------------- 6
    def test_large_graph_perf(self):
        d = self.make_project()
        intents = d / ".sapper" / "intents"
        for i in range(1, 1001):
            (intents / f"i{i:03d}.json").write_text(json.dumps({
                "id": f"i{i:03d}", "from": ["f001"], "description": f"bulk {i}",
                "status": "open", "worker": None, "requires_confirmation": False,
                "confirmed_at": None, "doc": "", "creator": "test",
            }))
        t0 = time.time()
        r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--no-run",
                          env={**self.env, "FAKE_EMPTY_FRONTIER": "1"}, timeout=60)
        dt = time.time() - t0
        self.assertEqual(r.returncode, 0)
        self.assertLess(dt, 30, f"1000 条 intent 的建图耗时 {dt:.1f}s，超过 30s")

    # ---------------------------------------------------------------- 7
    def test_readonly_project(self):
        d = self.make_project()
        os.chmod(d, stat.S_IRUSR | stat.S_IXUSR)
        try:
            r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--no-run")
            self.assertLess(r.returncode, 10, "只读目录应优雅失败")
            self.assertNotIn("Traceback", r.stderr)
        finally:
            os.chmod(d, stat.S_IRWXU)

    # ---------------------------------------------------------------- 8
    def test_missing_python(self):
        clean = self.tmp / "cleanbin"
        clean.mkdir()
        for c in ("bash", "curl", "mkdir", "date", "cat", "awk", "sed", "grep",
                  "cut", "tr", "head", "tail", "sleep", "dirname", "basename",
                  "nohup", "install", "ln", "rm", "cp", "chmod", "env", "sh", "ls"):
            p = shutil.which(c)
            if p:
                (clean / c).symlink_to(p)
        (clean / "sapper").symlink_to(LAYER_A / "sapper")
        env = {**self.env, "PATH": str(clean)}
        r = self.run_nuwa("http://127.0.0.1:19999", "p1", "--no-view", "--no-run",
                          env=env, timeout=30)
        self.assertEqual(r.returncode, 3, f"缺 python3 应退出 3:\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
