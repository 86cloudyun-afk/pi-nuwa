#!/usr/bin/env python3
"""R1 崩溃注入：四个提交点，每点一个独立项目。

每个点：用 NUWA_CRASH_POINT 让 dispatch 在指定位置退出 137，
然后 repair + 重新 dispatch，断言只产生一个带 key 的 fact。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from nuwa import graph, txn  # noqa: E402
from nuwa.ledger import Ledger  # noqa: E402

POINTS = ["before_reserve", "after_reserve", "after_prepare", "after_execute"]


class CrashInject(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-crash-"))
        self.env = dict(os.environ)
        self.env["PATH"] = f"{HERE}:{self.env.get('PATH', '')}"
        self.env["SAPPER_HOME"] = str(self.tmp / "lab")
        self.env["PI_AGENT_HOME"] = str(self.tmp / "agent")
        self.env["NUWA_ENGINE"] = "fake-claude"
        self._old = dict(os.environ)
        os.environ.update(self.env)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _project(self, name: str) -> Path:
        root = self.tmp / "lab" / name
        root.mkdir(parents=True)
        for cmd in (["sapper", "setup", "--goal", name],
                    ["sapper", "fact", "alive", "-k", "host"],
                    ["sapper", "intent", "--from", "f001", "probe"]):
            subprocess.run(cmd, cwd=root, env=self.env, check=True, capture_output=True)
        return root

    def test_points(self):
        for idx, point in enumerate(POINTS):
            with self.subTest(point=point):
                root = self._project(f"c{idx}")
                env = dict(self.env, NUWA_CRASH_POINT=point)
                proc = subprocess.run(
                    [sys.executable, "-m", "nuwa.cli", "dispatch", "i001",
                     "--model", "fake", "--root", str(root)],
                    env={**env, "PYTHONPATH": str(REPO)},
                    capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(proc.returncode, 137, proc.stderr)

                txn.repair(root)
                # 清理可能残留的预占
                Ledger().reclaim("r-missing", reason="test")
                subprocess.run(
                    [sys.executable, "-m", "nuwa.cli", "dispatch", "i001",
                     "--model", "fake", "--root", str(root)],
                    env={**self.env, "PYTHONPATH": str(REPO)},
                    check=True, capture_output=True, text=True, timeout=60,
                )
                facts = [f for f in graph.facts(root) if "[nuwa:" in (f.get("description") or "")]
                self.assertEqual(len(facts), 1, f"{point}: {len(facts)} facts")
                intent = graph.get_intent(root, "i001")
                self.assertEqual(intent["status"], "done")
                self.assertEqual(intent["to"], facts[0]["id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
