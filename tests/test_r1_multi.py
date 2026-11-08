#!/usr/bin/env python3
"""R1 多项目并发：4 项目同时跑，注册表一致、锁清理。"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from nuwa import registry, runner  # noqa: E402
from nuwa.locks import is_locked  # noqa: E402


class MultiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-multi-"))
        self.env = dict(os.environ)
        self.env["PATH"] = f"{HERE}:{self.env.get('PATH', '')}"
        self.env["SAPPER_HOME"] = str(self.tmp / "lab")
        self.env["PI_AGENT_HOME"] = str(self.tmp / "agent")
        self.env["NUWA_ENGINE"] = "fake-claude"
        self.env["NUWA_MAX_ROUNDS"] = "2"
        self._old = dict(os.environ)
        os.environ.update(self.env)
        self.roots = []
        for i in range(4):
            root = self.tmp / "lab" / f"p{i}"
            root.mkdir(parents=True)
            self._run(root, ["sapper", "setup", "--goal", f"multi {i}"])
            self._run(root, ["sapper", "fact", "alive", "-k", "host"])
            self._run(root, ["sapper", "intent", "--from", "f001", "probe"])
            self.roots.append(root)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, root, cmd):
        r = subprocess.run(cmd, cwd=str(root), env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_four_projects_concurrent(self):
        with ThreadPoolExecutor(max_workers=4) as ex:
            codes = list(ex.map(lambda r: runner.run(r, minutes=1, parallel=2, model="fake"),
                                self.roots))
        self.assertEqual(codes, [0, 0, 0, 0])

        items = registry.rebuild()
        names = {i["name"] for i in items}
        self.assertTrue({"p0", "p1", "p2", "p3"} <= names)
        for root in self.roots:
            self.assertFalse(is_locked(root / ".nuwa" / "run.lock"))
            run = json.loads((root / ".nuwa" / "run.json").read_text())
            self.assertEqual(run["status"], "stopped")
            self.assertGreaterEqual(run["round"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
