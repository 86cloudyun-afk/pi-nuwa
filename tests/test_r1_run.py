#!/usr/bin/env python3
"""R1 run 端到端：fake-sapper + fake-claude，2 轮。"""
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

from nuwa import registry, runner  # noqa: E402
from nuwa.locks import is_locked  # noqa: E402


class RunTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-run-"))
        self.root = self.tmp / "lab" / "p1"
        self.root.mkdir(parents=True)
        self.env = dict(os.environ)
        self.env["PATH"] = f"{HERE}:{self.env.get('PATH', '')}"
        self.env["SAPPER_HOME"] = str(self.tmp / "lab")
        self.env["PI_AGENT_HOME"] = str(self.tmp / "agent")
        self.env["NUWA_ENGINE"] = "fake-claude"
        self.env["NUWA_MAX_ROUNDS"] = "2"
        self._old = dict(os.environ)
        os.environ.update(self.env)
        self._run(["sapper", "setup", "--goal", "run"])
        self._run(["sapper", "fact", "target alive", "-k", "host"])
        self._run(["sapper", "intent", "--from", "f001", "probe"])

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, cmd):
        r = subprocess.run(cmd, cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def test_reason_engine_missing_does_not_crash(self):
        self._run(["sapper", "done", "i001", "--fact", "seed"])
        old = os.environ.get("NUWA_ENGINE")
        os.environ["NUWA_ENGINE"] = "/nonexistent/nuwa-engine"
        try:
            code = runner.run(self.root, minutes=1, parallel=1, model="fake")
            self.assertIn(code, (0, 5))
        finally:
            if old is None:
                os.environ.pop("NUWA_ENGINE", None)
            else:
                os.environ["NUWA_ENGINE"] = old

    def test_revert_removes_goal_edge(self):
        from nuwa import graph
        self._run(["sapper", "complete", "--from", "f001", "--note", "done"])
        self.assertEqual(graph.project(self.root).get("status"), "completed")
        self.assertTrue(any(i.get("to") == "goal" for i in graph.intents(self.root)))
        runner._revert(self.root, "test")
        self.assertEqual(graph.project(self.root).get("status"), "active")
        self.assertFalse(any(i.get("to") == "goal" for i in graph.intents(self.root)))
        v = subprocess.run(["sapper", "validate"], cwd=self.root, env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_revert_keeps_valid_completion(self):
        from nuwa import graph
        self._run(["sapper", "flag", "flag{ok}"])
        flags = [f for f in graph.facts(self.root) if f.get("kind") == "flag"]
        self.assertTrue(flags)
        self._run(["sapper", "complete", "--from", flags[0]["id"], "--note", "done"])
        self.assertEqual(runner._revert(self.root, "x"), "noop")
        self.assertEqual(graph.project(self.root).get("status"), "completed")
        self.assertTrue(any(i.get("to") == "goal" for i in graph.intents(self.root)))

    def test_run_two_rounds(self):
        before = len(list((self.root / ".sapper" / "facts").glob("*.json")))
        code = runner.run(self.root, minutes=1, parallel=2, model="fake")
        self.assertEqual(code, 0)
        after = len(list((self.root / ".sapper" / "facts").glob("*.json")))
        self.assertGreater(after, before)
        run = json.loads((self.root / ".nuwa" / "run.json").read_text())
        self.assertEqual(run["run_schema"], 1)
        self.assertGreaterEqual(run["round"], 2)
        self.assertFalse(is_locked(self.root / ".nuwa" / "run.lock"))
        journal = (self.root / ".nuwa" / "journal.jsonl").read_text()
        self.assertIn("run_start", journal)
        self.assertIn("run_stop", journal)
        self.assertIn("reason_applied", journal)

        # resume：计数从 run.json 继续
        (self.root / ".nuwa" / "run.json").write_text(json.dumps(
            {"run_schema": 1, "round": 3, "turns": 7}))
        os.environ["NUWA_MAX_ROUNDS"] = "4"
        code2 = runner.run(self.root, minutes=1, parallel=2, model="fake", resume=True)
        self.assertEqual(code2, 0)
        run2 = json.loads((self.root / ".nuwa" / "run.json").read_text())
        self.assertGreaterEqual(run2["round"], 4)
        self.assertGreaterEqual(run2["turns"], 7)

        items = registry.rebuild()
        self.assertTrue(any(i["name"] == "p1" for i in items))


if __name__ == "__main__":
    unittest.main(verbosity=2)
