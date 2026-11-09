#!/usr/bin/env python3
"""R1 dispatch 端到端：fake-sapper + fake-claude。"""
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

from nuwa import dispatch, txn  # noqa: E402
from nuwa.ledger import Ledger  # noqa: E402


class DispatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-dispatch-"))
        self.root = self.tmp / "lab" / "p1"
        self.root.mkdir(parents=True)
        self.env = dict(os.environ)
        self.env["PATH"] = f"{HERE}:{self.env.get('PATH', '')}"
        self.env["SAPPER_HOME"] = str(self.tmp / "lab")
        self.env["PI_AGENT_HOME"] = str(self.tmp / "agent")
        self.env["NUWA_ENGINE"] = "fake-claude"
        self._old = dict(os.environ)
        os.environ.update(self.env)
        self._run(["sapper", "setup", "--goal", "dispatch"])
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

    def facts(self):
        return list((self.root / ".sapper" / "facts").glob("*.json"))

    def test_dispatch_commits_and_reuses(self):
        before = len(self.facts())
        r1 = dispatch.dispatch(self.root, "i001", engine="fake-claude")
        self.assertEqual(len(self.facts()), before + 1)
        self.assertFalse(r1["reused"])
        intent = json.loads((self.root / ".sapper" / "intents" / "i001.json").read_text())
        self.assertEqual(intent["status"], "done")
        self.assertEqual(intent["to"], r1["fact"])

        r2 = dispatch.dispatch(self.root, "i001", engine="fake-claude")
        self.assertTrue(r2["reused"])
        self.assertEqual(len(self.facts()), before + 1)

        led = Ledger()
        s = led.summary()
        self.assertEqual(s["settled_total"], 4000)  # 复用不再计费
        self.assertEqual(s["reserved"], 0)

        journal = (self.root / ".nuwa" / "journal.jsonl").read_text()
        self.assertIn("commit_done", journal)
        self.assertIn("ledger_settle", journal)

    def test_reuse_marker_fact_binds_source(self):
        intent_obj = json.loads(
            (self.root / ".sapper" / "intents" / "i001.json").read_text())
        key = txn.dispatch_key(self.root.name, "i001", txn.attempt_of(intent_obj))
        self._run(["sapper", "fact", f"done [nuwa:{key}]", "-k", "host"])
        r = dispatch.dispatch(self.root, "i001", engine="fake-claude")
        self.assertTrue(r["reused"])
        fact = json.loads(
            (self.root / ".sapper" / "facts" / f"{r['fact']}.json").read_text())
        self.assertEqual(fact.get("source_intent"), "i001")
        intent = json.loads((self.root / ".sapper" / "intents" / "i001.json").read_text())
        self.assertEqual(intent["status"], "done")
        self.assertEqual(intent["to"], r["fact"])

    def test_budget_blocks(self):
        Ledger().set_cap(1000)
        with self.assertRaises(dispatch.DispatchError):
            dispatch.dispatch(self.root, "i001", engine="fake-claude")


if __name__ == "__main__":
    unittest.main(verbosity=2)
