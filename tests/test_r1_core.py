#!/usr/bin/env python3
"""R1 核心单测：journal / ledger / txn。"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from nuwa.journal import Journal, replay_state  # noqa: E402
from nuwa.ledger import Ledger  # noqa: E402
from nuwa import txn  # noqa: E402


def env_for(tmp: Path) -> dict:
    env = dict(os.environ)
    env["PATH"] = f"{HERE}:{env.get('PATH', '')}"
    env["SAPPER_HOME"] = str(tmp / "lab")
    env["PI_AGENT_HOME"] = str(tmp / "agent")
    return env


class JournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-journal-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_append_and_seq(self):
        j = Journal(self.tmp)
        j.append("a")
        j.append("b")
        recs = j.read()
        self.assertEqual([r["seq"] for r in recs], [1, 2])

    def test_concurrent_append_unique(self):
        j = Journal(self.tmp)

        def work():
            for _ in range(10):
                j.append("x")

        threads = [threading.Thread(target=work) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        seqs = [r["seq"] for r in j.read()]
        self.assertEqual(len(seqs), 50)
        self.assertEqual(len(set(seqs)), 50)
        self.assertEqual(sorted(seqs), list(range(1, 51)))

    def test_replay_state(self):
        j = Journal(self.tmp)
        j.append("executing_prepare", txn="t1", intent="i001")
        j.append("executing", txn="t1", intent="i001")
        j.append("executed", txn="t1", status="ok")
        j.append("commit_done", txn="t1", intent="i001", fact="f002")
        st = replay_state(self.tmp)
        self.assertEqual(st["inflight"], {})
        self.assertIn("t1", st["committed"])


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-ledger-"))
        self.led = Ledger(self.tmp)
        self.led.set_cap(1000)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_reserve_settle(self):
        self.led.reserve("r1", "p1", 100)
        s = self.led.summary()
        self.assertEqual(s["reserved"], 100)
        self.assertEqual(s["remaining_global"], 1000 - 105)
        self.led.settle("r1", 90)
        s = self.led.summary()
        self.assertEqual(s["settled_total"], 90)
        self.assertEqual(s["reserved"], 0)
        self.assertEqual(s["remaining_global"], 910)

    def test_reclaim(self):
        self.led.reserve("r1", "p1", 100)
        self.led.reclaim("r1")
        self.assertEqual(self.led.summary()["reserved"], 0)

    def test_admit(self):
        ok, _ = self.led.admit(900)
        self.assertTrue(ok)
        ok, _ = self.led.admit(1000)
        self.assertFalse(ok)

    def test_concurrent_reserve(self):
        def work(i):
            self.led.reserve(f"r{i}", "p1", 10)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(self.led.summary()["outstanding"]), 20)


class TxnTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-txn-"))
        self.root = self.tmp / "lab" / "p1"
        self.root.mkdir(parents=True)
        self.env = env_for(self.tmp)
        self._old = dict(os.environ)
        os.environ.update(self.env)
        self._run(["sapper", "setup", "--goal", "r1"])
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

    def test_commit_idempotent(self):
        key = txn.dispatch_key("p1", "i001", 0)
        before = len(self.facts())
        r1 = txn.commit(self.root, "i001", "probe result", key)
        after1 = len(self.facts())
        self.assertEqual(after1, before + 1)
        r2 = txn.commit(self.root, "i001", "probe result", key)
        after2 = len(self.facts())
        self.assertEqual(after2, after1)
        self.assertTrue(r2["reused"])
        self.assertEqual(r1["fact"], r2["fact"])
        intent = json.loads((self.root / ".sapper" / "intents" / "i001.json").read_text())
        self.assertEqual(intent["status"], "done")
        self.assertEqual(intent["to"], r1["fact"])
        fact = json.loads((self.root / ".sapper" / "facts" / f"{r1['fact']}.json").read_text())
        self.assertIn(f"[nuwa:{key}]", fact["description"])

    def test_adopt_once(self):
        a = txn.adopt(self.root)
        b = txn.adopt(self.root)
        self.assertTrue(a["adopted"])
        self.assertFalse(b["adopted"])

    def test_repair_releases_claimed(self):
        subprocess.run(["sapper", "claim", "i001", "--worker", "test"],
                       cwd=self.root, env=self.env, check=True, capture_output=True)
        j = Journal(self.root)
        j.append("reserve_pending", txn="t9", rid="r9", intent="i001",
                 attempt_seq=0, tokens=4000)
        j.append("reserve_committed", txn="t9", rid="r9", intent="i001")
        j.append("executing_prepare", txn="t9", rid="r9", intent="i001")
        from nuwa.ledger import Ledger
        Ledger().reserve("r9", "p1", 4000)
        res = txn.repair(self.root)
        self.assertEqual(res["count"], 1)
        intent = json.loads((self.root / ".sapper" / "intents" / "i001.json").read_text())
        self.assertEqual(intent["status"], "open")
        s = Ledger().summary()
        self.assertEqual(s["reserved"], 0)
        self.assertEqual(s["settled_total"], 4000)

    def test_recover_lists_pending(self):
        j = Journal(self.root)
        j.append("executing_prepare", txn="t1", intent="i001")
        res = txn.recover(self.root)
        self.assertEqual(len(res["pending"]), 1)
        self.assertEqual(res["pending"][0]["txn"], "t1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
