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

    def test_compact_keeps_seq_across_generations(self):
        """compact 后新文件必须接着归档代的 seq，不能从 1 重数。"""
        j = Journal(self.tmp)
        j.append("a")
        j.append("b")
        j.compact()
        j.append("c")
        self.assertEqual([r["seq"] for r in j.read()], [1, 2, 3])
        ck = json.loads((j.dir / "checkpoint.1.json").read_text())
        self.assertEqual(ck["seq"], 2)

    def test_gc_removes_only_old_generations(self):
        """keep=2 时保留当前代与上一代，更早的代际文件被删除。"""
        j = Journal(self.tmp)
        for _ in range(5):
            j.append("x")
            j.compact(keep=0)
        self.assertEqual(j.current_gen(), 5)
        for gen in (1, 2, 3, 4, 5):
            self.assertTrue((j.dir / f"journal.{gen}.jsonl").exists())
        removed = j.gc(keep=2)
        names = {p.name for p in removed}
        self.assertEqual(names, {"journal.1.jsonl", "checkpoint.1.json",
                                 "journal.2.jsonl", "checkpoint.2.json",
                                 "journal.3.jsonl", "checkpoint.3.json"})
        self.assertTrue((j.dir / "journal.4.jsonl").exists())
        self.assertTrue((j.dir / "journal.5.jsonl").exists())
        self.assertTrue((j.dir / "checkpoint.5.json").exists())

    def test_compact_auto_gc_uses_env(self):
        j = Journal(self.tmp)
        os.environ["NUWA_JOURNAL_KEEP"] = "1"
        try:
            for _ in range(3):
                j.append("x")
                j.compact()
        finally:
            del os.environ["NUWA_JOURNAL_KEEP"]
        self.assertFalse((j.dir / "journal.1.jsonl").exists())
        self.assertFalse((j.dir / "journal.2.jsonl").exists())
        self.assertTrue((j.dir / "journal.3.jsonl").exists())

    def test_empty_compaction_keeps_seq_high_water(self):
        """空代被 GC 后，seq 必须从 checkpoint 高水位继续，不能回到 0。"""
        j = Journal(self.tmp)
        j.append("a")
        j.compact()
        j.compact()
        j.compact()
        self.assertFalse((j.dir / "journal.1.jsonl").exists())
        j.append("b")
        self.assertEqual(j.last_seq(), 2)
        self.assertEqual([r["seq"] for r in j.read()], [2])

    def test_compact_never_overwrites_existing_gen(self):
        """CURRENT 未发布（模拟崩溃）时，下一次 compact 不能覆盖已有归档。"""
        j = Journal(self.tmp)
        j.append("a")
        j.compact(keep=0)
        (j.dir / "CURRENT").unlink()
        j.append("b")
        j.compact(keep=0)
        self.assertTrue((j.dir / "journal.1.jsonl").exists())
        self.assertTrue((j.dir / "journal.2.jsonl").exists())
        self.assertEqual([r["seq"] for r in j.read()], [1, 2])

    def test_gc_keeps_generation_with_pending_txn(self):
        j = Journal(self.tmp)
        j.append("executing_prepare", txn="t1", intent="i001")
        j.compact(keep=1)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        self.assertTrue((j.dir / "journal.1.jsonl").exists(), "未决事务所在代必须保留")

    def test_gc_writes_recovery_snapshot(self):
        j = Journal(self.tmp)
        j.append("commit_done", txn="t1", intent="i001")
        j.compact(keep=0)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        self.assertFalse((j.dir / "journal.1.jsonl").exists())
        rec = j.read_recovery()
        self.assertIsNotNone(rec)
        self.assertIn("t1", rec["committed"])
        self.assertIn("t1", replay_state(self.tmp)["committed"])

    def test_tail_seq_handles_long_record(self):
        j = Journal(self.tmp)
        j.append("x", blob="a" * 20000)
        self.assertEqual(j.last_seq(), 1)
        j.compact(keep=0)
        j.append("y")
        self.assertEqual(j.last_seq(), 2)

    def test_files_sorted_by_generation_number(self):
        """gen10 不能排在 gen9 前，否则未决判定会读到旧状态。"""
        j = Journal(self.tmp)
        (j.dir / "journal.9.jsonl").write_text(
            json.dumps({"seq": 1, "event": "executing_prepare", "txn": "t1", "intent": "i001"}) + "\n")
        (j.dir / "journal.10.jsonl").write_text(
            json.dumps({"seq": 2, "event": "executed", "txn": "t1"}) + "\n")
        (j.dir / "checkpoint.10.json").write_text(json.dumps({"seq": 2}))
        (j.dir / "CURRENT").write_text("10")
        j.gc(keep=1)
        self.assertFalse((j.dir / "journal.9.jsonl").exists(), "t1 已终态，gen9 不应被保护")

    def test_bad_utf8_record_is_skipped_consistently(self):
        j = Journal(self.tmp)
        j.append("a")
        with open(j.path, "ab") as fh:
            fh.write(b'{"seq":2,"event":"x","blob":"\xff\xfe"}\n')
        self.assertEqual(j.last_seq(), 1)
        j.append("b")
        self.assertEqual(j.last_seq(), 2)
        recs = j.read()
        self.assertEqual([r["seq"] for r in recs], [1, 2])
        self.assertEqual(recs[-1]["event"], "b")

    def test_tail_seq_handles_cr_in_json(self):
        """JSON 属性间的 CR 不能被当换行，否则尾读会退回旧 seq。"""
        j = Journal(self.tmp)
        with open(j.path, "wb") as fh:
            fh.write(b'{"seq":8,"event":"a"}\n{"seq":9,\r"event":"b"}\n')
        self.assertEqual(j.last_seq(), 9)
        self.assertEqual(len(j.read()), 2)

    def test_tail_seq_skips_window_fragment(self):
        """窗口起点落在坏行中间时，残片不能当作合法 seq。"""
        j = Journal(self.tmp)
        for i in range(1, 9):
            j.append("x", i=i)
        with open(j.path, "ab") as fh:
            fh.write(b"BAD" + b" " * 9000 + b'{"seq":1}\n')
        self.assertEqual(j.last_seq(), 8)
        j.append("y")
        self.assertEqual(j.last_seq(), 9)

    def test_zero_seq_records_not_deduped(self):
        j = Journal(self.tmp)
        with open(j.path, "wb") as fh:
            fh.write(b'{"seq":0,"event":"executing_prepare","txn":"t1"}\n')
            fh.write(b'{"seq":0,"event":"ack","txn":"t1"}\n')
        st = replay_state(self.tmp)
        self.assertNotIn("t1", st["inflight"])

    def test_snapshot_ignores_bad_seq(self):
        j = Journal(self.tmp)
        j.append("a")
        with open(j.path, "ab") as fh:
            fh.write(b'{"seq":"bad","event":"x"}\n')
        st = replay_state(self.tmp)
        self.assertEqual(st["last_seq"], 1)
        rec = txn.recover(self.tmp)
        self.assertEqual(rec["last_seq"], 1)

    def test_rejected_reserve_without_ack_has_tombstone(self):
        j = Journal(self.tmp)
        j.append("executing_prepare", txn="t1", intent="i001")
        j.append("reserve_rejected", txn="t1", intent="i001")
        j.compact(keep=0)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        rec = j.read_recovery()
        self.assertNotIn("t1", rec.get("inflight", {}))
        self.assertIn("t1", rec.get("ended", []))

    def test_rejected_reserve_not_in_recovery(self):
        j = Journal(self.tmp)
        j.append("executing_prepare", txn="t1", intent="i001")
        j.append("reserve_rejected", txn="t1", intent="i001")
        j.append("ack", txn="t1", intent="i001", status="rejected")
        j.compact(keep=0)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        rec = j.read_recovery()
        self.assertNotIn("t1", rec.get("inflight", {}))

    def test_recovery_merges_settled_and_committed_across_files(self):
        j = Journal(self.tmp)
        j.append("commit_done", txn="t1")
        j.append("ledger_settle", txn="t1", rid="r1")
        j.compact(keep=0)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        rec = j.read_recovery()
        self.assertIn("t1", rec["committed"])
        self.assertIn("r1", rec["settled"])

    def test_recovery_does_not_revive_committed_inflight(self):
        j = Journal(self.tmp)
        j.append("executing_prepare", txn="t1", intent="i001")
        j.compact(keep=0)
        j.append("executed", txn="t1")
        j.append("commit_done", txn="t1")
        j.compact(keep=1)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        rec = j.read_recovery()
        self.assertIsNotNone(rec)
        self.assertNotIn("t1", rec.get("inflight", {}))
        self.assertNotIn("t1", replay_state(self.tmp)["inflight"])

    def test_gc_keeps_generation_with_ledger_settle(self):
        j = Journal(self.tmp)
        j.append("executed", txn="t1", intent="i001")
        j.append("ledger_settle", txn="t1", rid="r1")
        j.compact(keep=1)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        self.assertTrue((j.dir / "journal.1.jsonl").exists(), "已结算未 ack 的事务仍须保护")

    def test_concurrent_append_and_compact_unique_seq(self):
        j = Journal(self.tmp)
        errors = []
        barrier = threading.Barrier(4)

        def writer():
            try:
                barrier.wait(timeout=10)
                for _ in range(10):
                    j.append("w")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def compactor():
            try:
                barrier.wait(timeout=10)
                for _ in range(3):
                    j.compact(keep=0)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer) for _ in range(3)]
        threads.append(threading.Thread(target=compactor))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        seqs = [r["seq"] for r in j.read()]
        self.assertEqual(len(seqs), 30)
        self.assertEqual(len(set(seqs)), 30)
        self.assertEqual(sorted(seqs), list(range(1, 31)))


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r1-ledger-"))
        self.led = Ledger(self.tmp)
        self.led.set_cap(1000)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_append_after_bad_tail(self):
        self.led.path.write_bytes(b'{"type":"reserve","rid":"r0","tokens":1}')
        self.led.reserve("r1", "p1", 100)
        self.assertEqual(len(self.led.records()), 2)

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

    def test_commit_auto_key_is_idempotent(self):
        cmd = [sys.executable, "-m", "nuwa.cli", "commit", "--root", str(self.root),
               "--intent", "i001", "--key", "auto", "--fact", "auto key", "--kind", "note"]
        env = {**self.env, "PYTHONPATH": str(REPO)}
        r1 = subprocess.run(cmd, env=env, capture_output=True, text=True)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        res1 = json.loads(r1.stdout)
        self.assertEqual(res1["key"], txn.dispatch_key("p1", "i001", 0))
        r2 = subprocess.run(cmd, env=env, capture_output=True, text=True)
        res2 = json.loads(r2.stdout)
        self.assertTrue(res2["reused"])
        self.assertEqual(res1["fact"], res2["fact"])

    def test_attempt_of_strict(self):
        from nuwa.txn import attempt_of, CommitError
        self.assertEqual(attempt_of({}), 0)
        self.assertEqual(attempt_of({"x-nuwa-attempt": 3}), 3)
        self.assertEqual(attempt_of({"x-nuwa-attempt": "2"}), 2)
        for bad in (None, -1, "abc", True, 1.5):
            with self.assertRaises(CommitError):
                attempt_of({"x-nuwa-attempt": bad})

    def test_complete_requires_evidence(self):
        self._run(["sapper", "fact", "just a note", "-k", "note"])
        facts = [f for f in (self.root / ".sapper" / "facts").glob("*.json")
                 if json.loads(f.read_text()).get("kind") == "note"]
        note_id = json.loads(facts[-1].read_text())["id"]
        env = {**self.env, "PYTHONPATH": str(REPO)}

        def complete(fid):
            return subprocess.run(
                [sys.executable, "-m", "nuwa.cli", "complete", "--root", str(self.root),
                 "--from", fid], env=env, capture_output=True, text=True)

        r = complete(note_id)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self._run(["sapper", "flag", "flag{test}"])
        facts = [f for f in (self.root / ".sapper" / "facts").glob("*.json")
                 if json.loads(f.read_text()).get("kind") == "flag"]
        flag_id = json.loads(facts[-1].read_text())["id"]
        r2 = complete(flag_id)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        project = json.loads((self.root / ".sapper" / "project.json").read_text())
        self.assertEqual(project["status"], "completed")

    def test_commit_rejects_other_key_when_done(self):
        k1 = txn.dispatch_key("p1", "i001", 0)
        txn.commit(self.root, "i001", "first", k1)
        k2 = txn.dispatch_key("p1", "i001", 1)
        with self.assertRaises(txn.CommitError):
            txn.commit(self.root, "i001", "second", k2)
        facts = [json.loads(p.read_text()) for p in self.facts()]
        self.assertEqual(len([f for f in facts if "nuwa:" in f["description"]]), 1)

    def test_repair_uses_reserve_tokens(self):
        led = Ledger(self.tmp)
        led.set_cap(100000)
        j = Journal(self.root)
        j.append("reserve_pending", txn="t1", rid="r1", intent="i001", tokens=7777)
        j.append("reserve_committed", txn="t1", rid="r1", intent="i001", tokens=7777)
        led.reserve("r1", "p1", 7777)
        txn.repair(self.root, led)
        self.assertEqual(led.summary()["settled_total"], 7777)

    def test_repair_does_not_settle_rejected_reserve(self):
        led = Ledger(self.tmp)
        led.set_cap(1000)
        j = Journal(self.root)
        j.append("reserve_pending", txn="t1", rid="r1", intent="i001", tokens=4000)
        j.append("reserve_rejected", txn="t1", rid="r1", intent="i001")
        j.append("ack", txn="t1", intent="i001", status="rejected")
        txn.repair(self.root, led)
        self.assertEqual(led.summary()["settled_total"], 0)

    def test_ack_clears_inflight_in_recovery(self):
        j = Journal(self.tmp)
        j.append("executing_prepare", txn="t1", intent="i001")
        j.append("ack", txn="t1", intent="i001", status="crashed")
        j.compact(keep=0)
        j.append("x")
        j.compact(keep=1)
        j.append("y")
        j.compact(keep=1)
        rec = j.read_recovery()
        self.assertNotIn("t1", rec.get("inflight", {}))

    def test_complete_multiple_facts(self):
        self._run(["sapper", "flag", "flag{a}"])
        self._run(["sapper", "flag", "flag{b}"])
        flags = [json.loads(p.read_text()) for p in self.facts()
                 if json.loads(p.read_text()).get("kind") == "flag"]
        ids = [f["id"] for f in flags]
        r = subprocess.run(
            [sys.executable, "-m", "nuwa.cli", "complete", "--root", str(self.root),
             "--from", *ids],
            env={**self.env, "PYTHONPATH": str(REPO)}, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        project = json.loads((self.root / ".sapper" / "project.json").read_text())
        self.assertEqual(project["status"], "completed")

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
