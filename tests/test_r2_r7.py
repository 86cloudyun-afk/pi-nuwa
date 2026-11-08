#!/usr/bin/env python3
"""R2-R7 模块测试：公平、证据、指标、策略、插件、长测。"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from nuwa import evidence, fairness, metrics, plugins, policy, soak, migrate  # noqa: E402
from nuwa.journal import Journal  # noqa: E402


class FairnessTest(unittest.TestCase):
    def test_weighted(self):
        shares = fairness.schedule({"p0": 2, "p1": 1, "p2": 1}, slots=400)
        self.assertAlmostEqual(shares["p0"], 0.5, places=2)
        self.assertAlmostEqual(shares["p1"], 0.25, places=2)
        self.assertAlmostEqual(shares["p2"], 0.25, places=2)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            fairness.schedule({"p0": 0})


class EvidenceTest(unittest.TestCase):
    def _fact(self, **kw):
        target = {"host": "h", "port": 80, "scheme": "http"}
        ev = evidence.capture(
            command=kw.get("command", "curl -sS http://h/flag"),
            cwd="/tmp", exit_code=kw.get("exit_code", 0),
            stdout=kw.get("stdout", b"flag{x}"), stderr=b"",
            target=target, intent_id="i001", project_id="p1",
            assertion=kw.get("assertion", {"field": "stdout", "op": "contains", "value": "flag{"}),
            captured_at=kw.get("captured_at"),
        )
        return {"x-nuwa-evidence": ev, "x-nuwa-target": target}

    def test_ok(self):
        code, msg = evidence.verify(self._fact(), b"flag{x}")
        self.assertEqual((code, msg), (0, "ok"))

    def test_no_command(self):
        f = self._fact()
        f["x-nuwa-evidence"]["command"] = ""
        self.assertEqual(evidence.verify(f)[0], 10)

    def test_assertion_false(self):
        f = self._fact()
        f["x-nuwa-evidence"]["assertion"]["value"] = "not-there"
        self.assertEqual(evidence.verify(f, b"flag{x}")[0], 11)

    def test_stale(self):
        f = self._fact(captured_at=time.time() - 3600)
        self.assertEqual(evidence.verify(f, b"flag{x}")[0], 12)

    def test_hash_mismatch(self):
        f = self._fact()
        self.assertEqual(evidence.verify(f, b"other")[0], 13)

    def test_target_mismatch(self):
        f = self._fact()
        f["x-nuwa-target"] = {"host": "other", "port": 80, "scheme": "http"}
        self.assertEqual(evidence.verify(f, b"flag{x}")[0], 14)

    def test_confidence(self):
        now = time.time()
        base = self._fact(captured_at=now)["x-nuwa-evidence"]
        base["assertion"] = {"op": "eq"}
        self.assertEqual(evidence.confidence(base, now), 1.0)
        mid = dict(base, captured_at=evidence._iso(now - 1200))
        mid["assertion"] = {"op": "contains"}
        mid["norm_sha256"] = ""
        self.assertEqual(evidence.confidence(mid, now), 0.65)
        low = dict(base, captured_at=evidence._iso(now - 2400))
        low["assertion"] = {"op": "contains"}
        low["norm_sha256"] = ""
        self.assertEqual(evidence.confidence(low, now), 0.45)


class MetricsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r4-metrics-"))
        j = Journal(self.tmp)
        j.append("executed", txn="t1", duration_ms=100, tokens=40)
        j.append("executed", txn="t2", duration_ms=300, tokens=60)
        j.append("commit_done", txn="t1")
        j.append("completion_rejected")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_compute(self):
        d = metrics.compute(self.tmp)
        self.assertEqual(d["dispatches"], 2)
        self.assertEqual(d["commits"], 1)
        self.assertEqual(d["rejects"], 1)
        self.assertEqual(d["tokens"], 100)
        self.assertEqual(d["duration_ms"]["p50"], 200)

    def test_html(self):
        out = metrics.render_html(metrics.compute(self.tmp))
        self.assertIn("<html>", out)
        self.assertIn("dispatches=2", out)


class PolicyTest(unittest.TestCase):
    def test_deny(self):
        ok, rule = policy.check_command("rm -rf /")
        self.assertFalse(ok)
        self.assertEqual(rule, "P-001")

    def test_allow(self):
        ok, rule = policy.check_command("nmap -sV 127.0.0.1")
        self.assertTrue(ok)
        self.assertIsNone(rule)

    def test_redact(self):
        text = "token=abc123 sk-ABCDEFGH1234"
        out = policy.redact(text)
        self.assertNotIn("abc123", out)
        self.assertNotIn("ABCDEFGH1234", out)

    def test_signature(self):
        key = b"k"
        sig = policy.sign(b"data", key)
        self.assertTrue(policy.verify_signature(b"data", key, sig))
        self.assertFalse(policy.verify_signature(b"data2", key, sig))


class PluginTest(unittest.TestCase):
    def test_discover_and_run(self):
        found = plugins.discover(HERE / "fixtures" / "plugins")
        names = {p["name"] for p in found}
        self.assertIn("fake-engine", names)
        self.assertNotIn("old-engine", names)
        p = [x for x in found if x["name"] == "fake-engine"][0]
        self.assertEqual(plugins.run(p, "hello"), "ok:hello")


class MigrationTest(unittest.TestCase):
    def test_loop_state_2_to_3(self):
        tmp = Path(tempfile.mkdtemp(prefix="r6-migrate-"))
        try:
            d = tmp / "cache" / "nuwa-loop"
            d.mkdir(parents=True)
            f = d / "s1.json"
            f.write_text(json.dumps({"schema": 2, "turns": 3, "spentTokens": 9}))
            res = migrate.migrate_loop_state(write=True, home=tmp)
            self.assertEqual(res["migrated"], ["s1.json"])
            data = json.loads(f.read_text())
            self.assertEqual(data["schema"], 3)
            self.assertEqual(data["turns"], 3)
            self.assertTrue((d / "s1.json.bak").exists())
            res2 = migrate.migrate_loop_state(write=True, home=tmp)
            self.assertEqual(res2["migrated"], [])
            self.assertEqual(res2["skipped"], ["s1.json"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SoakTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="r7-soak-"))
        self.env = dict(os.environ)
        self.env["PATH"] = f"{HERE}:{self.env.get('PATH', '')}"
        self.env["SAPPER_HOME"] = str(self.tmp / "lab")
        self.env["PI_AGENT_HOME"] = str(self.tmp / "agent")
        self.env["NUWA_ENGINE"] = "fake-claude"
        self.env["NUWA_MAX_ROUNDS"] = "1"
        self._old = dict(os.environ)
        os.environ.update(self.env)
        self.roots = []
        for i in range(2):
            root = self.tmp / "lab" / f"s{i}"
            root.mkdir(parents=True)
            subprocess.run(["sapper", "setup", "--goal", f"s{i}"], cwd=root,
                           env=self.env, check=True, capture_output=True)
            subprocess.run(["sapper", "fact", "alive", "-k", "host"], cwd=root,
                           env=self.env, check=True, capture_output=True)
            subprocess.run(["sapper", "intent", "--from", "f001", "probe"], cwd=root,
                           env=self.env, check=True, capture_output=True)
            self.roots.append(root)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_smoke(self):
        res = soak.soak(self.roots, minutes=0.05, interval=0.02)
        self.assertTrue(res["verdict"]["all_zero"])
        self.assertTrue(res["verdict"]["facts_ok"])
        self.assertGreaterEqual(res["samples"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
