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

from nuwa import evidence, fairness, metrics, plugins, policy, soak, migrate, night  # noqa: E402
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

    def test_prompt_blocks_direct_commit(self):
        ok, rule = policy.check_command("正常提示\nsapper done i001 --fact x")
        self.assertFalse(ok)
        self.assertEqual(rule, "P-006")
        ok, rule = policy.check_command("sapper claim i001 --worker w")
        self.assertTrue(ok)

    def test_prompt_allows_dry_run(self):
        ok, rule = policy.check_prompt("[dispatch] dry-run target=i001 model=deepseek-flash")
        self.assertTrue(ok)
        self.assertIsNone(rule)

    def test_prompt_blocks_shell_wrappers(self):
        for text in (
            "cd /p && sapper done i001 --fact x",
            "sh -c 'sapper done i001 --fact x'",
            "echo $(sapper done i001 --fact x)",
            "\\sapper done i001 --fact x",
            "sapper complete",
        ):
            ok, rule = policy.check_command(text)
            self.assertFalse(ok, text)
            self.assertEqual(rule, "P-006", text)
        ok, rule = policy.check_command("sapper complete --from f009")
        self.assertFalse(ok, rule)

    def test_command_blocks_global_store_forms(self):
        for text in (
            "sapper --store /p/.sapper done i001 --fact x",
            'sapper --store="/p/a b/.sapper" done i001 --fact x',
            "sapper -s/p/.sapper done i001 --fact x",
        ):
            ok, rule = policy.check_command(text)
            self.assertFalse(ok, text)
            self.assertEqual(rule, "P-006", text)

    def test_path_blocks_real_budget_ledger(self):
        for path in ("/root/sapper-lab/budget/global.jsonl",
                     "C:\\lab\\.sapper\\facts\\f1.json"):
            ok, rule = policy.check_path(path)
            self.assertFalse(ok, path)
        self.assertEqual(policy.check_path("/root/sapper-lab/budget/global.jsonl")[1], "P-007")

    def test_path_rules(self):
        cases = {
            ".sapper/facts/f001.json": "P-005",
            "/p/.sapper/intents/i001.json": "P-005",
            "/p/.nuwa/journal.jsonl": "P-007",
            "/p/.nuwa/checkpoint.3.json": "P-007",
            "/p/.sapper/project.json": "P-009",
        }
        for path, want in cases.items():
            ok, rule = policy.check_path(path)
            self.assertFalse(ok, path)
            self.assertEqual(rule, want, path)
        ok, rule = policy.check_path("/tmp/notes.md")
        self.assertTrue(ok)
        self.assertIsNone(rule)


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


class NightTest(unittest.TestCase):
    def test_night_smoke(self):
        tmp = Path(tempfile.mkdtemp(prefix="r7-night-"))
        old = dict(os.environ)
        os.environ.update({
            "PATH": f"{HERE}:{old.get('PATH','')}",
            "SAPPER_HOME": str(tmp / "lab"),
            "PI_AGENT_HOME": str(tmp / "agent"),
            "NUWA_ENGINE": "fake-claude",
            "NUWA_MAX_ROUNDS": "1",
        })
        try:
            res = night.run(tmp / "base", minutes=0.02, projects=2, interval=0.01, model="fake")
            self.assertEqual(res["mode"], "soak")
            self.assertTrue((tmp / "base" / "REPORT.json").exists())
            self.assertTrue((tmp / "base" / "MODE").read_text().strip() == "soak")
        finally:
            os.environ.clear()
            os.environ.update(old)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_night_verify_report(self):
        tmp = Path(tempfile.mkdtemp(prefix="r7-night-verify-"))
        old = dict(os.environ)
        os.environ.update({
            "PATH": f"{HERE}:{old.get('PATH','')}",
            "SAPPER_HOME": str(tmp / "lab"),
            "PI_AGENT_HOME": str(tmp / "agent"),
            "NUWA_ENGINE": "fake-claude",
            "NUWA_MAX_ROUNDS": "1",
        })
        try:
            night.run(tmp / "base", minutes=0.02, projects=2, interval=0.01, model="fake")
            v = night.verify(tmp / "base")
            self.assertTrue(v["ok"], v)
            self.assertTrue(all(v["checks"].values()), v)
            (tmp / "base" / "MODE").write_text("dev\n", encoding="utf-8")
            bad = night.verify(tmp / "base")
            self.assertFalse(bad["ok"])
            self.assertFalse(bad["checks"]["mode"])
        finally:
            os.environ.clear()
            os.environ.update(old)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_night_verify_rejects_malformed_types(self):
        tmp = Path(tempfile.mkdtemp(prefix="r7-night-bad-"))
        try:
            (tmp / "MODE").write_text("soak\n", encoding="utf-8")
            (tmp / "COMMIT").write_text("abc\n", encoding="utf-8")
            cases = [
                {"mode": "soak", "minutes": "abc", "samples": 2, "verdict": {}},
                {"mode": "soak", "minutes": 1, "samples": 2,
                 "verdict": {"all_zero": "false", "rss_ok": True, "fd_ok": True, "facts_ok": True}},
                {"mode": "soak", "minutes": 1, "samples": 2, "verdict": ["ok"]},
                {"mode": "soak", "minutes": float("inf"), "samples": 2,
                 "verdict": {"all_zero": True, "rss_ok": True, "fd_ok": True, "facts_ok": True}},
                {"mode": "soak", "minutes": 1, "samples": 2.5,
                 "verdict": {"all_zero": True, "rss_ok": True, "fd_ok": True, "facts_ok": True}},
            ]
            for body in cases:
                (tmp / "REPORT.json").write_text(json.dumps(body), encoding="utf-8")
                v = night.verify(tmp)
                self.assertFalse(v["ok"], body)
                self.assertIn("error", v)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_night_verify_expect_commit(self):
        tmp = Path(tempfile.mkdtemp(prefix="r7-night-expect-"))
        old = dict(os.environ)
        os.environ.update({
            "PATH": f"{HERE}:{old.get('PATH','')}",
            "SAPPER_HOME": str(tmp / "lab"),
            "PI_AGENT_HOME": str(tmp / "agent"),
            "NUWA_ENGINE": "fake-claude",
            "NUWA_MAX_ROUNDS": "1",
        })
        try:
            night.run(tmp / "base", minutes=0.02, projects=2, interval=0.01, model="fake")
            self.assertTrue(night.verify(tmp / "base", expect_commit="deadbeef")["ok"] is False)
            real = (tmp / "base" / "COMMIT").read_text().strip()
            self.assertTrue(night.verify(tmp / "base", expect_commit=real)["ok"])
        finally:
            os.environ.clear()
            os.environ.update(old)
            shutil.rmtree(tmp, ignore_errors=True)

    def test_night_verify_missing_report(self):
        tmp = Path(tempfile.mkdtemp(prefix="r7-night-missing-"))
        try:
            v = night.verify(tmp)
            self.assertFalse(v["ok"])
            self.assertIn("error", v)
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
