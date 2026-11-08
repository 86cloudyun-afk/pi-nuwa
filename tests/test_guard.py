#!/usr/bin/env python3
"""sapper-guard：执行层提交闸门。"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
GUARD = REPO / "bin" / "sapper-guard"
FAKE = HERE / "fake-sapper"


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="guard-"))
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        (self.bin / "sapper.real").symlink_to(FAKE)
        shutil.copy(GUARD, self.bin / "sapper")
        (self.bin / "sapper").chmod(0o755)
        lab = self.tmp / "lab"
        lab.mkdir()
        (lab / ".submit_token").write_text("testtoken\n", encoding="utf-8")
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "SAPPER_HOME": str(lab),
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_guard(self, *args, allowed=False):
        env = dict(self.env)
        if allowed:
            env["NUWA_SUBMIT_ALLOWED"] = "testtoken"
        return subprocess.run(["sapper", *args], env=env, capture_output=True,
                              text=True, timeout=30)

    def test_allows_dry_run(self):
        self.assertNotEqual(
            self.run_guard("dispatch", "i001", "--dry-run").returncode, 7)

    def test_blocks_done(self):
        self.assertEqual(self.run_guard("done", "i001", "--fact", "x").returncode, 7)

    def test_blocks_dispatch_intent(self):
        self.assertEqual(self.run_guard("dispatch", "i001", "--model", "fake").returncode, 7)

    def test_blocks_complete(self):
        self.assertEqual(self.run_guard("complete", "--from", "f001").returncode, 7)

    def test_allows_reason_internal(self):
        self.assertNotEqual(
            self.run_guard("dispatch", "reason", "--model", "fake", allowed=True).returncode, 7)

    def test_allows_internal_commit(self):
        self.assertNotEqual(
            self.run_guard("done", "i001", "--fact", "x", allowed=True).returncode, 7)

    def test_allows_version(self):
        self.assertEqual(self.run_guard("--version").returncode, 0)

    def test_blocks_store_prefix(self):
        self.assertEqual(
            self.run_guard("--store", "/p/.sapper", "done", "i001", "--fact", "x").returncode, 7)

    def test_blocks_abbrev_store(self):
        self.assertEqual(
            self.run_guard("--st", "/p/.sapper", "done", "i001", "--fact", "x").returncode, 7)

    def test_blocks_dispatch_with_options(self):
        self.assertEqual(
            self.run_guard("dispatch", "--model", "fake", "i001").returncode, 7)

    def test_blocks_fact_from_intent(self):
        self.assertEqual(self.run_guard("fact", "x", "--from-intent", "i001").returncode, 7)
        self.assertEqual(self.run_guard("fact", "x", "--f", "i001").returncode, 7)

    def test_blocks_dispatch_reason(self):
        self.assertEqual(self.run_guard("dispatch", "reason", "--model", "fake").returncode, 7)

    def test_allows_fact_without_from_intent(self):
        self.assertNotEqual(self.run_guard("fact", "x", "-k", "host").returncode, 7)

    def test_blocks_forged_env(self):
        env = dict(self.env)
        env["NUWA_SUBMIT_ALLOWED"] = "1"
        r = subprocess.run(["sapper", "done", "i001", "--fact", "x"], env=env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
