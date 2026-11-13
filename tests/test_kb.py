#!/usr/bin/env python3
"""知识库注入单测：开关、脱敏、预算、CVE 命中。"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from nuwa import kb  # noqa: E402


class KbTest(unittest.TestCase):
    def setUp(self):
        self._old = {k: os.environ.get(k) for k in ("NUWA_KB", "NUWA_KB_DB", "NUWA_KB_TOKENS")}

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_disabled_by_default(self):
        os.environ.pop("NUWA_KB", None)
        self.assertFalse(kb.enabled())

    def test_sanitize_drops_dangerous_lines(self):
        text = "ok line\nrm -rf /\nmkfs.ext4 /dev/sda\nkeep line"
        out = kb.sanitize(text)
        self.assertIn("ok line", out)
        self.assertIn("keep line", out)
        self.assertNotIn("rm -rf", out)
        self.assertNotIn("mkfs", out)

    def test_estimate_tokens(self):
        self.assertGreater(kb.estimate_tokens("CVE-2021-44228 中文"), 0)
        self.assertGreater(kb.estimate_tokens("a" * 400), 90)

    @unittest.skipUnless(kb.db_path().exists(), "kb.db missing")
    def test_enrich_cve(self):
        os.environ["NUWA_KB"] = "1"
        block = kb.enrich("check CVE-2021-44228 on tomcat")
        self.assertIn("<kb-data", block)
        self.assertIn("CVE-2021-44228", block)
        self.assertIn("trust=\"reference-only\"", block)

    @unittest.skipUnless(kb.db_path().exists(), "kb.db missing")
    def test_budget_cap(self):
        os.environ["NUWA_KB"] = "1"
        os.environ["NUWA_KB_TOKENS"] = "300"
        block = kb.enrich("CVE-2021-44228 tomcat weblogic exchange")
        self.assertLessEqual(kb.estimate_tokens(block), 300)


if __name__ == "__main__":
    unittest.main(verbosity=2)
