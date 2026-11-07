#!/usr/bin/env python3
"""
确定性端到端：用 fake-claude 顶替模型，跑完整 sapper 链路，零成本、可重复。

覆盖：
  1. reason → intents → dispatch → facts，图能通过 validate
  2. hallucinate 模式：模型谎报 complete → 证据闸门打回 active + hint
  3. noop 模式：reason 返回空 intents → 干净退出
  4. malformed 模式：引擎返回非 JSON → 错误被捕获，不崩
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _paths import BIN, WORK, NUWA, FAKE_CLAUDE as FAKE  # noqa: E402


class E2E(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nuwa-e2e-"))
        (self.tmp / "lab").mkdir()
        (self.tmp / "agent").mkdir()
        self.env = dict(os.environ)
        self.env["PATH"] = f"{BIN}:{Path.home()}/.local/bin:{self.env.get('PATH', '')}"
        self.env["SAPPER_HOME"] = str(self.tmp / "lab")
        self.env["PI_AGENT_HOME"] = str(self.tmp / "agent")
        self.env["NUWA_ENV"] = "/dev/null"
        self.env["SAPPER_BIN"] = str(FAKE)
        self.env["FAKE_ENGINE_COUNTER"] = str(self.tmp / "engine.count")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, cmd, cwd, timeout=90, extra=None):
        env = dict(self.env)
        if extra:
            env.update(extra)
        return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                              text=True, timeout=timeout)

    def project(self, name="p1") -> Path:
        d = self.tmp / "lab" / name
        d.mkdir(parents=True, exist_ok=True)
        self.sh(["sapper", "setup", "--goal", "e2e"], d)
        self.sh(["sapper", "fact", "target alive", "-k", "host", "-d", "ip=127.0.0.1"], d)
        return d

    # ---------------------------------------------------------------- 1
    def test_full_chain(self):
        d = self.project()
        r = self.sh(["sapper", "dispatch", "reason", "--model", "fake", "--timeout", "30"], d)
        self.assertEqual(r.returncode, 0, r.stderr)
        intents = list((d / ".sapper" / "intents").glob("*.json"))
        self.assertGreaterEqual(len(intents), 2)

        r = self.sh([str(NUWA), "http://127.0.0.1:19999", "p1", "--no-view",
                     "--minutes", "1", "--parallel", "2"], d,
                    extra={"FAKE_COMPLETE_AFTER": "999"})
        self.assertEqual(r.returncode, 0, r.stderr)

        facts = list((d / ".sapper" / "facts").glob("*.json"))
        self.assertGreaterEqual(len(facts), 4, f"facts={len(facts)}")
        v = self.sh(["sapper", "validate"], d)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        events = (d / "events.jsonl").read_text()
        self.assertIn("dispatch_end", events)
        self.assertIn("round_start", events)

    # ---------------------------------------------------------------- 2
    def test_hallucinated_completion_rejected(self):
        d = self.project()
        # 引擎谎报 complete：sapper 会把项目标 completed，但没有任何 flag/vuln/loot
        r = self.sh(["sapper", "dispatch", "reason", "--model", "fake", "--timeout", "30"], d,
                    extra={"FAKE_ENGINE_MODE": "hallucinate"})
        self.assertEqual(r.returncode, 0, r.stderr)
        pj = json.loads((d / ".sapper" / "project.json").read_text())
        self.assertEqual(pj["status"], "completed", "前置条件：sapper 已标记完成")

        r = self.sh([str(NUWA), "http://127.0.0.1:19999", "p1", "--no-view",
                     "--minutes", "1"], d,
                    extra={"FAKE_ENGINE_MODE": "hallucinate", "FAKE_COMPLETE_AFTER": "999"})
        self.assertEqual(r.returncode, 0, r.stderr)
        pj = json.loads((d / ".sapper" / "project.json").read_text())
        self.assertNotEqual(pj["status"], "completed", "无证据完成应被打回")
        hints = json.loads((d / ".sapper" / "hints.json").read_text())
        self.assertTrue(any("完成被拒绝" in h.get("content", "") for h in hints),
                        f"应写 hint: {hints}")
        self.assertIn("completion_rejected", (d / "events.jsonl").read_text())

    # ---------------------------------------------------------------- 3
    def test_noop_reason_exits_clean(self):
        d = self.project()
        r = self.sh([str(NUWA), "http://127.0.0.1:19999", "p1", "--no-view",
                     "--minutes", "1"], d,
                    extra={"FAKE_ENGINE_MODE": "noop"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("frontier 为空", r.stdout + r.stderr)

    # ---------------------------------------------------------------- 4
    def test_malformed_engine_does_not_crash(self):
        d = self.project()
        r = self.sh(["sapper", "dispatch", "reason", "--model", "fake", "--timeout", "30"], d,
                    extra={"FAKE_ENGINE_MODE": "malformed"})
        self.assertNotEqual(r.returncode, 0, "非 JSON 输出应报错")
        self.assertNotIn("Traceback", r.stderr, "应是 sapper 的业务错误，不是 Python 崩溃")


if __name__ == "__main__":
    unittest.main(verbosity=2)
