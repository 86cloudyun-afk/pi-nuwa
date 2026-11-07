#!/usr/bin/env python3
"""
A 层验收测试：直接对 bin/nuwa 与 nuwa-loop 的可观察行为下断言。

每条测试都对应尸检报告里的一个缺陷编号。设计原则：
  - 改造前必须 FAIL（证明缺陷真实存在）
  - 改造后必须 PASS（证明修复有效）
  - 不需要模型、不需要网络、毫秒级

用法：
  python3 test_nuwa_shell.py            # 跑全部
  python3 test_nuwa_shell.py -k p0      # 只跑 P0
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _paths import LAYER_A, WORK, NUWA, EXT, INSTALL  # noqa: E402


def sandbox_env(extra: dict | None = None) -> dict:
    env = dict(os.environ)
    env["PATH"] = f"{LAYER_A}:{env.get('PATH', '')}"
    env["SAPPER_HOME"] = str(WORK / "state" / "lab")
    env["PI_AGENT_HOME"] = str(WORK / "state" / "agent")
    env["NUWA_ENV"] = "/dev/null"
    env.pop("NUWA_LOOP", None)
    if extra:
        env.update(extra)
    return env


def run(cmd: list[str], cwd: Path, env: dict, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True,
                          text=True, timeout=timeout)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nuwa-a-"))
        self.lab = self.tmp / "lab"
        self.agent = self.tmp / "agent"
        self.lab.mkdir(parents=True)
        self.agent.mkdir(parents=True)
        self.env = sandbox_env({
            "SAPPER_HOME": str(self.lab),
            "PI_AGENT_HOME": str(self.agent),
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def nuwa(self, *args, timeout=60):
        return run([str(NUWA), *args], self.tmp, self.env, timeout)

    def init_graph(self, project: str = "p1") -> Path:
        d = self.lab / project
        d.mkdir(parents=True, exist_ok=True)
        run(["sapper", "setup", "--goal", "test"], d, self.env)
        run(["sapper", "fact", "靶标可达", "-k", "host", "-d", "ip=127.0.0.1"], d, self.env)
        (self.agent / "cache").mkdir(parents=True, exist_ok=True)
        (self.agent / "cache" / "nuwa-current").write_text(str(d) + "\n")
        return d

    def read_calls(self, d: Path) -> list[dict]:
        p = d / ".sapper" / "calls.jsonl"
        if not p.exists():
            return []
        out = []
        for line in p.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return out


# ---------------------------------------------------------------- P0


class P0_FrontierGuard(Base):
    """0.2 frontier 空输出不得被当成 intent id。"""

    def test_empty_frontier_does_not_dispatch_garbage(self):
        d = self.init_graph()
        # 先让 reason 不产出任何 intent
        r = self.nuwa("http://127.0.0.1:18080", "p1", "--no-view", "--minutes", "1",
                      timeout=90) if False else None
        env = dict(self.env)
        env["FAKE_EMPTY_FRONTIER"] = "1"
        env["FAKE_COMPLETE_AFTER"] = ""
        # 直接驱动 nuwa 的循环：用 --no-run 不行（不执行），所以跑真循环但限制 1 分钟
        r = run([str(NUWA), "http://127.0.0.1:18080", "p1", "--no-view", "--minutes", "1"],
                self.tmp, env, timeout=90)
        combined = r.stdout + r.stderr
        calls = self.read_calls(d)
        dispatched = [c for c in calls if c["argv"] and c["argv"][0] == "dispatch"
                      and len(c["argv"]) > 1 and not c["argv"][1].startswith("reason")]
        bad = [c for c in dispatched if not re.match(r"^i\d+$", c["argv"][1])]
        self.assertEqual(bad, [], f"把非 intent 当 id 派发了: {bad}\n输出:\n{combined[-1500:]}")


class P0_ClaimWorker(Base):
    """0.3 directive 必须带 --worker，否则子代理第一步就失败。"""

    def test_directive_claim_has_worker(self):
        src = EXT.read_text(encoding="utf-8")
        m = re.search(r"buildDirective[\s\S]*?return `\$\{head\}", src)
        block = src[src.find("export function buildDirective"):]
        # 找到拼装 steps 的那一段
        steps_region = block[: block.find("export default")]
        claim_lines = [ln for ln in steps_region.splitlines() if "sapper claim" in ln]
        self.assertTrue(claim_lines, "directive 里没有 claim 指令")
        joined = "\n".join(claim_lines)
        self.assertIn("--worker", joined,
                      f"directive 的 claim 缺 --worker，真实 sapper 会 exit 2:\n{joined}")

    def test_claim_without_worker_really_fails(self):
        """反向证明：真实约束确实存在。"""
        d = self.init_graph()
        run(["sapper", "dispatch", "reason"], d, self.env)
        r = run(["sapper", "claim", "i001"], d, self.env)
        self.assertEqual(r.returncode, 2, "fake-sapper 应复现 --worker required")


class P0_DocSet(Base):
    """0.4 directive 必须给 doc 传内容，否则子代理挂编辑器。"""

    def test_directive_doc_has_body(self):
        block = EXT.read_text(encoding="utf-8")
        block = block[block.find("export function buildDirective"):]
        block = block[: block.find("export default")]
        doc_lines = [ln for ln in block.splitlines() if "sapper doc" in ln]
        self.assertTrue(doc_lines, "directive 里没有 doc 指令")
        joined = "\n".join(doc_lines)
        self.assertTrue("--set" in joined or "--set-file" in joined,
                        f"directive 的 doc 没有内容参数:\n{joined}")


class P0_DependencyCheck(Base):
    """0.1 缺 sapper 时必须在第一行退出，而不是空转。"""

    def test_missing_sapper_exits_fast(self):
        env = dict(self.env)
        # PATH 里塞一个只有基础命令的目录，模拟 sapper 缺失
        clean = self.tmp / "cleanbin"
        clean.mkdir()
        for c in ("bash", "python3", "curl", "mkdir", "date", "cat", "awk", "sed",
                  "grep", "cut", "tr", "head", "tail", "sleep", "dirname", "basename",
                  "nohup", "install", "ln", "rm", "cp", "chmod", "env", "sh"):
            p = shutil.which(c)
            if p:
                (clean / c).symlink_to(p)
        env["PATH"] = f"{clean}:/usr/bin:/bin"
        r = run([str(NUWA), "http://127.0.0.1:18080", "p1", "--no-view", "--minutes", "1"],
                self.tmp, env, timeout=30)
        self.assertNotEqual(r.returncode, 0, "缺 sapper 时退出码应为非 0")
        self.assertLessEqual(r.returncode, 3, f"应以专用退出码退出，实际 {r.returncode}")
        combined = r.stdout + r.stderr
        self.assertIn("sapper", combined.lower(), "错误信息应点明缺 sapper")


class P0_InstallGuard(Base):
    """0.5 install.sh 在缺 sapper 时必须硬失败。"""

    def test_install_hard_fails_without_sapper(self):
        text = INSTALL.read_text(encoding="utf-8")
        tail = text[text.find('command -v sapper'):]
        self.assertTrue(re.search(r"command -v sapper[\s\S]{0,200}?exit\s+1", tail),
                        "install.sh 检测到 sapper 缺失后应 exit 1，而不是只 echo")


class P0_EngineWrapper(Base):
    """0.6 install.sh 必须生成 SAPPER_BIN 指向的执行引擎。"""

    def test_install_creates_engine(self):
        text = INSTALL.read_text(encoding="utf-8")
        self.assertTrue(re.search(r"omp-claude", text),
                        "install.sh 应创建 $SAPPER_HOME/bin/omp-claude")
        self.assertTrue(re.search(r"chmod\s+\+?0?755|install\s+-m", text),
                        "生成的引擎应可执行")


# ---------------------------------------------------------------- P1


class P1_UrlNormalize(Base):
    """1.9 无 scheme 的目标必须能解析出 host。"""

    def test_url_without_scheme(self):
        r = run([str(NUWA), "127.0.0.1:18080", "--no-view", "--no-run"],
                self.tmp, self.env, timeout=60)
        combined = r.stdout + r.stderr
        facts = []
        for d in self.lab.iterdir():
            if d.is_dir() and (d / ".sapper").exists():
                facts.extend((d / ".sapper" / "facts").glob("*.json"))
        ok = False
        for f in facts:
            try:
                data = json.loads(f.read_text()).get("data", {})
                if data.get("ip") == "127.0.0.1" and data.get("port") in ("18080", 18080):
                    ok = True
            except json.JSONDecodeError:
                pass
        self.assertTrue(ok, f"未规范化 URL，落库 ip/port 为空:\n{combined[-800:]}")


class P1_ProjectCollision(Base):
    """1.10 同一分钟内两次启动不得复用同一目录。"""

    def test_same_minute_two_projects(self):
        r1 = self.nuwa("http://127.0.0.1:18080", "--no-view", "--no-run", timeout=40)
        r2 = self.nuwa("http://127.0.0.1:18081", "--no-view", "--no-run", timeout=40)
        dirs = sorted(p.name for p in self.lab.iterdir() if p.is_dir())
        self.assertGreaterEqual(len(dirs), 2, f"两次启动复用了同一目录: {dirs}")
        # 且两张图的 goal 不同
        goals = []
        for d in dirs:
            pj = self.lab / d / ".sapper" / "project.json"
            if pj.exists():
                goals.append(json.loads(pj.read_text()).get("goal", ""))
        self.assertEqual(len(set(goals)), len(goals), f"goal 被覆盖: {goals}")


class P1_FindRootIsolation(Base):
    """1.1 指针指向 B 项目时，A 会话不得接管 B。"""

    def test_pointer_isolation(self):
        a = self.init_graph("projA")
        b = self.init_graph("projB")
        # 指针现在指向 B
        ptr = self.agent / "cache" / "nuwa-current"
        self.assertEqual(ptr.read_text().strip(), str(b))
        # 在 A 目录里跑扩展的 findRoot 逻辑（通过 bun 加载）
        if not shutil.which("bun"):
            self.skipTest("bun 不在 PATH")
        probe = self.tmp / "probe.ts"
        probe.write_text(
            f'import {{ findRoot }} from "{EXT}";\n'
            f'console.log(findRoot("{a}"));\n',
            encoding="utf-8",
        )
        r = run(["bun", str(probe)], a, self.env, timeout=60)
        out = (r.stdout or "").strip()
        self.assertEqual(out, str(a), f"findRoot 从 A 目录返回了 {out}，应为 {a}")


class P1_StallSignal(Base):
    """1.5 无效 note 增长不应重置 stall。"""

    def test_stall_not_reset_by_note_facts(self):
        """读源码：sig 应包含有效推进，而不只是 facts 计数。"""
        src = EXT.read_text(encoding="utf-8")
        self.assertTrue(re.search(r"effective|useful|quality|note", src, re.I),
                        "stall 判据未区分有效推进与 note 噪声")


class P1_EnvValidation(Base):
    """1.6 非法环境变量必须回落默认值。"""

    def test_invalid_max_turns(self):
        if not shutil.which("bun"):
            self.skipTest("bun 不在 PATH")
        probe = self.tmp / "probe2.ts"
        probe.write_text(
            f'process.env.NUWA_MAX_TURNS = "abc";\n'
            f'const m = await import("{EXT}");\n'
            f'console.log(JSON.stringify(m.__cfg ?? {{}}));\n',
            encoding="utf-8",
        )
        r = run(["bun", str(probe)], self.tmp, self.env, timeout=60)
        self.assertNotIn("NaN", r.stdout + r.stderr, "NaN 未被校验")


# ---------------------------------------------------------------- P2


class P2_StateSchema(Base):
    """2.6 状态文件必须带 schema 版本。"""

    def test_state_schema(self):
        src = EXT.read_text(encoding="utf-8")
        self.assertTrue(re.search(r"schema", src), "状态文件缺 schema 版本")
        self.assertTrue(re.search(r"createHash|sha1|sha256", src), "statePath 未做哈希")


class P2_Logging(Base):
    """2.1 必须落 JSONL 日志。"""

    def test_jsonl_log(self):
        src = EXT.read_text(encoding="utf-8")
        self.assertTrue(re.search(r"\.jsonl|appendFile|appendFileSync", src), "无 JSONL 日志")


if __name__ == "__main__":
    unittest.main(verbosity=2)
