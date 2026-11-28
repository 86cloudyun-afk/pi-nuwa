#!/usr/bin/env python3
"""
契约检查：
  1. 先校验 v2（omp 原生运行时）文件结构、12 个 nuwa_* 工具、install.sh 与 SKILL.md（无需 sapper）。
  2. 再对比真实 sapper 与 tests/fake-sapper 的 v1 CLI 契约（--v2-only 可跳过；
     若系统无真实 sapper 且未设 NUWA_REQUIRE_V1_SAPPER=1，则打印 SKIP 并返回 0）。

用法：
  python3 tests/contract_check.py
  python3 tests/contract_check.py --v2-only
  python3 tests/contract_check.py --real /root/.local/bin/sapper

退出码：0 通过或 v1 SKIP；1 契约不一致；2 强制要求真实 sapper 但缺失。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FAKE = HERE / "fake-sapper"

NUWA_V2_TOOLS = (
    "nuwa_init",
    "nuwa_plan",
    "nuwa_frontier",
    "nuwa_claim",
    "nuwa_commit",
    "nuwa_flag",
    "nuwa_complete",
    "nuwa_status",
    "nuwa_report",
    "nuwa_expand",
    "nuwa_stop",
    "nuwa_kb",
)


def find_tsc_bin(repo_root: Path) -> str | None:
    """探测本地可用 tsc 编译器（优先显式环境变量、PATH、本地 node_modules 与常见系统目录）。"""
    explicit = os.environ.get("NUWA_TSC_BIN", "").strip()
    if explicit and Path(explicit).is_file() and os.access(explicit, os.X_OK):
        return explicit
    in_path = shutil.which("tsc")
    if in_path:
        return in_path
    local_tsc = repo_root / "node_modules" / ".bin" / "tsc"
    if local_tsc.is_file() and os.access(local_tsc, os.X_OK):
        return str(local_tsc)
    for static_cand in (
        Path("/usr/local/lib/node_modules/typescript/bin/tsc"),
        Path.home() / ".bun/install/global/node_modules/.bin/tsc",
    ):
        try:
            if static_cand.is_file() and os.access(static_cand, os.X_OK):
                return str(static_cand)
        except OSError:
            pass
    try:
        for cand in sorted(Path("/opt").glob("*/node_modules/.bin/tsc")):
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
    except OSError:
        pass
    return None


def make_bin(tmp: Path, target: Path) -> Path:
    d = tmp / f"bin-{target.stem}"
    d.mkdir(parents=True, exist_ok=True)
    link = d / "sapper"
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target)
    return d


def run(bin_dir: Path, args: list[str], cwd: Path, timeout: int = 30) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    return subprocess.run(
        ["sapper", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*.json")):
        h.update(str(p.relative_to(root)).encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def check(name: str, real: subprocess.CompletedProcess, fake: subprocess.CompletedProcess,
          compare_stdout: bool = True) -> dict:
    ok = real.returncode == fake.returncode
    detail = ""
    if compare_stdout and ok:
        ok = real.stdout.strip() == fake.stdout.strip()
        if not ok:
            detail = f"stdout real={real.stdout.strip()!r} fake={fake.stdout.strip()!r}"
    if not ok and not detail:
        detail = f"rc real={real.returncode} fake={fake.returncode}"
    return {"name": name, "ok": ok, "detail": detail}


def check_v2_contract(repo_root: Path) -> tuple[bool, list[dict]]:
    """无 sapper 依赖的 v2 omp 原生契约检查。"""
    results: list[dict] = []
    required_files = [
        "omp/nuwa.ts",
        "omp/types.ts",
        "omp/storage-io.ts",
        "omp/storage.ts",
        "omp/sqlite-schema.ts",
        "omp/sqlite-store.ts",
        "omp/graph-dedup.ts",
        "omp/graph.ts",
        "omp/graph-planner.ts",
        "omp/graph-commands.ts",
        "omp/autoexec-baseline.ts",
        "omp/autoexec.ts",
        "omp/auto-loops.ts",
        "omp/belief-search.ts",
        "omp/calibration.ts",
        "omp/traffic-mutator.ts",
        "omp/traffic-workbench.ts",
        "omp/hybrid-audit.ts",
        "omp/browser-recon.ts",
        "omp/scope.ts",
        "omp/evidence.ts",
        "omp/profiles.ts",
        "omp/reincarnate.ts",
        "omp/lineage.ts",
        "omp/kb.ts",
        "omp/session-vault.ts",
        "omp/auth-diff.ts",
        "omp/verifier-gate.ts",
        "omp/sandbox-egress.ts",
        "omp/sandbox.ts",
        "omp/oob.ts",
        "omp/hypothesis.ts",
        "omp/reporting.ts",
        "omp/ui.ts",
        "omp/ui-native.ts",
        "omp/cdp-client.ts",
        "omp/cdp-bridge.ts",
        "omp/chain-capabilities.ts",
        "omp/chain-composer.ts",
        "omp/specialist-squad.ts",
        "omp/kb-v2.ts",
        "omp/dispatch-bridge.ts",
        "omp/env.d.ts",
        "core/protocol.ts",
        "core/engine-helpers.ts",
        "core/engine.ts",
        "core/autonomous-doctor.ts",
        "core/mcp-server.ts",
        "bin/nuwa-mcp",
        "tsconfig.json",
        "kb/schema.sql",
        "kb/seed-cards.json",
        "kb/seed-cves.json",
        "kb/seed-techniques.json",
        "kb/seed-v7-pack.json",
        "kb/build-kb.ts",
        "benchmarks/targets.json",
        "benchmarks/run-eval.ts",
        "benchmarks/run-l2-eval.ts",
        "benchmarks/l3-live/run-l3-eval.ts",
        "agents/fujiang.md",
        "agents/nuwa-verifier.md",
        "agents/nuwa-scout.md",
        "agents/nuwa-spa-reverser.md",
        "agents/nuwa-auth-breaker.md",
        "agents/nuwa-code-auditor.md",
        "config/autoexec.example.json",
        "docker/Dockerfile.sandbox",
        "bin/nuwa-autonomous",
        "install.sh",
        "skills/nuwa-pentest/SKILL.md",
    ]
    missing = [rel for rel in required_files if not (repo_root / rel).is_file() or (repo_root / rel).stat().st_size == 0]
    results.append({
        "name": "v2_required_files",
        "ok": len(missing) == 0,
        "detail": "" if not missing else f"missing={missing}",
    })
    if missing:
        return False, results

    # 校验所有 omp/*.ts 子模块严禁运行时反向 import ./nuwa（仅允许 import type）
    bad_submodules: list[str] = []
    for ts_file in sorted((repo_root / "omp").glob("*.ts")):
        if ts_file.name == "nuwa.ts" or ts_file.name.endswith(".d.ts"):
            continue
        ts_src = ts_file.read_text(encoding="utf-8")
        stripped = re.sub(r'^\s*import\s+type\s+[^;]+from\s+["\']\./nuwa["\'];?\s*$', "", ts_src, flags=re.MULTILINE)
        if re.search(r'from\s+["\']\./nuwa["\']|import\s*\(\s*["\']\./nuwa["\']\s*\)|require\s*\(\s*["\']\./nuwa["\']\s*\)', stripped):
            bad_submodules.append(ts_file.name)
    results.append({
        "name": "v4_submodule_no_runtime_nuwa_import",
        "ok": len(bad_submodules) == 0,
        "detail": "" if not bad_submodules else f"runtime_import_nuwa={bad_submodules}",
    })

    nuwa_src = (repo_root / "omp/nuwa.ts").read_text(encoding="utf-8")
    ver_ok = bool(re.search(r'export\s+const\s+VERSION\s*=\s*["\']\d+\.\d+\.\d+', nuwa_src))
    results.append({"name": "v2_nuwa_version", "ok": ver_ok, "detail": "" if ver_ok else "VERSION missing"})

    found_tools = set(re.findall(r'\bname\s*:\s*["\'](nuwa_[a-z0-9_]+)["\']', nuwa_src))
    missing_tools = [t for t in NUWA_V2_TOOLS if t not in found_tools]
    extra_tools = sorted(found_tools - set(NUWA_V2_TOOLS))
    tools_ok = not missing_tools and not extra_tools and len(found_tools) == 12
    detail = "" if tools_ok else f"missing={missing_tools} extra={extra_tools} count={len(found_tools)}"
    results.append({"name": "v2_12_nuwa_tools", "ok": tools_ok, "detail": detail})

    export_specs = (
        ("v2_autoexec_exports", "omp/autoexec.ts", ("pickAuto", "ruleFor", "runAutoIntent", "shellQuote")),
        ("v2_ui_exports", "omp/ui.ts", ("buildSnapshot", "renderStatusLine", "renderWidgetLines", "renderBoardLines")),
        ("v2_ui_native_exports", "omp/ui-native.ts", ("buildWidgetNode", "buildBoardNode", "createWidgetComponent", "createBoardComponent")),
    )
    for name, rel, symbols in export_specs:
        src = (repo_root / rel).read_text(encoding="utf-8")
        missing_syms = [s for s in symbols if not re.search(rf'\bexport\b[\s\S]{{0,40}}\b{s}\b', src)]
        results.append({
            "name": name,
            "ok": len(missing_syms) == 0,
            "detail": "" if not missing_syms else f"missing={missing_syms}",
        })

    install_src = (repo_root / "install.sh").read_text(encoding="utf-8")
    install_ok = (
        "command -v sapper" not in install_src
        and "omp/nuwa.ts" in install_src
        and "index.ts" in install_src
        and "ui.ts" in install_src
        and "ui-native.ts" in install_src
        and "autoexec.ts" in install_src
        and all(t in install_src for t in NUWA_V2_TOOLS)
    )
    results.append({
        "name": "v2_install_contract",
        "ok": install_ok,
        "detail": "" if install_ok else "install.sh 缺少 v2 模块/工具校验或误依赖 sapper",
    })

    skill_src = (repo_root / "skills/nuwa-pentest/SKILL.md").read_text(encoding="utf-8")
    skill_missing = [t for t in NUWA_V2_TOOLS if t not in skill_src]
    skill_ok = ("name: nuwa-pentest" in skill_src) and not skill_missing
    results.append({
        "name": "v2_skill_contract",
        "ok": skill_ok,
        "detail": "" if skill_ok else f"missing_tools={skill_missing}",
    })

    # 全量离线静态构建门禁 + 运行时异步 Bun.plugin 加载契约（含 KB 懒建库与子代理血缘拦截）
    bun_bin = shutil.which("bun")
    if bun_bin:
        env = dict(os.environ)
        env.pop("BUN_OPTIONS", None)

        with tempfile.TemporaryDirectory(prefix="nuwa-contract-build-") as build_dir:
            omp_entries = [str(p) for p in sorted((repo_root / "omp").glob("*.ts"))]
            core_entries = [str(p) for p in sorted((repo_root / "core").glob("*.ts"))]
            build_cmd = [
                bun_bin,
                "build",
                *omp_entries,
                *core_entries,
                str(repo_root / "kb" / "build-kb.ts"),
                "--target",
                "bun",
                "--external",
                "@oh-my-pi/pi-coding-agent",
                "--external",
                "playwright",
                "--external",
                "playwright-core",
                "--outdir",
                build_dir,
            ]
            bld = subprocess.run(build_cmd, cwd=str(repo_root), env=env, capture_output=True, text=True, timeout=30)
            bld_ok = bld.returncode == 0
            bld_detail = "bun build ok" if bld_ok else (bld.stderr.strip() or bld.stdout.strip() or f"rc={bld.returncode}")
        results.append({
            "name": "v4_offline_static_build",
            "ok": bld_ok,
            "detail": bld_detail[:200],
        })

        # 全仓 tsconfig.json include 完整性与静态类型检查（覆盖 omp/kb/core/benchmarks）
        try:
            tsconfig_data = json.loads((repo_root / "tsconfig.json").read_text(encoding="utf-8"))
            includes = tsconfig_data.get("include") if isinstance(tsconfig_data, dict) else []
            required_includes = ["omp/**/*.ts", "omp/**/*.d.ts", "kb/**/*.ts", "core/**/*.ts", "benchmarks/**/*.ts"]
            missing_includes = [inc for inc in required_includes if not isinstance(includes, list) or inc not in includes]
        except Exception as exc:
            missing_includes = [f"tsconfig.json invalid: {exc}"]

        if missing_includes:
            results.append({
                "name": "v6_tsc_typecheck",
                "ok": False,
                "detail": f"tsconfig include 缺失: {missing_includes}"[:200],
            })
        else:
            tsc_bin = find_tsc_bin(repo_root)
            if tsc_bin:
                tsc_proc = subprocess.run(
                    [tsc_bin, "-p", str(repo_root / "tsconfig.json"), "--noEmit"],
                    cwd=str(repo_root),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                tsc_ok = tsc_proc.returncode == 0
                tsc_detail = (
                    f"tsc -p tsconfig.json ok ({tsc_bin})"
                    if tsc_ok
                    else (tsc_proc.stdout.strip() or tsc_proc.stderr.strip() or f"rc={tsc_proc.returncode}")
                )
                results.append({
                    "name": "v6_tsc_typecheck",
                    "ok": tsc_ok,
                    "detail": tsc_detail[:200],
                })
            elif os.environ.get("NUWA_REQUIRE_TSC") == "1":
                results.append({
                    "name": "v6_tsc_typecheck",
                    "ok": False,
                    "detail": "tsc not found (NUWA_REQUIRE_TSC=1)",
                })
            else:
                results.append({
                    "name": "v6_tsc_typecheck",
                    "ok": True,
                    "detail": "tsconfig include ok (SKIP: tsc not installed)",
                })

        omp_dir = str((repo_root / "omp").resolve())
        smoke_js = """
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const agentHome = mkdtempSync(join(tmpdir(), "nuwa-contract-home-"));
process.env.PI_AGENT_HOME = agentHome;
const ompDir = process.env.NUWA_OMP_DIR!;
const coreDir = join(ompDir, "..", "core");
const escapedOmp = ompDir.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");
const escapedCore = coreDir.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");
const transpiler = new Bun.Transpiler({ loader: "ts" });
Bun.plugin({
  name: "nuwa-contract-async-ext",
  setup(build) {
    build.onLoad({ filter: new RegExp(`^(?:${escapedOmp}|${escapedCore})/.*\\\\.ts$`) }, async (args) => {
      const text = await Bun.file(args.path).text();
      return { contents: transpiler.transformSync(text), loader: "js" };
    });
  },
});
const mod = await import(`${ompDir}/nuwa.ts`);
const tools = new Map<string, any>();
const hooks = new Map<string, Array<(...a: any[]) => any>>();
const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
const z = new Proxy({}, { get: () => () => chain() });
mod.default({
  zod: z,
  registerTool: (t: any) => tools.set(t.name, t),
  registerCommand: () => {},
  on: (ev: string, fn: any) => {
    const arr = hooks.get(ev) ?? [];
    arr.push(fn);
    hooks.set(ev, arr);
  },
});
const dir = mkdtempSync(join(tmpdir(), "nuwa-contract-rt-"));
try {
  const ctx: any = { cwd: dir, agent: { kind: "main", id: "main-0" }, sessionManager: { getSessionId: () => "contract-rt" } };
  const r1 = await tools.get("nuwa_init").execute("1", { target: "http://127.0.0.1:18080", mode: "ctf", root: dir }, undefined, undefined, ctx);
  const t1 = r1?.content?.[0]?.text ?? "";
  if (!t1.includes("女娲已上膛") || t1.includes("ERROR:")) {
    throw new Error(`nuwa_init failed: ${t1}`);
  }
  const r2 = await tools.get("nuwa_status").execute("2", { root: dir }, undefined, undefined, ctx);
  const t2 = r2?.content?.[0]?.text ?? "";
  if (!t2.includes("phase=recon") || !t2.includes("kb=ready") || t2.includes("ERROR:")) {
    throw new Error(`nuwa_status failed: ${t2}`);
  }
  const kbRes = await tools.get("nuwa_kb").execute("3", { query: "spring", kind: "auto", limit: 3 }, undefined, undefined, ctx);
  const kbText = kbRes?.content?.[0]?.text ?? "";
  if (!kbText || kbText.includes("未命中") || kbText.includes("ERROR:")) {
    throw new Error(`nuwa_kb failed: ${kbText}`);
  }
  hooks.get("before_subagent_spawn")?.[0]?.({ agent: "fujiang", task: "probe" }, ctx);
  const subCtx: any = { cwd: dir, agent: { kind: "sub", id: "0-fujiang", parentId: "main-0" }, sessionManager: { getSessionId: () => "contract-sub-99" } };
  const verdict = hooks.get("tool_call")?.[0]?.({ toolName: "read", input: { path: "http://evil.outside.invalid/x" } }, subCtx);
  if (!verdict?.block || !String(verdict.reason ?? "").includes("N-007")) {
    throw new Error(`subagent guard failed: ${JSON.stringify(verdict)}`);
  }
  console.log(`RUNTIME_OK:${mod.VERSION}:tools=${tools.size}`);
} finally {
  rmSync(dir, { recursive: true, force: true });
  rmSync(agentHome, { recursive: true, force: true });
}
"""
        env["NUWA_OMP_DIR"] = omp_dir
        rt = subprocess.run([bun_bin, "-e", smoke_js], cwd=str(repo_root), env=env, capture_output=True, text=True, timeout=30)
        rt_ok = rt.returncode == 0 and "RUNTIME_OK:" in rt.stdout and "tools=12" in rt.stdout
        rt_detail = rt.stdout.strip() if rt_ok else (rt.stderr.strip() or rt.stdout.strip() or f"rc={rt.returncode}")
    else:
        results.append({"name": "v4_offline_static_build", "ok": False, "detail": "bun not found in PATH"})
        rt_ok = False
        rt_detail = "bun not found in PATH"
    results.append({
        "name": "v2_omp_async_plugin_runtime",
        "ok": rt_ok,
        "detail": rt_detail[:200],
    })

    return all(r["ok"] for r in results), results


def is_fake_sapper(candidate: Path) -> bool:
    try:
        resolved = candidate.resolve()
        return resolved == FAKE.resolve() or resolved.parent == HERE.resolve()
    except OSError:
        return False


def find_real_sapper(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() and not is_fake_sapper(p) else None
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        cand = Path(entry) / "sapper"
        if cand.is_file() and os.access(cand, os.X_OK) and not is_fake_sapper(cand):
            return cand
    return None


def run_v1_contract(real_bin: Path) -> tuple[int, list[dict]]:
    if not FAKE.exists():
        print(f"contract(v1): 缺少 {FAKE}")
        return 2, []

    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="nuwa-contract-") as td:
        tmp = Path(td)
        rb = make_bin(tmp, real_bin)
        fb = make_bin(tmp, FAKE)

        # --version：退出码一致 + 真实版本字符串符合 semver 并被记录
        r_ver = run(rb, ["--version"], tmp)
        f_ver = run(fb, ["--version"], tmp)
        ver_line = r_ver.stdout.strip()
        results.append({
            "name": "version",
            "ok": r_ver.returncode == f_ver.returncode and bool(re.match(r"^sapper \d+\.\d+\.\d+", ver_line)),
            "detail": f"real={ver_line!r}",
        })

        # setup
        for name in ("real", "fake"):
            (tmp / name).mkdir()
        r_setup = run(rb, ["setup", "--goal", "contract"], tmp / "real")
        f_setup = run(fb, ["setup", "--goal", "contract"], tmp / "fake")
        results.append(check("setup", r_setup, f_setup, compare_stdout=False))

        # 空 frontier 输出必须一致
        results.append(check("frontier_empty",
                             run(rb, ["frontier"], tmp / "real"),
                             run(fb, ["frontier"], tmp / "fake")))

        # fact + intent + frontier 行格式（frontier 列的是 intent，不是 fact）
        for name in ("real", "fake"):
            b = rb if name == "real" else fb
            run(b, ["fact", "target alive", "-k", "host"], tmp / name)
            run(b, ["intent", "--from", "f001", "contract probe"], tmp / name)
        r_fr = run(rb, ["frontier"], tmp / "real")
        f_fr = run(fb, ["frontier"], tmp / "fake")
        line_ok = bool(re.match(r"^i\d{3}\tfrom=f\d{3}\t", r_fr.stdout.strip() or "x"))
        results.append({
            "name": "frontier_format",
            "ok": line_ok and bool(re.match(r"^i\d{3}\tfrom=f\d{3}\t", f_fr.stdout.strip() or "x")),
            "detail": "" if line_ok else f"real={r_fr.stdout.strip()!r}",
        })

        # claim 缺 --worker 必须 exit 2
        r_claim = run(rb, ["claim", "i001"], tmp / "real")
        f_claim = run(fb, ["claim", "i001"], tmp / "fake")
        results.append(check("claim_requires_worker", r_claim, f_claim, compare_stdout=False))

        # done 缺 --fact 必须 exit 2
        r_done = run(rb, ["done", "i001"], tmp / "real")
        f_done = run(fb, ["done", "i001"], tmp / "fake")
        results.append(check("done_requires_fact", r_done, f_done, compare_stdout=False))

        # 正向结案：done 必须同时更新 intent 与新建 fact
        for name in ("real", "fake"):
            b = rb if name == "real" else fb
            run(b, ["intent", "--from", "f001", "positive case"], tmp / name)
            before = len(list((tmp / name / ".sapper" / "facts").glob("*.json")))
            run(b, ["done", "i002", "--fact", "positive conclusion", "-k", "note"], tmp / name)
            after = len(list((tmp / name / ".sapper" / "facts").glob("*.json")))
            intent = json.loads((tmp / name / ".sapper" / "intents" / "i002.json").read_text())
            ok = after == before + 1 and intent.get("status") == "done" and intent.get("to")
            results.append({
                "name": f"done_positive_{name}",
                "ok": ok,
                "detail": "" if ok else f"facts {before}->{after}, intent={intent.get('status')}",
            })

        # 未知字段保留：经过 validate 与一次写操作后仍在
        for name in ("real", "fake"):
            b = rb if name == "real" else fb
            root = tmp / name
            fp = root / ".sapper" / "facts" / "f001.json"
            d = json.loads(fp.read_text())
            d["x-nuwa-probe"] = {"keep": True}
            fp.write_text(json.dumps(d, ensure_ascii=False, indent=2))
            run(b, ["validate"], root)
            run(b, ["done", "i001", "--fact", "post-write probe", "-k", "note"], root)
            fp2 = root / ".sapper" / "facts" / "f001.json"
            d2 = json.loads(fp2.read_text()) if fp2.exists() else {}
            ok = d2.get("x-nuwa-probe", {}).get("keep") is True
            results.append({
                "name": f"unknown_field_preserved_{name}",
                "ok": ok,
                "detail": "" if ok else "field dropped after write",
            })

        # dry-run 渲染与零写入：用未结案的新 intent，输出含意图标记，且内容哈希不变
        for name in ("real", "fake"):
            b = rb if name == "real" else fb
            root = tmp / name
            run(b, ["intent", "--from", "f001", "dry run probe"], root)
            before = tree_hash(root / ".sapper")
            r = run(b, ["dispatch", "i003", "--dry-run"], root)
            after = tree_hash(root / ".sapper")
            ok = r.returncode == 0 and "Intent" in r.stdout and before == after
            results.append({
                "name": f"dry_run_zero_write_{name}",
                "ok": ok,
                "detail": "" if ok else f"rc={r.returncode}, hash {before[:8]}->{after[:8]}",
            })

        # validate 成功输出前缀一致
        r_val = run(rb, ["validate"], tmp / "real")
        f_val = run(fb, ["validate"], tmp / "fake")
        results.append(check("validate_ok", r_val, f_val, compare_stdout=False))

    failed = [r for r in results if not r["ok"]]
    return (0 if not failed else 1), results


def main() -> int:
    ap = argparse.ArgumentParser(description="v2 原生契约 + 可选 v1 sapper 契约校验")
    ap.add_argument("--real", default=None)
    ap.add_argument("--v2-only", action="store_true", help="仅运行 v2 契约检查，跳过 v1 sapper 对比")
    args = ap.parse_args()

    v2_ok, v2_results = check_v2_contract(REPO)
    for r in v2_results:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['name']}" + (f"  {r['detail']}" if r["detail"] else ""))
    v2_pass = sum(1 for r in v2_results if r["ok"])
    print(f"contract(v2): {v2_pass}/{len(v2_results)} 通过")
    if not v2_ok:
        return 1

    if args.v2_only:
        print("contract(v1): SKIP (--v2-only)")
        return 0

    real_candidate = find_real_sapper(args.real)
    if not real_candidate:
        if os.environ.get("NUWA_REQUIRE_V1_SAPPER") == "1":
            print("contract(v1): FAIL (no sapper; NUWA_REQUIRE_V1_SAPPER=1)")
            return 2
        print("contract(v1): SKIP (no sapper)")
        return 0

    rc, v1_results = run_v1_contract(real_candidate.resolve())
    for r in v1_results:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['name']}" + (f"  {r['detail']}" if r["detail"] else ""))
    v1_pass = sum(1 for r in v1_results if r["ok"])
    print(f"contract(v1): {v1_pass}/{len(v1_results)} 一致")
    return rc


if __name__ == "__main__":
    sys.exit(main())
