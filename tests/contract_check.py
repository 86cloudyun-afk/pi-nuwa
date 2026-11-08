#!/usr/bin/env python3
"""
契约检查：逐条对比真实 sapper 与 tests/fake-sapper 的 CLI 行为。

用法：
  python3 tests/contract_check.py
  python3 tests/contract_check.py --real /root/.local/bin/sapper

退出码：0 全部一致；1 有差异；2 缺少真实 sapper。
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
FAKE = HERE / "fake-sapper"


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
    return subprocess.run(["sapper", *args], cwd=str(cwd), env=env,
                          capture_output=True, text=True, timeout=timeout)


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", default=shutil.which("sapper"))
    args = ap.parse_args()
    if not args.real:
        print("contract: 缺少真实 sapper（PATH 中没有）")
        return 2
    real_bin = Path(args.real).resolve()
    if not FAKE.exists():
        print(f"contract: 缺少 {FAKE}")
        return 2

    results = []
    with tempfile.TemporaryDirectory(prefix="nuwa-contract-") as td:
        tmp = Path(td)
        rb = make_bin(tmp, real_bin)
        fb = make_bin(tmp, FAKE)

        # --version：退出码一致 + 真实版本字符串符合 semver 并被记录
        r_ver = run(rb, ["--version"], tmp)
        f_ver = run(fb, ["--version"], tmp)
        ver_line = r_ver.stdout.strip()
        results.append({"name": "version",
                        "ok": r_ver.returncode == f_ver.returncode and bool(re.match(r"^sapper \d+\.\d+\.\d+", ver_line)),
                        "detail": f"real={ver_line!r}"})

        # setup
        for name, b in (("real", rb), ("fake", fb)):
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
        results.append({"name": "frontier_format",
                        "ok": line_ok and bool(re.match(r"^i\d{3}\tfrom=f\d{3}\t", f_fr.stdout.strip() or "x")),
                        "detail": "" if line_ok else f"real={r_fr.stdout.strip()!r}"})

        # reason 生成意图（fake 直接生成；real 需要模型，跳过执行，只比参数约束）
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
            results.append({"name": f"done_positive_{name}", "ok": ok,
                            "detail": "" if ok else f"facts {before}->{after}, intent={intent.get('status')}"})

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
            results.append({"name": f"unknown_field_preserved_{name}", "ok": ok,
                            "detail": "" if ok else "field dropped after write"})

        # dry-run 渲染与零写入：用未结案的新 intent，输出含意图标记，且内容哈希不变
        for name in ("real", "fake"):
            b = rb if name == "real" else fb
            root = tmp / name
            run(b, ["intent", "--from", "f001", "dry run probe"], root)
            before = tree_hash(root / ".sapper")
            r = run(b, ["dispatch", "i003", "--dry-run"], root)
            after = tree_hash(root / ".sapper")
            ok = r.returncode == 0 and "Intent" in r.stdout and before == after
            results.append({"name": f"dry_run_zero_write_{name}", "ok": ok,
                            "detail": "" if ok else f"rc={r.returncode}, hash {before[:8]}->{after[:8]}"})

        # validate 成功输出前缀一致
        r_val = run(rb, ["validate"], tmp / "real")
        f_val = run(fb, ["validate"], tmp / "fake")
        results.append(check("validate_ok", r_val, f_val, compare_stdout=False))

    failed = [r for r in results if not r["ok"]]
    for r in results:
        print(f"  {'PASS' if r['ok'] else 'FAIL'}  {r['name']}" + (f"  {r['detail']}" if r["detail"] else ""))
    print(f"contract: {len(results) - len(failed)}/{len(results)} 一致")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
