#!/usr/bin/env python3
"""
版本一致性检查（Issue #9）：
校验 omp/nuwa.ts 的 `export const VERSION`、CHANGELOG.md 顶部首个 `## x.y.z`
以及 install.sh（若存在显式版本或安装版本回显）严格一致。

用法：
  python3 tests/version_check.py
  python3 tests/version_check.py --root /path/to/repo

退出码：0 一致；1 不一致或缺少版本定义。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SEMVER_RE = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?"


def extract_nuwa_version(nuwa_ts: Path) -> str:
    text = nuwa_ts.read_text(encoding="utf-8")
    m = re.search(rf'export\s+const\s+VERSION\s*=\s*["\']({SEMVER_RE})["\']', text)
    if not m:
        raise ValueError(f"{nuwa_ts} 未找到 export const VERSION = \"x.y.z\"")
    return m.group(1)


def extract_changelog_version(changelog: Path) -> str:
    text = changelog.read_text(encoding="utf-8")
    for line in text.splitlines():
        m = re.match(rf"^##\s+v?({SEMVER_RE})(?:\b|\s|$)", line.strip())
        if m:
            return m.group(1)
    raise ValueError(f"{changelog} 顶部未找到 `## x.y.z` 标题")


def check_install_version(install_sh: Path, expected: str) -> tuple[bool, str]:
    if not install_sh.exists():
        return True, "install.sh 不存在（跳过）"
    text = install_sh.read_text(encoding="utf-8")

    # 若显式写了字面量回显 `installed version = x.y.z`，必须严格匹配
    lit_echo = re.findall(rf'installed\s+version\s*=\s*v?({SEMVER_RE})', text)
    for ver in lit_echo:
        if ver != expected:
            return False, f"install.sh 回显字面版本 {ver} != {expected}"

    # 若显式定义了 VERSION="x.y.z" / NUWA_VERSION="x.y.z"，也必须严格匹配
    lit_vars = re.findall(rf'(?:^|\n)\s*(?:NUWA_)?VERSION\s*=\s*["\']({SEMVER_RE})["\']', text)
    for ver in lit_vars:
        if ver != expected:
            return False, f"install.sh 变量定义 {ver} != {expected}"

    # 检查是否存在回显格式（支持从 omp/nuwa.ts 动态提取）
    has_echo = bool(re.search(r'installed\s+version\s*=\s*', text))
    if has_echo:
        if lit_echo:
            return True, f"install.sh literal={lit_echo[0]}"
        if "VERSION" in text and "omp/nuwa.ts" in text:
            return True, "install.sh dynamic(from omp/nuwa.ts)"
        return True, "install.sh dynamic"
    return True, "install.sh 无硬编码版本冲突"


def verify_repo_versions(root: Path, require_install_echo: bool = False) -> tuple[bool, list[str]]:
    lines: list[str] = []
    nuwa_ts = root / "omp" / "nuwa.ts"
    changelog = root / "CHANGELOG.md"
    install_sh = root / "install.sh"

    if not nuwa_ts.exists():
        return False, [f"FAIL: 缺少 {nuwa_ts}"]
    if not changelog.exists():
        return False, [f"FAIL: 缺少 {changelog}"]

    try:
        nuwa_ver = extract_nuwa_version(nuwa_ts)
    except ValueError as exc:
        return False, [f"FAIL: {exc}"]

    try:
        chg_ver = extract_changelog_version(changelog)
    except ValueError as exc:
        return False, [f"FAIL: {exc}"]

    lines.append(f"omp/nuwa.ts VERSION = {nuwa_ver}")
    lines.append(f"CHANGELOG.md top    = {chg_ver}")

    if nuwa_ver != chg_ver:
        lines.append(f"FAIL: 版本不一致 omp/nuwa.ts({nuwa_ver}) != CHANGELOG.md({chg_ver})")
        return False, lines

    ok_install, install_msg = check_install_version(install_sh, nuwa_ver)
    lines.append(f"install.sh          = {install_msg}")
    if not ok_install:
        lines.append(f"FAIL: {install_msg}")
        return False, lines

    if require_install_echo and install_sh.exists():
        if not re.search(r'installed\s+version\s*=\s*', install_sh.read_text(encoding="utf-8")):
            lines.append("FAIL: install.sh 缺少 `installed version =` 回显")
            return False, lines

    lines.append(f"version_check: OK ({nuwa_ver})")
    return True, lines


def main() -> int:
    ap = argparse.ArgumentParser(description="检查 omp/nuwa.ts 与 CHANGELOG.md / install.sh 版本一致性")
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                    help="仓库根目录（默认自动定位）")
    ap.add_argument("--require-install-echo", action="store_true",
                    help="强制要求 install.sh 包含 `installed version =` 回显")
    args = ap.parse_args()

    ok, messages = verify_repo_versions(args.root.resolve(), args.require_install_echo)
    for msg in messages:
        print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
