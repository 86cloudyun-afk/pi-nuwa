#!/usr/bin/env bash
# 女娲回归入口：bun test 默认在同一全局对象里跑全部用例，多个测试文件都会
# 改写 PI_AGENT_HOME / NUWA_SHARED_CWDS 并 import ../omp/nuwa，先到先得，
# 后跑的用例会拿到别人的 agent home，出现 6 例假红。
# --isolate 让每个测试文件用独立全局对象，实测 154/154 通过。
set -u
unset BUN_OPTIONS
cd "$(dirname "$0")" || exit 1
export NUWA_WORK="${NUWA_WORK:-$(pwd)}"
exec bun test --isolate "$@"
