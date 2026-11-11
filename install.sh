#!/usr/bin/env bash
# pi-nuwa v2 安装器：只装 omp 扩展与 skill，不装 CLI、不依赖 sapper/python。
#
# 退出码：0 成功 / 1 依赖缺失 / 2 参数错误 / 3 回滚失败
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAPPER_HOME="${SAPPER_HOME:-$HOME/sapper-lab}"
NUWA_MIN_OMP="18.16.0"
KEEP_LEGACY=0

say() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit "${2:-1}"; }

if [[ -n "${PI_AGENT_HOME:-}" ]]; then
  AGENT_HOME="$PI_AGENT_HOME"
elif [[ -d "$HOME/.omp/agent" ]]; then
  AGENT_HOME="$HOME/.omp/agent"
else
  AGENT_HOME="$HOME/.pi/agent"
fi
EXT_DIR="$AGENT_HOME/extensions/nuwa-omp"

# ---------------------------------------------------------------- 回滚
if [[ "${1:-}" == "--rollback" ]]; then
  BAK=""
  while IFS= read -r -d '' cand; do BAK="$cand"; break; done \
    < <(find -L "$AGENT_HOME/extensions" -maxdepth 1 -name 'nuwa-omp.bak-*' -print0 2>/dev/null | sort -zr)
  [[ -n "$BAK" ]] || die "没有 nuwa-omp 备份可回滚" 3
  rm -rf "$EXT_DIR"
  cp -R "$BAK" "$EXT_DIR"
  # 恢复被退役的 v1 扩展（最近一份）
  RET=""
  while IFS= read -r -d '' cand; do RET="$cand"; break; done \
    < <(find -L "$AGENT_HOME/extensions" -maxdepth 1 -name 'nuwa-loop.retired-*' -print0 2>/dev/null | sort -zr)
  if [[ -n "$RET" ]]; then
    rm -rf "$AGENT_HOME/extensions/nuwa-loop"
    mv "$RET" "$AGENT_HOME/extensions/nuwa-loop"
    say "已恢复 $(basename "$RET") -> nuwa-loop"
  fi
  say "已回滚 nuwa-omp 到 $(basename "$BAK")"
  exit 0
fi

case "${1:-}" in
  -h|--help)
    cat <<'EOF'
用法: ./install.sh [--keep-legacy] [--rollback]
  --keep-legacy  保留旧的 $SAPPER_HOME/bin/nuwa（默认改名为 nuwa.legacy）
  --rollback     恢复最近一次安装前的 nuwa-omp 扩展
EOF
    exit 0
    ;;
  --keep-legacy) KEEP_LEGACY=1 ;;
  "") ;;
  *) die "未知参数: $1（--help 查看用法）" 2 ;;
esac

# ---------------------------------------------------------------- 依赖闸门
command -v omp >/dev/null 2>&1 || die "未找到 omp；本工具必须在 omp 会话里运行" 1
OMP_VER="$(omp --version 2>/dev/null | sed -E 's#^omp/?v?##; s# .*##' || true)"
if [[ -n "$OMP_VER" ]] && [[ "$(printf '%s\n%s\n' "$NUWA_MIN_OMP" "$OMP_VER" | sort -V | head -1)" != "$NUWA_MIN_OMP" ]]; then
  say "警告: omp $OMP_VER 低于验证版本 $NUWA_MIN_OMP"
fi
say "omp: ${OMP_VER:-unknown}"

[[ -f "$REPO_DIR/omp/nuwa.ts" ]] || die "仓库缺少 omp/nuwa.ts" 1
[[ -f "$REPO_DIR/skills/nuwa-pentest/SKILL.md" ]] || die "仓库缺少 skills/nuwa-pentest/SKILL.md" 1

command -v sqlite3 >/dev/null 2>&1 || say "提示: 未找到 sqlite3，nuwa_kb 将不可用（其余功能正常）"

# ---------------------------------------------------------------- 1. 扩展
say "[1/4] agent home = $AGENT_HOME"
mkdir -p "$AGENT_HOME/extensions" "$AGENT_HOME/cache"

if [[ -d "$EXT_DIR" ]]; then
  BAK="$EXT_DIR.bak-$(date +%Y%m%dT%H%M%S)"
  cp -R "$EXT_DIR" "$BAK"
  say "  已备份到 $(basename "$BAK")"
  find -L "$AGENT_HOME/extensions" -maxdepth 1 -name 'nuwa-omp.bak-*' -print0 \
    | sort -z -r | tail -z -n +6 | xargs -0 -r rm -rf --
fi
rm -rf "$EXT_DIR"
mkdir -p "$EXT_DIR"
cp "$REPO_DIR/omp/nuwa.ts" "$EXT_DIR/index.ts" || die "扩展复制失败" 1
say "  已安装 nuwa-omp（11 个 nuwa_* 工具）"

# v1 的 nuwa-loop 会与新运行时抢 session_stop/tool_call；默认退役，避免双跑。
if [[ -d "$AGENT_HOME/extensions/nuwa-loop" ]]; then
  RET="$AGENT_HOME/extensions/nuwa-loop.retired-$(date +%Y%m%dT%H%M%S)"
  mv "$AGENT_HOME/extensions/nuwa-loop" "$RET"
  say "  已退役 nuwa-loop -> $(basename "$RET")"
fi

# ---------------------------------------------------------------- 2. skill
say "[2/4] 安装 nuwa-pentest skill"
mkdir -p "$AGENT_HOME/skills" "$HOME/.claude/skills"
rm -rf "$AGENT_HOME/skills/nuwa-pentest"
cp -R "$REPO_DIR/skills/nuwa-pentest" "$AGENT_HOME/skills/nuwa-pentest"
if [[ -e "$HOME/.claude/skills/nuwa-pentest" && ! -L "$HOME/.claude/skills/nuwa-pentest" ]]; then
  mv "$HOME/.claude/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest.bak-$(date +%s)"
fi
ln -sfn "$AGENT_HOME/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest"
say "  $AGENT_HOME/skills/nuwa-pentest"

# ---------------------------------------------------------------- 3. 旧入口退场
say "[3/4] 处理旧 CLI 入口"
if [[ -x "$SAPPER_HOME/bin/nuwa" && "$KEEP_LEGACY" -eq 0 ]]; then
  mv "$SAPPER_HOME/bin/nuwa" "$SAPPER_HOME/bin/nuwa.legacy"
  say "  已改名 $SAPPER_HOME/bin/nuwa -> nuwa.legacy（--keep-legacy 可保留）"
else
  say "  未发现旧入口或要求保留"
fi

# ---------------------------------------------------------------- 4. 验收
say "[4/4] 验收"
missing=0
for t in nuwa_init nuwa_plan nuwa_frontier nuwa_claim nuwa_commit nuwa_flag nuwa_complete nuwa_status nuwa_report nuwa_stop nuwa_kb; do
  grep -q "name: \"$t\"" "$EXT_DIR/index.ts" || { say "  缺少工具: $t"; missing=1; }
done
[[ "$missing" -eq 0 ]] || die "扩展自检失败" 1
say "  工具面完整"

cat <<EOF

下一步（必须在 omp 会话里）：
  1. 重启 omp 或 /reload 扩展
  2. 在项目目录里说：女娲模式，打 http://TARGET:PORT
     或直接调用：nuwa_init(target="http://TARGET:PORT", mode="ctf")
  3. 之后由 session_stop 自动续跑；用 nuwa_status 看板，nuwa_report 出报告

配置（可选）：
  NUWA_MAX_TURNS=200 NUWA_MAX_MINUTES=480 NUWA_MAX_TOKENS=4000000
  NUWA_CLAIM_TTL=900 NUWA_MAX_BATCH=4 NUWA_KB_DB=/data/nuwa-kb/kb.db
  NUWA_SCANNER_GUARD=1 NUWA_REQUIRE_FUJIANG=1 NUWA_LOOP=0（关续跑）

回滚：$0 --rollback
EOF
