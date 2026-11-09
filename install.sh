#!/usr/bin/env bash
# pi-nuwa 安装器：把扩展、skill、入口脚本放到 agent 会加载的位置。
#
# 退出码：0 成功 / 1 依赖缺失 / 2 参数错误 / 3 回滚失败
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAPPER_HOME="${SAPPER_HOME:-$HOME/sapper-lab}"
NUWA_MIN_OMP="18.16.0"

say() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit "${2:-1}"; }

# ---------------------------------------------------------------- 回滚
if [[ "${1:-}" == "--rollback" ]]; then
  if [[ -n "${PI_AGENT_HOME:-}" ]]; then AGENT_HOME="$PI_AGENT_HOME"
  elif [[ -d "$HOME/.omp/agent" ]]; then AGENT_HOME="$HOME/.omp/agent"
  else AGENT_HOME="$HOME/.pi/agent"; fi
  BAK="$(ls -dt "$AGENT_HOME"/extensions/nuwa-loop.bak-* 2>/dev/null | head -1)"
  [[ -n "$BAK" ]] || die "没有可回滚的备份" 3
  rm -rf "$AGENT_HOME/extensions/nuwa-loop"
  cp -R "$BAK" "$AGENT_HOME/extensions/nuwa-loop"
  say "已回滚到 $(basename "$BAK")"
  exit 0
fi

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && {
  cat <<'EOF'
用法: ./install.sh [--rollback]
  --rollback   恢复最近一次安装前的扩展备份
EOF
  exit 0
}

# ---------------------------------------------------------------- 依赖闸门（P0-0.5）
command -v sapper >/dev/null 2>&1 || {
  printf '[install] ERROR: sapper 未安装。先装 sapper-v2: https://github.com/86cloudyun-afk/sapper-v2\n' >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || die "python3 未安装" 1
command -v curl >/dev/null 2>&1 || die "curl 未安装" 1

if command -v omp >/dev/null 2>&1; then
  OMP_VER="$(omp --version 2>/dev/null | sed -E 's#^omp/?v?##; s# .*##')"
  if [[ -n "$OMP_VER" ]] && [[ "$(printf '%s\n%s\n' "$NUWA_MIN_OMP" "$OMP_VER" | sort -V | head -1)" != "$NUWA_MIN_OMP" ]]; then
    say "警告: omp $OMP_VER 低于验证版本 $NUWA_MIN_OMP，行为可能漂移"
  fi
  say "omp: $OMP_VER"
else
  say "警告: 未找到 omp，扩展只有 pi 会加载"
fi

# ---------------------------------------------------------------- agent 目录
if [[ -n "${PI_AGENT_HOME:-}" ]]; then
  AGENT_HOME="$PI_AGENT_HOME"
elif [[ -d "$HOME/.omp/agent" ]]; then
  AGENT_HOME="$HOME/.omp/agent"
else
  AGENT_HOME="$HOME/.pi/agent"
fi

say "[1/6] agent home = $AGENT_HOME"
mkdir -p "$AGENT_HOME/extensions" "$AGENT_HOME/cache" "$SAPPER_HOME/bin" "$HOME/.claude/skills"

# ---------------------------------------------------------------- 扩展（带备份）
say "[2/6] 安装 nuwa-loop 扩展"
if [[ -d "$AGENT_HOME/extensions/nuwa-loop" ]]; then
  BAK="$AGENT_HOME/extensions/nuwa-loop.bak-$(date +%Y%m%dT%H%M%S)"
  cp -R "$AGENT_HOME/extensions/nuwa-loop" "$BAK"
  say "  已备份到 $(basename "$BAK")"
  # 只保留最近 5 份
  ls -dt "$AGENT_HOME"/extensions/nuwa-loop.bak-* 2>/dev/null | tail -n +6 | xargs -r rm -rf
fi
rm -rf "$AGENT_HOME/extensions/nuwa-loop"
cp -R "$REPO_DIR/extensions/nuwa-loop" "$AGENT_HOME/extensions/nuwa-loop"

# ---------------------------------------------------------------- skill
say "[3/6] 安装 nuwa-pentest skill"
mkdir -p "$AGENT_HOME/skills"
rm -rf "$AGENT_HOME/skills/nuwa-pentest"
cp -R "$REPO_DIR/skills/nuwa-pentest" "$AGENT_HOME/skills/nuwa-pentest"
if [[ -e "$HOME/.claude/skills/nuwa-pentest" && ! -L "$HOME/.claude/skills/nuwa-pentest" ]]; then
  mv "$HOME/.claude/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest.bak-$(date +%s)"
fi
ln -sfn "$AGENT_HOME/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest"

# ---------------------------------------------------------------- 入口
say "[4/6] 安装 nuwa 入口与 Python 包"
install -m 0755 "$REPO_DIR/bin/nuwa" "$SAPPER_HOME/bin/nuwa"

# 执行层提交闸门：真实 sapper 链到 sapper.real，sapper 指向 guard。
TOKEN_FILE="$SAPPER_HOME/.submit_token"
if [[ ! -s "$TOKEN_FILE" ]]; then
  python3 -c 'import secrets; print(secrets.token_hex(20))' >"$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
fi
_guard="$(readlink -f "$REPO_DIR/bin/sapper-guard")"
_real_sapper="$(readlink -f "$(command -v sapper || true)" 2>/dev/null || true)"
if [[ -f "$SAPPER_HOME/bin/sapper" ]] && grep -q 'sapper-guard' "$SAPPER_HOME/bin/sapper" 2>/dev/null; then
  install -m 0755 "$REPO_DIR/bin/sapper-guard" "$SAPPER_HOME/bin/sapper"
  echo "updated: sapper guard -> $SAPPER_HOME/bin/sapper"
elif [[ -n "$_real_sapper" && "$_real_sapper" != "$_guard" ]]; then
  if [[ "$_real_sapper" == "$SAPPER_HOME/bin/sapper" ]]; then
    mv "$SAPPER_HOME/bin/sapper" "$SAPPER_HOME/bin/sapper.real"
  else
    ln -sfn "$_real_sapper" "$SAPPER_HOME/bin/sapper.real"
  fi
  install -m 0755 "$REPO_DIR/bin/sapper-guard" "$SAPPER_HOME/bin/sapper"
  echo "installed: sapper guard -> $SAPPER_HOME/bin/sapper (real: $_real_sapper)"
fi
install -m 0755 "$REPO_DIR/bin/nuwa-soak-night.sh" "$SAPPER_HOME/bin/nuwa-soak-night"
mkdir -p "$SAPPER_HOME/nuwa"
if cp -R "$REPO_DIR/nuwa/." "$SAPPER_HOME/nuwa/"; then
  if ! git -C "$REPO_DIR" rev-parse HEAD > "$SAPPER_HOME/COMMIT" 2>/dev/null; then
    rm -f "$SAPPER_HOME/COMMIT" || exit 1
  fi
fi

# ---------------------------------------------------------------- 执行引擎（P0-0.6）
say "[5/6] 配置 SAPPER_BIN 执行引擎"
ENGINE="$SAPPER_HOME/bin/omp-claude"
if [[ ! -x "$ENGINE" ]]; then
  cat >"$ENGINE" <<'EOF'
#!/usr/bin/env bash
# omp-claude — 让 sapper 的 `claude` 调用面落到 omp 上。
# sapper dispatch 会把 prompt 通过 stdin/参数传给该引擎；这里保持与原 claude CLI 兼容。
set -uo pipefail
exec omp --print --dangerously-skip-permissions "$@" 2>/dev/null || exec omp -p "$@"
EOF
  chmod 0755 "$ENGINE"
  say "  已生成 $ENGINE"
else
  say "  沿用已有 $ENGINE"
fi

# ---------------------------------------------------------------- env
say "[6/6] 检查运行环境"
if [[ ! -f "$SAPPER_HOME/env.sh" ]]; then
  cp "$REPO_DIR/env/env.example.sh" "$SAPPER_HOME/env.sh"
  chmod 600 "$SAPPER_HOME/env.sh"
  say "  已生成 $SAPPER_HOME/env.sh，先填入 GLM_API_KEY / DEEPSEEK_API_KEY"
else
  say "  沿用已有 $SAPPER_HOME/env.sh"
fi

say ""
say "验证："
say "  source $SAPPER_HOME/env.sh && sapper-who"
say "  \$EDITOR $SAPPER_HOME/env.sh"
say "  nuwa https://TARGET --no-run"
say "  nuwa https://TARGET --no-view --minutes 2   # 冒烟"
say "回滚：$0 --rollback"
