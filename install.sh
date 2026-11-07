#!/usr/bin/env bash
# pi-nuwa 安装器：把扩展、skill、入口脚本放到 agent 会加载的位置。
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAPPER_HOME="${SAPPER_HOME:-$HOME/sapper-lab}"

# agent 目录：omp 优先，其次 pi
if [[ -n "${PI_AGENT_HOME:-}" ]]; then
  AGENT_HOME="$PI_AGENT_HOME"
elif [[ -d "$HOME/.omp/agent" ]]; then
  AGENT_HOME="$HOME/.omp/agent"
else
  AGENT_HOME="$HOME/.pi/agent"
fi

echo "[1/5] agent home = $AGENT_HOME"
mkdir -p "$AGENT_HOME/extensions" "$AGENT_HOME/cache" "$SAPPER_HOME/bin" "$HOME/.claude/skills"

echo "[2/5] 安装 nuwa-loop 扩展"
rm -rf "$AGENT_HOME/extensions/nuwa-loop"
cp -R "$REPO_DIR/extensions/nuwa-loop" "$AGENT_HOME/extensions/nuwa-loop"

echo "[3/5] 安装 nuwa-pentest skill"
mkdir -p "$AGENT_HOME/skills"
rm -rf "$AGENT_HOME/skills/nuwa-pentest"
cp -R "$REPO_DIR/skills/nuwa-pentest" "$AGENT_HOME/skills/nuwa-pentest"
# omp 的 skills.enableClaudeUser 会扫 ~/.claude/skills，链接一份保证两个入口都命中
ln -sfn "$AGENT_HOME/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest"

echo "[4/5] 安装 nuwa 入口"
install -m 0755 "$REPO_DIR/bin/nuwa" "$SAPPER_HOME/bin/nuwa"

echo "[5/5] 检查运行环境"
if [[ ! -f "$SAPPER_HOME/env.sh" ]]; then
  cp "$REPO_DIR/env/env.example.sh" "$SAPPER_HOME/env.sh"
  chmod 600 "$SAPPER_HOME/env.sh"
  echo "  已生成 $SAPPER_HOME/env.sh，先填入 GLM_API_KEY / DEEPSEEK_API_KEY"
else
  echo "  沿用已有 $SAPPER_HOME/env.sh"
fi

command -v sapper >/dev/null 2>&1 \
  && echo "  sapper: $(command -v sapper)" \
  || echo "  sapper 未安装：先装 sapper-v2（https://github.com/86cloudyun-afk/sapper-v2）"

echo
echo "验证："
echo "  source $SAPPER_HOME/env.sh && sapper-who"
echo "  \$EDITOR $SAPPER_HOME/env.sh"
echo "  nuwa https://TARGET --no-run"
