#!/usr/bin/env bash
# pi-nuwa v6.0 安装器：一键部署 omp 原生扩展全模块、独立核心与跨宿主 MCP Server (nuwa-mcp)、
# 随仓便携知识库 kb.db、合规子代理模板（fujiang + nuwa-verifier）、nuwa-pentest skill 与无头守护器 nuwa-autonomous。
#
# 退出码：0 成功 / 1 依赖或自检缺失 / 2 参数错误 / 3 回滚失败
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAPPER_HOME="${SAPPER_HOME:-$HOME/sapper-lab}"
NUWA_MIN_OMP="18.16.0"
KEEP_LEGACY=0
FORCE_AGENTS=0
CLEAN_KB=0
DO_ROLLBACK=0

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

# 扩展子模块清单（主入口 omp/nuwa.ts 复制为 index.ts，其余保持原名）
EXT_MODULES=(
  "omp/types.ts"
  "omp/storage.ts"
  "omp/sqlite-store.ts"
  "omp/graph.ts"
  "omp/graph-planner.ts"
  "omp/graph-commands.ts"
  "omp/ui.ts"
  "omp/ui-native.ts"
  "omp/autoexec.ts"
  "omp/auto-loops.ts"
  "omp/belief-search.ts"
  "omp/calibration.ts"
  "omp/traffic-workbench.ts"
  "omp/hybrid-audit.ts"
  "omp/browser-recon.ts"
  "omp/scope.ts"
  "omp/evidence.ts"
  "omp/profiles.ts"
  "omp/reincarnate.ts"
  "omp/lineage.ts"
  "omp/kb.ts"
  "omp/session-vault.ts"
  "omp/auth-diff.ts"
  "omp/verifier-gate.ts"
  "omp/sandbox.ts"
  "omp/oob.ts"
  "omp/hypothesis.ts"
  "omp/reporting.ts"
  "omp/env.d.ts"
)

KB_FILES=(
  "kb/schema.sql"
  "kb/seed-cards.json"
  "kb/seed-cves.json"
  "kb/seed-techniques.json"
  "kb/build-kb.ts"
)

AGENT_TEMPLATES=(
  "fujiang.md"
  "nuwa-verifier.md"
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      cat <<'EOF'
用法: ./install.sh [--keep-legacy] [--force-agents] [--clean-kb] [--rollback]
  --keep-legacy   保留旧的 $SAPPER_HOME/bin/nuwa（默认改名为 nuwa.legacy）
  --force-agents  强制用仓库最新模板覆盖已存在的 $AGENT_HOME/agents/{fujiang,nuwa-verifier}.md
  --clean-kb      删除已有 $AGENT_HOME/nuwa-kb/kb.db 并从随仓种子全新构建纯净知识库
  --rollback      恢复最近一次安装前的 nuwa-omp 扩展

环境变量:
  PI_AGENT_HOME   指定 omp/pi agent 目录（默认自动探测 ~/.omp/agent 或 ~/.pi/agent）
  NUWA_BIN_DIR    指定 nuwa-autonomous 无头守护器安装目录（默认 ~/.local/bin）
EOF
      exit 0
      ;;
    --keep-legacy) KEEP_LEGACY=1 ;;
    --force-agents) FORCE_AGENTS=1 ;;
    --clean-kb) CLEAN_KB=1 ;;
    --rollback) DO_ROLLBACK=1 ;;
    *) die "未知参数: $1（--help 查看用法）" 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- 回滚
if [[ "$DO_ROLLBACK" -eq 1 ]]; then
  BAK_ROOT="$AGENT_HOME/backups/nuwa-omp"
  BAK=""
  while IFS= read -r -d '' cand; do BAK="$cand"; break; done \
    < <(find -L "$BAK_ROOT" -maxdepth 1 -name 'nuwa-omp.bak-*' -print0 2>/dev/null | sort -zr)
  [[ -n "$BAK" ]] || die "没有 nuwa-omp 备份可回滚" 3
  rm -rf "$EXT_DIR"
  cp -R "$BAK" "$EXT_DIR"
  RET=""
  while IFS= read -r -d '' cand; do RET="$cand"; break; done \
    < <(find -L "$AGENT_HOME/backups" -maxdepth 1 -name 'nuwa-loop.retired-*' -print0 2>/dev/null | sort -zr)
  if [[ -n "$RET" ]]; then
    rm -rf "$AGENT_HOME/extensions/nuwa-loop"
    cp -R "$RET" "$AGENT_HOME/extensions/nuwa-loop"
    say "已恢复 $(basename "$RET") -> nuwa-loop"
  fi
  say "已回滚 nuwa-omp 到 $(basename "$BAK")"
  exit 0
fi

# ---------------------------------------------------------------- 依赖闸门
command -v omp >/dev/null 2>&1 || die "未找到 omp；本工具必须在 omp 会话里运行" 1
command -v bun >/dev/null 2>&1 || die "未找到 bun；v4 知识库构建与扩展自检需要 bun 运行时" 1
OMP_VER="$(omp --version 2>/dev/null | sed -E 's#^omp/?v?##; s# .*##' || true)"
if [[ -n "$OMP_VER" ]] && [[ "$(printf '%s\n%s\n' "$NUWA_MIN_OMP" "$OMP_VER" | sort -V | head -1)" != "$NUWA_MIN_OMP" ]]; then
  say "警告: omp $OMP_VER 低于验证版本 $NUWA_MIN_OMP"
fi
say "omp: ${OMP_VER:-unknown}"

[[ -f "$REPO_DIR/omp/nuwa.ts" ]] || die "仓库缺少 omp/nuwa.ts" 1
for mod in "${EXT_MODULES[@]}"; do
  [[ -f "$REPO_DIR/$mod" ]] || die "仓库缺少 $mod" 1
done
for kbf in "${KB_FILES[@]}"; do
  [[ -f "$REPO_DIR/$kbf" ]] || die "仓库缺少 $kbf" 1
done
for ag in "${AGENT_TEMPLATES[@]}"; do
  [[ -f "$REPO_DIR/agents/$ag" ]] || die "仓库缺少 agents/$ag" 1
done
[[ -f "$REPO_DIR/config/autoexec.example.json" ]] || die "仓库缺少 config/autoexec.example.json" 1
[[ -f "$REPO_DIR/skills/nuwa-pentest/SKILL.md" ]] || die "仓库缺少 skills/nuwa-pentest/SKILL.md" 1
[[ -f "$REPO_DIR/bin/nuwa-autonomous" ]] || die "仓库缺少 bin/nuwa-autonomous" 1
[[ -f "$REPO_DIR/core/protocol.ts" ]] || die "仓库缺少 core/protocol.ts" 1
[[ -f "$REPO_DIR/core/mcp-server.ts" ]] || die "仓库缺少 core/mcp-server.ts" 1
[[ -f "$REPO_DIR/bin/nuwa-mcp" ]] || die "仓库缺少 bin/nuwa-mcp" 1

# 从 omp/nuwa.ts 动态提取 VERSION（单一事实来源）
INSTALLED_VER="$(sed -nE "s/^export[[:space:]]+const[[:space:]]+VERSION[[:space:]]*=[[:space:]]*[\"']([^\"']+)[\"'].*/\1/p" "$REPO_DIR/omp/nuwa.ts" | head -n 1)"
[[ -n "$INSTALLED_VER" ]] || die "无法从 omp/nuwa.ts 提取 VERSION" 1

# ---------------------------------------------------------------- 1. 扩展模块与配置资产
say "[1/5] agent home = $AGENT_HOME"
mkdir -p "$AGENT_HOME/extensions" "$AGENT_HOME/cache"

# 关键：omp 会把 extensions/ 下每个含 index.ts 的目录都当扩展加载。
# 备份与退役目录必须放到 extensions 之外，避免新旧两个 session_stop 抢跑。
BAK_ROOT="$AGENT_HOME/backups/nuwa-omp"
mkdir -p "$BAK_ROOT"
shopt -s nullglob
for stale in "$AGENT_HOME/extensions"/nuwa-omp.bak-* "$AGENT_HOME/extensions"/nuwa-loop.*; do
  [[ -e "$stale" ]] || continue
  mv "$stale" "$BAK_ROOT/" 2>/dev/null || true
  say "  已移出加载目录: $(basename "$stale")"
done
shopt -u nullglob

if [[ -d "$EXT_DIR" ]]; then
  BAK="$BAK_ROOT/nuwa-omp.bak-$(date +%Y%m%dT%H%M%S)"
  cp -R "$EXT_DIR" "$BAK"
  say "  已备份到 $BAK"
  bak_idx=0
  while IFS= read -r -d '' old_bak; do
    bak_idx=$((bak_idx + 1))
    if [[ "$bak_idx" -gt 5 ]]; then
      rm -rf -- "$old_bak"
    fi
  done < <(find "$BAK_ROOT" -maxdepth 1 -name 'nuwa-omp.bak-*' -print0 2>/dev/null | sort -zr)
fi

rm -rf "$EXT_DIR"
mkdir -p "$EXT_DIR/kb" "$EXT_DIR/config"
cp "$REPO_DIR/omp/nuwa.ts" "$EXT_DIR/index.ts" || die "扩展主入口复制失败" 1
for mod in "${EXT_MODULES[@]}"; do
  base="$(basename "$mod")"
  cp "$REPO_DIR/$mod" "$EXT_DIR/$base" || die "$base 复制失败" 1
done
for kbf in "${KB_FILES[@]}"; do
  cp "$REPO_DIR/$kbf" "$EXT_DIR/kb/$(basename "$kbf")" || die "$kbf 复制失败" 1
done
cp "$REPO_DIR/config/autoexec.example.json" "$EXT_DIR/config/autoexec.example.json" || die "autoexec.example.json 复制失败" 1
say "  已安装 nuwa-omp v${INSTALLED_VER}（index.ts + ${#EXT_MODULES[@]} 个模块 + kb/ + config/，12 个 nuwa_* 工具）"

# 部署 v6.0 独立核心协议层与跨宿主 MCP Server ($AGENT_HOME/nuwa-core)
CORE_DIR="$AGENT_HOME/nuwa-core"
rm -rf "$CORE_DIR"
mkdir -p "$CORE_DIR/core" "$CORE_DIR/bin"
cp "$REPO_DIR/core/protocol.ts" "$CORE_DIR/core/protocol.ts" || die "core/protocol.ts 复制失败" 1
cp "$REPO_DIR/core/mcp-server.ts" "$CORE_DIR/core/mcp-server.ts" || die "core/mcp-server.ts 复制失败" 1
cp "$REPO_DIR/bin/nuwa-mcp" "$CORE_DIR/bin/nuwa-mcp" || die "bin/nuwa-mcp 复制失败" 1
chmod +x "$CORE_DIR/bin/nuwa-mcp"
ln -sfn "$EXT_DIR" "$CORE_DIR/omp"
ln -sfn "$EXT_DIR/index.ts" "$EXT_DIR/nuwa.ts"
say "  已部署独立核心与跨宿主 MCP Server: $CORE_DIR/bin/nuwa-mcp"

# v1 的 nuwa-loop 会与新运行时抢 session_stop/tool_call；默认退役，避免双跑。
if [[ -d "$AGENT_HOME/extensions/nuwa-loop" ]]; then
  mkdir -p "$AGENT_HOME/backups"
  RET="$AGENT_HOME/backups/nuwa-loop.retired-$(date +%Y%m%dT%H%M%S)"
  mv "$AGENT_HOME/extensions/nuwa-loop" "$RET"
  say "  已退役 nuwa-loop -> $RET"
fi

# ---------------------------------------------------------------- 2. 便携知识库 + skill + 子代理模板
say "[2/5] 构建便携知识库、安装 skill 与合规子代理模板"
KB_OUT="$AGENT_HOME/nuwa-kb/kb.db"
mkdir -p "$(dirname "$KB_OUT")"
if [[ "$CLEAN_KB" -eq 1 ]]; then
  rm -f "$KB_OUT" "${KB_OUT}-shm" "${KB_OUT}-wal"
  say "  已按 --clean-kb 清理旧知识库，准备全新构建"
fi
KB_BUILD_OUT="$(env -u BUN_OPTIONS bun "$EXT_DIR/kb/build-kb.ts" --out "$KB_OUT" 2>&1)" || die "便携知识库构建失败: $KB_BUILD_OUT" 1
rm -f "${KB_OUT}-shm" "${KB_OUT}-wal"
[[ -s "$KB_OUT" ]] || die "便携知识库未成功生成: $KB_OUT" 1
say "  知识库就绪: $KB_OUT"

mkdir -p "$AGENT_HOME/skills"
rm -rf "$AGENT_HOME/skills/nuwa-pentest"
cp -R "$REPO_DIR/skills/nuwa-pentest" "$AGENT_HOME/skills/nuwa-pentest"
if [[ -z "${PI_AGENT_HOME:-}" ]]; then
  if mkdir -p "$HOME/.claude/skills" 2>/dev/null && [[ -w "$HOME/.claude/skills" ]]; then
    if [[ -e "$HOME/.claude/skills/nuwa-pentest" && ! -L "$HOME/.claude/skills/nuwa-pentest" ]]; then
      mv "$HOME/.claude/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest.bak-$(date +%s)"
    fi
    ln -sfn "$AGENT_HOME/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest"
  fi
fi
say "  skill: $AGENT_HOME/skills/nuwa-pentest"

mkdir -p "$AGENT_HOME/agents"
for ag in "${AGENT_TEMPLATES[@]}"; do
  dest="$AGENT_HOME/agents/$ag"
  if [[ -f "$dest" && "$FORCE_AGENTS" -eq 0 ]]; then
    say "  保留已有子代理定义: ${dest}（加 --force-agents 可覆盖）"
  else
    cp "$REPO_DIR/agents/$ag" "$dest" || die "安装子代理模板失败: ${ag}" 1
    say "  已安装子代理模板: ${dest}"
  fi
done

# ---------------------------------------------------------------- 3. 无头守护器 nuwa-autonomous
say "[3/5] 安装外层无头守护器 nuwa-autonomous"
BIN_DIR="${NUWA_BIN_DIR:-$HOME/.local/bin}"
BIN_TARGET="$BIN_DIR/nuwa-autonomous"
BIN_INSTALLED=0
if [[ -n "${NUWA_BIN_DIR:-}" ]]; then
  mkdir -p "$BIN_DIR" || die "无法创建 NUWA_BIN_DIR: $BIN_DIR" 1
  cp "$REPO_DIR/bin/nuwa-autonomous" "$BIN_TARGET" || die "nuwa-autonomous 复制失败" 1
  chmod +x "$BIN_TARGET"
  BIN_INSTALLED=1
  say "  $BIN_TARGET"
else
  if ( [[ -d "$BIN_DIR" && -w "$BIN_DIR" ]] ) || ( [[ ! -e "$BIN_DIR" ]] && mkdir -p "$BIN_DIR" 2>/dev/null && [[ -w "$BIN_DIR" ]] ); then
    cp "$REPO_DIR/bin/nuwa-autonomous" "$BIN_TARGET" || die "nuwa-autonomous 复制失败" 1
    chmod +x "$BIN_TARGET"
    BIN_INSTALLED=1
    say "  $BIN_TARGET"
  else
  say "  已跳过安装 nuwa-autonomous（${BIN_DIR} 不可写；可通过 NUWA_BIN_DIR 指定可写目录）"
  fi
fi

if [[ "$BIN_INSTALLED" -eq 1 ]]; then
  MCP_BIN_TARGET="$BIN_DIR/nuwa-mcp"
  cat > "$MCP_BIN_TARGET" <<EOF
#!/usr/bin/env bash
exec "$CORE_DIR/bin/nuwa-mcp" "\$@"
EOF
  chmod +x "$MCP_BIN_TARGET"
  say "  $MCP_BIN_TARGET -> $CORE_DIR/bin/nuwa-mcp"
fi

# ---------------------------------------------------------------- 4. 旧入口退场
say "[4/5] 处理旧 CLI 入口"
if [[ -x "$SAPPER_HOME/bin/nuwa" && "$KEEP_LEGACY" -eq 0 ]]; then
  mv "$SAPPER_HOME/bin/nuwa" "$SAPPER_HOME/bin/nuwa.legacy"
  say "  已改名 $SAPPER_HOME/bin/nuwa -> nuwa.legacy（--keep-legacy 可保留）"
else
  say "  未发现旧入口或要求保留"
fi

# ---------------------------------------------------------------- 5. 验收
say "[5/5] 验收"
missing=0
for t in nuwa_init nuwa_plan nuwa_frontier nuwa_claim nuwa_commit nuwa_flag nuwa_complete nuwa_status nuwa_report nuwa_expand nuwa_stop nuwa_kb; do
  grep -q "name: \"$t\"" "$EXT_DIR/index.ts" || { say "  缺少工具: $t"; missing=1; }
done
[[ "$missing" -eq 0 ]] || die "扩展自检失败" 1
[[ -f "$EXT_DIR/index.ts" ]] || die "扩展缺少 index.ts" 1
for mod in "${EXT_MODULES[@]}"; do
  base="$(basename "$mod")"
  [[ -f "$EXT_DIR/$base" ]] || die "扩展缺少 $base" 1
done
for ag in "${AGENT_TEMPLATES[@]}"; do
  [[ -f "$AGENT_HOME/agents/$ag" ]] || die "缺少子代理模板: $AGENT_HOME/agents/$ag" 1
done
if [[ "$BIN_INSTALLED" -eq 1 ]]; then
  [[ -x "$BIN_TARGET" ]] || die "守护器缺少可执行权限: $BIN_TARGET" 1
  [[ -x "$BIN_DIR/nuwa-mcp" ]] || die "MCP 入口缺少可执行权限: $BIN_DIR/nuwa-mcp" 1
fi
MCP_SMOKE_VER="$(PI_AGENT_HOME="$AGENT_HOME" env -u BUN_OPTIONS "$CORE_DIR/bin/nuwa-mcp" --version 2>&1)" || die "nuwa-mcp 自检失败: $MCP_SMOKE_VER" 1
[[ "$MCP_SMOKE_VER" == *"$INSTALLED_VER"* ]] || die "nuwa-mcp 版本不匹配: $MCP_SMOKE_VER != $INSTALLED_VER" 1
say "  MCP Server 自检: $MCP_SMOKE_VER"
extra="$(find -L "$AGENT_HOME/extensions" -maxdepth 1 -type d -name 'nuwa-*' ! -name 'nuwa-omp' -print 2>/dev/null | wc -l | tr -d ' ')"
[[ "$extra" -eq 0 ]] || die "extensions/ 下仍有 $extra 个旧 nuwa 扩展，会与 nuwa-omp 抢 session_stop；先移出再装" 1

# 显式清理历史冒烟残留产物与 SQLite WAL/SHM 伴生文件，确保真实 kb.db 纯净且单文件冷启动可读
rm -f "$AGENT_HOME/cache/nuwa-current.d/install-smoke"* "${KB_OUT}-shm" "${KB_OUT}-wal" 2>/dev/null || true

# 运行时加载冒烟（复刻 omp 异步 Bun.plugin，使用独立临时会话目录避免污染真实 cache/kb.db，同时校验无 -shm/-wal 下的真实 kb.db 命中与血缘越界拦截）
SMOKE_OUT="$(
  REAL_KB_OUT="$KB_OUT" EXT_DIR="$EXT_DIR" EXPECT_VER="$INSTALLED_VER" env -u BUN_OPTIONS bun -e '
    import { existsSync, mkdtempSync, rmSync } from "node:fs";
    import { tmpdir } from "node:os";
    import { join } from "node:path";
    const extDir = process.env.EXT_DIR!;
    const realKbOut = process.env.REAL_KB_OUT!;
    const escaped = extDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const transpiler = new Bun.Transpiler({ loader: "ts" });
    Bun.plugin({
      name: "nuwa-install-async-smoke",
      setup(build) {
        build.onLoad({ filter: new RegExp(`^${escaped}/.*\\.ts$`) }, async (args) => {
          const text = await Bun.file(args.path).text();
          return { contents: transpiler.transformSync(text), loader: "js" };
        });
      },
    });
    const smokeHome = mkdtempSync(join(tmpdir(), "nuwa-install-smoke-home-"));
    const dir = mkdtempSync(join(tmpdir(), "nuwa-install-smoke-proj-"));
    process.env.PI_AGENT_HOME = smokeHome;
    try {
      const mod = await import(`${extDir}/index.ts`);
      if (mod.VERSION !== process.env.EXPECT_VER) {
        throw new Error(`VERSION mismatch: ${mod.VERSION} != ${process.env.EXPECT_VER}`);
      }
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
      if (tools.size !== 12) {
        throw new Error(`Expected 12 tools, got ${tools.size}`);
      }
      const ctx: any = {
        cwd: dir,
        agent: { kind: "main", id: "smoke-main-0" },
        sessionManager: { getSessionId: () => "install-smoke-main" },
      };

      // 1) 在无 -shm/-wal 伴生文件冷启动状态下，直接只读查询刚部署的真实 kb.db 验证 100% 命中且不生成伴生写文件
      process.env.NUWA_KB_DB = realKbOut;
      const kbSpring = await tools.get("nuwa_kb").execute("1", { query: "spring", kind: "auto", limit: 3 }, undefined, undefined, ctx);
      const kbSpringText = kbSpring?.content?.[0]?.text ?? "";
      if (!kbSpringText || kbSpringText.includes("未命中") || kbSpringText.includes("ERROR:")) {
        throw new Error(`nuwa_kb(spring) failed: ${kbSpringText}`);
      }
      const kbCve = await tools.get("nuwa_kb").execute("2", { query: "CVE-2021-44228", kind: "auto", limit: 3 }, undefined, undefined, ctx);
      const kbCveText = kbCve?.content?.[0]?.text ?? "";
      if (!kbCveText.includes("CVE-2021-44228") || kbCveText.includes("未命中") || kbCveText.includes("ERROR:")) {
        throw new Error(`nuwa_kb(CVE-2021-44228) failed: ${kbCveText}`);
      }
      if (existsSync(`${realKbOut}-shm`) || existsSync(`${realKbOut}-wal`)) {
        throw new Error("readonly nuwa_kb unexpectedly created -shm/-wal sidecar files");
      }

      // 2) 切换至隔离临时 NUWA_KB_DB 验证 nuwa_init / nuwa_status 与子代理血缘越界拦截，绝不污染真实 kb.db
      process.env.NUWA_KB_DB = join(smokeHome, "nuwa-kb", "kb.db");
      const r1 = await tools.get("nuwa_init").execute("3", { target: "http://127.0.0.1:18080", mode: "ctf", root: dir }, undefined, undefined, ctx);
      const t1 = r1?.content?.[0]?.text ?? "";
      if (!t1.includes("女娲已上膛") || t1.includes("ERROR:")) {
        throw new Error(`nuwa_init failed: ${t1}`);
      }
      const r2 = await tools.get("nuwa_status").execute("4", { root: dir }, undefined, undefined, ctx);
      const t2 = r2?.content?.[0]?.text ?? "";
      if (!t2.includes("phase=recon") || !t2.includes("kb=ready") || t2.includes("ERROR:")) {
        throw new Error(`nuwa_status failed: ${t2}`);
      }

      // 绑定子代理派生并验证不同 subSessionId 的子代理越界请求被 N-007 精准拦截
      const onSpawn = hooks.get("before_subagent_spawn")?.[0];
      if (onSpawn) {
        onSpawn({ agent: "fujiang", task: "smoke" }, ctx);
      }
      const subCtx: any = {
        cwd: dir,
        agent: { kind: "sub", id: "0-fujiang", name: "fujiang", parentId: "smoke-main-0", depth: 1 },
        sessionManager: { getSessionId: () => "install-smoke-sub-isolated" },
      };
      const onToolCall = hooks.get("tool_call")?.[0];
      if (!onToolCall) throw new Error("tool_call hook missing");
      const blockVerdict = onToolCall({ toolName: "read", input: { path: "http://evil.outside.invalid/leak" } }, subCtx);
      if (!blockVerdict?.block || !String(blockVerdict.reason ?? "").includes("N-007")) {
        throw new Error(`subagent lineage scope guard failed: ${JSON.stringify(blockVerdict)}`);
      }
      console.log(`SMOKE_OK ${mod.VERSION} tools=${tools.size}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(smokeHome, { recursive: true, force: true });
    }
  ' 2>&1
)" || die "扩展运行时异步加载冒烟失败: $SMOKE_OUT" 1
say "  运行时冒烟: $SMOKE_OUT"

# 验证删除 -shm/-wal 后守护器 doctor 能准确读取真实知识库各表记录数
rm -f "${KB_OUT}-shm" "${KB_OUT}-wal"
DOCTOR_CHECK_BIN="$REPO_DIR/bin/nuwa-autonomous"
if [[ "$BIN_INSTALLED" -eq 1 ]]; then
  DOCTOR_CHECK_BIN="$BIN_TARGET"
fi
DOCTOR_KB_SUMMARY="$(
  DOCTOR_BIN="$DOCTOR_CHECK_BIN" TARGET_HOME="$AGENT_HOME" TARGET_KB="$KB_OUT" env -u BUN_OPTIONS bun -e '
    import { spawnSync } from "node:child_process";
    const res = spawnSync(process.execPath, [process.env.DOCTOR_BIN!, "doctor", "--json", "--agent-home", process.env.TARGET_HOME!], {
      encoding: "utf8",
      env: { ...process.env, BUN_OPTIONS: undefined, NUWA_KB_DB: process.env.TARGET_KB! },
    });
    const payload = JSON.parse((res.stdout || "").trim() || "{}");
    const kb = payload?.checks?.kb;
    if (!kb?.ok || !(Number(kb?.totalRecords ?? 0) > 300) || !(Number(kb?.counts?.card ?? 0) >= 36)) {
      throw new Error(`doctor KB check failed: ${JSON.stringify(kb)}`);
    }
    console.log(`ok totalRecords=${kb.totalRecords} card=${kb.counts.card} cve=${kb.counts.cve}`);
  ' 2>&1
)" || die "无伴生文件状态下 doctor 知识库验收失败: $DOCTOR_KB_SUMMARY" 1
say "  doctor 知识库验收: $DOCTOR_KB_SUMMARY"

MOD_TOTAL=$(( ${#EXT_MODULES[@]} + 1 ))
say "  工具面完整 · 模块齐备（${MOD_TOTAL}/${MOD_TOTAL}） · 便携知识库就绪 · 单一扩展（无旧版共存）"
say "installed version = ${INSTALLED_VER}"

cat <<EOF

下一步（omp 会话内或无头守护）：
  1. 重启 omp 或 /reload 扩展，执行 /nuwa doctor 或 nuwa-autonomous doctor 体检
  2. 交互式开工：在项目目录执行 /nuwa 打 http://TARGET:PORT（支持 /nuwa session 与 /nuwa spa）
     多领域支持：nuwa_init(target="...", mode="ctf|pentest|audit|coding|ops")
  3. 长跑无头守护（跨世代自动换血 + 模型路由 + 容器沙盒）：
     nuwa-autonomous --target http://TARGET:PORT --mode pentest --sandbox docker --max-generations 20

回滚：$0 --rollback
EOF
