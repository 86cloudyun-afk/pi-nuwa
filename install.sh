#!/usr/bin/env bash
# pi-nuwa v3 安装器：安装 omp 原生扩展（9 模块）、nuwa-pentest skill 与无头守护器 nuwa-autonomous。
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

# 扩展子模块清单（主入口 omp/nuwa.ts 复制为 index.ts，其余保持原名）
EXT_MODULES=(
  "omp/types.ts"
  "omp/ui.ts"
  "omp/ui-native.ts"
  "omp/autoexec.ts"
  "omp/scope.ts"
  "omp/evidence.ts"
  "omp/profiles.ts"
  "omp/reincarnate.ts"
)

# ---------------------------------------------------------------- 回滚
if [[ "${1:-}" == "--rollback" ]]; then
  BAK_ROOT="$AGENT_HOME/backups/nuwa-omp"
  BAK=""
  while IFS= read -r -d '' cand; do BAK="$cand"; break; done \
    < <(find -L "$BAK_ROOT" -maxdepth 1 -name 'nuwa-omp.bak-*' -print0 2>/dev/null | sort -zr)
  [[ -n "$BAK" ]] || die "没有 nuwa-omp 备份可回滚" 3
  rm -rf "$EXT_DIR"
  cp -R "$BAK" "$EXT_DIR"
  # 恢复被退役的 v1 扩展（最近一份）
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

case "${1:-}" in
  -h|--help)
    cat <<'EOF'
用法: ./install.sh [--keep-legacy] [--rollback]
  --keep-legacy  保留旧的 $SAPPER_HOME/bin/nuwa（默认改名为 nuwa.legacy）
  --rollback     恢复最近一次安装前的 nuwa-omp 扩展

环境变量:
  PI_AGENT_HOME  指定 omp/pi agent 目录（默认自动探测 ~/.omp/agent 或 ~/.pi/agent）
  NUWA_BIN_DIR   指定 nuwa-autonomous 无头守护器安装目录（默认 ~/.local/bin）
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
for mod in "${EXT_MODULES[@]}"; do
  [[ -f "$REPO_DIR/$mod" ]] || die "仓库缺少 $mod" 1
done
[[ -f "$REPO_DIR/skills/nuwa-pentest/SKILL.md" ]] || die "仓库缺少 skills/nuwa-pentest/SKILL.md" 1
[[ -f "$REPO_DIR/bin/nuwa-autonomous" ]] || die "仓库缺少 bin/nuwa-autonomous" 1

# 从 omp/nuwa.ts 动态提取 VERSION（Issue #9：与代码保持单一事实来源）
INSTALLED_VER="$(sed -nE "s/^export[[:space:]]+const[[:space:]]+VERSION[[:space:]]*=[[:space:]]*[\"']([^\"']+)[\"'].*/\1/p" "$REPO_DIR/omp/nuwa.ts" | head -n 1)"
[[ -n "$INSTALLED_VER" ]] || die "无法从 omp/nuwa.ts 提取 VERSION" 1

command -v sqlite3 >/dev/null 2>&1 || say "提示: 未找到 sqlite3，nuwa_kb 将不可用（其余功能正常）"

# ---------------------------------------------------------------- 1. 扩展
say "[1/5] agent home = $AGENT_HOME"
mkdir -p "$AGENT_HOME/extensions" "$AGENT_HOME/cache"

# 关键：omp 会把 extensions/ 下每个含 index.ts 的目录都当扩展加载。
# 备份与退役目录必须放到 extensions 之外，否则新旧两个 session_stop 同时抢跑，
# 旧版仍按 continue 放行，omp 的 continuation cap（8）耗尽后就会「停下来」。
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
  # 保留最近 5 份备份（跨平台兼容 macOS BSD 与 GNU 工具链）
  bak_idx=0
  while IFS= read -r -d '' old_bak; do
    bak_idx=$((bak_idx + 1))
    if [[ "$bak_idx" -gt 5 ]]; then
      rm -rf -- "$old_bak"
    fi
  done < <(find "$BAK_ROOT" -maxdepth 1 -name 'nuwa-omp.bak-*' -print0 2>/dev/null | sort -zr)
fi

rm -rf "$EXT_DIR"
mkdir -p "$EXT_DIR"
cp "$REPO_DIR/omp/nuwa.ts" "$EXT_DIR/index.ts" || die "扩展主入口复制失败" 1
for mod in "${EXT_MODULES[@]}"; do
  base="$(basename "$mod")"
  cp "$REPO_DIR/$mod" "$EXT_DIR/$base" || die "$base 复制失败" 1
done
say "  已安装 nuwa-omp v${INSTALLED_VER}（index.ts + ${#EXT_MODULES[@]} 个模块，12 个 nuwa_* 工具）"

# v1 的 nuwa-loop 会与新运行时抢 session_stop/tool_call；默认退役，避免双跑。
if [[ -d "$AGENT_HOME/extensions/nuwa-loop" ]]; then
  mkdir -p "$AGENT_HOME/backups"
  RET="$AGENT_HOME/backups/nuwa-loop.retired-$(date +%Y%m%dT%H%M%S)"
  mv "$AGENT_HOME/extensions/nuwa-loop" "$RET"
  say "  已退役 nuwa-loop -> $RET"
fi

# ---------------------------------------------------------------- 2. skill
say "[2/5] 安装 nuwa-pentest skill"
mkdir -p "$AGENT_HOME/skills"
rm -rf "$AGENT_HOME/skills/nuwa-pentest"
cp -R "$REPO_DIR/skills/nuwa-pentest" "$AGENT_HOME/skills/nuwa-pentest"
# 非隔离安装时同步建立 ~/.claude/skills 软链，隔离 PI_AGENT_HOME 测试不污染宿主目录
if [[ -z "${PI_AGENT_HOME:-}" ]]; then
  if mkdir -p "$HOME/.claude/skills" 2>/dev/null && [[ -w "$HOME/.claude/skills" ]]; then
    if [[ -e "$HOME/.claude/skills/nuwa-pentest" && ! -L "$HOME/.claude/skills/nuwa-pentest" ]]; then
      mv "$HOME/.claude/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest.bak-$(date +%s)"
    fi
    ln -sfn "$AGENT_HOME/skills/nuwa-pentest" "$HOME/.claude/skills/nuwa-pentest"
  fi
fi
say "  $AGENT_HOME/skills/nuwa-pentest"

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
    say "  跳过安装 nuwa-autonomous（$BIN_DIR 不可写；可通过 NUWA_BIN_DIR 指定可写目录）"
  fi
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
if [[ "$BIN_INSTALLED" -eq 1 ]]; then
  [[ -x "$BIN_TARGET" ]] || die "守护器缺少可执行权限: $BIN_TARGET" 1
fi
# 双扩展自检：extensions/ 下除 nuwa-omp 外不允许再有 nuwa-* 目录（含 .bak/.retired）
extra="$(find -L "$AGENT_HOME/extensions" -maxdepth 1 -type d -name 'nuwa-*' ! -name 'nuwa-omp' -print 2>/dev/null | wc -l | tr -d ' ')"
[[ "$extra" -eq 0 ]] || die "extensions/ 下仍有 $extra 个旧 nuwa 扩展，会与 nuwa-omp 抢 session_stop；先移出再装" 1

# 运行时加载冒烟（复刻 omp 异步 Bun.plugin，拦截 createRequire 等 async module 错误）
if command -v bun >/dev/null 2>&1; then
  SMOKE_OUT="$(
    EXT_DIR="$EXT_DIR" EXPECT_VER="$INSTALLED_VER" env -u BUN_OPTIONS bun -e '
      import { mkdtempSync, rmSync } from "node:fs";
      import { tmpdir } from "node:os";
      import { join } from "node:path";
      const extDir = process.env.EXT_DIR!;
      const escaped = extDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      Bun.plugin({
        name: "nuwa-install-async-smoke",
        setup(build) {
          build.onLoad({ filter: new RegExp(`^${escaped}/.*\\.ts$`) }, async (args) => {
            const text = await Bun.file(args.path).text();
            return { contents: text, loader: "ts" };
          });
        },
      });
      const mod = await import(`${extDir}/index.ts`);
      if (mod.VERSION !== process.env.EXPECT_VER) {
        throw new Error(`VERSION mismatch: ${mod.VERSION} != ${process.env.EXPECT_VER}`);
      }
      const tools = new Map<string, any>();
      const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
      const z = new Proxy({}, { get: () => () => chain() });
      mod.default({
        zod: z,
        registerTool: (t: any) => tools.set(t.name, t),
        registerCommand: () => {},
        on: () => {},
      });
      const dir = mkdtempSync(join(tmpdir(), "nuwa-install-smoke-"));
      try {
        const ctx: any = {
          cwd: dir,
          agent: { kind: "main" },
          sessionManager: { getSessionId: () => "install-smoke" },
        };
        const r1 = await tools.get("nuwa_init").execute("1", { target: "http://127.0.0.1:18080", mode: "ctf", root: dir }, undefined, undefined, ctx);
        const t1 = r1?.content?.[0]?.text ?? "";
        if (!t1.includes("女娲已上膛") || t1.includes("ERROR:")) {
          throw new Error(`nuwa_init failed: ${t1}`);
        }
        const r2 = await tools.get("nuwa_status").execute("2", { root: dir }, undefined, undefined, ctx);
        const t2 = r2?.content?.[0]?.text ?? "";
        if (!t2.includes("phase=recon") || t2.includes("ERROR:")) {
          throw new Error(`nuwa_status failed: ${t2}`);
        }
        console.log(`SMOKE_OK ${mod.VERSION} tools=${tools.size}`);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    ' 2>&1
  )" || die "扩展运行时异步加载冒烟失败: $SMOKE_OUT" 1
  say "  运行时冒烟: $SMOKE_OUT"
fi

say "  工具面完整 · 模块齐备（9/9） · 单一扩展（无旧版共存）"
say "installed version = ${INSTALLED_VER}"

cat <<EOF

下一步（omp 会话内或无头守护）：
  1. 重启 omp 或 /reload 扩展
  2. 交互式开工：在项目目录说「女娲模式，打 http://TARGET:PORT」或 /nuwa 打 http://TARGET:PORT
     多领域支持：nuwa_init(target="...", mode="ctf|pentest|audit|coding|ops")
  3. 长跑无头守护（跨世代自动换血）：
     nuwa-autonomous --target http://TARGET:PORT --mode ctf --max-generations 20

常用配置（可选）：
  NUWA_INFINITE=1（默认永动；=0 回到旧预算闸）
  NUWA_HEADLESS_DAEMON=1 NUWA_REINCARNATE_TOKENS=140000 NUWA_REINCARNATE_TURNS=30
  NUWA_STRICT_EVIDENCE=1（开启真实执行账本证据复验）
  NUWA_SCOPE_ALLOW_SUBDOMAINS=1 NUWA_SCOPE_ALLOW_CIDRS=10.0.0.0/24
  NUWA_AUTO=1 NUWA_AUTO_MAX=3 NUWA_EMPTY_LIMIT=3 NUWA_MAX_ATTEMPTS=3
  NUWA_SCANNER_GUARD=1 NUWA_REQUIRE_FUJIANG=1 NUWA_LOOP=0（关续跑）

回滚：$0 --rollback
EOF
