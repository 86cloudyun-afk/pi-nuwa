/**
 * 女娲 v7.0 单核合一权威工具与命令执行引擎（零特定宿主 SDK 依赖）。
 *
 * 职责：
 * 1. `NuwaUnifiedEngine`：提供全部 12 个 `nuwa_*` 工具与 `/nuwa` 斜杠命令的单一权威执行内核，
 *    通过可选 `NuwaHostHooks` 注入上下文、UI 刷新、自动侦察批与实时 Token 等宿主差异，
 *    彻底消除 `omp/nuwa.ts` 与 `core/mcp-server.ts` 的双写分裂；
 * 2. 完整内聚 `#53/#54/#55` 全部边界守卫：
 *    - 终态 `sealed_negative` / `completed` 防复活与防降级（非 `force` 零写盘只读、半封盘自动修齐、`resume=true` 永不复活终态）；
 *    - `nuwa_init` 多模式（`ctf`/`ops`/`coding`/`audit`/`pentest`）无默认值精确探测复用；
 *    - 非 `f1000+` 截断的任意位数精确 `evidenceRef` 落盘与绑定；
 *    - 反自证校准机械源对账结算（假阳性门禁拦截与实锤复验）；
 *    - 含口令 `egress` 代理 URL 全链路掩码脱敏零明文泄露；
 *    - `nuwa_status` 全部分支（含默认看板）在 JSON/SQLite/Dual 下严格零磁盘写入。
 *
 * 约束：零外部 npm 依赖，零 `@oh-my-pi/pi-coding-agent` 依赖，严禁运行时 `import "../omp/nuwa"`。
 */
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type {
	FactKind,
	IntentStatus,
	Mode,
	NuwaState,
	Phase,
	RejectedIntentEntry,
	ScopePolicy,
	SurfaceDomain,
} from "../omp/types";
import {
	SCHEMA,
	atomicWrite,
	backupExistingProjectState,
	bindLoadedStateRoot,
	checkAndLogAutoRuleSource,
	checkWorkspaceTempWarning,
	cleanupTrackedProcesses,
	defaultProjectRoot,
	findLocalRoot,
	findRoot,
	getAgentHome,
	hasProjectState,
	isPausedState,
	isSharedCwd,
	journalPath,
	loadState,
	logEvent,
	migrateSapper,
	normalizeState,
	normalizeTargetForMode,
	readCfg,
	readJournalTail,
	readJson,
	readSessionPointer,
	resolveStorageBackend,
	saveState,
	setPausedState,
	sqliteDbPath,
	stateDir,
	statePath,
	verifyWorkspaceIntegrity,
	withLock,
	writePointer,
} from "../omp/storage";
import {
	addIntent,
	autoPlan,
	budgetPressure,
	buildConvergenceAdvice,
	buildDoctorSummary,
	claimAutoBatch,
	claimIntent,
	commitFreeFact,
	completeProject,
	computeRepeatRatio,
	executeAssetsCommand,
	executeAuthDiffWorkflow,
	executeBeliefCommand,
	executeCalibrateCommand,
	executeCommitWithGates,
	executeHybridCommand,
	executeMcpCommand,
	executeOobCommand,
	executeScopeCommand,
	executeSessionCommand,
	executeSessionHealthCommand,
	executeTrafficCommand,
	extractIntentTargetKey,
	extractTarget,
	finalizeReportPhase,
	frontierList,
	inspectGraph,
	kickPrompt,
	newState,
	pickMode,
	planIntents,
	recordFlag,
	releaseAutoBatchRemaining,
	reportMarkdown,
	runSpaSurfaceWorkflow,
	sealEngagement,
	seedPhase,
	shouldRecommendSeal,
	statusBoard,
	type AddIntentInput,
	type ConvergenceAdvice,
} from "../omp/graph";
import { resolveReportPhaseTransition, type ReportPhaseTransition } from "../omp/reincarnate";
import { buildSnapshot, extractProbeHealth, renderBoardLines, renderFullStatus, themeStyle } from "../omp/ui";
import { injectEgressIntoScript, loadAutoRules } from "../omp/autoexec";
import { defaultScopeForTarget, isHostInScope } from "../omp/scope";
import {
	evaluatePositiveEvidenceGate,
	parseAgentResult,
	probeToolchain,
	saveFactEvidenceLog,
	validateDeliverableRealism,
	verifyExecutionEvidence,
	type AgentEvidenceItem,
	type DeliverableRealismResult,
	type PositiveEvidenceGateResult,
	type SavedEvidenceLog,
} from "../omp/evidence";
import {
	InflightTargetRegistry,
	buildDispatchPacket,
	chunkBatchTasks,
	injectResolvedTargetContext,
	registerActiveSession,
	type BatchTaskItem,
	type ChunkBatchResult,
} from "../omp/lineage";
import { distillProjectExperience, ensureBundledKb, kbLookupSafe } from "../omp/kb";
import { loadSessionVault, redactVaultSecrets } from "../omp/session-vault";
import {
	buildFalsePositiveNote,
	extractVerifyTargetFactId,
	isVerifyVulnIntentKey,
	validateVerificationCommit,
} from "../omp/verifier-gate";
import {
	buildCurlProxyArgs,
	injectEgressEnv,
	maskEgressUrl,
	normalizeTaskEgressUrl,
	readSandboxConfig,
	resolveConfiguredEgressUrl,
} from "../omp/sandbox";
import { ensurePrimaryAsset } from "../omp/hypothesis";
import {
	buildJsonReport,
	buildSarifReport,
	exportEpisodeTimeline,
	searchArchiveIndexes,
	writeEpisodeArchiveIndex,
	writePocBundle,
	type ArchiveSearchQuery,
	type WriteEpisodeArchiveResult,
} from "../omp/reporting";
import { loadStateFromSqlite } from "../omp/sqlite-store";
import { hasCalibrationRecords, loadCalibrationRecords, safeSettlePrediction } from "../omp/calibration";
import {
	NUWA_CORE_TOOLS,
	isNuwaToolName,
	type McpToolCallResult,
	type McpToolDefinition,
	type NuwaToolName,
} from "./protocol";

const VALID_MODES = new Set<Mode>(["ctf", "pentest", "audit", "coding", "ops"]);
const ALL_MODE_PROBES: readonly Mode[] = ["ctf", "ops", "coding", "audit", "pentest"];
const VALID_PHASES = new Set<Phase>(["recon", "surface", "vuln", "exploit", "post", "report"]);
const VALID_FACT_KINDS = new Set<FactKind>([
	"target",
	"asset",
	"service",
	"endpoint",
	"cred",
	"vuln",
	"flag",
	"loot",
	"note",
	"blocked",
]);
const VALID_DOMAINS = new Set<SurfaceDomain>(["port", "path", "host"]);
const VALID_INTENT_STATUS = new Set<IntentStatus>(["open", "claimed", "done", "blocked"]);
const VALID_KB_KINDS = new Set(["auto", "product", "cve", "technique", "poc"]);
const VALID_REPORT_FORMATS = new Set(["md", "json", "sarif", "timeline"]);
const COMBINED_HARD_VIOLATIONS = new Set(["placeholder_bracket", "unexpanded_target_literal"]);

/** `/nuwa` 斜杠命令支持的全部子命令列表（保持与 omp 自动补全完全一致）。 */
export const NUWA_SUBCOMMANDS = [
	"status",
	"board",
	"scope",
	"session",
	"authdiff",
	"oob",
	"assets",
	"report",
	"doctor",
	"spa",
	"log",
	"why",
	"seal",
	"note",
	"inspect",
	"query",
	"pause",
	"stop",
	"resume",
	"export",
	"belief",
	"calibrate",
	"traffic",
	"hybrid",
	"mcp",
] as const;

export type NuwaSubcommand = (typeof NUWA_SUBCOMMANDS)[number];

/** 统一工具调用返回契约（同时满足 omp `registerTool` 与标准 MCP `CallToolResult`）。 */
export interface UnifiedToolResult extends McpToolCallResult {
	content: Array<{ type: "text"; text: string }>;
	details: Record<string, unknown>;
	isError: boolean;
}

/** 斜杠命令 `/nuwa` 核心执行返回结果。 */
export interface SlashCommandResult {
	message: string;
	level: "info" | "error";
	kicked?: boolean;
	root?: string | null;
}

/**
 * 宿主环境差异注入钩子（全部可选，缺省时退化为纯无头/MCP 独立模式）。
 */
export interface NuwaHostHooks {
	/** 获取当前会话标识（omp 为 `ctx.sessionManager.getSessionId()`，MCP 默认为 `mcp-<pid>`）。 */
	getSessionId?: () => string;
	/** 获取当前基准工作目录。 */
	getCwd?: () => string;
	/** 获取 Agent Home 路径。 */
	getAgentHome?: () => string;
	/** 自定义宿主血缘根目录解析器（如 omp `resolveRootWithLineage`）。 */
	resolveRoot?: (explicitRoot?: string) => string | null;
	/** 绑定活跃主会话血缘回调。 */
	onBindSession?: (root: string, projectId: string | undefined, sessionId: string) => void;
	/** 刷新宿主 UI 状态栏与挂件（纯只读展示钩子）。 */
	onRefreshUi?: (root: string, state: NuwaState, force?: boolean) => void;
	/** 获取宿主当前实时上下文 Token 用量（封盘/完成验收时合并至 `runtime.tokens`）。 */
	getLiveTokens?: () => number;
	/** 宿主是否提供本地命令自动批执行能力（如 omp `hasExec()`）。 */
	canRunAutoBatch?: () => boolean;
	/** 启动异步确定性自动侦察批。 */
	onStartAutoBatch?: (root: string, intentIds: string[]) => void;
	/** 中断在途自动侦察批并释放认领意图。 */
	onAbortAutoBatch?: (root: string, reason: string) => string[];
	/** 斜杠命令 UI 通知回调。 */
	onNotify?: (message: string, level: "info" | "error") => void;
	/** 斜杠命令向宿主会话注入首轮/恢复提示词回调。 */
	onKick?: (promptText: string) => boolean;
	/** 斜杠命令 `/nuwa board` 全屏 Overlay 渲染回调（返回 `true` 表示已由宿主 TUI 接管展示）。 */
	onRenderBoardOverlay?: (root: string, state: NuwaState) => Promise<boolean> | boolean;
	/** 自定义便携知识库预热钩子。 */
	onWarmKb?: (agentHome: string) => void;
}

export interface NuwaUnifiedEngineOptions {
	/** 显式绑定的默认项目根目录（如 CLI `--project <dir>`）。 */
	projectRoot?: string;
	/** 默认基准工作目录（默认 `process.cwd()`）。 */
	cwd?: string;
	/** 默认会话标识（默认 `mcp-<pid>`）。 */
	sessionId?: string;
	/** 显式指定的 Agent Home 目录。 */
	agentHome?: string;
	/** 宿主标识标签（写入 `registerActiveSession` 的默认 `agentId`，默认 `"nuwa-core"`）。 */
	hostAgentId?: string;
	/** 是否在无自动批执行器且显式请求 `autoStart=true` 时返回跳过说明（MCP 模式默认开启）。 */
	emitAutoStartSkipNote?: boolean;
	/** 默认宿主差异钩子（可在单次 `callTool` / `executeSlashCommand` 中按调用覆盖）。 */
	hooks?: NuwaHostHooks;
}

function isPlainRecord(val: unknown): val is Record<string, unknown> {
	return Boolean(val && typeof val === "object" && !Array.isArray(val));
}

function toolText(text: string, details: Record<string, unknown> = {}): UnifiedToolResult {
	return {
		content: [{ type: "text", text }],
		details,
		isError: false,
	};
}

function toolError(err: unknown, details: Record<string, unknown> = {}): UnifiedToolResult {
	const msg = err instanceof Error ? err.message : String(err);
	return {
		content: [{ type: "text", text: `ERROR: ${msg}` }],
		details: { error: true, ...details },
		isError: true,
	};
}

/** 判断项目状态是否已进入合法终态（`sealed_negative` 或 `completed`）。 */
export function isTerminalProjectState(st: NuwaState | null | undefined): boolean {
	if (!st) return false;
	const ps = st.project?.status;
	const rs = st.runtime?.status;
	return ps === "sealed_negative" || rs === "sealed_negative" || ps === "completed" || rs === "completed";
}

/** 提取终态项目的权威终态枚举值。 */
export function terminalStatusOf(st: NuwaState): "sealed_negative" | "completed" {
	return st.project?.status === "sealed_negative" || st.runtime?.status === "sealed_negative"
		? "sealed_negative"
		: "completed";
}

/**
 * 终态（负向封盘或完成验收）报告自动同步刷新器。
 * 保证封盘后 `REPORT.md` 与已存在的 `REPORT.json` / `REPORT.sarif.json` 立即反映终态元数据。
 */
export function syncTerminalReports(root: string, st: NuwaState, opts: { writeMd?: boolean } = {}): string {
	const normRoot = resolve(root);
	const nuwaDir = join(normRoot, ".nuwa");
	const mdPath = join(nuwaDir, "REPORT.md");
	const jsonPath = join(nuwaDir, "REPORT.json");
	const sarifPath = join(nuwaDir, "REPORT.sarif.json");
	let writtenMd = "";
	try {
		if (opts.writeMd || existsSync(mdPath)) {
			const md = redactVaultSecrets(reportMarkdown(st, normRoot), normRoot);
			atomicWrite(mdPath, md);
			writtenMd = mdPath;
		}
		if (existsSync(jsonPath)) {
			atomicWrite(jsonPath, `${JSON.stringify(buildJsonReport(st, normRoot), null, 2)}\n`);
		}
		if (existsSync(sarifPath)) {
			atomicWrite(sarifPath, `${JSON.stringify(buildSarifReport(st, normRoot), null, 2)}\n`);
		}
		if (opts.writeMd || writtenMd) {
			writeEpisodeArchiveIndex(normRoot, {
				episode: st.project.episode ?? 1,
				state: st,
				summary:
					terminalStatusOf(st) === "sealed_negative"
						? `负向封盘自动报告 (${st.project.sealMeta?.reason ?? "sealed_negative"})`
						: "完成验收报告同步",
			});
		}
	} catch {
		/* 报告自动刷新失败不阻断封盘/验收主流程 */
	}
	return writtenMd;
}

/**
 * 严格零磁盘写入加载项目状态（专用于 `nuwa_status` 及纯只读诊断视图）。
 * - SQLite/Dual 模式：以 `readonly: true` 打开查询，绝不产生 `-wal`/`-shm` 或触发 JSON->SQLite 迁移写盘；
 * - JSON 模式：纯内存解析 `state.json`（若缺失仅在内存中读取快照恢复，绝不调用 `atomicWrite` 回写磁盘）。
 */
export function loadStateZeroWrite(root: string): NuwaState | null {
	const normRoot = resolve(root);
	const backend = resolveStorageBackend(normRoot);
	const dbFile = sqliteDbPath(normRoot);

	if ((backend === "sqlite" || backend === "dual") && existsSync(dbFile)) {
		try {
			const fromDb = loadStateFromSqlite(normRoot, { fallbackToJson: false });
			if (fromDb) return bindLoadedStateRoot(normalizeState(fromDb), normRoot);
		} catch {
			/* 坏库或不可读时继续尝试纯内存 JSON 读取 */
		}
	}

	const sp = statePath(normRoot);
	if (existsSync(sp)) {
		const direct = readJson<NuwaState>(sp);
		if (direct && direct.schema === SCHEMA && direct.project) {
			const cloned = JSON.parse(JSON.stringify(direct)) as NuwaState;
			return bindLoadedStateRoot(normalizeState(cloned), normRoot);
		}
	}

	if (existsSync(dbFile)) {
		try {
			const fromDbFallback = loadStateFromSqlite(normRoot, { fallbackToJson: false });
			if (fromDbFallback) return bindLoadedStateRoot(normalizeState(fromDbFallback), normRoot);
		} catch {
			/* ignore */
		}
	}

	// 纯内存兜底读取 journal 最新内联快照（不触发任何磁盘回写）
	const jp = journalPath(normRoot);
	if (existsSync(jp)) {
		try {
			const lines = readFileSync(jp, "utf8").trim().split("\n");
			for (let i = lines.length - 1; i >= 0; i--) {
				try {
					const rec = JSON.parse(lines[i]!) as { type?: string; state?: NuwaState; file?: string };
					if (rec?.type === "snapshot" && rec.state?.schema === SCHEMA && rec.state.project) {
						return bindLoadedStateRoot(normalizeState(rec.state), normRoot);
					}
					if (rec?.type === "snapshot" && typeof rec.file === "string" && !rec.file.endsWith(".gz")) {
						const snapCandidate = readJson<NuwaState>(join(stateDir(normRoot), rec.file));
						if (snapCandidate?.schema === SCHEMA && snapCandidate.project) {
							return bindLoadedStateRoot(normalizeState(snapCandidate), normRoot);
						}
					}
				} catch {
					/* 跳过损坏日志行 */
				}
			}
		} catch {
			/* ignore */
		}
	}

	return null;
}

/**
 * 严格零磁盘写入渲染状态看板（专用于 `nuwa_status`、终态只读 `nuwa_init` 与 `/nuwa status`）：
 * 预先使用纯只读 `loadAutoRules` 校验项目/全局 `autoexec.json`；若配置损坏包含 `error`，
 * 则在内存中补齐角色计数与规则源并省略透传 `root`，彻底阻断 `checkAndLogAutoRuleSource` 调用 `logEvent` 写盘。
 */
export function statusBoardZeroWrite(st: NuwaState, root?: string, agentHome?: string): string {
	if (!root) return statusBoard(st);
	const normRoot = resolve(root);
	const defaultHome = getAgentHome();
	const effectiveHome = agentHome && agentHome.trim() ? resolve(agentHome.trim()) : defaultHome;
	const checkEffective = loadAutoRules(normRoot, effectiveHome);
	const checkDefault = effectiveHome === resolve(defaultHome) ? checkEffective : loadAutoRules(normRoot, defaultHome);
	if (!checkEffective.error && !checkDefault.error) {
		return statusBoard(st, normRoot);
	}
	let roleNames = st.project.activeRoles ?? [];
	try {
		roleNames = Object.keys(loadSessionVault(normRoot).roles);
	} catch {
		/* ignore */
	}
	const safeClone: NuwaState = {
		...st,
		project: {
			...st.project,
			activeRoles: roleNames,
		},
		runtime: {
			...st.runtime,
			rulesSource: checkEffective.source,
		},
	};
	return statusBoard(safeClone, undefined);
}

/** 释放指定项目下残留的自动批认领意图。 */
export function releaseInflightAutoBatch(root: string, reason = "stopped"): string[] {
	const normRoot = resolve(root);
	let released: string[] = [];
	if (hasProjectState(normRoot)) {
		try {
			withLock(normRoot, () => {
				const s = loadState(normRoot);
				if (!s) return;
				released = releaseAutoBatchRemaining(s);
				if (released.length > 0) {
					saveState(normRoot, s);
					logEvent(normRoot, { type: "auto_aborted", ids: released, reason });
				}
			});
		} catch {
			/* 停机期锁竞争忽略 */
		}
	}
	return released;
}

function formatAgentEvidenceOutput(ev: AgentEvidenceItem): string {
	const metricParts: string[] = [];
	if (ev.http_code !== undefined) metricParts.push(`http_code=${ev.http_code}`);
	if (ev.size_download !== undefined) metricParts.push(`size_download=${ev.size_download}`);
	if (ev.remote_ip) metricParts.push(`remote_ip=${ev.remote_ip}`);
	if (ev.cf_ray) metricParts.push(`cf_ray=${ev.cf_ray}`);
	if (ev.server) metricParts.push(`server=${ev.server}`);
	if (ev.time_total !== undefined) metricParts.push(`time_total=${ev.time_total}`);
	if (ev.body_sha256) metricParts.push(`body_sha256=${ev.body_sha256}`);
	const header = metricParts.join(" ");
	if (header && ev.snippet) return `${header}\n${ev.snippet}`;
	return ev.snippet || header;
}

/**
 * 提交内容真实性与占位符未展开拦截守卫（#26, #39）。
 */
export function checkCommitRealismGuard(
	pre: NuwaState,
	fields: { command?: string; output?: string; detail?: string },
	strictRealism = false,
): { ok: true } | { ok: false; reason: string; result: DeliverableRealismResult } {
	const combined = [fields.command, fields.output, fields.detail]
		.map((s) => (s ?? "").trim())
		.filter(Boolean)
		.join("\n");
	if (!combined) return { ok: true };

	const targetHost = pre.project.scheme !== "local" ? pre.project.host : undefined;
	const res = validateDeliverableRealism(combined, targetHost);
	const outOnly = (fields.output ?? "").trim();
	const outRes = outOnly ? validateDeliverableRealism(outOnly, targetHost) : null;

	const activeViolations = res.violations.filter((v) => {
		if (COMBINED_HARD_VIOLATIONS.has(v)) return true;
		if (v === "target_host_mismatch") {
			const projScope =
				pre.project.scope ?? defaultScopeForTarget(pre.project.url || pre.project.target, pre.project.mode);
			const urlMatches = combined.match(/https?:\/\/[^\s"'<>`)\]]+/gi) ?? [];
			const anyInScope = urlMatches.some((rawUrl) => {
				try {
					const h = new URL(rawUrl.replace(/[),.;]+$/, "")).hostname;
					return isHostInScope(h, projScope).ok;
				} catch {
					return false;
				}
			});
			return !anyInScope;
		}
		if (v === "missing_probe_metrics") {
			return strictRealism;
		}
		return false;
	});

	if (outRes?.violations.includes("script_only_no_status") && !activeViolations.includes("script_only_no_status")) {
		activeViolations.push("script_only_no_status");
	}

	if (activeViolations.length === 0) return { ok: true };
	const mergedReasons = [
		...res.reasons.filter((_, idx) => {
			const v = res.violations[idx];
			return v ? activeViolations.includes(v) : false;
		}),
		...(outRes?.violations.includes("script_only_no_status")
			? outRes.reasons.filter((_, idx) => outRes.violations[idx] === "script_only_no_status")
			: []),
	];
	return {
		ok: false,
		reason: `模板化/未解析回包拦截: ${(mergedReasons.length ? mergedReasons : res.reasons).join("；")}`,
		result: { ...res, violations: activeViolations },
	};
}

function getInflightRegistry(root: string): InflightTargetRegistry {
	return new InflightTargetRegistry({ persistPath: join(resolve(root), ".nuwa", "inflight-targets.json") });
}

const PLAIN_THEME_STYLE = themeStyle({
	fg: (_color: string, text: string) => text,
	bold: (text: string) => text,
});

/**
 * 女娲 v7.0 单核合一执行引擎。
 * 可同时直接作为 `omp` 扩展的核心执行器与无头 `MCP Server` 的核心引擎。
 */
export class NuwaUnifiedEngine {
	private readonly defaultCwd: string;
	private readonly configuredProjectRoot?: string;
	private readonly defaultSessionId: string;
	private readonly explicitAgentHome?: string;
	private readonly hostAgentId: string;
	private readonly emitAutoStartSkipNote: boolean;
	private readonly baseHooks: NuwaHostHooks;
	private activeRoot: string | null;
	private initialized = false;

	constructor(opts?: NuwaUnifiedEngineOptions) {
		this.defaultCwd = resolve(opts?.cwd ?? process.cwd());
		this.configuredProjectRoot = opts?.projectRoot ? resolve(this.defaultCwd, opts.projectRoot) : undefined;
		this.defaultSessionId = (opts?.sessionId ?? "").trim() || `nuwa-${process.pid}`;
		this.explicitAgentHome = opts?.agentHome ? resolve(opts.agentHome) : undefined;
		this.hostAgentId = (opts?.hostAgentId ?? "").trim() || "nuwa-core";
		this.emitAutoStartSkipNote = opts?.emitAutoStartSkipNote ?? true;
		this.baseHooks = opts?.hooks ?? {};
		this.activeRoot = this.configuredProjectRoot ?? null;
	}

	/** 标记协议握手已完成（兼容 MCP `initialize` 状态查询）。 */
	markInitialized(): void {
		this.initialized = true;
	}

	isInitialized(): boolean {
		return this.initialized;
	}

	/** 获取当前引擎关联的活跃项目根目录。 */
	getActiveRoot(): string | null {
		return this.activeRoot ?? this.configuredProjectRoot ?? null;
	}

	/** 列出全部 12 个女娲核心工具定义契约。 */
	listTools(): readonly McpToolDefinition[] {
		return NUWA_CORE_TOOLS;
	}

	private mergeHooks(perCall?: Partial<NuwaHostHooks>): NuwaHostHooks {
		if (!perCall) return this.baseHooks;
		return { ...this.baseHooks, ...perCall };
	}

	private resolveCwd(hooks: NuwaHostHooks): string {
		const c = hooks.getCwd?.();
		return c && c.trim() ? resolve(c) : this.defaultCwd;
	}

	private resolveSessionId(hooks: NuwaHostHooks): string {
		const sid = hooks.getSessionId?.();
		return sid && sid.trim() ? sid.trim() : this.defaultSessionId;
	}

	private resolveAgentHome(hooks: NuwaHostHooks): string {
		const ah = hooks.getAgentHome?.();
		if (ah && ah.trim()) return resolve(ah.trim());
		return this.explicitAgentHome ?? getAgentHome();
	}

	private warmKb(hooks: NuwaHostHooks): void {
		const agentHome = this.resolveAgentHome(hooks);
		try {
			if (hooks.onWarmKb) {
				hooks.onWarmKb(agentHome);
			} else {
				ensureBundledKb(undefined, { agentHome });
			}
		} catch {
			/* 只读文件系统或无内置种子时不阻断主流程 */
		}
	}

	private bindSession(hooks: NuwaHostHooks, root: string, projectId?: string): void {
		const normRoot = resolve(root);
		const sid = this.resolveSessionId(hooks);
		this.activeRoot = normRoot;
		if (hooks.onBindSession) {
			try {
				hooks.onBindSession(normRoot, projectId, sid);
				return;
			} catch {
				/* ignore custom bind error */
			}
		}
		try {
			registerActiveSession(
				{
					sessionId: sid,
					root: normRoot,
					cwd: this.resolveCwd(hooks),
					agentId: this.hostAgentId,
					projectId,
				},
				this.resolveAgentHome(hooks),
			);
		} catch {
			/* ignore */
		}
	}

	private refreshUi(hooks: NuwaHostHooks, root: string, state: NuwaState, force = false): void {
		try {
			hooks.onRefreshUi?.(resolve(root), state, force);
		} catch {
			/* UI 刷新异常绝不阻断业务返回 */
		}
	}

	private abortAutoBatch(hooks: NuwaHostHooks, root: string, reason: string): string[] {
		if (hooks.onAbortAutoBatch) {
			try {
				return hooks.onAbortAutoBatch(resolve(root), reason);
			} catch {
				/* 回退释放状态内残余认领 */
			}
		}
		return releaseInflightAutoBatch(root, reason);
	}

	/**
	 * 解析生效的项目根目录：
	 * 1. 显式 `explicitRoot` 参数；
	 * 2. 宿主注入的 `hooks.resolveRoot`（如 omp 主从血缘解析）；
	 * 3. 引擎绑定的 `configuredProjectRoot` / `activeRoot`；
	 * 4. 本地目录树向上探测 `findLocalRoot` 与会话指针 `findRoot`。
	 */
	resolveRoot(explicitRoot?: unknown, perCallHooks?: Partial<NuwaHostHooks>): string | null {
		const hooks = this.mergeHooks(perCallHooks);
		const cwd = this.resolveCwd(hooks);
		const explicitStr = typeof explicitRoot === "string" && explicitRoot.trim() ? explicitRoot.trim() : undefined;
		if (explicitStr) {
			return resolve(cwd, explicitStr);
		}
		if (hooks.resolveRoot) {
			const viaHook = hooks.resolveRoot(undefined);
			if (viaHook) return resolve(viaHook);
		}
		if (this.configuredProjectRoot && hasProjectState(this.configuredProjectRoot)) {
			return this.configuredProjectRoot;
		}
		if (this.activeRoot && hasProjectState(this.activeRoot)) {
			return this.activeRoot;
		}
		if (this.configuredProjectRoot) {
			return this.configuredProjectRoot;
		}
		const sid = this.resolveSessionId(hooks);
		return findLocalRoot(cwd, sid) ?? findRoot(cwd, sid);
	}

	/**
	 * 执行全部 12 个 `nuwa_*` 核心工具中的任意一个。
	 */
	async callTool(
		name: string,
		rawArgs?: Record<string, unknown>,
		perCallHooks?: Partial<NuwaHostHooks>,
	): Promise<UnifiedToolResult> {
		if (!isNuwaToolName(name)) {
			return toolError(`未知工具: ${name}`);
		}
		const args: Record<string, unknown> = isPlainRecord(rawArgs) ? rawArgs : {};
		const hooks = this.mergeHooks(perCallHooks);
		switch (name as NuwaToolName) {
			case "nuwa_init":
				return this.execInit(args, hooks);
			case "nuwa_plan":
				return this.execPlan(args, hooks);
			case "nuwa_frontier":
				return this.execFrontier(args, hooks);
			case "nuwa_claim":
				return this.execClaim(args, hooks);
			case "nuwa_commit":
				return this.execCommit(args, hooks);
			case "nuwa_flag":
				return this.execFlag(args, hooks);
			case "nuwa_complete":
				return this.execComplete(args, hooks);
			case "nuwa_status":
				return this.execStatus(args, hooks);
			case "nuwa_report":
				return this.execReport(args, hooks);
			case "nuwa_expand":
				return this.execExpand(args, hooks);
			case "nuwa_stop":
				return this.execStop(args, hooks);
			case "nuwa_kb":
				return this.execKb(args, hooks);
		}
	}

	private execInit(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			this.warmKb(hooks);
			const curCfg = readCfg();
			const cwd = this.resolveCwd(hooks);
			const sid = this.resolveSessionId(hooks);
			const explicitRawMode = p.mode === undefined ? undefined : String(p.mode);
			if (explicitRawMode !== undefined && !VALID_MODES.has(explicitRawMode as Mode)) {
				throw new Error(`非法 mode: ${explicitRawMode}`);
			}

			const resume = Boolean(p.resume ?? false);
			const force = Boolean(p.force ?? false);
			const migrate = Boolean(p.migrate ?? false);
			const autoStartRequested = p.autoStart === true;
			const hostCanExecAuto = Boolean(hooks.canRunAutoBatch?.());
			const autoStartMeta =
				autoStartRequested && !hostCanExecAuto && this.emitAutoStartSkipNote
					? {
							autoStartSkipped: true,
							autoStartNote:
								"当前无头协议服务不包含宿主 Shell 执行器，已跳过 autoStart 自动批，请通过 nuwa_frontier / nuwa_claim 驱动",
						}
					: {};

			const targetArg = typeof p.target === "string" && p.target.trim() ? p.target.trim() : undefined;
			const explicitRootArg = typeof p.root === "string" && p.root.trim() ? p.root.trim() : undefined;

			let probeRoot = "";
			if (explicitRootArg) {
				probeRoot = resolve(cwd, explicitRootArg);
			} else if (this.configuredProjectRoot) {
				probeRoot = this.configuredProjectRoot;
			} else if (targetArg) {
				const targetDir = resolve(cwd, targetArg);
				if (hasProjectState(targetDir)) probeRoot = targetDir;
			}

			if (!probeRoot && !targetArg) {
				const local = findLocalRoot(cwd, sid);
				if (local) {
					probeRoot = local;
				} else if (isSharedCwd(cwd)) {
					const ptr = readSessionPointer(sid);
					if (ptr?.root) probeRoot = resolve(ptr.root);
				} else {
					probeRoot = resolve(cwd);
				}
			}

			// 多模式（ctf/ops/coding/audit/pentest）无默认值精确探测复用：未显式传 mode 时按已有项目的真实 mode 比对 URL
			if (!probeRoot && !explicitRawMode && targetArg) {
				const envProj = process.env.NUWA_PROJECT?.trim();
				const ptr = readSessionPointer(sid);
				const cwdResolved = resolve(cwd);
				const candSet = new Set<string>();
				const addCand = (pCand: string | null | undefined) => {
					if (!pCand) return;
					const resolvedCand = resolve(pCand);
					if (hasProjectState(resolvedCand)) candSet.add(resolvedCand);
				};
				addCand(findLocalRoot(cwd, sid));
				if (!isSharedCwd(cwdResolved)) addCand(cwdResolved);
				if (envProj) addCand(envProj);
				if (ptr?.root) addCand(ptr.root);
				for (const candMode of ALL_MODE_PROBES) {
					try {
						addCand(defaultProjectRoot(cwd, targetArg, sid, candMode));
					} catch {
						/* 非该模式合法目标则跳过 */
					}
				}
				for (const localCand of candSet) {
					const localSt = loadStateZeroWrite(localCand);
					if (!localSt) continue;
					try {
						if (localSt.project.url === normalizeTargetForMode(targetArg, localSt.project.mode).url) {
							probeRoot = localCand;
							break;
						}
					} catch {
						/* 非匹配目标则按常规流程校验 */
					}
				}
			}

			const preExisting = probeRoot && hasProjectState(probeRoot) ? loadStateZeroWrite(probeRoot) : null;
			const mode = ((explicitRawMode as Mode | undefined) ?? preExisting?.project?.mode ?? "ctf") as Mode;
			const rawTarget =
				targetArg ??
				(!resume && !migrate && (mode === "coding" || mode === "ops" || mode === "audit")
					? (this.configuredProjectRoot ?? cwd)
					: undefined);
			const want = rawTarget ? normalizeTargetForMode(rawTarget, mode).url : "";

			let root: string;
			if (explicitRootArg) {
				root = resolve(cwd, explicitRootArg);
			} else if (this.configuredProjectRoot) {
				root = this.configuredProjectRoot;
			} else if (probeRoot && preExisting) {
				root = probeRoot;
			} else if (rawTarget) {
				root = defaultProjectRoot(cwd, rawTarget, sid, mode);
			} else {
				const local = findLocalRoot(cwd, sid);
				if (local) {
					root = local;
				} else if (isSharedCwd(cwd)) {
					const ptr = readSessionPointer(sid);
					if (ptr?.root) root = resolve(ptr.root);
					else throw new Error("共享 cwd 下新建/恢复项目需要 target 或 root");
				} else {
					root = resolve(cwd);
				}
			}

			const scopeOverride = isPlainRecord(p.scope) ? (p.scope as Partial<ScopePolicy>) : undefined;
			// 先以零写盘方式读取现有状态，确保跨会话/同会话终态 resume 在无需修齐时 100% 零磁盘写入
			const existing = hasProjectState(root) ? (loadStateZeroWrite(root) ?? loadState(root)) : null;

			if (existing?.project.ownerSessionId && existing.project.ownerSessionId !== sid && !force) {
				if (resume && isTerminalProjectState(existing)) {
					const termStatus = terminalStatusOf(existing);
					this.activeRoot = resolve(root);
					this.refreshUi(hooks, root, existing, true);
					return toolText(
						`该项目已处于终态 (${termStatus}): ${existing.project.id}（属于其他会话 ${existing.project.ownerSessionId}，已降级为只读查看；如需接管重建请传 force=true）\n\n${statusBoardZeroWrite(existing, root, this.resolveAgentHome(hooks))}`,
						{ root, readonly: true, status: termStatus, sealed: termStatus === "sealed_negative", ...autoStartMeta },
					);
				}
				throw new Error("该项目属于其他会话；用 force=true 明确接管，避免跨任务污染");
			}

			if (existing && want && existing.project.url !== want && !force) {
				throw new Error(`该目录已是 ${existing.project.url} 的项目；新目标请换 root，或 force=true 明确接管`);
			}

			if (migrate) {
				if (existing && !force) throw new Error("已有 .nuwa 状态；加 force=true 覆盖后再迁移");
				if (existing && force) backupExistingProjectState(root);
				const migrated = withLock(root, () => {
					const st = migrateSapper(root);
					st.project.ownerSessionId = sid;
					st.project.toolchain = probeToolchain();
					st.project.sandboxMode = readSandboxConfig().mode;
					ensurePrimaryAsset(st);
					saveState(root, st, { reason: "init" });
					return st;
				});
				verifyWorkspaceIntegrity(root, { recordBaseline: true });
				writePointer(root, sid);
				this.bindSession(hooks, root, migrated.project.id);
				this.refreshUi(hooks, root, migrated, true);
				return toolText(`已从 .sapper 迁移: ${migrated.project.id}\n\n${statusBoard(migrated, root)}`, {
					root,
					migrated: true,
				});
			}

			if (existing && resume) {
				// PR #55 终态防复活守卫：无论 force=false 还是跨代接力传 resume=true, force=true，终态均不可通过 resume 复活
				if (isTerminalProjectState(existing)) {
					const termStatus = terminalStatusOf(existing);
					let finalTerminal = existing;
					// 自动修齐半封盘状态（project.status 与 runtime.status 不一致时单次加锁对齐；已对齐时严格零写盘）
					if (existing.project.status !== termStatus || existing.runtime.status !== termStatus) {
						finalTerminal = withLock(root, () => {
							const s = loadState(root);
							if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init");
							s.project.status = termStatus;
							s.runtime.status = termStatus;
							saveState(root, s, {
								reason: termStatus === "sealed_negative" ? "resume-sealed-align" : "resume-completed-align",
							});
							return s;
						});
					}
					const wsIntegrity = verifyWorkspaceIntegrity(root);
					this.activeRoot = resolve(root);
					this.refreshUi(hooks, root, finalTerminal, true);
					return toolText(
						`项目已处于终态 (${termStatus}): ${finalTerminal.project.id}（终态不可通过 resume 复活；如需重新评估请换 root 或 nuwa_init(force=true) 重建）\n\n${statusBoardZeroWrite(finalTerminal, root, this.resolveAgentHome(hooks))}`,
						{
							root,
							status: termStatus,
							sealed: termStatus === "sealed_negative",
							readonly: true,
							integrity: wsIntegrity.status,
							...autoStartMeta,
						},
					);
				}

				if (isPausedState(root)) {
					setPausedState(root, false, "nuwa_init resume");
				}
				const resumed = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init");
					if (isTerminalProjectState(s)) {
						const termStatus = terminalStatusOf(s);
						if (s.project.status !== termStatus || s.runtime.status !== termStatus) {
							s.project.status = termStatus;
							s.runtime.status = termStatus;
							saveState(root, s, {
								reason: termStatus === "sealed_negative" ? "resume-sealed-noop" : "resume-completed-noop",
							});
						}
						return s;
					}
					s.project.status = "active";
					s.project.stopReason = undefined;
					s.project.ownerSessionId = sid;
					s.runtime.status = "active";
					if (scopeOverride) {
						s.project.scope = defaultScopeForTarget(s.project.url || s.project.target, s.project.mode, {
							...s.project.scope,
							...scopeOverride,
						});
					} else if (!s.project.scope) {
						s.project.scope = defaultScopeForTarget(s.project.url || s.project.target, s.project.mode);
					}
					s.project.toolchain = probeToolchain();
					s.project.sandboxMode = readSandboxConfig().mode;
					ensurePrimaryAsset(s);
					const prevStart = s.runtime.projectStartedAt ?? s.runtime.startedAt ?? Date.now();
					const prevTurns = Math.max(0, Number(s.runtime.turns ?? 0));
					const prevTotalTurns = Math.max(Number(s.runtime.totalTurns ?? 0), prevTurns);
					const prevTotalTokens = Number(s.runtime.totalTokens ?? 0) + Math.max(0, Number(s.runtime.tokens ?? 0));
					Object.assign(s.runtime, {
						startedAt: s.runtime.startedAt || prevStart,
						projectStartedAt: prevStart,
						turns: prevTurns,
						totalTurns: prevTotalTurns,
						totalTokens: prevTotalTokens,
						genTurns: 0,
						stall: 0,
						idle: 0,
						tokens: 0,
						completionRejects: 0,
						lastSig: "",
						lastSettleAt: 0,
						blockStreak: 0,
						pressure: 0,
						rulesSource: checkAndLogAutoRuleSource(root, s),
					});
					saveState(root, s, { reason: "init" });
					return s;
				});

				if (isTerminalProjectState(resumed)) {
					const termStatus = terminalStatusOf(resumed);
					const wsIntegrity = verifyWorkspaceIntegrity(root);
					this.activeRoot = resolve(root);
					this.refreshUi(hooks, root, resumed, true);
					return toolText(
						`项目已处于终态 (${termStatus}): ${resumed.project.id}（终态不可通过 resume 复活；如需重新评估请换 root 或 nuwa_init(force=true) 重建）\n\n${statusBoardZeroWrite(resumed, root, this.resolveAgentHome(hooks))}`,
						{
							root,
							status: termStatus,
							sealed: termStatus === "sealed_negative",
							readonly: true,
							integrity: wsIntegrity.status,
							...autoStartMeta,
						},
					);
				}

				const wsIntegrity = verifyWorkspaceIntegrity(root, { recordBaseline: true });
				writePointer(root, sid);
				this.bindSession(hooks, root, resumed.project.id);
				this.refreshUi(hooks, root, resumed, true);
				return toolText(`已恢复 ${resumed.project.id}\n\n${statusBoard(resumed, root)}`, {
					root,
					integrity: wsIntegrity.status,
					...autoStartMeta,
				});
			}

			if (existing && !force) {
				if (existing.project.status === "active" && !isTerminalProjectState(existing)) {
					this.bindSession(hooks, root, existing.project.id);
				} else {
					this.activeRoot = resolve(root);
				}
				return toolText(
					`项目已存在: ${existing.project.id} status=${existing.project.status} phase=${existing.project.phase}\n` +
						`用 nuwa_init(resume=true) 继续，或 nuwa_init(force=true) 重建（旧 state 自动备份）。\n\n${statusBoardZeroWrite(existing, root, this.resolveAgentHome(hooks))}`,
					{ root, existing: true, ...autoStartMeta },
				);
			}

			if (!rawTarget) throw new Error("target 必填（新建项目时）");
			if (existing && force) {
				backupExistingProjectState(root);
			}
			const goal = typeof p.goal === "string" ? p.goal : "";
			const st = newState(rawTarget, goal, mode, curCfg, sid, scopeOverride);
			st.project.toolchain = probeToolchain();
			st.project.sandboxMode = readSandboxConfig().mode;
			ensurePrimaryAsset(st);

			const shouldAutoStart =
				(autoStartRequested || (process.env.NUWA_AUTO_ON_INIT ?? "").trim() === "1") && hostCanExecAuto;
			let autoIds: string[] = [];
			withLock(root, () => {
				seedPhase(st, "recon");
				if (shouldAutoStart) autoIds = claimAutoBatch(st, curCfg, root);
				st.runtime.rulesSource = checkAndLogAutoRuleSource(root, st);
				saveState(root, st, { reason: "init" });
			});
			const wsIntegrity = verifyWorkspaceIntegrity(root, { recordBaseline: true });
			const tmpWarn = checkWorkspaceTempWarning(root);
			try {
				mkdirSync(`/tmp/nuwa/${st.project.id}`, { recursive: true });
			} catch {
				/* 非默认权限目录忽略 */
			}
			writePointer(root, sid);
			this.bindSession(hooks, root, st.project.id);
			logEvent(root, { type: "init", id: st.project.id, url: st.project.url, mode: st.project.mode });
			this.refreshUi(hooks, root, st, true);
			if (autoIds.length > 0) {
				hooks.onStartAutoBatch?.(root, autoIds);
			}

			const warnSuffix = tmpWarn ? `\n⚠ ${tmpWarn.message}` : "";
			const autoStartSuffix =
				"autoStartNote" in autoStartMeta && autoStartMeta.autoStartNote ? `\nℹ ${autoStartMeta.autoStartNote}` : "";
			return toolText(`女娲已上膛: ${st.project.id}${warnSuffix}${autoStartSuffix}\n\n${statusBoard(st, root)}`, {
				root,
				project: st.project.id,
				integrity: wsIntegrity.status,
				...(tmpWarn ? { workspaceWarning: tmpWarn } : {}),
				...autoStartMeta,
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execPlan(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；先 nuwa_init");
			const phaseArg = p.phase !== undefined ? String(p.phase) : undefined;
			if (phaseArg !== undefined && !VALID_PHASES.has(phaseArg as Phase)) {
				throw new Error(`非法 phase: ${phaseArg}`);
			}
			const force = typeof p.force === "boolean" ? p.force : undefined;
			const cooldownMs =
				typeof p.cooldown_ms === "number" && Number.isFinite(p.cooldown_ms) ? p.cooldown_ms : undefined;
			const rawIntents = Array.isArray(p.intents) ? p.intents : [];
			const inflightReg = getInflightRegistry(root);
			const added: string[] = [];
			const rejectedReasons: RejectedIntentEntry[] = [];
			let batchPlanOut: ChunkBatchResult<BatchTaskItem> | undefined;
			let egressEnvOut: Record<string, string> | undefined;

			const updated = withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("state 不存在；先 nuwa_init");
				if (isTerminalProjectState(s)) {
					throw new Error(`项目已处于终态 (${terminalStatusOf(s)})，禁止继续 nuwa_plan 派生意图`);
				}

				for (const it of Object.values(s.intents)) {
					if (it.status === "claimed") {
						const tk = it.targetKey ?? extractIntentTargetKey(it, s.project.host);
						if (tk && !tk.startsWith("seed:")) {
							inflightReg.claim(tk, { intentId: it.id, worker: it.worker ?? "fujiang", claimedAt: it.claimedAt });
						}
					}
				}

				const prefilteredIntents: AddIntentInput[] = [];
				for (const rawItem of rawIntents) {
					if (!isPlainRecord(rawItem) || typeof rawItem.title !== "string" || !rawItem.title.trim()) {
						throw new Error("intents 条目必须包含非空字符串 title");
					}
					if (rawItem.phase !== undefined && !VALID_PHASES.has(String(rawItem.phase) as Phase)) {
						throw new Error(`非法 intent.phase: ${String(rawItem.phase)}`);
					}
					if (rawItem.expectedKind !== undefined && !VALID_FACT_KINDS.has(String(rawItem.expectedKind) as FactKind)) {
						throw new Error(`非法 intent.expectedKind: ${String(rawItem.expectedKind)}`);
					}
					if (
						rawItem.surfaceDomain !== undefined &&
						!VALID_DOMAINS.has(String(rawItem.surfaceDomain) as SurfaceDomain)
					) {
						throw new Error(`非法 intent.surfaceDomain: ${String(rawItem.surfaceDomain)}`);
					}
					const title = rawItem.title;
					const detail = typeof rawItem.detail === "string" ? rawItem.detail : undefined;
					const itemPhase = (rawItem.phase as Phase | undefined) ?? (phaseArg as Phase | undefined) ?? s.project.phase;
					const targetKeyRaw =
						typeof rawItem.targetKey === "string"
							? rawItem.targetKey
							: typeof rawItem.target === "string"
								? rawItem.target
								: undefined;
					const candKey = extractIntentTargetKey(
						{
							title,
							detail,
							targetKey: targetKeyRaw,
							phase: itemPhase,
						},
						s.project.host,
					);
					const itemForce = Boolean(rawItem.force);
					if (!force && !itemForce && candKey && !candKey.startsWith("seed:") && inflightReg.isInflight(candKey)) {
						rejectedReasons.push({ title, targetKey: candKey, reason: "inflight" });
						continue;
					}
					prefilteredIntents.push({
						title,
						...(detail !== undefined ? { detail } : {}),
						...(rawItem.phase !== undefined ? { phase: rawItem.phase as Phase } : {}),
						...(Array.isArray(rawItem.from) ? { from: rawItem.from.map((x) => String(x)) } : {}),
						...(typeof rawItem.priority === "number" ? { priority: rawItem.priority } : {}),
						...(typeof rawItem.target === "string" ? { target: rawItem.target } : {}),
						...(typeof rawItem.targetKey === "string" ? { targetKey: rawItem.targetKey } : {}),
						...(typeof rawItem.hint === "string" ? { hint: rawItem.hint } : {}),
						...(rawItem.expectedKind !== undefined ? { expectedKind: rawItem.expectedKind as FactKind } : {}),
						...(rawItem.surfaceDomain !== undefined ? { surfaceDomain: rawItem.surfaceDomain as SurfaceDomain } : {}),
						...(rawItem.force !== undefined ? { force: Boolean(rawItem.force) } : {}),
					});
				}

				const planRes = planIntents(
					s,
					{
						phase: phaseArg as Phase | undefined,
						intents: prefilteredIntents,
						force,
						cooldownMs,
					},
					curCfg,
				);
				added.push(...planRes.added);
				rejectedReasons.push(...planRes.rejectedReasons);

				// 含口令 egress 代理 URL 统一掩码脱敏，杜绝在返回细节、分片文件或状态中泄露明文凭据
				const egressInput = typeof p.egress === "string" ? p.egress : resolveConfiguredEgressUrl();
				const activeEgress = normalizeTaskEgressUrl(egressInput);
				const safeEgress = activeEgress ? maskEgressUrl(activeEgress) : undefined;
				if (safeEgress) {
					egressEnvOut = injectEgressEnv(safeEgress, {});
					for (const id of planRes.added) {
						const created = s.intents[id];
						if (created && !created.detail.includes("NUWA_EGRESS")) {
							const curlArgs = buildCurlProxyArgs(safeEgress).join(" ");
							created.detail = `${created.detail ? `${created.detail}\n` : ""}[出口注入] NUWA_EGRESS=${safeEgress} (curl 附加: ${curlArgs})`;
						}
					}
				}

				if (Array.isArray(p.batch_tasks) && p.batch_tasks.length > 0) {
					const filterRes = inflightReg.filterTasks(p.batch_tasks as BatchTaskItem[], { autoClaim: false });
					for (const sk of filterRes.skipped) {
						rejectedReasons.push({
							title: String(sk.task.title ?? sk.task.id ?? sk.targetKey),
							targetKey: sk.targetKey,
							reason: "inflight",
						});
					}
					const enrichedTasks: BatchTaskItem[] = filterRes.accepted.map((item) => {
						const pkt = buildDispatchPacket({
							task: String(item.task ?? ""),
							targetKey: typeof item.targetKey === "string" ? item.targetKey : undefined,
							target: {
								url: s.project.url,
								host: s.project.host,
								...(safeEgress ? { egress: safeEgress } : {}),
							},
						});
						return {
							...item,
							task: safeEgress ? injectEgressIntoScript(pkt.task, safeEgress) : pkt.task,
							targetKey: pkt.targetKey || item.targetKey,
						};
					});
					batchPlanOut = chunkBatchTasks(enrichedTasks, { root });
				}

				saveState(root, s);
				return s;
			});

			const rejSummary = rejectedReasons.length
				? `\n抑制重复/冷却/在途 (${rejectedReasons.length} 条): ${rejectedReasons.map((r) => `${r.targetKey}[${r.reason}]`).slice(0, 8).join(", ")}`
				: "";
			const batchSummary = batchPlanOut
				? `\n批派单分片: mode=${batchPlanOut.mode} chunks=${batchPlanOut.chunks.length} totalBytes=${batchPlanOut.totalBytes}${batchPlanOut.tasks_file ? ` tasks_file=${batchPlanOut.tasks_file}` : ""}`
				: "";
			return toolText(
				`已追加 ${added.length} 条意图: ${added.join(" ") || "(无新增，均已存在或被抑制)"}${rejSummary}${batchSummary}\nphase=${updated.project.phase}\n\n${statusBoard(updated, root)}`,
				{
					root,
					added,
					rejectedReasons,
					...(batchPlanOut ? { batch: batchPlanOut } : {}),
					...(egressEnvOut ? { egressEnv: egressEnvOut } : {}),
				},
			);
		} catch (e) {
			return toolError(e);
		}
	}

	private execFrontier(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const st = loadStateZeroWrite(root) ?? loadState(root);
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			const limit = typeof p.limit === "number" && Number.isFinite(p.limit) ? Math.max(1, Math.floor(p.limit)) : 12;
			const items = frontierList(st, limit, curCfg.claimTtl, root);
			if (!items.length) {
				return toolText("frontier 为空。用 nuwa_plan 播种下一阶段，或 nuwa_status 查依赖。", { root, ids: [] });
			}
			return toolText(
				items
					.map(
						(it) =>
							`${it.intent.id}\t${it.intent.phase}\t${it.intent.title}\tfrom=${it.intent.from.join(",") || "-"}\tattempts=${it.intent.attempts}${it.stale ? "\tstale" : ""}`,
					)
					.join("\n"),
				{ root, ids: items.map((i) => i.intent.id) },
			);
		} catch (e) {
			return toolError(e);
		}
	}

	private execClaim(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const curCfg = readCfg();
			const id = typeof p.id === "string" ? p.id.trim() : "";
			if (!id) throw new Error("参数 id 必填");
			const worker = typeof p.worker === "string" && p.worker.trim() ? p.worker.trim() : "fujiang";
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");

			let packet = "";
			let stale = false;
			let expectedKind: FactKind | undefined;
			let targetKey = "";
			const egressInput = typeof p.egress === "string" ? p.egress : resolveConfiguredEgressUrl();
			const activeEgress = normalizeTaskEgressUrl(egressInput);
			const safeEgress = activeEgress ? maskEgressUrl(activeEgress) : undefined;

			withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				if (isTerminalProjectState(s)) {
					throw new Error(`项目已处于终态 (${terminalStatusOf(s)})，禁止继续认领 nuwa_claim`);
				}
				const r = claimIntent(s, id, worker, curCfg.claimTtl, root);
				expectedKind = r.intent.expectedKind;
				targetKey = r.intent.targetKey ?? "";
				const injected = injectResolvedTargetContext(r.packet, {
					url: s.project.url,
					host: s.project.host,
					...(safeEgress ? { egress: safeEgress } : {}),
				});
				packet = injected.task;
				if (safeEgress) {
					const proxyArgs = buildCurlProxyArgs(safeEgress).join(" ");
					packet += `\n\n[出口强制注入]: 已配置出口 ${safeEgress}；首步须对目标执行 Gate 探活（如统一 403/WAF 阻断立即报 egress_blocked 停止盲扫），所有 curl 须携带 ${proxyArgs}`;
				}
				stale = r.stale;
				if (targetKey && !targetKey.startsWith("seed:")) {
					getInflightRegistry(root).claim(targetKey, {
						intentId: id,
						worker,
						claimedAt: r.intent.claimedAt,
					});
				}
				saveState(root, s);
				logEvent(root, { type: "claim", id, worker, stale, expectedKind, targetKey });
			});

			return toolText(packet, {
				root,
				id,
				stale,
				...(expectedKind ? { expectedKind } : {}),
				...(targetKey ? { targetKey } : {}),
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execCommit(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const pre = loadState(root);
			if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			if (isTerminalProjectState(pre)) {
				throw new Error(`项目已处于终态 (${terminalStatusOf(pre)})，禁止继续 nuwa_commit 篡改终态图谱`);
			}

			if (p.kind !== undefined && !VALID_FACT_KINDS.has(String(p.kind) as FactKind)) {
				throw new Error(`非法 kind: ${String(p.kind)}`);
			}

			let parsedAgentObj: Record<string, unknown> | undefined;
			let effTitle = typeof p.title === "string" ? p.title : "";
			let effDetail = typeof p.detail === "string" ? p.detail : "";
			let effCommand = typeof p.command === "string" ? p.command : undefined;
			let effOutput = typeof p.output === "string" ? p.output : undefined;
			let effBlocked = Boolean(p.blocked ?? false);
			let effNote = typeof p.note === "string" ? p.note : undefined;

			if (p.agent_result !== undefined) {
				const parsed = parseAgentResult(p.agent_result as string | Record<string, unknown>);
				if (!parsed.ok || !parsed.result) {
					throw new Error(`结构化 agent_result 解析失败: ${parsed.error ?? "非法回包格式"}`);
				}
				const ar = parsed.result;
				parsedAgentObj = ar as unknown as Record<string, unknown>;
				if (!effTitle && ar.summary) effTitle = ar.summary;
				if (!effDetail && (ar.summary || ar.next)) {
					effDetail = [ar.summary, ar.next ? `下一步: ${ar.next}` : ""].filter(Boolean).join(" | ");
				}
				if (p.blocked === undefined || (p.blocked === false && ar.blocked && !effCommand && !effOutput)) {
					effBlocked = ar.blocked;
				}
				if (effBlocked && !effNote && (ar.blockedReason || ar.summary)) {
					effNote = ar.blockedReason || ar.summary;
				}
				const firstEv = ar.evidence[0];
				if (firstEv) {
					if (!effCommand && firstEv.cmd) effCommand = firstEv.cmd;
					if (!effOutput) effOutput = formatAgentEvidenceOutput(firstEv);
				}
			}

			const rawId = typeof p.id === "string" ? p.id.trim() : "";
			const isFree = !rawId || p.free_note === true;
			const targetIntent = !isFree ? pre.intents[rawId] : undefined;
			const intentKey = targetIntent?.key ?? "";
			const explicitKindArg = p.kind !== undefined ? (String(p.kind) as FactKind) : undefined;
			let effectiveKind: FactKind = (explicitKindArg ?? targetIntent?.expectedKind ?? "note") as FactKind;
			let explicitKind: FactKind | undefined = explicitKindArg;

			if (!effBlocked) {
				const realism = checkCommitRealismGuard(
					pre,
					{ command: effCommand, output: effOutput, detail: effDetail },
					Boolean(p.strict_realism),
				);
				if (!realism.ok) {
					logEvent(root, {
						type: "deliverable_rejected",
						id: rawId || "free",
						kind: effectiveKind,
						violations: realism.result.violations,
					});
					throw new Error(realism.reason);
				}
			}

			const isVerifyCommit = !isFree && !effBlocked && isVerifyVulnIntentKey(intentKey);
			const verifyTargetFid = isVerifyCommit ? extractVerifyTargetFactId(intentKey) : null;
			const candidateFact = verifyTargetFid ? pre.facts[verifyTargetFid] : undefined;

			if (isVerifyCommit) {
				const vc = validateVerificationCommit({
					intentKey,
					kind: effectiveKind,
					blocked: effBlocked,
					worker: targetIntent?.worker,
					candidateFact,
				});
				if (!vc.ok) {
					logEvent(root, { type: "verify_commit_rejected", id: rawId, kind: effectiveKind, reason: vc.reason });
					throw new Error(`双盲复验门禁拒绝: ${vc.reason ?? "复验提交不合规"}`);
				}
			}

			let downgradedFalsePositive = false;
			let fpGateResult: PositiveEvidenceGateResult | undefined;
			const rawResponseStr = typeof p.raw_response === "string" ? p.raw_response : undefined;
			if (!effBlocked && (effectiveKind === "vuln" || effectiveKind === "cred" || effectiveKind === "loot")) {
				const rawCheckText = String(rawResponseStr ?? effOutput ?? "");
				const hasBodyOrBaseline =
					p.baseline !== undefined ||
					rawResponseStr !== undefined ||
					rawCheckText.replace(/\r\n/g, "\n").includes("\n\n") ||
					rawCheckText.trim().startsWith("{");
				if (hasBodyOrBaseline) {
					const posGate = evaluatePositiveEvidenceGate({
						kind: effectiveKind,
						output: rawCheckText,
						baseline: p.baseline as Parameters<typeof evaluatePositiveEvidenceGate>[0]["baseline"],
					});
					if (!posGate.ok && posGate.falsePositive) {
						fpGateResult = posGate;
						// 反自证校准机械对账：命中假阳性门禁时统一由机械源 verifier-gate 结算 outcome=0
						if (!isFree && rawId && hasCalibrationRecords(root)) {
							try {
								for (const rec of loadCalibrationRecords(root)) {
									if (!rec.settled && rec.intentId === rawId) {
										safeSettlePrediction(root, {
											predictionId: rec.predictionId,
											outcome: 0,
											isFalsePositive: true,
											actualTokens: rec.estimatedTokens || Math.max(0, Number(pre.runtime.tokens ?? 0)),
											durationMs: 0,
											source: "verifier-gate",
											note: `假阳性复核门禁拦截 (${posGate.matchedSignals.join(",")})`,
										});
									}
								}
							} catch {
								/* ignore calibration settlement error */
							}
						}
						logEvent(root, {
							type: "false_positive_intercepted",
							id: rawId || "free",
							kind: effectiveKind,
							signals: posGate.matchedSignals,
							autoDowngrade: Boolean(p.auto_downgrade),
						});
						if (p.auto_downgrade) {
							const fpNote = buildFalsePositiveNote(
								{ id: rawId || "free", kind: effectiveKind, title: effTitle || "candidate" },
								posGate.reason ?? "假阳性复核未通过",
							);
							effectiveKind = "note";
							explicitKind = "note";
							effTitle = fpNote.title;
							effDetail = `${fpNote.detail}${effDetail ? `\n原描述: ${effDetail}` : ""}`;
							downgradedFalsePositive = true;
						} else {
							return toolError(posGate.reason ?? '假阳性复核拦截：建议降级以 kind="note" 记账', {
								root,
								id: rawId || "free",
								falsePositive: true,
								suggestedKind: posGate.suggestedKind ?? "note",
								recommendedAction: posGate.recommendedAction,
								matchedSignals: posGate.matchedSignals,
							});
						}
					}
				}
			}

			let verifiedFlag: boolean | undefined;
			if (!effBlocked && (effectiveKind === "vuln" || effectiveKind === "cred" || effectiveKind === "flag")) {
				const strict = (process.env.NUWA_STRICT_EVIDENCE ?? "").trim() === "1";
				const extractedFlag =
					effectiveKind === "flag"
						? (`${effTitle} ${effDetail} ${effOutput ?? ""}`.match(/flag\{[^}\s]{2,}\}/i)?.[0] ?? undefined)
						: undefined;
				const vr = verifyExecutionEvidence(root, {
					projectId: pre.project.id,
					kind: effectiveKind,
					command: effCommand,
					output: effOutput,
					flagValue: extractedFlag,
					strict: strict || isVerifyCommit,
					...(isVerifyCommit
						? {
								minSeq: candidateFact?.evidenceSeq ?? 0,
								...(candidateFact?.createdAt ? { sinceTs: candidateFact.createdAt } : {}),
								requireSubstantive: true,
							}
						: effectiveKind === "vuln"
							? { requireSubstantive: true }
							: {}),
				});
				if (!vr.ok) {
					logEvent(root, { type: "evidence_rejected", id: rawId || "free", kind: effectiveKind, reason: vr.reason });
					throw new Error(`证据复验未通过: ${vr.reason ?? "未在真实执行账本中核验到对应输出"}`);
				}
				verifiedFlag = vr.verified;
			}

			const evidenceRefArg = typeof p.evidence_ref === "string" && p.evidence_ref.trim() ? p.evidence_ref.trim() : undefined;
			const commitRes = executeCommitWithGates(
				root,
				{
					id: isFree ? undefined : rawId,
					freeNote: isFree,
					kind: explicitKind,
					title: effTitle,
					detail: effDetail,
					command: effCommand,
					output: effOutput,
					blocked: effBlocked,
					note: effNote,
					evidenceRef: evidenceRefArg,
					agentResult: parsedAgentObj,
				},
				verifiedFlag,
			);

			if (rawId) {
				getInflightRegistry(root).releaseByIntent(rawId);
			}

			let finalState = commitRes.state;
			let savedEvLog: SavedEvidenceLog | undefined;
			if (!effBlocked && (Boolean(p.save_evidence_log) || rawResponseStr !== undefined)) {
				// 精确使用完整 factId（如 f001、f1000、f12345），严禁 3 位数字截断
				const exactFactId =
					commitRes.factId ??
					(!isFree && finalState.intents[rawId]?.to ? finalState.intents[rawId]!.to : undefined);
				if (exactFactId) {
					savedEvLog = saveFactEvidenceLog(root, {
						factId: exactFactId,
						command: effCommand,
						output: effOutput,
						rawResponse: rawResponseStr,
					});
					finalState = withLock(root, () => {
						const s = loadState(root) ?? finalState;
						if (s.facts[exactFactId]) {
							s.facts[exactFactId]!.evidenceRef = savedEvLog!.evidenceRef;
							saveState(root, s);
						}
						return s;
					});
				}
			}

			this.refreshUi(hooks, root, finalState);
			const blockedSummaryLine = `blocked_stats: blockedIntents=${commitRes.blockedIntents}(${commitRes.blockedIntentsDelta >= 0 ? "+" : ""}${commitRes.blockedIntentsDelta}) · blockedCommits=${commitRes.blockedCommits}(+${commitRes.blockedCommitsDelta})`;
			const resolvedEvRef = savedEvLog?.evidenceRef ?? evidenceRefArg;
			const evRefLine = savedEvLog
				? `\nevidence_ref: ${savedEvLog.evidenceRef} (${savedEvLog.bytes}B)`
				: evidenceRefArg
					? `\nevidence_ref: ${evidenceRefArg}`
					: "";
			const fpLine = downgradedFalsePositive ? `\n假阳性门禁自动降级: 已转为 note(false_positive) 入账` : "";

			return toolText(`${commitRes.text}${fpLine}${evRefLine}\n${blockedSummaryLine}\n\n${statusBoard(finalState, root)}`, {
				root,
				id: rawId || "free",
				...(commitRes.factId ? { factId: commitRes.factId } : {}),
				freeFact: isFree,
				inheritedKind: p.kind === undefined ? effectiveKind : undefined,
				blockedIntents: commitRes.blockedIntents,
				blockedCommits: commitRes.blockedCommits,
				blockedIntentsDelta: commitRes.blockedIntentsDelta,
				blockedCommitsDelta: commitRes.blockedCommitsDelta,
				...(resolvedEvRef ? { evidenceRef: resolvedEvRef } : {}),
				...(downgradedFalsePositive
					? { falsePositive: true, suggestedKind: "note", matchedSignals: fpGateResult?.matchedSignals }
					: {}),
				...(commitRes.verifyStageOut ? { verifyStage: commitRes.verifyStageOut } : {}),
				...(commitRes.verifyIntentId ? { verifyIntent: commitRes.verifyIntentId } : {}),
				...(commitRes.ingestedRole ? { role: commitRes.ingestedRole } : {}),
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execFlag(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const value = typeof p.value === "string" ? p.value : "";
			const command = typeof p.command === "string" ? p.command : "";
			const output = typeof p.output === "string" ? p.output : "";
			if (!value || !command || !output) {
				throw new Error("参数 value、command、output 必填");
			}
			const challenge = typeof p.challenge === "string" ? p.challenge : undefined;
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const pre = loadState(root);
			if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			if (isTerminalProjectState(pre)) {
				throw new Error(`项目已处于终态 (${terminalStatusOf(pre)})，禁止继续 nuwa_flag 写入 flag`);
			}

			const strict = (process.env.NUWA_STRICT_EVIDENCE ?? "").trim() === "1";
			const vr = verifyExecutionEvidence(root, {
				projectId: pre.project.id,
				kind: "flag",
				command,
				output,
				flagValue: value,
				strict,
			});
			if (!vr.ok) {
				logEvent(root, { type: "evidence_rejected", kind: "flag", value: value.slice(0, 32), reason: vr.reason });
				throw new Error(`证据复验未通过: ${vr.reason ?? "flag 未在真实工具执行账本中出现"}`);
			}

			let fact = "";
			let dup = false;
			const updated = withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				if (isTerminalProjectState(s)) {
					throw new Error(`项目已处于终态 (${terminalStatusOf(s)})，禁止继续 nuwa_flag 写入 flag`);
				}
				const r = recordFlag(s, value, command, output, challenge, vr.verified);
				fact = r.fact.id;
				dup = r.duplicate ?? false;
				saveState(root, s, { reason: "flag" });
				logEvent(root, { type: "flag", fact, value: value.slice(0, 32), verified: vr.verified, duplicate: dup });
				return s;
			});
			this.refreshUi(hooks, root, updated, true);
			return toolText(`${dup ? "幂等命中" : "flag 已入账"}: ${fact} = ${value}`, {
				root,
				fact,
				verified: vr.verified,
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execComplete(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const liveTokens = Number(hooks.getLiveTokens?.() ?? 0);

			if (Boolean(p.seal)) {
				const existingPre = loadStateZeroWrite(root) ?? loadState(root);
				if (!existingPre) {
					throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				}
				if (isTerminalProjectState(existingPre) && terminalStatusOf(existingPre) === "completed") {
					throw new Error(`项目已完成验收 (status=completed)，禁止通过 seal=true 降级篡改为 sealed_negative`);
				}

				const rawReason = typeof p.reason === "string" ? p.reason : typeof p.note === "string" ? p.note : "";
				const sealReason = rawReason.trim() || "攻击面已全面验证排除且无正向突破，执行负向封盘";
				this.abortAutoBatch(hooks, root, "sealed_negative");

				if (Number.isFinite(liveTokens) && liveTokens > 0) {
					withLock(root, () => {
						const pre = loadState(root);
						if (pre && liveTokens > (pre.runtime.tokens ?? 0)) {
							pre.runtime.tokens = liveTokens;
							saveState(root, pre);
						}
					});
				}

				const excludedSurface = Array.isArray(p.excluded_surface)
					? p.excluded_surface.map((item) => String(item))
					: undefined;
				const coverage = isPlainRecord(p.coverage) ? p.coverage : undefined;
				const sealed = sealEngagement(root, {
					reason: sealReason,
					excludedSurface,
					coverage,
				});
				withLock(root, () => {
					const post = loadState(root);
					if (post) {
						post.runtime.reportWritten = true;
						saveState(root, post, { reason: "seal-report-flag" });
					}
				});
				sealed.state.runtime.reportWritten = true;
				const reportPath = syncTerminalReports(root, sealed.state, { writeMd: true });
				cleanupTrackedProcesses(root, { reason: "nuwa_complete:seal" });
				if (isPausedState(root)) setPausedState(root, false, "sealed_negative");
				try {
					distillProjectExperience(sealed.state, { agentHome: this.resolveAgentHome(hooks), negativeOnly: true });
				} catch {
					/* 蒸馏异常不阻断封盘 */
				}
				this.refreshUi(hooks, root, sealed.state, true);
				const reportHint = reportPath
					? `已自动同步封盘报告: ${reportPath}（如需 json/sarif/bundle 可调 nuwa_report）`
					: `调 nuwa_report(write=true) 导出封盘覆盖报告。`;
				return toolText(
					`负向封盘已完成: ${sealed.state.project.id} (status=${sealed.status})\n` +
						`封盘依据: ${sealed.sealMeta.reason}\n` +
						`已排除面 (${sealed.sealMeta.excludedSurface.length}): ${sealed.sealMeta.excludedSurface.slice(0, 12).join(", ") || "(自动汇总)"}\n\n` +
						reportHint,
					{
						root,
						ok: true,
						sealed: true,
						status: sealed.status,
						sealMeta: sealed.sealMeta,
						...(reportPath ? { reportPath } : {}),
					},
				);
			}

			const curCfg = readCfg();
			const fromList = Array.isArray(p.from) ? p.from.map((x) => String(x)) : undefined;
			const noteStr = typeof p.note === "string" ? p.note : undefined;
			let res: { ok: boolean; reason?: string; from: string[]; convergence?: ConvergenceAdvice } = {
				ok: false,
				from: [],
			};

			const updated = withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				if (isTerminalProjectState(s) && terminalStatusOf(s) === "sealed_negative") {
					throw new Error("项目已处于负向封盘终态 (status=sealed_negative)，不可直接改为 completed");
				}
				if (Number.isFinite(liveTokens) && liveTokens > (s.runtime.tokens ?? 0)) {
					s.runtime.tokens = liveTokens;
				}
				res = completeProject(s, fromList, noteStr);
				if (res.ok) {
					s.runtime.status = "completed";
				}
				saveState(root, s, res.ok ? { reason: "complete" } : undefined);
				logEvent(root, { type: "complete", ok: res.ok, from: res.from, reason: res.reason });
				return s;
			});

			this.refreshUi(hooks, root, updated, true);
			if (!res.ok) {
				const convergence = res.convergence ?? buildConvergenceAdvice(updated, curCfg, root);
				const sealRec = shouldRecommendSeal(updated, curCfg, root);
				const convText = convergence.active
					? `\n${convergence.message}\n收敛出口: nuwa_report(write=true) 后调 nuwa_complete(seal=true, reason="...", excluded_surface=[...])`
					: "";
				return toolText(
					`完成被拒: ${res.reason}\nrejects=${updated.runtime.completionRejects}${convText}\n\n${statusBoard(updated, root)}`,
					{
						root,
						ok: false,
						reason: res.reason,
						rejects: updated.runtime.completionRejects,
						convergence,
						recommendSeal: sealRec,
					},
				);
			}

			const syncedPath = syncTerminalReports(root, updated, { writeMd: false });
			cleanupTrackedProcesses(root, { reason: "nuwa_complete:completed" });
			let distillLine = "";
			let distilledCount = 0;
			try {
				const dist = distillProjectExperience(updated, { agentHome: this.resolveAgentHome(hooks) });
				distilledCount = dist.updated;
				logEvent(root, {
					type: "experience_distill",
					techKeys: dist.techKeys,
					updated: dist.updated,
					positive: dist.positive,
					negative: dist.negative,
				});
				if (dist.updated > 0) {
					distillLine = `\n自进化经验回流: 已脱敏沉淀 ${dist.updated} 条跨项目经验（技术栈: ${dist.techKeys.join(", ")}）`;
				}
			} catch {
				/* 蒸馏异常不阻断验收返回 */
			}

			return toolText(
				`完成已验收: ${updated.project.id}\n证据: ${res.from.join(",")}${distillLine}\n\n${syncedPath ? `已同步更新报告: ${syncedPath}` : "调 nuwa_report(write=true) 生成报告。"}`,
				{ root, ok: true, status: "completed", distilled: distilledCount, ...(syncedPath ? { reportPath: syncedPath } : {}) },
			);
		} catch (e) {
			return toolError(e);
		}
	}

	private execStatus(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");

			const limit = typeof p.limit === "number" && Number.isFinite(p.limit) ? p.limit : undefined;
			const offset = typeof p.offset === "number" && Number.isFinite(p.offset) ? p.offset : undefined;
			const fmt = p.format === "json" || p.format === "text" ? p.format : undefined;
			if (p.format !== undefined && fmt === undefined) {
				throw new Error(`非法 format: ${String(p.format)}`);
			}

			// 1) 纯只读跨轮归档检索（严格零磁盘写入）
			if (p.archive_query !== undefined) {
				const q: string | ArchiveSearchQuery =
					typeof p.archive_query === "string"
						? { text: p.archive_query, ...(limit !== undefined ? { limit } : {}) }
						: { ...(p.archive_query as ArchiveSearchQuery), ...(limit !== undefined ? { limit } : {}) };
				const hits = searchArchiveIndexes(root, q);
				if (fmt === "json") {
					return toolText(JSON.stringify({ ok: true, count: hits.length, hits }, null, 2), {
						root,
						readonly: true,
						archiveHits: hits,
					});
				}
				const body = hits.length
					? hits
							.map(
								(h) =>
									`[E${h.episode} · ${h.source}] ${h.factId ?? "-"} ${h.title ?? h.command ?? ""} status=${h.statusCode ?? "-"} bytes=${h.bytes ?? "-"} sha256=${h.bodySha256?.slice(0, 12) ?? "-"} :: ${h.snippet}`,
							)
							.join("\n")
					: "(未命中匹配的归档记录)";
				return toolText(`归档检索命中 ${hits.length} 条:\n${body}`, {
					root,
					readonly: true,
					archiveHits: hits,
				});
			}

			// 2) 纯只读图诊断接口（严格零磁盘写入）
			if (p.inspect_intent !== undefined || p.query_status !== undefined || p.target_key !== undefined) {
				if (p.query_status !== undefined && !VALID_INTENT_STATUS.has(String(p.query_status) as IntentStatus)) {
					throw new Error(`非法 query_status: ${String(p.query_status)}`);
				}
				const diag = inspectGraph(root, {
					intentId: typeof p.inspect_intent === "string" ? p.inspect_intent : undefined,
					status: p.query_status as IntentStatus | undefined,
					targetKey: typeof p.target_key === "string" ? p.target_key : undefined,
					limit,
				});
				if (!diag.ok) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init");
				if (fmt === "json") {
					return toolText(JSON.stringify(diag, null, 2), { root, readonly: true, inspect: diag });
				}
				const rows = diag.intents.map(
					(it) =>
						`${it.id}\t[${it.status}]\t${it.phase}\tdomain=${it.resolvedSurfaceDomain}\tkind=${it.resolvedExpectedKind}\ttarget=${it.resolvedTargetKey}\ttitle=${it.title}${it.note ? `\tnote=${it.note}` : ""}${it.to ? `\tto=${it.to}` : ""}`,
				);
				const header =
					`只读图诊断 (${diag.project?.id ?? "unknown"}) · matched=${diag.matchedCount}/${diag.summary.totalIntents} · ` +
					`repeat_ratio=${diag.summary.repeatRatio.toFixed(2)} · blockedIntents=${diag.summary.blockedIntents} · blockedCommits=${diag.summary.blockedCommits}`;
				return toolText(`${header}\n${rows.join("\n") || "(无匹配意图)"}`, {
					root,
					readonly: true,
					inspect: diag,
				});
			}

			// 3) 不截断全量/分页状态输出（严格零磁盘写入）
			if (p.raw !== undefined || offset !== undefined || limit !== undefined || fmt !== undefined) {
				const fullText = renderFullStatus(root, {
					raw: typeof p.raw === "boolean" ? p.raw : undefined,
					offset,
					limit,
					format: fmt,
				});
				return toolText(fullText, {
					root,
					readonly: true,
					format: fmt ?? "text",
					raw: Boolean(p.raw),
				});
			}

			// 4) 默认状态看板：强制通过 loadStateZeroWrite 加载，确保在任何存储后端下 100% 零磁盘写入
			const st = loadStateZeroWrite(root);
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			this.refreshUi(hooks, root, st);
			const rep = computeRepeatRatio(st);
			const probe = extractProbeHealth(st);
			const blockedIntents = Object.values(st.intents).filter((i) => i.status === "blocked").length;
			const blockedCommits = st.runtime.blockedCommits ?? blockedIntents;
			const paused = isPausedState(root);
			const effectiveStatus =
				st.runtime.status === "sealed_negative" || st.project.status === "sealed_negative"
					? "sealed_negative"
					: st.runtime.status === "completed" || st.project.status === "completed"
						? "completed"
						: st.project.status;
			const curTokens = st.runtime.tokens ?? 0;
			const totalTokens = (st.runtime.totalTokens ?? 0) + curTokens;
			const metricsLine = `metrics: repeat_ratio=${rep.repeatRatio.toFixed(2)} · last_ok=${probe.lastOk} · blockedIntents=${blockedIntents} · blockedCommits=${blockedCommits} · tokens=${curTokens} · totalTokens=${totalTokens}${paused ? " · paused=true" : ""}`;
			return toolText(`${statusBoardZeroWrite(st, root, this.resolveAgentHome(hooks))}\n${metricsLine}`, {
				root,
				readonly: true,
				status: effectiveStatus,
				paused,
				repeat_ratio: rep.repeatRatio,
				last_ok: probe.lastOk,
				blockedIntents,
				blockedCommits,
				tokens: curTokens,
				totalTokens,
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execReport(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const roProbe = loadStateZeroWrite(root);
			let st =
				roProbe && isTerminalProjectState(roProbe)
					? roProbe
					: ((Boolean(p.write) || Boolean(p.finalize_phase) ? loadState(root) : roProbe) ?? loadState(root));
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			const fmtRaw = p.format === undefined ? "md" : String(p.format);
			if (!VALID_REPORT_FORMATS.has(fmtRaw)) {
				throw new Error(`非法 format: ${fmtRaw}`);
			}
			const fmt = fmtRaw as "md" | "json" | "sarif" | "timeline";
			const write = Boolean(p.write ?? false);
			const bundle = Boolean(p.bundle ?? false);
			const archive = Boolean(p.archive ?? false);
			const finalizePhaseFlag = Boolean(p.finalize_phase ?? false);
			const episode = typeof p.episode === "number" && Number.isFinite(p.episode) ? p.episode : undefined;

			let outText = "";
			let fileName = "REPORT.md";
			if (fmt === "timeline") {
				outText = exportEpisodeTimeline(root, { episode, format: "markdown" });
				fileName = episode !== undefined ? `TIMELINE-E${episode}.md` : "TIMELINE.md";
			} else if (fmt === "sarif") {
				outText = `${JSON.stringify(buildSarifReport(st, root), null, 2)}\n`;
				fileName = "REPORT.sarif.json";
			} else if (fmt === "json") {
				outText = `${JSON.stringify(buildJsonReport(st, root), null, 2)}\n`;
				fileName = "REPORT.json";
			} else {
				outText = redactVaultSecrets(reportMarkdown(st, root), root);
			}

			let path = "";
			if (write) {
				path = join(root, ".nuwa", fileName);
				atomicWrite(path, outText);
			}

			let archiveRes: WriteEpisodeArchiveResult | undefined;
			if (write || archive) {
				const targetEp = episode ?? st.project.episode ?? 1;
				archiveRes = writeEpisodeArchiveIndex(root, {
					episode: targetEp,
					state: st,
					summary: `报告生成 (${fmt})`,
				});
			}

			let phaseTransitionOut: ReportPhaseTransition | undefined;
			if (write || finalizePhaseFlag) {
				if (isTerminalProjectState(st)) {
					const termSt = terminalStatusOf(st);
					if (st.project.phase === "report") {
						phaseTransitionOut = {
							action: termSt === "completed" ? "complete" : "seal_negative",
							reason: `项目已处于终态 (${termSt})，禁止通过 finalize_phase 降级或覆写封盘元数据`,
							canAdvanceEpisode: false,
						};
					}
					if (write && !st.runtime.reportWritten) {
						st = withLock(root, () => {
							const s = loadState(root) ?? st!;
							if (!s.runtime.reportWritten) {
								s.runtime.reportWritten = true;
								saveState(root, s);
							}
							return s;
						});
					}
				} else {
					const curCfg = readCfg();
					st = withLock(root, () => {
						const s = loadState(root) ?? st!;
						if (isTerminalProjectState(s)) {
							const termSt = terminalStatusOf(s);
							if (s.project.phase === "report") {
								phaseTransitionOut = {
									action: termSt === "completed" ? "complete" : "seal_negative",
									reason: `项目已处于终态 (${termSt})，禁止通过 finalize_phase 降级或覆写封盘元数据`,
									canAdvanceEpisode: false,
								};
							}
							if (write && !s.runtime.reportWritten) {
								s.runtime.reportWritten = true;
								saveState(root, s);
							}
							return s;
						}
						const needWriteFlag = write && !s.runtime.reportWritten;
						if (write) s.runtime.reportWritten = true;
						if (finalizePhaseFlag && s.project.phase === "report") {
							const fin = finalizeReportPhase(s, curCfg, {
								root,
								reportWritten: Boolean(write || s.runtime.reportWritten),
								autoSeal: true,
							});
							phaseTransitionOut = fin.transition;
							saveState(root, s);
						} else {
							if (s.project.phase === "report") {
								phaseTransitionOut = resolveReportPhaseTransition(s, {
									reportWritten: Boolean(write || s.runtime.reportWritten),
									maxEpisodes: curCfg.maxEpisodes,
								});
							}
							if (needWriteFlag) {
								saveState(root, s);
							}
						}
						return s;
					});
				}
				this.refreshUi(hooks, root, st, true);
			}

			let bundleDir = "";
			let bundleFiles = 0;
			if (bundle) {
				const b = writePocBundle(root, st);
				bundleDir = b.dir;
				bundleFiles = b.files.length;
			}
			const suffixParts: string[] = [];
			if (path) suffixParts.push(`已写入: ${path}`);
			if (archiveRes) suffixParts.push(`Episode E${archiveRes.episode} 归档索引已更新: ${archiveRes.jsonPath}`);
			if (bundleDir) suffixParts.push(`脱敏证据包已生成: ${bundleDir} (${bundleFiles} 个文件)`);
			if (phaseTransitionOut) {
				suffixParts.push(`report 阶段状态建议: action=${phaseTransitionOut.action} (${phaseTransitionOut.reason})`);
			}
			return toolText(suffixParts.length ? `${outText}\n\n${suffixParts.join("\n")}` : outText, {
				root,
				path,
				format: fmt,
				...(archiveRes ? { archiveJson: archiveRes.jsonPath, archiveMd: archiveRes.markdownPath } : {}),
				...(phaseTransitionOut ? { reportTransition: phaseTransitionOut } : {}),
				...(bundleDir ? { bundleDir, bundleFiles } : {}),
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execExpand(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const inflightReg = getInflightRegistry(root);
			const force = Boolean(p.force ?? false);
			let text = "";
			let rejectedReasons: RejectedIntentEntry[] = [];
			let batchOut: ChunkBatchResult<BatchTaskItem> | undefined;
			const egressInput = typeof p.egress === "string" ? p.egress : resolveConfiguredEgressUrl();
			const activeEgress = normalizeTaskEgressUrl(egressInput);
			const safeEgress = activeEgress ? maskEgressUrl(activeEgress) : undefined;

			const st = withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("state 不存在；先 nuwa_init");
				if (isTerminalProjectState(s)) {
					throw new Error(`项目已处于终态 (${terminalStatusOf(s)})，禁止继续 nuwa_expand 扩展攻击面`);
				}
				const r = autoPlan(s, curCfg);
				rejectedReasons = [...r.rejectedReasons];

				const finalAdded: string[] = [];
				for (const id of r.added) {
					const it = s.intents[id];
					if (!it) continue;
					const tk = it.targetKey ?? extractIntentTargetKey(it, s.project.host);
					if (!force && tk && !tk.startsWith("seed:") && inflightReg.isInflight(tk)) {
						rejectedReasons.push({ title: it.title, targetKey: tk, reason: "inflight" });
						delete s.intents[id];
						continue;
					}
					if (safeEgress && !it.detail.includes("NUWA_EGRESS")) {
						it.detail = `${it.detail ? `${it.detail}\n` : ""}[出口注入] NUWA_EGRESS=${safeEgress}`;
					}
					finalAdded.push(id);
				}

				if (Array.isArray(p.batch_tasks) && p.batch_tasks.length > 0) {
					const filtered = inflightReg.filterTasks(p.batch_tasks as BatchTaskItem[], { autoClaim: false });
					for (const sk of filtered.skipped) {
						rejectedReasons.push({
							title: String(sk.task.title ?? sk.task.id ?? sk.targetKey),
							targetKey: sk.targetKey,
							reason: "inflight",
						});
					}
					const sanitizedAccepted: BatchTaskItem[] = safeEgress
						? filtered.accepted.map((item) => {
								if (typeof item.task !== "string") return item;
								const pkt = buildDispatchPacket({
									task: item.task,
									targetKey: typeof item.targetKey === "string" ? item.targetKey : undefined,
									target: { url: s.project.url, host: s.project.host, egress: safeEgress },
								});
								return {
									...item,
									task: injectEgressIntoScript(pkt.task, safeEgress),
									targetKey: pkt.targetKey || item.targetKey,
								};
							})
						: filtered.accepted;
					batchOut = chunkBatchTasks(sanitizedAccepted, { root });
				}

				saveState(root, s);
				logEvent(root, {
					type: "expand_manual",
					reason: r.reason,
					added: finalAdded,
					rejectedCount: rejectedReasons.length,
					phase: r.phase,
					episode: r.episode,
				});
				const rejNote = rejectedReasons.length ? ` · 抑制 ${rejectedReasons.length} 条` : "";
				text = `扩张: ${r.reason} · phase=${r.phase ?? s.project.phase} · ep=${s.project.episode ?? 1} · 新增 ${finalAdded.length} 条${finalAdded.length ? `: ${finalAdded.join(" ")}` : ""}${rejNote}`;
				return s;
			});

			if (st) this.refreshUi(hooks, root, st, true);
			return toolText(`${text}\n\n${st ? statusBoard(st, root) : ""}`, {
				root,
				rejectedReasons,
				...(batchOut ? { batch: batchOut } : {}),
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execStop(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root, hooks);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const st = loadStateZeroWrite(root) ?? loadState(root);
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			if (isTerminalProjectState(st)) {
				const termStatus = terminalStatusOf(st);
				this.refreshUi(hooks, root, st, true);
				return toolText(
					`项目已处于终态 (${termStatus}): ${st.project.id}（终态不可通过 nuwa_stop 降级为 stopped/paused）`,
					{ root, stopped: false, paused: false, terminal: true, status: termStatus },
				);
			}

			const rawReason = p.reason === undefined ? "manual stop/pause" : String(p.reason);
			if (p.pause === true) {
				const pauseReason = rawReason.trim() || "manual soft pause";
				this.abortAutoBatch(hooks, root, `paused:${pauseReason}`);
				const pausedRec = setPausedState(root, true, pauseReason);
				this.refreshUi(hooks, root, st, true);
				return toolText(
					`已进入软暂停挂起状态: ${pauseReason}\n守护器与自动续跑已优雅挂起；执行 /nuwa resume 或 nuwa_init(resume=true) 即可无缝恢复。`,
					{ root, paused: true, stopped: false, pausedState: pausedRec },
				);
			}

			const reason = rawReason.trim();
			if (reason.length < 4) throw new Error("reason 至少 4 字");
			const confirmStr = typeof p.confirm === "string" ? p.confirm.trim() : "";
			if (curCfg.infinite && confirmStr !== "STOP") {
				logEvent(root, { type: "stop_rejected", reason });
				return toolText(
					`停机被拒：永动模式下只有目标完成或负向封盘才会自动停。\n` +
						`- 临时挂起（免确认即时软暂停） → nuwa_stop(pause=true, reason="...")\n` +
						`- 硬化无漏洞合法封盘 → nuwa_complete(seal=true, reason="...")\n` +
						`- 想换攻击面 → nuwa_expand()\n` +
						`- 人工硬停机 → nuwa_stop(reason="...", confirm="STOP")\n\n${statusBoardZeroWrite(st, root, this.resolveAgentHome(hooks))}`,
					{ root, stopped: false },
				);
			}

			this.abortAutoBatch(hooks, root, reason);
			const procCleanup = cleanupTrackedProcesses(root, { reason: `nuwa_stop:${reason}` });
			if (isPausedState(root)) setPausedState(root, false, "hard_stopped");
			const updated = withLock(root, () => {
				const s = loadState(root) ?? st;
				if (isTerminalProjectState(s)) return s;
				s.project.status = "stopped";
				s.project.stopReason = reason;
				saveState(root, s, { reason: "stop" });
				return s;
			});
			if (isTerminalProjectState(updated)) {
				const termStatus = terminalStatusOf(updated);
				this.refreshUi(hooks, root, updated, true);
				return toolText(
					`项目已处于终态 (${termStatus}): ${updated.project.id}（终态不可通过 nuwa_stop 降级为 stopped/paused）`,
					{ root, stopped: false, paused: false, terminal: true, status: termStatus },
				);
			}
			logEvent(root, { type: "stop_manual", reason, cleanedProcesses: procCleanup.cleaned.length });
			try {
				const dist = distillProjectExperience(updated, { agentHome: this.resolveAgentHome(hooks), negativeOnly: true });
				if (dist.updated > 0) {
					logEvent(root, {
						type: "experience_distill",
						negativeOnly: true,
						techKeys: dist.techKeys,
						updated: dist.updated,
						positive: dist.positive,
						negative: dist.negative,
					});
				}
			} catch {
				/* 负向经验回流异常不阻断停机 */
			}
			this.refreshUi(hooks, root, updated, true);
			const cleanSuffix =
				procCleanup.cleaned.length > 0 ? `（已清理残留子进程 ${procCleanup.cleaned.length} 个）` : "";
			return toolText(`已停机: ${reason}${cleanSuffix}`, {
				root,
				stopped: true,
				cleanedProcesses: procCleanup.cleaned.length,
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execKb(p: Record<string, unknown>, hooks: NuwaHostHooks): UnifiedToolResult {
		try {
			if (typeof p.query !== "string" || !p.query.trim()) {
				throw new Error("参数 query 必填");
			}
			const kindRaw = p.kind === undefined ? "auto" : String(p.kind);
			if (!VALID_KB_KINDS.has(kindRaw)) {
				throw new Error(`非法 kind: ${kindRaw}`);
			}
			const limit = typeof p.limit === "number" && Number.isFinite(p.limit) ? Math.max(1, Math.floor(p.limit)) : 5;
			return toolText(
				kbLookupSafe(p.query, kindRaw as "auto" | "product" | "cve" | "technique" | "poc", limit, {
					agentHome: this.resolveAgentHome(hooks),
				}),
				{ query: p.query },
			);
		} catch (e) {
			return toolError(e);
		}
	}

	/**
	 * `/nuwa` 斜杠命令单一权威执行入口（含全部 25 个子命令与自然语言目标上膛/并入）。
	 */
	async executeSlashCommand(
		rawArgs: string | undefined,
		perCallHooks?: Partial<NuwaHostHooks>,
	): Promise<SlashCommandResult> {
		const hooks = this.mergeHooks(perCallHooks);
		const cwd = this.resolveCwd(hooks);
		const sid = this.resolveSessionId(hooks);
		const arg = (rawArgs ?? "").trim();
		const found = this.resolveRoot(undefined, hooks) ?? findRoot(cwd, sid);

		const emit = (message: string, level: "info" | "error" = "info", extra: Partial<SlashCommandResult> = {}): SlashCommandResult => {
			try {
				hooks.onNotify?.(message, level);
			} catch {
				/* ignore notify error */
			}
			return { message, level, root: found, ...extra };
		};
		const kick = (text: string): boolean => {
			try {
				return Boolean(hooks.onKick?.(text));
			} catch {
				return false;
			}
		};

		const guardTerminalMutation = (actionLabel: string): SlashCommandResult | null => {
			if (!found) return null;
			const cur = loadStateZeroWrite(found);
			if (cur && isTerminalProjectState(cur)) {
				const tStatus = terminalStatusOf(cur);
				this.refreshUi(hooks, found, cur, true);
				return emit(`该项目已处于终态 (${tStatus}): ${cur.project.id}，禁止执行 ${actionLabel} 改写已封盘图谱`, "error");
			}
			return null;
		};

		if (arg === "doctor" || arg.startsWith("doctor ")) {
			return emit(buildDoctorSummary(found));
		}
		if (arg === "belief" || arg.startsWith("belief ")) {
			const r = executeBeliefCommand(found, arg.slice(6));
			return emit(r.msg, r.level);
		}
		if (arg === "calibrate" || arg.startsWith("calibrate ")) {
			const r = executeCalibrateCommand(found, arg.slice(9));
			return emit(r.msg, r.level);
		}
		if (arg === "traffic" || arg.startsWith("traffic ")) {
			const r = executeTrafficCommand(found, arg.slice(7));
			return emit(r.msg, r.level);
		}
		if (arg === "hybrid" || arg.startsWith("hybrid ")) {
			const hybridSub = arg.slice(6).trim();
			if (/^plan(?:\s|$)/i.test(hybridSub)) {
				const blocked = guardTerminalMutation("/nuwa hybrid plan");
				if (blocked) return blocked;
			}
			const r = executeHybridCommand(found, arg.slice(6));
			if (/^plan(?:\s|$)/i.test(hybridSub) && found) {
				const stAfter = loadStateZeroWrite(found) ?? loadState(found);
				if (stAfter) this.refreshUi(hooks, found, stAfter, true);
			}
			return emit(r.msg, r.level);
		}
		if (arg === "mcp" || arg.startsWith("mcp ")) {
			const r = executeMcpCommand(found, arg.slice(3));
			return emit(r.msg, r.level);
		}

		// /nuwa seal [reason]
		if (arg === "seal" || arg.startsWith("seal ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const preCheck = loadStateZeroWrite(found) ?? loadState(found);
			if (preCheck && isTerminalProjectState(preCheck)) {
				const tStatus = terminalStatusOf(preCheck);
				this.refreshUi(hooks, found, preCheck, true);
				if (tStatus === "completed") {
					return emit(`该项目已完成验收 (status=completed): ${preCheck.project.id}，不可降级篡改为 sealed_negative`, "error");
				}
				return emit(`该项目已处于负向封盘终态 (status=sealed_negative): ${preCheck.project.id}，禁止重复封盘覆写原因`, "error");
			}
			const reason = arg.slice(4).trim() || "人工通过 /nuwa seal 执行负向封盘";
			try {
				this.abortAutoBatch(hooks, found, "sealed_negative");
				const liveTokens = Number(hooks.getLiveTokens?.() ?? 0);
				if (Number.isFinite(liveTokens) && liveTokens > 0) {
					withLock(found, () => {
						const pre = loadState(found);
						if (pre && liveTokens > (pre.runtime.tokens ?? 0)) {
							pre.runtime.tokens = liveTokens;
							saveState(found, pre);
						}
					});
				}
				const sealed = sealEngagement(found, { reason });
				withLock(found, () => {
					const post = loadState(found);
					if (post) {
						post.runtime.reportWritten = true;
						saveState(found, post, { reason: "slash-seal-report-flag" });
					}
				});
				sealed.state.runtime.reportWritten = true;
				const reportPath = syncTerminalReports(found, sealed.state, { writeMd: true });
				cleanupTrackedProcesses(found, { reason: "slash_seal" });
				if (isPausedState(found)) setPausedState(found, false, "sealed_negative");
				this.refreshUi(hooks, found, sealed.state, true);
				return emit(
					`已封盘 ${sealed.state.project.id} (status=${sealed.status}) · 原因: ${sealed.sealMeta.reason}${reportPath ? ` · 报告: ${reportPath}` : ""}`,
				);
			} catch (e) {
				return emit(`封盘失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		}

		// /nuwa note [tag:] <title> [:: <detail>]
		if (arg === "note" || arg.startsWith("note ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const preSt = loadStateZeroWrite(found);
			if (preSt && isTerminalProjectState(preSt)) {
				return emit(`该项目已处于终态 (${terminalStatusOf(preSt)}): ${preSt.project.id}，禁止继续写入事实`, "error");
			}
			const rest = arg.slice(4).trim();
			if (!rest) return emit("用法: /nuwa note [note|endpoint|service|asset:] <标题> [:: <详情>]", "error");
			let tagPrefix = "";
			let body = rest;
			const kindMatch = /^(target|asset|service|endpoint|cred|vuln|flag|loot|note|blocked)\s*:\s*(.+)$/i.exec(rest);
			if (kindMatch) {
				const matchedTag = kindMatch[1]!.toLowerCase();
				if (matchedTag !== "note") tagPrefix = `[${matchedTag}] `;
				body = kindMatch[2]!.trim();
			}
			const sepIdx = body.indexOf("::");
			const rawTitle = (sepIdx >= 0 ? body.slice(0, sepIdx) : body).trim();
			const title = `${tagPrefix}${rawTitle}`.trim();
			const detail = sepIdx >= 0 ? body.slice(sepIdx + 2).trim() : "";
			try {
				const committed = commitFreeFact(found, { kind: "note", title, detail });
				this.refreshUi(hooks, found, committed.state, true);
				return emit(`免票据事实已入账: ${committed.fact.id} [${committed.fact.kind}] ${committed.fact.title}`);
			} catch (e) {
				return emit(`免票据记账失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		}

		// /nuwa inspect <intentId>（纯只读零写入）
		if (arg === "inspect" || arg.startsWith("inspect ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const intentId = arg.slice(7).trim();
			if (!intentId) return emit("用法: /nuwa inspect <intentId>（如 /nuwa inspect i001）", "error");
			const diag = inspectGraph(found, { intentId });
			if (!diag.ok) return emit("state 读取失败", "error");
			const hit = diag.intents[0];
			if (!hit) return emit(`未找到意图: ${intentId}`, "error");
			return emit(
				[
					`[只读诊断 ${hit.id}] status=${hit.status} phase=${hit.phase} domain=${hit.resolvedSurfaceDomain} expectedKind=${hit.resolvedExpectedKind}`,
					`targetKey=${hit.resolvedTargetKey} attempts=${hit.attempts} worker=${hit.worker ?? "-"}`,
					`标题: ${hit.title}`,
					...(hit.note ? [`备注: ${hit.note}`] : []),
					...(hit.toFact ? [`产出事实: ${hit.toFact.id} [${hit.toFact.kind}] ${hit.toFact.title}`] : []),
				].join("\n"),
			);
		}

		// /nuwa query [status=... | target=... | archive=...]（纯只读零写入）
		if (arg === "query" || arg.startsWith("query ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const qRaw = arg.slice(5).trim();
			if (!qRaw || qRaw === "raw" || qRaw === "full") {
				try {
					return emit(renderFullStatus(found, { raw: true }));
				} catch (e) {
					return emit(`全量状态读取失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
			}
			if (qRaw.startsWith("archive ") || qRaw.startsWith("archive=")) {
				const kw = qRaw.replace(/^archive[\s=]+/, "").trim();
				const hits = searchArchiveIndexes(found, kw);
				return emit(
					hits.length
						? `归档命中 ${hits.length} 条:\n${hits.map((h) => `[E${h.episode}] ${h.factId ?? "-"} ${h.title ?? h.command ?? ""} :: ${h.snippet}`).join("\n")}`
						: `归档未命中: ${kw}`,
				);
			}
			const statusMatch = /\bstatus=(open|claimed|done|blocked)\b/i.exec(qRaw);
			const targetMatch = /\btarget(?:_key)?=([^\s]+)/i.exec(qRaw);
			const statusFilter = statusMatch?.[1]?.toLowerCase() as IntentStatus | undefined;
			const targetFilter = targetMatch?.[1] ?? (!statusFilter ? qRaw : undefined);
			const diag = inspectGraph(found, { status: statusFilter, targetKey: targetFilter, limit: 50 });
			if (!diag.ok) return emit("state 读取失败", "error");
			const lines = diag.intents.map(
				(it) => `${it.id} [${it.status}] ${it.phase} (${it.resolvedSurfaceDomain}) ${it.resolvedTargetKey} — ${it.title}`,
			);
			return emit(`查询命中 ${diag.matchedCount} 条:\n${lines.join("\n") || "(无匹配项)"}`);
		}

		// /nuwa pause [reason]
		if (arg === "pause" || arg.startsWith("pause ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const stPre = loadStateZeroWrite(found) ?? loadState(found);
			if (stPre && isTerminalProjectState(stPre)) {
				const termStatus = terminalStatusOf(stPre);
				this.refreshUi(hooks, found, stPre, true);
				return emit(`该项目已处于终态 (${termStatus}): ${stPre.project.id}，终态不可挂起`, "error");
			}
			const reason = arg.slice(5).trim() || "user paused via /nuwa pause";
			this.abortAutoBatch(hooks, found, `paused:${reason}`);
			setPausedState(found, true, reason);
			if (stPre) this.refreshUi(hooks, found, stPre, true);
			return emit(`已软暂停项目 · ${reason}｜执行 /nuwa resume 即可恢复`);
		}

		// /nuwa export [episode]
		if (arg === "export" || arg.startsWith("export ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const st = loadStateZeroWrite(found) ?? loadState(found);
			if (!st) return emit("state 读取失败", "error");
			const epArg = arg.slice(6).trim();
			const epNum = epArg && Number.isFinite(Number(epArg)) && Number(epArg) > 0 ? Math.floor(Number(epArg)) : undefined;
			try {
				const tlText = exportEpisodeTimeline(found, { episode: epNum, format: "markdown" });
				const tlFile = join(found, ".nuwa", epNum !== undefined ? `TIMELINE-E${epNum}.md` : "TIMELINE.md");
				atomicWrite(tlFile, tlText);
				const arch = writeEpisodeArchiveIndex(found, {
					episode: epNum ?? st.project.episode ?? 1,
					state: st,
					summary: "exported via /nuwa export",
				});
				return emit(`已导出时间线: ${tlFile}\n已生成归档索引: ${arch.jsonPath}`);
			} catch (e) {
				return emit(`导出失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		}

		if (arg === "session" || arg.startsWith("session ")) {
			const subSession = arg.slice(7).trim();
			if (subSession && subSession.toLowerCase() !== "list") {
				const blocked = guardTerminalMutation(`/nuwa session ${subSession.split(/\s+/)[0]}`);
				if (blocked) return blocked;
			}
			if (subSession === "health" || subSession.startsWith("health ")) {
				const r = await executeSessionHealthCommand(found, subSession.slice(6));
				const stAfter = found ? loadStateZeroWrite(found) : null;
				if (found && stAfter) this.refreshUi(hooks, found, stAfter, true);
				return emit(r.msg, r.level);
			}
			const r = executeSessionCommand(found, arg.slice(7));
			return emit(r.msg, r.level);
		}

		if (arg === "authdiff" || arg.startsWith("authdiff ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const blocked = guardTerminalMutation("/nuwa authdiff");
			if (blocked) return blocked;
			try {
				const rawPaths = arg.slice(8).trim();
				const explicitPaths = rawPaths ? rawPaths.split(/\s+/).filter(Boolean) : undefined;
				const r = await executeAuthDiffWorkflow(found, explicitPaths);
				const stAfter = loadStateZeroWrite(found);
				if (stAfter) this.refreshUi(hooks, found, stAfter, true);
				return emit(r.msg);
			} catch (e) {
				return emit(`鉴权差分失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		}

		if (arg === "oob" || arg.startsWith("oob ")) {
			const oobSub = arg.slice(3).trim();
			if (oobSub && oobSub.toLowerCase() !== "list") {
				const blocked = guardTerminalMutation(`/nuwa oob ${oobSub.split(/\s+/)[0]}`);
				if (blocked) return blocked;
			}
			const r = await executeOobCommand(found, arg.slice(3));
			const stAfter = found ? loadStateZeroWrite(found) : null;
			if (found && stAfter) this.refreshUi(hooks, found, stAfter, true);
			return emit(r.msg, r.level);
		}

		if (arg === "assets" || arg.startsWith("assets ")) {
			const blocked = guardTerminalMutation("/nuwa assets");
			if (blocked) return blocked;
			const r = executeAssetsCommand(found);
			const stAfter = found ? loadStateZeroWrite(found) : null;
			if (found && stAfter) this.refreshUi(hooks, found, stAfter, true);
			return emit(r.msg, r.level);
		}

		if (arg === "report" || arg.startsWith("report ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const st = loadStateZeroWrite(found) ?? loadState(found);
			if (!st) return emit("state 读取失败", "error");
			const subFmt = arg.slice(6).trim().toLowerCase() || "md";
			try {
				if (subFmt === "timeline" || subFmt.startsWith("timeline ")) {
					const epStr = subFmt.slice(8).trim();
					const ep = epStr && Number.isFinite(Number(epStr)) ? Math.floor(Number(epStr)) : undefined;
					const tl = exportEpisodeTimeline(found, { episode: ep, format: "markdown" });
					const outPath = join(found, ".nuwa", ep !== undefined ? `TIMELINE-E${ep}.md` : "TIMELINE.md");
					atomicWrite(outPath, tl);
					writeEpisodeArchiveIndex(found, { episode: ep ?? st.project.episode ?? 1, state: st });
					return emit(`Episode 时间线已写入: ${outPath}`);
				}
				if (subFmt === "bundle") {
					const b = writePocBundle(found, st);
					return emit(`已生成脱敏证据包: ${b.dir}（${b.files.length} 个文件）`);
				}
				if (subFmt === "sarif") {
					const sarif = buildSarifReport(st, found);
					const outPath = join(found, ".nuwa", "REPORT.sarif.json");
					atomicWrite(outPath, `${JSON.stringify(sarif, null, 2)}\n`);
					writeEpisodeArchiveIndex(found, { episode: st.project.episode ?? 1, state: st });
					const count = (sarif.runs as Array<{ results?: unknown[] }> | undefined)?.[0]?.results?.length ?? 0;
					return emit(`SARIF 2.1.0 报告已写入: ${outPath}（已确认漏洞 ${count} 条）`);
				}
				if (subFmt === "json") {
					const rep = buildJsonReport(st, found);
					const outPath = join(found, ".nuwa", "REPORT.json");
					atomicWrite(outPath, `${JSON.stringify(rep, null, 2)}\n`);
					writeEpisodeArchiveIndex(found, { episode: st.project.episode ?? 1, state: st });
					return emit(`JSON 报告已写入: ${outPath}`);
				}
				if (subFmt === "md" || subFmt === "markdown") {
					const md = redactVaultSecrets(reportMarkdown(st, found), found);
					const outPath = join(found, ".nuwa", "REPORT.md");
					atomicWrite(outPath, md);
					writeEpisodeArchiveIndex(found, { episode: st.project.episode ?? 1, state: st });
					return emit(`Markdown 报告已写入: ${outPath}\n\n${md.slice(0, 1200)}`);
				}
				return emit("用法: /nuwa report [md | json | sarif | timeline | bundle]", "error");
			} catch (e) {
				return emit(`报告生成失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		}

		if (arg === "spa" || arg.startsWith("spa ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const blocked = guardTerminalMutation("/nuwa spa");
			if (blocked) return blocked;
			try {
				const r = await runSpaSurfaceWorkflow(found);
				const stAfter = loadStateZeroWrite(found);
				if (stAfter) this.refreshUi(hooks, found, stAfter, true);
				return emit(
					`SPA 表面感知完成 (mode=${r.spa.mode})：识别技术栈=[${r.spa.tech.join(",") || "无"}] 路由=${r.spa.routes.length} API=${r.spa.endpoints.length}${r.factId ? ` · 入账 ${r.factId}` : ""}${r.derived.length ? ` · 派生 ${r.derived.join(" ")}` : ""}`,
				);
			} catch (e) {
				return emit(`SPA 感知失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
		}

		if (arg === "scope" || arg.startsWith("scope ")) {
			const scopeSub = arg.slice(5).trim();
			if (scopeSub && scopeSub.toLowerCase() !== "show" && scopeSub.toLowerCase() !== "list") {
				const blocked = guardTerminalMutation("/nuwa scope");
				if (blocked) return blocked;
			}
			const r = executeScopeCommand(found, arg.slice(5));
			return emit(r.msg, r.level);
		}

		if (arg === "log" || arg.startsWith("log ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const n = Math.max(1, Math.min(100, Number(arg.split(/\s+/)[1]) || 10));
			try {
				const tail = readJournalTail(found, n);
				return emit(tail.length > 0 ? tail.map((e) => JSON.stringify(e)).join("\n") : "(空日志)");
			} catch {
				return emit("(空日志)");
			}
		}

		if (arg === "board") {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const st = loadStateZeroWrite(found);
			if (!st) return emit("state 读取失败", "error");
			if (hooks.onRenderBoardOverlay) {
				try {
					const rendered = await hooks.onRenderBoardOverlay(found, st);
					if (rendered) return { message: "board overlay rendered", level: "info", root: found };
				} catch {
					/* 回退文本模式 */
				}
			}
			const curCfg = readCfg();
			const snap = buildSnapshot(st, curCfg, budgetPressure(st, curCfg), readJournalTail(found, 400));
			return emit(renderBoardLines(snap, PLAIN_THEME_STYLE, { width: 88 }).join("\n"));
		}

		if (arg === "why") {
			const st = found ? loadStateZeroWrite(found) : null;
			return emit(st?.runtime.lastDirective || "(还没注入过指令)");
		}

		if (arg === "stop" || arg.startsWith("stop ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const preSt = loadStateZeroWrite(found) ?? loadState(found);
			if (preSt && isTerminalProjectState(preSt)) {
				const termStatus = terminalStatusOf(preSt);
				this.refreshUi(hooks, found, preSt, true);
				return emit(`该项目已处于终态 (${termStatus}): ${preSt.project.id}，终态不可改为 stopped`, "error");
			}
			const reason = arg.slice(4).trim() || "user stopped";
			this.abortAutoBatch(hooks, found, reason);
			cleanupTrackedProcesses(found, { reason: `slash_stop:${reason}` });
			if (isPausedState(found)) setPausedState(found, false, "stopped");
			const st = withLock(found, () => {
				const s = loadState(found);
				if (!s) return null;
				if (isTerminalProjectState(s)) return s;
				s.project.status = "stopped";
				s.project.stopReason = reason;
				saveState(found, s, { reason: "stop" });
				return s;
			});
			if (!st) return emit("state 读取失败", "error");
			if (isTerminalProjectState(st)) {
				const termStatus = terminalStatusOf(st);
				this.refreshUi(hooks, found, st, true);
				return emit(`该项目已处于终态 (${termStatus}): ${st.project.id}，终态不可改为 stopped`, "error");
			}
			logEvent(found, { type: "stop", reason, via: "command" });
			try {
				const dist = distillProjectExperience(st, { agentHome: this.resolveAgentHome(hooks), negativeOnly: true });
				if (dist.updated > 0) {
					logEvent(found, {
						type: "experience_distill",
						negativeOnly: true,
						techKeys: dist.techKeys,
						updated: dist.updated,
						positive: dist.positive,
						negative: dist.negative,
					});
				}
			} catch {
				/* 负向经验回流异常不阻断停机 */
			}
			this.refreshUi(hooks, found, st, true);
			return emit(`已停止 ${st.project.id} · ${reason}｜/nuwa resume 继续`);
		}

		if (arg === "resume" || arg.startsWith("resume ")) {
			if (!found) return emit("当前目录没有女娲项目", "error");
			const preSt = loadStateZeroWrite(found) ?? loadState(found);
			if (preSt && isTerminalProjectState(preSt)) {
				const termStatus = terminalStatusOf(preSt);
				this.refreshUi(hooks, found, preSt, true);
				return emit(
					`该项目已处于终态 (${termStatus}): ${preSt.project.id}，终态不可续跑；新目标请换 root 或 nuwa_init(force=true) 重建`,
					"error",
				);
			}
			this.warmKb(hooks);
			if (isPausedState(found)) {
				setPausedState(found, false, "resumed via /nuwa resume");
			}
			const st = withLock(found, () => {
				const s = loadState(found);
				if (!s) return null;
				if (isTerminalProjectState(s)) return s;
				s.project.status = "active";
				s.project.stopReason = undefined;
				s.runtime.status = "active";
				s.project.toolchain = probeToolchain();
				const prevStart = s.runtime.projectStartedAt ?? s.runtime.startedAt ?? Date.now();
				const prevTurns = Math.max(0, Number(s.runtime.turns ?? 0));
				const prevTotalTurns = Math.max(Number(s.runtime.totalTurns ?? 0), prevTurns);
				const prevTotalTokens = Number(s.runtime.totalTokens ?? 0) + Math.max(0, Number(s.runtime.tokens ?? 0));
				Object.assign(s.runtime, {
					startedAt: s.runtime.startedAt || prevStart,
					projectStartedAt: prevStart,
					turns: prevTurns,
					totalTurns: prevTotalTurns,
					totalTokens: prevTotalTokens,
					genTurns: 0,
					stall: 0,
					idle: 0,
					tokens: 0,
					completionRejects: 0,
					lastSig: "",
					lastSettleAt: 0,
					blockStreak: 0,
					pressure: 0,
				});
				saveState(found, s, { reason: "init" });
				return s;
			});
			if (!st) return emit("state 读取失败", "error");
			if (isTerminalProjectState(st)) {
				const termStatus = terminalStatusOf(st);
				this.refreshUi(hooks, found, st, true);
				return emit(
					`该项目已处于终态 (${termStatus}): ${st.project.id}，终态不可续跑；新目标请换 root 或 nuwa_init(force=true) 重建`,
					"error",
				);
			}
			verifyWorkspaceIntegrity(found, { recordBaseline: true });
			writePointer(found, sid);
			this.bindSession(hooks, found, st.project.id);
			this.refreshUi(hooks, found, st, true);
			const resumeMsg = `已恢复 ${st.project.id} · phase=${st.project.phase}`;
			hooks.onNotify?.(resumeMsg, "info");
			const kicked = kick(kickPrompt(st));
			if (!kicked) hooks.onNotify?.("已恢复；发任意一句话即继续", "info");
			return { message: resumeMsg, level: "info", kicked, root: found };
		}

		if (!arg || arg === "status") {
			if (!found) return emit("用法: /nuwa 打 http://10.0.0.5:8080 拿 flag｜/nuwa 看板");
			const st = loadStateZeroWrite(found);
			return emit(st ? statusBoardZeroWrite(st, found, this.resolveAgentHome(hooks)) : "state 读取失败", st ? "info" : "error");
		}

		// 自然语言任务直连开工/并入意图
		this.warmKb(hooks);
		const curCfg = readCfg();
		const mode = pickMode(arg);
		const target = extractTarget(arg) ?? (mode === "coding" || mode === "ops" || mode === "audit" ? cwd : null);
		const want = target ? normalizeTargetForMode(target, mode).url : "";
		const root: string | null = target
			? defaultProjectRoot(cwd, target, sid, mode)
			: (findLocalRoot(cwd, sid) ?? (isSharedCwd(cwd) ? findRoot(cwd, sid) : null));
		if (!root) {
			return emit("用法: /nuwa 打 http://10.0.0.5:8080 拿 flag；或先在该目录 nuwa_init / 设 NUWA_PROJECT", "error");
		}
		const prev = hasProjectState(root) ? (loadStateZeroWrite(root) ?? loadState(root)) : null;
		if (prev?.project.ownerSessionId && prev.project.ownerSessionId !== sid) {
			return emit("该项目属于其他会话；用 NUWA_PROJECT 明确接管", "error", { root });
		}
		if (prev && want && prev.project.url !== want) {
			return emit(`根目录属于 ${prev.project.url}，与本次目标不同；请换目录`, "error", { root });
		}

		if (prev) {
			if (isTerminalProjectState(prev)) {
				const termStatus = terminalStatusOf(prev);
				return emit(
					`该项目已处于终态 (${termStatus})：${prev.project.id}；新目标请换 root 或 nuwa_init(force=true) 重建`,
					"error",
					{ root },
				);
			}
			const it = withLock(root, () => {
				const s = loadState(root);
				if (!s || isTerminalProjectState(s)) return null;
				s.project.status = "active";
				s.project.stopReason = undefined;
				s.project.ownerSessionId = sid;
				if (mode !== s.project.mode) s.project.mode = mode;
				const intent = addIntent(s, { title: arg, detail: arg, phase: s.project.phase, priority: 95 });
				saveState(root, s);
				return intent;
			});
			if (!it) {
				const cur = loadStateZeroWrite(root);
				if (isTerminalProjectState(cur)) {
					const termStatus = terminalStatusOf(cur!);
					return emit(
						`该项目已处于终态 (${termStatus})：${cur!.project.id}；新目标请换 root 或 nuwa_init(force=true) 重建`,
						"error",
						{ root },
					);
				}
				return emit("state 读取失败", "error", { root });
			}
			writePointer(root, sid);
			const st = loadState(root)!;
			this.bindSession(hooks, root, st.project.id);
			logEvent(root, { type: "task", intent: it.id, text: arg, via: "command" });
			this.refreshUi(hooks, root, st, true);
			const mergeMsg = `已并入 ${st.project.id}：${it.id} ${it.title}（phase=${it.phase} priority=95）\n${statusBoard(st, root)}`;
			hooks.onNotify?.(mergeMsg, "info");
			const kicked = kick(kickPrompt(st));
			if (!kicked) hooks.onNotify?.("已记账；发任意一句话即开始执行", "info");
			return { message: mergeMsg, level: "info", kicked, root };
		}

		if (!target) {
			return emit(
				"没识别到目标。用法: /nuwa 打 http://10.0.0.5:8080 拿 flag\n也可先 export NUWA_TARGET=http://host:port 再 /nuwa <任务>",
				"error",
				{ root },
			);
		}

		let st: NuwaState;
		let autoIds: string[] = [];
		const hostCanExecAuto = Boolean(hooks.canRunAutoBatch?.());
		try {
			const tc = probeToolchain();
			st = withLock(root, () => {
				const s = newState(target, arg, mode, curCfg, sid);
				ensurePrimaryAsset(s);
				s.project.toolchain = tc;
				s.project.sandboxMode = readSandboxConfig().mode;
				seedPhase(s, "recon");
				if (hostCanExecAuto && curCfg.auto) autoIds = claimAutoBatch(s, curCfg, root);
				saveState(root, s, { reason: "init" });
				return s;
			});
		} catch (e) {
			return emit(`上膛失败: ${e instanceof Error ? e.message : String(e)}`, "error", { root });
		}
		verifyWorkspaceIntegrity(root, { recordBaseline: true });
		try {
			mkdirSync(`/tmp/nuwa/${st.project.id}`, { recursive: true });
		} catch {
			/* ignore */
		}
		writePointer(root, sid);
		this.bindSession(hooks, root, st.project.id);
		logEvent(root, { type: "init", id: st.project.id, url: st.project.url, mode: st.project.mode, via: "command" });
		this.refreshUi(hooks, root, st, true);
		if (autoIds.length > 0) {
			hooks.onStartAutoBatch?.(root, autoIds);
		}
		const initMsg = `女娲已上膛: ${st.project.id} · ${st.project.url} · mode=${st.project.mode}\n${statusBoard(st, root)}`;
		hooks.onNotify?.(initMsg, "info");
		const kicked = kick(kickPrompt(st));
		if (!kicked) hooks.onNotify?.("已上膛；发任意一句话即开始执行", "info");
		return { message: initMsg, level: "info", kicked, root };
	}
}
