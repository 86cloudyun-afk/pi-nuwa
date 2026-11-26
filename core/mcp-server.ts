/**
 * 女娲 v6.0 宿主无关 JSON-RPC 2.0 over stdio MCP Server（纯 Bun/TS，零外部依赖）。
 *
 * 职责：
 * 1. `NuwaCoreEngine`：脱离特定 Coding Agent 宿主独立执行全部 12 个 `nuwa_*` 工具，
 *    直接复用 `omp/storage.ts`、`omp/graph.ts`、`omp/kb.ts`、`omp/reporting.ts`、`omp/verifier-gate.ts` 等底层模块；
 * 2. `handleMcpMessage`：支持 MCP `initialize`、`notifications/initialized`、`ping`、`tools/list`、`tools/call`；
 * 3. `startStdioMcpServer`：同时兼容按换行分隔 JSON-RPC（NDJSON）与 `Content-Length` 字节帧格式，
 *    严格保证 `stdout` 仅输出合法 JSON-RPC 2.0 帧，所有诊断日志统一路由至 `stderr`。
 */
import { existsSync, mkdirSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";
import { format as formatUtil } from "node:util";
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
	atomicWrite,
	checkAndLogAutoRuleSource,
	checkWorkspaceTempWarning,
	cleanupTrackedProcesses,
	defaultProjectRoot,
	findLocalRoot,
	findRoot,
	getAgentHome,
	isPausedState,
	isSharedCwd,
	loadState,
	logEvent,
	migrateSapper,
	normalizeTargetForMode,
	readCfg,
	readSessionPointer,
	saveState,
	setPausedState,
	statePath,
	verifyWorkspaceIntegrity,
	withLock,
	writePointer,
} from "../omp/storage";
import {
	autoPlan,
	buildConvergenceAdvice,
	claimIntent,
	completeProject,
	computeRepeatRatio,
	executeCommitWithGates,
	extractIntentTargetKey,
	finalizeReportPhase,
	frontierList,
	inspectGraph,
	newState,
	planIntents,
	recordFlag,
	releaseAutoBatchRemaining,
	reportMarkdown,
	sealEngagement,
	seedPhase,
	shouldRecommendSeal,
	statusBoard,
	type AddIntentInput,
	type ConvergenceAdvice,
} from "../omp/graph";
import { resolveReportPhaseTransition, type ReportPhaseTransition } from "../omp/reincarnate";
import { extractProbeHealth, renderFullStatus } from "../omp/ui";
import { injectEgressIntoScript } from "../omp/autoexec";
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
import { redactVaultSecrets } from "../omp/session-vault";
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
import {
	JSONRPC_ERROR_CODES,
	JSONRPC_VERSION,
	NUWA_CORE_SERVER_NAME,
	NUWA_CORE_SERVER_VERSION,
	NUWA_CORE_TOOLS,
	NUWA_MCP_PROTOCOL_VERSION,
	createJsonRpcError,
	createJsonRpcSuccess,
	isNuwaToolName,
	isValidJsonRpcId,
	type JsonRpcId,
	type JsonRpcResponse,
	type McpInitializeResult,
	type McpToolCallResult,
	type McpToolDefinition,
	type NuwaToolName,
} from "./protocol";

const VALID_MODES = new Set<Mode>(["ctf", "pentest", "audit", "coding", "ops"]);
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

function isPlainRecord(val: unknown): val is Record<string, unknown> {
	return Boolean(val && typeof val === "object" && !Array.isArray(val));
}

function toolText(text: string, details: Record<string, unknown> = {}): McpToolCallResult {
	return {
		content: [{ type: "text", text }],
		details,
		isError: false,
	};
}

function toolError(err: unknown, details: Record<string, unknown> = {}): McpToolCallResult {
	const msg = err instanceof Error ? err.message : String(err);
	return {
		content: [{ type: "text", text: `ERROR: ${msg}` }],
		details: { error: true, ...details },
		isError: true,
	};
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

function checkCommitRealismGuard(
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

function releaseInflightAutoBatch(root: string, reason = "stopped"): string[] {
	const normRoot = resolve(root);
	let released: string[] = [];
	if (existsSync(statePath(normRoot))) {
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

export interface NuwaCoreEngineOptions {
	/** 显式绑定的默认项目根目录（如 CLI `--project <dir>`）。 */
	projectRoot?: string;
	/** 基准工作目录（默认 `process.cwd()`）。 */
	cwd?: string;
	/** 当前宿主无关会话标识（默认 `mcp-<pid>`）。 */
	sessionId?: string;
	/** 可选自定义 Agent Home 路径。 */
	agentHome?: string;
}

/**
 * 宿主无关的女娲核心工具执行引擎。
 * 独立驱动全部 12 个 `nuwa_*` 工具，零特定宿主 SDK 依赖。
 */
export class NuwaCoreEngine {
	private readonly cwd: string;
	private readonly configuredProjectRoot?: string;
	private readonly sessionId: string;
	private readonly explicitAgentHome?: string;
	private activeRoot: string | null;
	private initialized = false;

	constructor(opts?: NuwaCoreEngineOptions) {
		this.cwd = resolve(opts?.cwd ?? process.cwd());
		this.configuredProjectRoot = opts?.projectRoot ? resolve(this.cwd, opts.projectRoot) : undefined;
		this.sessionId = (opts?.sessionId ?? "").trim() || `mcp-${process.pid}`;
		this.explicitAgentHome = opts?.agentHome ? resolve(opts.agentHome) : undefined;
		this.activeRoot = this.configuredProjectRoot ?? null;
	}

	/** 标记已完成 MCP `initialize` / `notifications/initialized` 握手。 */
	markInitialized(): void {
		this.initialized = true;
	}

	isInitialized(): boolean {
		return this.initialized;
	}

	/** 返回当前引擎关联的默认或最近激活的项目根目录。 */
	getActiveRoot(): string | null {
		return this.activeRoot ?? this.configuredProjectRoot ?? null;
	}

	/** 列出全部 12 个女娲核心工具定义。 */
	listTools(): readonly McpToolDefinition[] {
		return NUWA_CORE_TOOLS;
	}

	private resolveAgentHome(): string {
		return this.explicitAgentHome ?? getAgentHome();
	}

	private warmKb(): void {
		try {
			ensureBundledKb(undefined, { agentHome: this.resolveAgentHome() });
		} catch {
			/* 只读环境或无种子时不阻塞主流程 */
		}
	}

	private bindSession(root: string, projectId?: string): void {
		this.activeRoot = resolve(root);
		try {
			registerActiveSession(
				{
					sessionId: this.sessionId,
					root: this.activeRoot,
					cwd: this.cwd,
					agentId: "nuwa-mcp",
					projectId,
				},
				this.resolveAgentHome(),
			);
		} catch {
			/* ignore */
		}
	}

	/** 解析工具调用生效的项目目录：显式 `root` > `--project` 绑定目录 > 会话记忆激活目录 > 本地/指针探测。 */
	resolveRoot(explicitRoot?: unknown): string | null {
		if (typeof explicitRoot === "string" && explicitRoot.trim()) {
			return resolve(this.cwd, explicitRoot.trim());
		}
		if (this.configuredProjectRoot && existsSync(statePath(this.configuredProjectRoot))) {
			return this.configuredProjectRoot;
		}
		if (this.activeRoot && existsSync(statePath(this.activeRoot))) {
			return this.activeRoot;
		}
		if (this.configuredProjectRoot) {
			return this.configuredProjectRoot;
		}
		return findLocalRoot(this.cwd, this.sessionId) ?? findRoot(this.cwd, this.sessionId);
	}

	/** 执行任意 12 个 `nuwa_*` 工具，返回标准 MCP `CallToolResult`。 */
	async callTool(name: string, rawArgs?: Record<string, unknown>): Promise<McpToolCallResult> {
		if (!isNuwaToolName(name)) {
			return toolError(`未知工具: ${name}`);
		}
		const args: Record<string, unknown> = isPlainRecord(rawArgs) ? rawArgs : {};
		switch (name as NuwaToolName) {
			case "nuwa_init":
				return this.execInit(args);
			case "nuwa_plan":
				return this.execPlan(args);
			case "nuwa_frontier":
				return this.execFrontier(args);
			case "nuwa_claim":
				return this.execClaim(args);
			case "nuwa_commit":
				return this.execCommit(args);
			case "nuwa_flag":
				return this.execFlag(args);
			case "nuwa_complete":
				return this.execComplete(args);
			case "nuwa_status":
				return this.execStatus(args);
			case "nuwa_report":
				return this.execReport(args);
			case "nuwa_expand":
				return this.execExpand(args);
			case "nuwa_stop":
				return this.execStop(args);
			case "nuwa_kb":
				return this.execKb(args);
		}
	}

	private execInit(p: Record<string, unknown>): McpToolCallResult {
		try {
			this.warmKb();
			const curCfg = readCfg();
			const sid = this.sessionId;
			const rawMode = p.mode === undefined ? "ctf" : String(p.mode);
			if (!VALID_MODES.has(rawMode as Mode)) {
				throw new Error(`非法 mode: ${rawMode}`);
			}
			const mode = rawMode as Mode;
			const resume = Boolean(p.resume ?? false);
			const force = Boolean(p.force ?? false);
			const migrate = Boolean(p.migrate ?? false);
			const autoStartRequested = p.autoStart === true;
			const autoStartMeta = autoStartRequested
				? {
						autoStartSkipped: true,
						autoStartNote: "MCP 独立协议服务不包含宿主 Shell 执行器，已跳过 autoStart 自动批，请通过 nuwa_frontier / nuwa_claim 驱动",
					}
				: {};
			const targetArg = typeof p.target === "string" && p.target.trim() ? p.target.trim() : undefined;
			const rawTarget =
				targetArg ??
				(!resume && !migrate && (mode === "coding" || mode === "ops" || mode === "audit")
					? (this.configuredProjectRoot ?? this.cwd)
					: undefined);
			const want = rawTarget ? normalizeTargetForMode(rawTarget, mode).url : "";

			let root: string;
			if (typeof p.root === "string" && p.root.trim()) {
				root = resolve(this.cwd, p.root.trim());
			} else if (this.configuredProjectRoot) {
				root = this.configuredProjectRoot;
			} else if (rawTarget) {
				root = defaultProjectRoot(this.cwd, rawTarget, sid, mode);
			} else {
				const local = findLocalRoot(this.cwd, sid);
				if (local) {
					root = local;
				} else if (isSharedCwd(this.cwd)) {
					const ptr = readSessionPointer(sid);
					if (ptr?.root) root = resolve(ptr.root);
					else throw new Error("共享 cwd 下新建/恢复项目需要 target 或 root");
				} else {
					root = resolve(this.cwd);
				}
			}

			const scopeOverride = isPlainRecord(p.scope) ? (p.scope as Partial<ScopePolicy>) : undefined;
			const existing = loadState(root);
			if (existing?.project.ownerSessionId && existing.project.ownerSessionId !== sid && !force) {
				throw new Error("该项目属于其他会话；用 force=true 明确接管，避免跨任务污染");
			}
			if (existing && want && existing.project.url !== want && !force) {
				throw new Error(`该目录已是 ${existing.project.url} 的项目；新目标请换 root，或 force=true 明确接管`);
			}

			if (migrate) {
				if (existing && !force) throw new Error("已有 .nuwa 状态；加 force=true 覆盖后再迁移");
				if (existing && force) renameSync(statePath(root), `${statePath(root)}.bak-${Date.now()}`);
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
				this.bindSession(root, migrated.project.id);
				return toolText(`已从 .sapper 迁移: ${migrated.project.id}\n\n${statusBoard(migrated, root)}`, {
					root,
					migrated: true,
				});
			}

			if (existing && resume) {
				if (isPausedState(root)) {
					setPausedState(root, false, "nuwa_init resume");
				}
				const resumed = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init");
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
				const wsIntegrity = verifyWorkspaceIntegrity(root, { recordBaseline: true });
				writePointer(root, sid);
				this.bindSession(root, resumed.project.id);
				return toolText(`已恢复 ${resumed.project.id}\n\n${statusBoard(resumed, root)}`, {
					root,
					integrity: wsIntegrity.status,
					...autoStartMeta,
				});
			}

			if (existing && !force) {
				if (existing.project.status === "active") this.bindSession(root, existing.project.id);
				else this.activeRoot = resolve(root);
				return toolText(
					`项目已存在: ${existing.project.id} status=${existing.project.status} phase=${existing.project.phase}\n` +
						`用 nuwa_init(resume=true) 继续，或 nuwa_init(force=true) 重建（旧 state 自动备份）。\n\n${statusBoard(existing, root)}`,
					{ root, existing: true, ...autoStartMeta },
				);
			}

			if (!rawTarget) throw new Error("target 必填（新建项目时）");
			if (existing && force && existsSync(statePath(root))) {
				renameSync(statePath(root), `${statePath(root)}.bak-${Date.now()}`);
			}
			const goal = typeof p.goal === "string" ? p.goal : "";
			const st = newState(rawTarget, goal, mode, curCfg, sid, scopeOverride);
			st.project.toolchain = probeToolchain();
			st.project.sandboxMode = readSandboxConfig().mode;
			ensurePrimaryAsset(st);
			withLock(root, () => {
				seedPhase(st, "recon");
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
			this.bindSession(root, st.project.id);
			logEvent(root, { type: "init", id: st.project.id, url: st.project.url, mode: st.project.mode });
			const warnSuffix = tmpWarn ? `\n⚠ ${tmpWarn.message}` : "";
			const autoStartSuffix = autoStartRequested ? `\nℹ ${autoStartMeta.autoStartNote}` : "";
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

	private execPlan(p: Record<string, unknown>): McpToolCallResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；先 nuwa_init");
			const phaseArg = p.phase !== undefined ? String(p.phase) : undefined;
			if (phaseArg !== undefined && !VALID_PHASES.has(phaseArg as Phase)) {
				throw new Error(`非法 phase: ${phaseArg}`);
			}
			const force = typeof p.force === "boolean" ? p.force : undefined;
			const cooldownMs = typeof p.cooldown_ms === "number" && Number.isFinite(p.cooldown_ms) ? p.cooldown_ms : undefined;
			const rawIntents = Array.isArray(p.intents) ? p.intents : [];
			const inflightReg = getInflightRegistry(root);
			const added: string[] = [];
			const rejectedReasons: RejectedIntentEntry[] = [];
			let batchPlanOut: ChunkBatchResult<BatchTaskItem> | undefined;
			let egressEnvOut: Record<string, string> | undefined;

			const updated = withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("state 不存在；先 nuwa_init");

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

	private execFrontier(p: Record<string, unknown>): McpToolCallResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const st = loadState(root);
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			const limit = typeof p.limit === "number" && Number.isFinite(p.limit) ? Math.max(1, Math.floor(p.limit)) : 12;
			const items = frontierList(st, limit, curCfg.claimTtl);
			if (!items.length) return toolText("frontier 为空。用 nuwa_plan 播种下一阶段，或 nuwa_status 查依赖。", { root, ids: [] });
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

	private execClaim(p: Record<string, unknown>): McpToolCallResult {
		try {
			const curCfg = readCfg();
			const id = typeof p.id === "string" ? p.id.trim() : "";
			if (!id) throw new Error("参数 id 必填");
			const worker = typeof p.worker === "string" && p.worker.trim() ? p.worker.trim() : "fujiang";
			const root = this.resolveRoot(p.root);
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

	private execCommit(p: Record<string, unknown>): McpToolCallResult {
		try {
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const pre = loadState(root);
			if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

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

			const evidenceRefArg = typeof p.evidence_ref === "string" ? p.evidence_ref : undefined;
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
				const createdFact = Object.values(finalState.facts)
					.sort((a, b) => a.id.localeCompare(b.id))
					.at(-1);
				const targetFact =
					(!isFree && finalState.intents[rawId]?.to ? finalState.facts[finalState.intents[rawId]!.to!] : undefined) ??
					createdFact;
				if (targetFact) {
					savedEvLog = saveFactEvidenceLog(root, {
						factId: targetFact.id,
						command: effCommand,
						output: effOutput,
						rawResponse: rawResponseStr,
					});
					finalState = withLock(root, () => {
						const s = loadState(root) ?? finalState;
						if (s.facts[targetFact.id]) {
							s.facts[targetFact.id]!.evidenceRef = savedEvLog!.evidenceRef;
							saveState(root, s);
						}
						return s;
					});
				}
			}

			const blockedSummaryLine = `blocked_stats: blockedIntents=${commitRes.blockedIntents}(${commitRes.blockedIntentsDelta >= 0 ? "+" : ""}${commitRes.blockedIntentsDelta}) · blockedCommits=${commitRes.blockedCommits}(+${commitRes.blockedCommitsDelta})`;
			const evRefLine = savedEvLog
				? `\nevidence_ref: ${savedEvLog.evidenceRef} (${savedEvLog.bytes}B)`
				: evidenceRefArg
					? `\nevidence_ref: ${evidenceRefArg}`
					: "";
			const fpLine = downgradedFalsePositive ? `\n假阳性门禁自动降级: 已转为 note(false_positive) 入账` : "";

			return toolText(`${commitRes.text}${fpLine}${evRefLine}\n${blockedSummaryLine}\n\n${statusBoard(finalState, root)}`, {
				root,
				id: rawId || "free",
				freeFact: isFree,
				inheritedKind: p.kind === undefined ? effectiveKind : undefined,
				blockedIntents: commitRes.blockedIntents,
				blockedCommits: commitRes.blockedCommits,
				blockedIntentsDelta: commitRes.blockedIntentsDelta,
				blockedCommitsDelta: commitRes.blockedCommitsDelta,
				...(savedEvLog ? { evidenceRef: savedEvLog.evidenceRef } : evidenceRefArg ? { evidenceRef: evidenceRefArg } : {}),
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

	private execFlag(p: Record<string, unknown>): McpToolCallResult {
		try {
			const value = typeof p.value === "string" ? p.value : "";
			const command = typeof p.command === "string" ? p.command : "";
			const output = typeof p.output === "string" ? p.output : "";
			if (!value || !command || !output) {
				throw new Error("参数 value、command、output 必填");
			}
			const challenge = typeof p.challenge === "string" ? p.challenge : undefined;
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const pre = loadState(root);
			if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

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
			withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				const r = recordFlag(s, value, command, output, challenge, vr.verified);
				fact = r.fact.id;
				dup = r.duplicate ?? false;
				saveState(root, s, { reason: "flag" });
				logEvent(root, { type: "flag", fact, value: value.slice(0, 32), verified: vr.verified, duplicate: dup });
				return s;
			});
			return toolText(`${dup ? "幂等命中" : "flag 已入账"}: ${fact} = ${value}`, {
				root,
				fact,
				verified: vr.verified,
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execComplete(p: Record<string, unknown>): McpToolCallResult {
		try {
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");

			if (Boolean(p.seal)) {
				const rawReason = typeof p.reason === "string" ? p.reason : typeof p.note === "string" ? p.note : "";
				const sealReason = rawReason.trim() || "攻击面已全面验证排除且无正向突破，执行负向封盘";
				releaseInflightAutoBatch(root, "sealed_negative");
				const excludedSurface = Array.isArray(p.excluded_surface)
					? p.excluded_surface.map((item) => String(item))
					: undefined;
				const coverage = isPlainRecord(p.coverage) ? p.coverage : undefined;
				const sealed = sealEngagement(root, {
					reason: sealReason,
					excludedSurface,
					coverage,
				});
				cleanupTrackedProcesses(root, { reason: "nuwa_complete:seal" });
				if (isPausedState(root)) setPausedState(root, false, "sealed_negative");
				try {
					distillProjectExperience(sealed.state, { agentHome: this.resolveAgentHome(), negativeOnly: true });
				} catch {
					/* 蒸馏异常不阻断封盘 */
				}
				return toolText(
					`负向封盘已完成: ${sealed.state.project.id} (status=${sealed.status})\n` +
						`封盘依据: ${sealed.sealMeta.reason}\n` +
						`已排除面 (${sealed.sealMeta.excludedSurface.length}): ${sealed.sealMeta.excludedSurface.slice(0, 12).join(", ") || "(自动汇总)"}\n\n` +
						`调 nuwa_report(write=true) 导出封盘覆盖报告。`,
					{
						root,
						ok: true,
						sealed: true,
						status: sealed.status,
						sealMeta: sealed.sealMeta,
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
				res = completeProject(s, fromList, noteStr);
				saveState(root, s, res.ok ? { reason: "complete" } : undefined);
				logEvent(root, { type: "complete", ok: res.ok, from: res.from, reason: res.reason });
				return s;
			});
			if (!res.ok) {
				const convergence = res.convergence ?? buildConvergenceAdvice(updated, curCfg);
				const sealRec = shouldRecommendSeal(updated, curCfg);
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

			cleanupTrackedProcesses(root, { reason: "nuwa_complete:completed" });
			let distillLine = "";
			let distilledCount = 0;
			try {
				const dist = distillProjectExperience(updated, { agentHome: this.resolveAgentHome() });
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
				`完成已验收: ${updated.project.id}\n证据: ${res.from.join(",")}${distillLine}\n\n调 nuwa_report(write=true) 生成报告。`,
				{ root, ok: true, distilled: distilledCount },
			);
		} catch (e) {
			return toolError(e);
		}
	}

	private execStatus(p: Record<string, unknown>): McpToolCallResult {
		try {
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");

			const limit = typeof p.limit === "number" && Number.isFinite(p.limit) ? p.limit : undefined;
			const offset = typeof p.offset === "number" && Number.isFinite(p.offset) ? p.offset : undefined;
			const fmt = p.format === "json" || p.format === "text" ? p.format : undefined;
			if (p.format !== undefined && fmt === undefined) {
				throw new Error(`非法 format: ${String(p.format)}`);
			}

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

			const st = loadState(root);
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
			const rep = computeRepeatRatio(st);
			const probe = extractProbeHealth(st);
			const blockedIntents = Object.values(st.intents).filter((i) => i.status === "blocked").length;
			const blockedCommits = st.runtime.blockedCommits ?? blockedIntents;
			const paused = isPausedState(root);
			const effectiveStatus =
				st.runtime.status === "sealed_negative" || st.project.status === "sealed_negative"
					? "sealed_negative"
					: st.project.status;
			const metricsLine = `metrics: repeat_ratio=${rep.repeatRatio.toFixed(2)} · last_ok=${probe.lastOk} · blockedIntents=${blockedIntents} · blockedCommits=${blockedCommits}${paused ? " · paused=true" : ""}`;
			return toolText(`${statusBoard(st, root)}\n${metricsLine}`, {
				root,
				status: effectiveStatus,
				paused,
				repeat_ratio: rep.repeatRatio,
				last_ok: probe.lastOk,
				blockedIntents,
				blockedCommits,
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execReport(p: Record<string, unknown>): McpToolCallResult {
		try {
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			let st = loadState(root);
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
				const curCfg = readCfg();
				st = withLock(root, () => {
					const s = loadState(root) ?? st!;
					if (write) s.runtime.reportWritten = true;
					if (finalizePhaseFlag && s.project.phase === "report") {
						const fin = finalizeReportPhase(s, curCfg, {
							root,
							reportWritten: Boolean(write || s.runtime.reportWritten),
							autoSeal: true,
						});
						phaseTransitionOut = fin.transition;
					} else if (s.project.phase === "report") {
						phaseTransitionOut = resolveReportPhaseTransition(s, {
							reportWritten: Boolean(write || s.runtime.reportWritten),
							maxEpisodes: curCfg.maxEpisodes,
						});
					}
					saveState(root, s);
					return s;
				});
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

	private execExpand(p: Record<string, unknown>): McpToolCallResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const inflightReg = getInflightRegistry(root);
			const force = Boolean(p.force ?? false);
			let text = "";
			let rejectedReasons: RejectedIntentEntry[] = [];
			let batchOut: ChunkBatchResult<BatchTaskItem> | undefined;
			const egressInput = typeof p.egress === "string" ? p.egress : resolveConfiguredEgressUrl();
			const activeEgress = normalizeTaskEgressUrl(egressInput);

			const st = withLock(root, () => {
				const s = loadState(root);
				if (!s) throw new Error("state 不存在；先 nuwa_init");
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
					if (activeEgress && !it.detail.includes("NUWA_EGRESS")) {
						it.detail = `${it.detail ? `${it.detail}\n` : ""}[出口注入] NUWA_EGRESS=${maskEgressUrl(activeEgress)}`;
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
					batchOut = chunkBatchTasks(filtered.accepted, { root });
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

			return toolText(`${text}\n\n${st ? statusBoard(st, root) : ""}`, {
				root,
				rejectedReasons,
				...(batchOut ? { batch: batchOut } : {}),
			});
		} catch (e) {
			return toolError(e);
		}
	}

	private execStop(p: Record<string, unknown>): McpToolCallResult {
		try {
			const curCfg = readCfg();
			const root = this.resolveRoot(p.root);
			if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
			const st = loadState(root);
			if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

			const rawReason = p.reason === undefined ? "manual stop/pause" : String(p.reason);
			if (p.pause === true) {
				const pauseReason = rawReason.trim() || "manual soft pause";
				releaseInflightAutoBatch(root, `paused:${pauseReason}`);
				const pausedRec = setPausedState(root, true, pauseReason);
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
						`- 人工硬停机 → nuwa_stop(reason="...", confirm="STOP")\n\n${statusBoard(st, root)}`,
					{ root, stopped: false },
				);
			}

			releaseInflightAutoBatch(root, reason);
			const procCleanup = cleanupTrackedProcesses(root, { reason: `nuwa_stop:${reason}` });
			if (isPausedState(root)) setPausedState(root, false, "hard_stopped");
			const updated = withLock(root, () => {
				const s = loadState(root) ?? st;
				s.project.status = "stopped";
				s.project.stopReason = reason;
				saveState(root, s, { reason: "stop" });
				return s;
			});
			logEvent(root, { type: "stop_manual", reason, cleanedProcesses: procCleanup.cleaned.length });
			try {
				const dist = distillProjectExperience(updated, { agentHome: this.resolveAgentHome(), negativeOnly: true });
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

	private execKb(p: Record<string, unknown>): McpToolCallResult {
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
					agentHome: this.resolveAgentHome(),
				}),
				{ query: p.query },
			);
		} catch (e) {
			return toolError(e);
		}
	}
}

async function handleSingleRpcObject(msg: unknown, engine: NuwaCoreEngine): Promise<JsonRpcResponse | null> {
	if (!msg || typeof msg !== "object" || Array.isArray(msg)) {
		return createJsonRpcError(null, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: expected JSON object");
	}
	const rec = msg as Record<string, unknown>;
	const hasIdField = "id" in rec && rec.id !== undefined;
	const safeId: JsonRpcId = hasIdField && isValidJsonRpcId(rec.id) ? rec.id : null;

	if (rec.jsonrpc !== JSONRPC_VERSION) {
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: jsonrpc must be '2.0'");
	}
	if (typeof rec.method !== "string" || rec.method.length === 0) {
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: method must be non-empty string");
	}
	if (hasIdField && !isValidJsonRpcId(rec.id)) {
		return createJsonRpcError(null, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: invalid id type");
	}

	const method = rec.method;
	const params = rec.params;
	if (params !== undefined && (typeof params !== "object" || params === null)) {
		if (!hasIdField) return null;
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INVALID_PARAMS, "Invalid params: expected object or array");
	}

	// JSON-RPC 2.0 Notification（无 id 字段）：严禁向客户端返回响应帧
	if (!hasIdField) {
		if (method === "notifications/initialized" || method === "initialized") {
			engine.markInitialized();
		}
		return null;
	}

	try {
		switch (method) {
			case "initialize": {
				engine.markInitialized();
				const initResult: McpInitializeResult = {
					protocolVersion: NUWA_MCP_PROTOCOL_VERSION,
					capabilities: {
						tools: {
							listChanged: false,
						},
					},
					serverInfo: {
						name: NUWA_CORE_SERVER_NAME,
						version: NUWA_CORE_SERVER_VERSION,
					},
				};
				return createJsonRpcSuccess(safeId, initResult);
			}

			case "ping": {
				return createJsonRpcSuccess(safeId, {});
			}

			case "tools/list": {
				return createJsonRpcSuccess(safeId, {
					tools: engine.listTools(),
				});
			}

			case "tools/call": {
				if (!isPlainRecord(params)) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						"Invalid params: tools/call requires object params",
					);
				}
				const toolName = params.name;
				if (typeof toolName !== "string" || !toolName.trim()) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						"Invalid params: missing tool name",
					);
				}
				if (!isNuwaToolName(toolName)) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						`Unknown tool: ${toolName}`,
					);
				}
				if (params.arguments !== undefined && !isPlainRecord(params.arguments)) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						"Invalid params: tool arguments must be an object",
					);
				}
				const callRes = await engine.callTool(toolName, params.arguments as Record<string, unknown> | undefined);
				return createJsonRpcSuccess(safeId, callRes);
			}

			default: {
				return createJsonRpcError(
					safeId,
					JSONRPC_ERROR_CODES.METHOD_NOT_FOUND,
					`Method not found: ${method}`,
				);
			}
		}
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INTERNAL_ERROR, `Internal error: ${message}`);
	}
}

/**
 * 处理单条或批量 JSON-RPC 2.0 / MCP 消息。
 * 对通知消息（如 `notifications/initialized`）返回 `null`，调用方不得输出响应帧。
 */
export async function handleMcpMessage(
	msg: unknown,
	engine: NuwaCoreEngine,
): Promise<JsonRpcResponse | JsonRpcResponse[] | null> {
	if (Array.isArray(msg)) {
		if (msg.length === 0) {
			return createJsonRpcError(null, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: empty batch");
		}
		const batchOut: JsonRpcResponse[] = [];
		for (const item of msg) {
			const res = await handleSingleRpcObject(item, engine);
			if (res !== null) batchOut.push(res);
		}
		return batchOut.length > 0 ? batchOut : null;
	}
	return handleSingleRpcObject(msg, engine);
}

export type McpFramingMode = "newline" | "content-length";

interface ExtractedFrame {
	rawJson: string;
	framing: McpFramingMode;
	consumedBytes: number;
	invalidHeaderError?: string;
}

const MAX_MCP_FRAME_BYTES = 64 * 1024 * 1024;

/**
 * 从字节流缓冲区提取单个完整帧：
 * - 自动识别 `Content-Length: <N>\r\n\r\n<UTF8-Body>`（兼容 `\n\n` 头分隔）按字节长度精确切片；
 * - 自动识别按换行分隔的 JSON-RPC（NDJSON）；
 * - 半包时返回 `null` 等待后续字节到达。
 */
export function extractNextMcpFrame(buf: Buffer, isEof = false): ExtractedFrame | null {
	let offset = 0;
	while (offset < buf.length) {
		const b = buf[offset]!;
		if (b === 0x0d || b === 0x0a || b === 0x20 || b === 0x09) {
			offset += 1;
		} else {
			break;
		}
	}
	if (offset >= buf.length) {
		return offset > 0 ? { rawJson: "", framing: "newline", consumedBytes: offset } : null;
	}

	const working = offset > 0 ? buf.subarray(offset) : buf;
	const firstByte = working[0]!;

	// 非 '{' 且非 '[' 开头时，检测是否为 Content-Length / HTTP MIME 头帧（兼容任意前置自定义头与半包等待）
	if (firstByte !== 0x7b && firstByte !== 0x5b) {
		const previewAscii = working.subarray(0, Math.min(working.length, 256)).toString("latin1");
		const hasHeaderLine = /^[A-Za-z][A-Za-z0-9-]*\s*:/m.test(previewAscii) && /^[A-Za-z][A-Za-z0-9-]*\s*:/.test(previewAscii);
		const looksLikeHeaderPrefix =
			!isEof && working.length < 64 && /^[A-Za-z][A-Za-z0-9-]*[ \t]*:?$/.test(previewAscii);

		if (hasHeaderLine || looksLikeHeaderPrefix) {
			const crlfIdx = working.indexOf("\r\n\r\n");
			const lfIdx = working.indexOf("\n\n");
			let headerEnd = -1;
			let sepLen = 0;
			if (crlfIdx >= 0 && (lfIdx < 0 || crlfIdx <= lfIdx)) {
				headerEnd = crlfIdx;
				sepLen = 4;
			} else if (lfIdx >= 0) {
				headerEnd = lfIdx;
				sepLen = 2;
			}

			if (headerEnd < 0) {
				if (!isEof && working.length < 8192) return null;
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + working.length,
					invalidHeaderError: "Incomplete Content-Length header",
				};
			}

			const headerText = working.subarray(0, headerEnd).toString("latin1");
			const match = /(?:^|\r?\n)content-length\s*:\s*(\d+)\s*(?:\r?\n|$)/i.exec(headerText);
			if (!match) {
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + headerEnd + sepLen,
					invalidHeaderError: "Missing Content-Length value",
				};
			}
			const bodyBytes = Number(match[1]);
			if (!Number.isSafeInteger(bodyBytes) || bodyBytes <= 0 || bodyBytes > MAX_MCP_FRAME_BYTES) {
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + headerEnd + sepLen,
					invalidHeaderError: `Invalid Content-Length: ${match[1]}`,
				};
			}
			const bodyStart = headerEnd + sepLen;
			if (working.length < bodyStart + bodyBytes) {
				if (!isEof) return null;
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + working.length,
					invalidHeaderError: "Truncated Content-Length frame body at EOF",
				};
			}
			const rawJson = working.subarray(bodyStart, bodyStart + bodyBytes).toString("utf8");
			return {
				rawJson,
				framing: "content-length",
				consumedBytes: offset + bodyStart + bodyBytes,
			};
		}
	}

	// 按换行分隔 JSON-RPC（NDJSON），带最大单帧内存上限保护
	const nlIdx = working.indexOf(0x0a);
	if (nlIdx < 0) {
		if (working.length > MAX_MCP_FRAME_BYTES) {
			return {
				rawJson: "",
				framing: "newline",
				consumedBytes: offset + working.length,
				invalidHeaderError: `NDJSON frame exceeds maximum byte limit (${MAX_MCP_FRAME_BYTES})`,
			};
		}
		if (!isEof) return null;
		const tail = working.toString("utf8").replace(/\r$/, "").trim();
		return {
			rawJson: tail,
			framing: "newline",
			consumedBytes: offset + working.length,
		};
	}
	if (nlIdx > MAX_MCP_FRAME_BYTES) {
		return {
			rawJson: "",
			framing: "newline",
			consumedBytes: offset + nlIdx + 1,
			invalidHeaderError: `NDJSON frame exceeds maximum byte limit (${MAX_MCP_FRAME_BYTES})`,
		};
	}
	const line = working.subarray(0, nlIdx).toString("utf8").replace(/\r$/, "").trim();
	return {
		rawJson: line,
		framing: "newline",
		consumedBytes: offset + nlIdx + 1,
	};
}

/** 将 JSON-RPC 响应对象编码为指定帧格式字符串。 */
export function encodeMcpFrame(payload: JsonRpcResponse | JsonRpcResponse[], framing: McpFramingMode): string {
	const json = JSON.stringify(payload);
	if (framing === "content-length") {
		const byteLen = Buffer.byteLength(json, "utf8");
		return `Content-Length: ${byteLen}\r\n\r\n${json}`;
	}
	return `${json}\n`;
}

export interface StartStdioMcpServerOptions {
	engine?: NuwaCoreEngine;
	projectRoot?: string;
	cwd?: string;
	sessionId?: string;
	input?: NodeJS.ReadableStream;
	output?: { write(chunk: string | Uint8Array): unknown };
	errorOutput?: { write(chunk: string | Uint8Array): unknown };
	/** 是否将全局 `console.log/info/warn/debug` 重定向到 stderr 以保护 stdout 纯净（默认 true）。 */
	redirectConsoleToStderr?: boolean;
}

/**
 * 启动 stdio MCP 协议服务端并监听输入流直至 EOF。
 * 严格保证 `stdout` 只输出合法 JSON-RPC 2.0 帧，所有诊断信息写往 `stderr`。
 */
export async function startStdioMcpServer(opts?: StartStdioMcpServerOptions): Promise<void> {
	const input = opts?.input ?? process.stdin;
	const output = opts?.output ?? process.stdout;
	const errOut = opts?.errorOutput ?? process.stderr;
	const rawWriteOut = output.write.bind(output);
	const rawWriteErr = errOut.write.bind(errOut);

	const logDiag = (...args: unknown[]): void => {
		try {
			rawWriteErr(`[nuwa-mcp] ${formatUtil(...args)}\n`);
		} catch {
			/* ignore stderr EPIPE */
		}
	};

	const shouldRedirectConsole = opts?.redirectConsoleToStderr !== false;
	const prevConsole = {
		log: console.log,
		info: console.info,
		warn: console.warn,
		debug: console.debug,
	};
	if (shouldRedirectConsole) {
		const redirectFn = (...args: unknown[]) => {
			try {
				rawWriteErr(`${formatUtil(...args)}\n`);
			} catch {
				/* ignore */
			}
		};
		console.log = redirectFn;
		console.info = redirectFn;
		console.warn = redirectFn;
		console.debug = redirectFn;
	}

	const engine =
		opts?.engine ??
		new NuwaCoreEngine({
			projectRoot: opts?.projectRoot,
			cwd: opts?.cwd,
			sessionId: opts?.sessionId,
		});

	let buffer = Buffer.alloc(0);
	let chain = Promise.resolve();

	const dispatchFrame = (frame: ExtractedFrame): void => {
		if (frame.framing === "newline" && !frame.rawJson && !frame.invalidHeaderError) return;
		chain = chain.then(async () => {
			try {
				if (frame.invalidHeaderError) {
					logDiag(`协议帧头异常: ${frame.invalidHeaderError}`);
					const errResp = createJsonRpcError(
						null,
						JSONRPC_ERROR_CODES.PARSE_ERROR,
						`Parse error: ${frame.invalidHeaderError}`,
					);
					rawWriteOut(encodeMcpFrame(errResp, frame.framing));
					return;
				}
				let parsed: unknown;
				try {
					parsed = JSON.parse(frame.rawJson);
				} catch (err) {
					logDiag(`JSON 解析失败: ${err instanceof Error ? err.message : String(err)}`);
					const errResp = createJsonRpcError(null, JSONRPC_ERROR_CODES.PARSE_ERROR, "Parse error: invalid JSON");
					rawWriteOut(encodeMcpFrame(errResp, frame.framing));
					return;
				}
				const response = await handleMcpMessage(parsed, engine);
				if (response !== null) {
					rawWriteOut(encodeMcpFrame(response, frame.framing));
				}
			} catch (err) {
				logDiag(`单帧处理/写出异常（已隔离恢复，不影响后续帧）: ${err instanceof Error ? err.message : String(err)}`);
			}
		});
	};

	const drainBuffer = (isEof: boolean): void => {
		for (;;) {
			const frame = extractNextMcpFrame(buffer, isEof);
			if (!frame) break;
			buffer = buffer.subarray(frame.consumedBytes);
			dispatchFrame(frame);
			if (buffer.length === 0) break;
		}
	};

	try {
		await new Promise<void>((resolveDone, rejectDone) => {
			const onData = (chunk: Buffer | string) => {
				const bufChunk = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
				buffer = buffer.length === 0 ? bufChunk : Buffer.concat([buffer, bufChunk]);
				drainBuffer(false);
			};
			const onEnd = () => {
				cleanupListeners();
				drainBuffer(true);
				chain.then(resolveDone, rejectDone);
			};
			const onError = (err: Error) => {
				cleanupListeners();
				logDiag(`输入流异常: ${err.message}`);
				chain.then(() => rejectDone(err), rejectDone);
			};
			const cleanupListeners = () => {
				input.off("data", onData);
				input.off("end", onEnd);
				input.off("error", onError);
			};

			input.on("data", onData);
			input.on("end", onEnd);
			input.on("error", onError);
			if (typeof (input as NodeJS.ReadableStream & { resume?: () => void }).resume === "function") {
				input.resume();
			}
		});
	} finally {
		if (shouldRedirectConsole) {
			console.log = prevConsole.log;
			console.info = prevConsole.info;
			console.warn = prevConsole.warn;
			console.debug = prevConsole.debug;
		}
	}
}

export interface NuwaMcpCliArgs {
	version: boolean;
	help: boolean;
	projectRoot?: string;
}

/** 解析 `nuwa-mcp` 命令行参数。 */
export function parseNuwaMcpCliArgs(argv: readonly string[]): NuwaMcpCliArgs {
	let version = false;
	let help = false;
	let projectRoot: string | undefined;

	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i]!;
		if (arg === "--version" || arg === "-v") {
			version = true;
		} else if (arg === "--help" || arg === "-h") {
			help = true;
		} else if (arg === "--project") {
			const val = argv[++i];
			if (!val || val.startsWith("-")) {
				throw new Error("--project 需要指定目录路径");
			}
			projectRoot = resolve(val);
		} else if (arg.startsWith("--project=")) {
			const val = arg.slice("--project=".length).trim();
			if (!val) {
				throw new Error("--project= 需要指定非空目录路径");
			}
			projectRoot = resolve(val);
		} else {
			throw new Error(`未知参数: ${arg}`);
		}
	}

	return { version, help, projectRoot };
}

/** 运行 `nuwa-mcp` CLI 主入口。 */
export async function runNuwaMcpCli(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
	let parsed: NuwaMcpCliArgs;
	try {
		parsed = parseNuwaMcpCliArgs(argv);
	} catch (err) {
		process.stderr.write(`[nuwa-mcp] 参数错误: ${err instanceof Error ? err.message : String(err)}\n`);
		return 2;
	}

	if (parsed.help) {
		process.stdout.write(
			[
				`${NUWA_CORE_SERVER_NAME} v${NUWA_CORE_SERVER_VERSION} — 女娲跨宿主 MCP 协议服务 (protocol ${NUWA_MCP_PROTOCOL_VERSION})`,
				"",
				"用法:",
				"  nuwa-mcp [--project <dir>] [--version] [--help]",
				"",
				"选项:",
				"  --project <dir>   绑定默认女娲项目工作区目录（同时注入 NUWA_PROJECT）",
				"  -v, --version     输出服务端与 MCP 协议版本号",
				"  -h, --help        显示本帮助说明",
				"",
			].join("\n"),
		);
		return 0;
	}

	if (parsed.version) {
		process.stdout.write(`${NUWA_CORE_SERVER_NAME} ${NUWA_CORE_SERVER_VERSION} (mcp ${NUWA_MCP_PROTOCOL_VERSION})\n`);
		return 0;
	}

	if (parsed.projectRoot) {
		process.env.NUWA_PROJECT = parsed.projectRoot;
	}

	await startStdioMcpServer({
		projectRoot: parsed.projectRoot,
	});
	return 0;
}

if (import.meta.main) {
	const code = await runNuwaMcpCli(process.argv.slice(2));
	process.exit(code);
}
