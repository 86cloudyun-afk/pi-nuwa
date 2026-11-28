/**
 * core/engine-helpers.ts — 女娲 v8.0.0 单核引擎只读状态加载、终态同步、真实性门禁检查与响应拼接辅助模块。
 *
 * 约束：零外部第三方依赖，零特定宿主 SDK 依赖，严禁反向导入 `./engine` 或 `../omp/nuwa`。
 */
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type {
	FactKind,
	IntentStatus,
	Mode,
	NuwaState,
	Phase,
	SurfaceDomain,
} from "../omp/types";
import {
	SCHEMA,
	atomicWrite,
	bindLoadedStateRoot,
	getAgentHome,
	hasProjectState,
	isPausedState,
	journalPath,
	loadState,
	logEvent,
	normalizeState,
	readCfg,
	readJson,
	resolveStorageBackend,
	saveState,
	sqliteDbPath,
	stateDir,
	statePath,
	withLock,
} from "../omp/storage";
import {
	computeRepeatRatio,
	executeCommitWithGates,
	finalizeReportPhase,
	inspectGraph,
	releaseAutoBatchRemaining,
	reportMarkdown,
	statusBoard,
} from "../omp/graph";
import { resolveReportPhaseTransition, type ReportPhaseTransition } from "../omp/reincarnate";
import { extractProbeHealth, renderFullStatus, themeStyle } from "../omp/ui";
import { loadAutoRules } from "../omp/autoexec";
import { defaultScopeForTarget, isHostInScope } from "../omp/scope";
import {
	evaluatePositiveEvidenceGate,
	parseAgentResult,
	saveFactEvidenceLog,
	validateDeliverableRealism,
	verifyExecutionEvidence,
	type AgentEvidenceItem,
	type DeliverableRealismResult,
	type PositiveEvidenceGateResult,
	type SavedEvidenceLog,
} from "../omp/evidence";
import { InflightTargetRegistry } from "../omp/lineage";
import { loadSessionVault, redactVaultSecrets } from "../omp/session-vault";
import {
	buildFalsePositiveNote,
	extractVerifyTargetFactId,
	isVerifyVulnIntentKey,
	validateVerificationCommit,
} from "../omp/verifier-gate";
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
import type { McpToolCallResult } from "./protocol";

export const VALID_MODES = new Set<Mode>(["ctf", "pentest", "audit", "coding", "ops"]);
export const ALL_MODE_PROBES: readonly Mode[] = ["ctf", "ops", "coding", "audit", "pentest"];
export const VALID_PHASES = new Set<Phase>(["recon", "surface", "vuln", "exploit", "post", "report"]);
export const VALID_FACT_KINDS = new Set<FactKind>([
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
export const VALID_DOMAINS = new Set<SurfaceDomain>(["port", "path", "host"]);
export const VALID_INTENT_STATUS = new Set<IntentStatus>(["open", "claimed", "done", "blocked"]);
export const VALID_KB_KINDS = new Set(["auto", "product", "cve", "technique", "poc"]);
export const VALID_REPORT_FORMATS = new Set(["md", "json", "sarif", "timeline"]);
export const COMBINED_HARD_VIOLATIONS = new Set(["placeholder_bracket", "unexpanded_target_literal"]);

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
	"cdp",
	"chains",
	"squad",
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

export function isPlainRecord(val: unknown): val is Record<string, unknown> {
	return Boolean(val && typeof val === "object" && !Array.isArray(val));
}

export function toolText(text: string, details: Record<string, unknown> = {}): UnifiedToolResult {
	return {
		content: [{ type: "text", text }],
		details,
		isError: false,
	};
}

export function toolError(err: unknown, details: Record<string, unknown> = {}): UnifiedToolResult {
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

export function formatAgentEvidenceOutput(ev: AgentEvidenceItem): string {
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

export function getInflightRegistry(root: string): InflightTargetRegistry {
	return new InflightTargetRegistry({ persistPath: join(resolve(root), ".nuwa", "inflight-targets.json") });
}

export const PLAIN_THEME_STYLE = themeStyle({
	fg: (_color: string, text: string) => text,
	bold: (text: string) => text,
});

export interface EngineHelperContext {
	resolveRoot: (explicitRoot?: unknown) => string | null;
	refreshUi: (root: string, state: NuwaState, force?: boolean) => void;
	getAgentHome: () => string;
}

export function executeEngineCommitHelper(p: Record<string, unknown>, ctx: EngineHelperContext): UnifiedToolResult {
		try {
			const root = ctx.resolveRoot(p.root);
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

			ctx.refreshUi(root, finalState);
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

export function executeEngineStatusHelper(p: Record<string, unknown>, ctx: EngineHelperContext): UnifiedToolResult {
		try {
			const root = ctx.resolveRoot(p.root);
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
			ctx.refreshUi(root, st);
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
			return toolText(`${statusBoardZeroWrite(st, root, ctx.getAgentHome())}\n${metricsLine}`, {
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

export function executeEngineReportHelper(p: Record<string, unknown>, ctx: EngineHelperContext): UnifiedToolResult {
		try {
			const root = ctx.resolveRoot(p.root);
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
				ctx.refreshUi(root, st, true);
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
