/**
 * nuwa-omp v4.0.1 — 女娲模式：全自主安全评估与多领域执行引擎（纯 omp 原生组装入口）。
 *
 * 子模块分工：
 *   - `./types`         共享类型契约与常量
 *   - `./storage`       配置、文件锁、原子写、增量快照、会话指针与崩溃恢复
 *   - `./graph`         六阶段种子、状态机、经验提权排序、双盲复验门禁与纪律策略
 *   - `./lineage`       主从会话血缘追踪与子代理动态模型路由
 *   - `./scope`         全工具面靶标范围与高危动作护栏
 *   - `./evidence`      可信执行证据源白名单与防幻觉账本复验
 *   - `./autoexec`      Soft-404 基线校准、内容指纹实锤与工具链自适应升档
 *   - `./browser-recon` SPA 动态无头浏览器与静态 JS Bundle 接口感知
 *   - `./kb`            随仓便携 SQLite FTS5 知识库与跨项目脱敏经验蒸馏
 *   - `./session-vault` 多角色认证会话保险箱与零明文鉴权差分重放
 *   - `./verifier-gate` 候选漏洞双盲独立挑刺复验闸门
 *   - `./sandbox`       零信任 Docker 容器隔离包裹器
 */
import { existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";
import { setInterval as setNodeInterval } from "node:timers";
import type { ExtensionAPI, ExtensionContext, SessionStopEvent, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";
import {
	PHASE_ORDER, type AutoFactMeta, type AutoPlanResult, type Cfg, type CommitInput, type ExecRecordInput,
	type ExpansionResult, type Fact, type FactKind, type FrontierItem, type Intent, type IntentStatus,
	type Mode, type NuwaState, type Phase, type PolicyVerdict, type ProfileMode, type ProfileSpec,
	type Project, type ReincarnatePolicy, type Runtime, type ScopePolicy, type Seed, type ToolchainCaps,
	type VerifyEvidenceInput, type VerifyEvidenceResult, type VerifyStage,
} from "./types";
import {
	SCHEMA, atomicWrite, cell, checkAndLogAutoRuleSource, createInitialState, defaultProjectRoot,
	findLocalRoot, findRoot, getAgentHome, isSharedCwd, journalAppend, journalPath, loadState, lockPath,
	logEvent, migrateSapper, nextFactId, nextIntentId, normOneLine, normalizeState, normalizeTarget,
	normalizeTargetForMode, nowIso, pidAlive, readCfg, readJournalTail, readJson, readSessionPointer,
	saveState, sha, slug, stateDir, statePath, withLock, writePointer,
	type SaveStateOptions,
} from "./storage";
import {
	SEEDS, addFallbackIntent, addIntent, appendIntentSpecs, applyAutoItemResult, applyEmptyGuard,
	autoPlan, budgetPressure, buildDirective, buildDoctorSummary, checkBashPolicy, checkTaskPolicy,
	checkWritePolicy, claimAutoBatch, claimIntent, claimedFresh, collectPaths, commitIntent, compactFacts,
	compactIntents, completeProject, deriveFromFacts, evidenceProblem, executeAutoBatchCycle,
	executeCommitWithGates, executeScopeCommand, executeSessionCommand, extractEventOutput, extractTarget,
	formatScopeSummary, frontierList, isCompliantSandboxDockerCommand, kbLookup, kickPrompt, maybeAdvance,
	newState, phaseIndex, pickMode, proofKinds, recordFlag, releaseAutoBatchRemaining, releaseStaleClaims,
	renderDetail, reportMarkdown, runSpaSurfaceWorkflow, seedEpisode, seedPhase, settleSessionStopState,
	sigOf, statusBoard, stopReason,
} from "./graph";
import { buildHandoffSummary, prepareNextGeneration, readReincarnatePolicy, shouldReincarnate } from "./reincarnate";
import { buildSnapshot, renderBoardLines, renderStatusLine, renderWidgetLines, themeStyle } from "./ui";
import { createBoardComponent, createWidgetComponent } from "./ui-native";
import type { ExecLike } from "./autoexec";
import { checkToolScopeAndRisk, defaultScopeForTarget } from "./scope";
import { isTrustedEvidenceEvent, probeToolchain, recordToolExecution, verifyExecutionEvidence } from "./evidence";
import { bindSubagentSpawn, registerActiveSession, resolveLineageRoot, routeSubagentModel } from "./lineage";
import { distillProjectExperience, ensureBundledKb, kbLookupSafe } from "./kb";
import { redactVaultSecrets } from "./session-vault";
import { isVerifyVulnIntentKey } from "./verifier-gate";
import { readSandboxConfig, wrapCommandInDockerSandbox } from "./sandbox";

export const VERSION = "4.0.1";

export {
	PHASE_ORDER, SCHEMA, SEEDS, addFallbackIntent, addIntent, appendIntentSpecs, applyAutoItemResult,
	applyEmptyGuard, atomicWrite, autoPlan, budgetPressure, buildDirective, buildDoctorSummary,
	buildHandoffSummary, cell, checkBashPolicy, checkTaskPolicy, checkWritePolicy, claimAutoBatch,
	claimIntent, claimedFresh, collectPaths, commitIntent, compactFacts, compactIntents, completeProject,
	createInitialState, defaultProjectRoot, deriveFromFacts, evidenceProblem, extractTarget, findLocalRoot,
	findRoot, formatScopeSummary, frontierList, getAgentHome, isSharedCwd, journalAppend, journalPath,
	kbLookup, kickPrompt, loadState, lockPath, logEvent, maybeAdvance, migrateSapper, newState, nextFactId,
	nextIntentId, normOneLine, normalizeState, normalizeTarget, normalizeTargetForMode, nowIso, phaseIndex,
	pickMode, prepareNextGeneration, proofKinds, readCfg, readReincarnatePolicy, recordFlag,
	releaseAutoBatchRemaining, releaseStaleClaims, renderDetail, reportMarkdown, runSpaSurfaceWorkflow,
	saveState, seedEpisode, seedPhase, sha, shouldReincarnate, sigOf, slug, stateDir, statePath,
	statusBoard, stopReason, withLock, writePointer,
};

export type {
	AutoFactMeta, AutoPlanResult, Cfg, CommitInput, ExecRecordInput, ExpansionResult, Fact, FactKind,
	FrontierItem, Intent, IntentStatus, Mode, NuwaState, Phase, PolicyVerdict, ProfileMode, ProfileSpec,
	Project, ReincarnatePolicy, Runtime, SaveStateOptions, ScopePolicy, Seed, ToolchainCaps,
	VerifyEvidenceInput, VerifyEvidenceResult, VerifyStage,
};

function sidOf(ctx: ExtensionContext): string {
	try {
		return ctx.sessionManager.getSessionId();
	} catch {
		return "default";
	}
}

function isMain(ctx: ExtensionContext): boolean {
	try {
		return ctx.agent?.kind === "main";
	} catch {
		return true;
	}
}

function resolveRootWithLineage(ctx: ExtensionContext, explicit?: string): string | null {
	if (explicit) return resolve(ctx.cwd, explicit);
	const sid = sidOf(ctx);
	const lineageHit = resolveLineageRoot(
		{
			cwd: ctx.cwd,
			sessionId: sid,
			agent: ctx.agent as { kind?: string; id?: string; name?: string; parentId?: string; depth?: number } | undefined,
			sessionManager: ctx.sessionManager as { getSessionId?: () => string; getParentSessionId?: () => string | undefined },
		},
		getAgentHome(),
	);
	return lineageHit ?? findRoot(ctx.cwd, sid);
}

function warmBundledKb(): void {
	try {
		ensureBundledKb(undefined, { agentHome: getAgentHome() });
	} catch {
		/* 种子缺失或只读文件系统时不阻断主流程 */
	}
}

function bindMainSession(ctx: ExtensionContext, root: string, projectId?: string): void {
	try {
		registerActiveSession({ sessionId: sidOf(ctx), root, cwd: ctx.cwd, agentId: ctx.agent?.id, projectId }, getAgentHome());
	} catch {
		/* ignore */
	}
}

function toolText(text: string, details: Record<string, unknown> = {}) {
	return { content: [{ type: "text" as const, text }], details };
}

function toolError(err: unknown, details: Record<string, unknown> = {}) {
	const msg = err instanceof Error ? err.message : String(err);
	return { content: [{ type: "text" as const, text: `ERROR: ${msg}` }], details: { error: true, ...details } };
}

export default function nuwaOmp(pi: ExtensionAPI) {
	const z = pi.zod;
	const liveCalls = new Map<string, number>();
	const autoAborts = new Map<string, AbortController>();
	const pumpSessions = new Map<string, ExtensionContext>();

	const hasExec = (): boolean => typeof (pi as unknown as { exec?: unknown }).exec === "function";

	const sendDirectiveMessage = (text: string, customType = "nuwa-kick"): boolean => {
		try {
			pi.sendUserMessage(text);
			return true;
		} catch {
			/* 流式中回退到自定义消息 */
		}
		try {
			pi.sendMessage({ customType, content: text, display: true }, { triggerTurn: true, deliverAs: "followUp" });
			return true;
		} catch {
			return false;
		}
	};

	const abortAutoBatch = (root: string, reason = "stopped"): string[] => {
		const normRoot = resolve(root);
		const ac = autoAborts.get(normRoot);
		if (ac) {
			autoAborts.delete(normRoot);
			try {
				ac.abort(reason);
			} catch {
				/* ignore */
			}
		}
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
				/* ignore lock failure on shutdown */
			}
		}
		return released;
	};

	const readUiCfg = () => {
		const e = (k: string, d: string): string => (process.env[k] ?? d).trim();
		return {
			enabled: e("NUWA_UI", "1") !== "0",
			widget: e("NUWA_UI_WIDGET", "1") !== "0",
			lines: (e("NUWA_UI_LINES", "3") === "5" ? 5 : 3) as 3 | 5,
			boardMax: Math.max(5, Number(e("NUWA_UI_BOARD_MAX", "30")) || 30),
		};
	};
	let uiSig = "";
	let uiAt = 0;

	const refreshUi = (ctx: ExtensionContext, root: string, st: NuwaState, force = false): void => {
		const u = readUiCfg();
		if (!u.enabled) return;
		const curCfg = readCfg();
		const sig = `${sigOf(st)}|${st.runtime.turns}|${st.runtime.expansions ?? 0}|${st.project.phase}|${st.project.status}`;
		const now = Date.now();
		if (!force && sig === uiSig && now - uiAt < 5000) return;
		if (!force && now - uiAt < 250) return;
		uiSig = sig;
		uiAt = now;
		try {
			const ui = ctx.ui;
			const style = themeStyle(ui.theme as unknown as { fg(color: string, text: string): string; bold(text: string): string });
			const snap = buildSnapshot(st, curCfg, budgetPressure(st, curCfg), readJournalTail(root));
			ui.setStatus("nuwa", renderStatusLine(snap, style));
			if (u.widget) {
				const lines = renderWidgetLines(snap, style, { width: 96, lines: u.lines });
				if ((process.env.NUWA_UI_NATIVE ?? "1").trim() !== "0") {
					const comp = createWidgetComponent(snap, style, { lines: u.lines });
					ui.setWidget("nuwa", () => comp, { placement: "aboveEditor" });
				} else {
					ui.setWidget("nuwa", lines, { placement: "aboveEditor" });
				}
			}
			ui.setTitle?.(`女娲 ${st.project.host}:${st.project.port} · ${st.project.phase} · E${st.project.episode ?? 1}`);
		} catch {
			/* print/RPC 或宿主无 UI 通道 */
		}
	};

	/** 自动批：运行受控确定性侦察、工具链升档规则及 SPA 表面路由感知，并在锁内即时派生。 */
	const runAutoBatch = async (ctx: ExtensionContext, root: string, ids: string[]): Promise<void> => {
		if (!ids.length || !hasExec()) return;
		const normRoot = resolve(root);
		const prevAc = autoAborts.get(normRoot);
		if (prevAc) {
			try {
				prevAc.abort("superseded");
			} catch {
				/* ignore */
			}
		}
		const ac = new AbortController();
		autoAborts.set(normRoot, ac);
		const execFn: ExecLike = (c, a, o) => (pi as unknown as { exec: ExecLike }).exec(c, a, o);
		try {
			await executeAutoBatchCycle({
				root: normRoot,
				ids,
				execFn,
				signal: ac.signal,
				onStateChanged: (s) => refreshUi(ctx, normRoot, s, true),
			});
		} catch {
			/* 自动批异常不阻断主线程 */
		} finally {
			if (autoAborts.get(normRoot) === ac) autoAborts.delete(normRoot);
		}
	};

	const clearUi = (ctx: ExtensionContext): void => {
		try {
			ctx.ui.setWidget("nuwa", undefined);
			ctx.ui.setStatus("nuwa", undefined);
		} catch {
			/* 无 UI 通道 */
		}
		uiSig = "";
		uiAt = 0;
	};

	// ---------------------------------------------------------------- 工具（严格保持 12 个工具名）
	pi.registerTool({
		name: "nuwa_init",
		label: "女娲初始化",
		description: "创建/恢复女娲项目：写 .nuwa/state.json，初始化靶标 Scope 护栏、便携知识库与本地工具链探针，播种首阶段意图，返回看板。",
		loadMode: "essential",
		parameters: z.object({
			target: z.string().optional().describe("目标 URL、host:port 或本地目录/服务标识（coding/ops）"),
			goal: z.string().optional().describe("目标描述"),
			mode: z.enum(["ctf", "pentest", "audit", "coding", "ops"]).default("ctf").describe("任务模式，决定阶段种子与完成证据类型"),
			root: z.string().optional().describe("项目目录，默认当前 cwd"),
			resume: z.boolean().default(false).describe("恢复已停止的项目，保留 facts/intents"),
			force: z.boolean().default(false).describe("覆盖现有项目（备份旧 state）"),
			migrate: z.boolean().default(false).describe("从同目录 .sapper 图迁移旧项目"),
			autoStart: z.boolean().default(false).describe("是否在初始化后立即触发首轮确定性自动侦察批"),
			scope: z
				.object({
					allowHosts: z.array(z.string()).optional(), allowCidrs: z.array(z.string()).optional(),
					denyHosts: z.array(z.string()).optional(), allowSubdomains: z.boolean().optional(),
					allowPrivateNetwork: z.boolean().optional(), allowDestructive: z.boolean().optional(),
				})
				.optional()
				.describe("可选靶标范围与风险策略覆盖"),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				warmBundledKb();
				const curCfg = readCfg();
				const sid = sidOf(ctx);
				const mode = (p.mode ?? "ctf") as Mode;
				const rawTarget = p.target ?? (!p.resume && !p.migrate && (mode === "coding" || mode === "ops") ? ctx.cwd : undefined);
				const want = rawTarget ? normalizeTargetForMode(rawTarget, mode).url : "";
				let root: string;
				if (p.root) {
					root = resolve(ctx.cwd, p.root);
				} else if (rawTarget) {
					root = defaultProjectRoot(ctx.cwd, rawTarget, sid, mode);
				} else {
					const local = findLocalRoot(ctx.cwd, sid);
					if (local) {
						root = local;
					} else if (isSharedCwd(ctx.cwd)) {
						const ptr = readSessionPointer(sid);
						if (ptr?.root) root = resolve(ptr.root);
						else throw new Error("共享 cwd 下新建/恢复项目需要 target 或 root");
					} else {
						root = resolve(ctx.cwd);
					}
				}
				const existing = loadState(root);
				if (existing?.project.ownerSessionId && existing.project.ownerSessionId !== sid && !p.force) {
					throw new Error("该项目属于其他 omp 会话；用 force=true 明确接管，避免跨任务污染");
				}
				if (existing && want && existing.project.url !== want && !p.force) {
					throw new Error(`该目录已是 ${existing.project.url} 的项目；新目标请换 root，或 force=true 明确接管`);
				}
				if (p.migrate) {
					if (existing && !p.force) throw new Error("已有 .nuwa 状态；加 force=true 覆盖后再迁移");
					if (existing && p.force) renameSync(statePath(root), `${statePath(root)}.bak-${Date.now()}`);
					const migrated = withLock(root, () => {
						const st = migrateSapper(root);
						st.project.ownerSessionId = sid;
						st.project.toolchain = probeToolchain();
						st.project.sandboxMode = readSandboxConfig().mode;
						saveState(root, st, { reason: "init" });
						return st;
					});
					writePointer(root, sid);
					bindMainSession(ctx, root, migrated.project.id);
					refreshUi(ctx, root, migrated, true);
					return toolText(`已从 .sapper 迁移: ${migrated.project.id}\n\n${statusBoard(migrated, root)}`, { root, migrated: true });
				}
				if (existing && p.resume) {
					const resumed = withLock(root, () => {
						const s = loadState(root);
						if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init");
						s.project.status = "active";
						s.project.stopReason = undefined;
						s.project.ownerSessionId = sid;
						if (p.scope) {
							s.project.scope = defaultScopeForTarget(s.project.url || s.project.target, s.project.mode, { ...s.project.scope, ...p.scope });
						} else if (!s.project.scope) {
							s.project.scope = defaultScopeForTarget(s.project.url || s.project.target, s.project.mode);
						}
						s.project.toolchain = probeToolchain();
						s.project.sandboxMode = readSandboxConfig().mode;
						Object.assign(s.runtime, {
							startedAt: Date.now(), turns: 0, genTurns: 0, stall: 0, idle: 0, tokens: 0,
							completionRejects: 0, lastSig: "", lastSettleAt: 0, blockStreak: 0, pressure: 0,
							rulesSource: checkAndLogAutoRuleSource(root, s),
						});
						saveState(root, s, { reason: "init" });
						return s;
					});
					writePointer(root, sid);
					bindMainSession(ctx, root, resumed.project.id);
					refreshUi(ctx, root, resumed, true);
					return toolText(`已恢复 ${resumed.project.id}\n\n${statusBoard(resumed, root)}`, { root });
				}
				if (existing && !p.force) {
					if (existing.project.status === "active") bindMainSession(ctx, root, existing.project.id);
					return toolText(
						`项目已存在: ${existing.project.id} status=${existing.project.status} phase=${existing.project.phase}\n` +
							`用 nuwa_init(resume=true) 继续，或 nuwa_init(force=true) 重建（旧 state 自动备份）。\n\n${statusBoard(existing, root)}`,
						{ root, existing: true },
					);
				}
				if (!rawTarget) throw new Error("target 必填（新建项目时）");
				if (existing && p.force) renameSync(statePath(root), `${statePath(root)}.bak-${Date.now()}`);
				const st = newState(rawTarget, p.goal ?? "", mode, curCfg, sid, p.scope);
				st.project.toolchain = probeToolchain();
				st.project.sandboxMode = readSandboxConfig().mode;
				const shouldAutoStart = (p.autoStart === true || (process.env.NUWA_AUTO_ON_INIT ?? "").trim() === "1") && hasExec();
				let autoIds: string[] = [];
				withLock(root, () => {
					seedPhase(st, "recon");
					if (shouldAutoStart) autoIds = claimAutoBatch(st, curCfg, root);
					st.runtime.rulesSource = checkAndLogAutoRuleSource(root, st);
					saveState(root, st, { reason: "init" });
				});
				mkdirSync(`/tmp/nuwa/${st.project.id}`, { recursive: true });
				writePointer(root, sid);
				bindMainSession(ctx, root, st.project.id);
				logEvent(root, { type: "init", id: st.project.id, url: st.project.url, mode: st.project.mode });
				refreshUi(ctx, root, st, true);
				if (autoIds.length > 0) void runAutoBatch(ctx, root, autoIds);
				return toolText(`女娲已上膛: ${st.project.id}\n\n${statusBoard(st, root)}`, { root, project: st.project.id });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_plan",
		label: "女娲规划",
		description: "播种一个阶段的意图（recon/surface/vuln/exploit/post/report），或追加自定义意图。按 key 去重，可反复调用。",
		loadMode: "essential",
		parameters: z.object({
			phase: z.enum(["recon", "surface", "vuln", "exploit", "post", "report"]).optional().describe("要播种的阶段"),
			intents: z
				.array(z.object({ title: z.string(), detail: z.string().optional(), phase: z.enum(["recon", "surface", "vuln", "exploit", "post", "report"]).optional(), from: z.array(z.string()).optional(), priority: z.number().optional() }))
				.optional()
				.describe("自定义意图"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；先 nuwa_init");
				const added: string[] = [];
				const updated = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("state 不存在；先 nuwa_init");
					if (p.phase) {
						if (phaseIndex(p.phase) > phaseIndex(s.project.phase)) s.project.phase = p.phase;
						added.push(...seedPhase(s, p.phase));
					}
					for (const it of p.intents ?? []) added.push(addIntent(s, it).id);
					saveState(root, s);
					return s;
				});
				return toolText(
					`已追加 ${added.length} 条意图: ${added.join(" ") || "(无新增，均已存在)"}\nphase=${updated.project.phase}\n\n${statusBoard(updated, root)}`,
					{ root, added },
				);
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_frontier",
		label: "女娲待办",
		description: "列出当前可执行意图（依赖事实已满足、未被有效认领），结合跨项目历史经验自适应排序。",
		loadMode: "essential",
		parameters: z.object({ limit: z.number().default(12), root: z.string().optional() }),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				const items = frontierList(st, p.limit, curCfg.claimTtl);
				if (!items.length) return toolText("frontier 为空。用 nuwa_plan 播种下一阶段，或 nuwa_status 查依赖。");
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
		},
	});

	pi.registerTool({
		name: "nuwa_claim",
		label: "女娲认领",
		description: "认领一条意图，返回完整派单包（含多角色鉴权差分重放指引、工具链适配与输出契约）。主线程 claim，子代理执行，主线程 commit。",
		loadMode: "essential",
		parameters: z.object({ id: z.string().describe("意图 id，如 i007"), worker: z.string().default("fujiang"), root: z.string().optional() }),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				let packet = "";
				let stale = false;
				withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
					const r = claimIntent(s, p.id, p.worker, curCfg.claimTtl, root);
					packet = r.packet;
					stale = r.stale;
					saveState(root, s);
					logEvent(root, { type: "claim", id: p.id, worker: p.worker, stale });
				});
				return toolText(packet, { root, id: p.id, stale });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_commit",
		label: "女娲记账",
		description: "提交一条意图的结果并生成事实。自动收纳 cred 至会话保险箱并全量脱敏，对 vuln 启动双盲复验闸门；用 blocked=true 收口卡住的意图。",
		loadMode: "essential",
		parameters: z.object({
			id: z.string(),
			kind: z.enum(["target", "asset", "service", "endpoint", "cred", "vuln", "flag", "loot", "note", "blocked"]).default("note"),
			title: z.string().default(""),
			detail: z.string().default(""),
			command: z.string().optional(),
			output: z.string().optional(),
			blocked: z.boolean().default(false),
			note: z.string().optional(),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const pre = loadState(root);
				if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

				let verifiedFlag: boolean | undefined;
				if (!p.blocked && (p.kind === "vuln" || p.kind === "cred" || p.kind === "flag")) {
					const strict = (process.env.NUWA_STRICT_EVIDENCE ?? "").trim() === "1";
					const extractedFlag =
						p.kind === "flag" ? (`${p.title ?? ""} ${p.detail ?? ""} ${p.output ?? ""}`.match(/flag\{[^}\s]{2,}\}/i)?.[0] ?? undefined) : undefined;
					const vr = verifyExecutionEvidence(root, {
						projectId: pre.project.id,
						kind: p.kind,
						command: p.command,
						output: p.output,
						flagValue: extractedFlag,
						strict,
					});
					if (!vr.ok) {
						logEvent(root, { type: "evidence_rejected", id: p.id, kind: p.kind, reason: vr.reason });
						throw new Error(`证据复验未通过: ${vr.reason ?? "未在真实执行账本中核验到对应输出"}`);
					}
					verifiedFlag = vr.verified;
				}

				const { state: updated, text, verifyStageOut, verifyIntentId, ingestedRole } = executeCommitWithGates(
					root,
					p,
					verifiedFlag,
				);
				refreshUi(ctx, root, updated);
				return toolText(`${text}\n\n${statusBoard(updated, root)}`, {
					root,
					id: p.id,
					...(verifyStageOut ? { verifyStage: verifyStageOut } : {}),
					...(verifyIntentId ? { verifyIntent: verifyIntentId } : {}),
					...(ingestedRole ? { role: ingestedRole } : {}),
				});
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_flag",
		label: "女娲 Flag",
		description: "立即入账 flag。output 必须包含完整 flag 值且经可信执行账本复验；同一 flag 幂等。不要等批次结束。",
		loadMode: "essential",
		parameters: z.object({
			value: z.string(),
			command: z.string(),
			output: z.string(),
			challenge: z.string().optional(),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const pre = loadState(root);
				if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

				const strict = (process.env.NUWA_STRICT_EVIDENCE ?? "").trim() === "1";
				const vr = verifyExecutionEvidence(root, {
					projectId: pre.project.id,
					kind: "flag",
					command: p.command,
					output: p.output,
					flagValue: p.value,
					strict,
				});
				if (!vr.ok) {
					logEvent(root, { type: "evidence_rejected", kind: "flag", value: p.value.slice(0, 32), reason: vr.reason });
					throw new Error(`证据复验未通过: ${vr.reason ?? "flag 未在真实工具执行账本中出现"}`);
				}

				let fact = "";
				let dup = false;
				const updated = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
					const r = recordFlag(s, p.value, p.command, p.output, p.challenge, vr.verified);
					fact = r.fact.id;
					dup = r.duplicate ?? false;
					saveState(root, s, { reason: "flag" });
					logEvent(root, { type: "flag", fact, value: p.value.slice(0, 32), verified: vr.verified, duplicate: dup });
					return s;
				});
				refreshUi(ctx, root, updated, true);
				return toolText(`${dup ? "幂等命中" : "flag 已入账"}: ${fact} = ${p.value}`, { root, fact, verified: vr.verified });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_complete",
		label: "女娲收口",
		description: "请求完成项目。必须至少有一条已确认（非 candidate/rejected）的实锤证据事实；验收成功后自动蒸馏脱敏经验回流知识库。",
		loadMode: "essential",
		parameters: z.object({
			from: z.array(z.string()).optional().describe("完成引用的 fact id；省略则用全部已确认证据事实"),
			note: z.string().optional(),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				let res: { ok: boolean; reason?: string; from: string[] } = { ok: false, from: [] };
				const updated = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
					res = completeProject(s, p.from, p.note);
					saveState(root, s, res.ok ? { reason: "complete" } : undefined);
					logEvent(root, { type: "complete", ok: res.ok, from: res.from, reason: res.reason });
					return s;
				});
				refreshUi(ctx, root, updated, true);
				if (!res.ok) {
					return toolText(
						`完成被拒: ${res.reason}\nrejects=${updated.runtime.completionRejects}\n\n${statusBoard(updated, root)}`,
						{ root, ok: false, reason: res.reason },
					);
				}

				let distillLine = "";
				let distilledCount = 0;
				try {
					const dist = distillProjectExperience(updated, { agentHome: getAgentHome() });
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
		},
	});

	pi.registerTool({
		name: "nuwa_status",
		label: "女娲看板",
		description: "查看项目状态：阶段进度、事实统计、待复验候选、会话仓角色、知识库状态、预算与 frontier。",
		loadMode: "essential",
		parameters: z.object({ root: z.string().optional() }),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				refreshUi(ctx, root, st);
				return toolText(statusBoard(st, root), { root, status: st.project.status });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_report",
		label: "女娲报告",
		description: "生成评估报告（攻击链、flag 台账、漏洞、资产、未完成面）。write=true 时写到 .nuwa/REPORT.md。",
		loadMode: "essential",
		parameters: z.object({ write: z.boolean().default(false), root: z.string().optional() }),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				const md = redactVaultSecrets(reportMarkdown(st), root);
				let path = "";
				if (p.write) {
					path = join(root, ".nuwa", "REPORT.md");
					atomicWrite(path, md);
				}
				return toolText(path ? `${md}\n\n已写入: ${path}` : md, { root, path });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_expand",
		label: "女娲扩张",
		description: "强制扩张攻击面：回收过量 blocked/note、从事实与便携知识库派生新意图、逐阶段推进；frontier 空则开下一轮 episode。",
		loadMode: "essential",
		parameters: z.object({ root: z.string().optional() }),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				let text = "";
				const st = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("state 不存在；先 nuwa_init");
					const r = autoPlan(s, curCfg);
					saveState(root, s);
					logEvent(root, { type: "expand_manual", reason: r.reason, added: r.added, phase: r.phase, episode: r.episode });
					text = `扩张: ${r.reason} · phase=${r.phase ?? s.project.phase} · ep=${s.project.episode ?? 1} · 新增 ${r.added.length} 条${r.added.length ? `: ${r.added.join(" ")}` : ""}`;
					return s;
				});
				if (st) refreshUi(ctx, root, st, true);
				return toolText(`${text}\n\n${st ? statusBoard(st, root) : ""}`, { root });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_stop",
		label: "女娲停机",
		description: "人工停机（需要 confirm=\"STOP\"）。永动模式下模型不得自行停机：没有 confirm 会被拒绝并提示扩张；确认停机立即中断在途自动批。",
		loadMode: "essential",
		parameters: z.object({
			reason: z.string(),
			confirm: z.string().optional().describe('人工停机必须显式传 "STOP"'),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				const reason = (p.reason ?? "").trim();
				if (reason.length < 4) throw new Error("reason 至少 4 字");
				if (curCfg.infinite && (p.confirm ?? "").trim() !== "STOP") {
					logEvent(root, { type: "stop_rejected", reason });
					return toolText(
						`停机被拒：永动模式下只有目标完成才会停。\n` +
							`- 想换攻击面 → nuwa_expand()\n` +
							`- 卡死 → nuwa_commit(id, blocked=true, note="...")\n` +
							`- 人工停机 → nuwa_stop(reason="...", confirm="STOP")\n\n${statusBoard(st, root)}`,
						{ root, stopped: false },
					);
				}
				abortAutoBatch(root, reason);
				const updated = withLock(root, () => {
					const s = loadState(root) ?? st;
					s.project.status = "stopped";
					s.project.stopReason = reason;
					saveState(root, s, { reason: "stop" });
					return s;
				});
				logEvent(root, { type: "stop_manual", reason });
				refreshUi(ctx, root, updated, true);
				return toolText(`已停机: ${reason}`, { root });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerTool({
		name: "nuwa_kb",
		label: "女娲知识库",
		description: "安全查询便携知识库（参数化 FTS5 + 跨项目历史经验提示）：产品审计卡、CVE、ATT&CK 技术。支持 'spring'、'CVE-2021-44228'、'T1190'。",
		loadMode: "essential",
		parameters: z.object({
			query: z.string(),
			kind: z.enum(["auto", "product", "cve", "technique", "poc"]).default("auto"),
			limit: z.number().default(5),
		}),
		async execute(_id, p) {
			try {
				return toolText(kbLookupSafe(p.query, p.kind, p.limit, { agentHome: getAgentHome() }), { query: p.query });
			} catch (e) {
				return toolError(e);
			}
		},
	});

	pi.registerCommand?.("nuwa", {
		description: "女娲：/nuwa <任务> 开工 | /nuwa status | board | scope | session | doctor | spa | log [n] | why | stop | resume",
		getArgumentCompletions: (prefix: string) =>
			["status", "board", "scope", "session", "doctor", "spa", "log", "why", "stop", "resume"]
				.filter((v) => v.startsWith(prefix))
				.map((v) => ({ value: v, label: v })),
		handler: async (args, ctx) => {
			const notify = (t: string, level: "info" | "error" = "info") => {
				try {
					ctx.ui.notify(t, level);
				} catch {
					/* 非 TUI 模式无通知通道 */
				}
			};
			const kick = (text: string): boolean => sendDirectiveMessage(text, "nuwa-kick");
			const arg = (args ?? "").trim();
			const found = resolveRootWithLineage(ctx as ExtensionContext) ?? findRoot(ctx.cwd, sidOf(ctx as ExtensionContext));

			if (arg === "doctor" || arg.startsWith("doctor ")) return notify(buildDoctorSummary(found));

			if (arg === "session" || arg.startsWith("session ")) {
				const r = executeSessionCommand(found, arg.slice(7));
				return notify(r.msg, r.level);
			}

			if (arg === "spa" || arg.startsWith("spa ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				try {
					const r = await runSpaSurfaceWorkflow(found);
					const stAfter = loadState(found);
					if (stAfter) refreshUi(ctx as ExtensionContext, found, stAfter, true);
					return notify(
						`SPA 表面感知完成 (mode=${r.spa.mode})：识别技术栈=[${r.spa.tech.join(",") || "无"}] 路由=${r.spa.routes.length} API=${r.spa.endpoints.length}${r.factId ? ` · 入账 ${r.factId}` : ""}${r.derived.length ? ` · 派生 ${r.derived.join(" ")}` : ""}`,
					);
				} catch (e) {
					return notify(`SPA 感知失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
			}

			if (arg === "scope" || arg.startsWith("scope ")) {
				const r = executeScopeCommand(found, arg.slice(5));
				return notify(r.msg, r.level);
			}

			if (arg.startsWith("log")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const n = Math.max(1, Math.min(100, Number(arg.split(/\s+/)[1]) || 10));
				try {
					notify(readFileSync(journalPath(found), "utf8").trim().split("\n").slice(-n).join("\n"));
				} catch {
					notify("(空日志)");
				}
				return;
			}
			if (arg === "board") {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const st = loadState(found);
				if (!st) return notify("state 读取失败", "error");
				const curCfg = readCfg();
				const style = themeStyle(ctx.ui.theme as unknown as { fg(color: string, text: string): string; bold(text: string): string });
				const snap = buildSnapshot(st, curCfg, budgetPressure(st, curCfg), readJournalTail(found, 400));
				try {
					await ctx.ui.custom(
						(_tui, theme, _kb, done) => {
							const th = themeStyle(theme as unknown as { fg(color: string, text: string): string; bold(text: string): string });
							return createBoardComponent(snap, th, () => done(undefined));
						},
						{ overlay: true, overlayOptions: { width: "92%", maxHeight: "85%", anchor: "center" } },
					);
				} catch {
					notify(renderBoardLines(snap, style, { width: 88 }).join("\n"));
				}
				return;
			}
			if (arg === "why") {
				const st = found ? loadState(found) : null;
				return notify(st?.runtime.lastDirective || "(还没注入过指令)");
			}
			if (arg === "stop" || arg.startsWith("stop ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const reason = arg.slice(4).trim() || "user stopped";
				abortAutoBatch(found, reason);
				const st = withLock(found, () => {
					const s = loadState(found);
					if (!s) return null;
					s.project.status = "stopped";
					s.project.stopReason = reason;
					saveState(found, s, { reason: "stop" });
					return s;
				});
				if (!st) return notify("state 读取失败", "error");
				logEvent(found, { type: "stop", reason, via: "command" });
				refreshUi(ctx as ExtensionContext, found, st, true);
				return notify(`已停止 ${st.project.id} · ${reason}｜/nuwa resume 继续`);
			}
			if (arg === "resume") {
				if (!found) return notify("当前目录没有女娲项目", "error");
				warmBundledKb();
				const st = withLock(found, () => {
					const s = loadState(found);
					if (!s) return null;
					s.project.status = "active";
					s.project.stopReason = undefined;
					s.project.toolchain = probeToolchain();
					Object.assign(s.runtime, {
						startedAt: Date.now(), turns: 0, genTurns: 0, stall: 0, idle: 0, tokens: 0,
						completionRejects: 0, lastSig: "", lastSettleAt: 0, blockStreak: 0, pressure: 0,
					});
					saveState(found, s, { reason: "init" });
					return s;
				});
				if (!st) return notify("state 读取失败", "error");
				writePointer(found, sidOf(ctx as ExtensionContext));
				bindMainSession(ctx as ExtensionContext, found, st.project.id);
				refreshUi(ctx as ExtensionContext, found, st, true);
				notify(`已恢复 ${st.project.id} · phase=${st.project.phase}`);
				if (!kick(kickPrompt(st))) notify("已恢复；发任意一句话即继续");
				return;
			}
			if (!arg || arg === "status") {
				if (!found) return notify("用法: /nuwa 打 http://10.0.0.5:8080 拿 flag｜/nuwa 看板");
				const st = loadState(found);
				return notify(st ? statusBoard(st, found) : "state 读取失败", st ? "info" : "error");
			}

			warmBundledKb();
			const curCfg = readCfg();
			const sid = sidOf(ctx as ExtensionContext);
			const mode = pickMode(arg);
			const target = extractTarget(arg) ?? (mode === "coding" || mode === "ops" ? ctx.cwd : null);
			const want = target ? normalizeTargetForMode(target, mode).url : "";
			const root: string | null = target
				? defaultProjectRoot(ctx.cwd, target, sid, mode)
				: (findLocalRoot(ctx.cwd, sid) ?? (isSharedCwd(ctx.cwd) ? findRoot(ctx.cwd, sid) : null));
			if (!root) return notify("用法: /nuwa 打 http://10.0.0.5:8080 拿 flag；或先在该目录 nuwa_init / 设 NUWA_PROJECT", "error");
			const prev = loadState(root);
			if (prev?.project.ownerSessionId && prev.project.ownerSessionId !== sid) {
				return notify("该项目属于其他 omp 会话；用 NUWA_PROJECT 明确接管", "error");
			}
			if (prev && want && prev.project.url !== want) return notify(`根目录属于 ${prev.project.url}，与本次目标不同；请换目录`, "error");

			if (prev) {
				const it = withLock(root, () => {
					const s = loadState(root);
					if (!s) return null;
					s.project.status = "active";
					s.project.stopReason = undefined;
					s.project.ownerSessionId = sid;
					if (mode !== s.project.mode) s.project.mode = mode;
					const intent = addIntent(s, { title: arg, detail: arg, phase: s.project.phase, priority: 95 });
					saveState(root, s);
					return intent;
				});
				if (!it) return notify("state 读取失败", "error");
				writePointer(root, sid);
				const st = loadState(root)!;
				bindMainSession(ctx as ExtensionContext, root, st.project.id);
				logEvent(root, { type: "task", intent: it.id, text: arg, via: "command" });
				refreshUi(ctx as ExtensionContext, root, st, true);
				notify(`已并入 ${st.project.id}：${it.id} ${it.title}（phase=${it.phase} priority=95）\n${statusBoard(st, root)}`);
				if (!kick(kickPrompt(st))) notify("已记账；发任意一句话即开始执行");
				return;
			}

			if (!target) {
				return notify("没识别到目标。用法: /nuwa 打 http://10.0.0.5:8080 拿 flag\n也可先 export NUWA_TARGET=http://host:port 再 /nuwa <任务>", "error");
			}
			let st: NuwaState;
			let autoIds: string[] = [];
			try {
				const tc = probeToolchain();
				st = withLock(root, () => {
					const s = newState(target, arg, mode, curCfg, sid);
					s.project.toolchain = tc;
					s.project.sandboxMode = readSandboxConfig().mode;
					seedPhase(s, "recon");
					if (hasExec() && curCfg.auto) autoIds = claimAutoBatch(s, curCfg, root);
					saveState(root, s, { reason: "init" });
					return s;
				});
			} catch (e) {
				return notify(`上膛失败: ${e instanceof Error ? e.message : String(e)}`, "error");
			}
			mkdirSync(`/tmp/nuwa/${st.project.id}`, { recursive: true });
			writePointer(root, sid);
			bindMainSession(ctx as ExtensionContext, root, st.project.id);
			logEvent(root, { type: "init", id: st.project.id, url: st.project.url, mode: st.project.mode, via: "command" });
			refreshUi(ctx as ExtensionContext, root, st, true);
			if (autoIds.length > 0) void runAutoBatch(ctx as ExtensionContext, root, autoIds);
			notify(`女娲已上膛: ${st.project.id} · ${st.project.url} · mode=${st.project.mode}\n${statusBoard(st, root)}`);
			if (!kick(kickPrompt(st))) notify("已上膛；发任意一句话即开始执行");
		},
	});

	// ---------------------------------------------------------------- 事件与血缘路由
	let pump: { unref: () => void } | null = null;
	let pumpPeriodMs = 0;

	const tickAllPumpSessions = (): void => {
		const curCfg = readCfg();
		if (!curCfg.loop) return;
		for (const [sid, c] of pumpSessions.entries()) {
			try {
				if (!c || (c.isIdle && !c.isIdle()) || c.hasPendingMessages?.()) continue;
				const root = findLocalRoot(c.cwd, sid) ?? findRoot(c.cwd, sid);
				if (!root) continue;
				const probe = loadState(root);
				if (!probe || probe.project.status !== "active") continue;
				if (Date.now() - (probe.runtime.lastSettleAt ?? 0) < curCfg.tickMs) continue;

				let directive = "";
				let autoIds: string[] = [];
				let stoppedWhy = "";
				withLock(root, () => {
					const s = loadState(root);
					if (!s || s.project.status !== "active") return;
					const why = stopReason(s, curCfg);
					if (why) {
						s.project.status = "stopped";
						s.project.stopReason = why;
						stoppedWhy = why;
						saveState(root, s, { reason: "stop" });
						logEvent(root, { type: "stop_budget", why, via: "pump" });
						return;
					}
					applyEmptyGuard(s, curCfg, false);
					autoPlan(s, curCfg);
					if (hasExec()) autoIds = claimAutoBatch(s, curCfg, root);
					s.runtime.turns += 1;
					s.runtime.genTurns = (s.runtime.genTurns ?? 0) + 1;
					s.runtime.lastSettleAt = Date.now();
					directive = buildDirective(s, curCfg);
					s.runtime.lastDirective = directive;
					saveState(root, s);
					logEvent(root, { type: "pump", sessionId: sid, turn: s.runtime.turns, phase: s.project.phase });
				});
				if (stoppedWhy) {
					const halted = loadState(root);
					if (halted) refreshUi(c, root, halted, true);
					continue;
				}
				if (autoIds.length > 0) void runAutoBatch(c, root, autoIds);
				if (directive) sendDirectiveMessage(directive, "nuwa-pump");
			} catch {
				/* 单个会话看门狗失败不影响其它会话 */
			}
		}
	};

	const stopPump = (): void => {
		if (pump) {
			try {
				clearInterval(pump as unknown as ReturnType<typeof setInterval>);
			} catch {
				/* ignore */
			}
			pump = null;
			pumpPeriodMs = 0;
		}
	};

	const armPump = (ctx: ExtensionContext): void => {
		pumpSessions.set(sidOf(ctx), ctx);
		const wantPeriod = Math.max(50, readCfg().tickMs);
		if (pump && pumpPeriodMs === wantPeriod) return;
		stopPump();
		pumpPeriodMs = wantPeriod;
		pump = setNodeInterval(tickAllPumpSessions, wantPeriod);
		pump.unref();
	};

	pi.on("session_start", (_event, ctx) => {
		warmBundledKb();
		const c = ctx as ExtensionContext;
		if (isMain(c)) armPump(c);
		try {
			const sid = sidOf(c);
			if (!isMain(c)) {
				resolveRootWithLineage(c);
				return;
			}
			const root = findLocalRoot(c.cwd, sid) ?? findRoot(c.cwd, sid);
			if (!root) return;
			const st = loadState(root);
			if (st && st.project.status === "active") {
				bindMainSession(c, root, st.project.id);
				refreshUi(c, root, st, true);
			}
		} catch {
			/* 无项目或无 UI 通道 */
		}
	});

	pi.on("before_subagent_spawn" as Parameters<ExtensionAPI["on"]>[0], ((event: Record<string, unknown>, ctx: ExtensionContext) => {
		try {
			const root = resolveRootWithLineage(ctx);
			if (!root) return;
			bindSubagentSpawn(sidOf(ctx), ctx.agent?.id, root, getAgentHome());
			const st = loadState(root);
			if (!st || st.project.status !== "active") return;

			const agentName =
				typeof event?.agent === "string"
					? event.agent
					: typeof event?.agentName === "string"
						? event.agentName
						: typeof event?.name === "string"
							? event.name
							: "";
			const taskText = String(event?.task ?? event?.prompt ?? "");
			const activeIntents = Object.values(st.intents).filter((i) => i.status === "claimed" || i.status === "open");
			const claimedKeys = activeIntents.filter((i) => i.status === "claimed").map((i) => i.key);
			const hasPendingVerify =
				agentName === "nuwa-verifier" || activeIntents.some((i) => isVerifyVulnIntentKey(i.key)) || /verify-vuln:|\[双盲独立复验任务/.test(taskText);
			const hasReflect = claimedKeys.some((k) => k.startsWith("reflect:")) || /\breflect:|战略复盘/.test(taskText);

			const routedModel = routeSubagentModel({
				agent: agentName,
				phase: st.project.phase,
				intentKeys: claimedKeys,
				hasPendingVerify,
				hasReflect,
			});
			if (routedModel) {
				if (event && typeof event === "object" && !event.model) event.model = routedModel;
				return { model: routedModel };
			}
		} catch {
			/* ignore */
		}
		return;
	}) as Parameters<ExtensionAPI["on"]>[1]);

	pi.on("session_shutdown", (_event, ctx) => {
		const c = ctx as ExtensionContext;
		const sid = sidOf(c);
		pumpSessions.delete(sid);
		if (pumpSessions.size === 0) stopPump();
		try {
			const root = findLocalRoot(c.cwd, sid) ?? findRoot(c.cwd, sid);
			if (root) abortAutoBatch(root, "session_shutdown");
		} catch {
			/* ignore */
		}
		clearUi(c);
	});

	pi.on("tool_execution_end", (event, ctx) => {
		const sid = sidOf(ctx);
		liveCalls.set(sid, (liveCalls.get(sid) ?? 0) + 1);
		try {
			const { toolName, inputObj, command, output } = extractEventOutput((event ?? {}) as Record<string, unknown>);
			if (!isTrustedEvidenceEvent(toolName, inputObj)) return;
			const root = resolveRootWithLineage(ctx);
			if (!root) return;
			if (command || output) {
				recordToolExecution(root, { tool: toolName, command, output, sessionId: sid });
			}
		} catch {
			/* 账本记录异常不阻塞主流程 */
		}
	});

	pi.on("tool_call", (event: ToolCallEvent, ctx) => {
		try {
			const root = resolveRootWithLineage(ctx);
			if (!root) return;
			const st = loadState(root);
			if (!st) return;
			const active = st.project.status === "active";
			const main = isMain(ctx);
			const name = event.toolName;
			const input = ((event as { input?: Record<string, unknown> }).input ?? {}) as Record<string, unknown>;
			const projScope = st.project.scope ?? defaultScopeForTarget(st.project.url || st.project.target, st.project.mode);

			if (active && !main && /^nuwa_(init|plan|claim|commit|flag|complete|expand|stop)$/.test(name)) {
				return { block: true, reason: `nuwa N-005: ${name} 只能由主线程调用；子代理把结果回给主线程` };
			}
			if (name === "bash") {
				const cmd = typeof input.command === "string" ? input.command : "";
				const v = checkBashPolicy(cmd, active, main, projScope, st.project.mode);
				if (v) return v;
				if (active && !main) {
					const sbCfg = readSandboxConfig();
					if (sbCfg.mode === "docker" && cmd.trim()) {
						const sbVerdict = isCompliantSandboxDockerCommand(cmd, st.project.id);
						if (!sbVerdict.ok) {
							let hintCmd = "";
							try {
								hintCmd = wrapCommandInDockerSandbox(cmd, { projectId: st.project.id, scope: projScope, config: sbCfg, ensureWorkdir: false });
							} catch {
								hintCmd = "docker run --rm --read-only --cap-drop=ALL ...";
							}
							return { block: true, reason: `nuwa N-009: 已启用零信任 Docker 沙盒 (${sbVerdict.reason})；请改用合规沙盒包裹命令:\n${hintCmd}` };
						}
					}
				}
				return;
			}
			if (name === "task") {
				const v = checkTaskPolicy(input, active, main);
				if (v) return v;
				if (active && main) bindSubagentSpawn(sidOf(ctx), ctx.agent?.id, root, getAgentHome());
				return;
			}
			if (name === "eval") {
				const code = typeof input.code === "string" ? input.code : "";
				if (active && main && readCfg().requireFujiang && /\bagent\s*\(/.test(code) && !/\b(?:fujiang|nuwa-verifier)\b/.test(code)) {
					return { block: true, reason: 'nuwa N-004: eval 里的 agent() 必须显式 agent: "fujiang" 或 "nuwa-verifier"' };
				}
				if (active) {
					const sv = checkToolScopeAndRisk("eval", input, projScope, st.project.mode);
					if (sv) return sv;
				}
				return;
			}
			if (
				active &&
				(name === "read" || name === "read_file" || name === "fetch" || name === "web_fetch" ||
					name === "browser" || name.startsWith("browser_") ||
					name === "web_search" || name.startsWith("web_search") || name === "search_web" || name === "google_search")
			) {
				const sv = checkToolScopeAndRisk(name, input, projScope, st.project.mode);
				if (sv) return sv;
			}
			if (["write", "edit", "multi_edit", "apply_patch", "notebook_edit"].includes(name)) {
				const v = checkWritePolicy(input, active);
				if (v) return v;
			}
			return;
		} catch {
			return;
		}
	});

	pi.on("session_stop", (event: SessionStopEvent, ctx) => {
		try {
			const curCfg = readCfg();
			if (!curCfg.loop || !isMain(ctx)) return;
			const sid = String(event.session_id ?? sidOf(ctx));
			const local = findLocalRoot(ctx.cwd, sid);
			const root = local ?? (isSharedCwd(ctx.cwd) || process.env.NUWA_PROJECT ? findRoot(ctx.cwd, sid) : null);
			if (!root) return;
			const cur = loadState(root);
			if (!cur || cur.project.status !== "active") return;

			const lock = readJson<{ pid?: number }>(lockPath(root));
			if (lock?.pid && lock.pid !== process.pid && pidAlive(lock.pid)) return;

			const usage = ctx.getContextUsage?.() as { tokens?: number; usedTokens?: number } | undefined;
			const tokens = Number(usage?.tokens ?? usage?.usedTokens ?? 0);
			const settled = settleSessionStopState({ root, curCfg, tokens, liveCallCount: liveCalls.get(sid) ?? 0, canAutoExec: hasExec(), initialPhase: cur.project.phase });
			if (settled.stoppedWhy) {
				if (settled.state) refreshUi(ctx, root, settled.state, true);
				ctx.ui?.setStatus?.("nuwa", `停机 (${settled.stoppedWhy})`);
				return;
			}
			if (settled.reincarnated) {
				abortAutoBatch(root, "reincarnate");
				const latest = loadState(root) ?? settled.state;
				if (latest) refreshUi(ctx, root, latest, true);
				ctx.ui?.setStatus?.("nuwa", `世代交接 -> G${settled.reincarnated.generation} (${settled.reincarnated.reason})`);
				return undefined;
			}
			const directive = settled.directive;
			if (!directive || !settled.state) return;
			if (settled.autoIds.length) void runAutoBatch(ctx, root, settled.autoIds);
			refreshUi(ctx, root, settled.state, true);
			ctx.ui?.setStatus?.("nuwa", `续跑 #${settled.turn} · E${settled.episode} · ${settled.phase} · facts=${settled.facts} stall=${settled.stall}`);
			return { decision: "block" as const, reason: directive };
		} catch {
			return;
		}
	});
}
