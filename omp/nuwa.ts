/**
 * nuwa-omp v8.0.0 — 女娲模式：全自主安全评估与多领域执行引擎（单核合一精简组装入口）。
 *
 * 架构职责：
 *   - 全部 12 个 `nuwa_*` 核心工具与 `/nuwa` 斜杠子命令统一委托给权威单核 `NuwaUnifiedEngine` (`../core/engine`)；
 *   - 异步派单缓冲、`taskFile`/占位符展开、`eval` 词法解析与 `SubagentWatchdog` 生命周期统一委托给 `./dispatch-bridge`；
 *   - 本文件仅保留宿主 TUI 胶水、自动侦察批与后台续跑心跳钩子，并 100% 完整重导出 v4–v8 全部公共符号与类型。
 */
import { resolve } from "node:path";
import { setInterval as setNodeInterval } from "node:timers";
import type { ExtensionAPI, ExtensionContext, SessionStopEvent } from "@oh-my-pi/pi-coding-agent";
import {
	NUWA_SUBCOMMANDS,
	NuwaUnifiedEngine,
	checkCommitRealismGuard,
	isTerminalProjectState,
	loadStateZeroWrite,
	releaseInflightAutoBatch,
	statusBoardZeroWrite,
	syncTerminalReports,
	terminalStatusOf,
	type NuwaHostHooks,
	type NuwaSubcommand,
	type NuwaUnifiedEngineOptions,
	type SlashCommandResult,
	type UnifiedToolResult,
} from "../core/engine";
import { type ExecLike } from "./autoexec";
import {
	DispatchBridgeStore,
	handleBeforeSubagentSpawn,
	handleToolCallDispatch,
	handleToolExecutionEnd,
	handleToolResult,
	type DispatchToolCallEvent,
} from "./dispatch-bridge";
import {
	applyEmptyGuard,
	autoPlan,
	budgetPressure,
	buildDirective,
	claimAutoBatch,
	executeAutoBatchCycle,
	releaseAutoBatchRemaining,
	settleSessionStopState,
	sigOf,
	stopReason,
} from "./graph";
import { ensureBundledKb } from "./kb";
import { registerActiveSession, resolveLineageRoot } from "./lineage";
import {
	SubagentWatchdog,
	cleanupTrackedProcesses,
	findLocalRoot,
	findRoot,
	getAgentHome,
	hasProjectState,
	isPausedState,
	isSharedCwd,
	loadState,
	lockPath,
	logEvent,
	pidAlive,
	readCfg,
	readJournalTail,
	readJson,
	saveState,
	verifyWorkspaceIntegrity,
	withLock,
} from "./storage";
import type { NuwaState } from "./types";
import { buildSnapshot, renderBoardLines, renderStatusLine, renderWidgetLines, themeStyle } from "./ui";
import { createBoardComponent, createWidgetComponent } from "./ui-native";

export const VERSION = "8.0.0";

// ============================================================================
// 100% 向后兼容符号与类型全量重导出（覆盖 v4.0 – v7.0 全部模块）
// ============================================================================
export {
	NUWA_VERSION, PHASE_ORDER, type AssetNode, type AttemptedEntry, type AutoFactMeta, type AutoPlanResult,
	type Cfg, type CommitInput, type ExecRecordInput, type ExpansionResult, type Fact, type FactKind,
	type FrontierItem, type HypothesisNode, type Intent, type IntentStatus, type Mode, type NuwaState,
	type Phase, type PlanRejectReason, type PolicyVerdict, type ProfileMode, type ProfileSpec,
	type Project, type ProjectStatus, type ReincarnatePolicy, type RejectedIntentEntry, type Runtime,
	type RuntimeStatus, type ScopePolicy, type SealMeta, type Seed, type SurfaceDomain, type ToolchainCaps,
	type VerifyEvidenceInput, type VerifyEvidenceResult, type VerifyStage,
} from "./types";
export {
	ProcessGroupTracker, SCHEMA, SubagentWatchdog, atomicWrite, backupExistingProjectState, bindLoadedStateRoot,
	cell, checkAndLogAutoRuleSource, checkWorkspaceTempWarning, cleanupTrackedProcesses, createInitialState,
	defaultProjectRoot, findLocalRoot, findRoot, getAgentHome, getLoadedStateRoot, hasProjectState,
	installProcessCleanupHooks, isPausedState, isProcessAliveNonZombie, isSharedCwd, journalAppend, journalPath,
	loadState, loadStateJsonOnly, lockPath, logEvent, migrateSapper, nextFactId, nextIntentId, normOneLine,
	normalizeState, normalizeTarget, normalizeTargetForMode, nowIso, pausedStatePath, pidAlive,
	processTrackerPath, readCfg, readJournalTail, readJson, readPausedState, readSessionPointer,
	resolveDefaultWorkspacesDir, resolvePersistentStateDir, resolveStorageBackend, saveState, saveStateJsonOnly,
	setPausedState, sha, slug, sqliteDbPath, stateDir, statePath, subagentWatchdogPath, verifyWorkspaceIntegrity,
	withLock, writePointer,
	type CleanupProcessOptions, type CleanupProcessResult, type PausedState, type SaveStateOptions,
	type StorageBackend, type SubagentWatchdogConfig, type SubagentWatchdogEntry, type WatchdogSweepResult,
	type WorkspaceIntegrityOptions, type WorkspaceIntegrityReport, type WorkspaceWarning,
} from "./storage";
export {
	SEEDS, addFallbackIntent, addIntent, appendIntentSpecs, applyAutoItemResult, applyEmptyGuard,
	attachBeliefGraphCache, attempted, autoPlan, beliefGraphPath, budgetPressure, buildConvergenceAdvice,
	buildDirective, buildDoctorSummary, buildIntentDedupKey, canDeriveCrossSurface, checkBashPolicy,
	checkTaskPolicy, checkWritePolicy, claimAutoBatch, claimIntent, claimedFresh, collectPaths, commitFreeFact,
	commitIntent, compactFacts, compactIntents, completeProject, computeRepeatRatio, deriveFromFacts,
	evidenceProblem, executeAssetsCommand, executeAuthDiffWorkflow, executeAutoBatchCycle, executeBeliefCommand,
	executeCalibrateCommand, executeCdpCommand, executeChainsCommand, executeCommitWithGates, executeHybridCommand,
	executeMcpCommand, executeOobCommand, executeScopeCommand, executeSessionCommand, executeSessionHealthCommand,
	executeSquadCommand, executeTrafficCommand, expandGraph, extractEventOutput, extractIntentTargetKey,
	extractTarget, finalizeReportPhase, formatScopeSummary, frontierList, getCompletionRejectAdvice, hasAttempted,
	inferExpectedKind, inferSurfaceDomain, inspectGraph, isCompliantSandboxDockerCommand, isTargetInBlockedCooldown,
	kbLookup, kickPrompt, loadBeliefGraphReadOnly, loadOrInitBeliefGraph, maybeAdvance, newState,
	normalizeTargetKey, phaseIndex, pickMode, planIntents, proofKinds, recordFlag, releaseAutoBatchRemaining,
	releaseStaleClaims, renderDetail, reportMarkdown, runPostBatchAutonomousLoops, runSpaSurfaceWorkflow,
	saveBeliefGraph, sealEngagement, seedEpisode, seedPhase, settleSessionStopState, shouldRecommendSeal, sigOf,
	statusBoard, stopReason, tickNoveltyStall,
	type AddIntentInput, type CommitIntentResult, type ConvergenceAdvice, type FreeFactInput,
	type InspectGraphQuery, type InspectGraphResult, type PlanIntentsResult, type SealEngagementInput,
	type SealEngagementResult, type SealRecommendation,
} from "./graph";
export {
	buildHandoffSummary, prepareNextGeneration, readReincarnatePolicy, resolveReportPhaseTransition,
	shouldReincarnate, type ReportPhaseTransition,
} from "./reincarnate";
export {
	buildSnapshot, extractProbeHealth, renderBoardLines, renderFullStatus, renderStatusLine,
	renderWidgetLines, themeStyle, type FullStatusOptions, type ProbeHealthSummary,
} from "./ui";
export { createBoardComponent, createWidgetComponent } from "./ui-native";
export {
	classifyEndpointResponse, detectSoft404, injectEgressIntoScript, preflightEgressCheck, sampleSoft404Baseline,
} from "./autoexec";
export {
	buildChromiumLaunchConfig, detectChallengeGate, loadHumanSessionFromVault, saveHumanSessionToVault,
} from "./browser-recon";
export {
	buildUnifiedNetworkEnv, checkScopeAndRisk, checkToolScopeAndRisk, defaultScopeForTarget,
	extractInlineScriptTargets, formatScopeBlockReason, isHostInScope, type EnforcementLayer,
} from "./scope";
export {
	REQUIRED_CURL_WRITE_OUT, computeBodyHash, evaluatePositiveEvidenceGate, extractHitEvidenceMetrics,
	hasSubstantiveBusinessData, isTinyErrorEnvelope, isTrustedEvidenceEvent, parseAgentResult, probeToolchain,
	readFactEvidenceLog, recordToolExecution, saveFactEvidenceLog, validateDeliverableRealism,
	validateHitEvidenceFields, verifyExecutionEvidence,
	type AgentEvidenceItem, type AgentResult, type DeliverableRealismResult, type HitEvidenceMetrics,
	type ParseAgentResultOutcome, type PositiveEvidenceGateInput, type PositiveEvidenceGateResult,
	type SavedEvidenceLog,
} from "./evidence";
export {
	ALLOWED_SUBAGENT_MODELS, DEFAULT_BATCH_MAX_BYTES, DEFAULT_SUBAGENT_MODEL, DispatchReceiptRegistry,
	InflightTargetRegistry, bindSubagentSpawn, buildDispatchPacket, chunkBatchTasks, coalesceProbesByTarget,
	createDispatchReceiptRegistry, inferCalibrationTaskCategory, injectResolvedTargetContext,
	normalizeDispatchTargetKey, readSpilledBatchTasks, recommendIntentSpecialist, registerActiveSession,
	resolveLineageRoot, resolveTaskIntentContext, routeSubagentModel, validateSubagentDispatch,
	type BatchTaskItem, type ChunkBatchOptions, type ChunkBatchResult, type DispatchReceipt,
	type DispatchValidationResult, type SubagentDispatchPayload,
} from "./lineage";
export {
	canonicalizeExperienceIntentKey, computeExperiencePriorityBoost, distillProjectExperience,
	ensureBundledKb, kbLookupSafe,
} from "./kb";
export { redactVaultSecrets, upsertSessionRole } from "./session-vault";
export {
	buildFalsePositiveNote, extractVerifyTargetFactId, isVerifyVulnIntentKey,
	validateVerificationCommit, verifyPositiveConclusion,
} from "./verifier-gate";
export {
	EgressPoolManager, buildCurlProxyArgs, extractSandboxInnerCommand, injectEgressEnv,
	isCompliantSidecarCommand, maskEgressUrl, normalizeTaskEgressUrl, readSandboxConfig,
	resolveConfiguredEgressUrl, wrapCommandInDockerSandbox, wrapCommandInSidecarSandbox,
} from "./sandbox";
export { ensurePrimaryAsset } from "./hypothesis";
export {
	buildEpisodeTimelineData, buildJsonReport, buildSarifReport, exportEpisodeTimeline,
	searchArchiveIndexes, writeEpisodeArchiveIndex, writePocBundle,
	type ArchiveSearchHit, type ArchiveSearchQuery, type EpisodeArchiveIndex, type EpisodeArchiveInput,
	type ExportEpisodeTimelineOptions, type WriteEpisodeArchiveResult,
} from "./reporting";
export {
	ALL_SQLITE_TABLES, NuwaSqliteCorruptError, NuwaSqliteStore, SQLITE_SCHEMA_VERSION, V1_CORE_TABLES,
	V2_EXTENSION_TABLES, appendJournalSqlite, exportStateJsonCompat, loadStateFromSqlite,
	migrateJsonToSqlite, migrateSqliteSchemaV1ToV2, openNuwaDb, openSqliteReadonlyZeroWrite,
	queryFactsByText, readSqliteSchemaVersion, saveStateToSqlite,
	type AppendJournalOptions, type AssetCredentialRow, type AssetCredentialStatus, type CalibrationRecordRow,
	type ExportCompatOptions, type ExportCompatResult, type FactSearchHit, type LoadSqliteStateOptions,
	type MigrateJsonOptions, type MigrateJsonResult, type OobCorrelationRow, type OobCorrelationStatus,
	type OpenNuwaDbOptions, type ProtocolFrameDirection, type ProtocolFrameKind, type ProtocolFrameRow,
	type QueryFactsOptions, type SaveSqliteStateOptions, type SqliteSchemaMigrationResult,
	type SqliteTableName, type TrafficEntryRow, type TrafficQueryFilter as SqliteTrafficQueryFilter,
	type V1CoreTableName, type V2ExtensionTableName, type WorkflowActionLevel, type WorkflowRunRow,
} from "./sqlite-store";
export { normalizeCredentialFingerprint } from "./sqlite-schema";
export {
	DEFAULT_AUTHDIFF_COOLDOWN_MS, DEFAULT_MAX_AUTH_PATHS, DEFAULT_MAX_NEW_OOB_CANARIES,
	DEFAULT_OOB_POLL_INTERVAL_MS, collectTestableAuthPaths, computeAuthDiffSignature,
	planAutonomousOobProbes, runAutonomousAuthDiff, runAutonomousCdpLoop, runAutonomousChainVerification,
	runAutonomousOobPoll, shouldAutoTriggerAuthDiff,
	type AutoAuthDiffTriggerDecision, type AutoAuthDiffTriggerOptions, type AutonomousAuthDiffResult,
	type AutonomousCdpLoopResult, type AutonomousChainLoopResult, type AutonomousOobPlanResult,
	type AutonomousOobPollResult, type CollectAuthPathsOptions, type OobProbePlanItem, type OobSurfaceCategory,
	type PlanOobProbesOptions, type RunAutonomousAuthDiffOptions, type RunAutonomousCdpOptions,
	type RunAutonomousChainOptions, type RunOobPollOptions,
} from "./auto-loops";
export {
	DEFAULT_NEGATIVE_SEAL_THRESHOLD, DEFAULT_PROPAGATION_DECAY, DEFAULT_PRUNE_THRESHOLD,
	MAX_BETA_PARAM, MIN_BETA_PARAM, VALID_BELIEF_OBSERVATIONS, computeBetaPosterior,
	computeExpectedInfoGain, computeNodeUncertainty, computeOneStepEntropyReduction,
	initBeliefGraphFromState, propagateBeliefUpdate, pruneLowYieldSubtree, rankFrontierByBelief,
	recommendSearchPivot, resolveBeliefNodeId, shannonBinaryEntropy, updateBeliefPosterior,
	type BeliefGraph, type BeliefNode, type BeliefNodeKind, type BeliefObservation,
	type BeliefObservationType, type BeliefPropagationEvent, type BeliefPropagationResult,
	type PivotDirection, type PruneSubtreeOptions, type PruneSubtreeResult, type PruneSuggestion,
	type RankFrontierOptions, type RankedFrontierItem, type SearchPivotOptions,
	type SearchPivotRecommendation,
} from "./belief-search";
export {
	ALLOWED_SETTLEMENT_SOURCES, CalibrationError, VALID_TASK_CATEGORIES, calibrationLedgerPath,
	computeCalibrationSummary, formatCalibrationReport, hasCalibrationRecords, loadCalibrationRecords,
	recommendAdaptiveModelRoute, recordPrediction, redactCalibrationText, safeSettlePrediction,
	settlePrediction, validateSettlementSource,
	type AdaptiveModelRouteDecision, type AdaptiveModelRouteInput, type CalibrationBinStat,
	type CalibrationDimensionMetrics, type CalibrationErrorCode, type CalibrationPredictionInput,
	type CalibrationRecord, type CalibrationSettlementInput, type CalibrationSettlementSource,
	type CalibrationSummary, type CalibrationTaskCategory, type ComputeCalibrationOptions,
	type ModelCandidateEvaluation,
} from "./calibration";
export {
	MAX_MUTATION_CONCURRENCY, REDACTED_MARKER, TrafficRecorder, redactTrafficBody,
	redactTrafficHeaders, redactTrafficUrl, replayTrafficSequence, runStructuredMutations,
	type MutationAnomaly, type MutationBaseRequest, type MutationCaseResult, type MutationMode,
	type MutationProbeSummary, type ReplayStepResult, type ReplayTrafficOptions, type ReplayTrafficResult,
	type StructuredMutationsOptions, type StructuredMutationsResult, type TrafficEntry,
	type TrafficExtractorSpec, type TrafficFetchFn, type TrafficFetchResponseLike, type TrafficQueryFilter,
	type TrafficRecordInput, type TrafficRecorderOptions, type TrafficReplayStep,
} from "./traffic-workbench";
export {
	bridgeWhiteboxToBlackboxIntents, correlateBlackboxFindingToSource, extractCodeAttackSurface,
	extractFromSourceMap,
	type BlackboxFindingLike, type CodeAttackSurface, type CodeSinkKind, type CodeSinkWarning,
	type CodeSurfaceInput, type DetectedFramework, type ExtractSurfaceOptions, type ExtractedRoute,
	type HybridHypothesisSpec, type HybridVerificationIntentSpec, type RouteRiskFlag,
	type SourceCorrelationCandidate, type SourceCorrelationResult, type SupportedLanguage,
	type VirtualSourceFile, type WhiteboxBridgeOptions, type WhiteboxBridgeResult,
} from "./hybrid-audit";
export * from "./cdp-bridge";
export * from "./chain-composer";
export * from "./specialist-squad";
export * from "./kb-v2";
export * from "./dispatch-bridge";
export * from "./stateful-workflow";
export * from "./cdp-auth";
export * from "./protocol-inspector";
export {
	ASSET_ROUTER_VERSION, applySsrfUrlTemplate, probeViaConfirmedSsrf, resolveAssetRoutePlan, verifyCredentialPivot,
	type AssetRouteKind, type AssetRoutePlan, type AssetRoutePlanEntry, type CredentialCandidateTarget,
	type CredentialProbeStatus, type CredentialReuseFinding, type CredentialSpec, type HeaderBagLike,
	type ProbeViaConfirmedSsrfOptions, type ProbeViaConfirmedSsrfResult, type ResolveAssetRoutePlanOptions,
	type RouteTargetInput, type SocksTunnelSpec, type SsrfBlockedTarget, type SsrfProbeFinding,
	type SsrfTargetCandidate, type TrafficFetchFn as AssetRouterFetchFn, type TrafficFetchResponse,
	type VerifyCredentialPivotOptions, type VerifyCredentialPivotResult,
} from "./asset-router";
export * from "./resilience-oob";
export * from "./rgs-analyzer";
export * from "./v8-commands";
export {
	NUWA_SUBCOMMANDS, NuwaUnifiedEngine, checkCommitRealismGuard, isTerminalProjectState,
	loadStateZeroWrite, releaseInflightAutoBatch, statusBoardZeroWrite, syncTerminalReports, terminalStatusOf,
	type NuwaHostHooks, type NuwaSubcommand, type NuwaUnifiedEngineOptions,
	type SlashCommandResult, type UnifiedToolResult,
};

// ============================================================================
// omp 宿主轻量胶水与单核委托入口
// ============================================================================
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

function warmBundledKb(agentHome?: string): void {
	try {
		ensureBundledKb(undefined, { agentHome: agentHome ?? getAgentHome() });
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

export default function nuwaOmp(pi: ExtensionAPI) {
	const z = pi.zod;
	const bridgeStore = new DispatchBridgeStore();
	const engine = new NuwaUnifiedEngine({ hostAgentId: "omp-main", emitAutoStartSkipNote: false });
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
		bridgeStore.clearByRoot(normRoot);
		return releaseInflightAutoBatch(normRoot, reason);
	};

	const readUiCfg = () => {
		const e = (k: string, d: string): string => (process.env[k] ?? d).trim();
		return {
			enabled: e("NUWA_UI", "1") !== "0",
			widget: e("NUWA_UI_WIDGET", "1") !== "0",
			lines: (e("NUWA_UI_LINES", "3") === "5" ? 5 : 3) as 3 | 5,
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

	const runAutoBatch = async (ctx: ExtensionContext, root: string, ids: string[]): Promise<void> => {
		if (!ids.length || !hasExec()) return;
		const normRoot = resolve(root);
		autoAborts.get(normRoot)?.abort("superseded");
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

	const hooksForCtx = (ctx?: ExtensionContext): NuwaHostHooks => ({
		getSessionId: () => (ctx ? sidOf(ctx) : "default"),
		getCwd: () => ctx?.cwd ?? process.cwd(),
		getAgentHome: () => getAgentHome(),
		resolveRoot: (explicit) => (ctx ? resolveRootWithLineage(ctx, explicit) : findRoot(process.cwd(), "default")),
		onBindSession: (root, projectId) => {
			if (ctx) bindMainSession(ctx, root, projectId);
		},
		onRefreshUi: (root, st, force) => {
			if (ctx) refreshUi(ctx, root, st, force);
		},
		getLiveTokens: () => {
			const usage = ctx?.getContextUsage?.() as { tokens?: number; usedTokens?: number } | undefined;
			return Number(usage?.tokens ?? usage?.usedTokens ?? 0);
		},
		canRunAutoBatch: () => hasExec(),
		onStartAutoBatch: (root, ids) => {
			if (ctx) void runAutoBatch(ctx, root, ids);
		},
		onAbortAutoBatch: (root, reason) => abortAutoBatch(root, reason),
		onNotify: (msg, level) => {
			try {
				ctx?.ui?.notify?.(msg, level);
			} catch {
				/* 非 TUI 忽略 */
			}
		},
		onKick: (promptText) => sendDirectiveMessage(promptText, "nuwa-kick"),
		onWarmKb: (agentHome) => warmBundledKb(agentHome),
		onRenderBoardOverlay: async (root, st) => {
			if (!ctx?.ui?.custom) return false;
			const curCfg = readCfg();
			const snap = buildSnapshot(st, curCfg, budgetPressure(st, curCfg), readJournalTail(root, 400));
			try {
				await ctx.ui.custom(
					(_tui, theme, _kb, done) => {
						const th = themeStyle(theme as unknown as { fg(color: string, text: string): string; bold(text: string): string });
						return createBoardComponent(snap, th, () => done(undefined));
					},
					{ overlay: true, overlayOptions: { width: "92%", maxHeight: "85%", anchor: "center" } },
				);
				return true;
			} catch {
				const style = themeStyle(ctx.ui.theme as unknown as { fg(color: string, text: string): string; bold(text: string): string });
				ctx.ui.notify(renderBoardLines(snap, style, { width: 88 }).join("\n"), "info");
				return true;
			}
		},
	});

	// ---------------------------------------------------------------- 12 个核心工具（全部委托 NuwaUnifiedEngine）
	pi.registerTool({
		name: "nuwa_init",
		label: "女娲初始化",
		description: "创建/恢复女娲项目：初始化 SQLite WAL / state.json、靶标 Scope 护栏、工作区完整性基线、KB 2.0 便携知识库与本地工具链探针，播种首阶段意图，返回看板。",
		loadMode: "essential",
		parameters: z.object({
			target: z.string().optional().describe("目标 URL、host:port 或本地目录/服务标识（coding/ops）"),
			goal: z.string().optional().describe("目标描述"),
			mode: z.enum(["ctf", "pentest", "audit", "coding", "ops"]).optional().describe("任务模式，决定阶段种子与完成证据类型（未指定时默认沿用已有项目 mode，新建项目默认 ctf）"),
			root: z.string().optional().describe("项目目录，默认持久化工作区或当前 cwd"),
			resume: z.boolean().default(false).describe("恢复已停止/软暂停的项目，保留 facts/intents"),
			force: z.boolean().default(false).describe("覆盖现有项目（备份旧 state）"),
			migrate: z.boolean().default(false).describe("从同目录 .sapper 图迁移旧项目"),
			autoStart: z.boolean().default(false).describe("是否在初始化后立即触发首轮确定性自动侦察批"),
			scope: z
				.object({
					allowHosts: z.array(z.string()).optional(), allowCidrs: z.array(z.string()).optional(),
					denyHosts: z.array(z.string()).optional(), allowSubdomains: z.boolean().optional(),
					allowPrivateNetwork: z.boolean().optional(), allowDestructive: z.boolean().optional(),
					allowLoopback: z.boolean().optional(), oobDomains: z.array(z.string()).optional(),
				})
				.optional()
				.describe("可选靶标范围与风险策略覆盖"),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_init", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_plan",
		label: "女娲规划",
		description: "播种一个阶段的意图（recon/surface/vuln/exploit/post/report），或追加自定义意图。支持规范化三元组去重、在途目标去重、批派单 6KB 分片溢写与出口注入，返回 rejectedReasons。",
		loadMode: "essential",
		parameters: z.object({
			phase: z.enum(["recon", "surface", "vuln", "exploit", "post", "report"]).optional().describe("要播种的阶段"),
			intents: z
				.array(
					z.object({
						title: z.string(),
						detail: z.string().optional(),
						phase: z.enum(["recon", "surface", "vuln", "exploit", "post", "report"]).optional(),
						from: z.array(z.string()).optional(),
						priority: z.number().optional(),
						target: z.string().optional(),
						targetKey: z.string().optional(),
						hint: z.string().optional(),
						expectedKind: z.enum(["target", "asset", "service", "endpoint", "cred", "vuln", "flag", "loot", "note", "blocked"]).optional(),
						surfaceDomain: z.enum(["port", "path", "host"]).optional(),
						force: z.boolean().optional(),
					}),
				)
				.optional()
				.describe("自定义意图列表"),
			force: z.boolean().optional().describe("是否强制绕过冷却与重复抑制"),
			cooldown_ms: z.number().optional().describe("可选 blocked 目标冷却窗口毫秒数"),
			egress: z.string().optional().describe("可选任务出口代理 URL（自动注入派单上下文与环境变量）"),
			batch_tasks: z.array(z.record(z.string(), z.any())).optional().describe("可选待派发子任务批次：自动执行在途去重、出口注入与 >6000B 安全分片/溢写"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_plan", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_frontier",
		label: "女娲待办",
		description: "列出当前可执行意图（依赖事实已满足、未被有效认领），结合信念图、历史经验与 5+1 专精小队推荐自适应排序。",
		loadMode: "essential",
		parameters: z.object({ limit: z.number().default(12), root: z.string().optional() }),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_frontier", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_claim",
		label: "女娲认领",
		description: "认领一条意图，返回完整派单包（自动注入 resolved_host、出口代理指引、多角色鉴权差分头文件与输出契约，并登记在途目标去重）。",
		loadMode: "essential",
		parameters: z.object({
			id: z.string().describe("意图 id，如 i007"),
			worker: z.string().default("fujiang"),
			egress: z.string().optional().describe("可选任务出口代理 URL（如 socks5h://127.0.0.1:7890）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_claim", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_commit",
		label: "女娲记账",
		description: "提交意图结果或免票据直记事实（省略 id 或 free_note=true）。支持省略 kind 自动继承 expectedKind、结构化 agent_result 解析、evidence_ref 落盘指针、模板化回包拦截与假阳性门禁，并回显 blockedIntents vs blockedCommits。",
		loadMode: "essential",
		parameters: z.object({
			id: z.string().optional().describe("意图 id；省略或设 free_note=true 时免票据直接落账（#31）"),
			free_note: z.boolean().optional().describe("免票据直记开关：open=0 时无需占用 intent 直接写入事实（#31）"),
			kind: z.enum(["target", "asset", "service", "endpoint", "cred", "vuln", "flag", "loot", "note", "blocked"]).optional().describe("事实类型；省略时自动继承认领意图的 expectedKind（兜底 note，#29）"),
			title: z.string().default(""),
			detail: z.string().default(""),
			command: z.string().optional(),
			output: z.string().optional(),
			blocked: z.boolean().default(false),
			note: z.string().optional(),
			agent_result: z.union([z.string(), z.record(z.string(), z.any())]).optional().describe("子代理结构化回包 AgentResult（JSON 对象或字符串），自动解析提取命令、证据指标与结论（#51）"),
			evidence_ref: z.string().optional().describe("原始响应/日志证据文件相对路径指针（如 .nuwa/evidence/f001.log，#42）"),
			save_evidence_log: z.boolean().optional().describe("是否自动将原始响应脱敏落盘到 .nuwa/evidence/<factId>.log 并绑定 evidence_ref（#42）"),
			raw_response: z.string().optional().describe("可选完整原始 HTTP 响应内容，用于证据落盘与假阳性复核"),
			baseline: z.any().optional().describe("可选负向对照基线响应（401/404），用于假阳性门禁比对（#24）"),
			auto_downgrade: z.boolean().optional().describe("命中假阳性门禁时是否自动降级为 note(false_positive) 落账（#24）"),
			strict_realism: z.boolean().optional().describe("是否强制校验网络探针五项命中指标（#26, #39）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_commit", p as Record<string, unknown>, hooksForCtx(ctx));
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
			return engine.callTool("nuwa_flag", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_complete",
		label: "女娲收口",
		description: "请求完成项目或执行负向封盘（seal=true → status=sealed_negative，与夺旗并列为合法终态）。无实锤被拒时自动输出 report/seal 策略收敛建议。",
		loadMode: "essential",
		parameters: z.object({
			from: z.array(z.string()).optional().describe("完成引用的 fact id；省略则用全部已确认证据事实"),
			note: z.string().optional(),
			seal: z.boolean().optional().describe("负向封盘开关：对已穷尽攻击面且无正向漏洞的硬化目标合法封盘（status=sealed_negative，#22）"),
			reason: z.string().optional().describe("负向封盘依据说明（seal=true 时使用）"),
			excluded_surface: z.array(z.string()).optional().describe("已验证排除的攻击面列表（seal=true 时记录）"),
			coverage: z.record(z.string(), z.any()).optional().describe("覆盖度指标字典（seal=true 时合并记录）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_complete", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_status",
		label: "女娲看板",
		description: "查看项目状态（展示 repeat_ratio、last_ok、blockedIntents vs blockedCommits）。支持 raw/offset/limit/format 全量不截断输出，以及 inspect_intent / query_status / target_key / archive_query 纯只读零写入诊断。",
		loadMode: "essential",
		parameters: z.object({
			raw: z.boolean().optional().describe("是否输出不截断全量状态（#34）"),
			offset: z.number().optional().describe("全量状态或只读查询分页起始偏移（#34）"),
			limit: z.number().optional().describe("分页返回最大条数（#34, #35, #52）"),
			format: z.enum(["text", "json"]).optional().describe("输出格式：text（默认）或 json（#34）"),
			inspect_intent: z.string().optional().describe("纯只读诊断指定意图 ID（零磁盘写入，#35）"),
			query_status: z.enum(["open", "claimed", "done", "blocked"]).optional().describe("纯只读按状态筛选意图（零磁盘写入，#35）"),
			target_key: z.string().optional().describe("纯只读按目标键筛选意图（零磁盘写入，#35）"),
			archive_query: z.union([z.string(), z.record(z.string(), z.any())]).optional().describe("纯只读检索跨轮 Episode 结构化归档索引（#52）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_status", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_report",
		label: "女娲报告",
		description: "生成评估报告（支持 md/json/sarif 2.1.0/timeline 时间线导出）。write=true 时落盘并自动写入 .nuwa/archive/episode-<N> 结构化归档索引，同时支持 report 阶段完结转移。",
		loadMode: "essential",
		parameters: z.object({
			write: z.boolean().default(false),
			format: z.enum(["md", "json", "sarif", "timeline"]).default("md").describe("报告格式：md（默认）/ json / sarif / timeline（#42）"),
			episode: z.number().optional().describe("指定 Episode 编号（用于 timeline 导出与归档索引，#42, #52）"),
			bundle: z.boolean().default(false).describe("是否同时生成 .nuwa/poc-bundle 脱敏证据包"),
			archive: z.boolean().optional().describe("是否显式写入 .nuwa/archive/episode-<N>.json/.md 归档索引（write=true 时默认自动写入，#52）"),
			finalize_phase: z.boolean().optional().describe("处于 report 阶段时是否立即执行完结/封盘/推进转移（#45）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_report", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_expand",
		label: "女娲扩张",
		description: "强制扩张攻击面：结合三元组去重、在途去重、表面分域保护、批分片与出口注入派生新意图，输出结构化 rejectedReasons。",
		loadMode: "essential",
		parameters: z.object({
			force: z.boolean().optional().describe("是否强制重派生"),
			egress: z.string().optional().describe("可选出口代理 URL 注入新派生意图"),
			batch_tasks: z.array(z.record(z.string(), z.any())).optional().describe("可选待派发任务列表：执行跨子代理在途去重、同目标探针合并与 >6000B 分片保护"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_expand", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_stop",
		label: "女娲停机",
		description: "停机与软暂停控制：传 pause=true 可免确认即时软暂停（优雅挂起，/nuwa resume 恢复）；永动模式硬停机须显式传 confirm=\"STOP\"，硬停机时自动中断在途批并级联清理登记的残留子进程组。",
		loadMode: "essential",
		parameters: z.object({
			reason: z.string().default("manual stop/pause").describe("停机或软暂停原因（硬停机至少 4 字）"),
			confirm: z.string().optional().describe('硬停机确认口令：永动模式下人工硬停机必须显式传 "STOP"'),
			pause: z.boolean().optional().default(false).describe("免确认即时软暂停开关（true 时无需 confirm=\"STOP\" 立即优雅挂起，#44）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_stop", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});
	pi.registerTool({
		name: "nuwa_kb",
		label: "女娲知识库",
		description: "安全查询 KB 2.0 混合语义便携知识库（FTS5 + 中英同义扩展 + TF-IDF/N-gram/SimHash + 蒸馏经验治理）：支持产品审计卡、CVE、ATT&CK 技术与检查单。",
		loadMode: "essential",
		parameters: z.object({
			query: z.string(),
			kind: z.enum(["auto", "product", "cve", "technique", "poc"]).default("auto"),
			limit: z.number().default(5),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			return engine.callTool("nuwa_kb", p as Record<string, unknown>, hooksForCtx(ctx));
		},
	});

	// ---------------------------------------------------------------- 斜杠命令（全面委托 NuwaUnifiedEngine）
	pi.registerCommand?.("nuwa", {
		description: "女娲模式：/nuwa <目标任务> | status | board | belief | calibrate | traffic | hybrid | mcp | cdp | chains | squad | scope | session | authdiff | oob | assets | spa | report | export | seal | inspect | query | pause | stop | resume | doctor",
		getArgumentCompletions: (prefix) =>
			NUWA_SUBCOMMANDS.filter((s) => s.startsWith(prefix)).map((s) => ({ value: s, label: s })),
		handler: async (args, ctx) => {
			await engine.executeSlashCommand(args, hooksForCtx(ctx as ExtensionContext));
		},
	});

	// ---------------------------------------------------------------- 会话心跳与派单桥接事件钩子
	let pump: { unref: () => void } | null = null;
	let pumpPeriodMs = 0;

	const tickAllPumpSessions = (): void => {
		const curCfg = readCfg();
		if (!curCfg.loop) return;
		for (const [sid, c] of pumpSessions.entries()) {
			try {
				if (!c || (c.isIdle && !c.isIdle()) || c.hasPendingMessages?.()) continue;
				const root = findLocalRoot(c.cwd, sid) ?? findRoot(c.cwd, sid);
				if (!root || isPausedState(root)) continue;
				const probe = loadState(root);
				if (!probe || probe.project.status !== "active" || isTerminalProjectState(probe)) continue;
				if (Date.now() - (probe.runtime.lastSettleAt ?? 0) < curCfg.tickMs) continue;

				try {
					new SubagentWatchdog(root).checkTimeouts();
				} catch {
					/* ignore watchdog sweep error */
				}
				const wsCheck = verifyWorkspaceIntegrity(root);
				if (!wsCheck.ok && wsCheck.status === "corrupted") {
					logEvent(root, { type: "workspace_corrupted", warnings: wsCheck.warnings });
					continue;
				}

				let directive = "";
				let autoIds: string[] = [];
				let stoppedWhy = "";
				withLock(root, () => {
					const s = loadState(root);
					if (!s || s.project.status !== "active" || isTerminalProjectState(s)) return;
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
					s.runtime.totalTurns = Math.max(s.runtime.totalTurns ?? 0, s.runtime.turns - 1) + 1;
					s.runtime.genTurns = (s.runtime.genTurns ?? 0) + 1;
					s.runtime.lastSettleAt = Date.now();
					directive = buildDirective(s, curCfg, root);
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
				verifyWorkspaceIntegrity(root, { recordBaseline: true });
				bindMainSession(c, root, st.project.id);
				refreshUi(c, root, st, true);
			}
		} catch {
			/* 无项目或无 UI 通道 */
		}
	});

	pi.on("before_subagent_spawn" as Parameters<ExtensionAPI["on"]>[0], ((event: Record<string, unknown>, ctx: ExtensionContext) =>
		handleBeforeSubagentSpawn(bridgeStore, event, ctx)) as Parameters<ExtensionAPI["on"]>[1]);

	pi.on("session_shutdown", (_event, ctx) => {
		const c = ctx as ExtensionContext;
		const sid = sidOf(c);
		pumpSessions.delete(sid);
		if (pumpSessions.size === 0) stopPump();
		try {
			const root = findLocalRoot(c.cwd, sid) ?? findRoot(c.cwd, sid);
			if (root) {
				abortAutoBatch(root, "session_shutdown");
				try {
					const wd = new SubagentWatchdog(root);
					for (const t of wd.listTasks({ status: "running" })) {
						wd.completeTask(t.taskId, "cancelled");
						bridgeStore.activeSpawns.delete(t.taskId);
					}
				} catch {
					/* ignore watchdog cleanup */
				}
				cleanupTrackedProcesses(root, { reason: "session_shutdown" });
				bridgeStore.clearByRoot(root, sid);
			}
		} catch {
			/* ignore */
		}
		clearUi(c);
	});

	pi.on("tool_execution_end", (event, ctx) => {
		handleToolExecutionEnd(bridgeStore, event, ctx as ExtensionContext);
	});

	pi.on("tool_result", (event, ctx) => {
		handleToolResult(bridgeStore, event, ctx as ExtensionContext);
	});

	pi.on("tool_call", (event, ctx) =>
		handleToolCallDispatch(bridgeStore, event as unknown as DispatchToolCallEvent, ctx as ExtensionContext));

	pi.on("session_stop", (event: SessionStopEvent, ctx) => {
		try {
			const curCfg = readCfg();
			if (!curCfg.loop || !isMain(ctx)) return;
			const sid = String(event.session_id ?? sidOf(ctx));
			const local = findLocalRoot(ctx.cwd, sid);
			const root = local ?? (isSharedCwd(ctx.cwd) || process.env.NUWA_PROJECT ? findRoot(ctx.cwd, sid) : null);
			if (!root) return;

			if (isPausedState(root)) {
				ctx.ui?.setStatus?.("nuwa", "已软暂停 (/nuwa resume 恢复)");
				return undefined;
			}

			const cur = loadState(root);
			if (!cur || cur.project.status !== "active" || isTerminalProjectState(cur)) return;

			const lock = readJson<{ pid?: number }>(lockPath(root));
			if (lock?.pid && lock.pid !== process.pid && pidAlive(lock.pid)) return;

			try {
				new SubagentWatchdog(root).checkTimeouts();
			} catch {
				/* ignore */
			}

			const wsReport = verifyWorkspaceIntegrity(root);
			if (!wsReport.ok && wsReport.status === "corrupted") {
				logEvent(root, { type: "workspace_corrupted", warnings: wsReport.warnings });
				ctx.ui?.setStatus?.("nuwa", `工作区异常 (${wsReport.warnings[0]?.code ?? "corrupted"})`);
				return undefined;
			}

			const usage = ctx.getContextUsage?.() as { tokens?: number; usedTokens?: number } | undefined;
			const tokens = Number(usage?.tokens ?? usage?.usedTokens ?? 0);
			const settled = settleSessionStopState({
				root,
				curCfg,
				tokens,
				liveCallCount: bridgeStore.getLiveCallCount(sid),
				canAutoExec: hasExec(),
				initialPhase: cur.project.phase,
			});
			if (settled.stoppedWhy) {
				cleanupTrackedProcesses(root, { reason: `session_stop:${settled.stoppedWhy}` });
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
