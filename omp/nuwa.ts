/**
 * nuwa-omp v6.0.0 — 女娲模式：全自主安全评估与多领域执行引擎（纯 omp 原生组装入口）。
 *
 * 子模块分工：
 *   - `./types`         共享类型契约与常量
 *   - `./storage`       配置、文件锁、原子写、进程组登记回收、软暂停、子代理看门狗与工作区完整性校验
 *   - `./graph`         六阶段种子、表面分域三元组去重、封盘终态、语义停滞、免票据直记、只读图诊断与纪律策略
 *   - `./lineage`       主从会话血缘追踪、子代理派单守卫、6KB 分片保护、在途目标去重与动态模型路由
 *   - `./scope`         跨运行时统一靶标范围护栏（含内联脚本拦截与显式拦截层标签）
 *   - `./evidence`      可信执行证据账本、假阳性复核门禁、模板化回包拦截、证据落盘与 AgentResult 解析
 *   - `./autoexec`      出口注入与 Gate 预检、Soft-404 多语言/RSC 识别、端点鉴权分类与多出口健康池
 *   - `./browser-recon` 合规持久化浏览器会话、挑战门确定性识别停机与静态 JS Bundle 接口感知
 *   - `./kb`            随仓便携 SQLite FTS5 知识库与跨项目脱敏经验蒸馏
 *   - `./session-vault` 多角色认证会话保险箱、会话健康巡检与零明文鉴权差分重放
 *   - `./auth-diff`     确定性多角色只读鉴权差分矩阵（Auto-BOLA / BFLA）
 *   - `./verifier-gate` 候选漏洞双盲独立挑刺复验闸门与假阳性降级辅助
 *   - `./sandbox`       零信任 Docker / Sidecar 沙盒、抗 DNS 重绑定 Egress Proxy 与出口熔断池
 *   - `./oob`           一等 OOB 外带回调 Canary 通道（受 scope.oobDomains 门控）
 *   - `./hypothesis`    多资产跳板拓扑、跨事实假设图推理与驳回剪枝
 *   - `./reporting`     分层 Markdown / SARIF 2.1.0 / JSON / Episode 时间线 / 结构化归档索引与脱敏证据包导出
 */
import { existsSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { join, resolve } from "node:path";
import { setInterval as setNodeInterval } from "node:timers";
import type { ExtensionAPI, ExtensionContext, SessionStopEvent, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";
import {
	NUWA_VERSION, PHASE_ORDER, type AssetNode, type AttemptedEntry, type AutoFactMeta, type AutoPlanResult,
	type Cfg, type CommitInput, type ExecRecordInput, type ExpansionResult, type Fact, type FactKind,
	type FrontierItem, type HypothesisNode, type Intent, type IntentStatus, type Mode, type NuwaState,
	type Phase, type PlanRejectReason, type PolicyVerdict, type ProfileMode, type ProfileSpec,
	type Project, type ProjectStatus, type ReincarnatePolicy, type RejectedIntentEntry, type Runtime,
	type RuntimeStatus, type ScopePolicy, type SealMeta, type Seed, type SurfaceDomain, type ToolchainCaps,
	type VerifyEvidenceInput, type VerifyEvidenceResult, type VerifyStage,
} from "./types";
import {
	SCHEMA, ProcessGroupTracker, SubagentWatchdog, atomicWrite, backupExistingProjectState, bindLoadedStateRoot, cell, checkAndLogAutoRuleSource,
	checkWorkspaceTempWarning, cleanupTrackedProcesses, createInitialState, defaultProjectRoot,
	findLocalRoot, findRoot, getAgentHome, getLoadedStateRoot, installProcessCleanupHooks, isPausedState,
	isProcessAliveNonZombie, isSharedCwd, journalAppend, journalPath, loadState, lockPath, logEvent, migrateSapper, nextFactId, nextIntentId,
	normOneLine, normalizeState, normalizeTarget, normalizeTargetForMode, nowIso, pausedStatePath,
	pidAlive, processTrackerPath, readCfg, readJournalTail, readJson, readPausedState, readSessionPointer,
	hasProjectState, loadStateJsonOnly, resolveDefaultWorkspacesDir, resolvePersistentStateDir, resolveStorageBackend, saveState, saveStateJsonOnly, setPausedState, sha, slug, sqliteDbPath,
	stateDir, statePath, subagentWatchdogPath, verifyWorkspaceIntegrity, withLock, writePointer,
	type CleanupProcessOptions, type CleanupProcessResult, type PausedState, type SaveStateOptions,
	type SubagentWatchdogConfig, type SubagentWatchdogEntry, type WatchdogSweepResult,
	type StorageBackend, type WorkspaceIntegrityOptions, type WorkspaceIntegrityReport, type WorkspaceWarning,
} from "./storage";
import {
	SEEDS, addFallbackIntent, addIntent, appendIntentSpecs, applyAutoItemResult, applyEmptyGuard,
	attempted, autoPlan, budgetPressure, buildConvergenceAdvice, buildDirective, buildDoctorSummary,
	buildIntentDedupKey, canDeriveCrossSurface, checkBashPolicy, checkTaskPolicy, checkWritePolicy,
	claimAutoBatch, claimIntent, claimedFresh, collectPaths, commitFreeFact, commitIntent, compactFacts,
	compactIntents, completeProject, computeRepeatRatio, deriveFromFacts, evidenceProblem,
	attachBeliefGraphCache, beliefGraphPath, executeAssetsCommand, executeAuthDiffWorkflow, executeAutoBatchCycle, executeBeliefCommand, executeCalibrateCommand, executeCommitWithGates,
	executeHybridCommand, executeMcpCommand, executeOobCommand, executeScopeCommand, executeSessionCommand, executeSessionHealthCommand, executeTrafficCommand, loadBeliefGraphReadOnly, loadOrInitBeliefGraph, runPostBatchAutonomousLoops, saveBeliefGraph,
	expandGraph, extractEventOutput, extractIntentTargetKey, extractTarget, finalizeReportPhase,
	formatScopeSummary, frontierList, getCompletionRejectAdvice, hasAttempted, inferExpectedKind,
	inferSurfaceDomain, inspectGraph, isCompliantSandboxDockerCommand, isTargetInBlockedCooldown,
	kbLookup, kickPrompt, maybeAdvance, newState, normalizeTargetKey, phaseIndex, pickMode, planIntents,
	proofKinds, recordFlag, releaseAutoBatchRemaining, releaseStaleClaims, renderDetail, reportMarkdown,
	runSpaSurfaceWorkflow, sealEngagement, seedEpisode, seedPhase, settleSessionStopState,
	shouldRecommendSeal, sigOf, statusBoard, stopReason, tickNoveltyStall,
	type AddIntentInput, type CommitIntentResult, type ConvergenceAdvice, type FreeFactInput,
	type InspectGraphQuery, type InspectGraphResult, type PlanIntentsResult, type SealEngagementInput,
	type SealEngagementResult, type SealRecommendation,
} from "./graph";
import {
	buildHandoffSummary, prepareNextGeneration, readReincarnatePolicy, resolveReportPhaseTransition,
	shouldReincarnate, type ReportPhaseTransition,
} from "./reincarnate";
import {
	buildSnapshot, extractProbeHealth, renderBoardLines, renderFullStatus, renderStatusLine,
	renderWidgetLines, themeStyle, type FullStatusOptions, type ProbeHealthSummary,
} from "./ui";
import { createBoardComponent, createWidgetComponent } from "./ui-native";
import {
	classifyEndpointResponse, detectSoft404, injectEgressIntoScript, preflightEgressCheck,
	sampleSoft404Baseline, type ExecLike,
} from "./autoexec";
import {
	buildChromiumLaunchConfig, detectChallengeGate, loadHumanSessionFromVault, saveHumanSessionToVault,
} from "./browser-recon";
import {
	buildUnifiedNetworkEnv, checkScopeAndRisk, checkToolScopeAndRisk, defaultScopeForTarget,
	extractInlineScriptTargets, formatScopeBlockReason, isHostInScope, type EnforcementLayer,
} from "./scope";
import {
	REQUIRED_CURL_WRITE_OUT, computeBodyHash, evaluatePositiveEvidenceGate, extractHitEvidenceMetrics,
	hasSubstantiveBusinessData, isTinyErrorEnvelope, isTrustedEvidenceEvent, parseAgentResult,
	probeToolchain, readFactEvidenceLog, recordToolExecution, saveFactEvidenceLog,
	validateDeliverableRealism, validateHitEvidenceFields, verifyExecutionEvidence,
	type AgentEvidenceItem, type AgentResult, type DeliverableRealismResult, type HitEvidenceMetrics,
	type ParseAgentResultOutcome, type PositiveEvidenceGateInput, type PositiveEvidenceGateResult,
	type SavedEvidenceLog,
} from "./evidence";
import {
	DEFAULT_BATCH_MAX_BYTES, DispatchReceiptRegistry, InflightTargetRegistry, bindSubagentSpawn,
	buildDispatchPacket, chunkBatchTasks, coalesceProbesByTarget, createDispatchReceiptRegistry,
	injectResolvedTargetContext, normalizeDispatchTargetKey, readSpilledBatchTasks,
	ALLOWED_SUBAGENT_MODELS, DEFAULT_SUBAGENT_MODEL, inferCalibrationTaskCategory, registerActiveSession, resolveLineageRoot, resolveTaskIntentContext, routeSubagentModel,
	validateSubagentDispatch, type BatchTaskItem, type ChunkBatchOptions, type ChunkBatchResult,
	type DispatchReceipt, type DispatchValidationResult, type SubagentDispatchPayload,
} from "./lineage";
import { distillProjectExperience, ensureBundledKb, kbLookupSafe } from "./kb";
import { redactVaultSecrets, upsertSessionRole } from "./session-vault";
import {
	buildFalsePositiveNote, extractVerifyTargetFactId, isVerifyVulnIntentKey,
	validateVerificationCommit, verifyPositiveConclusion,
} from "./verifier-gate";
import {
	EgressPoolManager, buildCurlProxyArgs, extractSandboxInnerCommand, injectEgressEnv,
	isCompliantSidecarCommand, maskEgressUrl, normalizeTaskEgressUrl, readSandboxConfig,
	resolveConfiguredEgressUrl, wrapCommandInDockerSandbox, wrapCommandInSidecarSandbox,
} from "./sandbox";
import { ensurePrimaryAsset } from "./hypothesis";
import {
	buildEpisodeTimelineData, buildJsonReport, buildSarifReport, exportEpisodeTimeline,
	searchArchiveIndexes, writeEpisodeArchiveIndex, writePocBundle,
	type ArchiveSearchHit, type ArchiveSearchQuery, type EpisodeArchiveIndex, type EpisodeArchiveInput,
	type ExportEpisodeTimelineOptions, type WriteEpisodeArchiveResult,
} from "./reporting";

import {
	NuwaSqliteCorruptError, NuwaSqliteStore, SQLITE_SCHEMA_VERSION, appendJournalSqlite,
	exportStateJsonCompat, loadStateFromSqlite, migrateJsonToSqlite, openNuwaDb, queryFactsByText,
	saveStateToSqlite,
	type AppendJournalOptions, type CalibrationRecordRow, type ExportCompatOptions,
	type ExportCompatResult, type FactSearchHit, type LoadSqliteStateOptions, type MigrateJsonOptions,
	type MigrateJsonResult, type OpenNuwaDbOptions, type QueryFactsOptions, type SaveSqliteStateOptions,
	type TrafficEntryRow, type TrafficQueryFilter as SqliteTrafficQueryFilter,
} from "./sqlite-store";
import {
	DEFAULT_AUTHDIFF_COOLDOWN_MS, DEFAULT_MAX_AUTH_PATHS, DEFAULT_MAX_NEW_OOB_CANARIES,
	DEFAULT_OOB_POLL_INTERVAL_MS, collectTestableAuthPaths, computeAuthDiffSignature,
	planAutonomousOobProbes, runAutonomousAuthDiff, runAutonomousOobPoll, shouldAutoTriggerAuthDiff,
	type AutoAuthDiffTriggerDecision, type AutoAuthDiffTriggerOptions, type AutonomousAuthDiffResult,
	type AutonomousOobPlanResult, type AutonomousOobPollResult, type CollectAuthPathsOptions,
	type OobProbePlanItem, type OobSurfaceCategory, type PlanOobProbesOptions,
	type RunAutonomousAuthDiffOptions, type RunOobPollOptions,
} from "./auto-loops";
import {
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
import {
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
import {
	MAX_MUTATION_CONCURRENCY, REDACTED_MARKER, TrafficRecorder, redactTrafficBody,
	redactTrafficHeaders, redactTrafficUrl, replayTrafficSequence, runStructuredMutations,
	type MutationAnomaly, type MutationBaseRequest, type MutationCaseResult, type MutationMode,
	type MutationProbeSummary, type ReplayStepResult, type ReplayTrafficOptions,
	type ReplayTrafficResult, type StructuredMutationsOptions, type StructuredMutationsResult,
	type TrafficEntry, type TrafficExtractorSpec, type TrafficFetchFn, type TrafficFetchResponseLike,
	type TrafficQueryFilter, type TrafficRecordInput, type TrafficRecorderOptions,
	type TrafficReplayStep,
} from "./traffic-workbench";
import {
	bridgeWhiteboxToBlackboxIntents, correlateBlackboxFindingToSource, extractCodeAttackSurface,
	extractFromSourceMap,
	type BlackboxFindingLike, type CodeAttackSurface, type CodeSinkKind, type CodeSinkWarning,
	type CodeSurfaceInput, type DetectedFramework, type ExtractSurfaceOptions, type ExtractedRoute,
	type HybridHypothesisSpec, type HybridVerificationIntentSpec, type RouteRiskFlag,
	type SourceCorrelationCandidate, type SourceCorrelationResult, type SupportedLanguage,
	type VirtualSourceFile, type WhiteboxBridgeOptions, type WhiteboxBridgeResult,
} from "./hybrid-audit";

export const VERSION = "6.0.0";

export {
	DEFAULT_BATCH_MAX_BYTES, DispatchReceiptRegistry, EgressPoolManager, InflightTargetRegistry,
	NUWA_VERSION, PHASE_ORDER, ProcessGroupTracker, REQUIRED_CURL_WRITE_OUT, SCHEMA, SEEDS,
	SubagentWatchdog, addFallbackIntent, addIntent, appendIntentSpecs, applyAutoItemResult,
	applyEmptyGuard, atomicWrite, attempted, autoPlan, bindSubagentSpawn, budgetPressure,
	buildChromiumLaunchConfig, buildConvergenceAdvice, buildCurlProxyArgs, buildDirective,
	buildDispatchPacket, buildDoctorSummary, buildEpisodeTimelineData, buildFalsePositiveNote,
	buildHandoffSummary, buildIntentDedupKey, buildJsonReport, buildSarifReport, buildUnifiedNetworkEnv,
	canDeriveCrossSurface, cell, checkAndLogAutoRuleSource, checkBashPolicy, checkScopeAndRisk,
	checkTaskPolicy, checkToolScopeAndRisk, checkWorkspaceTempWarning, checkWritePolicy,
	chunkBatchTasks, claimAutoBatch, claimIntent, claimedFresh, classifyEndpointResponse,
	cleanupTrackedProcesses, coalesceProbesByTarget, collectPaths, commitFreeFact, commitIntent,
	compactFacts, compactIntents, completeProject, computeBodyHash, computeRepeatRatio,
	createDispatchReceiptRegistry, createInitialState, defaultProjectRoot, defaultScopeForTarget,
	deriveFromFacts, detectChallengeGate, detectSoft404, distillProjectExperience, ensurePrimaryAsset,
	evaluatePositiveEvidenceGate, evidenceProblem, executeAssetsCommand, executeAuthDiffWorkflow,
	executeAutoBatchCycle, executeCommitWithGates, executeOobCommand, executeScopeCommand,
	executeSessionCommand, executeSessionHealthCommand, expandGraph, exportEpisodeTimeline,
	extractEventOutput, extractHitEvidenceMetrics, extractInlineScriptTargets, extractIntentTargetKey,
	extractProbeHealth, extractTarget, finalizeReportPhase, findLocalRoot, findRoot,
	formatScopeBlockReason, formatScopeSummary, frontierList, getAgentHome, getCompletionRejectAdvice,
	hasAttempted, hasSubstantiveBusinessData, inferExpectedKind, inferSurfaceDomain,
	injectEgressEnv, injectEgressIntoScript, injectResolvedTargetContext, inspectGraph,
	installProcessCleanupHooks, isPausedState, isProcessAliveNonZombie, isSharedCwd,
	isTargetInBlockedCooldown, isTinyErrorEnvelope, isTrustedEvidenceEvent, journalAppend, journalPath,
	kbLookup, kickPrompt, loadHumanSessionFromVault, loadState, lockPath, logEvent, maskEgressUrl,
	maybeAdvance, migrateSapper, newState, nextFactId, nextIntentId, normOneLine,
	normalizeDispatchTargetKey, normalizeState, normalizeTarget, normalizeTargetForMode,
	normalizeTargetKey, normalizeTaskEgressUrl, nowIso, parseAgentResult, pausedStatePath, phaseIndex,
	pickMode, pidAlive, planIntents, preflightEgressCheck, prepareNextGeneration, processTrackerPath, proofKinds, readCfg,
	readFactEvidenceLog, readPausedState, readReincarnatePolicy, readSpilledBatchTasks, recordFlag, recordToolExecution,
	releaseAutoBatchRemaining, releaseStaleClaims, renderDetail, renderFullStatus, reportMarkdown,
	resolveConfiguredEgressUrl, resolveDefaultWorkspacesDir, resolveLineageRoot, resolvePersistentStateDir,
	resolveReportPhaseTransition, routeSubagentModel, runSpaSurfaceWorkflow, sampleSoft404Baseline, saveFactEvidenceLog,
	saveHumanSessionToVault, saveState, sealEngagement, searchArchiveIndexes, seedEpisode, seedPhase,
	setPausedState, sha, shouldRecommendSeal, shouldReincarnate, sigOf, slug, stateDir, statePath,
	statusBoard, stopReason, subagentWatchdogPath, tickNoveltyStall, validateDeliverableRealism,
	validateHitEvidenceFields, validateSubagentDispatch, verifyPositiveConclusion,
	verifyWorkspaceIntegrity, withLock, writeEpisodeArchiveIndex, writePocBundle, writePointer,
};

export type {
	AddIntentInput, AgentEvidenceItem, AgentResult, ArchiveSearchHit, ArchiveSearchQuery, AssetNode,
	AttemptedEntry, AutoFactMeta, AutoPlanResult, BatchTaskItem, Cfg, ChunkBatchOptions,
	ChunkBatchResult, CleanupProcessOptions, CleanupProcessResult, CommitInput, CommitIntentResult,
	ConvergenceAdvice, DeliverableRealismResult, DispatchReceipt, DispatchValidationResult,
	EnforcementLayer, EpisodeArchiveIndex, EpisodeArchiveInput, ExecRecordInput, ExpansionResult,
	ExportEpisodeTimelineOptions, Fact, FactKind, FreeFactInput, FrontierItem, FullStatusOptions,
	HitEvidenceMetrics, HypothesisNode, InspectGraphQuery, InspectGraphResult, Intent, IntentStatus,
	Mode, NuwaState, ParseAgentResultOutcome, PausedState, Phase, PlanIntentsResult, PlanRejectReason,
	PolicyVerdict, PositiveEvidenceGateInput, PositiveEvidenceGateResult, ProbeHealthSummary,
	ProfileMode, ProfileSpec, Project, ProjectStatus, ReincarnatePolicy, RejectedIntentEntry,
	ReportPhaseTransition, Runtime, RuntimeStatus, SaveStateOptions, SavedEvidenceLog, ScopePolicy,
	SealEngagementInput, SealEngagementResult, SealMeta, SealRecommendation, Seed,
	SubagentDispatchPayload, SubagentWatchdogConfig, SubagentWatchdogEntry, SurfaceDomain,
	ToolchainCaps, VerifyEvidenceInput, VerifyEvidenceResult, VerifyStage, WatchdogSweepResult,
	WorkspaceIntegrityOptions, WorkspaceIntegrityReport, WorkspaceWarning, WriteEpisodeArchiveResult,
};


export {
	ALLOWED_SETTLEMENT_SOURCES, ALLOWED_SUBAGENT_MODELS, CalibrationError,
	DEFAULT_AUTHDIFF_COOLDOWN_MS, DEFAULT_MAX_AUTH_PATHS, DEFAULT_MAX_NEW_OOB_CANARIES,
	DEFAULT_NEGATIVE_SEAL_THRESHOLD, DEFAULT_OOB_POLL_INTERVAL_MS, DEFAULT_PROPAGATION_DECAY,
	DEFAULT_PRUNE_THRESHOLD, DEFAULT_SUBAGENT_MODEL, MAX_BETA_PARAM, MAX_MUTATION_CONCURRENCY,
	MIN_BETA_PARAM, NuwaSqliteCorruptError, NuwaSqliteStore, REDACTED_MARKER, SQLITE_SCHEMA_VERSION,
	TrafficRecorder, VALID_BELIEF_OBSERVATIONS, VALID_TASK_CATEGORIES, appendJournalSqlite,
	attachBeliefGraphCache, backupExistingProjectState, beliefGraphPath, bindLoadedStateRoot, bridgeWhiteboxToBlackboxIntents, calibrationLedgerPath,
	collectTestableAuthPaths, computeAuthDiffSignature, computeBetaPosterior,
	computeCalibrationSummary, computeExpectedInfoGain, computeNodeUncertainty,
	computeOneStepEntropyReduction, correlateBlackboxFindingToSource, executeBeliefCommand,
	executeCalibrateCommand, executeHybridCommand, executeMcpCommand, executeTrafficCommand,
	exportStateJsonCompat, extractCodeAttackSurface, extractFromSourceMap, formatCalibrationReport,
	getLoadedStateRoot, hasProjectState, inferCalibrationTaskCategory, initBeliefGraphFromState, loadBeliefGraphReadOnly,
	loadCalibrationRecords, loadOrInitBeliefGraph, loadStateFromSqlite, loadStateJsonOnly,
	migrateJsonToSqlite, openNuwaDb, planAutonomousOobProbes, propagateBeliefUpdate,
	pruneLowYieldSubtree, queryFactsByText, rankFrontierByBelief, recommendAdaptiveModelRoute,
	recommendSearchPivot, recordPrediction, redactCalibrationText, redactTrafficBody,
	redactTrafficHeaders, redactTrafficUrl, replayTrafficSequence, resolveBeliefNodeId,
	resolveStorageBackend, runAutonomousAuthDiff, runAutonomousOobPoll, runPostBatchAutonomousLoops,
	runStructuredMutations, safeSettlePrediction, saveBeliefGraph, saveStateJsonOnly,
	saveStateToSqlite, settlePrediction, shannonBinaryEntropy, shouldAutoTriggerAuthDiff,
	sqliteDbPath, updateBeliefPosterior, upsertSessionRole, validateSettlementSource,
};

export type {
	AdaptiveModelRouteDecision, AdaptiveModelRouteInput, AppendJournalOptions,
	AutoAuthDiffTriggerDecision, AutoAuthDiffTriggerOptions, AutonomousAuthDiffResult,
	AutonomousOobPlanResult, AutonomousOobPollResult, BeliefGraph, BeliefNode, BeliefNodeKind,
	BeliefObservation, BeliefObservationType, BeliefPropagationEvent, BeliefPropagationResult,
	BlackboxFindingLike, CalibrationBinStat, CalibrationDimensionMetrics, CalibrationErrorCode,
	CalibrationPredictionInput, CalibrationRecord, CalibrationRecordRow, CalibrationSettlementInput,
	CalibrationSettlementSource, CalibrationSummary, CalibrationTaskCategory, CodeAttackSurface,
	CodeSinkKind, CodeSinkWarning, CodeSurfaceInput, CollectAuthPathsOptions,
	ComputeCalibrationOptions, DetectedFramework, ExportCompatOptions, ExportCompatResult,
	ExtractSurfaceOptions, ExtractedRoute, FactSearchHit, HybridHypothesisSpec,
	HybridVerificationIntentSpec, LoadSqliteStateOptions, MigrateJsonOptions, MigrateJsonResult,
	ModelCandidateEvaluation, MutationAnomaly, MutationBaseRequest, MutationCaseResult, MutationMode,
	MutationProbeSummary, OobProbePlanItem, OobSurfaceCategory, OpenNuwaDbOptions, PivotDirection,
	PlanOobProbesOptions, PruneSubtreeOptions, PruneSubtreeResult, PruneSuggestion,
	QueryFactsOptions, RankFrontierOptions, RankedFrontierItem, ReplayStepResult,
	ReplayTrafficOptions, ReplayTrafficResult, RouteRiskFlag, RunAutonomousAuthDiffOptions,
	RunOobPollOptions, SaveSqliteStateOptions, SearchPivotOptions, SearchPivotRecommendation,
	SourceCorrelationCandidate, SourceCorrelationResult, SqliteTrafficQueryFilter, StorageBackend,
	StructuredMutationsOptions, StructuredMutationsResult, SupportedLanguage, TrafficEntry,
	TrafficEntryRow, TrafficExtractorSpec, TrafficFetchFn, TrafficFetchResponseLike,
	TrafficQueryFilter, TrafficRecordInput, TrafficRecorderOptions, TrafficReplayStep,
	VirtualSourceFile, WhiteboxBridgeOptions, WhiteboxBridgeResult,
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

function getInflightRegistry(root: string): InflightTargetRegistry {
	return new InflightTargetRegistry({ persistPath: join(resolve(root), ".nuwa", "inflight-targets.json") });
}

function getDispatchRegistry(root: string): DispatchReceiptRegistry {
	return createDispatchReceiptRegistry(join(resolve(root), ".nuwa", "dispatch-receipts.json"));
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

const COMBINED_HARD_VIOLATIONS = new Set([
	"placeholder_bracket",
	"unexpanded_target_literal",
]);

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

export default function nuwaOmp(pi: ExtensionAPI) {
	const z = pi.zod;
	const liveCalls = new Map<string, number>();
	const autoAborts = new Map<string, AbortController>();
	const pumpSessions = new Map<string, ExtensionContext>();
	const activeSpawns = new Map<
		string,
		{
			spawnId: string;
			root: string;
			agent: string;
			intentId?: string;
			rawTask: string;
			injectedTask: string;
			sessionId: string;
		}
	>();
	let spawnSeq = 0;

	const resolveWatchdogTaskId = (wd: SubagentWatchdog, ctx: ExtensionContext): string => {
		const direct = ctx.agent?.id?.trim();
		if (direct && wd.getTask(direct)) return direct;
		if (ctx.agent?.kind === "sub") {
			const running = wd.listTasks({ status: "running" });
			const agentName = typeof ctx.agent?.name === "string" ? ctx.agent.name.trim() : "";
			if (agentName) {
				const sameAgent = running.filter((t) => t.agent === agentName);
				if (sameAgent.length === 1) return sameAgent[0]!.taskId;
			}
			if (running.length === 1) return running[0]!.taskId;
		}
		return direct || sidOf(ctx);
	};

	const completeWatchdogOnTaskEnd = (
		root: string,
		evObj: Record<string, unknown>,
		inputObj: Record<string, unknown> | null,
		ctx: ExtensionContext,
	): void => {
		if (ctx.agent?.kind === "sub") return;
		const wd = new SubagentWatchdog(root);
		const running = wd.listTasks({ status: "running" });
		const normRoot = resolve(root);
		const runningIdSet = new Set(running.map((r) => r.taskId));
		for (const [sidKey, sp] of activeSpawns.entries()) {
			if (resolve(sp.root) === normRoot && !runningIdSet.has(sidKey)) {
				activeSpawns.delete(sidKey);
			}
		}
		if (running.length === 0) return;
		const safeInput = inputObj && typeof inputObj === "object" ? inputObj : {};

		const details =
			evObj.details && typeof evObj.details === "object"
				? (evObj.details as Record<string, unknown>)
				: evObj.result && typeof evObj.result === "object" && (evObj.result as Record<string, unknown>).details && typeof (evObj.result as Record<string, unknown>).details === "object"
					? ((evObj.result as Record<string, unknown>).details as Record<string, unknown>)
					: undefined;

		const explicitIds = new Set<string>();
		const pushStrId = (v: unknown) => {
			if (typeof v === "string" && v.trim()) explicitIds.add(v.trim());
		};
		const pushArrIds = (arr: unknown) => {
			if (!Array.isArray(arr)) return;
			for (const item of arr) {
				if (typeof item === "string") pushStrId(item);
				else if (item && typeof item === "object") {
					const rec = item as Record<string, unknown>;
					pushStrId(rec.spawnId);
					pushStrId(rec.taskId);
					pushStrId(rec.id);
				}
			}
		};

		pushStrId(evObj.spawnId);
		pushStrId(evObj.taskId);
		pushStrId(details?.spawnId);
		pushStrId(details?.taskId);
		pushArrIds(details?.spawnIds);
		pushArrIds(details?.taskIds);
		pushStrId(safeInput.spawnId);
		pushStrId(safeInput.taskId);
		pushArrIds(safeInput.tasks);

		const matchedIds = new Set<string>();
		for (const r of running) {
			if (explicitIds.has(r.taskId)) matchedIds.add(r.taskId);
		}

		// 若宿主未回传 spawnId，则通过精确派单正文或 intentId 严格配对对应子代理（严禁用短子串误释放并行同类任务）
		if (matchedIds.size === 0) {
			const taskTexts: string[] = [];
			const addTaskText = (v: unknown) => {
				if (typeof v === "string" && v.trim()) taskTexts.push(v.trim());
			};
			const isBatchCall = Array.isArray(safeInput.tasks) && safeInput.tasks.length > 0;
			addTaskText(safeInput.task);
			addTaskText(safeInput.prompt);
			if (Array.isArray(safeInput.tasks)) {
				for (const item of safeInput.tasks) {
					if (item && typeof item === "object") {
						addTaskText((item as Record<string, unknown>).task);
						addTaskText((item as Record<string, unknown>).prompt);
					}
				}
			}

			const intentIds = new Set<string>();
			if (typeof safeInput.intentId === "string" && safeInput.intentId.trim()) intentIds.add(safeInput.intentId.trim());
			if (typeof details?.intentId === "string" && details.intentId.trim()) intentIds.add(details.intentId.trim());
			for (const txt of taskTexts) {
				for (const m of txt.matchAll(/\[女娲派单\s+(i\d{3,})\]/g)) {
					if (m[1]) intentIds.add(m[1]);
				}
			}

			// 1) 优先按显式/注入 intentId 精确匹配
			if (intentIds.size > 0) {
				for (const [sidKey, sp] of activeSpawns.entries()) {
					if (resolve(sp.root) !== normRoot) continue;
					if (sp.intentId && intentIds.has(sp.intentId)) {
						matchedIds.add(sidKey);
					}
				}
				if (matchedIds.size === 0) {
					for (const r of running) {
						if (r.intentId && intentIds.has(r.intentId)) matchedIds.add(r.taskId);
					}
				}
			}

			// 2) 若无 intentId 命中，按完整文本严格相等匹配；每条 taskText 至多认领一条尚未配对的最早同源 spawn
			if (matchedIds.size === 0 && taskTexts.length > 0) {
				for (const txt of taskTexts) {
					for (const [sidKey, sp] of activeSpawns.entries()) {
						if (resolve(sp.root) !== normRoot || matchedIds.has(sidKey)) continue;
						if (txt === sp.rawTask || txt === sp.injectedTask) {
							matchedIds.add(sidKey);
							break;
						}
					}
					if (!isBatchCall && matchedIds.size > 0) break;
				}
			}

			if (matchedIds.size === 0) {
				const agentArg =
					typeof safeInput.agent === "string"
						? safeInput.agent.trim()
						: typeof safeInput.agentName === "string"
							? safeInput.agentName.trim()
							: "";
				if (agentArg) {
					const byAgent = running.filter((r) => r.agent === agentArg);
					if (byAgent.length === 1) matchedIds.add(byAgent[0]!.taskId);
				} else if (running.length === 1) {
					matchedIds.add(running[0]!.taskId);
				}
			}
		}

		const status = evObj.isError === true ? "failed" : "completed";
		for (const tid of matchedIds) {
			wd.completeTask(tid, status);
			activeSpawns.delete(tid);
		}
	};

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
		description: "创建/恢复女娲项目：写 .nuwa/state.json，初始化靶标 Scope 护栏、工作区完整性基线、便携知识库与本地工具链探针，播种首阶段意图，返回看板。",
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
			try {
				const warmResult = warmBundledKb();
				void warmResult;
				const curCfg = readCfg();
				const sid = sidOf(ctx);
				const explicitMode = p.mode as Mode | undefined;
				let probeRoot = "";
				if (p.root) {
					probeRoot = resolve(ctx.cwd, p.root);
				} else if (p.target) {
					const targetDir = resolve(ctx.cwd, p.target);
					if (hasProjectState(targetDir)) probeRoot = targetDir;
				}
				if (!probeRoot && !p.target) {
					const local = findLocalRoot(ctx.cwd, sid);
					if (local) {
						probeRoot = local;
					} else if (isSharedCwd(ctx.cwd)) {
						const ptr = readSessionPointer(sid);
						if (ptr?.root) probeRoot = resolve(ptr.root);
					} else {
						probeRoot = resolve(ctx.cwd);
					}
				}
				if (!probeRoot && !explicitMode && p.target) {
					const envProj = process.env.NUWA_PROJECT?.trim();
					const ptr = readSessionPointer(sid);
					const cwdResolved = resolve(ctx.cwd);
					const candSet = new Set<string>();
					const addCand = (pCand: string | null | undefined) => {
						if (!pCand) return;
						const resolvedCand = resolve(pCand);
						if (hasProjectState(resolvedCand)) candSet.add(resolvedCand);
					};
					addCand(findLocalRoot(ctx.cwd, sid));
					if (!isSharedCwd(cwdResolved)) addCand(cwdResolved);
					if (envProj) addCand(envProj);
					if (ptr?.root) addCand(ptr.root);
					for (const candMode of ["ctf", "ops", "coding", "audit", "pentest"] as const) {
						try {
							addCand(defaultProjectRoot(ctx.cwd, p.target, sid, candMode));
						} catch {
							/* 非该模式合法目标则跳过 */
						}
					}
					for (const localCand of candSet) {
						const localSt = loadState(localCand);
						if (!localSt) continue;
						const localMode = localSt.project.mode;
						try {
							if (localSt.project.url === normalizeTargetForMode(p.target, localMode).url) {
								probeRoot = localCand;
								break;
							}
						} catch {
							/* 非匹配目标则按常规流程校验 */
						}
					}
				}
				const preExisting = probeRoot && hasProjectState(probeRoot) ? loadState(probeRoot) : null;
				const mode = (explicitMode ?? preExisting?.project?.mode ?? "ctf") as Mode;
				const rawTarget =
					p.target ?? (!p.resume && !p.migrate && (mode === "coding" || mode === "ops" || mode === "audit") ? ctx.cwd : undefined);
				const want = rawTarget ? normalizeTargetForMode(rawTarget, mode).url : "";
				let root: string;
				if (p.root) {
					root = resolve(ctx.cwd, p.root);
				} else if (probeRoot && preExisting) {
					root = probeRoot;
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
					if (existing && p.force) backupExistingProjectState(root);
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
					bindMainSession(ctx, root, migrated.project.id);
					refreshUi(ctx, root, migrated, true);
					return toolText(`已从 .sapper 迁移: ${migrated.project.id}\n\n${statusBoard(migrated, root)}`, { root, migrated: true });
				}
				if (existing && p.resume) {
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
						if (p.scope) {
							s.project.scope = defaultScopeForTarget(s.project.url || s.project.target, s.project.mode, { ...s.project.scope, ...p.scope });
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
					bindMainSession(ctx, root, resumed.project.id);
					refreshUi(ctx, root, resumed, true);
					return toolText(`已恢复 ${resumed.project.id}\n\n${statusBoard(resumed, root)}`, { root, integrity: wsIntegrity.status });
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
				if (existing && p.force) backupExistingProjectState(root);
				const st = newState(rawTarget, p.goal ?? "", mode, curCfg, sid, p.scope);
				st.project.toolchain = probeToolchain();
				st.project.sandboxMode = readSandboxConfig().mode;
				ensurePrimaryAsset(st);
				const shouldAutoStart = (p.autoStart === true || (process.env.NUWA_AUTO_ON_INIT ?? "").trim() === "1") && hasExec();
				let autoIds: string[] = [];
				withLock(root, () => {
					seedPhase(st, "recon");
					if (shouldAutoStart) autoIds = claimAutoBatch(st, curCfg, root);
					st.runtime.rulesSource = checkAndLogAutoRuleSource(root, st);
					saveState(root, st, { reason: "init" });
				});
				const wsIntegrity = verifyWorkspaceIntegrity(root, { recordBaseline: true });
				const tmpWarn = checkWorkspaceTempWarning(root);
				mkdirSync(`/tmp/nuwa/${st.project.id}`, { recursive: true });
				writePointer(root, sid);
				bindMainSession(ctx, root, st.project.id);
				logEvent(root, { type: "init", id: st.project.id, url: st.project.url, mode: st.project.mode });
				refreshUi(ctx, root, st, true);
				if (autoIds.length > 0) void runAutoBatch(ctx, root, autoIds);
				const warnSuffix = tmpWarn ? `\n⚠ ${tmpWarn.message}` : "";
				return toolText(`女娲已上膛: ${st.project.id}${warnSuffix}\n\n${statusBoard(st, root)}`, {
					root,
					project: st.project.id,
					integrity: wsIntegrity.status,
					...(tmpWarn ? { workspaceWarning: tmpWarn } : {}),
				});
			} catch (e) {
				return toolError(e);
			}
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
			batch_tasks: z
				.array(z.record(z.string(), z.any()))
				.optional()
				.describe("可选待派发子任务批次：自动执行在途去重、出口注入与 >6000B 安全分片/溢写"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；先 nuwa_init");
				const inflightReg = getInflightRegistry(root);
				const added: string[] = [];
				const rejectedReasons: RejectedIntentEntry[] = [];
				let batchPlanOut: ChunkBatchResult<BatchTaskItem> | undefined;
				let egressEnvOut: Record<string, string> | undefined;

				const updated = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("state 不存在；先 nuwa_init");

					// 同步当前 claimed 意图到跨子代理在途登记池（#50）
					for (const it of Object.values(s.intents)) {
						if (it.status === "claimed") {
							const tk = it.targetKey ?? extractIntentTargetKey(it, s.project.host);
							if (tk && !tk.startsWith("seed:")) {
								inflightReg.claim(tk, { intentId: it.id, worker: it.worker ?? "fujiang", claimedAt: it.claimedAt });
							}
						}
					}

					const prefilteredIntents: AddIntentInput[] = [];
					for (const rawIt of p.intents ?? []) {
						const candKey = extractIntentTargetKey(
							{
								title: rawIt.title,
								detail: rawIt.detail,
								targetKey: rawIt.targetKey ?? rawIt.target,
								phase: rawIt.phase ?? p.phase ?? s.project.phase,
							},
							s.project.host,
						);
						if (!p.force && !rawIt.force && candKey && !candKey.startsWith("seed:") && inflightReg.isInflight(candKey)) {
							rejectedReasons.push({ title: rawIt.title, targetKey: candKey, reason: "inflight" });
							continue;
						}
						prefilteredIntents.push(rawIt as AddIntentInput);
					}

					const planRes = planIntents(
						s,
						{
							phase: p.phase,
							intents: prefilteredIntents,
							force: p.force,
							cooldownMs: p.cooldown_ms,
						},
						curCfg,
					);
					added.push(...planRes.added);
					rejectedReasons.push(...planRes.rejectedReasons);

					const activeEgress = normalizeTaskEgressUrl(p.egress ?? resolveConfiguredEgressUrl());
					if (activeEgress) {
						egressEnvOut = injectEgressEnv(activeEgress, {});
						for (const id of planRes.added) {
							const created = s.intents[id];
							if (created && !created.detail.includes("NUWA_EGRESS")) {
								const curlArgs = buildCurlProxyArgs(activeEgress).join(" ");
								created.detail = `${created.detail ? `${created.detail}\n` : ""}[出口注入] NUWA_EGRESS=${maskEgressUrl(activeEgress)} (curl 附加: ${curlArgs})`;
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
									...(activeEgress ? { egress: activeEgress } : {}),
								},
							});
							return {
								...item,
								task: activeEgress ? injectEgressIntoScript(pkt.task, activeEgress) : pkt.task,
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
				const items = frontierList(st, p.limit, curCfg.claimTtl, root);
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
		description: "认领一条意图，返回完整派单包（自动注入 resolved_host、出口代理指引、多角色鉴权差分头文件与输出契约，并登记在途目标去重）。",
		loadMode: "essential",
		parameters: z.object({
			id: z.string().describe("意图 id，如 i007"),
			worker: z.string().default("fujiang"),
			egress: z.string().optional().describe("可选任务出口代理 URL（如 socks5h://127.0.0.1:7890）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				let packet = "";
				let stale = false;
				let expectedKind: FactKind | undefined;
				let targetKey = "";
				const activeEgress = normalizeTaskEgressUrl(p.egress ?? resolveConfiguredEgressUrl());
				withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
					const r = claimIntent(s, p.id, p.worker, curCfg.claimTtl, root);
					expectedKind = r.intent.expectedKind;
					targetKey = r.intent.targetKey ?? "";
					const injected = injectResolvedTargetContext(r.packet, {
						url: s.project.url,
						host: s.project.host,
						...(activeEgress ? { egress: maskEgressUrl(activeEgress) } : {}),
					});
					packet = injected.task;
					if (activeEgress) {
						const proxyArgs = buildCurlProxyArgs(activeEgress).join(" ");
						packet += `\n\n[出口强制注入]: 已配置出口 ${maskEgressUrl(activeEgress)}；首步须对目标执行 Gate 探活（如统一 403/WAF 阻断立即报 egress_blocked 停止盲扫），所有 curl 须携带 ${proxyArgs}`;
					}
					stale = r.stale;
					if (targetKey && !targetKey.startsWith("seed:")) {
						getInflightRegistry(root).claim(targetKey, {
							intentId: p.id,
							worker: p.worker,
							claimedAt: r.intent.claimedAt,
						});
					}
					saveState(root, s);
					logEvent(root, { type: "claim", id: p.id, worker: p.worker, stale, expectedKind, targetKey });
				});
				return toolText(packet, {
					root,
					id: p.id,
					stale,
					...(expectedKind ? { expectedKind } : {}),
					...(targetKey ? { targetKey } : {}),
				});
			} catch (e) {
				return toolError(e);
			}
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
			kind: z
				.enum(["target", "asset", "service", "endpoint", "cred", "vuln", "flag", "loot", "note", "blocked"])
				.optional()
				.describe("事实类型；省略时自动继承认领意图的 expectedKind（兜底 note，#29）"),
			title: z.string().default(""),
			detail: z.string().default(""),
			command: z.string().optional(),
			output: z.string().optional(),
			blocked: z.boolean().default(false),
			note: z.string().optional(),
			agent_result: z
				.union([z.string(), z.record(z.string(), z.any())])
				.optional()
				.describe("子代理结构化回包 AgentResult（JSON 对象或字符串），自动解析提取命令、证据指标与结论（#51）"),
			evidence_ref: z.string().optional().describe("原始响应/日志证据文件相对路径指针（如 .nuwa/evidence/f001.log，#42）"),
			save_evidence_log: z.boolean().optional().describe("是否自动将原始响应脱敏落盘到 .nuwa/evidence/<factId>.log 并绑定 evidence_ref（#42）"),
			raw_response: z.string().optional().describe("可选完整原始 HTTP 响应内容，用于证据落盘与假阳性复核"),
			baseline: z.any().optional().describe("可选负向对照基线响应（401/404），用于假阳性门禁比对（#24）"),
			auto_downgrade: z.boolean().optional().describe("命中假阳性门禁时是否自动降级为 note(false_positive) 落账（#24）"),
			strict_realism: z.boolean().optional().describe("是否强制校验网络探针五项命中指标（#26, #39）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const pre = loadState(root);
				if (!pre) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

				let parsedAgentObj: Record<string, unknown> | undefined;
				let effTitle = p.title ?? "";
				let effDetail = p.detail ?? "";
				let effCommand = p.command;
				let effOutput = p.output;
				let effBlocked = Boolean(p.blocked);
				let effNote = p.note;

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

				const rawId = (p.id ?? "").trim();
				const isFree = !rawId || p.free_note === true;
				const targetIntent = !isFree ? pre.intents[rawId] : undefined;
				const intentKey = targetIntent?.key ?? "";
				let effectiveKind: FactKind = (p.kind ?? targetIntent?.expectedKind ?? "note") as FactKind;
				let explicitKind: FactKind | undefined = p.kind as FactKind | undefined;

				// #26 模板化/未解析回包拦截（对非 blocked 提交拦截占位符、未展开 TARGET/$U 与纯脚本回包）
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

				// #24 假阳性复核门禁（拦截 HTTP 200 微小错误壳、Soft-404 与同基线哈希的伪正向结论；纯无空行通用头交由下方账本熵校验处理）
				let downgradedFalsePositive = false;
				let fpGateResult: PositiveEvidenceGateResult | undefined;
				if (!effBlocked && (effectiveKind === "vuln" || effectiveKind === "cred" || effectiveKind === "loot")) {
					const rawCheckText = String(p.raw_response ?? effOutput ?? "");
					const hasBodyOrBaseline =
						p.baseline !== undefined ||
						p.raw_response !== undefined ||
						rawCheckText.replace(/\r\n/g, "\n").includes("\n\n") ||
						rawCheckText.trim().startsWith("{");
					if (hasBodyOrBaseline) {
						const posGate = evaluatePositiveEvidenceGate({
							kind: effectiveKind,
							output: rawCheckText,
							baseline: p.baseline,
						});
						if (!posGate.ok && posGate.falsePositive) {
							fpGateResult = posGate;
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
						evidenceRef: p.evidence_ref,
						agentResult: parsedAgentObj,
					},
					verifiedFlag,
				);

				if (rawId) {
					getInflightRegistry(root).releaseByIntent(rawId);
				}

				let finalState = commitRes.state;
				let savedEvLog: SavedEvidenceLog | undefined;
				if (!effBlocked && (p.save_evidence_log || p.raw_response !== undefined)) {
					const targetFact =
						(commitRes.factId ? finalState.facts[commitRes.factId] : undefined) ??
						(!isFree && finalState.intents[rawId]?.to ? finalState.facts[finalState.intents[rawId]!.to!] : undefined);
					if (targetFact) {
						savedEvLog = saveFactEvidenceLog(root, {
							factId: targetFact.id,
							command: effCommand,
							output: effOutput,
							rawResponse: p.raw_response,
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

				refreshUi(ctx, root, finalState);
				const blockedSummaryLine = `blocked_stats: blockedIntents=${commitRes.blockedIntents}(${commitRes.blockedIntentsDelta >= 0 ? "+" : ""}${commitRes.blockedIntentsDelta}) · blockedCommits=${commitRes.blockedCommits}(+${commitRes.blockedCommitsDelta})`;
				const evRefLine = savedEvLog
					? `\nevidence_ref: ${savedEvLog.evidenceRef} (${savedEvLog.bytes}B)`
					: p.evidence_ref
						? `\nevidence_ref: ${p.evidence_ref}`
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
					...(savedEvLog ? { evidenceRef: savedEvLog.evidenceRef } : p.evidence_ref ? { evidenceRef: p.evidence_ref } : {}),
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
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");

				if (p.seal) {
					const sealReason = (p.reason ?? p.note ?? "").trim() || "攻击面已全面验证排除且无正向突破，执行负向封盘";
					abortAutoBatch(root, "sealed_negative");
					const sealed = sealEngagement(root, {
						reason: sealReason,
						excludedSurface: p.excluded_surface,
						coverage: p.coverage as Record<string, unknown> | undefined,
					});
					cleanupTrackedProcesses(root, { reason: "nuwa_complete:seal" });
					if (isPausedState(root)) setPausedState(root, false, "sealed_negative");
					try {
						distillProjectExperience(sealed.state, { agentHome: getAgentHome(), negativeOnly: true });
					} catch {
						/* 蒸馏异常不阻断封盘 */
					}
					refreshUi(ctx, root, sealed.state, true);
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
				let res: { ok: boolean; reason?: string; from: string[]; convergence?: ConvergenceAdvice } = { ok: false, from: [] };
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

				cleanupTrackedProcesses(root, { reason: "nuwa_complete:completed" });
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
			archive_query: z
				.union([z.string(), z.record(z.string(), z.any())])
				.optional()
				.describe("纯只读检索跨轮 Episode 结构化归档索引（#52）"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");

				// 1) 纯只读跨轮归档检索（#52，严格零磁盘写入）
				if (p.archive_query !== undefined) {
					const q: string | ArchiveSearchQuery =
						typeof p.archive_query === "string"
							? { text: p.archive_query, ...(p.limit !== undefined ? { limit: p.limit } : {}) }
							: { ...(p.archive_query as ArchiveSearchQuery), ...(p.limit !== undefined ? { limit: p.limit } : {}) };
					const hits = searchArchiveIndexes(root, q);
					if (p.format === "json") {
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

				// 2) 纯只读图诊断接口（#35，严格零磁盘写入，不改任何文件或 mtime）
				if (p.inspect_intent !== undefined || p.query_status !== undefined || p.target_key !== undefined) {
					const diag = inspectGraph(root, {
						intentId: p.inspect_intent,
						status: p.query_status,
						targetKey: p.target_key,
						limit: p.limit,
					});
					if (!diag.ok) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init");
					if (p.format === "json") {
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

				// 3) 不截断全量/分页状态输出（#34，纯只读零磁盘写入）
				if (p.raw !== undefined || p.offset !== undefined || p.limit !== undefined || p.format !== undefined) {
					const fullText = renderFullStatus(root, {
						raw: p.raw,
						offset: p.offset,
						limit: p.limit,
						format: p.format,
					});
					return toolText(fullText, {
						root,
						readonly: true,
						format: p.format ?? "text",
						raw: Boolean(p.raw),
					});
				}

				// 4) 默认状态看板（同时输出 repeat_ratio 与 last_ok，#21, #38, #49）
				const st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				refreshUi(ctx, root, st);
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
			try {
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				let st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");
				const fmt = p.format ?? "md";
				let outText = "";
				let fileName = "REPORT.md";
				if (fmt === "timeline") {
					outText = exportEpisodeTimeline(root, { episode: p.episode, format: "markdown" });
					fileName = p.episode !== undefined ? `TIMELINE-E${p.episode}.md` : "TIMELINE.md";
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
				if (p.write) {
					path = join(root, ".nuwa", fileName);
					atomicWrite(path, outText);
				}

				let archiveRes: WriteEpisodeArchiveResult | undefined;
				if (p.write || p.archive) {
					const targetEp = p.episode ?? st.project.episode ?? 1;
					archiveRes = writeEpisodeArchiveIndex(root, {
						episode: targetEp,
						state: st,
						summary: `报告生成 (${fmt})`,
					});
				}

				let phaseTransitionOut: ReportPhaseTransition | undefined;
				if (p.write || p.finalize_phase) {
					const curCfg = readCfg();
					st = withLock(root, () => {
						const s = loadState(root) ?? st!;
						if (p.write) s.runtime.reportWritten = true;
						if (p.finalize_phase && s.project.phase === "report") {
							const fin = finalizeReportPhase(s, curCfg, {
								root,
								reportWritten: Boolean(p.write || s.runtime.reportWritten),
								autoSeal: true,
							});
							phaseTransitionOut = fin.transition;
						} else if (s.project.phase === "report") {
							phaseTransitionOut = resolveReportPhaseTransition(s, {
								reportWritten: Boolean(p.write || s.runtime.reportWritten),
								maxEpisodes: curCfg.maxEpisodes,
							});
						}
						saveState(root, s);
						return s;
					});
					refreshUi(ctx, root, st, true);
				}

				let bundleDir = "";
				let bundleFiles = 0;
				if (p.bundle) {
					const b = writePocBundle(root, st);
					bundleDir = b.dir;
					bundleFiles = b.files.length;
				}
				const suffixParts: string[] = [];
				if (path) suffixParts.push(`已写入: ${path}`);
				if (archiveRes) suffixParts.push(`Episode E${archiveRes.episode} 归档索引已更新: ${archiveRes.jsonPath}`);
				if (bundleDir) suffixParts.push(`脱敏证据包已生成: ${bundleDir} (${bundleFiles} 个文件)`);
				if (phaseTransitionOut) suffixParts.push(`report 阶段状态建议: action=${phaseTransitionOut.action} (${phaseTransitionOut.reason})`);
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
			batch_tasks: z
				.array(z.record(z.string(), z.any()))
				.optional()
				.describe("可选待派发任务列表：执行跨子代理在途去重、同目标探针合并与 >6000B 分片保护"),
			root: z.string().optional(),
		}),
		async execute(_id, p, _sig, _up, ctx) {
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const inflightReg = getInflightRegistry(root);
				let text = "";
				let rejectedReasons: RejectedIntentEntry[] = [];
				let batchOut: ChunkBatchResult<BatchTaskItem> | undefined;
				const activeEgress = normalizeTaskEgressUrl(p.egress ?? resolveConfiguredEgressUrl());

				const st = withLock(root, () => {
					const s = loadState(root);
					if (!s) throw new Error("state 不存在；先 nuwa_init");
					const r = autoPlan(s, curCfg);
					rejectedReasons = [...r.rejectedReasons];

					// 校验新派生意图是否与外部登记的 inflight 池冲突（#50）
					const finalAdded: string[] = [];
					for (const id of r.added) {
						const it = s.intents[id];
						if (!it) continue;
						const tk = it.targetKey ?? extractIntentTargetKey(it, s.project.host);
						if (!p.force && tk && !tk.startsWith("seed:") && inflightReg.isInflight(tk)) {
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
				if (st) refreshUi(ctx, root, st, true);
				return toolText(`${text}\n\n${st ? statusBoard(st, root) : ""}`, {
					root,
					rejectedReasons,
					...(batchOut ? { batch: batchOut } : {}),
				});
			} catch (e) {
				return toolError(e);
			}
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
			try {
				const curCfg = readCfg();
				const root = resolveRootWithLineage(ctx, p.root);
				if (!root) throw new Error("未找到女娲项目；用 NUWA_PROJECT=<根> 指定，或在项目目录 nuwa_init(resume=true) 接管");
				const st = loadState(root);
				if (!st) throw new Error("该项目没有 .nuwa/state.json；先 nuwa_init（旧项目用 nuwa_init(migrate=true)）");

				// #44 免确认即时软暂停通道
				if (p.pause === true) {
					const pauseReason = (p.reason ?? "").trim() || "manual soft pause";
					abortAutoBatch(root, `paused:${pauseReason}`);
					const pausedRec = setPausedState(root, true, pauseReason);
					refreshUi(ctx, root, st, true);
					return toolText(
						`已进入软暂停挂起状态: ${pauseReason}\n守护器与自动续跑已优雅挂起；执行 /nuwa resume 或 nuwa_init(resume=true) 即可无缝恢复。`,
						{ root, paused: true, stopped: false, pausedState: pausedRec },
					);
				}

				const reason = (p.reason ?? "").trim();
				if (reason.length < 4) throw new Error("reason 至少 4 字");
				if (curCfg.infinite && (p.confirm ?? "").trim() !== "STOP") {
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
				abortAutoBatch(root, reason);
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
					const dist = distillProjectExperience(updated, { agentHome: getAgentHome(), negativeOnly: true });
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
				refreshUi(ctx, root, updated, true);
				const cleanSuffix = procCleanup.cleaned.length > 0 ? `（已清理残留子进程 ${procCleanup.cleaned.length} 个）` : "";
				return toolText(`已停机: ${reason}${cleanSuffix}`, {
					root,
					stopped: true,
					cleanedProcesses: procCleanup.cleaned.length,
				});
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

	const NUWA_SUBCOMMANDS = [
		"status", "board", "scope", "session", "authdiff", "oob", "assets",
		"report", "doctor", "spa", "log", "why", "seal", "note", "inspect",
		"query", "pause", "stop", "resume", "export",
		"belief", "calibrate", "traffic", "hybrid", "mcp",
	] as const;

	pi.registerCommand?.("nuwa", {
		description:
			"女娲：/nuwa <任务> 开工 | /nuwa status | board | seal | note | inspect | query | pause | resume | export | scope | session | authdiff | oob | assets | report | doctor | spa | log [n] | why | stop",
		getArgumentCompletions: (prefix: string) =>
			NUWA_SUBCOMMANDS.filter((v) => v.startsWith(prefix)).map((v) => ({ value: v, label: v })),
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

			if (arg === "belief" || arg.startsWith("belief ")) {
				const r = executeBeliefCommand(found, arg.slice(6));
				return notify(r.msg, r.level);
			}
			if (arg === "calibrate" || arg.startsWith("calibrate ")) {
				const r = executeCalibrateCommand(found, arg.slice(9));
				return notify(r.msg, r.level);
			}
			if (arg === "traffic" || arg.startsWith("traffic ")) {
				const r = executeTrafficCommand(found, arg.slice(7));
				return notify(r.msg, r.level);
			}
			if (arg === "hybrid" || arg.startsWith("hybrid ")) {
				const r = executeHybridCommand(found, arg.slice(6));
				if (arg.slice(6).trim().toLowerCase().startsWith("plan") && found) {
					const stAfter = loadState(found);
					if (stAfter) refreshUi(ctx as ExtensionContext, found, stAfter, true);
				}
				return notify(r.msg, r.level);
			}
			if (arg === "mcp" || arg.startsWith("mcp ")) {
				const r = executeMcpCommand(found, arg.slice(3));
				return notify(r.msg, r.level);
			}

			// /nuwa seal [reason] (#22)
			if (arg === "seal" || arg.startsWith("seal ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const reason = arg.slice(4).trim() || "人工通过 /nuwa seal 执行负向封盘";
				try {
					abortAutoBatch(found, "sealed_negative");
					const sealed = sealEngagement(found, { reason });
					cleanupTrackedProcesses(found, { reason: "slash_seal" });
					if (isPausedState(found)) setPausedState(found, false, "sealed_negative");
					refreshUi(ctx as ExtensionContext, found, sealed.state, true);
					return notify(`已封盘 ${sealed.state.project.id} (status=${sealed.status}) · 原因: ${sealed.sealMeta.reason}`);
				} catch (e) {
					return notify(`封盘失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
			}

			// /nuwa note [tag:] <title> [:: <detail>] (#31)
			if (arg === "note" || arg.startsWith("note ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const rest = arg.slice(4).trim();
				if (!rest) return notify("用法: /nuwa note [note|endpoint|service|asset:] <标题> [:: <详情>]", "error");
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
					refreshUi(ctx as ExtensionContext, found, committed.state, true);
					return notify(`免票据事实已入账: ${committed.fact.id} [${committed.fact.kind}] ${committed.fact.title}`);
				} catch (e) {
					return notify(`免票据记账失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
			}

			// /nuwa inspect <intentId> (#35 纯只读零写入)
			if (arg === "inspect" || arg.startsWith("inspect ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const intentId = arg.slice(7).trim();
				if (!intentId) return notify("用法: /nuwa inspect <intentId>（如 /nuwa inspect i001）", "error");
				const diag = inspectGraph(found, { intentId });
				if (!diag.ok) return notify("state 读取失败", "error");
				const hit = diag.intents[0];
				if (!hit) return notify(`未找到意图: ${intentId}`, "error");
				return notify(
					[
						`[只读诊断 ${hit.id}] status=${hit.status} phase=${hit.phase} domain=${hit.resolvedSurfaceDomain} expectedKind=${hit.resolvedExpectedKind}`,
						`targetKey=${hit.resolvedTargetKey} attempts=${hit.attempts} worker=${hit.worker ?? "-"}`,
						`标题: ${hit.title}`,
						...(hit.note ? [`备注: ${hit.note}`] : []),
						...(hit.toFact ? [`产出事实: ${hit.toFact.id} [${hit.toFact.kind}] ${hit.toFact.title}`] : []),
					].join("\n"),
				);
			}

			// /nuwa query [status=... | target=... | archive=...] (#34, #35, #52 纯只读零写入)
			if (arg === "query" || arg.startsWith("query ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const qRaw = arg.slice(5).trim();
				if (!qRaw || qRaw === "raw" || qRaw === "full") {
					try {
						return notify(renderFullStatus(found, { raw: true }));
					} catch (e) {
						return notify(`全量状态读取失败: ${e instanceof Error ? e.message : String(e)}`, "error");
					}
				}
				if (qRaw.startsWith("archive ") || qRaw.startsWith("archive=")) {
					const kw = qRaw.replace(/^archive[\s=]+/, "").trim();
					const hits = searchArchiveIndexes(found, kw);
					return notify(
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
				if (!diag.ok) return notify("state 读取失败", "error");
				const lines = diag.intents.map(
					(it) => `${it.id} [${it.status}] ${it.phase} (${it.resolvedSurfaceDomain}) ${it.resolvedTargetKey} — ${it.title}`,
				);
				return notify(`查询命中 ${diag.matchedCount} 条:\n${lines.join("\n") || "(无匹配项)"}`);
			}

			// /nuwa pause [reason] (#44 免确认软暂停)
			if (arg === "pause" || arg.startsWith("pause ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const reason = arg.slice(5).trim() || "user paused via /nuwa pause";
				abortAutoBatch(found, `paused:${reason}`);
				setPausedState(found, true, reason);
				const st = loadState(found);
				if (st) refreshUi(ctx as ExtensionContext, found, st, true);
				return notify(`已软暂停项目 · ${reason}｜执行 /nuwa resume 即可恢复`);
			}

			// /nuwa export [episode] (#42, #52 时间线与归档导出)
			if (arg === "export" || arg.startsWith("export ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const st = loadState(found);
				if (!st) return notify("state 读取失败", "error");
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
					return notify(`已导出时间线: ${tlFile}\n已生成归档索引: ${arch.jsonPath}`);
				} catch (e) {
					return notify(`导出失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
			}

			if (arg === "session" || arg.startsWith("session ")) {
				const subSession = arg.slice(7).trim();
				if (subSession === "health" || subSession.startsWith("health ")) {
					const r = await executeSessionHealthCommand(found, subSession.slice(6));
					const stAfter = found ? loadState(found) : null;
					if (found && stAfter) refreshUi(ctx as ExtensionContext, found, stAfter, true);
					return notify(r.msg, r.level);
				}
				const r = executeSessionCommand(found, arg.slice(7));
				return notify(r.msg, r.level);
			}

			if (arg === "authdiff" || arg.startsWith("authdiff ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				try {
					const rawPaths = arg.slice(8).trim();
					const explicitPaths = rawPaths ? rawPaths.split(/\s+/).filter(Boolean) : undefined;
					const r = await executeAuthDiffWorkflow(found, explicitPaths);
					const stAfter = loadState(found);
					if (stAfter) refreshUi(ctx as ExtensionContext, found, stAfter, true);
					return notify(r.msg);
				} catch (e) {
					return notify(`鉴权差分失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
			}

			if (arg === "oob" || arg.startsWith("oob ")) {
				const r = await executeOobCommand(found, arg.slice(3));
				const stAfter = found ? loadState(found) : null;
				if (found && stAfter) refreshUi(ctx as ExtensionContext, found, stAfter, true);
				return notify(r.msg, r.level);
			}

			if (arg === "assets" || arg.startsWith("assets ")) {
				const r = executeAssetsCommand(found);
				const stAfter = found ? loadState(found) : null;
				if (found && stAfter) refreshUi(ctx as ExtensionContext, found, stAfter, true);
				return notify(r.msg, r.level);
			}

			if (arg === "report" || arg.startsWith("report ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				const st = loadState(found);
				if (!st) return notify("state 读取失败", "error");
				const subFmt = (arg.slice(6).trim().toLowerCase() || "md");
				try {
					if (subFmt === "timeline" || subFmt.startsWith("timeline ")) {
						const epStr = subFmt.slice(8).trim();
						const ep = epStr && Number.isFinite(Number(epStr)) ? Math.floor(Number(epStr)) : undefined;
						const tl = exportEpisodeTimeline(found, { episode: ep, format: "markdown" });
						const outPath = join(found, ".nuwa", ep !== undefined ? `TIMELINE-E${ep}.md` : "TIMELINE.md");
						atomicWrite(outPath, tl);
						writeEpisodeArchiveIndex(found, { episode: ep ?? st.project.episode ?? 1, state: st });
						return notify(`Episode 时间线已写入: ${outPath}`);
					}
					if (subFmt === "bundle") {
						const b = writePocBundle(found, st);
						return notify(`已生成脱敏证据包: ${b.dir}（${b.files.length} 个文件）`);
					}
					if (subFmt === "sarif") {
						const sarif = buildSarifReport(st, found);
						const outPath = join(found, ".nuwa", "REPORT.sarif.json");
						atomicWrite(outPath, `${JSON.stringify(sarif, null, 2)}\n`);
						writeEpisodeArchiveIndex(found, { episode: st.project.episode ?? 1, state: st });
						const count = (sarif.runs as Array<{ results?: unknown[] }> | undefined)?.[0]?.results?.length ?? 0;
						return notify(`SARIF 2.1.0 报告已写入: ${outPath}（已确认漏洞 ${count} 条）`);
					}
					if (subFmt === "json") {
						const rep = buildJsonReport(st, found);
						const outPath = join(found, ".nuwa", "REPORT.json");
						atomicWrite(outPath, `${JSON.stringify(rep, null, 2)}\n`);
						writeEpisodeArchiveIndex(found, { episode: st.project.episode ?? 1, state: st });
						return notify(`JSON 报告已写入: ${outPath}`);
					}
					if (subFmt === "md" || subFmt === "markdown") {
						const md = redactVaultSecrets(reportMarkdown(st, found), found);
						const outPath = join(found, ".nuwa", "REPORT.md");
						atomicWrite(outPath, md);
						writeEpisodeArchiveIndex(found, { episode: st.project.episode ?? 1, state: st });
						return notify(`Markdown 报告已写入: ${outPath}\n\n${md.slice(0, 1200)}`);
					}
					return notify("用法: /nuwa report [md | json | sarif | timeline | bundle]", "error");
				} catch (e) {
					return notify(`报告生成失败: ${e instanceof Error ? e.message : String(e)}`, "error");
				}
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
					const tail = readJournalTail(found, n);
					notify(tail.length > 0 ? tail.map((e) => JSON.stringify(e)).join("\n") : "(空日志)");
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
				cleanupTrackedProcesses(found, { reason: `slash_stop:${reason}` });
				if (isPausedState(found)) setPausedState(found, false, "stopped");
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
				try {
					const dist = distillProjectExperience(st, { agentHome: getAgentHome(), negativeOnly: true });
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
				refreshUi(ctx as ExtensionContext, found, st, true);
				return notify(`已停止 ${st.project.id} · ${reason}｜/nuwa resume 继续`);
			}
			if (arg === "resume" || arg.startsWith("resume ")) {
				if (!found) return notify("当前目录没有女娲项目", "error");
				warmBundledKb();
				if (isPausedState(found)) {
					setPausedState(found, false, "resumed via /nuwa resume");
				}
				const st = withLock(found, () => {
					const s = loadState(found);
					if (!s) return null;
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
				if (!st) return notify("state 读取失败", "error");
				verifyWorkspaceIntegrity(found, { recordBaseline: true });
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
			const target = extractTarget(arg) ?? (mode === "coding" || mode === "ops" || mode === "audit" ? ctx.cwd : null);
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
					ensurePrimaryAsset(s);
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
			verifyWorkspaceIntegrity(root, { recordBaseline: true });
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
				if (isPausedState(root)) continue;
				const probe = loadState(root);
				if (!probe || probe.project.status !== "active" || probe.runtime.status === "sealed_negative") continue;
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
					if (!s || s.project.status !== "active" || s.runtime.status === "sealed_negative") return;
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

	pi.on("before_subagent_spawn" as Parameters<ExtensionAPI["on"]>[0], ((event: Record<string, unknown>, ctx: ExtensionContext) => {
		try {
			const root = resolveRootWithLineage(ctx);
			if (!root) return;
			bindSubagentSpawn(sidOf(ctx), ctx.agent?.id, root, getAgentHome());
			const st = loadState(root);
			if (!st || st.project.status !== "active") return;

			const watchdog = new SubagentWatchdog(root);
			watchdog.checkTimeouts();

			const agentName =
				typeof event?.agent === "string"
					? event.agent
					: typeof event?.agentName === "string"
						? event.agentName
						: typeof event?.name === "string"
							? event.name
							: "";
			const taskText = String(event?.task ?? event?.prompt ?? "");
			const spawnId =
				typeof event?.spawnId === "string" && event.spawnId.trim()
					? event.spawnId.trim()
					: typeof event?.id === "string" && event.id.trim()
						? event.id.trim()
						: `spawn-${Date.now()}-${++spawnSeq}`;
			const routeCtx = resolveTaskIntentContext(agentName, taskText, st.intents, st.project.phase);

			// #26 / #23 先对非空派单注入 resolved_host、target_url 与出口环境变量指引（展开 [TARGET]/https://TARGET）
			const activeEgress = normalizeTaskEgressUrl(resolveConfiguredEgressUrl());
			const trimmedRawTask = taskText.trim();
			const preInjectedTask =
				trimmedRawTask.length >= 8
					? buildDispatchPacket({
							task: taskText,
							target: {
								url: st.project.url,
								host: st.project.host,
								...(activeEgress ? { egress: maskEgressUrl(activeEgress) } : {}),
							},
						}).task
					: taskText;

			// #27 校验派单非空、达到最小有效长度且登记派单回执
			const dispatchReg = getDispatchRegistry(root).register(spawnId, {
				spawnId,
				agent: agentName,
				task: preInjectedTask,
				targetUrl: st.project.url,
				resolvedHost: st.project.host,
				intentId: routeCtx.intentId,
				context: event?.context as Record<string, unknown> | string | undefined,
			});
			if (!dispatchReg.ok) {
				logEvent(root, {
					type: "dispatch_rejected",
					spawnId,
					agent: agentName || "unknown",
					reason: dispatchReg.validation.reason,
					requeue: dispatchReg.requeue,
				});
				return {
					block: true,
					requeue: dispatchReg.requeue,
					reason: dispatchReg.validation.reason ?? "派单守卫拒收：任务为空或上下文不完整",
				};
			}

			if (event && typeof event === "object") {
				if ("task" in event || event.prompt === undefined) event.task = preInjectedTask;
				else event.prompt = preInjectedTask;
			}

			// #46 启动子代理心跳与超时看门狗监控
			const pidVal = typeof event?.pid === "number" ? event.pid : undefined;
			watchdog.startTask({
				taskId: spawnId,
				agent: agentName || "fujiang",
				intentId: routeCtx.intentId,
				pid: pidVal,
			});
			activeSpawns.set(spawnId, {
				spawnId,
				root,
				agent: agentName || "fujiang",
				...(routeCtx.intentId ? { intentId: routeCtx.intentId } : {}),
				rawTask: trimmedRawTask,
				injectedTask: preInjectedTask,
				sessionId: sidOf(ctx),
			});

			const routedModel = routeSubagentModel({
				agent: agentName,
				phase: routeCtx.phase,
				intentKeys: routeCtx.intentKey ? [routeCtx.intentKey] : [],
				hasPendingVerify: routeCtx.isVerify,
				hasReflect: routeCtx.isReflect,
				root,
			});

			// v6.0 反自证校准事前预测登记（基于意图信念后验，留待后续机械门禁对账结算）
			if (routeCtx.intentId && (process.env.NUWA_CALIBRATION ?? "1").trim() !== "0") {
				try {
					const bGraph = loadOrInitBeliefGraph(root, st);
					const bNodeId = resolveBeliefNodeId(bGraph, routeCtx.intentId, "intent");
					const posterior = bNodeId && bGraph.nodes[bNodeId] ? bGraph.nodes[bNodeId]!.posterior : 0.5;
					const effModelId =
						routedModel ||
						(typeof event?.model === "string" && event.model.trim() ? event.model.trim() : "host-default");
					recordPrediction(root, {
						predictionId: `pred-${spawnId}`,
						intentId: routeCtx.intentId,
						taskCategory: inferCalibrationTaskCategory({
							agent: agentName,
							phase: routeCtx.phase,
							intentKey: routeCtx.intentKey,
							hasPendingVerify: routeCtx.isVerify,
						}),
						modelId: effModelId,
						predictedConfidence: Math.max(0.01, Math.min(0.99, Number(posterior.toFixed(4)))),
						estimatedTokens: 4000,
						note: `spawn:${agentName || "fujiang"}:${routeCtx.intentKey ?? routeCtx.intentId}`,
					});
				} catch {
					/* 重复 spawnId 或只读异常不阻断子代理派生 */
				}
			}
			if (routedModel) {
				if (event && typeof event === "object" && !event.model) event.model = routedModel;
				logEvent(root, {
					type: "model_route",
					agent: agentName || "unknown",
					model: routedModel,
					phase: routeCtx.phase,
					...(routeCtx.intentId ? { intentId: routeCtx.intentId } : {}),
					...(routeCtx.intentKey ? { intentKey: routeCtx.intentKey } : {}),
					isVerify: routeCtx.isVerify,
					isReflect: routeCtx.isReflect,
				});
				return { model: routedModel, spawnId, task: preInjectedTask };
			}
			return { spawnId, task: preInjectedTask };
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
			if (root) {
				abortAutoBatch(root, "session_shutdown");
				try {
					const wd = new SubagentWatchdog(root);
					for (const t of wd.listTasks({ status: "running" })) {
						wd.completeTask(t.taskId, "cancelled");
						activeSpawns.delete(t.taskId);
					}
				} catch {
					/* ignore watchdog cleanup */
				}
				cleanupTrackedProcesses(root, { reason: "session_shutdown" });
			}
		} catch {
			/* ignore */
		}
		clearUi(c);
	});

	pi.on("tool_execution_end", (event, ctx) => {
		const sid = sidOf(ctx);
		liveCalls.set(sid, (liveCalls.get(sid) ?? 0) + 1);
		try {
			const evObj = (event ?? {}) as Record<string, unknown>;
			const { toolName, inputObj, command, output } = extractEventOutput(evObj);
			const root = resolveRootWithLineage(ctx);
			if (root && !isMain(ctx)) {
				const wd = new SubagentWatchdog(root);
				wd.recordOutput(resolveWatchdogTaskId(wd, ctx));
			}
			const normTool = toolName.trim().toLowerCase();
			if (root && (normTool === "task" || normTool === "subagent" || normTool === "agent" || normTool === "delegate")) {
				completeWatchdogOnTaskEnd(root, evObj, inputObj, ctx);
			}
			if (!isTrustedEvidenceEvent(toolName, inputObj)) return;
			if (!root) return;
			if (command || output) {
				const agentObj = ctx.agent as { name?: string; kind?: string } | undefined;
				const agentName = agentObj?.name ?? agentObj?.kind;
				recordToolExecution(root, { tool: toolName, command, output, sessionId: sid, agentName });
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

			if (active && !main) {
				const wd = new SubagentWatchdog(root);
				wd.recordRequest(resolveWatchdogTaskId(wd, ctx));
			}

			if (active && !main && /^nuwa_(init|plan|claim|commit|flag|complete|expand|stop)$/.test(name)) {
				return { block: true, reason: `nuwa N-005: ${name} 只能由主线程调用；子代理把结果回给主线程` };
			}
			if (name === "bash") {
				const cmd = typeof input.command === "string" ? input.command : "";
				const sbCfg = active && !main ? readSandboxConfig() : null;
				let cmdForPolicy = cmd;

				if (sbCfg && (sbCfg.mode === "docker" || sbCfg.mode === "sidecar") && cmd.trim()) {
					const isCompliant =
						sbCfg.mode === "docker"
							? isCompliantSandboxDockerCommand(cmd, st.project.id).ok
							: isCompliantSidecarCommand(cmd, st.project.id).ok || isCompliantSandboxDockerCommand(cmd, st.project.id).ok;
					if (isCompliant) {
						const inner = extractSandboxInnerCommand(cmd, sbCfg.egressProxyUrl);
						if (inner !== null) {
							cmdForPolicy = inner;
						}
					}
				}

				// #48 统一调用 omp/scope.ts（拦截 curl/wget 与内联 python -c/node -e/bun -e 等越界并携带 [layer=...]）
				const v = checkBashPolicy(cmdForPolicy, active, main, projScope, st.project.mode);
				if (v) return v;
				if (sbCfg && cmd.trim()) {
					if (sbCfg.mode === "docker") {
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
					} else if (sbCfg.mode === "sidecar") {
						const scVerdict = isCompliantSidecarCommand(cmd, st.project.id);
						const dkVerdict = scVerdict.ok ? { ok: true } : isCompliantSandboxDockerCommand(cmd, st.project.id);
						if (!scVerdict.ok && !dkVerdict.ok) {
							let hintCmd = "";
							try {
								hintCmd = wrapCommandInSidecarSandbox(cmd, {
									projectId: st.project.id,
									scope: projScope,
									config: sbCfg,
									proxyUrl: sbCfg.egressProxyUrl,
									ensureWorkdir: false,
								});
							} catch {
								hintCmd = `docker exec -w /tmp/nuwa/${st.project.id} nuwa-sb-${st.project.id} sh -c '...'`;
							}
							return { block: true, reason: `nuwa N-009: 已启用常驻零信任 Sidecar 沙盒 (${scVerdict.reason})；请改用合规 Sidecar 包裹命令:\n${hintCmd}` };
						}
					}
				}
				return;
			}
			if (name === "task") {
				const v = checkTaskPolicy(input, active, main);
				if (v) return v;
				if (active && main) {
					bindSubagentSpawn(sidOf(ctx), ctx.agent?.id, root, getAgentHome());
					const rawTasks = Array.isArray(input.tasks)
						? (input.tasks as Array<Record<string, unknown>>)
						: [input];
					for (const item of rawTasks) {
						const tStr = String(item?.task ?? item?.prompt ?? "").trim();
						if (!tStr) {
							const dv = validateSubagentDispatch({ task: "", targetUrl: st.project.url });
							return { block: true, reason: `nuwa N-007: ${dv.reason ?? "派单 task 为空"}` };
						}
						if (/\[(?:TARGET|HOST|DOMAIN|URL)\]|https?:\/\/(?:TARGET|HOST|DOMAIN)\b|\bno\s+assigned\s+task\b/i.test(tStr)) {
							const dv = validateSubagentDispatch({ task: tStr, targetUrl: st.project.url, resolvedHost: st.project.host });
							if (!dv.ok) return { block: true, reason: `nuwa N-007: ${dv.reason}` };
						}
					}
					if (Array.isArray(input.tasks) && input.tasks.length > 1) {
						const chunked = chunkBatchTasks(input.tasks as BatchTaskItem[], { root });
						if (chunked.exceeded) {
							logEvent(root, {
								type: "batch_spilled",
								totalBytes: chunked.totalBytes,
								chunks: chunked.chunks.length,
								tasksFile: chunked.tasks_file,
							});
						}
					}
				}
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

			// #44 软暂停挂起检查：优雅挂起不强阻塞续跑
			if (isPausedState(root)) {
				ctx.ui?.setStatus?.("nuwa", "已软暂停 (/nuwa resume 恢复)");
				return undefined;
			}

			const cur = loadState(root);
			if (!cur || cur.project.status !== "active" || cur.runtime.status === "sealed_negative") return;

			const lock = readJson<{ pid?: number }>(lockPath(root));
			if (lock?.pid && lock.pid !== process.pid && pidAlive(lock.pid)) return;

			// #46 结算前巡检子代理超时看门狗
			try {
				new SubagentWatchdog(root).checkTimeouts();
			} catch {
				/* ignore */
			}

			// #47 结算前校验工作区目录与 .git 完好性
			const wsReport = verifyWorkspaceIntegrity(root);
			if (!wsReport.ok && wsReport.status === "corrupted") {
				logEvent(root, { type: "workspace_corrupted", warnings: wsReport.warnings });
				ctx.ui?.setStatus?.("nuwa", `工作区异常 (${wsReport.warnings[0]?.code ?? "corrupted"})`);
				return undefined;
			}

			const usage = ctx.getContextUsage?.() as { tokens?: number; usedTokens?: number } | undefined;
			const tokens = Number(usage?.tokens ?? usage?.usedTokens ?? 0);
			const settled = settleSessionStopState({ root, curCfg, tokens, liveCallCount: liveCalls.get(sid) ?? 0, canAutoExec: hasExec(), initialPhase: cur.project.phase });
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
