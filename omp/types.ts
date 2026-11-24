/**
 * 女娲 v3.0 共享类型定义。
 *
 * 汇总核心状态机、范围护栏、证据账本、多领域 Profile 与世代轮转的公共类型，
 * 供各子模块 `import type` 使用，并由 `omp/nuwa.ts` 完整 re-export 以保持 100% 向后兼容。
 */

export const PHASE_ORDER = ["recon", "surface", "vuln", "exploit", "post", "report"] as const;

export type ProfileMode = "ctf" | "pentest" | "audit" | "coding" | "ops";
export type Mode = ProfileMode;

export type FactKind =
	| "target"
	| "asset"
	| "service"
	| "endpoint"
	| "cred"
	| "vuln"
	| "flag"
	| "loot"
	| "note"
	| "blocked";

export type Phase = (typeof PHASE_ORDER)[number];
export type IntentStatus = "open" | "claimed" | "done" | "blocked";

export interface AutoFactMeta {
	ports?: number[];
	paths?: string[];
	server?: string;
	tech?: string[];
	status?: number;
	san?: string[];
	waf?: string;
}

export interface ScopePolicy {
	allowHosts: string[];
	allowCidrs: string[];
	denyHosts: string[];
	allowSubdomains: boolean;
	allowPrivateNetwork: boolean;
	allowDestructive: boolean;
}

export interface ExecRecordInput {
	tool: string;
	command?: string;
	output: string;
	sessionId?: string;
}

export interface VerifyEvidenceInput {
	projectId: string;
	kind: string;
	command?: string;
	output?: string;
	flagValue?: string;
	strict?: boolean;
}

export interface VerifyEvidenceResult {
	ok: boolean;
	verified: boolean;
	reason?: string;
}

export interface ToolchainCaps {
	available: string[];
	missing: string[];
	probedAt: string;
}

export interface ReincarnatePolicy {
	maxTokens: number;
	maxTurns: number;
	headless: boolean;
}

export interface ProfileSpec {
	mode: ProfileMode;
	label: string;
	proofKinds: FactKind[];
	phases: readonly Phase[];
	requireHttpTarget: boolean;
	seeds: Record<Phase, Array<{ key: string; title: string; detail: string; priority?: number }>>;
}

export interface Fact {
	id: string;
	kind: FactKind;
	title: string;
	detail: string;
	command?: string;
	output?: string;
	intent?: string;
	key?: string;
	createdAt: string;
	meta?: AutoFactMeta;
	verified?: boolean;
}

export interface Intent {
	id: string;
	phase: Phase;
	key: string;
	title: string;
	detail: string;
	from: string[];
	to?: string;
	status: IntentStatus;
	worker?: string;
	priority: number;
	attempts: number;
	createdAt: string;
	claimedAt?: string;
	doneAt?: string;
	note?: string;
	/** 网络错误退避冷却截止时间戳（ms）。 */
	nextRunAt?: number;
}

export interface Project {
	id: string;
	target: string;
	url: string;
	host: string;
	port: number;
	scheme: string;
	goal: string;
	mode: Mode;
	status: "active" | "completed" | "stopped";
	phase: Phase;
	createdAt: string;
	updatedAt: string;
	completedAt?: string;
	completedFrom?: string[];
	stopReason?: string;
	/** 扩张轮次：report 全终态后 +1 并回到 recon；目标未达就永不封顶。 */
	episode?: number;
	/** 首次创建/接管的 omp 会话；共享 cwd 下用它拒绝跨会话接管。 */
	ownerSessionId?: string;
	/** v3.0 靶标范围与高危拦截策略。 */
	scope?: ScopePolicy;
	/** v3.0 本地可用工具链能力快照。 */
	toolchain?: ToolchainCaps;
}

export interface Runtime {
	startedAt: number;
	turns: number;
	stall: number;
	idle: number;
	blockStreak: number;
	toolCalls: number;
	lastToolCalls: number;
	tokens: number;
	lastSig: string;
	lastDirective: string;
	completionRejects: number;
	emptyRounds: number;
	/** 二维空转闸：有工具活动但无新事实的连续轮次。 */
	suspectRounds?: number;
	/** 最近一次 settle/续跑时间；看门狗据此判断是否断线。 */
	lastSettleAt?: number;
	/** 累计自动扩张次数与最近一次时间。 */
	expansions?: number;
	lastExpandAt?: number;
	/** 预算压力 0..1，只用于降档，不用于停机。 */
	pressure?: number;
	/** 上一轮 facts 数，空转闸用它判断是否有新事实。 */
	lastFacts?: number;
	/** 当前会话世代号（从 1 开始）。 */
	generation?: number;
	/** 当前世代内已运行的轮次数。 */
	genTurns?: number;
	/** 世代轮转交接摘要，供外层守护器拉起下一代会话注入。 */
	handoffSummary?: string;
	/** 自动批网络抖动重试累计次数。 */
	netRetries?: number;
	/** saveState 累计写盘次数，用于增量控制全量 gz 快照频率。 */
	saveCount?: number;
	/** 最近一次 state.json 字节数。 */
	stateBytes?: number;
	/** 当前自动批规则来源标识（builtin/project/agent）。 */
	rulesSource?: string;
}

export interface NuwaState {
	schema: number;
	version: string;
	project: Project;
	facts: Record<string, Fact>;
	intents: Record<string, Intent>;
	seq: { fact: number; intent: number };
	runtime: Runtime;
}

export interface Cfg {
	loop: boolean;
	/** 无限推进：预算只降档不停机；唯一停机条件是目标完成或人工 stop。 */
	infinite: boolean;
	maxTurns: number;
	maxStall: number;
	maxIdle: number;
	maxTokens: number;
	maxMinutes: number;
	maxBatch: number;
	claimTtl: number;
	blockStreak: number;
	guardHours: number;
	kbDb: string;
	scannerGuard: boolean;
	requireFujiang: boolean;
	/** 看门狗心跳间隔（毫秒）；stop hook 失效时用它兜底续跑。 */
	tickMs: number;
	/** 单次扩张最多派生多少条意图。 */
	expandDepth: number;
	/** 扩张轮次上限；0 = 无限。 */
	maxEpisodes: number;
	/** 确定性侦察自动执行（omp 驱动）。 */
	auto: boolean;
	/** 每轮自动批上限。 */
	autoMax: number;
	/** 连续 N 轮无工具且无新事实触发空转硬闸。 */
	emptyLimit: number;
	/** 连续 N 轮有工具活动但无新事实触发疑似空转收口（默认 5）。 */
	suspectLimit?: number;
	/** 单条意图尝试上限，超过自动 blocked。 */
	maxAttempts: number;
	/** 单批自动执行总时间预算（毫秒，默认 90000）。 */
	autoBudgetMs?: number;
	/** 自动批并发度（默认 1）。 */
	autoConcurrency?: number;
}

export interface Seed {
	key: string;
	title: string;
	detail: string;
	priority?: number;
}

export interface FrontierItem {
	intent: Intent;
	stale: boolean;
	missing: string[];
}

export interface ExpansionResult {
	added: string[];
	rules: string[];
}

export interface AutoPlanResult {
	added: string[];
	reason: string;
	phase?: Phase;
	episode?: number;
}

export interface CommitInput {
	id: string;
	kind?: FactKind;
	title?: string;
	detail?: string;
	command?: string;
	output?: string;
	blocked?: boolean;
	note?: string;
	meta?: AutoFactMeta;
	verified?: boolean;
}

export interface PolicyVerdict {
	block: true;
	reason: string;
}
