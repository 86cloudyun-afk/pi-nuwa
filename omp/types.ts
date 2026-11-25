/**
 * 女娲 v4.0 共享类型定义。
 *
 * 汇总核心状态机、范围护栏、证据账本、多领域 Profile、会话保险箱、
 * 双盲复验闸门、零信任沙盒与世代轮转的公共类型，
 * 供各子模块 `import type` 使用，并由 `omp/nuwa.ts` 完整 re-export 以保持 100% 向后兼容。
 */

export const NUWA_VERSION = "4.1.0";
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
export type VerifyStage = "candidate" | "confirmed" | "rejected";

export interface AutoFactMeta {
	ports?: number[];
	paths?: string[];
	server?: string;
	tech?: string[];
	status?: number;
	san?: string[];
	waf?: string;
	routes?: string[];
	bundles?: string[];
	graphql?: boolean;
}

export interface ScopePolicy {
	allowHosts: string[];
	allowCidrs: string[];
	denyHosts: string[];
	allowSubdomains: boolean;
	allowPrivateNetwork: boolean;
	allowDestructive: boolean;
	/** v4.1 回环地址放行策略；undefined 兼容历史策略，false 时禁止越界访问宿主机回环。 */
	allowLoopback?: boolean;
	/** v5.0 受控 OOB（带外回调，如 Interactsh/DNSLog）允许域名白名单。 */
	oobDomains?: string[];
}

export interface ExecRecordInput {
	tool: string;
	command?: string;
	output: string;
	sessionId?: string;
	/** v4.1 记录执行该工具的代理名（如 fujiang / nuwa-verifier / main / egress-proxy）。 */
	agentName?: string;
}

export interface VerifyEvidenceInput {
	projectId: string;
	kind: string;
	command?: string;
	output?: string;
	flagValue?: string;
	strict?: boolean;
	/** v4.1 要求匹配序列号严格大于 minSeq 的新执行记录（防止复验复用候选旧输出）。 */
	minSeq?: number;
	/** v4.1 可选时间戳下界（ISO 字符串）。 */
	sinceTs?: string;
	/** v4.1 强制要求命中非泛化高信息熵行，拒绝仅凭 HTTP/1.1 200 OK 等通用头放行。 */
	requireSubstantive?: boolean;
}

export interface VerifyEvidenceResult {
	ok: boolean;
	verified: boolean;
	reason?: string;
	matchedSeq?: number;
	matchedAgent?: string;
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
	/** v4.0 双盲独立复验状态：candidate 待复验 / confirmed 已证实 / rejected 已证伪驳回。 */
	verifyStage?: VerifyStage;
	verifyNote?: string;
	verifiedAt?: string;
	verifiedBy?: string;
	/** v4.1 候选创建时的执行账本序列水位，用于校验复验阶段确实发生了新的独立执行。 */
	evidenceSeq?: number;
	/** v5.0 关联的多资产节点 ID。 */
	assetId?: string;
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
	/** v5.0 关联的假设图节点 ID。 */
	hypothesisId?: string;
	/** v5.0 关联的多资产节点 ID。 */
	assetId?: string;
	/** v5.0 指定认证态角色（Session Vault 角色名）。 */
	authRole?: string;
	/** v5.0 当依赖前提事实被证伪时的自动剪枝/失效原因。 */
	invalidatedReason?: string;
}

/** v5.0 多资产与跳板可达拓扑节点。 */
export interface AssetNode {
	id: string;
	kind: "web" | "host" | "subnet" | "repo" | "service";
	target: string;
	host?: string;
	port?: number;
	scheme?: string;
	reachableVia?: string[];
	tags?: string[];
	sourceFactId?: string;
	createdAt: string;
}

/** v5.0 跨事实结构化假设节点。 */
export interface HypothesisNode {
	id: string;
	title: string;
	statement: string;
	requiredFacts: string[];
	falsificationTest: string;
	expectedGain: number;
	estimatedCost: number;
	status: "open" | "confirmed" | "falsified" | "invalidated";
	linkedIntents: string[];
	createdAt: string;
	updatedAt: string;
	note?: string;
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
	/** v4.0 会话保险箱中已收纳的角色名列表（不含任何敏感值）。 */
	activeRoles?: string[];
	/** v4.0/v5.0 沙盒隔离模式标识。 */
	sandboxMode?: "none" | "docker" | "sidecar";
	/** v5.0 配置的受控 OOB 回调域名（若有）。 */
	oobDomain?: string;
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
	/** 当前自动批规则来源标识（builtin/project/global）。 */
	rulesSource?: string;
	/** v4.1 跨世代保留的项目首次启动时间戳（resume/reincarnate 绝不清零）。 */
	projectStartedAt?: number;
	/** v4.1 跨世代累计总轮次（resume/reincarnate 绝不清零）。 */
	totalTurns?: number;
	/** v4.1 跨世代累计总 Token 消耗（含世代交接累加）。 */
	totalTokens?: number;
	/** v5.0 跨世代估算累计成本（USD）。 */
	totalCostUsd?: number;
}

export interface NuwaState {
	schema: number;
	version: string;
	project: Project;
	facts: Record<string, Fact>;
	intents: Record<string, Intent>;
	seq: { fact: number; intent: number };
	runtime: Runtime;
	/** v5.0 多资产与跳板可达拓扑图。 */
	assets?: Record<string, AssetNode>;
	/** v5.0 跨事实结构化假设图。 */
	hypotheses?: Record<string, HypothesisNode>;
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
	verifyStage?: VerifyStage;
}

export interface PolicyVerdict {
	block: true;
	reason: string;
}
