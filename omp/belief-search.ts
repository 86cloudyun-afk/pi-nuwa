/**
 * 女娲 v6.0 信念驱动攻击图搜索引擎（Cairn 启发式状态空间搜索核）。
 *
 * 核心职责：
 * 1. 维护数学严谨、数值稳定的 Beta(alpha, beta) 共轭先验/后验信念节点 `BeliefNode`；
 * 2. 基于二元香农熵、认知样本饱和度与未探索依赖子树广度精确计算预期信息增益（VoI）；
 * 3. 支持观测证据贝叶斯更新、WAF 硬阻断/双盲复验驳回沿拓扑衰减级联剪枝、以及关键跃迁信号
 *    （如 `.js.map` 源码泄露、获取 `cred`、越权实锤）触发关联攻击链先验跃升与全局前沿重排；
 * 4. 将信念后验、VoI、执行代价效用与优先级/UCB1 无缝融合排序，并给出搜索转向及 `sealed_negative` 收口置信度。
 *
 * 约束：严禁运行时导入 `./nuwa`，仅依赖 `./types` 纯类型及 Node 内置模块，保持零循环依赖。
 */
import type {
	Fact,
	FactKind,
	FrontierItem,
	HypothesisNode,
	Intent,
	NuwaState,
	Phase,
	SurfaceDomain,
} from "./types";

/** Beta 分布伪计数安全下界，严防 0/0、负数或对数奇点。 */
export const MIN_BETA_PARAM = 1e-4;
/** Beta 分布伪计数安全上界，防止极端循环观测导致浮点溢出。 */
export const MAX_BETA_PARAM = 1e6;
/** 默认低收益子树自动剪枝后验阈值。 */
export const DEFAULT_PRUNE_THRESHOLD = 0.2;
/** 默认拓扑级联衰减系数。 */
export const DEFAULT_PROPAGATION_DECAY = 0.7;
/** 默认负向封盘建议置信度阈值。 */
export const DEFAULT_NEGATIVE_SEAL_THRESHOLD = 0.75;

export type BeliefNodeKind = "fact" | "intent" | "hypothesis" | "surface";

export type BeliefObservationType =
	| "confirmed_hit"
	| "partial_signal"
	| "waf_block"
	| "soft404_miss"
	| "verifier_reject"
	| "timeout"
	| "breakthrough_signal";

export const VALID_BELIEF_OBSERVATIONS: ReadonlySet<BeliefObservationType> = new Set([
	"confirmed_hit",
	"partial_signal",
	"waf_block",
	"soft404_miss",
	"verifier_reject",
	"timeout",
	"breakthrough_signal",
]);

export interface BeliefObservation {
	type: BeliefObservationType;
	/** 观测强度权重（默认 1.0，自动钳制在 [0.05, 10]）。 */
	weight?: number;
	/** 观测备注（如 ".js.map 源码泄露"、"WAF 403 拦截"）。 */
	note?: string;
	/** 可选观测时间戳（ISO-8601）。 */
	at?: string;
}

export interface BeliefNode {
	id: string;
	kind: BeliefNodeKind;
	sourceId: string;
	title: string;
	phase?: Phase;
	targetKey?: string;
	alpha: number;
	beta: number;
	/** Beta 后验均值：alpha / (alpha + beta)，严格位于 (0, 1)。 */
	posterior: number;
	/** 后验不确定性度量（融合二元香农熵与样本饱和收缩），严格位于 [0, 1]。 */
	uncertainty: number;
	/** 预期信息增益（Value of Information, VoI），严格 >= 0。 */
	expectedInfoGain: number;
	/** 预估执行代价，严格 >= 0.5。 */
	estimatedCost: number;
	/** 单位代价综合效用得分，严格 >= 0。 */
	utilityScore: number;
	/** 是否已被低收益/证伪剪枝。 */
	pruned: boolean;
	/** 剪枝原因说明。 */
	pruneReason?: string;
	/** 上游前置依赖节点 ID 列表。 */
	parentIds: string[];
	/** 下游派生节点 ID 列表。 */
	childIds: string[];
	/** 攻击面分域（port / path / host）。 */
	surfaceDomain?: SurfaceDomain;
	/** 累计观测更新次数（供 UCB1 探索项使用）。 */
	observations: number;
	/** 关键跃迁信号加成强度（>= 0）。 */
	breakthroughBoost: number;
	/** 节点最近更新时间（ISO-8601）。 */
	updatedAt: string;
}

export interface BeliefGraph {
	projectId: string;
	nodes: Record<string, BeliefNode>;
	/** 实体查找索引：支持裸 ID 或 `<kind>:<id>` 精确解析到节点 ID。 */
	index: Record<string, string>;
	updatedAt: string;
}

export interface BeliefPropagationEvent {
	/** 触发事件的目标节点 ID（支持节点 ID、factId、intentId 或 hypothesisId）。 */
	nodeId: string;
	/** 观测事件或类型。 */
	observation: BeliefObservationType | BeliefObservation;
	/** 沿图拓扑每跳传播衰减因子（默认 0.7，钳制在 (0.05, 0.98)）。 */
	decayFactor?: number;
	/** 最大拓扑传播深度（默认 8）。 */
	maxDepth?: number;
	/** 低收益自动剪枝阈值（默认 0.2）。 */
	pruneThreshold?: number;
	/** 是否同步将剪枝命中的下游 `open` 意图在 `state.intents` 中置为 `blocked`（默认 false 仅返回清单）。 */
	applyToState?: boolean;
	/** 事件补充原因（如 ".js.map 源码泄露"、"获取 admin 凭据"、"双盲复验驳回"）。 */
	reason?: string;
}

export interface RankedFrontierItem {
	intent: Intent;
	nodeId: string;
	/** Beta 后验信念均值 posterior ∈ (0, 1)。 */
	beliefScore: number;
	/** 预期信息增益 VoI >= 0。 */
	voiScore: number;
	/** 节点效用得分 utilityScore >= 0。 */
	utilityScore: number;
	/** UCB1 探索加成项 >= 0。 */
	ucbScore: number;
	/** 原始意图优先级归一化分 [0, 1]。 */
	priorityScore: number;
	/** 叠加信念、VoI、效用、优先级与 UCB1 后的综合排序得分。 */
	compositeScore: number;
	/** 节点是否已处于剪枝态。 */
	pruned: boolean;
	/** 简体中文可解释评分依据。 */
	explanation: string;
}

export interface BeliefPropagationResult {
	triggerNodeId: string;
	observationType: BeliefObservationType;
	isBreakthrough: boolean;
	updatedNodeIds: string[];
	boostedNodeIds: string[];
	prunedNodeIds: string[];
	/** 下游被剪枝且在 `state.intents` 中仍处于 `open` 状态的可阻塞意图 ID 清单。 */
	blockableOpenIntentIds: string[];
	/** 传播后触发重排的最新前沿排序结果。 */
	rerankedFrontier: RankedFrontierItem[];
}

export interface PruneSubtreeOptions {
	/** 若指定则仅针对该根节点及其可达下游子树扫描剪枝；未指定则全图扫描。 */
	rootNodeId?: string;
	/** 可选多根种子节点列表（如 WAF 同路径前缀关联节点集），将对所有根的可达子图扫描剪枝。 */
	seedNodeIds?: readonly string[];
	/** 自定义剪枝原因文案。 */
	reason?: string;
	/** 是否同步将命中的 `state.intents` 中 `open` 意图直接置为 `blocked`。 */
	applyToState?: boolean;
}

export interface PruneSubtreeResult {
	threshold: number;
	prunedNodeIds: string[];
	/** 被剪枝子树中对应 `state.intents` 里 `status === "open"` 的未执行意图 ID 列表。 */
	blockableOpenIntentIds: string[];
	blockableOpenIntents: Intent[];
}

export interface RankFrontierOptions {
	/** 复用已有信念图（未提供时基于 state 自动同步生成）。 */
	graph?: BeliefGraph;
	/** UCB1 探索系数（默认 0.25）。 */
	ucbExplorationConstant?: number;
	/** 是否直接从返回列表中剔除已标记 `pruned` 的意图（默认 false：保留并以极低分垫底）。 */
	excludePruned?: boolean;
	/** 返回结果条数上限（默认不截断全部返回）。 */
	limit?: number;
	/** 权重配置（可选覆盖默认融合比例）。 */
	weights?: {
		priority?: number;
		belief?: number;
		voi?: number;
		utility?: number;
		ucb?: number;
	};
}

export interface PivotDirection {
	intentId: string;
	nodeId: string;
	title: string;
	phase: Phase;
	surfaceDomain?: SurfaceDomain;
	beliefScore: number;
	voiScore: number;
	utilityScore: number;
	compositeScore: number;
	rationale: string;
}

export interface PruneSuggestion {
	nodeId: string;
	title: string;
	posterior: number;
	intentIds: string[];
	reason: string;
}

export interface SearchPivotOptions {
	pruneThreshold?: number;
	sealThreshold?: number;
	noveltyStallThreshold?: number;
}

export interface SearchPivotRecommendation {
	action:
		| "explore_high_voi"
		| "verify_candidates"
		| "pivot_surface"
		| "prune_and_converge"
		| "seal_negative";
	topDirection: PivotDirection | null;
	alternativeDirections: PivotDirection[];
	pruneSuggestions: PruneSuggestion[];
	/** 搜索收敛程度 [0, 1]。 */
	convergenceConfidence: number;
	/** 负向封盘（`sealed_negative`）置信度 [0, 1]，存在已确认漏洞时恒为 0。 */
	negativeSealConfidence: number;
	/** 是否达到建议执行 `sealEngagement` 负向封盘的条件。 */
	recommendSeal: boolean;
	/** 可直接传给 `sealEngagement` 的中文封盘原因（当 recommendSeal 为 true 时提供）。 */
	sealReason?: string;
	/** 已排除攻击面列表（供 `SealMeta.excludedSurface` 衔接）。 */
	excludedSurface: string[];
	/** 简体中文全局策略建议摘要。 */
	summary: string;
}

const OBSERVATION_DELTAS: Record<BeliefObservationType, { dAlpha: number; dBeta: number }> = {
	confirmed_hit: { dAlpha: 4.5, dBeta: 0 },
	breakthrough_signal: { dAlpha: 6.5, dBeta: 0 },
	partial_signal: { dAlpha: 1.5, dBeta: 0.25 },
	timeout: { dAlpha: 0, dBeta: 0.8 },
	soft404_miss: { dAlpha: 0, dBeta: 2.5 },
	waf_block: { dAlpha: 0, dBeta: 7.5 },
	verifier_reject: { dAlpha: 0, dBeta: 10.0 },
};

const BREAKTHROUGH_FACT_RE =
	/(?:\.js\.map\b|sourcemap|sourceMappingURL|\bcred\b|bearer\b|jwt\b|bola\b|bfla\b|idor\b|ssrf\b|越权|源码映射|凭据|未授权访问)/i;
const SOURCEMAP_SIGNAL_RE = /(?:\.js\.map\b|sourcemap|sourceMappingURL|源码映射|源码泄露|whitebox|greybox)/i;
const CRED_AUTH_SIGNAL_RE = /(?:\bcred\b|session|cookie|bearer|jwt|token|role|login|auth|凭据|会话|登录|角色)/i;
const PRIV_EXPLOIT_SIGNAL_RE = /(?:\bbola\b|\bbfla\b|\bidor\b|越权|未授权|ssrf|rce|sqli|traversal|lfi)/i;

const SOURCEMAP_CHAIN_TARGET_RE =
	/(?:js|map|bundle|route|api|admin|internal|export|graphql|sink|whitebox|greybox|vuln|exploit|源码|路由|导出|管理)/i;
const CRED_CHAIN_TARGET_RE =
	/(?:auth|idor|bola|bfla|admin|role|priv|user|order|account|profile|dashboard|api|鉴权|越权|角色|管理|订单)/i;
const EXPLOIT_CHAIN_TARGET_RE =
	/(?:exploit|post|pivot|internal|loot|flag|admin|ssrf|chain|纵深|内网|跳板|提权|利用)/i;

function nowIso(): string {
	return new Date().toISOString();
}

function clamp(value: number, min: number, max: number): number {
	if (Number.isNaN(value)) return min;
	if (value === Number.POSITIVE_INFINITY) return max;
	if (value === Number.NEGATIVE_INFINITY) return min;
	return Math.max(min, Math.min(max, value));
}

function sanitizeBetaParam(raw: number, fallback = 1.0): number {
	if (typeof raw !== "number" || Number.isNaN(raw)) {
		return clamp(fallback, MIN_BETA_PARAM, MAX_BETA_PARAM);
	}
	if (raw === Number.POSITIVE_INFINITY) return MAX_BETA_PARAM;
	if (raw <= 0) return MIN_BETA_PARAM;
	return clamp(raw, MIN_BETA_PARAM, MAX_BETA_PARAM);
}

function sanitizeCost(raw: number | undefined, fallback = 3.0): number {
	if (typeof raw !== "number" || !Number.isFinite(raw) || raw <= 0) {
		return Math.max(0.5, fallback);
	}
	return clamp(raw, 0.5, 1000);
}

function uniqPush(arr: string[], item: string): void {
	if (item && !arr.includes(item)) {
		arr.push(item);
	}
}

/**
 * 计算 Beta(alpha, beta) 后验均值 `alpha / (alpha + beta)`，保证数值稳定且恒处于 `(0, 1)`。
 */
export function computeBetaPosterior(alpha: number, beta: number): number {
	const a = sanitizeBetaParam(alpha);
	const b = sanitizeBetaParam(beta);
	const sum = a + b;
	if (!Number.isFinite(sum) || sum <= 0) return 0.5;
	return clamp(a / sum, MIN_BETA_PARAM / (MIN_BETA_PARAM + MAX_BETA_PARAM), 1 - MIN_BETA_PARAM / (MIN_BETA_PARAM + MAX_BETA_PARAM));
}

/**
 * 二元香农熵 $H_2(p) = -p \log_2(p) - (1-p) \log_2(1-p)$，精确归一化于 `[0, 1]`。
 * 满足：
 * - $H_2(0) = 0, H_2(1) = 0, H_2(0.5) = 1$；
 * - 在 $[0, 0.5]$ 上严格单调递增，在 $[0.5, 1]$ 上严格单调递减；
 * - 极值边界零 `NaN` 风险。
 */
export function shannonBinaryEntropy(p: number): number {
	if (typeof p !== "number" || !Number.isFinite(p)) return 0;
	if (p <= 1e-12 || p >= 1 - 1e-12) return 0;
	const h = -p * Math.log2(p) - (1 - p) * Math.log2(1 - p);
	if (!Number.isFinite(h)) return 0;
	return clamp(h, 0, 1);
}

/**
 * 计算 Beta(alpha, beta) 一步伯努利观测预期香农熵减（Expected Information Gain / Mutual Information）：
 * $\Delta H(\alpha, \beta) = H_2(p) - [p H_2(\frac{\alpha+1}{\alpha+\beta+1}) + (1-p) H_2(\frac{\alpha}{\alpha+\beta+1})]$。
 * 由香农熵严格凹性与 Jensen 不等式，恒有 $\Delta H \ge 0$。
 */
export function computeOneStepEntropyReduction(alpha: number, beta: number): number {
	const a = sanitizeBetaParam(alpha);
	const b = sanitizeBetaParam(beta);
	const n = a + b;
	const p = a / n;
	const hBefore = shannonBinaryEntropy(p);
	const pHit = (a + 1) / (n + 1);
	const pMiss = a / (n + 1);
	const expectedHAfter = p * shannonBinaryEntropy(pHit) + (1 - p) * shannonBinaryEntropy(pMiss);
	return Math.max(0, hBefore - expectedHAfter);
}

/**
 * 计算节点的综合不确定性度量 `uncertainty ∈ [0, 1]`：
 * 结合后验二元香农熵 $H_2(p)$ 与样本量认知收缩因子 $\frac{1}{\sqrt{1 + \max(0, \alpha+\beta-2)/4}}$。
 * - Beta(1, 1) 均匀无知先验下精确等于 `1.0`；
 * - 固定总样本量时，后验越偏离 0.5（越确定），不确定性严格越低；
 * - 固定后验均值时，累计观测证据越多，认知不确定性严格越低。
 */
export function computeNodeUncertainty(alpha: number, beta: number): number {
	const a = sanitizeBetaParam(alpha);
	const b = sanitizeBetaParam(beta);
	const p = computeBetaPosterior(a, b);
	const entropy = shannonBinaryEntropy(p);
	const sampleExcess = Math.max(0, a + b - 2);
	const epistemicShrink = 1 / Math.sqrt(1 + sampleExcess / 4);
	return clamp(entropy * epistemicShrink, 0, 1);
}

function inferSurfaceDomainLight(
	explicitDomain: SurfaceDomain | undefined,
	targetKey: string | undefined,
	keyOrTitle: string | undefined,
): SurfaceDomain {
	if (explicitDomain === "port" || explicitDomain === "path" || explicitDomain === "host") {
		return explicitDomain;
	}
	const tk = String(targetKey ?? "").trim();
	const kt = String(keyOrTitle ?? "").trim();
	if (/^port:/i.test(tk) || /:\d{2,5}$/.test(tk) || /\bportscan\b|\bnmap\b/i.test(kt)) {
		return "port";
	}
	if (
		/^path:|^endpoint:|^route:/i.test(tk) ||
		/https?:\/\/[^/]+\/.+/i.test(tk) ||
		tk.startsWith("/") ||
		/(?:^|:)(?:ep|dir|api|route|vuln|idor|bola|bfla):/i.test(kt)
	) {
		return "path";
	}
	return "host";
}

function estimateIntentCost(intent: Intent, hypotheses?: Record<string, HypothesisNode>): number {
	if (intent.hypothesisId && hypotheses?.[intent.hypothesisId]) {
		return sanitizeCost(hypotheses[intent.hypothesisId]!.estimatedCost, 4);
	}
	const key = String(intent.key ?? "").toLowerCase();
	if (key.includes("verify-vuln:")) return 2.5;
	switch (intent.phase) {
		case "recon":
			return 2.0;
		case "surface":
			return 2.5;
		case "vuln":
			return 4.0;
		case "exploit":
			return 5.0;
		case "post":
			return 4.5;
		case "report":
			return 1.5;
		default:
			return 3.0;
	}
}

function deriveFactPrior(fact: Fact): {
	alpha: number;
	beta: number;
	pruned: boolean;
	pruneReason?: string;
	breakthroughBoost: number;
} {
	if (fact.kind === "blocked" || fact.verifyStage === "rejected") {
		return {
			alpha: 0.5,
			beta: 6.0,
			pruned: fact.verifyStage === "rejected",
			pruneReason:
				fact.verifyStage === "rejected"
					? fact.verifyNote || "事实已被双盲复验驳回"
					: undefined,
			breakthroughBoost: 0,
		};
	}

	const blob = `${fact.title ?? ""} ${fact.detail ?? ""} ${fact.output ?? ""}`;
	const hasBreakthrough =
		fact.kind === "cred" ||
		fact.kind === "flag" ||
		(fact.kind === "vuln" && fact.verifyStage === "confirmed") ||
		BREAKTHROUGH_FACT_RE.test(blob);

	if (fact.kind === "flag" || (fact.kind === "vuln" && (fact.verifyStage === "confirmed" || fact.verified === true))) {
		return { alpha: 8.0, beta: 0.8, pruned: false, breakthroughBoost: 0.35 };
	}
	if (fact.kind === "cred" || fact.kind === "loot") {
		return { alpha: 6.5, beta: 1.0, pruned: false, breakthroughBoost: 0.3 };
	}
	if (fact.verifyStage === "candidate") {
		return { alpha: 1.6, beta: 1.4, pruned: false, breakthroughBoost: hasBreakthrough ? 0.1 : 0 };
	}
	return {
		alpha: 1.8,
		beta: 1.0,
		pruned: false,
		breakthroughBoost: SOURCEMAP_SIGNAL_RE.test(blob) ? 0.25 : 0,
	};
}

function finiteOrDefault(raw: unknown, fallback: number): number {
	return typeof raw === "number" && Number.isFinite(raw) ? raw : fallback;
}

function deriveHypothesisPrior(hyp: HypothesisNode): {
	alpha: number;
	beta: number;
	pruned: boolean;
	pruneReason?: string;
} {
	if (hyp.status === "confirmed") {
		return { alpha: 7.5, beta: 0.9, pruned: false };
	}
	if (hyp.status === "falsified" || hyp.status === "invalidated") {
		return {
			alpha: 0.4,
			beta: 6.5,
			pruned: true,
			pruneReason: hyp.note || `假设已处于 ${hyp.status} 状态`,
		};
	}
	const gainNorm = clamp(finiteOrDefault(hyp.expectedGain, 50) / 100, 0.02, 0.95);
	const alpha = 1.0 + 2.2 * gainNorm;
	const beta = 1.0 + 1.8 * (1 - gainNorm);
	return { alpha, beta, pruned: false };
}

function deriveIntentPrior(intent: Intent, state: NuwaState): {
	alpha: number;
	beta: number;
	pruned: boolean;
	pruneReason?: string;
	observations: number;
} {
	const prioNorm = clamp(finiteOrDefault(intent.priority, 50) / 100, 0, 0.98);
	const priorMean = clamp(0.18 + 0.64 * prioNorm, 0.15, 0.85);
	const pseudoTotal = 2.4;
	let alpha = pseudoTotal * priorMean;
	let beta = pseudoTotal * (1 - priorMean);
	let observations = Math.max(0, Math.floor(Number(intent.attempts) || 0));

	if (intent.status === "blocked" || intent.invalidatedReason) {
		beta += 4.8;
		observations = Math.max(1, observations);
		if (intent.invalidatedReason) {
			return {
				alpha,
				beta,
				pruned: true,
				pruneReason: intent.invalidatedReason,
				observations,
			};
		}
	} else if (intent.status === "done") {
		const producedPositive = Object.values(state.facts ?? {}).some(
			(f) => f.intent === intent.id && f.kind !== "blocked" && f.verifyStage !== "rejected",
		);
		if (producedPositive) {
			alpha += 3.5;
		} else {
			beta += 1.5;
		}
		observations = Math.max(1, observations);
	} else if (observations > 0) {
		beta += 0.85 * observations;
	}

	return { alpha, beta, pruned: false, observations };
}

function computeUtilityFromMetrics(
	posterior: number,
	expectedInfoGain: number,
	estimatedCost: number,
	breakthroughBoost: number,
	pruned: boolean,
): number {
	if (pruned) return 0;
	const p = clamp(posterior, 0, 1);
	const voi = Math.max(0, expectedInfoGain);
	const boost = Math.max(0, breakthroughBoost || 0);
	const cost = sanitizeCost(estimatedCost, 3.0);
	// 融合 Exploitation（后验命中率）与 Exploration（预期信息增益）并按代价次线性折现
	const raw = (0.55 * p + 0.45 * voi + boost) / Math.pow(cost, 0.55);
	return Number.isFinite(raw) ? Math.max(0, raw) : 0;
}

/**
 * 使用防环 BFS 统计节点未探索（未剪枝且未终结）的下游依赖子树广度。
 * 即使调用方手工构造了带环图，也通过 `visited` 集合严格保证在 $O(|V|+|E|)$ 内安全终止。
 */
function countUnexploredDependentSubtree(
	node: BeliefNode,
	state: NuwaState | undefined,
	graph?: BeliefGraph,
): number {
	let unexploredCount = 0;

	if (graph) {
		const visited = new Set<string>([node.id]);
		const queue: string[] = [...node.childIds];
		while (queue.length > 0) {
			const curId = queue.shift()!;
			if (visited.has(curId)) continue;
			visited.add(curId);
			const child = graph.nodes[curId];
			if (!child) continue;

			if (!child.pruned) {
				if (child.kind === "intent") {
					const stIntent = state?.intents?.[child.sourceId];
					if (!stIntent || stIntent.status === "open" || stIntent.status === "claimed") {
						unexploredCount += 1;
					}
				} else if (child.kind === "hypothesis") {
					const stHyp = state?.hypotheses?.[child.sourceId];
					if (!stHyp || stHyp.status === "open") {
						unexploredCount += 1;
					}
				}
			}

			for (const nextId of child.childIds) {
				if (!visited.has(nextId)) {
					queue.push(nextId);
				}
			}
		}
		return unexploredCount;
	}

	// 无显式 graph 时直接基于 state.intents / state.hypotheses 依赖关系做防环 BFS
	if (!state) return node.childIds.length;
	const visited = new Set<string>([node.id, node.sourceId]);

	const adj = new Map<string, string[]>();
	const link = (parent: string, child: string) => {
		if (!parent || !child) return;
		const list = adj.get(parent) ?? [];
		if (!list.includes(child)) list.push(child);
		adj.set(parent, list);
	};

	for (const f of Object.values(state.facts ?? {})) {
		if (f.intent) link(f.intent, f.id);
	}
	for (const h of Object.values(state.hypotheses ?? {})) {
		for (const rf of h.requiredFacts ?? []) link(rf, h.id);
	}
	for (const it of Object.values(state.intents ?? {})) {
		for (const pf of it.from ?? []) link(pf, it.id);
		if (it.hypothesisId) link(it.hypothesisId, it.id);
	}

	const queue: string[] = [...(adj.get(node.sourceId) ?? []), ...(adj.get(node.id) ?? []), ...node.childIds];
	while (queue.length > 0) {
		const cur = queue.shift()!;
		if (visited.has(cur)) continue;
		visited.add(cur);

		const it = state.intents?.[cur];
		if (it && it.status === "open" && !it.invalidatedReason) {
			unexploredCount += 1;
		} else {
			const hyp = state.hypotheses?.[cur];
			if (hyp && hyp.status === "open") {
				unexploredCount += 1;
			}
		}

		for (const nxt of adj.get(cur) ?? []) {
			if (!visited.has(nxt)) queue.push(nxt);
		}
	}

	return unexploredCount;
}

/**
 * 计算节点的预期信息增益（VoI，Value of Information）：
 * 融合节点后验不确定性熵、一步伯努利预期香农熵减（乘常数放大对齐量纲）与未探索依赖子树广度加成。
 *
 * 严格数学性质：
 * 1. 非负性：对任意合法节点与状态，恒有 `VoI >= 0`；已剪枝节点 `VoI === 0`；
 * 2. 熵单调性：固定总样本量与子树广度，后验越接近 `0.5`（不确定性越高），VoI 严格越大；
 * 3. 子树广度单调性：固定节点 `alpha, beta`，下游未探索开放依赖越多，VoI 严格越大。
 */
export function computeExpectedInfoGain(
	node: BeliefNode,
	state?: NuwaState,
	graph?: BeliefGraph,
): number {
	if (!node || node.pruned) return 0;
	const a = sanitizeBetaParam(node.alpha);
	const b = sanitizeBetaParam(node.beta);
	const uncertainty = computeNodeUncertainty(a, b);
	// Beta(1, 1) 下一步熵减约为 0.0817，乘以 8 归一化到 ~0.65 量级与 uncertainty 同阶平滑组合
	const stepEntropyGain = clamp(computeOneStepEntropyReduction(a, b) * 8.0, 0, 1);
	const baseInfoValue = 0.72 * uncertainty + 0.28 * stepEntropyGain;
	const breadth = countUnexploredDependentSubtree(node, state, graph);
	const subtreeMultiplier = 1 + 0.35 * Math.log1p(Math.max(0, breadth));
	const voi = baseInfoValue * subtreeMultiplier;
	return Number.isFinite(voi) ? Math.max(0, voi) : 0;
}

function refreshNodeDerivedMetrics(node: BeliefNode, state?: NuwaState, graph?: BeliefGraph): BeliefNode {
	node.alpha = sanitizeBetaParam(node.alpha);
	node.beta = sanitizeBetaParam(node.beta);
	node.estimatedCost = sanitizeCost(node.estimatedCost);
	node.posterior = computeBetaPosterior(node.alpha, node.beta);
	node.uncertainty = computeNodeUncertainty(node.alpha, node.beta);
	node.expectedInfoGain = node.pruned ? 0 : computeExpectedInfoGain(node, state, graph);
	node.utilityScore = computeUtilityFromMetrics(
		node.posterior,
		node.expectedInfoGain,
		node.estimatedCost,
		node.breakthroughBoost,
		node.pruned,
	);
	return node;
}

export function resolveBeliefNodeId(
	graph: BeliefGraph,
	rawRef: string,
	preferredKind?: BeliefNodeKind,
): string | undefined {
	const ref = String(rawRef ?? "").trim();
	if (!ref) return undefined;
	if (preferredKind) {
		const typed = graph.index[`${preferredKind}:${ref}`];
		if (typed && graph.nodes[typed]) return typed;
	}
	if (graph.nodes[ref]) return ref;
	const indexed = graph.index[ref];
	if (indexed && graph.nodes[indexed]) return indexed;
	return undefined;
}

function addDirectedEdge(graph: BeliefGraph, parentId: string | undefined, childId: string | undefined): void {
	if (!parentId || !childId || parentId === childId) return;
	const pNode = graph.nodes[parentId];
	const cNode = graph.nodes[childId];
	if (!pNode || !cNode) return;
	uniqPush(pNode.childIds, childId);
	uniqPush(cNode.parentIds, parentId);
}

/**
 * 从 `NuwaState`（`facts` / `hypotheses` / `intents`）确定性构建或增量同步攻击信念图 `BeliefGraph`。
 * 若提供 `existingGraph`，保留已有节点的历史贝叶斯累积计数与剪枝标记，同时合并新增拓扑边。
 */
export function initBeliefGraphFromState(state: NuwaState, existingGraph?: BeliefGraph): BeliefGraph {
	const ts = nowIso();
	const graph: BeliefGraph = {
		projectId: state?.project?.id || "nuwa-project",
		nodes: {},
		index: {},
		updatedAt: ts,
	};

	const allocateNodeId = (kind: BeliefNodeKind, sourceId: string): string => {
		const prevTyped = existingGraph?.index?.[`${kind}:${sourceId}`];
		if (prevTyped && !graph.nodes[prevTyped]) return prevTyped;
		if (!graph.nodes[sourceId]) return sourceId;
		return `${kind}:${sourceId}`;
	};

	const registerNode = (node: BeliefNode) => {
		graph.nodes[node.id] = node;
		graph.index[`${node.kind}:${node.sourceId}`] = node.id;
		if (!graph.index[node.sourceId]) {
			graph.index[node.sourceId] = node.id;
		}
	};

	// 1. 确定性导入 Fact 节点
	const facts = Object.values(state?.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	for (const f of facts) {
		const nodeId = allocateNodeId("fact", f.id);
		const prev = existingGraph?.nodes?.[nodeId];
		const prior = deriveFactPrior(f);
		const alpha = prev ? sanitizeBetaParam(Math.max(prev.alpha, prior.alpha)) : prior.alpha;
		const beta = prev
			? sanitizeBetaParam(f.verifyStage === "rejected" ? Math.max(prev.beta, prior.beta) : prev.beta)
			: prior.beta;
		const pruned = prior.pruned || Boolean(prev?.pruned);

		registerNode({
			id: nodeId,
			kind: "fact",
			sourceId: f.id,
			title: f.title || f.id,
			targetKey: f.targetKey,
			alpha,
			beta,
			posterior: computeBetaPosterior(alpha, beta),
			uncertainty: computeNodeUncertainty(alpha, beta),
			expectedInfoGain: 0,
			estimatedCost: 1.0,
			utilityScore: 0,
			pruned,
			pruneReason: prior.pruneReason ?? prev?.pruneReason,
			parentIds: prev ? [...prev.parentIds] : [],
			childIds: prev ? [...prev.childIds] : [],
			surfaceDomain: inferSurfaceDomainLight(f.surfaceDomain, f.targetKey, f.key || f.title),
			observations: prev?.observations ?? 1,
			breakthroughBoost: Math.max(prev?.breakthroughBoost ?? 0, prior.breakthroughBoost),
			updatedAt: prev?.updatedAt ?? f.createdAt ?? ts,
		});
	}

	// 2. 确定性导入 Hypothesis 节点
	const hypotheses = Object.values(state?.hypotheses ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	for (const h of hypotheses) {
		const nodeId = allocateNodeId("hypothesis", h.id);
		const prev = existingGraph?.nodes?.[nodeId];
		const prior = deriveHypothesisPrior(h);
		const alpha = prev ? sanitizeBetaParam(prev.alpha) : prior.alpha;
		const beta = prev
			? sanitizeBetaParam(prior.pruned ? Math.max(prev.beta, prior.beta) : prev.beta)
			: prior.beta;
		const pruned = prior.pruned || Boolean(prev?.pruned);

		registerNode({
			id: nodeId,
			kind: "hypothesis",
			sourceId: h.id,
			title: h.title || h.id,
			alpha,
			beta,
			posterior: computeBetaPosterior(alpha, beta),
			uncertainty: computeNodeUncertainty(alpha, beta),
			expectedInfoGain: 0,
			estimatedCost: sanitizeCost(h.estimatedCost, 4.0),
			utilityScore: 0,
			pruned,
			pruneReason: prior.pruneReason ?? prev?.pruneReason,
			parentIds: prev ? [...prev.parentIds] : [],
			childIds: prev ? [...prev.childIds] : [],
			surfaceDomain: "path",
			observations: prev?.observations ?? 0,
			breakthroughBoost: prev?.breakthroughBoost ?? 0,
			updatedAt: h.updatedAt || prev?.updatedAt || ts,
		});
	}

	// 3. 确定性导入 Intent 节点
	const intents = Object.values(state?.intents ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	for (const it of intents) {
		const nodeId = allocateNodeId("intent", it.id);
		const prev = existingGraph?.nodes?.[nodeId];
		const prior = deriveIntentPrior(it, state);
		const alpha = prev ? sanitizeBetaParam(prev.alpha) : prior.alpha;
		const beta = prev
			? sanitizeBetaParam(prior.pruned ? Math.max(prev.beta, prior.beta) : prev.beta)
			: prior.beta;
		const pruned = prior.pruned || Boolean(prev?.pruned);

		registerNode({
			id: nodeId,
			kind: "intent",
			sourceId: it.id,
			title: it.title || it.key || it.id,
			phase: it.phase,
			targetKey: it.targetKey,
			alpha,
			beta,
			posterior: computeBetaPosterior(alpha, beta),
			uncertainty: computeNodeUncertainty(alpha, beta),
			expectedInfoGain: 0,
			estimatedCost: prev?.estimatedCost ?? estimateIntentCost(it, state?.hypotheses),
			utilityScore: 0,
			pruned,
			pruneReason: prior.pruneReason ?? prev?.pruneReason,
			parentIds: prev ? [...prev.parentIds] : [],
			childIds: prev ? [...prev.childIds] : [],
			surfaceDomain: inferSurfaceDomainLight(it.surfaceDomain, it.targetKey, it.key || it.title),
			observations: Math.max(prev?.observations ?? 0, prior.observations),
			breakthroughBoost: prev?.breakthroughBoost ?? 0,
			updatedAt: prev?.updatedAt ?? it.createdAt ?? ts,
		});
	}

	// 4. 构建有向因果与依赖边（Intent -> 产出 Fact -> Hypothesis / 下游 Intent）
	for (const f of facts) {
		const fNodeId = resolveBeliefNodeId(graph, f.id, "fact");
		if (f.intent) {
			const iNodeId = resolveBeliefNodeId(graph, f.intent, "intent");
			addDirectedEdge(graph, iNodeId, fNodeId);
		}
	}

	for (const h of hypotheses) {
		const hNodeId = resolveBeliefNodeId(graph, h.id, "hypothesis");
		for (const reqFid of h.requiredFacts ?? []) {
			const fNodeId = resolveBeliefNodeId(graph, reqFid, "fact");
			addDirectedEdge(graph, fNodeId, hNodeId);
		}
		for (const linkedIid of h.linkedIntents ?? []) {
			const iNodeId = resolveBeliefNodeId(graph, linkedIid, "intent");
			addDirectedEdge(graph, hNodeId, iNodeId);
		}
	}

	for (const it of intents) {
		const iNodeId = resolveBeliefNodeId(graph, it.id, "intent");
		for (const fromId of it.from ?? []) {
			const parentNodeId =
				resolveBeliefNodeId(graph, fromId, "fact") ?? resolveBeliefNodeId(graph, fromId);
			addDirectedEdge(graph, parentNodeId, iNodeId);
		}
		if (it.hypothesisId) {
			const hNodeId = resolveBeliefNodeId(graph, it.hypothesisId, "hypothesis");
			addDirectedEdge(graph, hNodeId, iNodeId);
		}
	}

	// 清理可能失效的历史悬挂引用并重算全图 VoI 与效用得分
	for (const node of Object.values(graph.nodes)) {
		node.parentIds = node.parentIds.filter((id) => Boolean(graph.nodes[id]) && id !== node.id);
		node.childIds = node.childIds.filter((id) => Boolean(graph.nodes[id]) && id !== node.id);
	}
	for (const node of Object.values(graph.nodes)) {
		refreshNodeDerivedMetrics(node, state, graph);
	}

	return graph;
}

function normalizeObservation(observation: BeliefObservationType | BeliefObservation): {
	type: BeliefObservationType;
	weight: number;
	note?: string;
	at: string;
} {
	if (typeof observation === "string") {
		if (!VALID_BELIEF_OBSERVATIONS.has(observation)) {
			throw new Error(`非法信念观测类型: ${JSON.stringify(observation)}`);
		}
		return { type: observation, weight: 1.0, at: nowIso() };
	}
	if (!observation || typeof observation !== "object" || !VALID_BELIEF_OBSERVATIONS.has(observation.type)) {
		throw new Error(`非法信念观测载荷: ${JSON.stringify(observation)}`);
	}
	const rawW = observation.weight ?? 1.0;
	if (typeof rawW !== "number" || Number.isNaN(rawW) || rawW <= 0) {
		throw new Error(`观测权重必须为正数，收到: ${String(rawW)}`);
	}
	return {
		type: observation.type,
		weight: clamp(rawW, 0.05, 10),
		note: observation.note,
		at: observation.at || nowIso(),
	};
}

/**
 * 对指定 `BeliefNode` 应用单步贝叶斯 Beta 共轭后验更新，并同步刷新 `posterior`、`uncertainty`、
 * `expectedInfoGain` 与 `utilityScore`（原地更新并返回同一节点引用，兼具函数式与命令式可用性）。
 */
export function updateBeliefPosterior(
	node: BeliefNode,
	observation: BeliefObservationType | BeliefObservation,
	state?: NuwaState,
	graph?: BeliefGraph,
): BeliefNode {
	if (!node || typeof node !== "object") {
		throw new Error("updateBeliefPosterior 需要有效的 BeliefNode 对象");
	}
	const obs = normalizeObservation(observation);
	const delta = OBSERVATION_DELTAS[obs.type];

	node.alpha = sanitizeBetaParam(node.alpha + delta.dAlpha * obs.weight);
	node.beta = sanitizeBetaParam(node.beta + delta.dBeta * obs.weight);
	node.observations = Math.max(0, Math.floor(node.observations || 0)) + 1;

	if (obs.type === "breakthrough_signal") {
		node.breakthroughBoost = clamp((node.breakthroughBoost || 0) + 0.35 * obs.weight, 0, 1.5);
	} else if (obs.type === "confirmed_hit") {
		node.breakthroughBoost = clamp((node.breakthroughBoost || 0) + 0.15 * obs.weight, 0, 1.5);
	} else if (obs.type === "verifier_reject" || obs.type === "waf_block") {
		node.breakthroughBoost = Math.max(0, (node.breakthroughBoost || 0) * 0.2);
	}

	node.updatedAt = obs.at;
	return refreshNodeDerivedMetrics(node, state, graph);
}

/**
 * 扫描并剪枝低收益节点及其依赖子树：
 * - 当某节点后验 `posterior < threshold`（默认 `0.2`）或已被证伪剪枝时，沿下游 `childIds` 执行单调不动点传播；
 * - 若下游节点的后验同样低于阈值，或其所有上游前置节点均已被剪枝（完美覆盖菱形 DAG 多父节点汇合），自动标记 `pruned = true`；
 * - 即使存在有向环，每个节点最多加入 `prunedSet` 一次，严格保证在 $O(|V|+|E|)$ 内安全终止；
 * - 精准返回可阻塞的下游未执行 `open` 意图清单（严禁触碰 `done`、`claimed`、已 `blocked` 或无关意图）。
 */
export function pruneLowYieldSubtree(
	graph: BeliefGraph,
	state: NuwaState,
	threshold: number = DEFAULT_PRUNE_THRESHOLD,
	opts?: PruneSubtreeOptions,
): PruneSubtreeResult {
	const effThreshold = clamp(
		typeof threshold === "number" && Number.isFinite(threshold) ? threshold : DEFAULT_PRUNE_THRESHOLD,
		0.01,
		0.95,
	);
	const ts = nowIso();

	// 1. 解析扫描子图范围：指定 rootNodeId / seedNodeIds 时防环收集全部可达子图节点，未指定时扫描全图
	const rawRoots: string[] = [];
	if (opts?.rootNodeId) rawRoots.push(opts.rootNodeId);
	if (Array.isArray(opts?.seedNodeIds)) {
		for (const sid of opts.seedNodeIds) {
			if (sid) rawRoots.push(sid);
		}
	}

	let scopeNodes: BeliefNode[];
	if (rawRoots.length > 0) {
		const subVisited = new Set<string>();
		const subQueue: string[] = [];
		for (const raw of rawRoots) {
			const resolved = resolveBeliefNodeId(graph, raw);
			if (resolved && graph.nodes[resolved] && !subVisited.has(resolved)) {
				subVisited.add(resolved);
				subQueue.push(resolved);
			}
		}
		scopeNodes = [];
		while (subQueue.length > 0) {
			const nid = subQueue.shift()!;
			const n = graph.nodes[nid];
			if (!n) continue;
			scopeNodes.push(n);
			for (const cid of n.childIds) {
				if (graph.nodes[cid] && !subVisited.has(cid)) {
					subVisited.add(cid);
					subQueue.push(cid);
				}
			}
		}
		scopeNodes.sort((a, b) => a.id.localeCompare(b.id));
	} else {
		scopeNodes = Object.values(graph.nodes).sort((a, b) => a.id.localeCompare(b.id));
	}

	// 2. 单调不动点级联剪枝：仅在节点确认剪枝加入 prunedSet 时扩散其 childIds，彻底消除多父节点先后顺序漏剪
	const prunedSet = new Set<string>();
	const inQueue = new Set<string>();
	const queue: BeliefNode[] = [];

	const enqueueNode = (n: BeliefNode | undefined) => {
		if (!n || prunedSet.has(n.id) || inQueue.has(n.id)) return;
		inQueue.add(n.id);
		queue.push(n);
	};

	for (const n of scopeNodes) {
		const allParentsPruned =
			n.parentIds.length > 0 && n.parentIds.every((pid) => Boolean(graph.nodes[pid]?.pruned));
		if (n.pruned || n.posterior < effThreshold || allParentsPruned) {
			enqueueNode(n);
		}
	}

	while (queue.length > 0) {
		const cur = queue.shift()!;
		inQueue.delete(cur.id);
		if (prunedSet.has(cur.id)) continue;

		const allParentsPruned =
			cur.parentIds.length > 0 && cur.parentIds.every((pid) => Boolean(graph.nodes[pid]?.pruned));
		const shouldPrune = cur.pruned || cur.posterior < effThreshold || allParentsPruned;
		if (!shouldPrune) continue;

		cur.pruned = true;
		if (!cur.pruneReason) {
			cur.pruneReason =
				opts?.reason ||
				(allParentsPruned && cur.posterior >= effThreshold
					? `上游前置节点已全部剪枝失效 (posterior=${cur.posterior.toFixed(3)})`
					: `信念后验低于剪枝阈值 (${cur.posterior.toFixed(3)} < ${effThreshold.toFixed(3)})`);
		}
		cur.expectedInfoGain = 0;
		cur.utilityScore = 0;
		cur.updatedAt = ts;
		prunedSet.add(cur.id);

		for (const cid of cur.childIds) {
			enqueueNode(graph.nodes[cid]);
		}
	}

	// 刷新未剪枝父节点的子树广度 VoI
	for (const node of Object.values(graph.nodes)) {
		if (!node.pruned) {
			refreshNodeDerivedMetrics(node, state, graph);
		}
	}

	const blockableOpenIntents: Intent[] = [];
	for (const nid of [...prunedSet].sort((a, b) => a.localeCompare(b))) {
		const node = graph.nodes[nid];
		if (!node || node.kind !== "intent") continue;
		const stIntent = state?.intents?.[node.sourceId];
		if (!stIntent || stIntent.status !== "open") continue;
		blockableOpenIntents.push(stIntent);

		if (opts?.applyToState) {
			stIntent.status = "blocked";
			stIntent.invalidatedReason = node.pruneReason || "低收益攻击子树自动剪枝";
			stIntent.note = `信念剪枝: ${stIntent.invalidatedReason}`;
			stIntent.doneAt = ts;
		}
	}

	blockableOpenIntents.sort((a, b) => a.id.localeCompare(b.id));
	graph.updatedAt = ts;

	return {
		threshold: effThreshold,
		prunedNodeIds: [...prunedSet].sort((a, b) => a.localeCompare(b)),
		blockableOpenIntentIds: blockableOpenIntents.map((i) => i.id),
		blockableOpenIntents,
	};
}

function isBreakthroughEvent(
	obsType: BeliefObservationType,
	triggerNode: BeliefNode,
	state: NuwaState,
	reason?: string,
): boolean {
	if (obsType === "breakthrough_signal") return true;
	if (obsType !== "confirmed_hit") return false;
	const fact = triggerNode.kind === "fact" ? state?.facts?.[triggerNode.sourceId] : undefined;
	if (fact && (fact.kind === "cred" || fact.kind === "flag" || fact.kind === "vuln" || fact.kind === "loot")) {
		return true;
	}
	const text = `${triggerNode.title} ${reason ?? ""} ${fact?.detail ?? ""}`;
	return BREAKTHROUGH_FACT_RE.test(text);
}

function matchesBreakthroughAssociation(
	signalBlob: string,
	candidate: BeliefNode,
	state: NuwaState,
): boolean {
	if (candidate.pruned) return false;
	const intent = candidate.kind === "intent" ? state?.intents?.[candidate.sourceId] : undefined;
	if (intent && intent.status !== "open" && intent.status !== "claimed") return false;
	const candBlob = `${candidate.title} ${candidate.targetKey ?? ""} ${intent?.key ?? ""} ${intent?.detail ?? ""}`;

	if (SOURCEMAP_SIGNAL_RE.test(signalBlob) && SOURCEMAP_CHAIN_TARGET_RE.test(candBlob)) {
		return true;
	}
	if (CRED_AUTH_SIGNAL_RE.test(signalBlob) && ( Boolean(intent?.authRole) || CRED_CHAIN_TARGET_RE.test(candBlob) )) {
		return true;
	}
	if (PRIV_EXPLOIT_SIGNAL_RE.test(signalBlob) && EXPLOIT_CHAIN_TARGET_RE.test(candBlob)) {
		return true;
	}
	return false;
}

/**
 * 在信念状态图上沿拓扑传播观测事件：
 * - 当遇到 `waf_block` 或 `verifier_reject`（或 `soft404_miss`）时，以衰减因子 $\gamma^d$ 级联下调
 *   整棵下游依赖子树（及同表面分域同路径前缀的未执行子节点）信念，自动剪枝低于阈值的节点并返回
 *   可阻塞的下游 `open` 意图清单；
 * - 当出现 `breakthrough_signal` 或关键跃迁命中（`.js.map` 源码泄露、获取 `cred`、越权实锤）时，
 *   瞬时提升下游子树与关联攻击链节点的先验 `alpha` 与 `breakthroughBoost`，并立即触发全局前沿重排。
 */
export function propagateBeliefUpdate(
	graph: BeliefGraph,
	state: NuwaState,
	event: BeliefPropagationEvent,
): BeliefPropagationResult {
	const resolvedId = resolveBeliefNodeId(graph, event.nodeId);
	if (!resolvedId || !graph.nodes[resolvedId]) {
		throw new Error(`信念图中未找到目标节点: ${JSON.stringify(event.nodeId)}`);
	}

	const obs = normalizeObservation(event.observation);
	const decay = clamp(
		typeof event.decayFactor === "number" && Number.isFinite(event.decayFactor)
			? event.decayFactor
			: DEFAULT_PROPAGATION_DECAY,
		0.05,
		0.98,
	);
	const maxDepth = Math.max(1, Math.min(32, Math.floor(event.maxDepth ?? 8)));
	const pruneThreshold = event.pruneThreshold ?? DEFAULT_PRUNE_THRESHOLD;
	const triggerNode = graph.nodes[resolvedId]!;
	const ts = obs.at;

	updateBeliefPosterior(triggerNode, obs, state, graph);
	const updatedSet = new Set<string>([triggerNode.id]);
	const boostedSet = new Set<string>();

	const isNegativeHard = obs.type === "waf_block" || obs.type === "verifier_reject";
	const isNegativeSoft = obs.type === "soft404_miss" || obs.type === "timeout";
	const breakthrough = isBreakthroughEvent(obs.type, triggerNode, state, event.reason ?? obs.note);

	if (obs.type === "verifier_reject") {
		triggerNode.pruned = true;
		triggerNode.pruneReason = event.reason || obs.note || "双盲独立复验证伪驳回";
	} else if (obs.type === "waf_block" && triggerNode.posterior < pruneThreshold) {
		triggerNode.pruned = true;
		triggerNode.pruneReason = event.reason || obs.note || "WAF/边缘策略硬阻断";
	}

	// 1. 沿有向拓扑 childIds 执行带衰减因子的防环层序 BFS 传播
	const visited = new Set<string>([triggerNode.id]);
	const queue: Array<{ id: string; depth: number }> = triggerNode.childIds.map((cid) => ({
		id: cid,
		depth: 1,
	}));

	// 若为 WAF 路径分域硬拦截，同时将同 surfaceDomain 且共享受阻路径前缀的 open 意图纳入 1 跳传播（严守跨分域隔离）
	if (obs.type === "waf_block" && triggerNode.surfaceDomain && triggerNode.targetKey) {
		const blockedPrefix = triggerNode.targetKey.replace(/\/+$/, "");
		if (blockedPrefix.length >= 4) {
			for (const peer of Object.values(graph.nodes)) {
				if (peer.id === triggerNode.id || visited.has(peer.id)) continue;
				if (peer.surfaceDomain !== triggerNode.surfaceDomain) continue;
				if (
					peer.targetKey &&
					(peer.targetKey === blockedPrefix || peer.targetKey.startsWith(`${blockedPrefix}/`))
				) {
					queue.push({ id: peer.id, depth: 1 });
				}
			}
		}
	}

	while (queue.length > 0) {
		const { id: curId, depth } = queue.shift()!;
		if (visited.has(curId) || depth > maxDepth) continue;
		visited.add(curId);

		const curNode = graph.nodes[curId];
		if (!curNode) continue;

		const factor = Math.pow(decay, depth);
		if (factor < 0.02) continue;

		if (isNegativeHard || isNegativeSoft) {
			// 对 verifier_reject 的直接依赖子节点施加更强证伪惩罚，确保无效前提下游可靠收敛低于剪枝阈值
			const extraMultiplier = obs.type === "verifier_reject" && depth === 1 ? 1.8 : 1.0;
			const effWeight = clamp(obs.weight * factor * extraMultiplier, 0.05, 10);
			updateBeliefPosterior(curNode, { type: obs.type, weight: effWeight, at: ts }, state, graph);
			updatedSet.add(curNode.id);
		} else {
			const effWeight = clamp(obs.weight * factor, 0.05, 10);
			updateBeliefPosterior(curNode, { type: obs.type, weight: effWeight, at: ts }, state, graph);
			if (breakthrough) {
				curNode.breakthroughBoost = clamp(
					(curNode.breakthroughBoost || 0) + 0.3 * factor * obs.weight,
					0,
					1.5,
				);
				boostedSet.add(curNode.id);
			}
			updatedSet.add(curNode.id);
		}

		for (const nextId of curNode.childIds) {
			if (!visited.has(nextId)) {
				queue.push({ id: nextId, depth: depth + 1 });
			}
		}
	}

	// 2. 关键跃迁信号跨图关联攻击链瞬时提权（即使尚未建立显式 from 边也能感知全局跃迁线索）
	if (breakthrough) {
		const triggerFact = triggerNode.kind === "fact" ? state?.facts?.[triggerNode.sourceId] : undefined;
		const signalBlob = [
			triggerNode.title,
			event.reason ?? "",
			obs.note ?? "",
			triggerFact?.kind ?? "",
			triggerFact?.detail ?? "",
		].join(" ");

		for (const cand of Object.values(graph.nodes).sort((a, b) => a.id.localeCompare(b.id))) {
			if (cand.id === triggerNode.id || boostedSet.has(cand.id)) continue;
			if (!matchesBreakthroughAssociation(signalBlob, cand, state)) continue;

			cand.alpha = sanitizeBetaParam(cand.alpha + 3.6 * obs.weight);
			cand.breakthroughBoost = clamp((cand.breakthroughBoost || 0) + 0.35 * obs.weight, 0, 1.5);
			cand.updatedAt = ts;
			updatedSet.add(cand.id);
			boostedSet.add(cand.id);
		}
	}

	// 3. 负向传播后执行低收益子树自动剪枝，正向传播后全图刷新 VoI 与效用
	let prunedNodeIds: string[] = [];
	let blockableOpenIntentIds: string[] = [];

	if (isNegativeHard || isNegativeSoft) {
		const pruneRes = pruneLowYieldSubtree(graph, state, pruneThreshold, {
			seedNodeIds: [...updatedSet],
			reason: event.reason || obs.note,
			applyToState: event.applyToState,
		});
		prunedNodeIds = pruneRes.prunedNodeIds;
		blockableOpenIntentIds = pruneRes.blockableOpenIntentIds;
	}

	for (const node of Object.values(graph.nodes)) {
		refreshNodeDerivedMetrics(node, state, graph);
	}
	graph.updatedAt = ts;

	const rerankedFrontier = rankFrontierByBelief(state, undefined, { graph });

	return {
		triggerNodeId: triggerNode.id,
		observationType: obs.type,
		isBreakthrough: breakthrough,
		updatedNodeIds: [...updatedSet].sort((a, b) => a.localeCompare(b)),
		boostedNodeIds: [...boostedSet].sort((a, b) => a.localeCompare(b)),
		prunedNodeIds,
		blockableOpenIntentIds,
		rerankedFrontier,
	};
}

function extractIntentListFromInput(
	state: NuwaState,
	intents?: ReadonlyArray<Intent | FrontierItem>,
): Intent[] {
	if (Array.isArray(intents)) {
		const out: Intent[] = [];
		for (const item of intents) {
			if (!item) continue;
			if ("intent" in item && item.intent) {
				out.push(item.intent);
			} else {
				out.push(item as Intent);
			}
		}
		return out;
	}

	// 未显式传入列表时默认抽取 state 中可调度的 open 前沿意图
	return Object.values(state?.intents ?? {})
		.filter((it) => {
			if (!it || it.status !== "open") return false;
			const missing = (it.from ?? []).some((fid) => !state.facts?.[fid]);
			return !missing;
		})
		.sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * 基于信念后验（Exploitation）、预期信息增益（VoI）、单位代价效用、既有优先级与 UCB1 探索项对前沿意图做综合排序。
 */
export function rankFrontierByBelief(
	state: NuwaState,
	intents?: ReadonlyArray<Intent | FrontierItem>,
	opts?: RankFrontierOptions,
): RankedFrontierItem[] {
	const graph = opts?.graph ?? initBeliefGraphFromState(state);
	const list = extractIntentListFromInput(state, intents);
	if (list.length === 0) return [];

	const ucbC = clamp(
		typeof opts?.ucbExplorationConstant === "number" && Number.isFinite(opts.ucbExplorationConstant)
			? opts.ucbExplorationConstant
			: 0.25,
		0,
		2.0,
	);

	const wPriority = opts?.weights?.priority ?? 0.24;
	const wBelief = opts?.weights?.belief ?? 0.30;
	const wVoi = opts?.weights?.voi ?? 0.20;
	const wUtility = opts?.weights?.utility ?? 0.16;
	const wUcb = opts?.weights?.ucb ?? 0.10;

	const totalVisits = Math.max(
		1,
		Object.values(state?.facts ?? {}).length +
			Object.values(state?.intents ?? {}).reduce((acc, it) => acc + Math.max(0, it.attempts || 0), 0),
	);

	const ranked: RankedFrontierItem[] = [];

	for (const intent of list) {
		const nodeId = resolveBeliefNodeId(graph, intent.id, "intent") ?? intent.id;
		let node = graph.nodes[nodeId];
		if (!node) {
			const prior = deriveIntentPrior(intent, state);
			node = {
				id: intent.id,
				kind: "intent",
				sourceId: intent.id,
				title: intent.title || intent.key || intent.id,
				phase: intent.phase,
				targetKey: intent.targetKey,
				alpha: prior.alpha,
				beta: prior.beta,
				posterior: computeBetaPosterior(prior.alpha, prior.beta),
				uncertainty: computeNodeUncertainty(prior.alpha, prior.beta),
				expectedInfoGain: 0,
				estimatedCost: estimateIntentCost(intent, state?.hypotheses),
				utilityScore: 0,
				pruned: prior.pruned,
				pruneReason: prior.pruneReason,
				parentIds: [...(intent.from ?? [])],
				childIds: [],
				surfaceDomain: inferSurfaceDomainLight(
					intent.surfaceDomain,
					intent.targetKey,
					intent.key || intent.title,
				),
				observations: prior.observations,
				breakthroughBoost: 0,
				updatedAt: intent.createdAt || nowIso(),
			};
			refreshNodeDerivedMetrics(node, state, graph);
		}

		if (opts?.excludePruned && node.pruned) {
			continue;
		}

		const rawPriority = finiteOrDefault(intent.priority, 50);
		const priorityScore = clamp(rawPriority / 100, 0, 1);
		const beliefScore = node.posterior;
		const voiScore = node.expectedInfoGain;
		const utilityScore = node.utilityScore;
		const visits = Math.max(0, (intent.attempts || 0) + (node.observations || 0));
		const ucbScore = node.pruned ? 0 : ucbC * Math.sqrt(Math.log(totalVisits + 1) / (visits + 1));

		const voiNorm = voiScore / (1 + voiScore);
		const utilNorm = utilityScore / (1 + utilityScore);
		const isVerifyVuln = /(?:^|:)verify-vuln:/i.test(intent.key ?? "");
		const verifyBonus = isVerifyVuln && !node.pruned ? 0.18 : 0;
		const breakthroughBonus = !node.pruned ? clamp(node.breakthroughBoost || 0, 0, 0.6) : 0;

		let compositeScore =
			100 *
			(wPriority * priorityScore +
				wBelief * beliefScore +
				wVoi * voiNorm +
				wUtility * utilNorm +
				wUcb * clamp(ucbScore, 0, 1) +
				verifyBonus +
				breakthroughBonus);

		if (node.pruned) {
			// 已剪枝节点压入 [0, 4.99] 垫底区间，确保所有有效未剪枝方向严格排在前面
			compositeScore = clamp(compositeScore * 0.04, 0, 4.99);
		}

		const tags: string[] = [];
		if (node.pruned) {
			tags.push(`已剪枝: ${node.pruneReason || "低收益子树"}`);
		} else {
			if (isVerifyVuln) tags.push("双盲复验优先");
			if ((node.breakthroughBoost || 0) > 0.05) {
				tags.push(`跃迁信号加成(+${(node.breakthroughBoost || 0).toFixed(2)})`);
			}
			if (voiScore >= 0.55) tags.push("高信息增益探索");
		}

		const explanation =
			`综合=${compositeScore.toFixed(2)} (后验=${beliefScore.toFixed(3)}, VoI=${voiScore.toFixed(3)}, ` +
			`效用=${utilityScore.toFixed(3)}, 优先级=${intent.priority}, UCB=${ucbScore.toFixed(3)})` +
			(tags.length > 0 ? ` [${tags.join(" | ")}]` : "");

		ranked.push({
			intent,
			nodeId: node.id,
			beliefScore,
			voiScore,
			utilityScore,
			ucbScore,
			priorityScore,
			compositeScore,
			pruned: node.pruned,
			explanation,
		});
	}

	ranked.sort(
		(a, b) =>
			Number(a.pruned) - Number(b.pruned) ||
			b.compositeScore - a.compositeScore ||
			b.utilityScore - a.utilityScore ||
			a.intent.id.localeCompare(b.intent.id),
	);

	if (typeof opts?.limit === "number" && Number.isFinite(opts.limit) && opts.limit > 0) {
		return ranked.slice(0, Math.floor(opts.limit));
	}
	return ranked;
}

function hasConfirmedPositiveFinding(state: NuwaState): boolean {
	const proofSet = new Set<FactKind>(["flag", "vuln", "loot"]);
	for (const f of Object.values(state?.facts ?? {})) {
		if (!f || !proofSet.has(f.kind)) continue;
		if (f.verifyStage === "candidate" || f.verifyStage === "rejected") continue;
		return true;
	}
	return false;
}

/**
 * 综合当前信念图状态与运行态停滞指标，输出下一步最高 VoI 探索转向、低收益剪枝建议
 * 以及收敛 / 负向封盘（`sealed_negative`）置信度评估。
 */
export function recommendSearchPivot(
	state: NuwaState,
	graph?: BeliefGraph,
	opts?: SearchPivotOptions,
): SearchPivotRecommendation {
	const g = graph ?? initBeliefGraphFromState(state);
	const pruneThreshold = opts?.pruneThreshold ?? DEFAULT_PRUNE_THRESHOLD;
	const sealThreshold = opts?.sealThreshold ?? DEFAULT_NEGATIVE_SEAL_THRESHOLD;
	const stallThreshold = Math.max(1, opts?.noveltyStallThreshold ?? 8);

	const candidateFacts = Object.values(state?.facts ?? {})
		.filter((f) => f && f.verifyStage === "candidate")
		.sort((a, b) => a.id.localeCompare(b.id));
	const confirmedPositive = hasConfirmedPositiveFinding(state);

	const rankedActive = rankFrontierByBelief(state, undefined, {
		graph: g,
		excludePruned: true,
	});

	// 汇总仍有待执行 open 意图（或尚未剪枝且非历史终结态）的低收益剪枝建议
	const pruneSuggestions: PruneSuggestion[] = [];
	for (const node of Object.values(g.nodes).sort((a, b) => a.posterior - b.posterior || a.id.localeCompare(b.id))) {
		if (node.posterior >= pruneThreshold && !node.pruned) continue;
		const relatedIntentIds: string[] = [];
		let actionable = false;
		if (node.kind === "intent") {
			const it = state?.intents?.[node.sourceId];
			if (it) {
				if (it.status === "open") {
					relatedIntentIds.push(it.id);
					actionable = true;
				}
			} else if (!node.pruned) {
				actionable = true;
			}
		} else {
			for (const cid of node.childIds) {
				const cNode = g.nodes[cid];
				if (cNode?.kind === "intent" && state?.intents?.[cNode.sourceId]?.status === "open") {
					uniqPush(relatedIntentIds, cNode.sourceId);
				}
			}
			actionable = relatedIntentIds.length > 0;
		}
		if (actionable) {
			pruneSuggestions.push({
				nodeId: node.id,
				title: node.title,
				posterior: node.posterior,
				intentIds: relatedIntentIds,
				reason:
					node.pruneReason ||
					`节点后验信念偏低 (${node.posterior.toFixed(3)} < ${pruneThreshold.toFixed(3)})，建议剪枝止损`,
			});
		}
	}

	// 收集已排除表面供 SealMeta.excludedSurface 无缝衔接
	const excludedSurfaceSet = new Set<string>();
	let excludedFactCount = 0;
	for (const f of Object.values(state?.facts ?? {})) {
		if (f.kind === "blocked" || f.verifyStage === "rejected") {
			excludedFactCount += 1;
			excludedSurfaceSet.add(f.targetKey || f.key || f.title || f.id);
		}
	}
	for (const it of Object.values(state?.intents ?? {})) {
		if (it.status === "blocked") {
			excludedSurfaceSet.add(it.targetKey || it.key || it.title || it.id);
		}
	}
	for (const n of Object.values(g.nodes)) {
		if (n.pruned) {
			excludedSurfaceSet.add(n.targetKey || n.title || n.id);
		}
	}
	const excludedSurface = [...excludedSurfaceSet].slice(0, 32);

	const toPivotDirection = (item: RankedFrontierItem, rationalePrefix?: string): PivotDirection => ({
		intentId: item.intent.id,
		nodeId: item.nodeId,
		title: item.intent.title,
		phase: item.intent.phase,
		surfaceDomain: g.nodes[item.nodeId]?.surfaceDomain ?? item.intent.surfaceDomain,
		beliefScore: item.beliefScore,
		voiScore: item.voiScore,
		utilityScore: item.utilityScore,
		compositeScore: item.compositeScore,
		rationale: rationalePrefix ? `${rationalePrefix}：${item.explanation}` : item.explanation,
	});

	// 计算搜索空间收敛度与负向封盘置信度（零历史探索证据或零停滞零驳回时绝不误报封盘）
	const allIntents = Object.values(state?.intents ?? {});
	const totalIntentCount = allIntents.length;
	const terminalOrPrunedCount = allIntents.filter((it) => {
		if (it.status === "done" || it.status === "blocked") return true;
		const nid = resolveBeliefNodeId(g, it.id, "intent");
		return Boolean(nid && g.nodes[nid]?.pruned);
	}).length;
	const hasExplorationEvidence = terminalOrPrunedCount > 0 || excludedFactCount > 0;

	const frontierExhaustion =
		totalIntentCount > 0
			? terminalOrPrunedCount / totalIntentCount
			: hasExplorationEvidence && rankedActive.length === 0
				? 1.0
				: 0;

	const maxRemainingBelief =
		rankedActive.length > 0 ? Math.max(...rankedActive.map((r) => r.beliefScore)) : 0;
	const maxRemainingVoi =
		rankedActive.length > 0 ? Math.max(...rankedActive.map((r) => r.voiScore)) : 0;

	const noveltyStall = Math.max(0, Number(state?.runtime?.noveltyStall ?? 0));
	const stallRatio = clamp(noveltyStall / stallThreshold, 0, 1);
	const rejects = Math.max(0, Number(state?.runtime?.completionRejects ?? 0));
	const rejectBonus = clamp(rejects * 0.15, 0, 0.3);

	const convergenceConfidence =
		!hasExplorationEvidence && rankedActive.length === 0
			? 0
			: clamp(
					0.45 * frontierExhaustion +
						0.30 * (rankedActive.length > 0 ? 1 - clamp(maxRemainingVoi, 0, 1) : frontierExhaustion) +
						0.25 * stallRatio,
					0,
					1,
				);

	let negativeSealConfidence = 0;
	if (!confirmedPositive && hasExplorationEvidence) {
		const lowBeliefFactor = rankedActive.length > 0 ? 1 - clamp(maxRemainingBelief, 0, 1) : frontierExhaustion;
		const lowVoiFactor = rankedActive.length > 0 ? 1 - clamp(maxRemainingVoi, 0, 1) : frontierExhaustion;
		let rawSeal =
			0.30 * frontierExhaustion +
			0.20 * lowBeliefFactor +
			0.35 * stallRatio +
			0.08 * lowVoiFactor +
			rejectBonus;
		// 零语义停滞且无结案驳回时（如阶段切换间隙队列暂空），封顶 <= 0.60 严禁误触发负向封盘
		if (noveltyStall === 0 && rejects === 0) {
			rawSeal = Math.min(0.6, rawSeal);
		}
		// 若存在待复验候选漏洞，必须先完成双盲复验才允许封盘，封顶 <= 0.35
		negativeSealConfidence =
			candidateFacts.length > 0 ? Math.min(0.35, clamp(rawSeal, 0, 1)) : clamp(rawSeal, 0, 1);
	}

	// 1. 优先处理待复验候选漏洞
	if (candidateFacts.length > 0) {
		const verifyItem =
			rankedActive.find((r) => /(?:^|:)verify-vuln:/i.test(r.intent.key ?? "")) ?? rankedActive[0];
		const topDirection = verifyItem
			? toPivotDirection(verifyItem, `优先完成候选事实 [${candidateFacts.map((f) => f.id).join(", ")}] 的双盲独立复验`)
			: null;
		return {
			action: "verify_candidates",
			topDirection,
			alternativeDirections: rankedActive
				.filter((r) => r.intent.id !== verifyItem?.intent.id)
				.slice(0, 3)
				.map((r) => toPivotDirection(r)),
			pruneSuggestions,
			convergenceConfidence,
			negativeSealConfidence,
			recommendSeal: false,
			excludedSurface,
			summary: `存在 ${candidateFacts.length} 个待复验候选事实，建议优先执行双盲正负对照复验后再决定纵深推进或封盘收口。`,
		};
	}

	// 2. 高负向封盘置信度 -> 建议 sealed_negative 收口
	const recommendSeal =
		!confirmedPositive &&
		hasExplorationEvidence &&
		(noveltyStall > 0 || rejects > 0) &&
		negativeSealConfidence >= sealThreshold;
	if (recommendSeal) {
		const sealReason =
			`信念搜索引擎判定攻击面已收敛且无有效突破信号（负向封盘置信度=${negativeSealConfidence.toFixed(3)}，` +
			`剩余活跃前沿=${rankedActive.length}，最高残余后验=${maxRemainingBelief.toFixed(3)}，语义停滞=${noveltyStall}/${stallThreshold}）`;
		return {
			action: "seal_negative",
			topDirection: rankedActive[0] ? toPivotDirection(rankedActive[0], "残余低信念备选") : null,
			alternativeDirections: rankedActive.slice(1, 3).map((r) => toPivotDirection(r)),
			pruneSuggestions,
			convergenceConfidence,
			negativeSealConfidence,
			recommendSeal: true,
			sealReason,
			excludedSurface,
			summary: `建议转入负向封盘（sealed_negative）：${sealReason}。`,
		};
	}

	// 2.5 全新空状态（尚未规划任何种子意图且无历史探索证据）
	if (rankedActive.length === 0 && !hasExplorationEvidence) {
		return {
			action: "explore_high_voi",
			topDirection: null,
			alternativeDirections: [],
			pruneSuggestions,
			convergenceConfidence: 0,
			negativeSealConfidence: 0,
			recommendSeal: false,
			excludedSurface,
			summary: "当前尚未规划可执行前沿意图，建议先执行侦察/表面种子规划以展开攻击信念图。",
		};
	}

	// 3. 若无活跃高价值方向但存在待剪枝建议，引导剪枝收敛
	if (rankedActive.length === 0 || (pruneSuggestions.length > 0 && maxRemainingBelief < pruneThreshold + 0.08)) {
		return {
			action: "prune_and_converge",
			topDirection: rankedActive[0] ? toPivotDirection(rankedActive[0], "收敛期剩余方向") : null,
			alternativeDirections: rankedActive.slice(1, 4).map((r) => toPivotDirection(r)),
			pruneSuggestions,
			convergenceConfidence,
			negativeSealConfidence,
			recommendSeal: false,
			excludedSurface,
			summary: `当前活跃高收益方向匮乏，建议剪枝 ${pruneSuggestions.length} 个低收益节点并转向报告/收敛核验。`,
		};
	}

	// 4. 按决策论综合价值（融合综合信念效用分、预期信息增益 VoI 与单位代价效用）推荐下一步探索或跨分域转向
	const pivotScore = (r: RankedFrontierItem): number => {
		const utilNorm = r.utilityScore / (1 + r.utilityScore);
		return 0.55 * (r.compositeScore / 100) + 0.25 * r.voiScore + 0.2 * utilNorm;
	};
	const byDecisionValue = [...rankedActive].sort(
		(a, b) => pivotScore(b) - pivotScore(a) || a.intent.id.localeCompare(b.intent.id),
	);
	const best = byDecisionValue[0]!;
	const curPhase = state?.project?.phase;
	const isSurfacePivot =
		Boolean(curPhase && best.intent.phase !== curPhase) || pruneSuggestions.length >= 2;

	return {
		action: isSurfacePivot ? "pivot_surface" : "explore_high_voi",
		topDirection: toPivotDirection(
			best,
			isSurfacePivot ? "跨面高信息增益转向推荐" : "最高预期信息增益探索方向",
		),
		alternativeDirections: byDecisionValue
			.filter((r) => r.intent.id !== best.intent.id)
			.slice(0, 3)
			.map((r) => toPivotDirection(r)),
		pruneSuggestions,
		convergenceConfidence,
		negativeSealConfidence,
		recommendSeal: false,
		excludedSurface,
		summary:
			`推荐探索 [${best.intent.id}] ${best.intent.title}（后验=${best.beliefScore.toFixed(3)}, ` +
			`VoI=${best.voiScore.toFixed(3)}, 效用=${best.utilityScore.toFixed(3)}），` +
			`当前收敛度=${convergenceConfidence.toFixed(2)}，负向封盘置信度=${negativeSealConfidence.toFixed(2)}。`,
	};
}
