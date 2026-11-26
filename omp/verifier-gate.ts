/**
 * 女娲 v4.0 漏洞 candidate → confirmed 双盲独立复验闸门（Verifier Gate）。
 *
 * 设计目标：
 * 1. 新发现的非自动批实锤 `vuln` 事实默认暂存为 `verifyStage="candidate"`，不可直接作为 `nuwa_complete` 验收依据。
 * 2. 自动派生高优先（P96）双盲独立复验意图 `verify-vuln:<factId>`，建议交由独立审查子代理 `nuwa-verifier`
 *    从“挑刺证伪”视角执行正负对照实验。
 * 3. 复验回传非 blocked 时将原候选漏洞升格为 `confirmed`（`verified=true`）；
 *    复验回传 blocked 时标记为 `rejected`（`verified=false`），杜绝幻觉误报过早结案。
 * 4. 兼容历史项目与自动批实锤事实：无 `verifyStage` 的事实照常放行。
 *
 * 约束：仅使用 `import type` 引用 `./types`，严禁运行时 import `./nuwa`。
 */
import type { Fact, FactKind, NuwaState, Phase } from "./types";
import {
	evaluatePositiveEvidenceGate,
	type PositiveEvidenceGateInput,
	type PositiveEvidenceGateResult,
	type ResponseSnapshot,
} from "./evidence";

export type VerifyStage = "candidate" | "confirmed" | "rejected";

export type VerifiableFact = Fact & {
	verifyStage?: VerifyStage;
	verifyNote?: string;
	verifiedAt?: string;
	verifiedBy?: string;
};

export interface StageCandidateInput {
	kind?: FactKind | string;
	intentKey?: string;
	/** 自动批确定性规则已实锤时为 true，无需二次暂存 candidate。 */
	autoVerified?: boolean;
	/** 自动批来源别名，语义等同 autoVerified。 */
	isAuto?: boolean;
	/** 自动批来源别名，语义等同 autoVerified。 */
	fromAutoBatch?: boolean;
	/** 允许调用方显式覆写环境变量开关（主要用于单测或局部策略控制）。 */
	doubleBlindEnabled?: boolean;
}

export interface VerifyIntentSpec {
	key: string;
	phase: Phase;
	title: string;
	detail: string;
	priority: number;
	from: string[];
	recommendedAgent: "nuwa-verifier";
	targetFactId: string;
}

export interface VerificationOutcome {
	matched: boolean;
	factId?: string;
	stage?: "confirmed" | "rejected";
	fact?: VerifiableFact;
	reason?: string;
	/** v5.1 (#24) 假阳性判定标识 */
	falsePositive?: boolean;
	/** v5.1 (#24) 降级建议记账类型 */
	suggestedKind?: "note";
	/** v5.1 (#24) 是否因假阳性复核门禁自动阻断升格并降级 */
	downgraded?: boolean;
	/** v5.1 (#24) 建议生成的 note(false_positive) 记账负载 */
	downgradeNote?: {
		kind: "note";
		title: string;
		detail: string;
		falsePositiveOf: string;
	};
}

export interface ResolveVerificationOptions {
	falsePositive?: boolean;
	output?: string;
	response?: ResponseSnapshot;
	baseline?: ResponseSnapshot | ResponseSnapshot[];
	requireBusinessPayload?: boolean;
}

export const VERIFY_VULN_PREFIX = "verify-vuln:";
export const DOUBLE_BLIND_VERIFY_PRIORITY = 96;

const VERIFY_VULN_KEY_RE = /(?:^|:)verify-vuln:([a-zA-Z0-9._-]+)$/i;
const VALID_PHASES = new Set<Phase>(["recon", "surface", "vuln", "exploit", "post", "report"]);

function oneLine(text: string | undefined, max = 120): string {
	return String(text ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

function clipBlock(text: string | undefined, max = 600): string {
	const s = String(text ?? "").trim();
	if (!s) return "(无)";
	if (s.length <= max) return s;
	return `${s.slice(0, max)}...(已截断)`;
}

/**
 * 判断双盲独立复验闸门是否启用。
 * 默认开启；仅当环境变量 `NUWA_DOUBLE_BLIND=0` 时关闭。
 */
export function isDoubleBlindEnabled(): boolean {
	return (process.env.NUWA_DOUBLE_BLIND ?? "").trim() !== "0";
}

/**
 * 判断意图键是否属于双盲漏洞复验意图（`verify-vuln:<factId>` 或 `<phase>:verify-vuln:<factId>`）。
 */
export function isVerifyVulnIntentKey(key: string | undefined | null): boolean {
	const norm = String(key ?? "").trim();
	if (!norm) return false;
	return VERIFY_VULN_KEY_RE.test(norm);
}

/**
 * 从 `verify-vuln:<factId>` 意图键中提取目标候选事实 ID。
 */
export function extractVerifyTargetFactId(key: string | undefined | null): string | null {
	const norm = String(key ?? "").trim();
	if (!norm) return null;
	const m = VERIFY_VULN_KEY_RE.exec(norm);
	return m?.[1] ? m[1] : null;
}

/**
 * 判断一次提交是否应先暂存为 `verifyStage="candidate"` 等待双盲复验。
 *
 * 规则：
 * 1. 双盲开关关闭时直接返回 false。
 * 2. 仅针对 `kind === "vuln"` 生效；其余事实类型直接放行。
 * 3. 自动批确定性规则已实锤（autoVerified / isAuto / fromAutoBatch）时不暂存。
 * 4. 意图键本身为 `verify-vuln:*`（复验任务自身回传）时不二次套娃暂存。
 */
export function shouldStageAsCandidate(input: StageCandidateInput): boolean {
	if (!input) return false;
	const enabled = input.doubleBlindEnabled ?? isDoubleBlindEnabled();
	if (!enabled) return false;

	const kind = String(input.kind ?? "").trim().toLowerCase();
	if (kind !== "vuln") return false;

	if (input.autoVerified === true || input.isAuto === true || input.fromAutoBatch === true) {
		return false;
	}

	if (isVerifyVulnIntentKey(input.intentKey)) {
		return false;
	}

	return true;
}

/**
 * 为候选漏洞事实构造高优先（P96）独立挑刺正负对照双盲复验意图规格。
 * 若非 `vuln` 事实或状态中已存在同目标复验意图则返回 null（幂等去重）。
 */
export function buildDoubleBlindVerifyIntentSpec(
	st: NuwaState,
	fact: VerifiableFact,
): VerifyIntentSpec | null {
	if (!st || !fact || !fact.id || fact.kind !== "vuln") return null;

	const key = `${VERIFY_VULN_PREFIX}${fact.id}`;
	const alreadyExists = Object.values(st.intents ?? {}).some((intent) => {
		if (!intent) return false;
		if (intent.key === key) return true;
		return extractVerifyTargetFactId(intent.key) === fact.id;
	});
	if (alreadyExists) return null;

	const rawPhase = st.project?.phase;
	const phase: Phase = rawPhase && VALID_PHASES.has(rawPhase) ? rawPhase : "vuln";

	const detail = [
		`[双盲独立复验任务 · 优先派发 nuwa-verifier]`,
		`待复验候选事实: ${fact.id} [${fact.kind}] ${oneLine(fact.title, 100)}`,
		`目标地址: ${st.project?.url || st.project?.target || "(未指定)"}`,
		`候选详情摘要: ${clipBlock(fact.detail, 500)}`,
		`候选宣称命令: ${clipBlock(fact.command, 320)}`,
		`候选宣称回显: ${clipBlock(fact.output, 420)}`,
		``,
		`独立审查要求（默认假设候选为误报，须通过正负对照实验独立证实或证伪）:`,
		`1. 优先由独立审查子代理 task(agent="nuwa-verifier") 执行，避免原发现视角确认偏差。`,
		`2. 正例独立重现（Positive Control）：从零发起最小、非破坏性验证请求，独立确认异常行为可稳定复现且与目标直接相关。`,
		`3. 负例基线对照（Negative Control）：构造等价的正常/无触发条件/匿名对照请求，比对状态码、字节数与响应体哈希（body_sha256），确认正向响应包含真实业务数据字段，排除仅 HTTP 200 + 微小错误壳（如 {"detail":"Not Found"}、<64B 空壳）、Soft-404、通用报错页、静态回显、缓存污染或 WAF 误判。`,
		`4. 严格遵守授权 Scope 与最小影响原则，禁止破坏性操作，所有回显必须来自本次真实执行。`,
		``,
		`复验落盘契约:`,
		`- 若正负对照均成立（确认为真实缺陷）：调用 nuwa_commit(id="{ID}", kind="vuln", title="复验确认: ${oneLine(fact.title, 60)}", detail="正例与负例对照详情...", command="<实际复验命令>", output="<关键对照回显>")，系统将把 ${fact.id} 升格为 confirmed。`,
		`- 若无法复现、负例无差异或属于误报：调用 nuwa_commit(id="{ID}", blocked=true, note="双盲复验驳回：<误报原因与负例对照证据>")，系统将把 ${fact.id} 标记为 rejected。`,
	].join("\n");

	return {
		key,
		phase,
		title: `双盲复验候选漏洞 ${fact.id}: ${oneLine(fact.title, 72)}`,
		detail,
		priority: DOUBLE_BLIND_VERIFY_PRIORITY,
		from: [fact.id],
		recommendedAgent: "nuwa-verifier",
		targetFactId: fact.id,
	};
}

/**
 * 构造假阳性降级 `note` 记账建议载荷（Issue #24 / NW-04）。
 */
export function buildFalsePositiveNote(
	fact: Pick<VerifiableFact, "id" | "kind" | "title">,
	reason: string,
): { kind: "note"; title: string; detail: string; falsePositiveOf: string } {
	return {
		kind: "note",
		title: `false_positive(${fact.id}): ${oneLine(fact.title, 80)}`,
		detail: `原候选 ${fact.id} [${fact.kind}] 复核判定为假阳性并阻断升格：${reason}`,
		falsePositiveOf: fact.id,
	};
}

/**
 * #24 (NW-04) 复核正向 `vuln`/`bypass`/`cred`/`loot` 结论是否存在假阳性风险。
 */
export function verifyPositiveConclusion(input: PositiveEvidenceGateInput): PositiveEvidenceGateResult {
	return evaluatePositiveEvidenceGate(input);
}

/**
 * 结算双盲复验结果并回写原候选事实的 `verifyStage` 状态：
 * - `blocked === false`：先执行 v5.1 (#24) 假阳性门禁校验（如传入响应/基线/输出），若命中错误壳、空壳或同基线哈希则强制阻断升格并降级为 `rejected`（返回 `falsePositive: true`, `suggestedKind: "note"`）；通过后升格为 `confirmed`（`verified = true`）；
 * - `blocked === true`：将原候选标记为 `rejected`（`verified = false`），并在命中误报语义时给出 `note` 记账建议。
 */
export function resolveVerificationOutcome(
	st: NuwaState,
	intentKey: string,
	blocked: boolean,
	note?: string,
	opts?: ResolveVerificationOptions,
): VerificationOutcome {
	const factId = extractVerifyTargetFactId(intentKey);
	if (!factId) {
		return { matched: false, reason: "非 verify-vuln:* 复验意图键" };
	}

	const target = st?.facts?.[factId] as VerifiableFact | undefined;
	if (!target) {
		return {
			matched: false,
			factId,
			reason: `状态中未找到待复验候选事实: ${factId}`,
		};
	}

	const ts = new Date().toISOString();
	const trimmedNote = String(note ?? "").trim();

	if (!blocked) {
		let fpReason: string | undefined;
		if (opts?.falsePositive === true) {
			fpReason = trimmedNote || "显式标记为假阳性，阻断升格并降级为 note";
		} else if (
			opts &&
			(opts.response !== undefined ||
				opts.baseline !== undefined ||
				opts.output !== undefined ||
				opts.requireBusinessPayload === true)
		) {
			const gate = evaluatePositiveEvidenceGate({
				kind: target.kind,
				title: target.title,
				detail: target.detail,
				output: opts.output ?? target.output,
				response: opts.response,
				baseline: opts.baseline,
				requireBusinessPayload: opts.requireBusinessPayload ?? true,
			});
			if (gate.falsePositive) {
				fpReason = gate.reason;
			}
		}

		if (fpReason) {
			target.verifyStage = "rejected";
			target.verified = false;
			target.verifiedAt = ts;
			target.verifiedBy = intentKey;
			target.verifyNote = fpReason;
			return {
				matched: true,
				factId,
				stage: "rejected",
				fact: target,
				reason: fpReason,
				falsePositive: true,
				suggestedKind: "note",
				downgraded: true,
				downgradeNote: buildFalsePositiveNote(target, fpReason),
			};
		}

		target.verifyStage = "confirmed";
		target.verified = true;
		target.verifiedAt = ts;
		target.verifiedBy = intentKey;
		if (trimmedNote) {
			target.verifyNote = trimmedNote;
		}
		return {
			matched: true,
			factId,
			stage: "confirmed",
			fact: target,
		};
	}

	const rejectReason = trimmedNote || "双盲复验驳回（正负对照未通过）";
	target.verifyStage = "rejected";
	target.verified = false;
	target.verifiedAt = ts;
	target.verifiedBy = intentKey;
	target.verifyNote = rejectReason;
	const signalsFalsePositive =
		opts?.falsePositive === true ||
		/误报|假阳性|soft-404|基线一致|错误壳|false[_\s-]?positive/i.test(rejectReason);
	return {
		matched: true,
		factId,
		stage: "rejected",
		fact: target,
		...(signalsFalsePositive
			? {
					falsePositive: true,
					suggestedKind: "note" as const,
					downgradeNote: buildFalsePositiveNote(target, rejectReason),
				}
			: {}),
	};
}

/**
 * 过滤可用于项目验收（`nuwa_complete`）的有效实锤证据事实：
 * - 拒绝 `verifyStage === "candidate"`（尚未复验）与 `verifyStage === "rejected"`（已证伪驳回）的事实；
 * - 放行 `verifyStage === "confirmed"` 的已复验事实；
 * - 放行无 `verifyStage` 属性的历史事实或非双盲类型实锤事实（如 flag / loot / note / 自动批实锤 vuln）。
 */
export function filterConfirmedProofs(
	facts: Iterable<VerifiableFact> | Record<string, VerifiableFact>,
	proofKinds: readonly FactKind[],
): VerifiableFact[] {
	if (!facts || !Array.isArray(proofKinds) || proofKinds.length === 0) return [];

	const allowedKinds = new Set<FactKind>(proofKinds);
	const list: VerifiableFact[] =
		Symbol.iterator in Object(facts)
			? [...(facts as Iterable<VerifiableFact>)]
			: Object.values(facts as Record<string, VerifiableFact>);

	const out: VerifiableFact[] = [];
	for (const fact of list) {
		if (!fact || !allowedKinds.has(fact.kind)) continue;
		if (fact.verifyStage === "candidate" || fact.verifyStage === "rejected") {
			continue;
		}
		out.push(fact);
	}
	return out;
}

export interface VerifyCommitValidationInput {
	intentKey: string;
	kind?: string;
	blocked?: boolean;
	worker?: string;
	candidateFact?: VerifiableFact;
	hasFreshExecution?: boolean;
	executedByVerifier?: boolean;
	requireVerifierWorker?: boolean;
	/** v5.1 (#24) 复验回显与对照基线，用于阻断微小错误壳/空壳/同基线哈希误报升格 */
	output?: string;
	title?: string;
	detail?: string;
	response?: ResponseSnapshot;
	baseline?: ResponseSnapshot | ResponseSnapshot[];
	requireBusinessPayload?: boolean;
}

export interface VerifyCommitValidationResult {
	ok: boolean;
	reason?: string;
	falsePositive?: boolean;
	suggestedKind?: "note";
}

export interface FactVerifyPartition {
	confirmed: VerifiableFact[];
	candidate: VerifiableFact[];
	rejected: VerifiableFact[];
}

/**
 * 校验双盲复验提交（verify-vuln:*）及正向结论的硬性门禁条件，防止绕过升格与假阳性通过：
 * - blocked=true（驳回）直接放行；
 * - 对 verify-vuln:* 意图强制要求 kind="vuln"、存在晚于候选水位的新增独立执行记录，以及（如启用）nuwa-verifier 认领；
 * - 对正向 vuln/bypass/cred/loot 提交，如提供 response/baseline/output，额外执行 #24 假阳性复核门禁，失败时返回 `falsePositive: true` 并建议降级为 `note`。
 */
export function validateVerificationCommit(
	input: VerifyCommitValidationInput,
): VerifyCommitValidationResult {
	if (!input || input.blocked === true) {
		return { ok: true };
	}

	const normKind = String(input.kind ?? "").trim().toLowerCase();
	const isVerifyIntent = isVerifyVulnIntentKey(input.intentKey);

	if (isVerifyIntent) {
		if (normKind !== "vuln") {
			return {
				ok: false,
				reason: '双盲复验确认必须使用 kind="vuln" 并通过执行证据账本核验，禁止用默认 note 绕过升格',
			};
		}

		if (input.hasFreshExecution === false) {
			return {
				ok: false,
				reason: "双盲复验缺少晚于候选创建时间的独立工具执行记录，禁止复用历史输出直接升格",
			};
		}

		const worker = String(input.worker ?? "").trim();
		if (input.requireVerifierWorker && worker !== "nuwa-verifier") {
			return {
				ok: false,
				reason: "双盲复验须由独立审查代理 nuwa-verifier 认领执行",
			};
		}
	}

	const positiveKind =
		normKind === "vuln" || normKind === "bypass" || normKind === "cred" || normKind === "loot";
	if (
		positiveKind &&
		(input.response !== undefined ||
			input.baseline !== undefined ||
			input.output !== undefined ||
			input.requireBusinessPayload === true)
	) {
		const gate = evaluatePositiveEvidenceGate({
			kind: normKind,
			title: input.title ?? input.candidateFact?.title,
			detail: input.detail ?? input.candidateFact?.detail,
			output: input.output,
			response: input.response,
			baseline: input.baseline,
			requireBusinessPayload:
				input.requireBusinessPayload ?? (input.response !== undefined || input.baseline !== undefined),
		});
		if (gate.falsePositive) {
			return {
				ok: false,
				falsePositive: true,
				suggestedKind: "note",
				reason: gate.reason,
			};
		}
	}

	return { ok: true };
}

/**
 * 按 verifyStage 将事实划分为 confirmed / candidate / rejected 三组（可选按 FactKind 过滤）：
 * - verifyStage === "rejected" -> rejected
 * - verifyStage === "candidate" -> candidate
 * - verifyStage === "confirmed" 或 undefined -> confirmed
 */
export function partitionFactsByVerifyStage(
	facts: Iterable<VerifiableFact> | Record<string, VerifiableFact>,
	kindFilter?: FactKind,
): FactVerifyPartition {
	const confirmed: VerifiableFact[] = [];
	const candidate: VerifiableFact[] = [];
	const rejected: VerifiableFact[] = [];
	if (!facts) {
		return { confirmed, candidate, rejected };
	}

	const list: VerifiableFact[] =
		Symbol.iterator in Object(facts)
			? [...(facts as Iterable<VerifiableFact>)]
			: Object.values(facts as Record<string, VerifiableFact>);

	for (const fact of list) {
		if (!fact) continue;
		if (kindFilter !== undefined && fact.kind !== kindFilter) continue;
		if (fact.verifyStage === "rejected") {
			rejected.push(fact);
		} else if (fact.verifyStage === "candidate") {
			candidate.push(fact);
		} else {
			confirmed.push(fact);
		}
	}

	return { confirmed, candidate, rejected };
}

