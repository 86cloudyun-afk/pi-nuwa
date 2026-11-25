/**
 * 女娲 v5.x 世代轮转（Reincarnation）与阶段收口协同模块。
 *
 * 在外层无头守护器（`NUWA_HEADLESS_DAEMON=1`）托管下，当单代会话 token、轮次或语义停滞（noveltyStall）
 * 达到阈值时，精炼 1500 字以内的交接摘要（Handoff Summary），重置本代计数器并优雅放行 `session_stop`；
 * 同时为 `report` 阶段提供无新事实/零漏洞下的干净完结、转世推进或 `sealed_negative` 收口状态转移判定（#30, #45）。
 */
import type { Fact, FactKind, Mode, NuwaState, ReincarnatePolicy } from "./types";

export type { ReincarnatePolicy } from "./types";

const DEFAULT_REINCARNATE_TOKENS = 140_000;
const DEFAULT_REINCARNATE_TURNS = 30;
const DEFAULT_NOVELTY_STALL_THRESHOLD = 8;
const MAX_SUMMARY_CHARS = 1500;

function parsePositiveInt(raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const n = Number(raw);
	return Number.isFinite(n) && n >= 1 ? Math.floor(n) : fallback;
}

function oneLine(text: string | undefined, max = 100): string {
	return String(text ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

function proofKindsForMode(mode: Mode): FactKind[] {
	if (mode === "ctf") return ["flag"];
	if (mode === "audit") return ["vuln", "loot"];
	if (mode === "pentest") return ["vuln", "loot", "flag"];
	return ["vuln", "loot", "flag", "note"];
}

function hasConfirmedPositiveProof(st: NuwaState): boolean {
	const allowed = proofKindsForMode(st.project?.mode ?? "ctf");
	return Object.values(st.facts ?? {}).some(
		(f) => allowed.includes(f.kind) && f.verifyStage !== "candidate" && f.verifyStage !== "rejected",
	);
}

function hasSettledReportArtifact(st: NuwaState, explicitReportWritten?: boolean): boolean {
	if (explicitReportWritten || st.runtime?.reportWritten) return true;
	const reportIntents = Object.values(st.intents ?? {}).filter((i) => i.phase === "report");
	if (reportIntents.length === 0) return false;
	const hasLive = reportIntents.some((i) => i.status === "open" || i.status === "claimed");
	const hasDoneOrBlocked = reportIntents.some((i) => i.status === "done" || i.status === "blocked");
	return !hasLive && hasDoneOrBlocked;
}

export interface ReportPhaseTransition {
	action: "complete" | "seal_negative" | "advance_episode" | "wait_live" | "seed_report" | "noop";
	reason: string;
	canAdvanceEpisode: boolean;
}

/**
 * 判定 report 阶段的干净出口转移（#45）：
 * 即使 vuln/exploit/post 成功数为 0，只要报告已写或无新事实达标（noveltyStall >= threshold / completionRejects >= 1），
 * 立即给出 complete / seal_negative / advance_episode 干净出口，不再反复重展已死事实。
 */
export function resolveReportPhaseTransition(
	st: NuwaState,
	opts?: {
		reportWritten?: boolean;
		noveltyThreshold?: number;
		maxEpisodes?: number;
	},
): ReportPhaseTransition {
	if (st.project?.phase !== "report") {
		return { action: "noop", reason: `phase=${st.project?.phase ?? "unknown"}`, canAdvanceEpisode: false };
	}

	const reportIntents = Object.values(st.intents ?? {}).filter((i) => i.phase === "report");
	const liveReport = reportIntents.filter((i) => i.status === "open" || i.status === "claimed");
	const reportReady = hasSettledReportArtifact(st, opts?.reportWritten);

	if (hasConfirmedPositiveProof(st) && (reportReady || liveReport.length === 0)) {
		return { action: "complete", reason: "confirmed_proof_ready_in_report", canAdvanceEpisode: false };
	}

	if (liveReport.length > 0 && !opts?.reportWritten && !st.runtime?.reportWritten) {
		return { action: "wait_live", reason: `report_live(${liveReport.length})`, canAdvanceEpisode: false };
	}

	if (reportIntents.length === 0 && !reportReady) {
		return { action: "seed_report", reason: "report_unseeded", canAdvanceEpisode: false };
	}

	const threshold = opts?.noveltyThreshold ?? DEFAULT_NOVELTY_STALL_THRESHOLD;
	const noveltyStall = Number(st.runtime?.noveltyStall ?? 0);
	const rejects = Number(st.runtime?.completionRejects ?? 0);
	const ep = Number(st.project?.episode ?? 1);
	const maxEpisodes = opts?.maxEpisodes ?? 0;
	const episodeCapReached = maxEpisodes > 0 && ep >= maxEpisodes;

	if (
		noveltyStall >= threshold ||
		rejects >= 1 ||
		Boolean(opts?.reportWritten || st.runtime?.reportWritten)
	) {
		return {
			action: "seal_negative",
			reason:
				rejects >= 1
					? `report_converged_after_rejects(${rejects})`
					: noveltyStall >= threshold
						? `report_novelty_stall(${noveltyStall}>=${threshold})`
						: "report_written_zero_positive_proof",
			canAdvanceEpisode: false,
		};
	}

	if (episodeCapReached) {
		return {
			action: "noop",
			reason: `report_episode_capped(${ep}/${maxEpisodes})`,
			canAdvanceEpisode: false,
		};
	}

	return {
		action: "advance_episode",
		reason: `report_settled_next_episode(E${ep + 1})`,
		canAdvanceEpisode: true,
	};
}

/** 读取世代轮转策略：默认 140000 tokens / 30 turns，仅在 NUWA_HEADLESS_DAEMON=1 时启用。 */
export function readReincarnatePolicy(): ReincarnatePolicy {
	const base: ReincarnatePolicy = {
		maxTokens: parsePositiveInt(process.env.NUWA_REINCARNATE_TOKENS, DEFAULT_REINCARNATE_TOKENS),
		maxTurns: parsePositiveInt(process.env.NUWA_REINCARNATE_TURNS, DEFAULT_REINCARNATE_TURNS),
		headless: (process.env.NUWA_HEADLESS_DAEMON ?? "").trim() === "1",
	};
	const rawNovelty = process.env.NUWA_NOVELTY_STALL_THRESHOLD;
	if (rawNovelty !== undefined && rawNovelty.trim() !== "") {
		base.noveltyStallThreshold = parsePositiveInt(rawNovelty, DEFAULT_NOVELTY_STALL_THRESHOLD);
	}
	return base;
}

/** 判断当前状态是否需要触发会话世代轮转（兼容 #30 语义停滞升级与 #45 report 阶段收口推进）。 */
export function shouldReincarnate(
	st: NuwaState,
	policy: ReincarnatePolicy,
): { needed: boolean; reason?: string } {
	if (!policy.headless) return { needed: false };
	if (st.project?.status !== "active") return { needed: false };
	if (st.runtime?.status === "completed" || st.runtime?.status === "sealed_negative") {
		return { needed: false };
	}

	const tokens = Number(st.runtime?.tokens ?? 0);
	if (policy.maxTokens > 0 && tokens >= policy.maxTokens) {
		return { needed: true, reason: `max_tokens(${tokens}>=${policy.maxTokens})` };
	}

	const genTurns =
		typeof st.runtime?.genTurns === "number" && Number.isFinite(st.runtime.genTurns)
			? st.runtime.genTurns
			: Number(st.runtime?.turns ?? 0);
	if (policy.maxTurns > 0 && genTurns >= policy.maxTurns) {
		return { needed: true, reason: `max_gen_turns(${genTurns}>=${policy.maxTurns})` };
	}

	const stallThreshold =
		policy.noveltyStallThreshold ??
		parsePositiveInt(process.env.NUWA_NOVELTY_STALL_THRESHOLD, DEFAULT_NOVELTY_STALL_THRESHOLD);
	const noveltyStall = Number(st.runtime?.noveltyStall ?? 0);
	if (stallThreshold > 0 && noveltyStall >= stallThreshold) {
		if (st.project.phase === "report") {
			return {
				needed: true,
				reason: `report_seal_convergence(novelty_stall=${noveltyStall}>=${stallThreshold})`,
			};
		}
		return { needed: true, reason: `novelty_stall(${noveltyStall}>=${stallThreshold})` };
	}

	if (st.project.phase === "report" && genTurns >= 2) {
		const reportTrans = resolveReportPhaseTransition(st, { noveltyThreshold: stallThreshold });
		if (reportTrans.action === "seal_negative" || reportTrans.action === "complete") {
			return { needed: true, reason: `report_phase_exit(${reportTrans.reason})` };
		}
	}

	return { needed: false };
}

const FACT_PRIORITY: Record<string, number> = {
	flag: 100,
	vuln: 90,
	cred: 85,
	loot: 80,
	service: 65,
	endpoint: 60,
	asset: 55,
	target: 40,
	note: 20,
	blocked: 10,
};

/** 精炼跨世代交接摘要（严格控制在 1500 字符以内）。 */
export function buildHandoffSummary(st: NuwaState, reason?: string): string {
	const p = st.project;
	const rt = st.runtime;
	const gen = rt.generation ?? 1;
	const ep = p.episode ?? 1;

	const rawTotalTurns = Number(rt.totalTurns ?? 0);
	const rawTurns = Number(rt.turns ?? 0);
	const totalTurns = Math.max(
		Number.isFinite(rawTotalTurns) ? Math.max(0, rawTotalTurns) : 0,
		Number.isFinite(rawTurns) ? Math.max(0, rawTurns) : 0,
	);
	const rawTotalTokens = Number(rt.totalTokens ?? 0);
	const rawTokens = Number(rt.tokens ?? 0);
	const totalTokens = Math.max(
		Number.isFinite(rawTotalTokens) ? Math.max(0, rawTotalTokens) : 0,
		Number.isFinite(rawTokens) ? Math.max(0, rawTokens) : 0,
	);
	const noveltyStall = Number(rt.noveltyStall ?? 0);
	const rejects = Number(rt.completionRejects ?? 0);

	const headerLines = [
		`[女娲世代交接 G${gen}->G${gen + 1}]`,
		`目标: ${p.url} (${p.mode}) — ${oneLine(p.goal, 120)}`,
		`进度: phase=${p.phase} episode=E${ep} totalTurns=${totalTurns}${totalTokens > 0 ? ` totalTokens=${totalTokens}` : ""}${noveltyStall > 0 ? ` noveltyStall=${noveltyStall}` : ""}${rejects > 0 ? ` rejects=${rejects}` : ""}${reason ? ` trigger=${oneLine(reason, 60)}` : ""}`,
	];

	// 1. 关键事实（按价值权重 + 最新排序，去噪保留核心发现）
	const allFacts = Object.values(st.facts ?? {});
	const keyFacts: Fact[] = allFacts
		.filter((f) => f.kind !== "note" && f.kind !== "blocked")
		.sort((a, b) => {
			const pa = FACT_PRIORITY[a.kind] ?? 30;
			const pb = FACT_PRIORITY[b.kind] ?? 30;
			if (pb !== pa) return pb - pa;
			return b.id.localeCompare(a.id);
		})
		.slice(0, 8);

	const factLines = keyFacts.length
		? [
				`关键事实(${allFacts.length}条):`,
				...keyFacts.map(
					(f) =>
						`- ${f.id}[${f.kind}${f.verified ? "✓" : ""}] ${oneLine(f.title, 55)}: ${oneLine(f.detail, 80)}`,
				),
			]
		: [`关键事实: 暂无高价值事实（共 ${allFacts.length} 条记录）`];

	// 2. Blocked 踩坑经验（避免新世代重复无效尝试）
	const blockedIntents = Object.values(st.intents ?? {})
		.filter((i) => i.status === "blocked")
		.sort((a, b) => (b.doneAt ?? b.createdAt).localeCompare(a.doneAt ?? a.createdAt))
		.slice(0, 5);

	const blockedLines = blockedIntents.length
		? [
				`避坑经验(近期blocked):`,
				...blockedIntents.map((i) => `- ${i.id}[${i.phase}] ${oneLine(i.title, 40)} => ${oneLine(i.note, 65)}`),
			]
		: [];

	// 3. 高优待办意图或 report/seal 收口指引（供下一代立即接力，避免重展死事实）
	const openIntents = Object.values(st.intents ?? {})
		.filter((i) => i.status === "open" || i.status === "claimed")
		.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id))
		.slice(0, 6);

	let todoLines: string[];
	if (openIntents.length) {
		todoLines = [
			`优先待办(open/claimed):`,
			...openIntents.map(
				(i) => `- ${i.id}[${i.phase}|P${i.priority}] ${oneLine(i.title, 55)}${i.status === "claimed" ? " (待续)" : ""}`,
			),
		];
	} else if (p.phase === "report" || rejects >= 1 || noveltyStall >= DEFAULT_NOVELTY_STALL_THRESHOLD) {
		const trans = p.phase === "report" ? resolveReportPhaseTransition(st) : null;
		if (trans?.action === "complete") {
			todoLines = [`优先待办: report 阶段证据已备齐，请生成报告并调用 nuwa_complete 收口`];
		} else if (trans?.action === "seal_negative" || rejects >= 1 || noveltyStall >= DEFAULT_NOVELTY_STALL_THRESHOLD) {
			todoLines = [
				`优先待办: 已触发收敛/停滞条件（禁止重展已死事实），请整理排除面生成报告并执行 sealEngagement(sealed_negative) 合法封盘`,
			];
		} else {
			todoLines = [`优先待办: report 阶段收尾，完成报告整理后按新线索推进下一轮`];
		}
	} else {
		todoLines = [`优先待办: 当前队列待 nuwa_expand() 派生新面`];
	}

	const raw = [...headerLines, ...factLines, ...blockedLines, ...todoLines].join("\n");
	if (raw.length <= MAX_SUMMARY_CHARS) return raw;
	const suffix = "\n...(摘要已截断)";
	return raw.slice(0, MAX_SUMMARY_CHARS - suffix.length) + suffix;
}

/** 执行世代交接状态变更：保全跨世代累计账目、递增 generation、写入 handoffSummary、归零 genTurns/tokens、重置 lastSig。 */
export function prepareNextGeneration(
	st: NuwaState,
	reason?: string,
): { generation: number; summary: string } {
	const prevTotalTokens = Number(st.runtime.totalTokens ?? 0);
	const curTokens = Number(st.runtime.tokens ?? 0);
	const prevTotalTurns = Number(st.runtime.totalTurns ?? 0);
	const curTurns = Number(st.runtime.turns ?? 0);

	st.runtime.projectStartedAt =
		typeof st.runtime.projectStartedAt === "number" && Number.isFinite(st.runtime.projectStartedAt)
			? st.runtime.projectStartedAt
			: st.runtime.startedAt;
	st.runtime.totalTokens =
		(Number.isFinite(prevTotalTokens) ? Math.max(0, prevTotalTokens) : 0) +
		(Number.isFinite(curTokens) ? Math.max(0, curTokens) : 0);
	st.runtime.totalTurns = Math.max(
		Number.isFinite(prevTotalTurns) ? Math.max(0, prevTotalTurns) : 0,
		Number.isFinite(curTurns) ? Math.max(0, curTurns) : 0,
	);

	const summary = buildHandoffSummary(st, reason);
	const nextGen = (st.runtime.generation ?? 1) + 1;
	st.runtime.generation = nextGen;
	st.runtime.handoffSummary = summary;
	st.runtime.genTurns = 0;
	st.runtime.tokens = 0;
	st.runtime.lastSig = "";
	return { generation: nextGen, summary };
}
