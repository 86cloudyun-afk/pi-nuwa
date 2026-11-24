/**
 * 女娲 v3.0 世代轮转（Reincarnation）模块。
 *
 * 在外层无头守护器（`NUWA_HEADLESS_DAEMON=1`）托管下，当单代会话 token 或轮次达到阈值时，
 * 精炼 1500 字以内的交接摘要（Handoff Summary），重置本代计数器并优雅放行 `session_stop`，
 * 由外层守护进程以全新上下文拉起下一代会话继续推进。
 */
import type { Fact, NuwaState, ReincarnatePolicy } from "./types";

export type { ReincarnatePolicy } from "./types";

const DEFAULT_REINCARNATE_TOKENS = 140_000;
const DEFAULT_REINCARNATE_TURNS = 30;
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

/** 读取世代轮转策略：默认 140000 tokens / 30 turns，仅在 NUWA_HEADLESS_DAEMON=1 时启用。 */
export function readReincarnatePolicy(): ReincarnatePolicy {
	return {
		maxTokens: parsePositiveInt(process.env.NUWA_REINCARNATE_TOKENS, DEFAULT_REINCARNATE_TOKENS),
		maxTurns: parsePositiveInt(process.env.NUWA_REINCARNATE_TURNS, DEFAULT_REINCARNATE_TURNS),
		headless: (process.env.NUWA_HEADLESS_DAEMON ?? "").trim() === "1",
	};
}

/** 判断当前状态是否需要触发会话世代轮转。 */
export function shouldReincarnate(
	st: NuwaState,
	policy: ReincarnatePolicy,
): { needed: boolean; reason?: string } {
	if (!policy.headless) return { needed: false };
	if (st.project?.status !== "active") return { needed: false };

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

	const headerLines = [
		`[女娲世代交接 G${gen}->G${gen + 1}]`,
		`目标: ${p.url} (${p.mode}) — ${oneLine(p.goal, 120)}`,
		`进度: phase=${p.phase} episode=E${ep} totalTurns=${rt.turns ?? 0}${reason ? ` trigger=${oneLine(reason, 60)}` : ""}`,
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

	// 3. 高优待办意图（供下一代立即接力）
	const openIntents = Object.values(st.intents ?? {})
		.filter((i) => i.status === "open" || i.status === "claimed")
		.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id))
		.slice(0, 6);

	const todoLines = openIntents.length
		? [
				`优先待办(open/claimed):`,
				...openIntents.map(
					(i) => `- ${i.id}[${i.phase}|P${i.priority}] ${oneLine(i.title, 55)}${i.status === "claimed" ? " (待续)" : ""}`,
				),
			]
		: [`优先待办: 当前队列待 nuwa_expand() 派生新面`];

	const raw = [...headerLines, ...factLines, ...blockedLines, ...todoLines].join("\n");
	if (raw.length <= MAX_SUMMARY_CHARS) return raw;
	const suffix = "\n...(摘要已截断)";
	return raw.slice(0, MAX_SUMMARY_CHARS - suffix.length) + suffix;
}

/** 执行世代交接状态变更：递增 generation、写入 handoffSummary、归零 genTurns/tokens、重置 lastSig。 */
export function prepareNextGeneration(
	st: NuwaState,
	reason?: string,
): { generation: number; summary: string } {
	const summary = buildHandoffSummary(st, reason);
	const nextGen = (st.runtime.generation ?? 1) + 1;
	st.runtime.generation = nextGen;
	st.runtime.handoffSummary = summary;
	st.runtime.genTurns = 0;
	st.runtime.tokens = 0;
	st.runtime.lastSig = "";
	return { generation: nextGen, summary };
}
