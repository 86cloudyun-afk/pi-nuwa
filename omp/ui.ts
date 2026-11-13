/**
 * 女娲可视化：状态快照 + 纯渲染函数。
 *
 * 设计约束（见 docs/UI-DESIGN.md）：
 * - 不 import 运行时模块，只 import 类型，避免与 nuwa.ts 形成循环依赖。
 * - 不 import @oh-my-pi/pi-tui：扩展目录没有 node_modules，包解析失败会拖垮整个扩展。
 * - 所有渲染函数接受 UiStyle，测试用 plainStyle，运行时用 themeStyle(theme)。
 * - 先拼纯文本再上色，截断按可见宽度计算（ANSI 感知），CJK 用 Bun.stringWidth。
 */
import type { Cfg, NuwaState, Phase } from "./nuwa";

export const UI_PHASES = ["recon", "surface", "vuln", "exploit", "post", "report"] as const;

export type UiColor = "accent" | "success" | "warning" | "error" | "muted" | "dim" | "text" | "border";

export interface UiStyle {
	fg(color: UiColor, text: string): string;
	bold(text: string): string;
	dim(text: string): string;
}

export const plainStyle: UiStyle = {
	fg: (_color, text) => text,
	bold: (text) => text,
	dim: (text) => text,
};

export interface ThemeLike {
	fg(color: string, text: string): string;
	bold(text: string): string;
}

/** 把 omp Theme 适配成 UiStyle；未知 token 原样返回，保证 light/dark 主题都不炸。 */
export function themeStyle(theme: ThemeLike): UiStyle {
	const fg = (color: UiColor, text: string): string => {
		try {
			return theme.fg(color, text);
		} catch {
			return text;
		}
	};
	return {
		fg,
		bold: (text) => {
			try {
				return theme.bold(text);
			} catch {
				return text;
			}
		},
		dim: (text) => fg("dim", text),
	};
}

export interface PhaseStat {
	phase: Phase;
	open: number;
	claimed: number;
	done: number;
	blocked: number;
	total: number;
}

export interface FrontierRow {
	id: string;
	title: string;
	phase: Phase;
	priority: number;
}

export interface IntentRow {
	id: string;
	title: string;
	phase: Phase;
	status: string;
	priority: number;
}

export interface RecentRow {
	ts: string;
	type: string;
	text: string;
}

export interface UiSnapshot {
	project: {
		id: string;
		url: string;
		host: string;
		port: number;
		mode: string;
		status: string;
		phase: Phase;
		goal: string;
		episode: number;
	};
	phases: PhaseStat[];
	totals: {
		facts: number;
		flags: number;
		intents: number;
		open: number;
		claimed: number;
		done: number;
		blocked: number;
	};
	frontier: FrontierRow[];
	intents: IntentRow[];
	runtime: {
		turns: number;
		stall: number;
		idle: number;
		pressure: number;
		expansions: number;
		startedAt: number;
	};
	infinite: boolean;
	recent: RecentRow[];
	rate: number;
	sparks: number[];
}

export interface JournalEntry {
	ts?: string;
	type?: string;
	[k: string]: unknown;
}

/** journal 事件 → 一行短文本；未知类型原样保留，方便排查。 */
export function journalText(e: JournalEntry): string {
	const id = typeof e.id === "string" ? e.id : "";
	const fact = typeof e.fact === "string" ? e.fact : "";
	switch (e.type) {
		case "commit":
			return `+ ${fact || "?"} ← ${id || "?"}`;
		case "blocked":
			return `■ ${id || "?"} blocked`;
		case "claim":
			return `→ ${id || "?"}`;
		case "expand": {
			const added = Array.isArray(e.added) ? e.added.length : 0;
			return `↗ ${String(e.reason ?? "expand")} +${added}`;
		}
		case "episode":
			return `E${String(e.episode ?? "?")}`;
		case "flag":
			return `⚑ ${fact || "?"}`;
		case "init":
			return `init ${id || ""}`.trim();
		case "block":
			return `#${String(e.turn ?? "?")} ${String(e.phase ?? "")} stall=${String(e.stall ?? 0)}`;
		case "stop_budget":
		case "stop_manual":
			return `stop: ${String(e.why ?? e.reason ?? "")}`;
		default:
			return String(e.type ?? "?");
	}
}

function hhmm(ts: string | undefined): string {
	if (!ts) return "--:--";
	const d = new Date(ts);
	if (Number.isNaN(d.getTime())) return "--:--";
	return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** journal 尾部解析：纯函数，测试直接喂字符串。 */
export function parseJournalTail(text: string, limit = 200): JournalEntry[] {
	const lines = text.trim().split("\n");
	const out: JournalEntry[] = [];
	for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
		const line = lines[i].trim();
		if (!line) continue;
		try {
			const rec = JSON.parse(line) as JournalEntry;
			if (rec?.type === "snapshot") continue;
			out.push(rec);
		} catch {
			/* 坏行跳过 */
		}
	}
	return out.reverse();
}

export function buildRecent(entries: JournalEntry[], limit = 12): RecentRow[] {
	return entries.slice(-limit).map((e) => ({
		ts: hhmm(e.ts),
		type: String(e.type ?? "?"),
		text: journalText(e),
	}));
}

/** 最近 8 分钟按分钟分桶的 commit 数，返回 8 个桶 + 每分钟均值。 */
export function commitRate(entries: JournalEntry[], now = Date.now(), minutes = 8): { rate: number; sparks: number[] } {
	const buckets = new Array<number>(minutes).fill(0);
	for (const e of entries) {
		if (e.type !== "commit" || !e.ts) continue;
		const t = Date.parse(e.ts);
		if (!Number.isFinite(t)) continue;
		const age = Math.floor((now - t) / 60_000);
		if (age < 0 || age >= minutes) continue;
		buckets[minutes - 1 - age] += 1;
	}
	const total = buckets.reduce((a, b) => a + b, 0);
	return { rate: total / minutes, sparks: buckets };
}

function frontierOf(st: NuwaState, cfg: Cfg): FrontierRow[] {
	const now = Date.now();
	return Object.values(st.intents)
		.filter((i) => i.status === "open" || i.status === "claimed")
		.filter((i) => i.from.every((f) => st.facts[f]))
		.filter((i) => {
			if (i.status === "open") return true;
			const at = i.claimedAt ? Date.parse(i.claimedAt) : 0;
			return !at || now - at > cfg.claimTtl * 1000;
		})
		.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id))
		.slice(0, Math.max(1, cfg.maxBatch))
		.map((i) => ({ id: i.id, title: i.title, phase: i.phase, priority: i.priority }));
}

export function buildSnapshot(
	st: NuwaState,
	cfg: Cfg,
	pressure: number,
	entries: JournalEntry[] = [],
): UiSnapshot {
	const intents = Object.values(st.intents);
	const phases: PhaseStat[] = UI_PHASES.map((phase) => {
		const xs = intents.filter((i) => i.phase === phase);
		return {
			phase,
			open: xs.filter((i) => i.status === "open").length,
			claimed: xs.filter((i) => i.status === "claimed").length,
			done: xs.filter((i) => i.status === "done").length,
			blocked: xs.filter((i) => i.status === "blocked").length,
			total: xs.length,
		};
	}).filter((x) => x.total > 0);
	const { rate, sparks } = commitRate(entries);
	return {
		project: {
			id: st.project.id,
			url: st.project.url,
			host: st.project.host,
			port: st.project.port,
			mode: st.project.mode,
			status: st.project.status,
			phase: st.project.phase,
			goal: st.project.goal,
			episode: st.project.episode ?? 1,
		},
		phases,
		totals: {
			facts: Object.keys(st.facts).length,
			flags: Object.values(st.facts).filter((f) => f.kind === "flag").length,
			intents: intents.length,
			open: intents.filter((i) => i.status === "open").length,
			claimed: intents.filter((i) => i.status === "claimed").length,
			done: intents.filter((i) => i.status === "done").length,
			blocked: intents.filter((i) => i.status === "blocked").length,
		},
		frontier: frontierOf(st, cfg),
		intents: intents
			.sort((a, b) => a.id.localeCompare(b.id))
			.slice(0, 200)
			.map((i) => ({ id: i.id, title: i.title, phase: i.phase, status: i.status, priority: i.priority })),
		runtime: {
			turns: st.runtime.turns,
			stall: st.runtime.stall,
			idle: st.runtime.idle,
			pressure,
			expansions: st.runtime.expansions ?? 0,
			startedAt: st.runtime.startedAt,
		},
		infinite: cfg.infinite,
		recent: buildRecent(entries),
		rate,
		sparks,
	};
}

// ---------------------------------------------------------------------------
// 文本宽度与 ANSI 截断
// ---------------------------------------------------------------------------

const ANSI_RE = /\x1b\[[0-9;]*m/g;

export function visibleWidth(text: string): number {
	const plain = text.replace(ANSI_RE, "");
	const B = (globalThis as { Bun?: { stringWidth?: (s: string) => number } }).Bun;
	if (B?.stringWidth) return B.stringWidth(plain);
	// 无 Bun 时按 East Asian 宽字符估算，够 UI 截断用。
	let w = 0;
	for (const ch of plain) {
		const code = ch.codePointAt(0) ?? 0;
		w += code >= 0x1100 && (code <= 0x115f || (code >= 0x2e80 && code <= 0xa4cf) || (code >= 0xac00 && code <= 0xd7a3) || (code >= 0xf900 && code <= 0xfaff) || (code >= 0xfe30 && code <= 0xfe4f) || (code >= 0xff00 && code <= 0xff60) || (code >= 0xffe0 && code <= 0xffe6) || (code >= 0x1f300 && code <= 0x1faff)) ? 2 : 1;
	}
	return w;
}

/** 按可见宽度截断，保留完整 ANSI 序列，截断后补 reset。 */
export function clipAnsi(text: string, width: number): string {
	if (width <= 0) return "";
	if (visibleWidth(text) <= width) return text;
	let out = "";
	let w = 0;
	let i = 0;
	while (i < text.length) {
		if (text[i] === "\x1b") {
			const m = /^\x1b\[[0-9;]*m/.exec(text.slice(i));
			if (m) {
				out += m[0];
				i += m[0].length;
				continue;
			}
		}
		const ch = text[i];
		const cw = visibleWidth(ch);
		if (w + cw > width - 1) {
			out += "…";
			break;
		}
		out += ch;
		w += cw;
		i += 1;
	}
	return `${out}\x1b[0m`;
}

export function padRight(text: string, width: number): string {
	const pad = width - visibleWidth(text);
	return pad > 0 ? text + " ".repeat(pad) : text;
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

function statusMark(status: string): string {
	if (status === "completed") return "✓";
	if (status === "stopped") return "■";
	return "●";
}

function phaseColor(phase: Phase): UiColor {
	switch (phase) {
		case "recon":
			return "muted";
		case "surface":
			return "muted";
		case "vuln":
			return "warning";
		case "exploit":
			return "accent";
		case "post":
			return "accent";
		default:
			return "muted";
	}
}

const SPARK = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

/** 8 桶 commit 数的块字符图。 */
export function sparkline(values: readonly number[]): string {
	if (values.length === 0) return "";
	const max = Math.max(...values, 1);
	return values.map((v) => SPARK[Math.min(7, Math.max(0, Math.round((v / max) * 7)))]).join("");
}

export function renderPhaseBar(snap: UiSnapshot, style: UiStyle, width = 12): string {
	const cur = snap.phases.find((p) => p.phase === snap.project.phase);
	const total = cur?.total ?? 0;
	const done = cur ? cur.done + cur.blocked : 0;
	const filled = total > 0 ? Math.round((done / total) * width) : 0;
	const w = Math.max(4, width);
	return style.fg("success", "█".repeat(Math.min(filled, w))) + style.fg("dim", "░".repeat(Math.max(0, w - filled)));
}

/** 状态栏一行，≤ 48 列（Tern 状态栏会截断更宽的文本）。 */
export function renderStatusLine(snap: UiSnapshot, style: UiStyle): string {
	const cur = snap.phases.find((p) => p.phase === snap.project.phase);
	const done = cur?.done ?? 0;
	const total = cur?.total ?? 0;
	const pressure = Math.round(snap.runtime.pressure * 100);
	const tail = snap.infinite ? "∞" : `${pressure}%`;
	const lead = `${style.fg("accent", "女娲")} ${style.fg(snap.project.status === "active" ? "success" : "warning", statusMark(snap.project.status))}`;
	const rest = [
		style.fg(phaseColor(snap.project.phase), snap.project.phase),
		`${done}/${total}`,
		`派单 ${snap.totals.claimed}`,
		`E${snap.project.episode}`,
		tail,
	].join(" · ");
	return clipAnsi(`${lead} ${rest}`, 48);
}

export interface WidgetOptions {
	width?: number;
	lines?: 3 | 5;
}

/** 编辑器上方 mini 看板：默认 3 行，5 行模式补 pressure/耗时/扩张。 */
export function renderWidgetLines(snap: UiSnapshot, style: UiStyle, opts: WidgetOptions = {}): string[] {
	const width = opts.width ?? 80;
	const lines = opts.lines ?? 3;
	const cur = snap.phases.find((p) => p.phase === snap.project.phase);
	const done = cur?.done ?? 0;
	const total = cur?.total ?? 0;
	const pressure = Math.round(snap.runtime.pressure * 100);
	const mins = Math.max(0, Math.floor((Date.now() - snap.runtime.startedAt) / 60_000));
	const bar = renderPhaseBar(snap, style, Math.max(8, Math.min(16, Math.floor(width * 0.18))));
	const head = [
		`${style.bold(style.fg("accent", "女娲"))} ${style.fg(snap.project.status === "active" ? "success" : "warning", statusMark(snap.project.status))}`,
		style.fg(phaseColor(snap.project.phase), snap.project.phase),
		bar,
		style.fg("text", `${done}/${total}`),
		style.dim(`E${snap.project.episode}`),
		style.dim(snap.infinite ? "∞" : `${pressure}%`),
	].join(" ");
	const claimedIds = snap.intents
		.filter((i) => i.status === "claimed")
		.slice(0, 4)
		.map((i) => i.id);
	const batch = snap.frontier.length
		? `批 ${snap.frontier.map((f) => f.id).join(" ")}`
		: claimedIds.length
			? `批 ${claimedIds.join(" ")} (claimed)`
			: "批 (空)";
	const second = [
		style.fg("text", batch),
		style.dim(`claim ${snap.totals.claimed}`),
		style.dim(`blocked ${snap.totals.blocked}`),
		style.dim(`facts ${snap.totals.facts}`),
		snap.rate > 0 ? style.fg("success", `${snap.rate.toFixed(1)}/min`) : style.dim("0/min"),
	].join(" · ");
	const third = style.dim(`pressure ${pressure}% · turns ${snap.runtime.turns} · ${mins}min`);
	const out = [clipAnsi(head, width), clipAnsi(second, width), clipAnsi(third, width)];
	if (lines >= 5) {
		out.push(clipAnsi(`${style.fg("success", sparkline(snap.sparks))} ${style.dim("commits/8min")}`, width));
		out.push(
			clipAnsi(
				style.dim(`expand ${snap.runtime.expansions} · stall ${snap.runtime.stall} · idle ${snap.runtime.idle}`),
				width,
			),
		);
	}
	return out;
}

function phaseSymbol(p: PhaseStat, style: UiStyle): string {
	if (p.total > 0 && p.done + p.blocked === p.total) return style.fg("success", "✓");
	if (p.open + p.claimed > 0) return style.fg("accent", "●");
	return style.fg("warning", "○");
}

export interface BoardOptions {
	width?: number;
	maxIntents?: number;
}

/** `/nuwa board` 的文本版：阶段表 + frontier + 攻击链 + 事件流。 */
export function renderBoardLines(snap: UiSnapshot, style: UiStyle, opts: BoardOptions = {}): string[] {
	const width = opts.width ?? 80;
	const maxIntents = opts.maxIntents ?? 30;
	const p = snap.project;
	const pressure = Math.round(snap.runtime.pressure * 100);
	const mins = Math.max(0, Math.floor((Date.now() - snap.runtime.startedAt) / 60_000));
	const out: string[] = [];
	const title = `女娲 ${p.id} · ${p.mode} · ${p.status} · E${p.episode}`;
	out.push(clipAnsi(style.bold(style.fg("accent", title)), width));
	out.push(clipAnsi(style.dim(`目标 ${p.url} · ${mins}min · turns ${snap.runtime.turns} · pressure ${pressure}%`), width));
	out.push(style.dim("─".repeat(Math.max(10, Math.min(width, 72)))));

	out.push(style.bold("阶段"));
	const barW = Math.max(6, Math.min(14, Math.floor(width * 0.16)));
	for (const ph of snap.phases) {
		const bar = (() => {
			const filled = ph.total > 0 ? Math.round(((ph.done + ph.blocked) / ph.total) * barW) : 0;
			return style.fg("success", "█".repeat(filled)) + style.fg("dim", "░".repeat(Math.max(0, barW - filled)));
		})();
		const counts = `${ph.done}/${ph.total}`;
		const extra = ph.claimed > 0 ? style.fg("warning", ` claim ${ph.claimed}`) : ph.blocked > 0 ? style.fg("error", ` blocked ${ph.blocked}`) : "";
		out.push(clipAnsi(` ${phaseSymbol(ph, style)} ${padRight(ph.phase, 8)} ${counts.padStart(7)} ${bar}${extra}`, width));
	}

	out.push("");
	out.push(style.bold("frontier"));
	if (snap.frontier.length === 0) out.push(style.dim("  (空)"));
	for (const f of snap.frontier.slice(0, maxIntents)) {
		out.push(clipAnsi(`  ${style.fg("accent", f.id)} ${f.title} ${style.dim(`p${f.priority}`)}`, width));
	}

	out.push("");
	out.push(style.bold("攻击链"));
	const chain = snap.intents.filter((i) => i.status === "done").slice(-8);
	if (chain.length === 0) out.push(style.dim("  (无已完成节点)"));
	for (const i of chain) {
		out.push(clipAnsi(`  ${style.dim(i.id)} ${i.title}`, width));
	}

	out.push("");
	out.push(style.bold("最近事件"));
	if (snap.recent.length === 0) out.push(style.dim("  (空)"));
	for (const r of snap.recent.slice(-10)) {
		out.push(clipAnsi(`  ${style.dim(r.ts)} ${r.text}`, width));
	}

	out.push("");
	out.push(clipAnsi(style.dim("q / Esc 关闭 · r 刷新 · /nuwa status 文本看板"), width));
	return out;
}
