/**
 * 女娲可视化：状态快照 + 纯渲染函数 + 全量不截断状态导出。
 *
 * 设计约束（见 docs/UI-DESIGN.md）：
 * - 不 import 运行时业务模块（storage/graph/nuwa），只 import 共享纯类型与 node:fs/node:path（供只读状态加载），杜绝循环依赖。
 * - 不 import @oh-my-pi/pi-tui：扩展目录没有 node_modules，包解析失败会拖垮整个扩展。
 * - 所有渲染函数接受 UiStyle，测试用 plainStyle，运行时用 themeStyle(theme)。
 * - 先拼纯文本再上色，截断按可见宽度计算（ANSI 感知），CJK 用 Bun.stringWidth。
 */
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { NuwaSqliteStore, loadStateFromSqlite, resolveStorageBackend, sqliteDbPath } from "./sqlite-store";
import type { Cfg, Fact, FactKind, Intent, NuwaState, Phase, SealMeta } from "./types";

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

export interface ProbeHealthSummary {
	/** 最近一次成功探测状态码（如 "200"）或 "none"（#38）。 */
	lastOk: string;
	/** 已结案意图中的受阻占比 0..1（#38）。 */
	blockedRatio: number;
	/** 尾部连续 403/blocked 次数（#38）。 */
	consecutiveEdgeBlocks: number;
	/** 是否处于连续 403/blocked 边缘受阻状态（#38）。 */
	edgeBlocked: boolean;
	/** 直观阶段健康标签，区分正常阶段推进、边缘受阻与负向封盘（#38, #22）。 */
	stageLabel: string;
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
		sealMeta?: SealMeta;
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
		/** 当前处于 blocked 状态的票据数（#49）。 */
		blockedIntents: number;
		/** 历史累计 blocked=true 提交总次数（#49）。 */
		blockedCommits: number;
		/** 最近一次 blockedIntents 增量（#49）。 */
		blockedIntentsDelta: number;
		/** 最近一次 blockedCommits 增量（#49）。 */
		blockedCommitsDelta: number;
		/** 重复尝试比率 1 - distinct/total（#21）。 */
		repeatRatio: number;
		/** 已结案受阻比率 blocked / (done + blocked)（#38）。 */
		blockedRatio: number;
	};
	probe: ProbeHealthSummary;
	frontier: FrontierRow[];
	intents: IntentRow[];
	runtime: {
		turns: number;
		stall: number;
		noveltyStall: number;
		idle: number;
		pressure: number;
		expansions: number;
		startedAt: number;
		tokens?: number;
		totalTokens?: number;
		blockedCommits: number;
		repeatRatio: number;
		status: string;
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
		case "commit_free":
			return `+ ${fact || "?"} (free)`;
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
		case "seal":
			return `⊘ sealed: ${String(e.reason ?? "")}`.trim();
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
		if ((e.type !== "commit" && e.type !== "commit_free") || !e.ts) continue;
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
		.filter((i) => !(i.status === "open" && typeof i.nextRunAt === "number" && i.nextRunAt > now))
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

function normalizeUiTargetKey(raw: string, defaultHost = ""): string {
	const text = (raw ?? "").trim().replace(/^(?:port|path|host):/i, "").trim();
	if (!text) return defaultHost ? defaultHost.toLowerCase() : "/";
	if (text.startsWith("/")) {
		const qIdx = text.indexOf("?");
		const pathPart = (qIdx >= 0 ? text.slice(0, qIdx) : text).replace(/\/{2,}/g, "/");
		const cleanPath = pathPart.length > 1 ? pathPart.replace(/\/+$/, "") : "/";
		if (qIdx < 0) return cleanPath;
		const params = new URLSearchParams(text.slice(qIdx + 1));
		params.sort();
		const qs = params.toString();
		return qs ? `${cleanPath}?${qs}` : cleanPath;
	}
	const tcpMatch = /^(?:([a-zA-Z0-9.-]+):)?(\d{1,5})(?:\/(?:tcp|udp))?$/i.exec(text);
	if (tcpMatch) {
		const h = (tcpMatch[1] || defaultHost || "port").toLowerCase();
		return tcpMatch[1] || defaultHost ? `${h}:${tcpMatch[2]}` : `port:${tcpMatch[2]}`;
	}
	if (/^https?:\/\//i.test(text)) {
		try {
			const u = new URL(text);
			const host = u.hostname.toLowerCase();
			const port = u.port && !((u.protocol === "http:" && u.port === "80") || (u.protocol === "https:" && u.port === "443")) ? `:${u.port}` : "";
			const cleanPath = u.pathname.replace(/\/{2,}/g, "/");
			const normPath = cleanPath.length > 1 ? cleanPath.replace(/\/+$/, "") : cleanPath;
			const params = new URLSearchParams(u.search);
			params.sort();
			const qs = params.toString() ? `?${params.toString()}` : "";
			if ((normPath && normPath !== "/") || qs) {
				if (defaultHost && host === defaultHost.toLowerCase() && !port) return `${normPath}${qs}`;
				return `${host}${port}${normPath}${qs}`;
			}
			return `${host}${port}`;
		} catch {
			return text.toLowerCase();
		}
	}
	return text.toLowerCase();
}

function inferUiSemanticAttemptKey(it: Intent, host: string): string {
	const kind: FactKind =
		it.expectedKind ??
		(it.phase === "recon"
			? "service"
			: it.phase === "surface"
				? "endpoint"
				: it.phase === "vuln" || it.phase === "exploit"
					? "vuln"
					: it.phase === "post"
						? "loot"
						: "note");
	if (it.targetKey) {
		return `${kind}|${normalizeUiTargetKey(it.targetKey, host)}`;
	}
	const canonKey = it.key.replace(/^e\d+:/i, "");
	const epMatch = /^ep:[^:]+:(.+)$/.exec(canonKey);
	if (epMatch) return `${kind}|${normalizeUiTargetKey(epMatch[1]!, host)}`;
	const svcMatch = /^svc:[^:]+:(\d{1,5})$/.exec(canonKey);
	if (svcMatch) return `service|${normalizeUiTargetKey(`${host}:${svcMatch[1]!}`, host)}`;
	const sanMatch = /^san:[^:]+:(.+)$/.exec(canonKey);
	if (sanMatch) return `asset|${normalizeUiTargetKey(sanMatch[1]!, host)}`;
	const titlePath = it.title.match(/(\/[A-Za-z0-9._~/-]{1,100})/)?.[1];
	if (titlePath) return `${kind}|${normalizeUiTargetKey(titlePath, host)}`;
	const titleHostPort = it.title.match(/\b([a-zA-Z0-9.-]+:\d{1,5})\b/)?.[1];
	if (titleHostPort) return `${kind}|${normalizeUiTargetKey(titleHostPort, host)}`;
	return `${kind}|seed:${canonKey}`;
}

function computeUiRepeatRatio(st: NuwaState): number {
	const intents = Object.values(st.intents ?? {});
	const host = st.project?.host ?? "";
	const sigs: string[] = intents.map((it) => inferUiSemanticAttemptKey(it, host));
	const attemptedMap = st.runtime?.attemptedKeys ?? {};
	const currentIds = new Set(sigs);
	// 补充已被 compactIntents 清理但仍在 attemptedKeys 留痕的不同目标
	for (const entry of Object.values(attemptedMap)) {
		const sig = `${entry.expectedKind}|${normalizeUiTargetKey(entry.targetKey, host)}`;
		if (!currentIds.has(sig)) {
			sigs.push(sig);
			currentIds.add(sig);
		}
	}
	const total = Math.max(intents.length, sigs.length);
	if (total === 0) return 0;
	const distinct = new Set(sigs).size;
	return Math.max(0, Math.min(1, Number((1 - distinct / total).toFixed(4))));
}

function extractFactHttpCode(f: Fact): number | null {
	if (typeof f.meta?.status === "number" && f.meta.status >= 100 && f.meta.status <= 599) {
		return f.meta.status;
	}
	const blob = `${f.title ?? ""}\n${f.detail ?? ""}\n${f.output ?? ""}`;
	const m =
		/\bHTTP\/[\d.]+\s+(\d{3})\b/i.exec(blob) ??
		/\bFINAL\s+(\d{3})\b/.exec(blob) ??
		/\bcode=(\d{3})\b/i.exec(blob) ??
		/\bHTTP\s+(\d{3})\b/i.exec(blob);
	if (!m) return null;
	const code = Number(m[1]);
	return code >= 100 && code <= 599 ? code : null;
}

function isEdgeBlockCode(code: number | null): boolean {
	return code === 403 || code === 429 || code === 503;
}

function isEdgeBlockedIntent(it: Intent, facts: Record<string, Fact>): boolean {
	if (it.status === "blocked") {
		return true;
	}
	if (it.status === "done" && it.to && facts[it.to]) {
		const code = extractFactHttpCode(facts[it.to]!);
		if (code === 403 || code === 429) return true;
	}
	return false;
}

function hasExplicitEdgeSignal(it: Intent, facts: Record<string, Fact>): boolean {
	const note = `${it.note ?? ""} ${it.title ?? ""}`;
	if (/\b(?:403|429|waf|cloudflare|turnstile|forbidden|egress_blocked|blocked_by_waf|被墙|拦截)\b/i.test(note)) {
		return true;
	}
	if (it.to && facts[it.to]) {
		const code = extractFactHttpCode(facts[it.to]!);
		if (isEdgeBlockCode(code)) return true;
	}
	return false;
}

/** 提取探测健康摘要：last_ok 状态码、blocked_ratio 与连续 403/blocked 边缘受阻判定（#38）。 */
export function extractProbeHealth(st: NuwaState, _entries: JournalEntry[] = []): ProbeHealthSummary {
	const facts = Object.values(st.facts ?? {}).sort(
		(a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id),
	);
	let lastOk = "none";
	for (const f of facts) {
		if (f.kind === "blocked" || f.verifyStage === "rejected") continue;
		const code = extractFactHttpCode(f);
		if (code !== null) {
			if (!isEdgeBlockCode(code) && code > 0) {
				lastOk = String(code);
			}
		} else if (f.kind !== "note" && lastOk === "none") {
			lastOk = "ok";
		}
	}

	const intents = Object.values(st.intents ?? {});
	const doneCount = intents.filter((i) => i.status === "done").length;
	const blockedIntents = intents.filter((i) => i.status === "blocked").length;
	const blockedCommits = typeof st.runtime?.blockedCommits === "number" ? st.runtime.blockedCommits : blockedIntents;
	const effectiveBlocked = Math.max(blockedIntents, blockedCommits);
	const settled = doneCount + effectiveBlocked;
	const blockedRatio = settled > 0 ? Math.min(1, Math.max(0, Number((effectiveBlocked / settled).toFixed(4)))) : 0;

	const settledIntents = intents
		.filter((i) => i.status === "done" || i.status === "blocked")
		.sort((a, b) => (a.doneAt ?? a.createdAt).localeCompare(b.doneAt ?? b.createdAt) || a.id.localeCompare(b.id));

	let consecutiveEdgeBlocks = 0;
	let explicitEdgeHits = 0;
	for (let idx = settledIntents.length - 1; idx >= 0; idx--) {
		const it = settledIntents[idx]!;
		if (isEdgeBlockedIntent(it, st.facts ?? {})) {
			consecutiveEdgeBlocks += 1;
			if (hasExplicitEdgeSignal(it, st.facts ?? {})) explicitEdgeHits += 1;
		} else {
			break;
		}
	}

	const projStatus = st.runtime?.status === "sealed_negative" ? "sealed_negative" : st.project.status;
	const edgeBlocked =
		projStatus === "active" &&
		((consecutiveEdgeBlocks >= 2 && (explicitEdgeHits >= 1 || lastOk === "none")) ||
			(consecutiveEdgeBlocks >= 3) ||
			(consecutiveEdgeBlocks >= 1 && explicitEdgeHits >= 1 && lastOk === "none"));

	let stageLabel: string = st.project.phase;
	if (projStatus === "sealed_negative") {
		stageLabel = "已封盘(sealed_negative)";
	} else if (projStatus === "completed") {
		stageLabel = "已完成(completed)";
	} else if (projStatus === "stopped") {
		stageLabel = "已停止(stopped)";
	} else if (edgeBlocked) {
		stageLabel = "边缘受阻(403/blocked)";
	}

	return {
		lastOk,
		blockedRatio,
		consecutiveEdgeBlocks,
		edgeBlocked,
		stageLabel,
	};
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
	const blockedIntents = intents.filter((i) => i.status === "blocked").length;
	const blockedCommits =
		typeof st.runtime.blockedCommits === "number" ? st.runtime.blockedCommits : blockedIntents;
	const blockedIntentsDelta = st.runtime.lastBlockedIntentsDelta ?? 0;
	const blockedCommitsDelta = st.runtime.lastBlockedCommitsDelta ?? 0;
	const repeatRatio = computeUiRepeatRatio(st);
	const probe = extractProbeHealth(st, entries);
	const effectiveStatus =
		st.runtime.status === "sealed_negative" || st.project.status === "sealed_negative"
			? "sealed_negative"
			: st.runtime.status === "completed" || st.project.status === "completed"
				? "completed"
				: st.project.status;
	const sealMeta = st.runtime.sealMeta ?? st.project.sealMeta;

	return {
		project: {
			id: st.project.id,
			url: st.project.url,
			host: st.project.host,
			port: st.project.port,
			mode: st.project.mode,
			status: effectiveStatus,
			phase: st.project.phase,
			goal: st.project.goal,
			episode: st.project.episode ?? 1,
			...(sealMeta ? { sealMeta } : {}),
		},
		phases,
		totals: {
			facts: Object.keys(st.facts).length,
			flags: Object.values(st.facts).filter((f) => f.kind === "flag").length,
			intents: intents.length,
			open: intents.filter((i) => i.status === "open").length,
			claimed: intents.filter((i) => i.status === "claimed").length,
			done: intents.filter((i) => i.status === "done").length,
			blocked: blockedIntents,
			blockedIntents,
			blockedCommits,
			blockedIntentsDelta,
			blockedCommitsDelta,
			repeatRatio,
			blockedRatio: probe.blockedRatio,
		},
		probe,
		frontier: frontierOf(st, cfg),
		intents: intents
			.sort((a, b) => a.id.localeCompare(b.id))
			.slice(0, 200)
			.map((i) => ({ id: i.id, title: i.title, phase: i.phase, status: i.status, priority: i.priority })),
		runtime: {
			turns: st.runtime.turns,
			stall: st.runtime.stall,
			noveltyStall: st.runtime.noveltyStall ?? 0,
			idle: st.runtime.idle,
			pressure,
			expansions: st.runtime.expansions ?? 0,
			startedAt: st.runtime.startedAt,
			tokens: st.runtime.tokens ?? 0,
			totalTokens: (st.runtime.totalTokens ?? 0) + (st.runtime.tokens ?? 0),
			blockedCommits,
			repeatRatio,
			status:
				effectiveStatus === "sealed_negative" || effectiveStatus === "completed"
					? effectiveStatus
					: (st.runtime.status ?? effectiveStatus),
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
		w +=
			code >= 0x1100 &&
			(code <= 0x115f ||
				(code >= 0x2e80 && code <= 0xa4cf) ||
				(code >= 0xac00 && code <= 0xd7a3) ||
				(code >= 0xf900 && code <= 0xfaff) ||
				(code >= 0xfe30 && code <= 0xfe4f) ||
				(code >= 0xff00 && code <= 0xff60) ||
				(code >= 0xffe0 && code <= 0xffe6) ||
				(code >= 0x1f300 && code <= 0x1faff))
				? 2
				: 1;
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

function statusMark(status: string, edgeBlocked = false): string {
	if (status === "completed") return "✓";
	if (status === "sealed_negative") return "⊘";
	if (status === "stopped") return "■";
	if (edgeBlocked) return "⚠";
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

/**
 * 状态栏一行，默认 ≤ 48 列（Tern 状态栏上限），同时紧凑呈现阶段、进度、E轮次、永动标记、
 * last_ok=<status|none>、blockedIntents/blockedCommits 增量及受阻比率与边缘受阻标记（#38, #49）。
 */
export function renderStatusLine(
	snap: UiSnapshot,
	style: UiStyle,
	opts?: { maxWidth?: number },
): string {
	const maxWidth = opts?.maxWidth ?? 48;
	const cur = snap.phases.find((p) => p.phase === snap.project.phase);
	const done = cur?.done ?? 0;
	const total = cur?.total ?? 0;
	const pressure = Math.round(snap.runtime.pressure * 100);
	const tail = snap.infinite ? "∞" : `${pressure}%`;
	const edgeBlocked = snap.probe?.edgeBlocked ?? false;
	const lastOk = snap.probe?.lastOk ?? "none";
	const blkPct = Math.round((snap.probe?.blockedRatio ?? 0) * 100);
	const bi = snap.totals.blockedIntents ?? snap.totals.blocked;
	const bc = snap.totals.blockedCommits ?? bi;
	const bcDelta = snap.totals.blockedCommitsDelta ?? 0;
	const biDelta = snap.totals.blockedIntentsDelta ?? 0;

	const markColor: UiColor =
		snap.project.status === "completed"
			? "success"
			: edgeBlocked
				? "error"
				: snap.project.status === "active"
					? "success"
					: "warning";
	const mark = style.fg(markColor, statusMark(snap.project.status, edgeBlocked));
	const phaseText = edgeBlocked
		? style.fg("error", `${snap.project.phase}阻`)
		: style.fg(phaseColor(snap.project.phase), snap.project.phase);

	if (maxWidth > 64) {
		const deltaPart = bcDelta !== 0 || biDelta !== 0 ? `(+${biDelta}/+${bcDelta})` : "";
		const stageExtra = edgeBlocked ? ` · ${style.fg("error", "边缘受阻")}` : "";
		const wide = `${style.fg("accent", "女娲")} ${mark} ${phaseText}${stageExtra} · ${done}/${total} · E${snap.project.episode} · ${tail} · last_ok=${lastOk} · blocked_ratio=${blkPct}% · blocked=${bi}/${bc}${deltaPart}`;
		return clipAnsi(wide, maxWidth);
	}

	const deltaTag = bcDelta > 0 ? `+${bcDelta}` : "";
	const blkSegment = `b=${bi}/${bc}${deltaTag}(${blkPct}%)`;
	const candidate = `${style.fg("accent", "女娲")}${mark}${phaseText} ${done}/${total} E${snap.project.episode}${tail} last_ok=${lastOk} ${blkSegment}`;
	if (visibleWidth(candidate) <= maxWidth) {
		return candidate;
	}
	const compact = `${style.fg("accent", "女娲")}${mark}${phaseText} ${done}/${total} E${snap.project.episode}${tail} last_ok=${lastOk} b=${bi}/${bc}`;
	return clipAnsi(compact, maxWidth);
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
	const edgeBlocked = snap.probe?.edgeBlocked ?? false;
	const lastOk = snap.probe?.lastOk ?? "none";
	const blkPct = Math.round((snap.probe?.blockedRatio ?? 0) * 100);
	const bi = snap.totals.blockedIntents ?? snap.totals.blocked;
	const bc = snap.totals.blockedCommits ?? bi;

	const head = [
		`${style.bold(style.fg("accent", "女娲"))} ${style.fg(edgeBlocked ? "error" : snap.project.status === "active" ? "success" : "warning", statusMark(snap.project.status, edgeBlocked))}`,
		edgeBlocked ? style.fg("error", `${snap.project.phase}[边缘受阻]`) : style.fg(phaseColor(snap.project.phase), snap.project.phase),
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
		style.dim(`blocked ${bi}/${bc}`),
		style.dim(`facts ${snap.totals.facts}`),
		snap.rate > 0 ? style.fg("success", `${snap.rate.toFixed(1)}/min`) : style.dim("0/min"),
	].join(" · ");
	const third = style.dim(
		`pressure ${pressure}% · turns ${snap.runtime.turns} · ${mins}min · last_ok=${lastOk} · blocked_ratio=${blkPct}%`,
	);
	const out = [clipAnsi(head, width), clipAnsi(second, width), clipAnsi(third, width)];
	if (lines >= 5) {
		out.push(clipAnsi(`${style.fg("success", sparkline(snap.sparks))} ${style.dim("commits/8min")}`, width));
		out.push(
			clipAnsi(
				style.dim(
					`expand ${snap.runtime.expansions} · stall ${snap.runtime.stall} · novelty_stall ${snap.runtime.noveltyStall ?? 0} · idle ${snap.runtime.idle}`,
				),
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
	const lastOk = snap.probe?.lastOk ?? "none";
	const blkPct = Math.round((snap.probe?.blockedRatio ?? 0) * 100);
	const bi = snap.totals.blockedIntents ?? snap.totals.blocked;
	const bc = snap.totals.blockedCommits ?? bi;
	const stageLabel = snap.probe?.stageLabel ?? p.phase;
	const out: string[] = [];
	const title = `女娲 ${p.id} · ${p.mode} · ${p.status} · E${p.episode}`;
	out.push(clipAnsi(style.bold(style.fg("accent", title)), width));
	out.push(clipAnsi(style.dim(`目标 ${p.url} · ${mins}min · turns ${snap.runtime.turns} · pressure ${pressure}%`), width));
	out.push(
		clipAnsi(
			snap.probe?.edgeBlocked
				? style.fg("error", `探测 ${stageLabel} · last_ok=${lastOk} · blocked_ratio=${blkPct}% · blocked=${bi}/${bc}`)
				: style.dim(`探测 ${stageLabel} · last_ok=${lastOk} · blocked_ratio=${blkPct}% · blocked=${bi}/${bc} · repeat=${(snap.totals.repeatRatio * 100).toFixed(1)}%`),
			width,
		),
	);
	out.push(style.dim("─".repeat(Math.max(10, Math.min(width, 72)))));

	out.push(style.bold("阶段"));
	const barW = Math.max(6, Math.min(14, Math.floor(width * 0.16)));
	for (const ph of snap.phases) {
		const bar = (() => {
			const filled = ph.total > 0 ? Math.round(((ph.done + ph.blocked) / ph.total) * barW) : 0;
			return style.fg("success", "█".repeat(filled)) + style.fg("dim", "░".repeat(Math.max(0, barW - filled)));
		})();
		const counts = `${ph.done}/${ph.total}`;
		const isCurEdgeBlocked = snap.probe?.edgeBlocked && ph.phase === p.phase;
		const extra = isCurEdgeBlocked
			? style.fg("error", ` 边缘受阻(${ph.blocked})`)
			: ph.claimed > 0
				? style.fg("warning", ` claim ${ph.claimed}`)
				: ph.blocked > 0
					? style.fg("error", ` blocked ${ph.blocked}`)
					: "";
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

// ---------------------------------------------------------------------------
// 全量不截断状态导出 renderFullStatus（#34）
// ---------------------------------------------------------------------------

export interface FullStatusOptions {
	raw?: boolean;
	offset?: number;
	limit?: number;
	format?: "text" | "json";
}

function readStateReadOnly(root: string): { state: NuwaState; entries: JournalEntry[] } {
	const normRoot = resolve(root);
	const backend = resolveStorageBackend(normRoot);
	const dbFile = sqliteDbPath(normRoot);
	let state: NuwaState | null = null;
	let loadedFromSqlite = false;
	if ((backend === "sqlite" || backend === "dual") && existsSync(dbFile)) {
		try {
			state = loadStateFromSqlite(normRoot);
			loadedFromSqlite = Boolean(state);
		} catch {
			state = null;
		}
	}
	if (!state) {
		const sp = join(normRoot, ".nuwa", "state.json");
		if (!existsSync(sp)) {
			throw new Error(
				`未找到状态文件: ${(backend === "sqlite" || backend === "dual") && existsSync(dbFile) ? dbFile : sp}`,
			);
		}
		state = JSON.parse(readFileSync(sp, "utf8")) as NuwaState;
	}
	let entries: JournalEntry[] = [];
	if (loadedFromSqlite || ((backend === "sqlite" || backend === "dual") && existsSync(dbFile))) {
		let store: NuwaSqliteStore | null = null;
		try {
			store = new NuwaSqliteStore(normRoot, { readonly: true });
			entries = store.readJournalTail(200) as JournalEntry[];
		} catch {
			entries = [];
		} finally {
			store?.close();
		}
	}
	if (entries.length === 0) {
		const jp = join(normRoot, ".nuwa", "journal.jsonl");
		if (existsSync(jp)) {
			try {
				const rawJ = readFileSync(jp, "utf8");
				entries = parseJournalTail(rawJ.length > 2_000_000 ? rawJ.slice(-2_000_000) : rawJ, 200);
			} catch {
				entries = [];
			}
		}
	}
	return { state, entries };
}

/**
 * 不截断全量状态渲染（#34）：
 * 支持传入 root 目录路径（纯只读零磁盘写入）或内存 NuwaState 对象，支持分页与 text/json 双格式输出，
 * 彻底消除 768B 单行硬截断与固定列宽省略。
 */
export function renderFullStatus(rootOrState: string | NuwaState, opts: FullStatusOptions = {}): string {
	const { state: st, entries } =
		typeof rootOrState === "string" ? readStateReadOnly(rootOrState) : { state: rootOrState, entries: [] };

	const format = opts.format ?? "text";
	const raw = opts.raw ?? false;
	const offset = Math.max(0, Math.floor(opts.offset ?? 0));

	const allIntents = Object.values(st.intents ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const allFacts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const defaultLimit = raw ? Math.max(allIntents.length, allFacts.length, 1000) : 100;
	const limit = opts.limit !== undefined ? Math.max(1, Math.floor(opts.limit)) : defaultLimit;

	const slicedIntents = allIntents.slice(offset, offset + limit);
	const slicedFacts = allFacts.slice(offset, offset + limit);

	const blockedIntents = allIntents.filter((i) => i.status === "blocked").length;
	const blockedCommits =
		typeof st.runtime?.blockedCommits === "number" ? st.runtime.blockedCommits : blockedIntents;
	const repeatRatio = computeUiRepeatRatio(st);
	const probe = extractProbeHealth(st, entries);
	const effectiveStatus =
		st.runtime?.status === "sealed_negative" || st.project.status === "sealed_negative"
			? "sealed_negative"
			: st.runtime?.status === "completed" || st.project.status === "completed"
				? "completed"
				: st.project.status;
	const sealMeta = st.runtime?.sealMeta ?? st.project.sealMeta;
	const curTokens = st.runtime?.tokens ?? 0;
	const totalTokensAgg = (st.runtime?.totalTokens ?? 0) + curTokens;

	const phases = UI_PHASES.map((phase) => {
		const xs = allIntents.filter((i) => i.phase === phase);
		return {
			phase,
			open: xs.filter((i) => i.status === "open").length,
			claimed: xs.filter((i) => i.status === "claimed").length,
			done: xs.filter((i) => i.status === "done").length,
			blocked: xs.filter((i) => i.status === "blocked").length,
			total: xs.length,
		};
	});

	const hasMore = offset + limit < allIntents.length || offset + limit < allFacts.length;

	if (format === "json") {
		return JSON.stringify(
			{
				project: {
					...st.project,
					status: effectiveStatus,
					...(sealMeta ? { sealMeta } : {}),
				},
				runtime: {
					...st.runtime,
					status:
						effectiveStatus === "sealed_negative" || effectiveStatus === "completed"
							? effectiveStatus
							: (st.runtime?.status ?? effectiveStatus),
					tokens: curTokens,
					totalTokens: totalTokensAgg,
					noveltyStall: st.runtime?.noveltyStall ?? 0,
					blockedCommits,
				},
				metrics: {
					repeatRatio,
					blockedIntents,
					blockedCommits,
					blockedRatio: probe.blockedRatio,
					lastOk: probe.lastOk,
					edgeBlocked: probe.edgeBlocked,
					stageLabel: probe.stageLabel,
				},
				phases,
				pagination: {
					raw,
					offset,
					limit,
					totalIntents: allIntents.length,
					totalFacts: allFacts.length,
					returnedIntents: slicedIntents.length,
					returnedFacts: slicedFacts.length,
					hasMore,
					nextOffset: hasMore ? offset + limit : null,
				},
				intents: slicedIntents,
				facts: slicedFacts,
			},
			null,
			2,
		);
	}

	const lines: string[] = [
		`=== 女娲全量状态 (${st.project.id}) ===`,
		`目标: ${st.project.url} (${st.project.mode}) · status=${effectiveStatus} · phase=${st.project.phase} · episode=E${st.project.episode ?? 1}`,
		`任务目标: ${st.project.goal}`,
		`探测健康: stage=${probe.stageLabel} · last_ok=${probe.lastOk} · blocked_ratio=${(probe.blockedRatio * 100).toFixed(1)}% · edge_blocked=${probe.edgeBlocked}`,
		`运行计数: turns=${st.runtime?.turns ?? 0} · tokens=${curTokens} · totalTokens=${totalTokensAgg} · stall=${st.runtime?.stall ?? 0} · noveltyStall=${st.runtime?.noveltyStall ?? 0} · idle=${st.runtime?.idle ?? 0} · rejects=${st.runtime?.completionRejects ?? 0}`,
		`去重与受阻: repeatRatio=${repeatRatio.toFixed(4)} · blockedIntents=${blockedIntents} · blockedCommits=${blockedCommits} · facts=${allFacts.length} · intents=${allIntents.length}`,
	];

	if (sealMeta) {
		lines.push(
			`封盘元数据: sealedAt=${sealMeta.sealedAt} · reason=${sealMeta.reason} · excludedSurface=[${sealMeta.excludedSurface.join(", ")}]`,
		);
	}

	lines.push("", "[阶段明细]");
	for (const ph of phases) {
		if (ph.total === 0 && !raw) continue;
		lines.push(
			`- ${ph.phase}: open=${ph.open} claimed=${ph.claimed} done=${ph.done} blocked=${ph.blocked} total=${ph.total}`,
		);
	}

	lines.push("", `[事实列表 offset=${offset} limit=${limit} total=${allFacts.length}]`);
	if (slicedFacts.length === 0) {
		lines.push("- (无)");
	} else {
		for (const f of slicedFacts) {
			const detailStr = raw ? f.detail : f.detail.replace(/\s+/g, " ").trim();
			lines.push(
				`- ${f.id} [${f.kind}${f.verifyStage ? `:${f.verifyStage}` : ""}] ${f.title} :: ${detailStr}${f.evidenceRef ? ` (ref=${f.evidenceRef})` : ""}`,
			);
		}
	}

	lines.push("", `[意图列表 offset=${offset} limit=${limit} total=${allIntents.length}]`);
	if (slicedIntents.length === 0) {
		lines.push("- (无)");
	} else {
		for (const it of slicedIntents) {
			const notePart = it.note ? ` | note=${raw ? it.note : it.note.replace(/\s+/g, " ").trim()}` : "";
			const domainPart = it.surfaceDomain ? ` domain=${it.surfaceDomain}` : "";
			const targetPart = it.targetKey ? ` target=${it.targetKey}` : "";
			const kindPart = it.expectedKind ? ` expected=${it.expectedKind}` : "";
			lines.push(
				`- ${it.id} [${it.phase}|${it.status}|P${it.priority}] key=${it.key}${kindPart}${domainPart}${targetPart} :: ${it.title}${notePart}`,
			);
		}
	}

	lines.push(
		"",
		`[分页游标] offset=${offset} limit=${limit} hasMore=${hasMore}${hasMore ? ` nextOffset=${offset + limit}` : ""}`,
	);

	return lines.join("\n");
}
