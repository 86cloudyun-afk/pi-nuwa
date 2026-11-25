/**
 * Tern 原生渲染层（v5.x）。
 *
 * 不 import @oh-my-pi/pi-tui：该包的入口依赖 pi-natives 原生模块，扩展目录解析会失败。
 * 这里直接构造 TSP 节点（纯 JSON），组件只暴露 render() 与 describe()：
 * - 普通终端 / TUI：只调 render()，走 ui.ts 的字符串渲染。
 * - Tern：调 describe(cx)，按 cx.supports() 逐项降级成原生 card / progress / meter / table / tree / list。
 */
import {
	renderBoardLines,
	renderWidgetLines,
	type UiSnapshot,
	type UiStyle,
} from "./ui";

export interface NativeNode {
	k: string;
	p?: Record<string, unknown>;
	c?: NativeNode[];
	key?: string;
}

export interface NativeDescribeContext {
	supports(kind: string): boolean;
	cols: number;
	dark?: boolean;
}

export interface NativeComponent {
	render(width: number): readonly string[];
	describe?(cx: NativeDescribeContext): NativeNode;
	handleInput?(data: string): void;
	invalidate?(): void;
	dispose?(): void;
}

export interface WidgetNativeOptions {
	lines?: 3 | 5;
}

function phaseTone(phase: string, edgeBlocked = false): string {
	if (edgeBlocked) return "error";
	switch (phase) {
		case "vuln":
			return "warning";
		case "exploit":
		case "post":
			return "accent";
		default:
			return "muted";
	}
}

function statusTone(status: string, edgeBlocked = false): string {
	if (status === "completed") return "success";
	if (status === "sealed_negative") return "warning";
	if (status === "stopped") return "error";
	if (edgeBlocked) return "error";
	return "accent";
}

function batchLabel(snap: UiSnapshot): string {
	if (snap.frontier.length) return snap.frontier.map((f) => f.id).join(" ");
	const claimed = snap.intents.filter((i) => i.status === "claimed").slice(0, 4).map((i) => i.id);
	return claimed.length ? `${claimed.join(" ")} (claimed)` : "(空)";
}

/** mini 看板的原生节点：card > row(badge/progress/episode/last_ok) + kv + row(meter/turns)。 */
export function buildWidgetNode(
	snap: UiSnapshot,
	supports: (kind: string) => boolean = () => true,
): NativeNode {
	const cur = snap.phases.find((p) => p.phase === snap.project.phase);
	const done = cur?.done ?? 0;
	const blocked = cur?.blocked ?? 0;
	const total = cur?.total ?? 0;
	const frac = total > 0 ? Math.min(1, (done + blocked) / total) : 0;
	const pressure = Math.min(1, Math.max(0, snap.runtime.pressure));
	const mins = Math.max(0, Math.floor((Date.now() - snap.runtime.startedAt) / 60_000));
	const edgeBlocked = snap.probe?.edgeBlocked ?? false;
	const lastOk = snap.probe?.lastOk ?? "none";
	const blkPct = Math.round((snap.probe?.blockedRatio ?? 0) * 100);
	const bi = snap.totals.blockedIntents ?? snap.totals.blocked;
	const bc = snap.totals.blockedCommits ?? bi;

	const phaseBadgeText =
		snap.project.status === "sealed_negative"
			? `${snap.project.phase} · 已封盘`
			: edgeBlocked
				? `${snap.project.phase} · 边缘受阻`
				: snap.project.phase;

	const row1: NativeNode[] = [
		{ k: "badge", p: { text: phaseBadgeText, tone: phaseTone(snap.project.phase, edgeBlocked) } },
	];
	if (supports("progress")) {
		row1.push({ k: "progress", p: { value: frac, label: `${done}/${total}` } });
	} else {
		row1.push({ k: "text", p: { text: `${done}/${total}` } });
	}
	row1.push({ k: "text", p: { text: `E${snap.project.episode}`, tone: "muted" } });
	row1.push({
		k: "text",
		p: {
			text: `last_ok=${lastOk} · blocked_ratio=${blkPct}%`,
			tone: edgeBlocked ? "error" : "muted",
		},
	});

	const row3: NativeNode[] = [];
	if (supports("meter")) {
		row3.push({
			k: "meter",
			p: {
				value: pressure,
				style: "bar",
				size: "sm",
				thresholds: { warn: 0.75, bad: 0.9 },
				label: `${Math.round(pressure * 100)}%`,
			},
		});
	} else {
		row3.push({ k: "text", p: { text: `pressure ${Math.round(pressure * 100)}%` } });
	}
	row3.push({ k: "text", p: { text: `turns ${snap.runtime.turns} · ${mins}min`, tone: "muted" } });

	const body: NativeNode[] = [
		{ k: "row", p: { gap: "sm", align: "center" }, c: row1 },
		{
			k: "kv",
			p: {
				layout: "inline",
				items: [
					{ k: "批", v: batchLabel(snap) },
					{ k: "claim", v: String(snap.totals.claimed) },
					{ k: "facts", v: String(snap.totals.facts) },
					{ k: "blocked", v: `${bi}/${bc}` },
					{ k: "last_ok", v: lastOk },
					{ k: "blocked_ratio", v: `${blkPct}%` },
					{ k: "rate", v: `${snap.rate.toFixed(1)}/min` },
				],
			},
		},
		{ k: "row", p: { gap: "sm", align: "center" }, c: row3 },
	];

	if ((snap.runtime.expansions ?? 0) > 0 || snap.runtime.stall > 0 || (snap.runtime.noveltyStall ?? 0) > 0) {
		body.push({
			k: "text",
			p: {
				text: `expand ${snap.runtime.expansions} · stall ${snap.runtime.stall} · novelty_stall ${snap.runtime.noveltyStall ?? 0} · idle ${snap.runtime.idle}`,
				tone: "dim",
			},
		});
	}

	return {
		k: "card",
		p: {
			title: `女娲 · ${snap.project.host}:${snap.project.port}${edgeBlocked ? " · 边缘受阻" : ""}`,
			tone: statusTone(snap.project.status, edgeBlocked),
		},
		c: body,
	};
}

function phaseRows(snap: UiSnapshot): NativeNode {
	const edgeBlocked = snap.probe?.edgeBlocked ?? false;
	const lastOk = snap.probe?.lastOk ?? "none";
	const rows = snap.phases.map((p) => {
		const isCurEdge = edgeBlocked && p.phase === snap.project.phase;
		const phSettled = p.done + p.blocked;
		const phBlkPct = phSettled > 0 ? Math.round((p.blocked / phSettled) * 100) : 0;
		return {
			id: p.phase,
			cells: {
				state: p.total > 0 && p.done + p.blocked === p.total ? "✓" : isCurEdge ? "⚠" : p.open + p.claimed > 0 ? "●" : "○",
				phase: isCurEdge ? `${p.phase} (边缘受阻)` : p.phase,
				progress: `${p.done}/${p.total}`,
				extra: isCurEdge
					? `边缘受阻 · last_ok=${lastOk} · blocked_ratio=${phBlkPct}%`
					: p.claimed > 0
						? `claim ${p.claimed}`
						: p.blocked > 0
							? `blocked ${p.blocked} (${phBlkPct}%)`
							: "",
			},
		};
	});
	return {
		k: "table",
		p: {
			cols: [
				{ id: "state", head: "", align: "start", priority: 9 },
				{ id: "phase", head: "阶段", align: "start", priority: 9 },
				{ id: "progress", head: "进度", align: "end", priority: 8 },
				{ id: "extra", head: "", align: "start", priority: 3, truncate: "end" },
			],
			rows,
		},
	};
}

/** `/nuwa board` 的原生节点：card > 阶段表 + frontier 列表 + 攻击链树 + 事件流。 */
export function buildBoardNode(
	snap: UiSnapshot,
	supports: (kind: string) => boolean = () => true,
): NativeNode {
	const p = snap.project;
	const mins = Math.max(0, Math.floor((Date.now() - snap.runtime.startedAt) / 60_000));
	const edgeBlocked = snap.probe?.edgeBlocked ?? false;
	const lastOk = snap.probe?.lastOk ?? "none";
	const blkPct = Math.round((snap.probe?.blockedRatio ?? 0) * 100);
	const stageLabel = snap.probe?.stageLabel ?? p.phase;
	const bi = snap.totals.blockedIntents ?? snap.totals.blocked;
	const bc = snap.totals.blockedCommits ?? bi;
	const sections: NativeNode[] = [];

	sections.push({
		k: "kv",
		p: {
			layout: "grid",
			items: [
				{ k: "目标", v: p.url },
				{ k: "模式", v: p.mode },
				{ k: "轮次", v: `E${p.episode} · ${mins}min · turns ${snap.runtime.turns}` },
				{ k: "压力", v: `${Math.round(snap.runtime.pressure * 100)}%${snap.infinite ? " · ∞" : ""}` },
				{ k: "探测状态", v: `${stageLabel} · last_ok=${lastOk} · blocked_ratio=${blkPct}%` },
				{ k: "受阻与去重", v: `blocked=${bi}/${bc} · repeat=${(snap.totals.repeatRatio * 100).toFixed(1)}%` },
			],
		},
	});

	const fallbackStageText =
		snap.phases.map((x) => `${x.phase} ${x.done}/${x.total}`).join(" · ") +
		` · last_ok=${lastOk} · blocked_ratio=${blkPct}%${edgeBlocked ? " · 边缘受阻" : ""}`;

	sections.push({
		k: "section",
		p: { head: "阶段" },
		c: [supports("table") ? phaseRows(snap) : { k: "text", p: { text: fallbackStageText } }],
	});

	if (snap.frontier.length) {
		sections.push({
			k: "section",
			p: { head: "frontier" },
			c: [
				{
					k: "list",
					c: snap.frontier.map((f) => ({
						k: "item",
						p: { label: `${f.id}  ${f.title}`, detail: `p${f.priority}`, value: f.phase },
					})),
				},
			],
		});
	}

	const done = snap.intents.filter((i) => i.status === "done").slice(-10);
	if (done.length) {
		if (supports("tree")) {
			sections.push({
				k: "section",
				p: { head: "攻击链" },
				c: [
					{
						k: "tree",
						p: {
							nodes: done.map((i) => ({
								id: i.id,
								label: `${i.id}  ${i.title}`,
								open: false,
							})),
						},
					},
				],
			});
		} else {
			sections.push({
				k: "section",
				p: { head: "攻击链" },
				c: [{ k: "text", p: { text: done.map((i) => `${i.id} ${i.title}`).join("\n") } }],
			});
		}
	}

	if (snap.recent.length) {
		sections.push({
			k: "section",
			p: { head: "最近事件" },
			c: [
				{
					k: "list",
					c: snap.recent.slice(-10).map((r) => ({ k: "item", p: { label: `${r.ts}  ${r.text}` } })),
				},
			],
		});
	}

	sections.push({ k: "text", p: { text: "q / Esc 关闭", tone: "dim" } });

	return {
		k: "card",
		p: {
			title: `女娲 ${p.id} · ${p.status}${edgeBlocked ? " · 边缘受阻" : ""}`,
			tone: statusTone(p.status, edgeBlocked),
		},
		c: sections,
	};
}

/** widget 组件：Tern 走 describe，其他走字符串。 */
export function createWidgetComponent(
	snap: UiSnapshot,
	style: UiStyle,
	opts: WidgetNativeOptions = {},
): NativeComponent {
	let cached: NativeNode | null = null;
	return {
		render(width: number) {
			return renderWidgetLines(snap, style, { width, lines: opts.lines ?? 3 });
		},
		describe(cx: NativeDescribeContext) {
			cached ??= buildWidgetNode(snap, (k) => safeSupports(cx, k));
			return cached;
		},
		invalidate() {
			cached = null;
		},
	};
}

/** board 组件：Tern 走 describe；q/Esc 关闭。 */
export function createBoardComponent(
	snap: UiSnapshot,
	style: UiStyle,
	done: () => void,
	opts: { width?: number; maxIntents?: number } = {},
): NativeComponent {
	let cached: NativeNode | null = null;
	return {
		render(width: number) {
			return renderBoardLines(snap, style, { width: opts.width ?? width, maxIntents: opts.maxIntents });
		},
		describe(cx: NativeDescribeContext) {
			cached ??= buildBoardNode(snap, (k) => safeSupports(cx, k));
			return cached;
		},
		handleInput(data: string) {
			if (data === "q" || data === "\x1b") done();
		},
		invalidate() {
			cached = null;
		},
		dispose() {
			/* 无外部资源 */
		},
	};
}

function safeSupports(cx: NativeDescribeContext, kind: string): boolean {
	try {
		return cx.supports(kind);
	} catch {
		return false;
	}
}
