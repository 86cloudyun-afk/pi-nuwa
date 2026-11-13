/**
 * 2.3.0 可视化测试：快照、状态行、mini 看板、看板、宽度截断、提交速率。
 */
import { describe, expect, test } from "bun:test";
import {
	commitIntent,
	newState,
	readCfg,
	seedPhase,
	type NuwaState,
} from "../omp/nuwa";
import {
	buildSnapshot,
	clipAnsi,
	commitRate,
	parseJournalTail,
	plainStyle,
	renderBoardLines,
	renderStatusLine,
	renderWidgetLines,
	sparkline,
	visibleWidth,
	type JournalEntry,
} from "../omp/ui";

const cfg = readCfg();

function fresh(): NuwaState {
	const st = newState("10.0.0.5:8080", "打穿并拿 flag", "ctf", cfg);
	seedPhase(st, "recon");
	return st;
}

function commitFirst(st: NuwaState, id?: string): void {
	const it = Object.values(st.intents).find((i) => i.status === "open" && (!id || i.id === id))!;
	commitIntent(st, {
		id: it.id,
		kind: "service",
		title: "HTTP 200 nginx",
		detail: "server: nginx",
		command: `curl -k -sS -D - ${st.project.url}/`,
		output: "HTTP/1.1 200 OK\nServer: nginx",
	});
}

describe("buildSnapshot", () => {
	test("阶段、总数与 frontier", () => {
		const st = fresh();
		const snap = buildSnapshot(st, cfg, 0.2);
		expect(snap.project.phase).toBe("recon");
		expect(snap.project.episode).toBe(1);
		expect(snap.phases.length).toBe(1);
		expect(snap.phases[0]).toMatchObject({ phase: "recon", open: 6, total: 6 });
		expect(snap.totals.intents).toBe(6);
		expect(snap.totals.open).toBe(6);
		expect(snap.totals.facts).toBe(0);
		expect(snap.frontier.length).toBe(Math.min(4, cfg.maxBatch));
		expect(snap.infinite).toBe(true);
	});

	test("commit 后 facts/done 增长", () => {
		const st = fresh();
		commitFirst(st);
		const snap = buildSnapshot(st, cfg, 0.1);
		expect(snap.totals.facts).toBe(1);
		expect(snap.totals.done).toBe(1);
		expect(snap.phases[0].done).toBe(1);
	});

	test("frontier 排除未到期 claim", () => {
		const st = fresh();
		const first = Object.values(st.intents)[0];
		first.status = "claimed";
		first.claimedAt = new Date().toISOString();
		const snap = buildSnapshot(st, cfg, 0);
		expect(snap.frontier.some((f) => f.id === first.id)).toBe(false);
	});
});

describe("状态行与 widget", () => {
	test("状态行包含阶段、计数与永动标记", () => {
		const st = fresh();
		commitFirst(st);
		const line = renderStatusLine(buildSnapshot(st, cfg, 0.42), plainStyle);
		expect(line).toContain("女娲");
		expect(line).toContain("recon");
		expect(line).toContain("1/6");
		expect(line).toContain("E1");
		expect(line).toContain("∞");
		expect(visibleWidth(line)).toBeLessThanOrEqual(48);
	});

	test("widget 默认 3 行，5 行模式追加趋势与扩张", () => {
		const st = fresh();
		const snap = buildSnapshot(st, cfg, 0.55);
		const three = renderWidgetLines(snap, plainStyle, { width: 96 });
		expect(three.length).toBe(3);
		expect(three[0]).toContain("recon");
		expect(three[1]).toContain("批");
		expect(three[2]).toContain("pressure");
		const five = renderWidgetLines(snap, plainStyle, { width: 96, lines: 5 });
		expect(five.length).toBe(5);
		expect(five[3]).toContain("commits/8min");
		expect(five[4]).toContain("expand");
		for (const line of five) expect(visibleWidth(line)).toBeLessThanOrEqual(96);
	});

	test("窄宽度不溢出", () => {
		const st = fresh();
		const snap = buildSnapshot(st, cfg, 0.9);
		for (const line of renderWidgetLines(snap, plainStyle, { width: 40 })) {
			expect(visibleWidth(line)).toBeLessThanOrEqual(40);
		}
	});
});

describe("看板", () => {
	test("包含阶段、frontier、攻击链、事件流", () => {
		const st = fresh();
		commitFirst(st);
		const snap = buildSnapshot(st, cfg, 0.3, [
			{ ts: new Date().toISOString(), type: "commit", fact: "f001", id: "i001" },
		]);
		const lines = renderBoardLines(snap, plainStyle, { width: 80 });
		const text = lines.join("\n");
		expect(text).toContain("阶段");
		expect(text).toContain("frontier");
		expect(text).toContain("攻击链");
		expect(text).toContain("最近事件");
		expect(text).toContain("recon");
		expect(text).toContain("f001");
		expect(text).toContain("q / Esc 关闭");
		for (const line of lines) expect(visibleWidth(line)).toBeLessThanOrEqual(80);
	});

	test("空项目也有结构", () => {
		const st = fresh();
		const snap = buildSnapshot(st, cfg, 0);
		const text = renderBoardLines(snap, plainStyle, { width: 80 }).join("\n");
		expect(text).toContain("阶段");
		expect(text).toContain("frontier");
	});
});

describe("宽度与 ANSI", () => {
	test("CJK 宽度按双宽计", () => {
		expect(visibleWidth("女娲")).toBe(4);
		expect(visibleWidth("abc")).toBe(3);
	});

	test("截断保留 ANSI 并补 reset", () => {
		const clipped = clipAnsi("\x1b[31mabcdef\x1b[0m", 4);
		expect(visibleWidth(clipped)).toBeLessThanOrEqual(4);
		expect(clipped.endsWith("\x1b[0m")).toBe(true);
		expect(clipAnsi("短", 10)).toBe("短");
	});

	test("sparkline 长度与极值", () => {
		expect(sparkline([])).toBe("");
		const s = sparkline([0, 1, 2, 3]);
		expect([...s].length).toBe(4);
		expect(s.startsWith("▁")).toBe(true);
		expect(s.endsWith("█")).toBe(true);
	});
});

describe("journal 解析与速率", () => {
	test("跳过 snapshot，保留事件", () => {
		const raw = [
			{ type: "init", id: "p" },
			{ type: "snapshot", state: { big: true } },
			{ type: "commit", id: "i001", fact: "f001" },
		]
			.map((x) => JSON.stringify(x))
			.join("\n");
		const out = parseJournalTail(raw, 10);
		expect(out.length).toBe(2);
		expect(out.map((e) => e.type)).toEqual(["init", "commit"]);
	});

	test("commitRate 按分钟分桶", () => {
		const now = Date.now();
		const entries: JournalEntry[] = [
			{ type: "commit", ts: new Date(now - 30_000).toISOString() },
			{ type: "commit", ts: new Date(now - 90_000).toISOString() },
			{ type: "claim", ts: new Date(now - 30_000).toISOString() },
		];
		const { rate, sparks } = commitRate(entries, now, 8);
		expect(rate).toBeCloseTo(2 / 8, 5);
		expect(sparks.length).toBe(8);
		expect(sparks[7]).toBe(1);
		expect(sparks[6]).toBe(1);
	});
});
