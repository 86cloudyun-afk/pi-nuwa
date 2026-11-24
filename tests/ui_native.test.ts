/**
 * 2.4.0 原生节点测试：TSP 节点结构、supports 降级、describe 缓存、键盘关闭与 Issue #6 降级矩阵。
 */
import { describe, expect, test } from "bun:test";
import {
	commitIntent,
	newState,
	readCfg,
	seedPhase,
	type NuwaState,
} from "../omp/nuwa";
import { buildSnapshot, plainStyle } from "../omp/ui";
import {
	buildBoardNode,
	buildWidgetNode,
	createBoardComponent,
	createWidgetComponent,
	type NativeNode,
} from "../omp/ui-native";

const cfg = readCfg();

function fresh(): NuwaState {
	const st = newState("10.0.0.5:8080", "打穿并拿 flag", "ctf", cfg);
	seedPhase(st, "recon");
	return st;
}

function populated(): NuwaState {
	const st = fresh();
	const first = Object.values(st.intents)[0];
	commitIntent(st, {
		id: first.id,
		kind: "service",
		title: "HTTP 200",
		command: `curl -sS ${st.project.url}`,
		output: "HTTP/1.1 200 OK",
	});
	st.runtime.expansions = 1;
	st.runtime.stall = 1;
	return st;
}

function snapOf(st: NuwaState) {
	return buildSnapshot(st, cfg, 0.42, [
		{ ts: "12:00", type: "init", fact: "target up" },
		{ ts: "12:01", type: "commit", id: "i001", fact: "HTTP 200" },
	]);
}

const all = (): boolean => true;
const minimal = (k: string): boolean => ["card", "row", "col", "text", "section", "kv", "list", "item"].includes(k);

function kinds(node: NativeNode, out: string[] = []): string[] {
	out.push(node.k);
	for (const child of node.c ?? []) kinds(child, out);
	return out;
}

function texts(node: NativeNode, out: string[] = []): string[] {
	if (typeof node.p?.text === "string") out.push(node.p.text);
	for (const child of node.c ?? []) texts(child, out);
	return out;
}

function plainWidth(line: string): number {
	return Bun.stringWidth(line.replace(/\x1b\[[0-9;]*m/g, ""));
}

describe("widget 节点", () => {
	test("全支持时包含 progress 与 meter", () => {
		const node = buildWidgetNode(snapOf(fresh()), all);
		expect(node.k).toBe("card");
		const ks = kinds(node);
		expect(ks).toContain("row");
		expect(ks).toContain("kv");
		expect(ks).toContain("progress");
		expect(ks).toContain("meter");
		expect(ks).toContain("badge");
	});

	test("不支持 progress/meter 时降级为 text", () => {
		const node = buildWidgetNode(snapOf(fresh()), minimal);
		const ks = kinds(node);
		expect(ks).not.toContain("progress");
		expect(ks).not.toContain("meter");
		expect(ks).toContain("text");
	});

	test("describe 缓存同一节点引用", () => {
		const comp = createWidgetComponent(snapOf(fresh()), plainStyle, { lines: 3 });
		const a = comp.describe!({ supports: all, cols: 80, dark: true });
		const b = comp.describe!({ supports: all, cols: 80, dark: true });
		expect(a).toBe(b);
	});

	test("render 仍是 3 行字符串", () => {
		const comp = createWidgetComponent(snapOf(fresh()), plainStyle, { lines: 3 });
		const lines = comp.render(80);
		expect(lines.length).toBe(3);
		expect(lines[0]).toContain("recon");
	});
});

describe("board 节点", () => {
	test("全支持时包含 table 与 tree", () => {
		const node = buildBoardNode(snapOf(populated()), all);
		const ks = kinds(node);
		expect(ks).toContain("section");
		expect(ks).toContain("table");
		expect(ks).toContain("tree");
		expect(ks).toContain("list");
	});

	test("不支持 table/tree 时回退 text", () => {
		const ks = kinds(buildBoardNode(snapOf(populated()), minimal));
		expect(ks).not.toContain("table");
		expect(ks).not.toContain("tree");
		expect(ks).toContain("text");
	});

	test("q 关闭 board", () => {
		let closed = 0;
		const comp = createBoardComponent(snapOf(fresh()), plainStyle, () => {
			closed += 1;
		});
		comp.handleInput!("q");
		comp.handleInput!("\x1b");
		comp.handleInput!("j");
		expect(closed).toBe(2);
	});
});

describe("Issue #6 降级与窄宽度矩阵", () => {
	test("仅 table 缺失：阶段表降级 text，tree 保留", () => {
		const comp = createBoardComponent(snapOf(populated()), plainStyle, () => {});
		const node = comp.describe!({ supports: (k) => k !== "table", cols: 80, dark: true });
		const ks = kinds(node);
		expect(ks).not.toContain("table");
		expect(ks).toContain("tree");
		expect(texts(node).some((t) => t.includes("recon 1/6"))).toBe(true);
	});

	test("仅 tree 缺失：攻击链降级 text，table 保留", () => {
		const st = populated();
		const doneIntent = Object.values(st.intents).find((i) => i.status === "done")!;
		const comp = createBoardComponent(snapOf(st), plainStyle, () => {});
		const node = comp.describe!({ supports: (k) => k !== "tree", cols: 80, dark: true });
		const ks = kinds(node);
		expect(ks).toContain("table");
		expect(ks).not.toContain("tree");
		expect(texts(node).some((t) => t.includes(doneIntent.id) && t.includes(doneIntent.title))).toBe(true);
	});

	test("progress+meter 缺失：widget 降级为可读 text 指标", () => {
		const comp = createWidgetComponent(snapOf(populated()), plainStyle, { lines: 5 });
		const node = comp.describe!({
			supports: (k) => k !== "progress" && k !== "meter",
			cols: 80,
			dark: false,
		});
		const ks = kinds(node);
		expect(ks).not.toContain("progress");
		expect(ks).not.toContain("meter");
		const allText = texts(node);
		expect(allText.some((t) => t.includes("1/6"))).toBe(true);
		expect(allText.some((t) => t.includes("pressure 42%"))).toBe(true);
		expect(allText.some((t) => t.includes("expand 1"))).toBe(true);
	});

	test("badge+kv 缺失探针与全关降级不崩溃且输出合法 JSON", () => {
		const snap = snapOf(populated());
		const noBadgeKv = (k: string) => k !== "badge" && k !== "kv";
		const wNode = createWidgetComponent(snap, plainStyle).describe!({
			supports: noBadgeKv,
			cols: 80,
			dark: true,
		});
		const bNode = createBoardComponent(snap, plainStyle, () => {}).describe!({
			supports: noBadgeKv,
			cols: 80,
			dark: true,
		});
		expect(wNode.k).toBe("card");
		expect(bNode.k).toBe("card");
		expect(kinds(wNode)).toContain("progress");
		expect(kinds(wNode)).toContain("meter");
		expect(kinds(bNode)).toContain("table");
		expect(kinds(bNode)).toContain("tree");
		expect(() => JSON.stringify({ wNode, bNode })).not.toThrow();

		// 全能力返回 false 与 supports 抛异常时，安全降级所有可选原生原语
		const noneNodeW = buildWidgetNode(snap, () => false);
		const noneNodeB = buildBoardNode(snap, () => false);
		for (const bad of ["progress", "meter", "table", "tree"]) {
			expect(kinds(noneNodeW)).not.toContain(bad);
			expect(kinds(noneNodeB)).not.toContain(bad);
		}
		const throwing = createBoardComponent(snap, plainStyle, () => {}).describe!({
			supports: () => {
				throw new Error("probe error");
			},
			cols: 80,
		});
		expect(kinds(throwing)).not.toContain("table");
		expect(kinds(throwing)).not.toContain("tree");
	});

	test("16 组可选原语开关组合矩阵全覆盖", () => {
		const snap = snapOf(populated());
		const opts = ["table", "tree", "progress", "meter"] as const;
		for (let mask = 0; mask < 16; mask += 1) {
			const enabled = new Set<string>(["card", "row", "col", "text", "section", "kv", "badge", "list", "item"]);
			opts.forEach((opt, idx) => {
				if ((mask & (1 << idx)) !== 0) enabled.add(opt);
			});
			const supports = (k: string) => enabled.has(k);
			const wComp = createWidgetComponent(snap, plainStyle, { lines: 3 });
			const bComp = createBoardComponent(snap, plainStyle, () => {});
			const wNode = wComp.describe!({ supports, cols: 80, dark: mask % 2 === 0 });
			const bNode = bComp.describe!({ supports, cols: 80, dark: mask % 2 === 1 });
			const wk = kinds(wNode);
			const bk = kinds(bNode);
			expect(wk.includes("progress")).toBe(enabled.has("progress"));
			expect(wk.includes("meter")).toBe(enabled.has("meter"));
			expect(bk.includes("table")).toBe(enabled.has("table"));
			expect(bk.includes("tree")).toBe(enabled.has("tree"));
			expect(() => JSON.stringify([wNode, bNode])).not.toThrow();
		}
	});

	test("极窄宽度 (cols: 40) 下 widget/board describe 与 render 均不溢出", () => {
		const snap = snapOf(populated());
		const w3 = createWidgetComponent(snap, plainStyle, { lines: 3 });
		const w5 = createWidgetComponent(snap, plainStyle, { lines: 5 });
		const board = createBoardComponent(snap, plainStyle, () => {}, { width: 40 });

		expect(w3.describe!({ supports: all, cols: 40, dark: true }).k).toBe("card");
		expect(w5.describe!({ supports: minimal, cols: 40, dark: false }).k).toBe("card");
		expect(board.describe!({ supports: minimal, cols: 40, dark: false }).k).toBe("card");

		// invalidate 清缓存后重算返回新引用
		const before = board.describe!({ supports: minimal, cols: 40, dark: false });
		board.invalidate!();
		const after = board.describe!({ supports: all, cols: 40, dark: true });
		expect(after).not.toBe(before);
		expect(kinds(after)).toContain("table");

		const l3 = w3.render(40);
		const l5 = w5.render(40);
		const lb = board.render(40);
		expect(l3.length).toBe(3);
		expect(l5.length).toBe(5);
		expect(lb.length).toBeGreaterThan(5);
		for (const ln of [...l3, ...l5, ...lb]) {
			expect(plainWidth(ln)).toBeLessThanOrEqual(40);
		}
	});
});
