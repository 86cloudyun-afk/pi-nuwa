/**
 * 2.4.0 原生节点测试：TSP 节点结构、supports 降级、describe 缓存、键盘关闭。
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

function snapOf(st: NuwaState) {
	return buildSnapshot(st, cfg, 0.42);
}

const all = (): boolean => true;
const minimal = (k: string): boolean => ["card", "row", "col", "text", "section", "kv", "list", "item"].includes(k);

function kinds(node: NativeNode, out: string[] = []): string[] {
	out.push(node.k);
	for (const child of node.c ?? []) kinds(child, out);
	return out;
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
		const st = fresh();
		const first = Object.values(st.intents)[0];
		commitIntent(st, {
			id: first.id,
			kind: "service",
			title: "HTTP 200",
			command: `curl -sS ${st.project.url}`,
			output: "HTTP/1.1 200 OK",
		});
		const node = buildBoardNode(snapOf(st), all);
		const ks = kinds(node);
		expect(ks).toContain("section");
		expect(ks).toContain("table");
		expect(ks).toContain("tree");
		expect(ks).toContain("list");
	});

	test("不支持 table/tree 时回退 text", () => {
		const st = fresh();
		const first = Object.values(st.intents)[0];
		commitIntent(st, {
			id: first.id,
			kind: "service",
			title: "HTTP 200",
			command: `curl -sS ${st.project.url}`,
			output: "HTTP/1.1 200 OK",
		});
		const ks = kinds(buildBoardNode(snapOf(st), minimal));
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
