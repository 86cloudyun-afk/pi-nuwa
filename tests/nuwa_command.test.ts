import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** 最小 zod 链式替身。 */
function chain(): any {
	const f: any = (..._args: any[]) => chain();
	return new Proxy(f, {
		get: () => (..._args: any[]) => chain(),
	});
}
const z: any = new Proxy({}, { get: () => (..._args: any[]) => chain() });

let nuwaOmp: any;
let extractTarget: (t: string) => string | null;
let pickMode: (t: string) => string;
const dirs: string[] = [];

beforeAll(async () => {
	const home = mkdtempSync(join(tmpdir(), "nuwa-home-"));
	dirs.push(home);
	process.env.PI_AGENT_HOME = home;
	delete process.env.NUWA_TARGET;
	delete process.env.TARGET;
	// 动态导入是刻意的：PI_AGENT_HOME 在模块加载时求值，必须先改环境变量再载入。
	const mod: any = await import("../omp/nuwa");
	nuwaOmp = mod.default;
	extractTarget = mod.extractTarget;
	pickMode = mod.pickMode;
});

afterAll(() => {
	for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function setup(cwd: string, opts: { streaming?: boolean } = {}) {
	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...a: any[]) => any>>();
	let command: any = null;
	const sent: string[] = [];
	const notes: string[] = [];
	const pi: any = {
		zod: z,
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (name: string, o: any) => {
			command = { name, ...o };
		},
		on: (n: string, fn: (...a: any[]) => any) => {
			const l = hooks.get(n) ?? [];
			l.push(fn);
			hooks.set(n, l);
		},
		sendUserMessage: (text: string) => {
			if (opts.streaming) throw new Error("agent is streaming");
			sent.push(text);
		},
		sendMessage: (m: any) => {
			sent.push(String(m.content));
		},
	};
	nuwaOmp(pi);
	const ctx: any = {
		cwd,
		agent: { kind: "main" },
		sessionManager: { getSessionId: () => "sess-cmd" },
		getContextUsage: () => ({ tokens: 0, usedTokens: 0 }),
		ui: {
			notify: (t: string) => notes.push(t),
			setStatus() {},
		},
	};
	return { tools, hooks, ctx, sent, notes, run: (a: string) => command.handler(a, ctx) };
}

describe("extractTarget", () => {
	test("URL 优先，去掉尾标点", () => {
		expect(extractTarget("打 https://a.example.com:8443/app，拿 flag")).toBe("https://a.example.com:8443/app");
		expect(extractTarget("目标是 http://10.1.2.3:8080/")).toBe("http://10.1.2.3:8080/");
	});
	test("裸 IP 补 http 与默认端口", () => {
		expect(extractTarget("打 10.0.0.5")).toBe("http://10.0.0.5:80");
		expect(extractTarget("打 10.0.0.5:8080 拿 flag")).toBe("http://10.0.0.5:8080");
	});
	test("主机名可用，文件名不误判", () => {
		expect(extractTarget("渗透 demo.target.test")).toBe("http://demo.target.test:80");
		expect(extractTarget("审计 state.json 里的逻辑")).toBeNull();
		expect(extractTarget("看下 app.ts 的实现")).toBeNull();
	});
	test("环境变量兜底", () => {
		process.env.NUWA_TARGET = "http://env.target:9000";
		expect(extractTarget("打这个站")).toBe("http://env.target:9000");
		delete process.env.NUWA_TARGET;
	});
});

describe("pickMode", () => {
	test("语义分流", () => {
		expect(pickMode("对这个仓库做代码审计")).toBe("audit");
		expect(pickMode("内网渗透，先打点再提权")).toBe("pentest");
		expect(pickMode("打靶场拿 flag")).toBe("ctf");
	});
});

describe("/nuwa <任务>", () => {
	test("一句话开工：建项目 + 播种 recon + 注入起跑指令", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-cmd-"));
		dirs.push(dir);
		const { run, sent, notes } = setup(dir);

		await run("打 http://10.0.0.9:8080 拿 flag");

		const st = JSON.parse(readFileSync(join(dir, ".nuwa/state.json"), "utf8"));
		expect(st.project.url).toBe("http://10.0.0.9:8080");
		expect(st.project.status).toBe("active");
		expect(st.project.mode).toBe("ctf");
		expect(st.project.goal).toContain("拿 flag");
		expect(Object.values(st.intents).filter((i: any) => i.phase === "recon").length).toBeGreaterThanOrEqual(6);
		expect(sent.length).toBe(1);
		expect(sent[0]).toContain("[女娲 v");
		expect(sent[0]).toContain("nuwa_frontier");
		expect(sent[0]).toContain('agent:"fujiang"');
		expect(notes.join("\n")).toContain("女娲已上膛");
	});

	test("已有项目：任务并入为 priority=95 的意图，不重建", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-cmd-"));
		dirs.push(dir);
		const { run, sent } = setup(dir);
		await run("打 10.0.0.9:8080 拿 flag");
		sent.length = 0;
		await run("再补一个 SQL 注入验证");

		const st = JSON.parse(readFileSync(join(dir, ".nuwa/state.json"), "utf8"));
		const custom = Object.values(st.intents).filter((i: any) => i.key.startsWith("custom:")) as any[];
		expect(custom.length).toBe(1);
		expect(custom[0].priority).toBe(95);
		expect(custom[0].title).toContain("SQL 注入");
		expect(sent.length).toBe(1);
	});

	test("stop / resume / 看板", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-cmd-"));
		dirs.push(dir);
		const { run, sent, notes } = setup(dir);
		await run("打 10.0.0.9:8080");
		await run("stop 手工停");
		expect(JSON.parse(readFileSync(join(dir, ".nuwa/state.json"), "utf8")).project.status).toBe("stopped");
		expect(notes.at(-1)).toContain("已停止");

		sent.length = 0;
		await run("resume");
		expect(JSON.parse(readFileSync(join(dir, ".nuwa/state.json"), "utf8")).project.status).toBe("active");
		expect(sent[0]).toContain("[女娲 v");

		notes.length = 0;
		await run("status");
		expect(notes.at(-1)).toContain("recon");
	});

	test("无目标时给用法，不落状态", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-cmd-"));
		dirs.push(dir);
		const { run, notes, sent } = setup(dir);
		await run("帮我看看这个站");
		expect(existsSync(join(dir, ".nuwa/state.json"))).toBe(false);
		expect(notes.at(-1)).toContain("用法");
		expect(sent.length).toBe(0);
	});

	test("流式中回退到 sendMessage 仍能起跑", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-cmd-"));
		dirs.push(dir);
		const { run, sent } = setup(dir, { streaming: true });
		await run("打 10.0.0.9:8080");
		expect(sent.length).toBe(1);
		expect(sent[0]).toContain("[女娲 v");
	});

	test("审计模式按语义选 mode", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-cmd-"));
		dirs.push(dir);
		const { run } = setup(dir);
		await run("对 http://10.0.0.9:8080 做白盒审计");
		const st = JSON.parse(readFileSync(join(dir, ".nuwa/state.json"), "utf8"));
		expect(st.project.mode).toBe("audit");
	});
});
