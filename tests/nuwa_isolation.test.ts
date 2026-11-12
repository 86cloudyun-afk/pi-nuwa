import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// 模块顶层会读 PI_AGENT_HOME，必须先固定测试 agent home，再动态导入。
const AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-isolation-agent-"));
const SHARED = mkdtempSync("/var/tmp/nuwa-shared-root-");
process.env.PI_AGENT_HOME = AGENT_HOME;
process.env.NUWA_SHARED_CWDS = SHARED;
delete process.env.NUWA_PROJECT;
const mod = await import("../omp/nuwa");

const dirs: string[] = [];
afterAll(() => {
	for (const d of dirs) rmSync(d, { recursive: true, force: true });
	rmSync(AGENT_HOME, { recursive: true, force: true });
	rmSync(SHARED, { recursive: true, force: true });
});

function base(): string {
	const d = mkdtempSync("/var/tmp/nuwa-isolation-");
	dirs.push(d);
	return d;
}

function makeState(root: string, owner?: string, url?: string): void {
	mkdirSync(join(root, ".nuwa"), { recursive: true });
	writeFileSync(join(root, ".nuwa", "state.json"), JSON.stringify({
		schema: 1,
		project: { id: "p", url, target: url, ownerSessionId: owner, phase: "recon" },
	}));
}

type RegisteredTool = {
	name: string;
	execute: (...args: unknown[]) => Promise<{ details?: Record<string, unknown> }>;
};

function captureTools(): Map<string, RegisteredTool> {
	const chain = (): unknown => {
		const f = (..._args: unknown[]) => chain();
		return new Proxy(f, { get: () => (..._args: unknown[]) => chain() });
	};
	const z = new Proxy({}, { get: () => (..._args: unknown[]) => chain() });
	const tools = new Map<string, RegisteredTool>();
	const pi = {
		zod: z,
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		registerTool: (t: RegisteredTool) => tools.set(t.name, t),
		registerCommand: () => {},
		on: () => {},
	};
	// 测试只依赖工具注册面，这里按注册表形状做一次性断言。
	mod.default(pi as unknown as Parameters<typeof mod.default>[0]);
	return tools;
}

function makeCtx(cwd: string, sid: string): Record<string, unknown> {
	return {
		cwd,
		agent: { kind: "main" },
		sessionManager: { getSessionId: () => sid },
		getContextUsage: () => ({ tokens: 0, usedTokens: 0 }),
		ui: { notify() {}, setStatus() {} },
	};
}

beforeEach(() => {
	rmSync(join(AGENT_HOME, "cache", "nuwa-current.d"), { recursive: true, force: true });
	rmSync(join(AGENT_HOME, "cache", "nuwa-current.json"), { force: true });
	rmSync(join(AGENT_HOME, "cache", "nuwa-projects"), { recursive: true, force: true });
	rmSync(SHARED, { recursive: true, force: true });
	mkdirSync(SHARED, { recursive: true });
});

describe("v2 会话/项目隔离", () => {
	test("按 sessionId 写独立指针，互不覆盖", () => {
		const root = base();
		const a = join(root, "a");
		const b = join(root, "b");
		mkdirSync(a, { recursive: true });
		mkdirSync(b, { recursive: true });
		makeState(a, "sess-A");
		makeState(b, "sess-B");
		mod.writePointer(a, "sess-A");
		mod.writePointer(b, "sess-B");
		const scratch = join(root, "scratch");
		mkdirSync(scratch, { recursive: true });
		expect(mod.findRoot(scratch, "sess-A")).toBe(a);
		expect(mod.findRoot(scratch, "sess-B")).toBe(b);
		expect(mod.findRoot(scratch, "sess-C")).toBeNull();
	});

	test("具名会话不接管空 sessionId 的 legacy 指针", () => {
		const root = base();
		const a = join(root, "a");
		mkdirSync(a, { recursive: true });
		makeState(a, "sess-A");
		mod.writePointer(a, "");
		const scratch = join(root, "scratch");
		mkdirSync(scratch, { recursive: true });
		// legacy 只服务无会话调用；具名会话必须走自己的指针。
		expect(mod.findRoot(scratch)).toBe(a);
		expect(mod.findRoot(scratch, "sess-A")).toBeNull();
	});

	test("有 sessionId 时不写全局 legacy 指针", () => {
		const root = base();
		makeState(root, "sess-A");
		mod.writePointer(root, "sess-A");
		expect(existsSync(join(AGENT_HOME, "cache", "nuwa-current.json"))).toBe(false);
		expect(existsSync(join(AGENT_HOME, "cache", "nuwa-current.d"))).toBe(true);
	});

	test("其他会话的 state 直接拒绝，不向上找父图", () => {
		const root = base();
		const project = join(root, "project");
		const child = join(project, "child");
		mkdirSync(child, { recursive: true });
		makeState(project, "sess-A");
		expect(mod.findRoot(child, "sess-B")).toBeNull();
		expect(mod.findRoot(project, "sess-A")).toBe(project);
	});

	test("共享 cwd 按 target + session 分配不同项目根", () => {
		expect(mod.isSharedCwd(tmpdir())).toBe(true);
		const a = mod.defaultProjectRoot(tmpdir(), "10.0.0.5:8080", "sess-A");
		const b = mod.defaultProjectRoot(tmpdir(), "10.0.0.5:8080", "sess-B");
		expect(resolve(a)).not.toBe(resolve(tmpdir()));
		expect(resolve(a)).not.toBe(resolve(b));
		expect(resolve(a).startsWith(resolve(AGENT_HOME, "cache", "nuwa-projects"))).toBe(true);
	});

	test("nuwa_init 在共享 /tmp 不写 /tmp/.nuwa", async () => {
		const chain = (): any => {
			const f: any = (..._args: any[]) => chain();
			return new Proxy(f, {
				get: () => (..._args: any[]) => chain(),
			});
		};
		const z: any = new Proxy({}, { get: () => (..._args: any[]) => chain() });
		const tools = new Map<string, any>();
		const pi: any = {
			zod: z,
			logger: { debug() {}, info() {}, warn() {}, error() {} },
			registerTool: (t: any) => tools.set(t.name, t),
			registerCommand: () => {},
			on: () => {},
		};
		mod.default(pi);
		const ctx: any = {
			cwd: tmpdir(),
			agent: { kind: "main" },
			sessionManager: { getSessionId: () => "sess-shared" },
			getContextUsage: () => ({ tokens: 0, usedTokens: 0 }),
			ui: { notify() {}, setStatus() {} },
		};
		const res = await tools.get("nuwa_init").execute(
			"call-1",
			{ target: "10.0.0.9:8080", mode: "ctf" },
			undefined,
			undefined,
			ctx,
		);
		const root = res.details.root as string;
		expect(resolve(root)).not.toBe(resolve(tmpdir()));
		expect(existsSync(join(root, ".nuwa", "state.json"))).toBe(true);
		expect(resolve(root).startsWith(resolve(AGENT_HOME, "cache", "nuwa-projects"))).toBe(true);

		const res2 = await tools.get("nuwa_init").execute(
			"call-2",
			{ target: "10.0.0.10:8080", mode: "ctf" },
			undefined,
			undefined,
			ctx,
		);
		const root2 = res2.details.root as string;
		expect(resolve(root2)).not.toBe(resolve(root));
		const st2 = JSON.parse(readFileSync(join(root2, ".nuwa", "state.json"), "utf8"));
		expect(st2.project.url).toBe("http://10.0.0.10:8080");
	});

	test("共享根的项目不向子目录继承", () => {
		makeState(SHARED, "sess-A", "http://10.0.0.9:8080");
		mod.writePointer(SHARED, "sess-A");
		const sub = join(SHARED, "sub");
		mkdirSync(sub, { recursive: true });
		expect(mod.findRoot(sub, "sess-A")).toBeNull();
		expect(mod.findRoot(SHARED, "sess-A")).toBe(SHARED);
	});

	test("共享根被别的会话占用时，落到本会话指针", () => {
		makeState(SHARED, "sess-other", "http://10.0.0.66:8080");
		mod.writePointer(SHARED, "sess-other");
		const own = base();
		makeState(own, "sess-A", "http://10.0.0.9:8080");
		mod.writePointer(own, "sess-A");
		expect(mod.findRoot(SHARED, "sess-A")).toBe(own);
		expect(mod.findRoot(SHARED, "sess-other")).toBe(SHARED);
		expect(mod.findRoot(SHARED, "sess-none")).toBeNull();
	});

	test("共享根同会话换目标：开新根，旧 state 不动", () => {
		makeState(SHARED, "sess-A", "http://10.0.0.9:8080");
		const before = readFileSync(join(SHARED, ".nuwa", "state.json"), "utf8");
		const next = mod.defaultProjectRoot(SHARED, "10.0.0.10:8080", "sess-A");
		expect(resolve(next)).not.toBe(resolve(SHARED));
		expect(resolve(next).startsWith(resolve(AGENT_HOME, "cache", "nuwa-projects"))).toBe(true);
		expect(readFileSync(join(SHARED, ".nuwa", "state.json"), "utf8")).toBe(before);
	});

	test("共享根同会话同目标：复用原根", () => {
		makeState(SHARED, "sess-A", "http://10.0.0.9:8080");
		expect(mod.defaultProjectRoot(SHARED, "http://10.0.0.9:8080", "sess-A")).toBe(SHARED);
	});

	test("非共享 cwd 第二目标落 .nuwa-tasks", () => {
		const dir = base();
		makeState(dir, "sess-A", "http://10.0.0.9:8080");
		const next = mod.defaultProjectRoot(dir, "10.0.0.10:8080", "sess-A");
		expect(resolve(next)).not.toBe(resolve(dir));
		expect(resolve(next).startsWith(join(resolve(dir), ".nuwa-tasks"))).toBe(true);
		expect(mod.defaultProjectRoot(dir, "10.0.0.9:8080", "sess-A")).toBe(dir);
	});

	test("nuwa_init 在共享根换目标不覆盖旧项目", async () => {
		makeState(SHARED, "sess-A", "http://10.0.0.9:8080");
		const before = readFileSync(join(SHARED, ".nuwa", "state.json"), "utf8");
		const tools = captureTools();
		const res = await tools.get("nuwa_init")!.execute(
			"call-x",
			{ target: "10.0.0.11:8080", mode: "ctf" },
			undefined,
			undefined,
			makeCtx(SHARED, "sess-A"),
		);
		const root = String(res.details?.root ?? "");
		expect(resolve(root)).not.toBe(resolve(SHARED));
		expect(readFileSync(join(SHARED, ".nuwa", "state.json"), "utf8")).toBe(before);
		const st = JSON.parse(readFileSync(join(root, ".nuwa", "state.json"), "utf8"));
		expect(st.project.url).toBe("http://10.0.0.11:8080");
	});
});
