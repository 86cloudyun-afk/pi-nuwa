import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import nuwaOmp from "../omp/nuwa";

/** 最小 zod 链式替身：只验证注册与执行路径，不做 schema 校验。 */
function chain(): any {
	const f: any = (..._args: any[]) => chain();
	return new Proxy(f, {
		get: (_t, prop) => {
			if (prop === "optional" || prop === "default" || prop === "describe" || prop === "nullable") {
				return (..._args: any[]) => chain();
			}
			return (..._args: any[]) => chain();
		},
	});
}
const z: any = new Proxy(
	{},
	{
		get: () => (..._args: any[]) => chain(),
	},
);

const dirs: string[] = [];
afterAll(() => {
	for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function setup(cwd: string) {
	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	const pi: any = {
		zod: z,
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: () => {},
		on: (name: string, fn: (...args: any[]) => any) => {
			const list = hooks.get(name) ?? [];
			list.push(fn);
			hooks.set(name, list);
		},
	};
	nuwaOmp(pi);
	const ctx: any = {
		cwd,
		agent: { kind: "main", id: "Main", name: "main", depth: 0 },
		sessionManager: { getSessionId: () => "sess-test" },
		getContextUsage: () => ({ tokens: 1234, usedTokens: 1234 }),
		ui: { setStatus() {}, notify() {} },
	};
	const call = (name: string, args: any) => tools.get(name).execute("call-1", args, undefined, undefined, ctx);
	return { tools, hooks, ctx, call };
}

describe("extension wiring", () => {
	test("注册 11 个工具与 3 类事件", () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-omp-"));
		dirs.push(dir);
		const { tools, hooks } = setup(dir);
		expect(tools.size).toBe(11);
		for (const n of [
			"nuwa_init",
			"nuwa_plan",
			"nuwa_frontier",
			"nuwa_claim",
			"nuwa_commit",
			"nuwa_flag",
			"nuwa_complete",
			"nuwa_status",
			"nuwa_report",
			"nuwa_stop",
			"nuwa_kb",
		]) {
			expect(tools.has(n)).toBe(true);
		}
		expect(hooks.get("session_stop")?.length).toBe(1);
		expect(hooks.get("tool_call")?.length).toBe(1);
		expect(hooks.get("tool_execution_end")?.length).toBe(1);
	});

	test("完整生命周期：init → claim → commit → flag → complete → report", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-omp-"));
		dirs.push(dir);
		const { call, hooks, ctx } = setup(dir);

		const init = await call("nuwa_init", { target: "10.0.0.5:8080", goal: "拿 flag", mode: "ctf" });
		expect(init.content[0].text).toContain("女娲已上膛");
		expect(existsSync(join(dir, ".nuwa/state.json"))).toBe(true);

		const claim = await call("nuwa_claim", { id: "i001" });
		expect(claim.content[0].text).toContain("[女娲派单 i001]");

		const commit = await call("nuwa_commit", {
			id: "i001",
			kind: "service",
			title: "HTTP 200 nginx",
			detail: "server: nginx",
			command: "curl -k -sS -D - http://10.0.0.5:8080",
			output: "HTTP/1.1 200 OK\nServer: nginx",
		});
		expect(commit.content[0].text).toContain("已入账 f001");

		const flag = await call("nuwa_flag", {
			value: "flag{omp_native}",
			command: "curl -sS http://10.0.0.5:8080/flag",
			output: "flag{omp_native}",
		});
		expect(flag.content[0].text).toContain("f002");

		const done = await call("nuwa_complete", {});
		expect(done.content[0].text).toContain("完成已验收");

		const report = await call("nuwa_report", { write: true });
		expect(report.content[0].text).toContain("flag{omp_native}");
		expect(existsSync(join(dir, ".nuwa/REPORT.md"))).toBe(true);
		expect(readFileSync(join(dir, ".nuwa/REPORT.md"), "utf8")).toContain("## Flag 台账");

		const status = await call("nuwa_status", {});
		expect(status.content[0].text).toContain("completed");
	});

	test("tool_call 拦截：主线程扫描 / 子代理记账 / 写 state", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-omp-"));
		dirs.push(dir);
		const { call, hooks, ctx } = setup(dir);
		await call("nuwa_init", { target: "10.0.0.5:8080", mode: "ctf" });
		const guard = hooks.get("tool_call")![0];

		const scan = guard({ toolName: "bash", input: { command: "nmap -sV 10.0.0.5" } }, ctx);
		expect(scan?.block).toBe(true);
		expect(scan?.reason).toContain("N-001");

		const cli = guard({ toolName: "bash", input: { command: "bin/nuwa http://x" } }, ctx);
		expect(cli?.block).toBe(true);
		expect(cli?.reason).toContain("N-002");

		const write = guard({ toolName: "write", input: { path: join(dir, ".nuwa/state.json"), content: "x" } }, ctx);
		expect(write?.block).toBe(true);
		expect(write?.reason).toContain("N-003");

		const sub: any = { ...ctx, agent: { kind: "sub", id: "0-fujiang", name: "fujiang", depth: 1 } };
		const subCommit = guard({ toolName: "nuwa_commit", input: {} }, sub);
		expect(subCommit?.block).toBe(true);
		expect(subCommit?.reason).toContain("N-005");

		const badTask = guard({ toolName: "task", input: { tasks: [{ agent: "task", task: "x" }] } }, ctx);
		expect(badTask?.block).toBe(true);
		expect(badTask?.reason).toContain("N-004");
	});

	test("session_stop 注入续跑指令", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-omp-"));
		dirs.push(dir);
		const { call, hooks, ctx } = setup(dir);
		await call("nuwa_init", { target: "10.0.0.5:8080", mode: "ctf" });
		const stop = hooks.get("session_stop")![0];
		const ev: any = { session_id: "sess-test", stop_hook_active: false };
		const res = await stop(ev, ctx);
		expect(res?.decision).toBe("block");
		expect(res?.reason).toContain("nuwa_claim");
		expect(res?.reason).toContain("fujiang");
	});

	test("stop 后不再续跑", async () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-omp-"));
		dirs.push(dir);
		const { call, hooks, ctx } = setup(dir);
		await call("nuwa_init", { target: "10.0.0.5:8080", mode: "ctf" });
		await call("nuwa_stop", { reason: "测试停机" });
		const stop = hooks.get("session_stop")![0];
		const res = await stop({ session_id: "sess-test", stop_hook_active: false } as any, ctx);
		expect(res).toBeUndefined();
	});
});
