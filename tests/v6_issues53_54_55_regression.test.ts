import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as graphMod from "../omp/graph";
import * as nuwaMod from "../omp/nuwa";
import * as reportingMod from "../omp/reporting";
import * as scopeMod from "../omp/scope";
import * as uiMod from "../omp/ui";
import { NuwaCoreEngine } from "../core/mcp-server";

const DAEMON_BIN = resolve(import.meta.dir, "..", "bin", "nuwa-autonomous");

const tmpDirs: string[] = [];
const savedEnv: Record<string, string | undefined> = {};

function setEnvTemp(key: string, val: string | undefined): void {
	if (!(key in savedEnv)) savedEnv[key] = process.env[key];
	if (val === undefined) delete process.env[key];
	else process.env[key] = val;
}

function makeWorkspace(prefix = "nuwa-issue-reg-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	mkdirSync(join(dir, ".git"), { recursive: true });
	writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
	tmpDirs.push(dir);
	return dir;
}

function makeCleanDaemonEnv(extra: Record<string, string | undefined> = {}): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(process.env)) {
		if (v === undefined) continue;
		if (
			k.startsWith("NUWA_") &&
			k !== "NUWA_WORK" &&
			k !== "NUWA_STORAGE_BACKEND"
		) {
			continue;
		}
		if (["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"].includes(k)) {
			continue;
		}
		out[k] = v;
	}
	for (const [k, v] of Object.entries(extra)) {
		if (v === undefined) delete out[k];
		else out[k] = v;
	}
	return out;
}

function writeExecutableStub(dir: string, filename: string, content: string): string {
	const p = join(dir, filename);
	writeFileSync(p, content, "utf8");
	chmodSync(p, 0o755);
	return p;
}

function setupHarness(
	cwd: string,
	sessionId = "sess-issue-reg",
	opts: { contextUsage?: { tokens: number; usedTokens?: number } } = {},
) {
	const agentHome = makeWorkspace("nuwa-issue-home-");
	setEnvTemp("PI_AGENT_HOME", agentHome);

	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	const notifications: Array<{ text: string; level: string }> = [];
	const sentMessages: string[] = [];
	let commandDef: any = null;

	const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
	const z = new Proxy({}, { get: () => () => chain() });

	nuwaMod.default({
		zod: z,
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (_name: string, def: any) => {
			commandDef = def;
		},
		on: (ev: string, fn: any) => {
			const arr = hooks.get(ev) ?? [];
			arr.push(fn);
			hooks.set(ev, arr);
		},
		sendUserMessage: (text: string) => {
			sentMessages.push(text);
		},
		sendMessage: (m: any) => {
			sentMessages.push(String(m?.content ?? ""));
		},
	} as any);

	let currentContextUsage = opts.contextUsage ?? { tokens: 0, usedTokens: 0 };

	const ctx: any = {
		cwd,
		agent: { kind: "main", id: "main-0" },
		sessionManager: { getSessionId: () => sessionId },
		getContextUsage: () => currentContextUsage,
		ui: {
			notify: (text: string, level = "info") => notifications.push({ text, level }),
			setStatus: () => {},
			setWidget: () => {},
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
		},
	};

	return {
		agentHome,
		tools,
		hooks,
		notifications,
		sentMessages,
		ctx,
		setContextUsage(usage: { tokens: number; usedTokens?: number }) {
			currentContextUsage = usage;
		},
		call(name: string, args: Record<string, unknown>) {
			const t = tools.get(name);
			if (!t) throw new Error(`missing tool: ${name}`);
			return t.execute(`call-${name}-${Date.now()}`, args, undefined, () => {}, ctx);
		},
		runCommand(args: string) {
			if (!commandDef) throw new Error("missing /nuwa command");
			return commandDef.handler(args, ctx);
		},
	};
}

afterEach(() => {
	for (const [k, v] of Object.entries(savedEnv)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
	for (const k of Object.keys(savedEnv)) delete savedEnv[k];
	while (tmpDirs.length > 0) {
		const d = tmpDirs.pop()!;
		rmSync(d, { recursive: true, force: true });
	}
});

describe("Issue #54: 真实 omp tool_call -> before_subagent_spawn -> tool_execution_end 全链路回归", () => {
	test("omp before_subagent_spawn 仅传 { type, agent, invocationKind, spawnKey }（无 task/prompt 键）时通过前置 tool_call 缓冲正确放行与回收", async () => {
		const ws = makeWorkspace("nuwa-iss54-single-");
		const h = setupHarness(ws, "sess-iss54-single");
		await h.call("nuwa_init", {
			target: "http://127.0.0.1:18890",
			mode: "pentest",
			root: ws,
			goal: "Issue #54 real omp task protocol verification",
		});

		const claimed = await h.call("nuwa_claim", { id: "i001", worker: "fujiang", root: ws });
		expect(claimed.details?.error).toBeFalsy();
		const claimText = String(claimed.content[0]?.text ?? "");
		expect(claimText).toContain("i001");

		const onToolCall = h.hooks.get("tool_call")![0]!;
		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const onToolEnd = h.hooks.get("tool_execution_end")![0]!;

		// 1) 真实 omp 调 task 工具（无占位符时不返回修改后的 input，避免破坏既有契约）
		const tcRes = onToolCall(
			{
				toolName: "task",
				toolCallId: "tc-real-1",
				input: {
					tasks: [
						{
							agent: "fujiang",
							description: "首轮服务侦察",
							assignment: "[女娲派单 i001] 使用 curl 与端口探测真实目标 http://127.0.0.1:18890 的接口面",
						},
					],
				},
			},
			h.ctx,
		);
		expect(tcRes).toBeUndefined();

		// 2) 真实 omp 发射 before_subagent_spawn：完全不包含 task / prompt / assignment / context 键
		const spRes = onSpawn(
			{
				type: "before_subagent_spawn",
				agent: "fujiang",
				invocationKind: "task",
				modelRole: "default",
				patterns: ["*"],
				spawnKey: "tc-real-1:0",
			},
			h.ctx,
		) as Record<string, unknown>;

		expect(spRes).toBeDefined();
		expect(spRes.block).not.toBe(true);
		expect(spRes.spawnId).toBe("tc-real-1:0");
		expect(String(spRes.task ?? "")).toContain("[女娲派单 i001]");

		const wdRunning = new nuwaMod.SubagentWatchdog(ws);
		expect(wdRunning.activeCount()).toBe(1);
		const tracked = wdRunning.getTask("tc-real-1:0");
		expect(tracked?.status).toBe("running");
		expect(tracked?.intentId).toBe("i001");

		const reg = new nuwaMod.DispatchReceiptRegistry(join(ws, ".nuwa", "dispatch-receipts.json"));
		expect(reg.get("tc-real-1:0")?.intentId).toBe("i001");

		// 3) 真实 omp 返回 details.results[].id 完成并释放看门狗
		onToolEnd(
			{
				toolName: "task",
				toolCallId: "tc-real-1",
				details: { results: [{ id: "tc-real-1:0", agent: "fujiang", aborted: false }] },
				result: { content: "done" },
			},
			h.ctx,
		);
		expect(new nuwaMod.SubagentWatchdog(ws).activeCount()).toBe(0);
		expect(new nuwaMod.SubagentWatchdog(ws).getTask("tc-real-1:0")?.status).toBe("completed");
	});

	test("覆盖批量乱序完成、taskFile、占位符自动展开、eval 调用、原生无前置兜底与显式空 task 拒收", async () => {
		const ws = makeWorkspace("nuwa-iss54-matrix-");
		const h = setupHarness(ws, "sess-iss54-matrix");
		await h.call("nuwa_init", {
			target: "http://127.0.0.1:18891",
			mode: "pentest",
			root: ws,
		});
		await h.call("nuwa_plan", {
			phase: "surface",
			intents: [{ title: "批量路径接口核验", detail: "对多路径核验" }],
			root: ws,
		});

		const onToolCall = h.hooks.get("tool_call")![0]!;
		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const onToolEnd = h.hooks.get("tool_execution_end")![0]!;

		const taskFilePath = join(ws, "brief-verify.md");
		writeFileSync(taskFilePath, "[女娲派单 i002] 请独立双盲复验已发现路径并返回可复现 curl 命令", "utf8");
		const emptyTaskFilePath = join(ws, "empty-brief.md");
		writeFileSync(emptyTaskFilePath, "   \n", "utf8");

		// A) 空 taskFile 必须被 N-007 拦截
		const emptyFileBlock = onToolCall(
			{
				toolName: "task",
				toolCallId: "tc-empty-file",
				input: { tasks: [{ agent: "fujiang", taskFile: emptyTaskFilePath }] },
			},
			h.ctx,
		);
		expect(emptyFileBlock?.block).toBe(true);
		expect(String(emptyFileBlock?.reason ?? "")).toContain("N-007");

		// B) 批量混用占位符 [TARGET] + taskFile：tool_call 展开占位符返回 revisedInput，并缓冲 2 条派单
		const batchTc = onToolCall(
			{
				toolName: "task",
				toolCallId: "tc-batch-real",
				input: {
					tasks: [
						{ agent: "fujiang", task: "[女娲派单 i001] 对 [TARGET]/health 执行真实探测" },
						{ agent: "nuwa-verifier", taskFile: taskFilePath },
					],
				},
			},
			h.ctx,
		) as { input?: { tasks?: Array<{ task?: string }> } };

		expect(batchTc?.input?.tasks?.[0]?.task).toContain("http://127.0.0.1:18891");
		expect(batchTc?.input?.tasks?.[0]?.task).not.toContain("[TARGET]");

		// 乱序 spawn：先 idx=1（nuwa-verifier），再 idx=0（fujiang），都不带 task 字段
		const spSecond = onSpawn(
			{ type: "before_subagent_spawn", agent: "nuwa-verifier", invocationKind: "task", spawnKey: "tc-batch-real:1" },
			h.ctx,
		) as Record<string, unknown>;
		const spFirst = onSpawn(
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "task", spawnKey: "tc-batch-real:0" },
			h.ctx,
		) as Record<string, unknown>;

		expect(spSecond.block).not.toBe(true);
		expect(String(spSecond.task ?? "")).toContain("双盲复验");
		expect(spFirst.block).not.toBe(true);
		expect(String(spFirst.task ?? "")).toContain("http://127.0.0.1:18891");
		expect(new nuwaMod.SubagentWatchdog(ws).activeCount()).toBe(2);

		onToolEnd(
			{
				toolName: "task",
				toolCallId: "tc-batch-real",
				details: { results: [{ id: "tc-batch-real:0" }, { id: "tc-batch-real:1" }] },
			},
			h.ctx,
		);
		expect(new nuwaMod.SubagentWatchdog(ws).activeCount()).toBe(0);

		// C) eval 嵌套 agent() 派生
		const evalTc = onToolCall(
			{
				toolName: "eval",
				toolCallId: "tc-eval-real",
				input: { code: 'await agent({ agent: "fujiang", task: "[女娲派单 i001] 探测鉴权端点" });' },
			},
			h.ctx,
		);
		expect(evalTc).toBeUndefined();

		const evalSpawn = onSpawn(
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "eval", spawnKey: "eval-sp-1" },
			h.ctx,
		) as Record<string, unknown>;
		expect(evalSpawn.block).not.toBe(true);
		expect(String(evalSpawn.task ?? "")).toContain("[eval:fujiang]");

		// D) 原生 invocationKind="task" 无前置缓冲时走兜底协议，而非误判为空
		const fallbackSpawn = onSpawn(
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "task", spawnKey: "speculative-99" },
			h.ctx,
		) as Record<string, unknown>;
		expect(fallbackSpawn.block).not.toBe(true);
		expect(String(fallbackSpawn.task ?? "")).toContain("[omp:task:fujiang]");
		const journal = readFileSync(join(ws, ".nuwa", "journal.jsonl"), "utf8");
		expect(journal).toContain("dispatch_omp_protocol_fallback");

		// E) 显式传空 task: "" 依然必须被守卫拒收
		const explicitEmpty = onSpawn(
			{ spawnId: "sp-explicit-empty", agent: "fujiang", task: "" },
			h.ctx,
		) as Record<string, unknown>;
		expect(explicitEmpty.block).toBe(true);
		expect(explicitEmpty.requeue).toBe(true);
	});
});

describe("Issue #53: socks5h 与 Bun fetch 隔离、stopped 续跑及 /tmp --migrate-workspace 回归", () => {
	test("socks5h 出口代理在 buildUnifiedNetworkEnv 与守护器运行中绝不注入 HTTP_PROXY/HTTPS_PROXY，且实测 Bun fetch 访问模型接口成功", async () => {
		const envObj = scopeMod.buildUnifiedNetworkEnv("socks5h://127.0.0.1:7890", ["target.local"], {
			bunSafe: true,
		});
		expect(envObj.NUWA_EGRESS_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(envObj.NUWA_EGRESS).toBe("socks5h://127.0.0.1:7890");
		expect(envObj.ALL_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(envObj.HTTP_PROXY).toBe("");
		expect(envObj.HTTPS_PROXY).toBe("");

		const ws = makeWorkspace("nuwa-iss53-socks-");
		// 故意在父进程污染 socks5h HTTP_PROXY/HTTPS_PROXY，验证 --dry-run 与真实子进程都彻底剥离
		const pollutedEnv = makeCleanDaemonEnv({
			HTTP_PROXY: "socks5h://127.0.0.1:7890",
			HTTPS_PROXY: "socks5h://127.0.0.1:7890",
			http_proxy: "socks5h://127.0.0.1:7890",
			https_proxy: "socks5h://127.0.0.1:7890",
		});

		const drySocks = spawnSync(
			DAEMON_BIN,
			["--target", "http://127.0.0.1:80", "--root", ws, "--egress-proxy", "socks5h://127.0.0.1:7890", "--dry-run"],
			{ encoding: "utf8", timeout: 10_000, env: pollutedEnv },
		);
		expect(drySocks.status).toBe(0);
		const planText = drySocks.stdout.slice(drySocks.stdout.indexOf("{"));
		const plan = JSON.parse(planText.slice(0, planText.lastIndexOf("}") + 1));
		expect(plan.env.NUWA_EGRESS_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(plan.env.NUWA_EGRESS).toBe("socks5h://127.0.0.1:7890");
		expect(plan.env.ALL_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(plan.env.HTTP_PROXY).toBeUndefined();
		expect(plan.env.HTTPS_PROXY).toBeUndefined();

		// --model-proxy socks5:// 必须报参数错误退出 2
		const badModelProxy = spawnSync(
			DAEMON_BIN,
			["--target", "http://127.0.0.1:80", "--root", ws, "--model-proxy", "socks5://127.0.0.1:7890", "--dry-run"],
			{ encoding: "utf8", timeout: 10_000, env: makeCleanDaemonEnv() },
		);
		expect(badModelProxy.status).toBe(2);

		// --model-proxy http:// + --no-proxy 生效
		const drySplit = spawnSync(
			DAEMON_BIN,
			[
				"--target",
				"http://127.0.0.1:80",
				"--root",
				ws,
				"--egress-proxy",
				"socks5h://127.0.0.1:7890",
				"--model-proxy",
				"http://127.0.0.1:8888",
				"--no-proxy",
				"internal.corp",
				"--dry-run",
			],
			{ encoding: "utf8", timeout: 10_000, env: makeCleanDaemonEnv() },
		);
		expect(drySplit.status).toBe(0);
		expect(drySplit.stdout).toContain('"HTTP_PROXY": "http://127.0.0.1:8888"');
		expect(drySplit.stdout).toContain('"NUWA_EGRESS_PROXY": "socks5h://127.0.0.1:7890"');
		expect(drySplit.stdout).toContain("internal.corp");

		// 启动本地模拟模型 API，使用 stub omp 在子进程内真正调用 Bun fetch()
		const modelServer = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				if (new URL(req.url).pathname === "/v1/models") {
					return Response.json({ ok: true, model: "stub-model" });
				}
				return new Response("not found", { status: 404 });
			},
		});

		try {
			const stubDir = makeWorkspace("nuwa-iss53-stub-");
			const probeFile = join(ws, "child-fetch-probe.json");
			const stubBin = writeExecutableStub(
				stubDir,
				"omp",
				`#!/usr/bin/env bun
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const res = await fetch("http://127.0.0.1:${modelServer.port}/v1/models");
const body = await res.json();
const nuwaDir = join(${JSON.stringify(ws)}, ".nuwa");
mkdirSync(nuwaDir, { recursive: true });
writeFileSync(${JSON.stringify(probeFile)}, JSON.stringify({
  ok: body.ok,
  HTTP_PROXY: process.env.HTTP_PROXY ?? null,
  HTTPS_PROXY: process.env.HTTPS_PROXY ?? null,
  NUWA_EGRESS_PROXY: process.env.NUWA_EGRESS_PROXY ?? null,
  ALL_PROXY: process.env.ALL_PROXY ?? null,
}), "utf8");
writeFileSync(join(nuwaDir, "state.json"), JSON.stringify({
  project: { id: "p-socks", target: "http://127.0.0.1:80", url: "http://127.0.0.1:80", mode: "pentest", phase: "report", status: "completed", goal: "done" },
  runtime: { status: "completed", generation: 1, turns: 1, totalTokens: 10 },
  facts: {},
  intents: {},
}), "utf8");
`,
			);

			const child = Bun.spawn(
				[
					DAEMON_BIN,
					"--target",
					"http://127.0.0.1:80",
					"--root",
					ws,
					"--egress-proxy",
					"socks5h://127.0.0.1:7890",
					"--omp-bin",
					stubBin,
				],
				{
					env: pollutedEnv,
					stdout: "pipe",
					stderr: "pipe",
				},
			);
			const timer = setTimeout(() => {
				try {
					child.kill();
				} catch {
					/* ignore */
				}
			}, 15_000);
			const exitCode = await child.exited;
			clearTimeout(timer);
			expect(exitCode).toBe(0);
			const probe = JSON.parse(readFileSync(probeFile, "utf8"));
			expect(probe.ok).toBe(true);
			expect(probe.HTTP_PROXY).toBeNull();
			expect(probe.HTTPS_PROXY).toBeNull();
			expect(probe.NUWA_EGRESS_PROXY).toBe("socks5h://127.0.0.1:7890");
			expect(probe.ALL_PROXY).toBe("socks5h://127.0.0.1:7890");
		} finally {
			modelServer.stop(true);
		}
	}, 25_000);

	test("status=stopped 默认退出码 2，追加 --resume-stopped / --force 可恢复续跑且防再次停机死循环", async () => {
		const ws = makeWorkspace("nuwa-iss53-stopped-");
		const h = setupHarness(ws, "sess-iss53-stopped");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18892", mode: "pentest", root: ws });
		await h.call("nuwa_stop", { reason: "操作者指令停环，当前阶段暂无有效漏洞", confirm: "STOP", root: ws });
		expect(nuwaMod.loadState(ws)?.project.status).toBe("stopped");

		// 1) 未带 --resume-stopped 必须拒跑并退出 2
		const blockedRes = spawnSync(
			DAEMON_BIN,
			["--root", ws, "--dry-run"],
			{ encoding: "utf8", timeout: 10_000, env: makeCleanDaemonEnv() },
		);
		expect(blockedRes.status).toBe(0); // dry-run 正常预览
		const noForceRes = spawnSync(
			DAEMON_BIN,
			["--root", ws],
			{ encoding: "utf8", timeout: 10_000, env: makeCleanDaemonEnv() },
		);
		expect(noForceRes.status).toBe(2);
		expect(noForceRes.stdout).toContain("--resume-stopped");

		// 2) 带 --resume-stopped：stub 模拟真实会话通过 storage.ts（兼容 json/sqlite/dual）把状态改回 active -> completed 后成功退出 0
		const stubDir = makeWorkspace("nuwa-iss53-resume-stub-");
		const promptCapture = join(ws, "resumed-prompt.txt");
		const storagePath = resolve(import.meta.dir, "..", "omp", "storage.ts");
		const successStub = writeExecutableStub(
			stubDir,
			"omp-resume-ok",
			`#!/usr/bin/env bun
import { writeFileSync } from "node:fs";
import { loadState, saveState } from ${JSON.stringify(storagePath)};
const prompt = process.argv[process.argv.length - 1] ?? "";
writeFileSync(${JSON.stringify(promptCapture)}, prompt, "utf8");
const root = ${JSON.stringify(ws)};
const st = loadState(root);
if (!st) process.exit(1);
st.project.status = "completed";
st.project.stopReason = undefined;
st.project.completedAt = new Date().toISOString();
st.runtime.status = "completed";
saveState(root, st, { reason: "complete" });
`,
		);

		const resumeOk = spawnSync(
			DAEMON_BIN,
			["--root", ws, "--resume-stopped", "--omp-bin", successStub],
			{ encoding: "utf8", timeout: 15_000, env: makeCleanDaemonEnv() },
		);
		expect(resumeOk.status).toBe(0);
		expect(readFileSync(promptCapture, "utf8")).toContain("停机续跑");
		expect(nuwaMod.loadState(ws)?.project.status).toBe("completed");

		// 3) 若回到 stopped 状态且带 --force 运行，但子进程正常退出 0 却未恢复 active/completed（防无限循环）：应退出 2 且只拉起 1 次
		const wsLoop = makeWorkspace("nuwa-iss53-stop-guard-");
		const hLoop = setupHarness(wsLoop, "sess-iss53-stop-guard");
		await hLoop.call("nuwa_init", { target: "http://127.0.0.1:18893", mode: "pentest", root: wsLoop });
		await hLoop.call("nuwa_stop", { reason: "人工停机", confirm: "STOP", root: wsLoop });

		const counterFile = join(wsLoop, "spawn-count.txt");
		const noopStub = writeExecutableStub(
			stubDir,
			"omp-noop",
			`#!/usr/bin/env bun
import { appendFileSync } from "node:fs";
appendFileSync(${JSON.stringify(counterFile)}, "1\\n", "utf8");
`,
		);
		const guardRes = spawnSync(
			DAEMON_BIN,
			["--root", wsLoop, "--force", "--max-generations", "5", "--omp-bin", noopStub],
			{ encoding: "utf8", timeout: 15_000, env: makeCleanDaemonEnv() },
		);
		expect(guardRes.status).toBe(2);
		expect(readFileSync(counterFile, "utf8").trim().split("\n").length).toBe(1);
	}, 25_000);

	test("/tmp 工作区告警引导 --migrate-workspace，执行 --migrate-workspace 可迁移 SQLite WAL 状态到持久化目录并运行成功", async () => {
		const tmpWs = makeWorkspace("nuwa-iss53-tmpws-");
		const persistBase = makeWorkspace("nuwa-iss53-persist-");

		const warn = nuwaMod.checkWorkspaceTempWarning(tmpWs, { forceCheck: true });
		expect(warn?.code).toBe("NUWA_VOLATILE_TMP_WORKSPACE");
		expect(warn?.message).toContain("--migrate-workspace");

		// 强制用 dual 创建真实 SQLite WAL 状态，检验 WAL checkpoint + 迁移完整保留事实
		setEnvTemp("NUWA_STORAGE_BACKEND", "dual");
		const h = setupHarness(tmpWs, "sess-iss53-migrate");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18894", mode: "ctf", root: tmpWs });
		const onToolEndMig = h.hooks.get("tool_execution_end")![0]!;
		onToolEndMig(
			{
				toolName: "bash",
				input: { command: "curl -s http://127.0.0.1:18894/flag" },
				result: { stdout: "flag{migrated_from_tmp_wal}" },
			},
			h.ctx,
		);
		const fRes = await h.call("nuwa_flag", {
			value: "flag{migrated_from_tmp_wal}",
			command: "curl -s http://127.0.0.1:18894/flag",
			output: "flag{migrated_from_tmp_wal}",
			root: tmpWs,
		});
		expect(fRes.details?.error).toBeFalsy();

		const stubDir = makeWorkspace("nuwa-iss53-mig-stub-");
		const storagePath = resolve(import.meta.dir, "..", "omp", "storage.ts");
		const migStub = writeExecutableStub(
			stubDir,
			"omp-mig",
			`#!/usr/bin/env bun
import { loadState, saveState } from ${JSON.stringify(storagePath)};
const root = process.env.NUWA_PROJECT;
if (!root) process.exit(2);
const st = loadState(root);
if (!st) process.exit(3);
const hasFlag = Object.values(st.facts ?? {}).some((f) => f?.kind === "flag");
if (!hasFlag) process.exit(4);
st.project.status = "completed";
st.project.completedAt = new Date().toISOString();
st.runtime.status = "completed";
saveState(root, st, { reason: "complete" });
`,
		);

		const dryMig = spawnSync(
			DAEMON_BIN,
			["--root", tmpWs, "--migrate-workspace", "--dry-run"],
			{
				encoding: "utf8",
				timeout: 10_000,
				env: makeCleanDaemonEnv({ NUWA_WORKSPACES_DIR: persistBase }),
			},
		);
		expect(dryMig.status).toBe(0);
		expect(dryMig.stdout).toContain("plannedMigrationRoot");

		const migRes = spawnSync(
			DAEMON_BIN,
			["--root", tmpWs, "--migrate-workspace", "--omp-bin", migStub],
			{
				encoding: "utf8",
				timeout: 15_000,
				env: makeCleanDaemonEnv({ NUWA_WORKSPACES_DIR: persistBase }),
			},
		);
		expect(migRes.status).toBe(0);
		expect(migRes.stdout).toContain("已根据 --migrate-workspace 将工作区从易失目录迁出");

		const matchLine = migRes.stdout
			.split("\n")
			.find((l) => l.includes("迁出:"));
		expect(matchLine).toBeTruthy();
		const migratedRoot = matchLine!.split("->").pop()!.trim();
		expect(migratedRoot.startsWith(resolve(persistBase))).toBe(true);
		expect(existsSync(join(migratedRoot, ".nuwa", "nuwa.db"))).toBe(true);
		const meta = JSON.parse(readFileSync(join(migratedRoot, ".nuwa", "workspace-meta.json"), "utf8"));
		expect(meta.root).toBe(resolve(migratedRoot));
		expect(meta.migratedFrom).toBe(resolve(tmpWs));
		const finalMigrated = nuwaMod.loadState(migratedRoot);
		expect(finalMigrated?.project.status).toBe("completed");
		expect(Object.values(finalMigrated?.facts ?? {}).some((f) => f.kind === "flag")).toBe(true);
	}, 25_000);
});

describe("PR #55 + P1–P8: sealed_negative 终态守卫、跨会话只读、报告/Token 同步与守护器退出 0", () => {
	test("P1–P5 & P7–P8: sealed_negative 不可被任何 resume 入口复活，跨会话只读降级，驱动头/报告/Token 自动同步", async () => {
		const ws = makeWorkspace("nuwa-pr55-seal-");
		const h = setupHarness(ws, "sess-pr55-owner", { contextUsage: { tokens: 12345, usedTokens: 12345 } });
		await h.call("nuwa_init", { target: "http://127.0.0.1:18895", mode: "pentest", root: ws });

		// 先写入一份旧 active 报告（模拟中盘曾经生成的报告），验证 P7 封盘自动重写覆盖旧文件
		const oldMd = await h.call("nuwa_report", { write: true, format: "md", root: ws });
		const oldJson = await h.call("nuwa_report", { write: true, format: "json", root: ws });
		expect(oldMd.details?.error).toBeFalsy();
		expect(oldJson.details?.error).toBeFalsy();
		const reportMdPath = join(ws, ".nuwa", "REPORT.md");
		const reportJsonPath = join(ws, ".nuwa", "REPORT.json");
		expect(readFileSync(reportMdPath, "utf8")).toContain("active");

		// 执行负向封盘
		const sealRes = await h.call("nuwa_complete", {
			seal: true,
			reason: "全量 RBAC 与输入校验已覆盖全部探测面，无有效漏洞",
			excluded_surface: ["/health", "/metrics"],
			evidence: "200/403 独立采样校验完成",
			root: ws,
		});
		expect(sealRes.details?.error).toBeFalsy();
		expect(sealRes.details?.status).toBe("sealed_negative");

		// P7: 无需再调 nuwa_report，REPORT.md 与 REPORT.json 已被自动刷新为 sealed_negative
		const mdAfterSeal = readFileSync(reportMdPath, "utf8");
		expect(mdAfterSeal).toContain("sealed_negative");
		expect(mdAfterSeal).toContain("负向封盘说明（Sealed Negative）");
		expect(mdAfterSeal).toContain("/health");
		const jsonAfterSeal = JSON.parse(readFileSync(reportJsonPath, "utf8"));
		expect(jsonAfterSeal.project.status).toBe("sealed_negative");
		expect(jsonAfterSeal.project.sealMeta?.excludedSurface).toEqual(["/health", "/metrics"]);

		// P8: 实时 Token 被合并到 runtime.tokens，nuwa_status / buildDirective / ui.buildSnapshot / REPORT.md 全链路均暴露准确汇总 totalTokens（含往代累计 + 本代实时）
		const cfg = {
			loop: true,
			infinite: true,
			maxTurns: 20,
			maxStall: 8,
			idleTurns: 4,
			reincarnateTokens: 140000,
			reincarnateTurns: 30,
			tickMs: 1000,
			maxParallel: 3,
			claimTtl: 60000,
			autoExpand: true,
			autoExecute: false,
			requireFujiang: true,
		};
		const stSealed = nuwaMod.loadState(ws)!;
		expect(stSealed.runtime.tokens).toBe(12345);
		expect(stSealed.runtime.totalTokens).toBe(0);
		const statusRes = await h.call("nuwa_status", { root: ws });
		expect(statusRes.details?.error).toBeFalsy();
		expect(String(statusRes.content[0]?.text ?? "")).toContain("tokens=12345");
		expect(String(statusRes.content[0]?.text ?? "")).toContain("totalTokens=12345");
		expect(statusRes.details?.tokens).toBe(12345);
		expect(statusRes.details?.totalTokens).toBe(12345);
		const snap = uiMod.buildSnapshot(stSealed, cfg, 0);
		expect(snap.runtime.tokens).toBe(12345);
		expect(snap.runtime.totalTokens).toBe(12345);

		// P5: buildDirective 输出状态与 sealed_negative 一致（绝不为 active）
		const dirText = graphMod.buildDirective(stSealed, cfg, ws);
		expect(dirText).toContain("status=sealed_negative");
		expect(dirText).not.toContain("status=active");

		// P1: nuwa_init(resume=true) 不可复活
		const initResume = await h.call("nuwa_init", { resume: true, force: true, root: ws });
		expect(initResume.details?.error).toBeFalsy();
		expect(initResume.details?.status).toBe("sealed_negative");
		expect(nuwaMod.loadState(ws)?.project.status).toBe("sealed_negative");
		expect(nuwaMod.loadState(ws)?.runtime.status).toBe("sealed_negative");

		// P2: /nuwa resume 不可复活且不触发 kick (sentMessages 仍为 0)
		const beforeSent = h.sentMessages.length;
		await h.runCommand("resume");
		expect(h.sentMessages.length).toBe(beforeSent);
		expect(h.notifications.some((n) => n.text.includes("sealed_negative"))).toBe(true);
		expect(nuwaMod.loadState(ws)?.project.status).toBe("sealed_negative");

		// P3: /nuwa <target> 不可重置/复活已封盘项目
		await h.runCommand("http://127.0.0.1:18895");
		expect(h.sentMessages.length).toBe(beforeSent);
		expect(nuwaMod.loadState(ws)?.project.status).toBe("sealed_negative");

		// P4: 跨会话调 nuwa_init(resume=true) 不报错，降级为只读查看且不篡改磁盘 ownerSessionId
		const hOther = setupHarness(ws, "sess-pr55-outsider");
		const otherResume = await hOther.call("nuwa_init", { resume: true, root: ws });
		expect(otherResume.details?.error).toBeFalsy();
		expect(otherResume.details?.readonly).toBe(true);
		expect(otherResume.details?.status).toBe("sealed_negative");
		expect(nuwaMod.loadState(ws)?.project.ownerSessionId).toBe("sess-pr55-owner");

		// MCP Server 同构验证（同会话不可复活 + 跨会话只读 + 自己封盘自动刷新报告）
		const engOther = new NuwaCoreEngine({
			cwd: ws,
			sessionId: "sess-mcp-outsider",
			agentHome: hOther.agentHome,
		});
		const mcpReadonly = await engOther.callTool("nuwa_init", { root: ws, resume: true });
		expect(mcpReadonly.isError).toBe(false);
		expect(mcpReadonly.details?.readonly).toBe(true);
		expect(mcpReadonly.details?.status).toBe("sealed_negative");
		expect(nuwaMod.loadState(ws)?.project.ownerSessionId).toBe("sess-pr55-owner");

		// 守护器识别 sealed_negative 直接退出 0（不拉起 omp）
		const daemonRes = spawnSync(
			DAEMON_BIN,
			["--root", ws, "--resume-stopped"],
			{ encoding: "utf8", timeout: 10_000, env: makeCleanDaemonEnv() },
		);
		expect(daemonRes.status).toBe(0);
		expect(daemonRes.stdout).toContain("status=sealed_negative");

		// MCP 独立封盘刷新报告检验
		const mcpWs = makeWorkspace("nuwa-pr55-mcp-seal-");
		const eng = new NuwaCoreEngine({ cwd: mcpWs, sessionId: "sess-mcp-seal", agentHome: hOther.agentHome });
		await eng.callTool("nuwa_init", { target: "http://127.0.0.1:18896", mode: "audit", root: mcpWs });
		const mcpSeal = await eng.callTool("nuwa_complete", {
			seal: true,
			reason: "MCP 独立评估确认无漏洞",
			excluded_surface: ["/api/ping"],
			root: mcpWs,
		});
		expect(mcpSeal.isError).toBe(false);
		expect(mcpSeal.details?.status).toBe("sealed_negative");
		expect(existsSync(join(mcpWs, ".nuwa", "REPORT.md"))).toBe(true);
		expect(readFileSync(join(mcpWs, ".nuwa", "REPORT.md"), "utf8")).toContain("sealed_negative");
	}, 20_000);

	test("P6: compactIntents 裁剪超限 blockedIntents 至 120 时与累计 blockedCommits 双口径保持正确", async () => {
		const ws = makeWorkspace("nuwa-pr55-p6-");
		const h = setupHarness(ws, "sess-pr55-p6");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18897", mode: "pentest", root: ws });

		const st = nuwaMod.loadState(ws)!;
		for (let idx = 1; idx <= 125; idx++) {
			const iid = `i${String(idx + 10).padStart(3, "0")}`;
			st.intents[iid] = {
				id: iid,
				phase: "vuln",
				title: `probe-blocked-${idx}`,
				from: [],
				priority: 10,
				status: "blocked",
				attempts: 1,
				createdAt: new Date(Date.now() - (200 - idx) * 1000).toISOString(),
				doneAt: new Date(Date.now() - (200 - idx) * 1000).toISOString(),
				result: "403 blocked",
			};
		}
		st.runtime.blockedCommits = 125;
		const removed = graphMod.compactIntents(st, 120);
		nuwaMod.saveState(ws, st, { reason: "compact-test" });

		const statusRes = await h.call("nuwa_status", { root: ws });
		const blockedInMem = Object.values(nuwaMod.loadState(ws)!.intents).filter((i) => i.status === "blocked").length;
		expect(removed).toBe(5);
		expect(blockedInMem).toBe(120);
		expect(nuwaMod.loadState(ws)!.runtime.blockedCommits).toBe(125);
		expect(String(statusRes.content[0]?.text ?? "")).toContain("blockedIntents=120");
		expect(String(statusRes.content[0]?.text ?? "")).toContain("blockedCommits=125");
	});
});

describe("深度审查回归：Async/eval 竞态、终态防降级篡改、全链路口径及 --force-resume / 新 /tmp 直迁", () => {
	test("Issue #54 深度场景：async 批派单先 tool_execution_end 后 before_subagent_spawn（乱序+无 name），看门狗不被误注销，eval 内 tool.task 经 tool_result 收口，以及空 tasks/taskFile/context 展开", async () => {
		const ws = makeWorkspace("nuwa-iss54-async-deep-");
		const h = setupHarness(ws, "sess-iss54-async");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18901", mode: "pentest", root: ws });

		const onToolCall = h.hooks.get("tool_call")![0]!;
		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const onToolEnd = h.hooks.get("tool_execution_end")![0]!;
		const onToolResult = h.hooks.get("tool_result")![0]!;

		// 1) 空批派单 tasks: [] 直接被拦截
		const emptyBatch = onToolCall({ toolName: "task", toolCallId: "tc-empty-batch", input: { tasks: [] } }, h.ctx) as Record<string, unknown>;
		expect(emptyBatch?.block).toBe(true);
		expect(String(emptyBatch?.reason ?? "")).toContain("nuwa N-007");

		// 2) taskFile 含 [TARGET] 且共享 input.context 含 [TARGET]，校验自动展开并替换 taskFile 防止宿主再读未展开原文件
		const tfPath = join(ws, "probe-task.md");
		writeFileSync(tfPath, "[女娲派单 i001] 使用 taskFile 核查 http://TARGET/admin 是否存在鉴权绕过", "utf8");
		const tfRewrite = onToolCall(
			{
				toolName: "task",
				toolCallId: "tc-tf-ph",
				input: {
					agent: "fujiang",
					taskFile: tfPath,
					context: { base: "https://TARGET/api" },
				},
			},
			h.ctx,
		) as { input?: Record<string, unknown> };
		expect(tfRewrite?.input).toBeTruthy();
		expect(String(tfRewrite.input?.task ?? "")).toContain("127.0.0.1:18901/admin");
		expect(tfRewrite.input?.taskFile).toBeUndefined();
		expect((tfRewrite.input?.context as Record<string, unknown>)?.base).toBe("http://127.0.0.1:18901/api");
		onToolEnd({ toolName: "task", toolCallId: "tc-tf-ph", input: tfRewrite.input, result: { details: { results: [] } } }, h.ctx);

		// 3) 真实 async 批派单（无 name）：tool_execution_end 在后台子代理 before_subagent_spawn 前触发且带有 progress(pending)
		const asyncBatchTc = onToolCall(
			{
				toolName: "task",
				toolCallId: "tc-async-1",
				input: {
					tasks: [
						{ agent: "fujiang", task: "[女娲派单 i001] 探测第一条异步任务 alpha" },
						{ agent: "nuwa-verifier", task: "[女娲派单 i002] 复验第二条异步任务 beta" },
					],
				},
			},
			h.ctx,
		);
		expect(asyncBatchTc).toBeUndefined();

		// 若先启动了一条其它在途看门狗任务，async.state="running" 的 tool_execution_end 绝对不能把正在跑的唯一任务误注销
		const wd = new nuwaMod.SubagentWatchdog(ws);
		wd.startTask({ taskId: "pre-running-job", agent: "fujiang" });
		expect(wd.activeCount()).toBe(1);

		onToolEnd(
			{
				toolName: "task",
				toolCallId: "tc-async-1",
				result: {
					details: {
						async: { state: "running" },
						progress: [
							{ index: 0, id: "brave-owl-71", status: "pending" },
							{ index: 1, id: "calm-fox-82", status: "pending" },
						],
						results: [],
					},
				},
			},
			h.ctx,
		);
		expect(wd.activeCount()).toBe(1); // 不得误注销 pre-running-job

		// 后台子代理乱序到达：calm-fox-82（index=1）先 spawn，brave-owl-71（index=0）后 spawn
		const sp1 = onSpawn(
			{ type: "before_subagent_spawn", agent: "nuwa-verifier", invocationKind: "task", spawnKey: "calm-fox-82" },
			h.ctx,
		) as Record<string, unknown>;
		const sp0 = onSpawn(
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "task", spawnKey: "brave-owl-71" },
			h.ctx,
		) as Record<string, unknown>;
		expect(sp1.block).not.toBe(true);
		expect(sp0.block).not.toBe(true);
		expect(String(sp1.task ?? "")).toContain("第二条异步任务 beta");
		expect(String(sp0.task ?? "")).toContain("第一条异步任务 alpha");
		expect(wd.activeCount()).toBe(3);

		// 完成后正常收口
		onToolEnd(
			{
				toolName: "task",
				toolCallId: "tc-async-1",
				result: { details: { results: [{ id: "brave-owl-71" }, { id: "calm-fox-82" }, { id: "pre-running-job" }] } },
			},
			h.ctx,
		);
		expect(wd.activeCount()).toBe(0);

		// 4) eval 内多条 agent({ prompt, label }) 与 tool.task()：外层 eval 先结束，后台异步子代理携 Parent.label 前缀随后 spawn，以及 js-task 经 tool_result 收口
		const evalEmptyBlocked = onToolCall(
			{ toolName: "eval", toolCallId: "tc-eval-empty", input: { code: 'await agent({ agent: "fujiang", prompt: "   " });' } },
			h.ctx,
		) as Record<string, unknown>;
		expect(evalEmptyBlocked?.block).toBe(true);

		onToolCall(
			{
				toolName: "eval",
				toolCallId: "tc-eval-multi",
				input: {
					code: [
						'agent({ agent: "fujiang", label: "lbl-a", prompt: "测试端点 http://TARGET/eval-a" });',
						'agent({ agent: "nuwa-verifier", label: "lbl-b", prompt: "核验端点 http://TARGET/eval-b" });',
					].join("\n"),
				},
			},
			h.ctx,
		);
		// 外层 eval 成功执行后即返回，尚未消费的 eval agent 派单不得在 tool_execution_end("eval") 时被提前销毁
		onToolEnd({ toolName: "eval", toolCallId: "tc-eval-multi", isError: false, result: { text: "queued 2" } }, h.ctx);

		const evSpB = onSpawn(
			{ type: "before_subagent_spawn", agent: "nuwa-verifier", invocationKind: "eval", spawnKey: "root-parent.lbl-b" },
			h.ctx,
		) as Record<string, unknown>;
		const evSpA = onSpawn(
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "eval", spawnKey: "lbl-a" },
			h.ctx,
		) as Record<string, unknown>;
		expect(evSpB.block).not.toBe(true);
		expect(evSpA.block).not.toBe(true);
		expect(String(evSpB.task ?? "")).toContain("127.0.0.1:18901/eval-b");
		expect(String(evSpA.task ?? "")).toContain("127.0.0.1:18901/eval-a");
		expect(wd.activeCount()).toBe(2);

		// 通过 tool_result（eval 内 tool.task 专属通道）精确回收并记录可信执行账本（且去重不记两遍）
		onToolResult(
			{
				toolName: "task",
				toolCallId: "js-task-1",
				result: { details: { results: [{ id: "lbl-a" }, { id: "root-parent.lbl-b" }] } },
			},
			h.ctx,
		);
		expect(wd.activeCount()).toBe(0);

		const journal = readFileSync(join(ws, ".nuwa", "journal.jsonl"), "utf8");
		expect(journal).not.toContain("dispatch_omp_protocol_fallback");
	});

	test("PR #55 终态不可篡改与全链路口径：nuwa_stop/plan/claim/expand/slash 均拦截、/nuwa seal 同步 Token、跨/同会话真零写入及 SARIF/renderFullStatus 对齐", async () => {
		const ws = makeWorkspace("nuwa-pr55-immutable-");
		const h = setupHarness(ws, "sess-pr55-lock", { contextUsage: { tokens: 24680, usedTokens: 24680 } });
		await h.call("nuwa_init", { target: "http://127.0.0.1:18902", mode: "pentest", root: ws });

		// 通过 /nuwa seal 封盘并验证 Token 与 reportWritten 同步
		await h.runCommand("seal 经/nuwa seal人工负向封盘");
		const sealedState = nuwaMod.loadState(ws)!;
		expect(sealedState.project.status).toBe("sealed_negative");
		expect(sealedState.runtime.status).toBe("sealed_negative");
		expect(sealedState.runtime.tokens).toBe(24680);
		expect(sealedState.runtime.reportWritten).toBe(true);
		expect(existsSync(join(ws, ".nuwa", "REPORT.md"))).toBe(true);

		// 封盘后调用 nuwa_stop（硬停/软暂停）、/nuwa stop、/nuwa pause、nuwa_plan、nuwa_claim、nuwa_expand 均不得复活或改写为 stopped
		const stopHardRes = await h.call("nuwa_stop", { reason: "尝试覆写终态", confirm: "STOP", root: ws });
		expect(stopHardRes.details?.stopped).toBe(false);
		expect(stopHardRes.details?.terminal).toBe(true);
		const stopPauseRes = await h.call("nuwa_stop", { pause: true, reason: "尝试软暂停终态", root: ws });
		expect(stopPauseRes.details?.paused).toBe(false);
		expect(existsSync(join(ws, ".nuwa", "paused.json"))).toBe(false);

		await h.runCommand("stop 试图命令停机");
		await h.runCommand("pause 试图命令软暂停");
		expect(existsSync(join(ws, ".nuwa", "paused.json"))).toBe(false);
		expect(nuwaMod.loadState(ws)?.project.status).toBe("sealed_negative");

		const planBlocked = await h.call("nuwa_plan", { intents: [{ title: "forbidden after seal" }], root: ws });
		expect(planBlocked.details?.error).toBe(true);
		const claimBlocked = await h.call("nuwa_claim", { id: "i001", worker: "fujiang", root: ws });
		expect(claimBlocked.details?.error).toBe(true);
		const expandBlocked = await h.call("nuwa_expand", { root: ws });
		expect(expandBlocked.details?.error).toBe(true);

		// MCP Server 同构拦截检查
		const engSame = new NuwaCoreEngine({ cwd: ws, sessionId: "sess-pr55-lock", agentHome: h.agentHome });
		const mcpStop = await engSame.callTool("nuwa_stop", { root: ws, confirm: "STOP", reason: "mcp try stop" });
		expect(mcpStop.details?.stopped).toBe(false);
		expect(mcpStop.details?.terminal).toBe(true);
		expect((await engSame.callTool("nuwa_plan", { root: ws, intents: [{ title: "mcp forbidden" }] })).isError).toBe(true);
		expect((await engSame.callTool("nuwa_expand", { root: ws })).isError).toBe(true);

		// 同会话无 force 调 nuwa_init(resume=true) 真正零写盘只读
		const statePath = join(ws, ".nuwa", "state.json");
		const mtimeBefore = statSync(statePath).mtimeMs;
		await new Promise((r) => setTimeout(r, 25));
		const roResume = await h.call("nuwa_init", { resume: true, root: ws });
		expect(roResume.details?.readonly).toBe(true);
		expect(roResume.details?.status).toBe("sealed_negative");
		expect(statSync(statePath).mtimeMs).toBe(mtimeBefore);

		// buildDirective / SARIF / PoC Bundle / renderFullStatus 全口径一致
		const cfg = {
			loop: true,
			infinite: true,
			maxTurns: 10,
			maxStall: 5,
			idleTurns: 4,
			reincarnateTokens: 140000,
			reincarnateTurns: 30,
			tickMs: 1000,
			maxParallel: 3,
			claimTtl: 60000,
			autoExpand: true,
			autoExecute: false,
			requireFujiang: true,
		};
		const dirTerminal = graphMod.buildDirective(sealedState, cfg, ws);
		expect(dirTerminal).toContain("status=sealed_negative");
		expect(dirTerminal).not.toContain("至少 1 次 task 批量派单");

		const sarif = reportingMod.buildSarifReport(sealedState, ws) as any;
		expect(sarif.runs[0].invocations[0].properties.status).toBe("sealed_negative");
		expect(sarif.runs[0].invocations[0].endTimeUtc).toBeTruthy();

		const fullJson = JSON.parse(uiMod.renderFullStatus(ws, { format: "json" }));
		expect(fullJson.project.status).toBe("sealed_negative");
		expect(fullJson.runtime.status).toBe("sealed_negative");
		expect(fullJson.runtime.tokens).toBe(24680);
		expect(fullJson.runtime.totalTokens).toBe(24680);
		const fullText = uiMod.renderFullStatus(ws, { format: "text" });
		expect(fullText).toContain("tokens=24680");
		expect(fullText).toContain("totalTokens=24680");

		const snap = uiMod.buildSnapshot(sealedState, cfg, 0);
		expect(snap.runtime.status).toBe("sealed_negative");
	});

	test("Issue #53 别名与直迁增强：--force-resume 别名、NUWA_EGRESS 旧变量兼容与尚未创建的 /tmp 新目录配合 --migrate-workspace 直落持久化目录", async () => {
		const ws = makeWorkspace("nuwa-iss53-alias-");
		const stubDir = makeWorkspace("nuwa-iss53-alias-stub-");
		const persistBase = makeWorkspace("nuwa-iss53-alias-persist-");

		// 1) NUWA_EGRESS 旧环境变量下同样开启 Bun fetch 代理隔离
		const legacyEnvDry = spawnSync(
			DAEMON_BIN,
			["--root", ws, "--target", "http://127.0.0.1:18903", "--dry-run"],
			{
				encoding: "utf8",
				timeout: 10_000,
				env: makeCleanDaemonEnv({ NUWA_EGRESS: "socks5h://127.0.0.1:7891" }),
			},
		);
		expect(legacyEnvDry.status).toBe(0);
		expect(legacyEnvDry.stdout).toContain(`"ALL_PROXY": "socks5h://127.0.0.1:7891"`);
		expect(legacyEnvDry.stdout).not.toContain(`"HTTP_PROXY": "socks5h://`);

		// 2) --force-resume 别名可正常接管 status=stopped 项目并完成
		const h = setupHarness(ws, "sess-iss53-force-resume");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18903", mode: "pentest", root: ws });
		await h.call("nuwa_stop", { reason: "测试别名接管", confirm: "STOP", root: ws });
		const storagePath = resolve(import.meta.dir, "..", "omp", "storage.ts");
		const completeStub = writeExecutableStub(
			stubDir,
			"omp-force-resume",
			`#!/usr/bin/env bun
import { loadState, saveState } from ${JSON.stringify(storagePath)};
const st = loadState(process.env.NUWA_PROJECT);
st.project.status = "completed";
st.project.stopReason = undefined;
st.project.completedAt = new Date().toISOString();
st.runtime.status = "completed";
saveState(process.env.NUWA_PROJECT, st, { reason: "complete" });
`,
		);
		const aliasRun = spawnSync(
			DAEMON_BIN,
			["--root", ws, "--force-resume", "--omp-bin", completeStub],
			{ encoding: "utf8", timeout: 15_000, env: makeCleanDaemonEnv() },
		);
		expect(aliasRun.status).toBe(0);
		expect(nuwaMod.loadState(ws)?.project.status).toBe("completed");

		// 3) 尚不存在的 /tmp 新路径配合 --migrate-workspace：直接重定位创建于持久化目录，不在 /tmp 建状态
		const nonexistentTmp = join(tmpdir(), `nuwa-nonexistent-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`);
		const dryFresh = spawnSync(
			DAEMON_BIN,
			["--root", nonexistentTmp, "--target", "http://127.0.0.1:18904", "--migrate-workspace", "--dry-run"],
			{
				encoding: "utf8",
				timeout: 10_000,
				env: makeCleanDaemonEnv({ NUWA_WORKSPACES_DIR: persistBase }),
			},
		);
		expect(dryFresh.status).toBe(0);
		expect(dryFresh.stdout).toContain("plannedMigrationRoot");
		expect(dryFresh.stdout).toContain(`"NUWA_PROJECT": "${resolve(persistBase)}`);

		const graphPath = resolve(import.meta.dir, "..", "omp", "graph.ts");
		const freshStub = writeExecutableStub(
			stubDir,
			"omp-fresh-persist",
			`#!/usr/bin/env bun
import { newState } from ${JSON.stringify(graphPath)};
import { saveState } from ${JSON.stringify(storagePath)};
const root = process.env.NUWA_PROJECT;
const st = newState("http://127.0.0.1:18904", "fresh persisted", "pentest", {}, "sess-fresh");
st.project.status = "completed";
st.project.completedAt = new Date().toISOString();
st.runtime.status = "completed";
saveState(root, st, { reason: "complete" });
`,
		);
		const runFresh = spawnSync(
			DAEMON_BIN,
			[
				"--root",
				nonexistentTmp,
				"--target",
				"http://127.0.0.1:18904",
				"--egress-proxy",
				"socks5h://u:secret@127.0.0.1:7891",
				"--migrate-workspace",
				"--omp-bin",
				freshStub,
			],
			{
				encoding: "utf8",
				timeout: 15_000,
				env: makeCleanDaemonEnv({ NUWA_WORKSPACES_DIR: persistBase }),
			},
		);
		expect(runFresh.status).toBe(0);
		expect(existsSync(nonexistentTmp)).toBe(false);
		expect(runFresh.stdout).toContain("重定位至持久化目录");
		const migLine = runFresh.stdout.split("\n").find((l) => l.includes("重定位至持久化目录:"));
		expect(migLine).toBeTruthy();
		const targetPersistRoot = migLine!.split("->").pop()!.trim();
		const daemonCfg = JSON.parse(readFileSync(join(targetPersistRoot, ".nuwa", "daemon-config.json"), "utf8"));
		expect(daemonCfg.egressProxy).not.toContain("secret");
		expect(daemonCfg.egressProxy).toContain("***");
		expect(nuwaMod.loadState(targetPersistRoot)?.project.status).toBe("completed");
	}, 25_000);
});
