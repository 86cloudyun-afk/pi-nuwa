/**
 * pi-nuwa v6.0 跨宿主 MCP 协议服务与 L2 离线微基准套件端到端验收测试。
 *
 * 覆盖：
 * 1. `core/protocol.ts` 零外部依赖契约与 `omp/nuwa.ts` 12 工具定义 100% 对齐校验；
 * 2. `core/mcp-server.ts` JSON-RPC 2.0 边界、通知静默、半包/粘包 Content-Length 与 NDJSON 帧解析、`nuwa_status` 零磁盘写入；
 * 3. `Bun.spawn` 真实启动 `bin/nuwa-mcp` 子进程测试完整 stdio 协议（`initialize`、`notifications/initialized`、`ping`、`tools/list`、`tools/call` 实跑 `nuwa_init`/`nuwa_plan`/`nuwa_status`/`nuwa_stop`）；
 * 4. 实跑 `runL2BenchmarkSuite()` 验证 5 个本机 `127.0.0.1:0` 场景全绿与全部四大硬门禁。
 */
import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { EventEmitter } from "node:events";
import {
	JSONRPC_ERROR_CODES,
	NUWA_CORE_TOOLS,
	NUWA_MCP_PROTOCOL_VERSION,
	NUWA_TOOL_NAMES,
	createJsonRpcError,
	createJsonRpcNotification,
	createJsonRpcRequest,
	createJsonRpcSuccess,
	getNuwaToolDefinition,
	isJsonRpcNotification,
	isJsonRpcRequest,
} from "../core/protocol";
import {
	NuwaCoreEngine,
	encodeMcpFrame,
	extractNextMcpFrame,
	handleMcpMessage,
	startStdioMcpServer,
} from "../core/mcp-server";
import { L2_SCENARIO_SPECS, startL2ScenarioServer } from "../benchmarks/l2-range/servers";
import { runL2BenchmarkSuite } from "../benchmarks/run-l2-eval";

const REPO_ROOT = resolve(import.meta.dir, "..");
const BIN_NUWA_MCP = join(REPO_ROOT, "bin", "nuwa-mcp");

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(d);
	return d;
}

afterEach(() => {
	while (tempDirs.length > 0) {
		const dir = tempDirs.pop()!;
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

describe("core/protocol.ts 跨宿主协议契约与 12 工具对齐", () => {
	test("12 个核心工具名称、顺序及参数属性与 omp/nuwa.ts 保持 100% 对齐", () => {
		expect(NUWA_MCP_PROTOCOL_VERSION).toBe("2024-11-05");
		expect(NUWA_CORE_TOOLS.length).toBe(12);
		expect(NUWA_CORE_TOOLS.map((t) => t.name)).toEqual([...NUWA_TOOL_NAMES]);

		// 提取 omp/nuwa.ts 中注册的工具名与顶层参数名进行静态对齐校验
		const nuwaSrc = readFileSync(join(REPO_ROOT, "omp", "nuwa.ts"), "utf8");
		const regMatches = [...nuwaSrc.matchAll(/pi\.registerTool\(\{\s*name:\s*"(nuwa_[a-z_]+)"/g)].map(
			(m) => m[1]!,
		);
		expect(regMatches).toEqual([...NUWA_TOOL_NAMES]);

		for (const tool of NUWA_CORE_TOOLS) {
			expect(tool.description.length).toBeGreaterThan(10);
			expect(tool.inputSchema.type).toBe("object");
			expect(getNuwaToolDefinition(tool.name)?.name).toBe(tool.name);
		}

		expect(getNuwaToolDefinition("nuwa_claim")?.inputSchema.required).toEqual(["id"]);
		expect(getNuwaToolDefinition("nuwa_flag")?.inputSchema.required).toEqual(["value", "command", "output"]);
		expect(getNuwaToolDefinition("nuwa_kb")?.inputSchema.required).toEqual(["query"]);
	});

	test("core/protocol.ts 零外部运行时依赖且 JSON-RPC 2.0 守卫精确区分 id:null 请求与无 id 通知", () => {
		const protoSrc = readFileSync(join(REPO_ROOT, "core", "protocol.ts"), "utf8");
		expect(/^\s*import\s+/m.test(protoSrc)).toBe(false);

		const serverSrc = readFileSync(join(REPO_ROOT, "core", "mcp-server.ts"), "utf8");
		expect(serverSrc.includes("@oh-my-pi")).toBe(false);
		expect(/from\s+["']\.\.\/omp\/nuwa["']/.test(serverSrc)).toBe(false);

		const reqNormal = createJsonRpcRequest(1, "tools/list");
		const reqZero = createJsonRpcRequest(0, "ping");
		const reqNull = createJsonRpcRequest(null, "ping");
		const notif = createJsonRpcNotification("notifications/initialized");
		const okResp = createJsonRpcSuccess(1, { ok: true });
		const errResp = createJsonRpcError(1, JSONRPC_ERROR_CODES.INVALID_PARAMS, "bad param");

		expect(isJsonRpcRequest(reqNormal)).toBe(true);
		expect(isJsonRpcRequest(reqZero)).toBe(true);
		expect(isJsonRpcRequest(reqNull)).toBe(true);
		expect(isJsonRpcNotification(reqNull)).toBe(false);

		expect(isJsonRpcNotification(notif)).toBe(true);
		expect(isJsonRpcRequest(notif)).toBe(false);

		expect(okResp.jsonrpc).toBe("2.0");
		expect(errResp.error.code).toBe(-32602);
	});
});

describe("core/mcp-server.ts 协议帧解析、错误边界与只读契约", () => {
	test("Content-Length 多字节中文 UTF-8 半包/粘包、附加 Content-Type 头与换行分隔混合帧精确提取", () => {
		const msg1 = createJsonRpcRequest(10, "tools/call", {
			name: "nuwa_kb",
			arguments: { query: "女娲跨宿主协议测试中文多字节边界" },
		});
		const msg2 = createJsonRpcRequest(11, "ping");
		const body1 = JSON.stringify(createJsonRpcSuccess(10, msg1));
		const frame1 = `Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body1, "utf8")}\r\n\r\n${body1}`;
		const frame2 = `${JSON.stringify(msg2)}\n`;

		const fullBuf = Buffer.from(frame1 + frame2, "utf8");
		// 半包截断在头部和中文 UTF-8 字节中间时均必须返回 null 等待后续数据
		expect(extractNextMcpFrame(fullBuf.subarray(0, 6), false)).toBeNull();
		expect(extractNextMcpFrame(fullBuf.subarray(0, 92), false)).toBeNull();

		const extracted1 = extractNextMcpFrame(fullBuf, false);
		expect(extracted1).not.toBeNull();
		expect(extracted1!.framing).toBe("content-length");
		expect(JSON.parse(extracted1!.rawJson).id).toBe(10);

		const remBuf = fullBuf.subarray(extracted1!.consumedBytes);
		const extracted2 = extractNextMcpFrame(remBuf, false);
		expect(extracted2).not.toBeNull();
		expect(extracted2!.framing).toBe("newline");
		expect(JSON.parse(extracted2!.rawJson).method).toBe("ping");
	});

	test("handleMcpMessage 正确处理通知静默、未知方法、未知工具且 nuwa_status 保持零磁盘写入", async () => {
		const ws = makeTempDir("nuwa-mcp-unit-");
		const agentHome = makeTempDir("nuwa-mcp-home-");
		const engine = new NuwaCoreEngine({
			projectRoot: ws,
			cwd: ws,
			sessionId: "unit-mcp-session",
			agentHome,
		});

		// notifications/initialized 绝不返回响应
		const notifOut = await handleMcpMessage(
			{ jsonrpc: "2.0", method: "notifications/initialized" },
			engine,
		);
		expect(notifOut).toBeNull();
		expect(engine.isInitialized()).toBe(true);

		// 未知方法返回 -32601
		const unknownMethod = (await handleMcpMessage(
			{ jsonrpc: "2.0", id: 2, method: "resources/unknown" },
			engine,
		)) as { error?: { code: number } };
		expect(unknownMethod.error?.code).toBe(JSONRPC_ERROR_CODES.METHOD_NOT_FOUND);

		// 未知工具返回 -32602
		const unknownTool = (await handleMcpMessage(
			{ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "nuwa_nonexistent" } },
			engine,
		)) as { error?: { code: number } };
		expect(unknownTool.error?.code).toBe(JSONRPC_ERROR_CODES.INVALID_PARAMS);

		// 初始化后执行多次 nuwa_status 查询，验证 state.json mtimeMs 零变化
		const initCall = await engine.callTool("nuwa_init", {
			target: "http://127.0.0.1:18080",
			mode: "pentest",
			goal: "验证只读看板零磁盘写入",
		});
		expect(initCall.isError).toBe(false);

		const stFile = join(ws, ".nuwa", "state.json");
		const beforeStat = statSync(stFile);
		await Bun.sleep(15);

		const s1 = await engine.callTool("nuwa_status", {});
		const s2 = await engine.callTool("nuwa_status", { query_status: "open", format: "json" });
		const s3 = await engine.callTool("nuwa_status", { raw: true, format: "json" });
		expect(s1.isError).toBe(false);
		expect(s2.isError).toBe(false);
		expect(s3.isError).toBe(false);

		const afterStat = statSync(stFile);
		expect(afterStat.mtimeMs).toBe(beforeStat.mtimeMs);
		expect(afterStat.size).toBe(beforeStat.size);
	});

	test("含认证口令的 egress 代理零明文落盘与零响应泄露，且 autoStart/baseline Schema 完整", async () => {
		const commitDef = getNuwaToolDefinition("nuwa_commit");
		expect(Array.isArray(commitDef?.inputSchema.properties.baseline?.oneOf)).toBe(true);

		const ws = makeTempDir("nuwa-mcp-egress-");
		const agentHome = makeTempDir("nuwa-mcp-egress-home-");
		const engine = new NuwaCoreEngine({
			projectRoot: ws,
			cwd: ws,
			sessionId: "egress-mask-session",
			agentHome,
		});

		const initRes = await engine.callTool("nuwa_init", {
			target: "http://127.0.0.1:18888",
			mode: "pentest",
			autoStart: true,
		});
		expect(initRes.isError).toBe(false);
		expect(initRes.details?.autoStartSkipped).toBe(true);

		const proxySecret = "SuperSecretProxyPass98765";
		const rawEgress = `socks5h://proxyuser:${proxySecret}@127.0.0.1:7890`;

		const planRes = await engine.callTool("nuwa_plan", {
			egress: rawEgress,
			intents: [
				{
					phase: "surface",
					title: "通过受控代理探测 /api/v1/health",
					targetKey: "/api/v1/health",
					expectedKind: "endpoint",
					surfaceDomain: "path",
				},
			],
			batch_tasks: [
				{
					id: "bt-1",
					title: "批派发出口测试",
					targetKey: "/api/v1/info",
					task: "curl -sS http://127.0.0.1:18888/api/v1/info",
				},
			],
		});
		expect(planRes.isError).toBe(false);
		const addedId = ((planRes.details?.added as string[]) ?? [])[0]!;
		expect(addedId).toBeTruthy();

		const claimRes = await engine.callTool("nuwa_claim", {
			id: addedId,
			egress: rawEgress,
		});
		expect(claimRes.isError).toBe(false);

		const stateRaw = readFileSync(join(ws, ".nuwa", "state.json"), "utf8");
		expect(stateRaw.includes(proxySecret)).toBe(false);
		expect(JSON.stringify(planRes).includes(proxySecret)).toBe(false);
		expect(JSON.stringify(claimRes).includes(proxySecret)).toBe(false);
	});

	test("Content-Length: 0 报 -32700、前置自定义头正常解析且单帧写出异常不锁死后续帧", async () => {
		// 1) Content-Length: 0 绝不静默丢弃，必须标记 invalidHeaderError 触发 -32700
		const clZeroBuf = Buffer.from("Content-Length: 0\r\n\r\n", "utf8");
		const clZeroFrame = extractNextMcpFrame(clZeroBuf, false);
		expect(clZeroFrame).not.toBeNull();
		expect(clZeroFrame!.invalidHeaderError).toBeTruthy();

		// 2) 自定义头在前 (X-Foo: bar) 的 Content-Length 帧不被误拆为 newline
		const pingBody = JSON.stringify(createJsonRpcRequest(99, "ping"));
		const customHdrBuf = Buffer.from(
			`X-Foo: bar\r\nContent-Length: ${Buffer.byteLength(pingBody, "utf8")}\r\n\r\n${pingBody}`,
			"utf8",
		);
		const customExtracted = extractNextMcpFrame(customHdrBuf, false);
		expect(customExtracted).not.toBeNull();
		expect(customExtracted!.framing).toBe("content-length");
		expect(JSON.parse(customExtracted!.rawJson).id).toBe(99);

		// 3) startStdioMcpServer 流式测试：Content-Length: 0 返回 -32700，且第 1 个正常请求写出抛错后第 2、3 个请求照常成功回写
		const ws = makeTempDir("nuwa-mcp-stream-resilience-");
		const agentHome = makeTempDir("nuwa-mcp-stream-home-");
		const engine = new NuwaCoreEngine({ projectRoot: ws, cwd: ws, agentHome });
		const input = new PassThrough();
		const writtenFrames: string[] = [];
		let writeCount = 0;

		const serverPromise = startStdioMcpServer({
			engine,
			input,
			output: {
				write(chunk: string | Uint8Array): boolean {
					writeCount += 1;
					// 模拟第 2 次写出发生瞬时流错误，验证会话链不会锁死
					if (writeCount === 2) {
						throw new Error("Simulated transient EAGAIN write error");
					}
					writtenFrames.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
					return true;
				},
			},
			errorOutput: {
				write(): boolean {
					return true;
				},
			},
			redirectConsoleToStderr: false,
		});

		input.write("Content-Length: 0\r\n\r\n");
		input.write(`${JSON.stringify(createJsonRpcRequest(1, "ping"))}\n`);
		input.write(`${JSON.stringify(createJsonRpcRequest(2, "ping"))}\n`);
		const req3 = JSON.stringify(createJsonRpcRequest(3, "ping"));
		input.write(`X-Trace-Id: t-003\r\nContent-Length: ${Buffer.byteLength(req3, "utf8")}\r\n\r\n${req3}`);
		input.end();

		await serverPromise;

		// writeCount === 1: Content-Length: 0 的 -32700 错误帧
		// writeCount === 2: id=1 模拟写出抛错被捕获隔离
		// writeCount === 3 & 4: id=2 与 id=3 正常恢复写出
		expect(writtenFrames.length).toBe(3);
		const errFrame = extractNextMcpFrame(Buffer.from(writtenFrames[0]!, "utf8"), true)!;
		expect(JSON.parse(errFrame.rawJson).error.code).toBe(JSONRPC_ERROR_CODES.PARSE_ERROR);

		expect(JSON.parse(writtenFrames[1]!.trim()).id).toBe(2);

		const okFrame3 = extractNextMcpFrame(Buffer.from(writtenFrames[2]!, "utf8"), true)!;
		expect(okFrame3.framing).toBe("content-length");
		expect(JSON.parse(okFrame3.rawJson).id).toBe(3);

		// 4) 仅实现 on/once/removeListener（无 off 与 resume）的兼容 NodeJS.ReadableStream 在 end 时通过 removeListener 清理监听
		const emitter = new EventEmitter();
		const compatStream: NodeJS.ReadableStream = {
			readable: true,
			on(ev: string, fn: (...args: any[]) => void) {
				emitter.on(ev, fn);
				return this;
			},
			once(ev: string, fn: (...args: any[]) => void) {
				emitter.once(ev, fn);
				return this;
			},
			removeListener(ev: string, fn: (...args: any[]) => void) {
				emitter.removeListener(ev, fn);
				return this;
			},
		};
		const compatOut: string[] = [];
		const compatPromise = startStdioMcpServer({
			engine,
			input: compatStream,
			output: {
				write(chunk: string | Uint8Array): boolean {
					compatOut.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
					return true;
				},
			},
			errorOutput: { write: () => true },
			redirectConsoleToStderr: false,
		});
		expect(emitter.listenerCount("data")).toBe(1);
		expect(emitter.listenerCount("end")).toBe(1);
		expect(emitter.listenerCount("error")).toBe(1);
		emitter.emit("data", `${JSON.stringify(createJsonRpcRequest("compat-1", "ping"))}\n`);
		emitter.emit("end");
		await compatPromise;
		expect(emitter.listenerCount("data")).toBe(0);
		expect(emitter.listenerCount("end")).toBe(0);
		expect(emitter.listenerCount("error")).toBe(0);
		expect(JSON.parse(compatOut[0]!.trim()).id).toBe("compat-1");
	});
});

describe("bin/nuwa-mcp 子进程真实 stdio JSON-RPC 2.0 端到端测试", () => {
	test("CLI --version 与 --help 正常输出且退出码为 0", async () => {
		const verProc = Bun.spawn([BIN_NUWA_MCP, "--version"], {
			stdout: "pipe",
			stderr: "pipe",
		});
		const verOut = await new Response(verProc.stdout).text();
		expect(await verProc.exited).toBe(0);
		expect(verOut).toContain("nuwa-mcp");
		expect(verOut).toContain(NUWA_MCP_PROTOCOL_VERSION);

		const helpProc = Bun.spawn([BIN_NUWA_MCP, "--help"], {
			stdout: "pipe",
			stderr: "pipe",
		});
		const helpOut = await new Response(helpProc.stdout).text();
		expect(await helpProc.exited).toBe(0);
		expect(helpOut).toContain("--project <dir>");
	});

	test("通过 Bun.spawn 驱动 NDJSON stdio 全链路：initialize / tools/list / nuwa_init / nuwa_plan / nuwa_status / nuwa_stop", async () => {
		const projectDir = makeTempDir("nuwa-mcp-stdio-proj-");
		const agentHome = makeTempDir("nuwa-mcp-stdio-home-");

		const proc = Bun.spawn([BIN_NUWA_MCP, "--project", projectDir], {
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
			env: {
				...process.env,
				PI_AGENT_HOME: agentHome,
			},
		});

		const requests = [
			createJsonRpcRequest(1, "initialize", {
				protocolVersion: NUWA_MCP_PROTOCOL_VERSION,
				capabilities: {},
				clientInfo: { name: "bun-e2e-test", version: "1.0.0" },
			}),
			createJsonRpcNotification("notifications/initialized"),
			createJsonRpcRequest(2, "ping"),
			createJsonRpcRequest(3, "tools/list"),
			createJsonRpcRequest(4, "tools/call", {
				name: "nuwa_init",
				arguments: {
					target: "http://127.0.0.1:19999",
					mode: "pentest",
					goal: "子进程 MCP 全链路验收测试",
				},
			}),
			createJsonRpcRequest(5, "tools/call", {
				name: "nuwa_plan",
				arguments: {
					phase: "surface",
					intents: [
						{
							title: "探测测试 API 版本路由 /api/v1/version",
							targetKey: "/api/v1/version",
							expectedKind: "endpoint",
							surfaceDomain: "path",
						},
					],
				},
			}),
			createJsonRpcRequest(6, "tools/call", {
				name: "nuwa_status",
				arguments: {},
			}),
			createJsonRpcRequest(7, "tools/call", {
				name: "nuwa_stop",
				arguments: {
					reason: "MCP 端到端测试正常结束硬停机",
					confirm: "STOP",
				},
			}),
		];

		for (const msg of requests) {
			proc.stdin.write(`${JSON.stringify(msg)}\n`);
		}
		proc.stdin.end();

		const rawStdout = await new Response(proc.stdout).text();
		const exitCode = await proc.exited;
		expect(exitCode).toBe(0);

		// 严格校验 stdout 每一行均为合法 JSON-RPC 2.0 响应帧，无任何杂散日志污染，且通知不回包（共 7 个请求帧）
		const lines = rawStdout
			.split("\n")
			.map((l) => l.trim())
			.filter(Boolean);
		expect(lines.length).toBe(7);

		const responses = lines.map((line) => JSON.parse(line) as {
			jsonrpc: string;
			id: number;
			result?: Record<string, unknown>;
			error?: unknown;
		});
		for (const r of responses) {
			expect(r.jsonrpc).toBe("2.0");
			expect(r.error).toBeUndefined();
		}

		expect(responses.map((r) => r.id)).toEqual([1, 2, 3, 4, 5, 6, 7]);
		expect(responses[0]!.result?.protocolVersion).toBe(NUWA_MCP_PROTOCOL_VERSION);

		const listedTools = (responses[2]!.result?.tools as Array<{ name: string }>) ?? [];
		expect(listedTools.length).toBe(12);
		expect(listedTools.map((t) => t.name)).toEqual([...NUWA_TOOL_NAMES]);

		const initDetails = (responses[3]!.result?.details as { root?: string }) ?? {};
		expect(initDetails.root).toBe(projectDir);
		expect(existsSync(join(projectDir, ".nuwa", "state.json"))).toBe(true);

		const planDetails = (responses[4]!.result?.details as { added?: string[] }) ?? {};
		expect((planDetails.added ?? []).length).toBeGreaterThanOrEqual(1);

		const statusDetails = (responses[5]!.result?.details as { status?: string }) ?? {};
		expect(statusDetails.status).toBe("active");

		const stopDetails = (responses[6]!.result?.details as { stopped?: boolean }) ?? {};
		expect(stopDetails.stopped).toBe(true);
	});

	test("通过 Bun.spawn 验证 Content-Length 帧格式 stdio 双向通信", async () => {
		const projectDir = makeTempDir("nuwa-mcp-cl-proj-");
		const agentHome = makeTempDir("nuwa-mcp-cl-home-");

		const proc = Bun.spawn([BIN_NUWA_MCP, "--project", projectDir], {
			stdin: "pipe",
			stdout: "pipe",
			stderr: "pipe",
			env: {
				...process.env,
				PI_AGENT_HOME: agentHome,
			},
		});

		const toClFrame = (obj: unknown) => {
			const s = JSON.stringify(obj);
			return `Content-Length: ${Buffer.byteLength(s, "utf8")}\r\n\r\n${s}`;
		};

		proc.stdin.write(
			toClFrame(
				createJsonRpcRequest("cl-1", "initialize", {
					protocolVersion: NUWA_MCP_PROTOCOL_VERSION,
				}),
			),
		);
		proc.stdin.write(toClFrame(createJsonRpcNotification("notifications/initialized")));
		proc.stdin.write(
			toClFrame(
				createJsonRpcRequest("cl-2", "tools/call", {
					name: "nuwa_kb",
					arguments: { query: "spring", limit: 3 },
				}),
			),
		);
		proc.stdin.end();

		const stdoutBuf = Buffer.from(await new Response(proc.stdout).arrayBuffer());
		expect(await proc.exited).toBe(0);

		const parsedFrames: Array<{ id: string; framing: string; result?: Record<string, unknown> }> = [];
		let cursor = stdoutBuf;
		while (cursor.length > 0) {
			const f = extractNextMcpFrame(cursor, true);
			if (!f || !f.rawJson) break;
			const obj = JSON.parse(f.rawJson) as { id: string; result?: Record<string, unknown> };
			parsedFrames.push({ id: obj.id, framing: f.framing, result: obj.result });
			cursor = cursor.subarray(f.consumedBytes);
		}

		expect(parsedFrames.length).toBe(2);
		expect(parsedFrames[0]!.framing).toBe("content-length");
		expect(parsedFrames[0]!.id).toBe("cl-1");
		expect(parsedFrames[1]!.framing).toBe("content-length");
		expect(parsedFrames[1]!.id).toBe("cl-2");
		expect(parsedFrames[1]!.result?.isError).toBe(false);
	});
});

describe("benchmarks/run-l2-eval.ts L2 五场景微基准全量验收与硬门禁校验", () => {
	test("实跑 runL2BenchmarkSuite() 验证 5 场景全绿且四大硬门禁 100% 达标", async () => {
		const summary = await runL2BenchmarkSuite({ deterministic: true });

		expect(summary.schema).toBe(2);
		expect(summary.scenarios.length).toBe(5);
		expect(summary.scenarios.map((s) => s.id)).toEqual(L2_SCENARIO_SPECS.map((s) => s.id));

		for (const sc of summary.scenarios) {
			expect(sc.error).toBeUndefined();
			expect(sc.passed).toBe(true);
		}

		// 硬门禁逐项断言
		expect(summary.metrics.recallRate).toBe(1.0);
		expect(summary.metrics.falsePositiveRate).toBe(0);
		expect(summary.metrics.vaultLeakCount).toBe(0);
		expect(summary.metrics.hardenedSealTurns).toBeGreaterThan(0);
		expect(summary.metrics.hardenedSealTurns).toBeLessThanOrEqual(15);

		const hardened = summary.scenarios.find((s) => s.id === "t5-hardened-zero-vuln")!;
		expect(hardened.terminalStatus).toBe("sealed_negative");
		expect(hardened.turnsUsed).toBeLessThanOrEqual(15);
		expect(hardened.falsePositives).toBe(0);

		expect(summary.gates.recallGate).toBe(true);
		expect(summary.gates.zeroFalsePositiveGate).toBe(true);
		expect(summary.gates.zeroVaultLeakGate).toBe(true);
		expect(summary.gates.hardenedConvergenceGate).toBe(true);
		expect(summary.gates.allPassed).toBe(true);
	}, 30_000);

	test("支持 --scenario 单场景过滤运行与非法场景参数拦截", async () => {
		await expect(runL2BenchmarkSuite({ scenario: "nonexistent-scenario" })).rejects.toThrow("未知 L2 场景 ID");

		const cliProc = Bun.spawn(
			["bun", join(REPO_ROOT, "benchmarks", "run-l2-eval.ts"), "--json", "--scenario", "t5-hardened-zero-vuln"],
			{
				cwd: REPO_ROOT,
				stdout: "pipe",
				stderr: "pipe",
			},
		);
		const cliOut = await new Response(cliProc.stdout).text();
		expect(await cliProc.exited).toBe(0);

		const parsed = JSON.parse(cliOut) as {
			scenarios: Array<{ id: string; terminalStatus: string }>;
			gates: { allPassed: boolean };
		};
		expect(parsed.scenarios.length).toBe(1);
		expect(parsed.scenarios[0]!.id).toBe("t5-hardened-zero-vuln");
		expect(parsed.scenarios[0]!.terminalStatus).toBe("sealed_negative");
		expect(parsed.gates.allPassed).toBe(true);
	}, 30_000);

	test("t3-blind-ssrf-oob 严格限定仅允许回调本场景专属 collectorPort，拒绝其他本机端口", async () => {
		const srv = startL2ScenarioServer("t3-blind-ssrf-oob");
		try {
			// 尝试回调目标服务自身或其他非 collector 的 127.0.0.1 端口，必须被 400 拦截
			const wrongPortRes = await fetch(`${srv.baseUrl}/api/v1/integrations/health-callback`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ callbackUrl: `http://127.0.0.1:${srv.port}/healthz` }),
			});
			expect(wrongPortRes.status).toBe(400);

			// 回调本场景专属 collectorPort 时放行并返回 202
			const okRes = await fetch(`${srv.baseUrl}/api/v1/integrations/health-callback`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ callbackUrl: `${srv.collectorUrl}/callback/port-guard-ok` }),
			});
			expect(okRes.status).toBe(202);
			expect(srv.getCollectorEvents().length).toBe(1);
		} finally {
			srv.stop();
		}
	});
});
