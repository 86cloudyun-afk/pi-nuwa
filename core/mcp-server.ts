/**
 * 女娲 v7.0 宿主无关 JSON-RPC 2.0 over stdio MCP Server（纯 Bun/TS，零外部依赖）。
 *
 * 职责：
 * 1. `NuwaCoreEngine`：全面委托给单一权威内核 `NuwaUnifiedEngine`（`core/engine.ts`），
 *    消除 `omp/nuwa.ts` 与 `core/mcp-server.ts` 之间的双核分叉逻辑，100% 保持既有 API 兼容；
 * 2. `handleMcpMessage`：支持 MCP `initialize`、`notifications/initialized`、`ping`、`tools/list`、`tools/call`；
 * 3. `startStdioMcpServer`：同时兼容按换行分隔 JSON-RPC（NDJSON）与 `Content-Length` 字节帧格式，
 *    严格保证 `stdout` 仅输出合法 JSON-RPC 2.0 帧，所有诊断日志统一路由至 `stderr`。
 */
import { resolve } from "node:path";
import { format as formatUtil } from "node:util";
import { NuwaUnifiedEngine } from "./engine";
import {
	JSONRPC_ERROR_CODES,
	JSONRPC_VERSION,
	NUWA_CORE_SERVER_NAME,
	NUWA_CORE_SERVER_VERSION,
	NUWA_MCP_PROTOCOL_VERSION,
	createJsonRpcError,
	createJsonRpcSuccess,
	isNuwaToolName,
	isValidJsonRpcId,
	type JsonRpcId,
	type JsonRpcResponse,
	type McpInitializeResult,
} from "./protocol";

function isPlainRecord(val: unknown): val is Record<string, unknown> {
	return Boolean(val && typeof val === "object" && !Array.isArray(val));
}

export interface NuwaCoreEngineOptions {
	/** 显式绑定的默认项目根目录（如 CLI `--project <dir>`）。 */
	projectRoot?: string;
	/** 基准工作目录（默认 `process.cwd()`）。 */
	cwd?: string;
	/** 当前宿主无关会话标识（默认 `mcp-<pid>`）。 */
	sessionId?: string;
	/** 可选自定义 Agent Home 路径。 */
	agentHome?: string;
}

/**
 * 宿主无关的女娲核心工具执行引擎（v7.0 单核合一委托层）。
 * 直接继承 `NuwaUnifiedEngine`，独立驱动全部 12 个 `nuwa_*` 工具，零特定宿主 SDK 依赖。
 */
export class NuwaCoreEngine extends NuwaUnifiedEngine {
	constructor(opts?: NuwaCoreEngineOptions) {
		super({
			projectRoot: opts?.projectRoot,
			cwd: opts?.cwd,
			sessionId: (opts?.sessionId ?? "").trim() || `mcp-${process.pid}`,
			agentHome: opts?.agentHome,
			hostAgentId: "nuwa-mcp",
			emitAutoStartSkipNote: true,
		});
	}
}

async function handleSingleRpcObject(
	rawObj: unknown,
	engine: NuwaUnifiedEngine,
): Promise<JsonRpcResponse | null> {
	if (!isPlainRecord(rawObj)) {
		return createJsonRpcError(null, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: expected JSON object");
	}
	const rec = rawObj;
	const hasIdField = Object.prototype.hasOwnProperty.call(rec, "id");
	const safeId: JsonRpcId = hasIdField && isValidJsonRpcId(rec.id) ? rec.id : null;

	if (rec.jsonrpc !== JSONRPC_VERSION) {
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"');
	}
	if (typeof rec.method !== "string" || !rec.method.trim()) {
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: method must be non-empty string");
	}
	if (hasIdField && !isValidJsonRpcId(rec.id)) {
		return createJsonRpcError(null, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: invalid id type");
	}

	const method = rec.method;
	const params = rec.params;
	if (params !== undefined && (typeof params !== "object" || params === null)) {
		if (!hasIdField) return null;
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INVALID_PARAMS, "Invalid params: expected object or array");
	}

	// JSON-RPC 2.0 Notification（无 id 字段）：严禁向客户端返回响应帧
	if (!hasIdField) {
		if (method === "notifications/initialized" || method === "initialized") {
			engine.markInitialized();
		}
		return null;
	}

	try {
		switch (method) {
			case "initialize": {
				engine.markInitialized();
				const initResult: McpInitializeResult = {
					protocolVersion: NUWA_MCP_PROTOCOL_VERSION,
					capabilities: {
						tools: {
							listChanged: false,
						},
					},
					serverInfo: {
						name: NUWA_CORE_SERVER_NAME,
						version: NUWA_CORE_SERVER_VERSION,
					},
				};
				return createJsonRpcSuccess(safeId, initResult);
			}

			case "ping": {
				return createJsonRpcSuccess(safeId, {});
			}

			case "tools/list": {
				return createJsonRpcSuccess(safeId, {
					tools: engine.listTools(),
				});
			}

			case "tools/call": {
				if (!isPlainRecord(params)) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						"Invalid params: tools/call requires object params",
					);
				}
				const toolName = params.name;
				if (typeof toolName !== "string" || !toolName.trim()) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						"Invalid params: missing tool name",
					);
				}
				if (!isNuwaToolName(toolName)) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						`Unknown tool: ${toolName}`,
					);
				}
				if (params.arguments !== undefined && !isPlainRecord(params.arguments)) {
					return createJsonRpcError(
						safeId,
						JSONRPC_ERROR_CODES.INVALID_PARAMS,
						"Invalid params: tool arguments must be an object",
					);
				}
				const callRes = await engine.callTool(toolName, params.arguments as Record<string, unknown> | undefined);
				return createJsonRpcSuccess(safeId, callRes);
			}

			default: {
				return createJsonRpcError(
					safeId,
					JSONRPC_ERROR_CODES.METHOD_NOT_FOUND,
					`Method not found: ${method}`,
				);
			}
		}
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return createJsonRpcError(safeId, JSONRPC_ERROR_CODES.INTERNAL_ERROR, `Internal error: ${message}`);
	}
}

/**
 * 处理单条或批量 JSON-RPC 2.0 / MCP 消息。
 * 对通知消息（如 `notifications/initialized`）返回 `null`，调用方不得输出响应帧。
 */
export async function handleMcpMessage(
	msg: unknown,
	engine: NuwaUnifiedEngine,
): Promise<JsonRpcResponse | JsonRpcResponse[] | null> {
	if (Array.isArray(msg)) {
		if (msg.length === 0) {
			return createJsonRpcError(null, JSONRPC_ERROR_CODES.INVALID_REQUEST, "Invalid Request: empty batch");
		}
		const batchOut: JsonRpcResponse[] = [];
		for (const item of msg) {
			const res = await handleSingleRpcObject(item, engine);
			if (res !== null) batchOut.push(res);
		}
		return batchOut.length > 0 ? batchOut : null;
	}
	return handleSingleRpcObject(msg, engine);
}

export type McpFramingMode = "newline" | "content-length";

interface ExtractedFrame {
	rawJson: string;
	framing: McpFramingMode;
	consumedBytes: number;
	invalidHeaderError?: string;
}

const MAX_MCP_FRAME_BYTES = 64 * 1024 * 1024;

/**
 * 从字节流缓冲区提取单个完整帧：
 * - 自动识别 `Content-Length: <N>\r\n\r\n<UTF8-Body>`（兼容 `\n\n` 头分隔）按字节长度精确切片；
 * - 自动识别按换行分隔的 JSON-RPC（NDJSON）；
 * - 半包时返回 `null` 等待后续字节到达。
 */
export function extractNextMcpFrame(buf: Buffer, isEof = false): ExtractedFrame | null {
	let offset = 0;
	while (offset < buf.length) {
		const b = buf[offset]!;
		if (b === 0x0d || b === 0x0a || b === 0x20 || b === 0x09) {
			offset += 1;
		} else {
			break;
		}
	}
	if (offset >= buf.length) {
		return offset > 0 ? { rawJson: "", framing: "newline", consumedBytes: offset } : null;
	}

	const working = offset > 0 ? buf.subarray(offset) : buf;
	const firstByte = working[0]!;

	// 非 '{' 且非 '[' 开头时，检测是否为 Content-Length / HTTP MIME 头帧（兼容任意前置自定义头与半包等待）
	if (firstByte !== 0x7b && firstByte !== 0x5b) {
		const previewAscii = working.subarray(0, Math.min(working.length, 256)).toString("latin1");
		const hasHeaderLine = /^[A-Za-z][A-Za-z0-9-]*\s*:/m.test(previewAscii) && /^[A-Za-z][A-Za-z0-9-]*\s*:/.test(previewAscii);
		const looksLikeHeaderPrefix =
			!isEof && working.length < 64 && /^[A-Za-z][A-Za-z0-9-]*[ \t]*:?$/.test(previewAscii);

		if (hasHeaderLine || looksLikeHeaderPrefix) {
			const crlfIdx = working.indexOf("\r\n\r\n");
			const lfIdx = working.indexOf("\n\n");
			let headerEnd = -1;
			let sepLen = 0;
			if (crlfIdx >= 0 && (lfIdx < 0 || crlfIdx <= lfIdx)) {
				headerEnd = crlfIdx;
				sepLen = 4;
			} else if (lfIdx >= 0) {
				headerEnd = lfIdx;
				sepLen = 2;
			}

			if (headerEnd < 0) {
				if (!isEof && working.length < 8192) return null;
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + working.length,
					invalidHeaderError: "Incomplete Content-Length header",
				};
			}

			const headerText = working.subarray(0, headerEnd).toString("latin1");
			const match = /(?:^|\r?\n)content-length\s*:\s*(\d+)\s*(?:\r?\n|$)/i.exec(headerText);
			if (!match) {
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + headerEnd + sepLen,
					invalidHeaderError: "Missing Content-Length value",
				};
			}
			const bodyBytes = Number(match[1]);
			if (!Number.isSafeInteger(bodyBytes) || bodyBytes <= 0 || bodyBytes > MAX_MCP_FRAME_BYTES) {
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + headerEnd + sepLen,
					invalidHeaderError: `Invalid Content-Length: ${match[1]}`,
				};
			}
			const bodyStart = headerEnd + sepLen;
			if (working.length < bodyStart + bodyBytes) {
				if (!isEof) return null;
				return {
					rawJson: "",
					framing: "content-length",
					consumedBytes: offset + working.length,
					invalidHeaderError: "Truncated Content-Length frame body at EOF",
				};
			}
			const rawJson = working.subarray(bodyStart, bodyStart + bodyBytes).toString("utf8");
			return {
				rawJson,
				framing: "content-length",
				consumedBytes: offset + bodyStart + bodyBytes,
			};
		}
	}

	// 按换行分隔 JSON-RPC（NDJSON），带最大单帧内存上限保护
	const nlIdx = working.indexOf(0x0a);
	if (nlIdx < 0) {
		if (working.length > MAX_MCP_FRAME_BYTES) {
			return {
				rawJson: "",
				framing: "newline",
				consumedBytes: offset + working.length,
				invalidHeaderError: `NDJSON frame exceeds maximum byte limit (${MAX_MCP_FRAME_BYTES})`,
			};
		}
		if (!isEof) return null;
		const tail = working.toString("utf8").replace(/\r$/, "").trim();
		return {
			rawJson: tail,
			framing: "newline",
			consumedBytes: offset + working.length,
		};
	}
	if (nlIdx > MAX_MCP_FRAME_BYTES) {
		return {
			rawJson: "",
			framing: "newline",
			consumedBytes: offset + nlIdx + 1,
			invalidHeaderError: `NDJSON frame exceeds maximum byte limit (${MAX_MCP_FRAME_BYTES})`,
		};
	}
	const line = working.subarray(0, nlIdx).toString("utf8").replace(/\r$/, "").trim();
	return {
		rawJson: line,
		framing: "newline",
		consumedBytes: offset + nlIdx + 1,
	};
}

/** 将 JSON-RPC 响应对象编码为指定帧格式字符串。 */
export function encodeMcpFrame(payload: JsonRpcResponse | JsonRpcResponse[], framing: McpFramingMode): string {
	const json = JSON.stringify(payload);
	if (framing === "content-length") {
		const byteLen = Buffer.byteLength(json, "utf8");
		return `Content-Length: ${byteLen}\r\n\r\n${json}`;
	}
	return `${json}\n`;
}

export interface StartStdioMcpServerOptions {
	engine?: NuwaUnifiedEngine;
	projectRoot?: string;
	cwd?: string;
	sessionId?: string;
	input?: NodeJS.ReadableStream;
	output?: { write(chunk: string | Uint8Array): unknown };
	errorOutput?: { write(chunk: string | Uint8Array): unknown };
	/** 是否将全局 `console.log/info/warn/debug` 重定向到 stderr 以保护 stdout 纯净（默认 true）。 */
	redirectConsoleToStderr?: boolean;
}

/**
 * 启动 stdio MCP 协议服务端并监听输入流直至 EOF。
 * 严格保证 `stdout` 只输出合法 JSON-RPC 2.0 帧，所有诊断信息写往 `stderr`。
 */
export async function startStdioMcpServer(opts?: StartStdioMcpServerOptions): Promise<void> {
	const input = opts?.input ?? process.stdin;
	const output = opts?.output ?? process.stdout;
	const errOut = opts?.errorOutput ?? process.stderr;
	const rawWriteOut = output.write.bind(output);
	const rawWriteErr = errOut.write.bind(errOut);

	const logDiag = (...args: unknown[]): void => {
		try {
			rawWriteErr(`[nuwa-mcp] ${formatUtil(...args)}\n`);
		} catch {
			/* ignore stderr EPIPE */
		}
	};

	const shouldRedirectConsole = opts?.redirectConsoleToStderr !== false;
	const prevConsole = {
		log: console.log,
		info: console.info,
		warn: console.warn,
		debug: console.debug,
	};
	if (shouldRedirectConsole) {
		const redirectFn = (...args: unknown[]) => {
			try {
				rawWriteErr(`${formatUtil(...args)}\n`);
			} catch {
				/* ignore */
			}
		};
		console.log = redirectFn;
		console.info = redirectFn;
		console.warn = redirectFn;
		console.debug = redirectFn;
	}

	const engine =
		opts?.engine ??
		new NuwaCoreEngine({
			projectRoot: opts?.projectRoot,
			cwd: opts?.cwd,
			sessionId: opts?.sessionId,
		});

	let buffer = Buffer.alloc(0);
	let chain = Promise.resolve();

	const dispatchFrame = (frame: ExtractedFrame): void => {
		if (frame.framing === "newline" && !frame.rawJson && !frame.invalidHeaderError) return;
		chain = chain.then(async () => {
			try {
				if (frame.invalidHeaderError) {
					logDiag(`协议帧头异常: ${frame.invalidHeaderError}`);
					const errResp = createJsonRpcError(
						null,
						JSONRPC_ERROR_CODES.PARSE_ERROR,
						`Parse error: ${frame.invalidHeaderError}`,
					);
					rawWriteOut(encodeMcpFrame(errResp, frame.framing));
					return;
				}
				let parsed: unknown;
				try {
					parsed = JSON.parse(frame.rawJson);
				} catch (err) {
					logDiag(`JSON 解析失败: ${err instanceof Error ? err.message : String(err)}`);
					const errResp = createJsonRpcError(null, JSONRPC_ERROR_CODES.PARSE_ERROR, "Parse error: invalid JSON");
					rawWriteOut(encodeMcpFrame(errResp, frame.framing));
					return;
				}
				const response = await handleMcpMessage(parsed, engine);
				if (response !== null) {
					rawWriteOut(encodeMcpFrame(response, frame.framing));
				}
			} catch (err) {
				logDiag(`单帧处理/写出异常（已隔离恢复，不影响后续帧）: ${err instanceof Error ? err.message : String(err)}`);
			}
		});
	};

	const drainBuffer = (isEof: boolean): void => {
		for (;;) {
			const frame = extractNextMcpFrame(buffer, isEof);
			if (!frame) break;
			buffer = buffer.subarray(frame.consumedBytes);
			dispatchFrame(frame);
			if (buffer.length === 0) break;
		}
	};

	try {
		await new Promise<void>((resolveDone, rejectDone) => {
			const onData = (chunk: Buffer | string) => {
				const bufChunk = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
				buffer = buffer.length === 0 ? bufChunk : Buffer.concat([buffer, bufChunk]);
				drainBuffer(false);
			};
			const onEnd = () => {
				cleanupListeners();
				drainBuffer(true);
				chain.then(resolveDone, rejectDone);
			};
			const onError = (err: Error) => {
				cleanupListeners();
				logDiag(`输入流异常: ${err.message}`);
				chain.then(() => rejectDone(err), rejectDone);
			};
			const cleanupListeners = () => {
				if (typeof input.off === "function") {
					input.off("data", onData);
					input.off("end", onEnd);
					input.off("error", onError);
				} else if (typeof input.removeListener === "function") {
					input.removeListener("data", onData);
					input.removeListener("end", onEnd);
					input.removeListener("error", onError);
				}
			};

			input.on("data", onData);
			input.on("end", onEnd);
			input.on("error", onError);
			if (typeof input.resume === "function") {
				input.resume();
			}
		});
	} finally {
		if (shouldRedirectConsole) {
			console.log = prevConsole.log;
			console.info = prevConsole.info;
			console.warn = prevConsole.warn;
			console.debug = prevConsole.debug;
		}
	}
}

export interface NuwaMcpCliArgs {
	version: boolean;
	help: boolean;
	projectRoot?: string;
}

/** 解析 `nuwa-mcp` 命令行参数。 */
export function parseNuwaMcpCliArgs(argv: readonly string[]): NuwaMcpCliArgs {
	let version = false;
	let help = false;
	let projectRoot: string | undefined;

	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i]!;
		if (arg === "--version" || arg === "-v") {
			version = true;
		} else if (arg === "--help" || arg === "-h") {
			help = true;
		} else if (arg === "--project") {
			const val = argv[++i];
			if (!val || val.startsWith("-")) {
				throw new Error("--project 需要指定目录路径");
			}
			projectRoot = resolve(val);
		} else if (arg.startsWith("--project=")) {
			const val = arg.slice("--project=".length).trim();
			if (!val) {
				throw new Error("--project= 需要指定非空目录路径");
			}
			projectRoot = resolve(val);
		} else {
			throw new Error(`未知参数: ${arg}`);
		}
	}

	return { version, help, projectRoot };
}

/** 运行 `nuwa-mcp` CLI 主入口。 */
export async function runNuwaMcpCli(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
	let parsed: NuwaMcpCliArgs;
	try {
		parsed = parseNuwaMcpCliArgs(argv);
	} catch (err) {
		process.stderr.write(`[nuwa-mcp] 参数错误: ${err instanceof Error ? err.message : String(err)}\n`);
		return 2;
	}

	if (parsed.help) {
		process.stdout.write(
			[
				`${NUWA_CORE_SERVER_NAME} v${NUWA_CORE_SERVER_VERSION} — 女娲跨宿主 MCP 协议服务 (protocol ${NUWA_MCP_PROTOCOL_VERSION})`,
				"",
				"用法:",
				"  nuwa-mcp [--project <dir>] [--version] [--help]",
				"",
				"选项:",
				"  --project <dir>   绑定默认女娲项目工作区目录（同时注入 NUWA_PROJECT）",
				"  -v, --version     输出服务端与 MCP 协议版本号",
				"  -h, --help        显示本帮助说明",
				"",
			].join("\n"),
		);
		return 0;
	}

	if (parsed.version) {
		process.stdout.write(`${NUWA_CORE_SERVER_NAME} ${NUWA_CORE_SERVER_VERSION} (mcp ${NUWA_MCP_PROTOCOL_VERSION})\n`);
		return 0;
	}

	if (parsed.projectRoot) {
		process.env.NUWA_PROJECT = parsed.projectRoot;
	}

	await startStdioMcpServer({
		projectRoot: parsed.projectRoot,
	});
	return 0;
}

if (import.meta.main) {
	const code = await runNuwaMcpCli(process.argv.slice(2));
	process.exit(code);
}
