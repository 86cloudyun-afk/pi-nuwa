/**
 * 女娲 v7.0 `omp` 异步派单桥接、占位符展开与子代理看门狗协调引擎。
 *
 * 职责：
 * 1. `DispatchBridgeStore` & `PendingToolDispatch`：零私有全局态管理 `tool_call("task"|"eval")` 前置缓冲、
 *    在途 `activeSpawns` 映射、会话活跃计数 `liveCalls` 以及执行证据去重集合；
 * 2. `handleToolCallDispatch`：处理 `task` 空数组拦截、4 MiB `taskFile` 读取与占位符替换、`context` 纯 URL/Host 无头展开、
 *    `eval` 多 `agent({ label, prompt })` 平衡解析，以及“先展开占位符再过 Scope 护栏”校验；
 * 3. `handleBeforeSubagentSpawn`：对接 `omp 18.16.0` 无内联 `task` 的 `{ type, agent, invocationKind, spawnKey }` 协议，
 *    完成派单回执登记、脱敏出口注入、动态模型路由、反自证校准事前预测登记与 `SubagentWatchdog` 追踪；
 * 4. `handleToolExecutionEnd` & `handleToolResult`：完美处理 `omp 18.16.0` 默认 `async.state === "running"` 先返回 `progress[]`
 *    后异步乱序 `before_subagent_spawn` 的竞态，杜绝误注销已有看门狗任务并实现一对一精确回收与执行账本去重落账。
 *
 * 约束：零外部依赖，零 `@oh-my-pi/pi-coding-agent` 运行时导入，严禁运行时 `import "./nuwa"`。
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { NuwaState, PolicyVerdict } from "./types";
import {
	SubagentWatchdog,
	findRoot,
	getAgentHome,
	loadState,
	logEvent,
	readCfg,
} from "./storage";
import {
	checkBashPolicy,
	checkTaskPolicy,
	checkWritePolicy,
	extractEventOutput,
	isCompliantSandboxDockerCommand,
	loadOrInitBeliefGraph,
} from "./graph";
import { checkToolScopeAndRisk, defaultScopeForTarget } from "./scope";
import { isTrustedEvidenceEvent, recordToolExecution } from "./evidence";
import {
	type BatchTaskItem,
	type DispatchReceiptRegistry,
	bindSubagentSpawn,
	buildDispatchPacket,
	chunkBatchTasks,
	createDispatchReceiptRegistry,
	inferCalibrationTaskCategory,
	resolveLineageRoot,
	resolveTaskIntentContext,
	routeSubagentModel,
	validateSubagentDispatch,
} from "./lineage";
import {
	extractSandboxInnerCommand,
	isCompliantSidecarCommand,
	maskEgressUrl,
	normalizeTaskEgressUrl,
	readSandboxConfig,
	resolveConfiguredEgressUrl,
	wrapCommandInDockerSandbox,
	wrapCommandInSidecarSandbox,
} from "./sandbox";
import { resolveBeliefNodeId } from "./belief-search";
import { recordPrediction } from "./calibration";

export const DISPATCH_EMPTY_CONTEXT_RE =
	/\b(?:no\s+assigned\s+task|awaiting\s+work\s+item|no\s+task\s+provided|empty\s+task)\b/i;

export const DISPATCH_PLACEHOLDER_CASE_RE =
	/\[(?:TARGET|HOST|DOMAIN|URL|TARGET_URL)\]|https?:\/\/(?:TARGET|HOST|DOMAIN)(?::\d+)?(?![A-Za-z0-9_])|\$\{(?:TARGET|HOST|DOMAIN|U)\}|\$(?:TARGET|HOST|DOMAIN|U)(?![A-Za-z0-9_])/;

export const PENDING_DISPATCH_TTL_MS = 5 * 60_000;
export const EVAL_DISPATCH_WINDOW_TTL_MS = 60_000;
export const MAX_OMP_TASK_FILE_BYTES = 4 * 1024 * 1024;
export const TASK_FILE_PREVIEW_BYTES = 512 * 1024;

const TERMINAL_PROGRESS_STATES = new Set(["completed", "failed", "error", "aborted", "cancelled"]);

/** 宿主无关的轻量上下文契约（直接兼容 omp `ExtensionContext`）。 */
export interface DispatchBridgeContext {
	cwd: string;
	sessionId?: string;
	agent?: {
		kind?: string;
		id?: string;
		name?: string;
		parentId?: string;
		depth?: number;
	};
	sessionManager?: {
		getSessionId?: () => string;
		getParentSessionId?: () => string | undefined;
	};
}

/** 前置 `tool_call("task" | "eval")` 缓冲派单条目。 */
export interface PendingToolDispatch {
	seq: number;
	root: string;
	sessionId: string;
	toolCallId?: string;
	invocationKind: "task" | "eval";
	agent: string;
	name?: string;
	index: number;
	taskText: string;
	context?: Record<string, unknown> | string;
	spawnKeyCandidates: string[];
	asyncPending?: boolean;
	evalWindow?: boolean;
	reusable?: boolean;
	createdAt: number;
}

/** 正在运行中的子代理派生追踪记录（用于无显式 spawnId 时的精确配对回收）。 */
export interface ActiveSubagentSpawn {
	spawnId: string;
	root: string;
	agent: string;
	toolCallId?: string;
	intentId?: string;
	rawTask: string;
	injectedTask: string;
	sessionId: string;
}

export interface DispatchToolCallEvent {
	toolName: string;
	toolCallId?: string;
	input?: Record<string, unknown>;
}

export type DispatchToolCallResult =
	| PolicyVerdict
	| { input: Record<string, unknown>; additionalContext?: string }
	| undefined;

export type BeforeSubagentSpawnResult =
	| { block: true; requeue?: boolean; reason: string }
	| { model?: string; spawnId: string; task: string }
	| undefined;

export interface ParsedEvalAgentCall {
	agent: string;
	agentExplicit: boolean;
	prompt?: string;
	label?: string;
	hasEmptyPrompt: boolean;
}

export interface DispatchBridgeOptions {
	/** 可选自定义项目根解析器。 */
	resolveRoot?: (ctx: DispatchBridgeContext) => string | null;
	/** 可选自定义 Agent Home 解析器。 */
	getAgentHome?: () => string;
}

function isTerminalStateInternal(st: NuwaState | null | undefined): boolean {
	if (!st) return false;
	const ps = st.project?.status;
	const rs = st.runtime?.status;
	return ps === "sealed_negative" || rs === "sealed_negative" || ps === "completed" || rs === "completed";
}

export function getBridgeSessionId(ctx: DispatchBridgeContext): string {
	if (typeof ctx.sessionId === "string" && ctx.sessionId.trim()) {
		return ctx.sessionId.trim();
	}
	try {
		const sid = ctx.sessionManager?.getSessionId?.();
		if (sid && sid.trim()) return sid.trim();
	} catch {
		/* ignore */
	}
	return "default";
}

export function isMainBridgeAgent(ctx: DispatchBridgeContext): boolean {
	try {
		if (!ctx.agent?.kind) return true;
		return ctx.agent.kind === "main";
	} catch {
		return true;
	}
}

export function resolveBridgeRoot(ctx: DispatchBridgeContext, opts?: DispatchBridgeOptions): string | null {
	if (opts?.resolveRoot) {
		return opts.resolveRoot(ctx);
	}
	const sid = getBridgeSessionId(ctx);
	const agentHome = opts?.getAgentHome ? opts.getAgentHome() : getAgentHome();
	const lineageHit = resolveLineageRoot(
		{
			cwd: ctx.cwd,
			sessionId: sid,
			agent: ctx.agent,
			sessionManager: ctx.sessionManager,
		},
		agentHome,
	);
	return lineageHit ?? findRoot(ctx.cwd, sid);
}

function getDispatchRegistry(root: string): DispatchReceiptRegistry {
	return createDispatchReceiptRegistry(join(resolve(root), ".nuwa", "dispatch-receipts.json"));
}

/**
 * 读取 `taskFile` 文件内容（强制 4 MiB 硬上限防 OOM，`text` 提供 512 KiB 缓冲预览，`fullText` 保留完整正文供内联展开）。
 */
export function readTaskFileForDispatch(
	filePath: string,
): { exists: boolean; unreadable?: boolean; empty?: boolean; tooLarge?: boolean; text: string; fullText?: string } {
	try {
		const fStat = statSync(filePath);
		if (!fStat.isFile()) return { exists: false, text: "" };
		if (fStat.size > MAX_OMP_TASK_FILE_BYTES) {
			return { exists: true, tooLarge: true, text: "" };
		}
		if (fStat.size === 0) return { exists: true, empty: true, text: "" };
		const raw = readFileSync(filePath, "utf8");
		const trimmed = raw.trim();
		if (!trimmed) return { exists: true, empty: true, text: "" };
		return {
			exists: true,
			empty: false,
			text: trimmed.length > TASK_FILE_PREVIEW_BYTES ? trimmed.slice(0, TASK_FILE_PREVIEW_BYTES) : trimmed,
			fullText: trimmed,
		};
	} catch {
		return { exists: false, unreadable: true, text: "" };
	}
}

/**
 * 纯无头占位符展开器（专门用于 `context` 纯 URL/字典字段及字符串字面量，绝不插入多行说明头、绝不截断误伤 `$USER`/`$URL`/`$TARGET_ID`/`$HOSTNAME`，亦不做裸词替换）。
 */
export function expandPlaceholdersPlain(
	raw: string,
	targetInfo: { url: string; host: string },
): string {
	let body = String(raw ?? "");
	const targetUrl = String(targetInfo.url ?? "").trim();
	const resolvedHost = String(targetInfo.host ?? "").trim();
	if (targetUrl) {
		body = body
			.replace(/https?:\/\/(?:TARGET|HOST|DOMAIN)(?::\d+)?(?![A-Za-z0-9_])/g, targetUrl)
			.replace(/\$\{U\}|\$U(?![A-Za-z0-9_])/g, targetUrl)
			.replace(/\[(?:TARGET_URL|URL)\]/g, targetUrl);
	}
	if (resolvedHost) {
		body = body
			.replace(/\[(?:TARGET|HOST|DOMAIN)\]/g, resolvedHost)
			.replace(/\$\{(?:TARGET|HOST|DOMAIN)\}|\$(?:TARGET|HOST|DOMAIN)(?![A-Za-z0-9_])/g, resolvedHost);
	}
	return body;
}

/**
 * 保留引号字符串字面量的同时剥离 JS 单行 `//` 与块级 `/* ... *\/` 注释（非换行字符替换为空格以保持偏移与行号不变）。
 */
export function stripJsCommentsPreservingStrings(code: string): string {
	let out = "";
	let i = 0;
	const len = code.length;
	let quote: string | null = null;
	let escaped = false;

	while (i < len) {
		const ch = code[i]!;
		const next = i + 1 < len ? code[i + 1]! : "";
		if (quote) {
			out += ch;
			if (escaped) {
				escaped = false;
			} else if (ch === "\\") {
				escaped = true;
			} else if (ch === quote) {
				quote = null;
			}
			i++;
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			quote = ch;
			out += ch;
			i++;
			continue;
		}
		if (ch === "/" && next === "/") {
			out += "  ";
			i += 2;
			while (i < len && code[i] !== "\n") {
				out += " ";
				i++;
			}
			continue;
		}
		if (ch === "/" && next === "*") {
			out += "  ";
			i += 2;
			while (i < len) {
				if (code[i] === "*" && i + 1 < len && code[i + 1] === "/") {
					out += "  ";
					i += 2;
					break;
				}
				out += code[i] === "\n" ? "\n" : " ";
				i++;
			}
			continue;
		}
		out += ch;
		i++;
	}
	return out;
}

/**
 * 针对 `eval` JS 源码的词法安全占位符展开器：
 * 严格跳过引号外的 JS 标识符、对象键与注释（确保 `const TARGET = ...`、`{ HOST: ... }` 等合法代码零语法破坏），
 * 仅对字符串/模板字面量内部的显式占位符执行无头替换。
 */
export function expandEvalCodePlaceholders(
	code: string,
	targetInfo: { url: string; host: string },
): string {
	if (!code || !DISPATCH_PLACEHOLDER_CASE_RE.test(code)) return code;
	let out = "";
	let i = 0;
	const len = code.length;

	while (i < len) {
		const ch = code[i]!;
		const next = i + 1 < len ? code[i + 1]! : "";

		if (ch === "/" && next === "/") {
			const start = i;
			i += 2;
			while (i < len && code[i] !== "\n") i++;
			out += code.slice(start, i);
			continue;
		}
		if (ch === "/" && next === "*") {
			const start = i;
			i += 2;
			while (i < len && !(code[i] === "*" && i + 1 < len && code[i + 1] === "/")) i++;
			if (i < len) i += 2;
			out += code.slice(start, i);
			continue;
		}
		if (ch === '"' || ch === "'") {
			const quoteChar = ch;
			let inner = "";
			i++;
			let escaped = false;
			let closed = false;
			while (i < len) {
				const c = code[i]!;
				if (escaped) {
					inner += c;
					escaped = false;
					i++;
					continue;
				}
				if (c === "\\") {
					inner += c;
					escaped = true;
					i++;
					continue;
				}
				if (c === quoteChar) {
					closed = true;
					i++;
					break;
				}
				inner += c;
				i++;
			}
			if (!closed) {
				out += quoteChar + inner;
			} else {
				const expanded = DISPATCH_PLACEHOLDER_CASE_RE.test(inner)
					? expandPlaceholdersPlain(inner, targetInfo)
					: inner;
				out += quoteChar + expanded + quoteChar;
			}
			continue;
		}
		if (ch === "`") {
			out += "`";
			i++;
			let seg = "";
			let escaped = false;
			while (i < len) {
				const c = code[i]!;
				if (escaped) {
					seg += c;
					escaped = false;
					i++;
					continue;
				}
				if (c === "\\") {
					seg += c;
					escaped = true;
					i++;
					continue;
				}
				if (c === "`") {
					out += DISPATCH_PLACEHOLDER_CASE_RE.test(seg) ? expandPlaceholdersPlain(seg, targetInfo) : seg;
					out += "`";
					i++;
					seg = "";
					break;
				}
				if (c === "$" && i + 1 < len && code[i + 1] === "{") {
					out += DISPATCH_PLACEHOLDER_CASE_RE.test(seg) ? expandPlaceholdersPlain(seg, targetInfo) : seg;
					seg = "";
					i += 2;
					let braceDepth = 1;
					let expr = "";
					let exprQuote: string | null = null;
					let exprEsc = false;
					while (i < len && braceDepth > 0) {
						const ec = code[i]!;
						if (exprQuote) {
							expr += ec;
							if (exprEsc) exprEsc = false;
							else if (ec === "\\") exprEsc = true;
							else if (ec === exprQuote) exprQuote = null;
							i++;
							continue;
						}
						if (ec === '"' || ec === "'" || ec === "`") {
							exprQuote = ec;
							expr += ec;
							i++;
							continue;
						}
						if (ec === "{") {
							braceDepth++;
							expr += ec;
							i++;
							continue;
						}
						if (ec === "}") {
							braceDepth--;
							if (braceDepth === 0) {
								i++;
								break;
							}
							expr += ec;
							i++;
							continue;
						}
						expr += ec;
						i++;
					}
					const trimmedExpr = expr.trim();
					if (/^(?:U|TARGET|HOST|DOMAIN)$/.test(trimmedExpr)) {
						const tokenExpanded = expandPlaceholdersPlain(`\${${trimmedExpr}}`, targetInfo);
						out += tokenExpanded;
					} else {
						out += `\${${expandEvalCodePlaceholders(expr, targetInfo)}}`;
					}
					continue;
				}
				seg += c;
				i++;
			}
			if (seg) {
				out += DISPATCH_PLACEHOLDER_CASE_RE.test(seg) ? expandPlaceholdersPlain(seg, targetInfo) : seg;
			}
			continue;
		}

		out += ch;
		i++;
	}
	return out;
}

/**
 * 展开派单 `context` 字段（支持纯字符串或嵌套对象/数组，保持原结构且不破坏纯 URL）。
 */
export function expandDispatchContextValue(
	ctxVal: unknown,
	targetInfo: { url: string; host: string; egress?: string },
): { value: Record<string, unknown> | string | undefined; changed: boolean } {
	const expandAny = (val: unknown): { val: unknown; changed: boolean } => {
		if (typeof val === "string") {
			if (!DISPATCH_PLACEHOLDER_CASE_RE.test(val)) return { val, changed: false };
			const expanded = expandPlaceholdersPlain(val, targetInfo);
			return { val: expanded, changed: expanded !== val };
		}
		if (Array.isArray(val)) {
			let anyChanged = false;
			const nextArr = val.map((item) => {
				const r = expandAny(item);
				if (r.changed) anyChanged = true;
				return r.val;
			});
			return { val: anyChanged ? nextArr : val, changed: anyChanged };
		}
		if (val && typeof val === "object") {
			const rec = val as Record<string, unknown>;
			let anyChanged = false;
			const out: Record<string, unknown> = { ...rec };
			for (const [k, v] of Object.entries(rec)) {
				const r = expandAny(v);
				if (r.changed) {
					out[k] = r.val;
					anyChanged = true;
				}
			}
			return { val: anyChanged ? out : rec, changed: anyChanged };
		}
		return { val, changed: false };
	};

	const res = expandAny(ctxVal);
	return {
		value: res.val as Record<string, unknown> | string | undefined,
		changed: res.changed,
	};
}

function extractEvalStringProp(objText: string, prop: string): { found: boolean; value: string } {
	const re = new RegExp(`\\b${prop}\\s*:\\s*(?:"((?:[^"\\\\]|\\\\.)*)"|'((?:[^'\\\\]|\\\\.)*)'|\`((?:[^\`\\\\]|\\\\.)*)\`)`, "s");
	const m = re.exec(objText);
	if (!m) return { found: false, value: "" };
	const raw = m[1] ?? m[2] ?? m[3] ?? "";
	return {
		found: true,
		value: raw.replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\(["'`\\])/g, "$1"),
	};
}

/**
 * 解析 `eval` 代码块内的全部 `agent({ agent, label, prompt })` 调用（先剥离单行 `//` 与块级 `/* *\/` 注释以防注释内 `}` 截断绕过）。
 */
export function parseEvalAgentCalls(code: string): ParsedEvalAgentCall[] {
	const cleanCode = stripJsCommentsPreservingStrings(code);
	const results: ParsedEvalAgentCall[] = [];
	const callRe = /\bagent\s*\(\s*\{/g;
	let match: RegExpExecArray | null;
	while ((match = callRe.exec(cleanCode)) !== null) {
		let idx = match.index + match[0].length;
		let depth = 1;
		let quote: string | null = null;
		let escaped = false;
		while (idx < cleanCode.length && depth > 0) {
			const ch = cleanCode[idx]!;
			if (escaped) {
				escaped = false;
				idx++;
				continue;
			}
			if (quote) {
				if (ch === "\\") escaped = true;
				else if (ch === quote) quote = null;
				idx++;
				continue;
			}
			if (ch === '"' || ch === "'" || ch === "`") {
				quote = ch;
			} else if (ch === "{") {
				depth++;
			} else if (ch === "}") {
				depth--;
				if (depth === 0) break;
			}
			idx++;
		}
		if (depth !== 0) continue;
		const body = cleanCode.slice(match.index + match[0].length, idx);
		const ag = extractEvalStringProp(body, "agent");
		const pr = extractEvalStringProp(body, "prompt");
		const tk = pr.found ? pr : extractEvalStringProp(body, "task");
		const lb = extractEvalStringProp(body, "label");
		const nm = lb.found ? lb : extractEvalStringProp(body, "name");
		const agentExplicit = ag.found && ag.value.trim().length > 0;
		results.push({
			agent: agentExplicit ? ag.value.trim() : "fujiang",
			agentExplicit,
			...(tk.found ? { prompt: tk.value } : {}),
			...(nm.found && nm.value.trim() ? { label: nm.value.trim() } : {}),
			hasEmptyPrompt: tk.found && tk.value.trim().length === 0,
		});
	}
	return results;
}

/**
 * 判断缓冲候选键是否匹配宿主实际派发的 `spawnKey`（兼容数字后缀与 `parent.label` 层级前缀）。
 */
export function matchesSpawnCandidate(cand: string, actualKey: string): boolean {
	if (!cand || !actualKey) return false;
	if (cand === actualKey) return true;
	if (actualKey.startsWith(`${cand}-`) && /^\d+$/.test(actualKey.slice(cand.length + 1))) return true;
	const dotIdx = actualKey.lastIndexOf(".");
	if (dotIdx > 0 && dotIdx < actualKey.length - 1) {
		const tail = actualKey.slice(dotIdx + 1);
		if (tail === cand) return true;
		if (tail.startsWith(`${cand}-`) && /^\d+$/.test(tail.slice(cand.length + 1))) return true;
	}
	return false;
}

function extractEventDetails(evObj: Record<string, unknown>): Record<string, unknown> | undefined {
	if (evObj.details && typeof evObj.details === "object") {
		return evObj.details as Record<string, unknown>;
	}
	const resObj = evObj.result && typeof evObj.result === "object" ? (evObj.result as Record<string, unknown>) : undefined;
	if (resObj?.details && typeof resObj.details === "object") {
		return resObj.details as Record<string, unknown>;
	}
	return undefined;
}

function resolveWatchdogTaskId(wd: SubagentWatchdog, ctx: DispatchBridgeContext): string {
	const direct = ctx.agent?.id?.trim();
	if (direct && wd.getTask(direct)) return direct;
	if (ctx.agent?.kind === "sub") {
		const running = wd.listTasks({ status: "running" });
		const agentName = typeof ctx.agent?.name === "string" ? ctx.agent.name.trim() : "";
		if (agentName) {
			const sameAgent = running.filter((t) => t.agent === agentName);
			if (sameAgent.length === 1) return sameAgent[0]!.taskId;
		}
		if (running.length === 1) return running[0]!.taskId;
	}
	return direct || getBridgeSessionId(ctx);
}

/**
 * 独立可实例化的派单桥接状态仓库（零模块级私有全局状态，多会话/多测试完全隔离）。
 */
export class DispatchBridgeStore {
	readonly pendingToolDispatches: PendingToolDispatch[] = [];
	readonly activeSpawns = new Map<string, ActiveSubagentSpawn>();
	readonly liveCalls = new Map<string, number>();
	readonly seenEvidenceToolCallIds = new Set<string>();
	private spawnSeq = 0;
	private dispatchSeq = 0;

	nextSpawnSeq(): number {
		this.spawnSeq += 1;
		return this.spawnSeq;
	}

	nextDispatchSeq(): number {
		this.dispatchSeq += 1;
		return this.dispatchSeq;
	}

	incrementLiveCalls(sessionId: string): number {
		const next = (this.liveCalls.get(sessionId) ?? 0) + 1;
		this.liveCalls.set(sessionId, next);
		return next;
	}

	getLiveCallCount(sessionId: string): number {
		return this.liveCalls.get(sessionId) ?? 0;
	}

	getPendingCount(root?: string): number {
		if (!root) return this.pendingToolDispatches.length;
		const normRoot = resolve(root);
		return this.pendingToolDispatches.filter((e) => resolve(e.root) === normRoot).length;
	}

	listPending(root?: string): PendingToolDispatch[] {
		if (!root) return [...this.pendingToolDispatches];
		const normRoot = resolve(root);
		return this.pendingToolDispatches.filter((e) => resolve(e.root) === normRoot);
	}

	prune(nowMs = Date.now()): void {
		for (let i = this.pendingToolDispatches.length - 1; i >= 0; i--) {
			const e = this.pendingToolDispatches[i]!;
			const ttl = e.evalWindow ? EVAL_DISPATCH_WINDOW_TTL_MS : PENDING_DISPATCH_TTL_MS;
			if (nowMs - e.createdAt > ttl) {
				this.pendingToolDispatches.splice(i, 1);
			}
		}
		if (this.pendingToolDispatches.length > 200) {
			this.pendingToolDispatches.splice(0, this.pendingToolDispatches.length - 200);
		}
		if (this.seenEvidenceToolCallIds.size > 500) {
			this.seenEvidenceToolCallIds.clear();
		}
	}

	clearByToolCall(root: string, toolCallId?: string): void {
		if (!toolCallId) return;
		const normRoot = resolve(root);
		for (let i = this.pendingToolDispatches.length - 1; i >= 0; i--) {
			const entry = this.pendingToolDispatches[i]!;
			if (resolve(entry.root) === normRoot && entry.toolCallId === toolCallId) {
				this.pendingToolDispatches.splice(i, 1);
			}
		}
	}

	clearByRoot(root: string, sessionId?: string): void {
		const normRoot = resolve(root);
		for (let i = this.pendingToolDispatches.length - 1; i >= 0; i--) {
			const entry = this.pendingToolDispatches[i]!;
			if (resolve(entry.root) === normRoot && (!sessionId || entry.sessionId === sessionId)) {
				this.pendingToolDispatches.splice(i, 1);
			}
		}
	}

	/**
	 * 在 `tool_execution_end` / `tool_result` 返回时对账异步进度句柄：
	 * - 若 `details.async.state === "running"` 或 `progress[]` 存在未完成条目，将宿主预分配随机 ID（如 `brave-owl-71`）
	 *   动态头插绑定回对应 `index` 的 `PendingToolDispatch`，并保留等待后续乱序 `before_subagent_spawn`；
	 * - 若同步结束且无未决异步项，立即清理该 `toolCallId` 的残留缓冲。
	 */
	reconcileOnToolResult(root: string, toolCallId: string, evObj: Record<string, unknown>): void {
		const normRoot = resolve(root);
		const details = extractEventDetails(evObj);
		const asyncObj =
			details?.async && typeof details.async === "object" ? (details.async as Record<string, unknown>) : undefined;
		const asyncRunning = asyncObj?.state === "running";
		const progressArr = Array.isArray(details?.progress) ? (details.progress as Array<Record<string, unknown>>) : [];
		const resultsArr = Array.isArray(details?.results) ? (details.results as Array<Record<string, unknown>>) : [];

		let hasUnsettledProgress = false;
		const settledIds = new Set<string>();
		const settledIndices = new Set<number>();

		for (const res of resultsArr) {
			if (!res || typeof res !== "object") continue;
			if (typeof res.id === "string" && res.id.trim()) settledIds.add(res.id.trim());
			if (typeof res.spawnId === "string" && res.spawnId.trim()) settledIds.add(res.spawnId.trim());
			if (typeof res.taskId === "string" && res.taskId.trim()) settledIds.add(res.taskId.trim());
			if (typeof res.index === "number") settledIndices.add(res.index);
		}

		const boundEntrySeqs = new Set<number>();
		for (let pPos = 0; pPos < progressArr.length; pPos++) {
			const prog = progressArr[pPos];
			if (!prog || typeof prog !== "object") continue;
			const progId =
				typeof prog.id === "string" && prog.id.trim()
					? prog.id.trim()
					: typeof prog.spawnId === "string" && prog.spawnId.trim()
						? prog.spawnId.trim()
						: typeof prog.taskId === "string" && prog.taskId.trim()
							? prog.taskId.trim()
							: "";
			const progIdx = typeof prog.index === "number" ? prog.index : -1;
			const progState = typeof prog.status === "string" ? prog.status.trim().toLowerCase() : "";
			const isTerminal = progState ? TERMINAL_PROGRESS_STATES.has(progState) : false;

			if (isTerminal) {
				if (progId) settledIds.add(progId);
				if (progIdx >= 0) settledIndices.add(progIdx);
				continue;
			}

			if (progId && toolCallId) {
				let targetEntry: PendingToolDispatch | undefined;
				if (progIdx >= 0) {
					targetEntry = this.pendingToolDispatches.find(
						(e) => resolve(e.root) === normRoot && e.toolCallId === toolCallId && e.index === progIdx,
					);
				} else {
					targetEntry =
						this.pendingToolDispatches.find(
							(e) =>
								resolve(e.root) === normRoot &&
								e.toolCallId === toolCallId &&
								e.spawnKeyCandidates.includes(progId),
						) ??
						this.pendingToolDispatches.find(
							(e) =>
								resolve(e.root) === normRoot &&
								e.toolCallId === toolCallId &&
								!boundEntrySeqs.has(e.seq) &&
								e.index === pPos,
						) ??
						this.pendingToolDispatches.find(
							(e) =>
								resolve(e.root) === normRoot &&
								e.toolCallId === toolCallId &&
								!boundEntrySeqs.has(e.seq),
						);
				}
				if (targetEntry) {
					boundEntrySeqs.add(targetEntry.seq);
					if (!targetEntry.spawnKeyCandidates.includes(progId)) {
						targetEntry.spawnKeyCandidates.unshift(progId);
					}
					targetEntry.asyncPending = true;
				}
			}
			if (asyncRunning || progState === "pending" || progState === "running") {
				hasUnsettledProgress = true;
			}
		}

		if (!toolCallId) return;

		if (asyncRunning || hasUnsettledProgress) {
			for (let i = this.pendingToolDispatches.length - 1; i >= 0; i--) {
				const e = this.pendingToolDispatches[i]!;
				if (resolve(e.root) !== normRoot || e.toolCallId !== toolCallId) continue;
				const idxSettled = settledIndices.has(e.index);
				const idSettled = e.spawnKeyCandidates.some((c) => settledIds.has(c));
				if (idxSettled || idSettled) {
					this.pendingToolDispatches.splice(i, 1);
				} else {
					e.asyncPending = true;
				}
			}
			return;
		}

		this.clearByToolCall(normRoot, toolCallId);
	}

	/**
	 * 消费一条匹配的待派生缓冲记录（优先按 `spawnKey` 精确配对，防止跨异步批误抢消费）。
	 */
	consumePending(
		root: string,
		sessionId: string,
		agentName: string,
		spawnKey?: string,
		invocationKind?: string,
	): PendingToolDispatch | undefined {
		this.prune();
		const normRoot = resolve(root);
		const normAgent = agentName.trim().toLowerCase();
		const normSpawnKey = typeof spawnKey === "string" ? spawnKey.trim() : "";
		const normKind = invocationKind === "task" || invocationKind === "eval" ? invocationKind : undefined;

		let matchedIdx = -1;
		if (normSpawnKey) {
			matchedIdx = this.pendingToolDispatches.findIndex((e) => {
				if (resolve(e.root) !== normRoot) return false;
				return e.spawnKeyCandidates.some((cand) => matchesSpawnCandidate(cand, normSpawnKey));
			});
		}

		const pickBest = (
			requireSameAgent: boolean,
			requireSameSession: boolean,
			kindFilter?: "task" | "eval",
			skipExplicitKeyedAsync = true,
		): number => {
			return this.pendingToolDispatches.findIndex((e) => {
				if (resolve(e.root) !== normRoot) return false;
				if (requireSameSession && e.sessionId !== sessionId) return false;
				if (kindFilter && e.invocationKind !== kindFilter) return false;
				if (requireSameAgent && normAgent && e.agent.trim().toLowerCase() !== normAgent) return false;
				if (
					skipExplicitKeyedAsync &&
					e.asyncPending &&
					normSpawnKey &&
					e.spawnKeyCandidates.length > 0 &&
					!e.spawnKeyCandidates.some((cand) => matchesSpawnCandidate(cand, normSpawnKey))
				) {
					return false;
				}
				return true;
			});
		};

		if (matchedIdx < 0) matchedIdx = pickBest(true, true, normKind);
		if (matchedIdx < 0) matchedIdx = pickBest(true, false, normKind);
		if (matchedIdx < 0 && normKind === "eval") matchedIdx = pickBest(false, true, "eval");
		if (matchedIdx < 0 && normKind === "eval") matchedIdx = pickBest(false, false, "eval");
		if (matchedIdx < 0 && !normKind) matchedIdx = pickBest(true, true, undefined);
		if (matchedIdx < 0 && !normKind) matchedIdx = pickBest(false, true, undefined);
		if (matchedIdx < 0 && normKind === "task") {
			matchedIdx = this.pendingToolDispatches.findIndex(
				(e) =>
					resolve(e.root) === normRoot &&
					e.evalWindow &&
					(!normAgent || e.agent.trim().toLowerCase() === normAgent),
			);
		}

		if (matchedIdx < 0) return undefined;
		const hit = this.pendingToolDispatches[matchedIdx]!;
		if (!hit.reusable) {
			this.pendingToolDispatches.splice(matchedIdx, 1);
		}
		return hit;
	}

	/**
	 * 会话关闭时级联取消运行态子代理看门狗并清理缓冲记录。
	 */
	shutdownSession(root: string | null, sessionId: string): void {
		if (!root) return;
		try {
			const wd = new SubagentWatchdog(root);
			for (const t of wd.listTasks({ status: "running" })) {
				wd.completeTask(t.taskId, "cancelled");
				this.activeSpawns.delete(t.taskId);
			}
		} catch {
			/* ignore watchdog cleanup error */
		}
		this.clearByRoot(root, sessionId);
	}
}

function completeWatchdogOnTaskEnd(
	store: DispatchBridgeStore,
	root: string,
	evObj: Record<string, unknown>,
	inputObj: Record<string, unknown> | null,
	ctx: DispatchBridgeContext,
): void {
	if (ctx.agent?.kind === "sub") return;
	const wd = new SubagentWatchdog(root);
	const running = wd.listTasks({ status: "running" });
	const normRoot = resolve(root);
	const runningIdSet = new Set(running.map((r) => r.taskId));
	for (const [sidKey, sp] of store.activeSpawns.entries()) {
		if (resolve(sp.root) === normRoot && !runningIdSet.has(sidKey)) {
			store.activeSpawns.delete(sidKey);
		}
	}
	if (running.length === 0) return;
	const safeInput = inputObj && typeof inputObj === "object" ? inputObj : {};

	const details = extractEventDetails(evObj);
	const asyncObj =
		details?.async && typeof details.async === "object" ? (details.async as Record<string, unknown>) : undefined;
	const asyncRunning = asyncObj?.state === "running";

	const explicitIds = new Set<string>();
	const pushStrId = (v: unknown) => {
		if (typeof v === "string" && v.trim()) explicitIds.add(v.trim());
	};
	const pushArrIds = (arr: unknown, onlyTerminalStatus = false) => {
		if (!Array.isArray(arr)) return;
		for (const item of arr) {
			if (typeof item === "string") {
				if (!onlyTerminalStatus) pushStrId(item);
			} else if (item && typeof item === "object") {
				const rec = item as Record<string, unknown>;
				if (onlyTerminalStatus) {
					const st = typeof rec.status === "string" ? rec.status.trim().toLowerCase() : "";
					if (!TERMINAL_PROGRESS_STATES.has(st)) continue;
				}
				pushStrId(rec.spawnId);
				pushStrId(rec.taskId);
				pushStrId(rec.id);
			}
		}
	};

	pushStrId(evObj.spawnId);
	pushStrId(evObj.taskId);
	pushStrId(evObj.spawnKey);
	pushStrId(details?.spawnId);
	pushStrId(details?.taskId);
	pushArrIds(details?.spawnIds);
	pushArrIds(details?.taskIds);
	pushArrIds(details?.results);
	// progress 中处于 pending/running 的异步任务尚未结束，仅吸收已到达终态的条目
	pushArrIds(details?.progress, true);
	pushStrId(safeInput.spawnId);
	pushStrId(safeInput.taskId);
	pushArrIds(safeInput.tasks);

	// 异步模式仅返回运行态句柄（results 为空、无终态 ID）：绝不误注销其它正在运行的看门狗任务
	if (asyncRunning && explicitIds.size === 0) return;

	const matchedIds = new Set<string>();
	for (const r of running) {
		if (explicitIds.has(r.taskId)) matchedIds.add(r.taskId);
	}

	if (asyncRunning && matchedIds.size === 0) return;

	const tcId = typeof evObj.toolCallId === "string" ? evObj.toolCallId.trim() : "";

	// 同步无显式 spawnId 场景：通过 toolCallId、intentId 或完整派单文本严格一对一配对
	if (matchedIds.size === 0) {
		if (tcId) {
			for (const [sidKey, sp] of store.activeSpawns.entries()) {
				if (resolve(sp.root) === normRoot && sp.toolCallId === tcId) {
					matchedIds.add(sidKey);
				}
			}
			const hasUnspawnedPendingForTc = store.pendingToolDispatches.some(
				(e) => resolve(e.root) === normRoot && e.toolCallId === tcId,
			);
			if (matchedIds.size === 0 && hasUnspawnedPendingForTc) {
				return;
			}
		}

		const taskTexts: string[] = [];
		const addTaskText = (v: unknown) => {
			if (typeof v === "string" && v.trim()) taskTexts.push(v.trim());
		};
		const isBatchCall = Array.isArray(safeInput.tasks) && safeInput.tasks.length > 0;
		addTaskText(safeInput.task);
		addTaskText(safeInput.prompt);
		if (Array.isArray(safeInput.tasks)) {
			for (const item of safeInput.tasks) {
				if (item && typeof item === "object") {
					addTaskText((item as Record<string, unknown>).task);
					addTaskText((item as Record<string, unknown>).prompt);
				}
			}
		}

		const intentIds = new Set<string>();
		if (typeof safeInput.intentId === "string" && safeInput.intentId.trim()) intentIds.add(safeInput.intentId.trim());
		if (typeof details?.intentId === "string" && details.intentId.trim()) intentIds.add(details.intentId.trim());
		for (const txt of taskTexts) {
			for (const m of txt.matchAll(/\[女娲派单\s+(i\d{3,})\]/g)) {
				if (m[1]) intentIds.add(m[1]);
			}
		}

		if (matchedIds.size === 0 && intentIds.size > 0) {
			for (const [sidKey, sp] of store.activeSpawns.entries()) {
				if (resolve(sp.root) !== normRoot) continue;
				if (sp.intentId && intentIds.has(sp.intentId)) {
					matchedIds.add(sidKey);
				}
			}
			if (matchedIds.size === 0) {
				for (const r of running) {
					if (r.intentId && intentIds.has(r.intentId)) matchedIds.add(r.taskId);
				}
			}
		}

		if (matchedIds.size === 0 && taskTexts.length > 0) {
			for (const txt of taskTexts) {
				for (const [sidKey, sp] of store.activeSpawns.entries()) {
					if (resolve(sp.root) !== normRoot || matchedIds.has(sidKey)) continue;
					if (txt === sp.rawTask || txt === sp.injectedTask) {
						matchedIds.add(sidKey);
						break;
					}
				}
				if (!isBatchCall && matchedIds.size > 0) break;
			}
		}

		// 防误杀守卫：若当前事件报错（未派生即失败）或已携带明确标识（tcId / explicitIds / intentIds / taskTexts）却未命中，严禁按 agent 名盲杀后台无关在途看门狗
		const hasSpecificIdentity =
			Boolean(tcId) || explicitIds.size > 0 || intentIds.size > 0 || taskTexts.length > 0;
		if (matchedIds.size === 0 && !hasSpecificIdentity && evObj.isError !== true) {
			const agentArg =
				typeof safeInput.agent === "string"
					? safeInput.agent.trim()
					: typeof safeInput.agentName === "string"
						? safeInput.agentName.trim()
						: "";
			if (agentArg) {
				const byAgent = running.filter((r) => r.agent === agentArg);
				if (byAgent.length === 1) matchedIds.add(byAgent[0]!.taskId);
			} else if (running.length === 1) {
				matchedIds.add(running[0]!.taskId);
			}
		}
	}

	const status = evObj.isError === true ? "failed" : "completed";
	for (const tid of matchedIds) {
		wd.completeTask(tid, status);
		store.activeSpawns.delete(tid);
	}
}

/**
 * 处理 `tool_call` 事件：包含子代理派单前置缓冲、`task` / `eval` 占位符展开、4 MiB `taskFile` 读取、
 * Scope 范围护栏、主从权限守卫与零信任容器沙盒校验。
 */
export function handleToolCallDispatch(
	store: DispatchBridgeStore,
	event: DispatchToolCallEvent,
	ctx: DispatchBridgeContext,
	opts?: DispatchBridgeOptions,
): DispatchToolCallResult {
	try {
		const root = resolveBridgeRoot(ctx, opts);
		if (!root) return undefined;
		const st = loadState(root);
		if (!st) return undefined;

		const active = st.project.status === "active" && !isTerminalStateInternal(st);
		const main = isMainBridgeAgent(ctx);
		const name = event.toolName;
		const input = (event.input ?? {}) as Record<string, unknown>;
		const projScope = st.project.scope ?? defaultScopeForTarget(st.project.url || st.project.target, st.project.mode);
		const agentHome = opts?.getAgentHome ? opts.getAgentHome() : getAgentHome();

		if (active && !main) {
			const wd = new SubagentWatchdog(root);
			wd.recordRequest(resolveWatchdogTaskId(wd, ctx));
		}

		if (active && !main && /^nuwa_(init|plan|claim|commit|flag|complete|expand|stop)$/.test(name)) {
			return { block: true, reason: `nuwa N-005: ${name} 只能由主线程调用；子代理把结果回给主线程` };
		}

		if (name === "bash") {
			const cmd = typeof input.command === "string" ? input.command : "";
			const sbCfg = active && !main ? readSandboxConfig() : null;
			let cmdForPolicy = cmd;

			if (sbCfg && (sbCfg.mode === "docker" || sbCfg.mode === "sidecar") && cmd.trim()) {
				const isCompliant =
					sbCfg.mode === "docker"
						? isCompliantSandboxDockerCommand(cmd, st.project.id).ok
						: isCompliantSidecarCommand(cmd, st.project.id).ok || isCompliantSandboxDockerCommand(cmd, st.project.id).ok;
				if (isCompliant) {
					const inner = extractSandboxInnerCommand(cmd, sbCfg.egressProxyUrl);
					if (inner !== null) {
						cmdForPolicy = inner;
					}
				}
			}

			const v = checkBashPolicy(cmdForPolicy, active, main, projScope, st.project.mode);
			if (v) return v;

			if (sbCfg && cmd.trim()) {
				if (sbCfg.mode === "docker") {
					const sbVerdict = isCompliantSandboxDockerCommand(cmd, st.project.id);
					if (!sbVerdict.ok) {
						let hintCmd = "";
						try {
							hintCmd = wrapCommandInDockerSandbox(cmd, {
								projectId: st.project.id,
								scope: projScope,
								config: sbCfg,
								ensureWorkdir: false,
							});
						} catch {
							hintCmd = "docker run --rm --read-only --cap-drop=ALL ...";
						}
						return {
							block: true,
							reason: `nuwa N-009: 已启用零信任 Docker 沙盒 (${sbVerdict.reason})；请改用合规沙盒包裹命令:\n${hintCmd}`,
						};
					}
				} else if (sbCfg.mode === "sidecar") {
					const scVerdict = isCompliantSidecarCommand(cmd, st.project.id);
					const dkVerdict = scVerdict.ok ? { ok: true } : isCompliantSandboxDockerCommand(cmd, st.project.id);
					if (!scVerdict.ok && !dkVerdict.ok) {
						let hintCmd = "";
						try {
							hintCmd = wrapCommandInSidecarSandbox(cmd, {
								projectId: st.project.id,
								scope: projScope,
								config: sbCfg,
								proxyUrl: sbCfg.egressProxyUrl,
								ensureWorkdir: false,
							});
						} catch {
							hintCmd = `docker exec -w /tmp/nuwa/${st.project.id} nuwa-sb-${st.project.id} sh -c '...'`;
						}
						return {
							block: true,
							reason: `nuwa N-009: 已启用常驻零信任 Sidecar 沙盒 (${scVerdict.reason})；请改用合规 Sidecar 包裹命令:\n${hintCmd}`,
						};
					}
				}
			}
			return undefined;
		}

		if (name === "task") {
			const v = checkTaskPolicy(input, active, main);
			if (v) return v;
			if (active && main) {
				const sid = getBridgeSessionId(ctx);
				bindSubagentSpawn(sid, ctx.agent?.id, root, agentHome);
				const toolCallId =
					typeof event.toolCallId === "string" && event.toolCallId.trim() ? event.toolCallId.trim() : undefined;
				const isBatchInput = Array.isArray(input.tasks);
				const rawTasks = isBatchInput ? (input.tasks as Array<Record<string, unknown>>) : [input];
				if (isBatchInput && rawTasks.length === 0) {
					return { block: true, reason: "nuwa N-007: 批派单 tasks 数组不能为空" };
				}

				const configuredEgress = normalizeTaskEgressUrl(resolveConfiguredEgressUrl());
				const targetInfo = {
					url: st.project.url,
					host: st.project.host,
					...(configuredEgress ? { egress: maskEgressUrl(configuredEgress) } : {}),
				};
				const sharedCtxRaw =
					typeof input.context === "string" || (input.context && typeof input.context === "object")
						? (input.context as Record<string, unknown> | string)
						: undefined;
				const expandedSharedCtx =
					sharedCtxRaw !== undefined
						? expandDispatchContextValue(sharedCtxRaw, targetInfo)
						: { value: undefined, changed: false };
				let needsRewrite = expandedSharedCtx.changed;
				const rewrittenItems = rawTasks.map((it) => (it && typeof it === "object" ? { ...it } : it));
				const stagedDispatches: PendingToolDispatch[] = [];
				const normRoot = resolve(root);
				const nowMs = Date.now();

				for (let idx = 0; idx < rawTasks.length; idx++) {
					const item = rawTasks[idx];
					const rawTaskStr =
						typeof item?.task === "string"
							? item.task
							: typeof item?.prompt === "string"
								? item.prompt
								: typeof item?.assignment === "string"
									? item.assignment
									: "";
					let tStr = rawTaskStr.trim();
					const taskFile = typeof item?.taskFile === "string" ? item.taskFile.trim() : "";
					const taskFileBaseDir = ctx.cwd && ctx.cwd.trim() ? resolve(ctx.cwd) : normRoot;
					const resolvedTaskFile =
						taskFile && !taskFile.startsWith("local://") ? resolve(taskFileBaseDir, taskFile) : taskFile;
					let fromTaskFile = false;
					let taskFileFullText = "";

					if (!tStr && !taskFile) {
						const dv = validateSubagentDispatch({ task: "", targetUrl: st.project.url });
						return { block: true, reason: `nuwa N-007: ${dv.reason ?? "派单 task 为空"}` };
					}
					if (!tStr && taskFile) {
						if (!taskFile.startsWith("local://") && existsSync(resolvedTaskFile)) {
							const tf = readTaskFileForDispatch(resolvedTaskFile);
							if (tf.tooLarge) {
								return { block: true, reason: `nuwa N-007: taskFile 超过 4 MiB 上限 (${taskFile})` };
							}
							if (tf.empty) {
								const dv = validateSubagentDispatch({ task: "", targetUrl: st.project.url });
								return { block: true, reason: `nuwa N-007: ${dv.reason ?? "派单 taskFile 为空"}` };
							}
							if (tf.text) {
								tStr = tf.text;
								taskFileFullText = tf.fullText ?? tf.text;
								fromTaskFile = true;
							}
						}
						if (!tStr) {
							tStr = `[taskFile] ${taskFile} target=${st.project.url || st.project.host || "local"}`;
						}
					}

					if (DISPATCH_EMPTY_CONTEXT_RE.test(tStr)) {
						const dv = validateSubagentDispatch({
							task: tStr,
							targetUrl: st.project.url,
							resolvedHost: st.project.host,
						});
						if (!dv.ok) return { block: true, reason: `nuwa N-007: ${dv.reason}` };
					}

					let finalTaskForDispatch = tStr;
					const candidateSourceText = rawTaskStr || (fromTaskFile ? taskFileFullText : "");
					if (candidateSourceText && DISPATCH_PLACEHOLDER_CASE_RE.test(candidateSourceText)) {
						const pkt = buildDispatchPacket({
							task: candidateSourceText,
							target: targetInfo,
						});
						if (DISPATCH_PLACEHOLDER_CASE_RE.test(pkt.task)) {
							const dv = validateSubagentDispatch({
								task: pkt.task,
								targetUrl: st.project.url,
								resolvedHost: st.project.host,
							});
							if (!dv.ok) return { block: true, reason: `nuwa N-007: ${dv.reason}` };
						} else {
							finalTaskForDispatch =
								fromTaskFile && pkt.task.length > TASK_FILE_PREVIEW_BYTES
									? pkt.task.slice(0, TASK_FILE_PREVIEW_BYTES)
									: pkt.task;
							needsRewrite = true;
							const cloned = rewrittenItems[idx];
							if (cloned && typeof cloned === "object") {
								if (typeof cloned.task === "string") cloned.task = pkt.task;
								else if (typeof cloned.prompt === "string") cloned.prompt = pkt.task;
								else if (typeof cloned.assignment === "string") cloned.assignment = pkt.task;
								else if (fromTaskFile) {
									cloned.task = pkt.task;
									delete cloned.taskFile;
								}
							}
						}
					}

					const itemAgent = typeof item?.agent === "string" && item.agent.trim() ? item.agent.trim() : "fujiang";
					const itemName = typeof item?.name === "string" && item.name.trim() ? item.name.trim() : undefined;
					let itemCtx: Record<string, unknown> | string | undefined;
					if (item?.context !== undefined) {
						const expItemCtx = expandDispatchContextValue(item.context, targetInfo);
						itemCtx = expItemCtx.value;
						if (expItemCtx.changed) {
							needsRewrite = true;
							const cloned = rewrittenItems[idx];
							if (cloned && typeof cloned === "object") cloned.context = expItemCtx.value;
						}
					} else {
						itemCtx = expandedSharedCtx.value;
					}

					const spawnKeyCandidates: string[] = [];
					if (toolCallId) spawnKeyCandidates.push(`${toolCallId}:${idx}`);
					if (itemName) spawnKeyCandidates.push(itemName);
					stagedDispatches.push({
						seq: store.nextDispatchSeq(),
						root: normRoot,
						sessionId: sid,
						...(toolCallId ? { toolCallId } : {}),
						invocationKind: "task",
						agent: itemAgent,
						...(itemName ? { name: itemName } : {}),
						index: idx,
						taskText: finalTaskForDispatch,
						...(itemCtx !== undefined ? { context: itemCtx } : {}),
						spawnKeyCandidates,
						createdAt: nowMs,
					});
				}

				store.prune(nowMs);
				if (toolCallId) store.clearByToolCall(normRoot, toolCallId);
				store.pendingToolDispatches.push(...stagedDispatches);

				if (Array.isArray(input.tasks) && input.tasks.length > 1) {
					const chunked = chunkBatchTasks(rewrittenItems as BatchTaskItem[], { root });
					if (chunked.exceeded) {
						logEvent(root, {
							type: "batch_spilled",
							totalBytes: chunked.totalBytes,
							chunks: chunked.chunks.length,
							tasksFile: chunked.tasks_file,
						});
					}
				}

				if (needsRewrite) {
					const revisedInput = isBatchInput
						? {
								...input,
								...(expandedSharedCtx.changed ? { context: expandedSharedCtx.value } : {}),
								tasks: rewrittenItems,
							}
						: {
								...(rewrittenItems[0] as Record<string, unknown>),
								...(expandedSharedCtx.changed ? { context: expandedSharedCtx.value } : {}),
							};
					return { input: revisedInput };
				}
			}
			return undefined;
		}

		if (name === "eval") {
			const rawCode = typeof input.code === "string" ? input.code : "";
			const targetInfo = {
				url: st.project.url,
				host: st.project.host,
			};
			// 仅对 eval 字符串/模板字面量中的显式占位符做词法安全展开（保护引号外 JS 标识符与对象键），再进入子代理名白名单与 Scope 护栏检查
			const effectiveCode =
				active && (targetInfo.url || targetInfo.host) && DISPATCH_PLACEHOLDER_CASE_RE.test(rawCode)
					? expandEvalCodePlaceholders(rawCode, targetInfo)
					: rawCode;
			const needsEvalRewrite = effectiveCode !== rawCode;
			const strippedEvalCode = stripJsCommentsPreservingStrings(effectiveCode);
			const hasAgentCallInEval = /\bagent\s*\(/.test(strippedEvalCode);
			const parsedAgentCalls = hasAgentCallInEval ? parseEvalAgentCalls(strippedEvalCode) : [];

			if (active && main && readCfg().requireFujiang && hasAgentCallInEval) {
				const allowedAgents = new Set(["fujiang", "nuwa-verifier"]);
				const rawAgentCallCount = [...strippedEvalCode.matchAll(/\bagent\s*\(/g)].length;
				if (parsedAgentCalls.length > 0) {
					const hasDisallowedCall = parsedAgentCalls.some(
						(pc) => !pc.agentExplicit || !allowedAgents.has(pc.agent),
					);
					if (hasDisallowedCall) {
						return { block: true, reason: 'nuwa N-004: eval 里的 agent() 必须显式 agent: "fujiang" 或 "nuwa-verifier"' };
					}
					if (rawAgentCallCount > parsedAgentCalls.length && !/\b(?:fujiang|nuwa-verifier)\b/.test(strippedEvalCode)) {
						return { block: true, reason: 'nuwa N-004: eval 里的 agent() 必须显式 agent: "fujiang" 或 "nuwa-verifier"' };
					}
				} else if (!/\b(?:fujiang|nuwa-verifier)\b/.test(strippedEvalCode)) {
					return { block: true, reason: 'nuwa N-004: eval 里的 agent() 必须显式 agent: "fujiang" 或 "nuwa-verifier"' };
				}
			}
			if (active) {
				const evalScopeInput = needsEvalRewrite ? { ...input, code: effectiveCode } : input;
				const sv = checkToolScopeAndRisk("eval", evalScopeInput, projScope, st.project.mode);
				if (sv) return sv;
			}
			if (active && main && /\b(?:agent|tool\.task)\s*\(/.test(strippedEvalCode)) {
				const evalToolCallId =
					typeof event.toolCallId === "string" && event.toolCallId.trim() ? event.toolCallId.trim() : undefined;
				for (const pc of parsedAgentCalls) {
					if (pc.hasEmptyPrompt) {
						return { block: true, reason: "nuwa N-007: eval 内 agent() prompt 不能为空" };
					}
					if (pc.prompt && DISPATCH_EMPTY_CONTEXT_RE.test(pc.prompt)) {
						const dv = validateSubagentDispatch({
							task: pc.prompt,
							targetUrl: st.project.url,
							resolvedHost: st.project.host,
						});
						if (!dv.ok) return { block: true, reason: `nuwa N-007: ${dv.reason}` };
					}
				}

				const normRoot = resolve(root);
				const sid = getBridgeSessionId(ctx);
				const nowMs = Date.now();
				store.prune(nowMs);
				if (evalToolCallId) store.clearByToolCall(normRoot, evalToolCallId);

				if (parsedAgentCalls.length > 0) {
					parsedAgentCalls.forEach((pc, idx) => {
						let taskText = pc.prompt?.trim() ?? "";
						if (taskText) {
							if (DISPATCH_PLACEHOLDER_CASE_RE.test(taskText)) {
								taskText = expandPlaceholdersPlain(taskText, targetInfo);
							}
							if (!taskText.startsWith(`[eval:${pc.agent}]`)) {
								taskText = `[eval:${pc.agent}] ${taskText}`;
							}
						}
						if (!taskText) {
							const intentHits = [...effectiveCode.matchAll(/\b(i\d{3,})\b/g)].map((m) => m[1]).filter(Boolean);
							taskText = `[eval:${pc.agent}]${intentHits.length ? ` [女娲派单 ${intentHits[0]}]` : ""} ${effectiveCode.slice(0, 600)}`.trim();
						}
						store.pendingToolDispatches.push({
							seq: store.nextDispatchSeq(),
							root: normRoot,
							sessionId: sid,
							...(evalToolCallId ? { toolCallId: evalToolCallId } : {}),
							invocationKind: "eval",
							agent: pc.agent,
							...(pc.label ? { name: pc.label } : {}),
							index: idx,
							taskText,
							spawnKeyCandidates: pc.label ? [pc.label] : [],
							evalWindow: true,
							createdAt: nowMs,
						});
					});
				}

				if (/\btool\.task\s*\(/.test(strippedEvalCode) || parsedAgentCalls.length === 0) {
					const intentHits = [...effectiveCode.matchAll(/\b(i\d{3,})\b/g)].map((m) => m[1]).filter(Boolean);
					const inferredAgent =
						/\bnuwa-verifier\b/.test(effectiveCode) && !/\bfujiang\b/.test(effectiveCode)
							? "nuwa-verifier"
							: "fujiang";
					const summaryText = `[eval:${inferredAgent}]${intentHits.length ? ` [女娲派单 ${intentHits[0]}]` : ""} ${effectiveCode.slice(0, 600)}`.trim();
					store.pendingToolDispatches.push({
						seq: store.nextDispatchSeq(),
						root: normRoot,
						sessionId: sid,
						...(evalToolCallId ? { toolCallId: evalToolCallId } : {}),
						invocationKind: "eval",
						agent: inferredAgent,
						index: parsedAgentCalls.length,
						taskText: summaryText,
						spawnKeyCandidates: [],
						evalWindow: true,
						reusable: true,
						createdAt: nowMs,
					});
				}
			}

			if (needsEvalRewrite) {
				return { input: { ...input, code: effectiveCode } };
			}
			return undefined;
		}

		if (
			active &&
			(name === "read" ||
				name === "read_file" ||
				name === "fetch" ||
				name === "web_fetch" ||
				name === "browser" ||
				name.startsWith("browser_") ||
				name === "web_search" ||
				name.startsWith("web_search") ||
				name === "search_web" ||
				name === "google_search")
		) {
			const sv = checkToolScopeAndRisk(name, input, projScope, st.project.mode);
			if (sv) return sv;
		}

		if (["write", "edit", "multi_edit", "apply_patch", "notebook_edit"].includes(name)) {
			const v = checkWritePolicy(input, active);
			if (v) return v;
		}

		return undefined;
	} catch {
		return undefined;
	}
}

/**
 * 处理 `before_subagent_spawn` 事件：
 * 消费前置异步/同步派单缓冲、校验派单回执、启动 `SubagentWatchdog`、动态模型路由并登记反自证校准预测。
 */
export function handleBeforeSubagentSpawn(
	store: DispatchBridgeStore,
	event: Record<string, unknown>,
	ctx: DispatchBridgeContext,
	opts?: DispatchBridgeOptions,
): BeforeSubagentSpawnResult {
	try {
		const root = resolveBridgeRoot(ctx, opts);
		if (!root) return undefined;
		const sid = getBridgeSessionId(ctx);
		const agentHome = opts?.getAgentHome ? opts.getAgentHome() : getAgentHome();
		bindSubagentSpawn(sid, ctx.agent?.id, root, agentHome);

		const st = loadState(root);
		if (!st || st.project.status !== "active" || isTerminalStateInternal(st)) return undefined;

		const watchdog = new SubagentWatchdog(root);
		watchdog.checkTimeouts();

		const agentName =
			typeof event?.agent === "string"
				? event.agent
				: typeof event?.agentName === "string"
					? event.agentName
					: typeof event?.name === "string"
						? event.name
						: "";
		const spawnKeyStr = typeof event?.spawnKey === "string" ? event.spawnKey.trim() : "";
		const invocationKind =
			typeof event?.invocationKind === "string" ? event.invocationKind.trim().toLowerCase() : "";
		const hasInlineTaskField =
			Boolean(event && typeof event === "object") &&
			(Object.prototype.hasOwnProperty.call(event, "task") ||
				Object.prototype.hasOwnProperty.call(event, "prompt") ||
				Object.prototype.hasOwnProperty.call(event, "assignment"));

		const matchedPending = !hasInlineTaskField
			? store.consumePending(root, sid, agentName, spawnKeyStr, invocationKind)
			: undefined;
		const ompNativeNoInlineTask =
			!hasInlineTaskField && !matchedPending && (invocationKind === "task" || invocationKind === "eval");

		const spawnId =
			typeof event?.spawnId === "string" && event.spawnId.trim()
				? event.spawnId.trim()
				: typeof event?.id === "string" && event.id.trim()
					? event.id.trim()
					: spawnKeyStr || `spawn-${Date.now()}-${store.nextSpawnSeq()}`;

		const taskText = hasInlineTaskField
			? String(event?.task ?? event?.prompt ?? event?.assignment ?? "")
			: matchedPending
				? matchedPending.taskText
				: ompNativeNoInlineTask
					? `[omp:${invocationKind}:${agentName || "fujiang"}] spawnKey=${spawnId} target=${st.project.url || st.project.host || "local"}`
					: "";
		const dispatchContext =
			event?.context !== undefined ? (event.context as Record<string, unknown> | string) : matchedPending?.context;
		const routeCtx = resolveTaskIntentContext(agentName, taskText, st.intents, st.project.phase);

		const activeEgress = normalizeTaskEgressUrl(resolveConfiguredEgressUrl());
		const trimmedRawTask = taskText.trim();
		const preInjectedTask =
			trimmedRawTask.length >= 8
				? buildDispatchPacket({
						task: taskText,
						target: {
							url: st.project.url,
							host: st.project.host,
							...(activeEgress ? { egress: maskEgressUrl(activeEgress) } : {}),
						},
					}).task
				: taskText;

		const dispatchReg = getDispatchRegistry(root).register(spawnId, {
			spawnId,
			agent: agentName,
			task: preInjectedTask,
			targetUrl: st.project.url,
			resolvedHost: st.project.host,
			intentId: routeCtx.intentId,
			context: dispatchContext,
		});
		if (!dispatchReg.ok) {
			logEvent(root, {
				type: "dispatch_rejected",
				spawnId,
				agent: agentName || "unknown",
				reason: dispatchReg.validation.reason,
				requeue: dispatchReg.requeue,
			});
			return {
				block: true,
				requeue: dispatchReg.requeue,
				reason: dispatchReg.validation.reason ?? "派单守卫拒收：任务为空或上下文不完整",
			};
		}

		if (ompNativeNoInlineTask) {
			logEvent(root, {
				type: "dispatch_omp_protocol_fallback",
				spawnId,
				agent: agentName || "unknown",
				invocationKind,
			});
		}

		if (event && typeof event === "object") {
			if ("task" in event || event.prompt === undefined) event.task = preInjectedTask;
			else event.prompt = preInjectedTask;
		}

		const pidVal = typeof event?.pid === "number" ? event.pid : undefined;
		watchdog.startTask({
			taskId: spawnId,
			agent: agentName || "fujiang",
			intentId: routeCtx.intentId,
			pid: pidVal,
		});
		store.activeSpawns.set(spawnId, {
			spawnId,
			root,
			agent: agentName || "fujiang",
			...(matchedPending?.toolCallId ? { toolCallId: matchedPending.toolCallId } : {}),
			...(routeCtx.intentId ? { intentId: routeCtx.intentId } : {}),
			rawTask: trimmedRawTask,
			injectedTask: preInjectedTask,
			sessionId: sid,
		});

		const routedModel = routeSubagentModel({
			agent: agentName,
			phase: routeCtx.phase,
			intentKeys: routeCtx.intentKey ? [routeCtx.intentKey] : [],
			hasPendingVerify: routeCtx.isVerify,
			hasReflect: routeCtx.isReflect,
			root,
		});

		if (routeCtx.intentId && (process.env.NUWA_CALIBRATION ?? "1").trim() !== "0") {
			try {
				const bGraph = loadOrInitBeliefGraph(root, st);
				const bNodeId = resolveBeliefNodeId(bGraph, routeCtx.intentId, "intent");
				const posterior = bNodeId && bGraph.nodes[bNodeId] ? bGraph.nodes[bNodeId]!.posterior : 0.5;
				const effModelId =
					routedModel || (typeof event?.model === "string" && event.model.trim() ? event.model.trim() : "host-default");
				recordPrediction(root, {
					predictionId: `pred-${spawnId}`,
					intentId: routeCtx.intentId,
					taskCategory: inferCalibrationTaskCategory({
						agent: agentName,
						phase: routeCtx.phase,
						intentKey: routeCtx.intentKey,
						hasPendingVerify: routeCtx.isVerify,
					}),
					modelId: effModelId,
					predictedConfidence: Math.max(0.01, Math.min(0.99, Number(posterior.toFixed(4)))),
					estimatedTokens: 4000,
					note: `spawn:${agentName || "fujiang"}:${routeCtx.intentKey ?? routeCtx.intentId}`,
				});
			} catch {
				/* 重复 spawnId 或只读环境异常不阻断子代理派生 */
			}
		}

		if (routedModel) {
			if (event && typeof event === "object" && !event.model) event.model = routedModel;
			logEvent(root, {
				type: "model_route",
				agent: agentName || "unknown",
				model: routedModel,
				phase: routeCtx.phase,
				...(routeCtx.intentId ? { intentId: routeCtx.intentId } : {}),
				...(routeCtx.intentKey ? { intentKey: routeCtx.intentKey } : {}),
				isVerify: routeCtx.isVerify,
				isReflect: routeCtx.isReflect,
			});
			return { model: routedModel, spawnId, task: preInjectedTask };
		}

		return { spawnId, task: preInjectedTask };
	} catch {
		return undefined;
	}
}

function handleToolEndOrResultInternal(
	store: DispatchBridgeStore,
	event: unknown,
	ctx: DispatchBridgeContext,
	countLiveCall: boolean,
	opts?: DispatchBridgeOptions,
): void {
	const sid = getBridgeSessionId(ctx);
	if (countLiveCall) {
		store.incrementLiveCalls(sid);
	}
	try {
		const evObj = (event ?? {}) as Record<string, unknown>;
		const { toolName, inputObj, command, output } = extractEventOutput(evObj);
		const root = resolveBridgeRoot(ctx, opts);
		if (root && !isMainBridgeAgent(ctx)) {
			const wd = new SubagentWatchdog(root);
			wd.recordOutput(resolveWatchdogTaskId(wd, ctx));
		}
		const normTool = toolName.trim().toLowerCase();
		const tcId = typeof evObj.toolCallId === "string" ? evObj.toolCallId.trim() : "";
		if (root && (normTool === "task" || normTool === "subagent" || normTool === "agent" || normTool === "delegate")) {
			completeWatchdogOnTaskEnd(store, root, evObj, inputObj, ctx);
			store.reconcileOnToolResult(root, tcId, evObj);
		} else if (root && normTool === "eval" && evObj.isError === true) {
			store.clearByToolCall(root, tcId);
		}

		if (!isTrustedEvidenceEvent(toolName, inputObj)) return;
		if (!root) return;
		if (tcId) {
			const dedupKey = `${resolve(root)}::${tcId}`;
			if (store.seenEvidenceToolCallIds.has(dedupKey)) return;
			store.seenEvidenceToolCallIds.add(dedupKey);
		}
		if (command || output) {
			const agentName = ctx.agent?.name ?? ctx.agent?.kind;
			recordToolExecution(root, { tool: toolName, command, output, sessionId: sid, agentName });
		}
	} catch {
		/* 账本或看门狗更新异常不阻塞宿主执行 */
	}
}

/**
 * 处理 `tool_execution_end` 事件（计入 `liveCalls`，协调 `async.state === "running"` 句柄与看门狗回收，并记录可信证据账本）。
 */
export function handleToolExecutionEnd(
	store: DispatchBridgeStore,
	event: unknown,
	ctx: DispatchBridgeContext,
	opts?: DispatchBridgeOptions,
): void {
	handleToolEndOrResultInternal(store, event, ctx, true, opts);
}

/**
 * 处理 `tool_result` 事件（专用于 `eval` 内 `tool.task` 异步结果通道等回包回收，不重复累加 `liveCalls`，并去重记录执行证据账本）。
 */
export function handleToolResult(
	store: DispatchBridgeStore,
	event: unknown,
	ctx: DispatchBridgeContext,
	opts?: DispatchBridgeOptions,
): void {
	handleToolEndOrResultInternal(store, event, ctx, false, opts);
}
