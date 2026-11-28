/**
 * 女娲 v8.0.0 浏览器可执行文件探测、原生 WebSocket CDP JSON-RPC 客户端与进程树生命周期管理模块。
 *
 * 约束：零外部第三方 npm 依赖，仅类型引用 `./types`，严禁导入 `./nuwa` 或 `./cdp-bridge`。
 */
import { randomUUID } from "node:crypto";
import {
	accessSync,
	constants as fsConstants,
	existsSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Mode, ScopePolicy } from "./types";

/** CDP 启动与 WebSocket 握手默认超时（毫秒，兼容完整 Chrome 冷启动）。 */
export const DEFAULT_LAUNCH_TIMEOUT_MS = 30_000;

/** 单条 CDP JSON-RPC 指令默认超时（毫秒）。 */
export const DEFAULT_RPC_TIMEOUT_MS = 10_000;

export interface ResolveChromeOptions {
	/** 显式指定的浏览器可执行文件路径（最高优先级）。 */
	executablePath?: string;
	/** 自定义环境变量映射（默认读取 `process.env`）。 */
	env?: Record<string, string | undefined>;
	/** 自定义主目录路径（用于查找 `~/.cache/ms-playwright`）。 */
	homeDir?: string;
	/** 是否优先选用启动更快的 `chrome-headless-shell`（默认 true）。 */
	preferHeadlessShell?: boolean;
}

export interface CdpTransportLike {
	send(data: string): void;
	close(): void;
	onMessage(handler: (data: string) => void): void;
	onClose(handler: (reason?: string) => void): void;
	onError(handler: (err: Error) => void): void;
}

export interface CdpClientOptions {
	defaultTimeoutMs?: number;
}

export type CdpEventListener = (params: Record<string, unknown>, sessionId?: string) => void;

export interface LaunchCdpSessionOptions {
	executablePath?: string;
	headless?: boolean;
	extraArgs?: string[];
	userDataDir?: string;
	launchTimeoutMs?: number;
	rpcTimeoutMs?: number;
	env?: Record<string, string | undefined>;
	/** 可选注入确定性 Mock CDP Transport（注入后不拉起真实宿主机浏览器子进程）。 */
	transport?: CdpTransportLike;
	wsEndpoint?: string;
}

export interface CdpHeaderEntry {
	name: string;
	value: string;
}

export interface CdpCookieParam {
	name: string;
	value: string;
	url?: string;
	domain?: string;
	path?: string;
	secure?: boolean;
	httpOnly?: boolean;
	sameSite?: "Strict" | "Lax" | "None";
}

/** 内部请求拦截覆写规则（按一次性探针 Token 关联）。 */
export interface ProbeInterceptRule {
	authMode: "inherit" | "anonymous" | "override";
	overrideHeaders?: Record<string, string>;
	matchedUrl?: string;
	blockedReason?: string;
}

/** 会话级网络拦截控制器状态。 */
export interface SessionInterceptorState {
	enabled: boolean;
	scope: ScopePolicy;
	mode: Mode | string;
	allowedMethods?: ReadonlySet<string>;
	readonlyLockCount: number;
	lastReadonlyBlockReason?: string;
	blockedRequests: BlockedCdpRequest[];
	probeRules: Map<string, ProbeInterceptRule>;
	onAllowedRequest?: (info: { requestId: string; url: string; method: string; headers: Record<string, string> }) => void;
	unsubscribe?: () => void;
}

export interface CdpSession {
	readonly id: string;
	readonly client: CdpClient;
	readonly wsEndpoint: string;
	readonly targetId: string;
	readonly sessionId: string;
	readonly executablePath?: string;
	readonly pid?: number;
	readonly userDataDir?: string;
	readonly ownsUserDataDir: boolean;
	readonly processTag: string;
	readonly browserVersion?: string;
	readonly isMock: boolean;
	closed: boolean;
	/** 内部子进程句柄与拦截器状态。 */
	_proc?: Bun.SpawnSubprocess;
	_interceptor?: SessionInterceptorState;
}

export interface BlockedCdpRequest {
	url: string;
	method: string;
	resourceType?: string;
	reason: string;
}

// ==================== 1. Chrome 可执行文件探测 ====================

function isExecutableFile(filePath: string | undefined): filePath is string {
	if (!filePath || !filePath.trim()) return false;
	const resolved = filePath.trim();
	try {
		if (!existsSync(resolved)) return false;
		const st = statSync(resolved);
		if (!st.isFile()) return false;
		accessSync(resolved, fsConstants.X_OK);
		return true;
	} catch {
		return false;
	}
}

function collectPlaywrightBrowsers(cacheRoot: string, preferHeadlessShell: boolean): string[] {
	if (!cacheRoot || !existsSync(cacheRoot)) return [];
	let entries: string[] = [];
	try {
		entries = readdirSync(cacheRoot);
	} catch {
		return [];
	}

	// 按目录名数值感知逆序排列，使更高版本号（如 chromium-1248 > chromium-999）排在前面
	const sorted = [...entries].sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
	const headlessShellBins: string[] = [];
	const fullChromeBins: string[] = [];

	for (const dirName of sorted) {
		const fullDir = join(cacheRoot, dirName);
		let subDirs: string[] = [];
		try {
			if (!statSync(fullDir).isDirectory()) continue;
			subDirs = readdirSync(fullDir).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
		} catch {
			continue;
		}

		if (dirName.startsWith("chromium_headless_shell")) {
			for (const sub of subDirs) {
				if (!sub.startsWith("chrome-headless-shell") && !sub.startsWith("chrome-linux")) continue;
				const cand = join(fullDir, sub, "chrome-headless-shell");
				if (isExecutableFile(cand)) headlessShellBins.push(cand);
			}
		} else if (dirName.startsWith("chromium")) {
			for (const sub of subDirs) {
				if (!sub.startsWith("chrome-linux") && !sub.startsWith("chrome-")) continue;
				const candChrome = join(fullDir, sub, "chrome");
				if (isExecutableFile(candChrome)) fullChromeBins.push(candChrome);
				const candShell = join(fullDir, sub, "chrome-headless-shell");
				if (isExecutableFile(candShell)) headlessShellBins.push(candShell);
			}
		}
	}

	return preferHeadlessShell
		? [...headlessShellBins, ...fullChromeBins]
		: [...fullChromeBins, ...headlessShellBins];
}

/**
 * 自动探测本机可用的 Chrome / Chromium / Headless Shell 可执行文件路径。
 * 优先级：
 * 1. `opts.executablePath` 显式路径；
 * 2. `NUWA_CHROME_BIN` 环境变量；
 * 3. Playwright 浏览器缓存（`~/.cache/ms-playwright`，默认优先选用极速启动的 `chrome-headless-shell`，回退 `chrome-linux64/chrome`）；
 * 4. `/usr/bin/google-chrome` 等系统标准安装路径及 `PATH` 查找。
 */
export function resolveChromeExecutable(opts?: ResolveChromeOptions): string | null {
	if (isExecutableFile(opts?.executablePath)) {
		return opts.executablePath.trim();
	}

	const env = opts?.env ?? process.env;
	const envBin = env.NUWA_CHROME_BIN?.trim();
	if (isExecutableFile(envBin)) {
		return envBin;
	}

	const preferHeadlessShell = opts?.preferHeadlessShell ?? true;
	const home = opts?.homeDir?.trim() || env.HOME?.trim() || homedir();
	const pwCacheCandidates = [
		env.PLAYWRIGHT_BROWSERS_PATH?.trim(),
		home ? join(home, ".cache", "ms-playwright") : "",
		"/root/.cache/ms-playwright",
	].filter((p): p is string => Boolean(p));

	for (const cacheDir of pwCacheCandidates) {
		const found = collectPlaywrightBrowsers(cacheDir, preferHeadlessShell);
		if (found.length > 0) {
			return found[0]!;
		}
	}

	const systemCandidates = [
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/opt/google/chrome/google-chrome",
	];
	for (const sysPath of systemCandidates) {
		if (isExecutableFile(sysPath)) {
			return sysPath;
		}
	}

	for (const binName of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome-headless-shell"]) {
		try {
			const located = Bun.which(binName);
			if (isExecutableFile(located ?? undefined)) {
				return located!;
			}
		} catch {
			/* 忽略 which 查找异常 */
		}
	}

	return null;
}

// ==================== 2. 原生 WebSocket CDP JSON-RPC 客户端 ====================

interface PendingRpcEntry {
	method: string;
	resolve: (value: Record<string, unknown>) => void;
	reject: (err: Error) => void;
	timer: ReturnType<typeof setTimeout>;
}

/** 将浏览器/Bun 原生全局 `WebSocket` 包装为标准 `CdpTransportLike`。 */
function createNativeWebSocketTransport(wsUrl: string, connectTimeoutMs: number): Promise<CdpTransportLike> {
	return new Promise<CdpTransportLike>((resolvePromise, rejectPromise) => {
		let settled = false;
		let ws: WebSocket;
		try {
			ws = new WebSocket(wsUrl);
		} catch (err) {
			rejectPromise(err instanceof Error ? err : new Error(String(err)));
			return;
		}

		const msgHandlers: Array<(data: string) => void> = [];
		const closeHandlers: Array<(reason?: string) => void> = [];
		const errorHandlers: Array<(err: Error) => void> = [];

		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			try {
				ws.close();
			} catch {
				/* ignore */
			}
			rejectPromise(new Error(`CDP WebSocket 握手超时 (${connectTimeoutMs}ms): ${wsUrl}`));
		}, connectTimeoutMs);

		ws.addEventListener("open", () => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolvePromise({
				send(data: string) {
					ws.send(data);
				},
				close() {
					try {
						ws.close();
					} catch {
						/* ignore */
					}
				},
				onMessage(handler) {
					msgHandlers.push(handler);
				},
				onClose(handler) {
					closeHandlers.push(handler);
				},
				onError(handler) {
					errorHandlers.push(handler);
				},
			});
		});

		ws.addEventListener("message", (ev: MessageEvent) => {
			const raw =
				typeof ev.data === "string"
					? ev.data
					: ev.data instanceof ArrayBuffer
						? Buffer.from(ev.data).toString("utf8")
						: Buffer.isBuffer(ev.data)
							? ev.data.toString("utf8")
							: String(ev.data ?? "");
			for (const h of msgHandlers) {
				try {
					h(raw);
				} catch {
					/* 隔离单个消息处理器异常 */
				}
			}
		});

		ws.addEventListener("close", (ev: CloseEvent) => {
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				rejectPromise(new Error(`CDP WebSocket 握手阶段提前关闭 (code=${ev.code})`));
				return;
			}
			for (const h of closeHandlers) {
				try {
					h(ev.reason || `code=${ev.code}`);
				} catch {
					/* ignore */
				}
			}
		});

		ws.addEventListener("error", () => {
			const err = new Error(`CDP WebSocket 通信异常 (${wsUrl})`);
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				rejectPromise(err);
				return;
			}
			for (const h of errorHandlers) {
				try {
					h(err);
				} catch {
					/* ignore */
				}
			}
		});
	});
}

/**
 * 零依赖原生 CDP JSON-RPC 客户端。
 * 支持多路复用 `sessionId`、单请求独立超时、事件订阅与底层连接断开快速失败。
 */
export class CdpClient {
	private readonly transport: CdpTransportLike;
	private readonly defaultTimeoutMs: number;
	private nextId = 1;
	private closed = false;
	private readonly pending = new Map<number, PendingRpcEntry>();
	private readonly listeners = new Map<string, Set<CdpEventListener>>();
	private readonly eventWaiters = new Set<(err: Error) => void>();

	constructor(transport: CdpTransportLike, opts?: CdpClientOptions) {
		this.transport = transport;
		this.defaultTimeoutMs = Math.max(200, opts?.defaultTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS);

		this.transport.onMessage((raw) => this.handleRawMessage(raw));
		this.transport.onClose((reason) => this.failAllPending(new Error(`CDP 连接已关闭${reason ? `: ${reason}` : ""}`)));
		this.transport.onError((err) => this.failAllPending(err));
	}

	/** 通过原生 `WebSocket` 直连指定 DevTools 端点并返回初始化就绪的 `CdpClient`。 */
	public static async connect(
		wsUrl: string,
		opts?: CdpClientOptions & { connectTimeoutMs?: number },
	): Promise<CdpClient> {
		const connectTimeoutMs = Math.max(500, opts?.connectTimeoutMs ?? DEFAULT_LAUNCH_TIMEOUT_MS);
		const transport = await createNativeWebSocketTransport(wsUrl, connectTimeoutMs);
		return new CdpClient(transport, opts);
	}

	public get isClosed(): boolean {
		return this.closed;
	}

	/** 发送 CDP JSON-RPC 指令并等待匹配 `id` 的结果。 */
	public send<T = Record<string, unknown>>(
		method: string,
		params?: Record<string, unknown>,
		opts?: { sessionId?: string; timeoutMs?: number },
	): Promise<T> {
		if (this.closed) {
			return Promise.reject(new Error(`CDP 客户端已关闭，无法调用 ${method}`));
		}
		const id = this.nextId++;
		const timeoutMs = Math.max(100, opts?.timeoutMs ?? this.defaultTimeoutMs);
		const payload: Record<string, unknown> = { id, method };
		if (params !== undefined) payload.params = params;
		if (opts?.sessionId) payload.sessionId = opts.sessionId;

		return new Promise<T>((resolvePromise, rejectPromise) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				rejectPromise(new Error(`CDP 请求超时 (${method}, ${timeoutMs}ms)`));
			}, timeoutMs);

			this.pending.set(id, {
				method,
				resolve: (res) => resolvePromise(res as T),
				reject: rejectPromise,
				timer,
			});

			try {
				this.transport.send(JSON.stringify(payload));
			} catch (err) {
				clearTimeout(timer);
				this.pending.delete(id);
				rejectPromise(err instanceof Error ? err : new Error(String(err)));
			}
		});
	}

	/** 订阅指定 CDP 域事件（如 `"Fetch.requestPaused"`），返回取消订阅函数。 */
	public on(event: string, listener: CdpEventListener): () => void {
		let set = this.listeners.get(event);
		if (!set) {
			set = new Set<CdpEventListener>();
			this.listeners.set(event, set);
		}
		set.add(listener);
		return () => this.off(event, listener);
	}

	public off(event: string, listener: CdpEventListener): void {
		const set = this.listeners.get(event);
		if (!set) return;
		set.delete(listener);
		if (set.size === 0) {
			this.listeners.delete(event);
		}
	}

	/** 等待满足条件的单次 CDP 事件（含超时自动退订与断连立即唤醒拒绝）。 */
	public waitForEvent<T = Record<string, unknown>>(
		event: string,
		opts?: {
			sessionId?: string;
			predicate?: (params: T, sessionId?: string) => boolean;
			timeoutMs?: number;
		},
	): Promise<T> {
		if (this.closed) {
			return Promise.reject(new Error(`CDP 客户端已关闭，无法等待事件 ${event}`));
		}
		const timeoutMs = Math.max(100, opts?.timeoutMs ?? this.defaultTimeoutMs);
		return new Promise<T>((resolvePromise, rejectPromise) => {
			let done = false;
			const onAbort = (err: Error) => {
				if (done) return;
				done = true;
				clearTimeout(timer);
				off();
				this.eventWaiters.delete(onAbort);
				rejectPromise(err);
			};

			const timer = setTimeout(() => {
				if (done) return;
				done = true;
				off();
				this.eventWaiters.delete(onAbort);
				rejectPromise(new Error(`等待 CDP 事件超时 (${event}, ${timeoutMs}ms)`));
			}, timeoutMs);

			const off = this.on(event, (params, evSessionId) => {
				if (done) return;
				if (opts?.sessionId && evSessionId && evSessionId !== opts.sessionId) return;
				const typed = params as unknown as T;
				if (opts?.predicate && !opts.predicate(typed, evSessionId)) return;
				done = true;
				clearTimeout(timer);
				off();
				this.eventWaiters.delete(onAbort);
				resolvePromise(typed);
			});

			this.eventWaiters.add(onAbort);
		});
	}

	/** 幂等关闭客户端并拒绝全部未决请求。 */
	public close(): void {
		if (this.closed) return;
		this.closed = true;
		this.failAllPending(new Error("CDP 客户端主动关闭"));
		this.listeners.clear();
		try {
			this.transport.close();
		} catch {
			/* ignore */
		}
	}

	private handleRawMessage(raw: string): void {
		if (!raw) return;
		let msg: Record<string, unknown>;
		try {
			msg = JSON.parse(raw) as Record<string, unknown>;
		} catch {
			return;
		}

		if (typeof msg.id === "number") {
			const entry = this.pending.get(msg.id);
			if (!entry) return;
			clearTimeout(entry.timer);
			this.pending.delete(msg.id);

			if (msg.error && typeof msg.error === "object") {
				const errObj = msg.error as Record<string, unknown>;
				const errMsg = typeof errObj.message === "string" ? errObj.message : JSON.stringify(errObj);
				const errData = typeof errObj.data === "string" ? ` (${errObj.data})` : "";
				entry.reject(new Error(`CDP 错误 [${entry.method}]: ${errMsg}${errData}`));
			} else {
				const result =
					msg.result && typeof msg.result === "object"
						? (msg.result as Record<string, unknown>)
						: {};
				entry.resolve(result);
			}
			return;
		}

		if (typeof msg.method === "string") {
			const eventName = msg.method;
			const params =
				msg.params && typeof msg.params === "object"
					? (msg.params as Record<string, unknown>)
					: {};
			const sessionId = typeof msg.sessionId === "string" ? msg.sessionId : undefined;
			const handlers = this.listeners.get(eventName);
			if (handlers && handlers.size > 0) {
				for (const fn of [...handlers]) {
					try {
						fn(params, sessionId);
					} catch {
						/* 隔离事件回调错误 */
					}
				}
			}
		}
	}

	private failAllPending(err: Error): void {
		this.closed = true;
		for (const [id, entry] of this.pending.entries()) {
			clearTimeout(entry.timer);
			this.pending.delete(id);
			try {
				entry.reject(err);
			} catch {
				/* ignore */
			}
		}
		for (const abortWaiter of [...this.eventWaiters]) {
			this.eventWaiters.delete(abortWaiter);
			try {
				abortWaiter(err);
			} catch {
				/* ignore */
			}
		}
	}
}

// ==================== 3. Chrome 进程管理与零残留清理 ====================

/**
 * 扫描 `/proc` 查找命令行包含指定唯一标识且非僵尸态（`State !== Z`）的本机进程 PID 列表。
 * 用于强力回收 Chrome 渲染器/GPU/网络子进程并在测试中校验零残留。
 */
export function findLiveProcessesByTag(processTag: string): number[] {
	const tag = String(processTag ?? "").trim();
	if (!tag || !existsSync("/proc")) return [];
	const matched: number[] = [];
	let entries: string[] = [];
	try {
		entries = readdirSync("/proc");
	} catch {
		return [];
	}

	for (const name of entries) {
		if (!/^\d+$/.test(name)) continue;
		const pid = Number(name);
		if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) continue;
		try {
			const cmdlineBuf = readFileSync(`/proc/${pid}/cmdline`);
			if (!cmdlineBuf || cmdlineBuf.length === 0) continue;
			const cmdline = cmdlineBuf.toString("utf8").replace(/\0+/g, " ");
			if (!cmdline.includes(tag)) continue;

			const statText = readFileSync(`/proc/${pid}/stat`, "utf8");
			const rparen = statText.lastIndexOf(")");
			const stateChar = rparen > 0 ? statText.slice(rparen + 2, rparen + 3) : "";
			if (stateChar === "Z") continue;
			matched.push(pid);
		} catch {
			/* 进程可能已退出，安全忽略 */
		}
	}
	return matched;
}

/** 扫描 `/proc` 递归收集指定父进程的所有存活后代子进程 PID。 */
function findDescendantPids(rootPid: number): number[] {
	if (!Number.isInteger(rootPid) || rootPid <= 1 || !existsSync("/proc")) return [];
	const childrenMap = new Map<number, number[]>();
	try {
		for (const name of readdirSync("/proc")) {
			if (!/^\d+$/.test(name)) continue;
			const pid = Number(name);
			if (pid <= 1) continue;
			try {
				const statText = readFileSync(`/proc/${pid}/stat`, "utf8");
				const rparen = statText.lastIndexOf(")");
				if (rparen < 0) continue;
				const fields = statText.slice(rparen + 2).trim().split(/\s+/);
				const stateChar = fields[0] ?? "";
				const ppid = Number(fields[1] ?? "0");
				if (stateChar === "Z" || !Number.isInteger(ppid) || ppid <= 1) continue;
				const list = childrenMap.get(ppid) ?? [];
				list.push(pid);
				childrenMap.set(ppid, list);
			} catch {
				/* ignore */
			}
		}
	} catch {
		return [];
	}

	const descendants: number[] = [];
	const queue = [...(childrenMap.get(rootPid) ?? [])];
	const seen = new Set<number>(queue);
	while (queue.length > 0) {
		const cur = queue.shift()!;
		descendants.push(cur);
		for (const nxt of childrenMap.get(cur) ?? []) {
			if (!seen.has(nxt)) {
				seen.add(nxt);
				queue.push(nxt);
			}
		}
	}
	return descendants;
}

function safeKillPid(pid: number, signal: "SIGTERM" | "SIGKILL"): void {
	if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) return;
	try {
		process.kill(pid, signal);
	} catch {
		/* ESRCH 已退出忽略 */
	}
}

async function waitWithTimeout<T>(promise: Promise<T>, ms: number): Promise<{ timedOut: boolean; value?: T }> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const res = await Promise.race([
			promise.then((value) => ({ timedOut: false, value })),
			new Promise<{ timedOut: true }>((resolvePromise) => {
				timer = setTimeout(() => resolvePromise({ timedOut: true }), ms);
			}),
		]);
		return res;
	} finally {
		if (timer) clearTimeout(timer);
	}
}

/** 从子进程流异步读取文本直至匹配到 `DevTools listening on ws://...` 或超时。 */
async function readDevToolsWsEndpoint(
	proc: Bun.SpawnSubprocess,
	timeoutMs: number,
): Promise<string> {
	const wsRegex = /DevTools listening on (ws:\/\/127\.0\.0\.1:\d+\/devtools\/\S+)/;
	const collectedLogs: string[] = [];

	return new Promise<string>((resolvePromise, rejectPromise) => {
		let settled = false;
		const decoder = new TextDecoder();

		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			const tail = collectedLogs.join("").slice(-500);
			rejectPromise(
				new Error(`等待 Chrome DevTools WebSocket 端点超时 (${timeoutMs}ms)${tail ? `: ${tail}` : ""}`),
			);
		}, timeoutMs);

		const pumpStream = async (stream: ReadableStream<Uint8Array> | undefined) => {
			if (!stream) return;
			const reader = stream.getReader();
			let buffer = "";
			try {
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!settled && value) {
						const chunk = decoder.decode(value, { stream: true });
						collectedLogs.push(chunk);
						if (collectedLogs.length > 24) collectedLogs.shift();
						buffer += chunk;
						const match = wsRegex.exec(buffer);
						if (match?.[1]) {
							settled = true;
							clearTimeout(timer);
							buffer = "";
							collectedLogs.length = 0;
							resolvePromise(match[1].trim());
							// 关键：匹配成功后不中断循环，继续后台静默排空子进程管道输出直至关闭，防止 64KB 缓冲写满死锁
							continue;
						}
						if (buffer.length > 8192) {
							buffer = buffer.slice(-2048);
						}
					}
				}
			} catch {
				/* 流关闭忽略 */
			} finally {
				try {
					reader.releaseLock();
				} catch {
					/* ignore */
				}
			}
		};

		void pumpStream(proc.stderr);
		void pumpStream(proc.stdout);

		void proc.exited.then((exitCode) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			const tail = collectedLogs.join("").slice(-500);
			rejectPromise(new Error(`Chrome 子进程在输出 DevTools 端点前异常退出 (code=${exitCode})${tail ? `: ${tail}` : ""}`));
		});
	});
}

/**
 * 启动受控 Headless Chrome 会话并建立原生 CDP WebSocket 连接（或挂载注入的 Mock Transport）。
 * 若握手或目标初始化期间发生任何异常，内部自动强制清理子进程与临时目录，保证零残留。
 */
export async function launchCdpSession(opts?: LaunchCdpSessionOptions): Promise<CdpSession> {
	const id = `cdp_${randomUUID().slice(0, 8)}`;
	const processTag = `nuwa-cdp-${id}-${Date.now()}`;
	const rpcTimeoutMs = Math.max(200, opts?.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS);

	// 分支 A：确定性 Mock Transport 注入模式（无需拉起真实宿主机浏览器）
	if (opts?.transport) {
		const client = new CdpClient(opts.transport, { defaultTimeoutMs: rpcTimeoutMs });
		try {
			const verRes = await client
				.send<{ product?: string }>("Browser.getVersion", {}, { timeoutMs: rpcTimeoutMs })
				.catch(() => ({ product: "MockChrome/1.0" }));
			const created = await client.send<{ targetId?: string }>(
				"Target.createTarget",
				{ url: "about:blank" },
				{ timeoutMs: rpcTimeoutMs },
			);
			const targetId = String(created.targetId ?? "mock-target-1");
			const attached = await client.send<{ sessionId?: string }>(
				"Target.attachToTarget",
				{ targetId, flatten: true },
				{ timeoutMs: rpcTimeoutMs },
			);
			const sessionId = String(attached.sessionId ?? "mock-session-1");
			return {
				id,
				client,
				wsEndpoint: opts.wsEndpoint ?? "ws://127.0.0.1:0/devtools/browser/mock",
				targetId,
				sessionId,
				ownsUserDataDir: false,
				processTag,
				browserVersion: verRes.product ?? "MockChrome/1.0",
				isMock: true,
				closed: false,
			};
		} catch (err) {
			client.close();
			throw err;
		}
	}

	// 分支 B：真实拉起本机 Headless Chrome 直连原生 CDP WebSocket
	const executablePath = resolveChromeExecutable({
		executablePath: opts?.executablePath,
		env: opts?.env,
	});
	if (!executablePath) {
		throw new Error(
			"未探测到可用的 Chrome/Chromium 可执行文件；请设置 NUWA_CHROME_BIN 或安装 google-chrome / playwright chromium",
		);
	}

	const ownsUserDataDir = !opts?.userDataDir;
	const userDataDir = opts?.userDataDir
		? resolve(opts.userDataDir)
		: mkdtempSync(join(tmpdir(), `${processTag}-`));

	const headlessFlag = opts?.headless === false ? undefined : "--headless=new";
	const launchArgs: string[] = [
		...(headlessFlag ? [headlessFlag] : []),
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--remote-debugging-port=0",
		"--remote-debugging-address=127.0.0.1",
		`--user-data-dir=${userDataDir}`,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-background-timer-throttling",
		"--disable-client-side-phishing-detection",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-hang-monitor",
		"--disable-popup-blocking",
		"--disable-prompt-on-repost",
		"--disable-sync",
		"--metrics-recording-only",
		"--mute-audio",
		"--password-store=basic",
		"--use-mock-keychain",
		...(opts?.extraArgs ?? []),
		"about:blank",
	];

	const launchTimeoutMs = Math.max(1, opts?.launchTimeoutMs ?? DEFAULT_LAUNCH_TIMEOUT_MS);
	const mergedEnv: Record<string, string | undefined> = {
		...process.env,
		...(opts?.env ?? {}),
		// 阻断桌面 DBus 自动唤醒超时导致的 10s+ 冷启动阻塞
		DBUS_SESSION_BUS_ADDRESS: "/dev/null",
	};

	const proc = Bun.spawn([executablePath, ...launchArgs], {
		env: mergedEnv,
		stdin: "ignore",
		stdout: "pipe",
		stderr: "pipe",
	});
	const pid = (proc as unknown as { pid?: number }).pid;

	let partialSession: CdpSession = {
		id,
		client: null as unknown as CdpClient,
		wsEndpoint: "",
		targetId: "",
		sessionId: "",
		executablePath,
		...(typeof pid === "number" ? { pid } : {}),
		userDataDir,
		ownsUserDataDir,
		processTag,
		isMock: false,
		closed: false,
		_proc: proc,
	};

	try {
		const wsEndpoint = await readDevToolsWsEndpoint(proc, launchTimeoutMs);
		const client = await CdpClient.connect(wsEndpoint, {
			defaultTimeoutMs: rpcTimeoutMs,
			connectTimeoutMs: launchTimeoutMs,
		});
		partialSession = {
			...partialSession,
			client,
			wsEndpoint,
		};

		const verRes = await client
			.send<{ product?: string }>("Browser.getVersion", {}, { timeoutMs: rpcTimeoutMs })
			.catch(() => ({ product: undefined }));
		const created = await client.send<{ targetId?: string }>(
			"Target.createTarget",
			{ url: "about:blank" },
			{ timeoutMs: rpcTimeoutMs },
		);
		const targetId = String(created.targetId ?? "");
		if (!targetId) {
			throw new Error("CDP Target.createTarget 未返回有效 targetId");
		}
		const attached = await client.send<{ sessionId?: string }>(
			"Target.attachToTarget",
			{ targetId, flatten: true },
			{ timeoutMs: rpcTimeoutMs },
		);
		const sessionId = String(attached.sessionId ?? "");
		if (!sessionId) {
			throw new Error("CDP Target.attachToTarget 未返回有效 sessionId");
		}

		return {
			...partialSession,
			targetId,
			sessionId,
			...(verRes.product ? { browserVersion: verRes.product } : {}),
		};
	} catch (err) {
		await closeCdpSession(partialSession);
		throw err;
	}
}

/**
 * 安全关闭 CDP 会话并强制回收浏览器主进程、全部派生子进程及临时用户目录。
 * 幂等无异常抛出，适合放入任何 `finally` 块。
 */
export async function closeCdpSession(session: CdpSession | null | undefined): Promise<void> {
	if (!session || session.closed) return;
	session.closed = true;

	if (session._interceptor?.unsubscribe) {
		try {
			session._interceptor.unsubscribe();
		} catch {
			/* ignore */
		}
	}

	if (session.client && !session.client.isClosed) {
		try {
			await session.client.send("Browser.close", {}, { timeoutMs: 600 }).catch(() => {});
		} catch {
			/* ignore */
		}
		session.client.close();
	}

	if (!session.isMock) {
		const proc = session._proc;
		const rootPid = session.pid;
		const preDescendants = rootPid ? findDescendantPids(rootPid) : [];
		const taggedPids = session.processTag ? findLiveProcessesByTag(session.processTag) : [];

		if (proc) {
			try {
				proc.kill();
			} catch {
				/* ignore */
			}
		}
		if (rootPid) safeKillPid(rootPid, "SIGTERM");
		for (const childPid of [...preDescendants, ...taggedPids]) {
			safeKillPid(childPid, "SIGTERM");
		}

		if (proc) {
			const graceful = await waitWithTimeout(proc.exited.catch(() => 0), 800);
			if (graceful.timedOut) {
				if (rootPid) safeKillPid(rootPid, "SIGKILL");
				try {
					proc.kill(9);
				} catch {
					/* ignore */
				}
				await waitWithTimeout(proc.exited.catch(() => 0), 1_200);
			}
		}

		// 轮询清剿直至后代进程与标识进程彻底清零（防止返回瞬间仍有渲染器/GPU/crashpad 子进程存活）
		const reapDeadline = Date.now() + 1_800;
		while (Date.now() < reapDeadline) {
			const remainingPids = new Set<number>([
				...(rootPid ? findDescendantPids(rootPid) : []),
				...(session.processTag ? findLiveProcessesByTag(session.processTag) : []),
			]);
			if (remainingPids.size === 0) break;
			for (const remPid of remainingPids) {
				safeKillPid(remPid, "SIGKILL");
			}
			await Bun.sleep(25);
		}
	}

	if (session.ownsUserDataDir && session.userDataDir) {
		for (let attempt = 0; attempt < 6; attempt++) {
			try {
				if (!existsSync(session.userDataDir)) break;
				rmSync(session.userDataDir, { recursive: true, force: true });
				if (!existsSync(session.userDataDir)) break;
			} catch {
				/* 子进程句柄刚释放时短暂重试 */
			}
			await Bun.sleep(30);
		}
	}
}
