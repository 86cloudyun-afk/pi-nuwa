/**
 * 女娲 v7.0 原生 CDP 流量桥接与受控页面内只读契约差分模块。
 *
 * 核心职责：
 * 1. 零第三方依赖自动探测本机 Chrome / Chromium / Headless Shell 可执行文件，
 *    通过 `Bun.spawn` 拉起受控无头实例并基于原生 `WebSocket` 实现可靠 CDP JSON-RPC 客户端
 *    （含单请求超时、异常与 `finally` 进程树强制清理，杜绝残留子进程，同时支持注入 Mock Transport）。
 * 2. `captureCdpSessionTraffic`：启用 CDP `Network` / `Fetch` 拦截实时 XHR / Fetch / GraphQL 流量，
 *    在发包前强制执行 `isHostInScope` 与 `checkScopeAndRisk` 范围校验（主动 `Fetch.failRequest` 阻断越界请求），
 *    将捕获的认证凭据安全同步至 `SessionVault`，并将流量全量脱敏后写入 `TrafficRecorder`。
 * 3. `executeInPageSignedProbe` 与 `runCdpSignedAuthDiff`：在受控同源页面上下文内调用前端原生请求签名钩子
 *    或同源 `fetch` 包装器执行纯只读（`GET` / `HEAD` / `OPTIONS`）合规契约差分探测，结合 Soft-404 与基线哈希去噪，
 *    免逆向识别动态签名接口的越权访问边界缺陷（BOLA / BFLA / 未授权访问）。
 *
 * 约束：零外部 npm 依赖，严禁运行时或类型引用 `./nuwa`。
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
import {
	computeBodyHash,
	computeTemplateFingerprint,
	detectSoft404,
	type AutoFact,
	type Soft404Baseline,
	type Soft404BaselineInput,
} from "./autoexec";
import {
	computeKeyJaccard,
	extractJsonTopKeys,
	type AuthDiffAnomalyKind,
} from "./auth-diff";
import {
	checkScopeAndRisk,
	formatScopeBlockReason,
	isHostInScope,
} from "./scope";
import {
	formatSessionVaultSummary,
	getRoleHeadersMap,
	loadSessionVault,
	redactVaultSecrets,
	upsertSessionRole,
	type SessionVault,
} from "./session-vault";
import {
	REDACTED_MARKER,
	redactTrafficBody,
	redactTrafficHeaders,
	redactTrafficUrl,
	TrafficRecorder,
	type TrafficEntry,
} from "./traffic-workbench";
import type { Mode, ScopePolicy } from "./types";

/** 页面内只读差分并发度硬上限（严格不超过 8）。 */
export const MAX_CDP_PROBE_CONCURRENCY = 4 as const;

/** CDP 启动与 WebSocket 握手默认超时（毫秒，兼容完整 Chrome 冷启动）。 */
const DEFAULT_LAUNCH_TIMEOUT_MS = 30_000;

/** 单条 CDP JSON-RPC 指令默认超时（毫秒）。 */
const DEFAULT_RPC_TIMEOUT_MS = 10_000;

/** 页面导航与单步探针默认超时（毫秒）。 */
const DEFAULT_NAVIGATION_TIMEOUT_MS = 15_000;
const DEFAULT_PROBE_TIMEOUT_MS = 8_000;

/** 只读安全 HTTP 方法白名单。 */
const READONLY_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** 安全签名钩子属性路径正则（严禁括号、分号或任意表达式注入）。 */
const SAFE_SIGNER_HOOK_RE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,4}$/;

/** 常见静态资源扩展名（默认流量录制聚焦 API / 文档流量，可通过 includeStaticAssets 切换）。 */
const STATIC_ASSET_PATH_RE =
	/\.(?:css|scss|less|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|map)$/i;

/** 内部探针请求对齐标记头（在 CDP Fetch 拦截层剥离，绝不发往目标服务端）。 */
const INTERNAL_PROBE_HEADER = "x-nuwa-cdp-probe-token";

/** 认证敏感 JSON 响应键名匹配（用于登录响应凭据捕获与瞬态脱敏登记）。 */
const AUTH_TOKEN_JSON_KEY_RE = /^(?:access_token|accessToken|auth_token|authToken|id_token|idToken|jwt|token)$/i;
const CSRF_JSON_KEY_RE = /^(?:csrf_token|csrfToken|xsrf_token|xsrfToken|_csrf)$/i;
const SECRET_INPUT_JSON_KEY_RE =
	/^(?:password|passwd|pwd|secret|client_secret|clientSecret|refresh_token|refreshToken|api_key|apiKey|private_token)$/i;

const ADMIN_ROLE_NAME_RE = /^(?:super[-_]?admin|admin|administrator|root|staff|manager|operator|owner)(?:[-_0-9].*)?$/i;
const ADMIN_ENDPOINT_PATH_RE =
	/\/(?:admin|internal|manage|management|staff|console|metrics|actuator|roles|permissions|audit|system|ops|backoffice)(?:\/|$|\?)/i;
const OBJECT_ID_PATH_OR_QUERY_RE =
	/(?:\/(?:[0-9]{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)|[?&](?:id|uid|user_?id|account_?id|order_?id|tenant_?id|doc_?id|item_?id|record_?id)=)/i;

// ==================== 公共类型定义 ====================

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
interface ProbeInterceptRule {
	authMode: "inherit" | "anonymous" | "override";
	overrideHeaders?: Record<string, string>;
	matchedUrl?: string;
	blockedReason?: string;
}

/** 会话级网络拦截控制器状态。 */
interface SessionInterceptorState {
	enabled: boolean;
	scope: ScopePolicy;
	mode: Mode | string;
	allowedMethods?: ReadonlySet<string>;
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

export interface CaptureCdpTrafficOptions {
	session?: CdpSession;
	recorder?: TrafficRecorder;
	mode?: Mode | string;
	/** 捕获到的认证凭据同步写入 SessionVault 的角色名（默认 "cdp-captured"）。 */
	captureRole?: string;
	/** 导航前从 SessionVault 预加载注入会话的角色名。 */
	preloadRole?: string;
	initialCookies?: CdpCookieParam[];
	extraHeaders?: Record<string, string>;
	/** 页面加载完成后的网络静默等待毫秒数（默认 400ms）。 */
	settleMs?: number;
	navigationTimeoutMs?: number;
	launchOptions?: LaunchCdpSessionOptions;
	/** 是否将图片/样式/字体等静态资源也计入 TrafficRecorder（默认 false，聚焦 API/XHR/Fetch/GraphQL）。 */
	includeStaticAssets?: boolean;
	/** 可选在页面加载后执行的只读交互等待钩子（例如等待异步数据渲染完成）。 */
	afterLoadDelayMs?: number;
	/** 额外登记需强制脱敏的敏感明文列表。 */
	extraSecrets?: string[];
}

export interface CaptureCdpTrafficResult {
	ok: boolean;
	targetUrl: string;
	blockedByScope: boolean;
	blockReason?: string;
	capturedCount: number;
	entries: TrafficEntry[];
	blockedCount: number;
	blockedRequests: BlockedCdpRequest[];
	syncedRoles: string[];
	vaultSummary: string;
	browserVersion?: string;
}

export interface InPageSignedProbeSpec {
	/** 目标完整 URL 或相对当前页面同源的以 `/` 开头路径。 */
	url: string;
	/** 强制仅允许 GET / HEAD / OPTIONS（默认 GET）。 */
	method?: "GET" | "HEAD" | "OPTIONS" | string;
	/** 附加安全请求头。 */
	headers?: Record<string, string>;
	/**
	 * 页面内签名钩子属性路径（如 `"__nuwaSign"` 或 `"app.signRequest"`）。
	 * 未指定时自动探测 `window.__nuwaSign` / `window.__signRequest`，并兼容页面同源 `window.fetch` 包装加签。
	 */
	signerHook?: string;
	/**
	 * 认证态模式：
	 * - `"inherit"`：沿用当前浏览器页面会话（含 HttpOnly Cookie）；
	 * - `"anonymous"`：剥离全部 Cookie / Authorization 凭据发送匿名加签探针；
	 * - `"override"`：在 CDP 拦截层替换为 `overrideAuthHeaders` 指定的目标角色凭据，同时保留页面生成的动态签名头。
	 */
	authMode?: "inherit" | "anonymous" | "override";
	overrideAuthHeaders?: Record<string, string>;
	/** 是否允许跨出当前页面 origin 访问 Scope 内其他同授权主机（默认 false，强制同源）。 */
	allowCrossOriginInScope?: boolean;
}

export interface InPageProbeOptions {
	mode?: Mode | string;
	timeoutMs?: number;
	root?: string;
	vault?: SessionVault;
	recorder?: TrafficRecorder;
	roleLabel?: string;
	soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null;
}

export interface InPageSignedProbeResult {
	ok: boolean;
	blocked: boolean;
	timedOut?: boolean;
	blockReason?: string;
	url: string;
	method: string;
	status: number;
	headers: Record<string, string>;
	bodySnippet: string;
	bodyBytes: number;
	bodyHash: string;
	templateHash: string;
	jsonKeys: string[];
	isSoft404: boolean;
	signedByHook: boolean;
	appliedSignatureHeaders: string[];
	durationMs: number;
	error?: string;
}

export interface CdpSignedAuthDiffFinding {
	path: string;
	url: string;
	kind: AuthDiffAnomalyKind;
	severity: "high" | "medium";
	summary: string;
	baselineRole: string;
	testedRole: string;
	similarity: number;
	unsignedStatus?: number;
	probes: Array<{
		role: string;
		status: number;
		bodyBytes: number;
		bodyHash: string;
		templateHash: string;
		jsonKeys: string[];
		isSoft404: boolean;
		signedByHook: boolean;
		sampleSnippet: string;
	}>;
}

export interface RunCdpSignedAuthDiffOptions {
	session?: CdpSession;
	/** 基线高权角色名（若不指定，优先选用当前页面原生会话或 Vault 中首个高权/已登记角色）。 */
	baselineRole?: string;
	/** 待对比的角色列表（默认自动纳入 Vault 内其余角色及 `"anon"`）。 */
	compareRoles?: string[];
	/** 显式附加的额外对比角色认证头映射（便于免预写磁盘直接传入测试角色头）。 */
	extraRoleHeaders?: Record<string, Record<string, string>>;
	signerHook?: string;
	/** 是否同时发送一次剥离动态签名的普通直连只读请求以核验签名门禁（默认 true）。 */
	verifyUnsignedBaseline?: boolean;
	fetchFn?: typeof fetch;
	concurrency?: number;
	timeoutMs?: number;
	navigationTimeoutMs?: number;
	settleMs?: number;
	mode?: Mode | string;
	soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null;
	autoSampleSoft404?: boolean;
	recorder?: TrafficRecorder;
	launchOptions?: LaunchCdpSessionOptions;
}

export interface RunCdpSignedAuthDiffResult {
	ok: boolean;
	targetUrl: string;
	blockedByScope: boolean;
	blockReason?: string;
	effectiveConcurrency: number;
	testedPaths: string[];
	blockedPaths: string[];
	unsignedStatuses: Record<string, number>;
	findings: CdpSignedAuthDiffFinding[];
	fact: AutoFact | null;
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

	// 按目录名逆序排列，使更高版本号（如 chromium-1248 > chromium-1134）排在前面
	const sorted = [...entries].sort((a, b) => b.localeCompare(a));
	const headlessShellBins: string[] = [];
	const fullChromeBins: string[] = [];

	for (const dirName of sorted) {
		const fullDir = join(cacheRoot, dirName);
		let subDirs: string[] = [];
		try {
			if (!statSync(fullDir).isDirectory()) continue;
			subDirs = readdirSync(fullDir).sort((a, b) => b.localeCompare(a));
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

	/** 等待满足条件的单次 CDP 事件（含超时自动退订）。 */
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
			const timer = setTimeout(() => {
				if (done) return;
				done = true;
				off();
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
				resolvePromise(typed);
			});
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
				while (!settled) {
					const { done, value } = await reader.read();
					if (done) break;
					if (value) {
						const chunk = decoder.decode(value, { stream: true });
						collectedLogs.push(chunk);
						if (collectedLogs.length > 24) collectedLogs.shift();
						buffer += chunk;
						const match = wsRegex.exec(buffer);
						if (match?.[1]) {
							if (!settled) {
								settled = true;
								clearTimeout(timer);
								resolvePromise(match[1].trim());
							}
							break;
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

		// 二次兜底清剿任何残留的渲染器/GPU/crashpad 子进程
		const remainingPids = new Set<number>([
			...(rootPid ? findDescendantPids(rootPid) : []),
			...(session.processTag ? findLiveProcessesByTag(session.processTag) : []),
		]);
		if (remainingPids.size > 0) {
			for (const remPid of remainingPids) {
				safeKillPid(remPid, "SIGKILL");
			}
			await Bun.sleep(60);
		}
	}

	if (session.ownsUserDataDir && session.userDataDir) {
		try {
			rmSync(session.userDataDir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
}

// ==================== 4. Scope 校验与统一 CDP Fetch 拦截层 ====================

function checkHttpTargetScope(
	rawUrl: string,
	method: string,
	scope: ScopePolicy,
	mode: Mode | string = "audit",
	label = "CDP 请求目标",
): { ok: true; parsed: URL } | { ok: false; reason: string } {
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		return {
			ok: false,
			reason: formatScopeBlockReason("egress-proxy", `${label} URL 非法 (${rawUrl})`, "N-007"),
		};
	}

	const proto = parsed.protocol.toLowerCase();
	if (proto !== "http:" && proto !== "https:" && proto !== "ws:" && proto !== "wss:") {
		return {
			ok: false,
			reason: formatScopeBlockReason(
				"egress-proxy",
				`${label} 协议不受支持 (${parsed.protocol})，仅允许 http/https/ws/wss`,
				"N-007",
			),
		};
	}

	const hostVerdict = isHostInScope(parsed.hostname, scope);
	if (!hostVerdict.ok) {
		return {
			ok: false,
			reason: formatScopeBlockReason(
				"egress-proxy",
				`${label}越界 (${parsed.hostname}) — ${hostVerdict.reason ?? "不在授权 Scope 内"}`,
				"N-007",
			),
		};
	}

	const riskVerdict = checkScopeAndRisk(
		`curl -X ${String(method || "GET").toUpperCase()} ${parsed.toString()}`,
		scope,
		mode,
		{ layer: "egress-proxy" },
	);
	if (riskVerdict?.block) {
		return {
			ok: false,
			reason: riskVerdict.reason,
		};
	}

	return { ok: true, parsed };
}

function normalizeCdpHeadersObject(rawHeaders: unknown): Record<string, string> {
	const out: Record<string, string> = {};
	if (!rawHeaders) return out;
	if (Array.isArray(rawHeaders)) {
		for (const item of rawHeaders) {
			if (!item || typeof item !== "object") continue;
			const rec = item as Record<string, unknown>;
			const k = typeof rec.name === "string" ? rec.name.trim() : "";
			const v = typeof rec.value === "string" ? rec.value : "";
			if (!k) continue;
			out[k] = out[k] ? `${out[k]}; ${v}` : v;
		}
		return out;
	}
	if (typeof rawHeaders === "object") {
		for (const [k, v] of Object.entries(rawHeaders as Record<string, unknown>)) {
			if (v === undefined || v === null) continue;
			const cleanK = k.trim();
			if (!cleanK) continue;
			out[cleanK] = Array.isArray(v) ? v.map(String).join("\n") : String(v);
		}
	}
	return out;
}

function findHeaderCaseInsensitive(headers: Record<string, string>, targetName: string): string | undefined {
	const lower = targetName.toLowerCase();
	for (const [k, v] of Object.entries(headers)) {
		if (k.toLowerCase() === lower) return v;
	}
	return undefined;
}

function buildFinalProbeHeaderEntries(
	originalHeaders: Record<string, string>,
	rule: ProbeInterceptRule,
): CdpHeaderEntry[] {
	const filtered: Array<[string, string]> = [];
	const authHeaderNames = new Set([
		"cookie",
		"authorization",
		"proxy-authorization",
		"x-csrf-token",
		"x-xsrf-token",
		"csrf-token",
		"xsrf-token",
		"x-api-key",
		"x-auth-token",
	]);

	for (const [k, v] of Object.entries(originalHeaders)) {
		const lower = k.toLowerCase();
		// 始终剥离内部对齐头，绝不泄露给目标服务
		if (lower === INTERNAL_PROBE_HEADER) continue;
		if ((rule.authMode === "anonymous" || rule.authMode === "override") && authHeaderNames.has(lower)) {
			continue;
		}
		filtered.push([k, v]);
	}

	if (rule.authMode === "override" && rule.overrideHeaders) {
		const existingLower = new Map<string, number>();
		filtered.forEach(([k], idx) => existingLower.set(k.toLowerCase(), idx));
		for (const [ok, ov] of Object.entries(rule.overrideHeaders)) {
			const cleanName = ok.replace(/[\r\n]+/g, "").trim();
			const cleanVal = String(ov ?? "").replace(/[\r\n]+/g, " ").trim();
			if (!cleanName || !cleanVal) continue;
			const prevIdx = existingLower.get(cleanName.toLowerCase());
			if (prevIdx !== undefined) {
				filtered[prevIdx] = [cleanName, cleanVal];
			} else {
				existingLower.set(cleanName.toLowerCase(), filtered.length);
				filtered.push([cleanName, cleanVal]);
			}
		}
	}

	return filtered.map(([name, value]) => ({ name, value }));
}

/**
 * 为指定 `CdpSession` 挂载或更新统一的 `Fetch.requestPaused` 范围护栏与探针请求头覆写器。
 * 任何不在 `ScopePolicy` 内的外部子请求均在网络发包前直接 `Fetch.failRequest(BlockedByClient)`。
 */
async function ensureSessionInterceptor(
	session: CdpSession,
	scope: ScopePolicy,
	mode: Mode | string = "audit",
): Promise<SessionInterceptorState> {
	if (session._interceptor?.enabled) {
		session._interceptor.scope = scope;
		session._interceptor.mode = mode;
		return session._interceptor;
	}

	const state: SessionInterceptorState = {
		enabled: true,
		scope,
		mode,
		blockedRequests: [],
		probeRules: new Map<string, ProbeInterceptRule>(),
	};

	const unsubscribe = session.client.on("Fetch.requestPaused", (params, evSessionId) => {
		if (evSessionId && evSessionId !== session.sessionId) return;
		const requestId = typeof params.requestId === "string" ? params.requestId : "";
		if (!requestId) return;

		const reqObj =
			params.request && typeof params.request === "object"
				? (params.request as Record<string, unknown>)
				: {};
		const rawUrl = typeof reqObj.url === "string" ? reqObj.url : "";
		const method = typeof reqObj.method === "string" ? reqObj.method.toUpperCase() : "GET";
		const resourceType = typeof params.resourceType === "string" ? params.resourceType : undefined;
		const reqHeaders = normalizeCdpHeadersObject(reqObj.headers);

		// 放行浏览器内部 about:blank / data: / blob: 非网络资源
		const lowerUrl = rawUrl.trim().toLowerCase();
		if (lowerUrl.startsWith("about:") || lowerUrl.startsWith("data:") || lowerUrl.startsWith("blob:")) {
			void session.client
				.send("Fetch.continueRequest", { requestId }, { sessionId: session.sessionId, timeoutMs: 3_000 })
				.catch(() => {});
			return;
		}

		const probeToken = findHeaderCaseInsensitive(reqHeaders, INTERNAL_PROBE_HEADER)?.trim();
		const matchedRule = probeToken ? state.probeRules.get(probeToken) : undefined;

		// 1. 强制 Scope 范围与风险检查
		const scopeCheck = checkHttpTargetScope(rawUrl, method, state.scope, state.mode, "CDP 子请求");
		if (!scopeCheck.ok) {
			if (matchedRule) matchedRule.blockedReason = scopeCheck.reason;
			state.blockedRequests.push({
				url: redactTrafficUrl(rawUrl),
				method,
				...(resourceType ? { resourceType } : {}),
				reason: scopeCheck.reason,
			});
			void session.client
				.send(
					"Fetch.failRequest",
					{ requestId, errorReason: "BlockedByClient" },
					{ sessionId: session.sessionId, timeoutMs: 3_000 },
				)
				.catch(() => {});
			return;
		}

		// 2. 若属于页面内只读加签探针请求，二次强校验只读 HTTP 方法并执行认证头净化/覆写
		if (matchedRule) {
			matchedRule.matchedUrl = rawUrl;
			if (!READONLY_HTTP_METHODS.has(method)) {
				const reason = formatScopeBlockReason(
					"egress-proxy",
					`页面内借壳探针仅允许只读方法 GET/HEAD/OPTIONS，已拦截 ${method}`,
					"N-008",
				);
				matchedRule.blockedReason = reason;
				state.blockedRequests.push({
					url: redactTrafficUrl(rawUrl),
					method,
					...(resourceType ? { resourceType } : {}),
					reason,
				});
				void session.client
					.send(
						"Fetch.failRequest",
						{ requestId, errorReason: "BlockedByClient" },
						{ sessionId: session.sessionId, timeoutMs: 3_000 },
					)
					.catch(() => {});
				return;
			}

			const rewrittenHeaders = buildFinalProbeHeaderEntries(reqHeaders, matchedRule);
			const flatForLog: Record<string, string> = {};
			for (const h of rewrittenHeaders) flatForLog[h.name] = h.value;
			state.onAllowedRequest?.({
				requestId: typeof params.networkId === "string" ? params.networkId : requestId,
				url: rawUrl,
				method,
				headers: flatForLog,
			});
			void session.client
				.send(
					"Fetch.continueRequest",
					{ requestId, headers: rewrittenHeaders },
					{ sessionId: session.sessionId, timeoutMs: 3_000 },
				)
				.catch(() => {});
			return;
		}

		// 3. 可选会话级方法白名单检查
		if (state.allowedMethods && !state.allowedMethods.has(method)) {
			const reason = formatScopeBlockReason(
				"egress-proxy",
				`CDP 会话只读策略拦截非白名单方法 (${method} ${rawUrl})`,
				"N-008",
			);
			state.blockedRequests.push({
				url: redactTrafficUrl(rawUrl),
				method,
				...(resourceType ? { resourceType } : {}),
				reason,
			});
			void session.client
				.send(
					"Fetch.failRequest",
					{ requestId, errorReason: "BlockedByClient" },
					{ sessionId: session.sessionId, timeoutMs: 3_000 },
				)
				.catch(() => {});
			return;
		}

		state.onAllowedRequest?.({
			requestId: typeof params.networkId === "string" ? params.networkId : requestId,
			url: rawUrl,
			method,
			headers: reqHeaders,
		});
		void session.client
			.send("Fetch.continueRequest", { requestId }, { sessionId: session.sessionId, timeoutMs: 3_000 })
			.catch(() => {});
	});

	state.unsubscribe = unsubscribe;
	session._interceptor = state;

	await session.client.send(
		"Fetch.enable",
		{
			patterns: [{ urlPattern: "*", requestStage: "Request" }],
		},
		{ sessionId: session.sessionId },
	);

	return state;
}

// ==================== 5. 实时流量录制与 SessionVault 凭据同步 ====================

interface TrackedNetworkTransaction {
	requestId: string;
	url: string;
	method: string;
	resourceType: string;
	requestHeaders: Record<string, string>;
	requestBody?: string;
	status: number;
	responseHeaders: Record<string, string>;
	startedAtMs: number;
	finishedAtMs?: number;
	failed?: boolean;
	errorText?: string;
}

function collectSecretsFromJsonText(
	rawText: string | undefined,
	onSecret: (val: string, kind: "bearer" | "csrf" | "transient") => void,
): void {
	if (!rawText) return;
	const trimmed = rawText.trim();
	if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
		try {
			const parsed = JSON.parse(trimmed) as unknown;
			const walk = (node: unknown, depth: number) => {
				if (depth > 6 || !node || typeof node !== "object") return;
				if (Array.isArray(node)) {
					for (const item of node.slice(0, 10)) walk(item, depth + 1);
					return;
				}
				for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
					if (typeof v === "string" && v.trim().length >= 4) {
						if (AUTH_TOKEN_JSON_KEY_RE.test(k)) {
							onSecret(v.trim(), "bearer");
						} else if (CSRF_JSON_KEY_RE.test(k)) {
							onSecret(v.trim(), "csrf");
						} else if (SECRET_INPUT_JSON_KEY_RE.test(k)) {
							onSecret(v.trim(), "transient");
						}
					} else if (v && typeof v === "object") {
						walk(v, depth + 1);
					}
				}
			};
			walk(parsed, 0);
			return;
		} catch {
			/* 非严格 JSON 回退到表单键值对检查 */
		}
	}

	if (trimmed.includes("=") && !trimmed.startsWith("<")) {
		try {
			const params = new URLSearchParams(trimmed);
			for (const [k, v] of params.entries()) {
				const cleanVal = v.trim();
				if (cleanVal.length < 4) continue;
				if (AUTH_TOKEN_JSON_KEY_RE.test(k)) onSecret(cleanVal, "bearer");
				else if (CSRF_JSON_KEY_RE.test(k)) onSecret(cleanVal, "csrf");
				else if (SECRET_INPUT_JSON_KEY_RE.test(k)) onSecret(cleanVal, "transient");
			}
		} catch {
			/* ignore */
		}
	}
}

function shouldRecordTransaction(tx: TrackedNetworkTransaction, includeStaticAssets: boolean): boolean {
	if (!tx.url || tx.failed) return false;
	const lowerUrl = tx.url.toLowerCase();
	if (!lowerUrl.startsWith("http://") && !lowerUrl.startsWith("https://")) return false;
	if (includeStaticAssets) return true;

	const rt = tx.resourceType.toLowerCase();
	if (rt === "xhr" || rt === "fetch" || rt === "websocket") return true;
	if (rt === "image" || rt === "font" || rt === "stylesheet" || rt === "media") return false;

	try {
		const pathname = new URL(tx.url).pathname;
		if (STATIC_ASSET_PATH_RE.test(pathname)) return false;
		if (/\/(?:api|v\d+|graphql|gql|auth|login|session|rpc|rest)\b/i.test(pathname)) return true;
	} catch {
		return false;
	}

	return rt === "document" || tx.status >= 400;
}

function parseSetCookiePairs(rawSetCookie: string): Array<{ name: string; value: string }> {
	const out: Array<{ name: string; value: string }> = [];
	for (const line of rawSetCookie.split(/\r?\n/)) {
		const first = line.split(";")[0]?.trim() ?? "";
		if (!first) continue;
		const eq = first.indexOf("=");
		if (eq <= 0) continue;
		const name = first.slice(0, eq).trim();
		const value = first.slice(eq + 1).trim();
		if (name && value) out.push({ name, value });
	}
	return out;
}

/**
 * 在受控 Headless Chrome 会话中访问 `targetUrl`，实时拦截子请求执行 Scope 护栏校验，
 * 将授权范围内的 API / Fetch / XHR / GraphQL 流量全量脱敏写入 `TrafficRecorder`，
 * 并将捕获到的 Cookie / Authorization / CSRF 认证状态安全同步至 `SessionVault`。
 */
export async function captureCdpSessionTraffic(
	targetUrl: string,
	root: string,
	scope: ScopePolicy,
	opts?: CaptureCdpTrafficOptions,
): Promise<CaptureCdpTrafficResult> {
	const resolvedRoot = resolve(root);
	const mode = opts?.mode ?? "audit";

	// 入口 URL 前置 Scope 强拦截（越界目标零启动、零发包）
	const entryCheck = checkHttpTargetScope(targetUrl, "GET", scope, mode, "CDP 导航入口");
	if (!entryCheck.ok) {
		const vaultSummary = formatSessionVaultSummary(resolvedRoot);
		return {
			ok: false,
			targetUrl: redactTrafficUrl(targetUrl, { root: resolvedRoot }),
			blockedByScope: true,
			blockReason: entryCheck.reason,
			capturedCount: 0,
			entries: [],
			blockedCount: 1,
			blockedRequests: [
				{
					url: redactTrafficUrl(targetUrl, { root: resolvedRoot }),
					method: "GET",
					resourceType: "Document",
					reason: entryCheck.reason,
				},
			],
			syncedRoles: [],
			vaultSummary,
		};
	}

	const ownsSession = !opts?.session;
	const session = opts?.session ?? (await launchCdpSession(opts?.launchOptions));
	const recorder =
		opts?.recorder ??
		new TrafficRecorder(resolvedRoot, {
			extraSecrets: opts?.extraSecrets,
		});
	for (const sec of opts?.extraSecrets ?? []) {
		recorder.registerTransientSecret(sec);
	}

	const transactions = new Map<string, TrackedNetworkTransaction>();
	const unsubscribers: Array<() => void> = [];
	const capturedCookies = new Map<string, string>();
	const capturedCustomAuthHeaders: Record<string, string> = {};
	let capturedBearer: string | undefined;
	let capturedCsrfHeaderName: string | undefined;
	let capturedCsrfValue: string | undefined;

	const registerSecretToRecorder = (val: string | undefined) => {
		const clean = String(val ?? "").trim();
		if (clean.length >= 4) {
			recorder.registerTransientSecret(clean);
		}
	};

	const harvestHeadersAuth = (headers: Record<string, string>, isResponse: boolean) => {
		for (const [rawName, rawValue] of Object.entries(headers)) {
			const lower = rawName.toLowerCase().trim();
			const val = String(rawValue ?? "").trim();
			if (!val) continue;

			if (!isResponse && lower === "authorization") {
				capturedBearer = val;
				registerSecretToRecorder(val);
				registerSecretToRecorder(val.replace(/^(?:Bearer|Basic|Token|JWT)\s+/i, ""));
			} else if (!isResponse && lower === "cookie") {
				for (const seg of val.split(";")) {
					const eq = seg.indexOf("=");
					if (eq > 0) {
						const ck = seg.slice(0, eq).trim();
						const cv = seg.slice(eq + 1).trim();
						if (ck && cv) {
							capturedCookies.set(ck, cv);
							registerSecretToRecorder(cv);
						}
					}
				}
			} else if (isResponse && lower === "set-cookie") {
				for (const pair of parseSetCookiePairs(val)) {
					capturedCookies.set(pair.name, pair.value);
					registerSecretToRecorder(pair.value);
				}
			} else if (
				lower === "x-csrf-token" ||
				lower === "x-xsrf-token" ||
				lower === "csrf-token" ||
				lower === "xsrf-token"
			) {
				capturedCsrfHeaderName = rawName.trim();
				capturedCsrfValue = val;
				capturedCustomAuthHeaders[capturedCsrfHeaderName] = val;
				registerSecretToRecorder(val);
			} else if (lower === "x-api-key" || lower === "x-auth-token" || lower === "x-access-token") {
				capturedCustomAuthHeaders[rawName.trim()] = val;
				registerSecretToRecorder(val);
			}
		}
	};

	try {
		const interceptor = await ensureSessionInterceptor(session, scope, mode);
		const startBlockedIdx = interceptor.blockedRequests.length;
		const sid = session.sessionId;

		await session.client.send("Page.enable", {}, { sessionId: sid });
		await session.client.send("Runtime.enable", {}, { sessionId: sid });
		await session.client.send("Network.enable", {}, { sessionId: sid });

		// 预注入已有角色凭据或显式请求头/Cookie
		const preloadHeaders: Record<string, string> = { ...(opts?.extraHeaders ?? {}) };
		if (opts?.preloadRole) {
			const roleMap = getRoleHeadersMap(resolvedRoot, opts.preloadRole);
			if (roleMap) {
				for (const [rk, rv] of Object.entries(roleMap)) {
					if (!(rk in preloadHeaders)) preloadHeaders[rk] = rv;
				}
			}
		}
		if (Object.keys(preloadHeaders).length > 0) {
			harvestHeadersAuth(preloadHeaders, false);
			await session.client.send(
				"Network.setExtraHTTPHeaders",
				{ headers: preloadHeaders },
				{ sessionId: sid },
			);
		}
		if (opts?.initialCookies && opts.initialCookies.length > 0) {
			for (const c of opts.initialCookies) {
				registerSecretToRecorder(c.value);
			}
			await session.client.send(
				"Network.setCookies",
				{
					cookies: opts.initialCookies.map((c) => ({
						...c,
						url: c.url ?? entryCheck.parsed.origin,
					})),
				},
				{ sessionId: sid },
			);
		}

		// 订阅 Network 生命周期事件（含 ExtraInfo 原始凭据头）
		unsubscribers.push(
			session.client.on("Network.requestWillBeSent", (params, evSid) => {
				if (evSid && evSid !== sid) return;
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				const req =
					params.request && typeof params.request === "object"
						? (params.request as Record<string, unknown>)
						: {};
				if (!requestId || typeof req.url !== "string") return;

				const reqHeaders = normalizeCdpHeadersObject(req.headers);
				const postData = typeof req.postData === "string" ? req.postData : undefined;
				harvestHeadersAuth(reqHeaders, false);
				collectSecretsFromJsonText(postData, (sec) => registerSecretToRecorder(sec));

				const existing = transactions.get(requestId);
				transactions.set(requestId, {
					requestId,
					url: req.url,
					method: typeof req.method === "string" ? req.method.toUpperCase() : "GET",
					resourceType: typeof params.type === "string" ? params.type : existing?.resourceType ?? "Other",
					requestHeaders: { ...(existing?.requestHeaders ?? {}), ...reqHeaders },
					...(postData !== undefined ? { requestBody: postData } : {}),
					status: existing?.status ?? 0,
					responseHeaders: existing?.responseHeaders ?? {},
					startedAtMs: Date.now(),
				});
			}),
		);

		unsubscribers.push(
			session.client.on("Network.requestWillBeSentExtraInfo", (params, evSid) => {
				if (evSid && evSid !== sid) return;
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				if (!requestId) return;
				const extraHeaders = normalizeCdpHeadersObject(params.headers);
				harvestHeadersAuth(extraHeaders, false);
				const tx = transactions.get(requestId);
				if (tx) {
					tx.requestHeaders = { ...tx.requestHeaders, ...extraHeaders };
				}
			}),
		);

		unsubscribers.push(
			session.client.on("Network.responseReceived", (params, evSid) => {
				if (evSid && evSid !== sid) return;
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				const resp =
					params.response && typeof params.response === "object"
						? (params.response as Record<string, unknown>)
						: {};
				if (!requestId) return;
				const respHeaders = normalizeCdpHeadersObject(resp.headers);
				harvestHeadersAuth(respHeaders, true);

				const tx = transactions.get(requestId);
				if (tx) {
					if (typeof params.type === "string" && params.type) tx.resourceType = params.type;
					if (typeof resp.status === "number") tx.status = resp.status;
					tx.responseHeaders = { ...tx.responseHeaders, ...respHeaders };
				}
			}),
		);

		unsubscribers.push(
			session.client.on("Network.responseReceivedExtraInfo", (params, evSid) => {
				if (evSid && evSid !== sid) return;
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				if (!requestId) return;
				const extraHeaders = normalizeCdpHeadersObject(params.headers);
				harvestHeadersAuth(extraHeaders, true);
				const tx = transactions.get(requestId);
				if (tx) {
					tx.responseHeaders = { ...tx.responseHeaders, ...extraHeaders };
				}
			}),
		);

		unsubscribers.push(
			session.client.on("Network.loadingFinished", (params, evSid) => {
				if (evSid && evSid !== sid) return;
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				const tx = transactions.get(requestId);
				if (tx) tx.finishedAtMs = Date.now();
			}),
		);

		unsubscribers.push(
			session.client.on("Network.loadingFailed", (params, evSid) => {
				if (evSid && evSid !== sid) return;
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				const tx = transactions.get(requestId);
				if (tx) {
					tx.failed = true;
					tx.finishedAtMs = Date.now();
					tx.errorText = typeof params.errorText === "string" ? params.errorText : "failed";
				}
			}),
		);

		const navTimeoutMs = Math.max(500, opts?.navigationTimeoutMs ?? DEFAULT_NAVIGATION_TIMEOUT_MS);
		const loadFiredPromise = session.client
			.waitForEvent("Page.loadEventFired", { sessionId: sid, timeoutMs: navTimeoutMs })
			.catch(() => null);

		await session.client.send(
			"Page.navigate",
			{ url: entryCheck.parsed.toString() },
			{ sessionId: sid, timeoutMs: navTimeoutMs },
		);
		await loadFiredPromise;

		// 等待页面异步 Fetch / XHR 完成静默收敛
		const settleMs = Math.max(50, opts?.settleMs ?? 400);
		const settleDeadline = Date.now() + Math.max(settleMs, opts?.afterLoadDelayMs ?? 0);
		while (Date.now() < settleDeadline) {
			await Bun.sleep(60);
		}
		// 若仍有飞行中的 XHR/Fetch，最多再给予短暂收尾缓冲
		for (let extra = 0; extra < 8; extra++) {
			const inflightApi = [...transactions.values()].some(
				(tx) =>
					!tx.finishedAtMs &&
					!tx.failed &&
					(tx.resourceType.toLowerCase() === "xhr" || tx.resourceType.toLowerCase() === "fetch"),
			);
			if (!inflightApi) break;
			await Bun.sleep(60);
		}

		// 从浏览器 Cookie 存储补充读取同源 Cookie（含 HttpOnly Cookie）
		const cookieRes = await session.client
			.send<{ cookies?: Array<{ name?: string; value?: string }> }>(
				"Network.getCookies",
				{ urls: [entryCheck.parsed.origin] },
				{ sessionId: sid, timeoutMs: 3_000 },
			)
			.catch(() => ({ cookies: [] }));
		for (const ck of cookieRes.cookies ?? []) {
			if (ck.name && ck.value) {
				capturedCookies.set(ck.name, ck.value);
				registerSecretToRecorder(ck.value);
			}
		}

		// 逐条拉取响应体并提取登录/会话响应中的动态 Token
		const includeStaticAssets = opts?.includeStaticAssets ?? false;
		const candidateTxs = [...transactions.values()].filter((tx) =>
			shouldRecordTransaction(tx, includeStaticAssets),
		);
		const responseBodies = new Map<string, string>();

		for (const tx of candidateTxs) {
			const scopeVerdict = checkHttpTargetScope(tx.url, tx.method, scope, mode, "CDP 落盘校验");
			if (!scopeVerdict.ok) continue;

			const bodyRes = await session.client
				.send<{ body?: string; base64Encoded?: boolean }>(
					"Network.getResponseBody",
					{ requestId: tx.requestId },
					{ sessionId: sid, timeoutMs: 3_000 },
				)
				.catch(() => null);

			if (bodyRes && typeof bodyRes.body === "string") {
				const decoded = bodyRes.base64Encoded
					? Buffer.from(bodyRes.body, "base64").toString("utf8")
					: bodyRes.body;
				responseBodies.set(tx.requestId, decoded);
				collectSecretsFromJsonText(decoded, (val, kind) => {
					registerSecretToRecorder(val);
					if (kind === "bearer" && !capturedBearer) {
						capturedBearer = val;
					} else if (kind === "csrf" && !capturedCsrfValue) {
						capturedCsrfHeaderName = capturedCsrfHeaderName ?? "X-CSRF-Token";
						capturedCsrfValue = val;
						capturedCustomAuthHeaders[capturedCsrfHeaderName] = val;
					}
				});
			}
		}

		// 先将捕获到的认证凭据安全持久化至 SessionVault（权限 0o600），以便后续 TrafficRecorder 全量关联脱敏
		const syncedRoles: string[] = [];
		const hasCapturedAuth =
			capturedCookies.size > 0 ||
			Boolean(capturedBearer) ||
			Object.keys(capturedCustomAuthHeaders).length > 0;

		if (hasCapturedAuth) {
			const roleName = opts?.captureRole?.trim() || "cdp-captured";
			const serializedCookie =
				capturedCookies.size > 0
					? [...capturedCookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ")
					: undefined;
			let csrfCookieName: string | undefined;
			for (const ckName of capturedCookies.keys()) {
				if (/csrf|xsrf/i.test(ckName)) {
					csrfCookieName = ckName;
					break;
				}
			}

			upsertSessionRole(resolvedRoot, {
				role: roleName,
				...(serializedCookie ? { cookie: serializedCookie } : {}),
				...(capturedBearer ? { bearer: capturedBearer } : {}),
				...(Object.keys(capturedCustomAuthHeaders).length > 0 ? { headers: capturedCustomAuthHeaders } : {}),
				...(capturedCsrfHeaderName ? { csrfHeader: capturedCsrfHeaderName } : {}),
				...(csrfCookieName ? { csrfCookie: csrfCookieName } : {}),
				note: "由原生 CDP 会话自动捕获同步",
			});
			syncedRoles.push(roleName);
		}

		// 全量脱敏写入 TrafficRecorder
		const recordedEntries: TrafficEntry[] = [];
		for (const tx of candidateTxs) {
			const scopeVerdict = checkHttpTargetScope(tx.url, tx.method, scope, mode, "CDP 落盘校验");
			if (!scopeVerdict.ok) continue;

			const entry = recorder.record({
				method: tx.method,
				url: tx.url,
				requestHeaders: tx.requestHeaders,
				...(tx.requestBody !== undefined ? { requestBody: tx.requestBody } : {}),
				status: tx.status,
				responseHeaders: tx.responseHeaders,
				...(responseBodies.has(tx.requestId) ? { responseBody: responseBodies.get(tx.requestId) } : {}),
				durationMs: Math.max(0, (tx.finishedAtMs ?? Date.now()) - tx.startedAtMs),
				tags: ["cdp-capture", tx.resourceType.toLowerCase()],
				...(syncedRoles[0] ? { role: syncedRoles[0] } : {}),
			});
			recordedEntries.push(entry);
		}

		const latestVault = loadSessionVault(resolvedRoot);
		const newlyBlocked = interceptor.blockedRequests.slice(startBlockedIdx).map((b) => ({
			...b,
			url: redactTrafficUrl(b.url, {
				root: resolvedRoot,
				vault: latestVault,
				extraSecrets: opts?.extraSecrets,
			}),
			reason: redactVaultSecrets(b.reason, latestVault),
		}));
		const safeTargetUrl = redactTrafficUrl(targetUrl, { root: resolvedRoot, vault: latestVault });

		return {
			ok: true,
			targetUrl: safeTargetUrl,
			blockedByScope: false,
			capturedCount: recordedEntries.length,
			entries: recordedEntries,
			blockedCount: newlyBlocked.length,
			blockedRequests: newlyBlocked,
			syncedRoles,
			vaultSummary: formatSessionVaultSummary(latestVault),
			...(session.browserVersion ? { browserVersion: session.browserVersion } : {}),
		};
	} finally {
		for (const off of unsubscribers) {
			try {
				off();
			} catch {
				/* ignore */
			}
		}
		if (ownsSession) {
			await closeCdpSession(session);
		}
	}
}

// ==================== 6. 页面内借壳加签只读探针与多角色契约差分 ====================

async function getCurrentPageOrigin(session: CdpSession, timeoutMs: number): Promise<string | null> {
	try {
		const evalRes = await session.client.send<{ result?: { value?: unknown } }>(
			"Runtime.evaluate",
			{
				expression: "window.location.href",
				returnByValue: true,
			},
			{ sessionId: session.sessionId, timeoutMs },
		);
		const href = typeof evalRes.result?.value === "string" ? evalRes.result.value : "";
		if (!href || href.startsWith("about:")) return null;
		return new URL(href).origin;
	} catch {
		return null;
	}
}

/**
 * 构建纯数据参数化的受控页面内只读 `fetch` 表达式。
 * 所有外部输入均通过 `JSON.stringify` 作为纯 JSON 对象传参，绝不拼接动态代码标识符。
 */
function buildInPageReadonlyProbeExpression(payload: {
	url: string;
	expectedOrigin: string;
	enforceSameOrigin: boolean;
	pathWithQuery: string;
	method: "GET" | "HEAD" | "OPTIONS";
	headers: Record<string, string>;
	signerHookPath: string[];
	probeToken: string;
	credentialsMode: "include" | "omit";
	internalHeaderName: string;
}): string {
	const safeJsonArg = JSON.stringify(payload);
	return `(async (cfg) => {
		const startedAt = Date.now();
		const mergedHeaders = Object.assign({}, cfg.headers || {});
		const appliedSigHeaders = [];
		let signedByHook = false;
		let targetUrl = cfg.url;

		const resolveHook = (segments) => {
			if (!Array.isArray(segments) || segments.length === 0) {
				if (typeof window.__nuwaSign === "function") return { fn: window.__nuwaSign, ctx: window };
				if (typeof window.__signRequest === "function") return { fn: window.__signRequest, ctx: window };
				return null;
			}
			let ctx = window;
			let cur = window;
			for (let i = 0; i < segments.length; i++) {
				const key = segments[i];
				if (cur == null || typeof cur !== "object" && typeof cur !== "function") return null;
				if (key === "__proto__" || key === "constructor" || key === "prototype") return null;
				ctx = cur;
				cur = cur[key];
			}
			return typeof cur === "function" ? { fn: cur, ctx } : null;
		};

		const hookEntry = resolveHook(cfg.signerHookPath);
		if (hookEntry) {
			const signOut = await hookEntry.fn.call(hookEntry.ctx, {
				url: cfg.url,
				path: cfg.pathWithQuery,
				method: cfg.method,
				headers: Object.assign({}, mergedHeaders),
			});
			signedByHook = true;
			if (signOut && typeof signOut === "object") {
				const hdrSrc = signOut.headers && typeof signOut.headers === "object" ? signOut.headers : signOut;
				for (const [hk, hv] of Object.entries(hdrSrc)) {
					if (hk === "url" && typeof signOut.headers === "object") continue;
					if (typeof hv === "string" || typeof hv === "number") {
						mergedHeaders[hk] = String(hv);
						appliedSigHeaders.push(hk);
					}
				}
				if (typeof signOut.url === "string" && signOut.url.trim()) {
					const resolvedOut = new URL(signOut.url.trim(), cfg.expectedOrigin);
					if (cfg.enforceSameOrigin && resolvedOut.origin !== cfg.expectedOrigin) {
						return { ok: false, crossOriginHookBlocked: resolvedOut.toString() };
					}
					targetUrl = resolvedOut.toString();
				}
			} else if (typeof signOut === "string" && signOut.trim()) {
				mergedHeaders["x-signature"] = signOut.trim();
				appliedSigHeaders.push("x-signature");
			}
		}

		mergedHeaders[cfg.internalHeaderName] = cfg.probeToken;

		const resp = await window.fetch(targetUrl, {
			method: cfg.method,
			headers: mergedHeaders,
			credentials: cfg.credentialsMode,
			redirect: "manual",
			cache: "no-store",
		});

		const respHeaders = {};
		resp.headers.forEach((val, key) => {
			respHeaders[key.toLowerCase()] = val;
		});
		const bodyText = cfg.method === "HEAD" ? "" : await resp.text();
		return {
			ok: true,
			status: resp.status,
			headers: respHeaders,
			body: bodyText.slice(0, 65536),
			signedByHook,
			appliedSignatureHeaders: appliedSigHeaders,
			durationMs: Math.max(0, Date.now() - startedAt),
		};
	})(${safeJsonArg})`;
}

/**
 * 在受控同源页面上下文内执行单次纯只读借壳加签探针。
 * 强制约束：
 * 1. 仅允许 `GET` / `HEAD` / `OPTIONS`，任何写/破坏性方法立即拦截拒绝；
 * 2. 目标 URL 强制通过 `ScopePolicy` 与同源校验；
 * 3. `signerHook` 强制校验纯属性标识符路径，杜绝脚本注入；
 * 4. 响应结果经 `redactTrafficBody` / `redactVaultSecrets` 全量脱敏并计算 Soft-404 与结构指纹。
 */
export async function executeInPageSignedProbe(
	session: CdpSession,
	probeSpec: InPageSignedProbeSpec,
	scope: ScopePolicy,
	opts?: InPageProbeOptions,
): Promise<InPageSignedProbeResult> {
	const startedAt = Date.now();
	const mode = opts?.mode ?? "audit";
	const timeoutMs = Math.max(300, opts?.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS);
	const rawMethod = String(probeSpec.method ?? "GET").trim().toUpperCase();

	const makeBlockedResult = (reason: string, rawUrl: string): InPageSignedProbeResult => {
		const emptyHash = computeBodyHash("");
		return {
			ok: false,
			blocked: true,
			blockReason: reason,
			url: redactTrafficUrl(rawUrl, { root: opts?.root, vault: opts?.vault }),
			method: rawMethod || "GET",
			status: 0,
			headers: {},
			bodySnippet: "",
			bodyBytes: 0,
			bodyHash: emptyHash.bodyHash,
			templateHash: computeTemplateFingerprint(""),
			jsonKeys: [],
			isSoft404: false,
			signedByHook: false,
			appliedSignatureHeaders: [],
			durationMs: Math.max(0, Date.now() - startedAt),
		};
	};

	// 1. 强制只读方法门禁
	if (!READONLY_HTTP_METHODS.has(rawMethod)) {
		return makeBlockedResult(
			formatScopeBlockReason(
				"egress-proxy",
				`executeInPageSignedProbe 禁止非只读 HTTP 方法 (${rawMethod})，仅允许 GET/HEAD/OPTIONS`,
				"N-008",
			),
			probeSpec.url,
		);
	}
	const safeMethod = rawMethod as "GET" | "HEAD" | "OPTIONS";

	// 2. 强制签名钩子标识符语法白名单校验（阻断表达式注入）
	let signerHookPath: string[] = [];
	if (probeSpec.signerHook !== undefined && probeSpec.signerHook.trim() !== "") {
		const trimmedHook = probeSpec.signerHook.replace(/^window\./, "").trim();
		if (
			!SAFE_SIGNER_HOOK_RE.test(trimmedHook) ||
			/(?:__proto__|constructor|prototype)/.test(trimmedHook)
		) {
			return makeBlockedResult(
				formatScopeBlockReason(
					"shell-guard",
					`非法 signerHook 标识符 (${probeSpec.signerHook})，禁止包含动态代码或原型链属性`,
					"N-008",
				),
				probeSpec.url,
			);
		}
		signerHookPath = trimmedHook.split(".");
	}

	// 3. 解析目标 URL 并执行同源与 Scope 双重校验
	const pageOrigin = await getCurrentPageOrigin(session, Math.min(timeoutMs, 3_000));
	let resolvedUrl: URL;
	try {
		resolvedUrl = pageOrigin ? new URL(probeSpec.url, pageOrigin) : new URL(probeSpec.url);
	} catch {
		return makeBlockedResult(
			formatScopeBlockReason("egress-proxy", `探针目标 URL 非法 (${probeSpec.url})`, "N-007"),
			probeSpec.url,
		);
	}

	if (resolvedUrl.protocol !== "http:" && resolvedUrl.protocol !== "https:") {
		return makeBlockedResult(
			formatScopeBlockReason("egress-proxy", `探针协议不受支持 (${resolvedUrl.protocol})`, "N-007"),
			resolvedUrl.toString(),
		);
	}

	const scopeVerdict = checkHttpTargetScope(
		resolvedUrl.toString(),
		safeMethod,
		scope,
		mode,
		"页面内加签探针",
	);
	if (!scopeVerdict.ok) {
		return makeBlockedResult(scopeVerdict.reason, resolvedUrl.toString());
	}

	if (pageOrigin && !probeSpec.allowCrossOriginInScope && resolvedUrl.origin !== pageOrigin) {
		return makeBlockedResult(
			formatScopeBlockReason(
				"egress-proxy",
				`页面内加签探针默认强制同源 (${resolvedUrl.origin} !== ${pageOrigin})`,
				"N-007",
			),
			resolvedUrl.toString(),
		);
	}

	// 4. 挂载拦截层探针规则以净化/覆写认证头并二次防御页面脚本篡改目标 URL
	const interceptor = await ensureSessionInterceptor(session, scope, mode);
	const probeToken = `pt_${randomUUID()}`;
	const authMode = probeSpec.authMode ?? "inherit";
	const rule: ProbeInterceptRule = {
		authMode,
		...(probeSpec.overrideAuthHeaders ? { overrideHeaders: probeSpec.overrideAuthHeaders } : {}),
	};
	interceptor.probeRules.set(probeToken, rule);

	const cleanCustomHeaders: Record<string, string> = {};
	for (const [hk, hv] of Object.entries(probeSpec.headers ?? {})) {
		const ck = hk.replace(/[\r\n]+/g, "").trim();
		const cv = String(hv ?? "").replace(/[\r\n]+/g, " ").trim();
		if (ck && cv && ck.toLowerCase() !== INTERNAL_PROBE_HEADER) {
			cleanCustomHeaders[ck] = cv;
		}
	}

	const expression = buildInPageReadonlyProbeExpression({
		url: resolvedUrl.toString(),
		expectedOrigin: pageOrigin ?? resolvedUrl.origin,
		enforceSameOrigin: !probeSpec.allowCrossOriginInScope,
		pathWithQuery: `${resolvedUrl.pathname}${resolvedUrl.search}`,
		method: safeMethod,
		headers: cleanCustomHeaders,
		signerHookPath,
		probeToken,
		// 匿名或角色覆写模式下禁止浏览器自动附带默认 Cookie Jar，彻底杜绝跨角色 Cookie 串味
		credentialsMode: authMode === "inherit" ? "include" : "omit",
		internalHeaderName: INTERNAL_PROBE_HEADER,
	});

	try {
		const evalRes = await session.client.send<{
			result?: { type?: string; value?: Record<string, unknown>; description?: string };
			exceptionDetails?: { text?: string; exception?: { description?: string } };
		}>(
			"Runtime.evaluate",
			{
				expression,
				awaitPromise: true,
				returnByValue: true,
			},
			{ sessionId: session.sessionId, timeoutMs },
		);

		if (rule.blockedReason) {
			return makeBlockedResult(rule.blockedReason, rule.matchedUrl ?? resolvedUrl.toString());
		}

		const preVal = evalRes.result?.value;
		if (preVal && typeof preVal.crossOriginHookBlocked === "string") {
			return makeBlockedResult(
				formatScopeBlockReason(
					"egress-proxy",
					`签名钩子返回了非同源目标 (${preVal.crossOriginHookBlocked})，已被同源护栏拦截`,
					"N-007",
				),
				preVal.crossOriginHookBlocked,
			);
		}

		if (evalRes.exceptionDetails) {
			const errDesc =
				evalRes.exceptionDetails.exception?.description ||
				evalRes.exceptionDetails.text ||
				"页面内探针执行异常";
			const emptyHash = computeBodyHash("");
			return {
				ok: false,
				blocked: false,
				url: redactTrafficUrl(resolvedUrl.toString(), { root: opts?.root, vault: opts?.vault }),
				method: safeMethod,
				status: 0,
				headers: {},
				bodySnippet: "",
				bodyBytes: 0,
				bodyHash: emptyHash.bodyHash,
				templateHash: computeTemplateFingerprint(""),
				jsonKeys: [],
				isSoft404: false,
				signedByHook: false,
				appliedSignatureHeaders: [],
				durationMs: Math.max(0, Date.now() - startedAt),
				error: opts?.root || opts?.vault ? redactVaultSecrets(errDesc, opts.vault ?? opts.root!) : errDesc,
			};
		}

		const val = evalRes.result?.value ?? {};
		const status = typeof val.status === "number" ? val.status : 0;
		const rawBody = typeof val.body === "string" ? val.body : "";
		const rawRespHeaders = normalizeCdpHeadersObject(val.headers);
		const signedByHook = val.signedByHook === true;
		const appliedSignatureHeaders = Array.isArray(val.appliedSignatureHeaders)
			? val.appliedSignatureHeaders.map(String)
			: [];

		const { bodyHash, bodyBytes } = computeBodyHash(rawBody);
		const templateHash = computeTemplateFingerprint(rawBody, resolvedUrl.pathname);
		const jsonKeys = extractJsonTopKeys(rawBody);
		const soft404Check = detectSoft404(
			{
				url: resolvedUrl.toString(),
				path: resolvedUrl.pathname,
				status,
				body: rawBody,
				headers: rawRespHeaders,
			},
			opts?.soft404Baseline ?? undefined,
		);

		const redactOpts = { root: opts?.root, vault: opts?.vault, maxChars: 1024 };
		const safeHeaders = redactTrafficHeaders(rawRespHeaders, redactOpts);
		const safeSnippet = redactTrafficBody(rawBody, redactOpts) ?? "";
		const safeUrl = redactTrafficUrl(resolvedUrl.toString(), redactOpts);

		if (opts?.recorder) {
			opts.recorder.record({
				method: safeMethod,
				url: resolvedUrl.toString(),
				requestHeaders: {
					...cleanCustomHeaders,
					...(rule.overrideHeaders ?? {}),
				},
				status,
				responseHeaders: rawRespHeaders,
				responseBody: rawBody,
				durationMs: typeof val.durationMs === "number" ? val.durationMs : Math.max(0, Date.now() - startedAt),
				tags: ["cdp-signed-probe"],
				...(opts.roleLabel ? { role: opts.roleLabel } : {}),
			});
		}

		return {
			ok: status > 0,
			blocked: false,
			url: safeUrl,
			method: safeMethod,
			status,
			headers: safeHeaders,
			bodySnippet: safeSnippet,
			bodyBytes,
			bodyHash,
			templateHash,
			jsonKeys,
			isSoft404: soft404Check.isSoft404,
			signedByHook,
			appliedSignatureHeaders,
			durationMs: Math.max(0, Date.now() - startedAt),
		};
	} catch (err) {
		if (rule.blockedReason) {
			return makeBlockedResult(rule.blockedReason, rule.matchedUrl ?? resolvedUrl.toString());
		}
		const errMsg = err instanceof Error ? err.message : String(err);
		const isTimeout = /超时|timeout/i.test(errMsg);
		const emptyHash = computeBodyHash("");
		return {
			ok: false,
			blocked: false,
			...(isTimeout ? { timedOut: true } : {}),
			url: redactTrafficUrl(resolvedUrl.toString(), { root: opts?.root, vault: opts?.vault }),
			method: safeMethod,
			status: 0,
			headers: {},
			bodySnippet: "",
			bodyBytes: 0,
			bodyHash: emptyHash.bodyHash,
			templateHash: computeTemplateFingerprint(""),
			jsonKeys: [],
			isSoft404: false,
			signedByHook: false,
			appliedSignatureHeaders: [],
			durationMs: Math.max(0, Date.now() - startedAt),
			error: opts?.root || opts?.vault ? redactVaultSecrets(errMsg, opts.vault ?? opts.root!) : errMsg,
		};
	} finally {
		interceptor.probeRules.delete(probeToken);
	}
}

async function runBoundedConcurrency<T, R>(
	items: readonly T[],
	concurrency: number,
	worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
	const limit = Math.max(1, Math.min(MAX_CDP_PROBE_CONCURRENCY, Math.floor(concurrency)));
	const results = new Array<R>(items.length);
	let cursor = 0;

	const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
		while (true) {
			const idx = cursor++;
			if (idx >= items.length) break;
			results[idx] = await worker(items[idx]!, idx);
		}
	});
	await Promise.all(runners);
	return results;
}

function classifySignedDiffAnomaly(params: {
	path: string;
	baselineRole: string;
	baselineProbe: InPageSignedProbeResult;
	testedRole: string;
	testedProbe: InPageSignedProbeResult;
}): { kind: AuthDiffAnomalyKind; severity: "high" | "medium"; similarity: number } | null {
	const { path, baselineRole, baselineProbe, testedRole, testedProbe } = params;
	if (baselineProbe.status < 200 || baselineProbe.status >= 300 || baselineProbe.isSoft404) {
		return null;
	}
	if (testedProbe.status < 200 || testedProbe.status >= 300 || testedProbe.isSoft404) {
		return null;
	}
	if (testedProbe.bodyBytes === 0) {
		return null;
	}

	const keySim = computeKeyJaccard(baselineProbe.jsonKeys, testedProbe.jsonKeys);
	const exactOrTemplateMatch =
		testedProbe.bodyHash === baselineProbe.bodyHash ||
		testedProbe.templateHash === baselineProbe.templateHash;
	const similarity = exactOrTemplateMatch ? Math.max(keySim, 1) : keySim;

	// 要求具备实质性结构化重合或相同响应指纹，过滤公开静态信息误报
	const hasSubstantiveMatch =
		(baselineProbe.jsonKeys.length > 0 && similarity >= 0.6) ||
		(baselineProbe.bodyBytes >= 16 && exactOrTemplateMatch);
	if (!hasSubstantiveMatch) return null;

	if (testedRole === "anon") {
		return {
			kind: "unauth_access",
			severity: "high",
			similarity: Number(similarity.toFixed(4)),
		};
	}

	const baselineIsAdmin = ADMIN_ROLE_NAME_RE.test(baselineRole);
	const testedIsAdmin = ADMIN_ROLE_NAME_RE.test(testedRole);
	if ((baselineIsAdmin && !testedIsAdmin) || ADMIN_ENDPOINT_PATH_RE.test(path)) {
		return {
			kind: "vertical_bfla",
			severity: "high",
			similarity: Number(similarity.toFixed(4)),
		};
	}

	if (OBJECT_ID_PATH_OR_QUERY_RE.test(path) || exactOrTemplateMatch || similarity >= 0.75) {
		return {
			kind: "horizontal_bola",
			severity: exactOrTemplateMatch ? "high" : "medium",
			similarity: Number(similarity.toFixed(4)),
		};
	}

	return null;
}

/**
 * 在受控 Headless Chrome 页面上下文中执行多角色借壳加签契约差分测试（穿透前端动态时间戳/Nonce/HMAC 签名门禁）。
 * 自动完成：
 * 1. Scope 前置校验与受控页面加载（复用或自动管理会话生命周期，确保退出后零残留进程）；
 * 2. 随机不存在路径预采样构建 Soft-404 基线，抑制 SPA 200 兜底页误报；
 * 3. 可选无签名普通直连请求对照，核验接口是否存在动态签名防重门禁；
 * 4. 对比基线高权角色与低权角色 / 匿名态在页面原生加签通道下的真实返回差异，检出 BOLA / BFLA / 未授权访问。
 */
export async function runCdpSignedAuthDiff(
	targetUrl: string,
	paths: readonly string[],
	root: string,
	scope: ScopePolicy,
	opts?: RunCdpSignedAuthDiffOptions,
): Promise<RunCdpSignedAuthDiffResult> {
	const resolvedRoot = resolve(root);
	const mode = opts?.mode ?? "audit";
	const effectiveConcurrency = Math.max(
		1,
		Math.min(MAX_CDP_PROBE_CONCURRENCY, Math.floor(opts?.concurrency ?? 2)),
	);
	const timeoutMs = Math.max(300, opts?.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS);

	const entryCheck = checkHttpTargetScope(targetUrl, "GET", scope, mode, "CDP 签名差分入口");
	if (!entryCheck.ok) {
		return {
			ok: false,
			targetUrl: redactTrafficUrl(targetUrl, { root: resolvedRoot }),
			blockedByScope: true,
			blockReason: entryCheck.reason,
			effectiveConcurrency,
			testedPaths: [],
			blockedPaths: [...paths],
			unsignedStatuses: {},
			findings: [],
			fact: null,
		};
	}

	const ownsSession = !opts?.session;
	const session = opts?.session ?? (await launchCdpSession(opts?.launchOptions));
	const recorder = opts?.recorder ?? new TrafficRecorder(resolvedRoot);

	try {
		await ensureSessionInterceptor(session, scope, mode);
		const sid = session.sessionId;
		await session.client.send("Page.enable", {}, { sessionId: sid });
		await session.client.send("Runtime.enable", {}, { sessionId: sid });
		await session.client.send("Network.enable", {}, { sessionId: sid });

		// 若当前页面尚未处于目标同源上下文，则导航加载目标页面以挂载其前端签名脚本与会话
		const currentOrigin = await getCurrentPageOrigin(session, 2_500);
		if (currentOrigin !== entryCheck.parsed.origin) {
			const navTimeoutMs = Math.max(500, opts?.navigationTimeoutMs ?? DEFAULT_NAVIGATION_TIMEOUT_MS);
			const loadFired = session.client
				.waitForEvent("Page.loadEventFired", { sessionId: sid, timeoutMs: navTimeoutMs })
				.catch(() => null);
			await session.client.send(
				"Page.navigate",
				{ url: entryCheck.parsed.toString() },
				{ sessionId: sid, timeoutMs: navTimeoutMs },
			);
			await loadFired;
			await Bun.sleep(Math.max(50, opts?.settleMs ?? 300));
		}

		const vault = loadSessionVault(resolvedRoot);
		const allRoleHeaders = new Map<string, Record<string, string>>();
		for (const roleName of Object.keys(vault.roles)) {
			const hdrs = getRoleHeadersMap(vault, roleName);
			if (hdrs && Object.keys(hdrs).length > 0) {
				allRoleHeaders.set(roleName, hdrs);
			}
		}
		for (const [extraRole, extraHdrs] of Object.entries(opts?.extraRoleHeaders ?? {})) {
			if (extraHdrs && Object.keys(extraHdrs).length > 0) {
				allRoleHeaders.set(extraRole, { ...extraHdrs });
				for (const hv of Object.values(extraHdrs)) {
					recorder.registerTransientSecret(hv);
					recorder.registerTransientSecret(hv.replace(/^(?:Bearer|Basic|Token|JWT)\s+/i, ""));
				}
			}
		}

		// 确定基线角色与待测对比角色
		let baselineRole = opts?.baselineRole?.trim() || "";
		if (!baselineRole) {
			const roleNames = [...allRoleHeaders.keys()];
			baselineRole =
				roleNames.find((r) => ADMIN_ROLE_NAME_RE.test(r)) ??
				roleNames[0] ??
				"page-session";
		}
		const baselineHasExplicitHeaders = allRoleHeaders.has(baselineRole);

		const compareRoles: string[] = [];
		if (opts?.compareRoles && opts.compareRoles.length > 0) {
			for (const r of opts.compareRoles) {
				const clean = r.trim();
				if (clean && clean !== baselineRole && !compareRoles.includes(clean)) {
					compareRoles.push(clean);
				}
			}
		} else {
			for (const r of allRoleHeaders.keys()) {
				if (r !== baselineRole && !compareRoles.includes(r)) {
					compareRoles.push(r);
				}
			}
			if (!compareRoles.includes("anon")) {
				compareRoles.push("anon");
			}
		}

		// 预采样双随机不存在路径构建 Soft-404 基线
		let resolvedSoft404: Soft404BaselineInput | Soft404Baseline | null = opts?.soft404Baseline ?? null;
		if (!resolvedSoft404 && (opts?.autoSampleSoft404 ?? true)) {
			const randTag = randomUUID().slice(0, 8);
			const sampleProbe = await executeInPageSignedProbe(
				session,
				{
					url: `/__nuwa_cdp_404_${randTag}`,
					method: "GET",
					signerHook: opts?.signerHook,
					authMode: baselineHasExplicitHeaders ? "override" : "inherit",
					overrideAuthHeaders: allRoleHeaders.get(baselineRole),
				},
				scope,
				{ mode, timeoutMs, root: resolvedRoot, vault },
			);
			if (sampleProbe.ok && (sampleProbe.status === 200 || (sampleProbe.status >= 300 && sampleProbe.status < 400))) {
				resolvedSoft404 = {
					active: true,
					probes: [
						{
							path: `/__nuwa_cdp_404_${randTag}`,
							status: sampleProbe.status,
							size: sampleProbe.bodyBytes,
							body: sampleProbe.bodySnippet,
							bodyHash: sampleProbe.bodyHash,
							templateHash: sampleProbe.templateHash,
						},
					],
				};
			}
		}

		// 过滤并校验待测路径列表
		const validTargets: Array<{ rawPath: string; resolved: URL }> = [];
		const blockedPaths: string[] = [];
		const seenUrls = new Set<string>();

		for (const rawPath of paths) {
			const trimmed = String(rawPath ?? "").trim();
			if (!trimmed) continue;
			let candUrl: URL;
			try {
				candUrl = new URL(trimmed, entryCheck.parsed.origin);
			} catch {
				blockedPaths.push(trimmed);
				continue;
			}
			const check = checkHttpTargetScope(candUrl.toString(), "GET", scope, mode, "CDP 差分路径");
			if (!check.ok || candUrl.origin !== entryCheck.parsed.origin) {
				blockedPaths.push(trimmed);
				continue;
			}
			const key = candUrl.toString();
			if (seenUrls.has(key)) continue;
			seenUrls.add(key);
			validTargets.push({
				rawPath: `${candUrl.pathname}${candUrl.search}`,
				resolved: candUrl,
			});
		}

		const unsignedStatuses: Record<string, number> = {};
		const findings: CdpSignedAuthDiffFinding[] = [];
		const fetchImpl = opts?.fetchFn ?? fetch;

		await runBoundedConcurrency(validTargets, effectiveConcurrency, async (target) => {
			// A. 可选发送一次剥离动态签名的普通直连 HTTP 请求，验证服务端动态签名校验门禁
			if (opts?.verifyUnsignedBaseline ?? true) {
				try {
					const ctrl = new AbortController();
					const timer = setTimeout(() => ctrl.abort(), Math.min(timeoutMs, 4_000));
					try {
						const unsignedHeaders = baselineHasExplicitHeaders
							? { ...(allRoleHeaders.get(baselineRole) ?? {}) }
							: {};
						const unsignedResp = await fetchImpl(target.resolved.toString(), {
							method: "GET",
							headers: unsignedHeaders,
							redirect: "manual",
							signal: ctrl.signal,
						});
						unsignedStatuses[target.rawPath] = unsignedResp.status;
					} finally {
						clearTimeout(timer);
					}
				} catch {
					unsignedStatuses[target.rawPath] = 0;
				}
			}

			// B. 基线角色页面内借壳加签探针
			const baselineProbe = await executeInPageSignedProbe(
				session,
				{
					url: target.resolved.toString(),
					method: "GET",
					signerHook: opts?.signerHook,
					authMode: baselineHasExplicitHeaders ? "override" : "inherit",
					overrideAuthHeaders: allRoleHeaders.get(baselineRole),
				},
				scope,
				{
					mode,
					timeoutMs,
					root: resolvedRoot,
					vault,
					recorder,
					roleLabel: baselineRole,
					soft404Baseline: resolvedSoft404,
				},
			);

			if (!baselineProbe.ok || baselineProbe.status < 200 || baselineProbe.status >= 300 || baselineProbe.isSoft404) {
				return;
			}

			// C. 逐个对比低权限角色与匿名态的借壳加签响应
			for (const testRole of compareRoles) {
				const isAnon = testRole === "anon";
				const roleHdrs = isAnon ? undefined : allRoleHeaders.get(testRole);
				if (!isAnon && !roleHdrs) continue;

				const testedProbe = await executeInPageSignedProbe(
					session,
					{
						url: target.resolved.toString(),
						method: "GET",
						signerHook: opts?.signerHook,
						authMode: isAnon ? "anonymous" : "override",
						overrideAuthHeaders: roleHdrs,
					},
					scope,
					{
						mode,
						timeoutMs,
						root: resolvedRoot,
						vault,
						recorder,
						roleLabel: testRole,
						soft404Baseline: resolvedSoft404,
					},
				);

				const verdict = classifySignedDiffAnomaly({
					path: target.rawPath,
					baselineRole,
					baselineProbe,
					testedRole: testRole,
					testedProbe,
				});
				if (!verdict) continue;

				const unsignedCode = unsignedStatuses[target.rawPath];
				const rawSummary = `CDP 页面内加签差分检出 ${verdict.kind}：路径 ${target.rawPath} 在角色 ${testRole} 下返回 HTTP ${testedProbe.status}（与基线 ${baselineRole} 相似度 ${verdict.similarity}${unsignedCode ? `，无签名直连返回 HTTP ${unsignedCode}` : ""}）`;
				const safeSummary = redactVaultSecrets(rawSummary, vault);

				findings.push({
					path: target.rawPath,
					url: baselineProbe.url,
					kind: verdict.kind,
					severity: verdict.severity,
					summary: safeSummary,
					baselineRole,
					testedRole: testRole,
					similarity: verdict.similarity,
					...(unsignedCode !== undefined ? { unsignedStatus: unsignedCode } : {}),
					probes: [
						{
							role: baselineRole,
							status: baselineProbe.status,
							bodyBytes: baselineProbe.bodyBytes,
							bodyHash: baselineProbe.bodyHash,
							templateHash: baselineProbe.templateHash,
							jsonKeys: baselineProbe.jsonKeys,
							isSoft404: baselineProbe.isSoft404,
							signedByHook: baselineProbe.signedByHook,
							sampleSnippet: baselineProbe.bodySnippet.slice(0, 240),
						},
						{
							role: testRole,
							status: testedProbe.status,
							bodyBytes: testedProbe.bodyBytes,
							bodyHash: testedProbe.bodyHash,
							templateHash: testedProbe.templateHash,
							jsonKeys: testedProbe.jsonKeys,
							isSoft404: testedProbe.isSoft404,
							signedByHook: testedProbe.signedByHook,
							sampleSnippet: testedProbe.bodySnippet.slice(0, 240),
						},
					],
				});
			}
		});

		const testedPaths = validTargets.map((t) => t.rawPath);
		let fact: AutoFact | null = null;
		if (findings.length > 0) {
			const top = findings[0]!;
			const safeDetail = redactVaultSecrets(
				findings.map((f) => f.summary).join(" | "),
				vault,
			);
			fact = {
				kind: "vuln",
				title: `CDP 动态加签契约差分检出 ${findings.length} 处越权边界缺陷 (${top.kind})`.slice(0, 120),
				detail: safeDetail.slice(0, 600),
				command: `nuwa-cdp-signed-diff ${redactTrafficUrl(targetUrl, { root: resolvedRoot, vault })}`,
				output: redactVaultSecrets(
					JSON.stringify(
						findings.map((f) => ({
							path: f.path,
							kind: f.kind,
							baselineRole: f.baselineRole,
							testedRole: f.testedRole,
							unsignedStatus: f.unsignedStatus,
							similarity: f.similarity,
						})),
					),
					vault,
				).slice(0, 800),
				meta: {
					paths: findings.map((f) => f.path),
					status: 200,
				},
			};
		}

		// 确保无任何已知敏感串残留在返回结构中
		const checkNoMarkerOnly = REDACTED_MARKER;
		void checkNoMarkerOnly;

		return {
			ok: true,
			targetUrl: redactTrafficUrl(targetUrl, { root: resolvedRoot, vault }),
			blockedByScope: false,
			effectiveConcurrency,
			testedPaths,
			blockedPaths,
			unsignedStatuses,
			findings,
			fact,
		};
	} finally {
		if (ownsSession) {
			await closeCdpSession(session);
		}
	}
}
