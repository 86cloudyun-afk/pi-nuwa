/**
 * SPA 与 JS Bundle 动态/静态 API 感知层（v5.1 合规增强版）。
 *
 * - 模式 A（Playwright 受控浏览器）：支持持久化 `--user-data-dir`、可配置 `headless` / `useXvfb` / `display`、
 *   通过请求拦截严格放行 `isHostInScope` 内的 GET/HEAD/OPTIONS 只读请求，零副作用记录 XHR/Fetch/GraphQL 端点、
 *   前端路由与 React/Vue/Next/Nuxt/Angular 技术栈。
 * - 模式 B（静态回退模式）：无 Playwright/Chromium 时自动回退，抓取首屏 HTML 与最多 8 个
 *   同源 JS Bundle，静态解析路由与 fetch/axios/XHR/GraphQL 接口并过滤静态资源后缀，
 *   产出统一 `AutoFact`（`kind: "endpoint"`）。
 * - 软 404 与合规挑战门识别（#33 / #37）：导出 `detectSoft404` 与 `detectChallengeGate`；
 *   命中 Turnstile/CAPTCHA 挑战门或连续 `net::ERR_FAILED` 立即中止盲目重试并返回结构化 `challenge_gated`，
 *   支持从 `session-vault` 复用用户手动完成验证后保存的合法 Cookie/Header（绝不包含任何绕过/自动破解逻辑）。
 *
 * 约束：仅允许引用 `./scope`、`./autoexec`、`./session-vault`，严禁运行时 `import ./nuwa`。
 */
import { resolve } from "node:path";
import { isHostInScope, type ScopePolicy } from "./scope";
import {
	detectSoft404,
	sampleSoft404Baseline,
	type AutoFact,
	type DetectSoft404Input,
	type HeaderBagLike,
	type Soft404Baseline,
	type Soft404BaselineInput,
	type Soft404DetectionResult,
} from "./autoexec";
import {
	getRoleHeadersMap,
	loadSessionVault,
	redactVaultSecrets,
	upsertSessionRole,
	type SessionRoleEntry,
} from "./session-vault";

export {
	detectSoft404,
	sampleSoft404Baseline,
	type DetectSoft404Input,
	type Soft404Baseline,
	type Soft404BaselineInput,
	type Soft404DetectionResult,
};

export const MAX_STATIC_BUNDLES = 8;
const MAX_BUNDLE_BYTES = 2 * 1024 * 1024;
const MAX_STATIC_REDIRECTS = 5;
const ALLOWED_DYNAMIC_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

const STATIC_ASSET_EXT_RE =
	/\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|sass|less|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|pdf|zip|tar|gz|br|wasm|xml|txt)$/i;

const STATIC_DIR_PREFIX_RE = /^\/(?:_next\/static|_nuxt\/builds?|static\/(?:js|css|img|media|fonts)|assets\/(?:js|css|img|fonts))\//i;

export interface SpaApiEndpoint {
	/** HTTP 方法（大写，如 GET / POST / PUT / PATCH / DELETE） */
	method: string;
	/** 规范化路径（如 /api/v1/users 或 /graphql） */
	path: string;
	/** 规范化同域 URL（若有） */
	url?: string;
	/** 查询参数键名列表（去重排序，不保存值） */
	queryKeys: string[];
	/** 请求体顶层键名列表（去重排序，不保存明文值） */
	bodyKeys: string[];
	/** 是否为 GraphQL 端点 */
	isGraphql?: boolean;
	/** GraphQL operationName（若识别到） */
	graphqlOperation?: string;
	/** 发现来源 */
	source: "playwright" | "static-html" | "static-bundle";
}

export interface StaticBundleExtractResult {
	tech: string[];
	routes: string[];
	endpoints: SpaApiEndpoint[];
	bundles: string[];
	blockedRequests: number;
	fact: AutoFact | null;
}

export type ChallengeProvider =
	| "cloudflare_turnstile"
	| "cloudflare_challenge"
	| "hcaptcha"
	| "recaptcha"
	| "aws_waf_captcha"
	| "akamai_bot_manager"
	| "datadome"
	| "generic_challenge";

export interface ChallengeGateInput {
	url?: string;
	status?: number;
	headers?: HeaderBagLike;
	body?: string;
	html?: string;
	title?: string;
	error?: string;
	observedUrls?: readonly string[];
	failedRequests?: ReadonlyArray<{ url: string; errorText?: string; status?: number }>;
}

export interface ChallengeGateDetection {
	detected: boolean;
	status: "challenge_gated" | "clear";
	requiresHumanSession: boolean;
	provider?: ChallengeProvider;
	siteKey?: string;
	signals: string[];
	retryAllowed: boolean;
	guidance: string;
}

export interface BrowserCookieEntry {
	name: string;
	value: string;
	url?: string;
	domain?: string;
	path?: string;
	httpOnly?: boolean;
	secure?: boolean;
	sameSite?: "Strict" | "Lax" | "None";
}

export interface ChromiumLaunchConfig {
	headless: boolean;
	args: string[];
	userDataDir?: string;
	usePersistentContext: boolean;
	useXvfb: boolean;
	display?: string;
	proxyServer?: string;
	env: Record<string, string>;
	xvfbPrefix?: string[];
}

export interface SpaReconResult {
	url: string;
	mode: "playwright" | "static";
	status?: "ok" | "challenge_gated" | "soft_404" | "error";
	requiresHumanSession?: boolean;
	provider?: ChallengeProvider;
	challenge?: ChallengeGateDetection;
	soft404?: boolean;
	soft404Reasons?: string[];
	launchConfig?: Pick<
		ChromiumLaunchConfig,
		"headless" | "userDataDir" | "useXvfb" | "display" | "usePersistentContext"
	>;
	sessionRole?: string;
	fallbackReason?: string;
	tech: string[];
	routes: string[];
	endpoints: SpaApiEndpoint[];
	bundles: string[];
	blockedRequests: number;
	fact: AutoFact | null;
}

export interface FetchLikeResponse {
	ok: boolean;
	status: number;
	text(): Promise<string>;
	headers?: { get(name: string): string | null };
}

export type FetchLike = (
	input: string,
	init?: {
		method?: string;
		headers?: Record<string, string>;
		signal?: AbortSignal;
		redirect?: "manual" | "follow" | "error";
	},
) => Promise<FetchLikeResponse>;

export interface PlaywrightRequestLike {
	url(): string;
	method(): string;
	resourceType(): string;
	postData(): string | null;
	failure?(): { errorText?: string } | null;
}

export interface PlaywrightResponseLike {
	url?(): string;
	status?(): number;
	headers?(): Record<string, string>;
}

export interface PlaywrightRouteLike {
	request(): PlaywrightRequestLike;
	continue(): Promise<void>;
	abort(errorCode?: string): Promise<void>;
}

export interface PlaywrightPageLike {
	route(url: string, handler: (route: PlaywrightRouteLike) => Promise<void> | void): Promise<void>;
	goto(url: string, options?: { waitUntil?: string; timeout?: number }): Promise<PlaywrightResponseLike | unknown>;
	evaluate<T>(fn: () => T): Promise<T>;
	content?(): Promise<string>;
	on?(event: string, listener: (...args: any[]) => void): void;
	close(): Promise<void>;
}

export interface PlaywrightContextLike {
	newPage(): Promise<PlaywrightPageLike>;
	addCookies?(cookies: BrowserCookieEntry[]): Promise<void>;
	pages?(): PlaywrightPageLike[];
	close(): Promise<void>;
}

export interface PlaywrightBrowserLike {
	newContext(options?: {
		ignoreHTTPSErrors?: boolean;
		extraHTTPHeaders?: Record<string, string>;
	}): Promise<PlaywrightContextLike>;
	close(): Promise<void>;
}

export interface PlaywrightLike {
	chromium: {
		launch(options?: {
			headless?: boolean;
			args?: string[];
			env?: Record<string, string>;
			proxy?: { server: string };
		}): Promise<PlaywrightBrowserLike>;
		launchPersistentContext?(
			userDataDir: string,
			options?: {
				headless?: boolean;
				args?: string[];
				env?: Record<string, string>;
				proxy?: { server: string };
				ignoreHTTPSErrors?: boolean;
				extraHTTPHeaders?: Record<string, string>;
			},
		): Promise<PlaywrightContextLike>;
	};
}

export interface SpaReconOptions {
	timeoutMs?: number;
	maxBundles?: number;
	disablePlaywright?: boolean;
	/** 设为 false 时等价于 disablePlaywright=true（兼容既有调用）。 */
	preferBrowser?: boolean;
	playwrightLoader?: () => Promise<PlaywrightLike | null>;
	fetchFn?: FetchLike;
	signal?: AbortSignal;
	/** 认证态只读探测附加请求头（绝不写入命令、日志或事实输出） */
	authHeaders?: Record<string, string>;
	/** 认证态角色标识（非敏感，用于标记产出事实来源或从 session-vault 加载凭据） */
	authRole?: string;
	/** 从 session-vault 加载用户人工完成后保存的合法会话角色名 */
	sessionRole?: string;
	/** session-vault 所在项目根目录（配合 sessionRole/authRole 自动注入合法 Cookie 与 Header） */
	vaultRoot?: string;
	/** 显式传入的合法浏览器 Cookie（如从人工会话导入，绝不写入日志或事实） */
	cookies?: BrowserCookieEntry[];
	/** 持久化 Chromium 会话目录（`--user-data-dir`，#37） */
	userDataDir?: string;
	/** 是否使用无头模式（默认 true；若启用 useXvfb 且未显式指定则自动为 false） */
	headless?: boolean;
	/** 是否启用 Xvfb 虚拟显示有头模式（#37） */
	useXvfb?: boolean;
	/** X11 Display 标识（如 `:99`） */
	display?: string;
	/** 合规出口代理地址（可选，如 `http://127.0.0.1:7890` 或 `socks5://127.0.0.1:7890`） */
	proxyServer?: string;
	/** 可选预采样 Soft-404 基线（用于阻断软 404 页面污染路由/端点清单，#33） */
	soft404Baseline?: Soft404BaselineInput | null;
	/** 非挑战门瞬态导航重试次数上限（默认 0；命中挑战门时强制 0 重试立刻中止） */
	maxRetries?: number;
	/** 是否发现并解析同源 .js.map SourceMap（默认 true，严格受 maxBundles 与同源限制） */
	discoverSourceMaps?: boolean;
}

function clip(text: string, max: number): string {
	const s = String(text ?? "").replace(/\r/g, "").trim();
	return s.length > max ? `${s.slice(0, max)}…` : s;
}

function uniqSorted(items: Iterable<string>): string[] {
	return [...new Set([...items].map((s) => s.trim()).filter(Boolean))].sort();
}

/** 识别 React / Vue / Next / Nuxt / Angular 等前端技术栈指纹。 */
function detectFrontendTech(sources: readonly string[]): string[] {
	const found = new Set<string>();
	const rules: ReadonlyArray<{ name: string; re: RegExp }> = [
		{ name: "nextjs", re: /__NEXT_DATA__|\/_next\/static\/|id=["']__next["']|next\/(?:router|navigation|head)/i },
		{
			name: "react",
			re: /data-reactroot|data-reactid|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom|React\.createElement|createRoot\s*\(|react-router/i,
		},
		{ name: "nuxt", re: /__NUXT__|\/_nuxt\/|id=["']__nuxt["']|nuxt-link/i },
		{ name: "vue", re: /__VUE__|__vue_app__|data-v-[0-9a-f]{6,}|createApp\s*\(|vue-router|Vue\.component/i },
		{ name: "angular", re: /\bng-version=|ng-reflect-|@angular\/core|platformBrowserDynamic|angular\.module/i },
	];
	for (const src of sources) {
		if (!src) continue;
		for (const r of rules) {
			if (r.re.test(src)) {
				found.add(r.name);
			}
		}
	}
	// Next.js 隐含 React，Nuxt 隐含 Vue
	if (found.has("nextjs")) found.add("react");
	if (found.has("nuxt")) found.add("vue");
	return [...found].sort();
}

/** 清洗路径并判断是否应过滤为静态资源或无意义噪声。 */
function normalizeApiPath(rawPath: string): string | null {
	let p = String(rawPath ?? "").trim();
	if (!p) return null;
	// 将模板字符串插值 ${...} 规范化为 :param
	p = p.replace(/\$\{[^}]+\}/g, ":param");
	const hashIdx = p.indexOf("#");
	if (hashIdx >= 0) p = p.slice(0, hashIdx);
	const qIdx = p.indexOf("?");
	if (qIdx >= 0) p = p.slice(0, qIdx);
	p = p.replace(/\/{2,}/g, "/");
	if (!p.startsWith("/")) return null;
	if (p === "/" || p.length > 240) return null;
	if (/\s/.test(p) || /[<>"'`\\]/.test(p)) return null;
	if (STATIC_ASSET_EXT_RE.test(p) || STATIC_DIR_PREFIX_RE.test(p)) return null;
	// 排除正则标志或极短无意义单字母路径（保留常见短路径如 /v1 /ws）
	if (/^\/[a-z]$/i.test(p)) return null;
	return p;
}

function extractQueryKeysFromRaw(rawUrlOrPath: string): string[] {
	const cleaned = String(rawUrlOrPath ?? "").replace(/\$\{[^}]+\}/g, "1");
	const qIdx = cleaned.indexOf("?");
	if (qIdx < 0) return [];
	const queryStr = cleaned.slice(qIdx + 1).split("#")[0] ?? "";
	if (!queryStr) return [];
	const keys = new Set<string>();
	for (const part of queryStr.split("&")) {
		const eq = part.indexOf("=");
		const rawKey = (eq >= 0 ? part.slice(0, eq) : part).trim();
		if (rawKey && /^[A-Za-z0-9._\[\]-]{1,64}$/.test(rawKey)) {
			keys.add(rawKey);
		}
	}
	return [...keys].sort();
}

/** 从一段源码中，从起始 `{` 截取平衡的花括号对象字面量文本。 */
function sliceBalancedBraces(src: string, openBraceIdx: number, maxLen = 1200): string | null {
	if (openBraceIdx < 0 || src[openBraceIdx] !== "{") return null;
	let depth = 0;
	let inSingle = false;
	let inDouble = false;
	let inTemplate = false;
	const endLimit = Math.min(src.length, openBraceIdx + maxLen);

	for (let i = openBraceIdx; i < endLimit; i++) {
		const ch = src[i]!;
		const prev = i > openBraceIdx ? src[i - 1] : "";
		if (inSingle) {
			if (ch === "'" && prev !== "\\") inSingle = false;
			continue;
		}
		if (inDouble) {
			if (ch === '"' && prev !== "\\") inDouble = false;
			continue;
		}
		if (inTemplate) {
			if (ch === "`" && prev !== "\\") inTemplate = false;
			continue;
		}
		if (ch === "'") {
			inSingle = true;
			continue;
		}
		if (ch === '"') {
			inDouble = true;
			continue;
		}
		if (ch === "`") {
			inTemplate = true;
			continue;
		}
		if (ch === "{") {
			depth++;
		} else if (ch === "}") {
			depth--;
			if (depth === 0) {
				return src.slice(openBraceIdx, i + 1);
			}
		}
	}
	return null;
}

/** 从 JS/JSON 对象字面量 `{ a: 1, "b": ..., c }` 中提取顶层键名（绝不提取敏感值）。 */
function extractJsObjectTopKeys(objLiteral: string): string[] {
	const s = objLiteral.trim();
	if (!s.startsWith("{") || !s.endsWith("}")) return [];
	const inner = s.slice(1, -1);
	const keys = new Set<string>();

	let depthBrace = 0;
	let depthBracket = 0;
	let depthParen = 0;
	let inSingle = false;
	let inDouble = false;
	let inTemplate = false;
	let segStart = 0;

	const processSegment = (seg: string) => {
		const t = seg.trim();
		if (!t || t.startsWith("...")) return;
		// key: value 或 "key": value 或 'key': value
		const colonMatch = /^(?:["']([A-Za-z_$][A-Za-z0-9_$-]{0,63})["']|([A-Za-z_$][A-Za-z0-9_$]{0,63}))\s*:/.exec(t);
		if (colonMatch) {
			const k = colonMatch[1] ?? colonMatch[2];
			if (k) keys.add(k);
			return;
		}
		// ES6 简写属性：{ orderId, items }
		const shorthand = /^([A-Za-z_$][A-Za-z0-9_$]{0,63})$/.exec(t);
		if (shorthand?.[1]) {
			keys.add(shorthand[1]);
		}
	};

	for (let i = 0; i < inner.length; i++) {
		const ch = inner[i]!;
		const prev = i > 0 ? inner[i - 1] : "";
		if (inSingle) {
			if (ch === "'" && prev !== "\\") inSingle = false;
			continue;
		}
		if (inDouble) {
			if (ch === '"' && prev !== "\\") inDouble = false;
			continue;
		}
		if (inTemplate) {
			if (ch === "`" && prev !== "\\") inTemplate = false;
			continue;
		}
		if (ch === "'") {
			inSingle = true;
			continue;
		}
		if (ch === '"') {
			inDouble = true;
			continue;
		}
		if (ch === "`") {
			inTemplate = true;
			continue;
		}
		if (ch === "{") depthBrace++;
		else if (ch === "}") depthBrace = Math.max(0, depthBrace - 1);
		else if (ch === "[") depthBracket++;
		else if (ch === "]") depthBracket = Math.max(0, depthBracket - 1);
		else if (ch === "(") depthParen++;
		else if (ch === ")") depthParen = Math.max(0, depthParen - 1);
		else if (ch === "," && depthBrace === 0 && depthBracket === 0 && depthParen === 0) {
			processSegment(inner.slice(segStart, i));
			segStart = i + 1;
		}
	}
	processSegment(inner.slice(segStart));
	return [...keys].sort();
}

/** 从动态请求 postData 中仅提取顶层键名与 GraphQL operationName（绝不保存原始明文值）。 */
function parsePostDataKeys(postData: string | null): {
	bodyKeys: string[];
	isGraphql: boolean;
	graphqlOperation?: string;
} {
	const raw = String(postData ?? "").trim();
	if (!raw) return { bodyKeys: [], isGraphql: false };

	if (raw.startsWith("{") || raw.startsWith("[")) {
		try {
			const parsed = JSON.parse(raw) as unknown;
			const target = Array.isArray(parsed) ? parsed[0] : parsed;
			if (target && typeof target === "object" && !Array.isArray(target)) {
				const rec = target as Record<string, unknown>;
				const bodyKeys = Object.keys(rec)
					.map((k) => k.trim())
					.filter(Boolean)
					.sort();
				const hasGqlQuery =
					typeof rec.query === "string" && /\b(?:query|mutation|subscription)\b/i.test(rec.query);
				const opName =
					typeof rec.operationName === "string" && rec.operationName.trim()
						? rec.operationName.trim()
						: hasGqlQuery
							? /\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(rec.query as string)?.[1]
							: undefined;
				const isGraphql = Boolean(hasGqlQuery || opName || (bodyKeys.includes("query") && bodyKeys.includes("variables")));
				return { bodyKeys, isGraphql, ...(opName ? { graphqlOperation: opName } : {}) };
			}
		} catch {
			/* 回退下方 form 解析 */
		}
	}

	if (raw.includes("=") && !raw.includes("<")) {
		const params = new URLSearchParams(raw);
		const bodyKeys = uniqSorted(params.keys());
		if (bodyKeys.length > 0) {
			return { bodyKeys, isGraphql: false };
		}
	}

	return { bodyKeys: [], isGraphql: false };
}

function isGraphqlPath(path: string): boolean {
	return /\/(?:graphql|gql)(?:\/|$)/i.test(path);
}

function resolveCandidateEndpointUrl(
	rawRef: string,
	baseUrl: URL,
	scope: ScopePolicy,
): { ok: true; path: string; fullUrl: string; queryKeys: string[] } | { ok: false; blocked: boolean } {
	const ref = String(rawRef ?? "").trim();
	if (!ref || ref.startsWith("data:") || ref.startsWith("javascript:") || ref.startsWith("mailto:")) {
		return { ok: false, blocked: false };
	}

	const queryKeys = extractQueryKeysFromRaw(ref);

	if (/^https?:\/\//i.test(ref)) {
		try {
			const cleaned = ref.replace(/\$\{[^}]+\}/g, ":param");
			const u = new URL(cleaned);
			if (!isHostInScope(u.hostname, scope).ok) {
				return { ok: false, blocked: true };
			}
			const path = normalizeApiPath(u.pathname);
			if (!path) return { ok: false, blocked: false };
			return { ok: true, path, fullUrl: `${u.origin}${path}`, queryKeys };
		} catch {
			return { ok: false, blocked: false };
		}
	}

	if (!ref.startsWith("/")) {
		return { ok: false, blocked: false };
	}
	const path = normalizeApiPath(ref);
	if (!path) return { ok: false, blocked: false };
	return { ok: true, path, fullUrl: `${baseUrl.origin}${path}`, queryKeys };
}

function mergeEndpoint(map: Map<string, SpaApiEndpoint>, ep: SpaApiEndpoint): void {
	const method = (ep.method || "GET").toUpperCase();
	const key = `${method} ${ep.path}`;
	const existing = map.get(key);
	if (!existing) {
		map.set(key, {
			...ep,
			method,
			queryKeys: uniqSorted(ep.queryKeys),
			bodyKeys: uniqSorted(ep.bodyKeys),
			...(ep.isGraphql || isGraphqlPath(ep.path) ? { isGraphql: true } : {}),
		});
		return;
	}
	existing.queryKeys = uniqSorted([...existing.queryKeys, ...ep.queryKeys]);
	existing.bodyKeys = uniqSorted([...existing.bodyKeys, ...ep.bodyKeys]);
	if (ep.isGraphql || isGraphqlPath(ep.path)) existing.isGraphql = true;
	if (!existing.graphqlOperation && ep.graphqlOperation) existing.graphqlOperation = ep.graphqlOperation;
	if (ep.source === "playwright") existing.source = "playwright";
}

/** 从一段 JS/内联脚本源码中静态提取 API 端点与前端路由。 */
function extractApisAndRoutesFromJs(
	code: string,
	baseUrl: URL,
	scope: ScopePolicy,
	source: "static-html" | "static-bundle",
	endpointMap: Map<string, SpaApiEndpoint>,
	routes: Set<string>,
): { blocked: number } {
	let blocked = 0;
	if (!code) return { blocked };

	const record = (
		rawUrl: string,
		method: string,
		bodyKeys: string[] = [],
		extra?: { isGraphql?: boolean; graphqlOperation?: string },
	) => {
		const resolved = resolveCandidateEndpointUrl(rawUrl, baseUrl, scope);
		if (!resolved.ok) {
			if (resolved.blocked) blocked++;
			return;
		}
		mergeEndpoint(endpointMap, {
			method: method.toUpperCase(),
			path: resolved.path,
			url: resolved.fullUrl,
			queryKeys: resolved.queryKeys,
			bodyKeys,
			...(extra?.isGraphql || isGraphqlPath(resolved.path) ? { isGraphql: true } : {}),
			...(extra?.graphqlOperation ? { graphqlOperation: extra.graphqlOperation } : {}),
			source,
		});
	};

	const inspectOptionsContext = (snippet: string): {
		method?: string;
		bodyKeys: string[];
		isGraphql: boolean;
		graphqlOperation?: string;
	} => {
		const methodMatch = /\bmethod\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']/i.exec(snippet);
		const method = methodMatch?.[1]?.toUpperCase();
		let bodyKeys: string[] = [];
		let isGraphql = false;
		let graphqlOperation: string | undefined;

		const stringifyIdx = snippet.search(/\bJSON\.stringify\s*\(\s*\{/);
		if (stringifyIdx >= 0) {
			const braceIdx = snippet.indexOf("{", stringifyIdx);
			const lit = sliceBalancedBraces(snippet, braceIdx);
			if (lit) {
				bodyKeys = extractJsObjectTopKeys(lit);
				const opMatch = /\boperationName\s*:\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/.exec(lit);
				const gqlOp = /\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(lit);
				graphqlOperation = opMatch?.[1] ?? gqlOp?.[1];
				isGraphql = Boolean(
					graphqlOperation ||
						/\bquery\s*:\s*["'`]\s*(?:query|mutation|subscription)\b/i.test(lit) ||
						(bodyKeys.includes("query") && bodyKeys.includes("variables")),
				);
			}
		} else {
			const dataProp = /\b(?:body|data)\s*:\s*\{/.exec(snippet);
			if (dataProp) {
				const braceIdx = snippet.indexOf("{", dataProp.index);
				const lit = sliceBalancedBraces(snippet, braceIdx);
				if (lit) {
					bodyKeys = extractJsObjectTopKeys(lit);
				}
			}
		}
		return { method, bodyKeys, isGraphql, ...(graphqlOperation ? { graphqlOperation } : {}) };
	};

	// 1. fetch("url", { method, body })
	const fetchRe = /\bfetch\s*\(\s*["'`]([^"'`\r\n]{2,260})["'`]/g;
	for (const m of code.matchAll(fetchRe)) {
		const rawUrl = m[1]!;
		const afterStart = (m.index ?? 0) + m[0].length;
		const windowSlice = code.slice(afterStart, afterStart + 450);
		let method = "GET";
		let bodyKeys: string[] = [];
		let isGraphql = isGraphqlPath(rawUrl);
		let graphqlOperation: string | undefined;

		const commaOpt = /^\s*,\s*\{/.exec(windowSlice);
		if (commaOpt) {
			const braceIdx = windowSlice.indexOf("{");
			const optObj = sliceBalancedBraces(windowSlice, braceIdx, 600);
			if (optObj) {
				const ctx = inspectOptionsContext(optObj);
				if (ctx.method) method = ctx.method;
				bodyKeys = ctx.bodyKeys;
				if (ctx.isGraphql) isGraphql = true;
				graphqlOperation = ctx.graphqlOperation;
			}
		}
		record(rawUrl, method, bodyKeys, { isGraphql, graphqlOperation });
	}

	// 2. axios / $http / http / ky .get/.post/.put/.patch/.delete/.head/.options("url", payload?)
	const clientMethodRe =
		/\b(?:axios|\$http|httpClient|apiClient|ky)\.(get|post|put|patch|delete|head|options)\s*(?:<[^>]{1,60}>)?\s*\(\s*["'`]([^"'`\r\n]{2,260})["'`]/gi;
	for (const m of code.matchAll(clientMethodRe)) {
		const method = m[1]!.toUpperCase();
		const rawUrl = m[2]!;
		const afterStart = (m.index ?? 0) + m[0].length;
		const windowSlice = code.slice(afterStart, afterStart + 400);
		let bodyKeys: string[] = [];
		let isGraphql = isGraphqlPath(rawUrl);
		let graphqlOperation: string | undefined;

		if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
			const secondObj = /^\s*,\s*\{/.exec(windowSlice);
			if (secondObj) {
				const lit = sliceBalancedBraces(windowSlice, windowSlice.indexOf("{"), 600);
				if (lit) {
					bodyKeys = extractJsObjectTopKeys(lit);
					const opMatch = /\boperationName\s*:\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/.exec(lit);
					const gqlOp = /\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(lit);
					graphqlOperation = opMatch?.[1] ?? gqlOp?.[1];
					if (graphqlOperation || (bodyKeys.includes("query") && bodyKeys.includes("variables"))) {
						isGraphql = true;
					}
				}
			}
		}
		record(rawUrl, method, bodyKeys, { isGraphql, graphqlOperation });
	}

	// 3. axios({ method: "post", url: "/api/...", data: { ... } })
	const axiosObjRe = /\baxios\s*\(\s*\{/g;
	for (const m of code.matchAll(axiosObjRe)) {
		const braceIdx = (m.index ?? 0) + m[0].length - 1;
		const optObj = sliceBalancedBraces(code, braceIdx, 600);
		if (!optObj) continue;
		const urlMatch = /\burl\s*:\s*["'`]([^"'`\r\n]{2,260})["'`]/.exec(optObj);
		if (!urlMatch?.[1]) continue;
		const ctx = inspectOptionsContext(optObj);
		record(urlMatch[1], ctx.method ?? "GET", ctx.bodyKeys, {
			isGraphql: ctx.isGraphql,
			graphqlOperation: ctx.graphqlOperation,
		});
	}

	// 4. XMLHttpRequest.open("METHOD", "/path")
	const xhrRe = /\.open\s*\(\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`\r\n]{2,260})["'`]/gi;
	for (const m of code.matchAll(xhrRe)) {
		record(m[2]!, m[1]!.toUpperCase());
	}

	// 5. 独立 API 路径字面量（如 "/api/v1/users/profile"、"/graphql"、"/v2/orders"）
	const literalApiRe =
		/["'`]((?:https?:\/\/[^"'`\s]{3,160})?\/(?:api|v[1-9]\d*|graphql|gql|rest|rpc|internal|auth|oauth|admin|actuator|swagger|openapi|metrics|health)(?:\/[A-Za-z0-9._~:@!$&*+,;=\-\/${}]*)?(?:\?[A-Za-z0-9._~=&%+-]+)?)["'`]/gi;
	for (const m of code.matchAll(literalApiRe)) {
		const rawUrl = m[1]!;
		const resolved = resolveCandidateEndpointUrl(rawUrl, baseUrl, scope);
		if (!resolved.ok) {
			if (resolved.blocked) blocked++;
			continue;
		}
		// 若已有任意非 GET 方法记录了同一 path，不再额外追加冗余 GET 占位
		const alreadyHasPath = [...endpointMap.values()].some((ep) => ep.path === resolved.path);
		if (!alreadyHasPath) {
			mergeEndpoint(endpointMap, {
				method: "GET",
				path: resolved.path,
				url: resolved.fullUrl,
				queryKeys: resolved.queryKeys,
				bodyKeys: [],
				...(isGraphqlPath(resolved.path) ? { isGraphql: true } : {}),
				source,
			});
		}
	}

	// 6. 前端路由提取（React Router / Vue Router / Next / Angular）
	const routePatterns = [
		/\bpath\s*:\s*["'](\/[A-Za-z0-9_/:.*-]{1,120})["']/g,
		/<Route\b[^>]*\bpath=["'](\/[A-Za-z0-9_/:.*-]{1,120})["']/gi,
		/\b(?:router\.push|router\.replace|navigate)\s*\(\s*["'](\/[A-Za-z0-9_/:.-]{1,120})["']/g,
	];
	for (const re of routePatterns) {
		for (const m of code.matchAll(re)) {
			const norm = normalizeApiPath(m[1]!);
			if (norm && !/^\/(?:api|graphql|gql)\b/i.test(norm)) {
				routes.add(norm);
			}
		}
	}

	return { blocked };
}

function extractInlineScripts(html: string): string[] {
	const scripts: string[] = [];
	const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
	for (const m of html.matchAll(re)) {
		const attrs = m[1] ?? "";
		const content = m[2] ?? "";
		if (/\bsrc\s*=/i.test(attrs)) continue;
		if (content.trim()) scripts.push(content);
	}
	return scripts;
}

function extractHtmlRoutes(html: string, baseUrl: URL, scope: ScopePolicy): string[] {
	const out = new Set<string>();
	const hrefRe = /<a\b[^>]*\bhref=["']([^"'#][^"']*)["']/gi;
	for (const m of html.matchAll(hrefRe)) {
		const raw = m[1]!.trim();
		if (!raw || raw.startsWith("javascript:") || raw.startsWith("mailto:")) continue;
		try {
			const u = new URL(raw, baseUrl);
			if (u.origin !== baseUrl.origin || !isHostInScope(u.hostname, scope).ok) continue;
			const norm = normalizeApiPath(u.pathname);
			if (norm) out.add(norm);
		} catch {
			/* 忽略非法 href */
		}
	}
	return [...out].sort();
}

function discoverSameOriginBundles(
	html: string,
	baseUrl: URL,
	scope: ScopePolicy,
	maxBundles: number,
): { bundleUrls: string[]; blocked: number } {
	const found: string[] = [];
	const seen = new Set<string>();
	let blocked = 0;

	const candidates: string[] = [];
	for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) {
		if (m[1]) candidates.push(m[1].trim());
	}
	for (const m of html.matchAll(
		/<link\b[^>]*\brel=["'](?:modulepreload|preload)["'][^>]*\bhref=["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi,
	)) {
		if (m[1]) candidates.push(m[1].trim());
	}

	for (const rawSrc of candidates) {
		if (!rawSrc || rawSrc.startsWith("data:") || rawSrc.startsWith("blob:")) continue;
		let resolved: URL;
		try {
			resolved = new URL(rawSrc, baseUrl);
		} catch {
			continue;
		}
		if (resolved.protocol !== "http:" && resolved.protocol !== "https:") continue;
		if (resolved.origin !== baseUrl.origin || !isHostInScope(resolved.hostname, scope).ok) {
			blocked++;
			continue;
		}
		const href = resolved.href;
		if (seen.has(href)) continue;
		seen.add(href);
		found.push(href);
		if (found.length >= maxBundles) break;
	}

	return { bundleUrls: found, blocked };
}

function mergeHeadersWithAccept(
	acceptValue: string,
	authHeaders?: Record<string, string>,
): Record<string, string> {
	const merged: Record<string, string> = {};
	if (authHeaders) {
		for (const [k, v] of Object.entries(authHeaders)) {
			const cleanK = String(k ?? "")
				.replace(/[\r\n]+/g, " ")
				.replace(/:\s*$/, "")
				.trim();
			const cleanV = String(v ?? "")
				.replace(/[\r\n]+/g, " ")
				.trim();
			if (!cleanK || !cleanV) continue;
			if (cleanK.toLowerCase() === "accept") continue;
			merged[cleanK] = cleanV;
		}
	}
	merged.Accept = acceptValue;
	return merged;
}

function discoverLazyChunksFromJs(
	jsCode: string,
	bundleUrl: URL,
	baseUrl: URL,
	scope: ScopePolicy,
): { chunkUrls: string[]; blocked: number } {
	const chunkUrls: string[] = [];
	const seen = new Set<string>();
	let blocked = 0;
	if (!jsCode) return { chunkUrls, blocked };

	const rawCandidates: string[] = [];
	const dynamicImportRe =
		/\bimport\s*\(\s*(?:\/\*[\s\S]*?\*\/\s*)?["']([^"'\s`${}<>\\]{2,240}\.(?:m?js|cjs)(?:\?[^"'\s`${}<>\\]*)?)["']\s*\)/g;
	for (const m of jsCode.matchAll(dynamicImportRe)) {
		if (m[1]) rawCandidates.push(m[1].trim());
	}

	const chunkLiteralRe =
		/["']((?:https?:\/\/[^"'\s`${}<>\\]{3,160})?(?:\/|\.\.?\/)(?:(?:_next\/static\/chunks|_nuxt|assets|static|chunks|js|dist|build|pages)\/[A-Za-z0-9._~/-]{1,200}|[A-Za-z0-9._~/-]{0,160}(?:chunk|bundle|lazy|async)[A-Za-z0-9._~/-]{0,80})\.(?:m?js|cjs)(?:\?[A-Za-z0-9._~=&%-]*)?)["']/gi;
	for (const m of jsCode.matchAll(chunkLiteralRe)) {
		if (m[1]) rawCandidates.push(m[1].trim());
	}

	for (const rawRef of rawCandidates) {
		if (!rawRef || rawRef.startsWith("data:") || rawRef.startsWith("blob:")) continue;
		let resolved: URL;
		try {
			resolved = new URL(rawRef, bundleUrl);
		} catch {
			continue;
		}
		if (resolved.protocol !== "http:" && resolved.protocol !== "https:") continue;
		if (resolved.origin !== baseUrl.origin || !isHostInScope(resolved.hostname, scope).ok) {
			blocked++;
			continue;
		}
		const href = resolved.href;
		if (seen.has(href)) continue;
		seen.add(href);
		chunkUrls.push(href);
	}

	return { chunkUrls, blocked };
}

function discoverSourceMapUrl(
	jsCode: string,
	bundleUrl: URL,
	baseUrl: URL,
	scope: ScopePolicy,
): { mapUrl: string | null; blocked: number } {
	if (!jsCode) return { mapUrl: null, blocked: 0 };

	let lastIdx = -1;
	let lastRaw = "";

	const lineMapRe = /\/\/[#@]\s*sourceMappingURL\s*=\s*([^\s'"]+)/g;
	for (const m of jsCode.matchAll(lineMapRe)) {
		const idx = m.index ?? -1;
		if (m[1] && idx >= lastIdx) {
			lastIdx = idx;
			lastRaw = m[1].trim();
		}
	}
	const blockMapRe = /\/\*[#@]\s*sourceMappingURL\s*=\s*([^\s*'"]+)\s*\*\//g;
	for (const m of jsCode.matchAll(blockMapRe)) {
		const idx = m.index ?? -1;
		if (m[1] && idx >= lastIdx) {
			lastIdx = idx;
			lastRaw = m[1].trim();
		}
	}

	if (!lastRaw || lastRaw.startsWith("data:") || lastRaw.startsWith("blob:")) {
		return { mapUrl: null, blocked: 0 };
	}

	let resolved: URL;
	try {
		resolved = new URL(lastRaw, bundleUrl);
	} catch {
		return { mapUrl: null, blocked: 0 };
	}
	if (resolved.protocol !== "http:" && resolved.protocol !== "https:") {
		return { mapUrl: null, blocked: 0 };
	}
	if (!/\.map$/i.test(resolved.pathname)) {
		return { mapUrl: null, blocked: 0 };
	}
	if (resolved.origin !== baseUrl.origin || !isHostInScope(resolved.hostname, scope).ok) {
		return { mapUrl: null, blocked: 1 };
	}
	return { mapUrl: resolved.href, blocked: 0 };
}

function defaultFetchImpl(): FetchLike {
	return async (input, init) => {
		const res = await fetch(input, {
			method: init?.method ?? "GET",
			headers: init?.headers,
			signal: init?.signal,
			redirect: init?.redirect ?? "manual",
		});
		return {
			ok: res.ok,
			status: res.status,
			text: () => res.text(),
			headers: res.headers,
		};
	};
}

type ScopedFetchOutcome =
	| { ok: true; response: FetchLikeResponse; finalUrl: string }
	| { ok: false; blocked: true; reason: string }
	| { ok: false; blocked: false; error: string };

/**
 * 受控只读 GET 抓取器：强制 `redirect: "manual"`，逐跳校验 301/302/303/307/308 的 Location
 * 是否符合 `http:`/`https:`、命中 `isHostInScope`（以及可选的同源约束），越界或超跳立即阻断。
 */
async function scopedGetFetch(
	initialUrl: string,
	scope: ScopePolicy,
	fetcher: FetchLike,
	opts: {
		headers?: Record<string, string>;
		signal?: AbortSignal;
		requireSameOrigin?: string;
		maxRedirects?: number;
	},
): Promise<ScopedFetchOutcome> {
	const maxRedirects = Math.max(0, Math.min(10, opts.maxRedirects ?? MAX_STATIC_REDIRECTS));
	let curUrl: URL;
	try {
		curUrl = new URL(initialUrl);
	} catch {
		return { ok: false, blocked: true, reason: `请求 URL 非法: ${initialUrl}` };
	}

	for (let hop = 0; hop <= maxRedirects; hop++) {
		if (curUrl.protocol !== "http:" && curUrl.protocol !== "https:") {
			return { ok: false, blocked: true, reason: `禁止非 HTTP(S) 协议: ${curUrl.protocol}` };
		}
		const scopeCheck = isHostInScope(curUrl.hostname, scope);
		if (!scopeCheck.ok) {
			return { ok: false, blocked: true, reason: scopeCheck.reason ?? `主机 ${curUrl.hostname} 超出范围` };
		}
		if (opts.requireSameOrigin && curUrl.origin !== opts.requireSameOrigin) {
			return { ok: false, blocked: true, reason: `跨源目标 ${curUrl.origin} 与预期同源 ${opts.requireSameOrigin} 不符` };
		}

		let resp: FetchLikeResponse;
		try {
			resp = await fetcher(curUrl.href, {
				method: "GET",
				headers: opts.headers,
				signal: opts.signal,
				redirect: "manual",
			});
		} catch (err) {
			return { ok: false, blocked: false, error: err instanceof Error ? err.message : String(err) };
		}

		if (!REDIRECT_STATUSES.has(resp.status)) {
			return { ok: true, response: resp, finalUrl: curUrl.href };
		}

		const location = resp.headers?.get("location")?.trim() ?? "";
		if (!location) {
			return { ok: true, response: resp, finalUrl: curUrl.href };
		}
		if (hop >= maxRedirects) {
			return { ok: false, blocked: true, reason: `重定向次数超过上限 (${maxRedirects})` };
		}

		let nextUrl: URL;
		try {
			nextUrl = new URL(location, curUrl);
		} catch {
			return { ok: false, blocked: true, reason: `非法重定向 Location: ${location}` };
		}
		if (nextUrl.protocol !== "http:" && nextUrl.protocol !== "https:") {
			return { ok: false, blocked: true, reason: `阻断非 HTTP(S) 重定向协议: ${nextUrl.protocol}` };
		}
		const nextScope = isHostInScope(nextUrl.hostname, scope);
		if (!nextScope.ok) {
			return {
				ok: false,
				blocked: true,
				reason: `阻断越界 30x 重定向至 ${nextUrl.hostname}: ${nextScope.reason ?? "超出 ScopePolicy"}`,
			};
		}
		if (opts.requireSameOrigin && nextUrl.origin !== opts.requireSameOrigin) {
			return {
				ok: false,
				blocked: true,
				reason: `阻断跨源 30x 重定向: ${nextUrl.origin} !== ${opts.requireSameOrigin}`,
			};
		}
		curUrl = nextUrl;
	}

	return { ok: false, blocked: true, reason: `重定向次数超过上限 (${maxRedirects})` };
}

function buildSpaAutoFact(
	url: string,
	mode: "playwright" | "static",
	tech: readonly string[],
	routes: readonly string[],
	endpoints: readonly SpaApiEndpoint[],
	bundlesCount: number,
	authRole?: string,
): AutoFact | null {
	if (endpoints.length === 0 && routes.length === 0) {
		return null;
	}

	const pathSet = new Set<string>();
	for (const ep of endpoints) pathSet.add(ep.path);
	for (const r of routes) pathSet.add(r);
	const paths = [...pathSet];

	const epSummary = endpoints.slice(0, 15).map((ep) => {
		const qPart = ep.queryKeys.length > 0 ? `?${ep.queryKeys.join("&")}` : "";
		const bPart = ep.bodyKeys.length > 0 ? ` body=[${ep.bodyKeys.join(",")}]` : "";
		const gqlPart = ep.isGraphql
			? ` [graphql${ep.graphqlOperation ? `:${ep.graphqlOperation}` : ""}]`
			: "";
		return `${ep.method} ${ep.path}${qPart}${bPart}${gqlPart}`;
	});

	const cleanRole = String(authRole ?? "")
		.replace(/[\r\n\s]+/g, "")
		.slice(0, 64);

	const detailParts = [
		`mode=${mode}`,
		cleanRole ? `authRole=${cleanRole}` : "",
		`tech=${tech.length ? tech.join(",") : "-"}`,
		`bundles=${bundlesCount}`,
		routes.length ? `routes=${routes.slice(0, 10).join(",")}` : "",
		epSummary.length ? `apis=${epSummary.join(" | ")}` : "",
	].filter(Boolean);

	const outLines = [
		...epSummary,
		...routes.slice(0, 15).map((r) => `ROUTE ${r}`),
	];

	return {
		kind: "endpoint",
		title: `SPA 感知 (${mode}) 发现 ${endpoints.length} 条 API / ${routes.length} 条路由`.slice(0, 120),
		detail: clip(detailParts.join(" ; "), 700),
		command: clip(`browser-recon (${mode}) ${url}`, 400),
		output: clip(outLines.join("\n"), 800),
		meta: {
			paths,
			...(tech.length > 0 ? { tech: [...tech] } : {}),
		},
	};
}

/**
 * 模式 B 核心实现：静态解析首屏 HTML 与最多 8 个同源 JS Bundle（含按需懒加载 Chunk 与同源 SourceMap），
 * 提取 API 路由与 fetch/axios/XHR/GraphQL 接口，过滤静态资源后缀，并产出统一 AutoFact。
 */
export async function extractStaticBundleApis(
	html: string,
	baseUrl: string,
	scope: ScopePolicy,
	fetchFn?: FetchLike,
	opts?: {
		maxBundles?: number;
		timeoutMs?: number;
		signal?: AbortSignal;
		authHeaders?: Record<string, string>;
		authRole?: string;
		discoverSourceMaps?: boolean;
	},
): Promise<StaticBundleExtractResult> {
	let parsedBase: URL;
	try {
		parsedBase = new URL(baseUrl);
	} catch {
		return { tech: [], routes: [], endpoints: [], bundles: [], blockedRequests: 1, fact: null };
	}

	if (!isHostInScope(parsedBase.hostname, scope).ok) {
		return { tech: [], routes: [], endpoints: [], bundles: [], blockedRequests: 1, fact: null };
	}

	const maxBundles = Math.min(MAX_STATIC_BUNDLES, Math.max(0, Math.floor(opts?.maxBundles ?? MAX_STATIC_BUNDLES)));
	const timeoutMs = Math.max(500, Math.min(60_000, opts?.timeoutMs ?? 8_000));
	const discoverSourceMaps = opts?.discoverSourceMaps !== false;
	const fetcher = fetchFn ?? defaultFetchImpl();

	const endpointMap = new Map<string, SpaApiEndpoint>();
	const routeSet = new Set<string>(extractHtmlRoutes(html, parsedBase, scope));
	const techSources: string[] = [html];
	let blockedRequests = 0;

	// 1. 解析首屏 HTML 内联脚本
	for (const inlineCode of extractInlineScripts(html)) {
		const res = extractApisAndRoutesFromJs(inlineCode, parsedBase, scope, "static-html", endpointMap, routeSet);
		blockedRequests += res.blocked;
	}

	// 2. 发现并抓取最多 maxBundles 个同源 JS Bundle / 懒加载 Chunk / SourceMap
	const { bundleUrls, blocked: blockedScriptHosts } = discoverSameOriginBundles(html, parsedBase, scope, maxBundles);
	blockedRequests += blockedScriptHosts;

	const queue: Array<{ url: string; kind: "js" | "sourcemap" }> = [];
	const queued = new Set<string>();
	const enqueue = (url: string, kind: "js" | "sourcemap") => {
		if (queued.has(url)) return;
		queued.add(url);
		queue.push({ url, kind });
	};
	for (const u of bundleUrls) {
		enqueue(u, "js");
	}

	const fetchedBundles: string[] = [];
	let fetchedAttempts = 0;

	while (queue.length > 0 && fetchedAttempts < maxBundles) {
		if (opts?.signal?.aborted) break;
		const item = queue.shift()!;
		fetchedAttempts++;

		const controller = new AbortController();
		const onAbort = () => controller.abort();
		opts?.signal?.addEventListener("abort", onAbort, { once: true });
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const accept =
				item.kind === "sourcemap"
					? "application/json, */*"
					: "application/javascript, text/javascript, */*";
			const fetched = await scopedGetFetch(item.url, scope, fetcher, {
				headers: mergeHeadersWithAccept(accept, opts?.authHeaders),
				signal: controller.signal,
				requireSameOrigin: parsedBase.origin,
			});
			if (!fetched.ok) {
				if (fetched.blocked) blockedRequests++;
				continue;
			}
			const resp = fetched.response;
			if (!resp.ok) continue;
			const rawText = await resp.text();
			const clippedText = rawText.length > MAX_BUNDLE_BYTES ? rawText.slice(0, MAX_BUNDLE_BYTES) : rawText;
			queued.add(fetched.finalUrl);

			if (item.kind === "sourcemap") {
				try {
					const parsedMap = JSON.parse(clippedText) as { sourcesContent?: unknown };
					if (parsedMap && typeof parsedMap === "object" && Array.isArray(parsedMap.sourcesContent)) {
						fetchedBundles.push(fetched.finalUrl);
						let consumed = 0;
						for (const entry of parsedMap.sourcesContent) {
							if (typeof entry !== "string" || !entry.trim()) continue;
							const remaining = MAX_BUNDLE_BYTES - consumed;
							if (remaining <= 0) break;
							const snippet = entry.length > remaining ? entry.slice(0, remaining) : entry;
							consumed += snippet.length;
							if (techSources.length < 32) techSources.push(snippet);
							const res = extractApisAndRoutesFromJs(
								snippet,
								parsedBase,
								scope,
								"static-bundle",
								endpointMap,
								routeSet,
							);
							blockedRequests += res.blocked;
						}
					}
				} catch {
					/* 非法或截断的 SourceMap JSON 安全忽略 */
				}
				continue;
			}

			fetchedBundles.push(fetched.finalUrl);
			if (techSources.length < 32) techSources.push(clippedText);
			const res = extractApisAndRoutesFromJs(clippedText, parsedBase, scope, "static-bundle", endpointMap, routeSet);
			blockedRequests += res.blocked;

			let finalBundleUrl = parsedBase;
			try {
				finalBundleUrl = new URL(fetched.finalUrl);
			} catch {
				/* 回退 parsedBase */
			}

			// 发现同源懒加载 JS Chunk（受剩余 maxBundles 预算约束）
			const lazy = discoverLazyChunksFromJs(clippedText, finalBundleUrl, parsedBase, scope);
			blockedRequests += lazy.blocked;
			for (const chunkUrl of lazy.chunkUrls) {
				enqueue(chunkUrl, "js");
			}

			// 可选发现同源 .js.map SourceMap（受剩余 maxBundles 预算约束）
			if (discoverSourceMaps) {
				const sm = discoverSourceMapUrl(clippedText, finalBundleUrl, parsedBase, scope);
				blockedRequests += sm.blocked;
				if (sm.mapUrl) {
					enqueue(sm.mapUrl, "sourcemap");
				}
			}
		} catch {
			/* 单个 Bundle 抓取超时或网络异常不影响其余 Bundle 分析 */
		} finally {
			clearTimeout(timer);
			opts?.signal?.removeEventListener("abort", onAbort);
		}
	}

	const tech = detectFrontendTech(techSources);
	const routes = [...routeSet].sort();
	const endpoints = [...endpointMap.values()].sort(
		(a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
	);
	const fact = buildSpaAutoFact(
		parsedBase.href,
		"static",
		tech,
		routes,
		endpoints,
		fetchedBundles.length,
		opts?.authRole,
	);

	return {
		tech,
		routes,
		endpoints,
		bundles: fetchedBundles,
		blockedRequests,
		fact,
	};
}

const CHALLENGE_TURNSTILE_URL_RE = /challenges\.cloudflare\.com\/turnstile/i;
const CHALLENGE_CF_PLATFORM_URL_RE = /challenges\.cloudflare\.com|\/cdn-cgi\/challenge-platform\b/i;
const CHALLENGE_HCAPTCHA_URL_RE = /(?:js\.|assets\.)?hcaptcha\.com\/1\/api\.js/i;
const CHALLENGE_RECAPTCHA_URL_RE = /(?:google\.com|recaptcha\.net)\/recaptcha\//i;

const CHALLENGE_TURNSTILE_DOM_RE =
	/\b(?:cf-turnstile|cf-turnstile-response|turnstile\.render|challenges\.cloudflare\.com\/turnstile)\b/i;
const CHALLENGE_CF_DOM_RE =
	/\b(?:just\s+a\s+moment\.\.\.|_cf_chl_opt|cf-browser-verification|cdn-cgi\/challenge-platform|enable\s+javascript\s+and\s+cookies\s+to\s+continue|checking\s+if\s+the\s+site\s+connection\s+is\s+secure)\b/i;
const CHALLENGE_HCAPTCHA_DOM_RE = /\b(?:class=["'][^"']*h-captcha|data-hcaptcha-response|hcaptcha\.com\/1\/api\.js)\b/i;
const CHALLENGE_RECAPTCHA_DOM_RE = /\b(?:class=["'][^"']*g-recaptcha|g-recaptcha-response|recaptcha\/api\.js)\b/i;
const CHALLENGE_AWS_DOM_RE = /\b(?:aws-waf-captcha|awswaf\.com\/|x-amzn-waf-action)\b/i;
const CHALLENGE_DATADOME_DOM_RE = /\b(?:geo\.captcha-delivery\.com|datadome)\b/i;
const CHALLENGE_AKAMAI_DOM_RE = /\b(?:_abck|ak_bmsc|akamai\s+bot\s+manager)\b/i;
const SITEKEY_ATTR_RE = /\bdata-sitekey=["']([A-Za-z0-9._-]{8,128})["']/i;
const ERR_FAILED_RE = /\bnet::ERR_FAILED\b/i;

const COOKIE_ATTR_SKIP = new Set([
	"path",
	"domain",
	"expires",
	"max-age",
	"samesite",
	"secure",
	"httponly",
	"priority",
	"partitioned",
	"version",
]);

function readHeaderValue(headers: HeaderBagLike | undefined, name: string): string {
	if (!headers) return "";
	const target = name.toLowerCase();
	if (typeof (headers as { get?: unknown }).get === "function") {
		return String((headers as { get(k: string): string | null }).get(name) ?? "").trim();
	}
	for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
		if (k.toLowerCase() !== target || v === undefined) continue;
		return Array.isArray(v) ? v.join(", ").trim() : String(v).trim();
	}
	return "";
}

/**
 * 构建合规的 Chromium 启动参数配置（#37）：
 * - 支持持久化 `--user-data-dir` 会话目录（优先使用 Playwright `launchPersistentContext`）；
 * - 支持可配置 `headless`、`useXvfb` 与 `display`（如 `:99`）参数；
 * - 严禁注入任何绕过/反检测/自动破解人机验证的参数或脚本。
 */
export function buildChromiumLaunchConfig(
	opts?: Pick<SpaReconOptions, "userDataDir" | "headless" | "useXvfb" | "display" | "proxyServer">,
	baseEnv: Record<string, string | undefined> = process.env,
): ChromiumLaunchConfig {
	const rawUserDataDir = String(opts?.userDataDir ?? baseEnv.NUWA_BROWSER_USER_DATA_DIR ?? "").trim();
	if (rawUserDataDir && /[\r\n\0]/.test(rawUserDataDir)) {
		throw new Error("非法 userDataDir：禁止包含控制字符");
	}
	const userDataDir = rawUserDataDir ? resolve(rawUserDataDir) : undefined;

	const envUseXvfb = ["1", "true", "yes"].includes(String(baseEnv.NUWA_BROWSER_USE_XVFB ?? "").trim().toLowerCase());
	const useXvfb = opts?.useXvfb !== undefined ? Boolean(opts.useXvfb) : envUseXvfb;

	const rawDisplay = String(
		opts?.display ?? baseEnv.NUWA_BROWSER_DISPLAY ?? (useXvfb ? baseEnv.DISPLAY || ":99" : ""),
	).trim();
	const display = rawDisplay && !/[\r\n\0\s]/.test(rawDisplay) ? rawDisplay : useXvfb ? ":99" : undefined;

	// 启用 Xvfb 且未显式指定 headless 时，默认使用有头模式配合虚拟显示
	const headless = opts?.headless !== undefined ? Boolean(opts.headless) : !useXvfb;

	const args: string[] = ["--no-sandbox", "--disable-gpu"];
	if (userDataDir) {
		args.push(`--user-data-dir=${userDataDir}`);
	}

	const env: Record<string, string> = {};
	if (display) {
		env.DISPLAY = display;
	}

	const rawProxy = String(opts?.proxyServer ?? "").trim();
	const proxyServer = rawProxy && !/[\r\n\0\s]/.test(rawProxy) ? rawProxy : undefined;

	return {
		headless,
		args,
		...(userDataDir ? { userDataDir } : {}),
		usePersistentContext: Boolean(userDataDir),
		useXvfb,
		...(display ? { display } : {}),
		...(proxyServer ? { proxyServer } : {}),
		env,
		...(useXvfb
			? { xvfbPrefix: ["xvfb-run", "-a", "--server-args=-screen 0 1280x800x24"] }
			: {}),
	};
}

/**
 * 确定性挑战门 / CAPTCHA / Turnstile 识别器（#37 / NW-17）：
 * - 识别 `cf-mitigated: challenge`、`challenges.cloudflare.com/turnstile`、Turnstile/Cloudflare/hCaptcha/reCAPTCHA DOM、
 *   以及针对挑战域或连续 `net::ERR_FAILED` 失败；
 * - 严格遵守合规安全红线：**仅识别并立即停止盲目重试**，返回 `{ status: "challenge_gated", requiresHumanSession: true, provider }`
 *   引导人工完成验证后通过 `session-vault` 复用合法会话凭据，绝不执行任何点击/计算/绕过动作。
 */
export function detectChallengeGate(input: ChallengeGateInput): ChallengeGateDetection {
	const signals: string[] = [];
	let provider: ChallengeProvider | undefined;

	const setProvider = (cand: ChallengeProvider) => {
		// cloudflare_turnstile 优先级高于泛化的 cloudflare_challenge / generic_challenge
		if (!provider) {
			provider = cand;
			return;
		}
		if (provider === "generic_challenge" || (provider === "cloudflare_challenge" && cand === "cloudflare_turnstile")) {
			provider = cand;
		}
	};

	const status = typeof input.status === "number" ? input.status : undefined;
	const html = String(input.html ?? input.body ?? "");
	const title = String(input.title ?? "");
	const errorText = String(input.error ?? "");
	const combinedText = `${title}\n${html}`;

	// 1. 响应头检测
	const cfMitigated = readHeaderValue(input.headers, "cf-mitigated");
	if (/challenge/i.test(cfMitigated)) {
		signals.push(`header:cf-mitigated=${cfMitigated}`);
		setProvider("cloudflare_challenge");
	}
	const amznAction = readHeaderValue(input.headers, "x-amzn-waf-action");
	if (/challenge|captcha/i.test(amznAction)) {
		signals.push(`header:x-amzn-waf-action=${amznAction}`);
		setProvider("aws_waf_captcha");
	}
	const datadomeHdr = readHeaderValue(input.headers, "x-datadome");
	if (/protected/i.test(datadomeHdr)) {
		signals.push(`header:x-datadome=${datadomeHdr}`);
		setProvider("datadome");
	}

	// 2. 观测 URL 与失败请求检测
	const allUrls: string[] = [];
	if (input.url) allUrls.push(input.url);
	for (const u of input.observedUrls ?? []) {
		if (u) allUrls.push(u);
	}
	let errFailedCount = ERR_FAILED_RE.test(errorText) ? 1 : 0;
	let challengeFailedCount = 0;

	for (const fr of input.failedRequests ?? []) {
		if (fr.url) allUrls.push(fr.url);
		const isErrFailed = Boolean(fr.errorText && ERR_FAILED_RE.test(fr.errorText));
		if (isErrFailed) errFailedCount += 1;
		if (
			CHALLENGE_TURNSTILE_URL_RE.test(fr.url) ||
			CHALLENGE_CF_PLATFORM_URL_RE.test(fr.url) ||
			CHALLENGE_HCAPTCHA_URL_RE.test(fr.url) ||
			CHALLENGE_RECAPTCHA_URL_RE.test(fr.url)
		) {
			if (isErrFailed || fr.status === 403 || fr.status === 503) {
				challengeFailedCount += 1;
			}
		}
	}

	for (const u of allUrls) {
		if (CHALLENGE_TURNSTILE_URL_RE.test(u)) {
			signals.push("url:challenges.cloudflare.com/turnstile");
			setProvider("cloudflare_turnstile");
		} else if (CHALLENGE_CF_PLATFORM_URL_RE.test(u)) {
			signals.push("url:cloudflare_challenge_platform");
			setProvider("cloudflare_challenge");
		} else if (CHALLENGE_HCAPTCHA_URL_RE.test(u)) {
			signals.push("url:hcaptcha");
			setProvider("hcaptcha");
		} else if (CHALLENGE_RECAPTCHA_URL_RE.test(u)) {
			signals.push("url:recaptcha");
			setProvider("recaptcha");
		}
	}

	// 3. DOM / HTML 特征检测
	if (CHALLENGE_TURNSTILE_DOM_RE.test(combinedText)) {
		signals.push("dom:cloudflare_turnstile");
		setProvider("cloudflare_turnstile");
	}
	if (CHALLENGE_CF_DOM_RE.test(combinedText)) {
		signals.push("dom:cloudflare_challenge");
		setProvider("cloudflare_challenge");
	}
	if (CHALLENGE_HCAPTCHA_DOM_RE.test(combinedText)) {
		signals.push("dom:hcaptcha");
		setProvider("hcaptcha");
	}
	if (CHALLENGE_RECAPTCHA_DOM_RE.test(combinedText)) {
		signals.push("dom:recaptcha");
		setProvider("recaptcha");
	}
	if (CHALLENGE_AWS_DOM_RE.test(combinedText)) {
		signals.push("dom:aws_waf_captcha");
		setProvider("aws_waf_captcha");
	}
	if (CHALLENGE_DATADOME_DOM_RE.test(combinedText) && (status === 403 || /captcha/i.test(combinedText))) {
		signals.push("dom:datadome");
		setProvider("datadome");
	}
	if (CHALLENGE_AKAMAI_DOM_RE.test(combinedText) && (status === 403 || /challenge|bot\s+manager/i.test(combinedText))) {
		signals.push("dom:akamai_bot_manager");
		setProvider("akamai_bot_manager");
	}

	// 4. 连续 net::ERR_FAILED 或挑战域失败立即触发停止重试信号
	if (challengeFailedCount > 0) {
		signals.push(`failed:challenge_net_err(${challengeFailedCount})`);
		setProvider("cloudflare_turnstile");
	} else if (errFailedCount >= 2) {
		signals.push(`failed:repeated_net_err_failed(${errFailedCount})`);
		setProvider("generic_challenge");
	} else if (errFailedCount === 1 && (signals.length > 0 || status === 403 || status === 503)) {
		signals.push("failed:net_err_failed_with_challenge_context");
		setProvider("generic_challenge");
	}

	const uniqSignals = [...new Set(signals)];
	if (uniqSignals.length === 0) {
		return {
			detected: false,
			status: "clear",
			requiresHumanSession: false,
			signals: [],
			retryAllowed: true,
			guidance: "",
		};
	}

	const siteKeyMatch = SITEKEY_ATTR_RE.exec(combinedText);
	const resolvedProvider = provider ?? "generic_challenge";
	return {
		detected: true,
		status: "challenge_gated",
		requiresHumanSession: true,
		provider: resolvedProvider,
		...(siteKeyMatch?.[1] ? { siteKey: siteKeyMatch[1] } : {}),
		signals: uniqSignals,
		retryAllowed: false,
		guidance:
			`检测到 ${resolvedProvider} 人机验证挑战门，已立即中止盲目重试。` +
			`请在合规可见浏览器（可配合 --user-data-dir 与 Xvfb）中由人工完成验证，并将合法 Cookie/Header 存入 session-vault 后复用继续侦察。`,
	};
}

/** 将 HTTP Cookie 头字符串解析为 Playwright `addCookies` 所需的标准 Cookie 条目数组。 */
export function parseCookieHeaderToEntries(cookieHeader: string, targetUrl?: string): BrowserCookieEntry[] {
	const raw = String(cookieHeader ?? "").trim();
	if (!raw) return [];
	let baseUrl: string | undefined;
	if (targetUrl) {
		try {
			const u = new URL(targetUrl);
			baseUrl = `${u.protocol}//${u.host}/`;
		} catch {
			baseUrl = undefined;
		}
	}
	const out: BrowserCookieEntry[] = [];
	const seen = new Set<string>();
	for (const part of raw.split(";")) {
		const seg = part.trim();
		if (!seg) continue;
		const eq = seg.indexOf("=");
		if (eq <= 0) continue;
		const name = seg.slice(0, eq).trim();
		const value = seg.slice(eq + 1).trim();
		if (!name || !value || COOKIE_ATTR_SKIP.has(name.toLowerCase())) continue;
		if (seen.has(name)) continue;
		seen.add(name);
		out.push({
			name,
			value,
			...(baseUrl ? { url: baseUrl } : { path: "/" }),
		});
	}
	return out;
}

/**
 * 从 `session-vault` 导入用户手动完成人机验证/登录后保存的合法 Cookie 与 HTTP Header，
 * 供 `runSpaRecon` 在后续浏览器与静态侦察中直接复用（#37）。
 */
export function loadHumanSessionFromVault(
	vaultRoot: string,
	role: string,
	targetUrl?: string,
): {
	found: boolean;
	role: string;
	headers: Record<string, string>;
	cookies: BrowserCookieEntry[];
} {
	const normRole = String(role ?? "").trim().toLowerCase();
	if (!vaultRoot || !normRole) {
		return { found: false, role: normRole, headers: {}, cookies: [] };
	}
	const vault = loadSessionVault(vaultRoot);
	const headers = getRoleHeadersMap(vault, normRole);
	if (!headers) {
		return { found: false, role: normRole, headers: {}, cookies: [] };
	}
	const cookieEntry = Object.entries(headers).find(([k]) => k.toLowerCase() === "cookie");
	const cookies = cookieEntry?.[1] ? parseCookieHeaderToEntries(cookieEntry[1], targetUrl) : [];
	return {
		found: true,
		role: normRole,
		headers,
		cookies,
	};
}

/**
 * 将用户手动完成验证后获得的合法 Cookie/Header 保存至 `session-vault`（权限 0o600），
 * 便于跨轮次侦察复用（绝不自动绕过或伪造凭据）。
 */
export function saveHumanSessionToVault(
	vaultRoot: string,
	input: {
		role: string;
		cookie?: string;
		cookies?: ReadonlyArray<{ name: string; value: string }>;
		bearer?: string;
		headers?: Record<string, string>;
		note?: string;
		checkUrl?: string;
		expiresAt?: string;
	},
): SessionRoleEntry {
	const cookieFromList =
		!input.cookie && Array.isArray(input.cookies) && input.cookies.length > 0
			? input.cookies
					.filter((c) => c && c.name && c.value)
					.map((c) => `${c.name.trim()}=${c.value.trim()}`)
					.join("; ")
			: undefined;
	const cookie = input.cookie?.trim() || cookieFromList;
	return upsertSessionRole(vaultRoot, {
		role: input.role,
		...(cookie ? { cookie } : {}),
		...(input.bearer ? { bearer: input.bearer } : {}),
		...(input.headers ? { headers: input.headers } : {}),
		...(input.note ? { note: input.note } : {}),
		...(input.checkUrl ? { checkUrl: input.checkUrl } : {}),
		...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
	});
}

async function tryLoadPlaywright(customLoader?: () => Promise<PlaywrightLike | null>): Promise<PlaywrightLike | null> {
	if (customLoader) {
		try {
			return await customLoader();
		} catch {
			return null;
		}
	}
	const candidates = ["playwright", "playwright-core"];
	for (const modName of candidates) {
		try {
			const loaded = (await import(modName)) as Partial<PlaywrightLike> & { default?: Partial<PlaywrightLike> };
			const pw = loaded.chromium ? loaded : loaded.default;
			if (pw && typeof pw.chromium?.launch === "function") {
				return pw as PlaywrightLike;
			}
		} catch {
			/* 模块未安装则继续尝试下一个候选 */
		}
	}
	return null;
}

interface PageDomSnapshot {
	html?: string;
	title?: string;
	pathname?: string;
	hash?: string;
	links?: string[];
	globals?: string[];
}

function mergeAuthHeaders(
	fromVault: Record<string, string>,
	explicit?: Record<string, string>,
): Record<string, string> {
	const merged: Record<string, string> = {};
	const seenLower = new Map<string, string>();
	const put = (source?: Record<string, string>) => {
		if (!source) return;
		for (const [k, v] of Object.entries(source)) {
			const cleanK = String(k ?? "").replace(/[\r\n]+/g, " ").trim();
			const cleanV = String(v ?? "").replace(/[\r\n]+/g, " ").trim();
			if (!cleanK || !cleanV) continue;
			const lower = cleanK.toLowerCase();
			const prevKey = seenLower.get(lower);
			if (prevKey && prevKey !== cleanK) {
				delete merged[prevKey];
			}
			seenLower.set(lower, cleanK);
			merged[cleanK] = cleanV;
		}
	};
	put(fromVault);
	put(explicit);
	return merged;
}

/**
 * 执行 SPA 与 JS Bundle 动态/静态 API 感知：
 * - 支持从 `session-vault` 加载人工完成验证后的合法 Cookie/Header；
 * - 模式 A（Playwright 受控浏览器）：支持持久化 `--user-data-dir`、`headless` / `useXvfb` / `display`；
 * - 命中 Turnstile/CAPTCHA 挑战门或连续 `net::ERR_FAILED` 立即中止重试并返回结构化 `challenge_gated`；
 * - 集成 `detectSoft404` 阻断软 404 页面污染前端路由与端点清单；
 * - 若 Playwright 或 Chromium 不可用（或显式关闭），自动回退模式 B（静态 HTML + 最多 8 个同源 JS Bundle）。
 */
export async function runSpaRecon(
	url: string,
	scope: ScopePolicy,
	opts?: SpaReconOptions,
): Promise<SpaReconResult> {
	let parsedUrl: URL;
	try {
		parsedUrl = new URL(url);
	} catch {
		return {
			url,
			mode: "static",
			status: "error",
			fallbackReason: "目标 URL 非法",
			tech: [],
			routes: [],
			endpoints: [],
			bundles: [],
			blockedRequests: 1,
			fact: null,
		};
	}

	if (!isHostInScope(parsedUrl.hostname, scope).ok) {
		return {
			url: parsedUrl.href,
			mode: "static",
			status: "error",
			fallbackReason: `目标主机 ${parsedUrl.hostname} 超出允许范围 (ScopePolicy)`,
			tech: [],
			routes: [],
			endpoints: [],
			bundles: [],
			blockedRequests: 1,
			fact: null,
		};
	}

	const timeoutMs = Math.max(1_000, Math.min(60_000, opts?.timeoutMs ?? 15_000));
	const maxBundles = Math.min(MAX_STATIC_BUNDLES, Math.max(0, Math.floor(opts?.maxBundles ?? MAX_STATIC_BUNDLES)));
	const forceStatic =
		Boolean(opts?.disablePlaywright) ||
		opts?.preferBrowser === false ||
		(process.env.NUWA_SPA_MODE ?? "").trim().toLowerCase() === "static";

	// 合并来自 session-vault 与显式参数的合法会话 Cookie / Header
	const effectiveRole = opts?.sessionRole ?? opts?.authRole;
	const vaultSession =
		opts?.vaultRoot && effectiveRole
			? loadHumanSessionFromVault(opts.vaultRoot, effectiveRole, parsedUrl.href)
			: { found: false, role: effectiveRole ?? "", headers: {} as Record<string, string>, cookies: [] as BrowserCookieEntry[] };
	const effectiveAuthHeaders = mergeAuthHeaders(vaultSession.headers, opts?.authHeaders);
	const hasEffectiveHeaders = Object.keys(effectiveAuthHeaders).length > 0;
	const effectiveCookies: BrowserCookieEntry[] = [
		...vaultSession.cookies,
		...(opts?.cookies ?? []).map((c) => ({
			...c,
			...(!c.url && !c.domain ? { url: `${parsedUrl.protocol}//${parsedUrl.host}/` } : {}),
		})),
	];

	const safeRedact = (text: string | undefined): string | undefined => {
		if (!text) return text;
		return opts?.vaultRoot ? redactVaultSecrets(text, opts.vaultRoot) : text;
	};

	const launchCfg = buildChromiumLaunchConfig(opts);
	const launchSummary = {
		headless: launchCfg.headless,
		...(launchCfg.userDataDir ? { userDataDir: launchCfg.userDataDir } : {}),
		useXvfb: launchCfg.useXvfb,
		...(launchCfg.display ? { display: launchCfg.display } : {}),
		usePersistentContext: launchCfg.usePersistentContext,
	};

	let fallbackReason: string | undefined;

	// 模式 A：Playwright 受控浏览器动态感知
	if (!forceStatic && !opts?.signal?.aborted) {
		const pw = await tryLoadPlaywright(opts?.playwrightLoader);
		if (!pw) {
			fallbackReason = "本地未检测到 Playwright 运行时，自动回退静态 Bundle 感知";
		} else {
			let browser: PlaywrightBrowserLike | null = null;
			let context: PlaywrightContextLike | null = null;
			let page: PlaywrightPageLike | null = null;

			const observedChallengeUrls: string[] = [];
			const failedRequests: Array<{ url: string; errorText?: string; status?: number }> = [];
			let lastResponseStatus: number | undefined;
			let lastResponseHeaders: HeaderBagLike | undefined;

			try {
				const extraLaunchFields: { env?: Record<string, string>; proxy?: { server: string } } = {
					...(Object.keys(launchCfg.env).length > 0 ? { env: launchCfg.env } : {}),
					...(launchCfg.proxyServer ? { proxy: { server: launchCfg.proxyServer } } : {}),
				};

				if (launchCfg.userDataDir && typeof pw.chromium.launchPersistentContext === "function") {
					context = await pw.chromium.launchPersistentContext(launchCfg.userDataDir, {
						headless: launchCfg.headless,
						args: launchCfg.args,
						...extraLaunchFields,
						ignoreHTTPSErrors: true,
						...(hasEffectiveHeaders ? { extraHTTPHeaders: { ...effectiveAuthHeaders } } : {}),
					});
					const existingPages = typeof context.pages === "function" ? context.pages() : [];
					page = existingPages[0] ?? (await context.newPage());
				} else {
					browser = await pw.chromium.launch({
						headless: launchCfg.headless,
						args: launchCfg.args,
						...extraLaunchFields,
					});
					context = await browser.newContext({
						ignoreHTTPSErrors: true,
						...(hasEffectiveHeaders ? { extraHTTPHeaders: { ...effectiveAuthHeaders } } : {}),
					});
					page = await context.newPage();
				}

				if (effectiveCookies.length > 0 && typeof context.addCookies === "function") {
					await context.addCookies(effectiveCookies);
				}

				const endpointMap = new Map<string, SpaApiEndpoint>();
				const routeSet = new Set<string>();
				let blockedRequests = 0;

				if (typeof page.on === "function") {
					page.on("requestfailed", (reqLike: PlaywrightRequestLike) => {
						const failedUrl = typeof reqLike?.url === "function" ? reqLike.url() : "";
						const errTxt = typeof reqLike?.failure === "function" ? reqLike.failure()?.errorText : undefined;
						if (failedUrl) {
							failedRequests.push({ url: failedUrl, ...(errTxt ? { errorText: errTxt } : {}) });
						}
					});
					page.on("response", (respLike: PlaywrightResponseLike) => {
						const st = typeof respLike?.status === "function" ? respLike.status() : undefined;
						const hdrs = typeof respLike?.headers === "function" ? respLike.headers() : undefined;
						const respUrl = typeof respLike?.url === "function" ? respLike.url() : "";
						if (respUrl === parsedUrl.href || (hdrs && /challenge/i.test(readHeaderValue(hdrs, "cf-mitigated")))) {
							if (st !== undefined) lastResponseStatus = st;
							if (hdrs) lastResponseHeaders = hdrs;
						}
					});
				}

				await page.route("**/*", async (route) => {
					const req = route.request();
					const reqUrlStr = req.url();
					const method = String(req.method() || "GET").toUpperCase();
					const resourceType = String(req.resourceType() || "").toLowerCase();

					if (/^(?:data|blob|about):/i.test(reqUrlStr)) {
						await route.continue();
						return;
					}

					// 观测挑战门脚本/平台域（绝不绕过，仅记录以便触发确定性 challenge_gated）
					if (
						CHALLENGE_TURNSTILE_URL_RE.test(reqUrlStr) ||
						CHALLENGE_CF_PLATFORM_URL_RE.test(reqUrlStr) ||
						CHALLENGE_HCAPTCHA_URL_RE.test(reqUrlStr) ||
						CHALLENGE_RECAPTCHA_URL_RE.test(reqUrlStr)
					) {
						observedChallengeUrls.push(reqUrlStr);
					}

					let reqUrl: URL;
					try {
						reqUrl = new URL(reqUrlStr);
					} catch {
						blockedRequests++;
						await route.abort("blockedbyclient");
						return;
					}

					// 范围护栏：严格拦截任何非 ScopePolicy 允许域名的请求
					if (!isHostInScope(reqUrl.hostname, scope).ok) {
						blockedRequests++;
						await route.abort("blockedbyclient");
						return;
					}

					// 在只读放行/阻断前，记录范围内 XHR / Fetch / GraphQL / API 接口契约
					const normPath = normalizeApiPath(reqUrl.pathname);
					const isApiLike =
						resourceType === "xhr" ||
						resourceType === "fetch" ||
						Boolean(normPath && (isGraphqlPath(normPath) || /^\/(?:api|v[1-9]\d*|rest|rpc)\b/i.test(normPath)));

					if (isApiLike && normPath) {
						const queryKeys = uniqSorted(reqUrl.searchParams.keys());
						const postInfo = parsePostDataKeys(req.postData());
						mergeEndpoint(endpointMap, {
							method,
							path: normPath,
							url: `${reqUrl.origin}${normPath}`,
							queryKeys,
							bodyKeys: postInfo.bodyKeys,
							...(postInfo.isGraphql || isGraphqlPath(normPath) ? { isGraphql: true } : {}),
							...(postInfo.graphqlOperation ? { graphqlOperation: postInfo.graphqlOperation } : {}),
							source: "playwright",
						});
					}

					// 只读方法护栏：动态浏览仅放行 GET / HEAD / OPTIONS，禁止非只读写请求真正发出
					if (!ALLOWED_DYNAMIC_METHODS.has(method)) {
						blockedRequests++;
						await route.abort("blockedbyclient");
						return;
					}

					await route.continue();
				});

				// 导航执行：支持非挑战门有限重试，但一旦命中挑战门或连续 net::ERR_FAILED 立刻中止（绝不盲目重试）
				const maxRetries = Math.max(0, Math.min(3, Math.floor(opts?.maxRetries ?? 0)));
				let gotoResp: PlaywrightResponseLike | undefined;
				let navError: unknown = null;
				let errFailedStreak = 0;

				for (let attempt = 0; attempt <= maxRetries; attempt++) {
					try {
						const rawResp = (await page.goto(parsedUrl.href, {
							waitUntil: "networkidle",
							timeout: timeoutMs,
						})) as PlaywrightResponseLike | undefined;
						gotoResp = rawResp;
						navError = null;
						break;
					} catch (err) {
						navError = err;
						const errMsg = err instanceof Error ? err.message : String(err);
						if (ERR_FAILED_RE.test(errMsg)) {
							errFailedStreak += 1;
							failedRequests.push({ url: parsedUrl.href, errorText: errMsg });
						}
						const preCheck = detectChallengeGate({
							url: parsedUrl.href,
							status: lastResponseStatus,
							headers: lastResponseHeaders,
							error: errMsg,
							observedUrls: observedChallengeUrls,
							failedRequests,
						});
						if (preCheck.detected || errFailedStreak >= 2) {
							const gated: ChallengeGateDetection = preCheck.detected
								? preCheck
								: {
										detected: true,
										status: "challenge_gated",
										requiresHumanSession: true,
										provider: "generic_challenge",
										signals: [`failed:repeated_net_err_failed(${errFailedStreak})`],
										retryAllowed: false,
										guidance:
											"连续触发 net::ERR_FAILED（疑似边缘反自动化挑战门阻断），已立即中止重试。请通过人工浏览器会话完成验证并写入 session-vault 后复用。",
									};
							return {
								url: parsedUrl.href,
								mode: "playwright",
								status: "challenge_gated",
								requiresHumanSession: true,
								provider: gated.provider,
								challenge: gated,
								launchConfig: launchSummary,
								...(effectiveRole ? { sessionRole: effectiveRole } : {}),
								fallbackReason: safeRedact(gated.guidance),
								tech: [],
								routes: [],
								endpoints: [],
								bundles: [],
								blockedRequests,
								fact: null,
							};
						}
					}
				}

				if (navError) {
					throw navError;
				}

				const navStatus =
					(typeof gotoResp?.status === "function" ? gotoResp.status() : undefined) ?? lastResponseStatus ?? 200;
				const navHeaders =
					(typeof gotoResp?.headers === "function" ? gotoResp.headers() : undefined) ?? lastResponseHeaders;

				const snap = (await page.evaluate(() => {
					const g = globalThis as Record<string, unknown>;
					const doc = g.document as
						| {
								title?: string;
								documentElement?: { outerHTML?: string };
								querySelectorAll?: (sel: string) => ArrayLike<{ getAttribute(k: string): string | null }>;
								querySelector?: (sel: string) => unknown;
						  }
						| undefined;
					const loc = g.location as { pathname?: string; hash?: string } | undefined;
					const globals: string[] = [];
					if (g.__NEXT_DATA__ || doc?.querySelector?.("#__next")) globals.push("nextjs", "react");
					if (g.__REACT_DEVTOOLS_GLOBAL_HOOK__ || g.React || doc?.querySelector?.("[data-reactroot]")) {
						globals.push("react");
					}
					if (g.__NUXT__ || doc?.querySelector?.("#__nuxt")) globals.push("nuxt", "vue");
					if (g.__VUE__ || g.Vue || doc?.querySelector?.("[data-v-app]")) globals.push("vue");
					if (g.ng || g.getAllAngularRootElements || doc?.querySelector?.("[ng-version]")) {
						globals.push("angular");
					}
					const links: string[] = [];
					const anchors = doc?.querySelectorAll?.("a[href]") ?? [];
					for (let i = 0; i < anchors.length && i < 100; i++) {
						const href = anchors[i]?.getAttribute("href");
						if (href) links.push(href);
					}
					return {
						html: doc?.documentElement?.outerHTML ?? "",
						title: doc?.title ?? "",
						pathname: loc?.pathname ?? "",
						hash: loc?.hash ?? "",
						links,
						globals,
					};
				})) as PageDomSnapshot;

				const renderedHtml = snap?.html || (typeof page.content === "function" ? await page.content() : "") || "";

				// 确定性挑战门检测（页面响应头 + 渲染 DOM + 观测到的挑战资源）
				const domChallenge = detectChallengeGate({
					url: parsedUrl.href,
					status: navStatus,
					headers: navHeaders,
					html: renderedHtml,
					title: snap?.title,
					observedUrls: observedChallengeUrls,
					failedRequests,
				});
				if (domChallenge.detected) {
					return {
						url: parsedUrl.href,
						mode: "playwright",
						status: "challenge_gated",
						requiresHumanSession: true,
						provider: domChallenge.provider,
						challenge: domChallenge,
						launchConfig: launchSummary,
						...(effectiveRole ? { sessionRole: effectiveRole } : {}),
						fallbackReason: safeRedact(domChallenge.guidance),
						tech: [],
						routes: [],
						endpoints: [],
						bundles: [],
						blockedRequests,
						fact: null,
					};
				}

				// 软 404 检测（#33）：阻断 Next.js RSC 404 / 多语言软 404 污染前端路由与端点清单
				const softCheck = detectSoft404(
					{
						url: parsedUrl.href,
						path: parsedUrl.pathname,
						status: navStatus,
						body: renderedHtml,
						headers: navHeaders,
					},
					opts?.soft404Baseline,
				);
				if (softCheck.isSoft404) {
					return {
						url: parsedUrl.href,
						mode: "playwright",
						status: "soft_404",
						soft404: true,
						soft404Reasons: softCheck.reasons,
						launchConfig: launchSummary,
						...(effectiveRole ? { sessionRole: effectiveRole } : {}),
						tech: [],
						routes: [],
						endpoints: [],
						bundles: [],
						blockedRequests,
						fact: null,
					};
				}

				if (snap?.pathname) {
					const norm = normalizeApiPath(snap.pathname);
					if (norm) routeSet.add(norm);
				}
				if (snap?.hash && snap.hash.startsWith("#/")) {
					const norm = normalizeApiPath(snap.hash.slice(1));
					if (norm) routeSet.add(norm);
				}
				for (const href of snap?.links ?? []) {
					try {
						const u = new URL(href, parsedUrl);
						if (u.origin === parsedUrl.origin && isHostInScope(u.hostname, scope).ok) {
							const norm = normalizeApiPath(u.pathname);
							if (norm) routeSet.add(norm);
						}
					} catch {
						/* 忽略无效链接 */
					}
				}

				// 结合静态 HTML 与同源 JS Bundle 补充提取未在首屏触发的端点与路由
				const staticSuppl = renderedHtml
					? await extractStaticBundleApis(renderedHtml, parsedUrl.href, scope, opts?.fetchFn, {
							maxBundles,
							timeoutMs: Math.min(timeoutMs, 8_000),
							signal: opts?.signal,
							authHeaders: hasEffectiveHeaders ? effectiveAuthHeaders : undefined,
							authRole: effectiveRole,
							discoverSourceMaps: opts?.discoverSourceMaps,
						})
					: { tech: [], routes: [], endpoints: [], bundles: [], blockedRequests: 0, fact: null };

				for (const ep of staticSuppl.endpoints) mergeEndpoint(endpointMap, ep);
				for (const r of staticSuppl.routes) routeSet.add(r);
				blockedRequests += staticSuppl.blockedRequests;

				const tech = uniqSorted([...(snap?.globals ?? []), ...staticSuppl.tech]);
				const routes = [...routeSet].sort();
				const endpoints = [...endpointMap.values()].sort(
					(a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
				);
				const fact = buildSpaAutoFact(
					parsedUrl.href,
					"playwright",
					tech,
					routes,
					endpoints,
					staticSuppl.bundles.length,
					effectiveRole,
				);

				return {
					url: parsedUrl.href,
					mode: "playwright",
					status: "ok",
					launchConfig: launchSummary,
					...(effectiveRole ? { sessionRole: effectiveRole } : {}),
					tech,
					routes,
					endpoints,
					bundles: staticSuppl.bundles,
					blockedRequests,
					fact,
				};
			} catch (err) {
				const errMsg = err instanceof Error ? err.message : String(err);
				const errChallenge = detectChallengeGate({
					url: parsedUrl.href,
					status: lastResponseStatus,
					headers: lastResponseHeaders,
					error: errMsg,
					observedUrls: observedChallengeUrls,
					failedRequests,
				});
				if (errChallenge.detected) {
					return {
						url: parsedUrl.href,
						mode: "playwright",
						status: "challenge_gated",
						requiresHumanSession: true,
						provider: errChallenge.provider,
						challenge: errChallenge,
						launchConfig: launchSummary,
						...(effectiveRole ? { sessionRole: effectiveRole } : {}),
						fallbackReason: safeRedact(errChallenge.guidance),
						tech: [],
						routes: [],
						endpoints: [],
						bundles: [],
						blockedRequests: 0,
						fact: null,
					};
				}
				fallbackReason = safeRedact(`Playwright 执行失败，已回退静态模式: ${errMsg}`);
			} finally {
				await page?.close().catch(() => {});
				await context?.close().catch(() => {});
				await browser?.close().catch(() => {});
			}
		}
	} else if (forceStatic) {
		fallbackReason = "已配置为静态 Bundle 感知模式";
	}

	// 模式 B：静态抓取首屏 HTML + 同源 JS Bundle 回退
	const fetcher = opts?.fetchFn ?? defaultFetchImpl();
	const controller = new AbortController();
	const onAbort = () => controller.abort();
	opts?.signal?.addEventListener("abort", onAbort, { once: true });
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	let html = "";
	let finalBaseUrl = parsedUrl.href;
	let staticStatus = 0;
	let staticHeaders: HeaderBagLike | undefined;
	try {
		const fetched = await scopedGetFetch(parsedUrl.href, scope, fetcher, {
			headers: mergeHeadersWithAccept(
				"text/html,application/xhtml+xml,*/*",
				hasEffectiveHeaders ? effectiveAuthHeaders : undefined,
			),
			signal: controller.signal,
		});
		if (!fetched.ok) {
			if (fetched.blocked) {
				return {
					url: parsedUrl.href,
					mode: "static",
					status: "error",
					fallbackReason: safeRedact(fallbackReason ? `${fallbackReason}；${fetched.reason}` : fetched.reason),
					tech: [],
					routes: [],
					endpoints: [],
					bundles: [],
					blockedRequests: 1,
					fact: null,
				};
			}
			return {
				url: parsedUrl.href,
				mode: "static",
				status: "error",
				fallbackReason: safeRedact(
					fallbackReason ? `${fallbackReason}；首屏抓取失败: ${fetched.error}` : `首屏抓取失败: ${fetched.error}`,
				),
				tech: [],
				routes: [],
				endpoints: [],
				bundles: [],
				blockedRequests: 0,
				fact: null,
			};
		}
		finalBaseUrl = fetched.finalUrl;
		const resp = fetched.response;
		staticStatus = resp.status;
		staticHeaders = resp.headers;
		if (resp.ok || (resp.status >= 200 && resp.status < 500)) {
			const raw = await resp.text();
			html = raw.length > MAX_BUNDLE_BYTES ? raw.slice(0, MAX_BUNDLE_BYTES) : raw;
		}
	} catch (err) {
		const fetchErr = err instanceof Error ? err.message : String(err);
		return {
			url: parsedUrl.href,
			mode: "static",
			status: "error",
			fallbackReason: safeRedact(
				fallbackReason ? `${fallbackReason}；首屏抓取失败: ${fetchErr}` : `首屏抓取失败: ${fetchErr}`,
			),
			tech: [],
			routes: [],
			endpoints: [],
			bundles: [],
			blockedRequests: 0,
			fact: null,
		};
	} finally {
		clearTimeout(timer);
		opts?.signal?.removeEventListener("abort", onAbort);
	}

	// 静态模式确定性挑战门检测（#37）：命中立刻中止 bundle 拉取并返回 challenge_gated
	const staticChallenge = detectChallengeGate({
		url: finalBaseUrl,
		status: staticStatus,
		headers: staticHeaders,
		html,
	});
	if (staticChallenge.detected) {
		return {
			url: parsedUrl.href,
			mode: "static",
			status: "challenge_gated",
			requiresHumanSession: true,
			provider: staticChallenge.provider,
			challenge: staticChallenge,
			...(effectiveRole ? { sessionRole: effectiveRole } : {}),
			fallbackReason: safeRedact(staticChallenge.guidance),
			tech: [],
			routes: [],
			endpoints: [],
			bundles: [],
			blockedRequests: 0,
			fact: null,
		};
	}

	// 静态模式软 404 阻断（#33）
	const staticSoft404 = detectSoft404(
		{
			url: finalBaseUrl,
			path: parsedUrl.pathname,
			status: staticStatus || 200,
			body: html,
			headers: staticHeaders,
		},
		opts?.soft404Baseline,
	);
	if (staticSoft404.isSoft404) {
		return {
			url: parsedUrl.href,
			mode: "static",
			status: "soft_404",
			soft404: true,
			soft404Reasons: staticSoft404.reasons,
			...(effectiveRole ? { sessionRole: effectiveRole } : {}),
			...(fallbackReason ? { fallbackReason } : {}),
			tech: [],
			routes: [],
			endpoints: [],
			bundles: [],
			blockedRequests: 0,
			fact: null,
		};
	}

	const extracted = await extractStaticBundleApis(html, finalBaseUrl, scope, fetcher, {
		maxBundles,
		timeoutMs: Math.min(timeoutMs, 8_000),
		signal: opts?.signal,
		authHeaders: hasEffectiveHeaders ? effectiveAuthHeaders : undefined,
		authRole: effectiveRole,
		discoverSourceMaps: opts?.discoverSourceMaps,
	});

	return {
		url: parsedUrl.href,
		mode: "static",
		status: "ok",
		...(effectiveRole ? { sessionRole: effectiveRole } : {}),
		...(fallbackReason ? { fallbackReason } : {}),
		tech: extracted.tech,
		routes: extracted.routes,
		endpoints: extracted.endpoints,
		bundles: extracted.bundles,
		blockedRequests: extracted.blockedRequests,
		fact: extracted.fact,
	};
}
