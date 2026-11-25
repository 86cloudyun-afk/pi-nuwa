/**
 * SPA 与 JS Bundle 动态/静态 API 感知层（v4.0）。
 *
 * - 模式 A（Playwright 受控无头页面）：通过请求拦截严格放行 `isHostInScope` 内的
 *   GET/HEAD/OPTIONS 只读请求，零副作用记录 XHR/Fetch/GraphQL 端点（方法、路径、查询键与 Body 键）、
 *   前端路由与 React/Vue/Next/Nuxt/Angular 技术栈。
 * - 模式 B（静态回退模式）：无 Playwright/Chromium 时自动回退，抓取首屏 HTML 与最多 8 个
 *   同源 JS Bundle，静态解析路由与 fetch/axios/XHR/GraphQL 接口并过滤静态资源后缀，
 *   产出统一 `AutoFact`（`kind: "endpoint"`）。
 *
 * 约束：仅允许引用 `./scope` 与 `import type` 引用 `./autoexec`，严禁运行时 `import ./nuwa`。
 */
import { isHostInScope, type ScopePolicy } from "./scope";
import type { AutoFact } from "./autoexec";

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

export interface SpaReconResult {
	url: string;
	mode: "playwright" | "static";
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
}

export interface PlaywrightRouteLike {
	request(): PlaywrightRequestLike;
	continue(): Promise<void>;
	abort(errorCode?: string): Promise<void>;
}

export interface PlaywrightPageLike {
	route(url: string, handler: (route: PlaywrightRouteLike) => Promise<void> | void): Promise<void>;
	goto(url: string, options?: { waitUntil?: string; timeout?: number }): Promise<unknown>;
	evaluate<T>(fn: () => T): Promise<T>;
	content?(): Promise<string>;
	close(): Promise<void>;
}

export interface PlaywrightContextLike {
	newPage(): Promise<PlaywrightPageLike>;
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
		launch(options?: { headless?: boolean; args?: string[] }): Promise<PlaywrightBrowserLike>;
	};
}

export interface SpaReconOptions {
	timeoutMs?: number;
	maxBundles?: number;
	disablePlaywright?: boolean;
	playwrightLoader?: () => Promise<PlaywrightLike | null>;
	fetchFn?: FetchLike;
	signal?: AbortSignal;
	/** 认证态只读探测附加请求头（绝不写入命令、日志或事实输出） */
	authHeaders?: Record<string, string>;
	/** 认证态角色标识（非敏感，用于标记产出事实来源） */
	authRole?: string;
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
	pathname?: string;
	hash?: string;
	links?: string[];
	globals?: string[];
}

/**
 * 执行 SPA 与 JS Bundle 动态/静态 API 感知：
 * - 优先尝试模式 A（Playwright 受控无头页面 + 只读范围请求拦截）；
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
		Boolean(opts?.disablePlaywright) || (process.env.NUWA_SPA_MODE ?? "").trim().toLowerCase() === "static";

	let fallbackReason: string | undefined;

	// 模式 A：Playwright 受控无头浏览器动态感知
	if (!forceStatic && !opts?.signal?.aborted) {
		const pw = await tryLoadPlaywright(opts?.playwrightLoader);
		if (!pw) {
			fallbackReason = "本地未检测到 Playwright 运行时，自动回退静态 Bundle 感知";
		} else {
			let browser: PlaywrightBrowserLike | null = null;
			let context: PlaywrightContextLike | null = null;
			let page: PlaywrightPageLike | null = null;

			try {
				browser = await pw.chromium.launch({
					headless: true,
					args: ["--no-sandbox", "--disable-gpu"],
				});
				const hasAuthHeaders = Boolean(opts?.authHeaders && Object.keys(opts.authHeaders).length > 0);
				context = await browser.newContext({
					ignoreHTTPSErrors: true,
					...(hasAuthHeaders ? { extraHTTPHeaders: { ...opts!.authHeaders } } : {}),
				});
				page = await context.newPage();

				const endpointMap = new Map<string, SpaApiEndpoint>();
				const routeSet = new Set<string>();
				let blockedRequests = 0;

				await page.route("**/*", async (route) => {
					const req = route.request();
					const reqUrlStr = req.url();
					const method = String(req.method() || "GET").toUpperCase();
					const resourceType = String(req.resourceType() || "").toLowerCase();

					if (/^(?:data|blob|about):/i.test(reqUrlStr)) {
						await route.continue();
						return;
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

				await page.goto(parsedUrl.href, { waitUntil: "networkidle", timeout: timeoutMs });

				const snap = (await page.evaluate(() => {
					const g = globalThis as Record<string, unknown>;
					const doc = g.document as
						| {
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
						pathname: loc?.pathname ?? "",
						hash: loc?.hash ?? "",
						links,
						globals,
					};
				})) as PageDomSnapshot;

				const renderedHtml = snap?.html || (typeof page.content === "function" ? await page.content() : "") || "";
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
							authHeaders: opts?.authHeaders,
							authRole: opts?.authRole,
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
					opts?.authRole,
				);

				return {
					url: parsedUrl.href,
					mode: "playwright",
					tech,
					routes,
					endpoints,
					bundles: staticSuppl.bundles,
					blockedRequests,
					fact,
				};
			} catch (err) {
				fallbackReason = `Playwright 执行失败，已回退静态模式: ${err instanceof Error ? err.message : String(err)}`;
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
	try {
		const fetched = await scopedGetFetch(parsedUrl.href, scope, fetcher, {
			headers: mergeHeadersWithAccept("text/html,application/xhtml+xml,*/*", opts?.authHeaders),
			signal: controller.signal,
		});
		if (!fetched.ok) {
			if (fetched.blocked) {
				return {
					url: parsedUrl.href,
					mode: "static",
					fallbackReason: fallbackReason ? `${fallbackReason}；${fetched.reason}` : fetched.reason,
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
				fallbackReason: fallbackReason
					? `${fallbackReason}；首屏抓取失败: ${fetched.error}`
					: `首屏抓取失败: ${fetched.error}`,
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
		if (resp.ok || (resp.status >= 200 && resp.status < 500)) {
			const raw = await resp.text();
			html = raw.length > MAX_BUNDLE_BYTES ? raw.slice(0, MAX_BUNDLE_BYTES) : raw;
		}
	} catch (err) {
		const fetchErr = err instanceof Error ? err.message : String(err);
		return {
			url: parsedUrl.href,
			mode: "static",
			fallbackReason: fallbackReason ? `${fallbackReason}；首屏抓取失败: ${fetchErr}` : `首屏抓取失败: ${fetchErr}`,
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

	const extracted = await extractStaticBundleApis(html, finalBaseUrl, scope, fetcher, {
		maxBundles,
		timeoutMs: Math.min(timeoutMs, 8_000),
		signal: opts?.signal,
		authHeaders: opts?.authHeaders,
		authRole: opts?.authRole,
		discoverSourceMaps: opts?.discoverSourceMaps,
	});

	return {
		url: parsedUrl.href,
		mode: "static",
		...(fallbackReason ? { fallbackReason } : {}),
		tech: extracted.tech,
		routes: extracted.routes,
		endpoints: extracted.endpoints,
		bundles: extracted.bundles,
		blockedRequests: extracted.blockedRequests,
		fact: extracted.fact,
	};
}
