/**
 * 女娲 v6.0 授权 HTTP 合规流量审计工作台（Traffic Workbench）。
 *
 * 核心职责：
 * 1. TrafficRecorder：将授权范围内的请求/响应结构化持久化至 `<root>/.nuwa/traffic/index.jsonl`（权限 0o600），
 *    强制对 Authorization、Cookie、Set-Cookie、X-API-Key、X-Auth-Token、敏感查询参数、JSON 凭据字段
 *    及 SessionVault 已知密钥执行完全脱敏（零明文泄露），支持只读 list / query / getById。
 * 2. replayTrafficSequence：多步有状态 HTTP 工作流重放器，每步发包前强制通过 checkScopeAndRisk / isHostInScope
 *    校验并拦截越界 30x 重定向（redirect: "manual"），自动维护内存 Cookie Jar，支持从响应头、Cookie 或
 *    JSON 路径（如 data.token、csrfToken）提取变量替换 `{{var}}`，支持可注入 fetchFn 与单步超时控制。
 * 3. runStructuredMutations：面向现代 Web/API 的纯只读合规契约差分校验器（全流程强 Scope 拦截 +
 *    并发硬上限 <= 8 + 超时保护 + Soft-404/基线哈希去噪），支持 idor_step、auth_strip、
 *    graphql_introspect、nextjs_rsc、race_probe 五类只读诊断模式。
 *
 * 约束：仅使用 `import type` 引用 `./types`，严禁运行时 import `./nuwa`。
 */
import { createHash, randomUUID } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
	computeBodyHash,
	computeTemplateFingerprint,
	detectSoft404,
	type Soft404Baseline,
	type Soft404BaselineInput,
} from "./autoexec";
import {
	checkScopeAndRisk,
	formatScopeBlockReason,
	isHostInScope,
} from "./scope";
import {
	getRoleHeadersMap,
	loadSessionVault,
	redactVaultSecrets,
	type SessionVault,
} from "./session-vault";
import type { Mode, ScopePolicy } from "./types";

/** 差分校验并发度硬上限（任何配置均不可突破 8）。 */
export const MAX_MUTATION_CONCURRENCY = 8 as const;

/** 单条流量记录保留的最大响应片段字符数。 */
const DEFAULT_MAX_BODY_SNIPPET_CHARS = 4096;

/** 默认单步 HTTP 超时时间（毫秒）。 */
const DEFAULT_STEP_TIMEOUT_MS = 8_000;

/** 默认允许安全跟随的同域/授权范围内最大重定向跳数。 */
const DEFAULT_MAX_REDIRECTS = 5;

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/** 必须强制完全脱敏的显式 HTTP 头集合（小写）。 */
const EXPLICIT_SENSITIVE_HEADERS = new Set([
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"x-auth-token",
	"x-access-token",
	"x-csrf-token",
	"x-xsrf-token",
	"csrf-token",
	"xsrf-token",
	"private-token",
	"x-vault-token",
	"x-session-token",
	"x-session-id",
	"api-key",
	"apikey",
	"x-amz-security-token",
	"x-goog-api-key",
]);

/** 标准非敏感 HTTP 头前缀/精确名白名单，防止宽泛关键字误伤常规协议头。 */
const SAFE_STANDARD_HEADERS = new Set([
	"accept",
	"accept-charset",
	"accept-encoding",
	"accept-language",
	"accept-ranges",
	"access-control-allow-credentials",
	"access-control-allow-headers",
	"access-control-allow-methods",
	"access-control-allow-origin",
	"access-control-expose-headers",
	"access-control-max-age",
	"access-control-request-headers",
	"access-control-request-method",
	"age",
	"allow",
	"alt-svc",
	"cache-control",
	"connection",
	"content-disposition",
	"content-encoding",
	"content-language",
	"content-length",
	"content-location",
	"content-range",
	"content-security-policy",
	"content-type",
	"date",
	"etag",
	"expect",
	"expires",
	"from",
	"host",
	"if-match",
	"if-modified-since",
	"if-none-match",
	"if-range",
	"if-unmodified-since",
	"keep-alive",
	"last-modified",
	"link",
	"origin",
	"pragma",
	"public-key-pins",
	"range",
	"referer",
	"referrer-policy",
	"retry-after",
	"rsc",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"sec-fetch-dest",
	"sec-fetch-mode",
	"sec-fetch-site",
	"sec-fetch-user",
	"sec-websocket-accept",
	"sec-websocket-extensions",
	"sec-websocket-key",
	"sec-websocket-protocol",
	"sec-websocket-version",
	"server",
	"strict-transport-security",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"upgrade-insecure-requests",
	"user-agent",
	"vary",
	"via",
	"warning",
	"www-authenticate",
	"x-content-type-options",
	"x-frame-options",
	"x-nextjs-cache",
	"x-nextjs-matched-path",
	"x-powered-by",
	"x-request-id",
	"x-xss-protection",
	"next-router-state-tree",
	"next-router-prefetch",
	"next-url",
]);

const SENSITIVE_HEADER_KEYWORD_RE =
	/(?:auth|token|key|secret|cookie|session|jwt|csrf|xsrf|pass|cred|sign|bearer|ticket)/i;

const COOKIE_META_ATTRS = new Set([
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

const GENERIC_NON_SECRET_WORDS = new Set([
	"1",
	"0",
	"true",
	"false",
	"null",
	"none",
	"on",
	"off",
	"yes",
	"no",
	"dark",
	"light",
	"auto",
	"en",
	"zh",
	"cn",
	"us",
	"zh-cn",
	"en-us",
	"lax",
	"strict",
	"get",
	"post",
	"put",
	"patch",
	"delete",
	"head",
	"options",
	"127.0.0.1",
	"localhost",
]);

const SENSITIVE_QUERY_PARAM_RE =
	/^(?:access_token|refresh_token|id_token|auth_token|api_key|apikey|token|secret|client_secret|password|passwd|pwd|auth|jwt|session|session_id|sid|csrf|csrf_token|xsrf|xsrf_token|sig|signature|ticket|private_token|key)$/i;

const SENSITIVE_JSON_FIELD_RE =
	/^(?:password|passwd|pwd|secret|clientSecret|client_secret|accessToken|access_token|refreshToken|refresh_token|idToken|id_token|apiKey|api_key|apiToken|api_token|authToken|auth_token|csrfToken|csrf_token|xsrfToken|xsrf_token|privateKey|private_key|sessionToken|session_token|token|bearer|jwt|authorization|cookie|setCookie|set_cookie|xApiKey|x_api_key)$/i;

const JWT_TOKEN_RE = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const BEARER_INLINE_RE = /\b(Bearer|Basic|Token|JWT)\s+([A-Za-z0-9._~+/=-]{6,})/gi;
const URL_USERINFO_RE = /\b(https?:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;
const QUERY_KV_SECRET_RE =
	/([?&](?:access_token|refresh_token|id_token|auth_token|api_key|apikey|token|secret|client_secret|password|passwd|pwd|jwt|session_id|private_token)=)([^&#\s"']+)/gi;

export const REDACTED_MARKER = "[REDACTED]" as const;

// ==================== 公共接口与类型定义 ====================

export interface TrafficFetchResponseLike {
	status: number;
	ok?: boolean;
	headers?:
		| Headers
		| Record<string, string | string[] | undefined>
		| {
				get(name: string): string | null;
				forEach?(cb: (value: string, key: string) => void): void;
				getSetCookie?(): string[];
		  };
	text(): Promise<string>;
}

export type TrafficFetchFn = (
	url: string,
	init?: {
		method?: string;
		headers?: Record<string, string>;
		body?: string;
		redirect?: "manual" | "follow" | "error";
		signal?: AbortSignal;
	},
) => Promise<TrafficFetchResponseLike>;

export interface TrafficRecordInput {
	id?: string;
	timestamp?: string;
	method: string;
	url: string;
	requestHeaders?: Record<string, string | string[] | undefined>;
	requestBody?: string;
	status: number;
	responseHeaders?: Record<string, string | string[] | undefined>;
	responseBody?: string;
	durationMs?: number;
	tags?: string[];
	role?: string;
	stepId?: string;
	note?: string;
}

export interface TrafficEntry {
	id: string;
	timestamp: string;
	method: string;
	url: string;
	host: string;
	path: string;
	requestHeaders: Record<string, string>;
	requestBody?: string;
	status: number;
	responseHeaders: Record<string, string>;
	responseBodySnippet?: string;
	responseBodyHash: string;
	responseBodyBytes: number;
	durationMs: number;
	tags: string[];
	role?: string;
	stepId?: string;
	note?: string;
}

export interface TrafficQueryFilter {
	host?: string;
	pathPrefix?: string;
	method?: string;
	status?: number;
	tag?: string;
	limit?: number;
}

export interface TrafficRecorderOptions {
	vault?: SessionVault;
	extraSecrets?: string[];
	maxBodySnippetChars?: number;
}

export interface TrafficExtractorSpec {
	/** 从响应头提取（大小写不敏感），例如 "x-csrf-token" */
	header?: string;
	/** 从 JSON 响应体按路径提取，例如 "data.token"、"csrfToken"、"items.0.id" */
	jsonPath?: string;
	/** 从当前 Cookie Jar 或响应 Set-Cookie 提取指定名称的 Cookie 值 */
	cookie?: string;
	/** 从响应文本通过正则提取（优先第 1 捕获组，否则取完整匹配） */
	regex?: string;
}

export interface TrafficReplayStep {
	id?: string;
	name?: string;
	method?: string;
	url: string;
	headers?: Record<string, string>;
	body?: string | Record<string, unknown>;
	/**
	 * 变量提取映射：
	 * - 支持结构化 TrafficExtractorSpec；
	 * - 支持简写字符串："header:x-csrf-token"、"cookie:sid" 或直接 JSON 路径 "data.csrfToken"。
	 */
	extract?: Record<string, string | TrafficExtractorSpec>;
	/** 是否自动跟随授权 Scope 内的 30x 重定向（默认 true；越界 Location 始终强制拦截）。 */
	followRedirects?: boolean;
	maxRedirects?: number;
	timeoutMs?: number;
	expectStatus?: number | number[];
	tags?: string[];
}

export interface ReplayStepResult {
	stepIndex: number;
	id: string;
	name?: string;
	method: string;
	resolvedUrl: string;
	finalUrl: string;
	status: number;
	ok: boolean;
	blocked: boolean;
	redirectBlocked?: boolean;
	timedOut?: boolean;
	blockReason?: string;
	error?: string;
	durationMs: number;
	redirectChain: string[];
	responseHeaders: Record<string, string>;
	responseBody: string;
	extracted: Record<string, string>;
	recordedEntryId?: string;
}

export interface ReplayTrafficOptions {
	fetchFn?: TrafficFetchFn;
	recorder?: TrafficRecorder;
	root?: string;
	mode?: Mode | string;
	initialVars?: Record<string, string>;
	initialCookies?: Record<string, string>;
	timeoutMs?: number;
	followRedirects?: boolean;
	maxRedirects?: number;
	continueOnError?: boolean;
	signal?: AbortSignal;
	tags?: string[];
}

export interface ReplayTrafficResult {
	ok: boolean;
	abortedByScope: boolean;
	blockedStepIndex?: number;
	blockReason?: string;
	steps: ReplayStepResult[];
	variables: Record<string, string>;
	cookies: Record<string, string>;
}

export type MutationMode =
	| "idor_step"
	| "auth_strip"
	| "graphql_introspect"
	| "nextjs_rsc"
	| "race_probe";

export interface MutationBaseRequest {
	method?: string;
	url: string;
	headers?: Record<string, string>;
	body?: string;
}

export interface MutationProbeSummary {
	label: string;
	method: string;
	url: string;
	status: number;
	bodyHash: string;
	templateHash: string;
	bodyBytes: number;
	isSoft404: boolean;
	blocked: boolean;
	blockReason?: string;
	timedOut?: boolean;
	durationMs: number;
}

export interface MutationCaseResult {
	mode: MutationMode;
	executed: boolean;
	anomalous: boolean;
	suppressedBySoft404: boolean;
	blockedByScope: boolean;
	severity: "high" | "medium" | "low" | "info";
	findingCode?: string;
	summary: string;
	evidence: Record<string, unknown>;
	probes: MutationProbeSummary[];
}

export interface MutationAnomaly {
	mode: MutationMode;
	findingCode: string;
	severity: "high" | "medium" | "low";
	method: string;
	url: string;
	path: string;
	summary: string;
	evidence: Record<string, unknown>;
}

export interface StructuredMutationsOptions {
	modes?: MutationMode[];
	fetchFn?: TrafficFetchFn;
	recorder?: TrafficRecorder;
	root?: string;
	vault?: SessionVault;
	lowPrivilegeRole?: string;
	lowPrivilegeHeaders?: Record<string, string>;
	idorCandidateIds?: Array<string | number>;
	graphqlPath?: string;
	raceCount?: number;
	concurrency?: number;
	timeoutMs?: number;
	mode?: Mode | string;
	soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null;
	autoSampleSoft404?: boolean;
	signal?: AbortSignal;
}

export interface StructuredMutationsResult {
	ok: boolean;
	blockedByScope: boolean;
	blockReason?: string;
	effectiveConcurrency: number;
	baseline?: {
		url: string;
		method: string;
		status: number;
		bodyHash: string;
		templateHash: string;
		bodyBytes: number;
		isSoft404: boolean;
	};
	results: Record<MutationMode, MutationCaseResult>;
	cases: MutationCaseResult[];
	anomalies: MutationAnomaly[];
}

// ==================== 内部工具与零明文脱敏实现 ====================

interface StoredCookie {
	name: string;
	value: string;
	domain?: string;
	path: string;
}

let recordCounter = 0;

function clampInt(val: unknown, fallback: number, min: number, max: number): number {
	if (val === Number.POSITIVE_INFINITY) return max;
	if (val === Number.NEGATIVE_INFINITY) return min;
	if (typeof val !== "number" || !Number.isFinite(val)) return fallback;
	return Math.max(min, Math.min(max, Math.floor(val)));
}

function isSensitiveHeaderName(headerName: string): boolean {
	const lower = headerName.trim().toLowerCase();
	if (!lower) return false;
	if (EXPLICIT_SENSITIVE_HEADERS.has(lower)) return true;
	if (SAFE_STANDARD_HEADERS.has(lower)) return false;
	if (lower.startsWith("sec-") || lower.startsWith("accept-") || lower.startsWith("content-") || lower.startsWith("access-control-")) {
		return false;
	}
	return SENSITIVE_HEADER_KEYWORD_RE.test(lower);
}

/**
 * 收集 Vault 及额外显式密钥的所有原始敏感串（含裸 Token、Cookie 值、Basic Base64 与 URL 编码变体），
 * 按长度降序返回，用于完全擦除为 `[REDACTED]`。
 */
function collectRawSecretsForZeroLeak(
	root?: string,
	vault?: SessionVault,
	extraSecrets?: string[],
): string[] {
	const set = new Set<string>();
	const addToken = (raw: string | undefined, minLen = 3) => {
		const s = String(raw ?? "").trim();
		if (!s || s.length < minLen) return;
		if (GENERIC_NON_SECRET_WORDS.has(s.toLowerCase())) {
			return;
		}
		set.add(s);
		try {
			const enc = encodeURIComponent(s);
			if (enc && enc.length >= minLen && !GENERIC_NON_SECRET_WORDS.has(enc.toLowerCase())) {
				set.add(enc);
			}
		} catch {
			/* 忽略编码异常 */
		}
	};

	const addCookiePairs = (cookieStr: string) => {
		for (const part of cookieStr.split(";")) {
			const seg = part.trim();
			if (!seg) continue;
			const eq = seg.indexOf("=");
			if (eq <= 0) continue;
			const k = seg.slice(0, eq).trim();
			const v = seg.slice(eq + 1).trim();
			if (!k || !v || COOKIE_META_ATTRS.has(k.toLowerCase())) continue;
			if (v.length >= 4 && !GENERIC_NON_SECRET_WORDS.has(v.toLowerCase())) {
				addToken(v, 4);
			}
		}
	};

	let resolvedVault = vault;
	if (!resolvedVault && root) {
		try {
			resolvedVault = loadSessionVault(root);
		} catch {
			resolvedVault = undefined;
		}
	}

	if (resolvedVault?.roles) {
		for (const entry of Object.values(resolvedVault.roles)) {
			if (!entry) continue;
			if (entry.cookie) addCookiePairs(entry.cookie);
			if (entry.bearer) {
				addToken(entry.bearer, 4);
				const bare = entry.bearer.replace(/^(?:Bearer|Basic|Token|JWT)\s+/i, "").trim();
				addToken(bare, 4);
			}
			if (entry.password) {
				addToken(entry.password, 3);
				if (entry.username) {
					const b64 = Buffer.from(`${entry.username}:${entry.password}`, "utf8").toString("base64");
					addToken(b64, 4);
				}
			}
			if (entry.headers) {
				for (const [hk, hv] of Object.entries(entry.headers)) {
					if (!hv) continue;
					if (hk.toLowerCase() === "cookie" || hk.toLowerCase() === "set-cookie") {
						addCookiePairs(hv);
					} else if (isSensitiveHeaderName(hk)) {
						addToken(hv, 4);
						const bare = hv.replace(/^(?:Bearer|Basic|Token|JWT)\s+/i, "").trim();
						addToken(bare, 4);
					}
				}
			}
		}
	}

	if (Array.isArray(extraSecrets)) {
		for (const sec of extraSecrets) {
			addToken(sec, 3);
		}
	}

	return [...set].sort((a, b) => b.length - a.length);
}

function scrubKnownSecrets(text: string, knownSecrets: string[], rootOrVault?: string | SessionVault): string {
	if (!text) return text;
	let out = text;
	for (const sec of knownSecrets) {
		if (sec && out.includes(sec)) {
			out = out.split(sec).join(REDACTED_MARKER);
		}
	}
	out = out
		.replace(URL_USERINFO_RE, `$1${REDACTED_MARKER}:${REDACTED_MARKER}@`)
		.replace(QUERY_KV_SECRET_RE, `$1${REDACTED_MARKER}`)
		.replace(BEARER_INLINE_RE, `$1 ${REDACTED_MARKER}`)
		.replace(JWT_TOKEN_RE, REDACTED_MARKER);
	if (rootOrVault) {
		out = redactVaultSecrets(out, rootOrVault);
	}
	return out;
}

function redactCookieHeaderValue(rawCookie: string): string {
	const trimmed = rawCookie.trim();
	if (!trimmed) return "";
	return trimmed
		.split(";")
		.map((part) => {
			const seg = part.trim();
			if (!seg) return "";
			const eq = seg.indexOf("=");
			if (eq <= 0) return REDACTED_MARKER;
			const name = seg.slice(0, eq).trim();
			if (!name) return REDACTED_MARKER;
			if (COOKIE_META_ATTRS.has(name.toLowerCase())) return seg;
			return `${name}=${REDACTED_MARKER}`;
		})
		.filter(Boolean)
		.join("; ");
}

function redactSetCookieHeaderValue(rawSetCookie: string): string {
	const lines = rawSetCookie.split(/\r?\n|\s*\|\|\s*/).filter(Boolean);
	return lines
		.map((line) => {
			const parts = line
				.split(";")
				.map((p) => p.trim())
				.filter(Boolean);
			if (parts.length === 0) return "";
			const first = parts[0]!;
			const eq = first.indexOf("=");
			const redactedFirst =
				eq > 0 ? `${first.slice(0, eq).trim()}=${REDACTED_MARKER}` : REDACTED_MARKER;
			const attrs = parts.slice(1).map((attr) => {
				const aEq = attr.indexOf("=");
				if (aEq <= 0) return attr;
				const aKey = attr.slice(0, aEq).trim();
				if (COOKIE_META_ATTRS.has(aKey.toLowerCase())) return attr;
				return `${aKey}=${REDACTED_MARKER}`;
			});
			return [redactedFirst, ...attrs].join("; ");
		})
		.filter(Boolean)
		.join(" | ");
}

/** 对 URL 执行零明文脱敏（擦除 userinfo、敏感查询参数及已知 Vault 密钥，同时保持其余查询参数完好）。 */
export function redactTrafficUrl(
	rawUrl: string,
	opts?: { root?: string; vault?: SessionVault; extraSecrets?: string[] },
): string {
	const knownSecrets = collectRawSecretsForZeroLeak(opts?.root, opts?.vault, opts?.extraSecrets);
	try {
		const u = new URL(rawUrl);
		const hadUser = Boolean(u.username || u.password);
		if (u.username) u.username = "REDACTED";
		if (u.password) u.password = "REDACTED";
		const keys = [...u.searchParams.keys()];
		for (const k of keys) {
			if (SENSITIVE_QUERY_PARAM_RE.test(k)) {
				u.searchParams.set(k, REDACTED_MARKER);
			} else {
				const vals = u.searchParams.getAll(k);
				const updated = vals.map((v) =>
					scrubKnownSecrets(v, knownSecrets, opts?.vault ?? opts?.root),
				);
				if (updated.some((nv, idx) => nv !== vals[idx])) {
					u.searchParams.delete(k);
					for (const nv of updated) u.searchParams.append(k, nv);
				}
			}
		}
		let serialized = u.toString();
		if (hadUser) {
			serialized = serialized.replace(URL_USERINFO_RE, `$1${REDACTED_MARKER}:${REDACTED_MARKER}@`);
		}
		// 将 URLSearchParams 编码的 %5BREDACTED%5D 还原为可读 [REDACTED]
		serialized = serialized.replace(/%5BREDACTED%5D/gi, REDACTED_MARKER);
		return scrubKnownSecrets(serialized, knownSecrets, opts?.vault ?? opts?.root);
	} catch {
		return scrubKnownSecrets(String(rawUrl ?? ""), knownSecrets, opts?.vault ?? opts?.root);
	}
}

/** 对 HTTP 请求头或响应头执行强制零明文脱敏。 */
export function redactTrafficHeaders(
	headers: Record<string, string | string[] | undefined> | undefined,
	opts?: { root?: string; vault?: SessionVault; extraSecrets?: string[] },
): Record<string, string> {
	if (!headers || typeof headers !== "object") return {};
	const knownSecrets = collectRawSecretsForZeroLeak(opts?.root, opts?.vault, opts?.extraSecrets);
	const out: Record<string, string> = {};

	for (const [rawKey, rawVal] of Object.entries(headers)) {
		if (rawVal === undefined) continue;
		const key = String(rawKey).trim();
		if (!key) continue;
		const lower = key.toLowerCase();
		const joinedVal = Array.isArray(rawVal) ? rawVal.join(lower === "set-cookie" ? "\n" : ", ") : String(rawVal);

		if (lower === "authorization" || lower === "proxy-authorization") {
			const m = /^(Bearer|Basic|Token|JWT|Digest)\s+/i.exec(joinedVal.trim());
			out[key] = m?.[1] ? `${m[1]} ${REDACTED_MARKER}` : REDACTED_MARKER;
			continue;
		}
		if (lower === "cookie") {
			out[key] = redactCookieHeaderValue(joinedVal);
			continue;
		}
		if (lower === "set-cookie") {
			out[key] = redactSetCookieHeaderValue(joinedVal);
			continue;
		}
		if (lower === "location") {
			out[key] = redactTrafficUrl(joinedVal, opts);
			continue;
		}
		if (isSensitiveHeaderName(key)) {
			out[key] = REDACTED_MARKER;
			continue;
		}
		out[key] = scrubKnownSecrets(joinedVal, knownSecrets, opts?.vault ?? opts?.root);
	}

	return out;
}

function redactJsonValueRecursive(
	val: unknown,
	knownSecrets: string[],
	rootOrVault?: string | SessionVault,
	depth = 0,
): unknown {
	if (depth > 12 || val === null || val === undefined) return val;
	if (typeof val === "string") {
		return scrubKnownSecrets(val, knownSecrets, rootOrVault);
	}
	if (Array.isArray(val)) {
		return val.map((item) => redactJsonValueRecursive(item, knownSecrets, rootOrVault, depth + 1));
	}
	if (typeof val === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
			if (SENSITIVE_JSON_FIELD_RE.test(k)) {
				out[k] = REDACTED_MARKER;
			} else {
				out[k] = redactJsonValueRecursive(v, knownSecrets, rootOrVault, depth + 1);
			}
		}
		return out;
	}
	return val;
}

/** 对请求体或响应体文本执行敏感 JSON 字段、表单凭据与 Vault 已知密钥完全脱敏。 */
export function redactTrafficBody(
	body: string | undefined,
	opts?: {
		root?: string;
		vault?: SessionVault;
		extraSecrets?: string[];
		maxChars?: number;
	},
): string | undefined {
	if (body === undefined) return undefined;
	const raw = String(body);
	if (!raw) return "";
	const knownSecrets = collectRawSecretsForZeroLeak(opts?.root, opts?.vault, opts?.extraSecrets);
	const rootOrVault = opts?.vault ?? opts?.root;

	let sanitized = raw;
	const trimmed = raw.trim();
	if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
		try {
			const parsed = JSON.parse(trimmed) as unknown;
			const redactedObj = redactJsonValueRecursive(parsed, knownSecrets, rootOrVault);
			sanitized = JSON.stringify(redactedObj);
		} catch {
			// 非严格 JSON 回退到正则文本脱敏（兼容双引号与单引号键值）
			sanitized = raw
				.replace(
					/("(?:password|passwd|pwd|secret|client_secret|access_token|accessToken|refresh_token|refreshToken|api_key|apiKey|auth_token|authToken|token|jwt|bearer|private_key|privateKey)"\s*:\s*)"[^"]*"/gi,
					`$1"${REDACTED_MARKER}"`,
				)
				.replace(
					/('(?:password|passwd|pwd|secret|client_secret|access_token|accessToken|refresh_token|refreshToken|api_key|apiKey|auth_token|authToken|token|jwt|bearer|private_key|privateKey)'\s*:\s*)'[^']*'/gi,
					`$1'${REDACTED_MARKER}'`,
				);
		}
	} else {
		// 处理 JSON 片段、单引号对象字面量或 application/x-www-form-urlencoded 敏感键值对
		sanitized = raw
			.replace(
				/("(?:password|passwd|pwd|secret|client_secret|access_token|accessToken|refresh_token|refreshToken|api_key|apiKey|auth_token|authToken|token|jwt|bearer|private_key|privateKey)"\s*:\s*)"[^"]*"/gi,
				`$1"${REDACTED_MARKER}"`,
			)
			.replace(
				/('(?:password|passwd|pwd|secret|client_secret|access_token|accessToken|refresh_token|refreshToken|api_key|apiKey|auth_token|authToken|token|jwt|bearer|private_key|privateKey)'\s*:\s*)'[^']*'/gi,
				`$1'${REDACTED_MARKER}'`,
			)
			.replace(
				/(^|[&\s])((?:password|passwd|pwd|secret|client_secret|access_token|refresh_token|api_key|apikey|auth_token|token|jwt)=)([^&\s"']+)/gi,
				`$1$2${REDACTED_MARKER}`,
			);
	}

	sanitized = scrubKnownSecrets(sanitized, knownSecrets, rootOrVault);
	const maxChars = opts?.maxChars ?? DEFAULT_MAX_BODY_SNIPPET_CHARS;
	if (maxChars > 0 && sanitized.length > maxChars) {
		return `${sanitized.slice(0, maxChars)}...[truncated]`;
	}
	return sanitized;
}

// ==================== 1. TrafficRecorder ====================

/**
 * 授权 HTTP 流量脱敏记录器：
 * 将请求与响应脱敏后追加写入 `<root>/.nuwa/traffic/index.jsonl`（文件权限 `0o600`），
 * 只读检索方法（`list` / `query` / `getById`）严格零磁盘写副作用。
 */
export class TrafficRecorder {
	public readonly root: string;
	public readonly indexPath: string;
	private readonly vault?: SessionVault;
	private readonly extraSecrets: string[];
	private readonly maxBodySnippetChars: number;

	constructor(root: string, opts?: TrafficRecorderOptions) {
		this.root = resolve(root);
		this.indexPath = join(this.root, ".nuwa", "traffic", "index.jsonl");
		this.vault = opts?.vault;
		this.extraSecrets = [...(opts?.extraSecrets ?? [])];
		this.maxBodySnippetChars = opts?.maxBodySnippetChars ?? DEFAULT_MAX_BODY_SNIPPET_CHARS;
	}

	/** 追加额外需强制完全擦除的运行时临时敏感值（如动态提取到的登录 Token）。 */
	public registerTransientSecret(secret: string): void {
		const trimmed = String(secret ?? "").trim();
		if (trimmed.length >= 4 && !this.extraSecrets.includes(trimmed)) {
			this.extraSecrets.push(trimmed);
		}
	}

	/** 将单次授权 HTTP 请求/响应脱敏后写入 `.nuwa/traffic/index.jsonl`。 */
	public record(input: TrafficRecordInput): TrafficEntry {
		const redactOpts = {
			root: this.root,
			vault: this.vault,
			extraSecrets: this.extraSecrets,
			maxChars: this.maxBodySnippetChars,
		};

		// 自动收集本次请求 URL userinfo 与敏感头中的原始凭据值，防止其在同条响应回显中明文残留
		const reqRawSecrets: string[] = [...this.extraSecrets];
		try {
			const rawParsed = new URL(input.url);
			if (rawParsed.password && rawParsed.password.length >= 3) {
				reqRawSecrets.push(decodeURIComponent(rawParsed.password));
			}
		} catch {
			/* ignore */
		}
		if (input.requestHeaders) {
			for (const [hk, hv] of Object.entries(input.requestHeaders)) {
				if (!hv || !isSensitiveHeaderName(hk)) continue;
				const strVal = Array.isArray(hv) ? hv.join("; ") : String(hv);
				if (hk.toLowerCase() === "cookie") {
					for (const seg of strVal.split(";")) {
						const eq = seg.indexOf("=");
						if (eq > 0) {
							const cv = seg.slice(eq + 1).trim();
							if (cv.length >= 4 && !GENERIC_NON_SECRET_WORDS.has(cv.toLowerCase())) {
								reqRawSecrets.push(cv);
							}
						}
					}
				} else {
					const bare = strVal.replace(/^(?:Bearer|Basic|Token|JWT)\s+/i, "").trim();
					if (bare.length >= 4 && !GENERIC_NON_SECRET_WORDS.has(bare.toLowerCase())) {
						reqRawSecrets.push(bare);
					}
				}
			}
		}
		if (input.responseHeaders) {
			for (const [hk, hv] of Object.entries(input.responseHeaders)) {
				if (!hv || hk.toLowerCase() !== "set-cookie") continue;
				const lines = Array.isArray(hv) ? hv : String(hv).split(/\r?\n/);
				for (const line of lines) {
					const first = line.split(";")[0]?.trim() ?? "";
					const eq = first.indexOf("=");
					if (eq > 0) {
						const cv = first.slice(eq + 1).trim();
						if (cv.length >= 4 && !GENERIC_NON_SECRET_WORDS.has(cv.toLowerCase())) {
							reqRawSecrets.push(cv);
						}
					}
				}
			}
		}
		redactOpts.extraSecrets = reqRawSecrets;

		const safeUrl = redactTrafficUrl(input.url, redactOpts);
		let host = "";
		let path = "/";
		try {
			const parsed = new URL(safeUrl);
			host = parsed.hostname.toLowerCase();
			path = `${parsed.pathname || "/"}${parsed.search || ""}`;
		} catch {
			host = "";
			path = safeUrl;
		}

		const rawRespBody = input.responseBody ?? "";
		const { bodyHash, bodyBytes } = computeBodyHash(rawRespBody);

		const id =
			input.id && input.id.trim()
				? input.id.trim()
				: `tx_${Date.now()}_${String(++recordCounter).padStart(4, "0")}`;

		const entry: TrafficEntry = {
			id,
			timestamp: input.timestamp ?? new Date().toISOString(),
			method: String(input.method || "GET").trim().toUpperCase(),
			url: safeUrl,
			host,
			path,
			requestHeaders: redactTrafficHeaders(input.requestHeaders, redactOpts),
			...(input.requestBody !== undefined
				? { requestBody: redactTrafficBody(input.requestBody, redactOpts) }
				: {}),
			status: Number(input.status) || 0,
			responseHeaders: redactTrafficHeaders(input.responseHeaders, redactOpts),
			...(input.responseBody !== undefined
				? { responseBodySnippet: redactTrafficBody(input.responseBody, redactOpts) }
				: {}),
			responseBodyHash: bodyHash,
			responseBodyBytes: bodyBytes,
			durationMs: Math.max(0, Number(input.durationMs ?? 0)),
			tags: Array.isArray(input.tags)
				? [...new Set(input.tags.map((t) => String(t).trim()).filter(Boolean))]
				: [],
			...(input.role ? { role: String(input.role).trim() } : {}),
			...(input.stepId ? { stepId: String(input.stepId).trim() } : {}),
			...(input.note
				? {
						note: scrubKnownSecrets(
							input.note,
							collectRawSecretsForZeroLeak(this.root, this.vault, reqRawSecrets),
							this.vault ?? this.root,
						),
					}
				: {}),
		};

		const dir = dirname(this.indexPath);
		mkdirSync(dir, { recursive: true, mode: 0o700 });
		try {
			chmodSync(dir, 0o700);
		} catch {
			/* 忽略非 POSIX 文件系统权限异常 */
		}

		appendFileSync(this.indexPath, `${JSON.stringify(entry)}\n`, {
			encoding: "utf8",
			mode: 0o600,
		});
		try {
			chmodSync(this.indexPath, 0o600);
		} catch {
			/* 忽略非 POSIX 文件系统权限异常 */
		}

		return entry;
	}

	/** 纯只读列出已记录流量条目（文件不存在时零写盘返回空数组）。 */
	public list(limit?: number): TrafficEntry[] {
		const all = this.readAllEntriesReadonly();
		if (limit === undefined) return all;
		if (typeof limit === "number" && Number.isFinite(limit)) {
			if (limit <= 0) return [];
			if (all.length > limit) return all.slice(-Math.floor(limit));
		}
		return all;
	}

	/** 纯只读多维条件过滤检索流量记录。 */
	public query(filter: TrafficQueryFilter = {}): TrafficEntry[] {
		const all = this.readAllEntriesReadonly();
		const wantHost = filter.host?.trim().toLowerCase();
		const wantHostBare = wantHost ? wantHost.replace(/:\d+$/, "") : undefined;
		const wantPrefix = filter.pathPrefix?.trim();
		const wantMethod = filter.method?.trim().toUpperCase();
		const wantStatus = filter.status;
		const wantTag = filter.tag?.trim();

		const matched = all.filter((entry) => {
			if (wantHost) {
				let entryHostPort = entry.host.toLowerCase();
				try {
					entryHostPort = new URL(entry.url).host.toLowerCase();
				} catch {
					/* ignore */
				}
				if (
					entry.host.toLowerCase() !== wantHost &&
					entry.host.toLowerCase() !== wantHostBare &&
					entryHostPort !== wantHost
				) {
					return false;
				}
			}
			if (wantPrefix && !entry.path.startsWith(wantPrefix)) {
				return false;
			}
			if (wantMethod && entry.method.toUpperCase() !== wantMethod) {
				return false;
			}
			if (wantStatus !== undefined && entry.status !== wantStatus) {
				return false;
			}
			if (wantTag && !(entry.tags ?? []).includes(wantTag)) {
				return false;
			}
			return true;
		});

		if (filter.limit !== undefined && typeof filter.limit === "number" && Number.isFinite(filter.limit)) {
			if (filter.limit <= 0) return [];
			if (matched.length > filter.limit) return matched.slice(-Math.floor(filter.limit));
		}
		return matched;
	}

	/** 纯只读按 ID 精确获取单条流量记录。 */
	public getById(id: string): TrafficEntry | null {
		const targetId = String(id ?? "").trim();
		if (!targetId) return null;
		const all = this.readAllEntriesReadonly();
		for (let i = all.length - 1; i >= 0; i--) {
			const item = all[i];
			if (item && item.id === targetId) return item;
		}
		return null;
	}

	private readAllEntriesReadonly(): TrafficEntry[] {
		if (!existsSync(this.indexPath)) return [];
		let raw = "";
		try {
			raw = readFileSync(this.indexPath, "utf8");
		} catch {
			return [];
		}
		if (!raw.trim()) return [];
		const entries: TrafficEntry[] = [];
		for (const line of raw.split(/\r?\n/)) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			try {
				const parsed = JSON.parse(trimmed) as TrafficEntry;
				if (parsed && typeof parsed === "object" && typeof parsed.id === "string") {
					entries.push(parsed);
				}
			} catch {
				/* 跳过单行不完整记录 */
			}
		}
		return entries;
	}
}

// ==================== 2. replayTrafficSequence ====================

function validateHttpUrlAgainstScope(
	rawUrl: string,
	method: string,
	scope: ScopePolicy,
	mode: Mode | string = "audit",
	contextLabel = "请求目标",
): { ok: true; parsed: URL } | { ok: false; reason: string } {
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		return {
			ok: false,
			reason: formatScopeBlockReason("egress-proxy", `${contextLabel} URL 非法 (${rawUrl})`, "N-007"),
		};
	}

	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return {
			ok: false,
			reason: formatScopeBlockReason(
				"egress-proxy",
				`${contextLabel} 协议不受支持 (${parsed.protocol})，仅允许 http/https`,
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
				`${contextLabel}越界 (${parsed.hostname}) — ${hostVerdict.reason ?? "不在授权 Scope 内"}`,
				"N-007",
			),
		};
	}

	const cmdVerdict = checkScopeAndRisk(
		`curl -X ${method.toUpperCase()} ${parsed.toString()}`,
		scope,
		mode,
		{ layer: "egress-proxy" },
	);
	if (cmdVerdict?.block) {
		return {
			ok: false,
			reason: cmdVerdict.reason,
		};
	}

	return { ok: true, parsed };
}

function interpolateTemplateString(template: string, vars: Record<string, string>): string {
	return template.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (full, varName: string) => {
		if (Object.prototype.hasOwnProperty.call(vars, varName)) {
			return vars[varName] ?? "";
		}
		return full;
	});
}

function interpolateUnknownValue(val: unknown, vars: Record<string, string>): unknown {
	if (typeof val === "string") return interpolateTemplateString(val, vars);
	if (Array.isArray(val)) return val.map((v) => interpolateUnknownValue(v, vars));
	if (val && typeof val === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
			out[interpolateTemplateString(k, vars)] = interpolateUnknownValue(v, vars);
		}
		return out;
	}
	return val;
}

function normalizeResponseHeaders(
	headers: TrafficFetchResponseLike["headers"],
): { flat: Record<string, string>; setCookies: string[] } {
	const flat: Record<string, string> = {};
	const setCookies: string[] = [];
	if (!headers) return { flat, setCookies };

	const maybeHeaders = headers as {
		getSetCookie?: () => string[];
		forEach?: (cb: (value: string, key: string) => void) => void;
		get?: (name: string) => string | null;
	};

	if (typeof maybeHeaders.getSetCookie === "function") {
		try {
			const list = maybeHeaders.getSetCookie();
			if (Array.isArray(list)) {
				for (const item of list) {
					if (item) setCookies.push(item);
				}
			}
		} catch {
			/* ignore */
		}
	}

	const hadGetSetCookie = setCookies.length > 0;
	if (typeof maybeHeaders.forEach === "function") {
		maybeHeaders.forEach((val, key) => {
			const lower = key.toLowerCase();
			if (lower === "set-cookie") {
				if (!hadGetSetCookie && val) {
					setCookies.push(val);
				}
				flat[lower] = flat[lower] ? `${flat[lower]}\n${val}` : val;
			} else {
				flat[lower] = val;
			}
		});
		if (setCookies.length > 0 && !flat["set-cookie"]) {
			flat["set-cookie"] = setCookies.join("\n");
		}
		return { flat, setCookies };
	}

	if (typeof headers === "object" && !("get" in headers && typeof headers.get === "function")) {
		for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
			if (v === undefined) continue;
			const lower = k.toLowerCase();
			if (lower === "set-cookie") {
				if (Array.isArray(v)) {
					setCookies.push(...v.filter(Boolean));
					flat[lower] = v.join("\n");
				} else if (v) {
					setCookies.push(v);
					flat[lower] = v;
				}
			} else {
				flat[lower] = Array.isArray(v) ? v.join(", ") : String(v);
			}
		}
		return { flat, setCookies };
	}

	if (typeof maybeHeaders.get === "function") {
		const commonNames = [
			"content-type",
			"location",
			"set-cookie",
			"x-csrf-token",
			"x-xsrf-token",
			"x-request-id",
			"x-auth-token",
			"authorization",
			"vary",
			"x-nextjs-matched-path",
			"retry-after",
			"www-authenticate",
		];
		for (const name of commonNames) {
			const v = maybeHeaders.get(name);
			if (v !== null && v !== undefined) {
				flat[name] = v;
				if (name === "set-cookie" && setCookies.length === 0) {
					setCookies.push(v);
				}
			}
		}
	}

	return { flat, setCookies };
}

function ingestSetCookiesIntoJar(
	jar: Map<string, StoredCookie>,
	setCookies: string[],
	requestUrl: URL,
): void {
	for (const rawLine of setCookies) {
		if (!rawLine) continue;
		const segments = rawLine
			.split(";")
			.map((s) => s.trim())
			.filter(Boolean);
		if (segments.length === 0) continue;
		const first = segments[0]!;
		const eq = first.indexOf("=");
		if (eq <= 0) continue;
		const name = first.slice(0, eq).trim();
		const value = first.slice(eq + 1).trim();
		if (!name) continue;

		let domain: string | undefined;
		let path = "/";
		let expired = false;

		for (let i = 1; i < segments.length; i++) {
			const attr = segments[i]!;
			const aEq = attr.indexOf("=");
			const aKey = (aEq > 0 ? attr.slice(0, aEq) : attr).trim().toLowerCase();
			const aVal = aEq > 0 ? attr.slice(aEq + 1).trim() : "";
			if (aKey === "domain" && aVal) {
				domain = aVal.replace(/^\./, "").toLowerCase();
			} else if (aKey === "path" && aVal) {
				path = aVal;
			} else if (aKey === "max-age") {
				const n = Number(aVal);
				if (Number.isFinite(n) && n <= 0) expired = true;
			}
		}

		if (expired || value === "") {
			jar.delete(name);
			continue;
		}
		jar.set(name, {
			name,
			value,
			domain: domain ?? requestUrl.hostname.toLowerCase(),
			path,
		});
	}
}

function buildCookieHeaderFromJar(
	jar: Map<string, StoredCookie>,
	targetUrl: URL,
	explicitCookieHeader?: string,
): string | undefined {
	const merged = new Map<string, string>();
	const reqHost = targetUrl.hostname.toLowerCase();
	const reqPath = targetUrl.pathname || "/";

	for (const item of jar.values()) {
		if (item.domain && reqHost !== item.domain && !reqHost.endsWith(`.${item.domain}`)) {
			continue;
		}
		if (item.path && item.path !== "/") {
			const pathMatches =
				reqPath === item.path ||
				(item.path.endsWith("/") && reqPath.startsWith(item.path)) ||
				reqPath.startsWith(`${item.path}/`);
			if (!pathMatches) continue;
		}
		merged.set(item.name, item.value);
	}

	if (explicitCookieHeader) {
		for (const part of explicitCookieHeader.split(";")) {
			const seg = part.trim();
			if (!seg) continue;
			const eq = seg.indexOf("=");
			if (eq > 0) {
				merged.set(seg.slice(0, eq).trim(), seg.slice(eq + 1).trim());
			}
		}
	}

	if (merged.size === 0) return undefined;
	return [...merged.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

function readJsonByPath(rootObj: unknown, pathExpr: string): string | undefined {
	const cleanPath = pathExpr.trim().replace(/^\$\.?/, "");
	if (!cleanPath) return undefined;
	const tokens = cleanPath
		.replace(/\[(\d+)\]/g, ".$1")
		.split(".")
		.map((s) => s.trim())
		.filter(Boolean);

	let cur: unknown = rootObj;
	for (const tok of tokens) {
		if (cur === null || cur === undefined) return undefined;
		if (Array.isArray(cur)) {
			const idx = Number(tok);
			if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return undefined;
			cur = cur[idx];
		} else if (typeof cur === "object") {
			cur = (cur as Record<string, unknown>)[tok];
		} else {
			return undefined;
		}
	}

	if (cur === null || cur === undefined) return undefined;
	if (typeof cur === "string") return cur;
	if (typeof cur === "number" || typeof cur === "boolean") return String(cur);
	return JSON.stringify(cur);
}

function extractVariablesFromResponse(
	extractMap: Record<string, string | TrafficExtractorSpec> | undefined,
	respHeaders: Record<string, string>,
	respBody: string,
	cookieJar: Map<string, StoredCookie>,
): Record<string, string> {
	const out: Record<string, string> = {};
	if (!extractMap) return out;

	let parsedJson: unknown;
	let jsonAttempted = false;
	const ensureJson = (): unknown => {
		if (!jsonAttempted) {
			jsonAttempted = true;
			try {
				parsedJson = JSON.parse(respBody);
			} catch {
				parsedJson = undefined;
			}
		}
		return parsedJson;
	};

	for (const [varName, rawSpec] of Object.entries(extractMap)) {
		if (!varName) continue;
		const spec: TrafficExtractorSpec =
			typeof rawSpec === "string"
				? rawSpec.startsWith("header:")
					? { header: rawSpec.slice("header:".length).trim() }
					: rawSpec.startsWith("cookie:")
						? { cookie: rawSpec.slice("cookie:".length).trim() }
						: { jsonPath: rawSpec.trim() }
				: rawSpec;

		let extractedVal: string | undefined;
		if (spec.header) {
			const hk = spec.header.trim().toLowerCase();
			extractedVal = respHeaders[hk];
		}
		if (extractedVal === undefined && spec.cookie) {
			extractedVal = cookieJar.get(spec.cookie.trim())?.value;
		}
		if (extractedVal === undefined && spec.jsonPath) {
			const j = ensureJson();
			if (j !== undefined) {
				extractedVal = readJsonByPath(j, spec.jsonPath);
			}
		}
		if (extractedVal === undefined && spec.regex) {
			try {
				const re = new RegExp(spec.regex);
				const m = re.exec(respBody);
				if (m) extractedVal = m[1] ?? m[0];
			} catch {
				/* 忽略非法正则 */
			}
		}

		if (extractedVal !== undefined) {
			out[varName] = extractedVal;
		}
	}

	return out;
}

async function executeTimedManualFetch(
	fetchFn: TrafficFetchFn,
	url: string,
	init: {
		method: string;
		headers: Record<string, string>;
		body?: string;
	},
	timeoutMs: number,
	outerSignal?: AbortSignal,
): Promise<{
	response?: TrafficFetchResponseLike;
	bodyText: string;
	durationMs: number;
	timedOut: boolean;
	error?: string;
}> {
	const startedAt = Date.now();
	const controller = new AbortController();
	let timedOut = false;

	const onOuterAbort = () => controller.abort();
	if (outerSignal) {
		if (outerSignal.aborted) {
			return {
				bodyText: "",
				durationMs: 0,
				timedOut: false,
				error: "外部 AbortSignal 已中止请求",
			};
		}
		outerSignal.addEventListener("abort", onOuterAbort, { once: true });
	}

	const timer = setTimeout(() => {
		timedOut = true;
		controller.abort();
	}, Math.max(50, timeoutMs));

	try {
		const response = await fetchFn(url, {
			method: init.method,
			headers: init.headers,
			...(init.body !== undefined ? { body: init.body } : {}),
			redirect: "manual",
			signal: controller.signal,
		});
		const bodyText = await response.text();
		return {
			response,
			bodyText,
			durationMs: Math.max(0, Date.now() - startedAt),
			timedOut: false,
		};
	} catch (err) {
		return {
			bodyText: "",
			durationMs: Math.max(0, Date.now() - startedAt),
			timedOut,
			error: timedOut
				? `HTTP 请求超时 (${timeoutMs}ms)`
				: err instanceof Error
					? err.message
					: String(err),
		};
	} finally {
		clearTimeout(timer);
		if (outerSignal) {
			outerSignal.removeEventListener("abort", onOuterAbort);
		}
	}
}

function defaultFetchAdapter(
	url: string,
	init?: {
		method?: string;
		headers?: Record<string, string>;
		body?: string;
		redirect?: "manual" | "follow" | "error";
		signal?: AbortSignal;
	},
): Promise<TrafficFetchResponseLike> {
	return fetch(url, {
		method: init?.method,
		headers: init?.headers,
		body: init?.body,
		redirect: init?.redirect ?? "manual",
		signal: init?.signal,
	});
}

/**
 * 多步有状态 HTTP 工作流重放器：
 * - 每步发包前强制执行 `isHostInScope` 与 `checkScopeAndRisk` 校验；
 * - 强制 `redirect: "manual"`，逐跳校验 30x `Location` 目标，拦截越界重定向；
 * - 自动维护内存 Cookie Jar，并支持从响应头 / Cookie / JSON Path / 正则提取变量替换 `{{var}}`。
 */
export async function replayTrafficSequence(
	steps: TrafficReplayStep[],
	scope: ScopePolicy,
	opts?: ReplayTrafficOptions,
): Promise<ReplayTrafficResult> {
	const fetchFn = opts?.fetchFn ?? defaultFetchAdapter;
	const mode = opts?.mode ?? "audit";
	const defaultTimeoutMs = clampInt(opts?.timeoutMs, DEFAULT_STEP_TIMEOUT_MS, 50, 120_000);
	const defaultFollowRedirects = opts?.followRedirects ?? true;
	const defaultMaxRedirects = clampInt(opts?.maxRedirects, DEFAULT_MAX_REDIRECTS, 0, 20);
	const variables: Record<string, string> = { ...(opts?.initialVars ?? {}) };
	const cookieJar = new Map<string, StoredCookie>();

	if (opts?.initialCookies) {
		for (const [ck, cv] of Object.entries(opts.initialCookies)) {
			if (ck && cv !== undefined) {
				cookieJar.set(ck, { name: ck, value: cv, path: "/" });
			}
		}
	}

	const stepResults: ReplayStepResult[] = [];
	let abortedByScope = false;
	let blockedStepIndex: number | undefined;
	let topBlockReason: string | undefined;

	for (let idx = 0; idx < steps.length; idx++) {
		const step = steps[idx]!;
		const stepId = step.id ?? `step_${idx + 1}`;
		const initialMethod = String(step.method ?? "GET").trim().toUpperCase();
		const resolvedUrl = interpolateTemplateString(step.url, variables);

		const interpolatedHeaders: Record<string, string> = {};
		let explicitCookieHeader: string | undefined;
		let hasContentType = false;
		if (step.headers) {
			for (const [hk, hv] of Object.entries(step.headers)) {
				const rk = interpolateTemplateString(hk, variables).trim();
				const rv = interpolateTemplateString(String(hv ?? ""), variables);
				if (!rk) continue;
				if (rk.toLowerCase() === "cookie") {
					explicitCookieHeader = rv;
				} else {
					if (rk.toLowerCase() === "content-type") hasContentType = true;
					interpolatedHeaders[rk] = rv;
				}
			}
		}

		let resolvedBody: string | undefined;
		if (typeof step.body === "string") {
			resolvedBody = interpolateTemplateString(step.body, variables);
		} else if (step.body && typeof step.body === "object") {
			resolvedBody = JSON.stringify(interpolateUnknownValue(step.body, variables));
			if (!hasContentType) {
				interpolatedHeaders["Content-Type"] = "application/json";
			}
		}

		// 1. 发包前强 Scope 门禁校验
		const scopeCheck = validateHttpUrlAgainstScope(
			resolvedUrl,
			initialMethod,
			scope,
			mode,
			`步骤 #${idx + 1} (${stepId})`,
		);
		if (!scopeCheck.ok) {
			abortedByScope = true;
			blockedStepIndex = idx;
			topBlockReason = scopeCheck.reason;
			stepResults.push({
				stepIndex: idx,
				id: stepId,
				name: step.name,
				method: initialMethod,
				resolvedUrl,
				finalUrl: resolvedUrl,
				status: 0,
				ok: false,
				blocked: true,
				blockReason: scopeCheck.reason,
				durationMs: 0,
				redirectChain: [],
				responseHeaders: {},
				responseBody: "",
				extracted: {},
			});
			if (!opts?.continueOnError) break;
			continue;
		}

		let currentUrlObj = scopeCheck.parsed;
		let currentMethod = initialMethod;
		let currentBody = resolvedBody;
		const followRedirects = step.followRedirects ?? defaultFollowRedirects;
		const maxRedirects = clampInt(step.maxRedirects, defaultMaxRedirects, 0, 20);
		const stepTimeoutMs = clampInt(step.timeoutMs, defaultTimeoutMs, 50, 120_000);
		const redirectChain: string[] = [];

		let finalStatus = 0;
		let finalHeaders: Record<string, string> = {};
		let finalBody = "";
		let totalDurationMs = 0;
		let stepBlocked = false;
		let redirectBlocked = false;
		let stepBlockReason: string | undefined;
		let stepTimedOut = false;
		let stepError: string | undefined;
		let lastRecordedId: string | undefined;

		for (let hop = 0; hop <= maxRedirects; hop++) {
			const reqHeaders: Record<string, string> = { ...interpolatedHeaders };
			const cookieHeader = buildCookieHeaderFromJar(cookieJar, currentUrlObj, explicitCookieHeader);
			if (cookieHeader) {
				reqHeaders.Cookie = cookieHeader;
			}

			const execRes = await executeTimedManualFetch(
				fetchFn,
				currentUrlObj.toString(),
				{
					method: currentMethod,
					headers: reqHeaders,
					body: currentBody,
				},
				stepTimeoutMs,
				opts?.signal,
			);
			totalDurationMs += execRes.durationMs;

			if (!execRes.response) {
				stepTimedOut = execRes.timedOut;
				stepError = execRes.error ?? "网络请求失败";
				break;
			}

			finalStatus = execRes.response.status;
			const { flat, setCookies } = normalizeResponseHeaders(execRes.response.headers);
			finalHeaders = flat;
			finalBody = execRes.bodyText;

			// 更新内存 Cookie Jar
			if (setCookies.length > 0) {
				ingestSetCookiesIntoJar(cookieJar, setCookies, currentUrlObj);
			}

			// 提前预提取当前跳响应中的敏感动态变量并注册到 Recorder，确保当步落盘响应体零明文残留
			if (opts?.recorder && step.extract) {
				const preExtracted = extractVariablesFromResponse(step.extract, flat, finalBody, cookieJar);
				for (const [vk, vv] of Object.entries(preExtracted)) {
					if (/(?:token|key|secret|auth|jwt|csrf|xsrf|session|sid)/i.test(vk)) {
						opts.recorder.registerTransientSecret(vv);
					}
				}
			}

			// 可选自动写入脱敏流量审计日志
			if (opts?.recorder) {
				const rec = opts.recorder.record({
					method: currentMethod,
					url: currentUrlObj.toString(),
					requestHeaders: reqHeaders,
					requestBody: currentBody,
					status: finalStatus,
					responseHeaders: finalHeaders,
					responseBody: finalBody,
					durationMs: execRes.durationMs,
					stepId,
					tags: [...(opts.tags ?? []), ...(step.tags ?? []), "replay"],
				});
				lastRecordedId = rec.id;
			}

			// 检查 30x 重定向（无论是否配置跟随，只要 Location 指向越界目标一律拦截告警）
			const locationRaw = finalHeaders.location;
			if (REDIRECT_STATUS_CODES.has(finalStatus) && locationRaw) {
				let nextUrlRaw: string;
				try {
					nextUrlRaw = new URL(locationRaw, currentUrlObj.toString()).toString();
				} catch {
					nextUrlRaw = locationRaw;
				}

				const redirectScopeCheck = validateHttpUrlAgainstScope(
					nextUrlRaw,
					finalStatus === 303 || ((finalStatus === 301 || finalStatus === 302) && currentMethod === "POST")
						? "GET"
						: currentMethod,
					scope,
					mode,
					`步骤 #${idx + 1} (${stepId}) 30x 重定向目标`,
				);

				if (!redirectScopeCheck.ok) {
					stepBlocked = true;
					redirectBlocked = true;
					stepBlockReason = redirectScopeCheck.reason;
					abortedByScope = true;
					blockedStepIndex = idx;
					topBlockReason = redirectScopeCheck.reason;
					break;
				}

				if (!followRedirects) {
					break;
				}

				if (hop === maxRedirects) {
					stepError = `超出最大重定向跳数限制 (${maxRedirects})`;
					break;
				}

				redirectChain.push(nextUrlRaw);
				currentUrlObj = redirectScopeCheck.parsed;
				if (
					finalStatus === 303 ||
					((finalStatus === 301 || finalStatus === 302) && currentMethod === "POST")
				) {
					currentMethod = "GET";
					currentBody = undefined;
					delete interpolatedHeaders["Content-Type"];
					delete interpolatedHeaders["content-type"];
				}
				// 跨跳时仅依赖更新后的 Cookie Jar，不再重复附加首跳静态显式 Cookie
				explicitCookieHeader = undefined;
				continue;
			}

			break;
		}

		const extracted =
			!stepBlocked && !stepError
				? extractVariablesFromResponse(step.extract, finalHeaders, finalBody, cookieJar)
				: {};

		for (const [vk, vv] of Object.entries(extracted)) {
			variables[vk] = vv;
			// 若提取到的变量属于潜在敏感令牌，同步注册到 Recorder 以确保后续回显 100% 脱敏
			if (opts?.recorder && /(?:token|key|secret|auth|jwt|csrf|xsrf|session|sid)/i.test(vk)) {
				opts.recorder.registerTransientSecret(vv);
			}
		}

		let statusMatched = finalStatus >= 200 && finalStatus < 400;
		if (step.expectStatus !== undefined) {
			const expectedList = Array.isArray(step.expectStatus) ? step.expectStatus : [step.expectStatus];
			statusMatched = expectedList.includes(finalStatus);
		}

		const stepOk = !stepBlocked && !stepTimedOut && !stepError && statusMatched;
		stepResults.push({
			stepIndex: idx,
			id: stepId,
			name: step.name,
			method: initialMethod,
			resolvedUrl,
			finalUrl: currentUrlObj.toString(),
			status: finalStatus,
			ok: stepOk,
			blocked: stepBlocked,
			...(redirectBlocked ? { redirectBlocked: true } : {}),
			...(stepTimedOut ? { timedOut: true } : {}),
			...(stepBlockReason ? { blockReason: stepBlockReason } : {}),
			...(stepError ? { error: stepError } : {}),
			durationMs: totalDurationMs,
			redirectChain,
			responseHeaders: finalHeaders,
			responseBody: finalBody,
			extracted,
			...(lastRecordedId ? { recordedEntryId: lastRecordedId } : {}),
		});

		if ((stepBlocked || stepTimedOut || stepError) && !opts?.continueOnError) {
			break;
		}
	}

	const cookiesOut: Record<string, string> = {};
	for (const [k, item] of cookieJar.entries()) {
		cookiesOut[k] = item.value;
	}

	const allOk =
		!abortedByScope &&
		stepResults.length === steps.length &&
		stepResults.every((r) => r.ok);

	return {
		ok: allOk,
		abortedByScope,
		...(blockedStepIndex !== undefined ? { blockedStepIndex } : {}),
		...(topBlockReason ? { blockReason: topBlockReason } : {}),
		steps: stepResults,
		variables,
		cookies: cookiesOut,
	};
}

// ==================== 3. runStructuredMutations ====================

const ALL_MUTATION_MODES: readonly MutationMode[] = [
	"idor_step",
	"auth_strip",
	"graphql_introspect",
	"nextjs_rsc",
	"race_probe",
];

interface RawProbeResult {
	label: string;
	method: string;
	url: string;
	status: number;
	headers: Record<string, string>;
	body: string;
	bodyHash: string;
	templateHash: string;
	bodyBytes: number;
	isSoft404: boolean;
	blocked: boolean;
	blockReason?: string;
	timedOut: boolean;
	error?: string;
	durationMs: number;
}

function toProbeSummary(p: RawProbeResult): MutationProbeSummary {
	return {
		label: p.label,
		method: p.method,
		url: p.url,
		status: p.status,
		bodyHash: p.bodyHash,
		templateHash: p.templateHash,
		bodyBytes: p.bodyBytes,
		isSoft404: p.isSoft404,
		blocked: p.blocked,
		...(p.blockReason ? { blockReason: p.blockReason } : {}),
		...(p.timedOut ? { timedOut: true } : {}),
		durationMs: p.durationMs,
	};
}

async function runWithConcurrencyLimit<T>(
	tasks: Array<() => Promise<T>>,
	maxConcurrency: number,
): Promise<T[]> {
	const limit = Math.max(1, Math.min(MAX_MUTATION_CONCURRENCY, Math.floor(maxConcurrency)));
	const results = new Array<T>(tasks.length);
	let cursor = 0;

	const worker = async () => {
		while (true) {
			const idx = cursor++;
			if (idx >= tasks.length) return;
			const fn = tasks[idx]!;
			results[idx] = await fn();
		}
	};

	const workersCount = Math.min(limit, tasks.length);
	await Promise.all(Array.from({ length: workersCount }, () => worker()));
	return results;
}

function looksLikeErrorJsonEnvelope(body: string): boolean {
	const trimmed = body.trim();
	if (!trimmed.startsWith("{")) return false;
	try {
		const obj = JSON.parse(trimmed) as Record<string, unknown>;
		if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
		if (obj.ok === false || obj.success === false) return true;
		const status = Number(obj.status ?? obj.statusCode ?? obj.code ?? 0);
		if (status >= 400) return true;
		const keys = Object.keys(obj);
		if (
			keys.length <= 3 &&
			typeof obj.error === "string" &&
			/(?:unauthorized|forbidden|not\s*found|denied|invalid|expired)/i.test(obj.error)
		) {
			return true;
		}
	} catch {
		return false;
	}
	return false;
}

function buildIdorStepUrls(
	baseUrl: string,
	customIds?: Array<string | number>,
): Array<{ label: string; url: string; originalId: string; mutatedId: string }> {
	let parsed: URL;
	try {
		parsed = new URL(baseUrl);
	} catch {
		return [];
	}

	const candidates: Array<{ label: string; url: string; originalId: string; mutatedId: string }> = [];
	const segments = parsed.pathname.split("/");

	// 1. 优先定位路径中的纯数字资源 ID 段（跳过 /v1、/v2 等版本号段）
	for (let i = segments.length - 1; i >= 0; i--) {
		const seg = segments[i] ?? "";
		if (!/^\d+$/.test(seg)) continue;
		const num = Number(seg);
		if (!Number.isSafeInteger(num)) continue;

		const replacements =
			customIds && customIds.length > 0
				? customIds.map((x) => String(x)).filter((x) => x !== seg)
				: num > 1
					? [String(num + 1), String(num - 1)]
					: [String(num + 1), String(num + 2)];

		for (const nextId of replacements.slice(0, 3)) {
			const cloned = new URL(parsed.toString());
			const nextSegs = [...segments];
			nextSegs[i] = encodeURIComponent(nextId);
			cloned.pathname = nextSegs.join("/");
			candidates.push({
				label: `path_id:${seg}->${nextId}`,
				url: cloned.toString(),
				originalId: seg,
				mutatedId: nextId,
			});
		}
		return candidates;
	}

	// 2. 检查查询字符串中的数值型资源 ID 参数
	for (const [k, v] of parsed.searchParams.entries()) {
		if (!/(?:^|_)(?:id|uid|oid|account|order|doc|record|item|user)(?:$|_)/i.test(k)) continue;
		if (!/^\d+$/.test(v)) continue;
		const num = Number(v);
		const replacements =
			customIds && customIds.length > 0
				? customIds.map((x) => String(x)).filter((x) => x !== v)
				: num > 1
					? [String(num + 1), String(num - 1)]
					: [String(num + 1), String(num + 2)];
		for (const nextId of replacements.slice(0, 3)) {
			const cloned = new URL(parsed.toString());
			cloned.searchParams.set(k, nextId);
			candidates.push({
				label: `query_${k}:${v}->${nextId}`,
				url: cloned.toString(),
				originalId: v,
				mutatedId: nextId,
			});
		}
		return candidates;
	}

	return candidates;
}

function stripAuthFromRequest(
	urlStr: string,
	headers: Record<string, string>,
): { strippedUrl: string; strippedHeaders: Record<string, string>; removedKeys: string[] } {
	const strippedHeaders: Record<string, string> = {};
	const removedKeys: string[] = [];

	for (const [k, v] of Object.entries(headers)) {
		if (isSensitiveHeaderName(k)) {
			removedKeys.push(k);
		} else {
			strippedHeaders[k] = v;
		}
	}

	let strippedUrl = urlStr;
	try {
		const u = new URL(urlStr);
		if (u.username || u.password) {
			u.username = "";
			u.password = "";
			removedKeys.push("url:userinfo");
		}
		for (const qk of [...u.searchParams.keys()]) {
			if (SENSITIVE_QUERY_PARAM_RE.test(qk)) {
				u.searchParams.delete(qk);
				removedKeys.push(`query:${qk}`);
			}
		}
		strippedUrl = u.toString();
	} catch {
		/* ignore */
	}

	return { strippedUrl, strippedHeaders, removedKeys };
}

/**
 * 面向现代 Web/API 的纯只读合规契约差分校验器：
 * - 强制全流程 Scope 校验 + 30x 越界重定向拦截；
 * - 强制并发硬上限 <= 8 + 单步超时保护；
 * - 集成 Soft-404 与模板指纹去噪，覆盖 `idor_step`、`auth_strip`、`graphql_introspect`、`nextjs_rsc`、`race_probe`。
 */
export async function runStructuredMutations(
	baseRequest: MutationBaseRequest,
	scope: ScopePolicy,
	opts?: StructuredMutationsOptions,
): Promise<StructuredMutationsResult> {
	const fetchFn = opts?.fetchFn ?? defaultFetchAdapter;
	const mode = opts?.mode ?? "audit";
	const timeoutMs = clampInt(opts?.timeoutMs, DEFAULT_STEP_TIMEOUT_MS, 50, 120_000);
	const effectiveConcurrency = clampInt(
		opts?.concurrency,
		4,
		1,
		MAX_MUTATION_CONCURRENCY,
	);
	const validCustomModes = Array.isArray(opts?.modes)
		? [...new Set(opts.modes.filter((m): m is MutationMode => ALL_MUTATION_MODES.includes(m)))]
		: [];
	const requestedModes: MutationMode[] =
		validCustomModes.length > 0 ? validCustomModes : [...ALL_MUTATION_MODES];

	const baseMethod = String(baseRequest.method ?? "GET").trim().toUpperCase();
	const baseHeaders: Record<string, string> = { ...(baseRequest.headers ?? {}) };

	// 0. 入口基线 URL 强 Scope 门禁校验
	const entryCheck = validateHttpUrlAgainstScope(
		baseRequest.url,
		baseMethod,
		scope,
		mode,
		"契约差分基线目标",
	);
	if (!entryCheck.ok) {
		const emptyMap = {} as Record<MutationMode, MutationCaseResult>;
		for (const m of requestedModes) {
			emptyMap[m] = {
				mode: m,
				executed: false,
				anomalous: false,
				suppressedBySoft404: false,
				blockedByScope: true,
				severity: "info",
				summary: entryCheck.reason,
				evidence: { blocked: true, reason: entryCheck.reason },
				probes: [],
			};
		}
		return {
			ok: false,
			blockedByScope: true,
			blockReason: entryCheck.reason,
			effectiveConcurrency,
			results: emptyMap,
			cases: Object.values(emptyMap),
			anomalies: [],
		};
	}

	let soft404Baseline: Soft404BaselineInput | Soft404Baseline | null =
		opts?.soft404Baseline ?? null;

	// 底层硬信号量门闸：从数学上保证任意时刻在飞探针数严格 <= effectiveConcurrency (<= 8)
	let activeProbes = 0;
	const waitQueue: Array<() => void> = [];
	const acquireProbeSlot = async (): Promise<void> => {
		if (activeProbes < effectiveConcurrency) {
			activeProbes++;
			return;
		}
		await new Promise<void>((resolveSlot) => {
			waitQueue.push(resolveSlot);
		});
		activeProbes++;
	};
	const releaseProbeSlot = (): void => {
		activeProbes = Math.max(0, activeProbes - 1);
		const next = waitQueue.shift();
		if (next) next();
	};

	const sendGuardedProbe = async (
		label: string,
		reqMethod: string,
		reqUrl: string,
		reqHeaders: Record<string, string>,
		reqBody?: string,
	): Promise<RawProbeResult> => {
		const verdict = validateHttpUrlAgainstScope(reqUrl, reqMethod, scope, mode, `探针 [${label}]`);
		if (!verdict.ok) {
			return {
				label,
				method: reqMethod,
				url: reqUrl,
				status: 0,
				headers: {},
				body: "",
				bodyHash: computeBodyHash("").bodyHash,
				templateHash: computeTemplateFingerprint(""),
				bodyBytes: 0,
				isSoft404: false,
				blocked: true,
				blockReason: verdict.reason,
				timedOut: false,
				durationMs: 0,
			};
		}

		await acquireProbeSlot();
		let execRes: Awaited<ReturnType<typeof executeTimedManualFetch>>;
		try {
			execRes = await executeTimedManualFetch(
				fetchFn,
				verdict.parsed.toString(),
				{
					method: reqMethod,
					headers: reqHeaders,
					body: reqBody,
				},
				timeoutMs,
				opts?.signal,
			);
		} finally {
			releaseProbeSlot();
		}

		if (!execRes.response) {
			return {
				label,
				method: reqMethod,
				url: reqUrl,
				status: 0,
				headers: {},
				body: "",
				bodyHash: computeBodyHash("").bodyHash,
				templateHash: computeTemplateFingerprint(""),
				bodyBytes: 0,
				isSoft404: false,
				blocked: false,
				timedOut: execRes.timedOut,
				error: execRes.error,
				durationMs: execRes.durationMs,
			};
		}

		const status = execRes.response.status;
		const { flat } = normalizeResponseHeaders(execRes.response.headers);
		const body = execRes.bodyText;

		// 校验响应 30x Location 是否指向越界目标
		if (REDIRECT_STATUS_CODES.has(status) && flat.location) {
			let redirTarget = flat.location;
			try {
				redirTarget = new URL(flat.location, verdict.parsed.toString()).toString();
			} catch {
				/* ignore */
			}
			const redirCheck = validateHttpUrlAgainstScope(
				redirTarget,
				"GET",
				scope,
				mode,
				`探针 [${label}] 30x 重定向`,
			);
			if (!redirCheck.ok) {
				if (opts?.recorder) {
					opts.recorder.record({
						method: reqMethod,
						url: reqUrl,
						requestHeaders: reqHeaders,
						requestBody: reqBody,
						status,
						responseHeaders: flat,
						responseBody: body,
						durationMs: execRes.durationMs,
						tags: ["mutation", label, "redirect-blocked"],
					});
				}
				return {
					label,
					method: reqMethod,
					url: reqUrl,
					status,
					headers: flat,
					body,
					bodyHash: computeBodyHash(body).bodyHash,
					templateHash: computeTemplateFingerprint(body, verdict.parsed.pathname),
					bodyBytes: Buffer.byteLength(body, "utf8"),
					isSoft404: false,
					blocked: true,
					blockReason: redirCheck.reason,
					timedOut: false,
					durationMs: execRes.durationMs,
				};
			}
		}

		const { bodyHash, bodyBytes } = computeBodyHash(body);
		const templateHash = computeTemplateFingerprint(body, verdict.parsed.pathname);
		const softCheck = detectSoft404(
			{
				url: reqUrl,
				path: verdict.parsed.pathname,
				status,
				body,
				bodyBytes,
				headers: flat,
			},
			soft404Baseline,
		);
		const softHit = softCheck.isSoft404;

		if (opts?.recorder) {
			opts.recorder.record({
				method: reqMethod,
				url: reqUrl,
				requestHeaders: reqHeaders,
				requestBody: reqBody,
				status,
				responseHeaders: flat,
				responseBody: body,
				durationMs: execRes.durationMs,
				tags: ["mutation", label],
			});
		}

		return {
			label,
			method: reqMethod,
			url: reqUrl,
			status,
			headers: flat,
			body,
			bodyHash,
			templateHash,
			bodyBytes,
			isSoft404: softHit,
			blocked: false,
			timedOut: false,
			durationMs: execRes.durationMs,
		};
	};

	// 1. 可选自动预采样随机不存在路径 Soft-404 基线
	if (!soft404Baseline && (opts?.autoSampleSoft404 ?? true)) {
		const randomNotFoundUrl = new URL(
			`/__nuwa_soft404_probe_${randomUUID().slice(0, 8)}`,
			entryCheck.parsed.origin,
		).toString();
		const sampleProbe = await sendGuardedProbe("soft404_baseline", "GET", randomNotFoundUrl, {});
		if (!sampleProbe.blocked && (sampleProbe.status === 200 || REDIRECT_STATUS_CODES.has(sampleProbe.status))) {
			soft404Baseline = {
				active: true,
				codes: [sampleProbe.status],
				size: sampleProbe.bodyBytes,
				bodyHash: sampleProbe.bodyHash,
				templateHash: sampleProbe.templateHash,
				probes: [
					{
						path: new URL(randomNotFoundUrl).pathname,
						status: sampleProbe.status,
						body: sampleProbe.body,
						bodyBytes: sampleProbe.bodyBytes,
						bodyHash: sampleProbe.bodyHash,
						templateHash: sampleProbe.templateHash,
						redirectLocation: sampleProbe.headers.location,
					},
				],
			};
		}
	}

	// 2. 获取基线响应（对非幂等写方法默认降级为只读 GET 基线，除非本身即为 GET/HEAD/OPTIONS/POST 查询）
	const safeBaselineMethod =
		baseMethod === "DELETE" || baseMethod === "PUT" || baseMethod === "PATCH" ? "GET" : baseMethod;
	const baselineProbe = await sendGuardedProbe(
		"baseline",
		safeBaselineMethod,
		baseRequest.url,
		baseHeaders,
		safeBaselineMethod === baseMethod ? baseRequest.body : undefined,
	);

	if (baselineProbe.blocked) {
		const blockedMap = {} as Record<MutationMode, MutationCaseResult>;
		for (const m of requestedModes) {
			blockedMap[m] = {
				mode: m,
				executed: false,
				anomalous: false,
				suppressedBySoft404: false,
				blockedByScope: true,
				severity: "info",
				summary: baselineProbe.blockReason ?? "基线响应触发越界重定向阻断",
				evidence: { blocked: true, reason: baselineProbe.blockReason },
				probes: [toProbeSummary(baselineProbe)],
			};
		}
		return {
			ok: false,
			blockedByScope: true,
			blockReason: baselineProbe.blockReason,
			effectiveConcurrency,
			results: blockedMap,
			cases: Object.values(blockedMap),
			anomalies: [],
		};
	}

	const resultsMap = {} as Record<MutationMode, MutationCaseResult>;
	const anomalies: MutationAnomaly[] = [];

	// 组装各诊断模式任务
	const modeRunners: Array<() => Promise<void>> = [];

	for (const currentMode of requestedModes) {
		if (currentMode === "idor_step") {
			modeRunners.push(async () => {
				const candidates = buildIdorStepUrls(baseRequest.url, opts?.idorCandidateIds);
				if (candidates.length === 0) {
					resultsMap.idor_step = {
						mode: "idor_step",
						executed: false,
						anomalous: false,
						suppressedBySoft404: false,
						blockedByScope: false,
						severity: "info",
						summary: "请求 URL 中未发现可步进的数值型资源标识符",
						evidence: { skippedReason: "no_numeric_id_in_url" },
						probes: [],
					};
					return;
				}

				const probes = await runWithConcurrencyLimit(
					candidates.map(
						(cand) => () =>
							sendGuardedProbe(`idor_${cand.label}`, "GET", cand.url, baseHeaders),
					),
					effectiveConcurrency,
				);

				const blockedHit = probes.find((p) => p.blocked);
				const softSuppressed = probes.some((p) => p.status === 200 && p.isSoft404);
				const baselineSuccess =
					baselineProbe.status >= 200 &&
					baselineProbe.status < 300 &&
					!baselineProbe.isSoft404;

				const unauthorizedExposed = probes.filter(
					(p) =>
						!p.blocked &&
						p.status >= 200 &&
						p.status < 300 &&
						!p.isSoft404 &&
						p.bodyBytes > 2 &&
						!looksLikeErrorJsonEnvelope(p.body) &&
						(baselineSuccess ? p.bodyHash !== baselineProbe.bodyHash || p.bodyBytes > 0 : true),
				);

				const anomalous = baselineSuccess && unauthorizedExposed.length > 0;
				const hitProbe = unauthorizedExposed[0];
				const summary = anomalous
					? `资源 ID 步进探测 (${hitProbe!.url}) 返回 HTTP ${hitProbe!.status} 有效业务响应，疑似存在水平访问控制边界缺失`
					: softSuppressed
						? "相邻资源 ID 返回 Soft-404 兜底页面，已自动去噪抑制"
						: "相邻资源 ID 访问均被正确拒绝或不存在";

				resultsMap.idor_step = {
					mode: "idor_step",
					executed: true,
					anomalous,
					suppressedBySoft404: !anomalous && softSuppressed,
					blockedByScope: Boolean(blockedHit),
					severity: anomalous ? "high" : "info",
					...(anomalous ? { findingCode: "idor_boundary_bypass" } : {}),
					summary,
					evidence: {
						baselineStatus: baselineProbe.status,
						baselineHash: baselineProbe.bodyHash,
						exposedUrls: unauthorizedExposed.map((p) => p.url),
					},
					probes: probes.map(toProbeSummary),
				};

				if (anomalous && hitProbe) {
					anomalies.push({
						mode: "idor_step",
						findingCode: "idor_boundary_bypass",
						severity: "high",
						method: "GET",
						url: baseRequest.url,
						path: entryCheck.parsed.pathname,
						summary,
						evidence: resultsMap.idor_step.evidence,
					});
				}
			});
		} else if (currentMode === "auth_strip") {
			modeRunners.push(async () => {
				const { strippedUrl, strippedHeaders, removedKeys } = stripAuthFromRequest(
					baseRequest.url,
					baseHeaders,
				);

				let lowPrivHeaders: Record<string, string> | null = opts?.lowPrivilegeHeaders ?? null;
				if (!lowPrivHeaders && opts?.lowPrivilegeRole && (opts.vault || opts.root)) {
					lowPrivHeaders = getRoleHeadersMap(opts.vault ?? opts.root!, opts.lowPrivilegeRole);
				}

				if (removedKeys.length === 0 && !lowPrivHeaders) {
					resultsMap.auth_strip = {
						mode: "auth_strip",
						executed: false,
						anomalous: false,
						suppressedBySoft404: false,
						blockedByScope: false,
						severity: "info",
						summary: "基线请求未携带认证头且未提供降权对比角色，跳过剥离差分",
						evidence: { skippedReason: "no_auth_credentials_present" },
						probes: [],
					};
					return;
				}

				const tasks: Array<() => Promise<RawProbeResult>> = [];
				if (removedKeys.length > 0) {
					tasks.push(() =>
						sendGuardedProbe(
							"auth_strip_unauthenticated",
							safeBaselineMethod,
							strippedUrl,
							strippedHeaders,
							safeBaselineMethod === baseMethod ? baseRequest.body : undefined,
						),
					);
				}
				if (lowPrivHeaders) {
					tasks.push(() =>
						sendGuardedProbe(
							"auth_strip_low_privilege",
							safeBaselineMethod,
							strippedUrl,
							{ ...strippedHeaders, ...lowPrivHeaders },
							safeBaselineMethod === baseMethod ? baseRequest.body : undefined,
						),
					);
				}

				const probes = await runWithConcurrencyLimit(tasks, effectiveConcurrency);
				const blockedHit = probes.find((p) => p.blocked);
				const softSuppressed = probes.some((p) => p.status === 200 && p.isSoft404);
				const baselineSuccess =
					baselineProbe.status >= 200 &&
					baselineProbe.status < 300 &&
					!baselineProbe.isSoft404 &&
					!looksLikeErrorJsonEnvelope(baselineProbe.body);

				const bypassedProbes = probes.filter((p) => {
					if (p.blocked || p.isSoft404 || p.status < 200 || p.status >= 300) return false;
					if (looksLikeErrorJsonEnvelope(p.body)) return false;
					if (p.bodyHash === baselineProbe.bodyHash || p.templateHash === baselineProbe.templateHash) {
						return true;
					}
					const ratio =
						baselineProbe.bodyBytes > 0
							? Math.abs(p.bodyBytes - baselineProbe.bodyBytes) / baselineProbe.bodyBytes
							: 1;
					return ratio <= 0.25 && p.bodyBytes > 2;
				});

				const anomalous = baselineSuccess && bypassedProbes.length > 0;
				const hit = bypassedProbes[0];
				const summary = anomalous
					? `剥离认证凭据或降权 (${hit!.label}) 后仍返回 HTTP ${hit!.status} 等效受保护数据，存在鉴权缺失或越权风险`
					: softSuppressed
						? "未认证请求返回 Soft-404 页面，已自动去噪过滤"
						: "剥离认证凭据后服务端正确拒绝访问";

				resultsMap.auth_strip = {
					mode: "auth_strip",
					executed: true,
					anomalous,
					suppressedBySoft404: !anomalous && softSuppressed,
					blockedByScope: Boolean(blockedHit),
					severity: anomalous ? "high" : "info",
					...(anomalous ? { findingCode: "missing_or_weak_auth_enforcement" } : {}),
					summary,
					evidence: {
						removedKeys,
						baselineStatus: baselineProbe.status,
						baselineHash: baselineProbe.bodyHash,
						bypassedLabels: bypassedProbes.map((p) => p.label),
					},
					probes: probes.map(toProbeSummary),
				};

				if (anomalous) {
					anomalies.push({
						mode: "auth_strip",
						findingCode: "missing_or_weak_auth_enforcement",
						severity: "high",
						method: safeBaselineMethod,
						url: baseRequest.url,
						path: entryCheck.parsed.pathname,
						summary,
						evidence: resultsMap.auth_strip.evidence,
					});
				}
			});
		} else if (currentMode === "graphql_introspect") {
			modeRunners.push(async () => {
				const targetUrlObj = new URL(baseRequest.url);
				const gqlUrl = opts?.graphqlPath
					? new URL(opts.graphqlPath, targetUrlObj.origin).toString()
					: /graphql|gql/i.test(targetUrlObj.pathname)
						? targetUrlObj.toString()
						: new URL("/graphql", targetUrlObj.origin).toString();

				const readonlyQuery = JSON.stringify({
					query: "query NuwaReadonlySchemaCheck { __schema { queryType { name } types { name kind } } }",
				});
				const gqlHeaders: Record<string, string> = {
					...stripAuthFromRequest(gqlUrl, baseHeaders).strippedHeaders,
					"Content-Type": "application/json",
					Accept: "application/json",
				};

				const probes: RawProbeResult[] = [];
				const postProbe = await sendGuardedProbe(
					"graphql_post_introspect",
					"POST",
					gqlUrl,
					gqlHeaders,
					readonlyQuery,
				);
				probes.push(postProbe);

				let activeProbe = postProbe;
				if (!postProbe.blocked && postProbe.status === 405) {
					const getUrl = new URL(gqlUrl);
					getUrl.searchParams.set("query", "{__schema{queryType{name}types{name kind}}}");
					const getProbe = await sendGuardedProbe(
						"graphql_get_introspect",
						"GET",
						getUrl.toString(),
						{ Accept: "application/json" },
					);
					probes.push(getProbe);
					activeProbe = getProbe;
				} else if (
					!postProbe.blocked &&
					(postProbe.status === 401 || postProbe.status === 403) &&
					Object.keys(baseHeaders).some((hk) => isSensitiveHeaderName(hk))
				) {
					// 若匿名探测被鉴权拒绝且调用方提供了合法认证头，进一步核验已认证角色下是否仍开放生产 Schema 内省
					const authedPostProbe = await sendGuardedProbe(
						"graphql_post_introspect_authed",
						"POST",
						gqlUrl,
						{
							...baseHeaders,
							"Content-Type": "application/json",
							Accept: "application/json",
						},
						readonlyQuery,
					);
					probes.push(authedPostProbe);
					activeProbe = authedPostProbe;
				}

				let exposedTypeCount = 0;
				let queryTypeName: string | undefined;
				let introspectionEnabled = false;

				if (!activeProbe.blocked && activeProbe.status === 200 && !activeProbe.isSoft404) {
					try {
						const parsed = JSON.parse(activeProbe.body) as {
							data?: {
								__schema?: {
									queryType?: { name?: string };
									types?: Array<{ name?: string }>;
								};
							};
						};
						const schema = parsed?.data?.__schema;
						if (schema && (schema.queryType?.name || Array.isArray(schema.types))) {
							introspectionEnabled = true;
							queryTypeName = schema.queryType?.name;
							exposedTypeCount = Array.isArray(schema.types) ? schema.types.length : 0;
						}
					} catch {
						introspectionEnabled = false;
					}
				}

				const summary = introspectionEnabled
					? `GraphQL 端点 (${gqlUrl}) 开启了未受限的 Schema Introspection（暴露 ${exposedTypeCount} 个类型定义）`
					: activeProbe.isSoft404
						? "GraphQL 探测路径命中 Soft-404 兜底，已去噪"
						: "未发现公开暴露的 GraphQL Introspection 元数据";

				resultsMap.graphql_introspect = {
					mode: "graphql_introspect",
					executed: true,
					anomalous: introspectionEnabled,
					suppressedBySoft404: !introspectionEnabled && activeProbe.isSoft404,
					blockedByScope: probes.some((p) => p.blocked),
					severity: introspectionEnabled ? "medium" : "info",
					...(introspectionEnabled ? { findingCode: "graphql_introspection_exposed" } : {}),
					summary,
					evidence: {
						graphqlUrl: gqlUrl,
						queryTypeName,
						exposedTypeCount,
					},
					probes: probes.map(toProbeSummary),
				};

				if (introspectionEnabled) {
					anomalies.push({
						mode: "graphql_introspect",
						findingCode: "graphql_introspection_exposed",
						severity: "medium",
						method: activeProbe.method,
						url: gqlUrl,
						path: new URL(gqlUrl).pathname,
						summary,
						evidence: resultsMap.graphql_introspect.evidence,
					});
				}
			});
		} else if (currentMode === "nextjs_rsc") {
			modeRunners.push(async () => {
				const { strippedUrl, strippedHeaders, removedKeys } = stripAuthFromRequest(
					baseRequest.url,
					baseHeaders,
				);

				const rscExtraHeaders = {
					RSC: "1",
					"Next-Router-State-Tree": "%5B%22%22%2C%7B%7D%5D",
				};

				const tasks: Array<() => Promise<RawProbeResult>> = [
					() =>
						sendGuardedProbe("nextjs_rsc_same_context", "GET", baseRequest.url, {
							...baseHeaders,
							...rscExtraHeaders,
						}),
				];

				if (removedKeys.length > 0) {
					tasks.push(() =>
						sendGuardedProbe("nextjs_rsc_unauthenticated", "GET", strippedUrl, {
							...strippedHeaders,
							...rscExtraHeaders,
						}),
					);
					tasks.push(() =>
						sendGuardedProbe("nextjs_plain_unauthenticated", "GET", strippedUrl, strippedHeaders),
					);
				}

				const probes = await runWithConcurrencyLimit(tasks, effectiveConcurrency);
				const sameCtxRsc = probes[0]!;
				const unauthRsc = probes[1];
				const unauthPlain = probes[2];

				const isFlightPayload = (p: RawProbeResult): boolean => {
					if (p.blocked || p.isSoft404 || p.status < 200 || p.status >= 300) return false;
					const ct = (p.headers["content-type"] ?? "").toLowerCase();
					return ct.includes("text/x-component") || /^\d+:["[{]/.test(p.body.trim());
				};

				const baselineBlockedOrRedirect =
					baselineProbe.status === 401 ||
					baselineProbe.status === 403 ||
					REDIRECT_STATUS_CODES.has(baselineProbe.status);

				const sameCtxBypass =
					baselineBlockedOrRedirect &&
					!sameCtxRsc.blocked &&
					!sameCtxRsc.isSoft404 &&
					sameCtxRsc.status >= 200 &&
					sameCtxRsc.status < 300;

				const unauthRscBypass =
					Boolean(unauthRsc && unauthPlain) &&
					(unauthPlain!.status === 401 ||
						unauthPlain!.status === 403 ||
						REDIRECT_STATUS_CODES.has(unauthPlain!.status)) &&
					!unauthRsc!.blocked &&
					!unauthRsc!.isSoft404 &&
					unauthRsc!.status >= 200 &&
					unauthRsc!.status < 300;

				const serverCrashDiff =
					baselineProbe.status < 500 && !sameCtxRsc.blocked && sameCtxRsc.status >= 500;

				const anomalous = sameCtxBypass || unauthRscBypass || serverCrashDiff;
				const softSuppressed = probes.some((p) => p.status === 200 && p.isSoft404);
				const flightDetected = isFlightPayload(sameCtxRsc) || (unauthRsc ? isFlightPayload(unauthRsc) : false);

				const summary = sameCtxBypass || unauthRscBypass
					? "Next.js RSC 请求头触发响应状态不一致（常规请求受阻而 RSC 请求返回 2xx），疑似中间件未覆盖 Flight 数据路由"
					: serverCrashDiff
						? `携带只读 RSC 头导致服务端异常响应 (HTTP ${sameCtxRsc.status} vs 基线 ${baselineProbe.status})`
						: softSuppressed
							? "Next.js RSC 探测命中 Flight 404 兜底，已自动去噪"
							: "Next.js RSC 头与常规请求响应策略保持一致";

				resultsMap.nextjs_rsc = {
					mode: "nextjs_rsc",
					executed: true,
					anomalous,
					suppressedBySoft404: !anomalous && softSuppressed,
					blockedByScope: probes.some((p) => p.blocked),
					severity: sameCtxBypass || unauthRscBypass ? "high" : serverCrashDiff ? "medium" : "info",
					...(anomalous ? { findingCode: "nextjs_rsc_response_inconsistency" } : {}),
					summary,
					evidence: {
						baselineStatus: baselineProbe.status,
						rscStatus: sameCtxRsc.status,
						unauthPlainStatus: unauthPlain?.status,
						unauthRscStatus: unauthRsc?.status,
						flightDetected,
					},
					probes: probes.map(toProbeSummary),
				};

				if (anomalous) {
					anomalies.push({
						mode: "nextjs_rsc",
						findingCode: "nextjs_rsc_response_inconsistency",
						severity: sameCtxBypass || unauthRscBypass ? "high" : "medium",
						method: "GET",
						url: baseRequest.url,
						path: entryCheck.parsed.pathname,
						summary,
						evidence: resultsMap.nextjs_rsc.evidence,
					});
				}
			});
		} else if (currentMode === "race_probe") {
			modeRunners.push(async () => {
				const burstCount = clampInt(
					opts?.raceCount,
					Math.min(5, effectiveConcurrency),
					2,
					Math.min(MAX_MUTATION_CONCURRENCY, effectiveConcurrency),
				);

				// 受控小并发同时触发，验证幂等性与状态一致性
				const probes = await Promise.all(
					Array.from({ length: burstCount }, (_, i) =>
						sendGuardedProbe(
							`race_${i + 1}`,
							safeBaselineMethod,
							baseRequest.url,
							baseHeaders,
							safeBaselineMethod === baseMethod ? baseRequest.body : undefined,
						),
					),
				);

				const validProbes = probes.filter((p) => !p.blocked && !p.timedOut && p.status > 0);
				const nonRateLimited = validProbes.filter((p) => p.status !== 429);
				const distinctStatuses = [...new Set(nonRateLimited.map((p) => p.status))];
				const successProbes = nonRateLimited.filter(
					(p) => p.status >= 200 && p.status < 300 && !p.isSoft404,
				);
				const distinctTemplates = [...new Set(successProbes.map((p) => p.templateHash))];

				// 状态分裂（排除正常 429 限流）或归一化模板指纹在并发下发生结构漂移视为幂等性异常
				const statusDiverged = distinctStatuses.length > 1;
				const templateDiverged = distinctTemplates.length > 1;
				const anomalous = statusDiverged || templateDiverged;

				const summary = anomalous
					? `受控 ${burstCount} 并发探测检出非幂等响应漂移（状态集合=[${distinctStatuses.join(",")}]，模板指纹数=${distinctTemplates.length}）`
					: `受控 ${burstCount} 并发探测响应状态与模板指纹保持幂等一致`;

				resultsMap.race_probe = {
					mode: "race_probe",
					executed: true,
					anomalous,
					suppressedBySoft404: !anomalous && validProbes.some((p) => p.isSoft404),
					blockedByScope: probes.some((p) => p.blocked),
					severity: anomalous ? "medium" : "info",
					...(anomalous ? { findingCode: "concurrency_idempotency_drift" } : {}),
					summary,
					evidence: {
						burstCount,
						distinctStatuses,
						distinctTemplateCount: distinctTemplates.length,
						rateLimitedCount: validProbes.filter((p) => p.status === 429).length,
					},
					probes: probes.map(toProbeSummary),
				};

				if (anomalous) {
					anomalies.push({
						mode: "race_probe",
						findingCode: "concurrency_idempotency_drift",
						severity: "medium",
						method: safeBaselineMethod,
						url: baseRequest.url,
						path: entryCheck.parsed.pathname,
						summary,
						evidence: resultsMap.race_probe.evidence,
					});
				}
			});
		}
	}

	// 顺序调度各模式（内部请求均受 MAX_MUTATION_CONCURRENCY <= 8 硬门禁控制），避免跨模式叠加突破 8 并发上限
	for (const runMode of modeRunners) {
		await runMode();
	}

	const orderedCases = requestedModes.map((m) => resultsMap[m]);
	const anyScopeBlocked = orderedCases.some((c) => c.blockedByScope);

	return {
		ok: !anyScopeBlocked,
		blockedByScope: anyScopeBlocked,
		effectiveConcurrency,
		baseline: {
			url: baselineProbe.url,
			method: baselineProbe.method,
			status: baselineProbe.status,
			bodyHash: baselineProbe.bodyHash,
			templateHash: baselineProbe.templateHash,
			bodyBytes: baselineProbe.bodyBytes,
			isSoft404: baselineProbe.isSoft404,
		},
		results: resultsMap,
		cases: orderedCases,
		anomalies,
	};
}
