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

import {
	DEFAULT_MAX_BODY_SNIPPET_CHARS,
	DEFAULT_MAX_REDIRECTS,
	DEFAULT_STEP_TIMEOUT_MS,
	EXPLICIT_SENSITIVE_HEADERS,
	MAX_MUTATION_CONCURRENCY,
	REDIRECT_STATUS_CODES,
	SAFE_STANDARD_HEADERS,
	SENSITIVE_HEADER_KEYWORD_RE,
	SENSITIVE_QUERY_PARAM_RE,
	clampInt,
	defaultFetchAdapter,
	executeTimedManualFetch,
	isSensitiveHeaderName,
	normalizeResponseHeaders,
	runStructuredMutations,
	validateHttpUrlAgainstScope,
	type MutationAnomaly,
	type MutationBaseRequest,
	type MutationCaseResult,
	type MutationMode,
	type MutationProbeSummary,
	type StructuredMutationsOptions,
	type StructuredMutationsResult,
	type TrafficEntry,
	type TrafficFetchFn,
	type TrafficFetchResponseLike,
	type TrafficRecordInput,
	type TrafficRecorderLike,
} from "./traffic-mutator";

export * from "./traffic-mutator";

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

const SENSITIVE_JSON_FIELD_RE =
	/^(?:password|passwd|pwd|secret|clientSecret|client_secret|accessToken|access_token|refreshToken|refresh_token|idToken|id_token|apiKey|api_key|apiToken|api_token|authToken|auth_token|csrfToken|csrf_token|xsrfToken|xsrf_token|privateKey|private_key|sessionToken|session_token|token|bearer|jwt|authorization|cookie|setCookie|set_cookie|xApiKey|x_api_key)$/i;

const JWT_TOKEN_RE = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const BEARER_INLINE_RE = /\b(Bearer|Basic|Token|JWT)\s+([A-Za-z0-9._~+/=-]{6,})/gi;
const URL_USERINFO_RE = /\b(https?:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;
const QUERY_KV_SECRET_RE =
	/([?&#](?:access_token|refresh_token|id_token|auth_token|api_key|apikey|api_token|csrf_token|xsrf_token|token|secret|client_secret|password|passwd|pwd|auth|jwt|session|session_id|sid|csrf|xsrf|sig|signature|ticket|private_token|key)=)([^&#\s"']+)/gi;

export const REDACTED_MARKER = "[REDACTED]" as const;

// ==================== 公共接口与类型定义 ====================

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

// ==================== 内部工具与零明文脱敏实现 ====================

interface StoredCookie {
	name: string;
	value: string;
	domain?: string;
	hostOnly: boolean;
	path: string;
}

let recordCounter = 0;

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

/** 对 URL 执行零明文脱敏（擦除 userinfo、敏感查询参数、URL Fragment 敏感键值及已知 Vault 密钥，同时保持其余参数完好）。 */
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
		if (u.hash && u.hash.length > 1) {
			const rawFrag = u.hash.slice(1);
			const qIdx = rawFrag.indexOf("?");
			if (qIdx >= 0) {
				const routePrefix = rawFrag.slice(0, qIdx + 1);
				const fragParams = new URLSearchParams(rawFrag.slice(qIdx + 1));
				for (const fk of [...fragParams.keys()]) {
					if (SENSITIVE_QUERY_PARAM_RE.test(fk)) {
						fragParams.set(fk, REDACTED_MARKER);
					} else {
						const fv = fragParams.get(fk) ?? "";
						fragParams.set(fk, scrubKnownSecrets(fv, knownSecrets, opts?.vault ?? opts?.root));
					}
				}
				u.hash = `#${routePrefix}${fragParams.toString()}`;
			} else if (rawFrag.includes("=")) {
				const fragParams = new URLSearchParams(rawFrag);
				for (const fk of [...fragParams.keys()]) {
					if (SENSITIVE_QUERY_PARAM_RE.test(fk)) {
						fragParams.set(fk, REDACTED_MARKER);
					} else {
						const fv = fragParams.get(fk) ?? "";
						fragParams.set(fk, scrubKnownSecrets(fv, knownSecrets, opts?.vault ?? opts?.root));
					}
				}
				u.hash = `#${fragParams.toString()}`;
			} else {
				u.hash = `#${scrubKnownSecrets(rawFrag, knownSecrets, opts?.vault ?? opts?.root)}`;
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
					/("(?:password|passwd|pwd|secret|client_secret|clientSecret|access_token|accessToken|refresh_token|refreshToken|id_token|idToken|api_key|apiKey|apikey|api_token|apiToken|auth_token|authToken|csrf_token|csrfToken|xsrf_token|xsrfToken|session_id|sessionId|session_token|sessionToken|private_token|privateToken|private_key|privateKey|token|jwt|bearer|sid|ticket)"\s*:\s*)"[^"]*"/gi,
					`$1"${REDACTED_MARKER}"`,
				)
				.replace(
					/('(?:password|passwd|pwd|secret|client_secret|clientSecret|access_token|accessToken|refresh_token|refreshToken|id_token|idToken|api_key|apiKey|apikey|api_token|apiToken|auth_token|authToken|csrf_token|csrfToken|xsrf_token|xsrfToken|session_id|sessionId|session_token|sessionToken|private_token|privateToken|private_key|privateKey|token|jwt|bearer|sid|ticket)'\s*:\s*)'[^']*'/gi,
					`$1'${REDACTED_MARKER}'`,
				);
		}
	} else {
		// 处理 JSON 片段、单引号对象字面量或 application/x-www-form-urlencoded 敏感键值对
		sanitized = raw
			.replace(
				/("(?:password|passwd|pwd|secret|client_secret|clientSecret|access_token|accessToken|refresh_token|refreshToken|id_token|idToken|api_key|apiKey|apikey|api_token|apiToken|auth_token|authToken|csrf_token|csrfToken|xsrf_token|xsrfToken|session_id|sessionId|session_token|sessionToken|private_token|privateToken|private_key|privateKey|token|jwt|bearer|sid|ticket)"\s*:\s*)"[^"]*"/gi,
				`$1"${REDACTED_MARKER}"`,
			)
			.replace(
				/('(?:password|passwd|pwd|secret|client_secret|clientSecret|access_token|accessToken|refresh_token|refreshToken|id_token|idToken|api_key|apiKey|apikey|api_token|apiToken|auth_token|authToken|csrf_token|csrfToken|xsrf_token|xsrfToken|session_id|sessionId|session_token|sessionToken|private_token|privateToken|private_key|privateKey|token|jwt|bearer|sid|ticket)'\s*:\s*)'[^']*'/gi,
				`$1'${REDACTED_MARKER}'`,
			)
			.replace(
				/(^|[?&#\s])((?:password|passwd|pwd|secret|client_secret|access_token|refresh_token|id_token|api_key|apikey|api_token|auth_token|csrf_token|xsrf_token|session_id|session_token|private_token|token|jwt|sid|ticket)=)([^&#\s"']+)/gi,
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

		// 自动收集本次请求 URL userinfo / 查询参数 / Fragment 与请求/响应敏感头中的原始凭据值，防止其在同条响应回显中明文残留
		const reqRawSecrets: string[] = [...this.extraSecrets];
		const pushRawCandidate = (candidate: string | undefined, minLen = 4) => {
			const c = String(candidate ?? "").trim();
			if (c.length >= minLen && !GENERIC_NON_SECRET_WORDS.has(c.toLowerCase())) {
				reqRawSecrets.push(c);
			}
		};
		try {
			const rawParsed = new URL(input.url);
			if (rawParsed.password && rawParsed.password.length >= 3) {
				pushRawCandidate(decodeURIComponent(rawParsed.password), 3);
			}
			for (const [qk, qv] of rawParsed.searchParams.entries()) {
				if (SENSITIVE_QUERY_PARAM_RE.test(qk)) {
					pushRawCandidate(qv, 4);
				}
			}
			if (rawParsed.hash && rawParsed.hash.length > 1) {
				const rawFrag = rawParsed.hash.slice(1);
				const qPart = rawFrag.includes("?") ? rawFrag.slice(rawFrag.indexOf("?") + 1) : rawFrag;
				if (qPart.includes("=")) {
					const fp = new URLSearchParams(qPart);
					for (const [fk, fv] of fp.entries()) {
						if (SENSITIVE_QUERY_PARAM_RE.test(fk)) {
							pushRawCandidate(fv, 4);
						}
					}
				}
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
							pushRawCandidate(seg.slice(eq + 1), 4);
						}
					}
				} else {
					const bare = strVal.replace(/^(?:Bearer|Basic|Token|JWT|Digest)\s+/i, "").trim();
					pushRawCandidate(bare, 4);
				}
			}
		}
		if (input.responseHeaders) {
			for (const [hk, hv] of Object.entries(input.responseHeaders)) {
				if (!hv || !isSensitiveHeaderName(hk)) continue;
				const lowerHk = hk.toLowerCase();
				if (lowerHk === "set-cookie") {
					const lines = Array.isArray(hv) ? hv : String(hv).split(/\r?\n/);
					for (const line of lines) {
						const first = line.split(";")[0]?.trim() ?? "";
						const eq = first.indexOf("=");
						if (eq > 0) {
							pushRawCandidate(first.slice(eq + 1), 4);
						}
					}
				} else {
					const strVal = Array.isArray(hv) ? hv.join(", ") : String(hv);
					const bare = strVal.replace(/^(?:Bearer|Basic|Token|JWT|Digest)\s+/i, "").trim();
					pushRawCandidate(bare, 4);
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

function cookieJarKey(domain: string | undefined, path: string, name: string): string {
	return `${domain ?? "*"}|${path}|${name}`;
}

function isIpLiteralHost(host: string): boolean {
	return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}

function ingestSetCookiesIntoJar(
	jar: Map<string, StoredCookie>,
	setCookies: string[],
	requestUrl: URL,
): void {
	const reqHost = requestUrl.hostname.toLowerCase();

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

		let rawDomainAttr: string | undefined;
		let path = "/";
		let expired = false;

		for (let i = 1; i < segments.length; i++) {
			const attr = segments[i]!;
			const aEq = attr.indexOf("=");
			const aKey = (aEq > 0 ? attr.slice(0, aEq) : attr).trim().toLowerCase();
			const aVal = aEq > 0 ? attr.slice(aEq + 1).trim() : "";
			if (aKey === "domain" && aVal) {
				rawDomainAttr = aVal.replace(/^\.+/, "").toLowerCase();
			} else if (aKey === "path" && aVal) {
				path = aVal.startsWith("/") ? aVal : "/";
			} else if (aKey === "max-age") {
				const n = Number(aVal);
				if (Number.isFinite(n) && n <= 0) expired = true;
			}
		}

		let cookieDomain = reqHost;
		let hostOnly = true;

		if (rawDomainAttr !== undefined) {
			// RFC 6265 §5.3：拒绝单段顶级域（如 Domain=com / Domain=test）以及与请求主机不匹配的跨站 Domain
			if (!rawDomainAttr || (!rawDomainAttr.includes(".") && !isIpLiteralHost(rawDomainAttr))) {
				continue;
			}
			if (isIpLiteralHost(reqHost)) {
				if (rawDomainAttr !== reqHost) continue;
			} else if (reqHost !== rawDomainAttr && !reqHost.endsWith(`.${rawDomainAttr}`)) {
				continue;
			}
			cookieDomain = rawDomainAttr;
			hostOnly = false;
		}

		const key = cookieJarKey(cookieDomain, path, name);
		if (expired || value === "") {
			jar.delete(key);
			continue;
		}
		jar.set(key, {
			name,
			value,
			domain: cookieDomain,
			hostOnly,
			path,
		});
	}
}

function doesCookieMatchUrl(item: StoredCookie, targetUrl: URL): boolean {
	const reqHost = targetUrl.hostname.toLowerCase();
	const reqPath = targetUrl.pathname || "/";

	if (item.domain !== undefined) {
		if (item.hostOnly) {
			if (reqHost !== item.domain) return false;
		} else {
			if (
				reqHost !== item.domain &&
				(isIpLiteralHost(reqHost) || !reqHost.endsWith(`.${item.domain}`))
			) {
				return false;
			}
		}
	}

	if (item.path && item.path !== "/") {
		const pathMatches =
			reqPath === item.path ||
			(item.path.endsWith("/") && reqPath.startsWith(item.path)) ||
			reqPath.startsWith(`${item.path}/`);
		if (!pathMatches) return false;
	}
	return true;
}

function buildCookieHeaderFromJar(
	jar: Map<string, StoredCookie>,
	targetUrl: URL,
	explicitCookieHeader?: string,
): string | undefined {
	const merged = new Map<string, string>();

	for (const item of jar.values()) {
		if (!doesCookieMatchUrl(item, targetUrl)) continue;
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
			const wantCookieName = spec.cookie.trim();
			for (const item of cookieJar.values()) {
				if (item.name === wantCookieName) {
					extractedVal = item.value;
				}
			}
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
				cookieJar.set(cookieJarKey(undefined, "/", ck), {
					name: ck,
					value: cv,
					hostOnly: false,
					path: "/",
				});
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

				const prevOrigin = currentUrlObj.origin;
				const nextParsed = redirectScopeCheck.parsed;
				redirectChain.push(nextUrlRaw);
				currentUrlObj = nextParsed;

				// 跨 Origin 重定向时强制剥离全部敏感认证/令牌请求头，严防 Authorization / API-Key 跨站泄露
				if (nextParsed.origin !== prevOrigin) {
					for (const hk of Object.keys(interpolatedHeaders)) {
						if (isSensitiveHeaderName(hk)) {
							delete interpolatedHeaders[hk];
						}
					}
				}

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
	for (const item of cookieJar.values()) {
		cookiesOut[item.name] = item.value;
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
