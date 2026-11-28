/**
 * 女娲 v8.0.0 结构化 HTTP 契约差分变异校验器（`runStructuredMutations`）与底层合规探测传输辅助模块。
 *
 * 约束：零外部第三方依赖，严禁导入 `./nuwa` 或 `./traffic-workbench`，保持纯单向无环依赖。
 */
import { randomUUID } from "node:crypto";
import {
	computeBodyHash,
	computeTemplateFingerprint,
	detectSoft404,
	type Soft404Baseline,
	type Soft404BaselineInput,
} from "./autoexec-baseline";
import {
	checkScopeAndRisk,
	formatScopeBlockReason,
	isHostInScope,
} from "./scope";
import {
	getRoleHeadersMap,
	type SessionVault,
} from "./session-vault";
import type { Mode, ScopePolicy } from "./types";

/** 差分校验并发度硬上限（任何配置均不可突破 8）。 */
export const MAX_MUTATION_CONCURRENCY = 8 as const;

/** 单条流量记录保留的最大响应片段字符数。 */
export const DEFAULT_MAX_BODY_SNIPPET_CHARS = 4096;

/** 默认单步 HTTP 超时时间（毫秒）。 */
export const DEFAULT_STEP_TIMEOUT_MS = 8_000;

/** 默认允许安全跟随的同域/授权范围内最大重定向跳数。 */
export const DEFAULT_MAX_REDIRECTS = 5;

export const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

/** 必须强制完全脱敏的显式 HTTP 头集合（小写）。 */
export const EXPLICIT_SENSITIVE_HEADERS = new Set([
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
export const SAFE_STANDARD_HEADERS = new Set([
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

export const SENSITIVE_HEADER_KEYWORD_RE =
	/(?:auth|token|key|secret|cookie|session|jwt|csrf|xsrf|pass|cred|sign|bearer|ticket)/i;

export const SENSITIVE_QUERY_PARAM_RE =
	/^(?:access_token|refresh_token|id_token|auth_token|api_key|apikey|token|secret|client_secret|password|passwd|pwd|auth|jwt|session|session_id|sid|csrf|csrf_token|xsrf|xsrf_token|sig|signature|ticket|private_token|key)$/i;

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

export interface TrafficRecorderLike {
	record(input: TrafficRecordInput): TrafficEntry;
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
	recorder?: TrafficRecorderLike;
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

export function clampInt(val: unknown, fallback: number, min: number, max: number): number {
	if (val === Number.POSITIVE_INFINITY) return max;
	if (val === Number.NEGATIVE_INFINITY) return min;
	if (typeof val !== "number" || !Number.isFinite(val)) return fallback;
	return Math.max(min, Math.min(max, Math.floor(val)));
}

export function isSensitiveHeaderName(headerName: string): boolean {
	const lower = headerName.trim().toLowerCase();
	if (!lower) return false;
	if (EXPLICIT_SENSITIVE_HEADERS.has(lower)) return true;
	if (SAFE_STANDARD_HEADERS.has(lower)) return false;
	if (lower.startsWith("sec-") || lower.startsWith("accept-") || lower.startsWith("content-") || lower.startsWith("access-control-")) {
		return false;
	}
	return SENSITIVE_HEADER_KEYWORD_RE.test(lower);
}

export function validateHttpUrlAgainstScope(
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

export function normalizeResponseHeaders(
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

export async function executeTimedManualFetch(
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

export function defaultFetchAdapter(
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

	// 底层硬信号量门闸（直接槽位所有权移交，彻底消除微任务唤醒空窗抢占，保证峰值严格 <= effectiveConcurrency）
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
	};
	const releaseProbeSlot = (): void => {
		const next = waitQueue.shift();
		if (next) {
			// 直接将当前已占用槽位原子移交给队首等待协程，activeProbes 不递减也不在恢复时重加
			next();
			return;
		}
		activeProbes = Math.max(0, activeProbes - 1);
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
						p.bodyHash !== baselineProbe.bodyHash,
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
				const maxRaceBurst = Math.max(1, Math.min(MAX_MUTATION_CONCURRENCY, effectiveConcurrency));
				const minRaceBurst = Math.min(2, maxRaceBurst);
				const burstCount = clampInt(
					opts?.raceCount,
					Math.min(5, maxRaceBurst),
					minRaceBurst,
					maxRaceBurst,
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
