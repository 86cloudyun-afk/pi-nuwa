import { randomBytes } from "node:crypto";
import {
	checkScopeAndRisk,
	formatScopeBlockReason,
	isHostInScope,
} from "./scope";
import type { Mode, ScopePolicy } from "./types";
import {
	computeBodyHash,
	computeTemplateFingerprint,
	detectSoft404,
	sampleSoft404Baseline,
} from "./autoexec";
import type { AutoFact, Soft404Baseline, Soft404BaselineInput } from "./autoexec";
import {
	computeKeyJaccard,
	extractJsonTopKeys,
	isAdminLikePath,
	isAdminLikeRole,
	isObjectResourcePath,
} from "./auth-diff";
import type { AuthDiffAnomalyKind } from "./auth-diff";
import {
	getRoleHeadersMap,
	loadSessionVault,
	redactVaultSecrets,
} from "./session-vault";
import type { SessionVault } from "./session-vault";
import {
	redactTrafficBody,
	redactTrafficHeaders,
	redactTrafficUrl,
	TrafficRecorder,
} from "./traffic-workbench";
import {
	closeCdpSession,
	launchCdpSession,
	MAX_CDP_PROBE_CONCURRENCY,
} from "./cdp-bridge";
import type { CdpSession } from "./cdp-bridge";

/**
 * 女娲 v7.0 页面内有状态动态加签只读/受控探针与多角色鉴权差分。
 *
 * 约束：仅使用本地模块与 Node 内置 crypto；任何日志、错误、记录、摘要与 AutoFact
 * 均经 SessionVault、URL 查询参数、Cookie、Authorization 与额外运行时密钥全量脱敏。
 */

export const MAX_STATEFUL_PROBE_CONCURRENCY = MAX_CDP_PROBE_CONCURRENCY;

export type StatefulHttpMethod = "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface InPageStatefulSignedProbeSpec {
	/** 目标完整 URL 或相对当前同源页面的路径。 */
	url: string;
	/** 支持 GET / HEAD / OPTIONS / POST / PUT / PATCH / DELETE（默认 GET）。 */
	method?: StatefulHttpMethod | string;
	/** 附加安全请求头。 */
	headers?: Record<string, string>;
	/** 自定义请求体（字符串或可 JSON 序列化的结构化对象/数组）。 */
	body?: string | Record<string, unknown> | unknown[];
	/** 显式 Content-Type（当 body 为对象且未指定时默认使用 application/json）。 */
	contentType?: string;
	/** 页面内签名钩子路径（如 "__nuwaSign" 或 "app.signRequest"）。 */
	signerHook?: string;
	/**
	 * 认证态模式：
	 * - "inherit"：沿用当前页面会话（含 HttpOnly Cookie）；
	 * - "anonymous"：剥离全部 Cookie / Authorization / 认证头，仅保留前端动态签名头；
	 * - "override"：替换为指定角色或 overrideAuthHeaders 的认证凭据，同时保留动态签名头。
	 */
	authMode?: "inherit" | "anonymous" | "override";
	/** 当指定 role 时，若未提供 overrideAuthHeaders，自动从 SessionVault 提取该角色头并以 override 模式发送。 */
	role?: string;
	overrideAuthHeaders?: Record<string, string>;
	/** 是否允许跨出当前页面 origin 访问授权 Scope 内的其他主机（默认 false，强制同源）。 */
	allowCrossOriginInScope?: boolean;
}

export interface InPageStatefulProbeOptions {
	mode?: Mode | string;
	timeoutMs?: number;
	root?: string;
	vault?: SessionVault;
	recorder?: TrafficRecorder;
	roleLabel?: string;
	soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null;
	extraSecrets?: string[];
}

export interface InPageStatefulSignedProbeResult {
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

export interface StatefulEndpointTargetSpec {
	path: string;
	method?: StatefulHttpMethod | string;
	body?: string | Record<string, unknown> | unknown[];
	headers?: Record<string, string>;
	contentType?: string;
}

export interface CdpStatefulSignedDiffFinding {
	path: string;
	method: string;
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
		method: string;
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

export interface RunCdpStatefulSignedAuthDiffOptions {
	session?: CdpSession;
	baselineRole?: string;
	compareRoles?: string[];
	extraRoleHeaders?: Record<string, Record<string, string>>;
	signerHook?: string;
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
	launchOptions?: Parameters<typeof launchCdpSession>[0];
}

export interface RunCdpStatefulSignedAuthDiffResult {
	ok: boolean;
	targetUrl: string;
	blockedByScope: boolean;
	blockReason?: string;
	effectiveConcurrency: number;
	testedEndpoints: string[];
	blockedEndpoints: string[];
	unsignedStatuses: Record<string, number>;
	findings: CdpStatefulSignedDiffFinding[];
	fact: AutoFact | null;
}

export interface StatefulProbeInterceptRule {
	authMode: "inherit" | "anonymous" | "override";
	overrideHeaders?: Record<string, string>;
	matchedUrl?: string;
	blockedReason?: string;
	method?: string;
}

export interface UpgradedInterceptorState {
	enabled: boolean;
	scope: ScopePolicy;
	mode: Mode | string;
	allowedMethods?: ReadonlySet<string>;
	readonlyLockCount: number;
	lastReadonlyBlockReason?: string;
	blockedRequests: Array<{ url: string; method: string; resourceType?: string; reason: string }>;
	probeRules: Map<string, StatefulProbeInterceptRule>;
	_statefulUpgraded: true;
	_statefulProbeRules: Map<string, StatefulProbeInterceptRule>;
	onAllowedRequest?: (info: {
		requestId: string;
		url: string;
		method: string;
		headers: Record<string, string>;
	}) => void;
	unsubscribe?: () => void;
}

const REDACTED = "[REDACTED]" as const;
const INTERNAL_STATEFUL_HEADER = "x-nuwa-stateful-probe-token";
const CDP_INTERNAL_PROBE_HEADER = "x-nuwa-cdp-probe-token";
const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_NAVIGATION_TIMEOUT_MS = 15_000;
const DEFAULT_SETTLE_MS = 450;
const MAX_BODY_CAPTURE = 65_536;
const MAX_SNIPPET_CHARS = 4_096;
const SAFE_SIGNER_HOOK_RE = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){0,4}$/;
const FORBIDDEN_HOOK_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);
const STATEFUL_HTTP_METHODS = new Set([
	"GET",
	"HEAD",
	"OPTIONS",
	"POST",
	"PUT",
	"PATCH",
	"DELETE",
]);
const READONLY_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const AUTH_HEADER_NAMES = new Set([
	"cookie",
	"authorization",
	"proxy-authorization",
	"x-csrf-token",
	"x-xsrf-token",
	"csrf-token",
	"xsrf-token",
	"x-api-key",
	"x-auth-token",
	"x-amz-security-token",
]);
const SENSITIVE_HEADER_NAME_RE =
	/^(?:authorization|proxy-authorization|cookie|set-cookie|x-csrf-token|x-xsrf-token|csrf-token|xsrf-token|x-api-key|x-auth-token|api-key|token|secret|password|passwd|session|jwt)/i;
const PURE_ERROR_TEXT_RE =
	/^(?:error|not\s*found|forbidden|unauthorized|access\s*denied|invalid\s+(?:token|request|user)|login\s+required|authentication\s+required|页面不存在|无权限|未授权)/i;

interface RawPageStatefulResult {
	ok?: boolean;
	status?: number;
	headers?: unknown;
	body?: string;
	bodyBytes?: number;
	signedByHook?: boolean;
	appliedSignatureHeaders?: string[];
	durationMs?: number;
	error?: string;
	timedOut?: boolean;
	hookError?: string;
	invalidProtocolBlocked?: string;
	crossOriginHookBlocked?: string;
}

interface RuntimeEvaluateResponse {
	result?: { value?: unknown; description?: string; type?: string };
	exceptionDetails?: { text?: string; exception?: { description?: string } };
}

interface NormalizedEndpoint {
	index: number;
	rawUrl: string;
	path: string;
	method: string;
	headers?: Record<string, string>;
	body?: InPageStatefulSignedProbeSpec["body"];
	contentType?: string;
}

interface ProbeTask {
	endpoint: NormalizedEndpoint;
	role: string;
	label: string;
}

function pushSecret(out: Set<string>, raw: unknown): void {
	const value = String(raw ?? "").trim();
	if (value.length >= 4 && value !== REDACTED) out.add(value);
}

/** 从认证头映射中提取需强制脱敏的明文凭据（含 Cookie、Bearer、Basic 解码口令与敏感自定义头）。 */
export function extractSecretsFromHeadersMap(headers?: Record<string, string>): string[] {
	const out = new Set<string>();
	if (!headers) return [];
	for (const [rawKey, rawVal] of Object.entries(headers)) {
		const key = String(rawKey ?? "").trim();
		const value = String(rawVal ?? "").trim();
		if (!key || !value) continue;
		const lower = key.toLowerCase();

		if (lower === "cookie" || lower === "set-cookie") {
			pushSecret(out, value);
			for (const part of value.split(/;\s*/)) {
				const eq = part.indexOf("=");
				if (eq > 0) pushSecret(out, part.slice(eq + 1).trim());
			}
			continue;
		}

		if (lower === "authorization" || lower === "proxy-authorization") {
			pushSecret(out, value);
			const match = /^(Bearer|Basic|Token|JWT|Digest)\s+(.+)$/i.exec(value);
			if (!match) continue;
			const scheme = match[1].toUpperCase();
			const token = match[2].trim();
			pushSecret(out, token);
			if (scheme === "BASIC") {
				try {
					const decoded = Buffer.from(token, "base64").toString("utf8");
					pushSecret(out, decoded);
					const colon = decoded.indexOf(":");
					if (colon >= 0 && colon < decoded.length - 1) pushSecret(out, decoded.slice(colon + 1));
				} catch { /* ignore */ }
			}
			continue;
		}

		if (SENSITIVE_HEADER_NAME_RE.test(lower)) {
			pushSecret(out, value);
			continue;
		}

		const embedded = /\b(Bearer|Basic|Token|JWT)\s+([A-Za-z0-9._~+/=-]{6,})/i.exec(value);
		if (embedded) pushSecret(out, embedded[2]);
	}
	return [...out];
}

function collectVaultSecretValues(rootOrVault?: string | SessionVault): string[] {
	if (!rootOrVault) return [];
	try {
		const vault = typeof rootOrVault === "string" ? loadSessionVault(rootOrVault) : rootOrVault;
		const out = new Set<string>();
		for (const entry of Object.values(vault.roles ?? {})) {
			if (!entry) continue;
			if (entry.password) pushSecret(out, entry.password);
			if (entry.bearer) {
				pushSecret(out, entry.bearer);
				pushSecret(out, entry.bearer.replace(/^Bearer\s+/i, "").trim());
			}
			if (entry.cookie) {
				for (const s of extractSecretsFromHeadersMap({ cookie: entry.cookie })) pushSecret(out, s);
			}
			if (entry.headers) {
				for (const s of extractSecretsFromHeadersMap(entry.headers)) pushSecret(out, s);
			}
		}
		return [...out];
	} catch {
		return [];
	}
}

/** 对任意文本执行额外运行时密钥与 SessionVault（优先全掩码再兜底局部掩码）的零明文脱敏。 */
export function scrubTextWithExtraSecrets(
	text: string,
	extraSecrets?: readonly string[],
	rootOrVault?: string | SessionVault,
): string {
	let out = String(text ?? "");
	const values = [...new Set([...(extraSecrets ?? []), ...collectVaultSecretValues(rootOrVault)])]
		.map((s) => String(s ?? "").trim())
		.filter((s) => s.length >= 4 && s !== REDACTED)
		.sort((a, b) => b.length - a.length);

	for (const secret of values) {
		const variants = new Set<string>([secret]);
		try {
			const encoded = encodeURIComponent(secret);
			variants.add(encoded);
			variants.add(encoded.replace(/%20/g, "+"));
		} catch { /* ignore */ }
		for (const variant of variants) {
			if (variant && out.includes(variant)) out = out.split(variant).join(REDACTED);
		}
	}
	if (rootOrVault) {
		try { out = redactVaultSecrets(out, rootOrVault); } catch { /* 保持兜底 */ }
	}
	return out;
}

/** 大小写不敏感读取头值。 */
function findHeaderCaseInsensitive(headers: Record<string, string>, name: string): string | undefined {
	const lower = String(name ?? "").toLowerCase();
	for (const [k, v] of Object.entries(headers)) {
		if (k.toLowerCase() === lower) return v;
	}
	return undefined;
}

/** 将 CDP 头数组或普通对象规范化为字符串映射。 */
export function normalizeCdpHeadersObject(rawHeaders: unknown): Record<string, string> {
	const out: Record<string, string> = {};
	if (!rawHeaders) return out;
	if (Array.isArray(rawHeaders)) {
		for (const item of rawHeaders) {
			if (!item || typeof item !== "object") continue;
			const rec = item as Record<string, unknown>;
			const key = typeof rec.name === "string" ? rec.name.trim() : "";
			const value = typeof rec.value === "string" ? rec.value : "";
			if (!key) continue;
			out[key] = out[key] ? `${out[key]}; ${value}` : value;
		}
		return out;
	}
	if (typeof rawHeaders === "object") {
		for (const [k, v] of Object.entries(rawHeaders as Record<string, unknown>)) {
			if (v === undefined || v === null) continue;
			const cleanKey = String(k).trim();
			if (!cleanKey) continue;
			out[cleanKey] = Array.isArray(v) ? v.map(String).join("\n") : String(v);
		}
	}
	return out;
}

/** 校验主机或 URL 的 Scope 与破坏性风险，供 CDP 拦截层与直连基线共用。 */
export function checkHttpTargetScope(
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
				`${label} 越界 (${parsed.hostname}) — ${hostVerdict.reason ?? "不在授权 Scope 内"}`,
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
		return { ok: false, reason: riskVerdict.reason };
	}
	return { ok: true, parsed };
}

/** 构造最终发往目标服务端的头数组，内部对齐头永不出网，并按 authMode 净化认证头。 */
function buildStatefulHeaderEntries(
	originalHeaders: Record<string, string>,
	rule: StatefulProbeInterceptRule,
): Array<{ name: string; value: string }> {
	const filtered: Array<[string, string]> = [];
	for (const [rawKey, rawVal] of Object.entries(originalHeaders)) {
		const key = String(rawKey ?? "").replace(/[\r\n]+/g, "").trim();
		const value = String(rawVal ?? "").replace(/[\r\n]+/g, " ").trim();
		if (!key) continue;
		const lower = key.toLowerCase();
		if (lower === INTERNAL_STATEFUL_HEADER || lower === CDP_INTERNAL_PROBE_HEADER) continue;
		if ((rule.authMode === "anonymous" || rule.authMode === "override") && AUTH_HEADER_NAMES.has(lower)) {
			continue;
		}
		filtered.push([key, value]);
	}

	if (rule.authMode === "override" && rule.overrideHeaders) {
		const existing = new Map<string, number>();
		filtered.forEach(([key], idx) => existing.set(key.toLowerCase(), idx));
		for (const [rawKey, rawVal] of Object.entries(rule.overrideHeaders)) {
			const key = String(rawKey ?? "").replace(/[\r\n]+/g, "").trim();
			const value = String(rawVal ?? "").replace(/[\r\n]+/g, " ").trim();
			if (!key || !value) continue;
			const prev = existing.get(key.toLowerCase());
			if (prev !== undefined) {
				filtered[prev] = [key, value];
			} else {
				existing.set(key.toLowerCase(), filtered.length);
				filtered.push([key, value]);
			}
		}
	}

	return filtered.map(([name, value]) => ({ name, value }));
}

/** 读取当前页面 origin；页面尚未导航或为 about: 时返回 null。 */
export async function getCurrentPageOrigin(session: CdpSession, timeoutMs = 5_000): Promise<string | null> {
	try {
		const evalRes = await session.client.send<RuntimeEvaluateResponse>(
			"Runtime.evaluate",
			{ expression: "window.location.href", returnByValue: true },
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
 * 挂载或升级可支持有状态方法的 Fetch 拦截器。
 * 所有不在 Scope 内的子请求在发包前直接 failRequest；探针请求强制剥离内部对齐头并按角色覆写认证头。
 */
export async function ensureStatefulCapableInterceptor(
	session: CdpSession,
	scope: ScopePolicy,
	mode: Mode | string = "audit",
): Promise<UpgradedInterceptorState> {
	const holder = session as unknown as { _interceptor?: UpgradedInterceptorState };
	const existing = holder._interceptor;
	if (existing?._statefulUpgraded && existing.enabled) {
		existing.scope = scope;
		existing.mode = mode;
		return existing;
	}
	if (existing?.enabled) {
		try {
			existing.unsubscribe?.();
		} catch {
			/* ignore */
		}
	}

	const state: UpgradedInterceptorState = {
		enabled: true,
		scope,
		mode,
		readonlyLockCount: 0,
		blockedRequests: [],
		probeRules: new Map<string, StatefulProbeInterceptRule>(),
		_statefulUpgraded: true,
		_statefulProbeRules: new Map<string, StatefulProbeInterceptRule>(),
	};

	const sendContinue = (requestId: string, headers?: Array<{ name: string; value: string }>): void => {
		const params: Record<string, unknown> = { requestId };
		if (headers) params.headers = headers;
		void session.client
			.send("Fetch.continueRequest", params, { sessionId: session.sessionId, timeoutMs: 3_000 })
			.catch(() => {});
	};

	const sendFail = (requestId: string, reason: string, url: string, method: string, resourceType?: string): void => {
		state.blockedRequests.push({
			url: redactTrafficUrl(url),
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
		const requestHeaders = normalizeCdpHeadersObject(reqObj.headers);
		const lowerUrl = rawUrl.trim().toLowerCase();

		if (lowerUrl.startsWith("about:")) {
			sendContinue(requestId);
			return;
		}

		if (lowerUrl.startsWith("data:") || lowerUrl.startsWith("blob:")) {
			if (state.readonlyLockCount > 0) {
				const reason = formatScopeBlockReason(
					"egress-proxy",
					`只读探针期间禁止非 HTTP(S) 伪协议请求 (${rawUrl.slice(0, 48)})`,
					"N-007",
				);
				state.lastReadonlyBlockReason = reason;
				sendFail(requestId, reason, rawUrl, method, resourceType);
				return;
			}
			sendContinue(requestId);
			return;
		}

		const token =
			findHeaderCaseInsensitive(requestHeaders, INTERNAL_STATEFUL_HEADER)?.trim() ||
			findHeaderCaseInsensitive(requestHeaders, CDP_INTERNAL_PROBE_HEADER)?.trim();
		const rule = token
			? state._statefulProbeRules.get(token) ?? state.probeRules.get(token)
			: undefined;

		const scopeCheck = checkHttpTargetScope(rawUrl, method, state.scope, state.mode, "CDP 子请求");
		if (!scopeCheck.ok) {
			if (rule) rule.blockedReason = scopeCheck.reason;
			sendFail(requestId, scopeCheck.reason, rawUrl, method, resourceType);
			return;
		}

		if (rule) {
			rule.matchedUrl = rawUrl;
			if (!STATEFUL_HTTP_METHODS.has(method)) {
				const reason = formatScopeBlockReason(
					"egress-proxy",
					`页面内有状态探针仅允许白名单方法 GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE，已拦截 ${method}`,
					"N-008",
				);
				rule.blockedReason = reason;
				state.lastReadonlyBlockReason = reason;
				sendFail(requestId, reason, rawUrl, method, resourceType);
				return;
			}
			if (rule.method && rule.method !== method) {
				const reason = formatScopeBlockReason(
					"egress-proxy",
					`探针对齐方法不匹配，期望 ${rule.method} 实际 ${method}`,
					"N-008",
				);
				rule.blockedReason = reason;
				sendFail(requestId, reason, rawUrl, method, resourceType);
				return;
			}

			const rewrittenHeaders = buildStatefulHeaderEntries(requestHeaders, rule);
			const flatForLog: Record<string, string> = {};
			for (const h of rewrittenHeaders) flatForLog[h.name] = h.value;
			state.onAllowedRequest?.({
				requestId: typeof params.networkId === "string" ? params.networkId : requestId,
				url: rawUrl,
				method,
				headers: flatForLog,
			});
			sendContinue(requestId, rewrittenHeaders);
			return;
		}

		const blockedByReadonlyLock = state.readonlyLockCount > 0 && !READONLY_HTTP_METHODS.has(method);
		const blockedByAllowedSet = Boolean(state.allowedMethods && !state.allowedMethods.has(method));
		if (blockedByReadonlyLock || blockedByAllowedSet) {
			const reason = formatScopeBlockReason(
				"egress-proxy",
				`CDP 会话方法策略拦截非白名单方法 (${method} ${rawUrl})`,
				"N-008",
			);
			state.lastReadonlyBlockReason = reason;
			sendFail(requestId, reason, rawUrl, method, resourceType);
			return;
		}

		const cleaned = buildStatefulHeaderEntries(requestHeaders, { authMode: "inherit" });
		const flatForLog: Record<string, string> = {};
		for (const h of cleaned) flatForLog[h.name] = h.value;
		state.onAllowedRequest?.({
			requestId: typeof params.networkId === "string" ? params.networkId : requestId,
			url: rawUrl,
			method,
			headers: flatForLog,
		});
		sendContinue(requestId, cleaned);
	});

	state.unsubscribe = unsubscribe;
	holder._interceptor = state;

	await session.client.send(
		"Fetch.enable",
		{ patterns: [{ urlPattern: "*", requestStage: "Request" }] },
		{ sessionId: session.sessionId },
	);
	return state;
}
/* ------------------------------------------------------------------ *
 * 页面内有状态加签探针表达式与执行入口
 * ------------------------------------------------------------------ */

interface StatefulProbeExpressionConfig {
	url: string;
	expectedOrigin: string;
	enforceSameOrigin: boolean;
	pathWithQuery: string;
	method: string;
	headers: Record<string, string>;
	serializedBody: string | null;
	hasBody: boolean;
	signerHookPath: string;
	probeToken: string;
	internalHeaderName: string;
	credentialsMode: "include" | "omit" | "same-origin";
	timeoutMs: number;
}

const SIGNED_PROBE_WRITE_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SIGNED_PROBE_AUTH_HEADER_RE = /^(cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)$/i;

function isStatefulHttpMethod(value: string): value is StatefulHttpMethod {
	return STATEFUL_HTTP_METHODS.has(value);
}

function buildStatefulProbeExpression(cfg: StatefulProbeExpressionConfig): string {
	return `(function () {
  var cfg = ${JSON.stringify(cfg)};
  return (async function () {
    var out = { ok: false, status: 0, headers: {}, bodyText: "", signedByHook: false, appliedSignatureHeaders: [], timedOut: false, error: null };
    var controller = new AbortController();
    var timer = setTimeout(function () { try { controller.abort(); } catch (e) {} }, cfg.timeoutMs);
    try {
      var target = new URL(cfg.url || cfg.pathWithQuery, location.href);
      if (target.protocol !== "http:" && target.protocol !== "https:") throw new Error("unsupported-protocol:" + target.protocol);
      if (cfg.enforceSameOrigin && (target.origin !== cfg.expectedOrigin || target.origin !== location.origin)) throw new Error("cross-origin-blocked");
      var headers = {}; var baseHeaders = {}; var k;
      for (k in cfg.headers) { if (Object.prototype.hasOwnProperty.call(cfg.headers, k)) { headers[k] = String(cfg.headers[k]); baseHeaders[k] = headers[k]; } }
      var finalUrl = target.toString(); var finalBody = cfg.hasBody ? cfg.serializedBody : null; var signer = null;
      if (cfg.signerHookPath) {
        var segs = String(cfg.signerHookPath).split("."); var node = window;
        for (var i = 0; i < segs.length; i++) { if (node == null) { node = null; break; } node = node[segs[i]]; }
        if (typeof node === "function") signer = node;
      }
      if (!signer && typeof window.__nuwaSign === "function") signer = window.__nuwaSign;
      if (!signer && typeof window.__signRequest === "function") signer = window.__signRequest;
      if (signer) {
        var signed = await signer({ url: finalUrl, path: cfg.pathWithQuery, method: cfg.method, headers: baseHeaders, body: finalBody });
        if (signed && typeof signed === "object") {
          var source = (signed.headers && typeof signed.headers === "object") ? signed.headers : signed;
          for (k in source) {
            if (!Object.prototype.hasOwnProperty.call(source, k)) continue;
            var rawValue = source[k];
            if (typeof rawValue === "string" || typeof rawValue === "number") headers[k] = String(rawValue);
          }
          if (typeof signed.url === "string" && signed.url) finalUrl = signed.url;
          if (typeof signed.body === "string") finalBody = signed.body;
        }
        out.signedByHook = true;
        var applied = [];
        for (k in headers) {
          if (!Object.prototype.hasOwnProperty.call(headers, k) || k === cfg.internalHeaderName) continue;
          if (!Object.prototype.hasOwnProperty.call(baseHeaders, k) || baseHeaders[k] !== headers[k]) applied.push(k);
        }
        out.appliedSignatureHeaders = applied;
      }
      headers[cfg.internalHeaderName] = cfg.probeToken;
      var hasBodyNow = (cfg.method === "GET" || cfg.method === "HEAD") ? false : cfg.hasBody;
      var res = await window.fetch(finalUrl, { method: cfg.method, headers: headers, body: hasBodyNow && finalBody != null ? finalBody : undefined, credentials: cfg.credentialsMode, signal: controller.signal, redirect: "manual", cache: "no-store" });
      var respHeaders = {};
      try { res.headers.forEach(function (v, n) { respHeaders[String(n).toLowerCase()] = String(v); }); } catch (e) {}
      var text = ""; try { text = await res.text(); } catch (e) { text = ""; }
      out.ok = true; out.status = res.status; out.headers = respHeaders; out.bodyText = typeof text === "string" ? text : "";
      return out;
    } catch (err) {
      var msg = err && err.name === "AbortError" ? "probe-timeout" : String((err && err.message) || err || "probe-error");
      out.timedOut = msg === "probe-timeout"; out.error = msg; return out;
    } finally { clearTimeout(timer); }
  })();
})()`;
}

function signedProbeSucceeded(status: number, isSoft404: boolean, bodyText: string): boolean {
	return status >= 200 && status < 300 && !isSoft404 && !PURE_ERROR_TEXT_RE.test(bodyText);
}

export async function executeInPageStatefulSignedProbe(
	session: CdpSession,
	probeSpec: InPageStatefulSignedProbeSpec,
	scope: ScopePolicy,
	opts?: InPageStatefulProbeOptions,
): Promise<InPageStatefulSignedProbeResult> {
	const rootOrVault: string | SessionVault | undefined = opts?.vault ?? opts?.root;
	const extraSecrets = [...(opts?.extraSecrets ?? []), ...extractSecretsFromHeadersMap(probeSpec.headers), ...extractSecretsFromHeadersMap(probeSpec.overrideAuthHeaders)];
	if (opts?.recorder) {
		for (const s of extraSecrets) opts.recorder.registerTransientSecret(s);
	}
	const timeoutMs = Math.max(1_000, Math.min(opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS, 120_000));
	const methodInput = String(probeSpec.method ?? "GET").trim().toUpperCase();
	const mode = opts?.mode ?? "pentest";
	const redactUrl = (raw: string): string => scrubTextWithExtraSecrets(redactTrafficUrl(raw, { root: opts?.root, vault: opts?.vault, extraSecrets }), extraSecrets, rootOrVault);
	const blockedResult = (reason: string, rawUrl: string): InPageStatefulSignedProbeResult => {
		const emptyHash = computeBodyHash("");
		return { ok: false, blocked: true, blockReason: scrubTextWithExtraSecrets(reason, extraSecrets, rootOrVault), url: redactUrl(rawUrl), method: methodInput, status: 0, headers: {}, bodySnippet: "", bodyBytes: 0, bodyHash: emptyHash.bodyHash, templateHash: computeTemplateFingerprint(""), jsonKeys: [], isSoft404: false, signedByHook: false, appliedSignatureHeaders: [], durationMs: 0 };
	};

	if (!isStatefulHttpMethod(methodInput)) {
		return blockedResult(formatScopeBlockReason("shell-guard", `不支持的 HTTP 方法: ${methodInput}`, "N-008"), String(probeSpec.url));
	}
	const rawHook = String(probeSpec.signerHook ?? "").trim();
	const signerHook = rawHook.replace(/^window\./, "");
	if (signerHook.length > 0) {
		if (!SAFE_SIGNER_HOOK_RE.test(signerHook) || signerHook.split(".").some((seg) => FORBIDDEN_HOOK_SEGMENTS.has(seg))) {
			return blockedResult(formatScopeBlockReason("shell-guard", `非法 signerHook 路径: ${rawHook}`, "N-008"), String(probeSpec.url));
		}
	}

	const startedAt = Date.now();
	const pageOrigin = await getCurrentPageOrigin(session, Math.min(timeoutMs, 3_000));
	let absoluteUrl: URL;
	try {
		absoluteUrl = pageOrigin ? new URL(String(probeSpec.url), pageOrigin) : new URL(String(probeSpec.url));
	} catch {
		return blockedResult(formatScopeBlockReason("egress-proxy", `探针目标 URL 非法: ${probeSpec.url}`, "N-007"), String(probeSpec.url));
	}
	const scopeCheck = checkHttpTargetScope(absoluteUrl.toString(), methodInput, scope, mode, "页面内有状态探针");
	if (!scopeCheck.ok) return blockedResult(scopeCheck.reason, absoluteUrl.toString());
	if (pageOrigin && absoluteUrl.origin !== pageOrigin) {
		const allowCross = probeSpec.allowCrossOriginInScope === true && isHostInScope(absoluteUrl.hostname, scope).ok;
		if (!allowCross) return blockedResult(formatScopeBlockReason("egress-proxy", "页面内探针默认禁止跨域访问", "N-007"), absoluteUrl.toString());
	}

	let authMode: "inherit" | "anonymous" | "override" = probeSpec.authMode ?? "inherit";
	const authHeaders: Record<string, string> = {};
	if (probeSpec.overrideAuthHeaders) Object.assign(authHeaders, probeSpec.overrideAuthHeaders);
	if (probeSpec.role && !probeSpec.overrideAuthHeaders) {
		const vault = opts?.vault ?? (opts?.root ? loadSessionVault(opts.root) : undefined);
		const roleHeaders = vault ? getRoleHeadersMap(vault, probeSpec.role) : undefined;
		if (roleHeaders) {
			Object.assign(authHeaders, roleHeaders);
			authMode = "override";
		}
	}
	if (Object.keys(authHeaders).length > 0 && authMode === "inherit") authMode = "override";
	for (const s of extractSecretsFromHeadersMap(authHeaders)) {
		if (!extraSecrets.includes(s)) extraSecrets.push(s);
		opts?.recorder?.registerTransientSecret(s);
	}

	const headers: Record<string, string> = {};
	for (const [name, value] of Object.entries(probeSpec.headers ?? {})) {
		if (typeof value === "string") headers[name] = value;
	}
	if (authMode === "override") Object.assign(headers, authHeaders);
	else if (authMode === "anonymous") {
		for (const name of Object.keys(headers)) {
			if (SIGNED_PROBE_AUTH_HEADER_RE.test(name)) delete headers[name];
		}
	}

	let serializedBody: string | null = null;
	const hasBody = methodInput !== "GET" && methodInput !== "HEAD" && probeSpec.body !== undefined;
	if (hasBody) {
		if (typeof probeSpec.body === "string") serializedBody = probeSpec.body;
		else {
			try { serializedBody = JSON.stringify(probeSpec.body); }
			catch { return blockedResult(formatScopeBlockReason("shell-guard", "请求体无法 JSON 序列化", "N-008"), absoluteUrl.toString()); }
			if (!Object.keys(headers).some((name) => name.toLowerCase() === "content-type")) {
				headers["content-type"] = probeSpec.contentType ?? "application/json";
			}
		}
	}

	const probeToken = randomBytes(16).toString("hex");
	const interceptor = await ensureStatefulCapableInterceptor(session, scope, mode);
	const rule: StatefulProbeInterceptRule = { authMode, method: methodInput, overrideHeaders: authMode === "override" ? authHeaders : undefined };
	interceptor._statefulProbeRules.set(probeToken, rule);

	let status = 0; let responseHeaders: Record<string, string> = {}; let bodyRaw = "";
	let signedByHook = false; let appliedSignatureHeaders: string[] = []; let timedOut = false; let errorText: string | undefined;
	try {
		const expression = buildStatefulProbeExpression({ url: absoluteUrl.toString(), expectedOrigin: pageOrigin || absoluteUrl.origin, enforceSameOrigin: probeSpec.allowCrossOriginInScope !== true, pathWithQuery: `${absoluteUrl.pathname}${absoluteUrl.search}`, method: methodInput, headers, serializedBody, hasBody, signerHookPath: signerHook, probeToken, internalHeaderName: INTERNAL_STATEFUL_HEADER, credentialsMode: authMode === "anonymous" ? "omit" : "include", timeoutMs });
		const evaluated = await session.client.send<{ result?: { value?: unknown }; exceptionDetails?: { text?: string } }>("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, { sessionId: session.sessionId, timeoutMs: timeoutMs + 1_000 });
		if (evaluated.exceptionDetails) throw new Error(evaluated.exceptionDetails.text ?? "页面探针脚本异常");
		const parsed = evaluated.result?.value && typeof evaluated.result.value === "object" ? (evaluated.result.value as Record<string, unknown>) : undefined;
		if (parsed) {
			status = typeof parsed.status === "number" ? parsed.status : 0;
			responseHeaders = normalizeCdpHeadersObject(parsed.headers);
			bodyRaw = typeof parsed.bodyText === "string" ? parsed.bodyText : "";
			signedByHook = parsed.signedByHook === true;
			appliedSignatureHeaders = Array.isArray(parsed.appliedSignatureHeaders) ? parsed.appliedSignatureHeaders.map((x) => String(x)) : [];
			timedOut = parsed.timedOut === true;
			if (typeof parsed.error === "string" && parsed.error) errorText = parsed.error;
		} else errorText = "empty-evaluate-result";
	} catch (error) {
		errorText = error instanceof Error ? error.message : String(error);
	} finally {
		interceptor._statefulProbeRules.delete(probeToken);
	}

	if (rule.blockedReason) return blockedResult(rule.blockedReason, absoluteUrl.toString());
	const durationMs = Date.now() - startedAt;
	const { bodyHash, bodyBytes } = computeBodyHash(bodyRaw);
	const templateHash = computeTemplateFingerprint(bodyRaw, `${absoluteUrl.pathname}${absoluteUrl.search}`);
	const jsonKeys = extractJsonTopKeys(bodyRaw);
	const isSoft404 = detectSoft404({ status, body: bodyRaw }, opts?.soft404Baseline ?? null).isSoft404;
	const redactedUrl = redactUrl(absoluteUrl.toString());
	const redactedResponseHeaders = redactTrafficHeaders(responseHeaders, { root: opts?.root, vault: opts?.vault, extraSecrets });
	const bodySnippet = scrubTextWithExtraSecrets(redactTrafficBody(bodyRaw.slice(0, MAX_BODY_CAPTURE), { root: opts?.root, vault: opts?.vault, extraSecrets }) ?? "", extraSecrets, rootOrVault).slice(0, MAX_SNIPPET_CHARS);
	const appliedRedacted = appliedSignatureHeaders.map((h) => scrubTextWithExtraSecrets(h, extraSecrets, rootOrVault));
	const result: InPageStatefulSignedProbeResult = {
		ok: errorText === undefined && status > 0, blocked: false, timedOut, url: redactedUrl, method: methodInput, status,
		headers: redactedResponseHeaders, bodySnippet, bodyBytes, bodyHash, templateHash, jsonKeys, isSoft404,
		signedByHook, appliedSignatureHeaders: appliedRedacted, durationMs,
	};
	if (errorText !== undefined) result.error = scrubTextWithExtraSecrets(errorText, extraSecrets, rootOrVault);

	opts?.recorder?.record({
		method: methodInput, url: redactedUrl,
		requestHeaders: redactTrafficHeaders(headers, { root: opts?.root, vault: opts?.vault, extraSecrets }),
		requestBody: serializedBody === null ? undefined : redactTrafficBody(serializedBody, { root: opts?.root, vault: opts?.vault, extraSecrets }),
		status, responseHeaders: redactedResponseHeaders,
		responseBody: redactTrafficBody(bodyRaw, { root: opts?.root, vault: opts?.vault, extraSecrets }),
		durationMs, tags: ["cdp-stateful-probe"], role: opts?.roleLabel ?? probeSpec.role, note: `signed=${signedByHook} soft404=${isSoft404}`,
	});
	return result;
}

function normalizeStatefulEndpoint(endpoint: StatefulEndpointTargetSpec | string): StatefulEndpointTargetSpec & { method: string } {
	if (typeof endpoint === "string") return { path: endpoint, method: "GET" };
	const method = String(endpoint.method ?? "GET").trim().toUpperCase();
	return { ...endpoint, method: isStatefulHttpMethod(method) ? method : "GET" };
}

function signedProbePairSimilarity(a: InPageStatefulSignedProbeResult, b: InPageStatefulSignedProbeResult): number {
	if (a.bodyHash.length > 0 && a.bodyHash === b.bodyHash) return 1;
	if (a.jsonKeys.length === 0 && b.jsonKeys.length === 0) return 0;
	return computeKeyJaccard(a.jsonKeys, b.jsonKeys);
}

async function runSignedProbePool<T, R>(items: readonly T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
	const results: R[] = new Array(items.length);
	let cursor = 0;
	const size = Math.max(1, Math.min(limit, items.length || 1));
	await Promise.all(Array.from({ length: size }, async () => {
		for (;;) {
			const idx = cursor++;
			if (idx >= items.length) return;
			results[idx] = await worker(items[idx] as T);
		}
	}));
	return results;
}

export async function runCdpStatefulSignedAuthDiff(
	targetUrl: string,
	endpoints: readonly (StatefulEndpointTargetSpec | string)[],
	root: string,
	scope: ScopePolicy,
	opts?: RunCdpStatefulSignedAuthDiffOptions,
): Promise<RunCdpStatefulSignedAuthDiffResult> {
	const mode: Mode | string = opts?.mode ?? "pentest";
	const timeoutMs = Math.max(1_000, Math.min(opts?.timeoutMs ?? 20_000, 120_000));
	const requestedConcurrency = opts?.concurrency ?? 2;
	const effectiveConcurrency = Math.max(1, Math.min(Math.floor(requestedConcurrency), MAX_STATEFUL_PROBE_CONCURRENCY));
	const entryCheck = checkHttpTargetScope(targetUrl, "GET", scope, mode, "有状态签名差分靶标");
	if (!entryCheck.ok) {
		return { ok: false, targetUrl: redactTrafficUrl(targetUrl, { root }), blockedByScope: true, blockReason: entryCheck.reason, effectiveConcurrency, testedEndpoints: [], blockedEndpoints: endpoints.map((e) => (typeof e === "string" ? e : `${String(e.method ?? "GET").toUpperCase()} ${e.path}`)), unsignedStatuses: {}, findings: [], fact: null };
	}

	const vault = loadSessionVault(root);
	const recorder = opts?.recorder;
	const roleHeaders = new Map<string, Record<string, string>>();
	const extraSecrets = new Set<string>();
	for (const roleName of Object.keys(vault.roles)) {
		const hdrs = getRoleHeadersMap(vault, roleName);
		if (hdrs) {
			roleHeaders.set(roleName, hdrs);
			for (const s of extractSecretsFromHeadersMap(hdrs)) { extraSecrets.add(s); recorder?.registerTransientSecret(s); }
		}
	}
	for (const [roleName, hdrs] of Object.entries(opts?.extraRoleHeaders ?? {})) {
		roleHeaders.set(roleName, hdrs);
		for (const s of extractSecretsFromHeadersMap(hdrs)) { extraSecrets.add(s); recorder?.registerTransientSecret(s); }
	}
	if (!roleHeaders.has("anon")) roleHeaders.set("anon", {});
	const roles = opts?.compareRoles ? [...new Set([...(opts.baselineRole ? [opts.baselineRole] : []), ...opts.compareRoles])] : Array.from(roleHeaders.keys());
	if (roles.length === 0) roles.push("anon");

	let baselineRole = opts?.baselineRole && roleHeaders.has(opts.baselineRole) ? opts.baselineRole : "";
	if (!baselineRole) baselineRole = roles.find((r) => r !== "anon" && isAdminLikeRole(r)) ?? roles.find((r) => r !== "anon") ?? "anon";
	const extraSecretsArr = Array.from(extraSecrets);

	const ownsSession = !opts?.session;
	let session: CdpSession | null = opts?.session ?? null;
	const findings: CdpStatefulSignedDiffFinding[] = [];
	const unsignedStatuses: Record<string, number> = {};
	const testedEndpoints: string[] = [];
	const blockedEndpoints: string[] = [];
	let blockReason: string | undefined;

	try {
		if (!session) session = await launchCdpSession(opts?.launchOptions);
		const activeSession = session;
		await ensureStatefulCapableInterceptor(activeSession, scope, mode);
		const sendOpts = { sessionId: activeSession.sessionId, timeoutMs };
		await activeSession.client.send("Page.enable", {}, sendOpts);
		await activeSession.client.send("Runtime.enable", {}, sendOpts);
		await activeSession.client.send("Network.enable", {}, sendOpts);

		const targetOrigin = entryCheck.parsed.origin;
		const pageOrigin = await getCurrentPageOrigin(activeSession, Math.min(timeoutMs, 3_000));
		if (pageOrigin !== targetOrigin) {
			const navTimeout = Math.max(500, opts?.navigationTimeoutMs ?? DEFAULT_NAVIGATION_TIMEOUT_MS);
			const loaded = activeSession.client.waitForEvent("Page.loadEventFired", { sessionId: activeSession.sessionId, timeoutMs: navTimeout }).catch(() => null);
			await activeSession.client.send("Page.navigate", { url: entryCheck.parsed.toString() }, { sessionId: activeSession.sessionId, timeoutMs: navTimeout });
			await loaded;
			await new Promise<void>((r) => setTimeout(r, Math.max(20, opts?.settleMs ?? DEFAULT_SETTLE_MS)));
		}

		const soft404Baseline: Soft404BaselineInput | Soft404Baseline | null =
			opts?.soft404Baseline !== undefined
				? opts.soft404Baseline
				: opts?.autoSampleSoft404 === false
					? null
					: await sampleSoft404Baseline(targetOrigin, opts?.fetchFn ? async (u, init) => {
						const r = await opts.fetchFn!(u, { method: init?.method, headers: init?.headers, redirect: init?.redirect, signal: init?.signal });
						return { ok: r.ok, status: r.status, text: () => r.text(), headers: r.headers };
					} : undefined, { timeoutMs }).catch(() => null);

		const normalized = endpoints.map(normalizeStatefulEndpoint);
		if (opts?.verifyUnsignedBaseline !== false) {
			const fetchImpl = opts?.fetchFn ?? fetch;
			for (const ep of normalized) {
				const directUrl = new URL(ep.path, targetOrigin).toString();
				const label = `${ep.method} ${ep.path}`;
				if (!checkHttpTargetScope(directUrl, ep.method, scope, mode, "无签名直连基线").ok) continue;
				const controller = new AbortController();
				const timer = setTimeout(() => controller.abort(), timeoutMs);
				try {
					const initHeaders: Record<string, string> = { ...(ep.headers ?? {}) };
					let directBody: string | undefined;
					if (ep.method !== "GET" && ep.method !== "HEAD" && ep.body !== undefined) {
						directBody = typeof ep.body === "string" ? ep.body : JSON.stringify(ep.body);
						if (!Object.keys(initHeaders).some((k) => k.toLowerCase() === "content-type")) initHeaders["content-type"] = ep.contentType ?? (typeof ep.body === "string" ? "text/plain" : "application/json");
					}
					const direct = await fetchImpl(directUrl, { method: ep.method, headers: initHeaders, body: directBody, redirect: "manual", signal: controller.signal });
					unsignedStatuses[label] = direct.status;
				} catch {
					unsignedStatuses[label] = 0;
				} finally {
					clearTimeout(timer);
				}
			}
		}

		const probeJobs: Array<{ ep: StatefulEndpointTargetSpec & { method: string }; role: string }> = [];
		for (const ep of normalized) {
			for (const roleName of roles) probeJobs.push({ ep, role: roleName });
		}
		const probeResults = await runSignedProbePool(probeJobs, effectiveConcurrency, async (job) => {
			const probe = await executeInPageStatefulSignedProbe(
				activeSession,
				{ url: job.ep.path, method: job.ep.method, body: job.ep.body, headers: job.ep.headers, contentType: job.ep.contentType, signerHook: opts?.signerHook, authMode: job.role === "anon" ? "anonymous" : "override", role: job.role === "anon" ? undefined : job.role, overrideAuthHeaders: job.role === "anon" ? undefined : roleHeaders.get(job.role) },
				scope,
				{ root, vault, recorder, timeoutMs, soft404Baseline, mode, roleLabel: job.role, extraSecrets: extraSecretsArr },
			);
			return { job, probe };
		});

		for (const ep of normalized) {
			const epLabel = `${ep.method} ${ep.path}`;
			const perRole = new Map<string, InPageStatefulSignedProbeResult>();
			for (const entry of probeResults) {
				if (entry.job.ep === ep) perRole.set(entry.job.role, entry.probe);
			}
			const baseline = perRole.get(baselineRole);
			const probes = Array.from(perRole.entries()).map(([role, probe]) => ({ role, method: ep.method, status: probe.status, bodyBytes: probe.bodyBytes, bodyHash: probe.bodyHash, templateHash: probe.templateHash, jsonKeys: probe.jsonKeys, isSoft404: probe.isSoft404, signedByHook: probe.signedByHook, sampleSnippet: probe.bodySnippet }));
			if (perRole.size === 0 || Array.from(perRole.values()).some((p) => p.blocked)) blockedEndpoints.push(epLabel);
			else testedEndpoints.push(epLabel);

			const endpointUrl = scrubTextWithExtraSecrets(redactTrafficUrl(new URL(ep.path, targetOrigin).toString(), { root, vault, extraSecrets: extraSecretsArr }), extraSecretsArr, vault);
			const endpointIsWrite = SIGNED_PROBE_WRITE_METHODS.has(ep.method);
			const endpointIsAdmin = isAdminLikePath(ep.path);
			const endpointIsObject = isObjectResourcePath(ep.path);

			const anonProbe = perRole.get("anon");
			const anonSucceeded = Boolean(anonProbe && signedProbeSucceeded(anonProbe.status, anonProbe.isSoft404, anonProbe.bodySnippet));
			if (anonProbe && anonSucceeded) {
				const similarity = baseline ? signedProbePairSimilarity(baseline, anonProbe) : 0;
				const hasPayload = anonProbe.jsonKeys.length > 0 || anonProbe.bodyBytes > 0 || ep.method === "DELETE" || ep.method === "POST";
				if (similarity >= 0.65 || hasPayload) {
					findings.push({ path: ep.path, method: ep.method, url: endpointUrl, kind: "unauth_access", severity: "high", summary: `匿名访问成功穿透 ${ep.method} ${ep.path}`, baselineRole, testedRole: "anon", similarity, unsignedStatus: unsignedStatuses[epLabel], probes });
				}
			}

			for (const [roleName, probe] of perRole) {
				if (roleName === "anon" || roleName === baselineRole || isAdminLikeRole(roleName)) continue;
				if (!signedProbeSucceeded(probe.status, probe.isSoft404, probe.bodySnippet)) continue;
				if (!endpointIsWrite && !endpointIsAdmin) continue;
				const similarity = baseline ? signedProbePairSimilarity(baseline, probe) : 0;
				if (similarity >= 0.65 || (baseline !== undefined && baseline.status === probe.status)) {
					findings.push({ path: ep.path, method: ep.method, url: endpointUrl, kind: "vertical_bfla", severity: "high", summary: `低权角色 ${roleName} 越权访问 ${ep.method} ${ep.path}`, baselineRole, testedRole: roleName, similarity, unsignedStatus: unsignedStatuses[epLabel], probes });
				}
			}

			const lowPrivileged = Array.from(perRole.entries()).filter(([r, p]) => r !== "anon" && !isAdminLikeRole(r) && signedProbeSucceeded(p.status, p.isSoft404, p.bodySnippet));
			if (lowPrivileged.length >= 2 && endpointIsObject && !anonSucceeded) {
				for (let i = 0; i < lowPrivileged.length; i += 1) {
					for (let j = i + 1; j < lowPrivileged.length; j += 1) {
						const [roleA, probeA] = lowPrivileged[i]!;
						const [roleB, probeB] = lowPrivileged[j]!;
						const similarity = signedProbePairSimilarity(probeA, probeB);
						if (probeA.status === probeB.status && probeA.bodyHash.length > 0 && probeA.bodyHash === probeB.bodyHash) {
							findings.push({ path: ep.path, method: ep.method, url: endpointUrl, kind: "horizontal_bola", severity: "medium", summary: `同级角色 ${roleA}/${roleB} 在 ${ep.method} ${ep.path} 返回完全相同的业务对象实体`, baselineRole, testedRole: roleA, similarity, unsignedStatus: unsignedStatuses[epLabel], probes });
						}
					}
				}
			}
		}
	} catch (error) {
		blockReason = scrubTextWithExtraSecrets(error instanceof Error ? error.message : String(error), extraSecretsArr, vault);
	} finally {
		if (ownsSession && session) await closeCdpSession(session);
	}

	const fact: AutoFact | null = findings.length === 0 ? null : {
		kind: "vuln",
		title: `CDP 有状态动态加签权限差分检出 ${findings.length} 项越权`,
		detail: scrubTextWithExtraSecrets(findings.map((f) => `[${f.kind}] ${f.method} ${f.path} (${f.testedRole}): ${f.summary}`).join("; "), extraSecretsArr, vault),
		command: `nuwa cdp-signed-probe ${scrubTextWithExtraSecrets(redactTrafficUrl(targetUrl, { root, vault, extraSecrets: extraSecretsArr }), extraSecretsArr, vault)}`,
		output: scrubTextWithExtraSecrets(findings.map((f) => f.summary).join("\n"), extraSecretsArr, vault),
		meta: { paths: [...new Set(findings.map((f) => f.path))] },
	};

	const safeTargetUrl = scrubTextWithExtraSecrets(redactTrafficUrl(targetUrl, { root, vault, extraSecrets: extraSecretsArr }), extraSecretsArr, vault);
	return { ok: blockReason === undefined, targetUrl: safeTargetUrl, blockedByScope: blockReason !== undefined, ...(blockReason !== undefined ? { blockReason } : {}), effectiveConcurrency, testedEndpoints, blockedEndpoints, unsignedStatuses, findings, fact };
}
