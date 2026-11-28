/**
 * omp/stateful-workflow.ts —— 第一部分（精炼版）
 *
 * 提供：
 * 1. 通用脱敏、模板插值、JSONPath 提取、Scope 守卫工具；
 * 2. 工作流动作风险分级（L0~L3）；
 * 3. 带 CookieJar、变量提取、手动重定向与零明文脱敏的多步状态链重放基础件。
 *
 * 所有注释与运行时提示均使用简体中文。
 */
import { randomUUID } from "node:crypto";
import { connect, type Socket } from "node:net";
import { computeBodyHash, computeTemplateFingerprint, detectSoft404, sampleSoft404Baseline, type Soft404Baseline, type Soft404BaselineInput } from "./autoexec";
import { propagateBeliefUpdate, resolveBeliefNodeId, type BeliefGraph, type BeliefObservation, type BeliefPropagationResult } from "./belief-search";
import { evaluatePositiveEvidenceGate, recordToolExecution, type ResponseSnapshot } from "./evidence";
import type { Fact, Mode, NuwaState, ScopePolicy } from "./types";
import { checkScopeAndRisk, defaultScopeForTarget, formatScopeBlockReason, isHostInScope } from "./scope";
import { REDACTED_MARKER, redactTrafficBody, redactTrafficHeaders, redactTrafficUrl, type TrafficExtractorSpec, type TrafficFetchFn, type TrafficFetchResponseLike, type TrafficRecorder } from "./traffic-workbench";
import { getRoleHeadersMap, loadSessionVault, redactVaultSecrets, type SessionVault } from "./session-vault";

// ==================== 通用工具 ====================
type HeaderRecord = Record<string, string>;
interface RedactOptions {
	root?: string; vault?: SessionVault; extraSecrets?: string[]; }
const SENSITIVE_SHORT_NAMES = new Set(["sid", "sig", "cred", "auth", "pwd", "jwt", "otp", "pin", "key"]);
const SENSITIVE_COMPACT_PARTS = ["token", "secret", "password", "passwd", "cookie", "authorization", "jwt",
	"bearer", "apikey", "csrf", "xsrf", "session", "ticket", "signature", "credential",
	"privatekey", "accesskey", "refreshtoken", "clientsecret", "authtoken"];
/** 判断字段名是否属于敏感字段。 */
export function isSensitiveKeyName(name: string): boolean {
	const raw = String(name ?? "").toLowerCase();
	if (!raw) return false;
	const compact = raw.replace(/[^a-z0-9]/g, "");
	if (!compact) return false;
	if (SENSITIVE_COMPACT_PARTS.some((part) => compact.includes(part))) return true;
	return raw.split(/[^a-z0-9]+/g).filter(Boolean).some((part) => SENSITIVE_SHORT_NAMES.has(part));
}
/** 安全调用 vault 加载，失败时静默忽略。 */
function tryLoadVault(root?: string): SessionVault | undefined {
	if (!root) return undefined;
	try {
		const vault = loadSessionVault(root) as unknown;
		if (vault && typeof (vault as { then?: unknown }).then !== "function") return vault as SessionVault;
	} catch {
		// 忽略加载失败，脱敏仍可通过 root 路径进行。
	}
	return undefined;
}
/** 收集需要强制擦除的敏感值集合。 */
export function collectSecretSet(opts?: { root?: string;
	vault?: SessionVault; extraSecrets?: string[]; headers?: Record<string, string>; roleHeaders?: Record<string, Record<string, string>>;
	vars?: Record<string, string>; cookies?: Record<string, string>;
}): Set<string> {
	const set = new Set<string>();
	const add = (value: unknown): void => {
		if (typeof value !== "string") return;
		const trimmed = value.trim();
		if (trimmed.length >= 3) set.add(trimmed);
	};
	for (const secret of opts?.extraSecrets ?? []) add(secret);
	for (const [key, value] of Object.entries(opts?.headers ?? {})) if (isSensitiveKeyName(key)) add(value);
	for (const roleMap of Object.values(opts?.roleHeaders ?? {})) { for (const [key, value] of Object.entries(roleMap)) if (isSensitiveKeyName(key)) add(value); }
	for (const [key, value] of Object.entries(opts?.vars ?? {})) { if (isSensitiveKeyName(key) || String(value ?? "").length >= 12) add(value); }
	for (const value of Object.values(opts?.cookies ?? {})) add(value);
	const vault = opts?.vault ?? tryLoadVault(opts?.root);
	if (vault) {
		try {
			const anyVault = vault as unknown as Record<string, unknown>;
			for (const fnName of ["listSecrets", "getSecrets", "allSecrets", "toJSON", "getAll"]) {
				const fn = anyVault[fnName];
				if (typeof fn !== "function") continue;
				const value = (fn as () => unknown).call(vault);
				if (value && typeof value === "object") { for (const item of Object.values(value as Record<string, unknown>)) add(item); }
			}
		} catch {
			// 忽略 vault 内部结构差异。
		}
	}
	return set;
}
/** 对任意文本执行多轮敏感信息擦除。 */
export function scrubSecretsInText(text: string, secrets: Set<string>, rootOrVault?: string | SessionVault,): string {
	let out = String(text ?? ""); const sorted = [...secrets].filter((secret) => secret.length >= 3).sort((a, b) => b.length - a.length);
	for (const secret of sorted) out = out.split(secret).join(REDACTED_MARKER);
	if (rootOrVault) {
		try {
			out = redactVaultSecrets(out, rootOrVault);
		} catch {
			// 忽略 vault 脱敏异常。
		}
	}
	out = out.replace(/(Bearer\s+)[A-Za-z0-9\-._~+/]+=*/gi, `$1${REDACTED_MARKER}`); out = out.replace(/(Basic\s+)[A-Za-z0-9+/=]+/gi, `$1${REDACTED_MARKER}`);
	out = out.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, REDACTED_MARKER);
	out = out.replace(/(\bhttps?:\/\/)([^/\s:@]+):([^/\s@]+)@/gi, `$1${REDACTED_MARKER}:${REDACTED_MARKER}@`);
	out = out.replace(
		/([?&](?:token|secret|password|passwd|pwd|cookie|auth|jwt|bearer|api_key|apikey|csrf|xsrf|session|sid|ticket|sig|signature|cred|private_key)=)[^&\s#]+/gi,
		`$1${REDACTED_MARKER}`, );
	return out;
}
/** 深度脱敏对象：敏感键值一律替换为 REDACTED_MARKER。 */
export function redactRecordDeep(obj: unknown, secrets: Set<string>, rootOrVault?: string | SessionVault,): unknown {
	const seen = new WeakSet<object>();
	const walk = (value: unknown, depth: number): unknown => {
		if (value === null || value === undefined) return value;
		if (typeof value === "string") return scrubSecretsInText(value, secrets, rootOrVault);
		if (typeof value !== "object") return value;
		if (depth > 8) return REDACTED_MARKER;
		if (seen.has(value as object)) return "[Circular]";
		seen.add(value as object);
		if (Array.isArray(value)) return value.map((item) => walk(item, depth + 1));
		if (value instanceof Date) return value.toISOString();
		const out: Record<string, unknown> = {};
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) { out[key] = isSensitiveKeyName(key) ? REDACTED_MARKER : walk(item, depth + 1); }
		return out;
	};
	return walk(obj, 0);
}
/** 支持点分路径、数组下标与 `items[0].token` 形式的 JSONPath 提取。 */
export function extractByJsonPath(obj: unknown, path: string): unknown {
	const cleaned = String(path ?? "").trim().replace(/^\$\.?/, "").replace(/\[(\d+)\]/g, ".$1").replace(/^\./, "");
	if (!cleaned) return obj;
	const tokens: Array<string | number> = [];
	for (const part of cleaned.split(".")) {
		if (!part) continue;
		tokens.push(/^\d+$/.test(part) ? Number(part) : part);
	}
	let current: unknown = obj;
	for (const token of tokens) {
		if (current === null || current === undefined) return undefined;
		if (typeof token === "number") {
			if (!Array.isArray(current)) return undefined;
			current = current[token];
			continue;
		}
		if (Array.isArray(current)) {
			const index = Number(token);
			if (!Number.isInteger(index)) return undefined;
			current = current[index];
			continue;
		}
		if (typeof current !== "object") return undefined;
		current = (current as Record<string, unknown>)[token];
	}
	return current;
}
/** 模板变量插值，返回替换结果与未解析变量名列表。 */
export function interpolateTemplate(tpl: string, vars: Record<string, string>,): { value: string; unresolved: string[] } {
	const unresolved: string[] = [];
	const value = String(tpl ?? "").replace(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g, (_match, name: string) => {
		if (Object.prototype.hasOwnProperty.call(vars, name)) return vars[name] ?? "";
		unresolved.push(name);
		return `{{${name}}}`;
	});
	return { value, unresolved: [...new Set(unresolved)] };
}
function headersToRecord(headers: TrafficFetchResponseLike["headers"] | undefined,): HeaderRecord {
	const out: HeaderRecord = {};
	if (!headers) return out;
	const anyHeaders = headers as { forEach?: (cb: (value: string, key: string) => void) => void };
	if (typeof anyHeaders.forEach === "function") {
		try {
			anyHeaders.forEach((value, key) => {
				out[String(key).toLowerCase()] = String(value);
			});
			return out;
		} catch {
			// 继续尝试对象枚举。
		}
	}
	for (const [key, value] of Object.entries(headers)) {
		if (value === undefined) continue;
		out[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
	}
	return out;
}
function getSetCookieList(headers: TrafficFetchResponseLike["headers"] | undefined,): string[] {
	if (!headers) return [];
	const anyHeaders = headers as { getSetCookie?: () => string[] };
	if (typeof anyHeaders.getSetCookie === "function") {
		try {
			const list = anyHeaders.getSetCookie();
			if (Array.isArray(list)) return list.map((item) => String(item));
		} catch {
			// 忽略并回退到普通头解析。
		}
	}
	const raw = headersToRecord(headers)["set-cookie"];
	return raw ? [raw] : [];
}
function normalizeHeaderRecord(headers?: Record<string, string>): HeaderRecord {
	const out: HeaderRecord = {};
	for (const [key, value] of Object.entries(headers ?? {})) {
		if (value === undefined) continue;
		out[key.toLowerCase()] = String(value);
	}
	return out;
}
function stripSensitiveHeaders(headers: HeaderRecord): HeaderRecord {
	const out: HeaderRecord = {};
	for (const [key, value] of Object.entries(headers)) {
		const lower = key.toLowerCase();
		if (lower === "cookie" || lower === "authorization" || lower === "proxy-authorization" || isSensitiveKeyName(key)) continue;
		out[key] = value;
	}
	return out;
}
function bodyToText(body: string | Record<string, unknown> | undefined): string | undefined {
	if (body === undefined) return undefined;
	if (typeof body === "string") return body;
	try {
		return JSON.stringify(body);
	} catch { return String(body); }
}
function interpolateBodyValue(body: string | Record<string, unknown> | undefined,
	vars: Record<string, string>,): { value?: string; unresolved: string[] } {
	if (body === undefined) return { value: undefined, unresolved: [] };
	if (typeof body === "string") {
		const result = interpolateTemplate(body, vars);
		return { value: result.value, unresolved: result.unresolved };
	}
	const unresolved: string[] = [];
	const walk = (value: unknown): unknown => {
		if (typeof value === "string") {
			const result = interpolateTemplate(value, vars); unresolved.push(...result.unresolved);
			return result.value;
		}
		if (Array.isArray(value)) return value.map(walk);
		if (value && typeof value === "object") {
			const out: Record<string, unknown> = {};
			for (const [key, item] of Object.entries(value as Record<string, unknown>)) out[key] = walk(item);
			return out;
		}
		return value;
	};
	return { value: JSON.stringify(walk(body)), unresolved };
}
function tryParseJson(text: string | undefined): unknown {
	if (!text) return undefined;
	try {
		return JSON.parse(text);
	} catch { return undefined; }
}
function safeRedactUrl(url: string, opts: RedactOptions): string {
	try {
		return redactTrafficUrl(url, opts);
	} catch { return scrubSecretsInText(url, new Set(opts.extraSecrets ?? []), opts.vault ?? opts.root); }
}
function safeRedactHeaders(headers: Record<string, string | string[] | undefined>, opts: RedactOptions,): HeaderRecord {
	try {
		return redactTrafficHeaders(headers, opts);
	} catch {
		const secrets = new Set(opts.extraSecrets ?? []);
		const out: HeaderRecord = {};
		for (const [key, value] of Object.entries(headers)) {
			if (value === undefined) continue;
			const text = Array.isArray(value) ? value.join(", ") : String(value);
			out[key] = isSensitiveKeyName(key) ? REDACTED_MARKER : scrubSecretsInText(text, secrets, opts.vault ?? opts.root);
		}
		return out;
	}
}
function safeRedactBody(body: string | undefined, opts: RedactOptions & { maxChars?: number },): string | undefined {
	if (body === undefined) return undefined;
	try {
		return redactTrafficBody(body, opts);
	} catch { return scrubSecretsInText(body.slice(0, opts.maxChars ?? 8192), new Set(opts.extraSecrets ?? []), opts.vault ?? opts.root); }
}

// ==================== CookieJar ====================

export interface CookieRecord {
	name: string; value: string; domain: string; path: string; expires?: string; secure?: boolean; httpOnly?: boolean; sameSite?: string;
}
/** 轻量 CookieJar：支持 Set-Cookie 收集、域名/路径匹配与脱敏导出。 */
export class CookieJar {
	private readonly cookies = new Map<string, CookieRecord>();
	constructor(initial?: Record<string, string>) {
		for (const [name, value] of Object.entries(initial ?? {})) this.set(name, value, "", "/");
	}
	private key(name: string, domain: string, path: string): string { return `${name}|${domain}|${path}`; }
	public set(name: string, value: string, domain: string, path: string, attrs?: Partial<Omit<CookieRecord, "name" | "value" | "domain" | "path">>,): void {
		const d = String(domain ?? "").replace(/^\./, "").toLowerCase(); const p = String(path ?? "/") || "/";
		this.cookies.set(this.key(name, d, p), { name, value: String(value ?? ""), domain: d, path: p, ...attrs });
	}
	public setFromSetCookie(setCookieHeaders: string[], requestUrl: string): string[] {
		const changed: string[] = []; let host = ""; let reqPath = "/";
		try {
			const parsed = new URL(requestUrl); host = parsed.hostname.toLowerCase(); reqPath = parsed.pathname || "/";
		} catch { return changed; }
		for (const raw of setCookieHeaders) {
			const pieces = String(raw ?? "").split(";"); const pair = pieces.shift()?.trim() ?? ""; const eq = pair.indexOf("=");
			if (eq <= 0) continue;
			const name = pair.slice(0, eq).trim(); const value = pair.slice(eq + 1).trim();
			if (!name) continue;
			let domain = ""; let path = "/"; let expires: string | undefined; let secure = false;
			let httpOnly = false; let sameSite: string | undefined; let maxAge: number | undefined;
			for (const piece of pieces) {
				const item = piece.trim();
				if (!item) continue;
				const sep = item.indexOf("="); const key = (sep >= 0 ? item.slice(0, sep) : item).trim().toLowerCase();
				const val = sep >= 0 ? item.slice(sep + 1).trim() : "";
				if (key === "domain") domain = val.replace(/^\./, "").toLowerCase();
				else if (key === "path") path = val || "/"; else if (key === "expires") expires = val;
				else if (key === "max-age") maxAge = Number(val); else if (key === "secure") secure = true;
				else if (key === "httponly") httpOnly = true; else if (key === "samesite") sameSite = val;
			}
			if (!domain) domain = host;
			if (maxAge !== undefined && Number.isFinite(maxAge)) {
				if (maxAge <= 0) {
					this.cookies.delete(this.key(name, domain, path));
					continue;
				}
				expires = new Date(Date.now() + maxAge * 1000).toUTCString();
			}
			if (expires && Date.parse(expires) < Date.now()) {
				this.cookies.delete(this.key(name, domain, path));
				continue;
			}
			this.set(name, value, domain, path, { expires, secure, httpOnly, sameSite });
			changed.push(name);
		}
		return changed;
	}
	private domainMatches(cookieDomain: string, host: string): boolean {
		if (!cookieDomain) return true;
		return host === cookieDomain || host.endsWith(`.${cookieDomain}`);
	}
	private pathMatches(cookiePath: string, requestPath: string): boolean {
		if (!cookiePath || cookiePath === "/") return true;
		if (requestPath === cookiePath) return true;
		return requestPath.startsWith(cookiePath.endsWith("/") ? cookiePath : `${cookiePath}/`);
	}
	public getCookieHeader(url: string): string {
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch { return ""; }
		const host = parsed.hostname.toLowerCase(); const path = parsed.pathname || "/"; const secure = parsed.protocol === "https:";
		return [...this.cookies.values()]
			.filter((cookie) => this.domainMatches(cookie.domain, host))
			.filter((cookie) => this.pathMatches(cookie.path, path))
			.filter((cookie) => !cookie.secure || secure)
			.sort((a, b) => b.path.length - a.path.length)
			.map((cookie) => `${cookie.name}=${cookie.value}`)
			.join("; ");
	}
	public getCookieValue(name: string): string | undefined {
		const target = String(name ?? "").toLowerCase();
		for (const cookie of this.cookies.values()) if (cookie.name.toLowerCase() === target) return cookie.value;
		return undefined;
	}
	public toJSON(): Record<string, string> {
		const out: Record<string, string> = {};
		for (const cookie of this.cookies.values()) out[cookie.name] = cookie.value;
		return out;
	}
	public toRedactedJSON(): Record<string, string> {
		const out: Record<string, string> = {};
		for (const cookie of this.cookies.values()) out[cookie.name] = REDACTED_MARKER;
		return out;
	}
}

// ==================== 动作风险分级 ====================

export const WORKFLOW_ACTION_TIERS = ["L0_PHYSICAL_READ", "L1_SEMANTIC_READ", "L2_SCOPED_STATEFUL", "L3_RESTRICTED_DESTRUCTIVE"] as const;

export type WorkflowActionTier = (typeof WORKFLOW_ACTION_TIERS)[number];

export interface ClassifyWorkflowActionInput {
	method?: string; url?: string; path?: string; headers?: Record<string, string>; body?: string | Record<string, unknown>;
	scope?: ScopePolicy; mode?: Mode | string; allowDestructive?: boolean; }

export interface WorkflowActionClassification {
	tier: WorkflowActionTier; method: string; allowedByDefault: boolean; isReadOnly: boolean; isStateChanging: boolean;
	isDestructive: boolean; reason: string; matchedSignals: string[]; }
const DESTRUCTIVE_WORD_RE = /\b(drop|truncate|wipe|purge|nuke|destroy|erase|deleteall|deletemany|droptable|factoryreset|resetdb|bulkdelete)\b/i;
const DESTRUCTIVE_COMPACT_RE = /(droptable|deleteall|deletemany|factoryreset|resetdb|bulkdelete|rm-rf)/i;
const COLLECTION_TAIL_RE =
	/\/(users|tenants|accounts|orders|customers|projects|databases|database|records|items|resources|collections|roles|groups|organizations|orgs)(\/)?$/i;
/** 解析 Scope 守卫返回值，区分 N-007（普通拦截）与 N-008（破坏性拦截）。 */
function scopeRiskBlocked(result: unknown): { blocked: boolean; reason: string } {
	if (!result || typeof result !== "object") return { blocked: false, reason: "" };
	const record = result as Record<string, unknown>; const reason = String(record.reason ?? record.message ?? "");
	if (record.risk === "destructive" || record.tier === "L3_RESTRICTED_DESTRUCTIVE" || record.destructive === true) {
		return { blocked: true, reason: reason || "破坏性动作" };
	}
	if (record.block === true || record.blocked === true || record.allowed === false) {
		if (!reason.includes("N-007") && (reason.includes("N-008") || /拦截高危破坏性操作|destructive|高危|不可逆/i.test(reason))) {
			return { blocked: true, reason: reason || "Scope 风险守卫拦截" };
		}
	}
	return { blocked: false, reason: "" };
}
/** 对单次工作流动作进行 L0~L3 风险分级。 */
export function classifyWorkflowAction(input: ClassifyWorkflowActionInput,): WorkflowActionClassification {
	const method = String(input.method ?? "GET").toUpperCase(); const url = String(input.url ?? "");
	const bodyText = bodyToText(input.body) ?? ""; const mode = input.mode ?? "pentest";
	const scope = input.scope ?? defaultScopeForTarget(url || "http://127.0.0.1", mode);
	const allowDestructive = input.allowDestructive === true; let path = String(input.path ?? "");
	if (!path && url) {
		try {
			path = new URL(url).pathname;
		} catch { path = ""; }
	}
	const lowerPath = path.toLowerCase(); const lowerUrl = url.toLowerCase();
	const lowerBody = bodyText.toLowerCase(); const combined = `${lowerUrl} ${lowerPath} ${lowerBody}`;
	const matchedSignals: string[] = []; const readOnlyMethod = method === "GET" || method === "HEAD" || method === "OPTIONS";
	const destructiveSignals: string[] = [];
	if (readOnlyMethod && (combined.includes("rm -rf") || /\b(?:drop\s+(?:table|database|schema)|truncate\s+table)\b/i.test(combined))) {
		destructiveSignals.push("destructive-payload-in-read");
	}
	if (!readOnlyMethod) {
		if (DESTRUCTIVE_WORD_RE.test(combined) || DESTRUCTIVE_COMPACT_RE.test(combined)) { destructiveSignals.push("destructive-keyword"); }
		if (combined.includes("rm -rf")) destructiveSignals.push("rm-rf");
		if (method === "DELETE") {
			const query = (() => {
				try {
					return new URL(url).searchParams;
				} catch { return new URLSearchParams(); }
			})();
			for (const key of ["all", "force", "cascade"]) { if (query.get(key) === "true" || query.get(key) === "1") destructiveSignals.push(`delete-${key}`); }
			if (lowerPath.includes("*")) destructiveSignals.push("delete-wildcard");
			if (COLLECTION_TAIL_RE.test(lowerPath) || lowerPath === "/database") destructiveSignals.push("delete-root-collection");
		}
		if (lowerBody.includes("mutation") && DESTRUCTIVE_WORD_RE.test(lowerBody)) { destructiveSignals.push("graphql-destructive-mutation"); }
	}
	let riskBlocked = false; let riskReason = "";
	try {
		const verdict = checkScopeAndRisk(`${method} ${url} ${bodyText.slice(0, 500)}`, { ...scope, allowDestructive: false }, mode,);
		const checked = scopeRiskBlocked(verdict);
		if (checked.blocked) { riskBlocked = true; riskReason = checked.reason; }
	} catch {
		// 分级守卫失败时不影响后续显式 Scope 检查。
	}
	if (destructiveSignals.length > 0 || riskBlocked) {
		matchedSignals.push(...destructiveSignals);
		if (riskBlocked) matchedSignals.push("scope-risk-destructive");
		return {
			tier: "L3_RESTRICTED_DESTRUCTIVE", method, allowedByDefault: allowDestructive, isReadOnly: false,
			isStateChanging: true, isDestructive: true, reason: riskReason ? `命中 L3 限制性破坏动作：${riskReason}` : "命中 L3 限制性破坏动作（不可逆或批量删除语义）", matchedSignals, };
	}
	if (readOnlyMethod) {
		return {
			tier: "L0_PHYSICAL_READ", method, allowedByDefault: true, isReadOnly: true,
			isStateChanging: false, isDestructive: false, reason: "物理只读请求", matchedSignals: ["safe-method"], };
	}
	const trimmedBody = bodyText.trim();
	const bodyParsed = trimmedBody.startsWith("{") ? tryParseJson(trimmedBody) : undefined;
	const gqlQueryField = bodyParsed && typeof bodyParsed === "object" && !Array.isArray(bodyParsed) && typeof (bodyParsed as Record<string, unknown>).query === "string"
		? String((bodyParsed as Record<string, unknown>).query).toLowerCase()
		: "";
	const bodyIsGraphqlQuery =
		/^query(?:\s+[A-Za-z_]\w*|\s*\(|\s*\{)/i.test(trimmedBody) ||
		(gqlQueryField.length > 0 && !/\b(?:mutation|subscription)\b/.test(gqlQueryField)) ||
		(lowerPath.includes("/graphql") && (trimmedBody.startsWith("{") ? gqlQueryField.length > 0 && !/\b(?:mutation|subscription)\b/.test(gqlQueryField) : !lowerBody.includes("mutation") && !lowerBody.includes("subscription")));
	const graphqlRead = (lowerPath.includes("/graphql") || bodyIsGraphqlQuery) && !lowerBody.includes("mutation") && !lowerBody.includes("subscription") && (lowerPath.includes("/graphql") || bodyIsGraphqlQuery);
	const esRead = /\/(_search|_msearch|_count|_validate|_explain)(\/|$)/.test(lowerPath);
	const hasWriteVerb = /\b(insert|update|delete|remove|create|drop|truncate|mutation|subscription)\b/.test(lowerBody);
	const readSegment = /\/(search|query|read|preview|dry-run|validate)(\/|$)/.test(lowerPath) && !hasWriteVerb;
	if (method === "QUERY" || graphqlRead || esRead || readSegment) {
		if (method === "QUERY") matchedSignals.push("query-method");
		if (graphqlRead) matchedSignals.push("graphql-read");
		if (esRead) matchedSignals.push("search-read");
		if (readSegment) matchedSignals.push("read-segment");
		return {
			tier: "L1_SEMANTIC_READ", method, allowedByDefault: true, isReadOnly: true,
			isStateChanging: false, isDestructive: false, reason: "语义只读请求（搜索/查询/预览/校验）", matchedSignals, };
	}
	matchedSignals.push("state-changing-method");
	if (lowerBody.includes("mutation")) matchedSignals.push("graphql-mutation");
	if (method === "DELETE") matchedSignals.push("single-entity-delete");
	return {
		tier: "L2_SCOPED_STATEFUL", method, allowedByDefault: true, isReadOnly: false,
		isStateChanging: true, isDestructive: false, reason: "Scope 内常规状态变更请求", matchedSignals, };
}
function hostAllowed(host: string, scope: ScopePolicy): boolean {
	try {
		const result = isHostInScope(host, scope) as unknown;
		if (typeof result === "boolean") return result;
		if (result && typeof result === "object") {
			const record = result as Record<string, unknown>;
			if (record.ok === false || record.block === true || record.blocked === true) return false;
			if (record.ok === true || record.allowed === true) return true;
		}
		return true;
	} catch { return false; }
}
/** 统一执行 URL 协议、Scope 与风险分级守卫。 */
export function validateUrlAndActionScope(urlStr: string, method: string, bodyText: string | undefined,
	scope: ScopePolicy, mode: Mode | string, allowDestructive: boolean,): { ok: boolean;
	parsed?: URL; blockedByTier?: boolean; tierClassification: WorkflowActionClassification; reason?: string;
} {
	const classification = classifyWorkflowAction({ method, url: urlStr, body: bodyText, scope, mode, allowDestructive });
	if (classification.tier === "L3_RESTRICTED_DESTRUCTIVE" && !allowDestructive) {
		return { ok: false, blockedByTier: true, tierClassification: classification, reason: `动作被分级守卫拦截：${classification.reason}` };
	}
	let parsed: URL;
	try {
		parsed = new URL(urlStr);
	} catch {
		return { ok: false, blockedByTier: false, tierClassification: classification, reason: "URL 非法或无法解析" };
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return {
			ok: false, parsed, blockedByTier: false, tierClassification: classification, reason: `仅允许 http/https 协议，实际为 ${parsed.protocol}`, };
	}
	if (!hostAllowed(parsed.hostname, scope)) {
		return {
			ok: false, parsed, blockedByTier: false, tierClassification: classification,
			reason: formatScopeBlockReason("shell-guard", `目标主机 ${parsed.hostname} 不在授权 Scope 内`), };
	}
	try {
		const verdict = checkScopeAndRisk(`${String(method ?? "GET").toUpperCase()} ${parsed.toString()}`, { ...scope, allowDestructive }, mode,);
		const checked = scopeRiskBlocked(verdict);
		if (checked.blocked) {
			return {
				ok: false, parsed, blockedByTier: classification.tier === "L3_RESTRICTED_DESTRUCTIVE",
				tierClassification: classification, reason: formatScopeBlockReason("shell-guard", checked.reason), };
		}
	} catch {
		// 风险守卫异常不构成放行依据，继续由后续执行层隔离。
	}
	return { ok: true, parsed, tierClassification: classification };
}

// ==================== 多步状态链重放器 ====================

export interface StatefulWorkflowStep {
	id?: string; name?: string; method?: string; url: string; headers?: Record<string, string>; extraHeaders?: Record<string, string>;
	body?: string | Record<string, unknown>; allowDestructive?: boolean; role?: string;
	extract?: Record<string, string | TrafficExtractorSpec>; followRedirects?: boolean; maxRedirects?: number; timeoutMs?: number;
	expectStatus?: number | number[]; tags?: string[]; allowUnresolvedVars?: boolean; note?: string; }

export interface ExecuteStatefulWorkflowOptions {
	root?: string; steps: StatefulWorkflowStep[]; scope: ScopePolicy; mode?: Mode | string;
	allowDestructive?: boolean; vars?: Record<string, string>; initialVars?: Record<string, string>;
	role?: string; roleHeaders?: Record<string, Record<string, string>>; extraHeaders?: Record<string, string>;
	vault?: SessionVault; fetchFn?: TrafficFetchFn; recorder?: TrafficRecorder;
	initialCookies?: Record<string, string>; extraSecrets?: string[]; recordTraffic?: boolean;
	signal?: AbortSignal; timeoutMs?: number; defaultTimeoutMs?: number;
	followRedirects?: boolean; maxRedirects?: number; continueOnError?: boolean; }

export interface StatefulStepTrace {
	stepIndex: number; id: string; name?: string; method: string; requestedUrl: string; resolvedUrl: string; finalUrl: string;
	status: number; ok: boolean; blocked: boolean; abortedByScope: boolean; redirectBlocked?: boolean; timedOut?: boolean; expectStatusOk?: boolean;
	blockReason?: string; error?: string; durationMs: number; redirectChain: string[];
	requestHeaders: Record<string, string>; requestBody?: string; responseHeaders: Record<string, string>; responseBodySnippet?: string;
	extracted: Record<string, string>; recordedEntryId?: string; tier: WorkflowActionTier; cookiesSet: string[]; }

export interface StatefulWorkflowResult {
	ok: boolean; blocked: boolean; abortedByScope: boolean; error?: string;
	steps: StatefulStepTrace[]; variables: Record<string, string>; cookies: Record<string, string>;
	finalStatus?: number; finalUrl?: string; totalRequests: number; durationMs: number; redacted: true; }

export interface InternalWorkflowExecResult extends StatefulWorkflowResult {
	rawVariables: Record<string, string>; rawCookies: Record<string, string>; rawLastResponseBody?: string; rawLastResponseJson?: unknown;
	rawLastResponseHeaders?: Record<string, string>; rawStepBodies: Array<string | undefined>; }
function normalizeExtractor(spec: string | TrafficExtractorSpec): TrafficExtractorSpec {
	if (typeof spec !== "string") return spec;
	const trimmed = spec.trim();
	if (trimmed.startsWith("header:")) return { header: trimmed.slice(7).trim() };
	if (trimmed.startsWith("cookie:")) return { cookie: trimmed.slice(7).trim() };
	if (trimmed.startsWith("regex:")) return { regex: trimmed.slice(6) };
	return { jsonPath: trimmed };
}
function extractBySpec(spec: string | TrafficExtractorSpec, headers: HeaderRecord, body: string, jar: CookieJar): string | undefined {
	const normalized = normalizeExtractor(spec);
	if (normalized.header) return headers[normalized.header.toLowerCase()];
	if (normalized.cookie) return jar.getCookieValue(normalized.cookie);
	if (normalized.regex) {
		try {
			const match = new RegExp(normalized.regex).exec(body);
			if (match) return match[1] ?? match[0];
		} catch { return undefined; }
		return undefined;
	}
	if (normalized.jsonPath) {
		const value = extractByJsonPath(tryParseJson(body), normalized.jsonPath);
		if (value === undefined || value === null) return undefined;
		return typeof value === "string" ? value : JSON.stringify(value);
	}
	return undefined;
}
function resolveRoleHeaders(opts: ExecuteStatefulWorkflowOptions, role: string | undefined): HeaderRecord {
	if (!role) return {};
	const fromMap = opts.roleHeaders?.[role];
	if (fromMap) return normalizeHeaderRecord(fromMap);
	try {
		const fromVault = getRoleHeadersMap(opts.vault ?? opts.root ?? process.cwd(), role);
		if (fromVault) return normalizeHeaderRecord(fromVault);
	} catch {
		// 忽略角色头获取失败。
	}
	return {};
}
function makeBlockedTrace(args: { stepIndex: number; step: StatefulWorkflowStep; id: string; method: string;
	requestedUrl: string; resolvedUrl: string; tier: WorkflowActionTier; reason: string;
	requestHeaders?: HeaderRecord; requestBody?: string; redirectChain?: string[]; abortedByScope?: boolean;
}): StatefulStepTrace {
	return {
		stepIndex: args.stepIndex, id: args.id, name: args.step.name, method: args.method,
		requestedUrl: args.requestedUrl, resolvedUrl: args.resolvedUrl, finalUrl: args.resolvedUrl,
		status: 0, ok: false, blocked: true, abortedByScope: args.abortedByScope ?? true,
		blockReason: args.reason, durationMs: 0, redirectChain: args.redirectChain ?? [],
		requestHeaders: args.requestHeaders ?? {}, requestBody: args.requestBody, responseHeaders: {}, extracted: {}, tier: args.tier, cookiesSet: [], };
}
/** 内部执行器：返回真实未脱敏变量与最后响应体，供同文件后续能力复用。 */
export async function executeStatefulWorkflowChainInternal(opts: ExecuteStatefulWorkflowOptions): Promise<InternalWorkflowExecResult> {
	const startedAt = Date.now(); const normRoot = opts.root ?? process.cwd();
	const vault = opts.vault ?? tryLoadVault(normRoot); const mode = opts.mode ?? "pentest"; const allowDestructive = opts.allowDestructive === true;
	const fetchFn = opts.fetchFn ?? ((globalThis as unknown as { fetch?: TrafficFetchFn }).fetch as TrafficFetchFn | undefined);
	const variables: Record<string, string> = { ...(opts.initialVars ?? {}), ...(opts.vars ?? {}) };
	const jar = new CookieJar(opts.initialCookies);
	const secrets = collectSecretSet({ root: normRoot, vault, extraSecrets: opts.extraSecrets,
		headers: opts.extraHeaders, roleHeaders: opts.roleHeaders, vars: variables, cookies: jar.toJSON() });
	const rawTraces: StatefulStepTrace[] = []; const rawStepBodies: Array<string | undefined> = [];
	let totalRequests = 0; let overallBlocked = false; let overallAbortedByScope = false; let overallFatalError = false;
	let overallError: string | undefined; let lastRawBody: string | undefined; let lastRawHeaders: HeaderRecord | undefined; let lastRawJson: unknown;
	let finalStatus: number | undefined; let finalUrl: string | undefined;
	if (!fetchFn) {
		return { ok: false, blocked: false, abortedByScope: false, error: "缺少 fetch 实现，无法执行工作流",
			steps: [], variables: {}, cookies: {}, totalRequests: 0, durationMs: Date.now() - startedAt,
			redacted: true, rawVariables: {}, rawCookies: {}, rawStepBodies: [] };
	}
	for (let index = 0; index < opts.steps.length; index++) {
		const step = opts.steps[index]; const stepStartedAt = Date.now();
		const id = step.id ?? `step-${index + 1}-${randomUUID().slice(0, 8)}`; const requestedUrl = step.url;
		const method = String(step.method ?? "GET").toUpperCase(); const urlInterpolated = interpolateTemplate(step.url, variables);
		const resolvedUrl = urlInterpolated.value; const bodyInterpolated = interpolateBodyValue(step.body, variables);
		const requestBody = bodyInterpolated.value; const unresolved = [...urlInterpolated.unresolved, ...bodyInterpolated.unresolved];
		const initialClassification = classifyWorkflowAction({ method, url: resolvedUrl, body: requestBody, scope: opts.scope, mode, allowDestructive });
		if (unresolved.length > 0 && step.allowUnresolvedVars !== true) {
			const trace = makeBlockedTrace({ stepIndex: index, step, id, method, requestedUrl, resolvedUrl,
				tier: initialClassification.tier, reason: `存在未解析模板变量：${unresolved.join(", ")}`, abortedByScope: false });
			rawTraces.push(trace); rawStepBodies.push(undefined); overallBlocked = true; overallError = trace.blockReason; break;
		}
		const stepAllowDestructive = step.allowDestructive ?? allowDestructive; const role = step.role ?? opts.role;
		const mergedHeaders: HeaderRecord = { ...resolveRoleHeaders(opts, role),
			...normalizeHeaderRecord(opts.extraHeaders), ...normalizeHeaderRecord(step.extraHeaders), ...normalizeHeaderRecord(step.headers) };
		for (const sVal of collectSecretSet({ headers: mergedHeaders })) secrets.add(sVal);
		if (step.body && typeof step.body === "object") {
			for (const [bk, bv] of Object.entries(step.body)) { if (isSensitiveKeyName(bk) && typeof bv === "string" && bv.trim().length >= 3) secrets.add(bv.trim()); }
		}
		const requestHeaders: HeaderRecord = {};
		const headerUnresolved: string[] = [];
		for (const [key, value] of Object.entries(mergedHeaders)) {
			const interpolated = interpolateTemplate(value, variables); headerUnresolved.push(...interpolated.unresolved);
			requestHeaders[key.toLowerCase()] = interpolated.value;
		}
		if (headerUnresolved.length > 0 && step.allowUnresolvedVars !== true) {
			const trace = makeBlockedTrace({ stepIndex: index, step, id, method, requestedUrl, resolvedUrl,
				tier: initialClassification.tier, reason: `请求头存在未解析模板变量：${headerUnresolved.join(", ")}`, requestHeaders, requestBody });
			rawTraces.push(trace); rawStepBodies.push(undefined); overallBlocked = true; overallAbortedByScope = true; overallError = trace.blockReason; break;
		}
		if (step.body !== undefined && typeof step.body === "object" && !requestHeaders["content-type"]) { requestHeaders["content-type"] = "application/json"; }
		const preflight = validateUrlAndActionScope(resolvedUrl, method, requestBody, opts.scope, mode, stepAllowDestructive);
		if (!preflight.ok) {
			const trace = makeBlockedTrace({ stepIndex: index, step, id, method, requestedUrl, resolvedUrl,
				tier: preflight.tierClassification.tier, reason: preflight.reason ?? "Scope 守卫拦截", requestHeaders, requestBody });
			if (preflight.blockedByTier) trace.abortedByScope = true;
			rawTraces.push(trace); rawStepBodies.push(undefined); overallBlocked = true;
			overallAbortedByScope = overallAbortedByScope || trace.abortedByScope; overallError = trace.blockReason; break;
		}
		const followRedirects = step.followRedirects ?? opts.followRedirects ?? true;
		const maxRedirects = Math.max(0, step.maxRedirects ?? opts.maxRedirects ?? 5);
		const timeoutMs = Math.max(1, step.timeoutMs ?? opts.timeoutMs ?? opts.defaultTimeoutMs ?? 30_000);
		const redirectChain: string[] = []; const cookiesSet: string[] = []; let currentUrl = resolvedUrl; let currentMethod = method;
		let currentBody = requestBody;
		let currentHeaders: HeaderRecord = { ...requestHeaders };
		let redirects = 0; let stepBlocked = false; let stepAbortedByScope = false; let stepRedirectBlocked = false;
		let stepTimedOut = false; let stepFatalError = false; let stepError: string | undefined; let stepStatus = 0; let stepFinalUrl = resolvedUrl;
		let responseHeaders: HeaderRecord = {};
		let responseBodySnippet: string | undefined; let recordedEntryId: string | undefined;
		for (;;) {
			const hopCheck = validateUrlAndActionScope(currentUrl, currentMethod, currentBody, opts.scope, mode, stepAllowDestructive);
			if (!hopCheck.ok) { stepBlocked = true; stepAbortedByScope = true; stepError = hopCheck.reason ?? "Scope 守卫拦截"; break; }
			const sendHeaders: HeaderRecord = { ...currentHeaders };
			const jarCookie = jar.getCookieHeader(currentUrl);
			if (jarCookie) sendHeaders.cookie = sendHeaders.cookie ? `${sendHeaders.cookie}; ${jarCookie}` : jarCookie;
			const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
			let externalAbortListener: (() => void) | undefined;
			if (opts.signal) {
				if (opts.signal.aborted) controller.abort();
				else { externalAbortListener = () => controller.abort(); opts.signal.addEventListener("abort", externalAbortListener); }
			}
			let response: TrafficFetchResponseLike; let responseText = ""; const requestStartedAt = Date.now();
			try {
				totalRequests++;
				response = await fetchFn(currentUrl, { method: currentMethod, headers: sendHeaders,
					body: currentMethod === "GET" || currentMethod === "HEAD" ? undefined : currentBody, redirect: "manual", signal: controller.signal });
				responseText = await response.text();
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				if (controller.signal.aborted) { stepTimedOut = true; stepError = `请求超时（${timeoutMs}ms）`; }
				else { stepFatalError = true; stepError = `请求失败：${message}`; }
				break;
			} finally {
				clearTimeout(timer);
				if (externalAbortListener && opts.signal) opts.signal.removeEventListener("abort", externalAbortListener);
			}
			const durationMs = Date.now() - requestStartedAt; stepStatus = response.status;
			stepFinalUrl = currentUrl; responseHeaders = headersToRecord(response.headers);
			responseBodySnippet = responseText.slice(0, 8192); const setCookieValues = getSetCookieList(response.headers);
			if (setCookieValues.length > 0) {
				for (const name of jar.setFromSetCookie(setCookieValues, currentUrl)) { if (!cookiesSet.includes(name)) cookiesSet.push(name); }
			}
			if (opts.recorder && opts.recordTraffic !== false) {
				try {
					const entry = opts.recorder.record({ method: currentMethod, url: currentUrl, requestHeaders: sendHeaders,
						requestBody: currentBody, status: response.status, responseHeaders, responseBody: responseText,
						durationMs, tags: step.tags, role, stepId: id, note: step.note });
					recordedEntryId = entry.id;
				} catch {
					// 记录失败不影响主流程。
				}
			}
			const location = responseHeaders["location"]; const isRedirect = response.status >= 300 && response.status < 400;
			if (!isRedirect || !location) break;
			if (!followRedirects) break;
			if (redirects >= maxRedirects) { stepFatalError = true; stepError = `超过最大重定向次数（${maxRedirects}）`; break; }
			let nextUrl: URL;
			try { nextUrl = new URL(location, currentUrl); }
			catch { stepFatalError = true; stepError = "重定向 Location 非法"; break; }
			const nextUrlStr = nextUrl.toString();
			const redirectCheck = validateUrlAndActionScope(nextUrlStr, currentMethod, currentBody, opts.scope, mode, stepAllowDestructive);
			if (!redirectCheck.ok) { stepBlocked = true; stepAbortedByScope = true; stepRedirectBlocked = true; stepError = redirectCheck.reason ?? "重定向目标越界"; break; }
			redirectChain.push(nextUrlStr); let currentOrigin = "";
			try { currentOrigin = new URL(currentUrl).origin; } catch { currentOrigin = ""; }
			if (currentOrigin && currentOrigin !== nextUrl.origin) currentHeaders = stripSensitiveHeaders(currentHeaders);
			if (response.status === 303 || ((response.status === 301 || response.status === 302) && currentMethod === "POST")) {
				currentMethod = "GET"; currentBody = undefined; delete currentHeaders["content-type"]; delete currentHeaders["content-length"];
			}
			currentUrl = nextUrlStr; redirects++;
		}
		const extracted: Record<string, string> = {};
		if (!stepBlocked && !stepTimedOut && responseBodySnippet !== undefined) {
			for (const [name, spec] of Object.entries(step.extract ?? {})) {
				const value = extractBySpec(spec, responseHeaders, responseBodySnippet, jar);
				if (value === undefined || value === null || value === "") continue;
				extracted[name] = value; variables[name] = value;
				if (isSensitiveKeyName(name) || value.length >= 12) {
					secrets.add(value);
					try { opts.recorder?.registerTransientSecret(value); } catch { /* 忽略 */ }
				}
			}
		}
		let expectStatusOk = true;
		if (step.expectStatus !== undefined && !stepBlocked && !stepTimedOut) {
			const expected = Array.isArray(step.expectStatus) ? step.expectStatus : [step.expectStatus]; expectStatusOk = expected.includes(stepStatus);
			if (!expectStatusOk) stepError = stepError ?? `期望状态码 ${expected.join("/")}，实际 ${stepStatus}`;
		}
		const stepOk = !stepBlocked && !stepTimedOut && !stepFatalError && expectStatusOk && stepError === undefined;
		const trace: StatefulStepTrace = { stepIndex: index, id, name: step.name, method,
			requestedUrl, resolvedUrl, finalUrl: stepFinalUrl, status: stepStatus, ok: stepOk, blocked: stepBlocked, abortedByScope: stepAbortedByScope,
			redirectBlocked: stepRedirectBlocked || undefined, timedOut: stepTimedOut || undefined,
			expectStatusOk, blockReason: stepBlocked ? stepError : undefined, error: stepError,
			durationMs: Date.now() - stepStartedAt, redirectChain, requestHeaders, requestBody,
			responseHeaders, responseBodySnippet, extracted, recordedEntryId, tier: initialClassification.tier, cookiesSet };
		rawTraces.push(trace); rawStepBodies.push(responseBodySnippet);
		finalStatus = stepStatus; finalUrl = stepFinalUrl; lastRawBody = responseBodySnippet; lastRawHeaders = responseHeaders;
		lastRawJson = tryParseJson(responseBodySnippet);
		if (stepBlocked || stepAbortedByScope || stepTimedOut || stepFatalError) {
			overallBlocked = overallBlocked || stepBlocked; overallAbortedByScope = overallAbortedByScope || stepAbortedByScope;
			overallFatalError = overallFatalError || stepFatalError; overallError = overallError ?? stepError;
			break;
		}
	}
	const redactOpts: RedactOptions = { root: opts.root, vault, extraSecrets: [...secrets] };
	const rootOrVault = vault ?? opts.root;
	const redactedSteps = rawTraces.map((trace) => {
		const extracted: Record<string, string> = {};
		for (const [key, value] of Object.entries(trace.extracted)) {
			extracted[key] = isSensitiveKeyName(key) ? REDACTED_MARKER : scrubSecretsInText(value, secrets, rootOrVault);
		}
		return { ...trace, requestedUrl: safeRedactUrl(trace.requestedUrl, redactOpts),
			resolvedUrl: safeRedactUrl(trace.resolvedUrl, redactOpts), finalUrl: safeRedactUrl(trace.finalUrl, redactOpts),
			redirectChain: trace.redirectChain.map((url) => safeRedactUrl(url, redactOpts)), requestHeaders: safeRedactHeaders(trace.requestHeaders, redactOpts),
			requestBody: safeRedactBody(trace.requestBody, { ...redactOpts, maxChars: 4096 }),
			responseHeaders: safeRedactHeaders(trace.responseHeaders, redactOpts),
			responseBodySnippet: safeRedactBody(trace.responseBodySnippet, { ...redactOpts, maxChars: 4096 }), extracted,
			blockReason: trace.blockReason ? scrubSecretsInText(trace.blockReason, secrets, rootOrVault) : undefined,
			error: trace.error ? scrubSecretsInText(trace.error, secrets, rootOrVault) : undefined, cookiesSet: [...trace.cookiesSet] };
	});
	const redactedVariables: Record<string, string> = {};
	for (const [key, value] of Object.entries(variables)) {
		redactedVariables[key] = isSensitiveKeyName(key) ? REDACTED_MARKER : scrubSecretsInText(value, secrets, rootOrVault);
	}
	const resultOk = !overallBlocked && !overallAbortedByScope && !overallFatalError && !overallError && rawTraces.every((trace) => trace.ok);
	return { ok: resultOk, blocked: overallBlocked, abortedByScope: overallAbortedByScope,
		error: overallError ? scrubSecretsInText(overallError, secrets, rootOrVault) : undefined,
		steps: redactedSteps, variables: redactedVariables, cookies: jar.toRedactedJSON(),
		finalStatus, finalUrl: finalUrl ? safeRedactUrl(finalUrl, redactOpts) : undefined, totalRequests, durationMs: Date.now() - startedAt, redacted: true,
		rawVariables: { ...variables }, rawCookies: jar.toJSON(), rawLastResponseBody: lastRawBody,
		rawLastResponseJson: lastRawJson, rawLastResponseHeaders: lastRawHeaders, rawStepBodies: [...rawStepBodies] };
}
/**
 * 对外多步状态链重放入口：仅返回 100% 脱敏结果。
 * 真实响应用于同文件后续能力时，请调用 {@link executeStatefulWorkflowChainInternal}。
 */
export async function executeStatefulWorkflowChain(opts: ExecuteStatefulWorkflowOptions): Promise<StatefulWorkflowResult> {
	const internal = await executeStatefulWorkflowChainInternal(opts);
	const { rawVariables: _rawVariables, rawCookies: _rawCookies, rawLastResponseBody: _rawLastResponseBody,
		rawLastResponseJson: _rawLastResponseJson, rawLastResponseHeaders: _rawLastResponseHeaders, rawStepBodies: _rawStepBodies, ...safe } = internal;
	return safe;
}

/* ------------------------------------------------------------------ *
 * 第三部分：Mass Assignment 探测 + 二阶有状态工作流验证
 * 接续第一、二部分，不含任何 import 语句，复用前两块已导出的工具与顶部注入依赖。
 * ------------------------------------------------------------------ */
const SW3_MISSING_VAR_RE = /unresolved|missing\s+var|未解析|缺少变量|缺失变量/i;
const SW3_FIELD_REJECT_RE = /unknown\s+field|unrecognized|not\s+allowed|invalid\s+(?:field|property|param)/i;
type Sw3Verdict = { allowed: boolean; reason?: string; tier?: WorkflowActionTier };
type Sw3FailureKind = NonNullable<SecondOrderWorkflowResult["failureKind"]>;
interface Sw3Session {
	vars: Record<string, string>; cookies: Record<string, string>; }
interface Sw3RunCtx {
	root: string; scope: ScopePolicy; mode: Mode | string; allowDestructive: boolean; vault?: SessionVault; role?: string;
	roleHeaders?: Record<string, Record<string, string>>; extraHeaders?: Record<string, string>; fetchFn?: TrafficFetchFn;
	recorder?: TrafficRecorder; extraSecrets?: string[]; timeoutMs?: number; recordTraffic?: boolean; signal?: AbortSignal; }
interface Sw3RunResult {
	trace?: StatefulStepTrace; status: number; ok: boolean; blocked: boolean; aborted: boolean; body?: string; json?: unknown;
	headers: Record<string, string>; error?: string; }
interface Sw3FetchLike {
	(url: string, init?: Record<string, unknown>): Promise<{
		ok: boolean; status: number; text: () => Promise<string>; headers: Headers;
	}>; }

/* ---------------------------- 内部工具补齐 ---------------------------- */
function sw3Err(e: unknown): string {
	if (e instanceof Error) return e.message;
	return typeof e === "string" ? e : "未知错误";
}
function sw3Obj(v: unknown): v is Record<string, unknown> { return typeof v === "object" && v !== null && !Array.isArray(v); }
function sw3Unit(n: unknown, fallback: number): number {
	const x = typeof n === "number" && Number.isFinite(n) ? n : fallback;
	return x < 0 ? 0 : x > 1 ? 1 : x;
}
function sw3Timeout(v: unknown, fallback = 15_000): number {
	const n = typeof v === "number" && Number.isFinite(v) ? v : fallback;
	return Math.max(500, Math.min(120_000, Math.round(n)));
}
function sw3Note(text: string, max: number): string {
	const t = String(text ?? "");
	return t.length > max ? `${t.slice(0, max)}…` : t;
}
function sw3Placeholder(name: string): string {
	const n = String(name ?? "").toLowerCase();
	if (n.includes("email")) return "probe@example.com";
	if (n.includes("ip")) return "127.0.0.1";
	if (n.includes("host") || n.includes("domain")) return "example.com";
	return "1";
}
/** 变量替换：优先复用 interpolateTemplate，未解析项以安全占位符兜底。 */
function sw3Subst(text: string, vars: Record<string, string>): string {
	const raw = String(text ?? "");
	if (!raw.includes("{{")) return raw;
	const fill = (s: string): string => s.replace(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g, (_m, name: string) => {
			const v = vars ? vars[name] : undefined;
			return typeof v === "string" && v.length > 0 ? v : sw3Placeholder(name);
		});
	try {
		return fill(String(interpolateTemplate(raw, vars ?? {}).value ?? ""));
	} catch { return fill(raw); }
}
function sw3Verdict(res: { ok: boolean; reason?: string }): Sw3Verdict { return { allowed: res.ok, reason: res.reason }; }
function sw3Secrets(extra?: string[]): Set<string> { return collectSecretSet({ extraSecrets: extra }); }
function sw3BodyText(body: unknown, vars: Record<string, string>): string | undefined {
	if (body === undefined || body === null) return undefined;
	if (typeof body === "string") return sw3Subst(body, vars).slice(0, 8_000);
	if (sw3Obj(body) || Array.isArray(body)) {
		try {
			return JSON.stringify(body).slice(0, 8_000);
		} catch { return undefined; }
	}
	return String(body).slice(0, 8_000);
}
function sw3Path(url: string | undefined, vars: Record<string, string>): string {
	try {
		const u = new URL(sw3Subst(String(url ?? ""), vars), "http://sw3.local");
		return `${u.pathname}${u.search}`;
	} catch { return ""; }
}
function sw3Origin(url: string | undefined, vars: Record<string, string>): { origin: string; host: string } | null {
	const raw = sw3Subst(String(url ?? ""), vars);
	if (!/^https?:\/\//i.test(raw)) return null;
	try {
		const u = new URL(raw);
		return { origin: u.origin, host: u.host || u.hostname };
	} catch { return null; }
}
function sw3Json(text?: string): unknown { return tryParseJson(text); }
function sw3FindDeep(obj: unknown, key: string, depth = 0): unknown {
	if (depth > 8 || obj === null || obj === undefined) return undefined;
	if (Array.isArray(obj)) {
		for (const item of obj) {
			const hit = sw3FindDeep(item, key, depth + 1);
			if (hit !== undefined) return hit;
		}
		return undefined;
	}
	if (!sw3Obj(obj)) return undefined;
	if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
	for (const v of Object.values(obj)) {
		const hit = sw3FindDeep(v, key, depth + 1);
		if (hit !== undefined) return hit;
	}
	return undefined;
}
function sw3DeepEq(a: unknown, b: unknown, depth = 0): boolean {
	if (depth > 6) return false;
	if (a === b) return true;
	if (typeof a === "number" && typeof b === "number") return Math.abs(a - b) < 1e-9;
	if (a === null || b === null || a === undefined || b === undefined) return false;
	if (Array.isArray(a) && Array.isArray(b)) {
		if (a.length !== b.length) return false;
		return a.every((v, i) => sw3DeepEq(v, b[i], depth + 1));
	}
	if (sw3Obj(a) && sw3Obj(b)) {
		const ka = Object.keys(a); const kb = Object.keys(b);
		if (ka.length !== kb.length) return false;
		return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && sw3DeepEq(a[k], b[k], depth + 1));
	}
	if (typeof a !== "object" && typeof b !== "object") return String(a) === String(b);
	return false;
}
function sw3Normalize(text: string, pathHint?: string): string {
	let s = String(text ?? "").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ");
	if (pathHint && pathHint.length > 1) {
		const clean = pathHint.split(/[?#]/)[0] ?? "";
		if (clean && clean !== "/") s = s.split(clean).join(" ");
	}
	return s
		.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, " ")
		.replace(/\b[0-9a-f]{16,}\b/gi, " ")
		.replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, " ")
		.replace(/\s+/g, "")
		.toLowerCase();
}
function sw3Dice(a: string, b: string): number {
	if (!a || !b) return 0;
	if (a === b) return 1;
	const grams = (s: string): Map<string, number> => {
		const m = new Map<string, number>();
		if (s.length < 2) {
			m.set(s, 1);
			return m;
		}
		for (let i = 0; i < s.length - 1; i++) { const g = s.slice(i, i + 2); m.set(g, (m.get(g) ?? 0) + 1); }
		return m;
	};
	const ma = grams(a); const mb = grams(b); let overlap = 0; let totalA = 0; let totalB = 0;
	ma.forEach((c, g) => {
		totalA += c; const other = mb.get(g);
		if (other) overlap += Math.min(c, other);
	});
	mb.forEach((c) => {
		totalB += c;
	});
	const denom = totalA + totalB;
	return denom === 0 ? 0 : (2 * overlap) / denom;
}
/** 计算两段响应体的模板相似度：模板指纹一致视为同一页面，否则退化为归一化 bigram Dice 系数。 */
export function computeTemplateSimilarity(textA: string, textB: string, pathHint?: string): number {
	const a = String(textA ?? ""); const b = String(textB ?? "");
	if (!a.trim() && !b.trim()) return 1;
	if (!a.trim() || !b.trim()) return 0;
	const na = sw3Normalize(a, pathHint); const nb = sw3Normalize(b, pathHint);
	if (na === nb) return 1;
	let fpA = ""; let fpB = "";
	try {
		fpA = computeTemplateFingerprint(a, pathHint); fpB = computeTemplateFingerprint(b, pathHint);
	} catch {
		/* 指纹不可用时仅使用文本相似度 */
	}
	const dice = sw3Unit(sw3Dice(na, nb), 0);
	if (fpA && fpA === fpB) return Math.max(dice, 0.99);
	return dice;
}
function sw3RedactValue(field: string, value: unknown, secrets: Set<string>): unknown { return isSensitiveKeyName(field) ? REDACTED_MARKER : redactRecordDeep(value, secrets); }
function sw3RedactVars(vars: Record<string, string>, secrets: Set<string>): Record<string, string> { return redactRecordDeep(vars ?? {}, secrets) as Record<string, string>; }
function sw3RedactTrace(trace: StatefulStepTrace | undefined, secrets: Set<string>): StatefulStepTrace | undefined {
	if (!trace) return undefined;
	const scrubHeaders = (h: Record<string, string> | undefined): Record<string, string> => {
		const out: Record<string, string> = {};
		for (const [k, v] of Object.entries(h ?? {})) { out[k] = isSensitiveKeyName(k) ? REDACTED_MARKER : scrubSecretsInText(String(v), secrets); }
		return out;
	};
	const scrubText = (t?: string): string | undefined => typeof t === "string" ? scrubSecretsInText(t, secrets).slice(0, 2_000) : t;
	return {
		...trace, requestedUrl: scrubSecretsInText(String(trace.requestedUrl ?? ""), secrets),
		resolvedUrl: scrubSecretsInText(String(trace.resolvedUrl ?? ""), secrets), finalUrl: scrubSecretsInText(String(trace.finalUrl ?? ""), secrets),
		redirectChain: (trace.redirectChain ?? []).map((u) => scrubSecretsInText(String(u), secrets)),
		requestHeaders: scrubHeaders(trace.requestHeaders), responseHeaders: scrubHeaders(trace.responseHeaders),
		requestBody: scrubText(trace.requestBody), responseBodySnippet: scrubText(trace.responseBodySnippet),
		blockReason: scrubText(trace.blockReason), error: scrubText(trace.error),
		extracted: redactRecordDeep(trace.extracted ?? {}, secrets) as Record<string, string>, };
}
function sw3Preflight(url: string, method: string, bodyText: string | undefined, scope: ScopePolicy, mode: Mode | string, allowDestructive: boolean): Sw3Verdict { try { return sw3Verdict(validateUrlAndActionScope(url, method, bodyText, scope, mode, allowDestructive)); } catch (e) { return { allowed: false, reason: `Scope 校验异常：${sw3Err(e)}` }; } }
function sw3PreflightStep(step: StatefulWorkflowStep | undefined, scope: ScopePolicy, mode: Mode | string,
	allowDestructive: boolean, vars: Record<string, string>,): { ok: boolean; reason?: string; tierBlocked: boolean } {
	if (!step) return { ok: true, tierBlocked: false };
	const method = String(step.method ?? "GET").toUpperCase(); const url = sw3Subst(String(step.url ?? ""), vars);
	if (!url) return { ok: false, reason: "步骤缺少 URL", tierBlocked: false };
	const bodyText = sw3BodyText(step.body, vars); const verdict = sw3Preflight(url, method, bodyText, scope, mode, allowDestructive);
	if (verdict.allowed) return { ok: true, tierBlocked: false };
	let tierBlocked = false;
	try {
		const cls = classifyWorkflowAction({ method, url, body: bodyText, scope, mode, allowDestructive });
		tierBlocked = cls.isDestructive === true && allowDestructive !== true;
	} catch {
		/* 分级判定失败时按 Scope 阻断处理 */
	}
	return { ok: false, reason: verdict.reason ?? `${method} ${url} 被 Scope/分级策略阻断`, tierBlocked };
}
function sw3ScopedFetch(base: Sw3FetchLike | undefined, scope: ScopePolicy, mode: Mode | string,
	allowDestructive: boolean, headers: Record<string, string> | undefined, secrets: Set<string>,): Sw3FetchLike {
	const inner: Sw3FetchLike = base ?? ((u, init) => fetch(u, init as RequestInit) as unknown as ReturnType<Sw3FetchLike>);
	return async (url, init) => {
		const method = String((init?.method as string | undefined) ?? "GET").toUpperCase();
		const verdict = sw3Preflight(url, method, undefined, scope, mode, allowDestructive);
		if (!verdict.allowed) {
			return {
				ok: false, status: 0, text: async () => `[SCOPE-BLOCKED] ${scrubSecretsInText(verdict.reason ?? "", secrets)}`, headers: new Headers(), };
		}
		try {
			const extra = (init?.headers as Record<string, string> | undefined) ?? {};
			return await inner(url, { ...(init ?? {}), method, headers: { ...(headers ?? {}), ...extra } });
		} catch (e) {
			return { ok: false, status: 0, text: async () => `[NETWORK-ERROR] ${sw3Err(e)}`, headers: new Headers() };
		}
	};
}
/** 单步执行：复用第一部分的有状态链，串联变量与 Cookie，并保留原始响应体。 */
async function sw3RunStep(step: StatefulWorkflowStep, session: Sw3Session, ctx: Sw3RunCtx, secrets: Set<string>,): Promise<Sw3RunResult> {
	let res: InternalWorkflowExecResult;
	try {
		res = await executeStatefulWorkflowChainInternal({ root: ctx.root, steps: [step], scope: ctx.scope,
			mode: ctx.mode, allowDestructive: ctx.allowDestructive, vars: { ...session.vars }, role: ctx.role,
			roleHeaders: ctx.roleHeaders, extraHeaders: ctx.extraHeaders, vault: ctx.vault, fetchFn: ctx.fetchFn,
			recorder: ctx.recorder, initialCookies: { ...session.cookies },
			extraSecrets: ctx.extraSecrets, recordTraffic: ctx.recordTraffic, signal: ctx.signal, defaultTimeoutMs: ctx.timeoutMs, });
	} catch (e) {
		return {
			status: 0, ok: false, blocked: false, aborted: false, headers: {}, error: scrubSecretsInText(sw3Err(e), secrets), };
	}
	const trace = res.steps.length > 0 ? res.steps[res.steps.length - 1] : undefined;
	session.vars = { ...session.vars, ...(res.rawVariables ?? res.variables ?? {}) };
	session.cookies = { ...session.cookies, ...(res.rawCookies ?? res.cookies ?? {}) };
	const headers: Record<string, string> = {};
	for (const [k, v] of Object.entries(res.rawLastResponseHeaders ?? {})) headers[k] = String(v);
	const lastStepBody = res.rawStepBodies.length > 0 ? res.rawStepBodies[res.rawStepBodies.length - 1] : undefined;
	return {
		trace, status: typeof trace?.status === "number" ? trace.status : 0,
		ok: res.ok === true && trace?.ok !== false, blocked: res.blocked === true || trace?.blocked === true,
		aborted: res.abortedByScope === true || trace?.abortedByScope === true,
		body: res.rawLastResponseBody ?? lastStepBody ?? trace?.responseBodySnippet, json: res.rawLastResponseJson, headers, error: res.error ?? trace?.error, };
}

/* ---------------------- 三、Mass Assignment 探测 ---------------------- */

export interface MassAssignmentFieldSpec {
	field: string; value: unknown; label?: string; expectedReadPath?: string; }

export interface MassAssignmentProbeOptions {
	scope: ScopePolicy; writeStep: StatefulWorkflowStep; readStep?: StatefulWorkflowStep; baselineBody?: Record<string, unknown>;
	candidateFields?: MassAssignmentFieldSpec[]; rollbackStep?: StatefulWorkflowStep;
	soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null; autoSampleSoft404?: boolean; templateSimilarityThreshold?: number;
	root?: string; mode?: Mode | string; vault?: SessionVault; role?: string; roleHeaders?: Record<string, Record<string, string>>;
	extraHeaders?: Record<string, string>; initialVars?: Record<string, string>; initialCookies?: Record<string, string>;
	fetchFn?: TrafficFetchFn; recorder?: TrafficRecorder; timeoutMs?: number; extraSecrets?: string[]; allowDestructive?: boolean; }

export interface MassAssignmentCaseResult {
	field: string; label?: string; bound: boolean; suppressedReason?: string; writeStatus: number; readStatus?: number;
	isSoft404: boolean; templateSimilarity: number; observedValueRedacted?: unknown; baselineValueRedacted?: unknown;
	writeTrace?: StatefulStepTrace; readTrace?: StatefulStepTrace; }

export interface MassAssignmentProbeResult {
	detected: boolean; abortedByScope: boolean; blockReason?: string; baselineStatus: number; baselineSoft404: boolean;
	vulnerableFields: string[]; cases: MassAssignmentCaseResult[]; rollbackExecuted: boolean; rollbackOk: boolean;
	rollbackTrace?: StatefulStepTrace; beliefObservation: BeliefObservation; summary: string; }
const SW3_DEFAULT_MASS_FIELDS: readonly MassAssignmentFieldSpec[] = [{ field: "role", value: "admin" },
	{ field: "isAdmin", value: true }, { field: "permissions", value: ["*"] }, { field: "verified", value: true }, ];
/**
 * Mass Assignment 探测：在基线写请求上逐字段注入越权属性，通过独立读步做差分比对，
 * 判定服务端是否真正绑定并持久化该字段。全流程受 Scope 与动作分级约束。
 */
export async function probeMassAssignment(opts: MassAssignmentProbeOptions): Promise<MassAssignmentProbeResult> {
	const root = opts.root ?? process.cwd(); const mode: Mode | string = opts.mode ?? "standard";
	const allowDestructive = opts.allowDestructive === true; const secrets = sw3Secrets(opts.extraSecrets);
	const session: Sw3Session = { vars: { ...(opts.initialVars ?? {}) }, cookies: { ...(opts.initialCookies ?? {}) }, };
	const threshold = sw3Unit(opts.templateSimilarityThreshold, 0.9); const timeoutMs = sw3Timeout(opts.timeoutMs);
	const cases: MassAssignmentCaseResult[] = []; const vulnerableFields: string[] = [];
	for (const [label, step] of [["写入步", opts.writeStep], ["读取步", opts.readStep], ["回滚步", opts.rollbackStep],
	] as Array<[string, StatefulWorkflowStep | undefined]>) {
		if (!step) continue;
		const verdict = sw3PreflightStep(step, opts.scope, mode, allowDestructive, session.vars);
		if (verdict.ok) continue;
		return {
			detected: false, abortedByScope: true, blockReason: `${label}预检被阻断：${verdict.reason ?? "超出授权范围"}`,
			baselineStatus: 0, baselineSoft404: false, vulnerableFields: [], cases: [],
			rollbackExecuted: false, rollbackOk: false, beliefObservation: { type: "waf_block", weight: 1,
				note: `${label}在 Scope/分级预检阶段被阻断，未发送任何请求`, }, summary: "Scope/分级预检未通过，本次探测未发送任何请求。", };
	}
	let soft404Baseline: Soft404BaselineInput | Soft404Baseline | null = opts.soft404Baseline ?? null;
	if (opts.soft404Baseline === undefined && opts.autoSampleSoft404 !== false) {
		const origin = sw3Origin(opts.writeStep.url, session.vars);
		if (origin && hostAllowed(origin.host, opts.scope)) {
			try {
				const fetcher = sw3ScopedFetch(opts.fetchFn as unknown as Sw3FetchLike | undefined, opts.scope, mode, allowDestructive, opts.extraHeaders, secrets,);
				soft404Baseline = await sampleSoft404Baseline(origin.origin, fetcher as unknown as Parameters<typeof sampleSoft404Baseline>[1],
					{ headers: opts.extraHeaders, timeoutMs: Math.min(timeoutMs, 6_000) },);
			} catch { soft404Baseline = null; }
		}
	}
	const ctx: Sw3RunCtx = { root, scope: opts.scope, mode, allowDestructive, vault: opts.vault, role: opts.role, roleHeaders: opts.roleHeaders,
		extraHeaders: opts.extraHeaders, fetchFn: opts.fetchFn, recorder: opts.recorder, extraSecrets: opts.extraSecrets, timeoutMs, };
	const writeBodyBase: unknown = opts.baselineBody !== undefined ? opts.baselineBody : opts.writeStep.body;
	const baselineObj: Record<string, unknown> = sw3Obj(writeBodyBase) ? { ...writeBodyBase } : {};
	const withBody = (body: Record<string, unknown>): StatefulWorkflowStep => ({ ...opts.writeStep, body: JSON.stringify(body), });
	const readPathHint = (): string => sw3Path(opts.readStep?.url ?? opts.writeStep.url, session.vars);
	const baselineWrite = await sw3RunStep(withBody(baselineObj), session, ctx, secrets);
	if (baselineWrite.aborted || baselineWrite.blocked) {
		return {
			detected: false, abortedByScope: baselineWrite.aborted, blockReason: baselineWrite.trace?.blockReason ?? baselineWrite.error ?? "基线写入步被策略阻断",
			baselineStatus: baselineWrite.status, baselineSoft404: false, vulnerableFields: [], cases: [], rollbackExecuted: false, rollbackOk: false,
			beliefObservation: { type: "waf_block", weight: 1, note: "基线写入请求被 Scope/分级策略阻断" }, summary: "基线写入请求被拦截，未能建立差分对比基线。", };
	}
	const baselineRead = opts.readStep ? await sw3RunStep(opts.readStep, session, ctx, secrets) : baselineWrite;
	if (baselineRead.aborted || baselineRead.blocked) {
		return {
			detected: false, abortedByScope: baselineRead.aborted,
			blockReason: baselineRead.trace?.blockReason ?? baselineRead.error ?? "基线读取步被策略阻断", baselineStatus: baselineRead.status,
			baselineSoft404: false, vulnerableFields: [], cases: [], rollbackExecuted: false,
			rollbackOk: false, beliefObservation: { type: "waf_block", weight: 1, note: "基线读取请求被 Scope/分级策略阻断" }, summary: "基线读取请求被拦截，未能建立差分对比基线。", };
	}
	const baselineStatus = baselineRead.status; const baselineText = baselineRead.body ?? ""; const baselineJson = baselineRead.json ?? sw3Json(baselineText);
	const baselineSoft = detectSoft404(
		{ status: baselineStatus, body: baselineText, headers: baselineRead.headers, path: readPathHint() }, soft404Baseline, ).isSoft404;
	if (!(baselineStatus >= 200 && baselineStatus < 300) || baselineSoft) {
		return {
			detected: false, abortedByScope: false, blockReason: `基线请求状态 ${baselineStatus}${baselineSoft ? "（疑似 Soft-404 兜底页）" : ""} 不可用于差分对比`,
			baselineStatus, baselineSoft404: baselineSoft, vulnerableFields: [], cases: [], rollbackExecuted: false, rollbackOk: false,
			beliefObservation: { type: "soft404_miss", weight: 0.6, note: "基线响应不可信，探测安全终止" }, summary: "基线响应不可作为对照（非 2xx 或 Soft-404），已安全终止。", };
	}
	let rollbackExecuted = false; let rollbackOk = false;
	let rollbackTrace: StatefulStepTrace | undefined; let abortedByScope = false; let abortReason: string | undefined;
	try {
		for (const spec of opts.candidateFields ?? SW3_DEFAULT_MASS_FIELDS) {
			if (!spec || typeof spec.field !== "string" || spec.field.length === 0) continue;
			const w = await sw3RunStep(withBody({ ...baselineObj, [spec.field]: spec.value }), session, ctx, secrets);
			if (w.aborted || w.blocked) {
				abortedByScope = w.aborted; abortReason = w.trace?.blockReason ?? w.error ?? "写入步被策略阻断";
				break;
			}
			const r = opts.readStep ? await sw3RunStep(opts.readStep, session, ctx, secrets) : w;
			if (r.aborted || r.blocked) {
				abortedByScope = r.aborted; abortReason = r.trace?.blockReason ?? r.error ?? "读取步被策略阻断";
				break;
			}
			const text = r.body ?? ""; const json = r.json ?? sw3Json(text);
			const soft = detectSoft404({ status: r.status, body: text, headers: r.headers, path: readPathHint() }, soft404Baseline,).isSoft404;
			const similarity = computeTemplateSimilarity(baselineText, text, readPathHint()); let observed: unknown;
			try {
				observed = spec.expectedReadPath ? extractByJsonPath(json, spec.expectedReadPath) : undefined;
			} catch { observed = undefined; }
			if (observed === undefined) observed = sw3FindDeep(json, spec.field);
			const baselineValue = sw3FindDeep(baselineJson, spec.field);
			const result: MassAssignmentCaseResult = { field: spec.field, label: spec.label, bound: false,
				writeStatus: w.status, readStatus: r.status, isSoft404: soft, templateSimilarity: Number(similarity.toFixed(4)),
				observedValueRedacted: sw3RedactValue(spec.field, observed, secrets),
				baselineValueRedacted: sw3RedactValue(spec.field, baselineValue, secrets), writeTrace: sw3RedactTrace(w.trace, secrets),
				readTrace: opts.readStep ? sw3RedactTrace(r.trace, secrets) : undefined, };
			if (r.status >= 400) {
				result.suppressedReason = `读取状态 ${r.status} >= 400，未形成有效绑定证据`; cases.push(result);
				continue;
			}
			if (soft) {
				result.suppressedReason = "响应被判为 Soft-404 兜底页，疑似假成功"; cases.push(result);
				continue;
			}
			if (SW3_FIELD_REJECT_RE.test(text.slice(0, 4_000))) {
				result.suppressedReason = "响应命中未知字段/拒绝提示文本，字段未被服务端接受"; cases.push(result);
				continue;
			}
			if (observed === undefined || observed === null) {
				result.suppressedReason = `未在响应中找到字段 ${spec.field} 的期望值（模板相似度 ${similarity.toFixed(2)}）`; cases.push(result);
				continue;
			}
			if (!sw3DeepEq(observed, spec.value)) {
				result.suppressedReason = `字段 ${spec.field} 的实际值与注入值不一致`; cases.push(result);
				continue;
			}
			if (baselineValue !== undefined && sw3DeepEq(observed, baselineValue)) {
				result.suppressedReason = similarity >= threshold ? "响应与基线高度同构且字段值未变，判为静态回显" : "字段值与基线一致，未发生实际写入（仅高模板相似度的静态回显）"; cases.push(result);
				continue;
			}
			result.bound = true; vulnerableFields.push(spec.field); cases.push(result);
		}
	} catch (e) {
		abortReason = `探测过程异常：${sw3Err(e)}`;
	} finally {
		if (opts.rollbackStep) {
			rollbackExecuted = true;
			try {
				const rb = await sw3RunStep(opts.rollbackStep, session, ctx, secrets); rollbackTrace = sw3RedactTrace(rb.trace, secrets);
				rollbackOk = rb.ok && !rb.blocked && !rb.aborted && rb.status > 0 && rb.status < 400;
				if (rb.aborted) abortedByScope = true;
			} catch (e) { rollbackOk = false; abortReason = abortReason ?? `回滚执行异常：${sw3Err(e)}`; }
		}
	}
	const detected = vulnerableFields.length > 0;
	const beliefObservation: BeliefObservation = detected ? {
				type: "confirmed_hit", weight: 1.2, note: `Mass Assignment 绑定成功字段：${vulnerableFields.map((f) => scrubSecretsInText(f, secrets)).join(", ")}`, }
		: abortedByScope ? { type: "waf_block", weight: 1, note: abortReason ?? "探测过程被 Scope/分级策略阻断" }
			: { type: "partial_signal", weight: 0.4, note: abortReason ?? "未观察到字段绑定行为" };
	return {
		detected, abortedByScope, blockReason: abortReason, baselineStatus, baselineSoft404: baselineSoft, vulnerableFields, cases, rollbackExecuted,
		rollbackOk, rollbackTrace, beliefObservation, summary: detected
			? `检测到 ${vulnerableFields.length} 个可被越权绑定的字段：${vulnerableFields.join(", ")}`
			: abortedByScope ? `探测被策略阻断：${scrubSecretsInText(abortReason ?? "越界访问", secrets)}`
				: `共测试 ${cases.length} 个候选字段，未观察到有效绑定（含 ${cases.filter((c) => c.suppressedReason).length} 例噪音抑制）。`, };
}

/* ------------------- 四、二阶有状态工作流验证 ------------------- */

export interface SecondOrderAssertionSpec {
	expectedStatus?: number | number[]; bodyIncludes?: string[]; bodyRegex?: string; jsonPath?: string; expectedValue?: unknown;
	requireChangedFromBaseline?: boolean; }

export interface VerifySecondOrderWorkflowOptions {
	scope: ScopePolicy; writeSteps: StatefulWorkflowStep[]; intermediateSteps?: StatefulWorkflowStep[];
	verifySteps: StatefulWorkflowStep[]; cleanupSteps?: StatefulWorkflowStep[]; baselineReadStep?: StatefulWorkflowStep;
	verifyAssertion?: SecondOrderAssertionSpec; soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null;
	autoSampleSoft404?: boolean; negativeBaseline?: ResponseSnapshot | ResponseSnapshot[]; root?: string; mode?: Mode | string;
	state?: NuwaState; beliefGraph?: BeliefGraph; applyBeliefUpdate?: boolean; recordLedger?: boolean; vault?: SessionVault;
	role?: string; roleHeaders?: Record<string, Record<string, string>>; extraHeaders?: Record<string, string>;
	initialVars?: Record<string, string>; initialCookies?: Record<string, string>; fetchFn?: TrafficFetchFn; recorder?: TrafficRecorder;
	timeoutMs?: number; extraSecrets?: string[]; allowDestructive?: boolean; candidateFactId?: string; candidateTitle?: string; }

export interface SecondOrderVerifyRecommendation {
	key: `verify-vuln:${string}`; factId: string; phase: "vuln"; title: string; detail: string; priority: number; from: string[]; }

export interface SecondOrderWorkflowResult {
	verified: boolean; abortedByScope: boolean; brokenAtStep?: number; brokenPhase?: "write" | "intermediate" | "verify"; brokenStepId?: string;
	failureKind?: | "scope_blocked"
		| "tier_blocked"
		| "missing_var"
		| "auth_401"
		| "auth_403"
		| "http_404"
		| "soft_404"
		| "http_error"
		| "assertion_failed"
		| "false_positive_filtered"
		| "timeout"
		| "network_error"; reason: string; stepTraces: StatefulStepTrace[]; redactedVariables: Record<string, string>;
	cleanupExecuted: boolean; cleanupOk: boolean; cleanupTraces: StatefulStepTrace[]; candidateFact?: Fact;
	verifyRecommendation?: SecondOrderVerifyRecommendation; beliefObservation: BeliefObservation;
	beliefPropagation?: BeliefPropagationResult; }
function sw3StepId(step: StatefulWorkflowStep | undefined, idx: number): string {
	const raw = String(step?.id ?? step?.name ?? "").trim();
	return raw.length > 0 ? raw : `step-${idx}`;
}
function sw3ClassifyFailure(r: Sw3RunResult): { kind: Sw3FailureKind; reason: string } | null {
	const trace = r.trace; const errText = `${r.error ?? ""} ${trace?.error ?? ""} ${trace?.blockReason ?? ""}`.trim();
	if (r.aborted || trace?.abortedByScope === true) {
		return { kind: "scope_blocked", reason: errText || "请求被 Scope 策略阻断" };
	}
	if (r.blocked || trace?.blocked === true) {
		const tierBlocked = /L3|destructive|破坏|需授权|未授权/i.test(errText);
		return { kind: tierBlocked ? "tier_blocked" : "scope_blocked", reason: errText || "请求被动作分级策略阻断" };
	}
	if (SW3_MISSING_VAR_RE.test(errText)) return { kind: "missing_var", reason: errText || "存在未解析的模板变量" };
	if (trace?.timedOut === true) return { kind: "timeout", reason: errText || "请求超时" };
	if (r.status === 401) return { kind: "auth_401", reason: "验证链返回 401 未授权" };
	if (r.status === 403) return { kind: "auth_403", reason: "验证链返回 403 被拒绝" };
	if (r.status === 404) return { kind: "http_404", reason: "验证链返回 404 不存在" };
	if (r.status >= 400) return { kind: "http_error", reason: `验证链返回 HTTP ${r.status}` };
	if (!r.ok) return { kind: r.status > 0 ? "http_error" : "network_error", reason: errText || "请求未成功完成" };
	return null;
}
function sw3Snapshot(r: Sw3RunResult): ResponseSnapshot {
	const body = r.body ?? "";
	const snap: ResponseSnapshot = { statusCode: r.status, body: body.slice(0, 8_000), bodyBytes: body.length, headers: r.headers, };
	try {
		snap.bodySha256 = computeBodyHash(body).bodyHash;
	} catch {
		/* 哈希计算失败时省略字段 */
	}
	return snap;
}
function sw3CheckAssertion(spec: SecondOrderAssertionSpec | undefined,
	ctx: { status: number; text: string; json: unknown; baselineText: string; vars: Record<string, string> }, ): { ok: boolean; reason: string } {
	if (!spec) return { ok: true, reason: "未配置额外断言，末步 2xx 即视为通过" };
	const problems: string[] = [];
	if (spec.expectedStatus !== undefined) {
		const allowed = (Array.isArray(spec.expectedStatus) ? spec.expectedStatus : [spec.expectedStatus]).map((n) => Number(n));
		if (!allowed.includes(Number(ctx.status))) problems.push(`状态码 ${ctx.status} 不在期望集合 [${allowed.join(",")}]`);
	}
	for (const needle of spec.bodyIncludes ?? []) {
		const t = sw3Subst(String(needle), ctx.vars);
		if (t.length > 0 && !ctx.text.includes(t)) problems.push(`响应体缺少期望片段「${sw3Note(t, 60)}」`);
	}
	if (spec.bodyRegex) {
		try {
			if (!new RegExp(spec.bodyRegex, "i").test(ctx.text)) { problems.push(`响应体未命中正则 /${sw3Note(spec.bodyRegex, 80)}/`); }
		} catch { problems.push("verifyAssertion.bodyRegex 非法"); }
	}
	if (spec.jsonPath) {
		let actual: unknown;
		try {
			actual = extractByJsonPath(ctx.json, spec.jsonPath);
		} catch { actual = undefined; }
		if (actual === undefined) {
			const leaf = spec.jsonPath.split(/[.[\]]+/).filter((s) => s.length > 0).pop() ?? spec.jsonPath; actual = sw3FindDeep(ctx.json, leaf);
		}
		if (spec.expectedValue !== undefined) {
			if (!sw3DeepEq(actual, spec.expectedValue)) problems.push(`JSONPath ${spec.jsonPath} 的实际值与期望值不一致`);
		} else if (actual === undefined) { problems.push(`JSONPath ${spec.jsonPath} 未能提取到值`); }
	}
	if (spec.requireChangedFromBaseline) {
		if (!ctx.baselineText) problems.push("缺少基线读取步，无法判定二阶状态变化");
		else if (sw3Normalize(ctx.text) === sw3Normalize(ctx.baselineText)) { problems.push("验证响应与基线响应一致，未观察到二阶状态变化"); }
	}
	return problems.length === 0 ? { ok: true, reason: "断言全部通过" } : { ok: false, reason: problems.join("；") };
}
/**
 * 二阶有状态工作流验证：写 -> 中间依赖 -> 读验证 的完整链路，
 * 通过软 404、正向证据门与断言三重过滤压制假阳性，并在 finally 中无条件执行清理。
 */
export async function verifySecondOrderWorkflow(opts: VerifySecondOrderWorkflowOptions, ): Promise<SecondOrderWorkflowResult> {
	const root = opts.root ?? process.cwd(); const mode: Mode | string = opts.mode ?? "standard";
	const allowDestructive = opts.allowDestructive === true; const secrets = sw3Secrets(opts.extraSecrets);
	const session: Sw3Session = { vars: { ...(opts.initialVars ?? {}) }, cookies: { ...(opts.initialCookies ?? {}) }, };
	const ctx: Sw3RunCtx = { root, scope: opts.scope, mode, allowDestructive, vault: opts.vault, role: opts.role, roleHeaders: opts.roleHeaders,
		extraHeaders: opts.extraHeaders, fetchFn: opts.fetchFn, recorder: opts.recorder, extraSecrets: opts.extraSecrets,
		timeoutMs: sw3Timeout(opts.timeoutMs), };
	const writeSteps = opts.writeSteps ?? []; const intermediateSteps = opts.intermediateSteps ?? [];
	const verifySteps = opts.verifySteps ?? []; const cleanupSteps = opts.cleanupSteps ?? [];
	const stepTraces: StatefulStepTrace[] = []; const cleanupTraces: StatefulStepTrace[] = [];
	const queue: Array<{ step: StatefulWorkflowStep; phase: "write" | "intermediate" | "verify"; idx: number }> = [];
	let gIdx = 0;
	for (const s of writeSteps) queue.push({ step: s, phase: "write", idx: gIdx++ });
	for (const s of intermediateSteps) queue.push({ step: s, phase: "intermediate", idx: gIdx++ });
	for (const s of verifySteps) queue.push({ step: s, phase: "verify", idx: gIdx++ });
	const preflightTargets: Array<{
		step?: StatefulWorkflowStep; phase: "write" | "intermediate" | "verify"; idx: number;
	}> = [...queue.map((q) => ({ step: q.step, phase: q.phase, idx: q.idx })),
		...(opts.baselineReadStep ? [{ step: opts.baselineReadStep, phase: "write" as const, idx: -1 }] : []) ];
	for (const target of preflightTargets) {
		if (!target.step) continue;
		const verdict = sw3PreflightStep(target.step, opts.scope, mode, allowDestructive, session.vars);
		if (verdict.ok) continue;
		return {
			verified: false, abortedByScope: true, brokenAtStep: target.idx >= 0 ? target.idx : undefined, brokenPhase: target.idx >= 0 ? target.phase : undefined,
			brokenStepId: sw3StepId(target.step, target.idx), failureKind: verdict.tierBlocked ? "tier_blocked" : "scope_blocked",
			reason: `预检阻断：${verdict.reason ?? "超出授权范围"}`,
			stepTraces: [], redactedVariables: sw3RedactVars(session.vars, secrets), cleanupExecuted: false, cleanupOk: false,
			cleanupTraces: [], beliefObservation: { type: "waf_block", weight: 1, note: "预检阶段发现越界或未授权的写入/读取步骤，未发送任何请求", }, };
	}
	let soft404Baseline: Soft404BaselineInput | Soft404Baseline | null = opts.soft404Baseline ?? null;
	if (opts.soft404Baseline === undefined && opts.autoSampleSoft404 !== false) {
		const firstUrl = writeSteps[0]?.url ?? verifySteps[0]?.url ?? cleanupSteps[0]?.url; const origin = sw3Origin(firstUrl, session.vars);
		if (origin && hostAllowed(origin.host, opts.scope)) {
			try {
				const fetcher = sw3ScopedFetch(opts.fetchFn as unknown as Sw3FetchLike | undefined, opts.scope, mode, allowDestructive, opts.extraHeaders, secrets,);
				soft404Baseline = await sampleSoft404Baseline(origin.origin, fetcher as unknown as Parameters<typeof sampleSoft404Baseline>[1],
					{ headers: opts.extraHeaders, timeoutMs: Math.min(ctx.timeoutMs ?? 6_000, 6_000) },);
			} catch { soft404Baseline = null; }
		}
	}
	let abortedByScope = false; let cleanupExecuted = false; let cleanupOk = false; let verified = false; let reason = ""; let baselineText = "";
	let lastResult: Sw3RunResult | null = null; let lastPhase: "write" | "intermediate" | "verify" = "verify";
	let lastVerifyStep: StatefulWorkflowStep | undefined;
	let broken: { idx: number;
		phase: "write" | "intermediate" | "verify"; stepId: string; kind: Sw3FailureKind; reason: string;
	} | null = null;
	let assertionSummary = "";
	try {
		if (opts.baselineReadStep) {
			const br = await sw3RunStep(opts.baselineReadStep, session, ctx, secrets); const redactedBr = sw3RedactTrace(br.trace, secrets);
			if (redactedBr) stepTraces.push(redactedBr);
			if (br.aborted) abortedByScope = true;
			const brFail = sw3ClassifyFailure(br);
			if (brFail) {
				broken = { idx: -1, phase: "write", stepId: sw3StepId(opts.baselineReadStep, -1), kind: brFail.kind, reason: `基线读取失败：${brFail.reason}`, };
			} else { baselineText = br.body ?? ""; }
		}
		if (!broken) {
			for (const item of queue) {
				const r = await sw3RunStep(item.step, session, ctx, secrets); const redacted = sw3RedactTrace(r.trace, secrets);
				if (redacted) stepTraces.push(redacted);
				if (r.aborted) abortedByScope = true;
				const fail = sw3ClassifyFailure(r);
				if (fail) {
					broken = { idx: item.idx, phase: item.phase, stepId: sw3StepId(item.step, item.idx), kind: fail.kind, reason: fail.reason, };
					break;
				}
				lastResult = r; lastPhase = item.phase;
				if (item.phase === "verify") {
					lastVerifyStep = item.step;
					const soft = detectSoft404(
						{ status: r.status, body: r.body ?? "", headers: r.headers, path: sw3Path(item.step.url, session.vars) }, soft404Baseline,);
					if (soft.isSoft404) {
						broken = { idx: item.idx, phase: item.phase, stepId: sw3StepId(item.step, item.idx), kind: "soft_404", reason: "验证阶段响应命中 Soft-404 兜底页指纹", };
						break;
					}
				}
			}
		}
		if (!broken && lastResult && lastPhase === "verify") {
			const text = lastResult.body ?? ""; const json = lastResult.json ?? sw3Json(text);
			const assertion = sw3CheckAssertion(opts.verifyAssertion, { status: lastResult.status, text, json, baselineText, vars: session.vars, });
			assertionSummary = assertion.reason;
			if (!assertion.ok) {
				broken = { idx: queue.length > 0 ? queue[queue.length - 1].idx : -1,
					phase: "verify", stepId: sw3StepId(lastVerifyStep, queue.length - 1), kind: "assertion_failed", reason: assertion.reason, };
			} else {
				let gateOk = true; let gateReason = "";
				const hasExplicitContentAssertion = Boolean(
					(opts.verifyAssertion?.bodyIncludes?.length ?? 0) > 0 || opts.verifyAssertion?.bodyRegex || opts.verifyAssertion?.jsonPath,
				);
				try {
					const gate = evaluatePositiveEvidenceGate({ kind: "vuln", title: opts.candidateTitle ?? "二阶有状态工作流漏洞", detail: text.slice(0, 2_000),
						output: json !== undefined ? scrubSecretsInText(JSON.stringify(json), secrets).slice(0, 2_000) : undefined,
						response: sw3Snapshot(lastResult), baseline: opts.negativeBaseline,
						requireBusinessPayload: !hasExplicitContentAssertion, minBodyBytes: hasExplicitContentAssertion ? 8 : 64, });
					gateOk = gate.ok; gateReason = gate.reason ?? gate.reasons.join("；");
				} catch { gateOk = true; }
				if (!gateOk) {
					broken = { idx: queue.length > 0 ? queue[queue.length - 1].idx : -1, phase: "verify", stepId: sw3StepId(lastVerifyStep, queue.length - 1),
						kind: "false_positive_filtered", reason: gateReason || "正向证据门判定为假阳性", };
				} else { verified = true; reason = "二阶有状态链路验证通过，已通过软 404、正向证据门与断言三重过滤"; }
			}
		} else if (!broken && !lastResult) {
			broken = { idx: -1, phase: "verify", stepId: "empty-chain", kind: "assertion_failed", reason: "验证链为空，无可执行步骤", };
		} else if (!broken && lastResult && lastPhase !== "verify") {
			broken = { idx: queue.length > 0 ? queue[queue.length - 1].idx : -1,
				phase: lastPhase, stepId: sw3StepId(queue[queue.length - 1]?.step, queue.length - 1), kind: "assertion_failed", reason: "缺少 verifySteps，无法形成二阶状态验证", };
		}
	} catch (e) {
		const msg = `验证执行异常：${sw3Err(e)}`;
		if (!broken) {
			broken = { idx: queue.length > 0 ? queue[queue.length - 1].idx : -1,
				phase: lastPhase, stepId: sw3StepId(queue[queue.length - 1]?.step, queue.length - 1), kind: "network_error", reason: msg, };
		}
		reason = msg;
	} finally {
		if (cleanupSteps.length > 0) {
			cleanupExecuted = true;
			let allCleanOk = true;
			for (const cStep of cleanupSteps) {
				try {
					const cRes = await executeStatefulWorkflowChainInternal({ root, steps: [cStep], scope: opts.scope,
						mode, allowDestructive, vars: { ...session.vars }, role: opts.role,
						roleHeaders: opts.roleHeaders, extraHeaders: opts.extraHeaders, vault: opts.vault, fetchFn: opts.fetchFn,
						recorder: opts.recorder, initialCookies: { ...session.cookies }, extraSecrets: opts.extraSecrets, defaultTimeoutMs: ctx.timeoutMs, });
					for (const t of cRes.steps) {
						const redacted = sw3RedactTrace(t, secrets);
						if (redacted) cleanupTraces.push(redacted);
					}
					const stepOk = cRes.ok === true && cRes.blocked !== true && cRes.abortedByScope !== true &&
						cRes.steps.every((s) => !s.blocked && !s.abortedByScope && s.status > 0 && s.status < 400);
					if (!stepOk) allCleanOk = false;
					session.vars = { ...session.vars, ...(cRes.rawVariables ?? cRes.variables ?? {}) };
					session.cookies = { ...session.cookies, ...(cRes.rawCookies ?? cRes.cookies ?? {}) };
				} catch { allCleanOk = false; }
			}
			cleanupOk = allCleanOk;
		}
	}
	if (!verified && !reason) reason = broken?.reason ?? "未形成有效二阶状态证据";
	const beliefObservation: BeliefObservation = verified ? { type: "breakthrough_signal", weight: 1.3, note: "二阶有状态链路验证通过，可进入独立复验候选" }
		: broken?.kind === "auth_401" || broken?.kind === "auth_403"
			? { type: "waf_block", weight: 1, note: scrubSecretsInText(reason, secrets) }
			: broken?.kind === "soft_404" || broken?.kind === "http_404"
				? { type: "soft404_miss", weight: 0.6, note: scrubSecretsInText(reason, secrets) }
				: broken?.kind === "timeout" ? { type: "timeout", weight: 0.5, note: scrubSecretsInText(reason, secrets) }
					: { type: "verifier_reject", weight: 0.7, note: scrubSecretsInText(reason, secrets) };
	let candidateFact: Fact | undefined; let verifyRecommendation: SecondOrderVerifyRecommendation | undefined;
	if (verified) {
		const rawId = typeof opts.candidateFactId === "string" ? opts.candidateFactId.trim() : ""; const fid = rawId.length > 0 ? rawId : `vuln-${randomUUID()}`;
		const rawTitle = typeof opts.candidateTitle === "string" && opts.candidateTitle.trim().length > 0
				? opts.candidateTitle.trim() : "二阶有状态工作流漏洞";
		const safeTitle = scrubSecretsInText(rawTitle, secrets);
		candidateFact = { id: fid, kind: "vuln", title: safeTitle, detail: scrubSecretsInText(
				`写 ${writeSteps.length} / 中间 ${intermediateSteps.length} / 验证 ${verifySteps.length} 步链路验证通过。${assertionSummary}`,
				secrets,), createdAt: new Date().toISOString(), verified: false, verifyStage: "candidate", };
		verifyRecommendation = { key: `verify-vuln:${fid}`, factId: fid, phase: "vuln", title: `复验：${safeTitle}`,
			detail: scrubSecretsInText("二阶有状态链路验证已通过，请以独立身份与全新会话复验。", secrets), priority: 8, from: [`fact:${fid}`], };
	}
	let beliefPropagation: BeliefPropagationResult | undefined;
	if (opts.applyBeliefUpdate === true && opts.beliefGraph && opts.state) {
		const targetNodeId = candidateFact?.id ?? (typeof opts.candidateFactId === "string" ? opts.candidateFactId : "");
		if (targetNodeId) {
			try {
				const resolved = resolveBeliefNodeId(opts.beliefGraph, targetNodeId);
				if (resolved && opts.beliefGraph.nodes[resolved]) {
					beliefPropagation = propagateBeliefUpdate(opts.beliefGraph, opts.state, { nodeId: resolved, observation: beliefObservation, });
				}
			} catch {
				/* 节点不存在时静默跳过，不中断主流程 */
			}
		}
	}
	if (opts.recordLedger === true && root) {
		try {
			recordToolExecution(root, { tool: "nuwa_second_order_workflow", command: "verifySecondOrderWorkflow",
				output: sw3Note(scrubSecretsInText(`${reason} | verified=${verified}`, secrets), 500), ok: verified, } as Parameters<typeof recordToolExecution>[1]);
		} catch {
			/* 账本记录失败不影响主流程 */
		}
	}
	return {
		verified, abortedByScope, brokenAtStep: broken && broken.idx >= 0 ? broken.idx : undefined, brokenPhase: broken ? broken.phase : undefined,
		brokenStepId: broken ? broken.stepId : undefined, failureKind: broken ? broken.kind : undefined, reason: scrubSecretsInText(reason, secrets), stepTraces,
		redactedVariables: sw3RedactVars(session.vars, secrets), cleanupExecuted, cleanupOk, cleanupTraces,
		candidateFact, verifyRecommendation, beliefObservation, beliefPropagation, };
}

/* ============================================================================
 * 第三部分：同步屏障并发竞态探测。
 * BarrierGate 令全部 worker 在同一事件循环 tick 内同步放行，用于验证服务端
 * 对同一资源的并发操作是否存在竞态（TOCTOU / 重复扣减 / 重复核销）。
 * 任何对外输出（状态摘要、响应片段、错误文案、阻断原因）均零明文脱敏，
 * 敏感键一律替换为 REDACTED_MARKER。
 * ========================================================================== */

export const MAX_RACE_CONCURRENCY = 32 as const;

export type RaceTransportMode = "fetch" | "net";

export type RaceProbeClassification = | "race_confirmed"
	| "rate_limited"
	| "mutex_protected"
	| "no_success"
	| "scope_blocked";

export interface BarrierAwaitResult {
	released: boolean; timedOut: boolean; aborted: boolean; arrived: number; }

export interface BarrierRaceProbeOptions {
	scope: ScopePolicy; request: StatefulWorkflowStep; concurrency?: number; transport?: RaceTransportMode; fetchFn?: TrafficFetchFn;
	timeoutMs?: number; barrierTimeoutMs?: number; beforeReadStep?: StatefulWorkflowStep; afterReadStep?: StatefulWorkflowStep;
	numericFieldPath?: string; expectedSingleDelta?: number; maxExpectedSuccesses?: number; root?: string; mode?: Mode | string;
	vault?: SessionVault; role?: string; roleHeaders?: Record<string, Record<string, string>>; extraHeaders?: Record<string, string>;
	initialVars?: Record<string, string>; initialCookies?: Record<string, string>; extraSecrets?: string[]; allowDestructive?: boolean; }

export interface RaceWorkerOutcome {
	index: number; status: number; ok: boolean; timedOut: boolean; error?: string; durationMs: number; bodyHash: string;
	bodyBytes: number; redactedResponseSnippet: string; }

export interface BarrierRaceProbeResult {
	abortedByScope: boolean; blockReason?: string; requestedConcurrency: number; concurrency: number; transportUsed: RaceTransportMode;
	raceConditionDetected: boolean; classification: RaceProbeClassification; successCount: number; rateLimitedCount: number;
	conflictCount: number; otherRejectedCount: number; serverErrorCount: number; statusCounts: Record<string, number>;
	uniqueBodyHashes: string[]; beforeValue?: number; afterValue?: number; numericDelta?: number; numericAnomaly: boolean;
	resourcesCleaned: boolean; leakedSockets: number; leakedTimers: number; results: RaceWorkerOutcome[]; summary: string; }
type RaceBarrierState = "pending" | "released" | "timedout" | "aborted";
/** 同步屏障：全部协程到齐后在同一个 tick 内广播放行，保证并发同时起跑。 */
export class BarrierGate {
	private readonly parties: number; private readonly timeoutMs: number; private arrived = 0; private state: RaceBarrierState = "pending";
	private readonly waiters: Array<(result: BarrierAwaitResult) => void> = []; private timer: ReturnType<typeof setTimeout> | null = null;
	constructor(parties: number, timeoutMs = 5_000) {
		const count = Math.floor(Number(parties)); this.parties = Number.isFinite(count) && count > 0 ? count : 1;
		const limit = Math.floor(Number(timeoutMs)); this.timeoutMs = Number.isFinite(limit) && limit > 0 ? limit : 5_000;
	}
	public get arrivedCount(): number { return this.arrived; }
	public get isReleased(): boolean { return this.state === "released"; }
	public get pendingTimers(): number { return this.timer === null ? 0 : 1; }
	public arriveAndAwait(): Promise<BarrierAwaitResult> {
		if (this.state !== "pending") return Promise.resolve(this.snapshot());
		this.arrived += 1;
		if (this.arrived >= this.parties) {
			this.settle("released");
			return Promise.resolve(this.snapshot());
		}
		const promise = new Promise<BarrierAwaitResult>((resolve) => {
			this.waiters.push(resolve);
		});
		if (this.timer === null) {
			this.timer = setTimeout(() => {
				this.timer = null;
				if (this.state === "pending") this.settle("timedout");
			}, this.timeoutMs);
			const handle = this.timer as unknown as { unref?: () => void };
			if (typeof handle.unref === "function") {
				try {
					handle.unref();
				} catch {
					/* 忽略 unref 失败 */
				}
			}
		}
		return promise;
	}
	public abort(): void {
		if (this.state === "pending") this.settle("aborted");
		else this.clearTimer();
	}
	public dispose(): void { this.abort(); this.waiters.length = 0; }
	private snapshot(): BarrierAwaitResult {
		return {
			released: this.state === "released", timedOut: this.state === "timedout", aborted: this.state === "aborted", arrived: this.arrived, };
	}
	private clearTimer(): void {
		if (this.timer !== null) {
			try {
				clearTimeout(this.timer);
			} catch {
				/* 忽略清理失败 */
			}
			this.timer = null;
		}
	}
	private settle(next: Exclude<RaceBarrierState, "pending">): void {
		this.state = next; this.clearTimer(); const pending = this.waiters.splice(0, this.waiters.length); const result = this.snapshot();
		for (const resolve of pending) {
			try {
				resolve(result);
			} catch {
				/* 忽略单个 waiter 异常 */
			}
		}
	}
}

/* --------------------------- 文本 / 脱敏 / 数值工具 ------------------------ */
const RACE_REDACT_RE =
	/("?(?:authorization|proxy-authorization|set-cookie|cookie|x-api-key|x-auth-token|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|password|passwd|secret|session[_-]?id)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^,;\r\n}]{0,512})/gi;
const RACE_NUMERIC_KEY_RE = /balance|credits?|amount|stock|count|quota/i;
const RACE_NUMERIC_TEXT_RE = /"(?:balance|credits?|amount|stock|count|quota)"\s*:\s*(-?\d+(?:\.\d+)?)/i;
/** 零明文脱敏：先按采集到的密钥擦除，再对敏感键名做兜底替换，最后截断。 */
function raceRedactText(text: string, secrets: Set<string>, opts: BarrierRaceProbeOptions, limit = 600): string {
	if (!text) return "";
	let out = text.length > 4_000 ? text.slice(0, 4_000) : text;
	try {
		out = scrubSecretsInText(out, secrets, opts.root ?? opts.vault);
	} catch {
		/* 忽略擦除失败 */
	}
	out = out.replace(RACE_REDACT_RE, (_match: string, prefix: string) => `${prefix}${REDACTED_MARKER}`);
	return out.length > limit ? `${out.slice(0, limit)}…` : out;
}
function raceIsSoft404(body: string, status: number): boolean { try { return Boolean(body) && detectSoft404({ status, body }).isSoft404; } catch { return false; } }
function raceToBuffer(chunk: unknown): Buffer | undefined { return chunk instanceof Uint8Array ? Buffer.from(chunk) : typeof chunk === "string" ? Buffer.from(chunk, "utf8") : undefined; }

/* ------------------------------ HTTP/1.1 编解码 ---------------------------- */
interface RacePreparedStep {
	url: string; method: string; headers: Record<string, string>; body?: string; unresolved: string[]; }
interface RaceRawResponse {
	status: number; headers: Record<string, string>; body: Buffer; }
interface RaceScopeDecision {
	blocked: boolean; reason?: string; }
function raceBuildHttpRequest(url: URL, prepared: RacePreparedStep): string {
	const lines: string[] = [`${prepared.method} ${url.pathname || "/"}${url.search || ""} HTTP/1.1`, `Host: ${url.host}`, "Connection: close"];
	const seen = new Set<string>(["host", "connection", "content-length", "transfer-encoding"]);
	for (const [key, value] of Object.entries(prepared.headers)) {
		const lower = key.toLowerCase();
		if (seen.has(lower)) continue;
		seen.add(lower); lines.push(`${key}: ${String(value).replace(/[\r\n]+/g, " ")}`);
	}
	const body = prepared.body ?? ""; const hasBody = body.length > 0;
	if (hasBody) lines.push(`Content-Length: ${Buffer.byteLength(body, "utf8")}`);
	lines.push("", ""); const head = lines.join("\r\n");
	return hasBody ? `${head}${body}` : head;
}
function raceDecodeChunked(body: Buffer): Buffer {
	const parts: Buffer[] = []; let pos = 0;
	while (pos < body.length) {
		const lineEnd = body.indexOf("\r\n", pos, "latin1");
		if (lineEnd < 0) break;
		const sizeText = body.toString("latin1", pos, lineEnd).split(";")[0]?.trim() ?? ""; const size = Number.parseInt(sizeText, 16); pos = lineEnd + 2;
		if (!Number.isFinite(size) || size <= 0) break;
		const end = Math.min(body.length, pos + size); parts.push(body.subarray(pos, end)); pos = end + 2;
	}
	return parts.length > 0 ? Buffer.concat(parts) : Buffer.alloc(0);
}
function raceParseHttpResponse(raw: Buffer): RaceRawResponse | undefined {
	const headerEnd = raw.indexOf("\r\n\r\n", 0, "latin1");
	if (headerEnd < 0) return raw.length > 0 ? { status: 0, headers: {}, body: raw } : undefined;
	const lines = raw.toString("latin1", 0, headerEnd).split("\r\n"); const statusLine = lines.shift() ?? "";
	const matched = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(statusLine);
	const status = matched && matched[1] ? Number.parseInt(matched[1], 10) : 0;
	const headers: Record<string, string> = {};
	for (const line of lines) {
		const index = line.indexOf(":");
		if (index <= 0) continue;
		const key = line.slice(0, index).trim().toLowerCase(); const value = line.slice(index + 1).trim();
		if (!key) continue;
		headers[key] = headers[key] ? `${headers[key]}, ${value}` : value;
	}
	let body = raw.subarray(headerEnd + 4);
	if ((headers["transfer-encoding"] ?? "").toLowerCase().includes("chunked")) body = raceDecodeChunked(body);
	else {
		const length = Number.parseInt(headers["content-length"] ?? "", 10);
		if (Number.isFinite(length) && length >= 0 && length < body.length) body = body.subarray(0, length);
	}
	return { status, headers, body };
}
function raceExchange(socket: Socket, rawRequest: string, timeoutMs: number,
	activeTimers: Set<ReturnType<typeof setTimeout>>, onTimeout: () => void): Promise<RaceRawResponse> {
	return new Promise<RaceRawResponse>((resolve, reject) => {
		const chunks: Buffer[] = []; let total = 0; let settled = false; let timer: ReturnType<typeof setTimeout> | undefined;
		const clearTimer = (): void => {
			if (timer === undefined) return;
			try {
				clearTimeout(timer);
			} catch {
				/* 忽略 */
			}
			activeTimers.delete(timer); timer = undefined;
		};
		const finish = (fn: () => void): void => {
			if (settled) return;
			settled = true; clearTimer(); fn();
		};
		const done = (): void => {
			finish(() => {
				const parsed = raceParseHttpResponse(Buffer.concat(chunks, total));
				if (parsed) resolve(parsed);
				else reject(new Error("无法解析 HTTP 响应"));
			});
		};
		timer = setTimeout(() => {
			onTimeout(); finish(() => reject(new Error("响应读取超时")));
		}, timeoutMs);
		activeTimers.add(timer);
		socket.on("data", (chunk: unknown) => {
			const bytes = raceToBuffer(chunk);
			if (!bytes) return;
			if (total < 1_048_576) { chunks.push(bytes); total += bytes.length; }
		});
		socket.on("error", (err: unknown) => {
			finish(() => reject(err instanceof Error ? err : new Error(String(err))));
		});
		socket.on("end", done); socket.on("close", done);
		try {
			socket.write(rawRequest);
		} catch (err) { finish(() => reject(err instanceof Error ? err : new Error(String(err)))); }
	});
}

/* ------------------------- 步骤准备 / 作用域 / 密钥采集 ---------------------- */
function raceScopeDecision(raw: { ok: boolean; reason?: string }): RaceScopeDecision { return { blocked: !raw.ok, reason: raw.reason ?? (raw.ok ? undefined : "Scope 校验拒绝") }; }
function raceMergeHeaders(step: StatefulWorkflowStep, opts: BarrierRaceProbeOptions, role: string | undefined): Record<string, string> {
	const merged: Record<string, string> = {};
	const push = (source?: Record<string, string>): void => {
		if (!source) return;
		for (const [key, value] of Object.entries(source)) if (typeof value === "string") merged[key] = value;
	};
	push(step.headers);
	if (role) push(opts.roleHeaders?.[role]);
	push(opts.extraHeaders);
	return merged;
}
function racePrepareStep(step: StatefulWorkflowStep, opts: BarrierRaceProbeOptions,
	vars: Record<string, string>, role: string | undefined): RacePreparedStep {
	const unresolved: string[] = [];
	const interpolate = (text: string): string => {
		const result = interpolateTemplate(text, vars);
		if (Array.isArray(result.unresolved)) for (const item of result.unresolved) unresolved.push(String(item));
		return typeof result.value === "string" ? result.value : text;
	};
	const headers: Record<string, string> = {};
	for (const [key, value] of Object.entries(raceMergeHeaders(step, opts, role))) headers[key] = interpolate(value);
	let body: string | undefined;
	try {
		if (typeof step.body === "string") body = interpolate(step.body);
		else if (step.body && typeof step.body === "object") body = interpolate(JSON.stringify(step.body));
	} catch { body = undefined; }
	const prepared: RacePreparedStep = { url: interpolate(step.url), method: (step.method ?? "GET").toUpperCase(), headers, unresolved, };
	if (body !== undefined) prepared.body = body;
	return prepared;
}
function raceValidateStep(prepared: RacePreparedStep, opts: BarrierRaceProbeOptions): RaceScopeDecision {
	let parsed: URL;
	try {
		parsed = new URL(prepared.url);
	} catch {
		return { blocked: true, reason: "目标 URL 非法" };
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { blocked: true, reason: "仅支持 http/https 协议" };
	try {
		const raw = validateUrlAndActionScope(prepared.url, prepared.method, prepared.body, opts.scope, opts.mode ?? "standard", opts.allowDestructive === true);
		return raceScopeDecision(raw);
	} catch (err) {
		return { blocked: true, reason: err instanceof Error ? err.message : "作用域校验异常" };
	}
}
function raceCollectSecrets(opts: BarrierRaceProbeOptions, vars: Record<string, string>,
	cookies: Record<string, string>, headerSets: Array<Record<string, string>>): Set<string> {
	let secrets: Set<string>;
	try {
		secrets = collectSecretSet({ root: opts.root, vault: opts.vault, extraSecrets: opts.extraSecrets, vars, cookies, role: undefined } as {
			root?: string; vault?: SessionVault; extraSecrets?: string[]; vars?: Record<string, string>;
			cookies?: Record<string, string>; });
	} catch { secrets = new Set<string>(); }
	if (!(secrets instanceof Set)) secrets = new Set<string>();
	const add = (value: unknown): void => {
		if (typeof value !== "string") return;
		const trimmed = value.trim();
		if (trimmed.length >= 4) secrets.add(trimmed);
	};
	for (const [key, value] of Object.entries(vars)) if (isSensitiveKeyName(key)) add(value);
	for (const value of Object.values(cookies)) add(value);
	for (const set of headerSets) { for (const [key, value] of Object.entries(set)) if (isSensitiveKeyName(key)) add(value); }
	if (opts.extraSecrets) for (const value of opts.extraSecrets) add(value);
	return secrets;
}
function raceExtractNumeric(value: unknown, path: string | undefined): number | undefined {
	if (value === undefined || value === null) return undefined;
	if (path) {
		try {
			const extracted = extractByJsonPath(value, path); const num = typeof extracted === "number" ? extracted : Number(extracted);
			if (Number.isFinite(num)) return num;
		} catch {
			/* 忽略提取失败 */
		}
	}
	const visit = (node: unknown, depth: number): number | undefined => {
		if (depth > 4 || node === null || node === undefined) return undefined;
		if (typeof node === "number" && Number.isFinite(node)) return node;
		if (typeof node === "string") {
			const num = Number(node.trim());
			return Number.isFinite(num) ? num : undefined;
		}
		if (Array.isArray(node)) {
			for (const item of node) {
				const found = visit(item, depth + 1);
				if (found !== undefined) return found;
			}
			return undefined;
		}
		if (typeof node === "object") {
			const record = node as Record<string, unknown>;
			for (const [key, child] of Object.entries(record)) {
				if (!RACE_NUMERIC_KEY_RE.test(key)) continue;
				const found = visit(child, depth + 1);
				if (found !== undefined) return found;
			}
			for (const child of Object.values(record)) {
				const found = visit(child, depth + 1);
				if (found !== undefined) return found;
			}
		}
		return undefined;
	};
	return visit(value, 0);
}
function raceExtractNumericFromBody(bodyText: string | undefined, path: string | undefined): number | undefined {
	if (!bodyText) return undefined;
	const trimmed = bodyText.trim();
	if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
		const parsed = tryParseJson(trimmed) as unknown;
		if (parsed !== undefined && parsed !== null) {
			const found = raceExtractNumeric(parsed, path);
			if (found !== undefined) return found;
		}
	}
	const match = RACE_NUMERIC_TEXT_RE.exec(bodyText);
	if (match && match[1]) {
		const num = Number(match[1]);
		if (Number.isFinite(num)) return num;
	}
	if (path) {
		const direct = Number(trimmed);
		if (Number.isFinite(direct)) return direct;
	}
	return undefined;
}
interface RaceReadStepResult {
	blocked: boolean; reason?: string; bodyText?: string; }
async function raceRunReadStep(step: StatefulWorkflowStep, opts: BarrierRaceProbeOptions,
	vars: Record<string, string>, cookies: Record<string, string>, secrets: Set<string>): Promise<RaceReadStepResult> {
	try {
		const result = await executeStatefulWorkflowChainInternal({ root: opts.root ?? process.cwd(),
			steps: [step], scope: opts.scope, mode: opts.mode, allowDestructive: opts.allowDestructive,
			vars, role: opts.role, roleHeaders: opts.roleHeaders, extraHeaders: opts.extraHeaders,
			vault: opts.vault, fetchFn: opts.fetchFn, initialCookies: cookies, extraSecrets: opts.extraSecrets,
			recordTraffic: false, defaultTimeoutMs: opts.timeoutMs, });
		if (result.abortedByScope || result.blocked) {
			return { blocked: true, reason: raceRedactText(result.error ?? "作用域阻断", secrets, opts, 300) };
		}
		return { blocked: false, bodyText: result.rawStepBodies?.[0] ?? result.rawLastResponseBody };
	} catch (err) {
		return { blocked: true, reason: raceRedactText(err instanceof Error ? err.message : String(err), secrets, opts, 300) };
	}
}
function raceScopeBlockedResult(reason: string, requestedConcurrency: number, concurrency: number,
	transportUsed: RaceTransportMode, secrets: Set<string>, opts: BarrierRaceProbeOptions): BarrierRaceProbeResult {
	const safeReason = raceRedactText(reason, secrets, opts, 500);
	return {
		abortedByScope: true, blockReason: safeReason, requestedConcurrency, concurrency,
		transportUsed, raceConditionDetected: false, classification: "scope_blocked", successCount: 0,
		rateLimitedCount: 0, conflictCount: 0, otherRejectedCount: 0, serverErrorCount: 0,
		statusCounts: {}, uniqueBodyHashes: [], numericAnomaly: false, resourcesCleaned: true,
		leakedSockets: 0, leakedTimers: 0, results: [], summary: `已阻断：${safeReason}`, };
}
interface RaceFetchInit {
	method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal: AbortSignal; }
interface RaceFetchLikeResponse {
	status: number; text(): Promise<string>; }
type RaceFetchLike = (url: string, init: RaceFetchInit) => Promise<RaceFetchLikeResponse>;

/* --------------------------------- 主入口 -------------------------------- */

export async function runBarrierRaceProbe(opts: BarrierRaceProbeOptions): Promise<BarrierRaceProbeResult> {
	const requestedConcurrency = opts.concurrency ?? 8;
	const concurrency = Math.min(MAX_RACE_CONCURRENCY, Math.max(1, Math.floor(Number.isFinite(requestedConcurrency) ? requestedConcurrency : 8)));
	const timeoutMs = Math.max(10, Math.floor(Number(opts.timeoutMs) || 10_000));
	const barrierTimeoutMs = Math.max(10, Math.floor(Number(opts.barrierTimeoutMs) || 5_000));
	const vars: Record<string, string> = { ...(opts.initialVars ?? {}) };
	const cookies: Record<string, string> = { ...(opts.initialCookies ?? {}) };
	const headerSets: Array<Record<string, string>> = []; let transportUsed: RaceTransportMode = opts.transport ?? (opts.fetchFn ? "fetch" : "net");
	const mainPrepared = racePrepareStep(opts.request, opts, vars, opts.role); headerSets.push(mainPrepared.headers);
	const mainDecision = raceValidateStep(mainPrepared, opts);
	if (mainDecision.blocked) {
		const secrets = raceCollectSecrets(opts, vars, cookies, headerSets);
		return raceScopeBlockedResult(mainDecision.reason ?? "主请求作用域校验未通过", requestedConcurrency, concurrency, transportUsed, secrets, opts);
	}
	let beforePrepared: RacePreparedStep | undefined;
	if (opts.beforeReadStep) {
		beforePrepared = racePrepareStep(opts.beforeReadStep, opts, vars, opts.role); headerSets.push(beforePrepared.headers);
		const decision = raceValidateStep(beforePrepared, opts);
		if (decision.blocked) {
			const secrets = raceCollectSecrets(opts, vars, cookies, headerSets);
			return raceScopeBlockedResult(decision.reason ?? "前置读取步骤作用域校验未通过", requestedConcurrency, concurrency, transportUsed, secrets, opts);
		}
	}
	let afterPrepared: RacePreparedStep | undefined;
	if (opts.afterReadStep) {
		afterPrepared = racePrepareStep(opts.afterReadStep, opts, vars, opts.role); headerSets.push(afterPrepared.headers);
		const decision = raceValidateStep(afterPrepared, opts);
		if (decision.blocked) {
			const secrets = raceCollectSecrets(opts, vars, cookies, headerSets);
			return raceScopeBlockedResult(decision.reason ?? "后置读取步骤作用域校验未通过", requestedConcurrency, concurrency, transportUsed, secrets, opts);
		}
	}
	const secrets = raceCollectSecrets(opts, vars, cookies, headerSets);
	try {
		const url = new URL(mainPrepared.url);
		if (url.protocol === "https:" && !opts.fetchFn) transportUsed = "fetch";
	} catch {
		/* 已校验，忽略 */
	}
	let beforeValue: number | undefined;
	if (beforePrepared) {
		const read = await raceRunReadStep(opts.beforeReadStep as StatefulWorkflowStep, opts, vars, cookies, secrets);
		if (read.blocked) { return raceScopeBlockedResult(read.reason ?? "前置读取被作用域阻断", requestedConcurrency, concurrency, transportUsed, secrets, opts); }
		beforeValue = raceExtractNumericFromBody(read.bodyText, opts.numericFieldPath);
	}
	const results: RaceWorkerOutcome[] = []; const activeSockets = new Set<Socket>();
	const activeTimers = new Set<ReturnType<typeof setTimeout>>(); const gate = new BarrierGate(concurrency, barrierTimeoutMs);
	let leakedSockets = 0; let leakedTimers = 0; let resourcesCleaned = false;
	try {
		if (transportUsed === "net") {
			const workers = Array.from({ length: concurrency }, (_, index) => (async (): Promise<RaceWorkerOutcome> => {
				const started = Date.now(); let socket: Socket | undefined; let connectTimer: ReturnType<typeof setTimeout> | undefined;
				try {
					const url = new URL(mainPrepared.url); const port = Number(url.port) || (url.protocol === "https:" ? 443 : 80);
					socket = await new Promise<Socket>((resolve, reject) => {
						const s = connect({ host: url.hostname, port }, () => resolve(s));
						activeSockets.add(s);
						connectTimer = setTimeout(() => {
							try {
								s.destroy();
							} catch {
								/* 忽略 */
							}
							reject(new Error("连接超时"));
						}, timeoutMs);
						activeTimers.add(connectTimer); s.once("error", (err: unknown) => reject(err instanceof Error ? err : new Error(String(err))));
					});
					if (connectTimer !== undefined) { clearTimeout(connectTimer); activeTimers.delete(connectTimer); connectTimer = undefined; }
					const barrier = await gate.arriveAndAwait();
					if (barrier.aborted) throw new Error("屏障已中止");
					if (barrier.timedOut) throw new Error("屏障超时");
					const response = await raceExchange(socket, raceBuildHttpRequest(url, mainPrepared), timeoutMs, activeTimers, () => {
							if (!socket) return;
							try {
								socket.destroy();
							} catch {
								/* 忽略 */
							}
						});
					const bodyText = response.body.toString("utf8"); const bodyInfo = computeBodyHash(response.body);
					const ok = response.status >= 200 && response.status < 300 && !raceIsSoft404(bodyText, response.status);
					return { index, status: response.status, ok, timedOut: false, error: undefined,
						durationMs: Date.now() - started, bodyHash: bodyInfo.bodyHash, bodyBytes: bodyInfo.bodyBytes,
						redactedResponseSnippet: raceRedactText(bodyText, secrets, opts, 400) };
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					return { index, status: 0, ok: false, timedOut: message.includes("超时"),
						error: raceRedactText(message, secrets, opts, 300), durationMs: Date.now() - started, bodyHash: "", bodyBytes: 0, redactedResponseSnippet: "" };
				} finally {
					if (connectTimer !== undefined) {
						try {
							clearTimeout(connectTimer);
						} catch {
							/* 忽略 */
						}
						activeTimers.delete(connectTimer);
					}
					if (socket) {
						try {
							if (!socket.destroyed) socket.destroy();
						} catch {
							/* 忽略 */
						}
						activeSockets.delete(socket);
					}
				}
			})());
			results.push(...(await Promise.all(workers)));
		} else {
			const rawFetch = opts.fetchFn ?? (globalThis.fetch as unknown as TrafficFetchFn | undefined);
			if (!rawFetch) {
				results.push({ index: 0, status: 0, ok: false, timedOut: false, error: "无可用 fetch 实现",
					durationMs: 0, bodyHash: "", bodyBytes: 0, redactedResponseSnippet: "" });
			} else {
				const fetchFn = rawFetch as unknown as RaceFetchLike;
				const workers = Array.from({ length: concurrency }, (_, index) => (async (): Promise<RaceWorkerOutcome> => {
					const started = Date.now(); let workerTimer: ReturnType<typeof setTimeout> | undefined; let controller: AbortController | undefined;
					try {
						const barrier = await gate.arriveAndAwait();
						if (barrier.aborted) throw new Error("屏障已中止");
						if (barrier.timedOut) throw new Error("屏障超时");
						controller = new AbortController();
						workerTimer = setTimeout(() => {
							try {
								controller?.abort();
							} catch {
								/* 忽略 */
							}
						}, timeoutMs);
						activeTimers.add(workerTimer);
						const init: RaceFetchInit = { method: mainPrepared.method, headers: mainPrepared.headers, redirect: "manual", signal: controller.signal };
						if (mainPrepared.body !== undefined) init.body = mainPrepared.body;
						const response = await fetchFn(mainPrepared.url, init); const text = await response.text();
						const bodyInfo = computeBodyHash(Buffer.from(text, "utf8"));
						const ok = response.status >= 200 && response.status < 300 && !raceIsSoft404(text, response.status);
						return { index, status: response.status, ok, timedOut: false, error: undefined,
							durationMs: Date.now() - started, bodyHash: bodyInfo.bodyHash, bodyBytes: bodyInfo.bodyBytes,
							redactedResponseSnippet: raceRedactText(text, secrets, opts, 400) };
					} catch (err) {
						const message = err instanceof Error ? err.message : String(err);
						const timedOut = err instanceof Error && (err.name === "AbortError" || message.includes("超时"));
						return { index, status: 0, ok: false, timedOut, error: raceRedactText(message, secrets, opts, 300), durationMs: Date.now() - started,
							bodyHash: "", bodyBytes: 0, redactedResponseSnippet: "" };
					} finally {
						if (workerTimer !== undefined) {
							try {
								clearTimeout(workerTimer);
							} catch {
								/* 忽略 */
							}
							activeTimers.delete(workerTimer);
						}
					}
				})());
				results.push(...(await Promise.all(workers)));
			}
		}
	} finally {
		for (const timer of Array.from(activeTimers)) {
			try {
				clearTimeout(timer);
			} catch {
				/* 忽略 */
			}
			activeTimers.delete(timer);
		}
		for (const socket of Array.from(activeSockets)) {
			try {
				if (!socket.destroyed) socket.destroy();
			} catch {
				/* 忽略 */
			}
			activeSockets.delete(socket);
		}
		gate.dispose(); leakedSockets = activeSockets.size;
		leakedTimers = activeTimers.size + gate.pendingTimers; resourcesCleaned = leakedSockets === 0 && leakedTimers === 0;
	}
	let afterValue: number | undefined;
	if (afterPrepared) {
		const read = await raceRunReadStep(opts.afterReadStep as StatefulWorkflowStep, opts, vars, cookies, secrets);
		if (!read.blocked) afterValue = raceExtractNumericFromBody(read.bodyText, opts.numericFieldPath);
	}
	const statusCounts: Record<string, number> = {};
	const uniqueBodyHashes = new Set<string>(); let successCount = 0; let rateLimitedCount = 0; let conflictCount = 0;
	let otherRejectedCount = 0; let serverErrorCount = 0;
	for (const r of results) {
		const key = String(r.status); statusCounts[key] = (statusCounts[key] ?? 0) + 1;
		if (r.bodyHash) uniqueBodyHashes.add(r.bodyHash);
		if (r.ok) successCount += 1;
		else if (r.status === 429) rateLimitedCount += 1; else if (r.status === 409 || r.status === 423) conflictCount += 1;
		else if (r.status >= 500 && r.status < 600) serverErrorCount += 1; else if (r.status > 0) otherRejectedCount += 1;
	}
	let numericDelta: number | undefined;
	if (beforeValue !== undefined && afterValue !== undefined) numericDelta = afterValue - beforeValue;
	let numericAnomaly = false;
	if (beforeValue !== undefined && afterValue !== undefined && opts.expectedSingleDelta !== undefined) {
		const expected = opts.expectedSingleDelta;
		if (Math.abs(numericDelta ?? 0) > Math.abs(expected) + 1e-6 || (expected < 0 && afterValue < 0)) numericAnomaly = true;
	}
	const maxAllowed = Math.max(1, opts.maxExpectedSuccesses ?? 1); let raceConditionDetected = false;
	let classification: RaceProbeClassification = "no_success";
	if (successCount > maxAllowed || numericAnomaly) {
		raceConditionDetected = true; classification = "race_confirmed";
	} else if (rateLimitedCount > 0 && conflictCount === 0) classification = "rate_limited";
	else if (conflictCount > 0) classification = "mutex_protected"; else if (rateLimitedCount > 0) classification = "rate_limited";
	else classification = successCount > 0 ? "mutex_protected" : "no_success";
	const summary = raceRedactText(
		`并发 ${concurrency} 次，成功 ${successCount}，限流 ${rateLimitedCount}，冲突 ${conflictCount}，其他拒绝 ${otherRejectedCount}，5xx ${serverErrorCount}；分类 ${classification}`,
		secrets, opts, 500);
	return {
		abortedByScope: false, requestedConcurrency, concurrency, transportUsed, raceConditionDetected, classification, successCount, rateLimitedCount,
		conflictCount, otherRejectedCount, serverErrorCount, statusCounts, uniqueBodyHashes: Array.from(uniqueBodyHashes), beforeValue, afterValue, numericDelta,
		numericAnomaly, resourcesCleaned, leakedSockets, leakedTimers, results, summary, };
}
