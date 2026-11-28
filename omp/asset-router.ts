/**
 * 女娲 v7.0 资产路由编排器（Asset Router）。
 *
 * 职责：
 * 1. `verifyCredentialPivot`：跨候选目标的多角色凭据复用复验——
 *    双闸范围护栏（`isHostInScope` + `checkScopeAndRisk`）→ 无认证基线探测 →
 *    软 404（`detectSoft404`）判定 → 零明文脱敏输出。
 * 2. `resolveAssetRoutePlan`：多资产 `reachableVia` 拓扑解析，成环检测、直连 / 出口代理 /
 *    `socks5h://` 隧道选路与凭据绑定元数据传播。
 * 3. `probeViaConfirmedSsrf`：仅对 `verifyStage === "confirmed"` 的 SSRF 事实做内网可达性探测，
 *    含负向基线（canary）比对，并将可达目标落地为干净 `AssetNode`。
 *
 * 约束：
 * - 严禁运行时导入 `./nuwa`（避免循环依赖）；
 * - `./types`、`./hypothesis` 仅使用 `import type`；
 * - 任何返回的摘要 / 证据 / 头部快照 / URL 中绝不出现明文凭据。
 */
import { createHash, randomBytes } from "node:crypto";
import { checkScopeAndRisk, isHostInScope } from "./scope";
import { redactVaultSecrets } from "./session-vault";
import { computeBodyHash, computeTemplateFingerprint, detectSoft404 } from "./autoexec";
import { redactTrafficBody, redactTrafficHeaders, redactTrafficUrl } from "./traffic-workbench";
import type { UpsertAssetInput } from "./hypothesis";
import type { AssetNode, Fact, Mode, ScopePolicy } from "./types";

export const ASSET_ROUTER_VERSION = "7.0.0";

/* ------------------------------------------------------------------ *
 * 通用常量与基础工具
 * ------------------------------------------------------------------ */

const DEFAULT_TIMEOUT_MS = 8000;
const MIN_TIMEOUT_MS = 500;
const MAX_TIMEOUT_MS = 120000;
const MIN_BODY_DELTA = 24;
const VALID_DIFF_SCORE = 50;
const REDACTED = "[REDACTED]";

const KNOWN_HEADERS = [
	"content-type",
	"content-length",
	"location",
	"set-cookie",
	"www-authenticate",
	"server",
	"x-powered-by",
	"x-nextjs-matched-path",
];

function nowIso(): string {
	return new Date().toISOString();
}

function sha256(input: string): string {
	return createHash("sha256").update(input, "utf8").digest("hex");
}

function shortHash(input: string, len = 10): string {
	return sha256(String(input ?? "")).slice(0, Math.max(4, len));
}

function oneLine(input: unknown, max = 200): string {
	return String(input ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

function slugKey(raw: string): string {
	return (
		String(raw ?? "")
			.trim()
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 48) || "item"
	);
}

function uniq(items: Iterable<string>): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const raw of items) {
		const s = String(raw ?? "").trim();
		if (!s || seen.has(s)) continue;
		seen.add(s);
		out.push(s);
	}
	return out;
}

function stripCrlf(value: string): string {
	return String(value ?? "").replace(/[\r\n]+/g, " ").trim();
}

function normalizeTimeout(input?: number): number {
	if (typeof input !== "number" || !Number.isFinite(input)) return DEFAULT_TIMEOUT_MS;
	return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.trunc(input)));
}

function readString(source: unknown, key: string): string | undefined {
	if (!source || typeof source !== "object") return undefined;
	const value = (source as Record<string, unknown>)[key];
	return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readStringArray(source: unknown, key: string): string[] {
	if (!source || typeof source !== "object") return [];
	const value = (source as Record<string, unknown>)[key];
	if (typeof value === "string") return value.trim() ? [value.trim()] : [];
	if (Array.isArray(value)) {
		return value
			.filter((item): item is string => typeof item === "string")
			.map((item) => item.trim())
			.filter(Boolean);
	}
	return [];
}

/* ------------------------------------------------------------------ *
 * 主机 / IP / CIDR 判定
 * ------------------------------------------------------------------ */

function hostKey(host: string): string {
	return String(host ?? "")
		.trim()
		.toLowerCase()
		.replace(/^\[/, "")
		.replace(/\]$/, "");
}

function parseIpv4(raw: string): number | null {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostKey(raw));
	if (!m) return null;
	let acc = 0;
	for (let i = 1; i <= 4; i++) {
		const part = m[i] ?? "";
		if (!part) return null;
		if (part.length > 1 && part.startsWith("0")) return null;
		const n = Number(part);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		acc = ((acc << 8) | n) >>> 0;
	}
	return acc >>> 0;
}

function parseCidr(raw: string): { net: number; mask: number; prefix: number } | null {
	const text = String(raw ?? "").trim();
	const slash = text.indexOf("/");
	if (slash <= 0) return null;
	const ip = parseIpv4(text.slice(0, slash));
	const prefix = Number(text.slice(slash + 1));
	if (ip === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return { net: (ip & mask) >>> 0, mask, prefix };
}

function cidrContainsCidr(rawCidr: string, host: string): boolean {
	const cidr = parseCidr(rawCidr);
	if (!cidr) return false;
	const direct = parseIpv4(host);
	if (direct !== null) return ((direct & cidr.mask) >>> 0) === cidr.net;
	return false;
}

function isPrivateHost(host: string): boolean {
	const h = hostKey(host);
	if (!h) return false;
	if (h === "localhost" || h.endsWith(".localhost") || h === "::1" || h === "0.0.0.0") return true;
	if (/\.(?:local|internal|lan|corp|intranet|intra|priv|private|home|localdomain|htb|thm|lab|box)$/.test(h)) {
		return true;
	}
	const ip = parseIpv4(h);
	if (ip === null) return false;
	const b0 = (ip >>> 24) & 0xff;
	const b1 = (ip >>> 16) & 0xff;
	if (b0 === 0 || b0 === 10 || b0 === 127) return true;
	if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
	if (b0 === 192 && b1 === 168) return true;
	if (b0 === 169 && b1 === 254) return true;
	if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
	return false;
}

/* ------------------------------------------------------------------ *
 * 目标 URL 构造
 * ------------------------------------------------------------------ */

export interface RouteTargetInput {
	host: string;
	port?: number;
	scheme?: string;
	path?: string;
	assetId?: string;
}

interface BuiltTarget {
	url: string;
	host: string;
	port?: number;
	scheme: string;
	path: string;
}

function defaultScheme(port?: number): string {
	if (port === 443 || port === 8443 || port === 9443) return "https";
	return "http";
}

function sanitizePath(rawPath?: string): string {
	const raw = String(rawPath ?? "").trim();
	if (!raw) return "/";
	const noHash = (raw.split("#")[0] ?? "").replace(/[\u0000-\u001f]/g, "");
	if (!noHash) return "/";
	const prefixed = noHash.startsWith("/") ? noHash : `/${noHash}`;
	return prefixed || "/";
}

function builtTargetLabel(input: RouteTargetInput): string {
	const host = hostKey(input.host) || "unknown";
	const port = typeof input.port === "number" ? `:${input.port}` : "";
	const scheme = String(input.scheme ?? "").trim().toLowerCase() || defaultScheme(input.port);
	return `${scheme}://${host}${port}${sanitizePath(input.path)}`;
}

function buildTargetUrl(input: RouteTargetInput): BuiltTarget | { error: string } {
	const rawHost = String(input.host ?? "").trim();
	if (!rawHost) return { error: "目标主机为空" };
	if (rawHost.includes("://")) return { error: `非法主机（禁止携带协议前缀）: ${rawHost}` };
	if (/[@\s\\]/.test(rawHost)) return { error: `非法主机（含保留字符）: ${rawHost}` };

	const plainHost = hostKey(rawHost);
	if (!plainHost) return { error: "目标主机为空" };

	const port =
		typeof input.port === "number" && Number.isInteger(input.port) && input.port >= 1 && input.port <= 65535
			? input.port
			: undefined;

	const rawScheme = String(input.scheme ?? "").trim().toLowerCase();
	const scheme = rawScheme === "https" ? "https" : rawScheme === "http" ? "http" : defaultScheme(port);
	const path = sanitizePath(input.path);

	let urlHost = plainHost;
	if (urlHost.includes(":") && !urlHost.startsWith("[")) urlHost = `[${urlHost}]`;
	const authority = port ? `${urlHost}:${port}` : urlHost;
	const candidate = `${scheme}://${authority}${path}`;

	try {
		const parsed = new URL(candidate);
		return { url: parsed.toString(), host: plainHost, port, scheme, path };
	} catch {
		return { error: `无法构造合法目标 URL: ${candidate}` };
	}
}

/* ------------------------------------------------------------------ *
 * 零明文脱敏工具
 * ------------------------------------------------------------------ */

function collectCredentialSecrets(credentials: readonly CredentialSpec[]): string[] {
	const out: string[] = [];
	const push = (raw: string | undefined): void => {
		const s = String(raw ?? "").trim();
		if (s.length < 4) return;
		out.push(s);
		const bare = s.replace(/^(?:Bearer|Basic|Token|JWT)\s+/i, "").trim();
		if (bare.length >= 4 && bare !== s) out.push(bare);
	};
	for (const cred of credentials) {
		push(cred.token);
		for (const v of Object.values(cred.cookies ?? {})) push(v);
		for (const v of Object.values(cred.headers ?? {})) push(v);
	}
	return uniq(out).sort((a, b) => b.length - a.length);
}

function maskExtraSecrets(text: string, extraSecrets?: readonly string[]): string {
	let out = text;
	for (const secret of extraSecrets ?? []) {
		if (!secret || secret.length < 4) continue;
		if (out.includes(secret)) out = out.split(secret).join("[REDACTED]");
		const enc = encodeURIComponent(secret);
		if (enc !== secret && out.includes(enc)) out = out.split(enc).join("[REDACTED]");
	}
	return out;
}

function scrubText(text: string, root?: string, extraSecrets?: readonly string[]): string {
	const src = String(text ?? "");
	if (!src) return src;
	let out = src;
	if (root) {
		try {
			out = redactVaultSecrets(out, root);
		} catch {
			/* ignore */
		}
	}
	return maskExtraSecrets(out, extraSecrets);
}

function scrubUrl(url: string, root?: string, extraSecrets?: string[]): string {
	const src = String(url ?? "");
	if (!src) return src;
	try {
		return maskExtraSecrets(redactTrafficUrl(src, { root, extraSecrets }), extraSecrets);
	} catch {
		return maskExtraSecrets(src, extraSecrets);
	}
}

function scrubHeaders(
	headers: Record<string, string | string[] | undefined> | undefined,
	root?: string,
	extraSecrets?: readonly string[],
): Record<string, string> {
	try {
		const redacted = redactTrafficHeaders(headers, { root });
		if (!extraSecrets || extraSecrets.length === 0) return redacted;
		const out: Record<string, string> = {};
		for (const [k, v] of Object.entries(redacted)) out[k] = maskExtraSecrets(v, extraSecrets);
		return out;
	} catch {
		return {};
	}
}

function scrubBody(
	body: string | undefined,
	root?: string,
	extraSecrets?: readonly string[],
): string | undefined {
	if (body === undefined) return undefined;
	try {
		const redacted = redactTrafficBody(body, { root, maxChars: 2000 });
		return redacted === undefined ? undefined : maskExtraSecrets(redacted, extraSecrets);
	} catch {
		return undefined;
	}
}

/* ------------------------------------------------------------------ *
 * 网络探针抽象
 * ------------------------------------------------------------------ */

export type HeaderBagLike =
	| Record<string, string | string[] | undefined>
	| { get(name: string): string | null }
	| { forEach(cb: (value: unknown, key: string) => void): void };

export interface TrafficFetchResponse {
	ok?: boolean;
	status?: number;
	statusCode?: number;
	headers?: HeaderBagLike;
	body?: string | Buffer | Uint8Array;
	text?: string;
	snippet?: string;
	latencyMs?: number;
	finalUrl?: string;
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
) => Promise<TrafficFetchResponse>;

const defaultTrafficFetch: TrafficFetchFn = async (url, init) => {
	const res = await fetch(url, {
		method: init?.method ?? "GET",
		headers: init?.headers,
		body: init?.body,
		redirect: init?.redirect ?? "manual",
		signal: init?.signal,
	});
	const text = await res.text();
	const headers: Record<string, string> = {};
	res.headers.forEach((value, key) => {
		headers[key] = value;
	});
	return { ok: res.ok, status: res.status, headers, body: text, finalUrl: res.url };
};

interface NormalizedResponse {
	status: number;
	headers: Record<string, string>;
	text: string;
	bodyHash: string;
	bodyBytes: number;
	templateHash: string;
	latencyMs: number;
	finalUrl?: string;
	error?: string;
}

function normalizeStatus(res: TrafficFetchResponse): number {
	const raw = typeof res.status === "number" ? res.status : typeof res.statusCode === "number" ? res.statusCode : 0;
	return Number.isFinite(raw) ? Math.trunc(raw) : 0;
}

function normalizeHeaders(headers: HeaderBagLike | undefined): Record<string, string> {
	const out: Record<string, string> = {};
	if (!headers || typeof headers !== "object") return out;
	const anyHeaders = headers as Record<string, unknown>;

	if (typeof anyHeaders.forEach === "function") {
		try {
			(anyHeaders as { forEach: (cb: (value: unknown, key: string) => void) => void }).forEach((value, key) => {
				const name = String(key ?? "").trim().toLowerCase();
				if (!name || value === undefined || value === null) return;
				out[name] = Array.isArray(value) ? value.map(String).join(", ") : String(value);
			});
			if (Object.keys(out).length > 0) return out;
		} catch {
			/* fallthrough */
		}
	}

	if (typeof anyHeaders.get === "function") {
		for (const name of KNOWN_HEADERS) {
			try {
				const value = (anyHeaders as { get: (n: string) => string | null }).get(name);
				if (typeof value === "string" && value) out[name] = value;
			} catch {
				/* ignore */
			}
		}
		return out;
	}

	for (const [key, value] of Object.entries(anyHeaders)) {
		if (value === undefined || value === null) continue;
		const name = String(key ?? "").trim().toLowerCase();
		if (!name) continue;
		out[name] = Array.isArray(value) ? value.map(String).join(", ") : String(value);
	}
	return out;
}

function extractBodyText(res: TrafficFetchResponse): string {
	if (typeof res.body === "string") return res.body;
	if (Buffer.isBuffer(res.body)) return res.body.toString("utf8");
	if (res.body instanceof Uint8Array) return Buffer.from(res.body).toString("utf8");
	if (typeof res.text === "string") return res.text;
	if (typeof res.snippet === "string") return res.snippet;
	return "";
}

async function performProbe(
	fetchFn: TrafficFetchFn,
	url: string,
	headers: Record<string, string> | undefined,
	timeoutMs: number,
): Promise<NormalizedResponse> {
	const startedAt = Date.now();
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const res = await fetchFn(url, {
			method: "GET",
			headers: headers && Object.keys(headers).length > 0 ? headers : undefined,
			redirect: "manual",
			signal: controller.signal,
		});
		const text = extractBodyText(res);
		const { bodyHash, bodyBytes } = computeBodyHash(text);
		return {
			status: normalizeStatus(res),
			headers: normalizeHeaders(res.headers),
			text,
			bodyHash,
			bodyBytes,
			templateHash: computeTemplateFingerprint(text),
			latencyMs:
				typeof res.latencyMs === "number" && Number.isFinite(res.latencyMs)
					? Math.max(0, Math.trunc(res.latencyMs))
					: Date.now() - startedAt,
			finalUrl: typeof res.finalUrl === "string" ? res.finalUrl : undefined,
		};
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return {
			status: 0,
			headers: {},
			text: "",
			bodyHash: computeBodyHash("").bodyHash,
			bodyBytes: 0,
			templateHash: computeTemplateFingerprint(""),
			latencyMs: Date.now() - startedAt,
			error: oneLine(message, 160) || "请求失败",
		};
	} finally {
		clearTimeout(timer);
	}
}

/* ------------------------------------------------------------------ *
 * 范围护栏双闸
 * ------------------------------------------------------------------ */

interface ScopeGateResult {
	ok: boolean;
	reason?: string;
}

function gateTarget(url: string, host: string, scope: ScopePolicy, mode: Mode | string): ScopeGateResult {
	const hostVerdict = isHostInScope(host, scope);
	if (!hostVerdict.ok) {
		return { ok: false, reason: `靶标越界 (${host}) — ${hostVerdict.reason ?? "不在授权 Scope 内"}` };
	}
	const risk = checkScopeAndRisk(`curl -s ${url}`, scope, mode);
	if (risk?.block) {
		return { ok: false, reason: risk.reason };
	}
	return { ok: true };
}

interface GuardedProbeOutcome {
	gate: ScopeGateResult;
	res?: NormalizedResponse;
}

async function probeGuarded(args: {
	url: string;
	host: string;
	scope: ScopePolicy;
	mode: Mode | string;
	fetchFn: TrafficFetchFn;
	timeoutMs: number;
	headers?: Record<string, string>;
}): Promise<GuardedProbeOutcome> {
	const gate = gateTarget(args.url, args.host, args.scope, args.mode);
	if (!gate.ok) return { gate };
	const res = await performProbe(args.fetchFn, args.url, args.headers, args.timeoutMs);
	return { gate, res };
}

/* ------------------------------------------------------------------ *
 * 软 404 判定封装
 * ------------------------------------------------------------------ */

type DetectSoft404Fn = typeof detectSoft404;
type Soft404Result = ReturnType<DetectSoft404Fn>;
type Soft404Baseline = Parameters<DetectSoft404Fn>[1];

function titleOf(text: string): string {
	const m = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(String(text ?? ""));
	return m && m[1] ? oneLine(m[1], 120).toLowerCase() : "";
}

function runSoft404(res: NormalizedResponse, path: string, baseline: Soft404Baseline): Soft404Result {
	const payload = {
		status: res.status,
		code: res.status,
		body: res.text,
		snippet: res.text.slice(0, 4096),
		headers: res.headers,
		contentType: res.headers["content-type"],
		path,
	};
	try {
		const detected = detectSoft404(
			payload as unknown as Parameters<DetectSoft404Fn>[0],
			baseline as Parameters<DetectSoft404Fn>[1],
		);
		const rule = (detected as unknown as { matchedRule?: string }).matchedRule;
		// 仅靠“双方均无 <title> 且体积差 <= 48B”触发的弱匹配不能覆盖完全不同的模板与正文
		if (detected.isSoft404 && rule === "baseline_size_title_match" && !titleOf(res.text)) {
			const samples = ((baseline as { samples?: Array<{ bodyHash?: string; templateHash?: string; titleSig?: string }> } | null)?.samples) ?? [];
			const hasRealMatch = samples.some(
				(s) =>
					(s.titleSig && s.titleSig.length > 0) ||
					(s.bodyHash && s.bodyHash === res.bodyHash) ||
					(s.templateHash && s.templateHash === res.templateHash),
			);
			if (!hasRealMatch) {
				return {
					isSoft404: false,
					confidence: "none",
					reasons: [],
					bodyBytes: res.bodyBytes,
					bodyHash: res.bodyHash,
					templateHash: res.templateHash,
				} as unknown as Soft404Result;
			}
		}
		return detected;
	} catch {
		return {
			isSoft404: false,
			confidence: "none",
			reasons: [],
			bodyBytes: res.bodyBytes,
			bodyHash: res.bodyHash,
			templateHash: res.templateHash,
		} as unknown as Soft404Result;
	}
}

function buildSoft404Baseline(sample: NormalizedResponse, path: string): Soft404Baseline {
	return {
		samples: [
			{
				code: sample.status,
				size: sample.bodyBytes,
				titleSig: titleOf(sample.text),
				bodyHash: sample.bodyHash,
				templateHash: sample.templateHash,
				path,
			},
		],
	} as unknown as Soft404Baseline;
}

/* ------------------------------------------------------------------ *
 * 1. 凭据复用复验
 * ------------------------------------------------------------------ */

export interface CredentialSpec {
	role: string;
	headers?: Record<string, string>;
	cookies?: Record<string, string>;
	token?: string;
}

export interface CredentialCandidateTarget {
	host: string;
	port?: number;
	scheme?: string;
	path?: string;
	assetId?: string;
}

export interface VerifyCredentialPivotOptions {
	root?: string;
	projectId?: string;
	scope: ScopePolicy;
	mode?: Mode | string;
	credentials: CredentialSpec[];
	candidates: CredentialCandidateTarget[];
	fetchFn?: TrafficFetchFn;
	timeoutMs?: number;
}

export type CredentialProbeStatus =
	| "valid"
	| "invalid"
	| "blocked_by_scope"
	| "soft_404"
	| "no_difference"
	| "error";

export interface CredentialReuseFinding {
	target: string;
	host: string;
	role: string;
	assetId?: string;
	status: CredentialProbeStatus;
	reason: string;
	diffScore: number;
	baselineStatus?: number;
	baselineBytes?: number;
	baselineHash?: string;
	authStatus?: number;
	authBytes?: number;
	authHash?: string;
	soft404?: boolean;
	requestHeaders?: Record<string, string>;
	responseHeaders?: Record<string, string>;
	evidence?: string;
}

export interface VerifyCredentialPivotResult {
	ok: boolean;
	generatedAt: string;
	projectId?: string;
	mode: string;
	roles: string[];
	results: CredentialReuseFinding[];
	validReuses: Array<{ role: string; host: string; target: string; assetId?: string; diffScore: number }>;
	blockedTargets: Array<{ target: string; host: string; reason: string }>;
	soft404Targets: string[];
	summary: string;
}

function sanitizeRole(raw: string): string {
	const role = oneLine(raw, 64).toLowerCase().replace(/\s+/g, "-");
	return role || "anonymous";
}

function buildCredentialHeaders(cred: CredentialSpec): Record<string, string> {
	const out: Record<string, string> = {};
	const seen = new Set<string>();

	const push = (rawName: string, rawValue: string): void => {
		const name = stripCrlf(rawName).replace(/:\s*$/, "");
		const value = stripCrlf(rawValue);
		if (!name || !value) return;
		const key = name.toLowerCase();
		if (seen.has(key)) return;
		seen.add(key);
		out[name] = value;
	};

	if (cred.headers && typeof cred.headers === "object") {
		for (const [k, v] of Object.entries(cred.headers)) push(k, String(v ?? ""));
	}

	if (cred.cookies && typeof cred.cookies === "object" && !seen.has("cookie")) {
		const pairs = Object.entries(cred.cookies)
			.map(([k, v]) => `${stripCrlf(k)}=${stripCrlf(String(v ?? ""))}`)
			.filter((pair) => !pair.endsWith("="));
		if (pairs.length > 0) push("Cookie", pairs.join("; "));
	}

	if (cred.token && !seen.has("authorization")) {
		const token = stripCrlf(cred.token);
		if (token) {
			push("Authorization", /^(?:Bearer|Basic|Token|JWT)\s+/i.test(token) ? token : `Bearer ${token}`);
		}
	}

	return out;
}

function isOkStatus(status: number): boolean {
	return status >= 200 && status < 400;
}

function scoreDifference(baseline: NormalizedResponse, auth: NormalizedResponse, soft404: boolean): number {
	let score = 0;
	if (auth.status !== baseline.status) score += 35;
	if (auth.bodyHash !== baseline.bodyHash) score += 30;
	if (Math.abs(auth.bodyBytes - baseline.bodyBytes) >= MIN_BODY_DELTA) score += 20;
	if (isOkStatus(auth.status) && !isOkStatus(baseline.status)) score += 15;
	if (soft404) score -= 60;
	return Math.max(0, Math.min(100, score));
}

const LOGIN_REDIRECT_RE = /(?:^\/|[?&=])(?:login|signin|sign-in|auth|sso|session\/new)(?:[/?#&]|$)/i;

/**
 * 跨目标凭据复用复验。
 *
 * 安全闸门为 STRICT：每个候选目标在**任何**网络请求（含无认证基线）之前，
 * 必须同时通过 `isHostInScope` 与 `checkScopeAndRisk`；被阻断目标永不触发 `fetchFn`。
 */
export async function verifyCredentialPivot(
	opts: VerifyCredentialPivotOptions,
): Promise<VerifyCredentialPivotResult> {
	const root = opts.root ? String(opts.root) : undefined;
	const mode = String(opts.mode ?? "pentest");
	const fetchFn = opts.fetchFn ?? defaultTrafficFetch;
	const timeoutMs = normalizeTimeout(opts.timeoutMs);

	const credentials: CredentialSpec[] = (opts.credentials ?? []).map((cred) => ({
		role: sanitizeRole(cred.role),
		headers: cred.headers,
		cookies: cred.cookies,
		token: cred.token,
	}));
	const roles = uniq(credentials.map((cred) => cred.role));
	const extraSecrets = collectCredentialSecrets(credentials);

	const results: CredentialReuseFinding[] = [];
	const validReuses: VerifyCredentialPivotResult["validReuses"] = [];
	const blockedTargets: VerifyCredentialPivotResult["blockedTargets"] = [];
	const soft404Targets: string[] = [];

	for (const candidate of opts.candidates ?? []) {
		const built = buildTargetUrl(candidate);
		const rawLabel = builtTargetLabel(candidate);
		const displayTarget = scrubUrl("url" in built ? built.url : rawLabel, root, extraSecrets);
		const host = hostKey(candidate.host);

		if ("error" in built) {
			blockedTargets.push({ target: displayTarget, host, reason: built.error });
			results.push({
				target: displayTarget,
				host,
				role: "n/a",
				assetId: candidate.assetId,
				status: "blocked_by_scope",
				reason: built.error,
				diffScore: 0,
			});
			continue;
		}

		const targetUrl = built.url;
		const targetHost = built.host;

		// 闸门：基线探测之前即判定；被阻断时绝不发起任何请求。
		const baselineOutcome = await probeGuarded({
			url: targetUrl,
			host: targetHost,
			scope: opts.scope,
			mode,
			fetchFn,
			timeoutMs,
		});

		if (!baselineOutcome.gate.ok || !baselineOutcome.res) {
			const reason = baselineOutcome.gate.reason ?? "靶标越界，禁止探测";
			blockedTargets.push({ target: displayTarget, host, reason });
			for (const cred of credentials.length > 0 ? credentials : [{ role: "n/a" } as CredentialSpec]) {
				results.push({
					target: displayTarget,
					host,
					role: cred.role,
					assetId: candidate.assetId,
					status: "blocked_by_scope",
					reason,
					diffScore: 0,
				});
			}
			continue;
		}

		const baseline = baselineOutcome.res;

		// 随机不存在路径预采样：构造软 404 基线（同样过双闸，越界则跳过）。
		const probePath = `/${shortHash(`${targetUrl}:${randomBytes(6).toString("hex")}`, 14)}-nuwa-not-found`;
		const probeBuilt = buildTargetUrl({
			host: candidate.host,
			port: candidate.port,
			scheme: candidate.scheme,
			path: probePath,
		});
		let soft404Baseline: Soft404Baseline = null;
		if (!("error" in probeBuilt)) {
			const randomOutcome = await probeGuarded({
				url: probeBuilt.url,
				host: probeBuilt.host,
				scope: opts.scope,
				mode,
				fetchFn,
				timeoutMs,
			});
			if (randomOutcome.gate.ok && randomOutcome.res) {
				soft404Baseline = buildSoft404Baseline(randomOutcome.res, probePath);
			}
		}

		const baselineSoft = runSoft404(baseline, built.path, soft404Baseline);
		const baselineIsSoft404 = Boolean(baselineSoft.isSoft404);

		for (const cred of credentials) {
			const authHeaders = buildCredentialHeaders(cred);
			const requestSnapshot = scrubHeaders(authHeaders, root, extraSecrets);

			if (Object.keys(authHeaders).length === 0) {
				results.push({
					target: displayTarget,
					host,
					role: cred.role,
					assetId: candidate.assetId,
					status: "invalid",
					reason: "凭据集合为空（无 headers / cookies / token），跳过认证探测",
					diffScore: 0,
					baselineStatus: baseline.status,
					baselineBytes: baseline.bodyBytes,
					baselineHash: baseline.bodyHash,
				});
				continue;
			}

			const authOutcome = await probeGuarded({
				url: targetUrl,
				host: targetHost,
				scope: opts.scope,
				mode,
				fetchFn,
				timeoutMs,
				headers: authHeaders,
			});

			if (!authOutcome.gate.ok || !authOutcome.res) {
				const reason = authOutcome.gate.reason ?? "靶标越界，禁止认证探测";
				if (!blockedTargets.some((item) => item.target === displayTarget)) {
					blockedTargets.push({ target: displayTarget, host, reason });
				}
				results.push({
					target: displayTarget,
					host,
					role: cred.role,
					assetId: candidate.assetId,
					status: "blocked_by_scope",
					reason,
					diffScore: 0,
					requestHeaders: requestSnapshot,
				});
				continue;
			}

			const auth = authOutcome.res;
			const responseSnapshot = scrubHeaders(auth.headers, root, extraSecrets);
			const authSoft = runSoft404(auth, built.path, soft404Baseline);
			const soft404 = Boolean(authSoft.isSoft404);
			const diffScore = scoreDifference(baseline, auth, soft404);

			const evidenceBody = scrubText(scrubBody(auth.text.slice(0, 400), root, extraSecrets) ?? "", root, extraSecrets);
			const evidence = [
				`baseline status=${baseline.status} bytes=${baseline.bodyBytes} hash=${shortHash(baseline.bodyHash, 12)}`,
				`auth status=${auth.status} bytes=${auth.bodyBytes} hash=${shortHash(auth.bodyHash, 12)}`,
				`diffScore=${diffScore}`,
				baselineIsSoft404 ? "baseline=soft404" : "baseline=real",
				soft404 ? "auth=soft404" : "auth=real",
				evidenceBody ? `snippet=${oneLine(evidenceBody, 160)}` : "",
			]
				.filter(Boolean)
				.join(" | ");

			const baseFinding: CredentialReuseFinding = {
				target: displayTarget,
				host,
				role: cred.role,
				assetId: candidate.assetId,
				status: "invalid",
				reason: "",
				diffScore,
				baselineStatus: baseline.status,
				baselineBytes: baseline.bodyBytes,
				baselineHash: baseline.bodyHash,
				authStatus: auth.status,
				authBytes: auth.bodyBytes,
				authHash: auth.bodyHash,
				soft404,
				requestHeaders: requestSnapshot,
				responseHeaders: responseSnapshot,
				evidence,
			};

			if (auth.error) {
				results.push({ ...baseFinding, status: "error", reason: `认证请求失败: ${oneLine(auth.error, 120)}` });
				continue;
			}

			if (auth.status === 401 || auth.status === 403) {
				results.push({
					...baseFinding,
					status: "invalid",
					reason: `凭据被拒绝（HTTP ${auth.status}）`,
				});
				continue;
			}

			if (soft404) {
				if (!soft404Targets.includes(displayTarget)) soft404Targets.push(displayTarget);
				results.push({
					...baseFinding,
					status: "soft_404",
					reason: `认证响应命中软 404（confidence=${String(authSoft.confidence ?? "none")}），不计为有效复用`,
				});
				continue;
			}

			const redirectLocation = auth.headers["location"] ?? "";
			if (auth.status >= 300 && auth.status < 400 && LOGIN_REDIRECT_RE.test(redirectLocation)) {
				results.push({
					...baseFinding,
					status: "invalid",
					reason: `认证响应被重定向至登录端点（${scrubUrl(redirectLocation, root)}），判定为无效凭据`,
				});
				continue;
			}

		 if (diffScore < VALID_DIFF_SCORE || !isOkStatus(auth.status)) {
				const sameBody = baseline.bodyHash === auth.bodyHash;
				results.push({
					...baseFinding,
					status: sameBody ? "no_difference" : "invalid",
					reason: sameBody
						? "认证响应与无认证基线完全一致，判定为无效复用"
						: `认证响应差异不足（diffScore=${diffScore} < ${VALID_DIFF_SCORE}），判定为无效复用`,
				});
				continue;
			}

			results.push({
				...baseFinding,
				status: "valid",
				reason: `认证响应与基线显著差异（diffScore=${diffScore}），确认凭据可复用`,
			});
			validReuses.push({
				role: cred.role,
				host,
				target: displayTarget,
				assetId: candidate.assetId,
				diffScore,
			});
		}
	}

	const summaryLines = [
		`凭据复用复验: 目标 ${uniq(results.map((item) => item.target)).length} 个 | 角色 ${roles.length} 个 | 有效复用 ${validReuses.length} | 越界阻断 ${blockedTargets.length} | 软 404 ${soft404Targets.length}`,
	];
	for (const reuse of validReuses.slice(0, 12)) {
		summaryLines.push(`- [valid] role=${reuse.role} target=${reuse.target} diffScore=${reuse.diffScore}`);
	}
	for (const blocked of blockedTargets.slice(0, 8)) {
		summaryLines.push(`- [blocked] ${blocked.target} — ${blocked.reason}`);
	}
	for (const target of soft404Targets.slice(0, 8)) {
		summaryLines.push(`- [soft-404] ${target}`);
	}

	return {
		ok: validReuses.length > 0,
		generatedAt: nowIso(),
		projectId: opts.projectId,
		mode,
		roles,
		results,
		validReuses,
		blockedTargets,
		soft404Targets: uniq(soft404Targets),
		summary: scrubText(summaryLines.join("\n"), root, extraSecrets),
	};
}

/* ------------------------------------------------------------------ *
 * 2. 资产路由规划
 * ------------------------------------------------------------------ */

export interface SocksTunnelSpec {
	id: string;
	proxyUrl: string;
	targetCidrs?: string[];
	targetHosts?: string[];
}

export interface ResolveAssetRoutePlanOptions {
	assets: AssetNode[];
	proxyPool?: string[];
	socksTunnels?: SocksTunnelSpec[];
	defaultDirect?: boolean;
}

export type AssetRouteKind = "direct" | "proxy" | "socks5h" | "blocked";

export interface AssetRoutePlanEntry {
	assetId: string;
	host: string;
	assetKind: string;
	route: AssetRouteKind;
	proxyUrl?: string;
	tunnelId?: string;
	chain: string[];
	cycleDetected: boolean;
	blocked: boolean;
	reason: string;
	privateHost: boolean;
	credentialRoles: string[];
	endpoint?: string;
}

export interface AssetRoutePlan {
	ok: boolean;
	generatedAt: string;
	directCount: number;
	proxyCount: number;
	socksCount: number;
	blockedCount: number;
	cycles: string[][];
	entries: AssetRoutePlanEntry[];
	upserts: UpsertAssetInput[];
	summary: string;
}

function assetIdOf(asset: AssetNode): string {
	const direct = readString(asset, "id");
	if (direct) return direct;
	const host = assetHostOf(asset);
	return `${slugKey(host || "asset")}-${shortHash(host || JSON.stringify(asset ?? {}), 8)}`;
}

function hostFromUrlLike(raw: string | undefined): string {
	const text = String(raw ?? "").trim();
	if (!text) return "";
	try {
		return hostKey(new URL(text).hostname);
	} catch {
		return "";
	}
}

function assetHostOf(asset: AssetNode | undefined): string {
	if (!asset) return "";
	const direct = readString(asset, "host") ?? readString(asset, "target");
	if (direct) return hostKey(direct);
	const fromUrl = hostFromUrlLike(readString(asset, "url"));
	if (fromUrl) return fromUrl;
	const ports = readStringArray(asset, "ports");
	void ports;
	return "";
}

function reachableViaOf(asset: AssetNode | undefined): string[] {
	if (!asset) return [];
	return uniq([...readStringArray(asset, "reachableVia"), ...readStringArray(asset, "reachable_via")]);
}

function assetCredentialRoles(asset: AssetNode | undefined): string[] {
	if (!asset) return [];
	const declared = uniq([
		...readStringArray(asset, "credentialRoles"),
		...readStringArray(asset, "roles"),
		...readStringArray(asset, "credentials"),
	]);
	const fromTags = readStringArray(asset, "tags")
		.map((tag) => (/^cred[:/]/i.test(tag) ? tag.slice(5).trim() : ""))
		.filter(Boolean);
	return uniq([...declared, ...fromTags]).map((role) => sanitizeRole(role));
}

interface ChainTrace {
	chain: string[];
	cycle: boolean;
	cyclePath: string[];
}

function traceReachability(startId: string, byId: Map<string, AssetNode>): ChainTrace {
	const chain: string[] = [];
	const seen = new Set<string>();
	let current: string | undefined = startId;
	let cycle = false;
	let cyclePath: string[] = [];

	while (current) {
		if (seen.has(current)) {
			const startAt = chain.indexOf(current);
			cyclePath = [...chain.slice(startAt >= 0 ? startAt : 0), current];
			cycle = true;
			break;
		}
		const node = byId.get(current);
		if (!node) break;
		seen.add(current);
		chain.push(current);
		const next = reachableViaOf(node).find((id) => id !== current);
		current = next;
	}

	return { chain, cycle, cyclePath };
}

function normalizeTunnelProxy(proxyUrl: string): string {
	const raw = stripCrlf(proxyUrl);
	if (!raw) return "";
	if (/^socks5:\/\//i.test(raw)) return raw.replace(/^socks5:\/\//i, "socks5h://");
	if (/^(?:socks5h|socks4|socks4a|http|https):\/\//i.test(raw)) return raw;
	return `socks5h://${raw}`;
}

function tunnelHasTargets(tunnel: SocksTunnelSpec): boolean {
	return (tunnel.targetHosts?.length ?? 0) > 0 || (tunnel.targetCidrs?.length ?? 0) > 0;
}

function tunnelMatches(tunnel: SocksTunnelSpec, host: string): boolean {
	const target = hostKey(host);
	if (!target) return false;
	if (!tunnelHasTargets(tunnel)) return true;

	for (const rawPattern of tunnel.targetHosts ?? []) {
		const pattern = hostKey(rawPattern);
		if (!pattern) continue;
		if (pattern === "*") return true;
		if (pattern.startsWith("*.")) {
			const base = pattern.slice(2);
			if (base && target.endsWith(`.${base}`) && target.length > base.length + 1) return true;
			continue;
		}
		if (target === pattern) return true;
	}

	for (const cidr of tunnel.targetCidrs ?? []) {
		if (cidrContainsCidr(cidr, target)) return true;
	}

	return false;
}

function pickFromPool(pool: string[], seed: string): string {
	const list = pool.map((item) => stripCrlf(item)).filter(Boolean);
	if (list.length === 0) return "";
	const digest = shortHash(seed, 8);
	const index = Number.parseInt(digest, 16) % list.length;
	return list[Number.isFinite(index) ? index : 0] ?? list[0] ?? "";
}

interface RouteDecision {
	route: AssetRouteKind;
	proxyUrl?: string;
	tunnelId?: string;
	reason: string;
}

function decideRoute(args: {
	asset: AssetNode;
	assetId: string;
	host: string;
	chain: string[];
	byId: Map<string, AssetNode>;
	cycle: boolean;
	cyclePath: string[];
	proxyPool: string[];
	tunnels: SocksTunnelSpec[];
	defaultDirect: boolean;
}): RouteDecision {
	const { asset, assetId, host, chain, byId, cycle, cyclePath, proxyPool, tunnels, defaultDirect } = args;

	if (cycle) {
		return {
			route: "blocked",
			reason: `reachableVia 链路成环（${cyclePath.join(" → ")}），已阻断以避免无限递归`,
		};
	}

	const assetKind = readString(asset, "kind") ?? "unknown";
	if (assetKind === "local") {
		return { route: "direct", reason: "本地白盒资产（local）直连，无需网络出口" };
	}

	const hopHosts = chain
		.filter((id) => id !== assetId)
		.map((id) => assetHostOf(byId.get(id)))
		.filter(Boolean);
	const privateHost = isPrivateHost(host);
	const needTunnel = privateHost || hopHosts.some((hop) => isPrivateHost(hop));

	if (needTunnel) {
		const tunnel = tunnels.find((item) => tunnelMatches(item, host));
		if (tunnel) {
			const proxyUrl = normalizeTunnelProxy(tunnel.proxyUrl);
			if (proxyUrl) {
				return {
					route: "socks5h",
					proxyUrl,
					tunnelId: tunnel.id,
					reason: `内网/跳板资产经 socks5h 隧道 (${tunnel.id}) 转发${privateHost ? "" : "（含内网跳板）"}`,
				};
			}
			return { route: "blocked", reason: `隧道 ${tunnel.id} 的 proxyUrl 非法或不完整，无法建立 socks5h 出口` };
		}
		return {
			route: "blocked",
			reason: `内网/跳板资产 ${host || "(unknown)"} 缺少匹配的可达 SOCKS 隧道（targetHosts / targetCidrs 均不匹配）`,
		};
	}

	if (!defaultDirect) {
		const proxy = pickFromPool(proxyPool, assetId);
		if (proxy) {
			return { route: "proxy", proxyUrl: proxy, reason: "已禁用直连，经出口代理池（egress-proxy）转发" };
		}
		const scopedTunnel = tunnels.find((item) => tunnelHasTargets(item) && tunnelMatches(item, host));
		if (scopedTunnel) {
			const proxyUrl = normalizeTunnelProxy(scopedTunnel.proxyUrl);
			if (proxyUrl) {
				return {
					route: "socks5h",
					proxyUrl,
					tunnelId: scopedTunnel.id,
					reason: `已禁用直连，经声明式 socks5h 隧道 (${scopedTunnel.id}) 转发`,
				};
			}
		}
		return { route: "blocked", reason: "已禁用直连且未配置可用出口代理 / 匹配隧道" };
	}

	return { route: "direct", reason: "公网可达资产默认直连（defaultDirect）" };
}

/**
 * 解析多资产路由计划：遍历 `reachableVia` 链、检测环路，并按资产属性确定性选路。
 */
export function resolveAssetRoutePlan(opts: ResolveAssetRoutePlanOptions): AssetRoutePlan {
	const assets = Array.isArray(opts.assets) ? opts.assets : [];
	const proxyPool = uniq((opts.proxyPool ?? []).map((item) => stripCrlf(item)));
	const tunnels: SocksTunnelSpec[] = (opts.socksTunnels ?? [])
		.map((tunnel) => ({
			id: stripCrlf(tunnel.id) || `tunnel-${shortHash(tunnel.proxyUrl ?? "", 8)}`,
			proxyUrl: stripCrlf(tunnel.proxyUrl ?? ""),
			targetCidrs: uniq(tunnel.targetCidrs ?? []),
			targetHosts: uniq(tunnel.targetHosts ?? []),
		}))
		.filter((tunnel) => Boolean(tunnel.proxyUrl));
	const defaultDirect = opts.defaultDirect !== false;

	const byId = new Map<string, AssetNode>();
	for (const asset of assets) {
		const id = assetIdOf(asset);
		if (!byId.has(id)) byId.set(id, asset);
	}

	const entries: AssetRoutePlanEntry[] = [];
	const cycles: string[][] = [];
	const upserts: UpsertAssetInput[] = [];
	const seenCycleKeys = new Set<string>();

	for (const asset of assets) {
		const assetId = assetIdOf(asset);
		const host = assetHostOf(asset);
		const trace = traceReachability(assetId, byId);
		if (trace.cycle) {
			const key = [...trace.cyclePath].sort().join("|");
			if (!seenCycleKeys.has(key)) {
				seenCycleKeys.add(key);
				cycles.push(trace.cyclePath);
			}
		}

		const decision = decideRoute({
			asset,
			assetId,
			host,
			chain: trace.chain,
			byId,
			cycle: trace.cycle,
			cyclePath: trace.cyclePath,
			proxyPool,
			tunnels,
			defaultDirect,
		});

		const credentialRoles = uniq([
			...assetCredentialRoles(asset),
			...trace.chain
				.filter((id) => id !== assetId)
				.flatMap((id) => assetCredentialRoles(byId.get(id))),
		]);

		const assetUrl = readString(asset, "url");
		const portCandidate =
			typeof (asset as unknown as Record<string, unknown>).port === "number"
				? ((asset as unknown as Record<string, unknown>).port as number)
				: undefined;

		const entry: AssetRoutePlanEntry = {
			assetId,
			host,
			assetKind: readString(asset, "kind") ?? "unknown",
			route: decision.route,
			proxyUrl: decision.proxyUrl,
			tunnelId: decision.tunnelId,
			chain: trace.chain,
			cycleDetected: trace.cycle,
			blocked: decision.route === "blocked",
			reason: decision.reason,
			privateHost: isPrivateHost(host),
			credentialRoles,
			endpoint: assetUrl ? scrubUrl(assetUrl) : host ? builtTargetLabel({ host, port: portCandidate }) : undefined,
		};
		entries.push(entry);

		const upsert = {
			id: assetId,
			host: host || undefined,
			url: assetUrl || undefined,
			port: portCandidate,
			ports: (readStringArray(asset, "ports").map((p) => Number(p)).filter((n) => Number.isFinite(n)) as number[]).slice(0, 8),
			kind: (readString(asset, "kind") ?? "target") as unknown as UpsertAssetInput["kind"],
			tags: uniq([...(readStringArray(asset, "tags") ?? []), `route:${decision.route}`]),
			reachableVia: trace.chain.slice(1),
			sourceFactId: readString(asset, "sourceFactId"),
			note: oneLine(`route=${decision.route}; ${decision.reason}`, 200),
		} as unknown as UpsertAssetInput;
		upserts.push(upsert);
	}

	const directCount = entries.filter((item) => item.route === "direct").length;
	const proxyCount = entries.filter((item) => item.route === "proxy").length;
	const socksCount = entries.filter((item) => item.route === "socks5h").length;
	const blockedCount = entries.filter((item) => item.route === "blocked").length;

	const summaryLines = [
		`资产路由计划: 资产 ${entries.length} 个 | 直连 ${directCount} | 出口代理 ${proxyCount} | socks5h ${socksCount} | 阻断 ${blockedCount} | 环路 ${cycles.length}`,
	];
	for (const entry of entries.slice(0, 20)) {
		const via = entry.route === "socks5h" ? ` via=${entry.tunnelId ?? entry.proxyUrl ?? "-"}` : "";
		summaryLines.push(
			`- ${entry.assetId} (${entry.host || "unknown"}) → ${entry.route}${via}${entry.cycleDetected ? " [cycle]" : ""} — ${entry.reason}`,
		);
	}

	return {
		ok: blockedCount === 0 && cycles.length === 0,
		generatedAt: nowIso(),
		directCount,
		proxyCount,
		socksCount,
		blockedCount,
		cycles,
		entries,
		upserts,
		summary: summaryLines.join("\n"),
	};
}

/* ------------------------------------------------------------------ *
 * 3. 已确认 SSRF 内网探测
 * ------------------------------------------------------------------ */

export interface SsrfTargetCandidate {
	host: string;
	port?: number;
	scheme?: string;
	path?: string;
}

export interface ProbeViaConfirmedSsrfOptions {
	fact: Fact;
	urlTemplate: string;
	targets: SsrfTargetCandidate[];
	scope: ScopePolicy;
	mode?: Mode | string;
	fetchFn?: TrafficFetchFn;
	timeoutMs?: number;
}

export interface SsrfBlockedTarget {
	target: string;
	host: string;
	reason: string;
}

export interface SsrfProbeFinding {
	target: string;
	host: string;
	reachable: boolean;
	status: number;
	bytes: number;
	bodyHash: string;
	latencyMs: number;
	reason: string;
	evidence?: string;
	responseHeaders?: Record<string, string>;
}

export interface ProbeViaConfirmedSsrfResult {
	ok: boolean;
	reason?: string;
	factId: string;
	generatedAt: string;
	discoveredAssets: AssetNode[];
	upserts: UpsertAssetInput[];
	blockedTargets: SsrfBlockedTarget[];
	findings: SsrfProbeFinding[];
	baseline: { used: boolean; status?: number; latencyMs?: number; bodyHash?: string; reason?: string };
	summary: string;
}

const SSRF_ERROR_TEXT_RE =
	/could\s*not\s*resolve|failed\s*to\s*connect|connection\s*refused|no\s*route\s*to\s*host|network\s*is\s*unreachable|name\s*or\s*service\s*not\s*known|getaddrinfo|dial\s*tcp|i\/o\s*timeout|context\s*deadline\s*exceeded|invalid\s*url|unsupported\s*protocol/i;

function containsTemplateToken(template: string): boolean {
	return /\{\{\s*(?:target|host|url)\s*\}\}/i.test(template);
}

/** 将目标安全注入 `urlTemplate`：优先替换 `{{target}}`/`{{host}}`/`{{url}}`，否则追加受控查询参数。 */
export function applySsrfUrlTemplate(template: string, target: string, host?: string): string {
	const raw = String(template ?? "").trim();
	const injected = String(target ?? "").trim();
	if (!raw) return injected;
	if (!injected) return raw;

	if (containsTemplateToken(raw)) {
		return raw
			.replace(/\{\{\s*target\s*\}\}/gi, injected)
			.replace(/\{\{\s*url\s*\}\}/gi, injected)
			.replace(/\{\{\s*host\s*\}\}/gi, host ? String(host) : injected);
	}

	const encoded = encodeURIComponent(injected);
	if (/[?&][^=&#]*=$/.test(raw)) return `${raw}${encoded}`;
	if (raw.includes("?")) return `${raw}${/[?&]$/.test(raw) ? "" : "&"}url=${encoded}`;
	return `${raw}${raw.endsWith("/") ? "" : "/"}?url=${encoded}`;
}

function buildSsrfAsset(args: {
	factId: string;
	host: string;
	port?: number;
	scheme: string;
	url: string;
	kind: "service" | "host";
	note: string;
}): { asset: AssetNode; upsert: UpsertAssetInput } {
	const id = `ssrf-${slugKey(args.host)}-${shortHash(`${args.factId}:${args.host}:${args.port ?? ""}`, 10)}`;
	const upsert = {
		id,
		host: args.host,
		target: args.url,
		url: args.url,
		port: args.port,
		ports: args.port ? [args.port] : [],
		scheme: args.scheme,
		kind: args.kind,
		tags: ["ssrf", "confirmed-fact"],
		reachableVia: [args.factId],
		sourceFactId: args.factId,
		note: oneLine(args.note, 200),
	} as unknown as UpsertAssetInput;
	return { asset: upsert as unknown as AssetNode, upsert };
}

/**
 * 已确认 SSRF 事实的内网可达性探测。
 *
 * 闸门 1：`fact.verifyStage !== "confirmed"` 立即拒绝，零网络请求。
 * 闸门 2：每个候选目标注入前均执行 `isHostInScope` + `checkScopeAndRisk`；被阻断目标永不触发 `fetchFn`。
 */
export async function probeViaConfirmedSsrf(
	opts: ProbeViaConfirmedSsrfOptions,
): Promise<ProbeViaConfirmedSsrfResult> {
	const factIdRaw = readString(opts.fact, "id");
	const factId = factIdRaw ?? `fact-${shortHash(JSON.stringify(opts.fact ?? {}), 10)}`;
	const stage = readString(opts.fact, "verifyStage") ?? readString(opts.fact, "verify_stage") ?? "";

	if (stage !== "confirmed") {
		return {
			ok: false,
			reason: "Fact verifyStage is not confirmed",
			factId,
			generatedAt: nowIso(),
			discoveredAssets: [],
			upserts: [],
			blockedTargets: [],
			findings: [],
			baseline: { used: false, reason: "未执行（事实未确认）" },
			summary: `SSRF 探测拒绝: 事实 ${factId} 的 verifyStage=${stage || "(empty)"}，仅接受 confirmed`,
		};
	}

	const mode = String(opts.mode ?? "pentest");
	const fetchFn = opts.fetchFn ?? defaultTrafficFetch;
	const timeoutMs = normalizeTimeout(opts.timeoutMs);
	const urlTemplate = String(opts.urlTemplate ?? "").trim();

	if (!urlTemplate) {
		return {
			ok: false,
			reason: "urlTemplate 为空，无法构造 SSRF 探测请求",
			factId,
			generatedAt: nowIso(),
			discoveredAssets: [],
			upserts: [],
			blockedTargets: [],
			findings: [],
			baseline: { used: false, reason: "未执行（模板为空）" },
			summary: `SSRF 探测拒绝: 事实 ${factId} 的 urlTemplate 为空`,
		};
	}

	// 负向基线（canary）：使用不可解析的保留域，先过双闸，越界即跳过并回退静态指纹。
	const canaryHost = `nuwa-canary-${shortHash(randomBytes(8).toString("hex"), 12)}.invalid`;
	const canaryUrl = applySsrfUrlTemplate(urlTemplate, `http://${canaryHost}/`, canaryHost);
	let baseline: ProbeViaConfirmedSsrfResult["baseline"] = { used: false };
	let baselineBytes = 0;
	const canaryGate = gateTarget(canaryUrl, canaryHost, opts.scope, mode);
	if (!canaryGate.ok) {
		baseline = { used: false, reason: "负向基线目标越界，回退静态错误指纹比对" };
	} else {
		const canaryRes = await performProbe(fetchFn, canaryUrl, undefined, timeoutMs);
		baselineBytes = canaryRes.bodyBytes;
		baseline = {
			used: true,
			status: canaryRes.status,
			latencyMs: canaryRes.latencyMs,
			bodyHash: canaryRes.bodyHash,
			reason: canaryRes.error
				? `canary 请求失败（${oneLine(canaryRes.error, 80)}），作为失败指纹基线`
				: "canary 采集完成",
		};
	}

	const findings: SsrfProbeFinding[] = [];
	const discoveredAssets: AssetNode[] = [];
	const upserts: UpsertAssetInput[] = [];
	const blockedTargets: SsrfBlockedTarget[] = [];

	for (const candidate of opts.targets ?? []) {
		const built = buildTargetUrl(candidate);
		const host = hostKey(candidate.host);
		const fallbackLabel = builtTargetLabel(candidate);
		const displayTarget = scrubUrl("url" in built ? built.url : fallbackLabel);

		if ("error" in built) {
			blockedTargets.push({ target: displayTarget, host, reason: built.error });
			continue;
		}

		// 严格闸门（Gate 2）：内网目标主机 + 靶标 URL 双检；被阻断目标永不触发 fetchFn。
		const targetGate = gateTarget(built.url, built.host, opts.scope, mode);
		if (!targetGate.ok) {
			blockedTargets.push({
				target: displayTarget,
				host,
				reason: targetGate.reason ?? "靶标越界，禁止探测",
			});
			continue;
		}

		const ssrfUrl = applySsrfUrlTemplate(urlTemplate, built.url, built.host);
		let outerHost = "";
		try {
			outerHost = hostKey(new URL(ssrfUrl).hostname);
		} catch {
			blockedTargets.push({
				target: displayTarget,
				host,
				reason: "无法解析注入后的 SSRF URL",
			});
			continue;
		}
		const outerGate = gateTarget(ssrfUrl, outerHost, opts.scope, mode);
		if (!outerGate.ok) {
			blockedTargets.push({
				target: displayTarget,
				host,
				reason: outerGate.reason ?? "SSRF 外层端点越界，禁止探测",
			});
			continue;
		}

		// 至此双闸均通过，可安全发起 SSRF 探测。
		const res = await performProbe(fetchFn, ssrfUrl, undefined, timeoutMs);

		const genericErrorText = SSRF_ERROR_TEXT_RE.test(`${res.text}\n${res.error ?? ""}`);
		const sameHash = baseline.bodyHash !== undefined && res.bodyHash === baseline.bodyHash;
		const sameStatus = baseline.status !== undefined && res.status === baseline.status;

		let reachable = false;
		let reason = "";

		if (res.status === 0 || res.error) {
			reachable = false;
			reason = `请求失败: ${oneLine(res.error ?? "无响应", 100)}`;
		} else if (baseline.used && sameHash && sameStatus) {
			reachable = false;
			reason = "响应与 canary 基线完全一致，疑似出口统一失败应答，判定不可达";
		} else if (baseline.used) {
			const delta = res.bodyBytes - baselineBytes;
			reachable = true;
			reason = `响应与 canary 基线差异（status ${baseline.status ?? "?"}→${res.status}, bytes=${res.bodyBytes}${delta ? `, Δ=${delta}` : ""}），判定可达`;
		} else if (genericErrorText && res.bodyBytes < 32) {
			reachable = false;
			reason = "响应匹配静态失败指纹且体积极小，判定不可达";
		} else {
			reachable = true;
			reason = `无 canary 基线，目标返回 HTTP ${res.status}（${res.bodyBytes} bytes），按可达处理`;
		}

		const evidenceSnippet = oneLine(scrubBody(res.text.slice(0, 400)) ?? "", 200);

		findings.push({
			target: displayTarget,
			host,
			reachable,
			status: res.status,
			bytes: res.bodyBytes,
			bodyHash: res.bodyHash,
			latencyMs: res.latencyMs,
			reason,
			evidence: evidenceSnippet || undefined,
			responseHeaders: scrubHeaders(res.headers),
		});

		if (reachable) {
			const assetKind: "service" | "host" = typeof candidate.port === "number" ? "service" : "host";
			const builtAsset = buildSsrfAsset({
				factId,
				host,
				port: candidate.port,
				scheme: built.scheme,
				url: displayTarget,
				kind: assetKind,
				note: `${reason} | HTTP ${res.status} / ${res.bodyBytes} bytes`,
			});
			discoveredAssets.push(builtAsset.asset);
			upserts.push(builtAsset.upsert);
		}
	}

	const reachableCount = findings.filter((item) => item.reachable).length;
	const summaryLines = [
		`SSRF 已确认事实探测: fact=${factId} | 目标 ${findings.length} | 可达 ${reachableCount} | 越界阻断 ${blockedTargets.length}`,
		baseline.used
			? `负向基线: status=${baseline.status ?? "?"} latency=${baseline.latencyMs ?? "?"}ms hash=${shortHash(baseline.bodyHash ?? "", 12)}`
			: `负向基线: 跳过（${baseline.reason ?? "不可用"}），回退静态失败指纹比对`,
	];
	for (const finding of findings.slice(0, 20)) {
		summaryLines.push(
			`- ${finding.reachable ? "[reachable]" : "[unreachable]"} ${finding.target} — ${finding.reason}`,
		);
	}
	for (const blocked of blockedTargets.slice(0, 10)) {
		summaryLines.push(`- [blocked] ${blocked.target} — ${blocked.reason}`);
	}

	return {
		ok: reachableCount > 0,
		factId,
		generatedAt: nowIso(),
		discoveredAssets,
		upserts,
		blockedTargets,
		findings,
		baseline,
		summary: scrubText(summaryLines.join("\n")),
	};
}
