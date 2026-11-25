/**
 * 女娲 v5.0 确定性多角色只读鉴权差分矩阵引擎（Auth Diff / Auto-BOLA & BFLA）。
 *
 * 职责：
 * 1. 对授权 Scope 内的候选接口以严格只读 GET（redirect: "manual"）并发对照匿名（anon）与会话保险箱内各角色。
 * 2. 自动采集双随机路径 Soft-404 基线，杜绝 SPA 200 HTML 兜底页引发误报。
 * 3. 提取响应状态码、字节数、HTML 标题签名、JSON 顶层结构键集合与 Jaccard 相似度，确定性检出：
 *    - `unauth_access`（未授权直接返回受保护接口结构化数据）
 *    - `vertical_bfla`（低权角色访问管理/内部接口或获得与高权角色高重合响应）
 *    - `horizontal_bola`（同级异角色在对象 ID 路径上均获 200 且返回高重合/同源对象内容）
 * 4. 所有输出片段、摘要与生成的候选 `AutoFact` 均通过 `redactVaultSecrets` 全量脱敏。
 *
 * 约束：仅使用 `import type` 引用 `./types` 与 `./autoexec`，严禁运行时 import `./nuwa`。
 */
import { createHash } from "node:crypto";
import { isHostInScope, type ScopePolicy } from "./scope";
import {
	getRoleHeadersMap,
	loadSessionVault,
	redactVaultSecrets,
	type SessionVault,
} from "./session-vault";
import type { AutoFact } from "./autoexec";

export interface AuthDiffFetchResponse {
	ok: boolean;
	status: number;
	text(): Promise<string>;
	headers?: { get(name: string): string | null };
}

export type AuthDiffFetchLike = (
	input: string,
	init?: {
		method?: string;
		headers?: Record<string, string>;
		redirect?: "manual" | "follow" | "error";
		signal?: AbortSignal;
	},
) => Promise<AuthDiffFetchResponse>;

export interface AuthRoleProbeResult {
	role: string;
	status: number;
	bytes: number;
	location?: string;
	titleSig?: string;
	jsonKeys: string[];
	bodySha1: string;
	sampleSnippet: string;
	isHtml: boolean;
	isSoft404: boolean;
	error?: string;
}

export type AuthDiffAnomalyKind = "unauth_access" | "vertical_bfla" | "horizontal_bola";

export interface AuthDiffFinding {
	path: string;
	kind: AuthDiffAnomalyKind;
	severity: "high" | "medium";
	summary: string;
	baselineRole: string;
	testedRole: string;
	similarity: number;
	probes: AuthRoleProbeResult[];
}

export interface AuthDiffMatrixOptions {
	roles?: string[];
	maxPaths?: number;
	timeoutMs?: number;
	fetchFn?: AuthDiffFetchLike;
	signal?: AbortSignal;
	adminRoles?: string[];
	lowPrivRoles?: string[];
}

export interface AuthDiffMatrixResult {
	baseUrl: string;
	testedPaths: string[];
	roles: string[];
	matrix: Record<string, AuthRoleProbeResult[]>;
	findings: AuthDiffFinding[];
	blockedPaths: string[];
	fact: AutoFact | null;
}

const DEFAULT_MAX_PATHS = 20;
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_BODY_CAPTURE = 65_536;
const ADMIN_ROLE_RE = /^(?:super[-_]?admin|admin|administrator|root|staff|manager|operator|owner|moderator)(?:[-_0-9].*)?$/i;
const ADMIN_PATH_RE = /\/(?:admin|internal|manage|management|staff|console|metrics|actuator|roles|permissions|audit|system|ops|backoffice)(?:\/|$|\?)/i;
const OBJECT_ID_PATH_RE = /\/(?:[0-9]{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)/i;
const OBJECT_ID_QUERY_RE = /[?&](?:id|uid|user_?id|account_?id|order_?id|tenant_?id|doc_?id|item_?id)=/i;
const HTML_SIG_RE = /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<title[\s>]/i;
const SOFT404_PROBES = ["/__nuwa_authdiff_404_a", "/__nuwa_authdiff_404_b.json"] as const;

function sha1Hex(text: string): string {
	return createHash("sha1").update(text, "utf8").digest("hex");
}

function clip(text: string, max: number): string {
	const s = String(text ?? "").replace(/\r/g, "").trim();
	return s.length > max ? `${s.slice(0, max)}…` : s;
}

function titleSigOf(body: string): string {
	const m = /<title[^>]*>([^<]{0,120})<\/title>/i.exec(body);
	return (m?.[1] ?? "").replace(/\s+/g, " ").trim().toLowerCase();
}

function resolveVaultInput(rootOrVault: string | SessionVault): SessionVault {
	if (typeof rootOrVault === "string") return loadSessionVault(rootOrVault);
	if (rootOrVault && typeof rootOrVault === "object" && rootOrVault.roles) return rootOrVault;
	return { schema: 1, updatedAt: "", roles: {} };
}

function defaultFetchImpl(): AuthDiffFetchLike {
	return async (input, init) => {
		const res = await fetch(input, {
			method: init?.method ?? "GET",
			headers: init?.headers,
			redirect: init?.redirect ?? "manual",
			signal: init?.signal,
		});
		return {
			ok: res.ok,
			status: res.status,
			text: () => res.text(),
			headers: res.headers,
		};
	};
}

/**
 * 从 JSON 响应体安全提取排序后的结构键签名（含顶层键及常见 data/result/user/order 嵌套键）。
 */
export function extractJsonTopKeys(body: string): string[] {
	const trimmed = String(body ?? "").trim();
	if (!trimmed || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) return [];
	try {
		const parsed = JSON.parse(trimmed) as unknown;
		const keys = new Set<string>();
		const collectObj = (obj: Record<string, unknown>, prefix = "") => {
			for (const [k, v] of Object.entries(obj)) {
				const full = prefix ? `${prefix}.${k}` : k;
				keys.add(full);
				if (
					!prefix &&
					v &&
					typeof v === "object" &&
					!Array.isArray(v) &&
					["data", "result", "user", "order", "item", "profile", "account", "record"].includes(k.toLowerCase())
				) {
					collectObj(v as Record<string, unknown>, k);
				}
			}
		};
		if (Array.isArray(parsed)) {
			const first = parsed[0];
			if (first && typeof first === "object" && !Array.isArray(first)) {
				collectObj(first as Record<string, unknown>);
			}
		} else if (parsed && typeof parsed === "object") {
			collectObj(parsed as Record<string, unknown>);
		}
		return [...keys].sort();
	} catch {
		return [];
	}
}

/**
 * 计算两个结构键集合的 Jaccard 相似度（0..1）；双方均为空集合时返回 0 防止空响应误匹配。
 */
export function computeKeyJaccard(keysA: readonly string[], keysB: readonly string[]): number {
	const setA = new Set(keysA.map((k) => k.trim()).filter(Boolean));
	const setB = new Set(keysB.map((k) => k.trim()).filter(Boolean));
	if (setA.size === 0 && setB.size === 0) return 0;
	let inter = 0;
	for (const k of setA) {
		if (setB.has(k)) inter += 1;
	}
	const union = setA.size + setB.size - inter;
	return union === 0 ? 0 : Number((inter / union).toFixed(4));
}

export function isAdminLikeRole(role: string, customAdmins?: readonly string[]): boolean {
	const norm = String(role ?? "").trim().toLowerCase();
	if (!norm || norm === "anon") return false;
	if (customAdmins?.some((r) => r.trim().toLowerCase() === norm)) return true;
	return ADMIN_ROLE_RE.test(norm);
}

export function isAdminLikePath(path: string): boolean {
	return ADMIN_PATH_RE.test(String(path ?? "").trim());
}

export function isObjectResourcePath(path: string): boolean {
	const p = String(path ?? "").trim();
	return OBJECT_ID_PATH_RE.test(p) || OBJECT_ID_QUERY_RE.test(p);
}

interface Soft404Ref {
	status: number;
	bytes: number;
	titleSig: string;
	bodySha1: string;
}

function matchesSoft404(
	probe: { status: number; bytes: number; titleSig?: string; bodySha1: string; isHtml: boolean },
	baselines: readonly Soft404Ref[],
): boolean {
	if (probe.status !== 200 && (probe.status < 300 || probe.status >= 400)) return false;
	for (const b of baselines) {
		if (b.status !== probe.status) continue;
		if (b.bodySha1 && b.bodySha1 === probe.bodySha1) return true;
		const tol = Math.max(48, b.bytes * 0.1);
		if (Math.abs(probe.bytes - b.bytes) <= tol) {
			if (!b.titleSig || b.titleSig === (probe.titleSig ?? "")) {
				return true;
			}
		}
	}
	return false;
}

function isSubstantive200(probe: AuthRoleProbeResult | undefined): probe is AuthRoleProbeResult {
	if (!probe) return false;
	if (probe.status < 200 || probe.status >= 300) return false;
	if (probe.isSoft404) return false;
	if (probe.bytes < 8) return false;
	return probe.jsonKeys.length > 0 || !probe.isHtml || probe.bytes >= 40;
}

function isBlockedStatus(probe: AuthRoleProbeResult | undefined): boolean {
	if (!probe) return false;
	return probe.status === 401 || probe.status === 403 || probe.status === 301 || probe.status === 302 || probe.status === 303 || probe.status === 307;
}

function normalizeCandidatePath(raw: string): string | null {
	const s = String(raw ?? "").trim();
	if (!s) return null;
	if (s.startsWith("/")) return s;
	try {
		const u = new URL(s);
		return `${u.pathname}${u.search}`;
	} catch {
		return null;
	}
}

async function probeEndpoint(
	url: string,
	role: string,
	headers: Record<string, string> | undefined,
	fetcher: AuthDiffFetchLike,
	vault: SessionVault,
	baselines: readonly Soft404Ref[],
	timeoutMs: number,
	signal?: AbortSignal,
): Promise<AuthRoleProbeResult> {
	const ac = new AbortController();
	const onAbort = () => ac.abort();
	signal?.addEventListener("abort", onAbort, { once: true });
	const timer = setTimeout(() => ac.abort(), timeoutMs);
	try {
		const resp = await fetcher(url, {
			method: "GET",
			headers: {
				Accept: "application/json, text/plain, text/html;q=0.8, */*;q=0.5",
				...(headers ?? {}),
			},
			redirect: "manual",
			signal: ac.signal,
		});
		const rawBody = await resp.text();
		const body = rawBody.length > MAX_BODY_CAPTURE ? rawBody.slice(0, MAX_BODY_CAPTURE) : rawBody;
		const bytes = Buffer.byteLength(rawBody, "utf8");
		const location = resp.headers?.get("location")?.trim() || undefined;
		const isHtml = HTML_SIG_RE.test(body);
		const titleSig = isHtml ? titleSigOf(body) : "";
		const jsonKeys = extractJsonTopKeys(body);
		const bodySha1 = sha1Hex(body.trim());
		const isSoft404 = matchesSoft404({ status: resp.status, bytes, titleSig, bodySha1, isHtml }, baselines);
		const sampleSnippet = redactVaultSecrets(clip(body.replace(/\s+/g, " "), 180), vault);
		return {
			role,
			status: resp.status,
			bytes,
			...(location ? { location: redactVaultSecrets(location, vault) } : {}),
			...(titleSig ? { titleSig } : {}),
			jsonKeys,
			bodySha1,
			sampleSnippet,
			isHtml,
			isSoft404,
		};
	} catch (err) {
		return {
			role,
			status: 0,
			bytes: 0,
			jsonKeys: [],
			bodySha1: "",
			sampleSnippet: "",
			isHtml: false,
			isSoft404: false,
			error: redactVaultSecrets(err instanceof Error ? err.message : String(err), vault),
		};
	} finally {
		clearTimeout(timer);
		signal?.removeEventListener("abort", onAbort);
	}
}

/**
 * 对指定目标与路径列表执行确定性只读多角色鉴权差分矩阵核验。
 * 严格受 `ScopePolicy` 保护，所有结果经 `redactVaultSecrets` 脱敏。
 */
export async function runAuthDiffMatrix(
	baseUrl: string,
	paths: readonly string[],
	rootOrVault: string | SessionVault,
	scope: ScopePolicy,
	opts?: AuthDiffMatrixOptions,
): Promise<AuthDiffMatrixResult> {
	const vault = resolveVaultInput(rootOrVault);
	let parsedBase: URL;
	try {
		parsedBase = new URL(baseUrl);
	} catch {
		return {
			baseUrl,
			testedPaths: [],
			roles: ["anon"],
			matrix: {},
			findings: [],
			blockedPaths: [...paths],
			fact: null,
		};
	}

	if ((parsedBase.protocol !== "http:" && parsedBase.protocol !== "https:") || !isHostInScope(parsedBase.hostname, scope).ok) {
		return {
			baseUrl: parsedBase.href,
			testedPaths: [],
			roles: ["anon"],
			matrix: {},
			findings: [],
			blockedPaths: [...paths],
			fact: null,
		};
	}

	const maxPaths = Math.max(1, Math.min(50, Math.floor(opts?.maxPaths ?? DEFAULT_MAX_PATHS)));
	const timeoutMs = Math.max(500, Math.min(30_000, Math.floor(opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS)));
	const fetcher = opts?.fetchFn ?? defaultFetchImpl();

	const vaultRoles = Object.keys(vault.roles ?? {}).sort();
	const selectedRoles = opts?.roles?.length
		? opts.roles.map((r) => r.trim().toLowerCase()).filter((r) => r && r !== "anon" && Boolean(vault.roles[r]))
		: vaultRoles;
	const roles = ["anon", ...new Set(selectedRoles)];

	const normalizedPaths: string[] = [];
	const seenPath = new Set<string>();
	const blockedPaths: string[] = [];

	for (const raw of paths) {
		if (normalizedPaths.length >= maxPaths) break;
		const norm = normalizeCandidatePath(raw);
		if (!norm) {
			blockedPaths.push(String(raw));
			continue;
		}
		if (seenPath.has(norm)) continue;
		try {
			const resolved = new URL(norm, parsedBase);
			if (!isHostInScope(resolved.hostname, scope).ok || resolved.origin !== parsedBase.origin) {
				blockedPaths.push(norm);
				continue;
			}
		} catch {
			blockedPaths.push(norm);
			continue;
		}
		seenPath.add(norm);
		normalizedPaths.push(norm);
	}

	// 1. 采集 Soft-404 兜底基线（仅作用于 200/30x 兜底页）
	const baselines: Soft404Ref[] = [];
	for (const bp of SOFT404_PROBES) {
		if (opts?.signal?.aborted) break;
		const baseProbe = await probeEndpoint(
			`${parsedBase.origin}${bp}`,
			"anon",
			undefined,
			fetcher,
			vault,
			[],
			timeoutMs,
			opts?.signal,
		);
		if (baseProbe.status === 200 || (baseProbe.status >= 300 && baseProbe.status < 400)) {
			baselines.push({
				status: baseProbe.status,
				bytes: baseProbe.bytes,
				titleSig: baseProbe.titleSig ?? "",
				bodySha1: baseProbe.bodySha1,
			});
		}
	}

	const matrix: Record<string, AuthRoleProbeResult[]> = {};
	const findings: AuthDiffFinding[] = [];
	const testedPaths: string[] = [];

	// 2. 逐路径执行 anon + 各角色只读 GET 探测并执行差分分类
	for (const path of normalizedPaths) {
		if (opts?.signal?.aborted) break;
		const targetUrl = new URL(path, parsedBase).href;
		const probes: AuthRoleProbeResult[] = [];
		for (const role of roles) {
			if (opts?.signal?.aborted) break;
			const hdrs = role === "anon" ? undefined : getRoleHeadersMap(vault, role) ?? undefined;
			const probe = await probeEndpoint(targetUrl, role, hdrs, fetcher, vault, baselines, timeoutMs, opts?.signal);
			probes.push(probe);
		}
		matrix[path] = probes;
		testedPaths.push(path);

		const anonProbe = probes.find((p) => p.role === "anon");
		const authProbes = probes.filter((p) => p.role !== "anon");
		const adminProbes = authProbes.filter((p) => isAdminLikeRole(p.role, opts?.adminRoles));
		const lowProbes = authProbes.filter((p) => {
			if (opts?.lowPrivRoles?.length) {
				return opts.lowPrivRoles.some((r) => r.trim().toLowerCase() === p.role);
			}
			return !isAdminLikeRole(p.role, opts?.adminRoles);
		});

		// 规则 A：未授权直接访问敏感/管理/对象资源或与认证响应高重合
		if (isSubstantive200(anonProbe) && !anonProbe.isHtml) {
			const refAuth = authProbes.find((p) => isSubstantive200(p));
			const sim = refAuth
				? refAuth.bodySha1 === anonProbe.bodySha1
					? 1
					: computeKeyJaccard(anonProbe.jsonKeys, refAuth.jsonKeys)
				: 0;
			const protectedPath = isAdminLikePath(path) || isObjectResourcePath(path);
			if (protectedPath || (refAuth && (sim >= 0.8 || anonProbe.bodySha1 === refAuth.bodySha1))) {
				findings.push({
					path,
					kind: "unauth_access",
					severity: isAdminLikePath(path) ? "high" : "medium",
					summary: redactVaultSecrets(
						`UNAUTH_ACCESS ${path}: anon=${anonProbe.status} (${anonProbe.bytes}B, keys=[${anonProbe.jsonKeys.slice(0, 6).join(",")}])` +
							(refAuth ? ` vs ${refAuth.role}=${refAuth.status} jaccard=${sim.toFixed(2)}` : ""),
						vault,
					),
					baselineRole: refAuth?.role ?? "auth",
					testedRole: "anon",
					similarity: sim || 1,
					probes,
				});
				continue;
			}
		}

		// 规则 B1：垂直越权（BFLA）— 低权角色在管理/内部路径上获得实质 200
		const okAdmin = adminProbes.find((p) => isSubstantive200(p));
		const okLowForBfla = lowProbes.find((p) => isSubstantive200(p));
		if (okLowForBfla && isAdminLikePath(path)) {
			const sim = okAdmin
				? okAdmin.bodySha1 === okLowForBfla.bodySha1
					? 1
					: computeKeyJaccard(okAdmin.jsonKeys, okLowForBfla.jsonKeys)
				: 1;
			findings.push({
				path,
				kind: "vertical_bfla",
				severity: "high",
				summary: redactVaultSecrets(
					`BFLA ${path}: anon=${anonProbe?.status ?? 0}` +
						(okAdmin ? ` ${okAdmin.role}=${okAdmin.status}(${okAdmin.bytes}B)` : "") +
						` ${okLowForBfla.role}=${okLowForBfla.status}(${okLowForBfla.bytes}B) jaccard=${sim.toFixed(2)}`,
					vault,
				),
				baselineRole: okAdmin?.role ?? "admin",
				testedRole: okLowForBfla.role,
				similarity: sim,
				probes,
			});
			continue;
		}

		// 规则 C：水平越权（BOLA/IDOR）— 两个不同低权同级角色在对象资源路径上均获 200 且结构/正文高度一致
		if (isObjectResourcePath(path) && isBlockedStatus(anonProbe)) {
			const okPeers = lowProbes.filter((p) => isSubstantive200(p));
			let bolaMatched = false;
			for (let i = 0; i < okPeers.length && !bolaMatched; i++) {
				for (let j = i + 1; j < okPeers.length; j++) {
					const a = okPeers[i]!;
					const b = okPeers[j]!;
					const exactSame = a.bodySha1.length > 0 && a.bodySha1 === b.bodySha1;
					const sim = exactSame ? 1 : computeKeyJaccard(a.jsonKeys, b.jsonKeys);
					const sizeClose = Math.abs(a.bytes - b.bytes) <= Math.max(32, Math.max(a.bytes, b.bytes) * 0.15);
					if (exactSame || (a.jsonKeys.length >= 2 && sim >= 0.85 && sizeClose)) {
						findings.push({
							path,
							kind: "horizontal_bola",
							severity: "high",
							summary: redactVaultSecrets(
								`BOLA ${path}: anon=${anonProbe?.status ?? 0} ${a.role}=${a.status}(${a.bytes}B) ${b.role}=${b.status}(${b.bytes}B) jaccard=${sim.toFixed(2)}`,
								vault,
							),
							baselineRole: a.role,
							testedRole: b.role,
							similarity: sim,
							probes,
						});
						bolaMatched = true;
						break;
					}
				}
			}
			if (bolaMatched) continue;
		}

		// 规则 B2：非对象 ID 的受保护路径上，anon 被拦而低权角色与管理员返回高重合非 HTML 数据
		if (!isObjectResourcePath(path) && okLowForBfla && okAdmin && isBlockedStatus(anonProbe) && !okLowForBfla.isHtml) {
			const sim =
				okAdmin.bodySha1 === okLowForBfla.bodySha1
					? 1
					: computeKeyJaccard(okAdmin.jsonKeys, okLowForBfla.jsonKeys);
			if (sim >= 0.8) {
				findings.push({
					path,
					kind: "vertical_bfla",
					severity: "high",
					summary: redactVaultSecrets(
						`BFLA ${path}: anon=${anonProbe?.status ?? 0} ${okAdmin.role}=${okAdmin.status}(${okAdmin.bytes}B) ${okLowForBfla.role}=${okLowForBfla.status}(${okLowForBfla.bytes}B) jaccard=${sim.toFixed(2)}`,
						vault,
					),
					baselineRole: okAdmin.role,
					testedRole: okLowForBfla.role,
					similarity: sim,
					probes,
				});
				continue;
			}
		}
	}

	let fact: AutoFact | null = null;
	if (findings.length > 0) {
		const outLines = findings.map((f) => f.summary);
		const summaryPaths = [...new Set(findings.map((f) => f.path))];
		const kindTags = [...new Set(findings.map((f) => f.kind))].join("/");
		fact = {
			kind: "vuln",
			title: redactVaultSecrets(`多角色鉴权差分疑似越权 (${kindTags}: ${summaryPaths.slice(0, 3).join(", ")})`, vault).slice(0, 120),
			detail: redactVaultSecrets(
				`roles=[${roles.join(",")}] tested=${testedPaths.length} findings=${findings.length} | ${outLines.join(" ; ")}`,
				vault,
			).slice(0, 700),
			command: clip(`auth-diff (${roles.join(",")}) ${parsedBase.origin} [${summaryPaths.slice(0, 5).join(",")}]`, 400),
			output: redactVaultSecrets(clip(outLines.join("\n"), 800), vault),
			meta: {
				paths: summaryPaths,
			},
		};
	}

	return {
		baseUrl: parsedBase.href,
		testedPaths,
		roles,
		matrix,
		findings,
		blockedPaths,
		fact,
	};
}
