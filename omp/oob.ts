/**
 * 女娲 v5.0 一等公民带外（OOB）回调验证通道管理器。
 *
 * 职责：
 * 1. 严格受 `ScopePolicy.oobDomains` 白名单门禁控制：空列表、通配符、未登记域名及黑名单域名一律拒绝。
 * 2. 生成 DNS 标签安全的唯一 Canary（`<projShort>-<nonce>.<domain>`）并以 0o600 原子持久化至 `<root>/.nuwa/oob-canaries.json`。
 * 3. 解析 Interactsh 风格 `{ data: [...] }` 及通用 `{ hits: [...] }` / 数组回调载荷，自动关联已签发 Canary。
 * 4. 轮询授权回调收集端（严格校验 `pollUrl` 主机满足 `isOobHostAllowed` 或 `isHostInScope`，越界默认拦截），
 *    更新命中计数并构建可直通 `verifyExecutionEvidence` 的高信息熵 `AutoFact` 实锤证据。
 *
 * 约束：仅运行时引用 Node 内置模块与 `./scope`，`import type` 引用 `./types` 与 `./autoexec`，严禁运行时 import `./nuwa`。
 */
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { isHostInScope } from "./scope";
import type { AutoFact } from "./autoexec";
import type { ScopePolicy } from "./types";

export interface OobCanary {
	id: string;
	token: string;
	domain: string;
	fqdn: string;
	projectId: string;
	intentId?: string;
	purpose?: string;
	createdAt: string;
	matchedHits: number;
}

export interface OobCallbackHit {
	id: string;
	protocol: "dns" | "http" | "https" | "smtp" | "other";
	fullId: string;
	remoteAddress?: string;
	timestamp: string;
	rawRequest?: string;
	matchedCanaryId?: string;
	matchedToken?: string;
}

export interface OobPollResult {
	ok: boolean;
	polledUrl?: string;
	hits: OobCallbackHit[];
	matchedCanaries: OobCanary[];
	error?: string;
}

export type OobFetchLike = (
	url: string,
	init?: { method?: string; headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

const VALID_DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const IPV4_LITERAL_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const MAX_PERSISTED_CANARIES = 500;

let atomicOobSeq = 0;

function normalizeDomainInput(raw: string): string {
	let s = String(raw ?? "").trim().toLowerCase();
	if (!s) return "";
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
		try {
			s = new URL(s).hostname.toLowerCase();
		} catch {
			return "";
		}
	}
	if (s.startsWith("[") && s.endsWith("]")) {
		s = s.slice(1, -1);
	}
	const colonCount = (s.match(/:/g) ?? []).length;
	if (colonCount === 1) {
		s = s.replace(/:\d{1,5}$/, "");
	}
	return s.replace(/\.+$/, "");
}

function isIpLiteral(host: string): boolean {
	return host.includes(":") || IPV4_LITERAL_RE.test(host);
}

function matchesDenyHost(host: string, rawDeny: string): boolean {
	const deny = normalizeDomainInput(rawDeny);
	if (!deny) return false;
	if (deny === "*") return true;
	if (deny.startsWith("*.")) {
		const base = deny.slice(2);
		return Boolean(base) && host.endsWith(`.${base}`) && host.length > base.length + 1;
	}
	return host === deny;
}

/**
 * 严格校验 OOB 域名或主机是否被 `ScopePolicy.oobDomains` 允许：
 * - 空列表、通配符（查询或配置含 `*`）、IP 字面量、非法域名或未登记域名一律拒绝；
 * - 若命中 `scope.denyHosts` 黑名单则优先拦截；
 * - 支持精确匹配与授权 OOB 域名的合法子域名（`<label>.<oobDomain>`）。
 */
export function isOobHostAllowed(
	domainOrHost: string,
	scope: ScopePolicy,
): { ok: boolean; matchedDomain?: string; reason?: string } {
	const raw = String(domainOrHost ?? "").trim();
	if (!raw) {
		return { ok: false, reason: "OOB 域名为空" };
	}
	if (raw.includes("*")) {
		return { ok: false, reason: `OOB 目标域名不允许包含通配符 (${raw})` };
	}

	const norm = normalizeDomainInput(raw);
	if (!norm || norm.includes("*") || isIpLiteral(norm) || !VALID_DOMAIN_RE.test(norm) || norm.length > 253) {
		return { ok: false, reason: `非法 OOB 域名格式 (${raw})` };
	}

	for (const deny of scope?.denyHosts ?? []) {
		if (matchesDenyHost(norm, deny)) {
			return { ok: false, reason: `OOB 域名 ${norm} 命中黑名单 denyHosts (${deny})` };
		}
	}

	const oobList = Array.isArray(scope?.oobDomains) ? scope.oobDomains : [];
	if (oobList.length === 0) {
		return { ok: false, reason: "ScopePolicy.oobDomains 未配置，禁止使用带外 OOB 通道" };
	}

	let sawWildcardConfig = false;
	for (const rawEntry of oobList) {
		const entryStr = String(rawEntry ?? "").trim();
		if (!entryStr) continue;
		if (entryStr.includes("*")) {
			sawWildcardConfig = true;
			continue;
		}
		const oobNorm = normalizeDomainInput(entryStr);
		if (!oobNorm || isIpLiteral(oobNorm) || !VALID_DOMAIN_RE.test(oobNorm)) {
			continue;
		}
		if (norm === oobNorm || (norm.endsWith(`.${oobNorm}`) && norm.length > oobNorm.length + 1)) {
			return { ok: true, matchedDomain: oobNorm };
		}
	}

	if (sawWildcardConfig) {
		return {
			ok: false,
			reason: `OOB 域名 ${norm} 未匹配有效授权项（ScopePolicy.oobDomains 禁止使用通配符）`,
		};
	}

	return {
		ok: false,
		reason: `OOB 域名 ${norm} 不在授权白名单 oobDomains (${oobList.join(",")}) 内`,
	};
}

function oobCanariesFilePath(root: string): string {
	return join(resolve(root), ".nuwa", "oob-canaries.json");
}

function normalizeStoredCanary(raw: unknown): OobCanary | null {
	if (!raw || typeof raw !== "object") return null;
	const obj = raw as Record<string, unknown>;
	const id = typeof obj.id === "string" ? obj.id.trim() : "";
	const token = typeof obj.token === "string" ? obj.token.trim().toLowerCase() : "";
	const domain = typeof obj.domain === "string" ? normalizeDomainInput(obj.domain) : "";
	const fqdn = typeof obj.fqdn === "string" ? normalizeDomainInput(obj.fqdn) : "";
	const projectId = typeof obj.projectId === "string" ? obj.projectId.trim() : "";
	if (!id || !token || !domain || !fqdn || !projectId) return null;

	const matchedHits =
		typeof obj.matchedHits === "number" && Number.isFinite(obj.matchedHits) && obj.matchedHits >= 0
			? Math.floor(obj.matchedHits)
			: 0;
	const createdAt = typeof obj.createdAt === "string" && obj.createdAt.trim() ? obj.createdAt.trim() : "";
	const intentId = typeof obj.intentId === "string" && obj.intentId.trim() ? obj.intentId.trim() : undefined;
	const purpose = typeof obj.purpose === "string" && obj.purpose.trim() ? obj.purpose.trim() : undefined;

	return {
		id,
		token,
		domain,
		fqdn,
		projectId,
		...(intentId ? { intentId } : {}),
		...(purpose ? { purpose } : {}),
		createdAt,
		matchedHits,
	};
}

/**
 * 读取项目已持久化的 OOB Canary 列表（`<root>/.nuwa/oob-canaries.json`）。
 * 文件不存在或损坏时安全返回空数组。
 */
export function loadOobCanaries(root: string): OobCanary[] {
	const file = oobCanariesFilePath(root);
	if (!existsSync(file)) return [];
	try {
		const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
		const list = Array.isArray(parsed)
			? parsed
			: parsed && typeof parsed === "object" && Array.isArray((parsed as Record<string, unknown>).canaries)
				? ((parsed as Record<string, unknown>).canaries as unknown[])
				: [];
		const out: OobCanary[] = [];
		for (const item of list) {
			const norm = normalizeStoredCanary(item);
			if (norm) out.push(norm);
		}
		return out;
	} catch {
		return [];
	}
}

/**
 * 以 `0o600` 权限原子写入项目 OOB Canary 列表至 `<root>/.nuwa/oob-canaries.json`。
 */
export function saveOobCanaries(root: string, canaries: OobCanary[]): void {
	const file = oobCanariesFilePath(root);
	const dir = dirname(file);
	mkdirSync(dir, { recursive: true });
	const bounded = canaries.slice(-MAX_PERSISTED_CANARIES);
	const payload = `${JSON.stringify(
		{
			schema: 1,
			updatedAt: new Date().toISOString(),
			canaries: bounded,
		},
		null,
		2,
	)}\n`;

	const tmp = `${file}.tmp-${process.pid}-${Date.now()}-${atomicOobSeq++}`;
	writeFileSync(tmp, payload, { encoding: "utf8", mode: 0o600 });
	try {
		chmodSync(tmp, 0o600);
	} catch {
		/* 非 POSIX 文件系统忽略 */
	}
	renameSync(tmp, file);
	try {
		chmodSync(file, 0o600);
	} catch {
		/* 非 POSIX 文件系统忽略 */
	}
}

function buildDnsSafeProjectShort(projectId: string): string {
	const cleaned = String(projectId ?? "")
		.trim()
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
	const short = cleaned.slice(0, 16).replace(/-+$/, "");
	return short || "nuwa";
}

/**
 * 为指定项目与授权 OOB 域名生成唯一 DNS 安全 Canary 并持久化至 `.nuwa/oob-canaries.json`。
 * 若 `domain` 未通过 `isOobHostAllowed(domain, scope)` 校验则立即抛错拦截。
 */
export function generateOobCanary(
	root: string,
	opts: {
		projectId: string;
		domain: string;
		scope: ScopePolicy;
		intentId?: string;
		purpose?: string;
	},
): OobCanary {
	const projectId = String(opts.projectId ?? "").trim();
	if (!projectId) {
		throw new Error("nuwa-oob: projectId 不能为空");
	}
	const check = isOobHostAllowed(opts.domain, opts.scope);
	if (!check.ok) {
		throw new Error(`nuwa-oob N-007: ${check.reason ?? "OOB 域名未获授权"}`);
	}

	const domain = normalizeDomainInput(opts.domain);
	const projShort = buildDnsSafeProjectShort(projectId);
	const nonce = randomBytes(6).toString("hex");
	const token = `${projShort}-${nonce}`;
	const fqdn = `${token}.${domain}`;
	if (token.length > 63 || fqdn.length > 253) {
		throw new Error(`nuwa-oob: 生成的 Canary FQDN 超出 DNS 长度限制 (${fqdn.length})`);
	}

	const canary: OobCanary = {
		id: `oob-${randomBytes(4).toString("hex")}`,
		token,
		domain,
		fqdn,
		projectId,
		...(opts.intentId?.trim() ? { intentId: opts.intentId.trim() } : {}),
		...(opts.purpose?.trim() ? { purpose: opts.purpose.trim() } : {}),
		createdAt: new Date().toISOString(),
		matchedHits: 0,
	};

	const existing = loadOobCanaries(root);
	existing.push(canary);
	saveOobCanaries(root, existing);
	return canary;
}

function normalizeOobProtocol(raw: unknown): OobCallbackHit["protocol"] {
	const s = String(raw ?? "").trim().toLowerCase();
	if (s === "dns" || s === "dns-a" || s === "dns-aaaa" || s === "dns-txt") return "dns";
	if (s === "https") return "https";
	if (s === "http") return "http";
	if (s === "smtp" || s === "smtps") return "smtp";
	return "other";
}

function firstStringField(obj: Record<string, unknown>, keys: readonly string[]): string {
	for (const k of keys) {
		const v = obj[k];
		if (typeof v === "string" && v.trim()) {
			return v.trim();
		}
	}
	return "";
}

function extractRawHitObjects(raw: unknown): Record<string, unknown>[] {
	let parsed: unknown = raw;
	if (typeof raw === "string") {
		const trimmed = raw.trim();
		if (!trimmed) return [];
		try {
			parsed = JSON.parse(trimmed);
		} catch {
			// 尝试按 NDJSON 逐行解析
			const ndItems: Record<string, unknown>[] = [];
			for (const line of trimmed.split("\n")) {
				const l = line.trim();
				if (!l) continue;
				try {
					const obj = JSON.parse(l);
					if (obj && typeof obj === "object" && !Array.isArray(obj)) {
						ndItems.push(obj as Record<string, unknown>);
					}
				} catch {
					/* 跳过非 JSON 行 */
				}
			}
			return ndItems;
		}
	}

	let rawList: unknown[] = [];
	if (Array.isArray(parsed)) {
		rawList = parsed;
	} else if (parsed && typeof parsed === "object") {
		const obj = parsed as Record<string, unknown>;
		if (Array.isArray(obj.data)) {
			rawList = obj.data;
		} else if (Array.isArray(obj.hits)) {
			rawList = obj.hits;
		} else if (Array.isArray(obj.interactions)) {
			rawList = obj.interactions;
		} else if (Array.isArray(obj.events)) {
			rawList = obj.events;
		} else if (
			typeof obj.full_id === "string" ||
			typeof obj["full-id"] === "string" ||
			typeof obj.fullId === "string" ||
			typeof obj.host === "string" ||
			typeof obj.url === "string"
		) {
			rawList = [obj];
		}
	}

	const out: Record<string, unknown>[] = [];
	for (const item of rawList) {
		if (typeof item === "string") {
			const trimmed = item.trim();
			if (!trimmed) continue;
			try {
				const inner = JSON.parse(trimmed);
				if (inner && typeof inner === "object" && !Array.isArray(inner)) {
					out.push(inner as Record<string, unknown>);
				}
			} catch {
				/* 跳过非 JSON 字符串条目 */
			}
		} else if (item && typeof item === "object" && !Array.isArray(item)) {
			out.push(item as Record<string, unknown>);
		}
	}
	return out;
}

/**
 * 解析 Interactsh `{ data: [...] }`、通用 `{ hits: [...] }` 或数组回调载荷，并与已签发 Canary 做令牌/FQDN 关联。
 */
export function parseOobCallbackPayload(raw: unknown, canaries: readonly OobCanary[]): OobCallbackHit[] {
	const items = extractRawHitObjects(raw);
	if (items.length === 0) return [];

	// 优先匹配更长的 FQDN/Token，避免短前缀误关联
	const sortedCanaries = [...canaries].sort((a, b) => b.fqdn.length - a.fqdn.length);
	const out: OobCallbackHit[] = [];

	for (const item of items) {
		const protocol = normalizeOobProtocol(item.protocol ?? item.type ?? item.proto);
		const fullId = firstStringField(item, [
			"full_id",
			"full-id",
			"fullId",
			"unique_id",
			"unique-id",
			"uniqueId",
			"host",
			"qname",
			"domain",
			"url",
		]);
		const rawRequest = firstStringField(item, ["raw_request", "raw-request", "rawRequest", "raw", "request"]);
		const remoteAddress = firstStringField(item, [
			"remote_address",
			"remote-address",
			"remoteAddress",
			"remote_addr",
			"remoteIp",
			"source_ip",
			"ip",
		]);
		const timestamp =
			firstStringField(item, ["timestamp", "ts", "created_at", "createdAt", "time"]) || new Date().toISOString();

		if (!fullId && !rawRequest) continue;

		const haystack = [
			fullId,
			firstStringField(item, ["host", "url", "qname", "domain"]),
			rawRequest,
		]
			.filter(Boolean)
			.join(" ")
			.toLowerCase();

		let matched: OobCanary | undefined;
		for (const c of sortedCanaries) {
			if (haystack.includes(c.fqdn.toLowerCase()) || haystack.includes(c.token.toLowerCase())) {
				matched = c;
				break;
			}
		}

		const explicitId = firstStringField(item, ["id", "hit_id", "hitId"]);
		const id =
			explicitId ||
			`hit-${createHash("sha256")
				.update(`${protocol}|${fullId}|${remoteAddress}|${timestamp}|${rawRequest.slice(0, 128)}`)
				.digest("hex")
				.slice(0, 12)}`;

		out.push({
			id,
			protocol,
			fullId: fullId || (matched?.fqdn ?? "unknown"),
			...(remoteAddress ? { remoteAddress } : {}),
			timestamp,
			...(rawRequest ? { rawRequest: rawRequest.slice(0, 4096) } : {}),
			...(matched ? { matchedCanaryId: matched.id, matchedToken: matched.token } : {}),
		});
	}

	return out;
}

/**
 * 轮询 OOB 回调收集端：
 * - 先校验 `pollUrl` 主机满足 `isOobHostAllowed` 或 `isHostInScope`（越界立即拦截，绝不发起请求）；
 * - 解析响应并自动回写命中 Canary 的 `matchedHits` 计数至 `.nuwa/oob-canaries.json`。
 */
export async function pollOobCallbacks(
	root: string,
	opts: {
		pollUrl: string;
		scope: ScopePolicy;
		authToken?: string;
		fetchFn?: OobFetchLike;
		timeoutMs?: number;
	},
): Promise<OobPollResult> {
	const rawUrl = String(opts.pollUrl ?? "").trim();
	let parsedUrl: URL;
	try {
		parsedUrl = new URL(rawUrl);
	} catch {
		return {
			ok: false,
			polledUrl: rawUrl,
			hits: [],
			matchedCanaries: [],
			error: `nuwa-oob N-007: 非法 OOB 轮询 URL (${rawUrl})`,
		};
	}

	if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
		return {
			ok: false,
			polledUrl: rawUrl,
			hits: [],
			matchedCanaries: [],
			error: `nuwa-oob N-007: OOB 轮询仅允许 http/https 协议 (${parsedUrl.protocol})`,
		};
	}

	const pollHost = parsedUrl.hostname.replace(/^\[|\]$/g, "").toLowerCase();
	const oobAllowed = isOobHostAllowed(pollHost, opts.scope);
	const scopeAllowed = oobAllowed.ok ? { ok: true } : isHostInScope(pollHost, opts.scope);
	if (!oobAllowed.ok && !scopeAllowed.ok) {
		return {
			ok: false,
			polledUrl: rawUrl,
			hits: [],
			matchedCanaries: [],
			error: `nuwa-oob N-007: OOB 轮询目标越界 (${pollHost}) — ${scopeAllowed.reason ?? oobAllowed.reason ?? "不在授权范围内"}`,
		};
	}

	const timeoutMs =
		typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
			? Math.floor(opts.timeoutMs)
			: 10_000;
	const fetchImpl: OobFetchLike | undefined =
		opts.fetchFn ?? (typeof globalThis.fetch === "function" ? (globalThis.fetch as unknown as OobFetchLike) : undefined);
	if (!fetchImpl) {
		return {
			ok: false,
			polledUrl: rawUrl,
			hits: [],
			matchedCanaries: [],
			error: "nuwa-oob: 运行时缺少可用的 fetch 实现",
		};
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const headers: Record<string, string> = {
			Accept: "application/json",
		};
		if (opts.authToken && opts.authToken.trim()) {
			headers.Authorization = opts.authToken.trim();
		}

		const res = await fetchImpl(rawUrl, {
			method: "GET",
			headers,
			signal: controller.signal,
		});

		if (!res.ok) {
			return {
				ok: false,
				polledUrl: rawUrl,
				hits: [],
				matchedCanaries: [],
				error: `nuwa-oob: 轮询返回 HTTP ${res.status}`,
			};
		}

		const bodyText = await res.text();
		const canaries = loadOobCanaries(root);
		const hits = parseOobCallbackPayload(bodyText, canaries);

		const hitCountByCanary = new Map<string, number>();
		for (const h of hits) {
			if (!h.matchedCanaryId) continue;
			hitCountByCanary.set(h.matchedCanaryId, (hitCountByCanary.get(h.matchedCanaryId) ?? 0) + 1);
		}

		const matchedCanaries: OobCanary[] = [];
		if (hitCountByCanary.size > 0) {
			for (const c of canaries) {
				const inc = hitCountByCanary.get(c.id);
				if (inc && inc > 0) {
					c.matchedHits += inc;
					matchedCanaries.push({ ...c });
				}
			}
			saveOobCanaries(root, canaries);
		}

		return {
			ok: true,
			polledUrl: rawUrl,
			hits,
			matchedCanaries,
		};
	} catch (err) {
		return {
			ok: false,
			polledUrl: rawUrl,
			hits: [],
			matchedCanaries: [],
			error: `nuwa-oob: 轮询失败 — ${err instanceof Error ? err.message : String(err)}`,
		};
	} finally {
		clearTimeout(timer);
	}
}

/**
 * 将命中 OOB 回调的 Canary 与记录组装为高信息熵、非模板化的 `AutoFact` (`kind: "vuln"`) 证据，
 * 确保 `output` 含 `OOB_CALLBACK_VERIFIED`、协议、Canary FQDN、源地址与时间戳，稳定通过 `verifyExecutionEvidence`。
 */
export function buildOobEvidenceFact(canary: OobCanary, hits: readonly OobCallbackHit[]): AutoFact {
	const matched = hits.filter(
		(h) =>
			h.matchedCanaryId === canary.id ||
			h.matchedToken === canary.token ||
			h.fullId.toLowerCase().includes(canary.token.toLowerCase()),
	);
	const effectiveHits = matched.length > 0 ? matched : [...hits];
	const protocols = [...new Set(effectiveHits.map((h) => h.protocol))];
	const protoText = protocols.join(",") || "unknown";
	const remotes = [...new Set(effectiveHits.map((h) => h.remoteAddress).filter(Boolean))];
	const firstTs = effectiveHits[0]?.timestamp ?? new Date().toISOString();

	const outputLines: string[] = [
		`OOB_CALLBACK_VERIFIED canary=${canary.id} token=${canary.token} fqdn=${canary.fqdn} hits=${effectiveHits.length} protocols=${protoText}`,
	];
	for (const hit of effectiveHits.slice(0, 10)) {
		outputLines.push(
			`OOB_HIT id=${hit.id} protocol=${hit.protocol} fullId=${hit.fullId} remote=${hit.remoteAddress ?? "unknown"} ts=${hit.timestamp}`,
		);
		if (hit.rawRequest) {
			const preview = hit.rawRequest.replace(/[\r\n]+/g, " ").trim().slice(0, 200);
			if (preview) {
				outputLines.push(`OOB_RAW ${preview}`);
			}
		}
	}

	const detailParts = [
		`canary=${canary.id}`,
		`fqdn=${canary.fqdn}`,
		`hits=${effectiveHits.length}`,
		`protocols=${protoText}`,
		`remotes=${remotes.join(",") || "unknown"}`,
		`firstTs=${firstTs}`,
	];
	if (canary.purpose) {
		detailParts.push(`purpose=${canary.purpose}`);
	}

	return {
		kind: "vuln",
		title: `OOB 带外回调实锤 (${protoText}): ${canary.fqdn}`.slice(0, 120),
		detail: detailParts.join(" "),
		command: `oob-poll ${canary.fqdn} project=${canary.projectId}${canary.intentId ? ` intent=${canary.intentId}` : ""}`,
		output: outputLines.join("\n"),
	};
}
