/**
 * 女娲 v8.0.0 三元组表面分域去重、`AttemptedEntry` 已尝试台账与冷却窗口管理模块。
 *
 * 约束：纯底层模块，仅依赖 `./types` 与 `./storage-io`，严禁导入 `./nuwa`、`./graph` 或 `./graph-planner`。
 */
import { nowIso, sha } from "./storage-io";
import type {
	AttemptedEntry,
	Cfg,
	Fact,
	FactKind,
	Intent,
	NuwaState,
	Phase,
	SurfaceDomain,
} from "./types";

// ============================================================================
// 表面分域、规范化三元组去重与已尝试冷却过滤
// ============================================================================

const DEFAULT_NOVELTY_THRESHOLD = 8;
const DEFAULT_BLOCKED_COOLDOWN_MS = 300_000;

export function readEnvCooldownMs(cfg?: Partial<Cfg>): number {
	if (typeof cfg?.blockedCooldownMs === "number" && Number.isFinite(cfg.blockedCooldownMs) && cfg.blockedCooldownMs >= 0) {
		return cfg.blockedCooldownMs;
	}
	const raw = process.env.NUWA_BLOCKED_COOLDOWN_MS;
	if (raw !== undefined && raw.trim() !== "") {
		const n = Number(raw);
		if (Number.isFinite(n) && n >= 0) return n;
	}
	return DEFAULT_BLOCKED_COOLDOWN_MS;
}

export function readNoveltyThreshold(cfg?: Partial<Cfg>): number {
	if (
		typeof cfg?.noveltyStallThreshold === "number" &&
		Number.isFinite(cfg.noveltyStallThreshold) &&
		cfg.noveltyStallThreshold >= 1
	) {
		return Math.floor(cfg.noveltyStallThreshold);
	}
	const raw = process.env.NUWA_NOVELTY_STALL_THRESHOLD;
	if (raw !== undefined && raw.trim() !== "") {
		const n = Number(raw);
		if (Number.isFinite(n) && n >= 1) return Math.floor(n);
	}
	return DEFAULT_NOVELTY_THRESHOLD;
}

/** 规范化目标键（#21, #43）：统一处理路径尾斜杠/查询串排序、host:port/tcp 与 URL 默认端口。 */
export function normalizeTargetKey(raw: string, defaultHost?: string): string {
	const trimmed = (raw ?? "").trim();
	if (!trimmed) return defaultHost ? defaultHost.toLowerCase() : "/";

	const prefixMatch = /^(port|path|host):(.*)$/i.exec(trimmed);
	const explicitDomain = prefixMatch ? (prefixMatch[1]!.toLowerCase() as SurfaceDomain) : undefined;
	const body = (prefixMatch ? prefixMatch[2]! : trimmed).trim();
	if (!body) return defaultHost ? defaultHost.toLowerCase() : "/";

	const normPathAndQuery = (rawPath: string): string => {
		const hashIdx = rawPath.indexOf("#");
		const noHash = hashIdx >= 0 ? rawPath.slice(0, hashIdx) : rawPath;
		const qIdx = noHash.indexOf("?");
		const pathOnly = (qIdx >= 0 ? noHash.slice(0, qIdx) : noHash).replace(/\/{2,}/g, "/");
		const cleanPath = pathOnly.length > 1 ? pathOnly.replace(/\/+$/, "") : pathOnly || "/";
		if (qIdx < 0) return cleanPath;
		const params = new URLSearchParams(noHash.slice(qIdx + 1));
		params.sort();
		const qs = params.toString();
		return qs ? `${cleanPath}?${qs}` : cleanPath;
	};

	if (body.startsWith("/") || explicitDomain === "path") {
		const ensured = body.startsWith("/") ? body : `/${body}`;
		return normPathAndQuery(ensured);
	}

	const portMatch = /^(?:([a-zA-Z0-9.-]+):)?(\d{1,5})(?:\/(?:tcp|udp))?$/i.exec(body);
	if (portMatch) {
		const hostPart = (portMatch[1] || defaultHost || "").toLowerCase();
		return hostPart ? `${hostPart}:${portMatch[2]}` : `port:${portMatch[2]}`;
	}

	if (/^https?:\/\//i.test(body)) {
		try {
			const u = new URL(body);
			const host = u.hostname.toLowerCase();
			const isDefaultPort =
				!u.port ||
				(u.protocol === "http:" && u.port === "80") ||
				(u.protocol === "https:" && u.port === "443");
			const portSuffix = isDefaultPort ? "" : `:${u.port}`;
			const pq = normPathAndQuery(`${u.pathname}${u.search}`);
			if (pq !== "/") {
				if (defaultHost && host === defaultHost.toLowerCase() && isDefaultPort) {
					return pq;
				}
				return `${host}${portSuffix}${pq}`;
			}
			return `${host}${portSuffix}`;
		} catch {
			return body.toLowerCase();
		}
	}

	const slashIdx = body.indexOf("/");
	if (slashIdx > 0 && !/^\d+\/(?:tcp|udp)$/i.test(body)) {
		const hostPart = body.slice(0, slashIdx).toLowerCase().replace(/:(?:80|443)$/, "");
		const pq = normPathAndQuery(body.slice(slashIdx));
		if (defaultHost && hostPart === defaultHost.toLowerCase()) {
			return pq;
		}
		return `${hostPart}${pq}`;
	}

	return body.toLowerCase().replace(/\/+$/, "");
}

/** 显式推断目标键所属的攻击面分域（#25）："port" | "path" | "host"。 */
export function inferSurfaceDomain(targetKey: string): SurfaceDomain {
	const raw = (targetKey ?? "").trim();
	if (!raw) return "host";
	if (/^port:/i.test(raw)) return "port";
	if (/^path:/i.test(raw)) return "path";
	if (/^host:/i.test(raw)) return "host";

	if (raw.startsWith("/")) return "path";

	if (/^https?:\/\//i.test(raw)) {
		try {
			const u = new URL(raw);
			if ((u.pathname && u.pathname !== "/") || u.search) return "path";
			if (u.port) return "port";
			return "host";
		} catch {
			/* fallthrough */
		}
	}

	if (/^(?:[a-zA-Z0-9.-]+:)?\d{1,5}(?:\/(?:tcp|udp))?$/i.test(raw)) {
		return "port";
	}

	if (raw.includes("/") && !/^\d{1,5}\/(?:tcp|udp)$/i.test(raw)) {
		return "path";
	}

	return "host";
}

/** 跨层派生校验（#25）：从某一 surfaceDomain 派生另一 surfaceDomain 时，必须携带有效非证伪的显式前置事实。 */
export function canDeriveCrossSurface(
	st: NuwaState,
	fromDomain: SurfaceDomain | undefined,
	toDomain: SurfaceDomain | undefined,
	fromFactIds: string[],
): boolean {
	if (!fromDomain || !toDomain || fromDomain === toDomain) return true;
	const validFacts = (fromFactIds ?? [])
		.map((fid) => st.facts[fid])
		.filter((f): f is Fact => Boolean(f) && f.kind !== "blocked" && f.verifyStage !== "rejected");
	if (validFacts.length === 0) return false;
	// 端口层 -> 路径层：必须有证明 HTTP/Web 端点或服务可达的事实，纯关闭端口或无关事实不可跨层派生路径
	if (fromDomain === "port" && toDomain === "path") {
		return validFacts.some((f) => {
			if (f.kind === "endpoint" || f.kind === "cred" || f.kind === "vuln" || f.kind === "loot") return true;
			if (f.kind === "service") {
				const blob = `${f.title} ${f.detail} ${f.output ?? ""} ${f.meta?.server ?? ""}`;
				return (
					(typeof f.meta?.status === "number" && f.meta.status > 0) ||
					(f.meta?.paths?.length ?? 0) > 0 ||
					/\b(?:http|https|html|nginx|apache|caddy|iis|express|nextjs|tomcat|jetty|werkzeug|uvicorn|gunicorn|200|301|302|401|403|404|405)\b/i.test(blob)
				);
			}
			return false;
		});
	}
	// 路径层 -> 端口层：必须有显式发现新主机资产或端口服务的事实（禁止路径 403 后无依据回头重扫死端口）
	if (fromDomain === "path" && toDomain === "port") {
		return validFacts.some((f) => f.kind === "asset" || f.kind === "service" || f.kind === "cred" || f.kind === "vuln");
	}
	return true;
}

/** 自动推断意图的期望事实类型 expectedKind（#29, #43：优先显式声明、证据契约、结构化规则键与阶段语义，避免泛化标题词污染三元组）。 */
export function inferExpectedKind(spec: {
	key?: string;
	phase?: Phase;
	title?: string;
	detail?: string;
	expectedKind?: FactKind;
}): FactKind {
	if (spec.expectedKind) return spec.expectedKind;
	const detail = spec.detail ?? "";
	const m = /证据\s*[:：]\s*kind\s*=\s*(target|asset|service|endpoint|cred|vuln|flag|loot|note)\b/i.exec(detail);
	if (m) return m[1]!.toLowerCase() as FactKind;

	const canonKey = (spec.key ?? "").replace(/^e\d+:/i, "").toLowerCase();
	if (canonKey.startsWith("svc:") || canonKey.endsWith(":http") || canonKey.endsWith(":ports")) return "service";
	if (canonKey.startsWith("san:")) return "asset";
	if (canonKey.startsWith("enum:")) return "service";
	if (canonKey.startsWith("ep:") || canonKey.startsWith("exp:") || canonKey.startsWith("verify-vuln:")) return "vuln";
	if (canonKey.startsWith("reuse:") || canonKey.endsWith(":creds")) return "cred";
	if (canonKey.startsWith("pivot:") || canonKey.endsWith(":loot")) return "loot";
	if (canonKey.endsWith(":flag")) return "flag";
	if (canonKey.startsWith("loot:") || canonKey.startsWith("reflect:") || canonKey.startsWith("report:")) return "note";
	if (canonKey.startsWith("surface:") || canonKey.endsWith(":dirs") || canonKey.endsWith(":tlsjs")) return "endpoint";

	if (spec.phase) {
		switch (spec.phase) {
			case "recon":
				return "service";
			case "surface":
				return "endpoint";
			case "vuln":
			case "exploit":
				return "vuln";
			case "post":
				return "loot";
			case "report":
				return "note";
		}
	}

	const title = (spec.title ?? "").toLowerCase();
	if (/\bflag\b/.test(title)) return "flag";
	if (/(sql\s*注入|sqli|xss|ssti|ssrf|rce|命令注入|路径穿越|lfi|越权|idor|绕过|漏洞|cve-|审计)/i.test(title)) return "vuln";
	if (/(凭据|口令|token|cookie|cred)/i.test(title)) return "cred";
	if (/(端口|nmap|服务枚举|服务深挖|存活)/i.test(title)) return "service";
	if (/(路由|目录|接口|api|endpoint|爬取|参数)/i.test(title)) return "endpoint";
	if (/(子域|虚拟主机|san|资产)/i.test(title)) return "asset";

	return "note";
}

/** 从意图 key / title / detail 中提取目标标识并规范化（#21, #25, #43）。 */
export function extractIntentTargetKey(
	spec: { key?: string; title?: string; detail?: string; targetKey?: string; phase?: Phase },
	defaultHost = "",
): string {
	if (spec.targetKey && spec.targetKey.trim()) {
		return normalizeTargetKey(spec.targetKey, defaultHost);
	}
	const rawKey = (spec.key ?? "").replace(/^e\d+:/i, "");
	if (rawKey.startsWith("svc:")) {
		const port = rawKey.split(":")[2];
		if (port) return normalizeTargetKey(`${defaultHost || "port"}:${port}`, defaultHost);
	}
	if (rawKey.startsWith("ep:")) {
		const parts = rawKey.split(":");
		if (parts.length >= 3) return normalizeTargetKey(parts.slice(2).join(":"), defaultHost);
	}
	if (rawKey.startsWith("san:")) {
		const dom = rawKey.split(":").slice(2).join(":");
		if (dom) return normalizeTargetKey(dom, defaultHost);
	}

	const blob = `${spec.title ?? ""}\n${spec.detail ?? ""}`;
	const urlHit = blob.match(/https?:\/\/[^\s"'`）)，。；;、<>]+/i)?.[0];
	if (urlHit) {
		return normalizeTargetKey(urlHit.replace(/[.,;:!?]+$/, ""), defaultHost);
	}
	const hostPortHit = blob.match(/\b([a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?:\d{1,5})\b/)?.[1];
	if (hostPortHit) {
		return normalizeTargetKey(hostPortHit, defaultHost);
	}
	const portProtoHit = blob.match(/\b(\d{1,5}\/(?:tcp|udp))\b/i)?.[1];
	if (portProtoHit) {
		return normalizeTargetKey(portProtoHit, defaultHost);
	}
	const pathHit = (spec.title ?? "").match(/(?:^|[\s"'(:])(\/[A-Za-z0-9._~:/?=&%-]{1,120})/)?.[1]
		?? (spec.detail ?? "").match(/(?:^|[\s"'(:])(\/[A-Za-z0-9._~:/?=&%-]{1,120})/)?.[1];
	if (pathHit && !pathHit.startsWith("//") && !pathHit.startsWith("/tmp/") && !pathHit.startsWith("/usr/") && !pathHit.startsWith("/etc/") && !pathHit.startsWith("/var/")) {
		return normalizeTargetKey(pathHit, defaultHost);
	}
	if (rawKey && !rawKey.startsWith("custom:")) {
		return `seed:${rawKey}`;
	}
	return defaultHost ? defaultHost.toLowerCase() : "/";
}

function normalizeHintForHash(rawHint: string): string {
	return rawHint
		.replace(/\bf\d{3,}\b/g, "<fact>")
		.replace(/\bi\d{3,}\b/g, "<intent>")
		.replace(/https?:\/\/[^\s"'`]+/gi, "<url>")
		.replace(/\s+/g, " ")
		.trim()
		.toLowerCase();
}

/**
 * 构建规划/展图的规范化三元组去重键 (expectedKind, normalizeTargetKey(target), hintHash)（#43）。
 */
export function buildIntentDedupKey(
	spec: {
		expectedKind?: FactKind;
		targetKey?: string;
		target?: string;
		hint?: string;
		detail?: string;
		title?: string;
		phase?: Phase;
		key?: string;
		surfaceDomain?: SurfaceDomain;
	},
	defaultHost = "",
): {
	dedupKey: string;
	expectedKind: FactKind;
	targetKey: string;
	surfaceDomain: SurfaceDomain;
	hintHash: string;
} {
	const expectedKind = inferExpectedKind(spec);
	const targetKey = spec.target
		? normalizeTargetKey(spec.target, defaultHost)
		: extractIntentTargetKey(spec, defaultHost);
	const surfaceDomain = spec.surfaceDomain ?? inferSurfaceDomain(targetKey.startsWith("seed:") ? (defaultHost || "/") : targetKey);

	// 对内置结构化规则（如 svc:<fid>:<port> / ep:<fid>:<path> / san:<fid>:<dom>）使用稳定的动作族标识，消除 <fid> 噪声
	const rawKey = (spec.key ?? "").replace(/^e\d+:/i, "");
	let semanticHintSource: string;
	if (spec.hint !== undefined && spec.hint.trim() !== "") {
		semanticHintSource = normalizeHintForHash(spec.hint);
	} else if (/^(?:svc|ep|san):/.test(rawKey)) {
		semanticHintSource = rawKey.split(":")[0]!;
	} else if (spec.detail && spec.detail.trim() !== "") {
		semanticHintSource = normalizeHintForHash(spec.detail);
	} else {
		semanticHintSource = normalizeHintForHash(spec.title ?? rawKey);
	}

	const hintHash = sha(semanticHintSource || "default", 10);
	const dedupKey = `${expectedKind}|${targetKey}|${hintHash}`;
	return { dedupKey, expectedKind, targetKey, surfaceDomain, hintHash };
}

function attemptRegistryKey(expectedKind: string, surfaceDomain: SurfaceDomain, targetKey: string): string {
	return `${expectedKind}|${surfaceDomain}|${targetKey}`;
}

export function recordAttemptedIntent(st: NuwaState, intent: Intent, status: "done" | "blocked"): void {
	const host = st.project?.host ?? "";
	const expectedKind = intent.expectedKind ?? inferExpectedKind(intent);
	const targetKey = intent.targetKey ? normalizeTargetKey(intent.targetKey, host) : extractIntentTargetKey(intent, host);
	const surfaceDomain = intent.surfaceDomain ?? inferSurfaceDomain(targetKey.startsWith("seed:") ? (host || "/") : targetKey);
	const regKey = attemptRegistryKey(expectedKind, surfaceDomain, targetKey);
	if (!st.runtime.attemptedKeys) st.runtime.attemptedKeys = {};
	const prev = st.runtime.attemptedKeys[regKey];
	const mergedFrom = [...new Set([...(prev?.from ?? []), ...(intent.from ?? [])])];
	st.runtime.attemptedKeys[regKey] = {
		key: regKey,
		expectedKind,
		targetKey,
		surfaceDomain,
		status,
		at: intent.doneAt ?? nowIso(),
		from: mergedFrom,
	};
}

export function hasUnlockingPrerequisiteFacts(
	st: NuwaState,
	lastAttemptAt: string,
	recordedFrom: string[],
	candidateFrom: string[],
	strictAutoDerive = false,
): boolean {
	const recordedSet = new Set(recordedFrom);
	const lastTs = Date.parse(lastAttemptAt);

	// 检查显式传入的 candidateFrom 中是否包含上次尝试时尚未关联的有效新前置事实
	for (const fid of candidateFrom) {
		const f = st.facts[fid];
		if (!f || f.kind === "blocked" || f.verifyStage === "rejected") continue;
		if (!recordedSet.has(fid)) {
			if (!strictAutoDerive) {
				return true;
			}
			// 自动派生（deriveFromFacts）场景：同质的 service/endpoint 重复发现不算新解锁条件，只有 cred/vuln/loot 等高阶新前置才解锁重测
			if (f.kind === "cred" || f.kind === "vuln" || f.kind === "loot") {
				return true;
			}
		}
	}

	// 全局检查：若在上次结案时间之后新增了有效凭据（cred），允许重测曾被 401/403 阻断的目标
	if (Number.isFinite(lastTs)) {
		for (const f of Object.values(st.facts)) {
			if (f.kind === "cred" && f.verifyStage !== "rejected") {
				const fTs = Date.parse(f.createdAt);
				if (Number.isFinite(fTs) && fTs > lastTs && !recordedSet.has(f.id)) {
					return true;
				}
			}
		}
	}
	return false;
}

/**
 * 已尝试过滤器 attempted(st, kind, targetKey, opts)（#21, #25）：
 * 覆盖 done 与 blocked 状态，严格按 surfaceDomain 隔离（端口 blocked 不污染路径），
 * 同键未传 force=true 且无新前置事实时返回 true 抑制重派生。
 */
export function attempted(
	st: NuwaState,
	kind: FactKind | string,
	targetKey: string,
	opts?: {
		force?: boolean;
		from?: string[];
		surfaceDomain?: SurfaceDomain;
		strictAutoDerive?: boolean;
	},
): boolean {
	if (opts?.force === true) return false;
	const host = st.project?.host ?? "";
	const normTarget = normalizeTargetKey(targetKey, host);
	const domain = opts?.surfaceDomain ?? inferSurfaceDomain(normTarget.startsWith("seed:") ? (host || "/") : normTarget);
	const regKey = attemptRegistryKey(kind, domain, normTarget);

	const regHit = st.runtime?.attemptedKeys?.[regKey];
	const matchingIntents = Object.values(st.intents ?? {}).filter((it) => {
		if (it.status !== "done" && it.status !== "blocked") return false;
		const itKind = it.expectedKind ?? inferExpectedKind(it);
		if (itKind !== kind) return false;
		const itTarget = it.targetKey ? normalizeTargetKey(it.targetKey, host) : extractIntentTargetKey(it, host);
		if (itTarget !== normTarget) return false;
		const itDomain = it.surfaceDomain ?? inferSurfaceDomain(itTarget.startsWith("seed:") ? (host || "/") : itTarget);
		return itDomain === domain;
	});

	if (!regHit && matchingIntents.length === 0) return false;

	const recordedFrom = new Set<string>(regHit?.from ?? []);
	let latestAt = regHit?.at ?? "";
	for (const it of matchingIntents) {
		for (const fid of it.from ?? []) recordedFrom.add(fid);
		const at = it.doneAt ?? it.createdAt;
		if (!latestAt || at > latestAt) latestAt = at;
	}

	if (
		hasUnlockingPrerequisiteFacts(
			st,
			latestAt,
			[...recordedFrom],
			opts?.from ?? [],
			Boolean(opts?.strictAutoDerive),
		)
	) {
		return false;
	}

	return true;
}

export const hasAttempted = attempted;

/** 检查目标键是否处于 blocked 冷却窗口内（#43, #25：按 surfaceDomain 隔离，端口不污染路径）。 */
export function isTargetInBlockedCooldown(
	st: NuwaState,
	targetKey: string,
	opts?: {
		surfaceDomain?: SurfaceDomain;
		cooldownMs?: number;
		now?: number;
		force?: boolean;
		from?: string[];
		strictAutoDerive?: boolean;
	},
): boolean {
	if (opts?.force === true) return false;
	const cooldownMs = opts?.cooldownMs ?? readEnvCooldownMs();
	if (cooldownMs <= 0) return false;
	const now = opts?.now ?? Date.now();
	const host = st.project?.host ?? "";
	const normTarget = normalizeTargetKey(targetKey, host);
	if (normTarget.startsWith("seed:")) return false;
	const domain = opts?.surfaceDomain ?? inferSurfaceDomain(normTarget);

	const blockedMatches = Object.values(st.intents ?? {}).filter((it) => {
		if (it.status !== "blocked") return false;
		const itTarget = it.targetKey ? normalizeTargetKey(it.targetKey, host) : extractIntentTargetKey(it, host);
		if (itTarget !== normTarget) return false;
		const itDomain = it.surfaceDomain ?? inferSurfaceDomain(itTarget);
		if (itDomain !== domain) return false;
		const blockedTs = Date.parse(it.doneAt ?? it.createdAt);
		return !Number.isFinite(blockedTs) || now - blockedTs < cooldownMs;
	});

	let regMatch: AttemptedEntry | undefined;
	for (const entry of Object.values(st.runtime?.attemptedKeys ?? {})) {
		if (entry.status !== "blocked") continue;
		if (entry.surfaceDomain !== domain || normalizeTargetKey(entry.targetKey, host) !== normTarget) continue;
		const ts = Date.parse(entry.at);
		if (!Number.isFinite(ts) || now - ts < cooldownMs) {
			regMatch = entry;
			break;
		}
	}

	if (blockedMatches.length === 0 && !regMatch) return false;

	const recordedFrom = new Set<string>(regMatch?.from ?? []);
	let latestAt = regMatch?.at ?? "";
	for (const it of blockedMatches) {
		for (const fid of it.from ?? []) recordedFrom.add(fid);
		const at = it.doneAt ?? it.createdAt;
		if (!latestAt || at > latestAt) latestAt = at;
	}

	if (
		hasUnlockingPrerequisiteFacts(
			st,
			latestAt,
			[...recordedFrom],
			opts?.from ?? [],
			Boolean(opts?.strictAutoDerive),
		)
	) {
		return false;
	}

	return true;
}

/** 计算重复尝试比率 repeatRatio = 1 - distinct/total（#21）。 */
export function computeRepeatRatio(st: NuwaState): { total: number; distinct: number; repeatRatio: number } {
	const host = st.project?.host ?? "";
	const intents = Object.values(st.intents ?? {});
	const sigs = intents.map((it) => {
		const k = it.expectedKind ?? inferExpectedKind(it);
		const t = it.targetKey ? normalizeTargetKey(it.targetKey, host) : extractIntentTargetKey(it, host);
		return `${k}|${t}`;
	});
	const seen = new Set(sigs);
	for (const entry of Object.values(st.runtime?.attemptedKeys ?? {})) {
		const sig = `${entry.expectedKind}|${normalizeTargetKey(entry.targetKey, host)}`;
		if (!seen.has(sig)) {
			sigs.push(sig);
			seen.add(sig);
		}
	}
	const total = Math.max(intents.length, sigs.length);
	if (total === 0) return { total: 0, distinct: 0, repeatRatio: 0 };
	const distinct = seen.size;
	return {
		total,
		distinct,
		repeatRatio: Math.max(0, Math.min(1, Number((1 - distinct / total).toFixed(4)))),
	};
}
