/**
 * 女娲 v6.0.0 自主闭环驱动模块（Autonomous AuthDiff & OOB Closed-Loop Engine）。
 *
 * 职责：
 * 1. AuthDiff 自主闭环：将多角色只读鉴权差分从手动 `/nuwa authdiff` 升级为主循环自动驱动能力。
 *    - 判定 Web 评估模式与多角色/新凭据触发条件（`shouldAutoTriggerAuthDiff`）；
 *    - 从事实图与意图队列智能抽取并排序高价值可测 API/对象端点（`collectTestableAuthPaths`）；
 *    - 按「角色集合 + 路径集合」哈希做持久化冷却防重，调用 `runAuthDiffMatrix`；
 *    - 严格遵守 Soft-404 去噪、双盲复验闸门（`verifyStage="candidate"` + `verify-vuln:<fid>`）与零凭据泄露。
 * 2. OOB 自主播撒与轮询闭环：将带外回调通道升级为自动规划与节流轮询闭环。
 *    - 当 `scope.oobDomains` 已授权且存在盲 SSRF/XXE/SSTI/反序列化等评估面时自动签发去重 Canary（`planAutonomousOobProbes`）；
 *    - 支持可配置节流间隔（默认 30s）与可注入 `fetchFn` 自动轮询，收到有效回连自动产出实锤 Fact 载荷并标记 Canary 已命中（`runAutonomousOobPoll`）。
 *
 * 约束：严禁运行时 `import "./nuwa"` 或 `./graph`，仅依赖底层纯模块与 `import type`。
 */
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
	isAdminLikePath,
	isObjectResourcePath,
	runAuthDiffMatrix,
	type AuthDiffAnomalyKind,
	type AuthDiffFinding,
	type AuthDiffMatrixOptions,
	type AuthDiffMatrixResult,
} from "./auth-diff";
import { getLatestLedgerSeq, recordToolExecution } from "./evidence";
import {
	buildOobEvidenceFact,
	generateOobCanary,
	isOobHostAllowed,
	loadOobCanaries,
	pollOobCallbacks,
	type OobCallbackHit,
	type OobCanary,
	type OobFetchLike,
	type OobPollResult,
} from "./oob";
import { isHostInScope } from "./scope";
import {
	ingestCredFactToVault,
	loadSessionVault,
	redactVaultSecrets,
	type SessionVault,
} from "./session-vault";
import { normOneLine, nowIso, sha } from "./storage";
import { buildDoubleBlindVerifyIntentSpec, type VerifyIntentSpec } from "./verifier-gate";
import type { AutoFact } from "./autoexec";
import type { Fact, Intent, NuwaState, ScopePolicy } from "./types";

// ============================================================================
// 共享持久化状态（冷却哈希与节流状态，0o600 落盘，绝不含任何明文凭据）
// ============================================================================

export const DEFAULT_AUTHDIFF_COOLDOWN_MS = 10 * 60_000;
export const DEFAULT_OOB_POLL_INTERVAL_MS = 30_000;
export const DEFAULT_MAX_AUTH_PATHS = 20;
export const DEFAULT_MAX_NEW_OOB_CANARIES = 5;

const WEB_EVALUATION_MODES = new Set(["pentest", "ctf", "audit"]);
const STATIC_ASSET_EXT_RE =
	/\.(?:css|js|mjs|cjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|mp3|wav|webm|pdf|zip|tar|gz|tgz|rar|7z|exe|dmg)(?:\?.*)?$/i;
const INTERNAL_PROBE_PATH_RE = /^\/__nuwa_/i;

interface AuthDiffCooldownRecord {
	signature: string;
	lastRunAtMs: number;
	lastRunAt: string;
	roles: string[];
	pathCount: number;
	findingsCount: number;
}

interface OobSeededSurfaceRecord {
	surfaceKey: string;
	category: OobSurfaceCategory;
	canaryId: string;
	fqdn: string;
	target: string;
	seededAt: string;
}

interface AutoLoopsPersistedState {
	schema: 1;
	updatedAt: string;
	authDiff: {
		runsBySignature: Record<string, AuthDiffCooldownRecord>;
		seenCredFactIds: string[];
	};
	oob: {
		seededSurfaces: Record<string, OobSeededSurfaceRecord>;
		lastPollAtMs: number;
		lastPollAt?: string;
		reportedHitIds: string[];
		hitCanaryIds: string[];
	};
}

let autoLoopsAtomicSeq = 0;

function autoLoopsStatePath(root: string): string {
	return join(resolve(root), ".nuwa", "auto-loops-state.json");
}

function emptyAutoLoopsState(): AutoLoopsPersistedState {
	return {
		schema: 1,
		updatedAt: "",
		authDiff: {
			runsBySignature: {},
			seenCredFactIds: [],
		},
		oob: {
			seededSurfaces: {},
			lastPollAtMs: 0,
			reportedHitIds: [],
			hitCanaryIds: [],
		},
	};
}

function loadAutoLoopsState(root: string): AutoLoopsPersistedState {
	const file = autoLoopsStatePath(root);
	if (!existsSync(file)) return emptyAutoLoopsState();
	try {
		const raw = JSON.parse(readFileSync(file, "utf8")) as Partial<AutoLoopsPersistedState>;
		if (!raw || typeof raw !== "object") return emptyAutoLoopsState();
		const base = emptyAutoLoopsState();
		if (raw.authDiff && typeof raw.authDiff === "object") {
			if (raw.authDiff.runsBySignature && typeof raw.authDiff.runsBySignature === "object") {
				base.authDiff.runsBySignature = { ...raw.authDiff.runsBySignature };
			}
			if (Array.isArray(raw.authDiff.seenCredFactIds)) {
				base.authDiff.seenCredFactIds = raw.authDiff.seenCredFactIds
					.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
					.slice(-500);
			}
		}
		if (raw.oob && typeof raw.oob === "object") {
			if (raw.oob.seededSurfaces && typeof raw.oob.seededSurfaces === "object") {
				base.oob.seededSurfaces = { ...raw.oob.seededSurfaces };
			}
			if (typeof raw.oob.lastPollAtMs === "number" && Number.isFinite(raw.oob.lastPollAtMs) && raw.oob.lastPollAtMs >= 0) {
				base.oob.lastPollAtMs = raw.oob.lastPollAtMs;
			}
			if (typeof raw.oob.lastPollAt === "string") {
				base.oob.lastPollAt = raw.oob.lastPollAt;
			}
			if (Array.isArray(raw.oob.reportedHitIds)) {
				base.oob.reportedHitIds = raw.oob.reportedHitIds
					.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
					.slice(-1000);
			}
			if (Array.isArray(raw.oob.hitCanaryIds)) {
				base.oob.hitCanaryIds = raw.oob.hitCanaryIds
					.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
					.slice(-500);
			}
		}
		base.updatedAt = typeof raw.updatedAt === "string" ? raw.updatedAt : "";
		return base;
	} catch {
		return emptyAutoLoopsState();
	}
}

function saveAutoLoopsState(root: string, st: AutoLoopsPersistedState): void {
	const file = autoLoopsStatePath(root);
	mkdirSync(dirname(file), { recursive: true });
	const boundedRuns = Object.entries(st.authDiff.runsBySignature)
		.sort((a, b) => (b[1]?.lastRunAtMs ?? 0) - (a[1]?.lastRunAtMs ?? 0))
		.slice(0, 100);
	const payload: AutoLoopsPersistedState = {
		schema: 1,
		updatedAt: nowIso(),
		authDiff: {
			runsBySignature: Object.fromEntries(boundedRuns),
			seenCredFactIds: [...new Set(st.authDiff.seenCredFactIds)].slice(-500),
		},
		oob: {
			seededSurfaces: st.oob.seededSurfaces,
			lastPollAtMs: st.oob.lastPollAtMs,
			...(st.oob.lastPollAt ? { lastPollAt: st.oob.lastPollAt } : {}),
			reportedHitIds: [...new Set(st.oob.reportedHitIds)].slice(-1000),
			hitCanaryIds: [...new Set(st.oob.hitCanaryIds)].slice(-500),
		},
	};
	const tmp = `${file}.tmp-${process.pid}-${Date.now()}-${autoLoopsAtomicSeq++}`;
	writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
	try {
		chmodSync(tmp, 0o600);
	} catch {
		/* 非 POSIX 忽略 */
	}
	renameSync(tmp, file);
	try {
		chmodSync(file, 0o600);
	} catch {
		/* 非 POSIX 忽略 */
	}
}

function sha256Short(input: string, len = 24): string {
	return createHash("sha256").update(input, "utf8").digest("hex").slice(0, len);
}

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
	if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
	return Math.max(min, Math.min(max, Math.floor(value)));
}

function resolveNowMs(value: number | undefined): number {
	return typeof value === "number" && Number.isFinite(value) ? value : Date.now();
}

function allocateNextFactId(state: NuwaState, usedIds: Set<string>): string {
	let n = Number.isFinite(state.seq?.fact) ? Math.floor(state.seq.fact) : 0;
	for (const id of Object.keys(state.facts ?? {})) {
		const m = /^F(\d+)$/.exec(id);
		if (m?.[1]) n = Math.max(n, Number(m[1]));
	}
	for (const id of usedIds) {
		const m = /^F(\d+)$/.exec(id);
		if (m?.[1]) n = Math.max(n, Number(m[1]));
	}
	n += 1;
	const fid = `F${n}`;
	usedIds.add(fid);
	return fid;
}

function allocateNextIntentId(state: NuwaState, usedIds: Set<string>): string {
	let n = Number.isFinite(state.seq?.intent) ? Math.floor(state.seq.intent) : 0;
	for (const id of Object.keys(state.intents ?? {})) {
		const m = /^I(\d+)$/.exec(id);
		if (m?.[1]) n = Math.max(n, Number(m[1]));
	}
	for (const id of usedIds) {
		const m = /^I(\d+)$/.exec(id);
		if (m?.[1]) n = Math.max(n, Number(m[1]));
	}
	n += 1;
	const iid = `I${n}`;
	usedIds.add(iid);
	return iid;
}

function isWebEvaluationState(state: NuwaState): { ok: boolean; baseUrl?: string; reason?: string } {
	if (!state?.project) {
		return { ok: false, reason: "状态缺少 project 定义" };
	}
	const mode = String(state.project.mode ?? "").trim().toLowerCase();
	if (!WEB_EVALUATION_MODES.has(mode)) {
		return { ok: false, reason: `当前模式 (${mode || "unknown"}) 非 Web 安全评估模式` };
	}
	const scheme = String(state.project.scheme ?? "").trim().toLowerCase();
	if (scheme === "local") {
		return { ok: false, reason: "本地目录目标 (scheme=local) 不适用 HTTP 鉴权差分" };
	}
	const rawUrl = String(state.project.url || state.project.target || "").trim();
	if (!rawUrl) {
		return { ok: false, reason: "项目缺少有效 HTTP(S) 目标地址" };
	}
	try {
		const parsed = new URL(rawUrl);
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
			return { ok: false, reason: `非 HTTP(S) 目标协议 (${parsed.protocol})` };
		}
		return { ok: true, baseUrl: parsed.origin };
	} catch {
		return { ok: false, reason: `无法解析项目目标 URL (${rawUrl})` };
	}
}

// ============================================================================
// 一、AuthDiff 自主闭环（自动触发判定 + 端点抽取 + 冷却防重 + 候选/复验生成）
// ============================================================================

export interface CollectAuthPathsOptions {
	maxPaths?: number;
	extraPaths?: readonly string[];
	includeRoot?: boolean;
}

export interface AutoAuthDiffTriggerOptions extends CollectAuthPathsOptions {
	/** 显式覆盖默认角色列表或会话保险箱（便于测试或主循环注入）。 */
	vault?: SessionVault;
	/** 显式传入待测路径列表（与自动抽取路径合并去重）。 */
	paths?: readonly string[];
	/** 冷却窗口毫秒数（默认 10 分钟）。 */
	cooldownMs?: number;
	/** 可注入当前时间戳毫秒值（便于单元测试确定性验证冷却窗口）。 */
	nowMs?: number;
	/** 强制忽略冷却防重窗口。 */
	force?: boolean;
	/** 允许的最小角色数量（默认 2；当存在新 cred 事实时允许 >= 1 个认证角色与 anon 差分）。 */
	minRoles?: number;
}

export interface AutoAuthDiffTriggerDecision {
	shouldTrigger: boolean;
	reason: string;
	triggerSource?: "multi_role_vault" | "new_cred_fact";
	roles: string[];
	paths: string[];
	signature: string;
	newCredFactIds: string[];
	cooldownRemainingMs?: number;
}

export interface RunAutonomousAuthDiffOptions extends AutoAuthDiffTriggerOptions {
	/** 传递给 `runAuthDiffMatrix` 的底层探测选项（含可注入 `fetchFn`、超时、角色角色分类）。 */
	matrixOpts?: AuthDiffMatrixOptions;
	/** 简写可注入 fetch 函数（若与 `matrixOpts.fetchFn` 同时设置，以 `fetchFn` 优先）。 */
	fetchFn?: AuthDiffMatrixOptions["fetchFn"];
	/** 高置信度异常最低相似度阈值（默认 0.5，针对非精确命中项过滤弱信号）。 */
	minSimilarity?: number;
	/** 是否在触发前自动尝试将未入库的新 `cred` 事实收纳至 Session Vault（默认 true）。 */
	autoIngestCreds?: boolean;
	/** 是否将脱敏后的差分结果记入执行证据账本（默认 true）。 */
	recordEvidence?: boolean;
	/** 是否直接将产出的候选 `vuln` Fact 与 `verify-vuln:<fid>` 意图写入传入的 `state` 对象（默认 false）。 */
	applyToState?: boolean;
}

export interface AutonomousAuthDiffResult {
	triggered: boolean;
	skippedReason?: string;
	decision: AutoAuthDiffTriggerDecision;
	ingestedRoles: string[];
	matrixResult: AuthDiffMatrixResult | null;
	highConfidenceFindings: AuthDiffFinding[];
	candidateFacts: Fact[];
	verifyIntentSpecs: VerifyIntentSpec[];
}

function normalizeEndpointCandidate(raw: string, baseOrigin?: string): string | null {
	let s = String(raw ?? "").trim();
	if (!s) return null;
	// 去除外围引号或尾随标点
	s = s.replace(/^['"`(<\[]+/, "").replace(/['"`)\]>,.;:]+$/, "");
	if (!s || /\s/.test(s) || s.includes("*") || s.includes("{") || s.includes("}")) return null;

	let pathWithQuery = "";
	if (/^https?:\/\//i.test(s)) {
		try {
			const u = new URL(s);
			if (baseOrigin && u.origin !== baseOrigin) return null;
			pathWithQuery = `${u.pathname}${u.search}`;
		} catch {
			return null;
		}
	} else if (s.startsWith("/")) {
		const hashIdx = s.indexOf("#");
		pathWithQuery = hashIdx >= 0 ? s.slice(0, hashIdx) : s;
	} else {
		return null;
	}

	if (!pathWithQuery.startsWith("/") || pathWithQuery.startsWith("//")) return null;
	// 规范化多重斜杠与非根尾斜杠
	const qIdx = pathWithQuery.indexOf("?");
	const rawPathname = qIdx >= 0 ? pathWithQuery.slice(0, qIdx) : pathWithQuery;
	const rawQuery = qIdx >= 0 ? pathWithQuery.slice(qIdx) : "";
	const normPathname = rawPathname.replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/";
	const normalized = `${normPathname}${rawQuery}`;

	if (INTERNAL_PROBE_PATH_RE.test(normPathname)) return null;
	if (STATIC_ASSET_EXT_RE.test(normPathname)) return null;
	if (normalized.length > 240) return null;
	return normalized;
}

function extractPathsFromText(text: string | undefined, baseOrigin?: string): string[] {
	if (!text) return [];
	const found: string[] = [];
	// 提取同源完整 HTTP(S) URL
	for (const m of text.matchAll(/https?:\/\/[^\s'"`<>|;&)\]]+/gi)) {
		const norm = normalizeEndpointCandidate(m[0], baseOrigin);
		if (norm && norm !== "/") found.push(norm);
	}
	// 提取显式路径字面量（如 /api/v1/orders/1001 或 /admin/settings?id=1）
	for (const m of text.matchAll(/(?:^|[\s"'`(\[,=:])(\/[a-zA-Z0-9._~-]+(?:\/[a-zA-Z0-9._~-]+)*(?:\?[a-zA-Z0-9._~=&%-]+)?)/g)) {
		const raw = m[1];
		if (!raw) continue;
		// 跳过类似 /usr/bin、/etc/passwd、/tmp/nuwa、/root/、/var/log 等明显本机文件系统路径
		if (/^\/(?:usr|etc|tmp|var|proc|sys|dev|bin|sbin|lib|opt|root|home|private\/tmp)\b/i.test(raw)) continue;
		const norm = normalizeEndpointCandidate(raw, baseOrigin);
		if (norm && norm !== "/") found.push(norm);
	}
	return found;
}

function scoreAuthPathValue(path: string, requiresAuthSet: Set<string>): number {
	let score = 10;
	if (requiresAuthSet.has(path)) score += 45;
	if (isAdminLikePath(path)) score += 40;
	if (isObjectResourcePath(path)) score += 38;
	if (/^\/(?:api|v\d+|graphql|rest|rpc|internal|private|user|users|account|accounts|order|orders|profile|me|settings|billing|invoice|tenant|org|project|doc|file)(?:\/|$|\?)/i.test(path)) {
		score += 25;
	}
	if (path.includes("?")) score += 8;
	if (path === "/") score -= 20;
	return score;
}

/**
 * 从 `NuwaState` 的事实图与意图队列中自动抽取并排序可测 API / 对象 / 管理端点路径。
 * 自动过滤 Soft-404 / not_found 已知失效路径与纯静态资源，优先保留对象 ID 与高敏管理端点。
 */
export function collectTestableAuthPaths(state: NuwaState, opts?: CollectAuthPathsOptions): string[] {
	const maxPaths = clampInt(opts?.maxPaths, DEFAULT_MAX_AUTH_PATHS, 1, 50);
	const webCheck = isWebEvaluationState(state);
	const baseOrigin = webCheck.baseUrl;

	const excludedDeadPaths = new Set<string>();
	const requiresAuthPaths = new Set<string>();
	const candidates = new Set<string>();

	const addCandidate = (raw: string | undefined) => {
		if (!raw) return;
		const norm = normalizeEndpointCandidate(raw, baseOrigin);
		if (!norm) return;
		if (norm === "/" && !opts?.includeRoot) return;
		candidates.add(norm);
	};

	for (const extra of opts?.extraPaths ?? []) {
		addCandidate(extra);
	}

	for (const fact of Object.values(state?.facts ?? {})) {
		if (!fact || fact.verifyStage === "rejected") continue;

		// 记录已知失效或 Soft-404 路径以便剔除
		const metaAny = fact.meta as
			| (NonNullable<Fact["meta"]> & {
					endpointClassifications?: Record<string, string>;
					requiresAuthPaths?: string[];
			  })
			| undefined;
		if (metaAny?.endpointClassifications) {
			for (const [ep, cls] of Object.entries(metaAny.endpointClassifications)) {
				const norm = normalizeEndpointCandidate(ep, baseOrigin);
				if (!norm) continue;
				if (cls === "not_found" || cls === "soft_404") {
					excludedDeadPaths.add(norm);
				} else if (cls === "exists_requires_auth") {
					requiresAuthPaths.add(norm);
					candidates.add(norm);
				} else if (cls === "exists" || cls === "redirect") {
					candidates.add(norm);
				}
			}
		}

		for (const p of metaAny?.requiresAuthPaths ?? []) {
			const norm = normalizeEndpointCandidate(p, baseOrigin);
			if (norm) {
				requiresAuthPaths.add(norm);
				candidates.add(norm);
			}
		}
		for (const p of fact.meta?.paths ?? []) addCandidate(p);
		for (const p of fact.meta?.routes ?? []) addCandidate(p);

		if (fact.targetKey) addCandidate(fact.targetKey);

		if (
			fact.kind === "endpoint" ||
			fact.kind === "asset" ||
			fact.kind === "service" ||
			fact.kind === "vuln" ||
			fact.kind === "note"
		) {
			for (const p of extractPathsFromText(fact.title, baseOrigin)) addCandidate(p);
			for (const p of extractPathsFromText(fact.detail, baseOrigin)) addCandidate(p);
			for (const p of extractPathsFromText(fact.output, baseOrigin)) addCandidate(p);
		}
	}

	for (const intent of Object.values(state?.intents ?? {})) {
		if (!intent || intent.status === "blocked") continue;
		if (intent.targetKey) addCandidate(intent.targetKey);
		if (intent.key.startsWith("ep:")) {
			addCandidate(intent.key.slice(3));
		}
	}

	const filtered = [...candidates].filter((p) => !excludedDeadPaths.has(p));
	filtered.sort((a, b) => {
		const diff = scoreAuthPathValue(b, requiresAuthPaths) - scoreAuthPathValue(a, requiresAuthPaths);
		return diff !== 0 ? diff : a.localeCompare(b);
	});

	return filtered.slice(0, maxPaths);
}

/** 计算「角色集合 + 路径集合」确定性冷却哈希。 */
export function computeAuthDiffSignature(roles: readonly string[], paths: readonly string[]): string {
	const normRoles = [...new Set(roles.map((r) => r.trim().toLowerCase()).filter(Boolean))].sort();
	const normPaths = [...new Set(paths.map((p) => p.trim()).filter(Boolean))].sort();
	return sha256Short(JSON.stringify({ roles: normRoles, paths: normPaths }), 24);
}

/**
 * 判断主循环是否应自动触发多角色鉴权差分：
 * 1. 必须处于 Web 评估模式（`pentest`/`ctf`/`audit` + 有效 `http(s)` 目标）；
 * 2. SessionVault 拥有 `>= 2` 个角色，或出现尚未处理的新 `cred` 事实（且具备至少 1 个认证角色）；
 * 3. 已抽取到非空可测端点集合；
 * 4. 同一「角色集合 + 路径集合」哈希未处于冷却窗口内（除非 `opts.force === true`）。
 */
export function shouldAutoTriggerAuthDiff(
	state: NuwaState,
	root: string,
	opts?: AutoAuthDiffTriggerOptions,
): AutoAuthDiffTriggerDecision {
	const normRoot = resolve(root);
	const webCheck = isWebEvaluationState(state);
	if (!webCheck.ok) {
		return {
			shouldTrigger: false,
			reason: webCheck.reason ?? "非 Web 评估模式",
			roles: [],
			paths: [],
			signature: "",
			newCredFactIds: [],
		};
	}

	const vault = opts?.vault ?? loadSessionVault(normRoot);
	const roles = Object.keys(vault.roles ?? {}).sort();
	const loopState = loadAutoLoopsState(normRoot);
	const seenCreds = new Set(loopState.authDiff.seenCredFactIds);

	const credFacts = Object.values(state.facts ?? {}).filter(
		(f) => f && f.kind === "cred" && f.verifyStage !== "rejected",
	);
	const newCredFactIds = credFacts.map((f) => f.id).filter((id) => !seenCreds.has(id)).sort();

	const minRoles = clampInt(opts?.minRoles, 2, 1, 50);
	const hasMultiRole = roles.length >= minRoles;
	const hasNewCred = newCredFactIds.length > 0;

	const paths = collectTestableAuthPaths(state, {
		maxPaths: opts?.maxPaths,
		extraPaths: [...(opts?.paths ?? []), ...(opts?.extraPaths ?? [])],
		includeRoot: opts?.includeRoot,
	});

	const signature = computeAuthDiffSignature(roles, paths);

	if (!hasMultiRole && !hasNewCred) {
		return {
			shouldTrigger: false,
			reason:
				roles.length === 0
					? "会话保险箱暂无可用认证角色，且无新入库凭据"
					: `会话保险箱仅 ${roles.length} 个角色（需 >= ${minRoles} 个角色或出现新 cred 事实触发）`,
			roles,
			paths,
			signature,
			newCredFactIds,
		};
	}

	if (paths.length === 0) {
		return {
			shouldTrigger: false,
			reason: "当前事实图中尚未收集到可测 API / 对象端点路径",
			roles,
			paths,
			signature,
			newCredFactIds,
		};
	}

	const nowMs = resolveNowMs(opts?.nowMs);
	const cooldownMs =
		typeof opts?.cooldownMs === "number" && Number.isFinite(opts.cooldownMs) && opts.cooldownMs >= 0
			? Math.floor(opts.cooldownMs)
			: DEFAULT_AUTHDIFF_COOLDOWN_MS;

	const prevRun = loopState.authDiff.runsBySignature[signature];
	// 仅当无尚未处理的新 cred 事实时受同签名冷却窗口拦截；一旦出现新 cred 事实则允许立即增量复测
	if (!opts?.force && !hasNewCred && prevRun && cooldownMs > 0) {
		const elapsed = nowMs - prevRun.lastRunAtMs;
		if (elapsed >= 0 && elapsed < cooldownMs) {
			const remaining = cooldownMs - elapsed;
			return {
				shouldTrigger: false,
				reason: `相同角色集合(${roles.join(",")})与路径集合(${paths.length}条)仍在冷却窗口内，剩余 ${Math.ceil(remaining / 1000)}s`,
				roles,
				paths,
				signature,
				newCredFactIds,
				cooldownRemainingMs: remaining,
			};
		}
	}

	const triggerSource = hasMultiRole ? "multi_role_vault" : "new_cred_fact";
	return {
		shouldTrigger: true,
		reason:
			triggerSource === "multi_role_vault"
				? `会话保险箱已具备 ${roles.length} 个角色 (${roles.join(",")}) 且发现 ${paths.length} 个可测端点`
				: `检测到 ${newCredFactIds.length} 条新 cred 事实 (${newCredFactIds.join(",")})，启动增量鉴权差分`,
		triggerSource,
		roles,
		paths,
		signature,
		newCredFactIds,
	};
}

function isHighConfidenceAuthFinding(finding: AuthDiffFinding, minSimilarity: number): boolean {
	const allowedKinds: AuthDiffAnomalyKind[] = ["unauth_access", "vertical_bfla", "horizontal_bola"];
	if (!allowedKinds.includes(finding.kind)) return false;

	// 二次 Soft-404 去噪校验：被测角色探针绝不能命中 Soft-404 基线
	const testedProbe = finding.probes.find((p) => p.role === finding.testedRole);
	if (testedProbe && (testedProbe.isSoft404 || testedProbe.status < 200 || testedProbe.status >= 300)) {
		return false;
	}

	if (finding.kind === "unauth_access") {
		if (testedProbe?.isHtml) return false;
		const protectedPath = isAdminLikePath(finding.path) || isObjectResourcePath(finding.path);
		return protectedPath || finding.similarity >= Math.max(minSimilarity, 0.8);
	}

	if (finding.kind === "vertical_bfla") {
		if (isAdminLikePath(finding.path)) return true;
		return finding.similarity >= Math.max(minSimilarity, 0.8);
	}

	// horizontal_bola
	return finding.similarity >= Math.max(minSimilarity, 0.85);
}

function formatAnomalyKindLabel(kind: AuthDiffAnomalyKind): string {
	switch (kind) {
		case "unauth_access":
			return "未授权访问 (UNAUTH_ACCESS)";
		case "vertical_bfla":
			return "垂直越权 (BFLA)";
		case "horizontal_bola":
			return "水平越权 (BOLA/IDOR)";
	}
}

function redactVerifySpec(spec: VerifyIntentSpec, vault: SessionVault): VerifyIntentSpec {
	return {
		...spec,
		title: redactVaultSecrets(spec.title, vault),
		detail: redactVaultSecrets(spec.detail, vault),
	};
}

/**
 * 主循环自动驱动的多角色只读鉴权差分闭环：
 * 1. 可选自动将新 `cred` 事实收纳进 SessionVault；
 * 2. 通过 `shouldAutoTriggerAuthDiff` 做模式、角色、路径与冷却哈希校验；
 * 3. 调用 `runAuthDiffMatrix` 执行 Soft-404 基线去噪与只读 GET 差分矩阵；
 * 4. 将高置信度异常（`unauth_access` / `vertical_bfla` / `horizontal_bola`）转为严格脱敏的候选 `vuln` Fact
 *    （`verifyStage="candidate"`, `verified=false`）与双盲复验意图 `verify-vuln:<fid>` spec。
 */
export async function runAutonomousAuthDiff(
	state: NuwaState,
	root: string,
	scope: ScopePolicy,
	opts?: RunAutonomousAuthDiffOptions,
): Promise<AutonomousAuthDiffResult> {
	const normRoot = resolve(root);
	const ingestedRoles: string[] = [];

	// 1. 若未注入自定义 vault 且启用了自动收纳，先尝试把新 cred 事实收纳至会话保险箱
	const ingestedFactIds: string[] = [];
	if (!opts?.vault && opts?.autoIngestCreds !== false) {
		const curVault = loadSessionVault(normRoot);
		const existingSourceIds = new Set(
			Object.values(curVault.roles ?? {})
				.map((r) => r.sourceFactId)
				.filter((x): x is string => Boolean(x)),
		);
		for (const f of Object.values(state.facts ?? {})) {
			if (!f || f.kind !== "cred" || f.verifyStage === "rejected") continue;
			if (existingSourceIds.has(f.id)) continue;
			try {
				const entry = ingestCredFactToVault(normRoot, f);
				if (entry) {
					ingestedRoles.push(entry.role);
					ingestedFactIds.push(f.id);
				}
			} catch {
				/* 无法自动抽取结构化凭据时静默跳过 */
			}
		}
	}

	const vault = opts?.vault ?? loadSessionVault(normRoot);
	// 若启用了 applyToState 且刚收纳了明文 cred 事实，立即就地脱敏原 cred 事实，杜绝明文残留 state
	if (opts?.applyToState === true && ingestedFactIds.length > 0) {
		for (const fid of ingestedFactIds) {
			const cf = state.facts?.[fid];
			if (!cf) continue;
			cf.title = redactVaultSecrets(cf.title, vault);
			cf.detail = redactVaultSecrets(cf.detail, vault);
			if (cf.command) cf.command = redactVaultSecrets(cf.command, vault);
			if (cf.output) cf.output = redactVaultSecrets(cf.output, vault);
		}
	}
	const decision = shouldAutoTriggerAuthDiff(state, normRoot, { ...opts, vault });
	if (!decision.shouldTrigger) {
		return {
			triggered: false,
			skippedReason: decision.reason,
			decision,
			ingestedRoles,
			matrixResult: null,
			highConfidenceFindings: [],
			candidateFacts: [],
			verifyIntentSpecs: [],
		};
	}

	if (decision.roles.length === 0) {
		if (decision.newCredFactIds.length > 0) {
			const ls = loadAutoLoopsState(normRoot);
			for (const id of decision.newCredFactIds) {
				ls.authDiff.seenCredFactIds.push(id);
			}
			saveAutoLoopsState(normRoot, ls);
		}
		return {
			triggered: false,
			skippedReason: "新 cred 事实未解析出可用 HTTP 会话角色，会话保险箱仍为空，跳过鉴权差分",
			decision,
			ingestedRoles,
			matrixResult: null,
			highConfidenceFindings: [],
			candidateFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const baseUrl = state.project.url || state.project.target;
	let parsedBase: URL;
	try {
		parsedBase = new URL(baseUrl);
	} catch {
		return {
			triggered: false,
			skippedReason: `无法解析项目目标 URL (${baseUrl})`,
			decision,
			ingestedRoles,
			matrixResult: null,
			highConfidenceFindings: [],
			candidateFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const hostCheck = isHostInScope(parsedBase.hostname, scope);
	if (!hostCheck.ok) {
		return {
			triggered: false,
			skippedReason: `目标主机越界，拦截自动鉴权差分: ${hostCheck.reason ?? parsedBase.hostname}`,
			decision,
			ingestedRoles,
			matrixResult: null,
			highConfidenceFindings: [],
			candidateFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const matrixOpts: AuthDiffMatrixOptions = {
		...(opts?.matrixOpts ?? {}),
		roles: opts?.matrixOpts?.roles ?? decision.roles,
		maxPaths: opts?.maxPaths ?? decision.paths.length,
		...(opts?.fetchFn ? { fetchFn: opts.fetchFn } : {}),
	};

	const matrixResult = await runAuthDiffMatrix(
		parsedBase.href,
		decision.paths,
		vault,
		scope,
		matrixOpts,
	);

	// 4. 持久化冷却状态（无论是否检出异常均写入，避免同角色+路径集合重复高频触发）
	const nowMs = resolveNowMs(opts?.nowMs);
	const loopState = loadAutoLoopsState(normRoot);
	const minSimilarity =
		typeof opts?.minSimilarity === "number" && Number.isFinite(opts.minSimilarity)
			? Math.max(0, Math.min(1, opts.minSimilarity))
			: 0.5;
	const highConfidenceFindings = matrixResult.findings.filter((f) =>
		isHighConfidenceAuthFinding(f, minSimilarity),
	);

	loopState.authDiff.runsBySignature[decision.signature] = {
		signature: decision.signature,
		lastRunAtMs: nowMs,
		lastRunAt: new Date(nowMs).toISOString(),
		roles: decision.roles,
		pathCount: decision.paths.length,
		findingsCount: highConfidenceFindings.length,
	};
	for (const f of Object.values(state.facts ?? {})) {
		if (f && f.kind === "cred" && f.verifyStage !== "rejected") {
			loopState.authDiff.seenCredFactIds.push(f.id);
		}
	}
	saveAutoLoopsState(normRoot, loopState);

	// 5. 构造严格脱敏的候选 vuln Fact 与双盲复验 verify-vuln:<fid> 意图 spec
	const candidateFacts: Fact[] = [];
	const verifyIntentSpecs: VerifyIntentSpec[] = [];
	const existingFactKeys = new Set(
		Object.values(state.facts ?? {})
			.map((f) => f?.key)
			.filter((k): k is string => Boolean(k)),
	);
	const usedFactIds = new Set<string>();
	const usedIntentIds = new Set<string>();

	// 用于生成不重复 verify-vuln 意图的虚拟视图，避免修改调用方原始 state（除非 applyToState=true）
	const virtualState: NuwaState = {
		...state,
		facts: { ...(state.facts ?? {}) },
		intents: { ...(state.intents ?? {}) },
	};

	let evidenceSeq: number | undefined;
	if (highConfidenceFindings.length > 0 && opts?.recordEvidence !== false && matrixResult.fact) {
		const safeCmd = redactVaultSecrets(matrixResult.fact.command, vault);
		const safeOut = redactVaultSecrets(matrixResult.fact.output, vault);
		recordToolExecution(normRoot, {
			tool: "auth-diff",
			command: safeCmd,
			output: safeOut,
			agentName: "auto-loops",
		});
		evidenceSeq = getLatestLedgerSeq(normRoot);
	}

	const createdTs = new Date(nowMs).toISOString();
	for (const finding of highConfidenceFindings) {
		const factKey = `auto-authdiff:${finding.kind}:${sha(finding.path)}`;
		if (existingFactKeys.has(factKey)) continue;
		existingFactKeys.add(factKey);

		const fid = allocateNextFactId(state, usedFactIds);
		const probeLines = finding.probes.map((p) => {
			const keysPart = p.jsonKeys.length > 0 ? ` keys=[${p.jsonKeys.slice(0, 6).join(",")}]` : "";
			return `ROLE_PROBE role=${p.role} status=${p.status} bytes=${p.bytes} soft404=${p.isSoft404}${keysPart} sha1=${p.bodySha1.slice(0, 10)}`;
		});

		const rawTitle = `自动鉴权差分检出 ${formatAnomalyKindLabel(finding.kind)}: ${finding.path}`;
		const rawDetail = [
			`kind=${finding.kind}`,
			`severity=${finding.severity}`,
			`path=${finding.path}`,
			`baseline=${finding.baselineRole}`,
			`tested=${finding.testedRole}`,
			`similarity=${finding.similarity.toFixed(2)}`,
			`summary=${finding.summary}`,
		].join(" | ");
		const rawCommand = `auto-authdiff (${matrixResult.roles.join(",")}) ${parsedBase.origin}${finding.path}`;
		const rawOutput = [
			`AUTH_DIFF_FINDING kind=${finding.kind} path=${finding.path} baseline=${finding.baselineRole} tested=${finding.testedRole} similarity=${finding.similarity.toFixed(2)}`,
			finding.summary,
			...probeLines,
		].join("\n");

		const candidate: Fact = {
			id: fid,
			kind: "vuln",
			title: normOneLine(redactVaultSecrets(rawTitle, vault), 120),
			detail: redactVaultSecrets(rawDetail, vault).slice(0, 700),
			command: redactVaultSecrets(rawCommand, vault).slice(0, 400),
			output: redactVaultSecrets(rawOutput, vault).slice(0, 1200),
			key: factKey,
			targetKey: finding.path,
			surfaceDomain: "path",
			createdAt: createdTs,
			meta: {
				paths: [finding.path],
			},
			verified: false,
			verifyStage: "candidate",
			...(evidenceSeq !== undefined ? { evidenceSeq } : {}),
		};

		candidateFacts.push(candidate);
		virtualState.facts[fid] = candidate;

		const rawSpec = buildDoubleBlindVerifyIntentSpec(virtualState, candidate);
		if (rawSpec) {
			const safeSpec = redactVerifySpec(rawSpec, vault);
			verifyIntentSpecs.push(safeSpec);
			const iid = allocateNextIntentId(virtualState, usedIntentIds);
			const verifyIntent: Intent = {
				id: iid,
				phase: safeSpec.phase,
				key: safeSpec.key,
				title: safeSpec.title,
				detail: safeSpec.detail,
				from: safeSpec.from,
				status: "open",
				priority: safeSpec.priority,
				attempts: 0,
				createdAt: createdTs,
				expectedKind: "vuln",
				surfaceDomain: "path",
				targetKey: finding.path,
			};
			virtualState.intents[iid] = verifyIntent;
		}
	}

	if (opts?.applyToState === true && (candidateFacts.length > 0 || verifyIntentSpecs.length > 0)) {
		for (const f of candidateFacts) {
			state.facts[f.id] = f;
			const m = /^F(\d+)$/.exec(f.id);
			if (m?.[1]) state.seq.fact = Math.max(state.seq.fact, Number(m[1]));
		}
		for (const spec of verifyIntentSpecs) {
			const alreadyHas = Object.values(state.intents).some((i) => i.key === spec.key);
			if (alreadyHas) continue;
			const nextNum = Math.max(state.seq.intent, Object.keys(state.intents).length) + 1;
			let iid = `I${nextNum}`;
			let cursor = nextNum;
			while (state.intents[iid]) {
				cursor += 1;
				iid = `I${cursor}`;
			}
			state.seq.intent = Math.max(state.seq.intent, cursor);
			const targetFact = state.facts[spec.targetFactId];
			state.intents[iid] = {
				id: iid,
				phase: spec.phase,
				key: spec.key,
				title: spec.title,
				detail: spec.detail,
				from: [...spec.from],
				status: "open",
				priority: spec.priority,
				attempts: 0,
				createdAt: createdTs,
				expectedKind: "vuln",
				surfaceDomain: "path",
				...(targetFact?.targetKey ? { targetKey: targetFact.targetKey } : {}),
			};
		}
	}

	return {
		triggered: true,
		decision,
		ingestedRoles,
		matrixResult,
		highConfidenceFindings,
		candidateFacts,
		verifyIntentSpecs,
	};
}

// ============================================================================
// 二、OOB 自主播撒与轮询闭环（高危盲打面识别去重 + 节流轮询 + 实锤 Fact 产出）
// ============================================================================

export type OobSurfaceCategory = "blind_ssrf" | "blind_xxe" | "blind_ssti" | "blind_deser";

export interface OobProbePlanItem {
	surfaceKey: string;
	category: OobSurfaceCategory;
	target: string;
	sourceId: string;
	sourceType: "fact" | "intent";
	canary: OobCanary;
	newlyCreated: boolean;
	recommendedChannel: "dns" | "http" | "dns+http";
	probeHint: string;
}

export interface PlanOobProbesOptions {
	/** 指定使用的授权 OOB 域名（省略时自动选取 `scope.oobDomains` 首个合法项）。 */
	domain?: string;
	/** 单次最多新签发的 Canary 数量（默认 5）。 */
	maxNewCanaries?: number;
}

export interface AutonomousOobPlanResult {
	enabled: boolean;
	reason: string;
	domain?: string;
	planned: OobProbePlanItem[];
	createdCanaries: OobCanary[];
	deduplicatedKeys: string[];
	existingCanaries: OobCanary[];
}

export interface RunOobPollOptions {
	/** OOB 回调收集端轮询 URL（省略时回退读取 `NUWA_OOB_POLL_URL`）。 */
	pollUrl?: string;
	/** 可选轮询鉴权令牌（省略时回退 `NUWA_OOB_POLL_TOKEN`，绝不落盘或写入 Fact）。 */
	authToken?: string;
	/** 节流最小轮询间隔毫秒数（默认 30_000 即 30 秒）。 */
	minIntervalMs?: number;
	/** 可注入当前时间戳毫秒值（便于单测验证节流行为）。 */
	nowMs?: number;
	/** 强制忽略节流窗口立即轮询。 */
	force?: boolean;
	/** 可注入 fetch 实现（便于单测模拟回调数据）。 */
	fetchFn?: OobFetchLike;
	/** 单次 HTTP 轮询超时毫秒数（默认 10_000）。 */
	timeoutMs?: number;
	/** 是否将回连证据记入执行证据账本（默认 true）。 */
	recordEvidence?: boolean;
	/** 是否将 OOB 命中暂存为 candidate 并派生复验意图（默认 false，默认作为确定性实锤 Fact 产出）。 */
	requireDoubleBlind?: boolean;
	/** 是否直接将产出的实锤 Fact 写入传入 `state.facts`（默认 false）。 */
	applyToState?: boolean;
}

export interface AutonomousOobPollResult {
	polled: boolean;
	throttled: boolean;
	nextPollInMs?: number;
	skippedReason?: string;
	error?: string;
	pollResult: OobPollResult | null;
	newHits: OobCallbackHit[];
	matchedCanaries: OobCanary[];
	markedHitCanaryIds: string[];
	evidenceFacts: Fact[];
	evidenceAutoFacts: AutoFact[];
	verifyIntentSpecs: VerifyIntentSpec[];
}

interface OobSurfacePattern {
	category: OobSurfaceCategory;
	label: string;
	recommendedChannel: "dns" | "http" | "dns+http";
	re: RegExp;
}

const OOB_SURFACE_PATTERNS: readonly OobSurfacePattern[] = [
	{
		category: "blind_ssrf",
		label: "盲 SSRF / 服务端外链抓取面",
		recommendedChannel: "dns+http",
		re: /\b(?:ssrf|webhook|callback(?:_?url)?|redirect_?uri|fetch_?url|remote_?url|proxy_?url|avatar_?url|image_?url|img_?url|import_?url|feed_?url|url_?preview|wkhtmltopdf|headless|pdf_?export|link_?preview)\b|服务端请求伪造|外链抓取/i,
	},
	{
		category: "blind_xxe",
		label: "盲 XXE / XML 解析面",
		recommendedChannel: "dns+http",
		re: /\b(?:xxe|xml|soap|saml|wsdl|rss|atom|docx|xlsx|svg_?upload|application\/xml|text\/xml)\b|外部实体/i,
	},
	{
		category: "blind_ssti",
		label: "盲 SSTI / 服务端模板渲染面",
		recommendedChannel: "dns+http",
		re: /\b(?:ssti|jinja2?|twig|freemarker|velocity|thymeleaf|handlebars|mustache|mako|erb|template_?render|render_?template)\b|模板注入/i,
	},
	{
		category: "blind_deser",
		label: "盲反序列化 / JNDI / 带外执行面",
		recommendedChannel: "dns",
		re: /\b(?:deserializ\w*|unserialize|fastjson|jackson|log4j2?|jndi|shiro|rememberMe|ysoserial|pickle|rmi|ldap|blind[\s_-]*(?:rce|cmd|command))\b|反序列化/i,
	},
];

function selectAuthorizedOobDomain(scope: ScopePolicy, explicitDomain?: string): string | null {
	if (explicitDomain && explicitDomain.trim()) {
		const check = isOobHostAllowed(explicitDomain.trim(), scope);
		return check.ok ? explicitDomain.trim().toLowerCase() : null;
	}
	for (const candidate of scope?.oobDomains ?? []) {
		const clean = String(candidate ?? "").trim();
		if (!clean) continue;
		const check = isOobHostAllowed(clean, scope);
		if (check.ok && check.matchedDomain) {
			return check.matchedDomain;
		}
	}
	return null;
}

function extractSurfaceTargetHint(
	record: { targetKey?: string; key?: string; title?: string; detail?: string; meta?: Fact["meta"] },
	baseOrigin?: string,
): string {
	if (record.meta?.paths?.[0]) {
		const norm = normalizeEndpointCandidate(record.meta.paths[0], baseOrigin);
		if (norm) return norm;
	}
	if (record.targetKey) {
		const norm = normalizeEndpointCandidate(record.targetKey, baseOrigin);
		if (norm) return norm;
		return record.targetKey.trim().toLowerCase().slice(0, 80);
	}
	const fromText = [
		...extractPathsFromText(record.title, baseOrigin),
		...extractPathsFromText(record.detail, baseOrigin),
	];
	if (fromText.length > 0) return fromText[0]!;
	if (record.key && record.key.trim()) return record.key.trim().toLowerCase().slice(0, 80);
	return normOneLine(record.title ?? "surface", 64).toLowerCase();
}

function buildOobProbeHint(category: OobSurfaceCategory, target: string, canary: OobCanary): string {
	const channelText =
		category === "blind_deser"
			? `DNS 回调域名 ${canary.fqdn}`
			: `DNS/HTTP 回调域名 ${canary.fqdn} (http://${canary.fqdn}/${canary.id})`;
	return `针对 ${category} 候选评估面 (${target}) 绑定唯一 Canary ${canary.id}，在授权验证请求中使用 ${channelText} 观察带外回连。`;
}

/**
 * 自主 OOB Canary 规划与播撒引擎：
 * - 当 `scope.oobDomains` 已配置合法域名且存在盲 SSRF/XXE/SSTI/反序列化等高危面时，
 *   自动为每个尚未覆盖的评估面签发唯一绑定 Canary 并持久化去重；
 * - 再次调用对已播撒的高危面严格去重，不会重复签发冗余 Canary。
 */
export function planAutonomousOobProbes(
	state: NuwaState,
	root: string,
	scope: ScopePolicy,
	opts?: PlanOobProbesOptions,
): AutonomousOobPlanResult {
	const normRoot = resolve(root);
	const existingCanaries = loadOobCanaries(normRoot);
	const domain = selectAuthorizedOobDomain(scope, opts?.domain);
	if (!domain) {
		return {
			enabled: false,
			reason: "ScopePolicy.oobDomains 未配置有效授权域名，跳过自动 OOB Canary 播撒",
			planned: [],
			createdCanaries: [],
			deduplicatedKeys: [],
			existingCanaries,
		};
	}

	const webCheck = isWebEvaluationState(state);
	const baseOrigin = webCheck.baseUrl;
	const maxNew = clampInt(opts?.maxNewCanaries, DEFAULT_MAX_NEW_OOB_CANARIES, 1, 20);

	interface DetectedSurface {
		surfaceKey: string;
		category: OobSurfaceCategory;
		target: string;
		sourceId: string;
		sourceType: "fact" | "intent";
		recommendedChannel: "dns" | "http" | "dns+http";
		intentId?: string;
	}

	const detectedMap = new Map<string, DetectedSurface>();

	const scanRecord = (
		sourceId: string,
		sourceType: "fact" | "intent",
		text: string,
		targetHint: string,
		intentId?: string,
	) => {
		if (!text.trim()) return;
		for (const pat of OOB_SURFACE_PATTERNS) {
			if (!pat.re.test(text)) continue;
			const normTarget = targetHint.trim().toLowerCase() || sourceId.toLowerCase();
			const surfaceKey = `${pat.category}:${normTarget}`;
			if (!detectedMap.has(surfaceKey)) {
				detectedMap.set(surfaceKey, {
					surfaceKey,
					category: pat.category,
					target: normTarget,
					sourceId,
					sourceType,
					recommendedChannel: pat.recommendedChannel,
					intentId,
				});
			}
		}
	};

	for (const fact of Object.values(state.facts ?? {})) {
		if (!fact || fact.verifyStage === "rejected") continue;
		const combined = [
			fact.title,
			fact.detail,
			fact.key ?? "",
			fact.targetKey ?? "",
			...(fact.meta?.tech ?? []),
			...(fact.meta?.paths ?? []),
			...(fact.meta?.routes ?? []),
		].join(" ");
		const targetHint = extractSurfaceTargetHint(fact, baseOrigin);
		scanRecord(fact.id, "fact", combined, targetHint, fact.intent);
	}

	for (const intent of Object.values(state.intents ?? {})) {
		if (!intent || intent.status === "blocked") continue;
		const combined = [intent.key, intent.title, intent.detail, intent.targetKey ?? ""].join(" ");
		const targetHint = extractSurfaceTargetHint(intent, baseOrigin);
		scanRecord(intent.id, "intent", combined, targetHint, intent.id);
	}

	if (detectedMap.size === 0) {
		return {
			enabled: true,
			reason: "当前状态尚未识别到盲 SSRF/XXE/SSTI/反序列化等带外验证面",
			domain,
			planned: [],
			createdCanaries: [],
			deduplicatedKeys: [],
			existingCanaries,
		};
	}

	const loopState = loadAutoLoopsState(normRoot);
	const canaryById = new Map<string, OobCanary>(existingCanaries.map((c) => [c.id, c]));

	const findExistingCanaryForSurface = (surface: DetectedSurface): OobCanary | undefined => {
		const rec = loopState.oob.seededSurfaces[surface.surfaceKey];
		if (rec) {
			const c = canaryById.get(rec.canaryId);
			if (c) return c;
		}
		const tag = `[auto-oob:${surface.surfaceKey}]`;
		return existingCanaries.find(
			(c) =>
				(c.purpose && c.purpose.includes(tag)) ||
				(surface.intentId && c.intentId === surface.intentId && c.purpose?.includes(surface.category)),
		);
	};

	const planned: OobProbePlanItem[] = [];
	const createdCanaries: OobCanary[] = [];
	const deduplicatedKeys: string[] = [];
	let stateDirty = false;

	for (const surface of detectedMap.values()) {
		const existing = findExistingCanaryForSurface(surface);
		if (existing) {
			deduplicatedKeys.push(surface.surfaceKey);
			planned.push({
				surfaceKey: surface.surfaceKey,
				category: surface.category,
				target: surface.target,
				sourceId: surface.sourceId,
				sourceType: surface.sourceType,
				canary: existing,
				newlyCreated: false,
				recommendedChannel: surface.recommendedChannel,
				probeHint: buildOobProbeHint(surface.category, surface.target, existing),
			});
			continue;
		}

		if (createdCanaries.length >= maxNew) continue;

		const purpose = `[auto-oob:${surface.surfaceKey}] ${surface.sourceType}=${surface.sourceId}`;
		const canary = generateOobCanary(normRoot, {
			projectId: state.project.id,
			domain,
			scope,
			intentId: surface.intentId,
			purpose,
		});
		createdCanaries.push(canary);
		canaryById.set(canary.id, canary);
		loopState.oob.seededSurfaces[surface.surfaceKey] = {
			surfaceKey: surface.surfaceKey,
			category: surface.category,
			canaryId: canary.id,
			fqdn: canary.fqdn,
			target: surface.target,
			seededAt: canary.createdAt,
		};
		stateDirty = true;

		planned.push({
			surfaceKey: surface.surfaceKey,
			category: surface.category,
			target: surface.target,
			sourceId: surface.sourceId,
			sourceType: surface.sourceType,
			canary,
			newlyCreated: true,
			recommendedChannel: surface.recommendedChannel,
			probeHint: buildOobProbeHint(surface.category, surface.target, canary),
		});
	}

	if (stateDirty) {
		saveAutoLoopsState(normRoot, loopState);
	}

	return {
		enabled: true,
		reason:
			createdCanaries.length > 0
				? `已为 ${createdCanaries.length} 个高危带外评估面新签发 OOB Canary（去重复用 ${deduplicatedKeys.length} 个）`
				: `全部 ${deduplicatedKeys.length} 个高危带外评估面已存在活跃 Canary，本次去重跳过`,
		domain,
		planned,
		createdCanaries,
		deduplicatedKeys,
		existingCanaries: loadOobCanaries(normRoot),
	};
}

function scrubAuthToken(text: string, authToken?: string): string {
	if (!text || !authToken || !authToken.trim()) return text;
	const tok = authToken.trim();
	let out = text.split(tok).join("[REDACTED_OOB_TOKEN]");
	const bare = tok.replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
	if (bare && bare !== tok && bare.length >= 4) {
		out = out.split(bare).join("[REDACTED_OOB_TOKEN]");
	}
	return out;
}

/**
 * 自主 OOB 回调节流轮询闭环：
 * - 支持节流间隔（默认 30 秒，可通过 `opts.minIntervalMs` 覆盖）与可注入 `fetchFn`；
 * - 复用 `pollOobCallbacks` 的严格 Scope/OOB 域名门控与 `.nuwa/oob-canaries.json` 命中计数持久化；
 * - 收到未上报过的有效回连时自动构造高信息熵实锤 `Fact` 载荷并标记对应 Canary 已命中。
 */
export async function runAutonomousOobPoll(
	state: NuwaState,
	root: string,
	scope: ScopePolicy,
	opts?: RunOobPollOptions,
): Promise<AutonomousOobPollResult> {
	const normRoot = resolve(root);
	const domain = selectAuthorizedOobDomain(scope);
	if (!domain) {
		return {
			polled: false,
			throttled: false,
			skippedReason: "ScopePolicy.oobDomains 未配置有效授权域名，跳过 OOB 轮询",
			pollResult: null,
			newHits: [],
			matchedCanaries: [],
			markedHitCanaryIds: [],
			evidenceFacts: [],
			evidenceAutoFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const canaries = loadOobCanaries(normRoot);
	if (canaries.length === 0) {
		return {
			polled: false,
			throttled: false,
			skippedReason: "当前项目尚未签发任何活跃 OOB Canary，跳过轮询",
			pollResult: null,
			newHits: [],
			matchedCanaries: [],
			markedHitCanaryIds: [],
			evidenceFacts: [],
			evidenceAutoFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const pollUrl = String(opts?.pollUrl ?? process.env.NUWA_OOB_POLL_URL ?? "").trim();
	if (!pollUrl) {
		return {
			polled: false,
			throttled: false,
			skippedReason: "未提供 OOB 回调轮询地址（请通过 opts.pollUrl 或 NUWA_OOB_POLL_URL 配置）",
			pollResult: null,
			newHits: [],
			matchedCanaries: [],
			markedHitCanaryIds: [],
			evidenceFacts: [],
			evidenceAutoFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const minIntervalMs =
		typeof opts?.minIntervalMs === "number" && Number.isFinite(opts.minIntervalMs) && opts.minIntervalMs >= 0
			? Math.floor(opts.minIntervalMs)
			: DEFAULT_OOB_POLL_INTERVAL_MS;
	const nowMs = resolveNowMs(opts?.nowMs);
	const loopState = loadAutoLoopsState(normRoot);

	if (!opts?.force && minIntervalMs > 0 && loopState.oob.lastPollAtMs > 0) {
		const elapsed = nowMs - loopState.oob.lastPollAtMs;
		if (elapsed >= 0 && elapsed < minIntervalMs) {
			return {
				polled: false,
				throttled: true,
				nextPollInMs: minIntervalMs - elapsed,
				skippedReason: `OOB 轮询处于节流窗口内，距离下次轮询还需 ${Math.ceil((minIntervalMs - elapsed) / 1000)}s`,
				pollResult: null,
				newHits: [],
				matchedCanaries: [],
				markedHitCanaryIds: [],
				evidenceFacts: [],
				evidenceAutoFacts: [],
				verifyIntentSpecs: [],
			};
		}
	}

	const authToken = opts?.authToken ?? process.env.NUWA_OOB_POLL_TOKEN;
	const vault = loadSessionVault(normRoot);

	// 记录本次轮询时间戳，确保失败/成功均纳入节流周期
	loopState.oob.lastPollAtMs = nowMs;
	loopState.oob.lastPollAt = new Date(nowMs).toISOString();
	saveAutoLoopsState(normRoot, loopState);

	const pollResult = await pollOobCallbacks(normRoot, {
		pollUrl,
		scope,
		authToken,
		fetchFn: opts?.fetchFn,
		timeoutMs: opts?.timeoutMs,
	});

	if (!pollResult.ok) {
		const safeErr = redactVaultSecrets(scrubAuthToken(pollResult.error ?? "OOB 轮询失败", authToken), vault);
		return {
			polled: true,
			throttled: false,
			error: safeErr,
			pollResult,
			newHits: [],
			matchedCanaries: [],
			markedHitCanaryIds: [],
			evidenceFacts: [],
			evidenceAutoFacts: [],
			verifyIntentSpecs: [],
		};
	}

	const reportedHitSet = new Set(loopState.oob.reportedHitIds);
	const newHits: OobCallbackHit[] = [];
	const evidenceFacts: Fact[] = [];
	const evidenceAutoFacts: AutoFact[] = [];
	const verifyIntentSpecs: VerifyIntentSpec[] = [];
	const markedHitCanaryIds: string[] = [];
	const usedFactIds = new Set<string>();
	const usedIntentIds = new Set<string>();
	const createdTs = new Date(nowMs).toISOString();

	const virtualState: NuwaState = {
		...state,
		facts: { ...(state.facts ?? {}) },
		intents: { ...(state.intents ?? {}) },
	};

	for (const canary of pollResult.matchedCanaries) {
		const canaryHits = pollResult.hits.filter(
			(h) =>
				(h.matchedCanaryId === canary.id || h.matchedToken === canary.token) &&
				!reportedHitSet.has(h.id),
		);
		if (canaryHits.length === 0) continue;

		for (const h of canaryHits) {
			reportedHitSet.add(h.id);
			loopState.oob.reportedHitIds.push(h.id);
			newHits.push(h);
		}
		if (!loopState.oob.hitCanaryIds.includes(canary.id)) {
			loopState.oob.hitCanaryIds.push(canary.id);
		}
		markedHitCanaryIds.push(canary.id);

		const rawAutoFact = buildOobEvidenceFact(canary, canaryHits);
		const safeAutoFact: AutoFact = {
			...rawAutoFact,
			title: normOneLine(redactVaultSecrets(scrubAuthToken(rawAutoFact.title, authToken), vault), 120),
			detail: redactVaultSecrets(scrubAuthToken(rawAutoFact.detail, authToken), vault),
			command: redactVaultSecrets(scrubAuthToken(rawAutoFact.command, authToken), vault),
			output: redactVaultSecrets(scrubAuthToken(rawAutoFact.output, authToken), vault),
		};
		evidenceAutoFacts.push(safeAutoFact);

		let evidenceSeq: number | undefined;
		if (opts?.recordEvidence !== false) {
			recordToolExecution(normRoot, {
				tool: "oob-poll",
				command: safeAutoFact.command,
				output: safeAutoFact.output,
				agentName: "auto-loops",
			});
			evidenceSeq = getLatestLedgerSeq(normRoot);
		}

		const fid = allocateNextFactId(state, usedFactIds);
		const requireDoubleBlind = opts?.requireDoubleBlind === true;
		const fact: Fact = {
			id: fid,
			kind: "vuln",
			title: safeAutoFact.title,
			detail: safeAutoFact.detail,
			command: safeAutoFact.command,
			output: safeAutoFact.output,
			key: `oob:${canary.id}`,
			targetKey: canary.fqdn,
			surfaceDomain: "host",
			...(canary.intentId ? { intent: canary.intentId } : {}),
			createdAt: createdTs,
			verified: !requireDoubleBlind,
			verifyStage: requireDoubleBlind ? "candidate" : "confirmed",
			...(!requireDoubleBlind ? { verifiedAt: createdTs, verifiedBy: "auto-oob-poll" } : {}),
			...(evidenceSeq !== undefined ? { evidenceSeq } : {}),
		};
		evidenceFacts.push(fact);
		virtualState.facts[fid] = fact;

		if (requireDoubleBlind) {
			const vSpec = buildDoubleBlindVerifyIntentSpec(virtualState, fact);
			if (vSpec) {
				const safeSpec = redactVerifySpec(vSpec, vault);
				verifyIntentSpecs.push(safeSpec);
				const iid = allocateNextIntentId(virtualState, usedIntentIds);
				virtualState.intents[iid] = {
					id: iid,
					phase: safeSpec.phase,
					key: safeSpec.key,
					title: safeSpec.title,
					detail: safeSpec.detail,
					from: safeSpec.from,
					status: "open",
					priority: safeSpec.priority,
					attempts: 0,
					createdAt: createdTs,
					expectedKind: "vuln",
					surfaceDomain: "host",
					targetKey: canary.fqdn,
				};
			}
		}
	}

	if (newHits.length > 0 || markedHitCanaryIds.length > 0) {
		saveAutoLoopsState(normRoot, loopState);
	}

	if (opts?.applyToState === true && evidenceFacts.length > 0) {
		for (const f of evidenceFacts) {
			state.facts[f.id] = f;
			const m = /^F(\d+)$/.exec(f.id);
			if (m?.[1]) state.seq.fact = Math.max(state.seq.fact, Number(m[1]));
		}
		for (const spec of verifyIntentSpecs) {
			if (Object.values(state.intents).some((i) => i.key === spec.key)) continue;
			let cursor = Math.max(state.seq.intent, Object.keys(state.intents).length) + 1;
			while (state.intents[`I${cursor}`]) cursor += 1;
			state.seq.intent = Math.max(state.seq.intent, cursor);
			state.intents[`I${cursor}`] = {
				id: `I${cursor}`,
				phase: spec.phase,
				key: spec.key,
				title: spec.title,
				detail: spec.detail,
				from: [...spec.from],
				status: "open",
				priority: spec.priority,
				attempts: 0,
				createdAt: createdTs,
				expectedKind: "vuln",
				surfaceDomain: "host",
			};
		}
	}

	return {
		polled: true,
		throttled: false,
		pollResult,
		newHits,
		matchedCanaries: pollResult.matchedCanaries,
		markedHitCanaryIds,
		evidenceFacts,
		evidenceAutoFacts,
		verifyIntentSpecs,
	};
}
