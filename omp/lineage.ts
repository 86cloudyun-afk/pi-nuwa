/**
 * 女娲 v4.0 主从会话血缘绑定（Session Lineage）与子代理动态模型分流（Model Router）。
 *
 * 核心职责：
 *   1. 根治真实 omp 下 task(agent="fujiang" | "nuwa-verifier") 子代理拥有独立 subSessionId 时，
 *      findRoot 因 ownerSessionId 不一致返回 null，导致子代理 tool_call 护栏与 tool_execution_end 证据账本断层的问题。
 *   2. 维护进程内血缘表 + <agentHome>/cache/nuwa-lineage.json 原子磁盘缓存（支持自定义 agentHome 隔离测试）。
 *   3. 按子代理角色、当前阶段、复验与复盘特征动态路由 fast / deep / verify 模型。
 *
 * 约束：仅使用 import type 引用 ./types（严禁运行时 import ./nuwa），确保零循环依赖。
 */
import { createHash } from "node:crypto";
import {
	chmodSync,
	closeSync,
	existsSync,
	fsyncSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	statSync,
	writeSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { Database } from "bun:sqlite";
import type { NuwaState, Phase } from "./types";
import {
	calibrationLedgerPath,
	hasCalibrationRecords,
	loadCalibrationRecords,
	recommendAdaptiveModelRoute,
	type CalibrationRecord,
	type CalibrationTaskCategory,
} from "./calibration";
import {
	VALID_SPECIALIST_ROLES,
	recommendSpecialistAndModel,
	type RecommendSpecialistOptions,
	type SpecialistAndModelRecommendation,
	type SpecialistIntentLike,
	type SpecialistRole,
} from "./specialist-squad";
import { openSqliteReadonlyZeroWrite } from "./sqlite-store";

export const DEFAULT_SUBAGENT_MODEL = "gemini-4-neon-xhigh";
export const ALLOWED_SUBAGENT_MODELS: readonly string[] = [
	"gemini-4-hydrogen-xhigh",
	"gemini-4-neon-xhigh",
	"gemini-4-carbon-high",
];

export interface ActiveSessionInfo {
	sessionId: string;
	root: string;
	cwd?: string;
	agentId?: string;
	projectId?: string;
	updatedAt?: number;
}

export interface LineageSessionRecord {
	sessionId: string;
	root: string;
	cwd: string;
	agentId?: string;
	projectId?: string;
	updatedAt: number;
}

export interface SubagentSpawnBinding {
	parentSessionId: string;
	parentAgentId?: string;
	root: string;
	cwd?: string;
	spawnedAt: number;
}

export interface LineageCacheData {
	schema: 1;
	updatedAt: number;
	sessions: Record<string, LineageSessionRecord>;
	spawns: SubagentSpawnBinding[];
}

export interface LineageAgentInfo {
	kind?: "main" | "sub" | string;
	id?: string;
	name?: string;
	parentId?: string;
	parentSessionId?: string;
	depth?: number;
}

export interface LineageContextLike {
	cwd?: string;
	sessionId?: string;
	agent?: LineageAgentInfo;
	sessionManager?: {
		getSessionId?: () => string;
		getParentSessionId?: () => string | undefined;
	};
}

export interface SubagentModelRouteInput {
	/** 子代理名称（如 "fujiang" | "nuwa-verifier"）。 */
	agent?: string;
	/** 当前阶段（如 "recon" | "surface" | "vuln" | "exploit" | "post" | "report"）。 */
	phase?: Phase | string;
	/** 单条派单意图 key（可选，用于辅助识别 verify-vuln:* / reflect:*）。 */
	intentKey?: string;
	/** 批量派单意图 key 列表（可选）。 */
	intentKeys?: readonly string[];
	/** 是否存在待执行的双盲漏洞复验任务。 */
	hasPendingVerify?: boolean;
	/** 是否处于战略复盘规划任务。 */
	hasReflect?: boolean;
	/** 显式传入快速模型（覆盖环境变量 NUWA_MODEL_FAST）。 */
	fastModel?: string;
	/** 显式传入深度推理模型（覆盖环境变量 NUWA_MODEL_DEEP）。 */
	deepModel?: string;
	/** 显式传入独立复验模型（覆盖环境变量 NUWA_MODEL_VERIFY）。 */
	verifyModel?: string;
	/** 可选项目根目录：存在已结算校准账本时启用自适应模型路由降权优选。 */
	root?: string;
	/** 可选候选模型白名单（与 fast/deep/verify 合并作为自适应路由允许集合）。 */
	allowedModels?: readonly string[];
}

interface MemoryLineageStore {
	sessions: Map<string, LineageSessionRecord>;
	spawns: SubagentSpawnBinding[];
	subSessionToRoot: Map<string, string>;
	agentIdToRoot: Map<string, string>;
}

const LINEAGE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_SESSIONS = 128;
const MAX_SPAWNS = 128;

const memoryStores = new Map<string, MemoryLineageStore>();
let atomicLineageSeq = 0;

/**
 * 解析当前生效的 agentHome 目录：优先使用显式入参，其次读 PI_AGENT_HOME，默认 ~/.omp/agent。
 */
export function resolveAgentHome(agentHome?: string): string {
	const explicit = (agentHome ?? "").trim();
	if (explicit) return resolve(explicit);
	const envHome = (process.env.PI_AGENT_HOME ?? "").trim();
	if (envHome) return resolve(envHome);
	const ompHome = join(homedir(), ".omp", "agent");
	if (existsSync(ompHome)) return ompHome;
	const piHome = join(homedir(), ".pi", "agent");
	return existsSync(piHome) ? piHome : ompHome;
}

/**
 * 返回血缘磁盘缓存文件绝对路径：<agentHome>/cache/nuwa-lineage.json。
 */
export function lineageCachePath(agentHome?: string): string {
	return join(resolveAgentHome(agentHome), "cache", "nuwa-lineage.json");
}

function sha1Short(input: string, len = 16): string {
	return createHash("sha1").update(input).digest("hex").slice(0, len);
}

function atomicWriteJson(filePath: string, data: unknown): void {
	try {
		mkdirSync(dirname(filePath), { recursive: true });
		const body = `${JSON.stringify(data, null, 2)}\n`;
		const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}-${atomicLineageSeq++}`;
		const fd = openSync(tmp, "w");
		try {
			writeSync(fd, body);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		renameSync(tmp, filePath);
	} catch {
		/* 磁盘缓存写失败不阻断进程内血缘解析 */
	}
}

function readJsonSafe<T>(filePath: string): T | null {
	try {
		if (!existsSync(filePath)) return null;
		return JSON.parse(readFileSync(filePath, "utf8")) as T;
	} catch {
		return null;
	}
}

function isSharedDirectory(cwd: string): boolean {
	const r = resolve(cwd || process.cwd());
	const extra = (process.env.NUWA_SHARED_CWDS ?? "")
		.split(":")
		.map((s) => s.trim())
		.filter(Boolean)
		.map((s) => resolve(s));
	return [resolve(tmpdir()), resolve(homedir()), resolve("/"), resolve("/data/workspace"), ...extra].includes(r);
}

function usableRootForCwd(cwd: string, root: string): boolean {
	const c = resolve(cwd);
	const r = resolve(root);
	if (c === r) return true;
	return !isSharedDirectory(r);
}

function stateFileOf(root: string): string {
	return join(resolve(root), ".nuwa", "state.json");
}

interface RootStateMeta {
	exists: boolean;
	status?: string;
	ownerSessionId?: string;
}

function inspectRootState(root: string): RootStateMeta {
	const p = stateFileOf(root);
	if (existsSync(p)) {
		const parsed = readJsonSafe<{ project?: { status?: string; ownerSessionId?: string } }>(p);
		if (parsed && typeof parsed === "object") {
			return {
				exists: true,
				status: typeof parsed.project?.status === "string" ? parsed.project.status : undefined,
				ownerSessionId: typeof parsed.project?.ownerSessionId === "string" ? parsed.project.ownerSessionId : undefined,
			};
		}
	}
	const dbFile = join(resolve(root), ".nuwa", "nuwa.db");
	if (existsSync(dbFile)) {
		let db: Database | null = null;
		try {
			db = openSqliteReadonlyZeroWrite(dbFile);
			const row = db.query("SELECT value FROM meta WHERE key = 'project_json'").get() as { value?: string } | null;
			if (row?.value) {
				const proj = JSON.parse(row.value) as { status?: string; ownerSessionId?: string };
				return {
					exists: true,
					status: typeof proj?.status === "string" ? proj.status : undefined,
					ownerSessionId: typeof proj?.ownerSessionId === "string" ? proj.ownerSessionId : undefined,
				};
			}
		} catch {
			/* ignore readonly sqlite probe failure */
		} finally {
			try {
				db?.close();
			} catch {
				/* ignore */
			}
		}
	}
	return { exists: false };
}

/** 判断项目根目录是否包含处于活跃态（或未显式终止）的 .nuwa/state.json。 */
function isRootActive(root: string, requireExplicitActive = false): boolean {
	const meta = inspectRootState(root);
	if (!meta.exists) return false;
	if (requireExplicitActive) {
		return meta.status === "active";
	}
	return meta.status !== "stopped" && meta.status !== "completed";
}

function getMemoryStore(normHome: string): MemoryLineageStore {
	let store = memoryStores.get(normHome);
	if (!store) {
		store = {
			sessions: new Map<string, LineageSessionRecord>(),
			spawns: [],
			subSessionToRoot: new Map<string, string>(),
			agentIdToRoot: new Map<string, string>(),
		};
		memoryStores.set(normHome, store);
	}
	return store;
}

/**
 * 读取并合并进程内与磁盘 <agentHome>/cache/nuwa-lineage.json 的血缘快照。
 */
export function loadLineageCache(agentHome?: string): LineageCacheData {
	const normHome = resolveAgentHome(agentHome);
	const store = getMemoryStore(normHome);
	const disk = readJsonSafe<Partial<LineageCacheData>>(lineageCachePath(normHome));
	const cutoff = Date.now() - LINEAGE_TTL_MS;

	if (disk?.sessions && typeof disk.sessions === "object") {
		for (const [sid, rec] of Object.entries(disk.sessions)) {
			if (!rec || typeof rec.root !== "string" || typeof rec.updatedAt !== "number") continue;
			if (rec.updatedAt < cutoff) continue;
			const memRec = store.sessions.get(sid);
			if (!memRec || rec.updatedAt > memRec.updatedAt) {
				store.sessions.set(sid, {
					sessionId: sid,
					root: resolve(rec.root),
					cwd: resolve(rec.cwd || rec.root),
					...(rec.agentId ? { agentId: rec.agentId } : {}),
					...(rec.projectId ? { projectId: rec.projectId } : {}),
					updatedAt: rec.updatedAt,
				});
			}
		}
	}

	if (Array.isArray(disk?.spawns)) {
		const existingKey = new Set(
			store.spawns.map((s) => `${s.parentSessionId}|${s.parentAgentId ?? ""}|${s.root}|${s.spawnedAt}`),
		);
		for (const sp of disk.spawns) {
			if (!sp || typeof sp.root !== "string" || typeof sp.spawnedAt !== "number") continue;
			if (sp.spawnedAt < cutoff) continue;
			const normSp: SubagentSpawnBinding = {
				parentSessionId: String(sp.parentSessionId ?? ""),
				...(sp.parentAgentId ? { parentAgentId: String(sp.parentAgentId) } : {}),
				root: resolve(sp.root),
				...(sp.cwd ? { cwd: resolve(sp.cwd) } : {}),
				spawnedAt: sp.spawnedAt,
			};
			const k = `${normSp.parentSessionId}|${normSp.parentAgentId ?? ""}|${normSp.root}|${normSp.spawnedAt}`;
			if (!existingKey.has(k)) {
				existingKey.add(k);
				store.spawns.push(normSp);
			}
		}
	}

	pruneStore(store);
	return serializeStore(store);
}

function pruneStore(store: MemoryLineageStore): void {
	const cutoff = Date.now() - LINEAGE_TTL_MS;
	for (const [sid, rec] of store.sessions.entries()) {
		if (rec.updatedAt < cutoff) {
			store.sessions.delete(sid);
		}
	}
	if (store.sessions.size > MAX_SESSIONS) {
		const sorted = [...store.sessions.entries()].sort((a, b) => a[1].updatedAt - b[1].updatedAt);
		for (const [sid] of sorted.slice(0, store.sessions.size - MAX_SESSIONS)) {
			store.sessions.delete(sid);
		}
	}

	store.spawns = store.spawns
		.filter((s) => s.spawnedAt >= cutoff)
		.sort((a, b) => a.spawnedAt - b.spawnedAt)
		.slice(-MAX_SPAWNS);
}

function serializeStore(store: MemoryLineageStore): LineageCacheData {
	const sessions: Record<string, LineageSessionRecord> = {};
	for (const [sid, rec] of store.sessions.entries()) {
		sessions[sid] = rec;
	}
	return {
		schema: 1,
		updatedAt: Date.now(),
		sessions,
		spawns: [...store.spawns],
	};
}

function flushLineageStore(normHome: string, store: MemoryLineageStore): void {
	pruneStore(store);
	atomicWriteJson(lineageCachePath(normHome), serializeStore(store));
}

/**
 * 仅用于测试隔离：清空指定（或全部）agentHome 的进程内血缘缓存，以验证纯磁盘持久化恢复。
 */
export function clearLineageMemory(agentHome?: string): void {
	if (agentHome !== undefined) {
		memoryStores.delete(resolveAgentHome(agentHome));
		return;
	}
	memoryStores.clear();
}

/**
 * 注册或刷新主会话活跃项目绑定，同步写入内存血缘表与 <agentHome>/cache/nuwa-lineage.json。
 */
export function registerActiveSession(info: ActiveSessionInfo, agentHome?: string): LineageSessionRecord {
	const normHome = resolveAgentHome(agentHome);
	loadLineageCache(normHome);
	const store = getMemoryStore(normHome);

	const sid = String(info.sessionId || "default").trim() || "default";
	const normRoot = resolve(info.root);
	const normCwd = resolve(info.cwd || info.root);
	const agentId = info.agentId ? String(info.agentId).trim() : undefined;
	const now = Number.isFinite(info.updatedAt) ? (info.updatedAt as number) : Date.now();

	const record: LineageSessionRecord = {
		sessionId: sid,
		root: normRoot,
		cwd: normCwd,
		...(agentId ? { agentId } : {}),
		...(info.projectId ? { projectId: String(info.projectId) } : {}),
		updatedAt: now,
	};

	store.sessions.set(sid, record);
	if (agentId) {
		store.agentIdToRoot.set(agentId, normRoot);
	}
	flushLineageStore(normHome, store);
	return record;
}

/**
 * 在主代理派发子代理（如 task 调用）前绑定父子血缘关系，持久化到 <agentHome>/cache/nuwa-lineage.json。
 */
export function bindSubagentSpawn(
	parentSessionId: string,
	parentAgentId: string | undefined,
	root: string,
	agentHome?: string,
): SubagentSpawnBinding {
	const normHome = resolveAgentHome(agentHome);
	loadLineageCache(normHome);
	const store = getMemoryStore(normHome);

	const pSid = String(parentSessionId ?? "").trim();
	const pAid = parentAgentId ? String(parentAgentId).trim() : undefined;
	const normRoot = resolve(root);
	const now = Date.now();

	const existingSession = pSid ? store.sessions.get(pSid) : undefined;
	const inferredCwd = existingSession?.cwd ?? (!isSharedDirectory(normRoot) ? normRoot : undefined);

	if (pSid) {
		store.sessions.set(pSid, {
			sessionId: pSid,
			root: normRoot,
			cwd: inferredCwd ?? normRoot,
			...(pAid ? { agentId: pAid } : existingSession?.agentId ? { agentId: existingSession.agentId } : {}),
			...(existingSession?.projectId ? { projectId: existingSession.projectId } : {}),
			updatedAt: now,
		});
	}
	if (pAid) {
		store.agentIdToRoot.set(pAid, normRoot);
	}

	// 去重合并同一父会话+父代理对同一 root 的近期 spawn，刷新时间戳置于队尾
	store.spawns = store.spawns.filter(
		(s) => !(s.parentSessionId === pSid && (s.parentAgentId ?? "") === (pAid ?? "") && s.root === normRoot),
	);

	const binding: SubagentSpawnBinding = {
		parentSessionId: pSid,
		...(pAid ? { parentAgentId: pAid } : {}),
		root: normRoot,
		...(inferredCwd ? { cwd: inferredCwd } : {}),
		spawnedAt: now,
	};
	store.spawns.push(binding);
	flushLineageStore(normHome, store);
	return binding;
}

function extractSessionId(ctx: LineageContextLike): string {
	if (typeof ctx.sessionId === "string" && ctx.sessionId.trim()) {
		return ctx.sessionId.trim();
	}
	try {
		const sid = ctx.sessionManager?.getSessionId?.();
		if (typeof sid === "string" && sid.trim()) return sid.trim();
	} catch {
		/* ignore */
	}
	return "";
}

function readSessionPointerRoot(normHome: string, sessionId: string): string | null {
	if (!sessionId) return null;
	const ptrPath = join(normHome, "cache", "nuwa-current.d", `${sha1Short(sessionId, 16)}.json`);
	const ptr = readJsonSafe<{ root?: string; sessionId?: string }>(ptrPath);
	if (!ptr?.root) return null;
	if (ptr.sessionId && ptr.sessionId !== sessionId) return null;
	const r = resolve(ptr.root);
	return inspectRootState(r).exists ? r : null;
}

function readLegacyPointerRoot(normHome: string): string | null {
	const ptrPath = join(normHome, "cache", "nuwa-current.json");
	const ptr = readJsonSafe<{ root?: string }>(ptrPath);
	if (!ptr?.root) return null;
	const r = resolve(ptr.root);
	return inspectRootState(r).exists ? r : null;
}

function cwdRelationScore(subCwd: string, recordCwd?: string): number {
	if (!recordCwd) return 0;
	const c = resolve(subCwd);
	const base = resolve(recordCwd);
	if (c === base) return 3;
	if (!isSharedDirectory(base) && c.startsWith(base + sep)) return 2;
	return 0;
}

function pickBestCandidate(
	candidates: Array<{ root: string; cwd?: string; ts: number }>,
	subCwd: string,
): string | null {
	const valid = candidates.filter((c) => isRootActive(c.root, false));
	if (valid.length === 0) return null;

	// 优先选择显式 status="active" > cwd 同目录/子目录匹配 > 时间戳最新
	valid.sort((a, b) => {
		const aAct = isRootActive(a.root, true) ? 1 : 0;
		const bAct = isRootActive(b.root, true) ? 1 : 0;
		if (bAct !== aAct) return bAct - aAct;
		const aRel = cwdRelationScore(subCwd, a.cwd);
		const bRel = cwdRelationScore(subCwd, b.cwd);
		if (bRel !== aRel) return bRel - aRel;
		return b.ts - a.ts;
	});

	return valid[0]?.root ?? null;
}

function resolveMainRoot(ctx: LineageContextLike, normHome: string, store: MemoryLineageStore): string | null {
	const start = resolve(ctx.cwd || process.cwd());
	const sid = extractSessionId(ctx);

	// 1. 沿 cwd 向上查找属于当前会话（或非共享无主）的 .nuwa/state.json
	let d = start;
	for (;;) {
		if (d !== start && isSharedDirectory(d)) break;
		const meta = inspectRootState(d);
		if (meta.exists) {
			if (!sid) return d;
			if (meta.ownerSessionId) {
				if (meta.ownerSessionId === sid) return d;
				break; // 其他会话占用的项目，停止向上查找，转查当前会话指针
			}
			if (!isSharedDirectory(d)) return d;
		}
		const up = dirname(d);
		if (up === d) break;
		d = up;
	}

	// 2. 环境变量 NUWA_PROJECT
	const envProj = (process.env.NUWA_PROJECT ?? "").trim();
	if (envProj && inspectRootState(resolve(envProj)).exists) {
		return resolve(envProj);
	}

	// 3. 血缘表已注册的当前会话
	if (sid) {
		const rec = store.sessions.get(sid);
		if (rec && inspectRootState(rec.root).exists && usableRootForCwd(start, rec.root)) {
			return rec.root;
		}
		const ptrRoot = readSessionPointerRoot(normHome, sid);
		if (ptrRoot && usableRootForCwd(start, ptrRoot)) {
			return ptrRoot;
		}
		return null;
	}

	// 4. 无 sessionId 时的 legacy 指针兜底
	const legacy = readLegacyPointerRoot(normHome);
	if (legacy && usableRootForCwd(start, legacy)) {
		return legacy;
	}
	return null;
}

/**
 * 解析当前扩展上下文所属的女娲项目 root：
 * - 主代理模式保持与 findRoot 一致的会话隔离语义；
 * - 子代理模式（ctx.agent?.kind === "sub"）按 parentSessionId / parentId 血缘映射 -> 同 cwd 活跃绑定 ->
 *   非共享目录向上 .nuwa/state.json(status="active") -> NUWA_PROJECT 顺序精准还原父项目 root。
 */
export function resolveLineageRoot(ctx: LineageContextLike, agentHome?: string): string | null {
	const normHome = resolveAgentHome(agentHome);
	loadLineageCache(normHome);
	const store = getMemoryStore(normHome);

	const isSub = ctx.agent?.kind === "sub" || (typeof ctx.agent?.depth === "number" && ctx.agent.depth > 0);
	if (!isSub) {
		return resolveMainRoot(ctx, normHome, store);
	}

	const subCwd = resolve(ctx.cwd || process.cwd());
	const subSid = extractSessionId(ctx);
	const subAgentId = (ctx.agent?.id ?? "").trim();

	// 0. 进程内已确认的子会话快速缓存
	if (subSid) {
		const cached = store.subSessionToRoot.get(subSid);
		if (cached && isRootActive(cached, false)) {
			return cached;
		}
	}

	const rememberAndReturn = (resolvedRoot: string): string => {
		const r = resolve(resolvedRoot);
		if (subSid) store.subSessionToRoot.set(subSid, r);
		if (subAgentId) store.agentIdToRoot.set(subAgentId, r);
		return r;
	};

	// 1. 显式父会话 ID / ctx.agent.parentId 血缘映射
	const explicitParentSid = (
		ctx.agent?.parentSessionId ??
		(() => {
			try {
				return ctx.sessionManager?.getParentSessionId?.();
			} catch {
				return undefined;
			}
		})() ??
		""
	).trim();
	const parentId = (ctx.agent?.parentId ?? "").trim();

	if (explicitParentSid) {
		const byParentSid: Array<{ root: string; cwd?: string; ts: number }> = [];
		for (const sp of store.spawns) {
			if (sp.parentSessionId === explicitParentSid) {
				byParentSid.push({ root: sp.root, cwd: sp.cwd, ts: sp.spawnedAt });
			}
		}
		const sess = store.sessions.get(explicitParentSid);
		if (sess) {
			byParentSid.push({ root: sess.root, cwd: sess.cwd, ts: sess.updatedAt });
		}
		const ptrRoot = readSessionPointerRoot(normHome, explicitParentSid);
		if (ptrRoot) {
			byParentSid.push({ root: ptrRoot, ts: 1 });
		}
		const picked = pickBestCandidate(byParentSid, subCwd);
		if (picked) return rememberAndReturn(picked);
	}

	if (parentId) {
		const byParentId: Array<{ root: string; cwd?: string; ts: number }> = [];
		for (const sp of store.spawns) {
			if (sp.parentAgentId === parentId || sp.parentSessionId === parentId) {
				byParentId.push({ root: sp.root, cwd: sp.cwd, ts: sp.spawnedAt });
			}
		}
		for (const sess of store.sessions.values()) {
			if (sess.agentId === parentId || sess.sessionId === parentId) {
				byParentId.push({ root: sess.root, cwd: sess.cwd, ts: sess.updatedAt });
			}
		}
		const chainedRoot = store.agentIdToRoot.get(parentId);
		if (chainedRoot) {
			byParentId.push({ root: chainedRoot, ts: Date.now() });
		}
		const ptrRoot = readSessionPointerRoot(normHome, parentId);
		if (ptrRoot) {
			byParentId.push({ root: ptrRoot, ts: 1 });
		}
		const picked = pickBestCandidate(byParentId, subCwd);
		if (picked) return rememberAndReturn(picked);
	}

	// 2. 同 cwd（或非共享父目录）活跃绑定匹配
	const sameCwdCandidates: Array<{ root: string; cwd?: string; ts: number }> = [];
	for (const sp of store.spawns) {
		if (cwdRelationScore(subCwd, sp.cwd) > 0) {
			sameCwdCandidates.push({ root: sp.root, cwd: sp.cwd, ts: sp.spawnedAt });
		}
	}
	for (const sess of store.sessions.values()) {
		if (cwdRelationScore(subCwd, sess.cwd) > 0) {
			sameCwdCandidates.push({ root: sess.root, cwd: sess.cwd, ts: sess.updatedAt });
		}
	}
	const sameCwdPicked = pickBestCandidate(sameCwdCandidates, subCwd);
	if (sameCwdPicked) return rememberAndReturn(sameCwdPicked);

	// 3. 非共享目录向上查找 .nuwa/state.json (status === "active")
	if (!isSharedDirectory(subCwd)) {
		let d = subCwd;
		for (;;) {
			if (isSharedDirectory(d)) break;
			if (isRootActive(d, true)) {
				return rememberAndReturn(d);
			}
			const up = dirname(d);
			if (up === d) break;
			d = up;
		}
	}

	// 4. 环境变量 NUWA_PROJECT 兜底
	const envProj = (process.env.NUWA_PROJECT ?? "").trim();
	if (envProj) {
		const normEnv = resolve(envProj);
		if (isRootActive(normEnv, false)) {
			return rememberAndReturn(normEnv);
		}
	}

	// 5. 当宿主子代理未携带 parentId（如部分内建调用），且当前 agentHome 仅存在唯一活跃 spawn 项目根时安全兜底
	if (!parentId && !explicitParentSid) {
		const activeSpawnRoots = new Set<string>();
		let latestRoot: string | null = null;
		for (let i = store.spawns.length - 1; i >= 0; i--) {
			const sp = store.spawns[i]!;
			if (isRootActive(sp.root, true) && usableRootForCwd(subCwd, sp.root)) {
				activeSpawnRoots.add(sp.root);
				if (!latestRoot) latestRoot = sp.root;
			}
		}
		if (activeSpawnRoots.size === 1 && latestRoot) {
			return rememberAndReturn(latestRoot);
		}
	}

	return null;
}

export interface TaskIntentRouteContext {
	intentId?: string;
	intentKey?: string;
	phase?: Phase;
	isVerify: boolean;
	isReflect: boolean;
}

/**
 * 按本次派单文本与子代理名称精准解析当前任务路由上下文（Issue #13）：
 * - 优先从 taskText 提取显式意图 ID（`[女娲派单 iXXX]` 或命中 intents 的 `\bi\d{3,}\b`），
 *   命中时依据该意图自身的 phase 与 key 判定 isVerify / isReflect；
 * - 未命中具体意图时回落到 fallbackPhase，仅依据 agentName 与 taskText 特征判定，
 *   绝不因盘面存在无关 open 的 verify-vuln:* 意图而误将常规侦察任务路由至复验模型。
 */
export function resolveTaskIntentContext(
	agentName: string,
	taskText: string,
	intents: Record<string, { id: string; key: string; phase: Phase; status: string }>,
	fallbackPhase: Phase,
): TaskIntentRouteContext {
	const normAgent = String(agentName ?? "").trim().toLowerCase();
	const text = String(taskText ?? "");
	const map = intents && typeof intents === "object" ? intents : {};

	const lookupIntent = (rawId: string | undefined) => {
		if (!rawId) return undefined;
		const trimmed = rawId.trim();
		if (!trimmed) return undefined;
		if (Object.prototype.hasOwnProperty.call(map, trimmed)) {
			return map[trimmed];
		}
		const lower = trimmed.toLowerCase();
		if (Object.prototype.hasOwnProperty.call(map, lower)) {
			return map[lower];
		}
		return undefined;
	};

	let matched: { id: string; key: string; phase: Phase; status: string } | undefined;

	const dispatchRe = /\[女娲派单\s+(i\d+)\]/gi;
	for (let m = dispatchRe.exec(text); m !== null; m = dispatchRe.exec(text)) {
		const hit = lookupIntent(m[1]);
		if (hit) {
			matched = hit;
			break;
		}
	}

	if (!matched) {
		const bareIdRe = /\b(i\d{3,})\b/gi;
		for (let m = bareIdRe.exec(text); m !== null; m = bareIdRe.exec(text)) {
			const hit = lookupIntent(m[1]);
			if (hit) {
				matched = hit;
				break;
			}
		}
	}

	const textSignalsVerify = /verify-vuln:|\[双盲独立复验任务/i.test(text);
	const textSignalsReflect = /\breflect:|战略复盘/i.test(text);

	if (matched) {
		const key = String(matched.key ?? "");
		return {
			intentId: matched.id,
			intentKey: key,
			phase: matched.phase,
			isVerify: normAgent === "nuwa-verifier" || /(?:^|:)verify-vuln:/i.test(key) || textSignalsVerify,
			isReflect: /^reflect:/i.test(key) || textSignalsReflect,
		};
	}

	return {
		phase: fallbackPhase,
		isVerify: normAgent === "nuwa-verifier" || textSignalsVerify,
		isReflect: textSignalsReflect,
	};
}

function cleanModelName(value: string | undefined): string | undefined {
	const trimmed = (value ?? "").trim();
	return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * 动态路由子代理模型：
 * - 支持显式入参或环境变量 NUWA_MODEL_FAST / NUWA_MODEL_DEEP / NUWA_MODEL_VERIFY；
 * - nuwa-verifier 或 hasPendingVerify 优先走 verifyModel || deepModel；
 * - vuln / exploit / hasReflect 走 deepModel；
 * - recon / surface 走 fastModel；
 * - 全未配置时返回 undefined，保持宿主默认模型配置。
 */
/**
 * 根据子代理角色、阶段与意图 Key 推断校准任务类别。
 */
export function inferCalibrationTaskCategory(input: {
	agent?: string;
	phase?: Phase | string;
	intentKey?: string;
	intentKeys?: readonly string[];
	hasPendingVerify?: boolean;
}): CalibrationTaskCategory {
	const agentName = (input.agent ?? "").trim().toLowerCase();
	const phase = (input.phase ?? "").trim().toLowerCase();
	const keys = [
		...(input.intentKeys ?? []),
		...(input.intentKey ? [input.intentKey] : []),
	].map((k) => String(k ?? "").trim().toLowerCase());

	if (
		agentName === "nuwa-verifier" ||
		Boolean(input.hasPendingVerify) ||
		keys.some((k) => /(?:^|:)verify-vuln:/i.test(k) || k.startsWith("verify:"))
	) {
		return "verify";
	}
	if (agentName === "nuwa-auth-breaker" || keys.some((k) => /auth|session|bola|bfla|idor|jwt|login/i.test(k))) {
		return "auth";
	}
	if (agentName === "nuwa-spa-reverser" || keys.some((k) => /spa|js|bundle|sourcemap|frontend|cdp/i.test(k))) {
		return "js-audit";
	}
	if (agentName === "nuwa-code-auditor" || keys.some((k) => /hybrid|whitebox|sast|code|audit/i.test(k))) {
		return "whitebox";
	}
	if (agentName === "nuwa-scout") {
		return "recon";
	}
	if (phase === "exploit" || phase === "post" || phase === "vuln") {
		return "exploit";
	}
	if (phase === "recon" || phase === "surface") {
		return "recon";
	}
	return "general";
}

export function routeSubagentModel(input: SubagentModelRouteInput = {}): string | undefined {
	const fastModel = cleanModelName(input.fastModel ?? process.env.NUWA_MODEL_FAST);
	const deepModel = cleanModelName(input.deepModel ?? process.env.NUWA_MODEL_DEEP);
	const verifyModel = cleanModelName(input.verifyModel ?? process.env.NUWA_MODEL_VERIFY);

	if (!fastModel && !deepModel && !verifyModel) {
		return undefined;
	}

	const agentName = (input.agent ?? "").trim().toLowerCase();
	const phase = (input.phase ?? "").trim().toLowerCase();
	const keys = [
		...(input.intentKeys ?? []),
		...(input.intentKey ? [input.intentKey] : []),
	].map((k) => String(k ?? "").trim().toLowerCase());

	const isVerifyTask =
		agentName === "nuwa-verifier" ||
		Boolean(input.hasPendingVerify) ||
		keys.some((k) => /(?:^|:)verify-vuln:/i.test(k) || k.startsWith("verify:"));

	let baseModel: string | undefined;
	if (isVerifyTask) {
		baseModel = verifyModel ?? deepModel;
	} else if (agentName === "nuwa-scout") {
		baseModel = fastModel ?? deepModel;
	} else if (agentName === "nuwa-code-auditor") {
		baseModel = deepModel ?? verifyModel;
	} else if (agentName === "nuwa-spa-reverser" || agentName === "nuwa-auth-breaker") {
		baseModel = deepModel ?? fastModel;
	} else {
		const isReflectTask = Boolean(input.hasReflect) || keys.some((k) => k.startsWith("reflect:"));
		if (phase === "vuln" || phase === "exploit" || isReflectTask) {
			baseModel = deepModel;
		} else if (phase === "recon" || phase === "surface") {
			baseModel = fastModel;
		} else if (phase === "post") {
			baseModel = deepModel ?? fastModel;
		} else if (phase === "report") {
			baseModel = fastModel ?? deepModel;
		}
	}

	if (!baseModel) return undefined;

	// v7.0 专精小队 + 校准驱动联合模型路由：结合 specialistRole × taskCategory × model 历史机械战绩择优
	if (input.root && (process.env.NUWA_CALIBRATION ?? "1").trim() !== "0") {
		const pool = [
			...new Set(
				[baseModel, fastModel, deepModel, verifyModel, ...(input.allowedModels ?? [])].filter(
					(m): m is string => Boolean(m && m.trim()),
				),
			),
		];
		if (pool.length >= 2 && hasCalibrationRecords(input.root)) {
			try {
				const records = loadCalibrationRecords(input.root);
				if (records.some((r) => r.settled)) {
					if (VALID_SPECIALIST_ROLES.has(agentName as SpecialistRole)) {
						const squadRec = recommendSpecialistAndModel(
							{
								key: keys[0] ?? "",
								phase: (phase || "recon") as Phase,
								worker: agentName,
							},
							null,
							records,
							{
								allowedModels: pool,
								defaultModel: baseModel,
								fastModel,
								deepModel: deepModel ?? verifyModel,
								verifyModel: verifyModel ?? deepModel,
								lockSpecialistRole: true,
							},
						);
						return squadRec.recommendedModel;
					}
					const decision = recommendAdaptiveModelRoute(records, {
						allowedModels: pool,
						defaultModel: baseModel,
						taskCategory: inferCalibrationTaskCategory(input),
					});
					return decision.recommendedModel;
				}
			} catch {
				/* 回退基准路由模型 */
			}
		}
	}

	return baseModel;
}

/**
 * 为单条意图推荐最佳 5+1 专精小队角色与适配模型（纯只读零磁盘写入，无校准记录时自动使用零样本意图画像分类）。
 */
export function recommendIntentSpecialist(
	intent: SpecialistIntentLike | null | undefined,
	state?: Partial<NuwaState> | null,
	root?: string,
	opts?: RecommendSpecialistOptions,
): SpecialistAndModelRecommendation {
	let records: CalibrationRecord[] = [];
	if (root && (process.env.NUWA_CALIBRATION ?? "1").trim() !== "0" && hasCalibrationRecords(root)) {
		try {
			records = loadCalibrationRecords(root);
		} catch {
			records = [];
		}
	}
	return recommendSpecialistAndModel(intent, state ?? null, records, opts);
}

// ============================================================================
// v5.1 派单目标自动注入、派单守卫与回执登记表、批派单分片/溢写、在途目标去重池
// 覆盖 Issues: #26 (NW-06), #27 (NW-07), #28 (NW-08), #50 (NW-30)
// ============================================================================

function sha256Short(input: string, len = 16): string {
	return createHash("sha256").update(input, "utf8").digest("hex").slice(0, len);
}

function secureAtomicWriteJson(filePath: string, data: unknown): void {
	mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
	const body = `${JSON.stringify(data, null, 2)}\n`;
	const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}-${atomicLineageSeq++}`;
	const fd = openSync(tmp, "w", 0o600);
	try {
		writeSync(fd, body);
		fsyncSync(fd);
	} finally {
		closeSync(fd);
	}
	try {
		chmodSync(tmp, 0o600);
	} catch {
		/* 非 POSIX 忽略 */
	}
	renameSync(tmp, filePath);
	try {
		chmodSync(filePath, 0o600);
	} catch {
		/* 非 POSIX 忽略 */
	}
}

// ----------------------------------------------------------------------------
// #26 (NW-06) 派单构建时自动注入 resolved_host 与目标 URL
// ----------------------------------------------------------------------------

export interface DispatchTargetContext {
	url?: string;
	target?: string;
	host?: string;
	resolvedHost?: string;
	port?: number;
	scheme?: string;
	resolvedIp?: string;
	egress?: string;
}

export interface DispatchPacketInput {
	task: string;
	target: DispatchTargetContext;
	intentId?: string;
	agent?: string;
	targetKey?: string;
}

export interface DispatchPacketResult {
	task: string;
	resolvedHost: string;
	targetUrl: string;
	targetKey: string;
	injected: boolean;
	replacedPlaceholders: number;
}

function resolveTargetEndpoint(target: DispatchTargetContext): { resolvedHost: string; targetUrl: string } {
	const rawUrl = String(target.url ?? target.target ?? "").trim();
	const rawHost = String(target.resolvedHost ?? target.host ?? "").trim();

	if (rawUrl) {
		const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl)
			? rawUrl
			: `${target.scheme || (target.port === 443 ? "https" : "http")}://${rawUrl}`;
		try {
			const u = new URL(withScheme);
			const host = rawHost || u.hostname;
			const portPart = u.port
				? `:${u.port}`
				: target.port && !((u.protocol === "http:" && target.port === 80) || (u.protocol === "https:" && target.port === 443))
					? `:${target.port}`
					: "";
			const pathname = u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, "");
			return {
				resolvedHost: host,
				targetUrl: `${u.protocol}//${host}${portPart}${pathname}${u.search}`,
			};
		} catch {
			/* 回退到 host 拼接 */
		}
	}

	const host = rawHost.replace(/^https?:\/\//i, "").split(/[/:?#]/)[0] ?? "";
	const scheme = (target.scheme ?? (target.port === 443 ? "https" : "http")).replace(/:$/, "");
	const portSuffix =
		target.port && !((scheme === "http" && target.port === 80) || (scheme === "https" && target.port === 443))
			? `:${target.port}`
			: "";
	const targetUrl = host ? `${scheme}://${host}${portSuffix}` : rawUrl;
	return { resolvedHost: host, targetUrl };
}

/**
 * #26 (NW-06) 将解析后的 `resolved_host` 与目标 URL 自动注入派单正文，
 * 并展开残留的 `https://TARGET`、`[TARGET]`、`[HOST]`、`[DOMAIN]`、`$U` 等占位符。
 */
export function injectResolvedTargetContext(
	taskText: string,
	target: DispatchTargetContext,
): { task: string; resolvedHost: string; targetUrl: string; replacedPlaceholders: number } {
	const { resolvedHost, targetUrl } = resolveTargetEndpoint(target);
	let body = String(taskText ?? "");
	let replacedPlaceholders = 0;

	const replaceAll = (re: RegExp, val: string) => {
		if (!val) return;
		body = body.replace(re, () => {
			replacedPlaceholders++;
			return val;
		});
	};

	if (targetUrl) {
		replaceAll(/https?:\/\/(?:TARGET|HOST|DOMAIN)(?::\d+)?/g, targetUrl);
		replaceAll(/\$\{?U\}?/g, targetUrl);
		replaceAll(/\[(?:TARGET_URL|URL)\]/g, targetUrl);
	}
	if (resolvedHost) {
		replaceAll(/\[(?:TARGET|HOST|DOMAIN)\]/g, resolvedHost);
		replaceAll(/\$\{?(?:TARGET|HOST|DOMAIN)\}?/g, resolvedHost);
		replaceAll(/\b(?:TARGET|HOST|DOMAIN)\b/g, resolvedHost);
	}

	const headerLines: string[] = [];
	if (resolvedHost && !new RegExp(`resolved_host\\s*[:=]\\s*${resolvedHost.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`, "i").test(body)) {
		headerLines.push(`resolved_host: ${resolvedHost}`);
	}
	if (targetUrl && !body.includes(`target_url: ${targetUrl}`)) {
		headerLines.push(`target_url: ${targetUrl}`);
	}
	if (target.resolvedIp && !body.includes(`resolved_ip: ${target.resolvedIp}`)) {
		headerLines.push(`resolved_ip: ${target.resolvedIp}`);
	}
	if (target.egress && !body.includes(`egress: ${target.egress}`)) {
		headerLines.push(`egress: ${target.egress}`);
	}

	const finalTask =
		headerLines.length > 0
			? `[派单目标上下文]\n${headerLines.join("\n")}\n\n${body.trim()}`
			: body.trim();

	return {
		task: finalTask,
		resolvedHost,
		targetUrl,
		replacedPlaceholders,
	};
}

/**
 * #26 (NW-06) 构造带 `resolved_host` 与 `target_url` 自动注入的规范派单包。
 */
export function buildDispatchPacket(input: DispatchPacketInput): DispatchPacketResult {
	const injectedRes = injectResolvedTargetContext(input.task, input.target);
	const targetKey = normalizeDispatchTargetKey(
		input.targetKey || injectedRes.targetUrl || injectedRes.resolvedHost || "",
	);
	return {
		task: injectedRes.task,
		resolvedHost: injectedRes.resolvedHost,
		targetUrl: injectedRes.targetUrl,
		targetKey,
		injected: Boolean(injectedRes.resolvedHost || injectedRes.targetUrl),
		replacedPlaceholders: injectedRes.replacedPlaceholders,
	};
}

// ----------------------------------------------------------------------------
// #27 (NW-07) 子代理派单校验 validateSubagentDispatch 与派单回执登记表
// ----------------------------------------------------------------------------

export interface SubagentDispatchPayload {
	spawnId?: string;
	agent?: string;
	task?: string;
	prompt?: string;
	targetKey?: string;
	targetUrl?: string;
	resolvedHost?: string;
	intentId?: string;
	context?: Record<string, unknown> | string;
	minTaskLength?: number;
}

export interface DispatchValidationResult {
	ok: boolean;
	accepted: boolean;
	requeue: boolean;
	reason?: string;
	reasons: string[];
	taskHash?: string;
	spawnId?: string;
	targetKey?: string;
}

export interface DispatchReceipt {
	spawnId: string;
	taskHash: string;
	dispatchedAt: string;
	targetKey: string;
	agent?: string;
	intentId?: string;
	taskBytes: number;
	acknowledgedAt?: string;
	contextLength?: number;
	status: "dispatched" | "acknowledged" | "requeued" | "completed" | "failed";
}

const EMPTY_AGENT_CONTEXT_RE =
	/\b(?:no\s+assigned\s+task|awaiting\s+work\s+item|no\s+task\s+provided|empty\s+task)\b/i;
const UNEXPANDED_DISPATCH_PLACEHOLDER_RE = /\[(?:TARGET|HOST|DOMAIN|URL)\]|https?:\/\/(?:TARGET|HOST|DOMAIN)\b/i;

function extractTargetKeyFromDispatch(payload: SubagentDispatchPayload, taskText: string): string {
	if (payload.targetKey && payload.targetKey.trim()) {
		return normalizeDispatchTargetKey(payload.targetKey);
	}
	if (payload.targetUrl && payload.targetUrl.trim()) {
		return normalizeDispatchTargetKey(payload.targetUrl);
	}
	const urlHit = /https?:\/\/[^\s"'<>`)\]]+/i.exec(taskText);
	if (urlHit?.[0]) {
		return normalizeDispatchTargetKey(urlHit[0].replace(/[),.;]+$/, ""));
	}
	if (payload.resolvedHost && payload.resolvedHost.trim()) {
		return normalizeDispatchTargetKey(payload.resolvedHost);
	}
	const pathHit = /(?:^|\s)(\/[a-zA-Z0-9._~/%-]{2,})(?=$|\s|[,;)])/.exec(taskText);
	if (pathHit?.[1]) {
		return normalizeDispatchTargetKey(pathHit[1]);
	}
	return "";
}

/**
 * #27 (NW-07) 校验子代理派单载荷：
 * - 校验 `task` 非空、达到最小有效长度且不含空转占位描述；
 * - 校验目标与执行上下文完整（禁止缺失目标信息或传入空 context 壳或未展开模板占位符）；
 * - 不通过时直接拒收并返回 `requeue: true` 触发重排。
 */
export function validateSubagentDispatch(
	payload: SubagentDispatchPayload | null | undefined,
): DispatchValidationResult {
	if (!payload || typeof payload !== "object") {
		return {
			ok: false,
			accepted: false,
			requeue: true,
			reason: "派单载荷为空，已拒收并标记重排",
			reasons: ["派单载荷为空"],
		};
	}

	const rawTask = String(payload.task ?? payload.prompt ?? "").trim();
	const minLen =
		typeof payload.minTaskLength === "number" && Number.isFinite(payload.minTaskLength) && payload.minTaskLength > 0
			? Math.floor(payload.minTaskLength)
			: 8;
	const reasons: string[] = [];

	if (!rawTask) {
		reasons.push("派单 task 为空");
	} else {
		if (EMPTY_AGENT_CONTEXT_RE.test(rawTask)) {
			reasons.push("派单内容包含空任务占位语句（no assigned task / awaiting work item）");
		}
		if (rawTask.length < minLen) {
			reasons.push(`派单 task 过短（${rawTask.length} < ${minLen} 字符），上下文不完整`);
		}
		if (UNEXPANDED_DISPATCH_PLACEHOLDER_RE.test(rawTask)) {
			reasons.push("派单 task 含未展开目标占位符（[TARGET]/[HOST]/https://TARGET）");
		}
	}

	const hasExplicitContext =
		typeof payload.context === "string"
			? payload.context.trim().length > 0
			: payload.context !== undefined && payload.context !== null
				? Object.keys(payload.context).length > 0
				: false;
	const explicitEmptyContext =
		payload.context !== undefined && !hasExplicitContext;

	const resolvedTargetKey = extractTargetKeyFromDispatch(payload, rawTask);
	const hasTargetOrIntent =
		Boolean(resolvedTargetKey) ||
		Boolean(payload.resolvedHost?.trim()) ||
		Boolean(payload.targetUrl?.trim()) ||
		Boolean(payload.intentId?.trim()) ||
		/\bresolved_host\s*[:=]/i.test(rawTask);

	if (explicitEmptyContext && !hasTargetOrIntent) {
		reasons.push("派单 context 为空且缺少目标/意图上下文");
	} else if (rawTask && !hasTargetOrIntent && !hasExplicitContext) {
		reasons.push("派单缺少目标上下文（需提供 targetUrl / resolvedHost / targetKey / intentId 或明确目标 URL）");
	}

	if (reasons.length > 0) {
		return {
			ok: false,
			accepted: false,
			requeue: true,
			reason: `派单守卫拒收（需重排）: ${reasons.join("；")}`,
			reasons,
			spawnId: payload.spawnId?.trim() || undefined,
			targetKey: resolvedTargetKey || undefined,
		};
	}

	return {
		ok: true,
		accepted: true,
		requeue: false,
		reasons: [],
		taskHash: sha256Short(rawTask, 16),
		spawnId: payload.spawnId?.trim() || undefined,
		targetKey: resolvedTargetKey || "unknown",
	};
}

/**
 * #27 (NW-07) 派单回执登记表：记录 `spawnId -> { taskHash, dispatchedAt, targetKey }`，
 * 空任务直接拒收并标记重排，支持 spawn 后首条 context 长度回读核验与可选磁盘持久化。
 */
export class DispatchReceiptRegistry {
	private readonly receipts = new Map<string, DispatchReceipt>();
	private readonly persistPath?: string;

	constructor(persistPath?: string) {
		this.persistPath = persistPath ? resolve(persistPath) : undefined;
		this.loadFromDisk();
	}

	private loadFromDisk(): void {
		if (!this.persistPath || !existsSync(this.persistPath)) return;
		const data = readJsonSafe<{ receipts?: Record<string, DispatchReceipt> }>(this.persistPath);
		if (!data?.receipts || typeof data.receipts !== "object") return;
		for (const [k, rec] of Object.entries(data.receipts)) {
			if (rec && typeof rec.spawnId === "string" && typeof rec.taskHash === "string") {
				this.receipts.set(k, rec);
			}
		}
	}

	private flushToDisk(): void {
		if (!this.persistPath) return;
		const obj: Record<string, DispatchReceipt> = {};
		for (const [k, v] of this.receipts.entries()) {
			obj[k] = v;
		}
		try {
			secureAtomicWriteJson(this.persistPath, { schema: 1, updatedAt: new Date().toISOString(), receipts: obj });
		} catch {
			/* 持久化失败不影响内存登记表 */
		}
	}

	register(
		spawnId: string,
		payload: SubagentDispatchPayload,
	): {
		ok: boolean;
		requeue: boolean;
		receipt?: DispatchReceipt;
		validation: DispatchValidationResult;
	} {
		const sid = String(spawnId ?? payload?.spawnId ?? "").trim();
		const validation = validateSubagentDispatch({ ...payload, spawnId: sid });
		if (!sid) {
			return {
				ok: false,
				requeue: true,
				validation: {
					...validation,
					ok: false,
					accepted: false,
					requeue: true,
					reason: "缺少有效 spawnId，无法登记派单回执",
					reasons: [...validation.reasons, "缺少有效 spawnId"],
				},
			};
		}

		if (!validation.ok) {
			const rejectedReceipt: DispatchReceipt = {
				spawnId: sid,
				taskHash: "",
				dispatchedAt: new Date().toISOString(),
				targetKey: validation.targetKey ?? "",
				...(payload?.agent ? { agent: payload.agent } : {}),
				...(payload?.intentId ? { intentId: payload.intentId } : {}),
				taskBytes: Buffer.byteLength(String(payload?.task ?? payload?.prompt ?? ""), "utf8"),
				status: "requeued",
			};
			this.receipts.set(sid, rejectedReceipt);
			this.flushToDisk();
			return { ok: false, requeue: true, receipt: rejectedReceipt, validation };
		}

		const rawTask = String(payload.task ?? payload.prompt ?? "").trim();
		const receipt: DispatchReceipt = {
			spawnId: sid,
			taskHash: validation.taskHash!,
			dispatchedAt: new Date().toISOString(),
			targetKey: validation.targetKey ?? "unknown",
			...(payload.agent ? { agent: payload.agent } : {}),
			...(payload.intentId ? { intentId: payload.intentId } : {}),
			taskBytes: Buffer.byteLength(rawTask, "utf8"),
			status: "dispatched",
		};
		this.receipts.set(sid, receipt);
		this.flushToDisk();
		return { ok: true, requeue: false, receipt, validation };
	}

	/**
	 * spawn 后回读 agent 首条 context：校验长度 > 0 且非空任务告警，通过才确认入列，否则标记重排。
	 */
	acknowledge(
		spawnId: string,
		firstContextText: string,
	): { ok: boolean; requeue: boolean; reason?: string; receipt?: DispatchReceipt } {
		const sid = String(spawnId ?? "").trim();
		const rec = this.receipts.get(sid);
		if (!rec) {
			return { ok: false, requeue: true, reason: `未找到 spawnId=${sid} 的派单回执` };
		}
		const trimmed = String(firstContextText ?? "").trim();
		if (trimmed.length === 0 || EMPTY_AGENT_CONTEXT_RE.test(trimmed)) {
			rec.status = "requeued";
			rec.contextLength = trimmed.length;
			this.flushToDisk();
			return {
				ok: false,
				requeue: true,
				reason: `agent 侧首条 context 为空或缺失任务（spawnId=${sid}），已标记重排`,
				receipt: rec,
			};
		}
		rec.status = "acknowledged";
		rec.acknowledgedAt = new Date().toISOString();
		rec.contextLength = trimmed.length;
		this.flushToDisk();
		return { ok: true, requeue: false, receipt: rec };
	}

	get(spawnId: string): DispatchReceipt | undefined {
		return this.receipts.get(String(spawnId ?? "").trim());
	}

	markStatus(spawnId: string, status: DispatchReceipt["status"]): DispatchReceipt | undefined {
		const rec = this.receipts.get(String(spawnId ?? "").trim());
		if (!rec) return undefined;
		rec.status = status;
		this.flushToDisk();
		return rec;
	}

	list(filter?: { status?: DispatchReceipt["status"]; targetKey?: string }): DispatchReceipt[] {
		const out: DispatchReceipt[] = [];
		const normKey = filter?.targetKey ? normalizeDispatchTargetKey(filter.targetKey) : undefined;
		for (const rec of this.receipts.values()) {
			if (filter?.status && rec.status !== filter.status) continue;
			if (normKey && rec.targetKey !== normKey) continue;
			out.push(rec);
		}
		return out;
	}

	remove(spawnId: string): boolean {
		const ok = this.receipts.delete(String(spawnId ?? "").trim());
		if (ok) this.flushToDisk();
		return ok;
	}

	clear(): void {
		this.receipts.clear();
		this.flushToDisk();
	}
}

export function createDispatchReceiptRegistry(persistPath?: string): DispatchReceiptRegistry {
	return new DispatchReceiptRegistry(persistPath);
}

// ----------------------------------------------------------------------------
// #28 (NW-08) 批派单分片保护 chunkBatchTasks 与磁盘溢写 tasks_file
// ----------------------------------------------------------------------------

export const DEFAULT_BATCH_MAX_BYTES = 6000;

export interface BatchTaskItem {
	id?: string;
	intentId?: string;
	agent?: string;
	targetKey?: string;
	task: string;
	[key: string]: unknown;
}

export interface ChunkBatchOptions {
	/** 单片最大序列化字节数，默认 6000 */
	maxBytes?: number;
	/** 若提供 spillDir，超限时溢写至 <spillDir>/batch-<id>.json 返回轻量 tasks_file 引用 */
	spillDir?: string;
	/** 可选项目根目录，未传 spillDir 时溢写至 <root>/.nuwa/dispatches/batch-<id>.json */
	root?: string;
	/** 可选自定义批次 ID */
	batchId?: string;
	/** 是否在超限时优先整批溢写（当提供 spillDir/root 时默认为 true） */
	preferSpill?: boolean;
}

export interface BatchChunk<T = BatchTaskItem> {
	chunkIndex: number;
	totalChunks: number;
	bytes: number;
	taskCount: number;
	spilled: boolean;
	tasks?: T[];
	tasks_file?: string;
}

export interface ChunkBatchResult<T = BatchTaskItem> {
	exceeded: boolean;
	totalBytes: number;
	maxBytes: number;
	mode: "inline" | "chunked" | "spilled";
	chunks: Array<BatchChunk<T>>;
	tasks_file?: string;
	spilledFiles: string[];
}

function resolveBatchSpillDirectory(opts?: ChunkBatchOptions): string | undefined {
	if (opts?.spillDir && opts.spillDir.trim()) {
		return resolve(opts.spillDir.trim());
	}
	if (opts?.root && opts.root.trim()) {
		return join(resolve(opts.root.trim()), ".nuwa", "dispatches");
	}
	return undefined;
}

/**
 * #28 (NW-08) 批派单分片保护：
 * - 当序列化字节数 <= `maxBytes`（默认 `6000`）时保持 `mode="inline"` 原样返回；
 * - 超过 `maxBytes` 且未指定 `spillDir`/`root` 时自动按字节上限切分为多个安全分片（`mode="chunked"`）；
 * - 超过 `maxBytes` 且指定 `spillDir`（或 `root` -> `.nuwa/dispatches`）时溢写 `batch-<id>.json`，
 *   返回轻量 `tasks_file` 引用（`mode="spilled"`），避免 ~6.5KB JSON 截断丢任务。
 */
export function chunkBatchTasks<T = BatchTaskItem>(
	tasks: readonly T[],
	opts?: ChunkBatchOptions,
): ChunkBatchResult<T> {
	const list = Array.isArray(tasks) ? [...tasks] : [];
	const maxBytes =
		typeof opts?.maxBytes === "number" && Number.isFinite(opts.maxBytes) && opts.maxBytes >= 128
			? Math.floor(opts.maxBytes)
			: DEFAULT_BATCH_MAX_BYTES;
	const serializedAll = JSON.stringify(list);
	const totalBytes = Buffer.byteLength(serializedAll, "utf8");
	const spillDir = resolveBatchSpillDirectory(opts);

	if (totalBytes <= maxBytes && opts?.preferSpill !== true) {
		return {
			exceeded: false,
			totalBytes,
			maxBytes,
			mode: "inline",
			chunks: [
				{
					chunkIndex: 0,
					totalChunks: 1,
					bytes: totalBytes,
					taskCount: list.length,
					spilled: false,
					tasks: list,
				},
			],
			spilledFiles: [],
		};
	}

	const batchId =
		opts?.batchId?.trim().replace(/[^a-zA-Z0-9._-]/g, "_") ||
		`${Date.now()}-${sha256Short(serializedAll, 8)}`;

	// 贪心装箱切分（用于 chunked 模式与 spill 模式的分片元信息）
	const buckets: T[][] = [];
	let current: T[] = [];
	for (const item of list) {
		const candidate = [...current, item];
		const candBytes = Buffer.byteLength(JSON.stringify(candidate), "utf8");
		if (current.length > 0 && candBytes > maxBytes) {
			buckets.push(current);
			current = [item];
		} else {
			current = candidate;
		}
	}
	if (current.length > 0) {
		buckets.push(current);
	}

	if (spillDir && (opts?.preferSpill !== false || buckets.some((b) => Buffer.byteLength(JSON.stringify(b), "utf8") > maxBytes))) {
		mkdirSync(spillDir, { recursive: true, mode: 0o700 });
		const mainFile = join(spillDir, `batch-${batchId}.json`);
		secureAtomicWriteJson(mainFile, {
			schema: 1,
			batchId,
			createdAt: new Date().toISOString(),
			maxBytes,
			totalBytes,
			taskCount: list.length,
			tasks: list,
		});

		const spilledFiles = [mainFile];
		const chunks: Array<BatchChunk<T>> = [];

		if (buckets.length <= 1) {
			const refObj = { tasks_file: mainFile, taskCount: list.length };
			chunks.push({
				chunkIndex: 0,
				totalChunks: 1,
				bytes: Buffer.byteLength(JSON.stringify(refObj), "utf8"),
				taskCount: list.length,
				spilled: true,
				tasks_file: mainFile,
			});
		} else {
			for (let i = 0; i < buckets.length; i++) {
				const bucket = buckets[i]!;
				const chunkFile = join(spillDir, `batch-${batchId}-part${i + 1}.json`);
				secureAtomicWriteJson(chunkFile, {
					schema: 1,
					batchId,
					chunkIndex: i,
					totalChunks: buckets.length,
					createdAt: new Date().toISOString(),
					taskCount: bucket.length,
					tasks: bucket,
				});
				spilledFiles.push(chunkFile);
				const refObj = { tasks_file: chunkFile, taskCount: bucket.length };
				chunks.push({
					chunkIndex: i,
					totalChunks: buckets.length,
					bytes: Buffer.byteLength(JSON.stringify(refObj), "utf8"),
					taskCount: bucket.length,
					spilled: true,
					tasks_file: chunkFile,
				});
			}
		}

		return {
			exceeded: totalBytes > maxBytes,
			totalBytes,
			maxBytes,
			mode: "spilled",
			chunks,
			tasks_file: mainFile,
			spilledFiles,
		};
	}

	const chunks: Array<BatchChunk<T>> = buckets.map((bucket, idx) => ({
		chunkIndex: idx,
		totalChunks: buckets.length,
		bytes: Buffer.byteLength(JSON.stringify(bucket), "utf8"),
		taskCount: bucket.length,
		spilled: false,
		tasks: bucket,
	}));

	return {
		exceeded: totalBytes > maxBytes,
		totalBytes,
		maxBytes,
		mode: "chunked",
		chunks,
		spilledFiles: [],
	};
}

/**
 * 读取由 `chunkBatchTasks` 溢写至磁盘的 `tasks_file` JSON 任务列表。
 */
export function readSpilledBatchTasks<T = BatchTaskItem>(tasksFile: string): T[] {
	const parsed = readJsonSafe<{ tasks?: T[] } | T[]>(resolve(tasksFile));
	if (Array.isArray(parsed)) return parsed;
	if (parsed && typeof parsed === "object" && Array.isArray(parsed.tasks)) {
		return parsed.tasks;
	}
	return [];
}

// ----------------------------------------------------------------------------
// #50 (NW-30) 跨子代理在途目标去重池 InflightTargetRegistry 与探针合并
// ----------------------------------------------------------------------------

export interface InflightTargetEntry {
	targetKey: string;
	intentId: string;
	worker: string;
	claimedAt: string;
	claimedAtMs: number;
	ttlMs: number;
}

export interface InflightClaimResult {
	claimed: boolean;
	targetKey: string;
	existing?: InflightTargetEntry;
	entry?: InflightTargetEntry;
}

export interface InflightFilterResult<T> {
	accepted: T[];
	skipped: Array<{
		task: T;
		targetKey: string;
		reason: "inflight_duplicate" | "batch_duplicate";
		existing?: InflightTargetEntry;
	}>;
}

export interface ProbeTaskLike {
	id?: string;
	intentId?: string;
	targetKey?: string;
	target?: string;
	url?: string;
	probe?: string;
	task?: string;
	title?: string;
	worker?: string;
	priority?: number;
	[key: string]: unknown;
}

export interface CoalescedProbeTask {
	targetKey: string;
	target: string;
	intentIds: string[];
	taskIds: string[];
	probes: string[];
	mergedTask: string;
	priority: number;
	sourceCount: number;
	worker?: string;
}

/**
 * 规范化派单目标键（统一大小写、默认端口、尾斜杠），确保跨子代理在途去重与探针合并准确命中。
 */
export function normalizeDispatchTargetKey(raw: string): string {
	const trimmed = String(raw ?? "").trim();
	if (!trimmed) return "";

	// 保留显式前缀类型（如 endpoint:/admin、port:host:80）并规范其主体
	const typedPrefix = /^(endpoint|port|host|path|chunk|asset|route):(.*)$/i.exec(trimmed);
	if (typedPrefix) {
		const prefix = typedPrefix[1]!.toLowerCase();
		const rest = normalizeDispatchTargetKey(typedPrefix[2]!);
		return `${prefix}:${rest}`;
	}

	if (/^https?:\/\//i.test(trimmed)) {
		try {
			const u = new URL(trimmed);
			const proto = u.protocol.toLowerCase();
			const host = u.hostname.toLowerCase();
			const port =
				u.port && !((proto === "http:" && u.port === "80") || (proto === "https:" && u.port === "443"))
					? `:${u.port}`
					: "";
			const pathname = u.pathname === "/" ? "/" : u.pathname.replace(/\/+$/, "");
			const params = [...u.searchParams.entries()].sort((a, b) => a[0].localeCompare(b[0]));
			const search = params.length > 0 ? `?${new URLSearchParams(params).toString()}` : "";
			return `${proto}//${host}${port}${pathname}${search}`;
		} catch {
			/* 回退到字符串规范化 */
		}
	}

	if (trimmed.startsWith("/")) {
		const normPath = trimmed.replace(/\/{2,}/g, "/");
		return normPath === "/" ? "/" : normPath.replace(/\/+$/, "").toLowerCase();
	}

	return trimmed.replace(/\/+$/, "").toLowerCase();
}

const DEFAULT_INFLIGHT_TTL_MS = 30 * 60 * 1000;

/**
 * #50 (NW-30) 跨子代理在途目标去重池：
 * 维护 `targetKey -> { intentId, worker, claimedAt }`，派单前过滤同 `targetKey` 重复任务，
 * 避免多个子代理并发重复探测同一路由或静态 chunk。
 */
export class InflightTargetRegistry {
	private readonly entries = new Map<string, InflightTargetEntry>();
	private readonly defaultTtlMs: number;
	private readonly persistPath?: string;

	constructor(opts?: { ttlMs?: number; persistPath?: string }) {
		this.defaultTtlMs =
			typeof opts?.ttlMs === "number" && Number.isFinite(opts.ttlMs) && opts.ttlMs > 0
				? opts.ttlMs
				: DEFAULT_INFLIGHT_TTL_MS;
		this.persistPath = opts?.persistPath ? resolve(opts.persistPath) : undefined;
		this.loadFromDisk();
	}

	private loadFromDisk(): void {
		if (!this.persistPath || !existsSync(this.persistPath)) return;
		const data = readJsonSafe<{ entries?: Record<string, InflightTargetEntry> }>(this.persistPath);
		if (!data?.entries || typeof data.entries !== "object") return;
		for (const [k, rec] of Object.entries(data.entries)) {
			if (rec && typeof rec.intentId === "string" && typeof rec.worker === "string") {
				this.entries.set(k, rec);
			}
		}
		this.pruneExpired();
	}

	private flushToDisk(): void {
		if (!this.persistPath) return;
		const obj: Record<string, InflightTargetEntry> = {};
		for (const [k, v] of this.entries.entries()) {
			obj[k] = v;
		}
		try {
			secureAtomicWriteJson(this.persistPath, { schema: 1, updatedAt: new Date().toISOString(), entries: obj });
		} catch {
			/* ignore */
		}
	}

	pruneExpired(nowMs = Date.now()): number {
		let removed = 0;
		for (const [key, entry] of this.entries.entries()) {
			const ttl = entry.ttlMs > 0 ? entry.ttlMs : this.defaultTtlMs;
			if (nowMs - entry.claimedAtMs >= ttl) {
				this.entries.delete(key);
				removed++;
			}
		}
		if (removed > 0) this.flushToDisk();
		return removed;
	}

	claim(
		targetKey: string,
		meta: { intentId: string; worker: string; claimedAt?: string; ttlMs?: number },
	): InflightClaimResult {
		const normKey = normalizeDispatchTargetKey(targetKey);
		if (!normKey) {
			return { claimed: false, targetKey: "" };
		}
		this.pruneExpired();
		const existing = this.entries.get(normKey);
		if (existing && !(existing.intentId === meta.intentId && existing.worker === meta.worker)) {
			return { claimed: false, targetKey: normKey, existing };
		}
		const nowMs = meta.claimedAt ? Date.parse(meta.claimedAt) || Date.now() : Date.now();
		const claimedAt = meta.claimedAt || new Date(nowMs).toISOString();
		const entry: InflightTargetEntry = {
			targetKey: normKey,
			intentId: String(meta.intentId ?? "").trim() || "unknown",
			worker: String(meta.worker ?? "").trim() || "fujiang",
			claimedAt,
			claimedAtMs: nowMs,
			ttlMs:
				typeof meta.ttlMs === "number" && Number.isFinite(meta.ttlMs) && meta.ttlMs > 0
					? meta.ttlMs
					: this.defaultTtlMs,
		};
		this.entries.set(normKey, entry);
		this.flushToDisk();
		return { claimed: true, targetKey: normKey, entry };
	}

	isInflight(targetKey: string): boolean {
		const normKey = normalizeDispatchTargetKey(targetKey);
		if (!normKey) return false;
		this.pruneExpired();
		return this.entries.has(normKey);
	}

	get(targetKey: string): InflightTargetEntry | undefined {
		const normKey = normalizeDispatchTargetKey(targetKey);
		if (!normKey) return undefined;
		this.pruneExpired();
		return this.entries.get(normKey);
	}

	release(targetKey: string, matcher?: { intentId?: string; worker?: string }): boolean {
		const normKey = normalizeDispatchTargetKey(targetKey);
		const existing = this.entries.get(normKey);
		if (!existing) return false;
		if (matcher?.intentId && existing.intentId !== matcher.intentId) return false;
		if (matcher?.worker && existing.worker !== matcher.worker) return false;
		const deleted = this.entries.delete(normKey);
		if (deleted) this.flushToDisk();
		return deleted;
	}

	releaseByIntent(intentId: string): number {
		let count = 0;
		for (const [k, v] of this.entries.entries()) {
			if (v.intentId === intentId) {
				this.entries.delete(k);
				count++;
			}
		}
		if (count > 0) this.flushToDisk();
		return count;
	}

	releaseByWorker(worker: string): number {
		let count = 0;
		for (const [k, v] of this.entries.entries()) {
			if (v.worker === worker) {
				this.entries.delete(k);
				count++;
			}
		}
		if (count > 0) this.flushToDisk();
		return count;
	}

	list(): InflightTargetEntry[] {
		this.pruneExpired();
		return [...this.entries.values()];
	}

	clear(): void {
		this.entries.clear();
		this.flushToDisk();
	}

	/**
	 * 派单前过滤同 `targetKey` 在途重复任务与同批次重复任务；可选 `autoClaim=true` 自动登记占坑。
	 */
	filterTasks<T extends ProbeTaskLike>(
		tasks: readonly T[],
		opts?: { autoClaim?: boolean; defaultWorker?: string },
	): InflightFilterResult<T> {
		this.pruneExpired();
		const accepted: T[] = [];
		const skipped: InflightFilterResult<T>["skipped"] = [];
		const batchSeen = new Set<string>();

		for (const task of tasks) {
			const rawKey = String(task.targetKey ?? task.url ?? task.target ?? "").trim();
			const normKey = normalizeDispatchTargetKey(rawKey);
			if (!normKey) {
				accepted.push(task);
				continue;
			}
			if (batchSeen.has(normKey)) {
				skipped.push({ task, targetKey: normKey, reason: "batch_duplicate" });
				continue;
			}
			const existing = this.entries.get(normKey);
			if (existing) {
				skipped.push({ task, targetKey: normKey, reason: "inflight_duplicate", existing });
				continue;
			}
			batchSeen.add(normKey);
			accepted.push(task);
			if (opts?.autoClaim) {
				this.claim(normKey, {
					intentId: String(task.intentId ?? task.id ?? normKey),
					worker: String(task.worker ?? opts.defaultWorker ?? "fujiang"),
				});
			}
		}

		return { accepted, skipped };
	}
}

/**
 * #50 (NW-30) 按规范化 `targetKey` 合并同目标探针，避免多个子代理重复抓取同一端点或同一批 chunk。
 */
export function coalesceProbesByTarget<T extends ProbeTaskLike>(tasks: readonly T[]): CoalescedProbeTask[] {
	const groups = new Map<
		string,
		{
			targetKey: string;
			target: string;
			intentIds: string[];
			taskIds: string[];
			probes: string[];
			priority: number;
			sourceCount: number;
			worker?: string;
			firstIndex: number;
		}
	>();

	for (let i = 0; i < tasks.length; i++) {
		const item = tasks[i]!;
		const rawTarget = String(item.targetKey ?? item.url ?? item.target ?? "").trim();
		const normKey = normalizeDispatchTargetKey(rawTarget) || `anon:${i}`;
		const displayTarget = String(item.url ?? item.target ?? item.targetKey ?? normKey).trim();
		const probeDesc = String(item.probe ?? item.task ?? item.title ?? "").trim();
		const prio = typeof item.priority === "number" && Number.isFinite(item.priority) ? item.priority : 50;

		let group = groups.get(normKey);
		if (!group) {
			group = {
				targetKey: normKey,
				target: displayTarget,
				intentIds: [],
				taskIds: [],
				probes: [],
				priority: prio,
				sourceCount: 0,
				worker: item.worker ? String(item.worker) : undefined,
				firstIndex: i,
			};
			groups.set(normKey, group);
		}

		group.sourceCount += 1;
		if (prio > group.priority) group.priority = prio;
		if (!group.worker && item.worker) group.worker = String(item.worker);
		if (item.intentId && !group.intentIds.includes(item.intentId)) {
			group.intentIds.push(item.intentId);
		}
		if (item.id && !group.taskIds.includes(item.id)) {
			group.taskIds.push(item.id);
		}
		if (probeDesc && !group.probes.includes(probeDesc)) {
			group.probes.push(probeDesc);
		}
	}

	return [...groups.values()]
		.sort((a, b) => (b.priority !== a.priority ? b.priority - a.priority : a.firstIndex - b.firstIndex))
		.map((g) => {
			const mergedTask =
				g.probes.length <= 1
					? `[合并探针 target=${g.target}] ${g.probes[0] ?? "执行单次定向探测"}`
					: [
							`[合并同目标探针 target=${g.target} (合并 ${g.sourceCount} 条任务)]`,
							...g.probes.map((p, idx) => `${idx + 1}. ${p}`),
						].join("\n");
			return {
				targetKey: g.targetKey,
				target: g.target,
				intentIds: g.intentIds,
				taskIds: g.taskIds,
				probes: g.probes,
				mergedTask,
				priority: g.priority,
				sourceCount: g.sourceCount,
				...(g.worker ? { worker: g.worker } : {}),
			};
		});
}
