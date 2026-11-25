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
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import type { Phase } from "./types";

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
	if (!existsSync(p)) return { exists: false };
	const parsed = readJsonSafe<{ project?: { status?: string; ownerSessionId?: string } }>(p);
	if (!parsed || typeof parsed !== "object") return { exists: false };
	return {
		exists: true,
		status: typeof parsed.project?.status === "string" ? parsed.project.status : undefined,
		ownerSessionId: typeof parsed.project?.ownerSessionId === "string" ? parsed.project.ownerSessionId : undefined,
	};
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

	if (isVerifyTask) {
		return verifyModel ?? deepModel;
	}

	const isReflectTask = Boolean(input.hasReflect) || keys.some((k) => k.startsWith("reflect:"));
	if (phase === "vuln" || phase === "exploit" || isReflectTask) {
		return deepModel;
	}

	if (phase === "recon" || phase === "surface") {
		return fastModel;
	}

	if (phase === "post") {
		return deepModel ?? fastModel;
	}

	if (phase === "report") {
		return fastModel ?? deepModel;
	}

	return undefined;
}
