/**
 * 女娲 v4.0 状态持久化、文件锁、快照恢复与会话指针存储层。
 *
 * 职责：
 *   1. 配置读取 `readCfg`、目标规范化 `normalizeTarget` / `normalizeTargetForMode`；
 *   2. 跨进程文件锁 `withLock`（支持同进程重入与死锁自动回收）与原子写 `atomicWrite`；
 *   3. 增量 `.json.gz` 快照、Agent 缓存镜像备份、journal 轮转与崩溃恢复；
 *   4. 多会话指针隔离 `findRoot` / `findLocalRoot` / `writePointer` / `defaultProjectRoot`；
 *   5. 旧 `.sapper` 图迁移 `migrateSapper` 以及状态归一化 `normalizeState` / `loadState` / `saveState`。
 *
 * 约束：严禁运行时 `import "./nuwa"`，保持纯单向无环模块依赖。
 */
import { createHash } from "node:crypto";
import {
	appendFileSync,
	closeSync,
	existsSync,
	fsyncSync,
	mkdirSync,
	openSync,
	readFileSync,
	readdirSync,
	renameSync,
	statSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import {
	NUWA_VERSION,
	type Cfg,
	type FactKind,
	type Mode,
	type NuwaState,
	type Runtime,
	type ScopePolicy,
} from "./types";
import { defaultScopeForTarget } from "./scope";
import { resolveKbPath } from "./kb";
import { loadAutoRules } from "./autoexec";
import { parseJournalTail, type JournalEntry } from "./ui";

export const SCHEMA = 1;

/** 动态解析当前生效的 Agent Home，兼容测试期动态切换 `PI_AGENT_HOME`。 */
export function getAgentHome(): string {
	const envHome = process.env.PI_AGENT_HOME?.trim();
	if (envHome) return resolve(envHome);
	const ompHome = join(homedir(), ".omp/agent");
	if (existsSync(ompHome)) return ompHome;
	return join(homedir(), ".pi/agent");
}

function pointerFilePath(): string {
	return join(getAgentHome(), "cache/nuwa-current.json");
}

function pointerDirPath(): string {
	return join(getAgentHome(), "cache/nuwa-current.d");
}

function projectsDirPath(): string {
	return join(getAgentHome(), "cache/nuwa-projects");
}

const loggedInvalidAutoCfg = new Set<string>();

/** 实时读取当前项目的自动批规则源；外置规则非法时去重写入 autoexec_config_invalid 事件。 */
export function checkAndLogAutoRuleSource(root?: string, st?: NuwaState): "project" | "global" | "builtin" {
	const agentHome = getAgentHome();
	if (root && root.trim()) {
		try {
			const loaded = loadAutoRules(root, agentHome);
			if (loaded.error) {
				const sig = `${resolve(root)}|${loaded.path ?? ""}|${loaded.error}`;
				if (!loggedInvalidAutoCfg.has(sig)) {
					loggedInvalidAutoCfg.add(sig);
					logEvent(root, { type: "autoexec_config_invalid", path: loaded.path, error: loaded.error });
				}
			}
			return loaded.source;
		} catch {
			/* 回退到已有读数或内置 */
		}
	}
	const rs = st?.runtime?.rulesSource;
	if (rs === "project" || rs === "global" || rs === "builtin") return rs;
	try {
		return loadAutoRules(undefined, agentHome).source;
	} catch {
		return "builtin";
	}
}

export function recordInvalidAutoRuleOnce(root: string, error: string, path?: string): void {
	const normRoot = resolve(root);
	const sig = `${normRoot}|${path ?? ""}|${error}`;
	if (!loggedInvalidAutoCfg.has(sig)) {
		loggedInvalidAutoCfg.add(sig);
		logEvent(normRoot, { type: "autoexec_config_invalid", ...(path ? { path } : {}), error });
	}
}

function num(name: string, dflt: number, min: number, zeroOk = false): number {
	const raw = Number(process.env[name] ?? dflt);
	if (zeroOk && raw === 0) return 0;
	return Number.isFinite(raw) && raw >= min ? raw : dflt;
}

export function readCfg(): Cfg {
	return {
		loop: (process.env.NUWA_LOOP ?? "1").trim() !== "0",
		infinite: (process.env.NUWA_INFINITE ?? "1").trim() !== "0",
		maxTurns: num("NUWA_MAX_TURNS", 0, 0, true),
		maxStall: num("NUWA_MAX_STALL", 12, 1),
		maxIdle: num("NUWA_MAX_IDLE", 4, 1),
		maxTokens: num("NUWA_MAX_TOKENS", 0, 0, true),
		maxMinutes: num("NUWA_MAX_MINUTES", 0, 0, true),
		maxBatch: num("NUWA_MAX_BATCH", 4, 1),
		claimTtl: num("NUWA_CLAIM_TTL", 900, 30),
		blockStreak: num("NUWA_BLOCK_STREAK", 4, 1),
		guardHours: num("NUWA_GUARD_HOURS", 24, 1),
		kbDb: resolveKbPath(process.env.PI_AGENT_HOME),
		scannerGuard: (process.env.NUWA_SCANNER_GUARD ?? "1").trim() !== "0",
		requireFujiang: (process.env.NUWA_REQUIRE_FUJIANG ?? "1").trim() !== "0",
		tickMs: num("NUWA_TICK_MS", 60_000, 50),
		expandDepth: num("NUWA_EXPAND_DEPTH", 24, 1),
		maxEpisodes: num("NUWA_MAX_EPISODES", 0, 0, true),
		auto: (process.env.NUWA_AUTO ?? "1").trim() !== "0",
		autoMax: num("NUWA_AUTO_MAX", 3, 1),
		emptyLimit: num("NUWA_EMPTY_LIMIT", 3, 1),
		suspectLimit: num("NUWA_SUSPECT_LIMIT", 5, 1),
		maxAttempts: num("NUWA_MAX_ATTEMPTS", 3, 1),
		autoBudgetMs: num("NUWA_AUTO_BUDGET_MS", 90_000, 100),
		autoConcurrency: num("NUWA_AUTO_CONCURRENCY", 1, 1),
	};
}

export function nowIso(): string {
	return new Date().toISOString();
}

export function sha(input: string, len = 12): string {
	return createHash("sha1").update(input).digest("hex").slice(0, len);
}

export function normOneLine(s: string, max = 160): string {
	return s.replace(/\s+/g, " ").trim().slice(0, max);
}

/** Markdown 表格单元格：压平空白并转义竖线，避免命令里的管道打断表格。 */
export function cell(s: string | undefined, max = 160): string {
	return normOneLine(s ?? "", max).replace(/\|/g, "\\|");
}

export function slug(s: string): string {
	return (
		s
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 48) || "target"
	);
}

/** 目标规范化：补协议、取 host/port，路径保留但不带尾斜杠。 */
export function normalizeTarget(raw: string): { url: string; host: string; port: number; scheme: string } {
	let text = (raw ?? "").trim();
	if (!text) throw new Error("target 为空");
	if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
		text = (/:443(\/|$)/.test(text) ? "https://" : "http://") + text;
	}
	let u: URL;
	try {
		u = new URL(text);
	} catch {
		throw new Error(`无法解析 target: ${raw}`);
	}
	if (!u.hostname) throw new Error(`target 缺少 host: ${raw}`);
	if (!["http:", "https:"].includes(u.protocol)) throw new Error(`只支持 http/https: ${raw}`);
	const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
	const path = u.pathname.replace(/\/+$/, "");
	return {
		url: `${u.protocol}//${u.hostname}:${port}${path}`,
		host: u.hostname,
		port,
		scheme: u.protocol.replace(":", ""),
	};
}

/** 按 Profile 模式规范化目标：coding/ops/audit 允许本地路径或服务标识（无需强制 HTTP）。 */
export function normalizeTargetForMode(
	raw: string,
	mode: Mode = "ctf",
): { url: string; host: string; port: number; scheme: string } {
	const text = (raw ?? "").trim();
	if (!text) throw new Error("target 为空");
	if (mode !== "coding" && mode !== "ops" && mode !== "audit") {
		return normalizeTarget(text);
	}
	const looksLocalPath =
		text === "." ||
		text === ".." ||
		/^(?:\/|\.\.?\/|~\/|local:\/\/)/i.test(text) ||
		/^[A-Za-z]:[\\/]/.test(text);
	if (!looksLocalPath) {
		try {
			if (
				/^https?:\/\//i.test(text) ||
				/^((?:\d{1,3}\.){3}\d{1,3}|localhost)(?::\d{1,5})?(?:\/|$)/i.test(text) ||
				(mode === "audit" && /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:\/|$)/i.test(text))
			) {
				return normalizeTarget(text);
			}
		} catch {
			/* 回退为本地目录目标 */
		}
	}
	const clean = text.replace(/^local:\/\//i, "").replace(/\/+$/, "") || "workspace";
	const label = slug(clean.split("/").filter(Boolean).pop() ?? clean);
	return {
		url: `local://${clean}`,
		host: label,
		port: 0,
		scheme: "local",
	};
}

export function stateDir(root: string): string {
	return join(root, ".nuwa");
}

export function statePath(root: string): string {
	return join(stateDir(root), "state.json");
}

export function journalPath(root: string): string {
	return join(stateDir(root), "journal.jsonl");
}

export function lockPath(root: string): string {
	return join(stateDir(root), "state.lock");
}

export function readJson<T>(path: string): T | null {
	try {
		return JSON.parse(readFileSync(path, "utf8")) as T;
	} catch {
		return null;
	}
}

let atomicSeq = 0;

export function atomicWrite(path: string, body: string): void {
	mkdirSync(dirname(path), { recursive: true });
	const tmp = `${path}.tmp-${process.pid}-${Date.now()}-${atomicSeq++}`;
	const fd = openSync(tmp, "w");
	try {
		writeSync(fd, body);
		fsyncSync(fd);
	} finally {
		closeSync(fd);
	}
	renameSync(tmp, path);
	try {
		const dfd = openSync(dirname(path), "r");
		try {
			fsyncSync(dfd);
		} finally {
			closeSync(dfd);
		}
	} catch {
		/* 目录 fsync 在部分文件系统上不支持，忽略 */
	}
}

export function pidAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

/** /proc/<pid>/stat 第 22 字段（starttime），用于识别 PID 复用。 */
function procStartTime(pid: number): string | null {
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		const close = stat.lastIndexOf(")");
		if (close < 0) return null;
		const fields = stat.slice(close + 2).split(" ");
		return fields[19] ?? null;
	} catch {
		return null;
	}
}

function sleepSync(ms: number): void {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

const heldLocks = new Set<string>();

/** 单写者锁：同进程可重入防自锁；活进程持锁时只等不抢；空壳或死进程的锁立即回收。 */
export function withLock<T>(root: string, fn: () => T, opts?: { timeoutMs?: number }): T {
	mkdirSync(stateDir(root), { recursive: true });
	const p = resolve(lockPath(root));
	if (heldLocks.has(p)) {
		return fn();
	}
	const deadline = Date.now() + (opts?.timeoutMs ?? 10_000);
	let backoff = 4;
	for (;;) {
		let fd = -1;
		try {
			fd = openSync(p, "wx");
			writeSync(fd, JSON.stringify({ pid: process.pid, ts: Date.now(), start: procStartTime(process.pid) }));
			fsyncSync(fd);
			closeSync(fd);
			fd = -1;
			heldLocks.add(p);
			try {
				return fn();
			} finally {
				heldLocks.delete(p);
				try {
					unlinkSync(p);
				} catch {
					/* 已被回收 */
				}
			}
		} catch (err) {
			if (fd >= 0) {
				try {
					closeSync(fd);
				} catch {
					/* ignore */
				}
			}
			const code = (err as NodeJS.ErrnoException)?.code;
			if (code !== "EEXIST") throw err;
			const held = readJson<{ pid?: number; ts?: number; start?: string }>(p);
			const heldPid = typeof held?.pid === "number" ? held.pid : 0;
			const heldStart = typeof held?.start === "string" ? held.start : null;
			const sameProcess = heldPid > 0 && pidAlive(heldPid) && (!heldStart || heldStart === procStartTime(heldPid));
			if (sameProcess) {
				if (Date.now() >= deadline) {
					throw new Error(`state locked by pid ${heldPid} (>${Date.now() - (held?.ts ?? Date.now())}ms)`);
				}
				sleepSync(backoff);
				backoff = Math.min(backoff * 2, 120);
				continue;
			}
			try {
				unlinkSync(p);
			} catch {
				/* 被别的进程先回收，下一轮重试 */
			}
		}
	}
}

const JOURNAL_MAX_BYTES = 8 * 1024 * 1024;
const JOURNAL_KEEP = 5;

function journalArchivePath(root: string): string {
	const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 17);
	return join(stateDir(root), `journal.${stamp}-${process.pid}.jsonl`);
}

function pruneJournalArchives(root: string): void {
	try {
		const dir = stateDir(root);
		const arcs = readdirSync(dir)
			.filter((f) => /^journal\..+\.jsonl$/.test(f))
			.sort();
		for (const f of arcs.slice(0, Math.max(0, arcs.length - JOURNAL_KEEP))) {
			try {
				unlinkSync(join(dir, f));
			} catch {
				/* 已被别的进程清理 */
			}
		}
	} catch {
		/* 目录读失败不影响主流程 */
	}
}

function rotateJournal(root: string): void {
	try {
		renameSync(journalPath(root), journalArchivePath(root));
	} catch {
		return;
	}
	pruneJournalArchives(root);
}

export function journalAppend(root: string, rec: Record<string, unknown>): void {
	try {
		const p = journalPath(root);
		mkdirSync(dirname(p), { recursive: true });
		appendFileSync(p, JSON.stringify({ ts: nowIso(), ...rec }) + "\n", "utf8");
		if (statSync(p).size > JOURNAL_MAX_BYTES) rotateJournal(root);
	} catch {
		/* 日志失败不阻塞主流程 */
	}
}

export function logEvent(root: string, rec: Record<string, unknown>): void {
	journalAppend(root, { type: "event", ...rec });
}

/** 读 journal 尾部；超过 2MB 只取末尾，避免长跑项目每次刷新全量解析。 */
export function readJournalTail(root: string, limit = 200): JournalEntry[] {
	try {
		const raw = readFileSync(journalPath(root), "utf8");
		return parseJournalTail(raw.length > 2_000_000 ? raw.slice(-2_000_000) : raw, limit);
	} catch {
		return [];
	}
}

const SNAP_DIR = "snap";
const SNAP_KEEP = 5;

function snapshotDir(root: string): string {
	return join(stateDir(root), SNAP_DIR);
}

function pruneSnapshots(root: string): void {
	try {
		const dir = snapshotDir(root);
		const files = readdirSync(dir)
			.filter((f) => f.endsWith(".json.gz"))
			.sort();
		for (const f of files.slice(0, Math.max(0, files.length - SNAP_KEEP))) {
			try {
				unlinkSync(join(dir, f));
			} catch {
				/* 已被别的进程清理 */
			}
		}
	} catch {
		/* 目录缺失 */
	}
}

/** 项目目录被整块删除时的兜底镜像：同一份 gz 再写一份到 agent 缓存，保留 3 份。 */
function writeSnapshotMirror(state: NuwaState, body: Buffer, name: string): void {
	try {
		const id = (state.project?.id || "unknown").replace(/[^A-Za-z0-9._-]/g, "_");
		const dir = join(getAgentHome(), "cache", "nuwa-backup", id);
		mkdirSync(dir, { recursive: true });
		const fd = openSync(join(dir, name), "w");
		try {
			writeSync(fd, body);
		} finally {
			closeSync(fd);
		}
		const files = readdirSync(dir)
			.filter((f) => f.endsWith(".json.gz"))
			.sort();
		for (const f of files.slice(0, Math.max(0, files.length - 3))) {
			try {
				unlinkSync(join(dir, f));
			} catch {
				/* 已被别的进程清理 */
			}
		}
	} catch {
		/* 镜像失败不影响记账 */
	}
}

/** 快照写独立 gz 文件：journal 只留一行引用，避免每次记账把整图塞进日志。 */
function writeSnapshotFile(root: string, state: NuwaState): { file: string; bytes: number } | null {
	try {
		const dir = snapshotDir(root);
		mkdirSync(dir, { recursive: true });
		const name = `${Date.now()}-${process.pid}-${atomicSeq++}.json.gz`;
		const body = gzipSync(Buffer.from(JSON.stringify(state)));
		const full = join(dir, name);
		const fd = openSync(full, "w");
		try {
			writeSync(fd, body);
			fsyncSync(fd);
		} finally {
			closeSync(fd);
		}
		pruneSnapshots(root);
		writeSnapshotMirror(state, body, name);
		return { file: `${SNAP_DIR}/${name}`, bytes: body.length };
	} catch {
		return null;
	}
}

function readSnapshotFile(root: string, rel: string): NuwaState | null {
	try {
		const buf = readFileSync(join(stateDir(root), rel));
		const text = rel.endsWith(".gz") ? gunzipSync(buf).toString("utf8") : buf.toString("utf8");
		const st = JSON.parse(text) as NuwaState;
		return st?.schema === SCHEMA ? st : null;
	} catch {
		return null;
	}
}

function stateFromSnapshotRecord(root: string, rec: { type?: string; state?: NuwaState; file?: string }): NuwaState | null {
	if (rec?.type !== "snapshot") return null;
	if (rec.state?.schema === SCHEMA) return rec.state;
	if (typeof rec.file === "string") return readSnapshotFile(root, rec.file);
	return null;
}

function snapshotFrom(root: string, file: string): NuwaState | null {
	try {
		const raw = readFileSync(file, "utf8").trim().split("\n");
		for (let i = raw.length - 1; i >= 0; i--) {
			try {
				const rec = JSON.parse(raw[i]) as { type?: string; state?: NuwaState; file?: string };
				const st = stateFromSnapshotRecord(root, rec);
				if (st) return st;
			} catch {
				/* 跳过坏行 */
			}
		}
	} catch {
		/* 文件缺失 */
	}
	return null;
}

function latestSnapshotFile(root: string): NuwaState | null {
	try {
		const files = readdirSync(snapshotDir(root))
			.filter((f) => f.endsWith(".json.gz"))
			.sort()
			.reverse();
		for (const f of files) {
			const st = readSnapshotFile(root, `${SNAP_DIR}/${f}`);
			if (st) return st;
		}
	} catch {
		/* 目录缺失 */
	}
	return null;
}

/** 从 journal 当前文件、轮转归档、快照目录三处依次找最后一份快照，避免 state.json 半写损坏导致整图丢失。 */
function recoverFromJournal(root: string): NuwaState | null {
	const direct = snapshotFrom(root, journalPath(root));
	if (direct) return direct;
	let arcs: string[] = [];
	try {
		const dir = stateDir(root);
		arcs = readdirSync(dir)
			.filter((f) => /^journal\..+\.jsonl$/.test(f))
			.sort()
			.reverse();
	} catch {
		arcs = [];
	}
	for (const f of arcs) {
		const st = snapshotFrom(root, join(stateDir(root), f));
		if (st) return st;
	}
	return latestSnapshotFile(root);
}

/** 老 state 读入时就地补齐新增字段，避免 undefined 参与算术。 */
export function normalizeState(st: NuwaState): NuwaState {
	if (!st.project) throw new Error("state 缺少 project");
	st.project.episode = Number.isFinite(st.project.episode) && (st.project.episode as number) > 0 ? st.project.episode : 1;
	const cur: Partial<Runtime> = st.runtime ?? {};
	const rt: Runtime = {
		startedAt: Number.isFinite(cur.startedAt) ? (cur.startedAt as number) : Date.now(),
		turns: Number.isFinite(cur.turns) ? (cur.turns as number) : 0,
		stall: Number.isFinite(cur.stall) ? (cur.stall as number) : 0,
		idle: Number.isFinite(cur.idle) ? (cur.idle as number) : 0,
		blockStreak: Number.isFinite(cur.blockStreak) ? (cur.blockStreak as number) : 0,
		toolCalls: Number.isFinite(cur.toolCalls) ? (cur.toolCalls as number) : 0,
		lastToolCalls: Number.isFinite(cur.lastToolCalls) ? (cur.lastToolCalls as number) : 0,
		tokens: Number.isFinite(cur.tokens) ? (cur.tokens as number) : 0,
		lastSig: typeof cur.lastSig === "string" ? cur.lastSig : "",
		lastDirective: typeof cur.lastDirective === "string" ? cur.lastDirective : "",
		completionRejects: Number.isFinite(cur.completionRejects) ? (cur.completionRejects as number) : 0,
		emptyRounds: Number.isFinite(cur.emptyRounds) ? (cur.emptyRounds as number) : 0,
		suspectRounds: Number.isFinite(cur.suspectRounds) ? (cur.suspectRounds as number) : 0,
		lastSettleAt: Number.isFinite(cur.lastSettleAt) ? (cur.lastSettleAt as number) : 0,
		expansions: Number.isFinite(cur.expansions) ? (cur.expansions as number) : 0,
		lastExpandAt: Number.isFinite(cur.lastExpandAt) ? (cur.lastExpandAt as number) : 0,
		pressure: Number.isFinite(cur.pressure) ? (cur.pressure as number) : 0,
		lastFacts: Number.isFinite(cur.lastFacts) ? (cur.lastFacts as number) : -1,
		generation: Number.isFinite(cur.generation) && (cur.generation as number) > 0 ? (cur.generation as number) : 1,
		genTurns: Number.isFinite(cur.genTurns) ? (cur.genTurns as number) : 0,
		handoffSummary: typeof cur.handoffSummary === "string" ? cur.handoffSummary : undefined,
		netRetries: Number.isFinite(cur.netRetries) ? (cur.netRetries as number) : 0,
		saveCount: Number.isFinite(cur.saveCount) ? (cur.saveCount as number) : 0,
		stateBytes: Number.isFinite(cur.stateBytes) ? (cur.stateBytes as number) : undefined,
		rulesSource: typeof cur.rulesSource === "string" ? cur.rulesSource : undefined,
		projectStartedAt: Number.isFinite(cur.projectStartedAt)
			? (cur.projectStartedAt as number)
			: Number.isFinite(cur.startedAt)
				? (cur.startedAt as number)
				: Date.now(),
		totalTurns: Number.isFinite(cur.totalTurns)
			? Math.max(cur.totalTurns as number, Number.isFinite(cur.turns) ? (cur.turns as number) : 0)
			: Number.isFinite(cur.turns)
				? (cur.turns as number)
				: 0,
		totalTokens: Number.isFinite(cur.totalTokens) ? (cur.totalTokens as number) : 0,
		totalCostUsd: Number.isFinite(cur.totalCostUsd) ? (cur.totalCostUsd as number) : 0,
	};
	st.runtime = rt;
	if (!st.facts || typeof st.facts !== "object") st.facts = {};
	if (!st.intents || typeof st.intents !== "object") st.intents = {};
	if (!st.seq) st.seq = { fact: 0, intent: 0 };
	if (st.assets !== undefined && (typeof st.assets !== "object" || st.assets === null)) st.assets = {};
	if (st.hypotheses !== undefined && (typeof st.hypotheses !== "object" || st.hypotheses === null)) st.hypotheses = {};
	return st;
}

export function loadState(root: string): NuwaState | null {
	const direct = readJson<NuwaState>(statePath(root));
	if (direct && direct.schema === SCHEMA && direct.project) return normalizeState(direct);
	const recovered = recoverFromJournal(root);
	if (recovered) {
		try {
			atomicWrite(statePath(root), JSON.stringify(normalizeState(recovered), null, 2));
		} catch {
			/* 恢复成功即可 */
		}
	}
	return recovered ? normalizeState(recovered) : null;
}

const SNAPSHOT_KEY_REASONS = new Set(["init", "flag", "complete", "stop", "reincarnate"]);
const STATE_WARN_BYTES = 2 * 1024 * 1024;

export interface SaveStateOptions {
	forceSnapshot?: boolean;
	reason?: string;
}

/** 原子写盘 + 增量快照（每 10 次或关键里程碑写 .json.gz 快照，超 2MB 记告警日志）。 */
export function saveState(root: string, state: NuwaState, opts?: SaveStateOptions): void {
	state.project.updatedAt = nowIso();
	state.runtime.saveCount = (state.runtime.saveCount ?? 0) + 1;
	const preliminary = JSON.stringify(state, null, 2);
	state.runtime.stateBytes = Buffer.byteLength(preliminary, "utf8");
	const body = JSON.stringify(state, null, 2);
	const finalBytes = Buffer.byteLength(body, "utf8");
	state.runtime.stateBytes = finalBytes;

	const shouldSnap =
		Boolean(opts?.forceSnapshot) ||
		(opts?.reason ? SNAPSHOT_KEY_REASONS.has(opts.reason) : false) ||
		state.runtime.saveCount % 10 === 0;
	if (shouldSnap) {
		const snap = writeSnapshotFile(root, state);
		journalAppend(
			root,
			snap
				? { type: "snapshot", file: snap.file, bytes: snap.bytes, reason: opts?.reason ?? "periodic" }
				: { type: "snapshot", state, reason: opts?.reason ?? "periodic" },
		);
	}
	atomicWrite(statePath(root), body);
	if (finalBytes > STATE_WARN_BYTES) {
		logEvent(root, { type: "state_size_warn", bytes: finalBytes, limit: STATE_WARN_BYTES });
	}
}

/** 共享 cwd 不能直接放 .nuwa，否则同机多个任务会写同一份 state。 */
export function isSharedCwd(cwd: string): boolean {
	const r = resolve(cwd || process.cwd());
	const extra = (process.env.NUWA_SHARED_CWDS ?? "")
		.split(":")
		.map((s) => s.trim())
		.filter(Boolean)
		.map((s) => resolve(s));
	return [resolve(tmpdir()), resolve(homedir()), resolve("/"), resolve("/data/workspace"), ...extra].includes(r);
}

/** 共享根只服务“恰好在该目录”的会话；普通项目根允许会话指针跨 cwd 指向。 */
function usableRoot(cwd: string, root: string): boolean {
	const c = resolve(cwd);
	const r = resolve(root);
	if (c === r) return true;
	return !isSharedCwd(r);
}

function sessionPointerPath(sessionId: string): string {
	return join(pointerDirPath(), `${sha(sessionId || "default", 16)}.json`);
}

function stateOwner(dir: string): string | undefined {
	const raw = readJson<{ project?: { ownerSessionId?: string } }>(statePath(dir));
	return raw?.project?.ownerSessionId;
}

function stateUrl(dir: string): string | undefined {
	const raw = readJson<{ project?: { url?: string } }>(statePath(dir));
	return raw?.project?.url;
}

function safeTargetUrl(raw: string, mode: Mode = "ctf"): string {
	if (!raw) return "";
	try {
		return normalizeTargetForMode(raw, mode).url;
	} catch {
		try {
			return normalizeTargetForMode(raw, "coding").url;
		} catch {
			return raw.trim();
		}
	}
}

/** target 为空表示“不按目标过滤”；有 target 时只认同一个规范化 URL。 */
function sameTarget(dir: string, targetUrl: string): boolean {
	if (!targetUrl) return true;
	const url = stateUrl(dir);
	return !url || url === safeTargetUrl(targetUrl);
}

export function readSessionPointer(sessionId: string): { root?: string; sessionId?: string } | null {
	const ptr = readJson<{ root?: string; sessionId?: string }>(sessionPointerPath(sessionId));
	if (!ptr?.root || !existsSync(statePath(ptr.root))) return null;
	if (ptr.sessionId && ptr.sessionId !== sessionId) return null;
	return ptr;
}

/** 默认项目根：同目标现有项目 > NUWA_PROJECT > 非共享 cwd 的任务子目录 > 共享 cwd 的会话隔离目录。 */
export function defaultProjectRoot(cwd: string, target: string, sessionId: string, mode: Mode = "ctf"): string {
	const want = target ? normalizeTargetForMode(target, mode).url : "";
	const local = findLocalRoot(cwd, sessionId, want);
	if (local) return local;
	const env = process.env.NUWA_PROJECT;
	if (env && existsSync(statePath(resolve(env))) && sameTarget(resolve(env), want)) return resolve(env);
	if (!isSharedCwd(cwd)) {
		const base = resolve(cwd);
		if (existsSync(statePath(base)) && !sameTarget(base, want)) {
			const t = normalizeTargetForMode(target, mode);
			return join(base, ".nuwa-tasks", `${slug(t.host)}-${t.port}-${sha(sessionId || "default", 8)}`);
		}
		return base;
	}
	const t = normalizeTargetForMode(target, mode);
	return join(projectsDirPath(), `${slug(t.host)}-${t.port}-${sha(sessionId || "default", 10)}`);
}

export function writePointer(root: string, sessionId: string): void {
	const sid = (sessionId || "").trim();
	const rec = { root: resolve(root), sessionId: sid, ts: Date.now() };
	try {
		mkdirSync(pointerDirPath(), { recursive: true });
		atomicWrite(sessionPointerPath(sid), JSON.stringify(rec, null, 2));
		// 无会话的旧调用只写 legacy；有会话时绝不覆盖全局指针，避免最后写入者串台。
		if (!sid) {
			const legacyPtr = pointerFilePath();
			mkdirSync(dirname(legacyPtr), { recursive: true });
			atomicWrite(legacyPtr, JSON.stringify(rec, null, 2));
		}
	} catch {
		/* 指针写失败不影响会话内 cwd 查找 */
	}
}

/** 具名会话只接管自己 owner 的 state；共享 cwd 的无 owner 旧 state 一律跳过。 */
function rootForSession(dir: string, sessionId: string): "use" | "skip" | "reject" {
	if (!existsSync(statePath(dir))) return "skip";
	if (!sessionId) return "use";
	const owner = stateOwner(dir);
	if (owner) return owner === sessionId ? "use" : "reject";
	return isSharedCwd(dir) ? "skip" : "use";
}

/** cwd 向上找 .nuwa/state.json → NUWA_PROJECT → 当前会话指针；别的会话占着共享根时，落到本会话指针。 */
export function findRoot(cwd: string, sessionId = "", target = ""): string | null {
	const start = resolve(cwd || process.cwd());
	const want = target ? safeTargetUrl(target) : "";
	let d = start;
	for (;;) {
		if (d !== start && isSharedCwd(d)) break;
		const verdict = rootForSession(d, sessionId);
		if (verdict === "use") {
			if (sameTarget(d, want)) return d;
			break;
		}
		if (verdict === "reject") break;
		const up = dirname(d);
		if (up === d) break;
		d = up;
	}
	const env = process.env.NUWA_PROJECT;
	if (env && existsSync(statePath(resolve(env))) && sameTarget(resolve(env), want)) return resolve(env);
	if (sessionId) {
		const ptr = readSessionPointer(sessionId);
		if (!ptr?.root) return null;
		const root = resolve(ptr.root);
		if (!usableRoot(cwd, root)) return null;
		return sameTarget(root, want) ? root : null;
	}
	const legacy = readJson<{ root?: string; sessionId?: string }>(pointerFilePath());
	if (legacy?.root && existsSync(statePath(legacy.root))) {
		const root = resolve(legacy.root);
		if (usableRoot(cwd, root) && sameTarget(root, want)) return root;
	}
	return null;
}

/** 只向上找 cwd 树里的 .nuwa，不接管指针；共享根不向下继承，目标不同即拒绝。 */
export function findLocalRoot(cwd: string, sessionId = "", target = ""): string | null {
	const start = resolve(cwd || process.cwd());
	const want = target ? safeTargetUrl(target) : "";
	let d = start;
	for (;;) {
		if (d !== start && isSharedCwd(d)) break;
		const verdict = rootForSession(d, sessionId);
		if (verdict === "use") return sameTarget(d, want) ? d : null;
		if (verdict === "reject") return null;
		const up = dirname(d);
		if (up === d) break;
		d = up;
	}
	return null;
}

export function nextFactId(st: NuwaState): string {
	st.seq.fact += 1;
	return `f${String(st.seq.fact).padStart(3, "0")}`;
}

export function nextIntentId(st: NuwaState): string {
	st.seq.intent += 1;
	return `i${String(st.seq.intent).padStart(3, "0")}`;
}

export function createInitialState(
	target: string,
	goal: string,
	mode: Mode,
	_cfg: Cfg,
	ownerSessionId = "",
	scopeOverrides?: Partial<ScopePolicy>,
): NuwaState {
	const t = normalizeTargetForMode(target, mode);
	const id = `${slug(t.host)}-${t.port}`;
	const ts = nowIso();
	const scope = defaultScopeForTarget(t.url, mode, scopeOverrides);
	const defaultGoal =
		mode === "coding"
			? `完成 ${t.url} 的软件工程任务并通过验证`
			: mode === "ops"
				? `完成 ${t.url} 的运维排障与巡检并验证恢复`
				: `对 ${t.url} 做完整渗透评估并取得 flag`;
	const nowMs = Date.now();
	return {
		schema: SCHEMA,
		version: NUWA_VERSION,
		project: {
			id,
			target,
			url: t.url,
			host: t.host,
			port: t.port,
			scheme: t.scheme,
			goal: goal || defaultGoal,
			mode,
			status: "active",
			phase: "recon",
			episode: 1,
			createdAt: ts,
			updatedAt: ts,
			ownerSessionId: ownerSessionId || undefined,
			scope,
		},
		facts: {},
		intents: {},
		seq: { fact: 0, intent: 0 },
		runtime: {
			startedAt: nowMs,
			projectStartedAt: nowMs,
			turns: 0,
			totalTurns: 0,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 0,
			lastToolCalls: 0,
			tokens: 0,
			totalTokens: 0,
			totalCostUsd: 0,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
			suspectRounds: 0,
			lastSettleAt: 0,
			expansions: 0,
			lastExpandAt: 0,
			pressure: 0,
			lastFacts: -1,
			generation: 1,
			genTurns: 0,
			netRetries: 0,
			saveCount: 0,
		},
	};
}

/** 从旧 .sapper 图迁移：事实与意图全部转成原生状态，id 重新编号并保持引用关系。 */
export function migrateSapper(root: string): NuwaState {
	const projPath = join(root, ".sapper", "project.json");
	const proj = readJson<{ goal?: string; status?: string; created_at?: string }>(projPath);
	if (!proj) throw new Error(`没有可迁移的 .sapper 图: ${projPath}`);
	const factDir = join(root, ".sapper", "facts");
	const intentDir = join(root, ".sapper", "intents");
	const oldFacts: Array<Record<string, unknown>> = [];
	const oldIntents: Array<Record<string, unknown>> = [];
	for (const dir of [factDir, intentDir]) {
		if (!existsSync(dir)) continue;
		for (const name of readdirSync(dir) as string[]) {
			if (!name.endsWith(".json")) continue;
			const rec = readJson<Record<string, unknown>>(join(dir, name));
			if (!rec || typeof rec !== "object") continue;
			if (dir === factDir) oldFacts.push(rec);
			else oldIntents.push(rec);
		}
	}
	const blob = JSON.stringify(oldFacts);
	const target = blob.match(/https?:\/\/[^"\s\\]+/)?.[0] ?? "http://migrated.local:80";
	const st = createInitialState(target, proj.goal ?? "migrated project", "pentest", readCfg());
	st.project.status = proj.status === "completed" ? "completed" : "active";
	st.project.phase = "recon";
	const map = new Map<string, string>();
	const kinds = new Set(["target", "asset", "service", "endpoint", "cred", "vuln", "flag", "loot", "note", "blocked"]);
	for (const f of oldFacts) {
		if (!f?.id || f.id === "goal") continue;
		const id = nextFactId(st);
		map.set(String(f.id), id);
		const rawKind = String(f.kind ?? "note");
		const kind = (kinds.has(rawKind) ? rawKind : rawKind === "host" ? "asset" : "note") as FactKind;
		st.facts[id] = {
			id,
			kind,
			title: normOneLine(String(f.description ?? f.id), 120),
			detail: `[migrated:${f.id}] ${String(f.description ?? "")}`,
			intent: undefined,
			key: `migrated:${f.id}`,
			createdAt: String(f.created_at ?? nowIso()),
		};
	}
	const imap = new Map<string, string>();
	for (const it of oldIntents) {
		if (!it?.id) continue;
		const id = nextIntentId(st);
		imap.set(String(it.id), id);
		st.intents[id] = {
			id,
			phase: "recon",
			key: `migrated:${it.id}`,
			title: normOneLine(String(it.description ?? it.id), 120),
			detail: `[migrated:${it.id}] ${String(it.description ?? "")}`,
			from: [],
			status: it.status === "done" || it.status === "complete" ? "done" : it.status === "claimed" ? "claimed" : "open",
			priority: 50,
			attempts: 0,
			createdAt: String(it.created_at ?? nowIso()),
		};
	}
	for (const it of oldIntents) {
		const id = imap.get(String(it.id));
		if (!id) continue;
		const n = st.intents[id]!;
		n.from = (Array.isArray(it.from) ? it.from : []).map((x: unknown) => map.get(String(x))).filter(Boolean) as string[];
		if (it.to && map.has(String(it.to))) n.to = map.get(String(it.to));
		if (n.to) {
			const f = st.facts[n.to];
			if (f) f.intent = id;
		}
	}
	return st;
}
