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
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
	appendFileSync,
	closeSync,
	existsSync,
	fsyncSync,
	linkSync,
	mkdirSync,
	openSync,
	readFileSync,
	readdirSync,
	realpathSync,
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
import {
	NuwaSqliteStore,
	appendJournalSqlite,
	loadStateFromSqlite,
	migrateJsonToSqlite,
	resolveStorageBackend,
	saveStateToSqlite,
	sqliteDbPath,
	type StorageBackend,
} from "./sqlite-store";

export { resolveStorageBackend, sqliteDbPath, type StorageBackend };

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

/** 解析持久化共享状态根目录（迁出 /tmp）：优先 NUWA_STATE_DIR > XDG_STATE_HOME/nuwa > ~/.local/state/nuwa。 */
export function resolvePersistentStateDir(env: Record<string, string | undefined> = process.env): string {
	const explicit = env.NUWA_STATE_DIR?.trim();
	if (explicit) return resolve(explicit);
	const xdg = env.XDG_STATE_HOME?.trim();
	if (xdg) return join(resolve(xdg), "nuwa");
	return join(homedir(), ".local", "state", "nuwa");
}

/** 解析默认持久化工作区目录（绝不默认落入 /tmp）：优先 NUWA_WORKSPACES_DIR > NUWA_STATE_DIR/workspaces > <agentHome>/workspaces > ~/.local/state/nuwa/workspaces。 */
export function resolveDefaultWorkspacesDir(env: Record<string, string | undefined> = process.env): string {
	const explicitWs = env.NUWA_WORKSPACES_DIR?.trim();
	if (explicitWs) return resolve(explicitWs);
	const explicitState = env.NUWA_STATE_DIR?.trim();
	if (explicitState) return join(resolve(explicitState), "workspaces");
	const envAgentHome = env.PI_AGENT_HOME?.trim();
	if (envAgentHome) return join(resolve(envAgentHome), "workspaces");
	return join(resolvePersistentStateDir(env), "workspaces");
}

function projectsDirPath(): string {
	const explicitState = process.env.NUWA_STATE_DIR?.trim();
	if (explicitState) return join(resolve(explicitState), "workspaces");
	// 兼容显式指定 PI_AGENT_HOME（含既有单测与旧缓存目录布局）
	if (process.env.PI_AGENT_HOME?.trim()) {
		return join(getAgentHome(), "cache/nuwa-projects");
	}
	return join(resolvePersistentStateDir(), "workspaces");
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
		storageBackend: resolveStorageBackend(),
		enableAutoLoops: (process.env.NUWA_AUTO_LOOPS ?? "1").trim() !== "0",
		enableBeliefSearch: (process.env.NUWA_BELIEF_SEARCH ?? "1").trim() !== "0",
		enableCalibration: (process.env.NUWA_CALIBRATION ?? "1").trim() !== "0",
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
let lockFileSeq = 0;

/** 单写者锁：先写完整载荷再用硬链接原子落锁（零空文件窗口），支持同进程重入与死锁自动回收。 */
export function withLock<T>(root: string, fn: () => T, opts?: { timeoutMs?: number }): T {
	mkdirSync(stateDir(root), { recursive: true });
	const p = resolve(lockPath(root));
	if (heldLocks.has(p)) {
		return fn();
	}
	const deadline = Date.now() + (opts?.timeoutMs ?? 10_000);
	let backoff = 4;
	const myNonce = `${process.pid}-${Date.now()}-${randomBytes(6).toString("hex")}`;
	const lockPayload = JSON.stringify({
		pid: process.pid,
		ts: Date.now(),
		start: procStartTime(process.pid),
		nonce: myNonce,
	});

	for (;;) {
		const tmp = `${p}.tmp-${process.pid}-${lockFileSeq++}`;
		let acquired = false;
		let useFallback = false;
		let tfd = -1;
		try {
			tfd = openSync(tmp, "wx", 0o600);
			writeSync(tfd, lockPayload);
			fsyncSync(tfd);
			closeSync(tfd);
			tfd = -1;
			try {
				linkSync(tmp, p);
				acquired = true;
			} catch (linkErr) {
				const lcode = (linkErr as NodeJS.ErrnoException)?.code;
				if (lcode === "EEXIST") {
					acquired = false;
				} else if (lcode === "EXDEV" || lcode === "EPERM" || lcode === "ENOSYS" || lcode === "EOPNOTSUPP") {
					useFallback = true;
				} else {
					throw linkErr;
				}
			}
		} finally {
			if (tfd >= 0) {
				try {
					closeSync(tfd);
				} catch {
					/* ignore */
				}
			}
			try {
				unlinkSync(tmp);
			} catch {
				/* ignore */
			}
		}

		if (useFallback) {
			let fd = -1;
			try {
				fd = openSync(p, "wx", 0o600);
				writeSync(fd, lockPayload);
				fsyncSync(fd);
				closeSync(fd);
				fd = -1;
				acquired = true;
			} catch (err) {
				if (fd >= 0) {
					try {
						closeSync(fd);
					} catch {
						/* ignore */
					}
					try {
						unlinkSync(p);
					} catch {
						/* ignore */
					}
					throw err;
				}
				const code = (err as NodeJS.ErrnoException)?.code;
				if (code !== "EEXIST") throw err;
				acquired = false;
			}
		}

		if (!acquired) {
			const held = readJson<{ pid?: number; ts?: number; start?: string; nonce?: string }>(p);
			let emptyMtimeMs: number | null = null;
			if (held) {
				const heldPid = typeof held.pid === "number" ? held.pid : 0;
				const heldStart = typeof held.start === "string" ? held.start : null;
				const sameProcess = heldPid > 0 && pidAlive(heldPid) && (!heldStart || heldStart === procStartTime(heldPid));
				if (sameProcess) {
					if (Date.now() >= deadline) {
						throw new Error(`state locked by pid ${heldPid} (>${Date.now() - (held.ts ?? Date.now())}ms)`);
					}
					sleepSync(backoff);
					backoff = Math.min(backoff * 2, 120);
					continue;
				}
			} else {
				// 刚创建但尚未完成写入的极短窗口内暂缓抢占，避免误删并发写者锁文件
				let recentlyCreated = false;
				try {
					emptyMtimeMs = statSync(p).mtimeMs;
					recentlyCreated = Date.now() - emptyMtimeMs < 300;
				} catch {
					emptyMtimeMs = null;
					recentlyCreated = false;
				}
				if (recentlyCreated && Date.now() < deadline) {
					sleepSync(backoff);
					backoff = Math.min(backoff * 2, 32);
					continue;
				}
			}
			// 使用一次性回收锁 + 二次核验，防止多进程同时判定死锁后误删首个恢复者刚建的新活锁
			const reclaimPath = `${p}.reclaim`;
			const reclaimTmp = `${p}.reclaim.tmp-${process.pid}-${lockFileSeq++}`;
			const reclaimNonce = `${process.pid}-${Date.now()}-${randomBytes(4).toString("hex")}`;
			const reclaimPayload = JSON.stringify({
				pid: process.pid,
				ts: Date.now(),
				start: procStartTime(process.pid),
				nonce: reclaimNonce,
			});
			let reclaimAcquired = false;
			let rfd = -1;
			try {
				rfd = openSync(reclaimTmp, "wx", 0o600);
				writeSync(rfd, reclaimPayload);
				fsyncSync(rfd);
				closeSync(rfd);
				rfd = -1;
				try {
					linkSync(reclaimTmp, reclaimPath);
					reclaimAcquired = true;
				} catch (rErr) {
					const rc = (rErr as NodeJS.ErrnoException)?.code;
					if (rc === "EXDEV" || rc === "EPERM" || rc === "ENOSYS" || rc === "EOPNOTSUPP") {
						try {
							const rfdFb = openSync(reclaimPath, "wx", 0o600);
							writeSync(rfdFb, reclaimPayload);
							fsyncSync(rfdFb);
							closeSync(rfdFb);
							reclaimAcquired = true;
						} catch {
							reclaimAcquired = false;
						}
					}
				}
			} catch {
				reclaimAcquired = false;
			} finally {
				if (rfd >= 0) {
					try {
						closeSync(rfd);
					} catch {
						/* ignore */
					}
				}
				try {
					unlinkSync(reclaimTmp);
				} catch {
					/* ignore */
				}
			}

			if (reclaimAcquired) {
				try {
					const nowHeld = readJson<{ pid?: number; ts?: number; start?: string; nonce?: string }>(p);
					let stillSameDead = false;
					if (held && nowHeld) {
						const sameHolder = held.nonce
							? nowHeld.nonce === held.nonce
							: !nowHeld.nonce && nowHeld.pid === held.pid && nowHeld.start === held.start;
						const nowPid = typeof nowHeld.pid === "number" ? nowHeld.pid : 0;
						const nowStart = typeof nowHeld.start === "string" ? nowHeld.start : null;
						const nowAlive = nowPid > 0 && pidAlive(nowPid) && (!nowStart || nowStart === procStartTime(nowPid));
						stillSameDead = sameHolder && !nowAlive;
					} else if (!held && !nowHeld && emptyMtimeMs !== null) {
						try {
							stillSameDead = Math.abs(statSync(p).mtimeMs - emptyMtimeMs) < 1;
						} catch {
							stillSameDead = false;
						}
					}
					if (stillSameDead) {
						try {
							unlinkSync(p);
						} catch {
							/* 已被回收 */
						}
					}
				} finally {
					try {
						const curReclaim = readJson<{ nonce?: string }>(reclaimPath);
						if (curReclaim?.nonce === reclaimNonce) unlinkSync(reclaimPath);
					} catch {
						/* ignore */
					}
				}
			} else {
				// 检查是否存在崩溃残留的僵尸回收锁
				const oldReclaim = readJson<{ pid?: number; ts?: number; start?: string }>(reclaimPath);
				const oldDead = oldReclaim
					? !oldReclaim.pid ||
						!pidAlive(oldReclaim.pid) ||
						Boolean(oldReclaim.start && oldReclaim.start !== procStartTime(oldReclaim.pid))
					: (() => {
							try {
								return Date.now() - statSync(reclaimPath).mtimeMs >= 5000;
							} catch {
								return false;
							}
						})();
				if (oldDead) {
					try {
						unlinkSync(reclaimPath);
					} catch {
						/* ignore */
					}
				} else {
					sleepSync(Math.min(backoff, 16));
				}
			}
			if (Date.now() >= deadline) {
				const cur = readJson<{ pid?: number; ts?: number }>(p);
				throw new Error(`state locked by pid ${cur?.pid ?? 0} (>${Date.now() - (cur?.ts ?? Date.now())}ms)`);
			}
			continue;
		}

		heldLocks.add(p);
		try {
			return fn();
		} finally {
			heldLocks.delete(p);
			try {
				const cur = readJson<{ nonce?: string }>(p);
				if (cur?.nonce === myNonce) {
					unlinkSync(p);
				}
			} catch {
				/* 已被回收 */
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
	try {
		const backend = resolveStorageBackend(root);
		if (backend === "sqlite" || backend === "dual") {
			const dbFile = sqliteDbPath(root);
			const hasDb =
				existsSync(dbFile) &&
				(() => {
					try {
						return statSync(dbFile).size > 0;
					} catch {
						return false;
					}
				})();
			if (hasDb) {
				appendJournalSqlite(root, rec);
			}
		}
	} catch {
		/* SQLite journal 写入异常不阻塞主流程 */
	}
}

export function logEvent(root: string, rec: Record<string, unknown>): void {
	journalAppend(root, { type: "event", ...rec });
}

/** 读 journal 尾部；超过 2MB 只取末尾，避免长跑项目每次刷新全量解析；SQLite 模式下兼容回退。 */
export function readJournalTail(root: string, limit = 200): JournalEntry[] {
	const backend = resolveStorageBackend(root);
	if ((backend === "sqlite" || backend === "dual") && existsSync(sqliteDbPath(root))) {
		let store: NuwaSqliteStore | null = null;
		try {
			store = new NuwaSqliteStore(root, { readonly: true });
			const entries = store.readJournalTail(limit);
			if (entries.length > 0 || !existsSync(journalPath(root))) {
				return entries;
			}
		} catch {
			/* 回退读取 journal.jsonl */
		} finally {
			store?.close();
		}
	}
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
		...cur,
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
		...(cur.status ? { status: cur.status } : {}),
		...(cur.sealMeta && typeof cur.sealMeta === "object" ? { sealMeta: cur.sealMeta } : {}),
		...(Number.isFinite(cur.noveltyStall) ? { noveltyStall: cur.noveltyStall as number } : {}),
		...(Number.isFinite(cur.lastNovelFacts) ? { lastNovelFacts: cur.lastNovelFacts as number } : {}),
		...(typeof cur.semanticStall === "boolean" ? { semanticStall: cur.semanticStall } : {}),
		...(Number.isFinite(cur.blockedCommits) ? { blockedCommits: cur.blockedCommits as number } : {}),
		...(Number.isFinite(cur.lastBlockedCommitsDelta) ? { lastBlockedCommitsDelta: cur.lastBlockedCommitsDelta as number } : {}),
		...(Number.isFinite(cur.lastBlockedIntentsDelta) ? { lastBlockedIntentsDelta: cur.lastBlockedIntentsDelta as number } : {}),
		...(typeof cur.reportWritten === "boolean" ? { reportWritten: cur.reportWritten } : {}),
		...(cur.attemptedKeys && typeof cur.attemptedKeys === "object" ? { attemptedKeys: cur.attemptedKeys } : {}),
	};
	st.runtime = rt;
	if (!st.facts || typeof st.facts !== "object") st.facts = {};
	if (!st.intents || typeof st.intents !== "object") st.intents = {};
	if (!st.seq) st.seq = { fact: 0, intent: 0 };
	if (st.assets !== undefined && (typeof st.assets !== "object" || st.assets === null)) st.assets = {};
	if (st.hypotheses !== undefined && (typeof st.hypotheses !== "object" || st.hypotheses === null)) st.hypotheses = {};
	return st;
}

const loadedStateRoots = new WeakMap<NuwaState, string>();

export function bindLoadedStateRoot(st: NuwaState, root: string): NuwaState {
	if (st && typeof st === "object" && root) {
		loadedStateRoots.set(st, resolve(root));
	}
	return st;
}

export function getLoadedStateRoot(st: NuwaState | null | undefined): string | undefined {
	if (!st || typeof st !== "object") return undefined;
	return loadedStateRoots.get(st);
}

/** 纯 JSON 状态加载（供 sqlite-store 迁移与坏库回退无环调用，亦作为 json 模式的底层实现）。 */
export function loadStateJsonOnly(root: string): NuwaState | null {
	const direct = readJson<NuwaState>(statePath(root));
	if (direct && direct.schema === SCHEMA && direct.project) return bindLoadedStateRoot(normalizeState(direct), root);
	const recovered = recoverFromJournal(root);
	if (recovered) {
		const norm = normalizeState(recovered);
		try {
			atomicWrite(statePath(root), JSON.stringify(norm, null, 2));
		} catch {
			/* 恢复成功即可 */
		}
		return bindLoadedStateRoot(norm, root);
	}
	return null;
}

export function loadState(root: string): NuwaState | null {
	const backend = resolveStorageBackend(root);
	if (backend === "sqlite" || backend === "dual") {
		try {
			const fromSql = loadStateFromSqlite(root, { fallbackToJson: true });
			if (fromSql) return bindLoadedStateRoot(normalizeState(fromSql), root);
		} catch {
			/* 坏库或未建库时回退存量 JSON 兼容读取 */
		}
	}
	return loadStateJsonOnly(root);
}

const SNAPSHOT_KEY_REASONS = new Set(["init", "flag", "complete", "stop", "reincarnate"]);
const STATE_WARN_BYTES = 2 * 1024 * 1024;

export interface SaveStateOptions {
	forceSnapshot?: boolean;
	reason?: string;
}

/** 纯 JSON 原子写盘 + 增量快照。 */
export function saveStateJsonOnly(root: string, state: NuwaState, opts?: SaveStateOptions): void {
	bindLoadedStateRoot(state, root);
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

/** 原子写盘 + 增量快照；当启用 `NUWA_STORAGE_BACKEND=sqlite|dual` 时写入 SQLite WAL 权威库并同步保留兼容导出。 */
export function saveState(root: string, state: NuwaState, opts?: SaveStateOptions): void {
	const backend = resolveStorageBackend(root);
	state.runtime.storageBackend = backend;
	if (backend === "sqlite" || backend === "dual") {
		const dbFile = sqliteDbPath(root);
		const hadDb = existsSync(dbFile) && (() => {
			try {
				return statSync(dbFile).size > 0;
			} catch {
				return false;
			}
		})();
		if (!hadDb && existsSync(statePath(root))) {
			try {
				migrateJsonToSqlite(root);
			} catch {
				/* 首次建库迁移失败时直接由后续 saveStateToSqlite 写入最新状态 */
			}
		}
		saveStateJsonOnly(root, state, opts);
		saveStateToSqlite(root, state);
		return;
	}
	saveStateJsonOnly(root, state, opts);
}

/** 判断指定目录是否存在有效状态存储（.nuwa/state.json 或非空 .nuwa/nuwa.db）。 */
export function hasProjectState(dir: string): boolean {
	if (existsSync(statePath(dir))) return true;
	const dbFile = sqliteDbPath(dir);
	if (!existsSync(dbFile)) return false;
	try {
		return statSync(dbFile).size > 0;
	} catch {
		return false;
	}
}

/**
 * 在 `nuwa_init(force=true)` 重建前安全备份现有项目状态（兼容仅存 `nuwa.db` 无 `state.json` 的纯 SQLite 模式），
 * 并清理旧 SQLite WAL/SHM 伴生文件，防止 ENOENT 崩溃或旧库数据残留污染新项目。
 */
export function backupExistingProjectState(root: string): string[] {
	const ts = Date.now();
	const backedUp: string[] = [];
	const sp = statePath(root);
	if (existsSync(sp)) {
		const bakJson = `${sp}.bak-${ts}`;
		renameSync(sp, bakJson);
		backedUp.push(bakJson);
	}
	const dbFile = sqliteDbPath(root);
	if (existsSync(dbFile)) {
		const bakDb = `${dbFile}.bak-${ts}`;
		renameSync(dbFile, bakDb);
		backedUp.push(bakDb);
	}
	for (const suffix of ["-wal", "-shm"]) {
		const sidecar = `${dbFile}${suffix}`;
		if (existsSync(sidecar)) {
			try {
				unlinkSync(sidecar);
			} catch {
				/* ignore */
			}
		}
	}
	return backedUp;
}

/** 共享 cwd 不能直接放 .nuwa，否则同机多个任务会写同一份 state。 */
export function isSharedCwd(cwd: string): boolean {
	const r = resolve(cwd || process.cwd());
	const extra = (process.env.NUWA_SHARED_CWDS ?? "")
		.split(":")
		.map((s) => s.trim())
		.filter(Boolean)
		.map((s) => resolve(s));
	const sharedRoots = [
		resolve(tmpdir()),
		resolve("/tmp"),
		resolve("/private/tmp"),
		resolve(homedir()),
		resolve("/"),
		resolve("/data/workspace"),
		...extra,
	];
	return sharedRoots.includes(r);
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
	const backend = resolveStorageBackend(dir);
	if ((backend === "sqlite" || backend === "dual") && existsSync(sqliteDbPath(dir))) {
		try {
			const owner = loadStateFromSqlite(dir)?.project?.ownerSessionId;
			if (owner !== undefined) return owner;
		} catch {
			/* 回退 JSON 读取 */
		}
	}
	const raw = readJson<{ project?: { ownerSessionId?: string } }>(statePath(dir));
	if (raw?.project?.ownerSessionId !== undefined) return raw.project.ownerSessionId;
	if (existsSync(sqliteDbPath(dir))) {
		try {
			return loadStateFromSqlite(dir)?.project?.ownerSessionId;
		} catch {
			return undefined;
		}
	}
	return undefined;
}

function stateUrl(dir: string): string | undefined {
	const backend = resolveStorageBackend(dir);
	if ((backend === "sqlite" || backend === "dual") && existsSync(sqliteDbPath(dir))) {
		try {
			const url = loadStateFromSqlite(dir)?.project?.url;
			if (url !== undefined) return url;
		} catch {
			/* 回退 JSON 读取 */
		}
	}
	const raw = readJson<{ project?: { url?: string } }>(statePath(dir));
	if (raw?.project?.url !== undefined) return raw.project.url;
	if (existsSync(sqliteDbPath(dir))) {
		try {
			return loadStateFromSqlite(dir)?.project?.url;
		} catch {
			return undefined;
		}
	}
	return undefined;
}

function stateMode(dir: string): Mode | undefined {
	const backend = resolveStorageBackend(dir);
	if ((backend === "sqlite" || backend === "dual") && existsSync(sqliteDbPath(dir))) {
		try {
			const mode = loadStateFromSqlite(dir)?.project?.mode;
			if (mode) return mode;
		} catch {
			/* 回退 JSON 读取 */
		}
	}
	const raw = readJson<{ project?: { mode?: Mode } }>(statePath(dir));
	if (raw?.project?.mode) return raw.project.mode;
	if (existsSync(sqliteDbPath(dir))) {
		try {
			return loadStateFromSqlite(dir)?.project?.mode;
		} catch {
			return undefined;
		}
	}
	return undefined;
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

/** target 为空表示“不按目标过滤”；有 target 时只认同一个规范化 URL（兼容 coding/ops/audit 本地模式）。 */
function sameTarget(dir: string, targetOrUrl: string): boolean {
	const raw = (targetOrUrl ?? "").trim();
	if (!raw) return true;
	const url = stateUrl(dir);
	if (!url) return true;
	const mode = stateMode(dir) ?? "ctf";
	return url === safeTargetUrl(raw, mode);
}

export function readSessionPointer(sessionId: string): { root?: string; sessionId?: string } | null {
	const ptr = readJson<{ root?: string; sessionId?: string }>(sessionPointerPath(sessionId));
	if (!ptr?.root || !hasProjectState(ptr.root)) return null;
	if (ptr.sessionId && ptr.sessionId !== sessionId) return null;
	return ptr;
}

/** 默认项目根：同目标现有项目 > NUWA_PROJECT > 非共享 cwd 的任务子目录 > 共享 cwd 的会话隔离目录。 */
export function defaultProjectRoot(cwd: string, target: string, sessionId: string, mode: Mode = "ctf"): string {
	const want = target ? normalizeTargetForMode(target, mode).url : "";
	const local = findLocalRoot(cwd, sessionId, want);
	if (local) return local;
	const env = process.env.NUWA_PROJECT;
	if (env && hasProjectState(resolve(env)) && sameTarget(resolve(env), want)) return resolve(env);
	if (!isSharedCwd(cwd)) {
		const base = resolve(cwd);
		if (hasProjectState(base) && !sameTarget(base, want)) {
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
	if (!hasProjectState(dir)) return "skip";
	if (!sessionId) return "use";
	const owner = stateOwner(dir);
	if (owner) return owner === sessionId ? "use" : "reject";
	return isSharedCwd(dir) ? "skip" : "use";
}

/** cwd 向上找 .nuwa/state.json → NUWA_PROJECT → 当前会话指针；别的会话占着共享根时，落到本会话指针。 */
export function findRoot(cwd: string, sessionId = "", target = ""): string | null {
	const start = resolve(cwd || process.cwd());
	const want = (target ?? "").trim();
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
	if (env && hasProjectState(resolve(env)) && sameTarget(resolve(env), want)) return resolve(env);
	if (sessionId) {
		const ptr = readSessionPointer(sessionId);
		if (!ptr?.root) return null;
		const root = resolve(ptr.root);
		if (!usableRoot(cwd, root)) return null;
		return sameTarget(root, want) ? root : null;
	}
	const legacy = readJson<{ root?: string; sessionId?: string }>(pointerFilePath());
	if (legacy?.root && hasProjectState(legacy.root)) {
		const root = resolve(legacy.root);
		if (usableRoot(cwd, root) && sameTarget(root, want)) return root;
	}
	return null;
}

/** 只向上找 cwd 树里的 .nuwa，不接管指针；共享根不向下继承，目标不同即拒绝。 */
export function findLocalRoot(cwd: string, sessionId = "", target = ""): string | null {
	const start = resolve(cwd || process.cwd());
	const want = (target ?? "").trim();
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

// ============================================================================
// v5.1 运行时守卫扩展：
//   - Issue #40 (NW-20): ProcessGroupTracker & cleanupTrackedProcesses
//   - Issue #44 (NW-24): 软暂停状态 setPausedState / isPausedState
//   - Issue #46 (NW-26): 子代理心跳与超时看门狗 SubagentWatchdog
//   - Issue #47 (NW-27): /tmp 临时目录告警与工作区完整性校验 verifyWorkspaceIntegrity
// ============================================================================

export interface TrackedProcessRecord {
	pid: number;
	pgid: number;
	label: string;
	taskId?: string;
	command?: string;
	startedAt: string;
	startedAtMs: number;
	procStart?: string | null;
	ownerPid: number;
}

export interface TrackProcessInput {
	pid: number;
	pgid?: number;
	label: string;
	taskId?: string;
	command?: string;
}

export interface CleanupProcessOptions {
	taskId?: string;
	labels?: string[];
	graceMs?: number;
	pollMs?: number;
	reason?: string;
	dryRun?: boolean;
}

export interface CleanedProcessOutcome {
	pid: number;
	pgid: number;
	label: string;
	taskId?: string;
	signal: "SIGTERM" | "SIGKILL" | "already_exited" | "skipped_unsafe" | "dry_run";
	groupKilled: boolean;
	reason?: string;
}

export interface CleanupProcessResult {
	ok: boolean;
	cleaned: CleanedProcessOutcome[];
	remaining: TrackedProcessRecord[];
	skippedUnsafe: number;
}

interface ProcessTrackerStore {
	schema: number;
	updatedAt: string;
	records: TrackedProcessRecord[];
}

export function processTrackerPath(root: string): string {
	return join(stateDir(root), "process-groups.json");
}

let cachedSelfPgid: number | null | undefined;

/** 探测指定 PID 所属的 POSIX 进程组 PGID；跨 macOS/Linux 兼容。 */
export function probeProcessGroupId(pid: number): number | null {
	if (!Number.isInteger(pid) || pid <= 0) return null;
	// 优先在 Linux 直接读 /proc/<pid>/stat（第 5 字段 pgrp），零子进程开销
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		const close = stat.lastIndexOf(")");
		if (close >= 0) {
			const fields = stat.slice(close + 2).trim().split(/\s+/);
			// close 后依次为 state(0), ppid(1), pgrp(2)
			const pgid = Number(fields[2]);
			if (Number.isInteger(pgid) && pgid > 0) return pgid;
		}
	} catch {
		/* 非 Linux 或 /proc 不可读，回退 ps */
	}
	try {
		const res = spawnSync("ps", ["-o", "pgid=", "-p", String(pid)], {
			encoding: "utf8",
			timeout: 1500,
			stdio: ["ignore", "pipe", "ignore"],
		});
		if (res.status === 0) {
			const pgid = Number(String(res.stdout ?? "").trim());
			if (Number.isInteger(pgid) && pgid > 0) return pgid;
		}
	} catch {
		/* ps 不可用 */
	}
	return null;
}

function getCurrentProcessPgid(): number | null {
	if (cachedSelfPgid !== undefined) return cachedSelfPgid;
	cachedSelfPgid = probeProcessGroupId(process.pid);
	return cachedSelfPgid;
}

/** 检测单进程是否存活且非僵尸态（Z/X），避免同步宽限期内未 reap 的子进程误触发 SIGKILL。 */
export function isProcessAliveNonZombie(pid: number): boolean {
	if (!pidAlive(pid)) return false;
	// Linux: 读取 /proc/<pid>/stat state 字段
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		const close = stat.lastIndexOf(")");
		if (close >= 0) {
			const state = stat.slice(close + 2).trim()[0] ?? "";
			if (state === "Z" || state === "X") return false;
			return true;
		}
	} catch {
		/* 非 Linux，回退 ps */
	}
	try {
		const res = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], {
			encoding: "utf8",
			timeout: 1500,
			stdio: ["ignore", "pipe", "ignore"],
		});
		if (res.status !== 0) return false;
		const st = String(res.stdout ?? "").trim();
		if (!st) return false;
		return !st.startsWith("Z") && !st.startsWith("X");
	} catch {
		return pidAlive(pid);
	}
}

/** 检测进程组中是否仍有存活（非僵尸）成员。 */
function isProcessGroupAliveNonZombie(pgid: number, fallbackPid?: number): boolean {
	if (!Number.isInteger(pgid) || pgid <= 1) {
		return fallbackPid ? isProcessAliveNonZombie(fallbackPid) : false;
	}
	let groupExists = false;
	try {
		process.kill(-pgid, 0);
		groupExists = true;
	} catch (err) {
		const code = (err as NodeJS.ErrnoException)?.code;
		if (code === "EPERM") {
			groupExists = true;
		} else {
			groupExists = false;
		}
	}
	if (!groupExists) {
		return fallbackPid ? isProcessAliveNonZombie(fallbackPid) : false;
	}
	// 通过标准 POSIX ps 检查该进程组是否还有非僵尸成员
	try {
		const res = spawnSync("ps", ["-axo", "pid=,pgid=,stat="], {
			encoding: "utf8",
			timeout: 1500,
			stdio: ["ignore", "pipe", "ignore"],
		});
		if (res.status === 0 && typeof res.stdout === "string" && res.stdout.trim()) {
			const lines = res.stdout.split("\n");
			for (const line of lines) {
				const parts = line.trim().split(/\s+/);
				if (parts.length < 3) continue;
				const rowPgid = Number(parts[1]);
				const rowStat = parts[2] ?? "";
				if (rowPgid === pgid && rowStat && !rowStat.startsWith("Z") && !rowStat.startsWith("X")) {
					return true;
				}
			}
			return false;
		}
	} catch {
		/* ps 失败时回退到 fallbackPid 判定 */
	}
	return fallbackPid ? isProcessAliveNonZombie(fallbackPid) : true;
}

function isSafeTargetPid(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 1) return false;
	if (pid === process.pid || pid === process.ppid) return false;
	return true;
}

function isSafeTargetPgid(pgid: number): boolean {
	if (!Number.isInteger(pgid) || pgid <= 1) return false;
	if (pgid === process.pid || pgid === process.ppid) return false;
	const selfPgid = getCurrentProcessPgid();
	if (selfPgid !== null && pgid === selfPgid) return false;
	return true;
}

function isSameProcessInstance(rec: TrackedProcessRecord): boolean {
	if (!rec.procStart) return true;
	const curStart = procStartTime(rec.pid);
	if (!curStart) return true;
	return curStart === rec.procStart;
}

function sendSignalSafe(
	rec: TrackedProcessRecord,
	signal: "SIGTERM" | "SIGKILL",
): { sent: boolean; groupKilled: boolean; unsafeReason?: string } {
	if (!isSafeTargetPid(rec.pid)) {
		return { sent: false, groupKilled: false, unsafeReason: `拒绝向受保护或非法 PID(${rec.pid}) 发送信号` };
	}
	if (!isSameProcessInstance(rec)) {
		return { sent: false, groupKilled: false, unsafeReason: `PID(${rec.pid}) 启动时间已变化，疑似 PID 复用，跳过清理` };
	}
	const canKillGroup = isSafeTargetPgid(rec.pgid);
	if (canKillGroup) {
		try {
			process.kill(-rec.pgid, signal);
			return { sent: true, groupKilled: true };
		} catch (err) {
			const code = (err as NodeJS.ErrnoException)?.code;
			if (code === "ESRCH") {
				// 进程组已退出，尝试确认单 PID（以防成员脱离原组）
				try {
					process.kill(rec.pid, signal);
					return { sent: true, groupKilled: false };
				} catch {
					return { sent: false, groupKilled: true };
				}
			}
			// EPERM 等回退单进程
		}
	}
	try {
		process.kill(rec.pid, signal);
		return { sent: true, groupKilled: false };
	} catch {
		return { sent: false, groupKilled: false };
	}
}

/**
 * 进程组登记簿（Issue #40 / NW-20）：
 * 持久化记录派生子进程 PID/PGID 及标签（如 chromeproxy/chromium/subagent），
 * 在任务取消、nuwa_stop 与退出信号时按 -pgid 执行 SIGTERM -> 宽限期 -> SIGKILL 级联回收。
 * 安全红线：严禁向 <= 1、当前进程 PID/PPID 或当前进程 PGID 发送任何信号。
 */
export class ProcessGroupTracker {
	readonly root: string;

	constructor(root: string) {
		this.root = resolve(root);
	}

	filePath(): string {
		return processTrackerPath(this.root);
	}

	private readStore(): ProcessTrackerStore {
		const raw = readJson<ProcessTrackerStore>(this.filePath());
		if (raw && Array.isArray(raw.records)) {
			return raw;
		}
		return { schema: 1, updatedAt: nowIso(), records: [] };
	}

	private writeStore(records: TrackedProcessRecord[]): void {
		const payload: ProcessTrackerStore = {
			schema: 1,
			updatedAt: nowIso(),
			records,
		};
		atomicWrite(this.filePath(), JSON.stringify(payload, null, 2));
	}

	register(input: TrackProcessInput): TrackedProcessRecord {
		const pid = Number(input.pid);
		if (!Number.isInteger(pid) || pid <= 1) {
			throw new Error(`非法子进程 PID: ${String(input.pid)}（必须为大于 1 的正整数）`);
		}
		if (pid === process.pid || pid === process.ppid) {
			throw new Error(`禁止将当前宿主进程或父进程 (${pid}) 登记为可清理子进程`);
		}
		const probedPgid = probeProcessGroupId(pid);
		const explicitPgid = Number.isInteger(input.pgid) && (input.pgid as number) > 1 ? (input.pgid as number) : null;
		const pgid = explicitPgid ?? probedPgid ?? pid;
		const nowMs = Date.now();
		const rec: TrackedProcessRecord = {
			pid,
			pgid,
			label: normOneLine(input.label || "child", 64) || "child",
			...(input.taskId ? { taskId: normOneLine(input.taskId, 96) } : {}),
			...(input.command ? { command: normOneLine(input.command, 200) } : {}),
			startedAt: new Date(nowMs).toISOString(),
			startedAtMs: nowMs,
			procStart: procStartTime(pid),
			ownerPid: process.pid,
		};
		withLock(this.root, () => {
			const store = this.readStore();
			const filtered = store.records.filter((r) => r.pid !== pid);
			filtered.push(rec);
			this.writeStore(filtered);
		});
		logEvent(this.root, {
			type: "process_tracked",
			pid: rec.pid,
			pgid: rec.pgid,
			label: rec.label,
			...(rec.taskId ? { taskId: rec.taskId } : {}),
		});
		return rec;
	}

	unregister(pid: number): boolean {
		if (!existsSync(this.filePath())) return false;
		let removed = false;
		withLock(this.root, () => {
			const store = this.readStore();
			const next = store.records.filter((r) => r.pid !== pid);
			removed = next.length !== store.records.length;
			if (removed) {
				this.writeStore(next);
			}
		});
		return removed;
	}

	list(opts?: { aliveOnly?: boolean; taskId?: string; labels?: string[] }): TrackedProcessRecord[] {
		const store = this.readStore();
		const labelSet = opts?.labels && opts.labels.length > 0 ? new Set(opts.labels.map((s) => s.toLowerCase())) : null;
		return store.records.filter((r) => {
			if (opts?.taskId && r.taskId !== opts.taskId) return false;
			if (labelSet && !labelSet.has(r.label.toLowerCase())) return false;
			if (opts?.aliveOnly) {
				const alive = isSafeTargetPgid(r.pgid)
					? isProcessGroupAliveNonZombie(r.pgid, r.pid)
					: isProcessAliveNonZombie(r.pid);
				if (!alive) return false;
			}
			return true;
		});
	}

	pruneDead(): number {
		if (!existsSync(this.filePath())) return 0;
		let pruned = 0;
		withLock(this.root, () => {
			const store = this.readStore();
			const alive: TrackedProcessRecord[] = [];
			for (const r of store.records) {
				const stillAlive = isSafeTargetPgid(r.pgid)
					? isProcessGroupAliveNonZombie(r.pgid, r.pid)
					: isProcessAliveNonZombie(r.pid);
				if (stillAlive) alive.push(r);
				else pruned += 1;
			}
			if (pruned > 0) this.writeStore(alive);
		});
		return pruned;
	}

	cleanup(opts: CleanupProcessOptions = {}): CleanupProcessResult {
		if (!existsSync(this.filePath())) {
			return { ok: true, cleaned: [], remaining: [], skippedUnsafe: 0 };
		}
		const graceMs =
			typeof opts.graceMs === "number" && Number.isFinite(opts.graceMs) && opts.graceMs >= 0
				? Math.min(30_000, Math.floor(opts.graceMs))
				: 1500;
		const pollMs =
			typeof opts.pollMs === "number" && Number.isFinite(opts.pollMs) && opts.pollMs >= 5
				? Math.min(500, Math.floor(opts.pollMs))
				: 30;
		const labelSet = opts.labels && opts.labels.length > 0 ? new Set(opts.labels.map((s) => s.toLowerCase())) : null;

		const store = this.readStore();
		const targets: TrackedProcessRecord[] = [];
		const untouched: TrackedProcessRecord[] = [];

		for (const rec of store.records) {
			const matchTask = !opts.taskId || rec.taskId === opts.taskId;
			const matchLabel = !labelSet || labelSet.has(rec.label.toLowerCase());
			if (matchTask && matchLabel) {
				targets.push(rec);
			} else {
				untouched.push(rec);
			}
		}

		const outcomes: CleanedProcessOutcome[] = [];
		let skippedUnsafe = 0;

		if (opts.dryRun) {
			for (const rec of targets) {
				if (!isSafeTargetPid(rec.pid) || !isSameProcessInstance(rec)) {
					skippedUnsafe += 1;
					outcomes.push({
						pid: rec.pid,
						pgid: rec.pgid,
						label: rec.label,
						taskId: rec.taskId,
						signal: "skipped_unsafe",
						groupKilled: false,
						reason: "受保护进程或 PID 复用",
					});
					continue;
				}
				outcomes.push({
					pid: rec.pid,
					pgid: rec.pgid,
					label: rec.label,
					taskId: rec.taskId,
					signal: "dry_run",
					groupKilled: isSafeTargetPgid(rec.pgid),
				});
			}
			return { ok: true, cleaned: outcomes, remaining: store.records, skippedUnsafe };
		}

		const pendingTerm: Array<{ rec: TrackedProcessRecord; groupKilled: boolean }> = [];

		for (const rec of targets) {
			if (!isSafeTargetPid(rec.pid)) {
				skippedUnsafe += 1;
				outcomes.push({
					pid: rec.pid,
					pgid: rec.pgid,
					label: rec.label,
					taskId: rec.taskId,
					signal: "skipped_unsafe",
					groupKilled: false,
					reason: `禁止向非法或宿主 PID(${rec.pid}) 发送信号`,
				});
				continue;
			}
			if (!isSameProcessInstance(rec)) {
				skippedUnsafe += 1;
				outcomes.push({
					pid: rec.pid,
					pgid: rec.pgid,
					label: rec.label,
					taskId: rec.taskId,
					signal: "skipped_unsafe",
					groupKilled: false,
					reason: `PID(${rec.pid}) 启动时间已变，跳过防误杀`,
				});
				continue;
			}
			const alive = isSafeTargetPgid(rec.pgid)
				? isProcessGroupAliveNonZombie(rec.pgid, rec.pid)
				: isProcessAliveNonZombie(rec.pid);
			if (!alive) {
				outcomes.push({
					pid: rec.pid,
					pgid: rec.pgid,
					label: rec.label,
					taskId: rec.taskId,
					signal: "already_exited",
					groupKilled: false,
				});
				continue;
			}
			const termRes = sendSignalSafe(rec, "SIGTERM");
			if (!termRes.sent) {
				if (termRes.unsafeReason) {
					skippedUnsafe += 1;
					outcomes.push({
						pid: rec.pid,
						pgid: rec.pgid,
						label: rec.label,
						taskId: rec.taskId,
						signal: "skipped_unsafe",
						groupKilled: false,
						reason: termRes.unsafeReason,
					});
				} else {
					outcomes.push({
						pid: rec.pid,
						pgid: rec.pgid,
						label: rec.label,
						taskId: rec.taskId,
						signal: "already_exited",
						groupKilled: termRes.groupKilled,
					});
				}
				continue;
			}
			pendingTerm.push({ rec, groupKilled: termRes.groupKilled });
		}

		// 宽限期轮询：已退出的进程立即结算为 SIGTERM，超时仍存活者升级 SIGKILL
		const stillPending = new Set(pendingTerm);
		const deadline = Date.now() + graceMs;
		while (stillPending.size > 0) {
			for (const item of [...stillPending]) {
				const alive = item.groupKilled
					? isProcessGroupAliveNonZombie(item.rec.pgid, item.rec.pid)
					: isProcessAliveNonZombie(item.rec.pid);
				if (!alive) {
					outcomes.push({
						pid: item.rec.pid,
						pgid: item.rec.pgid,
						label: item.rec.label,
						taskId: item.rec.taskId,
						signal: "SIGTERM",
						groupKilled: item.groupKilled,
					});
					stillPending.delete(item);
				}
			}
			if (stillPending.size === 0 || Date.now() >= deadline) break;
			const waitMs = Math.min(pollMs, Math.max(1, deadline - Date.now()));
			sleepSync(waitMs);
		}

		// 宽限期满仍存活的进程组升级 SIGKILL 强杀
		for (const item of stillPending) {
			const killRes = sendSignalSafe(item.rec, "SIGKILL");
			outcomes.push({
				pid: item.rec.pid,
				pgid: item.rec.pgid,
				label: item.rec.label,
				taskId: item.rec.taskId,
				signal: "SIGKILL",
				groupKilled: killRes.groupKilled || item.groupKilled,
			});
		}

		// 写回剩余未匹配的活跃进程
		if (existsSync(stateDir(this.root))) {
			try {
				withLock(this.root, () => {
					const latest = this.readStore();
					const handledPids = new Set(targets.map((t) => t.pid));
					const nextRecords = latest.records.filter((r) => !handledPids.has(r.pid));
					this.writeStore(nextRecords);
				});
			} catch {
				/* 清理阶段写回失败不掩盖结果 */
			}
			if (outcomes.length > 0) {
				logEvent(this.root, {
					type: "process_group_cleanup",
					reason: opts.reason ?? "cleanup",
					...(opts.taskId ? { taskId: opts.taskId } : {}),
					cleanedCount: outcomes.length,
					skippedUnsafe,
					sigkillCount: outcomes.filter((o) => o.signal === "SIGKILL").length,
				});
			}
		}

		const remaining = existsSync(this.filePath()) ? this.readStore().records : untouched;
		return {
			ok: true,
			cleaned: outcomes,
			remaining,
			skippedUnsafe,
		};
	}
}

/** 便捷入口：按 -pgid 执行 SIGTERM -> 宽限期 -> SIGKILL 级联回收指定项目的登记子进程。 */
export function cleanupTrackedProcesses(root: string, opts: CleanupProcessOptions = {}): CleanupProcessResult {
	return new ProcessGroupTracker(root).cleanup(opts);
}

/** 为 SIGINT / SIGTERM / SIGHUP 安装进程组回收钩子，返回卸载函数。 */
export function installProcessCleanupHooks(
	root: string,
	opts?: {
		graceMs?: number;
		signals?: NodeJS.Signals[];
		onCleaned?: (sig: NodeJS.Signals, res: CleanupProcessResult) => void;
	},
): () => void {
	const signals: NodeJS.Signals[] = opts?.signals ?? ["SIGINT", "SIGTERM", "SIGHUP"];
	const handlers = new Map<NodeJS.Signals, () => void>();
	for (const sig of signals) {
		const fn = () => {
			const res = cleanupTrackedProcesses(root, {
				graceMs: opts?.graceMs ?? 500,
				reason: `signal:${sig}`,
			});
			opts?.onCleaned?.(sig, res);
		};
		handlers.set(sig, fn);
		process.on(sig, fn);
	}
	return () => {
		for (const [sig, fn] of handlers) {
			process.off(sig, fn);
		}
		handlers.clear();
	};
}

// ----------------------------------------------------------------------------
// Issue #44 (NW-24): 软暂停状态读写 setPausedState / isPausedState
// ----------------------------------------------------------------------------

export interface PausedState {
	paused: boolean;
	reason: string;
	updatedAt: string;
	pausedAt?: string;
	resumedAt?: string;
	pid?: number;
}

export function pausedStatePath(root: string): string {
	return join(stateDir(root), "paused.json");
}

export function readPausedState(root: string): PausedState | null {
	const rec = readJson<PausedState>(pausedStatePath(root));
	if (!rec || typeof rec.paused !== "boolean") return null;
	return rec;
}

/** 写入软暂停或恢复标记（供 nuwa_stop 软暂停与 bin/nuwa-autonomous 优雅挂起/即时恢复共享）。 */
export function setPausedState(root: string, paused: boolean, reason = ""): PausedState {
	const cleanReason = normOneLine(reason || (paused ? "manual pause" : "manual resume"), 240);
	const ts = nowIso();
	const state = withLock(root, () => {
		const prev = readPausedState(root);
		const next: PausedState = {
			paused: Boolean(paused),
			reason: cleanReason,
			updatedAt: ts,
			...(paused
				? { pausedAt: ts, ...(prev?.resumedAt ? { resumedAt: prev.resumedAt } : {}) }
				: { ...(prev?.pausedAt ? { pausedAt: prev.pausedAt } : {}), resumedAt: ts }),
			pid: process.pid,
		};
		atomicWrite(pausedStatePath(root), JSON.stringify(next, null, 2));
		return next;
	});
	logEvent(root, {
		type: paused ? "pause_enabled" : "pause_resumed",
		paused: state.paused,
		reason: state.reason,
	});
	return state;
}

/** 纯只读检查项目当前是否处于软暂停挂起状态。 */
export function isPausedState(root: string): boolean {
	try {
		const rec = readPausedState(root);
		return rec?.paused === true;
	} catch {
		return false;
	}
}

// ----------------------------------------------------------------------------
// Issue #46 (NW-26): 子代理心跳与超时看门狗 SubagentWatchdog
// ----------------------------------------------------------------------------

export const DEFAULT_SUBAGENT_IDLE_TIMEOUT_MS = 300_000; // 300s 无输出空闲阈值
export const DEFAULT_SUBAGENT_HARD_TIMEOUT_MS = 900_000; // 900s 单任务硬超时
export const DEFAULT_SUBAGENT_MAX_CONCURRENCY = 4;

export type SubagentTaskStatus = "running" | "completed" | "failed" | "timeout" | "cancelled";

export interface SubagentWatchdogEntry {
	taskId: string;
	agent: string;
	intentId?: string;
	pid?: number;
	pgid?: number;
	status: SubagentTaskStatus;
	startedAt: number;
	lastReqAt: number;
	lastOutputAt: number;
	endedAt?: number;
	idleTimeoutMs: number;
	hardTimeoutMs: number;
	timeoutKind?: "idle_no_output" | "hard_timeout";
	timeoutReason?: string;
}

export interface SubagentWatchdogConfig {
	idleTimeoutMs?: number;
	hardTimeoutMs?: number;
	maxConcurrency?: number;
	cleanupGraceMs?: number;
}

export interface StartSubagentTaskInput {
	taskId: string;
	agent?: string;
	intentId?: string;
	pid?: number;
	pgid?: number;
	label?: string;
	command?: string;
	nowMs?: number;
	idleTimeoutMs?: number;
	hardTimeoutMs?: number;
}

export interface WatchdogTimeoutEvent {
	taskId: string;
	agent: string;
	intentId?: string;
	timeoutKind: "idle_no_output" | "hard_timeout";
	reason: string;
	idleMs: number;
	elapsedMs: number;
	cleanup: CleanupProcessResult;
}

export interface WatchdogSweepResult {
	checkedAt: number;
	timedOut: WatchdogTimeoutEvent[];
	runningCount: number;
	availableSlots: number;
}

interface WatchdogStore {
	schema: number;
	updatedAt: string;
	tasks: Record<string, SubagentWatchdogEntry>;
}

export function subagentWatchdogPath(root: string): string {
	return join(stateDir(root), "subagent-watchdog.json");
}

function readWatchdogMsFromEnv(msKey: string, secKey: string, fallbackMs: number): number {
	const msRaw = process.env[msKey]?.trim();
	if (msRaw) {
		const n = Number(msRaw);
		if (Number.isFinite(n) && n > 0) return Math.floor(n);
	}
	const secRaw = process.env[secKey]?.trim();
	if (secRaw) {
		const n = Number(secRaw);
		if (Number.isFinite(n) && n > 0) return Math.floor(n * 1000);
	}
	return fallbackMs;
}

/**
 * 子代理心跳与超时看门狗（Issue #46 / NW-26）：
 * 持久化追踪运行中子代理任务的 startedAt / lastReqAt / lastOutputAt；
 * 超过无输出空闲阈值（默认 300s）或单任务硬超时（默认 900s）时主动触发终止（联动 ProcessGroupTracker），
 * 将任务标为 timeout 并释放并发槽位。
 */
export class SubagentWatchdog {
	readonly root: string;
	readonly idleTimeoutMs: number;
	readonly hardTimeoutMs: number;
	readonly maxConcurrency: number;
	readonly cleanupGraceMs: number;
	readonly tracker: ProcessGroupTracker;

	constructor(root: string, config: SubagentWatchdogConfig = {}) {
		this.root = resolve(root);
		this.idleTimeoutMs =
			typeof config.idleTimeoutMs === "number" && Number.isFinite(config.idleTimeoutMs) && config.idleTimeoutMs > 0
				? Math.floor(config.idleTimeoutMs)
				: readWatchdogMsFromEnv("NUWA_SUBAGENT_IDLE_TIMEOUT_MS", "NUWA_SUBAGENT_IDLE_TIMEOUT_S", DEFAULT_SUBAGENT_IDLE_TIMEOUT_MS);
		this.hardTimeoutMs =
			typeof config.hardTimeoutMs === "number" && Number.isFinite(config.hardTimeoutMs) && config.hardTimeoutMs > 0
				? Math.floor(config.hardTimeoutMs)
				: readWatchdogMsFromEnv("NUWA_SUBAGENT_HARD_TIMEOUT_MS", "NUWA_SUBAGENT_HARD_TIMEOUT_S", DEFAULT_SUBAGENT_HARD_TIMEOUT_MS);
		const envConc = Number(process.env.NUWA_SUBAGENT_MAX_CONCURRENCY ?? DEFAULT_SUBAGENT_MAX_CONCURRENCY);
		this.maxConcurrency =
			typeof config.maxConcurrency === "number" && Number.isFinite(config.maxConcurrency) && config.maxConcurrency >= 1
				? Math.floor(config.maxConcurrency)
				: Number.isFinite(envConc) && envConc >= 1
					? Math.floor(envConc)
					: DEFAULT_SUBAGENT_MAX_CONCURRENCY;
		this.cleanupGraceMs =
			typeof config.cleanupGraceMs === "number" && Number.isFinite(config.cleanupGraceMs) && config.cleanupGraceMs >= 0
				? Math.floor(config.cleanupGraceMs)
				: 1500;
		this.tracker = new ProcessGroupTracker(this.root);
	}

	filePath(): string {
		return subagentWatchdogPath(this.root);
	}

	private readStore(): WatchdogStore {
		const raw = readJson<WatchdogStore>(this.filePath());
		if (raw && raw.tasks && typeof raw.tasks === "object") {
			return raw;
		}
		return { schema: 1, updatedAt: nowIso(), tasks: {} };
	}

	private writeStore(tasks: Record<string, SubagentWatchdogEntry>): void {
		const payload: WatchdogStore = {
			schema: 1,
			updatedAt: nowIso(),
			tasks,
		};
		atomicWrite(this.filePath(), JSON.stringify(payload, null, 2));
	}

	startTask(input: StartSubagentTaskInput): SubagentWatchdogEntry {
		const taskId = normOneLine(input.taskId, 96);
		if (!taskId) throw new Error("taskId 不能为空");
		const nowMs = typeof input.nowMs === "number" && Number.isFinite(input.nowMs) ? Math.floor(input.nowMs) : Date.now();
		const idleTimeoutMs =
			typeof input.idleTimeoutMs === "number" && Number.isFinite(input.idleTimeoutMs) && input.idleTimeoutMs > 0
				? Math.floor(input.idleTimeoutMs)
				: this.idleTimeoutMs;
		const hardTimeoutMs =
			typeof input.hardTimeoutMs === "number" && Number.isFinite(input.hardTimeoutMs) && input.hardTimeoutMs > 0
				? Math.floor(input.hardTimeoutMs)
				: this.hardTimeoutMs;

		let trackedPgid = input.pgid;
		if (typeof input.pid === "number" && Number.isInteger(input.pid) && input.pid > 1) {
			const rec = this.tracker.register({
				pid: input.pid,
				pgid: input.pgid,
				label: input.label ?? input.agent ?? "subagent",
				taskId,
				command: input.command,
			});
			trackedPgid = rec.pgid;
		}

		const entry: SubagentWatchdogEntry = {
			taskId,
			agent: normOneLine(input.agent ?? "subagent", 64) || "subagent",
			...(input.intentId ? { intentId: normOneLine(input.intentId, 64) } : {}),
			...(typeof input.pid === "number" ? { pid: input.pid } : {}),
			...(typeof trackedPgid === "number" ? { pgid: trackedPgid } : {}),
			status: "running",
			startedAt: nowMs,
			lastReqAt: nowMs,
			lastOutputAt: nowMs,
			idleTimeoutMs,
			hardTimeoutMs,
		};

		withLock(this.root, () => {
			const store = this.readStore();
			store.tasks[taskId] = entry;
			this.writeStore(store.tasks);
		});
		logEvent(this.root, {
			type: "subagent_started",
			taskId: entry.taskId,
			agent: entry.agent,
			...(entry.intentId ? { intentId: entry.intentId } : {}),
			...(entry.pid ? { pid: entry.pid, pgid: entry.pgid } : {}),
			idleTimeoutMs: entry.idleTimeoutMs,
			hardTimeoutMs: entry.hardTimeoutMs,
		});
		return entry;
	}

	heartbeat(
		taskId: string,
		opts?: { reqAt?: number; outputAt?: number; hasOutput?: boolean; nowMs?: number },
	): SubagentWatchdogEntry | null {
		if (!existsSync(this.filePath())) return null;
		const nowMs = typeof opts?.nowMs === "number" && Number.isFinite(opts.nowMs) ? Math.floor(opts.nowMs) : Date.now();
		return withLock(this.root, () => {
			const store = this.readStore();
			const entry = store.tasks[taskId];
			if (!entry || entry.status !== "running") return null;
			const reqAt = typeof opts?.reqAt === "number" && Number.isFinite(opts.reqAt) ? Math.floor(opts.reqAt) : nowMs;
			entry.lastReqAt = Math.max(entry.lastReqAt, reqAt);
			if (typeof opts?.outputAt === "number" && Number.isFinite(opts.outputAt)) {
				entry.lastOutputAt = Math.max(entry.lastOutputAt, Math.floor(opts.outputAt));
			} else if (opts?.hasOutput !== false) {
				entry.lastOutputAt = Math.max(entry.lastOutputAt, nowMs);
			}
			store.tasks[taskId] = entry;
			this.writeStore(store.tasks);
			return entry;
		});
	}

	recordRequest(taskId: string, nowMs = Date.now()): SubagentWatchdogEntry | null {
		return this.heartbeat(taskId, { reqAt: nowMs, hasOutput: false, nowMs });
	}

	recordOutput(taskId: string, nowMs = Date.now()): SubagentWatchdogEntry | null {
		return this.heartbeat(taskId, { reqAt: nowMs, outputAt: nowMs, hasOutput: true, nowMs });
	}

	completeTask(
		taskId: string,
		status: "completed" | "failed" | "cancelled" = "completed",
		nowMs = Date.now(),
		opts?: { cleanupProcesses?: boolean; graceMs?: number },
	): SubagentWatchdogEntry | null {
		if (!existsSync(this.filePath())) return null;
		const updated = withLock(this.root, () => {
			const store = this.readStore();
			const entry = store.tasks[taskId];
			if (!entry) return null;
			entry.status = status;
			entry.endedAt = nowMs;
			store.tasks[taskId] = entry;
			this.writeStore(store.tasks);
			return entry;
		});
		if (!updated) return null;
		if (opts?.cleanupProcesses !== false && (status === "cancelled" || this.tracker.list({ taskId }).length > 0)) {
			this.tracker.cleanup({
				taskId,
				graceMs: opts?.graceMs ?? this.cleanupGraceMs,
				reason: `subagent_${status}:${taskId}`,
			});
		}
		return updated;
	}

	getTask(taskId: string): SubagentWatchdogEntry | null {
		const store = this.readStore();
		return store.tasks[taskId] ?? null;
	}

	listTasks(filter?: { status?: SubagentTaskStatus }): SubagentWatchdogEntry[] {
		const store = this.readStore();
		const all = Object.values(store.tasks);
		if (!filter?.status) return all;
		return all.filter((t) => t.status === filter.status);
	}

	activeCount(): number {
		return this.listTasks({ status: "running" }).length;
	}

	availableSlots(): number {
		return Math.max(0, this.maxConcurrency - this.activeCount());
	}

	/** 巡检运行中任务：触发无输出空闲超时或单任务硬超时即联动 ProcessGroupTracker 终止并标为 timeout，释放并发槽位。 */
	checkTimeouts(nowMs = Date.now(), opts?: { graceMs?: number; dryRun?: boolean }): WatchdogSweepResult {
		const store = this.readStore();
		const timedOut: WatchdogTimeoutEvent[] = [];
		const graceMs =
			typeof opts?.graceMs === "number" && Number.isFinite(opts.graceMs) && opts.graceMs >= 0
				? Math.floor(opts.graceMs)
				: this.cleanupGraceMs;

		const candidates: Array<{
			entry: SubagentWatchdogEntry;
			timeoutKind: "idle_no_output" | "hard_timeout";
			reason: string;
			idleMs: number;
			elapsedMs: number;
		}> = [];

		for (const entry of Object.values(store.tasks)) {
			if (entry.status !== "running") continue;
			const elapsedMs = Math.max(0, nowMs - entry.startedAt);
			const idleMs = Math.max(0, nowMs - entry.lastOutputAt);
			if (elapsedMs >= entry.hardTimeoutMs) {
				candidates.push({
					entry,
					timeoutKind: "hard_timeout",
					reason: `子代理任务 ${entry.taskId} (${entry.agent}) 触发单任务硬超时 (${Math.round(elapsedMs / 1000)}s >= ${Math.round(entry.hardTimeoutMs / 1000)}s)`,
					idleMs,
					elapsedMs,
				});
			} else if (idleMs >= entry.idleTimeoutMs) {
				candidates.push({
					entry,
					timeoutKind: "idle_no_output",
					reason: `子代理任务 ${entry.taskId} (${entry.agent}) 触发无输出空闲超时 (${Math.round(idleMs / 1000)}s >= ${Math.round(entry.idleTimeoutMs / 1000)}s)`,
					idleMs,
					elapsedMs,
				});
			}
		}

		for (const c of candidates) {
			const cleanup = this.tracker.cleanup({
				taskId: c.entry.taskId,
				graceMs,
				reason: `watchdog:${c.timeoutKind}:${c.entry.taskId}`,
				dryRun: opts?.dryRun,
			});
			timedOut.push({
				taskId: c.entry.taskId,
				agent: c.entry.agent,
				intentId: c.entry.intentId,
				timeoutKind: c.timeoutKind,
				reason: c.reason,
				idleMs: c.idleMs,
				elapsedMs: c.elapsedMs,
				cleanup,
			});
		}

		if (candidates.length > 0 && !opts?.dryRun) {
			withLock(this.root, () => {
				const latest = this.readStore();
				for (const c of candidates) {
					const cur = latest.tasks[c.entry.taskId];
					if (!cur || cur.status !== "running") continue;
					cur.status = "timeout";
					cur.endedAt = nowMs;
					cur.timeoutKind = c.timeoutKind;
					cur.timeoutReason = c.reason;
					latest.tasks[c.entry.taskId] = cur;
				}
				this.writeStore(latest.tasks);
			});
			for (const ev of timedOut) {
				logEvent(this.root, {
					type: "subagent_timeout",
					taskId: ev.taskId,
					agent: ev.agent,
					...(ev.intentId ? { intentId: ev.intentId } : {}),
					timeoutKind: ev.timeoutKind,
					idleMs: ev.idleMs,
					elapsedMs: ev.elapsedMs,
					reason: ev.reason,
					cleanedProcesses: ev.cleanup.cleaned.length,
				});
			}
		}

		const runningCount = this.activeCount();
		return {
			checkedAt: nowMs,
			timedOut,
			runningCount,
			availableSlots: Math.max(0, this.maxConcurrency - runningCount),
		};
	}

	startPolling(intervalMs = 5000, onTimeout?: (res: WatchdogSweepResult) => void): () => void {
		const ms = Math.max(50, Math.floor(intervalMs));
		const timer = setInterval(() => {
			try {
				const res = this.checkTimeouts();
				if (res.timedOut.length > 0) {
					onTimeout?.(res);
				}
			} catch {
				/* 看门狗巡检异常不崩溃主进程 */
			}
		}, ms);
		timer.unref?.();
		return () => clearInterval(timer);
	}
}

// ----------------------------------------------------------------------------
// Issue #47 (NW-27): 易失 /tmp 告警与工作区完整性校验 verifyWorkspaceIntegrity
// ----------------------------------------------------------------------------

export type WorkspaceWarningCode =
	| "NUWA_VOLATILE_TMP_WORKSPACE"
	| "NUWA_WORKSPACE_MISSING"
	| "NUWA_GIT_METADATA_MISSING"
	| "NUWA_STATE_DIR_MISSING";

export interface WorkspaceWarning {
	code: WorkspaceWarningCode;
	severity: "warn" | "error";
	path: string;
	message: string;
	suggestedRoot?: string;
}

export interface WorkspaceIntegrityOptions {
	expectGit?: boolean;
	recordBaseline?: boolean;
	allowTmp?: boolean;
	forceTmpWarning?: boolean;
	env?: Record<string, string | undefined>;
}

export interface WorkspaceIntegrityReport {
	ok: boolean;
	status: "ok" | "warn" | "corrupted";
	root: string;
	exists: boolean;
	hasNuwaDir: boolean;
	hasStateFile: boolean;
	isVolatileTmp: boolean;
	gitExpected: boolean;
	gitPresent: boolean;
	gitHeadValid: boolean;
	warnings: WorkspaceWarning[];
	checkedAt: string;
}

interface WorkspaceMetaRecord {
	schema: number;
	root: string;
	hadGit: boolean;
	firstSeenAt: string;
	updatedAt: string;
	migratedFrom?: string;
	migratedAt?: string;
	[key: string]: unknown;
}

function isSubpathOrEqual(candidate: string, base: string): boolean {
	const c = resolve(candidate);
	const b = resolve(base);
	if (c === b) return true;
	const prefix = b.endsWith("/") ? b : `${b}/`;
	return c.startsWith(prefix);
}

/** 判断路径是否位于易失临时目录（/tmp、/private/tmp、/var/tmp 或 os.tmpdir()）。 */
export function isVolatileTempPath(dirPath: string): boolean {
	const raw = String(dirPath ?? "").trim();
	if (!raw) return false;
	const candidates = new Set<string>([resolve(raw)]);
	try {
		candidates.add(realpathSync(raw));
	} catch {
		/* 目录可能尚不存在或已丢失 */
	}
	const tmpBases = new Set<string>([
		resolve("/tmp"),
		resolve("/private/tmp"),
		resolve("/var/tmp"),
		resolve("/private/var/tmp"),
		resolve(tmpdir()),
	]);
	try {
		tmpBases.add(realpathSync(tmpdir()));
	} catch {
		/* ignore */
	}
	for (const cand of candidates) {
		for (const base of tmpBases) {
			if (isSubpathOrEqual(cand, base)) return true;
		}
	}
	return false;
}

/** 判断当前是否处于单测或显式允许 /tmp 工作区的环境，避免告警污染或破坏测试。 */
export function isTestRuntimeEnv(env: Record<string, string | undefined> = process.env): boolean {
	const allowTmp = (env.NUWA_ALLOW_TMP_WORKSPACE ?? "").trim().toLowerCase();
	if (allowTmp === "1" || allowTmp === "true") return true;
	const nodeEnv = (env.NODE_ENV ?? "").trim().toLowerCase();
	if (nodeEnv === "test") return true;
	if ((env.BUN_TEST ?? "").trim() === "1") return true;
	if (env.VITEST || env.JEST_WORKER_ID || env.NUWA_TEST_MODE === "1") return true;
	if (process.argv.some((a) => /(?:^|[\\/])test\b|\.test\.[jt]sx?$/i.test(a))) return true;
	return false;
}

/** 检测传入生产工作区是否位于易失 /tmp 目录并返回结构化警告（单测或显式允许时静默返回 null）。 */
export function checkWorkspaceTempWarning(
	root: string,
	opts?: { allowTmp?: boolean; forceCheck?: boolean; env?: Record<string, string | undefined> },
): WorkspaceWarning | null {
	if (!root || !root.trim()) return null;
	if (!isVolatileTempPath(root)) return null;
	if (opts?.allowTmp) return null;
	const env = opts?.env ?? process.env;
	if (!opts?.forceCheck && isTestRuntimeEnv(env)) return null;
	const suggestedRoot = resolveDefaultWorkspacesDir(env);
	return {
		code: "NUWA_VOLATILE_TMP_WORKSPACE",
		severity: "warn",
		path: resolve(root),
		suggestedRoot,
		message: `工作区位于易失临时目录 (${resolve(root)})，长跑或系统清理可能导致状态与 .git 丢失；建议迁移至持久化目录 ${suggestedRoot}（可在 nuwa-autonomous 追加 --migrate-workspace 自动迁出）或配置 NUWA_STATE_DIR`,
	};
}

function workspaceMetaPath(root: string): string {
	return join(stateDir(root), "workspace-meta.json");
}

function inspectGitMetadata(root: string): { gitPresent: boolean; gitHeadValid: boolean } {
	const gitEntry = join(root, ".git");
	if (!existsSync(gitEntry)) {
		return { gitPresent: false, gitHeadValid: false };
	}
	try {
		const st = statSync(gitEntry);
		if (st.isDirectory()) {
			return { gitPresent: true, gitHeadValid: existsSync(join(gitEntry, "HEAD")) };
		}
		if (st.isFile()) {
			// Git worktree / submodule 的 .git 指针文件：gitdir: <path>
			const content = readFileSync(gitEntry, "utf8").trim();
			const m = /^gitdir:\s*(.+)$/im.exec(content);
			if (!m?.[1]) return { gitPresent: true, gitHeadValid: false };
			const gitDir = resolve(root, m[1].trim());
			return { gitPresent: true, gitHeadValid: existsSync(join(gitDir, "HEAD")) };
		}
	} catch {
		return { gitPresent: true, gitHeadValid: false };
	}
	return { gitPresent: false, gitHeadValid: false };
}

/**
 * 校验工作区目录与 .git 元数据完好性（Issue #47 / NW-27）。
 * - 启动时可传 `recordBaseline: true` 记录 `hadGit` 基线；
 * - 每轮结算再次调用即可第一时间检出工作区被清理或 `.git` 丢失/损坏并返回明确告警状态。
 */
export function verifyWorkspaceIntegrity(
	root: string,
	opts: WorkspaceIntegrityOptions = {},
): WorkspaceIntegrityReport {
	const normRoot = resolve(root || process.cwd());
	const checkedAt = nowIso();
	const warnings: WorkspaceWarning[] = [];
	const isVolatileTmp = isVolatileTempPath(normRoot);

	let exists = false;
	try {
		exists = existsSync(normRoot) && statSync(normRoot).isDirectory();
	} catch {
		exists = false;
	}

	const hasNuwaDir = exists && existsSync(stateDir(normRoot));
	const hasStateFile = exists && hasProjectState(normRoot);
	const meta = hasNuwaDir ? readJson<WorkspaceMetaRecord>(workspaceMetaPath(normRoot)) : null;
	const { gitPresent, gitHeadValid } = exists
		? inspectGitMetadata(normRoot)
		: { gitPresent: false, gitHeadValid: false };

	if (exists && opts.recordBaseline && hasNuwaDir) {
		try {
			const hadGit = Boolean(meta?.hadGit || gitPresent || opts.expectGit);
			const nextMeta: WorkspaceMetaRecord = {
				...(meta && typeof meta === "object" ? meta : {}),
				schema: 1,
				root: normRoot,
				hadGit,
				firstSeenAt: meta?.firstSeenAt ?? checkedAt,
				updatedAt: checkedAt,
			};
			atomicWrite(workspaceMetaPath(normRoot), JSON.stringify(nextMeta, null, 2));
		} catch {
			/* 记录基线失败不中断主流程 */
		}
	}

	const gitExpected = Boolean(opts.expectGit || meta?.hadGit || gitPresent);

	if (!exists) {
		warnings.push({
			code: "NUWA_WORKSPACE_MISSING",
			severity: "error",
			path: normRoot,
			suggestedRoot: resolveDefaultWorkspacesDir(opts.env),
			message: `工作区目录已丢失或不存在: ${normRoot}`,
		});
	} else if (gitExpected && (!gitPresent || !gitHeadValid)) {
		warnings.push({
			code: "NUWA_GIT_METADATA_MISSING",
			severity: "error",
			path: join(normRoot, ".git"),
			suggestedRoot: resolveDefaultWorkspacesDir(opts.env),
			message: !gitPresent
				? `工作区 .git 元数据丢失（预期为 Git 仓库）: ${normRoot}`
				: `工作区 .git 元数据损坏（缺少有效 HEAD）: ${normRoot}`,
		});
	}

	const tmpWarn = checkWorkspaceTempWarning(normRoot, {
		allowTmp: opts.allowTmp,
		forceCheck: opts.forceTmpWarning,
		env: opts.env,
	});
	if (tmpWarn) {
		warnings.push(tmpWarn);
	}

	const hasError = warnings.some((w) => w.severity === "error");
	const status: "ok" | "warn" | "corrupted" = hasError ? "corrupted" : warnings.length > 0 ? "warn" : "ok";

	if (hasError && hasNuwaDir) {
		logEvent(normRoot, {
			type: "workspace_integrity_alert",
			status,
			root: normRoot,
			warnings: warnings.map((w) => ({ code: w.code, severity: w.severity, message: w.message })),
		});
	}

	return {
		ok: !hasError,
		status,
		root: normRoot,
		exists,
		hasNuwaDir,
		hasStateFile,
		isVolatileTmp,
		gitExpected,
		gitPresent,
		gitHeadValid,
		warnings,
		checkedAt,
	};
}
