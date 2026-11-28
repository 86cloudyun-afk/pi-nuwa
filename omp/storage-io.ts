/**
 * 女娲 v8.0.0 底层文件原子落盘、`state.lock` 单写者跨进程锁与通用路径序列化辅助模块。
 *
 * 约束：纯底层零业务环路模块，仅依赖 Node 内置模块与 `./types`，严禁导入 `./nuwa`、`./storage` 或 `./sqlite-store`。
 */
import { createHash, randomBytes } from "node:crypto";
import {
	closeSync,
	existsSync,
	fsyncSync,
	linkSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	statSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Mode } from "./types";

export const SCHEMA = 1;

/** 动态解析当前生效的 Agent Home，兼容测试期动态切换 `PI_AGENT_HOME`。 */
export function getAgentHome(): string {
	const envHome = process.env.PI_AGENT_HOME?.trim();
	if (envHome) return resolve(envHome);
	const ompHome = join(homedir(), ".omp/agent");
	if (existsSync(ompHome)) return ompHome;
	return join(homedir(), ".pi/agent");
}

export function pointerFilePath(): string {
	return join(getAgentHome(), "cache/nuwa-current.json");
}

export function pointerDirPath(): string {
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

export function projectsDirPath(): string {
	const explicitState = process.env.NUWA_STATE_DIR?.trim();
	if (explicitState) return join(resolve(explicitState), "workspaces");
	// 兼容显式指定 PI_AGENT_HOME（含既有单测与旧缓存目录布局）
	if (process.env.PI_AGENT_HOME?.trim()) {
		return join(getAgentHome(), "cache/nuwa-projects");
	}
	return join(resolvePersistentStateDir(), "workspaces");
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
export function procStartTime(pid: number): string | null {
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

export function sleepSync(ms: number): void {
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
