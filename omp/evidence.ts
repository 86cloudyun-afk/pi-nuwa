/**
 * 执行账本证据复验（升级 3）与本地工具链探针（升级 5）。
 *
 * 约束：仅使用 import type 引用 ./types，严禁运行时 import ./nuwa。
 */
import { createHash, randomBytes } from "node:crypto";
import {
	accessSync,
	chmodSync,
	closeSync,
	constants,
	existsSync,
	fsyncSync,
	linkSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	readdirSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";
import { redactVaultSecrets } from "./session-vault";
import type { FactKind } from "./types";

export interface ExecRecordInput {
	tool: string;
	command?: string;
	output: string;
	sessionId?: string;
	agentName?: string;
}

export interface VerifyEvidenceInput {
	projectId: string;
	kind: FactKind | string;
	command?: string;
	output?: string;
	flagValue?: string;
	strict?: boolean;
	minSeq?: number;
	sinceTs?: string;
	requireSubstantive?: boolean;
	/** v5.1 可选未授权/404 负向对照基线响应体，用于假阳性哈希比对（#24） */
	baselineBody?: string;
	/** v5.1 可选未授权/404 负向对照基线哈希（sha256 或 md5）（#24） */
	baselineHash?: string;
	/** v5.1 可选 HTTP 状态码（#24） */
	statusCode?: number;
	/** v5.1 可选响应体字节数（#24） */
	bodyBytes?: number;
	/** v5.1 显式启用完整假阳性复核门禁（#24） */
	checkFalsePositive?: boolean;
}

export interface VerifyEvidenceResult {
	ok: boolean;
	verified: boolean;
	reason?: string;
	matchedSeq?: number;
	matchedAgent?: string;
	/** v5.1 假阳性复核失败标记（#24） */
	falsePositive?: boolean;
	/** v5.1 假阳性降级建议类型（#24） */
	suggestedKind?: "note";
}

export interface ToolchainCaps {
	available: string[];
	missing: string[];
	probedAt: string;
}

export interface ExecLedgerEntry {
	seq: number;
	ts: string;
	tool: string;
	command?: string;
	sessionId?: string;
	agentName?: string;
	sha1: string;
	normSha1: string;
	bytes: number;
	snippet: string;
}

const LEDGER_MAX_ENTRIES = 200;
const LEDGER_LOCK_TIMEOUT_MS = 3000;
const SNIPPET_HEAD = 4096;
const SNIPPET_TAIL = 2048;

export const DEFAULT_PROBE_TOOLS = [
	"curl",
	"openssl",
	"nmap",
	"ffuf",
	"nuclei",
	"sqlmap",
	"whatweb",
	"hydra",
	"python3",
	"nc",
	"sqlite3",
] as const;

/**
 * 可作为真实执行证据源的工具白名单（read 需额外满足读取目标 URL 或 /tmp/nuwa/ 产物条件）。
 */
export const TRUSTED_EVIDENCE_TOOLS = [
	"bash",
	"sh",
	"shell",
	"exec",
	"autoexec",
	"browser",
	"fetch",
	"web_fetch",
	"http",
	"curl",
	"ssh",
	"read",
] as const;

const TRUSTED_TOOL_SET = new Set<string>(TRUSTED_EVIDENCE_TOOLS);

/**
 * 严禁记入执行证据账本的编排、思考、交互与本地修改工具集合（彻底阻断 task 子代理文本幻觉污染账本）。
 */
const UNTRUSTED_ORCHESTRATION_TOOLS = new Set<string>([
	"task",
	"subagent",
	"agent",
	"delegate",
	"eval",
	"todo",
	"todowrite",
	"todo_write",
	"todoread",
	"todo_read",
	"think",
	"thinking",
	"thought",
	"ask",
	"ask_user",
	"ask_question",
	"plan",
	"enter_plan_mode",
	"exit_plan_mode",
	"write",
	"edit",
	"multi_edit",
	"apply_patch",
	"notebook_edit",
	"web_search",
	"websearch",
	"google_search",
]);

const LOW_ENTROPY_HTTP_STATUS_RE = /^HTTP\/\d(?:\.\d)?\s+\d{3}(?:\s+[A-Za-z0-9 _-]+)?$/i;
const LOW_ENTROPY_HTTP_HEADER_RE =
	/^(?:Content-Type|Content-Length|Connection|Date|Server|Cache-Control|Transfer-Encoding|Accept-Ranges|Vary|Keep-Alive|Expires|Pragma|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Referrer-Policy|Content-Encoding|ETag|Last-Modified|Age|Host|User-Agent|Accept|Accept-Encoding|Accept-Language)\s*:/i;
const LOW_ENTROPY_BOILERPLATE_RE =
	/^(?:\d{3}\s+(?:OK|Found|Moved Permanently|Not Found|Forbidden|Unauthorized|Bad Request|Internal Server Error|Service Unavailable|No Content)|<html>|<\/html>|<head>|<\/head>|<body>|<\/body>|<!doctype\s+html>|\{\s*\}|\[\s*\]|true|false|ok|success|error|failed|denied)$/i;
const PUNCTUATION_ONLY_RE = /^[\s{}[\](),:;="'`~@#$%^&*+\-_/\\|<>?!.]+$/;

function isNuwaTmpArtifactPath(rawPath: string): boolean {
	const trimmed = rawPath.trim();
	if (!trimmed) return false;
	const resolved = resolve(trimmed).replace(/\\/g, "/");
	return resolved.startsWith("/tmp/nuwa/") || resolved.startsWith("/private/tmp/nuwa/");
}

function extractReadTarget(input?: Record<string, unknown> | string | null): string {
	if (typeof input === "string") return input.trim();
	if (!input || typeof input !== "object") return "";
	for (const key of ["path", "file_path", "file", "url", "command"]) {
		const val = input[key];
		if (typeof val === "string" && val.trim()) {
			return val.trim();
		}
	}
	return "";
}

/**
 * 判断一次工具事件是否允许作为可信执行证据源记入 exec-ledger：
 * - 明确拒绝 task、eval、todo、think、ask 及所有 nuwa_* 工具；
 * - read 仅在读取 http(s):// 目标 URL 或 /tmp/nuwa/ 产物文件时返回 true；
 * - 其余工具需命中 TRUSTED_EVIDENCE_TOOLS（含 browser_* 子动作）。
 */
export function isTrustedEvidenceEvent(
	toolName: string,
	input?: Record<string, unknown> | string | null,
): boolean {
	const name = String(toolName ?? "").trim().toLowerCase();
	if (!name) return false;
	if (name.startsWith("nuwa_") || UNTRUSTED_ORCHESTRATION_TOOLS.has(name)) {
		return false;
	}
	if (name === "read" || name === "read_file") {
		const target = extractReadTarget(input);
		if (!target) return false;
		return /^https?:\/\//i.test(target) || isNuwaTmpArtifactPath(target);
	}
	if (name.startsWith("browser_")) {
		return true;
	}
	return TRUSTED_TOOL_SET.has(name);
}

/**
 * 判断单行文本是否属于低信息熵的通用 HTTP 状态行、常规响应头或占位模板行。
 * 安全相关响应头（如 Set-Cookie / Authorization / Location / X-Debug-* / Access-Control-*）不视为通用行。
 */
export function isLowEntropyGenericLine(line: string): boolean {
	const trimmed = String(line ?? "").trim();
	if (!trimmed || trimmed.length < 3) return true;
	if (PUNCTUATION_ONLY_RE.test(trimmed)) return true;
	const cleaned = trimmed.replace(/^[<>]\s+/, "");
	if (LOW_ENTROPY_HTTP_STATUS_RE.test(cleaned)) return true;
	if (LOW_ENTROPY_HTTP_HEADER_RE.test(cleaned)) return true;
	if (LOW_ENTROPY_BOILERPLATE_RE.test(cleaned)) return true;
	return false;
}

interface MemoryLedgerRecord extends ExecLedgerEntry {
	rawOutput?: string;
}

const memoryRing = new Map<string, MemoryLedgerRecord[]>();
const heldLedgerLocks = new Set<string>();
const SLEEP_VIEW = new Int32Array(new SharedArrayBuffer(4));
let atomicLedgerSeq = 0;

function sha1Hex(text: string): string {
	return createHash("sha1").update(text).digest("hex");
}

function ledgerFilePath(root: string): string {
	return join(resolve(root), ".nuwa", "exec-ledger.jsonl");
}

function ledgerLockPath(root: string): string {
	return join(resolve(root), ".nuwa", "exec-ledger.lock");
}

function buildSnippet(output: string): string {
	if (output.length <= SNIPPET_HEAD + SNIPPET_TAIL) {
		return output;
	}
	return `${output.slice(0, SNIPPET_HEAD)}\n...[truncated]...\n${output.slice(-SNIPPET_TAIL)}`;
}

function safeRedact(text: string, normRoot: string): string {
	if (!text) return text;
	try {
		return redactVaultSecrets(text, normRoot);
	} catch {
		return text;
	}
}

function entrySeq(entry: Partial<ExecLedgerEntry> | undefined): number {
	return typeof entry?.seq === "number" && Number.isFinite(entry.seq) && entry.seq > 0
		? Math.floor(entry.seq)
		: 0;
}

function maxSeqOf(entries: readonly Partial<ExecLedgerEntry>[]): number {
	let max = 0;
	for (const e of entries) {
		const s = entrySeq(e);
		if (s > max) max = s;
	}
	return max;
}

function sleepSync(ms: number): void {
	if (ms <= 0) return;
	Atomics.wait(SLEEP_VIEW, 0, 0, ms);
}

function pidAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (err) {
		return (err as NodeJS.ErrnoException)?.code === "EPERM";
	}
}

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

function readLockHolder(lockFile: string): { pid?: number; ts?: number; start?: string | null; nonce?: string } | null {
	try {
		const raw = readFileSync(lockFile, "utf8").trim();
		if (!raw) return null;
		const parsed = JSON.parse(raw) as { pid?: number; ts?: number; start?: string | null; nonce?: string };
		return parsed && typeof parsed === "object" ? parsed : null;
	} catch {
		return null;
	}
}

function withLedgerLock<T>(normRoot: string, fn: () => T, timeoutMs = LEDGER_LOCK_TIMEOUT_MS): T {
	const p = ledgerLockPath(normRoot);
	mkdirSync(dirname(p), { recursive: true });
	if (heldLedgerLocks.has(p)) {
		return fn();
	}

	const deadline = Date.now() + timeoutMs;
	let backoff = 4;
	const myNonce = `${process.pid}-${Date.now()}-${randomBytes(6).toString("hex")}`;
	const payload = JSON.stringify({
		pid: process.pid,
		ts: Date.now(),
		start: procStartTime(process.pid),
		nonce: myNonce,
	});

	for (;;) {
		const tmp = `${p}.tmp-${process.pid}-${atomicLedgerSeq++}`;
		let acquired = false;
		let useFallback = false;
		let tfd = -1;
		try {
			tfd = openSync(tmp, "wx", 0o600);
			writeSync(tfd, payload);
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
				writeSync(fd, payload);
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
			const held = readLockHolder(p);
			let emptyMtimeMs: number | null = null;
			if (held) {
				const heldPid = typeof held.pid === "number" ? held.pid : 0;
				const heldStart = typeof held.start === "string" ? held.start : null;
				const sameProcess =
					heldPid > 0 && pidAlive(heldPid) && (!heldStart || heldStart === procStartTime(heldPid));
				if (sameProcess) {
					if (Date.now() >= deadline) {
						throw new Error(`exec-ledger locked by pid ${heldPid}`);
					}
					sleepSync(backoff);
					backoff = Math.min(backoff * 2, 64);
					continue;
				}
			} else {
				// 刚创建尚未写完 JSON 的极短窗口内暂缓抢占，避免误删并发写者的活锁
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

			// 独占回收锁 + 二次核验，杜绝多进程并发清理死锁时误删先恢复者的活锁
			const reclaimPath = `${p}.reclaim`;
			const reclaimTmp = `${p}.reclaim.tmp-${process.pid}-${atomicLedgerSeq++}`;
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
					const nowHeld = readLockHolder(p);
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
							/* 已被其他写者回收 */
						}
					}
				} finally {
					try {
						const curReclaim = readLockHolder(reclaimPath);
						if (curReclaim?.nonce === reclaimNonce) unlinkSync(reclaimPath);
					} catch {
						/* ignore */
					}
				}
			} else {
				const oldReclaim = readLockHolder(reclaimPath);
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
				const cur = readLockHolder(p);
				throw new Error(`exec-ledger locked by pid ${cur?.pid ?? 0}`);
			}
			continue;
		}

		heldLedgerLocks.add(p);
		try {
			return fn();
		} finally {
			heldLedgerLocks.delete(p);
			try {
				const cur = readLockHolder(p);
				if (cur?.nonce === myNonce) {
					unlinkSync(p);
				}
			} catch {
				/* 已被回收 */
			}
		}
	}
}

function readDiskLedger(root: string): ExecLedgerEntry[] {
	const p = ledgerFilePath(root);
	if (!existsSync(p)) return [];
	try {
		const raw = readFileSync(p, "utf8");
		const out: ExecLedgerEntry[] = [];
		for (const line of raw.split("\n")) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			try {
				const parsed = JSON.parse(trimmed) as Partial<ExecLedgerEntry>;
				if (parsed && typeof parsed.sha1 === "string" && typeof parsed.snippet === "string") {
					out.push({
						seq: entrySeq(parsed),
						ts: typeof parsed.ts === "string" ? parsed.ts : "",
						tool: typeof parsed.tool === "string" ? parsed.tool : "",
						...(typeof parsed.command === "string" ? { command: parsed.command } : {}),
						...(typeof parsed.sessionId === "string" ? { sessionId: parsed.sessionId } : {}),
						...(typeof parsed.agentName === "string" && parsed.agentName.trim()
							? { agentName: parsed.agentName.trim() }
							: {}),
						sha1: parsed.sha1,
						normSha1: typeof parsed.normSha1 === "string" ? parsed.normSha1 : parsed.sha1,
						bytes: typeof parsed.bytes === "number" && Number.isFinite(parsed.bytes) ? parsed.bytes : 0,
						snippet: parsed.snippet,
					});
				}
			} catch {
				/* 忽略损坏单行 */
			}
		}
		return out.slice(-LEDGER_MAX_ENTRIES);
	} catch {
		return [];
	}
}

function writeDiskLedger(root: string, entries: readonly ExecLedgerEntry[]): void {
	const p = ledgerFilePath(root);
	let tmp = "";
	try {
		mkdirSync(dirname(p), { recursive: true });
		const tail = entries.slice(-LEDGER_MAX_ENTRIES).map((e) => {
			const diskEntry: ExecLedgerEntry = {
				seq: entrySeq(e),
				ts: e.ts,
				tool: e.tool,
				...(e.command !== undefined ? { command: e.command } : {}),
				...(e.sessionId !== undefined ? { sessionId: e.sessionId } : {}),
				...(e.agentName !== undefined ? { agentName: e.agentName } : {}),
				sha1: e.sha1,
				normSha1: e.normSha1,
				bytes: e.bytes,
				snippet: e.snippet,
			};
			return JSON.stringify(diskEntry);
		});
		const body = tail.length ? `${tail.join("\n")}\n` : "";
		tmp = `${p}.tmp-${process.pid}-${Date.now()}-${atomicLedgerSeq++}`;
		writeFileSync(tmp, body, { encoding: "utf8", mode: 0o600 });
		try {
			chmodSync(tmp, 0o600);
		} catch {
			/* 忽略非 POSIX 权限异常 */
		}
		renameSync(tmp, p);
		tmp = "";
		try {
			chmodSync(p, 0o600);
		} catch {
			/* 忽略非 POSIX 权限异常 */
		}
	} catch {
		if (tmp) {
			try {
				unlinkSync(tmp);
			} catch {
				/* ignore */
			}
		}
		/* 写盘失败不打断主流程，内存缓冲仍保留 */
	}
}

/**
 * 获取指定项目根目录在内存环形缓冲与磁盘执行账本中的最高单调序列号（无记录时返回 0）。
 */
export function getLatestLedgerSeq(root: string): number {
	const normRoot = resolve(root || process.cwd());
	const memMax = maxSeqOf(memoryRing.get(normRoot) ?? []);
	const diskMax = maxSeqOf(readDiskLedger(normRoot));
	return Math.max(memMax, diskMax);
}

/**
 * 记录一次真实工具执行结果：在专属文件锁保护下同步更新进程内环形缓冲与 <root>/.nuwa/exec-ledger.jsonl
 * （单调递增 seq、自动脱敏会话保险箱凭据、0o600 落盘并滚动保留最近 200 条摘要与 SHA1）。
 * 防御性拒绝 task / eval / todo / think / ask / nuwa_* 等非执行编排工具，防止子代理幻觉文本污染账本。
 */
export function recordToolExecution(root: string, rec: ExecRecordInput): void {
	const rawTool = String(rec.tool ?? "").trim();
	const normTool = rawTool.toLowerCase();
	if (!normTool || normTool.startsWith("nuwa_") || UNTRUSTED_ORCHESTRATION_TOOLS.has(normTool)) {
		return;
	}
	if (normTool === "read" || normTool === "read_file") {
		if (!isTrustedEvidenceEvent(normTool, { path: rec.command })) {
			return;
		}
	}

	const normRoot = resolve(root || process.cwd());
	const rawOutput = String(rec.output ?? "");
	const redactedCommand = rec.command ? safeRedact(String(rec.command), normRoot).slice(0, 1000) : undefined;
	const redactedOutput = safeRedact(rawOutput, normRoot);
	const cleanAgent = rec.agentName ? String(rec.agentName).trim() : "";

	const buildEntry = (seq: number): MemoryLedgerRecord => ({
		seq,
		ts: new Date().toISOString(),
		tool: rawTool,
		...(redactedCommand ? { command: redactedCommand } : {}),
		...(rec.sessionId ? { sessionId: String(rec.sessionId) } : {}),
		...(cleanAgent ? { agentName: cleanAgent } : {}),
		sha1: sha1Hex(rawOutput),
		normSha1: sha1Hex(rawOutput.trim()),
		bytes: Buffer.byteLength(rawOutput, "utf8"),
		snippet: buildSnippet(redactedOutput),
		rawOutput: rawOutput.length <= 65_536 ? rawOutput : undefined,
	});

	const pushMemory = (entry: MemoryLedgerRecord): void => {
		const mem = memoryRing.get(normRoot) ?? [];
		mem.push(entry);
		if (mem.length > LEDGER_MAX_ENTRIES) {
			mem.splice(0, mem.length - LEDGER_MAX_ENTRIES);
		}
		memoryRing.set(normRoot, mem);
	};

	try {
		withLedgerLock(normRoot, () => {
			const mem = memoryRing.get(normRoot) ?? [];
			const diskExisting = readDiskLedger(normRoot);
			const nextSeq = Math.max(maxSeqOf(mem), maxSeqOf(diskExisting)) + 1;
			const entry = buildEntry(nextSeq);
			diskExisting.push(entry);
			writeDiskLedger(normRoot, diskExisting);
			pushMemory(entry);
		});
	} catch {
		const mem = memoryRing.get(normRoot) ?? [];
		const nextSeq = maxSeqOf(mem) + 1;
		pushMemory(buildEntry(nextSeq));
	}
}

/**
 * 判断指定项目根目录是否已存在真实工具执行历史（内存环形缓冲或磁盘 exec-ledger.jsonl）。
 */
export function hasExecutionHistory(root: string): boolean {
	const normRoot = resolve(root || process.cwd());
	const mem = memoryRing.get(normRoot);
	if (mem && mem.length > 0) return true;
	return readDiskLedger(normRoot).length > 0;
}

function collectArtifactTexts(projectId: string): string[] {
	const safeId = String(projectId ?? "").trim();
	if (!safeId || /[\\/]|\.\./.test(safeId)) return [];
	const baseDir = join("/tmp/nuwa", safeId);
	try {
		if (!existsSync(baseDir)) return [];
		const baseStat = lstatSync(baseDir);
		if (baseStat.isSymbolicLink() || !baseStat.isDirectory()) return [];
	} catch {
		return [];
	}

	const texts: string[] = [];
	let totalBytes = 0;
	const MAX_TOTAL = 2 * 1024 * 1024;
	const MAX_FILE = 256 * 1024;

	const walk = (dir: string, depth: number) => {
		if (depth > 2 || totalBytes >= MAX_TOTAL) return;
		let entries: string[] = [];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const name of entries) {
			if (totalBytes >= MAX_TOTAL) break;
			const full = join(dir, name);
			try {
				const st = lstatSync(full);
				if (st.isSymbolicLink()) continue;
				if (st.isDirectory()) {
					walk(full, depth + 1);
				} else if (st.isFile() && st.size > 0) {
					const buf = readFileSync(full);
					const slice = buf.length > MAX_FILE ? buf.subarray(0, MAX_FILE) : buf;
					totalBytes += slice.length;
					texts.push(slice.toString("utf8"));
				}
			} catch {
				/* 跳过不可读文件 */
			}
		}
	};

	walk(baseDir, 0);
	return texts;
}

function cleanOutputLines(output: string): string[] {
	return output
		.replace(/\r/g, "")
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l.length > 0 && !/^(?:\.\.\.|---.*---|todo|tbd|n\/a|none|null|-+)$/i.test(l));
}

function extractKeyLines(output: string): string[] {
	const lines = cleanOutputLines(output);
	const strong = lines.filter((l) => l.length >= 6);
	return strong.length > 0 ? strong.slice(0, 20) : lines.filter((l) => l.length >= 3).slice(0, 20);
}

function extractSubstantiveLines(output: string): string[] {
	const lines = cleanOutputLines(output).filter((l) => !isLowEntropyGenericLine(l));
	const strong = lines.filter((l) => l.length >= 6);
	return strong.length > 0 ? strong.slice(0, 20) : lines.filter((l) => l.length >= 3).slice(0, 20);
}

interface CorpusRecord {
	seq?: number;
	agentName?: string;
	sha1?: string;
	normSha1?: string;
	texts: string[];
}

function makeVerifiedResult(rec?: CorpusRecord): VerifyEvidenceResult {
	const res: VerifyEvidenceResult = { ok: true, verified: true };
	if (rec?.seq !== undefined && rec.seq > 0) {
		Object.defineProperty(res, "matchedSeq", {
			value: rec.seq,
			enumerable: false,
			configurable: true,
			writable: true,
		});
	}
	if (rec?.agentName) {
		Object.defineProperty(res, "matchedAgent", {
			value: rec.agentName,
			enumerable: false,
			configurable: true,
			writable: true,
		});
	}
	return res;
}

/**
 * 复验提交的证据（output / flagValue）是否真实出现在近期执行账本或 /tmp/nuwa/<projectId>/ 产物文件中。
 * 支持 minSeq / sinceTs 增量新鲜度校验、防低信息熵通用 HTTP 头绕过以及命中 seq/agentName 回传。
 */
export function verifyExecutionEvidence(root: string, input: VerifyEvidenceInput): VerifyEvidenceResult {
	const envMode = (process.env.NUWA_STRICT_EVIDENCE ?? "").trim();
	if (envMode === "0") {
		return { ok: true, verified: false, reason: "NUWA_STRICT_EVIDENCE=0 已放行" };
	}

	const normRoot = resolve(root || process.cwd());
	const allMemRecords = memoryRing.get(normRoot) ?? [];
	const allDiskRecords = readDiskLedger(normRoot);
	const hasAnyHist = allMemRecords.length > 0 || allDiskRecords.length > 0;

	const hasMinSeq = typeof input.minSeq === "number" && Number.isFinite(input.minSeq);
	const minSeqVal = hasMinSeq ? Math.floor(input.minSeq!) : undefined;
	const parsedSinceTs = input.sinceTs ? Date.parse(input.sinceTs) : Number.NaN;
	const hasSinceTs = Number.isFinite(parsedSinceTs);

	const matchesBounds = (r: ExecLedgerEntry): boolean => {
		if (hasMinSeq && entrySeq(r) <= minSeqVal!) return false;
		if (hasSinceTs) {
			const rTs = Date.parse(r.ts);
			if (!Number.isFinite(rTs) || rTs < parsedSinceTs - 1) return false;
		}
		return true;
	};

	const memRecords = allMemRecords.filter(matchesBounds);
	const diskRecords = allDiskRecords.filter(matchesBounds);

	// 合并内存与磁盘账本（按 seq 去重并保留最新顺序，内存 rawOutput 仅用于内存中复验绝不落盘）
	const bySeq = new Map<number, CorpusRecord>();
	const legacyRecords: CorpusRecord[] = [];

	const addLedgerRecord = (r: MemoryLedgerRecord | ExecLedgerEntry, rawOutput?: string) => {
		const seq = entrySeq(r);
		const texts: string[] = [];
		if (rawOutput) texts.push(rawOutput);
		if (r.snippet && !texts.includes(r.snippet)) texts.push(r.snippet);

		if (seq > 0) {
			const prev = bySeq.get(seq);
			if (prev) {
				for (const t of texts) {
					if (!prev.texts.includes(t)) prev.texts.unshift(t);
				}
				if (!prev.agentName && r.agentName) prev.agentName = r.agentName;
				if (!prev.sha1 && r.sha1) prev.sha1 = r.sha1;
				if (!prev.normSha1 && r.normSha1) prev.normSha1 = r.normSha1;
			} else {
				bySeq.set(seq, {
					seq,
					agentName: r.agentName,
					sha1: r.sha1,
					normSha1: r.normSha1,
					texts,
				});
			}
		} else {
			legacyRecords.push({
				agentName: r.agentName,
				sha1: r.sha1,
				normSha1: r.normSha1,
				texts,
			});
		}
	};

	for (const r of diskRecords) {
		addLedgerRecord(r);
	}
	for (const r of memRecords) {
		addLedgerRecord(r, r.rawOutput);
	}

	const corpusRecords: CorpusRecord[] = [
		...[...bySeq.values()].sort((a, b) => (b.seq ?? 0) - (a.seq ?? 0)),
		...legacyRecords.reverse(),
	];

	// 当指定了 minSeq 或 sinceTs 时仅检索严格更新的账本记录，跳过无序列水印的 /tmp/nuwa/ 产物兜底
	if (!hasMinSeq && !hasSinceTs) {
		const artifacts = collectArtifactTexts(input.projectId);
		for (const t of artifacts) {
			corpusRecords.push({ texts: [t] });
		}
	}

	const normKind = String(input.kind ?? "").trim().toLowerCase();
	const strictActive = Boolean(input.strict) || envMode === "1";
	const requireSubstantive = Boolean(input.requireSubstantive);
	const substantiveMode = requireSubstantive || normKind === "vuln" || normKind === "cred" || normKind === "bypass";

	const rawOut = String(input.output ?? "");
	const trimmedOut = rawOut.trim();
	const redactedRawOut = safeRedact(rawOut, normRoot);
	const redactedTrimmedOut = redactedRawOut.trim();

	// v5.1 (#24): 正向 vuln/bypass/cred/loot 假阳性门禁（拦截微小错误壳、HTTP 200 空壳与同基线哈希响应）
	const isPositiveFindingKind =
		normKind === "vuln" || normKind === "bypass" || normKind === "cred" || normKind === "loot";
	if (isPositiveFindingKind && trimmedOut.length > 0) {
		const hasExplicitFpCheck =
			Boolean(input.checkFalsePositive) ||
			input.baselineBody !== undefined ||
			input.baselineHash !== undefined ||
			input.statusCode !== undefined ||
			input.bodyBytes !== undefined;
		const substantiveLinesPrecheck = extractSubstantiveLines(rawOut);
		// 仅含通用 HTTP 状态/响应头时交由下方既有低信息熵过滤器返回精确提示
		if (substantiveLinesPrecheck.length > 0 || hasExplicitFpCheck) {
			const fpCheck = evaluatePositiveEvidenceGate({
				kind: normKind,
				output: rawOut,
				response:
					input.statusCode !== undefined || input.bodyBytes !== undefined
						? {
								statusCode: input.statusCode,
								bodyBytes: input.bodyBytes,
								body: extractHttpBodyFromOutput(rawOut),
							}
						: undefined,
				baseline:
					input.baselineBody !== undefined || input.baselineHash !== undefined
						? {
								body: input.baselineBody,
								bodySha256:
									input.baselineHash && input.baselineHash.trim().length === 64
										? input.baselineHash.trim().toLowerCase()
										: undefined,
								bodyMd5:
									input.baselineHash && input.baselineHash.trim().length === 32
										? input.baselineHash.trim().toLowerCase()
										: undefined,
							}
						: undefined,
				requireBusinessPayload: hasExplicitFpCheck,
			});
			if (fpCheck.falsePositive) {
				return {
					ok: false,
					verified: false,
					falsePositive: true,
					suggestedKind: "note",
					reason: fpCheck.reason ?? `假阳性复核未通过: ${normKind} 疑似错误壳或与负向基线一致，建议降级为 note 记账`,
				};
			}
		}
	}

	const explicitFlag = String(input.flagValue ?? "").trim();
	const inferredFlag =
		!explicitFlag && normKind === "flag" ? (rawOut.match(/flag\{[^}\s]{2,}\}/i)?.[0] ?? "") : "";
	const targetFlag = explicitFlag || inferredFlag;
	const isFlagCheck = Boolean(targetFlag) || normKind === "flag";

	if (hasMinSeq && corpusRecords.length === 0) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: 未找到序列号大于 ${minSeqVal} 的新增真实工具执行记录`,
		};
	}

	if (hasSinceTs && corpusRecords.length === 0) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: 未找到晚于 ${input.sinceTs} 的新增真实工具执行记录`,
		};
	}

	let matchedRecord: CorpusRecord | undefined;

	if (targetFlag) {
		matchedRecord = corpusRecords.find((rec) => rec.texts.some((chunk) => chunk.includes(targetFlag)));
	} else if (trimmedOut.length > 0) {
		if (substantiveMode) {
			const substantiveLines = extractSubstantiveLines(rawOut);
			const redactedSubstantiveLines =
				redactedRawOut !== rawOut
					? extractSubstantiveLines(redactedRawOut).filter((l) => !/^[\s*]+$/.test(l))
					: [];

			if (substantiveLines.length === 0) {
				if (
					requireSubstantive ||
					normKind === "vuln" ||
					(normKind === "cred" && (strictActive || hasAnyHist || hasMinSeq || hasSinceTs))
				) {
					return {
						ok: false,
						verified: false,
						reason: `证据复验未通过: ${input.kind} 仅含通用HTTP状态/响应头，缺少实质性差异或特征证据行`,
					};
				}
			} else {
				const rawSha1 = sha1Hex(rawOut);
				const trimmedSha1 = sha1Hex(trimmedOut);
				matchedRecord = corpusRecords.find(
					(rec) =>
						rec.sha1 === rawSha1 ||
						rec.normSha1 === rawSha1 ||
						rec.sha1 === trimmedSha1 ||
						rec.normSha1 === trimmedSha1,
				);

				if (!matchedRecord && trimmedOut.length >= 4) {
					matchedRecord = corpusRecords.find((rec) => rec.texts.some((chunk) => chunk.includes(trimmedOut)));
				}

				if (
					!matchedRecord &&
					redactedTrimmedOut !== trimmedOut &&
					redactedTrimmedOut.length >= 4 &&
					!/^[\s*]+$/.test(redactedTrimmedOut)
				) {
					matchedRecord = corpusRecords.find((rec) =>
						rec.texts.some((chunk) => chunk.includes(redactedTrimmedOut)),
					);
				}

				if (!matchedRecord) {
					matchedRecord = corpusRecords.find((rec) =>
						substantiveLines.some((line) => rec.texts.some((chunk) => chunk.includes(line))),
					);
				}

				if (!matchedRecord && redactedSubstantiveLines.length > 0) {
					matchedRecord = corpusRecords.find((rec) =>
						redactedSubstantiveLines.some((line) => rec.texts.some((chunk) => chunk.includes(line))),
					);
				}
			}
		} else {
			const rawSha1 = sha1Hex(rawOut);
			const trimmedSha1 = sha1Hex(trimmedOut);
			matchedRecord = corpusRecords.find(
				(rec) =>
					rec.sha1 === rawSha1 ||
					rec.normSha1 === rawSha1 ||
					rec.sha1 === trimmedSha1 ||
					rec.normSha1 === trimmedSha1,
			);
			if (!matchedRecord && trimmedOut.length >= 4) {
				matchedRecord = corpusRecords.find((rec) => rec.texts.some((chunk) => chunk.includes(trimmedOut)));
			}
			if (!matchedRecord) {
				const keyLines = extractKeyLines(rawOut);
				if (keyLines.length > 0) {
					matchedRecord = corpusRecords.find((rec) =>
						keyLines.some((line) => rec.texts.some((chunk) => chunk.includes(line))),
					);
				}
			}
		}
	}

	if (matchedRecord) {
		return makeVerifiedResult(matchedRecord);
	}

	if (hasMinSeq) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: 未在序列号大于 ${minSeqVal} 的新增真实执行账本中命中 ${input.kind} 关键证据`,
		};
	}

	if (hasSinceTs) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: 未在晚于 ${input.sinceTs} 的新增真实执行账本中命中 ${input.kind} 关键证据`,
		};
	}

	if (isFlagCheck && (strictActive || hasAnyHist)) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: flag 未在近期真实执行账本或 /tmp/nuwa/${input.projectId}/ 产物中出现`,
		};
	}

	if ((normKind === "vuln" || normKind === "cred") && (strictActive || hasAnyHist)) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: ${input.kind} 的关键回显未在近期真实执行账本或 /tmp/nuwa/${input.projectId}/ 产物中命中`,
		};
	}

	if (strictActive || requireSubstantive) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: ${input.kind} 的关键回显未在近期执行账本或产物目录中命中`,
		};
	}

	return {
		ok: true,
		verified: false,
		reason: hasAnyHist ? "未在近期账本摘要中完全匹配关键行（非严格模式软放行）" : "尚无工具执行账本记录",
	};
}

function isExecutableInPath(binName: string): boolean {
	const name = String(binName ?? "").trim();
	if (!name) return false;
	if (name.includes("/") || name.includes("\\")) {
		try {
			return statSync(name).isFile() && (accessSync(name, constants.X_OK), true);
		} catch {
			return false;
		}
	}
	const pathEnv = process.env.PATH ?? "";
	for (const dir of pathEnv.split(delimiter)) {
		if (!dir) continue;
		const full = join(dir, name);
		try {
			if (statSync(full).isFile()) {
				accessSync(full, constants.X_OK);
				return true;
			}
		} catch {
			/* 继续查找下一 PATH 目录 */
		}
	}
	return false;
}

/**
 * 探测当前系统 PATH 中已安装的可执行工具链。
 */
export function probeToolchain(names?: string[]): ToolchainCaps {
	const list = names !== undefined ? names : [...DEFAULT_PROBE_TOOLS];
	const available: string[] = [];
	const missing: string[] = [];
	const seen = new Set<string>();

	for (const raw of list) {
		const name = String(raw ?? "").trim();
		if (!name || seen.has(name)) continue;
		seen.add(name);
		if (isExecutableInPath(name)) {
			available.push(name);
		} else {
			missing.push(name);
		}
	}

	return {
		available,
		missing,
		probedAt: new Date().toISOString(),
	};
}

function escapeRegExp(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildFallbackHint(missingTool: string, avail: ReadonlySet<string>): string {
	const hasPy = avail.has("python3");
	const hasCurl = avail.has("curl");
	const hasNc = avail.has("nc");
	const hasOpenssl = avail.has("openssl");

	switch (missingTool.toLowerCase()) {
		case "nmap": {
			const alts = [
				hasPy ? "python3 (socket.create_connection 短超时并发端口探测)" : "",
				hasNc ? "nc -zv" : "",
				hasCurl ? "curl -vI" : "",
			].filter(Boolean);
			return `nmap 未安装 → 请改用 ${alts.join(" / ") || "内置网络工具"} 进行连通性与服务指纹核对`;
		}
		case "ffuf":
		case "gobuster":
		case "feroxbuster":
		case "dirsearch": {
			const alts = [
				hasCurl ? "curl 状态码循环探测 (-o /dev/null -w '%{http_code}')" : "",
				hasPy ? "python3 urllib.request 受控并发枚举" : "",
			].filter(Boolean);
			return `${missingTool} 未安装 → 请改用 ${alts.join(" 或 ") || "标准 HTTP 客户端"} 做常见路径枚举`;
		}
		case "nuclei":
		case "whatweb":
		case "httpx": {
			const alts = [
				hasCurl ? "curl -k -sS -D - 提取响应头与页面特征" : "",
				hasPy ? "python3 标准库解析指纹" : "",
			].filter(Boolean);
			return `${missingTool} 未安装 → 请改用 ${alts.join(" 配合 ") || "标准请求工具"} 做版本指纹与配置核查`;
		}
		case "sqlmap": {
			const alts = [hasCurl ? "curl" : "", hasPy ? "python3 urllib.request" : ""].filter(Boolean);
			return `sqlmap 未安装 → 请改用 ${alts.join(" / ") || "HTTP 请求工具"} 发送受控参数对照请求观察响应差异`;
		}
		case "hydra": {
			const alts = [hasCurl ? "curl" : "", hasPy ? "python3 标准客户端" : ""].filter(Boolean);
			return `hydra 未安装 → 请改用 ${alts.join(" / ") || "标准客户端"} 进行有限次数（<=5 次防锁定）的默认配置核查`;
		}
		case "openssl": {
			const alts = [hasCurl ? "curl -kvI" : "", hasPy ? "python3 ssl 模块" : ""].filter(Boolean);
			return `openssl 未安装 → 请改用 ${alts.join(" 或 ") || "标准 TLS 客户端"} 获取证书信息`;
		}
		case "nc": {
			return hasPy
				? "nc 未安装 → 请改用 python3 socket 模块读取服务基础 Banner"
				: "nc 未安装 → 请改用本地可用客户端探测端口响应";
		}
		case "sqlite3": {
			return hasPy
				? "sqlite3 CLI 未安装 → 请改用 python3 内置 sqlite3 模块只读查询本地数据库"
				: "sqlite3 CLI 未安装 → 请检查本地可用脚本运行时读取文件";
		}
		default: {
			const list = [...avail].join(", ") || "基础 shell 工具";
			return `${missingTool} 未安装 → 请改用本机已安装工具 (${list}) 完成等效合规验证`;
		}
	}
}

/**
 * 当派单指令中包含本机缺失工具时，自动附加基于本地已有可用工具的合规替代提示。
 */
export function adaptPacketForToolchain(packet: string, caps: ToolchainCaps): string {
	const text = String(packet ?? "");
	if (!text || !caps?.missing?.length) return text;

	const availSet = new Set((caps.available ?? []).map((s) => s.toLowerCase()));
	const hits: string[] = [];
	for (const tool of caps.missing) {
		const name = String(tool ?? "").trim();
		if (!name) continue;
		const re = new RegExp(`\\b${escapeRegExp(name)}\\b`, "i");
		if (re.test(text)) {
			hits.push(name);
		}
	}

	if (hits.length === 0) return text;

	const hints = hits.map((t) => `- ${buildFallbackHint(t, availSet)}`);
	const availLine = caps.available?.length ? caps.available.join(", ") : "(未探测到扩展工具)";

	return [
		text,
		"",
		`[本地工具链适配提示]`,
		`本机缺失工具: ${hits.join(", ")} | 当前可用工具: ${availLine}`,
		`请勿直接调用缺失命令，改用以下本地合规替代方案:`,
		...hints,
	].join("\n");
}

// ============================================================================
// v5.1 证据门禁加固、交付真实性校验、命中指标、落盘取证与结构化回包解析
// 覆盖 Issues: #24 (NW-04), #26 (NW-06), #39 (NW-19), #42 (NW-22), #51 (NW-31)
// ============================================================================

/** #39 (NW-19) 推荐强制使用的 curl -w 指标格式串。 */
export const REQUIRED_CURL_WRITE_OUT =
	"http_code=%{http_code} size_download=%{size_download} remote_ip=%{remote_ip} time_total=%{time_total}";

const POSITIVE_FINDING_KINDS = new Set<string>(["vuln", "bypass", "cred", "loot"]);

const META_ENVELOPE_KEYS = new Set<string>([
	"detail",
	"error",
	"err",
	"errmsg",
	"error_msg",
	"error_message",
	"message",
	"msg",
	"code",
	"errcode",
	"status",
	"statuscode",
	"status_code",
	"statustext",
	"status_text",
	"ok",
	"success",
	"timestamp",
	"time",
	"ts",
	"requestid",
	"request_id",
	"traceid",
	"trace_id",
	"path",
	"url",
	"title",
	"type",
]);

const ERROR_TEXT_RE =
	/\b(?:not\s+found|page\s+not\s+found|route\s+not\s+found|cannot\s+(?:get|post|put|delete|patch)\s+\/|unauthorized|forbidden|access\s+denied|permission\s+denied|method\s+not\s+allowed|bad\s+request|invalid\s+(?:token|session|credentials?|request|route|path)|missing\s+(?:token|auth|parameter)|please\s+log\s*in|unauthenticated|session\s+expired|internal\s+server\s+error)\b|找不到此頁面|找不到此页面|页面不存在|頁面不存在|未登录|未登入|无权限|無權限|NEXT_HTTP_ERROR_FALLBACK/i;

const SOFT_404_MARKER_RE =
	/NEXT_HTTP_ERROR_FALLBACK|找不到此頁面|找不到此页面|<title>\s*404\b|404\s+not\s+found|page\s+not\s+found|route\s+not\s+found/i;

const SUBSTANTIVE_PROOF_RE =
	/(?:flag|ctf)\{[^}\s]{2,}\}|uid=\d+\([^)]+\)|root:x:0:0:|-----BEGIN [A-Z0-9 ]+ KEY-----|SQLSTATE\[|syntax\s+error\s+near|[A-Z0-9_]{3,}(?:PASSWORD|SECRET|TOKEN|KEY|HASH)\s*=\s*\S+|Bearer\s+[A-Za-z0-9._-]{12,}/i;

const SECURITY_PROOF_HEADER_RE =
	/^(?:Set-Cookie|Authorization|Proxy-Authorization|X-Api-Key|X-Auth-Token|X-Session-Token|X-Access-Token|X-Debug-[A-Za-z0-9-]+|Access-Control-Allow-Credentials)\s*:\s*\S+/im;

export interface ResponseSnapshot {
	statusCode?: number;
	body?: string;
	bodyBytes?: number;
	bodySha256?: string;
	bodyMd5?: string;
	headers?: Record<string, string>;
}

export interface PositiveEvidenceGateInput {
	kind: FactKind | "bypass" | string;
	title?: string;
	detail?: string;
	output?: string;
	response?: ResponseSnapshot;
	baseline?: ResponseSnapshot | ResponseSnapshot[];
	requireBusinessPayload?: boolean;
	minBodyBytes?: number;
}

export interface PositiveEvidenceGateResult {
	ok: boolean;
	falsePositive: boolean;
	reason?: string;
	reasons: string[];
	suggestedKind?: "note";
	recommendedAction: "accept" | "downgrade_to_note" | "require_verification";
	matchedSignals: string[];
}

/**
 * 计算响应体摘要哈希（支持 sha256 与 md5）。
 */
export function computeBodyHash(body: string, algo: "sha256" | "md5" = "sha256"): string {
	return createHash(algo).update(String(body ?? ""), "utf8").digest("hex");
}

function extractHttpStatusFromOutput(text: string): number | undefined {
	const raw = String(text ?? "");
	const httpLine = /\bHTTP\/\d(?:\.\d)?\s+(\d{3})\b/i.exec(raw);
	if (httpLine?.[1]) return Number(httpLine[1]);
	const metricLine = /\bhttp_code\s*[:=]\s*(\d{3})\b/i.exec(raw);
	if (metricLine?.[1]) return Number(metricLine[1]);
	return undefined;
}

function extractHttpBodyFromOutput(text: string): string {
	const raw = String(text ?? "");
	if (!raw) return "";
	const norm = raw.replace(/\r\n/g, "\n");
	if (/^HTTP\/\d(?:\.\d)?\s+\d{3}/i.test(norm.trimStart())) {
		const sepIdx = norm.indexOf("\n\n");
		if (sepIdx >= 0) {
			return norm.slice(sepIdx + 2).trim();
		}
		// 仅含状态行与响应头时无正文
		const lines = norm
			.split("\n")
			.map((l) => l.trim())
			.filter(Boolean);
		if (lines.every((l) => /^HTTP\/\d/i.test(l) || /^[A-Za-z0-9-]+:\s*/.test(l))) {
			return "";
		}
	}
	return raw.trim();
}

function isNonEmptyBusinessValue(val: unknown): boolean {
	if (val === null || val === undefined || val === false) return false;
	if (typeof val === "string") {
		const t = val.trim();
		if (!t) return false;
		if (ERROR_TEXT_RE.test(t)) return false;
		return true;
	}
	if (typeof val === "number") return Number.isFinite(val);
	if (typeof val === "boolean") return val;
	if (Array.isArray(val)) return val.length > 0 && val.some((item) => isNonEmptyBusinessValue(item));
	if (typeof val === "object") {
		const entries = Object.entries(val as Record<string, unknown>);
		if (entries.length === 0) return false;
		return entries.some(([k, v]) => !META_ENVELOPE_KEYS.has(k.toLowerCase()) && isNonEmptyBusinessValue(v));
	}
	return false;
}

function tryParseJsonBody(body: string): { parsed: boolean; value?: unknown } {
	const t = String(body ?? "").trim();
	if (!t || (t[0] !== "{" && t[0] !== "[")) return { parsed: false };
	try {
		return { parsed: true, value: JSON.parse(t) };
	} catch {
		return { parsed: false };
	}
}

/**
 * 判断响应正文是否包含实质业务数据或高置信度漏洞实锤（排除空壳与错误信封）。
 */
export function hasSubstantiveBusinessData(body: string): boolean {
	const trimmed = String(body ?? "").trim();
	if (!trimmed) return false;
	if (SOFT_404_MARKER_RE.test(trimmed)) return false;
	if (SUBSTANTIVE_PROOF_RE.test(trimmed)) return true;

	const jsonRes = tryParseJsonBody(trimmed);
	if (jsonRes.parsed) {
		const val = jsonRes.value;
		if (Array.isArray(val)) {
			return val.length > 0 && val.some((item) => isNonEmptyBusinessValue(item));
		}
		if (val && typeof val === "object") {
			const obj = val as Record<string, unknown>;
			if (obj.ok === false || obj.success === false) return false;
			if (typeof obj.error === "string" && obj.error.trim().length > 0) return false;
			if (typeof obj.detail === "string" && ERROR_TEXT_RE.test(obj.detail)) return false;
			if (typeof obj.message === "string" && ERROR_TEXT_RE.test(obj.message)) return false;
			if (typeof obj.msg === "string" && ERROR_TEXT_RE.test(obj.msg)) return false;
			if (typeof obj.code === "number" && (obj.code === 401 || obj.code === 403 || obj.code === 404 || obj.code >= 500)) {
				return false;
			}
			for (const [k, v] of Object.entries(obj)) {
				const lk = k.toLowerCase();
				if (lk === "data" || lk === "result" || lk === "items" || lk === "records" || lk === "list" || lk === "user") {
					if (isNonEmptyBusinessValue(v)) return true;
					continue;
				}
				if (!META_ENVELOPE_KEYS.has(lk) && isNonEmptyBusinessValue(v)) {
					return true;
				}
			}
			return false;
		}
		return false;
	}

	const bytes = Buffer.byteLength(trimmed, "utf8");
	if (bytes < 64) {
		// 极短非 JSON 正文需避开空 HTML 壳、纯错误文本与低信息熵模板
		if (ERROR_TEXT_RE.test(trimmed)) return false;
		if (/^<(?:!doctype|html|head|body|div|span|p|h1)[^>]*>[\s\S]*<\/(?:html|body|div|span|p|h1)>$/i.test(trimmed)) {
			const stripped = trimmed.replace(/<[^>]+>/g, "").trim();
			if (!stripped || stripped.length < 16 || ERROR_TEXT_RE.test(stripped)) return false;
		}
		if (LOW_ENTROPY_BOILERPLATE_RE.test(trimmed) || PUNCTUATION_ONLY_RE.test(trimmed)) return false;
		return false;
	}

	return !ERROR_TEXT_RE.test(trimmed.slice(0, 512));
}

/**
 * 识别微小错误壳、Soft-404 外壳或 `<64B` 空壳响应（Issue #24 / NW-04）。
 */
export function isTinyErrorEnvelope(
	body: string,
	statusCode?: number,
	minBytes = 64,
	explicitBodyBytes?: number,
): { isEnvelope: boolean; signal?: string; reason?: string } {
	const trimmed = String(body ?? "").trim();
	const actualBytes =
		typeof explicitBodyBytes === "number" && Number.isFinite(explicitBodyBytes) && explicitBodyBytes >= 0
			? explicitBodyBytes
			: Buffer.byteLength(trimmed, "utf8");

	if (actualBytes === 0) {
		return {
			isEnvelope: true,
			signal: "empty_body_shell",
			reason: `响应体为空 (0B${statusCode ? `, HTTP ${statusCode}` : ""})，缺乏实质业务证据`,
		};
	}

	if (SOFT_404_MARKER_RE.test(trimmed)) {
		return {
			isEnvelope: true,
			signal: "soft_404_marker",
			reason: "响应命中 Soft-404 / NEXT_HTTP_ERROR_FALLBACK 特征，属于误报外壳",
		};
	}

	const jsonRes = tryParseJsonBody(trimmed);
	if (jsonRes.parsed) {
		const val = jsonRes.value;
		if (
			val === null ||
			(Array.isArray(val) && val.length === 0) ||
			(typeof val === "object" && !Array.isArray(val) && Object.keys(val as Record<string, unknown>).length === 0)
		) {
			return {
				isEnvelope: true,
				signal: "empty_json_shell",
				reason: `响应体为空 JSON 壳 (${actualBytes}B)，不含业务数据`,
			};
		}
		if (val && typeof val === "object" && !Array.isArray(val)) {
			const obj = val as Record<string, unknown>;
			const keys = Object.keys(obj);
			const nonMetaKeys = keys.filter((k) => !META_ENVELOPE_KEYS.has(k.toLowerCase()));
			const hasRealBusinessField = nonMetaKeys.some((k) => isNonEmptyBusinessValue(obj[k]));
			const dataVal = obj.data ?? obj.result ?? obj.items;
			const hasNonEmptyData = dataVal !== undefined && isNonEmptyBusinessValue(dataVal);
			const valuesText = keys
				.map((k) => (typeof obj[k] === "string" ? String(obj[k]) : ""))
				.filter(Boolean)
				.join(" ");

			if (
				!hasRealBusinessField &&
				!hasNonEmptyData &&
				(ERROR_TEXT_RE.test(valuesText) ||
					obj.ok === false ||
					obj.success === false ||
					(typeof obj.code === "number" && (obj.code === 401 || obj.code === 403 || obj.code === 404 || obj.code >= 500)))
			) {
				return {
					isEnvelope: true,
					signal: "tiny_error_json_envelope",
					reason: `响应为错误信封 (${actualBytes}B, ${trimmed.slice(0, 80)})，缺乏业务数据字段`,
				};
			}

			if (actualBytes < minBytes && !hasRealBusinessField && !hasNonEmptyData) {
				return {
					isEnvelope: true,
					signal: "tiny_shell_under_64b",
					reason: `响应为 <${minBytes}B 微小信封壳 (${actualBytes}B)，仅含状态/元信息无实质业务数据`,
				};
			}
		}
	}

	if (actualBytes < minBytes) {
		if (ERROR_TEXT_RE.test(trimmed)) {
			return {
				isEnvelope: true,
				signal: "tiny_error_text",
				reason: `响应为 <${minBytes}B 错误文本壳 (${actualBytes}B)`,
			};
		}
		if (LOW_ENTROPY_BOILERPLATE_RE.test(trimmed) || PUNCTUATION_ONLY_RE.test(trimmed)) {
			return {
				isEnvelope: true,
				signal: "tiny_boilerplate_shell",
				reason: `响应为 <${minBytes}B 低熵空壳 (${actualBytes}B)`,
			};
		}
		if (
			statusCode === 200 &&
			!hasSubstantiveBusinessData(trimmed)
		) {
			return {
				isEnvelope: true,
				signal: "http_200_tiny_shell",
				reason: `仅凭 HTTP 200 + <${minBytes}B 微小响应壳 (${actualBytes}B) 不足以证实阳性结论，缺少业务数据`,
			};
		}
	}

	return { isEnvelope: false };
}

function hashesForSnapshot(snap: ResponseSnapshot): { sha256?: string; md5?: string; normSha256?: string } {
	const sha256 = snap.bodySha256 ? snap.bodySha256.trim().toLowerCase() : undefined;
	const md5 = snap.bodyMd5 ? snap.bodyMd5.trim().toLowerCase() : undefined;
	if (snap.body !== undefined) {
		const rawBody = String(snap.body);
		return {
			sha256: sha256 || computeBodyHash(rawBody, "sha256"),
			md5: md5 || computeBodyHash(rawBody, "md5"),
			normSha256: computeBodyHash(rawBody.trim(), "sha256"),
		};
	}
	return { sha256, md5 };
}

/**
 * #24 (NW-04) 正向 vuln / bypass / cred / loot 结论假阳性复核门禁：
 * - 拦截仅凭 HTTP 200 + 微小错误壳（如 `{"detail":"Not Found"}`、`<64B` 空壳）通过的误报；
 * - 拦截与未授权/404 基线响应体哈希完全一致的假阳性；
 * - 失败时返回 `falsePositive: true` 并建议以 `note` 记账，阻断误报升格。
 */
export function evaluatePositiveEvidenceGate(input: PositiveEvidenceGateInput): PositiveEvidenceGateResult {
	const normKind = String(input?.kind ?? "").trim().toLowerCase();
	if (!POSITIVE_FINDING_KINDS.has(normKind)) {
		return {
			ok: true,
			falsePositive: false,
			reasons: [],
			recommendedAction: "accept",
			matchedSignals: [],
		};
	}

	const minBodyBytes =
		typeof input.minBodyBytes === "number" && Number.isFinite(input.minBodyBytes) && input.minBodyBytes > 0
			? Math.floor(input.minBodyBytes)
			: 64;

	const rawOutput = String(input.output ?? "");
	const derivedStatus = input.response?.statusCode ?? extractHttpStatusFromOutput(rawOutput);
	const derivedBody =
		input.response?.body !== undefined ? String(input.response.body) : extractHttpBodyFromOutput(rawOutput);
	const derivedBodyBytes =
		input.response?.bodyBytes !== undefined
			? input.response.bodyBytes
			: derivedBody !== "" || input.response?.body !== undefined
				? Buffer.byteLength(derivedBody.trim(), "utf8")
				: undefined;

	const candidateSnap: ResponseSnapshot = {
		statusCode: derivedStatus,
		body: derivedBody,
		bodyBytes: derivedBodyBytes,
		bodySha256: input.response?.bodySha256,
		bodyMd5: input.response?.bodyMd5,
		headers: input.response?.headers,
	};

	const reasons: string[] = [];
	const matchedSignals: string[] = [];

	// 1. 负向对照基线哈希一致性校验（与未授权 / 404 基线逐字节一致则必为假阳性）
	const baselines = Array.isArray(input.baseline)
		? input.baseline
		: input.baseline
			? [input.baseline]
			: [];
	if (baselines.length > 0) {
		const candHashes = hashesForSnapshot(candidateSnap);
		for (const base of baselines) {
			if (!base) continue;
			const baseHashes = hashesForSnapshot(base);
			const shaMatched = Boolean(candHashes.sha256 && baseHashes.sha256 && candHashes.sha256 === baseHashes.sha256);
			const normShaMatched = Boolean(
				candHashes.normSha256 && baseHashes.normSha256 && candHashes.normSha256 === baseHashes.normSha256,
			);
			const md5Matched = Boolean(candHashes.md5 && baseHashes.md5 && candHashes.md5 === baseHashes.md5);
			if (shaMatched || normShaMatched || md5Matched) {
				matchedSignals.push("baseline_body_hash_identical");
				reasons.push(
					`响应体哈希与未授权/404 负向对照基线完全一致 (${candHashes.sha256?.slice(0, 16) ?? candHashes.md5 ?? "matched"})，疑似路由兜底或假阳性`,
				);
				break;
			}
		}
	}

	// 2. 微小错误壳与 HTTP 200 <64B 空壳校验
	// 若调用方未显式提供 response 且 rawOutput 为 curl -I 这类无正文但含高价值安全响应头（如 Set-Cookie/Authorization/X-Debug-*）的输出，不误判为 0B 空壳
	const isHeadOnlyWithSecurityHeader =
		input.response === undefined &&
		derivedBody === "" &&
		SECURITY_PROOF_HEADER_RE.test(rawOutput) &&
		!rawOutput.replace(/\r\n/g, "\n").includes("\n\n");

	const shouldCheckEnvelope =
		!isHeadOnlyWithSecurityHeader &&
		(input.response !== undefined ||
			input.requireBusinessPayload === true ||
			derivedStatus !== undefined ||
			tryParseJsonBody(derivedBody).parsed ||
			SOFT_404_MARKER_RE.test(derivedBody) ||
			LOW_ENTROPY_BOILERPLATE_RE.test(derivedBody));

	if (shouldCheckEnvelope) {
		const envVerdict = isTinyErrorEnvelope(derivedBody, derivedStatus, minBodyBytes, derivedBodyBytes);
		if (envVerdict.isEnvelope) {
			matchedSignals.push(envVerdict.signal ?? "tiny_error_envelope");
			if (envVerdict.reason) reasons.push(envVerdict.reason);
		} else if (
			input.requireBusinessPayload === true &&
			derivedStatus === 200 &&
			!hasSubstantiveBusinessData(derivedBody)
		) {
			matchedSignals.push("missing_business_payload");
			reasons.push("HTTP 200 响应缺少实质业务数据字段，须复核确认而非直接升格阳性");
		}
	}

	if (reasons.length > 0) {
		return {
			ok: false,
			falsePositive: true,
			reason: `假阳性复核拦截 (${normKind} -> 建议降级为 note): ${reasons.join("；")}`,
			reasons,
			suggestedKind: "note",
			recommendedAction: "downgrade_to_note",
			matchedSignals,
		};
	}

	return {
		ok: true,
		falsePositive: false,
		reasons: [],
		recommendedAction: "accept",
		matchedSignals,
	};
}

// ----------------------------------------------------------------------------
// #26 (NW-06) 交付真实性校验 validateDeliverableRealism(text, targetHost)
// ----------------------------------------------------------------------------

export type DeliverableViolation =
	| "placeholder_bracket"
	| "unexpanded_target_literal"
	| "script_only_no_status"
	| "missing_probe_metrics"
	| "target_host_mismatch";

export interface DeliverableRealismResult {
	ok: boolean;
	reject: boolean;
	reasons: string[];
	violations: DeliverableViolation[];
	matchedPlaceholders: string[];
	matchedLiterals: string[];
}

const BRACKET_PLACEHOLDER_RE = /\[[A-Z_]{2,}\]/g;
const BRACKET_PLACEHOLDER_TEST_RE = /\[[A-Z_]{2,}\]/;
const UNEXPANDED_LITERAL_RE =
	/(?:\$\{?(?:U|URL|TARGET|HOST|DOMAIN)\}?|\b(?:TARGET|HOST|DOMAIN)\b)/g;
const SCRIPT_FRAGMENT_RE =
	/(?:^|\n)\s*(?:#!\/bin\/|for\s+\w+\s+in\b|while\s+|if\s+\[|[A-Z_][A-Z0-9_]*\s*=\s*["']?https?:\/\/|[A-Z_][A-Z0-9_]*\s*=\s*["']?\$|curl\s+-[a-zA-Z]|python3?\s+-c\b)/m;
const REAL_HTTP_STATUS_RE =
	/(?:HTTP\/\d(?:\.\d)?\s+[1-5]\d{2}\b|\bhttp_code\s*[:=]\s*[1-5]\d{2}\b|"http_code"\s*:\s*[1-5]\d{2}\b|\bstatus(?:_code)?\s*[:=]\s*[1-5]\d{2}\b)/i;
const REAL_PROBE_METRIC_RE =
	/(?:\bremote_ip\s*[:=]\s*[0-9a-fA-F:.]+|"remote_ip"\s*:\s*"[0-9a-fA-F:.]+"|\bcf[-_]ray\s*[:=]\s*[A-Za-z0-9-]+|"cf_ray"\s*:\s*"[A-Za-z0-9-]+"|\bsize_download\s*[:=]\s*\d+|"size_download"\s*:\s*\d+|\btime_total\s*[:=]\s*\d+(?:\.\d+)?|"time_total"\s*:\s*\d+(?:\.\d+)?|\bserver\s*[:=]\s*[A-Za-z0-9._/-]+|"server"\s*:\s*"[A-Za-z0-9._/-]+")/i;

function normalizeTargetHostName(raw: string | undefined): string {
	const s = String(raw ?? "").trim();
	if (!s) return "";
	try {
		const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `http://${s}`;
		return new URL(withScheme).hostname.toLowerCase();
	} catch {
		return s.replace(/^https?:\/\//i, "").split(/[/:?#]/)[0]?.toLowerCase() ?? "";
	}
}

/**
 * #26 (NW-06) 校验子代理回包真实性：
 * 拦截含 `\[[A-Z_]{2,}\]` 占位符、未展开的字面量 `TARGET`/`HOST`/`DOMAIN`/`$U`、
 * 仅脚本无状态码、缺少实际探针指标或目标主机错配的模板化回包。
 */
export function validateDeliverableRealism(text: string, targetHost?: string): DeliverableRealismResult {
	const raw = String(text ?? "");
	const trimmed = raw.trim();
	const reasons: string[] = [];
	const violations: DeliverableViolation[] = [];
	const matchedPlaceholders: string[] = [];
	const matchedLiterals: string[] = [];

	if (!trimmed) {
		return {
			ok: false,
			reject: true,
			reasons: ["回包内容为空，拒绝落账"],
			violations: ["missing_probe_metrics"],
			matchedPlaceholders,
			matchedLiterals,
		};
	}

	// 1. 拦截方括号大写占位符 \[[A-Z_]{2,}\]
	const phHits = [...new Set(raw.match(BRACKET_PLACEHOLDER_RE) ?? [])];
	if (phHits.length > 0) {
		matchedPlaceholders.push(...phHits);
		violations.push("placeholder_bracket");
		reasons.push(`回包含未填充占位符: ${phHits.slice(0, 6).join(", ")}`);
	}

	// 2. 拦截未展开字面量 TARGET / HOST / DOMAIN / $U
	const litHits = [...new Set(raw.match(UNEXPANDED_LITERAL_RE) ?? [])];
	if (litHits.length > 0) {
		matchedLiterals.push(...litHits);
		violations.push("unexpanded_target_literal");
		reasons.push(`回包含未展开的目标字面量/变量: ${litHits.slice(0, 6).join(", ")}`);
	}

	const hasHttpStatus = REAL_HTTP_STATUS_RE.test(raw);
	const hasProbeMetrics = REAL_PROBE_METRIC_RE.test(raw);
	const looksLikeScript = SCRIPT_FRAGMENT_RE.test(raw);

	// 3. 仅脚本或变量赋值，没有 HTTP/ 状态行或实际状态码
	if (looksLikeScript && !hasHttpStatus) {
		violations.push("script_only_no_status");
		reasons.push("回包仅含脚本/命令模板而无真实 HTTP 状态码输出，判定为未执行");
	}

	// 4. 缺少实际探针指标（remote_ip / cf_ray / server / size_download / time_total 或实际状态码）
	if (!hasProbeMetrics || !hasHttpStatus) {
		if (!violations.includes("script_only_no_status") || !hasProbeMetrics) {
			violations.push("missing_probe_metrics");
			reasons.push("缺少实际网络探针观测指标（需包含真实 HTTP 状态码及 remote_ip / cf_ray / server / size_download / time_total）");
		}
	}

	// 5. 若提供 targetHost，校验正文 URL 未指向明显偏离的错配主机
	const normTargetHost = normalizeTargetHostName(targetHost);
	if (normTargetHost) {
		const urlMatches = raw.match(/https?:\/\/[^\s"'<>`)\]]+/gi) ?? [];
		if (urlMatches.length > 0) {
			const hosts = new Set<string>();
			for (const u of urlMatches) {
				try {
					hosts.add(new URL(u.replace(/[),.;]+$/, "")).hostname.toLowerCase());
				} catch {
					/* ignore */
				}
			}
			const hostMatchesTarget = [...hosts].some(
				(h) => h === normTargetHost || h.endsWith(`.${normTargetHost}`),
			);
			const textMentionsTarget = raw.toLowerCase().includes(normTargetHost);
			if (hosts.size > 0 && !hostMatchesTarget && !textMentionsTarget) {
				violations.push("target_host_mismatch");
				reasons.push(`回包 URL 主机 (${[...hosts].join(", ")}) 与授权目标主机 ${normTargetHost} 不一致`);
			}
		}
	}

	return {
		ok: violations.length === 0,
		reject: violations.length > 0,
		reasons,
		violations,
		matchedPlaceholders,
		matchedLiterals,
	};
}

// ----------------------------------------------------------------------------
// #39 (NW-19) 子代理命中证据必需字段校验
// ----------------------------------------------------------------------------

export interface HitEvidenceMetrics {
	http_code?: number;
	size_download?: number;
	remote_ip?: string;
	cf_ray?: string;
	server?: string;
	time_total?: number;
}

export interface HitEvidenceValidationResult {
	ok: boolean;
	missingFields: string[];
	metrics: HitEvidenceMetrics;
	edgeOrOrigin: "cloudflare_edge" | "origin_or_proxy" | "unknown";
	reason?: string;
}

const VALID_IP_RE = /^(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})$/;

function toFiniteNumber(v: unknown): number | undefined {
	if (typeof v === "number" && Number.isFinite(v)) return v;
	if (typeof v === "string" && v.trim() !== "") {
		const n = Number(v.trim().replace(/s$/i, ""));
		if (Number.isFinite(n)) return n;
	}
	return undefined;
}

function cleanStringField(v: unknown): string | undefined {
	if (typeof v !== "string") return undefined;
	const t = v.trim();
	if (!t || BRACKET_PLACEHOLDER_TEST_RE.test(t) || /^(?:n\/a|none|null|unknown|-)$/i.test(t)) return undefined;
	return t;
}

/**
 * 从结构化对象或原始 curl -D - -w 输出中提取命中证据必需指标。
 */
export function extractHitEvidenceMetrics(raw: string | Record<string, unknown>): HitEvidenceMetrics {
	if (raw && typeof raw === "object") {
		const obj = raw as Record<string, unknown>;
		return {
			http_code: toFiniteNumber(obj.http_code ?? obj.httpCode ?? obj.status_code ?? obj.statusCode),
			size_download: toFiniteNumber(obj.size_download ?? obj.sizeDownload ?? obj.bytes),
			remote_ip: cleanStringField(obj.remote_ip ?? obj.remoteIp),
			cf_ray: cleanStringField(obj.cf_ray ?? obj.cfRay ?? obj["cf-ray"]),
			server: cleanStringField(obj.server ?? obj.Server),
			time_total: toFiniteNumber(obj.time_total ?? obj.timeTotal),
		};
	}

	const text = String(raw ?? "");
	const httpCodeMatch =
		/\bhttp_code\s*[:=]\s*(\d{3})\b/i.exec(text) ??
		/\bHTTP\/\d(?:\.\d)?\s+(\d{3})\b/i.exec(text);
	const sizeMatch = /\bsize_download\s*[:=]\s*(\d+)\b/i.exec(text);
	const ipMatch = /\bremote_ip\s*[:=]\s*([0-9a-fA-F:.]+)\b/i.exec(text);
	const cfRayMatch = /\bcf[-_]ray\s*[:=]\s*([A-Za-z0-9-]+)\b/i.exec(text);
	const serverMatch = /(?:^|\n|\s)server\s*[:=]\s*([^\r\n,;]+)/i.exec(text);
	const timeMatch = /\btime_total\s*[:=]\s*(\d+(?:\.\d+)?)s?\b/i.exec(text);

	return {
		http_code: httpCodeMatch?.[1] ? Number(httpCodeMatch[1]) : undefined,
		size_download: sizeMatch?.[1] ? Number(sizeMatch[1]) : undefined,
		remote_ip: cleanStringField(ipMatch?.[1]),
		cf_ray: cleanStringField(cfRayMatch?.[1]),
		server: cleanStringField(serverMatch?.[1]),
		time_total: timeMatch?.[1] ? Number(timeMatch[1]) : undefined,
	};
}

/**
 * #39 (NW-19) 校验子代理命中证据必需字段：
 * 必需包含 `http_code`、`size_download`、`remote_ip`、`cf_ray` 或 `server`、`time_total`。
 */
export function validateHitEvidenceFields(
	raw: string | Record<string, unknown> | HitEvidenceMetrics,
): HitEvidenceValidationResult {
	const metrics = extractHitEvidenceMetrics(raw as string | Record<string, unknown>);
	const missingFields: string[] = [];

	if (
		metrics.http_code === undefined ||
		!Number.isInteger(metrics.http_code) ||
		metrics.http_code < 100 ||
		metrics.http_code > 599
	) {
		missingFields.push("http_code");
	}
	if (metrics.size_download === undefined || metrics.size_download < 0) {
		missingFields.push("size_download");
	}
	if (!metrics.remote_ip || !VALID_IP_RE.test(metrics.remote_ip)) {
		missingFields.push("remote_ip");
	}
	if (!metrics.cf_ray && !metrics.server) {
		missingFields.push("cf_ray|server");
	}
	if (metrics.time_total === undefined || metrics.time_total < 0) {
		missingFields.push("time_total");
	}

	const isCloudflare =
		Boolean(metrics.cf_ray) || Boolean(metrics.server && /cloudflare/i.test(metrics.server));
	const edgeOrOrigin: HitEvidenceValidationResult["edgeOrOrigin"] =
		missingFields.length > 0
			? "unknown"
			: isCloudflare
				? "cloudflare_edge"
				: "origin_or_proxy";

	if (missingFields.length > 0) {
		return {
			ok: false,
			missingFields,
			metrics,
			edgeOrOrigin,
			reason: `子代理命中证据缺少必需字段: ${missingFields.join(", ")}（须附带 curl -w 指标与 cf_ray/server 响应头）`,
		};
	}

	return {
		ok: true,
		missingFields: [],
		metrics,
		edgeOrOrigin,
	};
}

// ----------------------------------------------------------------------------
// #42 (NW-22) 原始响应/日志落盘至 .nuwa/evidence/<factId>.log 与 evidenceRef 指针
// ----------------------------------------------------------------------------

export interface SaveEvidenceLogInput {
	factId: string;
	command?: string;
	output?: string;
	rawResponse?: string;
	headers?: Record<string, string>;
	metadata?: Record<string, unknown>;
	ts?: string;
}

export interface SavedEvidenceLog {
	factId: string;
	/** 相对项目根路径指针，格式为 `.nuwa/evidence/<factId>.log` */
	evidenceRef: string;
	absolutePath: string;
	bytes: number;
	sha256: string;
}

function sanitizeFactFileId(factId: string): string {
	const clean = String(factId ?? "")
		.trim()
		.replace(/[^a-zA-Z0-9._-]/g, "_");
	if (!clean || clean === "." || clean === "..") {
		throw new Error(`非法 factId，无法落盘证据日志: ${factId}`);
	}
	return clean;
}

/**
 * #42 (NW-22) 将原始响应/执行日志脱敏后原子落盘到 `<root>/.nuwa/evidence/<factId>.log`，
 * 并返回相对路径指针 `evidenceRef`（`.nuwa/evidence/<factId>.log`）。
 */
export function saveFactEvidenceLog(root: string, input: SaveEvidenceLogInput): SavedEvidenceLog {
	const normRoot = resolve(root || process.cwd());
	const safeId = sanitizeFactFileId(input.factId);
	const evDir = join(normRoot, ".nuwa", "evidence");
	mkdirSync(evDir, { recursive: true, mode: 0o700 });
	try {
		chmodSync(evDir, 0o700);
	} catch {
		/* 非 POSIX 忽略 */
	}

	const ts = input.ts && input.ts.trim() ? input.ts.trim() : new Date().toISOString();
	const sections: string[] = [
		`=== NUWA EVIDENCE LOG ===`,
		`fact_id: ${safeId}`,
		`timestamp: ${ts}`,
	];
	if (input.command) {
		sections.push(`command: ${safeRedact(String(input.command), normRoot)}`);
	}
	if (input.metadata && Object.keys(input.metadata).length > 0) {
		sections.push(`metadata: ${safeRedact(JSON.stringify(input.metadata), normRoot)}`);
	}
	if (input.headers && Object.keys(input.headers).length > 0) {
		sections.push(`--- HEADERS ---`);
		for (const [k, v] of Object.entries(input.headers)) {
			sections.push(`${k}: ${safeRedact(String(v), normRoot)}`);
		}
	}
	if (input.output !== undefined) {
		sections.push(`--- OUTPUT ---`);
		sections.push(safeRedact(String(input.output), normRoot));
	}
	if (input.rawResponse !== undefined && input.rawResponse !== input.output) {
		sections.push(`--- RAW RESPONSE ---`);
		sections.push(safeRedact(String(input.rawResponse), normRoot));
	}

	const content = `${sections.join("\n")}\n`;
	const fileName = `${safeId}.log`;
	const absolutePath = join(evDir, fileName);
	const tmpPath = `${absolutePath}.tmp-${process.pid}-${Date.now()}-${atomicLedgerSeq++}`;
	try {
		writeFileSync(tmpPath, content, { encoding: "utf8", mode: 0o600 });
		try {
			chmodSync(tmpPath, 0o600);
		} catch {
			/* ignore */
		}
		renameSync(tmpPath, absolutePath);
		try {
			chmodSync(absolutePath, 0o600);
		} catch {
			/* ignore */
		}
	} catch (err) {
		try {
			unlinkSync(tmpPath);
		} catch {
			/* ignore */
		}
		throw err;
	}

	return {
		factId: safeId,
		evidenceRef: `.nuwa/evidence/${fileName}`,
		absolutePath,
		bytes: Buffer.byteLength(content, "utf8"),
		sha256: createHash("sha256").update(content, "utf8").digest("hex"),
	};
}

/**
 * 安全读取 `<root>/.nuwa/evidence/<factId>.log`（严格防目录穿越）。
 */
export function readFactEvidenceLog(root: string, evidenceRefOrFactId: string): string | null {
	const normRoot = resolve(root || process.cwd());
	const evDir = resolve(join(normRoot, ".nuwa", "evidence"));
	const rawRef = String(evidenceRefOrFactId ?? "").trim();
	if (!rawRef) return null;

	const candidate =
		rawRef.startsWith(".nuwa/evidence/") || rawRef.startsWith("./.nuwa/evidence/")
			? resolve(normRoot, rawRef)
			: resolve(evDir, rawRef.endsWith(".log") ? rawRef : `${rawRef}.log`);

	if (!candidate.startsWith(`${evDir}/`) && candidate !== evDir) {
		return null;
	}
	if (!existsSync(candidate)) return null;
	try {
		return readFileSync(candidate, "utf8");
	} catch {
		return null;
	}
}

// ----------------------------------------------------------------------------
// #51 (NW-31) 结构化 AgentResult 类型与 parseAgentResult(raw) 解析器
// ----------------------------------------------------------------------------

export type AgentResultStatus = "ok" | "hit" | "confirmed" | "rejected" | "blocked" | "negative" | "error";

export interface AgentEvidenceItem {
	cmd: string;
	http_code?: number;
	size_download?: number;
	remote_ip?: string;
	cf_ray?: string;
	server?: string;
	time_total?: number;
	body_sha256?: string;
	snippet?: string;
}

export interface AgentResult {
	status: AgentResultStatus | string;
	target: string;
	evidence: AgentEvidenceItem[];
	blocked: boolean;
	summary: string;
	next: string;
	blockedReason?: string;
}

export interface ParseAgentResultOutcome {
	ok: boolean;
	format: "json" | "fenced_json" | "embedded_json" | "legacy_5line" | "invalid";
	result?: AgentResult;
	error?: string;
	warnings: string[];
}

function parseBlockedFlag(raw: unknown): { blocked: boolean; blockedReason?: string } {
	if (typeof raw === "boolean") return { blocked: raw };
	if (typeof raw === "string") {
		const t = raw.trim();
		if (!t || /^(?:无|none|no|false|null|n\/a|-)$/i.test(t)) {
			return { blocked: false };
		}
		return { blocked: true, blockedReason: t };
	}
	return { blocked: Boolean(raw) };
}

function normalizeEvidenceItem(rawItem: unknown): AgentEvidenceItem | null {
	if (!rawItem || typeof rawItem !== "object") return null;
	const obj = rawItem as Record<string, unknown>;
	const cmd = String(obj.cmd ?? obj.command ?? "").trim();
	const metrics = extractHitEvidenceMetrics(obj);
	const bodySha = cleanStringField(obj.body_sha256 ?? obj.bodySha256 ?? obj.sha256);
	const snippet = typeof obj.snippet === "string" && obj.snippet.trim() ? obj.snippet.trim() : undefined;

	return {
		cmd,
		...(metrics.http_code !== undefined ? { http_code: metrics.http_code } : {}),
		...(metrics.size_download !== undefined ? { size_download: metrics.size_download } : {}),
		...(metrics.remote_ip !== undefined ? { remote_ip: metrics.remote_ip } : {}),
		...(metrics.cf_ray !== undefined ? { cf_ray: metrics.cf_ray } : {}),
		...(metrics.server !== undefined ? { server: metrics.server } : {}),
		...(metrics.time_total !== undefined ? { time_total: metrics.time_total } : {}),
		...(bodySha !== undefined ? { body_sha256: bodySha } : {}),
		...(snippet !== undefined ? { snippet } : {}),
	};
}

function buildAgentResultFromObject(
	obj: Record<string, unknown>,
	format: "json" | "fenced_json" | "embedded_json",
): ParseAgentResultOutcome {
	const warnings: string[] = [];
	const hasCoreField =
		typeof obj.status === "string" ||
		typeof obj.summary === "string" ||
		Array.isArray(obj.evidence);

	if (!hasCoreField) {
		return {
			ok: false,
			format: "invalid",
			error: "JSON 对象缺少 AgentResult 核心字段（需至少包含 status / summary / evidence）",
			warnings,
		};
	}

	const { blocked, blockedReason } = parseBlockedFlag(obj.blocked);
	const rawBlockedReason =
		typeof obj.blockedReason === "string" && obj.blockedReason.trim()
			? obj.blockedReason.trim()
			: blockedReason;

	const status =
		typeof obj.status === "string" && obj.status.trim()
			? obj.status.trim()
			: blocked
				? "blocked"
				: "ok";
	const target = String(obj.target ?? "").trim();
	const summary = String(obj.summary ?? obj.conclusion ?? "").trim();
	const next = String(obj.next ?? obj.nextStep ?? "").trim();

	const evidenceRaw = Array.isArray(obj.evidence) ? obj.evidence : [];
	const evidence: AgentEvidenceItem[] = [];
	for (const item of evidenceRaw) {
		const norm = normalizeEvidenceItem(item);
		if (norm) evidence.push(norm);
	}

	if (evidence.length === 0 && !blocked) {
		warnings.push("evidence 数组为空");
	}
	for (let i = 0; i < evidence.length; i++) {
		const v = validateHitEvidenceFields(evidence[i]!);
		if (!v.ok) {
			warnings.push(`evidence[${i}] 缺少字段: ${v.missingFields.join(", ")}`);
		}
	}

	return {
		ok: true,
		format,
		result: {
			status,
			target,
			evidence,
			blocked,
			summary,
			next,
			...(rawBlockedReason ? { blockedReason: rawBlockedReason } : {}),
		},
		warnings,
	};
}

function extractBalancedJsonObjects(raw: string): string[] {
	const out: string[] = [];
	let depth = 0;
	let start = -1;
	let inString = false;
	let escaped = false;

	for (let i = 0; i < raw.length; i++) {
		const ch = raw[i]!;
		if (inString) {
			if (escaped) {
				escaped = false;
			} else if (ch === "\\") {
				escaped = true;
			} else if (ch === '"') {
				inString = false;
			}
			continue;
		}
		if (ch === '"') {
			inString = true;
			continue;
		}
		if (ch === "{") {
			if (depth === 0) start = i;
			depth++;
		} else if (ch === "}") {
			if (depth > 0) {
				depth--;
				if (depth === 0 && start >= 0) {
					out.push(raw.slice(start, i + 1));
					start = -1;
				}
			}
		}
	}
	return out;
}

function parseLegacyFiveLineResult(raw: string): ParseAgentResultOutcome | null {
	const conclusion = /(?:^|\n)\s*结论\s*[:：]\s*(.+)/.exec(raw)?.[1]?.trim();
	const evidenceLine = /(?:^|\n)\s*证据\s*[:：]\s*(.+)/.exec(raw)?.[1]?.trim();
	const cmdLine = /(?:^|\n)\s*命令\s*[:：]\s*(.+)/.exec(raw)?.[1]?.trim();
	const blockedLine = /(?:^|\n)\s*阻断\s*[:：]\s*(.+)/.exec(raw)?.[1]?.trim();
	const nextLine = /(?:^|\n)\s*下一步\s*[:：]\s*(.+)/.exec(raw)?.[1]?.trim();

	if (!conclusion || (!evidenceLine && !cmdLine && !blockedLine)) {
		return null;
	}

	const { blocked, blockedReason } = parseBlockedFlag(blockedLine ?? "");
	const metrics = extractHitEvidenceMetrics(`${evidenceLine ?? ""}\n${cmdLine ?? ""}`);
	const urlMatch = /https?:\/\/[^\s"'<>`]+/i.exec(`${cmdLine ?? ""} ${conclusion}`);
	const shaMatch = /\bbody_sha256\s*[:=]\s*([a-fA-F0-9]{64})\b/i.exec(evidenceLine ?? "");

	const status = blocked
		? "blocked"
		: /\bCONFIRMED\b/i.test(conclusion)
			? "confirmed"
			: /\bREJECTED\b/i.test(conclusion)
				? "rejected"
				: "ok";

	const evidence: AgentEvidenceItem[] =
		cmdLine || evidenceLine
			? [
					{
						cmd: cmdLine ?? "",
						...(metrics.http_code !== undefined ? { http_code: metrics.http_code } : {}),
						...(metrics.size_download !== undefined ? { size_download: metrics.size_download } : {}),
						...(metrics.remote_ip !== undefined ? { remote_ip: metrics.remote_ip } : {}),
						...(metrics.cf_ray !== undefined ? { cf_ray: metrics.cf_ray } : {}),
						...(metrics.server !== undefined ? { server: metrics.server } : {}),
						...(metrics.time_total !== undefined ? { time_total: metrics.time_total } : {}),
						...(shaMatch?.[1] ? { body_sha256: shaMatch[1] } : {}),
						...(evidenceLine ? { snippet: evidenceLine } : {}),
					},
				]
			: [];

	return {
		ok: true,
		format: "legacy_5line",
		result: {
			status,
			target: urlMatch?.[0] ?? "",
			evidence,
			blocked,
			summary: conclusion,
			next: nextLine ?? "",
			...(blockedReason ? { blockedReason } : {}),
		},
		warnings: ["检测到旧版 5 行文本格式，建议切换为标准 JSON AgentResult 回包"],
	};
}

/**
 * #51 (NW-31) 解析子代理结构化回包 `AgentResult`：
 * 兼容纯 JSON、Markdown fenced JSON（```json ... ```）、嵌入 JSON 及旧版 5 行摘要降级解析。
 */
export function parseAgentResult(raw: string | Record<string, unknown>): ParseAgentResultOutcome {
	if (raw && typeof raw === "object" && !Array.isArray(raw)) {
		return buildAgentResultFromObject(raw as Record<string, unknown>, "json");
	}

	const text = String(raw ?? "").trim();
	if (!text) {
		return { ok: false, format: "invalid", error: "回包为空", warnings: [] };
	}

	// 1. 纯 JSON 解析
	if (text.startsWith("{") && text.endsWith("}")) {
		try {
			const parsed = JSON.parse(text);
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
				return buildAgentResultFromObject(parsed as Record<string, unknown>, "json");
			}
		} catch {
			/* 回退到 fenced / embedded 解析 */
		}
	}

	// 2. Markdown fenced JSON（```json ... ``` 或 ``` ... ```）
	const fenceRe = /```(?:json|JSON)?\s*\r?\n([\s\S]*?)```/g;
	for (let m = fenceRe.exec(text); m !== null; m = fenceRe.exec(text)) {
		const block = (m[1] ?? "").trim();
		if (!block.startsWith("{")) continue;
		try {
			const parsed = JSON.parse(block);
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
				const out = buildAgentResultFromObject(parsed as Record<string, unknown>, "fenced_json");
				if (out.ok) return out;
			}
		} catch {
			/* 尝试下一个代码块 */
		}
	}

	// 3. 嵌入式 JSON 对象兜底（前后带说明文本或 Σ 尾注）
	const embeddedBlocks = extractBalancedJsonObjects(text);
	for (const block of embeddedBlocks) {
		try {
			const parsed = JSON.parse(block);
			if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
				const out = buildAgentResultFromObject(parsed as Record<string, unknown>, "embedded_json");
				if (out.ok) return out;
			}
		} catch {
			/* 忽略非 JSON 花括号片段 */
		}
	}

	// 4. 旧版 5 行契约兼容降级
	const legacy = parseLegacyFiveLineResult(text);
	if (legacy) return legacy;

	return {
		ok: false,
		format: "invalid",
		error: "无法解析为合法的 AgentResult JSON（也未匹配旧版 5 行回包格式）",
		warnings: [],
	};
}
