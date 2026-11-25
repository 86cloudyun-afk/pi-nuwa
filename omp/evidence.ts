/**
 * 执行账本证据复验（升级 3）与本地工具链探针（升级 5）。
 *
 * 约束：仅使用 import type 引用 ./types，严禁运行时 import ./nuwa。
 */
import { createHash } from "node:crypto";
import {
	accessSync,
	chmodSync,
	closeSync,
	constants,
	existsSync,
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
}

export interface VerifyEvidenceResult {
	ok: boolean;
	verified: boolean;
	reason?: string;
	matchedSeq?: number;
	matchedAgent?: string;
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

function readLockHolder(lockFile: string): { pid?: number; ts?: number; start?: string | null } | null {
	try {
		const raw = readFileSync(lockFile, "utf8").trim();
		if (!raw) return null;
		const parsed = JSON.parse(raw) as { pid?: number; ts?: number; start?: string | null };
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

	for (;;) {
		let fd = -1;
		try {
			fd = openSync(p, "wx", 0o600);
		} catch (err) {
			const code = (err as NodeJS.ErrnoException)?.code;
			if (code !== "EEXIST") throw err;

			const held = readLockHolder(p);
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
					recentlyCreated = Date.now() - statSync(p).mtimeMs < 250;
				} catch {
					recentlyCreated = false;
				}
				if (recentlyCreated && Date.now() < deadline) {
					sleepSync(backoff);
					backoff = Math.min(backoff * 2, 32);
					continue;
				}
			}

			try {
				unlinkSync(p);
			} catch {
				/* 已被其他写者回收 */
			}
			continue;
		}

		try {
			writeSync(fd, JSON.stringify({ pid: process.pid, ts: Date.now(), start: procStartTime(process.pid) }));
			closeSync(fd);
			fd = -1;
		} catch (writeErr) {
			if (fd >= 0) {
				try {
					closeSync(fd);
				} catch {
					/* ignore */
				}
			}
			try {
				unlinkSync(p);
			} catch {
				/* ignore */
			}
			throw writeErr;
		}

		heldLedgerLocks.add(p);
		try {
			return fn();
		} finally {
			heldLedgerLocks.delete(p);
			try {
				unlinkSync(p);
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
	if (!existsSync(baseDir)) return [];

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
				const st = statSync(full);
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
	const substantiveMode = requireSubstantive || normKind === "vuln" || normKind === "cred";

	const rawOut = String(input.output ?? "");
	const trimmedOut = rawOut.trim();
	const redactedRawOut = safeRedact(rawOut, normRoot);
	const redactedTrimmedOut = redactedRawOut.trim();

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
