/**
 * 执行账本证据复验（升级 3）与本地工具链探针（升级 5）。
 *
 * 约束：仅使用 import type 引用 ./nuwa，严禁运行时 import ./nuwa。
 */
import { createHash } from "node:crypto";
import {
	accessSync,
	constants,
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	renameSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";
import type { FactKind } from "./nuwa";

export interface ExecRecordInput {
	tool: string;
	command?: string;
	output: string;
	sessionId?: string;
}

export interface VerifyEvidenceInput {
	projectId: string;
	kind: FactKind | string;
	command?: string;
	output?: string;
	flagValue?: string;
	strict?: boolean;
}

export interface VerifyEvidenceResult {
	ok: boolean;
	verified: boolean;
	reason?: string;
}

export interface ToolchainCaps {
	available: string[];
	missing: string[];
	probedAt: string;
}

export interface ExecLedgerEntry {
	ts: string;
	tool: string;
	command?: string;
	sessionId?: string;
	sha1: string;
	normSha1: string;
	bytes: number;
	snippet: string;
}

const LEDGER_MAX_ENTRIES = 200;
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

interface MemoryLedgerRecord extends ExecLedgerEntry {
	rawOutput?: string;
}

const memoryRing = new Map<string, MemoryLedgerRecord[]>();
let atomicLedgerSeq = 0;

function sha1Hex(text: string): string {
	return createHash("sha1").update(text).digest("hex");
}

function ledgerFilePath(root: string): string {
	return join(resolve(root), ".nuwa", "exec-ledger.jsonl");
}

function buildSnippet(output: string): string {
	if (output.length <= SNIPPET_HEAD + SNIPPET_TAIL) {
		return output;
	}
	return `${output.slice(0, SNIPPET_HEAD)}\n...[truncated]...\n${output.slice(-SNIPPET_TAIL)}`;
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
				const parsed = JSON.parse(trimmed) as ExecLedgerEntry;
				if (parsed && typeof parsed.sha1 === "string" && typeof parsed.snippet === "string") {
					out.push(parsed);
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
	try {
		mkdirSync(dirname(p), { recursive: true });
		const tail = entries.slice(-LEDGER_MAX_ENTRIES).map((e) => {
			const diskEntry: ExecLedgerEntry = {
				ts: e.ts,
				tool: e.tool,
				...(e.command !== undefined ? { command: e.command } : {}),
				...(e.sessionId !== undefined ? { sessionId: e.sessionId } : {}),
				sha1: e.sha1,
				normSha1: e.normSha1,
				bytes: e.bytes,
				snippet: e.snippet,
			};
			return JSON.stringify(diskEntry);
		});
		const body = tail.length ? `${tail.join("\n")}\n` : "";
		const tmp = `${p}.tmp-${process.pid}-${Date.now()}-${atomicLedgerSeq++}`;
		writeFileSync(tmp, body, "utf8");
		renameSync(tmp, p);
	} catch {
		/* 写盘失败不打断主流程，内存缓冲仍保留 */
	}
}

/**
 * 记录一次真实工具执行结果：同步更新进程内环形缓冲与 <root>/.nuwa/exec-ledger.jsonl（滚动保留最近 200 条摘要与 SHA1）。
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
	const entry: MemoryLedgerRecord = {
		ts: new Date().toISOString(),
		tool: rawTool,
		...(rec.command ? { command: String(rec.command).slice(0, 1000) } : {}),
		...(rec.sessionId ? { sessionId: String(rec.sessionId) } : {}),
		sha1: sha1Hex(rawOutput),
		normSha1: sha1Hex(rawOutput.trim()),
		bytes: Buffer.byteLength(rawOutput, "utf8"),
		snippet: buildSnippet(rawOutput),
		rawOutput: rawOutput.length <= 65_536 ? rawOutput : undefined,
	};

	const mem = memoryRing.get(normRoot) ?? [];
	mem.push(entry);
	if (mem.length > LEDGER_MAX_ENTRIES) {
		mem.splice(0, mem.length - LEDGER_MAX_ENTRIES);
	}
	memoryRing.set(normRoot, mem);

	const diskExisting = readDiskLedger(normRoot);
	diskExisting.push(entry);
	writeDiskLedger(normRoot, diskExisting);
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

function extractKeyLines(output: string): string[] {
	const lines = output
		.replace(/\r/g, "")
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l.length > 0 && !/^(?:\.\.\.|---.*---|todo|tbd|n\/a|none|null|-+)$/i.test(l));
	const strong = lines.filter((l) => l.length >= 6);
	return strong.length > 0 ? strong.slice(0, 20) : lines.filter((l) => l.length >= 3).slice(0, 20);
}

/**
 * 复验提交的证据（output / flagValue）是否真实出现在近期执行账本或 /tmp/nuwa/<projectId>/ 产物文件中。
 */
export function verifyExecutionEvidence(root: string, input: VerifyEvidenceInput): VerifyEvidenceResult {
	const envMode = (process.env.NUWA_STRICT_EVIDENCE ?? "").trim();
	if (envMode === "0") {
		return { ok: true, verified: false, reason: "NUWA_STRICT_EVIDENCE=0 已放行" };
	}

	const normRoot = resolve(root || process.cwd());
	const memRecords = memoryRing.get(normRoot) ?? [];
	const diskRecords = readDiskLedger(normRoot);
	const artifacts = collectArtifactTexts(input.projectId);

	const corpusTexts: string[] = [];
	const shaSet = new Set<string>();

	for (const r of memRecords) {
		shaSet.add(r.sha1);
		shaSet.add(r.normSha1);
		corpusTexts.push(r.rawOutput ?? r.snippet);
	}
	for (const r of diskRecords) {
		shaSet.add(r.sha1);
		shaSet.add(r.normSha1);
		corpusTexts.push(r.snippet);
	}
	for (const t of artifacts) {
		corpusTexts.push(t);
	}

	const rawOut = String(input.output ?? "");
	const trimmedOut = rawOut.trim();
	const explicitFlag = String(input.flagValue ?? "").trim();
	const inferredFlag =
		!explicitFlag && input.kind === "flag" ? (rawOut.match(/flag\{[^}\s]{2,}\}/i)?.[0] ?? "") : "";
	const targetFlag = explicitFlag || inferredFlag;
	const isFlagCheck = Boolean(targetFlag) || input.kind === "flag";

	let verified = false;

	if (targetFlag) {
		verified = corpusTexts.some((chunk) => chunk.includes(targetFlag));
	} else if (trimmedOut.length > 0) {
		if (shaSet.has(sha1Hex(rawOut)) || shaSet.has(sha1Hex(trimmedOut))) {
			verified = true;
		} else if (trimmedOut.length >= 4 && corpusTexts.some((chunk) => chunk.includes(trimmedOut))) {
			verified = true;
		} else {
			const keyLines = extractKeyLines(rawOut);
			if (keyLines.length > 0) {
				verified = keyLines.some((line) => corpusTexts.some((chunk) => chunk.includes(line)));
			}
		}
	}

	if (verified) {
		return { ok: true, verified: true };
	}

	const hasHist = memRecords.length > 0 || diskRecords.length > 0;
	const strictActive = Boolean(input.strict) || envMode === "1";
	const normKind = String(input.kind ?? "").trim().toLowerCase();

	if (isFlagCheck && (strictActive || hasHist)) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: flag 未在近期真实执行账本或 /tmp/nuwa/${input.projectId}/ 产物中出现`,
		};
	}

	if ((normKind === "vuln" || normKind === "cred") && (strictActive || hasHist)) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: ${input.kind} 的关键回显未在近期真实执行账本或 /tmp/nuwa/${input.projectId}/ 产物中命中`,
		};
	}

	if (strictActive) {
		return {
			ok: false,
			verified: false,
			reason: `证据复验未通过: ${input.kind} 的关键回显未在近期执行账本或产物目录中命中`,
		};
	}

	return {
		ok: true,
		verified: false,
		reason: hasHist ? "未在近期账本摘要中完全匹配关键行（非严格模式软放行）" : "尚无工具执行账本记录",
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
