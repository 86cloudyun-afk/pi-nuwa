/**
 * 女娲 v6.0.0 SQLite WAL 权威状态存储引擎（零外部依赖，基于 Bun 内置 `bun:sqlite`）。
 *
 * 职责：
 * 1. 管理 `<root>/.nuwa/nuwa.db`，强制开启 WAL 模式、`busy_timeout=5000`、`synchronous=NORMAL` 与 `foreign_keys=ON`。
 * 2. 提供规范化 10 表结构（`meta`、`facts`+`facts_fts`、`intents`、`attempted`、`assets`、`hypotheses`、
 *    `journal`、`exec_ledger`、`calibration_records`、`traffic_entries`），支持长会话历史细节全文检索。
 * 3. 提供 JSON ↔ SQLite 无损往返存取、幂等存量迁移（`migrateJsonToSqlite`）与兼容导出（`exportStateJsonCompat`）。
 * 4. 所有写事务统一采用 `BEGIN IMMEDIATE` + 忙等重试，确保 4+ 并发读写无锁超时，事务严格原子。
 * 5. 入库前自动结合 Session Vault 与通用高危凭据规则全量脱敏，确保所有表与 FTS 索引绝不泄露明文凭据。
 * 6. 打开坏库时主动校验并提供清晰中文恢复指引（`NuwaSqliteCorruptError`），支持坏库隔离或回退 JSON 兜底。
 *
 * 约束：严禁运行时 `import "./nuwa"` 或 `./graph`，保持纯底层单向无环依赖。
 */
import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
	SCHEMA,
	atomicWrite,
	journalPath,
	loadStateJsonOnly,
	normalizeState,
	nowIso,
	stateDir,
	statePath,
} from "./storage";
import {
	loadSessionVault,
	maskSecretValue,
	redactVaultSecrets,
	type SessionVault,
} from "./session-vault";
import type { ExecLedgerEntry } from "./evidence";
import type {
	AssetNode,
	AttemptedEntry,
	Fact,
	FactKind,
	HypothesisNode,
	Intent,
	NuwaState,
	Project,
	Runtime,
	SurfaceDomain,
	VerifyStage,
} from "./types";
import type { JournalEntry } from "./ui";

export const SQLITE_SCHEMA_VERSION = 1;
export type StorageBackend = "json" | "sqlite" | "dual";

export interface OpenNuwaDbOptions {
	/** 当检测到损坏数据库文件时，自动将其重命名隔离为 `.corrupt-<ts>` 后重建新库。 */
	quarantineCorrupt?: boolean;
	/** 仅只读打开已有数据库（不建表）。 */
	readonly?: boolean;
}

export interface LoadSqliteStateOptions {
	/** 当 SQLite 坏库时是否自动回退到 `.nuwa/state.json` / 快照恢复。 */
	fallbackToJson?: boolean;
	/** 坏库兜底告警回调，便于上层记录日志或提示用户。 */
	onCorruptWarning?: (message: string, err: NuwaSqliteCorruptError) => void;
}

export interface SaveSqliteStateOptions {
	/** 可选显式传入会话保险箱以执行入库脱敏；省略时自动读取 `<root>/.nuwa/sessions/vault.json`。 */
	vault?: SessionVault;
	/** 是否顺便刷新 `project.updatedAt`（默认 false，确保往返序列化严格一致）。 */
	touchUpdatedAt?: boolean;
}

export interface AppendJournalOptions {
	vault?: SessionVault;
	/** 可选外部去重哈希（如迁移历史 `journal.jsonl` 时用于幂等防重）。 */
	dedupHash?: string;
}

export interface QueryFactsOptions {
	kind?: FactKind;
	verifyStage?: VerifyStage;
	surfaceDomain?: SurfaceDomain;
	limit?: number;
}

export interface FactSearchHit {
	fact: Fact;
	score: number;
	source: "fts5" | "like" | "hybrid";
	snippet: string;
}

export interface MigrateJsonOptions {
	/** 若 SQLite 已存在项目状态，是否强制用 `state.json` 覆盖（默认 false，幂等不覆盖）。 */
	force?: boolean;
	/** 是否同时扫描轮转后的历史 `journal.*.jsonl` 归档（默认 false）。 */
	includeJournalArchives?: boolean;
	vault?: SessionVault;
}

export interface MigrateJsonResult {
	ok: boolean;
	dbPath: string;
	migratedState: boolean;
	stateSkipped: boolean;
	factsCount: number;
	intentsCount: number;
	attemptedCount: number;
	assetsCount: number;
	hypothesesCount: number;
	journalInserted: number;
	journalSkipped: number;
	execLedgerInserted: number;
	calibrationInserted: number;
	trafficInserted: number;
}

export interface ExportCompatOptions {
	/** 是否原子写回 `<root>/.nuwa/state.json`（默认 true）。 */
	writeFile?: boolean;
	/** 自定义输出路径（默认 `<root>/.nuwa/state.json`）。 */
	outputPath?: string;
}

export interface ExportCompatResult {
	ok: boolean;
	path: string;
	bytes: number;
	state: NuwaState | null;
	json: string;
}

export interface CalibrationRecordRow {
	predictionId: string;
	intentId?: string;
	taskCategory: string;
	modelId: string;
	predictedConfidence: number;
	estimatedTokens?: number;
	outcome?: number;
	isFalsePositive?: boolean;
	actualTokens?: number;
	durationMs?: number;
	source?: string;
	settled: boolean;
	createdAt: string;
	settledAt?: string;
	payload?: Record<string, unknown>;
}

export interface TrafficEntryRow {
	id: string;
	ts: string;
	method: string;
	url: string;
	host: string;
	path: string;
	status: number;
	durationMs?: number;
	requestHeaders?: Record<string, string>;
	requestBodyPreview?: string;
	responseHeaders?: Record<string, string>;
	responseBodyPreview?: string;
	tags?: string[];
	redacted?: boolean;
	payload?: Record<string, unknown>;
}

export interface TrafficQueryFilter {
	host?: string;
	pathPrefix?: string;
	method?: string;
	status?: number;
	limit?: number;
}

/**
 * 坏库专用诊断异常：携带损坏库路径与明确的简体中文恢复建议。
 */
export class NuwaSqliteCorruptError extends Error {
	readonly code = "SQLITE_CORRUPT";
	readonly dbPath: string;
	readonly recoveryHint: string;

	constructor(dbPath: string, causeMessage: string) {
		const hint =
			`请先备份损坏库文件 (${dbPath}) 并清理同目录 -wal/-shm 文件，` +
			`随后运行 migrateJsonToSqlite(root) 从 .nuwa/state.json 或 .nuwa/snap 快照重建 SQLite 状态库。`;
		super(`女娲 SQLite 状态库损坏或格式非法 (${dbPath}): ${causeMessage}。恢复建议: ${hint}`);
		this.name = "NuwaSqliteCorruptError";
		this.dbPath = dbPath;
		this.recoveryHint = hint;
	}
}

const SLEEP_VIEW = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
	if (ms <= 0) return;
	Atomics.wait(SLEEP_VIEW, 0, 0, ms);
}

function sha256Hex(text: string): string {
	return createHash("sha256").update(text, "utf8").digest("hex");
}

function clampInt(value: number | undefined, fallback: number, min: number, max: number): number {
	if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
	return Math.max(min, Math.min(max, Math.floor(value)));
}

function formatFactMetaSearchText(meta: Fact["meta"] | undefined): string {
	if (!meta || typeof meta !== "object") return "";
	const parts: string[] = [];
	if (meta.server) parts.push(meta.server);
	if (meta.waf) parts.push(meta.waf);
	if (Array.isArray(meta.tech) && meta.tech.length) parts.push(meta.tech.join(" "));
	if (Array.isArray(meta.paths) && meta.paths.length) parts.push(meta.paths.join(" "));
	if (Array.isArray(meta.routes) && meta.routes.length) parts.push(meta.routes.join(" "));
	if (Array.isArray(meta.san) && meta.san.length) parts.push(meta.san.join(" "));
	return parts.join(" ");
}

function isBusyError(err: unknown): boolean {
	const msg = String(err instanceof Error ? err.message : err ?? "").toLowerCase();
	return (
		msg.includes("sqlite_busy") ||
		msg.includes("sqlite_locked") ||
		msg.includes("database is locked") ||
		msg.includes("database table is locked")
	);
}

function isCorruptError(err: unknown): boolean {
	const msg = String(err instanceof Error ? err.message : err ?? "").toLowerCase();
	return (
		msg.includes("sqlite_notadb") ||
		msg.includes("sqlite_corrupt") ||
		msg.includes("file is not a database") ||
		msg.includes("database disk image is malformed") ||
		msg.includes("malformed")
	);
}

/** 结合 `PRAGMA busy_timeout=5000` 与 `BEGIN IMMEDIATE` 的应用层短退避重试，防极端并发尖峰。 */
function runWithBusyRetry<T>(fn: () => T, maxRetries = 10): T {
	let attempt = 0;
	for (;;) {
		try {
			return fn();
		} catch (err) {
			if (!isBusyError(err) || attempt >= maxRetries) {
				throw err;
			}
			attempt += 1;
			const jitter = Math.floor(Math.random() * 15);
			const delay = Math.min(8 * attempt + jitter, 120);
			sleepSync(delay);
		}
	}
}

function safeChmod600(filePath: string): void {
	try {
		if (existsSync(filePath)) chmodSync(filePath, 0o600);
	} catch {
		/* 非 POSIX 文件系统忽略 */
	}
}

// ============================================================================
// 全表零明文凭据脱敏层（Vault 凭据 + 通用敏感头/口令/JWT 幂等掩码）
// ============================================================================

const SENSITIVE_FIELD_KEY_RE =
	/^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-session-token|api[-_]?key|auth[-_]?token|access[-_]?token|refresh[-_]?token|bearer|password|passwd|pwd|secret|client[-_]?secret|private[-_]?key|session[-_]?secret)$/i;

/** 仅用于 HTTP 请求/响应头字典：排除标准非敏感头后再宽泛匹配敏感头名（与 session-vault.ts 对齐）。 */
const STANDARD_NON_SENSITIVE_HTTP_HEADER_RE =
	/^(?:accept(?:-[a-z0-9-]+)?|content-(?:type|length|encoding|language|disposition|range|security-policy|md5)|cache-control|pragma|expires|etag|last-modified|if-(?:match|none-match|modified-since|unmodified-since|range)|connection|keep-alive|transfer-encoding|upgrade(?:-insecure-requests)?|host|origin|referer|user-agent|date|server|vary|via|age|location|allow|range|te|trailer|dnt|priority|sec-[a-z0-9-]+|x-forwarded-(?:for|host|proto|port)|x-real-ip|x-request-id|x-correlation-id|x-trace-id|x-ratelimit-[a-z0-9-]+|x-frame-options|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy|access-control-[a-z0-9-]+)$/i;
const SENSITIVE_HTTP_HEADER_NAME_RE =
	/(?:auth|token|key|secret|cookie|session|jwt|csrf|xsrf|pass|cred|sign|bearer|ticket|access)/i;

const GENERIC_AUTH_HEADER_RE =
	/\b(Authorization|Proxy-Authorization)\s*:\s*(Bearer|Basic|Token|JWT)\s+([A-Za-z0-9._~+/=-]{6,})/gi;
const GENERIC_API_KEY_HEADER_RE =
	/\b(X-API-Key|X-Auth-Token|X-Access-Token|X-Session-Token|Api-Key|Private-Token|X-Vault-Token|X-CSRF-Token|X-XSRF-Token|X-Gitlab-Token)\s*:\s*([^\s\r\n'",;]{4,})/gi;
const GENERIC_COOKIE_HEADER_RE =
	/\b(Cookie|Set-Cookie)\s*:\s*([^\r\n]+)/gi;
const GENERIC_PASSWORD_KV_RE =
	/\b(password|passwd|pwd|api_key|apikey|secret_key|client_secret|access_token|refresh_token)\s*([:=])\s*(["']?)([^\s\r\n"',;}{[\]&#)>]{4,})\3/gi;
const URL_USERINFO_RE =
	/(\b(?:https?|ftp|sftp|ftps|ws|wss|redis|rediss|mysql|postgres(?:ql)?|mongodb(?:\+srv)?|amqp|amqps|socks(?:4a?|5h?)?):\/\/)([^\/\s:@?#]+)?:([^\/\s@?#]+)@/gi;
const RAW_JWT_RE = /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,})\b/g;
const KNOWN_TOKEN_PREFIX_RE = /\b((?:sk-proj-|sk-live-|sk-|ghp_|gho_|ghu_|github_pat_|xoxb-|xoxp-|AKIA)[A-Za-z0-9_-]{10,})\b/g;

const COOKIE_ATTRS = new Set([
	"path",
	"domain",
	"expires",
	"max-age",
	"samesite",
	"secure",
	"httponly",
	"priority",
	"partitioned",
	"version",
]);

function alreadyMasked(val: string): boolean {
	return val.includes("***") || /^\*{4,}$/.test(val.trim());
}

function maskCookieHeaderLine(cookieVal: string): string {
	return cookieVal
		.split(";")
		.map((part) => {
			const seg = part.trim();
			if (!seg) return "";
			const eq = seg.indexOf("=");
			if (eq <= 0) return seg;
			const k = seg.slice(0, eq).trim();
			const v = seg.slice(eq + 1).trim();
			if (!k || !v || COOKIE_ATTRS.has(k.toLowerCase()) || alreadyMasked(v)) return seg;
			if (v.length < 4) return seg;
			return `${k}=${maskSecretValue(v)}`;
		})
		.filter(Boolean)
		.join("; ");
}

function redactGenericSecrets(text: string): string {
	if (!text) return text;
	let out = text;

	out = out.replace(GENERIC_AUTH_HEADER_RE, (_m, hdr: string, scheme: string, tok: string) => {
		if (alreadyMasked(tok)) return `${hdr}: ${scheme} ${tok}`;
		return `${hdr}: ${scheme} ${maskSecretValue(tok)}`;
	});

	out = out.replace(GENERIC_API_KEY_HEADER_RE, (_m, hdr: string, tok: string) => {
		if (alreadyMasked(tok)) return `${hdr}: ${tok}`;
		return `${hdr}: ${maskSecretValue(tok)}`;
	});

	out = out.replace(GENERIC_COOKIE_HEADER_RE, (_m, hdr: string, val: string) => {
		return `${hdr}: ${maskCookieHeaderLine(val)}`;
	});

	out = out.replace(
		GENERIC_PASSWORD_KV_RE,
		(_m, key: string, sep: string, quote: string, val: string) => {
			if (alreadyMasked(val)) return `${key}${sep}${quote}${val}${quote}`;
			return `${key}${sep}${quote}${maskSecretValue(val)}${quote}`;
		},
	);

	out = out.replace(URL_USERINFO_RE, (_m, scheme: string, user: string | undefined, pass: string) => {
		const userPart = user ?? "";
		if (alreadyMasked(pass)) return `${scheme}${userPart}:${pass}@`;
		return `${scheme}${userPart}:${maskSecretValue(pass)}@`;
	});

	out = out.replace(RAW_JWT_RE, (jwt) => (alreadyMasked(jwt) ? jwt : maskSecretValue(jwt)));
	out = out.replace(KNOWN_TOKEN_PREFIX_RE, (tok) => (alreadyMasked(tok) ? tok : maskSecretValue(tok)));

	return out;
}

function redactTextForStorage(text: string | undefined, vault: SessionVault): string | undefined {
	if (text === undefined) return undefined;
	if (!text) return text;
	const afterVault = redactVaultSecrets(text, vault);
	return redactGenericSecrets(afterVault);
}

function isSensitiveHttpHeaderName(name: string): boolean {
	const norm = name.trim();
	if (!norm) return false;
	if (STANDARD_NON_SENSITIVE_HTTP_HEADER_RE.test(norm)) return false;
	return SENSITIVE_FIELD_KEY_RE.test(norm) || SENSITIVE_HTTP_HEADER_NAME_RE.test(norm);
}

function redactHeadersRecord(
	headers: Record<string, string> | undefined,
	vault: SessionVault,
): Record<string, string> | undefined {
	if (!headers) return undefined;
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(headers)) {
		const cleanV = String(v ?? "");
		if (isSensitiveHttpHeaderName(k)) {
			if (k.trim().toLowerCase() === "cookie" || k.trim().toLowerCase() === "set-cookie") {
				out[k] = maskCookieHeaderLine(redactVaultSecrets(cleanV, vault));
			} else {
				const authScheme = /^(Bearer|Basic|Token|JWT)\s+(.+)$/i.exec(cleanV.trim());
				if (authScheme?.[1] && authScheme[2]) {
					const tok = authScheme[2].trim();
					out[k] = alreadyMasked(tok)
						? `${authScheme[1]} ${tok}`
						: `${authScheme[1]} ${maskSecretValue(tok)}`;
				} else {
					out[k] = alreadyMasked(cleanV) ? cleanV : maskSecretValue(cleanV);
				}
			}
		} else {
			out[k] = redactTextForStorage(cleanV, vault) ?? cleanV;
		}
	}
	return out;
}

function redactUnknownForStorage<T>(value: T, vault: SessionVault, depth = 0): T {
	if (depth > 12 || value === null || value === undefined) return value;
	if (typeof value === "string") {
		return (redactTextForStorage(value, vault) ?? value) as unknown as T;
	}
	if (Array.isArray(value)) {
		return value.map((item) => redactUnknownForStorage(item, vault, depth + 1)) as unknown as T;
	}
	if (typeof value === "object") {
		const obj = value as Record<string, unknown>;
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(obj)) {
			if (typeof v === "string" && SENSITIVE_FIELD_KEY_RE.test(k.trim())) {
				if (k.trim().toLowerCase() === "cookie" || k.trim().toLowerCase() === "set-cookie") {
					out[k] = maskCookieHeaderLine(redactVaultSecrets(v, vault));
				} else {
					out[k] = alreadyMasked(v) ? v : maskSecretValue(v);
				}
			} else {
				out[k] = redactUnknownForStorage(v, vault, depth + 1);
			}
		}
		return out as T;
	}
	return value;
}

function safeLoadVault(root: string, explicit?: SessionVault): SessionVault {
	if (explicit) return explicit;
	try {
		return loadSessionVault(root);
	} catch {
		return { schema: 1, updatedAt: "", roles: {} };
	}
}

// ============================================================================
// DDL 定义（10 张核心表 + FTS5 全文检索索引）
// ============================================================================

const CORE_DDL = `
CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY NOT NULL,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS facts (
	id TEXT PRIMARY KEY NOT NULL,
	kind TEXT NOT NULL,
	title TEXT NOT NULL,
	detail TEXT NOT NULL,
	command TEXT,
	output TEXT,
	intent TEXT,
	fact_key TEXT,
	created_at TEXT NOT NULL,
	verified INTEGER,
	verify_stage TEXT,
	verify_note TEXT,
	verified_at TEXT,
	verified_by TEXT,
	evidence_seq INTEGER,
	asset_id TEXT,
	target_key TEXT,
	surface_domain TEXT,
	evidence_ref TEXT,
	meta_json TEXT,
	agent_result_json TEXT,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_facts_kind ON facts(kind);
CREATE INDEX IF NOT EXISTS idx_facts_created_at ON facts(created_at);
CREATE INDEX IF NOT EXISTS idx_facts_fact_key ON facts(fact_key);
CREATE INDEX IF NOT EXISTS idx_facts_target_key ON facts(target_key);
CREATE INDEX IF NOT EXISTS idx_facts_verify_stage ON facts(verify_stage);

CREATE VIRTUAL TABLE IF NOT EXISTS facts_fts USING fts5(
	fact_id UNINDEXED,
	kind,
	title,
	detail,
	command,
	output,
	fact_key,
	target_key,
	tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS intents (
	id TEXT PRIMARY KEY NOT NULL,
	phase TEXT NOT NULL,
	intent_key TEXT NOT NULL,
	title TEXT NOT NULL,
	detail TEXT NOT NULL,
	from_json TEXT NOT NULL,
	to_fact_id TEXT,
	status TEXT NOT NULL,
	worker TEXT,
	priority INTEGER NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	claimed_at TEXT,
	done_at TEXT,
	note TEXT,
	next_run_at INTEGER,
	hypothesis_id TEXT,
	asset_id TEXT,
	auth_role TEXT,
	invalidated_reason TEXT,
	expected_kind TEXT,
	surface_domain TEXT,
	target_key TEXT,
	dedup_key TEXT,
	hint_hash TEXT,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_intents_status ON intents(status);
CREATE INDEX IF NOT EXISTS idx_intents_phase_status ON intents(phase, status);
CREATE INDEX IF NOT EXISTS idx_intents_key ON intents(intent_key);
CREATE INDEX IF NOT EXISTS idx_intents_dedup_key ON intents(dedup_key);
CREATE INDEX IF NOT EXISTS idx_intents_priority ON intents(priority DESC);

CREATE TABLE IF NOT EXISTS attempted (
	attempted_key TEXT PRIMARY KEY NOT NULL,
	entry_key TEXT NOT NULL,
	expected_kind TEXT NOT NULL,
	target_key TEXT NOT NULL,
	surface_domain TEXT NOT NULL,
	status TEXT NOT NULL,
	at TEXT NOT NULL,
	from_json TEXT NOT NULL,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempted_target ON attempted(target_key);
CREATE INDEX IF NOT EXISTS idx_attempted_status ON attempted(status);

CREATE TABLE IF NOT EXISTS assets (
	id TEXT PRIMARY KEY NOT NULL,
	kind TEXT NOT NULL,
	target TEXT NOT NULL,
	host TEXT,
	port INTEGER,
	scheme TEXT,
	reachable_via_json TEXT,
	tags_json TEXT,
	source_fact_id TEXT,
	created_at TEXT NOT NULL,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_host ON assets(host);

CREATE TABLE IF NOT EXISTS hypotheses (
	id TEXT PRIMARY KEY NOT NULL,
	title TEXT NOT NULL,
	statement TEXT NOT NULL,
	required_facts_json TEXT NOT NULL,
	falsification_test TEXT NOT NULL,
	expected_gain REAL NOT NULL,
	estimated_cost REAL NOT NULL,
	status TEXT NOT NULL,
	linked_intents_json TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	note TEXT,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_status ON hypotheses(status);

CREATE TABLE IF NOT EXISTS journal (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	type TEXT NOT NULL,
	dedup_hash TEXT UNIQUE,
	payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_journal_ts ON journal(ts);
CREATE INDEX IF NOT EXISTS idx_journal_type ON journal(type);

CREATE TABLE IF NOT EXISTS exec_ledger (
	seq INTEGER PRIMARY KEY,
	ts TEXT NOT NULL,
	tool TEXT NOT NULL,
	command TEXT,
	session_id TEXT,
	agent_name TEXT,
	sha1 TEXT NOT NULL,
	norm_sha1 TEXT NOT NULL,
	bytes INTEGER NOT NULL DEFAULT 0,
	snippet TEXT NOT NULL,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_exec_ledger_ts ON exec_ledger(ts);
CREATE INDEX IF NOT EXISTS idx_exec_ledger_tool ON exec_ledger(tool);

CREATE TABLE IF NOT EXISTS calibration_records (
	prediction_id TEXT PRIMARY KEY NOT NULL,
	intent_id TEXT,
	task_category TEXT NOT NULL,
	model_id TEXT NOT NULL,
	predicted_confidence REAL NOT NULL,
	estimated_tokens INTEGER,
	outcome INTEGER,
	is_false_positive INTEGER,
	actual_tokens INTEGER,
	duration_ms INTEGER,
	source TEXT,
	settled INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL,
	settled_at TEXT,
	payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_calib_model_cat ON calibration_records(model_id, task_category);
CREATE INDEX IF NOT EXISTS idx_calib_settled ON calibration_records(settled);
CREATE INDEX IF NOT EXISTS idx_calib_created_at ON calibration_records(created_at);

CREATE TABLE IF NOT EXISTS traffic_entries (
	id TEXT PRIMARY KEY NOT NULL,
	ts TEXT NOT NULL,
	method TEXT NOT NULL,
	url TEXT NOT NULL,
	host TEXT NOT NULL,
	path TEXT NOT NULL,
	status INTEGER NOT NULL,
	duration_ms INTEGER,
	request_headers_json TEXT,
	request_body_preview TEXT,
	response_headers_json TEXT,
	response_body_preview TEXT,
	tags_json TEXT,
	redacted INTEGER NOT NULL DEFAULT 1,
	payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_traffic_host_path ON traffic_entries(host, path);
CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic_entries(status);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_entries(ts);
`;

const KNOWN_FACT_KEYS = new Set([
	"id",
	"kind",
	"title",
	"detail",
	"command",
	"output",
	"intent",
	"key",
	"createdAt",
	"meta",
	"verified",
	"verifyStage",
	"verifyNote",
	"verifiedAt",
	"verifiedBy",
	"evidenceSeq",
	"assetId",
	"targetKey",
	"surfaceDomain",
	"evidenceRef",
	"agentResult",
]);

const KNOWN_INTENT_KEYS = new Set([
	"id",
	"phase",
	"key",
	"title",
	"detail",
	"from",
	"to",
	"status",
	"worker",
	"priority",
	"attempts",
	"createdAt",
	"claimedAt",
	"doneAt",
	"note",
	"nextRunAt",
	"hypothesisId",
	"assetId",
	"authRole",
	"invalidatedReason",
	"expectedKind",
	"surfaceDomain",
	"targetKey",
	"dedupKey",
	"hintHash",
]);

const KNOWN_ATTEMPTED_KEYS = new Set([
	"key",
	"expectedKind",
	"targetKey",
	"surfaceDomain",
	"status",
	"at",
	"from",
]);

const KNOWN_ASSET_KEYS = new Set([
	"id",
	"kind",
	"target",
	"host",
	"port",
	"scheme",
	"reachableVia",
	"tags",
	"sourceFactId",
	"createdAt",
]);

const KNOWN_HYPOTHESIS_KEYS = new Set([
	"id",
	"title",
	"statement",
	"requiredFacts",
	"falsificationTest",
	"expectedGain",
	"estimatedCost",
	"status",
	"linkedIntents",
	"createdAt",
	"updatedAt",
	"note",
]);

function extractExtraFields(obj: Record<string, unknown>, known: Set<string>): Record<string, unknown> | null {
	const extra: Record<string, unknown> = {};
	let count = 0;
	for (const [k, v] of Object.entries(obj)) {
		if (!known.has(k) && v !== undefined) {
			extra[k] = v;
			count += 1;
		}
	}
	return count > 0 ? extra : null;
}

function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
	if (!raw) return fallback;
	try {
		return JSON.parse(raw) as T;
	} catch {
		return fallback;
	}
}

// ============================================================================
// 路径与存储后端策略解析
// ============================================================================

/** 返回项目 SQLite 权威状态库路径：`<root>/.nuwa/nuwa.db`。 */
export function sqliteDbPath(root: string): string {
	return join(stateDir(resolve(root)), "nuwa.db");
}

/**
 * 读取 `NUWA_STORAGE_BACKEND` 环境变量解析生效存储后端：
 * - `sqlite` / `wal` / `db` -> `"sqlite"`
 * - `dual` / `both` / `hybrid` -> `"dual"`
 * - `json` / `file` / `legacy` -> `"json"`
 * - 未配置或 `auto`：若传入项目目录且 `.nuwa/nuwa.db` 已存在（非空）则返回 `"sqlite"`，否则平滑回退 `"json"` 兼容历史项目。
 */
export function resolveStorageBackend(
	rootOrOpts?: string | { root?: string; env?: Record<string, string | undefined> },
	envOverride?: Record<string, string | undefined>,
): StorageBackend {
	const root =
		typeof rootOrOpts === "string"
			? rootOrOpts
			: rootOrOpts && typeof rootOrOpts === "object"
				? rootOrOpts.root
				: undefined;
	const env =
		envOverride ??
		(rootOrOpts && typeof rootOrOpts === "object" && rootOrOpts.env ? rootOrOpts.env : process.env);

	const raw = String(env.NUWA_STORAGE_BACKEND ?? "").trim().toLowerCase();
	if (raw === "sqlite" || raw === "wal" || raw === "db") return "sqlite";
	if (raw === "dual" || raw === "both" || raw === "hybrid") return "dual";
	if (raw === "json" || raw === "file" || raw === "legacy") return "json";

	if (root && root.trim()) {
		try {
			const dbFile = sqliteDbPath(root);
			if (existsSync(dbFile) && statSync(dbFile).size > 0) {
				return "sqlite";
			}
		} catch {
			/* 无法读取则平滑回退 json */
		}
	}
	return "json";
}

// ============================================================================
// 打开、PRAGMA 配置、坏库检测与建表
// ============================================================================

function quarantineCorruptDbFiles(dbFile: string): string {
	const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 17);
	const backupPath = `${dbFile}.corrupt-${stamp}-${process.pid}`;
	if (existsSync(dbFile)) {
		renameSync(dbFile, backupPath);
	}
	for (const suffix of ["-wal", "-shm"]) {
		const side = `${dbFile}${suffix}`;
		if (existsSync(side)) {
			try {
				rmSync(side, { force: true });
			} catch {
				/* 忽略清理失败 */
			}
		}
	}
	return backupPath;
}

function hasTable(db: Database, name: string): boolean {
	try {
		const row = db
			.query("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?")
			.get(name) as { name?: string } | null;
		return Boolean(row?.name);
	} catch {
		return false;
	}
}

function isReadonlyCantOpenError(err: unknown): boolean {
	const msg = String(err instanceof Error ? err.message : err ?? "").toLowerCase();
	return msg.includes("sqlite_cantopen") || msg.includes("unable to open database file");
}

function configureAndInitDb(db: Database, dbFile: string, readonly: boolean): void {
	db.exec("PRAGMA busy_timeout = 5000;");
	if (readonly) {
		db.exec("PRAGMA query_only = ON;");
	} else {
		runWithBusyRetry(() => {
			const jmRow = db.query("PRAGMA journal_mode").get() as Record<string, unknown> | null;
			const curMode = jmRow ? String(Object.values(jmRow)[0] ?? "").toLowerCase() : "";
			if (curMode !== "wal") {
				db.exec("PRAGMA journal_mode = WAL;");
			}
			db.exec("PRAGMA synchronous = NORMAL;");
		});
	}
	db.exec("PRAGMA foreign_keys = ON;");

	// 快速完整性探测，及时发现损坏文件头或损坏页（只读安全，不触发写锁）
	const qc = runWithBusyRetry(() => db.query("PRAGMA quick_check(1)").get() as Record<string, unknown> | null);
	const qcVal = qc ? String(Object.values(qc)[0] ?? "").toLowerCase() : "";
	if (qcVal && qcVal !== "ok") {
		throw new NuwaSqliteCorruptError(dbFile, `PRAGMA quick_check 返回异常: ${qcVal}`);
	}

	if (!readonly) {
		runWithBusyRetry(() => {
			db.exec(CORE_DDL);
			const initTx = db.transaction(() => {
				db.query("INSERT OR IGNORE INTO meta (key, value, updated_at) VALUES (?, ?, ?)").run(
					"schema_version",
					String(SQLITE_SCHEMA_VERSION),
					nowIso(),
				);
			});
			initTx.immediate();
		});
		safeChmod600(dbFile);
	}
}

/**
 * 打开并初始化项目 SQLite 状态库（`<root>/.nuwa/nuwa.db`）。
 * - 写模式强制启用 WAL、busy_timeout=5000、synchronous=NORMAL、foreign_keys=ON 并初始化 10 表结构；
 * - 只读模式（`readonly: true`）绝不执行建表、写事务或元数据修改，无写锁争抢；
 * - 遇到已存在但为 0 字节空文件或格式/页损坏文件时统一抛出 `NuwaSqliteCorruptError`。
 */
const SQLITE_HEADER_MAGIC = "SQLite format 3\0";

function hasNonEmptyWalSidecar(dbFile: string): boolean {
	const walFile = `${dbFile}-wal`;
	if (!existsSync(walFile)) return false;
	try {
		return statSync(walFile).size > 0;
	} catch {
		return false;
	}
}

/**
 * 零磁盘写副作用的内存只读快照打开：
 * 当 WAL 库已正常关闭（不存在非空 `-wal`）或缺失 `-shm` 时，直接在内存副本中将 WAL 版本头字节 (18,19) 降为 1，
 * 通过 `Database.deserialize(..., { readonly: true })` 纯内存只读加载，严禁在磁盘新建/修改 `-wal` 或 `-shm`。
 */
function openReadonlyMemorySnapshot(dbFile: string): Database {
	const raw = readFileSync(dbFile);
	const buf = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
	const copy = new Uint8Array(buf.length);
	copy.set(buf);
	if (
		copy.length >= 100 &&
		Buffer.from(copy.subarray(0, 16)).toString("latin1") === SQLITE_HEADER_MAGIC &&
		copy[18] === 2 &&
		copy[19] === 2
	) {
		copy[18] = 1;
		copy[19] = 1;
	}
	return Database.deserialize(copy, { readonly: true });
}

export function openNuwaDb(root: string, opts?: OpenNuwaDbOptions): Database {
	const dbFile = sqliteDbPath(root);
	const readonly = opts?.readonly === true;
	if (!readonly) {
		mkdirSync(dirname(dbFile), { recursive: true });
	}

	const assertNotZeroByteCorrupt = (): void => {
		if (existsSync(dbFile)) {
			const st = statSync(dbFile);
			if (st.size === 0) {
				throw new NuwaSqliteCorruptError(dbFile, "数据库文件为 0 字节空文件（疑似崩溃截断或未完成初始化）");
			}
		}
	};

	const tryOpen = (): Database => {
		assertNotZeroByteCorrupt();
		if (readonly) {
			if (!existsSync(dbFile)) {
				throw new Error(`SQLITE_CANTOPEN: unable to open database file (${dbFile})`);
			}
			// 无活跃非空 -wal 时直接走纯内存只读反序列化，确保 100% 零新建 -wal/-shm、零 mtime 变动
			if (!hasNonEmptyWalSidecar(dbFile)) {
				let memDb: Database | null = null;
				try {
					memDb = openReadonlyMemorySnapshot(dbFile);
					configureAndInitDb(memDb, dbFile, true);
					return memDb;
				} catch (memErr) {
					try {
						memDb?.close();
					} catch {
						/* ignore */
					}
					if (memErr instanceof NuwaSqliteCorruptError) throw memErr;
					if (isCorruptError(memErr)) {
						throw new NuwaSqliteCorruptError(dbFile, memErr instanceof Error ? memErr.message : String(memErr));
					}
					throw memErr;
				}
			}
		}

		let db: Database | null = null;
		try {
			db = readonly ? new Database(dbFile, { readonly: true }) : new Database(dbFile, { create: true });
			configureAndInitDb(db, dbFile, readonly);
			return db;
		} catch (err) {
			try {
				db?.close();
			} catch {
				/* ignore */
			}
			// 存在非空 -wal 但极端缺失 -shm 导致 readonly 报 SQLITE_CANTOPEN 时：回退纯内存只读快照，严禁回退读写模式触碰磁盘
			if (readonly && isReadonlyCantOpenError(err) && existsSync(dbFile)) {
				let fbDb: Database | null = null;
				try {
					fbDb = openReadonlyMemorySnapshot(dbFile);
					configureAndInitDb(fbDb, dbFile, true);
					return fbDb;
				} catch (fbErr) {
					try {
						fbDb?.close();
					} catch {
						/* ignore */
					}
					if (fbErr instanceof NuwaSqliteCorruptError) throw fbErr;
					if (isCorruptError(fbErr)) {
						throw new NuwaSqliteCorruptError(dbFile, fbErr instanceof Error ? fbErr.message : String(fbErr));
					}
					throw fbErr;
				}
			}
			if (err instanceof NuwaSqliteCorruptError) {
				throw err;
			}
			if (isCorruptError(err)) {
				throw new NuwaSqliteCorruptError(dbFile, err instanceof Error ? err.message : String(err));
			}
			throw err;
		}
	};

	try {
		return tryOpen();
	} catch (err) {
		if (err instanceof NuwaSqliteCorruptError && opts?.quarantineCorrupt === true && !readonly) {
			quarantineCorruptDbFiles(dbFile);
			return tryOpen();
		}
		throw err;
	}
}

// ============================================================================
// 行结构 <-> 领域对象双向转换（保证 100% 无损往返）
// ============================================================================

function factFromRow(row: Record<string, any>): Fact {
	const extra = safeJsonParse<Record<string, unknown>>(row.extra_json, {});
	const fact: Fact = {
		...extra,
		id: String(row.id),
		kind: String(row.kind) as FactKind,
		title: String(row.title),
		detail: String(row.detail),
		createdAt: String(row.created_at),
	};
	if (row.command !== null && row.command !== undefined) fact.command = String(row.command);
	if (row.output !== null && row.output !== undefined) fact.output = String(row.output);
	if (row.intent !== null && row.intent !== undefined) fact.intent = String(row.intent);
	if (row.fact_key !== null && row.fact_key !== undefined) fact.key = String(row.fact_key);
	if (row.verified !== null && row.verified !== undefined) fact.verified = Number(row.verified) !== 0;
	if (row.verify_stage !== null && row.verify_stage !== undefined) {
		fact.verifyStage = String(row.verify_stage) as VerifyStage;
	}
	if (row.verify_note !== null && row.verify_note !== undefined) fact.verifyNote = String(row.verify_note);
	if (row.verified_at !== null && row.verified_at !== undefined) fact.verifiedAt = String(row.verified_at);
	if (row.verified_by !== null && row.verified_by !== undefined) fact.verifiedBy = String(row.verified_by);
	if (row.evidence_seq !== null && row.evidence_seq !== undefined) fact.evidenceSeq = Number(row.evidence_seq);
	if (row.asset_id !== null && row.asset_id !== undefined) fact.assetId = String(row.asset_id);
	if (row.target_key !== null && row.target_key !== undefined) fact.targetKey = String(row.target_key);
	if (row.surface_domain !== null && row.surface_domain !== undefined) {
		fact.surfaceDomain = String(row.surface_domain) as SurfaceDomain;
	}
	if (row.evidence_ref !== null && row.evidence_ref !== undefined) fact.evidenceRef = String(row.evidence_ref);
	if (row.meta_json) {
		const meta = safeJsonParse<Fact["meta"]>(row.meta_json, undefined);
		if (meta !== undefined) fact.meta = meta;
	}
	if (row.agent_result_json) {
		const ar = safeJsonParse<Record<string, unknown> | undefined>(row.agent_result_json, undefined);
		if (ar !== undefined) fact.agentResult = ar;
	}
	return fact;
}

function intentFromRow(row: Record<string, any>): Intent {
	const extra = safeJsonParse<Record<string, unknown>>(row.extra_json, {});
	const intent: Intent = {
		...extra,
		id: String(row.id),
		phase: String(row.phase) as Intent["phase"],
		key: String(row.intent_key),
		title: String(row.title),
		detail: String(row.detail),
		from: safeJsonParse<string[]>(row.from_json, []),
		status: String(row.status) as Intent["status"],
		priority: Number(row.priority),
		attempts: Number(row.attempts),
		createdAt: String(row.created_at),
	};
	if (row.to_fact_id !== null && row.to_fact_id !== undefined) intent.to = String(row.to_fact_id);
	if (row.worker !== null && row.worker !== undefined) intent.worker = String(row.worker);
	if (row.claimed_at !== null && row.claimed_at !== undefined) intent.claimedAt = String(row.claimed_at);
	if (row.done_at !== null && row.done_at !== undefined) intent.doneAt = String(row.done_at);
	if (row.note !== null && row.note !== undefined) intent.note = String(row.note);
	if (row.next_run_at !== null && row.next_run_at !== undefined) intent.nextRunAt = Number(row.next_run_at);
	if (row.hypothesis_id !== null && row.hypothesis_id !== undefined) intent.hypothesisId = String(row.hypothesis_id);
	if (row.asset_id !== null && row.asset_id !== undefined) intent.assetId = String(row.asset_id);
	if (row.auth_role !== null && row.auth_role !== undefined) intent.authRole = String(row.auth_role);
	if (row.invalidated_reason !== null && row.invalidated_reason !== undefined) {
		intent.invalidatedReason = String(row.invalidated_reason);
	}
	if (row.expected_kind !== null && row.expected_kind !== undefined) {
		intent.expectedKind = String(row.expected_kind) as FactKind;
	}
	if (row.surface_domain !== null && row.surface_domain !== undefined) {
		intent.surfaceDomain = String(row.surface_domain) as SurfaceDomain;
	}
	if (row.target_key !== null && row.target_key !== undefined) intent.targetKey = String(row.target_key);
	if (row.dedup_key !== null && row.dedup_key !== undefined) intent.dedupKey = String(row.dedup_key);
	if (row.hint_hash !== null && row.hint_hash !== undefined) intent.hintHash = String(row.hint_hash);
	return intent;
}

function attemptedFromRow(row: Record<string, any>): [string, AttemptedEntry] {
	const extra = safeJsonParse<Record<string, unknown>>(row.extra_json, {});
	const entry: AttemptedEntry = {
		...extra,
		key: String(row.entry_key),
		expectedKind: String(row.expected_kind) as FactKind,
		targetKey: String(row.target_key),
		surfaceDomain: String(row.surface_domain) as SurfaceDomain,
		status: String(row.status) as "done" | "blocked",
		at: String(row.at),
		from: safeJsonParse<string[]>(row.from_json, []),
	};
	return [String(row.attempted_key), entry];
}

function assetFromRow(row: Record<string, any>): AssetNode {
	const extra = safeJsonParse<Record<string, unknown>>(row.extra_json, {});
	const node: AssetNode = {
		...extra,
		id: String(row.id),
		kind: String(row.kind) as AssetNode["kind"],
		target: String(row.target),
		createdAt: String(row.created_at),
	};
	if (row.host !== null && row.host !== undefined) node.host = String(row.host);
	if (row.port !== null && row.port !== undefined) node.port = Number(row.port);
	if (row.scheme !== null && row.scheme !== undefined) node.scheme = String(row.scheme);
	if (row.reachable_via_json) {
		const rv = safeJsonParse<string[] | undefined>(row.reachable_via_json, undefined);
		if (rv !== undefined) node.reachableVia = rv;
	}
	if (row.tags_json) {
		const tags = safeJsonParse<string[] | undefined>(row.tags_json, undefined);
		if (tags !== undefined) node.tags = tags;
	}
	if (row.source_fact_id !== null && row.source_fact_id !== undefined) {
		node.sourceFactId = String(row.source_fact_id);
	}
	return node;
}

function hypothesisFromRow(row: Record<string, any>): HypothesisNode {
	const extra = safeJsonParse<Record<string, unknown>>(row.extra_json, {});
	const node: HypothesisNode = {
		...extra,
		id: String(row.id),
		title: String(row.title),
		statement: String(row.statement),
		requiredFacts: safeJsonParse<string[]>(row.required_facts_json, []),
		falsificationTest: String(row.falsification_test),
		expectedGain: Number(row.expected_gain),
		estimatedCost: Number(row.estimated_cost),
		status: String(row.status) as HypothesisNode["status"],
		linkedIntents: safeJsonParse<string[]>(row.linked_intents_json, []),
		createdAt: String(row.created_at),
		updatedAt: String(row.updated_at),
	};
	if (row.note !== null && row.note !== undefined) node.note = String(row.note);
	return node;
}

// ============================================================================
// 全文检索（FTS5 + 参数化 LIKE ESCAPE 混合检索，免疫 SQL/FTS 注入）
// ============================================================================

function escapeLike(input: string): string {
	return input.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

function hasDangerousSqlMeta(input: string): boolean {
	return /['";=()]|--|\/\*|\*\/|\b(?:union|select|drop|delete|insert|update|alter|pragma|attach|detach)\b/i.test(input);
}

function buildSafeFtsMatchQuery(raw: string): string | null {
	const trimmed = String(raw ?? "").trim();
	if (!trimmed || hasDangerousSqlMeta(trimmed)) return null;
	// 切分出安全的字母/数字/汉字短语，每个用双引号包裹成字面量，防止 OR/NOT/NEAR/列前缀语法注入
	const tokens = trimmed
		.toLowerCase()
		.split(/[^a-z0-9\u4e00-\u9fff]+/u)
		.map((t) => t.trim())
		.filter((t) => t.length >= 2)
		.slice(0, 6);
	if (tokens.length === 0) return null;
	return tokens.map((t) => `"${t.replace(/"/g, "")}"`).join(" AND ");
}

function buildFactSnippet(fact: Fact, query: string): string {
	const haystacks = [fact.title, fact.detail, fact.output ?? "", fact.command ?? ""];
	const needle = query.trim().toLowerCase();
	for (const h of haystacks) {
		if (!h) continue;
		const idx = h.toLowerCase().indexOf(needle);
		if (idx >= 0) {
			const start = Math.max(0, idx - 32);
			const end = Math.min(h.length, idx + needle.length + 64);
			const prefix = start > 0 ? "…" : "";
			const suffix = end < h.length ? "…" : "";
			return `${prefix}${h.slice(start, end).replace(/\s+/g, " ")}${suffix}`;
		}
	}
	return `${fact.title} | ${fact.detail}`.replace(/\s+/g, " ").slice(0, 140);
}

function queryFactsOnDb(db: Database, query: string, opts?: QueryFactsOptions): FactSearchHit[] {
	const q = String(query ?? "").trim();
	if (!q) return [];
	if (!hasTable(db, "facts")) return [];
	const limit = clampInt(opts?.limit, 20, 1, 100);

	const filterClauses: string[] = [];
	const filterParams: Array<string> = [];
	if (opts?.kind) {
		filterClauses.push("f.kind = ?");
		filterParams.push(opts.kind);
	}
	if (opts?.verifyStage) {
		filterClauses.push("f.verify_stage = ?");
		filterParams.push(opts.verifyStage);
	}
	if (opts?.surfaceDomain) {
		filterClauses.push("f.surface_domain = ?");
		filterParams.push(opts.surfaceDomain);
	}
	const extraWhere = filterClauses.length > 0 ? ` AND ${filterClauses.join(" AND ")}` : "";

	const hitMap = new Map<string, FactSearchHit>();

	// 1. 优先执行 FTS5 词元检索（BM25 相关性排序）
	const ftsExpr = buildSafeFtsMatchQuery(q);
	if (ftsExpr && hasTable(db, "facts_fts")) {
		try {
			const rows = db
				.query(
					`SELECT f.*, bm25(facts_fts) AS fts_rank
					 FROM facts_fts
					 JOIN facts f ON f.id = facts_fts.fact_id
					 WHERE facts_fts MATCH ?${extraWhere}
					 ORDER BY fts_rank ASC, f.created_at DESC
					 LIMIT ?`,
				)
				.all(ftsExpr, ...filterParams, limit) as Array<Record<string, any>>;

			for (const r of rows) {
				const fact = factFromRow(r);
				// bm25 为负数（越小越相关），转为正分方便合并排序
				const rankNum = Number(r.fts_rank);
				const score = Number.isFinite(rankNum) ? Math.max(1, 100 - Math.abs(rankNum)) : 50;
				hitMap.set(fact.id, {
					fact,
					score,
					source: "fts5",
					snippet: buildFactSnippet(fact, q),
				});
			}
		} catch {
			/* FTS 边界字符回退至 LIKE 参数化检索 */
		}
	}

	// 2. 参数化 LIKE ESCAPE 子串兜底（补齐中文连续词子串、URL 路径符号、IP:Port 及任意字面量精确命中）
	if (hitMap.size < limit) {
		const likeParam = `%${escapeLike(q)}%`;
		const likeRows = db
			.query(
				`SELECT f.*
				 FROM facts f
				 WHERE (
				   f.title LIKE ? ESCAPE '\\'
				   OR f.detail LIKE ? ESCAPE '\\'
				   OR COALESCE(f.command, '') LIKE ? ESCAPE '\\'
				   OR COALESCE(f.output, '') LIKE ? ESCAPE '\\'
				   OR COALESCE(f.fact_key, '') LIKE ? ESCAPE '\\'
				   OR COALESCE(f.target_key, '') LIKE ? ESCAPE '\\'
				   OR COALESCE(f.meta_json, '') LIKE ? ESCAPE '\\'
				 )${extraWhere}
				 ORDER BY f.created_at DESC
				 LIMIT ?`,
			)
			.all(likeParam, likeParam, likeParam, likeParam, likeParam, likeParam, likeParam, ...filterParams, limit * 2) as Array<
			Record<string, any>
		>;

		const lowerQ = q.toLowerCase();
		for (const r of likeRows) {
			const fact = factFromRow(r);
			let boost = 20;
			if (fact.title.toLowerCase().includes(lowerQ)) boost += 35;
			if ((fact.key ?? "").toLowerCase().includes(lowerQ) || (fact.targetKey ?? "").toLowerCase().includes(lowerQ)) {
				boost += 25;
			}
			if (fact.detail.toLowerCase().includes(lowerQ)) boost += 15;
			const prev = hitMap.get(fact.id);
			if (prev) {
				prev.score += boost * 0.5;
				prev.source = "hybrid";
			} else {
				hitMap.set(fact.id, {
					fact,
					score: boost,
					source: "like",
					snippet: buildFactSnippet(fact, q),
				});
			}
		}
	}

	return [...hitMap.values()]
		.sort((a, b) => b.score - a.score || b.fact.createdAt.localeCompare(a.fact.createdAt))
		.slice(0, limit);
}

// ============================================================================
// 核心封装类：NuwaSqliteStore
// ============================================================================

export class NuwaSqliteStore {
	readonly root: string;
	readonly dbPath: string;
	private db: Database;
	private closed = false;

	constructor(root: string, opts?: OpenNuwaDbOptions) {
		this.root = resolve(root);
		this.dbPath = sqliteDbPath(this.root);
		this.db = openNuwaDb(this.root, opts);
	}

	/** 返回底层 `bun:sqlite` Database 实例（供高级只读/调试场景使用）。 */
	get rawDb(): Database {
		if (this.closed) throw new Error(`NuwaSqliteStore 已关闭 (${this.dbPath})`);
		return this.db;
	}

	/** 显式关闭数据库连接。 */
	close(): void {
		if (this.closed) return;
		this.closed = true;
		try {
			this.db.close();
		} catch {
			/* ignore */
		}
	}

	/** 执行 PRAGMA integrity_check 并返回健康结果。 */
	integrityCheck(): {
		ok: boolean;
		journalMode: string;
		busyTimeout: number;
		synchronous: number;
		foreignKeys: number;
		detail: string;
	} {
		const jm = this.db.query("PRAGMA journal_mode").get() as Record<string, unknown> | null;
		const bt = this.db.query("PRAGMA busy_timeout").get() as Record<string, unknown> | null;
		const sy = this.db.query("PRAGMA synchronous").get() as Record<string, unknown> | null;
		const fk = this.db.query("PRAGMA foreign_keys").get() as Record<string, unknown> | null;
		const ic = this.db.query("PRAGMA quick_check(1)").get() as Record<string, unknown> | null;
		const detail = ic ? String(Object.values(ic)[0] ?? "") : "";
		return {
			ok: detail.toLowerCase() === "ok",
			journalMode: jm ? String(Object.values(jm)[0] ?? "").toLowerCase() : "",
			busyTimeout: bt ? Number(Object.values(bt)[0] ?? 0) : 0,
			synchronous: sy ? Number(Object.values(sy)[0] ?? 0) : 0,
			foreignKeys: fk ? Number(Object.values(fk)[0] ?? 0) : 0,
			detail,
		};
	}

	/** 在单条 `BEGIN IMMEDIATE` 事务中原子写入完整 `NuwaState`（同步维护 FTS5 与脱敏）。 */
	saveState(state: NuwaState, opts?: SaveSqliteStateOptions): void {
		if (!state || !state.project) {
			throw new Error("saveStateToSqlite: state 缺少 project 字段");
		}
		const vault = safeLoadVault(this.root, opts?.vault);
		const ts = nowIso();

		const projectCopy: Project = redactUnknownForStorage(
			opts?.touchUpdatedAt ? { ...state.project, updatedAt: ts } : { ...state.project },
			vault,
		);

		const hasAttemptedKeys = state.runtime?.attemptedKeys !== undefined;
		const rawRuntime: Record<string, unknown> = { ...(state.runtime ?? {}) };
		delete rawRuntime.attemptedKeys;
		const runtimeCopy = redactUnknownForStorage(rawRuntime, vault);
		const seqCopy = {
			fact: Number.isFinite(state.seq?.fact) ? Number(state.seq.fact) : 0,
			intent: Number.isFinite(state.seq?.intent) ? Number(state.seq.intent) : 0,
		};

		const hasAssets = state.assets !== undefined;
		const hasHypotheses = state.hypotheses !== undefined;

		const factsList = Object.values(state.facts ?? {}).map((f) => redactUnknownForStorage(f, vault));
		const intentsList = Object.values(state.intents ?? {}).map((i) => redactUnknownForStorage(i, vault));
		const attemptedEntries = Object.entries(state.runtime?.attemptedKeys ?? {}).map(
			([ak, v]) => [ak, redactUnknownForStorage(v, vault)] as const,
		);
		const assetsList = Object.values(state.assets ?? {}).map((a) => redactUnknownForStorage(a, vault));
		const hypsList = Object.values(state.hypotheses ?? {}).map((h) => redactUnknownForStorage(h, vault));

		const tx = this.db.transaction(() => {
			const setMeta = this.db.query(
				"INSERT OR REPLACE INTO meta (key, value, updated_at) VALUES (?, ?, ?)",
			);
			setMeta.run("schema_version", String(SQLITE_SCHEMA_VERSION), ts);
			setMeta.run("nuwa_schema", String(state.schema ?? SCHEMA), ts);
			setMeta.run("nuwa_version", String(state.version ?? "6.0.0"), ts);
			setMeta.run("project_json", JSON.stringify(projectCopy), ts);
			setMeta.run("seq_json", JSON.stringify(seqCopy), ts);
			setMeta.run("runtime_json", JSON.stringify(runtimeCopy), ts);
			setMeta.run("has_attempted_keys", hasAttemptedKeys ? "1" : "0", ts);
			setMeta.run("has_assets", hasAssets ? "1" : "0", ts);
			setMeta.run("has_hypotheses", hasHypotheses ? "1" : "0", ts);

			// 同步替换 facts 与 facts_fts（保持严格一致，免疫 FTS external content 损坏）
			this.db.query("DELETE FROM facts").run();
			this.db.query("DELETE FROM facts_fts").run();
			const insFact = this.db.query(
				`INSERT INTO facts (
					id, kind, title, detail, command, output, intent, fact_key, created_at,
					verified, verify_stage, verify_note, verified_at, verified_by, evidence_seq,
					asset_id, target_key, surface_domain, evidence_ref, meta_json, agent_result_json, extra_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			const insFts = this.db.query(
				`INSERT INTO facts_fts (fact_id, kind, title, detail, command, output, fact_key, target_key)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const f of factsList) {
				const extra = extractExtraFields(f as unknown as Record<string, unknown>, KNOWN_FACT_KEYS);
				insFact.run(
					f.id,
					f.kind,
					f.title,
					f.detail,
					f.command ?? null,
					f.output ?? null,
					f.intent ?? null,
					f.key ?? null,
					f.createdAt,
					f.verified === undefined ? null : f.verified ? 1 : 0,
					f.verifyStage ?? null,
					f.verifyNote ?? null,
					f.verifiedAt ?? null,
					f.verifiedBy ?? null,
					f.evidenceSeq ?? null,
					f.assetId ?? null,
					f.targetKey ?? null,
					f.surfaceDomain ?? null,
					f.evidenceRef ?? null,
					f.meta !== undefined ? JSON.stringify(f.meta) : null,
					f.agentResult !== undefined ? JSON.stringify(f.agentResult) : null,
					extra ? JSON.stringify(extra) : null,
				);
				insFts.run(
					f.id,
					f.kind,
					f.title,
					f.detail,
					f.command ?? "",
					[f.output ?? "", formatFactMetaSearchText(f.meta)].filter(Boolean).join(" "),
					f.key ?? "",
					f.targetKey ?? "",
				);
			}

			// 同步替换 intents
			this.db.query("DELETE FROM intents").run();
			const insIntent = this.db.query(
				`INSERT INTO intents (
					id, phase, intent_key, title, detail, from_json, to_fact_id, status, worker,
					priority, attempts, created_at, claimed_at, done_at, note, next_run_at,
					hypothesis_id, asset_id, auth_role, invalidated_reason, expected_kind,
					surface_domain, target_key, dedup_key, hint_hash, extra_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const it of intentsList) {
				const extra = extractExtraFields(it as unknown as Record<string, unknown>, KNOWN_INTENT_KEYS);
				insIntent.run(
					it.id,
					it.phase,
					it.key,
					it.title,
					it.detail,
					JSON.stringify(it.from ?? []),
					it.to ?? null,
					it.status,
					it.worker ?? null,
					it.priority,
					it.attempts,
					it.createdAt,
					it.claimedAt ?? null,
					it.doneAt ?? null,
					it.note ?? null,
					it.nextRunAt ?? null,
					it.hypothesisId ?? null,
					it.assetId ?? null,
					it.authRole ?? null,
					it.invalidatedReason ?? null,
					it.expectedKind ?? null,
					it.surfaceDomain ?? null,
					it.targetKey ?? null,
					it.dedupKey ?? null,
					it.hintHash ?? null,
					extra ? JSON.stringify(extra) : null,
				);
			}

			// 同步替换 attempted
			this.db.query("DELETE FROM attempted").run();
			const insAttempted = this.db.query(
				`INSERT INTO attempted (
					attempted_key, entry_key, expected_kind, target_key, surface_domain, status, at, from_json, extra_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const [ak, entry] of attemptedEntries) {
				const extra = extractExtraFields(entry as unknown as Record<string, unknown>, KNOWN_ATTEMPTED_KEYS);
				insAttempted.run(
					ak,
					entry.key,
					entry.expectedKind,
					entry.targetKey,
					entry.surfaceDomain,
					entry.status,
					entry.at,
					JSON.stringify(entry.from ?? []),
					extra ? JSON.stringify(extra) : null,
				);
			}

			// 同步替换 assets
			this.db.query("DELETE FROM assets").run();
			const insAsset = this.db.query(
				`INSERT INTO assets (
					id, kind, target, host, port, scheme, reachable_via_json, tags_json, source_fact_id, created_at, extra_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const a of assetsList) {
				const extra = extractExtraFields(a as unknown as Record<string, unknown>, KNOWN_ASSET_KEYS);
				insAsset.run(
					a.id,
					a.kind,
					a.target,
					a.host ?? null,
					a.port ?? null,
					a.scheme ?? null,
					a.reachableVia !== undefined ? JSON.stringify(a.reachableVia) : null,
					a.tags !== undefined ? JSON.stringify(a.tags) : null,
					a.sourceFactId ?? null,
					a.createdAt,
					extra ? JSON.stringify(extra) : null,
				);
			}

			// 同步替换 hypotheses
			this.db.query("DELETE FROM hypotheses").run();
			const insHyp = this.db.query(
				`INSERT INTO hypotheses (
					id, title, statement, required_facts_json, falsification_test,
					expected_gain, estimated_cost, status, linked_intents_json,
					created_at, updated_at, note, extra_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const h of hypsList) {
				const extra = extractExtraFields(h as unknown as Record<string, unknown>, KNOWN_HYPOTHESIS_KEYS);
				insHyp.run(
					h.id,
					h.title,
					h.statement,
					JSON.stringify(h.requiredFacts ?? []),
					h.falsificationTest,
					h.expectedGain,
					h.estimatedCost,
					h.status,
					JSON.stringify(h.linkedIntents ?? []),
					h.createdAt,
					h.updatedAt,
					h.note ?? null,
					extra ? JSON.stringify(extra) : null,
				);
			}
		});

		runWithBusyRetry(() => tx.immediate());
	}

	/** 从 SQLite 完整重建 `NuwaState`；尚未写入项目元数据或缺表时返回 `null`。 */
	loadState(): NuwaState | null {
		if (!hasTable(this.db, "meta")) return null;
		const metaRows = this.db.query("SELECT key, value FROM meta").all() as Array<{ key: string; value: string }>;
		const meta = new Map<string, string>(metaRows.map((r) => [r.key, r.value]));
		const projectRaw = meta.get("project_json");
		if (!projectRaw) return null;

		const project = safeJsonParse<Project | null>(projectRaw, null);
		if (!project) return null;

		const schema = Number(meta.get("nuwa_schema") ?? SCHEMA) || SCHEMA;
		const version = meta.get("nuwa_version") ?? "6.0.0";
		const seq = safeJsonParse<{ fact: number; intent: number }>(meta.get("seq_json"), { fact: 0, intent: 0 });
		const runtime = safeJsonParse<Runtime>(meta.get("runtime_json"), {} as Runtime);

		const facts: Record<string, Fact> = {};
		if (hasTable(this.db, "facts")) {
			for (const r of this.db.query("SELECT * FROM facts").all() as Array<Record<string, any>>) {
				const f = factFromRow(r);
				facts[f.id] = f;
			}
		}

		const intents: Record<string, Intent> = {};
		if (hasTable(this.db, "intents")) {
			for (const r of this.db.query("SELECT * FROM intents").all() as Array<Record<string, any>>) {
				const it = intentFromRow(r);
				intents[it.id] = it;
			}
		}

		const attemptedRows = hasTable(this.db, "attempted")
			? (this.db.query("SELECT * FROM attempted").all() as Array<Record<string, any>>)
			: [];
		if (attemptedRows.length > 0 || meta.get("has_attempted_keys") === "1") {
			const attemptedKeys: Record<string, AttemptedEntry> = {};
			for (const r of attemptedRows) {
				const [ak, entry] = attemptedFromRow(r);
				attemptedKeys[ak] = entry;
			}
			runtime.attemptedKeys = attemptedKeys;
		}

		const state: NuwaState = {
			schema,
			version,
			project,
			facts,
			intents,
			seq,
			runtime,
		};

		const assetRows = hasTable(this.db, "assets")
			? (this.db.query("SELECT * FROM assets").all() as Array<Record<string, any>>)
			: [];
		if (assetRows.length > 0 || meta.get("has_assets") === "1") {
			const assets: Record<string, AssetNode> = {};
			for (const r of assetRows) {
				const node = assetFromRow(r);
				assets[node.id] = node;
			}
			state.assets = assets;
		}

		const hypRows = hasTable(this.db, "hypotheses")
			? (this.db.query("SELECT * FROM hypotheses").all() as Array<Record<string, any>>)
			: [];
		if (hypRows.length > 0 || meta.get("has_hypotheses") === "1") {
			const hypotheses: Record<string, HypothesisNode> = {};
			for (const r of hypRows) {
				const node = hypothesisFromRow(r);
				hypotheses[node.id] = node;
			}
			state.hypotheses = hypotheses;
		}

		return normalizeState(state);
	}

	/** 单条增量写入或更新 Fact，并原子同步 `facts_fts`（适用于高并发局部写入）。 */
	upsertFact(fact: Fact, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeFact = redactUnknownForStorage(fact, vault);
		const extra = extractExtraFields(safeFact as unknown as Record<string, unknown>, KNOWN_FACT_KEYS);

		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO facts (
						id, kind, title, detail, command, output, intent, fact_key, created_at,
						verified, verify_stage, verify_note, verified_at, verified_by, evidence_seq,
						asset_id, target_key, surface_domain, evidence_ref, meta_json, agent_result_json, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					safeFact.id,
					safeFact.kind,
					safeFact.title,
					safeFact.detail,
					safeFact.command ?? null,
					safeFact.output ?? null,
					safeFact.intent ?? null,
					safeFact.key ?? null,
					safeFact.createdAt,
					safeFact.verified === undefined ? null : safeFact.verified ? 1 : 0,
					safeFact.verifyStage ?? null,
					safeFact.verifyNote ?? null,
					safeFact.verifiedAt ?? null,
					safeFact.verifiedBy ?? null,
					safeFact.evidenceSeq ?? null,
					safeFact.assetId ?? null,
					safeFact.targetKey ?? null,
					safeFact.surfaceDomain ?? null,
					safeFact.evidenceRef ?? null,
					safeFact.meta !== undefined ? JSON.stringify(safeFact.meta) : null,
					safeFact.agentResult !== undefined ? JSON.stringify(safeFact.agentResult) : null,
					extra ? JSON.stringify(extra) : null,
				);
			this.db.query("DELETE FROM facts_fts WHERE fact_id = ?").run(safeFact.id);
			this.db
				.query(
					`INSERT INTO facts_fts (fact_id, kind, title, detail, command, output, fact_key, target_key)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					safeFact.id,
					safeFact.kind,
					safeFact.title,
					safeFact.detail,
					safeFact.command ?? "",
					[safeFact.output ?? "", formatFactMetaSearchText(safeFact.meta)].filter(Boolean).join(" "),
					safeFact.key ?? "",
					safeFact.targetKey ?? "",
				);
		});

		runWithBusyRetry(() => tx.immediate());
	}

	/** 全文检索历史 Facts（FTS5 + 参数化 LIKE ESCAPE 混合检索）。 */
	queryFactsByText(query: string, opts?: QueryFactsOptions): FactSearchHit[] {
		return queryFactsOnDb(this.db, query, opts);
	}

	/** 追加 journal 记录并返回自增序列号 `seq`（全量脱敏）。 */
	appendJournal(rec: Record<string, unknown>, opts?: AppendJournalOptions): number {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeRec = redactUnknownForStorage({ ts: nowIso(), ...rec }, vault);
		const ts = typeof safeRec.ts === "string" && safeRec.ts.trim() ? safeRec.ts : nowIso();
		const type = typeof safeRec.type === "string" && safeRec.type.trim() ? safeRec.type : "event";
		const payloadJson = JSON.stringify(safeRec);
		const dedupHash = opts?.dedupHash ?? null;

		let insertedSeq = 0;
		const tx = this.db.transaction(() => {
			if (dedupHash) {
				const res = this.db
					.query("INSERT OR IGNORE INTO journal (ts, type, dedup_hash, payload_json) VALUES (?, ?, ?, ?)")
					.run(ts, type, dedupHash, payloadJson);
				insertedSeq = Number(res.lastInsertRowid ?? 0);
			} else {
				const res = this.db
					.query("INSERT INTO journal (ts, type, dedup_hash, payload_json) VALUES (?, ?, NULL, ?)")
					.run(ts, type, payloadJson);
				insertedSeq = Number(res.lastInsertRowid ?? 0);
			}
		});
		runWithBusyRetry(() => tx.immediate());
		return insertedSeq;
	}

	/** 读取最近 N 条 journal 记录（按时间正序返回，与 `readJournalTail` 一致）。 */
	readJournalTail(limit = 200): JournalEntry[] {
		const n = clampInt(limit, 200, 1, 5000);
		const rows = this.db
			.query("SELECT payload_json FROM journal ORDER BY seq DESC LIMIT ?")
			.all(n) as Array<{ payload_json: string }>;
		return rows
			.reverse()
			.map((r) => safeJsonParse<JournalEntry | null>(r.payload_json, null))
			.filter((x): x is JournalEntry => x !== null);
	}

	/** 写入执行证据账本条目（全量脱敏，支持幂等按 `seq` 写入）。 */
	appendExecLedger(entry: ExecLedgerEntry, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeEntry = redactUnknownForStorage(entry, vault);
		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO exec_ledger (
						seq, ts, tool, command, session_id, agent_name, sha1, norm_sha1, bytes, snippet, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					safeEntry.seq,
					safeEntry.ts,
					safeEntry.tool,
					safeEntry.command ?? null,
					safeEntry.sessionId ?? null,
					safeEntry.agentName ?? null,
					safeEntry.sha1,
					safeEntry.normSha1,
					safeEntry.bytes,
					safeEntry.snippet,
					null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 读取最近 N 条执行证据账本记录。 */
	listExecLedger(limit = 200): ExecLedgerEntry[] {
		const n = clampInt(limit, 200, 1, 2000);
		const rows = this.db
			.query("SELECT * FROM exec_ledger ORDER BY seq DESC LIMIT ?")
			.all(n) as Array<Record<string, any>>;
		return rows.reverse().map((r) => ({
			seq: Number(r.seq),
			ts: String(r.ts),
			tool: String(r.tool),
			...(r.command !== null && r.command !== undefined ? { command: String(r.command) } : {}),
			...(r.session_id !== null && r.session_id !== undefined ? { sessionId: String(r.session_id) } : {}),
			...(r.agent_name !== null && r.agent_name !== undefined ? { agentName: String(r.agent_name) } : {}),
			sha1: String(r.sha1),
			normSha1: String(r.norm_sha1),
			bytes: Number(r.bytes),
			snippet: String(r.snippet),
		}));
	}

	/** 写入或更新自校准预测/结算记录（全量脱敏）。 */
	upsertCalibrationRecord(record: CalibrationRecordRow, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeRec = redactUnknownForStorage(record, vault);
		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO calibration_records (
						prediction_id, intent_id, task_category, model_id, predicted_confidence,
						estimated_tokens, outcome, is_false_positive, actual_tokens, duration_ms,
						source, settled, created_at, settled_at, payload_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					safeRec.predictionId,
					safeRec.intentId ?? null,
					safeRec.taskCategory,
					safeRec.modelId,
					safeRec.predictedConfidence,
					safeRec.estimatedTokens ?? null,
					safeRec.outcome ?? null,
					safeRec.isFalsePositive === undefined ? null : safeRec.isFalsePositive ? 1 : 0,
					safeRec.actualTokens ?? null,
					safeRec.durationMs ?? null,
					safeRec.source ?? null,
					safeRec.settled ? 1 : 0,
					safeRec.createdAt,
					safeRec.settledAt ?? null,
					safeRec.payload ? JSON.stringify(safeRec.payload) : null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 查询自校准记录。 */
	listCalibrationRecords(opts?: { modelId?: string; taskCategory?: string; settledOnly?: boolean; limit?: number }): CalibrationRecordRow[] {
		const clauses: string[] = [];
		const params: Array<string | number> = [];
		if (opts?.modelId) {
			clauses.push("model_id = ?");
			params.push(opts.modelId);
		}
		if (opts?.taskCategory) {
			clauses.push("task_category = ?");
			params.push(opts.taskCategory);
		}
		if (opts?.settledOnly) {
			clauses.push("settled = 1");
		}
		const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
		const limit = clampInt(opts?.limit, 1000, 1, 5000);
		const rows = this.db
			.query(`SELECT * FROM calibration_records ${where} ORDER BY created_at ASC LIMIT ?`)
			.all(...params, limit) as Array<Record<string, any>>;

		return rows.map((r) => ({
			predictionId: String(r.prediction_id),
			...(r.intent_id !== null && r.intent_id !== undefined ? { intentId: String(r.intent_id) } : {}),
			taskCategory: String(r.task_category),
			modelId: String(r.model_id),
			predictedConfidence: Number(r.predicted_confidence),
			...(r.estimated_tokens !== null && r.estimated_tokens !== undefined ? { estimatedTokens: Number(r.estimated_tokens) } : {}),
			...(r.outcome !== null && r.outcome !== undefined ? { outcome: Number(r.outcome) } : {}),
			...(r.is_false_positive !== null && r.is_false_positive !== undefined
				? { isFalsePositive: Number(r.is_false_positive) !== 0 }
				: {}),
			...(r.actual_tokens !== null && r.actual_tokens !== undefined ? { actualTokens: Number(r.actual_tokens) } : {}),
			...(r.duration_ms !== null && r.duration_ms !== undefined ? { durationMs: Number(r.duration_ms) } : {}),
			...(r.source !== null && r.source !== undefined ? { source: String(r.source) } : {}),
			settled: Number(r.settled) !== 0,
			createdAt: String(r.created_at),
			...(r.settled_at !== null && r.settled_at !== undefined ? { settledAt: String(r.settled_at) } : {}),
			...(r.payload_json ? { payload: safeJsonParse<Record<string, unknown>>(r.payload_json, {}) } : {}),
		}));
	}

	/** 写入脱敏后的 HTTP 流量记录（对请求/响应头与正文强制执行零明文凭据掩码）。 */
	appendTrafficEntry(entry: TrafficEntryRow, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const reqHeaders = redactHeadersRecord(entry.requestHeaders, vault);
		const resHeaders = redactHeadersRecord(entry.responseHeaders, vault);
		const reqPreview = redactTextForStorage(entry.requestBodyPreview, vault);
		const resPreview = redactTextForStorage(entry.responseBodyPreview, vault);
		const safeUrl = redactTextForStorage(entry.url, vault) ?? entry.url;
		const safePath = redactTextForStorage(entry.path, vault) ?? entry.path;
		const safePayload = entry.payload ? redactUnknownForStorage(entry.payload, vault) : undefined;

		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO traffic_entries (
						id, ts, method, url, host, path, status, duration_ms,
						request_headers_json, request_body_preview,
						response_headers_json, response_body_preview,
						tags_json, redacted, payload_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
				)
				.run(
					entry.id,
					entry.ts,
					entry.method.toUpperCase(),
					safeUrl,
					entry.host.toLowerCase(),
					safePath,
					entry.status,
					entry.durationMs ?? null,
					reqHeaders ? JSON.stringify(reqHeaders) : null,
					reqPreview ?? null,
					resHeaders ? JSON.stringify(resHeaders) : null,
					resPreview ?? null,
					entry.tags ? JSON.stringify(entry.tags) : null,
					safePayload ? JSON.stringify(safePayload) : null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 按条件检索流量条目。 */
	queryTrafficEntries(filter?: TrafficQueryFilter): TrafficEntryRow[] {
		const clauses: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.host) {
			clauses.push("host = ?");
			params.push(filter.host.toLowerCase());
		}
		if (filter?.pathPrefix) {
			clauses.push("path LIKE ? ESCAPE '\\'");
			params.push(`${escapeLike(filter.pathPrefix)}%`);
		}
		if (filter?.method) {
			clauses.push("method = ?");
			params.push(filter.method.toUpperCase());
		}
		if (typeof filter?.status === "number") {
			clauses.push("status = ?");
			params.push(filter.status);
		}
		const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
		const limit = clampInt(filter?.limit, 200, 1, 2000);
		const rows = this.db
			.query(`SELECT * FROM traffic_entries ${where} ORDER BY ts DESC LIMIT ?`)
			.all(...params, limit) as Array<Record<string, any>>;

		return rows.map((r) => ({
			id: String(r.id),
			ts: String(r.ts),
			method: String(r.method),
			url: String(r.url),
			host: String(r.host),
			path: String(r.path),
			status: Number(r.status),
			...(r.duration_ms !== null && r.duration_ms !== undefined ? { durationMs: Number(r.duration_ms) } : {}),
			...(r.request_headers_json
				? { requestHeaders: safeJsonParse<Record<string, string>>(r.request_headers_json, {}) }
				: {}),
			...(r.request_body_preview !== null && r.request_body_preview !== undefined
				? { requestBodyPreview: String(r.request_body_preview) }
				: {}),
			...(r.response_headers_json
				? { responseHeaders: safeJsonParse<Record<string, string>>(r.response_headers_json, {}) }
				: {}),
			...(r.response_body_preview !== null && r.response_body_preview !== undefined
				? { responseBodyPreview: String(r.response_body_preview) }
				: {}),
			...(r.tags_json ? { tags: safeJsonParse<string[]>(r.tags_json, []) } : {}),
			redacted: Number(r.redacted) !== 0,
			...(r.payload_json ? { payload: safeJsonParse<Record<string, unknown>>(r.payload_json, {}) } : {}),
		}));
	}
}

// ============================================================================
// 函数式便捷导出接口
// ============================================================================

/** 从 `.nuwa/nuwa.db` 只读加载完整 `NuwaState`（零写事务、不抢写锁）；不存在返回 `null`，坏库按选项抛出诊断异常或回退 JSON。 */
export function loadStateFromSqlite(root: string, opts?: LoadSqliteStateOptions): NuwaState | null {
	const normRoot = resolve(root);
	const dbFile = sqliteDbPath(normRoot);
	if (!existsSync(dbFile)) return null;

	let store: NuwaSqliteStore | null = null;
	try {
		store = new NuwaSqliteStore(normRoot, { readonly: true });
		return store.loadState();
	} catch (err) {
		const corruptErr =
			err instanceof NuwaSqliteCorruptError
				? err
				: isCorruptError(err)
					? new NuwaSqliteCorruptError(dbFile, err instanceof Error ? err.message : String(err))
					: null;
		if (corruptErr) {
			if (opts?.fallbackToJson) {
				opts.onCorruptWarning?.(corruptErr.message, corruptErr);
				return loadStateJsonOnly(normRoot);
			}
			throw corruptErr;
		}
		throw err;
	} finally {
		store?.close();
	}
}

/** 将 `NuwaState` 原子写入 `.nuwa/nuwa.db`（自动脱敏并更新 FTS5 全文检索索引）。 */
export function saveStateToSqlite(root: string, state: NuwaState, opts?: SaveSqliteStateOptions): void {
	const store = new NuwaSqliteStore(root);
	try {
		store.saveState(state, opts);
	} finally {
		store.close();
	}
}

/** 向 `.nuwa/nuwa.db` 的 `journal` 表追加一条事件记录（全量脱敏）并返回自增 `seq`。 */
export function appendJournalSqlite(
	root: string,
	rec: Record<string, unknown>,
	opts?: AppendJournalOptions,
): number {
	const store = new NuwaSqliteStore(root);
	try {
		return store.appendJournal(rec, opts);
	} finally {
		store.close();
	}
}

/**
 * 全文检索历史 Facts（同时兼容传入项目根目录 `root`、已有 `Database` 或 `NuwaSqliteStore` 实例）。
 * 传入项目根目录时采用纯只读连接（零写事务、不修改文件元数据、不争抢写锁）。
 */
export function queryFactsByText(
	rootOrDb: string | Database | NuwaSqliteStore,
	query: string,
	opts?: QueryFactsOptions,
): FactSearchHit[] {
	if (rootOrDb instanceof NuwaSqliteStore) {
		return rootOrDb.queryFactsByText(query, opts);
	}
	if (typeof rootOrDb === "string") {
		const normRoot = resolve(rootOrDb);
		const dbFile = sqliteDbPath(normRoot);
		if (!existsSync(dbFile)) return [];
		const store = new NuwaSqliteStore(normRoot, { readonly: true });
		try {
			return store.queryFactsByText(query, opts);
		} catch (err) {
			if (isCorruptError(err) && !(err instanceof NuwaSqliteCorruptError)) {
				throw new NuwaSqliteCorruptError(dbFile, err instanceof Error ? err.message : String(err));
			}
			throw err;
		} finally {
			store.close();
		}
	}
	return queryFactsOnDb(rootOrDb, query, opts);
}

function readJsonlLinesSafe(filePath: string): Array<{ lineIndex: number; raw: string; parsed: Record<string, unknown> }> {
	if (!existsSync(filePath)) return [];
	try {
		const content = readFileSync(filePath, "utf8");
		const out: Array<{ lineIndex: number; raw: string; parsed: Record<string, unknown> }> = [];
		const lines = content.split("\n");
		for (let i = 0; i < lines.length; i++) {
			const trimmed = lines[i]?.trim() ?? "";
			if (!trimmed) continue;
			try {
				const parsed = JSON.parse(trimmed);
				if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
					out.push({ lineIndex: i, raw: trimmed, parsed: parsed as Record<string, unknown> });
				}
			} catch {
				/* 跳过损坏行 */
			}
		}
		return out;
	} catch {
		return [];
	}
}

/**
 * 幂等迁移存量 `.nuwa/state.json`、`journal.jsonl`（以及可选的 `exec-ledger.jsonl`、`calibration.jsonl`、`traffic/index.jsonl`）至 `.nuwa/nuwa.db`。
 * 多次重复执行绝不产生重复 journal/账本记录，且默认不覆盖 SQLite 中已有的更新状态（传 `force: true` 除外）。
 */
export function migrateJsonToSqlite(root: string, opts?: MigrateJsonOptions): MigrateJsonResult {
	const normRoot = resolve(root);
	const vault = safeLoadVault(normRoot, opts?.vault);
	const store = new NuwaSqliteStore(normRoot);
	try {
		let migratedState = false;
		let stateSkipped = false;
		let factsCount = 0;
		let intentsCount = 0;
		let attemptedCount = 0;
		let assetsCount = 0;
		let hypothesesCount = 0;

		const existing = store.loadState();
		const jsonState = loadStateJsonOnly(normRoot);

		if (jsonState) {
			if (!existing || opts?.force === true) {
				store.saveState(jsonState, { vault });
				migratedState = true;
				factsCount = Object.keys(jsonState.facts ?? {}).length;
				intentsCount = Object.keys(jsonState.intents ?? {}).length;
				attemptedCount = Object.keys(jsonState.runtime?.attemptedKeys ?? {}).length;
				assetsCount = Object.keys(jsonState.assets ?? {}).length;
				hypothesesCount = Object.keys(jsonState.hypotheses ?? {}).length;
			} else {
				stateSkipped = true;
				factsCount = Object.keys(existing.facts ?? {}).length;
				intentsCount = Object.keys(existing.intents ?? {}).length;
				attemptedCount = Object.keys(existing.runtime?.attemptedKeys ?? {}).length;
				assetsCount = Object.keys(existing.assets ?? {}).length;
				hypothesesCount = Object.keys(existing.hypotheses ?? {}).length;
			}
		} else if (existing) {
			stateSkipped = true;
			factsCount = Object.keys(existing.facts ?? {}).length;
			intentsCount = Object.keys(existing.intents ?? {}).length;
			attemptedCount = Object.keys(existing.runtime?.attemptedKeys ?? {}).length;
			assetsCount = Object.keys(existing.assets ?? {}).length;
			hypothesesCount = Object.keys(existing.hypotheses ?? {}).length;
		}

		// 幂等迁移 journal.jsonl（含可选归档）
		const journalFiles: Array<{ label: string; fullPath: string }> = [];
		if (opts?.includeJournalArchives) {
			try {
				const dir = stateDir(normRoot);
				const arcs = readdirSync(dir)
					.filter((f) => /^journal\..+\.jsonl$/.test(f))
					.sort();
				for (const f of arcs) {
					journalFiles.push({ label: f, fullPath: join(dir, f) });
				}
			} catch {
				/* ignore */
			}
		}
		journalFiles.push({ label: "journal.jsonl", fullPath: journalPath(normRoot) });

		let journalInserted = 0;
		let journalSkipped = 0;
		const db = store.rawDb;

		const journalTx = db.transaction(() => {
			const ins = db.query(
				"INSERT OR IGNORE INTO journal (ts, type, dedup_hash, payload_json) VALUES (?, ?, ?, ?)",
			);
			for (const jf of journalFiles) {
				const records = readJsonlLinesSafe(jf.fullPath);
				for (const { lineIndex, raw, parsed } of records) {
					const dedupHash = sha256Hex(`journal|${jf.label}|${lineIndex}|${raw}`);
					const safeRec = redactUnknownForStorage(parsed, vault);
					const ts = typeof safeRec.ts === "string" && safeRec.ts.trim() ? safeRec.ts : nowIso();
					const type = typeof safeRec.type === "string" && safeRec.type.trim() ? safeRec.type : "event";
					const res = ins.run(ts, type, dedupHash, JSON.stringify(safeRec));
					if (Number(res.changes ?? 0) > 0) journalInserted += 1;
					else journalSkipped += 1;
				}
			}
		});
		runWithBusyRetry(() => journalTx.immediate());

		// 幂等迁移 exec-ledger.jsonl（若存在）
		let execLedgerInserted = 0;
		const execLedgerFile = join(stateDir(normRoot), "exec-ledger.jsonl");
		const execLines = readJsonlLinesSafe(execLedgerFile);
		if (execLines.length > 0) {
			const execTx = db.transaction(() => {
				const ins = db.query(
					`INSERT OR IGNORE INTO exec_ledger (
						seq, ts, tool, command, session_id, agent_name, sha1, norm_sha1, bytes, snippet, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				);
				for (const { lineIndex, parsed } of execLines) {
					const safe = redactUnknownForStorage(parsed, vault);
					const seq =
						typeof safe.seq === "number" && Number.isFinite(safe.seq) && safe.seq > 0
							? Math.floor(safe.seq)
							: lineIndex + 1;
					const res = ins.run(
						seq,
						typeof safe.ts === "string" ? safe.ts : nowIso(),
						typeof safe.tool === "string" ? safe.tool : "unknown",
						typeof safe.command === "string" ? safe.command : null,
						typeof safe.sessionId === "string" ? safe.sessionId : null,
						typeof safe.agentName === "string" ? safe.agentName : null,
						typeof safe.sha1 === "string" ? safe.sha1 : sha256Hex(String(safe.snippet ?? "")).slice(0, 40),
						typeof safe.normSha1 === "string" ? safe.normSha1 : sha256Hex(String(safe.snippet ?? "")).slice(0, 40),
						typeof safe.bytes === "number" && Number.isFinite(safe.bytes) ? safe.bytes : 0,
						typeof safe.snippet === "string" ? safe.snippet : "",
						null,
					);
					if (Number(res.changes ?? 0) > 0) execLedgerInserted += 1;
				}
			});
			runWithBusyRetry(() => execTx.immediate());
		}

		// 幂等迁移 calibration.jsonl（若存在）
		let calibrationInserted = 0;
		const calibFile = join(stateDir(normRoot), "calibration.jsonl");
		const calibLines = readJsonlLinesSafe(calibFile);
		if (calibLines.length > 0) {
			const calibTx = db.transaction(() => {
				const ins = db.query(
					`INSERT OR IGNORE INTO calibration_records (
						prediction_id, intent_id, task_category, model_id, predicted_confidence,
						estimated_tokens, outcome, is_false_positive, actual_tokens, duration_ms,
						source, settled, created_at, settled_at, payload_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				);
				for (const { lineIndex, parsed } of calibLines) {
					const safe = redactUnknownForStorage(parsed, vault);
					const pid =
						typeof safe.predictionId === "string" && safe.predictionId.trim()
							? safe.predictionId.trim()
							: `mig-cal-${lineIndex}`;
					const res = ins.run(
						pid,
						typeof safe.intentId === "string" ? safe.intentId : null,
						typeof safe.taskCategory === "string" ? safe.taskCategory : "general",
						typeof safe.modelId === "string" ? safe.modelId : "unknown",
						typeof safe.predictedConfidence === "number" ? safe.predictedConfidence : 0.5,
						typeof safe.estimatedTokens === "number" ? safe.estimatedTokens : null,
						typeof safe.outcome === "number" ? safe.outcome : null,
						typeof safe.isFalsePositive === "boolean" ? (safe.isFalsePositive ? 1 : 0) : null,
						typeof safe.actualTokens === "number" ? safe.actualTokens : null,
						typeof safe.durationMs === "number" ? safe.durationMs : null,
						typeof safe.source === "string" ? safe.source : null,
						safe.settled === true || safe.outcome !== undefined ? 1 : 0,
						typeof safe.createdAt === "string" ? safe.createdAt : nowIso(),
						typeof safe.settledAt === "string" ? safe.settledAt : null,
						JSON.stringify(safe),
					);
					if (Number(res.changes ?? 0) > 0) calibrationInserted += 1;
				}
			});
			runWithBusyRetry(() => calibTx.immediate());
		}

		// 幂等迁移 traffic/index.jsonl（若存在）
		let trafficInserted = 0;
		const trafficFile = join(stateDir(normRoot), "traffic", "index.jsonl");
		const trafficLines = readJsonlLinesSafe(trafficFile);
		if (trafficLines.length > 0) {
			const trafficTx = db.transaction(() => {
				const ins = db.query(
					`INSERT OR IGNORE INTO traffic_entries (
						id, ts, method, url, host, path, status, duration_ms,
						request_headers_json, request_body_preview,
						response_headers_json, response_body_preview,
						tags_json, redacted, payload_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
				);
				for (const { lineIndex, parsed } of trafficLines) {
					const safe = redactUnknownForStorage(parsed, vault);
					const id = typeof safe.id === "string" && safe.id.trim() ? safe.id.trim() : `mig-tr-${lineIndex}`;
					const reqH =
						safe.requestHeaders && typeof safe.requestHeaders === "object" && !Array.isArray(safe.requestHeaders)
							? redactHeadersRecord(safe.requestHeaders as Record<string, string>, vault)
							: undefined;
					const resH =
						safe.responseHeaders && typeof safe.responseHeaders === "object" && !Array.isArray(safe.responseHeaders)
							? redactHeadersRecord(safe.responseHeaders as Record<string, string>, vault)
							: undefined;
					const res = ins.run(
						id,
						typeof safe.ts === "string" ? safe.ts : nowIso(),
						typeof safe.method === "string" ? safe.method.toUpperCase() : "GET",
						typeof safe.url === "string" ? safe.url : "",
						typeof safe.host === "string" ? safe.host.toLowerCase() : "",
						typeof safe.path === "string" ? safe.path : "/",
						typeof safe.status === "number" ? safe.status : 0,
						typeof safe.durationMs === "number" ? safe.durationMs : null,
						reqH ? JSON.stringify(reqH) : null,
						typeof safe.requestBodyPreview === "string" ? safe.requestBodyPreview : null,
						resH ? JSON.stringify(resH) : null,
						typeof safe.responseBodyPreview === "string" ? safe.responseBodyPreview : null,
						Array.isArray(safe.tags) ? JSON.stringify(safe.tags) : null,
						JSON.stringify(safe),
					);
					if (Number(res.changes ?? 0) > 0) trafficInserted += 1;
				}
			});
			runWithBusyRetry(() => trafficTx.immediate());
		}

		if (migratedState || journalInserted > 0 || execLedgerInserted > 0 || calibrationInserted > 0 || trafficInserted > 0) {
			const markTx = db.transaction(() => {
				db.query("INSERT OR REPLACE INTO meta (key, value, updated_at) VALUES (?, ?, ?)").run(
					"migrated_at",
					nowIso(),
					nowIso(),
				);
			});
			runWithBusyRetry(() => markTx.immediate());
		}

		return {
			ok: true,
			dbPath: store.dbPath,
			migratedState,
			stateSkipped,
			factsCount,
			intentsCount,
			attemptedCount,
			assetsCount,
			hypothesesCount,
			journalInserted,
			journalSkipped,
			execLedgerInserted,
			calibrationInserted,
			trafficInserted,
		};
	} finally {
		store.close();
	}
}

/**
 * 从 `.nuwa/nuwa.db` 导出与 v5.x 完全兼容的 `.nuwa/state.json`（默认原子写盘）。
 */
export function exportStateJsonCompat(root: string, opts?: ExportCompatOptions): ExportCompatResult {
	const normRoot = resolve(root);
	const outPath = opts?.outputPath ? resolve(opts.outputPath) : statePath(normRoot);
	const state = loadStateFromSqlite(normRoot);
	if (!state) {
		return {
			ok: false,
			path: outPath,
			bytes: 0,
			state: null,
			json: "",
		};
	}
	const json = JSON.stringify(state, null, 2);
	const bytes = Buffer.byteLength(json, "utf8");
	if (opts?.writeFile !== false) {
		atomicWrite(outPath, json);
	}
	return {
		ok: true,
		path: outPath,
		bytes,
		state,
		json,
	};
}
