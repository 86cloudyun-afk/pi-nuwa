/**
 * 女娲 v8.0.0 SQLite Schema v2 定义、行结构双向映射与平滑无损迁移模块。
 *
 * 职责：
 * 1. 定义权威 `SQLITE_SCHEMA_VERSION = 2` 及 10 张 v1 核心表（含 `facts_fts`）+ 4 张 v2 扩展表：
 *    - `protocol_frames`：GraphQL / WebSocket / Next.js RSC / gRPC-Web 协议帧审计台账（强制脱敏）；
 *    - `asset_credentials`：跨资产凭据复用验证矩阵与角色新鲜度索引（仅存指纹与掩码预览，零明文）；
 *    - `oob_correlations`：延迟异步 OOB 回调因果归因上下文台账；
 *    - `workflow_runs`：全方法有状态工作流链、Mass Assignment、二阶验证与并发屏障竞态运行记录。
 * 2. 提供幂等无损自动迁移函数 `migrateSqliteSchemaV1ToV2`：旧版 v1 库在首次读写打开时自动补齐 4 张新表并升级 `meta.schema_version = "2"`，保留全部存量数据零丢失。
 * 3. 严守只读零写盘红线：只读连接绝不调用迁移或建表，确保历史 v1 `nuwa.db` 只读打开 0 字节写盘且不报错。
 *
 * 约束：纯底层模块，严禁运行时 `import "./nuwa"`、`./graph`、`./storage` 或 `./sqlite-store`。
 */
import type { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { maskSecretValue, redactVaultSecrets, type SessionVault } from "./session-vault";
import { SCHEMA, nowIso } from "./storage-io";
import type {
	AssetNode,
	AttemptedEntry,
	Fact,
	FactKind,
	HypothesisNode,
	Intent,
	SurfaceDomain,
	VerifyStage,
} from "./types";

export const SQLITE_SCHEMA_VERSION = 2;

export const V1_CORE_TABLES = [
	"meta",
	"facts",
	"intents",
	"attempted",
	"assets",
	"hypotheses",
	"journal",
	"exec_ledger",
	"calibration_records",
	"traffic_entries",
] as const;

export const V2_EXTENSION_TABLES = [
	"protocol_frames",
	"asset_credentials",
	"oob_correlations",
	"workflow_runs",
] as const;

export const ALL_SQLITE_TABLES = [...V1_CORE_TABLES, ...V2_EXTENSION_TABLES] as const;

export type V1CoreTableName = (typeof V1_CORE_TABLES)[number];
export type V2ExtensionTableName = (typeof V2_EXTENSION_TABLES)[number];
export type SqliteTableName = (typeof ALL_SQLITE_TABLES)[number];

// ============================================================================
// v2 新增 4 张扩展表结构化行接口定义
// ============================================================================

export type ProtocolFrameKind = "graphql" | "websocket" | "rsc" | "grpc_web" | string;
export type ProtocolFrameDirection = "send" | "receive" | "request" | "response" | "bidirectional";

export interface ProtocolFrameRow {
	id: string;
	ts: string;
	protocol: ProtocolFrameKind;
	direction: ProtocolFrameDirection;
	url: string;
	host: string;
	operationName?: string;
	role?: string;
	status?: number;
	frameSeq?: number;
	headers?: Record<string, string>;
	payloadPreview?: string;
	schemaSummary?: Record<string, unknown>;
	anomalyTag?: string;
	redacted?: boolean;
	extra?: Record<string, unknown>;
}

export type AssetCredentialStatus = "valid" | "rejected" | "expired" | "scope_blocked" | "unverified";

export interface AssetCredentialRow {
	id: string;
	assetId: string;
	host: string;
	port?: number;
	role: string;
	credKind: string;
	/** 凭据 SHA-256 指纹摘要（严禁存入明文口令/Token/Cookie）。 */
	credFingerprint: string;
	/** 经掩码脱敏后的安全预览串。 */
	maskedPreview?: string;
	status: AssetCredentialStatus;
	sourceAssetId?: string;
	verifiedEndpoint?: string;
	verifiedStatusCode?: number;
	expiresAt?: string;
	lastVerifiedAt?: string;
	createdAt: string;
	updatedAt: string;
	extra?: Record<string, unknown>;
}

export type OobCorrelationStatus = "pending" | "correlated" | "expired";

export interface OobCorrelationRow {
	canaryId: string;
	projectId: string;
	intentId?: string;
	factId?: string;
	endpoint: string;
	paramName?: string;
	templateHash?: string;
	authRole?: string;
	channel: string;
	tokenSig?: string;
	status: OobCorrelationStatus;
	callbackTs?: string;
	callbackSourceIp?: string;
	callbackDetail?: string;
	createdAt: string;
	extra?: Record<string, unknown>;
}

export type WorkflowActionLevel =
	| "L0_PHYSICAL_READ"
	| "L1_SEMANTIC_READ"
	| "L2_SCOPED_STATEFUL"
	| "L3_RESTRICTED_DESTRUCTIVE";

export interface WorkflowRunRow {
	runId: string;
	workflowKind: string;
	actionLevel: WorkflowActionLevel | string;
	intentId?: string;
	targetUrl: string;
	role?: string;
	status: string;
	stepCount: number;
	brokenAtStep?: number;
	cleanupExecuted: boolean;
	candidateFactId?: string;
	startedAt: string;
	finishedAt?: string;
	summary?: string;
	steps?: Array<Record<string, unknown>>;
	extra?: Record<string, unknown>;
}

export interface SqliteSchemaMigrationResult {
	migrated: boolean;
	previousVersion: number;
	currentVersion: number;
	createdTables: string[];
}

// ============================================================================
// DDL 定义（10 张 v1 核心表 + FTS5 全文检索索引 + 4 张 v2 扩展表）
// ============================================================================

export const V1_CORE_DDL = `
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

export const V2_EXTENSION_DDL = `
CREATE TABLE IF NOT EXISTS protocol_frames (
	id TEXT PRIMARY KEY NOT NULL,
	ts TEXT NOT NULL,
	protocol TEXT NOT NULL,
	direction TEXT NOT NULL DEFAULT 'bidirectional',
	url TEXT NOT NULL,
	host TEXT NOT NULL,
	operation_name TEXT,
	role TEXT,
	status INTEGER,
	frame_seq INTEGER,
	headers_json TEXT,
	payload_preview TEXT,
	schema_summary_json TEXT,
	anomaly_tag TEXT,
	redacted INTEGER NOT NULL DEFAULT 1,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_protocol_frames_proto_host ON protocol_frames(protocol, host);
CREATE INDEX IF NOT EXISTS idx_protocol_frames_ts ON protocol_frames(ts);
CREATE INDEX IF NOT EXISTS idx_protocol_frames_op ON protocol_frames(operation_name);

CREATE TABLE IF NOT EXISTS asset_credentials (
	id TEXT PRIMARY KEY NOT NULL,
	asset_id TEXT NOT NULL,
	host TEXT NOT NULL,
	port INTEGER,
	role TEXT NOT NULL,
	cred_kind TEXT NOT NULL,
	cred_fingerprint TEXT NOT NULL,
	masked_preview TEXT,
	status TEXT NOT NULL DEFAULT 'unverified',
	source_asset_id TEXT,
	verified_endpoint TEXT,
	verified_status_code INTEGER,
	expires_at TEXT,
	last_verified_at TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_asset_creds_asset_role ON asset_credentials(asset_id, role);
CREATE INDEX IF NOT EXISTS idx_asset_creds_host ON asset_credentials(host);
CREATE INDEX IF NOT EXISTS idx_asset_creds_status ON asset_credentials(status);

CREATE TABLE IF NOT EXISTS oob_correlations (
	canary_id TEXT PRIMARY KEY NOT NULL,
	project_id TEXT NOT NULL,
	intent_id TEXT,
	fact_id TEXT,
	endpoint TEXT NOT NULL,
	param_name TEXT,
	template_hash TEXT,
	auth_role TEXT,
	channel TEXT NOT NULL DEFAULT 'http',
	token_sig TEXT,
	status TEXT NOT NULL DEFAULT 'pending',
	callback_ts TEXT,
	callback_source_ip TEXT,
	callback_detail TEXT,
	created_at TEXT NOT NULL,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_oob_corr_status ON oob_correlations(status);
CREATE INDEX IF NOT EXISTS idx_oob_corr_intent ON oob_correlations(intent_id);
CREATE INDEX IF NOT EXISTS idx_oob_corr_created ON oob_correlations(created_at);

CREATE TABLE IF NOT EXISTS workflow_runs (
	run_id TEXT PRIMARY KEY NOT NULL,
	workflow_kind TEXT NOT NULL,
	action_level TEXT NOT NULL,
	intent_id TEXT,
	target_url TEXT NOT NULL,
	role TEXT,
	status TEXT NOT NULL,
	step_count INTEGER NOT NULL DEFAULT 0,
	broken_at_step INTEGER,
	cleanup_executed INTEGER NOT NULL DEFAULT 0,
	candidate_fact_id TEXT,
	started_at TEXT NOT NULL,
	finished_at TEXT,
	summary TEXT,
	steps_json TEXT,
	extra_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_kind_status ON workflow_runs(workflow_kind, status);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_intent ON workflow_runs(intent_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_started ON workflow_runs(started_at);
`;

export const CORE_DDL = `${V1_CORE_DDL}\n${V2_EXTENSION_DDL}`;

export function hasSqliteTable(db: Database, name: string): boolean {
	try {
		const row = db
			.query("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?")
			.get(name) as { name?: string } | null;
		return Boolean(row?.name);
	} catch {
		return false;
	}
}

export function readSqliteSchemaVersion(db: Database): number {
	if (!hasSqliteTable(db, "meta")) return 0;
	try {
		const row = db.query("SELECT value FROM meta WHERE key = 'schema_version'").get() as { value?: string } | null;
		const parsed = Number(row?.value ?? 0);
		return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : 0;
	} catch {
		return 0;
	}
}

/**
 * 幂等无损将 SQLite Schema v1 平滑迁移至 v2：
 * - 自动检测缺失的 4 张 v2 扩展表（`protocol_frames`、`asset_credentials`、`oob_correlations`、`workflow_runs`）并补齐；
 * - 绝不删除、清空或篡改已有 10 张 v1 核心表与历史记录；
 * - 升级 `meta.schema_version = "2"`；已处于 v2 且 4 张扩展表齐全时零写事务直接幂等返回。
 */
export function migrateSqliteSchemaV1ToV2(
	db: Database,
	opts?: { now?: string },
): SqliteSchemaMigrationResult {
	const previousVersion = readSqliteSchemaVersion(db);
	const missingTables = V2_EXTENSION_TABLES.filter((tbl) => !hasSqliteTable(db, tbl));

	if (previousVersion >= SQLITE_SCHEMA_VERSION && missingTables.length === 0) {
		return {
			migrated: false,
			previousVersion,
			currentVersion: previousVersion,
			createdTables: [],
		};
	}

	const ts = opts?.now ?? nowIso();
	const targetVersion = Math.max(previousVersion, SQLITE_SCHEMA_VERSION);
	const tx = db.transaction(() => {
		if (!hasSqliteTable(db, "meta")) {
			db.exec(`
				CREATE TABLE IF NOT EXISTS meta (
					key TEXT PRIMARY KEY NOT NULL,
					value TEXT NOT NULL,
					updated_at TEXT NOT NULL
				);
			`);
		}
		if (missingTables.length > 0) {
			db.exec(V2_EXTENSION_DDL);
		}
		db.query("INSERT OR REPLACE INTO meta (key, value, updated_at) VALUES (?, ?, ?)").run(
			"schema_version",
			String(targetVersion),
			ts,
		);
	});
	tx.immediate();

	return {
		migrated: true,
		previousVersion,
		currentVersion: targetVersion,
		createdTables: [...missingTables],
	};
}

// ============================================================================
// 已知属性集合与行结构 <-> 领域对象双向转换（保证 100% 无损往返）
// ============================================================================

export const KNOWN_FACT_KEYS = new Set([
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

export const KNOWN_INTENT_KEYS = new Set([
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

export const KNOWN_ATTEMPTED_KEYS = new Set([
	"key",
	"expectedKind",
	"targetKey",
	"surfaceDomain",
	"status",
	"at",
	"from",
]);

export const KNOWN_ASSET_KEYS = new Set([
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

export const KNOWN_HYPOTHESIS_KEYS = new Set([
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

export function extractExtraFields(obj: Record<string, unknown>, known: Set<string>): Record<string, unknown> | null {
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

export function safeJsonParse<T>(raw: string | null | undefined, fallback: T): T {
	if (!raw) return fallback;
	try {
		return JSON.parse(raw) as T;
	} catch {
		return fallback;
	}
}

export function formatFactMetaSearchText(meta: Fact["meta"] | undefined): string {
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

export function factFromRow(row: Record<string, any>): Fact {
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

export function intentFromRow(row: Record<string, any>): Intent {
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

export function normalizeAttemptedSurfaceDomain(rawDomain: unknown, targetKey: unknown): SurfaceDomain {
	if (rawDomain === "port" || rawDomain === "path" || rawDomain === "host") {
		return rawDomain;
	}
	const key = String(targetKey ?? "").trim();
	if (/^port:/i.test(key) || /^(?:[a-z0-9.-]+:)?\d{1,5}(?:\/(?:tcp|udp))?$/i.test(key)) {
		return "port";
	}
	if (/^path:/i.test(key) || key.startsWith("/")) {
		return "path";
	}
	if (/^https?:\/\//i.test(key)) {
		try {
			const u = new URL(key);
			if (u.pathname && u.pathname !== "/") return "path";
			if (u.search) return "path";
		} catch {
			/* ignore */
		}
	}
	const slashIdx = key.indexOf("/");
	if (slashIdx > 0 && !/^\d+\/(?:tcp|udp)$/i.test(key)) {
		return "path";
	}
	return "host";
}

export function attemptedFromRow(row: Record<string, any>): [string, AttemptedEntry] {
	const extra = safeJsonParse<Record<string, unknown>>(row.extra_json, {});
	const targetKey = String(row.target_key);
	const entry: AttemptedEntry = {
		...extra,
		key: String(row.entry_key),
		expectedKind: String(row.expected_kind) as FactKind,
		targetKey,
		surfaceDomain: normalizeAttemptedSurfaceDomain(row.surface_domain, targetKey),
		status: String(row.status) as "done" | "blocked",
		at: String(row.at),
		from: safeJsonParse<string[]>(row.from_json, []),
	};
	return [String(row.attempted_key), entry];
}

export function assetFromRow(row: Record<string, any>): AssetNode {
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

export function hypothesisFromRow(row: Record<string, any>): HypothesisNode {
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
// 全表零明文凭据脱敏层（Vault 凭据 + 通用敏感头/口令/JWT/TOTP/Query 幂等掩码）
// ============================================================================

const SENSITIVE_FIELD_KEY_RE =
	/^(?:authorization|proxy[-_]?authorization|auth[-_]?header|cookie|set[-_]?cookie|x[-_]?api[-_]?key|x[-_]?auth[-_]?token|x[-_]?access[-_]?token|x[-_]?session[-_]?token|x[-_]?csrf[-_]?token|x[-_]?xsrf[-_]?token|api[-_]?key|apikey|auth[-_]?token|access[-_]?token|refresh[-_]?token|id[-_]?token|session[-_]?token|csrf[-_]?token|bearer|token|jwt|session[-_]?id|password|passwd|pwd|passphrase|secret|secret[-_]?key|client[-_]?secret|private[-_]?key|session[-_]?secret|signing[-_]?secret|webhook[-_]?secret|totp[-_]?secret|otp[-_]?secret|mfa[-_]?secret|two[-_]?factor[-_]?secret|credential|credentials)$/i;

/** 仅用于 HTTP 请求/响应头字典：排除标准非敏感头后再宽泛匹配敏感头名（与 session-vault.ts 对齐）。 */
const STANDARD_NON_SENSITIVE_HTTP_HEADER_RE =
	/^(?:accept(?:-[a-z0-9-]+)?|content-(?:type|length|encoding|language|disposition|range|security-policy|md5)|cache-control|pragma|expires|etag|last-modified|if-(?:match|none-match|modified-since|unmodified-since|range)|connection|keep-alive|transfer-encoding|upgrade(?:-insecure-requests)?|host|origin|referer|user-agent|date|server|vary|via|age|location|allow|range|te|trailer|dnt|priority|sec-[a-z0-9-]+|x-forwarded-(?:for|host|proto|port)|x-real-ip|x-request-id|x-correlation-id|x-trace-id|x-ratelimit-[a-z0-9-]+|x-frame-options|x-content-type-options|strict-transport-security|referrer-policy|permissions-policy|access-control-[a-z0-9-]+)$/i;
const SENSITIVE_HTTP_HEADER_NAME_RE =
	/(?:auth|token|key|secret|cookie|session|jwt|csrf|xsrf|pass|cred|sign|bearer|ticket|access)/i;

const GENERIC_AUTH_HEADER_RE =
	/\b(Authorization|Proxy-Authorization)\s*:\s*(Bearer|Basic|Token|JWT)\s+([A-Za-z0-9._~+/=-]{4,})/gi;
const GENERIC_API_KEY_HEADER_RE =
	/\b(X-API-Key|X-Auth-Token|X-Access-Token|X-Session-Token|Api-Key|Private-Token|X-Vault-Token|X-CSRF-Token|X-XSRF-Token|X-Gitlab-Token)\s*:\s*([^\s\r\n'",;]{4,})/gi;
const GENERIC_COOKIE_HEADER_RE =
	/\b(Cookie|Set-Cookie)\s*:\s*([^\r\n]+)/gi;
const JSON_SENSITIVE_KV_RE =
	/(["'])(authorization|proxy[-_]?authorization|auth[-_]?header|cookie|set[-_]?cookie|x[-_]?api[-_]?key|x[-_]?auth[-_]?token|x[-_]?access[-_]?token|x[-_]?session[-_]?token|api[-_]?key|apikey|auth[-_]?token|access[-_]?token|refresh[-_]?token|id[-_]?token|session[-_]?token|csrf[-_]?token|bearer|token|jwt|session[-_]?id|password|passwd|pwd|passphrase|secret|secret[-_]?key|client[-_]?secret|private[-_]?key|session[-_]?secret|totp[-_]?secret|otp[-_]?secret|mfa[-_]?secret|credential|credentials)\1(\s*:\s*)(["'])([^"'\r\n]{4,})\4/gi;
const GENERIC_PASSWORD_KV_RE =
	/\b(password|passwd|pwd|passphrase|api[-_]?key|apikey|secret|secret[-_]?key|client[-_]?secret|private[-_]?key|session[-_]?secret|totp[-_]?secret|otp[-_]?secret|mfa[-_]?secret|access[-_]?token|refresh[-_]?token|auth[-_]?token|session[-_]?token|id[-_]?token|token|jwt|session[-_]?id|bearer|credential|auth[-_]?header)\s*([:=])\s*(["']?)([^\s\r\n"',;}{[\]&#)>]{4,})\3/gi;
const URL_SENSITIVE_QUERY_RE =
	/([?&])(token|access[-_]?token|refresh[-_]?token|auth[-_]?token|id[-_]?token|session[-_]?token|api[-_]?key|apikey|key|secret|secret[-_]?key|client[-_]?secret|password|passwd|pwd|pass|auth|jwt|session[-_]?id|sid|sig|signature|totp[-_]?secret|otp[-_]?secret|mfa[-_]?secret|credential)=([^&#\s"'\r\n]{4,})/gi;
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

/**
 * 幂等规范化凭据指纹：
 * - 若已符合 `sha256:<32~64位hex>` 格式，统一小写后原样保留（多次读写更新绝不二次哈希变异）；
 * - 否则计算 SHA-256 并格式化为 `sha256:<32位hex>`，杜绝明文凭据进入指纹列。
 */
export function normalizeCredentialFingerprint(raw: string): string {
	const trimmed = String(raw ?? "").trim();
	if (/^sha256:[0-9a-f]{32,64}$/i.test(trimmed)) {
		return `sha256:${trimmed.slice("sha256:".length).toLowerCase()}`;
	}
	const hex = createHash("sha256").update(trimmed, "utf8").digest("hex").slice(0, 32);
	return `sha256:${hex}`;
}

/**
 * 严格判定字符串是否已处于完整掩码态：
 * - 仅认可纯星号（`***` 及以上）、标准占位符（`[REDACTED]` / `<redacted>`）或 `maskSecretValue` 生成的短掩码（前 1~4 字符 + `***` + 后 0~2 字符）；
 * - 严防 `p@ss***SecretLeak9988` 等夹带 `***` 的混合长明文绕过脱敏。
 */
export function alreadyMasked(val: string): boolean {
	const trimmed = String(val ?? "").trim();
	if (!trimmed) return true;
	if (/^\*{3,}$/.test(trimmed)) return true;
	if (/^(?:\[REDACTED\]|<redacted>)$/i.test(trimmed)) return true;
	return /^[^\s*]{1,4}\*{3,}[^\s*]{0,2}$/.test(trimmed);
}

function maskSensitiveFieldString(rawVal: string, vault: SessionVault): string {
	const afterVault = redactVaultSecrets(rawVal, vault);
	const authScheme = /^(Bearer|Basic|Token|JWT)\s+(.+)$/i.exec(afterVault.trim());
	if (authScheme?.[1] && authScheme[2]) {
		const tok = authScheme[2].trim();
		return alreadyMasked(tok) ? `${authScheme[1]} ${tok}` : `${authScheme[1]} ${maskSecretValue(tok)}`;
	}
	return alreadyMasked(afterVault) ? afterVault : maskSecretValue(afterVault);
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

	out = out.replace(URL_USERINFO_RE, (_m, scheme: string, user: string | undefined, pass: string) => {
		const userPart = user ?? "";
		if (alreadyMasked(pass)) return `${scheme}${userPart}:${pass}@`;
		return `${scheme}${userPart}:${maskSecretValue(pass)}@`;
	});

	out = out.replace(URL_SENSITIVE_QUERY_RE, (_m, prefix: string, param: string, val: string) => {
		if (alreadyMasked(val)) return `${prefix}${param}=${val}`;
		return `${prefix}${param}=${maskSecretValue(val)}`;
	});

	out = out.replace(
		JSON_SENSITIVE_KV_RE,
		(_m, q1: string, key: string, sep: string, q2: string, val: string) => {
			const lowerKey = key.toLowerCase();
			if (lowerKey === "cookie" || lowerKey === "set-cookie" || lowerKey === "set_cookie") {
				return `${q1}${key}${q1}${sep}${q2}${maskCookieHeaderLine(val)}${q2}`;
			}
			const authScheme = /^(Bearer|Basic|Token|JWT)\s+(.+)$/i.exec(val.trim());
			if (authScheme?.[1] && authScheme[2]) {
				const tok = authScheme[2].trim();
				const maskedTok = alreadyMasked(tok) ? tok : maskSecretValue(tok);
				return `${q1}${key}${q1}${sep}${q2}${authScheme[1]} ${maskedTok}${q2}`;
			}
			if (alreadyMasked(val)) return `${q1}${key}${q1}${sep}${q2}${val}${q2}`;
			return `${q1}${key}${q1}${sep}${q2}${maskSecretValue(val)}${q2}`;
		},
	);

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

	out = out.replace(RAW_JWT_RE, (jwt) => (alreadyMasked(jwt) ? jwt : maskSecretValue(jwt)));
	out = out.replace(KNOWN_TOKEN_PREFIX_RE, (tok) => (alreadyMasked(tok) ? tok : maskSecretValue(tok)));

	return out;
}

export function redactTextForStorage(text: string | undefined, vault: SessionVault): string | undefined {
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

export function redactHeadersRecord(
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
				out[k] = maskSensitiveFieldString(cleanV, vault);
			}
		} else {
			out[k] = redactTextForStorage(cleanV, vault) ?? cleanV;
		}
	}
	return out;
}

export function redactUnknownForStorage<T>(value: T, vault: SessionVault, depth = 0): T {
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
			const trimmedKey = k.trim();
			const lowerKey = trimmedKey.toLowerCase();
			if (typeof v === "string" && SENSITIVE_FIELD_KEY_RE.test(trimmedKey)) {
				if (lowerKey === "cookie" || lowerKey === "set-cookie" || lowerKey === "set_cookie") {
					out[k] = maskCookieHeaderLine(redactVaultSecrets(v, vault));
				} else {
					out[k] = maskSensitiveFieldString(v, vault);
				}
			} else {
				out[k] = redactUnknownForStorage(v, vault, depth + 1);
			}
		}
		return out as T;
	}
	return value;
}

export { SCHEMA };
