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
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
	SCHEMA,
	atomicWrite,
	journalPath,
	nowIso,
	stateDir,
	statePath,
} from "./storage-io";
import { loadStateJsonOnly, normalizeState } from "./storage";
import {
	loadSessionVault,
	maskSecretValue,
	redactVaultSecrets,
	type SessionVault,
} from "./session-vault";
import {
	ALL_SQLITE_TABLES,
	CORE_DDL,
	KNOWN_ASSET_KEYS,
	KNOWN_ATTEMPTED_KEYS,
	KNOWN_FACT_KEYS,
	KNOWN_HYPOTHESIS_KEYS,
	KNOWN_INTENT_KEYS,
	SQLITE_SCHEMA_VERSION,
	V1_CORE_DDL,
	V1_CORE_TABLES,
	V2_EXTENSION_DDL,
	V2_EXTENSION_TABLES,
	alreadyMasked,
	assetFromRow,
	redactHeadersRecord,
	redactTextForStorage,
	redactUnknownForStorage,
	attemptedFromRow,
	extractExtraFields,
	factFromRow,
	formatFactMetaSearchText,
	hasSqliteTable,
	hypothesisFromRow,
	intentFromRow,
	migrateSqliteSchemaV1ToV2,
	normalizeAttemptedSurfaceDomain,
	normalizeCredentialFingerprint,
	readSqliteSchemaVersion,
	safeJsonParse,
	type AssetCredentialRow,
	type AssetCredentialStatus,
	type OobCorrelationRow,
	type OobCorrelationStatus,
	type ProtocolFrameDirection,
	type ProtocolFrameKind,
	type ProtocolFrameRow,
	type SqliteSchemaMigrationResult,
	type SqliteTableName,
	type V1CoreTableName,
	type V2ExtensionTableName,
	type WorkflowActionLevel,
	type WorkflowRunRow,
} from "./sqlite-schema";
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

export * from "./sqlite-schema";
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

function safeLoadVault(root: string, explicit?: SessionVault): SessionVault {
	if (explicit) return explicit;
	try {
		return loadSessionVault(root);
	} catch {
		return { schema: 1, updatedAt: "", roles: {} };
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
 * 读取 `NUWA_STORAGE_BACKEND` 环境变量解析生效存储后端（v7.0 SQLite WAL 正式转正为默认后端）：
 * - `sqlite` / `wal` / `db` -> `"sqlite"`
 * - `dual` / `both` / `hybrid` -> `"dual"`
 * - `json` / `file` / `legacy` -> `"json"`
 * - 未配置或 `auto`：默认返回 `"sqlite"`（只读路径对仅有 `.nuwa/state.json` 无 `nuwa.db` 的遗留项目严格保持零写盘只读兼容，发生写入时自动无损迁移并同步维护 `state.json` 兼容快照）。
 */
export function resolveStorageBackend(
	rootOrOpts?: string | { root?: string; env?: Record<string, string | undefined> },
	envOverride?: Record<string, string | undefined>,
): StorageBackend {
	const env =
		envOverride ??
		(rootOrOpts && typeof rootOrOpts === "object" && rootOrOpts.env ? rootOrOpts.env : process.env);

	const raw = String(env.NUWA_STORAGE_BACKEND ?? "").trim().toLowerCase();
	if (raw === "json" || raw === "file" || raw === "legacy") return "json";
	if (raw === "dual" || raw === "both" || raw === "hybrid") return "dual";
	if (raw === "sqlite" || raw === "wal" || raw === "db") return "sqlite";
	return "sqlite";
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

const hasTable = hasSqliteTable;

function isReadonlyCantOpenError(err: unknown): boolean {
	const msg = String(err instanceof Error ? err.message : err ?? "").toLowerCase();
	return (
		msg.includes("sqlite_cantopen") ||
		msg.includes("unable to open database file") ||
		msg.includes("sqlite_readonly") ||
		msg.includes("attempt to write a readonly database")
	);
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
			db.exec(V1_CORE_DDL);
			migrateSqliteSchemaV1ToV2(db);
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
 * 当 WAL 库已正常关闭（不存在非空 `-wal`）时，直接在内存副本中将 WAL 版本头字节 (18,19) 降为 1，
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

/**
 * 在隔离临时目录安全重放未 checkpoint 的 `-wal` 后读入纯内存只读快照：
 * 仅复制主库与 `-wal`（刻意不复制 `-shm` wal-index，由 SQLite 自动从 `-wal` 校验重建干净索引），
 * 既 100% 保留 `-wal` 最新提交状态，又确保对原 `.nuwa` 目录零写操作、零新建 `-shm`/`-wal`。
 */
function openReadonlyWalIsolatedSnapshot(dbFile: string): Database {
	const snapDir = mkdtempSync(join(tmpdir(), "nuwa-sqlite-ro-"));
	const snapDb = join(snapDir, "nuwa.db");
	try {
		copyFileSync(dbFile, snapDb);
		chmodSync(snapDb, 0o600);
		const walSrc = `${dbFile}-wal`;
		if (existsSync(walSrc)) {
			copyFileSync(walSrc, `${snapDb}-wal`);
			chmodSync(`${snapDb}-wal`, 0o600);
		}
		const rwSnap = new Database(snapDb, { readwrite: true });
		try {
			rwSnap.exec("PRAGMA busy_timeout = 3000;");
			rwSnap.exec("PRAGMA wal_checkpoint(TRUNCATE);");
			rwSnap.exec("PRAGMA journal_mode = DELETE;");
		} finally {
			rwSnap.close();
		}
		return openReadonlyMemorySnapshot(snapDb);
	} finally {
		try {
			rmSync(snapDir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
}

/** 供外部模块（如 lineage 探针）零原目录写入安全只读打开指定 SQLite 文件（含非空 -wal + -shm 时统一走隔离快照，杜绝触碰原目录 -shm）。 */
export function openSqliteReadonlyZeroWrite(dbFile: string): Database {
	if (!existsSync(dbFile)) {
		throw new Error(`SQLITE_CANTOPEN: unable to open database file (${dbFile})`);
	}
	if (hasNonEmptyWalSidecar(dbFile)) {
		return openReadonlyWalIsolatedSnapshot(dbFile);
	}
	return openReadonlyMemorySnapshot(dbFile);
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
			// 所有只读打开统一走纯内存只读快照（存在非空 -wal 时在隔离临时目录重放 WAL 后载入内存），确保原目录 nuwa.db/-wal/-shm 100% 零字节变动
			let memDb: Database | null = null;
			try {
				memDb = hasNonEmptyWalSidecar(dbFile)
					? openReadonlyWalIsolatedSnapshot(dbFile)
					: openReadonlyMemorySnapshot(dbFile);
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
			// 存在非空 -wal 但极端缺失 -shm 导致 readonly 报 SQLITE_CANTOPEN 时：在隔离临时目录重放 -wal 后转纯内存只读快照，严禁触碰原项目磁盘
			if (readonly && isReadonlyCantOpenError(err) && existsSync(dbFile)) {
				let fbDb: Database | null = null;
				try {
					fbDb = hasNonEmptyWalSidecar(dbFile)
						? openReadonlyWalIsolatedSnapshot(dbFile)
						: openReadonlyMemorySnapshot(dbFile);
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
			setMeta.run("nuwa_version", String(state.version ?? "7.0.0"), ts);
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
				const fKind = f.kind ?? "note";
				const fTitle = typeof f.title === "string" ? f.title : String(f.id ?? "");
				const fDetail = typeof f.detail === "string" ? f.detail : "";
				const fCreatedAt = typeof f.createdAt === "string" && f.createdAt ? f.createdAt : ts;
				insFact.run(
					f.id,
					fKind,
					fTitle,
					fDetail,
					f.command ?? null,
					f.output ?? null,
					f.intent ?? null,
					f.key ?? null,
					fCreatedAt,
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
					fKind,
					fTitle,
					fDetail,
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
					it.phase ?? "recon",
					typeof it.key === "string" ? it.key : String(it.id ?? ""),
					typeof it.title === "string" ? it.title : String(it.id ?? ""),
					typeof it.detail === "string" ? it.detail : "",
					JSON.stringify(it.from ?? []),
					it.to ?? null,
					it.status ?? "open",
					it.worker ?? null,
					Number.isFinite(Number(it.priority)) ? Number(it.priority) : 0,
					Number.isFinite(Number(it.attempts)) ? Number(it.attempts) : 0,
					typeof it.createdAt === "string" && it.createdAt ? it.createdAt : ts,
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
				const targetKey = typeof entry.targetKey === "string" ? entry.targetKey : "";
				insAttempted.run(
					ak,
					typeof entry.key === "string" ? entry.key : ak,
					entry.expectedKind ?? "note",
					targetKey,
					normalizeAttemptedSurfaceDomain(entry.surfaceDomain, targetKey),
					entry.status ?? "done",
					typeof entry.at === "string" && entry.at ? entry.at : ts,
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
					a.kind ?? "host",
					typeof a.target === "string" ? a.target : String(a.host ?? a.id ?? ""),
					a.host ?? null,
					a.port ?? null,
					a.scheme ?? null,
					a.reachableVia !== undefined ? JSON.stringify(a.reachableVia) : null,
					a.tags !== undefined ? JSON.stringify(a.tags) : null,
					a.sourceFactId ?? null,
					typeof a.createdAt === "string" && a.createdAt ? a.createdAt : ts,
					extra ? JSON.stringify(extra) : null,
				);
			}

			// 同步替换 hypotheses（兼容缺省 statement/falsificationTest/linkedIntents 的历史/稀疏假设节点）
			this.db.query("DELETE FROM hypotheses").run();
			const insHyp = this.db.query(
				`INSERT INTO hypotheses (
					id, title, statement, required_facts_json, falsification_test,
					expected_gain, estimated_cost, status, linked_intents_json,
					created_at, updated_at, note, extra_json
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const h of hypsList) {
				const rawHyp = h as unknown as Record<string, unknown>;
				const extra = extractExtraFields(rawHyp, KNOWN_HYPOTHESIS_KEYS);
				const hTitle = typeof h.title === "string" ? h.title : String(h.id ?? "");
				const hStatement =
					typeof h.statement === "string"
						? h.statement
						: typeof rawHyp.rationale === "string"
							? rawHyp.rationale
							: hTitle;
				const hFalsification = typeof h.falsificationTest === "string" ? h.falsificationTest : "";
				const hCreatedAt = typeof h.createdAt === "string" && h.createdAt ? h.createdAt : ts;
				const hUpdatedAt = typeof h.updatedAt === "string" && h.updatedAt ? h.updatedAt : hCreatedAt;
				insHyp.run(
					h.id,
					hTitle,
					hStatement,
					JSON.stringify(h.requiredFacts ?? []),
					hFalsification,
					Number.isFinite(Number(h.expectedGain)) ? Number(h.expectedGain) : 0,
					Number.isFinite(Number(h.estimatedCost)) ? Number(h.estimatedCost) : 0,
					h.status ?? "open",
					JSON.stringify(h.linkedIntents ?? []),
					hCreatedAt,
					hUpdatedAt,
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
		const version = meta.get("nuwa_version") ?? "7.0.0";
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
		const fKind = safeFact.kind ?? "note";
		const fTitle = typeof safeFact.title === "string" ? safeFact.title : String(safeFact.id ?? "");
		const fDetail = typeof safeFact.detail === "string" ? safeFact.detail : "";
		const fCreatedAt = typeof safeFact.createdAt === "string" && safeFact.createdAt ? safeFact.createdAt : nowIso();

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
					fKind,
					fTitle,
					fDetail,
					safeFact.command ?? null,
					safeFact.output ?? null,
					safeFact.intent ?? null,
					safeFact.key ?? null,
					fCreatedAt,
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
					fKind,
					fTitle,
					fDetail,
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
		const safeRec = redactUnknownForStorage({ ts: nowIso(), ...rec }, vault) as Record<string, unknown>;
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
				insertedSeq = Number(res.changes ?? 0) > 0 ? Number(res.lastInsertRowid ?? 0) : 0;
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
		const preservedSessionId =
			typeof entry.sessionId === "string" ? redactTextForStorage(entry.sessionId, vault) ?? null : null;
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
					preservedSessionId,
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

	/** 写入脱敏后的现代协议帧记录（`protocol_frames` 表）。 */
	upsertProtocolFrame(frame: ProtocolFrameRow, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeHeaders = redactHeadersRecord(frame.headers, vault);
		const safePreview = redactTextForStorage(frame.payloadPreview, vault);
		const safeUrl = redactTextForStorage(frame.url, vault) ?? frame.url;
		const safeSchema = frame.schemaSummary ? redactUnknownForStorage(frame.schemaSummary, vault) : undefined;
		const safeExtra = frame.extra ? redactUnknownForStorage(frame.extra, vault) : undefined;
		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO protocol_frames (
						id, ts, protocol, direction, url, host, operation_name, role, status,
						frame_seq, headers_json, payload_preview, schema_summary_json, anomaly_tag, redacted, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
				)
				.run(
					frame.id,
					frame.ts || nowIso(),
					frame.protocol,
					frame.direction || "bidirectional",
					safeUrl,
					frame.host.toLowerCase(),
					frame.operationName ?? null,
					frame.role ?? null,
					frame.status ?? null,
					frame.frameSeq ?? null,
					safeHeaders ? JSON.stringify(safeHeaders) : null,
					safePreview ?? null,
					safeSchema ? JSON.stringify(safeSchema) : null,
					frame.anomalyTag ?? null,
					safeExtra ? JSON.stringify(safeExtra) : null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 查询现代协议帧记录（若只读连接打开的是旧版 v1 库则安全返回空数组，零写盘不报错）。 */
	listProtocolFrames(filter?: { protocol?: string; host?: string; limit?: number }): ProtocolFrameRow[] {
		if (!hasTable(this.db, "protocol_frames")) return [];
		const clauses: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.protocol) {
			clauses.push("protocol = ?");
			params.push(filter.protocol);
		}
		if (filter?.host) {
			clauses.push("host = ?");
			params.push(filter.host.toLowerCase());
		}
		const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
		const limit = clampInt(filter?.limit, 200, 1, 2000);
		const rows = this.db
			.query(`SELECT * FROM protocol_frames ${where} ORDER BY ts DESC LIMIT ?`)
			.all(...params, limit) as Array<Record<string, any>>;
		return rows.map((r) => ({
			id: String(r.id),
			ts: String(r.ts),
			protocol: String(r.protocol),
			direction: String(r.direction) as ProtocolFrameDirection,
			url: String(r.url),
			host: String(r.host),
			...(r.operation_name !== null && r.operation_name !== undefined ? { operationName: String(r.operation_name) } : {}),
			...(r.role !== null && r.role !== undefined ? { role: String(r.role) } : {}),
			...(r.status !== null && r.status !== undefined ? { status: Number(r.status) } : {}),
			...(r.frame_seq !== null && r.frame_seq !== undefined ? { frameSeq: Number(r.frame_seq) } : {}),
			...(r.headers_json ? { headers: safeJsonParse<Record<string, string>>(r.headers_json, {}) } : {}),
			...(r.payload_preview !== null && r.payload_preview !== undefined ? { payloadPreview: String(r.payload_preview) } : {}),
			...(r.schema_summary_json ? { schemaSummary: safeJsonParse<Record<string, unknown>>(r.schema_summary_json, {}) } : {}),
			...(r.anomaly_tag !== null && r.anomaly_tag !== undefined ? { anomalyTag: String(r.anomaly_tag) } : {}),
			redacted: Number(r.redacted) !== 0,
			...(r.extra_json ? { extra: safeJsonParse<Record<string, unknown>>(r.extra_json, {}) } : {}),
		}));
	}

	/** 写入跨资产凭据复用验证记录（`asset_credentials` 表，强制仅存幂等指纹与掩码预览）。 */
	upsertAssetCredential(row: AssetCredentialRow, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const afterVaultPreview = row.maskedPreview ? redactVaultSecrets(row.maskedPreview, vault) : undefined;
		const safePreview = afterVaultPreview
			? alreadyMasked(afterVaultPreview)
				? afterVaultPreview.trim()
				: maskSecretValue(afterVaultPreview)
			: undefined;
		const safeFingerprint = normalizeCredentialFingerprint(row.credFingerprint);
		const safeVerifiedEndpoint = redactTextForStorage(row.verifiedEndpoint, vault);
		const safeExtra = row.extra ? redactUnknownForStorage(row.extra, vault) : undefined;
		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO asset_credentials (
						id, asset_id, host, port, role, cred_kind, cred_fingerprint, masked_preview,
						status, source_asset_id, verified_endpoint, verified_status_code,
						expires_at, last_verified_at, created_at, updated_at, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					row.id,
					row.assetId,
					row.host.toLowerCase(),
					row.port ?? null,
					row.role,
					row.credKind,
					safeFingerprint,
					safePreview ?? null,
					row.status,
					row.sourceAssetId ?? null,
					safeVerifiedEndpoint ?? null,
					row.verifiedStatusCode ?? null,
					row.expiresAt ?? null,
					row.lastVerifiedAt ?? null,
					row.createdAt || nowIso(),
					row.updatedAt || nowIso(),
					safeExtra ? JSON.stringify(safeExtra) : null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 查询跨资产凭据验证记录（旧版 v1 只读库安全返回空数组）。 */
	listAssetCredentials(filter?: { assetId?: string; role?: string; status?: AssetCredentialStatus; limit?: number }): AssetCredentialRow[] {
		if (!hasTable(this.db, "asset_credentials")) return [];
		const clauses: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.assetId) {
			clauses.push("asset_id = ?");
			params.push(filter.assetId);
		}
		if (filter?.role) {
			clauses.push("role = ?");
			params.push(filter.role);
		}
		if (filter?.status) {
			clauses.push("status = ?");
			params.push(filter.status);
		}
		const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
		const limit = clampInt(filter?.limit, 200, 1, 2000);
		const rows = this.db
			.query(`SELECT * FROM asset_credentials ${where} ORDER BY updated_at DESC LIMIT ?`)
			.all(...params, limit) as Array<Record<string, any>>;
		return rows.map((r) => ({
			id: String(r.id),
			assetId: String(r.asset_id),
			host: String(r.host),
			...(r.port !== null && r.port !== undefined ? { port: Number(r.port) } : {}),
			role: String(r.role),
			credKind: String(r.cred_kind),
			credFingerprint: String(r.cred_fingerprint),
			...(r.masked_preview !== null && r.masked_preview !== undefined ? { maskedPreview: String(r.masked_preview) } : {}),
			status: String(r.status) as AssetCredentialStatus,
			...(r.source_asset_id !== null && r.source_asset_id !== undefined ? { sourceAssetId: String(r.source_asset_id) } : {}),
			...(r.verified_endpoint !== null && r.verified_endpoint !== undefined ? { verifiedEndpoint: String(r.verified_endpoint) } : {}),
			...(r.verified_status_code !== null && r.verified_status_code !== undefined ? { verifiedStatusCode: Number(r.verified_status_code) } : {}),
			...(r.expires_at !== null && r.expires_at !== undefined ? { expiresAt: String(r.expires_at) } : {}),
			...(r.last_verified_at !== null && r.last_verified_at !== undefined ? { lastVerifiedAt: String(r.last_verified_at) } : {}),
			createdAt: String(r.created_at),
			updatedAt: String(r.updated_at),
			...(r.extra_json ? { extra: safeJsonParse<Record<string, unknown>>(r.extra_json, {}) } : {}),
		}));
	}

	/** 写入或更新延迟 OOB 因果归因台账记录（`oob_correlations` 表）。 */
	upsertOobCorrelation(row: OobCorrelationRow, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeEndpoint = redactTextForStorage(row.endpoint, vault) ?? row.endpoint;
		const safeDetail = redactTextForStorage(row.callbackDetail, vault);
		const safeExtra = row.extra ? redactUnknownForStorage(row.extra, vault) : undefined;
		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO oob_correlations (
						canary_id, project_id, intent_id, fact_id, endpoint, param_name, template_hash,
						auth_role, channel, token_sig, status, callback_ts, callback_source_ip,
						callback_detail, created_at, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					row.canaryId,
					row.projectId,
					row.intentId ?? null,
					row.factId ?? null,
					safeEndpoint,
					row.paramName ?? null,
					row.templateHash ?? null,
					row.authRole ?? null,
					row.channel || "http",
					row.tokenSig ?? null,
					row.status || "pending",
					row.callbackTs ?? null,
					row.callbackSourceIp ?? null,
					safeDetail ?? null,
					row.createdAt || nowIso(),
					safeExtra ? JSON.stringify(safeExtra) : null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 查询延迟 OOB 因果归因台账记录（旧版 v1 只读库安全返回空数组）。 */
	listOobCorrelations(filter?: { status?: OobCorrelationStatus; intentId?: string; limit?: number }): OobCorrelationRow[] {
		if (!hasTable(this.db, "oob_correlations")) return [];
		const clauses: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.status) {
			clauses.push("status = ?");
			params.push(filter.status);
		}
		if (filter?.intentId) {
			clauses.push("intent_id = ?");
			params.push(filter.intentId);
		}
		const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
		const limit = clampInt(filter?.limit, 200, 1, 2000);
		const rows = this.db
			.query(`SELECT * FROM oob_correlations ${where} ORDER BY created_at DESC LIMIT ?`)
			.all(...params, limit) as Array<Record<string, any>>;
		return rows.map((r) => ({
			canaryId: String(r.canary_id),
			projectId: String(r.project_id),
			...(r.intent_id !== null && r.intent_id !== undefined ? { intentId: String(r.intent_id) } : {}),
			...(r.fact_id !== null && r.fact_id !== undefined ? { factId: String(r.fact_id) } : {}),
			endpoint: String(r.endpoint),
			...(r.param_name !== null && r.param_name !== undefined ? { paramName: String(r.param_name) } : {}),
			...(r.template_hash !== null && r.template_hash !== undefined ? { templateHash: String(r.template_hash) } : {}),
			...(r.auth_role !== null && r.auth_role !== undefined ? { authRole: String(r.auth_role) } : {}),
			channel: String(r.channel),
			...(r.token_sig !== null && r.token_sig !== undefined ? { tokenSig: String(r.token_sig) } : {}),
			status: String(r.status) as OobCorrelationStatus,
			...(r.callback_ts !== null && r.callback_ts !== undefined ? { callbackTs: String(r.callback_ts) } : {}),
			...(r.callback_source_ip !== null && r.callback_source_ip !== undefined ? { callbackSourceIp: String(r.callback_source_ip) } : {}),
			...(r.callback_detail !== null && r.callback_detail !== undefined ? { callbackDetail: String(r.callback_detail) } : {}),
			createdAt: String(r.created_at),
			...(r.extra_json ? { extra: safeJsonParse<Record<string, unknown>>(r.extra_json, {}) } : {}),
		}));
	}

	/** 写入或更新有状态工作流链执行记录（`workflow_runs` 表）。 */
	upsertWorkflowRun(row: WorkflowRunRow, opts?: { vault?: SessionVault }): void {
		const vault = safeLoadVault(this.root, opts?.vault);
		const safeUrl = redactTextForStorage(row.targetUrl, vault) ?? row.targetUrl;
		const safeSummary = redactTextForStorage(row.summary, vault);
		const safeSteps = row.steps ? redactUnknownForStorage(row.steps, vault) : undefined;
		const safeExtra = row.extra ? redactUnknownForStorage(row.extra, vault) : undefined;
		const tx = this.db.transaction(() => {
			this.db
				.query(
					`INSERT OR REPLACE INTO workflow_runs (
						run_id, workflow_kind, action_level, intent_id, target_url, role, status,
						step_count, broken_at_step, cleanup_executed, candidate_fact_id,
						started_at, finished_at, summary, steps_json, extra_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					row.runId,
					row.workflowKind,
					row.actionLevel,
					row.intentId ?? null,
					safeUrl,
					row.role ?? null,
					row.status,
					row.stepCount,
					row.brokenAtStep ?? null,
					row.cleanupExecuted ? 1 : 0,
					row.candidateFactId ?? null,
					row.startedAt || nowIso(),
					row.finishedAt ?? null,
					safeSummary ?? null,
					safeSteps ? JSON.stringify(safeSteps) : null,
					safeExtra ? JSON.stringify(safeExtra) : null,
				);
		});
		runWithBusyRetry(() => tx.immediate());
	}

	/** 查询有状态工作流链执行记录（旧版 v1 只读库安全返回空数组）。 */
	listWorkflowRuns(filter?: { workflowKind?: string; status?: string; limit?: number }): WorkflowRunRow[] {
		if (!hasTable(this.db, "workflow_runs")) return [];
		const clauses: string[] = [];
		const params: Array<string | number> = [];
		if (filter?.workflowKind) {
			clauses.push("workflow_kind = ?");
			params.push(filter.workflowKind);
		}
		if (filter?.status) {
			clauses.push("status = ?");
			params.push(filter.status);
		}
		const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
		const limit = clampInt(filter?.limit, 200, 1, 2000);
		const rows = this.db
			.query(`SELECT * FROM workflow_runs ${where} ORDER BY started_at DESC LIMIT ?`)
			.all(...params, limit) as Array<Record<string, any>>;
		return rows.map((r) => ({
			runId: String(r.run_id),
			workflowKind: String(r.workflow_kind),
			actionLevel: String(r.action_level),
			...(r.intent_id !== null && r.intent_id !== undefined ? { intentId: String(r.intent_id) } : {}),
			targetUrl: String(r.target_url),
			...(r.role !== null && r.role !== undefined ? { role: String(r.role) } : {}),
			status: String(r.status),
			stepCount: Number(r.step_count),
			...(r.broken_at_step !== null && r.broken_at_step !== undefined ? { brokenAtStep: Number(r.broken_at_step) } : {}),
			cleanupExecuted: Number(r.cleanup_executed) !== 0,
			...(r.candidate_fact_id !== null && r.candidate_fact_id !== undefined ? { candidateFactId: String(r.candidate_fact_id) } : {}),
			startedAt: String(r.started_at),
			...(r.finished_at !== null && r.finished_at !== undefined ? { finishedAt: String(r.finished_at) } : {}),
			...(r.summary !== null && r.summary !== undefined ? { summary: String(r.summary) } : {}),
			...(r.steps_json ? { steps: safeJsonParse<Array<Record<string, unknown>>>(r.steps_json, []) } : {}),
			...(r.extra_json ? { extra: safeJsonParse<Record<string, unknown>>(r.extra_json, {}) } : {}),
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
					const preservedSid =
						typeof parsed.sessionId === "string"
							? redactTextForStorage(parsed.sessionId, vault) ?? null
							: null;
					const seq =
						typeof safe.seq === "number" && Number.isFinite(safe.seq) && safe.seq > 0
							? Math.floor(safe.seq)
							: lineIndex + 1;
					const res = ins.run(
						seq,
						typeof safe.ts === "string" ? safe.ts : nowIso(),
						typeof safe.tool === "string" ? safe.tool : "unknown",
						typeof safe.command === "string" ? safe.command : null,
						preservedSid,
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

		// 幂等迁移 calibration.jsonl（按 prediction/settlement 事件折叠，防止重复 prediction_id 丢弃结算行）
		let calibrationInserted = 0;
		const calibFile = join(stateDir(normRoot), "calibration.jsonl");
		const calibLines = readJsonlLinesSafe(calibFile);
		if (calibLines.length > 0) {
			const ALLOWED_SRC = new Set(["verifier-gate", "exec-ledger", "autoexec", "benchmark", "human"]);
			const folded = new Map<string, Record<string, unknown>>();
			const pendingSettlements = new Map<string, Record<string, unknown>>();
			for (const { lineIndex, parsed } of calibLines) {
				const safe = redactUnknownForStorage(parsed, vault) as Record<string, unknown>;
				const pid =
					typeof safe.predictionId === "string" && safe.predictionId.trim()
						? safe.predictionId.trim()
						: `mig-cal-${lineIndex}`;
				if (safe.kind === "prediction") {
					if (!folded.has(pid)) folded.set(pid, { ...safe, predictionId: pid, settled: false });
				} else if (safe.kind === "settlement") {
					const src = typeof safe.source === "string" ? safe.source : "";
					const outcome = safe.outcome;
					const isFp = safe.isFalsePositive;
					if (!ALLOWED_SRC.has(src)) continue;
					if (outcome !== 0 && outcome !== 1) continue;
					if (typeof isFp !== "boolean" || (isFp && outcome === 1)) continue;
					const cur = folded.get(pid);
					if (cur && !cur.settled) {
						folded.set(pid, {
							...cur,
							outcome,
							isFalsePositive: isFp,
							actualTokens: safe.actualTokens,
							durationMs: safe.durationMs,
							source: src,
							settled: true,
							settledAt: safe.settledAt,
							...(typeof safe.note === "string" && safe.note ? { settlementNote: safe.note } : {}),
						});
					} else if (!cur) {
						pendingSettlements.set(pid, safe);
					}
				} else if (!folded.has(pid)) {
					folded.set(pid, { ...safe, predictionId: pid });
				}
			}

			const calibTx = db.transaction(() => {
				const ins = db.query(
					`INSERT OR IGNORE INTO calibration_records (
						prediction_id, intent_id, task_category, model_id, predicted_confidence,
						estimated_tokens, outcome, is_false_positive, actual_tokens, duration_ms,
						source, settled, created_at, settled_at, payload_json
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				);
				const updSettle = db.query(
					`UPDATE calibration_records SET
						outcome = ?, is_false_positive = ?, actual_tokens = ?, duration_ms = ?,
						source = ?, settled = 1, settled_at = ?
					 WHERE prediction_id = ? AND settled = 0`,
				);
				for (const [pid, safe] of folded.entries()) {
					const isSettled = safe.settled === true || safe.outcome === 0 || safe.outcome === 1;
					const payloadObj: Record<string, unknown> = {};
					if (typeof safe.note === "string" && safe.note) payloadObj.note = safe.note;
					if (typeof safe.settlementNote === "string" && safe.settlementNote) {
						payloadObj.settlementNote = safe.settlementNote;
					}
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
						isSettled ? 1 : 0,
						typeof safe.createdAt === "string" ? safe.createdAt : nowIso(),
						typeof safe.settledAt === "string" ? safe.settledAt : null,
						Object.keys(payloadObj).length > 0 ? JSON.stringify(payloadObj) : null,
					);
					if (Number(res.changes ?? 0) > 0) {
						calibrationInserted += 1;
					} else if (isSettled) {
						updSettle.run(
							typeof safe.outcome === "number" ? safe.outcome : null,
							typeof safe.isFalsePositive === "boolean" ? (safe.isFalsePositive ? 1 : 0) : null,
							typeof safe.actualTokens === "number" ? safe.actualTokens : null,
							typeof safe.durationMs === "number" ? safe.durationMs : null,
							typeof safe.source === "string" ? safe.source : null,
							typeof safe.settledAt === "string" ? safe.settledAt : nowIso(),
							pid,
						);
					}
				}
				for (const [pid, safe] of pendingSettlements.entries()) {
					updSettle.run(
						typeof safe.outcome === "number" ? safe.outcome : null,
						typeof safe.isFalsePositive === "boolean" ? (safe.isFalsePositive ? 1 : 0) : null,
						typeof safe.actualTokens === "number" ? safe.actualTokens : null,
						typeof safe.durationMs === "number" ? safe.durationMs : null,
						typeof safe.source === "string" ? safe.source : null,
						typeof safe.settledAt === "string" ? safe.settledAt : nowIso(),
						pid,
					);
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
