/**
 * 女娲 v4 运行时便携知识库与跨项目自进化记忆引擎（纯 Bun SQLite）。
 *
 * 设计约束：
 * - 仅使用 `import type` 引用 `./types`，严禁运行时 `import ./nuwa`，确保扩展部署为独立模块时零循环依赖；
 * - 全量 SQL 查询采用参数化绑定与转义 LIKE，彻底免疫 SQL 注入与 FTS5 语法注入；
 * - DB 缺失时自动定位随仓或用户态 `kb/` 种子资产懒初始化建库，且绝不清空既有 `experience` 表；
 * - 跨项目经验蒸馏执行强脱敏过滤，严格剥离目标 URL/IP/端口/凭据/Flag，零隐私入库；
 * - 基于 UCB1 算法产出 `[-8, +15]` 意图优先级偏移，实现同类二期项目自适应提权与避坑降权。
 */
import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Fact, FactKind, Intent, NuwaState, Phase } from "./types";

export type KbLookupKind = "auto" | "product" | "cve" | "technique" | "poc";

export interface KbCommonOptions {
	dbPath?: string;
	agentHome?: string;
	seedDir?: string;
	autoInit?: boolean;
}

export interface EnsureKbOptions {
	agentHome?: string;
	seedDir?: string;
	forceRebuild?: boolean;
}

export interface KbStats {
	dbPath: string;
	exists: boolean;
	cards: number;
	cves: number;
	pocs: number;
	techniques: number;
	kevs: number;
	epss: number;
	templates: number;
	experiences: number;
	schemaVersion: string;
	builtAt: string;
}

export interface EnsureKbResult {
	ok: boolean;
	dbPath: string;
	created: boolean;
	migrated: boolean;
	seedDir?: string;
	stats: KbStats;
}

export interface KbLookupOptions extends KbCommonOptions {
	includeExperience?: boolean;
}

export interface DistillOptions extends KbCommonOptions {
	/** 仅蒸馏负向避坑经验（适用于人工停止或超时未完成项目，防止正向成功计数虚高）。 */
	negativeOnly?: boolean;
}

export interface DistillResult {
	ok: boolean;
	dbPath: string;
	techKeys: string[];
	updated: number;
	positive: number;
	negative: number;
	skipped: number;
}

export interface BoostOptions {
	dbPath?: string;
	agentHome?: string;
	autoInit?: boolean;
	seedDir?: string;
	/** 可选的当前时间戳（毫秒），默认取 Date.now()，便于时间衰减计算与测试。 */
	nowMs?: number;
}

export interface ExperienceRecord {
	id: number;
	tech_key: string;
	intent_key: string;
	phase: string;
	success_count: number;
	fail_count: number;
	helpful_pattern: string;
	pitfall_note: string;
	updated_at: string;
}

const LEGACY_KB_PATH = "/data/nuwa-kb/kb.db";
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/i;
const TECH_ID_RE = /^T\d{4}(?:\.\d{3})?$/i;

/** 与 omp/profiles.ts 保持完全一致的 36 个标准化技术栈识别模式。 */
const TECH_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
	{ name: "nginx", re: /\bnginx(?:\/[\d.]+)?\b/i },
	{ name: "tomcat", re: /\b(?:apache[\s/-]*)?tomcat(?:\/[\d.]+)?\b/i },
	{ name: "apache", re: /\b(?:apache(?:\/[\d.]+)?|httpd(?:\/[\d.]+)?)\b/i },
	{ name: "php", re: /\bphp(?:\/[\d.]+|info)?\b|\.php(?:[?#/\s"'`]|$)/i },
	{ name: "spring", re: /\bspring(?:[\s-]*boot|[\s-]*cloud|[\s-]*mvc|framework)?\b|\bactuator\b/i },
	{ name: "fastjson", re: /\bfastjson\b/i },
	{ name: "thinkphp", re: /\bthinkphp\b/i },
	{ name: "shiro", re: /\b(?:apache[\s-]*)?shiro\b|\brememberMe=/i },
	{ name: "redis", re: /\bredis(?:[\s/-]*server|\/[\d.]+)?\b/i },
	{ name: "mysql", re: /\bmysql(?:d|\/[\d.]+)?\b|\bmariadb\b/i },
	{ name: "postgres", re: /\bpostgres(?:ql)?(?:\/[\d.]+)?\b/i },
	{ name: "grafana", re: /\bgrafana\b/i },
	{ name: "gitlab", re: /\bgitlab\b/i },
	{ name: "jenkins", re: /\bjenkins\b|\bx-jenkins\b/i },
	{ name: "wordpress", re: /\bwordpress\b|\bwp-(?:content|admin|login|json|includes)\b/i },
	{ name: "graphql", re: /\bgraphql\b|\bgraphiql\b/i },
	{ name: "swagger", re: /\bswagger(?:[-_\s]*ui)?\b|\bopenapi(?:\.json|\.ya?ml)?\b/i },
	{ name: "log4j", re: /\blog4j2?\b/i },
	{ name: "struts", re: /\bstruts2?\b/i },
	{ name: "weblogic", re: /\bweblogic\b/i },
	{ name: "nacos", re: /\bnacos\b/i },
	{ name: "elasticsearch", re: /\belasticsearch\b/i },
	{ name: "kibana", re: /\bkibana\b/i },
	{ name: "mongodb", re: /\bmongodb?\b/i },
	{ name: "minio", re: /\bminio\b/i },
	{ name: "jetty", re: /\bjetty(?:\/[\d.]+)?\b/i },
	{ name: "iis", re: /\bmicrosoft-iis(?:\/[\d.]+)?\b|\biis\b/i },
	{ name: "openssh", re: /\bopenssh(?:[_\s/-][\d.p]+)?\b/i },
	{ name: "django", re: /\bdjango\b/i },
	{ name: "flask", re: /\bflask\b|\bwerkzeug\b/i },
	{ name: "laravel", re: /\blaravel\b/i },
	{ name: "drupal", re: /\bdrupal\b/i },
	{ name: "confluence", re: /\bconfluence\b/i },
	{ name: "jira", re: /\bjira\b/i },
	{ name: "nexus", re: /\bnexus\b/i },
	{ name: "harbor", re: /\bharbor\b/i },
];

const EXPERIENCE_DDL = `
CREATE TABLE IF NOT EXISTS experience (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	tech_key TEXT NOT NULL,
	intent_key TEXT NOT NULL,
	phase TEXT NOT NULL,
	success_count INTEGER DEFAULT 0,
	fail_count INTEGER DEFAULT 0,
	helpful_pattern TEXT DEFAULT '',
	pitfall_note TEXT DEFAULT '',
	updated_at TEXT NOT NULL,
	UNIQUE(tech_key, intent_key)
);
CREATE INDEX IF NOT EXISTS idx_experience_tech_key ON experience(tech_key);
CREATE INDEX IF NOT EXISTS idx_experience_intent_key ON experience(intent_key);
`;

function defaultAgentHome(): string {
	const envHome = process.env.PI_AGENT_HOME?.trim();
	if (envHome) return resolve(envHome);
	const ompHome = join(homedir(), ".omp", "agent");
	if (existsSync(ompHome)) return ompHome;
	return join(homedir(), ".pi", "agent");
}

/**
 * 解析知识库 SQLite 文件路径。
 * 优先级：NUWA_KB_DB → <agentHome>/nuwa-kb/kb.db → /data/nuwa-kb/kb.db。
 */
export function resolveKbPath(agentHome?: string): string {
	const envDb = process.env.NUWA_KB_DB?.trim();
	if (envDb) return resolve(envDb);

	if (agentHome && agentHome.trim()) {
		return join(resolve(agentHome.trim()), "nuwa-kb", "kb.db");
	}

	const explicitEnvHome = process.env.PI_AGENT_HOME?.trim();
	if (explicitEnvHome) {
		return join(resolve(explicitEnvHome), "nuwa-kb", "kb.db");
	}

	const homePath = join(defaultAgentHome(), "nuwa-kb", "kb.db");
	if (existsSync(homePath)) return homePath;
	if (existsSync(LEGACY_KB_PATH)) return LEGACY_KB_PATH;
	return homePath;
}

function isValidSeedDir(dir: string): boolean {
	return (
		existsSync(join(dir, "schema.sql")) &&
		existsSync(join(dir, "seed-cards.json")) &&
		existsSync(join(dir, "seed-cves.json")) &&
		existsSync(join(dir, "seed-techniques.json"))
	);
}

/** 定位随仓或用户目录下的 `kb/` 种子资产目录。 */
export function resolveSeedDir(explicitSeedDir?: string, agentHome?: string): string | null {
	const home = agentHome?.trim() ? resolve(agentHome.trim()) : defaultAgentHome();
	const candidates = [
		explicitSeedDir?.trim() ? resolve(explicitSeedDir.trim()) : "",
		process.env.NUWA_KB_SEED_DIR?.trim() ? resolve(process.env.NUWA_KB_SEED_DIR.trim()) : "",
		resolve(import.meta.dir, "..", "kb"),
		resolve(import.meta.dir, "kb"),
		join(home, "nuwa-kb", "seed"),
		join(home, "nuwa-kb", "kb"),
		resolve(process.cwd(), "kb"),
	].filter(Boolean);

	for (const cand of candidates) {
		if (isValidSeedDir(cand)) return cand;
	}
	return null;
}

function isSafeAdvisoryUrl(raw: string): boolean {
	const u = raw.trim();
	if (!u || u.length > 320) return false;
	try {
		const parsed = new URL(u);
		if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
		const host = parsed.hostname.toLowerCase();
		if (
			!host ||
			host === "localhost" ||
			host.endsWith(".local") ||
			host.endsWith(".internal") ||
			/^127\.|^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\./.test(host)
		) {
			return false;
		}
		return true;
	} catch {
		return false;
	}
}

function hasTable(db: Database, name: string): boolean {
	const row = db
		.query("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?")
		.get(name) as { name?: string } | null;
	return Boolean(row?.name);
}

/**
 * 写连接收尾辅助：关闭前执行 WAL 截断检查点并切换回 DELETE 模式。
 * 确保既有旧 WAL 库原地无损转回单文件 DELETE 模式（完整保留 experience 记录），消除对 -shm/-wal 的依赖。
 */
export function finalizeWritableKbDb(db: Database): void {
	try {
		db.exec("PRAGMA busy_timeout = 3000;");
	} catch {
		/* ignore */
	}
	try {
		db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
	} catch {
		/* ignore */
	}
	try {
		db.exec("PRAGMA journal_mode = DELETE;");
	} catch {
		/* ignore */
	}
}

/**
 * 健壮只读打开辅助：
 * 1) 优先以 `{ readonly: true }` + `PRAGMA busy_timeout = 3000` 打开并立即查询 sqlite_master 校验可读；
 * 2) 若外部遗留 WAL 库缺失 `-shm` 导致首条查询抛 `SQLITE_CANTOPEN`，安全回退普通连接并立即设 `PRAGMA query_only = ON`。
 */
export function openReadonlyKbDb(filePath: string): Database {
	let roDb: Database | null = null;
	try {
		roDb = new Database(filePath, { readonly: true });
		try {
			roDb.exec("PRAGMA busy_timeout = 3000;");
		} catch {
			/* ignore */
		}
		roDb.query("SELECT 1 FROM sqlite_master LIMIT 1").get();
		return roDb;
	} catch {
		try {
			roDb?.close();
		} catch {
			/* ignore */
		}
	}

	const fallbackDb = new Database(filePath);
	try {
		fallbackDb.exec("PRAGMA busy_timeout = 3000; PRAGMA query_only = ON;");
		fallbackDb.query("SELECT 1 FROM sqlite_master LIMIT 1").get();
		return fallbackDb;
	} catch (err) {
		try {
			fallbackDb.close();
		} catch {
			/* ignore */
		}
		throw err;
	}
}

function safeTableCount(db: Database, table: string): number {
	try {
		if (!hasTable(db, table)) return 0;
		const row = db.query(`SELECT COUNT(*) AS cnt FROM ${table}`).get() as { cnt?: number } | null;
		return Number(row?.cnt ?? 0);
	} catch {
		return 0;
	}
}

function readStatsFromDb(db: Database, dbPath: string): KbStats {
	let schemaVersion = "";
	let builtAt = "";
	try {
		if (hasTable(db, "kb_meta")) {
			const v = db.query("SELECT value FROM kb_meta WHERE key = ?").get("schema_version") as { value?: string } | null;
			const b = db.query("SELECT value FROM kb_meta WHERE key = ?").get("built_at") as { value?: string } | null;
			schemaVersion = v?.value ?? "";
			builtAt = b?.value ?? "";
		}
	} catch {
		/* 旧库无 kb_meta */
	}
	return {
		dbPath,
		exists: true,
		cards: safeTableCount(db, "card"),
		cves: safeTableCount(db, "cve"),
		pocs: safeTableCount(db, "poc"),
		techniques: safeTableCount(db, "technique"),
		kevs: safeTableCount(db, "kev"),
		epss: safeTableCount(db, "epss"),
		templates: safeTableCount(db, "template"),
		experiences: safeTableCount(db, "experience"),
		schemaVersion,
		builtAt,
	};
}

/** 内部自包含种子建库实现（与 kb/build-kb.ts 保持结构一致且保护 experience 表）。 */
function compileSeedIntoDb(db: Database, seedDir: string): void {
	const schemaSql = readFileSync(join(seedDir, "schema.sql"), "utf8");
	const cards = JSON.parse(readFileSync(join(seedDir, "seed-cards.json"), "utf8")) as Array<Record<string, any>>;
	const cves = JSON.parse(readFileSync(join(seedDir, "seed-cves.json"), "utf8")) as Array<Record<string, any>>;
	const techniques = JSON.parse(readFileSync(join(seedDir, "seed-techniques.json"), "utf8")) as Array<
		Record<string, any>
	>;
	const builtAt = new Date().toISOString();

	db.exec(schemaSql);

	const runTx = db.transaction(() => {
		db.query("DELETE FROM card").run();
		db.query("DELETE FROM technique").run();
		db.query("DELETE FROM kev").run();
		db.query("DELETE FROM epss").run();
		db.query("DELETE FROM cve WHERE source = ?").run("seed");
		db.query("DELETE FROM poc WHERE kind = ?").run("advisory");

		const insCard = db.query(
			"INSERT OR REPLACE INTO card (key, tech_key, title, keywords, body, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		);
		for (const c of cards) {
			insCard.run(
				String(c.key).trim(),
				String(c.tech_key).trim().toLowerCase(),
				String(c.title).trim(),
				String(c.keywords ?? "").trim(),
				String(c.body).trim(),
				builtAt,
			);
		}

		const insCve = db.query(
			`INSERT OR REPLACE INTO cve
			 (cve_id, product, affected_versions, severity, cvss, cwe, descr, verify_hint, remediation, published, source)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		);
		const insPoc = db.query("INSERT OR IGNORE INTO poc (cve_id, url, kind, title) VALUES (?, ?, ?, ?)");
		const insKev = db.query("INSERT OR REPLACE INTO kev (cve_id, added_date, note) VALUES (?, ?, ?)");
		const insEpss = db.query("INSERT OR REPLACE INTO epss (cve_id, score, percentile) VALUES (?, ?, ?)");

		for (const item of cves) {
			const cid = String(item.cve_id).trim().toUpperCase();
			insCve.run(
				cid,
				String(item.product ?? "").trim().toLowerCase(),
				String(item.affected_versions ?? "").trim(),
				String(item.severity ?? "UNKNOWN").trim().toUpperCase(),
				Number.isFinite(Number(item.cvss)) ? Number(item.cvss) : 0.0,
				String(item.cwe ?? "").trim().toUpperCase(),
				String(item.descr ?? "").trim(),
				String(item.verify_hint ?? "").trim(),
				String(item.remediation ?? "").trim(),
				String(item.published ?? "").trim(),
				"seed",
			);
			const advisories = Array.isArray(item.advisories) ? item.advisories : [];
			for (const rawUrl of advisories) {
				if (typeof rawUrl === "string" && isSafeAdvisoryUrl(rawUrl)) {
					insPoc.run(cid, rawUrl.trim(), "advisory", `${cid} 官方安全公告`);
				}
			}
			if (item.kev) {
				insKev.run(cid, String(item.published ?? ""), "CISA KEV 目录收录");
			}
			if (item.epss && Number.isFinite(Number(item.epss.score))) {
				insEpss.run(
					cid,
					Number(item.epss.score),
					Number.isFinite(Number(item.epss.percentile)) ? Number(item.epss.percentile) : 0.0,
				);
			}
		}

		const insTech = db.query(
			"INSERT OR REPLACE INTO technique (id, name, tactics, platforms, summary, detection_hint) VALUES (?, ?, ?, ?, ?, ?)",
		);
		for (const t of techniques) {
			insTech.run(
				String(t.id).trim().toUpperCase(),
				String(t.name).trim(),
				String(t.tactics ?? "").trim(),
				String(t.platforms ?? "").trim(),
				String(t.summary ?? "").trim(),
				String(t.detection_hint ?? "").trim(),
			);
		}

		// 重建 FTS5 索引（不触碰 experience 表）
		db.query("DELETE FROM cve_fts").run();
		db.query(
			"INSERT INTO cve_fts (cve_id, product, severity, descr, verify_hint) SELECT cve_id, product, severity, descr, verify_hint FROM cve",
		).run();

		db.query("DELETE FROM card_fts").run();
		db.query(
			"INSERT INTO card_fts (key, tech_key, title, keywords, body) SELECT key, tech_key, title, keywords, body FROM card",
		).run();

		const setMeta = db.query("INSERT OR REPLACE INTO kb_meta (key, value) VALUES (?, ?)");
		setMeta.run("schema_version", "4");
		setMeta.run("built_at", builtAt);
		setMeta.run("seed_dir", seedDir);
	});

	runTx();
}

/**
 * 确保本地便携知识库存在且结构就绪；DB 缺失时自动定位随仓 `kb/` 种子编译建库。
 * 既有库缺少 `experience` 表时仅原地增量建表，严禁清空已有数据。
 */
export function ensureBundledKb(dbPath?: string, opts?: EnsureKbOptions): EnsureKbResult {
	const target = dbPath?.trim() ? resolve(dbPath.trim()) : resolveKbPath(opts?.agentHome);
	const existsNonEmpty = existsSync(target) && statSync(target).size > 0;

	if (existsNonEmpty && !opts?.forceRebuild) {
		const db = new Database(target);
		try {
			const hasCore = hasTable(db, "card") && hasTable(db, "cve");
			if (hasCore) {
				let migrated = false;
				if (!hasTable(db, "experience")) {
					db.exec(EXPERIENCE_DDL);
					migrated = true;
				}
				const stats = readStatsFromDb(db, target);
				finalizeWritableKbDb(db);
				return {
					ok: true,
					dbPath: target,
					created: false,
					migrated,
					stats,
				};
			}
		} finally {
			db.close();
		}
	}

	const seedDir = resolveSeedDir(opts?.seedDir, opts?.agentHome);
	if (!seedDir) {
		throw new Error(`未找到随仓 kb/ 种子目录，无法初始化知识库: ${target}`);
	}

	mkdirSync(dirname(target), { recursive: true });
	const db = new Database(target);
	try {
		compileSeedIntoDb(db, seedDir);
		const stats = readStatsFromDb(db, target);
		finalizeWritableKbDb(db);
		return {
			ok: true,
			dbPath: target,
			created: true,
			migrated: false,
			seedDir,
			stats,
		};
	} finally {
		db.close();
	}
}

/** 读取知识库各表计数统计；默认无写盘副作用，可传 `autoInit: true` 触发懒初始化。 */
export function getKbStats(dbPath?: string, opts?: KbCommonOptions): KbStats {
	const target = dbPath?.trim() ? resolve(dbPath.trim()) : resolveKbPath(opts?.agentHome);
	if (!existsSync(target) || statSync(target).size === 0) {
		if (opts?.autoInit) {
			return ensureBundledKb(target, { agentHome: opts.agentHome, seedDir: opts.seedDir }).stats;
		}
		return {
			dbPath: target,
			exists: false,
			cards: 0,
			cves: 0,
			pocs: 0,
			techniques: 0,
			kevs: 0,
			epss: 0,
			templates: 0,
			experiences: 0,
			schemaVersion: "",
			builtAt: "",
		};
	}

	const db = openReadonlyKbDb(target);
	try {
		return readStatsFromDb(db, target);
	} finally {
		db.close();
	}
}

// ============================================================================
// 参数化安全检索（防 SQL 注入 / FTS 语法注入 + 关联历史经验提示）
// ============================================================================

function escapeLike(input: string): string {
	return input.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

function hasSqlMetaChars(input: string): boolean {
	return /['";=()]|--|\/\*|\*\/|\b(?:union|select|drop|delete|insert|update|alter|pragma|attach|detach)\b/i.test(input);
}

/** 仅允许由字母数字短横线下划线组成的干净词项构造 FTS5 安全字面量查询。 */
function buildSafeFtsQuery(input: string): string | null {
	if (hasSqlMetaChars(input)) return null;
	const tokens = input
		.toLowerCase()
		.split(/[^a-z0-9\u4e00-\u9fff]+/u)
		.map((t) => t.trim())
		.filter((t) => t.length >= 2 && !/^\d+(?:\.\d+)*$/.test(t))
		.slice(0, 4);
	if (tokens.length === 0) return null;
	// 每个 token 用双引号包裹成 FTS5 纯短语字面量，防止 OR/NOT/NEAR 等运算符注入
	return tokens.map((t) => `"${t.replace(/"/g, "")}"`).join(" AND ");
}

function extractSafeProductTokens(input: string): string[] {
	if (hasSqlMetaChars(input)) return [];
	const out: string[] = [];
	const seen = new Set<string>();
	for (const p of TECH_PATTERNS) {
		if (p.re.test(input) && !seen.has(p.name)) {
			seen.add(p.name);
			out.push(p.name);
		}
	}
	if (out.length > 0) return out;
	const rawTokens = input
		.toLowerCase()
		.split(/[\s/:_-]+/)
		.map((t) => t.trim())
		.filter((t) => t.length >= 2 && !/^\d+(?:\.\d+)*$/.test(t));
	for (const t of rawTokens) {
		if (!seen.has(t)) {
			seen.add(t);
			out.push(t);
		}
	}
	return out.slice(0, 3);
}

function formatExperienceHints(db: Database, techKeys: string[], limit = 3): string {
	if (!techKeys.length || !hasTable(db, "experience")) return "";
	const uniq = [...new Set(techKeys.map((t) => t.trim().toLowerCase()).filter(Boolean))];
	if (!uniq.length) return "";
	const placeholders = uniq.map(() => "?").join(",");
	try {
		const rows = db
			.query(
				`SELECT tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note
				 FROM experience
				 WHERE tech_key IN (${placeholders}) AND (success_count > 0 OR fail_count > 0)
				 ORDER BY (success_count - fail_count) DESC, success_count DESC, updated_at DESC
				 LIMIT ?`,
			)
			.all(...uniq, limit) as ExperienceRecord[];
		if (!rows.length) return "";
		const lines = rows.map((r) => {
			const parts = [
				`- [${r.phase}] ${r.intent_key} (tech=${r.tech_key}, 成功=${r.success_count}, 失败=${r.fail_count})`,
			];
			if (r.helpful_pattern) parts.push(`有效模式: ${r.helpful_pattern}`);
			if (r.pitfall_note) parts.push(`避坑: ${r.pitfall_note}`);
			return parts.join(" | ");
		});
		return `\n\n【历史经验提示】\n${lines.join("\n")}`;
	} catch {
		return "";
	}
}

/**
 * 参数化安全知识库检索，兼容 `omp/nuwa.ts` 的 `kbLookup` 契约，并自动附带关联历史经验提示。
 *
 * - 支持 `kind`: `"auto" | "product" | "cve" | "technique" | "poc"`；
 * - DB 缺失且 `opts?.autoInit !== false` 时自动触发随仓种子懒建库；
 * - 全参数化查询，任何 SQL 注入字面量均被安全当作普通字面量匹配，绝不引发报错或全表泄漏。
 */
export function kbLookupSafe(
	query: string,
	kind: KbLookupKind = "auto",
	limit = 5,
	opts?: KbLookupOptions,
): string {
	const q = String(query ?? "").trim();
	if (!q) throw new Error("query 为空");
	const n = Math.max(1, Math.min(20, Math.floor(Number.isFinite(limit) ? limit : 5)));
	const includeExp = opts?.includeExperience !== false;

	const targetPath = opts?.dbPath?.trim() ? resolve(opts.dbPath.trim()) : resolveKbPath(opts?.agentHome);
	if (!existsSync(targetPath) || statSync(targetPath).size === 0) {
		if (opts?.autoInit !== false) {
			ensureBundledKb(targetPath, { agentHome: opts?.agentHome, seedDir: opts?.seedDir });
		} else {
			throw new Error(`知识库不存在: ${targetPath}（用 NUWA_KB_DB 覆盖）`);
		}
	}

	const db = openReadonlyKbDb(targetPath);
	try {
		const cveMatch = q.match(CVE_RE)?.[0]?.toUpperCase();
		const likeParam = `%${escapeLike(q)}%`;

		// 1. CVE 精确查询（需避开含 SQL 元字符的注入串误抽 CVE）
		if (kind === "cve" || (kind === "auto" && cveMatch && !hasSqlMetaChars(q))) {
			const id = kind === "cve" && hasSqlMetaChars(q) ? q.toUpperCase() : cveMatch ?? q.toUpperCase();
			const row = db
				.query(
					`SELECT cve_id, product, affected_versions, severity, cvss, cwe,
					        substr(descr, 1, 600) AS descr, verify_hint, remediation
					 FROM cve WHERE cve_id = ? LIMIT 1`,
				)
				.get(id) as Record<string, any> | null;
			if (!row) return `未命中 ${id}`;

			let pocRows: Array<{ url: string }> = [];
			try {
				if (hasTable(db, "poc")) {
					pocRows = db
						.query("SELECT url FROM poc WHERE cve_id = ? LIMIT ?")
						.all(id, n) as Array<{ url: string }>;
				}
			} catch {
				/* poc 表可选 */
			}
			const kevRow = hasTable(db, "kev")
				? (db.query("SELECT 1 AS ok FROM kev WHERE cve_id = ? LIMIT 1").get(id) as { ok?: number } | null)
				: null;
			const epssRow = hasTable(db, "epss")
				? (db.query("SELECT score FROM epss WHERE cve_id = ? LIMIT 1").get(id) as { score?: number } | null)
				: null;

			const metaBits = [
				`${row.cve_id}  ${row.severity ?? "?"}  CVSS ${row.cvss ?? "?"}`,
				row.cwe ? `CWE ${row.cwe}` : "",
				kevRow ? "KEV=1" : "",
				epssRow ? `EPSS=${epssRow.score}` : "",
			]
				.filter(Boolean)
				.join("  ");

			const lines = [metaBits, String(row.descr ?? "")];
			if (row.affected_versions) lines.push(`受影响版本: ${row.affected_versions}`);
			if (row.verify_hint) lines.push(`核验要点: ${row.verify_hint}`);
			if (row.remediation) lines.push(`加固建议: ${row.remediation}`);
			lines.push(
				pocRows.length ? `PoC:\n${pocRows.map((x) => `- ${x.url}`).join("\n")}` : "PoC: 无",
			);

			const expBlock = includeExp && row.product ? formatExperienceHints(db, [String(row.product)]) : "";
			return `${lines.join("\n")}${expBlock}`;
		}

		// 2. ATT&CK Technique 查询
		if (kind === "technique" || (kind === "auto" && TECH_ID_RE.test(q))) {
			const rows = db
				.query(
					`SELECT id, name, tactics, platforms, summary, detection_hint
					 FROM technique
					 WHERE id LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\' OR tactics LIKE ? ESCAPE '\\'
					 LIMIT ?`,
				)
				.all(likeParam, likeParam, likeParam, n) as Array<Record<string, any>>;
			if (!rows.length) return `未命中 technique: ${q}`;
			return rows
				.map((r) => {
					const head = `${r.id}  ${r.name}  [${r.tactics ?? ""}] ${r.platforms ?? ""}`.trim();
					const extra = [r.summary ? `说明: ${r.summary}` : "", r.detection_hint ? `检测: ${r.detection_hint}` : ""]
						.filter(Boolean)
						.join(" | ");
					return extra ? `${head}\n  ${extra}` : head;
				})
				.join("\n");
		}

		// 3. 官方参考公告 / PoC 链接查询
		if (kind === "poc") {
			if (!hasTable(db, "poc")) return `未命中 PoC: ${q}`;
			const rows = db
				.query(
					`SELECT p.cve_id, p.url
					 FROM poc p
					 WHERE p.cve_id LIKE ? ESCAPE '\\' OR p.url LIKE ? ESCAPE '\\'
					 LIMIT ?`,
				)
				.all(likeParam, likeParam, n) as Array<{ cve_id: string; url: string }>;
			return rows.length ? rows.map((r) => `${r.cve_id}  ${r.url}`).join("\n") : `未命中 PoC: ${q}`;
		}

		// 4. product / auto：优先命中产品审计卡，其次回退 CVE 检索
		const lowerQ = q.toLowerCase();
		let cards = db
			.query(
				`SELECT key, tech_key, title, substr(body, 1, 1600) AS body
				 FROM card
				 WHERE lower(tech_key) = ?
				    OR lower(key) = ?
				    OR key LIKE ? ESCAPE '\\'
				    OR title LIKE ? ESCAPE '\\'
				    OR keywords LIKE ? ESCAPE '\\'
				 ORDER BY CASE WHEN lower(tech_key) = ? THEN 0 WHEN lower(key) LIKE ? ESCAPE '\\' THEN 1 ELSE 2 END
				 LIMIT ?`,
			)
			.all(lowerQ, lowerQ, likeParam, likeParam, likeParam, lowerQ, `%:${escapeLike(lowerQ)}%`, n) as Array<
			Record<string, any>
		>;

		// 安全多词查询回退（如 "nginx 1.18.0" 或 "Apache Tomcat/9.0"），对含 SQL 元字符输入严格禁用拆词
		if (!cards.length && !hasSqlMetaChars(q)) {
			const prodTokens = extractSafeProductTokens(q);
			for (const tok of prodTokens) {
				const tokLike = `%${escapeLike(tok)}%`;
				const hit = db
					.query(
						`SELECT key, tech_key, title, substr(body, 1, 1600) AS body
						 FROM card
						 WHERE lower(tech_key) = ? OR key LIKE ? ESCAPE '\\' OR keywords LIKE ? ESCAPE '\\'
						 ORDER BY CASE WHEN lower(tech_key) = ? THEN 0 ELSE 1 END
						 LIMIT ?`,
					)
					.all(tok, tokLike, tokLike, tok, n) as Array<Record<string, any>>;
				if (hit.length) {
					cards = hit;
					break;
				}
			}
		}

		// card_fts 安全短语回退
		if (!cards.length && hasTable(db, "card_fts")) {
			const ftsQ = buildSafeFtsQuery(q);
			if (ftsQ) {
				try {
					cards = db
						.query(
							`SELECT c.key, c.tech_key, c.title, substr(c.body, 1, 1600) AS body
							 FROM card_fts f
							 JOIN card c ON c.key = f.key
							 WHERE card_fts MATCH ?
							 ORDER BY bm25(card_fts)
							 LIMIT ?`,
						)
						.all(ftsQ, n) as Array<Record<string, any>>;
				} catch {
					/* 忽略 FTS 边界查询错误 */
				}
			}
		}

		if (cards.length) {
			const cardText = cards.map((c) => `## ${c.key} — ${c.title}\n${c.body}`).join("\n\n");
			const techKeys = cards.map((c) => String(c.tech_key ?? "")).filter(Boolean);
			const expBlock = includeExp ? formatExperienceHints(db, techKeys) : "";
			return `${cardText}${expBlock}`;
		}

		// 未命中卡片时回退 CVE 参数化查询 + FTS5
		let cves = db
			.query(
				`SELECT cve_id, product, severity, cvss, substr(descr, 1, 240) AS descr
				 FROM cve
				 WHERE lower(product) = ?
				    OR cve_id LIKE ? ESCAPE '\\'
				    OR descr LIKE ? ESCAPE '\\'
				 ORDER BY cvss DESC
				 LIMIT ?`,
			)
			.all(lowerQ, likeParam, likeParam, n) as Array<Record<string, any>>;

		if (!cves.length && hasTable(db, "cve_fts")) {
			const ftsQ = buildSafeFtsQuery(q);
			if (ftsQ) {
				try {
					cves = db
						.query(
							`SELECT c.cve_id, c.product, c.severity, c.cvss, substr(c.descr, 1, 240) AS descr
							 FROM cve_fts f
							 JOIN cve c ON c.cve_id = f.cve_id
							 WHERE cve_fts MATCH ?
							 ORDER BY bm25(cve_fts), c.cvss DESC
							 LIMIT ?`,
						)
						.all(ftsQ, n) as Array<Record<string, any>>;
				} catch {
					/* 忽略 FTS 边界错误 */
				}
			}
		}

		if (cves.length) {
			const listText = cves.map((c) => `${c.cve_id}  ${c.severity}  ${c.cvss}  ${c.descr}`).join("\n");
			const techKeys = cves.map((c) => String(c.product ?? "")).filter(Boolean);
			const expBlock = includeExp ? formatExperienceHints(db, techKeys) : "";
			return `${listText}${expBlock}`;
		}

		return `未命中: ${q}`;
	} finally {
		db.close();
	}
}

// ============================================================================
// 自进化经验脱敏、归一化与跨项目蒸馏回写
// ============================================================================

function escapeRegexLiteral(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const SAFE_GENERIC_PATH_SEGS = new Set([
	"api",
	"v1",
	"v2",
	"v3",
	"graphql",
	"graphiql",
	"swagger",
	"swagger-ui",
	"openapi",
	"api-docs",
	"actuator",
	"health",
	"info",
	"env",
	"metrics",
	"admin",
	"console",
	"manager",
	"dashboard",
	"login",
	"signin",
	"sign-in",
	"logout",
	"auth",
	"oauth",
	"sso",
	"upload",
	"uploads",
	"file",
	"files",
	"static",
	"assets",
	"public",
	"index",
	"status",
	"ping",
	"users",
	"user",
	"search",
	"config",
	"nacos",
	"wiki",
	"rest",
	"wp-admin",
	"wp-json",
	"wp-content",
	"wp-login",
]);

function collectSensitiveLiterals(st?: NuwaState): string[] {
	if (!st) return [];
	const lits = new Set<string>();
	const add = (val?: string) => {
		const s = String(val ?? "").trim();
		if (s.length >= 3) lits.add(s);
	};
	const addHost = (raw?: string) => {
		const h = String(raw ?? "")
			.trim()
			.replace(/^\*\./, "")
			.replace(/^\.+|\.+$/g, "");
		if (h.length >= 3) add(h);
	};
	const addPrivatePathSegs = (rawPath?: string) => {
		const p = String(rawPath ?? "").trim();
		if (!p.startsWith("/")) return;
		const segs = p
			.split(/[/?#]+/)
			.map((s) => s.trim())
			.filter(Boolean);
		for (const seg of segs) {
			const lower = seg.toLowerCase();
			if (lower.length < 4 || SAFE_GENERIC_PATH_SEGS.has(lower)) continue;
			// 跳过已知通用技术关键词或常见扩展文件（如 openapi.json）
			if (TECH_PATTERNS.some((tp) => tp.name === lower)) continue;
			if (/^[a-z0-9_-]+\.(?:json|ya?ml|xml|php|jsp|html?)$/i.test(lower)) continue;
			add(seg);
		}
	};

	add(st.project?.url);
	add(st.project?.target);
	addHost(st.project?.host);
	if (st.project?.host && st.project?.port) {
		add(`${st.project.host}:${st.project.port}`);
	}
	add(st.project?.id);

	// 收集 Scope 白/黑名单主机名与通配基域，防止关联业务域名穿透进入经验库
	for (const h of st.project?.scope?.allowHosts ?? []) addHost(h);
	for (const h of st.project?.scope?.denyHosts ?? []) addHost(h);

	// 收集派生意图 key 中携带的 SAN 域名与私有业务路径段，确保意图标题/备注中同样零残留
	for (const intent of Object.values(st.intents ?? {})) {
		const k = String(intent.key ?? "").trim();
		const sanMatch = k.match(/^(?:e\d+:)*san:f\d+:(.+)$/i);
		if (sanMatch) addHost(sanMatch[1]);
		const epMatch = k.match(/^(?:e\d+:)*ep:f\d+:(\/.*)$/i);
		if (epMatch) addPrivatePathSegs(epMatch[1]);
	}

	// 主动收集全部事实的 SAN 关联域名、私有路径，以及 flag / cred 事实的具体敏感值
	for (const fact of Object.values(st.facts ?? {})) {
		for (const san of fact.meta?.san ?? []) addHost(san);
		for (const p of fact.meta?.paths ?? []) addPrivatePathSegs(p);

		if (fact.kind === "flag" || fact.kind === "cred") {
			for (const field of [fact.title, fact.detail, fact.output]) {
				const txt = String(field ?? "");
				for (const m of txt.matchAll(/[A-Za-z0-9_-]{2,20}\{[^}\s]{2,160}\}/g)) {
					add(m[0]);
				}
				for (const m of txt.matchAll(/\b(?:FLAG|CTF)[-_:=][A-Za-z0-9_.-]{4,120}\b/gi)) {
					add(m[0]);
				}
				for (const m of txt.matchAll(
					/(?:password|passwd|pwd|secret|token|cookie|api[_-]?key|jsessionid|phpsessid|rememberme)\s*[:=]\s*([^\s,;'"`]+)/gi,
				)) {
					add(m[1]);
				}
				// 收集 user:pass 形态中的口令与整段凭据对
				if (fact.kind === "cred") {
					for (const m of txt.matchAll(/\b([A-Za-z0-9._-]{2,32}):([^\s,;'"`]{4,64})\b/g)) {
						if (!/^(?:http|https|ftp|ws|wss|tcp|udp|port|kind|note)$/i.test(m[1])) {
							add(m[0]);
							add(m[2]);
						}
					}
				}
			}
			// 针对 flag 事实，同时收集 detail 与 output 中的短行字面量（含非花括号自定义格式）
			if (fact.kind === "flag") {
				for (const rawField of [fact.detail, fact.output]) {
					for (const line of String(rawField ?? "").split(/\r?\n/)) {
						const clean = line.trim();
						if (clean.length >= 4 && clean.length <= 160) {
							add(clean);
							for (const tok of clean.split(/\s+/)) {
								if (tok.length >= 6 && tok.length <= 128 && /^[A-Za-z0-9_.:{}-]+$/.test(tok)) {
									add(tok);
								}
							}
						}
					}
				}
			}
		}
	}

	return [...lits].sort((a, b) => b.length - a.length);
}

const SAFE_NON_DOMAIN_EXTS = new Set([
	"js",
	"ts",
	"jsx",
	"tsx",
	"mjs",
	"cjs",
	"json",
	"yaml",
	"yml",
	"xml",
	"html",
	"htm",
	"css",
	"scss",
	"php",
	"jsp",
	"jspx",
	"asp",
	"aspx",
	"py",
	"rb",
	"go",
	"rs",
	"java",
	"class",
	"jar",
	"war",
	"ear",
	"sh",
	"bash",
	"zsh",
	"bat",
	"ps1",
	"sql",
	"db",
	"sqlite",
	"conf",
	"cfg",
	"ini",
	"env",
	"properties",
	"toml",
	"lock",
	"txt",
	"md",
	"log",
	"csv",
	"pdf",
	"png",
	"jpg",
	"jpeg",
	"gif",
	"svg",
	"ico",
	"woff",
	"woff2",
	"ttf",
	"zip",
	"tar",
	"gz",
	"tgz",
	"bak",
	"old",
	"swp",
	"exe",
	"dll",
	"so",
	"dylib",
	"action",
	"do",
	"vue",
	"map",
	"pem",
	"crt",
	"key",
	"cer",
	"csr",
	"p12",
	"jks",
	"pub",
	"sys",
	"fn",
	"core",
]);

const SAFE_CONFIG_PATH_PREFIXES = [
	"org.apache.",
	"com.alibaba.",
	"java.",
	"javax.",
	"jakarta.",
	"management.endpoints.",
	"nacos.core.",
	"xpack.security.",
];

const COMMON_DOMAIN_TLDS = new Set([
	"com",
	"net",
	"org",
	"gov",
	"edu",
	"mil",
	"int",
	"biz",
	"info",
	"name",
	"pro",
	"xyz",
	"top",
	"site",
	"online",
	"store",
	"tech",
	"app",
	"dev",
	"cloud",
	"page",
	"link",
	"live",
	"work",
	"shop",
	"club",
	"vip",
	"beer",
	"wiki",
	"blog",
	"news",
	"plus",
	"team",
	"zone",
	"space",
	"world",
	"today",
	"email",
	"games",
	"media",
	"local",
	"internal",
	"lan",
	"corp",
	"intranet",
	"ctf",
	"target",
	"lab",
	"box",
	"htb",
	"thm",
	"test",
	"example",
	"svc",
	"cluster",
	"home",
	"arpa",
]);

function shouldRedactDomainToken(token: string): boolean {
	const lower = token.toLowerCase();
	const labels = lower.split(".");
	if (labels.length < 2) return false;
	const tld = labels[labels.length - 1];
	// 排除静态文件扩展名与纯数字版本号
	if (SAFE_NON_DOMAIN_EXTS.has(tld)) return false;
	if (labels.every((seg) => /^\d+$/.test(seg))) return false;
	// 仅放行精确已知的 Java/框架配置命名空间（且末端非真实国家码/常见顶级域）
	if (
		SAFE_CONFIG_PATH_PREFIXES.some((prefix) => lower.startsWith(prefix)) &&
		tld.length !== 2 &&
		!COMMON_DOMAIN_TLDS.has(tld)
	) {
		return false;
	}
	// 3 级及以上域名（如 admin.hema.ai / auth.hema.ai / api.client.co.uk / portal.corp.beer）一律脱敏
	if (labels.length >= 3 && /^[a-z]{2,24}$/.test(tld)) return true;
	// 2 级域名：覆盖全部 2 字母 ccTLD（已排除 js/ts/py/rb/go/rs/sh/md/db/so/do/fn）及常见 gTLD/新顶级域
	if (tld.length === 2 || COMMON_DOMAIN_TLDS.has(tld)) return true;
	return false;
}

/**
 * 强脱敏清洗：彻底剥离目标 URL、IPv4/IPv6、端口、凭据、JWT、Cookie、邮箱、私钥、域名与 Flag。
 * 任何写入 `experience` 表的文本均必须经过本函数过滤。
 */
export function sanitizeExperienceText(text: string, st?: NuwaState, maxLen = 180): string {
	let out = String(text ?? "").replace(/\r/g, " ").replace(/\n+/g, " ");
	if (!out.trim()) return "";

	// 1. 优先精准擦除当前项目的靶标地址、主机、Scope/SAN 域名、项目 ID 以及 flag/cred 明文字面量
	for (const lit of collectSensitiveLiterals(st)) {
		const re = new RegExp(escapeRegexLiteral(lit), "gi");
		out = out.replace(re, "<REDACTED>");
	}

	// 2. PEM 私钥块
	out = out.replace(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g, "<KEY>");

	// 3. 任意协议 URL（含 http/https/ws/ftp/数据库连接串）
	out = out.replace(
		/\b(?:https?|wss?|ftp|sftp|jdbc:[a-z0-9]+|mysql|postgres(?:ql)?|redis|mongodb(?:\+srv)?|ldap|smb|ssh):\/\/[^\s"'<>]+/gi,
		"<URL>",
	);

	// 4. Flag 格式（花括号格式 flag{...}/CTF{...} 与非花括号格式 FLAG-2026-...）
	out = out.replace(/\b[A-Za-z0-9_-]{2,20}\{[^}\s]{2,160}\}/g, "<FLAG>");
	out = out.replace(/\b(?:FLAG|CTF)[-_][A-Za-z0-9_-]{6,120}\b/gi, "<FLAG>");

	// 5. JWT / Bearer / Basic 认证凭据与 Cookie
	out = out.replace(/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*\b/g, "<TOKEN>");
	out = out.replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi, "<CRED>");
	out = out.replace(/\b(?:Set-)?Cookie\s*:\s*[^\r\n]+/gi, "Cookie:<CRED>");
	out = out.replace(/\bAuthorization\s*:\s*[^\n,;]+/gi, "Authorization:<CRED>");

	// 6. 常见凭据与会话键值对（password/token/secret/api_key/session/cookie/user 等）
	out = out.replace(
		/\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session(?:_?id)?|jsessionid|phpsessid|rememberme|csrftoken|xsrf[-_]?token|laravel_session|_gitlab_session|auth(?:_?token)?|credential|username|user)\s*([:=])\s*[^\s,;'"`]+/gi,
		"$1$2<SECRET>",
	);

	// 7. 云厂商密钥前缀与长随机十六进制密钥
	out = out.replace(/\b(?:AKIA|ASIA|ghp_|gho_|glpat-|sk-[A-Za-z0-9])[A-Za-z0-9_-]{8,}\b/g, "<SECRET>");
	out = out.replace(/\b[a-f0-9]{32,}\b/gi, "<HASH>");

	// 8. 邮箱地址
	out = out.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "<EMAIL>");

	// 9. IPv4（含 CIDR 与端口）及 IPv6 地址
	out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2}|:\d{1,5})?\b/g, "<IP>");
	out = out.replace(/\[?(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\]?(?::\d{1,5})?/gi, (m) =>
		m.includes("::") || (m.match(/:/g)?.length ?? 0) >= 3 ? "<IP>" : m,
	);

	// 10. 显式端口表达（:8080 / port 8080 / 端口 8080，注意中文不走 ASCII \b）
	out = out.replace(/(?<=[^\d:]):(\d{2,5})\b/g, ":<PORT>");
	out = out.replace(/(?:\bport|端口)\s*[:=]?\s*\d{1,5}\b/gi, (m) =>
		m.startsWith("端口") ? "端口 <PORT>" : "port <PORT>",
	);

	// 11. 通用域名脱敏（覆盖 .ai / .co.uk / .hk / .beer / .internal 等任意国家二级域与新顶级域，排除静态文件扩展名）
	out = out.replace(
		/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
		(match) => (shouldRedactDomainToken(match) ? "<HOST>" : match),
	);

	// 12. 合并冗余占位与空白
	out = out
		.replace(/(?:<REDACTED>\s*){2,}/g, "<REDACTED> ")
		.replace(/\s+/g, " ")
		.trim();

	return out.length > maxLen ? `${out.slice(0, maxLen - 3)}...` : out;
}

const EP_SAFE_CATEGORIES: ReadonlyArray<{ category: string; re: RegExp }> = [
	{ category: "graphql", re: /\b(?:graphql|graphiql)\b/i },
	{ category: "swagger", re: /\bswagger(?:[-_]?ui)?\b/i },
	{ category: "openapi", re: /\b(?:openapi|api-docs)\b/i },
	{ category: "actuator", re: /\bactuator\b/i },
	{ category: "upload", re: /\buploads?\b/i },
	{ category: "admin", re: /\b(?:admin|console|manager|dashboard)\b/i },
	{ category: "login", re: /\b(?:login|signin|sign-in|auth|oauth|sso)\b/i },
	{ category: "api", re: /\bapi\b/i },
];

/**
 * 归一化意图键名，彻底剥离世代/轮次前缀 `e<N>:`、单项目事实编号（`fNNN`/`iNNN`）、
 * 目标域名、端口号及私有租户路径，确保跨项目聚合复用且零靶标信息泄漏。
 */
export function canonicalizeExperienceIntentKey(rawKey: string): string {
	let key = String(rawKey ?? "")
		.trim()
		.toLowerCase();
	if (!key) return "unknown";

	// 剥离 e2: / e10: 等多轮扩张前缀
	key = key.replace(/^(?:e\d+:)+/i, "");

	// 1. SAN 域名派生意图：san:f001:admin.example.internal -> san:domain
	if (/^san:(?:f\d+:)?/.test(key) && key !== "san") {
		return "san:domain";
	}

	// 2. 端口服务深挖意图：svc:f002:18443 / svc:8080 -> svc:port
	if (/^svc:(?:f\d+(?::.*)?|\d+)$/.test(key)) {
		return "svc:port";
	}

	// 3. 端点审计意图：ep:f003:/tenant-acme-corp/login -> 仅映射受控白名单类别，其余统一归为 ep:endpoint
	const epMatch = key.match(/^ep:(?:f\d+(?::(.*))?|(\/.*))$/);
	if (epMatch) {
		const rawPath = epMatch[1] ?? epMatch[2] ?? "";
		if (rawPath) {
			const normalizedSegs = rawPath.replace(/[^a-z0-9-]+/g, " ");
			for (const { category, re } of EP_SAFE_CATEGORIES) {
				if (re.test(normalizedSegs)) return `ep:${category}`;
			}
		}
		return "ep:endpoint";
	}

	// 4. 事实/意图 ID 绑定型派生键剥离单项目编号
	const derivedIdMatch = key.match(/^(exp|pivot|reuse|migrated):[fi]\d+(?::.*)?$/);
	if (derivedIdMatch) {
		return derivedIdMatch[1];
	}

	// 5. WAF 换路与战略复盘键归一化
	if (/^waf-bypass:[fi]?\d+(?::.*)?$/.test(key)) {
		return "waf-bypass";
	}
	const reflectMatch = key.match(/^reflect:(?:e\d+:)?([a-z]+)(?::.*)?$/);
	if (reflectMatch) {
		return `reflect:${reflectMatch[1]}`;
	}
	if (/^custom:[a-f0-9]{6,}$/.test(key)) {
		return "custom";
	}

	// 6. 知识库与双盲复验键剥离具体事实 ID
	key = key.replace(/^kb:f\d+:/i, "kb:");
	key = key.replace(/^(verify(?:-[a-z]+)?):f\d+(?::|$)/i, (_, p1: string) => `${p1}:`).replace(/:$/, "");

	// 7. 兜底剥离残留 IPv4、数字端口或单项目事实编号
	key = key
		.replace(/(?:\d{1,3}[.-]){3}\d{1,3}(?:[:-]\d{1,5})?/g, "target")
		.replace(/:[fi]\d+(?=:|$)/g, "")
		.replace(/:\d{2,5}(?=:|$)/g, ":port")
		.replace(/\s+/g, "-")
		.replace(/[^a-z0-9:_-]+/g, "")
		.replace(/:{2,}/g, ":")
		.replace(/^:|:$/g, "")
		.slice(0, 64);

	return key || "unknown";
}

/** 从项目状态已入账事实中提取标准化技术栈关键词列表（去重保序）。 */
export function extractStateTechStack(st: NuwaState): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	const push = (t: string) => {
		const norm = t.trim().toLowerCase();
		if (!norm || seen.has(norm)) return;
		seen.add(norm);
		out.push(norm);
	};

	const TECH_KINDS = new Set<FactKind>(["service", "endpoint", "vuln", "asset"]);
	const facts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));

	for (const fact of facts) {
		if (!TECH_KINDS.has(fact.kind)) continue;
		if (Array.isArray(fact.meta?.tech)) {
			for (const rawTech of fact.meta.tech) {
				const matched = TECH_PATTERNS.find((p) => p.re.test(String(rawTech)));
				if (matched) push(matched.name);
				else {
					const clean = String(rawTech).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
					if (clean.length >= 2 && clean.length <= 24) push(clean);
				}
			}
		}
		const blob = [fact.title ?? "", fact.detail ?? "", fact.output ?? "", fact.meta?.server ?? ""].join("\n");
		for (const { name, re } of TECH_PATTERNS) {
			if (re.test(blob)) push(name);
		}
	}

	return out;
}

function mergeExperienceNote(existing: string, incoming: string, maxLen = 220): string {
	const cleanNew = incoming.trim();
	if (!cleanNew) return existing;
	const cleanOld = existing.trim();
	if (!cleanOld) return cleanNew.slice(0, maxLen);
	if (cleanOld.includes(cleanNew)) return cleanOld;
	const merged = `${cleanOld}; ${cleanNew}`;
	return merged.length > maxLen ? merged.slice(merged.length - maxLen) : merged;
}

const POSITIVE_PROOF_KINDS = new Set<FactKind>(["vuln", "flag", "loot", "cred", "service", "endpoint", "asset"]);
const NEGATIVE_NOTE_RE = /(未发现|无异常|不适用|版本不匹配|无此功能|未开启|不存在|not\s+found|no\s+vuln)/i;
const PROXY_WRAPPER_TECHS = new Set<string>(["nginx", "apache", "openresty", "caddy", "iis"]);
const MS_PER_DAY = 86_400_000;
const EXPERIENCE_DECAY_HALF_LIFE_DAYS = 90;

function normalizeMetaTech(rawTech: unknown): string | null {
	const raw = String(rawTech ?? "").trim();
	if (!raw) return null;
	const matched = TECH_PATTERNS.find((p) => p.re.test(raw));
	if (matched) return matched.name;
	const clean = raw.toLowerCase().replace(/[^a-z0-9_-]/g, "");
	if (clean.length >= 2 && clean.length <= 24) return clean;
	return null;
}

function extractTechsFromText(text: string, extraTechs: readonly string[] = []): string[] {
	const src = String(text ?? "");
	if (!src.trim()) return [];
	const seen = new Set<string>();
	const out: string[] = [];
	const push = (t: string) => {
		const norm = t.trim().toLowerCase();
		if (!norm || norm === "generic" || seen.has(norm)) return;
		seen.add(norm);
		out.push(norm);
	};
	for (const { name, re } of TECH_PATTERNS) {
		if (re.test(src)) push(name);
	}
	for (const extra of extraTechs) {
		const norm = String(extra ?? "").trim().toLowerCase();
		if (!norm || norm === "generic" || seen.has(norm)) continue;
		const re = new RegExp(`\\b${escapeRegexLiteral(norm)}\\b`, "i");
		if (re.test(src)) push(norm);
	}
	return out;
}

function extractTechsFromFacts(
	facts: readonly Fact[],
	extraTechs: readonly string[],
	includeOutput: boolean,
): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	const push = (t: string | null) => {
		if (!t) return;
		const norm = t.trim().toLowerCase();
		if (!norm || norm === "generic" || seen.has(norm)) return;
		seen.add(norm);
		out.push(norm);
	};

	for (const fact of facts) {
		// 跳过 flag / cred 事实文本，避免 flag 字符串或泄露的下游连接串污染技术栈归因
		if (fact.kind === "flag" || fact.kind === "cred") continue;
		if (Array.isArray(fact.meta?.tech)) {
			for (const rawTech of fact.meta.tech) {
				push(normalizeMetaTech(rawTech));
			}
		}
		const primaryBlob = [fact.title ?? "", fact.detail ?? ""].join("\n");
		for (const t of extractTechsFromText(primaryBlob, extraTechs)) push(t);
		if (includeOutput) {
			const secondaryBlob = [fact.output ?? "", fact.meta?.server ?? ""].join("\n");
			for (const t of extractTechsFromText(secondaryBlob, extraTechs)) push(t);
		}
	}
	return out;
}

function preferAppLayerTechs(techs: readonly string[]): string[] {
	const unique: string[] = [];
	const seen = new Set<string>();
	for (const t of techs) {
		const norm = String(t ?? "").trim().toLowerCase();
		if (!norm || norm === "generic" || seen.has(norm)) continue;
		seen.add(norm);
		unique.push(norm);
	}
	if (unique.length === 0) return [];
	const appLayer = unique.filter((t) => !PROXY_WRAPPER_TECHS.has(t));
	return appLayer.length > 0 ? appLayer : unique;
}

/**
 * 为单条意图解析精确归因的技术栈，避免多组件项目产生跨组件笛卡尔积污染：
 * 1. 优先从 `intent.key` 直接提取显式技术标识（如 `kb:f002:spring` → `spring`）；
 * 2. 其次从 `intent.title` 与本意图直接产出的 `linkedFacts`（优先 `meta.tech`/标题/详情，未命中再看 `output`/`server`）提取；
 * 3. 若仍未命中，回溯 `intent.from` 引用的前提事实（混合前提存在应用层组件时过滤纯反向代理外壳）；
 * 4. 均未命中（如无 `from` 的通用种子意图）时，过滤 `projectTechKeys` 中的纯反向代理外壳层（若存在应用层组件），否则回退 `projectTechKeys` 或 `["generic"]`。
 */
export function resolveIntentTechKeys(
	intent: Intent,
	linkedFacts: readonly Fact[],
	st: NuwaState,
	projectTechKeys: readonly string[],
): string[] {
	const knownProjectTechs = projectTechKeys
		.map((t) => String(t ?? "").trim().toLowerCase())
		.filter((t) => Boolean(t) && t !== "generic");

	// Step 1a: 直接从 intent.key 提取显式技术关键词（如 kb:f002:spring / ep:f003:/actuator/env）
	const keyTechs = extractTechsFromText(String(intent.key ?? ""), knownProjectTechs);
	if (keyTechs.length > 0) return keyTechs;

	// Step 1b: 从 intent.title 与 linkedFacts 的结构化字段（meta.tech / title / detail）提取
	const directTechs: string[] = [];
	const pushDirect = (list: readonly string[]) => {
		for (const t of list) {
			if (!directTechs.includes(t)) directTechs.push(t);
		}
	};
	pushDirect(extractTechsFromText(String(intent.title ?? ""), knownProjectTechs));
	pushDirect(extractTechsFromFacts(linkedFacts, knownProjectTechs, false));
	if (directTechs.length > 0) return directTechs;

	// 若结构化字段未命中，再检查 linkedFacts 的回显与 Server 头（output / meta.server）
	const outputTechs = extractTechsFromFacts(linkedFacts, knownProjectTechs, true);
	if (outputTechs.length > 0) return outputTechs;

	// Step 1c: 回溯 intent.from 引用的前提事实
	const fromIds = Array.isArray(intent.from) ? intent.from : [];
	if (fromIds.length > 0 && st.facts) {
		const fromFacts: Fact[] = [];
		for (const fid of fromIds) {
			const f = st.facts[fid];
			if (f) fromFacts.push(f);
		}
		const fromPrimary = extractTechsFromFacts(fromFacts, knownProjectTechs, false);
		const fromAll = fromPrimary.length > 0 ? fromPrimary : extractTechsFromFacts(fromFacts, knownProjectTechs, true);
		if (fromAll.length > 0) {
			return preferAppLayerTechs(fromAll);
		}
	}

	// Step 3: 通用种子意图无直接/前提技术绑定时，存在应用层组件则过滤纯反向代理外壳层
	const fallback = preferAppLayerTechs(knownProjectTechs);
	return fallback.length > 0 ? fallback : ["generic"];
}

function classifyIntentOutcome(
	intent: Intent,
	linkedFacts: Fact[],
	st: NuwaState,
): { outcome: "positive" | "negative" | "skip"; helpful: string; pitfall: string } {
	if (intent.phase === "report") {
		return { outcome: "skip", helpful: "", pitfall: "" };
	}

	const canonicalKey = canonicalizeExperienceIntentKey(intent.key);
	const nonBlockedFacts = linkedFacts.filter((f) => f.kind !== "blocked");
	const blockedFacts = linkedFacts.filter((f) => f.kind === "blocked");

	// 负向经验：显式 blocked、仅产出 blocked 事实，或多次尝试失败无产出
	if (
		intent.status === "blocked" ||
		(intent.status === "done" && nonBlockedFacts.length === 0 && blockedFacts.length > 0) ||
		(intent.status !== "done" && intent.attempts >= 3 && nonBlockedFacts.length === 0)
	) {
		const rawReason = intent.note || blockedFacts[0]?.title || intent.title || "路径受阻或条件不满足";
		const pitfall = sanitizeExperienceText(`${intent.phase}/${canonicalKey}: ${rawReason}`, st, 160);
		return { outcome: "negative", helpful: "", pitfall };
	}

	// 误报抗污染：双盲复验已驳回（verifyStage === "rejected"）的漏洞事实直接归类为负向避坑教训
	const rejectedVuln = nonBlockedFacts.find((f) => f.kind === "vuln" && f.verifyStage === "rejected");
	if (rejectedVuln) {
		const rawRejectReason = rejectedVuln.verifyNote || rejectedVuln.title || "双盲复验未通过";
		const pitfall = sanitizeExperienceText(
			`${intent.phase}/${canonicalKey}: 双盲复验驳回误报 (${rawRejectReason})`,
			st,
			160,
		);
		return { outcome: "negative", helpful: "", pitfall };
	}

	if (intent.status !== "done") {
		return { outcome: "skip", helpful: "", pitfall: "" };
	}

	// 严禁未通过双盲复验的 candidate 或已驳回的 rejected 事实充当正向证明，防止虚增 success_count
	const confirmedNonBlocked = nonBlockedFacts.filter(
		(f) => f.verifyStage !== "candidate" && f.verifyStage !== "rejected",
	);

	// 正向经验：必须存在实质性有效且已确认的发现事实
	const strongFact =
		confirmedNonBlocked.find((f) => f.kind === "vuln" || f.kind === "flag" || f.kind === "loot" || f.kind === "cred") ??
		confirmedNonBlocked.find((f) => POSITIVE_PROOF_KINDS.has(f.kind));

	if (strongFact) {
		// 对 flag/cred 事实严禁引用其具体 title/detail 内容，仅保留抽象意图标题与事实类型
		const safeIntentTitle = sanitizeExperienceText(intent.title, st, 90);
		const safeFactHint =
			strongFact.kind === "flag" || strongFact.kind === "cred"
				? `验证达成 ${strongFact.kind} 目标证明`
				: sanitizeExperienceText(strongFact.title, st, 80);
		const helpful = sanitizeExperienceText(`[${strongFact.kind}] ${safeIntentTitle} -> ${safeFactHint}`, st, 160);
		return { outcome: "positive", helpful, pitfall: "" };
	}

	// 仅产出 note 且明确表示未发现/不适用时视为中性或轻微负向（若明确不适用/无发现则跳过不污染正经验）
	const noteFact = confirmedNonBlocked.find((f) => f.kind === "note");
	if (noteFact && NEGATIVE_NOTE_RE.test(`${noteFact.title} ${noteFact.detail}`)) {
		const pitfall = sanitizeExperienceText(`${canonicalKey}: 实测无异常/版本条件不匹配`, st, 140);
		return { outcome: "negative", helpful: "", pitfall };
	}

	return { outcome: "skip", helpful: "", pitfall: "" };
}

/**
 * 蒸馏项目终态经验并脱敏回写至 SQLite `experience` 表。
 *
 * - 自动识别项目技术栈（覆盖 36 个核心组件；未命中时回落为 `generic`）；
 * - 按单意图精确归因至直接关联技术栈（消除跨组件笛卡尔积污染）；
 * - 拒绝未复验候选漏洞（`verifyStage="candidate"`）膨胀正向计数，并将复验驳回误报（`verifyStage="rejected"`）沉淀为负向教训；
 * - 支持 `negativeOnly` 模式（中止/超时项目仅沉淀负向避坑教训）；
 * - 剥离全部目标 URL、IP、端口、凭据与 Flag，确保脱敏文本不含具体靶标信息；
 * - 按 `(tech_key, intent_key)` 增量累加 `success_count` / `fail_count`。
 */
export function distillProjectExperience(st: NuwaState, opts?: DistillOptions): DistillResult {
	const targetPath = opts?.dbPath?.trim() ? resolve(opts.dbPath.trim()) : resolveKbPath(opts?.agentHome);
	if (opts?.autoInit !== false) {
		ensureBundledKb(targetPath, { agentHome: opts?.agentHome, seedDir: opts?.seedDir });
	} else if (!existsSync(targetPath)) {
		throw new Error(`知识库不存在: ${targetPath}`);
	}

	const detectedTechs = extractStateTechStack(st);
	const techKeys = detectedTechs.length > 0 ? detectedTechs : ["generic"];
	const negativeOnly = opts?.negativeOnly === true;

	// 预先建立 intentId -> Fact[] 与 fact.key -> Fact[] 映射
	const factsByIntent = new Map<string, Fact[]>();
	const factsByKey = new Map<string, Fact[]>();
	for (const fact of Object.values(st.facts ?? {})) {
		if (fact.intent) {
			const list = factsByIntent.get(fact.intent) ?? [];
			list.push(fact);
			factsByIntent.set(fact.intent, list);
		}
		if (fact.key) {
			const list = factsByKey.get(fact.key) ?? [];
			list.push(fact);
			factsByKey.set(fact.key, list);
		}
	}

	// 汇总本项目的 (tech_key, intent_key) 增量，避免单项目内多条同键重复放大
	interface AggItem {
		techKey: string;
		intentKey: string;
		phase: Phase;
		successDelta: number;
		failDelta: number;
		helpful: string;
		pitfall: string;
	}
	const agg = new Map<string, AggItem>();
	let positive = 0;
	let negative = 0;
	let skipped = 0;

	for (const intent of Object.values(st.intents ?? {})) {
		const linked: Fact[] = [];
		const seenFactIds = new Set<string>();
		if (intent.to && st.facts?.[intent.to]) {
			linked.push(st.facts[intent.to]);
			seenFactIds.add(intent.to);
		}
		for (const f of factsByIntent.get(intent.id) ?? []) {
			if (!seenFactIds.has(f.id)) {
				linked.push(f);
				seenFactIds.add(f.id);
			}
		}
		if (linked.length === 0 && intent.key) {
			for (const f of factsByKey.get(intent.key) ?? []) {
				if (!seenFactIds.has(f.id)) {
					linked.push(f);
					seenFactIds.add(f.id);
				}
			}
		}

		const verdict = classifyIntentOutcome(intent, linked, st);
		if (verdict.outcome === "skip" || (negativeOnly && verdict.outcome === "positive")) {
			skipped += 1;
			continue;
		}
		if (verdict.outcome === "positive") positive += 1;
		else negative += 1;

		const canonicalKey = canonicalizeExperienceIntentKey(intent.key);
		const intentTechKeys = resolveIntentTechKeys(intent, linked, st, techKeys);
		for (const techKey of intentTechKeys) {
			const mapKey = `${techKey}::${canonicalKey}`;
			const cur = agg.get(mapKey) ?? {
				techKey,
				intentKey: canonicalKey,
				phase: intent.phase,
				successDelta: 0,
				failDelta: 0,
				helpful: "",
				pitfall: "",
			};
			if (verdict.outcome === "positive") {
				cur.successDelta += 1;
				if (verdict.helpful) cur.helpful = mergeExperienceNote(cur.helpful, verdict.helpful, 180);
			} else {
				cur.failDelta += 1;
				if (verdict.pitfall) cur.pitfall = mergeExperienceNote(cur.pitfall, verdict.pitfall, 180);
			}
			agg.set(mapKey, cur);
		}
	}

	const db = new Database(targetPath);
	const now = new Date().toISOString();
	let updated = 0;

	try {
		if (!hasTable(db, "experience")) {
			db.exec(EXPERIENCE_DDL);
		}

		const selectExisting = db.query(
			"SELECT helpful_pattern, pitfall_note FROM experience WHERE tech_key = ? AND intent_key = ?",
		);
		const upsertStmt = db.query(
			`INSERT INTO experience
			 (tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(tech_key, intent_key) DO UPDATE SET
			   phase = excluded.phase,
			   success_count = experience.success_count + excluded.success_count,
			   fail_count = experience.fail_count + excluded.fail_count,
			   helpful_pattern = excluded.helpful_pattern,
			   pitfall_note = excluded.pitfall_note,
			   updated_at = excluded.updated_at`,
		);

		const tx = db.transaction(() => {
			for (const item of agg.values()) {
				const prev = selectExisting.get(item.techKey, item.intentKey) as {
					helpful_pattern?: string;
					pitfall_note?: string;
				} | null;

				// 写入前再做一次脱敏闭环校验，彻底杜绝目标信息泄漏
				const safeHelpful = sanitizeExperienceText(
					mergeExperienceNote(prev?.helpful_pattern ?? "", item.helpful, 220),
					st,
					220,
				);
				const safePitfall = sanitizeExperienceText(
					mergeExperienceNote(prev?.pitfall_note ?? "", item.pitfall, 220),
					st,
					220,
				);

				upsertStmt.run(
					item.techKey,
					item.intentKey,
					item.phase,
					item.successDelta,
					item.failDelta,
					safeHelpful,
					safePitfall,
					now,
				);
				updated += 1;
			}
		});
		tx();
		finalizeWritableKbDb(db);
	} finally {
		db.close();
	}

	return {
		ok: true,
		dbPath: targetPath,
		techKeys,
		updated,
		positive,
		negative,
		skipped,
	};
}

// ============================================================================
// UCB1 跨项目意图优先级提权 / 避坑降权引擎（输出严格限定于 [-8, +15]）
// ============================================================================

function computeExperienceAgeDecay(updatedAt: string | undefined, nowMs: number): number {
	const ts = updatedAt ? Date.parse(updatedAt) : Number.NaN;
	if (!Number.isFinite(ts)) return 1;
	const ageDays = Math.max(0, (nowMs - ts) / MS_PER_DAY);
	return Math.pow(0.5, ageDays / EXPERIENCE_DECAY_HALF_LIFE_DAYS);
}

/**
 * 基于历史自进化经验表执行 UCB1（Upper Confidence Bound）计算，返回 `[-8, +15]` 闭区间优先级偏移。
 *
 * - 冷启动（库不存在或该技术栈尚无历史经验）返回 `0`；
 * - 按 90 天半衰期对每条历史记录执行温和时间衰减（`0.5^(ageDays/90)`），防止陈旧样本长期锁死探索；
 * - 同技术栈下历史高胜率路径获得显著正提权（最高 `+15`）；
 * - 历史反复失败/受阻路径获得负降权（最低 `-8`）；
 * - 该技术栈已有先验但当前路径尚未尝试时，按 UCB1 探索项给予温和正激励（`+1..+3`）。
 */
export function computeExperiencePriorityBoost(
	techStack: string | readonly string[],
	canonicalKey: string,
	opts?: BoostOptions,
): number {
	const rawList = Array.isArray(techStack) ? techStack : [techStack];
	const techs = [
		...new Set(
			rawList
				.map((t) => String(t ?? "").trim().toLowerCase())
				.filter(Boolean),
		),
	];
	const intentKey = canonicalizeExperienceIntentKey(canonicalKey);
	if (!techs.length || !intentKey || intentKey === "unknown") return 0;

	const targetPath = opts?.dbPath?.trim() ? resolve(opts.dbPath.trim()) : resolveKbPath(opts?.agentHome);
	if (!existsSync(targetPath) || statSync(targetPath).size === 0) {
		if (opts?.autoInit) {
			ensureBundledKb(targetPath, { agentHome: opts.agentHome, seedDir: opts.seedDir });
		} else {
			return 0;
		}
	}

	const db = openReadonlyKbDb(targetPath);
	try {
		if (!hasTable(db, "experience")) return 0;

		const placeholders = techs.map(() => "?").join(",");
		const rows = db
			.query(
				`SELECT intent_key, success_count, fail_count, updated_at
				 FROM experience
				 WHERE tech_key IN (${placeholders})`,
			)
			.all(...techs) as Array<{
			intent_key?: string;
			success_count?: number;
			fail_count?: number;
			updated_at?: string;
		}>;

		const nowMs = opts?.nowMs ?? Date.now();
		let totalN = 0;
		let s = 0;
		let f = 0;

		for (const row of rows) {
			const rowS = Math.max(0, Number(row.success_count ?? 0));
			const rowF = Math.max(0, Number(row.fail_count ?? 0));
			if (rowS <= 0 && rowF <= 0) continue;
			const decay = computeExperienceAgeDecay(row.updated_at, nowMs);
			const decayedS = rowS * decay;
			const decayedF = rowF * decay;
			totalN += decayedS + decayedF;
			if (row.intent_key === intentKey) {
				s += decayedS;
				f += decayedF;
			}
		}

		const EPS = 1e-9;
		if (totalN <= EPS) return 0;

		const n = s + f;

		const untriedBoost = Math.max(1, Math.min(3, Math.round(Math.sqrt(Math.log(totalN + 1)))));

		// 同一技术栈已有其他路径经验，但本意图尚未探索 -> 温和 UCB1 探索激励 [+1, +3]
		if (n <= EPS) {
			return untriedBoost;
		}

		// Beta(0.5, 0.5) 平滑胜率 + UCB1 置信上界探索项（衰减后有效样本 n < 1 时向未探索基线平滑收敛，避免 1/n 发散）
		const smoothedMean = (s + 0.5) / (n + 1);
		const exploreTerm = 0.18 * Math.sqrt(Math.log(Math.max(totalN, n) + 1) / Math.max(1, n));
		const ucbScore = smoothedMean + exploreTerm;
		const delta = ucbScore - 0.5;

		const ucbBoost = delta >= 0 ? Math.round(delta * 26) : Math.round(delta * 18);
		const rawBoost = n < 1 ? Math.round(untriedBoost * (1 - n) + ucbBoost * n) : ucbBoost;
		return Math.max(-8, Math.min(15, rawBoost));
	} catch {
		return 0;
	} finally {
		db.close();
	}
}
