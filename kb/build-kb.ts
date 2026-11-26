#!/usr/bin/env bun
/**
 * 女娲 v4 一键便携知识库建库脚本（纯 Bun 原生 bun:sqlite）。
 *
 * 特性：
 * - 零外部 sqlite3 / Python 依赖，开箱即用；
 * - 幂等初始化表结构并刷新种子资产（card / cve / poc / technique / kev / epss）及 FTS5 索引；
 * - 严禁清空或覆盖既有 `experience` 自进化经验表数据；
 * - 支持可选 `--nuclei-dir <dir>` 只读扫描本机 nuclei-templates YAML 元数据头并增量入库（严格跳过任何请求/载荷段）。
 *
 * 用法：
 *   env -u BUN_OPTIONS bun kb/build-kb.ts [--out <dbPath>] [--seed-dir <dir>] [--nuclei-dir <dir>] [--stats]
 */
import { Database } from "bun:sqlite";
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { ingestV7SeedPack } from "../omp/kb-v2";

export interface SeedCard {
	key: string;
	tech_key: string;
	title: string;
	keywords?: string;
	body: string;
}

export interface SeedCve {
	cve_id: string;
	product: string;
	affected_versions?: string;
	severity?: string;
	cvss?: number;
	cwe?: string;
	descr: string;
	verify_hint?: string;
	remediation?: string;
	advisories?: string[];
	kev?: boolean;
	epss?: { score: number; percentile?: number };
	published?: string;
}

export interface SeedTechnique {
	id: string;
	name: string;
	tactics?: string;
	platforms?: string;
	summary?: string;
	detection_hint?: string;
}

export interface BuildKbOptions {
	outPath: string;
	seedDir?: string;
	nucleiDir?: string;
	/** 是否自动并入 kb/seed-v7-pack.json（默认 true）。 */
	includeV7SeedPack?: boolean;
}

export interface BuildKbStats {
	dbPath: string;
	cards: number;
	cves: number;
	pocs: number;
	techniques: number;
	kevs: number;
	epss: number;
	templates: number;
	templateCveMaps: number;
	experiences: number;
	kbItems: number;
	nucleiScanned: number;
	nucleiAddedCves: number;
	builtAt: string;
}

export interface NucleiHeaderMeta {
	id: string;
	name: string;
	severity: string;
	description: string;
	cves: string[];
	cvss: number;
	cwe: string;
	tags: string;
	references: string[];
}

const CVE_ID_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const CWE_ID_RE = /\bCWE-\d{1,5}\b/i;
const MAX_NUCLEI_FILES = 50_000;
const MAX_HEADER_READ_BYTES = 8192;

/** 仅允许公开 HTTPS 官方公告/文档 URL 入库，排除内网或非常规协议。 */
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

function defaultAgentHome(): string {
	if (process.env.PI_AGENT_HOME?.trim()) return resolve(process.env.PI_AGENT_HOME.trim());
	const ompHome = join(homedir(), ".omp", "agent");
	if (existsSync(ompHome)) return ompHome;
	return join(homedir(), ".pi", "agent");
}

export function defaultBuildOutPath(): string {
	const envDb = process.env.NUWA_KB_DB?.trim();
	if (envDb) return resolve(envDb);
	return join(defaultAgentHome(), "nuwa-kb", "kb.db");
}

function stripYamlQuotes(raw: string): string {
	const s = raw.trim();
	if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
		return s.slice(1, -1).trim();
	}
	return s;
}

/**
 * 只读解析 nuclei-templates YAML 头部元数据（id 与 info 区块）。
 * 遇到任何请求/执行体顶级键（http/requests/network/code 等）立即截断停止，绝不读取载荷内容。
 */
export function parseNucleiYamlHeader(rawText: string): NucleiHeaderMeta | null {
	const lines = rawText.replace(/\r/g, "").split("\n");
	let id = "";
	let inInfo = false;
	let infoIndent = -1;
	let currentSection = "";
	let sectionIndent = -1;

	let name = "";
	let severity = "UNKNOWN";
	const descParts: string[] = [];
	const refList: string[] = [];
	const tagList: string[] = [];
	const cveSet = new Set<string>();
	let cvss = 0;
	let cwe = "";

	const STOP_TOP_KEYS = new Set([
		"http",
		"requests",
		"network",
		"tcp",
		"dns",
		"file",
		"headless",
		"ssl",
		"websocket",
		"whois",
		"code",
		"javascript",
		"workflows",
		"variables",
		"flow",
	]);

	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;

		const indent = line.length - line.trimStart().length;

		// 顶级键解析
		if (indent === 0) {
			const topMatch = trimmed.match(/^([A-Za-z0-9_-]+)\s*:(.*)$/);
			if (!topMatch) continue;
			const key = topMatch[1].toLowerCase();
			const val = stripYamlQuotes(topMatch[2] ?? "");

			if (STOP_TOP_KEYS.has(key)) {
				// 抵达模板执行体，立即停止解析
				break;
			}
			if (key === "id") {
				id = val;
				inInfo = false;
				currentSection = "";
				continue;
			}
			if (key === "info") {
				inInfo = true;
				infoIndent = -1;
				currentSection = "";
				continue;
			}
			inInfo = false;
			currentSection = "";
			continue;
		}

		if (!inInfo) continue;
		if (infoIndent < 0) infoIndent = indent;

		// 处理子块（reference / classification / description 多行块）
		if (currentSection && indent > sectionIndent) {
			if (currentSection === "description") {
				if (descParts.join(" ").length < 480) descParts.push(trimmed);
				continue;
			}
			if (currentSection === "reference") {
				const item = stripYamlQuotes(trimmed.replace(/^-\s*/, ""));
				if (isSafeAdvisoryUrl(item) && refList.length < 5) refList.push(item);
				continue;
			}
			if (currentSection === "tags") {
				const item = stripYamlQuotes(trimmed.replace(/^-\s*/, ""));
				if (item) tagList.push(item);
				continue;
			}
			if (currentSection === "classification") {
				const sub = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
				if (sub) {
					const sk = sub[1].toLowerCase();
					const sv = stripYamlQuotes(sub[2] ?? "");
					if (sk === "cve-id") {
						for (const m of sv.matchAll(CVE_ID_RE)) cveSet.add(m[0].toUpperCase());
					} else if (sk === "cvss-score") {
						const parsed = Number.parseFloat(sv);
						if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 10) cvss = parsed;
					} else if (sk === "cwe-id") {
						const cm = sv.match(CWE_ID_RE);
						if (cm) cwe = cm[0].toUpperCase();
					}
				} else if (trimmed.startsWith("-")) {
					for (const m of trimmed.matchAll(CVE_ID_RE)) cveSet.add(m[0].toUpperCase());
					const cm = trimmed.match(CWE_ID_RE);
					if (cm && !cwe) cwe = cm[0].toUpperCase();
				}
				continue;
			}
		}

		// 重置当前子块
		if (indent <= sectionIndent) {
			currentSection = "";
			sectionIndent = -1;
		}

		if (indent === infoIndent) {
			const kv = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
			if (!kv) continue;
			const k = kv[1].toLowerCase();
			const v = stripYamlQuotes(kv[2] ?? "");

			if (k === "name") {
				name = v;
			} else if (k === "severity") {
				severity = v ? v.toUpperCase() : "UNKNOWN";
			} else if (k === "description") {
				if (v === "|" || v === ">" || v === "|-" || v === ">-" || v === "") {
					currentSection = "description";
					sectionIndent = indent;
				} else {
					descParts.push(v);
				}
			} else if (k === "reference") {
				if (!v) {
					currentSection = "reference";
					sectionIndent = indent;
				} else if (isSafeAdvisoryUrl(v)) {
					refList.push(v);
				}
			} else if (k === "tags") {
				if (!v) {
					currentSection = "tags";
					sectionIndent = indent;
				} else {
					for (const t of v.split(",").map((x) => x.trim()).filter(Boolean)) {
						tagList.push(t);
					}
				}
			} else if (k === "classification") {
				currentSection = "classification";
				sectionIndent = indent;
			}
		}
	}

	if (!id) return null;
	for (const m of id.matchAll(CVE_ID_RE)) cveSet.add(m[0].toUpperCase());
	for (const t of tagList) {
		for (const m of t.matchAll(CVE_ID_RE)) cveSet.add(m[0].toUpperCase());
	}
	if (cveSet.size === 0) return null;

	const descr = descParts
		.join(" ")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 500);

	return {
		id,
		name: name || id,
		severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(severity) ? severity : "UNKNOWN",
		description: descr || `${name || id} 公开安全元数据条目。`,
		cves: [...cveSet],
		cvss,
		cwe,
		tags: [...new Set(tagList)].slice(0, 12).join(","),
		references: [...new Set(refList)].slice(0, 4),
	};
}

function readHeadUtf8(filePath: string, maxBytes = MAX_HEADER_READ_BYTES): string {
	let fd = -1;
	try {
		fd = openSync(filePath, "r");
		const buf = Buffer.alloc(maxBytes);
		const n = readSync(fd, buf, 0, maxBytes, 0);
		return buf.subarray(0, Math.max(0, n)).toString("utf8");
	} catch {
		return "";
	} finally {
		if (fd >= 0) {
			try {
				closeSync(fd);
			} catch {
				/* ignore */
			}
		}
	}
}

function collectYamlFiles(rootDir: string, out: string[] = []): string[] {
	if (out.length >= MAX_NUCLEI_FILES) return out;
	let entries: Array<{ name: string; isDirectory(): boolean; isFile(): boolean }> = [];
	try {
		entries = readdirSync(rootDir, { withFileTypes: true });
	} catch {
		return out;
	}
	for (const ent of entries) {
		if (out.length >= MAX_NUCLEI_FILES) break;
		if (ent.name.startsWith(".")) continue;
		const full = join(rootDir, ent.name);
		if (ent.isDirectory()) {
			collectYamlFiles(full, out);
		} else if (ent.isFile() && /\.ya?ml$/i.test(ent.name)) {
			out.push(full);
		}
	}
	return out;
}

function inferProductFromTags(tags: string, name: string): string {
	const ignore = new Set(["cve", "http", "https", "network", "tcp", "dns", "kev", "exposure", "misconfig", "vuln", "panel", "tech"]);
	for (const raw of tags.split(",")) {
		const t = raw.trim().toLowerCase();
		if (!t || ignore.has(t) || /^cve\d{4}$/i.test(t) || /^cve-\d{4}/i.test(t)) continue;
		return t.slice(0, 40);
	}
	const firstWord = name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, " ")
		.trim()
		.split(/\s+/)[0];
	return firstWord ? firstWord.slice(0, 40) : "";
}

function tableCount(db: Database, table: string): number {
	const has = db
		.query("SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name = ?")
		.get(table) as { name?: string } | null;
	if (!has?.name) return 0;
	const row = db.query(`SELECT COUNT(*) AS cnt FROM ${table}`).get() as { cnt?: number } | null;
	return Number(row?.cnt ?? 0);
}

function finalizeWritableKbDb(db: Database): void {
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

function openReadonlyKbDb(filePath: string): Database {
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

/** 读取已构建知识库各表统计。 */
export function readKbStats(dbPath: string): BuildKbStats {
	const resolved = resolve(dbPath);
	if (!existsSync(resolved)) {
		throw new Error(`知识库文件不存在: ${resolved}`);
	}
	const db = openReadonlyKbDb(resolved);
	try {
		const builtRow = db.query("SELECT value FROM kb_meta WHERE key = ?").get("built_at") as { value?: string } | null;
		return {
			dbPath: resolved,
			cards: tableCount(db, "card"),
			cves: tableCount(db, "cve"),
			pocs: tableCount(db, "poc"),
			techniques: tableCount(db, "technique"),
			kevs: tableCount(db, "kev"),
			epss: tableCount(db, "epss"),
			templates: tableCount(db, "template"),
			templateCveMaps: tableCount(db, "template_cve_map"),
			experiences: tableCount(db, "experience"),
			kbItems: tableCount(db, "kb_items"),
			nucleiScanned: Number(
				(db.query("SELECT value FROM kb_meta WHERE key = ?").get("nuclei_scanned") as { value?: string } | null)
					?.value ?? 0,
			),
			nucleiAddedCves: Number(
				(db.query("SELECT value FROM kb_meta WHERE key = ?").get("nuclei_added_cves") as { value?: string } | null)
					?.value ?? 0,
			),
			builtAt: builtRow?.value ?? "",
		};
	} finally {
		db.close();
	}
}

/**
 * 幂等初始化 SQLite 知识库并刷新种子数据、重建 FTS5 索引。
 * 严格保护 `experience` 自进化经验表，绝不清空或覆盖既有历史经验。
 */
export function buildKb(opts: BuildKbOptions): BuildKbStats {
	const outPath = resolve(opts.outPath);
	const seedDir = resolve(opts.seedDir ?? import.meta.dir);
	const schemaPath = join(seedDir, "schema.sql");
	const cardsPath = join(seedDir, "seed-cards.json");
	const cvesPath = join(seedDir, "seed-cves.json");
	const techPath = join(seedDir, "seed-techniques.json");

	for (const reqPath of [schemaPath, cardsPath, cvesPath, techPath]) {
		if (!existsSync(reqPath)) {
			throw new Error(`缺少知识库种子文件: ${reqPath}`);
		}
	}

	const schemaSql = readFileSync(schemaPath, "utf8");
	const cards = JSON.parse(readFileSync(cardsPath, "utf8")) as SeedCard[];
	const cves = JSON.parse(readFileSync(cvesPath, "utf8")) as SeedCve[];
	const techniques = JSON.parse(readFileSync(techPath, "utf8")) as SeedTechnique[];

	mkdirSync(dirname(outPath), { recursive: true });
	const db = new Database(outPath);
	const builtAt = new Date().toISOString();

	let nucleiScanned = 0;
	let nucleiAddedCves = 0;

	try {
		// 1. 幂等初始化表结构（含 experience 表，CREATE TABLE IF NOT EXISTS 不会影响已有记录）
		db.exec(schemaSql);

		// 2. 在单一事务中刷新种子资产（严禁触碰 experience 表）
		const refreshSeeds = db.transaction(() => {
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
			const insPoc = db.query(
				"INSERT OR IGNORE INTO poc (cve_id, url, kind, title) VALUES (?, ?, ?, ?)",
			);
			const insKev = db.query(
				"INSERT OR REPLACE INTO kev (cve_id, added_date, note) VALUES (?, ?, ?)",
			);
			const insEpss = db.query(
				"INSERT OR REPLACE INTO epss (cve_id, score, percentile) VALUES (?, ?, ?)",
			);

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
		});
		refreshSeeds();

		// 3. 可选只读扫描本机 nuclei-templates YAML 元数据头并增量写入
		if (opts.nucleiDir) {
			const nucleiRoot = resolve(opts.nucleiDir);
			if (existsSync(nucleiRoot) && statSync(nucleiRoot).isDirectory()) {
				const files = collectYamlFiles(nucleiRoot);
				const insTpl = db.query(
					"INSERT OR REPLACE INTO template (id, path, name, severity, tags, source) VALUES (?, ?, ?, ?, ?, ?)",
				);
				const insMap = db.query(
					"INSERT OR IGNORE INTO template_cve_map (template_id, cve_id) VALUES (?, ?)",
				);
				const insCveIgnore = db.query(
					`INSERT OR IGNORE INTO cve
					 (cve_id, product, affected_versions, severity, cvss, cwe, descr, verify_hint, remediation, published, source)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				);
				const insPocIgnore = db.query(
					"INSERT OR IGNORE INTO poc (cve_id, url, kind, title) VALUES (?, ?, ?, ?)",
				);

				const applyNuclei = db.transaction(() => {
					for (const file of files) {
						nucleiScanned += 1;
						const head = readHeadUtf8(file);
						if (!head) continue;
						const meta = parseNucleiYamlHeader(head);
						if (!meta) continue;
						const relPath = relative(nucleiRoot, file).replace(/\\/g, "/");
						insTpl.run(meta.id, relPath, meta.name, meta.severity, meta.tags, "nuclei");
						const prod = inferProductFromTags(meta.tags, meta.name);
						for (const cid of meta.cves) {
							insMap.run(meta.id, cid);
							const changes = insCveIgnore.run(
								cid,
								prod,
								"",
								meta.severity,
								meta.cvss,
								meta.cwe,
								meta.description,
								"核对对应组件实测版本号与官方安全公告受影响范围。",
								"参照官方安全公告升级至修复版本。",
								"",
								"nuclei",
							);
							if (Number(changes.changes ?? 0) > 0) {
								nucleiAddedCves += 1;
							}
							for (const refUrl of meta.references) {
								insPocIgnore.run(cid, refUrl, "nuclei-ref", meta.name);
							}
						}
					}
				});
				applyNuclei();
			}
		}

		// 4. 重建 FTS5 全文索引并记录构建元信息
		const rebuildFts = db.transaction(() => {
			db.query("DELETE FROM cve_fts").run();
			db.query(
				"INSERT INTO cve_fts (cve_id, product, severity, descr, verify_hint) SELECT cve_id, product, severity, descr, verify_hint FROM cve",
			).run();

			db.query("DELETE FROM card_fts").run();
			db.query(
				"INSERT INTO card_fts (key, tech_key, title, keywords, body) SELECT key, tech_key, title, keywords, body FROM card",
			).run();

			const setMeta = db.query("INSERT OR REPLACE INTO kb_meta (key, value) VALUES (?, ?)");
			setMeta.run("schema_version", "7");
			setMeta.run("built_at", builtAt);
			setMeta.run("seed_dir", seedDir);
			setMeta.run("nuclei_scanned", String(nucleiScanned));
			setMeta.run("nuclei_added_cves", String(nucleiAddedCves));
		});
		rebuildFts();

		// 5. v7.0 自动摄入 seed-v7-pack.json 构建统一混合语义索引（总条目 >= 520）
		const v7PackPath = join(seedDir, "seed-v7-pack.json");
		if (opts.includeV7SeedPack !== false && existsSync(v7PackPath)) {
			ingestV7SeedPack(db, v7PackPath, { seedDir });
		}

		finalizeWritableKbDb(db);

		return {
			dbPath: outPath,
			cards: tableCount(db, "card"),
			cves: tableCount(db, "cve"),
			pocs: tableCount(db, "poc"),
			techniques: tableCount(db, "technique"),
			kevs: tableCount(db, "kev"),
			epss: tableCount(db, "epss"),
			templates: tableCount(db, "template"),
			templateCveMaps: tableCount(db, "template_cve_map"),
			experiences: tableCount(db, "experience"),
			kbItems: tableCount(db, "kb_items"),
			nucleiScanned,
			nucleiAddedCves,
			builtAt,
		};
	} finally {
		db.close();
	}
}

function parseCliArgs(argv: string[]): {
	outPath: string;
	seedDir?: string;
	nucleiDir?: string;
	stats: boolean;
	statsOnly: boolean;
	help: boolean;
} {
	let outPath = defaultBuildOutPath();
	let seedDir: string | undefined;
	let nucleiDir: string | undefined;
	let stats = false;
	let statsOnly = false;
	let help = false;

	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "-h" || arg === "--help") {
			help = true;
		} else if (arg === "--stats") {
			stats = true;
		} else if (arg === "--stats-only") {
			stats = true;
			statsOnly = true;
		} else if (arg === "--out" && i + 1 < argv.length) {
			outPath = argv[++i];
		} else if (arg.startsWith("--out=")) {
			outPath = arg.slice("--out=".length);
		} else if (arg === "--seed-dir" && i + 1 < argv.length) {
			seedDir = argv[++i];
		} else if (arg.startsWith("--seed-dir=")) {
			seedDir = arg.slice("--seed-dir=".length);
		} else if (arg === "--nuclei-dir" && i + 1 < argv.length) {
			nucleiDir = argv[++i];
		} else if (arg.startsWith("--nuclei-dir=")) {
			nucleiDir = arg.slice("--nuclei-dir=".length);
		} else {
			throw new Error(`未知参数: ${arg}（使用 --help 查看用法）`);
		}
	}

	return { outPath, seedDir, nucleiDir, stats, statsOnly, help };
}

if (import.meta.main) {
	try {
		const args = parseCliArgs(process.argv.slice(2));
		if (args.help) {
			console.log(
				[
					"用法: env -u BUN_OPTIONS bun kb/build-kb.ts [选项]",
					"  --out <dbPath>       输出 SQLite 数据库路径（默认 NUWA_KB_DB 或 <agentHome>/nuwa-kb/kb.db）",
					"  --seed-dir <dir>     指定种子资产目录（默认 kb/）",
					"  --nuclei-dir <dir>   可选：只读扫描本机 nuclei-templates 目录并增量提取 CVE 元数据头",
					"  --stats              输出知识库各表统计 JSON",
					"  --stats-only         仅读取已有知识库统计，不执行重建",
				].join("\n"),
			);
			process.exit(0);
		}

		const result = args.statsOnly
			? readKbStats(args.outPath)
			: buildKb({
					outPath: args.outPath,
					seedDir: args.seedDir,
					nucleiDir: args.nucleiDir,
				});

		if (args.stats) {
			console.log(JSON.stringify(result, null, 2));
		} else {
			console.log(
				`[kb-build] 已构建 ${result.dbPath} (kb_items=${result.kbItems}, cards=${result.cards}, cves=${result.cves}, pocs=${result.pocs}, techniques=${result.techniques}, kev=${result.kevs}, epss=${result.epss}, templates=${result.templates}, experience=${result.experiences})`,
			);
		}
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.error(`[kb-build] ERROR: ${msg}`);
		process.exit(1);
	}
}
