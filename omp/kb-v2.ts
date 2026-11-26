/**
 * 女娲 v7.0 知识库 2.0 引擎（KB 2.0）：大规模种子并入、零依赖混合语义检索与蒸馏经验反自证优胜劣汰治理。
 *
 * 核心能力：
 * 1. `ingestV7SeedPack(dbOrPath, packPath?)`：基于 `bun:sqlite` 幂等初始化并融合既有 140 条 v4 种子
 *    与 `kb/seed-v7-pack.json`（>= 380 条）至统一 `kb_items` / `kb_items_fts` 及兼容基础表（总计 >= 520 条），
 *    100% 兼容 `kb/schema.sql` 且绝不破坏既有 `experience` 表或已治理蒸馏经验状态；
 * 2. `hybridKbSearch(dbOrPath, query, opts?)`：零外部向量库/API 服务依赖，融合「SQLite FTS5 多路召回 +
 *    中英双语安全领域同义概念词典扩展 + 字符 2/3-gram Dice 重叠度 + 64-bit SimHash 海明相似度 +
 *    平滑 TF-IDF 余弦相似度 + 状态过滤（自动抑制 `quarantined` 卡片，提权 `promoted` 卡片）」；
 * 3. `governDistilledExperience(dbOrPath, calibrationRecords, opts?)`：严格绑定 `calibration.ts`
 *    机械对账结算源（硬性拦截任何 `self / model / agent` 自证记录），对连续 `>= 5` 次派单零产出或高误报的
 *    蒸馏经验卡自动降权标记 `quarantined` 冻结，对持续高命中高 ROI 经验卡晋升 `promoted`，并严格保护
 *    普通种子卡绝不被误伤或误删。
 *
 * 架构约束：严禁运行时导入 `./nuwa` 或仓库外相对脚本，零第三方 npm 依赖。
 */
import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
	ALLOWED_SETTLEMENT_SOURCES,
	CalibrationError,
	computeCalibrationSummary,
	type CalibrationRecord,
	type CalibrationSettlementSource,
} from "./calibration";
import { finalizeWritableKbDb, openReadonlyKbDb, resolveKbPath, resolveSeedDir, sanitizeExperienceText } from "./kb";

export type KbItemKind = "card" | "cve" | "technique" | "checklist" | "experience";
export type KbItemStatus = "active" | "promoted" | "quarantined";
export type KbItemSource = "seed-v4" | "seed-v7" | "distilled" | string;

export interface V7SeedItem {
	id: string;
	kind: KbItemKind;
	tech: string;
	title: string;
	summary: string;
	tags: string;
	payload_or_check: string;
	severity: string;
	ref: string;
	affected_versions?: string;
	cvss?: number;
	cwe?: string;
	remediation?: string;
	published?: string;
}

export interface KbItemRecord {
	id: string;
	kind: KbItemKind;
	tech: string;
	title: string;
	summary: string;
	tags: string;
	payload_or_check: string;
	severity: string;
	ref: string;
	source: KbItemSource;
	status: KbItemStatus;
	simhash: string;
	hit_count: number;
	miss_count: number;
	fp_count: number;
	consecutive_zero_yield: number;
	roi_score: number;
	updated_at: string;
}

export interface IngestV7SeedOptions {
	agentHome?: string;
	seedDir?: string;
}

export interface IngestV7SeedResult {
	ok: boolean;
	dbPath: string;
	packPath: string;
	packCount: number;
	baseSeedCount: number;
	totalKbItems: number;
	activeCount: number;
	promotedCount: number;
	quarantinedCount: number;
	cards: number;
	cves: number;
	techniques: number;
	experiences: number;
}

export interface HybridKbSearchOptions {
	limit?: number;
	kind?: KbItemKind;
	tech?: string;
	/** 默认 false：自动硬性过滤抑制 status='quarantined' 的被冻结经验卡。 */
	includeQuarantined?: boolean;
	/** 当传入文件路径且 DB 不存在时是否自动建库并导入 v7 种子包（默认 true）。 */
	autoInit?: boolean;
	packPath?: string;
	seedDir?: string;
	agentHome?: string;
}

export interface HybridKbSearchHit {
	id: string;
	kind: KbItemKind;
	tech: string;
	title: string;
	summary: string;
	tags: string;
	payload_or_check: string;
	severity: string;
	ref: string;
	source: KbItemSource;
	status: KbItemStatus;
	score: number;
	ftsScore: number;
	tfidfCosine: number;
	ngramOverlap: number;
	simhashSimilarity: number;
	synonymBoost: number;
	statusMultiplier: number;
	matchedConcepts: string[];
}

export interface DistilledExperienceCardInput {
	id?: string;
	tech: string;
	intentKey: string;
	phase?: string;
	title: string;
	summary: string;
	tags?: string;
	payload_or_check: string;
	severity?: string;
	ref?: string;
	status?: KbItemStatus;
}

export interface ExperienceCalibrationRecord extends CalibrationRecord {
	/** 可选显式绑定的蒸馏经验卡 ID（如 exp:nextjs:server-action-auth）。 */
	experienceId?: string;
	cardId?: string;
	kbItemId?: string;
}

export interface GovernExperienceOptions {
	/** 触发自动隔离降权（quarantined）的连续零产出次数阈值（默认 5）。 */
	quarantineZeroYieldStreak?: number;
	/** 触发高误报隔离的最小机械结算样本数（默认 5）。 */
	minSamplesForFpQuarantine?: number;
	/** 触发自动隔离的最高允许假阳性误报率（默认 0.40）。 */
	maxFalsePositiveRate?: number;
	/** 触发晋升（promoted）的最小机械结算样本数（默认 3）。 */
	promoteMinSamples?: number;
	/** 触发晋升的最低实锤命中率（默认 0.60）。 */
	promoteMinHitRate?: number;
	/** 触发晋升的最高允许误报率（默认 0.15）。 */
	promoteMaxFpRate?: number;
	/** 触发晋升的最低综合 ROI 得分（默认 0.20）。 */
	promoteMinRoi?: number;
	/** 是否允许状态双向撤销/恢复（如 promoted 退化后撤销，或 quarantined 获新实锤后解封，默认 true）。 */
	allowRevoke?: boolean;
	/** 遇到 self/model/agent 等自证来源时是否直接抛 CalibrationError（默认 false：安全拦截拒入账并计数）。 */
	throwOnSelfCert?: boolean;
}

export interface ExperienceCardGovernanceDetail {
	id: string;
	previousStatus: KbItemStatus;
	newStatus: KbItemStatus;
	settledCount: number;
	hitCount: number;
	missCount: number;
	fpCount: number;
	consecutiveZeroYield: number;
	hitRate: number;
	falsePositiveRate: number;
	roiScore: number;
	reason: string;
}

export interface ExperienceGovernanceResult {
	ok: boolean;
	evaluatedRecords: number;
	acceptedMechanicalRecords: number;
	rejectedSelfCertCount: number;
	ignoredUnsettledOrInvalidCount: number;
	protectedSeedSkips: number;
	quarantinedIds: string[];
	promotedIds: string[];
	activeIds: string[];
	revokedIds: string[];
	restoredIds: string[];
	allowRevoke: boolean;
	details: Record<string, ExperienceCardGovernanceDetail>;
}

const KB_ITEMS_DDL = `
CREATE TABLE IF NOT EXISTS kb_items (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	tech TEXT NOT NULL,
	title TEXT NOT NULL,
	summary TEXT NOT NULL,
	tags TEXT NOT NULL DEFAULT '',
	payload_or_check TEXT NOT NULL,
	severity TEXT NOT NULL DEFAULT 'MEDIUM',
	ref TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT 'seed-v7',
	status TEXT NOT NULL DEFAULT 'active',
	simhash TEXT NOT NULL DEFAULT '0000000000000000',
	hit_count INTEGER NOT NULL DEFAULT 0,
	miss_count INTEGER NOT NULL DEFAULT 0,
	fp_count INTEGER NOT NULL DEFAULT 0,
	consecutive_zero_yield INTEGER NOT NULL DEFAULT 0,
	roi_score REAL NOT NULL DEFAULT 0.0,
	updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_kb_items_tech ON kb_items(tech);
CREATE INDEX IF NOT EXISTS idx_kb_items_kind ON kb_items(kind);
CREATE INDEX IF NOT EXISTS idx_kb_items_status ON kb_items(status);
CREATE INDEX IF NOT EXISTS idx_kb_items_source ON kb_items(source);

CREATE VIRTUAL TABLE IF NOT EXISTS kb_items_fts USING fts5(
	id,
	tech,
	title,
	tags,
	summary,
	payload_or_check,
	tokenize = 'unicode61'
);
`;

const DISTILLED_SQL_PREDICATE =
	"(source = 'distilled' OR (kind = 'experience' AND source NOT IN ('seed', 'seed-v4', 'seed-v7')))";

const NOT_DISTILLED_UPSERT_GUARD =
	"NOT (kb_items.source = 'distilled' OR (kb_items.kind = 'experience' AND kb_items.source NOT IN ('seed', 'seed-v4', 'seed-v7')))";

export interface SecuritySynonymCluster {
	conceptId: string;
	terms: readonly string[];
}

/**
 * 中英双语安全领域同义概念词典：打通中文口语化描述与英文规范技术术语/CWE/协议原语的语义鸿沟。
 */
export const SECURITY_SYNONYM_CLUSTERS: readonly SecuritySynonymCluster[] = [
	{
		conceptId: "concept_idor_bola",
		terms: [
			"越权",
			"水平越权",
			"对象级越权",
			"偷看别人",
			"他人数据",
			"他人订单",
			"改订单号",
			"改用户id",
			"跨租户",
			"跨用户",
			"idor",
			"bola",
			"broken object level authorization",
			"object ownership",
			"tenant isolation",
		],
	},
	{
		conceptId: "concept_bfla_rbac",
		terms: [
			"垂直越权",
			"功能级越权",
			"普通用户调管理接口",
			"管理后台未授权",
			"漏鉴权",
			"未鉴权路由",
			"角色绕过",
			"权限绕过",
			"bfla",
			"broken function level authorization",
			"rbac",
			"admin endpoint",
			"missing auth",
		],
	},
	{
		conceptId: "concept_spa_sourcemap",
		terms: [
			"前端源码",
			"打包文件",
			"映射文件",
			"还原源码",
			"隐藏路由",
			"隐藏接口",
			"前端泄露",
			"静态包",
			"sourcemap",
			"js.map",
			"sourcemappingurl",
			"webpack",
			"vite",
			"bundle",
			"chunk",
			"buildmanifest",
			"spa",
		],
	},
	{
		conceptId: "concept_frontend_signing",
		terms: [
			"前端加签",
			"接口加签",
			"请求签名",
			"验签",
			"签名算法",
			"防篡改",
			"重放攻击",
			"时间戳绕过",
			"硬编码密钥",
			"request signing",
			"x-signature",
			"hmac",
			"subtle.sign",
			"webcrypto",
			"nonce",
			"replay",
		],
	},
	{
		conceptId: "concept_nextjs_rsc",
		terms: [
			"服务端组件",
			"服务端动作",
			"中间件绕过",
			"客户端环境变量",
			"nextjs",
			"next.js",
			"app router",
			"rsc",
			"react server components",
			"server actions",
			"use server",
			"middleware.ts",
			"next_public",
			"flight",
		],
	},
	{
		conceptId: "concept_race_idempotency",
		terms: [
			"并发",
			"条件竞争",
			"竞态",
			"薅羊毛",
			"一券多用",
			"双花",
			"超发",
			"重复提交",
			"幂等",
			"防重",
			"分布式锁",
			"race condition",
			"toctou",
			"concurrency",
			"idempotency",
			"idempotency-key",
			"double spend",
			"for update",
		],
	},
	{
		conceptId: "concept_proxy_path_norm",
		terms: [
			"反向代理",
			"反代绕过",
			"网关绕过",
			"路径规范化",
			"目录穿越",
			"路径穿越",
			"斜杠闭合",
			"分号绕过",
			"双重编码",
			"reverse proxy",
			"path normalization",
			"path traversal",
			"nginx alias",
			"semicolon",
			"url discrepancy",
			"x-original-url",
			"x-forwarded-for",
		],
	},
	{
		conceptId: "concept_jwt_token",
		terms: [
			"令牌伪造",
			"空算法",
			"算法混淆",
			"公钥当密钥",
			"弱密钥",
			"令牌未失效",
			"jwt",
			"jws",
			"jwk",
			"jku",
			"x5u",
			"kid",
			"alg none",
			"rs256",
			"hs256",
			"bearer token",
		],
	},
	{
		conceptId: "concept_oauth_oidc",
		terms: [
			"单点登录",
			"第三方登录",
			"回调劫持",
			"授权码劫持",
			"回调地址",
			"随机态缺失",
			"oauth",
			"oauth2",
			"oidc",
			"openid",
			"redirect_uri",
			"pkce",
			"code_verifier",
			"state parameter",
			"sso",
		],
	},
	{
		conceptId: "concept_graphql",
		terms: [
			"图查询",
			"自省查询",
			"内省",
			"接口结构泄露",
			"深度嵌套",
			"批量别名",
			"graphql",
			"introspection",
			"__schema",
			"__typename",
			"query depth",
			"alias batching",
			"field authorization",
		],
	},
	{
		conceptId: "concept_spring_java",
		terms: [
			"监控端点",
			"健康检查泄露",
			"堆内存转储",
			"环境变量端点",
			"多态反序列化",
			"表达式注入",
			"spring",
			"spring-boot",
			"spring security",
			"actuator",
			"heapdump",
			"jackson",
			"fastjson",
			"snakeyaml",
			"spel",
			"deserialization",
		],
	},
	{
		conceptId: "concept_fastapi_django",
		terms: [
			"依赖注入鉴权",
			"响应模型脱敏",
			"批量赋值",
			"字段透传",
			"调试模式",
			"fastapi",
			"pydantic",
			"depends",
			"response_model",
			"mass assignment",
			"django",
			"drf",
			"queryset",
			"serializer",
		],
	},
	{
		conceptId: "concept_golang_web",
		terms: [
			"中间件注册顺序",
			"性能剖析泄露",
			"协程泄露",
			"结构体绑定",
			"golang",
			"gin",
			"echo",
			"pprof",
			"shouldbind",
			"goroutine",
			"middleware order",
		],
	},
	{
		conceptId: "concept_cloud_ssrf",
		terms: [
			"服务端请求伪造",
			"内网探测",
			"云元数据",
			"临时凭据",
			"存储桶公开",
			"对象存储",
			"预签名链接",
			"容器逃逸",
			"ssrf",
			"imds",
			"imdsv2",
			"169.254.169.254",
			"s3 bucket",
			"oss",
			"presigned url",
			"kubernetes",
			"serviceaccount",
			"rbac",
		],
	},
	{
		conceptId: "concept_sqli_orm",
		terms: [
			"数据库注入",
			"动态拼接",
			"排序注入",
			"原生查询",
			"sql injection",
			"sqli",
			"order by",
			"mybatis",
			"rawsql",
			"parameterized query",
		],
	},
	{
		conceptId: "concept_soft404_fp",
		terms: [
			"假404",
			"前端兜底",
			"误报剔除",
			"空壳响应",
			"负向对照",
			"soft-404",
			"negative baseline",
			"false positive",
			"body_sha256",
		],
	},
];

function safeFinite(val: number, fallback = 0): number {
	return typeof val === "number" && Number.isFinite(val) ? val : fallback;
}

function clamp01(val: number): number {
	const v = safeFinite(val, 0);
	if (v <= 0) return 0;
	if (v >= 1) return 1;
	return v;
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

function tableCount(db: Database, table: string): number {
	try {
		if (!hasTable(db, table)) return 0;
		const row = db.query(`SELECT COUNT(*) AS cnt FROM ${table}`).get() as { cnt?: number } | null;
		return Number(row?.cnt ?? 0);
	} catch {
		return 0;
	}
}

const LOWER_SYNONYM_CLUSTERS: ReadonlyArray<{ conceptId: string; lowerTerms: readonly string[] }> =
	SECURITY_SYNONYM_CLUSTERS.map((c) => ({
		conceptId: c.conceptId,
		lowerTerms: c.terms.map((t) => t.toLowerCase()),
	}));

/**
 * 计算单段特征字符串的确定性双通道 32-bit FNV-1a 混合哈希（零 BigInt 堆分配，极速位运算）。
 */
function hashTokenDual32(token: string): [number, number] {
	let h1 = 0x811c9dc5;
	let h2 = 0x27d4eb2d;
	for (let i = 0; i < token.length; i++) {
		const c = token.charCodeAt(i);
		h1 ^= c;
		h1 = Math.imul(h1, 0x01000193);
		h2 ^= c + Math.imul(i + 1, 0x9e3779b9);
		h2 = Math.imul(h2, 0x85ebca6b);
	}
	return [h1 >>> 0, h2 >>> 0];
}

/**
 * 提取用于 SimHash / TF-IDF 的中英混合语义特征词与字符 N-gram。
 */
export function extractHybridFeatures(text: string): Map<string, number> {
	const weights = new Map<string, number>();
	const norm = String(text ?? "")
		.toLowerCase()
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 4096);
	if (!norm) return weights;

	const addFeat = (feat: string, w: number) => {
		if (!feat) return;
		weights.set(feat, (weights.get(feat) ?? 0) + w);
	};

	// 1. 英文/数字技术标识符词项（含短横线/点号拆分）
	const asciiMatches = norm.match(/[a-z0-9][a-z0-9._:-]{1,36}/g);
	if (asciiMatches) {
		for (let m = 0; m < asciiMatches.length; m++) {
			const rawTok = asciiMatches[m]!;
			addFeat(`w:${rawTok}`, 2.2);
			if (rawTok.indexOf("-") >= 0 || rawTok.indexOf("_") >= 0 || rawTok.indexOf(".") >= 0 || rawTok.indexOf(":") >= 0) {
				const parts = rawTok.split(/[._:-]+/);
				for (let p = 0; p < parts.length; p++) {
					const sub = parts[p]!;
					if (sub.length >= 2) addFeat(`w:${sub}`, 1.4);
				}
			}
			if (rawTok.length >= 4 && rawTok.length <= 20) {
				for (let i = 0; i <= rawTok.length - 3; i++) {
					addFeat(`g3:${rawTok.slice(i, i + 3)}`, 0.45);
				}
			}
		}
	}

	// 2. 中文连续片段提取 2-gram 与 3-gram
	const cjkChunks = norm.match(/[\u4e00-\u9fff]{2,}/gu);
	if (cjkChunks) {
		for (let k = 0; k < cjkChunks.length; k++) {
			const chunk = cjkChunks[k]!;
			if (chunk.length === 2) {
				addFeat(`zh2:${chunk}`, 2.0);
				continue;
			}
			for (let i = 0; i <= chunk.length - 2; i++) {
				addFeat(`zh2:${chunk.slice(i, i + 2)}`, 1.8);
			}
			for (let i = 0; i <= chunk.length - 3; i++) {
				addFeat(`zh3:${chunk.slice(i, i + 3)}`, 2.2);
			}
		}
	}

	// 3. 标注命中的同义概念簇特征（强化跨语种对齐）
	for (let i = 0; i < LOWER_SYNONYM_CLUSTERS.length; i++) {
		const cluster = LOWER_SYNONYM_CLUSTERS[i]!;
		const terms = cluster.lowerTerms;
		for (let j = 0; j < terms.length; j++) {
			if (norm.indexOf(terms[j]!) >= 0) {
				addFeat(`cid:${cluster.conceptId}`, 3.2);
				break;
			}
		}
	}

	return weights;
}

const SIMHASH_MEMO = new Map<string, string>();
const MAX_SIMHASH_MEMO = 2048;

/**
 * 计算文本的 64-bit SimHash 指纹（固定 16 位小写 hex 字符串，纯 32-bit 位运算零 BigInt 开销 + 纯函数缓存）。
 */
export function computeSimHash64(text: string): string {
	const raw = String(text ?? "");
	if (!raw.trim()) return "0000000000000000";
	const cached = SIMHASH_MEMO.get(raw);
	if (cached !== undefined) return cached;

	const feats = extractHybridFeatures(raw);
	if (feats.size === 0) return "0000000000000000";

	const accum = new Float64Array(64);
	for (const [feat, weight] of feats.entries()) {
		const [hi, lo] = hashTokenDual32(feat);
		for (let bit = 0; bit < 32; bit++) {
			accum[bit] += ((lo >>> bit) & 1) === 1 ? weight : -weight;
			accum[bit + 32] += ((hi >>> bit) & 1) === 1 ? weight : -weight;
		}
	}

	let outLo = 0;
	let outHi = 0;
	for (let bit = 0; bit < 32; bit++) {
		if (accum[bit]! > 0) outLo = (outLo | (1 << bit)) >>> 0;
		if (accum[bit + 32]! > 0) outHi = (outHi | (1 << bit)) >>> 0;
	}
	const hex = outHi.toString(16).padStart(8, "0") + outLo.toString(16).padStart(8, "0");
	if (SIMHASH_MEMO.size >= MAX_SIMHASH_MEMO) {
		SIMHASH_MEMO.clear();
	}
	SIMHASH_MEMO.set(raw, hex);
	return hex;
}

function popcount32(x: number): number {
	let v = x >>> 0;
	v = v - ((v >>> 1) & 0x55555555);
	v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
	return (((v + (v >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
}

/**
 * 计算两个 64-bit SimHash 十六进制指纹的海明相似度 ∈ [0, 1]（严格零除零/零 NaN）。
 */
export function simHashSimilarity(hexA: string, hexB: string): number {
	const cleanA = String(hexA ?? "").trim().toLowerCase();
	const cleanB = String(hexB ?? "").trim().toLowerCase();
	if (!/^[0-9a-f]{1,16}$/.test(cleanA) || !/^[0-9a-f]{1,16}$/.test(cleanB)) {
		return 0;
	}
	const padA = cleanA.padStart(16, "0");
	const padB = cleanB.padStart(16, "0");
	if (padA === "0000000000000000" && padB === "0000000000000000") {
		return 0;
	}
	const hiA = Number.parseInt(padA.slice(0, 8), 16) >>> 0;
	const loA = Number.parseInt(padA.slice(8, 16), 16) >>> 0;
	const hiB = Number.parseInt(padB.slice(0, 8), 16) >>> 0;
	const loB = Number.parseInt(padB.slice(8, 16), 16) >>> 0;
	const dist = popcount32(hiA ^ hiB) + popcount32(loA ^ loB);
	return clamp01(1 - dist / 64);
}

/**
 * 提取字符 2-gram 与 3-gram 集合并计算 Dice 重叠度相似度 ∈ [0, 1]（任一为空集时安全返回 0）。
 */
export function computeCharNgramDice(textA: string, textB: string): number {
	const toNgrams = (raw: string): Set<string> => {
		const cleaned = String(raw ?? "")
			.toLowerCase()
			.replace(/[^a-z0-9\u4e00-\u9fff]+/gu, " ")
			.trim()
			.slice(0, 2048);
		const set = new Set<string>();
		if (!cleaned) return set;
		for (const part of cleaned.split(/\s+/)) {
			if (!part) continue;
			if (part.length < 2) {
				set.add(part);
				continue;
			}
			for (let i = 0; i <= part.length - 2; i++) {
				set.add(part.slice(i, i + 2));
			}
			for (let i = 0; i <= part.length - 3; i++) {
				set.add(part.slice(i, i + 3));
			}
		}
		return set;
	};

	const setA = toNgrams(textA);
	const setB = toNgrams(textB);
	if (setA.size === 0 || setB.size === 0) return 0;

	let inter = 0;
	const [smaller, larger] = setA.size <= setB.size ? [setA, setB] : [setB, setA];
	for (const g of smaller) {
		if (larger.has(g)) inter += 1;
	}
	const denom = setA.size + setB.size;
	return denom > 0 ? clamp01((2 * inter) / denom) : 0;
}

/**
 * 执行中英安全领域同义概念扩展。
 */
export function expandSecuritySynonyms(query: string): {
	normalizedQuery: string;
	rawTokens: string[];
	expandedTerms: string[];
	matchedConcepts: string[];
} {
	const normalizedQuery = String(query ?? "")
		.toLowerCase()
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 512);

	if (!normalizedQuery) {
		return { normalizedQuery: "", rawTokens: [], expandedTerms: [], matchedConcepts: [] };
	}

	const rawTokens = normalizedQuery
		.split(/[^a-z0-9._\-\u4e00-\u9fff]+/u)
		.map((t) => t.trim())
		.filter((t) => t.length >= 2)
		.slice(0, 16);

	const matchedConcepts: string[] = [];
	const expandedSet = new Set<string>(rawTokens);

	// 同时提取中文短词触发局部口语同义匹配（如 "改ID"、"偷看"、"订单"、"薅羊毛"、"打包"、"加签"）
	for (const cluster of SECURITY_SYNONYM_CLUSTERS) {
		let hit = false;
		for (const term of cluster.terms) {
			const lowTerm = term.toLowerCase();
			if (normalizedQuery.includes(lowTerm)) {
				hit = true;
				break;
			}
		}
		if (hit) {
			matchedConcepts.push(cluster.conceptId);
			for (const syn of cluster.terms) {
				expandedSet.add(syn.toLowerCase());
			}
		}
	}

	return {
		normalizedQuery,
		rawTokens,
		expandedTerms: [...expandedSet].slice(0, 48),
		matchedConcepts,
	};
}

function resolveV7PackPath(explicitPackPath?: string, seedDir?: string, agentHome?: string): string {
	if (explicitPackPath && explicitPackPath.trim()) {
		return resolve(explicitPackPath.trim());
	}
	const resolvedSeed = resolveSeedDir(seedDir, agentHome);
	if (resolvedSeed) {
		const cand = join(resolvedSeed, "seed-v7-pack.json");
		if (existsSync(cand)) return cand;
	}
	const repoCand = resolve(import.meta.dir, "..", "kb", "seed-v7-pack.json");
	return repoCand;
}

function openOrBorrowWritableDb(
	dbOrPath: Database | string | undefined,
	agentHome?: string,
): { db: Database; dbPath: string; owned: boolean } {
	if (dbOrPath && typeof dbOrPath === "object" && "exec" in dbOrPath && "query" in dbOrPath) {
		return {
			db: dbOrPath,
			dbPath: dbOrPath.filename || ":memory:",
			owned: false,
		};
	}
	const targetPath =
		typeof dbOrPath === "string" && dbOrPath.trim() ? resolve(dbOrPath.trim()) : resolveKbPath(agentHome);
	if (targetPath !== ":memory:") {
		mkdirSync(dirname(targetPath), { recursive: true });
	}
	const db = new Database(targetPath);
	return { db, dbPath: targetPath, owned: true };
}

function ensureSchemasOutsideTx(db: Database, seedDir: string | null): void {
	if (seedDir) {
		const schemaPath = join(seedDir, "schema.sql");
		if (existsSync(schemaPath)) {
			db.exec(readFileSync(schemaPath, "utf8"));
		}
	}

	// 若未找到外部 schema.sql（如纯内存最小测试环境），兜底创建核心兼容表
	db.exec(`
		CREATE TABLE IF NOT EXISTS kb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS card (
			key TEXT PRIMARY KEY,
			tech_key TEXT NOT NULL,
			title TEXT NOT NULL,
			keywords TEXT NOT NULL DEFAULT '',
			body TEXT NOT NULL,
			updated_at TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS cve (
			cve_id TEXT PRIMARY KEY,
			product TEXT NOT NULL DEFAULT '',
			affected_versions TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL DEFAULT 'UNKNOWN',
			cvss REAL NOT NULL DEFAULT 0.0,
			cwe TEXT NOT NULL DEFAULT '',
			descr TEXT NOT NULL,
			verify_hint TEXT NOT NULL DEFAULT '',
			remediation TEXT NOT NULL DEFAULT '',
			published TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'seed'
		);
		CREATE TABLE IF NOT EXISTS poc (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			cve_id TEXT NOT NULL,
			url TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT 'advisory',
			title TEXT NOT NULL DEFAULT '',
			UNIQUE(cve_id, url)
		);
		CREATE TABLE IF NOT EXISTS technique (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			tactics TEXT NOT NULL DEFAULT '',
			platforms TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL DEFAULT '',
			detection_hint TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY, added_date TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '');
		CREATE TABLE IF NOT EXISTS epss (cve_id TEXT PRIMARY KEY, score REAL NOT NULL DEFAULT 0.0, percentile REAL NOT NULL DEFAULT 0.0);
		CREATE TABLE IF NOT EXISTS template (id TEXT PRIMARY KEY, path TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'nuclei');
		CREATE TABLE IF NOT EXISTS template_cve_map (template_id TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY (template_id, cve_id));
		CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(cve_id, product, severity, descr, verify_hint, tokenize = 'unicode61');
		CREATE VIRTUAL TABLE IF NOT EXISTS card_fts USING fts5(key, tech_key, title, keywords, body, tokenize = 'unicode61');
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
	`);

	db.exec(KB_ITEMS_DDL);
}

function loadAndSyncV4SeedsInTx(db: Database, seedDir: string | null, nowIso: string): number {

	// 若当前库尚未载入基础 v4 140 条种子且 seedDir 可用，幂等载入基础种子
	if (seedDir) {
		const cardsPath = join(seedDir, "seed-cards.json");
		const cvesPath = join(seedDir, "seed-cves.json");
		const techPath = join(seedDir, "seed-techniques.json");
		if (existsSync(cardsPath) && existsSync(cvesPath) && existsSync(techPath)) {
			const baseCards = JSON.parse(readFileSync(cardsPath, "utf8")) as Array<Record<string, unknown>>;
			const baseCves = JSON.parse(readFileSync(cvesPath, "utf8")) as Array<Record<string, unknown>>;
			const baseTechs = JSON.parse(readFileSync(techPath, "utf8")) as Array<Record<string, unknown>>;

			const insCard = db.query(
				"INSERT OR REPLACE INTO card (key, tech_key, title, keywords, body, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			);
			for (const c of baseCards) {
				insCard.run(
					String(c.key ?? "").trim(),
					String(c.tech_key ?? "").trim().toLowerCase(),
					String(c.title ?? "").trim(),
					String(c.keywords ?? "").trim(),
					String(c.body ?? "").trim(),
					nowIso,
				);
			}

			const insCve = db.query(
				`INSERT OR REPLACE INTO cve
				 (cve_id, product, affected_versions, severity, cvss, cwe, descr, verify_hint, remediation, published, source)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			);
			for (const item of baseCves) {
				insCve.run(
					String(item.cve_id ?? "").trim().toUpperCase(),
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
			}

			const insTech = db.query(
				"INSERT OR REPLACE INTO technique (id, name, tactics, platforms, summary, detection_hint) VALUES (?, ?, ?, ?, ?, ?)",
			);
			for (const t of baseTechs) {
				insTech.run(
					String(t.id ?? "").trim().toUpperCase(),
					String(t.name ?? "").trim(),
					String(t.tactics ?? "").trim(),
					String(t.platforms ?? "").trim(),
					String(t.summary ?? "").trim(),
					String(t.detection_hint ?? "").trim(),
				);
			}
		}
	}

	// 将基础 v4 表中的条目幂等同步至 kb_items（source='seed-v4'）
	let syncedBaseCount = 0;
	const upsertItem = db.query(`
		INSERT INTO kb_items (id, kind, tech, title, summary, tags, payload_or_check, severity, ref, source, status, simhash, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'seed-v4', 'active', ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			kind = excluded.kind,
			tech = excluded.tech,
			title = excluded.title,
			summary = excluded.summary,
			tags = excluded.tags,
			payload_or_check = excluded.payload_or_check,
			severity = excluded.severity,
			ref = excluded.ref,
			simhash = excluded.simhash,
			updated_at = excluded.updated_at
		WHERE ${NOT_DISTILLED_UPSERT_GUARD}
	`);

	const cardRows = db
		.query("SELECT key, tech_key, title, keywords, body FROM card")
		.all() as Array<{ key: string; tech_key: string; title: string; keywords: string; body: string }>;
	for (const c of cardRows) {
		if (c.key.startsWith("v7-") || c.key.startsWith("V7-")) continue;
		const summary = c.body.split("\n")[0]?.slice(0, 240) || c.title;
		const sh = computeSimHash64(`${c.tech_key} ${c.title} ${c.keywords} ${c.body}`);
		upsertItem.run(c.key, "card", c.tech_key, c.title, summary, c.keywords, c.body, "MEDIUM", "Nuwa-v4-Baseline", sh, nowIso);
		syncedBaseCount += 1;
	}

	const cveRows = db
		.query("SELECT cve_id, product, affected_versions, severity, cwe, descr, verify_hint, remediation, source FROM cve WHERE source = 'seed'")
		.all() as Array<{
			cve_id: string;
			product: string;
			affected_versions: string;
			severity: string;
			cwe: string;
			descr: string;
			verify_hint: string;
			remediation: string;
			source: string;
		}>;
	for (const v of cveRows) {
		const checkBody = [
			v.affected_versions ? `【受影响版本】${v.affected_versions}` : "",
			v.verify_hint ? `【核验提示】${v.verify_hint}` : "",
			v.remediation ? `【修复加固】${v.remediation}` : "",
		]
			.filter(Boolean)
			.join("\n");
		const tags = [v.product, v.cwe.toLowerCase(), "cve"].filter(Boolean).join(",");
		const title = `${v.cve_id} (${v.product}) 组件版本基线核查`;
		const sh = computeSimHash64(`${v.cve_id} ${v.product} ${tags} ${v.descr} ${checkBody}`);
		upsertItem.run(
			v.cve_id,
			"cve",
			v.product || "general",
			title,
			v.descr,
			tags,
			checkBody || v.descr,
			v.severity || "MEDIUM",
			v.cwe || v.cve_id,
			sh,
			nowIso,
		);
		syncedBaseCount += 1;
	}

	const techRows = db
		.query("SELECT id, name, tactics, platforms, summary, detection_hint FROM technique")
		.all() as Array<{
			id: string;
			name: string;
			tactics: string;
			platforms: string;
			summary: string;
			detection_hint: string;
		}>;
	for (const t of techRows) {
		if (t.id.startsWith("V7-") || t.id.startsWith("v7-")) continue;
		const tags = [t.tactics, t.platforms, "mitre-attack"].filter(Boolean).join(",");
		const sh = computeSimHash64(`${t.id} ${t.name} ${tags} ${t.summary} ${t.detection_hint}`);
		upsertItem.run(
			t.id,
			"technique",
			"attack-matrix",
			t.name,
			t.summary || t.name,
			tags,
			t.detection_hint || t.summary || t.name,
			"MEDIUM",
			`MITRE ATT&CK ${t.id}`,
			sh,
			nowIso,
		);
		syncedBaseCount += 1;
	}

	return syncedBaseCount;
}

function syncExperienceTableToKbItems(db: Database, nowIso: string): void {
	if (!hasTable(db, "experience")) return;
	const expRows = db
		.query(
			"SELECT tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at FROM experience",
		)
		.all() as Array<{
			tech_key: string;
			intent_key: string;
			phase: string;
			success_count: number;
			fail_count: number;
			helpful_pattern: string;
			pitfall_note: string;
			updated_at: string;
		}>;

	if (expRows.length === 0) return;

	const insDistilled = db.query(`
		INSERT INTO kb_items (
			id, kind, tech, title, summary, tags, payload_or_check, severity, ref,
			source, status, simhash, hit_count, miss_count, updated_at
		) VALUES (?, 'experience', ?, ?, ?, ?, ?, 'MEDIUM', 'nuwa-distilled-experience', 'distilled', 'active', ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			summary = excluded.summary,
			payload_or_check = excluded.payload_or_check,
			simhash = excluded.simhash
		WHERE kb_items.source = 'distilled'
	`);

	for (const r of expRows) {
		const tech = String(r.tech_key ?? "general").trim().toLowerCase() || "general";
		const intentKey = String(r.intent_key ?? "general").trim() || "general";
		const expId = `exp:${tech}:${intentKey}`;
		const title = sanitizeExperienceText(`[蒸馏经验] ${tech} :: ${intentKey} (${r.phase})`);
		const summary = sanitizeExperienceText(
			r.helpful_pattern || r.pitfall_note || `${tech} 阶段 ${r.phase} 历史派单经验总结`,
		);
		const check = sanitizeExperienceText(
			[
				r.helpful_pattern ? `【有效模式】${r.helpful_pattern}` : "",
				r.pitfall_note ? `【避坑提示】${r.pitfall_note}` : "",
			]
				.filter(Boolean)
				.join("\n") || summary,
		);
		const tags = `${tech},${r.phase},distilled,intent:${intentKey}`;
		const sh = computeSimHash64(`${tech} ${intentKey} ${title} ${summary} ${check}`);
		insDistilled.run(
			expId,
			tech,
			title,
			summary,
			tags,
			check,
			sh,
			Math.max(0, Number(r.success_count ?? 0)),
			Math.max(0, Number(r.fail_count ?? 0)),
			r.updated_at || nowIso,
		);
	}
}

function rebuildKbV2Fts(db: Database): void {
	db.query("DELETE FROM kb_items_fts").run();
	db.query(`
		INSERT INTO kb_items_fts (id, tech, title, tags, summary, payload_or_check)
		SELECT id, tech, title, tags, summary, payload_or_check FROM kb_items
	`).run();

	if (hasTable(db, "card_fts") && hasTable(db, "card")) {
		db.query("DELETE FROM card_fts").run();
		db.query(
			"INSERT INTO card_fts (key, tech_key, title, keywords, body) SELECT key, tech_key, title, keywords, body FROM card",
		).run();
	}
	if (hasTable(db, "cve_fts") && hasTable(db, "cve")) {
		db.query("DELETE FROM cve_fts").run();
		db.query(
			"INSERT INTO cve_fts (cve_id, product, severity, descr, verify_hint) SELECT cve_id, product, severity, descr, verify_hint FROM cve",
		).run();
	}
}

/**
 * 幂等读取 `kb/seed-v7-pack.json` 并与既有 v4 种子融合写入 SQLite `kb_items` 及兼容基础表。
 * 保证入库后全库 `kb_items` 记录数 `>= 520` 条，且重复执行完全幂等、不丢失蒸馏经验状态。
 */
export function ingestV7SeedPack(
	dbOrPath?: Database | string,
	packPath?: string,
	opts?: IngestV7SeedOptions,
): IngestV7SeedResult {
	const seedDir = resolveSeedDir(opts?.seedDir, opts?.agentHome);
	const resolvedPackPath = resolveV7PackPath(packPath, opts?.seedDir, opts?.agentHome);
	if (!existsSync(resolvedPackPath)) {
		throw new Error(`未找到 v7 知识库种子包文件: ${resolvedPackPath}`);
	}

	const rawPack = JSON.parse(readFileSync(resolvedPackPath, "utf8")) as unknown;
	if (!Array.isArray(rawPack) || rawPack.length === 0) {
		throw new Error(`v7 知识库种子包格式非法或为空数组: ${resolvedPackPath}`);
	}

	const seenIds = new Set<string>();
	const validItems: V7SeedItem[] = [];
	for (let idx = 0; idx < rawPack.length; idx++) {
		const entry = rawPack[idx] as Record<string, unknown>;
		if (!entry || typeof entry !== "object") {
			throw new Error(`seed-v7-pack.json 第 ${idx} 项不是对象`);
		}
		const id = String(entry.id ?? "").trim();
		const kind = String(entry.kind ?? "card").trim().toLowerCase() as KbItemKind;
		const tech = String(entry.tech ?? "").trim().toLowerCase();
		const title = String(entry.title ?? "").trim();
		const summary = String(entry.summary ?? "").trim();
		const tags = String(entry.tags ?? "").trim();
		const payloadOrCheck = String(entry.payload_or_check ?? "").trim();
		const severity = String(entry.severity ?? "MEDIUM").trim().toUpperCase();
		const ref = String(entry.ref ?? "").trim();

		if (!id || !tech || !title || !summary || !payloadOrCheck) {
			throw new Error(`seed-v7-pack.json 第 ${idx} 项 (${id || "no-id"}) 存在空必填字段`);
		}
		if (seenIds.has(id)) {
			throw new Error(`seed-v7-pack.json 发现重复主键 ID: ${id}`);
		}
		seenIds.add(id);

		validItems.push({
			id,
			kind,
			tech,
			title,
			summary,
			tags,
			payload_or_check: payloadOrCheck,
			severity,
			ref,
			affected_versions: entry.affected_versions ? String(entry.affected_versions).trim() : undefined,
			cvss: typeof entry.cvss === "number" && Number.isFinite(entry.cvss) ? entry.cvss : undefined,
			cwe: entry.cwe ? String(entry.cwe).trim().toUpperCase() : undefined,
			remediation: entry.remediation ? String(entry.remediation).trim() : undefined,
			published: entry.published ? String(entry.published).trim() : undefined,
		});
	}

	const { db, dbPath, owned } = openOrBorrowWritableDb(dbOrPath, opts?.agentHome);
	const nowIso = new Date().toISOString();

	try {
		// 必须在事务之外执行 PRAGMA 与 CREATE TABLE DDL（SQLite 禁止在事务内部修改 synchronous 等安全级别）
		ensureSchemasOutsideTx(db, seedDir);

		let baseSeedCount = 0;
		const runIngestTx = db.transaction(() => {
			baseSeedCount = loadAndSyncV4SeedsInTx(db, seedDir, nowIso);

			const upsertKbItem = db.query(`
				INSERT INTO kb_items (
					id, kind, tech, title, summary, tags, payload_or_check, severity, ref,
					source, status, simhash, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'seed-v7', 'active', ?, ?)
				ON CONFLICT(id) DO UPDATE SET
					kind = excluded.kind,
					tech = excluded.tech,
					title = excluded.title,
					summary = excluded.summary,
					tags = excluded.tags,
					payload_or_check = excluded.payload_or_check,
					severity = excluded.severity,
					ref = excluded.ref,
					source = 'seed-v7',
					simhash = excluded.simhash,
					updated_at = excluded.updated_at
				WHERE ${NOT_DISTILLED_UPSERT_GUARD}
			`);

			const insCompatCard = db.query(
				"INSERT OR REPLACE INTO card (key, tech_key, title, keywords, body, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			);
			const insCompatCve = db.query(
				`INSERT OR REPLACE INTO cve
				 (cve_id, product, affected_versions, severity, cvss, cwe, descr, verify_hint, remediation, published, source)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'seed-v7')`,
			);
			const insCompatTech = db.query(
				"INSERT OR REPLACE INTO technique (id, name, tactics, platforms, summary, detection_hint) VALUES (?, ?, ?, ?, ?, ?)",
			);

			for (const item of validItems) {
				const sh = computeSimHash64(
					`${item.tech} ${item.title} ${item.tags} ${item.summary} ${item.payload_or_check}`,
				);
				upsertKbItem.run(
					item.id,
					item.kind,
					item.tech,
					item.title,
					item.summary,
					item.tags,
					item.payload_or_check,
					item.severity,
					item.ref,
					sh,
					nowIso,
				);

				// 同步写入 v4 兼容基础表，使旧接口统计同样完整可查
				if (item.kind === "cve") {
					const defaultCvss =
						item.severity === "CRITICAL"
							? 9.4
							: item.severity === "HIGH"
								? 8.1
								: item.severity === "MEDIUM"
									? 5.8
									: 3.5;
					insCompatCve.run(
						item.id.toUpperCase(),
						item.tech,
						item.affected_versions ?? "参见官方安全公告受影响版本区间",
						item.severity,
						item.cvss ?? defaultCvss,
						item.cwe ?? (item.ref.match(/\bCWE-\d+\b/i)?.[0]?.toUpperCase() ?? ""),
						item.summary,
						item.payload_or_check,
						item.remediation ?? "升级至官方安全修补版本并加固边界校验配置。",
						item.published ?? "",
					);
				} else if (item.kind === "technique") {
					insCompatTech.run(
						item.id.toUpperCase(),
						item.title,
						item.tags,
						item.tech,
						item.summary,
						item.payload_or_check,
					);
				} else {
					const cardKey = item.id.startsWith("v7-") ? item.id : `v7-${item.id}`;
					insCompatCard.run(
						cardKey,
						item.tech,
						item.title,
						item.tags,
						`${item.summary}\n${item.payload_or_check}`,
						nowIso,
					);
				}
			}

			syncExperienceTableToKbItems(db, nowIso);
			rebuildKbV2Fts(db);

			const totalItems = tableCount(db, "kb_items");
			const setMeta = db.query("INSERT OR REPLACE INTO kb_meta (key, value) VALUES (?, ?)");
			setMeta.run("schema_version", "7");
			setMeta.run("kb_v2_pack_count", String(validItems.length));
			setMeta.run("kb_v2_total", String(totalItems));
			setMeta.run("built_at", nowIso);
		});

		runIngestTx();

		const totalKbItems = tableCount(db, "kb_items");
		const activeCount = Number(
			(db.query("SELECT COUNT(*) AS cnt FROM kb_items WHERE status = 'active'").get() as { cnt?: number } | null)
				?.cnt ?? 0,
		);
		const promotedCount = Number(
			(db.query("SELECT COUNT(*) AS cnt FROM kb_items WHERE status = 'promoted'").get() as { cnt?: number } | null)
				?.cnt ?? 0,
		);
		const quarantinedCount = Number(
			(
				db.query("SELECT COUNT(*) AS cnt FROM kb_items WHERE status = 'quarantined'").get() as {
					cnt?: number;
				} | null
			)?.cnt ?? 0,
		);
		const cards = tableCount(db, "card");
		const cves = tableCount(db, "cve");
		const techniques = tableCount(db, "technique");
		const experiences = tableCount(db, "experience");

		if (owned && dbPath !== ":memory:") {
			finalizeWritableKbDb(db);
		}

		return {
			ok: true,
			dbPath,
			packPath: resolvedPackPath,
			packCount: validItems.length,
			baseSeedCount,
			totalKbItems,
			activeCount,
			promotedCount,
			quarantinedCount,
			cards,
			cves,
			techniques,
			experiences,
		};
	} finally {
		if (owned) {
			try {
				db.close();
			} catch {
				/* ignore */
			}
		}
	}
}

/**
 * 向 `kb_items` 注册或更新跨项目脱敏蒸馏经验卡（`source = 'distilled'`），自动剥离任何潜在隐私凭据。
 */
export function upsertDistilledExperienceCard(
	dbOrPath: Database | string,
	input: DistilledExperienceCardInput,
	opts?: IngestV7SeedOptions,
): KbItemRecord {
	const tech = sanitizeExperienceText(String(input.tech ?? "general").trim().toLowerCase()) || "general";
	const intentKey = sanitizeExperienceText(String(input.intentKey ?? "general").trim()) || "general";
	const id = input.id?.trim() ? input.id.trim() : `exp:${tech}:${intentKey}`;
	const phase = String(input.phase ?? "vuln").trim();
	const title = sanitizeExperienceText(String(input.title ?? "").trim()) || `[蒸馏经验] ${tech} :: ${intentKey}`;
	const summary = sanitizeExperienceText(String(input.summary ?? "").trim()) || title;
	const payloadOrCheck = sanitizeExperienceText(String(input.payload_or_check ?? "").trim()) || summary;
	const rawTags = input.tags?.trim() ? input.tags.trim() : `${tech},${phase},distilled`;
	const tags = rawTags.includes(`intent:${intentKey}`) ? rawTags : `${rawTags},intent:${intentKey}`;
	const severity = String(input.severity ?? "MEDIUM").trim().toUpperCase();
	const ref = String(input.ref ?? "nuwa-distilled-experience").trim();
	const status: KbItemStatus =
		input.status === "promoted" || input.status === "quarantined" ? input.status : "active";
	const nowIso = new Date().toISOString();
	const simhash = computeSimHash64(`${tech} ${intentKey} ${title} ${tags} ${summary} ${payloadOrCheck}`);

	const { db, dbPath, owned } = openOrBorrowWritableDb(dbOrPath, opts?.agentHome);
	try {
		db.exec(KB_ITEMS_DDL);
		db.query(`
			INSERT INTO kb_items (
				id, kind, tech, title, summary, tags, payload_or_check, severity, ref,
				source, status, simhash, updated_at
			) VALUES (?, 'experience', ?, ?, ?, ?, ?, ?, ?, 'distilled', ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				tech = excluded.tech,
				title = excluded.title,
				summary = excluded.summary,
				tags = excluded.tags,
				payload_or_check = excluded.payload_or_check,
				severity = excluded.severity,
				ref = excluded.ref,
				status = excluded.status,
				simhash = excluded.simhash,
				updated_at = excluded.updated_at
			WHERE kb_items.source = 'distilled'
		`).run(id, tech, title, summary, tags, payloadOrCheck, severity, ref, status, simhash, nowIso);

		db.query("DELETE FROM kb_items_fts WHERE id = ?").run(id);
		db.query(`
			INSERT INTO kb_items_fts (id, tech, title, tags, summary, payload_or_check)
			SELECT id, tech, title, tags, summary, payload_or_check FROM kb_items WHERE id = ?
		`).run(id);

		const row = db.query("SELECT * FROM kb_items WHERE id = ?").get(id) as unknown as KbItemRecord;
		if (owned && dbPath !== ":memory:") {
			finalizeWritableKbDb(db);
		}
		return row;
	} finally {
		if (owned) {
			try {
				db.close();
			} catch {
				/* ignore */
			}
		}
	}
}

function escapeLikePattern(input: string): string {
	return input.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

function buildSafeExpandedFtsMatch(terms: readonly string[]): string | null {
	const safeLiterals: string[] = [];
	const seen = new Set<string>();
	for (const raw of terms) {
		// 仅保留纯净字母数字与中文字符，剥离引号与 FTS5 操作符，防止任何语法报错
		const cleaned = raw
			.toLowerCase()
			.replace(/[^a-z0-9\u4e00-\u9fff._-]+/gu, " ")
			.trim();
		if (!cleaned || cleaned.length < 2) continue;
		if (/^(?:and|or|not|near)$/i.test(cleaned)) continue;
		if (!seen.has(cleaned)) {
			seen.add(cleaned);
			safeLiterals.push(`"${cleaned.replace(/"/g, "")}"`);
		}
		if (safeLiterals.length >= 28) break;
	}
	return safeLiterals.length > 0 ? safeLiterals.join(" OR ") : null;
}

/**
 * 零外部依赖混合语义检索引擎：
 * 结合 SQLite FTS5 BM25 宽召回 + 参数化子串补充召回 + 中英安全领域同义概念扩展 +
 * 平滑 TF-IDF 余弦相似度 + 字符 2/3-gram Dice + 64-bit SimHash 海明相似度 + 状态治理过滤。
 */
export function hybridKbSearch(
	dbOrPath: Database | string,
	query: string,
	opts?: HybridKbSearchOptions,
): HybridKbSearchHit[] {
	const rawQuery = String(query ?? "").trim();
	if (!rawQuery) return [];

	const limit = Math.max(1, Math.min(50, Math.floor(safeFinite(opts?.limit ?? 10, 10))));
	const includeQuarantined = opts?.includeQuarantined === true;
	const expansion = expandSecuritySynonyms(rawQuery);
	if (!expansion.normalizedQuery) return [];

	let db: Database;
	let owned = false;

	if (dbOrPath && typeof dbOrPath === "object" && "query" in dbOrPath) {
		db = dbOrPath;
		if (!hasTable(db, "kb_items")) {
			ingestV7SeedPack(db, opts?.packPath, { seedDir: opts?.seedDir, agentHome: opts?.agentHome });
		}
	} else {
		const targetPath =
			typeof dbOrPath === "string" && dbOrPath.trim()
				? resolve(dbOrPath.trim())
				: resolveKbPath(opts?.agentHome);
		if (!existsSync(targetPath) || statSync(targetPath).size === 0) {
			if (opts?.autoInit !== false) {
				ingestV7SeedPack(targetPath, opts?.packPath, { seedDir: opts?.seedDir, agentHome: opts?.agentHome });
			} else {
				throw new Error(`知识库文件不存在: ${targetPath}`);
			}
		} else {
			// 检查是否已初始化 kb_items，若为旧 v4 库则幂等升级并入 v7 种子包
			const probeDb = openReadonlyKbDb(targetPath);
			const ready = hasTable(probeDb, "kb_items") && tableCount(probeDb, "kb_items") > 0;
			probeDb.close();
			if (!ready && opts?.autoInit !== false) {
				ingestV7SeedPack(targetPath, opts?.packPath, { seedDir: opts?.seedDir, agentHome: opts?.agentHome });
			}
		}
		db = openReadonlyKbDb(targetPath);
		owned = true;
	}

	try {
		if (!hasTable(db, "kb_items")) return [];

		const candidateMap = new Map<string, { row: KbItemRecord; rawBm25: number | null }>();
		const recallPoolSize = Math.max(140, limit * 16);
		const filterKind = opts?.kind ? String(opts.kind).trim() : "";
		const filterTech = opts?.tech ? String(opts.tech).trim().toLowerCase() : "";

		// 1. FTS5 宽召回（结合原始词与中英同义扩展词，并将 kind/tech 下推至 SQL 层防止被其他类别挤出 LIMIT）
		const ftsExpr = buildSafeExpandedFtsMatch(expansion.expandedTerms);
		if (ftsExpr && hasTable(db, "kb_items_fts")) {
			try {
				const ftsRows = db
					.query(`
						SELECT k.*, bm25(kb_items_fts, 1.2, 2.5, 4.0, 2.5, 3.0, 1.5) AS raw_bm25
						FROM kb_items_fts
						JOIN kb_items k ON k.id = kb_items_fts.id
						WHERE kb_items_fts MATCH ?
						  AND (? = 1 OR k.status != 'quarantined')
						  AND (? = '' OR k.kind = ?)
						  AND (? = '' OR LOWER(k.tech) = ?)
						ORDER BY raw_bm25 ASC
						LIMIT ?
					`)
					.all(
						ftsExpr,
						includeQuarantined ? 1 : 0,
						filterKind,
						filterKind,
						filterTech,
						filterTech,
						recallPoolSize,
					) as unknown as Array<KbItemRecord & { raw_bm25?: number }>;
				for (const r of ftsRows) {
					candidateMap.set(r.id, {
						row: r,
						rawBm25: typeof r.raw_bm25 === "number" && Number.isFinite(r.raw_bm25) ? r.raw_bm25 : null,
					});
				}
			} catch {
				/* FTS 边缘表达式异常时无缝降级到参数化补充召回 */
			}
		}

		// 2. 参数化 LIKE 子串与中文双字切分补充召回（含 payload_or_check 并下推 kind/tech 过滤）
		const subPhrases: string[] = [];
		for (const term of expansion.expandedTerms) {
			if (term.length >= 2 && subPhrases.length < 10) {
				subPhrases.push(term);
			}
		}
		const cjkRuns = expansion.normalizedQuery.match(/[\u4e00-\u9fff]{2,}/gu) ?? [];
		for (const run of cjkRuns) {
			for (let i = 0; i <= run.length - 2 && subPhrases.length < 14; i++) {
				const bg = run.slice(i, i + 2);
				if (!subPhrases.includes(bg)) subPhrases.push(bg);
			}
		}

		if (subPhrases.length > 0) {
			const likeConds = subPhrases
				.map(
					() =>
						"(title LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' OR tech LIKE ? ESCAPE '\\' OR payload_or_check LIKE ? ESCAPE '\\')",
				)
				.join(" OR ");
			const likeParams: Array<string | number> = [];
			for (const p of subPhrases) {
				const pat = `%${escapeLikePattern(p.toLowerCase())}%`;
				likeParams.push(pat, pat, pat, pat, pat);
			}
			likeParams.push(
				includeQuarantined ? 1 : 0,
				filterKind,
				filterKind,
				filterTech,
				filterTech,
				recallPoolSize,
			);

			const subRows = db
				.query(`
					SELECT * FROM kb_items
					WHERE (${likeConds})
					  AND (? = 1 OR status != 'quarantined')
					  AND (? = '' OR kind = ?)
					  AND (? = '' OR LOWER(tech) = ?)
					LIMIT ?
				`)
				.all(...likeParams) as unknown as KbItemRecord[];

			for (const r of subRows) {
				if (!candidateMap.has(r.id)) {
					candidateMap.set(r.id, { row: r, rawBm25: null });
				}
			}
		}

		// 3. 若候选池仍偏小（例如极端罕见口语），补充采样活跃条目执行 SimHash + N-gram 兜底匹配（同样下推 kind/tech）
		if (candidateMap.size < Math.min(40, limit * 4)) {
			const fallbackRows = db
				.query(`
					SELECT * FROM kb_items
					WHERE (? = 1 OR status != 'quarantined')
					  AND (? = '' OR kind = ?)
					  AND (? = '' OR LOWER(tech) = ?)
					LIMIT 200
				`)
				.all(
					includeQuarantined ? 1 : 0,
					filterKind,
					filterKind,
					filterTech,
					filterTech,
				) as unknown as KbItemRecord[];
			for (const r of fallbackRows) {
				if (!candidateMap.has(r.id)) {
					candidateMap.set(r.id, { row: r, rawBm25: null });
				}
			}
		}

		// 按可选 kind / tech 精细过滤，并再次硬性拦截 quarantined
		const filteredEntries = [...candidateMap.values()].filter(({ row }) => {
			if (!includeQuarantined && row.status === "quarantined") return false;
			if (opts?.kind && row.kind !== opts.kind) return false;
			if (opts?.tech && row.tech.toLowerCase() !== opts.tech.trim().toLowerCase()) return false;
			return true;
		});

		if (filteredEntries.length === 0) return [];

		// 4. 构建局部语料平滑 TF-IDF 向量空间并计算余弦相似度 + N-gram + 64-bit SimHash
		const expandedQueryText = [expansion.normalizedQuery, ...expansion.expandedTerms].join(" ");
		const queryFeatures = extractHybridFeatures(expandedQueryText);
		const querySimHash = computeSimHash64(expandedQueryText);

		const docFeatureList: Array<Map<string, number>> = [];
		const dfMap = new Map<string, number>();
		for (const { row } of filteredEntries) {
			const docText = `${row.tech} ${row.title} ${row.title} ${row.tags} ${row.summary} ${row.payload_or_check}`;
			const feats = extractHybridFeatures(docText);
			docFeatureList.push(feats);
			for (const k of feats.keys()) {
				dfMap.set(k, (dfMap.get(k) ?? 0) + 1);
			}
		}

		const N = filteredEntries.length;
		const idfOf = (term: string): number => {
			const df = dfMap.get(term) ?? 0;
			return Math.log(1 + (N + 1) / (df + 1)) + 1.0;
		};

		let queryNormSq = 0;
		const queryTfIdf = new Map<string, number>();
		for (const [term, tf] of queryFeatures.entries()) {
			const w = (1 + Math.log(1 + tf)) * idfOf(term);
			queryTfIdf.set(term, w);
			queryNormSq += w * w;
		}
		const queryNorm = Math.sqrt(queryNormSq);

		// 归一化 BM25（SQLite bm25 越小越负代表越相关）
		let bestNegBm25 = 0;
		for (const { rawBm25 } of filteredEntries) {
			if (rawBm25 !== null && -rawBm25 > bestNegBm25) {
				bestNegBm25 = -rawBm25;
			}
		}

		const scoredHits: HybridKbSearchHit[] = [];
		for (let i = 0; i < filteredEntries.length; i++) {
			const { row, rawBm25 } = filteredEntries[i]!;
			const docFeats = docFeatureList[i]!;

			// (a) FTS BM25 归一化分
			const ftsScore =
				rawBm25 !== null && bestNegBm25 > 1e-9
					? clamp01(Math.max(0, -rawBm25) / bestNegBm25)
					: 0;

			// (b) TF-IDF 余弦相似度（严防零向量除零）
			let dot = 0;
			let docNormSq = 0;
			for (const [term, dtf] of docFeats.entries()) {
				const dw = (1 + Math.log(1 + dtf)) * idfOf(term);
				docNormSq += dw * dw;
				const qw = queryTfIdf.get(term);
				if (qw !== undefined) {
					dot += qw * dw;
				}
			}
			const denom = queryNorm * Math.sqrt(docNormSq);
			const tfidfCosine = denom > 1e-12 ? clamp01(dot / denom) : 0;

			// (c) 字符 2/3-gram Dice 重叠度
			const docCoreText = `${row.tech} ${row.title} ${row.tags} ${row.summary}`;
			const ngramOverlap = Math.max(
				computeCharNgramDice(expansion.normalizedQuery, docCoreText),
				computeCharNgramDice(expandedQueryText, docCoreText),
			);

			// (d) 64-bit SimHash 海明相似度
			const docSimHash =
				row.simhash && row.simhash !== "0000000000000000"
					? row.simhash
					: computeSimHash64(`${docCoreText} ${row.payload_or_check}`);
			const simhashSim = simHashSimilarity(querySimHash, docSimHash);

			// (e) 跨语种同义概念簇命中增益
			const docLower = `${docCoreText} ${row.payload_or_check}`.toLowerCase();
			const hitConcepts: string[] = [];
			for (const cid of expansion.matchedConcepts) {
				if (docFeats.has(`cid:${cid}`)) {
					hitConcepts.push(cid);
				}
			}
			let expandedTermHits = 0;
			for (const term of expansion.expandedTerms) {
				if (term.length >= 2 && docLower.includes(term)) {
					expandedTermHits += 1;
				}
			}
			const conceptRatio =
				expansion.matchedConcepts.length > 0
					? hitConcepts.length / expansion.matchedConcepts.length
					: 0;
			const termHitBoost = Math.min(1, expandedTermHits / Math.max(3, Math.min(8, expansion.expandedTerms.length)));
			const synonymBoost = clamp01(0.65 * conceptRatio + 0.35 * termHitBoost);

			// (f) 状态治理乘子（默认查询已硬性剔除 quarantined；显式开启 includeQuarantined 诊断时按 0.25 降权，promoted 按 1.25 提权）
			const statusMultiplier =
				row.status === "promoted" ? 1.25 : row.status === "quarantined" ? 0.25 : 1.0;

			const rawCombined =
				0.22 * ftsScore +
				0.32 * tfidfCosine +
				0.18 * ngramOverlap +
				0.10 * simhashSim +
				0.18 * synonymBoost;
			const finalScore = safeFinite(statusMultiplier * rawCombined, 0);

			scoredHits.push({
				id: row.id,
				kind: row.kind,
				tech: row.tech,
				title: row.title,
				summary: row.summary,
				tags: row.tags,
				payload_or_check: row.payload_or_check,
				severity: row.severity,
				ref: row.ref,
				source: row.source,
				status: row.status,
				score: finalScore,
				ftsScore: safeFinite(ftsScore, 0),
				tfidfCosine: safeFinite(tfidfCosine, 0),
				ngramOverlap: safeFinite(ngramOverlap, 0),
				simhashSimilarity: safeFinite(simhashSim, 0),
				synonymBoost: safeFinite(synonymBoost, 0),
				statusMultiplier: safeFinite(statusMultiplier, 1),
				matchedConcepts: hitConcepts,
			});
		}

		return scoredHits
			.filter((h) => h.score > 0)
			.sort((a, b) => (Math.abs(b.score - a.score) > 1e-9 ? b.score - a.score : a.id.localeCompare(b.id)))
			.slice(0, limit);
	} finally {
		if (owned) {
			try {
				db.close();
			} catch {
				/* ignore */
			}
		}
	}
}

function isDistilledExperienceItem(item: Pick<KbItemRecord, "kind" | "source">): boolean {
	return (
		item.source === "distilled" ||
		(item.kind === "experience" &&
			item.source !== "seed" &&
			item.source !== "seed-v4" &&
			item.source !== "seed-v7")
	);
}

function parseCalibrationEventTimeMs(rec: ExperienceCalibrationRecord): number | null {
	for (const raw of [rec.settledAt, rec.createdAt]) {
		const s = String(raw ?? "").trim();
		if (!s) continue;
		const ms = Date.parse(s);
		if (Number.isFinite(ms)) return ms;
	}
	return null;
}

function resolveReferencedKbItemId(
	rec: ExperienceCalibrationRecord,
	allItemsById: ReadonlyMap<string, KbItemRecord>,
	distilledByIntentKey: ReadonlyMap<string, string[]>,
): string[] {
	// 1. 显式字段优先精确绑定（若显式指向内置种子卡，交由外层执行种子卡保护统计）
	const explicitMatched = new Set<string>();
	for (const explicit of [rec.experienceId, rec.cardId, rec.kbItemId]) {
		const id = String(explicit ?? "").trim();
		if (id && allItemsById.has(id)) {
			explicitMatched.add(id);
		}
	}
	if (explicitMatched.size > 0) return [...explicitMatched];

	// 2. 隐式归因：同时收集 note 完整边界 Token 与 intentId 反向索引，严禁前缀子串误杀或种子卡遮蔽蒸馏卡
	const distilledMatched = new Set<string>();
	const explicitSeedMatched = new Set<string>();

	const addCandidate = (id: string, allowSeedFallback: boolean) => {
		const item = allItemsById.get(id);
		if (!item) return;
		if (isDistilledExperienceItem(item)) {
			distilledMatched.add(id);
		} else if (allowSeedFallback) {
			explicitSeedMatched.add(id);
		}
	};

	const noteText = `${rec.note ?? ""} ${rec.settlementNote ?? ""}`.trim();
	if (noteText) {
		const kvMatches = noteText.matchAll(
			/\b(?:exp|card|kb|experienceId|cardId)\s*[:=]\s*([A-Za-z0-9:._-]+)(?![A-Za-z0-9:._-])/gi,
		);
		for (const m of kvMatches) {
			const rawCand = m[1]!.replace(/\.+$/, "");
			for (const cand of [m[1]!, rawCand]) {
				if (!cand) continue;
				addCandidate(cand, true);
				addCandidate(`exp:${cand}`, false);
			}
		}

		// 提取前后严格不紧邻标识符字符的独立 Token，彻底杜绝 exp:nextjs:auth-bypass 误命中 exp:nextjs:auth
		const tokenMatches = noteText.matchAll(/(?<![A-Za-z0-9:._-])([A-Za-z0-9:._-]+)(?![A-Za-z0-9:._-])/g);
		for (const m of tokenMatches) {
			const tok = m[1]!;
			const stripped = tok.replace(/\.+$/, "");
			// note 自由文本顺带提及普通种子编号（如 MITRE T1190 / CVE）不视为攻击种子卡，仅匹配蒸馏经验卡
			addCandidate(tok, false);
			if (stripped && stripped !== tok) {
				addCandidate(stripped, false);
			}
		}
	}

	const intentId = String(rec.intentId ?? "").trim();
	if (intentId) {
		addCandidate(intentId, true);
		const byIntent = distilledByIntentKey.get(intentId.toLowerCase());
		if (byIntent) {
			for (const id of byIntent) addCandidate(id, false);
		}
	}

	if (distilledMatched.size > 0) {
		return [...distilledMatched];
	}
	return [...explicitSeedMatched];
}

/**
 * 蒸馏经验自动优胜劣汰治理器：
 * - 严格反自证：仅采信 `calibration.ts` 允许的 5 类机械核验源（`verifier-gate | exec-ledger | autoexec | benchmark | human`），
 *   任何 `self / model / agent` 自证记录一律拦截拒绝入账（或按 `throwOnSelfCert` 抛 `CalibrationError`）；
 * - 普通种子卡保护：对 `source` 为 `seed / seed-v4 / seed-v7` 的内置种子卡实施硬性写保护，绝不误冻结或误删；
 * - 连续 `>= 5` 次派单零产出（`outcome === 0`）或假阳性误报率超标的蒸馏经验卡自动标记 `quarantined`；
 * - 样本达标且高命中率、低误报率、高 ROI 的蒸馏经验卡自动晋升 `promoted`。
 */
export function governDistilledExperience(
	dbOrPath: Database | string,
	calibrationRecords: readonly ExperienceCalibrationRecord[] | null | undefined,
	opts?: GovernExperienceOptions,
): ExperienceGovernanceResult {
	const streakThreshold =
		typeof opts?.quarantineZeroYieldStreak === "number" &&
		Number.isFinite(opts.quarantineZeroYieldStreak) &&
		opts.quarantineZeroYieldStreak >= 1
			? Math.floor(opts.quarantineZeroYieldStreak)
			: 5;
	const minSamplesFp =
		typeof opts?.minSamplesForFpQuarantine === "number" &&
		Number.isFinite(opts.minSamplesForFpQuarantine) &&
		opts.minSamplesForFpQuarantine >= 1
			? Math.floor(opts.minSamplesForFpQuarantine)
			: 5;
	const maxFpRate =
		typeof opts?.maxFalsePositiveRate === "number" && Number.isFinite(opts.maxFalsePositiveRate)
			? clamp01(opts.maxFalsePositiveRate)
			: 0.40;
	const promoteMinSamples =
		typeof opts?.promoteMinSamples === "number" &&
		Number.isFinite(opts.promoteMinSamples) &&
		opts.promoteMinSamples >= 1
			? Math.floor(opts.promoteMinSamples)
			: 3;
	const promoteMinHitRate =
		typeof opts?.promoteMinHitRate === "number" && Number.isFinite(opts.promoteMinHitRate)
			? clamp01(opts.promoteMinHitRate)
			: 0.60;
	const promoteMaxFpRate =
		typeof opts?.promoteMaxFpRate === "number" && Number.isFinite(opts.promoteMaxFpRate)
			? clamp01(opts.promoteMaxFpRate)
			: 0.15;
	const promoteMinRoi =
		typeof opts?.promoteMinRoi === "number" && Number.isFinite(opts.promoteMinRoi)
			? Math.max(0, opts.promoteMinRoi)
			: 0.20;
	const allowRevoke = opts?.allowRevoke !== false;
	const throwOnSelfCert = opts?.throwOnSelfCert === true;

	const records = Array.isArray(calibrationRecords) ? calibrationRecords : [];
	const { db, dbPath, owned } = openOrBorrowWritableDb(dbOrPath);
	const nowIso = new Date().toISOString();

	try {
		db.exec(KB_ITEMS_DDL);
		syncExperienceTableToKbItems(db, nowIso);

		const allRows = db.query("SELECT * FROM kb_items").all() as unknown as KbItemRecord[];
		const allItemsById = new Map<string, KbItemRecord>();
		const distilledByIntentKey = new Map<string, string[]>();

		for (const r of allRows) {
			allItemsById.set(r.id, r);
			if (isDistilledExperienceItem(r)) {
				// 建立 intentKey 反向索引（例如 exp:nextjs:server-action-auth -> server-action-auth）
				const parts = r.id.split(":");
				if (parts.length >= 3 && parts[0] === "exp") {
					const ik = parts.slice(2).join(":").toLowerCase();
					const arr = distilledByIntentKey.get(ik) ?? [];
					if (!arr.includes(r.id)) arr.push(r.id);
					distilledByIntentKey.set(ik, arr);
				}
				for (const tagMatch of r.tags.matchAll(/\bintent:([A-Za-z0-9:._-]+)/gi)) {
					if (tagMatch[1]) {
						const ik = tagMatch[1].toLowerCase();
						const arr = distilledByIntentKey.get(ik) ?? [];
						if (!arr.includes(r.id)) arr.push(r.id);
						distilledByIntentKey.set(ik, arr);
					}
				}
			}
		}

		let acceptedMechanicalRecords = 0;
		let rejectedSelfCertCount = 0;
		let ignoredUnsettledOrInvalidCount = 0;
		let protectedSeedSkips = 0;

		const groupedRecords = new Map<string, Array<{ rec: ExperienceCalibrationRecord; origIdx: number }>>();

		for (let recIdx = 0; recIdx < records.length; recIdx++) {
			const rec = records[recIdx];
			if (!rec || typeof rec !== "object") {
				ignoredUnsettledOrInvalidCount += 1;
				continue;
			}
			const hasExplicitSource = rec.source !== undefined && rec.source !== null && String(rec.source).trim() !== "";
			const rawSource = typeof rec.source === "string" ? rec.source.trim() : hasExplicitSource ? String(rec.source) : "";
			if (hasExplicitSource && !ALLOWED_SETTLEMENT_SOURCES.has(rawSource as CalibrationSettlementSource)) {
				rejectedSelfCertCount += 1;
				if (throwOnSelfCert) {
					throw new CalibrationError(
						"SELF_CERTIFICATION_FORBIDDEN",
						`governDistilledExperience 严禁采信非机械结算来源: ${rawSource}`,
					);
				}
				continue;
			}
			if (rec.settled !== true || !rawSource) {
				ignoredUnsettledOrInvalidCount += 1;
				continue;
			}
			if ((rec.outcome !== 0 && rec.outcome !== 1) || (rec.isFalsePositive === true && rec.outcome === 1)) {
				ignoredUnsettledOrInvalidCount += 1;
				continue;
			}
			if (
				typeof rec.predictedConfidence !== "number" ||
				!Number.isFinite(rec.predictedConfidence) ||
				rec.predictedConfidence < 0 ||
				rec.predictedConfidence > 1
			) {
				ignoredUnsettledOrInvalidCount += 1;
				continue;
			}
			if (
				(rec.actualTokens !== undefined &&
					(typeof rec.actualTokens !== "number" || !Number.isFinite(rec.actualTokens) || rec.actualTokens < 0)) ||
				(rec.estimatedTokens !== undefined &&
					(typeof rec.estimatedTokens !== "number" || !Number.isFinite(rec.estimatedTokens) || rec.estimatedTokens < 0)) ||
				(rec.durationMs !== undefined &&
					(typeof rec.durationMs !== "number" || !Number.isFinite(rec.durationMs) || rec.durationMs < 0))
			) {
				ignoredUnsettledOrInvalidCount += 1;
				continue;
			}

			acceptedMechanicalRecords += 1;
			const refIds = resolveReferencedKbItemId(rec, allItemsById, distilledByIntentKey);
			for (const itemId of refIds) {
				const targetItem = allItemsById.get(itemId);
				if (!targetItem) continue;
				// 硬性保护普通种子卡（严禁任何校准记录降权或冻结内置种子卡）
				if (!isDistilledExperienceItem(targetItem)) {
					protectedSeedSkips += 1;
					continue;
				}
				const list = groupedRecords.get(itemId) ?? [];
				list.push({ rec, origIdx: recIdx });
				groupedRecords.set(itemId, list);
			}
		}

		const quarantinedIds: string[] = [];
		const promotedIds: string[] = [];
		const activeIds: string[] = [];
		const revokedIds: string[] = [];
		const restoredIds: string[] = [];
		const details: Record<string, ExperienceCardGovernanceDetail> = {};

		const updateStmt = db.query(`
			UPDATE kb_items
			SET status = ?,
			    hit_count = ?,
			    miss_count = ?,
			    fp_count = ?,
			    consecutive_zero_yield = ?,
			    roi_score = ?,
			    updated_at = ?
			WHERE id = ? AND ${DISTILLED_SQL_PREDICATE}
		`);

		const runGovTx = db.transaction(() => {
			for (const [itemId, rawEntries] of groupedRecords.entries()) {
				const item = allItemsById.get(itemId)!;
				const prevStatus: KbItemStatus = item.status;

				// 严格按 settledAt ?? createdAt 时间升序排列（相同或缺失时间戳保持原相对顺序），防止倒序/乱序误算尾部连败
				const sortedEntries = [...rawEntries].sort((a, b) => {
					const ta = parseCalibrationEventTimeMs(a.rec);
					const tb = parseCalibrationEventTimeMs(b.rec);
					if (ta !== null && tb !== null && ta !== tb) {
						return ta - tb;
					}
					return a.origIdx - b.origIdx;
				});
				const seq = sortedEntries.map((e) => e.rec);

				let hitCount = 0;
				let missCount = 0;
				let fpCount = 0;
				let tailZeroStreak = 0;

				for (const r of seq) {
					if (r.outcome === 1) {
						hitCount += 1;
						tailZeroStreak = 0;
					} else {
						missCount += 1;
						tailZeroStreak += 1;
						if (r.isFalsePositive === true) {
							fpCount += 1;
						}
					}
				}

				const settledCount = seq.length;
				const hitRate = settledCount > 0 ? safeFinite(hitCount / settledCount, 0) : 0;
				const fpRate = settledCount > 0 ? safeFinite(fpCount / settledCount, 0) : 0;
				const sliceSummary = computeCalibrationSummary(seq);
				const roiScore = safeFinite(sliceSummary.global.roiScore, 0);

				const shouldQuarantineByStreak = tailZeroStreak >= streakThreshold;
				const shouldQuarantineByFp = settledCount >= minSamplesFp && fpRate > maxFpRate;
				const shouldQuarantine = shouldQuarantineByStreak || shouldQuarantineByFp;

				const shouldPromote =
					!shouldQuarantine &&
					settledCount >= promoteMinSamples &&
					hitRate >= promoteMinHitRate &&
					fpRate <= promoteMaxFpRate &&
					roiScore >= promoteMinRoi;

				let newStatus: KbItemStatus = prevStatus;
				let reason = "";

				if (shouldQuarantine) {
					if (prevStatus === "promoted" && !allowRevoke) {
						newStatus = "promoted";
						reason = "触发退化阈值但 allowRevoke=false，保留原 promoted 状态。";
					} else {
						newStatus = "quarantined";
						if (prevStatus === "promoted") {
							revokedIds.push(itemId);
						}
						reason = shouldQuarantineByStreak
							? `连续 ${tailZeroStreak} 次机械结算零产出（>= ${streakThreshold}），自动降权冻结为 quarantined。`
							: `假阳性误报率 ${(fpRate * 100).toFixed(1)}% 超出上限 ${(maxFpRate * 100).toFixed(1)}%，自动降权冻结为 quarantined。`;
					}
				} else if (shouldPromote) {
					if (prevStatus === "quarantined" && !allowRevoke) {
						newStatus = "quarantined";
						reason = "战绩回升但 allowRevoke=false，维持原 quarantined 隔离状态。";
					} else {
						newStatus = "promoted";
						if (prevStatus === "quarantined") {
							restoredIds.push(itemId);
						}
						reason = `机械结算战绩优异（命中率=${(hitRate * 100).toFixed(1)}%, FPR=${(fpRate * 100).toFixed(1)}%, ROI=${roiScore.toFixed(3)}），晋升为 promoted。`;
					}
				} else {
					if (prevStatus === "quarantined") {
						if (allowRevoke && hitCount > 0 && tailZeroStreak === 0 && fpRate <= maxFpRate) {
							newStatus = "active";
							restoredIds.push(itemId);
							reason = "获得新机械实锤命中打破零产出连败且误报可控，解封恢复为 active。";
						} else {
							newStatus = "quarantined";
							reason = "尚未满足解封条件，维持 quarantined 状态。";
						}
					} else if (prevStatus === "promoted") {
						if (allowRevoke) {
							newStatus = "active";
							revokedIds.push(itemId);
							reason = "近期战绩回落至常规区间，从 promoted 平滑回调为 active。";
						} else {
							newStatus = "promoted";
							reason = "allowRevoke=false，维持 promoted 状态。";
						}
					} else {
						newStatus = "active";
						reason = "处于常规观察期，维持 active 状态。";
					}
				}

				updateStmt.run(
					newStatus,
					hitCount,
					missCount,
					fpCount,
					tailZeroStreak,
					roiScore,
					nowIso,
					itemId,
				);

				details[itemId] = {
					id: itemId,
					previousStatus: prevStatus,
					newStatus,
					settledCount,
					hitCount,
					missCount,
					fpCount,
					consecutiveZeroYield: tailZeroStreak,
					hitRate,
					falsePositiveRate: fpRate,
					roiScore,
					reason,
				};
			}
		});

		runGovTx();

		// 汇总全库当前蒸馏经验卡状态分布（与 isDistilledExperienceItem 严格一致）
		const distilledRows = db
			.query(`SELECT id, status FROM kb_items WHERE ${DISTILLED_SQL_PREDICATE}`)
			.all() as Array<{ id: string; status: KbItemStatus }>;
		for (const r of distilledRows) {
			if (r.status === "quarantined") quarantinedIds.push(r.id);
			else if (r.status === "promoted") promotedIds.push(r.id);
			else activeIds.push(r.id);
		}

		if (owned && dbPath !== ":memory:") {
			finalizeWritableKbDb(db);
		}

		return {
			ok: true,
			evaluatedRecords: records.length,
			acceptedMechanicalRecords,
			rejectedSelfCertCount,
			ignoredUnsettledOrInvalidCount,
			protectedSeedSkips,
			quarantinedIds,
			promotedIds,
			activeIds,
			revokedIds,
			restoredIds,
			allowRevoke,
			details,
		};
	} finally {
		if (owned) {
			try {
				db.close();
			} catch {
				/* ignore */
			}
		}
	}
}
