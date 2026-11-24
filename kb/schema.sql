-- 女娲 v4 便携知识库与自进化经验库 Schema
-- 兼容原有 nuwa/kb.py（card/cve/poc/technique/kev/epss/template/template_cve_map/cve_fts）
-- 并新增 card_fts 全文索引与 v4 自进化经验表 experience。
-- 严禁在本库任何表中存储武器化攻击载荷或目标隐私信息（URL/IP/凭据/Flag）。

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS kb_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

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

-- 仅收录官方安全公告、NVD 与厂商 Advisory 参考链接，严禁收录武器化载荷
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

CREATE TABLE IF NOT EXISTS kev (
	cve_id TEXT PRIMARY KEY,
	added_date TEXT NOT NULL DEFAULT '',
	note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS epss (
	cve_id TEXT PRIMARY KEY,
	score REAL NOT NULL DEFAULT 0.0,
	percentile REAL NOT NULL DEFAULT 0.0
);

-- 兼容旧版 nuwa/kb.py 与可选本机 nuclei-templates 元数据索引（仅存模板路径与只读元信息）
CREATE TABLE IF NOT EXISTS template (
	id TEXT PRIMARY KEY,
	path TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT '',
	tags TEXT NOT NULL DEFAULT '',
	source TEXT NOT NULL DEFAULT 'nuclei'
);

CREATE TABLE IF NOT EXISTS template_cve_map (
	template_id TEXT NOT NULL,
	cve_id TEXT NOT NULL,
	PRIMARY KEY (template_id, cve_id)
);

-- FTS5 全文检索虚拟表（cve_fts 保留 cve_id 列以兼容 nuwa/kb.py 的 bm25 查询）
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
	cve_id,
	product,
	severity,
	descr,
	verify_hint,
	tokenize = 'unicode61'
);

CREATE VIRTUAL TABLE IF NOT EXISTS card_fts USING fts5(
	key,
	tech_key,
	title,
	keywords,
	body,
	tokenize = 'unicode61'
);

-- v4 跨项目脱敏自进化经验表（重复建库/刷新种子时严禁清空或覆盖）
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

CREATE INDEX IF NOT EXISTS idx_card_tech_key ON card(tech_key);
CREATE INDEX IF NOT EXISTS idx_cve_product ON cve(product);
CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve(cvss DESC);
CREATE INDEX IF NOT EXISTS idx_poc_cve_id ON poc(cve_id);
CREATE INDEX IF NOT EXISTS idx_template_cve_map_cve_id ON template_cve_map(cve_id);
CREATE INDEX IF NOT EXISTS idx_experience_tech_key ON experience(tech_key);
CREATE INDEX IF NOT EXISTS idx_experience_intent_key ON experience(intent_key);
