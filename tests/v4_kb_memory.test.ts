/**
 * 女娲 v4 便携知识库与自进化记忆引擎验收测试。
 *
 * 覆盖维度：
 * 1. 静态架构约束（严禁运行时 import ./nuwa、零武器化载荷、36 个 TECH_PATTERNS 100% 覆盖）；
 * 2. 纯 Bun SQLite 一键建库（幂等重建、保护既有 experience 表、可选 nuclei-templates 只读元数据头扫描）；
 * 3. 路径解析优先级（NUWA_KB_DB → <agentHome>/nuwa-kb/kb.db → /data/nuwa-kb/kb.db）与缺失懒初始化；
 * 4. 36 张技术栈审计卡、60+ 公开 CVE、25+ ATT&CK、官方 Advisory 检索与 deriveKbIntents 联调；
 * 5. 参数化 SQL 查询对 SQL 注入 / LIKE 通配符 / FTS5 运算符注入完全免疫；
 * 6. 跨项目经验蒸馏与 100% 敏感信息脱敏（目标 URL/IP/端口/凭据/JWT/Cookie/Flag 绝不入库）；
 * 7. 同类二期项目 UCB1 提权与避坑降权严格落在 [-8, +15] 且单调有序；
 * 8. 向后兼容原 Python 模块 nuwa/kb.py（test_kb.py 全绿）。
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { NuwaState } from "../omp/types";
import { deriveKbIntents } from "../omp/profiles";
import {
	canonicalizeExperienceIntentKey,
	computeExperiencePriorityBoost,
	distillProjectExperience,
	ensureBundledKb,
	extractStateTechStack,
	getKbStats,
	kbLookupSafe,
	resolveKbPath,
	sanitizeExperienceText,
} from "../omp/kb";
import { buildKb, parseNucleiYamlHeader } from "../kb/build-kb";

const REPO_ROOT = resolve(import.meta.dir, "..");
const KB_DIR = join(REPO_ROOT, "kb");
const KB_TS_PATH = join(REPO_ROOT, "omp", "kb.ts");
const PROFILES_TS_PATH = join(REPO_ROOT, "omp", "profiles.ts");
const BUILD_SCRIPT_PATH = join(REPO_ROOT, "kb", "build-kb.ts");

const tmpDirs: string[] = [];
const savedEnv: Record<string, string | undefined> = {};
const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-kb-suite-home-"));
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
process.env.NUWA_KB_DB = join(SUITE_AGENT_HOME, "nuwa-kb", "kb.db");

afterAll(() => {
	rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
});

function makeTmpDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(dir);
	return dir;
}

function setTempEnv(key: string, val: string | undefined): void {
	if (!(key in savedEnv)) {
		savedEnv[key] = process.env[key];
	}
	if (val === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = val;
	}
}

afterEach(() => {
	for (const [k, v] of Object.entries(savedEnv)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
		delete savedEnv[k];
	}
	while (tmpDirs.length > 0) {
		const dir = tmpDirs.pop()!;
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

function extractProfileTechNames(): string[] {
	const src = readFileSync(PROFILES_TS_PATH, "utf8");
	const m = src.match(/const TECH_PATTERNS[\s\S]*?=\s*\[([\s\S]*?)\];/);
	if (!m) throw new Error("无法从 omp/profiles.ts 解析 TECH_PATTERNS");
	const names: string[] = [];
	for (const hit of m[1].matchAll(/\{\s*name:\s*"([^"]+)"/g)) {
		names.push(hit[1]);
	}
	return names;
}

function runBunScript(args: string[], extraEnv: Record<string, string> = {}) {
	const env: Record<string, string> = {};
	for (const [k, v] of Object.entries(process.env)) {
		if (k === "BUN_OPTIONS" || v === undefined) continue;
		env[k] = v;
	}
	Object.assign(env, extraEnv);
	return spawnSync("bun", args, {
		cwd: REPO_ROOT,
		encoding: "utf8",
		env,
		timeout: 30_000,
	});
}

function makeMockState(overrides?: Partial<NuwaState>): NuwaState {
	const ts = "2026-11-24T12:00:00.000Z";
	return {
		schema: 1,
		version: "4.0.0",
		project: {
			id: "target-secret-corp-internal-18443",
			target: "https://target-secret-corp.internal:18443/app",
			url: "https://target-secret-corp.internal:18443/app",
			host: "target-secret-corp.internal",
			port: 18443,
			scheme: "https",
			goal: "验证目标组件配置基线",
			mode: "pentest",
			status: "completed",
			phase: "report",
			episode: 2,
			createdAt: ts,
			updatedAt: ts,
		},
		facts: {},
		intents: {},
		seq: { fact: 0, intent: 0 },
		runtime: {
			startedAt: Date.now(),
			turns: 6,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 12,
			lastToolCalls: 10,
			tokens: 5000,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
		},
		...overrides,
	};
}

describe("静态约束与便携种子资产质量校验", () => {
	test("omp/kb.ts 严禁运行时 import ./nuwa 或仓库相对脚本", () => {
		const src = readFileSync(KB_TS_PATH, "utf8");
		expect(src).toMatch(/import\s+type\s+\{[^}]+\}\s+from\s+["']\.\/(?:types|nuwa)["']/);
		expect(src).not.toMatch(/import\s+(?!type\b)[^;\n]*from\s+["']\.\/nuwa["']/);
		expect(src).not.toMatch(/require\s*\(\s*["']\.\/nuwa["']\s*\)/);
		expect(src).not.toMatch(/from\s+["']\.\.\/kb\/build-kb/);
	});

	test("种子卡片 100% 覆盖 omp/profiles.ts 的全部 36 个 TECH_PATTERNS 且无武器化载荷", () => {
		const techNames = extractProfileTechNames();
		expect(techNames.length).toBe(36);

		const cards = JSON.parse(readFileSync(join(KB_DIR, "seed-cards.json"), "utf8")) as Array<{
			key: string;
			tech_key: string;
			title: string;
			body: string;
		}>;
		const cves = JSON.parse(readFileSync(join(KB_DIR, "seed-cves.json"), "utf8")) as Array<{
			cve_id: string;
			product: string;
			advisories?: string[];
		}>;
		const techniques = JSON.parse(readFileSync(join(KB_DIR, "seed-techniques.json"), "utf8")) as Array<{
			id: string;
			name: string;
		}>;

		expect(cards.length).toBeGreaterThanOrEqual(36);
		expect(cves.length).toBeGreaterThanOrEqual(60);
		expect(techniques.length).toBeGreaterThanOrEqual(25);

		const cardTechSet = new Set(cards.map((c) => c.tech_key));
		for (const name of techNames) {
			expect(cardTechSet.has(name)).toBe(true);
		}

		// 验证所有链接均为公开 HTTP(S) 官方公告参考，且所有种子文本零破坏性命令/武器化载荷
		const combined = [
			readFileSync(join(KB_DIR, "seed-cards.json"), "utf8"),
			readFileSync(join(KB_DIR, "seed-cves.json"), "utf8"),
			readFileSync(join(KB_DIR, "seed-techniques.json"), "utf8"),
		].join("\n");

		expect(combined).not.toMatch(/rm\s+-rf\s+\//i);
		expect(combined).not.toMatch(/\$\{jndi:/i);
		expect(combined).not.toMatch(/\/dev\/tcp\//i);
		expect(combined).not.toMatch(/mkfs\./i);
		expect(combined).not.toMatch(/dd\s+if=/i);

		for (const item of cves) {
			for (const url of item.advisories ?? []) {
				expect(url).toMatch(/^https:\/\//);
			}
		}
	});
});

describe("kb/build-kb.ts 一键纯 Bun SQLite 建库与幂等保护", () => {
	test("CLI --out --seed-dir --stats 一键建库成功，且重复重建绝不清空既有 experience 表", () => {
		const dir = makeTmpDir("nuwa-kb-build-");
		const dbPath = join(dir, "portable", "kb.db");

		const res1 = runBunScript([BUILD_SCRIPT_PATH, "--out", dbPath, "--seed-dir", KB_DIR, "--stats"]);
		expect(res1.status).toBe(0);
		expect(existsSync(dbPath)).toBe(true);

		const stats1 = JSON.parse(res1.stdout.trim());
		expect(stats1.cards).toBeGreaterThanOrEqual(36);
		expect(stats1.cves).toBeGreaterThanOrEqual(60);
		expect(stats1.techniques).toBeGreaterThanOrEqual(25);
		expect(stats1.pocs).toBeGreaterThanOrEqual(60);
		expect(stats1.kevs).toBeGreaterThan(0);
		expect(stats1.epss).toBeGreaterThanOrEqual(60);
		expect(stats1.experiences).toBe(0);

		// 写入一条自进化经验记录，模拟跨项目历史记忆
		const db = new Database(dbPath);
		db.query(
			`INSERT INTO experience (tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		).run("spring", "vuln:component", "vuln", 4, 1, "优先核对 Actuator 与依赖版本基线", "", "2026-11-24T10:00:00.000Z");
		db.close();

		// 再次幂等执行建库，断言种子表不重复、FTS5 同步且 experience 完好无损
		const res2 = runBunScript([BUILD_SCRIPT_PATH, "--out", dbPath, "--seed-dir", KB_DIR, "--stats"]);
		expect(res2.status).toBe(0);
		const stats2 = JSON.parse(res2.stdout.trim());
		expect(stats2.cards).toBe(stats1.cards);
		expect(stats2.cves).toBe(stats1.cves);
		expect(stats2.experiences).toBe(1);

		const checkDb = new Database(dbPath, { readonly: true });
		try {
			const exp = checkDb
				.query("SELECT tech_key, intent_key, success_count, fail_count, helpful_pattern FROM experience WHERE tech_key = ?")
				.get("spring") as any;
			expect(exp).toBeTruthy();
			expect(exp.intent_key).toBe("vuln:component");
			expect(exp.success_count).toBe(4);
			expect(exp.fail_count).toBe(1);
			expect(exp.helpful_pattern).toContain("Actuator");

			// 验证 FTS5 行数与主表一致，无重复索引
			const cveFtsCount = (checkDb.query("SELECT COUNT(*) AS c FROM cve_fts").get() as any).c;
			const cardFtsCount = (checkDb.query("SELECT COUNT(*) AS c FROM card_fts").get() as any).c;
			expect(cveFtsCount).toBe(stats2.cves);
			expect(cardFtsCount).toBe(stats2.cards);
		} finally {
			checkDb.close();
		}
	});

	test("--nuclei-dir 仅只读解析 YAML 元数据头并增量写入，严格跳过 http 请求体", () => {
		const dir = makeTmpDir("nuwa-kb-nuclei-");
		const dbPath = join(dir, "kb.db");
		const nucleiDir = join(dir, "nuclei-templates");
		mkdirSync(join(nucleiDir, "cves", "2025"), { recursive: true });

		// 模拟新 CVE 模板（含 http 请求段，验证解析器立即截断绝不入库载荷）
		const syntheticYaml = [
			"id: CVE-2025-99901",
			"",
			"info:",
			"  name: Demo Proxy Header Boundary Issue",
			"  severity: high",
			"  description: |",
			"    Synthetic vendor advisory metadata for unit testing header-only extraction.",
			"  reference:",
			"    - https://nvd.nist.gov/vuln/detail/CVE-2025-99901",
			"  classification:",
			"    cvss-score: 8.2",
			"    cve-id: CVE-2025-99901",
			"    cwe-id: CWE-287",
			"  tags: cve,cve2025,nginx,misconfig",
			"",
			"http:",
			"  - raw:",
			"      - |",
			"        GET /NEVER_STORE_THIS_PAYLOAD_MARKER HTTP/1.1",
			"        Host: {{Hostname}}",
		].join("\n");

		writeFileSync(join(nucleiDir, "cves", "2025", "CVE-2025-99901.yaml"), syntheticYaml, "utf8");

		// 模拟已存在于种子的 CVE 模板：仅关联 template_cve_map，不覆盖权威中文描述
		const existingYaml = [
			"id: CVE-2021-44228",
			"info:",
			"  name: Log4j Metadata Check",
			"  severity: critical",
			"  description: Should not overwrite seed description",
			"  classification:",
			"    cve-id: CVE-2021-44228",
			"  tags: cve,log4j",
			"http:",
			"  - method: GET",
			"    path:",
			"      - /IGNORED_BODY",
		].join("\n");
		writeFileSync(join(nucleiDir, "cves", "2025", "CVE-2021-44228.yaml"), existingYaml, "utf8");

		const parsed = parseNucleiYamlHeader(syntheticYaml);
		expect(parsed).toBeTruthy();
		expect(parsed!.cves).toEqual(["CVE-2025-99901"]);
		expect(parsed!.cvss).toBe(8.2);
		expect(parsed!.description).not.toContain("NEVER_STORE_THIS_PAYLOAD_MARKER");

		const stats = buildKb({ outPath: dbPath, seedDir: KB_DIR, nucleiDir });
		expect(stats.nucleiScanned).toBe(2);
		expect(stats.nucleiAddedCves).toBe(1);
		expect(stats.templates).toBe(2);
		expect(stats.templateCveMaps).toBe(2);

		const hitNew = kbLookupSafe("CVE-2025-99901", "cve", 3, { dbPath, autoInit: false });
		expect(hitNew).toContain("CVE-2025-99901");
		expect(hitNew).toContain("HIGH");
		expect(hitNew).toContain("8.2");
		expect(hitNew).not.toContain("NEVER_STORE_THIS_PAYLOAD_MARKER");

		// 验证已有种子描述未被覆盖
		const hitSeed = kbLookupSafe("CVE-2021-44228", "cve", 3, { dbPath, autoInit: false });
		expect(hitSeed).toContain("Apache Log4j2");
		expect(hitSeed).not.toContain("Should not overwrite seed description");
	});
});

describe("omp/kb.ts 路径优先级、懒初始化与安全检索", () => {
	test("resolveKbPath 严格遵循 NUWA_KB_DB → <agentHome>/nuwa-kb/kb.db 优先级", () => {
		const dir = makeTmpDir("nuwa-kb-path-");
		const customEnvDb = join(dir, "env-override.db");
		const agentHome = join(dir, "agent-home");

		setTempEnv("NUWA_KB_DB", customEnvDb);
		expect(resolveKbPath(agentHome)).toBe(resolve(customEnvDb));

		setTempEnv("NUWA_KB_DB", undefined);
		expect(resolveKbPath(agentHome)).toBe(join(resolve(agentHome), "nuwa-kb", "kb.db"));

		setTempEnv("PI_AGENT_HOME", agentHome);
		const homeDb = join(resolve(agentHome), "nuwa-kb", "kb.db");
		mkdirSync(join(agentHome, "nuwa-kb"), { recursive: true });
		writeFileSync(homeDb, "stub", "utf8");
		expect(resolveKbPath()).toBe(homeDb);
	});

	test("DB 缺失时 kbLookupSafe 自动懒初始化随仓种子，36 张卡片 + CVE + ATT&CK 全命中", () => {
		const dir = makeTmpDir("nuwa-kb-lazy-");
		const dbPath = join(dir, "auto-init", "kb.db");

		// 初始不存在且 getKbStats 默认不触发写盘
		const before = getKbStats(dbPath);
		expect(before.exists).toBe(false);
		expect(existsSync(dbPath)).toBe(false);

		// 首次查询触发懒建库
		const nginxHit = kbLookupSafe("nginx 1.18.0", "product", 3, { dbPath });
		expect(existsSync(dbPath)).toBe(true);
		expect(nginxHit).toContain("nginx:nginx");
		expect(nginxHit).toContain("【版本确认】");
		expect(nginxHit).toContain("【加固建议】");

		// 校验全部 36 个 TECH_PATTERNS 关键词均能命中对应中文技术栈审计卡
		const techNames = extractProfileTechNames();
		for (const kw of techNames) {
			const cardText = kbLookupSafe(kw, "product", 2, { dbPath, autoInit: false });
			expect(cardText.startsWith("未命中")).toBe(false);
			expect(cardText).toContain("## ");
			expect(cardText).toContain("【配置核查点】");
		}

		// CVE、Technique、PoC（官方公告）检索验证
		const cveHit = kbLookupSafe("CVE-2021-44228", "auto", 3, { dbPath, autoInit: false });
		expect(cveHit).toContain("CVE-2021-44228");
		expect(cveHit).toContain("CRITICAL");
		expect(cveHit).toContain("KEV=1");
		expect(cveHit).toContain("https://nvd.nist.gov/vuln/detail/CVE-2021-44228");

		const techHit = kbLookupSafe("T1190", "auto", 3, { dbPath, autoInit: false });
		expect(techHit).toContain("T1190");
		expect(techHit).toContain("Initial Access");

		const pocHit = kbLookupSafe("CVE-2023-22515", "poc", 3, { dbPath, autoInit: false });
		expect(pocHit).toContain("CVE-2023-22515");
		expect(pocHit).toContain("https://");

		// 与 omp/profiles.ts 的 deriveKbIntents 联调
		const st = makeMockState({
			facts: {
				F001: {
					id: "F001",
					kind: "service",
					title: "Apache Tomcat/9.0 + Spring Boot",
					detail: "检测到 Spring Actuator 与 CVE-2022-22965 关注项",
					createdAt: "2026-11-24T12:00:00.000Z",
				},
			},
		});
		const derived = deriveKbIntents(st, (q, k, lim) => kbLookupSafe(q, k, lim, { dbPath, autoInit: false }), 5);
		expect(derived.length).toBeGreaterThanOrEqual(3);
		expect(derived.some((d) => d.key === "kb:F001:tomcat")).toBe(true);
		expect(derived.some((d) => d.key === "kb:F001:spring")).toBe(true);
		expect(derived.some((d) => d.key === "kb:F001:cve-2022-22965")).toBe(true);
	});

	test("旧版 DB 缺少 experience 表时 ensureBundledKb 原地增量迁移不丢数据", () => {
		const dir = makeTmpDir("nuwa-kb-migrate-");
		const dbPath = join(dir, "legacy.db");
		const legacy = new Database(dbPath);
		legacy.exec(`
			CREATE TABLE card (key TEXT PRIMARY KEY, tech_key TEXT DEFAULT '', title TEXT, keywords TEXT DEFAULT '', body TEXT);
			CREATE TABLE cve (cve_id TEXT PRIMARY KEY, product TEXT DEFAULT '', affected_versions TEXT DEFAULT '', severity TEXT, cvss REAL, cwe TEXT DEFAULT '', descr TEXT, verify_hint TEXT DEFAULT '', remediation TEXT DEFAULT '');
			INSERT INTO card (key, tech_key, title, body) VALUES ('custom:demo', 'demo', 'Legacy Card', 'legacy body');
		`);
		legacy.close();

		const res = ensureBundledKb(dbPath);
		expect(res.ok).toBe(true);
		expect(res.created).toBe(false);
		expect(res.migrated).toBe(true);
		expect(res.stats.cards).toBe(1);

		const hit = kbLookupSafe("custom:demo", "product", 2, { dbPath, autoInit: false });
		expect(hit).toContain("Legacy Card");
	});

	test("全参数化查询对 SQL 注入、通配符注入与 FTS 语法注入完全免疫", () => {
		const dir = makeTmpDir("nuwa-kb-sqli-");
		const dbPath = join(dir, "kb.db");
		const init = ensureBundledKb(dbPath, { seedDir: KB_DIR });
		const beforeCards = init.stats.cards;
		const beforeCves = init.stats.cves;

		const payloads = [
			"' OR '1'='1",
			"' OR 1=1 --",
			"'; DROP TABLE cve; --",
			"'; DELETE FROM card; --",
			"nginx' UNION SELECT key, title, body FROM card --",
			"CVE-2021-44228' OR '1'='1",
			"100%_%_nonexistent",
			"\" OR * NEAR/0 (SELECT 1)",
		];

		for (const p of payloads) {
			for (const kind of ["auto", "product", "cve", "technique", "poc"] as const) {
				const out = kbLookupSafe(p, kind, 5, { dbPath, autoInit: false });
				expect(out.startsWith("未命中")).toBe(true);
			}
		}

		// 空查询保持与原 kbLookup 一致抛错
		expect(() => kbLookupSafe("   ", "auto", 5, { dbPath, autoInit: false })).toThrow("query 为空");

		// 核实所有核心表行数据 100% 完好
		const after = getKbStats(dbPath);
		expect(after.cards).toBe(beforeCards);
		expect(after.cves).toBe(beforeCves);
	});
});

describe("自进化经验脱敏蒸馏与 UCB1 跨项目提权", () => {
	test("sanitizeExperienceText 与 distillProjectExperience 100% 剥离目标 URL/IP/端口/凭据/Flag", () => {
		const dir = makeTmpDir("nuwa-kb-distill-");
		const dbPath = join(dir, "kb.db");
		ensureBundledKb(dbPath, { seedDir: KB_DIR });

		const fakeJwt =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
		const fakeFlag = "flag{nuwa_v4_secret_flag_987654}";
		const fakeCtf = "CTF{another_sensitive_proof_2026}";

		const phase1State = makeMockState({
			facts: {
				F001: {
					id: "F001",
					kind: "service",
					title: "HTTP 200 nginx/1.18.0 + Spring Boot Actuator",
					detail: "响应来自 https://target-secret-corp.internal:18443/actuator/health (10.23.45.67:18443)",
					output: "Server: nginx/1.18.0\nSpring Boot 2.6",
					intent: "I001",
					meta: { tech: ["nginx", "spring"] },
					createdAt: "2026-11-24T12:01:00.000Z",
				},
				F002: {
					id: "F002",
					kind: "vuln",
					title: `Spring Actuator 在 10.23.45.67:18443 暴露配置与 Bearer ${fakeJwt}`,
					detail: `password=Sup3rS3cret!99 Cookie: JSESSIONID=SECRET_SESS_9988; rememberMe=AAAABBBBCCCC api_key=sk-live998877665544`,
					intent: "I002",
					createdAt: "2026-11-24T12:02:00.000Z",
				},
				F003: {
					id: "F003",
					kind: "cred",
					title: "发现凭据 admin:DbP@ssw0rd2026 ops@secret-corp.internal",
					detail: "mysql://root:DbP@ssw0rd2026@10.23.45.67:3306/prod",
					intent: "I003",
					createdAt: "2026-11-24T12:03:00.000Z",
				},
				F004: {
					id: "F004",
					kind: "flag",
					title: `取证成功 ${fakeFlag}`,
					detail: `${fakeFlag}\n${fakeCtf}`,
					output: fakeFlag,
					intent: "I004",
					createdAt: "2026-11-24T12:04:00.000Z",
				},
				F005: {
					id: "F005",
					kind: "blocked",
					title: "目标 10.23.45.67:18443 无上传入口",
					detail: "https://target-secret-corp.internal:18443/upload 返回 404",
					intent: "I005",
					createdAt: "2026-11-24T12:05:00.000Z",
				},
			},
			intents: {
				I001: {
					id: "I001",
					phase: "recon",
					key: "recon:http",
					title: "HTTP 指纹识别 https://target-secret-corp.internal:18443",
					detail: "",
					from: [],
					to: "F001",
					status: "done",
					priority: 90,
					attempts: 1,
					createdAt: "2026-11-24T12:00:10.000Z",
				},
				I002: {
					id: "I002",
					phase: "vuln",
					key: "e2:vuln:component",
					title: "组件基线核验 10.23.45.67:18443",
					detail: "",
					from: ["F001"],
					to: "F002",
					status: "done",
					priority: 86,
					attempts: 1,
					createdAt: "2026-11-24T12:01:10.000Z",
				},
				I003: {
					id: "I003",
					phase: "exploit",
					key: "exploit:creds",
					title: "配置凭据暴露评估 admin:DbP@ssw0rd2026",
					detail: "",
					from: ["F002"],
					to: "F003",
					status: "done",
					priority: 84,
					attempts: 1,
					createdAt: "2026-11-24T12:02:10.000Z",
				},
				I004: {
					id: "I004",
					phase: "post",
					key: "post:flag",
					title: `验收标记取证 ${fakeFlag}`,
					detail: "",
					from: ["F002"],
					to: "F004",
					status: "done",
					priority: 95,
					attempts: 1,
					createdAt: "2026-11-24T12:03:10.000Z",
				},
				I005: {
					id: "I005",
					phase: "surface",
					key: "e2:surface:uploads",
					title: "文件上传入口梳理",
					detail: "",
					from: ["F001"],
					to: "F005",
					status: "blocked",
					note: "https://target-secret-corp.internal:18443/upload 不存在 (10.23.45.67 port 18443)",
					priority: 60,
					attempts: 2,
					createdAt: "2026-11-24T12:04:10.000Z",
				},
			},
		});

		expect(extractStateTechStack(phase1State)).toEqual(["nginx", "spring", "shiro"]);
		expect(canonicalizeExperienceIntentKey("e2:vuln:component")).toBe("vuln:component");
		expect(canonicalizeExperienceIntentKey("kb:F003:spring")).toBe("kb:spring");

		const cleanSample = sanitizeExperienceText(
			`连接 https://10.23.45.67:18443/x 与 [2001:db8::1]:8443 命中 ${fakeFlag} password=Sup3rS3cret!99`,
			phase1State,
		);
		expect(cleanSample).not.toContain("10.23.45.67");
		expect(cleanSample).not.toContain("18443");
		expect(cleanSample).not.toContain("2001:db8::1");
		expect(cleanSample).not.toContain("flag{");
		expect(cleanSample).not.toContain("Sup3rS3cret");

		const distillRes = distillProjectExperience(phase1State, { dbPath });
		expect(distillRes.ok).toBe(true);
		expect(distillRes.techKeys).toEqual(["nginx", "spring", "shiro"]);
		expect(distillRes.positive).toBe(4);
		expect(distillRes.negative).toBe(1);
		expect(distillRes.updated).toBe(9); // v4.1 精准来源归因（消除 3x5=15 笛卡尔积误污染）

		// 直接扫描 SQLite experience 全表，确认 0 敏感信息入库且无跨技术栈误污染
		const db = new Database(dbPath, { readonly: true });
		try {
			const rows = db.query("SELECT * FROM experience").all() as Array<Record<string, any>>;
			expect(rows.length).toBe(9);
			expect(rows.find((r) => r.tech_key === "nginx" && r.intent_key === "vuln:component")).toBeUndefined();
			expect(rows.find((r) => r.tech_key === "shiro" && r.intent_key === "surface:uploads")).toBeUndefined();
			const dumped = JSON.stringify(rows);

			const forbiddenSecrets = [
				"10.23.45.67",
				"target-secret-corp",
				"18443",
				"3306",
				"flag{",
				"nuwa_v4_secret_flag",
				"CTF{",
				"another_sensitive_proof",
				"Sup3rS3cret",
				"SECRET_SESS_9988",
				"AAAABBBBCCCC",
				"DbP@ssw0rd2026",
				"sk-live998877665544",
				"eyJhbGci",
				"ops@secret-corp",
			];
			for (const secret of forbiddenSecrets) {
				expect(dumped).not.toContain(secret);
			}

			// 校验规范化键与正负计数
			const springComp = rows.find((r) => r.tech_key === "spring" && r.intent_key === "vuln:component");
			expect(springComp).toBeTruthy();
			expect(springComp!.success_count).toBe(1);
			expect(springComp!.fail_count).toBe(0);

			const springUpload = rows.find((r) => r.tech_key === "spring" && r.intent_key === "surface:uploads");
			expect(springUpload).toBeTruthy();
			expect(springUpload!.success_count).toBe(0);
			expect(springUpload!.fail_count).toBe(1);
		} finally {
			db.close();
		}

		// 检索 spring 卡片时自动附带脱敏后的历史经验提示
		const lookupWithExp = kbLookupSafe("spring", "product", 3, { dbPath, autoInit: false });
		expect(lookupWithExp).toContain("【历史经验提示】");
		expect(lookupWithExp).toContain("vuln:component");
		expect(lookupWithExp).not.toContain("10.23.45.67");
		expect(lookupWithExp).not.toContain("nuwa_v4_secret_flag");
	});

	test("派生意图键归一化与非常规 TLD / Scope / SAN / output 非花括号 Flag 端到端零泄漏", () => {
		// 1. 派生意图键全量归一化规则校验
		expect(canonicalizeExperienceIntentKey("san:f001:admin.target-secret-corp.internal")).toBe("san:domain");
		expect(canonicalizeExperienceIntentKey("e2:san:F009:api.hema.ai")).toBe("san:domain");
		expect(canonicalizeExperienceIntentKey("svc:f002:18443")).toBe("svc:port");
		expect(canonicalizeExperienceIntentKey("e3:svc:F002:9443")).toBe("svc:port");
		expect(canonicalizeExperienceIntentKey("ep:f003:/tenant-acme-corp/login")).toBe("ep:login");
		expect(canonicalizeExperienceIntentKey("ep:f003:/secret-tenant")).toBe("ep:endpoint");
		expect(canonicalizeExperienceIntentKey("ep:f003:/v3/openapi.json")).toBe("ep:openapi");
		expect(canonicalizeExperienceIntentKey("ep:f003:/actuator/env")).toBe("ep:actuator");
		expect(canonicalizeExperienceIntentKey("ep:f003")).toBe("ep:endpoint");
		expect(canonicalizeExperienceIntentKey("exp:F007")).toBe("exp");
		expect(canonicalizeExperienceIntentKey("pivot:f008")).toBe("pivot");
		expect(canonicalizeExperienceIntentKey("reuse:F009")).toBe("reuse");
		expect(canonicalizeExperienceIntentKey("migrated:I002")).toBe("migrated");
		expect(canonicalizeExperienceIntentKey("waf-bypass:I003")).toBe("waf-bypass");
		expect(canonicalizeExperienceIntentKey("waf-bypass:4")).toBe("waf-bypass");
		expect(canonicalizeExperienceIntentKey("reflect:e2:vuln:3")).toBe("reflect:vuln");
		expect(canonicalizeExperienceIntentKey("reflect:surface:retry")).toBe("reflect:surface");

		// 2. 非常规 TLD 与国家二级域脱敏 + 静态文件/框架配置名防误杀校验
		const domainSanitized = sanitizeExperienceText(
			"跳转至 admin.hema.ai、auth.hema.ai 及 api.client.co.uk 与 portal.corp.beer 失败，端口 18443 无响应",
		);
		expect(domainSanitized).not.toContain("hema.ai");
		expect(domainSanitized).not.toContain("client.co.uk");
		expect(domainSanitized).not.toContain("corp.beer");
		expect(domainSanitized).not.toContain("18443");
		expect(domainSanitized).toContain("<HOST>");
		expect(domainSanitized).toContain("端口 <PORT>");

		const safeTechText = sanitizeExperienceText(
			"核查 openapi.json、web.xml、wp-config.php、HTTP.sys、WebMvc.fn 与 management.endpoints.web 配置",
		);
		expect(safeTechText).toContain("openapi.json");
		expect(safeTechText).toContain("web.xml");
		expect(safeTechText).toContain("wp-config.php");
		expect(safeTechText).toContain("HTTP.sys");
		expect(safeTechText).toContain("WebMvc.fn");
		expect(safeTechText).toContain("management.endpoints.web");

		// 3. 端到端蒸馏：含 Scope/SAN 域名、真实派生意图键及仅存于 output 的非花括号 Flag
		const dir = makeTmpDir("nuwa-kb-derived-sanitize-");
		const dbPath = join(dir, "kb.db");
		ensureBundledKb(dbPath, { seedDir: KB_DIR });

		const derivedState = makeMockState({
			project: {
				...makeMockState().project,
				id: "portal-hema-ai-18443",
				target: "https://portal.hema.ai:18443",
				url: "https://portal.hema.ai:18443",
				host: "portal.hema.ai",
				port: 18443,
				scope: {
					allowHosts: ["*.hema.ai", "billing.client.co.uk"],
					allowCidrs: [],
					denyHosts: ["vault.corp.beer"],
					allowSubdomains: true,
					allowPrivateNetwork: false,
					allowDestructive: false,
				},
			},
			facts: {
				F001: {
					id: "F001",
					kind: "service",
					title: "Nginx 1.24 反向代理服务",
					detail: "TLS 证书发现 SAN 域名",
					meta: {
						tech: ["nginx"],
						ports: [18443],
						san: ["admin.hema.ai", "api.client.co.uk", "portal.corp.beer"],
					},
					intent: "I001",
					createdAt: "2026-11-24T12:00:00.000Z",
				},
				F002: {
					id: "F002",
					kind: "asset",
					title: "SAN 资产 admin.hema.ai 与 billing.client.co.uk 存活",
					detail: "跳转至 portal.corp.beer 并拒连 vault.corp.beer",
					intent: "I002",
					createdAt: "2026-11-24T12:01:00.000Z",
				},
				F003: {
					id: "F003",
					kind: "vuln",
					title: "端点 /tenant-acme-corp/login 认证配置缺陷",
					detail: "涉及端口 18443 与 api.client.co.uk",
					meta: { paths: ["/tenant-acme-corp/login", "/secret-tenant"] },
					intent: "I004",
					createdAt: "2026-11-24T12:02:00.000Z",
				},
				F004: {
					id: "F004",
					kind: "flag",
					title: "完成验收目标读取",
					detail: "已获取主凭证证明",
					output: "stdout:\nFLAG-2026-SECRET-9988\nRAW_OUTPUT_PROOF_7788\n",
					intent: "I006",
					createdAt: "2026-11-24T12:03:00.000Z",
				},
				F005: {
					id: "F005",
					kind: "vuln",
					title: "二次复核中附带引用 FLAG-2026-SECRET-9988 与 RAW_OUTPUT_PROOF_7788",
					detail: "命中 /secret-tenant",
					intent: "I007",
					createdAt: "2026-11-24T12:04:00.000Z",
				},
			},
			intents: {
				I002: {
					id: "I002",
					phase: "recon",
					key: "san:F001:admin.hema.ai",
					title: "SAN 资产枚举 admin.hema.ai",
					detail: "",
					from: ["F001"],
					to: "F002",
					status: "done",
					priority: 74,
					attempts: 1,
					createdAt: "2026-11-24T12:00:30.000Z",
				},
				I003: {
					id: "I003",
					phase: "surface",
					key: "svc:F002:18443",
					title: "服务深挖 portal.hema.ai:18443",
					detail: "",
					from: ["F001"],
					status: "blocked",
					note: "端口 18443 连接至 portal.corp.beer 超时，跳过 vault.corp.beer",
					priority: 70,
					attempts: 2,
					createdAt: "2026-11-24T12:00:40.000Z",
				},
				I004: {
					id: "I004",
					phase: "vuln",
					key: "ep:F003:/tenant-acme-corp/login",
					title: "端点审计 /tenant-acme-corp/login",
					detail: "",
					from: ["F003"],
					to: "F003",
					status: "done",
					priority: 68,
					attempts: 1,
					createdAt: "2026-11-24T12:01:30.000Z",
				},
				I005: {
					id: "I005",
					phase: "vuln",
					key: "ep:F003:/secret-tenant",
					title: "端点审计 /secret-tenant",
					detail: "",
					from: ["F003"],
					status: "blocked",
					note: "路径 /secret-tenant 跳转至 api.client.co.uk 无有效接口",
					priority: 68,
					attempts: 2,
					createdAt: "2026-11-24T12:01:50.000Z",
				},
				I006: {
					id: "I006",
					phase: "post",
					key: "exp:F003",
					title: "利用验证 FLAG-2026-SECRET-9988",
					detail: "",
					from: ["F003"],
					to: "F004",
					status: "done",
					priority: 92,
					attempts: 1,
					createdAt: "2026-11-24T12:02:30.000Z",
				},
				I007: {
					id: "I007",
					phase: "vuln",
					key: "reflect:e2:vuln:1",
					title: "战略复盘 billing.client.co.uk",
					detail: "",
					from: ["F003"],
					to: "F005",
					status: "done",
					priority: 85,
					attempts: 1,
					createdAt: "2026-11-24T12:03:30.000Z",
				},
				I008: {
					id: "I008",
					phase: "vuln",
					key: "waf-bypass:I005",
					title: "WAF 换路验证",
					detail: "",
					from: ["F003"],
					status: "blocked",
					note: "admin.hema.ai 持续返回 429",
					priority: 75,
					attempts: 2,
					createdAt: "2026-11-24T12:04:30.000Z",
				},
			},
		});

		const res = distillProjectExperience(derivedState, { dbPath });
		expect(res.ok).toBe(true);
		expect(res.techKeys).toEqual(["nginx"]);

		const db = new Database(dbPath, { readonly: true });
		try {
			const rows = db.query("SELECT * FROM experience ORDER BY intent_key").all() as Array<Record<string, any>>;
			const keys = rows.map((r) => r.intent_key);
			expect(keys).toEqual(["ep:endpoint", "ep:login", "exp", "reflect:vuln", "san:domain", "svc:port", "waf-bypass"]);

			const dumped = JSON.stringify(rows);
			const forbidden = [
				"hema.ai",
				"client.co.uk",
				"corp.beer",
				"secret-tenant",
				"tenant-acme-corp",
				"18443",
				"f001",
				"f002",
				"f003",
				"FLAG-2026-SECRET-9988",
				"RAW_OUTPUT_PROOF_7788",
			];
			for (const bad of forbidden) {
				expect(dumped.toLowerCase()).not.toContain(bad.toLowerCase());
			}
		} finally {
			db.close();
		}

		// 验证二期新靶标下不同 F-ID/域名/端口/租户路径可无缝命中聚合 UCB1 经验
		const sanBoost1 = computeExperiencePriorityBoost(["nginx"], "san:F099:new-corp.example.ai", { dbPath });
		const loginBoost1 = computeExperiencePriorityBoost(["nginx"], "ep:F088:/other-org/login", { dbPath });
		const svcBoost1 = computeExperiencePriorityBoost(["nginx"], "svc:F077:28443", { dbPath });
		const epPrivateBoost1 = computeExperiencePriorityBoost(["nginx"], "ep:F066:/other-private-path", { dbPath });
		expect(sanBoost1).toBeGreaterThan(0);
		expect(loginBoost1).toBeGreaterThan(0);
		expect(sanBoost1).toBeGreaterThan(svcBoost1);
		expect(loginBoost1).toBeGreaterThan(epPrivateBoost1);

		// 再叠加一期同类经验后，持续受阻的 svc:port 与 ep:endpoint 严格转负降权
		distillProjectExperience(derivedState, { dbPath });
		const svcBoost2 = computeExperiencePriorityBoost(["nginx"], "svc:F077:28443", { dbPath });
		const epPrivateBoost2 = computeExperiencePriorityBoost(["nginx"], "ep:F066:/other-private-path", { dbPath });
		expect(svcBoost2).toBeLessThan(0);
		expect(epPrivateBoost2).toBeLessThan(0);
	});

	test("同类二期项目 UCB1 算法稳定实现高胜率提权、坑路径降权并严格限幅于 [-8, +15]", () => {
		const dir = makeTmpDir("nuwa-kb-ucb1-");
		const dbPath = join(dir, "kb.db");
		ensureBundledKb(dbPath, { seedDir: KB_DIR });

		// 冷启动：无历史经验时返回 0
		expect(computeExperiencePriorityBoost(["spring", "nginx"], "vuln:component", { dbPath })).toBe(0);
		expect(computeExperiencePriorityBoost(["spring"], "vuln:component", { dbPath: join(dir, "missing.db") })).toBe(0);

		// 模拟 2 期同技术栈（spring + nginx）项目经验沉淀：vuln:component 持续命中，surface:uploads 持续受阻
		const buildEpisodeState = (host: string) =>
			makeMockState({
				project: {
					...makeMockState().project,
					id: host.replace(/\./g, "-"),
					target: `http://${host}:8080`,
					url: `http://${host}:8080`,
					host,
					port: 8080,
				},
				facts: {
					F001: {
						id: "F001",
						kind: "service",
						title: "Spring Boot + Nginx",
						detail: "Spring Boot 2.x",
						intent: "I001",
						createdAt: "2026-11-24T12:00:00.000Z",
					},
					F002: {
						id: "F002",
						kind: "vuln",
						title: "Actuator 组件配置基线缺陷",
						detail: "只读核验命中",
						intent: "I002",
						createdAt: "2026-11-24T12:01:00.000Z",
					},
				},
				intents: {
					I002: {
						id: "I002",
						phase: "vuln",
						key: "vuln:component",
						title: "组件版本安全缺陷复核",
						detail: "",
						from: ["F001"],
						to: "F002",
						status: "done",
						priority: 80,
						attempts: 1,
						createdAt: "2026-11-24T12:00:30.000Z",
					},
					I003: {
						id: "I003",
						phase: "surface",
						key: "surface:uploads",
						title: "文件上传入口梳理",
						detail: "",
						from: ["F001"],
						status: "blocked",
						note: "无上传功能",
						priority: 60,
						attempts: 2,
						createdAt: "2026-11-24T12:00:40.000Z",
					},
				},
			});

		distillProjectExperience(buildEpisodeState("10.10.1.11"), { dbPath });
		distillProjectExperience(buildEpisodeState("10.10.1.12"), { dbPath });

		// 同类二期/三期项目调度优先级偏移评估（支持 e2: 前缀自动归一化）
		const highBoost = computeExperiencePriorityBoost(["spring", "nginx"], "e2:vuln:component", { dbPath });
		const untriedBoost = computeExperiencePriorityBoost(["spring", "nginx"], "vuln:ssrf", { dbPath });
		const pitfallBoost = computeExperiencePriorityBoost(["spring", "nginx"], "surface:uploads", { dbPath });
		const unrelatedBoost = computeExperiencePriorityBoost(["drupal"], "vuln:component", { dbPath });

		expect(highBoost).toBeGreaterThanOrEqual(8);
		expect(highBoost).toBeLessThanOrEqual(15);
		expect(untriedBoost).toBeGreaterThanOrEqual(1);
		expect(untriedBoost).toBeLessThanOrEqual(3);
		expect(pitfallBoost).toBeLessThan(0);
		expect(pitfallBoost).toBeGreaterThanOrEqual(-8);
		expect(unrelatedBoost).toBe(0);
		expect(highBoost).toBeGreaterThan(untriedBoost);
		expect(untriedBoost).toBeGreaterThan(pitfallBoost);

		// 极端样本数边界限幅测试（确保绝不越出 [-8, +15]）
		const db = new Database(dbPath);
		db.query(
			`INSERT INTO experience (tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at)
			 VALUES (?, ?, ?, ?, ?, '', '', ?)`,
		).run("redis", "vuln:auth", "vuln", 5000, 0, "2026-11-24T12:00:00.000Z");
		db.query(
			`INSERT INTO experience (tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at)
			 VALUES (?, ?, ?, ?, ?, '', '', ?)`,
		).run("redis", "surface:uploads", "surface", 0, 5000, "2026-11-24T12:00:00.000Z");
		db.close();

		const maxBoost = computeExperiencePriorityBoost("redis", "vuln:auth", { dbPath });
		const minBoost = computeExperiencePriorityBoost("redis", "surface:uploads", { dbPath });
		expect(maxBoost).toBeGreaterThanOrEqual(10);
		expect(maxBoost).toBeLessThanOrEqual(15);
		expect(minBoost).toBeGreaterThanOrEqual(-8);
		expect(minBoost).toBeLessThanOrEqual(-5);
	});
});

describe("向后兼容 Python nuwa/kb.py 回归测试", () => {
	test("新建便携 kb.db 通过 python3 tests/test_kb.py 全部 5 项测试（含 enrich_cve 与 budget_cap）", () => {
		const dir = makeTmpDir("nuwa-kb-py-compat-");
		const dbPath = join(dir, "kb.db");
		ensureBundledKb(dbPath, { seedDir: KB_DIR });

		const pyRes = spawnSync("python3", [join(REPO_ROOT, "tests", "test_kb.py")], {
			cwd: REPO_ROOT,
			encoding: "utf8",
			env: { ...process.env, NUWA_KB_DB: dbPath },
			timeout: 20_000,
		});
		expect(pyRes.status).toBe(0);
		const combined = `${pyRes.stdout}\n${pyRes.stderr}`;
		expect(combined).toContain("Ran 5 tests");
		expect(combined).not.toContain("skipped");
		expect(combined).toContain("OK");
	});
});

describe("v4.0.1 SQLite DELETE 模式、无伴生文件冷启动与遗留 WAL 库健壮读取回归", () => {
	const DAEMON_BIN_PATH = join(REPO_ROOT, "bin", "nuwa-autonomous");

	function stripWalSidecars(dbPath: string): void {
		rmSync(`${dbPath}-shm`, { force: true });
		rmSync(`${dbPath}-wal`, { force: true });
	}

	test("新建知识库默认为 DELETE 日志模式，强删 -shm/-wal 后全链路冷启动 100% 命中", () => {
		const dir = makeTmpDir("nuwa-kb-delete-mode-");
		const dbPath = join(dir, "kb.db");
		buildKb({ outPath: dbPath, seedDir: KB_DIR });

		// 写入一条脱敏经验并确认关闭后仍为 DELETE 模式
		const mockState = {
			schema: 1,
			version: "4.0.1",
			project: {
				id: "proj-del-1",
				target: "127.0.0.1:18080",
				url: "http://127.0.0.1:18080",
				host: "127.0.0.1",
				port: 18080,
				scheme: "http" as const,
				goal: "audit",
				mode: "pentest" as const,
				phase: "vuln" as const,
				episode: 1,
				status: "completed" as const,
				createdAt: "2026-11-25T00:00:00.000Z",
				updatedAt: "2026-11-25T00:01:00.000Z",
			},
			intents: {
				i001: {
					id: "i001",
					key: "vuln:component",
					phase: "vuln" as const,
					episode: 1,
					priority: 85,
					status: "done" as const,
					brief: "组件审计",
					prompt: "check",
					attempts: 1,
					createdAt: "2026-11-25T00:00:00.000Z",
					doneAt: "2026-11-25T00:01:00.000Z",
					to: "f001",
				},
			},
			facts: {
				f001: {
					id: "f001",
					kind: "vuln" as const,
					key: "vuln:component",
					intent: "i001",
					title: "Spring Boot Actuator 未授权端点暴露",
					detail: "Actuator env endpoint accessible",
					command: "curl -sS http://127.0.0.1:18080/actuator/env",
					output: "HTTP/1.1 200 OK activeProfiles",
					createdAt: "2026-11-25T00:01:00.000Z",
				},
			},
			flags: [],
			runtime: {
				startedAt: 1,
				turns: 2,
				tokens: 100,
				stall: 0,
				idle: 0,
				dispatches: 1,
				commits: 1,
				autoRuns: 0,
				emptyStreak: 0,
				compactions: 0,
				nextIntent: 2,
				nextFact: 2,
			},
		} satisfies NuwaState;

		distillProjectExperience(mockState, { dbPath, seedDir: KB_DIR });
		stripWalSidecars(dbPath);

		const checkModeDb = new Database(dbPath, { readonly: true });
		const modeRow = checkModeDb.query("PRAGMA journal_mode").get() as { journal_mode?: string } | null;
		checkModeDb.close();
		expect(String(modeRow?.journal_mode ?? "").toLowerCase()).toBe("delete");

		stripWalSidecars(dbPath);
		const springHit = kbLookupSafe("spring", "auto", 3, { dbPath, autoInit: false });
		expect(springHit).toContain("Spring");
		expect(springHit).not.toContain("未命中");

		stripWalSidecars(dbPath);
		const stats = getKbStats(dbPath);
		expect(stats.exists).toBe(true);
		expect(stats.cards).toBeGreaterThanOrEqual(36);
		expect(stats.cves).toBeGreaterThanOrEqual(60);
		expect(stats.experiences).toBeGreaterThanOrEqual(1);

		stripWalSidecars(dbPath);
		const boost = computeExperiencePriorityBoost(["spring"], "vuln:component", { dbPath });
		expect(boost).toBeGreaterThan(0);

		stripWalSidecars(dbPath);
		const cliStats = spawnSync(process.execPath, [BUILD_SCRIPT_PATH, "--out", dbPath, "--stats-only"], {
			cwd: REPO_ROOT,
			encoding: "utf8",
			env: { ...process.env, BUN_OPTIONS: undefined },
			timeout: 15_000,
		});
		expect(cliStats.status).toBe(0);
		const parsedStats = JSON.parse(cliStats.stdout.trim());
		expect(parsedStats.cards).toBeGreaterThanOrEqual(36);
		expect(parsedStats.cves).toBeGreaterThanOrEqual(60);

		stripWalSidecars(dbPath);
		const doctorRes = spawnSync(process.execPath, [DAEMON_BIN_PATH, "doctor", "--json", "--agent-home", dir], {
			cwd: REPO_ROOT,
			encoding: "utf8",
			env: { ...process.env, BUN_OPTIONS: undefined, NUWA_KB_DB: dbPath },
			timeout: 15_000,
		});
		const doctorJson = JSON.parse(doctorRes.stdout.trim());
		expect(doctorJson.checks.kb.ok).toBe(true);
		expect(doctorJson.checks.kb.totalRecords).toBeGreaterThan(300);
		expect(doctorJson.checks.kb.counts.card).toBeGreaterThanOrEqual(36);
	});

	test("即使外部遗留库先被设为 WAL 并强删 -shm/-wal，全套只读入口仍健壮命中且 ensureBundledKb 原地转回 DELETE", () => {
		const dir = makeTmpDir("nuwa-kb-legacy-wal-");
		const dbPath = join(dir, "legacy-wal.db");
		buildKb({ outPath: dbPath, seedDir: KB_DIR });

		// 人为把被测库切换为旧版 WAL 模式并写入经验记录，随后强删 -shm / -wal 伴生文件
		const forceWalDb = new Database(dbPath);
		forceWalDb.exec("PRAGMA journal_mode = WAL;");
		forceWalDb
			.query(
				`INSERT INTO experience (tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run("spring", "vuln:component", "vuln", 9, 0, "Actuator 审计有效", "", "2026-11-25T00:00:00.000Z");
		forceWalDb.exec("PRAGMA wal_checkpoint(PASSIVE);");
		forceWalDb.close();
		stripWalSidecars(dbPath);

		// 1) kbLookupSafe 在无 -shm/-wal 的遗留 WAL 库上不抛 SQLITE_CANTOPEN 且正常命中
		const lookupOut = kbLookupSafe("spring", "auto", 3, { dbPath, autoInit: false });
		expect(lookupOut).toContain("Spring");
		expect(lookupOut).toContain("【历史经验提示】");

		// 2) 再次强删 -shm/-wal，验证 getKbStats 正常统计
		stripWalSidecars(dbPath);
		const stats = getKbStats(dbPath);
		expect(stats.cards).toBeGreaterThanOrEqual(36);
		expect(stats.cves).toBeGreaterThanOrEqual(60);
		expect(stats.experiences).toBe(1);

		// 3) 再次强删 -shm/-wal，验证 computeExperiencePriorityBoost 正常提权
		stripWalSidecars(dbPath);
		const boost = computeExperiencePriorityBoost("spring", "vuln:component", { dbPath });
		expect(boost).toBeGreaterThan(0);

		// 4) 再次强删 -shm/-wal，验证 build-kb.ts --stats-only 正常返回统计
		stripWalSidecars(dbPath);
		const cliStats = spawnSync(process.execPath, [BUILD_SCRIPT_PATH, "--out", dbPath, "--stats-only"], {
			cwd: REPO_ROOT,
			encoding: "utf8",
			env: { ...process.env, BUN_OPTIONS: undefined },
			timeout: 15_000,
		});
		expect(cliStats.status).toBe(0);
		expect(JSON.parse(cliStats.stdout.trim()).experiences).toBe(1);

		// 5) 再次强删 -shm/-wal，验证 nuwa-autonomous doctor 正常读取全部表记录数（绝非 0）
		stripWalSidecars(dbPath);
		const doctorRes = spawnSync(process.execPath, [DAEMON_BIN_PATH, "doctor", "--json", "--agent-home", dir], {
			cwd: REPO_ROOT,
			encoding: "utf8",
			env: { ...process.env, BUN_OPTIONS: undefined, NUWA_KB_DB: dbPath },
			timeout: 15_000,
		});
		const doctorJson = JSON.parse(doctorRes.stdout.trim());
		expect(doctorJson.checks.kb.ok).toBe(true);
		expect(doctorJson.checks.kb.totalRecords).toBeGreaterThan(300);
		expect(doctorJson.checks.kb.counts.experience).toBe(1);

		// 6) 调用 ensureBundledKb 后原地无损转回 DELETE 模式，且既有 experience 记录 100% 保留
		stripWalSidecars(dbPath);
		const healed = ensureBundledKb(dbPath, { seedDir: KB_DIR });
		expect(healed.ok).toBe(true);
		expect(healed.stats.experiences).toBe(1);
		stripWalSidecars(dbPath);

		const pureRo = new Database(dbPath, { readonly: true });
		const healedMode = pureRo.query("PRAGMA journal_mode").get() as { journal_mode?: string } | null;
		const expCnt = pureRo.query("SELECT COUNT(*) AS cnt FROM experience WHERE tech_key = 'spring'").get() as {
			cnt?: number;
		} | null;
		pureRo.close();
		expect(String(healedMode?.journal_mode ?? "").toLowerCase()).toBe("delete");
		expect(Number(expCnt?.cnt ?? 0)).toBe(1);
	});
});
