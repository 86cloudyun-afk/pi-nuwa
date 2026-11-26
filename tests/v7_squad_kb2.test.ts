/**
 * 女娲 v7.0 专精特种小队（Specialist Squad）与 KB 2.0 混合语义知识引擎验收测试套件。
 *
 * 覆盖维度：
 * 1. 静态红线约束与 4 个新专精角色模板（nuwa-scout / nuwa-spa-reverser / nuwa-auth-breaker / nuwa-code-auditor）
 *    五项 curl -w 指标、AgentResult JSON + 5 行兼容回执契约及 N-002/N-003/N-007/N-008 红线检验；
 * 2. 专精角色确定性意图分发（classifyIntentForSpecialist）与联动 calibration.ts 的三维战绩白名单联合路由
 *    （recommendSpecialistAndModel，含冷启动回退、高误报降权切换、双盲复验隔离及硬白名单防越界）；
 * 3. kb/seed-v7-pack.json（>= 380 条）+ 既有 v4 种子（140 条）幂等并入 >= 520 条、零重复 ID、全合法字段及保护 experience 表；
 * 4. hybridKbSearch 零外部依赖混合检索（中文口语跨同义词命中英文规范卡片、64-bit SimHash + N-gram + TF-IDF 重排、
 *    防 SQL/FTS5 语法注入及极端输入零除零/零 NaN）；
 * 5. governDistilledExperience 蒸馏经验治理（连续 >= 5 次零产出或高误报自动标记 quarantined 并在搜索中抑制、
 *    高 ROI 卡片晋升 promoted、硬性拦截 self/model/agent 自证记录、以及普通内置种子卡绝对写保护）。
 */
import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { NuwaState } from "../omp/types";
import { buildKb } from "../kb/build-kb";
import { CalibrationError, type CalibrationSettlementSource, type CalibrationTaskCategory } from "../omp/calibration";
import {
	DEFAULT_ALLOWED_SPECIALIST_MODELS,
	NUWA_SPECIALIST_SQUAD,
	SPECIALIST_ROLES,
	classifyIntentForSpecialist,
	recommendSpecialistAndModel,
	type SpecialistCalibrationRecord,
} from "../omp/specialist-squad";
import {
	computeCharNgramDice,
	computeSimHash64,
	expandSecuritySynonyms,
	governDistilledExperience,
	hybridKbSearch,
	ingestV7SeedPack,
	simHashSimilarity,
	upsertDistilledExperienceCard,
	type ExperienceCalibrationRecord,
	type V7SeedItem,
} from "../omp/kb-v2";

const REPO_ROOT = resolve(import.meta.dir, "..");
const AGENTS_DIR = join(REPO_ROOT, "agents");
const KB_DIR = join(REPO_ROOT, "kb");
const PACK_PATH = join(KB_DIR, "seed-v7-pack.json");

const tmpDirs: string[] = [];

function makeTmpDir(prefix = "nuwa-v7-squad-kb2-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(dir);
	return dir;
}

afterEach(() => {
	while (tmpDirs.length > 0) {
		const dir = tmpDirs.pop()!;
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

function createMockState(overrides?: Partial<NuwaState>): NuwaState {
	const ts = "2026-11-26T12:00:00.000Z";
	return {
		schema: 1,
		version: "6.0.0",
		project: {
			id: "proj-v7-squad-test",
			target: "https://app.authorized.example:8443",
			url: "https://app.authorized.example:8443",
			host: "app.authorized.example",
			port: 8443,
			scheme: "https",
			goal: "评估现代全栈应用安全基线",
			mode: "pentest",
			status: "active",
			phase: "surface",
			createdAt: ts,
			updatedAt: ts,
		},
		facts: {},
		intents: {},
		seq: { fact: 0, intent: 0 },
		runtime: {
			startedAt: Date.now(),
			turns: 2,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 4,
			lastToolCalls: 2,
			tokens: 2400,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
		},
		...overrides,
	};
}

function makeSettledRecord(params: {
	id: string;
	intentId?: string;
	taskCategory: CalibrationTaskCategory;
	modelId: string;
	specialistRole?: string;
	outcome: 0 | 1;
	isFalsePositive?: boolean;
	predictedConfidence?: number;
	actualTokens?: number;
	source?: CalibrationSettlementSource | string;
	note?: string;
	experienceId?: string;
}): SpecialistCalibrationRecord & ExperienceCalibrationRecord {
	return {
		predictionId: params.id,
		intentId: params.intentId ?? `intent-${params.id}`,
		taskCategory: params.taskCategory,
		modelId: params.modelId,
		specialistRole: params.specialistRole,
		experienceId: params.experienceId,
		predictedConfidence: params.predictedConfidence ?? (params.outcome === 1 ? 0.82 : 0.35),
		estimatedTokens: 1200,
		createdAt: "2026-11-26T10:00:00.000Z",
		note: params.note,
		settled: true,
		outcome: params.outcome,
		isFalsePositive: params.isFalsePositive ?? false,
		actualTokens: params.actualTokens ?? 1000,
		durationMs: 850,
		source: (params.source ?? "verifier-gate") as CalibrationSettlementSource,
		settledAt: "2026-11-26T10:01:00.000Z",
	};
}

describe("1. 静态红线与 4 个新专精角色模板契约校验", () => {
	test("omp/specialist-squad.ts 与 omp/kb-v2.ts 严格零运行时 import ./nuwa 且无外部依赖", () => {
		for (const rel of ["omp/specialist-squad.ts", "omp/kb-v2.ts"]) {
			const src = readFileSync(join(REPO_ROOT, rel), "utf8");
			expect(src).not.toMatch(/import\s+(?!type\b)[^;\n]*from\s+["']\.\/nuwa["']/);
			expect(src).not.toMatch(/require\s*\(\s*["']\.\/nuwa["']\s*\)/);
			expect(src).not.toMatch(/from\s+["']\.\.\/kb\/build-kb/);
		}
	});

	test("4 个新专精角色模板完整满足五项 curl -w 证据、AgentResult JSON + 5 行回执及安全红线", () => {
		const newRoles = [
			"nuwa-scout",
			"nuwa-spa-reverser",
			"nuwa-auth-breaker",
			"nuwa-code-auditor",
		] as const;

		for (const roleName of newRoles) {
			const mdPath = join(AGENTS_DIR, `${roleName}.md`);
			expect(existsSync(mdPath)).toBe(true);
			const content = readFileSync(mdPath, "utf8");

			// 1) Frontmatter 规范
			expect(content).toMatch(new RegExp(`^---\\nname:\\s*${roleName}\\ndescription:\\s*.+\\n---`, "m"));

			// 2) 合规红线 N-002 / N-003 / N-007 / N-008 及防占位符/防假阳性条款
			expect(content).toContain("N-007");
			expect(content).toContain("N-008");
			expect(content).toContain("N-002");
			expect(content).toContain("N-003");
			expect(content).toContain("NW-04");
			expect(content).toContain("NW-06");
			expect(content).toContain("NW-19");
			expect(content).toContain("NW-31");
			expect(content).toContain("rm -rf");
			expect(content).toContain("DROP TABLE");
			expect(content).toContain("state.json");
			expect(content).toContain("[TARGET]");

			// 3) 强制五项 curl -w 指标 + body_sha256
			expect(content).toContain("%{http_code}");
			expect(content).toContain("%{size_download}");
			expect(content).toContain("%{remote_ip}");
			expect(content).toContain("%{time_total}");
			expect(content).toContain("http_code");
			expect(content).toContain("size_download");
			expect(content).toContain("remote_ip");
			expect(content).toContain("cf_ray");
			expect(content).toContain("server");
			expect(content).toContain("time_total");
			expect(content).toContain("body_sha256");

			// 4) Markdown fenced JSON (AgentResult) + 5 行兼容回执
			const jsonMatch = content.match(/```json\s*\n([\s\S]*?)\n```/);
			expect(jsonMatch).not.toBeNull();
			const parsedJson = JSON.parse(jsonMatch![1]!);
			expect(parsedJson).toHaveProperty("status");
			expect(parsedJson).toHaveProperty("target");
			expect(Array.isArray(parsedJson.evidence)).toBe(true);
			expect(parsedJson.evidence[0]).toHaveProperty("http_code");
			expect(parsedJson.evidence[0]).toHaveProperty("size_download");
			expect(parsedJson.evidence[0]).toHaveProperty("remote_ip");
			expect(parsedJson.evidence[0]).toHaveProperty("cf_ray");
			expect(parsedJson.evidence[0]).toHaveProperty("time_total");
			expect(parsedJson.evidence[0]).toHaveProperty("body_sha256");
			expect(parsedJson).toHaveProperty("blocked");
			expect(parsedJson).toHaveProperty("summary");
			expect(parsedJson).toHaveProperty("next");

			expect(content).toMatch(/^结论:\s*.+$/m);
			expect(content).toMatch(/^证据:\s*.+$/m);
			expect(content).toMatch(/^命令:\s*.+$/m);
			expect(content).toMatch(/^阻断:\s*.+$/m);
			expect(content).toMatch(/^下一步:\s*.+$/m);
		}
	});
});

describe("2. 专精小队精确意图分类与战绩白名单联合路由", () => {
	test("NUWA_SPECIALIST_SQUAD 完整定义 5+1 体系且模板文件全数对齐", () => {
		expect(SPECIALIST_ROLES.length).toBe(6);
		for (const role of SPECIALIST_ROLES) {
			const spec = NUWA_SPECIALIST_SQUAD[role];
			expect(spec).toBeDefined();
			expect(spec.role).toBe(role);
			expect(existsSync(join(REPO_ROOT, spec.agentTemplatePath))).toBe(true);
			expect(spec.specialties.length).toBeGreaterThan(0);
			expect(spec.techStacks.length).toBeGreaterThan(0);
		}
	});

	test("classifyIntentForSpecialist 准确将 6 类典型派单路由至对应专家角色", () => {
		const baseState = createMockState();

		// 1) 侦察测绘与 Soft-404 基线 -> nuwa-scout
		const rScout = classifyIntentForSpecialist(
			{
				key: "recon:baseline-fingerprint",
				phase: "recon",
				title: "采集服务响应指纹、TLS SAN 并标定 Soft-404 负向基线",
				detail: "探测目标端口 Banner 与 CDN/WAF 边缘拦截特征",
			},
			baseState,
		);
		expect(rScout.role).toBe("nuwa-scout");
		expect(rScout.taskCategory).toBe("recon");

		// 2) 前端 Bundle / SourceMap / RSC / 加签逆向 -> nuwa-spa-reverser
		const rSpa = classifyIntentForSpecialist(
			{
				key: "surface:spa-sourcemap-rsc",
				phase: "surface",
				title: "静态拆解 Next.js App Router Chunk、.js.map 与前端 X-Signature 加签拦截器",
				detail: "提取隐藏管理路由及 GraphQL Schema 查询定义",
			},
			baseState,
		);
		expect(rSpa.role).toBe("nuwa-spa-reverser");
		expect(rSpa.taskCategory).toBe("js-audit");

		// 3) 多角色鉴权差分 / IDOR / BOLA / 状态机 -> nuwa-auth-breaker
		const rAuth = classifyIntentForSpecialist(
			{
				key: "vuln:bola-order-diff",
				phase: "vuln",
				authRole: "low_tenant_user",
				title: "多角色会话 AuthDiff 检验订单接口 IDOR/BOLA 水平越权与幂等边界",
				detail: "对比匿名、普通租户与管理员响应差异",
			},
			baseState,
		);
		expect(rAuth.role).toBe("nuwa-auth-breaker");
		expect(rAuth.taskCategory).toBe("auth");

		// 4) 多语言白盒 Source->Sink 代码审计 -> nuwa-code-auditor
		const auditState = createMockState({
			project: { ...baseState.project, mode: "audit" },
		});
		const rAudit = classifyIntentForSpecialist(
			{
				key: "vuln:whitebox-taint-route",
				phase: "vuln",
				title: "白盒审查 FastAPI Depends 路由鉴权矩阵与 Source -> Sink SQL 污点追踪",
				detail: "输出精确 file:line 源码锚点",
			},
			auditState,
		);
		expect(rAudit.role).toBe("nuwa-code-auditor");
		expect(rAudit.taskCategory).toBe("whitebox");

		// 5) 候选漏洞双盲独立复验 -> nuwa-verifier（且不混入其他发现角色作为回退）
		const rVerify = classifyIntentForSpecialist(
			{
				key: "verify-vuln:f12",
				phase: "vuln",
				title: "对 candidate 候选越权漏洞执行双盲独立复验与正负对照实验",
				detail: "逐字节比对 body_sha256 排除微小错误壳假阳性",
			},
			baseState,
		);
		expect(rVerify.role).toBe("nuwa-verifier");
		expect(rVerify.taskCategory).toBe("verify");
		expect(rVerify.fallbackRoles).toEqual([]);

		// 6) 未命中特定专精信号的常规现场探测 -> 通用兜底 fujiang
		const rGeneral = classifyIntentForSpecialist(
			{
				key: "surface:misc-check",
				phase: "surface",
				title: "核对常规公开页面业务提示文本状态",
				detail: "执行单次标准 HTTP 请求并回传摘要",
			},
			baseState,
		);
		expect(rGeneral.role).toBe("fujiang");
		expect(rGeneral.taskCategory).toBe("general");
	});

	test("recommendSpecialistAndModel 联动校准战绩择优、冷启动回退、反自证过滤且 100% 严守 allowedModels 白名单", () => {
		const state = createMockState();
		const authIntent = {
			key: "vuln:jwt-bola-check",
			phase: "vuln" as const,
			title: "检验 JWT 角色声明与 /api/v1/invoices 跨租户 BOLA 越权",
			detail: "执行多角色会话只读比对",
		};

		const strictAllowlist = ["gemini-4-neon-xhigh", "gemini-4-carbon-high"] as const;

		// (a) 冷启动保护：样本不足 5 条时保持基准角色与白名单默认模型，且即使传入越界 defaultModel 亦强制钳制在白名单内
		const coldRes = recommendSpecialistAndModel(authIntent, state, [], {
			allowedModels: strictAllowlist,
			defaultModel: "outside-forbidden-model-v1",
			minSamples: 5,
		});
		expect(coldRes.recommendedRole).toBe("nuwa-auth-breaker");
		expect(strictAllowlist).toContain(coldRes.recommendedModel as any);
		expect(coldRes.coldStart).toBe(true);

		// (b) 模型级战绩切换 + 白名单外高分污染隔离 + 伪造自证过滤：
		//     - neon 在 auth 上连续 6 次高误报低 ROI；
		//     - carbon 在 auth 上连续 6 次真实机械实锤高 ROI；
		//     - 白名单外模型 "outside-super-llm" 塞入 10 条满分记录尝试诱骗越界；
		//     - neon 塞入 10 条 source="self" 伪造满分自证记录尝试洗白误报率。
		const records: SpecialistCalibrationRecord[] = [];
		for (let i = 0; i < 6; i++) {
			records.push(
				makeSettledRecord({
					id: `neon-fp-${i}`,
					taskCategory: "auth",
					modelId: "gemini-4-neon-xhigh",
					specialistRole: "nuwa-auth-breaker",
					outcome: 0,
					isFalsePositive: true,
					predictedConfidence: 0.9,
					actualTokens: 3500,
					source: "verifier-gate",
				}),
			);
			records.push(
				makeSettledRecord({
					id: `carbon-hit-${i}`,
					taskCategory: "auth",
					modelId: "gemini-4-carbon-high",
					specialistRole: "nuwa-auth-breaker",
					outcome: 1,
					isFalsePositive: false,
					predictedConfidence: 0.88,
					actualTokens: 1100,
					source: "verifier-gate",
				}),
			);
		}
		for (let i = 0; i < 10; i++) {
			records.push(
				makeSettledRecord({
					id: `rogue-out-${i}`,
					taskCategory: "auth",
					modelId: "outside-super-llm",
					specialistRole: "nuwa-auth-breaker",
					outcome: 1,
					actualTokens: 200,
					source: "verifier-gate",
				}),
			);
			records.push(
				makeSettledRecord({
					id: `self-cert-cheat-${i}`,
					taskCategory: "auth",
					modelId: "gemini-4-neon-xhigh",
					specialistRole: "nuwa-auth-breaker",
					outcome: 1,
					actualTokens: 100,
					source: "self",
				}),
			);
		}

		const switchedModelRes = recommendSpecialistAndModel(authIntent, state, records, {
			allowedModels: strictAllowlist,
			defaultModel: "gemini-4-neon-xhigh",
			minSamples: 5,
		});
		expect(switchedModelRes.recommendedRole).toBe("nuwa-auth-breaker");
		expect(switchedModelRes.recommendedModel).toBe("gemini-4-carbon-high");
		expect(strictAllowlist).toContain(switchedModelRes.recommendedModel as any);
		expect(switchedModelRes.modelSwitched).toBe(true);
		expect(switchedModelRes.ignoredInvalidRecords).toBe(10);

		// (c) 跨角色退化切换：当 nuwa-spa-reverser 在全部白名单模型上连续零产出退化，而 fujiang 战绩优异时自动回退切换
		const degradedRoleRecords: SpecialistCalibrationRecord[] = [];
		for (const m of DEFAULT_ALLOWED_SPECIALIST_MODELS) {
			for (let i = 0; i < 6; i++) {
				degradedRoleRecords.push(
					makeSettledRecord({
						id: `spa-zero-${m}-${i}`,
						taskCategory: "js-audit",
						modelId: m,
						specialistRole: "nuwa-spa-reverser",
						outcome: 0,
						isFalsePositive: true,
						predictedConfidence: 0.85,
						actualTokens: 4000,
						source: "exec-ledger",
					}),
				);
			}
		}
		for (let i = 0; i < 6; i++) {
			degradedRoleRecords.push(
				makeSettledRecord({
					id: `fujiang-rescue-${i}`,
					taskCategory: "js-audit",
					modelId: "gemini-4-neon-xhigh",
					specialistRole: "fujiang",
					outcome: 1,
					isFalsePositive: false,
					predictedConfidence: 0.85,
					actualTokens: 900,
					source: "verifier-gate",
				}),
			);
		}

		const roleSwitchRes = recommendSpecialistAndModel(
			{
				key: "surface:spa-bundle-check",
				title: "拉取前端 webpack chunk 梳理接口",
				detail: "检查静态构建清单",
			},
			state,
			degradedRoleRecords,
			{ allowedModels: DEFAULT_ALLOWED_SPECIALIST_MODELS, minSamples: 5 },
		);
		expect(roleSwitchRes.recommendedRole).toBe("fujiang");
		expect(roleSwitchRes.roleSwitched).toBe(true);
		expect(DEFAULT_ALLOWED_SPECIALIST_MODELS).toContain(roleSwitchRes.recommendedModel);

		// (d) 空 allowedModels 显式抛出 CalibrationError
		expect(() =>
			recommendSpecialistAndModel(authIntent, state, [], {
				allowedModels: [],
			}),
		).toThrow(CalibrationError);
	});
});

describe("3. kb/seed-v7-pack.json 种子资产门禁与 ingestV7SeedPack 幂等并入 (>= 520 条)", () => {
	test("seed-v7-pack.json >= 380 条、无重复 ID、无空字段、覆盖全栈核心领域且零武器化载荷", () => {
		expect(existsSync(PACK_PATH)).toBe(true);
		const rawText = readFileSync(PACK_PATH, "utf8");
		expect(rawText).not.toMatch(/rm\s+-rf\s+\//i);
		expect(rawText).not.toMatch(/\$\{jndi:/i);
		expect(rawText).not.toMatch(/\/dev\/tcp\//i);
		expect(rawText).not.toMatch(/mkfs\./i);
		expect(rawText).not.toMatch(/dd\s+if=/i);

		const pack = JSON.parse(rawText) as V7SeedItem[];
		expect(pack.length).toBeGreaterThanOrEqual(380);

		const ids = new Set<string>();
		const titles = new Set<string>();
		const techs = new Set<string>();

		for (const item of pack) {
			expect(item.id.trim().length).toBeGreaterThan(2);
			expect(ids.has(item.id.toLowerCase())).toBe(false);
			ids.add(item.id.toLowerCase());

			expect(item.title.trim().length).toBeGreaterThan(4);
			expect(titles.has(item.title.trim())).toBe(false);
			titles.add(item.title.trim());

			expect(["card", "cve", "technique", "checklist"]).toContain(item.kind);
			expect(item.tech.trim().length).toBeGreaterThan(0);
			expect(item.summary.trim().length).toBeGreaterThan(10);
			expect(item.tags.trim().length).toBeGreaterThan(2);
			expect(item.payload_or_check.trim().length).toBeGreaterThan(20);
			expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(item.severity);
			expect(item.ref.trim().length).toBeGreaterThan(2);
			techs.add(item.tech);
		}

		// 验证关键现代全栈领域覆盖
		for (const expectedTech of [
			"nextjs",
			"fastapi",
			"django",
			"spring-boot",
			"gin",
			"echo",
			"graphql",
			"oauth2",
			"jwt",
			"reverse-proxy",
			"concurrency",
			"cloud",
			"frontend-signing",
		]) {
			expect(techs.has(expectedTech)).toBe(true);
		}
	});

	test("buildKb + ingestV7SeedPack 合并建库总记录 >= 520 条，重复执行完全幂等且绝不清空 experience 表", () => {
		const dir = makeTmpDir("nuwa-v7-kb-ingest-");
		const dbPath = join(dir, "kb.db");

		// 先按 v4 buildKb 建基础 140 条库并写入 1 条历史蒸馏经验
		const v4Stats = buildKb({ outPath: dbPath, seedDir: KB_DIR, includeV7SeedPack: false });
		expect(v4Stats.cards + v4Stats.cves + v4Stats.techniques).toBe(140);

		const initDb = new Database(dbPath);
		initDb
			.query(
				`INSERT INTO experience (tech_key, intent_key, phase, success_count, fail_count, helpful_pattern, pitfall_note, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				"nextjs",
				"surface:rsc-actions",
				"surface",
				5,
				1,
				"核查 use server 导出动作内部会话断言",
				"排除静态页面外壳假阳性",
				"2026-11-26T09:00:00.000Z",
			);
		initDb.close();

		// 第一次并入 v7 种子包
		const ingest1 = ingestV7SeedPack(dbPath, PACK_PATH, { seedDir: KB_DIR });
		expect(ingest1.ok).toBe(true);
		expect(ingest1.packCount).toBeGreaterThanOrEqual(380);
		expect(ingest1.totalKbItems).toBeGreaterThanOrEqual(520);
		expect(ingest1.cards + ingest1.cves + ingest1.techniques).toBeGreaterThanOrEqual(520);
		expect(ingest1.experiences).toBe(1);

		// 第二次、第三次重复执行幂等校验：总条目数严格不变，experience 记录完好无损
		const ingest2 = ingestV7SeedPack(dbPath, PACK_PATH, { seedDir: KB_DIR });
		expect(ingest2.totalKbItems).toBe(ingest1.totalKbItems);
		expect(ingest2.experiences).toBe(1);

		// 验证直接传入内存 Database 实例同样支持且不会误关连接
		const memDb = new Database(":memory:");
		try {
			const memRes = ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });
			expect(memRes.totalKbItems).toBeGreaterThanOrEqual(520);
			const rowCount = (memDb.query("SELECT COUNT(*) AS c FROM kb_items").get() as { c: number }).c;
			expect(rowCount).toBe(memRes.totalKbItems);
		} finally {
			memDb.close();
		}
	});
});

describe("4. hybridKbSearch 中文口语跨同义词混合重排与数学无 NaN 边界测试", () => {
	test("中文口语描述跨同义词精准召回英文规范卡片且混合重排相关性显著优于纯字面查询", () => {
		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			// 场景 A：纯口语“改订单号偷看别人数据”（字面完全不含 IDOR / BOLA）
			const synA = expandSecuritySynonyms("普通用户改订单号偷看别人数据的水平越权怎么核查");
			expect(synA.expandedTerms).toContain("idor");
			expect(synA.expandedTerms).toContain("bola");

			const hitsIdor = hybridKbSearch(memDb, "普通用户改订单号偷看别人数据的水平越权怎么核查", { limit: 5 });
			expect(hitsIdor.length).toBeGreaterThan(0);
			const topIdorBlob = hitsIdor
				.slice(0, 3)
				.map((h) => `${h.id} ${h.title} ${h.tags}`)
				.join(" ")
				.toLowerCase();
			expect(topIdorBlob).toMatch(/idor|bola|越权/);

			// 对照纯字面 FTS（不经同义扩展直接匹配“偷看别人”字面在规范库中为 0 条），验证混合引擎跨语义召回优势
			const literalOnlyCount = (
				memDb
					.query("SELECT COUNT(*) AS c FROM kb_items WHERE title LIKE '%偷看别人%' OR summary LIKE '%偷看别人%'")
					.get() as { c: number }
			).c;
			expect(literalOnlyCount).toBe(0);
			expect(hitsIdor.length).toBeGreaterThan(literalOnlyCount);

			// 场景 B：口语“前端打包文件映射还原隐藏路由和接口请求签名防重放” -> 命中 SourceMap / 前端加签卡片
			const hitsSpa = hybridKbSearch(memDb, "前端打包文件映射还原隐藏路由和请求加签时间戳重放", { limit: 6 });
			expect(hitsSpa.length).toBeGreaterThan(0);
			const topSpaBlob = hitsSpa
				.map((h) => `${h.id} ${h.tech} ${h.tags} ${h.title}`)
				.join(" ")
				.toLowerCase();
			expect(topSpaBlob).toMatch(/sourcemap|frontend-signing|x-signature|bundle|chunk/);

			// 场景 C：口语“领券薅羊毛一券多用和重复提交双花” -> 命中 concurrency / TOCTOU / Idempotency-Key
			const hitsRace = hybridKbSearch(memDb, "领券薅羊毛一券多用重复提交双花", { limit: 5 });
			expect(hitsRace.length).toBeGreaterThan(0);
			expect(hitsRace[0]!.tech).toBe("concurrency");

			// 场景 D：口语“反向代理斜杠目录穿越绕过网关” -> 命中 Nginx alias / 路径规范化卡片
			const hitsProxy = hybridKbSearch(memDb, "反向代理斜杠目录穿越绕过网关", { limit: 5 });
			expect(hitsProxy.length).toBeGreaterThan(0);
			const topProxyBlob = hitsProxy
				.slice(0, 3)
				.map((h) => `${h.id} ${h.tech} ${h.tags}`)
				.join(" ")
				.toLowerCase();
			expect(topProxyBlob).toMatch(/reverse-proxy|nginx|alias|path-normalization/);
		} finally {
			memDb.close();
		}
	});

	test("SimHash / N-gram / TF-IDF 在空串、SQL/FTS5 注入与极端符号输入下严格零报错、零除零、零 NaN", () => {
		expect(computeSimHash64("")).toBe("0000000000000000");
		expect(simHashSimilarity("0000000000000000", "0000000000000000")).toBe(0);
		expect(simHashSimilarity("not-hex", "1234")).toBe(0);
		const sh1 = computeSimHash64("Next.js Server Actions 独立服务端鉴权核查");
		const sh2 = computeSimHash64("Next.js Server Actions 服务端鉴权边界核查");
		expect(simHashSimilarity(sh1, sh1)).toBe(1);
		expect(simHashSimilarity(sh1, sh2)).toBeGreaterThan(0.65);
		expect(computeCharNgramDice("", "abc")).toBe(0);
		expect(computeCharNgramDice("   ", "   ")).toBe(0);

		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			const adversarialQueries = [
				"",
				"     ",
				"!@#$%^&*()_+-=[]{};':\",./<>?",
				"'); DROP TABLE kb_items; --",
				'" OR NOT NEAR(a b, 5) AND * ^',
				"1234567890",
				"Next.js RSC auth",
			];

			for (const q of adversarialQueries) {
				const hits = hybridKbSearch(memDb, q, { limit: 8 });
				for (const h of hits) {
					for (const num of [
						h.score,
						h.ftsScore,
						h.tfidfCosine,
						h.ngramOverlap,
						h.simhashSimilarity,
						h.synonymBoost,
						h.statusMultiplier,
					]) {
						expect(Number.isFinite(num)).toBe(true);
						expect(Number.isNaN(num)).toBe(false);
					}
				}
			}

			// 确保表未被注入语句破坏
			const intactCount = (memDb.query("SELECT COUNT(*) AS c FROM kb_items").get() as { c: number }).c;
			expect(intactCount).toBeGreaterThanOrEqual(520);
		} finally {
			memDb.close();
		}
	});
});

describe("5. governDistilledExperience 连续 5 次零产出自动冻结、反自证拦截与普通种子卡保护", () => {
	test("连续 >= 5 次零产出经验自动标记 quarantined 并在搜索中抑制，高 ROI 经验晋升 promoted，拒绝自证且保护内置种子卡", () => {
		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			// 注册两张跨项目蒸馏经验卡（并验证自动脱敏）
			const cardStale = upsertDistilledExperienceCard(memDb, {
				id: "exp:graphql:stale-alias-probe",
				tech: "graphql",
				intentKey: "vuln:graphql-stale-probe",
				phase: "vuln",
				title: "GraphQL 历史低效猜测探针经验",
				summary: "曾对 https://secret.corp.internal:8443/graphql 使用 Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb 探测",
				payload_or_check: "尝试固定旧路径枚举 GraphQL 调试接口",
			});
			expect(cardStale.summary).not.toContain("secret.corp.internal");
			expect(cardStale.summary).not.toContain("eyJhbGciOiJIUzI1NiJ9");
			expect(cardStale.status).toBe("active");

			const cardHighRoi = upsertDistilledExperienceCard(memDb, {
				id: "exp:nextjs:high-yield-action-check",
				tech: "nextjs",
				intentKey: "vuln:nextjs-action-auth",
				phase: "vuln",
				title: "Next.js Server Actions 鉴权缺失高命中蒸馏打法",
				summary: "针对 App Router Server Actions 导出动作执行匿名与低权只读对照，命中率极高",
				payload_or_check: "优先梳理 use server 动作标识并核验服务端独立会话断言",
			});
			expect(cardHighRoi.status).toBe("active");

			const govRecords: ExperienceCalibrationRecord[] = [];

			// 1) 连续 5 次机械结算零产出 -> 触发 cardStale 自动冻结为 quarantined
			for (let i = 0; i < 5; i++) {
				govRecords.push(
					makeSettledRecord({
						id: `stale-miss-${i}`,
						intentId: "vuln:graphql-stale-probe",
						experienceId: "exp:graphql:stale-alias-probe",
						taskCategory: "js-audit",
						modelId: "gemini-4-neon-xhigh",
						outcome: 0,
						isFalsePositive: false,
						predictedConfidence: 0.6,
						actualTokens: 2200,
						source: "verifier-gate",
					}),
				);
			}

			// 2) 为 cardStale 伪造 8 条 source="self" / "agent" 的满分命中记录试图阻止冻结（必须被全部拦截拒绝！）
			for (let i = 0; i < 8; i++) {
				govRecords.push(
					makeSettledRecord({
						id: `stale-fake-self-${i}`,
						experienceId: "exp:graphql:stale-alias-probe",
						taskCategory: "js-audit",
						modelId: "gemini-4-neon-xhigh",
						outcome: 1,
						actualTokens: 100,
						source: i % 2 === 0 ? "self" : "agent",
					}),
				);
			}

			// 3) 为 cardHighRoi 提供 4 条真实 verifier-gate 实锤命中记录 -> 触发晋升 promoted
			for (let i = 0; i < 4; i++) {
				govRecords.push(
					makeSettledRecord({
						id: `highroi-hit-${i}`,
						intentId: "vuln:nextjs-action-auth",
						experienceId: "exp:nextjs:high-yield-action-check",
						taskCategory: "auth",
						modelId: "gemini-4-neon-xhigh",
						outcome: 1,
						isFalsePositive: false,
						predictedConfidence: 0.85,
						actualTokens: 800,
						source: "verifier-gate",
					}),
				);
			}

			// 4) 恶意/误配尝试：构造 6 条指向内置普通种子卡 "v7-nextjs-rsc-action-auth-001" 与 "nginx:nginx" 的零产出高误报记录 -> 必须被保护跳过！
			for (let i = 0; i < 6; i++) {
				govRecords.push(
					makeSettledRecord({
						id: `seed-attack-${i}`,
						intentId: i < 3 ? "v7-nextjs-rsc-action-auth-001" : "nginx:nginx",
						cardId: i < 3 ? "v7-nextjs-rsc-action-auth-001" : "nginx:nginx",
						taskCategory: "recon",
						modelId: "gemini-4-neon-xhigh",
						outcome: 0,
						isFalsePositive: true,
						actualTokens: 5000,
						source: "verifier-gate",
					}),
				);
			}

			const govRes = governDistilledExperience(memDb, govRecords);
			expect(govRes.ok).toBe(true);
			expect(govRes.rejectedSelfCertCount).toBe(8);
			expect(govRes.protectedSeedSkips).toBe(6);
			expect(govRes.quarantinedIds).toContain("exp:graphql:stale-alias-probe");
			expect(govRes.promotedIds).toContain("exp:nextjs:high-yield-action-check");
			expect(govRes.details["exp:graphql:stale-alias-probe"]?.consecutiveZeroYield).toBe(5);
			expect(govRes.details["exp:graphql:stale-alias-probe"]?.newStatus).toBe("quarantined");
			expect(govRes.details["exp:nextjs:high-yield-action-check"]?.newStatus).toBe("promoted");

			// 验证内置普通种子卡 100% 完好保持 active，绝未误伤
			const seedStatus1 = (
				memDb.query("SELECT status FROM kb_items WHERE id = ?").get("v7-nextjs-rsc-action-auth-001") as {
					status: string;
				}
			).status;
			const seedStatus2 = (
				memDb.query("SELECT status FROM kb_items WHERE id = ?").get("nginx:nginx") as { status: string }
			).status;
			expect(seedStatus1).toBe("active");
			expect(seedStatus2).toBe("active");

			// 验证 hybridKbSearch 默认自动抑制 quarantined 卡片，而 promoted 卡片正常赋予 1.25 倍提权
			const gqlSearchDefault = hybridKbSearch(memDb, "GraphQL 历史低效猜测探针经验", { limit: 20 });
			expect(gqlSearchDefault.some((h) => h.id === "exp:graphql:stale-alias-probe")).toBe(false);

			const gqlSearchDiag = hybridKbSearch(memDb, "GraphQL 历史低效猜测探针经验 stale-alias-probe", {
				limit: 50,
				includeQuarantined: true,
			});
			const quarantinedHit = gqlSearchDiag.find((h) => h.id === "exp:graphql:stale-alias-probe");
			expect(quarantinedHit).toBeDefined();
			expect(quarantinedHit!.statusMultiplier).toBe(0.25);

			const promotedSearch = hybridKbSearch(memDb, "Next.js Server Actions 鉴权缺失高命中蒸馏打法", { limit: 5 });
			const promotedHit = promotedSearch.find((h) => h.id === "exp:nextjs:high-yield-action-check");
			expect(promotedHit).toBeDefined();
			expect(promotedHit!.status).toBe("promoted");
			expect(promotedHit!.statusMultiplier).toBeGreaterThan(1.1);

			// 验证开启 throwOnSelfCert: true 时遇到自证来源直接抛 CalibrationError
			expect(() =>
				governDistilledExperience(
					memDb,
					[
						makeSettledRecord({
							id: "strict-self-err",
							experienceId: "exp:nextjs:high-yield-action-check",
							taskCategory: "auth",
							modelId: "gemini-4-neon-xhigh",
							outcome: 1,
							source: "model",
						}),
					],
					{ throwOnSelfCert: true },
				),
			).toThrow(CalibrationError);

			// 验证 allowRevoke: false 时锁定已晋升状态不被回退
			const noRevokeRes = governDistilledExperience(
				memDb,
				[
					...Array.from({ length: 5 }, (_, idx) =>
						makeSettledRecord({
							id: `norevoke-miss-${idx}`,
							experienceId: "exp:nextjs:high-yield-action-check",
							taskCategory: "auth",
							modelId: "gemini-4-neon-xhigh",
							outcome: 0,
							source: "verifier-gate",
						}),
					),
				],
				{ allowRevoke: false },
			);
			expect(noRevokeRes.allowRevoke).toBe(false);
			expect(noRevokeRes.promotedIds).toContain("exp:nextjs:high-yield-action-check");
		} finally {
			memDb.close();
		}
	});
});

describe("6. Boost 异构深度审查 6 项 P1 边界反例回归测试", () => {
	test("P1-1: governDistilledExperience 按 settledAt/createdAt 稳定升序排列，倒序/乱序输入绝不误冻结最新已回暖卡片且准确冻结最新连败卡片", () => {
		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			upsertDistilledExperienceCard(memDb, {
				id: "exp:order:time-recovered",
				tech: "nextjs",
				intentKey: "vuln:time-recovered",
				title: "早期 5 连败但最新实锤回暖经验卡",
				summary: "验证倒序传入记录时按真实时间戳升序计算尾部连败为 0",
				payload_or_check: "检查最新实锤恢复后不应被误冻结",
			});
			upsertDistilledExperienceCard(memDb, {
				id: "exp:order:time-degraded",
				tech: "nextjs",
				intentKey: "vuln:time-degraded",
				title: "最早 1 次命中但最近连续 5 次零产出退化经验卡",
				summary: "验证最早命中排在数组末尾时仍按真实时间戳识别最新 5 连败冻结",
				payload_or_check: "检查最近连续 5 次零产出必须被冻结",
			});

			// 倒序传入：数组第 0 项是最新的 t6 (10:06:30) 命中，后面跟着早期的 t5..t1 零产出
			const reversedRecovered: ExperienceCalibrationRecord[] = [
				{
					...makeSettledRecord({
						id: "rec-t6-hit",
						experienceId: "exp:order:time-recovered",
						taskCategory: "auth",
						modelId: "gemini-4-neon-xhigh",
						outcome: 1,
						source: "verifier-gate",
					}),
					createdAt: "2026-11-26T10:06:00.000Z",
					settledAt: "2026-11-26T10:06:30.000Z",
				},
				...[5, 4, 3, 2, 1].map((n) => ({
					...makeSettledRecord({
						id: `rec-t${n}-miss`,
						experienceId: "exp:order:time-recovered",
						taskCategory: "auth",
						modelId: "gemini-4-neon-xhigh",
						outcome: 0,
						source: "verifier-gate",
					}),
					createdAt: `2026-11-26T10:0${n}:00.000Z`,
					settledAt: `2026-11-26T10:0${n}:30.000Z`,
				})),
			];

			// 乱序传入：最近 t2..t6 连续 5 次零产出在前，最早 t1 (10:01:30) 命中放在数组最末尾
			const shuffledDegraded: ExperienceCalibrationRecord[] = [
				...[6, 5, 4, 3, 2].map((n) => ({
					...makeSettledRecord({
						id: `deg-t${n}-miss`,
						experienceId: "exp:order:time-degraded",
						taskCategory: "auth",
						modelId: "gemini-4-neon-xhigh",
						outcome: 0,
						source: "verifier-gate",
					}),
					createdAt: `2026-11-26T10:0${n}:00.000Z`,
					settledAt: `2026-11-26T10:0${n}:30.000Z`,
				})),
				{
					...makeSettledRecord({
						id: "deg-t1-hit",
						experienceId: "exp:order:time-degraded",
						taskCategory: "auth",
						modelId: "gemini-4-neon-xhigh",
						outcome: 1,
						source: "verifier-gate",
					}),
					createdAt: "2026-11-26T10:01:00.000Z",
					settledAt: "2026-11-26T10:01:30.000Z",
				},
			];

			const res = governDistilledExperience(memDb, [...reversedRecovered, ...shuffledDegraded]);
			expect(res.details["exp:order:time-recovered"]?.consecutiveZeroYield).toBe(0);
			expect(res.details["exp:order:time-recovered"]?.newStatus).not.toBe("quarantined");
			expect(res.quarantinedIds).not.toContain("exp:order:time-recovered");

			expect(res.details["exp:order:time-degraded"]?.consecutiveZeroYield).toBe(5);
			expect(res.details["exp:order:time-degraded"]?.newStatus).toBe("quarantined");
			expect(res.quarantinedIds).toContain("exp:order:time-degraded");
		} finally {
			memDb.close();
		}
	});

	test("P1-2: 经验卡归因严格校验完整 ID 边界（杜绝短前缀跨卡误杀）且 note 顺带提及种子卡绝不遮蔽 intentId 绑定的真实蒸馏卡", () => {
		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			upsertDistilledExperienceCard(memDb, {
				id: "exp:nextjs:auth",
				tech: "nextjs",
				intentKey: "vuln:short-auth",
				title: "短前缀无辜经验卡",
				summary: "0 派单记录，绝不可被 auth-bypass 子串误命中",
				payload_or_check: "检查短前缀隔离",
			});
			upsertDistilledExperienceCard(memDb, {
				id: "exp:nextjs:auth-bypass",
				tech: "nextjs",
				intentKey: "vuln:long-auth-bypass",
				title: "长后缀连续零产出经验卡",
				summary: "真实连续 5 次零产出的目标卡",
				payload_or_check: "检查精确命中长 ID",
			});
			upsertDistilledExperienceCard(memDb, {
				id: "exp:spring:actuator-check",
				tech: "spring-boot",
				intentKey: "vuln:spring-act-check",
				title: "通过 intentId 关联但 note 顺带提及 T1190 的经验卡",
				summary: "验证种子 ID T1190 不会提前截断遮蔽 intentId 反向索引",
				payload_or_check: "检查 intentId 正常归因冻结",
			});

			const recs: ExperienceCalibrationRecord[] = [];
			for (let i = 0; i < 5; i++) {
				recs.push(
					makeSettledRecord({
						id: `prefix-test-${i}`,
						intentId: `other-intent-${i}`,
						note: "tested exp:nextjs:auth-bypass zero yield",
						taskCategory: "auth",
						modelId: "gemini-4-neon-xhigh",
						outcome: 0,
						source: "verifier-gate",
					}),
				);
				recs.push(
					makeSettledRecord({
						id: `shadow-test-${i}`,
						intentId: "vuln:spring-act-check",
						note: "related to MITRE T1190 probe zero yield",
						taskCategory: "recon",
						modelId: "gemini-4-neon-xhigh",
						outcome: 0,
						source: "verifier-gate",
					}),
				);
			}

			const res = governDistilledExperience(memDb, recs);
			// 无辜短前缀卡 exp:nextjs:auth 必须毫发无损维持 active
			expect(res.quarantinedIds).not.toContain("exp:nextjs:auth");
			expect(res.activeIds).toContain("exp:nextjs:auth");
			expect(res.details["exp:nextjs:auth"]).toBeUndefined();

			// 真实目标卡与被 note 提及 T1190 的卡均须准确记账冻结
			expect(res.quarantinedIds).toContain("exp:nextjs:auth-bypass");
			expect(res.quarantinedIds).toContain("exp:spring:actuator-check");
			expect(res.details["exp:spring:actuator-check"]?.consecutiveZeroYield).toBe(5);
		} finally {
			memDb.close();
		}
	});

	test("P1-3: 拒绝 predictedConfidence=NaN / 负数 actualTokens 脏记录，且 kind='experience' 外部导入源与 SQL 更新条件严格一致", () => {
		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			// 直接写入一条 source='imported-exp', kind='experience' 的外部导入蒸馏经验卡
			memDb
				.query(`
					INSERT INTO kb_items (
						id, kind, tech, title, summary, tags, payload_or_check, severity, ref,
						source, status, simhash, updated_at
					) VALUES (
						'exp:custom:imported-card', 'experience', 'cloud', '外部导入经验卡', '验证非 distilled 字面量源同步写库',
						'cloud,intent:vuln:imported-exp', '核查写库一致性', 'MEDIUM', 'imported',
						'imported-exp', 'active', '1122334455667788', '2026-11-26T10:00:00.000Z'
					)
				`)
				.run();

			// 先传入 5 条含 NaN 置信度与负 Token 的脏记录 -> 必须全部归入 ignoredUnsettledOrInvalidCount，accepted=0
			const dirtyRecs: ExperienceCalibrationRecord[] = Array.from({ length: 5 }, (_, i) => ({
				...makeSettledRecord({
					id: `dirty-nan-${i}`,
					experienceId: "exp:custom:imported-card",
					taskCategory: "recon",
					modelId: "gemini-4-neon-xhigh",
					outcome: 1,
					source: "verifier-gate",
				}),
				predictedConfidence: Number.NaN,
				actualTokens: -500,
			}));

			const dirtyRes = governDistilledExperience(memDb, dirtyRecs);
			expect(dirtyRes.acceptedMechanicalRecords).toBe(0);
			expect(dirtyRes.ignoredUnsettledOrInvalidCount).toBe(5);

			// 再传入 5 条合法连续零产出记录 -> 数据库实际行状态与 quarantinedIds 必须同步变为 quarantined
			const validMissRecs: ExperienceCalibrationRecord[] = Array.from({ length: 5 }, (_, i) =>
				makeSettledRecord({
					id: `imported-miss-${i}`,
					experienceId: "exp:custom:imported-card",
					taskCategory: "recon",
					modelId: "gemini-4-neon-xhigh",
					outcome: 0,
					source: "verifier-gate",
				}),
			);

			const govRes = governDistilledExperience(memDb, validMissRecs);
			expect(govRes.quarantinedIds).toContain("exp:custom:imported-card");
			const dbRow = memDb
				.query("SELECT status, consecutive_zero_yield FROM kb_items WHERE id = ?")
				.get("exp:custom:imported-card") as { status: string; consecutive_zero_yield: number };
			expect(dbRow.status).toBe("quarantined");
			expect(dbRow.consecutive_zero_yield).toBe(5);
		} finally {
			memDb.close();
		}
	});

	test("P1-4: hybridKbSearch 将 kind 与 tech 下推至全部 SQL WHERE 子句并覆盖 payload_or_check，绝不被大池挤出漏召回", () => {
		const memDb = new Database(":memory:");
		try {
			ingestV7SeedPack(memDb, PACK_PATH, { seedDir: KB_DIR });

			upsertDistilledExperienceCard(memDb, {
				id: "exp:cloud:hecha-check",
				tech: "cloud",
				intentKey: "vuln:cloud-hecha",
				title: "云配置专项核查经验卡",
				summary: "针对云存储与元数据的核查经验",
				payload_or_check: "执行只读配置核查与独有标记 UNIQUE_BODY_ONLY_MARKER_9921 验证",
			});

			// 即使全库有数百条种子卡含高频词“核查”，指定 kind="experience" 下推 SQL 后仍 100% 召回该经验卡
			const expHits = hybridKbSearch(memDb, "核查", { kind: "experience", limit: 5 });
			expect(expHits.length).toBeGreaterThan(0);
			expect(expHits.some((h) => h.id === "exp:cloud:hecha-check")).toBe(true);

			// 仅出现在 payload_or_check 正文的独有词同样在 LIKE 补充层准确召回
			const bodyOnlyHits = hybridKbSearch(memDb, "UNIQUE_BODY_ONLY_MARKER_9921", { limit: 5 });
			expect(bodyOnlyHits.some((h) => h.id === "exp:cloud:hecha-check")).toBe(true);

			// 指定 tech="cloud" 检索宽泛中文词“安全 配置 校验”可充分召回满额 cloud 卡片（不被前序非 cloud 卡截断）
			const cloudHits = hybridKbSearch(memDb, "安全 配置 校验", { tech: "cloud", limit: 10 });
			expect(cloudHits.length).toBe(10);
			expect(cloudHits.every((h) => h.tech === "cloud")).toBe(true);
		} finally {
			memDb.close();
		}
	});

	test("P1-5 & P1-6: recommendSpecialistAndModel 隔离跨角色失败污染、candidate 正负对照 100% 锁定 nuwa-verifier、且非法 allowedRoles 显式抛错", () => {
		const state = createMockState();

		// P1-5 反例复验：nuwa-auth-breaker 在 neon 有 6 次失败，在 carbon 有 0 次记录；
		// 其他角色 fujiang 在 carbon (同 category="auth") 有 6 次失败 -> 绝不能污染 nuwa-auth-breaker × carbon！
		const crossRoleRecs: SpecialistCalibrationRecord[] = [];
		for (let i = 0; i < 6; i++) {
			crossRoleRecs.push(
				makeSettledRecord({
					id: `auth-neon-fail-${i}`,
					taskCategory: "auth",
					modelId: "gemini-4-neon-xhigh",
					specialistRole: "nuwa-auth-breaker",
					outcome: 0,
					isFalsePositive: true,
					predictedConfidence: 0.9,
					actualTokens: 3000,
					source: "verifier-gate",
				}),
			);
			crossRoleRecs.push(
				makeSettledRecord({
					id: `fujiang-carbon-fail-${i}`,
					taskCategory: "auth",
					modelId: "gemini-4-carbon-high",
					specialistRole: "fujiang",
					outcome: 0,
					isFalsePositive: true,
					predictedConfidence: 0.9,
					actualTokens: 3000,
					source: "verifier-gate",
				}),
			);
		}

		const isolatedRes = recommendSpecialistAndModel(
			{
				key: "vuln:check-bola",
				phase: "vuln",
				title: "多角色会话差分核验订单 BOLA 越权",
				detail: "对比低权与高权响应",
			},
			state,
			crossRoleRecs,
			{
				allowedModels: ["gemini-4-neon-xhigh", "gemini-4-carbon-high"],
				defaultModel: "gemini-4-neon-xhigh",
				minSamples: 5,
			},
		);

		const authCarbonCand = isolatedRes.candidates.find(
			(c) => c.role === "nuwa-auth-breaker" && c.modelId === "gemini-4-carbon-high",
		);
		expect(authCarbonCand).toBeDefined();
		expect(authCarbonCand!.settledCount).toBe(0);
		expect(authCarbonCand!.coldStart).toBe(true);
		expect(authCarbonCand!.demoted).toBe(false);
		expect(isolatedRes.recommendedRole).toBe("nuwa-auth-breaker");
		expect(isolatedRes.recommendedModel).toBe("gemini-4-carbon-high");

		// P1-6a 反例复验：不含 verify- 前缀但标题要求对 candidate 候选发现做正负对照复验裁定（即使详情含 BOLA 越权）-> 100% 锁定 nuwa-verifier
		const verifyClass = classifyIntentForSpecialist(
			{
				key: "vuln:check-f12",
				phase: "vuln",
				title: "对 candidate 候选发现做正负对照复验裁定",
				detail: "核查订单接口 BOLA 越权",
			},
			state,
		);
		expect(verifyClass.role).toBe("nuwa-verifier");
		expect(verifyClass.taskCategory).toBe("verify");
		expect(verifyClass.fallbackRoles).toEqual([]);

		// P1-6b 反例复验：显式传入空或全非法 allowedRoles 必须抛出 CalibrationError("INVALID_INPUT")，严禁静默放开全角色
		expect(() =>
			recommendSpecialistAndModel({ key: "vuln:check-bola", title: "BOLA 越权" }, state, [], {
				allowedRoles: ["nonexistent-role" as any],
			}),
		).toThrow(CalibrationError);

		expect(() =>
			recommendSpecialistAndModel({ key: "vuln:check-bola", title: "BOLA 越权" }, state, [], {
				allowedRoles: [],
			}),
		).toThrow(CalibrationError);
	});
});
