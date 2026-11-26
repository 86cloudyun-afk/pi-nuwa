/**
 * 女娲 v6.0.0 SQLite WAL 权威状态存储引擎与自主闭环（AuthDiff / OOB）全覆盖单元测试。
 */
import { afterEach, describe, expect, test } from "bun:test";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import * as http from "node:http";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	NuwaSqliteCorruptError,
	NuwaSqliteStore,
	appendJournalSqlite,
	exportStateJsonCompat,
	loadStateFromSqlite,
	migrateJsonToSqlite,
	openNuwaDb,
	queryFactsByText,
	resolveStorageBackend,
	saveStateToSqlite,
	sqliteDbPath,
} from "../omp/sqlite-store";
import {
	collectTestableAuthPaths,
	computeAuthDiffSignature,
	planAutonomousOobProbes,
	runAutonomousAuthDiff,
	runAutonomousOobPoll,
	shouldAutoTriggerAuthDiff,
} from "../omp/auto-loops";
import { loadOobCanaries } from "../omp/oob";
import { defaultScopeForTarget } from "../omp/scope";
import { upsertSessionRole } from "../omp/session-vault";
import { SCHEMA, journalAppend, loadState, normalizeState, saveState, statePath, withLock } from "../omp/storage";
import type { NuwaState } from "../omp/types";

const tmpDirs: string[] = [];
const cleanups: Array<() => Promise<void> | void> = [];

function makeTmpDir(prefix = "nuwa-v6-sl-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(dir);
	return dir;
}

async function startLocalServer(
	handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; port: number; close: () => Promise<void> }> {
	const server = http.createServer(handler);
	await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
	const addr = server.address() as net.AddressInfo;
	const close = () =>
		new Promise<void>((res) => {
			server.close(() => res());
		});
	cleanups.push(close);
	return { url: `http://127.0.0.1:${addr.port}`, port: addr.port, close };
}

function buildSampleState(url = "http://127.0.0.1:18080", mode: NuwaState["project"]["mode"] = "pentest"): NuwaState {
	const parsed = url.startsWith("local://") ? null : new URL(url);
	const ts = "2026-11-25T10:00:00.000Z";
	return normalizeState({
		schema: SCHEMA,
		version: "6.0.0",
		project: {
			id: "proj-v6-test",
			target: url,
			url,
			host: parsed?.hostname ?? "workspace",
			port: parsed ? Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80)) : 0,
			scheme: parsed ? parsed.protocol.replace(":", "") : "local",
			goal: "验证 SQLite WAL 与自主闭环",
			mode,
			status: "active",
			phase: "vuln",
			createdAt: ts,
			updatedAt: ts,
			episode: 2,
			ownerSessionId: "sess-v6-owner",
			scope: parsed ? defaultScopeForTarget(url, mode) : undefined,
			activeRoles: ["admin", "user_a"],
			sandboxMode: "none",
			oobDomain: "oast.lab.test",
		},
		facts: {
			F1: {
				id: "F1",
				kind: "service",
				title: "检测到 Nginx 与 Spring Boot Actuator 服务",
				detail: "Server: nginx/1.24.0，发现 /api/v1/users 与 /actuator/health 端点",
				command: "curl -i http://127.0.0.1:18080/",
				output: "HTTP/1.1 200 OK\nServer: nginx/1.24.0\nX-App: spring-boot",
				key: "recon:http",
				createdAt: ts,
				meta: {
					ports: [80, 18080],
					paths: ["/api/v1/users", "/actuator/health"],
					server: "nginx/1.24.0",
					tech: ["nginx", "spring"],
					status: 200,
				},
				verified: true,
				verifyStage: "confirmed",
				evidenceSeq: 1,
				targetKey: "/api/v1/users",
				surfaceDomain: "path",
			},
			F2: {
				id: "F2",
				kind: "vuln",
				title: "疑似订单对象水平越权漏洞 (CVE-2026-99999)",
				detail: "在 /api/orders/1001 端点发现疑似跨用户对象读取异常",
				command: "curl -sS http://127.0.0.1:18080/api/orders/1001",
				output: '{"orderId":1001,"owner":"alice","total":99}',
				key: "vuln:order-idor",
				createdAt: "2026-11-25T10:05:00.000Z",
				verified: false,
				verifyStage: "candidate",
				verifyNote: "待双盲独立复验",
				evidenceSeq: 2,
				assetId: "A1",
				targetKey: "/api/orders/1001",
				surfaceDomain: "path",
				evidenceRef: ".nuwa/evidence/F2.txt",
				agentResult: { confidence: 0.88, tags: ["bola", "orders"] },
			},
			F3: {
				id: "F3",
				kind: "endpoint",
				title: "发现管理后台配置接口与外部 Webhook 回调",
				detail: "管理路径 /api/admin/config 返回 401；另有 Webhook 抓取接口 /api/webhook?callback_url=...",
				createdAt: "2026-11-25T10:10:00.000Z",
				meta: {
					paths: ["/api/admin/config", "/api/webhook", "/assets/main.css", "/spa-dead-page"],
					routes: ["/api/orders/1001", "/static/logo.png"],
					...( {
						requiresAuthPaths: ["/api/admin/config"],
						endpointClassifications: {
							"/spa-dead-page": "soft_404",
							"/api/admin/config": "exists_requires_auth",
						},
					} as Record<string, unknown> ),
				},
				targetKey: "/api/admin/config",
				surfaceDomain: "path",
			},
		},
		intents: {
			I1: {
				id: "I1",
				phase: "vuln",
				key: "ep:/api/orders/1001",
				title: "核验订单接口权限隔离",
				detail: "验证 /api/orders/1001 是否存在对象级鉴权缺陷",
				from: ["F1"],
				to: "F2",
				status: "done",
				worker: "fujiang",
				priority: 90,
				attempts: 1,
				createdAt: ts,
				claimedAt: "2026-11-25T10:01:00.000Z",
				doneAt: "2026-11-25T10:05:00.000Z",
				hypothesisId: "H1",
				assetId: "A1",
				authRole: "user_a",
				expectedKind: "vuln",
				surfaceDomain: "path",
				targetKey: "/api/orders/1001",
				dedupKey: "vuln|path|/api/orders/1001|abc",
				hintHash: "abc",
			},
			I2: {
				id: "I2",
				phase: "vuln",
				key: "verify-vuln:F2",
				title: "双盲复验候选漏洞 F2",
				detail: "独立核验 /api/orders/1001 的正负对照基线",
				from: ["F2"],
				status: "open",
				priority: 96,
				attempts: 0,
				createdAt: "2026-11-25T10:05:01.000Z",
				expectedKind: "vuln",
				surfaceDomain: "path",
				targetKey: "/api/orders/1001",
			},
		},
		seq: { fact: 3, intent: 2 },
		runtime: {
			startedAt: 1764064800000,
			turns: 6,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 12,
			lastToolCalls: 10,
			tokens: 18500,
			lastSig: "sig-demo",
			lastDirective: "continue",
			completionRejects: 0,
			emptyRounds: 0,
			generation: 1,
			genTurns: 6,
			projectStartedAt: 1764064800000,
			totalTurns: 6,
			totalTokens: 18500,
			totalCostUsd: 0.12,
			status: "active",
			noveltyStall: 0,
			lastNovelFacts: 3,
			blockedCommits: 1,
			attemptedKeys: {
				"vuln:path:/api/orders/1001": {
					key: "ep:/api/orders/1001",
					expectedKind: "vuln",
					targetKey: "/api/orders/1001",
					surfaceDomain: "path",
					status: "done",
					at: "2026-11-25T10:05:00.000Z",
					from: ["F1"],
				},
			},
		},
		assets: {
			A1: {
				id: "A1",
				kind: "web",
				target: url,
				host: parsed?.hostname ?? "127.0.0.1",
				port: parsed ? Number(parsed.port || 80) : 0,
				scheme: parsed ? parsed.protocol.replace(":", "") : "local",
				reachableVia: ["direct"],
				tags: ["primary", "api"],
				sourceFactId: "F1",
				createdAt: ts,
			},
		},
		hypotheses: {
			H1: {
				id: "H1",
				title: "订单接口缺少属主校验假设",
				statement: "低权用户 user_b 可读取 user_a 订单数据",
				requiredFacts: ["F1", "F2"],
				falsificationTest: "使用 user_b 角色请求 /api/orders/1001 观察是否返回 403",
				expectedGain: 0.9,
				estimatedCost: 0.2,
				status: "open",
				linkedIntents: ["I1", "I2"],
				createdAt: ts,
				updatedAt: "2026-11-25T10:05:00.000Z",
				note: "高价值越权链",
			},
		},
	});
}

afterEach(async () => {
	while (cleanups.length > 0) {
		const fn = cleanups.pop()!;
		try {
			await fn();
		} catch {
			/* ignore */
		}
	}
	while (tmpDirs.length > 0) {
		const d = tmpDirs.pop()!;
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
	delete process.env.NUWA_STORAGE_BACKEND;
	delete process.env.NUWA_OOB_POLL_URL;
	delete process.env.NUWA_OOB_POLL_TOKEN;
});

describe("v6.0 SQLite WAL 权威状态存储引擎 (omp/sqlite-store.ts)", () => {
	test("初始化 PRAGMA、10 张规范表结构与存储后端策略解析", () => {
		const root = makeTmpDir();
		expect(resolveStorageBackend(root, {})).toBe("json");
		expect(resolveStorageBackend(root, { NUWA_STORAGE_BACKEND: "sqlite" })).toBe("sqlite");
		expect(resolveStorageBackend(root, { NUWA_STORAGE_BACKEND: "dual" })).toBe("dual");
		expect(resolveStorageBackend(root, { NUWA_STORAGE_BACKEND: "json" })).toBe("json");

		const db = openNuwaDb(root);
		try {
			expect(existsSync(sqliteDbPath(root))).toBe(true);
			const jm = db.query("PRAGMA journal_mode").get() as Record<string, string>;
			const bt = db.query("PRAGMA busy_timeout").get() as Record<string, number>;
			const sy = db.query("PRAGMA synchronous").get() as Record<string, number>;
			const fk = db.query("PRAGMA foreign_keys").get() as Record<string, number>;
			expect(String(Object.values(jm)[0]).toLowerCase()).toBe("wal");
			expect(Number(Object.values(bt)[0])).toBe(5000);
			expect(Number(Object.values(sy)[0])).toBe(1); // NORMAL
			expect(Number(Object.values(fk)[0])).toBe(1);

			const tables = db
				.query("SELECT name FROM sqlite_master WHERE type = 'table'")
				.all()
				.map((r: any) => String(r.name));
			for (const expectedTable of [
				"meta",
				"facts",
				"facts_fts",
				"intents",
				"attempted",
				"assets",
				"hypotheses",
				"journal",
				"exec_ledger",
				"calibration_records",
				"traffic_entries",
			]) {
				expect(tables).toContain(expectedTable);
			}
		} finally {
			db.close();
		}

		// 已存在 nuwa.db 且未显式指定 json 时平滑识别 sqlite
		expect(resolveStorageBackend(root, {})).toBe("sqlite");
		expect(resolveStorageBackend(root, { NUWA_STORAGE_BACKEND: "json" })).toBe("json");
	});

	test("JSON <-> SQLite 无损往返一致性、幂等迁移与兼容导出", () => {
		const root = makeTmpDir();
		const original = buildSampleState();

		// 1. 先落盘存量 JSON 状态与 journal / exec-ledger / calibration / traffic
		saveState(root, structuredClone(original), { reason: "init" });
		const savedJsonState = loadState(root)!;
		journalAppend(root, { type: "fact_add", factId: "F1", note: "历史侦察事件" });
		journalAppend(root, { type: "intent_done", intentId: "I1", note: "完成订单核验" });
		writeFileSync(
			join(root, ".nuwa", "exec-ledger.jsonl"),
			`${JSON.stringify({
				seq: 1,
				ts: "2026-11-25T10:00:00.000Z",
				tool: "bash",
				command: "curl -sS http://127.0.0.1:18080/api/orders/1001",
				sha1: "a".repeat(40),
				normSha1: "a".repeat(40),
				bytes: 42,
				snippet: '{"orderId":1001}',
			})}\n`,
			"utf8",
		);
		writeFileSync(
			join(root, ".nuwa", "calibration.jsonl"),
			`${JSON.stringify({
				predictionId: "pred-001",
				intentId: "I1",
				taskCategory: "auth",
				modelId: "gemini-4-neon-xhigh",
				predictedConfidence: 0.85,
				outcome: 1,
				isFalsePositive: false,
				source: "verifier-gate",
				settled: true,
				createdAt: "2026-11-25T10:01:00.000Z",
			})}\n`,
			"utf8",
		);
		mkdirSync(join(root, ".nuwa", "traffic"), { recursive: true });
		writeFileSync(
			join(root, ".nuwa", "traffic", "index.jsonl"),
			`${JSON.stringify({
				id: "tr-001",
				ts: "2026-11-25T10:02:00.000Z",
				method: "GET",
				url: "http://127.0.0.1:18080/api/orders/1001",
				host: "127.0.0.1",
				path: "/api/orders/1001",
				status: 200,
				requestHeaders: { Accept: "application/json" },
			})}\n`,
			"utf8",
		);

		// 2. 首次幂等迁移
		const mig1 = migrateJsonToSqlite(root);
		expect(mig1.ok).toBe(true);
		expect(mig1.migratedState).toBe(true);
		expect(mig1.stateSkipped).toBe(false);
		expect(mig1.factsCount).toBe(3);
		expect(mig1.intentsCount).toBe(2);
		expect(mig1.attemptedCount).toBe(1);
		expect(mig1.assetsCount).toBe(1);
		expect(mig1.hypothesesCount).toBe(1);
		expect(mig1.journalInserted).toBeGreaterThanOrEqual(2);
		expect(mig1.execLedgerInserted).toBe(1);
		expect(mig1.calibrationInserted).toBe(1);
		expect(mig1.trafficInserted).toBe(1);

		// 3. 验证 SQLite 读取与 JSON 状态 100% 无损一致
		const fromSqlite = loadStateFromSqlite(root)!;
		expect(fromSqlite).toEqual(savedJsonState);
		expect(fromSqlite.facts.F1?.verified).toBe(true);
		expect(fromSqlite.facts.F2?.verified).toBe(false);
		expect(fromSqlite.facts.F3?.verified).toBeUndefined();

		// 4. 第二次执行迁移必须严格幂等（不重复插 journal / 账本，不覆盖状态）
		const mig2 = migrateJsonToSqlite(root);
		expect(mig2.ok).toBe(true);
		expect(mig2.migratedState).toBe(false);
		expect(mig2.stateSkipped).toBe(true);
		expect(mig2.journalInserted).toBe(0);
		expect(mig2.journalSkipped).toBe(mig1.journalInserted);
		expect(mig2.execLedgerInserted).toBe(0);
		expect(mig2.calibrationInserted).toBe(0);
		expect(mig2.trafficInserted).toBe(0);

		// 5. 导出兼容 state.json 并校验往返一致性
		const compatOut = join(root, ".nuwa", "state-export.json");
		const exp = exportStateJsonCompat(root, { outputPath: compatOut });
		expect(exp.ok).toBe(true);
		expect(exp.bytes).toBeGreaterThan(100);
		expect(JSON.parse(readFileSync(compatOut, "utf8"))).toEqual(savedJsonState);

		// 6. 直接 saveStateToSqlite -> loadStateFromSqlite 往返测试（含 undefined assets/hypotheses 区分）
		const root2 = makeTmpDir();
		const minimal = buildSampleState();
		delete minimal.assets;
		delete minimal.hypotheses;
		delete minimal.runtime.attemptedKeys;
		saveStateToSqlite(root2, minimal);
		const reloadedMinimal = loadStateFromSqlite(root2)!;
		expect(reloadedMinimal).toEqual(minimal);
		expect(reloadedMinimal.assets).toBeUndefined();
		expect(reloadedMinimal.hypotheses).toBeUndefined();
		expect(reloadedMinimal.runtime.attemptedKeys).toBeUndefined();
	});

	test("历史细节全文检索（FTS5 英文/CVE + 中文子串 + 路径 + 过滤 + 防注入）", () => {
		const root = makeTmpDir();
		const st = buildSampleState();
		for (let i = 10; i < 40; i++) {
			st.facts[`F${i}`] = {
				id: `F${i}`,
				kind: "note",
				title: `常规探测日志节点 #${i}`,
				detail: `普通扫描记录 item=${i} status=200`,
				createdAt: `2026-11-25T10:${String(i % 60).padStart(2, "0")}:00.000Z`,
			};
		}
		st.facts.F99 = {
			id: "F99",
			kind: "vuln",
			title: "关键历史细节：GraphQL 批量查询泄露内部租户账单",
			detail: "在 /graphql/v2 发现 Introspection 开启且返回 billing_secret_schema",
			command: "curl -sS http://127.0.0.1:18080/graphql/v2",
			output: "schema=billing_secret_schema tenantId=core-prod",
			createdAt: "2026-11-25T11:00:00.000Z",
			verifyStage: "confirmed",
			surfaceDomain: "path",
			targetKey: "/graphql/v2",
		};
		saveStateToSqlite(root, st);

		// 英文关键词 FTS5 命中
		const hitsEn = queryFactsByText(root, "billing_secret_schema");
		expect(hitsEn.length).toBeGreaterThanOrEqual(1);
		expect(hitsEn[0]?.fact.id).toBe("F99");

		// CVE 编号命中
		const hitsCve = queryFactsByText(root, "CVE-2026-99999");
		expect(hitsCve.some((h) => h.fact.id === "F2")).toBe(true);

		// 中文子串命中（通过混合检索覆盖 unicode61 CJK 子串）
		const hitsZh = queryFactsByText(root, "内部租户账单");
		expect(hitsZh.some((h) => h.fact.id === "F99")).toBe(true);

		// 按 kind 与 verifyStage 过滤，且容错非法 limit (NaN)
		const hitsFiltered = queryFactsByText(root, "orders", {
			kind: "vuln",
			verifyStage: "candidate",
			limit: Number.NaN,
		});
		expect(hitsFiltered.length).toBe(1);
		expect(hitsFiltered[0]?.fact.id).toBe("F2");

		// 仅存在于 meta.tech 中的历史技术栈也可被检索命中
		const hitsMeta = queryFactsByText(root, "spring");
		expect(hitsMeta.some((h) => h.fact.id === "F1")).toBe(true);

		// SQL 注入与 FTS5 语法注入免疫测试
		for (const evil of [
			"' OR 1=1 --",
			'"; DROP TABLE facts; --',
			"title:admin* NEAR/5 OR NOT",
			"%_\\'",
		]) {
			const res = queryFactsByText(root, evil);
			expect(Array.isArray(res)).toBe(true);
			expect(res.length).toBe(0);
		}
		// 注入串未破坏 facts 表
		expect(Object.keys(loadStateFromSqlite(root)!.facts).length).toBeGreaterThan(30);
	});

	test("事务原子性回滚与坏库兜底提示（抛出诊断错误 / 回退 JSON / 自动隔离重建）", () => {
		const root = makeTmpDir();
		const st = buildSampleState();
		saveState(root, structuredClone(st), { reason: "init" });
		saveStateToSqlite(root, st);

		// 1. 验证事务原子性：向非法数据结构（缺少 id 违反 NOT NULL）写入时整笔事务回滚，原数据完好
		const store = new NuwaSqliteStore(root);
		try {
			const brokenState = structuredClone(st);
			brokenState.facts.F_BAD = {
				id: null as unknown as string,
				kind: "note",
				title: "坏数据",
				detail: "触发 NOT NULL 约束失败",
				createdAt: "2026-11-25T12:00:00.000Z",
			};
			expect(() => store.saveState(brokenState)).toThrow();
			const afterRollback = store.loadState()!;
			expect(Object.keys(afterRollback.facts).sort()).toEqual(["F1", "F2", "F3"]);
		} finally {
			store.close();
		}

		// 2. 破坏 nuwa.db 文件内容，验证坏库兜底提示
		const dbFile = sqliteDbPath(root);
		writeFileSync(dbFile, "CORRUPTED_NOT_A_VALID_SQLITE_FILE_HEADER_1234567890", "utf8");

		expect(() => openNuwaDb(root)).toThrow(NuwaSqliteCorruptError);
		try {
			loadStateFromSqlite(root);
			throw new Error("应当抛出 NuwaSqliteCorruptError");
		} catch (err) {
			expect(err).toBeInstanceOf(NuwaSqliteCorruptError);
			const cerr = err as NuwaSqliteCorruptError;
			expect(cerr.message).toContain("恢复建议");
			expect(cerr.recoveryHint).toContain("migrateJsonToSqlite");
		}

		// 3. 开启 fallbackToJson 时发出告警并自动回退 state.json
		let warningMsg = "";
		const fallbackState = loadStateFromSqlite(root, {
			fallbackToJson: true,
			onCorruptWarning: (msg) => {
				warningMsg = msg;
			},
		});
		expect(warningMsg).toContain("SQLite 状态库损坏");
		expect(fallbackState?.project.id).toBe("proj-v6-test");

		// 4. 开启 quarantineCorrupt 时自动隔离坏库文件并重建健康库
		const recoveredDb = openNuwaDb(root, { quarantineCorrupt: true });
		try {
			const qc = recoveredDb.query("PRAGMA quick_check(1)").get() as Record<string, string>;
			expect(String(Object.values(qc)[0]).toLowerCase()).toBe("ok");
		} finally {
			recoveredDb.close();
		}
		const corruptFiles = readdirSync(join(root, ".nuwa")).filter((f) => f.includes("nuwa.db.corrupt-"));
		expect(corruptFiles.length).toBe(1);

		// 5. 崩溃遗留 0 字节空文件 nuwa.db 也必须被识别为坏库并触发 fallbackToJson / quarantineCorrupt
		const rootZero = makeTmpDir();
		saveState(rootZero, structuredClone(st), { reason: "init" });
		const zeroDbFile = sqliteDbPath(rootZero);
		writeFileSync(zeroDbFile, "", "utf8");
		expect(statSync(zeroDbFile).size).toBe(0);
		expect(() => openNuwaDb(rootZero)).toThrow(NuwaSqliteCorruptError);
		expect(() => loadStateFromSqlite(rootZero)).toThrow(NuwaSqliteCorruptError);
		let zeroWarn = "";
		const zeroFallback = loadStateFromSqlite(rootZero, {
			fallbackToJson: true,
			onCorruptWarning: (msg) => {
				zeroWarn = msg;
			},
		});
		expect(zeroWarn).toContain("0 字节");
		expect(zeroFallback?.project.id).toBe("proj-v6-test");
		const rebuiltFromZero = openNuwaDb(rootZero, { quarantineCorrupt: true });
		try {
			const qc = rebuiltFromZero.query("PRAGMA quick_check(1)").get() as Record<string, string>;
			expect(String(Object.values(qc)[0]).toLowerCase()).toBe("ok");
		} finally {
			rebuiltFromZero.close();
		}
		expect(readdirSync(join(rootZero, ".nuwa")).some((f) => f.includes("nuwa.db.corrupt-"))).toBe(true);
	});

	test("纯只读查询零写事务验证（持排他写锁期间不阻塞、文件元数据零修改）", () => {
		const root = makeTmpDir();
		saveStateToSqlite(root, buildSampleState());

		const dbFile = sqliteDbPath(root);
		const statBefore = statSync(dbFile);

		// 另一连接持有 BEGIN IMMEDIATE 排他写锁，证明 loadStateFromSqlite 与 queryFactsByText 纯只读绝不抢写锁
		const writerDb = openNuwaDb(root);
		try {
			writerDb.exec("BEGIN IMMEDIATE;");
			const loaded = loadStateFromSqlite(root);
			expect(loaded?.project.id).toBe("proj-v6-test");
			const hits = queryFactsByText(root, "CVE-2026-99999");
			expect(hits.length).toBe(1);
			expect(hits[0]?.fact.id).toBe("F2");
			writerDb.exec("ROLLBACK;");
		} finally {
			writerDb.close();
		}

		const statAfter = statSync(dbFile);
		expect(statAfter.mtimeMs).toBe(statBefore.mtimeMs);
		expect(statAfter.size).toBe(statBefore.size);
	});

	test("SQLite WAL 4 路并发写入无锁超时（单进程 4 连接 + 4 真实并发子进程压测）", async () => {
		const root = makeTmpDir();
		saveStateToSqlite(root, buildSampleState());

		// A. 同进程 4 独立连接并发读写压测
		const stores = [
			new NuwaSqliteStore(root),
			new NuwaSqliteStore(root),
			new NuwaSqliteStore(root),
			new NuwaSqliteStore(root),
		];
		try {
			await Promise.all(
				stores.map(async (s, workerIdx) => {
					for (let i = 0; i < 20; i++) {
						s.upsertFact({
							id: `F_INPROC_${workerIdx}_${i}`,
							kind: "note",
							title: `并发连接写入 w=${workerIdx} i=${i}`,
							detail: `并发验证 payload_w${workerIdx}_n${i}`,
							createdAt: new Date().toISOString(),
						});
						s.appendJournal({ type: "concurrent_inproc", worker: workerIdx, iter: i });
						if (i % 4 === 0) {
							s.queryFactsByText(`payload_w${workerIdx}`);
						}
					}
				}),
			);
			const stAfterA = stores[0]!.loadState()!;
			const inprocFacts = Object.keys(stAfterA.facts).filter((id) => id.startsWith("F_INPROC_"));
			expect(inprocFacts.length).toBe(80);
			expect(stores[0]!.integrityCheck().ok).toBe(true);
		} finally {
			for (const s of stores) s.close();
		}

		// B. 真实 4 进程并发读写同一 nuwa.db 压测
		const modulePath = resolve(import.meta.dir, "../omp/sqlite-store.ts");
		const workerScript = `
			import { NuwaSqliteStore } from ${JSON.stringify(modulePath)};
			const root = process.env.TEST_ROOT;
			const wid = Number(process.env.WORKER_ID);
			const store = new NuwaSqliteStore(root);
			try {
				for (let i = 0; i < 25; i++) {
					store.upsertFact({
						id: "F_PROC_" + wid + "_" + i,
						kind: "endpoint",
						title: "多进程并发事实 proc=" + wid + " seq=" + i,
						detail: "mp_token_" + wid + "_" + i,
						createdAt: new Date().toISOString(),
					});
					store.appendJournal({ type: "mp_write", worker: wid, seq: i });
					store.appendTrafficEntry({
						id: "tr_" + wid + "_" + i,
						ts: new Date().toISOString(),
						method: "GET",
						url: "http://127.0.0.1:18080/api/item/" + i,
						host: "127.0.0.1",
						path: "/api/item/" + i,
						status: 200,
					});
					if (i % 5 === 0) {
						store.queryFactsByText("mp_token_" + wid);
					}
				}
			} finally {
				store.close();
			}
		`;

		const procs = Array.from({ length: 4 }, (_, wid) =>
			Bun.spawn(["bun", "-e", workerScript], {
				env: { ...process.env, TEST_ROOT: root, WORKER_ID: String(wid) },
				stdout: "pipe",
				stderr: "pipe",
			}),
		);
		const results = await Promise.all(
			procs.map(async (p) => ({
				code: await p.exited,
				stderr: await new Response(p.stderr).text(),
			})),
		);
		for (const r of results) {
			expect(r.stderr).toBe("");
			expect(r.code).toBe(0);
		}

		const verifyStore = new NuwaSqliteStore(root);
		try {
			const loaded = verifyStore.loadState()!;
			const mpFacts = Object.keys(loaded.facts).filter((id) => id.startsWith("F_PROC_"));
			expect(mpFacts.length).toBe(100);
			const mpJournal = verifyStore.readJournalTail(500).filter((j) => j.type === "mp_write");
			expect(mpJournal.length).toBe(100);
			const traffic = verifyStore.queryTrafficEntries({ limit: 200 });
			expect(traffic.length).toBe(100);
			expect(verifyStore.integrityCheck().ok).toBe(true);
		} finally {
			verifyStore.close();
		}
	});

	test("所有 SQLite 表与 FTS 索引零明文凭据泄露验证", () => {
		const root = makeTmpDir();
		const vaultBearer = "VaultAdminSecretToken_998877665544";
		const vaultCookie = "session_id=VaultCookieSecretValue_XYZ12345";
		const vaultPass = "SuperVaultPassword!98765";
		const inlineApiKey = "sk-live-InlineSensitiveApiKey_ABCDE123456";

		upsertSessionRole(root, {
			role: "admin",
			bearer: vaultBearer,
			cookie: vaultCookie,
			username: "admin",
			password: vaultPass,
		});

		const st = buildSampleState();
		const urlToken = "SecretAccessTok_88990011";
		const urlUserPass = "DbUserPass_776655";
		const privHeaderTok = "glpat-PrivateHeaderToken_554433";
		const vaultHeaderTok = "hvs.VaultHeaderSecret_221100";
		const csrfHeaderTok = "CsrfSecretToken_AABBCCDD";
		const xsrfHeaderTok = "XsrfSecretToken_EEFFGGHH";

		st.facts.F_SENS = {
			id: "F_SENS",
			kind: "cred",
			title: `发现凭据 Authorization: Bearer ${vaultBearer}`,
			detail: `Cookie: ${vaultCookie} | password=${vaultPass} | X-API-Key: ${inlineApiKey}`,
			command: `curl -H "Authorization: Bearer ${vaultBearer}" "https://alice:${urlUserPass}@api.example.com/v1/export?access_token=${urlToken}&role=admin#section1"`,
			output: `Set-Cookie: ${vaultCookie}\nBearer ${vaultBearer}\nPrivate-Token: ${privHeaderTok}`,
			createdAt: "2026-11-25T10:30:00.000Z",
		};
		saveStateToSqlite(root, st);

		appendJournalSqlite(root, {
			type: "debug_trace",
			header: `Authorization: Bearer ${vaultBearer}`,
			cookie: vaultCookie,
			password: vaultPass,
		});

		const store = new NuwaSqliteStore(root);
		try {
			store.appendExecLedger({
				seq: 10,
				ts: "2026-11-25T10:31:00.000Z",
				tool: "bash",
				command: `curl -H "X-API-Key: ${inlineApiKey}" http://127.0.0.1:18080`,
				sha1: "b".repeat(40),
				normSha1: "b".repeat(40),
				bytes: 64,
				snippet: `Authorization: Bearer ${vaultBearer}`,
			});
			store.upsertCalibrationRecord({
				predictionId: "pred-sec-1",
				taskCategory: "auth",
				modelId: "gemini-4-neon-xhigh",
				predictedConfidence: 0.7,
				settled: false,
				createdAt: "2026-11-25T10:32:00.000Z",
				payload: { note: `leak check ${vaultBearer}`, password: vaultPass },
			});
			store.appendTrafficEntry({
				id: "tr-sec-1",
				ts: "2026-11-25T10:33:00.000Z",
				method: "GET",
				url: `https://alice:${urlUserPass}@api.example.com/api/me?access_token=${urlToken}&role=admin#top`,
				host: "api.example.com",
				path: `/api/me?access_token=${urlToken}&role=admin`,
				status: 200,
				requestHeaders: {
					Authorization: `Bearer ${vaultBearer}`,
					Cookie: vaultCookie,
					"X-API-Key": inlineApiKey,
					"Private-Token": privHeaderTok,
					"X-Vault-Token": vaultHeaderTok,
					"X-CSRF-Token": csrfHeaderTok,
					"X-XSRF-Token": xsrfHeaderTok,
					"Content-Type": "application/json",
					Accept: "application/json",
				},
				responseHeaders: {
					"Set-Cookie": vaultCookie,
					"Access-Control-Allow-Origin": "https://api.example.com",
				},
				responseBodyPreview: `echo ${vaultBearer} and ${vaultPass}`,
			});

			// 强制 checkpoint 并关闭，随后扫描磁盘 DB 与 WAL 原始字节
			store.rawDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
		} finally {
			store.close();
		}

		const dbRaw = readFileSync(sqliteDbPath(root)).toString("latin1");
		const walFile = `${sqliteDbPath(root)}-wal`;
		const walRaw = existsSync(walFile) ? readFileSync(walFile).toString("latin1") : "";
		const combinedDisk = `${dbRaw}\n${walRaw}`;

		for (const secret of [
			vaultBearer,
			"VaultCookieSecretValue_XYZ12345",
			vaultPass,
			inlineApiKey,
			urlToken,
			urlUserPass,
			privHeaderTok,
			vaultHeaderTok,
			csrfHeaderTok,
			xsrfHeaderTok,
		]) {
			expect(combinedDisk).not.toContain(secret);
		}

		// 读回的对象绝不含明文，同时 URL 参数边界 (&role=admin#section1) 与结构化非敏感字段毫发无损
		const loaded = loadStateFromSqlite(root)!;
		expect(JSON.stringify(loaded)).not.toContain(vaultBearer);
		expect(JSON.stringify(loaded)).not.toContain(vaultPass);
		expect(JSON.stringify(loaded)).not.toContain(inlineApiKey);
		expect(loaded.facts.F_SENS?.command).toContain("&role=admin#section1");
		expect(loaded.facts.F_SENS?.command).toContain("https://alice:");
		expect(loaded.facts.F_SENS?.command).not.toContain(urlUserPass);
		expect(loaded.facts.F_SENS?.command).not.toContain(urlToken);
		// 确保 NuwaState 自身结构字段（ownerSessionId/targetKey/dedupKey/key）未被误脱敏
		expect(loaded.project.ownerSessionId).toBe("sess-v6-owner");
		expect(loaded.facts.F2?.targetKey).toBe("/api/orders/1001");
		expect(loaded.intents.I1?.dedupKey).toBe("vuln|path|/api/orders/1001|abc");

		const roStore = new NuwaSqliteStore(root, { readonly: true });
		try {
			const traffic = roStore.queryTrafficEntries({ limit: 5 });
			expect(traffic.length).toBe(1);
			const t0 = traffic[0]!;
			expect(t0.url).toContain("&role=admin#top");
			expect(t0.requestHeaders?.["Content-Type"]).toBe("application/json");
			expect(t0.requestHeaders?.Accept).toBe("application/json");
			expect(t0.responseHeaders?.["Access-Control-Allow-Origin"]).toBe("https://api.example.com");
			expect(t0.requestHeaders?.["Private-Token"]).toContain("***");
			expect(t0.requestHeaders?.["X-Vault-Token"]).toContain("***");
			expect(t0.requestHeaders?.["X-CSRF-Token"]).toContain("***");
			expect(t0.requestHeaders?.["X-XSRF-Token"]).toContain("***");
		} finally {
			roStore.close();
		}
	});
});

describe("v6.0 AuthDiff 自主闭环驱动引擎 (omp/auto-loops.ts)", () => {
	test("模式过滤、端点抽取排序与冷却防重逻辑", () => {
		const root = makeTmpDir();

		// 1. 非 Web 评估模式（coding / local）绝不触发
		const codingState = buildSampleState("local:///repo/app", "coding");
		const codingDecision = shouldAutoTriggerAuthDiff(codingState, root);
		expect(codingDecision.shouldTrigger).toBe(false);
		expect(codingDecision.reason).toContain("非 Web");

		// 2. 端点抽取应过滤静态资源与 soft_404，并优先保留管理/对象/需鉴权路径
		const webState = buildSampleState("http://127.0.0.1:18080", "pentest");
		const paths = collectTestableAuthPaths(webState);
		expect(paths).toContain("/api/admin/config");
		expect(paths).toContain("/api/orders/1001");
		expect(paths).toContain("/api/v1/users");
		expect(paths).not.toContain("/assets/main.css");
		expect(paths).not.toContain("/static/logo.png");
		expect(paths).not.toContain("/spa-dead-page");
		// 高价值路径排在普通路径前面
		expect(paths.indexOf("/api/admin/config")).toBeLessThan(paths.indexOf("/actuator/health"));

		// 3. 角色不足且无新 cred 时不触发
		const noRoleDecision = shouldAutoTriggerAuthDiff(webState, root);
		expect(noRoleDecision.shouldTrigger).toBe(false);

		// 4. Vault 达到 >=2 个角色后自动触发
		upsertSessionRole(root, { role: "admin", bearer: "tok_admin_11111111" });
		upsertSessionRole(root, { role: "user_a", bearer: "tok_usera_22222222" });
		const multiRoleDecision = shouldAutoTriggerAuthDiff(webState, root);
		expect(multiRoleDecision.shouldTrigger).toBe(true);
		expect(multiRoleDecision.triggerSource).toBe("multi_role_vault");
		expect(multiRoleDecision.roles).toEqual(["admin", "user_a"]);
		expect(multiRoleDecision.signature).toBe(
			computeAuthDiffSignature(["user_a", "admin"], multiRoleDecision.paths),
		);
	});

	test("端到端多角色差分检出（UNAUTH / BFLA / BOLA）、Soft-404 去噪、双盲复验、冷却防重与零凭据泄露", async () => {
		const root = makeTmpDir();
		const adminSecret = "AdminLiveSecretToken_AA11BB22CC33";
		const aliceSecret = "AliceLiveSecretToken_DD44EE55FF66";
		const bobSecret = "BobLiveSecretToken_GG77HH88II99";

		const srv = await startLocalServer((req, res) => {
			const auth = req.headers.authorization ?? "";
			const isAdmin = auth === `Bearer ${adminSecret}`;
			const isAlice = auth === `Bearer ${aliceSecret}`;
			const isBob = auth === `Bearer ${bobSecret}`;
			const url = req.url ?? "/";

			// Soft-404 兜底页
			if (url.startsWith("/__nuwa_authdiff_404_") || url === "/spa-fallback-route") {
				res.writeHead(200, { "Content-Type": "text/html" });
				res.end("<!doctype html><html><title>Portal SPA</title><body><div id='root'></div></body></html>");
				return;
			}
			// 1. unauth_access：匿名直接返回对象导出 JSON（故意回显收到的 Authorization 验证脱敏）
			if (url === "/api/v1/export/9001") {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						exportId: 9001,
						tenant: "finance",
						records: 42,
						echoAuth: auth || "none",
					}),
				);
				return;
			}
			// 2. vertical_bfla：管理接口放行低权角色
			if (url === "/api/admin/config") {
				if (!isAdmin && !isAlice && !isBob) {
					res.writeHead(401, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: "unauthorized" }));
					return;
				}
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						roleFeatureFlags: ["audit_export", "impersonate"],
						retentionDays: 180,
						debugEcho: auth,
					}),
				);
				return;
			}
			// 3. horizontal_bola：同级角色读取同一订单对象
			if (url === "/api/orders/1001") {
				if (!isAdmin && !isAlice && !isBob) {
					res.writeHead(401, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: "unauthorized" }));
					return;
				}
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						orderId: 1001,
						owner: "alice",
						amount: 512,
						shippingCity: "Shanghai",
					}),
				);
				return;
			}
			res.writeHead(404, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ error: "not_found" }));
		});

		const scope = defaultScopeForTarget(srv.url, "pentest");
		const state = buildSampleState(srv.url, "pentest");
		// 混合存量小写 f005 + 大写 F2 与已有意图 i003，故意使 seq 落后，验证全仓标准小写 3 位零填充 ID 防冲撞与字典序对齐
		state.facts = {
			f005: {
				id: "f005",
				kind: "endpoint",
				title: "发现核心业务与管理接口",
				detail: "API 列表包含 /api/admin/config, /api/orders/1001, /api/v1/export/9001, /spa-fallback-route",
				createdAt: "2026-11-25T10:00:00.000Z",
				meta: {
					paths: [
						"/spa-fallback-route",
						"/api/v1/export/9001",
						"/api/admin/config",
						"/api/orders/1001",
					],
				},
			},
			F2: {
				id: "F2",
				kind: "cred",
				title: "获取 user_b 角色登录态凭据",
				detail: "role=user_b 登录成功返回有效令牌",
				output: `Authorization: Bearer ${bobSecret}`,
				createdAt: "2026-11-25T10:01:00.000Z",
			},
		};
		state.intents = {
			i003: {
				id: "i003",
				phase: "recon",
				key: "recon:http",
				title: "初始 HTTP 探测",
				detail: "已完成",
				from: [],
				status: "done",
				priority: 90,
				attempts: 1,
				createdAt: "2026-11-25T09:59:00.000Z",
			},
		};
		state.seq = { fact: 1, intent: 1 };

		upsertSessionRole(root, { role: "admin", bearer: adminSecret });
		upsertSessionRole(root, { role: "user_a", bearer: aliceSecret });

		const t0 = 1_764_065_000_000;
		const run1 = await runAutonomousAuthDiff(state, root, scope, {
			nowMs: t0,
			cooldownMs: 300_000,
			applyToState: true,
		});

		expect(run1.triggered).toBe(true);
		// 新 cred 事实 F2 已自动收纳为 user_b
		expect(run1.ingestedRoles).toContain("user_b");
		expect(run1.decision.roles).toEqual(["admin", "user_a", "user_b"]);

		// Soft-404 被准确过滤，3 类高置信度异常全部检出
		const kinds = run1.highConfidenceFindings.map((f) => f.kind).sort();
		expect(kinds).toEqual(["horizontal_bola", "unauth_access", "vertical_bfla"]);
		expect(run1.highConfidenceFindings.some((f) => f.path === "/spa-fallback-route")).toBe(false);

		// 严格遵守双盲闸门与全仓 f001/i001 零填充 ID 规范：从 f006 / i004 递增且字典序一致
		expect(run1.candidateFacts.map((f) => f.id)).toEqual(["f006", "f007", "f008"]);
		expect(run1.verifyIntentSpecs.length).toBe(3);
		for (const cf of run1.candidateFacts) {
			expect(cf.id).toMatch(/^f\d{3,}$/);
			expect(cf.kind).toBe("vuln");
			expect(cf.verified).toBe(false);
			expect(cf.verifyStage).toBe("candidate");
			expect(state.facts[cf.id]).toBeDefined();
			const matchSpec = run1.verifyIntentSpecs.find((s) => s.key === `verify-vuln:${cf.id}`);
			expect(matchSpec).toBeDefined();
			expect(matchSpec?.recommendedAgent).toBe("nuwa-verifier");
			expect(matchSpec?.priority).toBe(96);
		}
		const addedVerifyIntents = Object.values(state.intents)
			.filter((i) => i.key.startsWith("verify-vuln:"))
			.sort((a, b) => a.id.localeCompare(b.id));
		expect(addedVerifyIntents.map((i) => i.id)).toEqual(["i004", "i005", "i006"]);
		expect(state.seq.fact).toBe(8);
		expect(state.seq.intent).toBe(6);

		// 零凭据泄露验证（返回对象、state、持久化冷却文件均不含明文凭据）
		const persistedLoopRaw = readFileSync(join(root, ".nuwa", "auto-loops-state.json"), "utf8");
		const serializedAll = `${JSON.stringify(run1)}\n${JSON.stringify(state)}\n${persistedLoopRaw}`;
		expect(serializedAll).not.toContain(adminSecret);
		expect(serializedAll).not.toContain(aliceSecret);
		expect(serializedAll).not.toContain(bobSecret);

		// 冷却防重：60s 后相同角色集合 + 路径集合应被冷却拦截
		const run2 = await runAutonomousAuthDiff(state, root, scope, {
			nowMs: t0 + 60_000,
			cooldownMs: 300_000,
		});
		expect(run2.triggered).toBe(false);
		expect(run2.decision.cooldownRemainingMs).toBeGreaterThan(0);

		// 新增端点路径后哈希改变，立即解除冷却重新触发
		state.facts.F99 = {
			id: "F99",
			kind: "endpoint",
			title: "新发现对象端点 /api/orders/1002",
			detail: "新增 /api/orders/1002",
			createdAt: "2026-11-25T10:03:00.000Z",
			meta: { paths: ["/api/orders/1002"] },
		};
		const run3 = await runAutonomousAuthDiff(state, root, scope, {
			nowMs: t0 + 70_000,
			cooldownMs: 300_000,
		});
		expect(run3.triggered).toBe(true);
		expect(run3.decision.signature).not.toBe(run1.decision.signature);

		// 冷却过期后相同集合也允许重新触发
		const run4 = await runAutonomousAuthDiff(state, root, scope, {
			nowMs: t0 + 400_000,
			cooldownMs: 300_000,
		});
		expect(run4.triggered).toBe(true);
	});
});

describe("v6.0 OOB 自主播撒与节流轮询闭环 (omp/auto-loops.ts)", () => {
	test("未配置 oobDomains 时安全禁用；配置后自动识别高危面播撒并严格去重", () => {
		const root = makeTmpDir();
		const state = buildSampleState("http://127.0.0.1:18080", "pentest");
		const scopeNoOob = defaultScopeForTarget("http://127.0.0.1:18080", "pentest");

		// 未配置 oobDomains
		const disabled = planAutonomousOobProbes(state, root, scopeNoOob);
		expect(disabled.enabled).toBe(false);
		expect(disabled.createdCanaries.length).toBe(0);

		// 注入盲 SSRF / XXE / SSTI / 反序列化 4 类高危评估面
		state.facts.F10 = {
			id: "F10",
			kind: "endpoint",
			title: "Webhook 回调抓取接口 /api/webhook",
			detail: "接收 callback_url 参数并由后端拉取，疑似存在盲 SSRF 风险面",
			createdAt: "2026-11-25T10:12:00.000Z",
			targetKey: "/api/webhook",
		};
		state.facts.F11 = {
			id: "F11",
			kind: "endpoint",
			title: "XML 文档导入接口 /api/xml/import",
			detail: "接收 application/xml 载荷，需排查盲 XXE 外部实体解析",
			createdAt: "2026-11-25T10:13:00.000Z",
			targetKey: "/api/xml/import",
		};
		state.facts.F12 = {
			id: "F12",
			kind: "note",
			title: "邮件模板渲染接口 /api/render",
			detail: "后端使用 Jinja2 template_render，存在盲 SSTI 风险面",
			createdAt: "2026-11-25T10:14:00.000Z",
			targetKey: "/api/render",
		};
		state.facts.F13 = {
			id: "F13",
			kind: "service",
			title: "识别到 Fastjson 反序列化组件",
			detail: "API 解析 JSON 时命中 fastjson 与 JNDI 依赖，需排查盲反序列化",
			createdAt: "2026-11-25T10:15:00.000Z",
			targetKey: "/api/json/parse",
		};

		const scopeWithOob = { ...scopeNoOob, oobDomains: ["oast.lab.test"] };
		const plan1 = planAutonomousOobProbes(state, root, scopeWithOob, { maxNewCanaries: 10 });
		expect(plan1.enabled).toBe(true);
		expect(plan1.domain).toBe("oast.lab.test");
		expect(plan1.createdCanaries.length).toBeGreaterThanOrEqual(4);
		const categories = new Set(plan1.planned.map((p) => p.category));
		expect(categories.has("blind_ssrf")).toBe(true);
		expect(categories.has("blind_xxe")).toBe(true);
		expect(categories.has("blind_ssti")).toBe(true);
		expect(categories.has("blind_deser")).toBe(true);
		for (const c of plan1.createdCanaries) {
			expect(c.fqdn.endsWith(".oast.lab.test")).toBe(true);
		}
		const countAfterPlan1 = loadOobCanaries(root).length;
		expect(countAfterPlan1).toBe(plan1.createdCanaries.length);

		// 第二次规划必须严格去重，不重复签发 Canary
		const plan2 = planAutonomousOobProbes(state, root, scopeWithOob, { maxNewCanaries: 10 });
		expect(plan2.createdCanaries.length).toBe(0);
		expect(plan2.deduplicatedKeys.length).toBe(plan1.planned.length);
		expect(loadOobCanaries(root).length).toBe(countAfterPlan1);
	});

	test("OOB 节流轮询（默认 30s 可覆盖）、模拟回连转实锤 Fact、标记 Canary 已命中与令牌防泄露", async () => {
		const root = makeTmpDir();
		const state = buildSampleState("http://127.0.0.1:18080", "pentest");
		state.facts = {
			F10: {
				id: "F10",
				kind: "endpoint",
				title: "盲 SSRF Webhook 端点 /api/webhook",
				detail: "支持 callback_url 参数",
				createdAt: "2026-11-25T10:12:00.000Z",
				targetKey: "/api/webhook",
			},
		};
		state.intents = {};
		state.seq = { fact: 10, intent: 0 };

		const scope = {
			...defaultScopeForTarget("http://127.0.0.1:18080", "pentest"),
			oobDomains: ["oast.lab.test"],
		};
		const planned = planAutonomousOobProbes(state, root, scope);
		expect(planned.createdCanaries.length).toBe(1);
		const canary = planned.createdCanaries[0]!;
		const secretPollToken = "OobPollSecretBearer_999000111";

		let fetchCalls = 0;
		const hitPayload1 = JSON.stringify({
			data: [
				{
					id: "evt-oob-001",
					protocol: "dns",
					"full-id": canary.fqdn,
					"remote-address": "10.20.30.40",
					timestamp: "2026-11-25T10:20:00.000Z",
					"raw-request": `A? ${canary.fqdn}.`,
				},
				{
					id: "evt-oob-002",
					protocol: "http",
					"full-id": canary.fqdn,
					"remote-address": "10.20.30.40",
					timestamp: "2026-11-25T10:20:02.000Z",
					"raw-request": `GET /probe HTTP/1.1 Host: ${canary.fqdn}`,
				},
			],
		});

		const mockFetch = async () => {
			fetchCalls += 1;
			return { ok: true, status: 200, text: async () => hitPayload1 };
		};

		const t0 = 1_764_066_000_000;

		// 0. 越界与非法 pollUrl 必须被 N-007 硬阻断（0 次网络发包）且绝不污染节流窗口
		const blockedOutOfScope = await runAutonomousOobPoll(state, root, scope, {
			pollUrl: "https://evil.out-of-scope.invalid/events",
			authToken: secretPollToken,
			minIntervalMs: 30_000,
			nowMs: t0,
			fetchFn: mockFetch,
		});
		expect(blockedOutOfScope.polled).toBe(false);
		expect(blockedOutOfScope.throttled).toBe(false);
		expect(blockedOutOfScope.error).toContain("N-007");
		expect(fetchCalls).toBe(0);

		const blockedInvalidUrl = await runAutonomousOobPoll(state, root, scope, {
			pollUrl: "not-a-valid-url",
			authToken: secretPollToken,
			minIntervalMs: 30_000,
			nowMs: t0,
			fetchFn: mockFetch,
		});
		expect(blockedInvalidUrl.polled).toBe(false);
		expect(blockedInvalidUrl.throttled).toBe(false);
		expect(blockedInvalidUrl.error).toContain("N-007");
		expect(fetchCalls).toBe(0);

		// 同一时间戳 t0 立刻改用合法 pollUrl：不得被先前越界拦截锁死节流
		const poll1 = await runAutonomousOobPoll(state, root, scope, {
			pollUrl: "https://poll.oast.lab.test/events",
			authToken: secretPollToken,
			minIntervalMs: 30_000,
			nowMs: t0,
			fetchFn: mockFetch,
			applyToState: true,
		});

		expect(poll1.polled).toBe(true);
		expect(poll1.throttled).toBe(false);
		expect(fetchCalls).toBe(1);
		expect(poll1.newHits.length).toBe(2);
		expect(poll1.markedHitCanaryIds).toEqual([canary.id]);
		expect(poll1.evidenceFacts.length).toBe(1);

		const evFact = poll1.evidenceFacts[0]!;
		expect(evFact.id).toBe("f011");
		expect(evFact.kind).toBe("vuln");
		expect(evFact.verified).toBe(true);
		expect(evFact.verifyStage).toBe("confirmed");
		expect(evFact.output).toContain("OOB_CALLBACK_VERIFIED");
		expect(evFact.output).toContain(canary.fqdn);
		expect(evFact.output).toContain("10.20.30.40");
		expect(state.facts[evFact.id]).toBeDefined();

		// 确认 .nuwa/oob-canaries.json 已标记该 Canary 命中（matchedHits >= 2）
		const persistedCanaries = loadOobCanaries(root);
		const hitCanary = persistedCanaries.find((c) => c.id === canary.id);
		expect(hitCanary?.matchedHits).toBe(2);

		// 确认 poll authToken 绝不泄露
		expect(JSON.stringify(poll1)).not.toContain(secretPollToken);
		expect(readFileSync(join(root, ".nuwa", "auto-loops-state.json"), "utf8")).not.toContain(
			secretPollToken,
		);
		expect(statSync(join(root, ".nuwa", "auto-loops-state.json")).mode & 0o777).toBe(0o600);

		// 10s 后再次调用（未满 30s 节流窗口）：应被节流拦截且不触发网络请求
		const poll2 = await runAutonomousOobPoll(state, root, scope, {
			pollUrl: "https://poll.oast.lab.test/events",
			authToken: secretPollToken,
			minIntervalMs: 30_000,
			nowMs: t0 + 10_000,
			fetchFn: mockFetch,
		});
		expect(poll2.polled).toBe(false);
		expect(poll2.throttled).toBe(true);
		expect(poll2.nextPollInMs).toBe(20_000);
		expect(fetchCalls).toBe(1);

		// 35s 后再次调用返回相同 hitId：允许轮询但对已上报 hit 幂等去重，不重复生成实锤 Fact
		const poll3 = await runAutonomousOobPoll(state, root, scope, {
			pollUrl: "https://poll.oast.lab.test/events",
			authToken: secretPollToken,
			minIntervalMs: 30_000,
			nowMs: t0 + 35_000,
			fetchFn: mockFetch,
		});
		expect(poll3.polled).toBe(true);
		expect(poll3.throttled).toBe(false);
		expect(fetchCalls).toBe(2);
		expect(poll3.newHits.length).toBe(0);
		expect(poll3.evidenceFacts.length).toBe(0);
	});
});

describe("v6.0.0 Boost 自检加固回归（文件锁原子落锁与 SQLite Journal 去重）", () => {
	test("withLock 使用临时文件硬链接原子落锁：4 进程并发累加零丢写且空锁宽限期内不误抢", async () => {
		const root = makeTmpDir("nuwa-lock-race-");
		mkdirSync(join(root, ".nuwa"), { recursive: true });
		const counterFile = join(root, ".nuwa", "conc-counter.txt");
		writeFileSync(counterFile, "0", "utf8");

		// 1) 4 个真实并发子进程各持锁累加 20 次 -> 必须精确等于 80 且全程零空锁碰撞异常
		const workerScript = `
			import { readFileSync, writeFileSync } from "node:fs";
			import { withLock } from ${JSON.stringify(resolve(import.meta.dir, "..", "omp", "storage.ts"))};
			const root = process.argv[1];
			const counter = process.argv[2];
			for (let i = 0; i < 20; i++) {
				withLock(root, () => {
					const cur = Number(readFileSync(counter, "utf8").trim() || "0");
					writeFileSync(counter, String(cur + 1), "utf8");
				});
			}
		`;
		const procs = Array.from({ length: 4 }, () =>
			Bun.spawn([process.execPath, "-e", workerScript, root, counterFile], {
				stdout: "pipe",
				stderr: "pipe",
			}),
		);
		const codes = await Promise.all(procs.map((p) => p.exited));
		expect(codes).toEqual([0, 0, 0, 0]);
		expect(Number(readFileSync(counterFile, "utf8").trim())).toBe(80);

		// 2) 刚创建的 0 字节空锁文件在宽限期(<300ms)内被子进程补充完整活 PID 后，withLock 绝不误删活锁而是等待其超时/释放
		const lockFile = join(root, ".nuwa", "state.lock");
		writeFileSync(lockFile, "", "utf8");
		const updaterScript = `
			import { writeFileSync } from "node:fs";
			const lp = process.argv[1];
			setTimeout(() => {
				writeFileSync(lp, JSON.stringify({ pid: process.pid, ts: Date.now() }), "utf8");
			}, 40);
			setTimeout(() => process.exit(0), 220);
		`;
		const child = Bun.spawn([process.execPath, "-e", updaterScript, lockFile], {
			stdout: "ignore",
			stderr: "ignore",
		});
		const tStart = Date.now();
		expect(() => withLock(root, () => "should-timeout", { timeoutMs: 120 })).toThrow(/locked by pid/);
		expect(Date.now() - tStart).toBeGreaterThanOrEqual(35);
		await child.exited;
		rmSync(lockFile, { force: true });
	});

	test("appendJournal 在 dedupHash 冲突被 INSERT OR IGNORE 时返回 0，绝不残留前次 lastInsertRowid", () => {
		const root = makeTmpDir("nuwa-journal-dedup-");
		const store = new NuwaSqliteStore(root);
		try {
			const seq1 = store.appendJournal({ type: "evt_first", msg: "first" });
			const seq2 = store.appendJournal({ type: "evt_dedup", msg: "once" }, { dedupHash: "hash-only-once" });
			const seq3 = store.appendJournal({ type: "evt_third", msg: "third" });
			expect(seq1).toBe(1);
			expect(seq2).toBe(2);
			expect(seq3).toBe(3);

			// 冲突去重插入：res.changes === 0，必须返回 0 而非残留的 seq3 (3)
			const dupSeq = store.appendJournal(
				{ type: "evt_dedup", msg: "duplicate" },
				{ dedupHash: "hash-only-once" },
			);
			expect(dupSeq).toBe(0);

			const rows = store.rawDb.query("SELECT COUNT(*) AS cnt FROM journal").get() as { cnt: number };
			expect(rows.cnt).toBe(3);
		} finally {
			store.close();
		}
	});

	test("SQLite saveState 对缺省 statement/falsificationTest 等字段的历史或稀疏 HypothesisNode/Fact 安全落库不报 NOT NULL 错误", () => {
		const root = makeTmpDir("nuwa-sparse-hyp-");
		const store = new NuwaSqliteStore(root);
		const now = new Date().toISOString();
		try {
			const sparseState = {
				schema: 2,
				version: "6.0.0",
				project: {
					id: "sparse-proj",
					target: "http://127.0.0.1:8080",
					url: "http://127.0.0.1:8080",
					host: "127.0.0.1",
					port: 8080,
					scheme: "http",
					goal: "稀疏节点兼容测试",
					mode: "pentest",
					status: "running",
					phase: "vuln",
					createdAt: now,
					updatedAt: now,
				},
				facts: {
					f1: { id: "f1", kind: "note", title: "仅有基础字段的事实" },
				},
				intents: {
					i1: { id: "i1", phase: "recon", title: "缺少 detail 与 attempts 的意图" },
				},
				seq: { fact: 1, intent: 1 },
				runtime: {
					attemptedKeys: {
						"k1": { key: "k1", status: "done" },
					},
				},
				assets: {
					a1: { id: "a1", kind: "host", host: "127.0.0.1" },
				},
				hypotheses: {
					h_legacy: {
						id: "h_legacy",
						title: "仅含 rationale 的历史形态假设",
						rationale: "若候选节点成立则深入排查",
						requiredFacts: ["f1"],
						expectedGain: 75,
						estimatedCost: 10,
						confidence: 0.72,
						status: "open",
						createdAt: now,
						updatedAt: now,
					},
				},
			} as unknown as Parameters<NuwaSqliteStore["saveState"]>[0];

			expect(() => store.saveState(sparseState)).not.toThrow();
			const reloaded = store.loadState()!;
			expect(reloaded).not.toBeNull();
			expect(reloaded.facts.f1?.title).toBe("仅有基础字段的事实");
			expect(reloaded.facts.f1?.detail).toBe("");
			expect(reloaded.intents.i1?.title).toBe("缺少 detail 与 attempts 的意图");
			expect(reloaded.assets?.a1?.target).toBe("127.0.0.1");
			const hyp = reloaded.hypotheses?.h_legacy as unknown as Record<string, unknown>;
			expect(hyp).toBeDefined();
			expect(hyp.statement).toBe("若候选节点成立则深入排查");
			expect(hyp.rationale).toBe("若候选节点成立则深入排查");
			expect(hyp.falsificationTest).toBe("");
			expect(hyp.confidence).toBe(0.72);
			expect(hyp.status).toBe("open");
		} finally {
			store.close();
		}
	});
});
