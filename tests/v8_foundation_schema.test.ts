import { Database } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { readSqliteStateDaemon } from "../core/autonomous-doctor";
import { NuwaUnifiedEngine } from "../core/engine";
import { executeChainsCommand } from "../omp/graph-commands";
import {
	ALL_SQLITE_TABLES,
	NuwaSqliteStore,
	SQLITE_SCHEMA_VERSION,
	V1_CORE_DDL,
	V1_CORE_TABLES,
	V2_EXTENSION_TABLES,
	loadStateFromSqlite,
	migrateSqliteSchemaV1ToV2,
	openNuwaDb,
	openSqliteReadonlyZeroWrite,
	queryFactsByText,
	readSqliteSchemaVersion,
	sqliteDbPath,
} from "../omp/sqlite-store";
import { createInitialState, readCfg, saveStateJsonOnly } from "../omp/storage";
import { upsertSessionRole } from "../omp/session-vault";

const REPO_ROOT = resolve(import.meta.dir, "..");

const SPLIT_MODULE_PAIRS: ReadonlyArray<{ parent: string; child: string }> = [
	{ parent: "omp/autoexec.ts", child: "omp/autoexec-baseline.ts" },
	{ parent: "bin/nuwa-autonomous", child: "core/autonomous-doctor.ts" },
	{ parent: "omp/cdp-bridge.ts", child: "omp/cdp-client.ts" },
	{ parent: "omp/traffic-workbench.ts", child: "omp/traffic-mutator.ts" },
	{ parent: "core/engine.ts", child: "core/engine-helpers.ts" },
	{ parent: "omp/sandbox.ts", child: "omp/sandbox-egress.ts" },
	{ parent: "omp/chain-composer.ts", child: "omp/chain-capabilities.ts" },
	{ parent: "omp/storage.ts", child: "omp/storage-io.ts" },
	{ parent: "omp/graph-planner.ts", child: "omp/graph-dedup.ts" },
	{ parent: "omp/sqlite-store.ts", child: "omp/sqlite-schema.ts" },
];

function countLines(filePath: string): number {
	const buf = readFileSync(filePath);
	let newlines = 0;
	for (let i = 0; i < buf.length; i++) {
		if (buf[i] === 0x0a) newlines++;
	}
	return newlines;
}

function collectRepoCodeFiles(dir: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "archive") {
			continue;
		}
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			collectRepoCodeFiles(full, out);
		} else if (entry.isFile()) {
			const rel = relative(REPO_ROOT, full);
			if (
				rel.endsWith(".ts") ||
				rel.endsWith(".js") ||
				rel.endsWith(".py") ||
				rel.endsWith(".sh") ||
				rel.startsWith("bin/")
			) {
				out.push(rel);
			}
		}
	}
	return out;
}

function snapshotDirectoryFiles(dir: string): Record<string, { size: number; sha256: string; mtimeMs: number }> {
	const snap: Record<string, { size: number; sha256: string; mtimeMs: number }> = {};
	if (!existsSync(dir)) return snap;
	const walk = (cur: string) => {
		for (const ent of readdirSync(cur, { withFileTypes: true })) {
			const full = join(cur, ent.name);
			if (ent.isDirectory()) {
				walk(full);
			} else if (ent.isFile()) {
				const rel = relative(dir, full);
				const st = statSync(full);
				const raw = readFileSync(full);
				const sha256 = createHash("sha256").update(raw).digest("hex");
				snap[rel] = { size: st.size, sha256, mtimeMs: st.mtimeMs };
			}
		}
	};
	walk(dir);
	return snap;
}

describe("Wave 0 架构地基拆解、导出兼容性与 SQLite Schema v2 门禁", () => {
	test("1. 十大拆解模块各自严格 < 2,400 行、nuwa.ts < 1,000 行、全仓代码文件 < 2,500 行且无环无反向引用", () => {
		const nuwaLines = countLines(join(REPO_ROOT, "omp/nuwa.ts"));
		expect(nuwaLines).toBeLessThan(1000);

		for (const { parent, child } of SPLIT_MODULE_PAIRS) {
			const pFull = join(REPO_ROOT, parent);
			const cFull = join(REPO_ROOT, child);
			expect(existsSync(pFull)).toBe(true);
			expect(existsSync(cFull)).toBe(true);

			const pLines = countLines(pFull);
			const cLines = countLines(cFull);
			expect(pLines).toBeLessThan(2400);
			expect(cLines).toBeLessThan(2400);

			// 子模块严禁反向 import 父模块（严格单向 DAG）
			const childSrc = readFileSync(cFull, "utf8");
			const parentBase = parent.split("/").pop()!.replace(/\.ts$/, "");
			const reverseImportRe = new RegExp(`from\\s+["'](?:\\.|\\.\\.)[^"']*\\/${parentBase}(?:\\.ts)?["']`);
			expect(reverseImportRe.test(childSrc)).toBe(false);
		}

		// 全仓所有源码与脚本文件严格 < 2,500 行，且除入口外严禁 import ./nuwa
		const allCodeFiles = collectRepoCodeFiles(REPO_ROOT);
		expect(allCodeFiles.length).toBeGreaterThan(50);

		for (const rel of allCodeFiles) {
			const full = join(REPO_ROOT, rel);
			const lines = countLines(full);
			expect(lines).toBeLessThan(2500);

			if ((rel.startsWith("omp/") || rel.startsWith("core/")) && rel !== "omp/nuwa.ts" && !rel.endsWith(".d.ts")) {
				const src = readFileSync(full, "utf8");
				const stripped = src.replace(
					/^\s*import\s+type\s+[^;]+from\s+["'](?:\.|\.\.\/omp)\/nuwa["'];?\s*$/gm,
					"",
				);
				const hasRuntimeNuwaImport =
					/from\s+["'](?:\.|\.\.\/omp)\/nuwa["']/.test(stripped) ||
					/import\s*\(\s*["'](?:\.|\.\.\/omp)\/nuwa["']\s*\)/.test(stripped) ||
					/require\s*\(\s*["'](?:\.|\.\.\/omp)\/nuwa["']\s*\)/.test(stripped);
				expect(hasRuntimeNuwaImport).toBe(false);
			}
		}
	});

	test("2. 全部拆解模块与 omp/nuwa.ts 保持 100% 历史运行时导出向后兼容 re-export", async () => {
		const tsTargets = [
			"omp/nuwa.ts",
			"omp/autoexec.ts",
			"omp/cdp-bridge.ts",
			"omp/traffic-workbench.ts",
			"core/engine.ts",
			"omp/sandbox.ts",
			"omp/chain-composer.ts",
			"omp/storage.ts",
			"omp/graph-planner.ts",
			"omp/sqlite-store.ts",
		];

		for (const rel of tsTargets) {
			const curMod = (await import(join(REPO_ROOT, rel))) as Record<string, unknown>;
			const curKeys = new Set(Object.keys(curMod));
			expect(curKeys.size).toBeGreaterThan(0);

			// 若存在基线提交 86bd6e6，用 Bun.Transpiler 扫描原提交中的导出运行时符号并确认无缺失
			const gitShow = spawnSync("git", ["show", `86bd6e6:${rel}`], {
				cwd: REPO_ROOT,
				encoding: "utf8",
			});
			if (gitShow.status === 0 && gitShow.stdout) {
				const transpiler = new Bun.Transpiler({ loader: "ts" });
				const jsOut = transpiler.transformSync(gitShow.stdout);
				const scanned = transpiler.scan(jsOut);
				for (const expName of scanned.exports) {
					expect(curKeys.has(expName)).toBe(true);
				}
			}
		}

		const nuwaMod = (await import(join(REPO_ROOT, "omp/nuwa.ts"))) as Record<string, unknown>;
		expect(nuwaMod.SQLITE_SCHEMA_VERSION).toBe(2);
		expect(typeof nuwaMod.migrateSqliteSchemaV1ToV2).toBe("function");
		expect(typeof nuwaMod.openSqliteReadonlyZeroWrite).toBe("function");
	});

	test("3. SQLite Schema v1 -> v2 原子无损幂等迁移、全反例零明文脱敏、credFingerprint 幂等及活跃 -wal/-shm 只读零写盘", async () => {
		expect(SQLITE_SCHEMA_VERSION).toBe(2);
		expect(V1_CORE_TABLES.length).toBe(10);
		expect(V2_EXTENSION_TABLES).toEqual([
			"protocol_frames",
			"asset_credentials",
			"oob_correlations",
			"workflow_runs",
		]);
		expect(ALL_SQLITE_TABLES.length).toBe(14);

		const tmpRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-sqlite-mig-"));
		const walLiveRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-wal-live-"));
		const legacyJsonRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-json-ro-"));
		try {
			// --- A. 构造纯 v1 旧版 nuwa.db（DELETE 日志模式，仅有 10 张 v1 表且 schema_version = "1"） ---
			const nuwaDir = join(tmpRoot, ".nuwa");
			mkdirSync(nuwaDir, { recursive: true });
			const dbFile = sqliteDbPath(tmpRoot);
			const ts = "2026-11-20T00:00:00.000Z";

			const seedLegacyV1Db = (targetDbFile: string, mode: "DELETE" | "WAL") => {
				const db = new Database(targetDbFile, { create: true });
				db.exec(`PRAGMA journal_mode = ${mode};`);
				if (mode === "WAL") {
					db.exec("PRAGMA wal_autocheckpoint = 0;");
				}
				db.exec(V1_CORE_DDL);
				const insMeta = db.query("INSERT INTO meta (key, value, updated_at) VALUES (?, ?, ?)");
				insMeta.run("schema_version", "1", ts);
				insMeta.run("nuwa_schema", "1", ts);
				insMeta.run("nuwa_version", "7.0.0", ts);
				insMeta.run(
					"project_json",
					JSON.stringify({
						id: "v1-legacy-proj",
						target: "http://127.0.0.1:18088",
						url: "http://127.0.0.1:18088",
						host: "127.0.0.1",
						port: 18088,
						scheme: "http",
						goal: "v1 legacy migration test",
						mode: "pentest",
						phase: "surface",
						status: "active",
						createdAt: ts,
						updatedAt: ts,
					}),
					ts,
				);
				insMeta.run("seq_json", JSON.stringify({ fact: 2, intent: 1 }), ts);
				insMeta.run(
					"runtime_json",
					JSON.stringify({
						status: "active",
						turns: 3,
						stall: 0,
						idle: 0,
						tokens: 1200,
						startedAt: 1700000000000,
						lastSig: "v1",
						lastSettleAt: 0,
						completionRejects: 0,
						blockStreak: 0,
						pressure: 0,
					}),
					ts,
				);
				db.query(
					`INSERT INTO facts (id, kind, title, detail, command, output, created_at)
					 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				).run("f001", "endpoint", "发现 /api/v1/orders", "HTTP 200 JSON", "curl -s /api/v1/orders", '{"ok":true}', ts);
				db.query(
					`INSERT INTO facts_fts (fact_id, kind, title, detail, command, output, fact_key, target_key)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				).run("f001", "endpoint", "发现 /api/v1/orders", "HTTP 200 JSON", "curl -s /api/v1/orders", '{"ok":true}', "", "/api/v1/orders");
				db.query(
					`INSERT INTO intents (id, phase, intent_key, title, detail, from_json, status, priority, attempts, created_at)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				).run("i001", "surface", "surface:api", "API 契约梳理", "枚举端点", '["f001"]', "open", 85, 0, ts);
				return db;
			};

			const rawV1 = seedLegacyV1Db(dbFile, "DELETE");
			rawV1.close();

			// --- B1. 仅有 v1 旧表的历史 nuwa.db 只读打开：零写盘、不报错 ---
			const snapBeforeRo = snapshotDirectoryFiles(nuwaDir);
			expect(Object.keys(snapBeforeRo)).toEqual(["nuwa.db"]);

			const zeroRoDb = openSqliteReadonlyZeroWrite(dbFile);
			try {
				expect(readSqliteSchemaVersion(zeroRoDb)).toBe(1);
				for (const extTbl of V2_EXTENSION_TABLES) {
					const row = zeroRoDb
						.query("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
						.get(extTbl);
					expect(row).toBeNull();
				}
			} finally {
				zeroRoDb.close();
			}

			expect(loadStateFromSqlite(tmpRoot)?.project.id).toBe("v1-legacy-proj");
			expect(queryFactsByText(tmpRoot, "orders")[0]?.fact.id).toBe("f001");

			const roStore = new NuwaSqliteStore(tmpRoot, { readonly: true });
			try {
				expect(roStore.listProtocolFrames()).toEqual([]);
				expect(roStore.listAssetCredentials()).toEqual([]);
				expect(roStore.listOobCorrelations()).toEqual([]);
				expect(roStore.listWorkflowRuns()).toEqual([]);
			} finally {
				roStore.close();
			}

			openNuwaDb(tmpRoot, { readonly: true }).close();
			const engine = new NuwaUnifiedEngine({ projectRoot: tmpRoot, cwd: tmpRoot });
			const statusRo = await engine.callTool("nuwa_status", { root: tmpRoot });
			expect(statusRo.isError).toBe(false);
			expect(snapshotDirectoryFiles(nuwaDir)).toEqual(snapBeforeRo);

			// --- B2. [#131 P1-2 反例] 历史 v1 nuwa.db 同时存在活跃非空 -wal + -shm 时，全部只读接口严禁改写原目录 nuwa.db-shm ---
			const walDir = join(walLiveRoot, ".nuwa");
			mkdirSync(walDir, { recursive: true });
			const walDbFile = sqliteDbPath(walLiveRoot);
			// 通过保持一个活跃 WAL 写连接（或子进程异常退出遗留非空 -wal + -shm）制造真实非空 -wal 与 -shm
			const liveWalWriter = seedLegacyV1Db(walDbFile, "WAL");
			try {
				liveWalWriter
					.query(
						`INSERT INTO facts (id, kind, title, detail, command, output, created_at)
						 VALUES (?, ?, ?, ?, ?, ?, ?)`,
					)
					.run("f_uncheckpointed", "note", "WAL 未刷盘事实", "live wal fact", "echo wal", "ok", ts);

				expect(existsSync(`${walDbFile}-wal`)).toBe(true);
				expect(statSync(`${walDbFile}-wal`).size).toBeGreaterThan(0);
				expect(existsSync(`${walDbFile}-shm`)).toBe(true);

				const snapWalBefore = snapshotDirectoryFiles(walDir);
				expect(snapWalBefore["nuwa.db-shm"]).toBeDefined();

				const roWal1 = openSqliteReadonlyZeroWrite(walDbFile);
				try {
					const row = roWal1.query("SELECT title FROM facts WHERE id = 'f_uncheckpointed'").get() as { title?: string } | null;
					expect(row?.title).toBe("WAL 未刷盘事实");
				} finally {
					roWal1.close();
				}

				const roWalState = loadStateFromSqlite(walLiveRoot);
				expect(roWalState?.facts.f_uncheckpointed?.title).toBe("WAL 未刷盘事实");

				const daemonWalState = readSqliteStateDaemon(walLiveRoot);
				expect(daemonWalState?.facts?.f_uncheckpointed).toBeDefined();

				const roWalStore = new NuwaSqliteStore(walLiveRoot, { readonly: true });
				roWalStore.close();

				const snapWalAfter = snapshotDirectoryFiles(walDir);
				expect(snapWalAfter).toEqual(snapWalBefore);
			} finally {
				liveWalWriter.close();
			}

			// --- C. 遗留纯 state.json 目录只读零写盘验证 ---
			const legacyState = createInitialState(
				"http://127.0.0.1:18099",
				"legacy json only",
				"ctf",
				readCfg(),
			);
			saveStateJsonOnly(legacyJsonRoot, legacyState);
			const legacyNuwaDir = join(legacyJsonRoot, ".nuwa");
			const snapJsonBefore = snapshotDirectoryFiles(legacyNuwaDir);
			const jsonEngine = new NuwaUnifiedEngine({ projectRoot: legacyJsonRoot, cwd: legacyJsonRoot });
			expect((await jsonEngine.callTool("nuwa_status", { root: legacyJsonRoot })).isError).toBe(false);
			expect((await jsonEngine.callTool("nuwa_frontier", { root: legacyJsonRoot })).isError).toBe(false);
			expect((await jsonEngine.executeSlashCommand("status")).level).toBe("info");
			expect(snapshotDirectoryFiles(legacyNuwaDir)).toEqual(snapJsonBefore);

			// --- D0. [#131 P2 验证] migrateSqliteSchemaV1ToV2 单事务原子回滚保护 ---
			const atomicTestDb = new Database(":memory:");
			try {
				atomicTestDb.exec(V1_CORE_DDL);
				atomicTestDb
					.query("INSERT INTO meta (key, value, updated_at) VALUES ('schema_version', '1', ?)")
					.run(ts);
				// 植入拒绝更新 schema_version 的触发器，模拟迁移事务末尾写入失败
				atomicTestDb.exec(`
					CREATE TRIGGER abort_schema_ver_update
					BEFORE INSERT ON meta
					WHEN NEW.key = 'schema_version'
					BEGIN
						SELECT RAISE(ABORT, 'simulated meta write failure');
					END;
				`);
				expect(() => migrateSqliteSchemaV1ToV2(atomicTestDb)).toThrow(/simulated meta write failure/);
				// 单事务回滚后：版本号仍为 1，且 4 张 v2 新表也一并回滚不存在（零半成品状态）
				expect(readSqliteSchemaVersion(atomicTestDb)).toBe(1);
				for (const extTbl of V2_EXTENSION_TABLES) {
					expect(
						atomicTestDb.query("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(extTbl),
					).toBeNull();
				}
			} finally {
				atomicTestDb.close();
			}

			// --- D. [#131 P1-1 全反例] v1 -> v2 迁移、credFingerprint 多次读写幂等、14 类明文泄漏反例全量二进制零残留 ---
			const secretBearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbi05OSJ9.superSecretSig998877";
			const leakSecrets = {
				jsonPass: "PlainJsonPass_991122",
				jsonApiKey: "ak_json_secret_334455",
				jsonAccessToken: "at_json_secret_556677",
				urlUserPass: "UrlBasicPass_778899",
				urlQueryTok: "UrlQueryTok_112233",
				urlQueryKey: "UrlQueryApiKey_445566",
				totpCamel: "JBSWY3DPEHPK3PXP_CAMEL",
				totpSnake: "JBSWY3DPEHPK3PXP_SNAKE",
				otpSecret: "OTP_RAW_SECRET_889900",
				mfaSecret: "MFA_RAW_SECRET_665544",
				opaqueToken: "opaq_tok_live_99001122",
				rawSessionId: "sess_secret_cookie_id_774411",
				rawCredential: "cred_raw_secret_val_332211",
				rawSecretKey: "sk_custom_hmac_key_558899",
				rawAuthHeader: "Bearer custom_hdr_tok_667788",
				mixedStars: "p@ss***SecretLeak9988",
			};
			upsertSessionRole(tmpRoot, { role: "admin", bearer: secretBearer });

			const rwStore = new NuwaSqliteStore(tmpRoot);
			try {
				expect(readSqliteSchemaVersion(rwStore.rawDb)).toBe(2);
				expect(migrateSqliteSchemaV1ToV2(rwStore.rawDb).migrated).toBe(false);

				// 验证 ExecLedger 追踪用 sessionId 不被误掩码
				rwStore.appendExecLedger({
					seq: 1,
					ts: "2026-11-28T00:00:00.000Z",
					tool: "bash",
					command: "curl -s http://127.0.0.1:18088/health",
					sessionId: "cli-trace-session-001",
					agentName: "main",
					sha1: "a".repeat(40),
					normSha1: "b".repeat(40),
					bytes: 12,
					snippet: "ok",
				});
				expect(rwStore.listExecLedger(10)[0]?.sessionId).toBe("cli-trace-session-001");

				// 1) credFingerprint 读写幂等性 + verifiedEndpoint URL userinfo/query + 伪掩码 mixedStars 反例
				rwStore.upsertAssetCredential({
					id: "ac-1",
					assetId: "asset-api",
					host: "127.0.0.1",
					port: 18088,
					role: "admin",
					credKind: "bearer",
					credFingerprint: secretBearer,
					maskedPreview: leakSecrets.mixedStars,
					status: "valid",
					verifiedEndpoint: `http://admin:${leakSecrets.urlUserPass}@127.0.0.1:18088/api/me?token=${leakSecrets.urlQueryTok}&api_key=${leakSecrets.urlQueryKey}`,
					verifiedStatusCode: 200,
					createdAt: "2026-11-28T00:00:00.000Z",
					updatedAt: "2026-11-28T00:00:00.000Z",
					extra: {
						totpSecret: leakSecrets.totpCamel,
						totp_secret: leakSecrets.totpSnake,
						credential: leakSecrets.rawCredential,
						secretKey: leakSecrets.rawSecretKey,
					},
				});

				const firstReadCred = rwStore.listAssetCredentials({ assetId: "asset-api" })[0]!;
				expect(firstReadCred.credFingerprint).toMatch(/^sha256:[0-9a-f]{32}$/);
				const fp1 = firstReadCred.credFingerprint;

				// 读出后更新 status 并连续写回两次，验证 credFingerprint 100% 恒定不变异
				rwStore.upsertAssetCredential({
					...firstReadCred,
					status: "expired",
					updatedAt: "2026-11-28T00:05:00.000Z",
				});
				const secondReadCred = rwStore.listAssetCredentials({ assetId: "asset-api" })[0]!;
				expect(secondReadCred.credFingerprint).toBe(fp1);

				rwStore.upsertAssetCredential({
					...secondReadCred,
					status: "valid",
					updatedAt: "2026-11-28T00:10:00.000Z",
				});
				const thirdReadCred = rwStore.listAssetCredentials({ assetId: "asset-api" })[0]!;
				expect(thirdReadCred.credFingerprint).toBe(fp1);

				// 2) protocol_frames：JSON 双引号敏感键值、schemaSummary/extra 中的 MFA/OTP/sessionId/authHeader/mixedStars
				rwStore.upsertProtocolFrame({
					id: "pf-1",
					ts: "2026-11-28T00:00:00.000Z",
					protocol: "graphql",
					direction: "request",
					url: `http://127.0.0.1:18088/graphql?token=${leakSecrets.urlQueryTok}&api_key=${leakSecrets.urlQueryKey}`,
					host: "127.0.0.1",
					operationName: "LoginMutation",
					role: "admin",
					status: 200,
					headers: { Authorization: `Bearer ${secretBearer}`, "X-Custom-Auth": leakSecrets.mixedStars },
					payloadPreview: JSON.stringify({
						password: leakSecrets.jsonPass,
						api_key: leakSecrets.jsonApiKey,
						access_token: leakSecrets.jsonAccessToken,
						mixed: `password=${leakSecrets.mixedStars}`,
					}),
					schemaSummary: {
						otp_secret: leakSecrets.otpSecret,
						mfa_secret: leakSecrets.mfaSecret,
						token: leakSecrets.opaqueToken,
						sessionId: leakSecrets.rawSessionId,
					},
					extra: {
						session_id: leakSecrets.rawSessionId,
						authHeader: leakSecrets.rawAuthHeader,
						password: leakSecrets.mixedStars,
					},
				});

				// 3) oob_correlations 与 workflow_runs steps 敏感字段全覆盖
				rwStore.upsertOobCorrelation({
					canaryId: "cny-001",
					projectId: "v1-legacy-proj",
					intentId: "i001",
					endpoint: `/api/v1/webhook?api_key=${leakSecrets.urlQueryKey}`,
					paramName: "callbackUrl",
					templateHash: "abcd1234",
					authRole: "admin",
					channel: "http",
					status: "correlated",
					callbackTs: "2026-11-28T00:01:00.000Z",
					callbackSourceIp: "127.0.0.1",
					callbackDetail: `{"password":"${leakSecrets.jsonPass}","access_token":"${leakSecrets.jsonAccessToken}"}`,
					createdAt: "2026-11-28T00:00:00.000Z",
				});

				rwStore.upsertWorkflowRun({
					runId: "wf-001",
					workflowKind: "second_order",
					actionLevel: "L2_SCOPED_STATEFUL",
					intentId: "i001",
					targetUrl: `http://127.0.0.1:18088/api/v1/orders?token=${leakSecrets.urlQueryTok}`,
					role: "admin",
					status: "passed",
					stepCount: 2,
					cleanupExecuted: true,
					startedAt: "2026-11-28T00:00:00.000Z",
					finishedAt: "2026-11-28T00:00:01.000Z",
					summary: `authenticated with ${secretBearer}`,
					steps: [
						{
							step: 1,
							token: leakSecrets.opaqueToken,
							totpSecret: leakSecrets.totpCamel,
							sessionId: leakSecrets.rawSessionId,
							secretKey: leakSecrets.rawSecretKey,
							credential: leakSecrets.mixedStars,
						},
					],
				});

				rwStore.rawDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
			} finally {
				rwStore.close();
			}

			// 二进制扫描 nuwa.db 原始字节，确认上述全部 17 个敏感明文片段 0 泄漏
			const dbRawText = readFileSync(dbFile).toString("latin1");
			expect(dbRawText.includes(secretBearer)).toBe(false);
			expect(dbRawText.includes("superSecretSig998877")).toBe(false);
			expect(dbRawText.includes("SecretLeak9988")).toBe(false);
			for (const [, plainSecret] of Object.entries(leakSecrets)) {
				expect(dbRawText.includes(plainSecret)).toBe(false);
			}
		} finally {
			rmSync(tmpRoot, { recursive: true, force: true });
			rmSync(walLiveRoot, { recursive: true, force: true });
			rmSync(legacyJsonRoot, { recursive: true, force: true });
		}
	});

	test(
		"4. bin/nuwa-autonomous 仓库态防外部 --agent-home 劫持，且安装态 doctor 严检 8+2 个拆解底层模块缺失",
		() => {
			const sbBase = mkdtempSync(join(tmpdir(), "nuwa-v8-install-doc-"));
			const hijackHome = join(sbBase, "hijack-old-home");
			const agentHome = join(sbBase, "agent-home");
			const binDir = join(sbBase, "bin");
			const ompStubDir = join(sbBase, "omp-stub");
			try {
				mkdirSync(ompStubDir, { recursive: true });
				const ompStub = join(ompStubDir, "omp");
				writeFileSync(ompStub, "#!/usr/bin/env bash\necho 'omp 18.16.0'\n", "utf8");
				chmodSync(ompStub, 0o755);

				// --- [#131 P1-3 反例] 在外部 <hijackHome>/nuwa-core/core/autonomous-doctor.ts 植入恶意抛错假模块 ---
				mkdirSync(join(hijackHome, "nuwa-core", "core"), { recursive: true });
				writeFileSync(
					join(hijackHome, "nuwa-core", "core", "autonomous-doctor.ts"),
					'throw new Error("HIJACKED_BY_EXTERNAL_AGENT_HOME");\n',
					"utf8",
				);

				// 仓库态同时传入 --agent-home <hijackHome> 与 PI_AGENT_HOME=<hijackHome>：必须优先加载同仓 ../core/autonomous-doctor.ts，绝不被劫持崩溃
				const repoAntiHijack = spawnSync(
					"bun",
					[join(REPO_ROOT, "bin/nuwa-autonomous"), "doctor", "--agent-home", hijackHome, "--omp-bin", ompStub, "--json"],
					{
						cwd: tmpdir(),
						env: {
							...process.env,
							PI_AGENT_HOME: hijackHome,
						},
						encoding: "utf8",
					},
				);
				expect(repoAntiHijack.stderr).not.toContain("HIJACKED_BY_EXTERNAL_AGENT_HOME");
				const antiHijackJson = JSON.parse(repoAntiHijack.stdout) as { agentHome: string; checks?: Record<string, any> };
				expect(antiHijackJson.agentHome).toBe(hijackHome);
				expect(typeof antiHijackJson.checks?.extension).toBe("object");

				// --- 独立 /tmp 沙盒运行 install.sh 后跨目录执行 installed_bin/nuwa-autonomous doctor --json ---
				const installEnv: Record<string, string | undefined> = {
					...process.env,
					PI_AGENT_HOME: agentHome,
					NUWA_BIN_DIR: binDir,
					PATH: `${ompStubDir}:${process.env.PATH ?? ""}`,
				};
				delete installEnv.BUN_OPTIONS;

				const inst = spawnSync("bash", [join(REPO_ROOT, "install.sh")], {
					cwd: REPO_ROOT,
					env: installEnv as NodeJS.ProcessEnv,
					encoding: "utf8",
					timeout: 60_000,
				});
				expect(inst.status).toBe(0);

				const installedBin = join(binDir, "nuwa-autonomous");
				expect(existsSync(installedBin)).toBe(true);
				expect(existsSync(join(agentHome, "nuwa-core", "core", "autonomous-doctor.ts"))).toBe(true);

				// 2a) 完整安装态 doctor --json 正常通过（exitCode=0, ok=true, submodulesMissing=[]）
				const docWithEnv = spawnSync("bun", [installedBin, "doctor", "--json", "--omp-bin", ompStub], {
					cwd: tmpdir(),
					env: installEnv as NodeJS.ProcessEnv,
					encoding: "utf8",
				});
				expect(docWithEnv.status).toBe(0);
				const jsonWithEnv = JSON.parse(docWithEnv.stdout) as {
					ok: boolean;
					exitCode: number;
					checks: { extension: { submodulesFound: string[]; submodulesMissing: string[]; nuwaCoreMissing: string[] } };
				};
				expect(jsonWithEnv.ok).toBe(true);
				expect(jsonWithEnv.exitCode).toBe(0);
				expect(jsonWithEnv.checks.extension.submodulesFound.length).toBe(8);
				expect(jsonWithEnv.checks.extension.submodulesMissing).toEqual([]);
				expect(jsonWithEnv.checks.extension.nuwaCoreMissing).toEqual([]);

				// 2b) 剥离 PI_AGENT_HOME 环境变量，仅通过 --agent-home 参数跨目录运行
				const strippedEnv: Record<string, string | undefined> = {
					...process.env,
					HOME: sbBase,
					PATH: `${ompStubDir}:${process.env.PATH ?? ""}`,
				};
				delete strippedEnv.PI_AGENT_HOME;
				delete strippedEnv.NUWA_CORE_DIR;
				delete strippedEnv.BUN_OPTIONS;

				const docCliFlag = spawnSync(
					"bun",
					[installedBin, "doctor", "--agent-home", agentHome, "--omp-bin", ompStub, "--json"],
					{
						cwd: tmpdir(),
						env: strippedEnv as NodeJS.ProcessEnv,
						encoding: "utf8",
					},
				);
				expect(docCliFlag.status).toBe(0);
				expect((JSON.parse(docCliFlag.stdout) as { ok: boolean }).ok).toBe(true);

				// 2c) [#131 P1-4 反例] 删除新拆解底层子模块 storage-io.ts / sqlite-schema.ts / autoexec-baseline.ts 及 engine-helpers.ts 后，doctor 必须报错返回 exitCode=1, ok=false
				const extDir = join(agentHome, "extensions", "nuwa-omp");
				rmSync(join(extDir, "storage-io.ts"), { force: true });
				rmSync(join(extDir, "sqlite-schema.ts"), { force: true });
				rmSync(join(extDir, "autoexec-baseline.ts"), { force: true });
				rmSync(join(agentHome, "nuwa-core", "core", "engine-helpers.ts"), { force: true });

				const docBroken = spawnSync("bun", [installedBin, "doctor", "--json", "--omp-bin", ompStub], {
					cwd: tmpdir(),
					env: installEnv as NodeJS.ProcessEnv,
					encoding: "utf8",
				});
				expect(docBroken.status).toBe(1);
				const jsonBroken = JSON.parse(docBroken.stdout) as {
					ok: boolean;
					exitCode: number;
					checks: { extension: { ok: boolean; submodulesMissing: string[]; nuwaCoreMissing: string[]; reason?: string } };
				};
				expect(jsonBroken.ok).toBe(false);
				expect(jsonBroken.exitCode).toBe(1);
				expect(jsonBroken.checks.extension.ok).toBe(false);
				expect(jsonBroken.checks.extension.submodulesMissing).toEqual([
					"storage-io.ts",
					"sqlite-schema.ts",
					"autoexec-baseline.ts",
				]);
				expect(jsonBroken.checks.extension.nuwaCoreMissing).toEqual(["engine-helpers.ts"]);
			} finally {
				rmSync(sbBase, { recursive: true, force: true });
			}
		},
		35_000,
	);

	test("5. executeChainsCommand(root, 'verify') 在入口锁前预读拦截终态项目，严格零写盘零发包", async () => {
		const termRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-chains-term-"));
		try {
			const st = createInitialState(
				"http://127.0.0.1:19999",
				"terminal chains verify guard",
				"pentest",
				readCfg(),
			);
			st.project.status = "sealed_negative";
			st.runtime.status = "sealed_negative";
			st.facts.f001 = {
				id: "f001",
				kind: "endpoint",
				title: "前端泄露内部导出路由 /internal/export",
				detail: "webpack sourcemap 暴露 /internal/export?ticket={{exportTicket}}",
				createdAt: "2026-11-28T00:00:00.000Z",
				meta: { paths: ["/internal/export"] },
			};
			st.facts.f002 = {
				id: "f002",
				kind: "vuln",
				title: "审批单越权泄露一次性 export_ticket",
				detail: 'GET /api/approvals/2 返回 {"export_ticket":"tk_123456"}',
				createdAt: "2026-11-28T00:00:01.000Z",
				meta: { paths: ["/api/approvals/2"] },
			};
			saveStateJsonOnly(termRoot, st);

			const nuwaDir = join(termRoot, ".nuwa");
			const beforeSnap = snapshotDirectoryFiles(nuwaDir);

			const res = await executeChainsCommand(termRoot, "verify");
			expect(res.level).toBe("error");
			expect(res.msg).toContain("已处于终态 (sealed_negative)");

			const afterSnap = snapshotDirectoryFiles(nuwaDir);
			expect(afterSnap).toEqual(beforeSnap);
		} finally {
			rmSync(termRoot, { recursive: true, force: true });
		}
	});
});
