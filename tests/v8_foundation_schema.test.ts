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

	test("3. SQLite Schema v1 -> v2 平滑无损幂等迁移、4 张新表脱敏存取及 v1/JSON 只读零写盘", async () => {
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
		const legacyJsonRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-json-ro-"));
		try {
			// --- A. 构造纯 v1 旧版 nuwa.db（仅有 10 张 v1 表且 schema_version = "1"） ---
			const nuwaDir = join(tmpRoot, ".nuwa");
			mkdirSync(nuwaDir, { recursive: true });
			const dbFile = sqliteDbPath(tmpRoot);

			const rawV1 = new Database(dbFile, { create: true });
			try {
				rawV1.exec("PRAGMA journal_mode = DELETE;");
				rawV1.exec(V1_CORE_DDL);
				const ts = "2026-11-20T00:00:00.000Z";
				const insMeta = rawV1.query("INSERT INTO meta (key, value, updated_at) VALUES (?, ?, ?)");
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
				rawV1
					.query(
						`INSERT INTO facts (id, kind, title, detail, command, output, created_at)
						 VALUES (?, ?, ?, ?, ?, ?, ?)`,
					)
					.run("f001", "endpoint", "发现 /api/v1/orders", "HTTP 200 JSON", "curl -s /api/v1/orders", '{"ok":true}', ts);
				rawV1
					.query(
						`INSERT INTO facts_fts (fact_id, kind, title, detail, command, output, fact_key, target_key)
						 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
					)
					.run("f001", "endpoint", "发现 /api/v1/orders", "HTTP 200 JSON", "curl -s /api/v1/orders", '{"ok":true}', "", "/api/v1/orders");
				rawV1
					.query(
						`INSERT INTO intents (id, phase, intent_key, title, detail, from_json, status, priority, attempts, created_at)
						 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					)
					.run("i001", "surface", "surface:api", "API 契约梳理", "枚举端点", '["f001"]', "open", 85, 0, ts);
			} finally {
				rawV1.close();
			}

			// 确认此时没有任何 v2 扩展表
			const snapBeforeRo = snapshotDirectoryFiles(nuwaDir);
			expect(Object.keys(snapBeforeRo)).toEqual(["nuwa.db"]);

			// --- B. 在仅有 v1 旧表的历史 nuwa.db 上执行多种只读操作：零写盘、不报错 ---
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

			const roLoaded = loadStateFromSqlite(tmpRoot);
			expect(roLoaded?.project.id).toBe("v1-legacy-proj");
			expect(roLoaded?.facts.f001?.title).toBe("发现 /api/v1/orders");

			const ftsHits = queryFactsByText(tmpRoot, "orders");
			expect(ftsHits.length).toBe(1);
			expect(ftsHits[0]?.fact.id).toBe("f001");

			const roStore = new NuwaSqliteStore(tmpRoot, { readonly: true });
			try {
				expect(roStore.listProtocolFrames()).toEqual([]);
				expect(roStore.listAssetCredentials()).toEqual([]);
				expect(roStore.listOobCorrelations()).toEqual([]);
				expect(roStore.listWorkflowRuns()).toEqual([]);
			} finally {
				roStore.close();
			}

			const roDbDirect = openNuwaDb(tmpRoot, { readonly: true });
			roDbDirect.close();

			const engine = new NuwaUnifiedEngine({ projectRoot: tmpRoot, cwd: tmpRoot });
			const statusRo = await engine.callTool("nuwa_status", { root: tmpRoot });
			expect(statusRo.isError).toBe(false);
			expect(statusRo.content[0]?.text).toContain("http://127.0.0.1:18088");
			expect(statusRo.content[0]?.text).toContain("v1 legacy migration test");

			const snapAfterRo = snapshotDirectoryFiles(nuwaDir);
			expect(snapAfterRo).toEqual(snapBeforeRo);

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
			expect(existsSync(join(legacyNuwaDir, "nuwa.db"))).toBe(false);

			const jsonEngine = new NuwaUnifiedEngine({ projectRoot: legacyJsonRoot, cwd: legacyJsonRoot });
			const stRes = await jsonEngine.callTool("nuwa_status", { root: legacyJsonRoot });
			expect(stRes.isError).toBe(false);
			const frRes = await jsonEngine.callTool("nuwa_frontier", { root: legacyJsonRoot });
			expect(frRes.isError).toBe(false);
			const slStatus = await jsonEngine.executeSlashCommand("status");
			expect(slStatus.level).toBe("info");
			const slScope = await jsonEngine.executeSlashCommand("scope show");
			expect(slScope.level).toBe("info");
			const slChains = await jsonEngine.executeSlashCommand("chains list");
			expect(slChains.level).toBe("info");

			const snapJsonAfter = snapshotDirectoryFiles(legacyNuwaDir);
			expect(snapJsonAfter).toEqual(snapJsonBefore);
			expect(existsSync(join(legacyNuwaDir, "nuwa.db"))).toBe(false);

			// --- D. 旧 v1 库首次读写打开：自动无损迁移至 Schema v2，多次执行严格幂等 ---
			const secretBearer = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbi05OSJ9.superSecretSig998877";
			upsertSessionRole(tmpRoot, { role: "admin", bearer: secretBearer });

			const rwStore = new NuwaSqliteStore(tmpRoot);
			try {
				expect(readSqliteSchemaVersion(rwStore.rawDb)).toBe(2);
				for (const tbl of ALL_SQLITE_TABLES) {
					const found = rwStore.rawDb
						.query("SELECT name FROM sqlite_master WHERE type='table' AND name=?")
						.get(tbl) as { name?: string } | null;
					expect(found?.name).toBe(tbl);
				}

				// 存量 v1 数据 100% 无损保留
				const migratedState = rwStore.loadState();
				expect(migratedState?.project.id).toBe("v1-legacy-proj");
				expect(migratedState?.facts.f001?.title).toBe("发现 /api/v1/orders");
				expect(migratedState?.intents.i001?.key).toBe("surface:api");

				// 二次调用 migrateSqliteSchemaV1ToV2 严格幂等
				const secondMig = migrateSqliteSchemaV1ToV2(rwStore.rawDb);
				expect(secondMig).toEqual({
					migrated: false,
					previousVersion: 2,
					currentVersion: 2,
					createdTables: [],
				});

				// 4 张 v2 扩展表写入与强制脱敏校验
				rwStore.upsertProtocolFrame({
					id: "pf-1",
					ts: "2026-11-28T00:00:00.000Z",
					protocol: "graphql",
					direction: "request",
					url: "http://127.0.0.1:18088/graphql",
					host: "127.0.0.1",
					operationName: "GetUserOrders",
					role: "admin",
					status: 200,
					headers: { Authorization: `Bearer ${secretBearer}`, "Content-Type": "application/json" },
					payloadPreview: `{"token":"${secretBearer}"}`,
				});
				rwStore.upsertAssetCredential({
					id: "ac-1",
					assetId: "asset-api",
					host: "127.0.0.1",
					port: 18088,
					role: "admin",
					credKind: "bearer",
					credFingerprint: secretBearer,
					maskedPreview: secretBearer,
					status: "valid",
					verifiedEndpoint: "/api/v1/orders",
					verifiedStatusCode: 200,
					createdAt: "2026-11-28T00:00:00.000Z",
					updatedAt: "2026-11-28T00:00:00.000Z",
				});
				rwStore.upsertOobCorrelation({
					canaryId: "cny-001",
					projectId: "v1-legacy-proj",
					intentId: "i001",
					endpoint: "/api/v1/webhook",
					paramName: "callbackUrl",
					templateHash: "abcd1234",
					authRole: "admin",
					channel: "http",
					status: "correlated",
					callbackTs: "2026-11-28T00:01:00.000Z",
					callbackSourceIp: "127.0.0.1",
					callbackDetail: `Authorization: Bearer ${secretBearer}`,
					createdAt: "2026-11-28T00:00:00.000Z",
				});
				rwStore.upsertWorkflowRun({
					runId: "wf-001",
					workflowKind: "second_order",
					actionLevel: "L2_SCOPED_STATEFUL",
					intentId: "i001",
					targetUrl: "http://127.0.0.1:18088/api/v1/orders",
					role: "admin",
					status: "passed",
					stepCount: 2,
					cleanupExecuted: true,
					startedAt: "2026-11-28T00:00:00.000Z",
					finishedAt: "2026-11-28T00:00:01.000Z",
					summary: `authenticated with ${secretBearer}`,
				});

				expect(rwStore.listProtocolFrames().length).toBe(1);
				expect(rwStore.listAssetCredentials().length).toBe(1);
				expect(rwStore.listOobCorrelations().length).toBe(1);
				expect(rwStore.listWorkflowRuns().length).toBe(1);

				rwStore.rawDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
			} finally {
				rwStore.close();
			}

			// 二进制扫描 nuwa.db 确保绝无明文凭据泄漏
			const dbRawText = readFileSync(dbFile).toString("latin1");
			expect(dbRawText.includes(secretBearer)).toBe(false);
			expect(dbRawText.includes("superSecretSig998877")).toBe(false);
		} finally {
			rmSync(tmpRoot, { recursive: true, force: true });
			rmSync(legacyJsonRoot, { recursive: true, force: true });
		}
	});

	test(
		"4. bin/nuwa-autonomous 在仓库态与沙盒安装态（含跨目录无环境变量）均能准确动态加载 core/autonomous-doctor.ts",
		() => {
		// 1) 仓库态直接运行 doctor --json
		const repoRun = spawnSync("bun", [join(REPO_ROOT, "bin/nuwa-autonomous"), "doctor", "--json"], {
			cwd: tmpdir(),
			encoding: "utf8",
		});
		const repoParsed = JSON.parse(repoRun.stdout) as { checks?: Record<string, unknown> };
		expect(typeof repoParsed.checks?.extension).toBe("object");

		// 2) 独立 /tmp 沙盒运行 install.sh 后跨目录执行 installed_bin/nuwa-autonomous doctor --json
		const sbBase = mkdtempSync(join(tmpdir(), "nuwa-v8-install-doc-"));
		const agentHome = join(sbBase, "agent-home");
		const binDir = join(sbBase, "bin");
		const ompStubDir = join(sbBase, "omp-stub");
		try {
			mkdirSync(ompStubDir, { recursive: true });
			const ompStub = join(ompStubDir, "omp");
			writeFileSync(ompStub, "#!/usr/bin/env bash\necho 'omp 18.16.0'\n", "utf8");
			chmodSync(ompStub, 0o755);

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

			// 2a) 带 PI_AGENT_HOME 从 /tmp 运行
			const docWithEnv = spawnSync("bun", [installedBin, "doctor", "--json", "--omp-bin", ompStub], {
				cwd: tmpdir(),
				env: installEnv as NodeJS.ProcessEnv,
				encoding: "utf8",
			});
			expect(docWithEnv.status).toBe(0);
			const jsonWithEnv = JSON.parse(docWithEnv.stdout) as { ok: boolean; exitCode: number };
			expect(jsonWithEnv.ok).toBe(true);
			expect(jsonWithEnv.exitCode).toBe(0);

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
			const jsonCliFlag = JSON.parse(docCliFlag.stdout) as { ok: boolean; agentHome: string };
			expect(jsonCliFlag.ok).toBe(true);
			expect(jsonCliFlag.agentHome).toBe(agentHome);

			// 2c) 既无 PI_AGENT_HOME 也无 --agent-home，依靠同目录 nuwa-mcp 指针解析 CORE_DIR 运行 --help
			const helpNoEnv = spawnSync("bun", [installedBin, "--help"], {
				cwd: tmpdir(),
				env: strippedEnv as NodeJS.ProcessEnv,
				encoding: "utf8",
			});
			expect(helpNoEnv.status).toBe(0);
			expect(helpNoEnv.stdout).toContain("nuwa-autonomous");
		} finally {
			rmSync(sbBase, { recursive: true, force: true });
		}
	},
	30_000,
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
