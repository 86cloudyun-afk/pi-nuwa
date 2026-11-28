/**
 * 女娲 v8.0.0 端到端全栈总装集成测试（Wave 2 Full-Stack Wiring & Zero-Write Invariants）。
 */
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
import * as http from "node:http";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import * as nuwaMod from "../omp/nuwa";
import { runL4BenchmarkSuite } from "../benchmarks/l4-arena/run-l4-eval";

const REPO_ROOT = resolve(import.meta.dir, "..");

function countLines(filePath: string): number {
	const buf = readFileSync(filePath);
	let n = 0;
	for (let i = 0; i < buf.length; i++) {
		if (buf[i] === 0x0a) n++;
	}
	return n;
}

function snapshotDir(dir: string): Record<string, { size: number; sha256: string; mtimeMs: number }> {
	const snap: Record<string, { size: number; sha256: string; mtimeMs: number }> = {};
	if (!existsSync(dir)) return snap;
	const walk = (cur: string) => {
		for (const ent of readdirSync(cur, { withFileTypes: true })) {
			const full = join(cur, ent.name);
			if (ent.isDirectory()) walk(full);
			else if (ent.isFile()) {
				const rel = relative(dir, full);
				const st = statSync(full);
				const sha256 = createHash("sha256").update(readFileSync(full)).digest("hex");
				snap[rel] = { size: st.size, sha256, mtimeMs: st.mtimeMs };
			}
		}
	};
	walk(dir);
	return snap;
}

describe("v8.0.0 全栈总装、模块行数红线与导出兼容性", () => {
	test("1. VERSION=8.0.0、nuwa.ts < 1000 行、全部 core/omp/kb/bin 代码严格 < 2500 行且全量导出齐备", () => {
		expect(nuwaMod.VERSION).toBe("8.0.0");
		expect(nuwaMod.NUWA_VERSION).toBe("8.0.0");
		expect(nuwaMod.SQLITE_SCHEMA_VERSION).toBe(2);
		expect(nuwaMod.NUWA_SUBCOMMANDS).toContain("proto");
		expect(nuwaMod.NUWA_SUBCOMMANDS).toContain("pivot");
		expect(nuwaMod.NUWA_SUBCOMMANDS).toContain("rgs");

		// 验证 v8 核心引擎函数均已从 omp/nuwa.ts 重导出
		expect(typeof nuwaMod.classifyWorkflowAction).toBe("function");
		expect(typeof nuwaMod.executeStatefulWorkflowChain).toBe("function");
		expect(typeof nuwaMod.probeMassAssignment).toBe("function");
		expect(typeof nuwaMod.verifySecondOrderWorkflow).toBe("function");
		expect(typeof nuwaMod.runBarrierRaceProbe).toBe("function");
		expect(typeof nuwaMod.generateTotpCode).toBe("function");
		expect(typeof nuwaMod.ensureSessionFresh).toBe("function");
		expect(typeof nuwaMod.executeInPageStatefulSignedProbe).toBe("function");
		expect(typeof nuwaMod.inspectGraphQLSchema).toBe("function");
		expect(typeof nuwaMod.parseRscFlightStream).toBe("function");
		expect(typeof nuwaMod.encodeGrpcWebFrame).toBe("function");
		expect(typeof nuwaMod.verifyCredentialPivot).toBe("function");
		expect(typeof nuwaMod.resolveAssetRoutePlan).toBe("function");
		expect(typeof nuwaMod.probeViaConfirmedSsrf).toBe("function");
		expect(typeof nuwaMod.GatewayAdaptiveController).toBe("function");
		expect(typeof nuwaMod.IsomorphicTrapDetector).toBe("function");
		expect(typeof nuwaMod.EmbeddedOobListener).toBe("function");
		expect(typeof nuwaMod.OobCorrelator).toBe("function");
		expect(typeof nuwaMod.analyzeCrossFileRgs).toBe("function");
		expect(typeof nuwaMod.generateStandalonePovScript).toBe("function");
		expect(typeof nuwaMod.writeStandalonePovScript).toBe("function");

		expect(countLines(join(REPO_ROOT, "omp/nuwa.ts"))).toBeLessThan(1000);
		expect(countLines(join(REPO_ROOT, "bin/nuwa-autonomous"))).toBeLessThan(2500);

		for (const subDir of ["core", "omp", "kb"]) {
			const dirFull = join(REPO_ROOT, subDir);
			for (const name of readdirSync(dirFull)) {
				if (!name.endsWith(".ts")) continue;
				const lines = countLines(join(dirFull, name));
				expect(lines).toBeLessThan(2500);
			}
		}
	});

	test("2. /nuwa proto|pivot|rgs 在未初始化目录与遗留纯 state.json 目录下严格保持 0 字节磁盘写入", async () => {
		const uninitRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-uninit-ro-"));
		const legacyRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-legacy-ro-"));
		const sampleSrcDir = mkdtempSync(join(tmpdir(), "nuwa-v8-rgs-src-"));
		try {
			writeFileSync(
				join(sampleSrcDir, "routes.ts"),
				[
					'import express from "express";',
					"const app = express();",
					'app.get("/api/admin/export", (req, res) => res.json({ ok: true }));',
				].join("\n"),
				"utf8",
			);

			// A. 未初始化空目录
			const engUninit = new nuwaMod.NuwaUnifiedEngine({ projectRoot: uninitRoot, cwd: uninitRoot });
			for (const cmd of ["proto", "proto status", "proto frames", "pivot", "pivot routes", "rgs", `rgs scan ${sampleSrcDir}`]) {
				const res = await engUninit.executeSlashCommand(cmd);
				expect(res.level).toBe("info");
			}
			expect(readdirSync(uninitRoot)).toEqual([]);
			expect(existsSync(join(uninitRoot, ".nuwa"))).toBe(false);

			// B. 遗留纯 state.json 目录（无 nuwa.db）
			const legacyState = nuwaMod.newState("http://127.0.0.1:19881", "v8 遗留零写盘测试", "pentest", nuwaMod.readCfg(), "v8-ro-sid");
			nuwaMod.ensurePrimaryAsset(legacyState);
			nuwaMod.saveStateJsonOnly(legacyRoot, legacyState);
			const nuwaDir = join(legacyRoot, ".nuwa");
			const beforeSnap = snapshotDir(nuwaDir);
			const beforeSrcSnap = snapshotDir(sampleSrcDir);
			expect(existsSync(nuwaMod.sqliteDbPath(legacyRoot))).toBe(false);

			const engLegacy = new nuwaMod.NuwaUnifiedEngine({ projectRoot: legacyRoot, cwd: legacyRoot });
			for (const cmd of ["proto", "proto frames 5", "pivot", "pivot routes", "rgs", `rgs scan ${sampleSrcDir}`]) {
				const res = await engLegacy.executeSlashCommand(cmd);
				expect(res.level).toBe("info");
			}
			expect(snapshotDir(nuwaDir)).toEqual(beforeSnap);
			expect(snapshotDir(sampleSrcDir)).toEqual(beforeSrcSnap);
			expect(existsSync(nuwaMod.sqliteDbPath(legacyRoot))).toBe(false);
		} finally {
			rmSync(uninitRoot, { recursive: true, force: true });
			rmSync(legacyRoot, { recursive: true, force: true });
			rmSync(sampleSrcDir, { recursive: true, force: true });
		}
	});

	test("3. writePocBundle 生成零明文 pov-<factId>.ts 且 SQLite v2 四表（含 operationName/anomalyTag）全量脱敏", () => {
		const ws = mkdtempSync(join(tmpdir(), "nuwa-v8-poc-sql-"));
		try {
			const secretJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2OF9hZG1pbiJ9.V8BundleSecret9911";
			const opLeak = "GetAdminSecrets?token=OpQuerySecret_778899";
			const tagLeak = "Bearer TagSecretToken_445566";
			nuwaMod.upsertSessionRole(ws, { role: "admin", bearer: secretJwt });

			const st = nuwaMod.newState("http://127.0.0.1:19882", "PoV 脱敏与 Schema v2 集成测试", "pentest", nuwaMod.readCfg());
			st.facts.f001 = {
				id: "f001",
				kind: "vuln",
				title: "订单导出接口缺失租户隔离校验",
				detail: `GET http://127.0.0.1:19882/api/orders/export 携带 Authorization: Bearer ${secretJwt} 可跨租户读取记录`,
				command: `curl -sS -H "Authorization: Bearer ${secretJwt}" http://127.0.0.1:19882/api/orders/export`,
				output: '{"tenant":"other","records":[1,2]}',
				verified: true,
				verifyStage: "confirmed",
				targetKey: "/api/orders/export",
				createdAt: "2026-11-28T00:00:00.000Z",
			};
			nuwaMod.saveState(ws, st);

			// 验证 #138 P2：protocol_frames 的 operationName 与 anomalyTag 强制脱敏（显式在 sqlite 后端下验证落库）
			const prevBe3 = process.env.NUWA_STORAGE_BACKEND;
			process.env.NUWA_STORAGE_BACKEND = "sqlite";
			try {
				nuwaMod.recordProtocolAuditFrame(ws, {
					id: "pf-p2-check",
					ts: "2026-11-28T00:00:01.000Z",
					protocol: "graphql",
					direction: "request",
					url: "http://127.0.0.1:19882/graphql",
					host: "127.0.0.1",
					operationName: opLeak,
					anomalyTag: tagLeak,
					status: 200,
				});
			} finally {
				if (prevBe3 === undefined) delete process.env.NUWA_STORAGE_BACKEND;
				else process.env.NUWA_STORAGE_BACKEND = prevBe3;
			}

			const store = new nuwaMod.NuwaSqliteStore(ws);
			try {
				expect(store.listProtocolFrames().length).toBe(1);
				store.rawDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
			} finally {
				store.close();
			}
			const dbRaw = readFileSync(nuwaMod.sqliteDbPath(ws)).toString("latin1");
			expect(dbRaw.includes("OpQuerySecret_778899")).toBe(false);
			expect(dbRaw.includes("TagSecretToken_445566")).toBe(false);
			expect(dbRaw.includes(secretJwt)).toBe(false);

			const bundle = nuwaMod.writePocBundle(ws, st);
			expect(bundle.confirmedCount).toBe(1);
			const povPath = join(bundle.dir, "pov-f001.ts");
			expect(existsSync(povPath)).toBe(true);
			expect(bundle.files).toContain(povPath);

			const povSrc = readFileSync(povPath, "utf8");
			expect(povSrc.includes(secretJwt)).toBe(false);
			expect(povSrc.includes("V8BundleSecret9911")).toBe(false);
			expect(povSrc).toContain("NUWA_POV_HEADERS_FILE");

			const manifest = JSON.parse(readFileSync(bundle.manifestPath, "utf8")) as {
				files: Array<{ name: string; sha256: string }>;
			};
			expect(manifest.files.some((f) => f.name === "pov-f001.ts")).toBe(true);
		} finally {
			rmSync(ws, { recursive: true, force: true });
		}
	});

	test(
		"4. install.sh 部署 v8.0.0 全模块并通过 doctor V8_EXT_MODULES (8/8) 门禁，L4 --live-openai-compat 支持 JSON/SSE 评测且缺 Key 必拒",
		async () => {
			// A. 缺少 NUWA_LIVE_API_KEY 时启用 --live-openai-compat 必须立即报错
			const prevKey = process.env.NUWA_LIVE_API_KEY;
			const prevBase = process.env.NUWA_LIVE_API_BASE;
			delete process.env.NUWA_LIVE_API_KEY;
			try {
				await expect(
					runL4BenchmarkSuite({ scenario: "s01-second-order-store-read", liveOpenAiCompat: true }),
				).rejects.toThrow(/NUWA_LIVE_API_KEY/);

				// B. 启动本地 Mock OpenAI 兼容服务（第 1 次返回 JSON，第 2 次返回 SSE 流式 + reasoning_tokens）
				let callIdx = 0;
				const mockLlmSrv = http.createServer((req, res) => {
					const chunks: Buffer[] = [];
					req.on("data", (c) => chunks.push(Buffer.from(c)));
					req.on("end", () => {
						callIdx += 1;
						if (callIdx % 2 === 1) {
							res.writeHead(200, { "Content-Type": "application/json" });
							res.end(
								JSON.stringify({
									id: "chatcmpl-1",
									choices: [
										{
											message: {
												content: '{"hypothesis":"验证跨步状态写入与二次读取一致性","actions":["write_profile","read_audit"],"params":{},"confidence":0.91}',
											},
										},
									],
									usage: {
										prompt_tokens: 120,
										completion_tokens: 45,
										completion_tokens_details: { reasoning_tokens: 18 },
										total_tokens: 165,
									},
								}),
							);
						} else {
							res.writeHead(200, { "Content-Type": "text/event-stream" });
							res.write(
								'data: {"choices":[{"delta":{"content":"{\\"confirmed\\":true,"}}]}\n\n',
							);
							res.write(
								'data: {"choices":[{"delta":{"content":"\\"rationale\\":\\"本地靶场实测验证通过\\",\\"confidence\\":0.95}"}}],"usage":{"prompt_tokens":140,"completion_tokens":30,"reasoning_tokens":12,"total_tokens":170}}\n\n',
							);
							res.end("data: [DONE]\n\n");
						}
					});
				});
				await new Promise<void>((resolveListen) => mockLlmSrv.listen(0, "127.0.0.1", () => resolveListen()));
				const addr = mockLlmSrv.address() as { port: number };
				try {
					const syntheticApiKey = "test_ephemeral_live_token_not_sk";
					process.env.NUWA_LIVE_API_BASE = `http://127.0.0.1:${addr.port}`;
					process.env.NUWA_LIVE_API_KEY = syntheticApiKey;

					const liveSummary = await runL4BenchmarkSuite({
						scenario: "s01-second-order-store-read",
						liveOpenAiCompat: true,
						model: "deepseek-flash-mock",
					});
					expect(liveSummary.allPassed).toBe(true);
					expect(liveSummary.liveMode?.enabled).toBe(true);
					expect(liveSummary.liveMode?.model).toBe("deepseek-flash-mock");
					expect(liveSummary.liveMode?.usage.llmCalls).toBe(2);
					expect(liveSummary.liveMode?.usage.promptTokens).toBe(260);
					expect(liveSummary.liveMode?.usage.completionTokens).toBe(75);
					expect(liveSummary.liveMode?.usage.reasoningTokens).toBe(30);
					expect(liveSummary.liveMode?.usage.totalTokens).toBe(335);
					expect(JSON.stringify(liveSummary).includes(syntheticApiKey)).toBe(false);
				} finally {
					mockLlmSrv.close();
				}
			} finally {
				if (prevKey === undefined) delete process.env.NUWA_LIVE_API_KEY;
				else process.env.NUWA_LIVE_API_KEY = prevKey;
				if (prevBase === undefined) delete process.env.NUWA_LIVE_API_BASE;
				else process.env.NUWA_LIVE_API_BASE = prevBase;
			}

			// C. 独立沙盒验证 install.sh v8.0.0 部署与 doctor V8_EXT_MODULES 8/8 体检
			const sb = mkdtempSync(join(tmpdir(), "nuwa-v8-e2e-inst-"));
			const agentHome = join(sb, "agent-home");
			const binDir = join(sb, "bin");
			const ompStubDir = join(sb, "omp-stub");
			try {
				mkdirSync(ompStubDir, { recursive: true });
				const ompStub = join(ompStubDir, "omp");
				writeFileSync(ompStub, "#!/usr/bin/env bash\necho 'omp 18.16.0'\n", "utf8");
				chmodSync(ompStub, 0o755);

				const env: Record<string, string | undefined> = {
					...process.env,
					PI_AGENT_HOME: agentHome,
					NUWA_BIN_DIR: binDir,
					PATH: `${ompStubDir}:${process.env.PATH ?? ""}`,
				};
				delete env.BUN_OPTIONS;

				const inst = spawnSync("bash", [join(REPO_ROOT, "install.sh"), "--force-agents", "--clean-kb"], {
					cwd: REPO_ROOT,
					env: env as NodeJS.ProcessEnv,
					encoding: "utf8",
					timeout: 60_000,
				});
				expect(inst.status).toBe(0);
				expect(inst.stdout).toContain("installed version = 8.0.0");

				const docOk = spawnSync("bun", [join(binDir, "nuwa-autonomous"), "doctor", "--json", "--omp-bin", ompStub], {
					cwd: tmpdir(),
					env: env as NodeJS.ProcessEnv,
					encoding: "utf8",
				});
				expect(docOk.status).toBe(0);
				const docJson = JSON.parse(docOk.stdout) as {
					ok: boolean;
					checks: { extension: { version: string; v8ModulesFound: string[]; v8ModulesMissing: string[] } };
				};
				expect(docJson.ok).toBe(true);
				expect(docJson.checks.extension.version).toBe("8.0.0");
				expect(docJson.checks.extension.v8ModulesFound.length).toBe(8);
				expect(docJson.checks.extension.v8ModulesMissing).toEqual([]);

				rmSync(join(agentHome, "extensions", "nuwa-omp", "rgs-analyzer.ts"), { force: true });
				const docFail = spawnSync("bun", [join(binDir, "nuwa-autonomous"), "doctor", "--json", "--omp-bin", ompStub], {
					cwd: tmpdir(),
					env: env as NodeJS.ProcessEnv,
					encoding: "utf8",
				});
				expect(docFail.status).toBe(1);
				const failJson = JSON.parse(docFail.stdout) as {
					ok: boolean;
					checks: { extension: { ok: boolean; v8ModulesMissing: string[] } };
				};
				expect(failJson.ok).toBe(false);
				expect(failJson.checks.extension.ok).toBe(false);
				expect(failJson.checks.extension.v8ModulesMissing).toContain("rgs-analyzer.ts");
			} finally {
				rmSync(sb, { recursive: true, force: true });
			}
		},
		40_000,
	);

	test(
		"5. Wave 2 终审全反例回归：损坏 state.json 零写盘、无环 DAG、五文件内联脱敏、retiredSecrets 轮换保护与 Live 严拒离线回退",
		async () => {
			// A1. [#171 P1-1] 13B 损坏 state.json + .nuwa/snap 快照下执行只读 /nuwa proto|pivot|rgs 严格 0 字节改动
			const corruptRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-corrupt-ro-"));
			// A3 & C1/C2 工作目录
			const rgsRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-rgs-guard-"));
			const bundleRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-bundle-inline-"));
			try {
				const stInit = nuwaMod.newState("http://127.0.0.1:19890", "corrupt state ro test", "pentest", nuwaMod.readCfg());
				nuwaMod.saveStateJsonOnly(corruptRoot, stInit, { forceSnapshot: true });
				rmSync(join(corruptRoot, ".nuwa", "journal.jsonl"), { force: true });
				writeFileSync(nuwaMod.statePath(corruptRoot), "{ broken json", "utf8"); // 13 bytes
				expect(statSync(nuwaMod.statePath(corruptRoot)).size).toBe(13);

				const corruptNuwaDir = join(corruptRoot, ".nuwa");
				const snapBeforeCorrupt = snapshotDir(corruptNuwaDir);
				const engCorrupt = new nuwaMod.NuwaUnifiedEngine({ projectRoot: corruptRoot, cwd: corruptRoot });
				for (const roCmd of ["proto", "pivot", "rgs"]) {
					await engCorrupt.executeSlashCommand(roCmd);
				}
				expect(snapshotDir(corruptNuwaDir)).toEqual(snapBeforeCorrupt);
				expect(statSync(nuwaMod.statePath(corruptRoot)).size).toBe(13);

				// A2. [#171 P1-2 / #172 P1-2 / #174 P1-3] rgs-analyzer.ts 零运行时反向引用 ./reporting
				const rgsSrc = readFileSync(join(REPO_ROOT, "omp/rgs-analyzer.ts"), "utf8");
				expect(/from\s+["']\.\/reporting(?:\.ts)?["']/.test(rgsSrc)).toBe(false);

				// A3. [#171 P1-3 + #172 P1-3] 终态 pov 拦截、跨目录相对路径解析、.nuwa/sessions N-003 阻断、scope_blocked 映射、proto 脱敏
				mkdirSync(join(rgsRoot, "src"), { recursive: true });
				writeFileSync(
					join(rgsRoot, "src", "app.ts"),
					'import express from "express"; const app = express(); app.post("/api/orders", (req, res) => res.json({ ok: true }));\n',
					"utf8",
				);
				const stRgs = nuwaMod.newState("http://127.0.0.1:19891", "rgs guard test", "pentest", nuwaMod.readCfg());
				stRgs.facts.f001 = {
					id: "f001",
					kind: "vuln",
					title: "订单接口越权访问",
					detail: "GET http://127.0.0.1:19891/api/orders/2 返回跨租户数据",
					command: "curl -sS http://127.0.0.1:19891/api/orders/2",
					output: '{"id":2}',
					verified: true,
					verifyStage: "confirmed",
					createdAt: "2026-11-28T00:00:00.000Z",
				};
				nuwaMod.saveState(rgsRoot, stRgs);
				nuwaMod.upsertSessionRole(rgsRoot, { role: "user", bearer: "tok_n003_guard_test_1122" });

				// 跨目录（当前进程 cwd 非 rgsRoot）传入相对路径 "src" 正常扫描项目内 src/app.ts
				const relScan = nuwaMod.executeRgsCommand(rgsRoot, "scan src");
				expect(relScan.level).toBe("info");
				expect(relScan.msg).toContain("routes=1");

				// 扫描 .nuwa/sessions 必须触发 N-003 硬阻断（斜杠命令层 + 核心 API 层双阻断）
				const nuwaScan = nuwaMod.executeRgsCommand(rgsRoot, "scan .nuwa/sessions");
				expect(nuwaScan.level).toBe("error");
				expect(nuwaScan.msg).toContain("N-003");
				expect(() => nuwaMod.analyzeCrossFileRgs(join(rgsRoot, ".nuwa", "sessions"))).toThrow(/N-003/);

				// proto graphql 越界/报错回显 URL 凭据脱敏
				const protoLeakRes = await nuwaMod.executeProtoCommand(
					rgsRoot,
					"graphql http://user:ProtoUrlPass9911@evil.example.test/graphql?api_key=ProtoQueryKey8822",
				);
				expect(protoLeakRes.level).toBe("error");
				expect(protoLeakRes.msg.includes("ProtoUrlPass9911")).toBe(false);
				expect(protoLeakRes.msg.includes("ProtoQueryKey8822")).toBe(false);

				// scope_blocked 映射落库校验 + Op_Basic 下划线前缀脱敏校验（显式在 sqlite 后端下验证落库）
				const prevBe5 = process.env.NUWA_STORAGE_BACKEND;
				process.env.NUWA_STORAGE_BACKEND = "sqlite";
				try {
					nuwaMod.recordPivotCredentialResults(rgsRoot, {
						ok: true,
						generatedAt: "2026-11-28T00:00:00.000Z",
						mode: "pentest",
						roles: ["user"],
						results: [
							{
								target: "http://blocked.internal.test:8080/",
								host: "blocked.internal.test",
								role: "user",
								status: "blocked_by_scope",
								reason: "N-007 out of scope",
								diffScore: 0,
							},
						],
						validReuses: [],
						blockedTargets: [{ target: "http://blocked.internal.test:8080/", host: "blocked.internal.test", reason: "N-007" }],
						soft404Targets: [],
						summary: "blocked=1",
					});
					nuwaMod.recordProtocolAuditFrame(rgsRoot, {
						id: "pf-underscore-basic",
						ts: "2026-11-28T00:00:02.000Z",
						protocol: "http",
						direction: "request",
						url: "http://127.0.0.1:19891/api",
						host: "127.0.0.1",
						anomalyTag: "Op_Basic dXNlcjpVbmRlcnNjb3JlQmFzaWNTZWNyZXQ5OQ==",
					});
				} finally {
					if (prevBe5 === undefined) delete process.env.NUWA_STORAGE_BACKEND;
					else process.env.NUWA_STORAGE_BACKEND = prevBe5;
				}
				const checkStore = new nuwaMod.NuwaSqliteStore(rgsRoot);
				try {
					const scopeBlockedRows = checkStore.listAssetCredentials({ status: "scope_blocked" });
					expect(scopeBlockedRows.length).toBe(1);
					expect(scopeBlockedRows[0]?.host).toBe("blocked.internal.test");
					checkStore.rawDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
				} finally {
					checkStore.close();
				}
				expect(
					readFileSync(nuwaMod.sqliteDbPath(rgsRoot))
						.toString("latin1")
						.includes("dXNlcjpVbmRlcnNjb3JlQmFzaWNTZWNyZXQ5OQ=="),
				).toBe(false);

				// 置为 sealed_negative 终态后直接调 executeRgsCommand(rgsRoot, "pov f001") 必须拦截且不写 pov-f001.ts
				stRgs.project.status = "sealed_negative";
				stRgs.runtime.status = "sealed_negative";
				nuwaMod.saveState(rgsRoot, stRgs);
				const povBlocked = nuwaMod.executeRgsCommand(rgsRoot, "pov f001");
				expect(povBlocked.level).toBe("error");
				expect(existsSync(join(rgsRoot, ".nuwa", "poc-bundle", "pov-f001.ts"))).toBe(false);

				// C1 & #182. SessionVault 角色凭据轮换覆盖后旧凭据保留脱敏 + writePocBundle 五文件非入罐内联凭据零明文
				const rotatedOldToken = "RotatedLegacyOpaqueToken_5566778899";
				const freshActiveToken = "FreshReplacementToken_1122334455";
				nuwaMod.upsertSessionRole(bundleRoot, { role: "member", bearer: rotatedOldToken });
				nuwaMod.upsertSessionRole(bundleRoot, { role: "member", bearer: freshActiveToken });

				const inlineUrlPass = "UrlPassSecret554433";
				const inlineQueryKey = "QueryApiKeySecret667788";
				const inlineTotp = "JBSWY3DPEHPK3PXP_INLINE";
				const inlineApiToken = ["s" + "k", "LiveInlineTestToken998877665544"].join("-");

				const stBundle = nuwaMod.newState(
					`http://admin:${inlineUrlPass}@127.0.0.1:19892`,
					"inline secret scrubbing test",
					"pentest",
					nuwaMod.readCfg(),
				);
				stBundle.facts.f001 = {
					id: "f001",
					kind: "vuln",
					title: "账单详情接口水平访问控制缺失",
					detail: `请求 http://admin:${inlineUrlPass}@127.0.0.1:19892/api/bills/9?api_key=${inlineQueryKey} 附带旧令牌 ${rotatedOldToken}`,
					command: `curl -sS "http://127.0.0.1:19892/api/bills/9?api_key=${inlineQueryKey}"`,
					output: JSON.stringify({
						totpSecret: inlineTotp,
						providerKey: inlineApiToken,
						oldTokenEcho: rotatedOldToken,
					}),
					verified: true,
					verifyStage: "confirmed",
					targetKey: "/api/bills/9",
					createdAt: "2026-11-28T00:00:00.000Z",
				};
				const outBundle = nuwaMod.writePocBundle(bundleRoot, stBundle);
				expect(outBundle.files.length).toBe(5);
				for (const fPath of outBundle.files) {
					const rawTxt = readFileSync(fPath, "utf8");
					for (const forbidden of [
						rotatedOldToken,
						freshActiveToken,
						inlineUrlPass,
						inlineQueryKey,
						inlineTotp,
						inlineApiToken,
					]) {
						expect(rawTxt.includes(forbidden)).toBe(false);
					}
				}

				// B1 & B2. [#174 P1-1 & P1-2] Live 评测拒绝空内容回退、配对花括号解析保留否决、SSE 0 帧不覆盖、401 回显密钥脱敏
				const prevKey = process.env.NUWA_LIVE_API_KEY;
				const prevBase = process.env.NUWA_LIVE_API_BASE;
				let modeSelector: "empty" | "tail_brace_false" | "sse_zero_tail" | "http_401_leak" = "empty";
				const leakTestKey = "ephemeral_live_secret_key_for_401_echo_check";
				let auth401Hits = 0;

				const advSrv = http.createServer((_req, res) => {
					if (modeSelector === "empty") {
						res.writeHead(200, { "Content-Type": "application/json" });
						res.end(
							JSON.stringify({
								choices: [{ message: { content: "", reasoning_content: "thinking exhausted" } }],
								usage: { prompt_tokens: 50, completion_tokens: 900, total_tokens: 950 },
							}),
						);
						return;
					}
					if (modeSelector === "tail_brace_false") {
						res.writeHead(200, { "Content-Type": "application/json" });
						// 第 1 次调返回合法 plan，第 2 次返回 confirmed:false 且带尾花括号 /users/{id}
						auth401Hits += 1;
						if (auth401Hits % 2 === 1) {
							res.end(
								JSON.stringify({
									choices: [{ message: { content: '{"hypothesis":"测试尾花括号","actions":["read"],"confidence":0.9} 参见 /items/{id}' } }],
									usage: { prompt_tokens: 40, completion_tokens: 20, total_tokens: 60 },
								}),
							);
						} else {
							res.end(
								JSON.stringify({
									choices: [{ message: { content: '{"confirmed":false,"rationale":"模型明确否决","confidence":0.92} 参考路由 /users/{id}' } }],
									usage: { prompt_tokens: 45, completion_tokens: 25, total_tokens: 70 },
								}),
							);
						}
						return;
					}
					if (modeSelector === "sse_zero_tail") {
						res.writeHead(200, { "Content-Type": "text/event-stream" });
						auth401Hits += 1;
						const payloadJson =
							auth401Hits % 2 === 1
								? '{"hypothesis":"SSE零帧测试","actions":["check"],"confidence":0.88}'
								: '{"confirmed":true,"rationale":"SSE实测确认","confidence":0.95}';
						res.write(
							`data: {"choices":[{"delta":{"content":${JSON.stringify(payloadJson)}}}],"usage":{"prompt_tokens":120,"completion_tokens":30,"reasoning_tokens":10,"total_tokens":150}}\n\n`,
						);
						res.write(
							'data: {"choices":[{"delta":{}}],"usage":{"prompt_tokens":0,"completion_tokens":0,"reasoning_tokens":0,"total_tokens":0}}\n\n',
						);
						res.end("data: [DONE]\n\n");
						return;
					}
					// http_401_leak
					auth401Hits += 1;
					res.writeHead(401, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: `Invalid header Authorization: Bearer ${leakTestKey}` }));
				});

				await new Promise<void>((r) => advSrv.listen(0, "127.0.0.1", () => r()));
				const advPort = (advSrv.address() as { port: number }).port;
				try {
					process.env.NUWA_LIVE_API_BASE = `http://127.0.0.1:${advPort}`;
					process.env.NUWA_LIVE_API_KEY = leakTestKey;

					// 1) 空内容严禁回退离线答案 -> allPassed=false, passed=false
					modeSelector = "empty";
					const emptySum = await runL4BenchmarkSuite({ scenario: "s01-second-order-store-read", liveOpenAiCompat: true });
					expect(emptySum.allPassed).toBe(false);
					expect(emptySum.scenarios[0]?.passed).toBe(false);

					// 2) JSON 后跟 /users/{id} 保留 confirmed:false 否决 -> allPassed=false, passed=false
					modeSelector = "tail_brace_false";
					auth401Hits = 0;
					const vetoSum = await runL4BenchmarkSuite({ scenario: "s01-second-order-store-read", liveOpenAiCompat: true });
					expect(vetoSum.allPassed).toBe(false);
					expect(vetoSum.scenarios[0]?.passed).toBe(false);
					expect(vetoSum.scenarios[0]?.detail).toContain("模型明确否决");

					// 3) SSE 结束帧为 0 不清零首帧 usage -> 2 次调用合计 totalTokens=300
					modeSelector = "sse_zero_tail";
					auth401Hits = 0;
					const sseSum = await runL4BenchmarkSuite({ scenario: "s01-second-order-store-read", liveOpenAiCompat: true });
					expect(sseSum.allPassed).toBe(true);
					expect(sseSum.liveMode?.usage.promptTokens).toBe(240);
					expect(sseSum.liveMode?.usage.completionTokens).toBe(60);
					expect(sseSum.liveMode?.usage.reasoningTokens).toBe(20);
					expect(sseSum.liveMode?.usage.totalTokens).toBe(300);

					// 4) HTTP 401 快速失败不重试（仅请求 1 次）且错误文本 0 明文泄露 apiKey
					modeSelector = "http_401_leak";
					auth401Hits = 0;
					const errSum = await runL4BenchmarkSuite({ scenario: "s01-second-order-store-read", liveOpenAiCompat: true });
					expect(errSum.allPassed).toBe(false);
					expect(auth401Hits).toBe(1);
					expect(JSON.stringify(errSum).includes(leakTestKey)).toBe(false);
				} finally {
					advSrv.close();
					if (prevKey === undefined) delete process.env.NUWA_LIVE_API_KEY;
					else process.env.NUWA_LIVE_API_KEY = prevKey;
					if (prevBase === undefined) delete process.env.NUWA_LIVE_API_BASE;
					else process.env.NUWA_LIVE_API_BASE = prevBase;
				}
			} finally {
				rmSync(corruptRoot, { recursive: true, force: true });
				rmSync(rgsRoot, { recursive: true, force: true });
				rmSync(bundleRoot, { recursive: true, force: true });
			}
		},
		45_000,
	);
});
