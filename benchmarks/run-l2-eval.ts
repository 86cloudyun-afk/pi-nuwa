#!/usr/bin/env bun
/**
 * pi-nuwa v6.0 L2 离线合成微基准测试运行器（状态机端到端闭环 + 硬门禁评分卡）。
 *
 * 用法:
 *   env -u BUN_OPTIONS bun benchmarks/run-l2-eval.ts [--json] [--scenario <id>] [--help]
 *
 * 评测硬门禁:
 *   - recallRate === 1.0          （合成已知缺陷 100% 召回）
 *   - falsePositiveRate === 0     （Soft-404 诱饵与硬化参考服务 0 误报）
 *   - vaultLeakCount === 0        （Markdown/JSON/SARIF/PoC Bundle 零凭据明文泄露）
 *   - hardenedSealTurns <= 15     （全加固零缺陷服务快速收敛至 sealed_negative）
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NuwaCoreEngine } from "../core/mcp-server";
import { classifyAutoFailure, isSoft404Hit, parseSoft404Baseline } from "../omp/autoexec";
import { runAuthDiffMatrix } from "../omp/auth-diff";
import { runSpaRecon } from "../omp/browser-recon";
import { recordToolExecution } from "../omp/evidence";
import { generateOobCanary, pollOobCallbacks } from "../omp/oob";
import { defaultScopeForTarget } from "../omp/scope";
import { clearSessionVault, upsertSessionRole } from "../omp/session-vault";
import { loadState, saveState, withLock } from "../omp/storage";
import {
	L2_SCENARIO_SPECS,
	L2_SYNTHETIC_TOKENS,
	startL2ScenarioServer,
	type L2ScenarioId,
	type L2ScenarioServerHandle,
	type L2ScenarioSpec,
} from "./l2-range/servers";

export interface L2ScenarioEvalResult {
	id: L2ScenarioId;
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

export interface L2HardGates {
	recallGate: boolean;
	zeroFalsePositiveGate: boolean;
	zeroVaultLeakGate: boolean;
	hardenedConvergenceGate: boolean;
	allPassed: boolean;
}

export interface L2ScorecardMetrics {
	totalScenarios: number;
	passedScenarios: number;
	expectedTotalFindings: number;
	truePositiveCount: number;
	falseNegativeCount: number;
	falsePositiveCount: number;
	recallRate: number;
	falsePositiveRate: number;
	vaultLeakCount: number;
	hardenedSealTurns: number;
	wallTimeMs: number;
}

export interface L2BenchmarkSummary {
	schema: 2;
	suite: "nuwa-l2-microbench";
	deterministic: boolean;
	generatedAt: string;
	metrics: L2ScorecardMetrics;
	gates: L2HardGates;
	scenarios: L2ScenarioEvalResult[];
}

export interface RunL2BenchmarkOptions {
	scenario?: string;
	deterministic?: boolean;
}

const FIXED_EVAL_TS = "2026-11-26T00:00:00.000Z";

interface L2EvalEnv {
	makeWorkspace: (prefix: string) => string;
	trackProjectId: (projectId: string) => void;
}

function assertOk(cond: unknown, msg: string): void {
	if (!cond) throw new Error(msg);
}

function extractTitle(html: string): string {
	return /<title[^>]*>([^<]{0,120})<\/title>/i.exec(html)?.[1]?.trim() ?? "-";
}

function tickTurn(root: string, delta = 1): number {
	return withLock(root, () => {
		const st = loadState(root);
		if (!st) throw new Error("状态未初始化");
		st.runtime.turns = (st.runtime.turns ?? 0) + delta;
		st.runtime.totalTurns = Math.max(st.runtime.totalTurns ?? 0, st.runtime.turns);
		saveState(root, st);
		return st.runtime.turns;
	});
}

/**
 * 在 `NuwaCoreEngine` 上执行“发现候选 -> 双盲复验员独立二次取证确认”的标准正向入账闭环。
 */
async function commitAndConfirmFinding(opts: {
	engine: NuwaCoreEngine;
	root: string;
	intentId: string;
	title: string;
	detail: string;
	candidateCmd: string;
	candidateOutput: string;
	verifyCmd: string;
	verifyOutput: string;
}): Promise<{ factId: string; turnsDelta: number }> {
	const { engine, root, intentId, title, detail, candidateCmd, candidateOutput, verifyCmd, verifyOutput } = opts;

	const claim1 = await engine.callTool("nuwa_claim", { id: intentId, worker: "fujiang" });
	assertOk(!claim1.isError, `认领意图 ${intentId} 失败: ${claim1.content[0]?.text ?? ""}`);

	recordToolExecution(root, {
		tool: "bash",
		command: candidateCmd,
		output: candidateOutput,
		agentName: "fujiang",
	});

	const commit1 = await engine.callTool("nuwa_commit", {
		id: intentId,
		kind: "vuln",
		title,
		detail,
		command: candidateCmd,
		output: candidateOutput,
	});
	assertOk(!commit1.isError, `候选提交失败: ${commit1.content[0]?.text ?? ""}`);
	tickTurn(root, 1);

	const verifyIntentId = commit1.details?.verifyIntent as string | undefined;
	if (!verifyIntentId) {
		const stNow = loadState(root)!;
		const fId = stNow.intents[intentId]?.to ?? "";
		return { factId: fId, turnsDelta: 1 };
	}

	// 双盲独立复验：确保新执行账本序列严格晚于候选记录
	await Bun.sleep(3);
	const claimVerify = await engine.callTool("nuwa_claim", {
		id: verifyIntentId,
		worker: "nuwa-verifier",
	});
	assertOk(!claimVerify.isError, `认领双盲复验意图 ${verifyIntentId} 失败`);

	recordToolExecution(root, {
		tool: "bash",
		command: verifyCmd,
		output: verifyOutput,
		agentName: "nuwa-verifier",
	});

	const commitVerify = await engine.callTool("nuwa_commit", {
		id: verifyIntentId,
		kind: "vuln",
		title: `[Verified] ${title}`,
		detail: `双盲独立复验确认: ${detail}`,
		command: verifyCmd,
		output: verifyOutput,
	});
	assertOk(!commitVerify.isError, `双盲复验提交失败: ${commitVerify.content[0]?.text ?? ""}`);
	tickTurn(root, 1);

	const stAfter = loadState(root)!;
	const origFactId = stAfter.intents[intentId]?.to ?? "";
	assertOk(
		origFactId && stAfter.facts[origFactId]?.verifyStage === "confirmed",
		`预期事实 ${origFactId} 进入 confirmed 状态`,
	);
	return { factId: origFactId, turnsDelta: 2 };
}

/**
 * 导出全部报告格式（Markdown / JSON / SARIF / PoC Bundle），校验 SARIF 确认结果数并扫描凭据泄露。
 */
async function exportReportsAndAuditSecrets(
	engine: NuwaCoreEngine,
	root: string,
	secretsToAudit: readonly string[],
): Promise<{ sarifResultCount: number; vaultLeaks: number }> {
	const mdRes = await engine.callTool("nuwa_report", { write: true, format: "md", bundle: true });
	const jsonRes = await engine.callTool("nuwa_report", { write: true, format: "json" });
	const sarifRes = await engine.callTool("nuwa_report", { write: true, format: "sarif" });
	assertOk(!mdRes.isError && !jsonRes.isError && !sarifRes.isError, "报告导出调用不应报错");

	const sarifPath = join(root, ".nuwa", "REPORT.sarif.json");
	const jsonPath = join(root, ".nuwa", "REPORT.json");
	const mdPath = join(root, ".nuwa", "REPORT.md");
	assertOk(existsSync(sarifPath) && existsSync(jsonPath) && existsSync(mdPath), "报告文件必须落盘");

	const sarifRaw = readFileSync(sarifPath, "utf8");
	const sarifParsed = JSON.parse(sarifRaw) as {
		runs?: Array<{ results?: Array<{ properties?: { factId?: string } }> }>;
	};
	const stSnap = loadState(root);
	const verifyReceiptFactIds = new Set<string>(
		Object.values(stSnap?.intents ?? {})
			.filter((it) => it.key.startsWith("verify-vuln:") && Boolean(it.to))
			.map((it) => it.to!),
	);
	const rawResults = sarifParsed.runs?.[0]?.results ?? [];
	const primaryConfirmedResults = rawResults.filter((item) => {
		const fid = item.properties?.factId;
		return !fid || !verifyReceiptFactIds.has(fid);
	});
	const sarifResultCount = primaryConfirmedResults.length;

	const textsToScan: string[] = [
		mdRes.content[0]?.text ?? "",
		jsonRes.content[0]?.text ?? "",
		sarifRes.content[0]?.text ?? "",
		readFileSync(mdPath, "utf8"),
		readFileSync(jsonPath, "utf8"),
		sarifRaw,
	];

	const bundleDir = mdRes.details?.bundleDir as string | undefined;
	if (bundleDir && existsSync(bundleDir)) {
		const manifestPath = join(bundleDir, "manifest.json");
		if (existsSync(manifestPath)) {
			const manifestRaw = readFileSync(manifestPath, "utf8");
			textsToScan.push(manifestRaw);
			const manifest = JSON.parse(manifestRaw) as { files?: Array<{ name: string }> };
			for (const f of manifest.files ?? []) {
				const fp = join(bundleDir, f.name);
				if (existsSync(fp)) textsToScan.push(readFileSync(fp, "utf8"));
			}
		}
	}

	let vaultLeaks = 0;
	for (const body of textsToScan) {
		for (const secret of secretsToAudit) {
			if (secret && secret.length >= 8 && body.includes(secret)) {
				vaultLeaks += 1;
			}
		}
	}

	return { sarifResultCount, vaultLeaks };
}

type ScenarioEvaluator = (
	spec: L2ScenarioSpec,
	srv: L2ScenarioServerHandle,
	env: L2EvalEnv,
) => Promise<Omit<L2ScenarioEvalResult, "id" | "name" | "category" | "durationMs">>;

const SCENARIO_EVALUATORS: Record<L2ScenarioId, ScenarioEvaluator> = {
	"t1-spa-jwt-bola": async (spec, srv, env) => {
		const root = env.makeWorkspace("nuwa-l2-t1-");
		const engine = new NuwaCoreEngine({ projectRoot: root, cwd: root, sessionId: "l2-t1" });

		const initRes = await engine.callTool("nuwa_init", {
			target: srv.baseUrl,
			mode: "pentest",
			goal: spec.description,
		});
		assertOk(!initRes.isError, `初始化失败: ${initRes.content[0]?.text ?? ""}`);
		const stInit = loadState(root)!;
		env.trackProjectId(stInit.project.id);
		tickTurn(root, 1);

		// 1. 静态 SPA 侦察提取前端 JS 清单路由
		const scope = stInit.project.scope ?? defaultScopeForTarget(srv.baseUrl, "pentest");
		const spaRecon = await runSpaRecon(`${srv.baseUrl}/app/dashboard`, scope, { disablePlaywright: true });
		const discoveredPaths = spaRecon.endpoints.map((e) => e.path);
		assertOk(
			discoveredPaths.includes("/api/v1/projects/1001") &&
				discoveredPaths.includes("/api/v1/admin/tenant-quotas"),
			`前端清单应提取出受测 API 路由，实际: ${JSON.stringify(discoveredPaths)}`,
		);

		// 2. 获取合成测试令牌并写入 SessionVault（后续校验报告零明文泄露）
		const tokRes = await fetch(`${srv.baseUrl}/api/v1/auth/issue-test-tokens`);
		const tokJson = (await tokRes.json()) as {
			roles: { member_alice: string; member_bob: string; tenant_admin: string };
		};
		upsertSessionRole(root, { role: "user_alice", bearer: tokJson.roles.member_alice });
		upsertSessionRole(root, { role: "user_bob", bearer: tokJson.roles.member_bob });
		upsertSessionRole(root, { role: "admin", bearer: tokJson.roles.tenant_admin });

		// 3. 运行多角色鉴权差分矩阵（水平 BOLA + 垂直 BFLA）
		const diffRes = await runAuthDiffMatrix(
			srv.baseUrl,
			["/api/v1/projects/1001", "/api/v1/admin/tenant-quotas"],
			root,
			scope,
		);
		assertOk(diffRes.findings.length >= 2, `鉴权差分矩阵应检出水平与垂直越权，实际=${diffRes.findings.length}`);

		// 4. 在 NuwaCoreEngine 中规划、认领、双盲复验入账两条真实权限配置缺陷
		const planRes = await engine.callTool("nuwa_plan", {
			intents: [
				{
					phase: "vuln",
					title: "校验 /api/v1/projects/1001 跨租户成员资源隔离",
					targetKey: "/api/v1/projects/1001",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
				{
					phase: "vuln",
					title: "校验 /api/v1/admin/tenant-quotas 管理配额垂直角色边界",
					targetKey: "/api/v1/admin/tenant-quotas",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
			],
		});
		const addedIds = (planRes.details?.added as string[] | undefined) ?? [];
		assertOk(addedIds.length === 2, "应成功规划 2 条权限边界验证意图");

		const bolaResp = await (
			await fetch(`${srv.baseUrl}/api/v1/projects/1001`, {
				headers: { Authorization: `Bearer ${tokJson.roles.member_bob}` },
			})
		).text();
		const bolaVerifyResp = await (
			await fetch(`${srv.baseUrl}/api/v1/projects/1001`, {
				headers: { Authorization: `Bearer ${tokJson.roles.member_bob}` },
			})
		).text();

		await commitAndConfirmFinding({
			engine,
			root,
			intentId: addedIds[0]!,
			title: `BOLA 水平资源越权访问 /api/v1/projects/1001`,
			detail: `匿名返回 401，但非属主角色携带 ${tokJson.roles.member_bob} 成功读取属主 alice 的项目配置`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${tokJson.roles.member_bob}" ${srv.baseUrl}/api/v1/projects/1001`,
			candidateOutput: bolaResp,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${tokJson.roles.member_bob}" ${srv.baseUrl}/api/v1/projects/1001`,
			verifyOutput: bolaVerifyResp,
		});

		const bflaResp = await (
			await fetch(`${srv.baseUrl}/api/v1/admin/tenant-quotas`, {
				headers: { Authorization: `Bearer ${tokJson.roles.member_alice}` },
			})
		).text();
		const bflaVerifyResp = await (
			await fetch(`${srv.baseUrl}/api/v1/admin/tenant-quotas`, {
				headers: { Authorization: `Bearer ${tokJson.roles.member_alice}` },
			})
		).text();

		await commitAndConfirmFinding({
			engine,
			root,
			intentId: addedIds[1]!,
			title: `Vertical BFLA 垂直角色鉴权缺失 /api/v1/admin/tenant-quotas`,
			detail: `普通成员角色携带 ${tokJson.roles.member_alice} 成功访问管理配额端点`,
			candidateCmd: `curl -sS -H "Authorization: Bearer ${tokJson.roles.member_alice}" ${srv.baseUrl}/api/v1/admin/tenant-quotas`,
			candidateOutput: bflaResp,
			verifyCmd: `curl -sS -H "Authorization: Bearer ${tokJson.roles.member_alice}" ${srv.baseUrl}/api/v1/admin/tenant-quotas`,
			verifyOutput: bflaVerifyResp,
		});

		const compRes = await engine.callTool("nuwa_complete", {});
		assertOk(compRes.details?.ok === true, `正向收口应通过: ${compRes.content[0]?.text ?? ""}`);

		const audit = await exportReportsAndAuditSecrets(engine, root, [
			L2_SYNTHETIC_TOKENS.t1Alice,
			L2_SYNTHETIC_TOKENS.t1Bob,
			L2_SYNTHETIC_TOKENS.t1Admin,
		]);
		clearSessionVault(root, stInit.project.id);

		const stFinal = loadState(root)!;
		const truePositives = Math.min(spec.expectedFindings, audit.sarifResultCount);
		const falseNegatives = Math.max(0, spec.expectedFindings - truePositives);
		const falsePositives = Math.max(0, audit.sarifResultCount - spec.expectedFindings);

		return {
			passed:
				stFinal.project.status === "completed" &&
				truePositives === spec.expectedFindings &&
				falsePositives === 0 &&
				audit.vaultLeaks === 0,
			terminalStatus: stFinal.project.status,
			turnsUsed: stFinal.runtime.turns,
			expectedFindings: spec.expectedFindings,
			truePositives,
			falseNegatives,
			falsePositives,
			vaultLeaks: audit.vaultLeaks,
			detail: `SPA提取=${discoveredPaths.length}路由, BOLA+BFLA双确认=${truePositives}, 误报=${falsePositives}, 泄露=${audit.vaultLeaks}`,
		};
	},

	"t2-waf-soft404-trap": async (spec, srv, env) => {
		const root = env.makeWorkspace("nuwa-l2-t2-");
		const engine = new NuwaCoreEngine({ projectRoot: root, cwd: root, sessionId: "l2-t2" });

		await engine.callTool("nuwa_init", {
			target: srv.baseUrl,
			mode: "pentest",
			goal: spec.description,
		});
		const stInit = loadState(root)!;
		env.trackProjectId(stInit.project.id);
		const t2VaultSecret = "sk-l2-t2-gateway-secret-token-776655";
		upsertSessionRole(root, { role: "probe_client", headers: { "X-Gateway-Key": t2VaultSecret } });
		tickTurn(root, 1);

		// 1. 验证 HTTP 429 + Retry-After 限流分类识别
		const wafRes = await fetch(`${srv.baseUrl}/api/v1/rate-gate`);
		const wafBody = await wafRes.text();
		const retryAfter = wafRes.headers.get("retry-after") ?? "";
		assertOk(wafRes.status === 429 && retryAfter === "2", "应收到 HTTP 429 与 Retry-After: 2");
		const wafVerdict = classifyAutoFailure({
			stdout: `HTTP/1.1 429 Too Many Requests\nRetry-After: ${retryAfter}\nX-RateLimit-Remaining: 0\n\n${wafBody}`,
			stderr: "",
			code: 0,
		});
		assertOk(
			wafVerdict.errorKind === "blocked_by_waf" && wafVerdict.waf === "rate-limit",
			`预期分类为 rate-limit，实际: ${JSON.stringify(wafVerdict)}`,
		);

		// 2. 验证兜底 200 HTML 软 404 基线采样与假阳性门禁拦截（绝不产生误报）
		const b1Res = await fetch(`${srv.baseUrl}/portal/__nonexistent_check_a`);
		const b1Body = await b1Res.text();
		const b2Res = await fetch(`${srv.baseUrl}/portal/__nonexistent_check_b`);
		const b2Body = await b2Res.text();
		const baseline = parseSoft404Baseline(
			[
				`BASELINE ${b1Res.status} ${Buffer.byteLength(b1Body, "utf8")} ${extractTitle(b1Body)}`,
				`BASELINE ${b2Res.status} ${Buffer.byteLength(b2Body, "utf8")} ${extractTitle(b2Body)}`,
			].join("\n"),
		);
		assertOk(baseline.active, "Soft-404 基线应激活");

		const trapRes = await fetch(`${srv.baseUrl}/portal/backup-admin-config`);
		const trapBody = await trapRes.text();
		const isTrapSoft404 = isSoft404Hit(
			{
				path: "/portal/backup-admin-config",
				code: trapRes.status,
				size: Buffer.byteLength(trapBody, "utf8"),
				titleSig: extractTitle(trapBody),
				body: trapBody,
			},
			baseline,
		);
		assertOk(isTrapSoft404, "兜底 200 HTML 路径必须被识别为 Soft-404");

		// 同时验证 NuwaCoreEngine 假阳性门禁对同基线 200 HTML 的自动降级保护
		const planRes = await engine.callTool("nuwa_plan", {
			intents: [
				{
					phase: "vuln",
					title: "校验 /portal/backup-admin-config 疑似敏感面板响应",
					targetKey: "/portal/backup-admin-config",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
				{
					phase: "vuln",
					title: "校验 /api/v1/diagnostics/build-meta 未授权内部诊断配置暴露",
					targetKey: "/api/v1/diagnostics/build-meta",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
			],
		});
		const addedIds = (planRes.details?.added as string[] | undefined) ?? [];
		assertOk(addedIds.length === 2, "应规划 2 条验证意图");

		await engine.callTool("nuwa_claim", { id: addedIds[0]!, worker: "fujiang" });
		const downgradedCommit = await engine.callTool("nuwa_commit", {
			id: addedIds[0]!,
			kind: "vuln",
			title: "疑似备份面板暴露",
			detail: "返回 HTTP 200 HTML",
			command: `curl -sS ${srv.baseUrl}/portal/backup-admin-config`,
			output: trapBody,
			raw_response: `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n${trapBody}`,
			baseline: { statusCode: b1Res.status, body: b1Body },
			auto_downgrade: true,
		});
		assertOk(
			!downgradedCommit.isError && downgradedCommit.details?.falsePositive === true,
			"同基线 Soft-404 伪漏洞提交应被假阳性门禁自动降级为 note",
		);
		tickTurn(root, 1);

		// 3. 验证唯一合法测试 API 端点并经双盲复验确认入账
		const diagRes = await fetch(`${srv.baseUrl}/api/v1/diagnostics/build-meta`);
		const diagBody = await diagRes.text();
		assertOk(
			!isSoft404Hit(
				{
					path: "/api/v1/diagnostics/build-meta",
					code: diagRes.status,
					size: Buffer.byteLength(diagBody, "utf8"),
					body: diagBody,
				},
				baseline,
			),
			"真实 JSON 诊断 API 绝不可被误判为 Soft-404",
		);

		const diagVerifyBody = await (await fetch(`${srv.baseUrl}/api/v1/diagnostics/build-meta`)).text();
		await commitAndConfirmFinding({
			engine,
			root,
			intentId: addedIds[1]!,
			title: "未授权暴露内部构建与网关诊断配置 /api/v1/diagnostics/build-meta",
			detail: `携带头 ${t2VaultSecret} 与匿名访问均暴露 debugDiagnosticsEnabled=true 与内部上游元数据`,
			candidateCmd: `curl -sS ${srv.baseUrl}/api/v1/diagnostics/build-meta`,
			candidateOutput: diagBody,
			verifyCmd: `curl -sS ${srv.baseUrl}/api/v1/diagnostics/build-meta`,
			verifyOutput: diagVerifyBody,
		});

		const compRes = await engine.callTool("nuwa_complete", {});
		assertOk(compRes.details?.ok === true, "t2 应完成正向收口");

		const audit = await exportReportsAndAuditSecrets(engine, root, [t2VaultSecret]);
		clearSessionVault(root, stInit.project.id);

		const stFinal = loadState(root)!;
		const truePositives = Math.min(spec.expectedFindings, audit.sarifResultCount);
		const falseNegatives = Math.max(0, spec.expectedFindings - truePositives);
		const falsePositives = Math.max(0, audit.sarifResultCount - spec.expectedFindings);

		return {
			passed:
				stFinal.project.status === "completed" &&
				truePositives === 1 &&
				falsePositives === 0 &&
				audit.vaultLeaks === 0,
			terminalStatus: stFinal.project.status,
			turnsUsed: stFinal.runtime.turns,
			expectedFindings: spec.expectedFindings,
			truePositives,
			falseNegatives,
			falsePositives,
			vaultLeaks: audit.vaultLeaks,
			detail: `429识别=rate-limit(Retry-After=${retryAfter}), Soft-404诱饵降级=true, 合法端点确认=${truePositives}, 误报=${falsePositives}`,
		};
	},

	"t3-blind-ssrf-oob": async (spec, srv, env) => {
		const root = env.makeWorkspace("nuwa-l2-t3-");
		const engine = new NuwaCoreEngine({ projectRoot: root, cwd: root, sessionId: "l2-t3" });
		assertOk(Boolean(srv.collectorUrl), "t3 必须具备本机 127.0.0.1 回调接收收集器");

		await engine.callTool("nuwa_init", {
			target: srv.baseUrl,
			mode: "pentest",
			goal: spec.description,
			scope: {
				allowLoopback: true,
				oobDomains: ["127.0.0.1", "oob.l2.local"],
			},
		});
		const stInit = loadState(root)!;
		env.trackProjectId(stInit.project.id);
		const t3VaultSecret = "l2_oob_poll_auth_secret_334455";
		upsertSessionRole(root, { role: "oob_operator", bearer: t3VaultSecret });
		tickTurn(root, 1);

		const scope = stInit.project.scope!;
		const planRes = await engine.callTool("nuwa_plan", {
			phase: "vuln",
			intents: [
				{
					title: "验证 /api/v1/integrations/health-callback 异步回调无回显服务端请求",
					targetKey: "/api/v1/integrations/health-callback",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
			],
		});
		const intentId = ((planRes.details?.added as string[] | undefined) ?? [])[0]!;
		assertOk(Boolean(intentId), "应规划 OOB 验证意图");

		// 1. 生成唯一 Canary 标识 -> 触发本机回路异步健康检查 -> 从本机收集器轮询确认
		const canary1 = generateOobCanary(root, {
			projectId: stInit.project.id,
			domain: "oob.l2.local",
			scope,
			intentId,
			purpose: "async-health-callback-probe",
		});

		// 同时验证非 127.0.0.1 外部地址被靶场安全护栏拒绝
		const externalAttempt = await fetch(`${srv.baseUrl}/api/v1/integrations/health-callback`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ callbackUrl: `http://example.invalid/${canary1.token}` }),
		});
		assertOk(externalAttempt.status === 400, "靶场必须拒绝非 127.0.0.1 回调地址");

		const callbackUrl1 = `${srv.collectorUrl}/callback/${canary1.token}?canary=${encodeURIComponent(canary1.fqdn)}`;
		const trigger1 = await fetch(`${srv.baseUrl}/api/v1/integrations/health-callback`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ callbackUrl: callbackUrl1 }),
		});
		assertOk(trigger1.status === 202, "异步健康检查应返回盲态 202");

		const poll1 = await pollOobCallbacks(root, {
			pollUrl: `${srv.collectorUrl}/oob/poll?canary=${encodeURIComponent(canary1.token)}`,
			scope,
		});
		assertOk(
			poll1.ok && poll1.matchedCanaries.some((c) => c.id === canary1.id),
			`本机回调收集器应匹配 Canary ${canary1.id}`,
		);

		// 2. 双盲复验员签发第二个独立 Canary 再次执行回路验证
		const canary2 = generateOobCanary(root, {
			projectId: stInit.project.id,
			domain: "oob.l2.local",
			scope,
			purpose: "verifier-recheck",
		});
		const callbackUrl2 = `${srv.collectorUrl}/callback/${canary2.token}?canary=${encodeURIComponent(canary2.fqdn)}`;
		await fetch(`${srv.baseUrl}/api/v1/integrations/health-callback`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ callbackUrl: callbackUrl2 }),
		});
		const poll2 = await pollOobCallbacks(root, {
			pollUrl: `${srv.collectorUrl}/oob/poll?canary=${encodeURIComponent(canary2.token)}`,
			scope,
		});
		assertOk(
			poll2.ok && poll2.matchedCanaries.some((c) => c.id === canary2.id),
			`双盲复验应独立匹配新 Canary ${canary2.id}`,
		);

		await commitAndConfirmFinding({
			engine,
			root,
			intentId,
			title: "Blind SSRF 服务端未鉴权异步回调确认 /api/v1/integrations/health-callback",
			detail: `经本机回路 Canary (${canary1.fqdn}) 与复验 Canary (${canary2.fqdn}) 双向确认（操作凭据 ${t3VaultSecret}）`,
			candidateCmd: `curl -sS "${srv.collectorUrl}/oob/poll?canary=${canary1.token}"`,
			candidateOutput: JSON.stringify({ canary: canary1.fqdn, hits: poll1.hits }),
			verifyCmd: `curl -sS "${srv.collectorUrl}/oob/poll?canary=${canary2.token}"`,
			verifyOutput: JSON.stringify({ canary: canary2.fqdn, hits: poll2.hits }),
		});

		const compRes = await engine.callTool("nuwa_complete", {});
		assertOk(compRes.details?.ok === true, "t3 应完成正向收口");

		const audit = await exportReportsAndAuditSecrets(engine, root, [t3VaultSecret]);
		clearSessionVault(root, stInit.project.id);

		const stFinal = loadState(root)!;
		const truePositives = Math.min(spec.expectedFindings, audit.sarifResultCount);
		const falseNegatives = Math.max(0, spec.expectedFindings - truePositives);
		const falsePositives = Math.max(0, audit.sarifResultCount - spec.expectedFindings);

		return {
			passed:
				stFinal.project.status === "completed" &&
				truePositives === 1 &&
				falsePositives === 0 &&
				audit.vaultLeaks === 0,
			terminalStatus: stFinal.project.status,
			turnsUsed: stFinal.runtime.turns,
			expectedFindings: spec.expectedFindings,
			truePositives,
			falseNegatives,
			falsePositives,
			vaultLeaks: audit.vaultLeaks,
			detail: `Canary生成与回路命中=${srv.getCollectorEvents().length}次, 状态机自动确认=${truePositives}, 误报=${falsePositives}`,
		};
	},

	"t4-hybrid-sourcemap-chain": async (spec, srv, env) => {
		const root = env.makeWorkspace("nuwa-l2-t4-");
		const engine = new NuwaCoreEngine({ projectRoot: root, cwd: root, sessionId: "l2-t4" });

		await engine.callTool("nuwa_init", {
			target: srv.baseUrl,
			mode: "pentest",
			goal: spec.description,
		});
		const stInit = loadState(root)!;
		env.trackProjectId(stInit.project.id);
		const t4VaultSecret = "l2_hybrid_reviewer_session_secret_667788";
		upsertSessionRole(root, { role: "auditor", cookie: `audit_sid=${t4VaultSecret}` });
		tickTurn(root, 1);

		// 1. 拉取前端脚本并提取 sourceMappingURL
		const bundleJs = await (await fetch(`${srv.baseUrl}/static/workflow.bundle.js`)).text();
		const mapMatch = /\/\/#\s*sourceMappingURL=(\S+)/.exec(bundleJs);
		assertOk(Boolean(mapMatch?.[1]), "前端构建产物应包含 sourceMappingURL 注释");

		// 2. 解析公开 .js.map 源码映射提取多步表单参数与未配置鉴权的内部快照路由
		const mapJson = (await (await fetch(`${srv.baseUrl}${mapMatch![1]}`)).json()) as {
			sourcesContent?: string[];
		};
		const joinedSrc = (mapJson.sourcesContent ?? []).join("\n");
		const step1RouteMatch = /fetch\(['"](\/api\/v2\/forms\/validate-ticket)['"]/.exec(joinedSrc);
		const hiddenRouteMatch = /INTERNAL_SNAPSHOT_ROUTE\s*=\s*['"](\/api\/v2\/internal\/audit-snapshot)['"]/.exec(
			joinedSrc,
		);
		const deptMatch = /department:\s*['"]([^'"]+)['"]/.exec(joinedSrc);
		const codeMatch = /ticketCode:\s*['"]([^'"]+)['"]/.exec(joinedSrc);
		assertOk(
			Boolean(step1RouteMatch && hiddenRouteMatch && deptMatch && codeMatch),
			"应从 SourceMap sourcesContent 完整提取多步表单契约与隐藏路由元数据",
		);

		const step1Route = step1RouteMatch![1]!;
		const hiddenRoute = hiddenRouteMatch![1]!;

		// 3. 验证缺少前置表单 stepToken 时直接请求被 428 拦截，通过多步表单校验后未鉴权读取内部快照
		const directRes = await fetch(`${srv.baseUrl}${hiddenRoute}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ stepToken: "invalid", includeConfigMeta: true }),
		});
		assertOk(directRes.status === 428, "未持有效 stepToken 应返回 428");

		const step1Res = await fetch(`${srv.baseUrl}${step1Route}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ department: deptMatch![1], ticketCode: codeMatch![1] }),
		});
		const step1Data = (await step1Res.json()) as { ok?: boolean; stepToken?: string };
		assertOk(step1Res.status === 200 && Boolean(step1Data.stepToken), "第一步表单校验应签发 stepToken");

		const snapRes = await fetch(`${srv.baseUrl}${hiddenRoute}`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ stepToken: step1Data.stepToken, includeConfigMeta: true }),
		});
		const snapText = await snapRes.text();
		assertOk(snapRes.status === 200 && snapText.includes("snap-l2-9042"), "应成功命中未配置鉴权的内部快照路由");

		// 4. 在 NuwaCoreEngine 状态机中记录 SourceMap 事实并完成双盲复验闭环
		await engine.callTool("nuwa_commit", {
			free_note: true,
			kind: "endpoint",
			title: `从 ${mapMatch![1]} 提取隐藏路由 ${hiddenRoute}`,
			detail: `SourceMap 泄露内部路由 ${hiddenRoute} 与前置表单契约 ${step1Route}`,
		});
		tickTurn(root, 1);

		const planRes = await engine.callTool("nuwa_plan", {
			phase: "vuln",
			intents: [
				{
					title: `定向验证 SourceMap 暴露路由 ${hiddenRoute} 缺失角色鉴权`,
					targetKey: hiddenRoute,
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
			],
		});
		const intentId = ((planRes.details?.added as string[] | undefined) ?? [])[0]!;

		const snapVerifyText = await (
			await fetch(`${srv.baseUrl}${hiddenRoute}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ stepToken: step1Data.stepToken, includeConfigMeta: true }),
			})
		).text();

		await commitAndConfirmFinding({
			engine,
			root,
			intentId,
			title: `公开 SourceMap 泄露及内部快照接口未配置管理员鉴权 ${hiddenRoute}`,
			detail: `通过 ${mapMatch![1]} 提取前置票据参数获取 stepToken 后，匿名会话（对比 ${t4VaultSecret}）直接读取内部审计快照`,
			candidateCmd: `curl -sS -X POST ${srv.baseUrl}${hiddenRoute} -d '{"stepToken":"${step1Data.stepToken}"}'`,
			candidateOutput: snapText,
			verifyCmd: `curl -sS -X POST ${srv.baseUrl}${hiddenRoute} -d '{"stepToken":"${step1Data.stepToken}"}'`,
			verifyOutput: snapVerifyText,
		});

		const compRes = await engine.callTool("nuwa_complete", {});
		assertOk(compRes.details?.ok === true, "t4 应完成正向收口");

		const audit = await exportReportsAndAuditSecrets(engine, root, [t4VaultSecret]);
		clearSessionVault(root, stInit.project.id);

		const stFinal = loadState(root)!;
		const truePositives = Math.min(spec.expectedFindings, audit.sarifResultCount);
		const falseNegatives = Math.max(0, spec.expectedFindings - truePositives);
		const falsePositives = Math.max(0, audit.sarifResultCount - spec.expectedFindings);

		return {
			passed:
				stFinal.project.status === "completed" &&
				truePositives === 1 &&
				falsePositives === 0 &&
				audit.vaultLeaks === 0,
			terminalStatus: stFinal.project.status,
			turnsUsed: stFinal.runtime.turns,
			expectedFindings: spec.expectedFindings,
			truePositives,
			falseNegatives,
			falsePositives,
			vaultLeaks: audit.vaultLeaks,
			detail: `SourceMap提取=${hiddenRoute}, 多步表单校验=200, 状态机确认=${truePositives}, 误报=${falsePositives}`,
		};
	},

	"t5-hardened-zero-vuln": async (spec, srv, env) => {
		const root = env.makeWorkspace("nuwa-l2-t5-");
		const engine = new NuwaCoreEngine({ projectRoot: root, cwd: root, sessionId: "l2-t5" });

		await engine.callTool("nuwa_init", {
			target: srv.baseUrl,
			mode: "pentest",
			goal: spec.description,
		});
		const stInit = loadState(root)!;
		env.trackProjectId(stInit.project.id);
		upsertSessionRole(root, { role: "alice", bearer: L2_SYNTHETIC_TOKENS.t5Alice });
		upsertSessionRole(root, { role: "bob", bearer: L2_SYNTHETIC_TOKENS.t5Bob });
		upsertSessionRole(root, { role: "admin", bearer: L2_SYNTHETIC_TOKENS.t5Admin });
		tickTurn(root, 1);

		const scope = stInit.project.scope ?? defaultScopeForTarget(srv.baseUrl, "pentest");

		// 1. 消费初始 recon 种子意图，验证公开面与 SourceMap 均已加固
		const frontier = await engine.callTool("nuwa_frontier", { limit: 10 });
		const seedIds = (frontier.details?.ids as string[] | undefined) ?? [];
		for (const sid of seedIds) {
			await engine.callTool("nuwa_claim", { id: sid, worker: "fujiang" });
			const healthBody = await (await fetch(`${srv.baseUrl}/healthz`)).text();
			await engine.callTool("nuwa_commit", {
				id: sid,
				kind: "service",
				title: "完成基础健康检查与静态资源核查",
				detail: `健康检查正常 (${healthBody})，/static/app.js.map 返回 404 无源码映射暴露`,
				command: `curl -sS ${srv.baseUrl}/healthz`,
				output: healthBody,
			});
			tickTurn(root, 1);
		}

		// 2. 运行多角色鉴权差分矩阵：确认匿名 401、跨角色访问严格 403，findings 为 0
		const diffRes = await runAuthDiffMatrix(
			srv.baseUrl,
			["/api/v1/projects/1001", "/api/v1/projects/1002", "/api/v1/admin/settings"],
			root,
			scope,
		);
		assertOk(diffRes.findings.length === 0, `加固服务不应产生任何越权检出，实际=${diffRes.findings.length}`);

		// 3. 对受保护端点执行状态机审查并记录 blocked/合规排除事实
		const planVuln = await engine.callTool("nuwa_plan", {
			intents: [
				{
					phase: "vuln",
					title: "核查 /api/v1/projects/1001 跨角色属主访问控制",
					targetKey: "/api/v1/projects/1001",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
				{
					phase: "vuln",
					title: "核查 /api/v1/admin/settings 管理接口角色隔离",
					targetKey: "/api/v1/admin/settings",
					expectedKind: "vuln",
					surfaceDomain: "path",
				},
			],
		});
		const checkIds = (planVuln.details?.added as string[] | undefined) ?? [];
		for (const cid of checkIds) {
			await engine.callTool("nuwa_claim", { id: cid, worker: "fujiang" });
			await engine.callTool("nuwa_commit", {
				id: cid,
				blocked: true,
				note: `匿名 401，非授权角色（${L2_SYNTHETIC_TOKENS.t5Bob}）严格返回 403 Forbidden，RBAC 合规无漏洞`,
			});
			tickTurn(root, 1);
		}

		// 4. 验证无实锤证据时普通 nuwa_complete 被拒绝，随即执行合法负向封盘 (sealed_negative)
		const prematureComplete = await engine.callTool("nuwa_complete", {});
		assertOk(prematureComplete.details?.ok === false, "零漏洞状态下请求正向完成必须被门禁拒绝");
		tickTurn(root, 1);

		const sealRes = await engine.callTool("nuwa_complete", {
			seal: true,
			reason: "全量受保护路由均严格执行 401/403 RBAC 边界控制且无 SourceMap/OOB 暴露，执行负向封盘",
			excluded_surface: [
				"/static/app.js.map (404)",
				"/api/v1/projects/prj-1001 (401/403 RBAC enforced)",
				"/api/v1/admin/settings (401/403 Admin enforced)",
			],
			coverage: {
				testedEndpoints: 5,
				authRolesVerified: ["anon", "alice", "bob", "admin"],
			},
		});
		assertOk(
			sealRes.details?.ok === true && sealRes.details?.status === "sealed_negative",
			"加固参考服务应成功收敛至 sealed_negative 终态",
		);
		tickTurn(root, 1);

		const statusRes = await engine.callTool("nuwa_status", {});
		assertOk(statusRes.details?.status === "sealed_negative", "nuwa_status 应报告 sealed_negative");

		const audit = await exportReportsAndAuditSecrets(engine, root, [
			L2_SYNTHETIC_TOKENS.t5Alice,
			L2_SYNTHETIC_TOKENS.t5Bob,
			L2_SYNTHETIC_TOKENS.t5Admin,
		]);
		clearSessionVault(root, stInit.project.id);

		const stFinal = loadState(root)!;
		const turnsUsed = stFinal.runtime.turns;
		const falsePositives = audit.sarifResultCount;

		return {
			passed:
				stFinal.project.status === "sealed_negative" &&
				turnsUsed <= 15 &&
				falsePositives === 0 &&
				audit.vaultLeaks === 0,
			terminalStatus: stFinal.project.status,
			turnsUsed,
			expectedFindings: 0,
			truePositives: 0,
			falseNegatives: 0,
			falsePositives,
			vaultLeaks: audit.vaultLeaks,
			detail: `终态=${stFinal.project.status}, 收敛轮次=${turnsUsed}(<=15), 误报=${falsePositives}, 泄露=${audit.vaultLeaks}`,
		};
	},
};

/**
 * 运行 v6.0 L2 五场景离线微基准套件并计算结构化评分卡与硬门禁结论。
 */
export async function runL2BenchmarkSuite(opts?: RunL2BenchmarkOptions): Promise<L2BenchmarkSummary> {
	const deterministic = Boolean(opts?.deterministic);
	const selectedSpecs = opts?.scenario
		? L2_SCENARIO_SPECS.filter((s) => s.id === opts.scenario)
		: [...L2_SCENARIO_SPECS];

	if (opts?.scenario && selectedSpecs.length === 0) {
		const validIds = L2_SCENARIO_SPECS.map((s) => s.id).join(", ");
		throw new Error(`未知 L2 场景 ID: ${opts.scenario}（可选值: ${validIds}）`);
	}

	const tmpDirs: string[] = [];
	const trackedProjectIds: string[] = [];
	const prevAgentHome = process.env.PI_AGENT_HOME;
	const prevNuwaProject = process.env.NUWA_PROJECT;
	const sandboxHome = mkdtempSync(join(tmpdir(), "nuwa-l2-agent-home-"));
	tmpDirs.push(sandboxHome);
	process.env.PI_AGENT_HOME = sandboxHome;
	delete process.env.NUWA_PROJECT;

	const env: L2EvalEnv = {
		makeWorkspace: (prefix: string) => {
			const dir = mkdtempSync(join(tmpdir(), prefix));
			tmpDirs.push(dir);
			return dir;
		},
		trackProjectId: (id: string) => {
			if (id) trackedProjectIds.push(id);
		},
	};

	const wallStart = Date.now();
	const scenarioResults: L2ScenarioEvalResult[] = [];

	try {
		for (const spec of selectedSpecs) {
			const t0 = Date.now();
			const srv = startL2ScenarioServer(spec.id);
			try {
				const evaluator = SCENARIO_EVALUATORS[spec.id];
				const outcome = await evaluator(spec, srv, env);
				scenarioResults.push({
					id: spec.id,
					name: spec.name,
					category: spec.category,
					durationMs: Date.now() - t0,
					...outcome,
				});
			} catch (err) {
				scenarioResults.push({
					id: spec.id,
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
					durationMs: Date.now() - t0,
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
			try {
				rmSync(join("/tmp/nuwa", pid), { recursive: true, force: true });
			} catch {
				/* ignore */
			}
		}
		for (const dir of tmpDirs) {
			try {
				rmSync(dir, { recursive: true, force: true });
			} catch {
				/* ignore */
			}
		}
	}

	const wallTimeMs = Date.now() - wallStart;
	const totalScenarios = scenarioResults.length;
	const passedScenarios = scenarioResults.filter((r) => r.passed).length;
	const expectedTotalFindings = scenarioResults.reduce((sum, r) => sum + r.expectedFindings, 0);
	const truePositiveCount = scenarioResults.reduce((sum, r) => sum + r.truePositives, 0);
	const falseNegativeCount = scenarioResults.reduce((sum, r) => sum + r.falseNegatives, 0);
	const falsePositiveCount = scenarioResults.reduce((sum, r) => sum + r.falsePositives, 0);
	const vaultLeakCount = scenarioResults.reduce((sum, r) => sum + r.vaultLeaks, 0);

	const recallRate =
		expectedTotalFindings > 0 ? Number((truePositiveCount / expectedTotalFindings).toFixed(4)) : 1.0;
	const falsePositiveRate =
		totalScenarios > 0 ? Number((falsePositiveCount / totalScenarios).toFixed(4)) : 0;

	const hardenedResult = scenarioResults.find((r) => r.id === "t5-hardened-zero-vuln");
	const hardenedSealTurns = hardenedResult ? hardenedResult.turnsUsed : 0;
	const hardenedConvergenceOk = hardenedResult
		? hardenedResult.terminalStatus === "sealed_negative" && hardenedSealTurns > 0 && hardenedSealTurns <= 15
		: true;

	const gates: L2HardGates = {
		recallGate: recallRate === 1.0,
		zeroFalsePositiveGate: falsePositiveRate === 0,
		zeroVaultLeakGate: vaultLeakCount === 0,
		hardenedConvergenceGate: hardenedConvergenceOk,
		allPassed:
			passedScenarios === totalScenarios &&
			recallRate === 1.0 &&
			falsePositiveRate === 0 &&
			vaultLeakCount === 0 &&
			hardenedConvergenceOk,
	};

	const metrics: L2ScorecardMetrics = {
		totalScenarios,
		passedScenarios,
		expectedTotalFindings,
		truePositiveCount,
		falseNegativeCount,
		falsePositiveCount,
		recallRate,
		falsePositiveRate,
		vaultLeakCount,
		hardenedSealTurns,
		wallTimeMs,
	};

	return {
		schema: 2,
		suite: "nuwa-l2-microbench",
		deterministic,
		generatedAt: deterministic ? FIXED_EVAL_TS : new Date().toISOString(),
		metrics,
		gates,
		scenarios: scenarioResults,
	};
}

function formatL2ScorecardTable(summary: L2BenchmarkSummary): string {
	const lines = [
		"pi-nuwa v6.0 L2 离线合成微基准评分卡 (NuwaCoreEngine 状态机闭环)",
		"==========================================================================================",
		`${"SCENARIO".padEnd(28)} ${"STATUS".padEnd(6)} ${"TERMINAL".padEnd(16)} ${"TURNS".padStart(5)} ${"TP/EXP".padStart(7)} ${"FP".padStart(3)}  DETAIL`,
		"------------------------------------------------------------------------------------------",
	];

	for (const s of summary.scenarios) {
		const status = s.passed ? "PASS" : "FAIL";
		const tpExp = `${s.truePositives}/${s.expectedFindings}`;
		const note = s.error ? `ERROR: ${s.error}` : s.detail;
		lines.push(
			`${s.id.padEnd(28)} ${status.padEnd(6)} ${s.terminalStatus.padEnd(16)} ${String(s.turnsUsed).padStart(5)} ${tpExp.padStart(7)} ${String(s.falsePositives).padStart(3)}  ${note}`,
		);
	}

	const m = summary.metrics;
	const g = summary.gates;
	lines.push(
		"------------------------------------------------------------------------------------------",
		`Metrics : passed=${m.passedScenarios}/${m.totalScenarios} | recallRate=${m.recallRate.toFixed(2)} (${m.truePositiveCount}/${m.expectedTotalFindings}) | falsePositiveRate=${m.falsePositiveRate.toFixed(2)} | vaultLeakCount=${m.vaultLeakCount} | hardenedSealTurns=${m.hardenedSealTurns} | wall=${m.wallTimeMs}ms`,
		`Gates   : recall=${g.recallGate ? "PASS" : "FAIL"} | zeroFP=${g.zeroFalsePositiveGate ? "PASS" : "FAIL"} | zeroLeak=${g.zeroVaultLeakGate ? "PASS" : "FAIL"} | hardenedTurns<=15=${g.hardenedConvergenceGate ? "PASS" : "FAIL"} => OVERALL=${g.allPassed ? "PASS" : "FAIL"}`,
	);
	return lines.join("\n");
}

function parseL2CliArgs(argv: readonly string[]): {
	json: boolean;
	deterministic: boolean;
	scenario?: string;
	help: boolean;
} {
	let json = false;
	let deterministic = false;
	let scenario: string | undefined;
	let help = false;

	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i]!;
		if (arg === "--help" || arg === "-h") {
			help = true;
		} else if (arg === "--json") {
			json = true;
		} else if (arg === "--deterministic") {
			deterministic = true;
		} else if (arg === "--scenario") {
			const val = argv[++i];
			if (!val || val.startsWith("-")) {
				throw new Error("--scenario 需要传入场景 ID");
			}
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
		const opts = parseL2CliArgs(process.argv.slice(2));
		if (opts.help) {
			console.log(
				[
					"用法: bun benchmarks/run-l2-eval.ts [--json] [--scenario <id>] [--deterministic] [--help]",
					"",
					"选项:",
					"  --json              输出结构化 JSON 评分卡与硬门禁结论",
					"  --scenario <id>     仅运行单个指定场景（如 t1-spa-jwt-bola / t5-hardened-zero-vuln）",
					"  --deterministic     使用固定时间戳输出确定性 JSON",
					"  -h, --help          显示本帮助信息",
				].join("\n"),
			);
			process.exit(0);
		}

		const summary = await runL2BenchmarkSuite({
			scenario: opts.scenario,
			deterministic: opts.deterministic,
		});
		if (opts.json) {
			console.log(JSON.stringify(summary, null, 2));
		} else {
			console.log(formatL2ScorecardTable(summary));
		}
		process.exit(summary.gates.allPassed ? 0 : 1);
	} catch (err) {
		console.error(`[l2-eval] 错误: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(2);
	}
}
