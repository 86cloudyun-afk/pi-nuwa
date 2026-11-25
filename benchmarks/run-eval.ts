#!/usr/bin/env bun
/**
 * pi-nuwa v5.0 离线确定性安全评估基准测试运行器。
 *
 * 用法:
 *   env -u BUN_OPTIONS bun benchmarks/run-eval.ts [--json] [--deterministic] [--scenario <id>]
 *
 * 特点：
 * - 100% 离线确定性：全部网络交互限定在 `127.0.0.1` 临时随机端口的良性合成模拟服务；
 * - 零外部依赖：仅调用真实 `omp/*` 核心模块；
 * - 严格清理：在 `finally` 中回收全部临时目录、物化头文件与模拟服务端口。
 */
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Database } from "bun:sqlite";
import type { NuwaState } from "../omp/types";
import { classifyAutoFailure, isSoft404Hit, parseSoft404Baseline } from "../omp/autoexec";
import { runSpaRecon } from "../omp/browser-recon";
import {
	isLowEntropyGenericLine,
	recordToolExecution,
	verifyExecutionEvidence,
} from "../omp/evidence";
import { newState } from "../omp/graph";
import { distillProjectExperience, resolveIntentTechKeys } from "../omp/kb";
import {
	buildJsonReport,
	buildSarifReport,
	inferFindingRuleMeta,
	renderStratifiedMarkdownReport,
	writePocBundle,
} from "../omp/reporting";
import { checkScopeAndRisk, defaultScopeForTarget, isHostInScope } from "../omp/scope";
import {
	buildAuthDiffPacketSection,
	clearSessionVault,
	materializeRoleHeaderFile,
	upsertSessionRole,
} from "../omp/session-vault";
import { normalizeTargetForMode, readCfg } from "../omp/storage";
import {
	DOUBLE_BLIND_VERIFY_PRIORITY,
	buildDoubleBlindVerifyIntentSpec,
	filterConfirmedProofs,
	resolveVerificationOutcome,
	shouldStageAsCandidate,
	validateVerificationCommit,
} from "../omp/verifier-gate";
import { BENCH_TOKENS, startMockBenchServer, type MockBenchServer } from "./mock-bench-server";

export interface TargetScenarioSpec {
	id: string;
	name: string;
	category: string;
	expectedVerdict: string;
	description: string;
}

export interface ScenarioRunResult {
	id: string;
	name: string;
	category: string;
	expectedVerdict: string;
	passed: boolean;
	durationMs: number;
	falsePositives: number;
	verifierChecked: boolean;
	verifierCaught: boolean;
	vaultLeaks: number;
	confirmedFindings: number;
	estimatedTokens: number;
	detail: string;
	error?: string;
}

export interface BenchmarkMetrics {
	totalScenarios: number;
	passedScenarios: number;
	passAt1Rate: number;
	falsePositiveCount: number;
	falsePositiveRate: number;
	verifierCatchRate: number;
	vaultLeakCount: number;
	estimatedTokensPerFinding: number;
	wallTimeMs: number;
}

export interface BenchmarkSummary {
	schema: 1;
	deterministic: boolean;
	generatedAt: string;
	metrics: BenchmarkMetrics;
	scenarios: ScenarioRunResult[];
}

interface ScenarioContext {
	server: MockBenchServer;
	deterministic: boolean;
	makeTmpDir: (prefix: string) => string;
	registerProjectId: (id: string) => string;
}

const TARGETS_PATH = resolve(import.meta.dir, "targets.json");
const FIXED_TS = "2026-11-25T00:00:00.000Z";

function loadTargets(): TargetScenarioSpec[] {
	return JSON.parse(readFileSync(TARGETS_PATH, "utf8")) as TargetScenarioSpec[];
}

function assertCondition(cond: boolean, message: string): void {
	if (!cond) throw new Error(message);
}

function sha256Hex(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

function extractHtmlTitle(html: string): string {
	return /<title[^>]*>([^<]{0,120})<\/title>/i.exec(html)?.[1]?.trim() ?? "-";
}

function makeBaseState(targetUrl: string, mode: NuwaState["project"]["mode"] = "pentest"): NuwaState {
	const cfg = readCfg();
	const st = newState(targetUrl, `Benchmark evaluation for ${targetUrl}`, mode, cfg);
	st.project.createdAt = FIXED_TS;
	st.project.updatedAt = FIXED_TS;
	return st;
}

type ScenarioRunner = (spec: TargetScenarioSpec, ctx: ScenarioContext) => Promise<Omit<ScenarioRunResult, "id" | "name" | "category" | "expectedVerdict" | "durationMs">>;

const RUNNERS: Record<string, ScenarioRunner> = {
	"spa-soft404-trap": async (_spec, ctx) => {
		const probePaths = ["/spa/__nuwa_404_check_1", "/spa/__nuwa_404_check_2.json"];
		const baselineLines: string[] = [];
		for (const p of probePaths) {
			const res = await fetch(`${ctx.server.baseUrl}${p}`);
			const body = await res.text();
			const size = Buffer.byteLength(body, "utf8");
			const title = extractHtmlTitle(body);
			baselineLines.push(`BASELINE ${res.status} ${size} ${title}`);
		}
		const baseline = parseSoft404Baseline(baselineLines.join("\n"));
		assertCondition(baseline.active, "Soft-404 baseline should be active for /spa/* catch-all");

		const trapRes = await fetch(`${ctx.server.baseUrl}/spa/nonexistent-secret-panel`);
		const trapBody = await trapRes.text();
		const trapSize = Buffer.byteLength(trapBody, "utf8");
		const trapIsSoft404 = isSoft404Hit(
			{
				path: "/spa/nonexistent-secret-panel",
				code: trapRes.status,
				size: trapSize,
				titleSig: extractHtmlTitle(trapBody),
				body: trapBody,
			},
			baseline,
		);
		assertCondition(trapIsSoft404, "Catch-all SPA route should be suppressed as Soft-404");

		const realApiRes = await fetch(`${ctx.server.baseUrl}/api/orders/1001`);
		const realApiBody = await realApiRes.text();
		const apiIsSoft404 = isSoft404Hit(
			{
				path: "/api/orders/1001",
				code: realApiRes.status,
				size: Buffer.byteLength(realApiBody, "utf8"),
				body: realApiBody,
			},
			baseline,
		);
		assertCondition(!apiIsSoft404, "Real API endpoint returning 401 must not be treated as Soft-404");

		const falsePositives = trapIsSoft404 ? 0 : 1;
		return {
			passed: trapIsSoft404 && !apiIsSoft404,
			falsePositives,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 0,
			estimatedTokens: 900,
			detail: `Soft-404 baseline active (size=${baseline.size}, title=${baseline.titleSig}); suppressed trap route without false positives`,
		};
	},

	"dual-role-bola-idor": async (_spec, ctx) => {
		const root = ctx.makeTmpDir("nuwa-bench-bola-");
		const projectId = ctx.registerProjectId(`bench-bola-${process.pid}-${Date.now()}`);

		upsertSessionRole(root, { role: "user_a", bearer: BENCH_TOKENS.userA });
		upsertSessionRole(root, { role: "user_b", bearer: BENCH_TOKENS.userB });

		const hdrA = materializeRoleHeaderFile(root, projectId, "user_a");
		const hdrB = materializeRoleHeaderFile(root, projectId, "user_b");
		assertCondition(Boolean(hdrA && existsSync(hdrA)), "user_a header file must be materialized");
		assertCondition(Boolean(hdrB && existsSync(hdrB)), "user_b header file must be materialized");

		const diffSection = buildAuthDiffPacketSection(root, "vuln:idor", projectId);
		assertCondition(diffSection.includes("多角色会话差分重放指引"), "Auth diff packet section should be generated");

		let vaultLeaks = 0;
		if (diffSection.includes(BENCH_TOKENS.userA) || diffSection.includes(BENCH_TOKENS.userB)) {
			vaultLeaks += 1;
		}

		const targetUrl = `${ctx.server.baseUrl}/api/orders/1001`;
		const anonRes = await fetch(targetUrl);
		const aRes = await fetch(targetUrl, { headers: { Authorization: `Bearer ${BENCH_TOKENS.userA}` } });
		const bRes = await fetch(targetUrl, { headers: { Authorization: `Bearer ${BENCH_TOKENS.userB}` } });
		const aBody = (await aRes.json()) as { orderId?: number; owner?: string };
		const bBody = (await bRes.json()) as { orderId?: number; owner?: string };

		const bolaDetected =
			anonRes.status === 401 &&
			aRes.status === 200 &&
			bRes.status === 200 &&
			aBody.orderId === 1001 &&
			bBody.owner === "alice" &&
			aBody.owner === bBody.owner;
		assertCondition(bolaDetected, "Expected dual-role BOLA differential hit on /api/orders/1001");

		const meta = inferFindingRuleMeta({
			kind: "vuln",
			title: "BOLA / IDOR on /api/orders/1001",
			detail: "user_b accessed alice's order 1001 while anon returned 401",
		});
		assertCondition(meta.ruleId === "NUWA-BOLA" && meta.cwe === "CWE-639", `Unexpected rule meta: ${JSON.stringify(meta)}`);

		clearSessionVault(root, projectId);
		return {
			passed: bolaDetected && vaultLeaks === 0,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks,
			confirmedFindings: 1,
			estimatedTokens: 2400,
			detail: `anon=${anonRes.status} user_a=${aRes.status} user_b=${bRes.status} owner=${bBody.owner}; rule=${meta.ruleId}/${meta.cwe}`,
		};
	},

	"vertical-bfla-admin": async (_spec, ctx) => {
		const root = ctx.makeTmpDir("nuwa-bench-bfla-");
		upsertSessionRole(root, { role: "admin", bearer: BENCH_TOKENS.admin });
		upsertSessionRole(root, { role: "user_a", bearer: BENCH_TOKENS.userA });

		const endpoint = `${ctx.server.baseUrl}/api/admin/metrics`;
		const anonRes = await fetch(endpoint);
		const adminRes = await fetch(endpoint, { headers: { Authorization: `Bearer ${BENCH_TOKENS.admin}` } });
		const lowRes = await fetch(endpoint, { headers: { Authorization: `Bearer ${BENCH_TOKENS.userA}` } });
		const adminJson = (await adminRes.json()) as { cluster?: string; activeNodes?: number };
		const lowJson = (await lowRes.json()) as { cluster?: string; activeNodes?: number };

		const bflaDetected =
			anonRes.status === 401 &&
			adminRes.status === 200 &&
			lowRes.status === 200 &&
			adminJson.cluster === "bench" &&
			lowJson.activeNodes === adminJson.activeNodes;
		assertCondition(bflaDetected, "Expected vertical BFLA hit on /api/admin/metrics");

		const meta = inferFindingRuleMeta({
			kind: "vuln",
			title: "Vertical BFLA on /api/admin/metrics",
			detail: "Low-privileged user_a accessed admin metrics endpoint",
		});
		assertCondition(meta.ruleId === "NUWA-AUTH" && meta.cwe === "CWE-287", `Unexpected BFLA rule meta: ${JSON.stringify(meta)}`);

		return {
			passed: bflaDetected,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 1,
			estimatedTokens: 2100,
			detail: `anon=${anonRes.status} admin=${adminRes.status} user_a=${lowRes.status}; rule=${meta.ruleId}/${meta.cwe}`,
		};
	},

	"auth-spa-bundle-api": async (_spec, ctx) => {
		const scope = defaultScopeForTarget(ctx.server.baseUrl, "pentest");
		const spaUrl = `${ctx.server.baseUrl}/spa/index`;

		// 1. 匿名静态 SPA + JS Bundle 提取
		const anonRecon = await runSpaRecon(spaUrl, scope, { disablePlaywright: true });
		const anonPaths = anonRecon.endpoints.map((e) => e.path);
		assertCondition(anonRecon.mode === "static", "Expected static fallback mode");
		assertCondition(anonRecon.tech.includes("react"), "Expected React detection from data-reactroot");
		assertCondition(anonPaths.includes("/api/v2/invoices"), "Expected /api/v2/invoices from /spa/app.js");
		assertCondition(anonPaths.includes("/graphql"), "Expected /graphql from /spa/app.js");
		assertCondition(Boolean(anonRecon.fact), "Expected non-null AutoFact from SPA recon");

		// 2. 匿名无法读取受鉴权保护的 admin-panel.js，携带管理员令牌后可发现后台接口
		const unauthAdminBundle = await fetch(`${ctx.server.baseUrl}/spa/admin-panel.js`);
		assertCondition(unauthAdminBundle.status === 401, "Expected 401 for unauthenticated /spa/admin-panel.js");

		const authFetch: Parameters<typeof runSpaRecon>[2] = {
			disablePlaywright: true,
			fetchFn: async (input, init) => {
				const headers = {
					...(init?.headers ?? {}),
					Authorization: `Bearer ${BENCH_TOKENS.admin}`,
				};
				const res = await fetch(input, {
					method: init?.method ?? "GET",
					headers,
					signal: init?.signal,
					redirect: init?.redirect,
				});
				return {
					ok: res.ok,
					status: res.status,
					text: () => res.text(),
					headers: { get: (name: string) => res.headers.get(name) },
				};
			},
		};
		const authRecon = await runSpaRecon(spaUrl, scope, authFetch);
		const authPaths = authRecon.endpoints.map((e) => e.path);
		assertCondition(
			authPaths.includes("/api/v2/admin/audit-logs"),
			"Expected /api/v2/admin/audit-logs from authenticated /spa/admin-panel.js",
		);

		return {
			passed: true,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 0,
			estimatedTokens: 1600,
			detail: `tech=[${anonRecon.tech.join(",")}] anonEndpoints=${anonPaths.length} authEndpoints=${authPaths.length}`,
		};
	},

	"waf-429-rate-limit": async (_spec, ctx) => {
		const res = await fetch(`${ctx.server.baseUrl}/waf/probe`);
		const body = await res.text();
		const retryAfter = res.headers.get("retry-after") ?? "";
		const remaining = res.headers.get("x-ratelimit-remaining") ?? "";
		assertCondition(res.status === 429, `Expected HTTP 429, got ${res.status}`);
		assertCondition(retryAfter === "5" && remaining === "0", "Expected rate-limit headers from /waf/probe");

		const rawTranscript = [
			`HTTP/1.1 ${res.status} Too Many Requests`,
			`Retry-After: ${retryAfter}`,
			`X-RateLimit-Remaining: ${remaining}`,
			``,
			body,
		].join("\n");
		const verdict = classifyAutoFailure({ stdout: rawTranscript, stderr: "", code: 0 });
		assertCondition(verdict.errorKind === "blocked_by_waf", `Expected blocked_by_waf, got ${verdict.errorKind}`);
		assertCondition(verdict.waf === "rate-limit", `Expected waf=rate-limit, got ${verdict.waf}`);

		return {
			passed: true,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 0,
			estimatedTokens: 800,
			detail: `HTTP 429 classified as ${verdict.errorKind} (waf=${verdict.waf}, Retry-After=${retryAfter})`,
		};
	},

	"blind-ssrf-oob-mock": async (_spec, ctx) => {
		const scope = defaultScopeForTarget(ctx.server.baseUrl, "pentest", {
			oobDomains: ["oast.bench.local"],
		});
		const canaryHost = "ssrf-canary-01.oast.bench.local";

		assertCondition(isHostInScope(canaryHost, scope).ok, "Configured oobDomains canary host must be in scope");
		assertCondition(!isHostInScope("rogue.outside.invalid", scope).ok, "Unlisted external domain must be rejected");

		const safeCmd = `curl -sS "${ctx.server.baseUrl}/oob/trigger?canary=${canaryHost}"`;
		assertCondition(checkScopeAndRisk(safeCmd, scope, "pentest") === null, "In-scope OOB probe command should pass N-007");

		const trigRes = await fetch(`${ctx.server.baseUrl}/oob/trigger?canary=${encodeURIComponent(canaryHost)}`);
		assertCondition(trigRes.status === 200, "OOB trigger endpoint should succeed");

		const pollRes = await fetch(`${ctx.server.baseUrl}/oob/poll?canary=${encodeURIComponent(canaryHost)}`);
		const pollJson = (await pollRes.json()) as { data?: Array<{ host?: string; "full-id"?: string }> };
		const serverHits = ctx.server.getOobHits();

		const hitRecorded =
			Array.isArray(pollJson.data) &&
			pollJson.data.some((d) => d["full-id"] === canaryHost) &&
			serverHits.some((h) => h.host === canaryHost);
		assertCondition(hitRecorded, "Expected deterministic Interactsh-compatible OOB hit");

		const meta = inferFindingRuleMeta({
			kind: "vuln",
			title: "Blind SSRF confirmed via OOB canary",
			detail: `Received out-of-band callback for ${canaryHost}`,
		});
		assertCondition(meta.ruleId === "NUWA-SSRF" && meta.cwe === "CWE-918", `Unexpected SSRF rule meta: ${JSON.stringify(meta)}`);

		return {
			passed: hitRecorded,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 1,
			estimatedTokens: 2200,
			detail: `OOB canary ${canaryHost} verified (${serverHits.length} hit); rule=${meta.ruleId}/${meta.cwe}`,
		};
	},

	"mixed-tech-attribution": async (_spec, ctx) => {
		const dir = ctx.makeTmpDir("nuwa-bench-kb-");
		const dbPath = join(dir, "kb.db");
		const st = makeBaseState("http://10.0.0.50:8080", "pentest");
		st.facts = {
			f001: {
				id: "f001",
				kind: "service",
				title: "HTTP 200 nginx + Spring Boot + Redis",
				detail: "nginx proxy -> spring boot -> redis",
				createdAt: FIXED_TS,
				meta: { tech: ["nginx", "spring", "redis"] },
			},
			f002: {
				id: "f002",
				kind: "vuln",
				title: "Spring Actuator Exposure",
				detail: "spring /actuator/env confirmed",
				createdAt: FIXED_TS,
				verifyStage: "confirmed",
			},
			f003: {
				id: "f003",
				kind: "vuln",
				title: "Unverified Redis Candidate",
				detail: "redis candidate awaiting verifier",
				createdAt: FIXED_TS,
				verifyStage: "candidate",
			},
			f004: {
				id: "f004",
				kind: "vuln",
				title: "Rejected Spring SQLi False Positive",
				detail: "spring query parameter negative control matched",
				createdAt: FIXED_TS,
				verifyStage: "rejected",
				verifyNote: "negative control identical",
			},
		};
		st.intents = {
			i001: {
				id: "i001",
				phase: "vuln",
				key: "kb:f001:spring",
				title: "Spring Actuator check",
				detail: "",
				from: ["f001"],
				to: "f002",
				status: "done",
				priority: 86,
				attempts: 1,
				createdAt: FIXED_TS,
			},
			i002: {
				id: "i002",
				phase: "vuln",
				key: "kb:f001:redis",
				title: "Redis candidate check",
				detail: "",
				from: ["f001"],
				to: "f003",
				status: "done",
				priority: 80,
				attempts: 1,
				createdAt: FIXED_TS,
			},
			i003: {
				id: "i003",
				phase: "vuln",
				key: "vuln:sqli",
				title: "Spring SQLi check",
				detail: "",
				from: ["f001"],
				to: "f004",
				status: "done",
				priority: 90,
				attempts: 1,
				createdAt: FIXED_TS,
			},
		};

		const attr = resolveIntentTechKeys(st.intents.i001, [st.facts.f002], st, ["nginx", "spring", "redis"]);
		assertCondition(attr.length === 1 && attr[0] === "spring", `Expected precise attribution ["spring"], got ${JSON.stringify(attr)}`);

		const res = distillProjectExperience(st, { dbPath });
		assertCondition(res.ok && res.positive === 1 && res.negative === 1 && res.skipped >= 1, `Unexpected distill result: ${JSON.stringify(res)}`);

		const db = new Database(dbPath, { readonly: true });
		try {
			const rows = db.query("SELECT tech_key, intent_key, success_count, fail_count FROM experience").all() as Array<{
				tech_key: string;
				intent_key: string;
				success_count: number;
				fail_count: number;
			}>;
			assertCondition(
				rows.some((r) => r.tech_key === "spring" && r.intent_key === "kb:spring" && r.success_count === 1),
				"spring kb success must be recorded",
			);
			assertCondition(
				!rows.some((r) => r.tech_key === "redis"),
				"redis must not be polluted by candidate or spring finding",
			);
			assertCondition(
				!rows.some((r) => r.tech_key === "nginx"),
				"nginx must not be polluted by spring finding",
			);
		} finally {
			db.close();
		}

		return {
			passed: true,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 1,
			estimatedTokens: 1500,
			detail: `Precise attribution=[${attr.join(",")}], positive=${res.positive}, negative=${res.negative}, skipped=${res.skipped}`,
		};
	},

	"false-positive-verifier-catch": async (_spec, ctx) => {
		const st = makeBaseState(ctx.server.baseUrl, "audit");
		assertCondition(
			shouldStageAsCandidate({ kind: "vuln", intentKey: "vuln:sqli", doubleBlindEnabled: true }),
			"Manual vuln commit must stage as candidate",
		);

		st.facts.f001 = {
			id: "f001",
			kind: "vuln",
			title: "Suspected SQLi on /spa/search",
			detail: "Returned HTTP 200 on single quote",
			command: `curl -sS ${ctx.server.baseUrl}/spa/search?q=1'`,
			output: "<!doctype html><title>Bench SPA</title>",
			createdAt: FIXED_TS,
			verifyStage: "candidate",
		};

		const verifySpec = buildDoubleBlindVerifyIntentSpec(st, st.facts.f001);
		assertCondition(verifySpec !== null && verifySpec.priority === DOUBLE_BLIND_VERIFY_PRIORITY, "Expected P96 verify intent");
		assertCondition(verifySpec!.recommendedAgent === "nuwa-verifier", "Expected nuwa-verifier agent recommendation");

		// Anti-bypass validation checks
		const noteBypass = validateVerificationCommit({ intentKey: verifySpec!.key, kind: "note" });
		const staleBypass = validateVerificationCommit({
			intentKey: verifySpec!.key,
			kind: "vuln",
			hasFreshExecution: false,
		});
		assertCondition(!noteBypass.ok && !staleBypass.ok, "Anti-bypass gates must reject note and stale evidence");

		// Double-blind verifier rejects false positive
		const outcome = resolveVerificationOutcome(st, verifySpec!.key, true, "Negative control matches SPA Soft-404 shell");
		assertCondition(outcome.matched && outcome.stage === "rejected", "Expected verifier rejection");

		const proofs = filterConfirmedProofs(st.facts, ["vuln"]);
		assertCondition(proofs.length === 0, "Rejected finding must not satisfy proof gate");

		const sarif = buildSarifReport(st) as { runs: Array<{ results: unknown[] }> };
		const sarifCount = sarif.runs?.[0]?.results?.length ?? -1;
		assertCondition(sarifCount === 0, `SARIF must exclude rejected findings, got ${sarifCount}`);

		return {
			passed: true,
			falsePositives: sarifCount,
			verifierChecked: true,
			verifierCaught: outcome.stage === "rejected" && sarifCount === 0,
			vaultLeaks: 0,
			confirmedFindings: 0,
			estimatedTokens: 1700,
			detail: `Verifier caught Soft-404 false positive (stage=${outcome.stage}, sarifResults=${sarifCount})`,
		};
	},

	"local-whitebox-audit": async (_spec, ctx) => {
		const workspace = ctx.makeTmpDir("nuwa-bench-whitebox-");
		writeFileSync(
			join(workspace, "app.ts"),
			'export function getOrder(id: string) { return { id, scope: "synthetic" }; }\n',
			"utf8",
		);

		const norm = normalizeTargetForMode(workspace, "coding");
		assertCondition(norm.scheme === "local" && norm.port === 0, `Expected local target normalization, got ${JSON.stringify(norm)}`);

		const st = makeBaseState(workspace, "coding");
		assertCondition(st.project.scheme === "local", "State should store local scheme for coding mode");

		recordToolExecution(workspace, {
			tool: "bash",
			command: "grep -n getOrder app.ts",
			output: '1:export function getOrder(id: string) { return { id, scope: "synthetic" }; }\nHTTP/1.1 200 OK',
			agentName: "fujiang",
		});

		assertCondition(isLowEntropyGenericLine("HTTP/1.1 200 OK"), "Generic HTTP status line must be flagged low-entropy");

		const genericCheck = verifyExecutionEvidence(workspace, {
			projectId: st.project.id,
			kind: "vuln",
			command: "grep -n getOrder app.ts",
			output: "HTTP/1.1 200 OK",
			strict: true,
			requireSubstantive: true,
		});
		assertCondition(!genericCheck.verified, "Generic header-only evidence must be rejected");

		const substantiveCheck = verifyExecutionEvidence(workspace, {
			projectId: st.project.id,
			kind: "vuln",
			command: "grep -n getOrder app.ts",
			output: 'export function getOrder(id: string) { return { id, scope: "synthetic" }; }',
			strict: true,
			requireSubstantive: true,
		});
		assertCondition(substantiveCheck.verified, `Substantive ledger match should pass: ${substantiveCheck.reason ?? ""}`);

		return {
			passed: true,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks: 0,
			confirmedFindings: 0,
			estimatedTokens: 1100,
			detail: `Normalized local target (${norm.url}); substantive ledger verified (seq=${substantiveCheck.matchedSeq})`,
		};
	},

	"vault-leak-sarif-redaction": async (_spec, ctx) => {
		const root = ctx.makeTmpDir("nuwa-bench-redaction-");
		const secretBearer = "eyJhbGciOiJIUzI1NiJ9.benchSecretPayload999.sig887766";
		const secretCookieVal = "bench_cookie_secret_445566";
		const secretApiKey = "sk-bench-live-secret-key-998877";
		const secretPassword = "BenchVaultPassword!2026";
		const rawSecrets = [secretBearer, "benchSecretPayload999", secretCookieVal, secretApiKey, secretPassword];

		upsertSessionRole(root, {
			role: "admin",
			bearer: secretBearer,
			cookie: `sid=${secretCookieVal}`,
			headers: { "X-API-Key": secretApiKey },
			username: "bench_admin",
			password: secretPassword,
		});

		const st = makeBaseState(ctx.server.baseUrl, "pentest");
		st.runtime.generation = 2;
		st.runtime.totalTurns = 14;
		st.runtime.totalTokens = 32000;
		st.runtime.tokens = 4500;
		st.runtime.totalCostUsd = 0.1095;
		st.assets = {
			a001: {
				id: "a001",
				kind: "web",
				target: `${ctx.server.baseUrl}/api?key=${secretApiKey}`,
				host: "127.0.0.1",
				port: ctx.server.port,
				tags: ["bench", "api"],
				createdAt: FIXED_TS,
			},
		};
		st.hypotheses = {
			h001: {
				id: "h001",
				title: "Admin order access hypothesis",
				statement: `Token ${secretBearer} grants access`,
				requiredFacts: ["f001"],
				falsificationTest: "Compare anonymous 401 vs authenticated 200",
				expectedGain: 9,
				estimatedCost: 2,
				status: "confirmed",
				linkedIntents: ["i001"],
				createdAt: FIXED_TS,
				updatedAt: FIXED_TS,
			},
		};
		st.facts = {
			f001: {
				id: "f001",
				kind: "vuln",
				title: `Confirmed BOLA on /api/orders/1001 (${secretApiKey})`,
				detail: `Replayed with Cookie sid=${secretCookieVal} and password=${secretPassword}`,
				command: `curl -H "Authorization: Bearer ${secretBearer}" ${ctx.server.baseUrl}/api/orders/1001`,
				output: `{"orderId":1001,"owner":"alice","echo":"${secretBearer}"}`,
				createdAt: FIXED_TS,
				verifyStage: "confirmed",
				verified: true,
				verifyNote: `Verified with ${secretPassword}`,
			},
			f002: {
				id: "f002",
				kind: "vuln",
				title: "Candidate XSS awaiting verifier",
				detail: `Contains secret ${secretCookieVal}`,
				createdAt: FIXED_TS,
				verifyStage: "candidate",
			},
			f003: {
				id: "f003",
				kind: "vuln",
				title: "Rejected SQLi false positive",
				detail: "Negative control matched",
				createdAt: FIXED_TS,
				verifyStage: "rejected",
				verifyNote: "Soft-404",
			},
		};

		const md = renderStratifiedMarkdownReport(st, root);
		const jsonReport = buildJsonReport(st, root);
		const sarifReport = buildSarifReport(st, root) as {
			$schema?: string;
			version?: string;
			runs?: Array<{ results?: Array<{ ruleId?: string; properties?: { factId?: string } }> }>;
		};
		const bundle = writePocBundle(root, st);

		// Verify SARIF schema & confirmed-only discipline
		assertCondition(sarifReport.version === "2.1.0", "SARIF version must be 2.1.0");
		assertCondition(
			sarifReport.$schema === "https://json.schemastore.org/sarif-2.1.0.json",
			"SARIF $schema must match 2.1.0 schema",
		);
		const results = sarifReport.runs?.[0]?.results ?? [];
		assertCondition(results.length === 1, `SARIF must contain exactly 1 confirmed vuln, got ${results.length}`);
		assertCondition(results[0]?.properties?.factId === "f001", "SARIF result must be confirmed f001");
		assertCondition(results[0]?.ruleId === "NUWA-BOLA", `Expected NUWA-BOLA, got ${results[0]?.ruleId}`);

		// Verify Markdown stratified sections
		assertCondition(md.includes("## 待复验候选漏洞（Candidate）"), "Markdown must include Candidate section");
		assertCondition(md.includes("## 已驳回误报（Rejected）"), "Markdown must include Rejected section");
		assertCondition(md.includes("## 多资产与跳板拓扑"), "Markdown must include Assets section");
		assertCondition(md.includes("## 假设图推理状态"), "Markdown must include Hypotheses section");

		// Verify bundle permissions & SHA-256 manifest
		assertCondition((statSync(bundle.dir).mode & 0o777) === 0o700, "poc-bundle dir must be 0o700");
		assertCondition(bundle.confirmedCount === 1, "bundle.confirmedCount must be 1");
		const manifestRaw = readFileSync(bundle.manifestPath, "utf8");
		const manifest = JSON.parse(manifestRaw) as {
			confirmedCount: number;
			files: Array<{ name: string; sha256: string; bytes: number }>;
		};
		assertCondition(manifest.confirmedCount === 1, "manifest confirmedCount must be 1");
		for (const fEntry of manifest.files) {
			const fp = join(bundle.dir, fEntry.name);
			assertCondition(existsSync(fp), `Bundle file missing: ${fEntry.name}`);
			assertCondition((statSync(fp).mode & 0o777) === 0o600, `Bundle file must be 0o600: ${fEntry.name}`);
			const content = readFileSync(fp, "utf8");
			assertCondition(sha256Hex(content) === fEntry.sha256, `SHA-256 mismatch for ${fEntry.name}`);
		}

		// Scan ALL artifacts for any secret leak
		const corpus: Array<{ label: string; text: string }> = [
			{ label: "markdown", text: md },
			{ label: "json", text: JSON.stringify(jsonReport) },
			{ label: "sarif", text: JSON.stringify(sarifReport) },
			...bundle.files.map((fp) => ({ label: fp, text: readFileSync(fp, "utf8") })),
		];

		let vaultLeaks = 0;
		for (const item of corpus) {
			for (const secret of rawSecrets) {
				if (item.text.includes(secret)) {
					vaultLeaks += 1;
				}
			}
		}
		assertCondition(vaultLeaks === 0, `Detected ${vaultLeaks} raw Vault secret leak(s) in reporting outputs`);

		return {
			passed: vaultLeaks === 0,
			falsePositives: 0,
			verifierChecked: false,
			verifierCaught: false,
			vaultLeaks,
			confirmedFindings: 1,
			estimatedTokens: 1900,
			detail: `0 Vault leaks across Markdown/JSON/SARIF/${bundle.files.length} bundle files; manifest SHA-256 verified`,
		};
	},
};

export async function runBenchmarks(opts?: {
	deterministic?: boolean;
	scenario?: string;
}): Promise<BenchmarkSummary> {
	const deterministic = Boolean(opts?.deterministic);
	const allTargets = loadTargets();
	const selected = opts?.scenario
		? allTargets.filter((t) => t.id === opts.scenario)
		: allTargets;

	if (opts?.scenario && selected.length === 0) {
		throw new Error(`Unknown scenario id: ${opts.scenario} (valid: ${allTargets.map((t) => t.id).join(", ")})`);
	}

	const tmpDirs: string[] = [];
	const tmpProjectIds: string[] = [];
	const prevAgentHome = process.env.PI_AGENT_HOME;
	const benchHome = mkdtempSync(join(tmpdir(), "nuwa-bench-home-"));
	tmpDirs.push(benchHome);
	process.env.PI_AGENT_HOME = benchHome;

	const server = startMockBenchServer();
	const wallStart = Date.now();
	const results: ScenarioRunResult[] = [];

	const ctx: ScenarioContext = {
		server,
		deterministic,
		makeTmpDir: (prefix: string) => {
			const d = mkdtempSync(join(tmpdir(), prefix));
			tmpDirs.push(d);
			return d;
		},
		registerProjectId: (id: string) => {
			tmpProjectIds.push(id);
			return id;
		},
	};

	try {
		for (const spec of selected) {
			const runner = RUNNERS[spec.id];
			const t0 = Date.now();
			if (!runner) {
				results.push({
					id: spec.id,
					name: spec.name,
					category: spec.category,
					expectedVerdict: spec.expectedVerdict,
					passed: false,
					durationMs: Date.now() - t0,
					falsePositives: 0,
					verifierChecked: false,
					verifierCaught: false,
					vaultLeaks: 0,
					confirmedFindings: 0,
					estimatedTokens: 0,
					detail: "No runner registered",
					error: `Missing runner for scenario ${spec.id}`,
				});
				continue;
			}
			try {
				const out = await runner(spec, ctx);
				results.push({
					id: spec.id,
					name: spec.name,
					category: spec.category,
					expectedVerdict: spec.expectedVerdict,
					durationMs: Date.now() - t0,
					...out,
				});
			} catch (err) {
				results.push({
					id: spec.id,
					name: spec.name,
					category: spec.category,
					expectedVerdict: spec.expectedVerdict,
					passed: false,
					durationMs: Date.now() - t0,
					falsePositives: 0,
					verifierChecked: false,
					verifierCaught: false,
					vaultLeaks: 0,
					confirmedFindings: 0,
					estimatedTokens: 0,
					detail: "Scenario execution failed",
					error: err instanceof Error ? err.message : String(err),
				});
			}
		}
	} finally {
		server.stop();
		if (prevAgentHome === undefined) delete process.env.PI_AGENT_HOME;
		else process.env.PI_AGENT_HOME = prevAgentHome;

		for (const pid of tmpProjectIds) {
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
	const totalScenarios = results.length;
	const passedScenarios = results.filter((r) => r.passed).length;
	const falsePositiveCount = results.reduce((sum, r) => sum + r.falsePositives, 0);
	const vaultLeakCount = results.reduce((sum, r) => sum + r.vaultLeaks, 0);
	const verifierChecked = results.filter((r) => r.verifierChecked).length;
	const verifierCaught = results.filter((r) => r.verifierChecked && r.verifierCaught).length;
	const totalConfirmed = results.reduce((sum, r) => sum + r.confirmedFindings, 0);
	const totalEstimatedTokens = results.reduce((sum, r) => sum + r.estimatedTokens, 0);

	const round4 = (n: number) => Number(n.toFixed(4));

	const metrics: BenchmarkMetrics = {
		totalScenarios,
		passedScenarios,
		passAt1Rate: totalScenarios > 0 ? round4(passedScenarios / totalScenarios) : 0,
		falsePositiveCount,
		falsePositiveRate: totalScenarios > 0 ? round4(falsePositiveCount / totalScenarios) : 0,
		verifierCatchRate: verifierChecked > 0 ? round4(verifierCaught / verifierChecked) : 1,
		vaultLeakCount,
		estimatedTokensPerFinding: Math.round(totalEstimatedTokens / Math.max(1, totalConfirmed)),
		wallTimeMs,
	};

	return {
		schema: 1,
		deterministic,
		generatedAt: deterministic ? FIXED_TS : new Date().toISOString(),
		metrics,
		scenarios: results,
	};
}

function formatHumanTable(summary: BenchmarkSummary): string {
	const header = [
		`pi-nuwa Offline Deterministic Security Benchmarks`,
		`================================================================================`,
		`${"SCENARIO".padEnd(32)} ${"CATEGORY".padEnd(18)} ${"STATUS".padEnd(6)} ${"MS".padStart(5)}  DETAIL`,
		`--------------------------------------------------------------------------------`,
	];
	const rows = summary.scenarios.map((s) => {
		const status = s.passed ? "PASS" : "FAIL";
		const note = s.error ? `ERROR: ${s.error}` : s.detail;
		return `${s.id.padEnd(32)} ${s.category.padEnd(18)} ${status.padEnd(6)} ${String(s.durationMs).padStart(5)}  ${note}`;
	});
	const m = summary.metrics;
	const footer = [
		`--------------------------------------------------------------------------------`,
		`Summary: ${m.passedScenarios}/${m.totalScenarios} passed (pass@1=${(m.passAt1Rate * 100).toFixed(1)}%) | FP=${m.falsePositiveCount} (${(m.falsePositiveRate * 100).toFixed(1)}%) | verifierCatch=${(m.verifierCatchRate * 100).toFixed(1)}% | vaultLeaks=${m.vaultLeakCount} | estTokens/finding=${m.estimatedTokensPerFinding} | wall=${m.wallTimeMs}ms`,
	];
	return [...header, ...rows, ...footer].join("\n");
}

function parseCliArgs(argv: string[]): { json: boolean; deterministic: boolean; scenario?: string; help: boolean } {
	let json = false;
	let deterministic = false;
	let scenario: string | undefined;
	let help = false;

	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i]!;
		if (arg === "-h" || arg === "--help") {
			help = true;
		} else if (arg === "--json") {
			json = true;
		} else if (arg === "--deterministic") {
			deterministic = true;
		} else if (arg === "--scenario") {
			const val = argv[++i];
			if (!val) throw new Error("--scenario requires a scenario id");
			scenario = val.trim();
		} else if (arg.startsWith("--scenario=")) {
			scenario = arg.slice("--scenario=".length).trim();
		} else {
			throw new Error(`Unknown option: ${arg}`);
		}
	}
	return { json, deterministic, scenario, help };
}

if (import.meta.main) {
	try {
		const opts = parseCliArgs(process.argv.slice(2));
		if (opts.help) {
			console.log(
				[
					"Usage: bun benchmarks/run-eval.ts [--json] [--deterministic] [--scenario <id>]",
					"",
					"Options:",
					"  --json            Output machine-readable JSON summary",
					"  --deterministic   Enable deterministic timestamp and fixed-seed mode",
					"  --scenario <id>   Run a single scenario by ID from benchmarks/targets.json",
					"  -h, --help        Show this help",
				].join("\n"),
			);
			process.exit(0);
		}
		const summary = await runBenchmarks({
			deterministic: opts.deterministic,
			scenario: opts.scenario,
		});
		if (opts.json) {
			console.log(JSON.stringify(summary, null, 2));
		} else {
			console.log(formatHumanTable(summary));
		}
		const ok =
			summary.metrics.passedScenarios === summary.metrics.totalScenarios &&
			summary.metrics.vaultLeakCount === 0;
		process.exit(ok ? 0 : 1);
	} catch (err) {
		console.error(`[benchmarks] ERROR: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(2);
	}
}
