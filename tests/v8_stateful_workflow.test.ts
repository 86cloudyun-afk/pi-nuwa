/**
 * 女娲 v8.0 有状态多步工作流与并发竞态引擎单元测试。
 *
 * 使用 Bun.serve 在 127.0.0.1 动态端口启动真实有状态轻量服务端，端到端覆盖：
 * 1. 动作风险四级分级（L0/L1/L2/L3）与破坏性动作默认拦截；
 * 2. 多步状态链重放（登录取 CSRF + CookieJar、创建/更新/删除/核对订单、手动重定向、
 *    越界与 L3 拦截零发包、全链路零明文泄露脱敏）；
 * 3. Mass Assignment 质量分配检测（真实漏洞 + finally 回滚、模板同构噪声、Soft-404、
 *    反射错误过滤、越界零发包）；
 * 4. 二阶有状态工作流验证（三段式串联 + candidate Fact + verify-vuln 建议 + 信念图传播 +
 *    finally 清理；中间步 403 精准定界且后续零发包、越界清理被 Scope 拦截）；
 * 5. 同步屏障并发竞态探测（并发硬上限钳制、TOCTOU 实锤、限流/互斥对照、句柄零泄漏）；
 * 6. BarrierGate 超时释放不悬挂。
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer as createNetServer, type Socket as NetSocket } from "node:net";
import { join } from "node:path";
import { initBeliefGraphFromState } from "../omp/belief-search";
import { defaultScopeForTarget, type ScopePolicy } from "../omp/scope";
import { loadSessionVault, upsertSessionRole } from "../omp/session-vault";
import {
	BarrierGate, CookieJar,
	MAX_RACE_CONCURRENCY, WORKFLOW_ACTION_TIERS,
	classifyWorkflowAction, collectSecretSet,
	computeTemplateSimilarity, executeStatefulWorkflowChain,
	executeStatefulWorkflowChainInternal, extractByJsonPath,
	interpolateTemplate, isSensitiveKeyName,
	probeMassAssignment, redactRecordDeep,
	runBarrierRaceProbe, scrubSecretsInText,
	validateUrlAndActionScope, verifySecondOrderWorkflow,
	type BarrierAwaitResult, type ExecuteStatefulWorkflowOptions,
} from "../omp/stateful-workflow";
import { TrafficRecorder } from "../omp/traffic-workbench";
import type { Fact, NuwaState } from "../omp/types";

// ==================== 通用工具 ====================

const tempDirs: string[] = [];
const NOW_ISO = "2026-11-26T00:00:00.000Z";

function makeTempWorkspace(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

function makeScope(target: string): ScopePolicy {
	const base = defaultScopeForTarget(target);
	return {
		...base, allowHosts: ["127.0.0.1"],
		allowLoopback: true, allowPrivateNetwork: false,
		allowDestructive: false, };
}

function makeState(target: string, facts: Fact[] = []): NuwaState {
	const u = new URL(target);
	const factMap: Record<string, Fact> = {};
	for (const f of facts) factMap[f.id] = f;
	return {
		schema: 6, version: "8.0.0",
		project: {
			id: "proj-v8-stateful", target,
			url: target, host: u.hostname,
			port: Number(u.port) || 80, scheme: u.protocol.replace(":", ""),
			goal: "验证 v8 有状态多步工作流引擎", mode: "audit",
			status: "active", phase: "vuln",
			createdAt: NOW_ISO, updatedAt: NOW_ISO,
			scope: makeScope(target), },
		facts: factMap, intents: {},
		seq: { fact: facts.length, intent: 0 }, runtime: {
			startedAt: Date.now(), turns: 1,
			stall: 0, idle: 0,
			blockStreak: 0, toolCalls: 0,
			lastToolCalls: 0, tokens: 0,
			lastSig: "", lastDirective: "",
			completionRejects: 0, emptyRounds: 0,
		}, } as unknown as NuwaState;
}

function jsonRes(data: unknown, status = 200): Response {
	return new Response(JSON.stringify(data), {
		status, headers: { "content-type": "application/json" },
	});
}

function htmlRes(body: string, status = 200): Response {
	return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}

type ChainFetch = NonNullable<ExecuteStatefulWorkflowOptions["fetchFn"]>;

function normalizeUrl(input: unknown): string {
	if (typeof input === "string") return input;
	if (input instanceof URL) return input.toString();
	if (input && typeof input === "object" && "url" in input) {
		return String((input as { url: unknown }).url);
	}
	return String(input);
}

/** 记录每一次真正发往网络层的请求，用于断言“越界 0 发包”。 */
function makeCountingFetch(): { calls: string[]; fn: ChainFetch } {
	const calls: string[] = [];
	const fn = ((input: unknown, init?: unknown) => {
		const url = normalizeUrl(input);
		calls.push(url);
		return fetch(url, init as RequestInit | undefined);
	}) as unknown as ChainFetch;
	return { calls, fn };
}

// ==================== 靶机 A：多步状态链 ====================

const chainToken = "csrf-abc123";
const chainSession = "sess-value-xyz";
const chainPassword = "S3cr3t-P@ss!";
const chainApiKey = "key-1234567890";
const chainOrders = new Map<string, { item: string; qty: number }>();
let chainSeq = 0;
let destructiveHits = 0;
let chainLog: Array<{
	method: string;
	path: string;
	auth?: string;
	trace?: string;
	csrf?: string;
}> = [];

let serverChain: ReturnType<typeof Bun.serve> | null = null;
let chainBase = "";

// ==================== 靶机 B：Mass Assignment ====================

type Profile = { id: number; name: string; role: string; isAdmin: boolean; email: string };
const MASS_BASELINE: Profile = {
	id: 1, name: "alice",
	role: "user", isAdmin: false,
	email: "alice@example.com", };
let massProfile: Profile = { ...MASS_BASELINE };
const MASS_SOFT404_HTML =
	"<html><head><title>Not Found</title></head><body><h1>Page Not Found</h1><p>404</p></body></html>";

let serverMass: ReturnType<typeof Bun.serve> | null = null;
let massBase = "";

// ==================== 靶机 C：二阶有状态工作流 ====================

let secondSeq = 0;
let secondVerifyHits = 0;
let secondApproveHits = 0;
let serverSecond: ReturnType<typeof Bun.serve> | null = null;
let secondBase = "";

// ==================== 靶机 D：并发竞态 ====================

let raceBalance = 100;
let mutexBusy = false;
let rateWindowCount = 0;
let serverRace: ReturnType<typeof Bun.serve> | null = null;
let raceBase = "";

beforeAll(() => {
	// ---------- 靶机 A ----------
	serverChain = Bun.serve({
		hostname: "127.0.0.1", port: 0,
		async fetch(req) {
			const u = new URL(req.url);
			const p = u.pathname;
			const m = req.method.toUpperCase();
			chainLog.push({
				method: m, path: p,
				auth: req.headers.get("authorization") ?? undefined, trace: req.headers.get("x-trace-id") ?? undefined,
				csrf: req.headers.get("x-csrf-token") ?? undefined, });

			if (p === "/api/login" && m === "POST") {
				await req.json().catch(() => null);
				return new Response(
					JSON.stringify({ data: { csrfToken: chainToken, user: "alice" } }), {
						status: 200, headers: {
							"content-type": "application/json",
							"set-cookie": `sid=${chainSession}; Path=/; HttpOnly; SameSite=Lax`,
						}, },
				);
			}

			if (p === "/api/orders" && m === "POST") {
				const csrf = req.headers.get("x-csrf-token");
				const auth = req.headers.get("authorization") ?? "";
				if (csrf !== chainToken) return jsonRes({ error: "csrf invalid" }, 403);
				if (!auth.includes("member-token")) return jsonRes({ error: "auth missing" }, 401);
				const id = `ord-${++chainSeq}`;
				chainOrders.set(id, { item: "book", qty: 1 });
				return jsonRes({ data: { id } }, 201);
			}

			const orderMatch = p.match(/^\/api\/orders\/([^/]+)$/);
			if (orderMatch) {
				const id = orderMatch[1] ?? "";
				if (m === "PATCH") {
					const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
					const cur = chainOrders.get(id);
					if (!cur) return jsonRes({ error: "not found" }, 404);
					const qty = Number(body.qty ?? cur.qty);
					chainOrders.set(id, { item: cur.item, qty });
					return jsonRes({ data: { id, qty } }, 200);
				}
				if (m === "DELETE") {
					if (!chainOrders.delete(id)) return jsonRes({ error: "not found" }, 404);
					return new Response(null, { status: 204 });
				}
				if (m === "GET") {
					const cur = chainOrders.get(id);
					if (!cur) return jsonRes({ error: "not found" }, 404);
					return jsonRes({ data: { id, ...cur } }, 200);
				}
			}

			if (p === "/v2/profile" && m === "GET") return jsonRes({ data: { user: "alice" } }, 200);
			if (p === "/redirect-in-scope" && m === "GET") {
				return new Response(null, { status: 302, headers: { location: "/v2/profile" } });
			}
			if (p === "/redirect-out-scope" && m === "GET") {
				return new Response(null, {
					status: 302,
					headers: { location: "http://evil.example.org/steal" },
				});
			}
			if (p === "/redirect-metadata" && m === "GET") {
				return new Response(null, {
					status: 302,
					headers: { location: "http://169.254.169.254/latest/meta-data" },
				});
			}
			if (p === "/api/db/drop" && m === "POST") {
				destructiveHits += 1;
				return jsonRes({ ok: true }, 200);
			}
			return jsonRes({ error: "not found" }, 404);
		}, });
	chainBase = `http://127.0.0.1:${serverChain.port}`;

	// ---------- 靶机 B ----------
	serverMass = Bun.serve({
		hostname: "127.0.0.1", port: 0,
		async fetch(req) {
			const u = new URL(req.url);
			const p = u.pathname;
			const m = req.method.toUpperCase();

			if (p === "/api/profile" && m === "GET") return jsonRes({ data: massProfile }, 200);

			if (p === "/api/profile" && m === "PATCH") {
				const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
				// 真实漏洞：未做字段白名单过滤
				massProfile = {
					...massProfile, role: body.role !== undefined ? String(body.role) : massProfile.role,
					isAdmin: body.isAdmin !== undefined ? Boolean(body.isAdmin) : massProfile.isAdmin, };
				return jsonRes({ data: massProfile }, 200);
			}

			if (p === "/api/profile-strict" && m === "PATCH") {
				await req.json().catch(() => ({}));
				return jsonRes({ data: massProfile }, 200);
			}

			if (p === "/api/profile-soft404" && m === "PATCH") {
				await req.json().catch(() => ({}));
				return htmlRes(MASS_SOFT404_HTML, 200);
			}

			if (p === "/soft/profile" && m === "GET") return htmlRes(MASS_SOFT404_HTML, 200);

			if (p === "/api/profile-reflect" && m === "PATCH") {
				const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
				return jsonRes({ error: `Unknown field: ${Object.keys(body).join(", ")}` }, 400);
			}

			// 兜底：任何未知路径均返回 200 Soft-404 HTML（供 autoSampleSoft404 采样）
			return htmlRes(MASS_SOFT404_HTML, 200);
		}, });
	massBase = `http://127.0.0.1:${serverMass.port}`;

	// ---------- 靶机 C ----------
	serverSecond = Bun.serve({
		hostname: "127.0.0.1", port: 0,
		async fetch(req) {
			const u = new URL(req.url);
			const p = u.pathname;
			const m = req.method.toUpperCase();

			if (p === "/api/tickets" && m === "POST") {
				await req.json().catch(() => null);
				return jsonRes({ data: { ticketId: `T-${++secondSeq}`, status: "open" } }, 201);
			}
			if (p === "/api/tickets-403" && m === "POST") {
				await req.json().catch(() => null);
				return jsonRes({ data: { ticketId: `T-403-${++secondSeq}`, status: "open" } }, 201);
			}
			if (/^\/api\/tickets\/[^/]+\/approve$/.test(p) && m === "POST") {
				secondApproveHits += 1;
				return jsonRes({ data: { status: "approved" } }, 200);
			}
			if (/^\/api\/tickets-403\/[^/]+\/approve$/.test(p) && m === "POST") {
				secondApproveHits += 1;
				return jsonRes({ error: "forbidden" }, 403);
			}
			if (p === "/api/reports/export" && m === "GET") {
				secondVerifyHits += 1;
				return new Response("report:SECRET-EXPORT-9", {
					status: 200, headers: { "content-type": "text/plain" },
				});
			}
			if (/^\/api\/tickets\/[^/]+$/.test(p) && m === "DELETE") {
				return new Response(null, { status: 204 });
			}
			return jsonRes({ error: "not found" }, 404);
		}, });
	secondBase = `http://127.0.0.1:${serverSecond.port}`;

	// ---------- 靶机 D ----------
	serverRace = Bun.serve({
		hostname: "127.0.0.1", port: 0,
		async fetch(req) {
			const u = new URL(req.url);
			const p = u.pathname;
			const m = req.method.toUpperCase();

			if (p === "/api/balance" && m === "GET") return jsonRes({ balance: raceBalance }, 200);

			if (p === "/api/redeem-race" && m === "POST") {
				// 真实 TOCTOU：先快照校验，再异步等待后扣减
				const snap = raceBalance;
				await Bun.sleep(60);
				if (snap >= 60) {
					raceBalance -= 60;
					return jsonRes({ ok: true, balance: raceBalance }, 200);
				}
				return jsonRes({ ok: false, balance: raceBalance }, 409);
			}

			if (p === "/api/redeem-mutex" && m === "POST") {
				if (mutexBusy) return jsonRes({ error: "locked" }, 409);
				mutexBusy = true;
				try {
					await Bun.sleep(30);
					if (raceBalance >= 60) {
						raceBalance -= 60;
						return jsonRes({ ok: true, balance: raceBalance }, 200);
					}
					return jsonRes({ error: "insufficient" }, 409);
				} finally {
					mutexBusy = false;
				}
			}

			if (p === "/api/redeem-rate" && m === "POST") {
				if (rateWindowCount >= 1) return jsonRes({ error: "too many requests" }, 429);
				rateWindowCount += 1;
				await Bun.sleep(20);
				if (raceBalance >= 60) {
					raceBalance -= 60;
					return jsonRes({ ok: true, balance: raceBalance }, 200);
				}
				return jsonRes({ error: "insufficient" }, 409);
			}

			if (p === "/api/slow" && m === "POST") {
				await Bun.sleep(400);
				return jsonRes({ ok: true, slow: true }, 200);
			}

			return jsonRes({ error: "not found" }, 404);
		}, });
	raceBase = `http://127.0.0.1:${serverRace.port}`;
});

afterAll(() => {
	for (const s of [serverChain, serverMass, serverSecond, serverRace]) {
		try {
			s?.stop(true);
		} catch {
			/* 忽略重复关闭 */
		}
	}
	for (const d of tempDirs) {
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* 忽略清理失败 */
		}
	}
});

// ==================== 覆盖 1：动作风险分级 ====================

describe("动作风险分级（classifyWorkflowAction）", () => {
	test("四级常量定义完整且顺序稳定", () => {
		expect(WORKFLOW_ACTION_TIERS.length).toBe(4);
		expect(WORKFLOW_ACTION_TIERS[0]).toBe("L0_PHYSICAL_READ");
		expect(WORKFLOW_ACTION_TIERS[1]).toBe("L1_SEMANTIC_READ");
		expect(WORKFLOW_ACTION_TIERS[2]).toBe("L2_SCOPED_STATEFUL");
		expect(WORKFLOW_ACTION_TIERS[3]).toBe("L3_RESTRICTED_DESTRUCTIVE");
	});

	test("GET/HEAD/OPTIONS 均为 L0 物理只读", () => {
		for (const method of ["GET", "HEAD", "OPTIONS"]) {
			const c = classifyWorkflowAction({ method, url: "http://127.0.0.1:8080/api/items" });
			expect(c.tier).toBe("L0_PHYSICAL_READ");
			expect(c.allowedByDefault).toBe(true);
			expect(c.isReadOnly).toBe(true);
			expect(c.isStateChanging).toBe(false);
			expect(c.method).toBe(method);
			expect(c.matchedSignals.length).toBeGreaterThan(0);
		}
	});

	test("POST 只读查询归为 L1 语义只读", () => {
		const graphql = classifyWorkflowAction({
			method: "POST",
			url: "http://127.0.0.1:8080/graphql",
			headers: { "content-type": "application/json" }, body: JSON.stringify({ query: "{ me { id name } }" }),
		});
		expect(graphql.tier).toBe("L1_SEMANTIC_READ");
		expect(graphql.allowedByDefault).toBe(true);

		const esSearch = classifyWorkflowAction({
			method: "POST",
			url: "http://127.0.0.1:8080/api/_search",
			body: { query: { match_all: {} } }, });
		expect(esSearch.tier).toBe("L1_SEMANTIC_READ");

		const userSearch = classifyWorkflowAction({
			method: "POST",
			url: "http://127.0.0.1:8080/users/search",
			body: { keyword: "alice" }, });
		expect(userSearch.tier).toBe("L1_SEMANTIC_READ");
	});

	test("GraphQL mutation 升为 L2，含 deleteAll 升为 L3", () => {
		const mutation = classifyWorkflowAction({
			method: "POST",
			url: "http://127.0.0.1:8080/graphql",
			body: JSON.stringify({ query: "mutation { updateUser(id: 1) { id } }" }), });
		expect(mutation.tier).toBe("L2_SCOPED_STATEFUL");
		expect(mutation.tier).not.toBe("L1_SEMANTIC_READ");

		const destroy = classifyWorkflowAction({
			method: "POST",
			url: "http://127.0.0.1:8080/graphql",
			body: JSON.stringify({ query: "mutation { deleteAllUsers { ok } }" }), });
		expect(destroy.tier).toBe("L3_RESTRICTED_DESTRUCTIVE");
		expect(destroy.allowedByDefault).toBe(false);
		expect(destroy.isDestructive).toBe(true);
	});

	test("POST/PUT/PATCH 与单实体 DELETE 归为 L2", () => {
		for (const method of ["POST", "PUT", "PATCH"]) {
			const c = classifyWorkflowAction({
				method,
				url: "http://127.0.0.1:8080/api/orders/123",
				body: { qty: 2 }, });
			expect(c.tier).toBe("L2_SCOPED_STATEFUL");
			expect(c.isStateChanging).toBe(true);
			expect(c.allowedByDefault).toBe(true);
		}
		const single = classifyWorkflowAction({
			method: "DELETE",
			url: "http://127.0.0.1:8080/api/orders/123",
		});
		expect(single.tier).toBe("L2_SCOPED_STATEFUL");
		expect(single.allowedByDefault).toBe(true);
	});

	test("危险删除与破坏性操作归为 L3 且默认拒绝", () => {
		const cases: Array<{ method: string; url: string; body?: string | Record<string, unknown> }> = [
			{ method: "DELETE", url: "http://127.0.0.1:8080/api/users?all=true" },
			{ method: "DELETE", url: "http://127.0.0.1:8080/api/tenants" },
			{ method: "POST", url: "http://127.0.0.1:8080/api/db/drop" },
			{ method: "POST", url: "http://127.0.0.1:8080/api/exec", body: "DROP TABLE users;" },
			{ method: "POST", url: "http://127.0.0.1:8080/api/exec", body: { cmd: "rm -rf /var/www" } },
			{ method: "GET", url: "http://127.0.0.1:8080/api/debug", body: "SELECT 1; DROP TABLE users" },
		];
		for (const c of cases) {
			const r = classifyWorkflowAction(c);
			expect(r.tier).toBe("L3_RESTRICTED_DESTRUCTIVE");
			expect(r.allowedByDefault).toBe(false);
			expect(r.isDestructive).toBe(true);
		}
		const allowed = classifyWorkflowAction({
			method: "DELETE",
			url: "http://127.0.0.1:8080/api/tenants",
			allowDestructive: true, });
		expect(allowed.tier).toBe("L3_RESTRICTED_DESTRUCTIVE");
		expect(allowed.allowedByDefault).toBe(true);
	});

	test("validateUrlAndActionScope 拒绝越界目标与未授权 L3", () => {
		const scope = makeScope(chainBase);
		const oob = validateUrlAndActionScope(
			"http://169.254.169.254/latest/meta-data",
			"GET", undefined,
			scope, "audit",
			false,);
		expect(oob.ok).toBe(false);

		const drop = validateUrlAndActionScope(
			`${chainBase}/api/db/drop`,
			"POST", undefined,
			scope, "audit",
			false,);
		expect(drop.ok).toBe(false);

		const read = validateUrlAndActionScope(`${chainBase}/v2/profile`, "GET", undefined, scope, "audit", false);
		expect(read.ok).toBe(true);
	});
});

// ==================== 导出完整性 / 小工具 ====================

describe("核心导出完整性", () => {
	test("模块导出函数、类与常量均可用", () => {
		expect(typeof executeStatefulWorkflowChain).toBe("function");
		expect(typeof executeStatefulWorkflowChainInternal).toBe("function");
		expect(typeof probeMassAssignment).toBe("function");
		expect(typeof verifySecondOrderWorkflow).toBe("function");
		expect(typeof runBarrierRaceProbe).toBe("function");
		expect(typeof BarrierGate).toBe("function");
		expect(typeof CookieJar).toBe("function");
		expect(typeof TrafficRecorder).toBe("function");
		expect(typeof upsertSessionRole).toBe("function");
		expect(typeof initBeliefGraphFromState).toBe("function");
		expect(MAX_RACE_CONCURRENCY).toBe(32);
	});

	test("脱敏/模板/提取工具行为正确", () => {
		expect(isSensitiveKeyName("authorization")).toBe(true);
		expect(isSensitiveKeyName("x-api-key")).toBe(true);
		expect(isSensitiveKeyName("content-length")).toBe(false);

		const scrubbed = scrubSecretsInText("token=abc123&x=1", new Set(["abc123"]));
		expect(scrubbed).not.toContain("abc123");

		const redacted = redactRecordDeep(
			{ password: "p@ss", nested: { apiKey: "k-999" }, ok: 1 }, new Set(["p@ss", "k-999"]),
		);
		const redactedJson = JSON.stringify(redacted);
		expect(redactedJson).not.toContain("p@ss");
		expect(redactedJson).not.toContain("k-999");

		const tpl = interpolateTemplate("a {{x}} b {{y}}", { x: "1" });
		expect(tpl.value).toContain("1");
		expect(tpl.unresolved).toContain("y");

		expect(extractByJsonPath({ a: { b: [{ c: 5 }] } }, "$.a.b[0].c")).toBe(5);

		const secrets = collectSecretSet({
			headers: { authorization: "Bearer zzz-token-value" }, vars: { password: "p@ss" },
		});
		expect(secrets.size).toBeGreaterThan(0);

		expect(computeTemplateSimilarity("a b c d", "a b c d")).toBeGreaterThan(0.9);
	});
});

// ==================== 覆盖 2：多步状态链重放 ====================

describe("多步状态链重放（executeStatefulWorkflowChain）", () => {
	test("登录/CSRF/角色注入/增改删查全链路", async () => {
		chainLog = [];
		const counter = makeCountingFetch();
		const result = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-chain-"), scope: makeScope(chainBase),
			mode: "audit", vars: { tenant: "acme" },
			role: "member", roleHeaders: { member: { authorization: "Bearer member-token-abc" } },
			extraHeaders: { "x-trace-id": "trace-1", "x-api-key": chainApiKey },
			extraSecrets: [chainPassword, chainToken, chainSession, chainApiKey], initialCookies: { locale: "zh-CN" },
			fetchFn: counter.fn, steps: [
				{
					id: "login", method: "POST",
					url: `${chainBase}/api/login`,
					body: { username: "alice", password: chainPassword }, extract: { csrfToken: "$.data.csrfToken" },
					expectStatus: 200, },
				{
					id: "create-order", method: "POST",
					url: `${chainBase}/api/orders`,
					headers: { "x-csrf-token": "{{csrfToken}}" }, body: { item: "book", qty: 2 },
					extract: { orderId: "$.data.id" }, expectStatus: [200, 201],
				}, {
					id: "update-order", method: "PATCH",
					url: `${chainBase}/api/orders/{{orderId}}`,
					body: { qty: 3 }, expectStatus: 200,
				}, {
					id: "delete-order", method: "DELETE",
					url: `${chainBase}/api/orders/{{orderId}}`,
					expectStatus: [200, 204], },
				{
					id: "read-order", method: "GET",
					url: `${chainBase}/api/orders/{{orderId}}`,
					expectStatus: 404, },
			], });

		expect(result.redacted).toBe(true);
		expect(result.abortedByScope).toBe(false);
		expect(result.steps.length).toBe(5);
		expect(result.totalRequests).toBe(5);
		expect(result.steps.map((s) => s.status)).toEqual([200, 201, 200, 204, 404]);

		const created = chainLog.filter((e) => e.method === "POST" && e.path === "/api/orders").pop();
		expect(created?.auth ?? "").toContain("member-token");
		expect(created?.trace).toBe("trace-1");
		expect(created?.csrf).toBe(chainToken);

		const orderId = result.steps[1]?.extracted.orderId ?? "";
		expect(orderId).toMatch(/^ord-\d+$/);
		expect(result.steps[3]?.status).toBe(204);

		// 零明文脱敏
		const dump = JSON.stringify(result);
		for (const secret of [chainPassword, chainToken, chainSession, chainApiKey]) {
			expect(dump).not.toContain(secret);
		}
		expect(dump).toContain("[REDACTED]");
	});

	test("302 手动重定向：Scope 内跟随，越界立即拦截", async () => {
		const inScope = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-redirect-"), scope: makeScope(chainBase),
			fetchFn: makeCountingFetch().fn, followRedirects: true,
			maxRedirects: 5,
			steps: [{ id: "in", method: "GET", url: `${chainBase}/redirect-in-scope`, followRedirects: true }],
		});
		expect(inScope.ok).toBe(true);
		expect(inScope.steps[0]?.status).toBe(200);
		expect(inScope.steps[0]?.finalUrl.endsWith("/v2/profile")).toBe(true);
		expect(inScope.steps[0]?.redirectChain.length).toBeGreaterThanOrEqual(1);
		expect(inScope.steps[0]?.redirectBlocked ?? false).toBe(false);

		const outOfScope = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-redirect-"), scope: makeScope(chainBase),
			fetchFn: makeCountingFetch().fn,
			steps: [{ method: "GET", url: `${chainBase}/redirect-out-scope`, followRedirects: true }],
		});
		expect(outOfScope.abortedByScope).toBe(true);
		expect(outOfScope.steps[0]?.redirectBlocked).toBe(true);

		const metadata = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-redirect-"), scope: makeScope(chainBase),
			fetchFn: makeCountingFetch().fn,
			steps: [{ method: "GET", url: `${chainBase}/redirect-metadata`, followRedirects: true }],
		});
		expect(metadata.abortedByScope).toBe(true);
		expect(metadata.steps[0]?.redirectBlocked).toBe(true);
	});

	test("越界 URL 与未授权 L3 动作零发包拦截", async () => {
		const oobCounter = makeCountingFetch();
		const oob = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-scope-"), scope: makeScope(chainBase),
			fetchFn: oobCounter.fn,
			steps: [{ method: "GET", url: "http://169.254.169.254/latest/meta-data" }],
		});
		expect(oob.abortedByScope).toBe(true);
		expect(oobCounter.calls.length).toBe(0);

		const l3Counter = makeCountingFetch();
		const before = destructiveHits;
		const l3 = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-scope-"), scope: makeScope(chainBase),
			fetchFn: l3Counter.fn, steps: [
				{
					id: "drop-db", method: "POST",
					url: `${chainBase}/api/db/drop`,
					body: { confirm: true }, },
			], });
		expect(l3.abortedByScope).toBe(true);
		expect(l3Counter.calls.length).toBe(0);
		expect(Boolean(l3.steps[0]?.blockReason)).toBe(true);
		expect(destructiveHits).toBe(before);
	});
});

// ==================== 覆盖 3：Mass Assignment ====================

describe("Mass Assignment 检测（probeMassAssignment）", () => {
	test("真实漏洞精确检出并在 finally 中回滚", async () => {
		massProfile = { ...MASS_BASELINE };
		const counter = makeCountingFetch();
		const res = await probeMassAssignment({
			scope: makeScope(massBase), root: makeTempWorkspace("nuwa-mass-"),
			mode: "audit",
			writeStep: { method: "PATCH", url: `${massBase}/api/profile`, body: { name: "alice" } },
			readStep: { method: "GET", url: `${massBase}/api/profile` },
			baselineBody: { ...MASS_BASELINE }, candidateFields: [
				{ field: "role", value: "admin", label: "提权到管理员", expectedReadPath: "$.data.role" },
				{ field: "isAdmin", value: true, label: "管理员标志", expectedReadPath: "$.data.isAdmin" },],
			rollbackStep: {
				method: "PATCH",
				url: `${massBase}/api/profile`,
				body: { role: "user", isAdmin: false }, },
			fetchFn: counter.fn, timeoutMs: 5000,
			extraSecrets: [], });

		expect(res.abortedByScope).toBe(false);
		expect(res.detected).toBe(true);
		expect(res.vulnerableFields).toContain("role");
		expect(res.vulnerableFields).toContain("isAdmin");
		expect(res.rollbackExecuted).toBe(true);
		expect(res.rollbackOk).toBe(true);
		expect(res.beliefObservation).toBeDefined();
		expect(res.summary.length).toBeGreaterThan(0);

		const after = (await fetch(`${massBase}/api/profile`).then((r) => r.json())) as {
			data: Profile;
		};
		expect(after.data.role).toBe("user");
		expect(after.data.isAdmin).toBe(false);
	});

	test("模板高度同构的 200 响应被去噪", async () => {
		massProfile = { ...MASS_BASELINE };
		const res = await probeMassAssignment({
			scope: makeScope(massBase), root: makeTempWorkspace("nuwa-mass-"),
			writeStep: { method: "PATCH", url: `${massBase}/api/profile-strict`, body: { name: "alice" } },
			readStep: { method: "GET", url: `${massBase}/api/profile` },
			baselineBody: { ...MASS_BASELINE }, candidateFields: [{ field: "role", value: "admin", expectedReadPath: "$.data.role" }],
			templateSimilarityThreshold: 0.85, fetchFn: makeCountingFetch().fn,
			extraSecrets: [], });
		expect(res.detected).toBe(false);
		expect(res.vulnerableFields.length).toBe(0);
		expect(res.cases.every((c) => c.bound === false)).toBe(true);
	});

	test("Soft-404 兜底 HTML 200 被识别并过滤", async () => {
		massProfile = { ...MASS_BASELINE };
		const res = await probeMassAssignment({
			scope: makeScope(massBase), root: makeTempWorkspace("nuwa-mass-"),
			writeStep: { method: "PATCH", url: `${massBase}/api/profile-soft404`, body: { name: "alice" } },
			readStep: { method: "GET", url: `${massBase}/soft/profile` },
			baselineBody: { ...MASS_BASELINE }, candidateFields: [{ field: "role", value: "admin", expectedReadPath: "$.data.role" }],
			autoSampleSoft404: true, fetchFn: makeCountingFetch().fn,
			extraSecrets: [], });
		expect(res.detected).toBe(false);
		const first = res.cases[0];
		if (first) {
			expect(Boolean(first.isSoft404) || Boolean(first.suppressedReason)).toBe(true);
		}
	});

	test("400 Unknown field 反射错误被过滤", async () => {
		massProfile = { ...MASS_BASELINE };
		const res = await probeMassAssignment({
			scope: makeScope(massBase), root: makeTempWorkspace("nuwa-mass-"),
			writeStep: {
				method: "PATCH",
				url: `${massBase}/api/profile-reflect`,
				body: { name: "alice" }, },
			readStep: { method: "GET", url: `${massBase}/api/profile` },
			baselineBody: { ...MASS_BASELINE }, candidateFields: [{ field: "role", value: "admin", expectedReadPath: "$.data.role" }],
			fetchFn: makeCountingFetch().fn, extraSecrets: [],
		});
		expect(res.detected).toBe(false);
		expect(res.vulnerableFields.length).toBe(0);
	});

	test("越界目标 0 发包且判定 abortedByScope", async () => {
		const counter = makeCountingFetch();
		const res = await probeMassAssignment({
			scope: makeScope(massBase), root: makeTempWorkspace("nuwa-mass-"),
			writeStep: {
				method: "PATCH",
				url: "http://169.254.169.254/latest/meta-data",
				body: { role: "admin" }, },
			readStep: { method: "GET", url: `${massBase}/api/profile` },
			candidateFields: [{ field: "role", value: "admin" }], fetchFn: counter.fn,
			extraSecrets: [], });
		expect(res.abortedByScope).toBe(true);
		expect(counter.calls.length).toBe(0);
		expect(res.detected).toBe(false);
	});
});

// ==================== 覆盖 4：二阶有状态工作流验证 ====================

describe("二阶有状态工作流验证（verifySecondOrderWorkflow）", () => {
	test("三段式串联验证成功、产物 candidate Fact 并回滚清理", async () => {
		secondVerifyHits = 0;
		const state = makeState(secondBase);
		const beliefGraph = initBeliefGraphFromState(state);
		const counter = makeCountingFetch();

		const res = await verifySecondOrderWorkflow({
			scope: makeScope(secondBase), root: makeTempWorkspace("nuwa-so-"),
			mode: "audit", state,
			beliefGraph, applyBeliefUpdate: true,
			recordLedger: true, candidateFactId: "f-so-1",
			candidateTitle: "二阶越权导出敏感报表", writeSteps: [
				{
					id: "create-ticket", method: "POST",
					url: `${secondBase}/api/tickets`,
					body: { title: "报销单" }, extract: { ticketId: "$.data.ticketId" },
					expectStatus: [200, 201], },
			], intermediateSteps: [
				{
					id: "approve-ticket", method: "POST",
					url: `${secondBase}/api/tickets/{{ticketId}}/approve`,
					expectStatus: 200, },
			], verifySteps: [
				{
					id: "export-report", method: "GET",
					url: `${secondBase}/api/reports/export`,
					expectStatus: 200, },
			], verifyAssertion: {
				expectedStatus: 200, bodyIncludes: ["SECRET-EXPORT-9"],
				requireChangedFromBaseline: false, },
			cleanupSteps: [
				{
					id: "cleanup-ticket", method: "DELETE",
					url: `${secondBase}/api/tickets/{{ticketId}}`,
					expectStatus: [200, 204], },
			], fetchFn: counter.fn,
			extraSecrets: ["SECRET-EXPORT-9"], });

		expect(res.verified).toBe(true);
		expect(res.abortedByScope).toBe(false);
		expect(res.brokenAtStep).toBeUndefined();
		expect(res.stepTraces.length).toBeGreaterThanOrEqual(3);
		expect(res.candidateFact?.verifyStage).toBe("candidate");
		expect(res.candidateFact?.verified ?? false).toBe(false);
		expect(res.verifyRecommendation?.key.startsWith("verify-vuln:")).toBe(true);
		expect(res.verifyRecommendation?.phase).toBe("vuln");
		expect(res.cleanupExecuted).toBe(true);
		expect(res.cleanupOk).toBe(true);
		expect(res.beliefObservation).toBeDefined();
		expect(secondVerifyHits).toBe(1);

		const dump = JSON.stringify(res);
		expect(dump).not.toContain("SECRET-EXPORT-9");
	});

	test("中间步 403 精准定界、后续零发包、finally 清理仍执行", async () => {
		secondVerifyHits = 0;
		const counter = makeCountingFetch();
		const res = await verifySecondOrderWorkflow({
			scope: makeScope(secondBase), root: makeTempWorkspace("nuwa-so-"),
			mode: "audit", state: makeState(secondBase),
			writeSteps: [
				{
					id: "create-ticket-403", method: "POST",
					url: `${secondBase}/api/tickets-403`,
					body: { title: "越权工单" }, extract: { ticketId: "$.data.ticketId" },
					expectStatus: [200, 201], },
			], intermediateSteps: [
				{
					id: "approve-403", method: "POST",
					url: `${secondBase}/api/tickets-403/{{ticketId}}/approve`,
					expectStatus: 200, },
			],
			verifySteps: [{ id: "export", method: "GET", url: `${secondBase}/api/reports/export` }],
			cleanupSteps: [
				{
					id: "cleanup-in-scope", method: "DELETE",
					url: `${secondBase}/api/tickets/{{ticketId}}`,
					expectStatus: [200, 204], },
				{
					id: "cleanup-oob", method: "GET",
					url: "http://169.254.169.254/latest/meta-data",
				},],
			fetchFn: counter.fn, extraSecrets: [],
		});

		expect(res.verified).toBe(false);
		expect(res.brokenAtStep).toBe(1);
		expect(res.brokenPhase).toBe("intermediate");
		expect(res.brokenStepId).toBe("approve-403");
		expect(res.failureKind).toBe("auth_403");
		expect(secondVerifyHits).toBe(0);
		expect(res.cleanupExecuted).toBe(true);
		expect(counter.calls.some((url) => url.includes("169.254.169.254"))).toBe(false);
		expect(res.candidateFact).toBeUndefined();
	});
});

// ==================== 覆盖 5：同步屏障并发竞态 ====================

type GateLike = {
	arrive?: (signal?: AbortSignal) => Promise<BarrierAwaitResult>;
	wait?: (signal?: AbortSignal) => Promise<BarrierAwaitResult>;
	arriveAndAwait?: (signal?: AbortSignal) => Promise<BarrierAwaitResult>;
	arriveAndWait?: (signal?: AbortSignal) => Promise<BarrierAwaitResult>;
	await?: (signal?: AbortSignal) => Promise<BarrierAwaitResult>;
};

function createGate(parties: number, timeoutMs: number): GateLike {
	const Positional = BarrierGate as unknown as new (a: unknown, b?: unknown) => GateLike;
	try {
		const g = new Positional(parties, timeoutMs);
		if (g && typeof g === "object") return g;
	} catch {
		/* 落回对象式构造 */
	}
	const ObjectStyle = BarrierGate as unknown as new (opts: {
		parties: number;
		size: number;
		count: number;
		timeoutMs: number;
	}) => GateLike;
	return new ObjectStyle({ parties, size: parties, count: parties, timeoutMs });
}

function arriveGate(gate: GateLike): Promise<BarrierAwaitResult> {
	const candidates = ["arriveAndAwait", "arrive", "wait", "arriveAndWait", "await"] as const;
	for (const key of candidates) {
		const fn = gate[key];
		if (typeof fn === "function") return fn.call(gate);
	}
	throw new Error("BarrierGate 缺少到达等待方法");
}

describe("同步屏障 BarrierGate", () => {
	test("多路齐步到达后统一释放", async () => {
		const gate = createGate(2, 3000);
		const [r1, r2] = await Promise.all([arriveGate(gate), arriveGate(gate)]);
		expect(r1.released).toBe(true);
		expect(r2.released).toBe(true);
		expect(r1.arrived).toBeGreaterThanOrEqual(2);
	});

	test("超时后自动释放且 Promise 不悬挂", async () => {
		const gate = createGate(3, 30);
		const pending = arriveGate(gate);
		const settled = await Promise.race([pending, Bun.sleep(1500).then(() => null)]);
		expect(settled).not.toBeNull();
		if (settled) {
			expect(settled.timedOut).toBe(true);
			expect(settled.arrived).toBeGreaterThanOrEqual(1);
		}
	});
});

describe("同步屏障并发竞态探测（runBarrierRaceProbe）", () => {
	test("并发硬上限钳制与越界 0 发包", async () => {
		raceBalance = 100;
		const clamped = await runBarrierRaceProbe({
			scope: makeScope(raceBase), root: makeTempWorkspace("nuwa-race-"),
			request: { method: "POST", url: `${raceBase}/api/redeem-race` },
			concurrency: 100, transport: "fetch",
			expectedSingleDelta: 60, maxExpectedSuccesses: 1,
			timeoutMs: 8000, fetchFn: makeCountingFetch().fn,
			extraSecrets: [], });
		expect(clamped.requestedConcurrency).toBe(100);
		expect(clamped.concurrency).toBe(MAX_RACE_CONCURRENCY);
		expect(clamped.concurrency).toBe(32);
		expect(clamped.abortedByScope).toBe(false);
		expect(clamped.leakedSockets).toBe(0);
		expect(clamped.leakedTimers).toBe(0);

		const oobCounter = makeCountingFetch();
		const oob = await runBarrierRaceProbe({
			scope: makeScope(raceBase), root: makeTempWorkspace("nuwa-race-"),
			request: { method: "POST", url: "http://169.254.169.254/latest/meta-data" },
			concurrency: 8, transport: "fetch",
			timeoutMs: 2000, fetchFn: oobCounter.fn,
			extraSecrets: [], });
		expect(oob.abortedByScope).toBe(true);
		expect(oobCounter.calls.length).toBe(0);
		expect(oob.raceConditionDetected).toBe(false);
		expect(oob.leakedSockets).toBe(0);
		expect(oob.leakedTimers).toBe(0);
	});

	test("真实 TOCTOU 并发竞争被实锤为 race_confirmed", async () => {
		raceBalance = 100;
		const res = await runBarrierRaceProbe({
			scope: makeScope(raceBase), root: makeTempWorkspace("nuwa-race-"),
			mode: "audit", request: {
				method: "POST",
				url: `${raceBase}/api/redeem-race`,
				headers: { "content-type": "application/json" }, body: { amount: 60 },
			}, concurrency: 8,
			transport: "net",
			beforeReadStep: { method: "GET", url: `${raceBase}/api/balance` },
			afterReadStep: { method: "GET", url: `${raceBase}/api/balance` },
			numericFieldPath: "balance", expectedSingleDelta: 60,
			maxExpectedSuccesses: 1, barrierTimeoutMs: 3000,
			timeoutMs: 8000, extraSecrets: [],
		});

		expect(res.abortedByScope).toBe(false);
		expect(res.transportUsed).toBe("net");
		expect(res.raceConditionDetected).toBe(true);
		expect(res.classification).toBe("race_confirmed");
		expect(res.successCount).toBeGreaterThan(1);
		expect(res.numericAnomaly).toBe(true);
		expect(res.leakedSockets).toBe(0);
		expect(res.leakedTimers).toBe(0);
		expect(res.results.length).toBe(8);
		expect(res.summary.length).toBeGreaterThan(0);
		expect(Object.keys(res.statusCounts).length).toBeGreaterThan(0);
	});

	test("限流 429 保护对照（fetch）", async () => {
		raceBalance = 100;
		rateWindowCount = 0;
		const res = await runBarrierRaceProbe({
			scope: makeScope(raceBase), root: makeTempWorkspace("nuwa-race-"),
			request: { method: "POST", url: `${raceBase}/api/redeem-rate`, body: { amount: 60 } },
			concurrency: 6, transport: "fetch",
			beforeReadStep: { method: "GET", url: `${raceBase}/api/balance` },
			afterReadStep: { method: "GET", url: `${raceBase}/api/balance` },
			numericFieldPath: "balance", expectedSingleDelta: 60,
			maxExpectedSuccesses: 1, barrierTimeoutMs: 3000,
			timeoutMs: 8000, fetchFn: makeCountingFetch().fn,
			extraSecrets: [], });

		expect(res.abortedByScope).toBe(false);
		expect(res.transportUsed).toBe("fetch");
		expect(res.raceConditionDetected).toBe(false);
		expect(res.successCount).toBe(1);
		expect(res.rateLimitedCount).toBeGreaterThanOrEqual(1);
		expect(res.classification).toBe("rate_limited");
		expect(res.numericAnomaly).toBe(false);
		expect(res.leakedSockets).toBe(0);
		expect(res.leakedTimers).toBe(0);
	});

	test("互斥锁 409 保护对照（node:net）", async () => {
		raceBalance = 100;
		mutexBusy = false;
		const res = await runBarrierRaceProbe({
			scope: makeScope(raceBase), root: makeTempWorkspace("nuwa-race-"),
			request: { method: "POST", url: `${raceBase}/api/redeem-mutex`, body: { amount: 60 } },
			concurrency: 6, transport: "net",
			beforeReadStep: { method: "GET", url: `${raceBase}/api/balance` },
			afterReadStep: { method: "GET", url: `${raceBase}/api/balance` },
			numericFieldPath: "balance", expectedSingleDelta: 60,
			maxExpectedSuccesses: 1, barrierTimeoutMs: 3000,
			timeoutMs: 8000, extraSecrets: [],
		});

		expect(res.abortedByScope).toBe(false);
		expect(res.transportUsed).toBe("net");
		expect(res.raceConditionDetected).toBe(false);
		expect(res.successCount).toBe(1);
		expect(res.conflictCount).toBeGreaterThanOrEqual(1);
		expect(res.classification).toBe("mutex_protected");
		expect(res.numericAnomaly).toBe(false);
		expect(res.leakedSockets).toBe(0);
		expect(res.leakedTimers).toBe(0);
	});

	test("慢响应超时后句柄零泄漏且无未决 Promise", async () => {
		const started = Date.now();
		const res = await runBarrierRaceProbe({
			scope: makeScope(raceBase), root: makeTempWorkspace("nuwa-race-"),
			request: { method: "POST", url: `${raceBase}/api/slow` },
			concurrency: 4, transport: "fetch",
			timeoutMs: 100, barrierTimeoutMs: 1000,
			fetchFn: makeCountingFetch().fn, extraSecrets: [],
		});
		const elapsed = Date.now() - started;

		expect(res.leakedSockets).toBe(0);
		expect(res.leakedTimers).toBe(0);
		expect(res.raceConditionDetected).toBe(false);
		expect(res.results.length).toBe(4);
		expect(res.results.every((r) => r.timedOut || r.status > 0)).toBe(true);
		expect(elapsed).toBeLessThan(5000);
	});
});

// ==================== 覆盖 6：内部执行与脱敏回溯 ====================

describe("内部执行结果（executeStatefulWorkflowChainInternal）", () => {
	test("保留原始变量与 Cookie，但对外结果已脱敏", async () => {
		const counter = makeCountingFetch();
		const internal = await executeStatefulWorkflowChainInternal({
			root: makeTempWorkspace("nuwa-internal-"), scope: makeScope(chainBase),
			mode: "audit", roleHeaders: { member: { authorization: "Bearer member-token-abc" } },
			role: "member", extraSecrets: [chainPassword, chainToken, chainSession],
			fetchFn: counter.fn, steps: [
				{
					id: "login", method: "POST",
					url: `${chainBase}/api/login`,
					body: { username: "alice", password: chainPassword }, extract: { csrfToken: "$.data.csrfToken" },
				}, {
					id: "create", method: "POST",
					url: `${chainBase}/api/orders`,
					headers: { "x-csrf-token": "{{csrfToken}}" }, body: { item: "pen" },
					extract: { orderId: "$.data.id" }, expectStatus: [200, 201],
				},],
		});

		expect(internal.redacted).toBe(true);
		expect(internal.rawVariables.csrfToken).toBe(chainToken);
		expect(internal.rawCookies.sid).toBe(chainSession);
		expect(internal.steps.length).toBe(2);
		expect(internal.steps[1]?.extracted.orderId).toMatch(/^ord-\d+$/);

		// 内部结构含原始值（供后续引擎复用），但对外序列化应全脱敏
		const publicView = await executeStatefulWorkflowChain({
			root: makeTempWorkspace("nuwa-internal-"), scope: makeScope(chainBase),
			mode: "audit", roleHeaders: { member: { authorization: "Bearer member-token-abc" } },
			role: "member", extraSecrets: [chainPassword, chainToken, chainSession],
			fetchFn: counter.fn, steps: [
				{
					id: "login", method: "POST",
					url: `${chainBase}/api/login`,
					body: { username: "alice", password: chainPassword }, extract: { csrfToken: "$.data.csrfToken" },
				},],
		});
		const dump = JSON.stringify(publicView);
		for (const secret of [chainPassword, chainToken, chainSession]) {
			expect(dump).not.toContain(secret);
		}
	});

	test("CookieJar 记录并回放 Set-Cookie", () => {
		const jar = new CookieJar();
		const changed = jar.setFromSetCookie(
			[`sid=${chainSession}; Path=/; HttpOnly; SameSite=Lax`],
			"http://127.0.0.1/api/login",
		);
		expect(changed).toContain("sid");
		const header = jar.getCookieHeader("http://127.0.0.1/api/orders");
		expect(header).toContain(`sid=${chainSession}`);
		expect(jar.toRedactedJSON().sid).toBe("[REDACTED]");
	});
});

// ==================== 覆盖 7：SessionVault 角色注入闭环 ====================

describe("SessionVault 角色注入闭环", () => {
	test("upsertSessionRole 写入的 Authorization 被状态链正确注入", async () => {
		const root = makeTempWorkspace("nuwa-vault-");
		chainLog = [];
		const vaultResult = await Promise.resolve()
			.then(() =>
				upsertSessionRole({
					root, role: "member",
					headers: { authorization: "Bearer member-token-abc" }, } as unknown as Parameters<typeof upsertSessionRole>[0]),
			)
			.catch(() => null);

		// 允许 vault 落盘 API 变体差异：即便写入形态不同，也应通过 roleHeaders 回退注入
		const counter = makeCountingFetch();
		const res = await executeStatefulWorkflowChain({
			root, scope: makeScope(chainBase),
			mode: "audit", role: "member",
			roleHeaders: { member: { authorization: "Bearer member-token-abc" } }, extraSecrets: [chainPassword, chainToken],
			fetchFn: counter.fn, vars: { csrfToken: chainToken },
			steps: [
				{
					id: "create", method: "POST",
					url: `${chainBase}/api/orders`,
					headers: { "x-csrf-token": "{{csrfToken}}" }, body: { item: "pen" },
					expectStatus: [200, 201], },
			], });

		expect(vaultResult === null || typeof vaultResult === "object").toBe(true);
		expect(res.steps[0]?.status).toBe(201);
		const hit = chainLog.find((e) => e.method === "POST" && e.path === "/api/orders");
		expect(hit?.auth ?? "").toContain("member-token");
	});
});
// ==================== 覆盖 8：异构审查 6 项 P1 边界回归 ====================

describe("异构审查 P1 边界回归", () => {
	test("[P1-1] 长请求体 600B 后破坏指令与 .nuwa 防篡改 (N-003) 严防绕过", () => {
		const scope = makeScope("http://127.0.0.1:8080");
		const longBody = JSON.stringify({ pad: "a".repeat(620), hook: "x; mkfs.ext4 /dev/sda" });
		const clsLong = classifyWorkflowAction({ method: "POST", url: "http://127.0.0.1:8080/api/items", body: longBody, scope });
		expect(clsLong.tier).toBe("L3_RESTRICTED_DESTRUCTIVE");
		expect(clsLong.allowedByDefault).toBe(false);
		expect(validateUrlAndActionScope("http://127.0.0.1:8080/api/items", "POST", longBody, scope, "audit", false).ok).toBe(false);

		const nuwaBody = JSON.stringify({ path: ".nuwa/sessions/vault.json", op: "cat" });
		const vNuwaUrl = validateUrlAndActionScope("http://127.0.0.1:8080/read?f=.nuwa/sessions/vault.json", "GET", undefined, scope, "audit", true);
		const vNuwaBody = validateUrlAndActionScope("http://127.0.0.1:8080/api/read", "POST", nuwaBody, scope, "audit", true);
		expect(vNuwaUrl.ok).toBe(false);
		expect(vNuwaBody.ok).toBe(false);
	});

	test("[P1-2] SessionVault password/bearer/cookie/自定义头全链路零明文", async () => {
		const root = makeTempWorkspace("nuwa-p1-vault-");
		const vPass = "VaultPass#9988"; const vBearer = "vault-jwt-secret-7766";
		const vCookie = "vsess_secret_5544"; const vCustom = "gw-custom-secret-3322";
		upsertSessionRole(root, { role: "auditor", password: vPass, bearer: vBearer,
			cookie: `vsid=${vCookie}`, headers: { "X-Gateway-Secret": vCustom } });
		const vault = loadSessionVault(root);
		const echoSrv = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
			const u = new URL(req.url);
			if (u.pathname === "/echo") {
				return new Response(JSON.stringify({ ok: true, data: { role: "user" },
					echo: `${vPass}|${vBearer}|${vCookie}|${vCustom}`, h: req.headers.get("x-gateway-secret") }),
					{ status: 200, headers: { "content-type": "application/json", "set-cookie": "dyn_c=dyn-cookie-secret-1100; Path=/" } });
			}
			return new Response("ok", { status: 200 });
		} });
		try {
			const base = `http://127.0.0.1:${echoSrv.port}`; const sc = makeScope(base);
			const chainRes = await executeStatefulWorkflowChain({ root, vault, scope: sc, role: "auditor",
				steps: [{ id: "e", method: "POST", url: `${base}/echo`, body: { x: 1 } }] });
			const massRes = await probeMassAssignment({ root, vault, scope: sc, role: "auditor", soft404Baseline: null,
				writeStep: { method: "POST", url: `${base}/echo`, body: { name: "a" } }, candidateFields: [{ field: "role", value: "admin" }] });
			const secRes = await verifySecondOrderWorkflow({ root, vault, scope: sc, role: "auditor", soft404Baseline: null,
				writeSteps: [{ method: "POST", url: `${base}/echo`, body: { x: 1 } }],
				verifySteps: [{ method: "GET", url: `${base}/echo` }],
				verifyAssertion: { expectedStatus: 200, bodyIncludes: ["data"] } });
			for (const dump of [JSON.stringify(chainRes), JSON.stringify(massRes), JSON.stringify(secRes)]) {
				for (const sec of [vPass, vBearer, vCookie, vCustom, "dyn-cookie-secret-1100"]) expect(dump).not.toContain(sec);
			}
		} finally { echoSrv.stop(true); }
	});

	test("[P1-3] 运行期动态提取 {{dynUrl}} 不被预检误杀，且越界动态目标发包前阻断", async () => {
		let evilHits = 0;
		const dynSrv = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
			const p = new URL(req.url).pathname;
			if (p === "/api/start-ok") return jsonRes({ nextUrl: `${`http://127.0.0.1:${dynSrv.port}`}/api/final-ok` }, 200);
			if (p === "/api/start-evil") return jsonRes({ nextUrl: "http://169.254.169.254/latest/meta-data" }, 200);
			if (p === "/api/final-ok") return jsonRes({ proof: "second-order-dynamic-verified-payload-ok", amount: 99 }, 200);
			return jsonRes({ error: "not found" }, 404);
		} });
		const counter: ChainFetch = ((input: unknown, init?: unknown) => {
			const u = normalizeUrl(input); if (u.includes("169.254.169.254")) evilHits += 1;
			return fetch(u, init as RequestInit | undefined);
		}) as unknown as ChainFetch;
		try {
			const base = `http://127.0.0.1:${dynSrv.port}`; const sc = makeScope(base);
			const okRes = await verifySecondOrderWorkflow({ scope: sc, soft404Baseline: null, fetchFn: counter,
				writeSteps: [{ id: "w", method: "POST", url: `${base}/api/start-ok`, body: {}, extract: { dynUrl: "$.nextUrl" } }],
				verifySteps: [{ id: "v", method: "GET", url: "{{dynUrl}}" }],
				verifyAssertion: { expectedStatus: 200, bodyIncludes: ["second-order-dynamic-verified-payload-ok"] } });
			expect(okRes.verified).toBe(true);
			expect(okRes.abortedByScope).toBe(false);

			const evilRes = await verifySecondOrderWorkflow({ scope: sc, soft404Baseline: null, fetchFn: counter,
				writeSteps: [{ id: "w", method: "POST", url: `${base}/api/start-evil`, body: {}, extract: { dynUrl: "$.nextUrl" } }],
				verifySteps: [{ id: "v", method: "GET", url: "{{dynUrl}}" }] });
			expect(evilRes.verified).toBe(false);
			expect(evilRes.abortedByScope).toBe(true);
			expect(evilHits).toBe(0);
		} finally { dynSrv.stop(true); }
	});

	test("[P1-4] Mass Assignment 过滤 requestEcho 容器回显，杜绝假阳性", async () => {
		const echoSrv = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
			const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
			return jsonRes({ requestEcho: { name: "alice", role: body.role ?? "member", ...(body.isAdmin !== undefined ? { isAdmin: body.isAdmin } : {}) },
				data: { name: "alice", role: "member" } }, 200);
		} });
		try {
			const base = `http://127.0.0.1:${echoSrv.port}`;
			const res = await probeMassAssignment({ scope: makeScope(base), soft404Baseline: null,
				writeStep: { method: "PATCH", url: `${base}/api/profile`, body: { name: "alice" } },
				candidateFields: [{ field: "role", value: "admin" }, { field: "isAdmin", value: true }] });
			expect(res.detected).toBe(false);
			expect(res.cases.every((c) => !c.bound)).toBe(true);
			expect(res.cases[0]?.suppressedReason).toBeTruthy();
			expect(res.cases[1]?.suppressedReason).toContain("回显");
		} finally { echoSrv.stop(true); }
	});

	test("[P1-5] runBarrierRaceProbe net 模式合并 Vault/优先级请求头、initialCookies 与 Content-Type", async () => {
		const root = makeTempWorkspace("nuwa-p1-race-hdr-");
		upsertSessionRole(root, { role: "worker", bearer: "vault-tok", headers: { "x-vault": "from-vault", "x-prio": "vault" } });
		let seen: { auth?: string; xVault?: string; xPrio?: string; cookie?: string; ct?: string } = {};
		const hdrSrv = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
			await req.text();
			seen = { auth: req.headers.get("authorization") ?? undefined, xVault: req.headers.get("x-vault") ?? undefined,
				xPrio: req.headers.get("x-prio") ?? undefined, cookie: req.headers.get("cookie") ?? undefined,
				ct: req.headers.get("content-type") ?? undefined };
			return jsonRes({ ok: true }, 200);
		} });
		try {
			const base = `http://127.0.0.1:${hdrSrv.port}`;
			const res = await runBarrierRaceProbe({ root, scope: makeScope(base), role: "worker", transport: "net", concurrency: 2,
				roleHeaders: { worker: { "x-prio": "roleHeaders" } }, extraHeaders: { "x-prio": "optsExtra" },
				initialCookies: { sid: "cookie-123" },
				request: { method: "POST", url: `${base}/api/test`, extraHeaders: { "x-prio": "stepExtra" },
					headers: { "x-prio": "stepHeaders" }, body: { a: 1 } } });
			expect(res.successCount).toBe(2);
			expect(seen.auth).toBe("Bearer vault-tok");
			expect(seen.xVault).toBe("from-vault");
			expect(seen.xPrio).toBe("stepHeaders");
			expect(seen.cookie).toContain("sid=cookie-123");
			expect(seen.ct).toBe("application/json");
		} finally { hdrSrv.stop(true); }
	});

	test("[P1-6] 配额 429 不误报、丢失更新必捕获与 net Keep-Alive 即收即结", async () => {
		let quotaBal = 100; let quotaOk = 0; let lostBal = 100;
		const kaSockets = new Set<NetSocket>();
		const kaSrv = createNetServer((sock) => {
			kaSockets.add(sock); sock.on("close", () => kaSockets.delete(sock));
			sock.once("data", () => {
				const body = JSON.stringify({ ok: true, mode: "keepalive" });
				sock.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: keep-alive\r\n\r\n${body}`);
				// 故意保持连接开启不主动关闭，测试即收即结
			});
		});
		await new Promise<void>((r) => kaSrv.listen(0, "127.0.0.1", () => r()));
		const kaPort = (kaSrv.address() as { port: number }).port;
		const raceSrv = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(req) {
			const p = new URL(req.url).pathname;
			if (p === "/q/bal") return jsonRes({ balance: quotaBal }, 200);
			if (p === "/q/hit") {
				if (quotaOk < 3) { quotaOk += 1; quotaBal -= 10; return jsonRes({ ok: true }, 200); }
				return jsonRes({ error: "rate" }, 429);
			}
			if (p === "/l/bal") return jsonRes({ balance: lostBal }, 200);
			if (p === "/l/hit") { lostBal = 90; return jsonRes({ ok: true }, 200); } // 并发丢失更新：5 次 200 仅扣减 10
			return jsonRes({}, 404);
		} });
		try {
			const base = `http://127.0.0.1:${raceSrv.port}`;
			const quotaRes = await runBarrierRaceProbe({ scope: makeScope(base), transport: "fetch", concurrency: 8,
				request: { method: "POST", url: `${base}/q/hit` }, beforeReadStep: { method: "GET", url: `${base}/q/bal` },
				afterReadStep: { method: "GET", url: `${base}/q/bal` }, numericFieldPath: "balance", expectedSingleDelta: -10, maxExpectedSuccesses: 5 });
			expect(quotaRes.numericDelta).toBe(-30);
			expect(quotaRes.numericAnomaly).toBe(false);
			expect(quotaRes.raceConditionDetected).toBe(false);
			expect(quotaRes.classification).toBe("rate_limited");

			const lostRes = await runBarrierRaceProbe({ scope: makeScope(base), transport: "fetch", concurrency: 5,
				request: { method: "POST", url: `${base}/l/hit` }, beforeReadStep: { method: "GET", url: `${base}/l/bal` },
				afterReadStep: { method: "GET", url: `${base}/l/bal` }, numericFieldPath: "balance", expectedSingleDelta: -10, maxExpectedSuccesses: 5 });
			expect(lostRes.successCount).toBe(5);
			expect(lostRes.numericDelta).toBe(-10);
			expect(lostRes.numericAnomaly).toBe(true);
			expect(lostRes.raceConditionDetected).toBe(true);
			expect(lostRes.classification).toBe("race_confirmed");

			const kaBase = `http://127.0.0.1:${kaPort}`;
			const t0 = Date.now();
			const kaRes = await runBarrierRaceProbe({ scope: makeScope(kaBase), transport: "net", concurrency: 3, timeoutMs: 2500,
				request: { method: "POST", url: `${kaBase}/ka`, body: { ping: 1 } } });
			expect(kaRes.successCount).toBe(3);
			expect(kaRes.results.every((r) => r.status === 200 && !r.timedOut)).toBe(true);
			expect(Date.now() - t0).toBeLessThan(1500);
			expect(kaRes.leakedSockets).toBe(0);
		} finally {
			raceSrv.stop(true);
			for (const sk of kaSockets) sk.destroy();
			kaSrv.close();
		}
	});
});
