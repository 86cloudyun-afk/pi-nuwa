/**
 * 女娲 v7.0 多跳攻击链合成与验证引擎单元测试。
 *
 * 使用 Bun.serve 在本机 127.0.0.1:0 启动 3 个真实多跳合成靶机及受控本机 OOB 接收器，全面验证：
 * 1. 三跳组合利用链：SourceMap/前端泄露内部审批路由 -> 普通低权凭据越权读取审批单中的 exportTicket
 *    -> 凭 exportTicket 调内部导出接口拿敏感业务数据（产出待双盲复验 candidate Fact 与 verify-vuln:<fid>）；
 * 2. 两跳/三跳受控本机 OOB 链：配置接口泄露回调端点模板 -> 提取一次性 antiReplayToken
 *    -> 触发仅限本机 127.0.0.1 的 OOB 回调接收器实锤（及越界 OOB 阻断、无回调防误报）；
 * 3. 中断定界与信念衰减靶机：第 1 跳正常、第 2 跳被严格鉴权 403 加固（及 Soft-404）阻断，
 *    精准返回 brokenAtStep === 1、verified === false、后续步骤 0 盲打，并驱动信念图下游分支精准衰减；
 * 4. 有向环防死循环、深度硬上界 <= 4、blocked/rejected 事实过滤、只读方法守卫与全链路零凭据明文泄露。
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initBeliefGraphFromState, resolveBeliefNodeId } from "../omp/belief-search";
import {
	applyChainResultToBeliefGraph,
	CAPABILITY_TAGS,
	compileChainToTrafficSequence,
	executeAttackChainVerification,
	extractFactCapabilities,
	MAX_CHAIN_DEPTH,
	synthesizeAttackChains,
	type AttackChainSpec,
	type CapabilityTag,
} from "../omp/chain-composer";
import { defaultScopeForTarget, type ScopePolicy } from "../omp/scope";
import { upsertSessionRole } from "../omp/session-vault";
import type { Fact, NuwaState } from "../omp/types";

const tempDirs: string[] = [];

function makeTempWorkspace(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

function makeBaseState(baseUrl: string, facts: Fact[], scope?: ScopePolicy): NuwaState {
	let host = "127.0.0.1";
	let port = 80;
	try {
		const u = new URL(baseUrl);
		host = u.hostname;
		port = Number(u.port) || 80;
	} catch {
		/* ignore */
	}
	const factMap: Record<string, Fact> = {};
	for (const f of facts) {
		factMap[f.id] = f;
	}
	return {
		schema: 6,
		version: "6.0.0",
		project: {
			id: "proj-v7-chain-test",
			target: baseUrl,
			url: baseUrl,
			host,
			port,
			scheme: "http",
			goal: "验证多跳组合攻击链合成与验证引擎",
			mode: "audit",
			status: "active",
			phase: "vuln",
			createdAt: "2026-11-26T00:00:00.000Z",
			updatedAt: "2026-11-26T00:00:00.000Z",
			scope: scope ?? makeLoopbackScope(),
		},
		facts: factMap,
		intents: {},
		seq: { fact: facts.length, intent: 0 },
		runtime: {
			startedAt: Date.now(),
			turns: 1,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 0,
			lastToolCalls: 0,
			tokens: 0,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
		},
	};
}

function makeLoopbackScope(): ScopePolicy {
	const base = defaultScopeForTarget("http://127.0.0.1");
	return {
		...base,
		allowHosts: ["127.0.0.1"],
		allowLoopback: true,
		allowPrivateNetwork: false,
		allowDestructive: false,
	};
}

// ==================== 3 个真实本机 127.0.0.1:0 多跳合成靶机 + 本机 OOB 接收器 ====================

let serverChainA: ReturnType<typeof Bun.serve>;
let baseUrlA = "";

let serverOobReceiver: ReturnType<typeof Bun.serve>;
let oobReceiverBaseUrl = "";
const oobCapturedHits: Array<{
	id: string;
	path: string;
	query: string;
	timestamp: string;
}> = [];

let serverChainB: ReturnType<typeof Bun.serve>;
let baseUrlB = "";
const issuedAntiReplayTokens = new Set<string>();
const consumedAntiReplayTokens = new Set<string>();

let serverChainC: ReturnType<typeof Bun.serve>;
let baseUrlC = "";
let serverCHop3HitCount = 0;

const LOW_PRIV_BEARER_SECRET = "low_priv_jwt_secret_token_2026_v7";
const EXPORT_TICKET_SECRET = "exp_tkt_internal_secret_99887766";
const ANTI_REPLAY_SECRET_PREFIX = "art_once_secret_";

const SOFT_404_SPA_HTML =
	"<!doctype html><html><head><title>Portal - 404 Not Found</title></head><body><div id='root'>找不到此页面 NEXT_HTTP_ERROR_FALLBACK</div></body></html>";

beforeAll(() => {
	// 靶机 A：三跳组合利用链（SourceMap 泄露内部路由 -> 低权越权读审批单拿 exportTicket -> 调内部导出拿敏感数据）
	serverChainA = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(req: Request) {
			const url = new URL(req.url);
			const method = req.method.toUpperCase();
			if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
				return Response.json({ ok: false, error: "method not allowed" }, { status: 405 });
			}

			// 第 1 跳：前端 SourceMap 泄露未公开内部审批路由
			if (url.pathname === "/assets/app.bundle.js.map") {
				return Response.json(
					{
						version: 3,
						file: "app.bundle.js",
						sources: ["src/modules/internalApprovalClient.ts"],
						sourcesContent: [
							`export async function fetchApproval() { return fetch('/api/internal/approvals/2026'); }`,
						],
						mappings: "AAAA,SAAS",
					},
					{ status: 200 },
				);
			}

			// 第 2 跳：内部审批单详情接口（存在 BOLA/BFLA 缺陷，普通低权员工凭据即可读取并泄露一次性 exportTicket）
			if (url.pathname === "/api/internal/approvals/2026") {
				const auth = req.headers.get("authorization") ?? "";
				if (auth !== `Bearer ${LOW_PRIV_BEARER_SECRET}`) {
					return Response.json({ ok: false, error: "unauthorized: missing token" }, { status: 401 });
				}
				return Response.json(
					{
						ok: true,
						data: {
							approvalId: "APPR-2026",
							department: "core-settlement",
							status: "approved",
							exportTicket: EXPORT_TICKET_SECRET,
						},
					},
					{ status: 200 },
				);
			}

			// 第 3 跳：内部数据导出接口（仅凭有效 exportTicket 放行敏感业务报表数据）
			if (url.pathname === "/api/internal/export") {
				const qTicket = url.searchParams.get("ticket") ?? url.searchParams.get("exportTicket") ?? "";
				const hTicket = req.headers.get("x-export-ticket") ?? "";
				const supplied = qTicket || hTicket;
				if (supplied !== EXPORT_TICKET_SECRET) {
					return Response.json({ ok: false, error: "forbidden: invalid exportTicket" }, { status: 403 });
				}
				return Response.json(
					{
						ok: true,
						reportId: "FIN-EXPORT-2026-Q4",
						records: [
							{ accountId: "ACC-9001", customerTier: "enterprise", settlementAmount: 1285000, currency: "CNY" },
							{ accountId: "ACC-9002", customerTier: "vip", settlementAmount: 642000, currency: "CNY" },
						],
					},
					{ status: 200 },
				);
			}

			// 其余未知路径统一返回 SPA Soft-404 壳，检验引擎抗噪能力
			return new Response(SOFT_404_SPA_HTML, {
				status: 200,
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		},
	});
	baseUrlA = `http://127.0.0.1:${serverChainA.port}`;

	// 本机受控 OOB 回调接收器（严格监听 127.0.0.1:0）
	serverOobReceiver = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(req: Request) {
			const url = new URL(req.url);
			if (url.pathname === "/oob/callback") {
				const hit = {
					id: `hit_${oobCapturedHits.length + 1}`,
					path: url.pathname,
					query: url.search,
					timestamp: new Date().toISOString(),
				};
				oobCapturedHits.push(hit);
				return Response.json({ received: true, id: hit.id }, { status: 200 });
			}
			if (url.pathname === "/oob/events") {
				return Response.json(
					{
						ok: true,
						count: oobCapturedHits.length,
						hits: oobCapturedHits,
					},
					{ status: 200 },
				);
			}
			return Response.json({ error: "not found" }, { status: 404 });
		},
	});
	oobReceiverBaseUrl = `http://127.0.0.1:${serverOobReceiver.port}`;

	// 靶机 B：两跳/三跳受控本机 OOB 回调链靶机
	let tokenSeq = 1;
	serverChainB = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		async fetch(req: Request) {
			const url = new URL(req.url);

			// 跳 1：配置接口泄露内部回调触发端点模板
			if (url.pathname === "/api/public/webhook-config") {
				return Response.json(
					{
						service: "audit-webhook-dispatcher",
						version: "2.4.0",
						callbackTemplate:
							"/api/internal/webhook/dispatch?antiReplayToken={{antiReplayToken}}&callback={{callback}}",
					},
					{ status: 200 },
				);
			}

			// 跳 2：签发一次性 antiReplayToken
			if (url.pathname === "/api/internal/webhook/nonce") {
				const token = `${ANTI_REPLAY_SECRET_PREFIX}${String(tokenSeq++).padStart(4, "0")}_x9z8`;
				issuedAntiReplayTokens.add(token);
				return new Response(
					JSON.stringify({
						ok: true,
						antiReplayToken: token,
						ttlSeconds: 60,
					}),
					{
						status: 200,
						headers: {
							"Content-Type": "application/json",
							"X-Anti-Replay-Token": token,
						},
					},
				);
			}

			// 紧凑两跳版入口：同时泄露路由并在响应头签发一次性 antiReplayToken
			if (url.pathname === "/api/public/compact-oob-init") {
				const token = `${ANTI_REPLAY_SECRET_PREFIX}compact_${String(tokenSeq++).padStart(4, "0")}`;
				issuedAntiReplayTokens.add(token);
				return Response.json(
					{
						dispatchEndpoint: "/api/internal/webhook/dispatch",
						antiReplayToken: token,
					},
					{ status: 200 },
				);
			}

			// 跳 3：触发仅限本机 127.0.0.1 的 OOB 回调
			if (url.pathname === "/api/internal/webhook/dispatch") {
				const token =
					url.searchParams.get("antiReplayToken") ??
					url.searchParams.get("token") ??
					req.headers.get("x-anti-replay-token") ??
					"";
				if (!token || !issuedAntiReplayTokens.has(token) || consumedAntiReplayTokens.has(token)) {
					return Response.json({ ok: false, error: "invalid or replayed token" }, { status: 403 });
				}
				consumedAntiReplayTokens.add(token);

				const cbRaw = url.searchParams.get("callback") ?? url.searchParams.get("callbackUrl") ?? "";
				let cbUrl: URL;
				try {
					cbUrl = new URL(cbRaw);
				} catch {
					return Response.json({ ok: false, error: "invalid callback url" }, { status: 400 });
				}

				// 靶机安全锁：仅允许回调本机 127.0.0.1
				if (cbUrl.hostname !== "127.0.0.1") {
					return Response.json({ ok: false, error: "only 127.0.0.1 loopback allowed" }, { status: 403 });
				}

				if (url.searchParams.get("dryRunNoOob") !== "1") {
					cbUrl.searchParams.set("source", "chain-b-dispatcher");
					await fetch(cbUrl.toString(), { method: "GET" });
				}
				return Response.json({ ok: true, dispatched: true }, { status: 200 });
			}

			return Response.json({ ok: false, error: "not found" }, { status: 404 });
		},
	});
	baseUrlB = `http://127.0.0.1:${serverChainB.port}`;

	// 靶机 C：中断定界靶机（第 1 跳正常 200，第 2 跳被严格 RBAC 鉴权 403 阻断，或 Soft-404 阻断）
	serverChainC = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(req: Request) {
			const url = new URL(req.url);

			if (url.pathname === "/assets/hardened.js.map") {
				return Response.json(
					{
						version: 3,
						sources: ["src/admin/approvals.ts"],
						sourcesContent: [`const API = '/api/internal/approvals/9001';`],
					},
					{ status: 200 },
				);
			}

			if (url.pathname === "/api/internal/approvals/9001") {
				// 严格 RBAC 加固：拒绝普通低权凭据，返回 403
				return Response.json(
					{
						ok: false,
						code: 403,
						error: "Forbidden: strict RBAC policy blocks low-privilege role",
					},
					{ status: 403 },
				);
			}

			if (url.pathname === "/api/internal/approvals/soft404") {
				return new Response(SOFT_404_SPA_HTML, {
					status: 200,
					headers: { "Content-Type": "text/html; charset=utf-8" },
				});
			}

			if (url.pathname === "/api/internal/export-hardened") {
				serverCHop3HitCount += 1;
				return Response.json({ ok: false, error: "should never be reached" }, { status: 403 });
			}

			return new Response(SOFT_404_SPA_HTML, {
				status: 200,
				headers: { "Content-Type": "text/html; charset=utf-8" },
			});
		},
	});
	baseUrlC = `http://127.0.0.1:${serverChainC.port}`;
});

afterAll(() => {
	serverChainA?.stop(true);
	serverChainB?.stop(true);
	serverChainC?.stop(true);
	serverOobReceiver?.stop(true);
	for (const dir of tempDirs) {
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

// ==================== 测试用例集 ====================

describe("能力标签提取与图合成边界守卫", () => {
	test("规范 CapabilityTag 全覆盖且自动过滤 blocked 与双盲 rejected 事实", () => {
		const requiredTags: CapabilityTag[] = [
			"cap:leaked_route",
			"cap:low_priv_token",
			"cap:admin_token",
			"cap:id_enumerable",
			"cap:ticket_or_token_leak",
			"cap:url_sink",
			"cap:admin_export_endpoint",
			"cap:oob_channel",
		];
		for (const tag of requiredTags) {
			expect(CAPABILITY_TAGS).toContain(tag as (typeof CAPABILITY_TAGS)[number]);
		}

		const customTag: CapabilityTag = "cap:custom_domain_pivot";
		expect(customTag.startsWith("cap:")).toBe(true);

		const blockedFact: Fact = {
			id: "f_blocked",
			kind: "blocked",
			title: "SourceMap 泄露内部路由 /api/internal/export",
			detail: "已被 WAF 阻断",
			createdAt: "2026-11-26T00:00:00Z",
		};
		const rejectedFact: Fact = {
			id: "f_rejected",
			kind: "vuln",
			title: "越权读取审批单中的 exportTicket",
			detail: "双盲复验证伪驳回",
			verifyStage: "rejected",
			createdAt: "2026-11-26T00:00:00Z",
		};

		expect(extractFactCapabilities(blockedFact).eligible).toBe(false);
		expect(extractFactCapabilities(blockedFact).provides).toEqual([]);
		expect(extractFactCapabilities(rejectedFact).eligible).toBe(false);
		expect(extractFactCapabilities(rejectedFact).provides).toEqual([]);
	});

	test("有向环图防死循环、深度上界严格 <= 4 且只读方法强制收敛", () => {
		// 构造含三元有向环 (f_c1 -> f_c2 -> f_c3 -> f_c1) + 5 跳超长链的复杂图
		const cyclicFacts: Fact[] = [
			{
				id: "f0_entry",
				kind: "endpoint",
				title: "入口侦察泄露路由",
				detail: "暴露 /api/step0",
				targetKey: "/api/step0",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:leaked_route"],
						requires: [],
						endpoint: "/api/step0",
					},
				},
			},
			{
				id: "f_c1",
				kind: "endpoint",
				title: "环节点 1",
				detail: "环测试节点 1",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:hop_a"],
						requires: ["cap:leaked_route", "cap:hop_c"],
						endpoint: "/api/c1",
					},
				},
			},
			{
				id: "f_c2",
				kind: "endpoint",
				title: "环节点 2",
				detail: "环测试节点 2",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:hop_b"],
						requires: ["cap:hop_a"],
						endpoint: "/api/c2",
					},
				},
			},
			{
				id: "f_c3",
				kind: "endpoint",
				title: "环节点 3 回指环节点 1",
				detail: "环测试节点 3",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:hop_c"],
						requires: ["cap:hop_b"],
						endpoint: "/api/c3",
					},
				},
			},
			// 另构造一条 5 跳长链 f0_entry -> s1 -> s2 -> s3 -> s4，验证深度上界 <= 4 截断
			{
				id: "s1",
				kind: "endpoint",
				title: "长链第 2 跳",
				detail: "长链节点 1",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:stage_1", "cap:hop_c"],
						requires: ["cap:leaked_route"],
						endpoint: "/api/s1",
					},
				},
			},
			{
				id: "s2",
				kind: "endpoint",
				title: "长链第 3 跳",
				detail: "长链节点 2",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:stage_2"],
						requires: ["cap:stage_1"],
						endpoint: "/api/s2",
					},
				},
			},
			{
				id: "s3",
				kind: "endpoint",
				title: "长链第 4 跳导出",
				detail: "长链节点 3",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:ticket_or_token_leak"],
						requires: ["cap:stage_2"],
						endpoint: "/api/s3",
					},
				},
			},
			{
				id: "s4_beyond_limit",
				kind: "endpoint",
				title: "第 5 跳超界节点",
				detail: "不应合成出 5 跳链",
				createdAt: "2026-11-26T00:00:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:admin_export_endpoint"],
						requires: ["cap:ticket_or_token_leak"],
						endpoint: "/api/s4",
					},
				},
			},
		];

		const st = makeBaseState("http://127.0.0.1:18080", cyclicFacts);
		const startMs = Date.now();
		// 故意传入超界 maxDepth: 99，验证硬钳制 <= MAX_CHAIN_DEPTH (4)
		const chains = synthesizeAttackChains(st, { minDepth: 2, maxDepth: 99, maxChains: 50 });
		const elapsedMs = Date.now() - startMs;

		expect(elapsedMs).toBeLessThan(500);
		expect(chains.length).toBeGreaterThan(0);
		for (const c of chains) {
			expect(c.depth).toBeGreaterThanOrEqual(2);
			expect(c.depth).toBeLessThanOrEqual(MAX_CHAIN_DEPTH);
			expect(c.depth).toBeLessThanOrEqual(4);
			// 断言每条链中无重复 Fact ID（零环重入）
			expect(new Set(c.factIds).size).toBe(c.factIds.length);
			expect(Number.isFinite(c.utilityScore)).toBe(true);
		}

		// 验证只读方法强制收敛：即使篡改 method 为 DELETE，编译出的 TrafficStep 也严格为 GET
		const sampleChain: AttackChainSpec = {
			...chains[0]!,
			steps: chains[0]!.steps.map((s) => ({
				...s,
				method: "DELETE" as unknown as "GET",
			})),
		};
		const compiled = compileChainToTrafficSequence(sampleChain, "http://127.0.0.1:18080");
		for (const step of compiled) {
			expect(step.method).toBe("GET");
			expect(step.body).toBeUndefined();
		}
	});
});

describe("靶机 A：三跳组合利用链端到端合成、编译与零泄露验证", () => {
	test("SourceMap 泄露内部审批路由 -> 低权凭据越权读 exportTicket -> 调内部导出拿敏感业务数据", async () => {
		const root = makeTempWorkspace("nuwa-v7-chain-a-");

		// 将低权员工凭据存入 SessionVault，验证全流程零明文泄露
		upsertSessionRole(root, {
			role: "low",
			bearer: LOW_PRIV_BEARER_SECRET,
			note: "普通低权员工会话",
		});

		const facts: Fact[] = [
			{
				id: "f1_sourcemap",
				kind: "endpoint",
				title: "前端 SourceMap 泄露内部审批路由",
				detail: "静态资源 /assets/app.bundle.js.map 暴露未公开内部审批接口路由线索",
				targetKey: "/assets/app.bundle.js.map",
				meta: { bundles: ["/assets/app.bundle.js.map"] },
				createdAt: "2026-11-26T01:00:00Z",
			},
			{
				id: "f_cred_low",
				kind: "cred",
				title: "已获取普通低权员工账号认证凭据 (role=low)",
				detail: "普通员工低权限会话，角色 role=low，已存入会话保险箱",
				createdAt: "2026-11-26T01:01:00Z",
			},
			{
				id: "f2_approval_bola",
				kind: "endpoint",
				title: "普通低权凭据越权读取审批单中的 exportTicket",
				detail: "携带普通低权凭据访问泄露的内部审批路由可越权读取审批单详情及一次性 exportTicket",
				createdAt: "2026-11-26T01:02:00Z",
			},
			{
				id: "f3_internal_export",
				kind: "endpoint",
				title: "内部导出接口凭 exportTicket 导出敏感业务数据",
				detail: "内部导出接口 /api/internal/export 校验 ticket/exportTicket 参数后返回财务结算敏感业务数据",
				targetKey: "/api/internal/export",
				meta: { paths: ["/api/internal/export"] },
				createdAt: "2026-11-26T01:03:00Z",
			},
		];

		const scope = makeLoopbackScope();
		const state = makeBaseState(baseUrlA, facts, scope);
		state.project.activeRoles = ["low"];

		// 1. 验证单事实能力提取准确性
		const c1 = extractFactCapabilities(facts[0]!);
		const c2 = extractFactCapabilities(facts[2]!);
		const c3 = extractFactCapabilities(facts[3]!);
		expect(c1.provides).toContain("cap:leaked_route");
		expect(c2.requires).toContain("cap:leaked_route");
		expect(c2.requires).toContain("cap:low_priv_token");
		expect(c2.provides).toContain("cap:ticket_or_token_leak");
		expect(c3.requires).toContain("cap:ticket_or_token_leak");
		expect(c3.provides).toContain("cap:admin_export_endpoint");

		// 2. 验证 3 跳组合链自动合成与评分排序
		const chains = synthesizeAttackChains(state);
		expect(chains.length).toBeGreaterThanOrEqual(1);
		const threeHop = chains.find(
			(c) =>
				c.depth === 3 &&
				c.factIds[0] === "f1_sourcemap" &&
				c.factIds[1] === "f2_approval_bola" &&
				c.factIds[2] === "f3_internal_export",
		);
		expect(threeHop).toBeDefined();
		expect(threeHop!.supportingFactIds).toContain("f_cred_low");
		expect(threeHop!.utilityScore).toBeGreaterThan(0);

		// 3. 验证编译为 TrafficStep[] 的提取器与 {{var}} 模板映射
		const compiled = compileChainToTrafficSequence(threeHop!, baseUrlA, { root });
		expect(compiled).toHaveLength(3);
		expect(compiled[0]!.method).toBe("GET");
		expect(compiled[0]!.url).toBe(`${baseUrlA}/assets/app.bundle.js.map`);
		expect(compiled[0]!.extract?.leakedRoute).toBeDefined();

		expect(compiled[1]!.url).toBe(`${baseUrlA}{{leakedRoute}}`);
		expect(compiled[1]!.extract?.exportTicket).toBeDefined();

		expect(compiled[2]!.url).toContain("{{exportTicket}}");

		// 4. 执行真实多跳有状态重放验证
		const beliefGraph = initBeliefGraphFromState(state);
		const execRes = await executeAttackChainVerification(threeHop!, root, scope, {
			baseUrl: baseUrlA,
			state,
			beliefGraph,
			applyBeliefUpdate: true,
			candidateFactId: "f099",
		});

		expect(execRes.verified).toBe(true);
		expect(execRes.brokenAtStep).toBeUndefined();
		expect(execRes.stepTraces).toHaveLength(3);
		expect(execRes.stepTraces[0]!.status).toBe(200);
		expect(execRes.stepTraces[1]!.status).toBe(200);
		expect(execRes.stepTraces[2]!.status).toBe(200);
		expect(execRes.stepTraces[2]!.redactedResponseSnippet).toContain("FIN-EXPORT-2026-Q4");

		// 5. 验证产出的待双盲复验 candidate 复合漏洞 Fact 与 verify-vuln:<fid> 建议
		expect(execRes.candidateFact).toBeDefined();
		expect(execRes.candidateFact!.id).toBe("f099");
		expect(execRes.candidateFact!.kind).toBe("vuln");
		expect(execRes.candidateFact!.verifyStage).toBe("candidate");
		expect(execRes.candidateFact!.verified).toBe(false);
		expect(execRes.verifySuggestionKey).toBe("verify-vuln:f099");
		expect(execRes.verifyRecommendation?.key).toBe("verify-vuln:f099");
		expect(execRes.beliefObservation.type).toBe("breakthrough_signal");

		// 6. 零明文凭据与中间敏感票据泄露硬核审计（返回值 + 流量日志 + 执行账本）
		expect(execRes.redactedVariables.exportTicket).toBe("[REDACTED]");
		const serializedResult = JSON.stringify(execRes);
		expect(serializedResult).not.toContain(LOW_PRIV_BEARER_SECRET);
		expect(serializedResult).not.toContain(EXPORT_TICKET_SECRET);

		const trafficLogPath = join(root, ".nuwa", "traffic", "index.jsonl");
		expect(existsSync(trafficLogPath)).toBe(true);
		const trafficLogRaw = readFileSync(trafficLogPath, "utf8");
		expect(trafficLogRaw).not.toContain(LOW_PRIV_BEARER_SECRET);
		expect(trafficLogRaw).not.toContain(EXPORT_TICKET_SECRET);
		expect(trafficLogRaw).toContain("[REDACTED]");

		const ledgerPath = join(root, ".nuwa", "exec-ledger.jsonl");
		expect(existsSync(ledgerPath)).toBe(true);
		const ledgerRaw = readFileSync(ledgerPath, "utf8");
		expect(ledgerRaw).not.toContain(LOW_PRIV_BEARER_SECRET);
		expect(ledgerRaw).not.toContain(EXPORT_TICKET_SECRET);
	});
});

describe("靶机 B：两跳/三跳受控本机 127.0.0.1 OOB 回调链实锤与安全护栏", () => {
	test("三跳 OOB 链（配置泄露模板 -> 提取一次性 antiReplayToken -> 触发本机 127.0.0.1 OOB 接收器）端到端实锤", async () => {
		oobCapturedHits.length = 0;
		const root = makeTempWorkspace("nuwa-v7-chain-b3-");
		const scope = makeLoopbackScope();

		const facts: Fact[] = [
			{
				id: "f_oob_cfg",
				kind: "endpoint",
				title: "配置接口泄露回调端点模板",
				detail: "公开配置接口 /api/public/webhook-config 泄露内部回调端点模板路径",
				targetKey: "/api/public/webhook-config",
				createdAt: "2026-11-26T02:00:00Z",
			},
			{
				id: "f_oob_nonce",
				kind: "endpoint",
				title: "提取一次性 antiReplayToken",
				detail: "防重放令牌端点 /api/internal/webhook/nonce 签发一次性 antiReplayToken",
				targetKey: "/api/internal/webhook/nonce",
				createdAt: "2026-11-26T02:01:00Z",
			},
			{
				id: "f_oob_sink",
				kind: "endpoint",
				title: "触发仅限本机 127.0.0.1 的 OOB 回调接收器",
				detail: "使用配置泄露的回调端点模板携带一次性 antiReplayToken 触发本机 127.0.0.1 OOB 回调接收器实锤",
				createdAt: "2026-11-26T02:02:00Z",
			},
		];

		const state = makeBaseState(baseUrlB, facts, scope);
		const chains = synthesizeAttackChains(state);
		const oobChain = chains.find(
			(c) =>
				c.depth === 3 &&
				c.factIds[0] === "f_oob_cfg" &&
				c.factIds[1] === "f_oob_nonce" &&
				c.factIds[2] === "f_oob_sink",
		);
		expect(oobChain).toBeDefined();

		const oobCallbackUrl = `${oobReceiverBaseUrl}/oob/callback`;
		const oobPollUrl = `${oobReceiverBaseUrl}/oob/events`;

		const res = await executeAttackChainVerification(oobChain!, root, scope, {
			baseUrl: baseUrlB,
			state,
			oobCallbackUrl,
			oobPollUrl,
			candidateFactId: "f_oob_001",
		});

		expect(res.verified).toBe(true);
		expect(res.oobConfirmed).toBe(true);
		expect(oobCapturedHits.length).toBe(1);
		expect(res.candidateFact?.verifyStage).toBe("candidate");
		expect(res.verifySuggestionKey).toBe("verify-vuln:f_oob_001");
		expect(res.redactedVariables.antiReplayToken).toBe("[REDACTED]");

		// 确认一次性 antiReplayToken 明文未出现在返回结构与流量日志中
		const dump = JSON.stringify(res);
		for (const tok of issuedAntiReplayTokens) {
			expect(dump).not.toContain(tok);
		}
		const trafficLog = readFileSync(join(root, ".nuwa", "traffic", "index.jsonl"), "utf8");
		for (const tok of issuedAntiReplayTokens) {
			expect(trafficLog).not.toContain(tok);
		}
	});

	test("两跳紧凑 OOB 链合成验证 + 越界外部 OOB 地址强制阻断 + 无回调零误报", async () => {
		oobCapturedHits.length = 0;
		const root = makeTempWorkspace("nuwa-v7-chain-b2-");
		const scope = makeLoopbackScope();

		const compactFacts: Fact[] = [
			{
				id: "f_compact_init",
				kind: "endpoint",
				title: "配置接口泄露回调端点模板并签发一次性 antiReplayToken",
				detail: "/api/public/compact-oob-init 同时泄露回调路由与一次性 antiReplayToken",
				targetKey: "/api/public/compact-oob-init",
				createdAt: "2026-11-26T02:10:00Z",
			},
			{
				id: "f_compact_trigger",
				kind: "endpoint",
				title: "触发仅限本机 127.0.0.1 的 OOB 回调接收器",
				detail: "携带一次性 antiReplayToken 调用泄露回调端点触发本机 127.0.0.1 OOB 接收器",
				createdAt: "2026-11-26T02:11:00Z",
			},
		];

		const state = makeBaseState(baseUrlB, compactFacts, scope);
		const chains = synthesizeAttackChains(state);
		const twoHop = chains.find((c) => c.depth === 2);
		expect(twoHop).toBeDefined();

		// 1. 越界外部 OOB 地址在发包前即被 Scope 拦截（0 发包）
		const blockedRes = await executeAttackChainVerification(twoHop!, root, scope, {
			baseUrl: baseUrlB,
			oobCallbackUrl: "http://evil.outside.invalid:9999/oob",
		});
		expect(blockedRes.verified).toBe(false);
		expect(blockedRes.failureKind).toBe("scope_blocked");
		expect(blockedRes.stepTraces).toHaveLength(0);
		expect(oobCapturedHits).toHaveLength(0);

		// 2. 正常两跳本机 127.0.0.1 OOB 实锤通过
		const okRes = await executeAttackChainVerification(twoHop!, root, scope, {
			baseUrl: baseUrlB,
			oobCallbackUrl: `${oobReceiverBaseUrl}/oob/callback`,
			oobPollUrl: `${oobReceiverBaseUrl}/oob/events`,
		});
		expect(okRes.verified).toBe(true);
		expect(okRes.oobConfirmed).toBe(true);
		expect(oobCapturedHits).toHaveLength(1);

		// 3. 若靶机未真实触发 OOB 回调，严格返回 oob_not_triggered，绝不产生误报 Fact
		oobCapturedHits.length = 0;
		const noHitRes = await executeAttackChainVerification(twoHop!, root, scope, {
			baseUrl: baseUrlB,
			oobCallbackUrl: `${oobReceiverBaseUrl}/oob/callback`,
			verifyOobHit: () => ({ hit: false }),
		});
		expect(noHitRes.verified).toBe(false);
		expect(noHitRes.failureKind).toBe("oob_not_triggered");
		expect(noHitRes.candidateFact).toBeUndefined();
	});
});

describe("靶机 C：中断定界靶机（第 2 跳 403 / Soft-404 精准定界与信念图精准衰减）", () => {
	test("第 1 跳正常、第 2 跳被严格鉴权 403 加固阻断：返回 brokenAtStep === 1、零误报且精准衰减第 2 跳及下游信念", async () => {
		serverCHop3HitCount = 0;
		const root = makeTempWorkspace("nuwa-v7-chain-c-");
		upsertSessionRole(root, {
			role: "low",
			bearer: LOW_PRIV_BEARER_SECRET,
		});

		const facts: Fact[] = [
			{
				id: "fc_1_map",
				kind: "endpoint",
				title: "前端 SourceMap 泄露内部审批路由",
				detail: "从 /assets/hardened.js.map 发现内部审批路由线索",
				targetKey: "/assets/hardened.js.map",
				createdAt: "2026-11-26T03:00:00Z",
			},
			{
				id: "fc_2_hardened_bola",
				kind: "endpoint",
				title: "普通低权凭据越权读取审批单中的 exportTicket",
				detail: "尝试以普通低权凭据读取泄露审批路由中的 exportTicket",
				createdAt: "2026-11-26T03:01:00Z",
			},
			{
				id: "fc_3_export",
				kind: "endpoint",
				title: "内部导出接口凭 exportTicket 拿敏感业务数据",
				detail: "调用 /api/internal/export-hardened 导出业务数据",
				targetKey: "/api/internal/export-hardened",
				createdAt: "2026-11-26T03:02:00Z",
			},
		];

		const scope = makeLoopbackScope();
		const state = makeBaseState(baseUrlC, facts, scope);
		state.project.activeRoles = ["low"];
		// 添加一个依赖 fc_2_hardened_bola 的下游开放意图，验证信念级联衰减
		state.intents["i_downstream_export"] = {
			id: "i_downstream_export",
			phase: "exploit",
			key: "exploit:export-via-ticket",
			title: "基于审批单票据执行后续导出验证",
			detail: "依赖 fc_2_hardened_bola",
			from: ["fc_2_hardened_bola"],
			status: "open",
			priority: 80,
			attempts: 0,
			createdAt: "2026-11-26T03:03:00Z",
		};

		const chains = synthesizeAttackChains(state);
		const targetChain = chains[0]!;
		expect(targetChain.depth).toBe(3);

		const graph = initBeliefGraphFromState(state);
		const f1NodeId = resolveBeliefNodeId(graph, "fc_1_map", "fact")!;
		const f2NodeId = resolveBeliefNodeId(graph, "fc_2_hardened_bola", "fact")!;
		const downstreamIntentNodeId = resolveBeliefNodeId(graph, "i_downstream_export", "intent")!;

		const f1Before = graph.nodes[f1NodeId]!.posterior;
		const f2Before = graph.nodes[f2NodeId]!.posterior;
		const intentBefore = graph.nodes[downstreamIntentNodeId]!.posterior;

		const res = await executeAttackChainVerification(targetChain, root, scope, {
			baseUrl: baseUrlC,
			state,
			beliefGraph: graph,
			applyBeliefUpdate: true,
		});

		// 核心断言：精准停在第 2 跳（0-based index === 1），第 3 跳 0 盲打，零误报，零凭据泄露
		expect(res.verified).toBe(false);
		expect(res.brokenAtStep).toBe(1);
		expect(res.brokenFactId).toBe("fc_2_hardened_bola");
		expect(res.failureKind).toBe("auth_403");
		expect(res.candidateFact).toBeUndefined();
		expect(res.verifyRecommendation).toBeUndefined();
		expect(res.stepTraces).toHaveLength(2);
		expect(res.stepTraces[0]!.status).toBe(200);
		expect(res.stepTraces[1]!.status).toBe(403);
		expect(serverCHop3HitCount).toBe(0);

		expect(res.beliefObservation.type).toBe("waf_block");
		expect(JSON.stringify(res)).not.toContain(LOW_PRIV_BEARER_SECRET);
		expect(readFileSync(join(root, ".nuwa", "traffic", "index.jsonl"), "utf8")).not.toContain(
			LOW_PRIV_BEARER_SECRET,
		);

		// 验证信念图更新精准性：第 1 跳不受污染，第 2 跳及下游分支精准衰减
		expect(graph.nodes[f1NodeId]!.posterior).toBeCloseTo(f1Before, 5);
		expect(graph.nodes[f2NodeId]!.posterior).toBeLessThan(f2Before);
		expect(graph.nodes[downstreamIntentNodeId]!.posterior).toBeLessThan(intentBefore);
	});

	test("第 2 跳返回 HTTP 200 Soft-404 壳时同样精准定界 brokenAtStep === 1 且零误报", async () => {
		const root = makeTempWorkspace("nuwa-v7-chain-soft404-");
		const scope = makeLoopbackScope();
		const facts: Fact[] = [
			{
				id: "fs_1",
				kind: "endpoint",
				title: "前端泄露内部路由",
				detail: "暴露 /assets/hardened.js.map",
				targetKey: "/assets/hardened.js.map",
				createdAt: "2026-11-26T03:10:00Z",
			},
			{
				id: "fs_2_soft404",
				kind: "endpoint",
				title: "普通低权凭据越权读取审批单中的 exportTicket",
				detail: "目标 /api/internal/approvals/soft404 实际返回 SPA Soft-404",
				targetKey: "/api/internal/approvals/soft404",
				createdAt: "2026-11-26T03:11:00Z",
			},
			{
				id: "fs_3_export",
				kind: "endpoint",
				title: "内部导出接口凭 exportTicket 拿敏感业务数据",
				detail: "目标 /api/internal/export-hardened",
				targetKey: "/api/internal/export-hardened",
				createdAt: "2026-11-26T03:12:00Z",
			},
		];

		const state = makeBaseState(baseUrlC, facts, scope);
		const chains = synthesizeAttackChains(state);
		expect(chains.length).toBeGreaterThanOrEqual(1);

		const graph = initBeliefGraphFromState(state);
		const res = await executeAttackChainVerification(chains[0]!, root, scope, {
			baseUrl: baseUrlC,
			state,
		});

		expect(res.verified).toBe(false);
		expect(res.brokenAtStep).toBe(1);
		expect(res.brokenFactId).toBe("fs_2_soft404");
		expect(res.failureKind).toBe("soft_404");
		expect(res.stepTraces[1]!.isSoft404).toBe(true);
		expect(res.beliefObservation.type).toBe("soft404_miss");
		expect(res.candidateFact).toBeUndefined();

		const prop = applyChainResultToBeliefGraph(res, graph, state);
		expect(prop).not.toBeNull();
		expect(prop!.observationType).toBe("soft404_miss");
	});

	test("极端反例挑刺：首跳 k=0 阻断精确返回 0、跨跳携带敏感票据遇越界阻断零泄露、终局假阳性基线去噪与脏标题脱敏", async () => {
		const root = makeTempWorkspace("nuwa-v7-chain-edge-");
		const scope = makeLoopbackScope();

		// 1. 输入 Fact 标题误含 Bearer / JWT 明文时，合成出的链标题与步骤标题自动脱敏
		const dirtyJwt =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsZWFrZWRfdXNlciJ9.sigDirtyHeaderSecret99";
		const dirtyFacts: Fact[] = [
			{
				id: "fd_1",
				kind: "endpoint",
				title: `前端 SourceMap 泄露内部路由 (附带 Bearer ${dirtyJwt})`,
				detail: "暴露 /assets/app.bundle.js.map",
				targetKey: "/assets/app.bundle.js.map",
				createdAt: "2026-11-26T04:00:00Z",
			},
			{
				id: "fd_2",
				kind: "endpoint",
				title: "普通低权凭据越权读取审批单中的 exportTicket",
				detail: "读取 /api/internal/approvals/2026 中的 exportTicket",
				targetKey: "/api/internal/approvals/2026",
				createdAt: "2026-11-26T04:01:00Z",
			},
			{
				id: "fd_3_outside",
				kind: "endpoint",
				title: "内部导出接口凭 exportTicket 拿敏感业务数据",
				detail: "指向越界外部导出地址",
				createdAt: "2026-11-26T04:02:00Z",
				agentResult: {
					capabilities: {
						provides: ["cap:admin_export_endpoint"],
						requires: ["cap:ticket_or_token_leak"],
						endpoint: "http://evil.outside.invalid:9999/api/export",
					},
				},
			},
		];

		const dirtyState = makeBaseState(baseUrlA, dirtyFacts, scope);
		const dirtyChains = synthesizeAttackChains(dirtyState);
		expect(dirtyChains.length).toBeGreaterThan(0);
		expect(JSON.stringify(dirtyChains)).not.toContain(dirtyJwt);

		// 2. 第 1 跳正常、第 2 跳成功提取真实敏感票据 EXPORT_TICKET_SECRET、第 3 跳因越界主机被 Scope 拦截：
		//    断言 brokenAtStep === 2，且 error/reason/failureDetail 中绝不泄露刚提取出的 EXPORT_TICKET_SECRET
		upsertSessionRole(root, { role: "low", bearer: LOW_PRIV_BEARER_SECRET });
		const targetDirtyChain = dirtyChains.find((c) => c.depth === 3)!;
		// 保留越界完整 URL 以测试第 3 跳带票据拦截
		targetDirtyChain.steps[2]!.endpoint = "http://evil.outside.invalid:9999/api/export";

		const scopeBlockRes = await executeAttackChainVerification(targetDirtyChain, root, scope, {
			baseUrl: baseUrlA,
			authHeaders: { Authorization: `Bearer ${LOW_PRIV_BEARER_SECRET}` },
		});
		expect(scopeBlockRes.verified).toBe(false);
		expect(scopeBlockRes.brokenAtStep).toBe(2);
		expect(scopeBlockRes.brokenFactId).toBe("fd_3_outside");
		expect(scopeBlockRes.failureKind).toBe("scope_blocked");
		const dumpBlocked = JSON.stringify(scopeBlockRes);
		expect(dumpBlocked).not.toContain(EXPORT_TICKET_SECRET);
		expect(dumpBlocked).not.toContain(LOW_PRIV_BEARER_SECRET);

		// 3. 首跳 k=0 直接越界阻断时，brokenAtStep 严格等于数字 0（非 undefined）
		const hop0BlockedChain: AttackChainSpec = {
			...targetDirtyChain,
			steps: targetDirtyChain.steps.map((s, idx) =>
				idx === 0 ? { ...s, endpoint: "http://untrusted.corp.invalid/map" } : s,
			),
		};
		const hop0Res = await executeAttackChainVerification(hop0BlockedChain, root, scope, {
			baseUrl: baseUrlA,
		});
		expect(hop0Res.verified).toBe(false);
		expect(hop0Res.brokenAtStep).toBe(0);
		expect(hop0Res.brokenFactId).toBe("fd_1");

		// 4. 终局步骤返回与负向基线哈希完全一致的伪 200 响应时，被反误报门禁精准拦截
		const fakeBaselineBody = JSON.stringify({
			ok: true,
			reportId: "FIN-EXPORT-2026-Q4",
			records: [
				{ accountId: "ACC-9001", customerTier: "enterprise", settlementAmount: 1285000, currency: "CNY" },
				{ accountId: "ACC-9002", customerTier: "vip", settlementAmount: 642000, currency: "CNY" },
			],
		});
		const validThreeHopChain: AttackChainSpec = {
			...targetDirtyChain,
			steps: targetDirtyChain.steps.map((s, idx) =>
				idx === 2 ? { ...s, endpoint: "/api/internal/export" } : s,
			),
		};
		const fpFilteredRes = await executeAttackChainVerification(validThreeHopChain, root, scope, {
			baseUrl: baseUrlA,
			authHeaders: { Authorization: `Bearer ${LOW_PRIV_BEARER_SECRET}` },
			negativeBaseline: { statusCode: 200, body: fakeBaselineBody },
		});
		expect(fpFilteredRes.verified).toBe(false);
		expect(fpFilteredRes.brokenAtStep).toBe(2);
		expect(fpFilteredRes.failureKind).toBe("false_positive_filtered");
		expect(fpFilteredRes.candidateFact).toBeUndefined();
	});
});
