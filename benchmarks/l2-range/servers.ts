#!/usr/bin/env bun
/**
 * 女娲 v6.0 L2 离线微基准合成服务集群（仅绑定本机 127.0.0.1:0，纯良性业务 JSON 响应）。
 *
 * 包含 5 个轻量合成回归测试场景：
 * 1) `t1-spa-jwt-bola`：前端 JS 清单 + 合成角色令牌签发 + 跨角色资源权限配置缺陷检测（水平/垂直权限边界校验）；
 * 2) `t2-waf-soft404-trap`：HTTP 429 限流响应（带 Retry-After）+ 兜底 200 HTML 页面（Soft-404 过滤）+ 1 个合法诊断 API 端点；
 * 3) `t3-blind-ssrf-oob`：服务端异步健康检查回调接口（严格仅允许回调本机 127.0.0.1 接收端）+ 本机回调收集器；
 * 4) `t4-hybrid-sourcemap-chain`：公开 `.js.map` 调试映射文件（内含未配置鉴权路由元数据）+ 多步表单校验端点；
 * 5) `t5-hardened-zero-vuln`：完全合规加固的零缺陷参考服务（统一 401/403 严格鉴权），验证零误报与快速负向封盘收敛。
 */

export type L2ScenarioId =
	| "t1-spa-jwt-bola"
	| "t2-waf-soft404-trap"
	| "t3-blind-ssrf-oob"
	| "t4-hybrid-sourcemap-chain"
	| "t5-hardened-zero-vuln";

export interface L2ScenarioSpec {
	id: L2ScenarioId;
	name: string;
	category: string;
	expectedFindings: number;
	expectedTerminalStatus: "completed" | "sealed_negative";
	description: string;
}

export const L2_SCENARIO_SPECS: readonly L2ScenarioSpec[] = [
	{
		id: "t1-spa-jwt-bola",
		name: "前端清单与多角色权限边界校验",
		category: "authz-boundary",
		expectedFindings: 2,
		expectedTerminalStatus: "completed",
		description: "模拟前端 JS 路由清单、合成角色令牌签发及水平/垂直权限配置遗漏检测",
	},
	{
		id: "t2-waf-soft404-trap",
		name: "限流退避与兜底页面过滤校验",
		category: "waf-soft404",
		expectedFindings: 1,
		expectedTerminalStatus: "completed",
		description: "模拟 HTTP 429 Retry-After 限流、SPA 兜底 200 HTML 软 404 陷阱过滤与合法诊断端点识别",
	},
	{
		id: "t3-blind-ssrf-oob",
		name: "异步健康检查本机回路回调闭环",
		category: "async-loopback-oob",
		expectedFindings: 1,
		expectedTerminalStatus: "completed",
		description: "模拟仅允许本机 127.0.0.1 回路的异步健康检查接口与本机 Canary 收集器自动确认闭环",
	},
	{
		id: "t4-hybrid-sourcemap-chain",
		name: "调试映射路由提取与多步表单校验",
		category: "sourcemap-chain",
		expectedFindings: 1,
		expectedTerminalStatus: "completed",
		description: "模拟公开 .js.map 源码映射提取未鉴权路由元数据及多步表单前置校验闭环",
	},
	{
		id: "t5-hardened-zero-vuln",
		name: "全加固零缺陷服务快速封盘收敛",
		category: "hardened-baseline",
		expectedFindings: 0,
		expectedTerminalStatus: "sealed_negative",
		description: "模拟严格鉴权合规加固的零缺陷参考服务，验证零误报与 <=15 轮快速负向封盘收敛",
	},
] as const;

/** 评测专用的良性合成测试令牌（同时用于写入 SessionVault 做零泄露脱敏审计）。 */
export const L2_SYNTHETIC_TOKENS = {
	t1Alice: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJtZW1iZXIifQ.l2_syn_alice_tok_8801",
	t1Bob: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IiLCJyb2xlIjoibWVtYmVyIn0.l2_syn_bob_tok_8802",
	t1Admin: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.l2_syn_admin_tok_8800",
	t5Alice: "l2_hardened_alice_bearer_9901",
	t5Bob: "l2_hardened_bob_bearer_9902",
	t5Admin: "l2_hardened_admin_bearer_9900",
} as const;

export interface L2LoopbackOobEvent {
	id: string;
	protocol: "http";
	fullId: string;
	remoteAddress: string;
	timestamp: string;
	rawRequest: string;
}

export interface L2ScenarioServerHandle {
	scenarioId: L2ScenarioId;
	baseUrl: string;
	port: number;
	/** 仅 `t3-blind-ssrf-oob` 提供本机 127.0.0.1 回路回调收集器地址。 */
	collectorUrl?: string;
	collectorPort?: number;
	getCollectorEvents: () => L2LoopbackOobEvent[];
	stop: () => void;
}

export interface L2RangeClusterHandle {
	servers: Record<L2ScenarioId, L2ScenarioServerHandle>;
	stopAll: () => void;
}

function jsonResponse(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json; charset=utf-8",
			"Cache-Control": "no-store",
			"X-Content-Type-Options": "nosniff",
			...extraHeaders,
		},
	});
}

function htmlResponse(html: string, status = 200): Response {
	return new Response(html, {
		status,
		headers: {
			"Content-Type": "text/html; charset=utf-8",
		},
	});
}

function jsResponse(code: string, status = 200): Response {
	return new Response(code, {
		status,
		headers: {
			"Content-Type": "application/javascript; charset=utf-8",
		},
	});
}

function extractBearerToken(req: Request): string {
	const raw = (req.headers.get("authorization") ?? "").trim();
	if (raw.toLowerCase().startsWith("bearer ")) {
		return raw.slice(7).trim();
	}
	return "";
}

// ------------------------ 场景 1: t1-spa-jwt-bola ------------------------

const T1_SPA_HTML = [
	"<!doctype html>",
	"<html><head><meta charset=\"utf-8\"><title>L2 Workspace Console</title></head>",
	"<body><div id=\"root\" data-reactroot></div><script src=\"/assets/app-manifest.js\"></script></body></html>",
].join("");

const T1_MANIFEST_JS = [
	"// 良性前端路由清单（合成基准测试夹具）",
	"export const API_ENDPOINTS = [",
	"  '/api/v1/auth/issue-test-tokens',",
	"  '/api/v1/projects/1001',",
	"  '/api/v1/admin/tenant-quotas'",
	"];",
	"export async function loadProject() { return fetch('/api/v1/projects/1001'); }",
	"export async function loadAdminQuotas() { return fetch('/api/v1/admin/tenant-quotas'); }",
].join("\n");

function createT1Server(port = 0): L2ScenarioServerHandle {
	const srv = Bun.serve({
		hostname: "127.0.0.1",
		port,
		fetch(req: Request): Response {
			const url = new URL(req.url);
			const p = url.pathname;

			if (p === "/healthz") {
				return jsonResponse({ status: "ok", scenario: "t1-spa-jwt-bola" });
			}
			if (p === "/" || p === "/app" || p.startsWith("/app/")) {
				return htmlResponse(T1_SPA_HTML);
			}
			if (p === "/assets/app-manifest.js") {
				return jsResponse(T1_MANIFEST_JS);
			}
			if (p === "/api/v1/auth/issue-test-tokens") {
				return jsonResponse({
					issuer: "l2-synthetic-auth",
					roles: {
						member_alice: L2_SYNTHETIC_TOKENS.t1Alice,
						member_bob: L2_SYNTHETIC_TOKENS.t1Bob,
						tenant_admin: L2_SYNTHETIC_TOKENS.t1Admin,
					},
				});
			}

			const tok = extractBearerToken(req);
			const role =
				tok === L2_SYNTHETIC_TOKENS.t1Admin
					? "tenant_admin"
					: tok === L2_SYNTHETIC_TOKENS.t1Alice
						? "member_alice"
						: tok === L2_SYNTHETIC_TOKENS.t1Bob
							? "member_bob"
							: null;

			// 合成水平权限配置遗漏：未校验资源 owner（member_bob 可读取 alice 的项目数据）
			if (p === "/api/v1/projects/1001") {
				if (!role) {
					return jsonResponse({ error: "unauthorized", message: "Missing bearer token" }, 401);
				}
				return jsonResponse({
					projectId: 1001,
					owner: "alice",
					planTier: "enterprise-synthetic",
					monthlyQuotaUnits: 5000,
				});
			}

			// 合成垂直角色配置遗漏：仅校验已登录，漏检 tenant_admin 角色要求
			if (p === "/api/v1/admin/tenant-quotas") {
				if (!role) {
					return jsonResponse({ error: "unauthorized", message: "Missing bearer token" }, 401);
				}
				return jsonResponse({
					clusterName: "l2-synthetic-cluster",
					maxTenants: 120,
					globalQuotaOverrideEnabled: true,
				});
			}

			return jsonResponse({ error: "not_found", path: p }, 404);
		},
	});

	const actualPort = srv.port ?? 0;
	return {
		scenarioId: "t1-spa-jwt-bola",
		baseUrl: `http://127.0.0.1:${actualPort}`,
		port: actualPort,
		getCollectorEvents: () => [],
		stop: () => srv.stop(true),
	};
}

// ------------------------ 场景 2: t2-waf-soft404-trap ------------------------

const T2_SOFT404_HTML = [
	"<!doctype html>",
	"<html><head><meta charset=\"utf-8\"><title>L2 Portal CatchAll Shell</title></head>",
	"<body><div id=\"portal-root\" data-reactroot><p>Portal Default View</p></div></body></html>",
].join("");

function createT2Server(port = 0): L2ScenarioServerHandle {
	const srv = Bun.serve({
		hostname: "127.0.0.1",
		port,
		fetch(req: Request): Response {
			const url = new URL(req.url);
			const p = url.pathname;

			if (p === "/healthz") {
				return jsonResponse({ status: "ok", scenario: "t2-waf-soft404-trap" });
			}

			// 模拟 HTTP 429 限流网关端点（带标准 Retry-After 响应头）
			if (p === "/api/v1/rate-gate") {
				return jsonResponse(
					{ error: "rate_limited", message: "Too Many Requests - back off required" },
					429,
					{
						"Retry-After": "2",
						"X-RateLimit-Remaining": "0",
					},
				);
			}

			// 唯一合法诊断测试 API 端点（暴露合成内部调试配置元数据）
			if (p === "/api/v1/diagnostics/build-meta") {
				return jsonResponse({
					service: "l2-portal-gateway",
					debugDiagnosticsEnabled: true,
					exposedProfile: "staging-internal-config",
					internalUpstream: "http://127.0.0.1:19090",
					corsAllowWildcard: true,
				});
			}

			// 兜底 200 HTML 软 404 页面（验证 Soft-404 基线识别与零误报抑制）
			if (p === "/" || p === "/portal" || p.startsWith("/portal/")) {
				return htmlResponse(T2_SOFT404_HTML, 200);
			}

			return jsonResponse({ error: "not_found", path: p }, 404);
		},
	});

	const actualPort = srv.port ?? 0;
	return {
		scenarioId: "t2-waf-soft404-trap",
		baseUrl: `http://127.0.0.1:${actualPort}`,
		port: actualPort,
		getCollectorEvents: () => [],
		stop: () => srv.stop(true),
	};
}

// ------------------------ 场景 3: t3-blind-ssrf-oob ------------------------

function createT3Server(port = 0): L2ScenarioServerHandle {
	const events: L2LoopbackOobEvent[] = [];
	let seq = 0;

	// 本机 127.0.0.1 回调接收收集器（模拟离线 OOB 收集端）
	const collector = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(req: Request): Response {
			const url = new URL(req.url);
			if (url.pathname === "/oob/poll") {
				const filter = (url.searchParams.get("canary") ?? "").trim().toLowerCase();
				const matched = filter
					? events.filter(
							(ev) => ev.fullId.toLowerCase().includes(filter) || ev.rawRequest.toLowerCase().includes(filter),
						)
					: events;
				return jsonResponse({
					data: matched.map((ev) => ({
						id: ev.id,
						protocol: ev.protocol,
						"unique-id": ev.id,
						"full-id": ev.fullId,
						"remote-address": ev.remoteAddress,
						timestamp: ev.timestamp,
						"raw-request": ev.rawRequest,
					})),
					extra: null,
				});
			}

			const canaryParam = (url.searchParams.get("canary") ?? "").trim();
			const pathToken = url.pathname.replace(/^\/callback\/?/, "").trim();
			const fullId = canaryParam || pathToken || url.pathname;
			const hit: L2LoopbackOobEvent = {
				id: `l2-oob-${String(++seq).padStart(4, "0")}`,
				protocol: "http",
				fullId,
				remoteAddress: "127.0.0.1",
				timestamp: new Date().toISOString(),
				rawRequest: `${req.method} ${url.pathname}${url.search} HTTP/1.1`,
			};
			events.push(hit);
			return jsonResponse({ ok: true, receivedId: hit.id });
		},
	});

	const collectorPort = collector.port ?? 0;
	const collectorUrl = `http://127.0.0.1:${collectorPort}`;

	const srv = Bun.serve({
		hostname: "127.0.0.1",
		port,
		async fetch(req: Request): Promise<Response> {
			const url = new URL(req.url);
			const p = url.pathname;

			if (p === "/healthz") {
				return jsonResponse({ status: "ok", scenario: "t3-blind-ssrf-oob" });
			}

			if (p === "/api/v1/integrations/health-callback") {
				let callbackTarget = (url.searchParams.get("callbackUrl") ?? "").trim();
				if (!callbackTarget && req.method === "POST") {
					try {
						const body = (await req.json()) as { callbackUrl?: string };
						callbackTarget = String(body?.callbackUrl ?? "").trim();
					} catch {
						return jsonResponse({ error: "invalid_json" }, 400);
					}
				}
				if (!callbackTarget) {
					return jsonResponse({ error: "missing_callback_url" }, 400);
				}

				let parsedCallback: URL;
				try {
					parsedCallback = new URL(callbackTarget);
				} catch {
					return jsonResponse({ error: "malformed_callback_url" }, 400);
				}

				// 安全护栏：合成基准服务严格只允许向本机 127.0.0.1 发起异步回路请求
				if (parsedCallback.protocol !== "http:" || parsedCallback.hostname !== "127.0.0.1") {
					return jsonResponse(
						{
							error: "loopback_only_in_l2_benchmark",
							message: "Synthetic benchmark restricts outbound callbacks strictly to http://127.0.0.1",
						},
						400,
					);
				}

				await fetch(parsedCallback.toString(), {
					method: "GET",
					headers: { "X-L2-Health-Probe": "synthetic-async-check" },
				}).catch(() => undefined);

				// 盲态响应：同步回包不包含任何内部回调响应内容，必须经由回调收集器确认
				return jsonResponse({ status: "queued", checkMode: "async-blind" }, 202);
			}

			return jsonResponse({ error: "not_found", path: p }, 404);
		},
	});

	const actualPort = srv.port ?? 0;
	return {
		scenarioId: "t3-blind-ssrf-oob",
		baseUrl: `http://127.0.0.1:${actualPort}`,
		port: actualPort,
		collectorUrl,
		collectorPort,
		getCollectorEvents: () => events.map((e) => ({ ...e })),
		stop: () => {
			srv.stop(true);
			collector.stop(true);
		},
	};
}

// ------------------------ 场景 4: t4-hybrid-sourcemap-chain ------------------------

const T4_INDEX_HTML = [
	"<!doctype html>",
	"<html><head><meta charset=\"utf-8\"><title>L2 Workflow Portal</title></head>",
	"<body><div id=\"app\"></div><script src=\"/static/workflow.bundle.js\"></script></body></html>",
].join("");

const T4_BUNDLE_JS = [
	"export function initPublicForm() { return '/api/v2/forms/validate-ticket'; }",
	"//# sourceMappingURL=/static/workflow.bundle.js.map",
].join("\n");

const T4_SOURCE_MAP = {
	version: 3,
	file: "workflow.bundle.js",
	sources: ["src/features/ticketFlow.ts", "src/routes/internalAuditSnapshot.ts"],
	sourcesContent: [
		[
			"export async function submitStep1() {",
			"  return fetch('/api/v2/forms/validate-ticket', {",
			"    method: 'POST',",
			"    headers: { 'Content-Type': 'application/json' },",
			"    body: JSON.stringify({ department: 'platform-ops', ticketCode: 'L2-FLOW-2026' })",
			"  });",
			"}",
		].join("\n"),
		[
			"// FIXME(sec-review): route mounted without requireAdminRole middleware in staging build",
			"export const INTERNAL_SNAPSHOT_ROUTE = '/api/v2/internal/audit-snapshot';",
			"export async function fetchInternalSnapshot(stepToken: string) {",
			"  return fetch(INTERNAL_SNAPSHOT_ROUTE, {",
			"    method: 'POST',",
			"    headers: { 'Content-Type': 'application/json' },",
			"    body: JSON.stringify({ stepToken, includeConfigMeta: true })",
			"  });",
			"}",
		].join("\n"),
	],
	mappings: "AAAA;AACA;",
};

const VALID_STEP_TOKEN = "stp_l2_verified_flow_2026";

function createT4Server(port = 0): L2ScenarioServerHandle {
	const srv = Bun.serve({
		hostname: "127.0.0.1",
		port,
		async fetch(req: Request): Promise<Response> {
			const url = new URL(req.url);
			const p = url.pathname;

			if (p === "/healthz") {
				return jsonResponse({ status: "ok", scenario: "t4-hybrid-sourcemap-chain" });
			}
			if (p === "/") {
				return htmlResponse(T4_INDEX_HTML);
			}
			if (p === "/static/workflow.bundle.js") {
				return jsResponse(T4_BUNDLE_JS);
			}
			if (p === "/static/workflow.bundle.js.map") {
				return jsonResponse(T4_SOURCE_MAP);
			}

			if (p === "/api/v2/forms/validate-ticket" && req.method === "POST") {
				try {
					const body = (await req.json()) as { department?: string; ticketCode?: string };
					if (body.department !== "platform-ops" || body.ticketCode !== "L2-FLOW-2026") {
						return jsonResponse(
							{
								error: "validation_failed",
								requiredFields: ["department", "ticketCode"],
							},
							422,
						);
					}
					return jsonResponse({
						ok: true,
						stepToken: VALID_STEP_TOKEN,
						nextStep: "/api/v2/internal/audit-snapshot",
					});
				} catch {
					return jsonResponse({ error: "invalid_json" }, 400);
				}
			}

			// 公开 SourceMap 暴露的未配置角色鉴权内部路由（通过多步表单 stepToken 后即可读取）
			if (p === "/api/v2/internal/audit-snapshot" && req.method === "POST") {
				try {
					const body = (await req.json()) as { stepToken?: string; includeConfigMeta?: boolean };
					if (body.stepToken !== VALID_STEP_TOKEN) {
						return jsonResponse({ error: "precondition_required", message: "Valid stepToken required" }, 428);
					}
					return jsonResponse({
						snapshotId: "snap-l2-9042",
						unauthenticatedAdminRoute: true,
						configMeta: {
							region: "local-synthetic",
							auditRetentionDays: 90,
							featureGateBypass: false,
						},
					});
				} catch {
					return jsonResponse({ error: "invalid_json" }, 400);
				}
			}

			return jsonResponse({ error: "not_found", path: p }, 404);
		},
	});

	const actualPort = srv.port ?? 0;
	return {
		scenarioId: "t4-hybrid-sourcemap-chain",
		baseUrl: `http://127.0.0.1:${actualPort}`,
		port: actualPort,
		getCollectorEvents: () => [],
		stop: () => srv.stop(true),
	};
}

// ------------------------ 场景 5: t5-hardened-zero-vuln ------------------------

const T5_PUBLIC_JS = "// 合规加固静态脚本（不含 SourceMap 与内部路由泄露）\nexport const APP_VERSION = '6.0.0-hardened';\n";

function createT5Server(port = 0): L2ScenarioServerHandle {
	const srv = Bun.serve({
		hostname: "127.0.0.1",
		port,
		fetch(req: Request): Response {
			const url = new URL(req.url);
			const p = url.pathname;

			if (p === "/healthz") {
				return jsonResponse({ status: "healthy", hardened: true });
			}
			if (p === "/") {
				return htmlResponse(
					"<!doctype html><html><head><title>Hardened Reference Service</title></head><body><script src=\"/static/app.js\"></script></body></html>",
				);
			}
			if (p === "/static/app.js") {
				return jsResponse(T5_PUBLIC_JS);
			}

			const tok = extractBearerToken(req);
			const role =
				tok === L2_SYNTHETIC_TOKENS.t5Admin
					? "admin"
					: tok === L2_SYNTHETIC_TOKENS.t5Alice
						? "alice"
						: tok === L2_SYNTHETIC_TOKENS.t5Bob
							? "bob"
							: null;

			if (p === "/api/v1/projects/1001") {
				if (!role) {
					return jsonResponse({ error: "unauthorized", message: "Valid bearer token required" }, 401);
				}
				if (role !== "alice" && role !== "admin") {
					return jsonResponse({ error: "forbidden", message: "Resource ownership mismatch" }, 403);
				}
				return jsonResponse({ projectId: 1001, owner: "alice", status: "active" });
			}

			if (p === "/api/v1/projects/1002") {
				if (!role) {
					return jsonResponse({ error: "unauthorized", message: "Valid bearer token required" }, 401);
				}
				if (role !== "bob" && role !== "admin") {
					return jsonResponse({ error: "forbidden", message: "Resource ownership mismatch" }, 403);
				}
				return jsonResponse({ projectId: 1002, owner: "bob", status: "active" });
			}

			if (p === "/api/v1/admin/settings") {
				if (!role) {
					return jsonResponse({ error: "unauthorized", message: "Valid bearer token required" }, 401);
				}
				if (role !== "admin") {
					return jsonResponse({ error: "forbidden", message: "Admin role strictly required" }, 403);
				}
				return jsonResponse({ auditEnforced: true, strictRbac: true });
			}

			if (p === "/api/v1/profile/me") {
				if (!role) {
					return jsonResponse({ error: "unauthorized", message: "Valid bearer token required" }, 401);
				}
				return jsonResponse({ subject: role, authenticated: true });
			}

			return jsonResponse({ error: "not_found", path: p }, 404);
		},
	});

	const actualPort = srv.port ?? 0;
	return {
		scenarioId: "t5-hardened-zero-vuln",
		baseUrl: `http://127.0.0.1:${actualPort}`,
		port: actualPort,
		getCollectorEvents: () => [],
		stop: () => srv.stop(true),
	};
}

/** 按场景 ID 启动单个本机 `127.0.0.1` 合成基准服务。 */
export function startL2ScenarioServer(scenarioId: L2ScenarioId, port = 0): L2ScenarioServerHandle {
	switch (scenarioId) {
		case "t1-spa-jwt-bola":
			return createT1Server(port);
		case "t2-waf-soft404-trap":
			return createT2Server(port);
		case "t3-blind-ssrf-oob":
			return createT3Server(port);
		case "t4-hybrid-sourcemap-chain":
			return createT4Server(port);
		case "t5-hardened-zero-vuln":
			return createT5Server(port);
	}
}

/** 一键启动全部 5 个本机 `127.0.0.1:0` L2 合成基准服务集群。 */
export function startL2RangeCluster(portBase?: number): L2RangeClusterHandle {
	const p = (offset: number) => (portBase && portBase > 0 ? portBase + offset : 0);
	const servers: Record<L2ScenarioId, L2ScenarioServerHandle> = {
		"t1-spa-jwt-bola": createT1Server(p(0)),
		"t2-waf-soft404-trap": createT2Server(p(1)),
		"t3-blind-ssrf-oob": createT3Server(p(2)),
		"t4-hybrid-sourcemap-chain": createT4Server(p(3)),
		"t5-hardened-zero-vuln": createT5Server(p(4)),
	};
	return {
		servers,
		stopAll: () => {
			for (const srv of Object.values(servers)) {
				try {
					srv.stop();
				} catch {
					/* ignore */
				}
			}
		},
	};
}

if (import.meta.main) {
	const portBaseEnv = Number(process.env.L2_PORT_BASE ?? "0");
	const cluster = startL2RangeCluster(Number.isFinite(portBaseEnv) && portBaseEnv > 0 ? portBaseEnv : 0);
	const manifest = Object.fromEntries(
		Object.entries(cluster.servers).map(([id, h]) => [
			id,
			{
				baseUrl: h.baseUrl,
				port: h.port,
				...(h.collectorUrl ? { collectorUrl: h.collectorUrl } : {}),
			},
		]),
	);
	console.log(JSON.stringify({ ready: true, scenarios: manifest }, null, 2));

	const shutdown = () => {
		cluster.stopAll();
		process.exit(0);
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}
