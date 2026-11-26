/**
 * 女娲 v6.0 HTTP 合规流量审计工作台与静态代码-动态契约协同引擎单元测试。
 *
 * 使用 Bun.serve 在本机 127.0.0.1:0 启动纯良性合成 API 服务，全链路验证：
 * 1. TrafficRecorder：0o600 权限、只读零写副作用、敏感 Header / URL / Body / SessionVault 零明文泄露脱敏、多维查询；
 * 2. replayTrafficSequence：多步有状态续传（Cookie Jar + Header/JSON Path CSRF 模板变量提取替换）、单步超时控制；
 * 3. Scope 强门禁：越界主机硬拦截、越界 30x Location 重定向零外连阻断、同源授权 30x 正常跟随；
 * 4. runStructuredMutations：五类只读契约差分（idor_step / auth_strip / graphql_introspect / nextjs_rsc / race_probe）、
 *    Soft-404 自动去噪零误报、并发度硬上限 <= 8（含超大值 / Infinity / NaN 防御）；
 * 5. hybrid-audit：TS/Express/Fastify/Koa/Next.js、Python/Flask/FastAPI/Django、Go/Gin/Echo/net/http 与 .js.map
 *    静态路由与缺鉴权提取、四类不安全代码模式告警、白盒->黑盒核验意图去重桥接、黑盒异常->源码文件行号反向定位。
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	bridgeWhiteboxToBlackboxIntents,
	correlateBlackboxFindingToSource,
	extractCodeAttackSurface,
	extractFromSourceMap,
} from "../omp/hybrid-audit";
import { defaultScopeForTarget, type ScopePolicy } from "../omp/scope";
import { upsertSessionRole } from "../omp/session-vault";
import {
	MAX_MUTATION_CONCURRENCY,
	REDACTED_MARKER,
	redactTrafficBody,
	redactTrafficUrl,
	replayTrafficSequence,
	runStructuredMutations,
	TrafficRecorder,
} from "../omp/traffic-workbench";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

// ==================== 本机 127.0.0.1:0 纯良性合成测试服务 ====================

let server: ReturnType<typeof Bun.serve>;
let baseUrl = "";
let outsideUrl = "http://evil.outside.invalid:9999";
let outsideHitCount = 0;

let activeInFlight = 0;
let peakInFlight = 0;
let raceCouponCounter = 0;

const VALID_SESSION_ID = "sess_live_9988776655443322";
const VALID_CSRF_TOKEN = "csrf_tok_aabbccddeeff0011";
const VALID_BEARER_ALICE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.sigAliceSecret99";
const VALID_API_KEY = "ak_prod_super_secret_key_2026";
const VAULT_MASTER_SECRET = "vault_ultra_secret_cred_778899";

const SPA_SOFT_404_HTML = `<!doctype html><html><head><title>App Shell - Page Not Found</title></head><body><div id="app">404 页面不存在</div></body></html>`;

beforeAll(() => {
	server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		async fetch(req: Request) {
			const url = new URL(req.url);
			const pathname = url.pathname;
			const method = req.method.toUpperCase();
			const cookie = req.headers.get("cookie") ?? "";
			const auth = req.headers.get("authorization") ?? "";

				// 1. 多步有状态工作流端点
				if (pathname === "/api/auth/login" && method === "POST") {
					const headers = new Headers({
						"Content-Type": "application/json",
						"X-Workflow-Stage": "authenticated",
					});
					headers.append("Set-Cookie", `sid=${VALID_SESSION_ID}; Path=/; HttpOnly; SameSite=Lax`);
					headers.append("Set-Cookie", "theme=dark; Path=/");
					return new Response(
						JSON.stringify({
							ok: true,
							data: {
								csrfToken: VALID_CSRF_TOKEN,
								echoSecret: VAULT_MASTER_SECRET,
							},
						}),
						{ status: 200, headers },
					);
				}

				if (pathname === "/api/workflow/ticket" && method === "GET") {
					if (!cookie.includes(`sid=${VALID_SESSION_ID}`)) {
						return Response.json({ error: "missing session cookie" }, { status: 401 });
					}
					return new Response(
						JSON.stringify({
							ticketId: "tkt_8848",
						}),
						{
							status: 200,
							headers: {
								"Content-Type": "application/json",
								"X-Step-Nonce": "nonce_step2_xyz",
							},
						},
					);
				}

				if (pathname === "/api/workflow/confirm" && method === "POST") {
					const csrfHdr = req.headers.get("x-csrf-token") ?? "";
					const stepNonce = req.headers.get("x-step-nonce") ?? "";
					if (!cookie.includes(`sid=${VALID_SESSION_ID}`) || csrfHdr !== VALID_CSRF_TOKEN) {
						return Response.json({ error: "forbidden csrf or session" }, { status: 403 });
					}
					const body = (await req.json()) as { ticketId?: string };
					if (body.ticketId !== "tkt_8848" || stepNonce !== "nonce_step2_xyz") {
						return Response.json({ error: "invalid workflow state" }, { status: 400 });
					}
					return Response.json({ confirmed: true, reference: "ORD-2026-OK" }, { status: 200 });
				}

				// 2. 重定向与超时测试端点
				if (pathname === "/api/redirect-inside") {
					return new Response(null, {
						status: 302,
						headers: { Location: "/api/public/ping" },
					});
				}

				if (pathname === "/api/redirect-outside") {
					return new Response(null, {
						status: 302,
						headers: { Location: `${outsideUrl}/callback` },
					});
				}

				if (pathname === "/api/public/ping") {
					return Response.json({ pong: true }, { status: 200 });
				}

				if (pathname === "/api/slow") {
					await Bun.sleep(350);
					return Response.json({ slow: true }, { status: 200 });
				}

				// 3. IDOR 边界测试端点（缺陷版 vs 加固版 vs Soft-404 版）
				const idorLeakMatch = /^\/api\/orders\/(\d+)$/.exec(pathname);
				if (idorLeakMatch && method === "GET") {
					if (auth !== `Bearer ${VALID_BEARER_ALICE}`) {
						return Response.json({ error: "unauthorized" }, { status: 401 });
					}
					const orderId = Number(idorLeakMatch[1]);
					// 未校验资源归属：101 属于 alice，102 属于 bob 但仍返回 200
					if (orderId === 101) {
						return Response.json({ orderId: 101, owner: "alice", total: 120 }, { status: 200 });
					}
					if (orderId === 102) {
						return Response.json({ orderId: 102, owner: "bob", total: 980 }, { status: 200 });
					}
					return Response.json({ error: "not found" }, { status: 404 });
				}

				const idorSafeMatch = /^\/api\/secure-orders\/(\d+)$/.exec(pathname);
				if (idorSafeMatch && method === "GET") {
					if (auth !== `Bearer ${VALID_BEARER_ALICE}`) {
						return Response.json({ error: "unauthorized" }, { status: 401 });
					}
					const orderId = Number(idorSafeMatch[1]);
					if (orderId === 101) {
						return Response.json({ orderId: 101, owner: "alice", total: 120 }, { status: 200 });
					}
					return Response.json({ error: "forbidden" }, { status: 403 });
				}

				const idorSoft404Match = /^\/api\/spa-items\/(\d+)$/.exec(pathname);
				if (idorSoft404Match && method === "GET") {
					const itemId = Number(idorSoft404Match[1]);
					if (itemId === 10) {
						return Response.json({ itemId: 10, title: "Valid Item" }, { status: 200 });
					}
					// 相邻 ID 返回 HTTP 200 SPA Soft-404 壳页面
					return new Response(SPA_SOFT_404_HTML, {
						status: 200,
						headers: { "Content-Type": "text/html; charset=utf-8" },
					});
				}

				// 4. Auth Strip 认证剥离差分测试端点
				if (pathname === "/api/admin/export" && method === "GET") {
					// 缺陷端点：源码漏挂鉴权中间件，有无 Authorization 均返回敏感列表
					return Response.json(
						{ exportedUsers: ["alice", "bob"], count: 2 },
						{ status: 200 },
					);
				}

				if (pathname === "/api/admin/secure-audit" && method === "GET") {
					if (auth !== `Bearer ${VALID_BEARER_ALICE}`) {
						return Response.json({ error: "unauthorized" }, { status: 401 });
					}
					return Response.json({ auditLogs: ["ok"] }, { status: 200 });
				}

				// 5. GraphQL 只读 Introspection 测试端点
				if (pathname === "/graphql" && method === "POST") {
					const bodyText = await req.text();
					if (bodyText.includes("__schema")) {
						return Response.json(
							{
								data: {
									__schema: {
										queryType: { name: "Query" },
										types: [
											{ name: "Query", kind: "OBJECT" },
											{ name: "UserAccount", kind: "OBJECT" },
											{ name: "AuditRecord", kind: "OBJECT" },
										],
									},
								},
							},
							{ status: 200 },
						);
					}
					return Response.json({ data: { __typename: "Query" } }, { status: 200 });
				}

				if (pathname === "/graphql-locked" && method === "POST") {
					return Response.json(
						{ errors: [{ message: "GraphQL introspection is disabled" }] },
						{ status: 400 },
					);
				}

				// 6. Next.js App Router 只读 RSC 头一致性测试端点
				if (pathname === "/app/dashboard" && method === "GET") {
					const isRsc = req.headers.get("rsc") === "1";
					// 模拟中间件配置疏漏：普通未认证访问 403，但携带 RSC: 1 头漏拦直接输出 Flight 数据流
					if (!auth && !isRsc) {
						return Response.json({ error: "login required" }, { status: 403 });
					}
					if (isRsc) {
						return new Response(
							`0:["$","div",null,{"children":"Internal Dashboard Flight Data"}]\n`,
							{
								status: 200,
								headers: { "Content-Type": "text/x-component" },
							},
						);
					}
					return new Response("<html><body>Dashboard</body></html>", {
						status: 200,
						headers: { "Content-Type": "text/html" },
					});
				}

				if (pathname === "/app/missing-rsc" && method === "GET") {
					// Next.js RSC Flight 404 兜底特征，应被 Soft-404 识别器过滤而不误报
					return new Response(`0:["$","div",null,"NEXT_NOT_FOUND"]\n`, {
						status: 200,
						headers: {
							"Content-Type": "text/x-component",
							"x-nextjs-matched-path": "/_not-found",
						},
					});
				}

				// 7. Race Probe 受控小并发幂等性测试端点
				if (pathname === "/api/concurrency/non-idempotent" && method === "GET") {
					activeInFlight++;
					if (activeInFlight > peakInFlight) peakInFlight = activeInFlight;
					try {
						await Bun.sleep(25);
						raceCouponCounter++;
						// 基线消耗第 1 次，并发突发中的首个请求消耗第 2 次返回 200，同批其余并发请求返回 409 产生状态分裂
						if (raceCouponCounter <= 2) {
							return Response.json({ claimState: "granted", slot: raceCouponCounter }, { status: 200 });
						}
						return Response.json({ claimState: "conflict_exhausted" }, { status: 409 });
					} finally {
						activeInFlight--;
					}
				}

				if (pathname === "/api/concurrency/idempotent" && method === "GET") {
					activeInFlight++;
					if (activeInFlight > peakInFlight) peakInFlight = activeInFlight;
					try {
						await Bun.sleep(25);
						return Response.json(
							{
								ok: true,
								status: "stable",
								requestId: crypto.randomUUID(),
								timestamp: new Date().toISOString(),
							},
							{ status: 200 },
						);
					} finally {
						activeInFlight--;
					}
				}

				// 默认未知路径返回 SPA Soft-404 HTML 外壳
				return new Response(SPA_SOFT_404_HTML, {
					status: 200,
					headers: { "Content-Type": "text/html; charset=utf-8" },
				});
		},
	});

	baseUrl = `http://127.0.0.1:${server.port}`;
});

afterAll(() => {
	server?.stop(true);
	for (const d of tempDirs) {
		rmSync(d, { recursive: true, force: true });
	}
});

/** 构造严格仅允许 127.0.0.1 且拉黑外部越界主机的 ScopePolicy */
function buildStrictTestScope(): ScopePolicy {
	return {
		...defaultScopeForTarget(baseUrl, "audit"),
		allowHosts: ["127.0.0.1"],
		denyHosts: ["evil.outside.invalid", "198.51.100.42"],
		allowLoopback: true,
		allowPrivateNetwork: false,
		allowSubdomains: false,
		allowDestructive: false,
	};
}

// ==================== 测试套件 ====================

describe("TrafficRecorder 脱敏持久化与多维只读检索", () => {
	test("空目录下 list / query / getById 零磁盘写副作用，写入后强制 0o600 权限与零明文泄露", () => {
		const root = makeTempDir("nuwa-traffic-rec-");

		// 预置 SessionVault 已知敏感凭据
		upsertSessionRole(root, {
			role: "auditor",
			bearer: `Bearer ${VALID_BEARER_ALICE}`,
			cookie: `sid=${VALID_SESSION_ID}; pref=1`,
			password: VAULT_MASTER_SECRET,
			username: "auditor_user",
			headers: {
				"X-API-Key": VALID_API_KEY,
			},
		});

		const recorder = new TrafficRecorder(root);
		// 只读操作不得创建 .nuwa/traffic 目录或 index.jsonl
		expect(recorder.list()).toEqual([]);
		expect(recorder.query({ host: "127.0.0.1" })).toEqual([]);
		expect(recorder.getById("nonexistent")).toBeNull();
		expect(existsSync(join(root, ".nuwa", "traffic"))).toBe(false);

		// 记录包含全方位敏感凭据的流量
		const inlineAuthTok = "x_auth_tok_secret_55667788";
		const urlSecretPass = "UrlPassSecret9911";
		const bodyPassword = "BodyPlainPassword_2026!";

		const entry1 = recorder.record({
			id: "tx_manual_001",
			method: "POST",
			url: `http://auditor_user:${urlSecretPass}@127.0.0.1:${server.port}/api/auth/login?access_token=${VALID_API_KEY}&page=2`,
			requestHeaders: {
				Authorization: `Bearer ${VALID_BEARER_ALICE}`,
				Cookie: `sid=${VALID_SESSION_ID}; theme=dark`,
				"X-API-Key": VALID_API_KEY,
				"X-Auth-Token": inlineAuthTok,
				"Content-Type": "application/json",
			},
			requestBody: JSON.stringify({
				username: "auditor_user",
				password: bodyPassword,
			}),
			status: 200,
			responseHeaders: {
				"Set-Cookie": `sid=${VALID_SESSION_ID}; Path=/; HttpOnly`,
				"Content-Type": "application/json",
			},
			responseBody: JSON.stringify({
				ok: true,
				leakedVaultSecretInBody: VAULT_MASTER_SECRET,
				jwtEcho: VALID_BEARER_ALICE,
			}),
			durationMs: 18,
			tags: ["auth", "login"],
			role: "auditor",
		});

		recorder.record({
			id: "tx_manual_002",
			method: "GET",
			url: `${baseUrl}/api/public/ping`,
			status: 200,
			responseBody: `{'token': 'single_quote_secret_999', 'ok': true}`,
			tags: ["health"],
		});

		// 校验文件权限严格为 0o600
		expect(existsSync(recorder.indexPath)).toBe(true);
		const modeBits = statSync(recorder.indexPath).mode & 0o777;
		expect(modeBits).toBe(0o600);

		// 读取原始 JSONL 文件文本，断言零明文密钥泄露
		const rawDiskContent = readFileSync(recorder.indexPath, "utf8");
		expect(rawDiskContent).not.toContain(VALID_SESSION_ID);
		expect(rawDiskContent).not.toContain(VALID_BEARER_ALICE);
		expect(rawDiskContent).not.toContain(VALID_API_KEY);
		expect(rawDiskContent).not.toContain(VAULT_MASTER_SECRET);
		expect(rawDiskContent).not.toContain(inlineAuthTok);
		expect(rawDiskContent).not.toContain(urlSecretPass);
		expect(rawDiskContent).not.toContain(bodyPassword);
		expect(rawDiskContent).not.toContain("single_quote_secret_999");

		// 非敏感查询参数与 Cookie 安全属性必须保留完好
		expect(entry1.url).toContain("page=2");
		expect(entry1.requestHeaders.Authorization).toBe(`Bearer ${REDACTED_MARKER}`);
		expect(entry1.requestHeaders["X-API-Key"]).toBe(REDACTED_MARKER);
		expect(entry1.requestHeaders["X-Auth-Token"]).toBe(REDACTED_MARKER);
		expect(entry1.responseHeaders["Set-Cookie"]).toContain(`sid=${REDACTED_MARKER}`);
		expect(entry1.responseHeaders["Set-Cookie"]).toContain("HttpOnly");

		// 验证 list / query / getById
		expect(recorder.list().length).toBe(2);
		expect(recorder.list(1).map((e) => e.id)).toEqual(["tx_manual_002"]);
		expect(recorder.list(0)).toEqual([]);
		expect(recorder.getById("tx_manual_001")?.path).toContain("/api/auth/login");
		expect(
			recorder.query({
				host: "127.0.0.1",
				pathPrefix: "/api/auth",
				method: "post",
				status: 200,
				tag: "login",
			}).length,
		).toBe(1);
		expect(recorder.query({ tag: "health", limit: 1 })[0]?.id).toBe("tx_manual_002");
	});
});

describe("replayTrafficSequence 多步状态续传与越界拦截", () => {
	test("完整串联登录 Set-Cookie + JSON/Header 变量提取与 {{var}} 替换，且落盘零明文", async () => {
		const root = makeTempDir("nuwa-replay-ok-");
		upsertSessionRole(root, {
			role: "alice",
			password: VAULT_MASTER_SECRET,
		});
		const recorder = new TrafficRecorder(root);
		const scope = buildStrictTestScope();

		const replayRes = await replayTrafficSequence(
			[
				{
					id: "login",
					method: "POST",
					url: `${baseUrl}/api/auth/login`,
					body: { username: "alice" },
					extract: {
						csrfToken: "data.csrfToken",
						stage: { header: "x-workflow-stage" },
					},
				},
				{
					id: "fetch_ticket",
					method: "GET",
					url: `${baseUrl}/api/workflow/ticket`,
					extract: {
						ticketId: { jsonPath: "ticketId" },
						stepNonce: "header:x-step-nonce",
					},
				},
				{
					id: "confirm_order",
					method: "POST",
					url: `${baseUrl}/api/workflow/confirm`,
					headers: {
						"X-CSRF-Token": "{{csrfToken}}",
						"X-Step-Nonce": "{{ stepNonce }}",
					},
					body: {
						ticketId: "{{ticketId}}",
					},
				},
			],
			scope,
			{ recorder, timeoutMs: 5000 },
		);

		expect(replayRes.ok).toBe(true);
		expect(replayRes.abortedByScope).toBe(false);
		expect(replayRes.steps.length).toBe(3);
		expect(replayRes.variables.csrfToken).toBe(VALID_CSRF_TOKEN);
		expect(replayRes.variables.stage).toBe("authenticated");
		expect(replayRes.variables.ticketId).toBe("tkt_8848");
		expect(replayRes.cookies.sid).toBe(VALID_SESSION_ID);
		expect(JSON.parse(replayRes.steps[2]!.responseBody)).toEqual({
			confirmed: true,
			reference: "ORD-2026-OK",
		});

		// 验证重放过程自动记录至 index.jsonl 且动态提取的 csrfToken 与 Cookie 均已脱敏
		const diskRaw = readFileSync(recorder.indexPath, "utf8");
		expect(diskRaw).not.toContain(VALID_SESSION_ID);
		expect(diskRaw).not.toContain(VALID_CSRF_TOKEN);
		expect(diskRaw).not.toContain(VAULT_MASTER_SECRET);
	});

	test("强拦截越界请求、越界 30x 重定向（零外连触发），支持授权内 302 跟随与单步超时控制", async () => {
		const scope = buildStrictTestScope();
		outsideHitCount = 0;

		// 1. 直接访问越界主机 -> 零发包阻断
		const directBlock = await replayTrafficSequence(
			[{ id: "out_direct", method: "GET", url: "http://evil.outside.invalid/secret" }],
			scope,
		);
		expect(directBlock.ok).toBe(false);
		expect(directBlock.abortedByScope).toBe(true);
		expect(directBlock.steps[0]?.blocked).toBe(true);
		expect(directBlock.steps[0]?.blockReason).toContain("N-007");

		// 2. 服务端返回 302 跳转到 Scope 外的越界目标 -> 必须拦截且绝不向越界目标发起 fetch
		const spyFetch: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
			const targetStr = String(input);
			if (targetStr.includes("evil.outside.invalid")) {
				outsideHitCount++;
			}
			return fetch(targetStr, init);
		}) as typeof fetch;

		const redirBlock = await replayTrafficSequence(
			[{ id: "out_redir", method: "GET", url: `${baseUrl}/api/redirect-outside` }],
			scope,
			{ fetchFn: spyFetch },
		);
		expect(redirBlock.ok).toBe(false);
		expect(redirBlock.abortedByScope).toBe(true);
		expect(redirBlock.steps[0]?.blocked).toBe(true);
		expect(redirBlock.steps[0]?.redirectBlocked).toBe(true);
		expect(outsideHitCount).toBe(0);

		// 3. 授权 Scope 内的同源 302 重定向正常跟随至 /api/public/ping
		const redirAllowed = await replayTrafficSequence(
			[{ id: "in_redir", method: "GET", url: `${baseUrl}/api/redirect-inside` }],
			scope,
		);
		expect(redirAllowed.ok).toBe(true);
		expect(redirAllowed.steps[0]?.status).toBe(200);
		expect(redirAllowed.steps[0]?.redirectChain.length).toBe(1);

		// 4. 单步超时保护
		const timeoutRes = await replayTrafficSequence(
			[{ id: "slow_step", method: "GET", url: `${baseUrl}/api/slow`, timeoutMs: 60 }],
			scope,
		);
		expect(timeoutRes.ok).toBe(false);
		expect(timeoutRes.steps[0]?.timedOut).toBe(true);
	});
});

describe("runStructuredMutations 五类只读契约差分、Soft-404 去噪与并发硬上限", () => {
	test("准确检出五类契约异常并在已加固/Soft-404 端点上保持零误报，严格遵守并发 <= 8", async () => {
		const scope = buildStrictTestScope();

		// 1. idor_step：缺陷端点检出 vs 加固端点不误报 vs Soft-404 自动去噪
		const idorVuln = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/api/orders/101`,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{ modes: ["idor_step"] },
		);
		expect(idorVuln.results.idor_step.anomalous).toBe(true);
		expect(idorVuln.anomalies[0]?.findingCode).toBe("idor_boundary_bypass");

		const idorSafe = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/api/secure-orders/101`,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{ modes: ["idor_step"] },
		);
		expect(idorSafe.results.idor_step.anomalous).toBe(false);

		const idorSoft404 = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/api/spa-items/10`,
			},
			scope,
			{ modes: ["idor_step"] },
		);
		expect(idorSoft404.results.idor_step.anomalous).toBe(false);
		expect(idorSoft404.results.idor_step.suppressedBySoft404).toBe(true);

		// 2. auth_strip：缺鉴权接口检出 vs 严格鉴权接口零误报
		const authVuln = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/api/admin/export`,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{ modes: ["auth_strip"] },
		);
		expect(authVuln.results.auth_strip.anomalous).toBe(true);

		const authSafe = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/api/admin/secure-audit`,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{ modes: ["auth_strip"] },
		);
		expect(authSafe.results.auth_strip.anomalous).toBe(false);

		// 3. graphql_introspect：暴露 Schema 检出 vs 禁用内省零误报
		const gqlExposed = await runStructuredMutations(
			{ method: "GET", url: `${baseUrl}/api/public/ping` },
			scope,
			{ modes: ["graphql_introspect"], graphqlPath: "/graphql" },
		);
		expect(gqlExposed.results.graphql_introspect.anomalous).toBe(true);
		expect(gqlExposed.results.graphql_introspect.evidence.exposedTypeCount).toBe(3);

		const gqlLocked = await runStructuredMutations(
			{ method: "GET", url: `${baseUrl}/api/public/ping` },
			scope,
			{ modes: ["graphql_introspect"], graphqlPath: "/graphql-locked" },
		);
		expect(gqlLocked.results.graphql_introspect.anomalous).toBe(false);

		// 4. nextjs_rsc：中间件漏拦 RSC 检出 vs NEXT_NOT_FOUND Soft-404 去噪
		const rscInconsistent = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/app/dashboard`,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{ modes: ["nextjs_rsc"] },
		);
		expect(rscInconsistent.results.nextjs_rsc.anomalous).toBe(true);

		const rscSoft404 = await runStructuredMutations(
			{ method: "GET", url: `${baseUrl}/app/missing-rsc` },
			scope,
			{ modes: ["nextjs_rsc"] },
		);
		expect(rscSoft404.results.nextjs_rsc.anomalous).toBe(false);
		expect(rscSoft404.results.nextjs_rsc.suppressedBySoft404).toBe(true);

		// 5. race_probe + 并发度硬上限 <= 8（传入超大值 99 与 Infinity 均钳制为 8）
		peakInFlight = 0;
		raceCouponCounter = 0;
		const raceDrift = await runStructuredMutations(
			{ method: "GET", url: `${baseUrl}/api/concurrency/non-idempotent` },
			scope,
			{ modes: ["race_probe"], concurrency: 99, raceCount: 50 },
		);
		expect(raceDrift.effectiveConcurrency).toBe(MAX_MUTATION_CONCURRENCY);
		expect(peakInFlight).toBeLessThanOrEqual(MAX_MUTATION_CONCURRENCY);
		expect(raceDrift.results.race_probe.anomalous).toBe(true);
		expect(raceDrift.results.race_probe.probes.length).toBe(MAX_MUTATION_CONCURRENCY);

		peakInFlight = 0;
		const raceStable = await runStructuredMutations(
			{ method: "GET", url: `${baseUrl}/api/concurrency/idempotent` },
			scope,
			{ modes: ["race_probe"], concurrency: Number.POSITIVE_INFINITY, raceCount: 6 },
		);
		expect(raceStable.effectiveConcurrency).toBe(MAX_MUTATION_CONCURRENCY);
		expect(peakInFlight).toBeLessThanOrEqual(MAX_MUTATION_CONCURRENCY);
		expect(raceStable.results.race_probe.anomalous).toBe(false);

		// NaN 并发参数安全回退且越界基线直接硬拦截
		const blockedMut = await runStructuredMutations(
			{ method: "GET", url: "http://evil.outside.invalid/api/orders/1" },
			scope,
			{ concurrency: Number.NaN },
		);
		expect(blockedMut.ok).toBe(false);
		expect(blockedMut.blockedByScope).toBe(true);
		expect(blockedMut.effectiveConcurrency).toBe(4);
	});
});

describe("hybrid-audit 多语言静态路由审计、SourceMap 解析与白盒⇄黑盒双向桥接", () => {
	test("递归提取 TS/Next.js/Python/Go 路由与鉴权状态、四类风险代码模式，并跳过 node_modules/dist/.git", async () => {
		const repoDir = makeTempDir("nuwa-hybrid-src-");

		// 1. Express + Fastify (TS)
		mkdirSync(join(repoDir, "src", "routes"), { recursive: true });
		writeFileSync(
			join(repoDir, "src", "routes", "orders.ts"),
			[
				`import express from "express";`,
				`const router = express.Router();`,
				`app.use("/api", router);`,
				`router.get("/orders/:orderId", rateLimiter(), requireAuth(), async (req, res) => {`,
				`  const sql = \`SELECT * FROM orders WHERE id = \${req.params.orderId}\`;`,
				`  await db.query(sql);`,
				`  res.json({ ok: true });`,
				`});`,
				`router.get("/admin/export", async (req, res) => {`,
				`  const raw = await db.query(\`SELECT * FROM users WHERE dept = '\${req.query.dept}'\`);`,
				`  res.json(raw);`,
				`});`,
				`fastify.post("/internal/webhook", { preHandler: [verifyJwt] }, async (req, reply) => {`,
				`  const resp = await fetch(req.body.callbackUrl);`,
				`  return resp.status;`,
				`});`,
			].join("\n"),
			"utf8",
		);

		// 2. Next.js App Router（带路由组 `(dashboard)`）
		mkdirSync(join(repoDir, "src", "app", "(dashboard)", "api", "reports"), { recursive: true });
		writeFileSync(
			join(repoDir, "src", "app", "(dashboard)", "api", "reports", "route.ts"),
			[
				`import { readFileSync } from "node:fs";`,
				`export async function GET(req: Request) {`,
				`  const file = readFileSync(\`/var/reports/\${req.url}\`);`,
				`  return new Response(file);`,
				`}`,
				`export async function POST(req: Request) {`,
				`  const session = await getServerSession();`,
				`  if (!session) return new Response("Unauthorized", { status: 401 });`,
				`  return Response.json({ created: true });`,
				`}`,
			].join("\n"),
			"utf8",
		);

		// 3. Python (FastAPI + Flask + Django)
		mkdirSync(join(repoDir, "py_service"), { recursive: true });
		writeFileSync(
			join(repoDir, "py_service", "api.py"),
			[
				`from fastapi import APIRouter, Depends`,
				`import subprocess`,
				`router = APIRouter(prefix="/v1")`,
				`@router.get("/items/{item_id}")`,
				`def read_item(item_id: str):`,
				`    subprocess.run(f"echo {item_id}", shell=True)`,
				`    return {"id": item_id}`,
				`@router.post("/items/protected")`,
				`def write_item(user = Depends(get_current_user)):`,
				`    return {"ok": True}`,
				`urlpatterns = [`,
				`    path("django/users/<int:pk>/", views.user_detail),`,
				`    path("django/billing/", login_required(views.billing_view)),`,
				`]`,
			].join("\n"),
			"utf8",
		);

		// 4. Go (Gin + net/http)
		mkdirSync(join(repoDir, "go_service"), { recursive: true });
		writeFileSync(
			join(repoDir, "go_service", "main.go"),
			[
				`package main`,
				`func register(r *gin.Engine) {`,
				`  authed := r.Group("/api/v2", JWTAuthMiddleware())`,
				`  authed.GET("/profile", getProfileHandler)`,
				`  r.GET("/debug/vars", dumpVarsHandler)`,
				`  http.HandleFunc("POST /ops/diag", func(w http.ResponseWriter, req *http.Request) {`,
				`    exec.Command("sh", "-c", req.URL.Query().Get("cmd"))`,
				`  })`,
				`}`,
			].join("\n"),
			"utf8",
		);

		// 5. 应被忽略的目录（node_modules / dist / .git）
		mkdirSync(join(repoDir, "node_modules", "pkg"), { recursive: true });
		mkdirSync(join(repoDir, "dist"), { recursive: true });
		mkdirSync(join(repoDir, ".git", "hooks"), { recursive: true });
		writeFileSync(
			join(repoDir, "node_modules", "pkg", "index.js"),
			`app.get("/should-ignore-node-modules", handler);`,
			"utf8",
		);
		writeFileSync(
			join(repoDir, "dist", "bundle.js"),
			`app.get("/should-ignore-dist", handler);`,
			"utf8",
		);

		const surface = extractCodeAttackSurface(repoDir);

		// 验证忽略目录完全未混入
		expect(surface.routes.some((r) => r.path.includes("should-ignore"))).toBe(false);

		// 验证各语言路由提取与鉴权判定准确
		const findRoute = (method: string, path: string) =>
			surface.routes.find((r) => r.method === method && r.path === path);

		const expAuthed = findRoute("GET", "/api/orders/:orderId");
		expect(expAuthed?.framework).toBe("express");
		expect(expAuthed?.hasAuthMiddleware).toBe(true);
		expect(expAuthed?.line).toBe(4);

		const expUnauthed = findRoute("GET", "/api/admin/export");
		expect(expUnauthed?.hasAuthMiddleware).toBe(false);
		expect(expUnauthed?.riskFlags).toContain("missing_auth_middleware");
		expect(expUnauthed?.riskFlags).toContain("unparameterized_sql");

		const nextGet = findRoute("GET", "/api/reports");
		const nextPost = findRoute("POST", "/api/reports");
		expect(nextGet?.framework).toBe("nextjs");
		expect(nextGet?.hasAuthMiddleware).toBe(false);
		expect(nextPost?.hasAuthMiddleware).toBe(true);

		const fastApiOpen = findRoute("GET", "/v1/items/{item_id}");
		const fastApiProtected = findRoute("POST", "/v1/items/protected");
		expect(fastApiOpen?.framework).toBe("fastapi");
		expect(fastApiOpen?.hasAuthMiddleware).toBe(false);
		expect(fastApiProtected?.hasAuthMiddleware).toBe(true);

		const djOpen = findRoute("ALL", "/django/users/<int:pk>/");
		const djAuthed = findRoute("ALL", "/django/billing/");
		expect(djOpen?.framework).toBe("django");
		expect(djOpen?.hasAuthMiddleware).toBe(false);
		expect(djAuthed?.hasAuthMiddleware).toBe(true);

		const ginAuthed = findRoute("GET", "/api/v2/profile");
		const ginOpen = findRoute("GET", "/debug/vars");
		const goStd = findRoute("POST", "/ops/diag");
		expect(ginAuthed?.hasAuthMiddleware).toBe(true);
		expect(ginOpen?.hasAuthMiddleware).toBe(false);
		expect(goStd?.framework).toBe("net/http");
		expect(goStd?.hasAuthMiddleware).toBe(false);

		// 验证四类静态风险模式全部被准确捕获
		const warningKinds = new Set(surface.warnings.map((w) => w.kind));
		expect(warningKinds.has("unparameterized_sql")).toBe(true);
		expect(warningKinds.has("dynamic_outbound_url")).toBe(true);
		expect(warningKinds.has("unchecked_path_join")).toBe(true);
		expect(warningKinds.has("dangerous_exec_call")).toBe(true);

		// 验证白盒 -> 黑盒意图桥接 + 动态核验 -> 源码行号反向定位闭环
		const bridged = bridgeWhiteboxToBlackboxIntents(surface, baseUrl);
		expect(bridged.intents.length).toBeGreaterThanOrEqual(6);
		expect(bridged.hypotheses.length).toBe(bridged.intents.length);

		const exportIntent = bridged.intents.find(
			(i) => i.path === "/api/admin/export" && i.riskCategory === "missing_auth_middleware",
		);
		expect(exportIntent).toBeDefined();
		expect(exportIntent?.anchor).toBe("src/routes/orders.ts:9");

		// 用桥接出的 URL 交给 runStructuredMutations 在真实本地服务上验证，再反向关联回源码行号
		const scope = buildStrictTestScope();
		const dynRes = await runStructuredMutations(
			{
				method: exportIntent!.method,
				url: exportIntent!.url,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{ modes: ["auth_strip"] },
		);
		expect(dynRes.anomalies.length).toBe(1);

		const corrExact = correlateBlackboxFindingToSource(dynRes.anomalies[0]!, surface);
		expect(corrExact.matched).toBe(true);
		expect(corrExact.confidence).toBe("exact");
		expect(corrExact.file).toBe("src/routes/orders.ts");
		expect(corrExact.line).toBe(9);
		expect(corrExact.relatedWarnings.some((w) => w.kind === "unparameterized_sql")).toBe(true);

		// 验证参数化路径（Express `:orderId`、FastAPI `{item_id}`、Django `<int:pk>`）的反向定位
		const corrParamExpress = correlateBlackboxFindingToSource(
			{ method: "GET", url: `${baseUrl}/api/orders/102` },
			surface,
		);
		expect(corrParamExpress.matched).toBe(true);
		expect(corrParamExpress.confidence).toBe("route_param");
		expect(corrParamExpress.anchor).toBe("src/routes/orders.ts:4");

		const corrParamFastApi = correlateBlackboxFindingToSource(
			{ method: "GET", path: "/v1/items/abc-99" },
			surface,
		);
		expect(corrParamFastApi.matched).toBe(true);
		expect(corrParamFastApi.anchor).toBe("py_service/api.py:4");

		const corrParamDjango = correlateBlackboxFindingToSource(
			{ method: "GET", path: "/django/users/42" },
			surface,
		);
		expect(corrParamDjango.matched).toBe(true);
		expect(corrParamDjango.file).toBe("py_service/api.py");
	});

	test("extractFromSourceMap 安全解析 .js.map（过滤 node_modules 并清洗防穿越路径）", () => {
		const rawMap = JSON.stringify({
			version: 3,
			file: "app.bundle.js",
			sources: [
				"webpack://admin-portal/./node_modules/react/index.js",
				"webpack://admin-portal/../../../src/internal/debug-routes.ts",
				"webpack://admin-portal/./src/client/api-client.ts",
			],
			sourcesContent: [
				`app.get("/react-internal-ignore", fn);`,
				[
					`import KoaRouter from "@koa/router";`,
					`const router = new KoaRouter({ prefix: "/internal" });`,
					`router.post("/sync-cache", async (ctx) => {`,
					`  ctx.body = { synced: true };`,
					`});`,
				].join("\n"),
				[
					`export async function triggerExport() {`,
					`  return fetch("/api/admin/export", { method: "GET" });`,
					`}`,
				].join("\n"),
			],
		});

		const mapSurface = extractFromSourceMap(rawMap, `${baseUrl}/static/app.bundle.js.map`);
		expect(mapSurface.sourceMapsParsed).toBe(1);
		expect(mapSurface.routes.some((r) => r.path.includes("react-internal-ignore"))).toBe(false);

		// 验证防穿越清洗后路径不含 `..`
		const koaRoute = mapSurface.routes.find((r) => r.path === "/internal/sync-cache");
		expect(koaRoute).toBeDefined();
		expect(koaRoute?.framework).toBe("koa");
		expect(koaRoute?.file).toBe("src/internal/debug-routes.ts");
		expect(koaRoute?.line).toBe(3);
		expect(koaRoute?.hasAuthMiddleware).toBe(false);

		// 客户端未带鉴权头的内部 API 调用线索也被提取供协同验证
		const clientHint = mapSurface.routes.find((r) => r.path === "/api/admin/export");
		expect(clientHint).toBeDefined();
		expect(clientHint?.framework).toBe("sourcemap-client");

		// 非法 JSON 输入容错不抛异常
		const broken = extractFromSourceMap("{not-valid-json");
		expect(broken.routes).toEqual([]);

		// 内存源码映射 Record<string, string> 输入 + 注释假路由过滤 + 去重桥接验证
		const memSurface = extractCodeAttackSurface({
			"backend/echo_server.go": [
				`package backend`,
				`/*`,
				` * e.GET("/commented/block-route", fakeHandler)`,
				` */`,
				`// e.POST("/commented/line-route", fakeHandler)`,
				`func mount(e *echo.Echo) {`,
				`  adm := e.Group("/admin")`,
				`  adm.Use(RequireAdminAuth())`,
				`  adm.DELETE("/users/:id", deleteUser)`,
				`  e.GET("/internal/metrics", dumpMetrics)`,
				`}`,
			].join("\n"),
			"backend/flask_app.py": [
				`from flask import Blueprint`,
				`# @bp.get("/commented-py-route")`,
				`bp = Blueprint("api", __name__, url_prefix="/flask")`,
				`@bp.route("/open-report", methods=["GET", "POST"])`,
				`def open_report():`,
				`    return "ok"`,
			].join("\n"),
		});

		expect(memSurface.routes.some((r) => r.path.includes("commented"))).toBe(false);
		expect(memSurface.routes.find((r) => r.path === "/admin/users/:id")?.hasAuthMiddleware).toBe(true);
		expect(memSurface.routes.find((r) => r.path === "/admin/users/:id")?.line).toBe(9);
		expect(memSurface.routes.find((r) => r.path === "/internal/metrics")?.hasAuthMiddleware).toBe(false);
		expect(memSurface.routes.filter((r) => r.path === "/flask/open-report").length).toBe(2);

		const memBridge = bridgeWhiteboxToBlackboxIntents(memSurface, baseUrl);
		expect(memBridge.intents.some((i) => i.path === "/admin/users/:id")).toBe(false);
		expect(memBridge.intents.filter((i) => i.path === "/flask/open-report").length).toBe(2);
	});
});

describe("Boost 异构审查边界回归验证（#28 全部 P1/P2 反例）", () => {
	test("P1-1: 跨 Origin 302 重定向自动剥离敏感认证头，且 Cookie Jar 严格执行 RFC 6265 Host-Only 与 Domain 边界", async () => {
		const capturedRequests: Array<{ url: string; headers: Record<string, string> }> = [];
		const multiHostScope: ScopePolicy = {
			allowHosts: ["app.internal.test", "cdn.internal.test", "example.test", "sub.example.test", "other.test"],
			allowCidrs: [],
			denyHosts: [],
			allowSubdomains: true,
			allowPrivateNetwork: false,
			allowDestructive: false,
			allowLoopback: true,
		};

		const mockFetch = async (
			url: string,
			init?: { method?: string; headers?: Record<string, string> },
		) => {
			const hdrs = { ...(init?.headers ?? {}) };
			capturedRequests.push({ url, headers: hdrs });
			const u = new URL(url);

			// 场景 A：app.internal.test 302 跨 Origin 跳转至 cdn.internal.test
			if (u.hostname === "app.internal.test" && u.pathname === "/download") {
				return {
					status: 302,
					headers: { location: "http://cdn.internal.test/asset.json" },
					text: async () => "",
				};
			}
			if (u.hostname === "cdn.internal.test") {
				return {
					status: 200,
					headers: { "content-type": "application/json" },
					text: async () => JSON.stringify({ asset: "ok" }),
				};
			}

			// 场景 B：example.test 同时下发 Host-Only Cookie、合法 Domain Cookie、伪造跨站 Domain Cookie 与单段 TLD Cookie
			if (u.hostname === "example.test" && u.pathname === "/set-cookies") {
				return {
					status: 200,
					headers: {
						"set-cookie": [
							"host_only_sid=ho_secret_111; Path=/; HttpOnly",
							"shared_org=org_val_222; Domain=example.test; Path=/",
							"forged_other=evil_333; Domain=other.test; Path=/",
							"tld_wide=bad_444; Domain=test; Path=/",
						],
					},
					text: async () => "ok",
				};
			}

			return {
				status: 200,
				headers: {},
				text: async () => "ok",
			};
		};

		const crossOriginRes = await replayTrafficSequence(
			[
				{
					id: "cross_origin_hop",
					method: "GET",
					url: "http://app.internal.test/download",
					headers: {
						Authorization: "Bearer SecretCrossOriginJwt",
						"X-API-Key": "SecretCrossOriginApiKey",
						Accept: "application/json",
					},
				},
			],
			multiHostScope,
			{ fetchFn: mockFetch },
		);

		expect(crossOriginRes.ok).toBe(true);
		expect(capturedRequests.length).toBe(2);
		expect(capturedRequests[0]?.headers.Authorization).toBe("Bearer SecretCrossOriginJwt");
		// 跳转到 cdn.internal.test 时敏感头必须被完全剥离，非敏感头保留
		expect(capturedRequests[1]?.url).toBe("http://cdn.internal.test/asset.json");
		expect(capturedRequests[1]?.headers.Authorization).toBeUndefined();
		expect(capturedRequests[1]?.headers["X-API-Key"]).toBeUndefined();
		expect(capturedRequests[1]?.headers.Accept).toBe("application/json");

		capturedRequests.length = 0;
		const cookieRes = await replayTrafficSequence(
			[
				{ id: "s1", method: "GET", url: "http://example.test/set-cookies" },
				{ id: "s2_exact", method: "GET", url: "http://example.test/dashboard" },
				{ id: "s3_sub", method: "GET", url: "http://sub.example.test/dashboard" },
				{ id: "s4_other", method: "GET", url: "http://other.test/dashboard" },
			],
			multiHostScope,
			{ fetchFn: mockFetch },
		);

		expect(cookieRes.ok).toBe(true);
		// example.test 收到 Host-Only + Domain=example.test
		expect(capturedRequests[1]?.headers.Cookie).toContain("host_only_sid=ho_secret_111");
		expect(capturedRequests[1]?.headers.Cookie).toContain("shared_org=org_val_222");
		// sub.example.test 仅收到显式 Domain=example.test，绝不能收到 Host-Only Cookie
		expect(capturedRequests[2]?.headers.Cookie).toBe("shared_org=org_val_222");
		expect(capturedRequests[2]?.headers.Cookie).not.toContain("host_only_sid");
		// other.test 绝不接收被丢弃的伪造 Domain=other.test 或单段 Domain=test Cookie
		expect(capturedRequests[3]?.headers.Cookie).toBeUndefined();
	});

	test("P1-2 & P1-3 & P2: idor_step 相同 bodyHash 零误报，底层信号量并发严格不超限且兼容 concurrency=1", async () => {
		const scope = buildStrictTestScope();
		let concurrentNow = 0;
		let concurrentMax = 0;

		const mockFetch = async (url: string) => {
			concurrentNow++;
			if (concurrentNow > concurrentMax) concurrentMax = concurrentNow;
			// 通过多次微任务挂起与极短延迟放大潜在抢占窗口
			await Promise.resolve();
			await Bun.sleep(10);
			await Promise.resolve();
			concurrentNow--;

			const u = new URL(url);
			if (u.pathname.startsWith("/__nuwa_soft404_probe_")) {
				return { status: 404, headers: {}, text: async () => "not found" };
			}
			// 对任意路径 ID 始终返回当前登录用户自己的同一份数据（相同 bodyHash）
			return {
				status: 200,
				headers: { "content-type": "application/json" },
				text: async () => JSON.stringify({ currentUser: "alice", fixedOrderId: 101 }),
			};
		};

		const sameHashRes = await runStructuredMutations(
			{
				method: "GET",
				url: `${baseUrl}/api/self-bound-orders/101`,
				headers: { Authorization: `Bearer ${VALID_BEARER_ALICE}` },
			},
			scope,
			{
				modes: ["idor_step"],
				idorCandidateIds: [102, 103, 104],
				concurrency: 2,
				fetchFn: mockFetch,
			},
		);

		// 相同 bodyHash 严禁误报 IDOR，且 concurrency=2 下峰值严格 <= 2
		expect(sameHashRes.results.idor_step.anomalous).toBe(false);
		expect(sameHashRes.anomalies).toEqual([]);
		expect(concurrentMax).toBeLessThanOrEqual(2);

		// P2: concurrency=1 时运行 race_probe 不得发生 min/max 区间倒置，峰值严格为 1
		concurrentMax = 0;
		const singleConcRace = await runStructuredMutations(
			{ method: "GET", url: `${baseUrl}/api/self-bound-orders/101` },
			scope,
			{
				modes: ["race_probe"],
				concurrency: 1,
				raceCount: 5,
				fetchFn: mockFetch,
			},
		);
		expect(singleConcRace.effectiveConcurrency).toBe(1);
		expect(singleConcRace.results.race_probe.probes.length).toBe(1);
		expect(concurrentMax).toBe(1);
	});

	test("P1-4: URL Fragment (#access_token=...) 脱敏、回退正文凭据字段补全与响应头/查询参数回显脱敏", () => {
		const fragUrl = "http://127.0.0.1:8080/oauth/cb#access_token=SuperSecretOAuth999&state=xyz123";
		const safeFrag = redactTrafficUrl(fragUrl);
		expect(safeFrag).not.toContain("SuperSecretOAuth999");
		expect(safeFrag).toContain(`access_token=${REDACTED_MARKER}`);
		expect(safeFrag).toContain("state=xyz123");

		// 非严格 JSON 片段中的 csrf_token / xsrf_token / session_id / private_token
		const brokenJsonBody = `{"csrf_token": "csrf_frag_112233", 'private_token': 'glpat_secret_445566', "session_id": "sess_778899", invalid_tail`;
		const safeBroken = redactTrafficBody(brokenJsonBody) ?? "";
		expect(safeBroken).not.toContain("csrf_frag_112233");
		expect(safeBroken).not.toContain("glpat_secret_445566");
		expect(safeBroken).not.toContain("sess_778899");

		// TrafficRecorder 收集敏感查询参数值与非 Set-Cookie 敏感响应头值，防止在响应体中回显泄露
		const root = makeTempDir("nuwa-frag-echo-");
		const recorder = new TrafficRecorder(root);
		const queryApiKey = "QueryKeyEchoSecret_8877";
		const respHeaderToken = "RespHeaderTokenSecret_6655";

		recorder.record({
			method: "GET",
			url: `${baseUrl}/api/echo?api_key=${queryApiKey}#id_token=FragIdTokSecret_3344`,
			status: 200,
			responseHeaders: {
				"X-Auth-Token": respHeaderToken,
				"Content-Type": "text/plain",
			},
			responseBody: `echoed query=${queryApiKey}, respHdr=${respHeaderToken}, frag=FragIdTokSecret_3344`,
		});

		const rawJsonl = readFileSync(recorder.indexPath, "utf8");
		expect(rawJsonl).not.toContain(queryApiKey);
		expect(rawJsonl).not.toContain(respHeaderToken);
		expect(rawJsonl).not.toContain("FragIdTokSecret_3344");
	});

	test("P1-5 & P2: Python 装饰器防串扰、JS 正则单引号/Go 原始串反斜杠词法健壮性、Express 带中间件挂载与女娲 targetKey 兼容", () => {
		const surface = extractCodeAttackSurface({
			"py/views.py": [
				`from flask import Flask`,
				`app = Flask(__name__)`,
				`@login_required`,
				`@app.get("/protected_before")`,
				`def protected_before():`,
				`    return "secret"`,
				``,
				`@app.get("/open_after_protected")`,
				`def open_after_protected():`,
				`    return "public_leak"`,
				`@login_required`,
				`@app.get("/protected_after")`,
				`def protected_after():`,
				`    return "secret2"`,
			].join("\n"),
			"ts/admin_mount.ts": [
				`import express from "express";`,
				`const qRe = /'/;`,
				`// app.get("/commented-after-regex", fakeHandler);`,
				`const adminRouter = express.Router();`,
				`app.use("/api/admin", rateLimit(10), requireAuth(), adminRouter);`,
				`adminRouter.get("/users", listUsers);`,
			].join("\n"),
			"go/raw_backtick.go": [
				`package main`,
				"const winTrail = `c:\\`",
				`// r.GET("/commented-in-go", fakeGoHandler)`,
				`func setup(r *gin.Engine) {`,
				`  r.GET("/real-go-open", realGoHandler)`,
				`}`,
			].join("\n"),
		});

		// 1. Python 相邻装饰器绝不串扰中间无鉴权路由
		expect(surface.routes.find((r) => r.path === "/protected_before")?.hasAuthMiddleware).toBe(true);
		expect(surface.routes.find((r) => r.path === "/open_after_protected")?.hasAuthMiddleware).toBe(false);
		expect(surface.routes.find((r) => r.path === "/protected_after")?.hasAuthMiddleware).toBe(true);

		// 2. JS 正则单引号与 Go 原始串尾随反斜杠后，单行注释内的假路由均不得被误提取
		expect(surface.routes.some((r) => r.path.includes("commented-after-regex"))).toBe(false);
		expect(surface.routes.some((r) => r.path.includes("commented-in-go"))).toBe(false);
		expect(surface.routes.find((r) => r.path === "/real-go-open")?.line).toBe(5);

		// 3. Express app.use("/api/admin", ..., requireAuth(), adminRouter) 保留完整前缀并继承挂载鉴权
		const mountedAdminUsers = surface.routes.find((r) => r.path === "/api/admin/users");
		expect(mountedAdminUsers).toBeDefined();
		expect(mountedAdminUsers?.hasAuthMiddleware).toBe(true);

		// 4. P2: correlateBlackboxFindingToSource 兼容女娲标准 Fact.targetKey 前缀 "path:..." / "endpoint:..."
		const corrNuwaTargetKey = correlateBlackboxFindingToSource(
			{
				kind: "vuln",
				title: "未授权接口暴露",
				targetKey: "path:/open_after_protected",
			},
			surface,
		);
		expect(corrNuwaTargetKey.matched).toBe(true);
		expect(corrNuwaTargetKey.file).toBe("py/views.py");
		expect(corrNuwaTargetKey.line).toBe(8);

		const corrEndpointPrefix = correlateBlackboxFindingToSource(
			{
				targetKey: "endpoint:GET /api/admin/users",
			},
			surface,
		);
		expect(corrEndpointPrefix.matched).toBe(true);
		expect(corrEndpointPrefix.anchor).toBe("ts/admin_mount.ts:6");
	});
});
