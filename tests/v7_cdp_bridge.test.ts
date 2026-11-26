import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	captureCdpSessionTraffic,
	CdpClient,
	closeCdpSession,
	executeInPageSignedProbe,
	findLiveProcessesByTag,
	launchCdpSession,
	resolveChromeExecutable,
	runCdpSignedAuthDiff,
	type CdpTransportLike,
} from "../omp/cdp-bridge";
import { defaultScopeForTarget } from "../omp/scope";
import { loadSessionVault, upsertSessionRole } from "../omp/session-vault";
import { TrafficRecorder } from "../omp/traffic-workbench";

// ==================== 测试微靶机常量定义 ====================

const HMAC_SHARED_KEY = "nuwa_v7_test_hmac_signing_key_2026";
const ALICE_PASSWORD = "Alice_Plain_Password_9981!";
const ALICE_SESSION_COOKIE = "sess_alice_secret_cookie_778899";
const ALICE_BEARER_TOKEN = "jwt_alice_secret_bearer_token_556677";
const ALICE_CSRF_TOKEN = "csrf_alice_secret_token_334455";

const BOB_SESSION_COOKIE = "sess_bob_secret_cookie_112233";
const BOB_BEARER_TOKEN = "jwt_bob_secret_bearer_token_445566";

function computeServerHmac(method: string, pathWithQuery: string, ts: string, nonce: string): string {
	return createHmac("sha256", HMAC_SHARED_KEY)
		.update(`${method.toUpperCase()}:${pathWithQuery}:${ts}:${nonce}`)
		.digest("hex");
}

function parseCookieMap(cookieHeader: string | null): Record<string, string> {
	const map: Record<string, string> = {};
	if (!cookieHeader) return map;
	for (const part of cookieHeader.split(";")) {
		const eq = part.indexOf("=");
		if (eq > 0) {
			const k = part.slice(0, eq).trim();
			const v = part.slice(eq + 1).trim();
			if (k && v) map[k] = v;
		}
	}
	return map;
}

function resolveUserFromRequest(req: Request): "alice" | "bob" | null {
	const auth = (req.headers.get("authorization") ?? "").trim();
	const cookies = parseCookieMap(req.headers.get("cookie"));
	if (auth === `Bearer ${ALICE_BEARER_TOKEN}` || cookies.sid === ALICE_SESSION_COOKIE) {
		return "alice";
	}
	if (auth === `Bearer ${BOB_BEARER_TOKEN}` || cookies.sid === BOB_SESSION_COOKIE) {
		return "bob";
	}
	return null;
}

/**
 * 构建带纯前端 WebCrypto 动态 HMAC-SHA256 签名器与越界外链探针的测试前端页面。
 */
function buildTargetAppHtml(oobBaseUrl: string): string {
	return `<!doctype html>
<html lang="zh-CN">
<head>
	<meta charset="utf-8" />
	<title>Order Console</title>
	<script src="${oobBaseUrl}/third-party-tracker.js" async></script>
</head>
<body>
	<div id="app">Order Management Portal</div>
	<script>
		const SIGN_KEY_TEXT = ${JSON.stringify(HMAC_SHARED_KEY)};
		const LOGIN_PASSWORD = ${JSON.stringify(ALICE_PASSWORD)};
		const OOB_URL = ${JSON.stringify(`${oobBaseUrl}/beacon-exfil`)};

		async function hmacSha256Hex(secret, message) {
			const enc = new TextEncoder();
			const cryptoKey = await crypto.subtle.importKey(
				"raw",
				enc.encode(secret),
				{ name: "HMAC", hash: "SHA-256" },
				false,
				["sign"]
			);
			const sigBuf = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
			return Array.from(new Uint8Array(sigBuf))
				.map((b) => b.toString(16).padStart(2, "0"))
				.join("");
		}

		// 前端原生动态请求签名钩子（每次生成全新时间戳与一次性随机 Nonce）
		window.__nuwaSign = async function ({ path, method }) {
			const m = String(method || "GET").toUpperCase();
			const ts = String(Date.now());
			const nonce = Math.random().toString(36).slice(2) + "_" + crypto.randomUUID();
			const sig = await hmacSha256Hex(SIGN_KEY_TEXT, m + ":" + path + ":" + ts + ":" + nonce);
			return {
				"x-timestamp": ts,
				"x-nonce": nonce,
				"x-signature": sig,
			};
		};

		(async () => {
			// 触发一个越界外部请求（应被 CDP Fetch.failRequest 阻断，零字节到达越界服务）
			fetch(OOB_URL).catch(() => {});

			// 执行同源登录并拉取首屏受保护订单数据
			const loginRes = await fetch("/api/auth/login", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ username: "alice", password: LOGIN_PASSWORD }),
			});
			const loginData = await loginRes.json();
			const sigHeaders = await window.__nuwaSign({ path: "/api/orders?id=1001", method: "GET" });
			await fetch("/api/orders?id=1001", {
				method: "GET",
				headers: Object.assign(
					{
						"authorization": "Bearer " + loginData.token,
						"x-csrf-token": loginData.csrfToken,
					},
					sigHeaders
				),
			});
			window.__bootCompleted = true;
		})();
	</script>
</body>
</html>`;
}

// ==================== 测试套件 ====================

describe("v7.0 原生 CDP 流量桥接与页面内加签契约差分", () => {
	let tempRoot = "";
	let targetServer: ReturnType<typeof Bun.serve>;
	let oobServer: ReturnType<typeof Bun.serve>;
	let targetOrigin = "";
	let oobOrigin = "";
	let oobHitCount = 0;
	let writeMethodHitCount = 0;
	const usedNonces = new Set<string>();

	beforeAll(() => {
		tempRoot = mkdtempSync(join(tmpdir(), "nuwa-v7-cdp-test-"));

		// 1. 启动越界第三方探针计数服务器（通过 localhost 访问，在 Scope 中被显式列为越界）
		oobServer = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				oobHitCount += 1;
				return new Response("console.log('oob');", {
					status: 200,
					headers: { "content-type": "application/javascript" },
				});
			},
		});
		oobOrigin = `http://localhost:${oobServer.port}`;

		// 2. 启动主测试微靶机（监听 127.0.0.1:0）
		targetServer = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(req: Request) {
				const url = new URL(req.url);
				const method = req.method.toUpperCase();
				const pathWithQuery = `${url.pathname}${url.search}`;

				if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS" && url.pathname !== "/api/auth/login") {
					writeMethodHitCount += 1;
					return Response.json({ error: "unexpected_write_method" }, { status: 405 });
				}

				// 首页应用挂载点
				if (url.pathname === "/app") {
					return new Response(buildTargetAppHtml(oobOrigin), {
						status: 200,
						headers: { "content-type": "text/html; charset=utf-8" },
					});
				}

				// 登录认证接口（下发 HttpOnly Cookie + Bearer Token + CSRF Token）
				if (url.pathname === "/api/auth/login" && method === "POST") {
					const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
					if (body.username === "alice" && body.password === ALICE_PASSWORD) {
						return new Response(
							JSON.stringify({
								ok: true,
								user: "alice",
								token: ALICE_BEARER_TOKEN,
								csrfToken: ALICE_CSRF_TOKEN,
							}),
							{
								status: 200,
								headers: {
									"content-type": "application/json",
									"set-cookie": `sid=${ALICE_SESSION_COOKIE}; Path=/; HttpOnly; SameSite=Lax`,
								},
							},
						);
					}
					return Response.json({ ok: false, error: "invalid_credentials" }, { status: 401 });
				}

				// 受动态时间戳 + Nonce + HMAC-SHA256 保护的订单接口
				if (url.pathname === "/api/orders" || url.pathname === "/api/orders-safe") {
					// 确保内部探针头绝未泄漏至靶机服务端
					if (req.headers.has("x-nuwa-cdp-probe-token")) {
						return Response.json({ error: "internal_probe_header_leaked" }, { status: 500 });
					}

					const ts = (req.headers.get("x-timestamp") ?? "").trim();
					const nonce = (req.headers.get("x-nonce") ?? "").trim();
					const sig = (req.headers.get("x-signature") ?? "").trim();
					const tsNum = Number(ts);
					if (!ts || !nonce || !sig || !Number.isFinite(tsNum) || Math.abs(Date.now() - tsNum) > 60_000) {
						return Response.json({ error: "missing_or_expired_signature" }, { status: 403 });
					}
					if (usedNonces.has(nonce)) {
						return Response.json({ error: "replayed_nonce" }, { status: 403 });
					}
					const expectedSig = computeServerHmac(method, pathWithQuery, ts, nonce);
					if (sig !== expectedSig) {
						return Response.json({ error: "invalid_hmac_signature" }, { status: 403 });
					}
					usedNonces.add(nonce);

					const user = resolveUserFromRequest(req);
					if (!user) {
						return Response.json({ error: "authentication_required" }, { status: 401 });
					}

					const orderId = url.searchParams.get("id") ?? "";
					const ordersDb: Record<string, { orderId: string; owner: string; item: string; amountCents: number }> = {
						"1001": { orderId: "1001", owner: "alice", item: "Enterprise Audit Suite", amountCents: 129000 },
						"1002": { orderId: "1002", owner: "bob", item: "Starter Plan", amountCents: 2900 },
					};
					const record = ordersDb[orderId];
					if (!record) {
						return Response.json({ error: "order_not_found" }, { status: 404 });
					}

					// /api/orders-safe 严格执行对象归属校验；/api/orders 存在水平越权缺陷（BOLA）
					if (url.pathname === "/api/orders-safe" && record.owner !== user) {
						return Response.json({ error: "forbidden_not_owner" }, { status: 403 });
					}

					return Response.json({
						ok: true,
						data: record,
					});
				}

				// SPA 统一 200 HTML 软 404 兜底页（测试 Soft-404 基线去噪）
				return new Response(
					`<!doctype html><html><head><title>Order Console</title></head><body><div class="not-found">路由未命中</div></body></html>`,
					{
						status: 200,
						headers: { "content-type": "text/html; charset=utf-8" },
					},
				);
			},
		});
		targetOrigin = `http://127.0.0.1:${targetServer.port}`;
	});

	afterAll(() => {
		try {
			targetServer?.stop(true);
		} catch {
			/* ignore */
		}
		try {
			oobServer?.stop(true);
		} catch {
			/* ignore */
		}
		if (tempRoot && existsSync(tempRoot)) {
			rmSync(tempRoot, { recursive: true, force: true });
		}
	});

	test("resolveChromeExecutable 与注入 Mock Transport 的确定性 CdpClient 超时/会话机制", async () => {
		// 1. 验证 NUWA_CHROME_BIN 环境变量最高优先级探测
		const fakeBin = join(tempRoot, "fake-chrome-bin");
		writeFileSync(fakeBin, "#!/bin/sh\necho ok\n", "utf8");
		chmodSync(fakeBin, 0o755);
		expect(resolveChromeExecutable({ env: { NUWA_CHROME_BIN: fakeBin } })).toBe(fakeBin);

		// 2. 验证本机真实 Chrome/Chromium 二进制可探测
		const realBin = resolveChromeExecutable();
		expect(realBin).toBeTruthy();
		expect(existsSync(realBin!)).toBe(true);

		// 3. 验证确定性 Mock CDP Transport 的 JSON-RPC、事件流、超时拒绝与关闭清理
		let serverPush: ((msg: Record<string, unknown>) => void) | undefined;
		let transportClosed = false;
		const mockTransport: CdpTransportLike = {
			send(raw: string) {
				const parsed = JSON.parse(raw) as { id: number; method: string; params?: Record<string, unknown> };
				if (parsed.method === "Browser.getVersion") {
					serverPush?.({ id: parsed.id, result: { product: "MockHeadlessChrome/156.0" } });
				} else if (parsed.method === "Target.createTarget") {
					serverPush?.({ id: parsed.id, result: { targetId: "t_mock_01" } });
				} else if (parsed.method === "Target.attachToTarget") {
					serverPush?.({ id: parsed.id, result: { sessionId: "s_mock_01" } });
				} else if (parsed.method === "Runtime.hangForever") {
					// 故意不回复以验证单请求超时清理
				} else if (parsed.method === "Browser.close") {
					serverPush?.({ id: parsed.id, result: {} });
				}
			},
			close() {
				transportClosed = true;
			},
			onMessage(handler) {
				serverPush = (obj) => handler(JSON.stringify(obj));
			},
			onClose() {},
			onError() {},
		};

		const mockSession = await launchCdpSession({ transport: mockTransport, rpcTimeoutMs: 500 });
		expect(mockSession.isMock).toBe(true);
		expect(mockSession.targetId).toBe("t_mock_01");
		expect(mockSession.sessionId).toBe("s_mock_01");
		expect(mockSession.browserVersion).toBe("MockHeadlessChrome/156.0");

		// 验证事件等待
		const evPromise = mockSession.client.waitForEvent<{ marker: string }>("Page.customEvent", {
			sessionId: "s_mock_01",
			timeoutMs: 500,
		});
		serverPush?.({ method: "Page.customEvent", sessionId: "s_mock_01", params: { marker: "hit" } });
		const evOut = await evPromise;
		expect(evOut.marker).toBe("hit");

		// 验证超时拒绝
		await expect(
			mockSession.client.send("Runtime.hangForever", {}, { timeoutMs: 120 }),
		).rejects.toThrow(/超时/);

		await closeCdpSession(mockSession);
		expect(mockSession.closed).toBe(true);
		expect(transportClosed).toBe(true);

		// 验证底层断开后拒绝新请求
		const client2 = new CdpClient(mockTransport);
		client2.close();
		await expect(client2.send("Page.enable")).rejects.toThrow(/已关闭/);
	});

	test("真实 Headless Chrome 直连 CDP：流量捕获入库、零明文泄露与越界子请求 0 发包阻断", async () => {
		const caseRoot = mkdtempSync(join(tempRoot, "capture-"));
		const scope = defaultScopeForTarget(targetOrigin, "audit", {
			allowHosts: ["127.0.0.1"],
			denyHosts: ["evil.example.com"],
			allowLoopback: false,
		});

		oobHitCount = 0;

		// 先验证入口 URL 越界时直接阻断且 0 发包
		const blockedEntry = await captureCdpSessionTraffic(`${oobOrigin}/admin`, caseRoot, scope);
		expect(blockedEntry.ok).toBe(false);
		expect(blockedEntry.blockedByScope).toBe(true);
		expect(oobHitCount).toBe(0);

		// 真实启动 Headless Chrome 捕获微靶机页面加载流量
		const session = await launchCdpSession();
		const processTag = session.processTag;
		const tempUserDataDir = session.userDataDir!;

		try {
			expect(session.isMock).toBe(false);
			expect(typeof session.pid).toBe("number");
			expect((session.pid ?? 0) > 1).toBe(true);
			expect(session.wsEndpoint).toMatch(/^ws:\/\/127\.0\.0\.1:\d+\/devtools\//);

			const captureRes = await captureCdpSessionTraffic(`${targetOrigin}/app`, caseRoot, scope, {
				session,
				captureRole: "alice",
				settleMs: 500,
			});

			expect(captureRes.ok).toBe(true);
			expect(captureRes.blockedByScope).toBe(false);
			expect(captureRes.syncedRoles).toContain("alice");

			// 1. 验证越界第三方脚本与 fetch 探针均在 CDP Fetch 拦截层被阻断，越界服务端命中数为 0
			expect(captureRes.blockedCount).toBeGreaterThanOrEqual(2);
			expect(captureRes.blockedRequests.some((b) => b.url.includes("localhost"))).toBe(true);
			expect(oobHitCount).toBe(0);

			// 2. 验证 XHR/Fetch 流量已写入 TrafficRecorder
			const recorder = new TrafficRecorder(caseRoot);
			const recorded = recorder.list();
			expect(recorded.length).toBeGreaterThanOrEqual(2);
			expect(recorded.some((e) => e.path.startsWith("/api/auth/login") && e.method === "POST")).toBe(true);
			expect(recorded.some((e) => e.path.startsWith("/api/orders?id=1001") && e.status === 200)).toBe(true);

			// 3. 验证认证凭据已安全同步至 SessionVault（具备 Cookie + Bearer + X-CSRF-Token）
			const vault = loadSessionVault(caseRoot);
			const aliceEntry = vault.roles.alice;
			expect(aliceEntry).toBeDefined();
			expect(aliceEntry?.cookie).toContain(ALICE_SESSION_COOKIE);
			expect(aliceEntry?.bearer).toContain(ALICE_BEARER_TOKEN);
			expect(
				Object.entries(aliceEntry?.headers ?? {}).some(
					([k, v]) => k.toLowerCase() === "x-csrf-token" && v === ALICE_CSRF_TOKEN,
				),
			).toBe(true);

			// 4. 严格校验磁盘流量日志与返回摘要零明文凭据泄露
			const rawTrafficJsonl = readFileSync(recorder.indexPath, "utf8");
			const serializedResult = JSON.stringify(captureRes);
			for (const secretValue of [
				ALICE_PASSWORD,
				ALICE_SESSION_COOKIE,
				ALICE_BEARER_TOKEN,
				ALICE_CSRF_TOKEN,
			]) {
				expect(rawTrafficJsonl.includes(secretValue)).toBe(false);
				expect(serializedResult.includes(secretValue)).toBe(false);
				expect(captureRes.vaultSummary.includes(secretValue)).toBe(false);
			}
		} finally {
			await closeCdpSession(session);
		}

		// 5. 确认关闭后零残留 Chrome 进程且临时用户目录已删除
		expect(findLiveProcessesByTag(processTag)).toEqual([]);
		expect(existsSync(tempUserDataDir)).toBe(false);
	});

	test("页面内借壳加签差分：阻断写方法/注入，穿透动态 HMAC 签名检出 BOLA 且无签名直连稳定返回 403", async () => {
		const diffRoot = mkdtempSync(join(tempRoot, "diff-"));
		const scope = defaultScopeForTarget(targetOrigin, "audit", {
			allowHosts: ["127.0.0.1"],
			denyHosts: ["evil.example.com"],
			allowLoopback: false,
		});

		// 在 SessionVault 中预置高权基线角色 alice 与另一普通角色 bob
		upsertSessionRole(diffRoot, {
			role: "alice",
			cookie: `sid=${ALICE_SESSION_COOKIE}`,
			bearer: ALICE_BEARER_TOKEN,
			headers: { "X-CSRF-Token": ALICE_CSRF_TOKEN },
		});
		upsertSessionRole(diffRoot, {
			role: "bob",
			cookie: `sid=${BOB_SESSION_COOKIE}`,
			bearer: BOB_BEARER_TOKEN,
		});

		// 1. 验证剥离动态签名的普通 HTTP 请求（即使携带合法 Bearer 与 Cookie）一律返回 403
		const plainAliceResp = await fetch(`${targetOrigin}/api/orders?id=1001`, {
			headers: {
				Authorization: `Bearer ${ALICE_BEARER_TOKEN}`,
				Cookie: `sid=${ALICE_SESSION_COOKIE}`,
			},
		});
		expect(plainAliceResp.status).toBe(403);

		const plainBobResp = await fetch(`${targetOrigin}/api/orders?id=1001`, {
			headers: {
				Authorization: `Bearer ${BOB_BEARER_TOKEN}`,
				Cookie: `sid=${BOB_SESSION_COOKIE}`,
			},
		});
		expect(plainBobResp.status).toBe(403);

		const session = await launchCdpSession();
		const processTag = session.processTag;

		try {
			// 先将会话导航至同源应用页挂载签名上下文
			await captureCdpSessionTraffic(`${targetOrigin}/app`, diffRoot, scope, {
				session,
				captureRole: "alice",
				settleMs: 350,
			});

			writeMethodHitCount = 0;

			// 2. 反例验证：非只读方法（POST / DELETE / PUT）全部在发包前被拦截，服务端写计数保持 0
			for (const badMethod of ["POST", "DELETE", "PUT", "PATCH"]) {
				const blockedWrite = await executeInPageSignedProbe(
					session,
					{ url: "/api/orders?id=1001", method: badMethod },
					scope,
					{ root: diffRoot },
				);
				expect(blockedWrite.ok).toBe(false);
				expect(blockedWrite.blocked).toBe(true);
				expect(blockedWrite.blockReason).toContain("N-008");
			}
			expect(writeMethodHitCount).toBe(0);

			// 3. 反例验证：越界 URL 与恶意 signerHook 代码注入尝试均被硬拦截
			const blockedOobProbe = await executeInPageSignedProbe(
				session,
				{ url: `${oobOrigin}/api/orders?id=1001`, method: "GET", allowCrossOriginInScope: true },
				scope,
				{ root: diffRoot },
			);
			expect(blockedOobProbe.blocked).toBe(true);
			expect(oobHitCount).toBe(0);

			const blockedHookInjection = await executeInPageSignedProbe(
				session,
				{
					url: "/api/orders?id=1001",
					method: "GET",
					signerHook: "__nuwaSign; window.__injectedFlag = 1",
				},
				scope,
				{ root: diffRoot },
			);
			expect(blockedHookInjection.blocked).toBe(true);
			const checkInjected = await session.client.send<{ result?: { value?: unknown } }>(
				"Runtime.evaluate",
				{ expression: "typeof window.__injectedFlag", returnByValue: true },
				{ sessionId: session.sessionId },
			);
			expect(checkInjected.result?.value).toBe("undefined");

			// 4. 执行多角色页面内借壳加签契约差分（同时测试存在 BOLA 的端点、安全鉴权端点与 SPA Soft-404 路径）
			const diffRes = await runCdpSignedAuthDiff(
				`${targetOrigin}/app`,
				["/api/orders?id=1001", "/api/orders-safe?id=1001", "/spa/non-existent-route"],
				diffRoot,
				scope,
				{
					session,
					baselineRole: "alice",
					compareRoles: ["bob", "anon"],
				},
			);

			expect(diffRes.ok).toBe(true);
			expect(diffRes.blockedByScope).toBe(false);

			// 普通无签名直连探测稳定记录为 403
			expect(diffRes.unsignedStatuses["/api/orders?id=1001"]).toBe(403);
			expect(diffRes.unsignedStatuses["/api/orders-safe?id=1001"]).toBe(403);

			// 精准检出 /api/orders?id=1001 对角色 bob 的 horizontal_bola，且安全接口与软 404 零误报
			expect(diffRes.findings.length).toBe(1);
			const finding = diffRes.findings[0]!;
			expect(finding.path).toBe("/api/orders?id=1001");
			expect(finding.kind).toBe("horizontal_bola");
			expect(finding.baselineRole).toBe("alice");
			expect(finding.testedRole).toBe("bob");
			expect(finding.unsignedStatus).toBe(403);
			expect(finding.probes.every((p) => p.signedByHook === true)).toBe(true);
			expect(diffRes.fact?.kind).toBe("vuln");

			// 验证差分结果与产出 Fact 零明文凭据泄露
			const diffJson = JSON.stringify(diffRes);
			for (const secret of [
				ALICE_SESSION_COOKIE,
				ALICE_BEARER_TOKEN,
				ALICE_CSRF_TOKEN,
				BOB_SESSION_COOKIE,
				BOB_BEARER_TOKEN,
			]) {
				expect(diffJson.includes(secret)).toBe(false);
			}
		} finally {
			await closeCdpSession(session);
		}

		expect(findLiveProcessesByTag(processTag)).toEqual([]);
	});

	test("启动握手超时异常下强制清理子进程与临时目录（零僵尸残留）", async () => {
		const beforeCount = findLiveProcessesByTag("nuwa-cdp-").length;
		const customTmpProfile = mkdtempSync(join(tempRoot, "timeout-profile-"));
		rmSync(customTmpProfile, { recursive: true, force: true });

		// 传入 1ms 极短启动超时触发握手阶段异常，验证 catch 块自动回收刚拉起的浏览器进程
		await expect(
			launchCdpSession({
				launchTimeoutMs: 1,
			}),
		).rejects.toThrow();

		await Bun.sleep(100);
		const afterPids = findLiveProcessesByTag("nuwa-cdp-");
		expect(afterPids.length).toBeLessThanOrEqual(beforeCount);
	});

	test("同源 fetch 包装器自动加签、单步钩子挂起超时优雅恢复与自动托管会话清理", async () => {
		const beforeCount = findLiveProcessesByTag("nuwa-cdp-").length;
		const wrapRoot = mkdtempSync(join(tempRoot, "wrap-fetch-"));

		// 启动仅通过同源 window.fetch 包装自动加签（未定义 window.__nuwaSign）的独立微服务端
		const wrapServer = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req: Request) {
				const u = new URL(req.url);
				if (u.pathname === "/portal") {
					return new Response(
						`<!doctype html><html><head><title>Admin Portal</title></head><body><script>
						const origFetch = window.fetch.bind(window);
						window.__hangHook = () => new Promise(() => {});
						window.__redirectHook = () => ({ url: "http://evil.example.com/data" });
						window.fetch = async (input, init) => {
							const reqUrl = new URL(String(input), window.location.origin);
							const hdrs = Object.assign({}, (init && init.headers) || {}, {
								"x-wrapped-ts": String(Date.now()),
								"x-wrapped-sig": "wrapped_valid_" + reqUrl.pathname,
							});
							return origFetch(input, Object.assign({}, init || {}, { headers: hdrs }));
						};
						</script></body></html>`,
						{ status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
					);
				}
				if (u.pathname === "/api/admin/settings") {
					const sig = req.headers.get("x-wrapped-sig") ?? "";
					if (sig !== "wrapped_valid_/api/admin/settings") {
						return Response.json({ error: "missing_wrapped_sig" }, { status: 403 });
					}
					const auth = req.headers.get("authorization") ?? "";
					if (!auth.startsWith("Bearer ")) {
						return Response.json({ error: "unauthenticated" }, { status: 401 });
					}
					// 模拟垂直访问控制缺失：低权角色也返回了管理配置
					return Response.json({ ok: true, data: { maintenanceMode: false, maxWorkers: 16 } });
				}
				return Response.json({ error: "not_found" }, { status: 404 });
			},
		});

		try {
			const wrapOrigin = `http://127.0.0.1:${wrapServer.port}`;
			const scope = defaultScopeForTarget(wrapOrigin, "audit", {
				allowHosts: ["127.0.0.1"],
				denyHosts: ["evil.example.com"],
				allowLoopback: false,
			});

			upsertSessionRole(wrapRoot, { role: "admin", bearer: "admin_secret_tok_9001" });
			upsertSessionRole(wrapRoot, { role: "bob", bearer: "bob_lowpriv_tok_9002" });

			// 1. 验证单步挂死钩子触发超时优雅返回，以及篡改非同源 URL 钩子被阻断
			const manualSession = await launchCdpSession();
			try {
				await captureCdpSessionTraffic(`${wrapOrigin}/portal`, wrapRoot, scope, {
					session: manualSession,
					settleMs: 150,
				});
				const timeoutProbe = await executeInPageSignedProbe(
					manualSession,
					{ url: "/api/admin/settings", method: "GET", signerHook: "__hangHook" },
					scope,
					{ timeoutMs: 320, root: wrapRoot },
				);
				expect(timeoutProbe.ok).toBe(false);
				expect(timeoutProbe.timedOut).toBe(true);

				const crossOriginHookProbe = await executeInPageSignedProbe(
					manualSession,
					{ url: "/api/admin/settings", method: "GET", signerHook: "__redirectHook" },
					scope,
					{ timeoutMs: 1000, root: wrapRoot },
				);
				expect(crossOriginHookProbe.ok).toBe(false);
				expect(crossOriginHookProbe.blocked).toBe(true);
			} finally {
				await closeCdpSession(manualSession);
			}

			// 2. 不传 session，测试 runCdpSignedAuthDiff 自动拉起并托管回收会话 + 同源 fetch 包装器检出 vertical_bfla
			const autoDiffRes = await runCdpSignedAuthDiff(
				`${wrapOrigin}/portal`,
				["/api/admin/settings"],
				wrapRoot,
				scope,
				{
					baselineRole: "admin",
					compareRoles: ["bob", "anon"],
				},
			);
			expect(autoDiffRes.ok).toBe(true);
			expect(autoDiffRes.unsignedStatuses["/api/admin/settings"]).toBe(403);
			expect(autoDiffRes.findings.length).toBe(1);
			expect(autoDiffRes.findings[0]?.kind).toBe("vertical_bfla");
			expect(autoDiffRes.findings[0]?.testedRole).toBe("bob");
			expect(JSON.stringify(autoDiffRes).includes("admin_secret_tok_9001")).toBe(false);
			expect(JSON.stringify(autoDiffRes).includes("bob_lowpriv_tok_9002")).toBe(false);
		} finally {
			wrapServer.stop(true);
		}

		await Bun.sleep(80);
		expect(findLiveProcessesByTag("nuwa-cdp-").length).toBeLessThanOrEqual(beforeCount);
	});
});
