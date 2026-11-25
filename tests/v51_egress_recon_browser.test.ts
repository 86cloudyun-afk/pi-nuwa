/**
 * 女娲 v5.1 回归与验收测试（egress-recon 分片）：
 * - #23 (NW-03)：出口环境变量注入、curl -x 代理透传与探测前 Gate URL 门控探活（统一 403 快速失败 egress_blocked）
 * - #32 (NW-12)：端点响应分类 classifyEndpointResponse（401 / 业务 403 / 405 Allow vs 404 与基线同指纹 + SHA-256 & 字节数）
 * - #33 (NW-13)：增强软 404 检测 detectSoft404（随机路径基线、Next.js RSC Flight、多语言 404 文案、体积+模板指纹）
 * - #36 (NW-16)：多出口健康度管理池 EgressPoolManager（TTFB/403/5xx/连接重置熔断、冷却半开恢复、多并发轮询/最少负载分配）
 * - #37 (NW-17)：合规浏览器侦察（--user-data-dir、headless/useXvfb/display、detectChallengeGate 停重试、session-vault 合法会话复用）
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import * as http from "node:http";
import type * as net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { newState, readCfg, seedPhase, type Cfg, type NuwaState } from "../omp/nuwa";
import {
	EgressPoolManager as AutoExecEgressPoolManager,
	classifyEndpointResponse,
	computeBodyHash,
	computeTemplateFingerprint,
	detectSoft404 as autoExecDetectSoft404,
	injectAuthHeaderFileIntoScript,
	injectEgressEnv as autoExecInjectEgressEnv,
	injectEgressIntoScript,
	isSoft404Hit,
	pickAuto,
	preflightEgressCheck,
	ruleFor,
	runAutoBatchManaged,
	runAutoIntent,
	sampleSoft404Baseline,
	shellQuote,
	type AutoRule,
	type ExecLike,
} from "../omp/autoexec";
import {
	buildChromiumLaunchConfig,
	detectChallengeGate,
	detectSoft404 as browserDetectSoft404,
	loadHumanSessionFromVault,
	runSpaRecon,
	saveHumanSessionToVault,
	type BrowserCookieEntry,
	type PlaywrightLike,
	type PlaywrightRouteLike,
} from "../omp/browser-recon";
import {
	EgressPoolManager,
	buildCurlProxyArgs,
	injectEgressEnv,
	maskEgressUrl,
	normalizeTaskEgressUrl,
	startScopedEgressProxy,
} from "../omp/sandbox";
import { defaultScopeForTarget } from "../omp/scope";

const REPO_ROOT = resolve(import.meta.dir, "..");
const SUITE_HOME = mkdtempSync(join(tmpdir(), "nuwa-v51-egress-home-"));
process.env.PI_AGENT_HOME = SUITE_HOME;
process.env.NUWA_KB_DB = join(SUITE_HOME, "nuwa-kb", "kb.db");

const cfg: Cfg = { ...readCfg(), auto: true, autoMax: 4, emptyLimit: 3, maxAttempts: 3 };
const tmpDirs: string[] = [];
const cleanups: Array<() => Promise<void> | void> = [];

function makeTmpDir(prefix = "nuwa-v51-egress-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(d);
	return d;
}

function makeState(url: string): NuwaState {
	const st = newState(url, "v5.1 出口与侦察验证", "pentest", cfg);
	seedPhase(st, "recon");
	return st;
}

const realAsyncExec: ExecLike = async (cmd, args, opts) => {
	const proc = Bun.spawn([cmd, ...args], {
		cwd: opts?.cwd,
		stdout: "pipe",
		stderr: "pipe",
	});
	const [stdout, stderr, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { stdout, stderr, code };
};

async function startLocalServer(
	handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; port: number; close: () => Promise<void> }> {
	const server = http.createServer(handler);
	await new Promise<void>((res) => server.listen(0, "127.0.0.1", () => res()));
	const addr = server.address() as net.AddressInfo;
	const close = () =>
		new Promise<void>((res) => {
			server.close(() => res());
		});
	cleanups.push(close);
	return { url: `http://127.0.0.1:${addr.port}`, port: addr.port, close };
}

afterEach(async () => {
	while (cleanups.length > 0) {
		const fn = cleanups.pop()!;
		try {
			await fn();
		} catch {
			/* ignore */
		}
	}
	while (tmpDirs.length > 0) {
		const d = tmpDirs.pop()!;
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
	delete process.env.NUWA_EGRESS;
	delete process.env.NUWA_EGRESS_PROXY;
	delete process.env.EGRESS;
	delete process.env.HTTP_PROXY;
	delete process.env.HTTPS_PROXY;
	delete process.env.ALL_PROXY;
	delete process.env.NUWA_BROWSER_USER_DATA_DIR;
	delete process.env.NUWA_BROWSER_USE_XVFB;
	delete process.env.NUWA_BROWSER_DISPLAY;
});

afterAll(() => {
	rmSync(SUITE_HOME, { recursive: true, force: true });
});

describe("Issue #23 (NW-03): 出口随任务注入、curl -x 透传与 Gate URL 快速失败", () => {
	test("injectEgressEnv / buildCurlProxyArgs / injectEgressIntoScript 严格校验并透传代理", () => {
		expect(autoExecInjectEgressEnv).toBe(injectEgressEnv);
		expect(AutoExecEgressPoolManager).toBe(EgressPoolManager);
		expect(typeof pickAuto).toBe("function");
		expect(typeof ruleFor).toBe("function");
		expect(typeof runAutoIntent).toBe("function");
		expect(typeof shellQuote).toBe("function");

		const env = injectEgressEnv("socks5h://127.0.0.1:7890", { PATH: "/usr/bin" });
		expect(env.NUWA_EGRESS).toBe("socks5h://127.0.0.1:7890");
		expect(env.EGRESS).toBe("socks5h://127.0.0.1:7890");
		expect(env.HTTP_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(env.HTTPS_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(env.ALL_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(env.http_proxy).toBe("socks5h://127.0.0.1:7890");
		expect(env.https_proxy).toBe("socks5h://127.0.0.1:7890");
		expect(env.NO_PROXY).toBe("");

		expect(buildCurlProxyArgs("socks5h://127.0.0.1:7890")).toEqual(["-x", "socks5h://127.0.0.1:7890"]);
		expect(maskEgressUrl("socks5h://alice:supersecret@127.0.0.1:7890")).toBe("socks5h://alice:***@127.0.0.1:7890");

		// 拒绝非法协议与 shell 注入
		expect(normalizeTaskEgressUrl("file:///etc/passwd")).toBeUndefined();
		expect(normalizeTaskEgressUrl("http://127.0.0.1:7890; id")).toBeUndefined();
		expect(() => injectEgressEnv("http://127.0.0.1:7890; id", {})).toThrow();

		// 与零明文头文件组合注入不冲突
		const script = injectEgressIntoScript(
			"curl -sS http://target.example/",
			"socks5h://127.0.0.1:7890",
			"/tmp/nuwa/proj1/sessions/admin.headers",
		);
		expect(script).toContain("NUWA_EGRESS='socks5h://127.0.0.1:7890'");
		expect(script).toContain('command curl --noproxy \'\' -x "$NUWA_EGRESS" -H @"$NUWA_AUTH_HEADER_FILE" "$@"');

		const authOnly = injectAuthHeaderFileIntoScript("curl -sS http://127.0.0.1/", "/tmp/nuwa/p1/sessions/u.headers");
		expect(authOnly).toContain('NUWA_AUTH_HEADER_FILE=');
		expect(authOnly).toContain('-H @"$NUWA_AUTH_HEADER_FILE"');
	});

	test("本地 Mock 代理 + Gate URL 端到端：放行出口正常执行，ASN 统一 403 立即 fail-fast 标 egress_blocked 且零假阴性", async () => {
		const targetHits: string[] = [];
		const target = await startLocalServer((req, res) => {
			const u = req.url ?? "/";
			targetHits.push(u);
			if (u === "/zh-tw") {
				res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", Server: "nginx" });
				res.end("<!doctype html><html><title>Portal TW</title><body>Welcome</body></html>");
				return;
			}
			if (u === "/") {
				res.writeHead(200, { "Content-Type": "text/html", Server: "openresty" });
				res.end("<html><title>Home</title><body>ok</body></html>");
				return;
			}
			res.writeHead(404);
			res.end("not found");
		});

		const proxyTraffic: Array<{ url: string; status: number }> = [];
		const scope = defaultScopeForTarget(target.url, "pentest");
		scope.allowLoopback = true;
		const proxy = await startScopedEgressProxy(scope, {
			onTraffic: (rec) => proxyTraffic.push({ url: rec.url, status: rec.status }),
		});
		cleanups.push(() => proxy.close());

		// 1. 合法代理出口探活 /zh-tw == 200 通过，并真实经代理完成 recon:http
		const pfOk = await preflightEgressCheck({
			gateUrl: `${target.url}/zh-tw`,
			egressUrl: proxy.url,
			exec: realAsyncExec,
		});
		expect(pfOk.ok).toBe(true);
		expect(pfOk.status).toBe("ok");
		expect(pfOk.httpStatus).toBe(200);
		expect(pfOk.bodyBytes).toBeGreaterThan(0);
		expect(pfOk.bodyHash).toHaveLength(64);
		expect(proxyTraffic.some((t) => t.url.endsWith("/zh-tw") && t.status === 200)).toBe(true);

		const dir = makeTmpDir();
		const st = makeState(target.url);
		const httpRun = await runAutoIntent(ruleFor("recon:http")!, st, realAsyncExec, dir, undefined, {
			egressUrl: proxy.url,
			gateUrl: `${target.url}/zh-tw`,
		});
		expect(httpRun.ok).toBe(true);
		expect(httpRun.fact?.meta?.server).toBe("openresty");
		expect(httpRun.egressUrl).toBe(proxy.url);

		// 2. 模拟出口 ASN 被边缘防火墙统一拦截（/zh-tw 返回 403 / 4549B Cloudflare 拦截页）
		const cfBlockedHtml =
			"<!doctype html><html><head><title>Attention Required! | Cloudflare</title></head><body>Sorry, you have been blocked" +
			"x".repeat(4400) +
			"</body></html>";
		const blockedOrigin = await startLocalServer((_req, res) => {
			res.writeHead(403, {
				"Content-Type": "text/html; charset=utf-8",
				Server: "cloudflare",
				"CF-Ray": "8f1234567890-SJC",
			});
			res.end(cfBlockedHtml);
		});

		const pfBlocked = await preflightEgressCheck({
			gateUrl: `${blockedOrigin.url}/zh-tw`,
		});
		expect(pfBlocked.ok).toBe(false);
		expect(pfBlocked.status).toBe("egress_blocked");
		expect(pfBlocked.errorKind).toBe("egress_blocked");
		expect(pfBlocked.httpStatus).toBe(403);
		expect(pfBlocked.waf).toBe("cloudflare");
		expect(pfBlocked.cfRay).toBe("8f1234567890-SJC");

		// 门控失败后，runAutoIntent 绝不执行实际业务探测脚本，也绝不产生任何假阴性 fact
		let probeExecCount = 0;
		const countingExec: ExecLike = async (cmd, args, opts) => {
			const script = args[1] ?? "";
			if (script.includes("SHOULD_NOT_RUN")) {
				probeExecCount++;
			}
			return realAsyncExec(cmd, args, opts);
		};
		const dummyProbeRule: AutoRule = {
			key: "recon:dirs",
			phase: "recon",
			timeoutMs: 5000,
			script: () => "echo SHOULD_NOT_RUN",
			parse: () => null,
		};
		const blockedRun = await runAutoIntent(
			dummyProbeRule,
			makeState(blockedOrigin.url),
			countingExec,
			dir,
			undefined,
			{ gateUrl: `${blockedOrigin.url}/zh-tw` },
		);
		expect(blockedRun.ok).toBe(false);
		expect(blockedRun.errorKind).toBe("egress_blocked");
		expect(blockedRun.fact).toBeUndefined();
		expect(probeExecCount).toBe(0);
	});
});

describe("Issue #32 (NW-12): classifyEndpointResponse 精准区分鉴权存在与 404 并记录 SHA-256 指纹", () => {
	test("区分 401 / 业务 403 / 405 Allow / 边缘 403 / 404 与同指纹基线，并计算精确 bodyHash 与 bodyBytes", async () => {
		const notFoundPage = `<!doctype html><html><title>404</title><body>Resource missing ${"p".repeat(6500)}</body></html>`;
		const expectedNf = computeBodyHash(notFoundPage);
		const baseline404 = { status: 404, body: notFoundPage };

		// 1) 401 -> exists_requires_auth
		const body401 = JSON.stringify({ code: 401, message: "Unauthenticated." });
		const r401 = classifyEndpointResponse(
			{ status: 401, headers: { "www-authenticate": 'Bearer realm="api"' }, body: body401 },
			baseline404,
		);
		expect(r401.classification).toBe("exists_requires_auth");
		expect(r401.exists).toBe(true);
		expect(r401.requiresAuth).toBe(true);
		expect(r401.bodyBytes).toBe(Buffer.byteLength(body401, "utf8"));
		expect(r401.bodyHash).toBe(createHash("sha256").update(body401).digest("hex"));
		expect(r401.meta.bodyHash).toBe(r401.bodyHash);
		expect(r401.meta.bodyBytes).toBe(r401.bodyBytes);

		// 2) 带业务鉴权语义的 403 -> exists_requires_auth
		const bodyBiz403 = JSON.stringify({ error: "permission denied", message: "无权限访问管理接口" });
		const rBiz403 = classifyEndpointResponse(
			{ status: 403, headers: { "content-type": "application/json" }, body: bodyBiz403 },
			baseline404,
		);
		expect(rBiz403.classification).toBe("exists_requires_auth");
		expect(rBiz403.exists).toBe(true);
		expect(rBiz403.requiresAuth).toBe(true);
		expect(rBiz403.bodyBytes).toBe(Buffer.byteLength(bodyBiz403, "utf8"));

		// 3) 边缘 Cloudflare 拦截 403 -> egress_blocked（绝不误标 exists_requires_auth）
		const rEdge403 = classifyEndpointResponse(
			{
				status: 403,
				headers: { server: "cloudflare", "cf-mitigated": "challenge", "content-type": "text/html" },
				body: "<!doctype html><html><title>Just a moment...</title><body>Attention Required! | Cloudflare</body></html>",
			},
			baseline404,
		);
		expect(rEdge403.classification).toBe("egress_blocked");
		expect(rEdge403.exists).toBe(false);
		expect(rEdge403.requiresAuth).toBe(false);

		// 4) 带 Allow 头的 405 -> exists_requires_auth
		const r405 = classifyEndpointResponse(
			{
				status: 405,
				headers: { allow: "POST, OPTIONS", "content-type": "application/json" },
				body: '{"message":"The GET method is not supported for this route."}',
			},
			baseline404,
		);
		expect(r405.classification).toBe("exists_requires_auth");
		expect(r405.exists).toBe(true);
		expect(r405.requiresAuth).toBe(true);
		expect(r405.allowMethods).toEqual(["POST", "OPTIONS"]);
		expect(r405.meta.allow).toEqual(["POST", "OPTIONS"]);

		// 5) 404 及与 404 基线同指纹响应 -> not_found
		const r404 = classifyEndpointResponse({ status: 404, body: notFoundPage }, baseline404);
		expect(r404.classification).toBe("not_found");
		expect(r404.exists).toBe(false);
		expect(r404.requiresAuth).toBe(false);
		expect(r404.bodyHash).toBe(expectedNf.bodyHash);
		expect(r404.bodyBytes).toBe(expectedNf.bodyBytes);

		// 同指纹伪装 405（无 Allow 头且响应体与 404 基线完全一致）-> not_found
		const rFake405 = classifyEndpointResponse({ status: 405, body: notFoundPage }, baseline404);
		expect(rFake405.classification).toBe("not_found");
		expect(rFake405.exists).toBe(false);

		// 6) 本地 Mock Server 复现 NW-12 实战：15 条 member 路径仅 2 条存在，其余 13 条为 404 同页
		const srv = await startLocalServer((req, res) => {
			if (req.url === "/api/v1/member/profile") {
				res.writeHead(405, { Allow: "POST", "Content-Type": "application/json" });
				res.end('{"error":"method not allowed"}');
				return;
			}
			if (req.url === "/api/v1/member/bank") {
				res.writeHead(401, { "Content-Type": "application/json" });
				res.end('{"code":401,"msg":"login required"}');
				return;
			}
			res.writeHead(404, { "Content-Type": "text/html" });
			res.end(notFoundPage);
		});

		const memberPaths = [
			"/api/v1/member/profile",
			"/api/v1/member/bank",
			...Array.from({ length: 13 }, (_, i) => `/api/v1/member/ghost_${i}`),
		];
		const authExists: string[] = [];
		const missing: string[] = [];
		for (const p of memberPaths) {
			const resp = await fetch(`${srv.url}${p}`);
			const text = await resp.text();
			const cls = classifyEndpointResponse({ path: p, status: resp.status, headers: resp.headers, body: text }, baseline404);
			if (cls.classification === "exists_requires_auth") authExists.push(p);
			if (cls.classification === "not_found") missing.push(p);
		}
		expect(authExists).toEqual(["/api/v1/member/profile", "/api/v1/member/bank"]);
		expect(missing.length).toBe(13);
	});
});

describe("Issue #33 (NW-13): detectSoft404 增强软 404 检测与端点清零污染阻断", () => {
	test("识别 Next.js RSC Flight 404、多语言 404 文案、随机路径预采样模板指纹，且零误杀真实业务 API", async () => {
		expect(browserDetectSoft404).toBe(autoExecDetectSoft404);

		// 1) Next.js RSC Flight 流 NEXT_HTTP_ERROR_FALLBACK;404
		const rscBody = '0:["$@1",["build-abc",null]]\n1:E{"digest":"NEXT_HTTP_ERROR_FALLBACK;404"}';
		const rscRes = autoExecDetectSoft404({
			path: "/zh-tw/admin",
			status: 200,
			headers: { "content-type": "text/x-component" },
			body: rscBody,
		});
		expect(rscRes.isSoft404).toBe(true);
		expect(rscRes.confidence).toBe("high");
		expect(rscRes.matchedRule).toBe("rsc_error_fallback");
		expect(isSoft404Hit({ path: "/zh-tw/admin", code: 200, body: rscBody }, null)).toBe(true);

		// 2) 多语言软 404 文案（繁中 / 简中 / 英文 / 日文）
		for (const sampleHtml of [
			"<!doctype html><html><title>找不到此頁面</title><body><h1>找不到此頁面</h1></body></html>",
			"<!doctype html><html><title>提示</title><body><div>抱歉，您访问的页面不存在</div></body></html>",
			"<!doctype html><html><title>App</title><body><h2>404 - Page Not Found</h2></body></html>",
			"<!doctype html><html><title>エラー</title><body>ページが見つかりません</body></html>",
		]) {
			const det = autoExecDetectSoft404({ status: 200, body: sampleHtml });
			expect(det.isSoft404).toBe(true);
			expect(det.matchedRule).toBe("multilingual_404_copy");
		}

		// 3) 真实业务 JSON 接口不被误杀
		const realApi = autoExecDetectSoft404({
			status: 200,
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				ok: true,
				data: [{ id: 1, label: "Page Not Found Banner Config" }],
			}),
		});
		expect(realApi.isSoft404).toBe(false);

		// 4) 本地 Mock Server 预采样随机路径基线 + 动态 nonce/路径回显模板指纹比对
		let reqSeq = 0;
		const srv = await startLocalServer((req, res) => {
			reqSeq++;
			const u = req.url ?? "/";
			if (u === "/api/v1/web/news") {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ code: 0, data: [{ id: 42, title: "Announcement" }] }));
				return;
			}
			// 软 404 页面：状态码 200，无明确 404 字样，且每次带不同 nonce / requestId / 回显路径
			const nonce = `nonce_${reqSeq}_${"a".repeat(8)}`;
			const reqId = `00000000-0000-4000-8000-${String(reqSeq).padStart(12, "0")}`;
			res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
			res.end(
				`<!doctype html><html><head><title>Portal Shell</title><script nonce="${nonce}">window.__REQ="${reqId}";</script></head><body><main>Route ${u} fallback shell</main></body></html>`,
			);
		});

		const baseline = await sampleSoft404Baseline(srv.url);
		expect(baseline.active).toBe(true);
		expect(baseline.samples.length).toBe(2);
		expect(baseline.templateHash).toHaveLength(64);

		// 验证模板指纹跨不同路径与 nonce 保持一致
		const fp1 = computeTemplateFingerprint(
			`<script nonce="abc123">{"requestId":"11111111-1111-4111-8111-111111111111"}</script><div>/zh-tw/m/login</div>`,
			"/zh-tw/m/login",
		);
		const fp2 = computeTemplateFingerprint(
			`<script nonce="xyz999">{"requestId":"22222222-2222-4222-8222-222222222222"}</script><div>/zh-tw/m/deposit</div>`,
			"/zh-tw/m/deposit",
		);
		expect(fp1).toBe(fp2);

		const fakeResp = await fetch(`${srv.url}/zh-tw/m/withdraw`);
		const fakeText = await fakeResp.text();
		const fakeDet = autoExecDetectSoft404(
			{ path: "/zh-tw/m/withdraw", status: fakeResp.status, headers: fakeResp.headers, body: fakeText },
			baseline,
		);
		expect(fakeDet.isSoft404).toBe(true);
		expect(fakeDet.matchedRule).toBe("baseline_template_match");

		// browser-recon 遇到软 404 页面时阻断污染，不产出 fact
		const scope = defaultScopeForTarget(srv.url, "pentest");
		const spaSoft = await runSpaRecon(`${srv.url}/zh-tw/m/deposit`, scope, {
			disablePlaywright: true,
			soft404Baseline: baseline,
		});
		expect(spaSoft.status).toBe("soft_404");
		expect(spaSoft.soft404).toBe(true);
		expect(spaSoft.fact).toBeNull();
		expect(spaSoft.routes).toEqual([]);
	});
});

describe("Issue #36 (NW-16): EgressPoolManager 健康度统计、熔断故障转移与多并发防抢占", () => {
	test("TTFB/403/5xx/连接重置熔断、冷却期半开恢复、可控降级与多并发轮询/最少负载分配", async () => {
		let nowMs = 1_700_000_000_000;
		const pool = new EgressPoolManager(
			[
				{ id: "slow-socks", url: "socks5h://101.36.104.239:10808", label: "remote-socks" },
				{ id: "local-clash", url: "socks5h://127.0.0.1:7890", label: "local-clash" },
				{ id: "backup-http", url: "http://127.0.0.1:8888", label: "backup-http" },
			],
			{
				maxTtfbMs: 5_000,
				maxErrorRate: 0.5,
				maxResetRate: 0.4,
				consecutiveFailureThreshold: 3,
				minSamplesForRate: 3,
				cooldownMs: 30_000,
				strategy: "least-loaded",
				now: () => nowMs,
			},
		);

		// 1) 并发 3 个 worker 同时申请，自动分配到 3 个不同出口，不抢占同一节点
		const l1 = pool.acquire("worker-1")!;
		const l2 = pool.acquire("worker-2")!;
		const l3 = pool.acquire("worker-3")!;
		expect(new Set([l1.id, l2.id, l3.id]).size).toBe(3);
		expect(pool.getHealth(l1.id)?.inFlight).toBe(1);
		l1.release({ ok: true, statusCode: 200, ttfbMs: 120 });
		l2.release({ ok: true, statusCode: 200, ttfbMs: 180 });
		l3.release({ ok: true, statusCode: 200, ttfbMs: 150 });
		expect(pool.getHealth(l1.id)?.inFlight).toBe(0);

		// 2) 复现 NW-16：slow-socks 发生高 TTFB + exit 97 连接重置 + exit 7 CONNECT 拒绝 -> 自动熔断
		pool.record("slow-socks", { ok: true, statusCode: 200, ttfbMs: 39_000 });
		pool.record("slow-socks", { ok: false, exitCode: 97, ttfbMs: 12_000, error: "connection reset" });
		const tripped = pool.record("slow-socks", { ok: false, exitCode: 7, ttfbMs: 5_000, error: "connect refused" })!;
		expect(tripped.state).toBe("open");
		expect(tripped.resetRate).toBeGreaterThanOrEqual(0.4);
		expect(tripped.avgTtfbMs).toBeGreaterThan(5_000);

		// 3) backup-http 连续 403 错误率超阈值 -> 自动熔断
		pool.record("backup-http", { ok: false, statusCode: 403, ttfbMs: 200, blocked: true });
		pool.record("backup-http", { ok: false, statusCode: 403, ttfbMs: 210, blocked: true });
		const backupTripped = pool.record("backup-http", { ok: false, statusCode: 503, ttfbMs: 250 })!;
		expect(backupTripped.state).toBe("open");
		expect(backupTripped.errorRate).toBeGreaterThanOrEqual(0.5);

		// 4) 熔断期间 acquire 自动故障转移到唯一健康出口 local-clash
		for (let i = 0; i < 4; i++) {
			const lease = pool.acquire(`worker-failover-${i}`)!;
			expect(lease.id).toBe("local-clash");
			expect(lease.degraded).toBe(false);
			lease.release({ ok: true, statusCode: 200, ttfbMs: 150 });
		}

		// 5) 全部熔断时：默认返回 null，允许降级时返回 degraded 租约
		pool.record("local-clash", { ok: false, statusCode: 403, blocked: true });
		pool.record("local-clash", { ok: false, statusCode: 403, blocked: true });
		pool.record("local-clash", { ok: false, statusCode: 403, blocked: true });
		expect(pool.acquire()).toBeNull();
		const degradedLease = pool.acquire({ allowDegradedFallback: true });
		expect(degradedLease).not.toBeNull();
		expect(degradedLease!.degraded).toBe(true);
		degradedLease!.release();

		// 6) 推进时间过冷却期 -> 半开恢复探活成功后回到 healthy
		nowMs += 31_000;
		const recoveredLease = pool.acquire("probe-after-cooldown");
		expect(recoveredLease).not.toBeNull();
		recoveredLease!.release({ ok: true, statusCode: 200, ttfbMs: 100 });
		// 清空历史劣化样本后再验证连续成功恢复状态
		pool.reset(recoveredLease!.id);
		pool.record(recoveredLease!.id, { ok: true, statusCode: 200, ttfbMs: 90 });
		expect(pool.getHealth(recoveredLease!.id)?.state).toBe("healthy");
	});

	test("runAutoIntent + runAutoBatchManaged 集成出口池：门控被拦自动故障转移 + 多并发分池调度", async () => {
		const target = await startLocalServer((req, res) => {
			if (req.url === "/zh-tw") {
				res.writeHead(200, { "Content-Type": "text/html" });
				res.end("<title>Gate OK</title>");
				return;
			}
			res.writeHead(200, { "Content-Type": "text/html", Server: "nginx" });
			res.end("<title>Target</title>");
		});

		// 坏代理：所有请求返回 403 Cloudflare 拦截；好代理：真实转发
		const badProxy = await startLocalServer((_req, res) => {
			res.writeHead(403, { Server: "cloudflare", "CF-Ray": "bad-egress-001", "Content-Type": "text/html" });
			res.end("<html><title>Attention Required! | Cloudflare</title><body>blocked</body></html>");
		});
		const scope = defaultScopeForTarget(target.url, "pentest");
		scope.allowLoopback = true;
		const goodProxyA = await startScopedEgressProxy(scope);
		const goodProxyB = await startScopedEgressProxy(scope);
		cleanups.push(() => goodProxyA.close(), () => goodProxyB.close());

		const pool = new EgressPoolManager(
			[
				{ id: "bad-1", url: badProxy.url },
				{ id: "good-a", url: goodProxyA.url },
				{ id: "good-b", url: goodProxyB.url },
			],
			{ consecutiveFailureThreshold: 1, minSamplesForRate: 1 },
		);

		const dir = makeTmpDir();
		const st = makeState(target.url);
		// bad-1 门控返回 403 -> 自动熔断并故障转移至 good-a 成功完成探测
		const res = await runAutoIntent(ruleFor("recon:http")!, st, realAsyncExec, dir, undefined, {
			egressPool: pool,
			gateUrl: `${target.url}/zh-tw`,
		});
		expect(res.ok).toBe(true);
		expect(res.egressId).toBe("good-a");
		expect(pool.getHealth("bad-1")?.state).toBe("open");

		// 批并发 2 个 worker，使用 good-a / good-b 分池避免抢占同一节点
		const usedEgressByIntent: string[] = [];
		const mockExec: ExecLike = async (_cmd, args) => {
			const script = args[1] ?? "";
			const m = /NUWA_EGRESS='([^']+)'/.exec(script);
			if (m?.[1]) usedEgressByIntent.push(m[1]);
			await new Promise((r) => setTimeout(r, 40));
			return {
				stdout: "FINAL 200 64 http://127.0.0.1/\n---HEAD---\nHTTP/1.1 200 OK\nServer: nginx\n---BODY---\n<title>OK</title>",
				stderr: "",
				code: 0,
			};
		};
		const stBatch = makeState(target.url);
		const httpId1 = Object.values(stBatch.intents).find((i) => i.key === "recon:http")!.id;
		stBatch.intents["i998"] = {
			...stBatch.intents[httpId1]!,
			id: "i998",
			key: "e2:recon:http",
			status: "open",
		};
		const batch = await runAutoBatchManaged([httpId1, "i998"], stBatch, mockExec, dir, {
			concurrency: 2,
			egressPool: pool,
		});
		expect(batch.items.length).toBe(2);
		expect(new Set(usedEgressByIntent).size).toBe(2);
		expect(usedEgressByIntent).not.toContain(badProxy.url);
	});
});

describe("Issue #37 (NW-17): 合规浏览器持久化会话、Xvfb配置、挑战门停重试与 session-vault 复用", () => {
	test("buildChromiumLaunchConfig 支持 --user-data-dir、headless、useXvfb 与 display", () => {
		const profileDir = makeTmpDir("nuwa-chrome-profile-");

		// 默认无头模式
		const defCfg = buildChromiumLaunchConfig();
		expect(defCfg.headless).toBe(true);
		expect(defCfg.useXvfb).toBe(false);
		expect(defCfg.usePersistentContext).toBe(false);
		expect(defCfg.args).toContain("--no-sandbox");

		// 持久化目录 + Xvfb 有头模式
		const xvfbCfg = buildChromiumLaunchConfig({
			userDataDir: profileDir,
			useXvfb: true,
			display: ":99",
		});
		expect(xvfbCfg.headless).toBe(false);
		expect(xvfbCfg.useXvfb).toBe(true);
		expect(xvfbCfg.display).toBe(":99");
		expect(xvfbCfg.env.DISPLAY).toBe(":99");
		expect(xvfbCfg.userDataDir).toBe(resolve(profileDir));
		expect(xvfbCfg.usePersistentContext).toBe(true);
		expect(xvfbCfg.args).toContain(`--user-data-dir=${resolve(profileDir)}`);
		expect(xvfbCfg.xvfbPrefix?.[0]).toBe("xvfb-run");

		// 显式覆写 headless=true 时以显式参数为准
		const explicitHeadless = buildChromiumLaunchConfig({ useXvfb: true, headless: true });
		expect(explicitHeadless.headless).toBe(true);
	});

	test("detectChallengeGate 确定性识别 Turnstile/cf-mitigated/hCaptcha/连续 ERR_FAILED 且严禁重试", () => {
		const cfHeader = detectChallengeGate({
			status: 403,
			headers: { "cf-mitigated": "challenge", server: "cloudflare" },
			html: "<html><title>Just a moment...</title></html>",
		});
		expect(cfHeader.detected).toBe(true);
		expect(cfHeader.status).toBe("challenge_gated");
		expect(cfHeader.requiresHumanSession).toBe(true);
		expect(cfHeader.provider).toBe("cloudflare_challenge");
		expect(cfHeader.retryAllowed).toBe(false);

		const turnstile = detectChallengeGate({
			status: 200,
			html: '<div class="cf-turnstile" data-sitekey="0x4AAAAAAABkMYinukE8n2"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>',
		});
		expect(turnstile.detected).toBe(true);
		expect(turnstile.status).toBe("challenge_gated");
		expect(turnstile.requiresHumanSession).toBe(true);
		expect(turnstile.provider).toBe("cloudflare_turnstile");
		expect(turnstile.siteKey).toBe("0x4AAAAAAABkMYinukE8n2");
		expect(turnstile.retryAllowed).toBe(false);

		const errFailed = detectChallengeGate({
			failedRequests: [
				{ url: "https://challenges.cloudflare.com/turnstile/v0/api.js", errorText: "net::ERR_FAILED" },
			],
		});
		expect(errFailed.detected).toBe(true);
		expect(errFailed.provider).toBe("cloudflare_turnstile");
		expect(errFailed.retryAllowed).toBe(false);

		const clean = detectChallengeGate({
			status: 200,
			html: "<!doctype html><html><title>Dashboard</title><body><div id='app'>Ready</div></body></html>",
		});
		expect(clean.detected).toBe(false);
		expect(clean.status).toBe("clear");
		expect(clean.requiresHumanSession).toBe(false);
		expect(clean.retryAllowed).toBe(true);
	});

	test("Playwright 模式命中 Turnstile + net::ERR_FAILED 立刻停止盲目重试且不回退重复打靶", async () => {
		const profileDir = makeTmpDir("nuwa-pw-profile-");
		let gotoCalls = 0;
		let staticFetchCalls = 0;
		let capturedUserDataDir = "";
		let capturedLaunchOpts: Record<string, unknown> | undefined;

		const fakePw: PlaywrightLike = {
			chromium: {
				launch: async () => {
					throw new Error("should use launchPersistentContext when userDataDir is set");
				},
				launchPersistentContext: async (userDataDir, options) => {
					capturedUserDataDir = userDataDir;
					capturedLaunchOpts = options as Record<string, unknown>;
					let routeHandler: ((route: PlaywrightRouteLike) => Promise<void> | void) | null = null;
					return {
						newPage: async () => ({
							route: async (_pat, handler) => {
								routeHandler = handler;
							},
							goto: async () => {
								gotoCalls++;
								// 模拟页面请求 Turnstile 脚本被阻断并抛出 net::ERR_FAILED
								if (routeHandler) {
									await routeHandler({
										request: () => ({
											url: () => "https://challenges.cloudflare.com/turnstile/v0/api.js",
											method: () => "GET",
											resourceType: () => "script",
											postData: () => null,
										}),
										continue: async () => {},
										abort: async () => {},
									});
								}
								throw new Error("page.goto: net::ERR_FAILED at http://127.0.0.1:9999/login");
							},
							evaluate: async () => ({}),
							close: async () => {},
						}),
						close: async () => {},
					};
				},
			},
		};

		const scope = defaultScopeForTarget("http://127.0.0.1:9999", "pentest");
		const res = await runSpaRecon("http://127.0.0.1:9999/login", scope, {
			playwrightLoader: async () => fakePw,
			userDataDir: profileDir,
			useXvfb: true,
			display: ":99",
			maxRetries: 3, // 即使配置了重试 3 次，命中挑战门也必须第 1 次就立刻停止
			fetchFn: async () => {
				staticFetchCalls++;
				return { ok: true, status: 200, text: async () => "<html></html>" };
			},
		});

		expect(capturedUserDataDir).toBe(resolve(profileDir));
		expect(capturedLaunchOpts?.headless).toBe(false);
		expect((capturedLaunchOpts?.env as Record<string, string>)?.DISPLAY).toBe(":99");
		expect(gotoCalls).toBe(1);
		expect(staticFetchCalls).toBe(0);
		expect(res.status).toBe("challenge_gated");
		expect(res.requiresHumanSession).toBe(true);
		expect(res.provider).toBe("cloudflare_turnstile");
		expect(res.challenge?.retryAllowed).toBe(false);
		expect(res.fact).toBeNull();
	});

	test("端到端合规人工会话闭环：未认证返回 challenge_gated -> 人工完成存入 session-vault -> 复用 Cookie/Header 完成侦察且零明文泄露", async () => {
		const vaultRoot = makeTmpDir("nuwa-vault-human-");
		const clearanceSecret = "cf_clearance_human_verified_token_9988776655";
		const sessionSecret = "sess_human_portal_abcdef123456";
		let bundleRequestsWhenGated = 0;

		const srv = await startLocalServer((req, res) => {
			const cookie = req.headers.cookie ?? "";
			const hasValidHumanSession = cookie.includes(clearanceSecret) && cookie.includes(sessionSecret);
			if (!hasValidHumanSession) {
				if (req.url?.endsWith(".js")) bundleRequestsWhenGated++;
				res.writeHead(403, {
					"Content-Type": "text/html; charset=utf-8",
					"CF-Mitigated": "challenge",
					Server: "cloudflare",
				});
				res.end(
					'<!doctype html><html><title>Just a moment...</title><body><div class="cf-turnstile" data-sitekey="0x4AAAAAAATestKey123"></div><script src="/assets/should-not-fetch.js"></script></body></html>',
				);
				return;
			}
			if (req.url === "/portal") {
				res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
				res.end(
					'<!doctype html><html><title>Member Portal</title><body><div id="__next"></div><script src="/assets/app.js"></script></body></html>',
				);
				return;
			}
			if (req.url === "/assets/app.js") {
				res.writeHead(200, { "Content-Type": "application/javascript" });
				res.end('fetch("/api/v1/member/profile", { method: "POST" }); fetch("/api/v1/member/wallet");');
				return;
			}
			res.writeHead(404);
			res.end("not found");
		});

		const scope = defaultScopeForTarget(srv.url, "pentest");

		// 1) 无人工验证会话 -> 确定性返回 challenge_gated，且立刻停止不抓取任何 JS bundle
		const gated = await runSpaRecon(`${srv.url}/portal`, scope, { disablePlaywright: true });
		expect(gated.status).toBe("challenge_gated");
		expect(gated.requiresHumanSession).toBe(true);
		expect(gated.provider).toBe("cloudflare_turnstile");
		expect(gated.fact).toBeNull();
		expect(bundleRequestsWhenGated).toBe(0);

		// 2) 用户在可见浏览器手动完成验证后，将合法 Cookie 写入 session-vault（权限 0o600）
		saveHumanSessionToVault(vaultRoot, {
			role: "human_verified",
			cookies: [
				{ name: "cf_clearance", value: clearanceSecret },
				{ name: "portal_sid", value: sessionSecret },
			],
			headers: { "X-Client-Locale": "zh-TW" },
			note: "人工完成 Turnstile 验证后的合法会话",
		});
		const vaultFile = join(vaultRoot, ".nuwa", "sessions", "vault.json");
		expect(statSync(vaultFile).mode & 0o777).toBe(0o600);

		const loaded = loadHumanSessionFromVault(vaultRoot, "human_verified", `${srv.url}/portal`);
		expect(loaded.found).toBe(true);
		expect(loaded.cookies.map((c) => c.name).sort()).toEqual(["cf_clearance", "portal_sid"]);

		// 3) 静态模式通过 vaultRoot + sessionRole 自动复用合法会话完成侦察
		const unlocked = await runSpaRecon(`${srv.url}/portal`, scope, {
			disablePlaywright: true,
			vaultRoot,
			sessionRole: "human_verified",
		});
		expect(unlocked.status).toBe("ok");
		expect(unlocked.sessionRole).toBe("human_verified");
		const paths = unlocked.endpoints.map((e) => e.path);
		expect(paths).toContain("/api/v1/member/profile");
		expect(paths).toContain("/api/v1/member/wallet");
		expect(unlocked.fact).not.toBeNull();
		// 严禁任何明文凭据泄露到返回结构或事实中
		const serialized = JSON.stringify(unlocked);
		expect(serialized).not.toContain(clearanceSecret);
		expect(serialized).not.toContain(sessionSecret);

		// 4) Playwright 模式验证 addCookies 注入合法 Cookie
		let injectedCookies: BrowserCookieEntry[] = [];
		const mockPwWithCookies: PlaywrightLike = {
			chromium: {
				launch: async () => ({
					newContext: async () => ({
						addCookies: async (cookies) => {
							injectedCookies = cookies;
						},
						newPage: async () => ({
							route: async () => {},
							goto: async () => ({ status: () => 200, headers: () => ({}) }),
							evaluate: async () => ({
								html: '<!doctype html><html><title>Member Portal</title><body><script>fetch("/api/v1/member/orders")</script></body></html>',
								pathname: "/portal",
								hash: "",
								links: [],
								globals: ["nextjs", "react"],
							}),
							close: async () => {},
						}),
						close: async () => {},
					}),
					close: async () => {},
				}),
			},
		};
		const pwUnlocked = await runSpaRecon(`${srv.url}/portal`, scope, {
			playwrightLoader: async () => mockPwWithCookies,
			vaultRoot,
			sessionRole: "human_verified",
		});
		expect(pwUnlocked.status).toBe("ok");
		expect(injectedCookies.map((c) => c.name).sort()).toEqual(["cf_clearance", "portal_sid"]);
		expect(pwUnlocked.endpoints.map((e) => e.path)).toContain("/api/v1/member/orders");
		expect(JSON.stringify(pwUnlocked)).not.toContain(clearanceSecret);
	});

	test("硬性契约与合规红线静态审计：无运行时 import ./nuwa 且无任何 CAPTCHA 绕过/自动点击代码", () => {
		for (const rel of ["omp/autoexec.ts", "omp/browser-recon.ts", "omp/sandbox.ts"]) {
			const src = readFileSync(join(REPO_ROOT, rel), "utf8");
			const stripped = src.replace(/^\s*import\s+type\s+[^;]+from\s+["']\.\/nuwa["'];?\s*$/gm, "");
			expect(stripped).not.toMatch(/from\s+["']\.\/nuwa["']|import\s*\(\s*["']\.\/nuwa["']\s*\)/);
		}

		const browserSrc = readFileSync(join(REPO_ROOT, "omp/browser-recon.ts"), "utf8");
		// 严禁出现自动求解/绕过/点击验证码的 API 或黑产服务引用
		expect(browserSrc).not.toMatch(/2captcha|anticaptcha|capsolver|solveCaptcha|bypassTurnstile|clickTurnstile|disable-blink-features=AutomationControlled/i);
	});
});
