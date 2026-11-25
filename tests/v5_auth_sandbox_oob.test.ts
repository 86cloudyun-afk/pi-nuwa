/**
 * 女娲 v5.0 回归测试（上）：认证态攻击面闭环（Issue #16）+ 零信任 Sidecar/Egress Proxy/OOB（Issue #17）。
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import * as http from "node:http";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as mod from "../omp/nuwa";
import {
	checkRoleHealth,
	decodeJwtExpiryIso,
	getRoleHeadersMap,
	upsertSessionRole,
} from "../omp/session-vault";
import { runSpaRecon } from "../omp/browser-recon";
import {
	computeKeyJaccard,
	extractJsonTopKeys,
	runAuthDiffMatrix,
} from "../omp/auth-diff";
import { injectAuthHeaderFileIntoScript } from "../omp/autoexec";
import {
	buildSidecarExecArgs,
	buildSidecarStartArgs,
	isCompliantSidecarCommand,
	readSandboxConfig,
	sidecarContainerName,
	startScopedEgressProxy,
	validateEgressTarget,
	wrapCommandInSidecarSandbox,
} from "../omp/sandbox";
import {
	buildOobEvidenceFact,
	generateOobCanary,
	isOobHostAllowed,
	loadOobCanaries,
	parseOobCallbackPayload,
	pollOobCallbacks,
} from "../omp/oob";
import { defaultScopeForTarget } from "../omp/scope";
import { recordToolExecution } from "../omp/evidence";

const REPO_ROOT = resolve(import.meta.dir, "..");
const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-v5-suite-a-"));
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
process.env.NUWA_KB_DB = join(SUITE_AGENT_HOME, "nuwa-kb", "kb.db");

const tmpDirs: string[] = [];
const cleanups: Array<() => Promise<void> | void> = [];

function makeTmpDir(prefix = "nuwa-v5a-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(d);
	return d;
}

function makeUnsignedJwt(payload: Record<string, unknown>): string {
	const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
	const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
	return `${h}.${p}.demoSignatureToken123456`;
}

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

function setupExt(cwd: string, sessionId = "sess-v5a-main") {
	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	let cmdHandler: ((args: string, ctx: any) => Promise<void>) | null = null;
	const notifications: Array<{ text: string; level: string }> = [];

	const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
	const z = new Proxy({}, { get: () => () => chain() });

	mod.default({
		zod: z,
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (_name: string, def: any) => {
			cmdHandler = def.handler;
		},
		on: (ev: string, fn: any) => {
			const arr = hooks.get(ev) ?? [];
			arr.push(fn);
			hooks.set(ev, arr);
		},
		sendUserMessage: () => {},
		sendMessage: () => {},
	} as any);

	const makeCtx = (kind: "main" | "subagent" = "main", sid = sessionId) => ({
		cwd,
		agent:
			kind === "main"
				? { kind: "main", id: "agent-main" }
				: { kind: "sub", id: "agent-fujiang", name: "fujiang", parentId: "agent-main", depth: 1 },
		sessionManager: {
			getSessionId: () => sid,
			getParentSessionId: () => (kind === "subagent" ? sessionId : undefined),
		},
		ui: {
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
			setStatus: () => {},
			setWidget: () => {},
			setTitle: () => {},
			notify: (t: string, level = "info") => notifications.push({ text: t, level }),
		},
	});

	return {
		tools,
		hooks,
		notifications,
		makeCtx,
		callTool: (name: string, params: Record<string, unknown>, ctx = makeCtx("main")) =>
			tools.get(name).execute("call-1", params, undefined, undefined, ctx),
		runCmd: (args: string, ctx = makeCtx("main")) => cmdHandler!(args, ctx),
		fireHook: (ev: string, payload: any, ctx = makeCtx("main")) => {
			let out: any;
			for (const fn of hooks.get(ev) ?? []) {
				const r = fn(payload, ctx);
				if (r !== undefined) out = r;
			}
			return out;
		},
	};
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
	delete process.env.NUWA_SANDBOX;
	delete process.env.NUWA_SANDBOX_SIDECAR;
	delete process.env.NUWA_EGRESS_PROXY;
	delete process.env.NUWA_SCOPE_OOB_DOMAINS;
});

afterAll(() => {
	rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
});

describe("Issue #16: 认证态攻击面闭环（Session Health / Auth SPA / Auto-BOLA-BFLA / Auth AutoExec）", () => {
	test("JWT 过期解析、CSRF Cookie 镜像头与会话健康巡检（过期自动派生刷新意图）", async () => {
		const root = makeTmpDir();
		const expiredJwt = makeUnsignedJwt({ sub: "alice", exp: Math.floor(Date.now() / 1000) - 3600 });
		const futureJwt = makeUnsignedJwt({ sub: "bob", exp: Math.floor(Date.now() / 1000) + 7200 });

		expect(decodeJwtExpiryIso(expiredJwt)).toBeDefined();
		expect(decodeJwtExpiryIso(futureJwt)).toBeDefined();
		expect(decodeJwtExpiryIso("not-a-jwt")).toBeUndefined();

		const srv = await startLocalServer((req, res) => {
			if (req.url === "/api/me") {
				const auth = req.headers.authorization ?? "";
				if (auth.includes(futureJwt)) {
					res.writeHead(200, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ user: "bob", ok: true }));
					return;
				}
				res.writeHead(401, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ error: "unauthorized" }));
				return;
			}
			if (req.url === "/dashboard") {
				res.writeHead(302, { Location: "/login?next=/dashboard" });
				res.end();
				return;
			}
			res.writeHead(404);
			res.end("not found");
		});

		upsertSessionRole(root, {
			role: "bob",
			bearer: futureJwt,
			cookie: "sid=bob_cookie_secret_999; csrftoken=csrf_demo_val_777",
			csrfHeader: "X-CSRF-Token",
			csrfCookie: "csrftoken",
			checkUrl: `${srv.url}/api/me`,
		});
		upsertSessionRole(root, {
			role: "alice",
			bearer: expiredJwt,
			checkUrl: `${srv.url}/api/me`,
		});
		upsertSessionRole(root, {
			role: "guest",
			cookie: "sid=guest_expired_cookie_111",
			checkUrl: `${srv.url}/dashboard`,
		});

		const bobHeaders = getRoleHeadersMap(root, "bob");
		expect(bobHeaders.Authorization).toBe(`Bearer ${futureJwt}`);
		expect(bobHeaders["X-CSRF-Token"]).toBe("csrf_demo_val_777");

		const scope = defaultScopeForTarget(srv.url, "pentest");
		const bobHealth = await checkRoleHealth(root, "bob", { scope });
		expect(bobHealth.healthy).toBe(true);
		expect(bobHealth.expired).toBe(false);

		const aliceHealth = await checkRoleHealth(root, "alice", { scope });
		expect(aliceHealth.healthy).toBe(false);
		expect(aliceHealth.expired).toBe(true);

		const guestHealth = await checkRoleHealth(root, "guest", { scope });
		expect(guestHealth.healthy).toBe(false);
		expect(guestHealth.expired).toBe(true);

		// 通过 /nuwa session health 命令集成验证自动派生 session-refresh 意图
		const ext = setupExt(root);
		await ext.callTool("nuwa_init", { target: srv.url, mode: "pentest", root, autoStart: false });
		await ext.runCmd("session health");
		const st = mod.loadState(root)!;
		const refreshIntents = Object.values(st.intents).filter((i) => i.key.startsWith("session-refresh:"));
		expect(refreshIntents.length).toBeGreaterThanOrEqual(2);
		expect(ext.notifications.some((n) => n.text.includes("EXPIRED") && n.text.includes("HEALTHY"))).toBe(true);
	});

	test("认证态 SPA 侦察：注入会话头、发现懒加载 Chunk 与同源 .js.map 隐藏 API 且零凭据泄露", async () => {
		const root = makeTmpDir();
		const secretToken = "BearerSuperSecretSpaToken_XYZ987654";

		const srv = await startLocalServer((req, res) => {
			const auth = req.headers.authorization ?? "";
			if (req.url === "/") {
				if (!auth.includes(secretToken)) {
					res.writeHead(200, { "Content-Type": "text/html" });
					res.end("<html><title>Login</title><body>Please sign in</body></html>");
					return;
				}
				res.writeHead(200, { "Content-Type": "text/html" });
				res.end(
					'<!doctype html><html><title>Portal</title><body><div id="root"></div><script src="/assets/app.bundle.js"></script></body></html>',
				);
				return;
			}
			if (req.url === "/assets/app.bundle.js") {
				res.writeHead(200, { "Content-Type": "application/javascript" });
				res.end(
					`const p = "/api/v1/profile"; import("/assets/lazy-admin.chunk.js");\n//# sourceMappingURL=app.bundle.js.map\n`,
				);
				return;
			}
			if (req.url === "/assets/lazy-admin.chunk.js") {
				res.writeHead(200, { "Content-Type": "application/javascript" });
				res.end(`fetch("/api/v2/admin/settings"); const r = "/settings/audit";`);
				return;
			}
			if (req.url === "/assets/app.bundle.js.map") {
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(
					JSON.stringify({
						version: 3,
						sources: ["src/api/billing.ts"],
						sourcesContent: ['export const fetchLedger = () => fetch("/api/v2/internal/ledger");'],
					}),
				);
				return;
			}
			res.writeHead(404);
			res.end("not found");
		});

		const scope = defaultScopeForTarget(srv.url, "pentest");
		const spa = await runSpaRecon(srv.url, scope, {
			preferBrowser: false,
			authRole: "admin",
			authHeaders: { Authorization: `Bearer ${secretToken}` },
			discoverSourceMaps: true,
		});

		expect(spa.mode).toBe("static");
		const epPaths = spa.endpoints.map((e) => e.path);
		expect(epPaths).toContain("/api/v1/profile");
		expect(epPaths).toContain("/api/v2/admin/settings");
		expect(epPaths).toContain("/api/v2/internal/ledger");
		expect(JSON.stringify(spa)).not.toContain(secretToken);
	});

	test("确定性只读多角色鉴权差分矩阵（Auto-BOLA / BFLA + Soft-404 过滤 + /nuwa authdiff 派发双盲复验）", async () => {
		const root = makeTmpDir();
		const adminTok = "admin_tok_secret_a1b2c3d4";
		const aliceTok = "alice_tok_secret_e5f6g7h8";
		const bobTok = "bob_tok_secret_i9j0k1l2";

		expect(extractJsonTopKeys('{"id":1,"user":{"name":"a","role":"user"}}')).toEqual([
			"id",
			"user",
			"user.name",
			"user.role",
		]);
		expect(computeKeyJaccard(["a", "b", "c"], ["a", "b", "d"])).toBeCloseTo(0.5, 4);

		const srv = await startLocalServer((req, res) => {
			const auth = req.headers.authorization ?? "";
			const isAdmin = auth === `Bearer ${adminTok}`;
			const isAlice = auth === `Bearer ${aliceTok}`;
			const isBob = auth === `Bearer ${bobTok}`;
			const url = req.url ?? "/";

			// Soft-404 SPA 兜底路径：无论任何角色都返回 200 HTML 壳
			if (url.startsWith("/__nuwa_authdiff_404_") || url === "/spa-catchall-page") {
				res.writeHead(200, { "Content-Type": "text/html" });
				res.end("<!doctype html><html><title>Demo App</title><body><div id='app'></div></body></html>");
				return;
			}
			// 垂直越权 BFLA：admin 接口放行了低权 alice/bob
			if (url === "/api/admin/config") {
				if (!isAdmin && !isAlice && !isBob) {
					res.writeHead(401, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: "auth required" }));
					return;
				}
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ featureFlags: ["beta"], auditRetentionDays: 90, tenant: "core" }));
				return;
			}
			// 水平越权 BOLA：对象 ID 1001 对同级 user_a 和 user_b 返回同一份数据
			if (url === "/api/orders/1001") {
				if (!isAdmin && !isAlice && !isBob) {
					res.writeHead(401, { "Content-Type": "application/json" });
					res.end(JSON.stringify({ error: "auth required" }));
					return;
				}
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ orderId: 1001, owner: "alice", amount: 120, status: "paid" }));
				return;
			}
			res.writeHead(404, { "Content-Type": "application/json" });
			res.end(JSON.stringify({ error: "not found" }));
		});

		upsertSessionRole(root, { role: "admin", bearer: adminTok });
		upsertSessionRole(root, { role: "user_a", bearer: aliceTok });
		upsertSessionRole(root, { role: "user_b", bearer: bobTok });

		const scope = defaultScopeForTarget(srv.url, "pentest");
		const diff = await runAuthDiffMatrix(
			srv.url,
			["/spa-catchall-page", "/api/admin/config", "/api/orders/1001"],
			root,
			scope,
		);

		expect(diff.findings.some((f) => f.path === "/spa-catchall-page")).toBe(false);
		expect(diff.findings.some((f) => f.path === "/api/admin/config" && f.kind === "vertical_bfla")).toBe(true);
		expect(diff.findings.some((f) => f.path === "/api/orders/1001" && f.kind === "horizontal_bola")).toBe(true);
		expect(diff.fact).not.toBeNull();
		const serialized = JSON.stringify(diff);
		expect(serialized).not.toContain(adminTok);
		expect(serialized).not.toContain(aliceTok);
		expect(serialized).not.toContain(bobTok);

		// /nuwa authdiff 命令：暂存 candidate 并派发 verify-vuln
		const ext = setupExt(root);
		await ext.callTool("nuwa_init", { target: srv.url, mode: "pentest", root, autoStart: false });
		await ext.runCmd("authdiff /api/admin/config /api/orders/1001");
		const st = mod.loadState(root)!;
		const candVulns = Object.values(st.facts).filter((f) => f.kind === "vuln" && f.verifyStage === "candidate");
		expect(candVulns.length).toBeGreaterThanOrEqual(1);
		const verifyIntents = Object.values(st.intents).filter((i) => i.key.startsWith("verify-vuln:"));
		expect(verifyIntents.length).toBeGreaterThanOrEqual(1);
	});

	test("认证态 AutoExec 零明文头文件注入与凭据入账自动派生 post-auth 侦察意图", async () => {
		const wrapped = injectAuthHeaderFileIntoScript("curl -sS 'http://127.0.0.1:8080/api'", "/tmp/nuwa/p1/sessions/user.headers");
		expect(wrapped).toContain('NUWA_AUTH_HEADER_FILE=');
		expect(wrapped).toContain('-H @"$NUWA_AUTH_HEADER_FILE"');

		const root = makeTmpDir();
		const ext = setupExt(root);
		await ext.callTool("nuwa_init", { target: "http://127.0.0.1:18080", mode: "pentest", root, autoStart: false });
		const st0 = mod.loadState(root)!;
		const firstId = Object.keys(st0.intents)[0]!;
		await ext.callTool("nuwa_claim", { id: firstId, root });

		const secretJwt = makeUnsignedJwt({ sub: "ops", exp: Math.floor(Date.now() / 1000) + 3600 });
		recordToolExecution(root, {
			tool: "bash",
			command: "curl -sS http://127.0.0.1:18080/login",
			output: `Authorization: Bearer ${secretJwt}\nrole=user_ops`,
		});
		await ext.callTool("nuwa_commit", {
			id: firstId,
			kind: "cred",
			title: "获取 user_ops 角色登录态凭据",
			detail: "登录后返回有效 Bearer JWT",
			command: "curl -sS http://127.0.0.1:18080/login",
			output: `Authorization: Bearer ${secretJwt}`,
			root,
		});

		const st1 = mod.loadState(root)!;
		const postAuthIntents = Object.values(st1.intents).filter((i) => i.key.startsWith("post-auth:recon:"));
		expect(postAuthIntents.length).toBeGreaterThanOrEqual(1);
		// 落盘 state 中不应出现明文 JWT
		expect(readFileSync(mod.statePath(root), "utf8")).not.toContain(secretJwt);
	});
});

describe("Issue #17: 零信任常驻 Sidecar、内置抗 DNS 重绑定 Egress Proxy 与一等 OOB Canary", () => {
	test("Sidecar 参数零信任断言、合规校验、Dockerfile 多阶段审计与 N-009 钩子拦截", async () => {
		process.env.NUWA_SANDBOX = "sidecar";
		process.env.NUWA_EGRESS_PROXY = "http://127.0.0.1:18999";
		const cfg = readSandboxConfig();
		expect(cfg.mode).toBe("sidecar");
		expect(cfg.egressProxyUrl).toBe("http://127.0.0.1:18999");

		const cname = sidecarContainerName("demo-proj-1");
		expect(cname).toBe("nuwa-sb-demo-proj-1");

		const scope = defaultScopeForTarget("http://10.0.0.5:8080", "pentest");
		const startArgs = buildSidecarStartArgs({
			projectId: "demo-proj-1",
			scope,
			config: cfg,
			proxyUrl: "http://127.0.0.1:18999",
		});
		expect(startArgs).toContain("--read-only");
		expect(startArgs).toContain("--cap-drop=ALL");
		expect(startArgs).toContain("--security-opt=no-new-privileges");
		expect(startArgs.join(" ")).not.toContain("docker.sock");
		expect(startArgs.join(" ")).toContain("HTTP_PROXY=http://127.0.0.1:18999");

		const execArgs = buildSidecarExecArgs({
			projectId: "demo-proj-1",
			command: "curl -sS http://10.0.0.5:8080/",
			scope,
			config: cfg,
			proxyUrl: "http://127.0.0.1:18999",
		});
		expect(execArgs[0]).toBe("exec");
		expect(execArgs).toContain(cname);

		const wrappedCmd = wrapCommandInSidecarSandbox("curl -sS http://10.0.0.5:8080/", {
			projectId: "demo-proj-1",
			scope,
			config: cfg,
			proxyUrl: "http://127.0.0.1:18999",
		});
		expect(isCompliantSidecarCommand(wrappedCmd, "demo-proj-1").ok).toBe(true);
		expect(isCompliantSidecarCommand(`docker exec --privileged ${cname} sh -c id`, "demo-proj-1").ok).toBe(false);
		expect(isCompliantSidecarCommand(`docker exec -u root ${cname} sh -c id`, "demo-proj-1").ok).toBe(false);
		expect(isCompliantSidecarCommand(`${wrappedCmd} && id`, "demo-proj-1").ok).toBe(false);

		// 多阶段 Dockerfile.sandbox 零 USER root 审计
		const df = readFileSync(join(REPO_ROOT, "docker", "Dockerfile.sandbox"), "utf8");
		expect(df).toMatch(/AS\s+base/i);
		expect(df).toMatch(/AS\s+lite/i);
		expect(df).toMatch(/AS\s+full/i);
		expect(df).toMatch(/^USER\s+nuwa\b/m);
		expect(df).not.toMatch(/\bUSER\s+root\s*$/m);

		// 扩展 tool_call(bash) N-009 Sidecar 拦截验证
		const root = makeTmpDir();
		const ext = setupExt(root);
		await ext.callTool("nuwa_init", { target: "http://10.0.0.5:8080", mode: "pentest", root, autoStart: false });
		ext.fireHook("before_subagent_spawn", { agent: "fujiang", task: "recon" }, ext.makeCtx("main"));
		const st = mod.loadState(root)!;
		const subCtx = ext.makeCtx("subagent", "sess-sub-sidecar");

		const blocked = ext.fireHook("tool_call", { toolName: "bash", input: { command: "curl -sS http://10.0.0.5:8080/" } }, subCtx);
		expect(blocked?.block).toBe(true);
		expect(String(blocked?.reason)).toContain("N-009");
		expect(String(blocked?.reason)).toContain("Sidecar");

		const okCmd = wrapCommandInSidecarSandbox("curl -sS http://10.0.0.5:8080/", {
			projectId: st.project.id,
			scope: st.project.scope,
			config: cfg,
			proxyUrl: "http://127.0.0.1:18999",
		});
		const allowed = ext.fireHook("tool_call", { toolName: "bash", input: { command: okCmd } }, subCtx);
		expect(allowed).toBeUndefined();

		// 即使外层是合规 Sidecar + 本机 Egress Proxy，内部命令越界访问外域或回环仍必须被 N-007 拦截
		const badInnerCmd = wrapCommandInSidecarSandbox("curl -sS http://127.0.0.1:9000/internal", {
			projectId: st.project.id,
			scope: st.project.scope,
			config: cfg,
			proxyUrl: "http://127.0.0.1:18999",
		});
		const blockedInner = ext.fireHook("tool_call", { toolName: "bash", input: { command: badInnerCmd } }, subCtx);
		expect(blockedInner?.block).toBe(true);
		expect(String(blockedInner?.reason)).toContain("N-007");
	});

	test("内置 Scoped Egress Proxy：放行 Scope 内流量、拦越界主机、拦 302 跳转越界、防 DNS 重绑定与 HTTPS CONNECT", async () => {
		const upstream = await startLocalServer((req, res) => {
			if (req.url === "/ok") {
				res.writeHead(200, { "Content-Type": "text/plain" });
				res.end("in-scope-payload-ok");
				return;
			}
			if (req.url === "/evil-redirect") {
				res.writeHead(302, { Location: "http://evil.example.invalid/steal" });
				res.end("redirecting");
				return;
			}
			res.writeHead(404);
			res.end("nope");
		});

		const traffic: any[] = [];
		const scope = defaultScopeForTarget(upstream.url, "pentest");
		scope.allowHosts = ["127.0.0.1", "rebind.target.test"];
		scope.allowLoopback = true;
		scope.allowPrivateNetwork = false;

		const proxy = await startScopedEgressProxy(scope, {
			onTraffic: (rec) => traffic.push(rec),
			dnsLookup: async (host) => {
				if (host === "rebind.target.test") return ["169.254.169.254"];
				return ["127.0.0.1"];
			},
		});
		cleanups.push(() => proxy.close());

		// 校验 validateEgressTarget 直接防 DNS 重绑定（云元数据 IP）
		const rebindCheck = await validateEgressTarget("rebind.target.test", scope, async () => ["169.254.169.254"]);
		expect(rebindCheck.ok).toBe(false);
		expect(rebindCheck.reason).toContain("N-007");

		const rawProxyHttp = (targetUrl: string): Promise<{ status: number; body: string }> =>
			new Promise((resolveReq, rejectReq) => {
				const req = http.request(
					{
						host: "127.0.0.1",
						port: proxy.port,
						method: "GET",
						path: targetUrl,
						headers: { Host: new URL(targetUrl).host },
					},
					(res) => {
						const chunks: Buffer[] = [];
						res.on("data", (c) => chunks.push(Buffer.from(c)));
						res.on("end", () => resolveReq({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
					},
				);
				req.on("error", rejectReq);
				req.end();
			});

		// 1) Scope 内放行
		const rOk = await rawProxyHttp(`${upstream.url}/ok`);
		expect(rOk.status).toBe(200);
		expect(rOk.body).toBe("in-scope-payload-ok");

		// 2) Scope 外拒绝
		const rOut = await rawProxyHttp("http://evil.example.invalid/secret");
		expect(rOut.status).toBe(403);
		expect(rOut.body).toContain("N-007");

		// 3) 302 跳转至 Scope 外拒绝
		const rRedir = await rawProxyHttp(`${upstream.url}/evil-redirect`);
		expect(rRedir.status).toBe(403);
		expect(rRedir.body).toContain("N-007");

		// 4) DNS 重绑定至云元数据拒绝
		const rRebind = await rawProxyHttp("http://rebind.target.test/latest/meta-data/");
		expect(rRebind.status).toBe(403);
		expect(rRebind.body).toContain("N-007");

		// 5) HTTPS CONNECT 隧道放行与阻断
		const rawConnect = (authority: string): Promise<string> =>
			new Promise((resolveConn, rejectConn) => {
				const sock = net.connect(proxy.port, "127.0.0.1", () => {
					sock.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
				});
				let buf = "";
				sock.on("data", (chunk) => {
					buf += chunk.toString("utf8");
					if (buf.includes("\r\n\r\n")) {
						sock.destroy();
						resolveConn(buf);
					}
				});
				sock.on("error", rejectConn);
			});

		const connAllow = await rawConnect(`127.0.0.1:${upstream.port}`);
		expect(connAllow).toContain("200 Connection Established");

		const connDeny = await rawConnect("evil.example.invalid:443");
		expect(connDeny).toContain("403");
		expect(connDeny).toContain("N-007");

		expect(proxy.stats().allowed).toBeGreaterThanOrEqual(2);
		expect(proxy.stats().blocked).toBeGreaterThanOrEqual(4);
		expect(traffic.some((t) => t.allowed && t.responsePreview?.includes("in-scope-payload-ok"))).toBe(true);
	});

	test("一等 OOB Canary 白名单门控、0o600 落盘、Interactsh 轮询解析与 /nuwa oob 集成", async () => {
		const root = makeTmpDir();
		const scope = defaultScopeForTarget("http://127.0.0.1:8080", "pentest");

		// 空 oobDomains 严禁生成
		expect(isOobHostAllowed("cb.oast.test", scope).ok).toBe(false);

		scope.oobDomains = ["oast.test"];
		expect(isOobHostAllowed("oast.test", scope).ok).toBe(true);
		expect(isOobHostAllowed("abc.oast.test", scope).ok).toBe(true);
		expect(isOobHostAllowed("*.oast.test", scope).ok).toBe(false);
		expect(isOobHostAllowed("other.invalid", scope).ok).toBe(false);

		const canary = generateOobCanary(root, {
			projectId: "proj-oob",
			domain: "oast.test",
			scope,
			purpose: "blind-ssrf-check",
		});
		expect(canary.fqdn.endsWith(".oast.test")).toBe(true);
		const filePath = join(root, ".nuwa", "oob-canaries.json");
		expect(existsSync(filePath)).toBe(true);
		expect(statSync(filePath).mode & 0o777).toBe(0o600);
		expect(loadOobCanaries(root).length).toBe(1);

		const samplePayload = JSON.stringify({
			data: [
				{
					protocol: "dns",
					"full-id": canary.fqdn,
					"remote-address": "10.10.1.9",
					timestamp: new Date().toISOString(),
					"raw-request": `A? ${canary.fqdn}.`,
				},
			],
		});
		const parsedHits = parseOobCallbackPayload(samplePayload, [canary]);
		expect(parsedHits.length).toBe(1);
		expect(parsedHits[0]?.matchedCanaryId).toBe(canary.id);

		const polled = await pollOobCallbacks(root, {
			pollUrl: "https://poll.oast.test/events",
			scope,
			fetchFn: async () => ({ ok: true, status: 200, text: async () => samplePayload }),
		});
		expect(polled.ok).toBe(true);
		expect(polled.matchedCanaries.length).toBe(1);
		expect(polled.matchedCanaries[0]?.matchedHits).toBe(1);

		const evFact = buildOobEvidenceFact(polled.matchedCanaries[0]!, polled.hits);
		expect(evFact.output).toContain(canary.fqdn);

		// /nuwa oob 命令流
		const ext = setupExt(root);
		await ext.callTool("nuwa_init", {
			target: "http://127.0.0.1:8080",
			mode: "pentest",
			root,
			scope: { oobDomains: ["oast.test"] },
			autoStart: false,
		});
		await ext.runCmd("oob gen oast.test verify-dns");
		expect(ext.notifications.some((n) => n.text.includes(".oast.test"))).toBe(true);
		await ext.runCmd("oob list");
		expect(ext.notifications.some((n) => n.text.includes("活跃 Canary"))).toBe(true);
	});
});
