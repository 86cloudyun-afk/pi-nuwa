/**
 * v4.0 recon-weapon 模块全量验收测试：
 * 1. Soft-404 基线校准与本地 127.0.0.1 SPA 假 200 Mock Server 实测
 * 2. 内容级语义指纹实锤（假 .env / 假 .git/HEAD 零误报、真实 .env 脱敏、OpenAPI Schema 校验）
 * 3. 工具链自适应升档（nmap / ffuf / katana / nuclei）与安全红线校验
 * 4. SPA 与 JS Bundle 动态（Playwright 拦截）/ 静态回退 API 感知层实测
 * 5. config/autoexec.example.json 外置规则 Schema 兼容性校验
 */
import { afterAll, describe, expect, test } from "bun:test";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { newState, readCfg, type Cfg, type NuwaState, type ToolchainCaps } from "../omp/nuwa";
import {
	AUTO_KEYS,
	AUTO_RULES,
	classifyAutoFailure,
	enrichmentRulesForToolchain,
	isSoft404Hit,
	loadAutoRules,
	maskEnvSecrets,
	parseSoft404Baseline,
	ruleFor,
	runAutoIntent,
	shellQuote,
	type ExecLike,
} from "../omp/autoexec";
import {
	extractStaticBundleApis,
	runSpaRecon,
	type PlaywrightLike,
	type PlaywrightRouteLike,
} from "../omp/browser-recon";
import { defaultScopeForTarget } from "../omp/scope";

const cfg: Cfg = { ...readCfg(), auto: true, autoMax: 3, emptyLimit: 3, maxAttempts: 3 };
const tempDirs: string[] = [];
const DEFAULT_TEST_HOME = mkdtempSync(join(tmpdir(), "nuwa-recon-suite-home-"));
tempDirs.push(DEFAULT_TEST_HOME);
process.env.PI_AGENT_HOME = DEFAULT_TEST_HOME;
process.env.NUWA_KB_DB = join(DEFAULT_TEST_HOME, "nuwa-kb", "kb.db");

function makeDir(prefix: string): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(d);
	return d;
}

afterAll(() => {
	for (const d of tempDirs) {
		rmSync(d, { recursive: true, force: true });
	}
});

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

function makeState(url = "http://127.0.0.1:8080", available?: string[]): NuwaState {
	const st = newState(url, "v4 侦察验收", "audit", cfg);
	if (available) {
		st.project.toolchain = {
			available,
			missing: [],
			probedAt: new Date().toISOString(),
		};
	}
	return st;
}

describe("1. Soft-404 基线校准与 SPA 假 200 端到端实测", () => {
	test("parseSoft404Baseline 识别 200/30x 兜底基线并兼容无 BASELINE 历史输入", () => {
		const none = parseSoft404Baseline("/admin 200 1234 \n");
		expect(none.active).toBe(false);
		expect(none.samples).toEqual([]);
		expect(none.codes).toEqual([]);

		const real404 = parseSoft404Baseline("BASELINE 404 19 -\nBASELINE 404 19 -\n");
		expect(real404.active).toBe(false);
		expect(real404.samples.length).toBe(2);

		const spa200 = parseSoft404Baseline(
			"BASELINE 200 1000 Portal SPA App\nBASELINE 200 1004 Portal SPA App\n",
		);
		expect(spa200.active).toBe(true);
		expect(spa200.codes).toEqual([200]);
		expect(spa200.size).toBe(1000);
		expect(spa200.titleSig).toBe("portal spa app");

		const redir302 = parseSoft404Baseline("BASELINE 302 0 -\nBASELINE 302 0 -\n");
		expect(redir302.active).toBe(true);
		expect(redir302.codes).toEqual([302]);
	});

	test("isSoft404Hit 严格按状态码 + 体积容差 ±max(48, 10%) + HTML title 过滤且不误杀真实接口", () => {
		// 小体积基线 200B -> 容差 max(48, 20) = 48
		const smallBase = parseSoft404Baseline("BASELINE 200 200 Demo SPA\n");
		expect(isSoft404Hit({ code: 200, size: 248, titleSig: "Demo SPA" }, smallBase)).toBe(true);
		expect(isSoft404Hit({ code: 200, size: 249, titleSig: "Demo SPA" }, smallBase)).toBe(false);

		// 大体积基线 1000B -> 容差 max(48, 100) = 100
		const largeBase = parseSoft404Baseline("BASELINE 200 1000 Demo SPA\n");
		expect(isSoft404Hit({ code: 200, size: 1100, titleSig: "demo spa" }, largeBase)).toBe(true);
		expect(isSoft404Hit({ code: 200, size: 1101, titleSig: "demo spa" }, largeBase)).toBe(false);
		// 不同 title 不误杀
		expect(isSoft404Hit({ code: 200, size: 1000, titleSig: "Admin Console" }, largeBase)).toBe(false);
		// 明确无 title（例如真实 JSON 接口）不误杀
		expect(isSoft404Hit({ code: 200, size: 1000, titleSig: "" }, largeBase)).toBe(false);
		expect(isSoft404Hit({ code: 200, size: 1000, body: '{"status":"ok"}' }, largeBase)).toBe(false);
		// 不同状态码不误杀
		expect(isSoft404Hit({ code: 403, size: 1000, titleSig: "Demo SPA" }, largeBase)).toBe(false);
		// 字符串行快捷判定
		expect(isSoft404Hit("/fake 200 1020  TITLE=Demo SPA", largeBase)).toBe(true);
		expect(isSoft404Hit("/api 200 1020  TITLE=-", largeBase)).toBe(false);
	});

	test("本地 127.0.0.1 纯假 200 SPA Mock Server：dirsRule 零假阳性，假 .env/.git/HEAD/openapi 零误报", async () => {
		// 构造一个体积恰好为 429 字节的 SPA 兜底 HTML，顺带验证不会误触发 429 WAF 误判
		const prefix = "<!doctype html><html><head><title>Fake SPA 404</title></head><body><div id='root'>";
		const suffix = "</div></body></html>";
		const pad = "x".repeat(429 - prefix.length - suffix.length);
		const spaHtml = `${prefix}${pad}${suffix}`;
		expect(spaHtml.length).toBe(429);

		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				return new Response(spaHtml, {
					status: 200,
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			},
		});

		try {
			const dir = makeDir("nuwa-spa-soft404-");
			mkdirSync(join(dir, ".nuwa"), { recursive: true });
			writeFileSync(
				join(dir, ".nuwa", "autoexec.json"),
				JSON.stringify({
					rules: [
						{ key: "recon:dirs", phase: "recon", timeoutMs: 10000, parse: "dirs", paths: ["/admin", "/login", "/backup.zip"] },
						{ key: "surface:sensitive", phase: "surface", timeoutMs: 10000, parse: "probe", paths: ["/.git/HEAD", "/.env", "/config.json"] },
						{ key: "surface:api", phase: "surface", timeoutMs: 10000, parse: "probe", paths: ["/openapi.json", "/swagger.json"] },
					],
				}),
			);

			const st = makeState(`http://127.0.0.1:${srv.port}`);

			const dirsRes = await runAutoIntent(ruleFor("recon:dirs", dir)!, st, realAsyncExec, dir);
			expect(dirsRes.ok).toBe(false);
			expect(dirsRes.errorKind).toBe("empty");

			const sensRes = await runAutoIntent(ruleFor("surface:sensitive", dir)!, st, realAsyncExec, dir);
			expect(sensRes.ok).toBe(false);
			expect(sensRes.fact).toBeUndefined();

			const apiRes = await runAutoIntent(ruleFor("surface:api", dir)!, st, realAsyncExec, dir);
			expect(apiRes.ok).toBe(false);
			expect(apiRes.fact).toBeUndefined();
		} finally {
			srv.stop(true);
		}
	});

	test("本地 127.0.0.1 混合 SPA Mock Server：过滤假路径，精准保留真实接口与脱敏后的真实 .env", async () => {
		const spaHtml =
			"<!doctype html><html><head><title>Enterprise Portal</title></head><body><div id='app'>Loading SPA...</div></body></html>";

		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const u = new URL(req.url);
				if (u.pathname === "/api/v1") {
					return new Response(JSON.stringify({ ok: true, service: "billing", version: "4.0" }), {
						status: 200,
						headers: { "content-type": "application/json" },
					});
				}
				if (u.pathname === "/robots.txt") {
					return new Response("User-agent: *\nDisallow: /internal\n", {
						status: 200,
						headers: { "content-type": "text/plain" },
					});
				}
				if (u.pathname === "/.env") {
					return new Response(
						'DB_HOST=127.0.0.1\nDB_PASSWORD=SuperSecretPass_9981;extra\nJWT_SECRET="top-secret-jwt-value"\nAPI_KEY=sk_live_445566\n',
						{ status: 200, headers: { "content-type": "text/plain" } },
					);
				}
				if (u.pathname === "/openapi.json") {
					return new Response(
						JSON.stringify({ openapi: "3.1.0", info: { title: "Billing API" }, paths: { "/api/v1": {} } }),
						{ status: 200, headers: { "content-type": "application/json" } },
					);
				}
				// 其余所有未知路径（含 /admin、/.git/HEAD、/__nuwa_404_check_*）一律返 SPA 假 200
				return new Response(spaHtml, {
					status: 200,
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			},
		});

		try {
			const dir = makeDir("nuwa-spa-mixed-");
			mkdirSync(join(dir, ".nuwa"), { recursive: true });
			writeFileSync(
				join(dir, ".nuwa", "autoexec.json"),
				JSON.stringify({
					rules: [
						{
							key: "recon:dirs",
							phase: "recon",
							timeoutMs: 10000,
							parse: "dirs",
							paths: ["/admin", "/login", "/api/v1", "/robots.txt"],
						},
						{
							key: "surface:sensitive",
							phase: "surface",
							timeoutMs: 10000,
							parse: "probe",
							paths: ["/.git/HEAD", "/.env", "/backup.zip"],
						},
						{
							key: "surface:api",
							phase: "surface",
							timeoutMs: 10000,
							parse: "probe",
							paths: ["/openapi.json", "/swagger.json"],
						},
					],
				}),
			);

			const st = makeState(`http://127.0.0.1:${srv.port}`);

			// 1. dirsRule 过滤假 /admin /login，保留真实 /api/v1 和 /robots.txt
			const dirsRes = await runAutoIntent(ruleFor("recon:dirs", dir)!, st, realAsyncExec, dir);
			expect(dirsRes.ok).toBe(true);
			expect(dirsRes.fact?.meta?.paths).toEqual(["/api/v1", "/robots.txt"]);
			expect(dirsRes.fact?.meta?.paths).not.toContain("/admin");
			expect(dirsRes.fact?.meta?.paths).not.toContain("/login");

			// 2. surface:sensitive 过滤假 /.git/HEAD 与 /backup.zip，仅实锤真实 /.env 且全量脱敏密钥值
			const sensRes = await runAutoIntent(ruleFor("surface:sensitive", dir)!, st, realAsyncExec, dir);
			expect(sensRes.ok).toBe(true);
			expect(sensRes.fact?.kind).toBe("vuln");
			expect(sensRes.fact?.title).toContain("敏感文件暴露");
			expect(sensRes.fact?.meta?.paths).toEqual(["/.env"]);
			const combinedText = `${sensRes.fact?.detail ?? ""}\n${sensRes.fact?.output ?? ""}`;
			expect(combinedText).toContain("DB_PASSWORD=***");
			expect(combinedText).toContain("JWT_SECRET=***");
			expect(combinedText).toContain("API_KEY=***");
			expect(combinedText).not.toContain("SuperSecretPass_9981");
			expect(combinedText).not.toContain("top-secret-jwt-value");
			expect(combinedText).not.toContain("sk_live_445566");

			// 3. surface:api 过滤假 /swagger.json，实锤真实 /openapi.json
			const apiRes = await runAutoIntent(ruleFor("surface:api", dir)!, st, realAsyncExec, dir);
			expect(apiRes.ok).toBe(true);
			expect(apiRes.fact?.title).toBe("API 文档暴露");
			expect(apiRes.fact?.meta?.paths).toEqual(["/openapi.json"]);
		} finally {
			srv.stop(true);
		}
	});
});

describe("2. 内容级语义指纹实锤与脱敏单元测试", () => {
	test("无 BASELINE 时，返回 HTML 或非实锤内容的 .git/HEAD 与 .env 绝不报 vuln", () => {
		const st = makeState();
		const rule = ruleFor("surface:sensitive")!;

		// HTML 假 .git/HEAD -> 零误报
		expect(
			rule.parse({ stdout: "/.git/HEAD 200 <!doctype html><html><title>SPA</title></html>\n", stderr: "", code: 0 }, st),
		).toBeNull();

		// HTML 假 .env -> 零误报
		expect(
			rule.parse({ stdout: "/.env 200 <html><body>404 Not Found</body></html>\n", stderr: "", code: 0 }, st),
		).toBeNull();

		// 普通无关纯文本 .env -> 绝不标记 vuln
		const nonEnv = rule.parse({ stdout: "/.env 200 welcome to demo service\n", stderr: "", code: 0 }, st);
		expect(nonEnv?.kind).not.toBe("vuln");

		// 40 位 hex commit 的 detached HEAD -> 实锤 vuln
		const detached = rule.parse(
			{ stdout: "/.git/HEAD 200 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\n", stderr: "", code: 0 },
			st,
		)!;
		expect(detached.kind).toBe("vuln");
		expect(detached.meta?.paths).toEqual(["/.git/HEAD"]);

		// maskEnvSecrets 边界验证（含闭合引号、分号值、以及 256 字节处截断未闭合双/单引号与多行 PEM 私钥）
		const masked = maskEnvSecrets('export SECRET_KEY="hello world" DB_PASS=p@ss;123 TOKEN=abc');
		expect(masked).toContain("export SECRET_KEY=***");
		expect(masked).toContain("DB_PASS=***");
		expect(masked).toContain("TOKEN=***");
		expect(masked).not.toContain("hello world");
		expect(masked).not.toContain("p@ss");
		expect(masked).not.toContain("abc");

		const truncatedDouble = maskEnvSecrets(
			'APP_ENV=prod PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA778899',
		);
		expect(truncatedDouble).toBe("APP_ENV=*** PRIVATE_KEY=***");
		expect(truncatedDouble).not.toContain("RSA PRIVATE KEY");
		expect(truncatedDouble).not.toContain("MIIEpAIBAAKCAQEA778899");

		const truncatedSingle = maskEnvSecrets(
			"DB_HOST=127.0.0.1 CERT='-----BEGIN CERTIFICATE----- MIID998877 truncated",
		);
		expect(truncatedSingle).toBe("DB_HOST=*** CERT=***");
		expect(truncatedSingle).not.toContain("CERTIFICATE");
		expect(truncatedSingle).not.toContain("MIID998877");

		// 端到端 parseProbeFact 验证：256 字节截断未闭合引号的 .env 仍实锤 vuln 且绝不泄露私钥片段
		const truncatedEnvFact = rule.parse(
			{
				stdout:
					'/.env 200 SIZE=1680 TITLE=-\tAPP_ENV=prod PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA778899\n',
				stderr: "",
				code: 0,
			},
			st,
		)!;
		expect(truncatedEnvFact.kind).toBe("vuln");
		expect(truncatedEnvFact.detail).toContain("PRIVATE_KEY=***");
		expect(truncatedEnvFact.detail).not.toContain("MIIEpAIBAAKCAQEA778899");
		expect(truncatedEnvFact.output).not.toContain("RSA PRIVATE KEY");
		expect(truncatedEnvFact.output).not.toContain("MIIEpAIBAAKCAQEA778899");
	});

	test("/openapi.json 与 /swagger.json 校验 JSON Schema 关键字，不把错误 JSON 误报为 API 文档暴露", () => {
		const st = makeState();
		const rule = ruleFor("surface:api")!;

		const fakeJson = rule.parse({ stdout: '/openapi.json 200 {"error":"not found"}\n', stderr: "", code: 0 }, st)!;
		expect(fakeJson.title).not.toContain("API 文档暴露");

		const validSwagger = rule.parse(
			{ stdout: '/swagger.json 200 {"swagger":"2.0","info":{"title":"Test"},"paths":{}}\n', stderr: "", code: 0 },
			st,
		)!;
		expect(validSwagger.title).toBe("API 文档暴露");
		expect(validSwagger.meta?.paths).toEqual(["/swagger.json"]);

		const schemaPathsInfo = rule.parse(
			{ stdout: '/openapi.json 200 {"info":{"title":"V3"},"paths":{"/users":{}}}\n', stderr: "", code: 0 },
			st,
		)!;
		expect(schemaPathsInfo.title).toBe("API 文档暴露");
	});
});

describe("3. 工具链自适应重武器升档（nmap / ffuf / katana / nuclei）", () => {
	test("nmap 可用时 recon:ports 构造安全命令并兼容解析 Ports: 与 open 行；NUWA_AUTO_TOOLCHAIN=0 回退 python3", () => {
		const rule = ruleFor("recon:ports")!;
		const stNmap = makeState("http://127.0.0.1:8080", ["nmap"]);
		stNmap.project.host = "127.0.0.1";

		const scriptNmap = rule.script(stNmap);
		expect(scriptNmap).toContain("nmap -Pn -sT -T4 --open -p ");
		expect(scriptNmap).toContain("-oG - '127.0.0.1'");

		// 验证防注入转义
		stNmap.project.host = "127.0.0.1'; id #";
		expect(rule.script(stNmap)).toContain(shellQuote("127.0.0.1'; id #"));

		// NUWA_AUTO_TOOLCHAIN=0 时强制回退 python3
		const prevEnv = process.env.NUWA_AUTO_TOOLCHAIN;
		process.env.NUWA_AUTO_TOOLCHAIN = "0";
		try {
			const fallbackScript = rule.script(stNmap);
			expect(fallbackScript).not.toContain("nmap -Pn");
			expect(fallbackScript).toContain("socket.create_connection");
		} finally {
			if (prevEnv === undefined) delete process.env.NUWA_AUTO_TOOLCHAIN;
			else process.env.NUWA_AUTO_TOOLCHAIN = prevEnv;
		}

		// 解析 nmap -oG - 输出
		stNmap.project.host = "127.0.0.1";
		const gnmapOut = [
			"# Nmap 7.98 scan initiated",
			"Host: 127.0.0.1 (localhost)\tStatus: Up",
			"Host: 127.0.0.1 (localhost)\tPorts: 22/open/tcp//ssh///, 8080/open/tcp//http-proxy///, 5432/open/tcp//postgresql///\tIgnored State: closed (26)",
			"# Nmap done",
		].join("\n");
		const fact = rule.parse({ stdout: gnmapOut, stderr: "", code: 0 }, stNmap)!;
		expect(fact.kind).toBe("service");
		expect(fact.meta?.ports).toEqual([22, 5432, 8080]);
		expect(fact.detail).toContain("8080/tcp");
		expect(fact.detail).toContain("ssh");
	});

	test("ffuf 可用时 recon:dirs 构造 ffuf -ac stdin 扫描并支持 NDJSON/文本解析与平滑回退 curl", () => {
		const rule = ruleFor("recon:dirs")!;
		const stFfuf = makeState("http://127.0.0.1:8080", ["ffuf"]);
		const script = rule.script(stFfuf);
		expect(script).toContain("ffuf -ac");
		expect(script).toContain("-w -");
		expect(script).toContain("curl -k -sS");
		expect(script).toContain("/__nuwa_404_check_1");

		// 解析 ffuf -json NDJSON（含真实 ffuf base64 编码的 input.FUZZ）并联动 Soft-404 基线过滤假阳性
		const ffufOut = [
			"BASELINE 200 1200 Demo SPA",
			JSON.stringify({
				input: { FUZZ: Buffer.from("fake-spa-route").toString("base64") },
				status: 200,
				length: 1204,
				url: "http://127.0.0.1:8080/fake-spa-route",
			}),
			JSON.stringify({
				input: { FUZZ: Buffer.from("api/v1").toString("base64") },
				status: 200,
				length: 92,
				url: "http://127.0.0.1:8080/api/v1",
			}),
			JSON.stringify({
				input: { FUZZ: Buffer.from("healthz").toString("base64") },
				status: 200,
				length: 18,
			}),
			"admin [Status: 403, Size: 180, Words: 12, Lines: 4]",
		].join("\n");
		const fact = rule.parse({ stdout: ffufOut, stderr: "", code: 0 }, stFfuf)!;
		expect(fact.kind).toBe("endpoint");
		expect(fact.meta?.paths).toEqual(["/api/v1", "/healthz", "/admin"]);
		expect(fact.meta?.paths).not.toContain("/fake-spa-route");
	});

	test("enrichmentRulesForToolchain 生成合规 katana / nuclei 规则且严禁 exploit/dos 标签，AUTO_KEYS 长度严格对齐", () => {
		expect(AUTO_RULES.length).toBe(AUTO_KEYS.length);
		expect(enrichmentRulesForToolchain(undefined)).toEqual([]);

		const caps: ToolchainCaps = {
			available: ["katana", "nuclei", "nmap"],
			missing: [],
			probedAt: new Date().toISOString(),
		};
		const rules = enrichmentRulesForToolchain(caps);
		expect(rules.map((r) => r.key)).toEqual(["recon:katana", "surface:nuclei"]);

		const st = makeState("http://127.0.0.1:8080");
		const katana = rules.find((r) => r.key === "recon:katana")!;
		const katanaScript = katana.script(st);
		expect(katanaScript).toContain("-d 2 -jc -silent");

		const katanaOut = [
			"http://127.0.0.1:8080/api/v1/orders",
			"http://127.0.0.1:8080/static/logo.png",
			"http://127.0.0.1:8080/assets/app.css",
			"https://other.example.com/api/leak",
			"/graphql",
		].join("\n");
		const katanaFact = katana.parse({ stdout: katanaOut, stderr: "", code: 0 }, st)!;
		expect(katanaFact.kind).toBe("endpoint");
		expect(katanaFact.meta?.paths).toEqual(["/api/v1/orders", "/graphql"]);

		const nuclei = rules.find((r) => r.key === "surface:nuclei")!;
		const nucleiScript = nuclei.script(st);
		expect(nucleiScript).toContain("-tags tech,exposure,misconfig -es info -jsonl -silent -duc -nc");
		expect(nucleiScript.toLowerCase()).not.toContain("exploit");
		expect(nucleiScript.toLowerCase()).not.toContain("dos");

		const nucleiOut = [
			JSON.stringify({
				"template-id": "http-trace-info",
				info: { name: "Info Noise", severity: "info", tags: ["tech"] },
				"matched-at": "http://127.0.0.1:8080/",
			}),
			JSON.stringify({
				"template-id": "tech-detect",
				"matcher-name": "nginx",
				info: { name: "Nginx Detected", severity: "low", tags: ["tech"] },
				"matched-at": "http://127.0.0.1:8080/",
			}),
			JSON.stringify({
				"template-id": "spring-actuator-env",
				info: { name: "Actuator Exposure", severity: "medium", tags: ["exposure", "misconfig"] },
				"matched-at": "http://127.0.0.1:8080/actuator/env",
			}),
		].join("\n");
		const nucleiFact = nuclei.parse({ stdout: nucleiOut, stderr: "", code: 0 }, st)!;
		expect(nucleiFact.kind).toBe("vuln");
		expect(nucleiFact.detail).not.toContain("http-trace-info");
		expect(nucleiFact.meta?.tech).toContain("nginx");
		expect(nucleiFact.meta?.paths).toContain("/actuator/env");

		// NUWA_AUTO_TOOLCHAIN=0 关闭扩展规则
		const prev = process.env.NUWA_AUTO_TOOLCHAIN;
		process.env.NUWA_AUTO_TOOLCHAIN = "0";
		try {
			expect(enrichmentRulesForToolchain(caps)).toEqual([]);
		} finally {
			if (prev === undefined) delete process.env.NUWA_AUTO_TOOLCHAIN;
			else process.env.NUWA_AUTO_TOOLCHAIN = prev;
		}
	});

	test("classifyAutoFailure 不把恰好 429 字节的 BASELINE 行误判为 WAF", () => {
		const cls = classifyAutoFailure({
			stdout: "BASELINE 200 429 Fake SPA\nBASELINE 200 429 Fake SPA\n",
			stderr: "",
			code: 0,
		});
		expect(cls.kind).toBe("empty");
	});
});

describe("4. SPA 与 JS Bundle 动态/静态 API 感知层 (omp/browser-recon.ts)", () => {
	test("本地 127.0.0.1 SPA Mock Server（模式 B 静态回退）：最多抓 8 个同源 Bundle，提取 API/路由/技术栈并过滤静态资源", async () => {
		const requestedPaths: string[] = [];
		const scriptTags = [
			`<script src="https://evil-cdn.outside.test/tracker.js"></script>`,
			...Array.from({ length: 10 }, (_, i) => `<script src="/static/chunk-${i + 1}.js"></script>`),
		].join("\n");

		const indexHtml = [
			"<!doctype html>",
			"<html><head><title>Next React App</title></head>",
			"<body>",
			'<div id="__next" data-reactroot></div>',
			'<a href="/pricing">Pricing</a>',
			'<a href="https://external.outside.test/about">Out</a>',
			'<script id="__NEXT_DATA__" type="application/json">{"page":"/home"}</script>',
			scriptTags,
			"</body></html>",
		].join("\n");

		const bundles: Record<string, string> = {
			"/static/chunk-1.js": `
				const routes = [{ path: "/dashboard" }, { path: "/settings" }];
				async function loadUsers() {
					return fetch('/api/v1/users?role=admin&page=1');
				}
				const assets = ["/img/logo.png", "/styles/main.css", "/fonts/app.woff2"];
			`,
			"/static/chunk-2.js": `
				async function createOrder() {
					return axios.post('/api/v1/orders', { itemId: 10, quantity: 2 });
				}
				async function getProfile() {
					return fetch('/graphql', {
						method: 'POST',
						body: JSON.stringify({
							query: 'query GetProfile { me { id } }',
							operationName: 'GetProfile',
							variables: { uid: 1 }
						})
					});
				}
				const xhr = new XMLHttpRequest();
				xhr.open('PUT', '/api/v1/profile');
			`,
			"/static/chunk-9.js": `fetch('/api/v1/should-not-be-fetched-over-limit');`,
			"/static/chunk-10.js": `fetch('/api/v1/should-not-be-fetched-10');`,
		};

		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const u = new URL(req.url);
				requestedPaths.push(u.pathname);
				if (u.pathname === "/") {
					return new Response(indexHtml, { status: 200, headers: { "content-type": "text/html" } });
				}
				if (u.pathname in bundles) {
					return new Response(bundles[u.pathname]!, {
						status: 200,
						headers: { "content-type": "application/javascript" },
					});
				}
				if (u.pathname.startsWith("/static/chunk-")) {
					return new Response(`// empty chunk ${u.pathname}`, {
						status: 200,
						headers: { "content-type": "application/javascript" },
					});
				}
				return new Response("not found", { status: 404 });
			},
		});

		try {
			const targetUrl = `http://127.0.0.1:${srv.port}/`;
			const scope = defaultScopeForTarget(targetUrl, "audit");

			const res = await runSpaRecon(targetUrl, scope, { disablePlaywright: true });
			expect(res.mode).toBe("static");
			expect(res.bundles.length).toBe(8);
			expect(requestedPaths).not.toContain("/static/chunk-9.js");
			expect(requestedPaths).not.toContain("/static/chunk-10.js");
			// 外域脚本被阻断
			expect(res.blockedRequests).toBeGreaterThanOrEqual(1);

			// 技术栈识别
			expect(res.tech).toContain("react");
			expect(res.tech).toContain("nextjs");

			// 前端路由识别
			expect(res.routes).toContain("/dashboard");
			expect(res.routes).toContain("/settings");
			expect(res.routes).toContain("/pricing");

			// API 端点识别（含 method / queryKeys / bodyKeys / GraphQL）
			const usersEp = res.endpoints.find((e) => e.path === "/api/v1/users");
			expect(usersEp?.method).toBe("GET");
			expect(usersEp?.queryKeys).toEqual(["page", "role"]);

			const ordersEp = res.endpoints.find((e) => e.path === "/api/v1/orders");
			expect(ordersEp?.method).toBe("POST");
			expect(ordersEp?.bodyKeys).toEqual(["itemId", "quantity"]);

			const gqlEp = res.endpoints.find((e) => e.path === "/graphql");
			expect(gqlEp?.method).toBe("POST");
			expect(gqlEp?.isGraphql).toBe(true);
			expect(gqlEp?.graphqlOperation).toBe("GetProfile");
			expect(gqlEp?.bodyKeys).toEqual(["operationName", "query", "variables"]);

			const profileEp = res.endpoints.find((e) => e.path === "/api/v1/profile");
			expect(profileEp?.method).toBe("PUT");

			// 过滤静态资源后缀，且未抓取第 9/10 个 Bundle
			const allPaths = res.endpoints.map((e) => e.path);
			expect(allPaths).not.toContain("/img/logo.png");
			expect(allPaths).not.toContain("/styles/main.css");
			expect(allPaths).not.toContain("/fonts/app.woff2");
			expect(allPaths).not.toContain("/api/v1/should-not-be-fetched-over-limit");

			// 统一 AutoFact 校验
			expect(res.fact).not.toBeNull();
			expect(res.fact?.kind).toBe("endpoint");
			expect(res.fact?.meta?.paths).toContain("/api/v1/users");
			expect(res.fact?.meta?.paths).toContain("/graphql");
			expect(res.fact?.meta?.tech).toContain("react");

			// 直接调用 extractStaticBundleApis 也保持一致产出
			const direct = await extractStaticBundleApis(indexHtml, targetUrl, scope);
			expect(direct.bundles.length).toBe(8);
			expect(direct.fact?.kind).toBe("endpoint");
		} finally {
			srv.stop(true);
		}
	});

	test("模式 A（Playwright 受控拦截）：仅放行范围内 GET/HEAD/OPTIONS，阻断越界与写请求并记录 XHR/Fetch/GraphQL", async () => {
		const targetUrl = "http://127.0.0.1:49999/";
		const scope = defaultScopeForTarget(targetUrl, "audit");

		const continued: string[] = [];
		const aborted: string[] = [];

		const mockPlaywright: PlaywrightLike = {
			chromium: {
				async launch() {
					return {
						async newContext() {
							return {
								async newPage() {
									let routeHandler: ((route: PlaywrightRouteLike) => Promise<void> | void) | null = null;
									const fire = async (
										url: string,
										method: string,
										resourceType: string,
										postData: string | null = null,
									) => {
										if (!routeHandler) return;
										await routeHandler({
											request: () => ({
												url: () => url,
												method: () => method,
												resourceType: () => resourceType,
												postData: () => postData,
											}),
											continue: async () => {
												continued.push(`${method} ${url}`);
											},
											abort: async () => {
												aborted.push(`${method} ${url}`);
											},
										});
									};

									return {
										async route(_pattern, handler) {
											routeHandler = handler;
										},
										async goto() {
											await fire("http://127.0.0.1:49999/", "GET", "document");
											await fire("http://127.0.0.1:49999/api/v2/items?sort=asc&limit=20", "GET", "fetch");
											await fire("http://127.0.0.1:49999/api/v2/ping", "OPTIONS", "xhr");
											await fire(
												"http://127.0.0.1:49999/graphql",
												"POST",
												"fetch",
												JSON.stringify({
													operationName: "ListAuditLogs",
													query: "query ListAuditLogs { logs { id } }",
													variables: { secretFilter: "DO_NOT_LEAK" },
												}),
											);
											await fire("http://127.0.0.1:49999/api/v2/items/9", "DELETE", "xhr");
											await fire("https://evil-thirdparty.example/collect?token=leak", "GET", "fetch");
										},
										async evaluate() {
											return {
												html: '<html><body><div id="__nuxt" ng-version="17.0.0"></div><a href="/reports">Reports</a></body></html>',
												pathname: "/console",
												hash: "#/audit-log",
												links: ["/reports"],
												globals: ["vue", "nuxt", "angular"],
											} as never;
										},
										async close() {},
									};
								},
								async close() {},
							};
						},
						async close() {},
					};
				},
			},
		};

		const res = await runSpaRecon(targetUrl, scope, {
			playwrightLoader: async () => mockPlaywright,
		});

		expect(res.mode).toBe("playwright");
		// 仅放行 scope 内 GET / OPTIONS
		expect(continued).toContain("GET http://127.0.0.1:49999/api/v2/items?sort=asc&limit=20");
		expect(continued).toContain("OPTIONS http://127.0.0.1:49999/api/v2/ping");
		// 拦截 POST / DELETE 与越界外域请求
		expect(aborted).toContain("POST http://127.0.0.1:49999/graphql");
		expect(aborted).toContain("DELETE http://127.0.0.1:49999/api/v2/items/9");
		expect(aborted).toContain("GET https://evil-thirdparty.example/collect?token=leak");
		expect(res.blockedRequests).toBe(3);

		// 越界域名端点不被记录
		expect(res.endpoints.some((e) => e.path.includes("collect"))).toBe(false);

		// 范围内 API 契约完整记录且不泄露明文 body 值
		const itemsEp = res.endpoints.find((e) => e.path === "/api/v2/items");
		expect(itemsEp?.method).toBe("GET");
		expect(itemsEp?.queryKeys).toEqual(["limit", "sort"]);

		const gqlEp = res.endpoints.find((e) => e.path === "/graphql");
		expect(gqlEp?.method).toBe("POST");
		expect(gqlEp?.isGraphql).toBe(true);
		expect(gqlEp?.graphqlOperation).toBe("ListAuditLogs");
		expect(gqlEp?.bodyKeys).toEqual(["operationName", "query", "variables"]);
		expect(JSON.stringify(res)).not.toContain("DO_NOT_LEAK");

		// 技术栈与前端路由
		expect(res.tech).toContain("vue");
		expect(res.tech).toContain("nuxt");
		expect(res.tech).toContain("angular");
		expect(res.routes).toContain("/console");
		expect(res.routes).toContain("/audit-log");
		expect(res.routes).toContain("/reports");

		expect(res.fact?.kind).toBe("endpoint");
	});

	test("入口目标越界直接拦截且零请求发出；Playwright 启动异常时优雅回退模式 B", async () => {
		const scope = defaultScopeForTarget("http://127.0.0.1:8080", "audit");
		let fetchCalled = 0;
		const blocked = await runSpaRecon("https://forbidden-target.example/app", scope, {
			fetchFn: async () => {
				fetchCalled++;
				return { ok: true, status: 200, text: async () => "" };
			},
		});
		expect(fetchCalled).toBe(0);
		expect(blocked.fact).toBeNull();
		expect(blocked.blockedRequests).toBe(1);

		// Playwright 抛错自动回退模式 B
		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				return new Response(
					'<html><body><div data-v-abcdef></div><script>fetch("/api/v1/health")</script></body></html>',
					{ status: 200, headers: { "content-type": "text/html" } },
				);
			},
		});
		try {
			const url = `http://127.0.0.1:${srv.port}/`;
			const res = await runSpaRecon(url, defaultScopeForTarget(url, "audit"), {
				playwrightLoader: async () => ({
					chromium: {
						async launch() {
							throw new Error("Executable doesn't exist");
						},
					},
				}),
			});
			expect(res.mode).toBe("static");
			expect(res.fallbackReason).toContain("回退静态模式");
			expect(res.tech).toContain("vue");
			expect(res.endpoints.some((e) => e.path === "/api/v1/health")).toBe(true);
		} finally {
			srv.stop(true);
		}
	});

	test("模式 B 静态抓取严格拦截 30x 越界/跨源重定向（零请求泄露）且正常跟随同源站内跳转", async () => {
		// 1. 陷阱服务器：验证跨源 302 指向该端口时收到 0 次请求
		let trapHits = 0;
		const trapSrv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				trapHits++;
				return new Response("fetch('/api/should-never-leak');", {
					status: 200,
					headers: { "content-type": "application/javascript" },
				});
			},
		});

		// 2. 主靶标服务器：
		//    - /meta-redir -> 302 到元数据 IP 169.254.169.254（越界必须阻断）
		//    - /start      -> 302 到同源 /app（合法站内跳转必须放行）
		//    - /app        -> 引用 2 个恶意重定向 Bundle（分别指向 trapSrv 跨端口与 169.254.169.254）和 1 个合法同源 Bundle
		const mainSrv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const u = new URL(req.url);
				if (u.pathname === "/meta-redir") {
					return new Response("", {
						status: 302,
						headers: { location: "http://169.254.169.254/latest/meta-data/" },
					});
				}
				if (u.pathname === "/start") {
					return new Response("", { status: 302, headers: { location: "/app" } });
				}
				if (u.pathname === "/app") {
					return new Response(
						[
							"<html><body><div data-reactroot></div>",
							'<script src="/static/redir-trap.js"></script>',
							'<script src="/static/redir-meta.js"></script>',
							'<script src="/static/good.js"></script>',
							"</body></html>",
						].join("\n"),
						{ status: 200, headers: { "content-type": "text/html" } },
					);
				}
				if (u.pathname === "/static/redir-trap.js") {
					return new Response("", {
						status: 302,
						headers: { location: `http://127.0.0.1:${trapSrv.port}/leak.js` },
					});
				}
				if (u.pathname === "/static/redir-meta.js") {
					return new Response("", {
						status: 301,
						headers: { location: "http://169.254.169.254/evil.js" },
					});
				}
				if (u.pathname === "/static/good.js") {
					return new Response("fetch('/api/v1/safe-endpoint');", {
						status: 200,
						headers: { "content-type": "application/javascript" },
					});
				}
				return new Response("not found", { status: 404 });
			},
		});

		try {
			const base = `http://127.0.0.1:${mainSrv.port}`;
			const scope = defaultScopeForTarget(base, "audit");

			// A. 首屏 302 重定向到 169.254.169.254 必须阻断
			const metaRes = await runSpaRecon(`${base}/meta-redir`, scope, { disablePlaywright: true });
			expect(metaRes.mode).toBe("static");
			expect(metaRes.blockedRequests).toBe(1);
			expect(metaRes.fact).toBeNull();
			expect(metaRes.fallbackReason).toContain("阻断越界 30x 重定向");

			// B. 同源 /start -> /app 正常跟随，但跨端口与元数据 Bundle 30x 重定向全部阻断，trapSrv 零命中
			const appRes = await runSpaRecon(`${base}/start`, scope, { disablePlaywright: true });
			expect(appRes.mode).toBe("static");
			expect(trapHits).toBe(0);
			expect(appRes.blockedRequests).toBeGreaterThanOrEqual(2);
			expect(appRes.bundles).toEqual([`${base}/static/good.js`]);
			expect(appRes.endpoints.some((e) => e.path === "/api/v1/safe-endpoint")).toBe(true);
			expect(appRes.endpoints.some((e) => e.path.includes("should-never-leak"))).toBe(false);

			// C. 自定义 fetchFn 验证显式传入 redirect: "manual" 且绝不对越界目标域名发第二跳
			const visited: Array<{ url: string; redirect?: string }> = [];
			const spyRes = await runSpaRecon("http://127.0.0.1:49888/", scope, {
				disablePlaywright: true,
				fetchFn: async (input, init) => {
					visited.push({ url: input, redirect: init?.redirect });
					return {
						ok: false,
						status: 307,
						headers: new Headers({ location: "https://evil.outside.example/ssrf" }),
						text: async () => "",
					};
				},
			});
			expect(visited).toEqual([{ url: "http://127.0.0.1:49888/", redirect: "manual" }]);
			expect(spyRes.blockedRequests).toBe(1);
			expect(spyRes.fact).toBeNull();
		} finally {
			mainSrv.stop(true);
			trapSrv.stop(true);
		}
	});
});

describe("5. config/autoexec.example.json 外置规则 Schema 校验", () => {
	test("标准示例配置可通过 loadAutoRules 无错加载且所有规则脚本正常渲染", () => {
		const examplePath = resolve(import.meta.dir, "../config/autoexec.example.json");
		const parsed = JSON.parse(readFileSync(examplePath, "utf8")) as { replace: boolean; rules: unknown[] };
		expect(parsed.replace).toBe(false);
		expect(Array.isArray(parsed.rules)).toBe(true);
		expect(parsed.rules.length).toBeGreaterThanOrEqual(AUTO_KEYS.length);

		const root = makeDir("nuwa-example-cfg-");
		mkdirSync(join(root, ".nuwa"), { recursive: true });
		cpSync(examplePath, join(root, ".nuwa", "autoexec.json"));

		const loaded = loadAutoRules(root);
		expect(loaded.source).toBe("project");
		expect(loaded.error).toBeUndefined();
		expect(loaded.rules.some((r) => r.key === "surface:health")).toBe(true);

		const st = makeState("http://127.0.0.1:8080");
		for (const r of loaded.rules) {
			const script = r.script(st);
			expect(typeof script).toBe("string");
			expect(script.length).toBeGreaterThan(10);
		}
	});
});
