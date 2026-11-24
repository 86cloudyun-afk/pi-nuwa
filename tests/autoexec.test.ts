/**
 * 2.6.0 & 3.0.0 自渗透引擎测试：
 * 规则解析、E2+ 归一化、跨平台 Python 端口探测、AutoFactMeta、外置 autoexec.json 热更新、
 * 失败三分类（network / blocked_by_waf / empty）、nextRunAt 冷却、预算与并发独占控制。
 */
import { afterAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	applyEmptyGuard,
	autoPlan,
	claimAutoBatch,
	deriveFromFacts,
	newState,
	readCfg,
	seedEpisode,
	seedPhase,
	type Cfg,
	type NuwaState,
} from "../omp/nuwa";
import {
	AUTO_KEYS,
	canonicalAutoKey,
	classifyAutoFailure,
	isAutoKey,
	loadAutoRules,
	originOf,
	pickAuto,
	ruleFor,
	runAutoBatchManaged,
	runAutoIntent,
	shellQuote,
	type ExecLike,
} from "../omp/autoexec";

const cfg: Cfg = { ...readCfg(), auto: true, autoMax: 3, emptyLimit: 3, maxAttempts: 3 };
const tempDirs: string[] = [];

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

function fresh(): NuwaState {
	const st = newState("10.0.0.5:8080", "打穿并拿 flag", "ctf", cfg);
	seedPhase(st, "recon");
	return st;
}

function execOf(stdout: string, code = 0): ExecLike {
	return async () => ({ stdout, stderr: "", code, killed: false });
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

describe("脚本与目标", () => {
	test("shellQuote 处理单引号", () => {
		expect(shellQuote("a'b")).toBe(`'a'\\''b'`);
		expect(shellQuote("http://x/")).toBe("'http://x/'");
	});

	test("originOf 去掉路径", () => {
		const st = fresh();
		st.project.url = "https://hema.beer:443/home";
		expect(originOf(st)).toBe("https://hema.beer");
	});
});

describe("规则解析与结构化 AutoFactMeta", () => {
	test("http 解析状态/Server/标题与 meta (server/tech/status/waf)", () => {
		const st = fresh();
		const rule = ruleFor("recon:http")!;
		const out = [
			"FINAL 200 1234 http://10.0.0.5:8080/",
			"---HEAD---",
			"HTTP/1.1 200 OK",
			"Server: nginx",
			"X-Powered-By: PHP/8.2",
			"CF-Ray: 88888888-SJC",
			"---BODY---",
			"<html><title>Home</title></html>",
		].join("\n");
		const fact = rule.parse({ stdout: out, stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("service");
		expect(fact.title).toContain("200");
		expect(fact.title).toContain("nginx");
		expect(fact.detail).toContain("x-powered-by=PHP/8.2");
		expect(fact.detail).toContain("title=Home");
		expect(fact.meta?.status).toBe(200);
		expect(fact.meta?.server).toBe("nginx");
		expect(fact.meta?.tech).toContain("nginx");
		expect(fact.meta?.tech).toContain("php");
		expect(fact.meta?.waf).toBe("cloudflare");
	});

	test("http 无响应返回 null", () => {
		const st = fresh();
		const rule = ruleFor("recon:http")!;
		expect(rule.parse({ stdout: "", stderr: "", code: 7 }, st)).toBeNull();
	});

	test("ports 解析 open 行并产出 meta.ports 与 80/tcp 派生兼容格式", () => {
		const st = fresh();
		const rule = ruleFor("recon:ports")!;
		const fact = rule.parse({ stdout: "open 22\nopen 80\nopen 443\n", stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("service");
		expect(fact.title).toContain("3");
		expect(fact.detail).toContain("22,80,443");
		expect(fact.detail).toContain("80/tcp");
		expect(fact.meta?.ports).toEqual([22, 80, 443]);

		// 验证现有 deriveFromFacts 可直接消费 portsRule 产出的 detail
		st.facts.f001 = {
			id: "f001",
			kind: fact.kind,
			title: fact.title,
			detail: fact.detail,
			command: fact.command,
			output: fact.output,
			createdAt: new Date().toISOString(),
		};
		const derived = deriveFromFacts(st);
		expect(derived.rules).toContain("svc:f001:80");
	});

	test("portsRule 脚本彻底移除 GNU timeout 与 /dev/tcp 并可在本地 127.0.0.1 真实扫出开放端口", async () => {
		const st = fresh();
		st.project.host = "127.0.0.1'; echo INJECTED #";
		const rawScript = ruleFor("recon:ports")!.script(st);
		expect(rawScript).not.toContain("/dev/tcp");
		expect(rawScript).not.toMatch(/\btimeout\s+1\b/);
		expect(rawScript).toContain("socket.create_connection");
		expect(rawScript).toContain(shellQuote(st.project.host));

		// 启动本地 127.0.0.1 临时 TCP 监听验证跨平台真实连通探测
		const srv = createServer((sock) => sock.end());
		await new Promise<void>((resolveListen) => srv.listen(0, "127.0.0.1", () => resolveListen()));
		const addr = srv.address();
		const listenPort = typeof addr === "object" && addr ? addr.port : 0;

		try {
			const dir = makeDir("nuwa-port-");
			mkdirSync(join(dir, ".nuwa"), { recursive: true });
			writeFileSync(
				join(dir, ".nuwa", "autoexec.json"),
				JSON.stringify({
					rules: [{ key: "recon:ports", phase: "recon", timeoutMs: 10000, parse: "ports", ports: [listenPort] }],
				}),
			);
			const customPortsRule = ruleFor("recon:ports", dir)!;
			const localSt = newState(`127.0.0.1:${listenPort}`, "本地连通验证", "ctf", cfg);
			const proc = spawnSync("bash", ["-lc", customPortsRule.script(localSt)], { encoding: "utf8", timeout: 8000 });
			expect(proc.status).toBe(0);
			expect(proc.stdout).toContain(`open ${listenPort}`);
			const parsed = customPortsRule.parse(
				{ stdout: proc.stdout, stderr: proc.stderr, code: proc.status ?? 0 },
				localSt,
			)!;
			expect(parsed.meta?.ports).toEqual([listenPort]);
			expect(parsed.detail).toContain(`${listenPort}/tcp`);
		} finally {
			await new Promise<void>((resolveClose) => srv.close(() => resolveClose()));
		}
	});

	test("dirs 解析路径行并产出 meta.paths 与 meta.status", () => {
		const st = fresh();
		const rule = ruleFor("recon:dirs")!;
		const out = "/admin 403 1234 \n/api 200 999 \n/x 404 0 \n";
		const fact = rule.parse({ stdout: out, stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("endpoint");
		expect(fact.detail).toContain("/admin");
		expect(fact.detail).toContain("/api");
		expect(fact.detail).not.toContain("/x");
		expect(fact.meta?.paths).toEqual(["/admin", "/api"]);
		expect(fact.meta?.status).toBe(200);
	});

	test("sensitive 命中 .git/HEAD 记 vuln 并带 meta.paths", () => {
		const st = fresh();
		const rule = ruleFor("surface:sensitive")!;
		const fact = rule.parse({ stdout: "/.git/HEAD 200 ref: refs/heads/main\n", stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("vuln");
		expect(fact.title).toContain("敏感文件暴露");
		expect(fact.meta?.paths).toEqual(["/.git/HEAD"]);
		expect(fact.meta?.status).toBe(200);
	});

	test("api 文档暴露判定并带 meta.paths（含多行格式化 JSON 实测）", async () => {
		const st = fresh();
		const rule = ruleFor("surface:api")!;
		const fact = rule.parse({ stdout: '/openapi.json 200 {"openapi":"3.0.0"}\n', stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("endpoint");
		expect(fact.title).toContain("API 文档");
		expect(fact.meta?.paths).toEqual(["/openapi.json"]);
		expect(fact.meta?.status).toBe(200);

		// 启动本地 127.0.0.1 HTTP 服务返回多行格式化 /openapi.json，验证 probePaths 脚本压平与解析
		const httpSrv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const u = new URL(req.url);
				if (u.pathname === "/openapi.json") {
					return new Response('{\n  "openapi": "3.1.0",\n  "info": {\n    "title": "Demo"\n  }\n}\n', {
						status: 200,
						headers: { "content-type": "application/json" },
					});
				}
				return new Response("not found", { status: 404 });
			},
		});
		try {
			const localSt = newState(`http://127.0.0.1:${httpSrv.port}`, "多行 OpenAPI 验证", "ctf", cfg);
			const runRes = await runAutoIntent(rule, localSt, realAsyncExec, "/tmp");
			expect(runRes.ok).toBe(true);
			expect(runRes.fact?.title).toContain("API 文档暴露");
			expect(runRes.fact?.meta?.paths).toEqual(["/openapi.json"]);
		} finally {
			httpSrv.stop(true);
		}
	});

	test("tls 加固 shellQuote 且解析 subject/SAN 与 meta.san", () => {
		const st = fresh();
		st.project.host = "bad'host.test";
		const rule = ruleFor("recon:tlsjs")!;
		expect(rule.script(st)).toContain(shellQuote("bad'host.test"));

		const out = [
			"subject=CN = hema.beer",
			"issuer=C = US, O = Let's Encrypt",
			"notAfter=Feb 1 00:00:00 2027 GMT",
			"X509v3 Subject Alternative Name:",
			"    DNS:hema.beer, DNS:www.hema.beer",
		].join("\n");
		const fact = rule.parse({ stdout: out, stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("service");
		expect(fact.detail).toContain("subject=CN = hema.beer");
		expect(fact.detail).toContain("www.hema.beer");
		expect(fact.meta?.san).toEqual(["hema.beer", "www.hema.beer"]);
	});
});

describe("E2+ 归一化、调度与冷却", () => {
	test("canonicalAutoKey 剥离 e<N>: 前缀，seedEpisode 意图可被 pickAuto 选中", () => {
		expect(canonicalAutoKey("e2:recon:http")).toBe("recon:http");
		expect(canonicalAutoKey("e15:surface:sensitive")).toBe("surface:sensitive");
		expect(canonicalAutoKey("recon:ports")).toBe("recon:ports");
		expect(isAutoKey("e2:recon:http")).toBe(true);
		expect(ruleFor("e3:recon:dirs")?.key).toBe("recon:dirs");

		const st = newState("127.0.0.1:8080", "E2 归一化验证", "ctf", cfg);
		seedEpisode(st, 2);
		const ids = pickAuto(st, cfg, 10);
		const keys = ids.map((id) => st.intents[id].key);
		expect(keys).toContain("e2:recon:http");
		expect(keys).toContain("e2:surface:sensitive");
	});

	test("pickAuto 只选白名单 key 且跳过 nextRunAt > now 的冷却意图", () => {
		const st = fresh();
		const now = 1_700_000_000_000;
		const httpIntent = Object.values(st.intents).find((i) => i.key === "recon:http")!;
		(httpIntent as { nextRunAt?: number }).nextRunAt = now + 60_000;

		const idsCooling = pickAuto(st, cfg, 10, now);
		const keysCooling = idsCooling.map((id) => st.intents[id].key);
		expect(keysCooling).not.toContain("recon:http");
		expect(keysCooling).toContain("recon:ports");

		// 冷却到期后重新可选
		const idsReady = pickAuto(st, cfg, 10, now + 60_001);
		expect(idsReady.map((id) => st.intents[id].key)).toContain("recon:http");

		for (const k of keysCooling) expect(AUTO_KEYS).toContain(k as never);
		expect(keysCooling).not.toContain("recon:vhost");
		expect(keysCooling).not.toContain("recon:techcve");
	});

	test("claimAutoBatch 标 claimed/worker=auto 并加 attempts", () => {
		const st = fresh();
		const ids = claimAutoBatch(st, cfg);
		expect(ids.length).toBe(3);
		for (const id of ids) {
			expect(st.intents[id].status).toBe("claimed");
			expect(st.intents[id].worker).toBe("auto");
			expect(st.intents[id].attempts).toBe(1);
		}
	});

	test("auto=false 不领批", () => {
		const st = fresh();
		expect(claimAutoBatch(st, { ...cfg, auto: false })).toEqual([]);
	});

	test("runAutoIntent 用 stub exec 产出 fact", async () => {
		const st = fresh();
		const rule = ruleFor("recon:ports")!;
		const res = await runAutoIntent(rule, st, execOf("open 22\nopen 80\n"), "/tmp");
		expect(res.ok).toBe(true);
		expect(res.fact?.kind).toBe("service");
	});

	test("runAutoIntent 无产出返回 error 与失败分类字段", async () => {
		const st = fresh();
		const rule = ruleFor("recon:ports")!;
		const res = await runAutoIntent(rule, st, execOf("", 1), "/tmp");
		expect(res.ok).toBe(false);
		expect(res.error).toContain("无产出");
		expect(res.errorKind).toBe("empty");
	});
});

describe("Issue #2 外置 autoexec.json 配置加载与热更新", () => {
	test("优先级 project > global > builtin、mtimeMs 热更新以及非法配置安全降级", () => {
		const root = makeDir("nuwa-rules-proj-");
		const agentHome = makeDir("nuwa-rules-home-");
		mkdirSync(join(root, ".nuwa"), { recursive: true });

		// 1. 无外置文件时为 builtin
		const b = loadAutoRules(root, agentHome);
		expect(b.source).toBe("builtin");
		expect(b.error).toBeUndefined();

		// 2. agentHome 全局级别配置生效
		const globalFile = join(agentHome, "nuwa-autoexec.json");
		writeFileSync(
			globalFile,
			JSON.stringify({
				rules: [{ key: "surface:custom_global", phase: "surface", timeoutMs: 9000, parse: "probe", paths: ["/healthz"] }],
			}),
		);
		const u = loadAutoRules(root, agentHome);
		expect(u.source).toBe("global");
		expect(u.rules.some((r) => r.key === "surface:custom_global")).toBe(true);

		// 3. project 级别配置高于 global，且支持热更新
		const projFile = join(root, ".nuwa", "autoexec.json");
		writeFileSync(
			projFile,
			JSON.stringify({
				rules: [{ key: "recon:http", phase: "recon", timeoutMs: 11_111, parse: "http" }],
			}),
		);
		const p1 = loadAutoRules(root, agentHome);
		expect(p1.source).toBe("project");
		expect(p1.rules.find((r) => r.key === "recon:http")?.timeoutMs).toBe(11_111);

		// 热更新修改 timeoutMs
		writeFileSync(
			projFile,
			JSON.stringify({
				rules: [{ key: "recon:http", phase: "recon", timeoutMs: 22_222, parse: "http" }],
			}),
		);
		const p2 = loadAutoRules(root, agentHome);
		expect(p2.rules.find((r) => r.key === "recon:http")?.timeoutMs).toBe(22_222);

		// 4. 非法 parser 被拒并降级回 builtin 带 error
		writeFileSync(
			projFile,
			JSON.stringify({
				rules: [{ key: "recon:evil", phase: "recon", timeoutMs: 5000, parse: "eval_arbitrary" }],
			}),
		);
		const badParser = loadAutoRules(root, agentHome);
		expect(badParser.source).toBe("builtin");
		expect(badParser.error).toContain("仅允许 http|ports|dirs|tls|probe");

		// 5. 损坏 JSON 降级回 builtin 带 error
		writeFileSync(projFile, "{ invalid json ");
		const badJson = loadAutoRules(root, agentHome);
		expect(badJson.source).toBe("builtin");
		expect(badJson.error).toBeDefined();
		expect(badJson.rules.length).toBe(AUTO_KEYS.length);

		// 6. replace: true 下 isAutoKey 与 ruleFor 严格一致（包括 PI_AGENT_HOME 全局覆盖）
		const replaceHome = makeDir("nuwa-replace-home-");
		writeFileSync(
			join(replaceHome, "nuwa-autoexec.json"),
			JSON.stringify({
				replace: true,
				rules: [{ key: "recon:only_one", phase: "recon", timeoutMs: 5000, parse: "http" }],
			}),
		);
		const prevAgentHome = process.env.PI_AGENT_HOME;
		process.env.PI_AGENT_HOME = replaceHome;
		try {
			expect(isAutoKey("recon:only_one")).toBe(true);
			expect(isAutoKey("recon:http")).toBe(false);
			expect(ruleFor("recon:http")).toBeUndefined();
		} finally {
			if (prevAgentHome === undefined) delete process.env.PI_AGENT_HOME;
			else process.env.PI_AGENT_HOME = prevAgentHome;
		}
	});
});

describe("Issue #3 失败三分类 classifyAutoFailure", () => {
	test("dirsRule 与 probePaths 在真实连接被拒 (curl 7) 和 429 限流时正确分类为 network / blocked_by_waf", async () => {
		// 找一个已关闭的随机空闲本地端口，测试连接被拒（curl exit 7 -> network）
		const tmpSrv = createServer();
		await new Promise<void>((r) => tmpSrv.listen(0, "127.0.0.1", () => r()));
		const closedPort = (tmpSrv.address() as { port: number }).port;
		await new Promise<void>((r) => tmpSrv.close(() => r()));

		const dir = makeDir("nuwa-net-cls-");
		mkdirSync(join(dir, ".nuwa"), { recursive: true });
		writeFileSync(
			join(dir, ".nuwa", "autoexec.json"),
			JSON.stringify({
				rules: [
					{ key: "recon:dirs", phase: "recon", timeoutMs: 8000, parse: "dirs", paths: ["/admin", "/api"] },
					{ key: "surface:api", phase: "surface", timeoutMs: 8000, parse: "probe", paths: ["/openapi.json"] },
				],
			}),
		);

		const closedSt = newState(`http://127.0.0.1:${closedPort}`, "连接拒绝分类验证", "ctf", cfg);
		const dirsNetRes = await runAutoIntent(ruleFor("recon:dirs", dir)!, closedSt, realAsyncExec, dir);
		expect(dirsNetRes.ok).toBe(false);
		expect(dirsNetRes.errorKind).toBe("network");
		expect(dirsNetRes.retryAfterMs).toBe(60_000);

		const probeNetRes = await runAutoIntent(ruleFor("surface:api", dir)!, closedSt, realAsyncExec, dir);
		expect(probeNetRes.ok).toBe(false);
		expect(probeNetRes.errorKind).toBe("network");
		expect(probeNetRes.retryAfterMs).toBe(60_000);

		// 启动返回全 429 的本地服务，验证 dirsRule 与 probePaths 分类为 blocked_by_waf
		const wafSrv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch() {
				return new Response("Too Many Requests", { status: 429, headers: { "server": "cloudflare" } });
			},
		});
		try {
			const wafSt = newState(`http://127.0.0.1:${wafSrv.port}`, "429 分类验证", "ctf", cfg);
			const dirsWafRes = await runAutoIntent(ruleFor("recon:dirs", dir)!, wafSt, realAsyncExec, dir);
			expect(dirsWafRes.ok).toBe(false);
			expect(dirsWafRes.errorKind).toBe("blocked_by_waf");

			const probeWafRes = await runAutoIntent(ruleFor("surface:api", dir)!, wafSt, realAsyncExec, dir);
			expect(probeWafRes.ok).toBe(false);
			expect(probeWafRes.errorKind).toBe("blocked_by_waf");
			expect(probeWafRes.waf).toBe("cloudflare");
		} finally {
			wafSrv.stop(true);
		}
	});
	test("精准区分 network、blocked_by_waf 与 empty", async () => {
		// network: curl 28 超时 / curl 6 DNS / killed
		const net1 = classifyAutoFailure({ stdout: "", stderr: "curl: (28) Operation timed out", code: 28 });
		expect(net1.kind).toBe("network");
		expect(net1.retryAfterMs).toBe(60_000);

		const net2 = classifyAutoFailure({ stdout: "", stderr: "", code: 137, killed: true });
		expect(net2.kind).toBe("network");
		expect(net2.retryAfterMs).toBe(60_000);

		// blocked_by_waf: 403 Cloudflare Challenge / 429 Rate Limit
		const waf1 = classifyAutoFailure({
			stdout: "HTTP/1.1 403 Forbidden\nServer: cloudflare\nJust a moment... Enable JavaScript and cookies",
			stderr: "",
			code: 0,
		});
		expect(waf1.kind).toBe("blocked_by_waf");
		expect(waf1.waf).toBe("cloudflare");

		const waf2 = classifyAutoFailure({
			stdout: "FINAL 429 120 http://127.0.0.1/\nToo Many Requests",
			stderr: "",
			code: 0,
		});
		expect(waf2.kind).toBe("blocked_by_waf");
		expect(waf2.waf).toBe("rate-limit");

		// empty: 全部 404 未命中
		const emp = classifyAutoFailure({ stdout: "", stderr: "", code: 0 });
		expect(emp.kind).toBe("empty");

		// runAutoIntent 透传 network retryAfterMs
		const st = fresh();
		const netRes = await runAutoIntent(
			ruleFor("recon:dirs")!,
			st,
			async () => ({ stdout: "", stderr: "Failed to connect", code: 7 }),
			"/tmp",
		);
		expect(netRes.ok).toBe(false);
		expect(netRes.errorKind).toBe("network");
		expect(netRes.retryAfterMs).toBe(60_000);
	});
});

describe("Issue #5 runAutoBatchManaged 预算、并发独占与取消", () => {
	test("concurrency=2 时普通意图并行，recon:ports 严格独占执行", async () => {
		const root = makeDir("nuwa-batch-conc-");
		const st = fresh();
		const httpId = Object.values(st.intents).find((i) => i.key === "recon:http")!.id;
		const dirsId = Object.values(st.intents).find((i) => i.key === "recon:dirs")!.id;
		const portsId = Object.values(st.intents).find((i) => i.key === "recon:ports")!.id;
		const tlsId = Object.values(st.intents).find((i) => i.key === "recon:tlsjs")!.id;

		let active = 0;
		let maxObserved = 0;
		let portsOverlap = 0;

		const mockExec: ExecLike = async (_cmd, args) => {
			const script = args[1] ?? "";
			const isPorts = script.includes("socket.create_connection");
			active++;
			if (active > maxObserved) maxObserved = active;
			if (isPorts && active > 1) portsOverlap++;
			await Bun.sleep(35);
			if (isPorts && active > 1) portsOverlap++;
			active--;
			if (isPorts) return { stdout: "open 80\n", stderr: "", code: 0 };
			if (script.includes("---HEAD---")) {
				return {
					stdout: "FINAL 200 10 http://127.0.0.1/\n---HEAD---\nHTTP/1.1 200 OK\nServer: test\n---BODY---\nok",
					stderr: "",
					code: 0,
				};
			}
			if (script.includes("subjectAltName")) {
				return { stdout: "subject=CN = local\nnotAfter=Jan 1 2030 GMT\n", stderr: "", code: 0 };
			}
			return { stdout: "/api 200 12 \n", stderr: "", code: 0 };
		};

		const summary = await runAutoBatchManaged([httpId, dirsId, portsId, tlsId], st, mockExec, root, {
			concurrency: 2,
			budgetMs: 5_000,
		});

		expect(maxObserved).toBe(2);
		expect(portsOverlap).toBe(0);
		expect(summary.skippedIds).toEqual([]);
		expect(Object.keys(summary.results).length).toBe(4);
		expect(summary.results[portsId]?.ok).toBe(true);
	});

	test("总预算超时与 AbortSignal 取消均触发 onBudgetSkip 回调剩余 ID", async () => {
		const root = makeDir("nuwa-batch-budget-");
		const st = fresh();
		const ids = pickAuto(st, cfg, 4);
		expect(ids.length).toBe(4);

		// 1. 预算超时测试：每条耗时 45ms，总预算 65ms -> 仅第 1 条完成，后 3 条被 budget_exceeded 跳过
		let skippedFromCb: string[] = [];
		let reasonFromCb = "";
		const slowExec: ExecLike = async () => {
			await Bun.sleep(45);
			return { stdout: "open 80\n", stderr: "", code: 0 };
		};

		const budgetSummary = await runAutoBatchManaged(ids, st, slowExec, root, {
			budgetMs: 65,
			concurrency: 1,
			onBudgetSkip(rem, reason) {
				skippedFromCb = rem;
				reasonFromCb = reason;
			},
		});

		expect(reasonFromCb).toBe("budget_exceeded");
		expect(skippedFromCb.length).toBeGreaterThanOrEqual(2);
		expect(budgetSummary.skippedIds).toEqual(skippedFromCb);

		// 2. 外部 AbortController 取消测试
		const ac = new AbortController();
		let abortSkipped: string[] = [];
		let abortReason = "";
		setTimeout(() => ac.abort(), 25);

		const abortSummary = await runAutoBatchManaged(ids, st, slowExec, root, {
			budgetMs: 10_000,
			concurrency: 1,
			signal: ac.signal,
			onBudgetSkip(rem, reason) {
				abortSkipped = rem;
				abortReason = reason;
			},
		});

		expect(abortReason).toBe("aborted");
		expect(abortSkipped.length).toBeGreaterThanOrEqual(3);
		expect(abortSummary.skipReason).toBe("aborted");
	});
});

describe("空转与尝试上限", () => {
	test("连续 emptyLimit 轮无新事实 → 收口模型批", () => {
		const st = fresh();
		st.runtime.lastFacts = 0;
		st.runtime.emptyRounds = 0;
		const first = Object.values(st.intents)[0];
		first.status = "claimed";
		first.worker = "fujiang";
		first.claimedAt = new Date().toISOString();
		expect(applyEmptyGuard(st, cfg)).toEqual([]);
		expect(applyEmptyGuard(st, cfg)).toEqual([]);
		const blocked = applyEmptyGuard(st, cfg);
		expect(blocked).toContain(first.id);
		expect(st.intents[first.id].status).toBe("blocked");
		expect(st.runtime.emptyRounds).toBe(0);
	});

	test("auto 批不被空转闸收口", () => {
		const st = fresh();
		st.runtime.lastFacts = 0;
		st.runtime.emptyRounds = 0;
		const first = Object.values(st.intents)[0];
		first.status = "claimed";
		first.worker = "auto";
		first.claimedAt = new Date().toISOString();
		applyEmptyGuard(st, cfg);
		applyEmptyGuard(st, cfg);
		expect(applyEmptyGuard(st, cfg)).toEqual([]);
		expect(st.intents[first.id].status).toBe("claimed");
	});

	test("facts 增长会清零空转计数", () => {
		const st = fresh();
		st.runtime.lastFacts = 0;
		st.runtime.emptyRounds = 2;
		st.facts.f999 = {
			id: "f999",
			kind: "note",
			title: "t",
			detail: "d",
			createdAt: new Date().toISOString(),
		};
		expect(applyEmptyGuard(st, cfg)).toEqual([]);
		expect(st.runtime.emptyRounds).toBe(0);
		expect(st.runtime.lastFacts).toBe(1);
	});

	test("autoPlan 把超限意图转 blocked", () => {
		const st = fresh();
		const first = Object.values(st.intents)[0];
		first.status = "open";
		first.attempts = 3;
		autoPlan(st, cfg);
		expect(st.intents[first.id].status).toBe("blocked");
		expect(st.intents[first.id].note).toContain("尝试上限");
	});
});
