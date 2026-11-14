/**
 * 2.6.0 自渗透测试：规则解析、pickAuto、runAutoIntent、空转闸、尝试上限。
 */
import { describe, expect, test } from "bun:test";
import {
	applyEmptyGuard,
	autoPlan,
	claimAutoBatch,
	newState,
	readCfg,
	seedPhase,
	type Cfg,
	type NuwaState,
} from "../omp/nuwa";
import {
	AUTO_KEYS,
	originOf,
	pickAuto,
	ruleFor,
	runAutoIntent,
	shellQuote,
	type ExecLike,
} from "../omp/autoexec";

const cfg: Cfg = { ...readCfg(), auto: true, autoMax: 3, emptyLimit: 3, maxAttempts: 3 };

function fresh(): NuwaState {
	const st = newState("10.0.0.5:8080", "打穿并拿 flag", "ctf", cfg);
	seedPhase(st, "recon");
	return st;
}

function execOf(stdout: string, code = 0): ExecLike {
	return async () => ({ stdout, stderr: "", code, killed: false });
}

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

describe("规则解析", () => {
	test("http 解析状态/Server/标题", () => {
		const st = fresh();
		const rule = ruleFor("recon:http")!;
		const out = [
			"FINAL 200 1234 http://10.0.0.5:8080/",
			"---HEAD---",
			"HTTP/1.1 200 OK",
			"Server: nginx",
			"X-Powered-By: PHP/8.2",
			"---BODY---",
			"<html><title>Home</title></html>",
		].join("\n");
		const fact = rule.parse({ stdout: out, stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("service");
		expect(fact.title).toContain("200");
		expect(fact.title).toContain("nginx");
		expect(fact.detail).toContain("x-powered-by=PHP/8.2");
		expect(fact.detail).toContain("title=Home");
	});

	test("http 无响应返回 null", () => {
		const st = fresh();
		const rule = ruleFor("recon:http")!;
		expect(rule.parse({ stdout: "", stderr: "", code: 7 }, st)).toBeNull();
	});

	test("ports 解析 open 行", () => {
		const st = fresh();
		const rule = ruleFor("recon:ports")!;
		const fact = rule.parse({ stdout: "open 22\nopen 80\nopen 443\n", stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("service");
		expect(fact.title).toContain("3");
		expect(fact.detail).toContain("22,80,443");
	});

	test("dirs 解析路径行", () => {
		const st = fresh();
		const rule = ruleFor("recon:dirs")!;
		const out = "/admin 403 1234 \n/api 200 999 \n/x 404 0 \n";
		const fact = rule.parse({ stdout: out, stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("endpoint");
		expect(fact.detail).toContain("/admin");
		expect(fact.detail).toContain("/api");
		expect(fact.detail).not.toContain("/x");
	});

	test("sensitive 命中 .git/HEAD 记 vuln", () => {
		const st = fresh();
		const rule = ruleFor("surface:sensitive")!;
		const fact = rule.parse({ stdout: "/.git/HEAD 200 ref: refs/heads/main\n", stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("vuln");
		expect(fact.title).toContain("敏感文件暴露");
	});

	test("api 文档暴露判定", () => {
		const st = fresh();
		const rule = ruleFor("surface:api")!;
		const fact = rule.parse({ stdout: '/openapi.json 200 {"openapi":"3.0.0"}\n', stderr: "", code: 0 }, st)!;
		expect(fact.kind).toBe("endpoint");
		expect(fact.title).toContain("API 文档");
	});

	test("tls 解析 subject/SAN", () => {
		const st = fresh();
		const rule = ruleFor("recon:tlsjs")!;
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
	});
});

describe("调度", () => {
	test("pickAuto 只选白名单 key", () => {
		const st = fresh();
		const ids = pickAuto(st, cfg, 10);
		const keys = ids.map((id) => st.intents[id].key);
		expect(keys.length).toBeGreaterThan(0);
		for (const k of keys) expect(AUTO_KEYS).toContain(k as never);
		expect(keys).not.toContain("recon:vhost");
		expect(keys).not.toContain("recon:techcve");
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

	test("runAutoIntent 无产出返回 error", async () => {
		const st = fresh();
		const rule = ruleFor("recon:ports")!;
		const res = await runAutoIntent(rule, st, execOf("", 1), "/tmp");
		expect(res.ok).toBe(false);
		expect(res.error).toContain("无产出");
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
