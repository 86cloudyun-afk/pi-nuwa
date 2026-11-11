import { describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	VERSION,
	buildDirective,
	checkBashPolicy,
	checkTaskPolicy,
	checkWritePolicy,
	claimIntent,
	commitIntent,
	completeProject,
	evidenceProblem,
	frontierList,
	maybeAdvance,
	migrateSapper,
	newState,
	normalizeTarget,
	readCfg,
	recordFlag,
	reportMarkdown,
	seedPhase,
	sigOf,
	statusBoard,
	type NuwaState,
} from "../omp/nuwa";

const cfg = readCfg();

function fresh(mode: "ctf" | "pentest" = "ctf"): NuwaState {
	const st = newState("10.0.0.5:8080", "打穿并拿 flag", mode, cfg);
	seedPhase(st, "recon");
	return st;
}

function commitAllRecon(st: NuwaState, except?: string): void {
	for (const it of Object.values(st.intents)) {
		if (it.phase !== "recon" || it.id === except) continue;
		commitIntent(st, {
			id: it.id,
			kind: "service",
			title: `${it.id} done`,
			detail: "test",
			command: `curl -sS ${st.project.url}`,
			output: "HTTP/1.1 200 OK server: nginx",
		});
	}
}

describe("target", () => {
	test("补协议与端口", () => {
		const t = normalizeTarget("10.0.0.5:8080/app/");
		expect(t.url).toBe("http://10.0.0.5:8080/app");
		expect(t.host).toBe("10.0.0.5");
		expect(t.port).toBe(8080);
	});
	test("https 默认端口", () => {
		const t = normalizeTarget("https://example.com");
		expect(t.port).toBe(443);
		expect(t.scheme).toBe("https");
	});
	test("拒绝空目标", () => {
		expect(() => normalizeTarget("")).toThrow();
	});
});

describe("playbook", () => {
	test("recon 播种 6 条且幂等", () => {
		const st = fresh();
		expect(Object.keys(st.intents).length).toBe(6);
		expect(seedPhase(st, "recon")).toEqual([]);
	});
	test("六阶段都有种子", () => {
		for (const p of ["recon", "surface", "vuln", "exploit", "post", "report"] as const) {
			expect(seedPhase(newState("http://a.test", "g", "ctf", cfg), p).length).toBeGreaterThan(0);
		}
	});
	test("frontier 按优先级排序", () => {
		const st = fresh();
		const f = frontierList(st, 10, cfg.claimTtl);
		expect(f[0].intent.key).toBe("recon:http");
		expect(f.map((x) => x.intent.id)).toContain("i002");
	});
});

describe("claim", () => {
	test("派单包含目标与命令", () => {
		const st = fresh();
		const r = claimIntent(st, "i001");
		expect(r.packet).toContain("10.0.0.5:8080");
		expect(r.packet).toContain("curl -k -sS");
		expect(r.intent.status).toBe("claimed");
		expect(r.intent.attempts).toBe(1);
	});
	test("重复 claim 被拒", () => {
		const st = fresh();
		claimIntent(st, "i001");
		expect(() => claimIntent(st, "i001")).toThrow(/已被/);
	});
	test("stale claim 可重领并累加 attempts", () => {
		const st = fresh();
		claimIntent(st, "i001");
		st.intents.i001.claimedAt = new Date(Date.now() - 3600_000).toISOString();
		const r = claimIntent(st, "i001");
		expect(r.stale).toBe(true);
		expect(r.intent.attempts).toBe(2);
	});
});

describe("commit", () => {
	test("无证据拒绝", () => {
		const st = fresh();
		claimIntent(st, "i001");
		expect(() => commitIntent(st, { id: "i001", kind: "service", title: "x" })).toThrow(/证据不足/);
	});
	test("echo 不能作为证据", () => {
		expect(evidenceProblem("vuln", "echo x", "x")).toMatch(/echo/);
	});
	test("成功入账并绑定 fact", () => {
		const st = fresh();
		claimIntent(st, "i001");
		const r = commitIntent(st, {
			id: "i001",
			kind: "service",
			title: "HTTP 200 nginx",
			detail: "server: nginx",
			command: "curl -k -sS -D - http://10.0.0.5:8080",
			output: "HTTP/1.1 200 OK\nServer: nginx",
		});
		expect(r.fact?.id).toBe("f001");
		expect(st.intents.i001.status).toBe("done");
		expect(st.intents.i001.to).toBe("f001");
		expect(r.duplicate).toBe(false);
	});
	test("幂等：同 attempt 同结论不重复入账", () => {
		const st = fresh();
		claimIntent(st, "i001");
		const input = {
			id: "i001",
			kind: "service" as const,
			title: "HTTP 200 nginx",
			command: "curl -k -sS http://10.0.0.5:8080",
			output: "HTTP/1.1 200 OK Server: nginx",
		};
		commitIntent(st, input);
		st.intents.i001.status = "claimed";
		const r = commitIntent(st, input);
		expect(r.duplicate).toBe(true);
		expect(Object.keys(st.facts).length).toBe(1);
	});
	test("blocked 收口不需要证据", () => {
		const st = fresh();
		claimIntent(st, "i001");
		const r = commitIntent(st, { id: "i001", kind: "note", title: "", blocked: true, note: "WAF 全部 403" });
		expect(r.intent.status).toBe("blocked");
	});
});

describe("phase", () => {
	test("阶段未清空不推进", () => {
		const st = fresh();
		expect(maybeAdvance(st).advanced).toBe(false);
		expect(st.project.phase).toBe("recon");
	});
	test("全部终态后推进并播种下一阶段", () => {
		const st = fresh();
		for (const it of Object.values(st.intents)) it.status = "blocked";
		const r = maybeAdvance(st);
		expect(r.advanced).toBe(true);
		expect(st.project.phase).toBe("surface");
		expect(r.added.length).toBe(6);
	});
	test("commit 最后一条自动推进", () => {
		const st = fresh();
		const ids = Object.values(st.intents).map((i) => i.id);
		const last = ids.pop() as string;
		commitAllRecon(st, last);
		claimIntent(st, last);
		const r = commitIntent(st, {
			id: last,
			kind: "service",
			title: "last",
			command: "curl -sS http://10.0.0.5:8080",
			output: "HTTP/1.1 200 OK",
		});
		expect(r.advanced?.phase).toBe("surface");
		expect(Object.values(st.intents).filter((i) => i.phase === "surface").length).toBe(6);
	});
});

describe("flag 与完成闸门", () => {
	test("flag output 必须含完整值", () => {
		const st = fresh();
		expect(() => recordFlag(st, "flag{abc}", "curl x", "no flag here")).toThrow(/包含/);
	});
	test("flag 幂等", () => {
		const st = fresh();
		const a = recordFlag(st, "flag{abc}", "curl x", "result: flag{abc}");
		const b = recordFlag(st, "flag{abc}", "curl x", "result: flag{abc}");
		expect(a.fact.id).toBe("f001");
		expect(b.duplicate).toBe(true);
	});
	test("ctf 无 flag 拒绝完成", () => {
		const st = fresh();
		const r = completeProject(st);
		expect(r.ok).toBe(false);
		expect(st.runtime.completionRejects).toBe(1);
	});
	test("ctf 有 flag 才收口", () => {
		const st = fresh();
		recordFlag(st, "flag{abc}", "curl x", "result: flag{abc}");
		const r = completeProject(st);
		expect(r.ok).toBe(true);
		expect(st.project.status).toBe("completed");
		expect(st.project.completedFrom).toEqual(["f001"]);
	});
	test("pentest 允许 vuln 收口", () => {
		const st = fresh("pentest");
		claimIntent(st, "i001");
		commitIntent(st, {
			id: "i001",
			kind: "vuln",
			title: "SQLi",
			command: "sqlmap -u http://x/?id=1 --batch",
			output: "Parameter id is vulnerable",
		});
		expect(completeProject(st).ok).toBe(true);
	});
});

describe("directive", () => {
	test("包含派单协议且不引用 CLI", () => {
		const st = fresh();
		st.runtime.turns = 3;
		const d = buildDirective(st, cfg);
		expect(d).toContain("nuwa_claim");
		expect(d).toContain('agent:"fujiang"');
		expect(d).toContain("nuwa_commit");
		expect(d).not.toContain("sapper dispatch");
		expect(d).not.toContain("bin/nuwa \"");
	});
	test("全部认领未提交时要求先 commit", () => {
		const st = fresh();
		for (const it of Object.values(st.intents)) claimIntent(st, it.id);
		const d = buildDirective(st, cfg);
		expect(d).toContain("已认领但未提交");
		expect(d).toContain("nuwa_commit");
	});
	test("stall 提示换路", () => {
		const st = fresh();
		st.runtime.stall = 4;
		expect(buildDirective(st, cfg)).toContain("无有效推进");
	});
});

describe("policy", () => {
	test("主线程扫描被拦，子代理放行", () => {
		expect(checkBashPolicy("nmap -sV 10.0.0.5", true, true)?.block).toBe(true);
		expect(checkBashPolicy("nmap -sV 10.0.0.5", true, false)).toBeNull();
	});
	test("CLI 被拦", () => {
		expect(checkBashPolicy("~/sapper-lab/bin/nuwa http://x", true, true)?.reason).toContain("N-002");
		expect(checkBashPolicy("nuwa dispatch i001", true, false)?.reason).toContain("N-002");
	});
	test("task 必须 fujiang", () => {
		expect(checkTaskPolicy({ tasks: [{ agent: "task" }] }, true, true)?.block).toBe(true);
		expect(checkTaskPolicy({ tasks: [{ agent: "fujiang" }] }, true, true)).toBeNull();
		expect(checkTaskPolicy({ agent: "fujiang", task: "x" }, true, true)).toBeNull();
	});
	test("受保护状态文件不可写", () => {
		expect(checkWritePolicy({ path: "/p/.nuwa/state.json" }, true)?.block).toBe(true);
		expect(checkWritePolicy({ path: "/p/.nuwa/notes.md" }, true)).toBeNull();
		expect(checkWritePolicy({ path: "/p/.nuwa/state.json" }, false)).toBeNull();
	});
	test("重定向写 state 被拦", () => {
		expect(checkBashPolicy("echo x > .nuwa/state.json", true, false)?.reason).toContain("N-003");
	});
});

describe("输出", () => {
	test("看板含阶段表", () => {
		const st = fresh();
		const b = statusBoard(st);
		expect(b).toContain("女娲 v" + VERSION);
		expect(b).toContain("| phase");
		expect(b).toContain("recon");
	});
	test("报告含 flag 台账", () => {
		const st = fresh();
		recordFlag(st, "flag{abc}", "curl x", "result: flag{abc}");
		const md = reportMarkdown(st);
		expect(md).toContain("# 渗透报告");
		expect(md).toContain("flag{abc}");
		expect(md).toContain("## 攻击链");
	});
	test("签名随事实变化", () => {
		const st = fresh();
		const a = sigOf(st);
		recordFlag(st, "flag{abc}", "curl x", "result: flag{abc}");
		expect(sigOf(st)).not.toBe(a);
	});
});

describe("sapper 迁移", () => {
	test("事实与意图重编号并保持引用", () => {
		const dir = mkdtempSync(join(tmpdir(), "nuwa-mig-"));
		mkdirSync(join(dir, ".sapper/facts"), { recursive: true });
		mkdirSync(join(dir, ".sapper/intents"), { recursive: true });
		writeFileSync(
			join(dir, ".sapper/project.json"),
			JSON.stringify({ goal: "迁移测试", status: "active", created_at: new Date().toISOString() }),
		);
		writeFileSync(
			join(dir, ".sapper/facts/f001.json"),
			JSON.stringify({ id: "f001", kind: "host", description: "http://10.1.1.1:8080 alive", created_at: new Date().toISOString() }),
		);
		writeFileSync(
			join(dir, ".sapper/facts/f002.json"),
			JSON.stringify({ id: "f002", kind: "vuln", description: "sqli", created_at: new Date().toISOString(), source_intent: "i001" }),
		);
		writeFileSync(
			join(dir, ".sapper/intents/i001.json"),
			JSON.stringify({ id: "i001", description: "打注入", status: "done", from: ["f001"], to: "f002", created_at: new Date().toISOString() }),
		);
		const st = migrateSapper(dir);
		expect(Object.keys(st.facts).length).toBe(2);
		expect(Object.keys(st.intents).length).toBe(1);
		const i = st.intents.i001;
		expect(i.status).toBe("done");
		expect(st.facts[i.from[0]].kind).toBe("asset");
		expect(st.facts[i.to as string].kind).toBe("vuln");
		expect(st.facts[i.to as string].intent).toBe("i001");
		expect(st.project.url).toContain("10.1.1.1:8080");
	});
});
