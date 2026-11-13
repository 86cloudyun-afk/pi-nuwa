/**
 * 2.2.0 永动引擎测试：预算不停机、frontier 永不空、episode 无限扩张、续跑只走 decision:block。
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	addFallbackIntent,
	autoPlan,
	budgetPressure,
	buildDirective,
	compactIntents,
	deriveFromFacts,
	maybeAdvance,
	newState,
	normalizeState,
	readCfg,
	releaseStaleClaims,
	seedEpisode,
	seedPhase,
	stopReason,
	type Cfg,
	type NuwaState,
} from "../omp/nuwa";

const cfg: Cfg = { ...readCfg(), infinite: true, maxBatch: 4, claimTtl: 900 };

function fresh(mode: "ctf" | "pentest" = "ctf"): NuwaState {
	const st = newState("10.0.0.5:8080", "打穿并拿 flag", mode, cfg);
	seedPhase(st, "recon");
	return st;
}

function finishAll(st: NuwaState): void {
	for (const it of Object.values(st.intents)) {
		it.status = "done";
		it.doneAt = new Date().toISOString();
	}
}

function addServiceFact(st: NuwaState, detail = "80/tcp open http nginx 1.18\n22/tcp open ssh OpenSSH 8.9"): void {
	st.facts.f001 = {
		id: "f001",
		kind: "service",
		title: "10.0.0.5 开放端口",
		detail,
		command: "nmap -sT -sV -Pn 10.0.0.5",
		output: detail,
		createdAt: new Date().toISOString(),
	};
}

describe("无限模式停机判定", () => {
	test("预算全部超限也不停", () => {
		const st = fresh();
		st.runtime.turns = 100_000;
		st.runtime.tokens = 999_000_000;
		st.runtime.stall = 999;
		st.runtime.idle = 999;
		st.runtime.startedAt = Date.now() - 365 * 24 * 3600 * 1000;
		expect(stopReason(st, cfg)).toBeNull();
	});

	test("目标完成才停", () => {
		const st = fresh();
		st.project.status = "completed";
		expect(stopReason(st, cfg)).toBe("completed");
	});

	test("人工停机保留原因", () => {
		const st = fresh();
		st.project.status = "stopped";
		st.project.stopReason = "scope changed";
		expect(stopReason(st, cfg)).toBe("scope changed");
	});

	test("非无限模式仍保留预算闸（兼容）", () => {
		const st = fresh();
		st.runtime.turns = 10;
		const finite: Cfg = { ...cfg, infinite: false, maxTurns: 5 };
		expect(stopReason(st, finite)).toContain("max_turns");
	});

	test("压力可超过 1 但不产生停机", () => {
		const st = fresh();
		st.runtime.turns = 50;
		const finite: Cfg = { ...cfg, maxTurns: 10 };
		expect(budgetPressure(st, finite)).toBeGreaterThan(1);
		expect(stopReason(st, cfg)).toBeNull();
	});
});

describe("事实派生扩张", () => {
	test("service 事实派生按端口意图且幂等", () => {
		const st = fresh();
		addServiceFact(st);
		const first = deriveFromFacts(st);
		expect(first.added.length).toBe(2);
		expect(first.rules).toContain("svc:f001:80");
		expect(first.rules).toContain("svc:f001:22");
		const second = deriveFromFacts(st);
		expect(second.added.length).toBe(0);
	});

	test("vuln 事实派生利用与横向两条", () => {
		const st = fresh();
		st.facts.f002 = {
			id: "f002",
			kind: "vuln",
			title: "SQLi in /login",
			detail: "boolean based",
			command: "sqlmap -u http://10.0.0.5:8080/login --batch",
			output: "Parameter username is vulnerable",
			createdAt: new Date().toISOString(),
		};
		const r = deriveFromFacts(st);
		expect(r.rules).toContain("exp:f002");
		expect(r.rules).toContain("pivot:f002");
	});

	test("无事实时不派生", () => {
		const st = fresh();
		expect(deriveFromFacts(st).added.length).toBe(0);
	});
});

describe("autoPlan：frontier 永不空", () => {
	test("有 live 意图不动", () => {
		const st = fresh();
		const r = autoPlan(st, cfg);
		expect(r.reason).toBe("frontier-live");
		expect(r.added.length).toBe(0);
	});

	test("frontier 空时从事实派生", () => {
		const st = fresh();
		finishAll(st);
		addServiceFact(st);
		const r = autoPlan(st, cfg);
		expect(r.reason).toBe("derive");
		expect(r.added.length).toBeGreaterThan(0);
	});

	test("report 全终态后自动开下一轮 episode", () => {
		const st = fresh();
		st.project.phase = "report";
		seedPhase(st, "report");
		finishAll(st);
		const r = autoPlan(st, cfg);
		expect(r.reason).toBe("episode");
		expect(r.episode).toBe(2);
		expect(st.project.phase).toBe("recon");
		expect(r.added.length).toBeGreaterThanOrEqual(30);
	});

	test("episode 种子带轮次前缀且可重复播", () => {
		const st = fresh();
		const e2 = seedEpisode(st, 2);
		expect(e2.length).toBeGreaterThanOrEqual(30);
		expect(Object.values(st.intents).some((i) => i.key === "e2:recon:http")).toBe(true);
		expect(seedEpisode(st, 2).length).toBe(0);
		const e3 = seedEpisode(st, 3);
		expect(e3.length).toBeGreaterThanOrEqual(30);
	});

	test("没有任何可派生面时兜底深挖", () => {
		const st = fresh();
		finishAll(st);
		st.project.phase = "report";
		seedPhase(st, "report");
		finishAll(st);
		// 封顶 episode 后必须落到 fallback，保证队列不为空
		const capped: Cfg = { ...cfg, maxEpisodes: 1 };
		const r = autoPlan(st, capped);
		expect(r.reason).toBe("fallback");
		const fb = Object.values(st.intents).filter((i) => i.key.startsWith("fallback:"));
		expect(fb.length).toBe(1);
		const second = addFallbackIntent(st);
		expect(second).not.toBeNull();
		expect(Object.values(st.intents).filter((i) => i.key.startsWith("fallback:")).length).toBe(2);
	});

	test("连续 60 轮零事实产出，frontier 仍不为空", () => {
		const st = fresh();
		const seen = new Set<string>();
		for (let round = 0; round < 60; round++) {
			const r = autoPlan(st, cfg);
			seen.add(r.reason);
			const live = Object.values(st.intents).filter((i) => i.status === "open" || i.status === "claimed");
			expect(live.length).toBeGreaterThan(0);
			// 模拟本轮执行完 4 条但没有任何新事实
			for (const it of live.slice(0, 4)) {
				it.status = "done";
				it.doneAt = new Date().toISOString();
			}
			expect(buildDirective(st, cfg).length).toBeGreaterThan(0);
		}
		expect(seen.has("episode")).toBe(true);
	});

	test("紧凑化只回收过量 blocked", () => {
		const st = fresh();
		for (let i = 0; i < 200; i++) {
			st.intents[`x${i}`] = {
				id: `x${i}`,
				phase: "recon",
				key: `k${i}`,
				title: `t${i}`,
				detail: "",
				from: [],
				status: "blocked",
				priority: 1,
				attempts: 1,
				createdAt: new Date(Date.now() + i).toISOString(),
				doneAt: new Date(Date.now() + i).toISOString(),
			};
		}
		const removed = compactIntents(st, 120);
		expect(removed).toBe(80);
		expect(Object.values(st.intents).filter((i) => i.status === "blocked").length).toBe(120);
	});
});


describe("stale claim 释放", () => {
	test("超过 TTL 的 claimed 释放回 open，新鲜的保留", () => {
		const st = fresh();
		const ids = Object.keys(st.intents);
		const a = st.intents[ids[0]];
		const b = st.intents[ids[1]];
		a.status = "claimed";
		a.claimedAt = new Date(Date.now() - 3_600_000).toISOString();
		a.worker = "fujiang";
		b.status = "claimed";
		b.claimedAt = new Date().toISOString();
		b.worker = "fujiang";
		const released = releaseStaleClaims(st, 900);
		expect(released).toContain(a.id);
		expect(released).not.toContain(b.id);
		expect(st.intents[a.id].status).toBe("open");
		expect(st.intents[a.id].claimedAt).toBeUndefined();
		expect(st.intents[b.id].status).toBe("claimed");
	});

	test("autoPlan 先释放 stale，再判断 frontier", () => {
		const st = fresh();
		for (const i of Object.values(st.intents)) {
			i.status = "claimed";
			i.claimedAt = new Date(Date.now() - 7_200_000).toISOString();
			i.worker = "fujiang";
		}
		const r = autoPlan(st, cfg);
		expect(r.reason).toBe("frontier-live");
		expect(Object.values(st.intents).every((i) => i.status === "open")).toBe(true);
	});
});

describe("指令与续跑形态", () => {
	test("frontier 空时指令要求扩张且不引导停机", () => {
		const st = fresh();
		finishAll(st);
		const d = buildDirective(st, cfg);
		expect(d).toContain("nuwa_expand()");
		expect(d).toContain("禁止 nuwa_stop");
		expect(d).toContain("只有 nuwa_complete 返回 ok=true");
	});

	test("每轮都带硬性动作要求", () => {
		const st = fresh();
		expect(buildDirective(st, cfg)).toContain("本轮硬性动作");
	});

	test("续跑只走 decision:block，不存在 continue 分支", () => {
		const src = readFileSync(join(import.meta.dir, "..", "omp", "nuwa.ts"), "utf8");
		expect(src).toContain('return { decision: "block" as const, reason: directive };');
		expect(src).not.toContain("continue: true");
	});
});

describe("旧状态兼容", () => {
	test("缺字段的 state 读入后补齐", () => {
		const st = fresh();
		delete st.project.episode;
		delete st.runtime.lastSettleAt;
		delete st.runtime.expansions;
		normalizeState(st);
		expect(st.project.episode).toBe(1);
		expect(st.runtime.lastSettleAt).toBe(0);
		expect(st.runtime.expansions).toBe(0);
	});

	test("maybeAdvance 仍按阶段推进", () => {
		const st = fresh();
		finishAll(st);
		const r = maybeAdvance(st);
		expect(r.advanced).toBe(true);
		expect(r.phase).toBe("surface");
	});
});
