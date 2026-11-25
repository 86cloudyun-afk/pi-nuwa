/**
 * v5.1 图状态机、封盘终态、表面分域去重、语义停滞与不截断可观测性专项测试。
 *
 * 完整覆盖 13 个 GitHub Issues：
 * #21, #22, #25, #29, #30, #31, #34, #35, #38, #41, #43, #45, #49
 * 以及 Fact / CommitInput 上 #42 evidenceRef 与 #51 agentResult 字段兼容性。
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dirs: string[] = [];
let AGENT_HOME = "";

function makeTempDir(prefix = "nuwa-v51-graph-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	dirs.push(d);
	return d;
}

let graphMod: typeof import("../omp/graph");
let reinMod: typeof import("../omp/reincarnate");
let uiMod: typeof import("../omp/ui");
let uiNativeMod: typeof import("../omp/ui-native");
let storageMod: typeof import("../omp/storage");

beforeAll(async () => {
	AGENT_HOME = makeTempDir("nuwa-v51-home-");
	process.env.PI_AGENT_HOME = AGENT_HOME;
	process.env.NUWA_KB_DB = join(AGENT_HOME, "nuwa-kb", "kb.db");
	delete process.env.NUWA_PROJECT;
	delete process.env.NUWA_HEADLESS_DAEMON;
	delete process.env.NUWA_NOVELTY_STALL_THRESHOLD;
	delete process.env.NUWA_BLOCKED_COOLDOWN_MS;

	graphMod = await import("../omp/graph");
	reinMod = await import("../omp/reincarnate");
	uiMod = await import("../omp/ui");
	uiNativeMod = await import("../omp/ui-native");
	storageMod = await import("../omp/storage");
});

afterAll(() => {
	for (const d of dirs) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("硬性契约：#42 evidenceRef 与 #51 agentResult 字段兼容与透传", () => {
	test("commitIntent 与 commitFreeFact 完整保留 evidenceRef 和 agentResult", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "渗透评估", "pentest", cfg);
		graphMod.seedPhase(st, "recon");

		const r1 = graphMod.commitIntent(st, {
			id: "i001",
			kind: "service",
			title: "HTTP 200 Next.js 16.3.3",
			detail: "Turbopack + Cloudflare",
			command: "curl -sS -D - http://rggo5269.com:80/",
			output: "HTTP/1.1 200 OK\nServer: cloudflare",
			evidenceRef: ".nuwa/evidence/f001.log",
			agentResult: {
				status: "ok",
				target: "http://rggo5269.com:80/",
				http_code: 200,
				size_download: 87815,
			},
		});
		expect(r1.fact?.evidenceRef).toBe(".nuwa/evidence/f001.log");
		expect(r1.fact?.agentResult).toEqual({
			status: "ok",
			target: "http://rggo5269.com:80/",
			http_code: 200,
			size_download: 87815,
		});

		const freeRes = graphMod.commitFreeFact(st, {
			kind: "note",
			title: "RSC Flight 分析",
			detail: "Server Actions 数量为 0",
			evidenceRef: ".nuwa/evidence/f002.log",
			agentResult: { status: "negative", actions: 0 },
		});
		expect(freeRes.fact.evidenceRef).toBe(".nuwa/evidence/f002.log");
		expect(freeRes.fact.agentResult).toEqual({ status: "negative", actions: 0 });
	});
});

describe("#21 (NW-01) 已尝试过滤器 attempted(kind, targetKey) 与 repeatRatio", () => {
	test("覆盖 done 与 blocked 状态，无 force 或无新前置事实时抑制重派生，compactIntents 后仍记忆", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "评估目标", "pentest", cfg);

		st.facts.f001 = {
			id: "f001",
			kind: "endpoint",
			title: "初步路由发现",
			detail: "/admin /login",
			meta: { paths: ["/admin", "/login"] },
			createdAt: "2026-11-25T10:00:00.000Z",
		};

		const d1 = graphMod.deriveFromFacts(st);
		expect(d1.added.length).toBe(2);
		const adminIntent = Object.values(st.intents).find((i) => i.targetKey === "/admin")!;
		const loginIntent = Object.values(st.intents).find((i) => i.targetKey === "/login")!;
		expect(adminIntent).toBeDefined();
		expect(loginIntent).toBeDefined();

		// /admin 提交为 blocked，/login 提交为 done
		graphMod.commitIntent(st, {
			id: adminIntent.id,
			blocked: true,
			note: "Cloudflare 403 拦截",
		});
		graphMod.commitIntent(st, {
			id: loginIntent.id,
			kind: "note",
			title: "/login 已核查无注入",
			detail: "静态表单页",
		});

		expect(graphMod.attempted(st, "vuln", "/admin")).toBe(true);
		expect(graphMod.attempted(st, "vuln", "/login")).toBe(true);
		expect(graphMod.attempted(st, "vuln", "/api/v1")).toBe(false);

		// 新增另一条同质 endpoint 事实再次上报 /admin 和 /login + 新路径 /api/v1
		st.facts.f002 = {
			id: "f002",
			kind: "endpoint",
			title: "二次爬虫路由",
			detail: "/admin /login /api/v1",
			meta: { paths: ["/admin", "/login", "/api/v1"] },
			createdAt: "2026-11-25T10:05:00.000Z",
		};
		const d2 = graphMod.deriveFromFacts(st);
		// 仅 /api/v1 被派生，/admin 与 /login 均被抑制
		expect(d2.added.length).toBe(1);
		expect(st.intents[d2.added[0]!]!.targetKey).toBe("/api/v1");
		expect(d2.rejectedReasons.some((r) => r.targetKey === "/admin")).toBe(true);
		expect(d2.rejectedReasons.some((r) => r.targetKey === "/login")).toBe(true);

		// 即使 compactIntents 强制清空所有 blocked 票据，attemptedKeys 依然阻止 /admin 死灰复燃
		graphMod.compactIntents(st, 0);
		expect(Object.values(st.intents).filter((i) => i.status === "blocked").length).toBe(0);
		expect(graphMod.attempted(st, "vuln", "/admin")).toBe(true);
		expect(graphMod.deriveFromFacts(st).added.length).toBe(0);

		// 显式传 force=true 时允许强制重派生
		expect(graphMod.attempted(st, "vuln", "/admin", { force: true })).toBe(false);
		const forcedPlan = graphMod.planIntents(st, {
			intents: [{ title: "强制复测 /admin", target: "/admin", expectedKind: "vuln", phase: "vuln", force: true }],
		});
		expect(forcedPlan.added.length).toBe(1);

		// 获得新 cred 凭据前置事实时，自动解锁先前 blocked 的目标
		st.facts.f003 = {
			id: "f003",
			kind: "cred",
			title: "获取管理员 Bearer Token",
			detail: "role=admin",
			command: "curl -sS http://rggo5269.com:80/auth",
			output: "token=adm_12345678",
			createdAt: new Date(Date.now() + 5_000).toISOString(),
		};
		expect(graphMod.attempted(st, "vuln", "/admin", { from: ["f003"] })).toBe(false);
	});

	test("快照与状态摘要准确输出 repeatRatio = 1 - distinct/total", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "测试重复率", "ctf", cfg);
		// 空图 repeatRatio = 0
		expect(graphMod.computeRepeatRatio(st)).toEqual({ total: 0, distinct: 0, repeatRatio: 0 });

		// 添加 4 条意图：其中 3 条指向同一 (vuln, /admin)，1 条指向 (vuln, /login) => total=4, distinct=2, repeatRatio=0.5
		graphMod.addIntent(st, { title: "审计 /admin #1", target: "/admin", expectedKind: "vuln", phase: "vuln" });
		graphMod.addIntent(st, { title: "审计 /admin #2", target: "/admin/", expectedKind: "vuln", phase: "vuln" });
		graphMod.addIntent(st, { title: "审计 /admin #3", target: "http://rggo5269.com:80/admin", expectedKind: "vuln", phase: "vuln" });
		graphMod.addIntent(st, { title: "审计 /login #1", target: "/login", expectedKind: "vuln", phase: "vuln" });

		const rep = graphMod.computeRepeatRatio(st);
		expect(rep.total).toBe(4);
		expect(rep.distinct).toBe(2);
		expect(rep.repeatRatio).toBeCloseTo(0.5, 4);

		const snap = uiMod.buildSnapshot(st, cfg, 0.2);
		expect(snap.totals.repeatRatio).toBeCloseTo(0.5, 4);
		expect(snap.runtime.repeatRatio).toBeCloseTo(0.5, 4);

		const board = graphMod.statusBoard(st);
		expect(board).toContain("repeatRatio=0.50");
	});
});

describe("#22 (NW-02) 封盘终态 sealed_negative、sealEngagement 与 shouldRecommendSeal", () => {
	test("sealEngagement 落盘 sealed_negative 与 sealMeta，并作为 stopReason 合法终态", () => {
		const dir = makeTempDir("nuwa-seal-");
		const cfg = { ...storageMod.readCfg(), infinite: true };
		const st = graphMod.newState("http://rggo5269.com:80", "CTF 夺旗", "ctf", cfg);
		graphMod.seedPhase(st, "recon");
		storageMod.saveState(dir, st, { reason: "init" });

		// 封盘前永动模式下 stopReason 为 null
		expect(graphMod.stopReason(st, cfg)).toBeNull();

		const res = graphMod.sealEngagement(dir, {
			reason: "全站静态化 + 注册双门禁(SMS+Turnstile)，49 条事实均排除 RCE/SQLi",
			excludedSurface: ["/admin", "/api/v1/member/signup", "rggo5269.com:21"],
			coverage: { endpointsTested: 63, rscActions: 0 },
		});

		expect(res.ok).toBe(true);
		expect(res.status).toBe("sealed_negative");
		expect(res.sealMeta.excludedSurface).toContain("/admin");
		expect(res.sealMeta.coverage.endpointsTested).toBe(63);
		expect(typeof res.sealMeta.sealedAt).toBe("string");

		const loaded = storageMod.loadState(dir)!;
		expect(loaded.project.status).toBe("sealed_negative");
		// 验证磁盘原始 JSON 中 runtime.status 与 runtime.sealMeta 已持久化
		const rawDisk = JSON.parse(readFileSync(join(dir, ".nuwa", "state.json"), "utf8"));
		expect(rawDisk.runtime.status).toBe("sealed_negative");
		expect(rawDisk.runtime.sealMeta.reason).toContain("Turnstile");

		// 封盘终态与 completed 并列解除永动续跑
		expect(graphMod.stopReason(rawDisk, cfg)).toBe("sealed_negative");
	});

	test("shouldRecommendSeal 在轮次超限、成本超限或 noveltyStall >= threshold 时建议封盘", () => {
		const cfg = { ...storageMod.readCfg(), maxTurns: 100, maxTokens: 500_000, maxCostUsd: 5.0, noveltyStallThreshold: 8 };
		const st = graphMod.newState("http://rggo5269.com:80", "test", "ctf", cfg);

		expect(graphMod.shouldRecommendSeal(st.runtime, cfg).recommend).toBe(false);

		// 1) noveltyStall >= 8
		st.runtime.noveltyStall = 8;
		const rStall = graphMod.shouldRecommendSeal(st.runtime, cfg);
		expect(rStall.recommend).toBe(true);
		expect(rStall.reason).toContain("novelty_stall(8>=8)");

		// 2) 成本超限
		st.runtime.noveltyStall = 0;
		st.runtime.totalCostUsd = 5.25;
		const rCost = graphMod.shouldRecommendSeal(st.runtime, cfg);
		expect(rCost.recommend).toBe(true);
		expect(rCost.reason).toContain("max_cost_usd");

		// 3) 轮次达上限
		st.runtime.totalCostUsd = 0;
		st.runtime.turns = 100;
		const rTurns = graphMod.shouldRecommendSeal(st.runtime, cfg);
		expect(rTurns.recommend).toBe(true);
		expect(rTurns.reason).toContain("max_turns(100>=100)");
	});
});

describe("#25 (NW-05) surfaceDomain 显式分域、隔离与跨层派生前置检查", () => {
	test("inferSurfaceDomain 准确识别 port / path / host，且端口级 blocked 不污染路径级推导", () => {
		expect(graphMod.inferSurfaceDomain("rggo5269.com:21")).toBe("port");
		expect(graphMod.inferSurfaceDomain("port:rggo5269.com:80")).toBe("port");
		expect(graphMod.inferSurfaceDomain("22/tcp")).toBe("port");
		expect(graphMod.inferSurfaceDomain("/admin/login")).toBe("path");
		expect(graphMod.inferSurfaceDomain("http://rggo5269.com:80/api/v1")).toBe("path");
		expect(graphMod.inferSurfaceDomain("api.rggo5269.com")).toBe("host");

		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "分域测试", "pentest", cfg);

		// 端口 80 和 21 的服务深挖全部被标为 blocked
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "端口扫描",
			detail: "21/tcp 80/tcp",
			meta: { ports: [21, 80] },
			surfaceDomain: "port",
			createdAt: new Date().toISOString(),
		};
		const dPort = graphMod.deriveFromFacts(st);
		expect(dPort.added.length).toBe(2);
		for (const id of dPort.added) {
			expect(st.intents[id]!.surfaceDomain).toBe("port");
			graphMod.commitIntent(st, { id, blocked: true, note: "端口探测超时阻断" });
		}

		// 端口域处于冷却中，但路径域完全不受污染，可正常推导路径审计
		expect(graphMod.isTargetInBlockedCooldown(st, "rggo5269.com:80", { surfaceDomain: "port" })).toBe(true);
		expect(graphMod.isTargetInBlockedCooldown(st, "/admin", { surfaceDomain: "path" })).toBe(false);

		st.facts.f002 = {
			id: "f002",
			kind: "endpoint",
			title: "发现后台路径",
			detail: "/admin",
			meta: { paths: ["/admin"] },
			surfaceDomain: "path",
			createdAt: new Date().toISOString(),
		};
		const dPath = graphMod.deriveFromFacts(st);
		expect(dPath.added.length).toBe(1);
		expect(st.intents[dPath.added[0]!]!.surfaceDomain).toBe("path");
		expect(st.intents[dPath.added[0]!]!.targetKey).toBe("/admin");

		// 跨层派生：无前置事实时拒绝从 port 跨层派生 path；有非 HTTP 纯端口 banner 事实也拒绝；有 HTTP/endpoint 事实才放行
		expect(graphMod.canDeriveCrossSurface(st, "port", "path", [])).toBe(false);
		st.facts.f003 = {
			id: "f003",
			kind: "service",
			title: "21/tcp FTP",
			detail: "vsftpd 3.0.3",
			surfaceDomain: "port",
			createdAt: new Date().toISOString(),
		};
		expect(graphMod.canDeriveCrossSurface(st, "port", "path", ["f003"])).toBe(false);
		expect(graphMod.canDeriveCrossSurface(st, "port", "path", ["f002"])).toBe(true);
	});
});

describe("#29 (NW-09) Intent.expectedKind 自动推断与 commitIntent 缺省继承", () => {
	test("规划/派生/认领自动填充 expectedKind，commitIntent 省略 kind 时继承 expectedKind（兜底 note）", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://10.0.0.5:8080", "kind 继承测试", "pentest", cfg);
		graphMod.seedPhase(st, "recon");

		// recon:http 种子 detail 含 `证据: kind=service`，自动推断 expectedKind="service"
		expect(st.intents.i001!.expectedKind).toBe("service");
		expect(st.intents.i003!.expectedKind).toBe("endpoint"); // recon:dirs -> endpoint

		const claimed = graphMod.claimIntent(st, "i001");
		expect(claimed.intent.expectedKind).toBe("service");
		expect(claimed.packet).toContain("期望类型: service");

		// commitIntent 省略 input.kind，自动继承 i001.expectedKind ("service")
		const committed = graphMod.commitIntent(st, {
			id: "i001",
			title: "HTTP 200 Apache",
			detail: "Server: Apache/2.4",
			command: "curl -sS -I http://10.0.0.5:8080/",
			output: "HTTP/1.1 200 OK\nServer: Apache/2.4",
		});
		expect(committed.fact?.kind).toBe("service");

		// 自定义无提示手工构造旧式 intent（无 expectedKind），commitIntent 省略 kind 时安全兜底为 "note"
		st.intents.i999 = {
			id: "i999",
			phase: "report",
			key: "legacy:manual",
			title: "通用备注整理",
			detail: "",
			from: [],
			status: "claimed",
			priority: 50,
			attempts: 1,
			createdAt: new Date().toISOString(),
		};
		const fallbackCommit = graphMod.commitIntent(st, {
			id: "i999",
			title: "手工总结",
			detail: "已完成阶段盘点",
		});
		expect(fallbackCommit.fact?.kind).toBe("note");
	});
});

describe("#30 (NW-10) Runtime.noveltyStall 语义停滞计数与升级信号", () => {
	test("blocked=true 提交绝不重置 noveltyStall，达阈值 8 触发升级，产出非 blocked 新 Fact 立即归零", () => {
		const cfg = { ...storageMod.readCfg(), noveltyStallThreshold: 8 };
		const st = graphMod.newState("http://rggo5269.com:80", "停滞测试", "ctf", cfg);
		graphMod.seedPhase(st, "recon");

		// 模拟连续 8 轮只有 blocked=true 提交，没有新非 blocked 事实
		for (let round = 1; round <= 8; round++) {
			const it = graphMod.addIntent(st, {
				title: `无效尝试 #${round}`,
				target: `/dead-${round}`,
				phase: "recon",
			});
			const cRes = graphMod.commitIntent(st, {
				id: it.id,
				blocked: true,
				note: "403 Cloudflare 阻断",
			});
			expect(cRes.blockedCommitsDelta).toBe(1);
			// 每轮结算推进 noveltyStall
			graphMod.applyEmptyGuard(st, cfg, true);
			expect(st.runtime.noveltyStall).toBe(round);
		}

		expect(st.runtime.noveltyStall).toBe(8);
		expect(st.runtime.semanticStall).toBe(true);

		// 再次提交 blocked=true，noveltyStall 绝对不被重置为 0！
		const extraBlocked = graphMod.addIntent(st, { title: "又一次阻断", target: "/dead-9", phase: "recon" });
		graphMod.commitIntent(st, { id: extraBlocked.id, blocked: true, note: "依然 403 阻断" });
		expect(st.runtime.noveltyStall).toBe(8);

		// 供封盘与转世消费
		expect(graphMod.shouldRecommendSeal(st, cfg).recommend).toBe(true);
		expect(reinMod.shouldReincarnate(st, { headless: true, maxTokens: 999_999, maxTurns: 999 }).needed).toBe(true);
		expect(graphMod.buildDirective(st, cfg)).toContain("语义停滞升级");

		// 产出一个非 blocked 的新 Fact 后，noveltyStall 立即归零！
		graphMod.commitIntent(st, {
			id: "i001",
			kind: "service",
			title: "HTTP 200 源站存活",
			detail: "通过 socks5 出口连通",
			command: "curl -x socks5h://127.0.0.1:7890 -sS http://rggo5269.com:80/zh-tw",
			output: "HTTP/1.1 200 OK\nContent-Length: 110674",
		});
		expect(st.runtime.noveltyStall).toBe(0);
		expect(st.runtime.semanticStall).toBe(false);
	});
});

describe("#31 (NW-11) 无票据直记 commitFreeFact 与 commitIntent 免 intent 直通", () => {
	test("open=0 时仍可通过 commitFreeFact 或省略 id / freeNote=true 落账关键事实", () => {
		const dir = makeTempDir("nuwa-free-fact-");
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "免票据落账测试", "pentest", cfg);
		graphMod.seedPhase(st, "recon");
		// 将所有意图置为 blocked，制造 open=0 且无 claimed 票据的极端状态
		for (const it of Object.values(st.intents)) {
			it.status = "blocked";
			it.note = "全部阻断";
			it.doneAt = new Date().toISOString();
		}
		const intentCountBefore = Object.keys(st.intents).length;
		expect(Object.values(st.intents).filter((i) => i.status === "open").length).toBe(0);

		// 1) commitIntent 省略 id 直通落账
		const r1 = graphMod.commitIntent(st, {
			kind: "note",
			title: "确认 CVE-2025-29927 为假阳性",
			detail: "Next.js 16.3.3 已忽略 x-middleware-subrequest 头",
		});
		expect(r1.freeFact).toBe(true);
		expect(r1.fact?.id).toBe("f001");
		expect(Object.keys(st.intents).length).toBe(intentCountBefore);

		// 2) commitIntent 传 freeNote=true 直通落账带证据的 endpoint 事实
		const r2 = graphMod.commitIntent(st, {
			id: "i001",
			freeNote: true,
			kind: "endpoint",
			title: "POST /api/v1/member/profile 存在需鉴权",
			detail: "405 Allow: POST",
			command: "curl -sS -i http://rggo5269.com:80/api/v1/member/profile",
			output: "HTTP/1.1 405 Method Not Allowed\nAllow: POST",
		});
		expect(r2.freeFact).toBe(true);
		expect(r2.fact?.id).toBe("f002");
		expect(st.intents.i001!.status).toBe("blocked"); // 不篡改原 blocked 票据

		// 3) 磁盘级 commitFreeFact(root, input)
		storageMod.saveState(dir, st, { reason: "init" });
		const diskFree = graphMod.commitFreeFact(dir, {
			kind: "note",
			title: "buildManifest 披露 5 条反代前缀",
			detail: "/api /file /liveapi /bkapi /r2imgs",
		});
		expect(diskFree.fact.id).toBe("f003");
		expect(diskFree.duplicate).toBe(false);
		expect(storageMod.loadState(dir)!.facts.f003?.title).toContain("buildManifest");
	});
});

describe("#34 (NW-14) renderFullStatus 不截断状态渲染（ui.ts & graph.ts 双导出）", () => {
	test("消除 768B 截断，支持 raw、offset/limit 分页与 text/json 双格式", () => {
		expect(graphMod.renderFullStatus).toBe(uiMod.renderFullStatus);

		const dir = makeTempDir("nuwa-full-status-");
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "长文本不截断验证", "pentest", cfg);
		const longDetail = `完整证据链详情-${"LONG_PAYLOAD_SEGMENT_".repeat(80)}END_MARKER_999`;
		for (let i = 1; i <= 15; i++) {
			graphMod.addIntent(st, {
				title: `深度审计任务 #${String(i).padStart(2, "0")} - /api/v1/module_${i}`,
				detail: longDetail,
				target: `/api/v1/module_${i}`,
				phase: "vuln",
			});
		}
		graphMod.commitFreeFact(st, {
			kind: "note",
			title: "超长复盘事实",
			detail: longDetail,
		});
		storageMod.saveState(dir, st, { reason: "init" });

		const fullText = graphMod.renderFullStatus(dir, { raw: true, format: "text" });
		expect(Buffer.byteLength(fullText, "utf8")).toBeGreaterThan(2048); // 远超 768B 不截断
		expect(fullText).toContain("END_MARKER_999");
		expect(fullText).toContain("/api/v1/module_15");

		// 分页查询验证
		const pagedJsonStr = uiMod.renderFullStatus(dir, { offset: 5, limit: 4, format: "json" });
		const paged = JSON.parse(pagedJsonStr);
		expect(paged.pagination.offset).toBe(5);
		expect(paged.pagination.limit).toBe(4);
		expect(paged.pagination.totalIntents).toBe(15);
		expect(paged.pagination.hasMore).toBe(true);
		expect(paged.pagination.nextOffset).toBe(9);
		expect(paged.intents.length).toBe(4);
	});
});

describe("#35 (NW-15) 纯只读诊断函数 inspectGraph（严格零磁盘写入）", () => {
	test("支持 intentId / status / targetKey / limit 过滤，且不修改任何 .nuwa/* 文件内容或 mtime", async () => {
		const dir = makeTempDir("nuwa-inspect-readonly-");
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "只读诊断验证", "pentest", cfg);
		const i1 = graphMod.addIntent(st, { title: "审计 /admin", target: "/admin", phase: "vuln" });
		const i2 = graphMod.addIntent(st, { title: "审计 /api/v1", target: "/api/v1", phase: "vuln" });
		graphMod.commitIntent(st, { id: i1.id, blocked: true, note: "403 Cloudflare Ray=abc123" });
		storageMod.saveState(dir, st, { forceSnapshot: true, reason: "init" });

		const nuwaDir = join(dir, ".nuwa");
		const snapshotDirMeta = () => {
			const files = readdirSync(nuwaDir).sort();
			return files.map((f) => {
				const full = join(nuwaDir, f);
				const s = statSync(full);
				const hash = s.isFile()
					? createHash("sha256").update(readFileSync(full)).digest("hex")
					: "dir";
				return { file: f, size: s.size, mtimeMs: s.mtimeMs, hash };
			});
		};

		const beforeMeta = snapshotDirMeta();
		await Bun.sleep(20);

		const byStatus = graphMod.inspectGraph(dir, { status: "blocked" });
		expect(byStatus.ok).toBe(true);
		expect(byStatus.matchedCount).toBe(1);
		expect(byStatus.intents[0]!.id).toBe(i1.id);
		expect(byStatus.intents[0]!.note).toContain("Ray=abc123");

		const byTarget = graphMod.inspectGraph(dir, { targetKey: "http://rggo5269.com:80/api/v1/" });
		expect(byTarget.matchedCount).toBe(1);
		expect(byTarget.intents[0]!.id).toBe(i2.id);

		const byId = graphMod.inspectGraph(dir, { intentId: i1.id, limit: 1 });
		expect(byId.intents.length).toBe(1);

		const afterMeta = snapshotDirMeta();
		expect(afterMeta).toEqual(beforeMeta);
	});
});

describe("#38 (NW-18) UI 与 Native 节点渲染 last_ok、blocked_ratio 及连续 403 边缘受阻标记", () => {
	test("连续 403/blocked 时直观标记边缘受阻而非泛化侦察中，有 200 时显示 last_ok=200", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "边缘受阻可视化", "ctf", cfg);
		graphMod.seedPhase(st, "recon");

		// 连续两次 403 blocked 探测，尚无任何 200 成功事实
		graphMod.commitIntent(st, { id: "i001", blocked: true, note: "HTTP 403 Cloudflare ASN block" });
		graphMod.commitIntent(st, { id: "i002", blocked: true, note: "HTTP 403 Forbidden WAF" });

		const snapBlocked = uiMod.buildSnapshot(st, cfg, 0.3);
		expect(snapBlocked.probe.lastOk).toBe("none");
		expect(snapBlocked.probe.blockedRatio).toBe(1);
		expect(snapBlocked.probe.edgeBlocked).toBe(true);
		expect(snapBlocked.probe.stageLabel).toContain("边缘受阻");

		const statusLine = uiMod.renderStatusLine(snapBlocked, uiMod.plainStyle);
		expect(uiMod.visibleWidth(statusLine)).toBeLessThanOrEqual(48);
		expect(statusLine).toContain("last_ok=none");
		expect(statusLine).toContain("阻");

		const widgetText = uiMod.renderWidgetLines(snapBlocked, uiMod.plainStyle, { width: 96 }).join("\n");
		expect(widgetText).toContain("边缘受阻");
		expect(widgetText).toContain("last_ok=none");
		expect(widgetText).toContain("blocked_ratio=100%");

		const boardNode = uiNativeMod.buildBoardNode(snapBlocked, () => true);
		const serialized = JSON.stringify(boardNode);
		expect(serialized).toContain("边缘受阻");
		expect(serialized).toContain("last_ok=none");
		expect(serialized).toContain("blocked_ratio=100%");

		// 随后切换健康代理拿到 HTTP 200 事实后，解除边缘受阻并显示 last_ok=200 与更新后的 blocked_ratio
		graphMod.commitIntent(st, {
			id: "i003",
			kind: "endpoint",
			title: "目录探测成功",
			detail: "/zh-tw 200",
			command: "curl -x socks5h://127.0.0.1:7890 -sS http://rggo5269.com:80/zh-tw",
			output: "HTTP/1.1 200 OK\nContent-Length: 110674",
			meta: { status: 200, paths: ["/zh-tw"] },
		});
		const snapRecovered = uiMod.buildSnapshot(st, cfg, 0.3);
		expect(snapRecovered.probe.lastOk).toBe("200");
		expect(snapRecovered.probe.edgeBlocked).toBe(false);
		expect(snapRecovered.probe.blockedRatio).toBeCloseTo(2 / 3, 3);
		expect(uiMod.renderStatusLine(snapRecovered, uiMod.plainStyle)).toContain("last_ok=200");
	});
});

describe("#41 (NW-21) completionRejects >= 1 策略收敛建议与防空转重跑", () => {
	test("completeProject 被拒后导出收敛建议，autoPlan 收敛至 report/seal 而非原样重播 Episode", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "收敛测试", "ctf", cfg);
		graphMod.seedPhase(st, "recon");
		for (const it of Object.values(st.intents)) {
			it.status = "blocked";
			it.note = "无暴露面";
			it.doneAt = new Date().toISOString();
		}

		const comp = graphMod.completeProject(st);
		expect(comp.ok).toBe(false);
		expect(st.runtime.completionRejects).toBe(1);

		const advice = graphMod.buildConvergenceAdvice(st, cfg);
		expect(advice.active).toBe(true);
		expect(advice.recommendedAction).toBe("report_and_seal");
		expect(advice.forbidBlindRerun).toBe(true);
		expect(advice.message).toContain("sealEngagement");

		// autoPlan 直接收敛至 report 阶段，不再盲目经历全部中间阶段或开启 E2 重跑
		const p1 = graphMod.autoPlan(st, cfg);
		expect(p1.phase).toBe("report");
		expect(p1.reason).toBe("converge-to-report");

		for (const it of Object.values(st.intents)) {
			if (it.status === "open") {
				it.status = "done";
				it.doneAt = new Date().toISOString();
			}
		}
		const p2 = graphMod.autoPlan(st, cfg);
		expect(p2.reason).toBe("report-seal-ready");
		expect(p2.added).toEqual([]);
		expect(st.project.episode).toBe(1); // 绝不盲目升到 E2 空转重跑
	});
});

describe("#43 (NW-23) 规范化三元组去重键、blocked 冷却窗抑制与 rejectedReasons", () => {
	test("区分不同测试向量新提示，准确返回 duplicate_key / blocked_cooldown / inflight 三种拒绝原因", () => {
		const cfg = { ...storageMod.readCfg(), blockedCooldownMs: 120_000 };
		const st = graphMod.newState("http://rggo5269.com:80", "三元组去重测试", "pentest", cfg);

		// 同一路径 /api/v1/member/signup 但 4 条不同攻击向量的提示应全部入队，绝不误拒！
		const batch1 = graphMod.planIntents(
			st,
			{
				phase: "vuln",
				intents: [
					{ title: "注册接口测试", target: "/api/v1/member/signup", hint: "sms_race_condition", detail: "并发短信验证码竞态" },
					{ title: "注册接口测试", target: "/api/v1/member/signup/", hint: "mass_assignment_role", detail: "PUT JSON role=admin 批量赋值" },
					{ title: "注册接口测试", target: "http://rggo5269.com:80/api/v1/member/signup", hint: "turnstile_null_token", detail: "空 token 校验缺失" },
					{ title: "后台模块枚举", target: "/api/v1/admin/users", hint: "method_override", detail: "X-HTTP-Method-Override 绕过" },
				],
			},
			cfg,
		);
		// phase="vuln" 会播种 10 条内置种子 + 4 条新向量自定义意图 = 14 条
		expect(batch1.rejectedReasons).toEqual([]);
		const customIds = batch1.added.filter((id) => st.intents[id]!.key.startsWith("custom:"));
		expect(customIds.length).toBe(4);

		// 1) duplicate_key：用等价 URL（带尾斜杠/协议头）提交相同 hint
		const dupPlan = graphMod.planIntents(
			st,
			{
				intents: [
					{
						title: "重复注册测试",
						target: "HTTP://RGGO5269.COM:80/api/v1/member/signup/",
						hint: "sms_race_condition",
						detail: "并发短信验证码竞态",
					},
				],
			},
			cfg,
		);
		expect(dupPlan.added).toEqual([]);
		expect(dupPlan.rejectedReasons).toEqual([
			{
				title: "重复注册测试",
				targetKey: "/api/v1/member/signup",
				reason: "duplicate_key",
			},
		]);

		// 2) inflight：认领 /api/v1/admin/users 使其处于 claimed 在途态，再次对该目标派发同类型任务被判为 inflight
		const adminUsersId = customIds[3]!;
		graphMod.claimIntent(st, adminUsersId, "fujiang");
		const inflightPlan = graphMod.planIntents(
			st,
			{
				intents: [
					{
						title: "并发撞车后台用户接口",
						target: "/api/v1/admin/users/",
						expectedKind: "vuln",
						hint: "another_probe_while_claimed",
					},
				],
			},
			cfg,
		);
		expect(inflightPlan.added).toEqual([]);
		expect(inflightPlan.rejectedReasons[0]?.reason).toBe("inflight");

		// 3) blocked_cooldown：将 /api/v1/admin/users 提交为 blocked，冷却窗内任何无新前置的同目标规划均返回 blocked_cooldown
		graphMod.commitIntent(st, { id: adminUsersId, blocked: true, note: "403 命名空间被边缘阻断" });
		const cooldownPlan = graphMod.planIntents(
			st,
			{
				intents: [
					{
						title: "冷却期内重打死路径",
						target: "/api/v1/admin/users",
						expectedKind: "vuln",
						hint: "retry_in_cooldown",
					},
				],
			},
			cfg,
		);
		expect(cooldownPlan.added).toEqual([]);
		expect(cooldownPlan.rejectedReasons).toEqual([
			{
				title: "冷却期内重打死路径",
				targetKey: "/api/v1/admin/users",
				reason: "blocked_cooldown",
			},
		]);
	});
});

describe("#45 (NW-25) 修复 report 阶段死锁（零正向漏洞下干净完结/转世/封盘）", () => {
	test("phase=report 且报告已写或停滞达标（vuln/exploit/post === 0）时不重展死事实并平滑转入 sealed_negative", () => {
		const dir = makeTempDir("nuwa-report-deadlock-");
		const cfg = { ...storageMod.readCfg(), noveltyStallThreshold: 8 };
		const st = graphMod.newState("http://rggo5269.com:80", "修复 report 死锁", "ctf", cfg);

		// 构造历史已死事实与被 compactIntents 压缩过的场景（模拟 E6 report 卡死现场）
		st.facts.f001 = {
			id: "f001",
			kind: "endpoint",
			title: "历史路径",
			detail: "/admin",
			meta: { paths: ["/admin"] },
			createdAt: "2026-11-25T08:00:00.000Z",
		};
		const d = graphMod.deriveFromFacts(st);
		for (const id of d.added) {
			graphMod.commitIntent(st, { id, blocked: true, note: "历史已测 403" });
		}
		graphMod.compactIntents(st, 0);

		st.project.phase = "report";
		st.project.episode = 6;
		const repIds = graphMod.seedPhase(st, "report");
		for (const id of repIds) {
			graphMod.commitIntent(st, {
				id,
				kind: "note",
				title: `报告收尾 ${id}`,
				detail: "攻击面已完整梳理，vuln=0 exploit=0 post=0",
			});
		}
		// 写入磁盘报告文件模拟 nuwa_report(write=true) 已完成
		storageMod.saveState(dir, st, { reason: "init" });
		writeFileSync(join(dir, ".nuwa", "REPORT.md"), "# 评估报告\n无高危漏洞\n", "utf8");
		st.runtime.reportWritten = true;

		// 1) autoPlan 绝不重展 /admin 死事实，直接返回 report-seal-ready
		const planRes = graphMod.autoPlan(st, cfg);
		expect(planRes.added).toEqual([]);
		expect(planRes.reason).toBe("report-seal-ready");

		// 2) reincarnate.ts 给出干净的 seal_negative 转移建议与交接摘要
		const trans = reinMod.resolveReportPhaseTransition(st, { reportWritten: true });
		expect(trans.action).toBe("seal_negative");
		const summary = reinMod.buildHandoffSummary(st, "report_phase_exit");
		expect(summary).toContain("禁止重展已死事实");

		// 3) finalizeReportPhase 一键干净完成 sealed_negative 状态转移
		const fin = graphMod.finalizeReportPhase(st, cfg, { root: dir, autoSeal: true });
		expect(fin.transition.action).toBe("seal_negative");
		expect(fin.sealed).toBeDefined();
		expect(st.project.status).toBe("sealed_negative");
		expect(st.runtime.status).toBe("sealed_negative");
	});
});

describe("#49 (NW-29) 区分 blockedIntents 与 Runtime.blockedCommits 及增量呈现", () => {
	test("compactIntents 回收票据后 blockedIntents 封顶但 blockedCommits 持续精确累加，UI 与返回值同步呈现", () => {
		const cfg = storageMod.readCfg();
		const st = graphMod.newState("http://rggo5269.com:80", "计数分离测试", "ctf", cfg);

		// 提交 5 次 blocked=true
		for (let i = 1; i <= 5; i++) {
			const it = graphMod.addIntent(st, { title: `探测点 #${i}`, target: `/p-${i}`, phase: "surface" });
			const r = graphMod.commitIntent(st, { id: it.id, blocked: true, note: `第 ${i} 次受阻` });
			expect(r.blockedIntents).toBe(i);
			expect(r.blockedCommits).toBe(i);
			expect(r.blockedIntentsDelta).toBe(1);
			expect(r.blockedCommitsDelta).toBe(1);
		}

		// 执行 compactIntents 仅保留 2 条 blocked 票据（模拟实战 120 条上限裁剪）
		const removed = graphMod.compactIntents(st, 2);
		expect(removed).toBe(3);

		// 再提交第 6 次 blocked=true：blockedIntents 变为 3 (+1)，而 blockedCommits 变为 6 (+1)！
		const it6 = graphMod.addIntent(st, { title: "探测点 #6", target: "/p-6", phase: "surface" });
		const r6 = graphMod.commitIntent(st, { id: it6.id, blocked: true, note: "第 6 次受阻" });
		expect(r6.blockedIntents).toBe(3);
		expect(r6.blockedCommits).toBe(6);
		expect(r6.blockedIntentsDelta).toBe(1);
		expect(r6.blockedCommitsDelta).toBe(1);

		const snap = uiMod.buildSnapshot(st, cfg, 0.1);
		expect(snap.totals.blockedIntents).toBe(3);
		expect(snap.totals.blockedCommits).toBe(6);
		expect(snap.totals.blockedIntentsDelta).toBe(1);
		expect(snap.totals.blockedCommitsDelta).toBe(1);

		const statusLine = uiMod.renderStatusLine(snap, uiMod.plainStyle);
		expect(uiMod.visibleWidth(statusLine)).toBeLessThanOrEqual(48);
		expect(statusLine).toContain("3/6+1");

		const wideLine = uiMod.renderStatusLine(snap, uiMod.plainStyle, { maxWidth: 120 });
		expect(wideLine).toContain("blocked=3/6(+1/+1)");
	});
});
