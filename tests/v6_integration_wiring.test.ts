import { afterEach, describe, expect, test } from "bun:test";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as graphMod from "../omp/graph";
import * as nuwaMod from "../omp/nuwa";
import { NuwaCoreEngine } from "../core/mcp-server";

const EXPECTED_12_TOOLS = [
	"nuwa_init",
	"nuwa_plan",
	"nuwa_frontier",
	"nuwa_claim",
	"nuwa_commit",
	"nuwa_flag",
	"nuwa_complete",
	"nuwa_status",
	"nuwa_report",
	"nuwa_expand",
	"nuwa_stop",
	"nuwa_kb",
] as const;

const tmpDirs: string[] = [];
const savedEnv: Record<string, string | undefined> = {};

function setEnvTemp(key: string, val: string | undefined): void {
	if (!(key in savedEnv)) savedEnv[key] = process.env[key];
	if (val === undefined) delete process.env[key];
	else process.env[key] = val;
}

function makeWorkspace(prefix = "nuwa-v6-wiring-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	mkdirSync(join(dir, ".git"), { recursive: true });
	writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
	tmpDirs.push(dir);
	return dir;
}

function snapshotTreeMtimes(dir: string): Array<{ rel: string; size: number; mtimeMs: number }> {
	const out: Array<{ rel: string; size: number; mtimeMs: number }> = [];
	const walk = (cur: string, prefix = "") => {
		if (!existsSync(cur)) return;
		for (const name of readdirSync(cur).sort()) {
			const abs = join(cur, name);
			const rel = prefix ? `${prefix}/${name}` : name;
			const st = statSync(abs);
			if (st.isDirectory()) {
				walk(abs, rel);
			} else {
				out.push({ rel, size: st.size, mtimeMs: Math.round(st.mtimeMs) });
			}
		}
	};
	walk(dir);
	return out;
}

function setupHarness(cwd: string, sessionId = "sess-v6-e2e") {
	const agentHome = makeWorkspace("nuwa-v6-agent-home-");
	setEnvTemp("PI_AGENT_HOME", agentHome);

	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	const notifications: Array<{ text: string; level: string }> = [];
	let commandDef: any = null;

	const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
	const z = new Proxy({}, { get: () => () => chain() });

	nuwaMod.default({
		zod: z,
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (_name: string, def: any) => {
			commandDef = def;
		},
		on: (ev: string, fn: any) => {
			const arr = hooks.get(ev) ?? [];
			arr.push(fn);
			hooks.set(ev, arr);
		},
	} as any);

	const ctx: any = {
		cwd,
		agent: { kind: "main", id: "main-0" },
		sessionManager: { getSessionId: () => sessionId },
		ui: {
			notify: (text: string, level = "info") => notifications.push({ text, level }),
			setStatus: () => {},
			setWidget: () => {},
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
		},
	};

	const call = (name: string, args: Record<string, unknown>) =>
		tools.get(name).execute("call-v6", args, undefined, undefined, ctx);
	const runSlash = (raw: string) => commandDef.handler(raw, ctx);

	return { tools, hooks, commandDef, notifications, ctx, call, runSlash, agentHome };
}

afterEach(() => {
	for (const [k, v] of Object.entries(savedEnv)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
	for (const k of Object.keys(savedEnv)) delete savedEnv[k];
	for (const d of tmpDirs.splice(0, tmpDirs.length)) {
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

describe("v6.0.0 架构不变量与 omp/graph.ts 巨石无环拆解兼容门面", () => {
	test("严格保持 12 个 nuwa_* 工具、版本号 6.0.0、omp/graph.ts < 2500 行且全量导出零丢失", () => {
		const ws = makeWorkspace();
		const h = setupHarness(ws);

		expect(nuwaMod.VERSION).toBe("6.0.0");
		expect(nuwaMod.NUWA_VERSION).toBe("6.0.0");
		expect(h.tools.size).toBe(12);
		expect([...h.tools.keys()].sort()).toEqual([...EXPECTED_12_TOOLS].sort());

		const repoRoot = resolve(import.meta.dir, "..");
		const graphLines = readFileSync(join(repoRoot, "omp/graph.ts"), "utf8").split("\n").length;
		expect(graphLines).toBeLessThan(2500);

		// 验证拆解后 omp/graph.ts 完整保留历史核心导出与新增子命令函数
		for (const sym of [
			"SEEDS",
			"newState",
			"seedPhase",
			"frontierList",
			"planIntents",
			"claimIntent",
			"commitIntent",
			"executeCommitWithGates",
			"executeAutoBatchCycle",
			"inspectGraph",
			"sealEngagement",
			"shouldRecommendSeal",
			"buildConvergenceAdvice",
			"statusBoard",
			"reportMarkdown",
			"executeBeliefCommand",
			"executeCalibrateCommand",
			"executeTrafficCommand",
			"executeHybridCommand",
			"executeMcpCommand",
		]) {
			expect(typeof (graphMod as Record<string, unknown>)[sym]).not.toBe("undefined");
			expect(typeof (nuwaMod as Record<string, unknown>)[sym]).not.toBe("undefined");
		}

		// 验证新增的 5 个 /nuwa 斜杠子命令已注册补全
		const completions = h.commandDef.getArgumentCompletions("").map((x: any) => x.value);
		for (const sub of ["belief", "calibrate", "traffic", "hybrid", "mcp"]) {
			expect(completions).toContain(sub);
		}
	});
});

describe("v6.0.0 SQLite WAL 权威存储全链路接线与兼容导出", () => {
	test("NUWA_STORAGE_BACKEND=sqlite 下全工具流读写 nuwa.db、FTS5 检索命中且纯 SQLite 只读诊断可用", async () => {
		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		const ws = makeWorkspace();
		const h = setupHarness(ws, "sess-sqlite-wiring");

		const initRes = await h.call("nuwa_init", {
			target: "http://127.0.0.1:18080",
			mode: "pentest",
			goal: "验证 SQLite 权威存储全链路接线",
		});
		expect(initRes.isError).toBeFalsy();
		expect(existsSync(nuwaMod.sqliteDbPath(ws))).toBe(true);
		expect(existsSync(nuwaMod.statePath(ws))).toBe(true);

		const claimRes = await h.call("nuwa_claim", { id: "i001", worker: "fujiang" });
		expect(claimRes.isError).toBeFalsy();

		const commitRes = await h.call("nuwa_commit", {
			id: "i001",
			kind: "service",
			title: "Spring Boot Actuator 暴露端点",
			detail: "检出 /actuator/env 与 CVE-2022-22947 路由特征",
			command: "curl -sS -D - http://127.0.0.1:18080/actuator",
			output:
				"HTTP/1.1 200 OK\nServer: Jetty\nhttp_code=200 size_download=512 remote_ip=127.0.0.1 time_total=0.02\n\n{\"_links\":{\"self\":{\"href\":\"http://127.0.0.1:18080/actuator\"}}}",
		});
		expect(commitRes.isError).toBeFalsy();

		const hits = nuwaMod.queryFactsByText(ws, "Actuator");
		expect(hits.length).toBeGreaterThanOrEqual(1);
		expect(hits[0]!.fact.title).toContain("Actuator");

		// 删除兼容 state.json 后，验证 loadState 与只读 inspectGraph 仍直接从权威 nuwa.db 准确读取
		unlinkSync(nuwaMod.statePath(ws));
		const loaded = nuwaMod.loadState(ws);
		expect(loaded).not.toBeNull();
		expect(Object.values(loaded!.facts).some((f) => f.title.includes("Actuator"))).toBe(true);

		const diag = nuwaMod.inspectGraph(ws, { intentId: "i001" });
		expect(diag.ok).toBe(true);
		expect(diag.intents[0]?.status).toBe("done");

		// 验证纯 SQLite 模式下血缘探测（meta 表 project_json）及全部只读命令严格零写盘（不产生 -wal/-shm 且 mtime 零变化）
		const resolvedLineage = nuwaMod.resolveLineageRoot(
			{ cwd: ws, sessionId: "sess-sqlite-wiring", agent: { kind: "sub", id: "sub-0", parentId: "main-0" } },
			h.agentHome,
		);
		expect(resolvedLineage).toBe(ws);

		await Bun.sleep(15);
		const snapBeforeRo = snapshotTreeMtimes(ws);
		expect(snapBeforeRo.some((f) => f.rel.endsWith("-wal") || f.rel.endsWith("-shm"))).toBe(false);
		await h.call("nuwa_status", {});
		for (const cmd of ["belief", "calibrate", "traffic", "hybrid", "mcp"]) {
			await h.runSlash(cmd);
		}
		const snapAfterRo = snapshotTreeMtimes(ws);
		expect(snapAfterRo).toEqual(snapBeforeRo);
	});
});

describe("v6.0.0 信念图前沿重排、双盲复验驳回剪枝与反自证校准闭环", () => {
	test("before_subagent_spawn 自动登记预测 -> candidate 不提前自证 -> 双盲复验驳回机械结算并级联剪枝下游意图", async () => {
		const ws = makeWorkspace();
		const h = setupHarness(ws, "sess-belief-calib");

		await h.call("nuwa_init", {
			target: "http://127.0.0.1:18081",
			mode: "pentest",
			goal: "验证信念剪枝与反自证校准闭环",
		});

		const planRes = await h.call("nuwa_plan", {
			phase: "vuln",
			intents: [
				{
					title: "检测 /api/v1/export 疑似 SQL 注入",
					targetKey: "/api/v1/export",
					expectedKind: "vuln",
					surfaceDomain: "path",
					priority: 88,
				},
			],
		});
		const vulnIntentId = planRes.details.added[0] as string;
		expect(vulnIntentId).toBeTruthy();

		// 1) 触发 before_subagent_spawn：自动基于信念后验向 calibration.jsonl 登记未结算预测
		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const spawnRes = onSpawn(
			{
				spawnId: "sp-cand-1",
				agent: "fujiang",
				model: "gemini-4-neon-xhigh",
				task: `[女娲派单 ${vulnIntentId}] 验证 http://127.0.0.1:18081/api/v1/export 参数注入`,
			},
			h.ctx,
		);
		expect(spawnRes?.spawnId).toBe("sp-cand-1");

		const recsAfterSpawn = nuwaMod.loadCalibrationRecords(ws);
		expect(recsAfterSpawn.length).toBe(1);
		expect(recsAfterSpawn[0]!.intentId).toBe(vulnIntentId);
		expect(recsAfterSpawn[0]!.settled).toBe(false);

		// 2) 提交候选漏洞（verifyStage=candidate）：严禁提前自我认证结算！
		await h.call("nuwa_claim", { id: vulnIntentId, worker: "fujiang" });
		const candCmd = "curl -sS 'http://127.0.0.1:18081/api/v1/export?id=1'";
		const candOut =
			"HTTP/1.1 200 OK\nContent-Type: application/json\n\n" +
			JSON.stringify({
				rows: [{ id: 1, name: "report_q4", owner: "dept_finance", sqlDebug: "SELECT * FROM reports WHERE id=1" }],
				meta: { queryTimeMs: 42, shard: "primary-db-01" },
			});
		nuwaMod.recordToolExecution(ws, { tool: "bash", command: candCmd, output: candOut, agentName: "fujiang" });

		const candCommit = await h.call("nuwa_commit", {
			id: vulnIntentId,
			kind: "vuln",
			title: "疑似 /api/v1/export 注入异常",
			detail: "500 报错疑似注入",
			command: candCmd,
			output: candOut,
		});
		expect(candCommit.details.verifyStage).toBe("candidate");
		const verifyIntentId = candCommit.details.verifyIntent as string;
		expect(verifyIntentId).toBeTruthy();

		// 确认在 candidate 阶段预测记录仍保持 settled=false（反自证核心红线）
		const recsAtCand = nuwaMod.loadCalibrationRecords(ws);
		expect(recsAtCand[0]!.settled).toBe(false);

		// 在候选事实下游挂载一条依赖它的后续利用 open 意图，验证复验驳回时自动级联剪枝
		const stMid = nuwaMod.loadState(ws)!;
		const candFactId = stMid.intents[vulnIntentId]!.to!;
		let downstreamId = "";
		nuwaMod.withLock(ws, () => {
			const s = nuwaMod.loadState(ws)!;
			const added = nuwaMod.appendIntentSpecs(s, [
				{
					key: `exploit:from:${candFactId}`,
					phase: "exploit",
					title: "利用 /api/v1/export 注入提取管理员表",
					detail: "基于候选注入事实深入利用",
					priority: 90,
					from: [candFactId],
				},
			]);
			downstreamId = added[0]!;
			nuwaMod.saveState(ws, s);
		});
		expect(downstreamId).toBeTruthy();

		// 3) 独立复验员 nuwa-verifier 双盲驳回该候选事实
		await h.call("nuwa_claim", { id: verifyIntentId, worker: "nuwa-verifier" });
		const rejectCommit = await h.call("nuwa_commit", {
			id: verifyIntentId,
			blocked: true,
			note: "正负对照实验均返回相同上游连接池 500 超时，非 SQL 注入假阳性",
		});
		expect(rejectCommit.details.verifyStage).toBe("rejected");

		// 4) 验证校准账本已由机械源 verifier-gate 自动结算为 outcome=0, isFalsePositive=true
		const recsSettled = nuwaMod.loadCalibrationRecords(ws);
		const settledOrig = recsSettled.find((r) => r.predictionId === "pred-sp-cand-1")!;
		expect(settledOrig.settled).toBe(true);
		expect(settledOrig.outcome).toBe(0);
		expect(settledOrig.isFalsePositive).toBe(true);
		expect(settledOrig.source).toBe("verifier-gate");

		// 5) 验证信念图已持久化且下游依赖意图已被自动剪枝置为 blocked
		expect(existsSync(nuwaMod.beliefGraphPath(ws))).toBe(true);
		const stAfterReject = nuwaMod.loadState(ws)!;
		expect(stAfterReject.facts[candFactId]?.verifyStage).toBe("rejected");
		expect(stAfterReject.intents[downstreamId]?.status).toBe("blocked");

		// 6) 验证校准自适应模型路由在积累高误报后自动切换健康模型
		for (let i = 0; i < 5; i++) {
			const p = nuwaMod.recordPrediction(ws, {
				intentId: `hist-bad-${i}`,
				taskCategory: "exploit",
				modelId: "model-noisy",
				predictedConfidence: 0.95,
				estimatedTokens: 2000,
			});
			nuwaMod.settlePrediction(ws, {
				predictionId: p.predictionId,
				outcome: 0,
				isFalsePositive: true,
				actualTokens: 2000,
				durationMs: 100,
				source: "verifier-gate",
			});
			const g = nuwaMod.recordPrediction(ws, {
				intentId: `hist-good-${i}`,
				taskCategory: "exploit",
				modelId: "model-calibrated",
				predictedConfidence: 0.85,
				estimatedTokens: 1500,
			});
			nuwaMod.settlePrediction(ws, {
				predictionId: g.predictionId,
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 1500,
				durationMs: 100,
				source: "verifier-gate",
			});
		}
		const routed = nuwaMod.routeSubagentModel({
			agent: "fujiang",
			phase: "exploit",
			deepModel: "model-noisy",
			verifyModel: "model-calibrated",
			root: ws,
		});
		expect(routed).toBe("model-calibrated");
	});
});

describe("v6.0.0 批处理收尾自主闭环（Auto-AuthDiff & Auto-OOB）与 5 个新斜杠视图零写盘验证", () => {
	test("runPostBatchAutonomousLoops 自动检出 BOLA + 自动播撒回收 OOB，且 /nuwa belief|calibrate|traffic|hybrid|mcp 严格零写盘", async () => {
		const oobHits: Array<Record<string, string>> = [];
		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			async fetch(req) {
				const u = new URL(req.url);
				const auth = req.headers.get("authorization") ?? "";
				if (u.pathname === "/api/orders/1001") {
					if (!auth) return Response.json({ error: "unauthorized" }, { status: 401 });
					// 模拟水平 BOLA：alice 和 bob 都能读取 alice 的订单详情
					return Response.json({ orderId: 1001, owner: "alice", amount: 9800, items: ["enterprise-license"] });
				}
				if (u.pathname === "/oob/poll") {
					return Response.json({ data: oobHits });
				}
				return new Response("Not Found", { status: 404 });
			},
		});

		try {
			const baseUrl = `http://127.0.0.1:${srv.port}`;
			const ws = makeWorkspace();
			const h = setupHarness(ws, "sess-autoloops-slash");

			await h.call("nuwa_init", {
				target: baseUrl,
				mode: "pentest",
				goal: "验证自主闭环与只读斜杠命令",
				scope: { allowLoopback: true, oobDomains: ["oob.test.local", "127.0.0.1"] },
			});

			const secretAlice = "tok_alice_super_secret_991122";
			const secretBob = "tok_bob_super_secret_883344";
			nuwaMod.upsertSessionRole(ws, { role: "user_alice", bearer: secretAlice });
			nuwaMod.upsertSessionRole(ws, { role: "user_bob", bearer: secretBob });

			// 记入发现的业务 API 与高危盲 SSRF 探测端点
			const freeRes = await h.call("nuwa_commit", {
				free_note: true,
				kind: "endpoint",
				title: "发现订单与异步 Webhook 接口",
				detail: "可测路径 /api/orders/1001 与 webhook callbackUrl 参数盲 SSRF 面",
				command: `curl -sS -I ${baseUrl}/api/orders/1001`,
				output: "HTTP/1.1 401 Unauthorized\nContent-Type: application/json\nhttp_code=401 size_download=26 remote_ip=127.0.0.1 time_total=0.01",
			});
			expect(freeRes.isError).toBeFalsy();
			nuwaMod.withLock(ws, () => {
				const s = nuwaMod.loadState(ws)!;
				const epFact = Object.values(s.facts).find((f) => f.kind === "endpoint")!;
				epFact.meta = { paths: ["/api/orders/1001"] };
				nuwaMod.appendIntentSpecs(s, [
					{
						key: "vuln:ssrf:webhook",
						phase: "vuln",
						title: "测试 /api/webhook callbackUrl 盲 SSRF 外带请求",
						detail: "验证异步 blind SSRF 回连",
						priority: 86,
						from: [epFact.id],
						targetKey: "/api/webhook",
					},
				]);
				nuwaMod.saveState(ws, s);
			});

			// 第 1 次运行收尾自主闭环：自动触发 AuthDiff 检出 BOLA 候选，并自动签发 OOB Canary
			const loopRes1 = await nuwaMod.runPostBatchAutonomousLoops(ws);
			expect(loopRes1.authDiffTriggered).toBe(true);
			expect(loopRes1.oobPlannedCanaries).toBeGreaterThanOrEqual(1);

			const canaries = JSON.parse(readFileSync(join(ws, ".nuwa/oob-canaries.json"), "utf8")) as {
				canaries: Array<{ id: string; fqdn: string; token: string }>;
			};
			const c0 = canaries.canaries[0]!;
			oobHits.push({
				id: "hit-1",
				"full-id": c0.fqdn,
				protocol: "http",
				"remote-address": "127.0.0.1",
				timestamp: new Date().toISOString(),
				"raw-request": `GET /cb HTTP/1.1 Host: ${c0.fqdn}`,
			});

			// 第 2 次传入 pollUrl 运行：验证 AuthDiff 处于冷却窗不重复触发，而 OOB 成功回收回连实锤
			const loopRes2 = await nuwaMod.runPostBatchAutonomousLoops(ws, {
				pollUrl: `${baseUrl}/oob/poll`,
			});
			expect(loopRes2.authDiffTriggered).toBe(false);
			expect(loopRes2.oobPolledHits).toBeGreaterThanOrEqual(1);

			const stAfterLoops = nuwaMod.loadState(ws)!;
			expect(Object.values(stAfterLoops.facts).some((f) => f.verifyStage === "candidate")).toBe(true);
			expect(Object.values(stAfterLoops.facts).some((f) => f.key.startsWith("oob:"))).toBe(true);

			// 准备一段本地示例源码供 /nuwa hybrid 扫描
			mkdirSync(join(ws, "src"), { recursive: true });
			writeFileSync(
				join(ws, "src", "server.ts"),
				`import express from "express";
const app = express();
app.get("/api/internal/export-users", async (req, res) => {
  const sql = "SELECT * FROM users WHERE dept = '" + req.query.dept + "'";
  res.json({ sql });
});
`,
				"utf8",
			);

			// 校验 5 个新增 /nuwa 子命令严格只读（零文件新增、零字节变化、零 mtime 变动）
			const beforeSnap = snapshotTreeMtimes(ws);
			for (const cmd of ["belief", "calibrate", "traffic", "hybrid src", "mcp"]) {
				await h.runSlash(cmd);
				expect(h.notifications.at(-1)?.level).toBe("info");
			}
			const afterSnap = snapshotTreeMtimes(ws);
			expect(afterSnap).toEqual(beforeSnap);

			// 显式执行 /nuwa hybrid plan src 时应成功将白盒桥接核验意图导入状态图
			await h.runSlash("hybrid plan src");
			expect(h.notifications.at(-1)?.text).toContain("本次已写入图:");
			const stAfterHybridPlan = nuwaMod.loadState(ws)!;
			expect(
				Object.values(stAfterHybridPlan.intents).some((it) => it.title.includes("/api/internal/export-users")),
			).toBe(true);

			// 扫描整个 .nuwa 目录（除加密/权限隔离的 sessions/vault.json 外）确认零明文凭据泄露
			const stateRaw = readFileSync(join(ws, ".nuwa/state.json"), "utf8");
			expect(stateRaw).not.toContain(secretAlice);
			expect(stateRaw).not.toContain(secretBob);
		} finally {
			srv.stop(true);
		}
	});
});

describe("Boost 异构审查边界回归验证（#37 全部 6 项 P1 与 P2 反例）", () => {
	test("P1-1: 确认/驳回/404受阻三类提交均真实更新持久化 belief-graph.json 后验并写入 belief_prune 事件", async () => {
		// 1) 普通 404 受阻提交不应抛异常吞没，belief-graph.json 必须正常落盘
		const wsBlocked = makeWorkspace("nuwa-p1-1-blk-");
		const hb = setupHarness(wsBlocked, "s-p1-1-blk");
		await hb.call("nuwa_init", { target: "http://127.0.0.1:18101", mode: "pentest" });
		await hb.call("nuwa_claim", { id: "i001", worker: "fujiang" });
		await hb.call("nuwa_commit", { id: "i001", blocked: true, note: "404 Not Found" });
		expect(existsSync(nuwaMod.beliefGraphPath(wsBlocked))).toBe(true);
		const bgBlk = nuwaMod.loadBeliefGraphReadOnly(wsBlocked)!;
		expect(bgBlk.nodes.i001!.posterior).toBeLessThan(0.5);

		// 2) 双盲确认 confirmed 必须使用 confirmed_hit 提升磁盘后验；双盲驳回 rejected 必须衰减剪枝并写 belief_prune 日志
		const wsVerify = makeWorkspace("nuwa-p1-1-ver-");
		const hv = setupHarness(wsVerify, "s-p1-1-ver");
		await hv.call("nuwa_init", { target: "http://127.0.0.1:18102", mode: "pentest" });
		const planned = await hv.call("nuwa_plan", {
			phase: "vuln",
			intents: [
				{ title: "候选漏洞 A（待确认）", targetKey: "/api/a", expectedKind: "vuln", surfaceDomain: "path" },
				{ title: "候选漏洞 B（待驳回）", targetKey: "/api/b", expectedKind: "vuln", surfaceDomain: "path" },
			],
		});
		const [idA, idB] = planned.details.added as [string, string];

		// 提交候选 A 并双盲确认
		await hv.call("nuwa_claim", { id: idA, worker: "fujiang" });
		const cmdA1 = "curl -sS http://127.0.0.1:18102/api/a";
		const outA1 =
			"HTTP/1.1 200 OK\nContent-Type: application/json\n\n" +
			JSON.stringify({ leak: "admin_private_config_dump_a1", rows: [1, 2, 3, 4], env: "prod" });
		nuwaMod.recordToolExecution(wsVerify, { tool: "bash", command: cmdA1, output: outA1, agentName: "fujiang" });
		const candA = await hv.call("nuwa_commit", {
			id: idA,
			kind: "vuln",
			title: "接口 A 未授权泄露",
			detail: "泄露配置",
			command: cmdA1,
			output: outA1,
		});
		const fidA = nuwaMod.loadState(wsVerify)!.intents[idA]!.to!;
		const postBeforeConfirm = nuwaMod.loadBeliefGraphReadOnly(wsVerify)!.nodes[fidA]!.posterior;

		await Bun.sleep(3);
		const verIdA = candA.details.verifyIntent as string;
		await hv.call("nuwa_claim", { id: verIdA, worker: "nuwa-verifier" });
		const cmdA2 = "curl -sS http://127.0.0.1:18102/api/a?recheck=1";
		const outA2 =
			"HTTP/1.1 200 OK\nContent-Type: application/json\n\n" +
			JSON.stringify({ leak: "admin_private_config_dump_a2_verified", rows: [1, 2, 3, 4], env: "prod" });
		nuwaMod.recordToolExecution(wsVerify, { tool: "bash", command: cmdA2, output: outA2, agentName: "nuwa-verifier" });
		const confRes = await hv.call("nuwa_commit", {
			id: verIdA,
			kind: "vuln",
			title: "[Verified] 接口 A 未授权泄露",
			detail: "独立复验确认",
			command: cmdA2,
			output: outA2,
		});
		expect(confRes.details.verifyStage).toBe("confirmed");
		const postAfterConfirm = nuwaMod.loadBeliefGraphReadOnly(wsVerify)!.nodes[fidA]!.posterior;
		expect(postAfterConfirm).toBeGreaterThan(postBeforeConfirm);

		// 提交候选 B 并双盲驳回
		await hv.call("nuwa_claim", { id: idB, worker: "fujiang" });
		const cmdB1 = "curl -sS http://127.0.0.1:18102/api/b";
		const outB1 =
			"HTTP/1.1 200 OK\nContent-Type: application/json\n\n" +
			JSON.stringify({ status: "public_catalog", items: ["x", "y", "z"], trace: "cand_b_payload" });
		nuwaMod.recordToolExecution(wsVerify, { tool: "bash", command: cmdB1, output: outB1, agentName: "fujiang" });
		const candB = await hv.call("nuwa_commit", {
			id: idB,
			kind: "vuln",
			title: "疑似接口 B 越权",
			detail: "待核验",
			command: cmdB1,
			output: outB1,
		});
		const fidB = nuwaMod.loadState(wsVerify)!.intents[idB]!.to!;
		const postBeforeReject = nuwaMod.loadBeliefGraphReadOnly(wsVerify)!.nodes[fidB]!.posterior;

		const verIdB = candB.details.verifyIntent as string;
		await hv.call("nuwa_claim", { id: verIdB, worker: "nuwa-verifier" });
		await hv.call("nuwa_commit", { id: verIdB, blocked: true, note: "公开目录接口，非越权假阳性" });

		const bgAfterReject = nuwaMod.loadBeliefGraphReadOnly(wsVerify)!;
		expect(bgAfterReject.nodes[fidB]!.posterior).toBeLessThan(postBeforeReject);
		expect(bgAfterReject.nodes[fidB]!.pruned).toBe(true);
		const journalRaw = readFileSync(nuwaMod.journalPath(wsVerify), "utf8");
		expect(journalRaw).toContain('"type":"belief_prune"');
	});

	test("P1-2 & P1-3: 信念图跨 loadState / NuwaCoreEngine 持久化重排生效且 compositeScore 归一化不淹没基础优先级", async () => {
		const ws = makeWorkspace("nuwa-p1-23-");
		const engine = new NuwaCoreEngine({ projectRoot: ws, cwd: ws, sessionId: "s-p1-23" });
		await engine.callTool("nuwa_init", { target: "http://127.0.0.1:18103", mode: "pentest" });

		const pRes = await engine.callTool("nuwa_plan", {
			intents: [
				{ phase: "vuln", title: "候选探索路径 A (p=60)", targetKey: "/api/boost", priority: 60 },
				{ phase: "vuln", title: "候选探索路径 B (p=85)", targetKey: "/api/pruned", priority: 85 },
			],
		});
		const [boostId, prunedId] = (pRes.details?.added as [string, string]) ?? [];

		// 1) 未修改信念前，基础整数优先级 85 > 60 严格保持单调顺序（未被百分制 compositeScore 淹没）
		const stInitial = nuwaMod.loadState(ws)!;
		const initialOrder = nuwaMod.frontierList(stInitial, 50).map((f) => f.intent.id);
		expect(initialOrder.indexOf(prunedId)).toBeLessThan(initialOrder.indexOf(boostId));

		// 2) 在持久化 belief-graph.json 上设置跃迁提权与剪枝，然后通过全新 loadState(ws) 与 NuwaCoreEngine 验证
		const bg = nuwaMod.loadOrInitBeliefGraph(ws, stInitial);
		bg.nodes[boostId]!.breakthroughBoost = 2.0;
		bg.nodes[boostId]!.posterior = 0.889;
		bg.nodes[prunedId]!.pruned = true;
		nuwaMod.saveBeliefGraph(ws, stInitial, bg);

		const reloadedState = nuwaMod.loadState(ws)!;
		const reloadedOrder = nuwaMod.frontierList(reloadedState, 50).map((f) => f.intent.id);
		expect(reloadedOrder.indexOf(boostId)).toBeLessThan(reloadedOrder.indexOf(prunedId));

		const mcpFrontier = await engine.callTool("nuwa_frontier", { limit: 50 });
		const mcpIds = (mcpFrontier.details?.ids as string[]) ?? [];
		expect(mcpIds.indexOf(boostId)).toBeLessThan(mcpIds.indexOf(prunedId));
	});

	test("P1-4 & P1-5: /nuwa mcp 输出合法 --project 与真实 12 工具；纯 SQLite 删 state.json 后 force=true 重建零崩溃", async () => {
		const ws = makeWorkspace("nuwa-p1-45-");
		const h = setupHarness(ws, "s-p1-45");

		// P1-4: /nuwa mcp 参数与真实 12 工具校验，且用解析出的 CLI 参数真实启动 bin/nuwa-mcp --version 退出码 0
		const mcpView = nuwaMod.executeMcpCommand(ws);
		expect(mcpView.msg).toContain('"--project"');
		expect(mcpView.msg).not.toContain('"--cwd"');
		for (const t of EXPECTED_12_TOOLS) {
			expect(mcpView.msg).toContain(t);
		}
		for (const fake of ["nuwa_seal", "nuwa_inspect", "nuwa_scope", "nuwa_session"]) {
			expect(mcpView.msg).not.toContain(fake);
		}
		const repoMcpBin = resolve(import.meta.dir, "..", "bin", "nuwa-mcp");
		const proc = Bun.spawn([repoMcpBin, "--project", ws, "--version"], { stdout: "pipe", stderr: "pipe" });
		expect(await proc.exited).toBe(0);

		// P1-5: 纯 SQLite 模式下删除 state.json，调用 nuwa_init(force=true) 与 NuwaCoreEngine force=true 均正常备份重建
		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18104", mode: "pentest" });
		await h.call("nuwa_commit", { free_note: true, kind: "note", title: "旧项目残留记录" });
		unlinkSync(nuwaMod.statePath(ws));
		expect(existsSync(nuwaMod.statePath(ws))).toBe(false);
		expect(nuwaMod.hasProjectState(ws)).toBe(true);

		const reinit1 = await h.call("nuwa_init", {
			target: "http://127.0.0.1:18105",
			mode: "pentest",
			root: ws,
			force: true,
		});
		expect(reinit1.isError).toBeFalsy();
		expect(Object.keys(nuwaMod.loadState(ws)!.facts).length).toBe(0);

		unlinkSync(nuwaMod.statePath(ws));
		const mcpEngine = new NuwaCoreEngine({ projectRoot: ws, cwd: ws, sessionId: "s-mcp-force" });
		const reinit2 = await mcpEngine.callTool("nuwa_init", {
			target: "http://127.0.0.1:18106",
			mode: "pentest",
			root: ws,
			force: true,
		});
		expect(reinit2.isError).toBe(false);
		expect(readdirSync(join(ws, ".nuwa")).some((n) => n.startsWith("nuwa.db.bak-"))).toBe(true);
	});

	test("P1-6 & P2: 未经执行账本核验的伪造事实严禁冒充 exec-ledger 结算 outcome=1；真实核验后回写 calibrationSettled", async () => {
		const ws = makeWorkspace("nuwa-p1-6-");
		const h = setupHarness(ws, "s-p1-6");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18107", mode: "pentest" });

		const pRes = await h.call("nuwa_plan", {
			phase: "surface",
			intents: [
				{ title: "无账本伪造端点提交", targetKey: "/fake-ep", expectedKind: "endpoint" },
				{ title: "真实执行账本核验端点提交", targetKey: "/real-ep", expectedKind: "endpoint" },
			],
		});
		const [fakeIntentId, realIntentId] = pRes.details.added as [string, string];

		// 1) 执行账本为空：登记预测后直接提交伪造 command/output -> 严禁伪造 exec-ledger 结算！
		const fakePred = nuwaMod.recordPrediction(ws, {
			intentId: fakeIntentId,
			taskCategory: "recon",
			modelId: "test-model",
			predictedConfidence: 0.8,
			estimatedTokens: 500,
		});
		await h.call("nuwa_claim", { id: fakeIntentId, worker: "fujiang" });
		await h.call("nuwa_commit", {
			id: fakeIntentId,
			kind: "endpoint",
			title: "口头伪造发现 /fake-ep",
			command: "curl -sS http://127.0.0.1:18107/fake-ep",
			output: "HTTP/1.1 200 OK\nhttp_code=200 size_download=128 remote_ip=127.0.0.1 time_total=0.01\n\n{\"ok\":true}",
		});
		const afterFake = nuwaMod.loadCalibrationRecords(ws).find((r) => r.predictionId === fakePred.predictionId)!;
		expect(afterFake.settled).toBe(false);
		expect(nuwaMod.loadState(ws)!.intents[fakeIntentId]?.calibrationSettled).toBeUndefined();

		// 2) 真实写入执行证据账本后提交 -> 允许以机械源 exec-ledger 结算 outcome=1 并同步更新状态字段
		const realPred = nuwaMod.recordPrediction(ws, {
			intentId: realIntentId,
			taskCategory: "recon",
			modelId: "test-model",
			predictedConfidence: 0.85,
			estimatedTokens: 600,
		});
		await h.call("nuwa_claim", { id: realIntentId, worker: "fujiang" });
		const realCmd = "curl -sS http://127.0.0.1:18107/real-ep";
		const realOut =
			"HTTP/1.1 200 OK\nServer: envoy\nhttp_code=200 size_download=256 remote_ip=127.0.0.1 time_total=0.02\n\n{\"service\":\"billing-v2\",\"routes\":[\"/real-ep\"]}";
		nuwaMod.recordToolExecution(ws, { tool: "bash", command: realCmd, output: realOut, agentName: "fujiang" });
		await h.call("nuwa_commit", {
			id: realIntentId,
			kind: "endpoint",
			title: "真实探明 /real-ep",
			command: realCmd,
			output: realOut,
		});

		const afterReal = nuwaMod.loadCalibrationRecords(ws).find((r) => r.predictionId === realPred.predictionId)!;
		expect(afterReal.settled).toBe(true);
		expect(afterReal.outcome).toBe(1);
		expect(afterReal.source).toBe("exec-ledger");

		const stFinal = nuwaMod.loadState(ws)!;
		expect(stFinal.intents[realIntentId]?.calibrationSettled).toBe(true);
		expect(stFinal.runtime.calibrationSettledCount).toBeGreaterThanOrEqual(1);
	});
});

