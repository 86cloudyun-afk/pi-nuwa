import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as graphMod from "../omp/graph";
import * as nuwaMod from "../omp/nuwa";
import { NUWA_CORE_TOOLS } from "../core/protocol";
import { NuwaCoreEngine } from "../core/mcp-server";
import { deriveFromFacts } from "../omp/graph-planner";
import { resolveLineageRoot } from "../omp/lineage";
import { validateVerificationCommit } from "../omp/verifier-gate";
import { openNuwaDb } from "../omp/sqlite-store";

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

describe("v6.0.0 Boost 自我检测全链路缺陷修缮回归验证", () => {
	test("纯 SQLite 模式（无 state.json/journal.jsonl）下 raw 状态/斜杠命令/守护器/WAL 空闲检测全部打通", async () => {
		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		const ws = makeWorkspace("nuwa-boost-sqlite-");
		const h = setupHarness(ws, "s-boost-sqlite");

		await h.call("nuwa_init", {
			target: "http://127.0.0.1:18201",
			mode: "pentest",
			goal: "验证纯 SQLite 全链路只读与守护器兼容",
			root: ws,
		});
		expect(existsSync(nuwaMod.sqliteDbPath(ws))).toBe(true);

		const cmd = "curl -sS http://127.0.0.1:18201/flag";
		const out = "HTTP/1.1 200 OK\nhttp_code=200 size_download=48 remote_ip=127.0.0.1 time_total=0.01\n\nflag{sqlite_full_e2e_ok}";
		nuwaMod.recordToolExecution(ws, { tool: "bash", command: cmd, output: out, agentName: "fujiang" });
		await h.call("nuwa_flag", { value: "flag{sqlite_full_e2e_ok}", command: cmd, output: out });
		await h.call("nuwa_complete", { summary: "纯 SQLite 完成" });

		// 移除 JSON 兼容快照与 JSONL 日志文件，模拟纯 SQLite 单库状态
		if (existsSync(nuwaMod.statePath(ws))) unlinkSync(nuwaMod.statePath(ws));
		if (existsSync(nuwaMod.journalPath(ws))) unlinkSync(nuwaMod.journalPath(ws));
		expect(existsSync(nuwaMod.statePath(ws))).toBe(false);
		expect(existsSync(nuwaMod.journalPath(ws))).toBe(false);

		// 1) nuwa_status(raw=true) 与 /nuwa raw / /nuwa log 在无 state.json 时正常返回
		const rawJsonRes = await h.call("nuwa_status", { raw: true, format: "json", root: ws });
		expect(rawJsonRes.isError).toBeFalsy();
		const parsedRaw = JSON.parse(rawJsonRes.content[0].text);
		expect(parsedRaw.project.status).toBe("completed");
		expect(Object.values(parsedRaw.facts).some((f: any) => f.kind === "flag")).toBe(true);

		const mcpEngine = new NuwaCoreEngine({ projectRoot: ws, cwd: ws, sessionId: "s-boost-mcp" });
		const mcpRawRes = await mcpEngine.callTool("nuwa_status", { raw: true, format: "text", root: ws });
		expect(mcpRawRes.isError).toBe(false);
		expect(mcpRawRes.content[0].text).toContain("completed");

		h.notifications.length = 0;
		await h.runSlash("query raw");
		expect(h.notifications.at(-1)?.level).toBe("info");
		expect(h.notifications.at(-1)?.text).toContain("flag{sqlite_full_e2e_ok}");

		h.notifications.length = 0;
		await h.runSlash("log 5");
		expect(h.notifications.at(-1)?.level).toBe("info");
		expect(h.notifications.at(-1)?.text).toContain('"type":"complete"');
		expect(h.notifications.at(-1)?.text).toContain('"type":"flag"');

		h.notifications.length = 0;
		await h.runSlash("log 20");
		expect(h.notifications.at(-1)?.text).toContain('"type":"init"');

		// 2) bin/nuwa-autonomous 在无 state.json 时从 nuwa.db 识别 status=completed 干净退出码 0
		const fakeBin = makeWorkspace("nuwa-boost-bin-");
		const fakeOmp = join(fakeBin, "omp");
		writeFileSync(fakeOmp, "#!/usr/bin/env bash\necho FAIL_SHOULD_NOT_SPAWN >&2\nexit 99\n", "utf8");
		chmodSync(fakeOmp, 0o755);
		const daemonRes = Bun.spawnSync(
			[
				process.execPath,
				resolve(import.meta.dir, "..", "bin", "nuwa-autonomous"),
				"--root",
				ws,
				"--omp-bin",
				fakeOmp,
				"--max-generations",
				"1",
			],
			{
				stdout: "pipe",
				stderr: "pipe",
				env: { ...process.env, NUWA_STORAGE_BACKEND: "sqlite", NUWA_ALLOW_TMP_WORKSPACE: "1" },
			},
		);
		expect(daemonRes.exitCode).toBe(0);
		expect(daemonRes.stdout.toString("utf8")).toContain("任务已完成 (status=completed)");
		expect(daemonRes.stderr.toString("utf8")).not.toContain("FAIL_SHOULD_NOT_SPAWN");

		// 3) 开启短 idle 看门狗(450ms)，假子进程在 >640ms 内仅持续写 nuwa.db/WAL 不写 state.json/journal.jsonl，随后落盘 completed -> 不得误杀且成功退出 0
		const wsWal = makeWorkspace("nuwa-boost-daemon-wal-");
		const hw = setupHarness(wsWal, "s-boost-wal");
		await hw.call("nuwa_init", { target: "http://127.0.0.1:18209", mode: "pentest", root: wsWal });
		if (existsSync(nuwaMod.statePath(wsWal))) unlinkSync(nuwaMod.statePath(wsWal));
		if (existsSync(nuwaMod.journalPath(wsWal))) unlinkSync(nuwaMod.journalPath(wsWal));

		const walOmp = join(fakeBin, "omp-wal");
		const sqliteModPath = resolve(import.meta.dir, "..", "omp", "sqlite-store.ts");
		writeFileSync(
			walOmp,
			`#!/usr/bin/env bun
import { loadStateFromSqlite, saveStateToSqlite } from ${JSON.stringify(sqliteModPath)};
const cwd = process.cwd();
for (let step = 0; step < 5; step++) {
  if (step > 0) await Bun.sleep(160);
  const st = loadStateFromSqlite(cwd)!;
  st.runtime.turns = (st.runtime.turns ?? 0) + 1;
  if (step === 4) {
    st.project.status = "completed";
    st.runtime.status = "completed";
  }
  saveStateToSqlite(cwd, st);
}
process.exit(0);
`,
			"utf8",
		);
		chmodSync(walOmp, 0o755);

		const walDaemonRes = Bun.spawnSync(
			[
				process.execPath,
				resolve(import.meta.dir, "..", "bin", "nuwa-autonomous"),
				"--root",
				wsWal,
				"--omp-bin",
				walOmp,
				"--max-generations",
				"1",
			],
			{
				stdout: "pipe",
				stderr: "pipe",
				env: {
					...process.env,
					NUWA_STORAGE_BACKEND: "sqlite",
					NUWA_ALLOW_TMP_WORKSPACE: "1",
					NUWA_DAEMON_IDLE_MS: "450",
					NUWA_DAEMON_MAX_ERRORS: "1",
					NUWA_DAEMON_BACKOFF_MS: "10",
				},
			},
		);
		expect(walDaemonRes.exitCode).toBe(0);
		expect(walDaemonRes.stdout.toString("utf8")).toContain("任务已完成 (status=completed)");
		expect(walDaemonRes.stderr.toString("utf8")).not.toContain("触发空闲看门狗");
	}, 15_000);

	test("nuwa.db 与过期 state.json 并存且无环境变量时优先只读 nuwa.db 且零写盘", async () => {
		const ws = makeWorkspace("nuwa-boost-coexist-");
		const h = setupHarness(ws, "s-boost-coexist");

		// 1) 先在 json 模式落盘旧 state.json 并保留快照
		setEnvTemp("NUWA_STORAGE_BACKEND", "json");
		await h.call("nuwa_init", {
			target: "http://127.0.0.1:18202",
			mode: "pentest",
			goal: "OLD_STALE_JSON_GOAL",
			root: ws,
		});
		expect(existsSync(nuwaMod.statePath(ws))).toBe(true);
		const staleJsonSnapshot = readFileSync(nuwaMod.statePath(ws), "utf8");

		// 2) 切到 sqlite 模式推进状态并写入新事实，再还原陈旧 state.json 制造共存冲突
		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		await h.call("nuwa_claim", { id: "i001", worker: "fujiang" });
		const freshCmd = "curl -sS http://127.0.0.1:18202/api/v2/health";
		const freshOut =
			"HTTP/1.1 200 OK\nhttp_code=200 size_download=64 remote_ip=127.0.0.1 time_total=0.01\n\n{\"tag\":\"FRESH_SQLITE_ONLY_MARKER\"}";
		nuwaMod.recordToolExecution(ws, { tool: "bash", command: freshCmd, output: freshOut, agentName: "fujiang" });
		await h.call("nuwa_commit", {
			id: "i001",
			kind: "endpoint",
			title: "FRESH_SQLITE_ENDPOINT",
			detail: "仅存在于 SQLite 的最新接口",
			command: freshCmd,
			output: freshOut,
		});
		writeFileSync(nuwaMod.statePath(ws), staleJsonSnapshot, "utf8");

		// 执行一次 checkpoint 清理 WAL 确保干净单文件只读测试
		const ckDb = openNuwaDb(ws);
		ckDb.exec("PRAGMA wal_checkpoint(TRUNCATE);");
		ckDb.close();

		// 3) 删除 NUWA_STORAGE_BACKEND 环境变量后验证所有只读入口均识别 nuwa.db 且严格零写盘
		setEnvTemp("NUWA_STORAGE_BACKEND", undefined);
		const snapBefore = snapshotTreeMtimes(join(ws, ".nuwa"));
		await Bun.sleep(15);

		const diag = graphMod.inspectGraph(ws, { status: "done", limit: 20 });
		expect(diag.ok).toBe(true);
		expect(diag.summary.totalFacts).toBe(1);
		expect(diag.relatedFacts.some((f) => f.title.includes("FRESH_SQLITE_ENDPOINT"))).toBe(true);

		const statusRes = await h.call("nuwa_status", { root: ws });
		expect(statusRes.content[0].text).toContain("OLD_STALE_JSON_GOAL");
		const rawJsonRes = await h.call("nuwa_status", { raw: true, format: "json", root: ws });
		expect(rawJsonRes.content[0].text).toContain("FRESH_SQLITE_ENDPOINT");

		const doctorText = graphMod.buildDoctorSummary(ws);
		expect(doctorText).toContain("mode=sqlite");

		const snapAfter = snapshotTreeMtimes(join(ws, ".nuwa"));
		expect(snapAfter).toEqual(snapBefore);
	});

	test("nuwa_commit 在 f1000 及去重命中时精确绑定 evidenceRef；coding/ops 缺省 mode 的 resume 兼容", async () => {
		// 1) f1000 词法排序陷阱回归 + 去重命中回归
		const ws = makeWorkspace("nuwa-boost-f1000-");
		const h = setupHarness(ws, "s-boost-f1000");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18203", mode: "pentest", root: ws });

		nuwaMod.withLock(ws, () => {
			const s = nuwaMod.loadState(ws)!;
			s.seq.fact = 998;
			nuwaMod.saveState(ws, s);
		});

		const cmd999 = "curl -sS http://127.0.0.1:18203/a";
		const out999 = "HTTP/1.1 200 OK\nhttp_code=200 size_download=32 remote_ip=127.0.0.1 time_total=0.01\n\n{\"ep\":\"a\"}";
		nuwaMod.recordToolExecution(ws, { tool: "bash", command: cmd999, output: out999, agentName: "fujiang" });
		const r999 = await h.call("nuwa_commit", {
			free_note: true,
			kind: "endpoint",
			title: "端点 999",
			detail: "第一个端点",
			command: cmd999,
			output: out999,
			root: ws,
		});
		expect(r999.isError).toBeFalsy();

		const cmd1000 = "curl -sS http://127.0.0.1:18203/b";
		const out1000 = "HTTP/1.1 200 OK\nhttp_code=200 size_download=40 remote_ip=127.0.0.1 time_total=0.01\n\n{\"ep\":\"b\"}";
		nuwaMod.recordToolExecution(ws, { tool: "bash", command: cmd1000, output: out1000, agentName: "fujiang" });
		const r1000 = await h.call("nuwa_commit", {
			free_note: true,
			kind: "endpoint",
			title: "端点 1000",
			detail: "第 1000 个端点",
			command: cmd1000,
			output: out1000,
			save_evidence_log: true,
			raw_response: "RAW_LOG_FOR_F1000",
			root: ws,
		});
		expect(r1000.details?.evidenceRef).toBe(".nuwa/evidence/f1000.log");
		const stMid = nuwaMod.loadState(ws)!;
		expect(stMid.facts.f1000?.evidenceRef).toBe(".nuwa/evidence/f1000.log");
		expect(stMid.facts.f999?.evidenceRef).toBeUndefined();

		// 重复提交同 title ("端点 999") 命中去重，evidenceRef 必须精确落到 f999 而非误覆写 f1000
		const r999Dup = await h.call("nuwa_commit", {
			free_note: true,
			kind: "endpoint",
			title: "端点 999",
			detail: "补录原始回显",
			command: cmd999,
			output: out999,
			save_evidence_log: true,
			raw_response: "RAW_LOG_FOR_F999",
			root: ws,
		});
		expect(r999Dup.details?.evidenceRef).toBe(".nuwa/evidence/f999.log");
		const stAfterDup = nuwaMod.loadState(ws)!;
		expect(stAfterDup.facts.f999?.evidenceRef).toBe(".nuwa/evidence/f999.log");
		expect(stAfterDup.facts.f1000?.evidenceRef).toBe(".nuwa/evidence/f1000.log");

		// 2) coding / ops 本地项目在未显式传 mode 时 resume=true + target 不得被默认 ctf 拒绝
		const codingWs = makeWorkspace("nuwa-boost-coding-");
		const hc = setupHarness(codingWs, "s-boost-coding");
		await hc.call("nuwa_init", { target: codingWs, mode: "coding", goal: "工程修复", root: codingWs });
		const resumeCoding1 = await hc.call("nuwa_init", { root: codingWs, resume: true, target: codingWs });
		expect(resumeCoding1.isError).toBeFalsy();
		const resumeCoding2 = await hc.call("nuwa_init", { target: codingWs, resume: true });
		expect(resumeCoding2.isError).toBeFalsy();

		const opsWs = makeWorkspace("nuwa-boost-ops-");
		const mcpOps = new NuwaCoreEngine({ projectRoot: opsWs, cwd: opsWs, sessionId: "s-boost-ops" });
		const initOps = await mcpOps.callTool("nuwa_init", { target: "billing-svc", mode: "ops", root: opsWs });
		expect(initOps.isError).toBe(false);
		const resumeOps = await mcpOps.callTool("nuwa_init", { root: opsWs, resume: true, target: "billing-svc" });
		expect(resumeOps.isError).toBe(false);
	});

	test("SubagentWatchdog 生命周期闭环（完成释放槽位/缺省 spawnId 回退/关闭清理）与 requireVerifierWorker 空值拦截", async () => {
		const ws = makeWorkspace("nuwa-boost-wd-");
		const h = setupHarness(ws, "s-boost-wd");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18204", mode: "pentest", root: ws });

		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const onToolCall = h.hooks.get("tool_call")![0]!;
		const onEnd = h.hooks.get("tool_execution_end")![0]!;
		const onShutdown = h.hooks.get("session_shutdown")![0]!;

		// 连续派发 5 轮（超过默认 maxConcurrency=4），包含无 spawnId 回退与显式 spawnId，每轮完成后槽位立即归还
		for (let i = 1; i <= 5; i++) {
			const withExplicit = i <= 2;
			const spawnEvt: Record<string, unknown> = {
				...(withExplicit ? { spawnId: `sp-loop-${i}` } : {}),
				agent: "fujiang",
				task: `[女娲派单 i001] 探测路径 /v${i}`,
			};
			const spawnOut = onSpawn(spawnEvt, h.ctx) as { spawnId: string; task: string };
			const subCtx: any = {
				...h.ctx,
				agent: { kind: "sub", id: withExplicit ? `sp-loop-${i}` : `host-sub-${i}`, name: "fujiang", parentId: "main-0" },
			};
			onToolCall({ toolName: "bash", input: { command: `curl -sS http://127.0.0.1:18204/v${i}` } }, subCtx);
			onEnd(
				{
					toolName: "bash",
					input: { command: `curl -sS http://127.0.0.1:18204/v${i}` },
					result: { stdout: "HTTP/1.1 200 OK", stderr: "" },
				},
				subCtx,
			);
			const wdMid = new nuwaMod.SubagentWatchdog(ws);
			expect(wdMid.activeCount()).toBe(1);
			expect(wdMid.getTask(spawnOut.spawnId)?.lastOutputAt).toBeGreaterThanOrEqual(
				wdMid.getTask(spawnOut.spawnId)!.startedAt,
			);

			onEnd(
				{
					toolName: "task",
					input: { agent: "fujiang", task: spawnEvt.task },
					details: withExplicit ? { spawnId: `sp-loop-${i}` } : {},
					result: { stdout: "subagent done" },
				},
				h.ctx,
			);

			const wdAfter = new nuwaMod.SubagentWatchdog(ws);
			expect(wdAfter.activeCount()).toBe(0);
			expect(wdAfter.availableSlots()).toBe(4);
			expect(wdAfter.getTask(spawnOut.spawnId)?.status).toBe("completed");
		}

		// 验证 session_shutdown 回收尚未结案的 running 任务
		const orphanRes = onSpawn({ spawnId: "sp-orphan", agent: "fujiang", task: "未结束的游离任务" }, h.ctx) as {
			spawnId: string;
		};
		expect(new nuwaMod.SubagentWatchdog(ws).activeCount()).toBe(1);
		onShutdown({}, h.ctx);
		const wdShutdown = new nuwaMod.SubagentWatchdog(ws);
		expect(wdShutdown.activeCount()).toBe(0);
		expect(wdShutdown.getTask(orphanRes.spawnId)?.status).toBe("cancelled");

		// 验证 requireVerifierWorker=true 时空 worker 也必须拦截
		const emptyWorkerGate = validateVerificationCommit({
			intentKey: "verify-vuln:f010",
			kind: "vuln",
			worker: "",
			hasFreshExecution: true,
			requireVerifierWorker: true,
		});
		expect(emptyWorkerGate.ok).toBe(false);
	});

	test("真实 Zod default 解析语义下 nuwa_init 不将已有 coding/ops 项目的缺省 mode 覆盖为 ctf", async () => {
		// 校验 core/protocol.ts 的 nuwa_init.mode 不再携带 default: "ctf"
		const initProto = NUWA_CORE_TOOLS.find((t) => t.name === "nuwa_init");
		expect((initProto?.inputSchema.properties.mode as Record<string, unknown> | undefined)?.default).toBeUndefined();

		// 构造会真实执行 .default() 与 .optional() 的 Zod 解析器注册 omp/nuwa.ts
		const ws = makeWorkspace("nuwa-zod-real-mode-");
		const agentHome = makeWorkspace("nuwa-zod-real-home-");
		setEnvTemp("PI_AGENT_HOME", agentHome);

		type SchemaNode = { parse: (val: unknown) => unknown; defaultVal?: unknown; hasDefault?: boolean };
		const makeType = (baseParse: (v: unknown) => unknown): any => {
			const node: SchemaNode & Record<string, any> = {
				parse: (v: unknown) => (v === undefined && node.hasDefault ? node.defaultVal : baseParse(v)),
				optional: () => makeType((v) => (v === undefined ? undefined : node.parse(v))),
				default: (d: unknown) => {
					const next = makeType((v) => baseParse(v));
					next.hasDefault = true;
					next.defaultVal = d;
					return next;
				},
				describe: () => node,
			};
			return node;
		};
		const realZod = {
			string: () => makeType((v) => v),
			number: () => makeType((v) => v),
			boolean: () => makeType((v) => v),
			any: () => makeType((v) => v),
			unknown: () => makeType((v) => v),
			record: () => makeType((v) => v),
			union: () => makeType((v) => v),
			enum: () => makeType((v) => v),
			array: () => makeType((v) => v),
			object: (shape: Record<string, any>) =>
				makeType((raw: unknown) => {
					const obj = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
					const out: Record<string, unknown> = {};
					for (const [k, sc] of Object.entries(shape)) {
						const parsed = sc.parse(obj[k]);
						if (parsed !== undefined) out[k] = parsed;
					}
					return out;
				}),
		};

		const tools = new Map<string, any>();
		nuwaMod.default({
			zod: realZod as any,
			registerTool: (t: any) => tools.set(t.name, t),
			registerCommand: () => {},
			on: () => {},
		} as any);
		const ctx: any = {
			cwd: ws,
			agent: { kind: "main", id: "main-zod" },
			sessionManager: { getSessionId: () => "sess-zod-real" },
			ui: { setStatus() {}, setWidget() {}, notify() {}, theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t } },
		};
		const callWithRealZod = async (name: string, rawParams: Record<string, unknown>) => {
			const tool = tools.get(name)!;
			const parsed = tool.parameters.parse(rawParams);
			return tool.execute("z-1", parsed, undefined, undefined, ctx);
		};

		const initRes = await callWithRealZod("nuwa_init", { target: ws, mode: "coding", goal: "真实 Zod 默认值测试", root: ws });
		expect(initRes.isError).toBeFalsy();
		const resumeRes = await callWithRealZod("nuwa_init", { target: ws, resume: true });
		expect(resumeRes.isError).toBeFalsy();
		expect(nuwaMod.loadState(ws)?.project.mode).toBe("coding");
	});

	test("多进程 withLock 遇到死亡 PID 遗留锁时通过独占回收锁协调，绝不误删先恢复者刚建的新活锁", async () => {
		const ws = makeWorkspace("nuwa-lock-reclaim-race-");
		mkdirSync(join(ws, ".nuwa"), { recursive: true });
		const counterFile = join(ws, ".nuwa", "counter.json");
		writeFileSync(counterFile, JSON.stringify({ count: 0, concurrentViolations: 0 }), "utf8");

		// 写入一个已死亡 PID 的陈旧 state.lock，诱发 4 个进程同时触发死锁恢复竞争
		const lockFile = join(ws, ".nuwa", "state.lock");
		writeFileSync(
			lockFile,
			JSON.stringify({ pid: 99999991, ts: Date.now() - 60_000, start: "1", nonce: "dead-nonce-0" }),
			"utf8",
		);

		const workerCode = `
			import { readFileSync, writeFileSync } from "node:fs";
			import { withLock } from ${JSON.stringify(resolve(import.meta.dir, "../omp/storage.ts"))};
			const ws = process.env.NUWA_TEST_WS!;
			const counterFile = process.env.NUWA_TEST_CNT!;
			withLock(ws, () => {
				const before = JSON.parse(readFileSync(counterFile, "utf8"));
				Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 80);
				const after = JSON.parse(readFileSync(counterFile, "utf8"));
				if (after.count !== before.count) {
					after.concurrentViolations += 1;
				}
				after.count += 1;
				writeFileSync(counterFile, JSON.stringify(after), "utf8");
			});
		`;
		const procs = Array.from({ length: 4 }, () =>
			Bun.spawn(["bun", "-e", workerCode], {
				env: { ...process.env, NUWA_TEST_WS: ws, NUWA_TEST_CNT: counterFile },
				stdout: "pipe",
				stderr: "pipe",
			}),
		);
		const codes = await Promise.all(procs.map((p) => p.exited));
		expect(codes).toEqual([0, 0, 0, 0]);
		const finalCounter = JSON.parse(readFileSync(counterFile, "utf8")) as {
			count: number;
			concurrentViolations: number;
		};
		expect(finalCounter.concurrentViolations).toBe(0);
		expect(finalCounter.count).toBe(4);
	});

	test("executeCommitWithGates 重复提交已 confirmed/rejected 事实时不降级覆盖状态，且 deriveFromFacts 真实同步 assets", async () => {
		const ws = makeWorkspace("nuwa-dup-confirmed-");
		const h = setupHarness(ws, "s-dup-confirmed");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18290", mode: "pentest", root: ws });

		const st0 = nuwaMod.loadState(ws)!;
		const expRes = deriveFromFacts(st0);
		// 为当前状态追加一个含内网 IP 与 SAN 的服务事实，验证 deriveFromFacts 内部 syncAssetsFromFacts 正常同步不抛 ReferenceError
		expect(Array.isArray(expRes.added)).toBe(true);
		st0.facts.f_san = {
			id: "f_san",
			kind: "service",
			title: "发现后端管理节点与 SAN",
			detail: "内网跳板 10.20.30.40 且存在 SAN: admin.internal.example",
			createdAt: new Date().toISOString(),
			meta: { san: ["admin.internal.example"], ports: [8080] },
		};
		deriveFromFacts(st0);
		expect(Object.keys(st0.assets ?? {}).length).toBeGreaterThanOrEqual(2);

		// 构造一个与 commitIntent key 一致的已 confirmed vuln 事实，再次以候选级提交命中 duplicate=true，严禁降级为 candidate/verified=false
		const st1 = nuwaMod.loadState(ws)!;
		const intentId = Object.keys(st1.intents)[0]!;
		const intent = st1.intents[intentId]!;
		const title = "确认 SQL 注入漏洞";
		const factKey = nuwaMod.sha(`${st1.project.id}|${intent.id}|${intent.attempts}|vuln|${title}`);
		st1.facts.f_confirmed = {
			id: "f_confirmed",
			kind: "vuln",
			title,
			detail: "confirmed sqli",
			key: factKey,
			createdAt: new Date().toISOString(),
			verified: true,
			verifyStage: "confirmed",
			evidenceSeq: 12,
		};
		nuwaMod.saveState(ws, st1);

		const dupRes = graphMod.executeCommitWithGates(
			ws,
			{
				id: intentId,
				kind: "vuln",
				title,
				detail: "repeat finding",
				command: "curl -sS http://127.0.0.1:18290/q?id=1",
				output: "SQL syntax error near id=1",
			},
			false,
		);
		const after = nuwaMod.loadState(ws)!;
		expect(dupRes.verifyStageOut).toBe("confirmed");
		expect(after.facts.f_confirmed?.verifyStage).toBe("confirmed");
		expect(after.facts.f_confirmed?.verified).toBe(true);
	});

	test("SubagentWatchdog 并发子代理严格匹配任务正文不误释放前缀重合任务，且 null input 容错 + 纯 SQLite 血缘识别", async () => {
		const ws = makeWorkspace("nuwa-wd-prefix-race-");
		const prevBackend = process.env.NUWA_STORAGE_BACKEND;
		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		const h = setupHarness(ws, "s-wd-prefix");
		await h.call("nuwa_init", { target: "http://127.0.0.1:18295", mode: "pentest", root: ws });

		// 移除兼容导出的 state.json 构造纯 SQLite 无 state.json 场景，验证 resolveLineageRoot 仍可准确探测项目根目录
		const compatJson = join(ws, ".nuwa", "state.json");
		if (existsSync(compatJson)) unlinkSync(compatJson);
		expect(existsSync(compatJson)).toBe(false);
		expect(resolveLineageRoot(h.ctx, process.env.PI_AGENT_HOME)).toBe(resolve(ws));

		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const onEnd = h.hooks.get("tool_execution_end")![0]!;

		const tShort = "probe /api endpoint status";
		const tLong = "probe /api/v2/admin sensitive endpoint";
		const sp1 = onSpawn({ agent: "fujiang", task: tShort }, h.ctx) as { spawnId: string };
		const sp2 = onSpawn({ agent: "fujiang", task: tLong }, h.ctx) as { spawnId: string };
		expect(new nuwaMod.SubagentWatchdog(ws).activeCount()).toBe(2);

		// 第 1 个任务以 rawTask 完成（不传 spawnId），绝不能因 sp2.injectedTask 包含子串而提前释放 sp2
		onEnd(
			{ toolName: "task", input: { agent: "fujiang", task: tShort }, result: { stdout: "done 1" } },
			h.ctx,
		);
		const wdMid = new nuwaMod.SubagentWatchdog(ws);
		expect(wdMid.activeCount()).toBe(1);
		expect(wdMid.getTask(sp1.spawnId)?.status).toBe("completed");
		expect(wdMid.getTask(sp2.spawnId)?.status).toBe("running");

		// 第 2 个任务完成时宿主传入 input: null（仅留单个运行任务兜底），不得崩溃且正确释放最后一个槽位
		onEnd({ toolName: "task", input: null, result: { stdout: "done 2" } }, h.ctx);
		const wdDone = new nuwaMod.SubagentWatchdog(ws);
		expect(wdDone.activeCount()).toBe(0);
		expect(wdDone.getTask(sp2.spawnId)?.status).toBe("completed");

		if (prevBackend === undefined) delete process.env.NUWA_STORAGE_BACKEND;
	});
});

