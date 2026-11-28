/**
 * 女娲 v7.0.0 全链路端到端总装集成测试（Wave 2 Single-Core & Full-Stack Wiring）。
 *
 * 覆盖核心不变量与端到端闭环：
 * 1. 单核统一路由：`omp/nuwa.ts` (< 1,000 行) 与 `core/mcp-server.ts` (`NuwaCoreEngine`) 100% 委托 `NuwaUnifiedEngine`，
 *    12 个 `nuwa_*` 工具名称、28 个 `/nuwa` 子命令补全及 v4–v7 全量符号 `re-export` 零丢失；
 * 2. 默认存储后端 SQLite WAL 转正与双核心不变量：
 *    - 未设 `NUWA_STORAGE_BACKEND` 时默认启用 `"sqlite"`，发生写入时同步维护 `.nuwa/state.json` 兼容快照；
 *    - 遗留仅有 `.nuwa/state.json`（无 `nuwa.db`）的目录执行任何只读工具/斜杠命令/前沿排序时，严格零磁盘写入（绝不创建 `nuwa.db` / `-wal` / `-shm`）；
 * 3. KB 2.0 混合语义检索与经验治理：`buildKb` / `ensureBundledKb` 自动摄入 `seed-v7-pack.json`（`kb_items >= 520`），
 *    `nuwa_kb` 默认启用 `hybridKbSearch` 中英同义命中，`distillProjectExperience` 联动 `governDistilledExperience` 机械对账晋升/冻结；
 * 4. 5+1 专精特种小队路由：6 个 `agents/*.md` 就位，`checkTaskPolicy` / `dispatch-bridge` 放行全部 6 角色，`frontierList` 与 `/nuwa squad` 给出联合校准路由推荐；
 * 5. 原生 CDP 桥接 + 多跳攻击链 + 信念图回灌闭环：事实提交自动派生 `chain:verify:*` 并触发 `breakthrough_signal`，
 *    多跳验证成功产出 `candidate` 复合漏洞，中间受阻 `brokenAtStep` 回灌衰减信念图；`/nuwa cdp`、`/nuwa chains`、`/nuwa squad` 零写盘且凭据零明文泄露；
 * 6. `install.sh` 隔离沙盒部署全链路：一键安装全套模块、6 个小队模板、`nuwa-mcp`、`kb.db >= 520` 与 `doctor` 验收通过。
 */
import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdtempSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as nuwaMod from "../omp/nuwa";
import { NuwaCoreEngine, handleMcpMessage } from "../core/mcp-server";
import { buildKb } from "../kb/build-kb";

const REPO_ROOT = resolve(import.meta.dir, "..");
const tempDirs: string[] = [];

function makeSandbox(prefix = "nuwa-v7-e2e-"): { root: string; agentHome: string; kbDb: string } {
	const base = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(base);
	const root = join(base, "proj");
	const agentHome = join(base, "agent-home");
	mkdirSync(root, { recursive: true });
	mkdirSync(agentHome, { recursive: true });
	return { root, agentHome, kbDb: join(agentHome, "nuwa-kb", "kb.db") };
}

function createOmpHarness(cwd: string, sessionId = "v7-e2e-session") {
	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	let slashCommand: any = null;
	const notifications: Array<{ msg: string; level: string }> = [];

	const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
	const z = new Proxy({}, { get: () => () => chain() });

	nuwaMod.default({
		zod: z,
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (name: string, cmd: any) => {
			if (name === "nuwa") slashCommand = cmd;
		},
		on: (ev: string, fn: any) => {
			const list = hooks.get(ev) ?? [];
			list.push(fn);
			hooks.set(ev, list);
		},
		sendUserMessage: () => {},
		sendMessage: () => {},
	} as any);

	const ctx: any = {
		cwd,
		agent: { kind: "main", id: "main-0" },
		sessionManager: { getSessionId: () => sessionId },
		ui: {
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
			setStatus: () => {},
			setWidget: () => {},
			setTitle: () => {},
			notify: (msg: string, level = "info") => notifications.push({ msg, level }),
		},
	};

	return { tools, hooks, slashCommand, ctx, notifications };
}

afterEach(() => {
	delete process.env.NUWA_STORAGE_BACKEND;
	delete process.env.NUWA_KB_DB;
	delete process.env.PI_AGENT_HOME;
	delete process.env.NUWA_MODEL_FAST;
	delete process.env.NUWA_MODEL_DEEP;
	delete process.env.NUWA_MODEL_VERIFY;
	while (tempDirs.length > 0) {
		const d = tempDirs.pop()!;
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

describe("v7.0.0 单核收敛、模块瘦身与向后兼容契约", () => {
	test("omp/nuwa.ts < 1000 行、omp/graph.ts < 2500 行、12 工具与 v7 全量符号完整重导出", () => {
		const nuwaLines = readFileSync(join(REPO_ROOT, "omp/nuwa.ts"), "utf8").trimEnd().split("\n").length;
		const graphLines = readFileSync(join(REPO_ROOT, "omp/graph.ts"), "utf8").trimEnd().split("\n").length;
		expect(nuwaLines).toBeLessThan(1000);
		expect(graphLines).toBeLessThan(2500);

		expect(nuwaMod.VERSION).toBe("8.0.0");
		expect(nuwaMod.NUWA_VERSION).toBe("8.0.0");

		// 验证 v7 核心导出符号全部挂载在 omp/nuwa.ts
		expect(typeof nuwaMod.NuwaUnifiedEngine).toBe("function");
		expect(typeof nuwaMod.DispatchBridgeStore).toBe("function");
		expect(typeof nuwaMod.resolveChromeExecutable).toBe("function");
		expect(typeof nuwaMod.captureCdpSessionTraffic).toBe("function");
		expect(typeof nuwaMod.runCdpSignedAuthDiff).toBe("function");
		expect(typeof nuwaMod.synthesizeAttackChains).toBe("function");
		expect(typeof nuwaMod.executeAttackChainVerification).toBe("function");
		expect(typeof nuwaMod.recommendSpecialistAndModel).toBe("function");
		expect(typeof nuwaMod.ingestV7SeedPack).toBe("function");
		expect(typeof nuwaMod.hybridKbSearch).toBe("function");
		expect(typeof nuwaMod.governDistilledExperience).toBe("function");
		expect(typeof nuwaMod.executeCdpCommand).toBe("function");
		expect(typeof nuwaMod.executeChainsCommand).toBe("function");
		expect(typeof nuwaMod.executeSquadCommand).toBe("function");

		const sb = makeSandbox();
		const h = createOmpHarness(sb.root);
		expect(h.tools.size).toBe(12);
		const completions = h.slashCommand.getArgumentCompletions("").map((c: any) => c.value);
		expect(completions).toContain("cdp");
		expect(completions).toContain("chains");
		expect(completions).toContain("squad");

		// NuwaCoreEngine 继承自单一权威内核 NuwaUnifiedEngine
		const mcpEngine = new NuwaCoreEngine({ cwd: sb.root, agentHome: sb.agentHome });
		expect(mcpEngine).toBeInstanceOf(nuwaMod.NuwaUnifiedEngine);
	});

	test("omp 扩展工具与 MCP JSON-RPC 共享同一单核状态与终态防复活守卫", async () => {
		const sb = makeSandbox();
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;

		const h = createOmpHarness(sb.root, "unify-sid");
		const initRes = await h.tools.get("nuwa_init").execute(
			"1",
			{ target: "http://127.0.0.1:18899", mode: "pentest", root: sb.root },
			undefined,
			undefined,
			h.ctx,
		);
		expect(initRes.isError).toBe(false);
		expect(initRes.content[0].text).toContain("女娲已上膛");

		// 通过 MCP 协议调用 nuwa_complete(seal=true) 封盘，验证两边完全同步且 omp 侧不可复活
		const mcpEngine = new NuwaCoreEngine({ projectRoot: sb.root, agentHome: sb.agentHome, sessionId: "unify-sid" });
		const sealRpc = await handleMcpMessage(
			{
				jsonrpc: "2.0",
				id: 10,
				method: "tools/call",
				params: {
					name: "nuwa_complete",
					arguments: {
						root: sb.root,
						seal: true,
						reason: "全加固端点已逐项排除无漏洞",
						excluded_surface: ["/api/health", "/api/public"],
					},
				},
			},
			mcpEngine,
		);
		expect(sealRpc && !Array.isArray(sealRpc) && "result" in sealRpc).toBe(true);

		const resumeAttempt = await h.tools.get("nuwa_init").execute(
			"2",
			{ resume: true, root: sb.root },
			undefined,
			undefined,
			h.ctx,
		);
		expect(resumeAttempt.details.sealed).toBe(true);
		expect(nuwaMod.loadStateZeroWrite(sb.root)?.project.status).toBe("sealed_negative");
	});
});

describe("v7.0.0 SQLite WAL 默认转正与遗留 JSON 只读零写盘守卫", () => {
	test("未配置 NUWA_STORAGE_BACKEND 时默认写入 SQLite WAL 并同步维护 state.json 兼容快照", async () => {
		const sb = makeSandbox();
		delete process.env.NUWA_STORAGE_BACKEND;
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;

		expect(nuwaMod.resolveStorageBackend(sb.root)).toBe("sqlite");

		const engine = new nuwaMod.NuwaUnifiedEngine({ cwd: sb.root, agentHome: sb.agentHome });
		const r1 = await engine.callTool("nuwa_init", {
			target: "http://127.0.0.1:19001",
			mode: "ctf",
			root: sb.root,
		});
		expect(r1.isError).toBe(false);
		expect(existsSync(nuwaMod.sqliteDbPath(sb.root))).toBe(true);
		expect(existsSync(nuwaMod.statePath(sb.root))).toBe(true);

		const cmdProbe = 'curl -sS -w "\\n__PROBE__|%{http_code}|%{size_download}|%{time_total}|%{remote_ip}|%{content_type}" http://127.0.0.1:19001/api/internal/export';
		const outProbe = '{"error":"ticket_required"}\n__PROBE__|403|27|0.008|127.0.0.1|application/json';
		nuwaMod.recordToolExecution(sb.root, {
			tool: "bash",
			command: cmdProbe,
			output: outProbe,
			exitCode: 0,
		});
		const commitRes = await engine.callTool("nuwa_commit", {
			free_note: true,
			strict_realism: false,
			kind: "endpoint",
			title: "发现内部订单导出路由 /api/internal/export",
			detail: "SourceMap 暴露管理路由 /api/internal/export",
			command: cmdProbe,
			output: outProbe,
			root: sb.root,
		});
		expect(commitRes.isError).toBe(false);

		const fromSqlite = nuwaMod.loadStateFromSqlite(sb.root)!;
		const fromJson = nuwaMod.loadStateJsonOnly(sb.root)!;
		expect(Object.keys(fromSqlite.facts).length).toBeGreaterThanOrEqual(1);
		expect(Object.keys(fromSqlite.facts).length).toBe(Object.keys(fromJson.facts).length);
		expect(Object.values(fromJson.facts).some((f) => f.title.includes("/api/internal/export"))).toBe(true);
	});

	test("遗留仅有 .nuwa/state.json（无 nuwa.db）的目录执行全部只读操作时严格零磁盘写入", async () => {
		const sb = makeSandbox();
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;
		nuwaMod.ensureBundledKb(sb.kbDb, { agentHome: sb.agentHome });

		// 先用显式 json 模式创建纯遗留 state.json 项目
		process.env.NUWA_STORAGE_BACKEND = "json";
		const cfg = nuwaMod.readCfg();
		const legacyState = nuwaMod.newState("http://127.0.0.1:19002", "遗留只读零写入测试", "pentest", cfg, "legacy-sid");
		nuwaMod.seedPhase(legacyState, "recon");
		nuwaMod.upsertSessionRole(sb.root, {
			role: "userA",
			headers: { Authorization: "Bearer super-secret-jwt-token-v7-999" },
		});
		nuwaMod.saveStateJsonOnly(sb.root, legacyState);
		expect(existsSync(nuwaMod.sqliteDbPath(sb.root))).toBe(false);

		// 切回默认（未设 NUWA_STORAGE_BACKEND -> 默认 sqlite）
		delete process.env.NUWA_STORAGE_BACKEND;
		expect(nuwaMod.resolveStorageBackend(sb.root)).toBe("sqlite");

		const nuwaDir = join(sb.root, ".nuwa");
		const beforeFiles = readdirSync(nuwaDir).sort();
		const stateMtimeBefore = statSync(nuwaMod.statePath(sb.root)).mtimeMs;

		const engine = new nuwaMod.NuwaUnifiedEngine({
			projectRoot: sb.root,
			cwd: sb.root,
			agentHome: sb.agentHome,
			sessionId: "legacy-sid",
		});

		// 连续执行全部只读工具与斜杠视图命令
		const stTool = await engine.callTool("nuwa_status", { root: sb.root });
		expect(stTool.isError).toBe(false);
		const frTool = await engine.callTool("nuwa_frontier", { root: sb.root });
		expect(frTool.isError).toBe(false);

		for (const cmd of [
			"status",
			"board",
			"belief",
			"calibrate",
			"traffic",
			"hybrid",
			"mcp",
			"cdp",
			"chains",
			"squad",
			"inspect i001",
			"query",
			"why",
			"log",
			"doctor",
		]) {
			const res = await engine.executeSlashCommand(cmd);
			expect(res.level).toBe("info");
			expect(res.message).not.toContain("super-secret-jwt-token-v7-999");
		}

		const afterFiles = readdirSync(nuwaDir).sort();
		expect(existsSync(nuwaMod.sqliteDbPath(sb.root))).toBe(false);
		expect(existsSync(`${nuwaMod.sqliteDbPath(sb.root)}-wal`)).toBe(false);
		expect(existsSync(`${nuwaMod.sqliteDbPath(sb.root)}-shm`)).toBe(false);
		expect(afterFiles).toEqual(beforeFiles);
		expect(statSync(nuwaMod.statePath(sb.root)).mtimeMs).toBe(stateMtimeBefore);
	});
});

describe("v7.0.0 KB 2.0 混合语义治理、5+1 专精小队与多跳攻击链端到端闭环", () => {
	test("buildKb 自动摄入 seed-v7-pack (>=520条)、nuwa_kb 混合语义命中且蒸馏经验由机械校准自动治理", async () => {
		const sb = makeSandbox();
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;

		const stats = buildKb({ outPath: sb.kbDb });
		expect(stats.kbItems).toBeGreaterThanOrEqual(520);

		const engine = new nuwaMod.NuwaUnifiedEngine({ cwd: sb.root, agentHome: sb.agentHome });
		// 中文安全同义词混合检索（"水平越权" -> BOLA/IDOR 概念簇命中）
		const kbHit = await engine.callTool("nuwa_kb", { query: "水平越权 对象级鉴权绕过", kind: "auto", limit: 5 });
		expect(kbHit.isError).toBe(false);
		expect(kbHit.content[0].text).not.toContain("未命中");

		// 蒸馏经验入库 + 连续 5 次机械结算零产出 -> 自动标记 quarantined 并被默认混合检索过滤
		nuwaMod.upsertDistilledExperienceCard(sb.kbDb, {
			id: "exp:spring:noisy-actuator-fp",
			tech: "spring",
			intentKey: "noisy-actuator-fp",
			phase: "vuln",
			title: "Spring 特定历史误报经验卡",
			summary: "特定旧模式在加固网关下连续无产出",
			payload_or_check: "GET /actuator/noisy-legacy-endpoint",
		});

		const mechRecords: nuwaMod.CalibrationRecord[] = Array.from({ length: 5 }, (_, idx) => ({
			predictionId: `pred-gov-${idx}`,
			intentId: "noisy-actuator-fp",
			taskCategory: "exploit",
			modelId: "gemini-4-neon-xhigh",
			predictedConfidence: 0.85,
			estimatedTokens: 3000,
			settled: true,
			outcome: 0,
			isFalsePositive: true,
			actualTokens: 3200,
			durationMs: 1200,
			source: "verifier-gate",
			createdAt: new Date(1700000000000 + idx * 1000).toISOString(),
			settledAt: new Date(1700000000500 + idx * 1000).toISOString(),
		}));

		const gov = nuwaMod.governDistilledExperience(sb.kbDb, mechRecords);
		expect(gov.quarantinedIds).toContain("exp:spring:noisy-actuator-fp");
		const postSearch = nuwaMod.hybridKbSearch(sb.kbDb, "noisy-actuator-fp");
		expect(postSearch.some((h) => h.id === "exp:spring:noisy-actuator-fp")).toBe(false);
	});

	test("5+1 专精小队派单守卫放行全部 6 角色且联合路由器自动避开高误报模型", () => {
		const sb = makeSandbox();
		const allSix = [
			"nuwa-scout",
			"nuwa-spa-reverser",
			"nuwa-auth-breaker",
			"nuwa-code-auditor",
			"nuwa-verifier",
			"fujiang",
		];
		for (const role of allSix) {
			expect(existsSync(join(REPO_ROOT, "agents", `${role}.md`))).toBe(true);
			const verdict = nuwaMod.checkTaskPolicy({ agent: role, task: "执行合规探针" }, true, true);
			expect(verdict).toBeNull();
		}
		const badVerdict = nuwaMod.checkTaskPolicy({ agent: "unknown-rogue-agent", task: "x" }, true, true);
		expect(badVerdict?.block).toBe(true);
		expect(badVerdict?.reason).toContain("N-004");

		// 验证前沿意图自动给出对应专精角色推荐
		const st = nuwaMod.newState("http://127.0.0.1:19005", "专精路由测试", "pentest", nuwaMod.readCfg());
		nuwaMod.addIntent(st, {
			key: "authdiff:bola:orders",
			phase: "vuln",
			title: "多角色 JWT BOLA 水平越权契约差分",
			detail: "对比 userA 与 userB 访问 /api/orders?id=1002 的响应结构差异",
			priority: 92,
		});
		const frontier = nuwaMod.frontierList(st, 5, 900, sb.root);
		expect(frontier[0]?.recommendedSpecialist).toBe("nuwa-auth-breaker");
	});

	test("多跳攻击链真实重放打穿产出 candidate 复合漏洞，受阻步骤精准回灌 brokenAtStep 至信念图", async () => {
		const sb = makeSandbox();
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;

		const secretTicket = "TICKET_DYNAMIC_SECRET_V7_778899";
		const lowBearer = "LOW_PRIV_JWT_SECRET_V7_112233";
		let blockHop2 = false;
		const server = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const u = new URL(req.url);
				if (u.pathname === "/assets/app.bundle.js.map") {
					return Response.json({
						version: 3,
						sources: ["src/internal/approvals.ts"],
						sourcesContent: [`export const APPROVAL_API = "/api/internal/approvals/101";`],
					});
				}
				if (u.pathname === "/api/internal/approvals/101") {
					if (blockHop2) {
						return Response.json({ error: "Forbidden by hardened RBAC" }, { status: 403 });
					}
					return Response.json({
						ok: true,
						approvalId: 101,
						exportTicket: secretTicket,
						owner: "dept-finance",
					});
				}
				if (u.pathname === "/api/internal/export") {
					const tk = u.searchParams.get("exportTicket") || u.searchParams.get("ticket");
					if (tk === secretTicket) {
						return Response.json({
							status: "exported",
							batch: "FIN-EXPORT-2026-V7",
							records: [
								{ employee: "alice", salary: 420000, ssnLast4: "8821" },
								{ employee: "bob", salary: 390000, ssnLast4: "1940" },
							],
						});
					}
					return new Response(JSON.stringify({ error: "Forbidden: invalid exportTicket" }), {
						status: 403,
						headers: { "content-type": "application/json" },
					});
				}
				return new Response("Not Found", { status: 404 });
			},
		});

		try {
			const baseUrl = `http://127.0.0.1:${server.port}`;
			const engine = new nuwaMod.NuwaUnifiedEngine({ projectRoot: sb.root, cwd: sb.root, agentHome: sb.agentHome });
			await engine.callTool("nuwa_init", { target: baseUrl, mode: "pentest", root: sb.root });
			nuwaMod.upsertSessionRole(sb.root, { role: "low", bearer: lowBearer, note: "低权员工会话" });

			// 写入三跳互补前置事实（SourceMap 泄露内部路由 -> 低权凭据越权读 exportTicket -> 凭 exportTicket 调内部导出接口）
			nuwaMod.withLock(sb.root, () => {
				const st = nuwaMod.loadState(sb.root)!;
				st.project.activeRoles = ["low"];
				st.facts.f1_sourcemap = {
					id: "f1_sourcemap",
					kind: "endpoint",
					title: "前端 SourceMap 泄露内部审批路由",
					detail: "静态资源 /assets/app.bundle.js.map 暴露未公开内部审批接口路由线索",
					targetKey: "/assets/app.bundle.js.map",
					meta: { bundles: ["/assets/app.bundle.js.map"] },
					createdAt: "2026-11-26T01:00:00Z",
				};
				st.facts.f_cred_low = {
					id: "f_cred_low",
					kind: "cred",
					title: "已获取普通低权员工账号认证凭据 (role=low)",
					detail: "普通员工低权限会话，角色 role=low，已存入会话保险箱",
					createdAt: "2026-11-26T01:01:00Z",
				};
				st.facts.f2_approval_bola = {
					id: "f2_approval_bola",
					kind: "endpoint",
					title: "普通低权凭据越权读取审批单中的 exportTicket",
					detail: "携带普通低权凭据访问泄露的内部审批路由可越权读取审批单详情及一次性 exportTicket",
					createdAt: "2026-11-26T01:02:00Z",
				};
				st.facts.f3_internal_export = {
					id: "f3_internal_export",
					kind: "endpoint",
					title: "内部导出接口凭 exportTicket 导出敏感业务数据",
					detail: "内部导出接口 /api/internal/export 校验 ticket/exportTicket 参数后返回财务结算敏感业务数据",
					targetKey: "/api/internal/export",
					meta: { paths: ["/api/internal/export"] },
					createdAt: "2026-11-26T01:03:00Z",
				};
				st.seq.fact = 4;
				nuwaMod.saveState(sb.root, st);
			});

			// 1. 只读 /nuwa chains 视图展示可合成的多跳链
			const listView = await engine.executeSlashCommand("chains");
			expect(listView.level).toBe("info");
			expect(listView.message).toContain("多跳攻击链合成视图");
			expect(listView.message).not.toContain("尚无满足");

			// 2. 执行 /nuwa chains verify 打穿全链 -> 自动产出 candidate 复合漏洞并派发 verify-vuln 双盲复验，且零明文票据泄露
			const verifyView = await engine.executeSlashCommand("chains verify");
			expect(verifyView.level).toBe("info");
			expect(verifyView.message).toContain("多跳攻击链验证打穿");
			expect(verifyView.message).not.toContain(secretTicket);
			expect(verifyView.message).not.toContain(lowBearer);

			const stAfter = nuwaMod.loadState(sb.root)!;
			const candFacts = Object.values(stAfter.facts).filter((f) => f.verifyStage === "candidate");
			expect(candFacts.length).toBeGreaterThanOrEqual(1);
			expect(JSON.stringify(candFacts)).not.toContain(secretTicket);
			expect(JSON.stringify(candFacts)).not.toContain(lowBearer);
			expect(Object.values(stAfter.intents).some((i) => i.key.startsWith("verify-vuln:"))).toBe(true);

			// 3. 切换第 2 跳加固 403 -> 验证 brokenAtStep=1 精准定界并回灌信念图衰减
			blockHop2 = true;
			const stBeforeBlock = nuwaMod.loadState(sb.root)!;
			const bg = nuwaMod.initBeliefGraphFromState(stBeforeBlock);
			const nodeIdHop2 = nuwaMod.resolveBeliefNodeId(bg, "f2_approval_bola")!;
			const priorHop2 = bg.nodes[nodeIdHop2]!.posterior;
			const loopRes = await nuwaMod.runAutonomousChainVerification(
				{
					...stBeforeBlock,
					facts: {
						f1_sourcemap: stBeforeBlock.facts.f1_sourcemap!,
						f_cred_low: stBeforeBlock.facts.f_cred_low!,
						f2_approval_bola: stBeforeBlock.facts.f2_approval_bola!,
						f3_internal_export: stBeforeBlock.facts.f3_internal_export!,
					},
				},
				sb.root,
				stBeforeBlock.project.scope!,
				{ beliefGraph: bg, maxVerifyChains: 1 },
			);
			expect(loopRes.brokenChains.length).toBe(1);
			expect(loopRes.brokenChains[0]!.brokenAtStep).toBe(1);
			expect(bg.nodes[nodeIdHop2]!.posterior).toBeLessThan(priorHop2);
		} finally {
			server.stop(true);
		}
	});

	test("install.sh 在独立隔离沙盒完整部署 v7 模块、6 个专精小队模板并构建 >=520 条 kb.db", () => {
		const sb = makeSandbox("nuwa-v7-install-");
		const fakeBin = join(sb.root, "fake-bin");
		const targetBin = join(sb.root, "local-bin");
		mkdirSync(fakeBin, { recursive: true });
		mkdirSync(targetBin, { recursive: true });

		const stubOmp = join(fakeBin, "omp");
		writeFileSync(stubOmp, "#!/usr/bin/env bash\necho 'omp 18.16.0'\n", "utf8");
		chmodSync(stubOmp, 0o755);

		const env = {
			...process.env,
			BUN_OPTIONS: undefined,
			PI_AGENT_HOME: sb.agentHome,
			NUWA_BIN_DIR: targetBin,
			PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
		};
		delete (env as Record<string, unknown>).BUN_OPTIONS;
		delete (env as Record<string, unknown>).NUWA_KB_DB;

		const res = spawnSync("bash", [join(REPO_ROOT, "install.sh"), "--force-agents", "--clean-kb"], {
			cwd: REPO_ROOT,
			env: env as NodeJS.ProcessEnv,
			encoding: "utf8",
			timeout: 120_000,
		});
		expect(res.status).toBe(0);
		expect(res.stdout).toContain("installed version = 8.0.0");

		for (const role of [
			"fujiang.md",
			"nuwa-verifier.md",
			"nuwa-scout.md",
			"nuwa-spa-reverser.md",
			"nuwa-auth-breaker.md",
			"nuwa-code-auditor.md",
		]) {
			expect(existsSync(join(sb.agentHome, "agents", role))).toBe(true);
		}
		expect(existsSync(join(sb.agentHome, "nuwa-core", "core", "engine.ts"))).toBe(true);

		const db = new Database(join(sb.agentHome, "nuwa-kb", "kb.db"), { readonly: true });
		try {
			const cnt = (db.query("SELECT COUNT(*) AS cnt FROM kb_items").get() as { cnt: number }).cnt;
			expect(cnt).toBeGreaterThanOrEqual(520);
		} finally {
			db.close();
		}

		// 验证 nuwa-autonomous doctor --json 完整校验 V7_EXT_MODULES 与 6 个专精小队模板（#92 P1-4）
		const docOk = spawnSync("bun", [join(targetBin, "nuwa-autonomous"), "doctor", "--json"], {
			cwd: sb.root,
			env: env as NodeJS.ProcessEnv,
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(docOk.status).toBe(0);
		const docOkJson = JSON.parse(docOk.stdout);
		expect(docOkJson.ok).toBe(true);
		expect(docOkJson.checks.extension.v7ModulesFound.length).toBe(5);
		expect(docOkJson.checks.extension.v7ModulesMissing.length).toBe(0);
		expect(docOkJson.checks.agents.ok).toBe(true);
		expect(docOkJson.checks.agents.squadMissing.length).toBe(0);

		// 删除 v7 模块与新小队模板后 doctor 必须报错并告警
		rmSync(join(sb.agentHome, "extensions", "nuwa-omp", "cdp-bridge.ts"), { force: true });
		rmSync(join(sb.agentHome, "agents", "nuwa-scout.md"), { force: true });
		const docFail = spawnSync("bun", [join(targetBin, "nuwa-autonomous"), "doctor", "--json"], {
			cwd: sb.root,
			env: env as NodeJS.ProcessEnv,
			encoding: "utf8",
			timeout: 15_000,
		});
		expect(docFail.status).toBe(1);
		const docFailJson = JSON.parse(docFail.stdout);
		expect(docFailJson.ok).toBe(false);
		expect(docFailJson.checks.extension.ok).toBe(false);
		expect(docFailJson.checks.extension.v7ModulesMissing).toContain("cdp-bridge.ts");
		expect(docFailJson.checks.agents.ok).toBe(false);
		expect(docFailJson.checks.agents.squadMissing).toContain("nuwa-scout.md");
	}, 120_000);
});

describe("Wave 2 Boost 异构终审全量反例回归（#91 / #92 / #93）", () => {
	test("终审 A (#91 P1-1 & P1-2): 损坏 autoexec.json 下 omp nuwa_status 零写盘，且 /nuwa scope show|list 与 session/oob list 零写锁零改写", async () => {
		const sb = makeSandbox("nuwa-v7-r91-");
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;
		nuwaMod.ensureBundledKb(sb.kbDb, { agentHome: sb.agentHome });

		// 1) 遗留纯 state.json + 损坏 autoexec.json 场景（无 journal.jsonl、无 nuwa.db）
		process.env.NUWA_STORAGE_BACKEND = "json";
		const stLegacy = nuwaMod.newState("http://127.0.0.1:19801", "终审A零写盘验证", "pentest", nuwaMod.readCfg(), "r91-sid");
		nuwaMod.seedPhase(stLegacy, "recon");
		nuwaMod.saveStateJsonOnly(sb.root, stLegacy);
		writeFileSync(join(sb.root, ".nuwa", "autoexec.json"), "{ invalid json syntax", "utf8");
		rmSync(join(sb.root, ".nuwa", "journal.jsonl"), { force: true });
		delete process.env.NUWA_STORAGE_BACKEND;

		const nuwaDir = join(sb.root, ".nuwa");
		const filesBefore = readdirSync(nuwaDir).sort();
		const dirMtimeBefore = statSync(nuwaDir).mtimeMs;
		const stateMtimeBefore = statSync(nuwaMod.statePath(sb.root)).mtimeMs;

		const h = createOmpHarness(sb.root, "r91-sid");
		const stRes = await h.tools.get("nuwa_status").execute("r91-1", { root: sb.root }, undefined, undefined, h.ctx);
		expect(stRes.isError).toBe(false);
		expect(existsSync(join(nuwaDir, "journal.jsonl"))).toBe(false);
		expect(existsSync(nuwaMod.sqliteDbPath(sb.root))).toBe(false);

		const eng = new nuwaMod.NuwaUnifiedEngine({ projectRoot: sb.root, cwd: sb.root, agentHome: sb.agentHome, sessionId: "r91-sid" });
		for (const cmd of ["scope", "scope show", "scope list", "session LIST", "oob LIST"]) {
			const r = await eng.executeSlashCommand(cmd);
			expect(r.level).toBe("info");
		}
		expect(readdirSync(nuwaDir).sort()).toEqual(filesBefore);
		expect(statSync(nuwaDir).mtimeMs).toBe(dirMtimeBefore);
		expect(statSync(nuwaMod.statePath(sb.root)).mtimeMs).toBe(stateMtimeBefore);

		// 2) 默认 SQLite 活跃项目 + 损坏 autoexec.json 场景：omp nuwa_status 不改写 nuwa.db mtime
		const sbSqlite = makeSandbox("nuwa-v7-r91-sql-");
		const hSql = createOmpHarness(sbSqlite.root, "r91-sql-sid");
		await hSql.tools.get("nuwa_init").execute(
			"init-sql",
			{ target: "http://127.0.0.1:19802", mode: "ctf", root: sbSqlite.root },
			undefined,
			undefined,
			hSql.ctx,
		);
		writeFileSync(join(sbSqlite.root, ".nuwa", "autoexec.json"), "{ broken", "utf8");
		const dbFile = nuwaMod.sqliteDbPath(sbSqlite.root);
		await Bun.sleep(20);
		const dbMtime0 = statSync(dbFile).mtimeMs;
		const stSqlRes = await hSql.tools.get("nuwa_status").execute("st-sql", { root: sbSqlite.root }, undefined, undefined, hSql.ctx);
		expect(stSqlRes.isError).toBe(false);
		expect(statSync(dbFile).mtimeMs).toBe(dbMtime0);
	});

	test("终审 B (#92 P1-1 & P1-2 & P1-3): KB 2.0 冻结经验零穿透不复活、专精角色锁死与环境变量联动、攻击链单次回灌及终态闭环守卫", async () => {
		const sb = makeSandbox("nuwa-v7-r92-");
		process.env.PI_AGENT_HOME = sb.agentHome;
		process.env.NUWA_KB_DB = sb.kbDb;
		buildKb({ outPath: sb.kbDb });

		// 1) P1-1: quarantined 经验不穿透 formatExperienceHints / UCB1，二次蒸馏不复活 quarantined、不降级 promoted
		const stDistill = nuwaMod.newState("http://127.0.0.1:19810", "蒸馏测试", "pentest", nuwaMod.readCfg());
		stDistill.facts.f1 = {
			id: "f1",
			kind: "service",
			title: "Spring Boot Actuator 暴露",
			detail: "检测到 Spring Boot 服务",
			createdAt: "2026-11-26T00:00:00Z",
		};
		stDistill.facts.f2 = {
			id: "f2",
			kind: "vuln",
			title: "Actuator env 敏感泄露",
			detail: "Spring Actuator 暴露配置",
			verified: true,
			verifyStage: "confirmed",
			createdAt: "2026-11-26T00:01:00Z",
		};
		stDistill.intents.i1 = {
			id: "i1",
			key: "ep:f1:/actuator/env",
			phase: "vuln",
			title: "核验 Actuator env",
			detail: "检查 /actuator/env",
			status: "done",
			priority: 80,
			from: ["f1"],
			to: "f2",
			attempts: 1,
			createdAt: "2026-11-26T00:00:30Z",
			updatedAt: "2026-11-26T00:01:00Z",
		};
		const d1 = nuwaMod.distillProjectExperience(stDistill, { dbPath: sb.kbDb });
		expect(d1.updated).toBeGreaterThanOrEqual(1);
		const canonKey = nuwaMod.canonicalizeExperienceIntentKey("ep:f1:/actuator/env");

		// 另插入一张 promoted 卡片，并将上述蒸馏卡通过 5 条误报结算冻结为 quarantined
		nuwaMod.upsertDistilledExperienceCard(sb.kbDb, {
			id: "exp:spring:promoted-card",
			tech: "spring",
			intentKey: "promoted-card",
			phase: "vuln",
			title: "高胜率晋升经验卡",
			summary: "已晋升有效模式",
			payload_or_check: "GET /actuator/heapdump",
			status: "promoted",
		});
		const fpRecs: nuwaMod.CalibrationRecord[] = Array.from({ length: 5 }, (_, idx) => ({
			predictionId: `fp-r92-${idx}`,
			intentId: canonKey,
			taskCategory: "exploit",
			modelId: "gemini-4-neon-xhigh",
			predictedConfidence: 0.8,
			estimatedTokens: 2000,
			settled: true,
			outcome: 0,
			isFalsePositive: true,
			actualTokens: 2100,
			durationMs: 800,
			source: "verifier-gate",
			createdAt: new Date(1700000000000 + idx * 1000).toISOString(),
			settledAt: new Date(1700000000500 + idx * 1000).toISOString(),
		}));
		const gov = nuwaMod.governDistilledExperience(sb.kbDb, fpRecs);
		expect(gov.quarantinedIds).toContain(`exp:spring:${canonKey}`);

		// 校验 kbLookupSafe 不穿透输出被冻结经验，且 UCB1 返回 0
		const springLookup = nuwaMod.kbLookupSafe("spring", "auto", 5, { dbPath: sb.kbDb, autoInit: false });
		expect(springLookup).not.toContain(canonKey);
		expect(nuwaMod.computeExperiencePriorityBoost(["spring"], "ep:f001:/actuator/env", { dbPath: sb.kbDb })).toBe(0);

		// 二次无校准记录蒸馏：quarantined 不得复活为 active，promoted 不得被重置降级为 active
		nuwaMod.upsertDistilledExperienceCard(sb.kbDb, {
			id: "exp:spring:promoted-card",
			tech: "spring",
			intentKey: "promoted-card",
			phase: "vuln",
			title: "高胜率晋升经验卡更新",
			summary: "补充摘要",
			payload_or_check: "HEAD /actuator/heapdump",
		});
		nuwaMod.distillProjectExperience(stDistill, { dbPath: sb.kbDb });
		const verifyDb = new Database(sb.kbDb, { readonly: true });
		try {
			const qRow = verifyDb.query("SELECT status FROM kb_items WHERE id = ?").get(`exp:spring:${canonKey}`) as { status: string };
			const pRow = verifyDb.query("SELECT status FROM kb_items WHERE id = ?").get("exp:spring:promoted-card") as { status: string };
			expect(qRow.status).toBe("quarantined");
			expect(pRow.status).toBe("promoted");
		} finally {
			verifyDb.close();
		}

		// 2) P1-2: routeSubagentModel 锁死当前专精角色，且 frontierList / squad 联动 NUWA_MODEL_* 环境变量
		const roleWs = makeSandbox("nuwa-v7-r92-role-");
		for (let i = 0; i < 5; i++) {
			const pScout = `p-scout-${i}`;
			nuwaMod.recordPrediction(roleWs.root, {
				predictionId: pScout,
				intentId: `recon:${i}`,
				taskCategory: "recon",
				modelId: "model-fast",
				predictedConfidence: 0.8,
				estimatedTokens: 1000,
				note: "role=nuwa-scout",
			});
			nuwaMod.settlePrediction(roleWs.root, {
				predictionId: pScout,
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 900,
				durationMs: 300,
				source: "exec-ledger",
			});
			const pAuthGood = `p-auth-good-${i}`;
			nuwaMod.recordPrediction(roleWs.root, {
				predictionId: pAuthGood,
				intentId: `auth:${i}`,
				taskCategory: "auth",
				modelId: "model-deep",
				predictedConfidence: 0.85,
				estimatedTokens: 1500,
				note: "role=nuwa-auth-breaker",
			});
			nuwaMod.settlePrediction(roleWs.root, {
				predictionId: pAuthGood,
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 1400,
				durationMs: 400,
				source: "verifier-gate",
			});
			const pAuthBad = `p-auth-bad-${i}`;
			nuwaMod.recordPrediction(roleWs.root, {
				predictionId: pAuthBad,
				intentId: `auth-bad:${i}`,
				taskCategory: "auth",
				modelId: "model-fast",
				predictedConfidence: 0.8,
				estimatedTokens: 1200,
				note: "role=nuwa-auth-breaker",
			});
			nuwaMod.settlePrediction(roleWs.root, {
				predictionId: pAuthBad,
				outcome: 0,
				isFalsePositive: true,
				actualTokens: 1200,
				durationMs: 350,
				source: "verifier-gate",
			});
		}

		process.env.NUWA_MODEL_FAST = "model-fast";
		process.env.NUWA_MODEL_DEEP = "model-deep";
		process.env.NUWA_MODEL_VERIFY = "model-verify";
		try {
			const routed = nuwaMod.routeSubagentModel({
				agent: "nuwa-auth-breaker",
				phase: "recon",
				intentKeys: ["recon:baseline"],
				root: roleWs.root,
				allowedModels: ["model-fast", "model-deep", "model-verify"],
			});
			expect(routed).toBe("model-deep");

			const stSquad = nuwaMod.newState("http://127.0.0.1:19812", "小队模型环境变量测试", "pentest", nuwaMod.readCfg());
			nuwaMod.addIntent(stSquad, {
				phase: "vuln",
				title: "多角色 JWT BOLA 水平越权鉴权差分核验",
				detail: "对比 userA/userB 访问 /api/orders?id=1002 的响应结构差异",
				priority: 90,
			});
			nuwaMod.saveState(roleWs.root, stSquad);
			const fItems = nuwaMod.frontierList(stSquad, 5, 900, roleWs.root);
			expect(fItems[0]?.recommendedSpecialist).toBe("nuwa-auth-breaker");
			expect(fItems[0]?.recommendedModel).toBe("model-deep");
			const squadOut = nuwaMod.executeSquadCommand(roleWs.root, "");
			expect(squadOut.msg).toContain("模型=model-deep");
		} finally {
			delete process.env.NUWA_MODEL_FAST;
			delete process.env.NUWA_MODEL_DEEP;
			delete process.env.NUWA_MODEL_VERIFY;
		}

		// 3) P1-3: runAutonomousChainVerification 绝不双重衰减信念，且终态项目拒绝 runPostBatchAutonomousLoops 改写
		let hitCount = 0;
		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				hitCount += 1;
				const u = new URL(req.url);
				if (u.pathname === "/assets/app.bundle.js.map") {
					return Response.json({
						version: 3,
						sources: ["src/approvals.ts"],
						sourcesContent: [`const API = "/api/internal/approvals/202";`],
					});
				}
				return Response.json({ error: "Forbidden" }, { status: 403 });
			},
		});
		try {
			const url = `http://127.0.0.1:${srv.port}`;
			const chainSb1 = makeSandbox("nuwa-v7-chain-single1-");
			const chainSb2 = makeSandbox("nuwa-v7-chain-single2-");
			const mkChainState = () => {
				const s = nuwaMod.newState(url, "单次回灌测试", "pentest", nuwaMod.readCfg());
				s.facts.f1 = {
					id: "f1",
					kind: "endpoint",
					title: "SourceMap 泄露内部审批路由",
					detail: "静态资源 /assets/app.bundle.js.map 暴露未公开内部审批接口路由线索",
					targetKey: "/assets/app.bundle.js.map",
					meta: { bundles: ["/assets/app.bundle.js.map"] },
					createdAt: "2026-11-26T01:00:00Z",
				};
				s.facts.f2 = {
					id: "f2",
					kind: "endpoint",
					title: "越权读取审批单中的 exportTicket",
					detail: "访问泄露的内部审批路由读取一次性 exportTicket",
					createdAt: "2026-11-26T01:01:00Z",
				};
				return s;
			};

			const s1 = mkChainState();
			const bg1 = nuwaMod.initBeliefGraphFromState(s1);
			await nuwaMod.runAutonomousChainVerification(s1, chainSb1.root, s1.project.scope!, {
				beliefGraph: bg1,
				applyBeliefUpdate: false,
				maxVerifyChains: 1,
			});

			const s2 = mkChainState();
			const bg2 = nuwaMod.initBeliefGraphFromState(s2);
			await nuwaMod.runAutonomousChainVerification(s2, chainSb2.root, s2.project.scope!, {
				beliefGraph: bg2,
				applyBeliefUpdate: true,
				maxVerifyChains: 1,
			});

			const nid1 = nuwaMod.resolveBeliefNodeId(bg1, "f2")!;
			const nid2 = nuwaMod.resolveBeliefNodeId(bg2, "f2")!;
			expect(bg2.nodes[nid2]!.beta).toBeCloseTo(bg1.nodes[nid1]!.beta, 6);

			// 终态项目调用 runPostBatchAutonomousLoops 必须零发包、零改写
			const termSb = makeSandbox("nuwa-v7-term-loop-");
			const termSt = mkChainState();
			(termSt.project as { status: string }).status = "done";
			termSt.runtime.status = "completed";
			nuwaMod.saveState(termSb.root, termSt);
			const hitsBeforeTerm = hitCount;
			const factsBeforeTerm = Object.keys(nuwaMod.loadState(termSb.root)!.facts).length;
			await nuwaMod.runPostBatchAutonomousLoops(termSb.root, {});
			expect(hitCount).toBe(hitsBeforeTerm);
			expect(Object.keys(nuwaMod.loadState(termSb.root)!.facts).length).toBe(factsBeforeTerm);
		} finally {
			srv.stop(true);
		}
	});
});
