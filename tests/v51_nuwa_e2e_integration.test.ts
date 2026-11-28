/**
 * 女娲 v5.1.0 端到端总装集成测试（覆盖 omp/nuwa.ts 12 工具不变量、全部新增参数、斜杠子命令、生命周期钩子与跨模块协作）。
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import * as nuwaMod from "../omp/nuwa";

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

const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-v51-e2e-home-"));
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
delete process.env.NUWA_KB_DB;

const tempDirs: string[] = [];
function makeTmpWorkspace(prefix = "nuwa-v51-e2e-ws-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tempDirs.push(dir);
	return dir;
}

afterEach(() => {
	while (tempDirs.length > 0) {
		const d = tempDirs.pop()!;
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
	delete process.env.NUWA_EGRESS;
	delete process.env.NUWA_STRICT_EVIDENCE;
});

afterAll(() => {
	try {
		rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
	} catch {
		/* ignore */
	}
});

/** 模拟 omp 插件宿主注册框架（对齐 contract_check.py）。 */
function createMockHarness(cwd: string, sessionId = "v51-e2e-sess") {
	process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	let commandDef: any = null;
	const notifications: Array<{ text: string; level: string }> = [];
	const statuses = new Map<string, string>();
	const sentMessages: string[] = [];

	const chain = (): any =>
		new Proxy(() => chain(), {
			get: () => (..._a: any[]) => chain(),
		});
	const z: any = new Proxy({}, { get: () => (..._a: any[]) => chain() });

	nuwaMod.default({
		zod: z,
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (name: string, def: any) => {
			commandDef = { name, ...def };
		},
		on: (ev: string, fn: (...args: any[]) => any) => {
			const list = hooks.get(ev) ?? [];
			list.push(fn);
			hooks.set(ev, list);
		},
		sendUserMessage: (msg: string) => {
			sentMessages.push(msg);
		},
		sendMessage: (m: any) => {
			sentMessages.push(String(m?.content ?? ""));
		},
	} as any);

	const ctx: any = {
		cwd,
		agent: { kind: "main", id: "main-0", name: "main", depth: 0 },
		sessionManager: { getSessionId: () => sessionId },
		getContextUsage: () => ({ tokens: 2048, usedTokens: 2048 }),
		ui: {
			notify: (text: string, level = "info") => notifications.push({ text, level }),
			setStatus: (key: string, val?: string) => {
				if (val === undefined) statuses.delete(key);
				else statuses.set(key, val);
			},
			setWidget: () => {},
			setTitle: () => {},
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
			custom: async () => undefined,
		},
	};

	const call = (name: string, params: Record<string, unknown> = {}) => {
		const tool = tools.get(name);
		if (!tool) throw new Error(`tool not found: ${name}`);
		return tool.execute("call-e2e", params, undefined, undefined, ctx);
	};

	const runSlash = async (arg: string) => {
		if (!commandDef?.handler) throw new Error("/nuwa command not registered");
		await commandDef.handler(arg, ctx);
	};

	return {
		tools,
		hooks,
		commandDef,
		ctx,
		notifications,
		statuses,
		sentMessages,
		call,
		runSlash,
	};
}

function snapshotTreeState(dir: string): Array<{ rel: string; mtimeMs: number; sha256: string }> {
	const out: Array<{ rel: string; mtimeMs: number; sha256: string }> = [];
	const walk = (cur: string) => {
		if (!existsSync(cur)) return;
		for (const ent of readdirSync(cur, { withFileTypes: true })) {
			const full = join(cur, ent.name);
			if (ent.isDirectory()) {
				walk(full);
			} else if (ent.isFile()) {
				const st = statSync(full);
				const sha256 = createHash("sha256").update(readFileSync(full)).digest("hex");
				out.push({ rel: relative(dir, full), mtimeMs: st.mtimeMs, sha256 });
			}
		}
	};
	walk(dir);
	return out.sort((a, b) => a.rel.localeCompare(b.rel));
}

describe("v5.1.0 总装契约：12 工具不变量、版本号与斜杠子命令补全", () => {
	test("严格保持 12 个 nuwa_* 工具名称且版本统一为 7.0.0", () => {
		const ws = makeTmpWorkspace();
		const h = createMockHarness(ws);

		expect(nuwaMod.VERSION).toBe("8.0.0");
		expect(nuwaMod.NUWA_VERSION).toBe("8.0.0");
		expect(h.tools.size).toBe(12);
		expect([...h.tools.keys()].sort()).toEqual([...EXPECTED_12_TOOLS].sort());

		const completions = h.commandDef.getArgumentCompletions("").map((x: any) => x.value);
		for (const sub of ["seal", "note", "inspect", "query", "pause", "resume", "export"]) {
			expect(completions).toContain(sub);
		}
	});
});

describe("v5.1.0 nuwa_plan / nuwa_claim / nuwa_expand：三元组去重、在途去重、分片保护与出口注入", () => {
	test("三元组去重、在途目标抑制、出口随任务注入及 >6000B 批派单自动溢写 tasks_file", async () => {
		const ws = makeTmpWorkspace();
		const h = createMockHarness(ws, "sess-plan-e2e");

		await h.call("nuwa_init", {
			target: "http://target.internal.test:8080",
			mode: "pentest",
			goal: "验证规划去重与分片保护",
			root: ws,
		});

		// 1) 新增两条等价目标的三元组意图，第二条应被 duplicate_key 抑制
		const p1 = await h.call("nuwa_plan", {
			egress: "socks5h://127.0.0.1:7890",
			intents: [
				{
					title: "探测管理端 /admin 鉴权",
					detail: "GET /admin 检查状态码",
					phase: "surface",
					target: "http://target.internal.test:8080/admin/",
					expectedKind: "endpoint",
					hint: "auth-check",
				},
				{
					title: "重复探测 /admin 路径",
					detail: "重复同一三元组",
					phase: "surface",
					target: "http://target.internal.test:8080/admin",
					expectedKind: "endpoint",
					hint: "auth-check",
				},
			],
		});
		expect(p1.details.added.length).toBe(1);
		expect(p1.details.rejectedReasons.some((r: any) => r.reason === "duplicate_key")).toBe(true);
		expect(p1.details.egressEnv.HTTPS_PROXY).toBe("socks5h://127.0.0.1:7890");

		// 2) 认领该意图后自动注入 resolved_host、出口指引并写入跨子代理在途去重池
		const addedId = p1.details.added[0] as string;
		const claimed = await h.call("nuwa_claim", {
			id: addedId,
			worker: "fujiang",
			egress: "socks5h://127.0.0.1:7890",
		});
		expect(claimed.content[0].text).toContain("resolved_host: target.internal.test");
		expect(claimed.content[0].text).toContain("[出口强制注入]");
		expect(claimed.details.expectedKind).toBe("endpoint");

		// 3) 再次对在途 targetKey 规划不同 hint 意图，被 inflight 在途去重池拦截
		const p2 = await h.call("nuwa_plan", {
			intents: [
				{
					title: "并发重复探测在途 /admin",
					phase: "surface",
					target: "http://target.internal.test:8080/admin",
					expectedKind: "vuln",
					hint: "another-probe",
				},
			],
		});
		expect(p2.details.added.length).toBe(0);
		expect(p2.details.rejectedReasons.some((r: any) => r.reason === "inflight")).toBe(true);

		// 4) 传入超过 6000 字节的 batch_tasks，验证自动溢写 .nuwa/dispatches/batch-*.json
		const largeTasks = Array.from({ length: 6 }, (_, idx) => ({
			id: `T-${idx + 1}`,
			agent: "fujiang",
			targetKey: `/api/v1/mod-${idx + 1}`,
			task: `探测模块 ${idx + 1} 路由 https://TARGET/api/v1/mod-${idx + 1} :: ${"X".repeat(1200)}`,
		}));
		const pBatch = await h.call("nuwa_plan", {
			egress: "socks5h://127.0.0.1:7890",
			batch_tasks: largeTasks,
		});
		expect(pBatch.details.batch.exceeded).toBe(true);
		expect(pBatch.details.batch.mode).toBe("spilled");
		expect(existsSync(pBatch.details.batch.tasks_file)).toBe(true);
		const spilledTasks = nuwaMod.readSpilledBatchTasks(pBatch.details.batch.tasks_file);
		expect(spilledTasks.length).toBe(6);
		expect(spilledTasks[0]!.task).toContain("target.internal.test");
		expect(spilledTasks[0]!.task).not.toContain("https://TARGET");

		// 5) nuwa_expand 返回结构化 rejectedReasons
		const expRes = await h.call("nuwa_expand", {});
		expect(Array.isArray(expRes.details.rejectedReasons)).toBe(true);
	});
});

describe("v5.1.0 nuwa_commit：免票据直记、expectedKind 继承、agent_result、evidence_ref、模板与假阳性拦截、blocked 双计数", () => {
	test("覆盖省略 kind 继承、免票据记账、AgentResult 解析、证据落盘、模板拦截、假阳性降级及 blockedCommits 累加", async () => {
		const ws = makeTmpWorkspace();
		const h = createMockHarness(ws, "sess-commit-e2e");

		await h.call("nuwa_init", {
			target: "http://app.demo.local:8080",
			mode: "pentest",
			goal: "验证记账全链路门禁",
			root: ws,
		});

		// 1) 认领 i001 (recon:http -> expectedKind="service")，省略 kind 提交自动继承 "service"
		const claim1 = await h.call("nuwa_claim", { id: "i001" });
		expect(claim1.details.expectedKind).toBe("service");

		const commitInherited = await h.call("nuwa_commit", {
			id: "i001",
			title: "Next.js 16.3.3 Web 服务存活",
			detail: "前置 Cloudflare + Next.js",
			command: "curl -sS -D - http://app.demo.local:8080/",
			output: "HTTP/1.1 200 OK\nServer: cloudflare\nx-powered-by: Next.js\nhttp_code=200 size_download=4096 remote_ip=10.0.0.8 cf_ray=8abc123-HKG time_total=0.12",
		});
		expect(commitInherited.details.error).toBeUndefined();
		expect(commitInherited.details.inheritedKind).toBe("service");
		const stAfter1 = nuwaMod.loadState(ws)!;
		expect(stAfter1.facts.f001?.kind).toBe("service");

		// 2) 免票据记账（省略 id + 结构化 fenced JSON agent_result + save_evidence_log=true 落盘）
		const fencedAgentJson = [
			"```json",
			JSON.stringify({
				status: "ok",
				target: "http://app.demo.local:8080/api/v1/config",
				blocked: false,
				summary: "发现公开配置端点 /api/v1/config",
				next: "审计返回字段是否含敏感配置",
				evidence: [
					{
						cmd: "curl -sS -w 'http_code=%{http_code}' http://app.demo.local:8080/api/v1/config",
						http_code: 200,
						size_download: 512,
						remote_ip: "10.0.0.8",
						cf_ray: "8abc999-HKG",
						time_total: 0.08,
						body_sha256: "a".repeat(64),
						snippet: '{"version":"16.3.3","publicFeatures":["news","carousel"]}',
					},
				],
			}),
			"```",
		].join("\n");

		const freeRes = await h.call("nuwa_commit", {
			free_note: true,
			kind: "endpoint",
			agent_result: fencedAgentJson,
			save_evidence_log: true,
			raw_response: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"version":"16.3.3","publicFeatures":["news","carousel"]}',
		});
		expect(freeRes.details.error).toBeUndefined();
		expect(freeRes.details.freeFact).toBe(true);
		expect(freeRes.details.evidenceRef).toBe(".nuwa/evidence/f002.log");
		expect(existsSync(join(ws, ".nuwa/evidence/f002.log"))).toBe(true);
		const stAfterFree = nuwaMod.loadState(ws)!;
		expect(stAfterFree.facts.f002?.evidenceRef).toBe(".nuwa/evidence/f002.log");
		expect(stAfterFree.facts.f002?.agentResult?.summary).toContain("/api/v1/config");

		// 3) #26 模板化回包拦截（含 [BOOL_DELTA] / https://TARGET 占位符直接拒收）
		const tplRes = await h.call("nuwa_commit", {
			free_note: true,
			kind: "note",
			title: "SQLi 盲注测试",
			command: "curl -sS https://TARGET/api/item?id=1",
			output: "delta=[BOOL_DELTA]B time=[TIME_DELTA]s",
		});
		expect(tplRes.details.error).toBe(true);
		expect(tplRes.content[0].text).toContain("模板化");

		// 4) #24 假阳性拦截（HTTP 200 + 微小错误壳 {"detail":"Not Found"} 阻断升格 vuln，支持 auto_downgrade 降级为 note）
		await h.call("nuwa_plan", { phase: "vuln" });
		const stVuln = nuwaMod.loadState(ws)!;
		const vulnIntent = Object.values(stVuln.intents).find((i) => i.phase === "vuln" && i.status === "open")!;
		await h.call("nuwa_claim", { id: vulnIntent.id });

		const fpBlocked = await h.call("nuwa_commit", {
			id: vulnIntent.id,
			kind: "vuln",
			title: "疑似中间件鉴权绕过",
			detail: "带 x-middleware-subrequest 返回 200",
			command: "curl -sS -i -H 'x-middleware-subrequest: pages/_middleware' http://app.demo.local:8080/api/v1/member/info",
			output: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"detail":"Not Found"}',
		});
		expect(fpBlocked.details.error).toBe(true);
		expect(fpBlocked.details.falsePositive).toBe(true);
		expect(fpBlocked.details.suggestedKind).toBe("note");

		const fpDowngraded = await h.call("nuwa_commit", {
			id: vulnIntent.id,
			kind: "vuln",
			title: "疑似中间件鉴权绕过",
			detail: "带 x-middleware-subrequest 返回 200",
			command: "curl -sS -i -H 'x-middleware-subrequest: pages/_middleware' http://app.demo.local:8080/api/v1/member/info",
			output: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"detail":"Not Found"}',
			auto_downgrade: true,
		});
		expect(fpDowngraded.details.error).toBeUndefined();
		expect(fpDowngraded.details.falsePositive).toBe(true);
		const stAfterFp = nuwaMod.loadState(ws)!;
		expect(Object.values(stAfterFp.facts).some((f) => f.kind === "vuln")).toBe(false);
		expect(
			Object.values(stAfterFp.facts).some(
				(f) => f.kind === "note" && (f.title.includes("false_positive") || f.title.includes("假阳性") || f.detail.includes("假阳性")),
			),
		).toBe(true);

		// 5) #49 blockedIntents vs blockedCommits 双计数回显
		await h.call("nuwa_claim", { id: "i002" });
		const blk1 = await h.call("nuwa_commit", { id: "i002", blocked: true, note: "边缘防火墙 403 阻断端口探测" });
		const blkFree = await h.call("nuwa_commit", { free_note: true, blocked: true, note: "免票据记录一次上游阻断" });
		expect(blk1.details.blockedIntents).toBe(1);
		expect(blk1.details.blockedCommits).toBe(1);
		expect(blkFree.details.blockedIntents).toBe(1);
		expect(blkFree.details.blockedCommits).toBe(2);
		expect(blkFree.content[0].text).toContain("blockedIntents=1");
		expect(blkFree.content[0].text).toContain("blockedCommits=2");
	});
});

describe("v5.1.0 nuwa_status / nuwa_report / nuwa_complete：零写入只读诊断、时间线归档、收敛建议与负向封盘", () => {
	test("只读诊断严格零磁盘写入、导出时间线与归档索引检索、complete 收敛提示及 sealed_negative 封盘终态", async () => {
		const ws = makeTmpWorkspace();
		const h = createMockHarness(ws, "sess-diag-seal-e2e");

		await h.call("nuwa_init", {
			target: "http://hardened.target.local:8080",
			mode: "ctf",
			goal: "获取 flag 或验证硬化封盘",
			root: ws,
		});
		await h.call("nuwa_claim", { id: "i001" });
		await h.call("nuwa_commit", {
			id: "i001",
			blocked: true,
			note: "全站静态化且后端管理面仅内网可达",
		});
		await h.runSlash("note service: Next.js 16.3.3 Turbopack :: Server Actions 数量为 0");

		// 1) 默认 nuwa_status 展示 repeat_ratio 与 last_ok
		const defStatus = await h.call("nuwa_status", {});
		expect(defStatus.content[0].text).toContain("repeat_ratio=");
		expect(defStatus.content[0].text).toContain("last_ok=");

		// 2) nuwa_report(format="timeline", episode=1, write=true) 生成时间线与 Episode 归档索引
		const repTl = await h.call("nuwa_report", { format: "timeline", episode: 1, write: true });
		expect(repTl.details.error).toBeUndefined();
		expect(existsSync(join(ws, ".nuwa/TIMELINE-E1.md"))).toBe(true);
		expect(existsSync(join(ws, ".nuwa/archive/episode-1.json"))).toBe(true);
		expect(existsSync(join(ws, ".nuwa/archive/episode-1.md"))).toBe(true);

		// 3) 校验 nuwa_status 只读诊断与归档检索严格零磁盘写入（文件内容哈希与 mtimeMs 零变化）
		const beforeSnap = snapshotTreeState(join(ws, ".nuwa"));
		await new Promise((r) => setTimeout(r, 15));

		const diagIntent = await h.call("nuwa_status", { inspect_intent: "i001", format: "json" });
		expect(diagIntent.details.readonly).toBe(true);
		expect(JSON.parse(diagIntent.content[0].text).intents[0].id).toBe("i001");

		const diagBlocked = await h.call("nuwa_status", { query_status: "blocked" });
		expect(diagBlocked.content[0].text).toContain("i001");

		const fullJson = await h.call("nuwa_status", { raw: true, offset: 0, limit: 20, format: "json" });
		const parsedFull = JSON.parse(fullJson.content[0].text);
		expect(parsedFull.pagination.raw).toBe(true);

		const archHits = await h.call("nuwa_status", { archive_query: "Turbopack" });
		expect(archHits.details.readonly).toBe(true);
		expect(archHits.details.archiveHits.length).toBeGreaterThanOrEqual(1);

		const afterSnap = snapshotTreeState(join(ws, ".nuwa"));
		expect(afterSnap).toEqual(beforeSnap);

		// 4) 无 flag 时调 nuwa_complete 被拒，自动返回 report_and_seal 策略收敛建议（#41）
		const compReject = await h.call("nuwa_complete", {});
		expect(compReject.details.ok).toBe(false);
		expect(compReject.details.rejects).toBe(1);
		expect(compReject.details.convergence.active).toBe(true);
		expect(compReject.details.convergence.recommendedAction).toBe("report_and_seal");
		expect(compReject.content[0].text).toContain("seal=true");

		// 5) 调用 nuwa_complete(seal=true, ...) 完成合法负向封盘（#22），session_stop 不再死循环续跑
		const sealedRes = await h.call("nuwa_complete", {
			seal: true,
			reason: "全部暴露路由与 RSC 端点已验证排除，注册面受短信与挑战门双重隔离",
			excluded_surface: ["/admin", "/api/v1/member/signup", "port:22"],
			coverage: { endpointsProbed: 15, portsProbed: 8 },
		});
		expect(sealedRes.details.ok).toBe(true);
		expect(sealedRes.details.status).toBe("sealed_negative");
		expect(sealedRes.details.sealMeta.excludedSurface).toContain("/admin");

		const onStop = h.hooks.get("session_stop")![0]!;
		const stopVerdict = await onStop({ session_id: "sess-diag-seal-e2e" }, h.ctx);
		expect(stopVerdict).toBeUndefined();
	});
});

describe("v5.1.0 nuwa_stop、斜杠命令、Hooks 守卫、进程组回收与工作区完整性校验", () => {
	test("软暂停/恢复、硬停机级联回收真实子进程组、内联脚本拦截 [layer=shell-guard]、空派单重排及 .git 丢失告警", async () => {
		const ws = makeTmpWorkspace();
		mkdirSync(join(ws, ".git"), { recursive: true });
		writeFileSync(join(ws, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");

		const h = createMockHarness(ws, "sess-hooks-guard-e2e");
		await h.call("nuwa_init", {
			target: "http://guard.target.local:8080",
			mode: "pentest",
			goal: "验证运行时守卫与斜杠子命令",
			root: ws,
		});

		// 1) before_subagent_spawn：空任务拒收并标记 requeue=true；正常任务自动注入 resolved_host 并启动看门狗
		const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
		const emptySpawn = onSpawn({ spawnId: "sp-empty", agent: "fujiang", task: "" }, h.ctx);
		expect(emptySpawn?.block).toBe(true);
		expect(emptySpawn?.requeue).toBe(true);

		const validEvent: Record<string, unknown> = {
			spawnId: "sp-valid-1",
			agent: "fujiang",
			task: "执行首轮探测 curl -sS https://TARGET/api/health",
		};
		const okSpawn = onSpawn(validEvent, h.ctx);
		expect(okSpawn?.spawnId).toBe("sp-valid-1");
		expect(String(validEvent.task)).toContain("resolved_host: guard.target.local");
		expect(String(validEvent.task)).not.toContain("https://TARGET");

		const wd = new nuwaMod.SubagentWatchdog(ws);
		expect(wd.getTask("sp-valid-1")?.status).toBe("running");

		// 2) tool_call(bash)：拦截 python3 -c 与 node -e 内联脚本越界请求并携带 [layer=shell-guard]（#48）
		const onToolCall = h.hooks.get("tool_call")![0]!;
		const subCtx: any = {
			...h.ctx,
			agent: { kind: "sub", id: "sp-valid-1", name: "fujiang", parentId: "main-0", depth: 1 },
		};
		const pyBlock = onToolCall(
			{
				toolName: "bash",
				input: { command: `python3 -c "import urllib.request; urllib.request.urlopen('https://api.github.com/zen')"` },
			},
			subCtx,
		);
		expect(pyBlock?.block).toBe(true);
		expect(pyBlock?.reason).toContain("N-007");
		expect(pyBlock?.reason).toContain("[layer=shell-guard]");

		const nodeBlock = onToolCall(
			{
				toolName: "bash",
				input: { command: `node -e "fetch('https://evil.outside.invalid/collect')"` },
			},
			subCtx,
		);
		expect(nodeBlock?.block).toBe(true);
		expect(nodeBlock?.reason).toContain("[layer=shell-guard]");

		// 3) 斜杠命令：/nuwa inspect、/nuwa query、/nuwa export、/nuwa pause、/nuwa resume
		h.notifications.length = 0;
		await h.runSlash("inspect i001");
		expect(h.notifications.at(-1)?.text).toContain("[只读诊断 i001]");

		await h.runSlash("query status=open");
		expect(h.notifications.at(-1)?.text).toContain("查询命中");

		await h.runSlash("export 1");
		expect(existsSync(join(ws, ".nuwa/TIMELINE-E1.md"))).toBe(true);

		// 4) nuwa_stop(pause=true) 免确认即时软暂停 -> session_stop 挂起 -> /nuwa resume 恢复
		const softPause = await h.call("nuwa_stop", { pause: true, reason: "等待操作员核验凭据" });
		expect(softPause.details.paused).toBe(true);
		expect(nuwaMod.isPausedState(ws)).toBe(true);

		const onStop = h.hooks.get("session_stop")![0]!;
		expect(await onStop({ session_id: "sess-hooks-guard-e2e" }, h.ctx)).toBeUndefined();

		await h.runSlash("resume");
		expect(nuwaMod.isPausedState(ws)).toBe(false);
		const resumedStop = await onStop({ session_id: "sess-hooks-guard-e2e" }, h.ctx);
		expect(resumedStop?.decision).toBe("block");

		// 5) 模拟工作区 .git 丢失，session_stop 自动检出 corrupted 并停止空转（#47）
		rmSync(join(ws, ".git"), { recursive: true, force: true });
		const corruptedStop = await onStop({ session_id: "sess-hooks-guard-e2e" }, h.ctx);
		expect(corruptedStop).toBeUndefined();
		expect(h.statuses.get("nuwa")).toContain("NUWA_GIT_METADATA_MISSING");

		// 恢复 .git 后验证 nuwa_stop(confirm="STOP") 级联清理真实登记的孤儿子进程组（#40）
		mkdirSync(join(ws, ".git"), { recursive: true });
		writeFileSync(join(ws, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");

		const child = spawn("sleep", ["30"], { detached: true, stdio: "ignore" });
		child.unref();
		const childPid = child.pid!;
		expect(childPid).toBeGreaterThan(1);

		const tracker = new nuwaMod.ProcessGroupTracker(ws);
		tracker.register({ pid: childPid, label: "chromeproxy-orphan-test" });
		expect(nuwaMod.pidAlive(childPid)).toBe(true);

		const hardStop = await h.call("nuwa_stop", { reason: "人工确认停机回收", confirm: "STOP" });
		expect(hardStop.details.stopped).toBe(true);
		expect(hardStop.details.cleanedProcesses).toBeGreaterThanOrEqual(1);
		expect(nuwaMod.isProcessAliveNonZombie(childPid)).toBe(false);

		// 6) 验证 /nuwa seal 斜杠命令终态收口
		await h.runSlash("seal 确认无残余风险封盘");
		const finalSt = nuwaMod.loadState(ws)!;
		expect(finalSt.project.status).toBe("sealed_negative");
	});
});
