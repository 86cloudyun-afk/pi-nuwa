import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** 最小 zod 链式替身。 */
function chain(): any {
	const f: any = (..._args: any[]) => chain();
	return new Proxy(f, {
		get: () => (..._args: any[]) => chain(),
	});
}
const z: any = new Proxy({}, { get: () => (..._args: any[]) => chain() });

const dirs: string[] = [];
let AGENT_HOME = "";
let mod: typeof import("../omp/nuwa");
let reinMod: typeof import("../omp/reincarnate");

beforeAll(async () => {
	AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-v3-agent-"));
	dirs.push(AGENT_HOME);
	process.env.PI_AGENT_HOME = AGENT_HOME;
	process.env.NUWA_KB_DB = join(AGENT_HOME, "nuwa-kb", "kb.db");
	delete process.env.NUWA_PROJECT;
	delete process.env.NUWA_HEADLESS_DAEMON;
	delete process.env.NUWA_AUTO_ON_INIT;
	delete process.env.NUWA_SCANNER_GUARD;
	delete process.env.NUWA_STRICT_EVIDENCE;
	mod = await import("../omp/nuwa");
	reinMod = await import("../omp/reincarnate");
});

afterAll(() => {
	for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

function makeTempDir(prefix = "nuwa-v3-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	dirs.push(d);
	return d;
}

function setupExt(
	cwd: string,
	opts: {
		sessionId?: string;
		exec?: (cmd: string, args: string[], options?: any) => Promise<{ stdout: string; stderr: string; code: number; killed?: boolean }>;
		streamingUserMsg?: boolean;
		tokens?: number;
	} = {},
) {
	const tools = new Map<string, any>();
	const hooks = new Map<string, Array<(...args: any[]) => any>>();
	let command: any = null;
	const sentUser: string[] = [];
	const sentFollowUp: string[] = [];
	const notifications: string[] = [];

	const pi: any = {
		zod: z,
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (name: string, spec: any) => {
			command = { name, ...spec };
		},
		on: (name: string, fn: (...args: any[]) => any) => {
			const list = hooks.get(name) ?? [];
			list.push(fn);
			hooks.set(name, list);
		},
		sendUserMessage: (text: string) => {
			if (opts.streamingUserMsg) throw new Error("streaming busy");
			sentUser.push(text);
		},
		sendMessage: (msg: any) => {
			sentFollowUp.push(String(msg.content));
		},
	};
	if (opts.exec) {
		pi.exec = opts.exec;
	}

	mod.default(pi);

	const sid = opts.sessionId ?? "sess-v3";
	const ctx: any = {
		cwd,
		agent: { kind: "main", id: "main", name: "main", depth: 0 },
		sessionManager: { getSessionId: () => sid },
		isIdle: () => true,
		hasPendingMessages: () => false,
		getContextUsage: () => ({ tokens: opts.tokens ?? 2000, usedTokens: opts.tokens ?? 2000 }),
		ui: {
			setStatus() {},
			setWidget() {},
			setTitle() {},
			notify: (msg: string) => notifications.push(msg),
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
			custom: async () => undefined,
		},
	};

	const call = (name: string, args: any, customCtx = ctx) =>
		tools.get(name).execute("call-v3", args, undefined, undefined, customCtx);
	const runCmd = (argStr: string, customCtx = ctx) => command.handler(argStr, customCtx);

	return { pi, tools, hooks, ctx, call, runCmd, sentUser, sentFollowUp, notifications };
}

describe("v3.0 版本、工具红线、Profile 模式与开局防抢跑", () => {
	test("VERSION 为 4.0.1 且严格保持 12 个注册工具", () => {
		expect(mod.VERSION).toBe("4.0.1");
		const dir = makeTempDir();
		const { tools } = setupExt(dir);
		expect(tools.size).toBe(12);
	});

	test("nuwa_init 默认不抢跑 i001，显式 autoStart=true 且有 exec 时立即运行并同轮派生", async () => {
		const dir1 = makeTempDir();
		let execCount1 = 0;
		const h1 = setupExt(dir1, {
			sessionId: "sess-no-autostart",
			exec: async () => {
				execCount1 += 1;
				return { stdout: "", stderr: "", code: 0 };
			},
		});
		await h1.call("nuwa_init", { target: "127.0.0.1:18080", mode: "ctf" });
		expect(execCount1).toBe(0);
		// 老测试路径：init 后立即手动 claim i001 绝不报错
		const claim = await h1.call("nuwa_claim", { id: "i001" });
		expect(claim.details?.error).toBeUndefined();
		expect(claim.content[0].text).toContain("[女娲派单 i001]");

		// 显式 autoStart: true 时立即跑自动批，且 commit 后锁内同轮触发 deriveFromFacts
		const dir2 = makeTempDir();
		const h2 = setupExt(dir2, {
			sessionId: "sess-autostart",
			exec: async (_cmd, args) => {
				const script = String(args?.[1] ?? "");
				if (script.includes("FINAL") || script.includes("--max-time")) {
					return {
						stdout: [
							"FINAL 200 512 http://127.0.0.1:18080/",
							"---HEAD---",
							"HTTP/1.1 200 OK",
							"Server: nginx/1.24",
							"---BODY---",
							"<title>Local</title>",
						].join("\n"),
						stderr: "",
						code: 0,
					};
				}
				return { stdout: "open 8080\n8080/tcp open\n", stderr: "", code: 0 };
			},
		});
		await h2.call("nuwa_init", { target: "127.0.0.1:18080", mode: "ctf", autoStart: true });
		await Bun.sleep(80);
		const st2 = mod.loadState(dir2)!;
		expect(Object.keys(st2.facts).length).toBeGreaterThan(0);
		// 端口 8080 事实在自动批内同轮即派生 svc:<fid>:8080
		const hasDerivedSvc = Object.values(st2.intents).some((i) => i.key.includes(":8080") && i.key.startsWith("svc:"));
		expect(hasDerivedSvc).toBe(true);
	});

	test("支持 coding / ops 模式与 /nuwa scope 查看调整", async () => {
		const dir = makeTempDir();
		const { call, runCmd, notifications } = setupExt(dir, { sessionId: "sess-coding" });
		const initRes = await call("nuwa_init", {
			target: dir,
			mode: "coding",
			goal: "重构状态模块并跑通单测",
			scope: { allowSubdomains: false },
		});
		expect(initRes.content[0].text).toContain("coding");
		const st = mod.loadState(dir)!;
		expect(st.project.mode).toBe("coding");
		expect(st.project.scheme).toBe("local");

		await runCmd("scope");
		expect(notifications.at(-1)).toContain("Scope 策略");
		await runCmd("scope +host api.internal.local");
		expect(mod.loadState(dir)!.project.scope?.allowHosts).toContain("api.internal.local");
		await runCmd("scope subdomains on");
		expect(mod.loadState(dir)!.project.scope?.allowSubdomains).toBe(true);
	});
});

describe("二维空转闸 applyEmptyGuard（Issue #4）", () => {
	test("无工具活动 3 轮收口；有工具活动需满 5 轮才收口；新事实同时清零两者", () => {
		const cfg = { ...mod.readCfg(), emptyLimit: 3, suspectLimit: 5 };
		const st = mod.newState("127.0.0.1:8080", "test", "ctf", cfg);
		mod.seedPhase(st, "recon");
		st.runtime.lastFacts = 0;

		const i1 = st.intents.i001!;
		i1.status = "claimed";
		i1.worker = "fujiang";
		i1.claimedAt = new Date().toISOString();

		// 有工具活动前 4 轮不收口
		for (let r = 0; r < 4; r++) {
			expect(mod.applyEmptyGuard(st, cfg, true)).toEqual([]);
		}
		expect(st.runtime.suspectRounds).toBe(4);
		expect(st.runtime.emptyRounds).toBe(0);
		expect(i1.status).toBe("claimed");

		// 第 5 轮有工具无新事实触发疑似空转收口
		const closedSuspect = mod.applyEmptyGuard(st, cfg, true);
		expect(closedSuspect).toContain("i001");
		expect(i1.status).toBe("blocked");
		expect(i1.note).toContain("疑似空转");
		expect(st.runtime.suspectRounds).toBe(0);

		// 新认领 i002，测试混合计数后新 fact 归零
		const i2 = st.intents.i002!;
		i2.status = "claimed";
		i2.worker = "fujiang";
		i2.claimedAt = new Date().toISOString();

		mod.applyEmptyGuard(st, cfg, false);
		mod.applyEmptyGuard(st, cfg, true);
		expect(st.runtime.emptyRounds).toBe(1);
		expect(st.runtime.suspectRounds).toBe(1);

		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "HTTP 200",
			detail: "ok",
			createdAt: new Date().toISOString(),
		};
		expect(mod.applyEmptyGuard(st, cfg, false)).toEqual([]);
		expect(st.runtime.emptyRounds).toBe(0);
		expect(st.runtime.suspectRounds).toBe(0);
		expect(st.runtime.lastFacts).toBe(1);
	});
});

describe("结构化 meta 派生、network 退避不烧尝试数与 AbortController 取消（Issues #1/#3/#5）", () => {
	test("deriveFromFacts 优先消费 meta.ports / meta.paths / Scope 内 meta.san", () => {
		const cfg = mod.readCfg();
		const st = mod.newState("https://app.example.test:443", "test", "pentest", cfg, "", {
			allowHosts: ["app.example.test", "*.example.test"],
			allowSubdomains: true,
		});
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "TLS & Ports",
			detail: "open ports",
			createdAt: new Date().toISOString(),
			meta: {
				ports: [8080, 8443],
				san: ["api.example.test", "out-of-scope.other.org"],
			},
		};
		st.facts.f002 = {
			id: "f002",
			kind: "endpoint",
			title: "发现 2 条路径",
			detail: "dirs",
			createdAt: new Date().toISOString(),
			meta: {
				paths: ["/admin", "/api/v1"],
			},
		};

		const res = mod.deriveFromFacts(st);
		expect(res.rules).toContain("svc:f001:8080");
		expect(res.rules).toContain("svc:f001:8443");
		expect(res.rules).toContain("san:f001:api.example.test");
		expect(res.rules).not.toContain("san:f001:out-of-scope.other.org");
		expect(res.rules).toContain("ep:f002:/admin");
		expect(res.rules).toContain("ep:f002:/api/v1");
	});

	test("network 失败释放回 open、回退 attempts 不烧尝试数并设置 nextRunAt 与 netRetries", () => {
		const cfg = mod.readCfg();
		const st = mod.newState("127.0.0.1:8080", "test", "ctf", cfg);
		mod.seedPhase(st, "recon");
		const ids = mod.claimAutoBatch(st, cfg);
		const targetId = ids[0]!;
		expect(st.intents[targetId]!.attempts).toBe(1);

		const now = Date.now();
		const out = mod.applyAutoItemResult(
			st,
			targetId,
			{
				ok: false,
				error: "curl exit 28 Operation timed out",
				errorKind: "network",
				retryAfterMs: 60_000,
			},
			now,
		);
		expect(out.retried).toBe(true);
		expect(st.intents[targetId]!.status).toBe("open");
		expect(st.intents[targetId]!.attempts).toBe(0);
		expect(st.intents[targetId]!.nextRunAt).toBe(now + 60_000);
		expect(st.runtime.netRetries).toBe(1);

		// 冷却期内不再被 claimAutoBatch 或 frontierList 选中
		expect(mod.claimAutoBatch(st, cfg)).not.toContain(targetId);
		expect(mod.frontierList(st, 20, cfg.claimTtl).map((x) => x.intent.id)).not.toContain(targetId);

		// blocked_by_waf 标记 blocked 并派生绕过意图
		const wafId = ids[1]!;
		const wafOut = mod.applyAutoItemResult(st, wafId, {
			ok: false,
			error: "HTTP 403 cloudflare",
			errorKind: "blocked_by_waf",
			waf: "cloudflare",
		});
		expect(st.intents[wafId]!.status).toBe("blocked");
		expect(wafOut.wafBypassAdded.length).toBe(1);
	});

	test("nuwa_stop 立即 abort 在途自动批并将未完成意图释放回 open、记录 auto_aborted", async () => {
		const dir = makeTempDir();
		let abortedSignal = false;
		const h = setupExt(dir, {
			sessionId: "sess-abort",
			exec: async (_cmd, _args, options) => {
				await new Promise<void>((resolvePromise) => {
					const t = setTimeout(resolvePromise, 2_000);
					options?.signal?.addEventListener(
						"abort",
						() => {
							abortedSignal = true;
							clearTimeout(t);
							resolvePromise();
						},
						{ once: true },
					);
				});
				return { stdout: "", stderr: "aborted", code: 137, killed: true };
			},
		});

		await h.call("nuwa_init", { target: "127.0.0.1:18080", mode: "ctf", autoStart: true });
		await Bun.sleep(25);
		const stopRes = await h.call("nuwa_stop", { reason: "紧急人工停机", confirm: "STOP" });
		expect(stopRes.content[0].text).toContain("已停机");
		await Bun.sleep(40);

		const st = mod.loadState(dir)!;
		expect(st.project.status).toBe("stopped");
		const autoClaimed = Object.values(st.intents).filter((i) => i.status === "claimed" && i.worker === "auto");
		expect(autoClaimed.length).toBe(0);
		const journal = readFileSync(join(dir, ".nuwa/journal.jsonl"), "utf8");
		expect(journal).toContain("auto_aborted");
		if (abortedSignal) expect(abortedSignal).toBe(true);
	});
});

describe("容量治理：compactFacts、增量快照、2MB 告警与看板指标（Issue #8）", () => {
	test("compactFacts 按 key 去重重定向引用，并仅保留最近 200 条未引用 note", () => {
		const cfg = mod.readCfg();
		const st = mod.newState("127.0.0.1:8080", "test", "ctf", cfg);

		st.facts.f001 = { id: "f001", kind: "service", title: "svc1", detail: "d", key: "dup-key", createdAt: "2026-01-01T00:00:01Z" };
		st.facts.f002 = { id: "f002", kind: "service", title: "svc1-dup", detail: "d", key: "dup-key", createdAt: "2026-01-01T00:00:02Z" };
		st.facts.f003 = { id: "f003", kind: "note", title: "referenced-note", detail: "keep", createdAt: "2026-01-01T00:00:00Z" };

		st.intents.i001 = {
			id: "i001",
			phase: "recon",
			key: "k1",
			title: "t1",
			detail: "",
			from: ["f002", "f003"],
			to: "f002",
			status: "done",
			priority: 50,
			attempts: 1,
			createdAt: "2026-01-01T00:00:03Z",
		};

		for (let i = 1; i <= 250; i++) {
			const id = `f${String(i + 10).padStart(3, "0")}`;
			st.facts[id] = {
				id,
				kind: "note",
				title: `noise-${i}`,
				detail: "noise",
				createdAt: new Date(1_700_000_000_000 + i * 1000).toISOString(),
			};
		}

		const removed = mod.compactFacts(st, 200);
		expect(removed).toBe(51); // 1 条重复 key + 50 条超额未引用 note
		expect(st.facts.f002).toBeUndefined();
		expect(st.facts.f001).toBeDefined();
		expect(st.facts.f003).toBeDefined(); // 被引用 note 保留
		expect(st.intents.i001.from).toContain("f001");
		expect(st.intents.i001.to).toBe("f001");
		const unrefNotesLeft = Object.values(st.facts).filter((f) => f.kind === "note" && f.id !== "f003");
		expect(unrefNotesLeft.length).toBe(200);
	});

	test("saveState 仅在每 10 次或关键节点写 .json.gz 快照，超 2MB 记告警且 statusBoard 展示新指标", () => {
		const dir = makeTempDir();
		const cfg = mod.readCfg();
		const st = mod.newState("127.0.0.1:8080", "test", "ctf", cfg);
		const snapDir = join(dir, ".nuwa/snap");

		// 第 1..9 次普通 saveState 不生成 .json.gz
		for (let i = 1; i <= 9; i++) {
			mod.saveState(dir, st);
		}
		expect(existsSync(snapDir) ? readdirSync(snapDir).filter((f) => f.endsWith(".json.gz")).length : 0).toBe(0);

		// 第 10 次触发周期全量快照
		mod.saveState(dir, st);
		expect(readdirSync(snapDir).filter((f) => f.endsWith(".json.gz")).length).toBe(1);

		// 第 11 次传关键节点 reason: "flag" 立即写快照
		mod.saveState(dir, st, { reason: "flag" });
		expect(readdirSync(snapDir).filter((f) => f.endsWith(".json.gz")).length).toBe(2);

		// 构造 >2MB 状态触发容量告警
		st.facts.f999 = {
			id: "f999",
			kind: "loot",
			title: "big-blob",
			detail: "x".repeat(2_200_000),
			createdAt: new Date().toISOString(),
		};
		mod.saveState(dir, st);
		const journal = readFileSync(join(dir, ".nuwa/journal.jsonl"), "utf8");
		expect(journal).toContain("state_size_warn");

		st.runtime.netRetries = 3;
		st.runtime.generation = 2;
		const board = mod.statusBoard(st, dir);
		expect(board).toContain("state=");
		expect(board).toContain("KB");
		expect(board).toContain("rules=");
		expect(board).toContain("net-retry=3");
		expect(board).toContain("gen=2");
	});
});

describe("护栏开关 NUWA_SCANNER_GUARD=0、Scope 拦截与真实证据账本防幻觉（Bug 4 + 升级 3/4）", () => {
	test("NUWA_SCANNER_GUARD=0 动态放行主线程扫描，Scope 护栏拦越界 N-007 与高危 N-008", () => {
		const scope = {
			allowHosts: ["127.0.0.1"],
			allowCidrs: [],
			denyHosts: [],
			allowSubdomains: false,
			allowPrivateNetwork: true,
			allowDestructive: false,
		};
		expect(mod.checkBashPolicy("nmap -sV 127.0.0.1", true, true, scope, "ctf")?.reason).toContain("N-001");

		process.env.NUWA_SCANNER_GUARD = "0";
		try {
			expect(mod.checkBashPolicy("nmap -sV 127.0.0.1", true, true, scope, "ctf")).toBeNull();
			// 越界目标仍被 N-007 拦截
			const outOfScope = mod.checkBashPolicy("curl -sS http://evil.outside.example:8080/", true, true, scope, "ctf");
			expect(outOfScope?.block).toBe(true);
			expect(outOfScope?.reason).toContain("N-007");
			// 高危破坏命令被 N-008 拦截
			const destructive = mod.checkBashPolicy("rm -rf /", true, false, scope, "ctf");
			expect(destructive?.block).toBe(true);
			expect(destructive?.reason).toContain("N-008");
			// 篡改 .nuwa/state.json 被 N-003 拦截
			const tamper = mod.checkBashPolicy("rm -f .nuwa/state.json", true, false, scope, "ctf");
			expect(tamper?.block).toBe(true);
			expect(tamper?.reason).toContain("N-003");
		} finally {
			delete process.env.NUWA_SCANNER_GUARD;
		}
	});

	test("tool_execution_end 记录账本后拦截伪造 flag，放行真实回显 flag", async () => {
		const dir = makeTempDir();
		const { call, hooks, ctx } = setupExt(dir, { sessionId: "sess-evidence" });
		await call("nuwa_init", { target: "127.0.0.1:18080", mode: "ctf" });

		const onEnd = hooks.get("tool_execution_end")![0]!;
		onEnd(
			{
				toolName: "bash",
				input: { command: "curl -sS http://127.0.0.1:18080/flag.txt" },
				result: { stdout: "congrats: flag{real_verified_777}\n", stderr: "" },
			},
			ctx,
		);

		// 伪造从未出现在执行流中的假 flag 必须被拒
		const fakeRes = await call("nuwa_flag", {
			value: "flag{hallucinated_fake_999}",
			command: "curl -sS http://127.0.0.1:18080/flag.txt",
			output: "flag{hallucinated_fake_999}",
		});
		expect(fakeRes.details?.error).toBe(true);
		expect(fakeRes.content[0].text).toContain("证据复验未通过");

		// 真实出现在执行账本中的 flag 通过并标记 verified=true
		const realRes = await call("nuwa_flag", {
			value: "flag{real_verified_777}",
			command: "curl -sS http://127.0.0.1:18080/flag.txt",
			output: "congrats: flag{real_verified_777}",
		});
		expect(realRes.details?.error).toBeUndefined();
		expect(realRes.details?.verified).toBe(true);
		const st = mod.loadState(dir)!;
		expect(Object.values(st.facts)[0]?.verified).toBe(true);
	});
});

describe("多会话隔离 armPump、战略复盘与世代轮转放行（Bug 5 + 升级 1/2）", () => {
	test("多会话 armPump 按 sessionId 隔离且支持 sendMessage 回退", async () => {
		process.env.NUWA_TICK_MS = "60";
		try {
			const dirA = makeTempDir("nuwa-pump-a-");
			const dirB = makeTempDir("nuwa-pump-b-");
			const h = setupExt(dirA, { sessionId: "sess-pump-A", streamingUserMsg: true });

			const ctxB: any = {
				...h.ctx,
				cwd: dirB,
				sessionManager: { getSessionId: () => "sess-pump-B" },
			};

			await h.call("nuwa_init", { target: "127.0.0.1:18081", mode: "ctf" }, h.ctx);
			await h.call("nuwa_init", { target: "127.0.0.1:18082", mode: "ctf" }, ctxB);

			const onStart = h.hooks.get("session_start")![0]!;
			onStart({}, h.ctx);
			onStart({}, ctxB);

			await Bun.sleep(150);

			// 两个会话均被独立泵起推进，且因 streamingUserMsg=true 成功回退到 sendMessage
			expect(mod.loadState(dirA)!.runtime.turns).toBeGreaterThanOrEqual(1);
			expect(mod.loadState(dirB)!.runtime.turns).toBeGreaterThanOrEqual(1);
			expect(h.sentFollowUp.length).toBeGreaterThanOrEqual(2);

			// shutdown 清理避免后续干扰
			const onShutdown = h.hooks.get("session_shutdown")![0]!;
			onShutdown({}, h.ctx);
			onShutdown({}, ctxB);
		} finally {
			delete process.env.NUWA_TICK_MS;
		}
	});

	test("autoPlan 在 stall >= 3 时注入战略复盘 reflect 意图且同桶幂等", () => {
		const cfg = mod.readCfg();
		const st = mod.newState("127.0.0.1:8080", "test", "pentest", cfg);
		mod.seedPhase(st, "recon");
		st.runtime.stall = 3;

		const r1 = mod.autoPlan(st, cfg);
		expect(r1.reason).toBe("reflect");
		expect(r1.added.length).toBe(1);
		expect(st.intents[r1.added[0]!]!.key).toMatch(/^reflect:e1:recon:/);

		// 同一轮次桶再次规划不重复刷屏
		const r2 = mod.autoPlan(st, cfg);
		expect(r2.reason).toBe("frontier-live");
	});

	test("reincarnate 纯函数与 session_stop 换代交接放行", async () => {
		process.env.NUWA_HEADLESS_DAEMON = "1";
		process.env.NUWA_REINCARNATE_TOKENS = "100000";
		process.env.NUWA_REINCARNATE_TURNS = "5";
		try {
			const policy = reinMod.readReincarnatePolicy();
			expect(policy).toEqual({ headless: true, maxTokens: 100_000, maxTurns: 5 });

			// 填充大量事实，验证 buildHandoffSummary 严格 <= 1500 字符
			const st = mod.newState("127.0.0.1:8080", "深度渗透测试并拿取最终凭证", "pentest", mod.readCfg());
			mod.seedPhase(st, "recon");
			for (let i = 1; i <= 40; i++) {
				const fid = `f${String(i).padStart(3, "0")}`;
				st.facts[fid] = {
					id: fid,
					kind: i % 3 === 0 ? "vuln" : "service",
					title: `关键发现 #${i} ${"A".repeat(40)}`,
					detail: `详细证据描述 ${"B".repeat(100)}`,
					createdAt: new Date().toISOString(),
					verified: true,
				};
			}
			const summary = reinMod.buildHandoffSummary(st, "max_tokens");
			expect(summary.length).toBeLessThanOrEqual(1500);
			expect(summary).toContain("G1->G2");

			// 实测 session_stop 命中世代阈值时写 handoffSummary 并返回 undefined 放行退出
			const dir = makeTempDir("nuwa-rein-");
			const h = setupExt(dir, { sessionId: "sess-rein", tokens: 120_000 });
			await h.call("nuwa_init", { target: "127.0.0.1:18089", mode: "ctf" });

			const stopHook = h.hooks.get("session_stop")![0]!;
			const hookRes = await stopHook({ session_id: "sess-rein", stop_hook_active: true } as any, h.ctx);
			expect(hookRes).toBeUndefined();

			const saved = mod.loadState(dir)!;
			expect(saved.runtime.generation).toBe(2);
			expect(saved.runtime.genTurns).toBe(0);
			expect(saved.runtime.tokens).toBe(0);
			expect(saved.runtime.lastSig).toBe("");
			expect(saved.runtime.handoffSummary).toContain("[女娲世代交接 G1->G2]");
			expect(saved.project.status).toBe("active");

			const journal = readFileSync(join(dir, ".nuwa/journal.jsonl"), "utf8");
			expect(journal).toContain('"type":"reincarnate"');
		} finally {
			delete process.env.NUWA_HEADLESS_DAEMON;
			delete process.env.NUWA_REINCARNATE_TOKENS;
			delete process.env.NUWA_REINCARNATE_TURNS;
		}
	});

	test("reincarnate 命中时自动 abort 在途自动批并将僵尸 auto 认领释放回 open", async () => {
		process.env.NUWA_HEADLESS_DAEMON = "1";
		process.env.NUWA_REINCARNATE_TOKENS = "100000";
		try {
			const dir = makeTempDir("nuwa-rein-abort-");
			let signalAborted = false;
			const h = setupExt(dir, {
				sessionId: "sess-rein-abort",
				tokens: 150_000,
				exec: async (_cmd, _args, options) => {
					await new Promise<void>((res) => {
						const t = setTimeout(res, 2_000);
						options?.signal?.addEventListener(
							"abort",
							() => {
								signalAborted = true;
								clearTimeout(t);
								res();
							},
							{ once: true },
						);
					});
					return { stdout: "", stderr: "aborted", code: 137, killed: true };
				},
			});

			await h.call("nuwa_init", { target: "127.0.0.1:18090", mode: "ctf", autoStart: true });
			await Bun.sleep(20);
			// 确认此时有在途 auto 认领
			expect(
				Object.values(mod.loadState(dir)!.intents).some((i) => i.status === "claimed" && i.worker === "auto"),
			).toBe(true);

			const stopHook = h.hooks.get("session_stop")![0]!;
			const hookRes = await stopHook({ session_id: "sess-rein-abort", stop_hook_active: true } as any, h.ctx);
			expect(hookRes).toBeUndefined();
			await Bun.sleep(30);

			const after = mod.loadState(dir)!;
			expect(after.runtime.generation).toBe(2);
			// 所有在途 auto 认领均已释放回 open 且 attempts 回退为 0
			const zombieAuto = Object.values(after.intents).filter((i) => i.status === "claimed" && i.worker === "auto");
			expect(zombieAuto.length).toBe(0);
			if (signalAborted) expect(signalAborted).toBe(true);
		} finally {
			delete process.env.NUWA_HEADLESS_DAEMON;
			delete process.env.NUWA_REINCARNATE_TOKENS;
		}
	});

	test("nuwa_commit(kind=flag) 非 flag{...} 格式配中文标题不误拒，且并发自动批入账零丢失", async () => {
		const dir = makeTempDir("nuwa-commit-flag-");
		const h = setupExt(dir, {
			sessionId: "sess-commit-flag",
			exec: async (_cmd, args) => {
				await Bun.sleep(15);
				const script = String(args?.[1] ?? "");
				if (script.includes("FINAL")) {
					return {
						stdout: "FINAL 200 128 http://127.0.0.1:18091/\n---HEAD---\nHTTP/1.1 200 OK\nServer: Apache\n---BODY---\n<title>App</title>",
						stderr: "",
						code: 0,
					};
				}
				return { stdout: "", stderr: "", code: 1 };
			},
		});

		await h.call("nuwa_init", { target: "127.0.0.1:18091", mode: "ctf" });
		// 默认 Scope allowPrivateNetwork 与 scope.ts 对齐为 false
		expect(mod.loadState(dir)!.project.scope?.allowPrivateNetwork).toBe(false);

		// 记录一条非 flag{...} 格式（TOKEN=CTF{real_12345}）的真实执行输出
		const onEnd = h.hooks.get("tool_execution_end")![0]!;
		onEnd(
			{
				toolName: "bash",
				input: { command: "curl -sS http://127.0.0.1:18091/secret" },
				result: { stdout: "AUTH_OK TOKEN=CTF{real_12345}\n", stderr: "" },
			},
			h.ctx,
		);

		// 先手动认领非自动意图 i004 (recon:vhost)
		await h.call("nuwa_claim", { id: "i004" });

		// 模拟后台自动批已将新事实写入磁盘，测试 nuwa_commit 在锁内重读最新 state 不会覆盖丢失自动批事实
		mod.withLock(dir, () => {
			const latest = mod.loadState(dir)!;
			latest.facts.f099 = {
				id: "f099",
				kind: "service",
				title: "HTTP 200 Apache (auto)",
				detail: "concurrent auto fact",
				createdAt: new Date().toISOString(),
			};
			latest.seq.fact = 99;
			mod.saveState(dir, latest);
		});

		const commitRes = await h.call("nuwa_commit", {
			id: "i004",
			kind: "flag",
			title: "拿到目标真实凭据",
			detail: "从 /secret 接口获取令牌",
			command: "curl -sS http://127.0.0.1:18091/secret",
			output: "AUTH_OK TOKEN=CTF{real_12345}",
		});
		expect(commitRes.details?.error).toBeUndefined();
		expect(commitRes.content[0].text).toContain("已入账");

		const finalState = mod.loadState(dir)!;
		// 自动批提前写入的 f099 完好保留，未被锁外旧快照覆盖
		expect(finalState.facts.f099).toBeDefined();
		expect(Object.values(finalState.facts).some((f) => f.title === "拿到目标真实凭据" && f.verified === true)).toBe(true);
	});

	test("Issue #2 & #10：外置规则热更新、非法配置记录 autoexec_config_invalid 且不阻塞，并验证静态 ESM 与异步插件加载", async () => {
		const dir = makeTempDir("nuwa-rule-invalid-");
		const h = setupExt(dir, { sessionId: "sess-rule-invalid" });
		await h.call("nuwa_init", { target: "127.0.0.1:18092", mode: "ctf" });

		// 1. 不重启扩展，写入项目级合法 autoexec.json，看板实时体现 rules=project
		const cfgFile = join(dir, ".nuwa", "autoexec.json");
		writeFileSync(
			cfgFile,
			JSON.stringify({
				rules: [{ key: "surface:graphql_probe", phase: "surface", timeoutMs: 9000, parse: "probe", paths: ["/graphql"] }],
			}),
			"utf8",
		);
		const stRes1 = await h.call("nuwa_status", {});
		expect(stRes1.content[0].text).toContain("rules=project");

		// 2. 损坏 JSON 后不阻塞 nuwa_status，回退 builtin 且 journal 记录 autoexec_config_invalid
		writeFileSync(cfgFile, "{ bad json !!!", "utf8");
		const stRes2 = await h.call("nuwa_status", {});
		expect(stRes2.details?.error).toBeUndefined();
		expect(stRes2.content[0].text).toContain("rules=builtin");
		const journal = readFileSync(join(dir, ".nuwa", "journal.jsonl"), "utf8");
		expect(journal).toContain('"type":"autoexec_config_invalid"');

		// 3. 源码静态约束（Issue #10 根治）：不含 createRequire，无顶层 await import
		const nuwaSrc = readFileSync(join(import.meta.dir, "..", "omp", "nuwa.ts"), "utf8");
		expect(nuwaSrc).not.toContain("createRequire");
		expect(nuwaSrc).not.toMatch(/\bawait\s+import\s*\(/);
	});
});

describe("v4.0 全链路能力接线端到端验收（血缘路由 / 全工具护栏 / 纯净账本 / 会话仓 / 双盲复验 / 经验蒸馏 / SPA）", () => {
	test("before_subagent_spawn 动态模型分流 + 异构 subSessionId 子代理全工具护栏（N-007）与容器沙盒校验（N-009）", async () => {
		const dir = makeTempDir("nuwa-v4-lineage-");
		const h = setupExt(dir, { sessionId: "sess-v4-main" });
		await h.call("nuwa_init", { target: "http://127.0.0.1:18095", mode: "pentest" });

		process.env.NUWA_MODEL_FAST = "gemini-fast-v4";
		process.env.NUWA_MODEL_DEEP = "gemini-deep-v4";
		process.env.NUWA_MODEL_VERIFY = "gemini-verify-v4";
		try {
			const onSpawn = h.hooks.get("before_subagent_spawn")![0]!;
			const rFast = onSpawn({ agent: "fujiang", task: "recon probe" }, h.ctx);
			expect(rFast?.model).toBe("gemini-fast-v4");

			const rVerify = onSpawn({ agent: "nuwa-verifier", task: "verify-vuln:f001" }, h.ctx);
			expect(rVerify?.model).toBe("gemini-verify-v4");

			// 切换阶段到 vuln，验证常规 fujiang 路由到 deep 模型
			await h.call("nuwa_plan", { phase: "vuln" });
			const rDeep = onSpawn({ agent: "fujiang", task: "vuln check" }, h.ctx);
			expect(rDeep?.model).toBe("gemini-deep-v4");
		} finally {
			delete process.env.NUWA_MODEL_FAST;
			delete process.env.NUWA_MODEL_DEEP;
			delete process.env.NUWA_MODEL_VERIFY;
		}

		// 异构独立 subSessionId 的子代理在 tool_call 上强制生效 N-007 全工具面护栏
		const subCtx: any = {
			...h.ctx,
			agent: { kind: "sub", id: "sub-fujiang-1", name: "fujiang", parentId: "main", depth: 1 },
			sessionManager: { getSessionId: () => "sub-isolated-session-888" },
		};
		const onToolCall = h.hooks.get("tool_call")![0]!;
		expect(onToolCall({ toolName: "read", input: { path: "http://outside-evil.example.org/data" } }, subCtx)?.reason).toContain(
			"N-007",
		);
		expect(onToolCall({ toolName: "browser", input: { url: "https://outside-evil.example.org/" } }, subCtx)?.reason).toContain(
			"N-007",
		);
		expect(onToolCall({ toolName: "web_search", input: { query: "site:127.0.0.1 secret" } }, subCtx)?.reason).toContain(
			"N-007",
		);

		// task 允许 nuwa-verifier 子代理
		expect(onToolCall({ toolName: "task", input: { agent: "nuwa-verifier", task: "verify" } }, h.ctx)).toBeUndefined();

		// 启用 NUWA_SANDBOX=docker 时，子代理裸跑 bash 被 N-009 拦截并给出零信任容器包裹命令
		process.env.NUWA_SANDBOX = "docker";
		try {
			const sbBlock = onToolCall({ toolName: "bash", input: { command: "curl -sS http://127.0.0.1:18095/" } }, subCtx);
			expect(sbBlock?.block).toBe(true);
			expect(sbBlock?.reason).toContain("N-009");
			expect(sbBlock?.reason).toContain("--cap-drop=ALL");
			expect(sbBlock?.reason).toContain("--read-only");
		} finally {
			delete process.env.NUWA_SANDBOX;
		}
	});

	test("纯净证据账本屏蔽 task/eval 幻觉 + 子代理血缘入账 + 会话仓脱敏 + 双盲复验闭环 + 经验蒸馏回流", async () => {
		const dir = makeTempDir("nuwa-v4-e2e-");
		const h = setupExt(dir, { sessionId: "sess-v4-e2e-main" });
		await h.call("nuwa_init", { target: "http://127.0.0.1:18096", mode: "pentest" });

		// 1. 绑定子代理血缘，验证 task/eval 伪造回显绝不进入 exec-ledger.jsonl
		h.hooks.get("before_subagent_spawn")![0]!({ agent: "fujiang", task: "dispatch" }, h.ctx);
		const subCtx: any = {
			...h.ctx,
			agent: { kind: "sub", id: "sub-worker-9", name: "fujiang", parentId: "main", depth: 1 },
			sessionManager: { getSessionId: () => "sub-sess-ledger-999" },
		};
		const onEnd = h.hooks.get("tool_execution_end")![0]!;

		// 子代理先执行一条真实指纹命令，激活严格账本模式
		onEnd(
			{
				toolName: "bash",
				input: { command: "curl -sS -I http://127.0.0.1:18096/" },
				result: { stdout: "HTTP/1.1 200 OK\nServer: Spring-Boot/2.7\nSet-Cookie: sid=super_secret_token_99887766\n", stderr: "" },
			},
			subCtx,
		);
		// 主线程 task 返回伪造 flag 幻觉，必须被 isTrustedEvidenceEvent 丢弃
		onEnd(
			{
				toolName: "task",
				input: { agent: "fujiang", task: "find flag" },
				result: { output: "结论: 拿到 flag{fake_hallucinated_from_task}" },
			},
			h.ctx,
		);
		const fakeFlagRes = await h.call("nuwa_flag", {
			value: "flag{fake_hallucinated_from_task}",
			command: "curl http://127.0.0.1:18096/flag",
			output: "flag{fake_hallucinated_from_task}",
		});
		expect(fakeFlagRes.details?.error).toBe(true);

		// 2. 提交 service（Spring）与 cred（自动收纳进 Session Vault 并全量脱敏落盘）
		await h.call("nuwa_claim", { id: "i001" });
		await h.call("nuwa_commit", {
			id: "i001",
			kind: "service",
			title: "HTTP 200 Spring-Boot",
			detail: "框架: spring boot 2.7",
			command: "curl -sS -I http://127.0.0.1:18096/",
			output: "HTTP/1.1 200 OK\nServer: Spring-Boot/2.7",
		});

		await h.call("nuwa_plan", { phase: "surface" });
		const stSurface = mod.loadState(dir)!;
		const authIntent = Object.values(stSurface.intents).find((i) => i.key === "surface:auth")!;
		await h.call("nuwa_claim", { id: authIntent.id });
		const credCommit = await h.call("nuwa_commit", {
			id: authIntent.id,
			kind: "cred",
			title: "登录获取 admin 会话",
			detail: "role: admin, Cookie: sid=super_secret_token_99887766",
			command: "curl -sS -I http://127.0.0.1:18096/",
			output: "HTTP/1.1 200 OK\nSet-Cookie: sid=super_secret_token_99887766",
		});
		expect(credCommit.details?.error).toBeUndefined();
		expect(credCommit.details?.role).toBe("admin");
		// state.json 中绝不残留明文 Cookie secret
		const rawStateText = readFileSync(join(dir, ".nuwa", "state.json"), "utf8");
		expect(rawStateText).not.toContain("super_secret_token_99887766");

		// /nuwa session list 与 /nuwa doctor 正常工作
		await h.runCmd("session list");
		expect(h.notifications.at(-1)).toContain("role=admin");
		expect(h.notifications.at(-1)).not.toContain("super_secret_token_99887766");
		await h.runCmd("doctor");
		expect(h.notifications.at(-1)).toContain("便携知识库: READY");

		// 3. nuwa_claim 对 vuln:idor 自动注入零明文多角色鉴权差分指引
		await h.call("nuwa_plan", { phase: "vuln" });
		const stVuln = mod.loadState(dir)!;
		const idorIntent = Object.values(stVuln.intents).find((i) => i.key === "vuln:idor")!;
		const idorClaim = await h.call("nuwa_claim", { id: idorIntent.id });
		expect(idorClaim.content[0].text).toContain("[多角色会话差分重放指引");
		expect(idorClaim.content[0].text).not.toContain("super_secret_token_99887766");

		// 4. 提交 vuln 进入 candidate 状态，自动派生 verify-vuln:<fid>，且 nuwa_complete 阻止未复验结案
		onEnd(
			{
				toolName: "bash",
				input: { command: "curl -sS http://127.0.0.1:18096/api/user/2" },
				result: { stdout: '{"uid":2,"role":"other_user","email":"b@local.test"}', stderr: "" },
			},
			subCtx,
		);
		const vulnCommit = await h.call("nuwa_commit", {
			id: idorIntent.id,
			kind: "vuln",
			title: "IDOR 越权读取他人资料",
			detail: "低权限访问 uid=2 返回敏感字段",
			command: "curl -sS http://127.0.0.1:18096/api/user/2",
			output: '{"uid":2,"role":"other_user","email":"b@local.test"}',
		});
		expect(vulnCommit.details?.verifyStage).toBe("candidate");
		const verifyIntentId = String(vulnCommit.details?.verifyIntent ?? "");
		expect(verifyIntentId).toMatch(/^i\d{3}$/);

		// 看板显示 cand=1 与 roles=1
		const boardMid = (await h.call("nuwa_status", {})).content[0].text;
		expect(boardMid).toContain("cand=1");
		expect(boardMid).toContain("roles=1");
		expect(boardMid).toContain("kb=ready");

		// 仅凭 candidate 漏洞调用 nuwa_complete 必须被拒收
		const earlyDone = await h.call("nuwa_complete", {});
		expect(earlyDone.details?.ok).toBe(false);
		expect(earlyDone.content[0].text).toContain("candidate");

		// 5. 独立复验通过 -> 升格 confirmed -> nuwa_complete 成功验收并蒸馏脱敏经验入 kb.db
		await h.call("nuwa_claim", { id: verifyIntentId, worker: "nuwa-verifier" });
		onEnd(
			{
				toolName: "bash",
				input: { command: "curl -sS -w '%{http_code}' http://127.0.0.1:18096/api/user/2" },
				result: { stdout: 'anon=401 vs user=200 {"uid":2,"role":"other_user"}', stderr: "" },
			},
			subCtx,
		);
		const verifyCommit = await h.call("nuwa_commit", {
			id: verifyIntentId,
			kind: "vuln",
			title: "复验确认 IDOR 正负对照成立",
			detail: "匿名返回 401，普通会话越权返回 200",
			command: "curl -sS -w '%{http_code}' http://127.0.0.1:18096/api/user/2",
			output: 'anon=401 vs user=200 {"uid":2,"role":"other_user"}',
		});
		expect(verifyCommit.details?.verifyStage).toBe("confirmed");

		const finalDone = await h.call("nuwa_complete", {});
		expect(finalDone.details?.ok).toBe(true);
		expect(Number(finalDone.details?.distilled ?? 0)).toBeGreaterThan(0);
	});

	test("本地 127.0.0.1 随机端口 SPA 表面路由工作流：/nuwa spa 提取 JS Bundle 接口并自动入账派生", async () => {
		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req) {
				const u = new URL(req.url);
				if (u.pathname === "/assets/main.a1b2c3d4.js") {
					return new Response(
						`const api = () => fetch("/api/v2/orders?page=1"); const gql = () => axios.post("/graphql", { operationName: "ListUsers" });`,
						{ headers: { "content-type": "application/javascript" } },
					);
				}
				return new Response(
					`<!doctype html><html><head><title>SPA App</title></head><body><div id="root" data-reactroot></div><script src="/assets/main.a1b2c3d4.js"></script></body></html>`,
					{ headers: { "content-type": "text/html" } },
				);
			},
		});
		try {
			const dir = makeTempDir("nuwa-v4-spa-");
			const h = setupExt(dir, { sessionId: "sess-v4-spa" });
			await h.call("nuwa_init", { target: `http://127.0.0.1:${srv.port}`, mode: "pentest" });
			process.env.NUWA_SPA_MODE = "static";
			try {
				await h.runCmd("spa");
			} finally {
				delete process.env.NUWA_SPA_MODE;
			}
			expect(h.notifications.at(-1)).toContain("SPA 表面感知完成");
			const st = mod.loadState(dir)!;
			const epFact = Object.values(st.facts).find((f) => f.kind === "endpoint" && (f.meta?.paths ?? []).includes("/api/v2/orders"));
			expect(epFact).toBeDefined();
			expect(Object.values(st.intents).some((i) => i.key.includes("/api/v2/orders"))).toBe(true);
		} finally {
			srv.stop(true);
		}
	});
});
