import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
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
	test("VERSION 为 3.0.0 且严格保持 12 个注册工具", () => {
		expect(mod.VERSION).toBe("3.0.0");
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
});
