/**
 * 女娲 v5.0 回归测试（下）：多资产拓扑与假设图推理（Issue #18）+ 离线评测/SARIF/成本封顶/Webhook（Issue #19）。
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdtempSync,
	mkdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import * as http from "node:http";
import * as net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import * as mod from "../omp/nuwa";
import {
	ensurePrimaryAsset,
	formatAssetTopology,
	propagateFactRejection,
	scoreHypothesisPriority,
	syncAssetsFromFacts,
	synthesizeCrossFactHypotheses,
	upsertAssetNode,
} from "../omp/hypothesis";
import { buildProfileFallbackIntent, deriveProfileIntents, isLocalAuditProject } from "../omp/profiles";
import {
	buildJsonReport,
	buildSarifReport,
	inferFindingRuleMeta,
	renderStratifiedMarkdownReport,
	writePocBundle,
} from "../omp/reporting";
import { recordToolExecution } from "../omp/evidence";
import { upsertSessionRole } from "../omp/session-vault";

const REPO_ROOT = resolve(import.meta.dir, "..");
const DAEMON_BIN = join(REPO_ROOT, "bin", "nuwa-autonomous");
const BENCH_SCRIPT = join(REPO_ROOT, "benchmarks", "run-eval.ts");

/** 异步启动子进程，避免阻塞当前测试进程内的本地 HTTP Webhook 服务器事件循环 */
function spawnAsync(
	cmd: string,
	args: string[],
	opts: { encoding?: BufferEncoding; env?: NodeJS.ProcessEnv; cwd?: string } = {},
): Promise<{ status: number | null; stdout: string; stderr: string }> {
	return new Promise((resolvePromise, rejectPromise) => {
		const child = spawn(cmd, args, {
			cwd: opts.cwd,
			env: opts.env,
			stdio: ["ignore", "pipe", "pipe"],
		});
		const outChunks: Buffer[] = [];
		const errChunks: Buffer[] = [];
		child.stdout?.on("data", (c) => outChunks.push(Buffer.from(c)));
		child.stderr?.on("data", (c) => errChunks.push(Buffer.from(c)));
		child.on("error", rejectPromise);
		child.on("close", (code) => {
			resolvePromise({
				status: code,
				stdout: Buffer.concat(outChunks).toString(opts.encoding ?? "utf8"),
				stderr: Buffer.concat(errChunks).toString(opts.encoding ?? "utf8"),
			});
		});
	});
}

const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-v5-suite-b-"));
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
process.env.NUWA_KB_DB = join(SUITE_AGENT_HOME, "nuwa-kb", "kb.db");

const tmpDirs: string[] = [];
const cleanups: Array<() => Promise<void> | void> = [];

function makeTmpDir(prefix = "nuwa-v5b-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(d);
	return d;
}

function setupExt(cwd: string, sessionId = "sess-v5b-main") {
	const tools = new Map<string, any>();
	let cmdHandler: ((args: string, ctx: any) => Promise<void>) | null = null;
	const notifications: Array<{ text: string; level: string }> = [];

	const chain = (): any => new Proxy(() => chain(), { get: () => () => chain() });
	const z = new Proxy({}, { get: () => () => chain() });

	mod.default({
		zod: z,
		registerTool: (t: any) => tools.set(t.name, t),
		registerCommand: (_name: string, def: any) => {
			cmdHandler = def.handler;
		},
		on: () => {},
		sendUserMessage: () => {},
		sendMessage: () => {},
	} as any);

	const ctx = {
		cwd,
		agent: { kind: "main", id: "agent-main" },
		sessionManager: { getSessionId: () => sessionId },
		ui: {
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
			setStatus: () => {},
			setWidget: () => {},
			setTitle: () => {},
			notify: (t: string, level = "info") => notifications.push({ text: t, level }),
		},
	};

	return {
		notifications,
		callTool: (name: string, params: Record<string, unknown>) =>
			tools.get(name).execute("call-1", params, undefined, undefined, ctx),
		runCmd: (args: string) => cmdHandler!(args, ctx),
	};
}

afterEach(async () => {
	while (cleanups.length > 0) {
		const fn = cleanups.pop()!;
		try {
			await fn();
		} catch {
			/* ignore */
		}
	}
	while (tmpDirs.length > 0) {
		const d = tmpDirs.pop()!;
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

afterAll(() => {
	rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
});

describe("Issue #18: 多资产拓扑、跨事实假设图推理、证伪剪枝与本地白盒 Audit / Profile 解耦", () => {
	test("多资产拓扑同步、5 类跨事实假设推理与收益/成本评分排序", async () => {
		const root = makeTmpDir();
		const st = mod.newState("http://app.corp.test:8080", "多资产评估", "pentest", mod.readCfg(), "s1");
		st.project.scope = {
			allowHosts: ["app.corp.test", "api.corp.test"],
			allowCidrs: ["10.20.0.0/16"],
			denyHosts: [],
			allowSubdomains: true,
			allowPrivateNetwork: true,
			allowLoopback: false,
			allowDestructive: false,
		};
		const primary = ensurePrimaryAsset(st);
		expect(primary.host).toBe("app.corp.test");

		// 注入跨事实推理所需的各类事实（认证态 + 对象端点 + 凭据 + 管理面 + SSRF + 内网主机 + 源码汇点 + 非HTTP服务）
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "TLS 证书与非 HTTP 服务发现",
			detail: "DNS:api.corp.test 开放 Redis 6379 与 Spring Boot",
			command: "nmap -sV app.corp.test",
			output: "6379/tcp open redis 7.0\nDNS:api.corp.test",
			key: "svc:1",
			createdAt: mod.nowIso(),
			meta: { san: ["api.corp.test"], ports: [8080, 6379], tech: ["redis", "spring"] },
		};
		st.facts.f002 = {
			id: "f002",
			kind: "cred",
			title: "普通用户 Session 凭据入库",
			detail: "已获取 user_a Bearer session 凭据与管理员候选口令",
			command: "curl -sS http://app.corp.test:8080/login",
			output: "role=user_a session ok",
			key: "cred:1",
			createdAt: mod.nowIso(),
		};
		st.facts.f003 = {
			id: "f003",
			kind: "endpoint",
			title: "业务对象与管理端点",
			detail: "发现 /api/orders/1001 与 /admin/dashboard 接口",
			command: "curl -sS http://app.corp.test:8080/api",
			output: "/api/orders/1001 /admin/dashboard",
			key: "ep:1",
			createdAt: mod.nowIso(),
			meta: { paths: ["/api/orders/1001", "/admin/dashboard"] },
		};
		st.facts.f004 = {
			id: "f004",
			kind: "vuln",
			title: "URL 抓取接口存在 SSRF 线索",
			detail: "服务端代理请求可访问内网 10.20.5.12:8080",
			command: "curl -sS http://app.corp.test:8080/fetch",
			output: "upstream 10.20.5.12:8080 reachable",
			key: "vuln:ssrf",
			createdAt: mod.nowIso(),
			verifyStage: "confirmed",
			verified: true,
		};
		st.facts.f005 = {
			id: "f005",
			kind: "loot",
			title: "内网主机清单与源码审计汇点",
			detail: "发现内网跳板主机 10.20.5.12 以及源码文件 src/controller/OrderController.java 存在 SQL sink 拼接线索",
			command: "rg -n query src/",
			output: "10.20.5.12\nsrc/controller/OrderController.java:42 executeQuery",
			key: "loot:1",
			createdAt: mod.nowIso(),
		};

		const synced = syncAssetsFromFacts(st);
		expect(synced.length).toBeGreaterThanOrEqual(2);
		const topo = formatAssetTopology(st);
		expect(topo).toContain("app.corp.test");
		expect(topo).toContain("api.corp.test");
		expect(topo).toContain("10.20.5.12");

		// 显式 upsert 跳板资产验证
		const pivot = upsertAssetNode(st, {
			host: "10.20.5.99",
			kind: "pivot",
			port: 5432,
			reachableVia: [primary.id],
		});
		expect(pivot.reachableVia).toContain(primary.id);

		// 收益/成本评分单调性
		const highScore = scoreHypothesisPriority({ expectedGain: 92, estimatedCost: 8, confidence: 0.9 });
		const lowScore = scoreHypothesisPriority({ expectedGain: 45, estimatedCost: 35, confidence: 0.4 });
		expect(highScore).toBeGreaterThan(lowScore);

		// 跨事实假设推理覆盖多类链路
		const synth = synthesizeCrossFactHypotheses(st, 12);
		expect(synth.hypotheses.length).toBeGreaterThanOrEqual(4);
		expect(synth.intents.length).toBe(synth.hypotheses.length);
		const hypKeys = synth.intents.map((i) => i.key);
		expect(hypKeys.some((k) => k.startsWith("hyp:auth-priv:"))).toBe(true);
		expect(hypKeys.some((k) => k.startsWith("hyp:ssrf-internal:"))).toBe(true);
		expect(hypKeys.some((k) => k.startsWith("hyp:greybox:"))).toBe(true);
		expect(hypKeys.some((k) => k.startsWith("hyp:svc-cve:"))).toBe(true);

		// /nuwa assets 命令展示拓扑与假设图
		mod.saveState(root, st, { reason: "init" });
		const ext = setupExt(root, "s1");
		await ext.runCmd("assets");
		expect(ext.notifications.some((n) => n.text.includes("主机/目标") && n.text.includes("跨事实假设图"))).toBe(true);
	});

	test("双盲驳回触发 propagateFactRejection 级联失效假设并剪枝 open 意图（不触碰 done/claimed/无关意图）", async () => {
		const root = makeTmpDir();
		const ext = setupExt(root);
		await ext.callTool("nuwa_init", { target: "http://127.0.0.1:19090", mode: "pentest", root, autoStart: false });

		const st0 = mod.loadState(root)!;
		const i001 = Object.keys(st0.intents)[0]!;
		await ext.callTool("nuwa_claim", { id: i001, root });

		// 提交候选漏洞 f001 -> 自动派生 verify-vuln:f001
		recordToolExecution(root, {
			tool: "bash",
			command: "curl -sS http://127.0.0.1:19090/search?q=test",
			output: "suspect reflection marker_unique_9911",
		});
		await ext.callTool("nuwa_commit", {
			id: i001,
			kind: "vuln",
			title: "疑似反射型异常",
			detail: "初步命中可疑回显",
			command: "curl -sS http://127.0.0.1:19090/search?q=test",
			output: "suspect reflection marker_unique_9911",
			root,
		});

		const st1 = mod.loadState(root)!;
		const candFact = Object.values(st1.facts).find((f) => f.kind === "vuln" && f.verifyStage === "candidate")!;
		const verifyIntent = Object.values(st1.intents).find((i) => i.key === `verify-vuln:${candFact.id}`)!;
		expect(candFact).toBeDefined();
		expect(verifyIntent).toBeDefined();

		// 挂接依赖 candFact 的假设节点、open 意图、done 意图与无关意图
		st1.hypotheses = {
			h001: {
				id: "h001",
				title: "基于候选漏洞的深挖假设",
				rationale: "若候选漏洞成立则继续验证链条",
				requiredFacts: [candFact.id],
				expectedGain: 80,
				estimatedCost: 10,
				confidence: 0.7,
				status: "open",
				createdAt: mod.nowIso(),
				updatedAt: mod.nowIso(),
			},
		};
		const depOpen = mod.addIntent(st1, {
			title: "依赖候选漏洞的 open 意图",
			detail: "测试剪枝",
			phase: "exploit",
			priority: 80,
			from: [candFact.id],
			key: "dep:open:1",
		});
		depOpen.hypothesisId = "h001";
		const depDone = mod.addIntent(st1, {
			title: "依赖候选漏洞的 done 意图",
			detail: "不应被改写",
			phase: "recon",
			priority: 50,
			from: [candFact.id],
			key: "dep:done:1",
		});
		depDone.status = "done";
		const unrelated = mod.addIntent(st1, {
			title: "无关的 open 意图",
			detail: "保持 open",
			phase: "recon",
			priority: 60,
			key: "unrelated:open:1",
		});
		mod.saveState(root, st1);

		// 认领 verify-vuln 并以 blocked=true 驳回 -> 自动级联失效 h001 并剪枝 depOpen
		await ext.callTool("nuwa_claim", { id: verifyIntent.id, root });
		await ext.callTool("nuwa_commit", {
			id: verifyIntent.id,
			blocked: true,
			note: "正负对照复验均为 HTML 实体转义，确认为误报",
			root,
		});

		const st2 = mod.loadState(root)!;
		expect(st2.facts[candFact.id]?.verifyStage).toBe("rejected");
		expect(st2.hypotheses?.h001?.status).toBe("invalidated");
		expect(st2.intents[depOpen.id]?.status).toBe("blocked");
		expect(st2.intents[depOpen.id]?.invalidatedReason).toContain("误报");
		expect(st2.intents[depDone.id]?.status).toBe("done");
		expect(st2.intents[unrelated.id]?.status).toBe("open");

		// 直接调用纯函数幂等性验证
		const again = propagateFactRejection(st2, candFact.id, "重复调用");
		expect(again.invalidatedHypotheses).toEqual([]);
		expect(again.invalidatedIntents).toEqual([]);
	});

	test("本地白盒 Audit 与 Coding/Ops Profile 派生完全解耦（零渗透扫描器污染）", async () => {
		const repoDir = makeTmpDir("nuwa-local-audit-");
		writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "demo-svc", version: "1.0.0" }));
		mkdirSync(join(repoDir, "src"), { recursive: true });
		writeFileSync(join(repoDir, "src", "server.ts"), "export function handler() { return 'ok'; }\n");

		const ext = setupExt(repoDir);
		await ext.callTool("nuwa_init", { target: repoDir, mode: "audit", goal: "本地源码安全审计", root: repoDir, autoStart: false });
		const st = mod.loadState(repoDir)!;
		expect(st.project.mode).toBe("audit");
		expect(st.project.scheme).toBe("local");
		expect(isLocalAuditProject(st)).toBe(true);

		// 添加 fact 后派生与兜底均不得包含 Web 扫描器命令（nmap/ffuf/gobuster/sqlmap/curl http）
		st.facts.f001 = {
			id: "f001",
			kind: "note",
			title: "发现 2 个业务路由处理器",
			detail: "src/server.ts 存在用户输入处理逻辑",
			command: "rg -n handler src/",
			output: "src/server.ts:1:export function handler()",
			key: "audit:f1",
			createdAt: mod.nowIso(),
		};
		const derived = deriveProfileIntents(st, st.facts.f001);
		expect(derived.length).toBeGreaterThanOrEqual(1);
		const fb = buildProfileFallbackIntent(st, 1);
		const combined = `${JSON.stringify(Object.values(st.intents))}\n${JSON.stringify(derived)}\n${JSON.stringify(fb)}`;
		expect(combined).not.toMatch(/\b(nmap|ffuf|gobuster|sqlmap|hydra)\b/i);

		// coding 模式同理零扫描器污染
		const codingDir = makeTmpDir("nuwa-coding-");
		const stCode = mod.newState(codingDir, "实现并验证新特性", "coding", mod.readCfg(), "s-code");
		stCode.facts.f001 = {
			id: "f001",
			kind: "note",
			title: "测试套件运行失败",
			detail: "unit test failed on parser.ts",
			command: "bun test",
			output: "1 fail in parser.ts",
			key: "code:f1",
			createdAt: mod.nowIso(),
		};
		mod.deriveFromFacts(stCode);
		const codeFb = buildProfileFallbackIntent(stCode, 1);
		const codeText = `${JSON.stringify(Object.values(stCode.intents))}\n${JSON.stringify(codeFb)}`;
		expect(codeText).not.toMatch(/\b(nmap|ffuf|gobuster|sqlmap|hydra)\b/i);
	});
});

describe("Issue #19: SARIF 2.1.0 / 脱敏证据包 / 守护器成本封顶与脱敏 Webhook / 离线评测靶场", () => {
	test("SARIF 2.1.0 仅含已确认漏洞、PoC 证据包 0o600 + SHA-256 清单且全链路零凭据泄露", async () => {
		const root = makeTmpDir();
		const vaultSecret = "BearerVerySensitiveProdToken_9988776655";
		upsertSessionRole(root, { role: "admin", bearer: vaultSecret });

		const ext = setupExt(root);
		await ext.callTool("nuwa_init", { target: "http://127.0.0.1:18888", mode: "pentest", root, autoStart: false });
		const st = mod.loadState(root)!;

		st.facts.f001 = {
			id: "f001",
			kind: "vuln",
			title: "订单接口水平越权 BOLA",
			detail: `跨角色访问 /api/orders/1001 成功，凭证 ${vaultSecret} 已复现`,
			command: `curl -H "Authorization: Bearer ${vaultSecret}" http://127.0.0.1:18888/api/orders/1001`,
			output: `{"orderId":1001,"owner":"alice","tokenEcho":"${vaultSecret}"}`,
			key: "v:bola",
			createdAt: mod.nowIso(),
			verified: true,
			verifyStage: "confirmed",
		};
		st.facts.f002 = {
			id: "f002",
			kind: "vuln",
			title: "未复验候选 SSRF",
			detail: "尚未双盲确认",
			command: "curl http://127.0.0.1:18888/proxy",
			output: "candidate output",
			key: "v:cand",
			createdAt: mod.nowIso(),
			verified: false,
			verifyStage: "candidate",
		};
		st.facts.f003 = {
			id: "f003",
			kind: "vuln",
			title: "已驳回误报 XSS",
			detail: "已证伪",
			command: "curl http://127.0.0.1:18888/q",
			output: "escaped output",
			key: "v:rej",
			createdAt: mod.nowIso(),
			verified: false,
			verifyStage: "rejected",
		};
		mod.saveState(root, st);

		expect(inferFindingRuleMeta(st.facts.f001).ruleId).toBe("NUWA-BOLA");
		expect(inferFindingRuleMeta(st.facts.f001).cwe).toBe("CWE-639");

		const sarif = buildSarifReport(st, root);
		expect(sarif.version).toBe("2.1.0");
		expect(sarif.runs[0].results.length).toBe(1);
		expect(sarif.runs[0].results[0].ruleId).toBe("NUWA-BOLA");
		expect(JSON.stringify(sarif)).not.toContain(vaultSecret);

		const jsonRep = buildJsonReport(st, root);
		expect(JSON.stringify(jsonRep)).not.toContain(vaultSecret);

		const md = renderStratifiedMarkdownReport(st, root);
		expect(md).toContain("## 漏洞");
		expect(md).toContain("NUWA-BOLA (CWE-639)");
		expect(md).toContain("待复验候选漏洞");
		expect(md).toContain("已驳回误报");
		expect(md).not.toContain(vaultSecret);

		// nuwa_report(format="sarif", write=true, bundle=true) 集成验证
		const repRes = await ext.callTool("nuwa_report", { format: "sarif", write: true, bundle: true, root });
		expect(repRes.details.format).toBe("sarif");
		expect(existsSync(join(root, ".nuwa", "REPORT.sarif.json"))).toBe(true);

		const bundleDir = join(root, ".nuwa", "poc-bundle");
		expect(existsSync(bundleDir)).toBe(true);
		expect(statSync(bundleDir).mode & 0o777).toBe(0o700);
		const manifestPath = join(bundleDir, "manifest.json");
		expect(statSync(manifestPath).mode & 0o777).toBe(0o600);
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		expect(manifest.confirmedCount).toBe(1);
		expect(JSON.stringify(manifest)).not.toContain(vaultSecret);

		// 逐文件核验 SHA-256 摘要
		for (const entry of manifest.files) {
			const fp = join(bundleDir, entry.name);
			expect(existsSync(fp)).toBe(true);
			const raw = readFileSync(fp);
			const digest = createHash("sha256").update(raw).digest("hex");
			expect(digest).toBe(entry.sha256);
			expect(raw.toString("utf8")).not.toContain(vaultSecret);
		}

		// /nuwa report sarif|json|bundle 命令测试
		await ext.runCmd("report json");
		expect(existsSync(join(root, ".nuwa", "REPORT.json"))).toBe(true);
		await ext.runCmd("report bundle");
		expect(ext.notifications.some((n) => n.text.includes("脱敏证据包"))).toBe(true);
		expect(writePocBundle(root, st).confirmedCount).toBe(1);
	});

	test("无头守护器 --sandbox sidecar、--max-total-tokens/--max-usd 退出码 3 与脱敏 Webhook/死信队列", async () => {
		const root = makeTmpDir();
		const vaultSecret = "SuperSecretCookie_DaemonMaskTest_4455";
		upsertSessionRole(root, { role: "admin", cookie: `sid=${vaultSecret}` });

		// 1) --dry-run 验证 --sandbox sidecar 与 Webhook URL 脱敏掩码
		const dry = spawnSync(
			"bun",
			[
				DAEMON_BIN,
				"--target",
				"http://127.0.0.1:18080",
				"--root",
				root,
				"--sandbox",
				"sidecar",
				"--max-total-tokens",
				"50000",
				"--max-usd",
				"1.5",
				"--webhook",
				"https://hooks.example.test/services/SECRET_TOKEN_XYZ12345?key=secret99",
				"--dry-run",
			],
			{ encoding: "utf8" },
		);
		expect(dry.status).toBe(0);
		expect(dry.stdout).toContain("sidecar");
		expect(dry.stdout).not.toContain("SECRET_TOKEN_XYZ12345");
		expect(dry.stdout).not.toContain("secret99");

		// 2) 启动本地 Webhook 接收端，模拟第 1 代写入超额 totalTokens 触发退出码 3 与脱敏告警
		const receivedPayloads: string[] = [];
		const webhookSrv = http.createServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on("data", (c) => chunks.push(Buffer.from(c)));
			req.on("end", () => {
				receivedPayloads.push(Buffer.concat(chunks).toString("utf8"));
				res.writeHead(200, { "Content-Type": "application/json" });
				res.end('{"ok":true}');
			});
		});
		await new Promise<void>((res) => webhookSrv.listen(0, "127.0.0.1", () => res()));
		const whPort = (webhookSrv.address() as net.AddressInfo).port;
		cleanups.push(() => new Promise<void>((res) => webhookSrv.close(() => res())));

		const stubOmp = join(root, "stub-omp.sh");
		writeFileSync(
			stubOmp,
			`#!/usr/bin/env bash
set -e
mkdir -p "$NUWA_PROJECT/.nuwa"
cat > "$NUWA_PROJECT/.nuwa/state.json" <<'JSON'
{
  "schema": 1,
  "project": {
    "id": "p-budget",
    "target": "http://127.0.0.1:18080",
    "url": "http://127.0.0.1:18080",
    "host": "127.0.0.1",
    "port": 18080,
    "scheme": "http",
    "mode": "pentest",
    "goal": "cost cap test",
    "phase": "recon",
    "status": "active",
    "createdAt": "2026-11-25T00:00:00.000Z"
  },
  "facts": {
    "f001": {
      "id": "f001",
      "kind": "note",
      "title": "包含凭据片段 ${vaultSecret}",
      "detail": "sid=${vaultSecret}",
      "command": "curl -sS http://127.0.0.1:18080/",
      "output": "ok",
      "key": "n1",
      "createdAt": "2026-11-25T00:00:00.000Z"
    }
  },
  "intents": {},
  "runtime": {
    "turns": 5,
    "totalTurns": 5,
    "tokens": 120000,
    "totalTokens": 120000,
    "generation": 1,
    "handoffSummary": "generation handoff ready",
    "startedAt": 1700000000000
  }
}
JSON
exit 0
`,
			{ mode: 0o755 },
		);
		chmodSync(stubOmp, 0o755);

		const runCap = await spawnAsync(
			"bun",
			[
				DAEMON_BIN,
				"--target",
				"http://127.0.0.1:18080",
				"--root",
				root,
				"--omp-bin",
				stubOmp,
				"--max-total-tokens",
				"100000",
				"--webhook",
				`http://127.0.0.1:${whPort}/alert`,
			],
			{
				encoding: "utf8",
				env: { ...process.env, NUWA_WEBHOOK_RETRY_MS: "10" },
			},
		);
		expect(runCap.status).toBe(3);
		expect(receivedPayloads.length).toBeGreaterThanOrEqual(1);
		const allWh = receivedPayloads.join("\n");
		expect(allWh).toContain("budget_exceeded");
		expect(allWh).not.toContain(vaultSecret);

		// 3) Webhook 不可达时自动重试并落盘 0o600 deadletter
		const deadRoot = makeTmpDir();
		const runDead = await spawnAsync(
			"bun",
			[
				DAEMON_BIN,
				"--target",
				"http://127.0.0.1:18080",
				"--root",
				deadRoot,
				"--omp-bin",
				stubOmp,
				"--max-usd",
				"0.01",
				"--usd-per-1m-tokens",
				"5.0",
				"--webhook",
				"http://127.0.0.1:1/unreachable-hook",
			],
			{
				encoding: "utf8",
				env: { ...process.env, NUWA_WEBHOOK_RETRY_MS: "5" },
			},
		);
		expect(runDead.status).toBe(3);
		const deadFile = join(deadRoot, ".nuwa", "webhook-deadletter.jsonl");
		expect(existsSync(deadFile)).toBe(true);
		expect(statSync(deadFile).mode & 0o777).toBe(0o600);
		expect(readFileSync(deadFile, "utf8")).not.toContain(vaultSecret);
	});

	test("离线确定性评测靶场 benchmarks/run-eval.ts 10/10 全绿零误报零泄露", () => {
		const res = spawnSync("bun", [BENCH_SCRIPT, "--deterministic", "--json"], {
			cwd: REPO_ROOT,
			encoding: "utf8",
			env: { ...process.env, BUN_OPTIONS: undefined },
		});
		expect(res.status).toBe(0);
		const report = JSON.parse(res.stdout);
		expect(report.metrics.totalScenarios).toBe(10);
		expect(report.metrics.passedScenarios).toBe(10);
		expect(report.metrics.passAt1Rate).toBe(1);
		expect(report.metrics.falsePositiveCount).toBe(0);
		expect(report.metrics.verifierCatchRate).toBe(1);
		expect(report.metrics.vaultLeakCount).toBe(0);
	});
});
