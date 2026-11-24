/**
 * 女娲 v3.0 多领域 Profile 引擎、KB 自动富化、战略复盘与外层无头守护器（bin/nuwa-autonomous）测试。
 */
import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import type { NuwaState } from "../omp/nuwa";
import {
	PROFILE_MODES,
	buildReflectIntentSpec,
	deriveKbIntents,
	extractTechKeywords,
	getProfile,
	isProfileMode,
	type ProfileMode,
} from "../omp/profiles";

const REPO_ROOT = resolve(import.meta.dir, "..");
const DAEMON_BIN = join(REPO_ROOT, "bin", "nuwa-autonomous");
const PROFILES_SRC = join(REPO_ROOT, "omp", "profiles.ts");

const tmpDirs: string[] = [];

function makeTmpDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(dir);
	return dir;
}

afterEach(() => {
	while (tmpDirs.length > 0) {
		const dir = tmpDirs.pop()!;
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

function makeMockState(overrides: Partial<{
	mode: NuwaState["project"]["mode"];
	status: NuwaState["project"]["status"];
	phase: NuwaState["project"]["phase"];
	episode: number;
	stall: number;
	turns: number;
}> = {}): NuwaState {
	const ts = "2026-11-24T00:00:00.000Z";
	return {
		schema: 1,
		version: "3.0.0",
		project: {
			id: "127-0-0-1-8080",
			target: "http://127.0.0.1:8080",
			url: "http://127.0.0.1:8080",
			host: "127.0.0.1",
			port: 8080,
			scheme: "http",
			goal: "验证测试目标",
			mode: overrides.mode ?? "ctf",
			status: overrides.status ?? "active",
			phase: overrides.phase ?? "recon",
			episode: overrides.episode ?? 1,
			createdAt: ts,
			updatedAt: ts,
		},
		facts: {},
		intents: {},
		seq: { fact: 0, intent: 0 },
		runtime: {
			startedAt: Date.now(),
			turns: overrides.turns ?? 1,
			stall: overrides.stall ?? 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 1,
			lastToolCalls: 0,
			tokens: 1000,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
		},
	};
}

function runDaemon(args: string[], extraEnv: Record<string, string> = {}) {
	const env: Record<string, string> = {};
	for (const [k, v] of Object.entries(process.env)) {
		if (k === "BUN_OPTIONS" || v === undefined) continue;
		env[k] = v;
	}
	Object.assign(env, extraEnv);
	return spawnSync(DAEMON_BIN, args, {
		encoding: "utf8",
		env,
		timeout: 20_000,
	});
}

describe("omp/profiles.ts 多领域 Profile 引擎", () => {
	test("严禁运行时 import ./nuwa，仅允许 import type", () => {
		const src = readFileSync(PROFILES_SRC, "utf8");
		expect(src).toMatch(/import\s+type\s+\{[^}]+\}\s+from\s+["']\.\/nuwa["']/);
		expect(src).not.toMatch(/import\s+(?!type\b)[^;\n]*from\s+["']\.\/nuwa["']/);
		expect(src).not.toMatch(/require\s*\(\s*["']\.\/nuwa["']\s*\)/);
	});

	test("5 种 ProfileMode 完整定义与 proofKinds / requireHttpTarget 正确", () => {
		expect(PROFILE_MODES).toEqual(["ctf", "pentest", "audit", "coding", "ops"]);
		for (const m of PROFILE_MODES) {
			expect(isProfileMode(m)).toBe(true);
		}
		expect(isProfileMode("unknown")).toBe(false);

		const cases: Array<{ mode: ProfileMode; proofKinds: string[]; requireHttpTarget: boolean }> = [
			{ mode: "ctf", proofKinds: ["flag"], requireHttpTarget: true },
			{ mode: "audit", proofKinds: ["vuln", "loot"], requireHttpTarget: true },
			{ mode: "pentest", proofKinds: ["vuln", "loot", "flag"], requireHttpTarget: true },
			{ mode: "coding", proofKinds: ["loot", "note"], requireHttpTarget: false },
			{ mode: "ops", proofKinds: ["loot", "note"], requireHttpTarget: false },
		];

		for (const c of cases) {
			const spec = getProfile(c.mode);
			expect(spec.mode).toBe(c.mode);
			expect(spec.label.length).toBeGreaterThan(0);
			expect(spec.proofKinds).toEqual(c.proofKinds);
			expect(spec.requireHttpTarget).toBe(c.requireHttpTarget);
			expect(spec.phases).toEqual(["recon", "surface", "vuln", "exploit", "post", "report"]);
			for (const phase of spec.phases) {
				expect(Array.isArray(spec.seeds[phase])).toBe(true);
				expect(spec.seeds[phase].length).toBeGreaterThan(0);
				for (const seed of spec.seeds[phase]) {
					expect(seed.key.length).toBeGreaterThan(0);
					expect(seed.title.length).toBeGreaterThan(0);
					expect(seed.detail.length).toBeGreaterThan(0);
				}
			}
		}

		// 大小写归一化与未知模式回退到 ctf，且返回独立副本
		const codingTrim = getProfile("  CODING ");
		expect(codingTrim.mode).toBe("coding");
		codingTrim.proofKinds.push("flag");
		codingTrim.seeds.recon.push({ key: "mutated", title: "mut", detail: "mut" });
		const codingFresh = getProfile("coding");
		expect(codingFresh.proofKinds).toEqual(["loot", "note"]);
		expect(codingFresh.seeds.recon.some((s) => s.key === "mutated")).toBe(false);

		expect(getProfile("non-existent-mode").mode).toBe("ctf");
		expect(getProfile("").mode).toBe("ctf");
	});
});

describe("extractTechKeywords 与 deriveKbIntents", () => {
	test("准确提取主流技术栈与 CVE，忽略非 service/endpoint/vuln 事实", () => {
		const kws = extractTechKeywords({
			kind: "service",
			title: "HTTP 200 nginx/1.18.0 + Apache Tomcat/9.0",
			detail: "X-Powered-By: PHP/8.1; Spring Boot Actuator; Fastjson; ThinkPHP; Shiro rememberMe=; Redis; MySQL; PostgreSQL",
			output: "Grafana GitLab X-Jenkins wp-content GraphQL swagger-ui CVE-2021-44228 cve-2023-22515 CVE-2021-44228",
		});

		for (const expected of [
			"CVE-2021-44228",
			"CVE-2023-22515",
			"nginx",
			"apache",
			"tomcat",
			"php",
			"spring",
			"fastjson",
			"thinkphp",
			"shiro",
			"redis",
			"mysql",
			"postgres",
			"grafana",
			"gitlab",
			"jenkins",
			"wordpress",
			"graphql",
			"swagger",
		]) {
			expect(kws).toContain(expected);
		}
		// 重复 CVE 应去重
		expect(kws.filter((x) => x === "CVE-2021-44228").length).toBe(1);

		// note / blocked / flag 不提取
		expect(
			extractTechKeywords({
				kind: "note",
				title: "nginx spring CVE-2021-44228",
				detail: "纯笔记",
				output: "",
			}),
		).toEqual([]);
	});

	test("deriveKbIntents 生成去重 KB 意图，过滤未命中并受 maxPerRun 限制", () => {
		const st = makeMockState();
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "HTTP 200 nginx",
			detail: "Spring Boot actuator + CVE-2022-22965 + redis",
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		st.facts.f002 = {
			id: "f002",
			kind: "endpoint",
			title: "发现 /swagger-ui.html",
			detail: "OpenAPI 文档暴露，后端 PHP/7.4",
			createdAt: "2026-11-24T00:00:02.000Z",
		};
		// 预先存在一条 key，确保排除重复
		st.intents.i001 = {
			id: "i001",
			phase: "vuln",
			key: "kb:f001:nginx",
			title: "已有 nginx 核验",
			detail: "",
			from: ["f001"],
			status: "open",
			priority: 86,
			attempts: 0,
			createdAt: "2026-11-24T00:00:03.000Z",
		};

		const queried: Array<{ q: string; kind: string }> = [];
		const lookup = (q: string, kind: "auto" | "product" | "cve") => {
			queried.push({ q, kind });
			if (q === "CVE-2022-22965") return "CVE-2022-22965 CRITICAL CVSS 9.8 Spring Framework RCE";
			if (q === "spring") return "## spring — Spring Boot 安全配置核查指南\n检查 actuator 暴露";
			if (q === "redis") return "未命中: redis";
			if (q === "swagger") return "## swagger — OpenAPI 鉴权与接口核查";
			return `未命中: ${q}`;
		};

		const specs = deriveKbIntents(st, lookup, 10);
		expect(specs.map((s) => s.key)).toEqual([
			"kb:f001:cve-2022-22965",
			"kb:f001:spring",
			"kb:f002:swagger",
		]);
		for (const s of specs) {
			expect(s.phase).toBe("vuln");
			expect(s.priority).toBe(86);
			expect(s.from.length).toBe(1);
			expect(s.detail).toContain("知识库摘要");
		}
		// 已有 key kb:f001:nginx 不应重复触发 lookupFn
		expect(queried.some((x) => x.q === "nginx")).toBe(false);
		expect(queried.find((x) => x.q === "CVE-2022-22965")?.kind).toBe("cve");
		expect(queried.find((x) => x.q === "spring")?.kind).toBe("product");

		// maxPerRun 限制
		const limited = deriveKbIntents(st, lookup, 1);
		expect(limited.length).toBe(1);
		expect(limited[0].key).toBe("kb:f001:cve-2022-22965");
	});

	test("缺少 KB 数据库抛出异常时不报错并返回空数组", () => {
		const st = makeMockState();
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "HTTP 200 nginx",
			detail: "Server: nginx/1.24",
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		const throwingLookup = () => {
			throw new Error("知识库不存在: /data/nuwa-kb/kb.db");
		};
		expect(deriveKbIntents(st, throwingLookup, 5)).toEqual([]);
	});
});

describe("buildReflectIntentSpec 战略复盘规划", () => {
	test("未达触发条件或非 active 项目返回 null", () => {
		const activeNormal = makeMockState({ phase: "recon", stall: 1 });
		activeNormal.intents.i001 = {
			id: "i001",
			phase: "recon",
			key: "recon:http",
			title: "HTTP",
			detail: "",
			from: [],
			status: "open",
			priority: 90,
			attempts: 0,
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		activeNormal.intents.i002 = {
			id: "i002",
			phase: "recon",
			key: "recon:ports",
			title: "ports",
			detail: "",
			from: [],
			status: "open",
			priority: 88,
			attempts: 0,
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		expect(buildReflectIntentSpec(activeNormal, "routine")).toBeNull();

		const completed = makeMockState({ status: "completed", stall: 5 });
		expect(buildReflectIntentSpec(completed, "stall=5")).toBeNull();
	});

	test("stall >= 3 生成带 from 依赖与 nuwa_plan 指令的复盘意图并按桶去重", () => {
		const st = makeMockState({ phase: "vuln", episode: 2, stall: 3 });
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "HTTP 200 nginx",
			detail: "Server: nginx/1.20",
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		st.intents.i001 = {
			id: "i001",
			phase: "vuln",
			key: "vuln:sqli",
			title: "SQL 边界核验",
			detail: "",
			from: [],
			status: "blocked",
			note: "WAF 返回 403",
			priority: 90,
			attempts: 2,
			createdAt: "2026-11-24T00:00:02.000Z",
		};

		const spec1 = buildReflectIntentSpec(st, "stall=3");
		expect(spec1).not.toBeNull();
		expect(spec1!.key).toBe("reflect:e2:vuln:s1");
		expect(spec1!.phase).toBe("vuln");
		expect(spec1!.from).toEqual(["f001"]);
		expect(spec1!.detail).toContain("nuwa_plan(intents=[");
		expect(spec1!.detail).toContain("WAF 返回 403");

		// 写入 state.intents 后同一停滞窗口内去重返回 null
		st.intents.i002 = {
			id: "i002",
			phase: spec1!.phase,
			key: spec1!.key,
			title: spec1!.title,
			detail: spec1!.detail,
			from: spec1!.from,
			status: "open",
			priority: spec1!.priority,
			attempts: 0,
			createdAt: "2026-11-24T00:00:03.000Z",
		};
		expect(buildReflectIntentSpec(st, "stall=4")).toBeNull();

		// stall 推进到 6 进入下一个去重桶 s2
		st.runtime.stall = 6;
		const spec2 = buildReflectIntentSpec(st, "stall=6");
		expect(spec2).not.toBeNull();
		expect(spec2!.key).toBe("reflect:e2:vuln:s2");
	});

	test("阶段收尾生成 closing 桶复盘意图并去重", () => {
		const st = makeMockState({ phase: "recon", episode: 1, stall: 0 });
		st.facts.f001 = {
			id: "f001",
			kind: "service",
			title: "HTTP 200",
			detail: "ok",
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		st.intents.i001 = {
			id: "i001",
			phase: "recon",
			key: "recon:http",
			title: "HTTP",
			detail: "",
			from: [],
			status: "done",
			priority: 90,
			attempts: 1,
			createdAt: "2026-11-24T00:00:01.000Z",
		};
		st.intents.i002 = {
			id: "i002",
			phase: "recon",
			key: "recon:ports",
			title: "ports",
			detail: "",
			from: [],
			status: "blocked",
			note: "仅开放 80",
			priority: 88,
			attempts: 1,
			createdAt: "2026-11-24T00:00:01.000Z",
		};

		const spec = buildReflectIntentSpec(st, "phase-closing:recon");
		expect(spec).not.toBeNull();
		expect(spec!.key).toBe("reflect:e1:recon:closing");
		expect(spec!.detail).toContain("nuwa_plan");

		st.intents.i003 = {
			id: "i003",
			phase: spec!.phase,
			key: spec!.key,
			title: spec!.title,
			detail: spec!.detail,
			from: spec!.from,
			status: "open",
			priority: spec!.priority,
			attempts: 0,
			createdAt: "2026-11-24T00:00:02.000Z",
		};
		expect(buildReflectIntentSpec(st, "phase-closing:recon")).toBeNull();
	});
});

describe("bin/nuwa-autonomous 外层无头守护器端到端测试", () => {
	test("--help、--dry-run 与非法参数校验", () => {
		const help = runDaemon(["--help"]);
		expect(help.status).toBe(0);
		expect(help.stdout).toContain("nuwa-autonomous");

		const emptyRoot = makeTmpDir("nuwa-daemon-empty-");
		const noTarget = runDaemon(["--root", emptyRoot]);
		expect(noTarget.status).toBe(2);
		expect(noTarget.stderr).toContain("--target");

		const badMode = runDaemon(["--target", "http://127.0.0.1:8080", "--mode", "invalid", "--root", emptyRoot]);
		expect(badMode.status).toBe(2);

		const dry = runDaemon([
			"--target",
			"http://127.0.0.1:18081",
			"--mode",
			"pentest",
			"--goal",
			"端到端 dry-run 验证",
			"--root",
			emptyRoot,
			"--max-generations",
			"5",
			"--max-hours",
			"2",
			"--reincarnate-tokens",
			"90000",
			"--reincarnate-turns",
			"12",
			"--allow-subdomains",
			"--allow-cidr",
			"10.10.0.0/24",
			"--allow-cidr",
			"192.168.1.0/24",
			"--model",
			"test-model",
			"--omp-bin",
			"/usr/bin/true",
			"--dry-run",
		]);
		expect(dry.status).toBe(0);
		expect(dry.stdout).toContain('"NUWA_LOOP": "1"');
		expect(dry.stdout).toContain('"NUWA_INFINITE": "1"');
		expect(dry.stdout).toContain('"NUWA_HEADLESS_DAEMON": "1"');
		expect(dry.stdout).toContain('"NUWA_STRICT_EVIDENCE": "1"');
		expect(dry.stdout).toContain('"NUWA_REINCARNATE_TOKENS": "90000"');
		expect(dry.stdout).toContain('"NUWA_REINCARNATE_TURNS": "12"');
		expect(dry.stdout).toContain('"NUWA_SCOPE_ALLOW_SUBDOMAINS": "1"');
		expect(dry.stdout).toContain('"NUWA_SCOPE_ALLOW_CIDRS": "10.10.0.0/24,192.168.1.0/24"');
		expect(dry.stdout).toContain('"test-model"');
	});

	test("多代换血闭环：第 1 代写 handoffSummary 退出 -> 第 2 代接力完成 -> 守护器 0 退出", () => {
		const work = makeTmpDir("nuwa-daemon-e2e-");
		const projRoot = join(work, "proj");
		mkdirSync(projRoot, { recursive: true });
		const tracePath = join(work, "stub-trace.jsonl");
		const stubPath = join(work, "omp-stub.py");

		writeFileSync(
			stubPath,
			`#!/usr/bin/env python3
import json, os, pathlib, sys

root = pathlib.Path(os.environ["NUWA_PROJECT"])
state_dir = root / ".nuwa"
state_dir.mkdir(parents=True, exist_ok=True)
state_path = state_dir / "state.json"
trace_path = pathlib.Path(${JSON.stringify(tracePath)})

prompt = sys.argv[-1] if len(sys.argv) > 1 else ""
call_idx = 1
if trace_path.exists():
    call_idx = len(trace_path.read_text(encoding="utf-8").splitlines()) + 1

rec = {
    "call": call_idx,
    "argv": sys.argv[1:],
    "prompt": prompt,
    "env": {
        "NUWA_LOOP": os.environ.get("NUWA_LOOP"),
        "NUWA_INFINITE": os.environ.get("NUWA_INFINITE"),
        "NUWA_HEADLESS_DAEMON": os.environ.get("NUWA_HEADLESS_DAEMON"),
        "NUWA_STRICT_EVIDENCE": os.environ.get("NUWA_STRICT_EVIDENCE"),
        "NUWA_REINCARNATE_TOKENS": os.environ.get("NUWA_REINCARNATE_TOKENS"),
        "NUWA_REINCARNATE_TURNS": os.environ.get("NUWA_REINCARNATE_TURNS"),
        "NUWA_PROJECT": os.environ.get("NUWA_PROJECT"),
        "NUWA_SCOPE_ALLOW_SUBDOMAINS": os.environ.get("NUWA_SCOPE_ALLOW_SUBDOMAINS"),
        "NUWA_SCOPE_ALLOW_CIDRS": os.environ.get("NUWA_SCOPE_ALLOW_CIDRS"),
    },
}
with trace_path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, ensure_ascii=False) + "\\n")

if call_idx == 1:
    st = {
        "schema": 1,
        "version": "3.0.0",
        "project": {
            "id": "127-0-0-1-18081",
            "target": "http://127.0.0.1:18081",
            "url": "http://127.0.0.1:18081",
            "host": "127.0.0.1",
            "port": 18081,
            "scheme": "http",
            "goal": "端到端换代闭环验证",
            "mode": "ctf",
            "status": "active",
            "phase": "vuln",
            "episode": 1,
            "createdAt": "2026-11-24T00:00:00.000Z",
            "updatedAt": "2026-11-24T00:01:00.000Z",
        },
        "facts": {
            "f001": {"id": "f001", "kind": "service", "title": "HTTP 200 nginx", "detail": "80/tcp open"}
        },
        "intents": {},
        "seq": {"fact": 1, "intent": 1},
        "runtime": {
            "generation": 2,
            "genTurns": 0,
            "tokens": 0,
            "handoffSummary": "[女娲世代交接 G1->G2] 已完成端口探测，下一代优先核验 /admin 接口。",
        },
    }
    state_path.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    sys.exit(0)

# 第 2 代完成任务并生成 REPORT.md
st = json.loads(state_path.read_text(encoding="utf-8"))
st["project"]["status"] = "completed"
st["project"]["phase"] = "report"
st["facts"]["f002"] = {"id": "f002", "kind": "flag", "title": "flag", "detail": "值: flag{daemon-ok}"}
state_path.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
(state_dir / "REPORT.md").write_text("# 报告\\nflag{daemon-ok}\\n", encoding="utf-8")
sys.exit(0)
`,
			"utf8",
		);
		chmodSync(stubPath, 0o755);

		const res = runDaemon(
			[
				"--target",
				"http://127.0.0.1:18081",
				"--mode",
				"ctf",
				"--goal",
				"端到端换代闭环验证",
				"--root",
				projRoot,
				"--max-generations",
				"3",
				"--reincarnate-tokens",
				"120000",
				"--reincarnate-turns",
				"15",
				"--allow-subdomains",
				"--allow-cidr",
				"127.0.0.0/8",
				"--omp-bin",
				stubPath,
			],
			{ NUWA_DAEMON_BACKOFF_MS: "10" },
		);

		expect(res.status).toBe(0);
		expect(res.stdout).toContain("任务已完成");
		expect(res.stdout).toContain("REPORT.md");

		const calls = readFileSync(tracePath, "utf8")
			.trim()
			.split("\n")
			.map((l) => JSON.parse(l));
		expect(calls.length).toBe(2);

		// 核验第 1 代环境变量与首次起跑 Prompt
		expect(calls[0].env.NUWA_LOOP).toBe("1");
		expect(calls[0].env.NUWA_INFINITE).toBe("1");
		expect(calls[0].env.NUWA_HEADLESS_DAEMON).toBe("1");
		expect(calls[0].env.NUWA_STRICT_EVIDENCE).toBe("1");
		expect(calls[0].env.NUWA_REINCARNATE_TOKENS).toBe("120000");
		expect(calls[0].env.NUWA_REINCARNATE_TURNS).toBe("15");
		expect(calls[0].env.NUWA_PROJECT).toBe(projRoot);
		expect(calls[0].env.NUWA_SCOPE_ALLOW_SUBDOMAINS).toBe("1");
		expect(calls[0].env.NUWA_SCOPE_ALLOW_CIDRS).toBe("127.0.0.0/8");
		expect(calls[0].argv).toContain("-p");
		expect(calls[0].argv).toContain("--cwd");
		expect(calls[0].prompt).toContain("nuwa_init");

		// 核验第 2 代收到干净的换代交接 Prompt（含目标、阶段、世代号及交接摘要）
		expect(calls[1].prompt).toContain("第 2 代交接接力");
		expect(calls[1].prompt).toContain("http://127.0.0.1:18081");
		expect(calls[1].prompt).toContain("当前阶段: vuln");
		expect(calls[1].prompt).toContain("[女娲世代交接 G1->G2]");
		expect(calls[1].prompt).toContain("下一代优先核验 /admin 接口");
	});

	test("子进程异常崩溃一次后自动指数退避重启并从磁盘接力完成", () => {
		const work = makeTmpDir("nuwa-daemon-retry-");
		const projRoot = join(work, "proj");
		mkdirSync(projRoot, { recursive: true });
		const counterPath = join(work, "count.txt");
		const stubPath = join(work, "omp-flaky.py");

		writeFileSync(
			stubPath,
			`#!/usr/bin/env python3
import json, os, pathlib, sys

counter = pathlib.Path(${JSON.stringify(counterPath)})
n = int(counter.read_text(encoding="utf-8")) + 1 if counter.exists() else 1
counter.write_text(str(n), encoding="utf-8")

root = pathlib.Path(os.environ["NUWA_PROJECT"])
state_dir = root / ".nuwa"
state_dir.mkdir(parents=True, exist_ok=True)
state_path = state_dir / "state.json"

if n == 1:
    # 第 1 次模拟写入活跃磁盘状态后遭遇 API 429 异常退出
    st = {
        "schema": 1,
        "version": "3.0.0",
        "project": {
            "id": "127-0-0-1-18082",
            "target": "http://127.0.0.1:18082",
            "url": "http://127.0.0.1:18082",
            "host": "127.0.0.1",
            "port": 18082,
            "scheme": "http",
            "goal": "崩溃恢复测试",
            "mode": "coding",
            "status": "active",
            "phase": "exploit",
        },
        "facts": {"f001": {"id": "f001", "kind": "note", "title": "进度保存", "detail": "ok"}},
        "intents": {},
        "seq": {"fact": 1, "intent": 0},
        "runtime": {"generation": 1},
    }
    state_path.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    sys.stderr.write("HTTP 429 Too Many Requests\\n")
    sys.exit(1)

# 第 2 次重试从磁盘接力并标记完成
st = json.loads(state_path.read_text(encoding="utf-8"))
st["project"]["status"] = "completed"
st["facts"]["f002"] = {"id": "f002", "kind": "loot", "title": "测试全绿", "detail": "pass"}
state_path.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
sys.exit(0)
`,
			"utf8",
		);
		chmodSync(stubPath, 0o755);

		const res = runDaemon(
			[
				"--target",
				"http://127.0.0.1:18082",
				"--mode",
				"coding",
				"--root",
				projRoot,
				"--max-generations",
				"2",
				"--omp-bin",
				stubPath,
			],
			{ NUWA_DAEMON_BACKOFF_MS: "15" },
		);

		expect(res.status).toBe(0);
		expect(readFileSync(counterPath, "utf8").trim()).toBe("2");
		expect(res.stdout).toContain("退避重试");
		expect(res.stdout).toContain("任务已完成");
	});

	test("遇到非换代 status=stopped 时打印停机原因并退出码 2", () => {
		const work = makeTmpDir("nuwa-daemon-stop-");
		const projRoot = join(work, "proj");
		mkdirSync(projRoot, { recursive: true });
		const stubPath = join(work, "omp-stop.py");

		writeFileSync(
			stubPath,
			`#!/usr/bin/env python3
import json, os, pathlib, sys

root = pathlib.Path(os.environ["NUWA_PROJECT"])
state_dir = root / ".nuwa"
state_dir.mkdir(parents=True, exist_ok=True)
st = {
    "schema": 1,
    "version": "3.0.0",
    "project": {
        "id": "stop-case",
        "target": "http://127.0.0.1:18083",
        "url": "http://127.0.0.1:18083",
        "host": "127.0.0.1",
        "port": 18083,
        "scheme": "http",
        "goal": "停机测试",
        "mode": "ctf",
        "status": "stopped",
        "phase": "recon",
        "stopReason": "人工手动中止测试",
    },
    "facts": {},
    "intents": {},
    "seq": {"fact": 0, "intent": 0},
    "runtime": {"generation": 1},
}
(state_dir / "state.json").write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
sys.exit(0)
`,
			"utf8",
		);
		chmodSync(stubPath, 0o755);

		const res = runDaemon(
			[
				"--target",
				"http://127.0.0.1:18083",
				"--root",
				projRoot,
				"--max-generations",
				"3",
				"--omp-bin",
				stubPath,
			],
			{ NUWA_DAEMON_BACKOFF_MS: "10" },
		);

		expect(res.status).toBe(2);
		expect(res.stdout).toContain("人工手动中止测试");
	});
});
