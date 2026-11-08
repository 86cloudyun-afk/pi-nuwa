/**
 * TS 单元测试：直接测扩展导出的纯函数。
 *
 * 运行：bun test layer-a/tests/unit.test.ts
 * 环境：NUWA_WORK 指向仓库根（默认 /tmp/nuwa-work）
 */
import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const WORK = process.env.NUWA_WORK ?? join(new URL(".", import.meta.url).pathname, "..");
const EXT = join(WORK, "extensions/nuwa-loop/index.ts");

let ROOT = "";
function fresh(): string {
	ROOT = mkdtempSync(join(tmpdir(), "nuwa-unit-"));
	return ROOT;
}

function makeGraph(root: string, opts: {
	status?: string;
	goal?: string;
	intents?: Array<{ id: string; status: string }>;
	facts?: Array<{ id: string; kind: string }>;
	lockPid?: number;
	viewUrl?: string;
} = {}) {
	const s = join(root, ".sapper");
	mkdirSync(join(s, "intents"), { recursive: true });
	mkdirSync(join(s, "facts"), { recursive: true });
	writeFileSync(join(s, "project.json"), JSON.stringify({
		status: opts.status ?? "active",
		goal: opts.goal ?? "unit goal",
	}));
	for (const it of opts.intents ?? []) {
		writeFileSync(join(s, "intents", `${it.id}.json`), JSON.stringify({
			id: it.id, status: it.status, from: ["f001"], description: it.id,
		}));
	}
	for (const f of opts.facts ?? []) {
		writeFileSync(join(s, "facts", `${f.id}.json`), JSON.stringify({
			id: f.id, kind: f.kind, description: f.id,
		}));
	}
	if (opts.lockPid) writeFileSync(join(s, "..", ".nuwa.lock"), `${opts.lockPid}\n`);
	if (opts.viewUrl) writeFileSync(join(s, "view.url"), opts.viewUrl + "\n");
}

// 扩展在模块顶层读 PI_AGENT_HOME，必须在导入前固定一个测试专用 agent 目录。
const AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-agent-"));
process.env.PI_AGENT_HOME = AGENT_HOME;

// 动态导入是测试边界：扩展路径由 NUWA_WORK 在运行时决定，静态导入无法覆盖多仓库布局。
const mod = await import(EXT);

beforeEach(() => {
	fresh();
	// 指针文件跨用例残留会污染 findRoot，每次清掉
	rmSync(join(AGENT_HOME, "cache", "nuwa-current"), { force: true });
});

afterAll(() => {
	if (ROOT) rmSync(ROOT, { recursive: true, force: true });
});

describe("findRoot", () => {
	test("从子目录向上找到 .sapper", () => {
		const root = fresh();
		makeGraph(root);
		const sub = join(root, "a", "b");
		mkdirSync(sub, { recursive: true });
		expect(mod.findRoot(sub)).toBe(root);
	});

	test("NUWA_PROJECT 兜底", () => {
		const root = fresh();
		makeGraph(root);
		process.env.NUWA_PROJECT = root;
		const elsewhere = join(root, "elsewhere");
		mkdirSync(elsewhere, { recursive: true });
		expect(mod.findRoot(elsewhere)).toBe(root);
		delete process.env.NUWA_PROJECT;
	});

	test("指针 JSON 命中", () => {
		const root = fresh();
		makeGraph(root);
		const ptrDir = AGENT_HOME;
		mkdirSync(join(ptrDir, "cache"), { recursive: true });
		writeFileSync(join(ptrDir, "cache", "nuwa-current"),
			JSON.stringify({ root, sessionId: "", ts: Date.now() }));
		const elsewhere = join(root, "x");
		mkdirSync(elsewhere, { recursive: true });
		expect(mod.findRoot(elsewhere)).toBe(root);
	});

	test("sessionId 不匹配时拒绝接管", () => {
		const root = fresh();
		makeGraph(root);
		const ptrDir = AGENT_HOME;
		mkdirSync(join(ptrDir, "cache"), { recursive: true });
		writeFileSync(join(ptrDir, "cache", "nuwa-current"),
			JSON.stringify({ root, sessionId: "other-session", ts: Date.now() }));
		const elsewhere = mkdtempSync(join(tmpdir(), "nuwa-probe-"));
		expect(mod.findRoot(elsewhere, "my-session")).toBeNull();
	});

	test("无图时返回 null", () => {
		const root = fresh();
		const elsewhere = join(root, "empty");
		mkdirSync(elsewhere, { recursive: true });
		expect(mod.findRoot(elsewhere)).toBeNull();
	});
});

describe("readGraph", () => {
	test("计数 open/claimed/done 与 effective", () => {
		const root = fresh();
		makeGraph(root, {
			intents: [
				{ id: "i001", status: "open" },
				{ id: "i002", status: "claimed" },
				{ id: "i003", status: "done" },
			],
			facts: [
				{ id: "f001", kind: "host" },
				{ id: "f002", kind: "note" },
				{ id: "f003", kind: "note" },
				{ id: "f004", kind: "vuln" },
			],
		});
		const g = mod.readGraph(root)!;
		expect(g.open).toBe(1);
		expect(g.claimed).toBe(1);
		expect(g.done).toBe(1);
		expect(g.facts).toBe(4);
		expect(g.effective).toBe(2); // host + vuln，note 不算
		expect(g.verified).toBe(true);
		expect(g.openIds).toEqual(["i001"]);
	});

	test("只有 note 时 verified=false", () => {
		const root = fresh();
		makeGraph(root, { facts: [{ id: "f001", kind: "note" }] });
		const g = mod.readGraph(root)!;
		expect(g.verified).toBe(false);
		expect(g.effective).toBe(0);
	});

	test("readGraph 对损坏 JSON 返回 null", () => {
		const root = fresh();
		const s = join(root, ".sapper");
		mkdirSync(s, { recursive: true });
		writeFileSync(join(s, "project.json"), "{broken");
		expect(mod.readGraph(root)).toBeNull();
	});

	test("识别活锁", () => {
		const root = fresh();
		makeGraph(root, { lockPid: process.pid + 100000 });
		const g = mod.readGraph(root)!;
		expect(g.locked).toBe(false); // pid 不存在
	});
});

describe("buildDirective", () => {
	const g = {
		root: "/tmp/x", status: "active", goal: "g", open: 2, done: 0, claimed: 0,
		facts: 1, flags: 0, effective: 1, verified: false, openIds: ["i001", "i002"],
		locked: false, viewUrl: null,
	};
	const st = {
		schema: 2, armed: true, armedAt: 0, turns: 3, stall: 0, idle: 0, blockStreak: 0,
		spentTokens: 0, lastTokens: 0, toolCalls: 1, lastToolCallsSnapshot: 1,
		completionRejects: 0, sig: "s", lastReason: "",
	};

	test("三条动作 + commit 收口", () => {
		const d = mod.buildDirective(g, st, "fujiang");
		expect(d).toContain("sapper claim <id> --worker");
		expect(d).toContain("sapper doc <id> --set");
		expect(d).toContain("nuwa commit --root /tmp/x --intent <id> --key auto");
		expect(d).not.toContain("    sapper done <id> --fact");
		expect(d).toContain("nuwa complete --from");
	});

	test("stall>=3 时给出换路指令", () => {
		const d = mod.buildDirective(g, { ...st, stall: 3 });
		expect(d).toContain("sapper release");
		expect(d).toContain("sapper hint");
	});

	test("idle>=2 时要求立刻调工具", () => {
		const d = mod.buildDirective(g, { ...st, idle: 2 });
		expect(d).toContain("没有调用任何工具");
	});

	test("locked 时提示只验收不重复派单", () => {
		const d = mod.buildDirective({ ...g, locked: true }, st);
		expect(d).toContain("只做验收与补位");
	});

	test("看板 URL 出现在头部", () => {
		const d = mod.buildDirective({ ...g, viewUrl: "http://127.0.0.1:8765/" }, st);
		expect(d).toContain("http://127.0.0.1:8765/");
	});
});

describe("revertCompletion", () => {
	test("无证据完成被打回 active 并写 hint", () => {
		const root = fresh();
		makeGraph(root, { status: "completed", facts: [{ id: "f001", kind: "note" }] });
		const ok = mod.revertCompletion(root, "no evidence");
		expect(ok).toBe(true);
		const p = JSON.parse(readFileSync(join(root, ".sapper", "project.json"), "utf8"));
		expect(p.status).toBe("active");
		expect(p.completed_at).toBeUndefined();
		const hints = JSON.parse(readFileSync(join(root, ".sapper", "hints.json"), "utf8"));
		expect(hints.length).toBe(1);
		expect(hints[0].content).toContain("no evidence");
	});

	test("非 completed 状态不动", () => {
		const root = fresh();
		makeGraph(root, { status: "active" });
		expect(mod.revertCompletion(root, "x")).toBe(false);
	});
});

describe("checkCommand", () => {
	test("拦截 rm -rf /", () => {
		expect(mod.checkCommand("rm -rf /").allowed).toBe(false);
		expect(mod.checkCommand("rm -rf /").rule).toBe("P-001");
	});
	test("拦截 mkfs", () => {
		expect(mod.checkCommand("mkfs.ext4 /dev/sda1").allowed).toBe(false);
	});
	test("拦截 --noproxy 直连元数据", () => {
		expect(mod.checkCommand("curl --noproxy '*' http://169.254.169.254/").allowed).toBe(false);
	});
	test("放行 nmap", () => {
		expect(mod.checkCommand("nmap -sV 127.0.0.1").allowed).toBe(true);
	});
});

describe("checkTool", () => {
	test("write 命中图目录被拦 P-005", () => {
		const v = mod.checkTool("write", { path: "/p/.sapper/facts/f002.json", content: "x" });
		expect(v.allowed).toBe(false);
		expect(v.rule).toBe("P-005");
	});
	test("edit 命中 journal 被拦 P-007", () => {
		const v = mod.checkTool("edit", { path: "/p/.nuwa/journal.jsonl", old: "a", new: "b" });
		expect(v.allowed).toBe(false);
		expect(v.rule).toBe("P-007");
	});
	test("write 改 project.json 被拦 P-009", () => {
		const v = mod.checkTool("write", { path: "/p/.sapper/project.json" });
		expect(v.allowed).toBe(false);
		expect(v.rule).toBe("P-009");
	});
	test("普通文件写入放行", () => {
		expect(mod.checkTool("write", { path: "/tmp/notes.md" }).allowed).toBe(true);
	});
	test("task 文案含 sapper done 被拦 P-006", () => {
		const v = mod.checkTool("task", { agent: "fujiang", task: "cd /p\nsapper done i001 --fact x" });
		expect(v.allowed).toBe(false);
		expect(v.rule).toBe("P-006");
	});
	test("批量 tasks 数组同样被扫", () => {
		const v = mod.checkTool("task", { tasks: [{ task: "sapper dispatch i002 --model x" }] });
		expect(v.allowed).toBe(false);
		expect(v.rule).toBe("P-006");
	});
	test("bash 直接 sapper done 被拦，claim 放行", () => {
		expect(mod.checkTool("bash", { command: "sapper done i001 --fact x" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: "sapper claim i001 --worker w" }).allowed).toBe(true);
	});
	test("只读工具放行", () => {
		expect(mod.checkTool("read", { path: "/p/.sapper/facts/f001.json" }).allowed).toBe(true);
	});
	test("相对路径与 .. 归一后仍被拦", () => {
		const root = fresh();
		mkdirSync(join(root, ".sapper", "facts"), { recursive: true });
		const v = mod.checkTool("write", { path: "../../.sapper/facts/f002.json" }, join(root, "a", "b"));
		expect(v.rule).toBe("P-005");
	});
	test("符号链接指向图目录被拦", () => {
		const root = fresh();
		const real = join(root, ".sapper", "facts");
		mkdirSync(real, { recursive: true });
		symlinkSync(real, join(root, "alias"));
		const v = mod.checkTool("write", { path: join(root, "alias", "f002.json") });
		expect(v.rule).toBe("P-005");
	});
	test("multi_edit 的 files[] 路径被扫", () => {
		const v = mod.checkTool("multi_edit", { files: [{ path: ".nuwa/journal.jsonl" }] }, "/p");
		expect(v.rule).toBe("P-007");
	});
	test("真实账本 budget/global.jsonl 被拦", () => {
		const v = mod.checkTool("write", { path: "/root/sapper-lab/budget/global.jsonl" });
		expect(v.rule).toBe("P-007");
	});
	test("bash 的 && / sh -c / $() / 反斜杠绕不过", () => {
		for (const cmd of [
			"cd /p && sapper done i001 --fact x",
			"sh -c 'sapper done i001 --fact x'",
			"echo $(sapper done i001 --fact x)",
			"\\sapper done i001 --fact x",
		]) {
			expect(mod.checkTool("bash", { command: cmd }).rule).toBe("P-006");
		}
	});
	test("sapper complete 一律拦截，nuwa complete 放行", () => {
		expect(mod.checkTool("bash", { command: "sapper complete --from f009" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: "sapper complete" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: "nuwa complete --from f009" }).allowed).toBe(true);
	});
	test("bash 写入图/账本路径被拦", () => {
		expect(mod.checkTool("bash", { command: "echo x > .sapper/facts/f1.json" }, "/p").rule).toBe("P-005");
		expect(mod.checkTool("bash", { command: "cp /tmp/x .nuwa/journal.jsonl" }, "/p").rule).toBe("P-007");
		expect(mod.checkTool("bash", { command: "echo x > /tmp/notes.txt" }, "/p").allowed).toBe(true);
	});
	test("sapper --store= 与 -s 形式被拦", () => {
		expect(mod.checkTool("bash", { command: "sapper --store=/p/.sapper done i001 --fact x" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: "sapper -s/p/.sapper done i001 --fact x" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: "sapper -s /p/.sapper done i001 --fact x" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: 'sapper --store="/p/a b/.sapper" done i001 --fact x' }).rule).toBe("P-006");
	});
	test("sapper 全局选项与绝对路径也拦", () => {
		expect(mod.checkTool("bash", { command: "sapper --store /p/.sapper done i001 --fact x" }).rule).toBe("P-006");
		expect(mod.checkTool("bash", { command: "/usr/local/bin/sapper done i001 --fact x" }).rule).toBe("P-006");
	});
	test("apply_patch 正文目标被提取", () => {
		const v = mod.checkTool("apply_patch", { patch: "*** Update File: .sapper/facts/f1.json\n+x" }, "/p");
		expect(v.rule).toBe("P-005");
	});
	test("多级祖先里的符号链接也被解析", () => {
		const root = fresh();
		const real = join(root, ".sapper", "facts");
		mkdirSync(real, { recursive: true });
		mkdirSync(join(root, "a"), { recursive: true });
		symlinkSync(real, join(root, "a", "b"));
		const v = mod.checkTool("write", { path: join(root, "a", "b", "f2.json") });
		expect(v.rule).toBe("P-005");
	});
	test("task 的 context 字段同样被扫", () => {
		const v = mod.checkTool("task", { tasks: [{ agent: "fujiang", context: "接着 sapper done i001 --fact x" }] });
		expect(v.rule).toBe("P-006");
	});
});

describe("readCfg", () => {
	test("非法值回落默认", () => {
		process.env.NUWA_MAX_TURNS = "abc";
		process.env.NUWA_MAX_STALL = "-1";
		process.env.NUWA_IDLE_LIMIT = "";
		const c = mod.readCfg();
		expect(c.maxTurns).toBe(120);
		expect(c.maxStall).toBe(10);
		expect(c.maxIdle).toBe(3);
		delete process.env.NUWA_MAX_TURNS;
		delete process.env.NUWA_MAX_STALL;
		delete process.env.NUWA_IDLE_LIMIT;
	});

	test("合法值生效", () => {
		process.env.NUWA_MAX_TURNS = "7";
		expect(mod.readCfg().maxTurns).toBe(7);
		delete process.env.NUWA_MAX_TURNS;
	});
});
