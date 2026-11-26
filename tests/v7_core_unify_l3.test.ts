import { afterEach, describe, expect, test } from "bun:test";
import {
	closeSync,
	existsSync,
	ftruncateSync,
	mkdirSync,
	mkdtempSync,
	openSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	NUWA_SUBCOMMANDS,
	NuwaUnifiedEngine,
	isTerminalProjectState,
	loadStateZeroWrite,
	terminalStatusOf,
} from "../core/engine";
import {
	DispatchBridgeStore,
	MAX_OMP_TASK_FILE_BYTES,
	expandDispatchContextValue,
	expandEvalCodePlaceholders,
	expandPlaceholdersPlain,
	handleBeforeSubagentSpawn,
	handleToolCallDispatch,
	handleToolExecutionEnd,
	handleToolResult,
	matchesSpawnCandidate,
	parseEvalAgentCalls,
	readTaskFileForDispatch,
} from "../omp/dispatch-bridge";
import { loadCalibrationRecords, recordPrediction } from "../omp/calibration";
import { readFactEvidenceLog, recordToolExecution } from "../omp/evidence";
import { upsertSessionRole } from "../omp/session-vault";
import { saveStateToSqlite, sqliteDbPath } from "../omp/sqlite-store";
import { SubagentWatchdog, loadState, saveState, withLock } from "../omp/storage";
import { runL3LiveSuite, scanSecretsInWorkspaceAndLogs } from "../benchmarks/l3-live/run-l3-eval";
import { requestViaSocks5Http, startLocalSocks5Server } from "../benchmarks/l3-live/socks5-server";

const tmpDirs: string[] = [];
const savedEnv: Record<string, string | undefined> = {};

function setEnvTemp(key: string, val: string | undefined): void {
	if (!(key in savedEnv)) savedEnv[key] = process.env[key];
	if (val === undefined) delete process.env[key];
	else process.env[key] = val;
}

function makeWorkspace(prefix = "nuwa-v7-core-l3-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	mkdirSync(join(dir, ".git"), { recursive: true });
	writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
	tmpDirs.push(dir);
	return dir;
}

afterEach(() => {
	for (const [k, v] of Object.entries(savedEnv)) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
	for (const k of Object.keys(savedEnv)) delete savedEnv[k];
	while (tmpDirs.length > 0) {
		const d = tmpDirs.pop()!;
		rmSync(d, { recursive: true, force: true });
	}
});

describe("NuwaUnifiedEngine 单核合一引擎：12 工具、HostHooks 与 #53/#54/#55 全量边界", () => {
	test("12 工具全生命周期、f1000+ 精确 evidenceRef、含口令 egress 零明文泄露与反自证机械校准结算", async () => {
		const agentHome = makeWorkspace("nuwa-v7-home-");
		setEnvTemp("PI_AGENT_HOME", agentHome);
		const ws = makeWorkspace("nuwa-v7-lifecycle-");

		let uiRefreshCount = 0;
		let liveTokens = 6789;
		const engine = new NuwaUnifiedEngine({
			cwd: ws,
			sessionId: "sess-v7-main",
			agentHome,
			hooks: {
				onRefreshUi: () => {
					uiRefreshCount += 1;
				},
				getLiveTokens: () => liveTokens,
			},
		});

		expect(engine.listTools().length).toBe(12);
		expect(NUWA_SUBCOMMANDS.length).toBe(28);

		// 1. nuwa_init
		const initRes = await engine.callTool("nuwa_init", {
			target: "http://127.0.0.1:19080",
			mode: "pentest",
			goal: "单核引擎全链路验证",
			root: ws,
			autoStart: true,
		});
		expect(initRes.isError).toBe(false);
		expect(initRes.details.autoStartSkipped).toBe(true);
		expect(uiRefreshCount).toBeGreaterThan(0);

		// 写入敏感凭据供后续报告零泄露校验
		const secretJwt = "eyJhbGciOiJIUzI1NiJ9.v7_ultra_secret_payload_998811.sig_part";
		upsertSessionRole(ws, { role: "tenant_admin", bearer: secretJwt });

		// 2. nuwa_plan + 含口令 egress 代理 URL 零明文泄露校验
		const rawSecretProxy = "socks5h://proxyadmin:top_secret_proxy_pw_7766@127.0.0.1:1080";
		const planRes = await engine.callTool("nuwa_plan", {
			phase: "vuln",
			egress: rawSecretProxy,
			intents: [
				{
					title: "校验管理接口未授权访问",
					detail: "探测 /api/v2/admin/export",
					expectedKind: "vuln",
				},
			],
			batch_tasks: [
				{
					id: "bt-1",
					targetKey: "/api/v2/admin/export",
					task: "curl -sS -i http://[TARGET]/api/v2/admin/export",
				},
			],
			root: ws,
		});
		expect(planRes.isError).toBe(false);
		const addedIds = planRes.details.added as string[];
		expect(addedIds.length).toBeGreaterThanOrEqual(1);
		const vulnIntentId = addedIds[addedIds.length - 1]!;

		const planSerialized = JSON.stringify(planRes);
		expect(planSerialized).not.toContain("top_secret_proxy_pw_7766");
		expect(planSerialized).toContain("***");
		expect(readFileSync(join(ws, ".nuwa", "state.json"), "utf8")).not.toContain("top_secret_proxy_pw_7766");

		// 3. nuwa_frontier & nuwa_claim（同样验证含口令 egress 掩码脱敏）
		const frontierRes = await engine.callTool("nuwa_frontier", { limit: 20, root: ws });
		expect(frontierRes.isError).toBe(false);
		expect((frontierRes.details.ids as string[]).includes(vulnIntentId)).toBe(true);

		const claimRes = await engine.callTool("nuwa_claim", {
			id: vulnIntentId,
			worker: "fujiang",
			egress: rawSecretProxy,
			root: ws,
		});
		expect(claimRes.isError).toBe(false);
		expect(claimRes.content[0]!.text).not.toContain("top_secret_proxy_pw_7766");
		expect(claimRes.content[0]!.text).toContain("127.0.0.1:1080");

		// 4. 构造 seq.fact = 999，测试 f1000+ 非截断精确 evidenceRef 落盘与反自证校准机械结算
		withLock(ws, () => {
			const s = loadState(ws)!;
			s.seq.fact = 999;
			saveState(ws, s);
		});
		recordPrediction(ws, {
			predictionId: "pred-v7-f1000",
			intentId: vulnIntentId,
			taskCategory: "exploit",
			modelId: "gemini-4-carbon-high",
			predictedConfidence: 0.88,
			estimatedTokens: 2000,
			note: "预测存在导出接口未授权访问",
		});

		const candCmd = "curl -sS -i http://127.0.0.1:19080/api/v2/admin/export";
		const candOut = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"users":[{"id":1,"email":"root@corp.internal"}],"exportId":"exp-901"}';
		recordToolExecution(ws, { tool: "bash", command: candCmd, output: candOut, agentName: "fujiang" });

		const commitCand = await engine.callTool("nuwa_commit", {
			id: vulnIntentId,
			title: "管理导出接口未授权访问",
			detail: "匿名直接导出租户用户列表",
			command: candCmd,
			output: candOut,
			raw_response: candOut,
			save_evidence_log: true,
			root: ws,
		});
		expect(commitCand.isError).toBe(false);
		expect(commitCand.details.factId).toBe("f1000");
		expect(commitCand.details.evidenceRef).toBe(".nuwa/evidence/f1000.log");
		expect(commitCand.details.verifyStage).toBe("candidate");
		expect(existsSync(join(ws, ".nuwa", "evidence", "f1000.log"))).toBe(true);
		expect(readFactEvidenceLog(ws, ".nuwa/evidence/f1000.log")).toContain("fact_id: f1000");
		expect(loadState(ws)?.facts.f1000?.evidenceRef).toBe(".nuwa/evidence/f1000.log");

		// candidate 阶段绝不提前结算校准预测（反自证铁律）
		expect(loadCalibrationRecords(ws).find((r) => r.predictionId === "pred-v7-f1000")?.settled).toBe(false);

		// 双盲复验确认后自动触发机械结算
		const verifyIntentId = String(commitCand.details.verifyIntent);
		expect(verifyIntentId).toMatch(/^i\d{3,}$/);
		await Bun.sleep(5);
		await engine.callTool("nuwa_claim", { id: verifyIntentId, worker: "nuwa-verifier", root: ws });
		const verCmd = "curl -sS -i http://127.0.0.1:19080/api/v2/admin/export?page=1";
		const verOut = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"users":[{"id":1,"email":"root@corp.internal"}],"verified":true}';
		recordToolExecution(ws, { tool: "bash", command: verCmd, output: verOut, agentName: "nuwa-verifier" });

		const commitVer = await engine.callTool("nuwa_commit", {
			id: verifyIntentId,
			kind: "vuln",
			title: "[Verified] 管理导出接口未授权访问确认",
			detail: "独立复验确认正向 200 业务结构且排除假阳性",
			command: verCmd,
			output: verOut,
			save_evidence_log: true,
			root: ws,
		});
		expect(commitVer.isError).toBe(false);
		expect(commitVer.details.factId).toBe("f1001");
		expect(commitVer.details.evidenceRef).toBe(".nuwa/evidence/f1001.log");
		expect(loadState(ws)?.facts.f1000?.verifyStage).toBe("confirmed");

		const settledCalib = loadCalibrationRecords(ws).find((r) => r.predictionId === "pred-v7-f1000");
		expect(settledCalib?.settled).toBe(true);
		expect(settledCalib?.outcome).toBe(1);
		expect(settledCalib?.source).toBe("verifier-gate");

		// 补充校验假阳性门禁自动降级 + 机械校准 outcome=0 结算 + nuwa_stop 软暂停再恢复
		const fpPlan = await engine.callTool("nuwa_plan", {
			phase: "vuln",
			intents: [{ title: "验证假阳性 Soft-404 自动降级", expectedKind: "vuln" }],
			root: ws,
		});
		const fpIntentId = (fpPlan.details.added as string[])[0]!;
		recordPrediction(ws, {
			predictionId: "pred-v7-fp",
			intentId: fpIntentId,
			taskCategory: "exploit",
			modelId: "gemini-4-carbon-high",
			predictedConfidence: 0.9,
			estimatedTokens: 1000,
		});
		await engine.callTool("nuwa_claim", { id: fpIntentId, worker: "fujiang", root: ws });
		const fpHtml = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!doctype html><html><title>404 Not Found</title><body>Page Not Found</body></html>";
		const fpCommit = await engine.callTool("nuwa_commit", {
			id: fpIntentId,
			kind: "vuln",
			title: "疑似未授权页面",
			command: "curl -sS -i http://127.0.0.1:19080/nonexistent",
			output: fpHtml,
			raw_response: fpHtml,
			auto_downgrade: true,
			root: ws,
		});
		expect(fpCommit.isError).toBe(false);
		expect(fpCommit.details.falsePositive).toBe(true);
		const fpCalib = loadCalibrationRecords(ws).find((r) => r.predictionId === "pred-v7-fp");
		expect(fpCalib?.settled).toBe(true);
		expect(fpCalib?.outcome).toBe(0);
		expect(fpCalib?.isFalsePositive).toBe(true);
		expect(fpCalib?.source).toBe("verifier-gate");

		// 校验免确认软暂停与恢复
		const pauseRes = await engine.callTool("nuwa_stop", { pause: true, reason: "阶段检查软暂停", root: ws });
		expect(pauseRes.isError).toBe(false);
		expect(pauseRes.details.paused).toBe(true);
		const resumeAfterPause = await engine.callTool("nuwa_init", { resume: true, root: ws });
		expect(resumeAfterPause.isError).toBe(false);

		// 5. nuwa_expand（验证含口令 egress 脱敏）& nuwa_kb & nuwa_flag
		const expRes = await engine.callTool("nuwa_expand", { egress: rawSecretProxy, root: ws });
		expect(expRes.isError).toBe(false);
		expect(JSON.stringify(expRes)).not.toContain("top_secret_proxy_pw_7766");

		const kbRes = await engine.callTool("nuwa_kb", { query: "spring", kind: "auto", limit: 3 });
		expect(kbRes.isError).toBe(false);
		expect(kbRes.content[0]!.text.length).toBeGreaterThan(10);

		const flagCmd = "curl -sS http://127.0.0.1:19080/flag";
		const flagOut = "flag{v7_unified_engine_ok}";
		recordToolExecution(ws, { tool: "bash", command: flagCmd, output: flagOut });
		const flagRes = await engine.callTool("nuwa_flag", {
			value: flagOut,
			command: flagCmd,
			output: flagOut,
			root: ws,
		});
		expect(flagRes.isError).toBe(false);
		expect(flagRes.details.fact).toBe("f1003");

		// 6. nuwa_complete 验收同步实时 Token，并防降级为 sealed_negative
		liveTokens = 13579;
		const compRes = await engine.callTool("nuwa_complete", { root: ws });
		expect(compRes.isError).toBe(false);
		expect(compRes.details.ok).toBe(true);
		expect(loadState(ws)?.project.status).toBe("completed");
		expect(loadState(ws)?.runtime.tokens).toBe(13579);

		// completed 终态禁止被 seal=true 降级覆盖
		const downgradeAttempt = await engine.callTool("nuwa_complete", {
			seal: true,
			reason: "试图把已完成项目篡改为负向封盘",
			root: ws,
		});
		expect(downgradeAttempt.isError).toBe(true);
		expect(loadState(ws)?.project.status).toBe("completed");

		// 7. nuwa_report 全格式导出且 Vault 凭据零明文泄露
		for (const fmt of ["md", "json", "sarif", "timeline"] as const) {
			const rep = await engine.callTool("nuwa_report", {
				write: true,
				format: fmt,
				bundle: fmt === "md",
				root: ws,
			});
			expect(rep.isError).toBe(false);
			expect(rep.content[0]!.text).not.toContain(secretJwt);
		}
	});

	test("多模式（ctf/ops/coding/audit/pentest）无默认 mode 精确探测复用、nuwa_status 严格零写盘及半封盘修齐", async () => {
		const agentHome = makeWorkspace("nuwa-v7-modes-home-");
		setEnvTemp("PI_AGENT_HOME", agentHome);

		// 1. 测试 coding / audit / ops 本地目录目标在未显式传 mode 时精确复用存量项目而不误按默认 ctf 报错
		for (const testMode of ["coding", "ops", "audit", "pentest", "ctf"] as const) {
			const projDir = makeWorkspace(`nuwa-v7-mode-${testMode}-`);
			const callerCwd = makeWorkspace(`nuwa-v7-caller-${testMode}-`);
			const targetInput =
				testMode === "coding" || testMode === "ops" || testMode === "audit"
					? projDir
					: `http://127.0.0.1:${19100 + testMode.length}`;

			const eng = new NuwaUnifiedEngine({ cwd: callerCwd, sessionId: `sess-mode-${testMode}`, agentHome });
			const created = await eng.callTool("nuwa_init", {
				target: targetInput,
				mode: testMode,
				...(testMode === "coding" || testMode === "ops" || testMode === "audit" ? { root: projDir } : {}),
			});
			expect(created.isError).toBe(false);
			const createdRoot = String(created.details.root);

			// 新引擎实例不传 root、不传 mode，仅传 target + resume=true，必须精确命中原模式项目
			const engReopen = new NuwaUnifiedEngine({ cwd: callerCwd, sessionId: `sess-mode-${testMode}`, agentHome });
			const reopened = await engReopen.callTool("nuwa_init", {
				target: targetInput,
				resume: true,
			});
			expect(reopened.isError).toBe(false);
			expect(resolve(String(reopened.details.root))).toBe(resolve(createdRoot));
			expect(loadState(createdRoot)?.project.mode).toBe(testMode);
		}

		// 2. 验证 nuwa_status 在 JSON 与 SQLite 后端下全部 4 种查询模式严格零磁盘写入（不创建 wal/shm、不改 mtime）
		const statusWs = makeWorkspace("nuwa-v7-status-zerowrite-");
		const statusEng = new NuwaUnifiedEngine({ cwd: statusWs, sessionId: "sess-zerowrite", agentHome });
		await statusEng.callTool("nuwa_init", { target: "http://127.0.0.1:19200", mode: "pentest", root: statusWs });
		await statusEng.callTool("nuwa_report", { write: true, format: "md", root: statusWs });

		const jsonPath = join(statusWs, ".nuwa", "state.json");
		const jsonMtime0 = statSync(jsonPath).mtimeMs;
		await Bun.sleep(20);

		for (const args of [
			{ root: statusWs },
			{ root: statusWs, raw: true, format: "json" },
			{ root: statusWs, inspect_intent: "i001" },
			{ root: statusWs, archive_query: "19200" },
		]) {
			const r = await statusEng.callTool("nuwa_status", args);
			expect(r.isError).toBe(false);
			expect(r.details.readonly).toBe(true);
		}
		expect(statSync(jsonPath).mtimeMs).toBe(jsonMtime0);
		expect(existsSync(join(statusWs, ".nuwa", "state.lock"))).toBe(false);

		// 切换为 SQLite 权威库并清除 -wal/-shm（checkpoint），验证只读 nuwa_status 不会生成 -wal/-shm
		const curSt = loadState(statusWs)!;
		saveStateToSqlite(statusWs, curSt);
		const dbFile = sqliteDbPath(statusWs);
		expect(existsSync(dbFile)).toBe(true);
		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		const filesBeforeSqlStatus = readdirSync(join(statusWs, ".nuwa")).sort();
		const dbMtime0 = statSync(dbFile).mtimeMs;
		await Bun.sleep(20);

		const sqlStatusRes = await statusEng.callTool("nuwa_status", { root: statusWs });
		expect(sqlStatusRes.isError).toBe(false);
		expect(statSync(dbFile).mtimeMs).toBe(dbMtime0);
		expect(readdirSync(join(statusWs, ".nuwa")).sort()).toEqual(filesBeforeSqlStatus);
		setEnvTemp("NUWA_STORAGE_BACKEND", undefined);

		// 3. 验证半封盘状态（runtime=sealed_negative 但 project=active）自动修齐，以及修齐后再次重入严格零写盘
		const halfSealWs = makeWorkspace("nuwa-v7-half-seal-");
		const halfEng = new NuwaUnifiedEngine({ cwd: halfSealWs, sessionId: "sess-half", agentHome });
		await halfEng.callTool("nuwa_init", { target: "http://127.0.0.1:19201", mode: "ctf", root: halfSealWs });
		withLock(halfSealWs, () => {
			const s = loadState(halfSealWs)!;
			s.project.status = "active";
			s.runtime.status = "sealed_negative";
			saveState(halfSealWs, s);
		});
		expect(isTerminalProjectState(loadStateZeroWrite(halfSealWs))).toBe(true);
		expect(terminalStatusOf(loadStateZeroWrite(halfSealWs)!)).toBe("sealed_negative");

		const alignRes = await halfEng.callTool("nuwa_init", { root: halfSealWs, resume: true });
		expect(alignRes.isError).toBe(false);
		expect(alignRes.details.status).toBe("sealed_negative");
		expect(loadStateZeroWrite(halfSealWs)?.project.status).toBe("sealed_negative");

		// 修齐之后再次 resume（无论是否跨会话）均严格零写盘，且斜杠命令 /nuwa stop / pause / resume 全部拦截终态
		const alignedMtime = statSync(join(halfSealWs, ".nuwa", "state.json")).mtimeMs;
		await Bun.sleep(20);
		const secondRo = await halfEng.callTool("nuwa_init", { root: halfSealWs, resume: true });
		expect(secondRo.details.readonly).toBe(true);
		expect(statSync(join(halfSealWs, ".nuwa", "state.json")).mtimeMs).toBe(alignedMtime);

		const notifications: Array<{ msg: string; level: string }> = [];
		const slashStop = await halfEng.executeSlashCommand("stop 试图降级终态", {
			onNotify: (msg, level) => notifications.push({ msg, level }),
		});
		expect(slashStop.level).toBe("error");
		expect(loadStateZeroWrite(halfSealWs)?.project.status).toBe("sealed_negative");
	});
});

describe("omp/dispatch-bridge.ts 独立异步派单桥接、4MiB taskFile、eval 与看门狗精确协调", () => {
	test("覆盖空数组拦截、4MiB 超限 taskFile、context 纯 URL 无头展开、async.state=running 乱序竞态与 eval Scope 先展开后校验", async () => {
		const agentHome = makeWorkspace("nuwa-v7-bridge-home-");
		setEnvTemp("PI_AGENT_HOME", agentHome);
		const ws = makeWorkspace("nuwa-v7-bridge-ws-");

		const engine = new NuwaUnifiedEngine({ cwd: ws, sessionId: "sess-bridge", agentHome });
		await engine.callTool("nuwa_init", {
			target: "http://127.0.0.1:19300",
			mode: "pentest",
			root: ws,
		});
		await engine.callTool("nuwa_plan", {
			phase: "surface",
			intents: [{ title: "第二条并行探测意图", detail: "测试双任务乱序派生" }],
			root: ws,
		});

		const store = new DispatchBridgeStore();
		const mainCtx = {
			cwd: ws,
			sessionId: "sess-bridge",
			agent: { kind: "main", id: "main-0", name: "main", depth: 0 },
			sessionManager: { getSessionId: () => "sess-bridge" },
		};

		// 1. 纯函数边界：context 纯 URL 无头展开（绝不插入派单说明头破坏 URL）与 spawnKey 候选匹配
		expect(expandPlaceholdersPlain("https://TARGET/v1/users", { url: "http://127.0.0.1:19300", host: "127.0.0.1" })).toBe(
			"http://127.0.0.1:19300/v1/users",
		);
		const ctxExp = expandDispatchContextValue(
			{ endpoint: "https://TARGET/api/graphql", nested: ["[HOST]:19300"] },
			{ url: "http://127.0.0.1:19300", host: "127.0.0.1" },
		);
		expect(ctxExp.changed).toBe(true);
		expect((ctxExp.value as Record<string, unknown>).endpoint).toBe("http://127.0.0.1:19300/api/graphql");
		expect(((ctxExp.value as Record<string, unknown>).nested as string[])[0]).toBe("127.0.0.1:19300");

		expect(matchesSpawnCandidate("lbl-a", "lbl-a")).toBe(true);
		expect(matchesSpawnCandidate("lbl-a", "lbl-a-0")).toBe(true);
		expect(matchesSpawnCandidate("lbl-a", "root-session.lbl-a")).toBe(true);
		expect(matchesSpawnCandidate("lbl-a", "lbl-alpha")).toBe(false);

		const parsedCalls = parseEvalAgentCalls(
			'await Promise.all([agent({ agent: "fujiang", label: "a1", prompt: "probe 1" }), agent({ agent: "nuwa-verifier", name: "v1", task: "" })]);',
		);
		expect(parsedCalls.length).toBe(2);
		expect(parsedCalls[0]!.label).toBe("a1");
		expect(parsedCalls[1]!.hasEmptyPrompt).toBe(true);

		// 2. 空 tasks: [] 数组拦截 & 超过 4 MiB 的稀疏大文件 taskFile 拦截
		const emptyTasksRes = handleToolCallDispatch(
			store,
			{ toolName: "task", toolCallId: "tc-empty", input: { tasks: [] } },
			mainCtx,
		);
		expect(emptyTasksRes && "block" in emptyTasksRes && emptyTasksRes.block).toBe(true);

		const hugeFile = join(ws, "huge-task.md");
		const fd = openSync(hugeFile, "w");
		ftruncateSync(fd, MAX_OMP_TASK_FILE_BYTES + 1024);
		closeSync(fd);
		expect(readTaskFileForDispatch(hugeFile).tooLarge).toBe(true);

		const hugeBlock = handleToolCallDispatch(
			store,
			{ toolName: "task", toolCallId: "tc-huge", input: { agent: "fujiang", taskFile: hugeFile } },
			mainCtx,
		);
		expect(hugeBlock && "block" in hugeBlock && hugeBlock.block).toBe(true);
		expect(hugeBlock && "reason" in hugeBlock ? hugeBlock.reason : "").toContain("4 MiB");

		// 3. 合法 taskFile 含 [TARGET] + context 纯 URL 展开：重写为内联 task 并删除原 taskFile 键
		const validTaskFile = join(ws, "valid-task.md");
		writeFileSync(validTaskFile, "[女娲派单 i001] 探测 http://TARGET/api/health 状态", "utf8");
		const rewritten = handleToolCallDispatch(
			store,
			{
				toolName: "task",
				toolCallId: "tc-tf-ok",
				input: {
					agent: "fujiang",
					taskFile: validTaskFile,
					context: { apiBase: "https://TARGET/api" },
				},
			},
			mainCtx,
		) as { input?: Record<string, unknown> };
		expect(rewritten?.input?.taskFile).toBeUndefined();
		expect(String(rewritten?.input?.task ?? "")).toContain("http://127.0.0.1:19300/api/health");
		expect((rewritten?.input?.context as Record<string, unknown>)?.apiBase).toBe("http://127.0.0.1:19300/api");
		handleToolExecutionEnd(store, { toolName: "task", toolCallId: "tc-tf-ok", result: { details: { results: [] } } }, mainCtx);

		// 4. omp 18.16.0 默认 async.state === "running" 先返回 progress[] 后乱序触发 before_subagent_spawn
		const wd = new SubagentWatchdog(ws);
		wd.startTask({ taskId: "existing-bg-worker", agent: "fujiang" });
		expect(wd.activeCount()).toBe(1);

		handleToolCallDispatch(
			store,
			{
				toolName: "task",
				toolCallId: "tc-async-race",
				input: {
					tasks: [
						{ agent: "fujiang", task: "[女娲派单 i001] 第一条异步侦察任务 payload-alpha" },
						{ agent: "nuwa-verifier", task: "[女娲派单 i002] 第二条异步复验任务 payload-beta" },
					],
				},
			},
			mainCtx,
		);

		handleToolExecutionEnd(
			store,
			{
				toolName: "task",
				toolCallId: "tc-async-race",
				result: {
					details: {
						async: { state: "running" },
						progress: [
							{ index: 0, id: "swift-falcon-01", status: "pending" },
							{ index: 1, id: "calm-otter-02", status: "pending" },
						],
						results: [],
					},
				},
			},
			mainCtx,
		);
		// 绝不能把正在运行的 existing-bg-worker 误杀！且两条异步待派发条目仍保留在缓冲中
		expect(wd.activeCount()).toBe(1);
		expect(store.getPendingCount(ws)).toBe(2);

		// 乱序派生：index=1 的 calm-otter-02 先到达，index=0 的 swift-falcon-01 后到达
		const spBeta = handleBeforeSubagentSpawn(
			store,
			{ type: "before_subagent_spawn", agent: "nuwa-verifier", invocationKind: "task", spawnKey: "calm-otter-02" },
			mainCtx,
		);
		const spAlpha = handleBeforeSubagentSpawn(
			store,
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "task", spawnKey: "swift-falcon-01" },
			mainCtx,
		);
		expect(spBeta && !("block" in spBeta) ? spBeta.task : "").toContain("payload-beta");
		expect(spAlpha && !("block" in spAlpha) ? spAlpha.task : "").toContain("payload-alpha");
		expect(wd.activeCount()).toBe(3);

		// 先完成其中一条 swift-falcon-01，确保一对一精确回收而不误释放另外两条
		handleToolResult(
			store,
			{
				toolName: "task",
				toolCallId: "tc-async-race",
				result: { details: { results: [{ id: "swift-falcon-01", status: "completed" }] } },
			},
			mainCtx,
		);
		expect(wd.activeCount()).toBe(2);
		expect(wd.getTask("swift-falcon-01")?.status).toBe("completed");
		expect(wd.getTask("calm-otter-02")?.status).toBe("running");

		handleToolExecutionEnd(
			store,
			{
				toolName: "task",
				toolCallId: "tc-async-race",
				result: {
					details: {
						results: [
							{ id: "calm-otter-02", status: "completed" },
							{ id: "existing-bg-worker", status: "completed" },
						],
					},
				},
			},
			mainCtx,
		);
		expect(wd.activeCount()).toBe(0);

		// 5. eval 先展开 [TARGET] 再过 Scope 校验（合法目标放行重写；真实越界域名仍被拦截！）
		const evalOutOfScope = handleToolCallDispatch(
			store,
			{
				toolName: "eval",
				toolCallId: "tc-eval-evil",
				input: { code: 'agent({ agent: "fujiang", prompt: "curl http://evil.attacker.invalid/pwn" });' },
			},
			mainCtx,
		);
		expect(evalOutOfScope && "block" in evalOutOfScope && evalOutOfScope.block).toBe(true);

		const evalInScope = handleToolCallDispatch(
			store,
			{
				toolName: "eval",
				toolCallId: "tc-eval-good",
				input: {
					code: 'agent({ agent: "fujiang", label: "ev-1", prompt: "[女娲派单 i001] 测试 http://TARGET/api/v1/ping" });',
				},
			},
			mainCtx,
		) as { input?: { code?: string } };
		expect(evalInScope?.input?.code).toContain("http://127.0.0.1:19300/api/v1/ping");

		// 外层 eval 结束不应清理尚未派生的 ev-1，且同一 toolCallId 同时经 end 与 result 触发时证据账本不重复记账
		handleToolExecutionEnd(store, { toolName: "eval", toolCallId: "tc-eval-good", isError: false }, mainCtx);
		const evSpawn = handleBeforeSubagentSpawn(
			store,
			{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "eval", spawnKey: "outer.ev-1" },
			mainCtx,
		);
		expect(evSpawn && !("block" in evSpawn) ? evSpawn.task : "").toContain("127.0.0.1:19300/api/v1/ping");

		const ledgerPath = join(ws, ".nuwa", "exec-ledger.jsonl");
		const beforeLines = existsSync(ledgerPath) ? readFileSync(ledgerPath, "utf8").trim().split("\n").filter(Boolean).length : 0;
		const bashEv = {
			toolName: "bash",
			toolCallId: "tc-bash-dedup-1",
			input: { command: "curl -sS http://127.0.0.1:19300/ping" },
			result: { stdout: "pong-12345678" },
		};
		handleToolExecutionEnd(store, bashEv, mainCtx);
		handleToolResult(store, bashEv, mainCtx);
		const afterLines = readFileSync(ledgerPath, "utf8").trim().split("\n").filter(Boolean).length;
		expect(afterLines - beforeLines).toBe(1);

		store.shutdownSession(ws, "sess-bridge");
		expect(wd.activeCount()).toBe(0);
	});
});

describe("benchmarks/l3-live/socks5-server.ts 真实 TCP RFC 1928/1929 握手与本地白名单隔离", () => {
	test("验证 ATYP=0x03 域名透传、ATYP=0x01 IPv4、0x00/0x02 认证及公网/未授权端口 REP=0x02 阻断与零 Socket 泄漏", async () => {
		const targetHttp = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req: Request) {
				const u = new URL(req.url);
				return Response.json({ ok: true, path: u.pathname, hostHeader: req.headers.get("host") });
			},
		});

		const socksNoAuth = await startLocalSocks5Server({
			allowedPorts: [targetHttp.port],
			domainMap: { "l3-target.internal": "127.0.0.1" },
		});
		const socksAuth = await startLocalSocks5Server({
			allowedPorts: [targetHttp.port],
			domainMap: { "l3-target.internal": "127.0.0.1" },
			auth: { username: "secop", password: "correct-horse-battery" },
		});

		try {
			// 0. 严禁绑定非 127.0.0.1 或将域名映射到公网 IP
			await expect(startLocalSocks5Server({ host: "0.0.0.0" })).rejects.toThrow("127.0.0.1");
			await expect(
				startLocalSocks5Server({ domainMap: { "bad.internal": "8.8.8.8" } }),
			).rejects.toThrow("127.0.0.1");

			// 1. ATYP=0x03 域名透传访问白名单靶机成功
			const domRes = await requestViaSocks5Http({
				proxyPort: socksNoAuth.port,
				targetHost: "l3-target.internal",
				targetPort: targetHttp.port,
				addressType: "domain",
				httpPath: "/hello-socks5h",
			});
			expect(domRes.ok).toBe(true);
			expect(domRes.socksReplyCode).toBe(0x00);
			expect(domRes.httpStatus).toBe(200);
			expect(domRes.body).toContain("/hello-socks5h");

			// 2. ATYP=0x01 IPv4 127.0.0.1 白名单端口成功
			const ipRes = await requestViaSocks5Http({
				proxyPort: socksNoAuth.port,
				targetHost: "127.0.0.1",
				targetPort: targetHttp.port,
				addressType: "ipv4",
				httpPath: "/hello-ipv4",
			});
			expect(ipRes.ok).toBe(true);
			expect(ipRes.httpStatus).toBe(200);

			// 3. 安全红线反例：公网 IP (8.8.8.8)、未授权公网域名 (example.com)、未加入白名单的本机端口均返回 REP=0x02 阻断
			const blockPublicIp = await requestViaSocks5Http({
				proxyPort: socksNoAuth.port,
				targetHost: "8.8.8.8",
				targetPort: targetHttp.port,
				addressType: "ipv4",
			});
			expect(blockPublicIp.ok).toBe(false);
			expect(blockPublicIp.socksReplyCode).toBe(0x02);

			const blockForeignDomain = await requestViaSocks5Http({
				proxyPort: socksNoAuth.port,
				targetHost: "evil.example.com",
				targetPort: targetHttp.port,
				addressType: "domain",
			});
			expect(blockForeignDomain.ok).toBe(false);
			expect(blockForeignDomain.socksReplyCode).toBe(0x02);

			const disallowedPort = targetHttp.port === 65530 ? 65529 : targetHttp.port + 1;
			const blockPort = await requestViaSocks5Http({
				proxyPort: socksNoAuth.port,
				targetHost: "127.0.0.1",
				targetPort: disallowedPort,
				addressType: "ipv4",
			});
			expect(blockPort.ok).toBe(false);
			expect(blockPort.socksReplyCode).toBe(0x02);

			const st1 = socksNoAuth.getStats();
			expect(st1.socks5HandshakeCount).toBe(2);
			expect(st1.socks5DomainRequests).toBe(2); // l3-target.internal + evil.example.com
			expect(st1.blockedCount).toBe(3);

			// 4. RFC 1929 用户名/密码 0x02 认证：错误密码被拒，正确密码放行
			const badAuth = await requestViaSocks5Http({
				proxyPort: socksAuth.port,
				targetHost: "l3-target.internal",
				targetPort: targetHttp.port,
				auth: { username: "secop", password: "wrong-password" },
			});
			expect(badAuth.ok).toBe(false);
			expect(badAuth.authReplyCode).toBe(0x01);

			const okAuth = await requestViaSocks5Http({
				proxyPort: socksAuth.port,
				targetHost: "l3-target.internal",
				targetPort: targetHttp.port,
				auth: { username: "secop", password: "correct-horse-battery" },
				httpPath: "/authed-check",
			});
			expect(okAuth.ok).toBe(true);
			expect(okAuth.authReplyCode).toBe(0x00);
			expect(okAuth.httpStatus).toBe(200);
			expect(socksAuth.getStats().authFailureCount).toBe(1);
			expect(socksAuth.getStats().authSuccessCount).toBe(1);
		} finally {
			await socksNoAuth.stop();
			await socksAuth.stop();
			targetHttp.stop(true);
		}

		expect(socksNoAuth.getStats().activeSocketCount).toBe(0);
		expect(socksAuth.getStats().activeSocketCount).toBe(0);
	});
});

describe("L3 真实进程树门禁 runL3LiveSuite() 端到端三场景全绿验收", () => {
	test("真实通过 Bun.spawn 拉起 bin/nuwa-autonomous + mock-omp-bin 跑通全部 3 大场景且硬门禁 100% 达标", async () => {
		const summary = await runL3LiveSuite();

		expect(summary.scenarios.length).toBe(3);
		for (const sc of summary.scenarios) {
			if (!sc.passed) {
				throw new Error(`L3 场景 ${sc.id} 失败: ${sc.error ?? sc.detail}`);
			}
			expect(sc.passed).toBe(true);
			expect(sc.exitCode).toBe(0);
		}

		expect(summary.allPassed).toBe(true);
		expect(summary.gates.allPassed).toBe(true);
		expect(summary.socks5HandshakeCount).toBeGreaterThan(0);
		expect(summary.socks5DomainRequests).toBeGreaterThan(0);
		expect(summary.modelApiRequests).toBeGreaterThanOrEqual(3);
		expect(summary.modelApiErrors).toBe(0);
		expect(summary.vaultLeakCount).toBe(0);

		// CLI 参数契约校验（--help）
		const runnerPath = resolve(import.meta.dir, "..", "benchmarks", "l3-live", "run-l3-eval.ts");
		const bunBin = Bun.which("bun") ?? "bun";
		const helpProc = Bun.spawn([bunBin, runnerPath, "--help"], {
			cwd: resolve(import.meta.dir, ".."),
			stdout: "pipe",
			stderr: "pipe",
		});
		const [helpOut, helpCode] = await Promise.all([new Response(helpProc.stdout).text(), helpProc.exited]);
		expect(helpCode).toBe(0);
		expect(helpOut).toContain("l3-async-socks5-finding");
		expect(helpOut).toContain("l3-hardened-seal-noop");
		expect(helpOut).toContain("l3-stopped-resume-migrate");
	}, 60_000);
});

describe("Boost 异构审查 #73 全量边界反例回归（P1-1 ~ P1-7）", () => {
	test("P1-1 & P1-2: nuwa_report(finalize_phase=true) 严禁降级/覆写终态、斜杠命令终态拦截与损坏 autoexec.json 下 100% 零写盘", async () => {
		const agentHome = makeWorkspace("nuwa-v7-r73-home-");
		setEnvTemp("PI_AGENT_HOME", agentHome);

		// 1a-1: status=completed 且 phase=report 时调 nuwa_report(finalize_phase=true) 严禁降级为 sealed_negative
		const compWs = makeWorkspace("nuwa-v7-r73-comp-");
		const compEng = new NuwaUnifiedEngine({ cwd: compWs, sessionId: "sess-r73-comp", agentHome });
		await compEng.callTool("nuwa_init", { target: "http://127.0.0.1:19401", mode: "ctf", root: compWs });
		const fCmd = "curl -sS http://127.0.0.1:19401/flag";
		const fOut = "flag{r73_completed_immutable}";
		recordToolExecution(compWs, { tool: "bash", command: fCmd, output: fOut });
		await compEng.callTool("nuwa_flag", { value: fOut, command: fCmd, output: fOut, root: compWs });
		await compEng.callTool("nuwa_complete", { root: compWs });
		withLock(compWs, () => {
			const s = loadState(compWs)!;
			s.project.phase = "report";
			s.runtime.reportWritten = true;
			saveState(compWs, s);
		});
		const repOnCompleted = await compEng.callTool("nuwa_report", {
			write: true,
			finalize_phase: true,
			root: compWs,
		});
		expect(repOnCompleted.isError).toBe(false);
		const afterCompReport = loadStateZeroWrite(compWs)!;
		expect(afterCompReport.project.status).toBe("completed");
		expect(afterCompReport.runtime.status).toBe("completed");

		// 1a-2 & 1b: 已封盘 sealed_negative 项目调 nuwa_report(finalize_phase=true) 不覆写原 sealMeta.reason，且 /nuwa spa|authdiff|hybrid plan|assets|seal 全部拦截
		const sealWs = makeWorkspace("nuwa-v7-r73-seal-");
		writeFileSync(
			join(sealWs, "app.ts"),
			'app.get("/api/internal/secret", (req, res) => res.json({ ok: true }));\n',
			"utf8",
		);
		const sealEng = new NuwaUnifiedEngine({ cwd: sealWs, sessionId: "sess-r73-seal", agentHome });
		await sealEng.callTool("nuwa_init", { target: "http://127.0.0.1:19402", mode: "pentest", root: sealWs });
		await sealEng.callTool("nuwa_complete", {
			seal: true,
			reason: "ORIGINAL_SEAL_REASON_MUST_KEEP",
			excluded_surface: ["/health"],
			root: sealWs,
		});
		withLock(sealWs, () => {
			const s = loadState(sealWs)!;
			s.project.phase = "report";
			s.runtime.reportWritten = true;
			saveState(sealWs, s);
		});
		const factsBefore = Object.keys(loadStateZeroWrite(sealWs)!.facts).length;
		const intentsBefore = Object.keys(loadStateZeroWrite(sealWs)!.intents).length;

		const repOnSealed = await sealEng.callTool("nuwa_report", {
			write: true,
			finalize_phase: true,
			root: sealWs,
		});
		expect(repOnSealed.isError).toBe(false);
		const afterSealReport = loadStateZeroWrite(sealWs)!;
		expect(afterSealReport.project.status).toBe("sealed_negative");
		expect(afterSealReport.project.sealMeta?.reason).toBe("ORIGINAL_SEAL_REASON_MUST_KEEP");
		expect(afterSealReport.runtime.sealMeta?.reason).toBe("ORIGINAL_SEAL_REASON_MUST_KEEP");

		for (const cmd of ["spa", "authdiff /admin", "hybrid plan", "assets", "oob gen oob.internal", "scope +host a.com", "seal OVERWRITE"]) {
			const r = await sealEng.executeSlashCommand(cmd);
			expect(r.level).toBe("error");
		}
		expect(Object.keys(loadStateZeroWrite(sealWs)!.facts).length).toBe(factsBefore);
		expect(Object.keys(loadStateZeroWrite(sealWs)!.intents).length).toBe(intentsBefore);
		expect(loadStateZeroWrite(sealWs)!.project.sealMeta?.reason).toBe("ORIGINAL_SEAL_REASON_MUST_KEEP");

		// 只读 /nuwa hybrid（不带 plan）仍可正常只读预览且不改图谱
		const roHybrid = await sealEng.executeSlashCommand("hybrid");
		expect(roHybrid.level).toBe("info");
		expect(Object.keys(loadStateZeroWrite(sealWs)!.intents).length).toBe(intentsBefore);

		// P1-2: 存在语法损坏的 .nuwa/autoexec.json 时，纯 SQLite 后端下 nuwa_status 与终态只读 nuwa_init 仍 100% 零写盘
		const badAutoWs = makeWorkspace("nuwa-v7-r73-badauto-");
		const badAutoEng = new NuwaUnifiedEngine({ cwd: badAutoWs, sessionId: "sess-r73-badauto", agentHome });
		await badAutoEng.callTool("nuwa_init", { target: "http://127.0.0.1:19403", mode: "pentest", root: badAutoWs });
		await badAutoEng.callTool("nuwa_complete", {
			seal: true,
			reason: "测试损坏 autoexec 下零写盘",
			root: badAutoWs,
		});
		const stForDb = loadState(badAutoWs)!;
		saveStateToSqlite(badAutoWs, stForDb);
		rmSync(join(badAutoWs, ".nuwa", "state.json"), { force: true });
		writeFileSync(join(badAutoWs, ".nuwa", "autoexec.json"), "{bad json syntax", "utf8");

		setEnvTemp("NUWA_STORAGE_BACKEND", "sqlite");
		const dbFile = sqliteDbPath(badAutoWs);
		const journalFile = join(badAutoWs, ".nuwa", "journal.jsonl");
		const filesSnap0 = readdirSync(join(badAutoWs, ".nuwa")).sort();
		const dbMtime0 = statSync(dbFile).mtimeMs;
		const journalSize0 = existsSync(journalFile) ? statSync(journalFile).size : 0;
		await Bun.sleep(20);

		const stRes = await badAutoEng.callTool("nuwa_status", { root: badAutoWs });
		expect(stRes.isError).toBe(false);
		const initRoRes = await badAutoEng.callTool("nuwa_init", { root: badAutoWs, resume: true });
		expect(initRoRes.isError).toBe(false);
		const slashRoRes = await badAutoEng.executeSlashCommand("status");
		expect(slashRoRes.level).toBe("info");

		expect(statSync(dbFile).mtimeMs).toBe(dbMtime0);
		expect(existsSync(journalFile) ? statSync(journalFile).size : 0).toBe(journalSize0);
		expect(readdirSync(join(badAutoWs, ".nuwa")).sort()).toEqual(filesSnap0);
		setEnvTemp("NUWA_STORAGE_BACKEND", undefined);
	});

	test("P1-3 ~ P1-7: eval JS 词法安全展开、环境变量零截断、相对路径与 700KiB taskFile、注释与 N-004 拦截、无 index 乱序及 SQLite 扫密", () => {
		const agentHome = makeWorkspace("nuwa-v7-r73-b-home-");
		setEnvTemp("PI_AGENT_HOME", agentHome);
		const ws = makeWorkspace("nuwa-v7-r73-b-ws-");
		const callerOtherCwd = makeWorkspace("nuwa-v7-r73-other-cwd-");
		const origCwd = process.cwd();

		const engine = new NuwaUnifiedEngine({ cwd: ws, sessionId: "sess-r73-b", agentHome });
		return (async () => {
			await engine.callTool("nuwa_init", { target: "http://127.0.0.1:19300", mode: "pentest", root: ws });
			await engine.callTool("nuwa_plan", {
				phase: "surface",
				intents: [{ title: "并行意图 B", detail: "测试无 index 乱序配对" }],
				root: ws,
			});

			const store = new DispatchBridgeStore();
			const mainCtx = {
				cwd: ws,
				sessionId: "sess-r73-b",
				agent: { kind: "main", id: "main-0", name: "main", depth: 0 },
				sessionManager: { getSessionId: () => "sess-r73-b" },
			};
			const targetInfo = { url: "http://127.0.0.1:19300", host: "127.0.0.1" };

			// P1-3b: $USER / $URL / $TARGET_ID / $HOSTNAME 严禁被截断误伤
			expect(
				expandPlaceholdersPlain("echo $USER $URL $TARGET_ID $HOSTNAME https://TARGET/api", targetInfo),
			).toBe("echo $USER $URL $TARGET_ID $HOSTNAME http://127.0.0.1:19300/api");
			const expCtx = expandDispatchContextValue({ cmd: "echo $USER on [TARGET]" }, targetInfo);
			expect((expCtx.value as Record<string, unknown>).cmd).toBe("echo $USER on 127.0.0.1");

			// P1-3a: eval 代码中 const TARGET = ... 与 { HOST: ... } 保持 100% 合法 JS 语法
			const code1 = 'const TARGET = "http://127.0.0.1:19300"; agent({ agent: "fujiang", prompt: "probe [TARGET]/api" });';
			const code2 = 'const headers = { HOST: "127.0.0.1" }; agent({ agent: "fujiang", prompt: "GET https://TARGET/x" });';
			const rw1 = expandEvalCodePlaceholders(code1, targetInfo);
			const rw2 = expandEvalCodePlaceholders(code2, targetInfo);
			expect(() => new Function(rw1)).not.toThrow();
			expect(() => new Function(rw2)).not.toThrow();
			expect(rw1).toContain("const TARGET =");
			expect(rw2).toContain("HOST:");

			const ev1Res = handleToolCallDispatch(
				store,
				{ toolName: "eval", toolCallId: "tc-r73-ev1", input: { code: code1 } },
				mainCtx,
			) as { input?: { code?: string } };
			expect(ev1Res?.input?.code).toBeDefined();
			expect(() => new Function(ev1Res.input!.code!)).not.toThrow();

			// P1-5a: 注释中包含 `}` 时仍精准识别空 prompt 并拦截，且保留真实 label
			const codeCommentBrace = 'agent({ agent: "fujiang", // comment }\n label: "lbl-real", prompt: "" });';
			const parsedComment = parseEvalAgentCalls(codeCommentBrace);
			expect(parsedComment.length).toBe(1);
			expect(parsedComment[0]!.label).toBe("lbl-real");
			expect(parsedComment[0]!.hasEmptyPrompt).toBe(true);
			const commentBlockRes = handleToolCallDispatch(
				store,
				{ toolName: "eval", toolCallId: "tc-r73-comment", input: { code: codeCommentBrace } },
				mainCtx,
			);
			expect(commentBlockRes && "block" in commentBlockRes && commentBlockRes.block).toBe(true);

			// P1-5b: rogue-worker 即使在 prompt 中提到 "fujiang" 也必须被 nuwa N-004 拦截
			const rogueRes = handleToolCallDispatch(
				store,
				{
					toolName: "eval",
					toolCallId: "tc-r73-rogue",
					input: { code: 'agent({ agent: "rogue-worker", prompt: "do not delegate to fujiang, run custom" });' },
				},
				mainCtx,
			);
			expect(rogueRes && "block" in rogueRes && rogueRes.block).toBe(true);
			expect(rogueRes && "reason" in rogueRes ? rogueRes.reason : "").toContain("N-004");

			// P1-4a & P1-4b: process.cwd() !== ctx.cwd 时相对路径 taskFile 拦截 + 700 KiB 合法 taskFile 完整保留尾部
			const relHuge = join(ws, "huge-rel.md");
			const fd = openSync(relHuge, "w");
			ftruncateSync(fd, MAX_OMP_TASK_FILE_BYTES + 2048);
			closeSync(fd);
			writeFileSync(join(ws, "empty-rel.md"), "   \n\t  ", "utf8");
			const big700kContent = `[女娲派单 i001] 起始探测 http://TARGET/start\n${"A".repeat(700 * 1024)}\nTAIL_MARKER_700KB_MUST_KEEP`;
			writeFileSync(join(ws, "big-700k.md"), big700kContent, "utf8");

			process.chdir(callerOtherCwd);
			try {
				const relHugeRes = handleToolCallDispatch(
					store,
					{ toolName: "task", toolCallId: "tc-rel-huge", input: { agent: "fujiang", taskFile: "huge-rel.md" } },
					mainCtx,
				);
				expect(relHugeRes && "block" in relHugeRes && relHugeRes.block).toBe(true);

				const relEmptyRes = handleToolCallDispatch(
					store,
					{ toolName: "task", toolCallId: "tc-rel-empty", input: { agent: "fujiang", taskFile: "empty-rel.md" } },
					mainCtx,
				);
				expect(relEmptyRes && "block" in relEmptyRes && relEmptyRes.block).toBe(true);

				const big700kRes = handleToolCallDispatch(
					store,
					{ toolName: "task", toolCallId: "tc-rel-700k", input: { agent: "fujiang", taskFile: "big-700k.md" } },
					mainCtx,
				) as { input?: Record<string, unknown> };
				expect(big700kRes?.input?.taskFile).toBeUndefined();
				const inlineTask = String(big700kRes?.input?.task ?? "");
				expect(inlineTask).toContain("http://127.0.0.1:19300/start");
				expect(inlineTask).toContain("TAIL_MARKER_700KB_MUST_KEEP");
				handleToolExecutionEnd(store, { toolName: "task", toolCallId: "tc-rel-700k", result: { details: { results: [] } } }, mainCtx);
			} finally {
				process.chdir(origCwd);
			}

			// P1-6a & P1-6b: 无 index 的 progress[] 一对一顺序绑定 + 派生前报错的无关 task 绝不误杀在途 bg-alive-worker
			const wd = new SubagentWatchdog(ws);
			wd.startTask({ taskId: "bg-alive-worker", agent: "fujiang" });
			expect(wd.activeCount()).toBe(1);

			// 主线程新发另一条 task 在派生前同步报错返回 (isError: true, details: {})
			handleToolCallDispatch(
				store,
				{ toolName: "task", toolCallId: "tc-sync-err", input: { agent: "fujiang", task: "[女娲派单 i001] 尚未派生即失败的任务" } },
				mainCtx,
			);
			handleToolExecutionEnd(
				store,
				{
					toolName: "task",
					toolCallId: "tc-sync-err",
					isError: true,
					input: { agent: "fujiang", task: "[女娲派单 i001] 尚未派生即失败的任务" },
					result: { details: {} },
				},
				mainCtx,
			);
			// 即使没有经过 handleToolCallDispatch 直接触发无 tcId 的报错事件，也严禁误杀 bg-alive-worker
			handleToolExecutionEnd(
				store,
				{
					toolName: "task",
					isError: true,
					input: { agent: "fujiang" },
					result: { details: {} },
				},
				mainCtx,
			);
			expect(wd.activeCount()).toBe(1);
			expect(wd.getTask("bg-alive-worker")?.status).toBe("running");

			// 批量派发 2 条任务，progress[] 不带 index 字段，乱序派生 rand-one 先、rand-zero 后
			handleToolCallDispatch(
				store,
				{
					toolName: "task",
					toolCallId: "tc-no-index",
					input: {
						tasks: [
							{ agent: "fujiang", task: "[女娲派单 i001] TASK_ALPHA_ZERO" },
							{ agent: "fujiang", task: "[女娲派单 i002] TASK_BETA_ONE" },
						],
					},
				},
				mainCtx,
			);
			handleToolExecutionEnd(
				store,
				{
					toolName: "task",
					toolCallId: "tc-no-index",
					result: {
						details: {
							async: { state: "running" },
							progress: [
								{ id: "rand-zero", status: "pending" },
								{ id: "rand-one", status: "pending" },
							],
							results: [],
						},
					},
				},
				mainCtx,
			);

			const spOne = handleBeforeSubagentSpawn(
				store,
				{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "task", spawnKey: "rand-one" },
				mainCtx,
			);
			const spZero = handleBeforeSubagentSpawn(
				store,
				{ type: "before_subagent_spawn", agent: "fujiang", invocationKind: "task", spawnKey: "rand-zero" },
				mainCtx,
			);
			expect(spOne && !("block" in spOne) ? spOne.task : "").toContain("TASK_BETA_ONE");
			expect(spZero && !("block" in spZero) ? spZero.task : "").toContain("TASK_ALPHA_ZERO");

			// P1-7a: 敏感凭据写入二进制 SQLite .nuwa/nuwa.db 时，scanSecretsInWorkspaceAndLogs 必须精准检出 > 0
			const leakWs = makeWorkspace("nuwa-v7-r73-sqlite-leak-");
			const leakEng = new NuwaUnifiedEngine({ cwd: leakWs, sessionId: "sess-leak", agentHome });
			await leakEng.callTool("nuwa_init", { target: "http://127.0.0.1:19409", mode: "ctf", root: leakWs });
			const leakedSecret = "SQLITE_RAW_SECRET_TOKEN_99112233";
			const leakState = loadState(leakWs)!;
			leakState.project.goal = `goal with ${leakedSecret}`;
			saveStateToSqlite(leakWs, leakState);
			rmSync(join(leakWs, ".nuwa", "state.json"), { force: true });
			rmSync(join(leakWs, ".nuwa", "journal.jsonl"), { force: true });
			expect(readFileSync(sqliteDbPath(leakWs)).includes(Buffer.from(leakedSecret, "utf8"))).toBe(true);
			expect(scanSecretsInWorkspaceAndLogs(leakWs, [], [leakedSecret])).toBeGreaterThan(0);

			store.shutdownSession(ws, "sess-r73-b");
		})();
	});
});
