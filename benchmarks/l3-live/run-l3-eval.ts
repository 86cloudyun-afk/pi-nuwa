#!/usr/bin/env bun
/**
 * pi-nuwa v7.0 L3 真实进程树门禁评测运行器 (`run-l3-eval.ts`)。
 *
 * 用法:
 *   env -u BUN_OPTIONS bun benchmarks/l3-live/run-l3-eval.ts [--json] [--scenario <id>] [--help]
 *
 * 三大真实进程树端到端门禁场景（均通过 `Bun.spawn` 调用 `bin/nuwa-autonomous --omp-bin <mock-omp-bin>`）：
 *   1. `l3-async-socks5-finding`:
 *      `--egress-proxy socks5h://127.0.0.1:<socksPort>` 启动无头守护器，验证子进程 `Bun.fetch` 访问模拟模型 API 0 代理错误、
 *      `omp 18.16.0` 默认 `async.state="running"` 先 `tool_execution_end` 后 `before_subagent_spawn` 乱序放行与看门狗精确归零、
 *      经 `socks5h://` (`ATYP=0x03` 域名透传) 发现漏洞 + `nuwa-verifier` 双盲复验确认完成并以退出码 `0` 收口。
 *   2. `l3-hardened-seal-noop`:
 *      硬化零洞靶完成 `sealed_negative` 负向封盘后，同项目再次重入，验证守护器与 `nuwa_init(resume=true)`
 *      严格保持 `sealed_negative` 零复活、零写盘篡改并退出码 `0`。
 *   3. `l3-stopped-resume-migrate`:
 *      位于 `/tmp` 易失目录下的 `status=stopped` 项目，未加 `--resume-stopped` 时退出码 `2`，
 *      通过 `--resume-stopped --migrate-workspace`（配合带认证口令的 `socks5h://` 代理）自动原子迁出至持久化工作区并接管续跑完成收口。
 *
 * 硬门禁:
 *   - `allPassed === true`
 *   - `socks5HandshakeCount > 0`
 *   - `modelApiErrors === 0`
 *   - `vaultLeakCount === 0`
 */
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { NuwaUnifiedEngine } from "../../core/engine";
import { recordToolExecution } from "../../omp/evidence";
import { upsertSessionRole } from "../../omp/session-vault";
import { loadState } from "../../omp/storage";
import type { MockOmpTelemetryRecord } from "./mock-omp-bin";
import { startLocalSocks5Server } from "./socks5-server";

export const L3_SCENARIO_IDS = [
	"l3-async-socks5-finding",
	"l3-hardened-seal-noop",
	"l3-stopped-resume-migrate",
] as const;

export type L3ScenarioId = (typeof L3_SCENARIO_IDS)[number];

export interface L3ScenarioResult {
	id: L3ScenarioId;
	name: string;
	passed: boolean;
	exitCode: number;
	terminalStatus: string;
	socks5HandshakesDelta: number;
	socks5DomainRequestsDelta: number;
	modelApiRequestsDelta: number;
	modelApiErrorsDelta: number;
	vaultLeaks: number;
	durationMs: number;
	detail: string;
	error?: string;
}

export interface L3HardGates {
	allScenariosPassed: boolean;
	socks5HandshakeGate: boolean;
	zeroModelApiErrorGate: boolean;
	zeroVaultLeakGate: boolean;
	allPassed: boolean;
}

export interface L3ScorecardMetrics {
	totalScenarios: number;
	passedScenarios: number;
	socks5HandshakeCount: number;
	socks5DomainRequests: number;
	modelApiRequests: number;
	modelApiErrors: number;
	vaultLeakCount: number;
	wallTimeMs: number;
}

export interface L3BenchmarkSummary {
	schema: 1;
	suite: "nuwa-l3-live-process-tree";
	generatedAt: string;
	allPassed: boolean;
	socks5HandshakeCount: number;
	socks5DomainRequests: number;
	modelApiRequests: number;
	modelApiErrors: number;
	vaultLeakCount: number;
	metrics: L3ScorecardMetrics;
	gates: L3HardGates;
	scenarios: L3ScenarioResult[];
}

export interface RunL3LiveOptions {
	scenario?: string;
	/** 可选自定义扩展入口文件路径（透传 `NUWA_L3_EXT_ENTRY`）。 */
	extEntryPath?: string;
	/** 单次守护器子进程超时上限毫秒数（默认 `25_000`）。 */
	daemonTimeoutMs?: number;
}

const REPO_ROOT = resolve(import.meta.dir, "..", "..");
const DAEMON_BIN = join(REPO_ROOT, "bin", "nuwa-autonomous");
const MOCK_OMP_SCRIPT = join(REPO_ROOT, "benchmarks", "l3-live", "mock-omp-bin.ts");

const L3_SYNTHETIC_VAULT_SECRET = "l3_vault_jwt_secret_token_do_not_leak_2026";
const L3_SOCKS_AUTH_USER = "l3proxyop";
const L3_SOCKS_AUTH_PASS = "l3_socks5_secret_pw_do_not_leak_8899";
const L3_MIGRATED_FLAG = "flag{l3_stopped_migrated_socks5h_ok}";

function assertL3(cond: unknown, msg: string): void {
	if (!cond) throw new Error(msg);
}

function makeCleanSubprocessEnv(extra: Record<string, string | undefined>): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [k, v] of Object.entries(process.env)) {
		if (v === undefined) continue;
		if (k === "BUN_OPTIONS") continue;
		if (k.startsWith("NUWA_") && k !== "NUWA_STORAGE_BACKEND") continue;
		if (
			[
				"HTTP_PROXY",
				"http_proxy",
				"HTTPS_PROXY",
				"https_proxy",
				"ALL_PROXY",
				"all_proxy",
				"NO_PROXY",
				"no_proxy",
			].includes(k)
		) {
			continue;
		}
		out[k] = v;
	}
	for (const [k, v] of Object.entries(extra)) {
		if (v === undefined) delete out[k];
		else out[k] = v;
	}
	return out;
}

function resolveBunBinary(): string {
	return Bun.which("bun") ?? (process as unknown as { execPath?: string }).execPath ?? "bun";
}

function createMockOmpWrapper(binDir: string): string {
	const wrapperPath = join(binDir, "mock-omp");
	try {
		chmodSync(MOCK_OMP_SCRIPT, 0o755);
	} catch {
		/* ignore */
	}
	const bunBin = resolveBunBinary();
	const scriptBody = [
		"#!/usr/bin/env bash",
		`exec ${JSON.stringify(bunBin)} ${JSON.stringify(MOCK_OMP_SCRIPT)} "$@"`,
		"",
	].join("\n");
	writeFileSync(wrapperPath, scriptBody, "utf8");
	chmodSync(wrapperPath, 0o755);
	return wrapperPath;
}

async function runDaemonProcess(
	args: string[],
	env: Record<string, string>,
	timeoutMs: number,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
	const bunBin = resolveBunBinary();
	const child = Bun.spawn([bunBin, DAEMON_BIN, ...args], {
		cwd: REPO_ROOT,
		env,
		stdout: "pipe",
		stderr: "pipe",
	});
	let timedOut = false;
	const timer = setTimeout(() => {
		timedOut = true;
		try {
			child.kill();
		} catch {
			/* ignore */
		}
	}, timeoutMs);

	try {
		const [stdout, stderr, exitCode] = await Promise.all([
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
			child.exited,
		]);
		if (timedOut) {
			throw new Error(`nuwa-autonomous 子进程执行超时 (>${timeoutMs}ms)\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`);
		}
		return { exitCode, stdout, stderr };
	} finally {
		clearTimeout(timer);
	}
}

function collectFilesRecursive(dir: string, out: string[] = []): string[] {
	if (!existsSync(dir)) return out;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		// 跳过会话保险箱自身的加密/本地凭据存储文件，审计其余全部报告、状态、日志、配置与证据包
		if (entry.name === "vault.json" || entry.name.endsWith(".headers")) continue;
		const full = join(dir, entry.name);
		if (entry.isDirectory()) {
			collectFilesRecursive(full, out);
		} else if (entry.isFile() && !entry.name.endsWith(".gz") && !entry.name.endsWith(".db")) {
			out.push(full);
		}
	}
	return out;
}

function scanSecretsInWorkspaceAndLogs(
	root: string,
	extraTexts: readonly string[],
	secrets: readonly string[],
): number {
	const files = collectFilesRecursive(join(root, ".nuwa"));
	const texts: string[] = [...extraTexts];
	for (const fp of files) {
		try {
			texts.push(readFileSync(fp, "utf8"));
		} catch {
			/* ignore */
		}
	}
	let leaks = 0;
	for (const text of texts) {
		for (const secret of secrets) {
			if (secret && secret.length >= 8 && text.includes(secret)) {
				leaks += 1;
			}
		}
	}
	return leaks;
}

function readTelemetryRecords(filePath: string): MockOmpTelemetryRecord[] {
	if (!existsSync(filePath)) return [];
	return readFileSync(filePath, "utf8")
		.split("\n")
		.map((l) => l.trim())
		.filter(Boolean)
		.map((l) => JSON.parse(l) as MockOmpTelemetryRecord);
}

function startL3TargetAndLlmServers() {
	let modelApiRequests = 0;
	let modelApiErrors = 0;

	const llmServer = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		async fetch(req: Request): Promise<Response> {
			const url = new URL(req.url);
			if (url.pathname === "/v1/models") {
				modelApiRequests += 1;
				return Response.json({ ok: true, data: [{ id: "nuwa-l3-mock-llm" }] });
			}
			if (url.pathname === "/v1/chat/completions" && req.method === "POST") {
				modelApiRequests += 1;
				try {
					const payload = (await req.json()) as { scenario?: string; messages?: unknown[] };
					if (!Array.isArray(payload?.messages)) {
						modelApiErrors += 1;
						return Response.json({ ok: false, error: "invalid messages" }, { status: 400 });
					}
					return Response.json({
						ok: true,
						id: `chatcmpl-l3-${modelApiRequests}`,
						choices: [{ index: 0, message: { role: "assistant", content: `plan:${payload.scenario ?? "default"}` } }],
					});
				} catch {
					modelApiErrors += 1;
					return Response.json({ ok: false, error: "bad json" }, { status: 400 });
				}
			}
			modelApiErrors += 1;
			return new Response("Not Found", { status: 404 });
		},
	});

	const targetServer = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(req: Request): Response {
			const url = new URL(req.url);
			const p = url.pathname;

			if (p === "/health") {
				return Response.json({ status: "ok", service: "l3-range-target" }, { status: 200 });
			}
			if (p === "/api/v1/internal/backup-manifest") {
				return Response.json(
					{
						environment: "staging-internal",
						snapshots: [
							{ id: "snap-2026-11-26", bucket: "s3://corp-internal-db-backups/prod-dump.sql.zst", sizeBytes: 4829104 },
							{ id: "snap-2026-11-25", bucket: "s3://corp-internal-db-backups/audit-dump.sql.zst", sizeBytes: 3910244 },
						],
						exposedBy: "misconfigured-debug-router",
					},
					{ status: 200 },
				);
			}
			if (p === "/api/v1/admin/config") {
				return Response.json({ error: "forbidden", message: "Strict RBAC policy enforced" }, { status: 403 });
			}
			if (p === "/api/v1/ctf/flag") {
				return Response.json({ ok: true, challenge: "l3-migrate-resume", flag: L3_MIGRATED_FLAG }, { status: 200 });
			}
			if (p.startsWith("/spa/")) {
				return new Response(
					"<!doctype html><html><head><title>App Shell</title></head><body><div id=\"root\"></div></body></html>",
					{ status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } },
				);
			}
			return Response.json({ error: "not_found", path: p }, { status: 404 });
		},
	});

	return {
		llmPort: llmServer.port,
		llmBaseUrl: `http://127.0.0.1:${llmServer.port}`,
		targetPort: targetServer.port,
		targetInternalUrl: `http://l3-target.internal:${targetServer.port}`,
		getLlmStats: () => ({ modelApiRequests, modelApiErrors }),
		recordExternalModelError: () => {
			modelApiErrors += 1;
		},
		stop: () => {
			llmServer.stop(true);
			targetServer.stop(true);
		},
	};
}

/**
 * 执行完整 L3 真实进程树门禁评测套件。
 */
export async function runL3LiveSuite(opts?: RunL3LiveOptions): Promise<L3BenchmarkSummary> {
	const suiteStartedAt = Date.now();
	const daemonTimeoutMs = opts?.daemonTimeoutMs ?? 25_000;
	const selectedScenario = opts?.scenario?.trim();
	if (selectedScenario && !L3_SCENARIO_IDS.includes(selectedScenario as L3ScenarioId)) {
		throw new Error(`未知 L3 场景 ID: ${selectedScenario}（可选: ${L3_SCENARIO_IDS.join(", ")}）`);
	}
	const targetIds: L3ScenarioId[] = selectedScenario
		? [selectedScenario as L3ScenarioId]
		: [...L3_SCENARIO_IDS];

	const tempDirs: string[] = [];
	const makePersistSandbox = (prefix: string): string => {
		const base = resolve(REPO_ROOT, ".nuwa-l3-tmp-persist");
		mkdirSync(base, { recursive: true });
		const d = mkdtempSync(join(base, prefix));
		mkdirSync(join(d, ".git"), { recursive: true });
		writeFileSync(join(d, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
		tempDirs.push(d);
		return d;
	};
	const makeVolatileTmpSandbox = (prefix: string): string => {
		const d = mkdtempSync(join(tmpdir(), prefix));
		mkdirSync(join(d, ".git"), { recursive: true });
		writeFileSync(join(d, ".git", "HEAD"), "ref: refs/heads/main\n", "utf8");
		tempDirs.push(d);
		return d;
	};

	const servers = startL3TargetAndLlmServers();
	const socksNoAuth = await startLocalSocks5Server({
		allowedPorts: [servers.targetPort],
		domainMap: { "l3-target.internal": "127.0.0.1", localhost: "127.0.0.1" },
	});
	const socksWithAuth = await startLocalSocks5Server({
		allowedPorts: [servers.targetPort],
		domainMap: { "l3-target.internal": "127.0.0.1", localhost: "127.0.0.1" },
		auth: { username: L3_SOCKS_AUTH_USER, password: L3_SOCKS_AUTH_PASS },
	});

	const scenariosOut: L3ScenarioResult[] = [];

	try {
		const binHolder = makeVolatileTmpSandbox("nuwa-l3-bin-");
		const mockOmpBin = createMockOmpWrapper(binHolder);
		const sharedAgentHome = makePersistSandbox("nuwa-l3-agent-home-");

		const snapshotTotals = () => {
			const s1 = socksNoAuth.getStats();
			const s2 = socksWithAuth.getStats();
			const llm = servers.getLlmStats();
			return {
				handshakes: s1.socks5HandshakeCount + s2.socks5HandshakeCount,
				domains: s1.socks5DomainRequests + s2.socks5DomainRequests,
				llmReqs: llm.modelApiRequests,
				llmErrs: llm.modelApiErrors,
			};
		};

		for (const scenarioId of targetIds) {
			const scStarted = Date.now();
			const before = snapshotTotals();

			if (scenarioId === "l3-async-socks5-finding") {
				const ws = makePersistSandbox("ws-s1-async-socks5-");
				const telemetryPath = join(binHolder, "telemetry-s1.jsonl");
				let exitCode = -1;
				let termStatus = "unknown";
				let leaks = 0;
				try {
					// 故意注入脏 HTTP_PROXY=socks5h:// 父环境，验证 nuwa-autonomous 自动剥离以保护子进程 Bun.fetch
					const env = makeCleanSubprocessEnv({
						PI_AGENT_HOME: sharedAgentHome,
						HTTP_PROXY: socksNoAuth.proxyUrl,
						HTTPS_PROXY: socksNoAuth.proxyUrl,
						NUWA_L3_SCENARIO: "l3-async-socks5-finding",
						NUWA_L3_MOCK_LLM_URL: servers.llmBaseUrl,
						NUWA_L3_TARGET_URL: servers.targetInternalUrl,
						NUWA_L3_TELEMETRY_FILE: telemetryPath,
						NUWA_L3_VAULT_SECRET: L3_SYNTHETIC_VAULT_SECRET,
						...(opts?.extEntryPath ? { NUWA_L3_EXT_ENTRY: opts.extEntryPath } : {}),
					});

					const runRes = await runDaemonProcess(
						[
							"--target",
							servers.targetInternalUrl,
							"--mode",
							"pentest",
							"--root",
							ws,
							"--egress-proxy",
							socksNoAuth.proxyUrl,
							"--max-generations",
							"2",
							"--omp-bin",
							mockOmpBin,
						],
						env,
						daemonTimeoutMs,
					);
					exitCode = runRes.exitCode;
					if (exitCode === 11) servers.recordExternalModelError();
					assertL3(exitCode === 0, `守护器退出码预期 0，实际=${exitCode}\nSTDERR: ${runRes.stderr}`);

					const finalState = loadState(ws);
					termStatus = finalState?.project.status ?? "missing";
					assertL3(termStatus === "completed", `预期终态 completed，实际=${termStatus}`);

					const confirmedVulns = Object.values(finalState?.facts ?? {}).filter(
						(f) => f.kind === "vuln" && f.verifyStage === "confirmed",
					);
					assertL3(confirmedVulns.length >= 1, "预期至少 1 条经双盲复验确认的 confirmed 漏洞事实");

					const tele = readTelemetryRecords(telemetryPath);
					assertL3(tele.length >= 1 && tele[0]!.modelFetchOk, "子进程模型 API fetch 必须成功");
					assertL3(tele[0]!.httpProxyEnv === null && tele[0]!.httpsProxyEnv === null, "子进程 HTTP(S)_PROXY 必须被剥离隔离");
					assertL3(tele[0]!.asyncWatchdogPeak >= 1 && tele[0]!.asyncWatchdogFinal === 0, "异步子代理看门狗须经历挂载并精确归零");

					leaks = scanSecretsInWorkspaceAndLogs(ws, [runRes.stdout, runRes.stderr], [L3_SYNTHETIC_VAULT_SECRET]);
					assertL3(leaks === 0, `检测到 SessionVault 敏感凭据泄露 ${leaks} 处`);

					const after = snapshotTotals();
					assertL3(after.handshakes - before.handshakes >= 2, "预期至少发生 2 次真实 SOCKS5h 隧道握手（发现 + 双盲复验）");
					assertL3(after.domains - before.domains >= 2, "预期通过 ATYP=0x03 域名透传请求 l3-target.internal");

					scenariosOut.push({
						id: scenarioId,
						name: "SOCKS5h 出口隔离 + 异步子代理竞态放行 + 双盲复验实锤完成",
						passed: true,
						exitCode,
						terminalStatus: termStatus,
						socks5HandshakesDelta: after.handshakes - before.handshakes,
						socks5DomainRequestsDelta: after.domains - before.domains,
						modelApiRequestsDelta: after.llmReqs - before.llmReqs,
						modelApiErrorsDelta: after.llmErrs - before.llmErrs,
						vaultLeaks: leaks,
						durationMs: Date.now() - scStarted,
						detail: `exit=0, confirmed=${confirmedVulns.length}, socks5Handshakes=${after.handshakes - before.handshakes}, watchdogPeak=${tele[0]!.asyncWatchdogPeak}->0`,
					});
				} catch (err) {
					const after = snapshotTotals();
					scenariosOut.push({
						id: scenarioId,
						name: "SOCKS5h 出口隔离 + 异步子代理竞态放行 + 双盲复验实锤完成",
						passed: false,
						exitCode,
						terminalStatus: termStatus,
						socks5HandshakesDelta: after.handshakes - before.handshakes,
						socks5DomainRequestsDelta: after.domains - before.domains,
						modelApiRequestsDelta: after.llmReqs - before.llmReqs,
						modelApiErrorsDelta: after.llmErrs - before.llmErrs,
						vaultLeaks: leaks,
						durationMs: Date.now() - scStarted,
						detail: "场景验收失败",
						error: err instanceof Error ? err.message : String(err),
					});
				}
			} else if (scenarioId === "l3-hardened-seal-noop") {
				const ws = makePersistSandbox("ws-s2-hardened-seal-");
				const telemetryPath = join(binHolder, "telemetry-s2.jsonl");
				let exitCode = -1;
				let termStatus = "unknown";
				let leaks = 0;
				try {
					const env = makeCleanSubprocessEnv({
						PI_AGENT_HOME: sharedAgentHome,
						NUWA_L3_SCENARIO: "l3-hardened-seal-noop",
						NUWA_L3_MOCK_LLM_URL: servers.llmBaseUrl,
						NUWA_L3_TARGET_URL: servers.targetInternalUrl,
						NUWA_L3_TELEMETRY_FILE: telemetryPath,
						NUWA_L3_VAULT_SECRET: L3_SYNTHETIC_VAULT_SECRET,
						...(opts?.extEntryPath ? { NUWA_L3_EXT_ENTRY: opts.extEntryPath } : {}),
					});

					// 第一轮：探测硬化零洞靶并执行负向封盘 sealed_negative
					const run1 = await runDaemonProcess(
						[
							"--target",
							servers.targetInternalUrl,
							"--mode",
							"pentest",
							"--root",
							ws,
							"--egress-proxy",
							socksNoAuth.proxyUrl,
							"--max-generations",
							"2",
							"--omp-bin",
							mockOmpBin,
						],
						env,
						daemonTimeoutMs,
					);
					exitCode = run1.exitCode;
					if (exitCode === 11) servers.recordExternalModelError();
					assertL3(exitCode === 0, `硬化封盘首轮守护器退出码预期 0，实际=${exitCode}\nSTDERR: ${run1.stderr}`);

					const sealedSt = loadState(ws);
					termStatus = sealedSt?.project.status ?? "missing";
					assertL3(
						termStatus === "sealed_negative" && sealedSt?.runtime.status === "sealed_negative",
						`预期双状态对齐 sealed_negative，实际=${termStatus}`,
					);
					assertL3(existsSync(join(ws, ".nuwa", "REPORT.md")), "封盘后必须自动同步生成 REPORT.md");

					const stateFile = join(ws, ".nuwa", "state.json");
					const mtimeBeforeReentry = statSync(stateFile).mtimeMs;
					await Bun.sleep(20);

					// 验证单核引擎 nuwa_init(resume=true) 同会话与跨会话重入均保持只读零写盘、零复活
					const unifyEng = new NuwaUnifiedEngine({
						cwd: ws,
						projectRoot: ws,
						sessionId: "l3-reentry-outsider",
						agentHome: sharedAgentHome,
					});
					const roRes = await unifyEng.callTool("nuwa_init", { root: ws, resume: true });
					assertL3(!roRes.isError && roRes.details.readonly === true && roRes.details.status === "sealed_negative", "nuwa_init(resume=true) 必须保持只读 sealed_negative");
					assertL3(statSync(stateFile).mtimeMs === mtimeBeforeReentry, "终态非 force 重入必须严格零写盘");

					const telemetryCountBeforeRun2 = readTelemetryRecords(telemetryPath).length;

					// 第二轮：同项目再次通过守护器重入（即使附带 --resume-stopped），守护器须识别终态直接 0 退出且不复活
					const run2 = await runDaemonProcess(
						["--root", ws, "--resume-stopped", "--omp-bin", mockOmpBin],
						env,
						daemonTimeoutMs,
					);
					assertL3(run2.exitCode === 0, `封盘终态二次重入守护器退出码预期 0，实际=${run2.exitCode}`);
					assertL3(run2.stdout.includes("status=sealed_negative"), "守护器二次重入输出应明确标识 status=sealed_negative");
					assertL3(
						readTelemetryRecords(telemetryPath).length === telemetryCountBeforeRun2,
						"守护器遇到已封盘终态项目应直接收敛退出，无需重复拉起子进程烧 Token",
					);
					assertL3(loadState(ws)?.project.status === "sealed_negative", "二次重入后磁盘状态仍须保持 sealed_negative");

					leaks = scanSecretsInWorkspaceAndLogs(ws, [run1.stdout, run1.stderr, run2.stdout], [L3_SYNTHETIC_VAULT_SECRET]);
					assertL3(leaks === 0, `硬化封盘场景检测到敏感凭据泄露 ${leaks} 处`);

					const after = snapshotTotals();
					scenariosOut.push({
						id: scenarioId,
						name: "硬化零洞靶负向封盘 sealed_negative 与重入零复活零写盘守卫",
						passed: true,
						exitCode: run2.exitCode,
						terminalStatus: "sealed_negative",
						socks5HandshakesDelta: after.handshakes - before.handshakes,
						socks5DomainRequestsDelta: after.domains - before.domains,
						modelApiRequestsDelta: after.llmReqs - before.llmReqs,
						modelApiErrorsDelta: after.llmErrs - before.llmErrs,
						vaultLeaks: leaks,
						durationMs: Date.now() - scStarted,
						detail: `run1=0(sealed_negative), reentry=0(zero-write & no-respawn), handshakes=${after.handshakes - before.handshakes}`,
					});
				} catch (err) {
					const after = snapshotTotals();
					scenariosOut.push({
						id: scenarioId,
						name: "硬化零洞靶负向封盘 sealed_negative 与重入零复活零写盘守卫",
						passed: false,
						exitCode,
						terminalStatus: termStatus,
						socks5HandshakesDelta: after.handshakes - before.handshakes,
						socks5DomainRequestsDelta: after.domains - before.domains,
						modelApiRequestsDelta: after.llmReqs - before.llmReqs,
						modelApiErrorsDelta: after.llmErrs - before.llmErrs,
						vaultLeaks: leaks,
						durationMs: Date.now() - scStarted,
						detail: "场景验收失败",
						error: err instanceof Error ? err.message : String(err),
					});
				}
			} else if (scenarioId === "l3-stopped-resume-migrate") {
				const volatileTmpWs = makeVolatileTmpSandbox("nuwa-l3-tmp-stopped-");
				const persistWsBase = makePersistSandbox("nuwa-l3-persist-workspaces-");
				const telemetryPath = join(binHolder, "telemetry-s3.jsonl");
				let exitCode = -1;
				let termStatus = "unknown";
				let leaks = 0;
				try {
					// 1. 先在 /tmp 易失目录下初始化项目、存入历史事实与 Vault 秘密，并人工硬停机为 status=stopped
					const seedEngine = new NuwaUnifiedEngine({
						cwd: volatileTmpWs,
						projectRoot: volatileTmpWs,
						sessionId: "l3-pre-stop-owner",
						agentHome: sharedAgentHome,
					});
					const initSeed = await seedEngine.callTool("nuwa_init", {
						target: servers.targetInternalUrl,
						mode: "ctf",
						goal: "验证 /tmp 停机工作区自动迁出与接管续跑夺旗",
						root: volatileTmpWs,
					});
					assertL3(!initSeed.isError, "初始化 /tmp 待迁移项目失败");
					upsertSessionRole(volatileTmpWs, { role: "ctf_player", bearer: L3_SYNTHETIC_VAULT_SECRET });

					recordToolExecution(volatileTmpWs, {
						tool: "bash",
						command: `curl -sS -I ${servers.targetInternalUrl}/health`,
						output: "HTTP/1.1 200 OK\nServer: l3-range-target",
					});
					await seedEngine.callTool("nuwa_claim", { id: "i001", worker: "fujiang", root: volatileTmpWs });
					await seedEngine.callTool("nuwa_commit", {
						id: "i001",
						kind: "service",
						title: "前置侦察发现靶机存活（停机前存量事实）",
						command: `curl -sS -I ${servers.targetInternalUrl}/health`,
						output: "HTTP/1.1 200 OK\nServer: l3-range-target",
						root: volatileTmpWs,
					});
					const stopSeed = await seedEngine.callTool("nuwa_stop", {
						reason: "阶段性人工停机等待持久化迁移续跑",
						confirm: "STOP",
						root: volatileTmpWs,
					});
					assertL3(!stopSeed.isError && stopSeed.details.stopped === true, "构造 status=stopped 状态失败");

					const baseEnv = makeCleanSubprocessEnv({
						PI_AGENT_HOME: sharedAgentHome,
						NUWA_WORKSPACES_DIR: persistWsBase,
						NUWA_L3_SCENARIO: "l3-stopped-resume-migrate",
						NUWA_L3_MOCK_LLM_URL: servers.llmBaseUrl,
						NUWA_L3_TARGET_URL: servers.targetInternalUrl,
						NUWA_L3_TELEMETRY_FILE: telemetryPath,
						NUWA_L3_VAULT_SECRET: L3_SYNTHETIC_VAULT_SECRET,
						...(opts?.extEntryPath ? { NUWA_L3_EXT_ENTRY: opts.extEntryPath } : {}),
					});

					// 2. 未传 --resume-stopped 时守护器必须拒绝强跑并以退出码 2 退出
					const blockedRun = await runDaemonProcess(
						["--root", volatileTmpWs, "--omp-bin", mockOmpBin],
						baseEnv,
						daemonTimeoutMs,
					);
					assertL3(blockedRun.exitCode === 2, `stopped 项目未带 --resume-stopped 预期退出码 2，实际=${blockedRun.exitCode}`);

					// 3. 传 --resume-stopped --migrate-workspace 并使用含口令的 socks5h:// 代理认证，执行自动迁出与续跑收口
					const authedProxyUrl = socksWithAuth.buildProxyUrl(true, "socks5h");
					const migratedRun = await runDaemonProcess(
						[
							"--root",
							volatileTmpWs,
							"--resume-stopped",
							"--migrate-workspace",
							"--egress-proxy",
							authedProxyUrl,
							"--max-generations",
							"2",
							"--omp-bin",
							mockOmpBin,
						],
						baseEnv,
						daemonTimeoutMs,
					);
					exitCode = migratedRun.exitCode;
					if (exitCode === 11) servers.recordExternalModelError();
					assertL3(exitCode === 0, `迁移续跑守护器退出码预期 0，实际=${exitCode}\nSTDERR: ${migratedRun.stderr}`);

					const migLine = migratedRun.stdout.split("\n").find((l) => l.includes("迁出:"));
					assertL3(Boolean(migLine), `守护器输出未包含易失目录迁出日志: ${migratedRun.stdout}`);
					const migratedRoot = migLine!.split("->").pop()!.trim();
					assertL3(
						resolve(migratedRoot).startsWith(resolve(persistWsBase)),
						`迁移目标目录应位于持久化基址 ${persistWsBase}，实际=${migratedRoot}`,
					);

					const finalMigState = loadState(migratedRoot);
					termStatus = finalMigState?.project.status ?? "missing";
					assertL3(termStatus === "completed", `迁移续跑终态预期 completed，实际=${termStatus}`);

					const factsList = Object.values(finalMigState?.facts ?? {});
					assertL3(
						factsList.some((f) => f.title.includes("停机前存量事实")),
						"从 /tmp 迁移后必须完整保留停机前的存量事实",
					);
					assertL3(
						factsList.some(
							(f) =>
								f.kind === "flag" &&
								`${f.title ?? ""} ${f.detail ?? ""} ${f.output ?? ""}`.includes(L3_MIGRATED_FLAG),
						),
						"迁移续跑后必须包含新夺取的验证 Flag",
					);

					// 严格扫描 SessionVault 令牌与含口令 SOCKS5 代理密码均零明文泄露
					leaks = scanSecretsInWorkspaceAndLogs(
						migratedRoot,
						[migratedRun.stdout, migratedRun.stderr],
						[L3_SYNTHETIC_VAULT_SECRET, L3_SOCKS_AUTH_PASS],
					);
					assertL3(leaks === 0, `迁移续跑场景检测到凭据或代理口令明文泄露 ${leaks} 处`);

					const after = snapshotTotals();
					assertL3(socksWithAuth.getStats().authSuccessCount >= 1, "预期至少完成 1 次 RFC 1929 SOCKS5 用户名/密码认证握手");

					scenariosOut.push({
						id: scenarioId,
						name: "/tmp 易失目录 stopped 项目自动迁出持久化工作区并接管续跑收口",
						passed: true,
						exitCode,
						terminalStatus: termStatus,
						socks5HandshakesDelta: after.handshakes - before.handshakes,
						socks5DomainRequestsDelta: after.domains - before.domains,
						modelApiRequestsDelta: after.llmReqs - before.llmReqs,
						modelApiErrorsDelta: after.llmErrs - before.llmErrs,
						vaultLeaks: leaks,
						durationMs: Date.now() - scStarted,
						detail: `blockedWithoutFlag=2, migratedToPersist=true, authSocks5=${socksWithAuth.getStats().authSuccessCount}, exit=0`,
					});
				} catch (err) {
					const after = snapshotTotals();
					scenariosOut.push({
						id: scenarioId,
						name: "/tmp 易失目录 stopped 项目自动迁出持久化工作区并接管续跑收口",
						passed: false,
						exitCode,
						terminalStatus: termStatus,
						socks5HandshakesDelta: after.handshakes - before.handshakes,
						socks5DomainRequestsDelta: after.domains - before.domains,
						modelApiRequestsDelta: after.llmReqs - before.llmReqs,
						modelApiErrorsDelta: after.llmErrs - before.llmErrs,
						vaultLeaks: leaks,
						durationMs: Date.now() - scStarted,
						detail: "场景验收失败",
						error: err instanceof Error ? err.message : String(err),
					});
				}
			}
		}

		const finalSocks1 = socksNoAuth.getStats();
		const finalSocks2 = socksWithAuth.getStats();
		const finalLlm = servers.getLlmStats();

		const socks5HandshakeCount = finalSocks1.socks5HandshakeCount + finalSocks2.socks5HandshakeCount;
		const socks5DomainRequests = finalSocks1.socks5DomainRequests + finalSocks2.socks5DomainRequests;
		const modelApiRequests = finalLlm.modelApiRequests;
		const modelApiErrors = finalLlm.modelApiErrors;
		const vaultLeakCount = scenariosOut.reduce((acc, s) => acc + s.vaultLeaks, 0);
		const passedScenarios = scenariosOut.filter((s) => s.passed).length;

		const gates: L3HardGates = {
			allScenariosPassed: passedScenarios === scenariosOut.length && scenariosOut.length > 0,
			socks5HandshakeGate: socks5HandshakeCount > 0 && socks5DomainRequests > 0,
			zeroModelApiErrorGate: modelApiRequests > 0 && modelApiErrors === 0,
			zeroVaultLeakGate: vaultLeakCount === 0,
			allPassed: false,
		};
		gates.allPassed =
			gates.allScenariosPassed &&
			gates.socks5HandshakeGate &&
			gates.zeroModelApiErrorGate &&
			gates.zeroVaultLeakGate;

		const metrics: L3ScorecardMetrics = {
			totalScenarios: scenariosOut.length,
			passedScenarios,
			socks5HandshakeCount,
			socks5DomainRequests,
			modelApiRequests,
			modelApiErrors,
			vaultLeakCount,
			wallTimeMs: Date.now() - suiteStartedAt,
		};

		return {
			schema: 1,
			suite: "nuwa-l3-live-process-tree",
			generatedAt: new Date().toISOString(),
			allPassed: gates.allPassed,
			socks5HandshakeCount,
			socks5DomainRequests,
			modelApiRequests,
			modelApiErrors,
			vaultLeakCount,
			metrics,
			gates,
			scenarios: scenariosOut,
		};
	} finally {
		await socksNoAuth.stop();
		await socksWithAuth.stop();
		servers.stop();
		for (const d of tempDirs.reverse()) {
			try {
				rmSync(d, { recursive: true, force: true });
			} catch {
				/* ignore */
			}
		}
		try {
			const persistContainer = resolve(REPO_ROOT, ".nuwa-l3-tmp-persist");
			if (existsSync(persistContainer) && readdirSync(persistContainer).length === 0) {
				rmSync(persistContainer, { recursive: true, force: true });
			}
		} catch {
			/* ignore */
		}
	}
}

const L3_HELP_TEXT = `女娲 v7.0 L3 真实进程树门禁评测运行器 (run-l3-eval.ts)

用法:
  env -u BUN_OPTIONS bun benchmarks/l3-live/run-l3-eval.ts [选项]

选项:
  --json               输出标准 JSON 评分报告
  --scenario <id>      仅运行指定 L3 场景（可选: ${L3_SCENARIO_IDS.join(" | ")}）
  -h, --help           显示帮助信息
`;

async function runCli(argv: readonly string[]): Promise<number> {
	let jsonOut = false;
	let scenario: string | undefined;

	for (let i = 0; i < argv.length; i += 1) {
		const a = argv[i]!;
		if (a === "--help" || a === "-h") {
			process.stdout.write(L3_HELP_TEXT);
			return 0;
		}
		if (a === "--json") {
			jsonOut = true;
		} else if (a === "--scenario") {
			const val = argv[++i];
			if (!val) throw new Error("--scenario 需要指定场景 ID");
			scenario = val.trim();
		} else if (a.startsWith("--scenario=")) {
			scenario = a.slice("--scenario=".length).trim();
		} else {
			throw new Error(`未知参数: ${a}`);
		}
	}

	const summary = await runL3LiveSuite({ scenario });
	if (jsonOut) {
		process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
	} else {
		const lines = [
			`[女娲 v7.0 L3 真实进程树门禁报告] allPassed=${summary.allPassed}`,
			`- 场景通过: ${summary.metrics.passedScenarios}/${summary.metrics.totalScenarios} · 耗时: ${summary.metrics.wallTimeMs}ms`,
			`- SOCKS5h 隧道握手: ${summary.socks5HandshakeCount} (ATYP=0x03 域名透传: ${summary.socks5DomainRequests})`,
			`- 模型 API 请求: ${summary.modelApiRequests} · 代理/协议错误: ${summary.modelApiErrors}`,
			`- 敏感凭据/代理口令泄露数: ${summary.vaultLeakCount}`,
			"",
			...summary.scenarios.map(
				(s) =>
					`  [${s.passed ? "PASS" : "FAIL"}] ${s.id} (${s.durationMs}ms) -> ${s.detail}${s.error ? ` | ERROR: ${s.error}` : ""}`,
			),
		];
		process.stdout.write(`${lines.join("\n")}\n`);
	}
	return summary.allPassed ? 0 : 1;
}

if (import.meta.main) {
	runCli(process.argv.slice(2))
		.then((code) => process.exit(code))
		.catch((err) => {
			process.stderr.write(`[run-l3-eval] ERROR: ${err instanceof Error ? err.message : String(err)}\n`);
			process.exit(2);
		});
}
