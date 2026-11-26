#!/usr/bin/env bun
/**
 * 女娲 v7.0 L3 真实子进程宿主模拟器（模拟 `omp 18.16.0` 无头运行与异步子代理事件流）。
 *
 * 由 `bin/nuwa-autonomous --omp-bin <mock-omp-bin.ts>` 真实通过 `Bun.spawn` 拉起，执行以下硬核校验：
 * 1. 验证子进程内 `Bun.fetch` 直连本地模拟 LLM 接口（即便外层传了 `--egress-proxy socks5h://...`，
 *    模型 API 依然直连且不触发 `UnsupportedProxyProtocol`）；
 * 2. 动态加载工作区 `omp/nuwa.ts`（或由 `NUWA_L3_EXT_ENTRY` 指定的扩展入口），驱动真实事件生命周期：
 *    `session_start` -> `tool_call("task"|"eval")` -> `tool_execution_end(async.state="running", progress[])` ->
 *    `before_subagent_spawn({ type, agent, invocationKind, spawnKey })` -> `tool_result` -> `session_shutdown`；
 * 3. 真实通过 `curl --proxy socks5h://...`（或本地 SOCKS5h TCP 客户端）经 `socks5-server.ts` 探测本地靶机！
 */
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { SubagentWatchdog, loadState } from "../../omp/storage";
import { upsertSessionRole } from "../../omp/session-vault";
import { maskEgressUrl } from "../../omp/sandbox";
import { requestViaSocks5Http } from "./socks5-server";

interface MockOmpCliParsed {
	cwd: string;
	model?: string;
	prompt: string;
}

export interface MockOmpTelemetryRecord {
	scenario: string;
	pid: number;
	cwd: string;
	nuwaProjectEnv: string;
	httpProxyEnv: string | null;
	httpsProxyEnv: string | null;
	egressProxyMasked: string | null;
	modelFetchOk: boolean;
	modelFetchStatus: number;
	modelFetchError?: string;
	asyncWatchdogPeak: number;
	asyncWatchdogFinal: number;
	promptSnippet: string;
	finalProjectStatus?: string;
}

function parseMockOmpArgs(argv: readonly string[]): MockOmpCliParsed {
	let cwd = process.cwd();
	let model: string | undefined;
	let prompt = "";
	for (let i = 0; i < argv.length; i += 1) {
		const a = argv[i]!;
		if (a === "--") {
			prompt = argv.slice(i + 1).join(" ");
			break;
		}
		if (a === "--cwd" && argv[i + 1]) {
			cwd = resolve(argv[++i]!);
		} else if (a === "--model" && argv[i + 1]) {
			model = argv[++i]!;
		}
	}
	return { cwd, ...(model ? { model } : {}), prompt };
}

function writeTelemetry(filePath: string | undefined, rec: MockOmpTelemetryRecord): void {
	if (!filePath) return;
	try {
		mkdirSync(dirname(filePath), { recursive: true });
		appendFileSync(filePath, `${JSON.stringify(rec)}\n`, "utf8");
	} catch {
		/* ignore telemetry write failure */
	}
}

function makeMockZod(): unknown {
	const chain = (): unknown => new Proxy(() => chain(), { get: () => () => chain() });
	return new Proxy({}, { get: () => () => chain() });
}

interface ProbeHttpOutcome {
	ok: boolean;
	command: string;
	output: string;
	statusCode: number;
}

/**
 * 真实经由 `socks5h://` 测试代理访问本地靶机（优先调用系统 `curl --proxy socks5h://...`，无 curl 时回退原生 TCP SOCKS5h）。
 */
async function probeTargetOverSocks5h(
	targetUrl: string,
	rawProxyUrl: string,
	headers: Record<string, string> = {},
): Promise<ProbeHttpOutcome> {
	const safeProxyDisplay = maskEgressUrl(rawProxyUrl) ?? rawProxyUrl;
	const curlBin = Bun.which("curl");
	if (curlBin) {
		const headerArgs: string[] = [];
		for (const [k, v] of Object.entries(headers)) {
			headerArgs.push("-H", `${k}: ${v}`);
		}
		const args = [
			"-sS",
			"-i",
			"--max-time",
			"5",
			"--proxy",
			rawProxyUrl,
			...headerArgs,
			"-w",
			"\nhttp_code=%{http_code} size_download=%{size_download} remote_ip=%{remote_ip} time_total=%{time_total}",
			targetUrl,
		];
		const res = spawnSync(curlBin, args, { encoding: "utf8", timeout: 8000 });
		const stdout = String(res.stdout ?? "").trim();
		const codeMatch = /http_code=(\d{3})/.exec(stdout) ?? /^HTTP\/1\.[01]\s+(\d{3})\b/m.exec(stdout);
		const statusCode = codeMatch ? Number(codeMatch[1]) : 0;
		const displayCmd = `curl -sS -i --proxy ${safeProxyDisplay} ${targetUrl}`;
		if (res.status === 0 && statusCode > 0) {
			return {
				ok: true,
				command: displayCmd,
				output: stdout,
				statusCode,
			};
		}
	}

	// 原生 TCP SOCKS5h (`ATYP=0x03`) 回退通道
	const parsedProxy = new URL(rawProxyUrl);
	const parsedTarget = new URL(targetUrl);
	const targetPort = parsedTarget.port ? Number(parsedTarget.port) : 80;
	const auth =
		parsedProxy.username || parsedProxy.password
			? {
					username: decodeURIComponent(parsedProxy.username),
					password: decodeURIComponent(parsedProxy.password),
				}
			: undefined;
	const tcpRes = await requestViaSocks5Http({
		proxyHost: parsedProxy.hostname || "127.0.0.1",
		proxyPort: Number(parsedProxy.port),
		targetHost: parsedTarget.hostname,
		targetPort,
		addressType: "domain",
		auth,
		httpPath: `${parsedTarget.pathname}${parsedTarget.search}`,
		headers,
	});
	const rawResp = tcpRes.rawHttpResponse ?? "";
	const bodyLen = Buffer.byteLength(tcpRes.body ?? "", "utf8");
	const displayCmd = `curl -sS -i --proxy ${safeProxyDisplay} ${targetUrl}`;
	const formattedOut = `${rawResp}\nhttp_code=${tcpRes.httpStatus ?? 0} size_download=${bodyLen} remote_ip=127.0.0.1 time_total=0.005`.trim();
	return {
		ok: tcpRes.ok && (tcpRes.httpStatus ?? 0) > 0,
		command: displayCmd,
		output: formattedOut,
		statusCode: tcpRes.httpStatus ?? 0,
	};
}

interface RegisteredToolLike {
	name: string;
	execute(
		id: string,
		params: Record<string, unknown>,
		signal: AbortSignal | undefined,
		onUpdate: unknown,
		ctx: unknown,
	): Promise<{ content: Array<{ type: string; text: string }>; details?: Record<string, unknown> }>;
}

async function runMockOmpMain(): Promise<number> {
	const cli = parseMockOmpArgs(process.argv.slice(2));
	const root = resolve(process.env.NUWA_PROJECT?.trim() || cli.cwd);
	const scenario = (process.env.NUWA_L3_SCENARIO ?? "l3-async-socks5-finding").trim();
	const mockLlmUrl = (process.env.NUWA_L3_MOCK_LLM_URL ?? "").trim();
	const targetBaseUrl = (process.env.NUWA_L3_TARGET_URL ?? process.env.NUWA_TARGET ?? "").trim().replace(/\/+$/, "");
	const telemetryFile = process.env.NUWA_L3_TELEMETRY_FILE?.trim();
	const vaultTestSecret = (process.env.NUWA_L3_VAULT_SECRET ?? "l3_vault_jwt_secret_token_do_not_leak_2026").trim();
	const rawEgressProxy = (
		process.env.NUWA_EGRESS_PROXY ??
		process.env.NUWA_EGRESS ??
		process.env.ALL_PROXY ??
		""
	).trim();

	// 1. 真实通过 Bun.fetch 调用本地模拟模型 API（验证 --egress-proxy socks5h:// 下 Bun fetch 零代理协议崩溃）
	let modelFetchOk = false;
	let modelFetchStatus = 0;
	let modelFetchError: string | undefined;
	if (!mockLlmUrl) {
		throw new Error("缺少 NUWA_L3_MOCK_LLM_URL 环境变量");
	}
	try {
		const resp = await fetch(`${mockLlmUrl}/v1/chat/completions`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				model: cli.model ?? "nuwa-l3-mock-llm",
				scenario,
				messages: [{ role: "user", content: cli.prompt.slice(0, 500) }],
			}),
		});
		modelFetchStatus = resp.status;
		const data = (await resp.json()) as { ok?: boolean };
		modelFetchOk = resp.ok && Boolean(data?.ok);
	} catch (err) {
		modelFetchError = err instanceof Error ? err.message : String(err);
	}

	if (!modelFetchOk) {
		writeTelemetry(telemetryFile, {
			scenario,
			pid: process.pid,
			cwd: cli.cwd,
			nuwaProjectEnv: root,
			httpProxyEnv: process.env.HTTP_PROXY ?? null,
			httpsProxyEnv: process.env.HTTPS_PROXY ?? null,
			egressProxyMasked: maskEgressUrl(rawEgressProxy) ?? null,
			modelFetchOk: false,
			modelFetchStatus,
			modelFetchError: modelFetchError ?? `HTTP ${modelFetchStatus}`,
			asyncWatchdogPeak: 0,
			asyncWatchdogFinal: 0,
			promptSnippet: cli.prompt.slice(0, 160),
		});
		return 11;
	}

	// 2. 动态加载扩展模块并模拟完整 omp 18.16.0 插件宿主生命周期
	const defaultExtEntry = resolve(import.meta.dir, "..", "..", "omp", "nuwa.ts");
	const extEntry = process.env.NUWA_L3_EXT_ENTRY?.trim()
		? resolve(process.env.NUWA_L3_EXT_ENTRY.trim())
		: defaultExtEntry;
	if (!existsSync(extEntry)) {
		throw new Error(`扩展入口文件不存在: ${extEntry}`);
	}

	const extMod = (await import(extEntry)) as { default: (api: unknown) => void };
	const tools = new Map<string, RegisteredToolLike>();
	const hooks = new Map<string, Array<(...args: unknown[]) => unknown>>();

	extMod.default({
		zod: makeMockZod(),
		registerTool: (t: RegisteredToolLike) => tools.set(t.name, t),
		registerCommand: () => {},
		sendUserMessage: () => {},
		sendMessage: () => {},
		on: (evName: string, handler: (...args: unknown[]) => unknown) => {
			const list = hooks.get(evName) ?? [];
			list.push(handler);
			hooks.set(evName, list);
		},
	});

	const sessionId = `l3-sess-${scenario}-${process.pid}`;
	const mainCtx = {
		cwd: root,
		agent: { kind: "main", id: "main-0", name: "main", depth: 0 },
		sessionManager: { getSessionId: () => sessionId },
		getContextUsage: () => ({ tokens: 4096, usedTokens: 4096 }),
		ui: {
			theme: { fg: (_c: string, t: string) => t, bold: (t: string) => t },
			setStatus: () => {},
			setWidget: () => {},
			setTitle: () => {},
			notify: () => {},
			custom: async () => undefined,
		},
	};

	const emitHook = (name: string, event: unknown, ctx: unknown = mainCtx): unknown => {
		let lastOut: unknown;
		for (const fn of hooks.get(name) ?? []) {
			const r = fn(event, ctx);
			if (r !== undefined) lastOut = r;
		}
		return lastOut;
	};

	const callNuwaTool = async (name: string, args: Record<string, unknown>) => {
		const t = tools.get(name);
		if (!t) throw new Error(`未注册核心工具: ${name}`);
		const res = await t.execute(`call-${name}-${Date.now()}`, args, undefined, undefined, mainCtx);
		if (res.details?.error) {
			throw new Error(`工具 ${name} 调用失败: ${res.content[0]?.text ?? "unknown"}`);
		}
		return res;
	};

	emitHook("session_start", {});

	let asyncWatchdogPeak = 0;
	let asyncWatchdogFinal = 0;

	try {
		if (scenario === "l3-async-socks5-finding") {
			if (!rawEgressProxy) throw new Error("场景 l3-async-socks5-finding 需要配置 SOCKS5h 出口代理");

			await callNuwaTool("nuwa_init", {
				target: targetBaseUrl,
				mode: "pentest",
				goal: "L3 异步派单与 SOCKS5h 双盲复验实锤验收",
				root,
			});
			upsertSessionRole(root, { role: "auditor_alice", bearer: vaultTestSecret });

			await callNuwaTool("nuwa_claim", { id: "i001", worker: "fujiang", root });

			// 模拟真实 omp 18.16.0 异步派单竞态：tool_call -> tool_execution_end(async.state="running") -> before_subagent_spawn(无内联 task)
			const tcOut = emitHook("tool_call", {
				toolName: "task",
				toolCallId: "tc-l3-async-1",
				input: {
					tasks: [
						{
							agent: "fujiang",
							task: "[女娲派单 i001] 经 SOCKS5h 探测 [TARGET]/api/v1/internal/backup-manifest 敏感备份清单暴露",
						},
					],
				},
			}) as { block?: boolean; input?: { tasks?: Array<{ task?: string }> } } | undefined;
			if (tcOut?.block) throw new Error("主线程合法异步 task 被误拦截");

			emitHook("tool_execution_end", {
				toolName: "task",
				toolCallId: "tc-l3-async-1",
				result: {
					details: {
						async: { state: "running" },
						progress: [{ index: 0, id: "async-fujiang-l3-01", status: "pending" }],
						results: [],
					},
				},
			});

			const spRes = emitHook("before_subagent_spawn", {
				type: "before_subagent_spawn",
				agent: "fujiang",
				invocationKind: "task",
				spawnKey: "async-fujiang-l3-01",
			}) as { block?: boolean; task?: string } | undefined;
			if (!spRes || spRes.block || !String(spRes.task ?? "").includes("/api/v1/internal/backup-manifest")) {
				throw new Error(`异步 before_subagent_spawn 放行异常: ${JSON.stringify(spRes)}`);
			}

			const wd = new SubagentWatchdog(root);
			asyncWatchdogPeak = Math.max(asyncWatchdogPeak, wd.activeCount());

			// 子代理真实经由 SOCKS5h (`ATYP=0x03` 域名透传) 请求本地靶机漏洞接口
			const probe1 = await probeTargetOverSocks5h(`${targetBaseUrl}/api/v1/internal/backup-manifest`, rawEgressProxy);
			if (!probe1.ok || probe1.statusCode !== 200) {
				throw new Error(`经 SOCKS5h 探测靶机失败: status=${probe1.statusCode}`);
			}

			const subFujiangCtx = {
				...mainCtx,
				agent: { kind: "sub", id: "async-fujiang-l3-01", name: "fujiang", parentId: "main-0", depth: 1 },
				sessionManager: { getSessionId: () => `${sessionId}-sub-1`, getParentSessionId: () => sessionId },
			};
			emitHook(
				"tool_execution_end",
				{
					toolName: "bash",
					toolCallId: "sub-bash-l3-1",
					input: { command: probe1.command },
					result: { stdout: probe1.output },
				},
				subFujiangCtx,
			);

			// 异步子代理执行完毕，通过 tool_result 精确回收看门狗
			emitHook("tool_result", {
				toolName: "task",
				toolCallId: "tc-l3-async-1",
				result: {
					details: {
						results: [{ id: "async-fujiang-l3-01", status: "completed" }],
					},
				},
			});

			const commitCand = await callNuwaTool("nuwa_commit", {
				id: "i001",
				kind: "vuln",
				title: "未授权敏感备份清单暴露 (/api/v1/internal/backup-manifest)",
				detail: "匿名经 SOCKS5h 访问返回生产数据库快照清单与对象存储桶元数据",
				command: probe1.command,
				output: probe1.output,
				save_evidence_log: true,
				root,
			});

			const verifyIntentId = String(commitCand.details?.verifyIntent ?? "");
			if (!verifyIntentId) {
				throw new Error("提交候选 vuln 后未自动派生双盲复验意图 verifyIntent");
			}

			await Bun.sleep(5);
			await callNuwaTool("nuwa_claim", { id: verifyIntentId, worker: "nuwa-verifier", root });

			// 第二阶段：使用 eval 多步异步 agent({ label, prompt }) 驱动双盲复验员 nuwa-verifier
			const evalOut = emitHook("tool_call", {
				toolName: "eval",
				toolCallId: "tc-l3-eval-ver",
				input: {
					code: `agent({ agent: "nuwa-verifier", label: "verifier-l3", prompt: "[女娲派单 ${verifyIntentId}] 对 http://TARGET/api/v1/internal/backup-manifest 执行正负对照双盲复验" });`,
				},
			}) as { block?: boolean } | undefined;
			if (evalOut?.block) throw new Error("eval 双盲复验派单被误拦截");

			emitHook("tool_execution_end", {
				toolName: "eval",
				toolCallId: "tc-l3-eval-ver",
				isError: false,
				result: { text: "spawned verifier-l3" },
			});

			const verSpawn = emitHook("before_subagent_spawn", {
				type: "before_subagent_spawn",
				agent: "nuwa-verifier",
				invocationKind: "eval",
				spawnKey: "parent.verifier-l3",
			}) as { block?: boolean; task?: string } | undefined;
			if (!verSpawn || verSpawn.block) {
				throw new Error(`eval 异步复验派生失败: ${JSON.stringify(verSpawn)}`);
			}
			asyncWatchdogPeak = Math.max(asyncWatchdogPeak, new SubagentWatchdog(root).activeCount());

			const probePos = await probeTargetOverSocks5h(`${targetBaseUrl}/api/v1/internal/backup-manifest?verify=1`, rawEgressProxy);
			const probeNeg = await probeTargetOverSocks5h(`${targetBaseUrl}/api/v1/internal/nonexistent-control`, rawEgressProxy);
			if (!probePos.ok || probePos.statusCode !== 200 || probeNeg.statusCode !== 404) {
				throw new Error(`双盲复验正负对照状态异常: pos=${probePos.statusCode} neg=${probeNeg.statusCode}`);
			}

			const subVerCtx = {
				...mainCtx,
				agent: { kind: "sub", id: "parent.verifier-l3", name: "nuwa-verifier", parentId: "main-0", depth: 1 },
				sessionManager: { getSessionId: () => `${sessionId}-ver-1`, getParentSessionId: () => sessionId },
			};
			const verifyCombinedOut = `${probePos.output}\n--- NEGATIVE_CONTROL (404) ---\nstatus=${probeNeg.statusCode}`;
			emitHook(
				"tool_execution_end",
				{
					toolName: "bash",
					toolCallId: "sub-bash-l3-ver",
					input: { command: probePos.command },
					result: { stdout: verifyCombinedOut },
				},
				subVerCtx,
			);

			emitHook("tool_result", {
				toolName: "task",
				toolCallId: "js-eval-ver-done",
				result: { details: { results: [{ id: "parent.verifier-l3", status: "completed" }] } },
			});
			asyncWatchdogFinal = new SubagentWatchdog(root).activeCount();

			await callNuwaTool("nuwa_commit", {
				id: verifyIntentId,
				kind: "vuln",
				title: "[Verified] 未授权敏感备份清单暴露已双盲确认",
				detail: "独立复验正向 HTTP 200 返回真实快照结构，负向随机对照 HTTP 404，排除 Soft-404",
				command: probePos.command,
				output: verifyCombinedOut,
				root,
			});

			const comp = await callNuwaTool("nuwa_complete", { root });
			if (!comp.details?.ok) {
				throw new Error(`nuwa_complete 验收未通过: ${comp.content[0]?.text ?? ""}`);
			}
			await callNuwaTool("nuwa_report", { write: true, format: "md", bundle: true, root });
			await callNuwaTool("nuwa_report", { write: true, format: "json", root });
			await callNuwaTool("nuwa_report", { write: true, format: "sarif", root });
		} else if (scenario === "l3-hardened-seal-noop") {
			const existing = loadState(root);
			if (
				existing &&
				(existing.project.status === "sealed_negative" || existing.runtime.status === "sealed_negative")
			) {
				// 重入验证：调用 nuwa_init(resume=true) 必须保持 sealed_negative 只读不复活
				const reInit = await callNuwaTool("nuwa_init", { root, resume: true });
				if (reInit.details?.status !== "sealed_negative" || reInit.details?.readonly !== true) {
					throw new Error(`硬化封盘重入未保持只读 sealed_negative: ${JSON.stringify(reInit.details)}`);
				}
			} else {
				await callNuwaTool("nuwa_init", {
					target: targetBaseUrl,
					mode: "pentest",
					goal: "硬化零洞参考服务全面排查与负向封盘验证",
					root,
				});
				upsertSessionRole(root, { role: "readonly_viewer", bearer: vaultTestSecret });
				await callNuwaTool("nuwa_claim", { id: "i001", worker: "fujiang", root });

				const healthProbe = rawEgressProxy
					? await probeTargetOverSocks5h(`${targetBaseUrl}/health`, rawEgressProxy)
					: {
							ok: true,
							command: `curl -sS -i ${targetBaseUrl}/health`,
							output: `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"hardened"}`,
							statusCode: 200,
						};
				const adminProbe = rawEgressProxy
					? await probeTargetOverSocks5h(`${targetBaseUrl}/api/v1/admin/config`, rawEgressProxy)
					: {
							ok: true,
							command: `curl -sS -i ${targetBaseUrl}/api/v1/admin/config`,
							output: `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{"error":"forbidden"}`,
							statusCode: 403,
						};
				if (adminProbe.statusCode !== 403) {
					throw new Error(`硬化靶机预期返回 403，实际: ${adminProbe.statusCode}`);
				}

				await callNuwaTool("nuwa_commit", {
					id: "i001",
					kind: "service",
					title: "硬化网关 RBAC 校验生效 (/health=200, /api/v1/admin/config=403)",
					detail: "全部管理端点强制鉴权拦截且排除 Soft-404 诱饵，无正向可利用面",
					command: healthProbe.command,
					output: `${healthProbe.output}\n---\n${adminProbe.output}`,
					root,
				});

				await callNuwaTool("nuwa_report", { write: true, format: "md", root });
				await callNuwaTool("nuwa_report", { write: true, format: "json", root });
				await callNuwaTool("nuwa_complete", {
					seal: true,
					reason: "全攻击面经实测均为严格 403 鉴权与静态健康探针，零有效漏洞，执行负向封盘",
					excluded_surface: ["/health", "/api/v1/admin/config", "/spa/not-found"],
					root,
				});
			}
		} else if (scenario === "l3-stopped-resume-migrate") {
			// 验证已从 /tmp 迁移至持久化目录且收到 --resume-stopped 恢复指令
			if (!cli.prompt.includes("停机续跑")) {
				throw new Error("预期收到包含“停机续跑”的守护器恢复提示词");
			}
			const resumed = await callNuwaTool("nuwa_init", {
				root,
				resume: true,
				force: true,
			});
			if (resumed.details?.error) {
				throw new Error("停机迁移后 nuwa_init(resume=true, force=true) 恢复失败");
			}
			const stAfterResume = loadState(root);
			if (!stAfterResume || stAfterResume.project.status !== "active") {
				throw new Error(`恢复后状态未变为 active: ${stAfterResume?.project.status ?? "null"}`);
			}

			const flagProbe = await probeTargetOverSocks5h(`${targetBaseUrl}/api/v1/ctf/flag`, rawEgressProxy);
			const flagMatch = /flag\{[^}\s]+\}/.exec(flagProbe.output);
			if (!flagProbe.ok || !flagMatch) {
				throw new Error(`迁移续跑后经 SOCKS5h 获取 Flag 失败: ${flagProbe.output.slice(0, 160)}`);
			}
			const flagVal = flagMatch[0]!;

			emitHook("tool_execution_end", {
				toolName: "bash",
				toolCallId: "tc-l3-mig-flag",
				input: { command: flagProbe.command },
				result: { stdout: flagProbe.output },
			});

			await callNuwaTool("nuwa_flag", {
				value: flagVal,
				command: flagProbe.command,
				output: flagProbe.output,
				root,
			});
			const comp = await callNuwaTool("nuwa_complete", { root });
			if (!comp.details?.ok) {
				throw new Error(`迁移续跑完成后 nuwa_complete 失败: ${comp.content[0]?.text ?? ""}`);
			}
			await callNuwaTool("nuwa_report", { write: true, format: "md", bundle: true, root });
			await callNuwaTool("nuwa_report", { write: true, format: "json", root });
			await callNuwaTool("nuwa_report", { write: true, format: "sarif", root });
		} else {
			throw new Error(`未知的 NUWA_L3_SCENARIO: ${scenario}`);
		}
	} finally {
		emitHook("session_shutdown", {});
	}

	const finalSt = loadState(root);
	writeTelemetry(telemetryFile, {
		scenario,
		pid: process.pid,
		cwd: cli.cwd,
		nuwaProjectEnv: root,
		httpProxyEnv: process.env.HTTP_PROXY ?? null,
		httpsProxyEnv: process.env.HTTPS_PROXY ?? null,
		egressProxyMasked: maskEgressUrl(rawEgressProxy) ?? null,
		modelFetchOk,
		modelFetchStatus,
		asyncWatchdogPeak,
		asyncWatchdogFinal,
		promptSnippet: cli.prompt.slice(0, 160),
		finalProjectStatus: finalSt?.project.status,
	});
	return 0;
}

if (import.meta.main) {
	runMockOmpMain()
		.then((code) => process.exit(code))
		.catch((err) => {
			process.stderr.write(`[mock-omp-bin] FATAL: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
			process.exit(1);
		});
}
