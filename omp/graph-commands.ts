/**
 * 女娲 v6.0 斜杠命令工作流、环境体检与只读分析视图模块。
 *
 * 约束：仅依赖底层引擎与 `./graph-planner`，严禁运行时 `import "./nuwa"` 或 `import "./graph"`。
 */
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
	NUWA_VERSION,
	PHASE_ORDER,
	type Phase,
	type Fact,
	type Mode,
	type NuwaState,
	type ScopePolicy,
} from "./types";
import {
	cell,
	checkAndLogAutoRuleSource,
	getAgentHome,
	loadState,
	loadStateJsonOnly,
	logEvent,
	nextFactId,
	normOneLine,
	nowIso,
	readCfg,
	resolveStorageBackend,
	saveState,
	sha,
	sqliteDbPath,
	withLock,
} from "./storage";
import { defaultScopeForTarget } from "./scope";
import { getLatestLedgerSeq, probeToolchain, recordToolExecution } from "./evidence";
import { ensureBundledKb, getKbStats } from "./kb";
import {
	buildRefreshIntentSpec,
	checkRoleHealth,
	clearSessionVault,
	formatSessionVaultSummary,
	getRoleHeadersMap,
	loadSessionVault,
	removeSessionRole,
	upsertSessionRole,
} from "./session-vault";
import { buildDoubleBlindVerifyIntentSpec } from "./verifier-gate";
import { probeDockerAvailable, readSandboxConfig } from "./sandbox";
import { runAuthDiffMatrix, type AuthDiffMatrixOptions, type AuthDiffMatrixResult } from "./auth-diff";
import { buildOobEvidenceFact, generateOobCanary, loadOobCanaries, pollOobCallbacks } from "./oob";
import { formatAssetTopology, syncAssetsFromFacts } from "./hypothesis";
import { extractProbeHealth } from "./ui";
import { formatProfileReportTitle } from "./profiles";
import { partitionFactsByVerifyStage } from "./verifier-gate";
import { renderStratifiedMarkdownReport } from "./reporting";
import {
	budgetPressure,
	buildConvergenceAdvice,
	claimedFresh,
	computeRepeatRatio,
	frontierList,
	shouldRecommendSeal,
} from "./graph-planner";
import {
	appendIntentSpecs,
	beliefGraphPath,
	loadBeliefGraphReadOnly,
} from "./graph-planner";
import { loadStateFromSqlite, openNuwaDb } from "./sqlite-store";
import {
	initBeliefGraphFromState,
	rankFrontierByBelief,
	recommendSearchPivot,
} from "./belief-search";
import {
	calibrationLedgerPath,
	computeCalibrationSummary,
	formatCalibrationReport,
	loadCalibrationRecords,
	recommendAdaptiveModelRoute,
} from "./calibration";
import { TrafficRecorder, type TrafficQueryFilter } from "./traffic-workbench";
import {
	bridgeWhiteboxToBlackboxIntents,
	correlateBlackboxFindingToSource,
	extractCodeAttackSurface,
	extractFromSourceMap,
} from "./hybrid-audit";
import { ALLOWED_SUBAGENT_MODELS, DEFAULT_SUBAGENT_MODEL } from "./lineage";

const VERSION = NUWA_VERSION;

/** 纯只读加载项目状态（不触发任何迁移或写盘副作用，用于只读诊断视图）。 */
function loadStateStrictlyReadOnly(root: string): NuwaState | null {
	const normRoot = resolve(root);
	const backend = resolveStorageBackend(normRoot);
	const dbFile = sqliteDbPath(normRoot);
	if ((backend === "sqlite" || backend === "dual") && existsSync(dbFile)) {
		try {
			const fromDb = loadStateFromSqlite(normRoot, { fallbackToJson: false });
			if (fromDb) return fromDb;
		} catch {
			/* 回退只读 JSON */
		}
	}
	const fromJson = loadStateJsonOnly(normRoot);
	if (fromJson) return fromJson;
	if (existsSync(dbFile)) {
		try {
			return loadStateFromSqlite(normRoot, { fallbackToJson: false });
		} catch {
			return null;
		}
	}
	return null;
}

// ---------------------------------------------------------------- /nuwa <任务> 解析

const TASK_URL_RE = /https?:\/\/[^\s"'`）)，。；;、]+/i;
const TASK_IP_RE = /\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b/;
const TASK_HOST_RE = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})(?::(\d{1,5}))?\b/i;
/** 文件名后缀不是主机名：state.json / app.ts 这类不该被当成 target。 */
const FILE_EXT = new Set(
	"json md ts tsx js jsx py go rs java php rb sh yml yaml toml ini log txt db sqlite html css xml zip tar gz tgz jar war bin exe dll so".split(" "),
);

/** 从自然语言任务里抽目标：URL → IPv4[:port] → 主机名[:port] → NUWA_TARGET/TARGET 环境变量。 */
export function extractTarget(text: string): string | null {
	const url = text.match(TASK_URL_RE);
	if (url) return url[0].replace(/[.,;:!?]+$/, "");
	const ip = text.match(TASK_IP_RE);
	if (ip) return `http://${ip[1]}:${ip[2] ?? 80}`;
	const host = text.match(TASK_HOST_RE);
	if (host && !FILE_EXT.has(host[1].split(".").pop()!.toLowerCase())) {
		return `http://${host[1]}:${host[2] ?? 80}`;
	}
	const env = (process.env.NUWA_TARGET ?? process.env.TARGET ?? "").trim();
	return env || null;
}

/** 任务语义 → 模式：审计 / 渗透 / 软件工程 / 运维 / ctf。 */
export function pickMode(text: string): Mode {
	if (/(代码审计|审计|白盒|静态分析|源码|audit|review|source\s*review)/i.test(text)) return "audit";
	if (/(渗透|打点|提权|横向|内网|域控|红队|拿权限|getshell|pentest|exploit|c2)/i.test(text)) return "pentest";
	if (!/(flag|靶场|ctf)/i.test(text)) {
		if (/(重构|开发功能|编写单测|修复\s*bug|coding|refactor|implement)/i.test(text)) return "coding";
		if (/(运维巡检|故障排查|服务恢复|告警处置|runbook|\bops\b)/i.test(text)) return "ops";
	}
	return "ctf";
}

/** 起跑 directive：作为用户消息打回主线程，触发第 1 轮。 */
export function kickPrompt(st: NuwaState): string {
	const p = st.project;
	const open = Object.values(st.intents).filter((i) => i.status === "open").length;
	const flags = Object.values(st.facts).filter((f) => f.kind === "flag").length;
	return [
		`[女娲 v${VERSION} · 开工] ${p.id} · ${p.url} · mode=${p.mode} · phase=${p.phase} · open=${open} · flags=${flags}`,
		`目标: ${p.goal}`,
		"",
		"现在开始第 1 轮，按顺序直接做，不要复述任务、不要问我：",
		"1) nuwa_frontier 取 eligible 意图（最多 6 条并行）",
		"2) 每条 nuwa_claim(id) 拿 packet",
		'3) task({tasks:[{agent:"fujiang", task:"<packet>"}]}) 并行派发',
		"4) 回包后 nuwa_commit(id, kind, title, command, output) 记账；拿到 flag 用 nuwa_flag",
		"5) 阶段清空先 nuwa_expand() 自动扩张；frontier 空会自动开下一轮 episode；卡住用 nuwa_commit(blocked=true, note=原因) 换路",
		"6) 只有 nuwa_complete 返回 ok=true 才收工；在此之前系统每轮自动续跑，禁止输出“收工/等待指示”",
		"纪律：主线程不扫端口、不走 CLI、不写 .nuwa/state.json；扫描与利用全部在 fujiang 子代理里执行。",
	].join("\n");
}

export function formatScopeSummary(scope: ScopePolicy): string {
	return [
		`Scope 策略:`,
		`- allowHosts: ${scope.allowHosts.join(", ") || "(无)"}`,
		`- allowCidrs: ${scope.allowCidrs.join(", ") || "(无)"}`,
		`- denyHosts: ${scope.denyHosts.join(", ") || "(无)"}`,
		`- allowSubdomains: ${scope.allowSubdomains}`,
		`- allowPrivateNetwork: ${scope.allowPrivateNetwork}`,
		`- allowLoopback: ${scope.allowLoopback ?? true}`,
		`- oobDomains: ${(scope.oobDomains ?? []).join(", ") || "(无)"}`,
		`- allowDestructive: ${scope.allowDestructive}`,
	].join("\n");
}

export function pickPrimaryVaultRole(root: string): { role: string; headers: Record<string, string> } | null {
	try {
		const vault = loadSessionVault(root);
		const names = Object.keys(vault.roles ?? {}).sort();
		if (names.length === 0) return null;
		const now = Date.now();
		// 优先选择未过期的角色
		const chosen =
			names.find((r) => {
				const exp = vault.roles[r]?.expiresAt;
				return !exp || !Number.isFinite(Date.parse(exp)) || Date.parse(exp) > now;
			}) ?? names[0]!;
		const headers = getRoleHeadersMap(vault, chosen);
		return headers && Object.keys(headers).length > 0 ? { role: chosen, headers } : null;
	} catch {
		return null;
	}
}

export function extractEventOutput(ev: Record<string, unknown>): {
	toolName: string;
	inputObj: Record<string, unknown> | null;
	command?: string;
	output: string;
} {
	const toolName = String(ev.toolName ?? ev.name ?? "tool");
	const rawInput = ev.input ?? ev.args ?? null;
	const inputObj = rawInput && typeof rawInput === "object" ? (rawInput as Record<string, unknown>) : null;
	const input = inputObj ?? {};
	const command =
		typeof input.command === "string"
			? input.command
			: typeof input.code === "string"
				? input.code
				: typeof input.url === "string"
					? input.url
					: typeof input.path === "string"
						? input.path
						: undefined;
	const rawRes = ev.result ?? ev.output ?? ev.response;
	let output = "";
	if (typeof rawRes === "string") {
		output = rawRes;
	} else if (rawRes && typeof rawRes === "object") {
		const obj = rawRes as Record<string, unknown>;
		if (typeof obj.stdout === "string" || typeof obj.stderr === "string") {
			output = `${obj.stdout ?? ""}\n${obj.stderr ?? ""}`.trim();
		} else if (typeof obj.output === "string") {
			output = obj.output;
		} else if (typeof obj.text === "string") {
			output = obj.text;
		} else if (Array.isArray(obj.content)) {
			output = obj.content
				.map((c: unknown) =>
					c && typeof c === "object" && typeof (c as { text?: unknown }).text === "string"
						? (c as { text: string }).text
						: "",
				)
				.filter(Boolean)
				.join("\n");
		} else {
			try {
				output = JSON.stringify(rawRes);
			} catch {
				output = "";
			}
		}
	}
	return { toolName, inputObj, command, output };
}

export function parseSessionSetArgs(rawRest: string): {
	role: string;
	cookie?: string;
	bearer?: string;
	username?: string;
	password?: string;
	headers?: Record<string, string>;
} | null {
	const trimmed = rawRest.trim();
	if (!trimmed) return null;
	const firstSpace = trimmed.search(/\s/);
	if (firstSpace < 0) return null;
	const role = trimmed.slice(0, firstSpace).trim();
	const body = trimmed.slice(firstSpace + 1).trim();
	if (!role || !body) return null;

	let cookie: string | undefined;
	let bearer: string | undefined;
	let username: string | undefined;
	let password: string | undefined;
	const headers: Record<string, string> = {};

	const tokenRe = /(cookie|bearer|token|user|username|pass|password|header)=("[^"]*"|'[^']*'|\S+)/gi;
	let matched = false;
	for (const m of body.matchAll(tokenRe)) {
		matched = true;
		const k = m[1]!.toLowerCase();
		const v = m[2]!.replace(/^['"]|['"]$/g, "");
		if (k === "cookie") cookie = v;
		else if (k === "bearer" || k === "token") bearer = v;
		else if (k === "user" || k === "username") username = v;
		else if (k === "pass" || k === "password") password = v;
		else if (k === "header") {
			const colon = v.indexOf(":");
			if (colon > 0) {
				headers[v.slice(0, colon).trim()] = v.slice(colon + 1).trim();
			}
		}
	}

	if (!matched) {
		if (/^Bearer\s+/i.test(body) || /^eyJ[A-Za-z0-9_-]+\./.test(body)) {
			bearer = body.replace(/^Bearer\s+/i, "").trim();
		} else if (body.includes("=")) {
			cookie = body;
		} else if (body.includes(":")) {
			const idx = body.indexOf(":");
			username = body.slice(0, idx).trim();
			password = body.slice(idx + 1).trim();
		} else {
			bearer = body;
		}
	}

	return {
		role,
		...(cookie ? { cookie } : {}),
		...(bearer ? { bearer } : {}),
		...(username ? { username } : {}),
		...(password ? { password } : {}),
		...(Object.keys(headers).length ? { headers } : {}),
	};
}

export function buildDoctorSummary(foundRoot: string | null): string {
	const agentHome = getAgentHome();
	try {
		ensureBundledKb(undefined, { agentHome });
	} catch {
		/* ignore */
	}
	const kb = getKbStats(undefined, { agentHome });
	const tc = probeToolchain();
	const sbCfg = readSandboxConfig();
	const dockerProbe =
		sbCfg.mode === "docker" ? probeDockerAvailable({ dockerBin: sbCfg.dockerBin, image: sbCfg.image }) : null;

	const repoAgentsDir = resolve(import.meta.dir, "..", "agents");
	const hasFujiang =
		existsSync(join(agentHome, "agents", "fujiang.md")) || existsSync(join(repoAgentsDir, "fujiang.md"));
	const hasVerifier =
		existsSync(join(agentHome, "agents", "nuwa-verifier.md")) || existsSync(join(repoAgentsDir, "nuwa-verifier.md"));
	const backend = resolveStorageBackend(foundRoot ?? undefined);

	const lines = [
		`[女娲 v${VERSION} 环境体检]`,
		`- Agent Home: ${agentHome}`,
		`- 存储后端: mode=${backend} (NUWA_STORAGE_BACKEND=json|sqlite|dual)`,
		`- 便携知识库: ${kb.exists ? "READY" : "MISSING"} (${kb.dbPath}) · cards=${kb.cards} cves=${kb.cves} techniques=${kb.techniques} experiences=${kb.experiences}`,
		`- 子代理模板: fujiang=${hasFujiang ? "OK" : "MISSING"} · nuwa-verifier=${hasVerifier ? "OK" : "MISSING"}`,
		`- 本地工具链: available=[${tc.available.join(", ") || "无"}] · missing=[${tc.missing.join(", ") || "无"}]`,
		`- 容器沙盒: mode=${sbCfg.mode}${dockerProbe ? ` · docker=${dockerProbe.available ? "READY" : `UNAVAILABLE(${dockerProbe.reason ?? "unknown"})`}` : ""}`,
	];

	if (foundRoot) {
		const st = loadStateStrictlyReadOnly(foundRoot);
		if (st) {
			const cand = Object.values(st.facts).filter((f) => f.verifyStage === "candidate").length;
			const hasDb = existsSync(sqliteDbPath(foundRoot));
			const hasCalib = existsSync(calibrationLedgerPath(foundRoot));
			let roleCount = 0;
			try {
				roleCount = Object.keys(loadSessionVault(foundRoot).roles).length;
			} catch {
				roleCount = st.project.activeRoles?.length ?? 0;
			}
			lines.push(
				`- 当前项目: ${st.project.id} (${st.project.status}) · phase=${st.project.phase} · facts=${Object.keys(st.facts).length} · cand=${cand} · roles=${roleCount} · sqlite=${hasDb ? "YES" : "NO"} · calib=${hasCalib ? "YES" : "NO"}`,
			);
		}
	}
	return lines.join("\n");
}

export function isCompliantSandboxDockerCommand(cmd: string, projectId: string): { ok: boolean; reason?: string } {
	const trimmed = cmd.trim();
	if (!/^docker\s+run\b/.test(trimmed)) {
		return { ok: false, reason: "命令未通过 docker run 容器沙盒包裹执行" };
	}
	if (/--privileged\b|--network\s*=?\s*host\b|docker\.sock/.test(trimmed)) {
		return { ok: false, reason: "严禁在沙盒命令中使用 --privileged、--network=host 或挂载 docker.sock" };
	}
	if (!trimmed.includes("--cap-drop=ALL") || !trimmed.includes("--read-only")) {
		return { ok: false, reason: "沙盒命令缺少 --cap-drop=ALL 或 --read-only 零信任硬约束" };
	}
	if (!trimmed.includes(`/tmp/nuwa/${projectId}:`)) {
		return { ok: false, reason: `沙盒命令仅允许挂载项目隔离目录 /tmp/nuwa/${projectId}` };
	}
	return { ok: true };
}

export function executeSessionCommand(found: string | null, subArg: string): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const sub = subArg.trim();
	if (!sub || sub === "list") return { msg: formatSessionVaultSummary(found), level: "info" };
	if (sub === "clear") {
		const st = loadState(found);
		clearSessionVault(found, st?.project.id);
		withLock(found, () => {
			const s = loadState(found);
			if (!s) return;
			s.project.activeRoles = [];
			saveState(found, s);
			logEvent(found, { type: "vault_clear", via: "command" });
		});
		return { msg: "已清空当前项目的会话保险箱及角色物化头文件", level: "info" };
	}
	if (sub.startsWith("remove ")) {
		const role = sub.slice(7).trim();
		if (!role) return { msg: "用法: /nuwa session remove <role>", level: "error" };
		const ok = removeSessionRole(found, role);
		withLock(found, () => {
			const s = loadState(found);
			if (!s) return;
			s.project.activeRoles = Object.keys(loadSessionVault(found).roles).sort();
			saveState(found, s);
			logEvent(found, { type: "vault_remove", role, ok, via: "command" });
		});
		return {
			msg: ok ? `已移除角色会话: ${role}\n${formatSessionVaultSummary(found)}` : `未找到角色: ${role}`,
			level: ok ? "info" : "error",
		};
	}
	if (sub.startsWith("set ")) {
		const parsed = parseSessionSetArgs(sub.slice(4));
		if (!parsed) {
			return { msg: '用法: /nuwa session set <role> cookie="sid=..." | bearer="..." | user=<u> pass=<p>', level: "error" };
		}
		try {
			upsertSessionRole(found, parsed);
			withLock(found, () => {
				const s = loadState(found);
				if (!s) return;
				s.project.activeRoles = Object.keys(loadSessionVault(found).roles).sort();
				saveState(found, s);
				logEvent(found, { type: "vault_set", role: parsed.role, via: "command" });
			});
			return { msg: `已保存角色 ${parsed.role}（凭据已加密掩码存储）:\n${formatSessionVaultSummary(found)}`, level: "info" };
		} catch (e) {
			return { msg: `会话保存失败: ${e instanceof Error ? e.message : String(e)}`, level: "error" };
		}
	}
	return { msg: "未知 session 子命令。用法: /nuwa session [list | set <role> <cred> | remove <role> | clear]", level: "error" };
}

export function executeScopeCommand(found: string | null, subArg: string): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const sub = subArg.trim();
	if (!sub) {
		const st = loadState(found);
		if (!st) return { msg: "state 读取失败", level: "error" };
		const sc = st.project.scope ?? defaultScopeForTarget(st.project.url || st.project.target, st.project.mode);
		return {
			msg: `${formatScopeSummary(sc)}\n用法: /nuwa scope +host <h> | -host <h> | +cidr <c> | +deny <h> | +oob <d> | -oob <d> | loopback on|off | subdomains on|off | destructive on|off | reset`,
			level: "info",
		};
	}
	const updated = withLock(found, () => {
		const s = loadState(found);
		if (!s) return null;
		let sc: ScopePolicy = s.project.scope ?? defaultScopeForTarget(s.project.url || s.project.target, s.project.mode);
		const [op, val = ""] = sub.split(/\s+/, 2);
		const v = val.trim();
		if (op === "reset") sc = defaultScopeForTarget(s.project.url || s.project.target, s.project.mode);
		else if (op === "+host" && v) {
			if (!sc.allowHosts.includes(v)) sc.allowHosts.push(v);
		} else if (op === "-host" && v) sc.allowHosts = sc.allowHosts.filter((h) => h !== v);
		else if (op === "+cidr" && v) {
			if (!sc.allowCidrs.includes(v)) sc.allowCidrs.push(v);
		} else if (op === "-cidr" && v) sc.allowCidrs = sc.allowCidrs.filter((c) => c !== v);
		else if (op === "+deny" && v) {
			if (!sc.denyHosts.includes(v)) sc.denyHosts.push(v);
		} else if (op === "-deny" && v) sc.denyHosts = sc.denyHosts.filter((d) => d !== v);
		else if (op === "+oob" && v) {
			const normOob = v.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
			const list = sc.oobDomains ?? [];
			if (normOob && !list.includes(normOob)) list.push(normOob);
			sc.oobDomains = list;
		} else if (op === "-oob" && v) {
			const normOob = v.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
			sc.oobDomains = (sc.oobDomains ?? []).filter((d) => d.toLowerCase() !== normOob);
		} else if (op === "loopback") sc.allowLoopback = ["on", "1", "true"].includes(v.toLowerCase());
		else if (op === "subdomains") sc.allowSubdomains = ["on", "1", "true"].includes(v.toLowerCase());
		else if (op === "destructive") sc.allowDestructive = ["on", "1", "true"].includes(v.toLowerCase());
		else return undefined;
		s.project.scope = sc;
		saveState(found, s);
		logEvent(found, { type: "scope_update", cmd: sub, scope: sc });
		return sc;
	});
	if (updated === null) return { msg: "state 读取失败", level: "error" };
	if (updated === undefined) {
		return {
			msg: "未知 scope 指令。用法: /nuwa scope [+host <h>|-host <h>|+cidr <c>|+deny <h>|+oob <d>|-oob <d>|loopback on|off|subdomains on|off|destructive on|off|reset]",
			level: "error",
		};
	}
	return { msg: `已更新靶标范围:\n${formatScopeSummary(updated)}`, level: "info" };
}

/**
 * 执行多角色只读鉴权差分矩阵工作流（/nuwa authdiff）：
 * 自动收集已发现路径或显式路径，按 ScopePolicy 与 Session Vault 执行只读差分，
 * 若发现疑似越权则以 candidate 暂存并自动派生独立双盲复验意图。
 */
export async function executeAuthDiffWorkflow(
	root: string,
	explicitPaths?: string[],
	opts?: AuthDiffMatrixOptions,
): Promise<{ result: AuthDiffMatrixResult; factId?: string; verifyIntentId?: string; msg: string }> {
	const normRoot = resolve(root);
	const st0 = loadState(normRoot);
	if (!st0) throw new Error("未找到有效 .nuwa/state.json");
	if (st0.project.scheme === "local") {
		throw new Error("本地非 HTTP 项目不支持多角色 HTTP 鉴权差分");
	}
	const projScope =
		st0.project.scope ?? defaultScopeForTarget(st0.project.url || st0.project.target, st0.project.mode);

	const pathSet = new Set<string>();
	for (const p of explicitPaths ?? []) {
		if (p.trim()) pathSet.add(p.trim());
	}
	if (pathSet.size === 0) {
		for (const f of Object.values(st0.facts)) {
			for (const mp of f.meta?.paths ?? []) {
				if (mp.startsWith("/")) pathSet.add(mp);
			}
		}
	}
	if (pathSet.size === 0) {
		for (const defPath of ["/admin", "/api/admin", "/api/v1/users", "/api/user/1", "/api/order/1001"]) {
			pathSet.add(defPath);
		}
	}

	const result = await runAuthDiffMatrix(st0.project.url, [...pathSet], normRoot, projScope, opts);
	let factId: string | undefined;
	let verifyIntentId: string | undefined;

	if (result.fact) {
		recordToolExecution(normRoot, {
			tool: "auth-diff",
			command: result.fact.command,
			output: result.fact.output,
		});
		withLock(normRoot, () => {
			const s = loadState(normRoot);
			if (!s) return;
			const fid = nextFactId(s);
			const f: Fact = {
				id: fid,
				kind: "vuln",
				title: normOneLine(result.fact!.title, 120),
				detail: result.fact!.detail,
				command: result.fact!.command,
				output: result.fact!.output,
				key: `authdiff:${sha(`${s.project.id}|${result.fact!.title}`)}`,
				createdAt: nowIso(),
				meta: result.fact!.meta,
				verified: false,
				verifyStage: "candidate",
				evidenceSeq: getLatestLedgerSeq(normRoot),
			};
			s.facts[fid] = f;
			factId = fid;
			const vSpec = buildDoubleBlindVerifyIntentSpec(s, f);
			if (vSpec) {
				const added = appendIntentSpecs(s, [vSpec]);
				verifyIntentId = added[0];
			}
			syncAssetsFromFacts(s);
			saveState(normRoot, s);
			logEvent(normRoot, {
				type: "auth_diff",
				tested: result.testedPaths.length,
				findings: result.findings.length,
				factId,
				verifyIntentId,
			});
		});
	}

	const msg = [
		`多角色鉴权差分完成: roles=[${result.roles.join(",")}] tested=${result.testedPaths.length} findings=${result.findings.length}`,
		...result.findings.slice(0, 6).map((f) => `- [${f.kind}] ${f.summary}`),
		...(factId
			? [`已暂存候选漏洞 ${factId} (verifyStage=candidate)${verifyIntentId ? ` · 自动派发双盲复验 ${verifyIntentId}` : ""}`]
			: ["未发现明显越权差分异常。"]),
	].join("\n");

	return { result, factId, verifyIntentId, msg };
}

/**
 * 执行 `/nuwa oob [list | gen <domain> [purpose] | poll <url> [token]]` 外带回调管理命令。
 */
export async function executeOobCommand(
	found: string | null,
	subArg: string,
	fetchFn?: (url: string, init?: { method?: string; headers?: Record<string, string>; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>,
): Promise<{ msg: string; level: "info" | "error" }> {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const st = loadState(normRoot);
	if (!st) return { msg: "state 读取失败", level: "error" };
	const scope = st.project.scope ?? defaultScopeForTarget(st.project.url || st.project.target, st.project.mode);
	const sub = subArg.trim();

	if (!sub || sub === "list") {
		const list = loadOobCanaries(normRoot);
		const domains = (scope.oobDomains ?? []).join(", ") || "(未配置，请先 /nuwa scope +oob <domain>)";
		if (list.length === 0) {
			return { msg: `OOB 域名白名单: ${domains}\n当前尚无活跃 Canary（用法: /nuwa oob gen <domain> [purpose] | poll <url> [token]）`, level: "info" };
		}
		return {
			msg: [
				`OOB 域名白名单: ${domains}`,
				`活跃 Canary (${list.length}):`,
				...list.map((c) => `- ${c.id}: ${c.fqdn} (hits=${c.matchedHits}${c.purpose ? `, ${c.purpose}` : ""})`),
			].join("\n"),
			level: "info",
		};
	}

	const parts = sub.split(/\s+/);
	const op = parts[0]?.toLowerCase() ?? "";
	if (op === "gen") {
		const domain = parts[1]?.trim() || scope.oobDomains?.[0] || "";
		if (!domain) {
			return { msg: "缺少 OOB 域名。请先 /nuwa scope +oob <domain> 再执行 /nuwa oob gen <domain>", level: "error" };
		}
		const purpose = parts.slice(2).join(" ").trim() || undefined;
		try {
			const canary = generateOobCanary(normRoot, {
				projectId: st.project.id,
				domain,
				scope,
				purpose,
			});
			logEvent(normRoot, { type: "oob_gen", id: canary.id, fqdn: canary.fqdn });
			return { msg: `已生成 OOB Canary ${canary.id}: ${canary.fqdn}`, level: "info" };
		} catch (e) {
			return { msg: `生成 OOB Canary 失败: ${e instanceof Error ? e.message : String(e)}`, level: "error" };
		}
	}

	if (op === "poll") {
		const pollUrl = parts[1]?.trim() ?? "";
		const authToken = parts[2]?.trim() || undefined;
		if (!pollUrl) {
			return { msg: "用法: /nuwa oob poll <pollUrl> [authToken]", level: "error" };
		}
		const polled = await pollOobCallbacks(normRoot, { pollUrl, scope, authToken, fetchFn });
		if (!polled.ok) {
			return { msg: `OOB 回调轮询失败: ${polled.error ?? "unknown"}`, level: "error" };
		}
		const matchedFacts: string[] = [];
		for (const canary of polled.matchedCanaries) {
			const canaryHits = polled.hits.filter((h) => h.matchedCanaryId === canary.id);
			if (canaryHits.length === 0) continue;
			const fact = buildOobEvidenceFact(canary, canaryHits);
			recordToolExecution(normRoot, { tool: "oob-poll", command: fact.command, output: fact.output });
			withLock(normRoot, () => {
				const s = loadState(normRoot);
				if (!s) return;
				const fid = nextFactId(s);
				s.facts[fid] = {
					id: fid,
					kind: "vuln",
					title: normOneLine(fact.title, 120),
					detail: fact.detail,
					command: fact.command,
					output: fact.output,
					key: `oob:${canary.id}`,
					createdAt: nowIso(),
					verified: false,
					verifyStage: "candidate",
					evidenceSeq: getLatestLedgerSeq(normRoot),
				};
				const vSpec = buildDoubleBlindVerifyIntentSpec(s, s.facts[fid]!);
				if (vSpec) appendIntentSpecs(s, [vSpec]);
				saveState(normRoot, s);
				matchedFacts.push(fid);
			});
		}
		logEvent(normRoot, { type: "oob_poll", hits: polled.hits.length, matchedFacts });
		return {
			msg: `OOB 轮询完成: 命中 ${polled.hits.length} 条回调${matchedFacts.length ? ` · 已暂存候选事实 ${matchedFacts.join(", ")}` : ""}`,
			level: "info",
		};
	}

	return { msg: "未知 oob 子命令。用法: /nuwa oob [list | gen <domain> [purpose] | poll <url> [token]]", level: "error" };
}

/**
 * 执行 `/nuwa assets`：同步并输出多资产拓扑表与跨事实假设图摘要。
 */
export function executeAssetsCommand(found: string | null): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const st = withLock(normRoot, () => {
		const s = loadState(normRoot);
		if (!s) return null;
		syncAssetsFromFacts(s);
		saveState(normRoot, s);
		return s;
	});
	if (!st) return { msg: "state 读取失败", level: "error" };
	const topo = formatAssetTopology(st);
	const hyps = Object.values(st.hypotheses ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const hypBlock = hyps.length
		? [
				"",
				`跨事实假设图 (${hyps.length}):`,
				...hyps.map((h) => `- ${h.id} [${h.status}] ${h.title} (from=${h.requiredFacts.join(",")}, gain=${h.expectedGain}/cost=${h.estimatedCost})`),
			].join("\n")
		: "\n跨事实假设图: (暂无)";
	return { msg: `${topo}${hypBlock}`, level: "info" };
}

/**
 * 执行 `/nuwa session health [role] [checkUrl]` 会话保活与过期巡检；若失效则自动派生刷新意图。
 */
export async function executeSessionHealthCommand(
	found: string | null,
	subArg: string,
	fetchFn?: (url: string, init?: { method?: string; headers?: Record<string, string>; redirect?: "manual" | "follow" | "error"; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; headers?: { get(name: string): string | null } }>,
): Promise<{ msg: string; level: "info" | "error" }> {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const st = loadState(normRoot);
	if (!st) return { msg: "state 读取失败", level: "error" };
	const vault = loadSessionVault(normRoot);
	const allRoles = Object.keys(vault.roles).sort();
	if (allRoles.length === 0) {
		return { msg: "会话保险箱为空，无需巡检。", level: "info" };
	}
	const parts = subArg.trim().split(/\s+/).filter(Boolean);
	const targetRoles = parts[0] && vault.roles[parts[0].toLowerCase()] ? [parts[0].toLowerCase()] : allRoles;
	const explicitUrl = parts[0] && /^https?:\/\//i.test(parts[0]) ? parts[0] : parts[1];
	const scope = st.project.scope ?? defaultScopeForTarget(st.project.url || st.project.target, st.project.mode);

	const lines: string[] = [`会话健康巡检 (${targetRoles.length} 个角色):`];
	const spawnedRefresh: string[] = [];
	for (const role of targetRoles) {
		const health = await checkRoleHealth(normRoot, role, {
			...(explicitUrl ? { checkUrl: explicitUrl } : {}),
			scope,
			fetchFn,
		});
		lines.push(`- ${role}: ${health.healthy ? "HEALTHY" : "EXPIRED"} (${health.reason})`);
		if (health.expired) {
			const spec = buildRefreshIntentSpec(role, health.reason, explicitUrl ?? vault.roles[role]?.checkUrl);
			withLock(normRoot, () => {
				const s = loadState(normRoot);
				if (!s) return;
				const added = appendIntentSpecs(s, [spec]);
				if (added.length) {
					spawnedRefresh.push(...added);
					saveState(normRoot, s);
					logEvent(normRoot, { type: "session_refresh_spawn", role, intent: added[0], reason: health.reason });
				}
			});
		}
	}
	if (spawnedRefresh.length > 0) {
		lines.push(`已自动派生会话刷新意图: ${spawnedRefresh.join(" ")}`);
	}
	return { msg: lines.join("\n"), level: "info" };
}

// ============================================================================
// v6.0 新增斜杠子命令视图（默认严格只读零磁盘写入）
// ============================================================================

/**
 * 执行 `/nuwa belief [limit]`：纯只读展示不确定性感知信念图、Top VoI 前沿排序、剪枝节点与搜索转向建议。
 */
export function executeBeliefCommand(
	found: string | null,
	subArg = "",
): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const st = loadStateStrictlyReadOnly(normRoot);
	if (!st) return { msg: "state 读取失败", level: "error" };

	const limitRaw = Number.parseInt(subArg.trim(), 10);
	const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.min(30, limitRaw) : 8;
	const diskGraph = loadBeliefGraphReadOnly(normRoot);
	const graph = initBeliefGraphFromState(st, diskGraph ?? undefined);
	const ranked = rankFrontierByBelief(st, undefined, { graph, limit });
	const pivot = recommendSearchPivot(st, graph);
	const allNodes = Object.values(graph.nodes);
	const prunedNodes = allNodes.filter((n) => n.pruned);

	const lines: string[] = [
		`[女娲 v${VERSION} 信念前沿与信息增益视图] (${existsSync(beliefGraphPath(normRoot)) ? "persisted" : "in-memory"})`,
		`- 节点总数: ${allNodes.length} · 已剪枝: ${prunedNodes.length} · 收敛置信度: ${(pivot.convergenceConfidence * 100).toFixed(1)}% · 负向封盘置信度: ${(pivot.negativeSealConfidence * 100).toFixed(1)}%`,
		`- 全局策略建议 [${pivot.action}]: ${pivot.summary}`,
	];

	if (ranked.length > 0) {
		lines.push("", `Top-${ranked.length} 前沿意图信念与 VoI 排序:`);
		for (const item of ranked) {
			lines.push(
				`  * ${item.intent.id} [${item.intent.phase}] ${item.intent.title} — posterior=${item.beliefScore.toFixed(3)} VoI=${item.voiScore.toFixed(3)} score=${item.compositeScore.toFixed(3)}${item.pruned ? " [PRUNED]" : ""}`,
			);
		}
	} else {
		lines.push("", "当前无待执行的活跃前沿意图。");
	}

	if (prunedNodes.length > 0) {
		lines.push(
			"",
			`已剪枝低收益节点 (${prunedNodes.length}):`,
			...prunedNodes.slice(0, 6).map(
				(n) => `  - ${n.id} (${n.kind}) ${n.title} · posterior=${n.posterior.toFixed(3)} · ${n.pruneReason ?? "后验低于阈值"}`,
			),
		);
	}

	return { msg: lines.join("\n"), level: "info" };
}

/**
 * 执行 `/nuwa calibrate [category]`：纯只读展示反自证校准账本指标（Brier / ECE / 误报率 / ROI）与自适应模型路由决策。
 */
export function executeCalibrateCommand(
	found: string | null,
	subArg = "",
): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const records = loadCalibrationRecords(normRoot);
	const summary = computeCalibrationSummary(records);
	const report = formatCalibrationReport(summary);

	const reqCategory = subArg.trim().toLowerCase();
	const routeDecision = recommendAdaptiveModelRoute(records, {
		allowedModels: ALLOWED_SUBAGENT_MODELS,
		defaultModel: DEFAULT_SUBAGENT_MODEL,
		...(reqCategory
			? {
					taskCategory: (["recon", "auth", "js-audit", "verify", "exploit", "whitebox", "general"].includes(
						reqCategory,
					)
						? reqCategory
						: "general") as "recon" | "auth" | "js-audit" | "verify" | "exploit" | "whitebox" | "general",
				}
			: {}),
	});

	const lines = [
		report,
		"",
		`[自适应模型路由评估 (category=${routeDecision.taskCategory})]`,
		`- 推荐模型: ${routeDecision.recommendedModel} (默认=${routeDecision.effectiveDefaultModel}, coldStart=${routeDecision.coldStart})`,
		`- 决策依据: ${routeDecision.reason}`,
	];
	return { msg: lines.join("\n"), level: "info" };
}

/**
 * 执行 `/nuwa traffic [limit | host=<h> | status=<s> | method=<m> | path=<p>]`：纯只读查询结构化脱敏 HTTP 流量工作台。
 */
export function executeTrafficCommand(
	found: string | null,
	subArg = "",
): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const recorder = new TrafficRecorder(normRoot);

	const filter: TrafficQueryFilter = {};
	let limit = 15;
	for (const tok of subArg.trim().split(/\s+/).filter(Boolean)) {
		if (/^\d+$/.test(tok)) {
			limit = Math.max(1, Math.min(100, Number.parseInt(tok, 10)));
		} else if (tok.startsWith("host=")) {
			filter.host = tok.slice(5);
		} else if (tok.startsWith("method=")) {
			filter.method = tok.slice(7);
		} else if (tok.startsWith("path=")) {
			filter.pathPrefix = tok.slice(5);
		} else if (tok.startsWith("status=")) {
			const stCode = Number.parseInt(tok.slice(7), 10);
			if (Number.isFinite(stCode)) filter.status = stCode;
		} else if (tok.startsWith("tag=")) {
			filter.tag = tok.slice(4);
		}
	}

	const hasFilter = Object.keys(filter).length > 0;
	const entries = hasFilter ? recorder.query(filter).slice(-limit) : recorder.list(limit);

	let sqliteCount = 0;
	const dbFile = sqliteDbPath(normRoot);
	if (existsSync(dbFile)) {
		try {
			const db = openNuwaDb(normRoot, { readonly: true });
			try {
				const row = db.query("SELECT COUNT(*) AS cnt FROM traffic_entries").get() as { cnt?: number } | null;
				sqliteCount = Number(row?.cnt ?? 0);
			} finally {
				db.close();
			}
		} catch {
			/* ignore */
		}
	}

	if (entries.length === 0 && sqliteCount === 0) {
		return {
			msg: `[女娲 v${VERSION} 流量工作台]\n当前暂无已录制的 HTTP 流量记录（用法: /nuwa traffic [limit] [host=<h>] [method=GET] [status=200] [path=/api]）。`,
			level: "info",
		};
	}

	const statusDist: Record<string, number> = {};
	for (const e of entries) {
		const bucket = `${Math.floor((e.status || 0) / 100)}xx`;
		statusDist[bucket] = (statusDist[bucket] ?? 0) + 1;
	}
	const distText = Object.entries(statusDist)
		.map(([k, v]) => `${k}:${v}`)
		.join(" ");

	const lines: string[] = [
		`[女娲 v${VERSION} 流量工作台] 显示最近 ${entries.length} 条脱敏流量${sqliteCount > 0 ? ` (SQLite 索引库=${sqliteCount} 条)` : ""}${distText ? ` · 分布=[${distText}]` : ""}:`,
		...entries.map(
			(e) =>
				`  - ${e.id} [${e.status}] ${e.method} ${e.url} (${e.durationMs}ms, ${e.responseBodyBytes}B${e.role ? `, role=${e.role}` : ""})`,
		),
	];
	return { msg: lines.join("\n"), level: "info" };
}

/**
 * 执行 `/nuwa hybrid [dirOrMapPath | plan [dirOrMapPath]]`：
 * 默认纯只读提取白盒源码/SourceMap 路由攻击面并双向关联黑盒发现；仅当显式指定 `plan` 子指令时才将桥接核验意图写入状态图。
 */
export function executeHybridCommand(
	found: string | null,
	subArg = "",
): { msg: string; level: "info" | "error" } {
	if (!found) return { msg: "当前目录没有女娲项目", level: "error" };
	const normRoot = resolve(found);
	const st = loadStateStrictlyReadOnly(normRoot);
	if (!st) return { msg: "state 读取失败", level: "error" };

	const tokens = subArg.trim().split(/\s+/).filter(Boolean);
	const shouldPlan = tokens[0]?.toLowerCase() === "plan";
	const rawTarget = (shouldPlan ? tokens.slice(1).join(" ") : subArg).trim();

	let targetPath = rawTarget ? resolve(normRoot, rawTarget) : "";
	if (!targetPath) {
		if (st.project.scheme === "local" && st.project.target && existsSync(resolve(st.project.target))) {
			targetPath = resolve(st.project.target);
		} else {
			targetPath = normRoot;
		}
	}

	if (!existsSync(targetPath)) {
		return { msg: `混合审计目标路径不存在: ${targetPath}`, level: "error" };
	}

	let surface;
	if (targetPath.endsWith(".map")) {
		try {
			const rawMap = readFileSync(targetPath, "utf8");
			surface = extractFromSourceMap(rawMap);
		} catch (e) {
			return { msg: `解析 SourceMap 失败: ${e instanceof Error ? e.message : String(e)}`, level: "error" };
		}
	} else {
		surface = extractCodeAttackSurface(targetPath);
	}

	const baseUrl = st.project.scheme === "local" ? "http://127.0.0.1" : st.project.url || "http://127.0.0.1";
	const bridged = bridgeWhiteboxToBlackboxIntents(surface, baseUrl);

	const vulnFacts = Object.values(st.facts).filter(
		(f) => f.kind === "vuln" && f.verifyStage !== "rejected",
	);
	const correlations = vulnFacts
		.slice(0, 5)
		.map((vf) => ({ fact: vf, corr: correlateBlackboxFindingToSource(vf, surface) }))
		.filter((item) => item.corr.matched);

	let plannedIds: string[] = [];
	if (shouldPlan && bridged.intents.length > 0) {
		withLock(normRoot, () => {
			const s = loadState(normRoot);
			if (!s) return;
			plannedIds = appendIntentSpecs(
				s,
				bridged.intents.slice(0, 12).map((spec) => ({
					key: spec.key,
					phase: spec.phase,
					title: spec.title,
					detail: `${spec.detail}\n源码锚点: ${spec.anchor}`,
					priority: spec.priority,
					from: [],
					targetKey: spec.targetKey,
					expectedKind: spec.expectedKind,
				})),
			);
			if (plannedIds.length > 0) {
				saveState(normRoot, s);
				logEvent(normRoot, { type: "hybrid_bridge_plan", added: plannedIds, targetPath });
			}
		});
	}

	const detectedFrameworks = Object.keys(surface.summary?.byFramework ?? {});
	const lines: string[] = [
		`[女娲 v${VERSION} 黑白盒混合审计视图] target=${targetPath}`,
		`- 扫描文件: ${surface.scannedFiles} · 检出框架: [${detectedFrameworks.join(", ") || "通用"}] · 路由总数: ${surface.routes.length} · 高风险告警: ${surface.warnings.length}`,
		`- 可桥接黑盒核验意图: ${bridged.intents.length} 条${shouldPlan ? ` (本次已写入图: ${plannedIds.length} 条)` : " (纯只读预览；执行 `/nuwa hybrid plan [dir]` 可导入待核验意图)"}`,
	];

	if (bridged.intents.length > 0) {
		lines.push(
			"",
			"高优白盒->黑盒待核验点:",
			...bridged.intents.slice(0, 6).map(
				(it) => `  * [${it.riskCategory}] ${it.method} ${it.path} (${it.anchor})`,
			),
		);
	}

	if (correlations.length > 0) {
		lines.push(
			"",
			"黑盒发现->白盒源码锚点关联:",
			...correlations.map(
				({ fact, corr }) =>
					`  * ${fact.id} ${fact.title} -> ${corr.anchor ?? "unknown"} (score=${corr.score.toFixed(2)}, confidence=${corr.confidence})`,
			),
		);
	}

	return { msg: lines.join("\n"), level: "info" };
}

/**
 * 执行 `/nuwa mcp`：纯只读展示独立核心引擎与跨宿主 MCP Server（`bin/nuwa-mcp`）契约状态及接入配置。
 */
export function executeMcpCommand(
	found: string | null,
	_subArg = "",
): { msg: string; level: "info" | "error" } {
	const binPath = resolve(import.meta.dir, "..", "bin", "nuwa-mcp");
	const installedBin = join(getAgentHome(), "nuwa-core", "bin", "nuwa-mcp");
	const effectiveBin = existsSync(binPath) ? binPath : installedBin;
	const cwdHint = found ? resolve(found) : process.cwd();

	const tools = [
		"nuwa_init",
		"nuwa_plan",
		"nuwa_frontier",
		"nuwa_claim",
		"nuwa_commit",
		"nuwa_flag",
		"nuwa_complete",
		"nuwa_status",
		"nuwa_report",
		"nuwa_expand",
		"nuwa_stop",
		"nuwa_kb",
	];

	const mcpConfig = JSON.stringify(
		{
			mcpServers: {
				"pi-nuwa": {
					command: effectiveBin,
					args: ["--project", cwdHint],
				},
			},
		},
		null,
		2,
	);

	const lines = [
		`[女娲 v${VERSION} 跨宿主 MCP Server 状态]`,
		`- 协议标准: MCP JSON-RPC 2.0 over stdio (protocolVersion=2024-11-05)`,
		`- 可执行入口: ${effectiveBin} (${existsSync(effectiveBin) ? "READY" : "NOT_INSTALLED"})`,
		`- 暴露核心工具 (${tools.length}): ${tools.join(", ")}`,
		`- 宿主配置示例 (Claude Code / Cursor / Codex):`,
		mcpConfig,
	];
	return { msg: lines.join("\n"), level: "info" };
}

function countsByKind(st: NuwaState): Record<string, number> {
	const out: Record<string, number> = {};
	for (const f of Object.values(st.facts)) out[f.kind] = (out[f.kind] ?? 0) + 1;
	return out;
}

function phaseStats(st: NuwaState): Array<{ phase: Phase; open: number; claimed: number; done: number; blocked: number; total: number }> {
	return PHASE_ORDER.map((phase) => {
		const ints = Object.values(st.intents).filter((i) => i.phase === phase);
		return {
			phase,
			open: ints.filter((i) => i.status === "open").length,
			claimed: ints.filter((i) => i.status === "claimed").length,
			done: ints.filter((i) => i.status === "done").length,
			blocked: ints.filter((i) => i.status === "blocked").length,
			total: ints.length,
		};
	}).filter((r) => r.total > 0);
}

function detectAutoRulesSource(root?: string, st?: NuwaState): string {
	return checkAndLogAutoRuleSource(root, st);
}

export function statusBoard(st: NuwaState, root?: string): string {
	const p = st.project;
	const rt = st.runtime;
	const kinds = countsByKind(st);
	const projectStart = rt.projectStartedAt ?? rt.startedAt;
	const mins = Math.floor((Date.now() - projectStart) / 60000);
	const cfg = readCfg();
	const rows = phaseStats(st);
	const head = `+${"-".repeat(8)}+${"-".repeat(7)}+${"-".repeat(7)}+${"-".repeat(7)}+${"-".repeat(9)}+${"-".repeat(7)}+`;
	const line = (a: string, b: string, c: string, d: string, e: string, f: string) =>
		`|${a.padEnd(8)}|${b.padStart(7)}|${c.padStart(7)}|${d.padStart(7)}|${e.padStart(9)}|${f.padStart(7)}|`;
	const table = [
		head,
		line(" phase", "open", "claim", "done", "blocked", "total"),
		head,
		...rows.map((r) => line(` ${r.phase}`, String(r.open), String(r.claimed), String(r.done), String(r.blocked), String(r.total))),
		head,
	].join("\n");
	const frontier = frontierList(st, 8, cfg.claimTtl, root).map((f) => f.intent.id).join(" ") || "(空)";
	const autoBatch = Object.values(st.intents)
		.filter((i) => i.status === "claimed" && i.worker === "auto")
		.map((i) => i.id)
		.join(" ");
	const kindLine = Object.entries(kinds)
		.sort((a, b) => b[1] - a[1])
		.map(([k, v]) => `${k}=${v}`)
		.join(" ");
	const pressure = budgetPressure(st, cfg);
	const rawBytes = rt.stateBytes ?? Buffer.byteLength(JSON.stringify(st), "utf8");
	const stateKb = Math.max(1, Math.round(rawBytes / 1024));
	const rulesSource = detectAutoRulesSource(root, st);
	const gen = rt.generation ?? 1;
	const netRetry = rt.netRetries ?? 0;
	const candCount = Object.values(st.facts).filter((f) => f.verifyStage === "candidate").length;
	let roleCount = p.activeRoles?.length ?? 0;
	if (root) {
		try {
			roleCount = Object.keys(loadSessionVault(root).roles).length;
		} catch {
			/* ignore */
		}
	}
	let kbReady = "missing";
	try {
		const stats = getKbStats(undefined, { agentHome: getAgentHome() });
		if (stats.exists && (stats.cards > 0 || stats.cves > 0)) {
			kbReady = "ready";
		}
	} catch {
		kbReady = "missing";
	}
	const totalTurns = Math.max(rt.totalTurns ?? 0, rt.turns);
	const totalTokens = (rt.totalTokens ?? 0) + rt.tokens;
	const turnsDisp = totalTurns > rt.turns ? `${rt.turns}(total=${totalTurns})` : `${rt.turns}`;
	const tokensDisp = (rt.totalTokens ?? 0) > 0 ? `${rt.tokens}(total=${totalTokens})` : `${rt.tokens}`;
	const assetCount = Object.keys(st.assets ?? {}).length;
	const hypCount = Object.values(st.hypotheses ?? {}).filter((h) => h.status === "open" || (h as { status: string }).status === "active").length;
	const rep = computeRepeatRatio(st);
	const probe = extractProbeHealth(st);
	const blockedIntents = Object.values(st.intents).filter((i) => i.status === "blocked").length;
	const blockedCommits = rt.blockedCommits ?? blockedIntents;
	const noveltyStall = rt.noveltyStall ?? 0;
	const effectiveStatus = rt.status === "sealed_negative" ? "sealed_negative" : p.status;
	const conv = buildConvergenceAdvice(st, cfg, root);
	const sealRec = shouldRecommendSeal(st, cfg, root);

	const extraMetaParts: string[] = [
		`repeatRatio=${rep.repeatRatio.toFixed(2)}`,
		`last_ok=${probe.lastOk}`,
		`blocked_ratio=${Math.round(probe.blockedRatio * 100)}%`,
		`blockedIntents=${blockedIntents}`,
		`blockedCommits=${blockedCommits}`,
	];
	if (probe.edgeBlocked) extraMetaParts.push("stage=边缘受阻");
	if (assetCount > 1) extraMetaParts.push(`assets=${assetCount}`);
	if (hypCount > 0) extraMetaParts.push(`hyp=${hypCount}`);
	if (p.sandboxMode && p.sandboxMode !== "none") extraMetaParts.push(`sandbox=${p.sandboxMode}`);
	const extraMeta = extraMetaParts.length ? ` · ${extraMetaParts.join(" · ")}` : "";
	const budgetLine = cfg.infinite
		? `budget: ∞ 永动 · gen=${gen} · turns=${turnsDisp} · ${mins}min · tokens=${tokensDisp} · stall=${rt.stall} noveltyStall=${noveltyStall} idle=${rt.idle} · pressure=${Math.round(pressure * 100)}% · ep=${p.episode ?? 1} expand=${rt.expansions ?? 0}`
		: `budget: 预算受限 · gen=${gen} · turns=${turnsDisp}/${cfg.maxTurns} · ${mins}/${cfg.maxMinutes}min · tokens=${tokensDisp}/${cfg.maxTokens} · stall=${rt.stall}/${cfg.maxStall} noveltyStall=${noveltyStall} idle=${rt.idle}/${cfg.maxIdle}`;
	const rejectNotes: string[] = [];
	if (conv.active) rejectNotes.push(`收敛:${conv.recommendedAction}`);
	if (sealRec.recommend && effectiveStatus === "active") rejectNotes.push(`建议封盘:${sealRec.reasons.join(",")}`);
	if (rt.sealMeta) rejectNotes.push(`封盘原因:${rt.sealMeta.reason}`);
	const rejectSuffix = rejectNotes.length ? ` (${rejectNotes.join(" | ")})` : "";
	return [
		`女娲 v${VERSION} · ${p.url} · ${p.mode} · ${effectiveStatus}`,
		`phase=${p.phase} · facts=${Object.keys(st.facts).length} (${kindLine || "无"}) · cand=${candCount} · roles=${roleCount} · kb=${kbReady} · state=${stateKb}KB · rules=${rulesSource} · net-retry=${netRetry}${extraMeta}`,
		budgetLine,
		`rejects=${rt.completionRejects}${rejectSuffix} · 目标: ${p.goal}`,
		table,
		`frontier: ${frontier}${autoBatch ? ` · auto: ${autoBatch}` : ""}`,
	].join("\n");
}

export function reportMarkdown(st: NuwaState, root?: string): string {
	return renderStratifiedMarkdownReport(st, root, { title: formatProfileReportTitle(st) });
}

