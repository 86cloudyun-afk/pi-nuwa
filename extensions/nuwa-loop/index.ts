/**
 * nuwa-loop — 女娲模式的运行时续跑器。
 *
 * 病根：SKILL.md 只是「提示词」，不是「运行时」。sapper-v2 之所以能 8 小时无人值守，
 * 靠的是 watchdog.sh 那个外部 bash 循环；omp 里没有任何东西在 task 批次返回后重新
 * 拉起主代理，模型写完一段战报 turn 就 settle 了 → 一轮即停。
 *
 * 本扩展补上运行时：监听 session_stop（主代理即将收工），读 .sapper 图状态，
 * 只要 project.status != completed 就返回 decision:"block" 把 turn 顶回去继续。
 * 用 block 而非 continue，是因为 omp 对 continue 有 SESSION_STOP_CONTINUATION_CAP=8
 * 的硬上限（omp 18.16.0 src/session/agent-session.ts:493；block 路径在 :5820 不受该上限约束）。
 *
 * 开关：NUWA_LOOP=0 关闭；NUWA_MAX_TURNS 单会话最大自动续跑轮数（默认 120）；
 *       NUWA_MAX_STALL 图状态连续无变化的上限（默认 10）；
 *       NUWA_MAX_TOKENS 累计上下文消耗上限（默认 2M，估算口径见 trackBudget）；
 *       NUWA_IDLE_LIMIT 连续空转轮数上限（默认 3，只涨 turn 不调工具即空转）；
 *       NUWA_GUARD_HOURS 上膛有效期小时数（默认 12）。
 */
import { createHash } from "node:crypto";
import {
	appendFileSync,
	existsSync,
	mkdirSync,
	lstatSync,
	readFileSync,
	readdirSync,
	readlinkSync,
	rmSync,
	realpathSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { ExtensionAPI, InputEvent, SessionStopEvent, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

const HOME = homedir();
// pi 与 omp 共用同一套目录布局；显式指定用 PI_AGENT_HOME，否则按存在性探测
const AGENT_HOME =
	process.env.PI_AGENT_HOME ??
	(existsSync(join(HOME, ".omp/agent")) ? join(HOME, ".omp/agent") : join(HOME, ".pi/agent"));
const POINTER = join(AGENT_HOME, "cache/nuwa-current");
const STATE_DIR = join(AGENT_HOME, "cache/nuwa-loop");
const LOG_DIR = join(AGENT_HOME, "cache/nuwa-loop/log");
const LAB_DIR = process.env.SAPPER_HOME ?? join(HOME, "sapper-lab");

const SCHEMA = 2;

/** 命令级策略：与 nuwa/policy.py 保持同一组规则 id。 */
const POLICY_RULES: Array<[RegExp, string]> = [
	[/(^|\s)rm\s+-rf\s+\/(\s|$)/, "P-001"],
	[/\bmkfs\./, "P-002"],
	[/\bdd\s+[^\n]*of=\/dev\/[sh]d/, "P-003"],
	[/curl[^\n]*--noproxy[^\n]*\b(169\.254|127\.0\.0\.1)/, "P-004"],
];

export function checkCommand(cmd: string): { allowed: boolean; rule?: string } {
	for (const [re, rule] of POLICY_RULES) {
		if (re.test(cmd)) return { allowed: false, rule };
	}
	return { allowed: true };
}

/** 写类工具：路径命中图或权威状态目录时拒绝，阻止绕开 CLI 直接改状态。 */
const WRITE_TOOLS: Record<string, true> = {
	write: true,
	edit: true,
	multi_edit: true,
	apply_patch: true,
	notebook_edit: true,
};

/** 只认路径类字段，避免把 write 的正文内容误当路径。 */
const PATH_KEYS: Record<string, true> = {
	path: true,
	file_path: true,
	file: true,
	filename: true,
	notebook_path: true,
	target: true,
};

const PATH_RULES: Array<[RegExp, string]> = [
	[/(^|[\\/])\.sapper[\\/](facts|intents)(?:[\\/]|$)/, "P-005"],
	[/(^|[\\/])\.sapper[\\/]project\.json$/, "P-009"],
	[/(^|[\\/])\.nuwa[\\/](journal[^\\/]*\.jsonl|checkpoint[^\\/]*\.json|CURRENT|global[^\\/]*\.jsonl|recovery\.json)$/, "P-007"],
	[/(^|[\\/])budget[\\/]([^\\/]*\.jsonl|cap\.json|freeze\.json)$/, "P-007"],
];

/**
 * 提交所有权：fact 只能经 nuwa commit 产生。分隔符覆盖 ; & | ( ) 换行引号反引号，
 * 允许反斜杠转义与 $() 包装；带 --from <fact> 的 complete 是证据入账后的合法完成。
 */
// 只在命令分隔符之后剥离开关，避免删除引号内的可执行文本或跨分隔符吞 token。
const GLOBAL_OPT_RE =
	/(^|[;&|()\n]|\bsapper\s+)(\s*)((?:(?:--store|-s)(?:=(?:"[^"$`]*"|'[^'$`]*'|[^\s;&|()$`]+)|\s+(?:"[^"$`]*"|'[^'$`]*'|[^\s;&|()$`]+)|[^\s;&|()$`]+)?\s*)+)/g;

function stripGlobalOptions(cmd: string): string {
	return cmd.replace(GLOBAL_OPT_RE, "$1$2");
}

const COMMIT_RE =
	/(?:^|[;&|()\n\r\t"'`\s]|\$\()\s*\\?(?:\S*[\\/])?sapper\s+(?:done\s+\S+|dispatch\s+i\d+|complete\b)/i;

/** store 值里出现变量展开/命令替换时，静态剥离不可靠：直接 fail-closed。 */
function hasUnresolvedStore(cmd: string): boolean {
	// 只要 sapper 段内出现变量展开/命令替换，就无法静态确定 store 与子命令边界，直接拒绝。
	return /\bsapper\b[^\n]*?[$`]/.test(cmd);
}

/** 命令中所有可能的 cwd：原目录与每个 cd 之后的目录。检查时取并集，避免时序漏检。 */
function candidateDirs(cmd: string, baseDir: string): string[] {
	const dirs = new Set<string>();
	const addChain = (p: string) => {
		let cur = resolve(p);
		while (true) {
			dirs.add(cur);
			const parent = dirname(cur);
			if (parent === cur) break;
			cur = parent;
		}
	};
	addChain(baseDir);
	for (const m of cmd.matchAll(/(?:^|[;&|]|\n)\s*cd\s+([^\s;|&>]+)/g)) {
		const target = m[1].replace(/^["']|["']$/g, "");
		// 每个 cd 可能成功、失败或停在任意祖先：对所有当前候选都解析一次。
		for (const base of [...dirs]) {
			addChain(isAbsolute(target) ? target : resolve(base, target));
		}
	}
	return [...dirs];
}

function collectShellTargets(cmd: string): Array<{ path: string; index: number }> {
	const out: Array<{ path: string; index: number }> = [];
	const push = (raw: string, index: number) => {
		const target = raw.replace(/^["']|["']$/g, "");
		if (target && !target.startsWith("-") && target !== "/dev/null" && !target.startsWith("&")) {
			out.push({ path: target, index });
		}
	};
	for (const m of cmd.matchAll(/(?:>>?|tee(?:\s+-a)?)\s*([^;|&]+)/g)) {
		for (const part of m[1].split(/\s+/)) push(part, m.index ?? 0);
	}
	for (const m of cmd.matchAll(/\b(?:cp|mv|install)\s+([^;|&]+)/g)) {
		for (const part of m[1].split(/\s+/)) push(part, m.index ?? 0);
	}
	return out;
}

/** 递归收集路径类字段；multi_edit/files/edits 等嵌套结构也能覆盖。 */
function collectPaths(value: unknown, out: string[], depth = 0): void {
	if (depth > 6 || value === null || typeof value !== "object") return;
	if (Array.isArray(value)) {
		for (const item of value) collectPaths(item, out, depth + 1);
		return;
	}
	for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
		if (typeof v === "string" && PATH_KEYS[k]) out.push(v);
		else if (v && typeof v === "object") collectPaths(v, out, depth + 1);
	}
}

/** 递归收集所有字符串；task 的 context/description 等字段同样参与 P-006 扫描。 */
function collectStrings(value: unknown, out: string[], depth = 0): void {
	if (depth > 6 || value === null) return;
	if (typeof value === "string") {
		out.push(value);
		return;
	}
	if (Array.isArray(value)) {
		for (const item of value) collectStrings(item, out, depth + 1);
		return;
	}
	if (typeof value === "object") {
		for (const v of Object.values(value as Record<string, unknown>)) {
			collectStrings(v, out, depth + 1);
		}
	}
}

/** 把相对路径、file://、符号链接都归一到真实绝对路径；不存在的文件用最近存在的祖先 realpath。 */
function resolvePath(value: string, baseDir: string): string[] {
	const raw = value.startsWith("file://") ? value.slice(7) : value;
	const normalized = raw.replace(/\\/g, "/");
	const abs = isAbsolute(normalized) ? normalized : resolve(baseDir, normalized);
	const out = new Set<string>([abs]);
	try {
		out.add(realpathSync(abs));
		return [...out];
	} catch {
		/* 目标不存在，继续按祖先解析 */
	}
	let probe = abs;
	const rest: string[] = [];
	while (probe !== dirname(probe) && !existsSync(probe)) {
		rest.unshift(probe.split("/").pop() ?? "");
		probe = dirname(probe);
	}
	try {
		out.add(join(realpathSync(probe), ...rest));
	} catch {
		/* 祖先也不存在 */
	}
	try {
		if (lstatSync(abs).isSymbolicLink()) {
			const target = readlinkSync(abs);
			const targetAbs = isAbsolute(target) ? target : resolve(dirname(abs), target);
			out.add(targetAbs);
			try {
				out.add(realpathSync(targetAbs));
			} catch {
				/* 链接目标不存在 */
			}
		}
	} catch {
		/* 非链接或无法 lstat */
	}
	return [...out];
}

/** apply_patch 的目标在补丁正文里，单独提取。 */
function collectPatchTargets(input: Record<string, unknown>, out: string[]): void {
	for (const key of ["patch", "input", "text", "diff"]) {
		const v = input[key];
		if (typeof v !== "string") continue;
		for (const m of v.matchAll(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$/gm)) {
			out.push(m[1].replace(/\s+\(.+\)\s*$/, "").trim());
		}
		for (const m of v.matchAll(/^\*\*\* Move to:\s*(.+)$/gm)) {
			out.push(m[1].trim());
		}
		for (const m of v.matchAll(/^---\s+(?:a\/)?(.+)$/gm)) {
			const target = m[1].split(/\s+/)[0];
			if (target && target !== "/dev/null") out.push(target);
		}
		for (const m of v.matchAll(/^\+\+\+\s+(?:b\/)?(.+)$/gm)) {
			const target = m[1].split(/\s+/)[0];
			if (target && target !== "/dev/null") out.push(target);
		}
	}
}

/** 三类工具统一判定：bash 看命令，task 看全部文案，write/edit 看全部路径字段。 */
export function checkTool(
	toolName: string,
	input: Record<string, unknown>,
	baseDir = process.cwd(),
): { allowed: boolean; rule?: string } {
	if (toolName === "bash") {
		const cmd = typeof input.command === "string" ? input.command : "";
		const base = checkCommand(cmd);
		if (!base.allowed) return base;
		// store 值含变量展开/命令替换时无法可靠剥离，按提交语义不明直接拒绝。
		if (hasUnresolvedStore(cmd)) return { allowed: false, rule: "P-006" };
		if (COMMIT_RE.test(stripGlobalOptions(cmd))) return { allowed: false, rule: "P-006" };
		for (const target of collectShellTargets(cmd)) {
			for (const shellDir of candidateDirs(cmd, baseDir)) {
				for (const candidate of resolvePath(target.path, shellDir)) {
					for (const [re, rule] of PATH_RULES) {
						if (re.test(candidate)) return { allowed: false, rule };
					}
				}
			}
		}
		return { allowed: true };
	}
	if (toolName === "task") {
		const texts: string[] = [];
		collectStrings(input, texts);
		const rawText = texts.join("\n");
		if (hasUnresolvedStore(rawText)) return { allowed: false, rule: "P-006" };
		const text = stripGlobalOptions(rawText);
		if (COMMIT_RE.test(text)) return { allowed: false, rule: "P-006" };
		return { allowed: true };
	}
	if (WRITE_TOOLS[toolName]) {
		const paths: string[] = [];
		collectPaths(input, paths);
		if (toolName === "apply_patch") collectPatchTargets(input, paths);
		for (const p of paths) {
			for (const candidate of resolvePath(p, baseDir)) {
				for (const [re, rule] of PATH_RULES) {
					if (re.test(candidate)) return { allowed: false, rule };
				}
			}
		}
	}
	return { allowed: true };
}

/** 运行时读配置，便于测试动态注入；非法值回落默认。 */
export function readCfg() {
	const num = (name: string, dflt: number, min: number) => {
		const raw = Number(process.env[name] ?? dflt);
		return Number.isFinite(raw) && raw >= min ? raw : dflt;
	};
	return {
		loop: (process.env.NUWA_LOOP ?? "1").trim() !== "0",
		maxTurns: num("NUWA_MAX_TURNS", 120, 1),
		maxStall: num("NUWA_MAX_STALL", 10, 1),
		maxIdle: num("NUWA_IDLE_LIMIT", 3, 1),
		maxTokens: num("NUWA_MAX_TOKENS", 2_000_000, 1000),
		guardMs: num("NUWA_GUARD_HOURS", 12, 1) * 60 * 60 * 1000,
		blockStreakLimit: num("NUWA_BLOCK_STREAK", 3, 1),
	};
}

export const __cfg = readCfg;

type Graph = {
	root: string;
	status: string;
	goal: string;
	open: number;
	done: number;
	claimed: number;
	facts: number;
	flags: number;
	/** 非 note 的 fact 数：stall 判据用它，避免垃圾 note 假装有进展 */
	effective: number;
	/** 是否出现可验收证据（flag / vuln / loot） */
	verified: boolean;
	openIds: string[];
	/** .nuwa.lock 是否被别的活进程持有 */
	locked: boolean;
	viewUrl: string | null;
};

type LoopState = {
	schema: number;
	armed: boolean;
	armedAt: number;
	turns: number;
	stall: number;
	idle: number;
	blockStreak: number;
	spentTokens: number;
	lastTokens: number;
	completionRejects: number;
	toolCalls: number;
	lastToolCallsSnapshot: number;
	sig: string;
	lastReason: string;
};

const emptyState = (): LoopState => ({
	schema: SCHEMA,
	armed: false,
	armedAt: 0,
	turns: 0,
	stall: 0,
	idle: 0,
	blockStreak: 0,
	spentTokens: 0,
	lastTokens: 0,
	completionRejects: 0,
	toolCalls: 0,
	lastToolCallsSnapshot: -1,
	sig: "",
	lastReason: "",
});

function readJson<T>(p: string): T | null {
	try {
		return JSON.parse(readFileSync(p, "utf8")) as T;
	} catch {
		return null;
	}
}

function hasGraph(dir: string): boolean {
	return existsSync(join(dir, ".sapper", "project.json"));
}

function shortHash(s: string): string {
	return createHash("sha1").update(s).digest("hex").slice(0, 16);
}

/**
 * 从 cwd 向上找 .sapper，再退到 NUWA_PROJECT / 指针文件。
 * 指针是 JSON（{root, sessionId, ts}），session 不匹配时拒绝接管，防止多项目串台。
 * 已删除旧的「扫 $SAPPER_HOME 下 mtime 最新 active 图」兜底：多项目并行必串台。
 */
export function findRoot(cwd: string, sessionId = ""): string | null {
	let d = resolve(cwd || process.cwd());
	for (;;) {
		if (hasGraph(d)) return d;
		const up = dirname(d);
		if (up === d) break;
		d = up;
	}
	const env = process.env.NUWA_PROJECT;
	if (env && hasGraph(env)) return resolve(env);
	const ptr = readJson<{ root?: string; sessionId?: string; ts?: number }>(POINTER);
	if (ptr?.root && hasGraph(ptr.root)) {
		// 旧格式（纯路径）没有 sessionId，按兼容放行
		if (!ptr.sessionId || !sessionId || ptr.sessionId === sessionId) return resolve(ptr.root);
		return null;
	}
	return null;
}

function lockHeldByOther(root: string): boolean {
	const p = join(root, ".nuwa.lock");
	if (!existsSync(p)) return false;
	let pid = 0;
	try {
		pid = Number(readFileSync(p, "utf8").trim());
	} catch {
		return false;
	}
	if (!Number.isFinite(pid) || pid <= 0 || pid === process.pid) return false;
	try {
		process.kill(pid, 0);
		return true; // 活进程持锁：说明 bin/nuwa 的 bash 循环在跑，扩展放行
	} catch {
		return false;
	}
}

export function readGraph(root: string): Graph | null {
	const proj = readJson<{ status?: string; goal?: string }>(join(root, ".sapper", "project.json"));
	if (!proj) return null;
	let open = 0;
	let done = 0;
	let claimed = 0;
	const openIds: string[] = [];
	const goalEdges: Array<{ status?: string; refs: string[] }> = [];
	let corrupt = false;
	try {
		for (const f of readdirSync(join(root, ".sapper", "intents"))) {
			if (!f.endsWith(".json")) continue;
			const it = readJson<{ id?: string; status?: string; to?: string; from?: string[] }>(
				join(root, ".sapper", "intents", f));
			if (!it) {
				corrupt = true;
				continue;
			}
			if (it.to === "goal") {
				goalEdges.push({
					status: it.status,
					refs: Array.isArray(it.from) ? it.from.map(String) : [],
				});
			}
			if (it.status === "open") {
				open++;
				if (it.id) openIds.push(it.id);
			} else if (it.status === "done") done++;
			else if (it.status === "claimed") claimed++;
		}
	} catch {
		/* 图还没建好 */
	}
	openIds.sort();
	let facts = 0;
	let flags = 0;
	let effective = 0;
	let verified = false;
	const kinds: Record<string, string> = {};
	try {
		for (const f of readdirSync(join(root, ".sapper", "facts"))) {
			if (!f.endsWith(".json") || f === "goal.json") continue;
			facts++;
			try {
				if (!readJson(join(root, ".sapper", "facts", f))) corrupt = true;
			} catch {
				corrupt = true;
			}
			const fact = readJson<{ id?: string; kind?: string }>(join(root, ".sapper", "facts", f));
			if (!fact) {
				corrupt = true;
				continue;
			}
			if (fact.id && fact.id !== f.replace(/\.json$/, "")) corrupt = true;
			if (fact.kind === "flag") flags++;
			if (fact?.kind && fact.kind !== "note") effective++;
			if (fact?.kind) kinds[f.replace(/\.json$/, "")] = fact.kind;
		}
	} catch {
		corrupt = true;
	}
	try {
		const goal = readJson<{ id?: string; kind?: string }>(
			join(root, ".sapper", "facts", "goal.json"));
		if (!goal || goal.id !== "goal" || goal.kind !== "goal") corrupt = true;
	} catch {
		corrupt = true;
	}
	const strong: Record<string, true> = { flag: true, vuln: true, loot: true };
	verified = !corrupt && goalEdges.length > 0 && goalEdges.every((edge) =>
		edge.status === "complete" && edge.refs.length > 0 &&
		edge.refs.every((id) => strong[kinds[id] ?? ""] === true));
	let viewUrl: string | null = null;
	try {
		const v = readFileSync(join(root, ".sapper", "view.url"), "utf8").trim();
		if (v) viewUrl = v;
	} catch {
		/* no view */
	}
	return {
		root,
		status: proj.status ?? "unknown",
		goal: proj.goal ?? "",
		open,
		done,
		claimed,
		facts,
		flags,
		effective,
		verified,
		openIds,
		locked: lockHeldByOther(root),
		viewUrl,
	};
}

/**
 * 完成证据闸门：模型常在 reason 阶段脑补"已拿到 flag"并直接 complete。
 * 没有 flag/vuln/loot 证据时把 status 打回 active，并写一条 hint。
 */
export function revertCompletion(root: string, why: string): boolean {
	const p = join(root, ".sapper", "project.json");
	const proj = readJson<Record<string, unknown>>(p);
	if (!proj || proj.status !== "completed") return false;
	proj.status = "active";
	delete proj.completed_at;
	delete proj.completed_from;
	proj.updated_at = new Date().toISOString();
	try {
		for (const f of readdirSync(join(root, ".sapper", "intents"))) {
			if (!f.endsWith(".json")) continue;
			const ip = join(root, ".sapper", "intents", f);
			const it = readJson<{ to?: string }>(ip);
			if (it?.to === "goal") {
				try {
					rmSync(ip);
				} catch {
					return false;
				}
			}
		}
		writeFileSync(p, JSON.stringify(proj, null, 2));
	} catch {
		return false;
	}
	try {
		const hp = join(root, ".sapper", "hints.json");
		const hints = readJson<Array<Record<string, unknown>>>(hp) ?? [];
		hints.push({ content: `完成被拒绝：${why}`, creator: "nuwa-loop", created_at: new Date().toISOString() });
		writeFileSync(hp, JSON.stringify(hints, null, 2));
	} catch {
		/* hint 写不进去不影响主流程 */
	}
	return true;
}

function safeId(s: string): string {
	return s.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 40) || "default";
}

function statePath(sessionId: string): string {
	return join(STATE_DIR, `${shortHash(sessionId)}.json`);
}

function logPath(sessionId: string): string {
	return join(LOG_DIR, `${safeId(sessionId)}.jsonl`);
}

/** 结构化日志：每轮一行，出问题先看这里。 */
export function logEvent(sessionId: string, rec: Record<string, unknown>): void {
	try {
		mkdirSync(LOG_DIR, { recursive: true });
		appendFileSync(logPath(sessionId), JSON.stringify({ ts: Date.now(), ...rec }) + "\n", "utf8");
	} catch {
		/* 日志写不进去也不能挡住主流程 */
	}
}

function loadState(sessionId: string): LoopState {
	const raw = readJson<Partial<LoopState>>(statePath(sessionId));
	if (!raw || raw.schema !== SCHEMA) return emptyState();
	return { ...emptyState(), ...raw, schema: SCHEMA };
}

function saveState(sessionId: string, st: LoopState): void {
	try {
		mkdirSync(STATE_DIR, { recursive: true });
		writeFileSync(statePath(sessionId), JSON.stringify(st, null, 2));
	} catch {
		logEvent(sessionId, { event: "state_save_failed" });
	}
}

/**
 * 续跑指令。四个 sapper 动作必须带齐参数：
 *   claim 的 --worker 是 sapper 的必填项；doc 必须 --set 才有内容；done 必须 --fact。
 */
export function buildDirective(g: Graph, st: LoopState, workerTag = "fujiang"): string {
	const head =
		`[女娲循环 · 自动续跑 第 ${st.turns} 轮]\n` +
		`项目 ${g.root}\n` +
		`status=${g.status} open=${g.open} claimed=${g.claimed} done=${g.done} facts=${g.facts} effective=${g.effective} flags=${g.flags}\n` +
		`goal: ${g.goal}\n` +
		`这是运行时注入的续跑指令，不是新任务，不要向爸爸请示。\n` +
		(g.locked ? `注意：${g.root}/.nuwa.lock 被外部 nuwa 进程持有，本会话只做验收与补位，避免重复派单。\n` : "") +
		(g.viewUrl ? `看板: ${g.viewUrl}\n` : "");

	const steps =
		g.open > 0
			? `按 SKILL.md 第 3 步派发本批（并行上限 5，一次 task 调用批量传）：\n` +
				`- 待办 intent: ${g.openIds.slice(0, 12).join(" ") || "(见 sapper frontier)"}\n` +
				`- 每个 task: agent="fujiang"，name=<intent id>，task 文案必须含下面三条（参数照抄）：\n` +
				`    cd ${g.root}\n` +
				`    sapper claim <id> --worker "${workerTag}-<id>"\n` +
				`    sapper doc <id> --set "<本轮执行的命令原文 + 关键输出摘要>"\n` +
				`- 子代理只回 5 行结论（结论/证据/命令/阻断/下一步），不直接 sapper done；主线程按批收口：\n` +
				`    nuwa commit --root ${g.root} --intent <id> --key auto --fact "<结论>" --kind <host|service|cred|vuln|loot|flag|note> --doc "<命令原文>"\n` +
				`- 禁止 sapper done / sapper dispatch <id> / 裸 sapper complete：扩展按 P-006 拦截；完成走 nuwa complete --from <fact>\n` +
				`- 通道：优先 task{tasks:[]} 批量；若改用 eval 的 agent()/workpool，每项同样必须 agent="fujiang"\n` +
				`- 主线程禁止自己跑 nmap/ffuf/curl，扫描只能发生在子代理里\n`
			: `frontier 为空：先 cd ${g.root} && nuwa run --root ${g.root} --minutes 2 --parallel 1，然后 sapper frontier 取新 intent 再派发。\n`;

	const discipline =
		`收工判据只有两个：flag 已入账并 nuwa complete --from <flag fact>，或 vuln/loot 事实足以支撑结论。\n` +
		`禁止在没有 flag/vuln/loot 事实时 nuwa complete：入口会校验 fact 的 kind，证据不足直接拒绝。\n` +
		`一轮 task 返回 ≠ 收工；不许输出"本轮战报""已完成"之类收尾段落。\n` +
		`每批返回后先跑 sapper status / sapper frontier 验收，再决定下一批。`;

	let escalate = "";
	if (st.stall >= 3) {
		escalate =
			`\n⚠ 图状态已连续 ${st.stall} 轮无有效变化（sig=${st.sig}）。换路，不要重复同一条命令：\n` +
			`- sapper release <卡住的 id> 2>/dev/null || true\n` +
			`- sapper hint "<intent id> 卡住：<一句话原因>"\n` +
			`- 改派另一条 intent，或重新 reason 生成新的攻击面。`;
	}
	if (st.idle >= 2) {
		escalate +=
			`\n⚠ 连续 ${st.idle} 轮没有调用任何工具。不要再输出说明文字：立刻用 task 派子代理，或直接执行 sapper status 验收。`;
	}

	return `${head}\n${steps}\n${discipline}${escalate}`;
}

export default function nuwaLoop(pi: ExtensionAPI) {
	const cfg = readCfg();
	if (!cfg.loop) return;

	// 每会话的实时工具调用计数（避免每次 tool_call 都写盘）
	const liveToolCalls = new Map<string, number>();

	const arm = (sessionId: string) => {
		const st = loadState(sessionId);
		if (st.armed && Date.now() - st.armedAt < cfg.guardMs) return;
		const fresh = emptyState();
		fresh.armed = true;
		fresh.armedAt = Date.now();
		saveState(sessionId, fresh);
		logEvent(sessionId, { event: "armed" });
	};

	const TRIGGER = /女娲模式|女娲渗透|开图|接入\s*sapper|sapper\s*模式/i;

	pi.on("before_agent_start", (event, ctx) => {
		if (!TRIGGER.test(event.prompt)) return;
		arm(ctx.sessionManager.getSessionId());
	});

	pi.on("input", (event: InputEvent, ctx) => {
		if (!TRIGGER.test(event.text)) return;
		arm(ctx.sessionManager.getSessionId());
	});

	// 结构化判定：真的执行了 sapper 命令，或真的派了 fujiang 子代理
	pi.on("tool_call", (event: ToolCallEvent, ctx) => {
		const sid = ctx.sessionManager.getSessionId();
		liveToolCalls.set(sid, (liveToolCalls.get(sid) ?? 0) + 1);
		const input = (event.input ?? {}) as Record<string, unknown>;
		const verdict = checkTool(event.toolName, input, ctx?.cwd ?? process.cwd());
		if (!verdict.allowed && (process.env.NUWA_POLICY_ENFORCE ?? "1").trim() !== "0") {
			const detail =
				event.toolName === "bash"
					? String(input.command ?? "")
					: JSON.stringify(input ?? {});
			logEvent(sid, {
				event: "policy_block",
				rule: verdict.rule,
				tool: event.toolName,
				detail: detail.slice(0, 160),
			});
			return {
				block: true,
				reason: `nuwa policy ${verdict.rule}: blocked ${event.toolName}`,
			};
		}
		if (event.toolName === "bash") {
			const cmd = typeof input.command === "string" ? input.command : "";
			if (/(^|[\s;&|()])sapper(\s|$)/.test(cmd)) arm(sid);
			return;
		}
		if (event.toolName === "task") {
			const agent = typeof input.agent === "string" ? input.agent : "";
			const text = JSON.stringify(input ?? {});
			if (agent === "fujiang" || /sapper/.test(text)) arm(sid);
			return;
		}
	});

	pi.on("session_stop", (event: SessionStopEvent, ctx) => {
		const sid = String(event.session_id ?? "default");
		const st = loadState(sid);
		if (!st.armed || Date.now() - st.armedAt > cfg.guardMs) return;

		const root = findRoot(ctx?.cwd ?? process.cwd(), sid);
		if (!root) return;
		const g = readGraph(root);
		if (!g) return;

		// 目标完成 → 先验证证据，再决定是否收工
		if (g.status === "completed") {
			const requireEvidence = (process.env.NUWA_REQUIRE_EVIDENCE ?? "1").trim() !== "0";
			if (requireEvidence && !g.verified) {
				st.completionRejects++;
				if (st.completionRejects <= 3 && revertCompletion(g.root, "没有任何 flag/vuln/loot 事实")) {
					g.status = "active";
					logEvent(sid, { event: "completion_rejected", flags: g.flags, effective: g.effective });
				} else {
					st.armed = false;
					saveState(sid, st);
					logEvent(sid, { event: "stop_completed_unverified", flags: g.flags });
					ctx?.ui?.setStatus?.("nuwa-loop", "停机：无证据完成且打回次数用尽");
					return;
				}
			} else {
				st.armed = false;
				saveState(sid, st);
				logEvent(sid, { event: "stop_completed", root: g.root, verified: g.verified });
				return;
			}
		}

		// 外部 nuwa 进程正在操作同一张图 → 让 bash 循环主导，扩展不抢
		if (g.locked) {
			logEvent(sid, { event: "stop_skip_locked", root: g.root });
			return;
		}

		st.turns++;
		st.toolCalls = liveToolCalls.get(sid) ?? st.toolCalls;

		// 预算：用当前上下文 tokens 的增量近似累计消耗
		const usage = ctx.getContextUsage?.();
		if (usage && Number.isFinite(usage.tokens)) {
			const delta = Math.max(0, usage.tokens - st.lastTokens);
			st.spentTokens += delta;
			st.lastTokens = usage.tokens;
		}

		// stall 用「有效推进」签名：note 噪声不再重置计数器
		const sig = `${g.status}|${g.open}|${g.claimed}|${g.done}|${g.effective}|${g.flags}`;
		const advanced = sig !== st.sig;
		if (advanced) {
			st.stall = 0;
			st.sig = sig;
		} else {
			st.stall++;
		}

		// 空转：turn 在涨但工具调用没涨（从未调工具也算）
		if (st.toolCalls === st.lastToolCallsSnapshot) st.idle++;
		else st.idle = 0;
		st.lastToolCallsSnapshot = st.toolCalls;

		const stop = (why: string) => {
			st.armed = false;
			saveState(sid, st);
			logEvent(sid, {
				event: "stop",
				why,
				turns: st.turns,
				stall: st.stall,
				idle: st.idle,
				spentTokens: st.spentTokens,
				sig,
			});
			ctx?.ui?.setStatus?.("nuwa-loop", `停机 (${why})`);
		};

		if (st.turns > cfg.maxTurns) return stop("max_turns");
		if (st.stall >= cfg.maxStall) return stop("max_stall");
		if (st.idle >= cfg.maxIdle) return stop("idle");
		if (st.spentTokens > cfg.maxTokens) return stop("max_tokens");

		saveState(sid, st);
		const reason = buildDirective(g, st);
		st.lastReason = reason;
		saveState(sid, st);

		logEvent(sid, {
			event: "block",
			turn: st.turns,
			stall: st.stall,
			idle: st.idle,
			sig,
			open: g.open,
			done: g.done,
			facts: g.facts,
			effective: g.effective,
			spentTokens: st.spentTokens,
		});

		ctx?.ui?.setStatus?.(
			"nuwa-loop",
			`续跑 #${st.turns} · open=${g.open} done=${g.done} eff=${g.effective} facts=${g.facts}`,
		);

		// block 链过长时切一次 continue，降低与其他 session_stop handler 的抢占
		st.blockStreak++;
		saveState(sid, st);
		if (event.stop_hook_active && st.blockStreak > cfg.blockStreakLimit) {
			st.blockStreak = 0;
			saveState(sid, st);
			return { continue: true as const, additionalContext: reason };
		}

		return { decision: "block" as const, reason };
	});

	pi.registerCommand?.("nuwa-loop", {
		description: "女娲循环状态：/nuwa-loop | off | on | log [n] | why | reset | budget <tokens>",
		handler: async (args, ctx) => {
			const sid = ctx.sessionManager.getSessionId();
			const st = loadState(sid);
			const arg = (args ?? "").trim();
			const [sub, ...rest] = arg.split(/\s+/);

			if (sub === "off") {
				st.armed = false;
				saveState(sid, st);
				ctx.ui.notify("nuwa-loop 已解除武装", "info");
				return;
			}
			if (sub === "on") {
				arm(sid);
				ctx.ui.notify("nuwa-loop 已上膛", "info");
				return;
			}
			if (sub === "reset") {
				saveState(sid, emptyState());
				ctx.ui.notify("nuwa-loop 状态已重置（未上膛）", "info");
				return;
			}
			if (sub === "why") {
				ctx.ui.notify(st.lastReason || "(还没有注入过指令)", "info");
				return;
			}
			if (sub === "budget") {
				const n = Number(rest[0]);
				if (Number.isFinite(n) && n > 0) {
					process.env.NUWA_MAX_TOKENS = String(n);
					ctx.ui.notify(`NUWA_MAX_TOKENS=${n}（下一轮生效）`, "info");
				} else {
					ctx.ui.notify(`已用 ≈${st.spentTokens} tokens，上限 ${cfg.maxTokens}`, "info");
				}
				return;
			}
			if (sub === "log") {
				const n = Math.max(1, Math.min(200, Number(rest[0]) || 10));
				try {
					const lines = readFileSync(logPath(sid), "utf8").trim().split("\n").slice(-n);
					ctx.ui.notify(lines.join("\n") || "(空日志)", "info");
				} catch {
					ctx.ui.notify("(还没有日志)", "info");
				}
				return;
			}

			const root = findRoot(ctx.cwd, sid);
			const g = root ? readGraph(root) : null;
			ctx.ui.notify(
				g
					? `armed=${st.armed} turns=${st.turns} stall=${st.stall} idle=${st.idle} tokens≈${st.spentTokens} | ${g.root} status=${g.status} open=${g.open} done=${g.done} eff=${g.effective}${g.locked ? " [locked]" : ""}`
					: `armed=${st.armed} turns=${st.turns} stall=${st.stall} idle=${st.idle} tokens≈${st.spentTokens} | 未找到 .sapper 图`,
				"info",
			);
		},
	});
}
