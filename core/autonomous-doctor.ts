/**
 * core/autonomous-doctor.ts — 女娲 v8.0 无头守护器环境健康体检（doctor）与只读诊断/告警辅助模块。
 *
 * 职责：
 * 1. 实现 `nuwa-autonomous doctor [--json]` 全量外部依赖与安装完整性核验（bun、omp、12 工具/扩展模块、
 *    `kb.db` 零写盘只读统计、6 个 5+1 专精小队子代理模板、本地工具链、Docker/Sidecar 沙盒、短超时 gh 探活）；
 * 2. 提供守护进程侧零磁盘写副作用的 SQLite / JSON 状态读取（`openReadonlyKbDb`、`readSqliteStateDaemon`、`readDiskState`）；
 * 3. 提供统一网络环境构建（`buildUnifiedNetworkEnvDaemon`）、跨世代预算阈值核算（`checkBudgetCap`）
 *    与全量凭据脱敏 Webhook 告警投递（`sendDaemonWebhook`）。
 *
 * 约束：零第三方 npm 依赖，严禁反向导入 `../bin/nuwa-autonomous` 或 `../omp/nuwa`。
 */
import { spawnSync } from "node:child_process";
import {
	accessSync,
	appendFileSync,
	chmodSync,
	constants,
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	readdirSync,
	rmSync,
	statSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { Database } from "bun:sqlite";

export const VALID_SANDBOX_MODES = new Set(["none", "docker", "sidecar"]);
export const DEFAULT_GH_HTTP_TIMEOUT_SEC = 5;
export const DEFAULT_EXTERNAL_PROBE_TIMEOUT_MS = 5000;
export const WEBHOOK_TIMEOUT_MS = 5000;
export const WEBHOOK_MAX_ATTEMPTS = 3;

export const REQUIRED_NUWA_TOOLS = [
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
] as const;

export const CORE_EXT_MODULES = [
	"types.ts",
	"storage.ts",
	"graph.ts",
	"ui.ts",
	"ui-native.ts",
	"autoexec.ts",
	"scope.ts",
	"evidence.ts",
	"profiles.ts",
	"reincarnate.ts",
] as const;

export const SPLIT_CORE_MODULES = new Set<string>(["storage.ts", "graph.ts"]);

export const V4_EXT_MODULES = [
	"lineage.ts",
	"session-vault.ts",
	"verifier-gate.ts",
	"sandbox.ts",
	"kb.ts",
	"browser-recon.ts",
] as const;

export const V5_EXT_MODULES = ["auth-diff.ts", "oob.ts", "hypothesis.ts", "reporting.ts"] as const;

export const V6_EXT_MODULES = [
	"sqlite-store.ts",
	"graph-planner.ts",
	"graph-commands.ts",
	"auto-loops.ts",
	"belief-search.ts",
	"calibration.ts",
	"traffic-workbench.ts",
	"hybrid-audit.ts",
] as const;

export const V7_EXT_MODULES = [
	"cdp-bridge.ts",
	"chain-composer.ts",
	"specialist-squad.ts",
	"kb-v2.ts",
	"dispatch-bridge.ts",
] as const;

/** Wave 0 无环拆解的 8 个 omp/ 底层子模块及其对应的父模块（用于体检防假绿并兼容 v4 旧版模拟环境）。 */
export const FOUNDATION_EXT_SUBMODULE_PAIRS = [
	{ parent: "storage.ts", child: "storage-io.ts" },
	{ parent: "sqlite-store.ts", child: "sqlite-schema.ts" },
	{ parent: "graph-planner.ts", child: "graph-dedup.ts" },
	{ parent: "autoexec.ts", child: "autoexec-baseline.ts" },
	{ parent: "traffic-workbench.ts", child: "traffic-mutator.ts" },
	{ parent: "sandbox.ts", child: "sandbox-egress.ts" },
	{ parent: "cdp-bridge.ts", child: "cdp-client.ts" },
	{ parent: "chain-composer.ts", child: "chain-capabilities.ts" },
] as const;

export const FOUNDATION_EXT_SUBMODULES = FOUNDATION_EXT_SUBMODULE_PAIRS.map((p) => p.child);

export const NUWA_CORE_REQUIRED_FILES = [
	"engine.ts",
	"engine-helpers.ts",
	"autonomous-doctor.ts",
] as const;

export const SQUAD_AGENT_FILES = [
	"fujiang.md",
	"nuwa-verifier.md",
	"nuwa-scout.md",
	"nuwa-spa-reverser.md",
	"nuwa-auth-breaker.md",
	"nuwa-code-auditor.md",
] as const;

export const DOCTOR_PROBE_TOOLS = [
	"curl",
	"openssl",
	"nmap",
	"ffuf",
	"nuclei",
	"sqlmap",
	"whatweb",
	"hydra",
	"python3",
	"nc",
	"sqlite3",
	"jq",
] as const;

export const KB_TABLES = ["kb_items", "card", "cve", "poc", "technique", "kev", "epss", "experience"] as const;

export const DOCTOR_HELP_TEXT = `女娲 v7.0 环境自检子命令 (nuwa-autonomous doctor)

用法:
  nuwa-autonomous doctor [选项]

选项:
  --json                       以标准 JSON 格式输出体检结果
  --agent-home <dir>           指定 agent home 目录（覆盖 PI_AGENT_HOME 自动探测）
  --omp-bin <path>             指定 omp 可执行文件路径（默认: omp）
  --bun-bin <path>             指定 bun 可执行文件路径（默认: bun）
  --kb-db <path>               指定知识库 SQLite 路径（覆盖 NUWA_KB_DB）
  --sandbox <none|docker|sidecar> 指定预期运行模式；为 docker/sidecar 时将 Docker 可用性纳入核心门禁
  --sandbox-image <img>        指定校验的沙盒镜像名（默认: nuwa-sandbox:latest）
  --docker-bin <path>          指定 docker 可执行文件路径（默认: docker）
  -h, --help                   显示本帮助信息
`;

export interface DoctorParsedOptions {
	json: boolean;
	help: boolean;
	agentHome: string;
	ompBin: string;
	bunBin: string;
	kbDb: string;
	sandbox: string;
	sandboxImage: string;
	dockerBin: string;
	ghBin: string;
	ghExplicit: boolean;
	checkGhAuth: boolean;
}

export interface ExternalProbeResult {
	ok: boolean;
	timedOut: boolean;
	status: number | null;
	signal: NodeJS.Signals | null;
	stdout: string;
	stderr: string;
	error: string;
	timeoutMs: number;
}

export interface DoctorCheckItem {
	ok: boolean;
	critical: boolean;
	reason?: string;
	[key: string]: unknown;
}

function logDoctorErr(msg: string): void {
	console.error(`[nuwa-autonomous] ERROR: ${msg}`);
}

export function parseDoctorArgs(argv: string[]): DoctorParsedOptions {
	const opts: DoctorParsedOptions = {
		json: false,
		help: false,
		agentHome: "",
		ompBin: (process.env.NUWA_OMP_BIN ?? "").trim() || "omp",
		bunBin: (process.env.NUWA_DOCTOR_BUN_BIN ?? "").trim() || "bun",
		kbDb: "",
		sandbox: "none",
		sandboxImage: (process.env.NUWA_SANDBOX_IMAGE ?? "").trim() || "nuwa-sandbox:latest",
		dockerBin: (process.env.NUWA_DOCKER_BIN ?? "").trim() || "docker",
		ghBin: (process.env.NUWA_GH_BIN ?? "").trim() || "gh",
		ghExplicit: Boolean((process.env.NUWA_GH_BIN ?? "").trim()),
		checkGhAuth: (process.env.NUWA_DOCTOR_CHECK_GH ?? "").trim() === "1",
	};

	const needVal = (flag: string, i: number): string => {
		if (i + 1 >= argv.length) throw new Error(`参数 ${flag} 缺少取值`);
		return argv[i + 1]!;
	};

	for (let i = 0; i < argv.length; i += 1) {
		const raw = argv[i]!;
		let flag = raw;
		let inlineVal: string | null = null;
		if (raw.startsWith("--") && raw.includes("=")) {
			const idx = raw.indexOf("=");
			flag = raw.slice(0, idx);
			inlineVal = raw.slice(idx + 1);
		}
		const take = (): string => (inlineVal !== null ? inlineVal : needVal(flag, i++));

		switch (flag) {
			case "-h":
			case "--help":
				opts.help = true;
				break;
			case "--json":
				opts.json = true;
				break;
			case "--agent-home":
				opts.agentHome = take().trim();
				break;
			case "--omp-bin":
				opts.ompBin = take().trim() || "omp";
				break;
			case "--bun-bin":
				opts.bunBin = take().trim() || "bun";
				break;
			case "--kb-db":
				opts.kbDb = take().trim();
				break;
			case "--sandbox":
				opts.sandbox = take().trim().toLowerCase();
				break;
			case "--sandbox-image":
				opts.sandboxImage = take().trim() || "nuwa-sandbox:latest";
				break;
			case "--docker-bin":
				opts.dockerBin = take().trim() || "docker";
				break;
			case "--gh-bin":
				opts.ghBin = take().trim() || "gh";
				opts.ghExplicit = true;
				break;
			case "--check-gh-auth":
				opts.checkGhAuth = true;
				break;
			default:
				throw new Error(`doctor 未知参数: ${raw}（使用 nuwa-autonomous doctor --help 查看用法）`);
		}
	}

	if (!VALID_SANDBOX_MODES.has(opts.sandbox)) {
		throw new Error(`doctor 不支持的 --sandbox: ${opts.sandbox}（可选: none, docker, sidecar）`);
	}
	return opts;
}

export function resolveExecutable(binName: string | undefined): string | null {
	const name = String(binName ?? "").trim();
	if (!name) return null;
	if (name.includes("/") || name.includes("\\")) {
		try {
			const full = resolve(name);
			if (statSync(full).isFile()) {
				accessSync(full, constants.X_OK);
				return full;
			}
		} catch {
			return null;
		}
		return null;
	}
	const pathEnv = process.env.PATH ?? "";
	for (const dir of pathEnv.split(delimiter)) {
		if (!dir) continue;
		const full = join(dir, name);
		try {
			if (statSync(full).isFile()) {
				accessSync(full, constants.X_OK);
				return full;
			}
		} catch {
			/* 继续查找下一 PATH 目录 */
		}
	}
	return null;
}

export function getGhHttpTimeoutSec(): number {
	const raw = (process.env.NUWA_GH_HTTP_TIMEOUT ?? process.env.GH_HTTP_TIMEOUT ?? "").trim();
	const n = Number(raw);
	return Number.isFinite(n) && n > 0 ? Math.floor(n) : DEFAULT_GH_HTTP_TIMEOUT_SEC;
}

export function getExternalProbeTimeoutMs(fallbackMs = DEFAULT_EXTERNAL_PROBE_TIMEOUT_MS): number {
	const raw = (process.env.NUWA_EXTERNAL_PROBE_TIMEOUT_MS ?? "").trim();
	const n = Number(raw);
	return Number.isFinite(n) && n >= 50 ? Math.floor(n) : fallbackMs;
}

/** 受短超时与 GH_HTTP_TIMEOUT=5 硬保护的外部命令探活，避免 gh/git/docker 等外部 CLI 无限挂死。 */
export function runExternalProbe(
	binPath: string,
	args: string[],
	opts: { timeoutMs?: number; env?: Record<string, string | undefined> } = {},
): ExternalProbeResult {
	const timeoutMs =
		typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
			? Math.floor(opts.timeoutMs)
			: getExternalProbeTimeoutMs();
	const ghSec = String(getGhHttpTimeoutSec());
	const env: Record<string, string | undefined> = {
		...process.env,
		GH_HTTP_TIMEOUT: ghSec,
		GIT_TERMINAL_PROMPT: "0",
		GIT_HTTP_LOW_SPEED_LIMIT: "1",
		GIT_HTTP_LOW_SPEED_TIME: ghSec,
		...(opts.env ?? {}),
	};
	try {
		const spawnOpts = {
			encoding: "utf8",
			timeout: timeoutMs,
			killSignal: "SIGKILL",
			env,
			stdio: ["ignore", "pipe", "pipe"],
		};
		const res = spawnSync(binPath, args, spawnOpts as Parameters<typeof spawnSync>[2]);
		const errCode = (res.error as NodeJS.ErrnoException | undefined)?.code;
		const timedOut =
			Boolean(res.error && (errCode === "ETIMEDOUT" || /timed out|ETIMEDOUT/i.test(String(res.error.message ?? "")))) ||
			(res.status === null && res.signal === "SIGKILL");
		return {
			ok: !res.error && !timedOut && res.status === 0,
			timedOut,
			status: res.status,
			signal: res.signal,
			stdout: String(res.stdout ?? ""),
			stderr: String(res.stderr ?? ""),
			error: res.error ? String(res.error.message ?? res.error) : "",
			timeoutMs,
		};
	} catch (err) {
		return {
			ok: false,
			timedOut: false,
			status: -1,
			signal: null,
			stdout: "",
			stderr: "",
			error: err instanceof Error ? err.message : String(err),
			timeoutMs,
		};
	}
}

export function probeBinaryVersion(binPath: string, versionArgs: string[] = ["--version"]): string | null {
	const res = runExternalProbe(binPath, versionArgs, { timeoutMs: Math.min(3000, getExternalProbeTimeoutMs(3000)) });
	if (res.timedOut || res.error) return null;
	const out = `${res.stdout}\n${res.stderr}`
		.split("\n")
		.map((s) => s.trim())
		.find(Boolean);
	return out || null;
}

export function checkGhCliProbe(ghBin: string, checkAuth = false): DoctorCheckItem {
	const binPath = resolveExecutable(ghBin);
	const ghHttpTimeoutSec = getGhHttpTimeoutSec();
	const timeoutMs = getExternalProbeTimeoutMs(DEFAULT_EXTERNAL_PROBE_TIMEOUT_MS);
	if (!binPath) {
		return {
			ok: true,
			critical: false,
			available: false,
			timedOut: false,
			ghHttpTimeoutSec,
			timeoutMs,
			bin: ghBin,
			reason: "未安装 gh（可选工具，不影响女娲核心运行）",
		};
	}
	const probeArgs = checkAuth ? ["auth", "status"] : ["--version"];
	const res = runExternalProbe(binPath, probeArgs, { timeoutMs: checkAuth ? timeoutMs : Math.min(2000, timeoutMs) });
	if (res.timedOut) {
		return {
			ok: false,
			critical: false,
			available: true,
			timedOut: true,
			ghHttpTimeoutSec,
			timeoutMs,
			bin: binPath,
			reason: `gh 探活超时（已按 ${timeoutMs}ms / GH_HTTP_TIMEOUT=${ghHttpTimeoutSec}s 保护截断，避免挂死）`,
		};
	}
	return {
		ok: true,
		critical: false,
		available: true,
		timedOut: false,
		...(checkAuth ? { authenticated: res.ok } : {}),
		ghHttpTimeoutSec,
		timeoutMs,
		bin: binPath,
		...(res.ok ? {} : { reason: checkAuth ? "gh 已安装但未登录（已快速返回，未阻塞）" : "gh 版本探测返回非零（已快速返回）" }),
	};
}

export function resolveAgentHome(overrideDir?: string): string {
	if (overrideDir && overrideDir.trim()) {
		return resolve(overrideDir.trim());
	}
	if (process.env.PI_AGENT_HOME && process.env.PI_AGENT_HOME.trim()) {
		return resolve(process.env.PI_AGENT_HOME.trim());
	}
	const ompAgent = join(homedir(), ".omp", "agent");
	if (existsSync(ompAgent)) return ompAgent;
	return join(homedir(), ".pi", "agent");
}

export function checkExtensionInstallation(agentHome: string) {
	const extRoot = join(agentHome, "extensions");
	const extDir = join(extRoot, "nuwa-omp");
	const indexPath = join(extDir, "index.ts");
	const indexExists = existsSync(indexPath);

	let indexSrc = "";
	let version: string | null = null;
	if (indexExists) {
		try {
			indexSrc = readFileSync(indexPath, "utf8");
			const m = /export\s+const\s+VERSION\s*=\s*["']([^"']+)["']/.exec(indexSrc);
			if (m?.[1]) version = m[1];
		} catch {
			/* 无法读取 index.ts */
		}
	}

	const toolsFound: string[] = [];
	const toolsMissing: string[] = [];
	for (const tool of REQUIRED_NUWA_TOOLS) {
		const re = new RegExp(`name\\s*:\\s*["']${tool}["']`);
		if (indexSrc && re.test(indexSrc)) {
			toolsFound.push(tool);
		} else {
			toolsMissing.push(tool);
		}
	}

	const referencesSplitModules =
		/from\s+["']\.\/(?:storage|graph)(?:\.ts)?["']/.test(indexSrc) ||
		/require\s*\(\s*["']\.\/(?:storage|graph)(?:\.ts)?["']\s*\)/.test(indexSrc);
	const hasAnySplitFile = existsSync(join(extDir, "storage.ts")) || existsSync(join(extDir, "graph.ts"));
	const isLegacyMonolith =
		!referencesSplitModules &&
		!hasAnySplitFile &&
		typeof version === "string" &&
		(version === "4.0.0" || /^3\./.test(version));

	const coreModulesFound: string[] = [];
	const coreModulesMissing: string[] = [];
	for (const mod of CORE_EXT_MODULES) {
		if (existsSync(join(extDir, mod))) {
			coreModulesFound.push(mod);
		} else if (!isLegacyMonolith || !SPLIT_CORE_MODULES.has(mod)) {
			coreModulesMissing.push(mod);
		}
	}

	const v4ModulesFound: string[] = [];
	const v4ModulesMissing: string[] = [];
	for (const mod of V4_EXT_MODULES) {
		if (existsSync(join(extDir, mod))) v4ModulesFound.push(mod);
		else v4ModulesMissing.push(mod);
	}

	const v5ModulesFound: string[] = [];
	const v5ModulesMissing: string[] = [];
	for (const mod of V5_EXT_MODULES) {
		if (existsSync(join(extDir, mod))) v5ModulesFound.push(mod);
		else v5ModulesMissing.push(mod);
	}

	const v6ModulesFound: string[] = [];
	const v6ModulesMissing: string[] = [];
	for (const mod of V6_EXT_MODULES) {
		if (existsSync(join(extDir, mod))) v6ModulesFound.push(mod);
		else v6ModulesMissing.push(mod);
	}

	const v7ModulesFound: string[] = [];
	const v7ModulesMissing: string[] = [];
	for (const mod of V7_EXT_MODULES) {
		if (existsSync(join(extDir, mod))) v7ModulesFound.push(mod);
		else v7ModulesMissing.push(mod);
	}

	const isV7OrAbove = typeof version === "string" && Number.parseInt(version.split(".")[0] ?? "0", 10) >= 7;

	// 校验 Wave 0 拆解的 8 个 omp 底层子模块（当 v7+ 或对应父模块实际引用了该子模块时列为必需，对 v4 模拟目录零误杀）
	const submodulesFound: string[] = [];
	const submodulesMissing: string[] = [];
	for (const { parent, child } of FOUNDATION_EXT_SUBMODULE_PAIRS) {
		const childExists = existsSync(join(extDir, child));
		if (childExists) {
			submodulesFound.push(child);
			continue;
		}
		let parentRefsChild = false;
		const parentPath = join(extDir, parent);
		if (existsSync(parentPath)) {
			try {
				const pSrc = readFileSync(parentPath, "utf8");
				const childStem = child.replace(/\.ts$/, "");
				parentRefsChild = new RegExp(`from\\s+["']\\./${childStem}(?:\\.ts)?["']`).test(pSrc);
			} catch {
				/* ignore */
			}
		}
		if (isV7OrAbove || parentRefsChild) {
			submodulesMissing.push(child);
		}
	}

	// 校验安装态 nuwa-core/core/{engine.ts,engine-helpers.ts,autonomous-doctor.ts}
	const nuwaCoreRoot = join(agentHome, "nuwa-core");
	const nuwaCoreDir = join(nuwaCoreRoot, "core");
	const referencesNuwaCore = /nuwa-core\/core\/engine/.test(indexSrc) || existsSync(nuwaCoreRoot);
	const nuwaCoreFound: string[] = [];
	const nuwaCoreMissing: string[] = [];
	if (isV7OrAbove || referencesNuwaCore) {
		for (const cf of NUWA_CORE_REQUIRED_FILES) {
			if (existsSync(join(nuwaCoreDir, cf))) {
				nuwaCoreFound.push(cf);
			} else {
				nuwaCoreMissing.push(cf);
			}
		}
	}

	const conflicts: string[] = [];
	if (existsSync(extRoot)) {
		try {
			for (const entry of readdirSync(extRoot)) {
				if (entry.startsWith("nuwa-") && entry !== "nuwa-omp") {
					conflicts.push(entry);
				}
			}
		} catch {
			/* ignore */
		}
	}

	const ok =
		indexExists &&
		toolsMissing.length === 0 &&
		coreModulesMissing.length === 0 &&
		(!isV7OrAbove || v7ModulesMissing.length === 0) &&
		submodulesMissing.length === 0 &&
		nuwaCoreMissing.length === 0;
	let reason = "";
	if (!indexExists) {
		reason = `未检测到已安装扩展入口 ${indexPath}（请运行 ./install.sh）`;
	} else if (toolsMissing.length > 0) {
		reason = `扩展缺少必需工具 (${toolsMissing.join(", ")})`;
	} else if (coreModulesMissing.length > 0) {
		reason = `扩展缺少核心模块 (${coreModulesMissing.join(", ")})`;
	} else if (isV7OrAbove && v7ModulesMissing.length > 0) {
		reason = `扩展缺少 v7 核心模块 (${v7ModulesMissing.join(", ")})`;
	} else if (submodulesMissing.length > 0) {
		reason = `扩展缺少底层拆解子模块 (${submodulesMissing.join(", ")})`;
	} else if (nuwaCoreMissing.length > 0) {
		reason = `nuwa-core 缺少核心引擎模块 (${nuwaCoreMissing.join(", ")})`;
	}

	return {
		ok,
		critical: true,
		dir: extDir,
		indexExists,
		version,
		toolsCount: toolsFound.length,
		toolsRequired: REQUIRED_NUWA_TOOLS.length,
		toolsFound,
		toolsMissing,
		coreModulesFound,
		coreModulesMissing,
		v4ModulesFound,
		v4ModulesMissing,
		v5ModulesFound,
		v5ModulesMissing,
		v6ModulesFound,
		v6ModulesMissing,
		v7ModulesFound,
		v7ModulesMissing,
		submodulesFound,
		submodulesMissing,
		nuwaCoreFound,
		nuwaCoreMissing,
		conflicts,
		...(reason ? { reason } : {}),
	};
}

export function openReadonlySqliteMemorySnapDaemon(filePath: string): Database {
	const raw = readFileSync(filePath);
	const copy = new Uint8Array(raw.length);
	copy.set(raw);
	if (
		copy.length >= 100 &&
		Buffer.from(copy.subarray(0, 16)).toString("latin1") === "SQLite format 3\0" &&
		copy[18] === 2 &&
		copy[19] === 2
	) {
		copy[18] = 1;
		copy[19] = 1;
	}
	return Database.deserialize(copy, { readonly: true });
}

export function openReadonlyWalIsolatedSnapDaemon(filePath: string): Database {
	const snapDir = mkdtempSync(join(tmpdir(), "nuwa-daemon-ro-"));
	const snapDb = join(snapDir, "snap.db");
	try {
		copyFileSync(filePath, snapDb);
		chmodSync(snapDb, 0o600);
		if (existsSync(`${filePath}-wal`)) {
			copyFileSync(`${filePath}-wal`, `${snapDb}-wal`);
			chmodSync(`${snapDb}-wal`, 0o600);
		}
		const rwSnap = new Database(snapDb, { readwrite: true });
		try {
			rwSnap.exec("PRAGMA busy_timeout = 3000;");
			rwSnap.exec("PRAGMA wal_checkpoint(TRUNCATE);");
			rwSnap.exec("PRAGMA journal_mode = DELETE;");
		} finally {
			rwSnap.close();
		}
		return openReadonlySqliteMemorySnapDaemon(snapDb);
	} finally {
		try {
			rmSync(snapDir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
}

export function openReadonlyKbDb(filePath: string): Database {
	const walFile = `${filePath}-wal`;
	let walNonEmpty = false;
	try {
		walNonEmpty = existsSync(walFile) && statSync(walFile).size > 0;
	} catch {
		walNonEmpty = false;
	}
	// 无论是否存在 -shm，统一走纯内存只读快照（非空 -wal 在隔离临时目录重放），确保原目录 -shm / -wal 100% 零字节变动
	const memDb = walNonEmpty
		? openReadonlyWalIsolatedSnapDaemon(filePath)
		: openReadonlySqliteMemorySnapDaemon(filePath);
	memDb.query("SELECT 1 FROM sqlite_master LIMIT 1").get();
	return memDb;
}

export function checkKnowledgeBase(agentHome: string, explicitPath?: string, explicitAgentHome = false) {
	const candidates: string[] = [];
	if (explicitPath && explicitPath.trim()) {
		candidates.push(resolve(explicitPath.trim()));
	} else if (process.env.NUWA_KB_DB && process.env.NUWA_KB_DB.trim()) {
		candidates.push(resolve(process.env.NUWA_KB_DB.trim()));
		if (explicitAgentHome) {
			candidates.push(join(agentHome, "nuwa-kb", "kb.db"));
		}
	} else if (explicitAgentHome || (process.env.PI_AGENT_HOME && process.env.PI_AGENT_HOME.trim())) {
		candidates.push(join(agentHome, "nuwa-kb", "kb.db"));
	} else {
		candidates.push(join(agentHome, "nuwa-kb", "kb.db"));
		candidates.push("/data/nuwa-kb/kb.db");
	}

	const foundPath = candidates.find((p) => existsSync(p)) ?? candidates[0]!;
	const exists = existsSync(foundPath);

	if (!exists) {
		return {
			ok: false,
			critical: false,
			path: foundPath,
			exists: false,
			counts: {} as Record<string, number>,
			totalRecords: 0,
			reason: `未找到知识库文件 ${foundPath}`,
		};
	}

	const counts: Record<string, number> = {};
	let totalRecords = 0;
	let db: Database | null = null;
	try {
		db = openReadonlyKbDb(foundPath);
		const existingTables = new Set(
			(db.query("SELECT name FROM sqlite_master WHERE type IN ('table', 'view')").all() as Array<{ name?: string }>).map(
				(r) => String(r?.name ?? ""),
			),
		);
		for (const table of KB_TABLES) {
			if (!existingTables.has(table)) continue;
			const row = db.query(`SELECT COUNT(*) AS cnt FROM "${table}"`).get() as { cnt?: number } | null;
			const cnt = Number(row?.cnt ?? 0);
			if (Number.isFinite(cnt)) {
				counts[table] = cnt;
				totalRecords += cnt;
			}
		}
		return {
			ok: totalRecords > 0,
			critical: false,
			path: foundPath,
			exists: true,
			counts,
			totalRecords,
			...(totalRecords === 0 ? { reason: "知识库文件存在但尚无有效记录" } : {}),
		};
	} catch (err) {
		return {
			ok: false,
			critical: false,
			path: foundPath,
			exists: true,
			counts,
			totalRecords: 0,
			reason: `读取知识库失败: ${err instanceof Error ? err.message : String(err)}`,
		};
	} finally {
		try {
			db?.close();
		} catch {
			/* ignore */
		}
	}
}

export function checkAgentTemplates(agentHome: string, extVersion: string | null = null) {
	const agentsDir = join(agentHome, "agents");
	const checkOne = (filename: string) => {
		const full = join(agentsDir, filename);
		let exists = false;
		let bytes = 0;
		try {
			const st = statSync(full);
			exists = st.isFile() && st.size > 0;
			bytes = st.size;
		} catch {
			exists = false;
		}
		return { exists, path: full, bytes };
	};

	const fujiang = checkOne("fujiang.md");
	const nuwaVerifier = checkOne("nuwa-verifier.md");
	const squad: Record<string, { exists: boolean; path: string; bytes: number }> = {};
	const missing: string[] = [];
	for (const af of SQUAD_AGENT_FILES) {
		const res = checkOne(af);
		squad[af] = res;
		if (!res.exists && (af === "fujiang.md" || af === "nuwa-verifier.md")) {
			missing.push(af);
		}
	}
	const squadMissing = SQUAD_AGENT_FILES.filter((af) => !squad[af]?.exists);
	const isV7OrAbove = typeof extVersion === "string" && Number.parseInt(extVersion.split(".")[0] ?? "0", 10) >= 7;
	const agentsOk = missing.length === 0 && (!isV7OrAbove || squadMissing.length === 0);
	const agentReason =
		missing.length > 0
			? `缺少核心子代理模板: ${missing.join(", ")}`
			: isV7OrAbove && squadMissing.length > 0
				? `缺少 5+1 专精小队子代理模板: ${squadMissing.join(", ")}`
				: "";

	return {
		ok: agentsOk,
		critical: false,
		dir: agentsDir,
		fujiang,
		nuwaVerifier,
		squad,
		squadMissing,
		missing,
		...(agentReason ? { reason: agentReason } : {}),
	};
}

export function checkToolchain() {
	const available: string[] = [];
	const missing: string[] = [];
	for (const tool of DOCTOR_PROBE_TOOLS) {
		if (resolveExecutable(tool)) {
			available.push(tool);
		} else {
			missing.push(tool);
		}
	}
	const hasBasic = available.includes("curl") || available.includes("python3");
	return {
		ok: hasBasic,
		critical: false,
		available,
		missing,
		...(hasBasic ? {} : { reason: "缺少基础网络/脚本工具 curl 与 python3" }),
	};
}

export function checkDockerSandbox(dockerBin: string, image: string, critical: boolean) {
	const binPath = resolveExecutable(dockerBin);
	if (!binPath) {
		return {
			ok: false,
			critical,
			available: false,
			daemonRunning: false,
			image,
			imagePresent: false,
			dockerBin,
			reason: `未找到 Docker 可执行文件: ${dockerBin}`,
		};
	}

	try {
		const info = spawnSync(binPath, ["info", "--format", "{{.ServerVersion}}"], {
			encoding: "utf8",
			timeout: 3000,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (info.error || info.status !== 0) {
			const msg = info.error?.message || (info.stderr ?? "").trim() || `docker info 退出码 ${info.status}`;
			return {
				ok: false,
				critical,
				available: false,
				daemonRunning: false,
				image,
				imagePresent: false,
				dockerBin: binPath,
				reason: msg,
			};
		}

		const serverVersion = (info.stdout ?? "").trim() || undefined;
		const inspect = spawnSync(binPath, ["image", "inspect", image], {
			encoding: "utf8",
			timeout: 3000,
			stdio: ["ignore", "pipe", "pipe"],
		});
		const imagePresent = !inspect.error && inspect.status === 0;
		const ok = imagePresent;

		return {
			ok,
			critical,
			available: true,
			daemonRunning: true,
			image,
			imagePresent,
			dockerBin: binPath,
			...(serverVersion ? { serverVersion } : {}),
			...(!imagePresent ? { reason: `Docker 运行中但本地缺少沙盒镜像 ${image}` } : {}),
		};
	} catch (err) {
		return {
			ok: false,
			critical,
			available: false,
			daemonRunning: false,
			image,
			imagePresent: false,
			dockerBin: binPath,
			reason: err instanceof Error ? err.message : String(err),
		};
	}
}

export function runDoctor(argv: string[]): never {
	let opts: DoctorParsedOptions;
	try {
		opts = parseDoctorArgs(argv);
	} catch (err) {
		logDoctorErr(err instanceof Error ? err.message : String(err));
		process.exit(2);
	}

	if (opts.help) {
		console.log(DOCTOR_HELP_TEXT.trimEnd());
		process.exit(0);
	}

	const agentHome = resolveAgentHome(opts.agentHome);

	// 1. 检查 bun
	const bunExplicit = opts.bunBin !== "bun";
	const runtimeExecPath = (process as unknown as { execPath?: string }).execPath ?? null;
	const bunPath = resolveExecutable(opts.bunBin) ?? (!bunExplicit ? runtimeExecPath : null);
	const bunVersion = bunPath
		? !bunExplicit && typeof Bun !== "undefined"
			? Bun.version
			: probeBinaryVersion(bunPath, ["--version"])
		: null;
	const bunCheck: DoctorCheckItem = {
		ok: Boolean(bunPath),
		critical: true,
		bin: opts.bunBin,
		path: bunPath,
		version: bunVersion,
		...(!bunPath ? { reason: `未找到 bun 可执行文件: ${opts.bunBin}` } : {}),
	};

	// 2. 检查 omp
	const ompPath = resolveExecutable(opts.ompBin);
	const ompVersion = ompPath ? probeBinaryVersion(ompPath, ["--version"]) : null;
	const ompCheck: DoctorCheckItem = {
		ok: Boolean(ompPath),
		critical: true,
		bin: opts.ompBin,
		path: ompPath,
		version: ompVersion,
		...(!ompPath ? { reason: `未找到 omp 可执行文件: ${opts.ompBin}` } : {}),
	};

	// 3. 检查 12 工具与扩展模块
	const extensionCheck = checkExtensionInstallation(agentHome);

	// 4. 检查 KB 数据库与记录数
	const kbCheck = checkKnowledgeBase(agentHome, opts.kbDb, Boolean(opts.agentHome));

	// 5. 检查子代理模板（v7+ 校验全部 6 个 5+1 专精小队模板）
	const agentsCheck = checkAgentTemplates(agentHome, extensionCheck.version);

	// 6. 检查本地工具链
	const toolchainCheck = checkToolchain();

	// 7. 检查 Docker 沙盒可用性
	const dockerCheck = checkDockerSandbox(
		opts.dockerBin,
		opts.sandboxImage,
		opts.sandbox === "docker" || opts.sandbox === "sidecar",
	);

	// 8. 短超时安全探活 gh CLI
	const ghCheck = checkGhCliProbe(opts.ghBin, Boolean(opts.ghExplicit || opts.checkGhAuth));

	const checks: Record<string, DoctorCheckItem> = {
		bun: bunCheck,
		omp: ompCheck,
		extension: extensionCheck,
		kb: kbCheck,
		agents: agentsCheck,
		toolchain: toolchainCheck,
		docker: dockerCheck,
		gh: ghCheck,
	};

	const allEntries = Object.entries(checks);
	const criticalEntries = allEntries.filter(([, c]) => c.critical);
	const criticalPassed = criticalEntries.filter(([, c]) => c.ok).length;
	const criticalFailed = criticalEntries.filter(([, c]) => !c.ok).map(([k]) => k);
	const warnings: string[] = [];

	if (extensionCheck.conflicts.length > 0) {
		warnings.push(`检测到冲突扩展目录: ${extensionCheck.conflicts.join(", ")}`);
	}
	for (const [name, c] of allEntries) {
		if (!c.critical && !c.ok && c.reason) {
			warnings.push(`${name}: ${c.reason}`);
		}
	}

	const overallOk = criticalFailed.length === 0;
	const exitCode = overallOk ? 0 : 1;

	const report = {
		ok: overallOk,
		exitCode,
		checkedAt: new Date().toISOString(),
		agentHome,
		checks,
		summary: {
			criticalPassed,
			criticalTotal: criticalEntries.length,
			criticalFailed,
			warnings,
		},
	};

	if (opts.json) {
		console.log(JSON.stringify(report, null, 2));
		process.exit(exitCode);
	}

	const badge = (c: { ok: boolean; critical: boolean }): string =>
		c.ok ? "[OK]" : c.critical ? "[FAIL]" : "[WARN]";
	const lines = [
		`女娲环境健康体检 (nuwa-autonomous doctor)`,
		`Agent Home: ${agentHome}`,
		`------------------------------------------------------------`,
		`${badge(bunCheck)} bun: ${bunCheck.ok ? `${bunCheck.version ?? "ok"} (${bunCheck.path})` : bunCheck.reason}`,
		`${badge(ompCheck)} omp: ${ompCheck.ok ? `${ompCheck.version ?? "ok"} (${ompCheck.path})` : ompCheck.reason}`,
		`${badge(extensionCheck)} 扩展与工具: ${
			extensionCheck.ok
				? `v${extensionCheck.version ?? "?"} · 工具 ${extensionCheck.toolsCount}/${extensionCheck.toolsRequired} · 核心模块 ${extensionCheck.coreModulesFound.length}/${extensionCheck.coreModulesFound.length + extensionCheck.coreModulesMissing.length} · v4模块 ${extensionCheck.v4ModulesFound.length}/${V4_EXT_MODULES.length} · v5模块 ${extensionCheck.v5ModulesFound.length}/${V5_EXT_MODULES.length} · v6模块 ${extensionCheck.v6ModulesFound.length}/${V6_EXT_MODULES.length} · v7模块 ${extensionCheck.v7ModulesFound.length}/${V7_EXT_MODULES.length}`
				: extensionCheck.reason
		}`,
		`${badge(kbCheck)} 知识库 KB: ${
			kbCheck.exists
				? `${kbCheck.path} (总记录 ${kbCheck.totalRecords}；${Object.entries(kbCheck.counts)
						.map(([k, v]) => `${k}=${v}`)
						.join(", ") || "无表"})`
				: kbCheck.reason
		}`,
		`${badge(agentsCheck)} 子代理模板: 5+1专精小队 ${SQUAD_AGENT_FILES.length - agentsCheck.squadMissing.length}/${SQUAD_AGENT_FILES.length}${agentsCheck.reason ? ` (${agentsCheck.reason})` : ` (就绪: ${agentsCheck.dir})`}`,
		`${badge(toolchainCheck)} 本地工具链: 可用 ${toolchainCheck.available.length}/${DOCTOR_PROBE_TOOLS.length} (${toolchainCheck.available.join(", ") || "无"})${
			toolchainCheck.missing.length ? ` | 缺失: ${toolchainCheck.missing.join(", ")}` : ""
		}`,
		`${badge(dockerCheck)} Docker 沙盒: ${
			dockerCheck.ok
				? `就绪 (daemon ${dockerCheck.serverVersion ?? "ok"}, 镜像 ${dockerCheck.image})`
				: dockerCheck.reason
		}`,
		`------------------------------------------------------------`,
		overallOk
			? `体检结论: 核心依赖就绪 (${criticalPassed}/${criticalEntries.length})${warnings.length ? `，存在 ${warnings.length} 项非阻断提醒` : ""}。`
			: `体检结论: 缺失核心依赖 (${criticalFailed.join(", ")})，请先修复后再运行。`,
	];
	console.log(lines.join("\n"));
	process.exit(exitCode);
}

// ============================================================================
// 守护器只读状态探测、网络环境构建、预算核算与脱敏 Webhook 投递辅助
// ============================================================================

export function buildUnifiedNetworkEnvDaemon(
	egressUrl?: string,
	allowedHosts: string[] = [],
	netOpts: { modelProxy?: string; extraNoProxy?: string | string[] } = {},
): Record<string, string> {
	const cleanProxy = String(egressUrl ?? "").trim();
	const rawModelProxy = String(netOpts?.modelProxy ?? "").trim();
	const modelProxyDirect = /^(?:direct|none)$/i.test(rawModelProxy);
	const cleanModelProxy = rawModelProxy && !modelProxyDirect ? rawModelProxy : "";
	const isSocksProxy = Boolean(cleanProxy && /^socks/i.test(cleanProxy));
	const ghSec = String(getGhHttpTimeoutSec());
	const noProxySet = new Set(["127.0.0.1", "localhost", "::1"]);
	if (cleanProxy) {
		try {
			const u = new URL(cleanProxy);
			const h = u.hostname.toLowerCase();
			if (h === "host.docker.internal" || h === "127.0.0.1" || h === "localhost" || h === "::1") {
				noProxySet.add(h);
			}
		} catch {
			/* ignore */
		}
	}
	const extraNoProxy = Array.isArray(netOpts?.extraNoProxy)
		? netOpts.extraNoProxy
		: String(netOpts?.extraNoProxy ?? "")
				.split(",")
				.map((s) => s.trim())
				.filter(Boolean);
	for (const item of extraNoProxy) {
		const token = String(item ?? "").trim().toLowerCase();
		if (token && !/[\r\n\s,]/.test(token)) {
			noProxySet.add(token);
		}
	}
	const noProxy = [...noProxySet].join(",");
	const out: Record<string, string> = {
		GH_HTTP_TIMEOUT: ghSec,
		GIT_TERMINAL_PROMPT: "0",
		GIT_HTTP_LOW_SPEED_LIMIT: "1",
		GIT_HTTP_LOW_SPEED_TIME: ghSec,
		NO_PROXY: noProxy,
		no_proxy: noProxy,
	};
	const httpProxyForSdk = cleanModelProxy
		? cleanModelProxy
		: !modelProxyDirect && cleanProxy && !isSocksProxy
			? cleanProxy
			: "";
	if (httpProxyForSdk) {
		out.HTTP_PROXY = httpProxyForSdk;
		out.http_proxy = httpProxyForSdk;
		out.HTTPS_PROXY = httpProxyForSdk;
		out.https_proxy = httpProxyForSdk;
	}
	if (cleanProxy) {
		out.NUWA_EGRESS_PROXY = cleanProxy;
		out.NUWA_EGRESS = cleanProxy;
		if (isSocksProxy) {
			out.ALL_PROXY = cleanProxy;
			out.all_proxy = cleanProxy;
		}
	}
	const cleanHosts = [...new Set(allowedHosts.map((h) => String(h ?? "").trim().toLowerCase()).filter(Boolean))];
	if (cleanHosts.length > 0) {
		out.NUWA_SCOPE_ALLOW_HOSTS = cleanHosts.join(",");
	}
	return out;
}

export function sqliteDbPathDaemon(root: string): string {
	return join(root, ".nuwa", "nuwa.db");
}

export function resolveStorageBackendDaemon(root: string): "json" | "sqlite" | "dual" {
	const raw = String(process.env.NUWA_STORAGE_BACKEND ?? "").trim().toLowerCase();
	if (raw === "json" || raw === "sqlite" || raw === "dual") return raw;
	const dbFile = sqliteDbPathDaemon(root);
	if (existsSync(dbFile)) {
		try {
			if (statSync(dbFile).size > 0) return "sqlite";
		} catch {
			/* ignore */
		}
	}
	return "json";
}

export function readSqliteStateDaemon(root: string): Record<string, any> | null {
	const dbFile = sqliteDbPathDaemon(root);
	if (!existsSync(dbFile)) return null;
	let db: Database | null = null;
	try {
		db = openReadonlyKbDb(dbFile);

		const metaRows = db
			.query("SELECT key, value FROM meta WHERE key IN ('project_json', 'runtime_json')")
			.all() as Array<{ key?: string; value?: string }>;
		let project: Record<string, any> | null = null;
		let runtime: Record<string, any> = {};
		for (const row of metaRows) {
			if (row?.key === "project_json" && typeof row.value === "string") {
				project = JSON.parse(row.value);
			} else if (row?.key === "runtime_json" && typeof row.value === "string") {
				runtime = JSON.parse(row.value);
			}
		}
		if (!project || typeof project !== "object") return null;

		const facts: Record<string, Record<string, unknown>> = {};
		for (const row of db.query("SELECT id, kind, verify_stage FROM facts").all() as Array<Record<string, any>>) {
			if (!row?.id) continue;
			facts[String(row.id)] = {
				id: String(row.id),
				kind: String(row.kind ?? "note"),
				...(row.verify_stage ? { verifyStage: String(row.verify_stage) } : {}),
			};
		}

		const intents: Record<string, Record<string, unknown>> = {};
		for (const row of db.query("SELECT id, status FROM intents").all() as Array<Record<string, any>>) {
			if (!row?.id) continue;
			intents[String(row.id)] = {
				id: String(row.id),
				status: String(row.status ?? "open"),
			};
		}

		return { project, runtime, facts, intents };
	} catch {
		return null;
	} finally {
		try {
			db?.close();
		} catch {
			/* ignore */
		}
	}
}

export function readDiskState(root: string): Record<string, any> | null {
	const backend = resolveStorageBackendDaemon(root);
	if (backend === "sqlite" || backend === "dual") {
		const sqliteState = readSqliteStateDaemon(root);
		if (sqliteState) return sqliteState;
	}
	const p = join(root, ".nuwa", "state.json");
	if (existsSync(p)) {
		try {
			const parsed = JSON.parse(readFileSync(p, "utf8")) as Record<string, any>;
			if (parsed && typeof parsed === "object" && parsed.project) return parsed;
		} catch {
			/* ignore */
		}
	}
	return readSqliteStateDaemon(root);
}

export function maskWebhookUrl(rawUrl?: string): string {
	const text = String(rawUrl ?? "").trim();
	if (!text) return "";
	try {
		const u = new URL(text);
		const origin = `${u.protocol}//${u.host}`;
		const segs = u.pathname.split("/").filter(Boolean);
		if (segs.length >= 2) {
			return `${origin}/${segs[0]}/***`;
		}
		if (segs.length === 1) {
			const seg = segs[0]!;
			const looksSecret = seg.length >= 16 || /[0-9a-f]{10,}|[A-Za-z0-9_-]{20,}/i.test(seg);
			const pathPart = looksSecret ? "/***" : `/${seg}`;
			return u.search ? `${origin}${pathPart}?***` : `${origin}${pathPart}`;
		}
		return u.search ? `${origin}/?***` : origin;
	} catch {
		return "***";
	}
}

export function collectVaultSecretStrings(root?: string): string[] {
	if (!root) return [];
	const vaultPath = join(root, ".nuwa", "sessions", "vault.json");
	if (!existsSync(vaultPath)) return [];
	try {
		const parsed = JSON.parse(readFileSync(vaultPath, "utf8")) as { roles?: Record<string, Record<string, any>> };
		const roles = parsed?.roles;
		if (!roles || typeof roles !== "object") return [];
		const secrets = new Set<string>();
		const pushVal = (v: unknown, minLen = 4) => {
			const s = String(v ?? "").trim();
			if (s.length >= minLen) secrets.add(s);
		};
		for (const entry of Object.values(roles)) {
			if (!entry || typeof entry !== "object") continue;
			if (typeof entry.bearer === "string") {
				pushVal(entry.bearer, 4);
				const bare = entry.bearer.replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
				if (bare) pushVal(bare, 4);
			}
			if (typeof entry.cookie === "string") {
				pushVal(entry.cookie, 4);
				for (const part of entry.cookie.split(";")) {
					const eq = part.indexOf("=");
					if (eq > 0) pushVal(part.slice(eq + 1), 4);
				}
			}
			if (typeof entry.password === "string") {
				pushVal(entry.password, 3);
				if (typeof entry.username === "string" && entry.username.trim()) {
					pushVal(Buffer.from(`${entry.username}:${entry.password}`, "utf8").toString("base64"), 4);
				}
			}
			if (entry.headers && typeof entry.headers === "object") {
				for (const [hk, hv] of Object.entries(entry.headers)) {
					if (/(?:auth|token|key|secret|cookie|session|jwt|csrf|pass|cred|bearer)/i.test(hk)) {
						pushVal(hv, 4);
						const bare = String(hv ?? "").replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
						if (bare) pushVal(bare, 4);
					}
				}
			}
		}
		return [...secrets].sort((a, b) => b.length - a.length);
	} catch {
		return [];
	}
}

export function redactSecretPatterns(text: string, vaultSecrets: string[] = []): string {
	let out = String(text ?? "");
	if (!out) return out;
	for (const secret of vaultSecrets) {
		if (secret && out.includes(secret)) {
			out = out.split(secret).join("***");
		}
	}
	out = out
		.replace(/(Authorization\s*:\s*(?:Bearer|Token|Basic|JWT)\s+)[^\s'",;\r\n]+/gi, "$1***")
		.replace(/\b(Bearer|Token|Basic|JWT)\s+[A-Za-z0-9._~+/=-]{6,}/gi, "$1 ***")
		.replace(/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g, "eyJ***")
		.replace(/\b(?:sk-[A-Za-z0-9_-]{8,}|ak_[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{16,})\b/g, "***")
		.replace(
			/\b((?:password|passwd|pass|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token|cookie)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;'"\r\n]+)/gi,
			"$1***",
		)
		.replace(/(https?:\/\/)[^/\s@]+:[^/\s@]+@/gi, "$1***@")
		.replace(/([?&](?:token|key|secret|auth|sig|password|pass|api_key)=)[^&\s]+/gi, "$1***");
	return out;
}

export function redactWebhookPayload(
	value: unknown,
	root?: string,
	vaultSecrets: string[] = collectVaultSecretStrings(root),
): unknown {
	if (typeof value === "string") {
		return redactSecretPatterns(value, vaultSecrets);
	}
	if (Array.isArray(value)) {
		return value.map((item) => redactWebhookPayload(item, root, vaultSecrets));
	}
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			if (v === undefined) continue;
			out[k] = redactWebhookPayload(v, root, vaultSecrets);
		}
		return out;
	}
	return value;
}

export function appendWebhookDeadletter(root: string, entry: Record<string, unknown>): void {
	try {
		const dir = join(root, ".nuwa");
		mkdirSync(dir, { recursive: true });
		const dlPath = join(dir, "webhook-deadletter.jsonl");
		appendFileSync(dlPath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
		try {
			chmodSync(dlPath, 0o600);
		} catch {
			/* 非 POSIX 文件系统忽略 */
		}
	} catch {
		/* 写死信队列失败不崩溃守护进程 */
	}
}

export async function sendDaemonWebhook(
	webhookUrl: string | undefined,
	root: string,
	payload: unknown,
	opts: { timeoutMs?: number; retryDelaysMs?: number[] } = {},
) {
	const targetUrl = String(webhookUrl ?? "").trim();
	if (!targetUrl) return { ok: false, skipped: true };

	const redactedPayload = redactWebhookPayload(payload, root);
	const body = JSON.stringify(redactedPayload);
	const maskedUrl = maskWebhookUrl(targetUrl);
	const timeoutMs =
		typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
			? opts.timeoutMs
			: WEBHOOK_TIMEOUT_MS;

	let retryDelays = [100, 250];
	if (Array.isArray(opts.retryDelaysMs)) {
		retryDelays = opts.retryDelaysMs;
	} else {
		const envRetry = (process.env.NUWA_WEBHOOK_RETRY_MS ?? "").trim();
		if (envRetry) {
			const parsed = Number(envRetry);
			if (Number.isFinite(parsed) && parsed >= 0) {
				retryDelays = [parsed, parsed * 2];
			}
		}
	}

	let lastError = "unknown webhook error";
	for (let attempt = 1; attempt <= WEBHOOK_MAX_ATTEMPTS; attempt += 1) {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const res = await fetch(targetUrl, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					"User-Agent": "pi-nuwa-autonomous/5.0",
				},
				body,
				signal: controller.signal,
			});
			if (res.ok) {
				return { ok: true, status: res.status, attempts: attempt };
			}
			lastError = `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ""}`;
		} catch (err) {
			const rawMsg = err instanceof Error ? err.message : String(err);
			lastError = rawMsg.includes(targetUrl) ? rawMsg.split(targetUrl).join(maskedUrl) : rawMsg;
		} finally {
			clearTimeout(timer);
		}

		if (attempt < WEBHOOK_MAX_ATTEMPTS) {
			const delayMs = retryDelays[attempt - 1] ?? retryDelays[retryDelays.length - 1] ?? 100;
			if (delayMs > 0) {
				await Bun.sleep(delayMs);
			}
		}
	}

	appendWebhookDeadletter(root, {
		ts: new Date().toISOString(),
		url: maskedUrl,
		attempts: WEBHOOK_MAX_ATTEMPTS,
		error: redactSecretPatterns(lastError),
		payload: redactedPayload,
	});
	logDoctorErr(
		`Webhook 推送失败 (${maskedUrl}，已重试 ${WEBHOOK_MAX_ATTEMPTS} 次，已写入 .nuwa/webhook-deadletter.jsonl): ${redactSecretPatterns(lastError)}`,
	);
	return { ok: false, attempts: WEBHOOK_MAX_ATTEMPTS, error: lastError, deadlettered: true };
}

export function computeCumulativeBudget(
	state: Record<string, any> | null | undefined,
	opts: { usdPer1mTokens: number },
): { cumulativeTokens: number; cumulativeUsd: number } {
	const rt = state?.runtime ?? {};
	const baseTokens = Number(rt.totalTokens ?? 0);
	const curTokens = Number(rt.tokens ?? 0);
	const cumulativeTokens =
		(Number.isFinite(baseTokens) && baseTokens > 0 ? baseTokens : 0) +
		(Number.isFinite(curTokens) && curTokens > 0 ? curTokens : 0);
	const recordedUsd = Number(rt.totalCostUsd ?? 0);
	const cumulativeUsd =
		Number.isFinite(recordedUsd) && recordedUsd > 0
			? recordedUsd
			: (cumulativeTokens / 1_000_000) * opts.usdPer1mTokens;
	return { cumulativeTokens, cumulativeUsd };
}

export function checkBudgetCap(
	state: Record<string, any> | null | undefined,
	opts: { maxTotalTokens: number; maxUsd: number; usdPer1mTokens: number },
): {
	exceeded: boolean;
	kind?: "tokens" | "usd";
	limit?: number;
	cumulativeTokens: number;
	cumulativeUsd: number;
	reason?: string;
} {
	if (!state) return { exceeded: false, cumulativeTokens: 0, cumulativeUsd: 0 };
	const { cumulativeTokens, cumulativeUsd } = computeCumulativeBudget(state, opts);
	if (opts.maxTotalTokens > 0 && cumulativeTokens >= opts.maxTotalTokens) {
		return {
			exceeded: true,
			kind: "tokens",
			limit: opts.maxTotalTokens,
			cumulativeTokens,
			cumulativeUsd,
			reason: `跨世代累计 Token 已达上限 (${cumulativeTokens} >= ${opts.maxTotalTokens})`,
		};
	}
	if (opts.maxUsd > 0 && cumulativeUsd >= opts.maxUsd) {
		return {
			exceeded: true,
			kind: "usd",
			limit: opts.maxUsd,
			cumulativeTokens,
			cumulativeUsd,
			reason: `跨世代累计费用已达上限 ($${cumulativeUsd.toFixed(4)} >= $${opts.maxUsd.toFixed(4)})`,
		};
	}
	return { exceeded: false, cumulativeTokens, cumulativeUsd };
}

export function buildWebhookEventPayload(
	event: string,
	opts: { target: string; mode: string; usdPer1mTokens: number },
	state: Record<string, any> | null | undefined,
	gen: number,
	extra: Record<string, unknown> = {},
): Record<string, unknown> {
	const { cumulativeTokens, cumulativeUsd } = computeCumulativeBudget(state, opts);
	const facts = Object.values(state?.facts ?? {}) as Array<Record<string, any>>;
	const flags = facts.filter((f) => f?.kind === "flag").length;
	const confirmedVulns = facts.filter(
		(f) => f?.kind === "vuln" && f?.verifyStage !== "candidate" && f?.verifyStage !== "rejected",
	).length;
	return {
		event,
		ts: new Date().toISOString(),
		projectId: state?.project?.id ?? "",
		target: state?.project?.url || state?.project?.target || opts.target,
		mode: state?.project?.mode || opts.mode,
		phase: state?.project?.phase || "recon",
		status: state?.project?.status || "active",
		generation: gen,
		stateGeneration: Number(state?.runtime?.generation ?? gen),
		cumulativeTokens,
		cumulativeUsd: Number(cumulativeUsd.toFixed(6)),
		factsCount: facts.length,
		flags,
		confirmedVulns,
		...extra,
	};
}
