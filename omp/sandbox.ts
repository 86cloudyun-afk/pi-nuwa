/**
 * 女娲 v4.0 零信任 Docker 容器沙盒隔离模块（Sandbox）。
 *
 * 零信任安全红线：
 * 1. 严禁挂载 `$HOME`、`~/.ssh`、`~/.omp`、`~/.pi`、`~/.aws`、`docker.sock` 或宿主机根目录。
 * 2. 仅允许挂载唯一项目产物工作区 `/tmp/nuwa/<projectId>`（强制校验单段标识符防路径穿越）。
 * 3. 严禁透传宿主机环境变量与 API Key / Token / Secret，仅注入最小白名单元数据。
 * 4. 强制开启 `--cap-drop=ALL`、`--security-opt=no-new-privileges`、`--pids-limit=256`、
 *    只读根文件系统（`--read-only`）以及内存与 CPU 硬限额，禁止 `--privileged` 与 `--network=host`。
 * 5. 结合 `ScopePolicy` 生成容器侧外连白名单前置校验脚本，越界目标在容器内执行前即被拦截（exit 126）。
 *
 * 约束：仅使用 `import type` 引用 `./types`，严禁运行时 import `./nuwa`。
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { ScopePolicy } from "./types";

export type SandboxMode = "none" | "docker";
export type SandboxNetworkMode = "bridge" | "none";

export interface SandboxConfig {
	mode: SandboxMode;
	image: string;
	memory: string;
	cpus: string;
	pidsLimit: number;
	network: SandboxNetworkMode;
	dockerBin: string;
}

export interface DockerProbeOptions {
	dockerBin?: string;
	image?: string;
	timeoutMs?: number;
}

export interface DockerProbeResult {
	available: boolean;
	daemonRunning: boolean;
	imagePresent: boolean;
	dockerBin: string;
	image: string;
	serverVersion?: string;
	reason?: string;
}

export interface BuildDockerRunArgsOptions {
	projectId: string;
	command: string;
	scope?: ScopePolicy;
	config?: Partial<SandboxConfig>;
	extraEnv?: Record<string, string>;
	ensureWorkdir?: boolean;
}

export interface WrapSandboxOptions {
	projectId: string;
	scope?: ScopePolicy;
	config?: Partial<SandboxConfig>;
	extraEnv?: Record<string, string>;
	ensureWorkdir?: boolean;
}

export const DEFAULT_SANDBOX_IMAGE = "nuwa-sandbox:latest";
export const DEFAULT_SANDBOX_MEMORY = "512m";
export const DEFAULT_SANDBOX_CPUS = "1";
export const DEFAULT_SANDBOX_PIDS_LIMIT = 256;

const SAFE_PROJECT_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const SAFE_IMAGE_RE = /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,255}$/;
const SAFE_MEMORY_RE = /^\d+(?:\.\d+)?[bkmgtBKMGT]?$/;
const SAFE_ENV_KEY_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

const SENSITIVE_ENV_KEY_RE =
	/(?:KEY|TOKEN|SECRET|PASS|PWD|AUTH|CRED|COOKIE|PRIVATE|SESSION|SIGN|CERT|AWS|GCP|AZURE|OPENAI|ANTHROPIC|GEMINI|GOOGLE|CLAUDE|GITHUB|GITLAB|SSH|DOCKER|NPM|PIP|OMP|PI_AGENT)/i;

/** 仅允许容器自身运行与外连白名单策略使用的内置非敏感环境变量白名单。 */
const INTERNAL_SAFE_ENV_KEYS = new Set([
	"NUWA_SANDBOX",
	"NUWA_PROJECT_ID",
	"NUWA_OUT",
	"HOME",
	"TMPDIR",
	"NUWA_SCOPE_ALLOW_HOSTS",
	"NUWA_SCOPE_ALLOW_CIDRS",
	"NUWA_SCOPE_DENY_HOSTS",
	"NUWA_SCOPE_ALLOW_SUBDOMAINS",
	"NUWA_SCOPE_ALLOW_PRIVATE",
]);

function parsePositiveInt(raw: string | undefined, fallback: number, min = 16, max = 4096): number {
	const trimmed = String(raw ?? "").trim();
	if (!trimmed) return fallback;
	const n = Number(trimmed);
	if (!Number.isFinite(n) || !Number.isInteger(n) || n < min || n > max) return fallback;
	return n;
}

function parseMemoryLimit(raw: string | undefined, fallback = DEFAULT_SANDBOX_MEMORY): string {
	const s = String(raw ?? "").trim();
	if (!s || !SAFE_MEMORY_RE.test(s)) return fallback;
	return s.toLowerCase();
}

function parseCpuLimit(raw: string | undefined, fallback = DEFAULT_SANDBOX_CPUS): string {
	const s = String(raw ?? "").trim();
	if (!s) return fallback;
	const n = Number(s);
	if (!Number.isFinite(n) || n <= 0 || n > 64) return fallback;
	return String(n);
}

function parseImageName(raw: string | undefined, fallback = DEFAULT_SANDBOX_IMAGE): string {
	const s = String(raw ?? "").trim();
	if (!s || !SAFE_IMAGE_RE.test(s) || s.includes("..")) return fallback;
	return s;
}

function parseNetworkMode(raw: string | undefined): SandboxNetworkMode {
	const norm = String(raw ?? "").trim().toLowerCase();
	if (norm === "none") return "none";
	// 零信任约束：强制禁止 host 网络模式，其余统一收口为 bridge
	return "bridge";
}

function assertSafeProjectId(projectId: string): string {
	const safe = String(projectId ?? "").trim();
	if (!safe || safe === "." || safe === ".." || /[\\/]|\.\./.test(safe) || !SAFE_PROJECT_ID_RE.test(safe)) {
		throw new Error(`非法 projectId: ${JSON.stringify(projectId)}（仅允许单段安全标识符，禁止路径穿越）`);
	}
	return safe;
}

function shellQuote(arg: string): string {
	return `'${String(arg).replace(/'/g, `'\\''`)}'`;
}

/**
 * 从环境变量读取沙盒隔离配置（默认关闭 `mode="none"`）。
 */
export function readSandboxConfig(env: Record<string, string | undefined> = process.env): SandboxConfig {
	const rawMode = String(env.NUWA_SANDBOX ?? "none").trim().toLowerCase();
	const mode: SandboxMode = rawMode === "docker" ? "docker" : "none";
	const dockerBinRaw = String(env.NUWA_DOCKER_BIN ?? "docker").trim();
	const dockerBin = dockerBinRaw && !/[\r\n;&|`$]/.test(dockerBinRaw) ? dockerBinRaw : "docker";

	return {
		mode,
		image: parseImageName(env.NUWA_SANDBOX_IMAGE, DEFAULT_SANDBOX_IMAGE),
		memory: parseMemoryLimit(env.NUWA_SANDBOX_MEMORY, DEFAULT_SANDBOX_MEMORY),
		cpus: parseCpuLimit(env.NUWA_SANDBOX_CPUS, DEFAULT_SANDBOX_CPUS),
		pidsLimit: parsePositiveInt(env.NUWA_SANDBOX_PIDS_LIMIT, DEFAULT_SANDBOX_PIDS_LIMIT),
		network: parseNetworkMode(env.NUWA_SANDBOX_NETWORK),
		dockerBin,
	};
}

function mergeConfig(overrides?: Partial<SandboxConfig>): SandboxConfig {
	const base = readSandboxConfig();
	if (!overrides) return base;
	return {
		mode: overrides.mode === "docker" ? "docker" : overrides.mode === "none" ? "none" : base.mode,
		image: overrides.image !== undefined ? parseImageName(overrides.image, base.image) : base.image,
		memory: overrides.memory !== undefined ? parseMemoryLimit(overrides.memory, base.memory) : base.memory,
		cpus: overrides.cpus !== undefined ? parseCpuLimit(overrides.cpus, base.cpus) : base.cpus,
		pidsLimit:
			overrides.pidsLimit !== undefined
				? parsePositiveInt(String(overrides.pidsLimit), base.pidsLimit)
				: base.pidsLimit,
		network: overrides.network !== undefined ? parseNetworkMode(overrides.network) : base.network,
		dockerBin:
			overrides.dockerBin && !/[\r\n;&|`$]/.test(overrides.dockerBin)
				? overrides.dockerBin.trim()
				: base.dockerBin,
	};
}

/**
 * 探测本机 Docker CLI、守护进程与目标沙盒镜像是否就绪。
 * 全程捕获异常，不向外抛错。
 */
export function probeDockerAvailable(opts: DockerProbeOptions = {}): DockerProbeResult {
	const cfg = readSandboxConfig();
	const dockerBin = (opts.dockerBin ?? cfg.dockerBin).trim() || "docker";
	const image = parseImageName(opts.image, cfg.image);
	const timeoutMs =
		typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
			? Math.floor(opts.timeoutMs)
			: 3000;

	try {
		const info = spawnSync(dockerBin, ["info", "--format", "{{.ServerVersion}}"], {
			encoding: "utf8",
			timeout: timeoutMs,
			stdio: ["ignore", "pipe", "pipe"],
		});

		if (info.error) {
			const code = (info.error as NodeJS.ErrnoException).code;
			return {
				available: false,
				daemonRunning: false,
				imagePresent: false,
				dockerBin,
				image,
				reason: code === "ENOENT" ? `未找到 Docker 可执行文件: ${dockerBin}` : info.error.message,
			};
		}

		if (info.status !== 0) {
			const stderr = (info.stderr ?? "").trim();
			return {
				available: false,
				daemonRunning: false,
				imagePresent: false,
				dockerBin,
				image,
				reason: stderr || `docker info 退出码 ${info.status}`,
			};
		}

		const serverVersion = (info.stdout ?? "").trim() || undefined;
		const inspect = spawnSync(dockerBin, ["image", "inspect", image], {
			encoding: "utf8",
			timeout: timeoutMs,
			stdio: ["ignore", "pipe", "pipe"],
		});
		const imagePresent = !inspect.error && inspect.status === 0;

		return {
			available: true,
			daemonRunning: true,
			imagePresent,
			dockerBin,
			image,
			...(serverVersion ? { serverVersion } : {}),
			...(!imagePresent ? { reason: `Docker 守护进程就绪，但本地缺少镜像 ${image}` } : {}),
		};
	} catch (err) {
		return {
			available: false,
			daemonRunning: false,
			imagePresent: false,
			dockerBin,
			image,
			reason: err instanceof Error ? err.message : String(err),
		};
	}
}

function collectHostSecretValues(): Set<string> {
	const secrets = new Set<string>();
	for (const [k, v] of Object.entries(process.env)) {
		if (!v || v.length < 8) continue;
		if (SENSITIVE_ENV_KEY_RE.test(k)) {
			secrets.add(v);
		}
	}
	return secrets;
}

function filterSafeExtraEnv(extraEnv?: Record<string, string>): Array<[string, string]> {
	if (!extraEnv || typeof extraEnv !== "object") return [];
	const hostSecrets = collectHostSecretValues();
	const out: Array<[string, string]> = [];
	for (const [rawK, rawV] of Object.entries(extraEnv)) {
		const k = String(rawK ?? "").trim();
		const v = String(rawV ?? "").replace(/[\r\n]+/g, " ");
		if (!SAFE_ENV_KEY_RE.test(k)) continue;
		if (SENSITIVE_ENV_KEY_RE.test(k)) continue;
		if (hostSecrets.has(v)) continue;
		out.push([k, v]);
	}
	return out;
}

/**
 * 生成容器侧 ScopePolicy 外连白名单前置校验脚本（依赖容器内置 python3，缺失时平滑退化）。
 *
 * 读取环境变量 `NUWA_SCOPE_ALLOW_HOSTS`、`NUWA_SCOPE_ALLOW_CIDRS`、`NUWA_SCOPE_DENY_HOSTS`、
 * `NUWA_SCOPE_ALLOW_SUBDOMAINS`、`NUWA_SCOPE_ALLOW_PRIVATE`，对 `$1` 命令中的网络目标逐一核验；
 * 任一目标越界立即退出 126，阻止命令实际执行。
 */
export function buildContainerScopePreflightScript(): string {
	return [
		`if command -v python3 >/dev/null 2>&1; then`,
		`python3 - "$1" <<'NUWA_SCOPE_PY'`,
		`import ipaddress, os, re, shlex, sys, urllib.parse`,
		`cmd = sys.argv[1] if len(sys.argv) > 1 else ""`,
		`allow_hosts = [x.strip().lower().rstrip(".") for x in os.environ.get("NUWA_SCOPE_ALLOW_HOSTS", "").split(",") if x.strip()]`,
		`allow_cidrs = [x.strip() for x in os.environ.get("NUWA_SCOPE_ALLOW_CIDRS", "").split(",") if x.strip()]`,
		`deny_hosts = [x.strip().lower().rstrip(".") for x in os.environ.get("NUWA_SCOPE_DENY_HOSTS", "").split(",") if x.strip()]`,
		`allow_sub = os.environ.get("NUWA_SCOPE_ALLOW_SUBDOMAINS", "0") == "1"`,
		`allow_priv = os.environ.get("NUWA_SCOPE_ALLOW_PRIVATE", "0") == "1"`,
		`def parse_ip(h):`,
		`    try: return ipaddress.ip_address(h)`,
		`    except ValueError: return None`,
		`def parse_net(c):`,
		`    try: return ipaddress.ip_network(c, strict=False)`,
		`    except ValueError: return None`,
		`def is_loopback(h):`,
		`    if h == "localhost" or h.endswith(".localhost"): return True`,
		`    ip = parse_ip(h)`,
		`    return bool(ip and (ip.is_loopback or str(ip) == "0.0.0.0"))`,
		`def match_pat(h, pat):`,
		`    if pat == "*": return True`,
		`    if pat.startswith("*."):`,
		`        base = pat[2:]`,
		`        return bool(base) and h.endswith("." + base) and len(h) > len(base) + 1`,
		`    net = parse_net(pat) if "/" in pat else None`,
		`    if net is not None:`,
		`        tnet = parse_net(h) if "/" in h else None`,
		`        if tnet is not None: return tnet.version == net.version and tnet.subnet_of(net)`,
		`        tip = parse_ip(h)`,
		`        return tip is not None and tip.version == net.version and tip in net`,
		`    return h == pat`,
		`def in_scope(h):`,
		`    h = h.strip().strip("[]").lower().rstrip(".")`,
		`    if not h: return (True, "")`,
		`    for d in deny_hosts:`,
		`        if match_pat(h, d): return (False, f"命中黑名单 denyHosts({d})")`,
		`        if "/" not in h and "/" not in d and is_loopback(h) and is_loopback(d): return (False, f"回环被 denyHosts({d}) 禁止")`,
		`    if "/" not in h and is_loopback(h): return (True, "")`,
		`    tip = parse_ip(h)`,
		`    tnet = parse_net(h) if "/" in h else None`,
		`    for a in allow_hosts:`,
		`        if match_pat(h, a): return (True, "")`,
		`        if allow_sub and tip is None and tnet is None and not a.startswith("*.") and parse_ip(a) is None:`,
		`            if h.endswith("." + a) and len(h) > len(a) + 1: return (True, "")`,
		`    if tip is not None or tnet is not None:`,
		`        for c in allow_cidrs:`,
		`            if match_pat(h, c): return (True, "")`,
		`    if tip is not None and tip.is_private:`,
		`        if allow_priv: return (True, "")`,
		`        return (False, "私网地址未在白名单且 allowPrivateNetwork=false")`,
		`    return (False, f"不在授权白名单 allowHosts={','.join(allow_hosts) or '无'}")`,
		`targets = []`,
		`def add_t(x):`,
		`    x = (x or "").strip().strip("[]").lower().rstrip(".")`,
		`    if x and x not in ("255.255.255.255", "255.255.255.0", "255.255.0.0") and x not in targets:`,
		`        targets.append(x)`,
		`url_re = re.compile(r"\\b(?:https?|wss?|ftps?|s?ftp|ssh|ldaps?|rediss?|mysql|postgres(?:ql)?|mongodb)://[^\\s\\x27\\x22<>|;&)]+", re.I)`,
		`def repl_url(m):`,
		`    u = m.group(0).rstrip(".,;:!?")`,
		`    try:`,
		`        p = urllib.parse.urlparse(u)`,
		`        if p.hostname: add_t(p.hostname)`,
		`    except Exception: pass`,
		`    return " "`,
		`rest = url_re.sub(repl_url, cmd)`,
		`for m in re.finditer(r"--connect-to(?:\\s+|=)[\\x27\\x22]?[^:\\x27\\x22\\s]*:\\d*:(\\[[^\\]]+\\]|[^:\\x27\\x22\\s]+)(?::\\d+)?[\\x27\\x22]?", rest, re.I): add_t(m.group(1))`,
		`for m in re.finditer(r"--resolve(?:\\s+|=)[\\x27\\x22]?([^:\\x27\\x22\\s]+):\\d+:([^\\s\\x27\\x22]+)[\\x27\\x22]?", rest, re.I):`,
		`    if m.group(1) != "*": add_t(m.group(1))`,
		`    for a in m.group(2).split(","): add_t(a)`,
		`for m in re.finditer(r"/dev/(?:tcp|udp)/(\\[[^\\]]+\\]|[^/\\s\\x27\\x22;&|)]+)/\\d{1,5}", rest, re.I): add_t(m.group(1))`,
		`for m in re.finditer(r"(?:^|\\s)-connect\\s+[\\x27\\x22]?(\\[[^\\]]+\\]|[^\\s:\\x27\\x22]+)(?::\\d{1,5})?[\\x27\\x22]?", rest, re.I): add_t(m.group(1))`,
		`for m in re.finditer(r"\\b(?:create_connection|connect|connect_ex)\\s*\\(\\s*\\(\\s*[\\x27\\x22](\\[[^\\]]+\\]|[^\\x27\\x22]+)[\\x27\\x22]", rest): add_t(m.group(1))`,
		`for m in re.finditer(r"\\b(?:HTTPConnection|HTTPSConnection|Telnet|FTP|SMTP|getaddrinfo|gethostbyname)\\s*\\(\\s*[\\x27\\x22](\\[[^\\]]+\\]|[^\\x27\\x22]+)[\\x27\\x22]", rest): add_t(m.group(1))`,
		`for m in re.finditer(r"(?<![0-9a-zA-Z._-])((?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}(?:/(?:3[0-2]|[12]?\\d))?)(?![0-9a-zA-Z._-])", rest): add_t(m.group(1))`,
		`for m in re.finditer(r"\\[([0-9a-fA-F:]{2,45})\\](?::\\d{1,5})?", rest):`,
		`    if ":" in m.group(1): add_t(m.group(1))`,
		`net_cmds = {"curl", "wget", "nmap", "nc", "ncat", "netcat", "socat", "openssl", "ping", "dig", "host", "nslookup", "ssh", "scp", "ftp", "ffuf", "nuclei", "sqlmap", "httpx"}`,
		`skip_val_flags = {"-o", "--output", "-D", "--dump-header", "-H", "--header", "-d", "--data", "--data-raw", "-b", "-c", "-A", "-X", "-u", "-w", "-m", "-p", "-oN", "-oX", "-oG", "-oA", "-iL"}`,
		`dom_re = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,24}$", re.I)`,
		`file_exts = {"json", "jsonl", "txt", "log", "out", "err", "tmp", "headers", "html", "htm", "xml", "csv", "md", "py", "sh", "js", "ts", "yml", "yaml", "conf", "cfg", "db", "sqlite", "sqlite3", "pem", "crt", "key", "nmap"}`,
		`for seg in re.split(r"[;|&\\n]+", rest):`,
		`    try: toks = shlex.split(seg)`,
		`    except ValueError: toks = seg.split()`,
		`    if not toks: continue`,
		`    i = 0`,
		`    while i < len(toks) and ("=" in toks[i] or os.path.basename(toks[i]).lower() in ("env", "sudo", "command", "exec")): i += 1`,
		`    if i >= len(toks): continue`,
		`    cname = os.path.basename(toks[i]).lower()`,
		`    if cname not in net_cmds: continue`,
		`    j = i + 1`,
		`    while j < len(toks):`,
		`        t = toks[j]`,
		`        if t in skip_val_flags: j += 2; continue`,
		`        if t.startswith("-") or t.startswith("/") or t.startswith("./") or t.startswith("@"): j += 1; continue`,
		`        h = t.split("/")[0]`,
		`        h = re.sub(r":\\d{1,5}$", "", h)`,
		`        if dom_re.match(h) and h.rsplit(".", 1)[-1].lower() not in file_exts: add_t(h)`,
		`        j += 1`,
		`for t in targets:`,
		`    ok, reason = in_scope(t)`,
		`    if not ok:`,
		`        sys.stderr.write(f"nuwa-sandbox N-007: 容器侧外连白名单拦截 ({t}) — {reason}\\n")`,
		`        sys.exit(126)`,
		`NUWA_SCOPE_PY`,
		`rc=$?; [ "$rc" -eq 0 ] || exit "$rc"`,
		`fi`,
		`exec sh -c "$1"`,
	].join("\n");
}

function assertZeroTrustArgs(args: readonly string[], allowedMountPrefix: string): void {
	const home = homedir();
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		if (a === "--privileged" || a === "--pid=host" || a === "--ipc=host" || a === "--network=host" || a === "--net=host") {
			throw new Error(`零信任沙盒拦截高危 Docker 参数: ${a}`);
		}
		if (a === "-v" || a === "--volume" || a === "--mount") {
			const spec = args[i + 1] ?? "";
			const hostPart = spec.split(":")[0] ?? "";
			if (
				!hostPart.startsWith(allowedMountPrefix) ||
				hostPart.includes("..") ||
				spec.includes("docker.sock") ||
				spec.includes(".ssh") ||
				spec.includes(".omp") ||
				(home && home !== "/tmp" && hostPart.startsWith(home))
			) {
				throw new Error(`零信任沙盒拦截非法宿主机挂载: ${spec}`);
			}
		}
		if (a === "-e" || a === "--env") {
			const kv = args[i + 1] ?? "";
			const key = kv.split("=")[0] ?? "";
			if (!kv.includes("=")) {
				throw new Error(`零信任沙盒禁止裸透传宿主环境变量: ${key}`);
			}
			if (!INTERNAL_SAFE_ENV_KEYS.has(key) && SENSITIVE_ENV_KEY_RE.test(key)) {
				throw new Error(`零信任沙盒拦截敏感环境变量透传: ${key}`);
			}
		}
	}
}

/**
 * 构建零信任 Docker 容器运行参数数组（供 `spawn("docker", args)` 或包装器调用）。
 *
 * 强制约束：
 * - 仅挂载 `/tmp/nuwa/<projectId>:/tmp/nuwa/<projectId>:rw`；
 * - 开启 `--cap-drop=ALL`、`--security-opt=no-new-privileges`、`--pids-limit=256`、`--read-only`、内存与 CPU 限额；
 * - 严禁挂载 `$HOME`/`~/.ssh`/`~/.omp`/`docker.sock` 或透传宿主 API Key 环境变量；
 * - 当提供 `scope` 时自动注入容器侧外连白名单前置校验脚本。
 */
export function buildDockerRunArgs(opts: BuildDockerRunArgsOptions): string[] {
	const safeProjectId = assertSafeProjectId(opts.projectId);
	const command = String(opts.command ?? "");
	const cfg = mergeConfig(opts.config);
	const workDir = join("/tmp/nuwa", safeProjectId);

	if (opts.ensureWorkdir) {
		mkdirSync(workDir, { recursive: true, mode: 0o700 });
		try {
			chmodSync(workDir, 0o700);
		} catch {
			/* ignore */
		}
	}

	const args: string[] = [
		"run",
		"--rm",
		"--init",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		`--pids-limit=${cfg.pidsLimit}`,
		`--memory=${cfg.memory}`,
		`--cpus=${cfg.cpus}`,
		"--read-only",
		"--tmpfs=/tmp:rw,nosuid,nodev,size=64m",
		`--network=${cfg.network}`,
		"-v",
		`${workDir}:${workDir}:rw`,
		"-w",
		workDir,
		"-e",
		"NUWA_SANDBOX=docker",
		"-e",
		`NUWA_PROJECT_ID=${safeProjectId}`,
		"-e",
		`NUWA_OUT=${workDir}`,
		"-e",
		`HOME=${workDir}`,
		"-e",
		`TMPDIR=${workDir}`,
	];

	if (opts.scope) {
		const allowHosts = (opts.scope.allowHosts ?? []).join(",");
		const allowCidrs = (opts.scope.allowCidrs ?? []).join(",");
		const denyHosts = (opts.scope.denyHosts ?? []).join(",");
		args.push(
			"-e",
			`NUWA_SCOPE_ALLOW_HOSTS=${allowHosts}`,
			"-e",
			`NUWA_SCOPE_ALLOW_CIDRS=${allowCidrs}`,
			"-e",
			`NUWA_SCOPE_DENY_HOSTS=${denyHosts}`,
			"-e",
			`NUWA_SCOPE_ALLOW_SUBDOMAINS=${opts.scope.allowSubdomains ? "1" : "0"}`,
			"-e",
			`NUWA_SCOPE_ALLOW_PRIVATE=${opts.scope.allowPrivateNetwork ? "1" : "0"}`,
		);
	}

	for (const [k, v] of filterSafeExtraEnv(opts.extraEnv)) {
		args.push("-e", `${k}=${v}`);
	}

	// 运行前执行零信任断言，确保任何路径/参数均未突破隔离边界
	assertZeroTrustArgs(args, `/tmp/nuwa/${safeProjectId}`);

	args.push(cfg.image);

	if (opts.scope) {
		args.push("sh", "-c", buildContainerScopePreflightScript(), "nuwa-sandbox", command);
	} else {
		args.push("sh", "-c", command);
	}

	return args;
}

/**
 * 将命令按沙盒配置包装为可执行的零信任 Docker 沙盒命令行；
 * 当配置为 `mode="none"` 时直接原样返回原始命令。
 */
export function wrapCommandInDockerSandbox(command: string, opts: WrapSandboxOptions): string {
	const cfg = mergeConfig(opts.config);
	if (cfg.mode !== "docker") {
		return command;
	}
	const args = buildDockerRunArgs({
		...opts,
		command,
		config: cfg,
	});
	return [cfg.dockerBin, ...args].map(shellQuote).join(" ");
}
