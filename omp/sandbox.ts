/**
 * 女娲 v5.0 零信任容器沙盒隔离（Docker / 持久 Sidecar）与内置防 DNS 重绑定 Scoped Egress Proxy 模块。
 *
 * 零信任安全红线：
 * 1. 严禁挂载 `$HOME`、`~/.ssh`、`~/.omp`、`~/.pi`、`~/.aws`、`docker.sock` 或宿主机根目录。
 * 2. 仅允许挂载唯一项目产物工作区 `/tmp/nuwa/<projectId>`（强制校验单段标识符防路径穿越）。
 * 3. 严禁透传宿主机环境变量与 API Key / Token / Secret，仅注入最小白名单元数据与受控代理地址。
 * 4. 强制开启 `--cap-drop=ALL`、`--security-opt=no-new-privileges`、`--pids-limit=256`、
 *    只读根文件系统（`--read-only`）以及内存与 CPU 硬限额，禁止 `--privileged`、`--user=0`/`-u root` 与 `--network=host`。
 * 5. 结合 `ScopePolicy` 生成容器侧外连白名单前置校验脚本，并提供内置 HTTP/HTTPS Scoped Egress Proxy
 *    （解析真实 IP 防 DNS 重绑定、阻断云元数据/越界回环/越界私网与越界 30x 重定向）。
 *
 * 约束：仅使用 `import type` 引用 `./types` 并可运行时引用 `./scope`，严禁运行时 import `./nuwa`。
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { isHostInScope } from "./scope";
import type { ScopePolicy } from "./types";

export type SandboxMode = "none" | "docker" | "sidecar";
export type SandboxNetworkMode = "bridge" | "none";

export interface SandboxConfig {
	mode: SandboxMode;
	image: string;
	memory: string;
	cpus: string;
	pidsLimit: number;
	network: SandboxNetworkMode;
	dockerBin: string;
	egressProxyUrl?: string;
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

/** 仅允许容器自身运行、受控代理与外连白名单策略使用的内置非敏感环境变量白名单。 */
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
	"NUWA_SCOPE_ALLOW_LOOPBACK",
	"NUWA_SCOPE_OOB_DOMAINS",
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"ALL_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
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

function parseEgressProxyUrl(raw: string | undefined): string | undefined {
	const s = String(raw ?? "").trim();
	if (!s || /[\r\n\s]/.test(s)) return undefined;
	try {
		const u = new URL(s);
		if (u.protocol !== "http:") return undefined;
		if (u.username || u.password) return undefined;
		if (u.pathname && u.pathname !== "/") return undefined;
		if (u.search || u.hash) return undefined;
		const host = u.hostname.toLowerCase();
		if (host !== "127.0.0.1" && host !== "host.docker.internal") return undefined;
		if (!u.port || !/^\d{1,5}$/.test(u.port)) return undefined;
		const portNum = Number(u.port);
		if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return undefined;
		return `http://${host}:${portNum}`;
	} catch {
		return undefined;
	}
}

/**
 * 从环境变量读取沙盒隔离配置（默认关闭 `mode="none"`）。
 * 支持 `NUWA_SANDBOX=sidecar` 或 `NUWA_SANDBOX_SIDECAR=1` 启用持久 Sidecar 模式，
 * 以及通过 `NUWA_EGRESS_PROXY` 注入受控本机代理地址。
 */
export function readSandboxConfig(env: Record<string, string | undefined> = process.env): SandboxConfig {
	const rawMode = String(env.NUWA_SANDBOX ?? "").trim().toLowerCase();
	const sidecarFlag = String(env.NUWA_SANDBOX_SIDECAR ?? "").trim().toLowerCase();
	let mode: SandboxMode = "none";
	if (rawMode === "sidecar") {
		mode = "sidecar";
	} else if (rawMode === "docker") {
		mode = "docker";
	} else if (rawMode === "" && (sidecarFlag === "1" || sidecarFlag === "true")) {
		mode = "sidecar";
	}

	const dockerBinRaw = String(env.NUWA_DOCKER_BIN ?? "docker").trim();
	const dockerBin = dockerBinRaw && !/[\r\n;&|`$]/.test(dockerBinRaw) ? dockerBinRaw : "docker";
	const egressProxyUrl = parseEgressProxyUrl(env.NUWA_EGRESS_PROXY);

	return {
		mode,
		image: parseImageName(env.NUWA_SANDBOX_IMAGE, DEFAULT_SANDBOX_IMAGE),
		memory: parseMemoryLimit(env.NUWA_SANDBOX_MEMORY, DEFAULT_SANDBOX_MEMORY),
		cpus: parseCpuLimit(env.NUWA_SANDBOX_CPUS, DEFAULT_SANDBOX_CPUS),
		pidsLimit: parsePositiveInt(env.NUWA_SANDBOX_PIDS_LIMIT, DEFAULT_SANDBOX_PIDS_LIMIT),
		network: parseNetworkMode(env.NUWA_SANDBOX_NETWORK),
		dockerBin,
		...(egressProxyUrl ? { egressProxyUrl } : {}),
	};
}

function mergeConfig(overrides?: Partial<SandboxConfig>): SandboxConfig {
	const base = readSandboxConfig();
	if (!overrides) return base;
	const mode: SandboxMode =
		overrides.mode === "sidecar"
			? "sidecar"
			: overrides.mode === "docker"
				? "docker"
				: overrides.mode === "none"
					? "none"
					: base.mode;
	const egressProxyUrl =
		overrides.egressProxyUrl !== undefined
			? parseEgressProxyUrl(overrides.egressProxyUrl)
			: base.egressProxyUrl;
	return {
		mode,
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
		...(egressProxyUrl ? { egressProxyUrl } : {}),
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
		`allow_loopback = os.environ.get("NUWA_SCOPE_ALLOW_LOOPBACK", "1") != "0"`,
		`oob_domains = [x.strip().lower().rstrip(".") for x in os.environ.get("NUWA_SCOPE_OOB_DOMAINS", "").split(",") if x.strip()]`,
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
		`    is_lb = "/" not in h and is_loopback(h)`,
		`    if is_lb and allow_loopback: return (True, "")`,
		`    tip = parse_ip(h)`,
		`    tnet = parse_net(h) if "/" in h else None`,
		`    for a in allow_hosts:`,
		`        if match_pat(h, a): return (True, "")`,
		`        if allow_sub and tip is None and tnet is None and not a.startswith("*.") and parse_ip(a) is None:`,
		`            if h.endswith("." + a) and len(h) > len(a) + 1: return (True, "")`,
		`    if tip is None and tnet is None:`,
		`        for od in oob_domains:`,
		`            if "*" in od or "." not in od or parse_ip(od) is not None: continue`,
		`            if h == od or (h.endswith("." + od) and len(h) > len(od) + 1): return (True, "")`,
		`    if is_lb: return (False, "回环地址被禁止 (allowLoopback=false)")`,
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
		if (
			a === "--privileged" ||
			a.startsWith("--privileged=") ||
			a === "--pid=host" ||
			a === "--ipc=host" ||
			a === "--network=host" ||
			a === "--net=host"
		) {
			throw new Error(`零信任沙盒拦截高危 Docker 参数: ${a}`);
		}
		if (a === "-u" || a === "--user") {
			const userVal = String(args[i + 1] ?? "").trim();
			if (/^(?:root|0)(?::|$)/i.test(userVal)) {
				throw new Error(`零信任沙盒禁止以 root/UID 0 运行容器: ${a} ${userVal}`);
			}
		}
		if (/^(?:-u|--user)=?(?:root|0)(?::|$)/i.test(a)) {
			throw new Error(`零信任沙盒禁止以 root/UID 0 运行容器: ${a}`);
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

function appendScopeEnvArgs(args: string[], scope: ScopePolicy): void {
	const allowHosts = (scope.allowHosts ?? []).join(",");
	const allowCidrs = (scope.allowCidrs ?? []).join(",");
	const denyHosts = (scope.denyHosts ?? []).join(",");
	const oobDomains = (scope.oobDomains ?? []).join(",");
	args.push(
		"-e",
		`NUWA_SCOPE_ALLOW_HOSTS=${allowHosts}`,
		"-e",
		`NUWA_SCOPE_ALLOW_CIDRS=${allowCidrs}`,
		"-e",
		`NUWA_SCOPE_DENY_HOSTS=${denyHosts}`,
		"-e",
		`NUWA_SCOPE_ALLOW_SUBDOMAINS=${scope.allowSubdomains ? "1" : "0"}`,
		"-e",
		`NUWA_SCOPE_ALLOW_PRIVATE=${scope.allowPrivateNetwork ? "1" : "0"}`,
		"-e",
		`NUWA_SCOPE_ALLOW_LOOPBACK=${scope.allowLoopback === false ? "0" : "1"}`,
		"-e",
		`NUWA_SCOPE_OOB_DOMAINS=${oobDomains}`,
	);
}

function resolveProxyUrlStrict(explicitProxyUrl: string | undefined, fallbackProxyUrl: string | undefined): string | undefined {
	if (explicitProxyUrl !== undefined) {
		const trimmed = explicitProxyUrl.trim();
		if (!trimmed) return undefined;
		const parsed = parseEgressProxyUrl(trimmed);
		if (!parsed) {
			throw new Error(
				`零信任沙盒拦截非法 egressProxyUrl: ${JSON.stringify(explicitProxyUrl)}（仅允许 http://127.0.0.1:<port> 或 http://host.docker.internal:<port>）`,
			);
		}
		return parsed;
	}
	return fallbackProxyUrl ? parseEgressProxyUrl(fallbackProxyUrl) : undefined;
}

function appendProxyEnvArgs(args: string[], proxyUrl: string | undefined): void {
	if (!proxyUrl) return;
	args.push(
		"-e",
		`HTTP_PROXY=${proxyUrl}`,
		"-e",
		`HTTPS_PROXY=${proxyUrl}`,
		"-e",
		`http_proxy=${proxyUrl}`,
		"-e",
		`https_proxy=${proxyUrl}`,
		"-e",
		"NO_PROXY=",
	);
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
		appendScopeEnvArgs(args, opts.scope);
	}

	appendProxyEnvArgs(args, cfg.egressProxyUrl);

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
 * 当配置为 `mode="none"` 时直接原样返回原始命令，`mode="sidecar"` 时委托 Sidecar 包装器。
 */
export function wrapCommandInDockerSandbox(command: string, opts: WrapSandboxOptions): string {
	const cfg = mergeConfig(opts.config);
	if (cfg.mode === "sidecar") {
		return wrapCommandInSidecarSandbox(command, { ...opts, config: cfg });
	}
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

// ══════════════════════════════════════════════════════════════════════════════
// v5.0 持久 Sidecar 容器生命周期管理与合规校验
// ══════════════════════════════════════════════════════════════════════════════

export interface BuildSidecarStartArgsOptions {
	projectId: string;
	scope?: ScopePolicy;
	config?: Partial<SandboxConfig>;
	proxyUrl?: string;
	extraEnv?: Record<string, string>;
	ensureWorkdir?: boolean;
}

export interface BuildSidecarExecArgsOptions {
	projectId: string;
	command: string;
	scope?: ScopePolicy;
	config?: Partial<SandboxConfig>;
	proxyUrl?: string;
	extraEnv?: Record<string, string>;
}

export interface SidecarOpResult {
	ok: boolean;
	containerName: string;
	stdout?: string;
	stderr?: string;
	code?: number;
	reason?: string;
	alreadyRunning?: boolean;
}

/**
 * 为项目生成确定性、安全的 Sidecar 容器名 `nuwa-sb-<safeProjectId>`（长度 <= 63，仅含 `[a-zA-Z0-9._-]`）。
 */
export function sidecarContainerName(projectId: string): string {
	const safe = assertSafeProjectId(projectId);
	const prefix = "nuwa-sb-";
	const candidate = `${prefix}${safe}`;
	if (candidate.length <= 63) {
		return candidate;
	}
	const suffix = createHash("sha256").update(safe).digest("hex").slice(0, 8);
	const maxHead = 63 - prefix.length - 1 - suffix.length;
	const head = safe.slice(0, maxHead).replace(/[._-]+$/, "") || "p";
	return `${prefix}${head}-${suffix}`;
}

/**
 * 构建持久 Sidecar 容器启动参数数组（`docker run -d --rm ...`），完整继承零信任隔离边界。
 */
export function buildSidecarStartArgs(opts: BuildSidecarStartArgsOptions): string[] {
	const safeProjectId = assertSafeProjectId(opts.projectId);
	const cfg = mergeConfig(opts.config);
	const workDir = join("/tmp/nuwa", safeProjectId);
	const containerName = sidecarContainerName(safeProjectId);
	const proxyUrl = resolveProxyUrlStrict(opts.proxyUrl, cfg.egressProxyUrl);

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
		"-d",
		"--rm",
		"--init",
		"--name",
		containerName,
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
		"NUWA_SANDBOX=sidecar",
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
		appendScopeEnvArgs(args, opts.scope);
	}
	appendProxyEnvArgs(args, proxyUrl);

	for (const [k, v] of filterSafeExtraEnv(opts.extraEnv)) {
		args.push("-e", `${k}=${v}`);
	}

	assertZeroTrustArgs(args, `/tmp/nuwa/${safeProjectId}`);

	args.push(cfg.image, "sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600; done");
	return args;
}

/**
 * 构建在既有项目 Sidecar 容器中执行单条命令的 `docker exec` 参数数组。
 */
export function buildSidecarExecArgs(opts: BuildSidecarExecArgsOptions): string[] {
	const safeProjectId = assertSafeProjectId(opts.projectId);
	const command = String(opts.command ?? "");
	const cfg = mergeConfig(opts.config);
	const workDir = join("/tmp/nuwa", safeProjectId);
	const containerName = sidecarContainerName(safeProjectId);
	const proxyUrl = resolveProxyUrlStrict(opts.proxyUrl, cfg.egressProxyUrl);

	const args: string[] = ["exec", "-w", workDir];

	if (opts.scope) {
		appendScopeEnvArgs(args, opts.scope);
	}
	appendProxyEnvArgs(args, proxyUrl);

	for (const [k, v] of filterSafeExtraEnv(opts.extraEnv)) {
		args.push("-e", `${k}=${v}`);
	}

	assertZeroTrustArgs(args, `/tmp/nuwa/${safeProjectId}`);

	args.push(containerName);
	if (opts.scope) {
		args.push("sh", "-c", buildContainerScopePreflightScript(), "nuwa-sandbox", command);
	} else {
		args.push("sh", "-c", command);
	}
	return args;
}

/**
 * 将命令包装为指向项目持久 Sidecar 容器的 `docker exec ...` 命令行。
 * 若显式传入 `config.mode === "none"` 则原样返回原始命令。
 */
export function wrapCommandInSidecarSandbox(
	command: string,
	opts: WrapSandboxOptions & { proxyUrl?: string },
): string {
	if (opts.config?.mode === "none") {
		return command;
	}
	const cfg = mergeConfig(opts.config);
	const args = buildSidecarExecArgs({
		projectId: opts.projectId,
		command,
		scope: opts.scope,
		config: cfg,
		proxyUrl: opts.proxyUrl,
		extraEnv: opts.extraEnv,
	});
	return [cfg.dockerBin, ...args].map(shellQuote).join(" ");
}

function tokenizeSingleShellCommand(cmd: string): { ok: boolean; tokens: string[]; reason?: string } {
	const tokens: string[] = [];
	let cur = "";
	let hasToken = false;
	let inSingle = false;
	let inDouble = false;

	for (let i = 0; i < cmd.length; i++) {
		const ch = cmd[i]!;
		if (inSingle) {
			if (ch === "'") {
				inSingle = false;
			} else {
				cur += ch;
			}
			continue;
		}
		if (inDouble) {
			if (ch === '"') {
				inDouble = false;
			} else if (ch === "\\" && i + 1 < cmd.length) {
				cur += cmd[++i]!;
			} else if (ch === "`" || (ch === "$" && cmd[i + 1] === "(")) {
				return { ok: false, tokens: [], reason: "Sidecar 宿主机命令行禁止包含命令替换" };
			} else {
				cur += ch;
			}
			continue;
		}

		if (ch === "'") {
			inSingle = true;
			hasToken = true;
			continue;
		}
		if (ch === '"') {
			inDouble = true;
			hasToken = true;
			continue;
		}
		if (ch === "\\" && i + 1 < cmd.length) {
			cur += cmd[++i]!;
			hasToken = true;
			continue;
		}
		if (ch === ";" || ch === "|" || ch === "&" || ch === "\n" || ch === "\r" || ch === "`" || ch === "(" || ch === ")") {
			return { ok: false, tokens: [], reason: `Sidecar 宿主机命令行禁止包含顶层多命令分隔符 (${ch})` };
		}
		if (ch === "$" && cmd[i + 1] === "(") {
			return { ok: false, tokens: [], reason: "Sidecar 宿主机命令行禁止包含命令替换 $()" };
		}
		if (/\s/.test(ch)) {
			if (hasToken || cur.length > 0) {
				tokens.push(cur);
				cur = "";
				hasToken = false;
			}
			continue;
		}
		cur += ch;
		hasToken = true;
	}

	if (inSingle || inDouble) {
		return { ok: false, tokens: [], reason: "Sidecar 命令行存在未闭合引号" };
	}
	if (hasToken || cur.length > 0) {
		tokens.push(cur);
	}
	return { ok: true, tokens };
}

const DOCKER_EXEC_VALUE_FLAGS = new Set(["-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys"]);

/**
 * 校验命令行是否为合规的项目 Sidecar `docker exec` 调用：
 * - 必须为单一 `docker exec` 命令（无宿主机侧 `;`/`|`/`&&`/命令替换逃逸）；
 * - 目标容器名必须严格等于 `sidecarContainerName(projectId)`；
 * - 严禁 `--privileged`、`-u root`、`--user=0`、`--env-file`、敏感宿主机环境变量透传及 `docker.sock`。
 */
export function isCompliantSidecarCommand(cmd: string, projectId: string): { ok: boolean; reason?: string } {
	let expectedName: string;
	let safeProjectId: string;
	try {
		safeProjectId = assertSafeProjectId(projectId);
		expectedName = sidecarContainerName(safeProjectId);
	} catch (err) {
		return { ok: false, reason: err instanceof Error ? err.message : String(err) };
	}

	const trimmed = String(cmd ?? "").trim();
	if (!trimmed) {
		return { ok: false, reason: "命令为空" };
	}
	if (/docker\.sock/i.test(trimmed)) {
		return { ok: false, reason: "严禁在 Sidecar 命令中引用或挂载 docker.sock" };
	}

	const parsed = tokenizeSingleShellCommand(trimmed);
	if (!parsed.ok) {
		return { ok: false, reason: parsed.reason };
	}
	const tokens = parsed.tokens;
	if (tokens.length < 4) {
		return { ok: false, reason: "命令未通过 docker exec Sidecar 沙盒包裹执行" };
	}

	const binName = basename(tokens[0] ?? "").toLowerCase();
	if (binName !== "docker" || tokens[1] !== "exec") {
		return { ok: false, reason: "命令未通过 docker exec Sidecar 沙盒包裹执行" };
	}

	const allowedWorkdir = `/tmp/nuwa/${safeProjectId}`;
	let idx = 2;
	while (idx < tokens.length) {
		const tok = tokens[idx]!;
		if (tok === "--") {
			idx += 1;
			break;
		}
		if (!tok.startsWith("-")) {
			break;
		}
		if (tok === "--privileged" || tok.startsWith("--privileged=")) {
			return { ok: false, reason: "严禁在 Sidecar 命令中使用 --privileged" };
		}
		if (tok === "--env-file" || tok.startsWith("--env-file=")) {
			return { ok: false, reason: "严禁通过 --env-file 读取宿主机环境变量文件" };
		}
		if (/^(?:-u|--user)=?(?:root|0)(?::|$)/i.test(tok)) {
			return { ok: false, reason: `严禁以 root/UID 0 执行 Sidecar 命令 (${tok})` };
		}
		if (tok === "-u" || tok === "--user") {
			const val = tokens[idx + 1] ?? "";
			if (/^(?:root|0)(?::|$)/i.test(val.trim())) {
				return { ok: false, reason: `严禁以 root/UID 0 执行 Sidecar 命令 (${tok} ${val})` };
			}
			idx += 2;
			continue;
		}
		if (tok === "-w" || tok === "--workdir") {
			const wd = tokens[idx + 1] ?? "";
			if (wd !== allowedWorkdir && !wd.startsWith(`${allowedWorkdir}/`)) {
				return { ok: false, reason: `Sidecar 工作目录必须限定在 ${allowedWorkdir} 内` };
			}
			if (wd.includes("..")) {
				return { ok: false, reason: "Sidecar 工作目录禁止路径穿越" };
			}
			idx += 2;
			continue;
		}
		if (tok.startsWith("--workdir=") || tok.startsWith("-w=")) {
			const wd = tok.slice(tok.indexOf("=") + 1);
			if ((wd !== allowedWorkdir && !wd.startsWith(`${allowedWorkdir}/`)) || wd.includes("..")) {
				return { ok: false, reason: `Sidecar 工作目录必须限定在 ${allowedWorkdir} 内` };
			}
			idx += 1;
			continue;
		}
		if (tok === "-e" || tok === "--env") {
			const kv = tokens[idx + 1] ?? "";
			if (!kv.includes("=")) {
				return { ok: false, reason: `Sidecar 禁止裸透传宿主机环境变量 (${kv})` };
			}
			const key = kv.split("=")[0] ?? "";
			if (!INTERNAL_SAFE_ENV_KEYS.has(key) && SENSITIVE_ENV_KEY_RE.test(key)) {
				return { ok: false, reason: `Sidecar 禁止透传敏感环境变量 (${key})` };
			}
			idx += 2;
			continue;
		}
		if (tok.startsWith("--env=") || tok.startsWith("-e=")) {
			const kv = tok.slice(tok.indexOf("=") + 1);
			if (!kv.includes("=")) {
				return { ok: false, reason: `Sidecar 禁止裸透传宿主机环境变量 (${kv})` };
			}
			const key = kv.split("=")[0] ?? "";
			if (!INTERNAL_SAFE_ENV_KEYS.has(key) && SENSITIVE_ENV_KEY_RE.test(key)) {
				return { ok: false, reason: `Sidecar 禁止透传敏感环境变量 (${key})` };
			}
			idx += 1;
			continue;
		}
		if (DOCKER_EXEC_VALUE_FLAGS.has(tok)) {
			idx += 2;
			continue;
		}
		idx += 1;
	}

	const containerTok = tokens[idx];
	if (containerTok !== expectedName) {
		return {
			ok: false,
			reason: `Sidecar 目标容器不匹配（期望 ${expectedName}，实际 ${containerTok ?? "缺失"}）`,
		};
	}
	if (idx + 1 >= tokens.length) {
		return { ok: false, reason: "Sidecar docker exec 缺少待执行的容器内命令" };
	}
	return { ok: true };
}

const DOCKER_RUN_VALUE_FLAGS = new Set([
	...DOCKER_EXEC_VALUE_FLAGS,
	"-v",
	"--volume",
	"--mount",
	"--network",
	"--net",
	"--memory",
	"-m",
	"--cpus",
	"--pids-limit",
	"--security-opt",
	"--cap-drop",
	"--cap-add",
	"--tmpfs",
	"--name",
	"--entrypoint",
	"--hostname",
	"-h",
	"--label",
	"-l",
]);

/**
 * 从已通过零信任合规校验的 `docker run` / `docker exec` 沙盒包装命令中精确提取容器内待执行命令。
 * 仅当代理环境变量与宿主 `allowedProxyUrl` 严格一致且预检脚本与 `buildContainerScopePreflightScript()` 字节级一致时，
 * 才剥离外层包装与预检脚本，杜绝通过伪造预检脚本或非法代理环境变量绕过宿主机 `N-007`/`N-008` 护栏。
 */
export function extractSandboxInnerCommand(cmd: string, allowedProxyUrl?: string): string | null {
	const parsed = tokenizeSingleShellCommand(String(cmd ?? "").trim());
	if (!parsed.ok) return null;
	const tokens = parsed.tokens;
	if (tokens.length < 4) return null;
	const binName = basename(tokens[0] ?? "").toLowerCase();
	if (binName !== "docker" || (tokens[1] !== "exec" && tokens[1] !== "run")) return null;

	const valueFlags = tokens[1] === "run" ? DOCKER_RUN_VALUE_FLAGS : DOCKER_EXEC_VALUE_FLAGS;
	const proxyKeys = new Set(["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]);

	let idx = 2;
	while (idx < tokens.length) {
		const tok = tokens[idx]!;
		if (tok === "--") {
			idx += 1;
			break;
		}
		if (!tok.startsWith("-")) {
			break;
		}
		let envKv: string | null = null;
		if (tok === "-e" || tok === "--env") {
			envKv = tokens[idx + 1] ?? "";
			idx += 2;
		} else if (tok.startsWith("-e=") || tok.startsWith("--env=")) {
			envKv = tok.slice(tok.indexOf("=") + 1);
			idx += 1;
		} else if (valueFlags.has(tok)) {
			idx += 2;
		} else {
			idx += 1;
		}
		if (envKv !== null) {
			const eq = envKv.indexOf("=");
			if (eq < 0) return null;
			const k = envKv.slice(0, eq);
			const v = envKv.slice(eq + 1);
			if (proxyKeys.has(k) && (!allowedProxyUrl || v !== allowedProxyUrl)) {
				return null;
			}
		}
	}

	// tokens[idx] 为容器名或镜像名，其后为容器内执行参数
	const inner = tokens.slice(idx + 1);
	if (inner.length === 0) return null;

	if (
		inner.length >= 5 &&
		inner[0] === "sh" &&
		inner[1] === "-c" &&
		inner[3] === "nuwa-sandbox" &&
		inner[2] === buildContainerScopePreflightScript()
	) {
		return inner.slice(4).join(" ");
	}
	if (inner.length === 3 && inner[0] === "sh" && inner[1] === "-c") {
		return inner[2]!;
	}
	return inner.join(" ");
}

/**
 * 确保项目持久 Sidecar 容器处于运行状态；Docker 缺失或守护进程未启动时安全返回结构化结果而不抛错。
 */
export function ensureProjectSidecar(
	opts: BuildSidecarStartArgsOptions & { timeoutMs?: number },
): SidecarOpResult {
	let containerName = "";
	try {
		containerName = sidecarContainerName(opts.projectId);
		const cfg = mergeConfig(opts.config);
		const timeout =
			typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
				? Math.floor(opts.timeoutMs)
				: 15_000;

		const inspect = spawnSync(cfg.dockerBin, ["inspect", "-f", "{{.State.Running}}", containerName], {
			encoding: "utf8",
			timeout,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (inspect.error) {
			const errCode = (inspect.error as NodeJS.ErrnoException).code;
			return {
				ok: false,
				containerName,
				reason: errCode === "ENOENT" ? `未找到 Docker 可执行文件: ${cfg.dockerBin}` : inspect.error.message,
			};
		}
		if (inspect.status === 0) {
			const running = (inspect.stdout ?? "").trim().toLowerCase() === "true";
			if (running) {
				return {
					ok: true,
					containerName,
					stdout: (inspect.stdout ?? "").trim(),
					code: 0,
					alreadyRunning: true,
				};
			}
			// 清理已退出的同名残余容器后再重建
			spawnSync(cfg.dockerBin, ["rm", "-f", containerName], {
				encoding: "utf8",
				timeout,
				stdio: ["ignore", "pipe", "pipe"],
			});
		}

		const startArgs = buildSidecarStartArgs({
			...opts,
			config: cfg,
			ensureWorkdir: opts.ensureWorkdir ?? true,
		});
		const started = spawnSync(cfg.dockerBin, startArgs, {
			encoding: "utf8",
			timeout,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (started.error) {
			return {
				ok: false,
				containerName,
				reason: started.error.message,
			};
		}
		if (started.status !== 0) {
			const stderr = (started.stderr ?? "").trim();
			return {
				ok: false,
				containerName,
				stdout: started.stdout ?? "",
				stderr: started.stderr ?? "",
				code: started.status ?? 1,
				reason: stderr || `docker run 启动 Sidecar 失败 (exit ${started.status})`,
			};
		}
		return {
			ok: true,
			containerName,
			stdout: (started.stdout ?? "").trim(),
			stderr: (started.stderr ?? "").trim(),
			code: 0,
			alreadyRunning: false,
		};
	} catch (err) {
		return {
			ok: false,
			containerName,
			reason: err instanceof Error ? err.message : String(err),
		};
	}
}

/**
 * 在项目持久 Sidecar 容器中同步执行命令；全程捕获异常，不向外抛错。
 */
export function execInProjectSidecar(
	opts: BuildSidecarExecArgsOptions & { timeoutMs?: number },
): SidecarOpResult {
	let containerName = "";
	try {
		containerName = sidecarContainerName(opts.projectId);
		const cfg = mergeConfig(opts.config);
		const timeout =
			typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
				? Math.floor(opts.timeoutMs)
				: 60_000;
		const execArgs = buildSidecarExecArgs({ ...opts, config: cfg });
		const res = spawnSync(cfg.dockerBin, execArgs, {
			encoding: "utf8",
			timeout,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (res.error) {
			const errCode = (res.error as NodeJS.ErrnoException).code;
			return {
				ok: false,
				containerName,
				reason: errCode === "ENOENT" ? `未找到 Docker 可执行文件: ${cfg.dockerBin}` : res.error.message,
			};
		}
		const code = res.status ?? 1;
		const stderr = res.stderr ?? "";
		return {
			ok: code === 0,
			containerName,
			stdout: res.stdout ?? "",
			stderr,
			code,
			...(code !== 0 ? { reason: stderr.trim() || `docker exec 退出码 ${code}` } : {}),
		};
	} catch (err) {
		return {
			ok: false,
			containerName,
			reason: err instanceof Error ? err.message : String(err),
		};
	}
}

/**
 * 停止并移除项目持久 Sidecar 容器；Docker 不可用时安全返回结构化结果而不抛错。
 */
export function stopProjectSidecar(
	projectIdOrOpts: string | { projectId: string; config?: Partial<SandboxConfig>; timeoutMs?: number },
	config?: Partial<SandboxConfig>,
	timeoutMs?: number,
): SidecarOpResult {
	const projectId = typeof projectIdOrOpts === "string" ? projectIdOrOpts : projectIdOrOpts.projectId;
	const effConfig = typeof projectIdOrOpts === "string" ? config : projectIdOrOpts.config;
	const effTimeout = typeof projectIdOrOpts === "string" ? timeoutMs : projectIdOrOpts.timeoutMs;

	let containerName = "";
	try {
		containerName = sidecarContainerName(projectId);
		const cfg = mergeConfig(effConfig);
		const timeout =
			typeof effTimeout === "number" && Number.isFinite(effTimeout) && effTimeout > 0
				? Math.floor(effTimeout)
				: 10_000;
		const res = spawnSync(cfg.dockerBin, ["rm", "-f", containerName], {
			encoding: "utf8",
			timeout,
			stdio: ["ignore", "pipe", "pipe"],
		});
		if (res.error) {
			const errCode = (res.error as NodeJS.ErrnoException).code;
			return {
				ok: false,
				containerName,
				reason: errCode === "ENOENT" ? `未找到 Docker 可执行文件: ${cfg.dockerBin}` : res.error.message,
			};
		}
		const stderr = (res.stderr ?? "").trim();
		if (res.status === 0) {
			return {
				ok: true,
				containerName,
				stdout: (res.stdout ?? "").trim(),
				stderr,
				code: 0,
			};
		}
		if (/no such container/i.test(stderr)) {
			return {
				ok: true,
				containerName,
				stdout: (res.stdout ?? "").trim(),
				stderr,
				code: 0,
				reason: "Sidecar 容器未运行或已清理",
			};
		}
		return {
			ok: false,
			containerName,
			stdout: res.stdout ?? "",
			stderr,
			code: res.status ?? 1,
			reason: stderr || `docker rm -f 失败 (exit ${res.status})`,
		};
	} catch (err) {
		return {
			ok: false,
			containerName,
			reason: err instanceof Error ? err.message : String(err),
		};
	}
}

export * from "./sandbox-egress";

const ALLOWED_TASK_EGRESS_PROTOCOLS = new Set(["http:", "https:", "socks5:", "socks5h:", "socks4:", "socks4a:"]);
const EGRESS_RESET_CURL_EXIT_CODES = new Set([7, 28, 35, 52, 56, 97]);
const EGRESS_RESET_ERROR_RE =
	/\b(?:ECONNRESET|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|EPIPE|socket hang up|connection reset|connection refused|connect failed|proxy connect|timed?\s*out)\b/i;

/**
 * 规范化并校验任务级代理出口 URL（支持 http/https/socks5/socks5h/socks4/socks4a）。
 * 拒绝换行、空白、Shell 元字符或非法主机端口，防止命令注入。
 */
export function normalizeTaskEgressUrl(raw: string | undefined): string | undefined {
	const s = String(raw ?? "").trim();
	if (!s || /[\r\n\s'"`$&;|<>\\]/.test(s)) return undefined;
	try {
		const u = new URL(s);
		if (!ALLOWED_TASK_EGRESS_PROTOCOLS.has(u.protocol)) return undefined;
		if (!u.hostname) return undefined;
		if (u.port) {
			if (!/^\d{1,5}$/.test(u.port)) return undefined;
			const p = Number(u.port);
			if (!Number.isInteger(p) || p < 1 || p > 65535) return undefined;
		}
		if (u.pathname && u.pathname !== "/") return undefined;
		if (u.search || u.hash) return undefined;
		const authPart = u.username ? `${u.username}${u.password ? `:${u.password}` : ""}@` : "";
		const hostPart = u.hostname.includes(":") && !u.hostname.startsWith("[") ? `[${u.hostname}]` : u.hostname;
		const portPart = u.port ? `:${u.port}` : "";
		return `${u.protocol}//${authPart}${hostPart}${portPart}`;
	} catch {
		return undefined;
	}
}

/** 脱敏展示出口 URL（隐藏代理认证密码，避免明文落日志）。 */
export function maskEgressUrl(raw: string | undefined): string {
	const norm = normalizeTaskEgressUrl(raw);
	if (!norm) return "";
	try {
		const u = new URL(norm);
		const hostPart = u.hostname.includes(":") && !u.hostname.startsWith("[") ? `[${u.hostname}]` : u.hostname;
		const portPart = u.port ? `:${u.port}` : "";
		if (u.username || u.password) {
			return `${u.protocol}//${u.username || "***"}:***@${hostPart}${portPart}`;
		}
		return `${u.protocol}//${hostPart}${portPart}`;
	} catch {
		return "";
	}
}

export interface InjectEgressEnvOptions {
	/** 显式传入的出口代理 URL；若省略则依次从 baseEnv / process.env 解析。 */
	egressUrl?: string;
	/** NO_PROXY 值，默认空串确保不意外绕过已验证出口。 */
	noProxy?: string;
	/** 是否同时透传上游已有环境变量，默认 true。 */
	inheritEnv?: boolean;
}

/**
 * 从环境变量对象中解析任务级出口代理 URL：
 * 默认优先读取女娲任务专用变量 `NUWA_EGRESS` > `NUWA_EGRESS_PROXY` > `EGRESS`；
 * 当 `opts.includeGenericProxy` 为 true 时再回退读取通用代理环境变量 `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY`。
 */
export function resolveConfiguredEgressUrl(
	env: Record<string, string | undefined> = process.env,
	opts?: { includeGenericProxy?: boolean },
): string | undefined {
	const candidates: Array<string | undefined> = [env.NUWA_EGRESS, env.NUWA_EGRESS_PROXY, env.EGRESS];
	if (opts?.includeGenericProxy) {
		candidates.push(env.ALL_PROXY, env.all_proxy, env.HTTPS_PROXY, env.https_proxy, env.HTTP_PROXY, env.http_proxy);
	}
	for (const c of candidates) {
		const norm = normalizeTaskEgressUrl(c);
		if (norm) return norm;
	}
	return undefined;
}

/**
 * 为子任务/执行环境统一注入出口代理环境变量（#23），覆盖 `NUWA_EGRESS`、`EGRESS`、`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 及其小写形式。
 * 若显式传入非法代理 URL 则直接抛错（fail-closed）；若未传入且环境中无出口则返回过滤后的基准环境。
 */
export function injectEgressEnv(
	egressUrl?: string,
	baseEnv: Record<string, string | undefined> = process.env,
	opts?: Omit<InjectEgressEnvOptions, "egressUrl">,
): Record<string, string> {
	const inherit = opts?.inheritEnv !== false;
	const out: Record<string, string> = {};
	if (inherit && baseEnv) {
		for (const [k, v] of Object.entries(baseEnv)) {
			if (typeof v === "string") {
				out[k] = v;
			}
		}
	}

	let resolved: string | undefined;
	if (egressUrl !== undefined && String(egressUrl).trim() !== "") {
		resolved = normalizeTaskEgressUrl(egressUrl);
		if (!resolved) {
			throw new Error(
				`非法出口代理地址: ${JSON.stringify(egressUrl)}（仅允许 http/https/socks5/socks5h/socks4/socks4a 且禁止控制字符）`,
			);
		}
	} else {
		resolved = resolveConfiguredEgressUrl(baseEnv, { includeGenericProxy: true });
	}

	if (!resolved) {
		return out;
	}

	const noProxy = opts?.noProxy !== undefined ? String(opts.noProxy).replace(/[\r\n]+/g, "") : "";
	out.NUWA_EGRESS = resolved;
	out.EGRESS = resolved;
	out.HTTP_PROXY = resolved;
	out.HTTPS_PROXY = resolved;
	out.ALL_PROXY = resolved;
	out.http_proxy = resolved;
	out.https_proxy = resolved;
	out.all_proxy = resolved;
	out.NO_PROXY = noProxy;
	out.no_proxy = noProxy;
	return out;
}

/** 为 curl 构造安全的 `-x <egressUrl>` 代理透传参数数组。 */
export function buildCurlProxyArgs(egressUrl?: string): string[] {
	if (!egressUrl || !String(egressUrl).trim()) return [];
	const norm = normalizeTaskEgressUrl(egressUrl);
	if (!norm) {
		throw new Error(`非法 curl 代理地址: ${JSON.stringify(egressUrl)}`);
	}
	return ["-x", norm];
}

export interface EgressEndpointConfig {
	id?: string;
	url: string;
	label?: string;
	priority?: number;
	maxInFlight?: number;
}

export interface EgressObservation {
	ok?: boolean;
	statusCode?: number;
	ttfbMs?: number;
	totalMs?: number;
	connectionReset?: boolean;
	exitCode?: number;
	blocked?: boolean;
	error?: string;
}

export type EgressCircuitState = "healthy" | "degraded" | "open";

export interface EgressHealthSnapshot {
	id: string;
	url: string;
	maskedUrl: string;
	label?: string;
	priority: number;
	state: EgressCircuitState;
	inFlight: number;
	maxInFlight?: number;
	totalRequests: number;
	windowSamples: number;
	avgTtfbMs: number;
	p95TtfbMs: number;
	errorRate: number;
	resetRate: number;
	consecutiveFailures: number;
	circuitOpenUntil?: number;
	lastFailureReason?: string;
	lastUpdatedAt?: number;
}

export interface EgressLease {
	id: string;
	url: string;
	maskedUrl: string;
	label?: string;
	degraded: boolean;
	workerId?: string;
	acquiredAt: number;
	/** 归还出口并发槽位并上报本次观测结果（幂等）。 */
	release: (obs?: EgressObservation) => void;
}

export interface EgressPoolOptions {
	/** 平均 TTFB 劣化阈值（ms，默认 8000） */
	maxTtfbMs?: number;
	/** 403/5xx/blocked 错误率熔断阈值（0..1，默认 0.5） */
	maxErrorRate?: number;
	/** 连接重置/拒绝/超时率熔断阈值（0..1，默认 0.4） */
	maxResetRate?: number;
	/** 连续失败触发熔断次数阈值（默认 3） */
	consecutiveFailureThreshold?: number;
	/** 触发比率类熔断的最小滑动窗口样本数（默认 3） */
	minSamplesForRate?: number;
	/** 滑动窗口最大样本数（默认 20） */
	windowSize?: number;
	/** 熔断冷却时长（ms，默认 30000） */
	cooldownMs?: number;
	/** 并发分配策略：least-loaded（最少负载+轮询，默认）或 round-robin（纯轮询） */
	strategy?: "least-loaded" | "round-robin";
	/** 全部出口熔断时是否允许可控降级到最优残余出口（默认 false） */
	allowDegradedFallback?: boolean;
	/** 自定义时钟（用于测试确定性推进时间） */
	now?: () => number;
}

interface EgressSampleRecord {
	ts: number;
	ok: boolean;
	isError: boolean;
	isReset: boolean;
	isBlocked: boolean;
	ttfbMs?: number;
	statusCode?: number;
	reason?: string;
}

interface EgressEndpointInternal {
	id: string;
	url: string;
	maskedUrl: string;
	label?: string;
	priority: number;
	maxInFlight?: number;
	inFlight: number;
	totalRequests: number;
	consecutiveFailures: number;
	state: EgressCircuitState;
	circuitOpenUntil?: number;
	lastFailureReason?: string;
	lastUpdatedAt?: number;
	samples: EgressSampleRecord[];
}

function defaultEgressId(url: string, index: number): string {
	const hash = createHash("sha256").update(url).digest("hex").slice(0, 8);
	return `egress-${index + 1}-${hash}`;
}

function percentile95(values: readonly number[]): number {
	if (values.length === 0) return 0;
	const sorted = [...values].sort((a, b) => a - b);
	const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
	return sorted[idx]!;
}

/**
 * 多出口健康度管理池（#36 / NW-16）：
 * - 实时追踪每个出口的 TTFB、403/5xx 错误率、连接重置率与连续失败次数；
 * - 劣化超阈值自动熔断并在冷却期后半开探活，支持向健康出口故障转移或可控降级；
 * - 多并发 worker 采用最少负载/轮询调度分配出口，防止并发抢占同一节点触发边缘限流。
 */
export class EgressPoolManager {
	private readonly endpoints: EgressEndpointInternal[] = [];
	private readonly byId = new Map<string, EgressEndpointInternal>();
	private rrCursor = 0;

	private readonly maxTtfbMs: number;
	private readonly maxErrorRate: number;
	private readonly maxResetRate: number;
	private readonly consecutiveFailureThreshold: number;
	private readonly minSamplesForRate: number;
	private readonly windowSize: number;
	private readonly cooldownMs: number;
	private readonly strategy: "least-loaded" | "round-robin";
	private readonly allowDegradedFallback: boolean;
	private readonly nowFn: () => number;

	constructor(endpoints: readonly (string | EgressEndpointConfig)[] = [], opts: EgressPoolOptions = {}) {
		this.maxTtfbMs = typeof opts.maxTtfbMs === "number" && opts.maxTtfbMs > 0 ? opts.maxTtfbMs : 8_000;
		this.maxErrorRate =
			typeof opts.maxErrorRate === "number" && opts.maxErrorRate > 0 && opts.maxErrorRate <= 1
				? opts.maxErrorRate
				: 0.5;
		this.maxResetRate =
			typeof opts.maxResetRate === "number" && opts.maxResetRate > 0 && opts.maxResetRate <= 1
				? opts.maxResetRate
				: 0.4;
		this.consecutiveFailureThreshold =
			typeof opts.consecutiveFailureThreshold === "number" && opts.consecutiveFailureThreshold >= 1
				? Math.floor(opts.consecutiveFailureThreshold)
				: 3;
		this.minSamplesForRate =
			typeof opts.minSamplesForRate === "number" && opts.minSamplesForRate >= 1
				? Math.floor(opts.minSamplesForRate)
				: 3;
		this.windowSize =
			typeof opts.windowSize === "number" && opts.windowSize >= 1 ? Math.floor(opts.windowSize) : 20;
		this.cooldownMs = typeof opts.cooldownMs === "number" && opts.cooldownMs >= 0 ? opts.cooldownMs : 30_000;
		this.strategy = opts.strategy === "round-robin" ? "round-robin" : "least-loaded";
		this.allowDegradedFallback = Boolean(opts.allowDegradedFallback);
		this.nowFn = opts.now ?? (() => Date.now());

		for (const ep of endpoints) {
			this.addEndpoint(typeof ep === "string" ? { url: ep } : ep);
		}
	}

	/** 添加出口节点到管理池（同 id 存在时覆盖配置并保留唯一性）。 */
	addEndpoint(config: EgressEndpointConfig): EgressHealthSnapshot {
		const normUrl = normalizeTaskEgressUrl(config.url);
		if (!normUrl) {
			throw new Error(`EgressPoolManager 拒绝非法出口地址: ${JSON.stringify(config.url)}`);
		}
		const id = (config.id?.trim() || defaultEgressId(normUrl, this.endpoints.length)).replace(/\s+/g, "-");
		const existing = this.byId.get(id);
		if (existing) {
			existing.url = normUrl;
			existing.maskedUrl = maskEgressUrl(normUrl);
			existing.label = config.label;
			existing.priority = typeof config.priority === "number" && Number.isFinite(config.priority) ? config.priority : 100;
			existing.maxInFlight =
				typeof config.maxInFlight === "number" && config.maxInFlight > 0
					? Math.floor(config.maxInFlight)
					: undefined;
			return this.snapshotOf(existing);
		}

		const entry: EgressEndpointInternal = {
			id,
			url: normUrl,
			maskedUrl: maskEgressUrl(normUrl),
			...(config.label ? { label: config.label } : {}),
			priority: typeof config.priority === "number" && Number.isFinite(config.priority) ? config.priority : 100,
			...(typeof config.maxInFlight === "number" && config.maxInFlight > 0
				? { maxInFlight: Math.floor(config.maxInFlight) }
				: {}),
			inFlight: 0,
			totalRequests: 0,
			consecutiveFailures: 0,
			state: "healthy",
			samples: [],
		};
		this.endpoints.push(entry);
		this.byId.set(id, entry);
		return this.snapshotOf(entry);
	}

	/** 池内出口总数。 */
	size(): number {
		return this.endpoints.length;
	}

	/** 刷新已过熔断冷却期的出口状态（从 open 恢复至 degraded 半开态供再次探活）。 */
	private refreshCircuits(now: number): void {
		for (const ep of this.endpoints) {
			if (ep.state === "open" && ep.circuitOpenUntil !== undefined && now >= ep.circuitOpenUntil) {
				ep.state = "degraded";
				ep.circuitOpenUntil = undefined;
				ep.consecutiveFailures = Math.max(0, this.consecutiveFailureThreshold - 1);
			}
		}
	}

	private computeMetrics(ep: EgressEndpointInternal): {
		avgTtfbMs: number;
		p95TtfbMs: number;
		errorRate: number;
		resetRate: number;
	} {
		const n = ep.samples.length;
		if (n === 0) {
			return { avgTtfbMs: 0, p95TtfbMs: 0, errorRate: 0, resetRate: 0 };
		}
		let errCount = 0;
		let resetCount = 0;
		const ttfbs: number[] = [];
		for (const s of ep.samples) {
			if (s.isError || s.isBlocked) errCount++;
			if (s.isReset) resetCount++;
			if (typeof s.ttfbMs === "number" && Number.isFinite(s.ttfbMs) && s.ttfbMs >= 0) {
				ttfbs.push(s.ttfbMs);
			}
		}
		const avgTtfbMs = ttfbs.length > 0 ? Math.round(ttfbs.reduce((a, b) => a + b, 0) / ttfbs.length) : 0;
		const p95TtfbMs = ttfbs.length > 0 ? Math.round(percentile95(ttfbs)) : 0;
		return {
			avgTtfbMs,
			p95TtfbMs,
			errorRate: Number((errCount / n).toFixed(4)),
			resetRate: Number((resetCount / n).toFixed(4)),
		};
	}

	private snapshotOf(ep: EgressEndpointInternal): EgressHealthSnapshot {
		const m = this.computeMetrics(ep);
		return {
			id: ep.id,
			url: ep.url,
			maskedUrl: ep.maskedUrl,
			...(ep.label ? { label: ep.label } : {}),
			priority: ep.priority,
			state: ep.state,
			inFlight: ep.inFlight,
			...(ep.maxInFlight !== undefined ? { maxInFlight: ep.maxInFlight } : {}),
			totalRequests: ep.totalRequests,
			windowSamples: ep.samples.length,
			avgTtfbMs: m.avgTtfbMs,
			p95TtfbMs: m.p95TtfbMs,
			errorRate: m.errorRate,
			resetRate: m.resetRate,
			consecutiveFailures: ep.consecutiveFailures,
			...(ep.circuitOpenUntil !== undefined ? { circuitOpenUntil: ep.circuitOpenUntil } : {}),
			...(ep.lastFailureReason ? { lastFailureReason: ep.lastFailureReason } : {}),
			...(ep.lastUpdatedAt !== undefined ? { lastUpdatedAt: ep.lastUpdatedAt } : {}),
		};
	}

	/** 获取单个出口的健康度快照。 */
	getHealth(id: string): EgressHealthSnapshot | undefined {
		this.refreshCircuits(this.nowFn());
		const ep = this.byId.get(id);
		return ep ? this.snapshotOf(ep) : undefined;
	}

	/** 获取全部出口的健康度快照列表。 */
	getSnapshot(): EgressHealthSnapshot[] {
		this.refreshCircuits(this.nowFn());
		return this.endpoints.map((ep) => this.snapshotOf(ep));
	}

	/** 手动重置指定出口或全部出口的健康状态。 */
	reset(id?: string): void {
		const targets = id ? [this.byId.get(id)].filter((x): x is EgressEndpointInternal => Boolean(x)) : this.endpoints;
		for (const ep of targets) {
			ep.samples = [];
			ep.consecutiveFailures = 0;
			ep.state = "healthy";
			ep.circuitOpenUntil = undefined;
			ep.lastFailureReason = undefined;
		}
	}

	/**
	 * 记录一次出口请求观测并重新评估健康状态与熔断开关。
	 */
	record(id: string, obs: EgressObservation): EgressHealthSnapshot | undefined {
		const ep = this.byId.get(id);
		if (!ep) return undefined;
		const now = this.nowFn();

		const status = typeof obs.statusCode === "number" && Number.isFinite(obs.statusCode) ? obs.statusCode : undefined;
		const isReset = Boolean(
			obs.connectionReset ||
				(typeof obs.exitCode === "number" && EGRESS_RESET_CURL_EXIT_CODES.has(obs.exitCode)) ||
				(obs.error && EGRESS_RESET_ERROR_RE.test(obs.error)),
		);
		const isBlocked = Boolean(obs.blocked);
		const isHttpError = status !== undefined && (status === 403 || status === 429 || (status >= 500 && status < 600));
		const isError = isBlocked || isHttpError;
		const ttfbMs = typeof obs.ttfbMs === "number" && Number.isFinite(obs.ttfbMs) && obs.ttfbMs >= 0 ? obs.ttfbMs : undefined;
		const isSlow = ttfbMs !== undefined && ttfbMs > this.maxTtfbMs;

		const explicitFail = obs.ok === false;
		const isFailure = explicitFail || isReset || isError;

		const reasonParts: string[] = [];
		if (isBlocked) reasonParts.push("egress_blocked");
		if (status !== undefined && isHttpError) reasonParts.push(`http_${status}`);
		if (isReset) reasonParts.push(obs.exitCode !== undefined ? `reset_exit_${obs.exitCode}` : "connection_reset");
		if (isSlow) reasonParts.push(`slow_ttfb_${Math.round(ttfbMs!)}ms`);
		if (obs.error) reasonParts.push(obs.error);

		ep.totalRequests += 1;
		ep.lastUpdatedAt = now;
		ep.samples.push({
			ts: now,
			ok: !isFailure,
			isError,
			isReset,
			isBlocked,
			...(ttfbMs !== undefined ? { ttfbMs } : {}),
			...(status !== undefined ? { statusCode: status } : {}),
			...(reasonParts.length > 0 ? { reason: reasonParts.join("; ") } : {}),
		});
		if (ep.samples.length > this.windowSize) {
			ep.samples.splice(0, ep.samples.length - this.windowSize);
		}

		if (isFailure) {
			ep.consecutiveFailures += 1;
			ep.lastFailureReason = reasonParts.join("; ") || "request_failed";
		} else {
			ep.consecutiveFailures = 0;
			if (!isSlow) {
				ep.lastFailureReason = undefined;
			} else {
				ep.lastFailureReason = `slow_ttfb_${Math.round(ttfbMs!)}ms`;
			}
		}

		const m = this.computeMetrics(ep);
		const enoughSamples = ep.samples.length >= this.minSamplesForRate;

		let tripReason: string | undefined;
		if (ep.consecutiveFailures >= this.consecutiveFailureThreshold) {
			tripReason = `连续失败 ${ep.consecutiveFailures} 次 (${ep.lastFailureReason ?? "error"})`;
		} else if (enoughSamples && m.resetRate >= this.maxResetRate) {
			tripReason = `连接重置率 ${(m.resetRate * 100).toFixed(0)}% >= ${(this.maxResetRate * 100).toFixed(0)}%`;
		} else if (enoughSamples && m.errorRate >= this.maxErrorRate) {
			tripReason = `403/5xx 错误率 ${(m.errorRate * 100).toFixed(0)}% >= ${(this.maxErrorRate * 100).toFixed(0)}%`;
		} else if (enoughSamples && m.avgTtfbMs > this.maxTtfbMs) {
			tripReason = `平均 TTFB ${m.avgTtfbMs}ms > 阈值 ${this.maxTtfbMs}ms`;
		}

		if (tripReason) {
			ep.state = "open";
			ep.circuitOpenUntil = now + this.cooldownMs;
			ep.lastFailureReason = tripReason;
		} else if (
			isSlow ||
			ep.consecutiveFailures > 0 ||
			m.errorRate >= this.maxErrorRate * 0.5 ||
			m.resetRate >= this.maxResetRate * 0.5 ||
			m.avgTtfbMs > this.maxTtfbMs * 0.75
		) {
			ep.state = "degraded";
			ep.circuitOpenUntil = undefined;
		} else {
			ep.state = "healthy";
			ep.circuitOpenUntil = undefined;
		}

		return this.snapshotOf(ep);
	}

	/**
	 * 为当前 worker 申请一个可用出口租约：
	 * - 自动过滤熔断中的出口并跳过 `excludeIds`（支持单次任务内故障转移）；
	 * - 优先使用 `healthy` 出口，其次 `degraded` 出口；
	 * - 支持 `least-loaded`（最少负载 + 轮询打破平局）与 `round-robin`，避免并发抢占单一出口；
	 * - 全部熔断且开启 `allowDegradedFallback` 时，可控降级到错误率最低的出口并标记 `lease.degraded = true`。
	 */
	acquire(opts?: string | { workerId?: string; excludeIds?: readonly string[]; allowDegradedFallback?: boolean }): EgressLease | null {
		if (this.endpoints.length === 0) return null;
		const now = this.nowFn();
		this.refreshCircuits(now);

		const workerId = typeof opts === "string" ? opts : opts?.workerId;
		const excludeSet = new Set(typeof opts === "string" ? [] : (opts?.excludeIds ?? []));
		const allowFallback =
			typeof opts === "object" && opts?.allowDegradedFallback !== undefined
				? opts.allowDegradedFallback
				: this.allowDegradedFallback;

		const hasCapacity = (ep: EgressEndpointInternal) =>
			ep.maxInFlight === undefined || ep.inFlight < ep.maxInFlight;

		const rotated = (): EgressEndpointInternal[] => {
			const len = this.endpoints.length;
			const start = this.rrCursor % len;
			const arr: EgressEndpointInternal[] = [];
			for (let i = 0; i < len; i++) {
				arr.push(this.endpoints[(start + i) % len]!);
			}
			return arr;
		};

		const order = rotated();
		const eligible = order.filter((ep) => !excludeSet.has(ep.id) && ep.state !== "open" && hasCapacity(ep));

		let chosen: EgressEndpointInternal | undefined;
		let isDegradedFallback = false;

		if (eligible.length > 0) {
			const healthyOnly = eligible.filter((ep) => ep.state === "healthy");
			const tier = healthyOnly.length > 0 ? healthyOnly : eligible;
			if (this.strategy === "round-robin") {
				chosen = tier[0];
			} else {
				// least-loaded：先按 inFlight 最少，再按 priority 最小，平局保留轮询先后顺序
				let best = tier[0]!;
				for (let i = 1; i < tier.length; i++) {
					const cand = tier[i]!;
					if (
						cand.inFlight < best.inFlight ||
						(cand.inFlight === best.inFlight && cand.priority < best.priority)
					) {
						best = cand;
					}
				}
				chosen = best;
			}
			isDegradedFallback = chosen!.state === "degraded";
		} else if (allowFallback) {
			const fallbackCandidates = order.filter((ep) => !excludeSet.has(ep.id) && hasCapacity(ep));
			if (fallbackCandidates.length > 0) {
				fallbackCandidates.sort((a, b) => {
					const ma = this.computeMetrics(a);
					const mb = this.computeMetrics(b);
					return (
						ma.resetRate + ma.errorRate - (mb.resetRate + mb.errorRate) ||
						a.inFlight - b.inFlight ||
						a.priority - b.priority
					);
				});
				chosen = fallbackCandidates[0];
				isDegradedFallback = true;
			}
		}

		if (!chosen) return null;

		const chosenIdx = this.endpoints.indexOf(chosen);
		this.rrCursor = (chosenIdx + 1) % this.endpoints.length;
		chosen.inFlight += 1;

		let released = false;
		const release = (obs?: EgressObservation) => {
			if (released) return;
			released = true;
			chosen!.inFlight = Math.max(0, chosen!.inFlight - 1);
			if (obs) {
				this.record(chosen!.id, obs);
			}
		};

		return {
			id: chosen.id,
			url: chosen.url,
			maskedUrl: chosen.maskedUrl,
			...(chosen.label ? { label: chosen.label } : {}),
			degraded: isDegradedFallback,
			...(workerId ? { workerId } : {}),
			acquiredAt: now,
			release,
		};
	}

	/** 批量主动探测所有出口的门控健康度。 */
	async probeAll(
		probeFn: (ep: { id: string; url: string; label?: string }) => Promise<EgressObservation>,
	): Promise<EgressHealthSnapshot[]> {
		const out: EgressHealthSnapshot[] = [];
		for (const ep of this.endpoints) {
			try {
				const obs = await probeFn({ id: ep.id, url: ep.url, label: ep.label });
				const snap = this.record(ep.id, obs);
				if (snap) out.push(snap);
			} catch (err) {
				const snap = this.record(ep.id, {
					ok: false,
					connectionReset: true,
					error: err instanceof Error ? err.message : String(err),
				});
				if (snap) out.push(snap);
			}
		}
		return out;
	}
}
