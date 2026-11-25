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
import { lookup as dnsLookupAll } from "node:dns/promises";
import { chmodSync, mkdirSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
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

// ══════════════════════════════════════════════════════════════════════════════
// v5.0 内置 Scoped Egress Proxy（HTTP 正向代理 + HTTPS CONNECT 隧道 + 防 DNS 重绑定）
// ══════════════════════════════════════════════════════════════════════════════

export interface EgressTrafficRecord {
	ts: string;
	method: string;
	url: string;
	host: string;
	port: number;
	resolvedIps?: string[];
	status: number;
	allowed: boolean;
	reason?: string;
	responsePreview?: string;
}

export interface EgressProxyOptions {
	host?: string;
	port?: number;
	timeoutMs?: number;
	dnsLookup?: (hostname: string) => Promise<string[]>;
	onTraffic?: (rec: EgressTrafficRecord) => void;
}

export interface ScopedEgressProxyHandle {
	host: string;
	port: number;
	url: string;
	stats: () => { allowed: number; blocked: number; total: number };
	close: () => Promise<void>;
}

export interface EgressTargetValidation {
	ok: boolean;
	hostname: string;
	resolvedIps: string[];
	reason?: string;
}

function normalizeEgressHost(raw: string): string {
	let s = String(raw ?? "").trim();
	if (s.startsWith("[") && s.endsWith("]")) {
		s = s.slice(1, -1);
	}
	return s.replace(/\.+$/, "").toLowerCase();
}

function parseIpv4Int(ip: string): number | null {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
	if (!m) return null;
	let acc = 0;
	for (let i = 1; i <= 4; i++) {
		const part = m[i]!;
		if (part.length > 1 && part.startsWith("0")) return null;
		const n = Number(part);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		acc = ((acc << 8) | n) >>> 0;
	}
	return acc >>> 0;
}

function parseIpv4Cidr(cidr: string): { net: number; mask: number } | null {
	const slash = cidr.indexOf("/");
	if (slash < 0) return null;
	const ipPart = cidr.slice(0, slash).trim();
	const prefixPart = cidr.slice(slash + 1).trim();
	if (!/^\d{1,2}$/.test(prefixPart)) return null;
	const prefix = Number(prefixPart);
	if (prefix < 0 || prefix > 32) return null;
	const ip = parseIpv4Int(ipPart);
	if (ip === null) return null;
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return { net: (ip & mask) >>> 0, mask };
}

/** 提取纯 IPv4 或 IPv4-mapped IPv6（如 ::ffff:169.254.169.254 / ::ffff:a9fe:a9fe）对应的 32 位 IPv4 整数。 */
function extractMappedIpv4Int(ip: string): number | null {
	const norm = normalizeEgressHost(ip);
	const direct = parseIpv4Int(norm);
	if (direct !== null) return direct;
	if (norm.startsWith("::ffff:")) {
		const tail = norm.slice(7);
		const dotted = parseIpv4Int(tail);
		if (dotted !== null) return dotted;
		const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(tail);
		if (hexMatch) {
			const hi = Number.parseInt(hexMatch[1]!, 16);
			const lo = Number.parseInt(hexMatch[2]!, 16);
			return (((hi << 16) | lo) >>> 0);
		}
	}
	return null;
}

function isLinkLocalOrMetadataIp(ip: string): boolean {
	const v4 = extractMappedIpv4Int(ip);
	if (v4 !== null) {
		const b0 = (v4 >>> 24) & 0xff;
		const b1 = (v4 >>> 16) & 0xff;
		// 169.254.0.0/16 链路本地与云元数据（169.254.169.254 / 169.254.170.2 等）
		return b0 === 169 && b1 === 254;
	}
	const norm = normalizeEgressHost(ip);
	// IPv6 链路本地 fe80::/10
	return /^fe[89ab][0-9a-f]:/i.test(norm) || norm === "fe80::";
}

function isLoopbackOrUnspecifiedIp(ip: string): boolean {
	const v4 = extractMappedIpv4Int(ip);
	if (v4 !== null) {
		const b0 = (v4 >>> 24) & 0xff;
		return b0 === 127 || b0 === 0;
	}
	const norm = normalizeEgressHost(ip);
	return (
		norm === "::1" ||
		norm === "::" ||
		norm === "0:0:0:0:0:0:0:1" ||
		norm === "0:0:0:0:0:0:0:0"
	);
}

function isPrivateRangeIp(ip: string): boolean {
	const v4 = extractMappedIpv4Int(ip);
	if (v4 !== null) {
		const b0 = (v4 >>> 24) & 0xff;
		const b1 = (v4 >>> 16) & 0xff;
		if (b0 === 10) return true;
		if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
		if (b0 === 192 && b1 === 168) return true;
		return false;
	}
	const norm = normalizeEgressHost(ip);
	// IPv6 Unique Local Address fc00::/7
	return /^f[cd][0-9a-f]{2}:/i.test(norm);
}

function ipMatchesExplicitPattern(ip: string, rawPattern: string): boolean {
	const pat = normalizeEgressHost(rawPattern);
	if (!pat || pat === "*" || pat.startsWith("*.")) return false;
	const normIp = normalizeEgressHost(ip);
	if (normIp === pat) return true;

	const v4 = extractMappedIpv4Int(normIp);
	if (v4 !== null) {
		const patV4 = extractMappedIpv4Int(pat);
		if (patV4 !== null && patV4 === v4) return true;
		const cidr = parseIpv4Cidr(pat);
		if (cidr && ((v4 & cidr.mask) >>> 0) === cidr.net) return true;
	}
	return false;
}

function isIpExplicitlyAllowed(ip: string, scope: ScopePolicy): boolean {
	for (const a of scope.allowHosts ?? []) {
		if (ipMatchesExplicitPattern(ip, a)) return true;
	}
	for (const c of scope.allowCidrs ?? []) {
		if (ipMatchesExplicitPattern(ip, c)) return true;
	}
	return false;
}

function isIpInDenyHosts(ip: string, scope: ScopePolicy): string | null {
	const normIp = normalizeEgressHost(ip);
	const ipLoopback = isLoopbackOrUnspecifiedIp(normIp);
	for (const rawDeny of scope.denyHosts ?? []) {
		const deny = normalizeEgressHost(rawDeny);
		if (!deny) continue;
		if (deny === "*") return rawDeny;
		if (ipMatchesExplicitPattern(normIp, deny)) return rawDeny;
		if (ipLoopback && (deny === "localhost" || deny.endsWith(".localhost") || isLoopbackOrUnspecifiedIp(deny))) {
			return rawDeny;
		}
	}
	return null;
}

async function defaultDnsLookup(hostname: string): Promise<string[]> {
	const records = await dnsLookupAll(hostname, { all: true, verbatim: true });
	const seen = new Set<string>();
	const out: string[] = [];
	for (const rec of records) {
		const addr = normalizeEgressHost(rec.address);
		if (addr && !seen.has(addr)) {
			seen.add(addr);
			out.push(addr);
		}
	}
	return out;
}

/**
 * 校验出站代理目标主机名与真实 DNS 解析结果，防止 DNS 重绑定至云元数据、禁用的回环或未授权私网。
 */
export async function validateEgressTarget(
	hostname: string,
	scope: ScopePolicy,
	dnsLookup?: (hostname: string) => Promise<string[]>,
): Promise<EgressTargetValidation> {
	const normHost = normalizeEgressHost(hostname);
	if (!normHost) {
		return { ok: false, hostname: "", resolvedIps: [], reason: "nuwa-egress N-007: 目标主机为空" };
	}

	const hostRes = isHostInScope(normHost, scope);
	if (!hostRes.ok) {
		return {
			ok: false,
			hostname: normHost,
			resolvedIps: [],
			reason: `nuwa-egress N-007: ${hostRes.reason ?? "目标不在授权 Scope 内"}`,
		};
	}

	// 1. 若目标本身为 IP 字面量，仍需强制拦截未显式授权的链路本地/云元数据地址（即使 allowHosts 含 *）
	if (net.isIP(normHost) !== 0) {
		if (isLinkLocalOrMetadataIp(normHost) && !isIpExplicitlyAllowed(normHost, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps: [normHost],
				reason: `nuwa-egress N-007: 禁止访问链路本地/云元数据地址 (${normHost})`,
			};
		}
		return { ok: true, hostname: normHost, resolvedIps: [normHost] };
	}

	// 2. 域名目标：解析真实 IP 并逐一核验，消除 TOCTOU DNS 重绑定窗口
	const resolver = dnsLookup ?? defaultDnsLookup;
	let rawIps: string[];
	try {
		rawIps = await resolver(normHost);
	} catch (err) {
		return {
			ok: false,
			hostname: normHost,
			resolvedIps: [],
			reason: `nuwa-egress N-007: DNS 解析失败 (${normHost}) — ${err instanceof Error ? err.message : String(err)}`,
		};
	}

	const resolvedIps: string[] = [];
	const seen = new Set<string>();
	for (const raw of rawIps ?? []) {
		const ip = normalizeEgressHost(raw);
		if (!ip || net.isIP(ip) === 0) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 返回非法 IP 地址 (${String(raw)})`,
			};
		}
		if (!seen.has(ip)) {
			seen.add(ip);
			resolvedIps.push(ip);
		}
	}

	if (resolvedIps.length === 0) {
		return {
			ok: false,
			hostname: normHost,
			resolvedIps: [],
			reason: `nuwa-egress N-007: DNS 未解析到有效 IP (${normHost})`,
		};
	}

	for (const ip of resolvedIps) {
		const deniedBy = isIpInDenyHosts(ip, scope);
		if (deniedBy) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 命中 denyHosts ${deniedBy})`,
			};
		}
		if (isLinkLocalOrMetadataIp(ip) && !isIpExplicitlyAllowed(ip, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 为云元数据/链路本地地址)`,
			};
		}
		if (isLoopbackOrUnspecifiedIp(ip) && scope.allowLoopback === false && !isIpExplicitlyAllowed(ip, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 为回环地址且 allowLoopback=false)`,
			};
		}
		if (isPrivateRangeIp(ip) && !scope.allowPrivateNetwork && !isIpExplicitlyAllowed(ip, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 为未授权私网地址且 allowPrivateNetwork=false)`,
			};
		}
	}

	return { ok: true, hostname: normHost, resolvedIps };
}

function parseConnectAuthority(raw: string): { host: string; port: number } | null {
	const s = String(raw ?? "").trim();
	if (!s) return null;
	if (s.startsWith("[")) {
		const m = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(s);
		if (!m) return null;
		const port = m[2] ? Number(m[2]) : 443;
		if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
		return { host: m[1]!, port };
	}
	const lastColon = s.lastIndexOf(":");
	if (lastColon > 0) {
		const host = s.slice(0, lastColon);
		const portStr = s.slice(lastColon + 1);
		if (!/^\d{1,5}$/.test(portStr)) return null;
		const port = Number(portStr);
		if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
		return { host, port };
	}
	return { host: s, port: 443 };
}

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const PREVIEW_MAX_BYTES = 2048;

/**
 * 启动内置零信任 Scoped Egress Proxy（HTTP 正向代理 + HTTPS CONNECT 隧道）：
 * - 对目标主机名与真实 DNS 解析 IP 执行防 DNS 重绑定校验，并直连已校验 IP 消除 TOCTOU；
 * - 拦截越界主机、云元数据（169.254.0.0/16）、未授权私网/回环与越界 30x 重定向（返回 403 `nuwa-egress N-007`）；
 * - 支持 `onTraffic` 回调采集响应前 2048 字节预览与统计计数；
 * - `close()` 立即销毁所有活跃连接并释放监听端口。
 */
export async function startScopedEgressProxy(
	scope: ScopePolicy,
	opts?: EgressProxyOptions,
): Promise<ScopedEgressProxyHandle> {
	const bindHost = opts?.host ?? "127.0.0.1";
	const bindPort = opts?.port ?? 0;
	const timeoutMs =
		typeof opts?.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
			? Math.floor(opts.timeoutMs)
			: 15_000;

	let allowedCount = 0;
	let blockedCount = 0;
	let closed = false;
	const openSockets = new Set<net.Socket>();

	const trackSocket = (sock: net.Socket): void => {
		openSockets.add(sock);
		sock.once("close", () => {
			openSockets.delete(sock);
		});
	};

	const emitTraffic = (rec: EgressTrafficRecord): void => {
		if (!opts?.onTraffic) return;
		try {
			opts.onTraffic(rec);
		} catch {
			/* 观测回调异常不影响代理主流程 */
		}
	};

	const httpServer = http.createServer();
	httpServer.on("connection", (sock) => {
		trackSocket(sock);
	});

	const sendErrorAndClose = (
		req: http.IncomingMessage,
		res: http.ServerResponse,
		statusCode: number,
		body: string,
	): void => {
		res.shouldKeepAlive = false;
		if (!res.headersSent) {
			res.writeHead(statusCode, { "Content-Type": "text/plain; charset=utf-8", Connection: "close" });
		}
		if (!res.writableEnded) {
			res.end(body, () => {
				try {
					req.socket?.end();
				} catch {
					/* ignore */
				}
			});
		}
	};

	httpServer.on("request", async (req, res) => {
		req.pause();
		const method = req.method ?? "GET";
		const rawReqUrl = String(req.url ?? "");
		const clientWantsClose = String(req.headers.connection ?? "").toLowerCase().includes("close");
		let targetUrl: URL;
		try {
			if (/^https?:\/\//i.test(rawReqUrl)) {
				targetUrl = new URL(rawReqUrl);
			} else if (req.headers.host) {
				targetUrl = new URL(rawReqUrl || "/", `http://${req.headers.host}`);
			} else {
				throw new Error("缺少有效绝对代理 URL");
			}
		} catch (err) {
			blockedCount++;
			const reason = `nuwa-egress N-007: 非法代理请求 URL (${rawReqUrl}) — ${err instanceof Error ? err.message : String(err)}`;
			sendErrorAndClose(req, res, 400, reason);
			emitTraffic({
				ts: new Date().toISOString(),
				method,
				url: rawReqUrl,
				host: "",
				port: 0,
				status: 400,
				allowed: false,
				reason,
			});
			return;
		}

		const hostname = normalizeEgressHost(targetUrl.hostname);
		const isHttps = targetUrl.protocol === "https:";
		const port = targetUrl.port ? Number(targetUrl.port) : isHttps ? 443 : 80;
		const fullUrlStr = targetUrl.toString();

		const check = await validateEgressTarget(hostname, scope, opts?.dnsLookup);
		if (!check.ok || check.resolvedIps.length === 0) {
			blockedCount++;
			const reason = check.reason ?? `nuwa-egress N-007: 目标越界 (${hostname})`;
			sendErrorAndClose(req, res, 403, reason);
			emitTraffic({
				ts: new Date().toISOString(),
				method,
				url: fullUrlStr,
				host: hostname,
				port,
				...(check.resolvedIps.length > 0 ? { resolvedIps: check.resolvedIps } : {}),
				status: 403,
				allowed: false,
				reason,
			});
			return;
		}

		const targetIp = check.resolvedIps[0]!;
		const outHeaders: http.OutgoingHttpHeaders = {};
		for (const [k, v] of Object.entries(req.headers)) {
			const lower = k.toLowerCase();
			if (lower === "proxy-connection" || lower === "proxy-authorization" || lower === "proxy-authenticate") {
				continue;
			}
			if (v !== undefined) outHeaders[k] = v;
		}
		outHeaders.host = req.headers.host ?? targetUrl.host;

		let handled = false;
		let recorded = false;
		const recordOnce = (rec: Omit<EgressTrafficRecord, "ts" | "method" | "url" | "host" | "port" | "resolvedIps">) => {
			if (recorded) return;
			recorded = true;
			emitTraffic({
				ts: new Date().toISOString(),
				method,
				url: fullUrlStr,
				host: hostname,
				port,
				resolvedIps: check.resolvedIps,
				...rec,
			});
		};

		const reqOpts: http.RequestOptions & https.RequestOptions = {
			protocol: targetUrl.protocol,
			host: targetIp,
			port,
			method,
			path: `${targetUrl.pathname}${targetUrl.search}`,
			headers: outHeaders,
			timeout: timeoutMs,
			...(isHttps && net.isIP(hostname) === 0 ? { servername: hostname } : {}),
		};

		const upReq = (isHttps ? https.request : http.request)(reqOpts, async (upRes) => {
			upRes.pause();
			const status = upRes.statusCode ?? 502;

			if (REDIRECT_STATUS_CODES.has(status) && upRes.headers.location) {
				const rawLoc = Array.isArray(upRes.headers.location)
					? upRes.headers.location[0]
					: upRes.headers.location;
				if (rawLoc) {
					let nextUrl: URL | null = null;
					try {
						nextUrl = new URL(rawLoc, fullUrlStr);
					} catch {
						nextUrl = null;
					}
					if (!nextUrl || (nextUrl.protocol !== "http:" && nextUrl.protocol !== "https:")) {
						handled = true;
						upRes.destroy();
						upReq.destroy();
						blockedCount++;
						const reason = `nuwa-egress N-007: 阻断越界 30x 重定向至非法协议 (${rawLoc})`;
						sendErrorAndClose(req, res, 403, reason);
						recordOnce({ status: 403, allowed: false, reason });
						return;
					}
					const nextHost = normalizeEgressHost(nextUrl.hostname);
					const redirCheck = await validateEgressTarget(nextHost, scope, opts?.dnsLookup);
					if (!redirCheck.ok) {
						handled = true;
						upRes.destroy();
						upReq.destroy();
						blockedCount++;
						const reason = `nuwa-egress N-007: 阻断越界 30x 重定向至 ${nextHost} (${redirCheck.reason ?? "不在授权范围内"})`;
						sendErrorAndClose(req, res, 403, reason);
						recordOnce({ status: 403, allowed: false, reason });
						return;
					}
				}
			}

			allowedCount++;
			const previewChunks: Buffer[] = [];
			let previewLen = 0;

			if (clientWantsClose) {
				res.shouldKeepAlive = false;
			}
			if (upRes.headers.date) {
				res.sendDate = false;
			}
			if (!res.headersSent) {
				res.writeHead(status, upRes.headers);
			}

			upRes.on("data", (chunk: Buffer | string) => {
				const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
				if (previewLen < PREVIEW_MAX_BYTES) {
					const remaining = PREVIEW_MAX_BYTES - previewLen;
					previewChunks.push(buf.length <= remaining ? buf : buf.subarray(0, remaining));
					previewLen += Math.min(buf.length, remaining);
				}
				if (!res.destroyed) {
					const ok = res.write(buf);
					if (!ok) {
						upRes.pause();
						res.once("drain", () => {
							if (!upRes.destroyed) upRes.resume();
						});
					}
				}
			});

			upRes.on("end", () => {
				handled = true;
				if (!res.writableEnded) {
					res.end(() => {
						if (clientWantsClose) {
							try {
								req.socket?.end();
							} catch {
								/* ignore */
							}
						}
					});
				}
				const responsePreview =
					previewChunks.length > 0 ? Buffer.concat(previewChunks).toString("utf8") : undefined;
				recordOnce({
					status,
					allowed: true,
					...(responsePreview !== undefined ? { responsePreview } : {}),
				});
			});

			upRes.on("error", (err) => {
				if (handled) return;
				handled = true;
				if (!res.writableEnded) {
					res.destroy(err);
				}
				const responsePreview =
					previewChunks.length > 0 ? Buffer.concat(previewChunks).toString("utf8") : undefined;
				recordOnce({
					status,
					allowed: true,
					reason: err.message,
					...(responsePreview !== undefined ? { responsePreview } : {}),
				});
			});

			upRes.resume();
		});

		upReq.on("timeout", () => {
			upReq.destroy(new Error(`上游连接超时 (${timeoutMs}ms)`));
		});

		upReq.on("error", (err) => {
			if (handled) return;
			handled = true;
			sendErrorAndClose(req, res, 502, `nuwa-egress 502: ${err.message}`);
			recordOnce({ status: 502, allowed: true, reason: err.message });
		});

		req.on("error", () => {
			upReq.destroy();
		});
		res.on("close", () => {
			if (!res.writableEnded) {
				upReq.destroy();
			}
		});

		req.pipe(upReq);
		req.resume();
	});

	const handleConnect = async (rawTarget: string, sock: net.Socket, head: Buffer): Promise<void> => {
		const parsed = parseConnectAuthority(rawTarget);
		if (!parsed) {
			blockedCount++;
			const reason = `nuwa-egress N-007: 非法 CONNECT 目标 (${rawTarget})`;
			if (!sock.destroyed) {
				sock.end(
					`HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n${reason}\r\n`,
				);
			}
			emitTraffic({
				ts: new Date().toISOString(),
				method: "CONNECT",
				url: rawTarget,
				host: "",
				port: 0,
				status: 400,
				allowed: false,
				reason,
			});
			return;
		}

		const hostname = normalizeEgressHost(parsed.host);
		const port = parsed.port;
		const check = await validateEgressTarget(hostname, scope, opts?.dnsLookup);
		if (!check.ok || check.resolvedIps.length === 0) {
			blockedCount++;
			const reason = check.reason ?? `nuwa-egress N-007: 目标越界 (${hostname})`;
			if (!sock.destroyed) {
				sock.end(
					`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n${reason}\r\n`,
				);
			}
			emitTraffic({
				ts: new Date().toISOString(),
				method: "CONNECT",
				url: `${hostname}:${port}`,
				host: hostname,
				port,
				...(check.resolvedIps.length > 0 ? { resolvedIps: check.resolvedIps } : {}),
				status: 403,
				allowed: false,
				reason,
			});
			return;
		}

		const targetIp = check.resolvedIps[0]!;
		const upstream = net.connect({ host: targetIp, port });
		trackSocket(upstream);
		upstream.setTimeout(timeoutMs);

		let established = false;
		let recorded = false;
		const recordConnectOnce = (status: number, allowed: boolean, reason?: string) => {
			if (recorded) return;
			recorded = true;
			emitTraffic({
				ts: new Date().toISOString(),
				method: "CONNECT",
				url: `${hostname}:${port}`,
				host: hostname,
				port,
				resolvedIps: check.resolvedIps,
				status,
				allowed,
				...(reason ? { reason } : {}),
			});
		};

		upstream.once("connect", () => {
			established = true;
			allowedCount++;
			upstream.setTimeout(0);
			if (sock.destroyed) {
				upstream.destroy();
				return;
			}
			sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			if (head && head.length > 0) {
				upstream.write(head);
			}
			upstream.pipe(sock);
			sock.pipe(upstream);
			sock.resume();
			recordConnectOnce(200, true);
		});

		upstream.on("timeout", () => {
			upstream.destroy(new Error(`CONNECT 上游超时 (${timeoutMs}ms)`));
		});

		upstream.on("error", (err) => {
			if (!established && !sock.destroyed) {
				sock.end(
					`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nnuwa-egress 502: ${err.message}\r\n`,
				);
			} else if (!sock.destroyed) {
				sock.destroy();
			}
			recordConnectOnce(502, true, err.message);
		});

		sock.on("error", () => {
			if (!upstream.destroyed) upstream.destroy();
		});
		sock.on("close", () => {
			if (!upstream.destroyed) upstream.destroy();
		});
		upstream.on("close", () => {
			if (!sock.destroyed) sock.destroy();
		});
	};

	await new Promise<void>((resolve, reject) => {
		const onError = (err: Error) => {
			httpServer.off("listening", onListening);
			reject(err);
		};
		const onListening = () => {
			httpServer.off("error", onError);
			resolve();
		};
		httpServer.once("error", onError);
		httpServer.once("listening", onListening);
		httpServer.listen(0, "127.0.0.1");
	});

	const innerAddr = httpServer.address();
	const httpPort = typeof innerAddr === "object" && innerAddr ? innerAddr.port : 0;

	const CONNECT_PREFIX = "CONNECT ";
	const MAX_CONNECT_HEADER_BYTES = 16 * 1024;

	const tcpServer = net.createServer((clientSock) => {
		trackSocket(clientSock);
		clientSock.setTimeout(timeoutMs);

		let peekBuf: Buffer = Buffer.alloc(0);
		let routed = false;

		const cleanupSniff = () => {
			clientSock.off("data", onSniffData);
			clientSock.off("timeout", onSniffTimeout);
		};

		const onSniffTimeout = () => {
			if (!routed) {
				cleanupSniff();
				clientSock.destroy();
			}
		};

		const routeToHttp = (initialBuf: Buffer) => {
			routed = true;
			cleanupSniff();
			clientSock.pause();
			clientSock.setTimeout(0);
			const inner = net.connect({ host: "127.0.0.1", port: httpPort });
			trackSocket(inner);
			inner.once("connect", () => {
				if (clientSock.destroyed) {
					inner.destroy();
					return;
				}
				if (initialBuf.length > 0) {
					inner.write(initialBuf);
				}
				clientSock.pipe(inner);
				inner.pipe(clientSock);
				clientSock.resume();
			});
			inner.on("error", () => {
				if (!clientSock.destroyed) clientSock.destroy();
			});
			clientSock.on("error", () => {
				if (!inner.destroyed) inner.destroy();
			});
			clientSock.on("close", () => {
				if (!inner.destroyed) inner.destroy();
			});
			inner.on("close", () => {
				if (!clientSock.destroyed) clientSock.destroy();
			});
		};

		const onSniffData = (chunk: Buffer | string) => {
			if (routed) return;
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			peekBuf = peekBuf.length === 0 ? buf : Buffer.concat([peekBuf, buf]);

			const prefixSample = peekBuf
				.subarray(0, Math.min(peekBuf.length, CONNECT_PREFIX.length))
				.toString("latin1")
				.toUpperCase();

			if (!CONNECT_PREFIX.startsWith(prefixSample)) {
				routeToHttp(peekBuf);
				return;
			}

			if (peekBuf.length >= CONNECT_PREFIX.length) {
				const headerEnd = peekBuf.indexOf("\r\n\r\n");
				if (headerEnd >= 0) {
					routed = true;
					cleanupSniff();
					clientSock.pause();
					clientSock.setTimeout(0);
					const headerStr = peekBuf.subarray(0, headerEnd).toString("latin1");
					const firstLine = headerStr.split("\r\n")[0] ?? "";
					const m = /^CONNECT\s+(\S+)\s+HTTP\/1\.[01]$/i.exec(firstLine.trim());
					const head = peekBuf.subarray(headerEnd + 4);
					void handleConnect(m?.[1] ?? "", clientSock, head);
					return;
				}
				if (peekBuf.length > MAX_CONNECT_HEADER_BYTES) {
					routed = true;
					cleanupSniff();
					clientSock.end("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
					clientSock.destroy();
				}
			}
		};

		clientSock.on("data", onSniffData);
		clientSock.once("timeout", onSniffTimeout);
		clientSock.on("error", () => {
			cleanupSniff();
		});
	});

	try {
		await new Promise<void>((resolve, reject) => {
			const onError = (err: Error) => {
				tcpServer.off("listening", onListening);
				reject(err);
			};
			const onListening = () => {
				tcpServer.off("error", onError);
				resolve();
			};
			tcpServer.once("error", onError);
			tcpServer.once("listening", onListening);
			tcpServer.listen(bindPort, bindHost);
		});
	} catch (err) {
		try {
			httpServer.close();
		} catch {
			/* ignore */
		}
		throw err;
	}

	const addr = tcpServer.address();
	const actualPort = typeof addr === "object" && addr ? addr.port : bindPort;
	const actualHost = typeof addr === "object" && addr && addr.address ? addr.address : bindHost;
	const urlHost = actualHost.includes(":") ? `[${actualHost}]` : actualHost;
	const url = `http://${urlHost}:${actualPort}`;

	const closeServer = (srv: net.Server | http.Server): Promise<void> =>
		new Promise<void>((resolve) => {
			const maybeCloseAll = (srv as unknown as { closeAllConnections?: () => void }).closeAllConnections;
			if (typeof maybeCloseAll === "function") {
				try {
					maybeCloseAll.call(srv);
				} catch {
					/* ignore */
				}
			}
			try {
				srv.close(() => resolve());
			} catch {
				resolve();
			}
		});

	return {
		host: actualHost,
		port: actualPort,
		url,
		stats: () => ({
			allowed: allowedCount,
			blocked: blockedCount,
			total: allowedCount + blockedCount,
		}),
		close: async () => {
			if (closed) return;
			closed = true;
			for (const sock of [...openSockets]) {
				try {
					sock.destroy();
				} catch {
					/* ignore */
				}
			}
			openSockets.clear();
			await Promise.all([closeServer(tcpServer), closeServer(httpServer)]);
		},
	};
}
