/**
 * 靶标范围护栏（N-007）、高危破坏性命令拦截（N-008）与 .nuwa 状态目录防篡改（N-003）。
 *
 * 约束：仅使用 import type 引用 ./nuwa，保持运行时零循环依赖。
 */
import type { Mode } from "./nuwa";

export interface ScopePolicy {
	allowHosts: string[];
	allowCidrs: string[];
	denyHosts: string[];
	allowSubdomains: boolean;
	allowPrivateNetwork: boolean;
	allowDestructive: boolean;
}

export interface ScopeBlockVerdict {
	block: true;
	reason: string;
}

const NON_TLD_EXTS = new Set(
	[
		"json",
		"jsonl",
		"md",
		"ts",
		"tsx",
		"js",
		"jsx",
		"mjs",
		"cjs",
		"py",
		"pyc",
		"go",
		"rs",
		"java",
		"php",
		"phtml",
		"phar",
		"jsp",
		"jspx",
		"asp",
		"aspx",
		"rb",
		"pl",
		"sh",
		"bash",
		"zsh",
		"yml",
		"yaml",
		"toml",
		"ini",
		"conf",
		"cfg",
		"config",
		"env",
		"bak",
		"old",
		"orig",
		"tmp",
		"swp",
		"lock",
		"pid",
		"log",
		"txt",
		"csv",
		"tsv",
		"db",
		"sqlite",
		"sqlite3",
		"sql",
		"html",
		"htm",
		"css",
		"scss",
		"less",
		"xml",
		"svg",
		"png",
		"jpg",
		"jpeg",
		"gif",
		"ico",
		"webp",
		"pdf",
		"zip",
		"tar",
		"gz",
		"tgz",
		"bz2",
		"xz",
		"7z",
		"rar",
		"jar",
		"war",
		"bin",
		"exe",
		"dll",
		"so",
		"dylib",
		"pem",
		"crt",
		"cer",
		"key",
		"csr",
		"p12",
		"pfx",
		"nmap",
		"gnmap",
		"cookie",
		"cookies",
		"out",
		"err",
		"sock",
		"service",
		"timer",
		"target",
		"mount",
	],
);

const KNOWN_TLDS = new Set(
	[
		"com",
		"net",
		"org",
		"io",
		"dev",
		"app",
		"ai",
		"co",
		"me",
		"tv",
		"cc",
		"xyz",
		"top",
		"info",
		"biz",
		"online",
		"site",
		"tech",
		"cloud",
		"pro",
		"icu",
		"vip",
		"club",
		"shop",
		"store",
		"work",
		"ink",
		"pub",
		"live",
		"fun",
		"run",
		"lol",
		"gg",
		"sh",
		"so",
		"to",
		"ly",
		"edu",
		"gov",
		"mil",
		"int",
		"arpa",
		"cn",
		"hk",
		"tw",
		"MO",
		"jp",
		"kr",
		"sg",
		"in",
		"au",
		"nz",
		"uk",
		"de",
		"fr",
		"nl",
		"se",
		"no",
		"fi",
		"dk",
		"ch",
		"at",
		"be",
		"es",
		"it",
		"pt",
		"pl",
		"cz",
		"ru",
		"ua",
		"br",
		"ca",
		"us",
		"mx",
		"za",
		"beer",
		"test",
		"example",
		"invalid",
		"localhost",
		"local",
		"internal",
		"lan",
		"corp",
		"home",
		"htb",
		"thm",
		"ctf",
		"lab",
		"box",
		"onion",
	].map((s) => s.toLowerCase()),
);

const CODE_IDENTIFIERS = new Set([
	"sys.argv",
	"sys.stdin",
	"sys.stdout",
	"sys.stderr",
	"sys.exit",
	"sys.path",
	"sys.modules",
	"os.path",
	"os.environ",
	"os.name",
	"socket.timeout",
	"socket.error",
	"urllib.request",
	"urllib.parse",
	"urllib.error",
	"http.client",
	"http.server",
	"concurrent.futures",
	"process.env",
	"process.argv",
	"process.stdout",
	"process.stderr",
	"console.log",
	"console.error",
]);

const INTERPRETER_CMDS = new Set(["python", "python3", "node", "bun", "ruby", "perl", "php"]);

const NET_CLIENT_CMDS = new Set([
	"curl",
	"wget",
	"nmap",
	"masscan",
	"nc",
	"ncat",
	"netcat",
	"socat",
	"telnet",
	"openssl",
	"ping",
	"ping6",
	"dig",
	"nslookup",
	"host",
	"traceroute",
	"tracepath",
	"mtr",
	"whois",
	"ssh",
	"scp",
	"sftp",
	"ftp",
	"ffuf",
	"gobuster",
	"feroxbuster",
	"dirsearch",
	"dirb",
	"wfuzz",
	"nuclei",
	"nikto",
	"wpscan",
	"sqlmap",
	"whatweb",
	"httpx",
	"katana",
	"subfinder",
	"amass",
	"hydra",
	"medusa",
	"ncrack",
	"redis-cli",
	"mysql",
	"psql",
	"pg_isready",
	"mongo",
	"mongosh",
]);

/** 紧跟文件/头部/报文/配置值而非目标主机的 CLI 选项。 */
const NON_HOST_VALUE_FLAGS = new Set([
	"-o",
	"--output",
	"-D",
	"--dump-header",
	"-b",
	"--cookie",
	"-c",
	"--cookie-jar",
	"-d",
	"--data",
	"--data-raw",
	"--data-binary",
	"--data-urlencode",
	"--data-ascii",
	"-F",
	"--form",
	"-H",
	"--header",
	"-A",
	"--user-agent",
	"-e",
	"--referer",
	"-X",
	"--request",
	"-T",
	"--upload-file",
	"-K",
	"--config",
	"--cacert",
	"--capath",
	"-CAfile",
	"-CApath",
	"--cert",
	"--key",
	"-cert",
	"-key",
	"-in",
	"-out",
	"-w",
	"--write-out",
	"-m",
	"--max-time",
	"--connect-timeout",
	"-oN",
	"-oX",
	"-oG",
	"-oA",
	"-oS",
	"-iL",
	"--excludefile",
	"--datadir",
	"--script",
	"--script-args",
	"--script-args-file",
	"-p",
	"--ports",
	"-g",
	"--source-port",
	"--interface",
	"-of",
	"-od",
	"-fc",
	"-mc",
	"-fs",
	"-ms",
	"-fw",
	"-mw",
	"-fl",
	"-ml",
	"-t",
	"-rate",
	"-i",
	"-l",
	"-L",
	"-P",
	"--output-document",
	"--save-headers",
	"--post-data",
	"--post-file",
]);

interface ShellToken {
	text: string;
	afterRedirect: boolean;
}

/** 将命令行按引号感知切分为子命令 token 序列，并标记重定向目标文件。 */
function splitShellCommands(src: string): ShellToken[][] {
	const cmds: ShellToken[][] = [];
	let curCmd: ShellToken[] = [];
	let cur = "";
	let hasTokenChar = false;
	let inSingle = false;
	let inDouble = false;
	let afterRedirect = false;

	const flushToken = () => {
		if (hasTokenChar || cur.length > 0) {
			curCmd.push({ text: cur, afterRedirect });
			cur = "";
			hasTokenChar = false;
			afterRedirect = false;
		}
	};

	const flushCmd = () => {
		flushToken();
		if (curCmd.length > 0) {
			cmds.push(curCmd);
			curCmd = [];
		}
		afterRedirect = false;
	};

	for (let i = 0; i < src.length; i++) {
		const ch = src[i]!;
		if (inSingle) {
			if (ch === "'") inSingle = false;
			else cur += ch;
			continue;
		}
		if (inDouble) {
			if (ch === '"') {
				inDouble = false;
			} else if (ch === "\\" && i + 1 < src.length) {
				cur += src[++i]!;
			} else {
				cur += ch;
			}
			continue;
		}

		if (ch === "'") {
			inSingle = true;
			hasTokenChar = true;
			continue;
		}
		if (ch === '"') {
			inDouble = true;
			hasTokenChar = true;
			continue;
		}
		if (ch === "\\" && i + 1 < src.length) {
			cur += src[++i]!;
			hasTokenChar = true;
			continue;
		}
		if (ch === ";" || ch === "|" || ch === "&" || ch === "\n" || ch === "(" || ch === ")") {
			if (ch === "&" && src[i + 1] === ">") {
				flushToken();
				i += 1;
				if (src[i + 1] === ">") i += 1;
				afterRedirect = true;
				continue;
			}
			flushCmd();
			continue;
		}
		if (ch === ">" || ch === "<") {
			if (/^\d+$/.test(cur)) {
				cur = "";
				hasTokenChar = false;
			} else {
				flushToken();
			}
			while (i + 1 < src.length && (src[i + 1] === ">" || src[i + 1] === "<" || src[i + 1] === "&" || /\d/.test(src[i + 1]!))) {
				i += 1;
			}
			afterRedirect = true;
			continue;
		}
		if (/\s/.test(ch)) {
			flushToken();
			continue;
		}
		cur += ch;
		hasTokenChar = true;
	}
	flushCmd();
	return cmds;
}

const WRAPPER_CMDS = new Set(["sudo", "env", "nohup", "nice", "stdbuf", "command", "builtin", "exec", "time"]);

function extractBareDomainsFromCommands(rest: string, onCandidate: (domain: string) => void): void {
	const subcmds = splitShellCommands(rest);
	for (const tokens of subcmds) {
		let idx = 0;
		while (idx < tokens.length) {
			const t = tokens[idx]!.text;
			if (!t || tokens[idx]!.afterRedirect) {
				idx++;
				continue;
			}
			if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
				idx++;
				continue;
			}
			const base = (t.split("/").pop() ?? t).toLowerCase();
			if (WRAPPER_CMDS.has(base)) {
				idx++;
				while (idx < tokens.length && tokens[idx]!.text.startsWith("-")) idx++;
				continue;
			}
			if (base === "timeout") {
				idx += 2;
				continue;
			}
			break;
		}
		if (idx >= tokens.length) continue;

		const cmdName = (tokens[idx]!.text.split("/").pop() ?? tokens[idx]!.text).toLowerCase();

		if (INTERPRETER_CMDS.has(cmdName)) {
			let sawInlineCode = false;
			let skippedScriptFile = false;
			for (let i = idx + 1; i < tokens.length; i++) {
				const tok = tokens[i]!;
				if (tok.afterRedirect) continue;
				const val = tok.text;
				if (!val) continue;
				if (val === "-c" || val === "-e" || val === "-r" || val === "--eval" || val === "--print" || val === "-m") {
					sawInlineCode = true;
					i += 1; // 跳过内联代码字符串本身，避免将 Python/JS 属性如 logging.info / myapp.app 误判为域名
					continue;
				}
				if (val.startsWith("-")) continue;
				if (!sawInlineCode && !skippedScriptFile) {
					skippedScriptFile = true; // 跳过首个本地脚本文件路径参数
					continue;
				}
				if (/^(?:\.{0,2}\/|~\/|@)/.test(val)) continue;
				const hostPart = val.split("/")[0]!.replace(/:\d{1,5}$/, "");
				if (looksLikeDomain(hostPart)) {
					onCandidate(hostPart);
				}
			}
			continue;
		}

		if (NET_CLIENT_CMDS.has(cmdName)) {
			for (let i = idx + 1; i < tokens.length; i++) {
				const tok = tokens[i]!;
				if (tok.afterRedirect) continue;
				const val = tok.text;
				if (!val) continue;
				if (NON_HOST_VALUE_FLAGS.has(val) || (cmdName === "curl" && (val === "-u" || val === "--user"))) {
					i += 1; // 跳过紧随其后的文件名/头部/配置值
					continue;
				}
				if (val.startsWith("-")) {
					const eq = val.indexOf("=");
					if (eq > 0) {
						const flagPart = val.slice(0, eq);
						if (NON_HOST_VALUE_FLAGS.has(flagPart) || (cmdName === "curl" && flagPart === "--user")) {
							continue;
						}
						const rhs = val.slice(eq + 1).split("/")[0]!.replace(/:\d{1,5}$/, "");
						if (looksLikeDomain(rhs)) onCandidate(rhs);
					}
					continue;
				}
				if (/^(?:\.{0,2}\/|~\/|@)/.test(val) || val.includes("@")) continue;
				const hostPart = val.split("/")[0]!.replace(/:\d{1,5}$/, "");
				if (looksLikeDomain(hostPart)) {
					onCandidate(hostPart);
				}
			}
		}
	}
}

/** 解析点分十进制 IPv4 为无符号 32 位整数；非法返回 null。 */
function parseIpv4(ip: string): number | null {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
	if (!m) return null;
	let acc = 0;
	for (let i = 1; i <= 4; i++) {
		const part = m[i];
		if (part.length > 1 && part.startsWith("0")) return null;
		const n = Number(part);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		acc = ((acc << 8) | n) >>> 0;
	}
	return acc >>> 0;
}

/** 解析 IPv4 CIDR（如 10.0.0.0/24 或单 IP 10.0.0.5/32）。 */
function parseCidr(cidr: string): { net: number; prefix: number; mask: number } | null {
	const trimmed = cidr.trim();
	const slash = trimmed.indexOf("/");
	if (slash < 0) return null;
	const ipPart = trimmed.slice(0, slash);
	const prefixPart = trimmed.slice(slash + 1);
	if (!/^\d{1,2}$/.test(prefixPart)) return null;
	const prefix = Number(prefixPart);
	if (prefix < 0 || prefix > 32) return null;
	const ip = parseIpv4(ipPart);
	if (ip === null) return null;
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return { net: (ip & mask) >>> 0, prefix, mask };
}

function isIpv6Literal(host: string): boolean {
	return host.includes(":");
}

function isLoopbackIpv4(ipInt: number): boolean {
	return (ipInt >>> 24) === 127 || ipInt === 0;
}

function isPrivateIpv4(ipInt: number): boolean {
	const b0 = (ipInt >>> 24) & 0xff;
	const b1 = (ipInt >>> 16) & 0xff;
	if (b0 === 10) return true;
	if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
	if (b0 === 192 && b1 === 168) return true;
	return false;
}

function isLoopbackHost(host: string): boolean {
	const h = host.toLowerCase();
	if (h === "localhost" || h.endsWith(".localhost")) return true;
	if (h === "::1" || h === "0:0:0:0:0:0:0:1" || h === "::ffff:127.0.0.1") return true;
	if (h.startsWith("::ffff:")) {
		const v4 = parseIpv4(h.slice(7));
		if (v4 !== null && isLoopbackIpv4(v4)) return true;
	}
	const v4 = parseIpv4(h);
	return v4 !== null && isLoopbackIpv4(v4);
}

function isPrivateHost(host: string): boolean {
	const h = host.toLowerCase();
	if (h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80:")) {
		if (isIpv6Literal(h)) return true;
	}
	if (h.startsWith("::ffff:")) {
		const v4 = parseIpv4(h.slice(7));
		if (v4 !== null) return isPrivateIpv4(v4);
	}
	const v4 = parseIpv4(h);
	return v4 !== null && isPrivateIpv4(v4);
}

/** 规范化主机或 CIDR 字符串：去引号、去方括号、剥离非 IPv6 端口、去末尾点号、转小写。 */
function normalizeHostToken(raw: string, allowCidrSuffix = false): string {
	let s = String(raw ?? "")
		.trim()
		.replace(/^['"`(\s]+|['"`)\s,;]+$/g, "");
	if (!s) return "";
	if (s.startsWith("[")) {
		const close = s.indexOf("]");
		if (close > 1) return s.slice(1, close).toLowerCase();
	}
	if (allowCidrSuffix && parseCidr(s) !== null) {
		return s.toLowerCase();
	}
	// 非 IPv6 多冒号场景剥离 :port 与 /path
	const colonCount = (s.match(/:/g) ?? []).length;
	if (colonCount <= 1) {
		s = s.split("/")[0] ?? s;
		s = s.replace(/:\d{1,5}$/, "");
	}
	s = s.replace(/\.+$/, "").toLowerCase();
	return s;
}

function parseTargetHost(targetUrlOrHost: string): string | null {
	const raw = String(targetUrlOrHost ?? "").trim();
	if (!raw) return null;
	// 本地路径表示（coding/ops 模式）不视作远程主机
	if (/^(?:\.{1,2}[\\/]|[\\/]|~[\\/])/.test(raw)) return null;
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
		try {
			const u = new URL(raw);
			const h = normalizeHostToken(u.hostname);
			return h || null;
		} catch {
			return null;
		}
	}
	if (raw.startsWith("[")) {
		const h = normalizeHostToken(raw);
		return h || null;
	}
	try {
		const u = new URL(`http://${raw}`);
		const h = normalizeHostToken(u.hostname);
		return h || null;
	} catch {
		const fallback = normalizeHostToken(raw);
		return fallback || null;
	}
}

function uniqClean(items: readonly string[] | undefined, allowCidr = false): string[] {
	const out: string[] = [];
	const seen = new Set<string>();
	for (const item of items ?? []) {
		const norm = normalizeHostToken(item, allowCidr);
		if (!norm || seen.has(norm)) continue;
		seen.add(norm);
		out.push(norm);
	}
	return out;
}

/**
 * 为指定目标与运行模式生成默认靶标范围策略。
 * 支持读取环境变量 NUWA_SCOPE_ALLOW_SUBDOMAINS / NUWA_SCOPE_ALLOW_CIDRS，overrides 显式字段优先。
 */
export function defaultScopeForTarget(
	targetUrlOrHost: string,
	mode: Mode | string,
	overrides?: Partial<ScopePolicy>,
): ScopePolicy {
	const host = parseTargetHost(targetUrlOrHost);
	const envSubRaw = (process.env.NUWA_SCOPE_ALLOW_SUBDOMAINS ?? "").trim().toLowerCase();
	const envSub = envSubRaw === "1" || envSubRaw === "true";
	const envCidrs = (process.env.NUWA_SCOPE_ALLOW_CIDRS ?? "")
		.split(/[,\s]+/)
		.map((s) => s.trim())
		.filter(Boolean);

	const m = String(mode ?? "ctf").toLowerCase();
	const defaultHosts = host ? [host] : m === "coding" || m === "ops" ? ["127.0.0.1", "localhost", "::1"] : [];

	const allowHosts = overrides?.allowHosts !== undefined ? uniqClean(overrides.allowHosts, false) : uniqClean(defaultHosts, false);
	const allowCidrs = overrides?.allowCidrs !== undefined ? uniqClean(overrides.allowCidrs, true) : uniqClean(envCidrs, true);
	const denyHosts = uniqClean(overrides?.denyHosts, true);

	return {
		allowHosts,
		allowCidrs,
		denyHosts,
		allowSubdomains: overrides?.allowSubdomains ?? envSub,
		allowPrivateNetwork: overrides?.allowPrivateNetwork ?? false,
		allowDestructive: overrides?.allowDestructive ?? false,
	};
}

function matchesHostPattern(host: string, rawPattern: string): boolean {
	const pat = normalizeHostToken(rawPattern, true);
	if (!pat) return false;
	if (pat === "*") return true;
	if (pat.startsWith("*.")) {
		const base = pat.slice(2);
		return Boolean(base) && host.endsWith(`.${base}`) && host.length > base.length + 1;
	}
	const patCidr = parseCidr(pat);
	if (patCidr) {
		const targetCidr = parseCidr(host);
		if (targetCidr) {
			return patCidr.prefix <= targetCidr.prefix && ((targetCidr.net & patCidr.mask) >>> 0) === patCidr.net;
		}
		const ip = parseIpv4(host);
		return ip !== null && ((ip & patCidr.mask) >>> 0) === patCidr.net;
	}
	return host === pat;
}

/**
 * 校验主机或 CIDR 是否在 ScopePolicy 允许范围内。
 * 优先级：denyHosts 黑名单 > 回环地址放行 > allowHosts（精确 / *.domain / allowSubdomains）> IPv4 CIDR > allowPrivateNetwork。
 */
export function isHostInScope(host: string, scope: ScopePolicy): { ok: boolean; reason?: string } {
	const norm = normalizeHostToken(host, true);
	if (!norm) {
		return { ok: false, reason: "目标主机为空" };
	}

	// 1. 黑名单最高优先级（含等价回环别名联动）
	for (const deny of scope.denyHosts ?? []) {
		if (matchesHostPattern(norm, deny)) {
			return { ok: false, reason: `目标 ${norm} 命中黑名单 denyHosts (${deny})` };
		}
		const denyNorm = normalizeHostToken(deny, false);
		if (!norm.includes("/") && !denyNorm.includes("/") && isLoopbackHost(norm) && isLoopbackHost(denyNorm)) {
			return { ok: false, reason: `回环目标 ${norm} 已被 denyHosts (${deny}) 禁止` };
		}
	}

	// 2. 本地回环地址放行（未命中 denyHosts）
	if (!norm.includes("/") && isLoopbackHost(norm)) {
		return { ok: true };
	}

	// 3. allowHosts 精确匹配、*.domain 通配与 allowSubdomains 派生匹配
	const targetIsIpOrCidr = parseIpv4(norm) !== null || parseCidr(norm) !== null || isIpv6Literal(norm);
	for (const allow of scope.allowHosts ?? []) {
		if (matchesHostPattern(norm, allow)) {
			return { ok: true };
		}
		if (scope.allowSubdomains && !targetIsIpOrCidr) {
			const base = normalizeHostToken(allow, false);
			if (
				base &&
				!base.startsWith("*.") &&
				parseIpv4(base) === null &&
				!isIpv6Literal(base) &&
				norm.endsWith(`.${base}`) &&
				norm.length > base.length + 1
			) {
				return { ok: true };
			}
		}
	}

	// 4. IPv4 CIDR 掩码匹配
	const targetCidr = parseCidr(norm);
	const targetIp = targetCidr ? null : parseIpv4(norm);
	if (targetCidr || targetIp !== null) {
		for (const rawCidr of scope.allowCidrs ?? []) {
			const cidr = parseCidr(rawCidr);
			if (!cidr) continue;
			if (targetCidr) {
				if (cidr.prefix <= targetCidr.prefix && ((targetCidr.net & cidr.mask) >>> 0) === cidr.net) {
					return { ok: true };
				}
			} else if (targetIp !== null) {
				if (((targetIp & cidr.mask) >>> 0) === cidr.net) {
					return { ok: true };
				}
			}
		}
	}

	// 5. 私网网段策略
	if (!norm.includes("/") && isPrivateHost(norm)) {
		if (scope.allowPrivateNetwork) {
			return { ok: true };
		}
		return { ok: false, reason: `私网目标 ${norm} 未列入白名单且 allowPrivateNetwork=false` };
	}

	return {
		ok: false,
		reason: `目标 ${norm} 不在授权范围内 (allowHosts=${scope.allowHosts.join(",") || "无"})`,
	};
}

function isPlausibleTargetToken(raw: string): boolean {
	if (!raw || raw.length > 253) return false;
	if (/[$`{}*?<>|\\]/.test(raw)) return false;
	if (raw.startsWith("-")) return false;
	if (/^\d+$/.test(raw)) return false;
	return true;
}

function looksLikeDomain(candidate: string): boolean {
	const lower = candidate.toLowerCase();
	if (lower === "localhost" || lower.endsWith(".localhost")) return true;
	if (CODE_IDENTIFIERS.has(lower)) return false;
	if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/i.test(lower)) {
		return false;
	}
	const parts = lower.split(".");
	const tld = parts[parts.length - 1] ?? "";
	if (KNOWN_TLDS.has(tld) && !NON_TLD_EXTS.has(tld)) return true;
	if (tld === "io" || tld === "ai" || tld === "co" || tld === "me" || tld === "cc") {
		return true;
	}
	return false;
}

/**
 * 从命令行文本中提取所有潜在网络目标（主机名、IPv4、IPv6、IPv4 CIDR）。
 * 覆盖：显式 URL、curl、nmap、openssl、nc、ssh、数据库客户端、/dev/tcp、Python/Node socket 连接及裸 IP/域名。
 */
export function extractCommandTargets(cmd: string): string[] {
	const text = String(cmd ?? "");
	if (!text.trim()) return [];

	const found: string[] = [];
	const seen = new Set<string>();
	const addTarget = (raw: string, allowCidr = false) => {
		if (!isPlausibleTargetToken(raw)) return;
		const norm = normalizeHostToken(raw, allowCidr);
		if (!norm || !isPlausibleTargetToken(norm)) return;
		// 忽略子网掩码/广播常量及已知代码标识符
		if (norm === "255.255.255.255" || norm === "255.255.255.0" || norm === "255.255.0.0") return;
		if (CODE_IDENTIFIERS.has(norm.toLowerCase())) return;
		if (!seen.has(norm)) {
			seen.add(norm);
			found.push(norm);
		}
	};

	// 1. 提取完整 scheme://... URL，仅取其连接目标 hostname，并从剩余扫描串抹除以避免路径/query 二次干扰
	const urlRe = /\b(?:https?|wss?|ftps?|s?ftp|ssh|ldaps?|rediss?|mysql|postgres(?:ql)?|mongodb):\/\/[^\s'"`<>|;&)]+/gi;
	const rest = text.replace(urlRe, (fullUrl) => {
		const cleaned = fullUrl.replace(/[.,;:!?]+$/, "");
		try {
			const u = new URL(cleaned);
			addTarget(u.hostname);
		} catch {
			const m = /^[a-z0-9+.-]+:\/\/(\[[^\]]+\]|[^/:?#]+)/i.exec(cleaned);
			if (m?.[1]) addTarget(m[1]);
		}
		return " ";
	});

	// 2. curl --connect-to HOST1:PORT1:HOST2:PORT2 与 --resolve HOST:PORT:ADDR[,ADDR]
	for (const m of rest.matchAll(/--connect-to(?:\s+|=)['"]?[^:'"\s]*:\d*:(\[[^\]]+\]|[^:'"\s]+)(?::\d+)?['"]?/gi)) {
		if (m[1]) addTarget(m[1]);
	}
	for (const m of rest.matchAll(/--resolve(?:\s+|=)['"]?([^:'"\s]+):\d+:([^\s'"]+)['"]?/gi)) {
		if (m[1] && m[1] !== "*") addTarget(m[1]);
		if (m[2]) {
			for (const addr of m[2].split(",")) {
				if (addr.trim()) addTarget(addr.trim());
			}
		}
	}

	// 3. openssl s_client -connect host:port / -servername host
	for (const m of rest.matchAll(/(?:^|\s)-connect\s+['"]?(\[[^\]]+\]|[^\s:'"]+)(?::\d{1,5})?['"]?/gi)) {
		if (m[1]) addTarget(m[1]);
	}
	for (const m of rest.matchAll(/(?:^|\s)-servername\s+['"]?([^\s'"]+)['"]?/gi)) {
		if (m[1]) addTarget(m[1]);
	}

	// 4. bash /dev/tcp/<host>/<port> 或 /dev/udp/<host>/<port>
	for (const m of rest.matchAll(/\/dev\/(?:tcp|udp)\/(\[[^\]]+\]|[^/\s'";&|)]+)\/\d{1,5}/gi)) {
		if (m[1]) addTarget(m[1]);
	}

	// 5. Python / Node / 标准库 socket 连接字面量
	for (const m of rest.matchAll(
		/\b(?:create_connection|connect|connect_ex)\s*\(\s*\(\s*['"](\[[^\]]+\]|[^'"]+)['"]/g,
	)) {
		if (m[1]) addTarget(m[1]);
	}
	for (const m of rest.matchAll(
		/\b(?:HTTPConnection|HTTPSConnection|Telnet|FTP|SMTP|IMAP4|POP3|getaddrinfo|gethostbyname)\s*\(\s*['"](\[[^\]]+\]|[^'"]+)['"]/g,
	)) {
		if (m[1]) addTarget(m[1]);
	}

	// 6. 数据库 / 缓存 CLI -h / --host
	if (/\b(?:redis-cli|mysql|psql|pg_isready|mongosh?|hydra)\b/i.test(rest)) {
		for (const m of rest.matchAll(/(?:^|\s)(?:-h|--host)(?:\s+|=)['"]?(\[[^\]]+\]|[^\s'"]+)['"]?/g)) {
			if (m[1]) addTarget(m[1]);
		}
	}

	// 7. ssh / scp / sftp / rsync 的 user@host[:path]
	if (/\b(?:ssh|scp|sftp|rsync)\b/i.test(rest)) {
		for (const m of rest.matchAll(/\b[a-zA-Z0-9._-]+@(\[[^\]]+\]|[a-zA-Z0-9.-]+)(?=[:\s/'"]|$)/g)) {
			if (m[1]) addTarget(m[1]);
		}
	}

	// 8. 裸 IPv4 与 IPv4 CIDR（如 nmap 10.0.0.5 / nmap 192.168.1.0/24 / python3 -c ... '10.0.0.5'）
	for (const m of rest.matchAll(
		/(?<![0-9a-zA-Z._-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?:\/(?:3[0-2]|[12]?\d))?)(?![0-9a-zA-Z._-])/g,
	)) {
		const token = m[1];
		if (!token) continue;
		if (token.includes("/")) {
			if (parseCidr(token) !== null) addTarget(token, true);
		} else if (parseIpv4(token) !== null) {
			addTarget(token, false);
		}
	}

	// 9. 方括号包裹的 IPv6 目标（如 curl -g [2001:db8::1]:8080）
	for (const m of rest.matchAll(/\[([0-9a-fA-F:]{2,45})\](?::\d{1,5})?/g)) {
		if (m[1] && m[1].includes(":")) addTarget(m[1]);
	}

	// 10. 网络相关命令与脚本外部参数中的裸域名（跳过 -c/-e 内联代码正文及 -o/-D/-oN 等非主机选项值）
	extractBareDomainsFromCommands(rest, (cand) => addTarget(cand));

	return found;
}

const NUWA_PROTECTED_TARGET_RE =
	/(?:^|[\s'"`=(/\\])\.nuwa(?:[\\/](?:state\.json|journal[^/\s'"`)|;&]*|exec-ledger[^/\s'"`)|;&]*|snap(?:[\\/][^\s'"`)|;&]*)?|state\.lock|\*)|[\\/]?['"`\s;|&)]|[\\/]?$)/i;

const NUWA_PROTECTED_FILE_ONLY_RE =
	/\.nuwa[\\/](?:state\.json|journal[^/\s'"`)|;&]*|exec-ledger[^/\s'"`)|;&]*|snap(?:[\\/][^\s'"`)|;&]*)?|state\.lock)/i;

const NUWA_REDIRECT_RE =
	/(?:>>?|>\||&>>?|tee\s+(?:-[a-zA-Z]+\s+)*)[^\n;|&]*\.nuwa[\\/](?:state\.json|journal|exec-ledger|snap|state\.lock)/i;

const NUWA_FILE_MUTATE_CMD_RE =
	/(?:^|[;&|()\s`])(?:sudo\s+)?(?:rm|unlink|shred|mv|cp|install|ln|truncate|dd|chmod|chown|touch)\b/i;

const NUWA_INPLACE_EDIT_RE =
	/(?:^|[;&|()\s`])(?:sudo\s+)?(?:sed\s+[^;|&]*(?:-[a-zA-Z]*i(?:\b|[.'"])|--in-place\b)|perl\s+[^;|&]*-[a-zA-Z]*i|awk\s+[^;|&]*-i\s+inplace)/i;

const NUWA_SCRIPT_WRITE_RE =
	/\b(?:writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|unlink|rmSync|rmdirSync|renameSync|copyFileSync|truncateSync|write_text|write_bytes|rmtree|os\.remove|os\.unlink|os\.rename|os\.replace|shutil\.(?:move|copy|copy2|copyfile|rmtree)|json\.dump|open\s*\([^)]*,\s*['"][wa+x])/i;

/**
 * 检查命令是否试图篡改 .nuwa/ 下的权威状态（state.json、journal、snap、state.lock 或整个 .nuwa 目录）。
 */
export function checkNuwaDirTamper(cmd: string): ScopeBlockVerdict | null {
	const text = String(cmd ?? "");
	if (!text.includes(".nuwa")) return null;

	if (NUWA_REDIRECT_RE.test(text)) {
		return {
			block: true,
			reason: "nuwa N-003: 禁止重定向或 tee 写入 .nuwa/ 权威状态文件 (state.json/journal/snap/state.lock)",
		};
	}

	if (NUWA_INPLACE_EDIT_RE.test(text) && NUWA_PROTECTED_FILE_ONLY_RE.test(text)) {
		return {
			block: true,
			reason: "nuwa N-003: 禁止使用 sed -i / 原地编辑修改 .nuwa/ 权威状态文件",
		};
	}

	if (NUWA_SCRIPT_WRITE_RE.test(text) && (NUWA_PROTECTED_FILE_ONLY_RE.test(text) || /rmtree\s*\([^)]*\.nuwa/i.test(text))) {
		return {
			block: true,
			reason: "nuwa N-003: 禁止通过内联脚本写入或删除 .nuwa/ 权威状态文件 (state.json/journal/snap/state.lock)",
		};
	}

	// 按子命令段拆分检查 rm / mv / cp / truncate / dd 等文件修改指令
	const segments = text.split(/[;&|\n]+/);
	for (const seg of segments) {
		if (!seg.includes(".nuwa")) continue;
		if (NUWA_INPLACE_EDIT_RE.test(seg) && NUWA_PROTECTED_TARGET_RE.test(seg)) {
			return {
				block: true,
				reason: "nuwa N-003: 禁止原地修改 .nuwa/ 权威状态文件",
			};
		}
		if (NUWA_FILE_MUTATE_CMD_RE.test(seg)) {
			// 允许操作 .nuwa/notes.md、.nuwa/report.md 等非权威附属文件，仅拦受保护核心文件或整个 .nuwa 目录
			if (
				NUWA_PROTECTED_FILE_ONLY_RE.test(seg) ||
				/(?:^|[\s'"`/\\])\.nuwa(?:[\\/]?\*|[\\/]?['"`\s)]|[\\/]?$)/i.test(seg)
			) {
				return {
					block: true,
					reason: "nuwa N-003: 禁止 rm/mv/cp/truncate 篡改 .nuwa/ 权威状态 (state.json/journal/snap/state.lock)",
				};
			}
		}
	}

	return null;
}

const DESTRUCTIVE_PATTERNS: ReadonlyArray<{ label: string; re: RegExp }> = [
	{
		label: "rm -rf",
		re: /(?:^|[;&|()\s`])(?:sudo\s+)?rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f\b|-[a-zA-Z]*f[a-zA-Z]*r\b|[^;|&]*\s-r\s+-f\b|[^;|&]*\s-f\s+-r\b|[^;|&]*--recursive\b[^;|&]*--force\b|[^;|&]*--force\b[^;|&]*--recursive\b|[^;|&]*--no-preserve-root\b)/i,
	},
	{
		label: "mkfs/wipefs",
		re: /(?:^|[;&|()\s`])(?:sudo\s+)?(?:mkfs(?:\.[a-z0-9]+)?|wipefs|fdisk|sfdisk|parted)\b/i,
	},
	{
		label: "dd if=",
		re: /(?:^|[;&|()\s`])(?:sudo\s+)?dd\s+[^;|&]*\bif=/i,
	},
	{
		label: "shutdown/reboot",
		re: /(?:^|[;&|()\s`])(?:sudo\s+)?(?:shutdown|reboot|poweroff|halt|init\s+[06]|systemctl\s+(?:poweroff|reboot|halt))\b/i,
	},
	{
		label: "SQL DROP/TRUNCATE",
		re: /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA)\b|TRUNCATE\s+TABLE\b)/i,
	},
	{
		label: "TRUNCATE",
		re: /\bTRUNCATE\s+[`"'[]?[a-zA-Z_][a-zA-Z0-9_.]*[`"'\]]?\s*(?:;|['"]|$)/i,
	},
	{
		label: "fork-bomb",
		re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
	},
];

/**
 * 综合校验命令的高危破坏风险（N-008）与靶标越界风险（N-007）。
 */
export function checkScopeAndRisk(
	cmd: string,
	scope: ScopePolicy,
	mode: Mode | string,
): ScopeBlockVerdict | null {
	const text = String(cmd ?? "");
	if (!text.trim()) return null;

	if (!scope.allowDestructive) {
		for (const item of DESTRUCTIVE_PATTERNS) {
			if (item.re.test(text)) {
				return {
					block: true,
					reason: `nuwa N-008: 拦截高危破坏性操作 (${item.label})；mode=${mode} 默认禁止破坏性指令`,
				};
			}
		}
	}

	const targets = extractCommandTargets(text);
	for (const target of targets) {
		const res = isHostInScope(target, scope);
		if (!res.ok) {
			return {
				block: true,
				reason: `nuwa N-007: 靶标越界 (${target}) — ${res.reason ?? "不在授权 Scope 内"}`,
			};
		}
	}

	return null;
}
