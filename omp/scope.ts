/**
 * 靶标范围护栏（N-007）、高危破坏性命令拦截（N-008）与 .nuwa 状态目录防篡改（N-003）。
 *
 * 约束：仅使用 import type 引用 ./nuwa，保持运行时零循环依赖。
 */
import { posix as posixPath } from "node:path";
import type { Mode } from "./types";

export interface ScopePolicy {
	allowHosts: string[];
	allowCidrs: string[];
	denyHosts: string[];
	allowSubdomains: boolean;
	allowPrivateNetwork: boolean;
	allowDestructive: boolean;
	/** v4.1 回环地址放行策略；undefined 兼容历史策略，false 时禁止越界访问宿主机回环。 */
	allowLoopback?: boolean;
	/** v5.0 受控 OOB（带外回调，如 Interactsh/DNSLog）允许域名白名单。 */
	oobDomains?: string[];
}

export type EnforcementLayer = "shell-guard" | "egress-proxy" | "sandbox-net";

export interface ScopeBlockVerdict {
	block: true;
	reason: string;
	layer?: EnforcementLayer;
}

export interface ScopeCheckOptions {
	layer?: EnforcementLayer;
}

/** 统一格式化安全阻断原因，显式标明规则号与执行拦截层（如 [layer=shell-guard]）。 */
export function formatScopeBlockReason(
	layer: EnforcementLayer,
	detail: string,
	code: "N-007" | "N-008" | "N-003" = "N-007",
): string {
	return `nuwa ${code} [layer=${layer}]: ${detail}`;
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

const INTERPRETER_CMDS = new Set(["python", "python2", "python3", "node", "nodejs", "bun", "ruby", "perl", "php"]);

function isInterpreterCmd(cmdName: string): boolean {
	if (INTERPRETER_CMDS.has(cmdName)) return true;
	return /^(?:python[23](?:\.\d+)?|ruby\d+(?:\.\d+)?|perl\d*(?:\.\d+)?|php\d+(?:\.\d+)?)$/.test(cmdName);
}

const INTERPRETER_INLINE_FLAGS = new Set(["-c", "-e", "-E", "-r", "-p", "--eval", "--print"]);

const INLINE_SCRIPT_NET_HINT_RE =
	/(?:\b(?:urllib|urllib3|requests|httpx|aiohttp|http\.client|socket|fetch|axios|undici|got|superagent|http\.get|https\.get|http\.request|https\.request|net\.connect|net\.createConnection|tls\.connect|dns\.lookup|dns\.resolve|Net::HTTP|OpenURI|TCPSocket|HTTParty|Faraday|IO::Socket|LWP|HTTP::Tiny|Mojo::UserAgent|file_get_contents|fsockopen|pfsockopen|curl_init|stream_socket_client|gethostbyname|getaddrinfo|create_connection|HTTPConnection|HTTPSConnection|urlopen|PeerAddr|PeerHost)\b|(?:require\s*\(\s*|from\s+)['"`](?:node:)?(?:http|https|http2|net|tls|dns|dgram)['"`])/i;

/** 对内联脚本做纯静态引号字面量拼接折叠（如 'https://' + 'api.github.com' -> 'https://api.github.com'），仅用于静态外连审计。 */
function foldInlineStringConcats(code: string): string {
	let out = code;
	for (let pass = 0; pass < 4; pass++) {
		const next = out
			// 同引号显式拼接（Python/JS/Ruby '+'、PHP/Perl '.'）或 Python 相邻字面量拼接
			.replace(/'([^'\\\r\n]*)'\s*(?:[+.]\s*)?'([^'\\\r\n]*)'/g, "'$1$2'")
			.replace(/"([^"\\\r\n]*)"\s*(?:[+.]\s*)?"([^"\\\r\n]*)"/g, '"$1$2"');
		if (next === out) break;
		out = next;
	}
	return out;
}

/**
 * 从 python/python3 -c、node -e、bun -e、ruby -e、perl -e、php -r 等内联脚本代码中提取潜在网络目标（URL、域名、IP）。
 * 规则：
 *   1. 先折叠同引号字符串拼接，防 "https://" + "api.github.com" 绕过；
 *   2. 提取完整 URL（含模板字符串插值占位化）；
 *   3. 提取常见多语言网络 API 调用中的主机字面量（urllib/requests/fetch/http.get/net.connect/Net::HTTP/IO::Socket/fsockopen/curl_init 等）；
 *   4. 当代码包含网络模块/API 上下文时，扫描引号包裹的字符串字面量中合法域名或 host:port，严防绕过；
 *   5. 严禁从未加引号的代码属性标识符（如 logging.info / myapp.app / obj.to）误提取域名。
 */
export function extractInlineScriptTargets(code: string): string[] {
	const raw = String(code ?? "");
	if (!raw.trim()) return [];

	const found: string[] = [];
	const seen = new Set<string>();
	const push = (cand: string, allowCidr = false) => {
		const cleaned = String(cand ?? "").trim();
		if (!cleaned || !isPlausibleTargetToken(cleaned)) return;
		const norm = normalizeHostToken(cleaned, allowCidr);
		if (!norm || !isPlausibleTargetToken(norm)) return;
		if (norm === "nuwa-tpl-var" || norm === "255.255.255.255" || norm === "255.255.255.0" || norm === "255.255.0.0") {
			return;
		}
		if (CODE_IDENTIFIERS.has(norm.toLowerCase())) return;
		if (!seen.has(norm)) {
			seen.add(norm);
			found.push(norm);
		}
	};

	// 将 JS 模板插值替换为安全占位符，避免 `https://${x}.evil.org` 被 `}` 截断，同时避免纯变量 `https://${host}` 误报
	const folded = foldInlineStringConcats(raw)
		.replace(/:\$\{[^}]*\}/g, ":80")
		.replace(/\$\{[^}]*\}/g, "nuwa-tpl-var");

	// 1. 提取内联代码中的显式 scheme:// URL
	const urlRe =
		/\b(?:https?|wss?|ftps?|s?ftp|ssh|ldaps?|rediss?|mysql|postgres(?:ql)?|mongodb|socks(?:4a?|5h?)?):\/\/[^\s'"`<>|;&),}\]]+/gi;
	for (const m of folded.matchAll(urlRe)) {
		const h = extractUrlHostnameLoose(m[0]);
		if (h && h !== "nuwa-tpl-var") push(h);
	}

	// 2. 提取多语言显式网络 API / 连接对象配置中的主机字面量
	const apiHostPatterns: RegExp[] = [
		// Python / Ruby / PHP / Perl / Node 函数首参为 host 字符串
		/\b(?:HTTPConnection|HTTPSConnection|Telnet|FTP|SMTP|IMAP4|POP3|getaddrinfo|gethostbyname|fsockopen|pfsockopen|stream_socket_client)\s*\(\s*['"`](\[[^\]]+\]|[^'"`\s]+)['"`]/g,
		// Ruby Net::HTTP.get('host', '/path') / Net::HTTP.start('host', 443) / TCPSocket.new('host', 80)
		/\b(?:Net::HTTP\.(?:get|get_response|start|new|post_form)|TCPSocket\.(?:new|open))\s*\(\s*['"`](\[[^\]]+\]|[^'"`\s]+)['"`]/g,
		// Node net.connect(port, 'host') / require('net').connect(port, 'host') / tls.connect(port, 'host') / dns.lookup('host')
		/(?:\b(?:net|tls)|require\s*\(\s*['"`](?:node:)?(?:net|tls)['"`]\s*\))\.(?:connect|createConnection)\s*\(\s*\d+\s*,\s*['"`](\[[^\]]+\]|[^'"`\s]+)['"`]/g,
		/(?:\bdns|require\s*\(\s*['"`](?:node:)?dns['"`]\s*\))\.(?:lookup|resolve|resolve4|resolve6|resolveAny)\s*\(\s*['"`]([^'"`\s]+)['"`]/g,
		// Python socket connect(('host', port))
		/\b(?:create_connection|connect|connect_ex)\s*\(\s*\(\s*['"`](\[[^\]]+\]|[^'"`\s]+)['"`]/g,
		// JS/TS/Ruby/Perl/Python 关键字或对象字段 host / hostname / PeerAddr / PeerHost
		/\b(?:hostname|host|PeerAddr|PeerHost)\s*(?::|=>|=)\s*['"`](\[[^\]]+\]|[^'"`\s]+)['"`]/g,
		// URL 参数传递（包括无 scheme 写法或 curl_init / urlopen / fetch / file_get_contents）
		/\b(?:urlopen|Request|fetch|curl_init|file_get_contents|URI\.open|URI\.parse)\s*\(\s*['"`]([^'"`\s]+)['"`]/g,
	];
	for (const re of apiHostPatterns) {
		for (const m of folded.matchAll(re)) {
			const val = m[1];
			if (!val) continue;
			if (SCHEME_URL_PREFIX_RE.test(val)) {
				const h = extractUrlHostnameLoose(val);
				if (h && h !== "nuwa-tpl-var") push(h);
				continue;
			}
			const cleaned = val.replace(/^(?:tcp|ssl|tls|udp):\/\//i, "");
			const hostPart = cleaned.startsWith("[")
				? cleaned.slice(1, cleaned.indexOf("]") > 1 ? cleaned.indexOf("]") : undefined)
				: cleaned.split("/")[0]!.replace(/:\d{1,5}$/, "");
			if (parseIpv4(hostPart) !== null || isIpv6Literal(hostPart) || looksLikeDomain(hostPart)) {
				push(hostPart);
			}
		}
	}

	// 3. 若脚本命中网络模块/函数特征，再扫描引号字面量中的独立域名或 host:port（如 host='api.github.com'）
	if (INLINE_SCRIPT_NET_HINT_RE.test(folded)) {
		for (const m of folded.matchAll(/(['"`])([^'"`\r\n]{3,253})\1/g)) {
			const lit = (m[2] ?? "").trim();
			if (!lit || /\s/.test(lit)) continue;
			if (SCHEME_URL_PREFIX_RE.test(lit)) {
				const h = extractUrlHostnameLoose(lit);
				if (h && h !== "nuwa-tpl-var") push(h);
				continue;
			}
			// 跳过文件路径、MIME 类型、模块通配符与相对路径
			if (/^(?:\.{0,2}\/|~\/|\/)/.test(lit)) continue;
			if (lit.includes("/") && !/^[a-z0-9.-]+(?::\d{1,5})?\/[^\s]*$/i.test(lit)) continue;
			const hostOnly = lit.split("/")[0]!.replace(/:\d{1,5}$/, "");
			if (!hostOnly || hostOnly.includes("nuwa-tpl-var")) continue;
			if (parseIpv4(hostOnly) !== null || looksLikeDomain(hostOnly)) {
				push(hostOnly);
			}
		}
	}

	return found;
}

/** 提取命令中的 heredoc 主体文本（如 python3 - <<'EOF' ... EOF），用于内联脚本越界检测。 */
function extractHeredocBodiesForInterpreters(text: string): string[] {
	const bodies: string[] = [];
	const re =
		/\b(?:python[23]?(?:\.\d+)?|node(?:js)?|bun|ruby\d*|perl\d*|php\d*)\b[^\n]*<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?[^\n]*\n([\s\S]*?)\n\s*\1(?:\s|$)/g;
	for (const m of text.matchAll(re)) {
		if (m[2]?.trim()) bodies.push(m[2]);
	}
	return bodies;
}

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

/** 跨工具通用的长参数名：紧跟 payload / 请求头 / Cookie / 输出文件 / 配置值而非目标主机。 */
const NON_HOST_VALUE_FLAGS = new Set([
	"--output",
	"--output-document",
	"--output-file",
	"--output-dir",
	"--append-output",
	"--directory-prefix",
	"--dump-header",
	"--cookie",
	"--cookie-jar",
	"--load-cookies",
	"--save-cookies",
	"--data",
	"--data-raw",
	"--data-binary",
	"--data-urlencode",
	"--data-ascii",
	"--json",
	"--body",
	"--body-data",
	"--body-file",
	"--post-data",
	"--post-file",
	"--form",
	"--form-string",
	"--header",
	"--headers",
	"--user-agent",
	"--referer",
	"--request",
	"--method",
	"--upload-file",
	"--config",
	"--cacert",
	"--capath",
	"--ca-certificate",
	"--ca-directory",
	"--cert",
	"--certificate",
	"--key",
	"--private-key",
	"--write-out",
	"--max-time",
	"--connect-timeout",
	"--timeout",
	"--tries",
	"--wordlist",
	"--excludefile",
	"--datadir",
	"--script",
	"--script-args",
	"--script-args-file",
	"--ports",
	"--source-port",
	"--interface",
	"--oauth2-bearer",
	"--auth-cred",
	"--auth-type",
	"--http-user",
	"--http-password",
	"--password",
	"--tamper",
	"--prefix",
	"--suffix",
	"--technique",
	"--dbms",
	"--level",
	"--risk",
	"--threads",
	"--rate",
	"--rate-limit",
	"--templates",
	"--tags",
	"--severity",
]);

interface CmdFlagSpec {
	exact: Set<string>;
	shortPrefixes: readonly string[];
}

function makeFlagSpec(extraExact: readonly string[], shortPrefixes: readonly string[] = []): CmdFlagSpec {
	return {
		exact: new Set([...NON_HOST_VALUE_FLAGS, ...extraExact]),
		shortPrefixes,
	};
}

const CURL_FLAG_SPEC = makeFlagSpec(
	["-d", "-F", "-H", "-b", "-c", "-e", "-A", "-X", "-o", "-D", "-T", "-K", "-w", "-m", "-u", "--user", "-E", "-r", "-z", "-C", "-Y", "-y", "-t"],
	["-d", "-F", "-H", "-b", "-c", "-e", "-A", "-X", "-o", "-D", "-T", "-K", "-w", "-m", "-u"],
);
const WGET_FLAG_SPEC = makeFlagSpec(
	["-O", "-o", "-a", "-P", "-T", "-t", "-U", "-i", "--user"],
	["-O", "-o", "-P", "-T", "-t", "-U"],
);
const FUZZ_FLAG_SPEC = makeFlagSpec(
	[
		"-H",
		"-b",
		"-c",
		"-d",
		"-X",
		"-w",
		"-o",
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
		"-p",
		"-e",
		"-A",
		"-timeout",
		"-z",
	],
	["-H", "-d", "-b", "-o", "-w", "-X", "-A"],
);
const WEB_SCAN_FLAG_SPEC = makeFlagSpec(
	[
		"-H",
		"-b",
		"-d",
		"-X",
		"-body",
		"-o",
		"-t",
		"-templates",
		"-tags",
		"-severity",
		"-etags",
		"-rl",
		"-rate",
		"-rate-limit",
		"-c",
		"-timeout",
		"-fc",
		"-mc",
		"-fs",
		"-ms",
		"-l",
		"-A",
		"-w",
		"-p",
		"-P",
	],
	["-H", "-d", "-b", "-o", "-X", "-A"],
);
const SQLMAP_FLAG_SPEC = makeFlagSpec(["-H", "-A", "-p", "-r", "-l", "-m", "-c", "-t"], ["-H", "-A"]);
const NMAP_FLAG_SPEC = makeFlagSpec(
	["-oN", "-oX", "-oG", "-oA", "-oS", "-oJ", "-iL", "-p", "-g", "-e", "-rate", "-c"],
	["-p"],
);
const OPENSSL_FLAG_SPEC = makeFlagSpec(["-CAfile", "-CApath", "-cert", "-key", "-in", "-out", "-passin", "-passout"]);
const SSH_FLAG_SPEC = makeFlagSpec(["-i", "-l", "-p", "-P", "-F", "-c", "-E"]);
const DB_FLAG_SPEC = makeFlagSpec(["-u", "-U", "--user", "--username", "-P", "--port", "-D", "-d", "--database", "--dbname", "-a"], ["-p"]);
const SUBDOMAIN_FLAG_SPEC = makeFlagSpec(["-o", "-oJ", "-oD", "-t", "-rl", "-config", "-pc", "-rf"]);
const NC_FLAG_SPEC = makeFlagSpec(["-p", "-w", "-i"]);
const PING_FLAG_SPEC = makeFlagSpec(["-c", "-i", "-w", "-W", "-I", "-s"]);
const BRUTE_FLAG_SPEC = makeFlagSpec(["-l", "-L", "-p", "-P", "-t", "-w", "-o", "-s", "-C"]);
const DEFAULT_NET_FLAG_SPEC = makeFlagSpec([]);

function getCmdNonHostFlags(cmdName: string): CmdFlagSpec {
	switch (cmdName) {
		case "curl":
			return CURL_FLAG_SPEC;
		case "wget":
			return WGET_FLAG_SPEC;
		case "ffuf":
		case "gobuster":
		case "feroxbuster":
		case "dirsearch":
		case "dirb":
		case "wfuzz":
			return FUZZ_FLAG_SPEC;
		case "httpx":
		case "nuclei":
		case "katana":
		case "whatweb":
		case "nikto":
		case "wpscan":
			return WEB_SCAN_FLAG_SPEC;
		case "sqlmap":
			return SQLMAP_FLAG_SPEC;
		case "nmap":
		case "masscan":
			return NMAP_FLAG_SPEC;
		case "openssl":
			return OPENSSL_FLAG_SPEC;
		case "ssh":
		case "scp":
		case "sftp":
			return SSH_FLAG_SPEC;
		case "mysql":
		case "psql":
		case "pg_isready":
		case "redis-cli":
		case "mongo":
		case "mongosh":
			return DB_FLAG_SPEC;
		case "subfinder":
		case "amass":
			return SUBDOMAIN_FLAG_SPEC;
		case "nc":
		case "ncat":
		case "netcat":
			return NC_FLAG_SPEC;
		case "ping":
		case "ping6":
			return PING_FLAG_SPEC;
		case "hydra":
		case "medusa":
		case "ncrack":
			return BRUTE_FLAG_SPEC;
		default:
			return DEFAULT_NET_FLAG_SPEC;
	}
}

/** 必须提取连接/代理目标主机的 CLI 选项（绝不可被 payload 掩码跳过）。 */
const PROXY_VALUE_FLAGS = new Set([
	"-x",
	"--proxy",
	"--preproxy",
	"--socks4",
	"--socks4a",
	"--socks5",
	"--socks5-hostname",
	"-proxy",
	"-http-proxy",
	"-replay-proxy",
]);

/** 显式承载目标 URL 的 CLI 选项（curl 的 -u 为凭据，单独排除）。 */
const URL_VALUE_FLAGS = new Set(["--url", "-u", "-target", "--target", "--second-url", "--csrf-url"]);

const SCHEME_URL_PREFIX_RE =
	/^(?:https?|wss?|ftps?|s?ftp|ssh|ldaps?|rediss?|mysql|postgres(?:ql)?|mongodb|socks(?:4a?|5h?)?):\/\//i;

interface ShellToken {
	text: string;
	afterRedirect: boolean;
	start: number;
	end: number;
}

/** 将命令行按引号感知切分为子命令 token 序列，记录原文偏移并标记文件重定向目标。 */
function splitShellCommands(src: string): ShellToken[][] {
	const cmds: ShellToken[][] = [];
	let curCmd: ShellToken[] = [];
	let cur = "";
	let hasTokenChar = false;
	let tokStart = -1;
	let inSingle = false;
	let inDouble = false;
	let afterRedirect = false;

	const flushToken = (endPos: number) => {
		if (hasTokenChar || cur.length > 0) {
			curCmd.push({
				text: cur,
				afterRedirect,
				start: tokStart >= 0 ? tokStart : endPos,
				end: endPos,
			});
			cur = "";
			hasTokenChar = false;
			tokStart = -1;
			afterRedirect = false;
		}
	};

	const flushCmd = (endPos: number) => {
		flushToken(endPos);
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
			} else if (ch === "\\" && src[i + 1] === "\n") {
				i += 1;
			} else if (ch === "\\" && src[i + 1] === "\r" && src[i + 2] === "\n") {
				i += 2;
			} else if (ch === "\\" && i + 1 < src.length) {
				cur += src[++i]!;
			} else {
				cur += ch;
			}
			continue;
		}

		if (ch === "\\" && src[i + 1] === "\n") {
			i += 1;
			continue;
		}
		if (ch === "\\" && src[i + 1] === "\r" && src[i + 2] === "\n") {
			i += 2;
			continue;
		}
		if (ch === "'") {
			if (tokStart < 0) tokStart = i;
			inSingle = true;
			hasTokenChar = true;
			continue;
		}
		if (ch === '"') {
			if (tokStart < 0) tokStart = i;
			inDouble = true;
			hasTokenChar = true;
			continue;
		}
		if (ch === "\\" && i + 1 < src.length) {
			if (tokStart < 0) tokStart = i;
			cur += src[++i]!;
			hasTokenChar = true;
			continue;
		}
		if (ch === ";" || ch === "|" || ch === "&" || ch === "\n" || ch === "(" || ch === ")") {
			if (ch === "&" && src[i + 1] === ">") {
				flushToken(i);
				i += 1;
				if (src[i + 1] === ">") i += 1;
				afterRedirect = true;
				continue;
			}
			flushCmd(i);
			continue;
		}
		if (ch === ">" || ch === "<") {
			if (/^\d+$/.test(cur)) {
				cur = "";
				hasTokenChar = false;
				tokStart = -1;
			} else {
				flushToken(i);
			}
			let op = ch;
			while (i + 1 < src.length && (src[i + 1] === ">" || src[i + 1] === "<" || src[i + 1] === "&" || src[i + 1] === "|")) {
				op += src[++i]!;
			}
			// 处理 2>&1 / <&0 / >&- 等文件描述符重定向，避免将后续正常参数误标为重定向目标
			if (op.endsWith("&")) {
				const fdStart = i + 1;
				if (src[fdStart] === "-") {
					i = fdStart;
					afterRedirect = false;
					continue;
				}
				if (fdStart < src.length && /\d/.test(src[fdStart]!)) {
					while (i + 1 < src.length && /\d/.test(src[i + 1]!)) {
						i += 1;
					}
					afterRedirect = false;
					continue;
				}
			}
			afterRedirect = true;
			continue;
		}
		if (/\s/.test(ch)) {
			flushToken(i);
			continue;
		}
		if (tokStart < 0) tokStart = i;
		cur += ch;
		hasTokenChar = true;
	}
	flushCmd(src.length);
	return cmds;
}

/** 从双引号或未加引号的 shell 片段中提取可执行命令替换 $(...) / `...` 正文（跳过单引号内字面量）。 */
function extractCommandSubstitutions(raw: string): string[] {
	const subs: string[] = [];
	let inSingle = false;
	let inDouble = false;
	for (let i = 0; i < raw.length; i++) {
		const ch = raw[i]!;
		if (inSingle) {
			if (ch === "'") inSingle = false;
			continue;
		}
		if (ch === "\\" && i + 1 < raw.length) {
			i += 1;
			continue;
		}
		if (!inDouble && ch === "'") {
			inSingle = true;
			continue;
		}
		if (ch === '"') {
			inDouble = !inDouble;
			continue;
		}
		if (ch === "$" && raw[i + 1] === "(" && raw[i + 2] !== "(") {
			let depth = 1;
			let j = i + 2;
			let innerSingle = false;
			let innerDouble = false;
			while (j < raw.length && depth > 0) {
				const c = raw[j]!;
				if (innerSingle) {
					if (c === "'") innerSingle = false;
				} else if (c === "\\" && j + 1 < raw.length) {
					j += 1;
				} else if (!innerDouble && c === "'") {
					innerSingle = true;
				} else if (c === '"') {
					innerDouble = !innerDouble;
				} else if (!innerDouble) {
					if (c === "(") depth++;
					else if (c === ")") depth--;
				}
				j++;
			}
			const body = raw.slice(i + 2, depth === 0 ? j - 1 : j).trim();
			if (body) subs.push(body);
			i = j - 1;
			continue;
		}
		if (ch === "`") {
			let j = i + 1;
			while (j < raw.length) {
				if (raw[j] === "\\" && j + 1 < raw.length) {
					j += 2;
					continue;
				}
				if (raw[j] === "`") break;
				j++;
			}
			const body = raw.slice(i + 1, j).trim();
			if (body) subs.push(body);
			i = j;
			continue;
		}
	}
	return subs;
}

const WRAPPER_CMDS = new Set(["sudo", "env", "nohup", "nice", "stdbuf", "command", "builtin", "exec", "time"]);

function findSubcommandIndex(tokens: readonly ShellToken[]): number {
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
			idx += 1;
			while (idx < tokens.length && tokens[idx]!.text.startsWith("-")) {
				const f = tokens[idx]!.text;
				idx++;
				if ((f === "-k" || f === "-s" || f === "--kill-after" || f === "--signal") && idx < tokens.length) {
					idx++;
				}
			}
			if (idx < tokens.length) idx++; // 跳过 duration 参数
			continue;
		}
		break;
	}
	return idx;
}

function nextNonRedirectIndex(tokens: readonly ShellToken[], startIdx: number): number {
	let idx = startIdx;
	while (idx < tokens.length && tokens[idx]!.afterRedirect) {
		idx++;
	}
	return idx;
}

function extractBareDomainsFromCommands(rest: string, onCandidate: (domain: string) => void): void {
	const subcmds = splitShellCommands(rest);
	for (const tokens of subcmds) {
		const idx = findSubcommandIndex(tokens);
		if (idx >= tokens.length) continue;

		const cmdName = (tokens[idx]!.text.split("/").pop() ?? tokens[idx]!.text).toLowerCase();

		if (isInterpreterCmd(cmdName)) {
			let sawInlineCode = false;
			let skippedScriptFile = false;
			for (let i = idx + 1; i < tokens.length; i++) {
				const tok = tokens[i]!;
				if (tok.afterRedirect) continue;
				const val = tok.text;
				if (!val) continue;
				if (INTERPRETER_INLINE_FLAGS.has(val) || val === "-m") {
					sawInlineCode = true;
					const codeIdx = nextNonRedirectIndex(tokens, i + 1);
					if (val !== "-m" && codeIdx < tokens.length) {
						for (const inlineHost of extractInlineScriptTargets(tokens[codeIdx]!.text)) {
							onCandidate(inlineHost);
						}
					}
					i = codeIdx; // 跳过内联代码字符串本身，避免将无引号 Python/JS 属性如 logging.info / myapp.app 误判为域名
					continue;
				}
				// 紧贴写法：如 python3 -c"..." / node -e"..." / php -r"..." / node --eval="..."
				if (val.startsWith("--eval=") || val.startsWith("--print=")) {
					sawInlineCode = true;
					const inlineCode = val.slice(val.indexOf("=") + 1);
					for (const inlineHost of extractInlineScriptTargets(inlineCode)) {
						onCandidate(inlineHost);
					}
					continue;
				}
				if (/^-(?:c|e|E|r|p).+/.test(val)) {
					sawInlineCode = true;
					for (const inlineHost of extractInlineScriptTargets(val.slice(2))) {
						onCandidate(inlineHost);
					}
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
			const flagSpec = getCmdNonHostFlags(cmdName);
			let afterDoubleDash = false;
			for (let i = idx + 1; i < tokens.length; i++) {
				const tok = tokens[i]!;
				if (tok.afterRedirect) continue;
				const val = tok.text;
				if (!val) continue;
				if (!afterDoubleDash && val === "--") {
					afterDoubleDash = true;
					continue;
				}
				if (!afterDoubleDash) {
					if (flagSpec.exact.has(val)) {
						i = nextNonRedirectIndex(tokens, i + 1); // 跳过紧随其后的文件名/头部/配置值
						continue;
					}
					if (val.startsWith("-")) {
						if (val.length > 2 && !val.startsWith("--") && flagSpec.shortPrefixes.some((p) => val.startsWith(p))) {
							continue;
						}
						const eq = val.indexOf("=");
						if (eq > 0) {
							const flagPart = val.slice(0, eq);
							if (flagSpec.exact.has(flagPart)) {
								continue;
							}
							const rhsRaw = val.slice(eq + 1).replace(/^[^@/]+@/, "");
							const rhs = rhsRaw.split("/")[0]!.replace(/:\d{1,5}$/, "");
							if (looksLikeDomain(rhs)) onCandidate(rhs);
						}
						continue;
					}
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
 * 支持读取环境变量 NUWA_SCOPE_ALLOW_SUBDOMAINS / NUWA_SCOPE_ALLOW_CIDRS / NUWA_SCOPE_ALLOW_LOOPBACK / NUWA_SCOPE_OOB_DOMAINS，overrides 显式字段优先。
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

	const envLoopRaw = (process.env.NUWA_SCOPE_ALLOW_LOOPBACK ?? "").trim().toLowerCase();
	const envLoopback: boolean | undefined =
		envLoopRaw === "1" || envLoopRaw === "true"
			? true
			: envLoopRaw === "0" || envLoopRaw === "false"
				? false
				: undefined;

	const envOobDomains = (process.env.NUWA_SCOPE_OOB_DOMAINS ?? "")
		.split(/[,\s]+/)
		.map((s) => s.trim())
		.filter(Boolean);

	const m = String(mode ?? "ctf").toLowerCase();
	const defaultHosts = host ? [host] : m === "coding" || m === "ops" ? ["127.0.0.1", "localhost", "::1"] : [];

	const allowHosts =
		overrides?.allowHosts !== undefined ? uniqClean(overrides.allowHosts, false) : uniqClean(defaultHosts, false);
	const allowCidrs =
		overrides?.allowCidrs !== undefined ? uniqClean(overrides.allowCidrs, true) : uniqClean(envCidrs, true);
	const denyHosts = uniqClean(overrides?.denyHosts, true);

	const allowLoopback =
		overrides?.allowLoopback !== undefined
			? overrides.allowLoopback
			: envLoopback !== undefined
				? envLoopback
				: !host || isLoopbackHost(host) || m === "coding" || m === "ops" || m === "ctf";

	const oobDomains =
		overrides?.oobDomains !== undefined ? uniqClean(overrides.oobDomains, false) : uniqClean(envOobDomains, false);

	return {
		allowHosts,
		allowCidrs,
		denyHosts,
		allowSubdomains: overrides?.allowSubdomains ?? envSub,
		allowPrivateNetwork: overrides?.allowPrivateNetwork ?? false,
		allowDestructive: overrides?.allowDestructive ?? false,
		allowLoopback,
		oobDomains,
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
 * 优先级：denyHosts 黑名单 > 回环策略（allowLoopback）> allowHosts（精确 / *.domain / allowSubdomains）> oobDomains > IPv4 CIDR > allowPrivateNetwork。
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

	// 2. 本地回环地址策略（未命中 denyHosts；allowLoopback === false 时仅允许 allowHosts 显式放行）
	const isLoopback = !norm.includes("/") && isLoopbackHost(norm);
	if (isLoopback && scope.allowLoopback !== false) {
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

	// 3b. 受控 OOB 回调域名白名单（精确匹配或子域名 *.oobDomain）
	if (!targetIsIpOrCidr) {
		for (const rawOob of scope.oobDomains ?? []) {
			const oobNorm = normalizeHostToken(rawOob, false);
			if (!oobNorm || oobNorm === "*" || !oobNorm.includes(".")) continue;
			if (oobNorm.startsWith("*.")) {
				const base = oobNorm.slice(2);
				if (base && norm.endsWith(`.${base}`) && norm.length > base.length + 1) {
					return { ok: true };
				}
			} else if (
				parseIpv4(oobNorm) === null &&
				!isIpv6Literal(oobNorm) &&
				(norm === oobNorm || (norm.endsWith(`.${oobNorm}`) && norm.length > oobNorm.length + 1))
			) {
				return { ok: true };
			}
		}
	}

	if (isLoopback) {
		return {
			ok: false,
			reason: `回环目标 ${norm} 被默认策略禁止 (allowLoopback=false)`,
		};
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

function extractUrlHostnameLoose(rawUrl: string): string | null {
	const cleaned = rawUrl.trim().replace(/[.,;:!?]+$/, "");
	if (!cleaned) return null;
	try {
		const u = new URL(cleaned);
		return u.hostname || null;
	} catch {
		const m = /^[a-z0-9+.-]+:\/\/(?:[^/@\s]+@)?(\[[^\]]+\]|[^/:?#\s]+)/i.exec(cleaned);
		return m?.[1] ?? null;
	}
}

function extractProxyHostLoose(rawProxy: string): string | null {
	const trimmed = rawProxy.trim();
	if (!trimmed) return null;
	if (SCHEME_URL_PREFIX_RE.test(trimmed)) {
		return extractUrlHostnameLoose(trimmed);
	}
	const noCred = trimmed.replace(/^[^/@\s]+@/, "");
	if (noCred.startsWith("[")) {
		const close = noCred.indexOf("]");
		return close > 1 ? noCred.slice(1, close) : null;
	}
	const hostPart = noCred.split("/")[0]?.replace(/:\d{1,5}$/, "") ?? "";
	return hostPart || null;
}

/**
 * 从命令行文本中提取所有潜在网络目标（主机名、IPv4、IPv6、IPv4 CIDR）。
 * 覆盖：显式 URL、curl、nmap、openssl、nc、ssh、数据库客户端、/dev/tcp、Python/Node socket 连接及裸 IP/域名。
 * 对已识别的 HTTP/网络客户端子命令按位置与选项语义解析：自动掩码 payload/header/output 参数值，
 * 避免 SSRF 测试载荷（如 -d 'url=http://169.254.169.254/' 或 -H 'Referer: ...'）误触发 N-007。
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

	// 0. 对已识别网络/HTTP 客户端子命令做 token 级位置解析：
	//    - 掩码 payload/header/output 等非主机参数值（保留其中可执行 $(...) / `...` 命令替换）
	//    - 优先按位置提取代理选项（-x/--proxy/--preproxy/--socks*）、URL 选项（--url/-u）与位置 URL 主机
	const chars = text.split("");
	const embeddedSubCmds: string[] = [];
	const maskTokenSpan = (tok: ShellToken, scanSubCmds = true) => {
		if (scanSubCmds && tok.end > tok.start) {
			const rawSlice = text.slice(tok.start, tok.end);
			for (const sub of extractCommandSubstitutions(rawSlice)) {
				embeddedSubCmds.push(sub);
			}
		}
		for (let k = tok.start; k < tok.end && k < chars.length; k++) {
			chars[k] = " ";
		}
	};

	const parsedSubcmds = splitShellCommands(text);
	for (const tokens of parsedSubcmds) {
		const cmdIdx = findSubcommandIndex(tokens);
		if (cmdIdx >= tokens.length) continue;
		const cmdName = (tokens[cmdIdx]!.text.split("/").pop() ?? tokens[cmdIdx]!.text).toLowerCase();
		if (!NET_CLIENT_CMDS.has(cmdName)) continue;

		const flagSpec = getCmdNonHostFlags(cmdName);
		let afterDoubleDash = false;

		for (let i = cmdIdx + 1; i < tokens.length; i++) {
			const tok = tokens[i]!;
			if (tok.afterRedirect) continue;
			const val = tok.text;
			if (!afterDoubleDash && val === "--") {
				afterDoubleDash = true;
				continue;
			}

			if (!afterDoubleDash) {
				// 代理/路由选项：提取代理主机并掩码该选项与值，保持从左到右的目标顺序
				if (PROXY_VALUE_FLAGS.has(val)) {
					const nextIdx = nextNonRedirectIndex(tokens, i + 1);
					if (nextIdx < tokens.length) {
						const proxyTok = tokens[nextIdx]!;
						const h = extractProxyHostLoose(proxyTok.text);
						if (h) addTarget(h);
						maskTokenSpan(tok, false);
						maskTokenSpan(proxyTok, true);
						i = nextIdx;
					}
					continue;
				}
				if (cmdName === "curl" && val.startsWith("-x") && val.length > 2) {
					const h = extractProxyHostLoose(val.slice(2));
					if (h) addTarget(h);
					maskTokenSpan(tok, true);
					continue;
				}

				// 非主机值选项（独立参数）：同时掩码选项与紧随其后的值
				if (flagSpec.exact.has(val)) {
					maskTokenSpan(tok, false);
					const nextIdx = nextNonRedirectIndex(tokens, i + 1);
					if (nextIdx < tokens.length) {
						maskTokenSpan(tokens[nextIdx]!, true);
						i = nextIdx;
					}
					continue;
				}

				// 显式 URL 选项（独立参数）：如 --url / ffuf -u / sqlmap -u / httpx -u / nuclei -u（不含 curl -u）
				if (URL_VALUE_FLAGS.has(val) && !(cmdName === "curl" && val === "-u")) {
					const nextIdx = nextNonRedirectIndex(tokens, i + 1);
					if (nextIdx < tokens.length) {
						const urlTok = tokens[nextIdx]!;
						if (SCHEME_URL_PREFIX_RE.test(urlTok.text)) {
							const h = extractUrlHostnameLoose(urlTok.text);
							if (h) addTarget(h);
							maskTokenSpan(tok, false);
							maskTokenSpan(urlTok, true);
							i = nextIdx;
							continue;
						}
					}
					continue;
				}

				if (val.startsWith("-")) {
					// 短选项紧贴值（如 curl -d'url=...' / -H"Referer: ..." / -ehttp://... / -oout.test / -uuser:pass）
					// 必须在 indexOf("=") 之前判断，因为紧贴的 payload 值内部常包含 '='
					if (val.length > 2 && !val.startsWith("--") && flagSpec.shortPrefixes.some((p) => val.startsWith(p))) {
						maskTokenSpan(tok, true);
						continue;
					}
					const eq = val.indexOf("=");
					if (eq > 0) {
						const flagPart = val.slice(0, eq);
						const rhs = val.slice(eq + 1);
						if (PROXY_VALUE_FLAGS.has(flagPart)) {
							const h = extractProxyHostLoose(rhs);
							if (h) addTarget(h);
							maskTokenSpan(tok, true);
							continue;
						}
						if (flagSpec.exact.has(flagPart)) {
							maskTokenSpan(tok, true);
							continue;
						}
						if (URL_VALUE_FLAGS.has(flagPart) && !(cmdName === "curl" && flagPart === "-u") && SCHEME_URL_PREFIX_RE.test(rhs)) {
							const h = extractUrlHostnameLoose(rhs);
							if (h) addTarget(h);
							maskTokenSpan(tok, true);
							continue;
						}
						continue;
					}
					continue;
				}
			}

			// 位置完整 URL 参数：只取 URL 真实连接主机并掩码整个 token（屏蔽 query 中内嵌回调 URL/IP）
			if (SCHEME_URL_PREFIX_RE.test(val)) {
				const h = extractUrlHostnameLoose(val);
				if (h) addTarget(h);
				maskTokenSpan(tok, true);
			}
		}
	}

	const maskedText = chars.join("");

	// 1. 提取剩余文本（非 HTTP 客户端子命令、管道、内联脚本、环境变量等）中的完整 scheme://... URL
	const urlRe =
		/\b(?:https?|wss?|ftps?|s?ftp|ssh|ldaps?|rediss?|mysql|postgres(?:ql)?|mongodb|socks(?:4a?|5h?)?):\/\/[^\s'"`<>|;&)]+/gi;
	const rest = maskedText.replace(urlRe, (fullUrl) => {
		const h = extractUrlHostnameLoose(fullUrl);
		if (h) addTarget(h);
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

	// 10. 网络相关命令与解释器内联脚本（python -c / node -e / bun -e / ruby -e / perl -e / php -r）外部参数及代码目标提取
	extractBareDomainsFromCommands(rest, (cand) => addTarget(cand));

	// 10b. 对原始文本再次单独解析解释器内联脚本（确保被步骤 1 抽走完整 URL 后的拼接/API 域名与 heredoc 均被完整覆盖）
	for (const tokens of parsedSubcmds) {
		const cmdIdx = findSubcommandIndex(tokens);
		if (cmdIdx >= tokens.length) continue;
		const cmdName = (tokens[cmdIdx]!.text.split("/").pop() ?? tokens[cmdIdx]!.text).toLowerCase();
		if (!isInterpreterCmd(cmdName)) continue;
		for (let i = cmdIdx + 1; i < tokens.length; i++) {
			const tok = tokens[i]!;
			if (tok.afterRedirect) continue;
			const val = tok.text;
			if (INTERPRETER_INLINE_FLAGS.has(val)) {
				const nextIdx = nextNonRedirectIndex(tokens, i + 1);
				if (nextIdx < tokens.length) {
					for (const t of extractInlineScriptTargets(tokens[nextIdx]!.text)) {
						addTarget(t, t.includes("/"));
					}
					i = nextIdx;
				}
				continue;
			}
			if (val.startsWith("--eval=") || val.startsWith("--print=")) {
				for (const t of extractInlineScriptTargets(val.slice(val.indexOf("=") + 1))) {
					addTarget(t, t.includes("/"));
				}
				continue;
			}
			if (/^-(?:c|e|E|r|p).+/.test(val)) {
				for (const t of extractInlineScriptTargets(val.slice(2))) {
					addTarget(t, t.includes("/"));
				}
			}
		}
	}
	for (const hdBody of extractHeredocBodiesForInterpreters(text)) {
		for (const t of extractInlineScriptTargets(hdBody)) {
			addTarget(t, t.includes("/"));
		}
	}

	// 10c. 管道喂入解释器（如 echo "import urllib..." | python3 / printf "..." | node）
	for (let c = 1; c < parsedSubcmds.length; c++) {
		const curIdx = findSubcommandIndex(parsedSubcmds[c]!);
		if (curIdx >= parsedSubcmds[c]!.length) continue;
		const curCmd = (parsedSubcmds[c]![curIdx]!.text.split("/").pop() ?? parsedSubcmds[c]![curIdx]!.text).toLowerCase();
		if (!isInterpreterCmd(curCmd)) continue;
		const prevTokens = parsedSubcmds[c - 1]!;
		const prevIdx = findSubcommandIndex(prevTokens);
		if (prevIdx >= prevTokens.length) continue;
		const prevCmd = (prevTokens[prevIdx]!.text.split("/").pop() ?? prevTokens[prevIdx]!.text).toLowerCase();
		if (prevCmd === "echo" || prevCmd === "printf") {
			const pipedCode = prevTokens
				.slice(prevIdx + 1)
				.filter((t) => !t.afterRedirect)
				.map((t) => t.text)
				.join(" ");
			for (const t of extractInlineScriptTargets(pipedCode)) {
				addTarget(t, t.includes("/"));
			}
		}
	}

	// 11. 递归检查掩码值中出现的可执行命令替换（如 -d "x=$(curl http://evil.com)"），严防命令替换绕过 N-007
	for (const sub of embeddedSubCmds) {
		for (const t of extractCommandTargets(sub)) {
			addTarget(t, t.includes("/"));
		}
	}

	return found;
}

const NUWA_PROTECTED_TARGET_RE =
	/(?:^|[\s'"`=(/\\])\.nuwa(?:[\\/](?:state\.json|journal[^/\s'"`)|;&]*|exec-ledger[^/\s'"`)|;&]*|snap(?:[\\/][^\s'"`)|;&]*)?|sessions(?:[\\/][^\s'"`)|;&]*)?|state\.lock|\*)|[\\/]?['"`\s;|&)]|[\\/]?$)/i;

const NUWA_PROTECTED_FILE_ONLY_RE =
	/\.nuwa[\\/](?:state\.json|journal[^/\s'"`)|;&]*|exec-ledger[^/\s'"`)|;&]*|snap(?:[\\/][^\s'"`)|;&]*)?|sessions(?:[\\/][^\s'"`)|;&]*)?|state\.lock)/i;

const NUWA_REDIRECT_RE =
	/(?:>>?|>\||&>>?|tee\s+(?:-[a-zA-Z]+\s+)*)[^\n;|&]*\.nuwa[\\/](?:state\.json|journal|exec-ledger|snap|sessions(?:[\\/][^\s'"`)|;&]*)?|state\.lock)/i;

const NUWA_SESSIONS_REF_RE =
	/(?:^|[\s'"`=(/@<\\:,{[])\.nuwa(?:[\\/]+\.)?[\\/]+sessions(?:[\\/]+[^\s'"`)|;&]*)?(?=$|[\s'"`)|;&/\\,}\]])/i;

const NUWA_SESSIONS_JOIN_RE = /['"]\.nuwa['"]\s*,\s*['"]sessions['"]/i;

const NUWA_VAULT_FILE_RE =
	/(?:^|[\s'"`=(/@<\\:,{[])\.nuwa[\\/]+[^\s'"`)|;&]*vault\.json(?=$|[\s'"`)|;&/\\,}\]])/i;

function hasNuwaSessionsReference(text: string): boolean {
	if (!text.toLowerCase().includes(".nuwa")) return false;
	return NUWA_SESSIONS_REF_RE.test(text) || NUWA_SESSIONS_JOIN_RE.test(text) || NUWA_VAULT_FILE_RE.test(text);
}

const NUWA_FILE_MUTATE_CMD_RE =
	/(?:^|[;&|()\s`])(?:sudo\s+)?(?:rm|unlink|shred|mv|cp|install|ln|truncate|dd|chmod|chown|touch)\b/i;

const NUWA_INPLACE_EDIT_RE =
	/(?:^|[;&|()\s`])(?:sudo\s+)?(?:sed\s+[^;|&]*(?:-[a-zA-Z]*i(?:\b|[.'"])|--in-place\b)|perl\s+[^;|&]*-[a-zA-Z]*i|awk\s+[^;|&]*-i\s+inplace)/i;

const NUWA_SCRIPT_WRITE_RE =
	/\b(?:writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|unlink|rmSync|rmdirSync|renameSync|copyFileSync|truncateSync|openSync|Bun\.write|write_text|write_bytes|rmtree|os\.remove|os\.unlink|os\.rename|os\.replace|shutil\.(?:move|copy|copy2|copyfile|rmtree)|json\.dump|open\s*\([^)]*,\s*['"][wa+x])/i;

/**
 * 检查命令是否试图篡改 .nuwa/ 下的权威状态（state.json、journal、snap、state.lock 或整个 .nuwa 目录），
 * 或读取/外带/篡改 .nuwa/sessions/vault.json 会话保险箱明文凭据。
 */
export function checkNuwaDirTamper(cmd: string): ScopeBlockVerdict | null {
	const text = String(cmd ?? "");
	if (!text.toLowerCase().includes(".nuwa")) return null;

	// 会话保险箱明文凭据保护：严禁任何命令读取、外带或篡改 .nuwa/sessions/ 与 .nuwa/sessions/vault.json
	if (hasNuwaSessionsReference(text)) {
		return {
			block: true,
			reason: "nuwa N-003: 禁止读取或篡改 .nuwa/sessions/vault.json 会话保险箱明文凭据",
		};
	}

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
		if (!seg.toLowerCase().includes(".nuwa")) continue;
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
	opts?: ScopeCheckOptions,
): ScopeBlockVerdict | null {
	const text = String(cmd ?? "");
	if (!text.trim()) return null;
	const layer: EnforcementLayer = opts?.layer ?? "shell-guard";

	if (!scope.allowDestructive) {
		for (const item of DESTRUCTIVE_PATTERNS) {
			if (item.re.test(text)) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(
						layer,
						`拦截高危破坏性操作 (${item.label})；mode=${mode} 默认禁止破坏性指令`,
						"N-008",
					),
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
				layer,
				reason: formatScopeBlockReason(
					layer,
					`靶标越界 (${target}) — ${res.reason ?? "不在授权 Scope 内"}`,
					"N-007",
				),
			};
		}
	}

	return null;
}

const INTERNAL_DOMAIN_LEAK_RE =
	/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|lan|corp|intranet|intra|priv|private|home|localdomain|htb|thm|ctf|lab|box|test|invalid|onion)\b/i;

function isSensitiveIpv4Int(ipInt: number): boolean {
	if (isPrivateIpv4(ipInt) || isLoopbackIpv4(ipInt)) return true;
	const b0 = (ipInt >>> 24) & 0xff;
	const b1 = (ipInt >>> 16) & 0xff;
	// 169.254.0.0/16 链路本地/云元数据与 100.64.0.0/10 运营商级内网
	if (b0 === 169 && b1 === 254) return true;
	if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
	return false;
}

function detectWebSearchTargetLeak(queryText: string, scope: ScopePolicy): string | null {
	const text = queryText.trim();
	if (!text) return null;

	// 1. 检测私网/回环/元数据 IPv4 或 CIDR
	for (const m of text.matchAll(
		/(?<![0-9a-zA-Z._-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:\/(?:3[0-2]|[12]?\d))?(?![0-9a-zA-Z._-])/g,
	)) {
		const ipStr = m[1];
		if (!ipStr) continue;
		const ipInt = parseIpv4(ipStr);
		if (ipInt !== null && isSensitiveIpv4Int(ipInt)) {
			return m[0];
		}
	}

	// 2. 检测私网/本地 IPv6
	const v6Match = /\b(?:fe80:[0-9a-f:]*|fc[0-9a-f]{2}:[0-9a-f:]*|fd[0-9a-f]{2}:[0-9a-f:]*|::1)\b/i.exec(text);
	if (v6Match) return v6Match[0];

	// 3. 检测 localhost 或内网/靶场专属域名特征
	const localMatch = /\blocalhost(?::\d{1,5})?\b/i.exec(text);
	if (localMatch) return localMatch[0];

	const domainMatch = INTERNAL_DOMAIN_LEAK_RE.exec(text);
	if (domainMatch) return domainMatch[0];

	// 4. 检测是否直接外泄当前 Scope 内的具体靶标域名或网段（使用边界匹配防止短主机名误伤普通英文单词）
	const lower = text.toLowerCase();
	for (const rawHost of scope.allowHosts ?? []) {
		const clean = normalizeHostToken(rawHost.replace(/^\*\./, ""), false);
		if (!clean || clean === "*" || clean.length < 4 || !clean.includes(".")) continue;
		const escaped = clean.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		const hostBoundaryRe = new RegExp(`(?<![a-z0-9.-])${escaped}(?![a-z0-9-])`, "i");
		if (hostBoundaryRe.test(lower)) {
			return clean;
		}
	}
	for (const rawCidr of scope.allowCidrs ?? []) {
		const clean = rawCidr.trim().toLowerCase();
		if (clean && lower.includes(clean)) {
			return clean;
		}
	}

	return null;
}

function collectWebSearchQueryText(params: Record<string, unknown>): string {
	const chunks: string[] = [];
	for (const key of ["query", "q", "search_query", "prompt"]) {
		const val = params[key];
		if (typeof val === "string" && val.trim()) {
			chunks.push(val.trim());
		}
	}
	if (Array.isArray(params.queries)) {
		for (const item of params.queries) {
			if (typeof item === "string" && item.trim()) {
				chunks.push(item.trim());
			}
		}
	}
	return chunks.join(" ");
}

function parseHostnameFromUrlStrict(rawUrl: string): string | null {
	try {
		const u = new URL(rawUrl);
		const h = normalizeHostToken(u.hostname, false);
		return h || null;
	} catch {
		return null;
	}
}

/**
 * 扩展全工具面靶标范围护栏与风险拦截（v4.0）：
 * - read：当 input.path 为 http(s):// URL 时校验 hostname 满足 isHostInScope，否则返回 nuwa N-007；
 * - browser：校验 input.url (http/https/ws/wss) 与 input.allowed_domains 满足 isHostInScope，非 coding 模式禁止 allow_file_access: true；
 * - web_search：安全评估模式下，未设 NUWA_ALLOW_WEB_SEARCH=1 且查询含私网 IP/内网域名/目标特征时拦截；
 * - eval：提取 input.code 中的 https?:// URL 校验 isHostInScope，并调用 checkNuwaDirTamper(code)；
 * - bash：兼容委托 checkNuwaDirTamper 与 checkScopeAndRisk。
 */
export function checkToolScopeAndRisk(
	toolName: string,
	input: Record<string, unknown> | null | undefined,
	scope: ScopePolicy,
	mode: Mode | string = "ctf",
	opts?: ScopeCheckOptions,
): ScopeBlockVerdict | null {
	const name = String(toolName ?? "").trim().toLowerCase();
	if (!name) return null;
	const params = (input && typeof input === "object" ? input : {}) as Record<string, unknown>;
	const normMode = String(mode ?? "ctf").trim().toLowerCase();

	if (name === "bash") {
		const cmd = typeof params.command === "string" ? params.command : "";
		const tamper = checkNuwaDirTamper(cmd);
		if (tamper) return tamper;
		return checkScopeAndRisk(cmd, scope, normMode, { layer: opts?.layer ?? "shell-guard" });
	}

	if (name === "read" || name === "read_file" || name === "fetch" || name === "web_fetch") {
		const layer: EnforcementLayer = opts?.layer ?? "egress-proxy";
		const rawPath =
			typeof params.path === "string"
				? params.path.trim()
				: typeof params.file_path === "string"
					? params.file_path.trim()
					: typeof params.url === "string"
						? params.url.trim()
						: "";
		if ((name === "read" || name === "read_file" || !/^https?:\/\//i.test(rawPath)) && rawPath) {
			const slashPath = rawPath.replace(/\\/g, "/");
			let decodedPath = slashPath;
			try {
				decodedPath = decodeURIComponent(slashPath);
			} catch {
				// 忽略非法百分号序列，按原始规范路径校验
			}
			const normSlash = posixPath.normalize(slashPath);
			const normDecoded = posixPath.normalize(decodedPath);
			const sessionsPathRe = /(?:^|\/)\.nuwa\/sessions(?:\/|$)/i;
			if (
				sessionsPathRe.test(slashPath) ||
				sessionsPathRe.test(normSlash) ||
				sessionsPathRe.test(decodedPath) ||
				sessionsPathRe.test(normDecoded)
			) {
				return {
					block: true,
					layer: "shell-guard",
					reason: "nuwa N-003: 禁止通过 read 工具读取 .nuwa/sessions/vault.json 明文凭据",
				};
			}
		}
		if (/^https?:\/\//i.test(rawPath)) {
			const host = parseHostnameFromUrlStrict(rawPath);
			if (!host) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(layer, `${name} URL 非法或缺少有效目标主机 (${rawPath})`, "N-007"),
				};
			}
			const res = isHostInScope(host, scope);
			if (!res.ok) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(
						layer,
						`${name} 远程靶标越界 (${host}) — ${res.reason ?? "不在授权 Scope 内"}`,
						"N-007",
					),
				};
			}
		}
		return null;
	}

	if (name === "browser" || name.startsWith("browser_")) {
		const layer: EnforcementLayer = opts?.layer ?? "egress-proxy";
		const allowFileAccess = params.allow_file_access === true || params.allowFileAccess === true;
		if (allowFileAccess && normMode !== "coding") {
			return {
				block: true,
				layer,
				reason: formatScopeBlockReason(layer, `browser 在 mode=${normMode} 下禁止开启 allow_file_access: true`, "N-008"),
			};
		}

		// coding 模式允许访问本地开发回环地址（仍严格服从 denyHosts 黑名单）
		const browserScope: ScopePolicy =
			normMode === "coding" && scope.allowLoopback === false ? { ...scope, allowLoopback: true } : scope;

		const rawUrl = typeof params.url === "string" ? params.url.trim() : "";
		if (rawUrl && rawUrl.toLowerCase() !== "about:blank") {
			if (/^file:\/\//i.test(rawUrl)) {
				if (normMode !== "coding") {
					return {
						block: true,
						layer,
						reason: formatScopeBlockReason(layer, `browser 在 mode=${normMode} 下禁止访问本地 file:// URL`, "N-008"),
					};
				}
			} else if (/^(?:https?|wss?):\/\//i.test(rawUrl)) {
				const host = parseHostnameFromUrlStrict(rawUrl);
				if (!host) {
					return {
						block: true,
						layer,
						reason: formatScopeBlockReason(layer, `browser URL 非法或无法解析主机 (${rawUrl})`, "N-007"),
					};
				}
				const res = isHostInScope(host, browserScope);
				if (!res.ok) {
					return {
						block: true,
						layer,
						reason: formatScopeBlockReason(
							layer,
							`browser 目标越界 (${host}) — ${res.reason ?? "不在授权 Scope 内"}`,
							"N-007",
						),
					};
				}
			} else if (/^[a-z][a-z0-9+.-]*:/i.test(rawUrl)) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(layer, `browser 不受支持的非授权协议 (${rawUrl})`, "N-007"),
				};
			} else {
				const host = parseTargetHost(rawUrl);
				if (host) {
					const res = isHostInScope(host, browserScope);
					if (!res.ok) {
						return {
							block: true,
							layer,
							reason: formatScopeBlockReason(
								layer,
								`browser 目标越界 (${host}) — ${res.reason ?? "不在授权 Scope 内"}`,
								"N-007",
							),
						};
					}
				}
			}
		}

		const rawDomains = params.allowed_domains ?? params.allowedDomains;
		const domainList: string[] = Array.isArray(rawDomains)
			? rawDomains.map((d) => String(d ?? "").trim()).filter(Boolean)
			: typeof rawDomains === "string"
				? rawDomains
						.split(/[,\s]+/)
						.map((d) => d.trim())
						.filter(Boolean)
				: [];

		for (const rawDomain of domainList) {
			if (rawDomain === "*" && !(browserScope.allowHosts ?? []).includes("*")) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(layer, "browser allowed_domains 禁止配置全局通配符 *", "N-007"),
				};
			}
			const candHost = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawDomain)
				? (parseHostnameFromUrlStrict(rawDomain) ?? rawDomain)
				: rawDomain;
			const res = isHostInScope(candHost, browserScope);
			if (!res.ok) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(
						layer,
						`browser allowed_domains 越界 (${rawDomain}) — ${res.reason ?? "不在授权 Scope 内"}`,
						"N-007",
					),
				};
			}
		}

		return null;
	}

	if (name === "web_search" || name === "websearch" || name === "google_search") {
		const layer: EnforcementLayer = opts?.layer ?? "egress-proxy";
		const isSecurityEvalMode = normMode !== "coding" && normMode !== "ops";
		if (!isSecurityEvalMode) return null;
		if ((process.env.NUWA_ALLOW_WEB_SEARCH ?? "").trim() === "1") return null;

		const queryText = collectWebSearchQueryText(params);
		const leak = detectWebSearchTargetLeak(queryText, scope);
		if (leak) {
			return {
				block: true,
				layer,
				reason: formatScopeBlockReason(
					layer,
					`web_search 在安全评估模式 (${normMode}) 下禁止外泄目标私网 IP 或内网域名特征 (${leak})；确需开启请设 NUWA_ALLOW_WEB_SEARCH=1`,
					"N-007",
				),
			};
		}
		return null;
	}

	if (name === "eval") {
		const layer: EnforcementLayer = opts?.layer ?? "shell-guard";
		const code =
			typeof params.code === "string"
				? params.code
				: typeof params.script === "string"
					? params.script
					: "";
		if (!code.trim()) return null;

		const tamper = checkNuwaDirTamper(code);
		if (tamper) return tamper;
		if (hasNuwaSessionsReference(code)) {
			return {
				block: true,
				layer,
				reason: "nuwa N-003: 禁止读取或篡改 .nuwa/sessions/vault.json 会话保险箱明文凭据",
			};
		}

		const targets = extractInlineScriptTargets(code);
		for (const host of targets) {
			const res = isHostInScope(host, scope);
			if (!res.ok) {
				return {
					block: true,
					layer,
					reason: formatScopeBlockReason(
						layer,
						`eval 代码内 URL/主机靶标越界 (${host}) — ${res.reason ?? "不在授权 Scope 内"}`,
						"N-007",
					),
				};
			}
		}
		return null;
	}

	return null;
}

export interface UnifiedNetworkEnvOptions {
	extraNoProxy?: readonly string[];
	includeAllProxy?: boolean;
	ghHttpTimeoutSec?: number;
	/** 启用 Bun 运行时安全模式（Issue #53）：socks* 代理仅注入 NUWA_EGRESS_PROXY/ALL_PROXY，不写入触发 UnsupportedProxyProtocol 的 HTTP_PROXY/HTTPS_PROXY */
	bunSafe?: boolean;
	/** 可选模型 API 专用代理（http/https URL 或 "direct"/"none"） */
	modelProxy?: string | null;
}

const VALID_EGRESS_SCHEMES = new Set(["http:", "https:", "socks4:", "socks4a:", "socks5:", "socks5h:"]);

function sanitizeEgressProxyUrl(raw: string | null | undefined): string {
	const s = String(raw ?? "").trim();
	if (!s) return "";
	if (/[\r\n\s]/.test(s)) {
		throw new Error(`非法 egressUrl: 包含空白或换行符 (${JSON.stringify(s)})`);
	}
	let parsed: URL;
	try {
		parsed = new URL(s);
	} catch {
		throw new Error(`非法 egressUrl: 无法解析 URL (${JSON.stringify(s)})`);
	}
	if (!VALID_EGRESS_SCHEMES.has(parsed.protocol.toLowerCase()) || !parsed.hostname) {
		throw new Error(`非法 egressUrl 协议或主机: ${JSON.stringify(s)}`);
	}
	return s;
}

/**
 * 统一跨运行时网络边界环境变量构造器（Issue #48 / NW-28, Issue #53）：
 * 为 bash/curl/wget/python/node/bun/ruby/perl/php/gh 统一注入 HTTP_PROXY/http_proxy/HTTPS_PROXY/https_proxy/NO_PROXY/no_proxy，
 * 同步写入 NUWA_SCOPE_ALLOW_HOSTS 与 GH_HTTP_TIMEOUT，避免不同工具层各自走不同代理或无限挂死。
 */
export function buildUnifiedNetworkEnv(
	egressUrl?: string | null,
	allowedHosts?: readonly string[] | ScopePolicy | null,
	opts: UnifiedNetworkEnvOptions = {},
): Record<string, string> {
	const cleanProxy = sanitizeEgressProxyUrl(egressUrl);
	const rawModelProxy = String(opts.modelProxy ?? "").trim();
	const modelProxyDirect = rawModelProxy.toLowerCase() === "direct" || rawModelProxy.toLowerCase() === "none";
	const cleanModelProxy = rawModelProxy && !modelProxyDirect ? sanitizeEgressProxyUrl(rawModelProxy) : "";
	if (cleanModelProxy && /^socks/i.test(cleanModelProxy)) {
		throw new Error(`非法 modelProxy 协议（Bun fetch 仅支持 http/https）: ${JSON.stringify(cleanModelProxy)}`);
	}

	const rawAllowed = Array.isArray(allowedHosts)
		? allowedHosts
		: allowedHosts && typeof allowedHosts === "object" && Array.isArray((allowedHosts as ScopePolicy).allowHosts)
			? (allowedHosts as ScopePolicy).allowHosts
			: [];
	const normalizedAllowed = uniqClean(rawAllowed, true);

	const noProxyItems: string[] = [];
	const noProxySeen = new Set<string>();
	const addNoProxy = (item: string) => {
		const v = String(item ?? "").trim().toLowerCase();
		if (!v || /[\r\n\s,]/.test(v) || noProxySeen.has(v)) return;
		noProxySeen.add(v);
		noProxyItems.push(v);
	};

	// 本地回环与代理自身宿主始终直连，避免代理循环
	addNoProxy("127.0.0.1");
	addNoProxy("localhost");
	addNoProxy("::1");
	if (cleanProxy) {
		try {
			const proxyHost = normalizeHostToken(new URL(cleanProxy).hostname, false);
			if (proxyHost && (proxyHost === "host.docker.internal" || isLoopbackHost(proxyHost))) {
				addNoProxy(proxyHost);
			}
		} catch {
			/* ignore */
		}
	}
	for (const extra of opts.extraNoProxy ?? []) {
		addNoProxy(extra);
	}

	const noProxyVal = noProxyItems.join(",");
	const ghTimeout =
		typeof opts.ghHttpTimeoutSec === "number" && Number.isFinite(opts.ghHttpTimeoutSec) && opts.ghHttpTimeoutSec > 0
			? String(Math.floor(opts.ghHttpTimeoutSec))
			: "5";

	const isSocksProxy = Boolean(cleanProxy && /^socks/i.test(cleanProxy));
	const effectiveHttpProxy = cleanModelProxy
		? cleanModelProxy
		: modelProxyDirect || (opts.bunSafe && isSocksProxy)
			? ""
			: cleanProxy;

	const env: Record<string, string> = {
		HTTP_PROXY: effectiveHttpProxy,
		http_proxy: effectiveHttpProxy,
		HTTPS_PROXY: effectiveHttpProxy,
		https_proxy: effectiveHttpProxy,
		NO_PROXY: noProxyVal,
		no_proxy: noProxyVal,
		GH_HTTP_TIMEOUT: ghTimeout,
	};

	if (cleanProxy) {
		env.NUWA_EGRESS_PROXY = cleanProxy;
		env.NUWA_EGRESS = cleanProxy;
		if (opts.includeAllProxy || isSocksProxy) {
			env.ALL_PROXY = cleanProxy;
			env.all_proxy = cleanProxy;
		}
	}
	if (normalizedAllowed.length > 0) {
		env.NUWA_SCOPE_ALLOW_HOSTS = normalizedAllowed.join(",");
	}
	return env;
}
