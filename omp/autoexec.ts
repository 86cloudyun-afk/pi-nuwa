/**
 * 确定性侦察执行器（v3.0）：omp 扩展自主跑命令入账，支持跨平台探测、E2+ 归一化、
 * 外置规则热加载、失败三分类（network / blocked_by_waf / empty）以及总预算与取消控制。
 *
 * 约束：仅使用 import type 引用 ./nuwa，严禁运行时 import ./nuwa。
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { Cfg, NuwaState, Phase } from "./nuwa";

export interface ExecLikeResult {
	stdout: string;
	stderr: string;
	code: number;
	killed?: boolean;
}

export type ExecLike = (
	command: string,
	args: string[],
	options?: { timeout?: number; cwd?: string; signal?: AbortSignal },
) => Promise<ExecLikeResult>;

export type AutoKind = "service" | "endpoint" | "asset" | "vuln" | "note" | "cred" | "loot";

export interface AutoFactMeta {
	ports?: number[];
	paths?: string[];
	server?: string;
	tech?: string[];
	status?: number;
	san?: string[];
	waf?: string;
}

export interface AutoFact {
	kind: AutoKind;
	title: string;
	detail: string;
	command: string;
	output: string;
	meta?: AutoFactMeta;
}

export interface AutoRule {
	key: string;
	phase: Phase;
	timeoutMs: number;
	script(st: NuwaState): string;
	parse(res: ExecLikeResult, st: NuwaState): AutoFact | null;
}

export type AutoParserName = "http" | "ports" | "dirs" | "tls" | "probe";
export type AutoErrorKind = "network" | "blocked_by_waf" | "empty";

export interface AutoFailureClassification {
	kind: AutoErrorKind;
	errorKind: AutoErrorKind;
	retryAfterMs?: number;
	waf?: string;
	reason: string;
}

export interface AutoRunResult {
	ok: boolean;
	fact?: AutoFact;
	error?: string;
	errorKind?: AutoErrorKind;
	retryAfterMs?: number;
	waf?: string;
}

export interface LoadedAutoRules {
	rules: readonly AutoRule[];
	source: "project" | "user" | "builtin";
	path?: string;
	error?: string;
}

export type BudgetSkipReason = "budget_exceeded" | "aborted";

export interface AutoBatchItemResult {
	id: string;
	key: string;
	canonicalKey: string;
	result: AutoRunResult;
	durationMs: number;
}

export interface AutoBatchOptions {
	budgetMs?: number;
	concurrency?: number;
	signal?: AbortSignal;
	agentHome?: string;
	getState?: () => NuwaState | null;
	onResult?: (item: AutoBatchItemResult) => void | Promise<void>;
	onBudgetSkip?: (remainingIds: string[], reason: BudgetSkipReason) => void | Promise<void>;
}

export interface AutoBatchManagedResult {
	results: Record<string, AutoRunResult>;
	items: AutoBatchItemResult[];
	skippedIds: string[];
	skipReason?: BudgetSkipReason;
	elapsedMs: number;
	ruleSource: "project" | "user" | "builtin";
	ruleError?: string;
}

export const AUTO_KEYS = [
	"recon:http",
	"recon:ports",
	"recon:dirs",
	"recon:tlsjs",
	"surface:sensitive",
	"surface:api",
] as const;

const AUTO_KEY_SET = new Set<string>(AUTO_KEYS);
const VALID_PHASES = new Set<Phase>(["recon", "surface", "vuln", "exploit", "post", "report"]);
const VALID_PARSERS = new Set<AutoParserName>(["http", "ports", "dirs", "tls", "probe"]);

/** 剥离扩张轮次前缀（如 e2:recon:http -> recon:http），用于跨轮次复用自动规则。 */
export function canonicalAutoKey(key: string): string {
	return String(key ?? "")
		.trim()
		.replace(/^e\d+:/i, "");
}

/** 单引号转义，供 bash -lc 内联安全传参。 */
export function shellQuote(value: string): string {
	return `'${String(value ?? "").replace(/'/g, `'\\''`)}'`;
}

export function originOf(st: NuwaState): string {
	try {
		const u = new URL(st.project.url);
		return `${u.protocol}//${u.host}`;
	} catch {
		return st.project.url;
	}
}

function clip(text: string, max: number): string {
	const s = String(text ?? "").replace(/\r/g, "").trim();
	return s.length > max ? `${s.slice(0, max)}…` : s;
}

function headerValue(headers: string, name: string): string {
	const re = new RegExp(`^${name}:\\s*(.+)$`, "im");
	return headers.match(re)?.[1]?.trim() ?? "";
}

function titleOf(body: string): string {
	return body.match(/<title[^>]*>([^<]{0,120})<\/title>/i)?.[1]?.trim() ?? "";
}

const WAF_SIGNATURES: ReadonlyArray<{ name: string; re: RegExp }> = [
	{ name: "cloudflare", re: /\b(?:cloudflare|cf-ray|__cf_bm|cf-chl-bypass)\b/i },
	{ name: "imperva", re: /\b(?:imperva|incapsula|incap_ses|visid_incap|x-iinfo)\b/i },
	{ name: "akamai", re: /\b(?:akamaighost|ak_bmsc|akamai-grn|x-akamai-)\b/i },
	{ name: "modsecurity", re: /\b(?:mod_security|modsecurity)\b/i },
	{ name: "aws-waf", re: /\b(?:x-amzn-waf-|aws-waf)\b/i },
	{ name: "aliyun-waf", re: /\b(?:ali-waf|errors\.aliyun\.com|waf\.aliyun)\b/i },
	{ name: "safedog", re: /\b(?:safedog|waf\/2\.0)\b/i },
	{ name: "sucuri", re: /\b(?:x-sucuri-id|sucuri\/cloudproxy)\b/i },
	{ name: "datadome", re: /\b(?:x-datadome|datadome)\b/i },
	{ name: "f5-bigip", re: /\b(?:bigipserver|f5-trafficshield)\b/i },
];

const WAF_CHALLENGE_RE =
	/\b(?:just a moment|attention required|challenge-platform|cf-turnstile|enable javascript and cookies|captcha|hcaptcha|recaptcha|web application firewall|request blocked|access denied|forbidden by administrative rules|rate limit exceeded|too many requests)\b/i;

function detectWafName(headers: string, body: string, status?: number): string | undefined {
	const combined = `${headers}\n${body}`;
	for (const sig of WAF_SIGNATURES) {
		if (sig.re.test(combined)) {
			return sig.name;
		}
	}
	if (status && (status === 403 || status === 406 || status === 429 || status === 503) && WAF_CHALLENGE_RE.test(combined)) {
		return status === 429 ? "rate-limit" : "generic-waf";
	}
	return undefined;
}

const TECH_RULES: ReadonlyArray<{ name: string; re: RegExp }> = [
	{ name: "nginx", re: /\bnginx\b/i },
	{ name: "apache", re: /\bapache\b/i },
	{ name: "openresty", re: /\bopenresty\b/i },
	{ name: "caddy", re: /\bcaddy\b/i },
	{ name: "iis", re: /\bmicrosoft-iis\b/i },
	{ name: "tomcat", re: /\b(?:apache-coyote|tomcat|jsessionid)\b/i },
	{ name: "spring", re: /\b(?:whitelabel error page|x-application-context|spring)\b/i },
	{ name: "php", re: /\b(?:php\/|phpsessid)\b|^x-powered-by:\s*php\b/im },
	{ name: "express", re: /^x-powered-by:\s*express\b/im },
	{ name: "nextjs", re: /\b(?:__next_data__|x-powered-by:\s*next\.js)\b/i },
	{ name: "aspnet", re: /\b(?:x-aspnet-version|asp\.net_sessionid)\b/i },
	{ name: "django", re: /\b(?:wsgiserver|csrftoken)\b/i },
	{ name: "flask", re: /\bwerkzeug\b/i },
	{ name: "laravel", re: /\blaravel_session\b/i },
	{ name: "thinkphp", re: /\bthinkphp\b/i },
	{ name: "shiro", re: /\brememberme=deleteme\b/i },
	{ name: "wordpress", re: /\bwp-(?:content|includes)\b/i },
	{ name: "grafana", re: /\bgrafana\b/i },
	{ name: "gitlab", re: /\b_gitlab_session\b|\bgitlab\b/i },
	{ name: "jenkins", re: /^x-jenkins:/im },
];

function extractHttpTech(headers: string, body: string): string[] {
	const combined = `${headers}\n${body}`;
	const found: string[] = [];
	for (const item of TECH_RULES) {
		if (item.re.test(combined)) {
			found.push(item.name);
		}
	}
	return found;
}

const DIR_PATHS = [
	"/admin",
	"/login",
	"/api",
	"/api/v1",
	"/swagger-ui.html",
	"/swagger/index.html",
	"/openapi.json",
	"/robots.txt",
	"/.git/HEAD",
	"/.env",
	"/backup.zip",
	"/config.json",
	"/actuator",
	"/actuator/health",
	"/graphql",
	"/health",
	"/metrics",
	"/debug",
	"/console",
	"/uploads/",
	"/files/",
	"/download",
	"/test",
];

const PORT_LIST = [
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389,
	5432, 6379, 8080, 8443, 9000, 9200, 11211, 27017,
];

function parseHttpFact(res: ExecLikeResult, st: NuwaState): AutoFact | null {
	const head = res.stdout.split("---HEAD---")[1]?.split("---BODY---")[0] ?? "";
	const body = res.stdout.split("---BODY---")[1] ?? "";
	const fin = res.stdout.match(/^FINAL\s+(\d{3})\s+(\d+)\s+(\S+)/m);
	const statusHead = head.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/m)?.[1];
	const code = fin?.[1] ?? statusHead ?? "000";
	const size = fin?.[2] ?? "0";
	if (code === "000" && !head.trim()) return null;

	const statusNum = Number(code);
	const rawServer = headerValue(head, "server");
	const server = rawServer || "-";
	const powered = headerValue(head, "x-powered-by") || "-";
	const location = headerValue(head, "location") || "-";
	const title = titleOf(body) || "-";
	const tech = extractHttpTech(head, body);
	const waf = detectWafName(head, body, Number.isFinite(statusNum) ? statusNum : undefined);

	const meta: AutoFactMeta = {
		...(Number.isFinite(statusNum) && statusNum > 0 ? { status: statusNum } : {}),
		...(rawServer ? { server: rawServer } : {}),
		tech,
		...(waf ? { waf } : {}),
	};

	return {
		kind: "service",
		title: `HTTP ${code} ${server}`.slice(0, 120),
		detail: `url=${fin?.[3] ?? st.project.url} size=${size} server=${server} x-powered-by=${powered} location=${location} title=${title}`,
		command: clip(`curl -k -sS -D - ${st.project.url}`, 400),
		output: clip(head.trim() || `code=${code}`, 800),
		meta,
	};
}

function buildPortsPythonScript(ports: readonly number[], host: string): string {
	const safePorts = ports.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535);
	const py = [
		"import socket, sys",
		"from concurrent.futures import ThreadPoolExecutor",
		"host = sys.argv[1].strip('[]')",
		`ports = [${safePorts.join(",")}]`,
		"def probe(p):",
		"    try:",
		"        with socket.create_connection((host, p), timeout=0.6):",
		"            return p",
		"    except Exception:",
		"        return None",
		"with ThreadPoolExecutor(max_workers=16) as ex:",
		"    found = [p for p in ex.map(probe, ports) if p is not None]",
		"for p in sorted(found):",
		"    print(f'open {p}')",
	].join("\n");
	return `python3 -c ${shellQuote(py)} ${shellQuote(host)}`;
}

function parsePortsFact(res: ExecLikeResult, st: NuwaState, portCount = PORT_LIST.length): AutoFact | null {
	const nums = [...new Set([...res.stdout.matchAll(/^open\s+(\d{1,5})$/gm)].map((m) => Number(m[1])))].filter(
		(n) => Number.isInteger(n) && n >= 1 && n <= 65535,
	);
	if (nums.length === 0) return null;
	const csv = nums.join(",");
	const tcpTokens = nums.map((p) => `${p}/tcp`).join(" ");
	return {
		kind: "service",
		title: `${st.project.host} TCP 开放 ${nums.length} 端口`,
		detail: `tcp connect (${csv}): ${tcpTokens}`,
		command: clip(`python3 socket.create_connection scan ${st.project.host} (${portCount} ports)`, 400),
		output: clip(nums.map((p) => `${p}/tcp open`).join("\n"), 800),
		meta: { ports: nums },
	};
}

function parseDirsFact(res: ExecLikeResult, st: NuwaState, pathCount = DIR_PATHS.length): AutoFact | null {
	const rows = res.stdout
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => /^\/\S*\s+(200|204|301|302|307|401|403|405|500)\s+\d+/.test(l));
	if (rows.length === 0) return null;

	const paths: string[] = [];
	const codes: number[] = [];
	for (const row of rows) {
		const m = /^(\/\S*)\s+(\d{3})\b/.exec(row);
		if (!m) continue;
		if (!paths.includes(m[1])) paths.push(m[1]);
		codes.push(Number(m[2]));
	}
	const preferredStatus = codes.find((c) => c >= 200 && c < 300) ?? codes[0] ?? 200;

	return {
		kind: "endpoint",
		title: `发现 ${rows.length} 条路径`,
		detail: rows.map((r) => r.replace(/\s+/g, " ")).join(" | ").slice(0, 600),
		command: clip(`curl HEAD ${pathCount} paths @ ${originOf(st)}`, 400),
		output: clip(rows.join("\n"), 800),
		meta: { paths, status: preferredStatus },
	};
}

function extractSanEntries(sanText: string): string[] {
	const out: string[] = [];
	const seen = new Set<string>();
	for (const m of sanText.matchAll(/(?:DNS|IP Address):\s*([^\s,;]+)/gi)) {
		const val = m[1]?.trim().toLowerCase();
		if (val && !seen.has(val)) {
			seen.add(val);
			out.push(val);
		}
	}
	return out;
}

function parseTlsFact(res: ExecLikeResult, st: NuwaState): AutoFact | null {
	const out = res.stdout;
	if (!/subject=/i.test(out) && !/notAfter=/i.test(out)) return null;
	const subject = out.match(/subject=\s*(.+)/i)?.[1]?.trim() ?? "-";
	const issuer = out.match(/issuer=\s*(.+)/i)?.[1]?.trim() ?? "-";
	const notAfter = out.match(/notAfter=\s*(.+)/i)?.[1]?.trim() ?? "-";
	const sanRaw = out.match(/X509v3 Subject Alternative Name:\s*\n?\s*(.+)/i)?.[1]?.trim() ?? "-";
	const sanList = sanRaw !== "-" ? extractSanEntries(sanRaw) : [];

	return {
		kind: "service",
		title: `TLS ${subject}`.slice(0, 120),
		detail: `subject=${subject} issuer=${issuer} notAfter=${notAfter} san=${sanRaw}`,
		command: clip(`openssl s_client -connect ${st.project.host}:${st.project.port || 443}`, 400),
		output: clip(out, 800),
		meta: { san: sanList },
	};
}

function parseProbeFact(key: string, pathCount: number, res: ExecLikeResult, st: NuwaState): AutoFact | null {
	const rows: string[] = [];
	for (const rawLine of res.stdout.replace(/\r/g, "").split("\n")) {
		const trimmed = rawLine.trim();
		if (!trimmed) continue;
		if (/^FINAL\s+\d{3}\b/.test(trimmed)) continue;
		if (/^\/\S*\s+/.test(trimmed)) {
			rows.push(trimmed);
		} else if (rows.length > 0) {
			// 兼容未压平的多行响应体续行（如多行 JSON / .env 内容）拼接回上一条命中记录
			rows[rows.length - 1] = `${rows[rows.length - 1]} ${trimmed}`.slice(0, 400);
		}
	}
	if (rows.length === 0) return null;

	const paths: string[] = [];
	let detectedStatus = 200;
	for (const rawRow of rows) {
		const trimmed = rawRow.trim();
		const m = /^(\/\S*)\s+(?:(\d{3})\b\s*)?/.exec(trimmed);
		if (m?.[1] && !paths.includes(m[1])) {
			paths.push(m[1]);
		}
		if (m?.[2]) {
			detectedStatus = Number(m[2]);
		}
	}

	const normKey = canonicalAutoKey(key);
	const isSensitive = normKey === "surface:sensitive";
	const hasGit = rows.some((r) => r.trim().startsWith("/.git/HEAD"));
	const hasEnv = rows.some((r) => r.trim().startsWith("/.env"));
	const openapi = rows.some((r) => /"(openapi|swagger)"\s*:/.test(r));
	const title = isSensitive
		? hasGit || hasEnv
			? `敏感文件暴露 ${rows.length} 条`
			: `敏感路径可读 ${rows.length} 条`
		: normKey === "surface:api"
			? openapi
				? "API 文档暴露"
				: `API 面可达 ${rows.length} 条`
			: `探测路径命中 ${rows.length} 条`;

	return {
		kind: isSensitive && (hasGit || hasEnv) ? "vuln" : "endpoint",
		title,
		detail: rows.map((r) => r.trim().slice(0, 180)).join(" | ").slice(0, 700),
		command: clip(`curl ${pathCount} paths @ ${originOf(st)}`, 400),
		output: clip(rows.join("\n"), 800),
		meta: { paths, status: detectedStatus },
	};
}

function httpRule(timeoutMs = 18_000): AutoRule {
	return {
		key: "recon:http",
		phase: "recon",
		timeoutMs,
		script(st) {
			const url = shellQuote(st.project.url);
			return [
				`h=$(mktemp); b=$(mktemp)`,
				`curl -k -sS -D "$h" -o "$b" --max-time 12 -w 'FINAL %{http_code} %{size_download} %{url_effective}\\n' ${url}`,
				`rc=$?`,
				`echo '---HEAD---'`,
				`cat "$h"`,
				`echo '---BODY---'`,
				`head -c 400 "$b"`,
				`rm -f "$h" "$b"`,
				`exit $rc`,
			].join("\n");
		},
		parse: parseHttpFact,
	};
}

function portsRule(ports: readonly number[] = PORT_LIST, timeoutMs = 50_000): AutoRule {
	return {
		key: "recon:ports",
		phase: "recon",
		timeoutMs,
		script(st) {
			return buildPortsPythonScript(ports, st.project.host);
		},
		parse(res, st) {
			return parsePortsFact(res, st, ports.length);
		},
	};
}

function dirsRule(paths: readonly string[] = DIR_PATHS, timeoutMs = 45_000): AutoRule {
	return {
		key: "recon:dirs",
		phase: "recon",
		timeoutMs,
		script(st) {
			const base = shellQuote(originOf(st));
			return [
				`BASE=${base}`,
				`hits=0; net_rc=0; waf_429=0`,
				`for p in ${paths.map(shellQuote).join(" ")}; do`,
				`  out=$(curl -k -sS -o /dev/null --max-time 6 -w '%{http_code} %{size_download} %{redirect_url}' "$BASE$p" 2>/dev/null)`,
				`  rc=$?`,
				`  code=\${out%% *}`,
				`  case "$rc" in 6|7|28|35|52|56) net_rc=$rc ;; esac`,
				`  [ "$code" = "429" ] && waf_429=1`,
				`  case "$code" in 200|204|301|302|307|401|403|405|500) hits=$((hits + 1)); echo "$p $out";; esac`,
				`done`,
				`if [ "$hits" -eq 0 ]; then`,
				`  if [ "$waf_429" -eq 1 ]; then echo "FINAL 429 0 $BASE"; exit 0; fi`,
				`  if [ "$net_rc" -ne 0 ]; then exit "$net_rc"; fi`,
				`fi`,
				`exit 0`,
			].join("\n");
		},
		parse(res, st) {
			return parseDirsFact(res, st, paths.length);
		},
	};
}

function tlsRule(timeoutMs = 15_000): AutoRule {
	return {
		key: "recon:tlsjs",
		phase: "recon",
		timeoutMs,
		script(st) {
			const rawHost = String(st.project.host ?? "").replace(/^\[|\]$/g, "");
			const port = Number(st.project.port) || 443;
			const connectHost = rawHost.includes(":") ? `[${rawHost}]:${port}` : `${rawHost}:${port}`;
			const target = shellQuote(connectHost);
			const servername = shellQuote(rawHost);
			return [
				`if command -v timeout >/dev/null 2>&1; then`,
				`  timeout 8 openssl s_client -connect ${target} -servername ${servername} </dev/null 2>/dev/null`,
				`elif command -v python3 >/dev/null 2>&1; then`,
				`  python3 -c 'import subprocess,sys; p=subprocess.run(["openssl","s_client","-connect",sys.argv[1],"-servername",sys.argv[2]],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8); sys.stdout.buffer.write(p.stdout)' ${target} ${servername} 2>/dev/null`,
				`else`,
				`  openssl s_client -connect ${target} -servername ${servername} </dev/null 2>/dev/null`,
				`fi | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`,
			].join("\n");
		},
		parse: parseTlsFact,
	};
}

function probePaths(key: string, phase: Phase, paths: readonly string[], timeoutMs: number): AutoRule {
	return {
		key,
		phase,
		timeoutMs,
		script(st) {
			const base = shellQuote(originOf(st));
			return [
				`BASE=${base}`,
				`hits=0; net_rc=0; waf_code=""; waf_hint=""`,
				`h=$(mktemp); b=$(mktemp)`,
				`trap 'rm -f "$h" "$b"' EXIT`,
				`for p in ${paths.map(shellQuote).join(" ")}; do`,
				`  code=$(curl -k -sS -D "$h" -o "$b" --max-time 6 -w '%{http_code}' "$BASE$p" 2>/dev/null)`,
				`  rc=$?`,
				`  case "$rc" in 6|7|28|35|52|56) net_rc=$rc ;; esac`,
				`  if [ "$code" = "200" ]; then`,
				`    hits=$((hits + 1))`,
				`    line=$(tr '\\r\\n' '  ' < "$b" | head -c 240)`,
				`    echo "$p 200 $line"`,
				`  elif [ "$code" = "429" ] || [ "$code" = "403" ] || [ "$code" = "406" ]; then`,
				`    waf_code="$code"`,
				`    waf_hint=$( (cat "$h"; head -c 240 "$b") | tr '\\r\\n' '  ' | head -c 300 )`,
				`  fi`,
				`done`,
				`if [ "$hits" -eq 0 ]; then`,
				`  if [ "$waf_code" = "429" ]; then echo "FINAL 429 0 $BASE"; echo "$waf_hint"; exit 0; fi`,
				`  if [ -n "$waf_code" ] && [ -n "$waf_hint" ]; then echo "FINAL $waf_code 0 $BASE"; echo "$waf_hint"; exit 0; fi`,
				`  if [ "$net_rc" -ne 0 ]; then exit "$net_rc"; fi`,
				`fi`,
				`exit 0`,
			].join("\n");
		},
		parse(res, st) {
			return parseProbeFact(key, paths.length, res, st);
		},
	};
}

export const AUTO_RULES: readonly AutoRule[] = [
	httpRule(),
	portsRule(),
	dirsRule(),
	tlsRule(),
	probePaths(
		"surface:sensitive",
		"surface",
		["/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/backup.zip", "/config.json"],
		32_000,
	),
	probePaths(
		"surface:api",
		"surface",
		["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api/v1", "/graphql"],
		28_000,
	),
];

const BUILTIN_BY_KEY = new Map(AUTO_RULES.map((r) => [r.key, r]));

interface ExternalRuleSpec {
	key?: unknown;
	phase?: unknown;
	timeoutMs?: unknown;
	parse?: unknown;
	parser?: unknown;
	paths?: unknown;
	ports?: unknown;
	script?: unknown;
	command?: unknown;
}

interface RuleCacheEntry {
	mtimeMs: number;
	size: number;
	rawContent: string;
	loaded: LoadedAutoRules;
}

const ruleFileCache = new Map<string, RuleCacheEntry>();

function defaultAgentHome(): string {
	if (process.env.PI_AGENT_HOME) return process.env.PI_AGENT_HOME;
	const ompDir = join(homedir(), ".omp", "agent");
	return existsSync(ompDir) ? ompDir : join(homedir(), ".pi", "agent");
}

function renderCustomScriptTemplate(tpl: string, st: NuwaState): string {
	return tpl
		.replaceAll("{URL}", shellQuote(st.project.url))
		.replaceAll("{ORIGIN}", shellQuote(originOf(st)))
		.replaceAll("{HOST}", shellQuote(st.project.host))
		.replaceAll("{PORT}", shellQuote(String(st.project.port)));
}

function buildRuleFromSpec(spec: ExternalRuleSpec, index: number): AutoRule {
	if (!spec || typeof spec !== "object") {
		throw new Error(`rules[${index}] 不是有效对象`);
	}
	const rawKey = typeof spec.key === "string" ? canonicalAutoKey(spec.key) : "";
	if (!rawKey) {
		throw new Error(`rules[${index}].key 缺失或为空`);
	}

	const builtin = BUILTIN_BY_KEY.get(rawKey);
	const rawParser = spec.parse ?? spec.parser;
	if (typeof rawParser !== "string" || !VALID_PARSERS.has(rawParser as AutoParserName)) {
		throw new Error(
			`rules[${index}] (${rawKey}) parse="${String(rawParser ?? "")}" 非法；仅允许 http|ports|dirs|tls|probe`,
		);
	}
	const parserName = rawParser as AutoParserName;

	const rawPhase = typeof spec.phase === "string" ? spec.phase : (builtin?.phase ?? "recon");
	if (!VALID_PHASES.has(rawPhase as Phase)) {
		throw new Error(`rules[${index}] (${rawKey}) phase="${rawPhase}" 非法`);
	}
	const phase = rawPhase as Phase;

	const timeoutRaw = spec.timeoutMs !== undefined ? Number(spec.timeoutMs) : (builtin?.timeoutMs ?? 20_000);
	if (!Number.isFinite(timeoutRaw) || timeoutRaw <= 0) {
		throw new Error(`rules[${index}] (${rawKey}) timeoutMs 非法`);
	}
	const timeoutMs = Math.min(180_000, Math.max(500, Math.floor(timeoutRaw)));

	const customTpl =
		typeof spec.script === "string" && spec.script.trim()
			? spec.script
			: typeof spec.command === "string" && spec.command.trim()
				? spec.command
				: null;

	const customPaths = Array.isArray(spec.paths)
		? spec.paths.filter((p): p is string => typeof p === "string" && p.startsWith("/"))
		: null;
	const customPorts = Array.isArray(spec.ports)
		? spec.ports.map((n) => Number(n)).filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535)
		: null;

	let baseRule: AutoRule;
	switch (parserName) {
		case "http":
			baseRule = { ...httpRule(timeoutMs), key: rawKey, phase, timeoutMs };
			break;
		case "ports":
			baseRule = { ...portsRule(customPorts?.length ? customPorts : PORT_LIST, timeoutMs), key: rawKey, phase, timeoutMs };
			break;
		case "dirs":
			baseRule = { ...dirsRule(customPaths?.length ? customPaths : DIR_PATHS, timeoutMs), key: rawKey, phase, timeoutMs };
			break;
		case "tls":
			baseRule = { ...tlsRule(timeoutMs), key: rawKey, phase, timeoutMs };
			break;
		case "probe": {
			const paths =
				customPaths && customPaths.length > 0
					? customPaths
					: rawKey === "surface:api"
						? ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api/v1", "/graphql"]
						: ["/robots.txt", "/.git/HEAD", "/.env", "/config.json"];
			baseRule = probePaths(rawKey, phase, paths, timeoutMs);
			break;
		}
	}

	if (!customTpl) {
		return baseRule;
	}
	return {
		...baseRule,
		script(st: NuwaState) {
			return renderCustomScriptTemplate(customTpl, st);
		},
	};
}

/**
 * 按优先级加载自动侦察规则：<root>/.nuwa/autoexec.json > <agentHome>/nuwa-autoexec.json > 内置 AUTO_RULES。
 * 支持基于 mtimeMs 的热更新缓存；遇到非法 JSON 或非法 parser 时安全降级回内置规则并附带 error 字段。
 */
export function loadAutoRules(root?: string, agentHome?: string): LoadedAutoRules {
	let targetPath: string | undefined;
	let source: "project" | "user" | "builtin" = "builtin";

	if (root && root.trim()) {
		const projFile = join(resolve(root), ".nuwa", "autoexec.json");
		if (existsSync(projFile)) {
			targetPath = projFile;
			source = "project";
		}
	}
	if (!targetPath) {
		const home = agentHome && agentHome.trim() ? resolve(agentHome) : defaultAgentHome();
		const userFile = join(home, "nuwa-autoexec.json");
		if (existsSync(userFile)) {
			targetPath = userFile;
			source = "user";
		}
	}

	if (!targetPath) {
		return { rules: AUTO_RULES, source: "builtin" };
	}

	try {
		const st = statSync(targetPath);
		const rawContent = readFileSync(targetPath, "utf8");
		const cached = ruleFileCache.get(targetPath);
		if (cached && cached.mtimeMs === st.mtimeMs && cached.size === st.size && cached.rawContent === rawContent) {
			return cached.loaded;
		}

		let parsed: unknown;
		try {
			parsed = JSON.parse(rawContent);
		} catch (e) {
			const errMsg = `autoexec.json 解析失败 (${targetPath}): ${e instanceof Error ? e.message : String(e)}`;
			const fallback: LoadedAutoRules = { rules: AUTO_RULES, source: "builtin", path: targetPath, error: errMsg };
			ruleFileCache.set(targetPath, { mtimeMs: st.mtimeMs, size: st.size, rawContent, loaded: fallback });
			return fallback;
		}

		let rawList: unknown[];
		let replaceAll = false;
		if (Array.isArray(parsed)) {
			rawList = parsed;
		} else if (parsed && typeof parsed === "object" && Array.isArray((parsed as { rules?: unknown }).rules)) {
			rawList = (parsed as { rules: unknown[] }).rules;
			replaceAll = Boolean((parsed as { replace?: unknown }).replace);
		} else {
			const errMsg = `autoexec.json 结构非法 (${targetPath}): 需为规则数组或含 rules 数组的对象`;
			const fallback: LoadedAutoRules = { rules: AUTO_RULES, source: "builtin", path: targetPath, error: errMsg };
			ruleFileCache.set(targetPath, { mtimeMs: st.mtimeMs, size: st.size, rawContent, loaded: fallback });
			return fallback;
		}

		const customRules = rawList.map((item, idx) => buildRuleFromSpec(item as ExternalRuleSpec, idx));
		let merged: AutoRule[];
		if (replaceAll) {
			merged = customRules;
		} else {
			const byKey = new Map<string, AutoRule>(AUTO_RULES.map((r) => [r.key, r]));
			for (const r of customRules) {
				byKey.set(r.key, r);
			}
			merged = [...byKey.values()];
		}

		const loaded: LoadedAutoRules = { rules: merged, source, path: targetPath };
		ruleFileCache.set(targetPath, { mtimeMs: st.mtimeMs, size: st.size, rawContent, loaded });
		return loaded;
	} catch (err) {
		const errMsg = `autoexec.json 加载失败 (${targetPath}): ${err instanceof Error ? err.message : String(err)}`;
		return { rules: AUTO_RULES, source: "builtin", path: targetPath, error: errMsg };
	}
}

export function isAutoKey(key: string, root?: string, agentHome?: string): boolean {
	const norm = canonicalAutoKey(key);
	if (!norm) return false;
	const { rules } = loadAutoRules(root, agentHome);
	return rules.some((r) => r.key === norm);
}

export function ruleFor(key: string, root?: string, agentHome?: string): AutoRule | undefined {
	const norm = canonicalAutoKey(key);
	if (!norm) return undefined;
	const { rules } = loadAutoRules(root, agentHome);
	return rules.find((r) => r.key === norm);
}

const CURL_NET_EXIT_CODES = new Set([6, 7, 28, 35, 52, 56, 124, 137, 143]);
const NET_ERR_RE =
	/\b(?:timed?\s*out|Operation timed out|Connection timed out|Could not resolve host|Name or service not known|Temporary failure in name resolution|Failed to connect|Connection refused|Network is unreachable|No route to host|Connection reset by peer|TimeoutExpired|ETIMEDOUT|ECONNREFUSED|ENOTFOUND|EHOSTUNREACH)\b/i;

const HTTP_BLOCK_STATUS_RE =
	/(?:^FINAL\s+(403|406|429|503)\b|^HTTP\/\d(?:\.\d)?\s+(403|406|429|503)\b|(?:^|\s)(403|406|429)(?:\s|$))/m;

/**
 * 侦察失败三分类：
 * - network：curl 6/7/28、进程被超时 kill 或明确网络/超时报错 → 建议 retryAfterMs: 60000
 * - blocked_by_waf：返回 403/406/429/503 且含 WAF/Challenge/速率限制特征
 * - empty：正常执行完毕但目标未命中有效结果
 */
export function classifyAutoFailure(res: ExecLikeResult): AutoFailureClassification {
	const stdout = String(res.stdout ?? "");
	const stderr = String(res.stderr ?? "");
	const combined = `${stdout}\n${stderr}`;

	if (res.killed || CURL_NET_EXIT_CODES.has(res.code) || NET_ERR_RE.test(combined)) {
		const reason = res.killed
			? "命令超时被终止 (killed)"
			: CURL_NET_EXIT_CODES.has(res.code)
				? `网络连接/超时错误 (code=${res.code})`
				: "网络不可达或请求超时";
		return {
			kind: "network",
			errorKind: "network",
			retryAfterMs: 60_000,
			reason,
		};
	}

	const statusMatch = HTTP_BLOCK_STATUS_RE.exec(combined);
	if (statusMatch) {
		const statusCode = Number(statusMatch[1] ?? statusMatch[2] ?? statusMatch[3] ?? 0);
		const waf = detectWafName(stdout, stderr, statusCode);
		if (waf || statusCode === 429 || WAF_CHALLENGE_RE.test(combined)) {
			const finalWaf = waf ?? (statusCode === 429 ? "rate-limit" : "generic-waf");
			return {
				kind: "blocked_by_waf",
				errorKind: "blocked_by_waf",
				waf: finalWaf,
				reason: `触发 WAF 或频率限制拦截 (HTTP ${statusCode}, waf=${finalWaf})`,
			};
		}
	}

	return {
		kind: "empty",
		errorKind: "empty",
		reason: `执行完成但无有效命中 (code=${res.code})`,
	};
}

/**
 * 选择本轮可自动执行的意图：
 * 满足 open 状态、归一化 key 命中自动规则、尝试未超上限、冷却时间 nextRunAt <= now 且前置依赖已满足。
 */
export function pickAuto(st: NuwaState, cfg: Cfg, max: number, now = Date.now(), root?: string): string[] {
	const out: Array<{ id: string; priority: number }> = [];
	const { rules } = loadAutoRules(root);
	const allowedKeys = new Set(rules.map((r) => r.key));

	for (const it of Object.values(st.intents)) {
		if (it.status !== "open") continue;
		if (!allowedKeys.has(canonicalAutoKey(it.key))) continue;
		if (it.attempts >= cfg.maxAttempts) continue;
		const nextRunAt = (it as { nextRunAt?: number }).nextRunAt;
		if (typeof nextRunAt === "number" && Number.isFinite(nextRunAt) && nextRunAt > now) continue;
		if (!it.from.every((f) => st.facts[f])) continue;
		out.push({ id: it.id, priority: it.priority });
	}
	out.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
	return out.slice(0, Math.max(0, max)).map((x) => x.id);
}

function raceWithSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
	if (!signal) return promise;
	if (signal.aborted) {
		return Promise.reject(new Error("aborted"));
	}
	return new Promise<T>((resolvePromise, rejectPromise) => {
		const onAbort = () => {
			rejectPromise(new Error("aborted"));
		};
		signal.addEventListener("abort", onAbort, { once: true });
		promise.then(
			(val) => {
				signal.removeEventListener("abort", onAbort);
				resolvePromise(val);
			},
			(err) => {
				signal.removeEventListener("abort", onAbort);
				rejectPromise(err);
			},
		);
	});
}

/** 执行单条自动意图：跑脚本 → 解析，无产出时附带失败三分类信息。入账由调用方在锁内完成。 */
export async function runAutoIntent(
	rule: AutoRule,
	st: NuwaState,
	exec: ExecLike,
	cwd: string,
	signal?: AbortSignal,
): Promise<AutoRunResult> {
	if (signal?.aborted) {
		return {
			ok: false,
			error: "任务已取消 (aborted)",
			errorKind: "network",
			retryAfterMs: 60_000,
		};
	}
	try {
		const res = await raceWithSignal(
			exec("bash", ["-lc", rule.script(st)], { timeout: rule.timeoutMs, cwd, signal }),
			signal,
		);
		const fact = rule.parse(res, st);
		if (!fact) {
			const cls = classifyAutoFailure(res);
			return {
				ok: false,
				error: `无产出 code=${res.code}${res.killed ? " killed" : ""} [${cls.errorKind}]`,
				errorKind: cls.errorKind,
				...(cls.retryAfterMs !== undefined ? { retryAfterMs: cls.retryAfterMs } : {}),
				...(cls.waf !== undefined ? { waf: cls.waf } : {}),
			};
		}
		return {
			ok: true,
			fact,
			...(fact.meta?.waf ? { waf: fact.meta.waf } : {}),
		};
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		const isNetOrAbort = signal?.aborted || /abort|timed?\s*out|ETIMEDOUT|ECONNREFUSED|ENOTFOUND/i.test(msg);
		return {
			ok: false,
			error: msg,
			...(isNetOrAbort ? { errorKind: "network" as const, retryAfterMs: 60_000 } : { errorKind: "empty" as const }),
		};
	}
}

function isExclusiveRuleKey(canonicalKey: string): boolean {
	return canonicalKey === "recon:ports";
}

/**
 * 受控并发与总预算自动批执行器（Issue #5）：
 * - 默认 budgetMs = 90000ms，concurrency = 1（并发 >= 2 时 recon:ports 保持独占运行）
 * - 透传 AbortSignal 并在总预算耗尽或外部取消时立即终止后续派发，回调 opts.onBudgetSkip(remainingIds, reason)
 */
export async function runAutoBatchManaged(
	ids: string[],
	st: NuwaState,
	exec: ExecLike,
	root: string,
	opts?: AutoBatchOptions,
): Promise<AutoBatchManagedResult> {
	const startedAt = Date.now();
	const loaded = loadAutoRules(root, opts?.agentHome);
	const ruleMap = new Map(loaded.rules.map((r) => [r.key, r]));

	if (ids.length === 0) {
		return {
			results: {},
			items: [],
			skippedIds: [],
			elapsedMs: 0,
			ruleSource: loaded.source,
			...(loaded.error ? { ruleError: loaded.error } : {}),
		};
	}

	const envBudget = Number(process.env.NUWA_AUTO_BUDGET_MS ?? 0);
	const budgetMs = opts?.budgetMs ?? (Number.isFinite(envBudget) && envBudget > 0 ? envBudget : 90_000);
	const deadline = startedAt + Math.max(1, budgetMs);

	const envConc = Number(process.env.NUWA_AUTO_CONCURRENCY ?? 0);
	const maxConcurrency = Math.max(
		1,
		Math.min(4, Math.floor(opts?.concurrency ?? (Number.isFinite(envConc) && envConc > 0 ? envConc : 1))),
	);

	if (opts?.signal?.aborted) {
		const skipped = [...ids];
		await opts.onBudgetSkip?.(skipped, "aborted");
		return {
			results: {},
			items: [],
			skippedIds: skipped,
			skipReason: "aborted",
			elapsedMs: Date.now() - startedAt,
			ruleSource: loaded.source,
			...(loaded.error ? { ruleError: loaded.error } : {}),
		};
	}

	const batchController = new AbortController();
	let extAborted = false;
	let budgetExceeded = false;

	const onExternalAbort = () => {
		extAborted = true;
		batchController.abort(opts?.signal?.reason ?? new Error("aborted"));
	};
	opts?.signal?.addEventListener("abort", onExternalAbort, { once: true });

	const budgetTimer = setTimeout(() => {
		budgetExceeded = true;
		batchController.abort(new Error("budget_exceeded"));
	}, Math.max(1, budgetMs));

	const results: Record<string, AutoRunResult> = {};
	const items: AutoBatchItemResult[] = [];
	const completedSet = new Set<string>();
	const interruptedSet = new Set<string>();

	const queue = [...ids];
	const inFlight = new Set<Promise<void>>();
	let runningExclusive = false;

	const isStopped = () => extAborted || budgetExceeded || Boolean(opts?.signal?.aborted) || Date.now() >= deadline;

	const launchOne = (id: string): Promise<void> => {
		const curState = opts?.getState?.() ?? st;
		const intent = curState.intents[id];
		const rawKey = intent?.key ?? "";
		const canonKey = canonicalAutoKey(rawKey);
		const exclusive = isExclusiveRuleKey(canonKey);
		if (exclusive) runningExclusive = true;

		const taskPromise = (async () => {
			const itemStart = Date.now();
			const latestState = opts?.getState?.() ?? st;
			const rule = ruleMap.get(canonKey);

			if (!rule) {
				const noRuleRes: AutoRunResult = {
					ok: false,
					error: `auto: 无匹配规则 (${rawKey || id})`,
					errorKind: "empty",
				};
				results[id] = noRuleRes;
				completedSet.add(id);
				const item: AutoBatchItemResult = {
					id,
					key: rawKey,
					canonicalKey: canonKey,
					result: noRuleRes,
					durationMs: Date.now() - itemStart,
				};
				items.push(item);
				await opts?.onResult?.(item);
				return;
			}

			const remMs = Math.max(1, deadline - Date.now());
			const boundedRule: AutoRule =
				remMs < rule.timeoutMs ? { ...rule, timeoutMs: remMs } : rule;

			const runRes = await runAutoIntent(boundedRule, latestState, exec, root, batchController.signal);

			// 若因预算耗尽或外部 abort 打断且未成功产出，归入剩余跳过列表由调用方回退 open
			if (!runRes.ok && (extAborted || budgetExceeded || opts?.signal?.aborted)) {
				interruptedSet.add(id);
				return;
			}

			results[id] = runRes;
			completedSet.add(id);
			const item: AutoBatchItemResult = {
				id,
				key: rawKey,
				canonicalKey: canonKey,
				result: runRes,
				durationMs: Date.now() - itemStart,
			};
			items.push(item);
			await opts?.onResult?.(item);
		})().finally(() => {
			if (exclusive) runningExclusive = false;
			inFlight.delete(taskPromise);
		});

		inFlight.add(taskPromise);
		return taskPromise;
	};

	try {
		while (queue.length > 0 || inFlight.size > 0) {
			while (queue.length > 0 && !isStopped()) {
				if (runningExclusive) break;
				const nextId = queue[0]!;
				const curState = opts?.getState?.() ?? st;
				const nextCanon = canonicalAutoKey(curState.intents[nextId]?.key ?? "");
				const nextIsExclusive = isExclusiveRuleKey(nextCanon);

				if (nextIsExclusive) {
					if (inFlight.size > 0) break;
					queue.shift();
					launchOne(nextId);
					break;
				}

				if (inFlight.size >= maxConcurrency) break;
				queue.shift();
				launchOne(nextId);
			}

			if (inFlight.size > 0) {
				await Promise.race(inFlight);
			} else if (isStopped()) {
				break;
			}
		}
	} finally {
		clearTimeout(budgetTimer);
		opts?.signal?.removeEventListener("abort", onExternalAbort);
	}

	let skipReason: BudgetSkipReason | undefined;
	if (extAborted || opts?.signal?.aborted) {
		skipReason = "aborted";
	} else if (budgetExceeded || (queue.length > 0 && Date.now() >= deadline)) {
		skipReason = "budget_exceeded";
	}

	const skippedIds = ids.filter((id) => !completedSet.has(id) && (interruptedSet.has(id) || !results[id]));
	if (skippedIds.length > 0 && skipReason) {
		await opts?.onBudgetSkip?.(skippedIds, skipReason);
	}

	return {
		results,
		items,
		skippedIds,
		...(skipReason ? { skipReason } : {}),
		elapsedMs: Date.now() - startedAt,
		ruleSource: loaded.source,
		...(loaded.error ? { ruleError: loaded.error } : {}),
	};
}
