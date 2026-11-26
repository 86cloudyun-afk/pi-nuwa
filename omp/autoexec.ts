/**
 * 确定性侦察执行器（v4.0）：omp 扩展自主跑命令入账，支持跨平台探测、E2+ 归一化、
 * 外置规则热加载、失败三分类（network / blocked_by_waf / empty）、总预算与取消控制、
 * Soft-404 基线校准、内容级语义指纹实锤与工具链自适应升档（nmap / ffuf / katana / nuclei）。
 *
 * 约束：仅使用 import type 引用 ./nuwa，严禁运行时 import ./nuwa。
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { Cfg, NuwaState, Phase, ToolchainCaps } from "./nuwa";
import {
	buildCurlProxyArgs,
	EgressPoolManager,
	injectEgressEnv,
	maskEgressUrl,
	normalizeTaskEgressUrl,
	resolveConfiguredEgressUrl,
	type EgressCircuitState,
	type EgressEndpointConfig,
	type EgressHealthSnapshot,
	type EgressLease,
	type EgressObservation,
	type EgressPoolOptions,
	type InjectEgressEnvOptions,
} from "./sandbox";

export {
	buildCurlProxyArgs,
	EgressPoolManager,
	injectEgressEnv,
	maskEgressUrl,
	normalizeTaskEgressUrl,
	resolveConfiguredEgressUrl,
	type EgressCircuitState,
	type EgressEndpointConfig,
	type EgressHealthSnapshot,
	type EgressLease,
	type EgressObservation,
	type EgressPoolOptions,
	type InjectEgressEnvOptions,
};

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
	bodyHash?: string;
	bodyBytes?: number;
	endpointClassifications?: Record<string, EndpointClassification>;
	requiresAuthPaths?: string[];
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

export type AutoParserName = "http" | "ports" | "dirs" | "tls" | "probe" | "katana" | "nuclei";
export type AutoErrorKind = "network" | "blocked_by_waf" | "empty" | "egress_blocked";

export type EndpointClassification =
	| "exists"
	| "exists_requires_auth"
	| "not_found"
	| "soft_404"
	| "egress_blocked"
	| "redirect"
	| "server_error"
	| "unknown";

export type HeaderBagLike =
	| Record<string, string | string[] | undefined>
	| Headers
	| { get(name: string): string | null };

export interface Soft404Sample {
	code: number;
	size: number;
	titleSig: string;
	path?: string;
	bodyHash?: string;
	templateHash?: string;
	redirectLocation?: string;
}

export interface Soft404Baseline {
	/** 是否识别到返 200/30x 的兜底页 Soft-404 基线。 */
	active: boolean;
	/** 全部解析到的 BASELINE 探测样本。 */
	samples: Soft404Sample[];
	/** 命中 200/30x 兜底行为的状态码列表（去重）。 */
	codes: number[];
	/** 首个 200/30x 兜底样本的响应体字节数。 */
	size?: number;
	/** 首个非空 200/30x 兜底样本的归一化 HTML title 签名。 */
	titleSig?: string;
	/** 首个兜底样本的精确响应体 SHA-256 哈希。 */
	bodyHash?: string;
	/** 首个兜底样本的归一化模板 SHA-256 指纹。 */
	templateHash?: string;
}

export interface Soft404Candidate {
	path?: string;
	url?: string;
	code: number;
	status?: number;
	size?: number;
	bodyBytes?: number;
	/** 未提供（undefined）表示采集源未提取 title；空串或 "-" 表示已检查响应且无 HTML title。 */
	titleSig?: string;
	body?: string;
	snippet?: string;
	headers?: HeaderBagLike;
	contentType?: string;
}

export interface DetectSoft404Input {
	url?: string;
	path?: string;
	status?: number;
	code?: number;
	body?: string | Buffer | Uint8Array;
	snippet?: string;
	size?: number;
	bodyBytes?: number;
	titleSig?: string;
	headers?: HeaderBagLike;
	contentType?: string;
}

export interface Soft404BaselineInput extends Partial<Soft404Baseline> {
	status?: number;
	body?: string | Buffer | Uint8Array;
	bodyBytes?: number;
	probes?: Array<{
		path?: string;
		status: number;
		size?: number;
		bodyBytes?: number;
		body?: string | Buffer | Uint8Array;
		bodyHash?: string;
		templateHash?: string;
		titleSig?: string;
		redirectLocation?: string;
	}>;
}

export interface Soft404DetectionResult {
	isSoft404: boolean;
	confidence: "high" | "medium" | "none";
	reasons: string[];
	matchedRule?:
		| "rsc_error_fallback"
		| "multilingual_404_copy"
		| "baseline_hash_match"
		| "baseline_template_match"
		| "baseline_size_title_match"
		| "baseline_redirect_match";
	bodyBytes: number;
	bodyHash: string;
	templateHash: string;
}

export interface EndpointResponseInput {
	url?: string;
	path?: string;
	method?: string;
	status: number;
	headers?: HeaderBagLike;
	body?: string | Buffer | Uint8Array;
	contentType?: string;
	bodyBytes?: number;
}

export interface EndpointBaseline404 extends Soft404BaselineInput {
	soft404Baseline?: Soft404Baseline;
}

export interface EndpointResponseClassification {
	classification: EndpointClassification;
	exists: boolean;
	requiresAuth: boolean;
	status: number;
	bodyHash: string;
	bodyBytes: number;
	templateHash: string;
	allowMethods?: string[];
	waf?: string;
	reason: string;
	meta: {
		status: number;
		bodyHash: string;
		bodyBytes: number;
		templateHash: string;
		classification: EndpointClassification;
		requiresAuth: boolean;
		allow?: string[];
		waf?: string;
	};
}

export interface PreflightFetchResponse {
	ok: boolean;
	status: number;
	text(): Promise<string>;
	headers?: { get(name: string): string | null };
}

export type PreflightFetchLike = (
	url: string,
	init?: {
		method?: string;
		headers?: Record<string, string>;
		signal?: AbortSignal;
		redirect?: "manual" | "follow" | "error";
	},
) => Promise<PreflightFetchResponse>;

export interface PreflightEgressOptions {
	gateUrl: string;
	egressUrl?: string;
	expectedStatuses?: readonly number[];
	timeoutMs?: number;
	exec?: ExecLike;
	cwd?: string;
	fetchFn?: PreflightFetchLike;
	headers?: Record<string, string>;
	signal?: AbortSignal;
	egressPool?: EgressPoolManager;
	egressId?: string;
}

export interface PreflightEgressResult {
	ok: boolean;
	status: "ok" | "egress_blocked" | "network_error";
	errorKind?: "egress_blocked" | "network";
	gateUrl: string;
	egressUrl?: string;
	httpStatus?: number;
	bodyBytes?: number;
	bodyHash?: string;
	ttfbMs?: number;
	waf?: string;
	cfRay?: string;
	remoteIp?: string;
	reason: string;
}

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
	egressId?: string;
	egressUrl?: string;
	preflight?: PreflightEgressResult;
}

export interface LoadedAutoRules {
	rules: readonly AutoRule[];
	source: "project" | "global" | "builtin";
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
	authHeaderFile?: string;
	egressUrl?: string;
	egressPool?: EgressPoolManager;
	gateUrl?: string;
	preflightExpectedStatuses?: readonly number[];
	preflightFetchFn?: PreflightFetchLike;
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
	ruleSource: "project" | "global" | "builtin";
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
const VALID_PARSERS = new Set<AutoParserName>(["http", "ports", "dirs", "tls", "probe", "katana", "nuclei"]);

/** 是否启用本地工具链自适应升档（默认开启；设置 NUWA_AUTO_TOOLCHAIN=0 关闭）。 */
function isAutoToolchainEnabled(): boolean {
	return (process.env.NUWA_AUTO_TOOLCHAIN ?? "1").trim() !== "0";
}

/** 检测当前项目工具链快照中是否包含指定工具。 */
function hasToolchainTool(st: NuwaState, toolName: string): boolean {
	if (!isAutoToolchainEnabled()) return false;
	const avail = st.project?.toolchain?.available;
	if (!Array.isArray(avail) || avail.length === 0) return false;
	const target = toolName.trim().toLowerCase();
	return avail.some((t) => String(t).trim().toLowerCase() === target);
}

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

const SOFT404_CHECK_PATHS = ["/__nuwa_404_check_1", "/__nuwa_404_check_2.json"] as const;
const HTML_SIGNATURE_RE = /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<title[\s>]|<meta\s[^>]*charset/i;
const GIT_HEAD_REF_RE = /^\s*ref:\s*refs\/[A-Za-z0-9._\/-]+(?:\s|$)/;
const GIT_HEAD_SHA_RE = /^\s*[0-9a-f]{40}(?:\s|$)/i;
const ENV_PAIR_TEST_RE =
	/(?:^|\s)(?:export\s+)?([A-Z][A-Z0-9_]{1,63})=([^\s"'`<>]\S*|"[^"\r\n]+(?:"|$)|'[^'\r\n]+(?:'|$))/;
const ENV_PAIR_MASK_RE =
	/(^|\s)((?:export\s+)?[A-Z][A-Z0-9_]{1,63}=)("(?:\\.|[^"])*(?:"|$)|'(?:\\.|[^'])*(?:'|$)|\S+)/g;
const OPENAPI_PATH_RE = /\/(?:openapi|swagger(?:\/[^/]+)*)\.json$/i;
const STATIC_ASSET_EXT_RE =
	/\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|sass|less|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|pdf|zip|tar|gz|br|wasm)$/i;
const DIR_HIT_STATUS_SET = new Set([200, 204, 301, 302, 307, 401, 403, 405, 500]);

function normalizeTitleSig(raw?: string): string {
	const s = String(raw ?? "")
		.replace(/\s+/g, " ")
		.trim();
	if (!s || s === "-") return "";
	return s.toLowerCase();
}

function isSoft404Status(code: number): boolean {
	return code === 200 || (code >= 300 && code < 400);
}

/**
 * 解析脚本输出中的 `BASELINE <code> <size> <title_sig>` 探测行，构建 Soft-404 兜底基线。
 * 无 `BASELINE` 行或全为 404/4xx/5xx/000 时返回 `active: false`，保持历史输入 100% 兼容。
 */
export function parseSoft404Baseline(stdout: string): Soft404Baseline {
	const samples: Soft404Sample[] = [];
	const codes: number[] = [];

	for (const rawLine of String(stdout ?? "").replace(/\r/g, "").split("\n")) {
		const m = /^BASELINE\s+(\d{3})\s+(\d+)(?:\s+(.*))?$/.exec(rawLine.trim());
		if (!m) continue;
		const code = Number(m[1]);
		const size = Number(m[2]);
		if (!Number.isFinite(code) || !Number.isFinite(size)) continue;
		const titleSig = normalizeTitleSig(m[3]);
		samples.push({ code, size, titleSig });
		if (isSoft404Status(code) && !codes.includes(code)) {
			codes.push(code);
		}
	}

	const activeSamples = samples.filter((s) => isSoft404Status(s.code));
	if (activeSamples.length === 0) {
		return { active: false, samples, codes: [] };
	}

	const firstTitle = activeSamples.find((s) => s.titleSig !== "")?.titleSig ?? "";
	return {
		active: true,
		samples,
		codes,
		size: activeSamples[0]!.size,
		titleSig: firstTitle,
	};
}

function parseSoft404RowString(rawRow: string): Soft404Candidate | null {
	const trimmed = String(rawRow ?? "").replace(/\r/g, "").trim();
	if (!trimmed) return null;

	// probePaths 新格式：/path 200 SIZE=1024 TITLE=App\t<body>（响应体为空时 \t 可被 trim 省略）
	const probeNew = /^(\/\S*)\s+(\d{3})\s+SIZE=(\d+)\s+TITLE=([^\t]*)(?:\t(.*))?$/.exec(trimmed);
	if (probeNew) {
		return {
			path: probeNew[1],
			code: Number(probeNew[2]),
			size: Number(probeNew[3]),
			titleSig: normalizeTitleSig(probeNew[4]),
			body: probeNew[5] ?? "",
		};
	}

	// dirsRule 格式：/path 200 1024 [redir] [TITLE=App]
	const dirsMatch = /^(\/\S*)\s+(\d{3})\s+(\d+)(?:\s+(.*))?$/.exec(trimmed);
	if (dirsMatch) {
		const rest = dirsMatch[4] ?? "";
		const titleMatch = /(?:^|\s)TITLE=(.*)$/.exec(rest);
		return {
			path: dirsMatch[1],
			code: Number(dirsMatch[2]),
			size: Number(dirsMatch[3]),
			...(titleMatch ? { titleSig: normalizeTitleSig(titleMatch[1]) } : {}),
		};
	}

	// probePaths 历史格式：/path 200 <body>
	const probeLegacy = /^(\/\S*)\s+(\d{3})\s+(.*)$/.exec(trimmed);
	if (probeLegacy) {
		const body = probeLegacy[3] ?? "";
		return {
			path: probeLegacy[1],
			code: Number(probeLegacy[2]),
			body,
			titleSig: normalizeTitleSig(titleOf(body)),
		};
	}

	return null;
}

const RSC_ERROR_FALLBACK_RE =
	/NEXT_HTTP_ERROR_FALLBACK\\?;404|"digest"\s*:\s*"NEXT_NOT_FOUND"|NEXT_NOT_FOUND|__next_error__|notFound":\s*true/i;

const NEXT_DATA_404_RE =
	/<script[^>]*id=["']__NEXT_DATA__["'][^>]*>[\s\S]*?(?:"page"\s*:\s*"\/(?:404|_error)"[\s\S]*?"statusCode"\s*:\s*404|"statusCode"\s*:\s*404[\s\S]*?"page"\s*:\s*"\/(?:404|_error)")/i;

const MULTILINGUAL_404_PATTERNS: ReadonlyArray<{ label: string; re: RegExp }> = [
	{ label: "zh-Hant:找不到此頁面", re: /找不到此頁面|找不到該頁面|此頁面不存在|頁面不存在|找不到網頁|查無此頁/i },
	{ label: "zh-Hans:页面不存在", re: /页面不存在|找不到该页面|找不到此页面|您访问的页面不存在|未找到页面|网页无法找到|该页面已失效/i },
	{
		label: "en:Page Not Found",
		re: /\b(?:404\s*[-–—:|]?\s*(?:page\s*)?not\s+found|page\s+not\s+found|this\s+page\s+could\s+not\s+be\s+found|the\s+requested\s+(?:url|page|resource)\s+was\s+not\s+found|we\s+couldn['’]?t\s+find\s+(?:that|this|the)\s+page|error\s*404|cannot\s+get\s+\/)\b/i,
	},
	{ label: "ja:ページが見つかりません", re: /ページが見つかりません|お探しのページは見つかりませんでした/i },
	{ label: "ko:페이지를 찾을 수 없습니다", re: /페이지를\s*찾을\s*수\s*없습니다/i },
	{ label: "eu:404-copy", re: /\b(?:página\s+no\s+encontrada|seite\s+nicht\s+gefunden|page\s+introuvable)\b/i },
];

const BUSINESS_AUTH_403_RE =
	/\b(?:unauthori[sz]ed|unauthenticated|permission\s+denied|insufficient\s+(?:permissions?|privileges?|scope)|invalid\s+token|token\s+(?:expired|invalid|missing|required)|jwt\s+(?:expired|invalid|missing)|auth(?:entication|orization)?\s+(?:required|failed|missing)|login\s+required|sign\s*in\s+required|role\s+required|admin\s+only|forbidden\s+resource|not\s+allowed\s+to\s+access)\b|无权限|权限不足|未授权|未登录|需要登录|请先登录|鉴权失败|令牌无效|令牌已过期/i;

const EDGE_BLOCK_403_RE =
	/\b(?:attention\s+required!?\s*\|\s*cloudflare|sorry,\s*you\s+have\s+been\s+blocked|just\s+a\s+moment\.\.\.|cf-error-details|cf-turnstile|challenge-platform|cloudflare\s+ray\s+id|enable\s+javascript\s+and\s+cookies\s+to\s+continue|why\s+have\s+i\s+been\s+blocked|access\s+denied\s+you\s+don['’]?t\s+have\s+permission\s+to\s+access\s+"[^"]+"\s+on\s+this\s+server|reference\s*#\d+\.\w+|request\s+blocked\s+by\s+(?:waf|cloudflare|cloudfront|akamai|imperva)|incapsula\s+incident\s+id|datadome)\b/i;

const LOGIN_LOCATION_RE = /\/(?:login|signin|sign-in|auth|oauth|sso|passport)(?:[/?#]|$)/i;

function readHeaderCaseInsensitive(headers: HeaderBagLike | undefined, name: string): string {
	if (!headers) return "";
	const target = name.toLowerCase();
	if (typeof (headers as { get?: unknown }).get === "function") {
		return String((headers as { get(k: string): string | null }).get(name) ?? "").trim();
	}
	const rec = headers as Record<string, string | string[] | undefined>;
	for (const [k, v] of Object.entries(rec)) {
		if (k.toLowerCase() !== target || v === undefined) continue;
		return Array.isArray(v) ? v.join(", ").trim() : String(v).trim();
	}
	return "";
}

function serializeHeadersForInspection(headers: HeaderBagLike | undefined): string {
	if (!headers) return "";
	const lines: string[] = [];
	if (typeof Headers !== "undefined" && headers instanceof Headers) {
		headers.forEach((v, k) => lines.push(`${k}: ${v}`));
		return lines.join("\n");
	}
	if (typeof (headers as { get?: unknown }).get === "function") {
		for (const key of [
			"server",
			"content-type",
			"location",
			"allow",
			"www-authenticate",
			"cf-ray",
			"cf-mitigated",
			"x-nextjs-matched-path",
			"x-amzn-waf-action",
			"x-datadome",
			"x-sucuri-id",
			"x-iinfo",
			"x-powered-by",
		]) {
			const val = (headers as { get(k: string): string | null }).get(key);
			if (val) lines.push(`${key}: ${val}`);
		}
		return lines.join("\n");
	}
	for (const [k, v] of Object.entries(headers as Record<string, string | string[] | undefined>)) {
		if (v === undefined) continue;
		lines.push(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
	}
	return lines.join("\n");
}

function bodyToBufferAndText(body?: string | Buffer | Uint8Array): { buf: Buffer; text: string } {
	if (body === undefined || body === null) {
		return { buf: Buffer.alloc(0), text: "" };
	}
	if (Buffer.isBuffer(body)) {
		return { buf: body, text: body.toString("utf8") };
	}
	if (body instanceof Uint8Array) {
		const buf = Buffer.from(body);
		return { buf, text: buf.toString("utf8") };
	}
	const text = String(body);
	return { buf: Buffer.from(text, "utf8"), text };
}

/** 计算响应体的精确 SHA-256 哈希与字节数。 */
export function computeBodyHash(body?: string | Buffer | Uint8Array): { bodyHash: string; bodyBytes: number } {
	const { buf } = bodyToBufferAndText(body);
	return {
		bodyHash: createHash("sha256").update(buf).digest("hex"),
		bodyBytes: buf.byteLength,
	};
}

/**
 * 计算响应体的归一化模板 SHA-256 指纹：
 * 剥离 nonce、UUID、ISO 时间戳、请求路径回显、长十六进制哈希与多余空白，
 * 使包含动态参数或路径回显的软 404 页面仍能稳定聚合到同一模板指纹。
 */
export function computeTemplateFingerprint(body: string | Buffer | Uint8Array | undefined, pathHint?: string): string {
	let text = bodyToBufferAndText(body).text;
	if (!text) {
		return createHash("sha256").update("").digest("hex");
	}
	if (pathHint && pathHint.length > 1) {
		const cleanPath = pathHint.split(/[?#]/)[0] ?? "";
		if (cleanPath && cleanPath !== "/") {
			text = text.split(cleanPath).join("<PATH>");
			try {
				const enc = encodeURIComponent(cleanPath);
				if (enc !== cleanPath) text = text.split(enc).join("<PATH>");
			} catch {
				/* ignore */
			}
		}
	}
	const normalized = text
		.replace(/\bnonce=["'][^"']+["']/gi, 'nonce="<NONCE>"')
		.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>")
		.replace(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g, "<TS>")
		.replace(/"(?:requestId|traceId|rayId|timestamp|nonce|csrfToken|buildId)"\s*:\s*"[^"]*"/gi, '"$1":"<DYN>"')
		.replace(/\b[0-9a-f]{24,64}\b/gi, "<HEX>")
		.replace(/\b\d{10,16}\b/g, "<NUM>")
		.replace(/\s+/g, " ")
		.trim()
		.toLowerCase();
	return createHash("sha256").update(normalized, "utf8").digest("hex");
}

function isJsonBusinessDataPayload(text: string, contentType: string): boolean {
	const trimmed = text.trim();
	if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return false;
	const looksJson = /json/i.test(contentType) || trimmed.startsWith("{") || trimmed.startsWith("[");
	if (!looksJson) return false;
	try {
		const parsed = JSON.parse(trimmed) as unknown;
		if (Array.isArray(parsed)) return parsed.length > 0;
		if (parsed && typeof parsed === "object") {
			const rec = parsed as Record<string, unknown>;
			if (rec.statusCode === 404 || rec.status === 404 || rec.code === 404) return false;
			if (typeof rec.error === "string" && /not\s*found/i.test(rec.error) && Object.keys(rec).length <= 3) {
				return false;
			}
			if (Array.isArray(rec.data) || (rec.data && typeof rec.data === "object")) return true;
			if (typeof rec.openapi === "string" || typeof rec.swagger === "string") return true;
			const keys = Object.keys(rec);
			if (keys.length >= 2 && !keys.every((k) => /^(?:error|message|msg|code|status|statusCode|path|timestamp)$/i.test(k))) {
				return true;
			}
		}
	} catch {
		return false;
	}
	return false;
}

function normalizeBaselineSamples(baseline?: Soft404BaselineInput | null): Soft404Sample[] {
	if (!baseline) return [];
	const out: Soft404Sample[] = [];
	if (Array.isArray(baseline.samples)) {
		for (const s of baseline.samples) {
			if (Number.isFinite(s.code) && Number.isFinite(s.size)) {
				out.push({ ...s, titleSig: normalizeTitleSig(s.titleSig) });
			}
		}
	}
	if (Array.isArray(baseline.probes)) {
		for (const p of baseline.probes) {
			const { buf, text } = bodyToBufferAndText(p.body);
			const size =
				typeof p.size === "number" && Number.isFinite(p.size)
					? p.size
					: typeof p.bodyBytes === "number" && Number.isFinite(p.bodyBytes)
						? p.bodyBytes
						: buf.byteLength;
			const bodyHash = p.bodyHash ?? (p.body !== undefined ? computeBodyHash(buf).bodyHash : undefined);
			const templateHash =
				p.templateHash ?? (p.body !== undefined ? computeTemplateFingerprint(text, p.path) : undefined);
			const titleSig = p.titleSig !== undefined ? normalizeTitleSig(p.titleSig) : normalizeTitleSig(titleOf(text));
			out.push({
				code: p.status,
				size,
				titleSig,
				...(p.path ? { path: p.path } : {}),
				...(bodyHash ? { bodyHash } : {}),
				...(templateHash ? { templateHash } : {}),
				...(p.redirectLocation ? { redirectLocation: p.redirectLocation } : {}),
			});
		}
	}
	if (out.length === 0) {
		const hasSingle =
			baseline.body !== undefined ||
			baseline.bodyHash !== undefined ||
			baseline.templateHash !== undefined ||
			typeof baseline.size === "number" ||
			typeof baseline.bodyBytes === "number";
		if (hasSingle) {
			const { buf, text } = bodyToBufferAndText(baseline.body);
			const size =
				typeof baseline.size === "number" && Number.isFinite(baseline.size)
					? baseline.size
					: typeof baseline.bodyBytes === "number" && Number.isFinite(baseline.bodyBytes)
						? baseline.bodyBytes
						: buf.byteLength;
			const bodyHash = baseline.bodyHash ?? (baseline.body !== undefined ? computeBodyHash(buf).bodyHash : undefined);
			const templateHash =
				baseline.templateHash ?? (baseline.body !== undefined ? computeTemplateFingerprint(text) : undefined);
			const titleSig =
				baseline.titleSig !== undefined ? normalizeTitleSig(baseline.titleSig) : normalizeTitleSig(titleOf(text));
			const codes =
				Array.isArray(baseline.codes) && baseline.codes.length > 0
					? baseline.codes
					: [typeof baseline.status === "number" ? baseline.status : 200];
			for (const code of codes) {
				out.push({
					code,
					size,
					titleSig,
					...(bodyHash ? { bodyHash } : {}),
					...(templateHash ? { templateHash } : {}),
				});
			}
		}
	}
	return out;
}

/**
 * 增强型软 404 检测（#33 / NW-13）：
 * 1. Next.js RSC Flight 流 `NEXT_HTTP_ERROR_FALLBACK;404` / `NEXT_NOT_FOUND` / `x-nextjs-matched-path: /_not-found`；
 * 2. 多语言 404 文案（如 `找不到此頁面`、`页面不存在`、`Page Not Found`、`ページが見つかりません` 等）；
 * 3. 随机不存在路径预采样基线比对（精确 bodyHash、归一化模板 templateHash、体积容差 + titleSig 与重定向目标一致性）。
 */
export function detectSoft404(
	res: DetectSoft404Input,
	baseline?: Soft404BaselineInput | null,
): Soft404DetectionResult {
	const status = Number(res.status ?? res.code ?? 0);
	const rawBodyInput = res.body !== undefined ? res.body : res.snippet;
	const { buf, text } = bodyToBufferAndText(rawBodyInput);
	const computed = computeBodyHash(buf);
	const bodyBytes =
		rawBodyInput !== undefined
			? computed.bodyBytes
			: typeof res.bodyBytes === "number" && Number.isFinite(res.bodyBytes)
				? res.bodyBytes
				: typeof res.size === "number" && Number.isFinite(res.size)
					? res.size
					: 0;
	const bodyHash = computed.bodyHash;
	const templateHash = computeTemplateFingerprint(text, res.path);
	const contentType = res.contentType ?? readHeaderCaseInsensitive(res.headers, "content-type");
	const nextMatchedPath = readHeaderCaseInsensitive(res.headers, "x-nextjs-matched-path");
	const locationHeader = readHeaderCaseInsensitive(res.headers, "location");
	const reasons: string[] = [];

	// 非 200/30x 状态码不是“假 200/30x 软 404”（真实 404 由 classifyEndpointResponse 归为 not_found）
	if (!Number.isFinite(status) || !isSoft404Status(status)) {
		return {
			isSoft404: false,
			confidence: "none",
			reasons,
			bodyBytes,
			bodyHash,
			templateHash,
		};
	}

	// 1. Next.js RSC Flight 流与框架级 404 特征（最高置信度，无需基线即可判定）
	if (nextMatchedPath && /^\/(?:_not-found|404)(?:\/|$)/i.test(nextMatchedPath)) {
		reasons.push(`x-nextjs-matched-path=${nextMatchedPath}`);
	}
	if (text && (RSC_ERROR_FALLBACK_RE.test(text) || NEXT_DATA_404_RE.test(text))) {
		const hit = /NEXT_HTTP_ERROR_FALLBACK\\?;404/i.test(text)
			? "NEXT_HTTP_ERROR_FALLBACK;404"
			: /NEXT_NOT_FOUND/i.test(text)
				? "NEXT_NOT_FOUND"
				: "__NEXT_DATA__ 404";
		reasons.push(`Next.js/RSC 404 特征 (${hit})`);
	}
	if (reasons.length > 0) {
		return {
			isSoft404: true,
			confidence: "high",
			reasons,
			matchedRule: "rsc_error_fallback",
			bodyBytes,
			bodyHash,
			templateHash,
		};
	}

	const extractedTitle = res.titleSig !== undefined ? normalizeTitleSig(res.titleSig) : normalizeTitleSig(titleOf(text));
	const isRealJsonBusiness = text ? isJsonBusinessDataPayload(text, contentType) : false;

	// 2. 多语言 404 文案特征（防 JSON 业务载荷误杀）
	if (!isRealJsonBusiness) {
		const inspectTarget = text || extractedTitle;
		if (inspectTarget) {
			for (const pat of MULTILINGUAL_404_PATTERNS) {
				if (pat.re.test(inspectTarget)) {
					reasons.push(`命中多语言软 404 文案 (${pat.label})`);
					return {
						isSoft404: true,
						confidence: "high",
						reasons,
						matchedRule: "multilingual_404_copy",
						bodyBytes,
						bodyHash,
						templateHash,
					};
				}
			}
		}
	}

	// 3. 预采样基线比对（仅在基线含 200/30x 兜底样本或显式提供基线样本时执行）
	const samples = normalizeBaselineSamples(baseline).filter((s) => isSoft404Status(s.code));
	if (samples.length === 0) {
		return {
			isSoft404: false,
			confidence: "none",
			reasons,
			bodyBytes,
			bodyHash,
			templateHash,
		};
	}

	const hasTitleEvidence = res.titleSig !== undefined || rawBodyInput !== undefined;

	for (const sample of samples) {
		if (status !== sample.code) continue;

		// 3a. 精确 bodyHash 一致（必须具有实际正文）
		if (rawBodyInput !== undefined && sample.bodyHash && sample.bodyHash === bodyHash && bodyBytes > 0) {
			reasons.push(`响应体 SHA-256 与 404 基线完全一致 (${bodyHash.slice(0, 12)})`);
			return {
				isSoft404: true,
				confidence: "high",
				reasons,
				matchedRule: "baseline_hash_match",
				bodyBytes,
				bodyHash,
				templateHash,
			};
		}

		// 3b. 归一化模板指纹一致 + 宽松体积容差
		if (rawBodyInput !== undefined && sample.templateHash && sample.templateHash === templateHash && bodyBytes > 0) {
			const tol = Math.max(128, sample.size * 0.25);
			if (sample.size === 0 || Math.abs(bodyBytes - sample.size) <= tol) {
				reasons.push(`响应模板指纹与 404 基线一致 (${templateHash.slice(0, 12)}, ${bodyBytes}B vs ${sample.size}B)`);
				return {
					isSoft404: true,
					confidence: "high",
					reasons,
					matchedRule: "baseline_template_match",
					bodyBytes,
					bodyHash,
					templateHash,
				};
			}
		}

		// 3c. 重定向 30x 跳转到与基线相同的兜底目标
		if (status >= 300 && status < 400 && sample.redirectLocation && locationHeader) {
			if (sample.redirectLocation.toLowerCase() === locationHeader.toLowerCase()) {
				reasons.push(`30x 重定向目标与 404 基线一致 (${locationHeader})`);
				return {
					isSoft404: true,
					confidence: "high",
					reasons,
					matchedRule: "baseline_redirect_match",
					bodyBytes,
					bodyHash,
					templateHash,
				};
			}
		}

		// 3d. 体积容差（±max(48, 10%)）+ HTML title 签名一致（与原有 isSoft404Hit 完全兼容）
		const sampleTitle = normalizeTitleSig(sample.titleSig);
		if (hasTitleEvidence && extractedTitle !== sampleTitle) {
			continue;
		}
		if (bodyBytes > 0 || typeof res.size === "number" || typeof res.bodyBytes === "number") {
			const effectiveSize =
				typeof res.size === "number" && Number.isFinite(res.size)
					? res.size
					: typeof res.bodyBytes === "number" && Number.isFinite(res.bodyBytes)
						? res.bodyBytes
						: bodyBytes;
			const tolerance = Math.max(48, sample.size * 0.1);
			if (Math.abs(effectiveSize - sample.size) <= tolerance) {
				reasons.push(`状态码 ${status}、体积 ${effectiveSize}B≈${sample.size}B 且标题签名一致`);
				return {
					isSoft404: true,
					confidence: "medium",
					reasons,
					matchedRule: "baseline_size_title_match",
					bodyBytes: effectiveSize,
					bodyHash,
					templateHash,
				};
			}
		} else if (text && sampleTitle !== "" && extractedTitle === sampleTitle && HTML_SIGNATURE_RE.test(text)) {
			reasons.push(`HTML 标题签名与 404 基线一致 (${sampleTitle})`);
			return {
				isSoft404: true,
				confidence: "medium",
				reasons,
				matchedRule: "baseline_size_title_match",
				bodyBytes,
				bodyHash,
				templateHash,
			};
		}
	}

	return {
		isSoft404: false,
		confidence: "none",
		reasons,
		bodyBytes,
		bodyHash,
		templateHash,
	};
}

/**
 * 对随机不存在路径执行预采样，构建包含精确 bodyHash、模板指纹 templateHash、体积与标题的 Soft-404 基线（#33）。
 */
export async function sampleSoft404Baseline(
	origin: string,
	fetchFn?: PreflightFetchLike,
	opts?: {
		paths?: readonly string[];
		headers?: Record<string, string>;
		timeoutMs?: number;
		signal?: AbortSignal;
	},
): Promise<Soft404Baseline> {
	const base = String(origin ?? "").replace(/\/+$/, "");
	const randHex = () => randomBytes(6).toString("hex");
	const paths =
		opts?.paths && opts.paths.length > 0
			? [...opts.paths]
			: [`/__nuwa_soft404_${randHex()}`, `/__nuwa_soft404_${randHex()}.html`];

	const fetcher: PreflightFetchLike =
		fetchFn ??
		(async (u, init) => {
			const r = await fetch(u, {
				method: init?.method ?? "GET",
				headers: init?.headers,
				signal: init?.signal,
				redirect: init?.redirect ?? "manual",
			});
			return { ok: r.ok, status: r.status, text: () => r.text(), headers: r.headers };
		});

	const timeoutMs = Math.max(500, Math.min(30_000, opts?.timeoutMs ?? 6_000));
	const samples: Soft404Sample[] = [];
	const codes: number[] = [];

	for (const p of paths) {
		if (opts?.signal?.aborted) break;
		const normPath = p.startsWith("/") ? p : `/${p}`;
		const controller = new AbortController();
		const onAbort = () => controller.abort();
		opts?.signal?.addEventListener("abort", onAbort, { once: true });
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		try {
			const resp = await fetcher(`${base}${normPath}`, {
				method: "GET",
				headers: opts?.headers,
				signal: controller.signal,
				redirect: "manual",
			});
			const bodyText = await resp.text();
			const { bodyHash, bodyBytes } = computeBodyHash(bodyText);
			const templateHash = computeTemplateFingerprint(bodyText, normPath);
			const titleSig = normalizeTitleSig(titleOf(bodyText));
			const redirectLocation = resp.headers?.get("location")?.trim() || undefined;
			samples.push({
				path: normPath,
				code: resp.status,
				size: bodyBytes,
				titleSig,
				bodyHash,
				templateHash,
				...(redirectLocation ? { redirectLocation } : {}),
			});
			if (isSoft404Status(resp.status) && !codes.includes(resp.status)) {
				codes.push(resp.status);
			}
		} catch {
			/* 单次采样失败不影响另一条随机基线 */
		} finally {
			clearTimeout(timer);
			opts?.signal?.removeEventListener("abort", onAbort);
		}
	}

	const activeSamples = samples.filter((s) => isSoft404Status(s.code));
	if (activeSamples.length === 0) {
		return { active: false, samples, codes: [] };
	}
	const first = activeSamples[0]!;
	const firstTitle = activeSamples.find((s) => s.titleSig !== "")?.titleSig ?? "";
	return {
		active: true,
		samples,
		codes,
		size: first.size,
		titleSig: firstTitle,
		...(first.bodyHash ? { bodyHash: first.bodyHash } : {}),
		...(first.templateHash ? { templateHash: first.templateHash } : {}),
	};
}

/**
 * 端点响应分类器（#32 / NW-12）：
 * - 明确区分 `exists_requires_auth`（401、带业务鉴权语义的 403、带 Allow 头的 405、跳登录页的 30x）
 *   与 `not_found`（404/410 或与 404 基线同指纹响应）、`soft_404`（200/30x 软 404）及 `egress_blocked`（边缘 WAF 阻断）；
 * - 强制计算并填入响应体 SHA-256 哈希与精确字节数至结果与 `meta`。
 */
export function classifyEndpointResponse(
	res: EndpointResponseInput,
	baseline404?: EndpointBaseline404 | null,
): EndpointResponseClassification {
	const status = Number(res.status ?? 0);
	const { buf, text } = bodyToBufferAndText(res.body);
	const computed = computeBodyHash(buf);
	const bodyBytes =
		res.body !== undefined
			? computed.bodyBytes
			: typeof res.bodyBytes === "number" && Number.isFinite(res.bodyBytes)
				? res.bodyBytes
				: 0;
	const bodyHash = computed.bodyHash;
	const templateHash = computeTemplateFingerprint(text, res.path);

	const headerText = serializeHeadersForInspection(res.headers);
	const contentType = res.contentType ?? readHeaderCaseInsensitive(res.headers, "content-type");
	const allowHeader = readHeaderCaseInsensitive(res.headers, "allow");
	const wwwAuthHeader = readHeaderCaseInsensitive(res.headers, "www-authenticate");
	const locationHeader = readHeaderCaseInsensitive(res.headers, "location");
	const cfMitigated = readHeaderCaseInsensitive(res.headers, "cf-mitigated");

	const allowMethods = allowHeader
		? allowHeader
				.split(",")
				.map((m) => m.trim().toUpperCase())
				.filter((m) => /^[A-Z]+$/.test(m))
		: undefined;
	const hasAllowMethods = Boolean(allowMethods && allowMethods.length > 0);
	const waf = detectWafName(headerText, text, Number.isFinite(status) ? status : undefined);

	const build = (
		classification: EndpointClassification,
		exists: boolean,
		requiresAuth: boolean,
		reason: string,
		extraWaf?: string,
	): EndpointResponseClassification => {
		const finalWaf = extraWaf ?? (classification === "egress_blocked" ? waf : undefined);
		return {
			classification,
			exists,
			requiresAuth,
			status,
			bodyHash,
			bodyBytes,
			templateHash,
			...(hasAllowMethods ? { allowMethods } : {}),
			...(finalWaf ? { waf: finalWaf } : {}),
			reason,
			meta: {
				status,
				bodyHash,
				bodyBytes,
				templateHash,
				classification,
				requiresAuth,
				...(hasAllowMethods ? { allow: allowMethods } : {}),
				...(finalWaf ? { waf: finalWaf } : {}),
			},
		};
	};

	// 与 404 基线比对精确哈希或模板指纹（覆盖任意状态码伪装同页 404，如 404/6586B）
	const baselineSamples = normalizeBaselineSamples(baseline404?.soft404Baseline ?? baseline404);
	const matches404BaselineFingerprint = (): boolean => {
		if (res.body === undefined || baselineSamples.length === 0) return false;
		for (const s of baselineSamples) {
			if (s.bodyHash && s.bodyHash === bodyHash && bodyBytes > 0) return true;
			if (s.templateHash && s.templateHash === templateHash && bodyBytes > 0) {
				const tol = Math.max(128, s.size * 0.25);
				if (s.size === 0 || Math.abs(bodyBytes - s.size) <= tol) return true;
			}
		}
		return false;
	};

	// 1. 明确 404 / 410：绝不混算为需要认证的端点
	if (status === 404 || status === 410) {
		return build("not_found", false, false, `HTTP ${status} 端点不存在 (${bodyBytes}B, sha256=${bodyHash.slice(0, 12)})`);
	}

	// 2. 明确 401：端点存在且要求鉴权
	if (status === 401) {
		return build(
			"exists_requires_auth",
			true,
			true,
			`HTTP 401 端点存在但需认证${wwwAuthHeader ? ` (${wwwAuthHeader})` : ""}`,
		);
	}

	// 3. 明确 405：带 Allow 头说明路由已注册存在（需换方法或鉴权）；否则若与 404 基线同指纹则判 not_found
	if (status === 405) {
		if (hasAllowMethods) {
			return build(
				"exists_requires_auth",
				true,
				true,
				`HTTP 405 路由存在 (Allow: ${allowMethods!.join(", ")})`,
			);
		}
		if (matches404BaselineFingerprint()) {
			return build("not_found", false, false, "HTTP 405 且响应体与 404 基线同指纹，判定不存在");
		}
		return build("exists", true, false, "HTTP 405 Method Not Allowed（未提供 Allow 头）");
	}

	// 4. 403：严格区分 边缘 WAF/Cloudflare 阻断 vs 业务鉴权语义 vs 与 404 基线同指纹
	if (status === 403) {
		const isChallengeHeader = /challenge/i.test(cfMitigated);
		const isHtmlBody = looksLikeHtml(text) || /text\/html/i.test(contentType);
		const isJsonBody = /application\/json|\+json/i.test(contentType) || (/^\s*\{[\s\S]*\}\s*$/.test(text) && !isHtmlBody);
		const hasEdgeBlockCopy = EDGE_BLOCK_403_RE.test(`${headerText}\n${text}`);
		const hasBusinessAuthSemantics =
			Boolean(wwwAuthHeader) ||
			BUSINESS_AUTH_403_RE.test(text) ||
			(isJsonBody && /"(?:error|message|msg|code|detail|reason)"\s*:/i.test(text) && !hasEdgeBlockCopy);

		if (isChallengeHeader || (hasEdgeBlockCopy && !isJsonBody)) {
			return build(
				"egress_blocked",
				false,
				false,
				`HTTP 403 边缘防火墙/WAF 拦截 (${waf ?? "edge-waf"})`,
				waf ?? "edge-waf",
			);
		}
		if (hasBusinessAuthSemantics) {
			return build(
				"exists_requires_auth",
				true,
				true,
				`HTTP 403 命中业务鉴权拒绝语义 (${bodyBytes}B, sha256=${bodyHash.slice(0, 12)})`,
			);
		}
		if (matches404BaselineFingerprint()) {
			return build("not_found", false, false, "HTTP 403 且与 404 基线同指纹，判定不存在");
		}
		if (waf && isHtmlBody) {
			return build("egress_blocked", false, false, `HTTP 403 HTML 命中 WAF 拦截特征 (${waf})`, waf);
		}
		return build("exists_requires_auth", true, true, `HTTP 403 访问受限（疑似鉴权边界，${bodyBytes}B）`);
	}

	// 5. 406 / 429 / 503 边缘拦截或挑战门
	if (status === 406 || status === 429 || status === 503) {
		if (/challenge/i.test(cfMitigated) || waf || EDGE_BLOCK_403_RE.test(`${headerText}\n${text}`)) {
			return build(
				"egress_blocked",
				false,
				false,
				`HTTP ${status} 触发边缘拦截/限流 (${waf ?? "rate-limit"})`,
				waf ?? (status === 429 ? "rate-limit" : "edge-waf"),
			);
		}
		if (status >= 500) {
			return build("server_error", false, false, `HTTP ${status} 服务端错误`);
		}
	}

	// 6. 2xx 响应：检查挑战门与软 404
	if (status >= 200 && status < 300) {
		if (/challenge/i.test(cfMitigated) || EDGE_BLOCK_403_RE.test(text)) {
			return build(
				"egress_blocked",
				false,
				false,
				`HTTP ${status} 返回人机挑战/边缘阻断页`,
				waf ?? "cloudflare",
			);
		}
		const soft = detectSoft404(
			{
				url: res.url,
				path: res.path,
				status,
				body: res.body,
				bodyBytes,
				headers: res.headers,
				contentType,
			},
			baseline404?.soft404Baseline ?? baseline404,
		);
		if (soft.isSoft404) {
			return build(
				"soft_404",
				false,
				false,
				`HTTP ${status} 命中软 404: ${soft.reasons.join("; ")}`,
			);
		}
		if (matches404BaselineFingerprint()) {
			return build("not_found", false, false, `HTTP ${status} 响应体与 404 基线同指纹，判定不存在`);
		}
		return build("exists", true, false, `HTTP ${status} 有效端点 (${bodyBytes}B, sha256=${bodyHash.slice(0, 12)})`);
	}

	// 7. 3xx 重定向：登录跳转判 exists_requires_auth，软 404 重定向判 soft_404
	if (status >= 300 && status < 400) {
		if (locationHeader && LOGIN_LOCATION_RE.test(locationHeader)) {
			return build("exists_requires_auth", true, true, `HTTP ${status} 重定向至登录认证页 (${locationHeader})`);
		}
		const soft = detectSoft404(
			{
				url: res.url,
				path: res.path,
				status,
				body: res.body,
				bodyBytes,
				headers: res.headers,
				contentType,
			},
			baseline404?.soft404Baseline ?? baseline404,
		);
		if (soft.isSoft404) {
			return build("soft_404", false, false, `HTTP ${status} 重定向命中软 404 基线`);
		}
		return build("redirect", true, false, `HTTP ${status} 重定向${locationHeader ? ` -> ${locationHeader}` : ""}`);
	}

	// 8. 其余 4xx 且与 404 基线同指纹 -> not_found；5xx -> server_error
	if (status >= 400 && status < 500 && matches404BaselineFingerprint()) {
		return build("not_found", false, false, `HTTP ${status} 与 404 基线同指纹`);
	}
	if (status >= 500 && status < 600) {
		return build("server_error", false, false, `HTTP ${status} 服务端错误`);
	}

	return build("unknown", false, false, `HTTP ${status} 未归类响应`);
}

/**
 * 判断单条探测结果是否命中 Soft-404 兜底基线：
 * 依据 Next.js RSC Flight 特征、多语言 404 文案、精确/模板指纹及状态码 + 体积容差（±max(48, 10%)）+ HTML title 签名一致判定。
 */
export function isSoft404Hit(
	row: string | Soft404Candidate,
	baseline: Soft404Baseline | null | undefined,
): boolean {
	const cand = typeof row === "string" ? parseSoft404RowString(row) : row;
	if (!cand) return false;
	const code = Number(cand.status ?? cand.code);
	if (!Number.isFinite(code) || !isSoft404Status(code)) return false;

	const rawBody = cand.body ?? cand.snippet;
	// 即使无有效基线，明确的 Next.js RSC 404 特征或多语言 404 页面文案也立即拦截
	if (rawBody !== undefined) {
		const res = detectSoft404(
			{
				url: cand.url,
				path: cand.path,
				status: code,
				body: rawBody,
				size: cand.size,
				bodyBytes: cand.bodyBytes,
				titleSig: cand.titleSig,
				headers: cand.headers,
				contentType: cand.contentType,
			},
			baseline && baseline.active ? baseline : null,
		);
		if (res.isSoft404) return true;
	}

	if (!baseline || !baseline.active) {
		// 若仅提取到明确的 404 多语言标题（无正文场景，如 dirsRule 行）也过滤
		if (cand.titleSig) {
			const normTitle = normalizeTitleSig(cand.titleSig);
			if (normTitle && MULTILINGUAL_404_PATTERNS.some((p) => p.re.test(normTitle))) {
				return true;
			}
		}
		return false;
	}

	let activeSamples = (baseline.samples ?? []).filter((s) => isSoft404Status(s.code));
	if (activeSamples.length === 0 && Array.isArray(baseline.codes) && typeof baseline.size === "number") {
		activeSamples = baseline.codes
			.filter((c) => isSoft404Status(c))
			.map((sampleCode) => ({
				code: sampleCode,
				size: baseline.size!,
				titleSig: normalizeTitleSig(baseline.titleSig),
			}));
	}
	if (activeSamples.length === 0) return false;

	const hasTitleEvidence = cand.titleSig !== undefined || rawBody !== undefined;
	const candTitle =
		cand.titleSig !== undefined
			? normalizeTitleSig(cand.titleSig)
			: rawBody !== undefined
				? normalizeTitleSig(titleOf(rawBody))
				: "";

	for (const sample of activeSamples) {
		if (code !== sample.code) continue;

		const sampleTitle = normalizeTitleSig(sample.titleSig);
		if (hasTitleEvidence && candTitle !== sampleTitle) {
			continue;
		}

		const candSize = cand.size ?? cand.bodyBytes;
		if (typeof candSize === "number" && Number.isFinite(candSize)) {
			const tolerance = Math.max(48, sample.size * 0.1);
			if (Math.abs(candSize - sample.size) <= tolerance) {
				return true;
			}
			continue;
		}

		// 若旧格式未携带 size，仅当存在相同非空 HTML title 且正文呈 HTML 特征时判定命中
		if (rawBody !== undefined && sampleTitle !== "" && candTitle === sampleTitle && HTML_SIGNATURE_RE.test(rawBody)) {
			return true;
		}
	}

	return false;
}

function looksLikeHtml(text: string): boolean {
	return HTML_SIGNATURE_RE.test(String(text ?? ""));
}

function isConfirmedGitHead(body: string): boolean {
	const s = String(body ?? "").trim();
	if (!s || looksLikeHtml(s)) return false;
	return GIT_HEAD_REF_RE.test(s) || GIT_HEAD_SHA_RE.test(s);
}

function isConfirmedEnvContent(body: string): boolean {
	const s = String(body ?? "").trim();
	if (!s || looksLikeHtml(s)) return false;
	return ENV_PAIR_TEST_RE.test(s);
}

/** 对 .env 配置行中的明文密钥值做脱敏掩码（保留键名，隐藏值）。 */
export function maskEnvSecrets(text: string): string {
	return String(text ?? "").replace(ENV_PAIR_MASK_RE, "$1$2***");
}

function isOpenApiPath(path: string): boolean {
	return OPENAPI_PATH_RE.test(String(path ?? "").trim());
}

function isConfirmedOpenApiDoc(body: string): boolean {
	const s = String(body ?? "").trim();
	if (!s || looksLikeHtml(s)) return false;
	if (/"(?:openapi|swagger)"\s*:/.test(s)) return true;
	if (/"paths"\s*:\s*\{/.test(s) && /"(?:info|components|definitions|servers|basePath|host)"\s*:/.test(s)) {
		return true;
	}
	return false;
}

/** 生成 Soft-404 随机不存在路径探测脚本片段（依赖 $BASE 与临时文件 $b）。 */
function buildSoft404BaselineLines(trackWafVar: "waf_429" | "waf_code"): string[] {
	const wafCheck =
		trackWafVar === "waf_429"
			? `  [ "$b_code" = "429" ] && waf_429=1`
			: `  [ "$b_code" = "429" ] && waf_code="429"`;
	return [
		`for bp in ${SOFT404_CHECK_PATHS.map(shellQuote).join(" ")}; do`,
		`  b_meta=$(curl -k -sS -o "$b" --max-time 5 -w '%{http_code} %{size_download}' "$BASE$bp" 2>/dev/null)`,
		`  b_rc=$?`,
		`  case "$b_rc" in 6|7|28|35|52|56) net_rc=$b_rc ;; esac`,
		`  b_code=\${b_meta%% *}`,
		`  b_size=\${b_meta#* }`,
		wafCheck,
		`  [ -z "$b_code" ] && b_code=000`,
		`  if [ -z "$b_size" ] || [ "$b_size" = "$b_meta" ]; then b_size=0; fi`,
		`  b_title=$(LC_ALL=C tr '\\r\\n\\t\\0' '    ' < "$b" | head -c 4096 | LC_ALL=C sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\\([^<]*\\)<\\/[Tt][Ii][Tt][Ll][Ee]>.*/\\1/p' | head -c 120 | LC_ALL=C sed 's/^[[:space:]]*//;s/[[:space:]]*$//')`,
		`  [ -z "$b_title" ] && b_title="-"`,
		`  echo "BASELINE $b_code $b_size $b_title"`,
		`done`,
	];
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

function buildPortsNmapScript(ports: readonly number[], host: string): string {
	const safePorts = ports.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535);
	const cleanHost = String(host ?? "").replace(/^\[|\]$/g, "");
	const ipv6Flag = cleanHost.includes(":") ? "-6 " : "";
	const portArg = safePorts.join(",");
	const nmapCmd = `nmap ${ipv6Flag}-Pn -sT -T4 --open -p ${portArg} -oG - ${shellQuote(cleanHost)}`;
	const fallback = buildPortsPythonScript(safePorts, host);
	return [
		`if command -v nmap >/dev/null 2>&1; then`,
		`  ${nmapCmd}`,
		`else`,
		`  ${fallback}`,
		`fi`,
	].join("\n");
}

function parsePortsFact(res: ExecLikeResult, st: NuwaState, portCount = PORT_LIST.length): AutoFact | null {
	const portServices = new Map<number, string>();
	let fromNmap = false;

	// 1. 兼容原有 `open <port>` 行
	for (const m of res.stdout.matchAll(/^open\s+(\d{1,5})$/gm)) {
		const n = Number(m[1]);
		if (Number.isInteger(n) && n >= 1 && n <= 65535 && !portServices.has(n)) {
			portServices.set(n, "");
		}
	}

	// 2. 兼容 `nmap -oG -` 的 `Ports:` 行
	for (const rawLine of res.stdout.replace(/\r/g, "").split("\n")) {
		const pm = /\bPorts:\s*([^\t]+)/.exec(rawLine);
		if (!pm) continue;
		for (const entry of pm[1]!.split(",")) {
			const em = /^\s*(\d{1,5})\/open\/(?:tcp|udp)\/[^/]*\/([^/]*)/.exec(entry.trim());
			if (!em) continue;
			const n = Number(em[1]);
			if (Number.isInteger(n) && n >= 1 && n <= 65535) {
				fromNmap = true;
				const svc = (em[2] ?? "").trim();
				if (!portServices.has(n) || (svc && !portServices.get(n))) {
					portServices.set(n, svc);
				}
			}
		}
	}

	const nums = [...portServices.keys()].sort((a, b) => a - b);
	if (nums.length === 0) return null;

	const csv = nums.join(",");
	const tcpTokens = nums
		.map((p) => {
			const svc = portServices.get(p);
			return svc ? `${p}/tcp(${svc})` : `${p}/tcp`;
		})
		.join(" ");
	const outLines = nums.map((p) => {
		const svc = portServices.get(p);
		return svc ? `${p}/tcp open ${svc}` : `${p}/tcp open`;
	});

	return {
		kind: "service",
		title: `${st.project.host} TCP 开放 ${nums.length} 端口`,
		detail: `${fromNmap ? "nmap -sT" : "tcp connect"} (${csv}): ${tcpTokens}`,
		command: clip(
			fromNmap
				? `nmap -Pn -sT -T4 --open -p ${portCount} ports -oG - ${st.project.host}`
				: `python3 socket.create_connection scan ${st.project.host} (${portCount} ports)`,
			400,
		),
		output: clip(outLines.join("\n"), 800),
		meta: { ports: nums },
	};
}

interface ParsedDirRow {
	path: string;
	code: number;
	size: number;
	redirect: string;
	titleSig?: string;
	fromFfuf?: boolean;
}

function parseDirsRowLine(rawLine: string): ParsedDirRow | null {
	const trimmed = rawLine.trim();
	if (!trimmed) return null;
	if (/^(?:BASELINE|FINAL)\s+/.test(trimmed)) return null;

	// 1. ffuf -json NDJSON 格式
	if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
		try {
			const obj = JSON.parse(trimmed) as {
				status?: unknown;
				length?: unknown;
				url?: unknown;
				redirectlocation?: unknown;
				input?: { FUZZ?: unknown };
			};
			const code = Number(obj.status);
			if (!DIR_HIT_STATUS_SET.has(code)) return null;
			const size = Number.isFinite(Number(obj.length)) ? Number(obj.length) : 0;
			let path = "";
			// 优先从明文 obj.url 提取 pathname（真实 ffuf -json 的 input.FUZZ 为 base64 编码）
			if (typeof obj.url === "string" && obj.url.trim()) {
				try {
					path = new URL(obj.url).pathname || "/";
				} catch {
					path = "";
				}
			}
			if (!path && typeof obj.input?.FUZZ === "string" && obj.input.FUZZ.trim()) {
				const rawFuzz = obj.input.FUZZ.trim();
				let decoded = rawFuzz;
				if (!rawFuzz.includes("/") && /^[A-Za-z0-9+/]+={0,2}$/.test(rawFuzz) && rawFuzz.length % 4 === 0) {
					try {
						const candidate = Buffer.from(rawFuzz, "base64").toString("utf8");
						if (candidate && /^[\x21-\x7e]+$/.test(candidate) && Buffer.from(candidate, "utf8").toString("base64") === rawFuzz) {
							decoded = candidate;
						}
					} catch {
						/* 保留原文 */
					}
				}
				path = decoded.startsWith("/") ? decoded : `/${decoded}`;
			}
			if (!path.startsWith("/")) return null;
			return {
				path,
				code,
				size,
				redirect: typeof obj.redirectlocation === "string" ? obj.redirectlocation.trim() : "",
				fromFfuf: true,
			};
		} catch {
			return null;
		}
	}

	// 2. curl 行格式：/path 200 1234 [redirect] [TITLE=xxx]
	const curlMatch = /^(\/\S*)\s+(200|204|301|302|307|401|403|405|500)\s+(\d+)(?:\s+(.*))?$/.exec(trimmed);
	if (curlMatch) {
		const path = curlMatch[1]!;
		const code = Number(curlMatch[2]);
		const size = Number(curlMatch[3]);
		let rest = (curlMatch[4] ?? "").trim();
		let titleSig: string | undefined;
		const tm = /(?:^|\s)TITLE=(.*)$/.exec(rest);
		if (tm) {
			titleSig = normalizeTitleSig(tm[1]);
			rest = rest.slice(0, tm.index).trim();
		}
		return { path, code, size, redirect: rest, titleSig };
	}

	// 3. ffuf 纯文本格式：admin [Status: 200, Size: 1234, ...]
	const ffufText = /^([^\s\[]+)\s+\[Status:\s*(\d{3}),\s*Size:\s*(\d+)/i.exec(trimmed);
	if (ffufText) {
		const code = Number(ffufText[2]);
		if (!DIR_HIT_STATUS_SET.has(code)) return null;
		const rawPath = ffufText[1]!.trim();
		const path = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
		return {
			path,
			code,
			size: Number(ffufText[3]),
			redirect: "",
			fromFfuf: true,
		};
	}

	return null;
}

function parseDirsFact(res: ExecLikeResult, st: NuwaState, pathCount = DIR_PATHS.length): AutoFact | null {
	const baseline = parseSoft404Baseline(res.stdout);
	const parsedRows: ParsedDirRow[] = [];
	const seenPath = new Set<string>();
	let usedFfuf = false;

	for (const rawLine of res.stdout.replace(/\r/g, "").split("\n")) {
		const row = parseDirsRowLine(rawLine);
		if (!row) continue;
		if (isSoft404Hit({ path: row.path, code: row.code, size: row.size, titleSig: row.titleSig }, baseline)) {
			continue;
		}
		if (seenPath.has(row.path)) continue;
		seenPath.add(row.path);
		if (row.fromFfuf) usedFfuf = true;
		parsedRows.push(row);
	}

	if (parsedRows.length === 0) return null;

	const paths = parsedRows.map((r) => r.path);
	const codes = parsedRows.map((r) => r.code);
	const preferredStatus = codes.find((c) => c >= 200 && c < 300) ?? codes[0] ?? 200;
	const displayRows = parsedRows.map((r) =>
		r.redirect ? `${r.path} ${r.code} ${r.size} ${r.redirect}` : `${r.path} ${r.code} ${r.size}`,
	);

	return {
		kind: "endpoint",
		title: `发现 ${parsedRows.length} 条路径`,
		detail: displayRows.join(" | ").slice(0, 600),
		command: clip(
			usedFfuf ? `ffuf -ac ${pathCount} paths @ ${originOf(st)}` : `curl ${pathCount} paths @ ${originOf(st)}`,
			400,
		),
		output: clip(displayRows.join("\n"), 800),
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

interface ParsedProbeRow {
	path: string;
	code: number;
	size?: number;
	titleSig?: string;
	body: string;
}

function parseProbeFact(key: string, pathCount: number, res: ExecLikeResult, st: NuwaState): AutoFact | null {
	const baseline = parseSoft404Baseline(res.stdout);
	const rawRows: string[] = [];

	for (const rawLine of res.stdout.replace(/\r/g, "").split("\n")) {
		const trimmed = rawLine.trim();
		if (!trimmed) continue;
		if (/^BASELINE\s+\d{3}\s+\d+/.test(trimmed)) continue;
		if (/^FINAL\s+\d{3}\b/.test(trimmed)) continue;
		if (/^\/\S*\s+/.test(trimmed)) {
			rawRows.push(trimmed);
		} else if (rawRows.length > 0) {
			// 兼容未压平的多行响应体续行（如多行 JSON / .env 内容）拼接回上一条命中记录
			rawRows[rawRows.length - 1] = `${rawRows[rawRows.length - 1]} ${trimmed}`.slice(0, 600);
		}
	}
	if (rawRows.length === 0) return null;

	const kept: Array<{
		row: ParsedProbeRow;
		confirmedGit: boolean;
		confirmedEnv: boolean;
		confirmedApiDoc: boolean;
		displayLine: string;
	}> = [];

	for (const raw of rawRows) {
		let parsed: ParsedProbeRow | null = null;
		const newFmt = /^(\/\S*)\s+(\d{3})\s+SIZE=(\d+)\s+TITLE=([^\t]*)(?:\t(.*))?$/.exec(raw);
		if (newFmt) {
			parsed = {
				path: newFmt[1]!,
				code: Number(newFmt[2]),
				size: Number(newFmt[3]),
				titleSig: normalizeTitleSig(newFmt[4]),
				body: (newFmt[5] ?? "").trim(),
			};
		} else {
			const legacyFmt = /^(\/\S*)\s+(?:(\d{3})\b\s*)?(.*)$/.exec(raw);
			if (legacyFmt?.[1]) {
				const body = (legacyFmt[3] ?? "").trim();
				parsed = {
					path: legacyFmt[1],
					code: legacyFmt[2] ? Number(legacyFmt[2]) : 200,
					body,
				};
			}
		}
		if (!parsed) continue;

		const isGitPath = parsed.path === "/.git/HEAD";
		const isEnvPath = parsed.path === "/.env" || /^\/\.env(?:\.[A-Za-z0-9_-]+)?$/i.test(parsed.path);
		const isApiDocPath = isOpenApiPath(parsed.path);

		const confirmedGit = isGitPath && isConfirmedGitHead(parsed.body);
		const confirmedEnv = isEnvPath && isConfirmedEnvContent(parsed.body);
		const confirmedApiDoc = isApiDocPath && isConfirmedOpenApiDoc(parsed.body);

		// 强语义实锤（真实 git HEAD / .env / OpenAPI JSON）不被无 title 小体积兜底误杀
		const hasStrongSemanticProof = confirmedGit || confirmedEnv || confirmedApiDoc;
		if (
			!hasStrongSemanticProof &&
			isSoft404Hit(
				{
					path: parsed.path,
					code: parsed.code,
					size: parsed.size,
					titleSig: parsed.titleSig,
					body: parsed.body,
				},
				baseline,
			)
		) {
			continue;
		}

		// 内容级语义兜底：即便无 BASELINE 行，返回 HTML 的 .git/HEAD、.env、openapi/swagger.json 绝不误报
		if ((isGitPath || isEnvPath || isApiDocPath) && looksLikeHtml(parsed.body)) {
			continue;
		}

		const safeBody = isEnvPath && confirmedEnv ? maskEnvSecrets(parsed.body) : parsed.body;
		const displayLine = safeBody ? `${parsed.path} ${parsed.code} ${safeBody}` : `${parsed.path} ${parsed.code}`;
		kept.push({
			row: { ...parsed, body: safeBody },
			confirmedGit,
			confirmedEnv,
			confirmedApiDoc,
			displayLine,
		});
	}

	if (kept.length === 0) return null;

	const paths: string[] = [];
	let detectedStatus = 200;
	for (const item of kept) {
		if (!paths.includes(item.row.path)) paths.push(item.row.path);
		detectedStatus = item.row.code;
	}

	const normKey = canonicalAutoKey(key);
	const isSensitive = normKey === "surface:sensitive";
	const hasConfirmedGit = kept.some((k) => k.confirmedGit);
	const hasConfirmedEnv = kept.some((k) => k.confirmedEnv);
	const hasConfirmedApiDoc = kept.some(
		(k) => k.confirmedApiDoc || (!isOpenApiPath(k.row.path) && isConfirmedOpenApiDoc(k.row.body)),
	);

	const title = isSensitive
		? hasConfirmedGit || hasConfirmedEnv
			? `敏感文件暴露 ${kept.length} 条`
			: `敏感路径可读 ${kept.length} 条`
		: normKey === "surface:api"
			? hasConfirmedApiDoc
				? "API 文档暴露"
				: `API 面可达 ${kept.length} 条`
			: `探测路径命中 ${kept.length} 条`;

	const displayRows = kept.map((k) => k.displayLine);

	return {
		kind: isSensitive && (hasConfirmedGit || hasConfirmedEnv) ? "vuln" : "endpoint",
		title,
		detail: displayRows.map((r) => r.trim().slice(0, 180)).join(" | ").slice(0, 700),
		command: clip(`curl ${pathCount} paths @ ${originOf(st)}`, 400),
		output: clip(displayRows.join("\n"), 800),
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
			if (hasToolchainTool(st, "nmap")) {
				return buildPortsNmapScript(ports, st.project.host);
			}
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
			const useFfuf = hasToolchainTool(st, "ffuf");
			const words = paths.map((p) => p.replace(/^\/+/, "")).filter(Boolean);
			const curlLoop = [
				`for p in ${paths.map(shellQuote).join(" ")}; do`,
				`  out=$(curl -k -sS -o "$b" --max-time 6 -w '%{http_code} %{size_download} %{redirect_url}' "$BASE$p" 2>/dev/null)`,
				`  rc=$?`,
				`  code=\${out%% *}`,
				`  case "$rc" in 6|7|28|35|52|56) net_rc=$rc ;; esac`,
				`  [ "$code" = "429" ] && waf_429=1`,
				`  case "$code" in 200|204|301|302|307|401|403|405|500)`,
				`    hits=$((hits + 1))`,
				`    p_title=$(LC_ALL=C tr '\\r\\n\\t\\0' '    ' < "$b" | head -c 4096 | LC_ALL=C sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\\([^<]*\\)<\\/[Tt][Ii][Tt][Ll][Ee]>.*/\\1/p' | head -c 120 | LC_ALL=C sed 's/^[[:space:]]*//;s/[[:space:]]*$//')`,
				`    [ -z "$p_title" ] && p_title="-"`,
				`    echo "$p $out TITLE=$p_title"`,
				`    ;;`,
				`  esac`,
				`done`,
			];

			const bodyLines: string[] = [
				`BASE=${base}`,
				`hits=0; net_rc=0; waf_429=0`,
				`b=$(mktemp)`,
				`trap 'rm -f "$b"' EXIT`,
				...buildSoft404BaselineLines("waf_429"),
			];

			if (useFfuf && words.length > 0) {
				bodyLines.push(
					`ffuf_ok=0`,
					`if command -v ffuf >/dev/null 2>&1; then`,
					`  ffuf_out=$(printf '%s\\n' ${words.map(shellQuote).join(" ")} | ffuf -ac -s -json -t 16 -timeout 6 -maxtime 30 -mc 200,204,301,302,307,401,403,405,500 -w - -u "$BASE/FUZZ" 2>/dev/null)`,
					`  if [ $? -eq 0 ]; then`,
					`    ffuf_ok=1`,
					`    if [ -n "$ffuf_out" ]; then hits=1; printf '%s\\n' "$ffuf_out"; fi`,
					`  fi`,
					`fi`,
					`if [ "$ffuf_ok" -eq 0 ]; then`,
					...curlLoop.map((l) => `  ${l}`),
					`fi`,
				);
			} else {
				bodyLines.push(...curlLoop);
			}

			bodyLines.push(
				`if [ "$hits" -eq 0 ]; then`,
				`  if [ "$waf_429" -eq 1 ]; then echo "FINAL 429 0 $BASE"; exit 0; fi`,
				`  if [ "$net_rc" -ne 0 ]; then exit "$net_rc"; fi`,
				`fi`,
				`exit 0`,
			);
			return bodyLines.join("\n");
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
				...buildSoft404BaselineLines("waf_code"),
				`for p in ${paths.map(shellQuote).join(" ")}; do`,
				`  meta=$(curl -k -sS -D "$h" -o "$b" --max-time 6 -w '%{http_code} %{size_download}' "$BASE$p" 2>/dev/null)`,
				`  rc=$?`,
				`  code=\${meta%% *}`,
				`  p_size=\${meta#* }`,
				`  [ -z "$code" ] && code=000`,
				`  if [ -z "$p_size" ] || [ "$p_size" = "$meta" ]; then p_size=0; fi`,
				`  case "$rc" in 6|7|28|35|52|56) net_rc=$rc ;; esac`,
				`  if [ "$code" = "200" ]; then`,
				`    hits=$((hits + 1))`,
				`    p_title=$(LC_ALL=C tr '\\r\\n\\t\\0' '    ' < "$b" | head -c 4096 | LC_ALL=C sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\\([^<]*\\)<\\/[Tt][Ii][Tt][Ll][Ee]>.*/\\1/p' | head -c 120 | LC_ALL=C sed 's/^[[:space:]]*//;s/[[:space:]]*$//')`,
				`    [ -z "$p_title" ] && p_title="-"`,
				`    line=$(LC_ALL=C tr '\\r\\n\\0' '   ' < "$b" | head -c 256)`,
				`    printf '%s 200 SIZE=%s TITLE=%s\\t%s\\n' "$p" "$p_size" "$p_title" "$line"`,
				`  elif [ "$code" = "429" ] || [ "$code" = "403" ] || [ "$code" = "406" ]; then`,
				`    waf_code="$code"`,
				`    waf_hint=$( (cat "$h"; head -c 240 "$b") | LC_ALL=C tr '\\r\\n\\0' '   ' | head -c 300 )`,
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

function parseKatanaFact(res: ExecLikeResult, st: NuwaState): AutoFact | null {
	const baseOrigin = originOf(st);
	let baseHost = "";
	try {
		baseHost = new URL(baseOrigin).host.toLowerCase();
	} catch {
		baseHost = String(st.project.host ?? "").toLowerCase();
	}

	const paths: string[] = [];
	const seen = new Set<string>();
	for (const rawLine of res.stdout.replace(/\r/g, "").split("\n")) {
		const line = rawLine.trim();
		if (!line) continue;
		let pathname = "";
		if (/^https?:\/\//i.test(line)) {
			try {
				const u = new URL(line);
				if (baseHost && u.host.toLowerCase() !== baseHost) continue;
				pathname = u.pathname || "/";
			} catch {
				continue;
			}
		} else if (line.startsWith("/")) {
			pathname = line.split(/[?#]/)[0] || "/";
		} else {
			continue;
		}
		if (pathname === "/" || STATIC_ASSET_EXT_RE.test(pathname)) continue;
		if (!seen.has(pathname)) {
			seen.add(pathname);
			paths.push(pathname);
		}
	}

	if (paths.length === 0) return null;

	return {
		kind: "endpoint",
		title: `Katana 爬取发现 ${paths.length} 条端点`,
		detail: paths.slice(0, 20).join(" | ").slice(0, 600),
		command: clip(`katana -u ${st.project.url} -d 2 -jc -silent`, 400),
		output: clip(paths.join("\n"), 800),
		meta: { paths },
	};
}

interface NucleiJsonlFinding {
	templateId: string;
	name: string;
	severity: string;
	tags: string[];
	matchedAt: string;
	matcherName: string;
	extracted: string[];
}

function parseNucleiFact(res: ExecLikeResult, st: NuwaState): AutoFact | null {
	const findings: NucleiJsonlFinding[] = [];
	const techSet = new Set<string>();
	const paths: string[] = [];
	const pathSet = new Set<string>();
	let hasActionableExposure = false;

	for (const rawLine of res.stdout.replace(/\r/g, "").split("\n")) {
		const line = rawLine.trim();
		if (!line.startsWith("{") || !line.endsWith("}")) continue;
		try {
			const obj = JSON.parse(line) as {
				"template-id"?: unknown;
				templateID?: unknown;
				"matched-at"?: unknown;
				matched?: unknown;
				"matcher-name"?: unknown;
				"extracted-results"?: unknown;
				info?: {
					name?: unknown;
					severity?: unknown;
					tags?: unknown;
				};
			};
			const templateId = String(obj["template-id"] ?? obj.templateID ?? "").trim();
			if (!templateId) continue;
			const severity = String(obj.info?.severity ?? "unknown").trim().toLowerCase();
			// 双重护栏：排除 info 级别噪声
			if (severity === "info") continue;

			const name = String(obj.info?.name ?? templateId).trim();
			const rawTags = obj.info?.tags;
			const tags = Array.isArray(rawTags)
				? rawTags.map((t) => String(t).trim().toLowerCase()).filter(Boolean)
				: typeof rawTags === "string"
					? rawTags
							.split(",")
							.map((t) => t.trim().toLowerCase())
							.filter(Boolean)
					: [];

			const matchedAt = String(obj["matched-at"] ?? obj.matched ?? "").trim();
			const matcherName = String(obj["matcher-name"] ?? "").trim();
			const extracted = Array.isArray(obj["extracted-results"])
				? obj["extracted-results"].map((v) => maskEnvSecrets(String(v).slice(0, 80)))
				: [];

			if (tags.includes("tech")) {
				if (matcherName) techSet.add(matcherName.toLowerCase());
				else techSet.add(templateId.toLowerCase());
			}
			if (
				(tags.includes("exposure") || tags.includes("misconfig")) &&
				(severity === "medium" || severity === "high" || severity === "critical" || severity === "low")
			) {
				hasActionableExposure = true;
			}

			if (matchedAt) {
				try {
					const u = new URL(matchedAt);
					if (u.pathname && !pathSet.has(u.pathname)) {
						pathSet.add(u.pathname);
						paths.push(u.pathname);
					}
				} catch {
					if (matchedAt.startsWith("/") && !pathSet.has(matchedAt)) {
						pathSet.add(matchedAt);
						paths.push(matchedAt);
					}
				}
			}

			findings.push({ templateId, name, severity, tags, matchedAt, matcherName, extracted });
		} catch {
			/* 忽略非 JSONL 日志行 */
		}
	}

	if (findings.length === 0) return null;

	const summaryLines = findings.map(
		(f) =>
			`[${f.severity}] ${f.templateId}${f.matcherName ? `:${f.matcherName}` : ""} ${f.name}${f.matchedAt ? ` @ ${f.matchedAt}` : ""}`,
	);
	const tech = [...techSet];
	const kind: AutoKind = hasActionableExposure ? "vuln" : tech.length > 0 ? "service" : "endpoint";

	return {
		kind,
		title: hasActionableExposure
			? `Nuclei 检出 ${findings.length} 项配置/暴露风险`
			: `Nuclei 识别 ${findings.length} 项服务指纹`,
		detail: summaryLines.join(" | ").slice(0, 700),
		command: clip(
			`nuclei -u ${st.project.url} -tags tech,exposure,misconfig -es info -jsonl -silent -duc -nc`,
			400,
		),
		output: clip(summaryLines.join("\n"), 800),
		meta: {
			...(paths.length > 0 ? { paths } : {}),
			...(tech.length > 0 ? { tech } : {}),
		},
	};
}

function katanaRule(timeoutMs = 45_000): AutoRule {
	return {
		key: "recon:katana",
		phase: "recon",
		timeoutMs,
		script(st) {
			return `katana -u ${shellQuote(st.project.url)} -d 2 -jc -silent -timeout 10 -ct 30s`;
		},
		parse: parseKatanaFact,
	};
}

function nucleiRule(timeoutMs = 60_000): AutoRule {
	return {
		key: "surface:nuclei",
		phase: "surface",
		timeoutMs,
		script(st) {
			// 安全护栏：仅允许非破坏性技术指纹、暴露面与错误配置标签，严禁 exploit / dos 标签
			return `nuclei -u ${shellQuote(st.project.url)} -tags tech,exposure,misconfig -es info -jsonl -silent -duc -nc`;
		},
		parse: parseNucleiFact,
	};
}

/**
 * 按本地可用工具链动态生成扩展侦察规则（katana 静态/JS 爬虫与 nuclei 合规暴露面核查）。
 * 保持核心 `AUTO_KEYS` 与 `AUTO_RULES` 长度不变，100% 向后兼容现有规则集。
 */
export function enrichmentRulesForToolchain(caps?: ToolchainCaps | null): AutoRule[] {
	if (!isAutoToolchainEnabled()) return [];
	const avail = new Set((caps?.available ?? []).map((t) => String(t).trim().toLowerCase()));
	const rules: AutoRule[] = [];
	if (avail.has("katana")) {
		rules.push(katanaRule());
	}
	if (avail.has("nuclei")) {
		rules.push(nucleiRule());
	}
	return rules;
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
			`rules[${index}] (${rawKey}) parse="${String(rawParser ?? "")}" 非法；仅允许 http|ports|dirs|tls|probe|katana|nuclei`,
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
		case "katana":
			baseRule = { ...katanaRule(timeoutMs), key: rawKey, phase, timeoutMs };
			break;
		case "nuclei":
			baseRule = { ...nucleiRule(timeoutMs), key: rawKey, phase, timeoutMs };
			break;
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
	let source: "project" | "global" | "builtin" = "builtin";

	if (root && root.trim()) {
		const projFile = join(resolve(root), ".nuwa", "autoexec.json");
		if (existsSync(projFile)) {
			targetPath = projFile;
			source = "project";
		}
	}
	if (!targetPath) {
		const home = agentHome && agentHome.trim() ? resolve(agentHome) : defaultAgentHome();
		const globalFile = join(home, "nuwa-autoexec.json");
		if (existsSync(globalFile)) {
			targetPath = globalFile;
			source = "global";
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

	// 剥离 Soft-404 BASELINE 行与路径探测行中的响应体字节数列，防止体积恰好为 403/406/429 字节时误判为 WAF 拦截
	const stdoutForBlockCheck = stdout
		.replace(/\r/g, "")
		.split("\n")
		.filter((l) => !/^BASELINE\s+\d{3}\s+\d+/.test(l.trim()))
		.map((l) => {
			const trimmed = l.trim();
			const dirRow = /^(\/\S*)\s+(\d{3})\s+(?:\d+|SIZE=\d+)(?:\s+.*)?$/.exec(trimmed);
			if (dirRow) {
				return `${dirRow[1]} ${dirRow[2]}`;
			}
			return l;
		})
		.join("\n");
	const combinedForBlockCheck = `${stdoutForBlockCheck}\n${stderr}`;

	const statusMatch = HTTP_BLOCK_STATUS_RE.exec(combinedForBlockCheck);
	if (statusMatch) {
		const statusCode = Number(statusMatch[1] ?? statusMatch[2] ?? statusMatch[3] ?? 0);
		const waf = detectWafName(stdoutForBlockCheck, stderr, statusCode);
		if (waf || statusCode === 429 || WAF_CHALLENGE_RE.test(combinedForBlockCheck)) {
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
export function pickAuto(st: NuwaState, cfg: Cfg, max: number, now = Date.now(), root?: string, agentHome?: string): string[] {
	const out: Array<{ id: string; priority: number }> = [];
	const { rules } = loadAutoRules(root, agentHome);
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

const SAFE_AUTH_HEADER_FILE_RE = /^\/tmp\/nuwa\/[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\/sessions\/[a-z0-9][a-z0-9._-]{0,63}\.headers$/;

/**
 * 在不暴露任何明文凭据的前提下，为自动侦察脚本注入零明文角色头文件包装器（`curl -H @"$NUWA_AUTH_HEADER_FILE"`）。
 * 同时兼容已注入的 `$NUWA_EGRESS`（自动附加 `-x "$NUWA_EGRESS"`）。
 * 仅接受位于 `/tmp/nuwa/<projectId>/sessions/<role>.headers` 的合法路径。
 */
export function injectAuthHeaderFileIntoScript(script: string, authHeaderFile?: string): string {
	const raw = String(authHeaderFile ?? "").trim();
	if (!raw || raw.includes("..") || !SAFE_AUTH_HEADER_FILE_RE.test(raw)) {
		return script;
	}
	const prelude = [
		`NUWA_AUTH_HEADER_FILE=${shellQuote(raw)}`,
		`export NUWA_AUTH_HEADER_FILE`,
		`curl() {`,
		`  if [ -n "$NUWA_EGRESS" ] && [ -r "$NUWA_AUTH_HEADER_FILE" ]; then`,
		`    command curl -x "$NUWA_EGRESS" -H @"$NUWA_AUTH_HEADER_FILE" "$@"`,
		`  elif [ -r "$NUWA_AUTH_HEADER_FILE" ]; then`,
		`    command curl -H @"$NUWA_AUTH_HEADER_FILE" "$@"`,
		`  elif [ -n "$NUWA_EGRESS" ]; then`,
		`    command curl -x "$NUWA_EGRESS" "$@"`,
		`  else`,
		`    command curl "$@"`,
		`  fi`,
		`}`,
	].join("\n");
	return `${prelude}\n${script}`;
}

/**
 * 将已验证的任务出口代理注入 Shell 探测脚本（#23）：
 * 同时导出 `NUWA_EGRESS`/`EGRESS`/`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` 及其小写形式，
 * 并通过 `curl()` 包装器强制透传 `-x "$NUWA_EGRESS"`（同时兼容 `authHeaderFile`）。
 */
export function injectEgressIntoScript(script: string, egressUrl?: string, authHeaderFile?: string): string {
	const normEgress = egressUrl !== undefined && String(egressUrl).trim() !== ""
		? normalizeTaskEgressUrl(egressUrl)
		: undefined;
	if (egressUrl !== undefined && String(egressUrl).trim() !== "" && !normEgress) {
		throw new Error(`非法出口代理地址，拒绝注入脚本: ${JSON.stringify(egressUrl)}`);
	}

	const rawAuth = String(authHeaderFile ?? "").trim();
	const validAuth = rawAuth && !rawAuth.includes("..") && SAFE_AUTH_HEADER_FILE_RE.test(rawAuth) ? rawAuth : undefined;

	if (!normEgress && !validAuth) {
		return script;
	}
	if (!normEgress && validAuth) {
		return injectAuthHeaderFileIntoScript(script, validAuth);
	}

	const quotedEgress = shellQuote(normEgress!);
	const lines: string[] = [
		`NUWA_EGRESS=${quotedEgress}`,
		`EGRESS=${quotedEgress}`,
		`HTTP_PROXY=${quotedEgress}`,
		`HTTPS_PROXY=${quotedEgress}`,
		`ALL_PROXY=${quotedEgress}`,
		`http_proxy=${quotedEgress}`,
		`https_proxy=${quotedEgress}`,
		`all_proxy=${quotedEgress}`,
		`NO_PROXY=''`,
		`no_proxy=''`,
		`export NUWA_EGRESS EGRESS HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy`,
	];
	if (validAuth) {
		lines.push(`NUWA_AUTH_HEADER_FILE=${shellQuote(validAuth)}`, `export NUWA_AUTH_HEADER_FILE`);
	}
	lines.push(
		`curl() {`,
		`  if [ -n "$NUWA_EGRESS" ] && [ -n "$NUWA_AUTH_HEADER_FILE" ] && [ -r "$NUWA_AUTH_HEADER_FILE" ]; then`,
		`    command curl --noproxy '' -x "$NUWA_EGRESS" -H @"$NUWA_AUTH_HEADER_FILE" "$@"`,
		`  elif [ -n "$NUWA_EGRESS" ]; then`,
		`    command curl --noproxy '' -x "$NUWA_EGRESS" "$@"`,
		`  elif [ -n "$NUWA_AUTH_HEADER_FILE" ] && [ -r "$NUWA_AUTH_HEADER_FILE" ]; then`,
		`    command curl -H @"$NUWA_AUTH_HEADER_FILE" "$@"`,
		`  else`,
		`    command curl "$@"`,
		`  fi`,
		`}`,
	);
	return `${lines.join("\n")}\n${script}`;
}

const DEFAULT_PREFLIGHT_EXPECTED_STATUSES = [200, 204, 301, 302, 307, 308] as const;

/**
 * 探测前 Gate URL 基线探活（#23 / NW-03）：
 * 当出口 IP/ASN 被边缘防火墙统一拦截（如 Gate URL 返回 403/406/429/503 或 WAF Challenge）时，
 * 立即快速失败并标记 `status: "egress_blocked"` / `errorKind: "egress_blocked"`，绝不产出“目标路径不存在”的假阴性结论。
 */
export async function preflightEgressCheck(opts: PreflightEgressOptions): Promise<PreflightEgressResult> {
	const gateUrl = String(opts.gateUrl ?? "").trim();
	const expected = new Set<number>(
		opts.expectedStatuses && opts.expectedStatuses.length > 0
			? opts.expectedStatuses
			: DEFAULT_PREFLIGHT_EXPECTED_STATUSES,
	);
	const timeoutMs = Math.max(500, Math.min(30_000, Math.floor(opts.timeoutMs ?? 8_000)));
	const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));

	let parsedGate: URL;
	try {
		parsedGate = new URL(gateUrl);
		if (parsedGate.protocol !== "http:" && parsedGate.protocol !== "https:") {
			throw new Error(`不支持的协议 ${parsedGate.protocol}`);
		}
	} catch (err) {
		return {
			ok: false,
			status: "network_error",
			errorKind: "network",
			gateUrl,
			reason: `Gate URL 非法: ${err instanceof Error ? err.message : String(err)}`,
		};
	}

	let egressUrl: string | undefined;
	if (opts.egressUrl !== undefined && String(opts.egressUrl).trim() !== "") {
		egressUrl = normalizeTaskEgressUrl(opts.egressUrl);
		if (!egressUrl) {
			return {
				ok: false,
				status: "network_error",
				errorKind: "network",
				gateUrl: parsedGate.href,
				reason: `非法出口代理地址: ${JSON.stringify(opts.egressUrl)}`,
			};
		}
	}

	const maskedEgress = egressUrl ? maskEgressUrl(egressUrl) : undefined;
	const reportPool = (obs: EgressObservation) => {
		if (opts.egressPool && opts.egressId) {
			opts.egressPool.record(opts.egressId, obs);
		}
	};

	const evaluateResponse = (
		httpStatus: number,
		headers: HeaderBagLike | string,
		bodyText: string,
		ttfbMs: number,
		remoteIp?: string,
	): PreflightEgressResult => {
		const { bodyHash, bodyBytes } = computeBodyHash(bodyText);
		const headerStr = typeof headers === "string" ? headers : serializeHeadersForInspection(headers);
		const cfRay =
			(typeof headers === "string"
				? headerValue(headers, "cf-ray")
				: readHeaderCaseInsensitive(headers, "cf-ray")) || undefined;
		const cfMitigated =
			typeof headers === "string"
				? headerValue(headers, "cf-mitigated")
				: readHeaderCaseInsensitive(headers, "cf-mitigated");
		const waf = detectWafName(headerStr, bodyText, httpStatus);
		const isChallenge = /challenge/i.test(cfMitigated) || EDGE_BLOCK_403_RE.test(`${headerStr}\n${bodyText}`);

		// 1. 显式被边缘防火墙/WAF 拦截或返回 403/406/429/503（且不在期望放行码中） -> egress_blocked
		const isBlockStatus = (httpStatus === 403 || httpStatus === 406 || httpStatus === 429 || httpStatus === 503) && !expected.has(httpStatus);
		if (isBlockStatus || isChallenge) {
			const effectiveWaf = waf ?? (httpStatus === 429 ? "rate-limit" : "edge-firewall");
			reportPool({
				ok: false,
				statusCode: httpStatus,
				ttfbMs,
				blocked: true,
				error: `preflight_${httpStatus}_${effectiveWaf}`,
			});
			return {
				ok: false,
				status: "egress_blocked",
				errorKind: "egress_blocked",
				gateUrl: parsedGate.href,
				...(maskedEgress ? { egressUrl: maskedEgress } : {}),
				httpStatus,
				bodyBytes,
				bodyHash,
				ttfbMs,
				waf: effectiveWaf,
				...(cfRay ? { cfRay } : {}),
				...(remoteIp ? { remoteIp } : {}),
				reason: `出口门控探活被边缘防火墙拦截: HTTP ${httpStatus} (${bodyBytes}B, waf=${effectiveWaf})`,
			};
		}

		// 2. 命中期望状态码且无边缘阻断 -> ok
		if (expected.has(httpStatus)) {
			reportPool({ ok: true, statusCode: httpStatus, ttfbMs });
			return {
				ok: true,
				status: "ok",
				gateUrl: parsedGate.href,
				...(maskedEgress ? { egressUrl: maskedEgress } : {}),
				httpStatus,
				bodyBytes,
				bodyHash,
				ttfbMs,
				...(waf ? { waf } : {}),
				...(cfRay ? { cfRay } : {}),
				...(remoteIp ? { remoteIp } : {}),
				reason: `出口门控探活通过: HTTP ${httpStatus} (${bodyBytes}B, ttfb=${ttfbMs}ms)`,
			};
		}

		// 3. 其他 5xx -> 归网络/上游异常
		if (httpStatus >= 500 && httpStatus < 600) {
			reportPool({ ok: false, statusCode: httpStatus, ttfbMs, error: `preflight_http_${httpStatus}` });
			return {
				ok: false,
				status: "network_error",
				errorKind: "network",
				gateUrl: parsedGate.href,
				...(maskedEgress ? { egressUrl: maskedEgress } : {}),
				httpStatus,
				bodyBytes,
				bodyHash,
				ttfbMs,
				...(cfRay ? { cfRay } : {}),
				...(remoteIp ? { remoteIp } : {}),
				reason: `出口门控探活上游错误: HTTP ${httpStatus}`,
			};
		}

		// 4. 非预期状态码（例如期望 200 却收到非期望 4xx）同样判定为门控受阻，防止继续盲探产生假阴性
		reportPool({ ok: false, statusCode: httpStatus, ttfbMs, blocked: true, error: `preflight_unexpected_${httpStatus}` });
		return {
			ok: false,
			status: "egress_blocked",
			errorKind: "egress_blocked",
			gateUrl: parsedGate.href,
			...(maskedEgress ? { egressUrl: maskedEgress } : {}),
			httpStatus,
			bodyBytes,
			bodyHash,
			ttfbMs,
			...(waf ? { waf } : {}),
			...(cfRay ? { cfRay } : {}),
			...(remoteIp ? { remoteIp } : {}),
			reason: `出口门控探活返回非预期状态码 HTTP ${httpStatus}（期望 ${[...expected].join("/")}）`,
		};
	};

	const startedAt = Date.now();

	// 路径 A：显式提供 exec，或配置了代理且未注入 fetchFn -> 使用 curl -x 实走代理
	if (opts.exec || (egressUrl && !opts.fetchFn)) {
		const runner: ExecLike =
			opts.exec ??
			(async (cmd, args, execOpts) => {
				const proc = Bun.spawn([cmd, ...args], {
					cwd: execOpts?.cwd,
					stdout: "pipe",
					stderr: "pipe",
				});
				const [stdout, stderr, code] = await Promise.all([
					new Response(proc.stdout).text(),
					new Response(proc.stderr).text(),
					proc.exited,
				]);
				return { stdout, stderr, code };
			});

		const proxyArgs = egressUrl ? `--noproxy '' ${buildCurlProxyArgs(egressUrl).map(shellQuote).join(" ")}` : "";
		const headerFlags = Object.entries(opts.headers ?? {})
			.map(([k, v]) => `-H ${shellQuote(`${k}: ${v}`)}`)
			.join(" ");
		const script = [
			...(egressUrl ? [`NO_PROXY=''`, `no_proxy=''`, `export NO_PROXY no_proxy`] : []),
			`h=$(mktemp); b=$(mktemp)`,
			`trap 'rm -f "$h" "$b"' EXIT`,
			`curl -k -sS ${proxyArgs} ${headerFlags} -D "$h" -o "$b" --max-time ${timeoutSec} -w 'FINAL %{http_code} %{size_download} %{time_starttransfer} %{remote_ip}\\n' ${shellQuote(parsedGate.href)}`,
			`rc=$?`,
			`echo '---HEAD---'`,
			`cat "$h"`,
			`echo '---BODY---'`,
			`head -c 8192 "$b"`,
			`exit $rc`,
		].join("\n");

		try {
			const res = await raceWithSignal(
				runner("bash", ["-lc", script], { timeout: timeoutMs + 2000, cwd: opts.cwd, signal: opts.signal }),
				opts.signal,
			);
			const head = res.stdout.split("---HEAD---")[1]?.split("---BODY---")[0] ?? "";
			const body = res.stdout.split("---BODY---")[1] ?? "";
			const fin = res.stdout.match(/^FINAL\s+(\d{3})\s+(\d+)\s+([0-9.]+)(?:\s+(\S+))?/m);
			const statusHead = head.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/m)?.[1];
			const httpStatus = Number(fin?.[1] ?? statusHead ?? 0);
			const ttfbMs = fin?.[3] ? Math.round(Number(fin[3]) * 1000) : Math.max(0, Date.now() - startedAt);
			const remoteIp = fin?.[4] && fin[4] !== "-" ? fin[4] : undefined;

			if (!httpStatus || res.killed || CURL_NET_EXIT_CODES.has(res.code) || res.code === 97) {
				const errText = res.stderr.trim() || `curl exit=${res.code}`;
				reportPool({
					ok: false,
					ttfbMs,
					connectionReset: true,
					exitCode: res.code,
					error: errText,
				});
				return {
					ok: false,
					status: "network_error",
					errorKind: "network",
					gateUrl: parsedGate.href,
					...(maskedEgress ? { egressUrl: maskedEgress } : {}),
					ttfbMs,
					reason: `出口门控探活网络/代理故障 (${errText})`,
				};
			}

			return evaluateResponse(httpStatus, head, body, ttfbMs, remoteIp);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			const ttfbMs = Math.max(0, Date.now() - startedAt);
			reportPool({ ok: false, ttfbMs, connectionReset: true, error: msg });
			return {
				ok: false,
				status: "network_error",
				errorKind: "network",
				gateUrl: parsedGate.href,
				...(maskedEgress ? { egressUrl: maskedEgress } : {}),
				ttfbMs,
				reason: `出口门控探活异常: ${msg}`,
			};
		}
	}

	// 路径 B：使用 fetchFn 或内置 fetch 探活
	const fetcher: PreflightFetchLike =
		opts.fetchFn ??
		(async (u, init) => {
			const r = await fetch(u, {
				method: init?.method ?? "GET",
				headers: init?.headers,
				signal: init?.signal,
				redirect: init?.redirect ?? "manual",
			});
			return { ok: r.ok, status: r.status, text: () => r.text(), headers: r.headers };
		});

	const controller = new AbortController();
	const onAbort = () => controller.abort();
	opts.signal?.addEventListener("abort", onAbort, { once: true });
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await fetcher(parsedGate.href, {
			method: "GET",
			headers: opts.headers,
			signal: controller.signal,
			redirect: "manual",
		});
		const ttfbMs = Math.max(0, Date.now() - startedAt);
		const bodyText = await resp.text();
		return evaluateResponse(resp.status, resp.headers ?? {}, bodyText, ttfbMs);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		const ttfbMs = Math.max(0, Date.now() - startedAt);
		reportPool({ ok: false, ttfbMs, connectionReset: true, error: msg });
		return {
			ok: false,
			status: "network_error",
			errorKind: "network",
			gateUrl: parsedGate.href,
			...(maskedEgress ? { egressUrl: maskedEgress } : {}),
			ttfbMs,
			reason: `出口门控探活请求失败: ${msg}`,
		};
	} finally {
		clearTimeout(timer);
		opts.signal?.removeEventListener("abort", onAbort);
	}
}

export interface RunAutoIntentOptions {
	authHeaderFile?: string;
	egressUrl?: string;
	egressPool?: EgressPoolManager;
	workerId?: string;
	gateUrl?: string;
	preflightExpectedStatuses?: readonly number[];
	preflightFetchFn?: PreflightFetchLike;
	skipPreflight?: boolean;
}

/** 执行单条自动意图：可选门控探活 + 出口代理注入 + 跑脚本 → 解析，无产出时附带失败分类信息。入账由调用方在锁内完成。 */
export async function runAutoIntent(
	rule: AutoRule,
	st: NuwaState,
	exec: ExecLike,
	cwd: string,
	signal?: AbortSignal,
	opts?: RunAutoIntentOptions,
): Promise<AutoRunResult> {
	if (signal?.aborted) {
		return {
			ok: false,
			error: "任务已取消 (aborted)",
			errorKind: "network",
			retryAfterMs: 60_000,
		};
	}

	const pool = opts?.egressPool;
	const explicitEgress =
		opts?.egressUrl !== undefined && String(opts.egressUrl).trim() !== ""
			? opts.egressUrl
			: !pool
				? resolveConfiguredEgressUrl(process.env)
				: undefined;

	let lease: EgressLease | null = null;
	let activeEgressUrl: string | undefined = explicitEgress;
	let lastPreflight: PreflightEgressResult | undefined;

	try {
		// 1. 出口选择与门控基线探活（支持多出口池自动熔断故障转移）
		if (pool && !explicitEgress) {
			const triedIds: string[] = [];
			const maxTries = Math.max(1, pool.size());
			for (let attempt = 0; attempt < maxTries; attempt++) {
				const candidate = pool.acquire({ workerId: opts?.workerId, excludeIds: triedIds });
				if (!candidate) {
					break;
				}
				triedIds.push(candidate.id);
				if (opts?.gateUrl && !opts.skipPreflight) {
					const pf = await preflightEgressCheck({
						gateUrl: opts.gateUrl,
						egressUrl: candidate.url,
						expectedStatuses: opts.preflightExpectedStatuses,
						exec: opts.preflightFetchFn ? undefined : exec,
						cwd,
						fetchFn: opts.preflightFetchFn,
						signal,
					});
					lastPreflight = pf;
					if (!pf.ok) {
						candidate.release({
							ok: false,
							statusCode: pf.httpStatus,
							ttfbMs: pf.ttfbMs,
							blocked: pf.status === "egress_blocked",
							connectionReset: pf.status === "network_error",
							error: pf.reason,
						});
						continue;
					}
				}
				lease = candidate;
				activeEgressUrl = candidate.url;
				break;
			}

			if (!lease) {
				const isNetOnly = lastPreflight?.status === "network_error";
				return {
					ok: false,
					error: lastPreflight?.reason ?? "出口池无健康可用出口（全部熔断或被边缘拦截）",
					errorKind: isNetOnly ? "network" : "egress_blocked",
					...(isNetOnly ? { retryAfterMs: 60_000 } : {}),
					...(lastPreflight?.waf ? { waf: lastPreflight.waf } : {}),
					...(lastPreflight ? { preflight: lastPreflight } : {}),
				};
			}
		} else if (opts?.gateUrl && !opts.skipPreflight) {
			const pf = await preflightEgressCheck({
				gateUrl: opts.gateUrl,
				egressUrl: activeEgressUrl,
				expectedStatuses: opts.preflightExpectedStatuses,
				exec: opts.preflightFetchFn ? undefined : exec,
				cwd,
				fetchFn: opts.preflightFetchFn,
				signal,
			});
			lastPreflight = pf;
			if (!pf.ok) {
				return {
					ok: false,
					error: pf.reason,
					errorKind: pf.errorKind ?? "egress_blocked",
					...(pf.errorKind === "network" ? { retryAfterMs: 60_000 } : {}),
					...(pf.waf ? { waf: pf.waf } : {}),
					...(activeEgressUrl ? { egressUrl: maskEgressUrl(activeEgressUrl) } : {}),
					preflight: pf,
				};
			}
		}

		// 2. 脚本构建与出口/认证头注入
		const rawScript = rule.script(st);
		const script = activeEgressUrl
			? injectEgressIntoScript(rawScript, activeEgressUrl, opts?.authHeaderFile)
			: opts?.authHeaderFile
				? injectAuthHeaderFileIntoScript(rawScript, opts.authHeaderFile)
				: rawScript;

		const execStart = Date.now();
		const res = await raceWithSignal(
			exec("bash", ["-lc", script], { timeout: rule.timeoutMs, cwd, signal }),
			signal,
		);
		const elapsedMs = Math.max(0, Date.now() - execStart);
		const fact = rule.parse(res, st);
		if (!fact) {
			const cls = classifyAutoFailure(res);
			lease?.release({
				ok: cls.errorKind === "empty",
				ttfbMs: elapsedMs,
				connectionReset: cls.errorKind === "network",
				exitCode: res.code,
				blocked: cls.errorKind === "blocked_by_waf" || cls.errorKind === "egress_blocked",
				error: cls.reason,
			});
			lease = null;
			return {
				ok: false,
				error: `无产出 code=${res.code}${res.killed ? " killed" : ""} [${cls.errorKind}]`,
				errorKind: cls.errorKind,
				...(cls.retryAfterMs !== undefined ? { retryAfterMs: cls.retryAfterMs } : {}),
				...(cls.waf !== undefined ? { waf: cls.waf } : {}),
				...(activeEgressUrl ? { egressUrl: maskEgressUrl(activeEgressUrl) } : {}),
				...(lastPreflight ? { preflight: lastPreflight } : {}),
			};
		}

		const statusNum = fact.meta?.status;
		const usedEgressId = lease?.id;
		const isEdgeWafHit = Boolean(
			fact.meta?.waf && (statusNum === 403 || statusNum === 429 || statusNum === 503),
		);
		lease?.release({
			ok: !isEdgeWafHit,
			...(isEdgeWafHit ? { statusCode: statusNum, blocked: true } : {}),
			ttfbMs: elapsedMs,
		});
		lease = null;

		return {
			ok: true,
			fact,
			...(fact.meta?.waf ? { waf: fact.meta.waf } : {}),
			...(usedEgressId ? { egressId: usedEgressId } : {}),
			...(activeEgressUrl ? { egressUrl: maskEgressUrl(activeEgressUrl) } : {}),
			...(lastPreflight ? { preflight: lastPreflight } : {}),
		};
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		const isNetOrAbort = signal?.aborted || /abort|timed?\s*out|ETIMEDOUT|ECONNREFUSED|ENOTFOUND/i.test(msg);
		lease?.release({
			ok: false,
			connectionReset: isNetOrAbort,
			error: msg,
		});
		lease = null;
		return {
			ok: false,
			error: msg,
			...(isNetOrAbort ? { errorKind: "network" as const, retryAfterMs: 60_000 } : { errorKind: "empty" as const }),
		};
	} finally {
		lease?.release();
	}
}

function isExclusiveRuleKey(canonicalKey: string): boolean {
	return canonicalKey === "recon:ports";
}

/**
 * 受控并发与总预算自动批执行器（Issue #5 / #23 / #36）：
 * - 默认 budgetMs = 90000ms，concurrency = 1（并发 >= 2 时 recon:ports 保持独占运行）
 * - 支持传入 `egressUrl` / `egressPool` / `gateUrl`，多并发 worker 按池内最少负载/轮询分配出口
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

			const intentOpts: RunAutoIntentOptions = {
				workerId: `auto:${id}`,
				...(opts?.authHeaderFile ? { authHeaderFile: opts.authHeaderFile } : {}),
				...(opts?.egressUrl ? { egressUrl: opts.egressUrl } : {}),
				...(opts?.egressPool ? { egressPool: opts.egressPool } : {}),
				...(opts?.gateUrl ? { gateUrl: opts.gateUrl } : {}),
				...(opts?.preflightExpectedStatuses ? { preflightExpectedStatuses: opts.preflightExpectedStatuses } : {}),
				...(opts?.preflightFetchFn ? { preflightFetchFn: opts.preflightFetchFn } : {}),
			};

			const runRes = await runAutoIntent(
				boundedRule,
				latestState,
				exec,
				root,
				batchController.signal,
				intentOpts,
			);

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


// v6.0 自主安全评估闭环（Auto-AuthDiff & Auto-OOB）桥接重导出
export {
	DEFAULT_AUTHDIFF_COOLDOWN_MS,
	DEFAULT_MAX_AUTH_PATHS,
	DEFAULT_MAX_NEW_OOB_CANARIES,
	DEFAULT_OOB_POLL_INTERVAL_MS,
	collectTestableAuthPaths,
	computeAuthDiffSignature,
	planAutonomousOobProbes,
	runAutonomousAuthDiff,
	runAutonomousOobPoll,
	shouldAutoTriggerAuthDiff,
	type AutoAuthDiffTriggerDecision,
	type AutoAuthDiffTriggerOptions,
	type AutonomousAuthDiffResult,
	type AutonomousOobPlanResult,
	type AutonomousOobPollResult,
	type CollectAuthPathsOptions,
	type OobProbePlanItem,
	type OobSurfaceCategory,
	type PlanOobProbesOptions,
	type RunAutonomousAuthDiffOptions,
	type RunOobPollOptions,
} from "./auto-loops";
