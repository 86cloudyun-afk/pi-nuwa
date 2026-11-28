/**
 * 女娲 v8.0.0 Soft-404 基线采样、SHA-256 响应哈希、归一化模板指纹与端点响应分类模块。
 *
 * 约束：纯底层模块，仅依赖 Node 内置 `crypto` 与 `./types` / `./sandbox` 类型，严禁导入 `./nuwa` 或 `./autoexec`。
 */
import { createHash, randomBytes } from "node:crypto";
import type { NuwaState } from "./types";
import type { EgressPoolManager } from "./sandbox";

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

export function clip(text: string, max: number): string {
	const s = String(text ?? "").replace(/\r/g, "").trim();
	return s.length > max ? `${s.slice(0, max)}…` : s;
}

export function headerValue(headers: string, name: string): string {
	const re = new RegExp(`^${name}:\\s*(.+)$`, "im");
	return headers.match(re)?.[1]?.trim() ?? "";
}

export function titleOf(body: string): string {
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

export const WAF_CHALLENGE_RE =
	/\b(?:just a moment|attention required|challenge-platform|cf-turnstile|enable javascript and cookies|captcha|hcaptcha|recaptcha|web application firewall|request blocked|access denied|forbidden by administrative rules|rate limit exceeded|too many requests)\b/i;

export function detectWafName(headers: string, body: string, status?: number): string | undefined {
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

export function extractHttpTech(headers: string, body: string): string[] {
	const combined = `${headers}\n${body}`;
	const found: string[] = [];
	for (const item of TECH_RULES) {
		if (item.re.test(combined)) {
			found.push(item.name);
		}
	}
	return found;
}

export const SOFT404_CHECK_PATHS = ["/__nuwa_404_check_1", "/__nuwa_404_check_2.json"] as const;
export const HTML_SIGNATURE_RE = /<!doctype\s+html|<html[\s>]|<head[\s>]|<body[\s>]|<title[\s>]|<meta\s[^>]*charset/i;
const GIT_HEAD_REF_RE = /^\s*ref:\s*refs\/[A-Za-z0-9._\/-]+(?:\s|$)/;
const GIT_HEAD_SHA_RE = /^\s*[0-9a-f]{40}(?:\s|$)/i;
const ENV_PAIR_TEST_RE =
	/(?:^|\s)(?:export\s+)?([A-Z][A-Z0-9_]{1,63})=([^\s"'`<>]\S*|"[^"\r\n]+(?:"|$)|'[^'\r\n]+(?:'|$))/;
const ENV_PAIR_MASK_RE =
	/(^|\s)((?:export\s+)?[A-Z][A-Z0-9_]{1,63}=)("(?:\\.|[^"])*(?:"|$)|'(?:\\.|[^'])*(?:'|$)|\S+)/g;
const OPENAPI_PATH_RE = /\/(?:openapi|swagger(?:\/[^/]+)*)\.json$/i;
export const STATIC_ASSET_EXT_RE =
	/\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|sass|less|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|pdf|zip|tar|gz|br|wasm)$/i;
export const DIR_HIT_STATUS_SET = new Set([200, 204, 301, 302, 307, 401, 403, 405, 500]);

export function normalizeTitleSig(raw?: string): string {
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

export const EDGE_BLOCK_403_RE =
	/\b(?:attention\s+required!?\s*\|\s*cloudflare|sorry,\s*you\s+have\s+been\s+blocked|just\s+a\s+moment\.\.\.|cf-error-details|cf-turnstile|challenge-platform|cloudflare\s+ray\s+id|enable\s+javascript\s+and\s+cookies\s+to\s+continue|why\s+have\s+i\s+been\s+blocked|access\s+denied\s+you\s+don['’]?t\s+have\s+permission\s+to\s+access\s+"[^"]+"\s+on\s+this\s+server|reference\s*#\d+\.\w+|request\s+blocked\s+by\s+(?:waf|cloudflare|cloudfront|akamai|imperva)|incapsula\s+incident\s+id|datadome)\b/i;

const LOGIN_LOCATION_RE = /\/(?:login|signin|sign-in|auth|oauth|sso|passport)(?:[/?#]|$)/i;

export function readHeaderCaseInsensitive(headers: HeaderBagLike | undefined, name: string): string {
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

export function serializeHeadersForInspection(headers: HeaderBagLike | undefined): string {
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

export function bodyToBufferAndText(body?: string | Buffer | Uint8Array): { buf: Buffer; text: string } {
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

export function looksLikeHtml(text: string): boolean {
	return HTML_SIGNATURE_RE.test(String(text ?? ""));
}

export function isConfirmedGitHead(body: string): boolean {
	const s = String(body ?? "").trim();
	if (!s || looksLikeHtml(s)) return false;
	return GIT_HEAD_REF_RE.test(s) || GIT_HEAD_SHA_RE.test(s);
}

export function isConfirmedEnvContent(body: string): boolean {
	const s = String(body ?? "").trim();
	if (!s || looksLikeHtml(s)) return false;
	return ENV_PAIR_TEST_RE.test(s);
}

/** 对 .env 配置行中的明文密钥值做脱敏掩码（保留键名，隐藏值）。 */
export function maskEnvSecrets(text: string): string {
	return String(text ?? "").replace(ENV_PAIR_MASK_RE, "$1$2***");
}

export function isOpenApiPath(path: string): boolean {
	return OPENAPI_PATH_RE.test(String(path ?? "").trim());
}

export function isConfirmedOpenApiDoc(body: string): boolean {
	const s = String(body ?? "").trim();
	if (!s || looksLikeHtml(s)) return false;
	if (/"(?:openapi|swagger)"\s*:/.test(s)) return true;
	if (/"paths"\s*:\s*\{/.test(s) && /"(?:info|components|definitions|servers|basePath|host)"\s*:/.test(s)) {
		return true;
	}
	return false;
}

/** 生成 Soft-404 随机不存在路径探测脚本片段（依赖 $BASE 与临时文件 $b）。 */
export function buildSoft404BaselineLines(trackWafVar: "waf_429" | "waf_code"): string[] {
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
