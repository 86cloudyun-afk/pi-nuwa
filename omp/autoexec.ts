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
import type { Cfg, NuwaState, Phase, ToolchainCaps } from "./types";
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

import {
	DIR_HIT_STATUS_SET,
	EDGE_BLOCK_403_RE,
	HTML_SIGNATURE_RE,
	SOFT404_CHECK_PATHS,
	STATIC_ASSET_EXT_RE,
	WAF_CHALLENGE_RE,
	bodyToBufferAndText,
	buildSoft404BaselineLines,
	classifyEndpointResponse,
	clip,
	computeBodyHash,
	computeTemplateFingerprint,
	detectSoft404,
	detectWafName,
	extractHttpTech,
	headerValue,
	isConfirmedEnvContent,
	isConfirmedGitHead,
	isConfirmedOpenApiDoc,
	isOpenApiPath,
	isSoft404Hit,
	looksLikeHtml,
	maskEnvSecrets,
	normalizeTitleSig,
	originOf,
	parseSoft404Baseline,
	readHeaderCaseInsensitive,
	sampleSoft404Baseline,
	serializeHeadersForInspection,
	shellQuote,
	titleOf,
	type DetectSoft404Input,
	type EndpointBaseline404,
	type EndpointClassification,
	type EndpointResponseClassification,
	type EndpointResponseInput,
	type ExecLike,
	type ExecLikeResult,
	type HeaderBagLike,
	type PreflightEgressOptions,
	type PreflightEgressResult,
	type PreflightFetchLike,
	type PreflightFetchResponse,
	type Soft404Baseline,
	type Soft404BaselineInput,
	type Soft404Candidate,
	type Soft404DetectionResult,
	type Soft404Sample,
} from "./autoexec-baseline";

export * from "./autoexec-baseline";
export { shellQuote } from "./autoexec-baseline";

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
