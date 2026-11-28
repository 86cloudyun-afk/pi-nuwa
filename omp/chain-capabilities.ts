/**
 * 女娲 v8.0.0 事实能力标签抽取、有界防环攻击链拓扑合成与信念效用排序构建器模块。
 *
 * 约束：零外部第三方依赖，严禁导入 `./nuwa` 或 `./chain-composer`，保持纯单向无环依赖。
 */
import { createHash } from "node:crypto";
import {
	initBeliefGraphFromState,
	resolveBeliefNodeId,
	type BeliefGraph,
	type BeliefObservation,
	type BeliefPropagationResult,
} from "./belief-search";
import type { Soft404Baseline, Soft404BaselineInput } from "./autoexec-baseline";
import type { ResponseSnapshot } from "./evidence";
import type { SessionVault } from "./session-vault";
import {
	REDACTED_MARKER,
	redactTrafficBody,
	redactTrafficUrl,
	TrafficRecorder,
	type TrafficExtractorSpec,
	type TrafficFetchFn,
	type TrafficReplayStep,
} from "./traffic-workbench";
import type { Fact, FactKind, Mode, NuwaState } from "./types";

export type { TrafficReplayStep };
/** 流量工作台可执行步骤别名，供上层编排与编译器直接消费。 */
export type TrafficStep = TrafficReplayStep;

// ==================== 1. 规范能力标签与核心数据结构 ====================

/** 内置规范安全能力枚举列表。 */
export const CAPABILITY_TAGS = [
	"cap:leaked_route",
	"cap:low_priv_token",
	"cap:admin_token",
	"cap:id_enumerable",
	"cap:ticket_or_token_leak",
	"cap:url_sink",
	"cap:admin_export_endpoint",
	"cap:oob_channel",
	"cap:config_disclosure",
	"cap:csrf_or_nonce",
] as const;

export type KnownCapabilityTag = (typeof CAPABILITY_TAGS)[number];

/** 支持内置规范能力枚举及 `cap:<custom>` 领域扩展标签。 */
export type CapabilityTag = KnownCapabilityTag | `cap:${string}`;

/** 攻击链合成深度硬上界（严防组合爆炸与超长幻觉链）。 */
export const MAX_CHAIN_DEPTH = 4 as const;
/** 默认攻击链最小跳数。 */
export const DEFAULT_MIN_CHAIN_DEPTH = 2 as const;
/** 默认攻击链最大跳数。 */
export const DEFAULT_MAX_CHAIN_DEPTH = 4 as const;

/** 允许编译与执行的纯只读安全探测 HTTP 方法集合。 */
export const READONLY_HTTP_METHODS = ["GET", "HEAD", "OPTIONS"] as const;
export type ReadonlyHttpMethod = (typeof READONLY_HTTP_METHODS)[number];

const READONLY_METHOD_SET = new Set<string>(READONLY_HTTP_METHODS);

export interface VariableExtractionHint {
	/** 规范化模板变量名（如 exportTicket、antiReplayToken、leakedRoute） */
	name: string;
	/** 首选提取来源 */
	source: "json" | "header" | "cookie" | "regex";
	/** JSON 点分路径（如 data.exportTicket 或 exportTicket） */
	jsonPath?: string;
	/** 响应头名（小写，如 x-export-ticket） */
	headerName?: string;
	/** Cookie 键名 */
	cookieName?: string;
	/** 正则提取模式（第 1 捕获组优先） */
	regex?: string;
	/** 该变量是否属于敏感凭据/票据（true 时全程强制 [REDACTED] 脱敏） */
	sensitive: boolean;
}

export interface ParameterBindingHint {
	/** 引用的上游变量名（对应 `{{varName}}`） */
	varName: string;
	/** 参数注入位置 */
	location: "query" | "header" | "path";
	/** 查询参数名或请求头名（如 ticket、X-Export-Ticket、callback） */
	paramName: string;
}

export interface FactCapabilities {
	factId: string;
	kind: FactKind;
	/** 非 blocked 且非 rejected 的事实才允许参与攻击链合成 */
	eligible: boolean;
	/** 该事实可提供的后置能力标签集合 */
	provides: CapabilityTag[];
	/** 进一步利用该事实所需的前置能力标签集合 */
	requires: CapabilityTag[];
	/** 提取到的关联 HTTP 端点路径列表 */
	endpoints: string[];
	/** 当前事实自身首选探测入口路径（如 /assets/app.js.map 或 /api/internal/export） */
	primaryEndpoint?: string;
	/** 事实内容中泄露给下游的内部路由线索（如从 SourceMap/配置中发现的路由） */
	leakedRoutes: string[];
	/** 只读合规探测方法 */
	method: ReadonlyHttpMethod;
	/** 可从该步响应中提取供下游消费的动态变量线索 */
	variableHints: VariableExtractionHint[];
	/** 该步请求消费上游变量的绑定线索 */
	templateParams: ParameterBindingHint[];
	/** 关联的会话角色名提示（仅角色标识，严禁含明文凭据） */
	authRoleHint?: string;
	/** 该事实自身文本是否已声明持有低权/认证上下文 */
	hasInlineLowPrivContext?: boolean;
	/** 作为攻击链终局目标时的基础影响分 [0, 100] */
	impactScore: number;
}

export interface AttackChainStep {
	stepIndex: number;
	factId: string;
	factKind: FactKind;
	title: string;
	endpoint?: string;
	method: ReadonlyHttpMethod;
	provides: CapabilityTag[];
	requires: CapabilityTag[];
	/** 本步为后续步骤贡献（或终局达成）的核心能力集合 */
	activeCapabilities: CapabilityTag[];
	extractVariables: VariableExtractionHint[];
	templateParams: ParameterBindingHint[];
	/** 来自 belief-search 的节点 Beta 后验均值 (0, 1) */
	beliefPosterior: number;
	/** 来自 belief-search 的节点预期信息增益 VoI >= 0 */
	expectedInfoGain: number;
	/** 单步执行成本估算 */
	stepCost: number;
	/** 可选认证角色名提示（不含任何敏感值） */
	authRole?: string;
}

export interface AttackChainSpec {
	id: string;
	title: string;
	rationale: string;
	steps: AttackChainStep[];
	depth: number;
	/** 链上按序排列的主干事实 ID 列表 */
	factIds: string[];
	/** 提供环境基础能力（如无端点的静态 cred 事实）的辅助事实 ID 列表 */
	supportingFactIds: string[];
	/** 终局目标达成的能力标签 */
	terminalCapabilities: CapabilityTag[];
	/** 多跳串联后验信念分 (0, 1) */
	chainBelief: number;
	/** 链条综合预期信息增益 VoI >= 0 */
	expectedInfoGain: number;
	/** 终局安全影响分 [0, 100] */
	terminalImpact: number;
	/** 综合跳数与预估 Token 开销的总成本 */
	estimatedCost: number;
	/** 确定性综合效用分（降序排序主键） */
	utilityScore: number;
	/** 用于同链语义去重的规范签名 */
	semanticSignature: string;
}

export interface SynthesizeChainsOptions {
	/** 最小链跳数（默认 2，钳制在 [2, maxDepth]，当 maxDepth=1 时为 1） */
	minDepth?: number;
	/** 最大链跳数（默认 4，硬上限严格 <= MAX_CHAIN_DEPTH = 4） */
	maxDepth?: number;
	/** 最大返回链条数（默认 12） */
	maxChains?: number;
	/** 复用已有信念图（未传时自动基于 state 初始化） */
	beliefGraph?: BeliefGraph;
	/** 是否包含信念图中已标记 pruned 的节点（默认 false 自动跳过） */
	includePruned?: boolean;
	/** 额外显式声明当前环境已具备的基础能力集合 */
	availableCapabilities?: readonly CapabilityTag[];
	/** 每跳预估附加 Token 折算成本系数（默认 1.2） */
	tokenCostPerHop?: number;
}

export interface CompileChainOptions {
	/** 受控本机/授权 OOB 回调接收 URL（如 http://127.0.0.1:<port>/oob/hit） */
	oobCallbackUrl?: string;
	/** 全局默认请求头（仅非敏感头或占位模板，敏感认证头建议通过执行期注入） */
	defaultHeaders?: Record<string, string>;
	/** 按步骤角色或全局注入的认证请求头（可选） */
	authHeaders?: Record<string, string>;
	roleHeaders?: Record<string, Record<string, string>>;
	/** 会话保险箱或工作区根目录（用于按 authRole 解析认证头） */
	vault?: SessionVault;
	root?: string;
	/** 单步超时毫秒数（默认 8000） */
	timeoutMs?: number;
	/** 是否允许在下游已有静态路径时仍优先使用上游提取的动态路由（默认 false） */
	preferDynamicRoute?: boolean;
}

export interface ChainStepTrace {
	stepIndex: number;
	stepId: string;
	factId: string;
	method: ReadonlyHttpMethod;
	redactedUrl: string;
	status: number;
	ok: boolean;
	blockedByScope: boolean;
	isSoft404: boolean;
	durationMs: number;
	extractedVarNames: string[];
	redactedExtracted: Record<string, string>;
	redactedResponseSnippet: string;
	recordedEntryId?: string;
	failureDetail?: string;
}

export interface VerifyVulnRecommendation {
	key: `verify-vuln:${string}`;
	factId: string;
	phase: "vuln";
	title: string;
	detail: string;
	priority: number;
	from: string[];
}

export type ChainFailureKind =
	| "scope_blocked"
	| "auth_401"
	| "auth_403"
	| "http_404"
	| "http_error"
	| "soft_404"
	| "missing_extracted_var"
	| "false_positive_filtered"
	| "oob_not_triggered"
	| "timeout"
	| "network_error";

export interface ExecuteChainVerificationOptions {
	/** 靶机基础 URL（未提供时尝试从 state.project.url 或步骤完整 URL 推断） */
	baseUrl?: string;
	state?: NuwaState;
	beliefGraph?: BeliefGraph;
	/** 若为 true 且提供了 beliefGraph + state，自动将验证观测传播至信念图（衰减第 k 跳及下游分支或提权） */
	applyBeliefUpdate?: boolean;
	mode?: Mode | string;
	fetchFn?: TrafficFetchFn;
	recorder?: TrafficRecorder;
	vault?: SessionVault;
	initialVars?: Record<string, string>;
	initialCookies?: Record<string, string>;
	authHeaders?: Record<string, string>;
	roleHeaders?: Record<string, Record<string, string>>;
	/** 受控 OOB 回调接收 URL（如 http://127.0.0.1:<port>/callback） */
	oobCallbackUrl?: string;
	/** 可选受控 OOB 状态轮询 URL（必须满足本机 127.0.0.1 或授权 Scope/oobDomains） */
	oobPollUrl?: string;
	/** 可选自定义本机 OOB 回调命中校验钩子 */
	verifyOobHit?: (ctx: {
		chain: AttackChainSpec;
		variables: Record<string, string>;
	}) => Promise<{ hit: boolean; detail?: string }> | { hit: boolean; detail?: string };
	soft404Baseline?: Soft404BaselineInput | Soft404Baseline | null;
	negativeBaseline?: ResponseSnapshot | ResponseSnapshot[];
	/** 是否在未传入 soft404Baseline 时对目标 Origin 自动采样随机 404 基线（默认 true） */
	autoSampleSoft404?: boolean;
	timeoutMs?: number;
	candidateFactId?: string;
	extraSecrets?: string[];
	/** 是否将脱敏后的真实多跳验证摘要同步记入 exec-ledger（默认 true） */
	recordLedger?: boolean;
	signal?: AbortSignal;
}

export interface ChainExecutionResult {
	chainId: string;
	/** 全链是否成功打穿终局目标并通过反误报与 OOB 核验 */
	verified: boolean;
	/** 若在第 k 跳阻断或证伪，精确返回 0-based 步骤索引 */
	brokenAtStep?: number;
	/** 阻断步骤对应的原始 Fact ID */
	brokenFactId?: string;
	/** 结构化阻断原因类别 */
	failureKind?: ChainFailureKind;
	/** 完全脱敏后的验证结论或阻断原因说明 */
	reason: string;
	/** 可直接喂给 belief-search.ts 更新第 k 跳及下游分支后验信念的观测对象 */
	beliefObservation: BeliefObservation;
	/** 若启用了 applyBeliefUpdate，返回信念传播与剪枝详情 */
	beliefPropagation?: BeliefPropagationResult;
	/** 逐跳完全脱敏的执行证据链 */
	stepTraces: ChainStepTrace[];
	/** 提取到的跨跳变量脱敏快照（敏感票据/凭据值一律为 [REDACTED]） */
	redactedVariables: Record<string, string>;
	/** 若攻击链涉及 OOB 通道，标记是否真实捕获到回调命中 */
	oobConfirmed?: boolean;
	/** 全链打穿时生成的待双盲复验 candidate 复合漏洞 Fact（阻断时恒为 undefined） */
	candidateFact?: Fact;
	/** 全链打穿时生成的 verify-vuln:<fid> 双盲复验建议（阻断时恒为 undefined） */
	verifyRecommendation?: VerifyVulnRecommendation;
	/** 便捷双盲复验键（如 verify-vuln:f_chain_xxx） */
	verifySuggestionKey?: `verify-vuln:${string}`;
}

// ==================== 2. 内部正则与纯工具函数 ====================

const SOURCEMAP_OR_FE_LEAK_RE =
	/(?:\.js\.map\b|sourcemap|sourceMappingURL|webpack|vite|bundle|chunk|manifest|前端.*泄露|源码映射|泄露.*(?:路由|端点|接口)|隐藏.*(?:路由|接口|端点))/i;

const CONFIG_DISCLOSURE_RE =
	/(?:配置接口|config(?:uration)?|settings|env\b|public[-_/]?config|webhook[-_/]?config|泄露.*(?:回调|模板|配置)|callback\s*template|endpoint\s*template)/i;

const ADMIN_CRED_RE =
	/(?:\badmin(?:istrator)?\b|\broot\b|\bsuperuser\b|管理员|超级用户|高权限|特权凭据)/i;

const LOW_PRIV_NEGATION_RE =
	/(?:非管理员|普通(?:用户|员工|账号|角色|低权)|低权(?:限|凭据|账号|角色|令牌|token)?|\blow[-_\s]?priv(?:ilege)?\b|\brole\s*[:=]\s*(?:user|member|guest|viewer|staff|employee|low)\b)/i;

const CRED_OR_TOKEN_MENTION_RE =
	/(?:\bcred\b|凭据|令牌|\btoken\b|\bcookie\b|\bbearer\b|\bjwt\b|\bsession\b|登录态|认证头|会话)/i;

const BOLA_IDOR_ENUM_RE =
	/(?:\bidor\b|\bbola\b|\bbfla\b|越权|水平权限|垂直权限|审批单|订单|对象.*枚举|可枚举|\benumerable\b)/i;

const TICKET_OR_ONCE_TOKEN_RE =
	/(?:\bexport[_-]?ticket\b|\banti[_-]?replay[_-]?token\b|\bdownload[_-]?ticket\b|\bonce[_-]?token\b|\btemp[_-]?token\b|\breset[_-]?token\b|\binvite[_-]?token\b|\bapproval[_-]?ticket\b|一次性.*(?:token|令牌|票据)|导出票据|防重放(?:令牌|token)|读取.*ticket|泄露.*(?:ticket|token|令牌|票据))/i;

const CSRF_OR_NONCE_RE =
	/(?:\bcsrf[_-]?token\b|\bxsrf[_-]?token\b|\banti[_-]?replay[_-]?token\b|\bnonce\b|防重放)/i;

const ADMIN_EXPORT_ENDPOINT_RE =
	/(?:\/export\b|\/dump\b|\/backup\b|\/download\b|导出接口|内部导出|数据导出|敏感业务数据|批量导出|\badmin[-_/]?export\b)/i;

const URL_SINK_RE =
	/(?:\bwebhook\b|\bcallback(?:[_-]?(?:url|endpoint|uri|target))?\b|\bssrf\b|\burl[_-]?sink\b|回调(?:端点|接口|地址|模板|触发)|出向请求|远程抓取)/i;

const OOB_CHANNEL_RE =
	/(?:\boob\b|带外|回调接收器|interactsh|dnslog|127\.0\.0\.1.*回调|回调.*实锤|oob[-_]?callback)/i;

const INTERNAL_OR_HIDDEN_ROUTE_RE =
	/(?:\/internal\/|\/admin\/|\/private\/|\/debug\/|\/approvals?\b|内部(?:审批|导出|路由|接口|端点)|隐藏(?:路由|接口|端点)|未公开(?:路由|接口)|泄露.*(?:路由|端点|模板))/i;

export const SENSITIVE_VAR_NAME_RE =
	/(?:ticket|token|secret|password|passwd|pwd|key|auth|jwt|sid|session|cookie|csrf|xsrf|nonce|cred|bearer|sig|signature)/i;

const KNOWN_TOKEN_IDENTIFIER_RE =
	/\b([a-zA-Z][a-zA-Z0-9_]*(?:Ticket|Token|Nonce|Secret|Key)|export_ticket|anti_replay_token|download_ticket|csrf_token|xsrf_token|temp_token|once_token)\b/g;

const NON_HTTP_FS_PATH_PREFIX_RE =
	/^\/(?:tmp|etc|usr|var|opt|root|home|proc|sys|dev|bin|sbin|lib|lib64|private|Users| swat)(?:\/|$)/i;

export function sha1Short(text: string, len = 10): string {
	return createHash("sha1").update(text).digest("hex").slice(0, len);
}

export function clamp(val: number, min: number, max: number): number {
	if (Number.isNaN(val)) return min;
	if (val === Number.POSITIVE_INFINITY) return max;
	if (val === Number.NEGATIVE_INFINITY) return min;
	return Math.max(min, Math.min(max, val));
}

export function oneLine(text: string | undefined, max = 140): string {
	return String(text ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

export function uniqTags(tags: Iterable<CapabilityTag>): CapabilityTag[] {
	const seen = new Set<CapabilityTag>();
	const out: CapabilityTag[] = [];
	for (const t of tags) {
		if (!t || !t.startsWith("cap:") || seen.has(t)) continue;
		seen.add(t);
		out.push(t);
	}
	return out;
}

export function uniqStrings(items: Iterable<string>): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const raw of items) {
		const s = String(raw ?? "").trim();
		if (!s || seen.has(s)) continue;
		seen.add(s);
		out.push(s);
	}
	return out;
}

export function camelToKebabHeader(varName: string): string {
	const kebab = varName
		.replace(/([a-z0-9])([A-Z])/g, "$1-$2")
		.replace(/[_\s]+/g, "-")
		.toLowerCase()
		.replace(/^-+|-+$/g, "");
	return kebab.startsWith("x-") ? kebab : `x-${kebab}`;
}

export function escapeRegexLiteral(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function normalizeReadonlyMethod(raw: unknown): ReadonlyHttpMethod {
	const upper = String(raw ?? "GET").trim().toUpperCase();
	if (READONLY_METHOD_SET.has(upper)) {
		return upper as ReadonlyHttpMethod;
	}
	return "GET";
}

const SENSITIVE_QUERY_PARAM_KEY_RE =
	/^(?:access_token|refresh_token|id_token|auth_token|api_key|apikey|api_token|csrf_token|xsrf_token|anti_replay_token|antiReplayToken|export_ticket|exportTicket|download_ticket|downloadTicket|token|secret|client_secret|password|passwd|pwd|auth|jwt|session|session_id|sid|csrf|xsrf|sig|signature|ticket|private_token|key|nonce)$/i;

export const COOKIE_ATTR_SKIP_SET = new Set([
	"path",
	"domain",
	"expires",
	"max-age",
	"samesite",
	"secure",
	"httponly",
	"priority",
	"partitioned",
	"version",
]);

export const NON_SECRET_TRIVIAL_VALUES = new Set([
	"1",
	"0",
	"true",
	"false",
	"null",
	"none",
	"lax",
	"strict",
	"dark",
	"light",
	"zh",
	"en",
	"cn",
	"us",
]);

function sanitizeQueryParametersInPath(pathAndQuery: string): string {
	const qIdx = pathAndQuery.indexOf("?");
	if (qIdx < 0) return pathAndQuery;
	const pathname = pathAndQuery.slice(0, qIdx);
	const rawQuery = pathAndQuery.slice(qIdx + 1);
	if (!rawQuery) return pathname;

	// 逐段处理查询参数：保留 {{var}} / {var} 模板占位符，将静态敏感参数值强制脱敏为 [REDACTED]
	const sanitizedParts = rawQuery.split("&").map((seg) => {
		if (!seg) return seg;
		const eq = seg.indexOf("=");
		if (eq <= 0) return seg;
		const rawKey = seg.slice(0, eq);
		const rawVal = seg.slice(eq + 1);
		let decodedKey = rawKey;
		try {
			decodedKey = decodeURIComponent(rawKey);
		} catch {
			/* ignore */
		}
		const trimmedVal = rawVal.trim();
		// 保留合法模板占位符（如 {{exportTicket}} 或 %7B%7BexportTicket%7D%7D）
		if (
			trimmedVal === "" ||
			trimmedVal === REDACTED_MARKER ||
			/^(?:\{\{[a-zA-Z0-9_.-]+\}\}|\{[a-zA-Z0-9_.-]+\}|%7B%7B[a-zA-Z0-9_.-]+%7D%7D)$/i.test(trimmedVal)
		) {
			return seg;
		}
		if (
			SENSITIVE_QUERY_PARAM_KEY_RE.test(decodedKey) ||
			SENSITIVE_VAR_NAME_RE.test(decodedKey) ||
			/^eyJ[A-Za-z0-9_-]{8,}\./.test(trimmedVal)
		) {
			return `${rawKey}=${REDACTED_MARKER}`;
		}
		return seg;
	});
	return `${pathname}?${sanitizedParts.join("&")}`;
}

export function sanitizeEndpointLiteral(raw: string): string {
	const trimmed = String(raw ?? "").trim();
	if (!trimmed) return "";
	if (/^https?:\/\//i.test(trimmed)) {
		try {
			const u = new URL(trimmed);
			const hadUser = Boolean(u.username || u.password);
			u.username = "";
			u.password = "";
			const cleanPathQuery = sanitizeQueryParametersInPath(`${u.pathname || "/"}${u.search || ""}`);
			const hostPart = u.host;
			const userPrefix = hadUser ? `${REDACTED_MARKER}:${REDACTED_MARKER}@` : "";
			return `${u.protocol}//${userPrefix}${hostPart}${cleanPathQuery}`;
		} catch {
			return redactTrafficUrl(trimmed);
		}
	}
	return sanitizeQueryParametersInPath(trimmed);
}

export function stripQueryFromEndpoint(endpoint: string | undefined): string | undefined {
	if (!endpoint) return undefined;
	const sanitized = sanitizeEndpointLiteral(endpoint);
	const qIdx = sanitized.indexOf("?");
	return qIdx >= 0 ? sanitized.slice(0, qIdx) : sanitized;
}

function cleanRouteCandidate(raw: string): string | null {
	let s = String(raw ?? "").trim();
	if (!s) return null;
	s = s.replace(/^(?:path|endpoint|route):/i, "").trim();
	s = s.replace(/['"`),;:\]>]+$/g, "");
	if (/^https?:\/\//i.test(s)) {
		try {
			const u = new URL(s);
			s = `${u.pathname || "/"}${u.search || ""}`;
		} catch {
			return null;
		}
	}
	if (!s.startsWith("/") || s.startsWith("//")) return null;
	if (s === "/") return null;
	if (NON_HTTP_FS_PATH_PREFIX_RE.test(s)) return null;
	if (/^\/(?:1\.1|1\.0|2\.0|2)\b/.test(s)) return null;
	if (s.length > 240) return null;
	return sanitizeQueryParametersInPath(s);
}

function extractEndpointsFromFact(fact: Fact, blob: string): {
	endpoints: string[];
	commandEndpoint?: string;
	targetEndpoint?: string;
} {
	const list: string[] = [];
	let targetEndpoint: string | undefined;
	let commandEndpoint: string | undefined;

	if (fact.targetKey) {
		const tk = cleanRouteCandidate(fact.targetKey);
		if (tk) {
			targetEndpoint = tk;
			list.push(tk);
		}
	}

	if (fact.command) {
		for (const m of fact.command.matchAll(/\bhttps?:\/\/[^\s'"`<>|;&)]+/gi)) {
			const p = cleanRouteCandidate(m[0]);
			if (p) {
				if (!commandEndpoint) commandEndpoint = p;
				list.push(p);
			}
		}
		for (const m of fact.command.matchAll(/(?:^|[\s'"`])(\/[A-Za-z0-9_./:?&={}-]{2,180})/g)) {
			const p = cleanRouteCandidate(m[1] ?? "");
			if (p) {
				if (!commandEndpoint) commandEndpoint = p;
				list.push(p);
			}
		}
	}

	for (const p of fact.meta?.paths ?? []) {
		const clean = cleanRouteCandidate(p);
		if (clean) list.push(clean);
	}
	for (const r of fact.meta?.routes ?? []) {
		const clean = cleanRouteCandidate(r);
		if (clean) list.push(clean);
	}
	for (const b of fact.meta?.bundles ?? []) {
		const clean = cleanRouteCandidate(b);
		if (clean) list.push(clean);
	}

	for (const m of blob.matchAll(/\bhttps?:\/\/[^\s'"`<>|;&)]+/gi)) {
		const p = cleanRouteCandidate(m[0]);
		if (p) list.push(p);
	}
	for (const m of blob.matchAll(/(?:^|[\s'"`(=:])(\/[A-Za-z0-9][A-Za-z0-9_./:?&={}-]{1,180})/gm)) {
		const p = cleanRouteCandidate(m[1] ?? "");
		if (p) list.push(p);
	}

	return {
		endpoints: uniqStrings(list),
		commandEndpoint,
		targetEndpoint,
	};
}

export function findJsonFieldPaths(
	obj: unknown,
	predicate: (key: string, val: unknown) => boolean,
	prefix = "",
	depth = 0,
): Array<{ key: string; path: string; val: unknown }> {
	if (depth > 8 || obj === null || obj === undefined) return [];
	const hits: Array<{ key: string; path: string; val: unknown }> = [];
	if (Array.isArray(obj)) {
		for (let i = 0; i < Math.min(obj.length, 5); i++) {
			const sub = prefix ? `${prefix}.${i}` : String(i);
			hits.push(...findJsonFieldPaths(obj[i], predicate, sub, depth + 1));
		}
		return hits;
	}
	if (typeof obj === "object") {
		for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
			const curPath = prefix ? `${prefix}.${k}` : k;
			if (predicate(k, v)) {
				hits.push({ key: k, path: curPath, val: v });
			}
			if (v && typeof v === "object") {
				hits.push(...findJsonFieldPaths(v, predicate, curPath, depth + 1));
			}
		}
	}
	return hits;
}

export function tryParseJsonFromText(text: string | undefined): unknown {
	const raw = String(text ?? "").trim();
	if (!raw) return undefined;
	if ((raw.startsWith("{") && raw.endsWith("}")) || (raw.startsWith("[") && raw.endsWith("]"))) {
		try {
			return JSON.parse(raw);
		} catch {
			/* 继续尝试提取内嵌 JSON 块 */
		}
	}
	const braceStart = raw.indexOf("{");
	const braceEnd = raw.lastIndexOf("}");
	if (braceStart >= 0 && braceEnd > braceStart) {
		try {
			return JSON.parse(raw.slice(braceStart, braceEnd + 1));
		} catch {
			return undefined;
		}
	}
	return undefined;
}

function isStaticOrEntryAssetPath(p: string): boolean {
	return /(?:\.js\.map\b|\.js\b|\/assets\/|\/static\/|\/public\/|\/config\b|\/manifest\b|\/fe-config\b)/i.test(p);
}

function inferRoleFromBlob(fact: Fact, blob: string): string | undefined {
	if (fact.agentResult && typeof fact.agentResult.authRole === "string" && fact.agentResult.authRole.trim()) {
		return fact.agentResult.authRole.trim().toLowerCase();
	}
	const roleMatch = /\b(?:authRole|role)\s*[:=]\s*['"]?([a-z0-9][a-z0-9._-]{0,31})['"]?/i.exec(blob);
	if (roleMatch?.[1]) {
		return roleMatch[1].toLowerCase();
	}
	if (LOW_PRIV_NEGATION_RE.test(blob)) {
		return "low";
	}
	if (fact.kind === "cred" && ADMIN_CRED_RE.test(blob)) {
		return "admin";
	}
	return undefined;
}

// ==================== 3. 事实能力与变量线索提取 ====================

/**
 * 确定性从单条 `Fact` 提取 `provides`（提供的能力与潜在提取变量线索）、`requires`（前置所需能力）
 * 及关联的只读端点与参数模板元数据。
 * 对于 `kind === "blocked"` 或 `verifyStage === "rejected"` 的事实严格返回空能力集且 `eligible: false`。
 */
export function extractFactCapabilities(fact: Fact): FactCapabilities {
	if (!fact || fact.kind === "blocked" || fact.verifyStage === "rejected") {
		return {
			factId: fact?.id ?? "",
			kind: fact?.kind ?? "note",
			eligible: false,
			provides: [],
			requires: [],
			endpoints: [],
			leakedRoutes: [],
			method: "GET",
			variableHints: [],
			templateParams: [],
			impactScore: 0,
		};
	}

	const blob = [
		fact.title ?? "",
		fact.detail ?? "",
		fact.output ?? "",
		fact.command ?? "",
		fact.key ?? "",
		fact.targetKey ?? "",
		...(fact.meta?.paths ?? []),
		...(fact.meta?.routes ?? []),
		...(fact.meta?.bundles ?? []),
	].join("\n");

	// 注意：推断能力特征时主要依据该事实自身的标题/详情/元数据（避免 command 中的请求头误污染 provides）
	const semanticText = [
		fact.title ?? "",
		fact.detail ?? "",
		fact.output ?? "",
		fact.key ?? "",
	].join("\n");

	const provides: CapabilityTag[] = [];
	const requires: CapabilityTag[] = [];
	const variableHints: VariableExtractionHint[] = [];
	const templateParams: ParameterBindingHint[] = [];

	const addVarHint = (hint: VariableExtractionHint) => {
		if (!hint.name || variableHints.some((v) => v.name === hint.name)) return;
		variableHints.push(hint);
	};

	const addParamBinding = (binding: ParameterBindingHint) => {
		if (
			!binding.varName ||
			templateParams.some(
				(p) =>
					p.varName === binding.varName &&
					p.location === binding.location &&
					p.paramName === binding.paramName,
			)
		) {
			return;
		}
		templateParams.push(binding);
	};

	// 1. 解析可选显式 agentResult.capabilities 标注
	const rawExplicit =
		(fact.agentResult?.chainCapabilities as Record<string, unknown> | undefined) ??
		(fact.agentResult?.capabilities as Record<string, unknown> | undefined);
	let explicitEndpoint: string | undefined;
	let explicitMethod: ReadonlyHttpMethod | undefined;

	let hasExplicitProvides = false;
	let hasExplicitRequires = false;

	if (rawExplicit && typeof rawExplicit === "object") {
		if (Array.isArray(rawExplicit.provides)) {
			hasExplicitProvides = true;
			for (const p of rawExplicit.provides) {
				const s = String(p ?? "").trim();
				if (s.startsWith("cap:")) provides.push(s as CapabilityTag);
			}
		}
		if (Array.isArray(rawExplicit.requires)) {
			hasExplicitRequires = true;
			for (const r of rawExplicit.requires) {
				const s = String(r ?? "").trim();
				if (s.startsWith("cap:")) requires.push(s as CapabilityTag);
			}
		}
		if (typeof rawExplicit.endpoint === "string") {
			const rawEpStr = rawExplicit.endpoint.trim();
			if (/^https?:\/\//i.test(rawEpStr)) {
				explicitEndpoint = sanitizeEndpointLiteral(rawEpStr);
			} else {
				const cleanEp = cleanRouteCandidate(rawEpStr);
				if (cleanEp) explicitEndpoint = cleanEp;
			}
		}
		if (typeof rawExplicit.method === "string") {
			explicitMethod = normalizeReadonlyMethod(rawExplicit.method);
		}
	}

	// 2. 提取端点与区分入口端点 vs 泄露路由
	const { endpoints, commandEndpoint, targetEndpoint } = extractEndpointsFromFact(fact, blob);
	if (explicitEndpoint && !endpoints.includes(explicitEndpoint)) {
		endpoints.unshift(explicitEndpoint);
	}

	const titleText = String(fact.title ?? "").trim();
	// 若标题明确属于下游越权访问、内部导出或触发 OOB 回调动作（且非 SourceMap/配置泄露源），避免因详情引用“泄露的路由/端点”而误判为泄露源
	const isDownstreamActionTitle =
		!/\.js\.map\b|sourcemap|sourceMappingURL|配置接口|前端.*泄露|源码映射/i.test(titleText) &&
		(OOB_CHANNEL_RE.test(titleText) ||
			ADMIN_EXPORT_ENDPOINT_RE.test(titleText) ||
			BOLA_IDOR_ENUM_RE.test(titleText) ||
			/^(?:触发|携带|使用|凭|调用|尝试)/.test(titleText));

	const isSourceMapOrRouteLeak =
		!isDownstreamActionTitle &&
		(SOURCEMAP_OR_FE_LEAK_RE.test(semanticText) ||
			(fact.meta?.routes?.length ?? 0) > 0 ||
			(fact.meta?.bundles?.length ?? 0) > 0);
	const isConfigLeak = !isDownstreamActionTitle && CONFIG_DISCLOSURE_RE.test(semanticText);

	let primaryEndpoint: string | undefined = explicitEndpoint ?? targetEndpoint ?? commandEndpoint;
	const leakedRoutes: string[] = [];

	if (isSourceMapOrRouteLeak || isConfigLeak) {
		const entryCand = endpoints.find((ep) => isStaticOrEntryAssetPath(ep));
		if (!primaryEndpoint) {
			primaryEndpoint = entryCand ?? endpoints[0];
		} else if (
			!explicitEndpoint &&
			!targetEndpoint &&
			entryCand &&
			primaryEndpoint !== entryCand &&
			INTERNAL_OR_HIDDEN_ROUTE_RE.test(primaryEndpoint)
		) {
			primaryEndpoint = entryCand;
		}
		for (const ep of endpoints) {
			if (ep !== primaryEndpoint && !isStaticOrEntryAssetPath(ep)) {
				leakedRoutes.push(ep);
			}
		}
	} else if (!primaryEndpoint && endpoints.length > 0) {
		primaryEndpoint = endpoints[0];
	}

	// 3. 启发式能力识别（provides & requires）
	const isLowPrivMention = LOW_PRIV_NEGATION_RE.test(semanticText);
	const isAdminMention = !isLowPrivMention && ADMIN_CRED_RE.test(semanticText);
	const isTicketLeak = TICKET_OR_ONCE_TOKEN_RE.test(semanticText);
	const isCsrfOrNonce = CSRF_OR_NONCE_RE.test(semanticText);
	const isExportEndpoint = ADMIN_EXPORT_ENDPOINT_RE.test(semanticText);
	const isUrlSink = URL_SINK_RE.test(semanticText);
	const isOobChannel = OOB_CHANNEL_RE.test(semanticText);
	const isBolaOrEnum =
		BOLA_IDOR_ENUM_RE.test(semanticText) ||
		Boolean(primaryEndpoint && /\/\d+(?:\/|$|\?)/.test(primaryEndpoint));

	// 3a. 路由泄露与配置泄露
	if (isSourceMapOrRouteLeak) {
		provides.push("cap:leaked_route");
	}
	if (isConfigLeak) {
		provides.push("cap:config_disclosure");
		if (/路由|端点|模板|endpoint|route|path|callback|webhook|url/i.test(semanticText) || leakedRoutes.length > 0) {
			provides.push("cap:leaked_route");
		}
	}

	// 3b. 凭据事实 vs 消费凭据的业务接口
	if (fact.kind === "cred") {
		if (isAdminMention) {
			provides.push("cap:admin_token");
		} else {
			provides.push("cap:low_priv_token");
		}
	}

	// 3c. 对象枚举与低权越权读取票据（如普通低权凭据越权读取审批单中的 exportTicket）
	if (isBolaOrEnum && !isExportEndpoint) {
		provides.push("cap:id_enumerable");
	}

	// 区分“产出票据/防重放令牌的中间跳”与“凭票据调终局导出/触发 OOB 的终局跳”
	const producesTicketInTitle =
		/(?:越权读取|提取|签发|生成|泄露|返回|产出|获取).*(?:export[_-]?ticket|anti[_-]?replay[_-]?token|ticket|token|票据|令牌|一次性)/i.test(
			titleText,
		);
	const consumesTicketOnly =
		!producesTicketInTitle &&
		(isExportEndpoint ||
			(isOobChannel && isDownstreamActionTitle) ||
			/(?:凭|携带|使用|传入|参数|require|with|using)[^。\n]{0,24}(?:ticket|token|票据|令牌)|[?&](?:ticket|exportTicket|token|antiReplayToken)=/i.test(
				semanticText,
			));

	if ((isTicketLeak || isCsrfOrNonce) && !consumesTicketOnly) {
		provides.push("cap:ticket_or_token_leak");
		if (isCsrfOrNonce) {
			provides.push("cap:csrf_or_nonce");
		}
	}

	// 3d. 终局内部导出接口
	if (isExportEndpoint && !provides.includes("cap:ticket_or_token_leak")) {
		if (!hasExplicitProvides) {
			provides.push("cap:admin_export_endpoint");
		}
		if (!hasExplicitRequires) {
			if (
				isTicketLeak ||
				/\bticket\b|\bexportTicket\b|票据|一次性/i.test(semanticText) ||
				Boolean(primaryEndpoint && /ticket/i.test(primaryEndpoint))
			) {
				requires.push("cap:ticket_or_token_leak");
			} else {
				requires.push("cap:admin_token");
			}
		}
	}

	// 3e. URL Sink 与 OOB 通道验证
	if (!hasExplicitProvides) {
		if (isUrlSink && !isConfigLeak) {
			provides.push("cap:url_sink");
		}
		if (isOobChannel) {
			provides.push("cap:oob_channel");
			if (!provides.includes("cap:url_sink") && !isConfigLeak) {
				provides.push("cap:url_sink");
			}
		}
	}

	// 3f. 推导中间跳与终局跳的 requires 前置条件
	if (
		!hasExplicitRequires &&
		fact.kind !== "cred" &&
		!isSourceMapOrRouteLeak &&
		!isConfigLeak
	) {
		// 若该事实缺少自身静态入口路径，或涉及内部/隐藏路由，需要前置泄露路由能力
		if (
			!isExportEndpoint &&
			(!primaryEndpoint ||
				INTERNAL_OR_HIDDEN_ROUTE_RE.test(semanticText) ||
				Boolean(primaryEndpoint && /^\/(?:api\/)?(?:internal|private|approvals?)\b/i.test(primaryEndpoint)))
		) {
			const isStandaloneTokenIssuer =
				provides.includes("cap:csrf_or_nonce") &&
				Boolean(primaryEndpoint) &&
				!/泄露|隐藏|sourcemap/i.test(semanticText) &&
				!isBolaOrEnum;
			if (!isStandaloneTokenIssuer) {
				requires.push("cap:leaked_route");
			}
		}

		// 若该事实要求低权限凭据执行越权探测
		if (
			(isLowPrivMention || (isBolaOrEnum && CRED_OR_TOKEN_MENTION_RE.test(semanticText))) &&
			!isExportEndpoint
		) {
			requires.push("cap:low_priv_token");
		} else if (isAdminMention && !isExportEndpoint) {
			requires.push("cap:admin_token");
		}

		// 若是触发 OOB 回调 / URL Sink 的终局节点
		if ((isOobChannel || (isUrlSink && !provides.includes("cap:ticket_or_token_leak"))) && !isConfigLeak) {
			if (
				/\banti[_-]?replay\b|\btoken\b|\bticket\b|\bnonce\b|防重放|一次性|令牌|票据/i.test(semanticText)
			) {
				requires.push("cap:ticket_or_token_leak");
			}
			if (
				!primaryEndpoint ||
				/\{\{.*\}\}/.test(primaryEndpoint) ||
				/配置.*泄露|回调端点模板|模板|内部/i.test(semanticText)
			) {
				requires.push("cap:leaked_route");
			}
		}
	}

	// 防止节点 requires 包含自己已经无条件 provides 的能力造成自依赖死锁
	const cleanProvides = uniqTags(provides);
	const cleanRequires = uniqTags(requires.filter((r) => !cleanProvides.includes(r)));

	// 4. 提取结构化动态变量线索（JSON Path / Header / Regex）
	const parsedOutJson = tryParseJsonFromText(fact.output);

	if (cleanProvides.includes("cap:leaked_route") || cleanProvides.includes("cap:config_disclosure")) {
		const routeJsonHits = parsedOutJson
			? findJsonFieldPaths(
					parsedOutJson,
					(k, v) =>
						typeof v === "string" &&
						v.includes("/") &&
						/(?:route|endpoint|path|url|template|callback|webhook|approval)/i.test(k),
				)
			: [];
		const preferredJsonPath = routeJsonHits[0]?.path;
		addVarHint({
			name: "leakedRoute",
			source: preferredJsonPath ? "json" : "regex",
			...(preferredJsonPath ? { jsonPath: preferredJsonPath } : {}),
			regex: `(?:^|['"\`\\s(=])(\\/(?:api|internal|admin|v\\d|approvals?|webhooks?|callbacks?|exports?)(?:\\/[A-Za-z0-9._-]+)+)(?![A-Za-z0-9._/-])`,
			sensitive: false,
		});
	}

	if (cleanProvides.includes("cap:ticket_or_token_leak") || cleanProvides.includes("cap:csrf_or_nonce")) {
		const discoveredNames: string[] = [];
		for (const m of semanticText.matchAll(KNOWN_TOKEN_IDENTIFIER_RE)) {
			const ident = m[1];
			if (ident && ident.length >= 4 && !/^(?:Bearer|Cookie|Token|Secret|Ticket)$/.test(ident)) {
				discoveredNames.push(ident);
			}
		}
		if (parsedOutJson) {
			const tokenJsonHits = findJsonFieldPaths(
				parsedOutJson,
				(k, v) =>
					(typeof v === "string" || typeof v === "number") &&
					/(?:ticket|token|nonce|csrf|xsrf)$/i.test(k),
			);
			for (const hit of tokenJsonHits) {
				discoveredNames.unshift(hit.key);
				addVarHint({
					name: hit.key,
					source: "json",
					jsonPath: hit.path,
					headerName: camelToKebabHeader(hit.key),
					regex: `"${escapeRegexLiteral(hit.key)}"\\s*:\\s*"([^"]+)"`,
					sensitive: true,
				});
			}
		}
		if (discoveredNames.length === 0) {
			discoveredNames.push(cleanProvides.includes("cap:csrf_or_nonce") ? "antiReplayToken" : "exportTicket");
		}
		for (const varName of uniqStrings(discoveredNames)) {
			addVarHint({
				name: varName,
				source: "json",
				jsonPath: varName,
				headerName: camelToKebabHeader(varName),
				regex: `"${escapeRegexLiteral(varName)}"\\s*:\\s*"([^"]+)"`,
				sensitive: SENSITIVE_VAR_NAME_RE.test(varName),
			});
		}
	}

	// 5. 提取当前步骤消费的参数绑定线索
	if (cleanRequires.includes("cap:ticket_or_token_leak")) {
		const referencedTokens: string[] = [];
		for (const m of semanticText.matchAll(KNOWN_TOKEN_IDENTIFIER_RE)) {
			if (m[1]) referencedTokens.push(m[1]);
		}
		const primaryVar =
			referencedTokens[0] ??
			(/anti[_-]?replay/i.test(semanticText) ? "antiReplayToken" : "exportTicket");
		const queryKeyMatch = /[?&]([a-zA-Z0-9_]+)=(?:\{\{[a-zA-Z0-9_.-]+\}\}|\{[a-zA-Z0-9_.-]+\}|$)/i.exec(
			primaryEndpoint ?? semanticText,
		);
		const paramName =
			queryKeyMatch?.[1] ??
			(/anti[_-]?replay/i.test(primaryVar) ? "antiReplayToken" : "ticket");
		addParamBinding({
			varName: primaryVar,
			location: "query",
			paramName,
		});
		addParamBinding({
			varName: primaryVar,
			location: "header",
			paramName: camelToKebabHeader(primaryVar),
		});
	}

	if (cleanProvides.includes("cap:url_sink") || cleanProvides.includes("cap:oob_channel")) {
		addParamBinding({
			varName: "oobCallbackUrl",
			location: "query",
			paramName: "callback",
		});
	}

	const authRoleHint = inferRoleFromBlob(fact, blob);
	const hasInlineLowPrivContext =
		fact.kind !== "cred" &&
		(isLowPrivMention || Boolean(authRoleHint && authRoleHint !== "admin"));

	// 6. 评估终局影响分（区分真正皇冠终局能力与中间跳板能力，确保完整打穿链优先于半途前缀链）
	let impactScore = 40;
	if (cleanProvides.includes("cap:admin_export_endpoint")) impactScore = 98;
	else if (cleanProvides.includes("cap:oob_channel")) impactScore = 95;
	else if (cleanProvides.includes("cap:admin_token")) impactScore = 92;
	else if (cleanProvides.includes("cap:url_sink")) impactScore = 86;
	else if (cleanProvides.includes("cap:ticket_or_token_leak")) impactScore = 52;
	else if (cleanProvides.includes("cap:id_enumerable")) impactScore = 46;
	else if (cleanProvides.includes("cap:leaked_route") || cleanProvides.includes("cap:config_disclosure")) {
		impactScore = 38;
	}

	return {
		factId: fact.id,
		kind: fact.kind,
		eligible: true,
		provides: cleanProvides,
		requires: cleanRequires,
		endpoints,
		...(primaryEndpoint ? { primaryEndpoint } : {}),
		leakedRoutes: uniqStrings(leakedRoutes),
		method: explicitMethod ?? "GET",
		variableHints,
		templateParams,
		...(authRoleHint ? { authRoleHint } : {}),
		...(hasInlineLowPrivContext ? { hasInlineLowPrivContext: true } : {}),
		impactScore,
	};
}

// ==================== 4. 有界防环攻击链合成与信念效用排序 ====================

const TERMINAL_WORTHY_CAPABILITIES: ReadonlySet<CapabilityTag> = new Set<CapabilityTag>([
	"cap:admin_export_endpoint",
	"cap:oob_channel",
	"cap:url_sink",
	"cap:admin_token",
	"cap:ticket_or_token_leak",
	"cap:id_enumerable",
]);

function capabilityStageRank(caps: readonly CapabilityTag[]): number {
	if (caps.includes("cap:leaked_route") || caps.includes("cap:config_disclosure")) return 1;
	if (caps.includes("cap:low_priv_token") || caps.includes("cap:admin_token")) return 2;
	if (caps.includes("cap:id_enumerable")) return 3;
	if (caps.includes("cap:csrf_or_nonce") || caps.includes("cap:ticket_or_token_leak")) return 4;
	if (caps.includes("cap:url_sink") || caps.includes("cap:oob_channel")) return 5;
	if (caps.includes("cap:admin_export_endpoint")) return 6;
	return 3;
}

interface SynthCandidateNode {
	fact: Fact;
	caps: FactCapabilities;
	posterior: number;
	voi: number;
	boost: number;
	pruned: boolean;
	stageRank: number;
}

/**
 * 验证给定步骤序列是否满足 STRIPS 无冗余因果链公理：
 * 1. 顺序可执行：每一步 `requires` 均被前序累积 `provides ∪ ambientCaps` 完全覆盖；
 * 2. 非冗余必然性：每个非终局步骤至少向后续某个步骤贡献了 1 个此前尚未具备的必需能力，
 *    且整个前缀不能有悬空无贡献的孤立步骤；
 * 3. 终局高价值：最后一步产出高价值安全影响能力，且与首步构成有效能力跃迁。
 */
function evaluateSequenceMinimality(
	seq: readonly SynthCandidateNode[],
	ambientCaps: ReadonlySet<CapabilityTag>,
): { valid: boolean; stepActiveCaps: CapabilityTag[][] } {
	const m = seq.length;
	if (m === 0) return { valid: false, stepActiveCaps: [] };

	const accumulatedBefore: Array<Set<CapabilityTag>> = [];
	const running = new Set<CapabilityTag>(ambientCaps);

	for (let i = 0; i < m; i++) {
		const node = seq[i]!;
		for (const req of node.caps.requires) {
			if (!running.has(req)) {
				return { valid: false, stepActiveCaps: [] };
			}
		}
		accumulatedBefore.push(new Set(running));
		for (const p of node.caps.provides) {
			running.add(p);
		}
	}

	const lastNode = seq[m - 1]!;
	const hasTerminalCap = lastNode.caps.provides.some(
		(c) => TERMINAL_WORTHY_CAPABILITIES.has(c) || !CAPABILITY_TAGS.includes(c as KnownCapabilityTag),
	);
	if (!hasTerminalCap) {
		return { valid: false, stepActiveCaps: [] };
	}
	if (m >= 2 && lastNode.caps.requires.length === 0) {
		return { valid: false, stepActiveCaps: [] };
	}

	const stepActiveCaps: CapabilityTag[][] = seq.map(() => []);
	stepActiveCaps[m - 1] = [...lastNode.caps.provides];

	// 逆向因果归因：从终局需求回溯，标记每个上游步骤首次提供的必需能力
	const neededDownstream = new Set<CapabilityTag>(lastNode.caps.requires);
	for (let i = m - 2; i >= 0; i--) {
		const cur = seq[i]!;
		const beforeSet = accumulatedBefore[i]!;
		const newlyProvidedNeeded = cur.caps.provides.filter(
			(p) => neededDownstream.has(p) && !beforeSet.has(p),
		);
		if (newlyProvidedNeeded.length === 0) {
			return { valid: false, stepActiveCaps: [] };
		}
		stepActiveCaps[i] = newlyProvidedNeeded;
		for (const p of newlyProvidedNeeded) {
			neededDownstream.delete(p);
		}
		for (const req of cur.caps.requires) {
			neededDownstream.add(req);
		}
	}

	// 检查可交换相邻独立步骤的规范偏序（消除 [A, B, C] 与 [B, A, C] 等价排列重复）
	for (let i = 0; i < m - 2; i++) {
		const a = seq[i]!;
		const b = seq[i + 1]!;
		const bNeedsA = b.caps.requires.some((r) => a.caps.provides.includes(r));
		if (!bNeedsA) {
			// a 与 b 彼此无直接先后依赖：强制要求 stageRank 较小（或同级 factId 字典序较小）的排在前面
			if (
				a.stageRank > b.stageRank ||
				(a.stageRank === b.stageRank && a.fact.id.localeCompare(b.fact.id) > 0)
			) {
				return { valid: false, stepActiveCaps: [] };
			}
		}
	}

	return { valid: true, stepActiveCaps };
}

/**
 * 基于 `provides -> requires` 能力互补图，在严格深度上界（`<= 4`）与防环 `visited` 保护下
 * 合成 2～4 跳组合攻击链，融合 `belief-search.ts` 节点后验信念、预期信息增益、终局影响分
 * 与跳数/Token 成本输出确定性降序列表。
 */
export function synthesizeAttackChains(
	state: NuwaState,
	opts?: SynthesizeChainsOptions,
): AttackChainSpec[] {
	if (!state || !state.facts) return [];

	// 硬上限强制锁死在 MAX_CHAIN_DEPTH (4)，严防非法入参导致超界搜索
	const rawMax =
		typeof opts?.maxDepth === "number" && Number.isFinite(opts.maxDepth)
			? Math.floor(opts.maxDepth)
			: DEFAULT_MAX_CHAIN_DEPTH;
	const maxDepth = clamp(rawMax, 1, MAX_CHAIN_DEPTH);

	const rawMin =
		typeof opts?.minDepth === "number" && Number.isFinite(opts.minDepth)
			? Math.floor(opts.minDepth)
			: DEFAULT_MIN_CHAIN_DEPTH;
	const minDepth = clamp(rawMin, maxDepth === 1 ? 1 : 2, maxDepth);

	const maxChains = clamp(
		typeof opts?.maxChains === "number" && Number.isFinite(opts.maxChains)
			? Math.floor(opts.maxChains)
			: 12,
		1,
		64,
	);
	const tokenCostPerHop = clamp(
		typeof opts?.tokenCostPerHop === "number" && Number.isFinite(opts.tokenCostPerHop)
			? opts.tokenCostPerHop
			: 1.2,
		0.1,
		20,
	);

	const beliefGraph = opts?.beliefGraph ?? initBeliefGraphFromState(state);
	const sortedFacts = Object.values(state.facts).sort((a, b) => a.id.localeCompare(b.id));

	// 收集候选事实与环境静态能力（如无独立 HTTP 端点的静态 cred 事实、Vault 活跃角色、项目 OOB 配置）
	const ambientCaps = new Set<CapabilityTag>(opts?.availableCapabilities ?? []);
	const ambientSourceMap = new Map<CapabilityTag, string[]>();
	const recordAmbientSource = (cap: CapabilityTag, factId?: string) => {
		ambientCaps.add(cap);
		if (factId) {
			const list = ambientSourceMap.get(cap) ?? [];
			if (!list.includes(factId)) list.push(factId);
			ambientSourceMap.set(cap, list);
		}
	};

	for (const role of state.project?.activeRoles ?? []) {
		if (ADMIN_CRED_RE.test(role)) {
			recordAmbientSource("cap:admin_token");
		} else {
			recordAmbientSource("cap:low_priv_token");
		}
	}
	if (state.project?.oobDomain || (state.project?.scope?.oobDomains?.length ?? 0) > 0) {
		recordAmbientSource("cap:oob_channel");
	}

	const allExtracted: SynthCandidateNode[] = [];
	let hasDedicatedLowPrivProvider = false;

	for (const f of sortedFacts) {
		const caps = extractFactCapabilities(f);
		if (!caps.eligible) continue;
		if (caps.provides.length === 0 && caps.requires.length === 0) continue;

		const bNodeId = resolveBeliefNodeId(beliefGraph, f.id, "fact");
		const bNode = bNodeId ? beliefGraph.nodes[bNodeId] : undefined;
		const pruned = Boolean(bNode?.pruned);
		if (pruned && !opts?.includePruned) continue;

		// 纯静态无端点的 cred 事实同步注册为环境基础凭据能力（同时保留其参与显式链的能力）
		if (f.kind === "cred" && caps.endpoints.length === 0) {
			for (const p of caps.provides) {
				recordAmbientSource(p, f.id);
			}
		}
		if (caps.provides.includes("cap:low_priv_token") && caps.endpoints.length > 0) {
			hasDedicatedLowPrivProvider = true;
		}

		allExtracted.push({
			fact: f,
			caps,
			posterior: clamp(bNode?.posterior ?? 0.6, 0.01, 0.999),
			voi: Math.max(0, bNode?.expectedInfoGain ?? 0.35),
			boost: Math.max(0, bNode?.breakthroughBoost ?? 0),
			pruned,
			stageRank: capabilityStageRank(caps.provides),
		});
	}

	// 若状态中没有带 HTTP 端点的独立低权凭据获取步骤，但某业务事实自身已注明携带低权会话上下文，放行环境低权能力
	if (!hasDedicatedLowPrivProvider && !ambientCaps.has("cap:low_priv_token")) {
		if (allExtracted.some((n) => n.caps.hasInlineLowPrivContext)) {
			recordAmbientSource("cap:low_priv_token");
		}
	}

	// 仅保留可作为 HTTP 探测步骤的节点（或当总节点较少时允许被编译兜底的节点）参与主干跳数搜索
	const stepNodes = allExtracted.filter(
		(n) => !(n.fact.kind === "cred" && n.caps.endpoints.length === 0 && n.caps.requires.length === 0),
	);
	const searchPool = stepNodes.length >= minDepth ? stepNodes : allExtracted;
	if (searchPool.length < minDepth) return [];

	const rawChains: AttackChainSpec[] = [];
	const seenSemanticSigs = new Set<string>();
	const MAX_DFS_STATES = 2500;
	let expandedStates = 0;

	const dfs = (
		path: SynthCandidateNode[],
		visitedFactIds: Set<string>,
		currentCaps: Set<CapabilityTag>,
	): void => {
		if (expandedStates >= MAX_DFS_STATES) return;
		expandedStates++;

		const depth = path.length;
		if (depth >= minDepth && depth <= maxDepth) {
			const check = evaluateSequenceMinimality(path, ambientCaps);
			if (check.valid) {
				const spec = buildChainSpecFromSequence(
					path,
					check.stepActiveCaps,
					ambientSourceMap,
					tokenCostPerHop,
				);
				if (!seenSemanticSigs.has(spec.semanticSignature)) {
					seenSemanticSigs.add(spec.semanticSignature);
					rawChains.push(spec);
				}
			}
		}

		if (depth >= maxDepth) return;

		for (const cand of searchPool) {
			// 严格防环：同一 Fact 绝不允许在同一条链中出现两次
			if (visitedFactIds.has(cand.fact.id)) continue;

			// 顺序前置可满足校验：候选节点所需的全部 requires 必须已在 currentCaps 中具备
			const reqSatisfied = cand.caps.requires.every((r) => currentCaps.has(r));
			if (!reqSatisfied) continue;

			// 剪枝无新增能力的纯空转扩展（除非该候选本身是合法的终局消费节点）
			const addsNewCap = cand.caps.provides.some((p) => !currentCaps.has(p));
			const isTerminalConsumer =
				cand.caps.requires.length > 0 &&
				cand.caps.provides.some((p) => TERMINAL_WORTHY_CAPABILITIES.has(p));
			if (!addsNewCap && !isTerminalConsumer) continue;

			visitedFactIds.add(cand.fact.id);
			const nextCaps = new Set(currentCaps);
			for (const p of cand.caps.provides) {
				nextCaps.add(p);
			}
			path.push(cand);

			dfs(path, visitedFactIds, nextCaps);

			path.pop();
			visitedFactIds.delete(cand.fact.id);
		}
	};

	// 从所有满足初始环境前置条件的起始节点启动有界 DFS
	for (const startNode of searchPool) {
		const canStart = startNode.caps.requires.every((r) => ambientCaps.has(r));
		if (!canStart) continue;
		if (startNode.caps.provides.length === 0) continue;

		const visited = new Set<string>([startNode.fact.id]);
		const initCaps = new Set<CapabilityTag>(ambientCaps);
		for (const p of startNode.caps.provides) {
			initCaps.add(p);
		}
		dfs([startNode], visited, initCaps);
	}

	rawChains.sort(
		(a, b) =>
			b.utilityScore - a.utilityScore ||
			b.chainBelief - a.chainBelief ||
			a.depth - b.depth ||
			a.id.localeCompare(b.id),
	);

	return rawChains.slice(0, maxChains);
}

function buildChainSpecFromSequence(
	seq: readonly SynthCandidateNode[],
	stepActiveCaps: readonly CapabilityTag[][],
	ambientSourceMap: ReadonlyMap<CapabilityTag, string[]>,
	tokenCostPerHop: number,
): AttackChainSpec {
	const depth = seq.length;
	const factIds = seq.map((n) => n.fact.id);
	const supportingSet = new Set<string>();

	let logBeliefSum = 0;
	let totalVoi = 0;
	let maxBoost = 0;
	let rawStepCostSum = 0;

	const steps: AttackChainStep[] = seq.map((node, idx) => {
		for (const req of node.caps.requires) {
			for (const supId of ambientSourceMap.get(req) ?? []) {
				if (!factIds.includes(supId)) supportingSet.add(supId);
			}
		}

		const p = clamp(node.posterior, 0.01, 0.999);
		logBeliefSum += Math.log(p);
		totalVoi += node.voi;
		if (node.boost > maxBoost) maxBoost = node.boost;

		const stepCost = Number((1.0 + tokenCostPerHop * (idx === 0 ? 0.8 : 1.0)).toFixed(3));
		rawStepCostSum += stepCost;

		const rawStepTitle = oneLine(node.fact.title, 120) || node.fact.id;
		const safeStepTitle = redactTrafficBody(rawStepTitle, { maxChars: 120 }) || node.fact.id;

		const safeEndpoint = node.caps.primaryEndpoint
			? sanitizeEndpointLiteral(node.caps.primaryEndpoint)
			: undefined;

		return {
			stepIndex: idx,
			factId: node.fact.id,
			factKind: node.fact.kind,
			title: safeStepTitle,
			...(safeEndpoint ? { endpoint: safeEndpoint } : {}),
			method: node.caps.method,
			provides: [...node.caps.provides],
			requires: [...node.caps.requires],
			activeCapabilities: stepActiveCaps[idx] ?? [...node.caps.provides],
			extractVariables: node.caps.variableHints.map((h) => ({ ...h })),
			templateParams: node.caps.templateParams.map((t) => ({ ...t })),
			beliefPosterior: Number(p.toFixed(6)),
			expectedInfoGain: Number(node.voi.toFixed(6)),
			stepCost,
			...(node.caps.authRoleHint ? { authRole: node.caps.authRoleHint } : {}),
		};
	});

	const lastNode = seq[depth - 1]!;
	const terminalCapabilities = [...lastNode.caps.provides];
	const terminalImpact = clamp(lastNode.caps.impactScore, 10, 100);

	// 串联信念：采用节点后验几何均值乘温和跳数衰减因子，避免与分母成本项双重惩罚长链
	const geomPosterior = Math.exp(logBeliefSum / Math.max(1, depth));
	const chainBelief = clamp(geomPosterior * Math.pow(0.94, Math.max(0, depth - 1)), 1e-4, 0.999);
	const avgVoi = totalVoi / Math.max(1, depth);
	const voiNorm = avgVoi / (1 + avgVoi);
	const boostNorm = clamp(maxBoost, 0, 1);

	const estimatedCost = Number((rawStepCostSum + Math.max(0, depth - 1) * 0.75).toFixed(3));
	const rawUtility =
		(terminalImpact * (0.65 * chainBelief + 0.2 * voiNorm + 0.15 * boostNorm)) /
		Math.pow(Math.max(1, estimatedCost), 0.55);
	const utilityScore = Number((Number.isFinite(rawUtility) ? Math.max(0, rawUtility) : 0).toFixed(4));

	// 同链语义签名：仅基于纯路径（剥离查询参数）与每跳关键能力归一化，杜绝查询参数泄露并消除同端点冗余链
	const semanticParts = steps.map(
		(s) => `${stripQueryFromEndpoint(s.endpoint) ?? s.factId}:${[...s.activeCapabilities].sort().join("+")}`,
	);
	const semanticSignature = semanticParts.join(" -> ");
	const id = `chain:${sha1Short(`${factIds.join(">")}|${semanticSignature}`, 12)}`;

	const titleArrow = steps.map((s) => oneLine(s.title, 42)).join(" -> ");
	const title = `多跳组合攻击链 (${depth} 跳): ${titleArrow}`;
	const rationale =
		`合成 ${depth} 跳能力跃迁链 [${factIds.join(" -> ")}]，终局能力 [${terminalCapabilities.join(", ")}]，` +
		`链后验=${chainBelief.toFixed(3)}，影响分=${terminalImpact}，预估成本=${estimatedCost.toFixed(2)}，效用=${utilityScore.toFixed(2)}`;

	return {
		id,
		title,
		rationale,
		steps,
		depth,
		factIds,
		supportingFactIds: [...supportingSet].sort((a, b) => a.localeCompare(b)),
		terminalCapabilities,
		chainBelief: Number(chainBelief.toFixed(6)),
		expectedInfoGain: Number(avgVoi.toFixed(6)),
		terminalImpact,
		estimatedCost,
		utilityScore,
		semanticSignature,
	};
}
