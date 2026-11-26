/**
 * 女娲 v7.0 多跳攻击链合成与有状态验证引擎（Chain Composer）。
 *
 * 融合 dsh-gungnir 前置-后置能力合成（Precondition-Postcondition Synthesis）思想，
 * 与 v6 信念图搜索引擎（`belief-search.ts`）及授权流量审计工作台（`traffic-workbench.ts`）深度衔接：
 * 1. `extractFactCapabilities`：从非 `blocked`/非 `rejected` 事实确定性提取 `provides` 与 `requires`
 *    能力标签、关联端点元数据与跨跳动态变量提取/注入线索；
 * 2. `synthesizeAttackChains`：基于 `provides -> requires` 互补有向图与环境能力闭包，在有界深度
 *    （默认 `minDepth=2, maxDepth=4`，硬上限 `<= 4`）下执行严格防环搜索与偏序同链语义去重，
 *    融合节点 Beta 后验信念、VoI、终局影响分与跳数/Token 成本输出确定性 `utilityScore` 排序；
 * 3. `compileChainToTrafficSequence`：将抽象攻击链自动编译为纯只读合规探测 `TrafficStep[]`
 *    （自动生成 JSON Path / Response Header / Regex 提取器与下一步 `{{var}}` 模板映射）；
 * 4. `executeAttackChainVerification`：调用 `replayTrafficSequence` 逐跳执行有状态合规验证，
 *    强制全步 Scope 门禁、Soft-404 与负向基线反误报过滤、全链路敏感凭据与一次性票据零明文脱敏；
 *    全链打穿时产出待双盲复验的 `candidate` 复合漏洞 `Fact` 与 `verify-vuln:<fid>` 建议，
 *    中间第 `k` 步受阻时精准定界 `brokenAtStep: k`、`brokenFactId` 与 `beliefObservation`。
 *
 * 约束：零外部第三方依赖，仅 `import type` 引用 `./types`，严禁运行时导入 `./nuwa`。
 */
import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";
import {
	computeBodyHash,
	detectSoft404,
	sampleSoft404Baseline,
	type Soft404Baseline,
	type Soft404BaselineInput,
} from "./autoexec";
import {
	initBeliefGraphFromState,
	propagateBeliefUpdate,
	resolveBeliefNodeId,
	type BeliefGraph,
	type BeliefObservation,
	type BeliefPropagationResult,
} from "./belief-search";
import {
	evaluatePositiveEvidenceGate,
	recordToolExecution,
	type ResponseSnapshot,
} from "./evidence";
import { isOobHostAllowed } from "./oob";
import {
	checkScopeAndRisk,
	formatScopeBlockReason,
	isHostInScope,
} from "./scope";
import {
	getRoleHeadersMap,
	loadSessionVault,
	redactVaultSecrets,
	type SessionVault,
} from "./session-vault";
import {
	REDACTED_MARKER,
	redactTrafficBody,
	redactTrafficHeaders,
	redactTrafficUrl,
	replayTrafficSequence,
	TrafficRecorder,
	type ReplayStepResult,
	type TrafficExtractorSpec,
	type TrafficFetchFn,
	type TrafficReplayStep,
} from "./traffic-workbench";
import type { Fact, FactKind, Mode, NuwaState, ScopePolicy } from "./types";

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

const SENSITIVE_VAR_NAME_RE =
	/(?:ticket|token|secret|password|passwd|pwd|key|auth|jwt|sid|session|cookie|csrf|xsrf|nonce|cred|bearer|sig|signature)/i;

const KNOWN_TOKEN_IDENTIFIER_RE =
	/\b([a-zA-Z][a-zA-Z0-9_]*(?:Ticket|Token|Nonce|Secret|Key)|export_ticket|anti_replay_token|download_ticket|csrf_token|xsrf_token|temp_token|once_token)\b/g;

const NON_HTTP_FS_PATH_PREFIX_RE =
	/^\/(?:tmp|etc|usr|var|opt|root|home|proc|sys|dev|bin|sbin|lib|lib64|private|Users| swat)(?:\/|$)/i;

function sha1Short(text: string, len = 10): string {
	return createHash("sha1").update(text).digest("hex").slice(0, len);
}

function clamp(val: number, min: number, max: number): number {
	if (Number.isNaN(val)) return min;
	if (val === Number.POSITIVE_INFINITY) return max;
	if (val === Number.NEGATIVE_INFINITY) return min;
	return Math.max(min, Math.min(max, val));
}

function oneLine(text: string | undefined, max = 140): string {
	return String(text ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

function uniqTags(tags: Iterable<CapabilityTag>): CapabilityTag[] {
	const seen = new Set<CapabilityTag>();
	const out: CapabilityTag[] = [];
	for (const t of tags) {
		if (!t || !t.startsWith("cap:") || seen.has(t)) continue;
		seen.add(t);
		out.push(t);
	}
	return out;
}

function uniqStrings(items: Iterable<string>): string[] {
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

function camelToKebabHeader(varName: string): string {
	const kebab = varName
		.replace(/([a-z0-9])([A-Z])/g, "$1-$2")
		.replace(/[_\s]+/g, "-")
		.toLowerCase()
		.replace(/^-+|-+$/g, "");
	return kebab.startsWith("x-") ? kebab : `x-${kebab}`;
}

function escapeRegexLiteral(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeReadonlyMethod(raw: unknown): ReadonlyHttpMethod {
	const upper = String(raw ?? "GET").trim().toUpperCase();
	if (READONLY_METHOD_SET.has(upper)) {
		return upper as ReadonlyHttpMethod;
	}
	return "GET";
}

const SENSITIVE_QUERY_PARAM_KEY_RE =
	/^(?:access_token|refresh_token|id_token|auth_token|api_key|apikey|api_token|csrf_token|xsrf_token|anti_replay_token|antiReplayToken|export_ticket|exportTicket|download_ticket|downloadTicket|token|secret|client_secret|password|passwd|pwd|auth|jwt|session|session_id|sid|csrf|xsrf|sig|signature|ticket|private_token|key|nonce)$/i;

const COOKIE_ATTR_SKIP_SET = new Set([
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

const NON_SECRET_TRIVIAL_VALUES = new Set([
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

function sanitizeEndpointLiteral(raw: string): string {
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

function stripQueryFromEndpoint(endpoint: string | undefined): string | undefined {
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

function findJsonFieldPaths(
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

function tryParseJsonFromText(text: string | undefined): unknown {
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

// ==================== 5. 编译抽象链为只读合规 TrafficStep[] ====================

function normalizeBaseOrigin(baseUrl: string): string {
	const trimmed = String(baseUrl ?? "").trim();
	if (!trimmed) return "http://127.0.0.1";
	try {
		const u = new URL(trimmed);
		return u.origin;
	} catch {
		return trimmed.replace(/\/+$/, "");
	}
}

function buildExtractorSpecFromHint(hint: VariableExtractionHint): TrafficExtractorSpec {
	const spec: TrafficExtractorSpec = {};
	if (hint.headerName) {
		spec.header = hint.headerName.toLowerCase();
	}
	if (hint.cookieName) {
		spec.cookie = hint.cookieName;
	}
	if (hint.jsonPath) {
		spec.jsonPath = hint.jsonPath;
	}
	if (hint.regex) {
		spec.regex = hint.regex;
	}
	if (!spec.header && !spec.cookie && !spec.jsonPath && !spec.regex) {
		spec.jsonPath = hint.name;
		spec.regex = `"${escapeRegexLiteral(hint.name)}"\\s*:\\s*"([^"]+)"`;
	}
	return spec;
}

function appendQueryTemplateIfMissing(rawUrl: string, paramName: string, varName: string): string {
	const placeholder = `{{${varName}}}`;
	const escapedParam = escapeRegexLiteral(paramName);
	const emptyParamRe = new RegExp(`([?&]${escapedParam}=)(?=&|$)`);
	if (emptyParamRe.test(rawUrl)) {
		return rawUrl.replace(emptyParamRe, `$1${placeholder}`);
	}
	const singleBraceRe = new RegExp(`([?&]${escapedParam}=)\\{${escapeRegexLiteral(varName)}\\}`);
	if (singleBraceRe.test(rawUrl)) {
		return rawUrl.replace(singleBraceRe, `$1${placeholder}`);
	}
	const existingParamRe = new RegExp(`[?&]${escapedParam}=`, "i");
	if (existingParamRe.test(rawUrl)) {
		return rawUrl;
	}
	const sep = rawUrl.includes("?") ? "&" : "?";
	return `${rawUrl}${sep}${encodeURIComponent(paramName)}=${placeholder}`;
}

/**
 * 将抽象 `AttackChainSpec` 自动编译为 `traffic-workbench.ts` 可直接执行的 `TrafficStep[]`：
 * - 严格保留纯只读探测方法（`GET` / `HEAD` / `OPTIONS`），拒绝构造任何写操作请求体；
 * - 自动为上游步骤注入 JSON Path / Response Header / Regex 复合提取器，
 *   并在下游步骤自动完成路径/查询参数/请求头的顶层 `{{var}}` 模板映射。
 */
export function compileChainToTrafficSequence(
	chain: AttackChainSpec,
	baseUrl: string,
	opts?: CompileChainOptions,
): TrafficStep[] {
	if (!chain || !Array.isArray(chain.steps) || chain.steps.length === 0) {
		return [];
	}

	const origin = normalizeBaseOrigin(baseUrl);
	const resolvedVault =
		opts?.vault ??
		(opts?.root
			? (() => {
					try {
						return loadSessionVault(opts.root);
					} catch {
						return undefined;
					}
				})()
			: undefined);

	// 跟踪上游已注册提取出的变量名及其主要能力类型
	const availableTicketVars: string[] = [];
	let availableRouteVar: string | undefined;

	const stepExtracts: Array<Record<string, TrafficExtractorSpec>> = chain.steps.map(() => ({}));

	// 第一遍：收集每一步可提取的变量，并登记到对应上游步骤
	for (let i = 0; i < chain.steps.length; i++) {
		const step = chain.steps[i]!;
		const isLast = i === chain.steps.length - 1;
		if (isLast) continue;

		for (const hint of step.extractVariables) {
			stepExtracts[i]![hint.name] = buildExtractorSpecFromHint(hint);
			if (hint.name === "leakedRoute") {
				availableRouteVar = hint.name;
			} else if (
				step.provides.includes("cap:ticket_or_token_leak") ||
				step.provides.includes("cap:csrf_or_nonce") ||
				SENSITIVE_VAR_NAME_RE.test(hint.name)
			) {
				if (!availableTicketVars.includes(hint.name)) {
					availableTicketVars.push(hint.name);
				}
			}
		}

		// 若某中间步骤声明提供了 cap:leaked_route 但无显式 extractVariables，自动补齐通用路由提取器
		if (
			(step.provides.includes("cap:leaked_route") || step.provides.includes("cap:config_disclosure")) &&
			!stepExtracts[i]!.leakedRoute
		) {
			stepExtracts[i]!.leakedRoute = {
				regex: `(?:^|['"\`\\s(=])(\\/(?:api|internal|admin|v\\d|approvals?|webhooks?|callbacks?|exports?)(?:\\/[A-Za-z0-9._-]+)+)(?![A-Za-z0-9._/-])`,
			};
			availableRouteVar = "leakedRoute";
		}

		// 若某中间步骤声明提供了 cap:ticket_or_token_leak 但无显式 extractVariables，自动补齐票据提取器
		if (step.provides.includes("cap:ticket_or_token_leak") && availableTicketVars.length === 0) {
			const fallbackName = step.provides.includes("cap:csrf_or_nonce") ? "antiReplayToken" : "exportTicket";
			stepExtracts[i]![fallbackName] = {
				header: camelToKebabHeader(fallbackName),
				jsonPath: fallbackName,
				regex: `"${fallbackName}"\\s*:\\s*"([^"]+)"`,
			};
			availableTicketVars.push(fallbackName);
		}
	}

	// 第二遍：构建每一步只读合规的 TrafficStep（含 URL 模板拼接与角色头注入）
	const compiledSteps: TrafficStep[] = [];
	const producedBeforeStep = new Set<string>();

	for (let i = 0; i < chain.steps.length; i++) {
		const step = chain.steps[i]!;
		const method = normalizeReadonlyMethod(step.method);

		const headers: Record<string, string> = {
			Accept: "application/json, text/plain, */*",
			...(opts?.defaultHeaders ?? {}),
		};

		// 认证头注入（优先角色专属头，其次全局 authHeaders，仅注入需要认证或低权越权的步骤或全局配置）
		if (step.authRole) {
			const fromOptRole = opts?.roleHeaders?.[step.authRole];
			const fromVaultRole = resolvedVault ? getRoleHeadersMap(resolvedVault, step.authRole) : null;
			const mergedRoleHeaders = fromOptRole ?? fromVaultRole;
			if (mergedRoleHeaders) {
				Object.assign(headers, mergedRoleHeaders);
			}
		}
		if (opts?.authHeaders && (step.requires.includes("cap:low_priv_token") || step.authRole || i > 0)) {
			for (const [hk, hv] of Object.entries(opts.authHeaders)) {
				if (headers[hk] === undefined) {
					headers[hk] = hv;
				}
			}
		}

		// 解析步骤目标 URL
		let rawEndpoint = step.endpoint?.trim() ?? "";
		// 仅当单花括号变量确实由前序步骤产出（或属于受控 OOB 回调变量）时，才将其规范化为双花括号 {{name}}，保留无关 OpenAPI 路径段原貌
		rawEndpoint = rawEndpoint.replace(/(?<!\{)\{([a-zA-Z0-9_.-]+)\}(?!\})/g, (fullMatch, name: string) =>
			producedBeforeStep.has(name) ||
			name === "oobCallbackUrl" ||
			name === "callbackUrl" ||
			name === "callback"
				? `{{${name}}}`
				: fullMatch,
		);

		let stepUrl: string;
		const useDynamicRoute =
			(!rawEndpoint || opts?.preferDynamicRoute === true) &&
			step.requires.includes("cap:leaked_route") &&
			availableRouteVar &&
			producedBeforeStep.has(availableRouteVar);

		if (useDynamicRoute && availableRouteVar) {
			stepUrl = `${origin}{{${availableRouteVar}}}`;
		} else if (!rawEndpoint) {
			stepUrl = `${origin}/`;
		} else if (/^https?:\/\//i.test(rawEndpoint)) {
			stepUrl = rawEndpoint;
		} else if (rawEndpoint.startsWith("{{")) {
			stepUrl = `${origin}${rawEndpoint}`;
		} else {
			const slashPath = rawEndpoint.startsWith("/") ? rawEndpoint : `/${rawEndpoint}`;
			stepUrl = `${origin}${slashPath}`;
		}

		// 绑定上游提取的票据/令牌模板参数
		if (step.requires.includes("cap:ticket_or_token_leak")) {
			// 匹配上游已产出的最新票据变量
			const candidateVars = [...producedBeforeStep].filter((v) => availableTicketVars.includes(v));
			const targetTicketVar =
				step.templateParams.find((p) => producedBeforeStep.has(p.varName))?.varName ??
				candidateVars[candidateVars.length - 1] ??
				availableTicketVars[0];

			if (targetTicketVar) {
				const explicitQueryHint = step.templateParams.find(
					(p) => p.location === "query" && (p.varName === targetTicketVar || availableTicketVars.length === 1),
				);
				const primaryParamName = explicitQueryHint?.paramName ?? targetTicketVar;
				stepUrl = appendQueryTemplateIfMissing(stepUrl, primaryParamName, targetTicketVar);
				// 同时兼容服务端按精确变量名或通用别名（ticket / token）读取查询参数
				if (primaryParamName !== targetTicketVar) {
					stepUrl = appendQueryTemplateIfMissing(stepUrl, targetTicketVar, targetTicketVar);
				} else if (/ticket/i.test(targetTicketVar) && primaryParamName !== "ticket") {
					stepUrl = appendQueryTemplateIfMissing(stepUrl, "ticket", targetTicketVar);
				} else if (/token/i.test(targetTicketVar) && primaryParamName !== "token") {
					stepUrl = appendQueryTemplateIfMissing(stepUrl, "token", targetTicketVar);
				}

				const headerName = camelToKebabHeader(targetTicketVar);
				if (!Object.keys(headers).some((k) => k.toLowerCase() === headerName.toLowerCase())) {
					headers[headerName] = `{{${targetTicketVar}}}`;
				}
			}
		}

		// 绑定 OOB 回调接收 URL 模板参数（当显式传入 oobCallbackUrl 或未禁用 OOB 模板注入时自动挂载）
		if (
			step.provides.includes("cap:url_sink") ||
			step.provides.includes("cap:oob_channel") ||
			step.templateParams.some((p) => p.varName === "oobCallbackUrl")
		) {
			if (
				opts?.oobCallbackUrl !== undefined &&
				!/\{\{\s*(?:oobCallbackUrl|callbackUrl|callback)\s*\}\}/.test(stepUrl)
			) {
				stepUrl = appendQueryTemplateIfMissing(stepUrl, "callback", "oobCallbackUrl");
				stepUrl = appendQueryTemplateIfMissing(stepUrl, "callbackUrl", "oobCallbackUrl");
			} else if (
				opts?.oobCallbackUrl === undefined &&
				!/[?&](?:callback|callbackUrl|oobCallbackUrl|url|target)=/i.test(stepUrl) &&
				!/\{\{\s*(?:oobCallbackUrl|callbackUrl|callback)\s*\}\}/.test(stepUrl)
			) {
				stepUrl = appendQueryTemplateIfMissing(stepUrl, "callback", "oobCallbackUrl");
				stepUrl = appendQueryTemplateIfMissing(stepUrl, "callbackUrl", "oobCallbackUrl");
			}
		}

		const extractObj = stepExtracts[i]!;
		const hasExtracts = Object.keys(extractObj).length > 0;

		compiledSteps.push({
			id: `chain_step_${i}`,
			name: `hop_${i + 1}:${step.factId}`,
			method,
			url: stepUrl,
			headers,
			...(hasExtracts ? { extract: extractObj } : {}),
			...(opts?.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}),
			followRedirects: true,
			tags: ["attack-chain", `hop:${i}`, `fact:${step.factId}`],
		});

		for (const extractedVar of Object.keys(extractObj)) {
			producedBeforeStep.add(extractedVar);
		}
	}

	return compiledSteps;
}

// ==================== 6. 有状态多跳验证执行、反误报门禁与精准断点定界 ====================

function collectTemplatePlaceholders(step: TrafficStep): string[] {
	const names = new Set<string>();
	const scan = (s: string | undefined) => {
		if (!s) return;
		for (const m of s.matchAll(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g)) {
			if (m[1]) names.add(m[1]);
		}
	};
	scan(step.url);
	if (step.headers) {
		for (const [k, v] of Object.entries(step.headers)) {
			scan(k);
			scan(v);
		}
	}
	return [...names];
}

function extractSensitiveValuesFromJson(rawBody: string, sink: Set<string>): void {
	const parsed = tryParseJsonFromText(rawBody);
	if (!parsed) return;
	const hits = findJsonFieldPaths(
		parsed,
		(k, v) => typeof v === "string" && v.trim().length >= 4 && SENSITIVE_VAR_NAME_RE.test(k),
	);
	for (const h of hits) {
		const val = String(h.val).trim();
		if (val.length >= 4 && val !== REDACTED_MARKER) {
			sink.add(val);
		}
	}
}

function scrubAllChainText(
	text: string,
	secrets: ReadonlySet<string>,
	root: string,
	vault?: SessionVault,
): string {
	if (!text) return "";
	const secretArr = [...secrets]
		.map((s) => s.trim())
		.filter((s) => s.length >= 4 && s !== REDACTED_MARKER)
		.sort((a, b) => b.length - a.length);

	let out = redactTrafficBody(text, {
		root,
		vault,
		extraSecrets: secretArr,
		maxChars: 8192,
	}) ?? text;

	for (const sec of secretArr) {
		if (out.includes(sec)) {
			out = out.split(sec).join(REDACTED_MARKER);
		}
		try {
			const encoded = encodeURIComponent(sec);
			if (encoded.length >= 4 && out.includes(encoded)) {
				out = out.split(encoded).join(REDACTED_MARKER);
			}
		} catch {
			/* ignore */
		}
	}
	try {
		out = redactVaultSecrets(out, vault ?? root);
	} catch {
		/* ignore */
	}
	return out;
}

function validateControlledOobEndpoint(
	rawUrl: string,
	scope: ScopePolicy,
	label: string,
): { ok: true; parsed: URL } | { ok: false; reason: string } {
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		return {
			ok: false,
			reason: formatScopeBlockReason("egress-proxy", `${label} URL 非法 (${rawUrl})`, "N-007"),
		};
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return {
			ok: false,
			reason: formatScopeBlockReason("egress-proxy", `${label} 仅允许 http/https 协议`, "N-007"),
		};
	}
	const host = parsed.hostname.toLowerCase();
	// 允许受控本机 127.0.0.1 回环 OOB 接收器（除非 scope.allowLoopback === false 显式禁止）
	if (host === "127.0.0.1") {
		if (scope.allowLoopback === false) {
			return {
				ok: false,
				reason: formatScopeBlockReason("egress-proxy", `${label} 被 allowLoopback=false 策略阻断`, "N-007"),
			};
		}
		if ((scope.denyHosts ?? []).some((d) => d.trim().toLowerCase() === "127.0.0.1")) {
			return {
				ok: false,
				reason: formatScopeBlockReason("egress-proxy", `${label} 命中 denyHosts (127.0.0.1)`, "N-007"),
			};
		}
		return { ok: true, parsed };
	}
	const inScope = isHostInScope(host, scope);
	if (inScope.ok) return { ok: true, parsed };
	const oobAllowed = isOobHostAllowed(host, scope);
	if (oobAllowed.ok) return { ok: true, parsed };

	return {
		ok: false,
		reason: formatScopeBlockReason(
			"egress-proxy",
			`${label} 主机越界 (${host})：既非本机 127.0.0.1，也不在授权 Scope 或 oobDomains 白名单内`,
			"N-007",
		),
	};
}

/**
 * 将攻击链验证执行结果同步应用至 `BeliefGraph`：
 * - 若验证在 `brokenFactId` 处受阻，精准对该节点及其下游依赖分支传播负向信念衰减与低收益剪枝；
 * - 若全链验证通过，对终局节点传播 `breakthrough_signal` 提权。
 */
export function applyChainResultToBeliefGraph(
	result: ChainExecutionResult,
	graph: BeliefGraph,
	state: NuwaState,
	opts?: { applyToState?: boolean },
): BeliefPropagationResult | null {
	const candidateRefs: string[] = [];
	if (result.verified) {
		if (result.candidateFact?.id) candidateRefs.push(result.candidateFact.id);
		for (let i = result.stepTraces.length - 1; i >= 0; i--) {
			const fid = result.stepTraces[i]?.factId;
			if (fid && !candidateRefs.includes(fid)) candidateRefs.push(fid);
		}
	} else if (result.brokenFactId) {
		candidateRefs.push(result.brokenFactId);
	}

	let resolvedNodeId: string | undefined;
	for (const ref of candidateRefs) {
		resolvedNodeId = resolveBeliefNodeId(graph, ref, "fact") ?? resolveBeliefNodeId(graph, ref);
		if (resolvedNodeId) break;
	}
	if (!resolvedNodeId) return null;

	return propagateBeliefUpdate(graph, state, {
		nodeId: resolvedNodeId,
		observation: result.beliefObservation,
		applyToState: opts?.applyToState,
		reason: result.reason,
	});
}

/**
 * 执行多跳攻击链有状态验证：
 * - 逐跳调用 `replayTrafficSequence` 执行只读合规探测与跨跳变量提取传递；
 * - 强制全步 Scope 校验、30x 重定向越界拦截、Soft-404 预采样去噪与 `evaluatePositiveEvidenceGate` 假阳性过滤；
 * - 全流程动态追踪并擦除认证凭据与中间提取票据（如 `exportTicket`、`antiReplayToken`），确保磁盘流量日志、
 *   `exec-ledger`、返回摘要与 `Fact` 标题/详情 100% 零明文凭据泄露；
 * - 全链打穿时产出 `verifyStage: "candidate", verified: false` 的复合漏洞 `Fact` 与 `verify-vuln:<fid>` 复验建议；
 * - 第 `k` 跳受阻时立即熔断后续发包，精准返回 `verified: false, brokenAtStep: k, brokenFactId, beliefObservation`。
 */
export async function executeAttackChainVerification(
	chain: AttackChainSpec,
	root: string,
	scope: ScopePolicy,
	opts?: ExecuteChainVerificationOptions,
): Promise<ChainExecutionResult> {
	const normRoot = resolve(root || process.cwd());
	const mode = opts?.mode ?? opts?.state?.project?.mode ?? "audit";
	const timeoutMs = clamp(opts?.timeoutMs ?? 8_000, 100, 60_000);

	// 1. 构建全链路动态秘密收集池与脱敏记录器
	let resolvedVault = opts?.vault;
	if (!resolvedVault) {
		try {
			resolvedVault = loadSessionVault(normRoot);
		} catch {
			resolvedVault = undefined;
		}
	}

	const collectedSecrets = new Set<string>();
	let recorderRef: TrafficRecorder | undefined;

	const registerSecret = (val: string | undefined) => {
		const trimmed = String(val ?? "").trim();
		if (
			trimmed.length >= 3 &&
			trimmed !== REDACTED_MARKER &&
			!NON_SECRET_TRIVIAL_VALUES.has(trimmed.toLowerCase())
		) {
			collectedSecrets.add(trimmed);
			recorderRef?.registerTransientSecret(trimmed);
			const bare = trimmed.replace(/^(?:Bearer|Basic|Token|JWT|Digest)\s+/i, "").trim();
			if (bare.length >= 3 && !NON_SECRET_TRIVIAL_VALUES.has(bare.toLowerCase())) {
				collectedSecrets.add(bare);
				recorderRef?.registerTransientSecret(bare);
			}
		}
	};

	const registerCookieHeaderSecrets = (rawCookieHeader: string | undefined) => {
		if (!rawCookieHeader) return;
		for (const line of String(rawCookieHeader).split(/\r?\n/)) {
			for (const part of line.split(";")) {
				const seg = part.trim();
				if (!seg) continue;
				const eq = seg.indexOf("=");
				if (eq <= 0) continue;
				const ck = seg.slice(0, eq).trim();
				const cv = seg.slice(eq + 1).trim();
				if (!ck || !cv || COOKIE_ATTR_SKIP_SET.has(ck.toLowerCase())) continue;
				if (!NON_SECRET_TRIVIAL_VALUES.has(cv.toLowerCase())) {
					registerSecret(cv);
				}
			}
		}
	};

	const registerHeaderMapSecrets = (hdrs: Record<string, string> | undefined) => {
		if (!hdrs) return;
		for (const [hk, hv] of Object.entries(hdrs)) {
			if (!hv) continue;
			const lowerHk = hk.trim().toLowerCase();
			if (lowerHk === "cookie" || lowerHk === "set-cookie") {
				registerCookieHeaderSecrets(hv);
			} else if (SENSITIVE_VAR_NAME_RE.test(hk)) {
				registerSecret(hv);
			}
		}
	};

	for (const s of opts?.extraSecrets ?? []) registerSecret(s);
	registerHeaderMapSecrets(opts?.authHeaders);
	if (opts?.roleHeaders) {
		for (const hdrMap of Object.values(opts.roleHeaders)) {
			registerHeaderMapSecrets(hdrMap);
		}
	}
	if (opts?.initialCookies) {
		for (const cv of Object.values(opts.initialCookies)) registerSecret(cv);
	}
	if (opts?.initialVars) {
		for (const [vk, vv] of Object.entries(opts.initialVars)) {
			if (SENSITIVE_VAR_NAME_RE.test(vk)) registerSecret(vv);
		}
	}

	const recorder =
		opts?.recorder ??
		new TrafficRecorder(normRoot, {
			vault: resolvedVault,
			extraSecrets: [...collectedSecrets],
		});
	recorderRef = recorder;
	for (const sec of collectedSecrets) {
		recorder.registerTransientSecret(sec);
	}

	const buildRedactedVarsSnapshot = (vars: Record<string, string>): Record<string, string> => {
		const out: Record<string, string> = {};
		for (const [k, v] of Object.entries(vars)) {
			if (SENSITIVE_VAR_NAME_RE.test(k) || collectedSecrets.has(v)) {
				out[k] = REDACTED_MARKER;
			} else if (k === "oobCallbackUrl" || /^https?:\/\//i.test(v)) {
				out[k] = redactTrafficUrl(v, {
					root: normRoot,
					vault: resolvedVault,
					extraSecrets: [...collectedSecrets],
				});
			} else {
				out[k] = scrubAllChainText(v, collectedSecrets, normRoot, resolvedVault);
			}
		}
		return out;
	};

	const finalizeFailure = (params: {
		stepIndex: number;
		factId: string;
		failureKind: ChainFailureKind;
		rawReason: string;
		obsType: BeliefObservation["type"];
		obsWeight?: number;
		stepTraces: ChainStepTrace[];
		currentVars: Record<string, string>;
		oobConfirmed?: boolean;
	}): ChainExecutionResult => {
		const safeReason = scrubAllChainText(params.rawReason, collectedSecrets, normRoot, resolvedVault);
		const beliefObservation: BeliefObservation = {
			type: params.obsType,
			weight: params.obsWeight ?? 1.0,
			note: safeReason,
			at: new Date().toISOString(),
		};
		const res: ChainExecutionResult = {
			chainId: chain?.id ?? "chain:invalid",
			verified: false,
			brokenAtStep: params.stepIndex,
			brokenFactId: params.factId,
			failureKind: params.failureKind,
			reason: safeReason,
			beliefObservation,
			stepTraces: params.stepTraces,
			redactedVariables: buildRedactedVarsSnapshot(params.currentVars),
			...(params.oobConfirmed !== undefined ? { oobConfirmed: params.oobConfirmed } : {}),
		};
		if (opts?.applyBeliefUpdate && opts.beliefGraph && opts.state) {
			const prop = applyChainResultToBeliefGraph(res, opts.beliefGraph, opts.state);
			if (prop) res.beliefPropagation = prop;
		}
		return res;
	};

	if (!chain || !Array.isArray(chain.steps) || chain.steps.length === 0) {
		return finalizeFailure({
			stepIndex: 0,
			factId: "",
			failureKind: "network_error",
			rawReason: "攻击链步骤列表为空，无法执行验证",
			obsType: "soft404_miss",
			stepTraces: [],
			currentVars: {},
		});
	}

	// 2. 校验可选受控 OOB 回调接收器与轮询端点安全性（严格锁死本机 127.0.0.1 或授权 Scope/oobDomains）
	const currentVars: Record<string, string> = { ...(opts?.initialVars ?? {}) };
	let currentCookies: Record<string, string> = { ...(opts?.initialCookies ?? {}) };
	// 为每次验证生成唯一一次性关联 Canary 参数，防止历史陈旧 OOB 记录导致假阳性
	const oobCorrelationToken = `nuwa_cid_${randomBytes(6).toString("hex")}`;

	if (opts?.oobCallbackUrl) {
		const oobCheck = validateControlledOobEndpoint(opts.oobCallbackUrl, scope, "OOB 回调接收器");
		if (!oobCheck.ok) {
			const lastIdx = chain.steps.length - 1;
			return finalizeFailure({
				stepIndex: lastIdx,
				factId: chain.steps[lastIdx]!.factId,
				failureKind: "scope_blocked",
				rawReason: oobCheck.reason,
				obsType: "waf_block",
				obsWeight: 1.5,
				stepTraces: [],
				currentVars,
				oobConfirmed: false,
			});
		}
		const correlatedCbUrl = new URL(oobCheck.parsed.toString());
		if (!correlatedCbUrl.searchParams.has("__nuwa_cid")) {
			correlatedCbUrl.searchParams.set("__nuwa_cid", oobCorrelationToken);
		}
		const encodedCbHref = encodeURIComponent(correlatedCbUrl.toString());
		currentVars.oobCallbackUrl = encodedCbHref;
		currentVars.callbackUrl = encodedCbHref;
		currentVars.callback = encodedCbHref;
	}

	if (opts?.oobPollUrl) {
		const pollCheck = validateControlledOobEndpoint(opts.oobPollUrl, scope, "OOB 轮询端点");
		if (!pollCheck.ok) {
			const lastIdx = chain.steps.length - 1;
			return finalizeFailure({
				stepIndex: lastIdx,
				factId: chain.steps[lastIdx]!.factId,
				failureKind: "scope_blocked",
				rawReason: pollCheck.reason,
				obsType: "waf_block",
				obsWeight: 1.5,
				stepTraces: [],
				currentVars,
				oobConfirmed: false,
			});
		}
	}

	// 3. 解析基础 URL 并编译为只读合规 TrafficStep[]
	const inferredBaseUrl =
		opts?.baseUrl?.trim() ||
		opts?.state?.project?.url?.trim() ||
		chain.steps.find((s) => s.endpoint && /^https?:\/\//i.test(s.endpoint))?.endpoint ||
		"http://127.0.0.1";

	const trafficSteps = compileChainToTrafficSequence(chain, inferredBaseUrl, {
		oobCallbackUrl: opts?.oobCallbackUrl,
		authHeaders: opts?.authHeaders,
		roleHeaders: opts?.roleHeaders,
		vault: resolvedVault,
		root: normRoot,
		timeoutMs,
	});

	// 4. 在目标主机处于授权 Scope 内时自动采样 Soft-404 基线（零越界保证）
	let soft404Baseline: Soft404BaselineInput | Soft404Baseline | null = opts?.soft404Baseline ?? null;
	if (!soft404Baseline && opts?.autoSampleSoft404 !== false) {
		try {
			const originUrl = new URL(normalizeBaseOrigin(inferredBaseUrl));
			const inScope = isHostInScope(originUrl.hostname, scope);
			const cmdCheck = checkScopeAndRisk(`curl -X GET ${originUrl.toString()}`, scope, mode, {
				layer: "egress-proxy",
			});
			if (inScope.ok && !cmdCheck?.block) {
				soft404Baseline = await sampleSoft404Baseline(
					originUrl.origin,
					opts?.fetchFn
						? async (u, init) => {
								const r = await opts.fetchFn!(u, init);
								return {
									ok: r.ok ?? (r.status >= 200 && r.status < 400),
									status: r.status,
									text: () => r.text(),
									headers:
										r.headers && "get" in r.headers && typeof r.headers.get === "function"
											? (r.headers as { get(name: string): string | null })
											: undefined,
								};
							}
						: undefined,
					{ timeoutMs: Math.min(3_000, timeoutMs), signal: opts?.signal },
				);
			}
		} catch {
			soft404Baseline = null;
		}
	}

	// 包装底层 fetchFn：强制锁定只读方法，并在响应落盘至 TrafficRecorder 前即时捕获动态敏感票据注册脱敏
	const rawFetcher: TrafficFetchFn =
		opts?.fetchFn ??
		((url, init) =>
			fetch(url, {
				method: init?.method,
				headers: init?.headers,
				body: init?.body,
				redirect: init?.redirect ?? "manual",
				signal: init?.signal,
			}));

	const guardedFetchFn: TrafficFetchFn = async (url, init) => {
		const reqMethod = normalizeReadonlyMethod(init?.method);
		registerHeaderMapSecrets(init?.headers);
		const resp = await rawFetcher(url, {
			...init,
			method: reqMethod,
			body: undefined,
		});
		if (resp.headers) {
			const hdrs = resp.headers as {
				getSetCookie?: () => string[];
				forEach?: (cb: (v: string, k: string) => void) => void;
				get?: (name: string) => string | null;
			};
			if (typeof hdrs.getSetCookie === "function") {
				try {
					for (const sc of hdrs.getSetCookie()) {
						registerCookieHeaderSecrets(sc);
					}
				} catch {
					/* ignore */
				}
			}
			if (typeof hdrs.forEach === "function") {
				hdrs.forEach((hv, hk) => {
					const lowerHk = hk.toLowerCase();
					if (lowerHk === "set-cookie" || lowerHk === "cookie") {
						registerCookieHeaderSecrets(hv);
					} else if (SENSITIVE_VAR_NAME_RE.test(hk)) {
						registerSecret(hv.trim());
					}
				});
			} else if (typeof resp.headers === "object" && !("get" in resp.headers && typeof hdrs.get === "function")) {
				for (const [hk, hv] of Object.entries(resp.headers as Record<string, unknown>)) {
					const lowerHk = hk.toLowerCase();
					if (lowerHk === "set-cookie" || lowerHk === "cookie") {
						if (Array.isArray(hv)) {
							for (const item of hv) {
								if (typeof item === "string") registerCookieHeaderSecrets(item);
							}
						} else if (typeof hv === "string") {
							registerCookieHeaderSecrets(hv);
						}
					} else if (SENSITIVE_VAR_NAME_RE.test(hk) && typeof hv === "string") {
						registerSecret(hv.trim());
					}
				}
			} else if (typeof hdrs.get === "function") {
				const sc = hdrs.get("set-cookie");
				if (sc) registerCookieHeaderSecrets(sc);
			}
		}
		let cachedBody: string | undefined;
		return {
			status: resp.status,
			ok: resp.ok,
			headers: resp.headers,
			async text(): Promise<string> {
				if (cachedBody === undefined) {
					cachedBody = await resp.text();
					const newlyFound = new Set<string>();
					extractSensitiveValuesFromJson(cachedBody, newlyFound);
					for (const val of newlyFound) {
						registerSecret(val);
					}
				}
				return cachedBody;
			},
		};
	};

	// 4b. 若提供了 oobPollUrl，在执行第 0 跳之前预采样历史命中基线计数与条目签名，严防历史记录造成误报
	const parsePollSnapshot = (pollText: string): { count: number; itemSigs: Set<string> } => {
		const sigs = new Set<string>();
		let count = 0;
		const parsedPoll = tryParseJsonFromText(pollText);
		if (parsedPoll && typeof parsedPoll === "object") {
			const obj = parsedPoll as Record<string, unknown>;
			const hitsArr = Array.isArray(obj.hits)
				? obj.hits
				: Array.isArray(obj.events)
					? obj.events
					: Array.isArray(obj.data)
						? obj.data
						: Array.isArray(parsedPoll)
							? (parsedPoll as unknown[])
							: [];
			for (const item of hitsArr) {
				try {
					sigs.add(typeof item === "string" ? item : JSON.stringify(item));
				} catch {
					/* ignore */
				}
			}
			count = Math.max(hitsArr.length, Number(obj.count ?? 0) || 0);
		}
		return { count, itemSigs: sigs };
	};

	let oobBaselineCount = 0;
	let oobBaselineSigs = new Set<string>();
	if (opts?.oobPollUrl) {
		try {
			const preResp = await guardedFetchFn(opts.oobPollUrl, {
				method: "GET",
				headers: { Accept: "application/json, text/plain, */*" },
				redirect: "manual",
				signal: opts.signal,
			});
			const preText = await preResp.text();
			if (preResp.status >= 200 && preResp.status < 300 && preText.trim()) {
				const snap = parsePollSnapshot(preText);
				oobBaselineCount = snap.count;
				oobBaselineSigs = snap.itemSigs;
			}
		} catch {
			oobBaselineCount = 0;
			oobBaselineSigs = new Set<string>();
		}
	}

	// 保存从动态路由模板（如 callbackTemplate 含 ?k={{v}}）剥离出的附加查询模板键值对
	const extractedRouteQueryTemplates: Array<[string, string]> = [];

	// 5. 逐跳有状态执行 replayTrafficSequence，遇阻立即精确定界熔断
	const stepTraces: ChainStepTrace[] = [];
	let lastStepReplay: ReplayStepResult | undefined;

	for (let k = 0; k < trafficSteps.length; k++) {
		let tStep = trafficSteps[k]!;
		const cStep = chain.steps[k]!;

		// 若本步使用了 {{leakedRoute}} 且上游提取的 callbackTemplate 带有自定义查询参数模板，安全合并入本步顶层 URL
		if (tStep.url.includes("{{leakedRoute}}") && extractedRouteQueryTemplates.length > 0) {
			let mergedUrl = tStep.url;
			for (const [qk, qTplVal] of extractedRouteQueryTemplates) {
				const normalizedTplVal = qTplVal.replace(/(?<!\{)\{([a-zA-Z0-9_.-]+)\}(?!\})/g, "{{$1}}");
				const escapedKey = escapeRegexLiteral(qk);
				if (!new RegExp(`[?&]${escapedKey}=`, "i").test(mergedUrl)) {
					const sep = mergedUrl.includes("?") ? "&" : "?";
					mergedUrl = `${mergedUrl}${sep}${encodeURIComponent(qk)}=${normalizedTplVal}`;
				}
			}
			tStep = { ...tStep, url: mergedUrl };
		}

		// 5a. 检查本步必需的上游模板变量是否已就绪；精准归因到声明提取该变量但未产出的上游步骤 j，否则归因当前步 k
		const neededVars = collectTemplatePlaceholders(tStep);
		const missingVars = neededVars.filter(
			(v) => currentVars[v] === undefined || String(currentVars[v]).trim() === "",
		);
		if (missingVars.length > 0) {
			const primaryMissing = missingVars[0]!;
			let producerStepIdx = -1;
			for (let j = k - 1; j >= 0; j--) {
				const prevExtracts = trafficSteps[j]?.extract;
				if (prevExtracts && Object.prototype.hasOwnProperty.call(prevExtracts, primaryMissing)) {
					producerStepIdx = j;
					break;
				}
			}
			const blameIdx = producerStepIdx >= 0 ? producerStepIdx : k;
			const blameStep = chain.steps[blameIdx]!;
			const rawMissingReason =
				producerStepIdx >= 0
					? `步骤 #${blameIdx + 1} (${blameStep.factId}) 未能从响应中提取下游必需变量 [${missingVars.join(", ")}]，已熔断后续步骤`
					: `步骤 #${blameIdx + 1} (${blameStep.factId}) 缺少必需绑定变量 [${missingVars.join(", ")}]，无法构造探测请求`;
			return finalizeFailure({
				stepIndex: blameIdx,
				factId: blameStep.factId,
				failureKind:
					(primaryMissing === "oobCallbackUrl" || primaryMissing === "callbackUrl" || primaryMissing === "callback") &&
					producerStepIdx < 0
						? "oob_not_triggered"
						: "missing_extracted_var",
				rawReason: rawMissingReason,
				obsType: "soft404_miss",
				obsWeight: 1.2,
				stepTraces,
				currentVars,
				...(primaryMissing === "oobCallbackUrl" ? { oobConfirmed: false } : {}),
			});
		}

		const replayRes = await replayTrafficSequence([tStep], scope, {
			fetchFn: guardedFetchFn,
			recorder,
			root: normRoot,
			mode,
			initialVars: currentVars,
			initialCookies: currentCookies,
			timeoutMs,
			signal: opts?.signal,
			tags: [`chain:${chain.id}`, `hop:${k}`],
		});

		currentCookies = { ...currentCookies, ...replayRes.cookies };
		for (const cv of Object.values(replayRes.cookies)) {
			registerSecret(cv);
		}

		const stepRes = replayRes.steps[0];
		if (!stepRes) {
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: "network_error",
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 未返回执行结果`,
				obsType: "timeout",
				stepTraces,
				currentVars,
			});
		}
		lastStepReplay = stepRes;

		// 登记提取到的变量：若提取到的路由变量附带查询模板（如 /api/dispatch?token={{antiReplayToken}}&cb={{callback}}），规范剥离查询模板防双 ? 与嵌套未展开
		for (const [vk, rawVv] of Object.entries(stepRes.extracted)) {
			let vv = rawVv;
			if (vk === "leakedRoute" || /(?:route|path|endpoint|template)$/i.test(vk)) {
				let candidatePath = vv.trim();
				if (/^https?:\/\//i.test(candidatePath)) {
					try {
						const parsedU = new URL(candidatePath);
						candidatePath = `${parsedU.pathname || "/"}${parsedU.search || ""}`;
					} catch {
						/* ignore */
					}
				}
				const qPos = candidatePath.indexOf("?");
				if (qPos >= 0) {
					const purePathname = candidatePath.slice(0, qPos) || "/";
					const rawQueryTpl = candidatePath.slice(qPos + 1);
					for (const seg of rawQueryTpl.split("&")) {
						const eq = seg.indexOf("=");
						if (eq > 0) {
							const qk = seg.slice(0, eq).trim();
							const qv = seg.slice(eq + 1).trim();
							if (qk && qv) {
								extractedRouteQueryTemplates.push([qk, qv]);
							}
						}
					}
					vv = purePathname.startsWith("/") ? purePathname : `/${purePathname}`;
				}
			}
			currentVars[vk] = vv;
			if (SENSITIVE_VAR_NAME_RE.test(vk)) {
				registerSecret(rawVv);
				registerSecret(vv);
			}
		}

		const soft404Check =
			!stepRes.blocked && stepRes.status > 0
				? detectSoft404(
						{
							url: stepRes.finalUrl,
							status: stepRes.status,
							body: stepRes.responseBody,
							headers: stepRes.responseHeaders,
						},
						soft404Baseline,
					)
				: { isSoft404: false, reasons: [] as string[] };

		const redactOpts = {
			root: normRoot,
			vault: resolvedVault,
			extraSecrets: [...collectedSecrets],
			maxChars: 512,
		};

		const redactedExtracted: Record<string, string> = {};
		for (const [ek, ev] of Object.entries(stepRes.extracted)) {
			redactedExtracted[ek] =
				SENSITIVE_VAR_NAME_RE.test(ek) || collectedSecrets.has(ev)
					? REDACTED_MARKER
					: scrubAllChainText(ev, collectedSecrets, normRoot, resolvedVault);
		}

		const trace: ChainStepTrace = {
			stepIndex: k,
			stepId: stepRes.id,
			factId: cStep.factId,
			method: normalizeReadonlyMethod(stepRes.method),
			redactedUrl: redactTrafficUrl(stepRes.finalUrl || stepRes.resolvedUrl, redactOpts),
			status: stepRes.status,
			ok: stepRes.ok && !soft404Check.isSoft404,
			blockedByScope: stepRes.blocked,
			isSoft404: soft404Check.isSoft404,
			durationMs: stepRes.durationMs,
			extractedVarNames: Object.keys(stepRes.extracted),
			redactedExtracted,
			redactedResponseSnippet:
				redactTrafficBody(stepRes.responseBody, redactOpts) ?? "",
			...(stepRes.recordedEntryId ? { recordedEntryId: stepRes.recordedEntryId } : {}),
		};
		stepTraces.push(trace);

		// 5b. 逐类阻断精准判定与信念观测映射（确保 trace.failureDetail 同样经过全量秘密擦除）
		if (stepRes.blocked || replayRes.abortedByScope) {
			const rawBlockDetail = stepRes.blockReason ?? replayRes.blockReason ?? "Scope 策略阻断";
			trace.failureDetail = scrubAllChainText(rawBlockDetail, collectedSecrets, normRoot, resolvedVault);
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: "scope_blocked",
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 被 Scope 护栏拦截: ${rawBlockDetail}`,
				obsType: "waf_block",
				obsWeight: 1.5,
				stepTraces,
				currentVars,
			});
		}

		if (stepRes.timedOut) {
			const rawTimeoutDetail = stepRes.error ?? "请求超时";
			trace.failureDetail = scrubAllChainText(rawTimeoutDetail, collectedSecrets, normRoot, resolvedVault);
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: "timeout",
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 请求超时 (${timeoutMs}ms)`,
				obsType: "timeout",
				obsWeight: 1.0,
				stepTraces,
				currentVars,
			});
		}

		if (stepRes.error || stepRes.status === 0) {
			const rawErrDetail = stepRes.error ?? "网络请求异常";
			trace.failureDetail = scrubAllChainText(rawErrDetail, collectedSecrets, normRoot, resolvedVault);
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: "network_error",
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 网络错误: ${rawErrDetail}`,
				obsType: "timeout",
				obsWeight: 1.0,
				stepTraces,
				currentVars,
			});
		}

		if (stepRes.status === 401 || stepRes.status === 403) {
			const fKind: ChainFailureKind = stepRes.status === 401 ? "auth_401" : "auth_403";
			trace.failureDetail = `HTTP ${stepRes.status} 严格鉴权/访问控制拦截`;
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: fKind,
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 被 HTTP ${stepRes.status} 严格鉴权加固阻断`,
				obsType: "waf_block",
				obsWeight: 1.35,
				stepTraces,
				currentVars,
			});
		}

		if (stepRes.status === 404 || soft404Check.isSoft404) {
			const fKind: ChainFailureKind = stepRes.status === 404 ? "http_404" : "soft_404";
			trace.failureDetail =
				stepRes.status === 404
					? "HTTP 404 端点不存在"
					: `命中 Soft-404 兜底页 (${soft404Check.reasons.join("; ") || "基线匹配"})`;
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: fKind,
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 未命中有效端点: ${trace.failureDetail}`,
				obsType: "soft404_miss",
				obsWeight: 1.15,
				stepTraces,
				currentVars,
			});
		}

		if (stepRes.status < 200 || stepRes.status >= 400) {
			trace.failureDetail = `HTTP ${stepRes.status} 非预期响应状态`;
			return finalizeFailure({
				stepIndex: k,
				factId: cStep.factId,
				failureKind: "http_error",
				rawReason: `步骤 #${k + 1} (${cStep.factId}) 返回异常状态码 HTTP ${stepRes.status}`,
				obsType: stepRes.status === 429 ? "waf_block" : "soft404_miss",
				obsWeight: 1.0,
				stepTraces,
				currentVars,
			});
		}
	}

	// 6. 终局目标实锤核验：OOB 回调接收器核实 + 正向证据门禁反误报去噪
	const finalIdx = chain.steps.length - 1;
	const finalChainStep = chain.steps[finalIdx]!;
	const isOobChain =
		chain.terminalCapabilities.includes("cap:oob_channel") ||
		Boolean(opts?.oobCallbackUrl || opts?.oobPollUrl || opts?.verifyOobHit);

	let oobConfirmed: boolean | undefined;
	let oobEvidenceDetail = "";

	if (isOobChain) {
		oobConfirmed = false;
		// 严禁 OOB 攻击链在未提供任何回调核验手段时回退普通响应长度检查造成盲报
		if (!opts?.verifyOobHit && !opts?.oobPollUrl) {
			return finalizeFailure({
				stepIndex: finalIdx,
				factId: finalChainStep.factId,
				failureKind: "oob_not_triggered",
				rawReason: `终局步骤 #${finalIdx + 1} (${finalChainStep.factId}) 属于 OOB 验证链但缺少回调核验源 (verifyOobHit / oobPollUrl)，拒绝无证据盲报`,
				obsType: "soft404_miss",
				obsWeight: 1.25,
				stepTraces,
				currentVars,
				oobConfirmed: false,
			});
		}

		if (opts.verifyOobHit) {
			const hitRes = await opts.verifyOobHit({ chain, variables: { ...currentVars } });
			oobConfirmed = Boolean(hitRes.hit);
			if (hitRes.detail) oobEvidenceDetail = hitRes.detail;
		} else if (opts.oobPollUrl) {
			const pollResp = await guardedFetchFn(opts.oobPollUrl, {
				method: "GET",
				headers: { Accept: "application/json, text/plain, */*" },
				redirect: "manual",
				signal: opts.signal,
			});
			const pollText = await pollResp.text();
			if (pollResp.status >= 200 && pollResp.status < 300 && pollText.trim()) {
				const postSnap = parsePollSnapshot(pollText);
				const matchedCid = opts.oobCallbackUrl ? pollText.includes(oobCorrelationToken) : false;
				let newItemCount = 0;
				for (const sig of postSnap.itemSigs) {
					if (!oobBaselineSigs.has(sig)) newItemCount++;
				}
				const countDelta = postSnap.count - oobBaselineCount;
				// 必须匹配本次一次性关联标识 __nuwa_cid，或存在严格大于发包前基线的新增回调记录
				if (matchedCid || newItemCount > 0 || countDelta > 0) {
					oobConfirmed = true;
					oobEvidenceDetail = pollText;
				}
			}
		}

		if (!oobConfirmed) {
			return finalizeFailure({
				stepIndex: finalIdx,
				factId: finalChainStep.factId,
				failureKind: "oob_not_triggered",
				rawReason: `终局步骤 #${finalIdx + 1} (${finalChainStep.factId}) 未触发本机/授权 OOB 回调接收器新增命中，拒绝盲报`,
				obsType: "soft404_miss",
				obsWeight: 1.25,
				stepTraces,
				currentVars,
				oobConfirmed: false,
			});
		}
	}

	// 正向假阳性门禁校验（拦截 <64B 空壳、{"ok":false} 错误信封及与未授权负向基线哈希一致的响应）
	const finalBody = lastStepReplay?.responseBody ?? "";
	const finalStatus = lastStepReplay?.status ?? 200;

	if (!oobConfirmed) {
		const fpVerdict = evaluatePositiveEvidenceGate({
			kind: "vuln",
			output: finalBody,
			response: {
				statusCode: finalStatus,
				body: finalBody,
				bodyBytes: computeBodyHash(finalBody).bodyBytes,
				headers: lastStepReplay?.responseHeaders,
			},
			baseline: opts?.negativeBaseline,
			requireBusinessPayload: true,
		});

		if (fpVerdict.falsePositive) {
			return finalizeFailure({
				stepIndex: finalIdx,
				factId: finalChainStep.factId,
				failureKind: "false_positive_filtered",
				rawReason: `终局步骤 #${finalIdx + 1} (${finalChainStep.factId}) 被反误报门禁拦截: ${fpVerdict.reason ?? "缺少实质业务数据"}`,
				obsType: "soft404_miss",
				obsWeight: 1.25,
				stepTraces,
				currentVars,
				...(oobConfirmed !== undefined ? { oobConfirmed } : {}),
			});
		}
	} else if (opts?.negativeBaseline) {
		// 即便 OOB 命中，若显式提供了负向基线也确保回调详情已脱敏记录
		extractSensitiveValuesFromJson(oobEvidenceDetail, collectedSecrets);
	}

	// 7. 全链打穿：组装 100% 脱敏的逐跳证据链、待双盲复验 candidate 复合 Fact 与 verify-vuln:<fid> 建议
	const candidateId =
		opts?.candidateFactId?.trim() ||
		(opts?.state?.seq?.fact !== undefined
			? `f${String(opts.state.seq.fact + 1).padStart(3, "0")}`
			: `f_chain_${sha1Short(chain.id, 8)}`);

	const redactedHopLines = stepTraces.map(
		(t) =>
			`[Hop ${t.stepIndex + 1}/${stepTraces.length}] (${t.factId}) ${t.method} ${t.redactedUrl} -> HTTP ${t.status} (${t.durationMs}ms)` +
			(t.extractedVarNames.length > 0 ? ` | 提取变量: ${t.extractedVarNames.join(", ")}` : "") +
			(t.redactedResponseSnippet ? `\n  响应摘要: ${t.redactedResponseSnippet}` : ""),
	);
	if (oobConfirmed) {
		const safeOobSnippet = scrubAllChainText(
			oobEvidenceDetail || "本机 127.0.0.1 受控 OOB 接收器已实锤捕获回调请求",
			collectedSecrets,
			normRoot,
			resolvedVault,
		);
		redactedHopLines.push(`[OOB 回调实锤] ${oneLine(safeOobSnippet, 280)}`);
	}

	const redactedFullOutput = scrubAllChainText(
		redactedHopLines.join("\n"),
		collectedSecrets,
		normRoot,
		resolvedVault,
	);
	const redactedCommandSummary = scrubAllChainText(
		stepTraces.map((t) => `${t.method} ${t.redactedUrl}`).join(" && "),
		collectedSecrets,
		normRoot,
		resolvedVault,
	);
	const safeChainTitle = scrubAllChainText(
		`多跳组合漏洞候选 (${chain.depth} 跳): ${chain.factIds.join(" -> ")} -> ${chain.terminalCapabilities.join("+")}`,
		collectedSecrets,
		normRoot,
		resolvedVault,
	);
	const safeChainDetail = scrubAllChainText(
		[
			`攻击链 ID: ${chain.id} | 效用分: ${chain.utilityScore.toFixed(2)} | 链后验: ${chain.chainBelief.toFixed(3)}`,
			`串联事实: ${chain.factIds.join(" -> ")}${chain.supportingFactIds.length > 0 ? ` (辅助前置: ${chain.supportingFactIds.join(", ")})` : ""}`,
			`终局达成能力: ${chain.terminalCapabilities.join(", ")}${oobConfirmed ? " [含本机受控 OOB 回调实锤]" : ""}`,
			`状态说明: 自动化只读有状态重放已打穿全链，当前标记为 candidate 等待独立 nuwa-verifier 双盲复验。`,
		].join("\n"),
		collectedSecrets,
		normRoot,
		resolvedVault,
	);

	// 同步将脱敏后的多跳重放证据记入 exec-ledger，便于后续独立审计溯源
	if (opts?.recordLedger !== false) {
		recordToolExecution(normRoot, {
			tool: "http",
			command: redactedCommandSummary,
			output: redactedFullOutput,
			agentName: "chain-composer",
		});
	}

	const finalUrlPath = (() => {
		try {
			return new URL(stepTraces[finalIdx]!.redactedUrl).pathname;
		} catch {
			return finalChainStep.endpoint;
		}
	})();

	const candidateFact: Fact = {
		id: candidateId,
		kind: "vuln",
		title: safeChainTitle,
		detail: safeChainDetail,
		command: redactedCommandSummary,
		output: redactedFullOutput,
		key: `vuln:chain:${chain.id}`,
		createdAt: new Date().toISOString(),
		verified: false,
		verifyStage: "candidate",
		verifyNote: "由 chain-composer 多跳只读重放合成，待双盲独立复验（反自证守卫）",
		surfaceDomain: "path",
		...(finalUrlPath ? { targetKey: finalUrlPath } : {}),
		meta: {
			status: finalStatus,
			...(finalUrlPath ? { paths: [finalUrlPath] } : {}),
		},
		agentResult: {
			chainId: chain.id,
			depth: chain.depth,
			factIds: [...chain.factIds],
			terminalCapabilities: [...chain.terminalCapabilities],
			...(oobConfirmed !== undefined ? { oobConfirmed } : {}),
		},
	};

	const verifySuggestionKey: `verify-vuln:${string}` = `verify-vuln:${candidateId}`;
	const verifyRecommendation: VerifyVulnRecommendation = {
		key: verifySuggestionKey,
		factId: candidateId,
		phase: "vuln",
		title: `双盲复验多跳攻击链候选漏洞 (${candidateId})`,
		detail: scrubAllChainText(
			`请由独立复验代理 nuwa-verifier 在隔离上下文下对候选多跳链 ${chain.id} (${chain.factIds.join(" -> ")}) 执行只读合规复验，严禁复用候选阶段旧输出。`,
			collectedSecrets,
			normRoot,
			resolvedVault,
		),
		priority: 94,
		from: uniqStrings([candidateId, ...chain.factIds, ...chain.supportingFactIds]),
	};

	const successReason = scrubAllChainText(
		`全链 ${chain.depth} 跳只读合规验证通过，已产出待双盲复验候选漏洞 ${candidateId} 及 ${verifySuggestionKey}`,
		collectedSecrets,
		normRoot,
		resolvedVault,
	);
	const beliefObservation: BeliefObservation = {
		type: "breakthrough_signal",
		weight: 1.5,
		note: successReason,
		at: new Date().toISOString(),
	};

	const result: ChainExecutionResult = {
		chainId: chain.id,
		verified: true,
		reason: successReason,
		beliefObservation,
		stepTraces,
		redactedVariables: buildRedactedVarsSnapshot(currentVars),
		...(oobConfirmed !== undefined ? { oobConfirmed } : {}),
		candidateFact,
		verifyRecommendation,
		verifySuggestionKey,
	};

	if (opts?.applyBeliefUpdate && opts.beliefGraph && opts.state) {
		const prop = applyChainResultToBeliefGraph(result, opts.beliefGraph, opts.state);
		if (prop) result.beliefPropagation = prop;
	}

	return result;
}
