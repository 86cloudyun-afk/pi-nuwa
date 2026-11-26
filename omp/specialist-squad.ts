/**
 * 女娲 v7.0 专精特种小队（5+1 Specialist Squad）意图分发与机械对账战绩联合路由引擎。
 *
 * 核心职责：
 * 1. 定义 5+1 专精角色体系（`nuwa-scout` / `nuwa-spa-reverser` / `nuwa-auth-breaker` /
 *    `nuwa-code-auditor` / `nuwa-verifier` + 通用兜底 `fujiang`）的能力画像、技术栈亲和度与默认任务类别；
 * 2. 提供确定性意图分派器 `classifyIntentForSpecialist(intent, state)`，精准将侦察测绘、现代前端逆向、
 *    多角色鉴权越权、白盒源码审计、双盲独立复验及通用任务路由至最佳专精角色；
 * 3. 提供战绩联动联合路由器 `recommendSpecialistAndModel(intent, state, calibrationRecords, opts?)`，
 *    严格遵循 `calibration.ts` 反自证机械结算原则，融合 `specialistRole × taskCategory × model`
 *    历史命中率、假阳性误报率与 Token ROI 执行角色与模型的联合择优，支持冷启动安全保护并 100% 严守
 *    `allowedModels` 白名单不越界。
 *
 * 架构约束：严禁运行时导入 `./nuwa`，仅依赖 `./calibration` 与 `import type` 引用 `./types`，零第三方依赖。
 */
import type { Intent, NuwaState, Phase } from "./types";
import {
	ALLOWED_SETTLEMENT_SOURCES,
	CalibrationError,
	VALID_TASK_CATEGORIES,
	computeCalibrationSummary,
	recommendAdaptiveModelRoute,
	type AdaptiveModelRouteDecision,
	type CalibrationDimensionMetrics,
	type CalibrationRecord,
	type CalibrationSettlementSource,
	type CalibrationSummary,
	type CalibrationTaskCategory,
} from "./calibration";

export type SpecialistRole =
	| "nuwa-scout"
	| "nuwa-spa-reverser"
	| "nuwa-auth-breaker"
	| "nuwa-code-auditor"
	| "nuwa-verifier"
	| "fujiang";

export const SPECIALIST_ROLES: readonly SpecialistRole[] = [
	"nuwa-scout",
	"nuwa-spa-reverser",
	"nuwa-auth-breaker",
	"nuwa-code-auditor",
	"nuwa-verifier",
	"fujiang",
] as const;

export const VALID_SPECIALIST_ROLES: ReadonlySet<SpecialistRole> = new Set(SPECIALIST_ROLES);

export const DEFAULT_ALLOWED_SPECIALIST_MODELS: readonly string[] = [
	"gemini-4-hydrogen-xhigh",
	"gemini-4-neon-xhigh",
	"gemini-4-carbon-high",
] as const;

export type SpecialistModelTier = "fast" | "standard" | "deep";

export interface SpecialistProfile {
	role: SpecialistRole;
	label: string;
	agentTemplatePath: string;
	defaultTaskCategory: CalibrationTaskCategory;
	preferredModelTier: SpecialistModelTier;
	defaultModel: string;
	priority: number;
	isFallback: boolean;
	specialties: readonly string[];
	techStacks: readonly string[];
	phases: readonly Phase[];
	description: string;
}

/**
 * 女娲 5+1 专精特种小队角色注册表。
 */
export const NUWA_SPECIALIST_SQUAD: Readonly<Record<SpecialistRole, SpecialistProfile>> = {
	"nuwa-scout": {
		role: "nuwa-scout",
		label: "高速侦察与拓扑测绘专家",
		agentTemplatePath: "agents/nuwa-scout.md",
		defaultTaskCategory: "recon",
		preferredModelTier: "fast",
		defaultModel: "gemini-4-hydrogen-xhigh",
		priority: 80,
		isFallback: false,
		specialties: [
			"端口与协议指纹测绘",
			"Soft-404 与错误壳负向基线标定",
			"CDN/WAF 边缘拦截甄别",
			"TLS SAN 与多资产拓扑发现",
		],
		techStacks: ["http", "tls", "nginx", "cloudflare", "envoy", "traefik", "openapi", "dns"],
		phases: ["recon", "surface"],
		description: "以最小无害探针快速摸清暴露面、服务指纹、边缘网关特征及 Soft-404 负向基线哈希。",
	},
	"nuwa-spa-reverser": {
		role: "nuwa-spa-reverser",
		label: "现代前端与接口契约逆向专家",
		agentTemplatePath: "agents/nuwa-spa-reverser.md",
		defaultTaskCategory: "js-audit",
		preferredModelTier: "standard",
		defaultModel: "gemini-4-neon-xhigh",
		priority: 85,
		isFallback: false,
		specialties: [
			"SPA Webpack/Vite Bundle 静态拆解",
			"SourceMap (.js.map) 真伪核验与源码树提取",
			"Next.js App Router / RSC / Server Actions 契约梳理",
			"GraphQL Schema 与前端动态请求加签逻辑逆向",
		],
		techStacks: ["nextjs", "react", "rsc", "vue", "nuxt", "vite", "webpack", "graphql", "webcrypto"],
		phases: ["surface", "recon", "vuln"],
		description: "只读分析现代前端构建产物、SourceMap、RSC 流与签名拦截器，还原隐藏 API 路由与接口契约。",
	},
	"nuwa-auth-breaker": {
		role: "nuwa-auth-breaker",
		label: "多角色鉴权差分与状态机核验专家",
		agentTemplatePath: "agents/nuwa-auth-breaker.md",
		defaultTaskCategory: "auth",
		preferredModelTier: "standard",
		defaultModel: "gemini-4-neon-xhigh",
		priority: 88,
		isFallback: false,
		specialties: [
			"匿名/低权/高权多视角 AuthDiff 权限矩阵比对",
			"IDOR / BOLA 对象级与 BFLA 功能级越权核验",
			"OAuth2 / OIDC / JWT / Session 令牌边界审查",
			"多步业务状态机跳步与并发幂等性窗口合规评估",
		],
		techStacks: ["oauth2", "oidc", "jwt", "session", "rbac", "abac", "reverse-proxy", "graphql", "rest"],
		phases: ["vuln", "surface", "exploit"],
		description: "利用受控多角色会话执行正负对照差分实验，精准检出越权、网关路径规范化绕过与状态机边界缺陷。",
	},
	"nuwa-code-auditor": {
		role: "nuwa-code-auditor",
		label: "多语言白盒与动静协同代码审计专家",
		agentTemplatePath: "agents/nuwa-code-auditor.md",
		defaultTaskCategory: "whitebox",
		preferredModelTier: "deep",
		defaultModel: "gemini-4-carbon-high",
		priority: 92,
		isFallback: false,
		specialties: [
			"TS/JS/Python/Go/Java 全量路由与鉴权中间件矩阵梳理",
			"Source → Sanitizer → Sink 污点可达性追踪",
			"反序列化、ORM 动态拼接与路径穿越白盒定位",
			"源码 file:line 锚点与在线灰盒可达性协同核验",
		],
		techStacks: ["typescript", "nextjs", "fastapi", "django", "spring-boot", "java", "golang", "gin", "echo"],
		phases: ["surface", "vuln", "recon"],
		description: "开展深度白盒路由鉴权审查与完整污点数据流分析，输出精确源码行号锚点与加固方案。",
	},
	"nuwa-verifier": {
		role: "nuwa-verifier",
		label: "双盲独立证伪复验专家",
		agentTemplatePath: "agents/nuwa-verifier.md",
		defaultTaskCategory: "verify",
		preferredModelTier: "deep",
		defaultModel: "gemini-4-carbon-high",
		priority: 100,
		isFallback: false,
		specialties: [
			"候选漏洞（candidate）双盲独立重放",
			"正负对照实验与 body_sha256 逐字节比对",
			"Soft-404 外壳与 <64B 微小错误信封拦截",
			"实测证据五项指标完整性裁定",
		],
		techStacks: ["http", "rest", "graphql", "spa", "cloud", "auth"],
		phases: ["vuln", "exploit", "post", "report"],
		description: "站在挑刺证伪立场对候选发现执行双盲正负对照复验，彻底剔除 Soft-404 与幻觉假阳性。",
	},
	fujiang: {
		role: "fujiang",
		label: "通用现场执行与取证子代理",
		agentTemplatePath: "agents/fujiang.md",
		defaultTaskCategory: "general",
		preferredModelTier: "standard",
		defaultModel: "gemini-4-neon-xhigh",
		priority: 50,
		isFallback: true,
		specialties: [
			"通用协议与常规端点合规取证",
			"多阶段综合复核与兜底现场执行",
			"标准 curl -w 五项探针采集",
		],
		techStacks: ["general", "http", "linux", "containers", "database"],
		phases: ["recon", "surface", "vuln", "exploit", "post", "report"],
		description: "5+1 体系中的通用兜底执行器，承接未命中特定专精特征或需跨领域回退的标准取证派单。",
	},
};

export type SpecialistIntentLike = Partial<Intent> & {
	id?: string;
	key?: string;
	title?: string;
	detail?: string;
	phase?: Phase | string;
	worker?: string;
	authRole?: string;
	targetKey?: string;
};

export interface SpecialistClassification {
	role: SpecialistRole;
	taskCategory: CalibrationTaskCategory;
	confidence: number;
	matchedSignals: string[];
	fallbackRoles: SpecialistRole[];
	reason: string;
}

export interface SpecialistCalibrationRecord extends CalibrationRecord {
	/** 可选显式标注执行该预测任务的专精角色名。 */
	specialistRole?: SpecialistRole | string;
	/** 兼容子代理字段名。 */
	agent?: string;
	/** 兼容派单 worker 字段名。 */
	worker?: string;
}

export interface RecommendSpecialistOptions {
	/** 候选模型硬白名单（传空数组将显式抛 CalibrationError；未传默认使用 Gemini 4 主力白名单）。 */
	allowedModels?: readonly string[];
	/** 可选候选专精角色范围限制（默认允许全部 6 个合法 SpecialistRole）。 */
	allowedRoles?: readonly SpecialistRole[];
	/** 可选显式基准模型（若不在 allowedModels 中将自动钳制到白名单内）。 */
	defaultModel?: string;
	/** 可选高速模型偏好（用于侦察角色）。 */
	fastModel?: string;
	/** 可选深度推理模型偏好（用于白盒代码审计）。 */
	deepModel?: string;
	/** 可选独立复验模型偏好（用于双盲复验官）。 */
	verifyModel?: string;
	/** 冷启动最小有效机械结算样本数（默认 5）。 */
	minSamples?: number;
	/** 触发自动降权的最高允许假阳性误报率（默认 0.30）。 */
	maxFalsePositiveRate?: number;
	/** 触发自动降权的最低可接受 ROI 阈值（默认 0.12）。 */
	minRoiScore?: number;
	/** 是否锁定分类出的专精角色不进行跨角色降级切换（默认 false；nuwa-verifier 始终锁定）。 */
	lockSpecialistRole?: boolean;
	/** 跨角色择优切换所需的最小联合得分领先裕度（默认 0.12）。 */
	roleSwitchMargin?: number;
}

export interface SpecialistJointCandidate {
	role: SpecialistRole;
	modelId: string;
	taskCategory: CalibrationTaskCategory;
	settledCount: number;
	exactSliceCount: number;
	confirmedCount: number;
	falsePositiveCount: number;
	hitRate: number;
	precision: number;
	falsePositiveRate: number;
	tokensPerConfirmedFinding: number;
	roiScore: number;
	brierScore: number;
	ece: number;
	jointScore: number;
	coldStart: boolean;
	demoted: boolean;
	demoteReasons: string[];
}

export interface SpecialistAndModelRecommendation {
	/** 最终推荐专精角色。 */
	recommendedRole: SpecialistRole;
	/** 与 recommendedRole 同义，便于上下游直接解构。 */
	specialistRole: SpecialistRole;
	/** 最终推荐模型（100% 严格属于 allowedModels 白名单）。 */
	recommendedModel: string;
	/** 与 recommendedModel 同义，便于上下游直接解构。 */
	modelId: string;
	taskCategory: CalibrationTaskCategory;
	classification: SpecialistClassification;
	modelDecision: AdaptiveModelRouteDecision;
	calibrationSummary: CalibrationSummary;
	coldStart: boolean;
	roleSwitched: boolean;
	modelSwitched: boolean;
	acceptedMechanicalRecords: number;
	ignoredInvalidRecords: number;
	candidates: SpecialistJointCandidate[];
	reason: string;
}

interface SignalRule {
	label: string;
	weight: number;
	keyRe?: RegExp;
	textRe?: RegExp;
}

const VERIFY_SIGNALS: readonly SignalRule[] = [
	{
		label: "双盲复验意图键前缀",
		weight: 6.0,
		keyRe: /^(?:verify-vuln|verify-candidate|double-blind|verify|recheck)(?:[:/_-]|$)/i,
	},
	{
		label: "双盲独立证伪复验指令",
		weight: 5.5,
		textRe:
			/双盲(?:独立)?复验|独立(?:证伪)?复验|候选漏洞复验|证伪复核|nuwa-verifier|\bdouble[-\s]?blind\s+verif|\bfalsification\s+check\b|\bverify\s+candidate\b/i,
	},
	{
		label: "正负对照复核 candidate 证据",
		weight: 3.5,
		textRe: /(?:candidate|候选发现|疑似漏洞)[\s\S]{0,24}(?:正负对照|独立重放|复验裁定)/i,
	},
];

const CODE_AUDIT_SIGNALS: readonly SignalRule[] = [
	{
		label: "白盒/动静协同意图键",
		weight: 4.5,
		keyRe: /\b(?:whitebox|code-audit|sast|hybrid-audit|taint|source-sink|ast-audit|semgrep|repo-audit)\b/i,
	},
	{
		label: "污点追踪与源码行号锚点",
		weight: 4.2,
		textRe:
			/白盒(?:代码)?审计|源码审计|代码审计|动静协同|灰盒(?:路由|协同|代码)|污点(?:追踪|分析|链)|source\s*(?:->|→)\s*(?:sanitizer\s*(?:->|→)\s*)?sink|\bsourceAnchor\b|源码锚点|\bAST\b/i,
	},
	{
		label: "服务端框架源码结构特征",
		weight: 3.0,
		textRe:
			/\b(?:middleware\.ts|route\.ts|APIRouter|Depends\s*\(|SecurityFilterChain|@PreAuthorize|@UseGuards|ShouldBind|r\.Group\s*\(|MyBatis|ObjectInputStream|SnakeYAML|enableDefaultTyping|pom\.xml|build\.gradle|go\.mod)\b/i,
	},
];

const SPA_REVERSER_SIGNALS: readonly SignalRule[] = [
	{
		label: "前端逆向与契约提取意图键",
		weight: 4.5,
		keyRe: /\b(?:spa|js-audit|sourcemap|bundle|chunk|rsc|server-action|graphql-schema|frontend-sign|webpack|vite)\b/i,
	},
	{
		label: "SourceMap 与前端构建产物解析",
		weight: 4.2,
		textRe:
			/\.js\.map\b|\bsourcemap\b|\bsourceMappingURL\b|_buildManifest|_ssgManifest|_next\/static|\bwebpack\b|\bvite\b|前端(?:逆向|打包|源码|构建产物|路由提取)|SPA\s*(?:Bundle|路由|逆向|Chunk)/i,
	},
	{
		label: "Next.js RSC / GraphQL / 前端动态加签拆解",
		weight: 3.8,
		textRe:
			/\bApp\s*Router\b|\bRSC\b|\bServer\s*Actions?\b|\bNEXT_PUBLIC_[A-Z0-9_]*|\bGraphQL\b[\s\S]{0,20}(?:Introspection|Schema|契约|__schema|__typename|逆向)|(?:前端|客户端|JS|拦截器)(?:请求)?(?:加签|签名|验签)|subtle\.sign|axios\.interceptors|\bX-Signature\b/i,
	},
];

const AUTH_BREAKER_SIGNALS: readonly SignalRule[] = [
	{
		label: "鉴权差分与状态机意图键",
		weight: 4.5,
		keyRe:
			/\b(?:auth-diff|authdiff|auth|idor|bola|bfla|rbac|abac|jwt|oauth2?|oidc|pkce|session|csrf|race|toctou|idempotency|state-machine|privilege)\b/i,
	},
	{
		label: "越权访问与多角色权限差分",
		weight: 4.2,
		textRe:
			/越权|水平权限|垂直权限|跨租户|\bIDOR\b|\bBOLA\b|\bBFLA\b|多角色(?:会话|差分|对照)|\bAuthDiff\b|权限(?:绕过|矩阵|边界)|未授权访问(?:受保护|管理|他人)/i,
	},
	{
		label: "令牌协议、反代路径规范化与并发幂等状态机",
		weight: 3.6,
		textRe:
			/\bJWT\b|\bOAuth2?\b|\bOIDC\b|\bPKCE\b|\bredirect_uri\b|\balg\s*[:=]\s*none\b|路径规范化(?:差异|绕过)|状态机(?:跳步|绕过|边界)|并发竞态|条件竞争|\bTOCTOU\b|\bIdempotency-Key\b|幂等(?:性|边界|防重)/i,
	},
];

const SCOUT_SIGNALS: readonly SignalRule[] = [
	{
		label: "侦察测绘与基线标定意图键",
		weight: 4.2,
		keyRe:
			/\b(?:recon|port-scan|ports|fingerprint|banner|baseline|soft-404|soft404|waf|cdn|tls-san|cert|subdomain|robots|well-known|topology|asset-discovery)\b/i,
	},
	{
		label: "指纹识别、Soft-404 基线与边缘防护测绘",
		weight: 3.8,
		textRe:
			/端口(?:扫描|探测|测绘)|服务指纹|响应指纹|\bBanner\b|Soft-?404|负向基线|(?:CDN|WAF)\s*(?:边缘|拦截|识别|防护)|证书\s*SAN|\bSubject\s+Alternative\s+Name\b|拓扑测绘|暴露面(?:盘点|测绘)|\/robots\.txt|\.well-known\/security\.txt/i,
	},
];

function safeFinite(val: number, fallback = 0): number {
	return typeof val === "number" && Number.isFinite(val) ? val : fallback;
}

function clamp01(val: number): number {
	const v = safeFinite(val, 0);
	if (v <= 0) return 0;
	if (v >= 1) return 1;
	return v;
}

function evaluateSignals(
	keyText: string,
	fullText: string,
	rules: readonly SignalRule[],
): { score: number; matched: string[] } {
	let score = 0;
	const matched: string[] = [];
	for (const r of rules) {
		let hit = false;
		if (r.keyRe && keyText && r.keyRe.test(keyText)) {
			hit = true;
		}
		if (!hit && r.textRe && fullText && r.textRe.test(fullText)) {
			hit = true;
		}
		if (hit) {
			score += r.weight;
			matched.push(r.label);
		}
	}
	return { score, matched };
}

function buildFallbackChain(primary: SpecialistRole, ranked: readonly SpecialistRole[]): SpecialistRole[] {
	if (primary === "nuwa-verifier") {
		// 双盲独立复验严禁混入常规发现角色，保持证伪独立性
		return [];
	}
	const out: SpecialistRole[] = [];
	for (const r of ranked) {
		if (r !== primary && r !== "nuwa-verifier" && !out.includes(r)) {
			out.push(r);
		}
	}
	if (primary !== "fujiang" && !out.includes("fujiang")) {
		out.push("fujiang");
	}
	return out;
}

/**
 * 确定性专精角色意图分类器：
 * 根据派单 `key`、`title`、`detail`、`phase`、`authRole` 及全局 `NuwaState`（如 `audit` 模式、`repo` 资产、活跃会话角色）
 * 将任务精确分发给 5+1 专精特种小队成员。
 */
export function classifyIntentForSpecialist(
	intent: SpecialistIntentLike | null | undefined,
	state?: Partial<NuwaState> | null,
): SpecialistClassification {
	const safeIntent = intent ?? {};
	const keyText = String(safeIntent.key ?? "").trim();
	const titleText = String(safeIntent.title ?? "").trim();
	const detailText = String(safeIntent.detail ?? "").trim();
	const targetKeyText = String(safeIntent.targetKey ?? "").trim();
	const workerHint = String(safeIntent.worker ?? "").trim();
	const phase = String(safeIntent.phase ?? state?.project?.phase ?? "").trim();
	const fullText = [keyText, titleText, detailText, targetKeyText].filter(Boolean).join(" | ");

	// 1. 显式指定 nuwa-verifier 或强匹配双盲独立复验信号 -> 最高优先级锁定 nuwa-verifier
	if (workerHint === "nuwa-verifier") {
		return {
			role: "nuwa-verifier",
			taskCategory: "verify",
			confidence: 0.99,
			matchedSignals: ["显式指定 worker=nuwa-verifier"],
			fallbackRoles: [],
			reason: "派单显式指定独立复验官 nuwa-verifier，路由至双盲证伪复验通道。",
		};
	}

	const verifyEval = evaluateSignals(keyText, fullText, VERIFY_SIGNALS);
	if (verifyEval.score >= 5.0) {
		return {
			role: "nuwa-verifier",
			taskCategory: "verify",
			confidence: clamp01(0.85 + Math.min(0.14, verifyEval.score * 0.02)),
			matchedSignals: verifyEval.matched,
			fallbackRoles: [],
			reason: `命中双盲复验特征（${verifyEval.matched.join("、")}），分发给 nuwa-verifier 执行独立正负对照证伪。`,
		};
	}

	// 2. 评估其余四大专精领域信号得分
	const roleScores = new Map<SpecialistRole, { score: number; matched: string[] }>([
		["nuwa-code-auditor", evaluateSignals(keyText, fullText, CODE_AUDIT_SIGNALS)],
		["nuwa-spa-reverser", evaluateSignals(keyText, fullText, SPA_REVERSER_SIGNALS)],
		["nuwa-auth-breaker", evaluateSignals(keyText, fullText, AUTH_BREAKER_SIGNALS)],
		["nuwa-scout", evaluateSignals(keyText, fullText, SCOUT_SIGNALS)],
	]);

	// 融合上下文与状态图谱先验加权
	if (VALID_SPECIALIST_ROLES.has(workerHint as SpecialistRole) && workerHint !== "fujiang") {
		const entry = roleScores.get(workerHint as SpecialistRole);
		if (entry) {
			entry.score += 3.2;
			entry.matched.push(`派单建议角色 ${workerHint}`);
		}
	}

	const mode = state?.project?.mode;
	if (mode === "audit" || mode === "coding") {
		const auditEntry = roleScores.get("nuwa-code-auditor")!;
		auditEntry.score += 2.2;
		auditEntry.matched.push(`项目模式 mode=${mode}`);
	}

	const hasRepoAsset =
		state?.assets &&
		Object.values(state.assets).some((a) => Boolean(a && a.kind === "repo"));
	if (hasRepoAsset) {
		const auditEntry = roleScores.get("nuwa-code-auditor")!;
		auditEntry.score += 1.0;
		auditEntry.matched.push("资产图谱存在源码仓库节点(repo)");
	}

	if (safeIntent.authRole && String(safeIntent.authRole).trim()) {
		const authEntry = roleScores.get("nuwa-auth-breaker")!;
		authEntry.score += 2.8;
		authEntry.matched.push(`携带受控会话角色 authRole=${String(safeIntent.authRole).trim()}`);
	}

	const hasGraphqlFact =
		state?.facts &&
		Object.values(state.facts).some((f) => Boolean(f?.meta?.graphql || (f?.meta?.bundles && f.meta.bundles.length > 0)));
	if (hasGraphqlFact && /\b(?:bundle|chunk|graphql|spa|route|api)\b/i.test(fullText)) {
		const spaEntry = roleScores.get("nuwa-spa-reverser")!;
		spaEntry.score += 0.8;
		spaEntry.matched.push("已知事实包含前端 Bundle/GraphQL 线索");
	}

	if (phase === "recon") {
		const scoutEntry = roleScores.get("nuwa-scout")!;
		scoutEntry.score += 2.4;
		scoutEntry.matched.push("当前处于侦察测绘阶段(phase=recon)");
	}

	// 按得分及角色固有优先级确定性排序
	const sortedSpecialists = (
		["nuwa-code-auditor", "nuwa-auth-breaker", "nuwa-spa-reverser", "nuwa-scout"] as SpecialistRole[]
	).sort((a, b) => {
		const sa = roleScores.get(a)!.score;
		const sb = roleScores.get(b)!.score;
		if (Math.abs(sb - sa) > 1e-6) return sb - sa;
		return NUWA_SPECIALIST_SQUAD[b].priority - NUWA_SPECIALIST_SQUAD[a].priority;
	});

	const topRole = sortedSpecialists[0]!;
	const topEntry = roleScores.get(topRole)!;

	// 显著专精阈值：得分 >= 2.2 时分配专精专家，否则回退通用执行子代理 fujiang
	if (topEntry.score >= 2.2) {
		const profile = NUWA_SPECIALIST_SQUAD[topRole];
		const secondScore = roleScores.get(sortedSpecialists[1]!)!.score;
		const margin = Math.max(0, topEntry.score - secondScore);
		const confidence = clamp01(0.62 + Math.min(0.35, topEntry.score * 0.05 + margin * 0.03));
		const activeFallbacks = sortedSpecialists.filter((r) => r !== topRole && roleScores.get(r)!.score >= 2.0);
		const fallbackRoles = buildFallbackChain(topRole, activeFallbacks);
		return {
			role: topRole,
			taskCategory: profile.defaultTaskCategory,
			confidence,
			matchedSignals: topEntry.matched,
			fallbackRoles,
			reason: `命中${profile.label}特征（${topEntry.matched.join("、")}），分发给 ${topRole}。`,
		};
	}

	const fallbackCategory: CalibrationTaskCategory = phase === "exploit" ? "exploit" : "general";
	return {
		role: "fujiang",
		taskCategory: fallbackCategory,
		confidence: 0.65,
		matchedSignals: ["未命中强专精特征，启用标准通用取证兜底"],
		fallbackRoles: ["nuwa-scout"],
		reason: "派单属于通用现场探测与取证任务，分发给标准执行子代理 fujiang 兜底执行。",
	};
}

/**
 * 从单条校准记录中提取关联的专精角色（若记录携带角色标记）。
 */
export function extractRecordSpecialistRole(rec: SpecialistCalibrationRecord): SpecialistRole | null {
	if (!rec || typeof rec !== "object") return null;

	for (const direct of [rec.specialistRole, rec.agent, rec.worker]) {
		const norm = String(direct ?? "").trim().toLowerCase();
		if (VALID_SPECIALIST_ROLES.has(norm as SpecialistRole)) {
			return norm as SpecialistRole;
		}
	}

	const combinedText = [rec.note ?? "", rec.settlementNote ?? "", rec.intentId ?? ""].join(" ");
	const kvMatch = combinedText.match(
		/\b(?:specialistRole|specialist|role|agent|worker)\s*[:=]\s*(nuwa-scout|nuwa-spa-reverser|nuwa-auth-breaker|nuwa-code-auditor|nuwa-verifier|fujiang)\b/i,
	);
	if (kvMatch?.[1]) {
		return kvMatch[1].toLowerCase() as SpecialistRole;
	}

	for (const role of SPECIALIST_ROLES) {
		const re = new RegExp(`(?:^|[^a-z0-9-])${role.replace(/-/g, "\\-")}(?:$|[^a-z0-9-])`, "i");
		if (re.test(combinedText)) {
			return role;
		}
	}

	return null;
}

/**
 * 严格核验校准记录是否为经机械核验源结算的合法记录（硬性排除任何自评/未结算/矛盾记录）。
 */
export function isMechanicalCalibrationRecord(rec: unknown): rec is SpecialistCalibrationRecord {
	if (!rec || typeof rec !== "object") return false;
	const r = rec as SpecialistCalibrationRecord;
	if (r.settled !== true) return false;
	if (r.outcome !== 0 && r.outcome !== 1) return false;
	if (typeof r.source !== "string" || !ALLOWED_SETTLEMENT_SOURCES.has(r.source as CalibrationSettlementSource)) {
		return false;
	}
	if (r.isFalsePositive === true && r.outcome === 1) return false;
	if (
		typeof r.predictedConfidence !== "number" ||
		!Number.isFinite(r.predictedConfidence) ||
		r.predictedConfidence < 0 ||
		r.predictedConfidence > 1
	) {
		return false;
	}
	if (typeof r.modelId !== "string" || !r.modelId.trim()) return false;
	if (!VALID_TASK_CATEGORIES.has(r.taskCategory)) return false;
	return true;
}

function resolveRoleDefaultModelInAllowlist(
	role: SpecialistRole,
	allowedModels: readonly string[],
	allowedSet: ReadonlySet<string>,
	opts?: RecommendSpecialistOptions,
): string {
	const profile = NUWA_SPECIALIST_SQUAD[role];

	if (role === "nuwa-verifier" && opts?.verifyModel && allowedSet.has(opts.verifyModel.trim())) {
		return opts.verifyModel.trim();
	}
	if (profile.preferredModelTier === "deep" && opts?.deepModel && allowedSet.has(opts.deepModel.trim())) {
		return opts.deepModel.trim();
	}
	if (profile.preferredModelTier === "fast" && opts?.fastModel && allowedSet.has(opts.fastModel.trim())) {
		return opts.fastModel.trim();
	}
	if (opts?.defaultModel && allowedSet.has(opts.defaultModel.trim())) {
		return opts.defaultModel.trim();
	}
	if (allowedSet.has(profile.defaultModel)) {
		return profile.defaultModel;
	}

	// 按档位关键词在白名单中平滑匹配最相近定位模型，绝不越出 allowedModels
	if (profile.preferredModelTier === "deep") {
		const deepCand =
			allowedModels.find((m) => /carbon|pro|deep|high/i.test(m)) ??
			allowedModels.find((m) => /neon/i.test(m));
		if (deepCand && allowedSet.has(deepCand)) return deepCand;
	} else if (profile.preferredModelTier === "fast") {
		const fastCand = allowedModels.find((m) => /hydrogen|flash|fast|lite/i.test(m));
		if (fastCand && allowedSet.has(fastCand)) return fastCand;
	} else {
		const stdCand = allowedModels.find((m) => /neon|standard/i.test(m));
		if (stdCand && allowedSet.has(stdCand)) return stdCand;
	}

	return allowedModels[0]!;
}

/**
 * 联动 `calibration.ts` 机械对账账本与 `computeCalibrationSummary` / `recommendAdaptiveModelRoute`，
 * 综合 `specialistRole × taskCategory × model` 三维历史命中率、误报率与 Token ROI 联合推荐最佳专精角色与模型。
 *
 * 硬性护栏：
 * - 严格过滤任何非机械结算来源（`self / model / agent` 等自证记录一律忽略并计数）；
 * - 返回的 `recommendedModel` 100% 属于 `allowedModels` 硬白名单，绝不越界；
 * - 样本不足 `minSamples` 时启动冷启动保护，稳健保持专精基准角色与白名单默认模型。
 */
export function recommendSpecialistAndModel(
	intent: SpecialistIntentLike | null | undefined,
	state: Partial<NuwaState> | null | undefined,
	calibrationRecords: readonly SpecialistCalibrationRecord[] | null | undefined,
	opts?: RecommendSpecialistOptions,
): SpecialistAndModelRecommendation {
	// 1. 校验并锁死 allowedModels 白名单
	const rawAllowedModels =
		opts && "allowedModels" in opts && opts.allowedModels !== undefined
			? opts.allowedModels
			: DEFAULT_ALLOWED_SPECIALIST_MODELS;

	if (!Array.isArray(rawAllowedModels)) {
		throw new CalibrationError("INVALID_INPUT", "recommendSpecialistAndModel: allowedModels 必须为字符串数组");
	}

	const allowedModels: string[] = [];
	const allowedModelSet = new Set<string>();
	for (const raw of rawAllowedModels) {
		const trimmed = String(raw ?? "").trim();
		if (trimmed && !allowedModelSet.has(trimmed)) {
			allowedModelSet.add(trimmed);
			allowedModels.push(trimmed);
		}
	}
	if (allowedModels.length === 0) {
		throw new CalibrationError(
			"INVALID_INPUT",
			"recommendSpecialistAndModel 需要至少包含 1 个有效模型的 allowedModels 白名单",
		);
	}

	// 2. 校验可选 allowedRoles 范围
	const allowedRoleSet = new Set<SpecialistRole>();
	if (opts?.allowedRoles && Array.isArray(opts.allowedRoles) && opts.allowedRoles.length > 0) {
		for (const r of opts.allowedRoles) {
			if (VALID_SPECIALIST_ROLES.has(r)) allowedRoleSet.add(r);
		}
	}
	if (allowedRoleSet.size === 0) {
		for (const r of SPECIALIST_ROLES) allowedRoleSet.add(r);
	}

	const minSamples =
		typeof opts?.minSamples === "number" && Number.isFinite(opts.minSamples) && opts.minSamples >= 1
			? Math.floor(opts.minSamples)
			: 5;
	const maxFpRate =
		typeof opts?.maxFalsePositiveRate === "number" && Number.isFinite(opts.maxFalsePositiveRate)
			? clamp01(opts.maxFalsePositiveRate)
			: 0.30;
	const minRoiScore =
		typeof opts?.minRoiScore === "number" && Number.isFinite(opts.minRoiScore)
			? Math.max(0, opts.minRoiScore)
			: 0.12;
	const roleSwitchMargin =
		typeof opts?.roleSwitchMargin === "number" && Number.isFinite(opts.roleSwitchMargin) && opts.roleSwitchMargin >= 0
			? opts.roleSwitchMargin
			: 0.12;

	// 3. 确定性意图初筛分类
	const baseClassification = classifyIntentForSpecialist(intent, state);
	const effectiveBaseRole: SpecialistRole = allowedRoleSet.has(baseClassification.role)
		? baseClassification.role
		: allowedRoleSet.has("fujiang")
			? "fujiang"
			: [...allowedRoleSet][0]!;
	const taskCategory = baseClassification.taskCategory;

	// 4. 反自证机械结算账本过滤
	const inputList = Array.isArray(calibrationRecords) ? calibrationRecords : [];
	const mechanicalRecords: SpecialistCalibrationRecord[] = [];
	let ignoredInvalidRecords = 0;

	for (const rec of inputList) {
		if (isMechanicalCalibrationRecord(rec)) {
			mechanicalRecords.push(rec);
		} else {
			ignoredInvalidRecords += 1;
		}
	}

	// 仅把白名单内模型的有效机械结算记录纳入汇总，彻底隔离白名单外脏数据
	const allowlistedRecords = mechanicalRecords.filter((r) => allowedModelSet.has(r.modelId.trim()));
	const calibrationSummary = computeCalibrationSummary(allowlistedRecords);

	// 5. 构建候选角色集合
	const candidateRoles: SpecialistRole[] = [effectiveBaseRole];
	const lockRole = opts?.lockSpecialistRole === true || effectiveBaseRole === "nuwa-verifier";
	if (!lockRole) {
		for (const fb of baseClassification.fallbackRoles) {
			if (allowedRoleSet.has(fb) && !candidateRoles.includes(fb)) {
				candidateRoles.push(fb);
			}
		}
		// 同时允许同一任务类别下已有成熟高战绩的其他合法角色参与竞争
		for (const r of SPECIALIST_ROLES) {
			if (r === "nuwa-verifier") continue;
			if (allowedRoleSet.has(r) && !candidateRoles.includes(r)) {
				const hasRoleCatHistory = allowlistedRecords.some(
					(rec) => extractRecordSpecialistRole(rec) === r && rec.taskCategory === taskCategory,
				);
				if (hasRoleCatHistory) {
					candidateRoles.push(r);
				}
			}
		}
	}

	// 预先按角色归组机械结算记录
	const recordsByRole = new Map<SpecialistRole, SpecialistCalibrationRecord[]>();
	let anyRoleTaggedRecords = false;
	for (const rec of allowlistedRecords) {
		const taggedRole = extractRecordSpecialistRole(rec);
		if (taggedRole) {
			anyRoleTaggedRecords = true;
			const bucket = recordsByRole.get(taggedRole) ?? [];
			bucket.push(rec);
			recordsByRole.set(taggedRole, bucket);
		}
	}

	// 6. 评估 (specialistRole × taskCategory × model) 联合候选矩阵
	const jointCandidates: SpecialistJointCandidate[] = [];
	const roleModelDecisions = new Map<SpecialistRole, AdaptiveModelRouteDecision>();

	for (const role of candidateRoles) {
		const roleBaselineModel = resolveRoleDefaultModelInAllowlist(role, allowedModels, allowedModelSet, opts);
		const roleTaggedSlice = recordsByRole.get(role) ?? [];
		// 若该角色专属样本充足，用专属切片驱动模型自适应路由；否则回退使用全局白名单校准账本
		const sliceForAdaptive = roleTaggedSlice.length >= minSamples ? roleTaggedSlice : allowlistedRecords;
		const adaptiveDecision = recommendAdaptiveModelRoute(sliceForAdaptive, {
			allowedModels,
			defaultModel: roleBaselineModel,
			taskCategory,
			minSamples,
			maxFalsePositiveRate: maxFpRate,
			minRoiScore,
		});
		roleModelDecisions.set(role, adaptiveDecision);

		const rolePrior =
			role === effectiveBaseRole
				? 1.0
				: baseClassification.fallbackRoles.includes(role)
					? 0.84
					: 0.76;

		for (const modelId of allowedModels) {
			const exactSlice = roleTaggedSlice.filter(
				(r) => r.modelId.trim() === modelId && r.taskCategory === taskCategory,
			);
			const roleModelSlice = roleTaggedSlice.filter((r) => r.modelId.trim() === modelId);
			const catModelMetrics: CalibrationDimensionMetrics | undefined =
				calibrationSummary.byModelAndCategory[`${modelId}::${taskCategory}`];
			const globalModelMetrics: CalibrationDimensionMetrics | undefined =
				calibrationSummary.byModel[modelId];

			// 选择最具代表性的评估切片：三维精确切片 >= minSamples > 角色×模型 >= minSamples > (若无角色标签则用类别×模型 / 全局模型)
			let activeMetrics: CalibrationDimensionMetrics | undefined;
			if (exactSlice.length >= minSamples) {
				activeMetrics = computeCalibrationSummary(exactSlice).global;
			} else if (roleModelSlice.length >= minSamples) {
				activeMetrics = computeCalibrationSummary(roleModelSlice).global;
			} else if (exactSlice.length > 0 && anyRoleTaggedRecords) {
				activeMetrics = computeCalibrationSummary(exactSlice).global;
			} else if (!anyRoleTaggedRecords && (catModelMetrics?.settledCount ?? 0) >= minSamples) {
				activeMetrics = catModelMetrics;
			} else if (!anyRoleTaggedRecords && (globalModelMetrics?.settledCount ?? 0) >= minSamples) {
				activeMetrics = globalModelMetrics;
			} else {
				activeMetrics = catModelMetrics?.settledCount ? catModelMetrics : globalModelMetrics;
			}

			const settledCount = activeMetrics?.settledCount ?? 0;
			const confirmedCount = activeMetrics?.confirmedCount ?? 0;
			const falsePositiveCount = activeMetrics?.falsePositiveCount ?? 0;
			const hitRate = settledCount > 0 ? safeFinite(confirmedCount / settledCount, 0) : 0;
			const precision = safeFinite(activeMetrics?.precision ?? 0, 0);
			const fpRate = safeFinite(activeMetrics?.falsePositiveRate ?? 0, 0);
			const tokensPerFinding = safeFinite(activeMetrics?.tokensPerConfirmedFinding ?? 0, 0);
			const roiScore = safeFinite(activeMetrics?.roiScore ?? 0, 0);
			const brierScore = safeFinite(activeMetrics?.brierScore ?? 0, 0);
			const ece = safeFinite(activeMetrics?.ece ?? 0, 0);

			const isCold = settledCount < minSamples;
			const demoteReasons: string[] = [];
			if (!isCold) {
				if (fpRate > maxFpRate) {
					demoteReasons.push(`误报率过高(${(fpRate * 100).toFixed(1)}% > ${(maxFpRate * 100).toFixed(1)}%)`);
				}
				if (roiScore < minRoiScore) {
					demoteReasons.push(`Token ROI 过低(${roiScore.toFixed(3)} < ${minRoiScore.toFixed(3)})`);
				}
				if (confirmedCount === 0 && settledCount >= minSamples) {
					demoteReasons.push(`连续 ${settledCount} 次结算零实锤产出`);
				}
				if (brierScore > 0.45) {
					demoteReasons.push(`校准偏差过大(Brier=${brierScore.toFixed(3)})`);
				}
			}

			const demoted = demoteReasons.length > 0;
			let jointScore: number;
			if (isCold) {
				jointScore =
					0.52 * rolePrior +
					(modelId === roleBaselineModel ? 0.06 : 0) +
					(modelId === adaptiveDecision.recommendedModel ? 0.03 : 0);
			} else {
				const roiNorm = roiScore / (roiScore + 0.5);
				const calibQuality = clamp01(1 - 0.6 * brierScore - 0.4 * ece);
				jointScore =
					0.28 * rolePrior +
					0.24 * hitRate +
					0.22 * roiNorm +
					0.16 * clamp01(1 - fpRate) +
					0.10 * calibQuality +
					(modelId === roleBaselineModel ? 0.02 : 0);
				if (demoted) {
					jointScore *= 0.20;
				}
			}

			jointCandidates.push({
				role,
				modelId,
				taskCategory,
				settledCount,
				exactSliceCount: exactSlice.length,
				confirmedCount,
				falsePositiveCount,
				hitRate,
				precision,
				falsePositiveRate: fpRate,
				tokensPerConfirmedFinding: tokensPerFinding,
				roiScore,
				brierScore,
				ece,
				jointScore: safeFinite(jointScore, 0),
				coldStart: isCold,
				demoted,
				demoteReasons,
			});
		}
	}

	const baseRoleBaselineModel = resolveRoleDefaultModelInAllowlist(
		effectiveBaseRole,
		allowedModels,
		allowedModelSet,
		opts,
	);
	const baseAdaptiveDecision = roleModelDecisions.get(effectiveBaseRole)!;
	const baseRoleCandidates = jointCandidates.filter((c) => c.role === effectiveBaseRole);
	const baseDefaultCand =
		baseRoleCandidates.find((c) => c.modelId === baseRoleBaselineModel) ?? baseRoleCandidates[0]!;

	// 挑选基准角色内部最优白名单候选（若基准默认模型处于冷启动，严格遵循冷启动保护维持 baseAdaptiveDecision.recommendedModel）
	const bestInBaseRole = baseDefaultCand.coldStart
		? baseRoleCandidates.find((c) => c.modelId === baseAdaptiveDecision.recommendedModel) ?? baseDefaultCand
		: [...baseRoleCandidates].sort((a, b) => b.jointScore - a.jointScore)[0]!;

	// 挑选跨角色成熟健康候选
	const bestOtherHealthy = jointCandidates
		.filter((c) => c.role !== effectiveBaseRole && !c.coldStart && !c.demoted)
		.sort((a, b) => b.jointScore - a.jointScore)[0];
	const bestOtherWarmFallback = jointCandidates
		.filter((c) => c.role !== effectiveBaseRole && !c.demoted)
		.sort((a, b) => b.jointScore - a.jointScore)[0];

	let chosenCandidate = bestInBaseRole;
	let roleSwitched = false;

	if (!lockRole) {
		const allBaseRoleDemoted =
			baseRoleCandidates.length > 0 && baseRoleCandidates.every((c) => !c.coldStart && c.demoted);
		if (allBaseRoleDemoted && (bestOtherHealthy ?? bestOtherWarmFallback)) {
			chosenCandidate = (bestOtherHealthy ?? bestOtherWarmFallback)!;
			roleSwitched = chosenCandidate.role !== effectiveBaseRole;
		} else if (
			bestOtherHealthy &&
			!bestInBaseRole.coldStart &&
			bestOtherHealthy.jointScore >= bestInBaseRole.jointScore + roleSwitchMargin
		) {
			chosenCandidate = bestOtherHealthy;
			roleSwitched = true;
		}
	}

	// 终极白名单不变量断言：确保 100% 不越出 allowedModels 与 allowedRoles
	const finalRole: SpecialistRole = allowedRoleSet.has(chosenCandidate.role)
		? chosenCandidate.role
		: effectiveBaseRole;
	const finalModel: string = allowedModelSet.has(chosenCandidate.modelId)
		? chosenCandidate.modelId
		: allowedModels[0]!;
	const finalModelDecision = roleModelDecisions.get(finalRole) ?? baseAdaptiveDecision;
	const modelSwitched = finalModel !== baseRoleBaselineModel;
	const coldStart = chosenCandidate.coldStart && finalModelDecision.coldStart;

	const reasonParts: string[] = [baseClassification.reason];
	if (roleSwitched) {
		const prevReasons = bestInBaseRole.demoteReasons.length
			? `（原角色 ${effectiveBaseRole} 触发降权：${bestInBaseRole.demoteReasons.join("、")}）`
			: `（联合效用分 ${chosenCandidate.jointScore.toFixed(3)} 显著优于 ${bestInBaseRole.jointScore.toFixed(3)}）`;
		reasonParts.push(`战绩联动角色切换：自动改派 ${finalRole} 搭配白名单模型 ${finalModel}${prevReasons}。`);
	} else if (coldStart) {
		reasonParts.push(
			`冷启动回退保护生效：有效机械结算样本 (${chosenCandidate.settledCount}) 未达门槛 (minSamples=${minSamples})，保持专精角色 ${finalRole} 与白名单模型 ${finalModel}。`,
		);
	} else if (modelSwitched) {
		reasonParts.push(
			`战绩联动模型优选：保持专精角色 ${finalRole}，切换至白名单高 ROI 模型 ${finalModel}（命中率=${(chosenCandidate.hitRate * 100).toFixed(1)}%, FPR=${(chosenCandidate.falsePositiveRate * 100).toFixed(1)}%, ROI=${chosenCandidate.roiScore.toFixed(3)}）。`,
		);
	} else {
		reasonParts.push(
			`战绩校验健康：维持专精角色 ${finalRole} 与白名单模型 ${finalModel}（样本=${chosenCandidate.settledCount}, 命中率=${(chosenCandidate.hitRate * 100).toFixed(1)}%, ROI=${chosenCandidate.roiScore.toFixed(3)}）。`,
		);
	}

	return {
		recommendedRole: finalRole,
		specialistRole: finalRole,
		recommendedModel: finalModel,
		modelId: finalModel,
		taskCategory,
		classification: baseClassification,
		modelDecision: finalModelDecision,
		calibrationSummary,
		coldStart,
		roleSwitched,
		modelSwitched,
		acceptedMechanicalRecords: allowlistedRecords.length,
		ignoredInvalidRecords,
		candidates: jointCandidates,
		reason: reasonParts.join(" "),
	};
}
