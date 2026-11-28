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

import {
	CAPABILITY_TAGS,
	COOKIE_ATTR_SKIP_SET,
	DEFAULT_MAX_CHAIN_DEPTH,
	DEFAULT_MIN_CHAIN_DEPTH,
	MAX_CHAIN_DEPTH,
	NON_SECRET_TRIVIAL_VALUES,
	READONLY_HTTP_METHODS,
	SENSITIVE_VAR_NAME_RE,
	camelToKebabHeader,
	clamp,
	escapeRegexLiteral,
	extractFactCapabilities,
	findJsonFieldPaths,
	normalizeReadonlyMethod,
	oneLine,
	sanitizeEndpointLiteral,
	sha1Short,
	stripQueryFromEndpoint,
	synthesizeAttackChains,
	tryParseJsonFromText,
	uniqStrings,
	uniqTags,
	type AttackChainSpec,
	type AttackChainStep,
	type CapabilityTag,
	type ChainExecutionResult,
	type ChainFailureKind,
	type ChainStepTrace,
	type CompileChainOptions,
	type ExecuteChainVerificationOptions,
	type FactCapabilities,
	type KnownCapabilityTag,
	type ParameterBindingHint,
	type ReadonlyHttpMethod,
	type SynthesizeChainsOptions,
	type TrafficStep,
	type VariableExtractionHint,
	type VerifyVulnRecommendation,
} from "./chain-capabilities";

export * from "./chain-capabilities";

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
