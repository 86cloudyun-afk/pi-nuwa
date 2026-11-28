/**
 * L4 综合演武场 OpenAI 兼容实网推理客户端（支持 JSON 与 SSE 流式响应、转义感知 JSON 解析、零回退门禁与密钥脱敏）。
 *
 * 环境变量约定（仓库内严禁硬编码任何密钥）：
 *   - NUWA_LIVE_API_BASE:   默认 "https://api.deepseek.com"
 *   - NUWA_LIVE_API_KEY:    必填（缺失时立即抛出明确错误）
 *   - NUWA_LIVE_MODEL:      默认 "deepseek-flash"（可被 CLI --model 覆盖）
 *   - NUWA_LIVE_MAX_TOKENS: 默认 4096
 */
import { analyzeCrossFileRgs } from "../../omp/rgs-analyzer";
import { S11_SPRING_BOOT_FILES, type L4ScenarioServerHandle, type L4ScenarioSpec } from "./servers";

export interface LiveOpenAiConfig {
	apiBase: string;
	apiKey: string;
	model: string;
	maxTokens: number;
	timeoutMs: number;
	maxRetries: number;
}

export interface LiveTokenUsage {
	promptTokens: number;
	completionTokens: number;
	reasoningTokens: number;
	totalTokens: number;
	llmCalls: number;
}

export interface LiveScenarioPlan {
	hypothesis: string;
	recommendedActions: string[];
	targetParameters: Record<string, string>;
	confidence: number;
	rawSummary: string;
	usage: LiveTokenUsage;
}

export interface LiveFinalVerdict {
	confirmed: boolean;
	rationale: string;
	confidence: number;
	usage: LiveTokenUsage;
}

const NON_RETRYABLE_HTTP_STATUS = new Set([400, 401, 403, 404, 422]);

export function scrubLiveErrorText(raw: string, apiKey?: string): string {
	let out = String(raw ?? "");
	if (!out) return out;
	if (apiKey && apiKey.trim().length >= 4) {
		const k = apiKey.trim();
		out = out.split(k).join("[REDACTED]");
		try {
			const enc = encodeURIComponent(k);
			if (enc !== k) out = out.split(enc).join("[REDACTED]");
		} catch {
			/* ignore */
		}
	}
	out = out.replace(/(^|[^A-Za-z0-9])(Bearer|Basic)\s+[^\s"',;}{[\])>]{4,}/gi, "$1$2 [REDACTED]");
	out = out.replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]");
	return out;
}

export function resolveLiveOpenAiConfig(opts?: {
	modelOverride?: string;
	env?: Record<string, string | undefined>;
	timeoutMs?: number;
	maxRetries?: number;
	maxTokens?: number;
}): LiveOpenAiConfig {
	const env = opts?.env ?? process.env;
	const apiKey = String(env.NUWA_LIVE_API_KEY ?? "").trim();
	if (!apiKey) {
		throw new Error(
			"缺少环境变量 NUWA_LIVE_API_KEY：启用 --live-openai-compat 实网评测模式时必须通过环境变量提供 API 密钥",
		);
	}
	const rawBase = String(env.NUWA_LIVE_API_BASE ?? "").trim() || "https://api.deepseek.com";
	const apiBase = rawBase.replace(/\/+$/, "");
	const model = String(opts?.modelOverride ?? env.NUWA_LIVE_MODEL ?? "").trim() || "deepseek-flash";
	const envMaxTokens = Number(env.NUWA_LIVE_MAX_TOKENS ?? "");
	const maxTokens =
		opts?.maxTokens ??
		(Number.isFinite(envMaxTokens) && envMaxTokens >= 256 ? Math.floor(envMaxTokens) : 4096);
	const timeoutMs = opts?.timeoutMs ?? 90_000;
	const maxRetries = opts?.maxRetries ?? 3;
	return { apiBase, apiKey, model, maxTokens, timeoutMs, maxRetries };
}

export function buildChatCompletionsUrl(apiBase: string): string {
	const clean = apiBase.replace(/\/+$/, "");
	if (clean.endsWith("/chat/completions")) return clean;
	if (/\/v\d+$/i.test(clean)) return `${clean}/chat/completions`;
	return `${clean}/v1/chat/completions`;
}

export function parseSseChatCompletion(rawText: string): { content: string; usage: Omit<LiveTokenUsage, "llmCalls"> } {
	let content = "";
	let promptTokens = 0;
	let completionTokens = 0;
	let reasoningTokens = 0;
	let totalTokens = 0;

	const takePositiveMax = (prev: number, rawVal: unknown): number => {
		const n = Number(rawVal);
		return Number.isFinite(n) && n > 0 ? Math.max(prev, Math.floor(n)) : prev;
	};

	for (const line of rawText.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed.startsWith("data:")) continue;
		const dataPart = trimmed.slice(5).trim();
		if (!dataPart || dataPart === "[DONE]") continue;
		try {
			const evt = JSON.parse(dataPart) as Record<string, any>;
			const delta = evt.choices?.[0]?.delta?.content ?? evt.choices?.[0]?.message?.content;
			if (typeof delta === "string") content += delta;
			if (evt.usage && typeof evt.usage === "object") {
				promptTokens = takePositiveMax(promptTokens, evt.usage.prompt_tokens);
				completionTokens = takePositiveMax(completionTokens, evt.usage.completion_tokens);
				reasoningTokens = takePositiveMax(
					reasoningTokens,
					evt.usage.completion_tokens_details?.reasoning_tokens ?? evt.usage.reasoning_tokens,
				);
				totalTokens = takePositiveMax(totalTokens, evt.usage.total_tokens);
			}
		} catch {
			/* 忽略非 JSON SSE 心跳行 */
		}
	}
	if (totalTokens < promptTokens + completionTokens) {
		totalTokens = promptTokens + completionTokens;
	}
	return { content, usage: { promptTokens, completionTokens, reasoningTokens, totalTokens } };
}

/**
 * 字符串转义感知的配对花括号扫描：提取文本中首个语法合法的顶层 JSON 对象，
 * 避免模型在 JSON 后附带 `/users/{id}` 等花括号说明导致解析失败。
 */
export function extractFirstJsonObject(raw: string): Record<string, any> | null {
	const cleaned = String(raw ?? "").replace(/```(?:json)?/gi, "").replace(/```/g, "").trim();
	if (!cleaned) return null;

	const len = cleaned.length;
	for (let start = 0; start < len; start++) {
		if (cleaned[start] !== "{") continue;
		let depth = 0;
		let inString = false;
		let escaped = false;
		for (let i = start; i < len; i++) {
			const ch = cleaned[i]!;
			if (inString) {
				if (escaped) {
					escaped = false;
				} else if (ch === "\\") {
					escaped = true;
				} else if (ch === '"') {
					inString = false;
				}
				continue;
			}
			if (ch === '"') {
				inString = true;
			} else if (ch === "{") {
				depth += 1;
			} else if (ch === "}") {
				depth -= 1;
				if (depth === 0) {
					const candidate = cleaned.slice(start, i + 1);
					try {
						const parsed = JSON.parse(candidate);
						if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
							return parsed as Record<string, any>;
						}
					} catch {
						/* 继续尝试下一个左花括号起点 */
					}
					break;
				}
			}
		}
	}
	return null;
}

class NonRetryableLiveHttpError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "NonRetryableLiveHttpError";
	}
}

export async function callOpenAiChatCompletion(
	cfg: LiveOpenAiConfig,
	messages: Array<{ role: "system" | "user" | "assistant"; content: string }>,
	fetchFn: typeof fetch = fetch,
): Promise<{ content: string; usage: LiveTokenUsage }> {
	const endpoint = buildChatCompletionsUrl(cfg.apiBase);
	let lastErr: unknown = null;

	for (let attempt = 1; attempt <= Math.max(1, cfg.maxRetries); attempt++) {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
		try {
			const resp = await fetchFn(endpoint, {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
					Authorization: `Bearer ${cfg.apiKey}`,
				},
				body: JSON.stringify({
					model: cfg.model,
					temperature: 0.1,
					max_tokens: cfg.maxTokens,
					messages,
				}),
				signal: controller.signal,
			});

			const contentType = (resp.headers.get("content-type") ?? "").toLowerCase();
			const rawBody = await resp.text();
			if (!resp.ok) {
				const safePreview = scrubLiveErrorText(rawBody.slice(0, 240), cfg.apiKey);
				const msg = `HTTP ${resp.status}: ${safePreview}`;
				if (NON_RETRYABLE_HTTP_STATUS.has(resp.status)) {
					throw new NonRetryableLiveHttpError(msg);
				}
				throw new Error(msg);
			}

			if (contentType.includes("text/event-stream") || rawBody.trimStart().startsWith("data:")) {
				const sse = parseSseChatCompletion(rawBody);
				return {
					content: sse.content.trim(),
					usage: { ...sse.usage, llmCalls: 1 },
				};
			}

			const json = JSON.parse(rawBody) as Record<string, any>;
			const msgContent = String(
				json.choices?.[0]?.message?.content ?? json.choices?.[0]?.text ?? "",
			).trim();
			const u = json.usage ?? {};
			const promptTokens = Number(u.prompt_tokens ?? 0) || 0;
			const completionTokens = Number(u.completion_tokens ?? 0) || 0;
			const reasoningTokens =
				Number(u.completion_tokens_details?.reasoning_tokens ?? u.reasoning_tokens ?? 0) || 0;
			const totalTokens = Number(u.total_tokens ?? promptTokens + completionTokens) || 0;
			return {
				content: msgContent,
				usage: {
					promptTokens,
					completionTokens,
					reasoningTokens,
					totalTokens,
					llmCalls: 1,
				},
			};
		} catch (err) {
			lastErr = err;
			if (err instanceof NonRetryableLiveHttpError) {
				break;
			}
			if (attempt < cfg.maxRetries) {
				await Bun.sleep(250 * attempt);
			}
		} finally {
			clearTimeout(timer);
		}
	}

	const rawReason = lastErr instanceof Error ? lastErr.message : String(lastErr);
	throw new Error(
		`实网模型调用失败 (${scrubLiveErrorText(cfg.apiBase, cfg.apiKey)} model=${cfg.model}): ${scrubLiveErrorText(rawReason, cfg.apiKey)}`,
	);
}

async function probeScenarioSurfaceHint(spec: L4ScenarioSpec, srv: L4ScenarioServerHandle): Promise<string> {
	const parts: string[] = [`scenario=${spec.id}`, `category=${spec.category}`, `baseUrl=${srv.baseUrl}`];
	if (spec.id === "s11-spring-rgs-standalone-pov") {
		const rgs = analyzeCrossFileRgs(S11_SPRING_BOOT_FILES);
		const unauth = rgs.unauthenticatedRoutes.map((r) => `${r.method} ${r.path}`).join(", ");
		parts.push(`rgsRoutes=${rgs.summary.totalRoutes}`, `unauthRoutes=[${unauth}]`);
	}
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), 3_000);
	try {
		const r = await fetch(srv.baseUrl, { method: "GET", signal: controller.signal });
		const txt = (await r.text()).slice(0, 180).replace(/\s+/g, " ");
		parts.push(`rootStatus=${r.status}`, `rootPreview=${txt}`);
	} catch {
		/* 非纯 HTTP 根路径或超时忽略 */
	} finally {
		clearTimeout(timer);
	}
	return parts.join(" | ");
}

export async function generateLiveScenarioPlan(
	cfg: LiveOpenAiConfig,
	spec: L4ScenarioSpec,
	srv: L4ScenarioServerHandle,
	fetchFn: typeof fetch = fetch,
): Promise<LiveScenarioPlan> {
	const surfaceHint = await probeScenarioSurfaceHint(spec, srv);
	const res = await callOpenAiChatCompletion(
		cfg,
		[
			{
				role: "system",
				content:
					"你是自动化软件接口契约与访问控制测试规划助手。请根据给定的本地测试服务特征，仅输出一个紧凑 JSON 对象：{\"hypothesis\":\"...\",\"actions\":[\"...\"],\"params\":{},\"confidence\":0.85}。",
			},
			{
				role: "user",
				content: `请为本地演武场测试场景生成结构化核验方案：\n名称: ${spec.name}\n特征摘要: ${surfaceHint}\n预期可检出问题数: ${spec.expectedFindings}`,
			},
		],
		fetchFn,
	);
	if (!res.content) {
		throw new Error(`实网规划阶段返回空内容 (scenario=${spec.id})，拒绝回退离线默认方案`);
	}
	const parsed = extractFirstJsonObject(res.content);
	if (!parsed || typeof parsed.hypothesis !== "string" || !parsed.hypothesis.trim()) {
		throw new Error(
			`实网规划阶段未返回合法 JSON hypothesis (scenario=${spec.id}): ${scrubLiveErrorText(res.content.slice(0, 160), cfg.apiKey)}`,
		);
	}
	return {
		hypothesis: parsed.hypothesis.trim().slice(0, 200),
		recommendedActions: Array.isArray(parsed.actions)
			? parsed.actions.map((x: unknown) => String(x)).slice(0, 6)
			: [],
		targetParameters:
			parsed.params && typeof parsed.params === "object" && !Array.isArray(parsed.params)
				? Object.fromEntries(Object.entries(parsed.params).map(([k, v]) => [k, String(v)]))
				: {},
		confidence: Math.min(0.99, Math.max(0.05, Number(parsed.confidence ?? 0.8) || 0.8)),
		rawSummary: scrubLiveErrorText(res.content.slice(0, 240), cfg.apiKey),
		usage: res.usage,
	};
}

export async function evaluateLiveScenarioVerdict(
	cfg: LiveOpenAiConfig,
	spec: L4ScenarioSpec,
	plan: LiveScenarioPlan,
	execDetail: { passed: boolean; truePositives: number; falsePositives: number; detail: string },
	fetchFn: typeof fetch = fetch,
): Promise<LiveFinalVerdict> {
	const res = await callOpenAiChatCompletion(
		cfg,
		[
			{
				role: "system",
				content:
					"你是自动化接口测试结果复核助手。请根据本地测试服务的实测回包证据摘要输出紧凑 JSON：{\"confirmed\":true|false,\"rationale\":\"...\",\"confidence\":0.9}。注意：当 expectedFindings=0 且实测未发现异常时 confirmed 应为 false（代表确认阴性无异常）。",
			},
			{
				role: "user",
				content: `场景: ${spec.id} (expectedFindings=${spec.expectedFindings})\n初始假设: ${plan.hypothesis}\n本地靶场实包验证摘要: truePositives=${execDetail.truePositives}, falsePositives=${execDetail.falsePositives}, detail=${execDetail.detail}`,
			},
		],
		fetchFn,
	);
	if (!res.content) {
		throw new Error(`实网复核阶段返回空内容 (scenario=${spec.id})，拒绝静默回退离线答案`);
	}
	const parsed = extractFirstJsonObject(res.content);
	if (!parsed || typeof parsed.confirmed !== "boolean") {
		throw new Error(
			`实网复核阶段未返回合法布尔字段 confirmed (scenario=${spec.id}): ${scrubLiveErrorText(res.content.slice(0, 160), cfg.apiKey)}`,
		);
	}
	return {
		confirmed: parsed.confirmed,
		rationale: scrubLiveErrorText(String(parsed.rationale ?? "").trim() || "LLM completed verdict", cfg.apiKey).slice(
			0,
			240,
		),
		confidence: Math.min(0.99, Math.max(0.05, Number(parsed.confidence ?? 0.85) || 0.85)),
		usage: res.usage,
	};
}

export function mergeLiveTokenUsage(a: LiveTokenUsage, b: LiveTokenUsage): LiveTokenUsage {
	return {
		promptTokens: a.promptTokens + b.promptTokens,
		completionTokens: a.completionTokens + b.completionTokens,
		reasoningTokens: a.reasoningTokens + b.reasoningTokens,
		totalTokens: a.totalTokens + b.totalTokens,
		llmCalls: a.llmCalls + b.llmCalls,
	};
}
