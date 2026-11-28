/**
 * 女娲 v6.0 跨宿主核心协议契约（MCP / JSON-RPC 2.0，零外部依赖）。
 *
 * 职责：
 * 1. 定义宿主无关的 MCP 协议常量与完整 12 个 `nuwa_*` 核心工具契约（名称、中文说明、JSON Schema），
 *    与 `omp/nuwa.ts` 注册定义保持 100% 对齐；
 * 2. 定义标准 JSON-RPC 2.0 请求、通知、成功响应、错误响应类型及纯函数构造器/类型守卫。
 */

export const JSONRPC_VERSION = "2.0" as const;

/** 标准 MCP 协议版本（兼容 Claude Code / Cursor / Codex / Antigravity / 通用 MCP 客户端）。 */
export const NUWA_MCP_PROTOCOL_VERSION = "2024-11-05" as const;

export const NUWA_CORE_SERVER_NAME = "nuwa-mcp" as const;
export const NUWA_CORE_SERVER_VERSION = "8.0.0" as const;

/** 标准 JSON-RPC 2.0 错误码常量。 */
export const JSONRPC_ERROR_CODES = {
	PARSE_ERROR: -32700,
	INVALID_REQUEST: -32600,
	METHOD_NOT_FOUND: -32601,
	INVALID_PARAMS: -32602,
	INTERNAL_ERROR: -32603,
} as const;

export type JsonRpcErrorCode = (typeof JSONRPC_ERROR_CODES)[keyof typeof JSONRPC_ERROR_CODES] | number;

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest<P = Record<string, unknown> | unknown[]> {
	jsonrpc: typeof JSONRPC_VERSION;
	id: JsonRpcId;
	method: string;
	params?: P;
}

export interface JsonRpcNotification<P = Record<string, unknown> | unknown[]> {
	jsonrpc: typeof JSONRPC_VERSION;
	method: string;
	params?: P;
}

export interface JsonRpcSuccessResponse<R = unknown> {
	jsonrpc: typeof JSONRPC_VERSION;
	id: JsonRpcId;
	result: R;
}

export interface JsonRpcErrorObject<D = unknown> {
	code: JsonRpcErrorCode;
	message: string;
	data?: D;
}

export interface JsonRpcErrorResponse<D = unknown> {
	jsonrpc: typeof JSONRPC_VERSION;
	id: JsonRpcId;
	error: JsonRpcErrorObject<D>;
}

export type JsonRpcResponse<R = unknown, D = unknown> = JsonRpcSuccessResponse<R> | JsonRpcErrorResponse<D>;
export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

/** MCP JSON Schema 属性节点定义（纯标准 Draft-07 / 2020-12 子集，零第三方依赖）。 */
export interface McpJsonSchemaProperty {
	type?: "string" | "number" | "integer" | "boolean" | "object" | "array";
	description?: string;
	enum?: readonly string[];
	default?: unknown;
	items?: McpJsonSchemaProperty;
	properties?: Record<string, McpJsonSchemaProperty>;
	required?: readonly string[];
	additionalProperties?: boolean | McpJsonSchemaProperty;
	oneOf?: readonly McpJsonSchemaProperty[];
}

export interface McpToolInputSchema {
	type: "object";
	properties: Record<string, McpJsonSchemaProperty>;
	required?: readonly string[];
	additionalProperties?: boolean;
}

export interface McpToolDefinition {
	name: NuwaToolName;
	description: string;
	inputSchema: McpToolInputSchema;
}

export interface McpTextContent {
	type: "text";
	text: string;
}

export interface McpToolCallParams {
	name: string;
	arguments?: Record<string, unknown>;
}

export interface McpToolCallResult {
	content: McpTextContent[];
	details?: Record<string, unknown>;
	structuredContent?: Record<string, unknown>;
	isError?: boolean;
}

export interface McpInitializeParams {
	protocolVersion?: string;
	capabilities?: Record<string, unknown>;
	clientInfo?: {
		name: string;
		version?: string;
	};
}

export interface McpInitializeResult {
	protocolVersion: string;
	capabilities: {
		tools: {
			listChanged: boolean;
		};
	};
	serverInfo: {
		name: string;
		version: string;
	};
}

/** 女娲核心 12 个工具名称枚举元组（顺序与 `omp/nuwa.ts` 严格一致）。 */
export const NUWA_TOOL_NAMES = [
	"nuwa_init",
	"nuwa_plan",
	"nuwa_frontier",
	"nuwa_claim",
	"nuwa_commit",
	"nuwa_flag",
	"nuwa_complete",
	"nuwa_status",
	"nuwa_report",
	"nuwa_expand",
	"nuwa_stop",
	"nuwa_kb",
] as const;

export type NuwaToolName = (typeof NUWA_TOOL_NAMES)[number];

const MODE_ENUM = ["ctf", "pentest", "audit", "coding", "ops"] as const;
const PHASE_ENUM = ["recon", "surface", "vuln", "exploit", "post", "report"] as const;
const FACT_KIND_ENUM = [
	"target",
	"asset",
	"service",
	"endpoint",
	"cred",
	"vuln",
	"flag",
	"loot",
	"note",
	"blocked",
] as const;
const SURFACE_DOMAIN_ENUM = ["port", "path", "host"] as const;
const INTENT_STATUS_ENUM = ["open", "claimed", "done", "blocked"] as const;
const KB_KIND_ENUM = ["auto", "product", "cve", "technique", "poc"] as const;

/**
 * 女娲核心 12 工具完整 MCP Schema 契约（与 `omp/nuwa.ts` 保持 100% 字段与语义对齐）。
 */
export const NUWA_CORE_TOOLS: readonly McpToolDefinition[] = [
	{
		name: "nuwa_init",
		description:
			"创建/恢复女娲项目：写 .nuwa/state.json，初始化靶标 Scope 护栏、工作区完整性基线、便携知识库与本地工具链探针，播种首阶段意图，返回看板。",
		inputSchema: {
			type: "object",
			properties: {
				target: {
					type: "string",
					description: "目标 URL、host:port 或本地目录/服务标识（coding/ops）",
				},
				goal: {
					type: "string",
					description: "目标描述",
				},
				mode: {
					type: "string",
					enum: MODE_ENUM,
					description: "任务模式，决定阶段种子与完成证据类型（未指定时默认沿用已有项目 mode，新建项目默认 ctf）",
				},
				root: {
					type: "string",
					description: "项目目录，默认持久化工作区或当前 cwd",
				},
				resume: {
					type: "boolean",
					default: false,
					description: "恢复已停止/软暂停的项目，保留 facts/intents",
				},
				force: {
					type: "boolean",
					default: false,
					description: "覆盖现有项目（备份旧 state）",
				},
				migrate: {
					type: "boolean",
					default: false,
					description: "从同目录 .sapper 图迁移旧项目",
				},
				autoStart: {
					type: "boolean",
					default: false,
					description: "是否在初始化后立即触发首轮确定性自动侦察批",
				},
				scope: {
					type: "object",
					description: "可选靶标范围与风险策略覆盖",
					properties: {
						allowHosts: { type: "array", items: { type: "string" } },
						allowCidrs: { type: "array", items: { type: "string" } },
						denyHosts: { type: "array", items: { type: "string" } },
						allowSubdomains: { type: "boolean" },
						allowPrivateNetwork: { type: "boolean" },
						allowDestructive: { type: "boolean" },
						allowLoopback: { type: "boolean" },
						oobDomains: { type: "array", items: { type: "string" } },
					},
					additionalProperties: false,
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_plan",
		description:
			"播种一个阶段的意图（recon/surface/vuln/exploit/post/report），或追加自定义意图。支持规范化三元组去重、在途目标去重、批派单 6KB 分片溢写与出口注入，返回 rejectedReasons。",
		inputSchema: {
			type: "object",
			properties: {
				phase: {
					type: "string",
					enum: PHASE_ENUM,
					description: "要播种的阶段",
				},
				intents: {
					type: "array",
					description: "自定义意图列表",
					items: {
						type: "object",
						properties: {
							title: { type: "string" },
							detail: { type: "string" },
							phase: { type: "string", enum: PHASE_ENUM },
							from: { type: "array", items: { type: "string" } },
							priority: { type: "number" },
							target: { type: "string" },
							targetKey: { type: "string" },
							hint: { type: "string" },
							expectedKind: { type: "string", enum: FACT_KIND_ENUM },
							surfaceDomain: { type: "string", enum: SURFACE_DOMAIN_ENUM },
							force: { type: "boolean" },
						},
						required: ["title"],
						additionalProperties: false,
					},
				},
				force: {
					type: "boolean",
					description: "是否强制绕过冷却与重复抑制",
				},
				cooldown_ms: {
					type: "number",
					description: "可选 blocked 目标冷却窗口毫秒数",
				},
				egress: {
					type: "string",
					description: "可选任务出口代理 URL（自动注入派单上下文与环境变量）",
				},
				batch_tasks: {
					type: "array",
					description: "可选待派发子任务批次：自动执行在途去重、出口注入与 >6000B 安全分片/溢写",
					items: {
						type: "object",
						additionalProperties: true,
					},
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_frontier",
		description: "列出当前可执行意图（依赖事实已满足、未被有效认领），结合跨项目历史经验自适应排序。",
		inputSchema: {
			type: "object",
			properties: {
				limit: {
					type: "number",
					default: 12,
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_claim",
		description:
			"认领一条意图，返回完整派单包（自动注入 resolved_host、出口代理指引、多角色鉴权差分头文件与输出契约，并登记在途目标去重）。",
		inputSchema: {
			type: "object",
			properties: {
				id: {
					type: "string",
					description: "意图 id，如 i007",
				},
				worker: {
					type: "string",
					default: "fujiang",
				},
				egress: {
					type: "string",
					description: "可选任务出口代理 URL（如 socks5h://127.0.0.1:7890）",
				},
				root: {
					type: "string",
				},
			},
			required: ["id"],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_commit",
		description:
			"提交意图结果或免票据直记事实（省略 id 或 free_note=true）。支持省略 kind 自动继承 expectedKind、结构化 agent_result 解析、evidence_ref 落盘指针、模板化回包拦截与假阳性门禁，并回显 blockedIntents vs blockedCommits。",
		inputSchema: {
			type: "object",
			properties: {
				id: {
					type: "string",
					description: "意图 id；省略或设 free_note=true 时免票据直接落账（#31）",
				},
				free_note: {
					type: "boolean",
					description: "免票据直记开关：open=0 时无需占用 intent 直接写入事实（#31）",
				},
				kind: {
					type: "string",
					enum: FACT_KIND_ENUM,
					description: "事实类型；省略时自动继承认领意图的 expectedKind（兜底 note，#29）",
				},
				title: {
					type: "string",
					default: "",
				},
				detail: {
					type: "string",
					default: "",
				},
				command: {
					type: "string",
				},
				output: {
					type: "string",
				},
				blocked: {
					type: "boolean",
					default: false,
				},
				note: {
					type: "string",
				},
				agent_result: {
					description: "子代理结构化回包 AgentResult（JSON 对象或字符串），自动解析提取命令、证据指标与结论（#51）",
					oneOf: [{ type: "string" }, { type: "object", additionalProperties: true }],
				},
				evidence_ref: {
					type: "string",
					description: "原始响应/日志证据文件相对路径指针（如 .nuwa/evidence/f001.log，#42）",
				},
				save_evidence_log: {
					type: "boolean",
					description: "是否自动将原始响应脱敏落盘到 .nuwa/evidence/<factId>.log 并绑定 evidence_ref（#42）",
				},
				raw_response: {
					type: "string",
					description: "可选完整原始 HTTP 响应内容，用于证据落盘与假阳性复核",
				},
				baseline: {
					description: "可选负向对照基线响应（401/404），用于假阳性门禁比对（#24）",
					oneOf: [
						{ type: "string" },
						{ type: "object", additionalProperties: true },
						{ type: "array", items: { type: "object", additionalProperties: true } },
					],
				},
				auto_downgrade: {
					type: "boolean",
					description: "命中假阳性门禁时是否自动降级为 note(false_positive) 落账（#24）",
				},
				strict_realism: {
					type: "boolean",
					description: "是否强制校验网络探针五项命中指标（#26, #39）",
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_flag",
		description: "立即入账 flag。output 必须包含完整 flag 值且经可信执行账本复验；同一 flag 幂等。不要等批次结束。",
		inputSchema: {
			type: "object",
			properties: {
				value: {
					type: "string",
				},
				command: {
					type: "string",
				},
				output: {
					type: "string",
				},
				challenge: {
					type: "string",
				},
				root: {
					type: "string",
				},
			},
			required: ["value", "command", "output"],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_complete",
		description:
			"请求完成项目或执行负向封盘（seal=true → status=sealed_negative，与夺旗并列为合法终态）。无实锤被拒时自动输出 report/seal 策略收敛建议。",
		inputSchema: {
			type: "object",
			properties: {
				from: {
					type: "array",
					items: { type: "string" },
					description: "完成引用的 fact id；省略则用全部已确认证据事实",
				},
				note: {
					type: "string",
				},
				seal: {
					type: "boolean",
					description: "负向封盘开关：对已穷尽攻击面且无正向漏洞的硬化目标合法封盘（status=sealed_negative，#22）",
				},
				reason: {
					type: "string",
					description: "负向封盘依据说明（seal=true 时使用）",
				},
				excluded_surface: {
					type: "array",
					items: { type: "string" },
					description: "已验证排除的攻击面列表（seal=true 时记录）",
				},
				coverage: {
					type: "object",
					additionalProperties: true,
					description: "覆盖度指标字典（seal=true 时合并记录）",
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_status",
		description:
			"查看项目状态（展示 repeat_ratio、last_ok、blockedIntents vs blockedCommits）。支持 raw/offset/limit/format 全量不截断输出，以及 inspect_intent / query_status / target_key / archive_query 纯只读零写入诊断。",
		inputSchema: {
			type: "object",
			properties: {
				raw: {
					type: "boolean",
					description: "是否输出不截断全量状态（#34）",
				},
				offset: {
					type: "number",
					description: "全量状态或只读查询分页起始偏移（#34）",
				},
				limit: {
					type: "number",
					description: "分页返回最大条数（#34, #35, #52）",
				},
				format: {
					type: "string",
					enum: ["text", "json"],
					description: "输出格式：text（默认）或 json（#34）",
				},
				inspect_intent: {
					type: "string",
					description: "纯只读诊断指定意图 ID（零磁盘写入，#35）",
				},
				query_status: {
					type: "string",
					enum: INTENT_STATUS_ENUM,
					description: "纯只读按状态筛选意图（零磁盘写入，#35）",
				},
				target_key: {
					type: "string",
					description: "纯只读按目标键筛选意图（零磁盘写入，#35）",
				},
				archive_query: {
					description: "纯只读检索跨轮 Episode 结构化归档索引（#52）",
					oneOf: [{ type: "string" }, { type: "object", additionalProperties: true }],
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_report",
		description:
			"生成评估报告（支持 md/json/sarif 2.1.0/timeline 时间线导出）。write=true 时落盘并自动写入 .nuwa/archive/episode-<N> 结构化归档索引，同时支持 report 阶段完结转移。",
		inputSchema: {
			type: "object",
			properties: {
				write: {
					type: "boolean",
					default: false,
				},
				format: {
					type: "string",
					enum: ["md", "json", "sarif", "timeline"],
					default: "md",
					description: "报告格式：md（默认）/ json / sarif / timeline（#42）",
				},
				episode: {
					type: "number",
					description: "指定 Episode 编号（用于 timeline 导出与归档索引，#42, #52）",
				},
				bundle: {
					type: "boolean",
					default: false,
					description: "是否同时生成 .nuwa/poc-bundle 脱敏证据包",
				},
				archive: {
					type: "boolean",
					description: "是否显式写入 .nuwa/archive/episode-<N>.json/.md 归档索引（write=true 时默认自动写入，#52）",
				},
				finalize_phase: {
					type: "boolean",
					description: "处于 report 阶段时是否立即执行完结/封盘/推进转移（#45）",
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_expand",
		description:
			"强制扩张攻击面：结合三元组去重、在途去重、表面分域保护、批分片与出口注入派生新意图，输出结构化 rejectedReasons。",
		inputSchema: {
			type: "object",
			properties: {
				force: {
					type: "boolean",
					description: "是否强制重派生",
				},
				egress: {
					type: "string",
					description: "可选出口代理 URL 注入新派生意图",
				},
				batch_tasks: {
					type: "array",
					description: "可选待派发任务列表：执行跨子代理在途去重、同目标探针合并与 >6000B 分片保护",
					items: {
						type: "object",
						additionalProperties: true,
					},
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_stop",
		description:
			"停机与软暂停控制：传 pause=true 可免确认即时软暂停（优雅挂起，/nuwa resume 恢复）；永动模式硬停机须显式传 confirm=\"STOP\"，硬停机时自动中断在途批并级联清理登记的残留子进程组。",
		inputSchema: {
			type: "object",
			properties: {
				reason: {
					type: "string",
					default: "manual stop/pause",
					description: "停机或软暂停原因（硬停机至少 4 字）",
				},
				confirm: {
					type: "string",
					description: "硬停机确认口令：永动模式下人工硬停机必须显式传 \"STOP\"",
				},
				pause: {
					type: "boolean",
					default: false,
					description: "免确认即时软暂停开关（true 时无需 confirm=\"STOP\" 立即优雅挂起，#44）",
				},
				root: {
					type: "string",
				},
			},
			required: [],
			additionalProperties: false,
		},
	},
	{
		name: "nuwa_kb",
		description:
			"安全查询便携知识库（参数化 FTS5 + 跨项目历史经验提示）：产品审计卡、CVE、ATT&CK 技术。支持 'spring'、'CVE-2021-44228'、'T1190'。",
		inputSchema: {
			type: "object",
			properties: {
				query: {
					type: "string",
				},
				kind: {
					type: "string",
					enum: KB_KIND_ENUM,
					default: "auto",
				},
				limit: {
					type: "number",
					default: 5,
				},
			},
			required: ["query"],
			additionalProperties: false,
		},
	},
] as const;

const TOOL_DEFINITION_MAP = new Map<string, McpToolDefinition>(
	NUWA_CORE_TOOLS.map((tool) => [tool.name, tool]),
);

/** 根据工具名称查找核心 MCP 工具定义。 */
export function getNuwaToolDefinition(name: string): McpToolDefinition | undefined {
	return TOOL_DEFINITION_MAP.get(name);
}

/** 判断字符串是否为合法的女娲核心工具名。 */
export function isNuwaToolName(name: string): name is NuwaToolName {
	return TOOL_DEFINITION_MAP.has(name);
}

/** 判断值是否为合法的 JSON-RPC 2.0 `id`（string | number | null，拒绝 NaN/Infinity）。 */
export function isValidJsonRpcId(id: unknown): id is JsonRpcId {
	if (id === null || typeof id === "string") return true;
	if (typeof id === "number") return Number.isFinite(id);
	return false;
}

/** 构造标准 JSON-RPC 2.0 请求对象。 */
export function createJsonRpcRequest<P = Record<string, unknown> | unknown[]>(
	id: JsonRpcId,
	method: string,
	params?: P,
): JsonRpcRequest<P> {
	return {
		jsonrpc: JSONRPC_VERSION,
		id,
		method,
		...(params !== undefined ? { params } : {}),
	};
}

/** 构造标准 JSON-RPC 2.0 通知对象（不含 `id`）。 */
export function createJsonRpcNotification<P = Record<string, unknown> | unknown[]>(
	method: string,
	params?: P,
): JsonRpcNotification<P> {
	return {
		jsonrpc: JSONRPC_VERSION,
		method,
		...(params !== undefined ? { params } : {}),
	};
}

/** 构造标准 JSON-RPC 2.0 成功响应对象。 */
export function createJsonRpcSuccess<R = unknown>(id: JsonRpcId, result: R): JsonRpcSuccessResponse<R> {
	return {
		jsonrpc: JSONRPC_VERSION,
		id,
		result,
	};
}

/** 构造标准 JSON-RPC 2.0 错误响应对象。 */
export function createJsonRpcError<D = unknown>(
	id: JsonRpcId,
	code: JsonRpcErrorCode,
	message: string,
	data?: D,
): JsonRpcErrorResponse<D> {
	return {
		jsonrpc: JSONRPC_VERSION,
		id,
		error: {
			code,
			message,
			...(data !== undefined ? { data } : {}),
		},
	};
}

/** 判断消息是否为合法 JSON-RPC 2.0 请求（显式包含有效 `id`）。 */
export function isJsonRpcRequest(msg: unknown): msg is JsonRpcRequest {
	if (!msg || typeof msg !== "object" || Array.isArray(msg)) return false;
	const rec = msg as Record<string, unknown>;
	if (rec.jsonrpc !== JSONRPC_VERSION) return false;
	if (typeof rec.method !== "string" || rec.method.length === 0) return false;
	if (!("id" in rec) || rec.id === undefined) return false;
	return isValidJsonRpcId(rec.id);
}

/** 判断消息是否为合法 JSON-RPC 2.0 通知（不含 `id` 或 `id === undefined`）。 */
export function isJsonRpcNotification(msg: unknown): msg is JsonRpcNotification {
	if (!msg || typeof msg !== "object" || Array.isArray(msg)) return false;
	const rec = msg as Record<string, unknown>;
	if (rec.jsonrpc !== JSONRPC_VERSION) return false;
	if (typeof rec.method !== "string" || rec.method.length === 0) return false;
	return !("id" in rec) || rec.id === undefined;
}
