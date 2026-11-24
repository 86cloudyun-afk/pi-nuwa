/**
 * 女娲 v3.0 多领域 Profile 引擎、知识库自动富化与战略复盘规划模块。
 *
 * 约束：
 * - 仅使用 `import type` 引用 `./nuwa`，严禁运行时导入，避免扩展部署为 `index.ts` 时出现循环依赖。
 * - 全部导出函数为纯函数或只读计算，不直接修改 `NuwaState`、不发外部网络请求。
 */
import type { Fact, FactKind, NuwaState, Phase } from "./nuwa";

export type ProfileMode = "ctf" | "pentest" | "audit" | "coding" | "ops";

export interface ProfileSeed {
	key: string;
	title: string;
	detail: string;
	priority?: number;
}

export interface ProfileSpec {
	mode: ProfileMode;
	label: string;
	proofKinds: FactKind[];
	phases: readonly Phase[];
	requireHttpTarget: boolean;
	seeds: Record<Phase, Array<{ key: string; title: string; detail: string; priority?: number }>>;
}

export interface DerivedIntentSpec {
	key: string;
	phase: Phase;
	title: string;
	detail: string;
	priority: number;
	from: string[];
}

export type KbLookupFn = (q: string, kind: "auto" | "product" | "cve", limit?: number) => string;

export const PROFILE_MODES: readonly ProfileMode[] = ["ctf", "pentest", "audit", "coding", "ops"] as const;

const STANDARD_PHASES: readonly Phase[] = ["recon", "surface", "vuln", "exploit", "post", "report"] as const;

const SECURITY_SEEDS: Record<Phase, ProfileSeed[]> = {
	recon: [
		{
			key: "http",
			title: "HTTP 存活与响应指纹",
			priority: 90,
			detail: [
				"目标: 确认 {URL} 服务存活、状态码、响应头 Server/X-Powered-By、页面标题与重定向链。",
				"要求: 使用只读 HTTP 探测命令采集响应头与页面摘要，输出落盘至 {OUT}/。",
				"证据: kind=service；记录状态码、服务指纹与 Cookie 属性。",
			].join("\n"),
		},
		{
			key: "ports",
			title: "端口与服务枚举",
			priority: 88,
			detail: [
				"目标: 盘点 {HOST} 开放端口、协议与服务版本基线。",
				"要求: 记录每个开放端口的 port/proto/service/version 信息，便于后续分面深挖。",
				"证据: kind=service；detail 需包含 <port>/tcp 或 <port>/udp 格式。",
			].join("\n"),
		},
		{
			key: "dirs",
			title: "目录与路由基线发现",
			priority: 80,
			detail: [
				"目标: 识别 {URL} 的常见公开路径、管理入口与静态资源目录。",
				"要求: 记录非 404 路径的状态码、响应长度与跳转目标。",
				"证据: kind=endpoint；至少给出一条可复验路径记录。",
			].join("\n"),
		},
		{
			key: "vhost",
			title: "虚拟主机与子域核查",
			priority: 60,
			detail: [
				"目标: 在授权范围（Scope）内核查同主机关联的虚拟主机与子域资产。",
				"要求: 先建立随机 Host 响应基线，再对比差异；若目标为纯 IP 则 blocked 说明原因。",
				"证据: kind=asset；detail 包含主机名、状态码与基线差异。",
			].join("\n"),
		},
		{
			key: "tlsjs",
			title: "证书 SAN 与前端路由提取",
			priority: 55,
			detail: [
				"目标: 检查 {HOST}:{PORT} TLS 证书主体/SAN 扩展，并从前端静态资源提取接口路由。",
				"要求: 记录证书有效范围、SAN 列表与页面引用的 API 路径。",
				"证据: kind=service 或 endpoint；无 TLS/无 JS 时记录事实并收口。",
			].join("\n"),
		},
		{
			key: "techcve",
			title: "技术栈与知识库 CVE 映射",
			priority: 70,
			detail: [
				"目标: 将已识别产品组件与版本号通过 nuwa_kb 映射至相关安全公告或已知 CVE。",
				"要求: 仅记录与实测版本相符的条目，注明影响版本范围与前置验证条件。",
				"证据: kind=vuln 或 note；须附带版本确认命令与回显。",
			].join("\n"),
		},
	],
	surface: [
		{
			key: "crawl",
			title: "站点路由与链接收敛",
			priority: 85,
			detail: [
				"目标: 梳理 {URL} 的页面路由、表单动作与接口集合。",
				"要求: 汇总去重后的路径、HTTP 方法与参数名清单，保存至 {OUT}/。",
				"证据: kind=endpoint；列出路由与交互入口。",
			].join("\n"),
		},
		{
			key: "params",
			title: "输入参数与边界清点",
			priority: 80,
			detail: [
				"目标: 盘点查询串、请求体、Header 与 Cookie 中的外部可控输入字段。",
				"要求: 标注参数位置、数据类型与服务端校验表现。",
				"证据: kind=endpoint；写明参数名、位置与示例响应。",
			].join("\n"),
		},
		{
			key: "auth",
			title: "认证机制与会话策略核查",
			priority: 78,
			detail: [
				"目标: 检查登录、会话令牌、Cookie 安全标记及认证保护机制。",
				"要求: 记录认证方式、锁定/验证码策略与会话属性。",
				"证据: kind=endpoint 或 cred；凭据信息须脱敏并附实测证据。",
			].join("\n"),
		},
		{
			key: "sensitive",
			title: "敏感配置与暴露面核查",
			priority: 76,
			detail: [
				"目标: 检查是否存在不应公开的配置文件、元信息或监控调试端点。",
				"要求: 仅做只读确认，记录响应码、体积及脱敏摘要。",
				"证据: kind=endpoint、vuln 或 loot。",
			].join("\n"),
		},
		{
			key: "api",
			title: "API 文档与 Schema 暴露检查",
			priority: 74,
			detail: [
				"目标: 检查 OpenAPI/Swagger 文档、GraphQL Schema 及版本化 API 入口。",
				"要求: 记录开放接口清单与认证要求。",
				"证据: kind=endpoint；说明文档可达性与鉴权状态。",
			].join("\n"),
		},
		{
			key: "uploads",
			title: "文件上传与解析入口梳理",
			priority: 60,
			detail: [
				"目标: 识别上传、导入、导出与附件处理接口及其限制策略。",
				"要求: 记录允许的内容类型、大小上限与返回结构；若无上传功能则 blocked 收口。",
				"证据: kind=endpoint。",
			].join("\n"),
		},
	],
	vuln: [
		{
			key: "sqli",
			title: "数据库查询边界核验",
			priority: 90,
			detail: "目标: 检查数据库查询参数是否存在未参数化拼接或异常回显缺陷，记录最小化只读复现依据。证据: kind=vuln 或 note。",
		},
		{
			key: "xss",
			title: "输出编码与前端渲染安全核验",
			priority: 70,
			detail: "目标: 检查用户输入在 HTML/属性/脚本上下文中的转义与 CSP 防护策略。证据: kind=vuln 或 note。",
		},
		{
			key: "ssti",
			title: "服务端模板渲染边界核验",
			priority: 76,
			detail: "目标: 检查模板渲染入口是否存在可控表达式解析风险，确认引擎类型与过滤策略。证据: kind=vuln 或 note。",
		},
		{
			key: "lfi",
			title: "文件路径规范化与读取边界核验",
			priority: 74,
			detail: "目标: 检查文件下载、模板包含与静态资源读取接口的路径规范化控制。证据: kind=vuln 或 note。",
		},
		{
			key: "ssrf",
			title: "服务端出向请求目标校验核验",
			priority: 72,
			detail: "目标: 检查 URL 抓取、回调或代理接口的目标白名单与协议限制。证据: kind=vuln 或 note。",
		},
		{
			key: "cmdi",
			title: "系统调用参数隔离核验",
			priority: 82,
			detail: "目标: 检查触发外部命令或子进程的接口是否正确进行参数隔离。证据: kind=vuln 或 note。",
		},
		{
			key: "upload-vuln",
			title: "上传校验与存储隔离核验",
			priority: 68,
			detail: "目标: 检查上传接口的后缀校验、MIME 检查、重命名与静态目录执行隔离。证据: kind=vuln 或 note。",
		},
		{
			key: "idor",
			title: "对象级访问控制核验",
			priority: 70,
			detail: "目标: 验证同级/低权限角色访问受保护资源 ID 时服务端是否强制校验归属关系。证据: kind=vuln 或 note。",
		},
		{
			key: "authbypass",
			title: "认证与访问控制一致性核验",
			priority: 76,
			detail: "目标: 检查反向代理路径解析、Header 信任边界及令牌签名校验是否存在绕过风险。证据: kind=vuln 或 note。",
		},
		{
			key: "component",
			title: "组件版本安全缺陷复核",
			priority: 80,
			detail: "目标: 对照 nuwa_kb 命中项复核组件实际版本、配置状态与缓解措施。证据: kind=vuln 或 note。",
		},
	],
	exploit: [
		{
			key: "verify",
			title: "核心风险链端到端复验",
			priority: 90,
			detail: "目标: 对已确认的高优先缺陷做最小化、非破坏性端到端复验，留存完整命令与原始回显。证据: kind=vuln 或 loot。",
		},
		{
			key: "rce",
			title: "执行边界影响确认",
			priority: 88,
			detail: "目标: 在授权范围内验证最小只读身份证明（非破坏性），确认影响边界。证据: kind=vuln 或 blocked。",
		},
		{
			key: "creds",
			title: "配置与凭据暴露影响评估",
			priority: 84,
			detail: "目标: 核查因配置缺陷暴露的凭据范围并进行脱敏记录。证据: kind=cred 或 loot。",
		},
		{
			key: "privesc",
			title: "权限边界与最小权限评估",
			priority: 70,
			detail: "目标: 评估当前权限上下文与宿主机/容器隔离配置是否存在过度授权。证据: kind=vuln 或 blocked。",
		},
		{
			key: "lateral",
			title: "授权网段可达性评估",
			priority: 60,
			detail: "目标: 仅在明确授权 Scope 内评估关联服务可达性与网络隔离现状。证据: kind=asset 或 blocked。",
		},
	],
	post: [
		{
			key: "flag",
			title: "目标验收标记取证",
			priority: 95,
			detail: "目标: 按任务验收口径定位目标证明（CTF 场景下的 flag 或授权评估核心证据），命中后立即通过 nuwa_flag / nuwa_commit 入账。",
		},
		{
			key: "loot",
			title: "核心影响证据脱敏归档",
			priority: 70,
			detail: "目标: 汇总证明风险影响面的脱敏证据与元数据清单。证据: kind=loot。",
		},
		{
			key: "impact",
			title: "影响面与恢复清理核查",
			priority: 50,
			detail: "目标: 评估潜在业务影响、暴露面范围与测试残留清理状态，禁止破坏性操作。证据: kind=note。",
		},
	],
	report: [
		{
			key: "chain",
			title: "证据链与复现路径整理",
			priority: 90,
			detail: "目标: 审阅 nuwa_report(write=false)，核对事实→意图→证据的完整链路并补齐缺口。证据: kind=note。",
		},
		{
			key: "fix",
			title: "分级修复与加固建议",
			priority: 60,
			detail: "目标: 针对每条确认风险给出具体定位、根因分析、修复方案与回归验证方法。证据: kind=note。",
		},
	],
};

const CODING_SEEDS: Record<Phase, ProfileSeed[]> = {
	recon: [
		{
			key: "repo-map",
			title: "代码库结构与构建系统测绘",
			priority: 92,
			detail: [
				"目标: 梳理目标工作区 {HOST} 的目录布局、语言栈、包管理配置与入口文件。",
				"要求: 记录核心模块清单、构建脚本与测试入口，避免遗漏约束文件。",
				"证据: kind=service 或 note；附目录/配置文件检查命令与回显。",
			].join("\n"),
		},
		{
			key: "test-baseline",
			title: "现有测试与构建基线执行",
			priority: 88,
			detail: [
				"目标: 运行现有测试套件与类型检查，建立改动前的基线通过率与耗时。",
				"要求: 完整记录测试命令、通过/失败统计与已存在的警告。",
				"证据: kind=loot 或 note；附实测命令与摘要回显。",
			].join("\n"),
		},
		{
			key: "deps-config",
			title: "依赖清单与运行环境核查",
			priority: 75,
			detail: [
				"目标: 核查运行时版本、关键依赖约束、环境变量与外部接口契约。",
				"要求: 识别潜在的版本冲突或平台差异（macOS/Linux）。",
				"证据: kind=asset 或 note。",
			].join("\n"),
		},
	],
	surface: [
		{
			key: "api-surface",
			title: "模块接口与调用链分析",
			priority: 86,
			detail: [
				"目标: 梳理待改动模块的导出函数、类型定义、上下游调用方与数据流。",
				"要求: 列出必须保持向后兼容的公共接口契约。",
				"证据: kind=endpoint 或 note；附代码检索命令与关键定义位置。",
			].join("\n"),
		},
		{
			key: "change-impact",
			title: "变更影响面与风险边界评估",
			priority: 80,
			detail: [
				"目标: 评估需求改动对并发、持久化状态、配置文件与下游测试的影响面。",
				"要求: 列出关键边界条件与需要新增回归测试的场景。",
				"证据: kind=note。",
			].join("\n"),
		},
	],
	vuln: [
		{
			key: "root-cause",
			title: "缺陷根因定位与最小复现",
			priority: 90,
			detail: [
				"目标: 对目标问题或待实现特性建立最小复现用例，精确定位根因或设计缺口。",
				"要求: 明确触发路径、文件行号与预期行为差异。",
				"证据: kind=vuln 或 note；附复现测试命令与输出。",
			].join("\n"),
		},
		{
			key: "static-check",
			title: "类型检查与静态分析诊断",
			priority: 76,
			detail: [
				"目标: 运行 lint/typecheck 等静态检查，识别潜在类型不匹配、空值处理或资源泄漏。",
				"证据: kind=note；附工具输出摘要。",
			].join("\n"),
		},
	],
	exploit: [
		{
			key: "implement",
			title: "核心代码实现与改动落地",
			priority: 92,
			detail: [
				"目标: 按架构设计与兼容性约束完成核心代码修改，保持变更聚焦、可读且可测。",
				"要求: 记录改动文件清单与核心设计取舍。",
				"证据: kind=loot 或 note；附 git diff --stat 或校验输出。",
			].join("\n"),
		},
		{
			key: "edge-cases",
			title: "边界条件与异常路径补齐",
			priority: 82,
			detail: [
				"目标: 补齐空输入、超时、重试、并发与错误降级等边界保护，并同步新增单元测试。",
				"证据: kind=loot 或 note；附新增测试用例列表。",
			].join("\n"),
		},
	],
	post: [
		{
			key: "verify-tests",
			title: "全量测试与回归验收",
			priority: 95,
			detail: [
				"目标: 运行新增测试与全量回归测试，确保 0 失败且无回归退化。",
				"要求: 将真实测试命令、通过数与关键输出作为验收证据入账。",
				"证据: kind=loot；必须附带完整测试命令与通过回显。",
			].join("\n"),
		},
		{
			key: "build-check",
			title: "构建产物与工作区整洁校验",
			priority: 80,
			detail: [
				"目标: 验证构建/打包产物可用，核对 git status 无临时垃圾文件残留。",
				"证据: kind=loot 或 note。",
			].join("\n"),
		},
	],
	report: [
		{
			key: "summary",
			title: "变更交付总结与文档同步",
			priority: 90,
			detail: [
				"目标: 生成交付报告，同步更新变更日志与使用文档，汇总验证结果。",
				"证据: kind=note；完成后满足验收条件可调 nuwa_complete。",
			].join("\n"),
		},
		{
			key: "followup",
			title: "遗留风险与后续优化项整理",
			priority: 65,
			detail: "目标: 记录尚未纳入本次迭代的边界假设、性能观察与后续改进建议。证据: kind=note。",
		},
	],
};

const OPS_SEEDS: Record<Phase, ProfileSeed[]> = {
	recon: [
		{
			key: "service-health",
			title: "服务健康状态与进程端口快照",
			priority: 92,
			detail: [
				"目标: 对目标服务 {HOST} 做只读健康探活，采集进程状态、监听端口与存活探针响应。",
				"要求: 禁止变更线上状态，所有采样结果归档至 {OUT}/。",
				"证据: kind=service；附健康检查命令与原始回显。",
			].join("\n"),
		},
		{
			key: "host-metrics",
			title: "系统资源与容量基线采集",
			priority: 86,
			detail: [
				"目标: 采集 CPU、内存、磁盘空间、inode、文件描述符与负载均值基线。",
				"证据: kind=service 或 note；附实测系统指标输出。",
			].join("\n"),
		},
		{
			key: "config-baseline",
			title: "运行配置与近期变更基线核查",
			priority: 80,
			detail: [
				"目标: 只读核对服务配置版本、启动参数、环境变量与最近发布/变更记录。",
				"证据: kind=asset 或 note。",
			].join("\n"),
		},
	],
	surface: [
		{
			key: "log-triage",
			title: "错误日志聚类与异常时间线定位",
			priority: 88,
			detail: [
				"目标: 检索应用/系统日志中的 ERROR/WARN/OOM/Timeout 峰值并对齐异常起始时间点。",
				"证据: kind=endpoint 或 note；附日志筛选命令与关键行。",
			].join("\n"),
		},
		{
			key: "dep-check",
			title: "上下游依赖与网络连通性核查",
			priority: 82,
			detail: [
				"目标: 核查数据库、缓存、消息队列、DNS 与依赖 API 的连通性、延迟与错误率。",
				"证据: kind=service 或 endpoint。",
			].join("\n"),
		},
	],
	vuln: [
		{
			key: "rca-verify",
			title: "故障根因假设与指标关联验证",
			priority: 90,
			detail: [
				"目标: 综合健康快照、日志聚类与依赖状态验证首要根因假设，排除误导症状。",
				"证据: kind=vuln 或 note；明确根因证据链。",
			].join("\n"),
		},
		{
			key: "drift-check",
			title: "配置漂移与资源瓶颈排查",
			priority: 76,
			detail: [
				"目标: 核查连接池耗尽、超时参数错配、磁盘满或证书临期等常见运维隐患。",
				"证据: kind=vuln 或 note。",
			].join("\n"),
		},
	],
	exploit: [
		{
			key: "remediate",
			title: "低风险止损与修复变更实施",
			priority: 90,
			detail: [
				"目标: 在授权且可回滚前提下实施最小化修复或配置校正，严禁未确认的高危破坏命令。",
				"要求: 执行前留存旧配置备份，执行后立即记录变更回显。",
				"证据: kind=loot 或 note。",
			].join("\n"),
		},
		{
			key: "rollback-check",
			title: "备份完整性与回滚路径核验",
			priority: 78,
			detail: [
				"目标: 确认变更前备份可读、回滚步骤明确且可在异常时秒级恢复。",
				"证据: kind=note。",
			].join("\n"),
		},
	],
	post: [
		{
			key: "post-verify",
			title: "恢复后健康探针与 SLO 复验",
			priority: 95,
			detail: [
				"目标: 连续复验核心健康端点、错误率、延迟与关键业务指标，确认服务稳定恢复。",
				"证据: kind=loot；附复验命令与正常回显。",
			].join("\n"),
		},
		{
			key: "cleanup-check",
			title: "告警收敛与临时产物清理检查",
			priority: 75,
			detail: [
				"目标: 确认告警恢复、无遗留诊断进程或临时大文件占用磁盘。",
				"证据: kind=note。",
			].join("\n"),
		},
	],
	report: [
		{
			key: "postmortem",
			title: "运维故障复盘报告生成",
			priority: 90,
			detail: [
				"目标: 汇总完整时间线、根因证据、止损操作与恢复验证结果，输出标准 Postmortem。",
				"证据: kind=note；满足验收后调用 nuwa_complete。",
			].join("\n"),
		},
		{
			key: "action-items",
			title: "监控告警与防复发改进清单",
			priority: 70,
			detail: "目标: 列出可执行的告警规则补充、自动化巡检项与架构韧性改进任务。证据: kind=note。",
		},
	],
};

function cloneSeeds(src: Record<Phase, ProfileSeed[]>): Record<Phase, ProfileSeed[]> {
	return {
		recon: src.recon.map((s) => ({ ...s })),
		surface: src.surface.map((s) => ({ ...s })),
		vuln: src.vuln.map((s) => ({ ...s })),
		exploit: src.exploit.map((s) => ({ ...s })),
		post: src.post.map((s) => ({ ...s })),
		report: src.report.map((s) => ({ ...s })),
	};
}

export function isProfileMode(mode: string): mode is ProfileMode {
	return (PROFILE_MODES as readonly string[]).includes(mode);
}

/** 按模式名获取领域 Profile 规范；未知模式回退到 ctf，返回独立副本避免被调用方意外修改。 */
export function getProfile(mode: string): ProfileSpec {
	const norm = String(mode ?? "")
		.trim()
		.toLowerCase();
	switch (norm) {
		case "pentest":
			return {
				mode: "pentest",
				label: "渗透测试与安全评估",
				proofKinds: ["vuln", "loot", "flag"],
				phases: [...STANDARD_PHASES],
				requireHttpTarget: true,
				seeds: cloneSeeds(SECURITY_SEEDS),
			};
		case "audit":
			return {
				mode: "audit",
				label: "代码与配置安全审计",
				proofKinds: ["vuln", "loot"],
				phases: [...STANDARD_PHASES],
				requireHttpTarget: true,
				seeds: cloneSeeds(SECURITY_SEEDS),
			};
		case "coding":
			return {
				mode: "coding",
				label: "软件工程自治开发",
				proofKinds: ["loot", "note"],
				phases: [...STANDARD_PHASES],
				requireHttpTarget: false,
				seeds: cloneSeeds(CODING_SEEDS),
			};
		case "ops":
			return {
				mode: "ops",
				label: "自动化运维与排障",
				proofKinds: ["loot", "note"],
				phases: [...STANDARD_PHASES],
				requireHttpTarget: false,
				seeds: cloneSeeds(OPS_SEEDS),
			};
		case "ctf":
		default:
			return {
				mode: "ctf",
				label: "CTF 靶场取证",
				proofKinds: ["flag"],
				phases: [...STANDARD_PHASES],
				requireHttpTarget: true,
				seeds: cloneSeeds(SECURITY_SEEDS),
			};
	}
}

// ============================================================================
// 技术栈关键词提取 + 知识库自动富化
// ============================================================================

const TECH_FACT_KINDS = new Set<FactKind>(["service", "endpoint", "vuln"]);

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

const TECH_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
	{ name: "nginx", re: /\bnginx(?:\/[\d.]+)?\b/i },
	{ name: "tomcat", re: /\b(?:apache[\s/-]*)?tomcat(?:\/[\d.]+)?\b/i },
	{ name: "apache", re: /\b(?:apache(?:\/[\d.]+)?|httpd(?:\/[\d.]+)?)\b/i },
	{ name: "php", re: /\bphp(?:\/[\d.]+|info)?\b|\.php(?:[?#/\s"'`]|$)/i },
	{ name: "spring", re: /\bspring(?:[\s-]*boot|[\s-]*cloud|[\s-]*mvc|framework)?\b|\bactuator\b/i },
	{ name: "fastjson", re: /\bfastjson\b/i },
	{ name: "thinkphp", re: /\bthinkphp\b/i },
	{ name: "shiro", re: /\b(?:apache[\s-]*)?shiro\b|\brememberMe=/i },
	{ name: "redis", re: /\bredis(?:[\s/-]*server|\/[\d.]+)?\b/i },
	{ name: "mysql", re: /\bmysql(?:d|\/[\d.]+)?\b|\bmariadb\b/i },
	{ name: "postgres", re: /\bpostgres(?:ql)?(?:\/[\d.]+)?\b/i },
	{ name: "grafana", re: /\bgrafana\b/i },
	{ name: "gitlab", re: /\bgitlab\b/i },
	{ name: "jenkins", re: /\bjenkins\b|\bx-jenkins\b/i },
	{ name: "wordpress", re: /\bwordpress\b|\bwp-(?:content|admin|login|json|includes)\b/i },
	{ name: "graphql", re: /\bgraphql\b|\bgraphiql\b/i },
	{ name: "swagger", re: /\bswagger(?:[-_\s]*ui)?\b|\bopenapi(?:\.json|\.ya?ml)?\b/i },
	{ name: "log4j", re: /\blog4j2?\b/i },
	{ name: "struts", re: /\bstruts2?\b/i },
	{ name: "weblogic", re: /\bweblogic\b/i },
	{ name: "nacos", re: /\bnacos\b/i },
	{ name: "elasticsearch", re: /\belasticsearch\b/i },
	{ name: "kibana", re: /\bkibana\b/i },
	{ name: "mongodb", re: /\bmongodb?\b/i },
	{ name: "minio", re: /\bminio\b/i },
	{ name: "jetty", re: /\bjetty(?:\/[\d.]+)?\b/i },
	{ name: "iis", re: /\bmicrosoft-iis(?:\/[\d.]+)?\b/i },
	{ name: "openssh", re: /\bopenssh(?:[_\s/-][\d.p]+)?\b/i },
	{ name: "django", re: /\bdjango\b/i },
	{ name: "flask", re: /\bflask\b|\bwerkzeug\b/i },
	{ name: "laravel", re: /\blaravel\b/i },
	{ name: "drupal", re: /\bdrupal\b/i },
	{ name: "confluence", re: /\bconfluence\b/i },
	{ name: "jira", re: /\bjira\b/i },
	{ name: "nexus", re: /\bnexus\b/i },
	{ name: "harbor", re: /\bharbor\b/i },
];

/** 从 service/endpoint/vuln 事实中提取标准化技术栈关键词与 CVE 编号（去重保序）。 */
export function extractTechKeywords(fact: Pick<Fact, "kind" | "title" | "detail" | "output">): string[] {
	if (!fact || !TECH_FACT_KINDS.has(fact.kind)) return [];
	const blob = [fact.title ?? "", fact.detail ?? "", fact.output ?? ""].join("\n");
	if (!blob.trim()) return [];

	const seen = new Set<string>();
	const out: string[] = [];
	const push = (kw: string) => {
		if (!kw || seen.has(kw)) return;
		seen.add(kw);
		out.push(kw);
	};

	for (const m of blob.matchAll(CVE_RE)) {
		push(m[0].toUpperCase());
	}
	for (const { name, re } of TECH_PATTERNS) {
		if (re.test(blob)) push(name);
	}
	return out;
}

function slugKeyword(kw: string): string {
	return (
		kw
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 48) || "item"
	);
}

function oneLine(text: string | undefined, max = 120): string {
	return String(text ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

function clipMultiline(text: string, max = 900): string {
	const cleaned = String(text ?? "").replace(/\r/g, "").trim();
	return cleaned.length > max ? `${cleaned.slice(0, max)}\n...(摘要已截断)` : cleaned;
}

function isKbHit(raw: string | undefined): boolean {
	const text = String(raw ?? "").trim();
	if (!text) return false;
	if (/^未命中/.test(text)) return false;
	if (/^ERROR:/i.test(text)) return false;
	return true;
}

/**
 * 基于已入账的 service/endpoint/vuln 事实自动查询本地知识库，派生高优先核验意图。
 *
 * - 每个命中条目生成 `key = kb:<fid>:<slug>`、`phase = "vuln"`、`priority = 86`、`from = [fact.id]`。
 * - 自动排除 `st.intents` 中已存在的 `key`。
 * - `lookupFn` 抛出异常（如缺 KB 库或 sqlite3 不可用）时静默吞错返回已有结果或空数组。
 */
export function deriveKbIntents(
	st: NuwaState,
	lookupFn: KbLookupFn,
	maxPerRun = 6,
): DerivedIntentSpec[] {
	const limit = Number.isFinite(maxPerRun) ? Math.floor(maxPerRun) : 6;
	if (limit <= 0 || typeof lookupFn !== "function") return [];

	const existingKeys = new Set(Object.values(st.intents ?? {}).map((i) => i.key));
	const addedKeys = new Set<string>();
	const out: DerivedIntentSpec[] = [];

	const facts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	for (const fact of facts) {
		if (out.length >= limit) break;
		if (!TECH_FACT_KINDS.has(fact.kind)) continue;
		const keywords = extractTechKeywords(fact);
		for (const kw of keywords) {
			if (out.length >= limit) break;
			const kwSlug = slugKeyword(kw);
			const key = `kb:${fact.id}:${kwSlug}`;
			if (existingKeys.has(key) || addedKeys.has(key)) continue;

			const lookupKind: "auto" | "product" | "cve" = /^CVE-\d{4}-\d{4,7}$/i.test(kw) ? "cve" : "product";
			let kbText = "";
			try {
				kbText = lookupFn(kw, lookupKind, 3);
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				if (/知识库不存在|ENOENT/i.test(msg)) {
					return out;
				}
				continue;
			}
			if (!isKbHit(kbText)) continue;

			addedKeys.add(key);
			out.push({
				key,
				phase: "vuln",
				title: `知识库核验 ${kw} (${fact.id})`,
				detail: [
					`目标: 根据本地知识库命中结果，对 ${fact.id} (${oneLine(fact.title, 80)}) 识别到的 ${kw} 进行版本匹配与配置核验。`,
					`来源事实: ${fact.id} [${fact.kind}] ${oneLine(fact.title, 100)}`,
					`知识库摘要:`,
					clipMultiline(kbText, 900),
					`要求: 仅对实测版本和授权范围匹配的条目做非破坏性验证，命令与关键回显原样通过 nuwa_commit 入账；不匹配则 commit(blocked=true, note="版本/条件不匹配")。`,
				].join("\n"),
				priority: 86,
				from: [fact.id],
			});
		}
	}

	return out;
}

// ============================================================================
// 战略复盘规划（Reflection & Re-planning）
// ============================================================================

const PHASE_CLOSING_REASON_RE = /(phase|stage|end|clos|advance|finish|empty|exhaust|收尾)/i;

/**
 * 在阶段收尾或连续停滞（`stall >= 3`）时生成战略复盘规划意图。
 *
 * - 去重键：`reflect:e<ep>:<phase>:<bucket>`
 * - 引导模型结合已有事实与阻塞原因调用 `nuwa_plan(intents=[...])` 构建带 `from` 依赖链的新假设。
 */
export function buildReflectIntentSpec(
	st: NuwaState,
	triggerReason: string,
): DerivedIntentSpec | null {
	if (!st?.project || st.project.status !== "active") return null;

	const phase = st.project.phase;
	const ep = Number.isFinite(st.project.episode) && (st.project.episode as number) > 0 ? (st.project.episode as number) : 1;
	const stall = Number(st.runtime?.stall ?? 0);
	const reason = String(triggerReason ?? "").trim();

	const phaseIntents = Object.values(st.intents ?? {}).filter((i) => i.phase === phase);
	const phaseLive = phaseIntents.filter((i) => i.status === "open" || i.status === "claimed");
	const phaseSettled = phaseIntents.length - phaseLive.length;
	const isPhaseClosed = phaseIntents.length > 0 && phaseLive.length === 0;
	const isPhaseClosing = phaseLive.length <= 1 && phaseSettled >= 2;
	const reasonIndicatesPhaseEnd = PHASE_CLOSING_REASON_RE.test(reason);
	const isStalled = stall >= 3;

	if (!isStalled && !isPhaseClosed && !isPhaseClosing && !reasonIndicatesPhaseEnd) {
		return null;
	}

	const bucket = isStalled ? `s${Math.floor(stall / 3)}` : "closing";
	const key = `reflect:e${ep}:${phase}:${bucket}`;
	if (Object.values(st.intents ?? {}).some((i) => i.key === key)) {
		return null;
	}

	const allFacts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const keyFacts = allFacts.filter((f) => f.kind !== "note" && f.kind !== "blocked");
	const fromIds = keyFacts.slice(-4).map((f) => f.id);

	const factSummary = (keyFacts.length ? keyFacts : allFacts)
		.slice(-8)
		.map((f) => `- ${f.id} [${f.kind}] ${oneLine(f.title, 70)} :: ${oneLine(f.detail, 90)}`)
		.join("\n");

	const blockedSummary = Object.values(st.intents ?? {})
		.filter((i) => i.status === "blocked")
		.slice(-6)
		.map((i) => `- ${i.id} [${i.phase}] ${oneLine(i.title, 50)} => ${oneLine(i.note, 80)}`)
		.join("\n");

	const mode = st.project.mode;
	const hypothesisNoun =
		mode === "coding" ? "实现/排障假设与验证任务" : mode === "ops" ? "根因排查假设与恢复验证项" : "新攻击假设与验证路径";

	const triggerLabel = reason || (isStalled ? `stall=${stall}` : `phase-closing:${phase}`);

	return {
		key,
		phase,
		title: `战略复盘规划 (${phase} · ${oneLine(triggerLabel, 32)})`,
		detail: [
			`触发原因: ${triggerLabel}（第 E${ep} 轮 · 阶段 ${phase} · stall=${stall}）。`,
			``,
			`当前关键事实（共 ${allFacts.length} 条）:`,
			factSummary || "- (暂无已入账事实)",
			``,
			`近期阻塞与踩坑记录:`,
			blockedSummary || "- (暂无阻塞记录)",
			``,
			`必须执行的复盘动作:`,
			`1. 综合以上已确认事实与阻塞原因，排除已经证伪或被拦截的死路，交叉关联端口、接口、组件版本与凭据线索。`,
			`2. 调用 nuwa_plan(intents=[{ title, detail, phase, from: ["fNNN"], priority }]) 新增 2–4 条带明确 from 依赖链的${hypothesisNoun}，避免重复既有失败路径。`,
			`3. 规划入账后，使用 nuwa_commit(id="{ID}", kind="note", title="复盘结论", detail="...") 归纳新增假设与换路理由。`,
		].join("\n"),
		priority: 88,
		from: fromIds,
	};
}
