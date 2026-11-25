/**
 * 女娲 v5.0 结构化报告与脱敏审计取证包模块（SARIF 2.1.0 / JSON / 分层 Markdown / PoC Evidence Bundle）。
 *
 * 职责：
 * 1. `inferFindingRuleMeta`：将漏洞与 Flag 事实自动归类至标准规则 ID、CWE 与严重级别。
 * 2. `renderStratifiedMarkdownReport`：分层渲染已确认漏洞、待复验候选（Candidate）、已驳回误报（Rejected）、
 *    多资产拓扑、假设图推理状态与跨世代累计统计，并在提供项目根时全量脱敏 Vault 凭据。
 * 3. `buildSarifReport`：生成符合 SARIF 2.1.0 规范的机器可读结果，严格仅包含已确认漏洞（confirmed），
 *    杜绝未复验候选与误报污染上游告警系统。
 * 4. `buildJsonReport`：输出完整结构化 JSON 评估报告并执行全量 Vault 凭据脱敏。
 * 5. `writePocBundle`：在 `<root>/.nuwa/poc-bundle/` 下以 0o700 目录 / 0o600 文件权限原子落盘
 *    审计取证包（`README.md`、`report.sarif.json`、`evidence-<factId>.json`、`manifest.json` 含 SHA-256 校验）。
 *
 * 约束：严禁运行时 `import` 或 `require` `./nuwa`，仅使用 `import type` 引用 `./types`。
 */
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AssetNode, Fact, HypothesisNode, NuwaState } from "./types";
import { partitionFactsByVerifyStage } from "./verifier-gate";
import { redactVaultSecrets } from "./session-vault";
import { atomicWrite, cell } from "./storage";

export interface FindingRuleMeta {
	ruleId: string;
	cwe?: string;
	level: "error" | "warning" | "note";
	category: string;
}

export interface PocBundleResult {
	dir: string;
	manifestPath: string;
	sarifPath: string;
	files: string[];
	confirmedCount: number;
}

const RULE_DESCRIPTIONS: Record<string, string> = {
	"NUWA-BOLA": "Broken Object Level Authorization (IDOR / BOLA)",
	"NUWA-AUTH": "Broken Function Level Authorization or Authentication Bypass",
	"NUWA-SQLI": "SQL Injection",
	"NUWA-SSRF": "Server-Side Request Forgery (SSRF)",
	"NUWA-LFI": "Path Traversal / Arbitrary File Read",
	"NUWA-RCE": "OS Command Injection or Remote Code Execution",
	"NUWA-XSS": "Cross-Site Scripting (XSS)",
	"NUWA-EXPOSURE": "Sensitive Information Exposure or Misconfiguration",
	"NUWA-FLAG": "Authorized Assessment Proof Artifact (Flag)",
	"NUWA-VULN": "Confirmed Security Finding",
};

const BOLA_IDOR_RE =
	/\b(?:idor|bola|broken\s+object\s+level|insecure\s+direct\s+object)\b|对象级越权|水平越权|越权修改他人|越权访问他人/i;
const BFLA_AUTH_RE =
	/\b(?:bfla|broken\s+function\s+level|auth[\s_-]?bypass|authentication\s+bypass|authorization\s+bypass|unauth(?:orized)?\s+admin|jwt\s+(?:none|bypass|forgery)|privilege\s+escalation)\b|功能级越权|垂直越权|认证绕过|鉴权绕过|未授权管理|权限绕过|权限提升/i;
const SQLI_RE = /\b(?:sqli|sql\s+injection)\b|sql\s*注入/i;
const SSRF_RE = /\b(?:ssrf|server[\s_-]?side\s+request\s+forgery)\b|服务端请求伪造/i;
const LFI_RE =
	/\b(?:lfi|path\s+traversal|directory\s+traversal|arbitrary\s+file\s+read|local\s+file\s+inclusion)\b|路径穿越|目录穿越|任意文件读取|本地文件包含/i;
const RCE_CMDI_RE =
	/\b(?:rce|cmdi|command\s+injection|os\s+command|remote\s+code\s+execution|code\s+execution|ssti|deserializ(?:ation|e))\b|命令注入|远程代码执行|模板注入|反序列化/i;
const XSS_RE = /\b(?:xss|cross[\s_-]?site\s+scripting)\b|跨站脚本/i;
const EXPOSURE_RE =
	/\b(?:exposure|information\s+disclosure|info\s+disclosure|sensitive\s+file|misconfig(?:uration)?|actuator|\.git\/head|\.env|swagger|openapi|debug\s+endpoint|directory\s+listing|cors\s+misconfig)\b|信息泄露|配置泄露|敏感文件|端点暴露|配置暴露|未授权暴露/i;
const GENERIC_AUTHZ_RE = /越权读取|越权/i;

/**
 * 将发现事实归类为标准规则元数据（ruleId / CWE / SARIF level / category）。
 */
export function inferFindingRuleMeta(fact: Pick<Fact, "kind" | "title" | "detail">): FindingRuleMeta {
	if (fact.kind === "flag") {
		return { ruleId: "NUWA-FLAG", level: "note", category: "flag" };
	}

	const text = `${fact.title ?? ""}\n${fact.detail ?? ""}`;

	if (BOLA_IDOR_RE.test(text)) {
		return {
			ruleId: "NUWA-BOLA",
			cwe: "CWE-639",
			level: "error",
			category: "broken-object-level-authorization",
		};
	}
	if (BFLA_AUTH_RE.test(text)) {
		return {
			ruleId: "NUWA-AUTH",
			cwe: "CWE-287",
			level: "error",
			category: "authentication-authorization-bypass",
		};
	}
	if (SQLI_RE.test(text)) {
		return {
			ruleId: "NUWA-SQLI",
			cwe: "CWE-89",
			level: "error",
			category: "sql-injection",
		};
	}
	if (SSRF_RE.test(text)) {
		return {
			ruleId: "NUWA-SSRF",
			cwe: "CWE-918",
			level: "error",
			category: "ssrf",
		};
	}
	if (LFI_RE.test(text)) {
		return {
			ruleId: "NUWA-LFI",
			cwe: "CWE-22",
			level: "error",
			category: "path-traversal",
		};
	}
	if (RCE_CMDI_RE.test(text)) {
		return {
			ruleId: "NUWA-RCE",
			cwe: "CWE-78",
			level: "error",
			category: "command-execution",
		};
	}
	if (XSS_RE.test(text)) {
		return {
			ruleId: "NUWA-XSS",
			cwe: "CWE-79",
			level: "warning",
			category: "cross-site-scripting",
		};
	}
	if (EXPOSURE_RE.test(text)) {
		return {
			ruleId: "NUWA-EXPOSURE",
			cwe: "CWE-200",
			level: "warning",
			category: "information-exposure",
		};
	}
	if (GENERIC_AUTHZ_RE.test(text)) {
		return {
			ruleId: "NUWA-BOLA",
			cwe: "CWE-639",
			level: "error",
			category: "broken-object-level-authorization",
		};
	}
	return {
		ruleId: "NUWA-VULN",
		level: "warning",
		category: "security-finding",
	};
}

function maybeRedact(text: string | undefined, root?: string): string {
	const raw = String(text ?? "");
	if (!raw || !root || !root.trim()) return raw;
	return redactVaultSecrets(raw, root);
}

function redactDeep<T>(value: T, root?: string): T {
	if (!root || !root.trim()) return value;
	if (typeof value === "string") {
		return redactVaultSecrets(value, root) as unknown as T;
	}
	if (Array.isArray(value)) {
		return value.map((item) => redactDeep(item, root)) as unknown as T;
	}
	if (value && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			if (v === undefined) continue;
			out[k] = redactDeep(v, root);
		}
		return out as T;
	}
	return value;
}

function sha256Hex(content: string | Buffer): string {
	return createHash("sha256").update(content).digest("hex");
}

function ensureSecureDir(dirPath: string): void {
	mkdirSync(dirPath, { recursive: true, mode: 0o700 });
	try {
		chmodSync(dirPath, 0o700);
	} catch {
		/* 非 POSIX 文件系统忽略权限变更异常 */
	}
}

function writeSecureFile(filePath: string, content: string): void {
	atomicWrite(filePath, content);
	try {
		chmodSync(filePath, 0o600);
	} catch {
		/* 非 POSIX 文件系统忽略权限变更异常 */
	}
}

function extractFactArtifactUri(fact: Fact, st: NuwaState): string {
	const sources = [fact.command ?? "", fact.detail ?? "", fact.title ?? ""];
	for (const src of sources) {
		const urlMatch = /https?:\/\/[^\s'"<>`]+/i.exec(src);
		if (urlMatch?.[0]) {
			return urlMatch[0].replace(/[),.;]+$/, "");
		}
	}
	const base = (st.project?.url || st.project?.target || "").replace(/\/+$/, "");
	for (const src of sources) {
		const pathMatch = /(?:^|[\s'"`(])(\/[a-zA-Z0-9._~/%-]{2,})(?=$|[\s'"`),;?#])/.exec(src);
		if (pathMatch?.[1] && base && /^https?:\/\//i.test(base)) {
			return `${base}${pathMatch[1]}`;
		}
		if (pathMatch?.[1] && !base) {
			return pathMatch[1];
		}
	}
	return st.project?.url || st.project?.target || "target://unknown";
}

function sortAssets(assets?: Record<string, AssetNode>): AssetNode[] {
	if (!assets || typeof assets !== "object") return [];
	return Object.values(assets)
		.filter((a): a is AssetNode => Boolean(a && typeof a === "object" && a.id))
		.sort((a, b) => a.id.localeCompare(b.id));
}

function sortHypotheses(hypotheses?: Record<string, HypothesisNode>): HypothesisNode[] {
	if (!hypotheses || typeof hypotheses !== "object") return [];
	return Object.values(hypotheses)
		.filter((h): h is HypothesisNode => Boolean(h && typeof h === "object" && h.id))
		.sort((a, b) => a.id.localeCompare(b.id));
}

function computeCumulativeStats(st: NuwaState): {
	generation: number;
	totalTurns: number;
	totalTokens: number;
	totalCostUsd?: number;
} {
	const rt = st.runtime;
	const generation = Number.isFinite(rt?.generation) && (rt.generation as number) > 0 ? (rt.generation as number) : 1;
	const curTurns = Number.isFinite(rt?.turns) ? rt.turns : 0;
	const totalTurns = Math.max(Number.isFinite(rt?.totalTurns) ? (rt.totalTurns as number) : 0, curTurns);
	const baseTokens = Number.isFinite(rt?.totalTokens) ? (rt.totalTokens as number) : 0;
	const curTokens = Number.isFinite(rt?.tokens) ? rt.tokens : 0;
	const totalTokens = baseTokens + curTokens;
	const totalCostUsd =
		typeof rt?.totalCostUsd === "number" && Number.isFinite(rt.totalCostUsd) && rt.totalCostUsd > 0
			? rt.totalCostUsd
			: undefined;
	return { generation, totalTurns, totalTokens, totalCostUsd };
}

/**
 * 渲染完整分层 Markdown 评估报告：
 * - 严格区分已确认漏洞（confirmed）、待复验候选（candidate）与已驳回误报（rejected）；
 * - 展示多资产与跳板拓扑、假设图推理状态及跨世代运行统计；
 * - 传入 `root` 时对整份报告执行 Vault 凭据全量脱敏。
 */
export function renderStratifiedMarkdownReport(
	st: NuwaState,
	root?: string,
	opts?: { title?: string },
): string {
	const p = st.project;
	const facts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const intents = Object.values(st.intents ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const flags = facts.filter((f) => f.kind === "flag");
	const vulnPart = partitionFactsByVerifyStage(facts, "vuln");
	const confirmedVulns = vulnPart.confirmed;
	const candidateVulns = vulnPart.candidate;
	const rejectedVulns = vulnPart.rejected;
	const queue = intents.filter((i) => i.status === "open" || i.status === "claimed");
	const blockedIntents = intents.filter((i) => i.status === "blocked");
	const assets = sortAssets(st.assets);
	const hypotheses = sortHypotheses(st.hypotheses);

	const chain = intents
		.filter((i) => i.status === "done" && i.to)
		.map(
			(i) =>
				`| ${i.id} | ${i.phase} | ${cell(i.title, 80)} | ${i.to} | ${st.facts[i.to as string]?.kind ?? "?"} | ${cell(st.facts[i.to as string]?.command, 90)} |`,
		);

	const noteParts: string[] = [];
	if (candidateVulns.length > 0) noteParts.push(`另有待复验候选 ${candidateVulns.length} 条`);
	if (rejectedVulns.length > 0) noteParts.push(`已驳回误报 ${rejectedVulns.length} 条`);
	const noteSuffix = noteParts.length > 0 ? `（${noteParts.join("；")}）` : "";

	let conclusionLine: string;
	if (flags.length > 0) {
		const vulnAddon = confirmedVulns.length > 0 ? `；确认漏洞 ${confirmedVulns.length} 条` : "";
		conclusionLine = `取得 flag ${flags.length} 个：${flags.map((f) => f.detail.replace(/^值:\s*/, "")).join(" / ")}${vulnAddon}${noteSuffix}`;
	} else if (confirmedVulns.length > 0) {
		conclusionLine = `未取得 flag；确认漏洞 ${confirmedVulns.length} 条${noteSuffix}，最高危害见下表。`;
	} else if (candidateVulns.length > 0) {
		const rejAddon = rejectedVulns.length > 0 ? `；已驳回误报 ${rejectedVulns.length} 条` : "";
		conclusionLine = `未取得可验收证据（当前仅有待复验候选漏洞 ${candidateVulns.length} 条，尚未通过双盲复验确认${rejAddon}）。`;
	} else if (rejectedVulns.length > 0) {
		conclusionLine = `未取得可验收证据（已驳回误报 ${rejectedVulns.length} 条）。`;
	} else {
		conclusionLine = `未取得可验收证据。`;
	}

	const stats = computeCumulativeStats(st);
	const metaLines: string[] = [
		`- 目标: ${p.url}`,
		`- 模式: ${p.mode} · 状态: ${p.status} · 阶段: ${p.phase}`,
		`- 开始: ${p.createdAt} · 完成: ${p.completedAt ?? "-"}`,
		`- 目标描述: ${p.goal}`,
	];
	if (
		stats.generation > 1 ||
		stats.totalTurns > 0 ||
		stats.totalTokens > 0 ||
		stats.totalCostUsd !== undefined
	) {
		const statParts = [
			`gen=${stats.generation}`,
			`turns=${stats.totalTurns}`,
			`tokens=${stats.totalTokens}`,
		];
		if (stats.totalCostUsd !== undefined) {
			statParts.push(`cost=$${stats.totalCostUsd.toFixed(4)}`);
		}
		metaLines.push(`- 累计运行: ${statParts.join(" · ")}`);
	}

	const extraSections: string[] = [];

	if (candidateVulns.length > 0) {
		extraSections.push(
			``,
			`## 待复验候选漏洞（Candidate）`,
			`| fact | 标题 | 证据 | 命令 |`,
			`|---|---|---|---|`,
			...candidateVulns.map(
				(f) => `| ${f.id} | ${cell(f.title, 80)} | ${cell(f.output, 120)} | ${cell(f.command, 100)} |`,
			),
		);
	}

	if (rejectedVulns.length > 0) {
		extraSections.push(
			``,
			`## 已驳回误报（Rejected）`,
			`| fact | 标题 | 驳回说明 |`,
			`|---|---|---|`,
			...rejectedVulns.map(
				(f) => `| ${f.id} | ${cell(f.title, 80)} | ${cell(f.verifyNote ?? f.detail, 140)} |`,
			),
		);
	}

	if (assets.length > 0) {
		extraSections.push(
			``,
			`## 多资产与跳板拓扑`,
			`| id | 类型 | 目标 | 跳板路径 | 标签 | 来源事实 |`,
			`|---|---|---|---|---|---|`,
			...assets.map((a) => {
				const via = a.reachableVia?.length ? a.reachableVia.join(" -> ") : "-";
				const tags = a.tags?.length ? a.tags.join(", ") : "-";
				return `| ${a.id} | ${a.kind} | ${cell(a.target, 100)} | ${cell(via, 80)} | ${cell(tags, 60)} | ${a.sourceFactId ?? "-"} |`;
			}),
		);
	}

	if (hypotheses.length > 0) {
		extraSections.push(
			``,
			`## 假设图推理状态`,
			`| id | 状态 | 标题 | 收益/成本 | 依赖事实 | 证伪验证 | 备注 |`,
			`|---|---|---|---|---|---|---|`,
			...hypotheses.map((h) => {
				const deps = h.requiredFacts?.length ? h.requiredFacts.join(",") : "-";
				return `| ${h.id} | ${h.status} | ${cell(h.title, 80)} | ${h.expectedGain}/${h.estimatedCost} | ${cell(deps, 60)} | ${cell(h.falsificationTest, 100)} | ${cell(h.note, 100)} |`;
			}),
		);
	}

	const serviceFacts = facts.filter((f) =>
		["target", "asset", "service", "endpoint", "cred", "loot"].includes(f.kind),
	);

	const md = [
		`# ${opts?.title ?? "渗透报告"} — ${p.host}:${p.port}`,
		``,
		...metaLines,
		``,
		`## 结论`,
		conclusionLine,
		``,
		`## 攻击链`,
		`| intent | 阶段 | 动作 | fact | 类型 | 命令 |`,
		`|---|---|---|---|---|---|`,
		...(chain.length ? chain : ["| - | - | 无已完成节点 | - | - | - |"]),
		``,
		`## Flag 台账`,
		flags.length
			? [
					`| fact | 值 | 命令 | 时间 |`,
					`|---|---|---|---|`,
					...flags.map(
						(f) =>
							`| ${f.id} | ${cell(f.detail.replace(/^值:\s*/, ""), 80)} | ${cell(f.command, 100)} | ${f.createdAt} |`,
					),
				].join("\n")
			: "无",
		``,
		`## 漏洞`,
		confirmedVulns.length
			? [
					`| fact | 规则 | 标题 | 证据 | 命令 |`,
					`|---|---|---|---|---|`,
					...confirmedVulns.map((f) => {
						const meta = inferFindingRuleMeta(f);
						const ruleLabel = meta.cwe ? `${meta.ruleId} (${meta.cwe})` : meta.ruleId;
						return `| ${f.id} | ${ruleLabel} | ${cell(f.title, 80)} | ${cell(f.output, 120)} | ${cell(f.command, 100)} |`;
					}),
				].join("\n")
			: "无",
		...extraSections,
		``,
		`## 资产与服务`,
		serviceFacts.length
			? [
					`| fact | 类型 | 标题 | 详情 |`,
					`|---|---|---|---|`,
					...serviceFacts.map((f) => `| ${f.id} | ${f.kind} | ${cell(f.title, 80)} | ${cell(f.detail, 160)} |`),
				].join("\n")
			: "无",
		``,
		`## 未完成面`,
		queue.length ? queue.map((i) => `- ${i.id} [${i.phase}] ${i.title} (${i.status})`).join("\n") : "无",
		``,
		`## 阻塞项`,
		blockedIntents.length
			? blockedIntents.map((i) => `- ${i.id} ${i.title}: ${i.note ?? ""}`).join("\n")
			: "无",
		``,
	].join("\n");

	return maybeRedact(md, root);
}

/**
 * 构建符合 SARIF 2.1.0 规范的扫描结果对象。
 * 严格仅导出经确认的漏洞（`partitionFactsByVerifyStage(st.facts, "vuln").confirmed`），
 * 绝不导出 `candidate` 或 `rejected` 事实，并在提供 `root` 时对全部字段执行 Vault 脱敏。
 */
export function buildSarifReport(st: NuwaState, root?: string): Record<string, unknown> {
	const confirmed = partitionFactsByVerifyStage(st.facts ?? {}, "vuln").confirmed.sort((a, b) =>
		a.id.localeCompare(b.id),
	);

	const rulesById = new Map<string, Record<string, unknown>>();
	const results: Array<Record<string, unknown>> = [];

	for (const fact of confirmed) {
		const meta = inferFindingRuleMeta(fact);
		if (!rulesById.has(meta.ruleId)) {
			const tags = meta.cwe ? ["security", meta.cwe, meta.category] : ["security", meta.category];
			rulesById.set(meta.ruleId, {
				id: meta.ruleId,
				name: meta.ruleId,
				shortDescription: {
					text: RULE_DESCRIPTIONS[meta.ruleId] ?? `Security finding (${meta.category})`,
				},
				defaultConfiguration: {
					level: meta.level,
				},
				properties: {
					category: meta.category,
					...(meta.cwe ? { cwe: meta.cwe } : {}),
					tags,
				},
			});
		}

		const redactedTitle = maybeRedact(fact.title, root);
		const redactedDetail = maybeRedact(fact.detail, root);
		const redactedCommand = fact.command ? maybeRedact(fact.command, root) : undefined;
		const redactedOutput = fact.output ? maybeRedact(fact.output, root) : undefined;
		const redactedVerifyNote = fact.verifyNote ? maybeRedact(fact.verifyNote, root) : undefined;
		const redactedUri = maybeRedact(extractFactArtifactUri(fact, st), root);

		const msgParts = [redactedTitle, redactedDetail].filter((s) => s.trim().length > 0);
		if (redactedVerifyNote) {
			msgParts.push(`Verification: ${redactedVerifyNote}`);
		}
		const messageText = msgParts.join(" — ") || `Confirmed finding ${fact.id}`;

		const fingerprint = sha256Hex(`${st.project?.id ?? ""}|${meta.ruleId}|${fact.id}|${redactedTitle}`).slice(0, 32);

		results.push({
			ruleId: meta.ruleId,
			level: meta.level,
			message: {
				text: messageText,
			},
			locations: [
				{
					physicalLocation: {
						artifactLocation: {
							uri: redactedUri,
						},
					},
				},
			],
			partialFingerprints: {
				"nuwa/factId": fact.id,
				"nuwa/fingerprint": fingerprint,
			},
			properties: {
				factId: fact.id,
				kind: fact.kind,
				category: meta.category,
				...(meta.cwe ? { cwe: meta.cwe } : {}),
				verifyStage: fact.verifyStage ?? "confirmed",
				verified: fact.verified ?? true,
				...(fact.verifiedAt ? { verifiedAt: fact.verifiedAt } : {}),
				...(fact.verifiedBy ? { verifiedBy: fact.verifiedBy } : {}),
				...(redactedVerifyNote ? { verifyNote: redactedVerifyNote } : {}),
				...(redactedCommand ? { command: redactedCommand } : {}),
				...(redactedOutput ? { output: redactedOutput } : {}),
				...(fact.assetId ? { assetId: fact.assetId } : {}),
				createdAt: fact.createdAt,
			},
		});
	}

	const sarif: Record<string, unknown> = {
		$schema: "https://json.schemastore.org/sarif-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "pi-nuwa",
						version: st.version || "5.0.0",
						informationUri: "https://github.com/86cloudyun-afk/pi-nuwa",
						rules: [...rulesById.values()],
					},
				},
				invocations: [
					{
						executionSuccessful: st.project?.status !== "stopped" || !st.project?.stopReason,
						...(st.project?.createdAt ? { startTimeUtc: st.project.createdAt } : {}),
						...(st.project?.completedAt ? { endTimeUtc: st.project.completedAt } : {}),
						properties: {
							projectId: st.project?.id ?? "",
							mode: st.project?.mode ?? "pentest",
							status: st.project?.status ?? "active",
							phase: st.project?.phase ?? "report",
							target: maybeRedact(st.project?.url || st.project?.target || "", root),
						},
					},
				],
				results,
			},
		],
	};

	return redactDeep(sarif, root);
}

function serializeFinding(fact: Fact): Record<string, unknown> {
	const meta = inferFindingRuleMeta(fact);
	return {
		id: fact.id,
		kind: fact.kind,
		ruleId: meta.ruleId,
		...(meta.cwe ? { cwe: meta.cwe } : {}),
		level: meta.level,
		category: meta.category,
		title: fact.title,
		detail: fact.detail,
		...(fact.command !== undefined ? { command: fact.command } : {}),
		...(fact.output !== undefined ? { output: fact.output } : {}),
		...(fact.intent !== undefined ? { intent: fact.intent } : {}),
		...(fact.assetId !== undefined ? { assetId: fact.assetId } : {}),
		verified: fact.verified ?? fact.verifyStage !== "rejected",
		verifyStage: fact.verifyStage ?? "confirmed",
		...(fact.verifyNote !== undefined ? { verifyNote: fact.verifyNote } : {}),
		...(fact.verifiedAt !== undefined ? { verifiedAt: fact.verifiedAt } : {}),
		...(fact.verifiedBy !== undefined ? { verifiedBy: fact.verifiedBy } : {}),
		createdAt: fact.createdAt,
	};
}

/**
 * 构建结构化机器可读 JSON 报告，并在提供 `root` 时执行全量 Vault 凭据脱敏。
 */
export function buildJsonReport(st: NuwaState, root?: string): Record<string, unknown> {
	const facts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const intents = Object.values(st.intents ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	const flags = facts.filter((f) => f.kind === "flag");
	const vulnPart = partitionFactsByVerifyStage(facts, "vuln");
	const assets = sortAssets(st.assets);
	const hypotheses = sortHypotheses(st.hypotheses);

	const doneIntents = intents.filter((i) => i.status === "done");
	const blockedIntents = intents.filter((i) => i.status === "blocked");
	const openIntents = intents.filter((i) => i.status === "open" || i.status === "claimed");

	const attackChain = doneIntents
		.filter((i) => Boolean(i.to))
		.map((i) => {
			const fact = st.facts[i.to as string];
			return {
				intentId: i.id,
				phase: i.phase,
				key: i.key,
				title: i.title,
				factId: i.to,
				factKind: fact?.kind ?? "unknown",
				factTitle: fact?.title ?? "",
				...(fact?.command ? { command: fact.command } : {}),
				...(i.doneAt ? { doneAt: i.doneAt } : {}),
			};
		});

	const blocked = blockedIntents.map((i) => ({
		intentId: i.id,
		phase: i.phase,
		key: i.key,
		title: i.title,
		note: i.note ?? "",
		attempts: i.attempts,
		...(i.doneAt ? { doneAt: i.doneAt } : {}),
	}));

	const stats = computeCumulativeStats(st);

	const report: Record<string, unknown> = {
		schema: 1,
		version: st.version,
		generatedAt: new Date().toISOString(),
		project: {
			id: st.project.id,
			target: st.project.target,
			url: st.project.url,
			host: st.project.host,
			port: st.project.port,
			scheme: st.project.scheme,
			goal: st.project.goal,
			mode: st.project.mode,
			status: st.project.status,
			phase: st.project.phase,
			episode: st.project.episode ?? 1,
			createdAt: st.project.createdAt,
			updatedAt: st.project.updatedAt,
			...(st.project.completedAt ? { completedAt: st.project.completedAt } : {}),
			...(st.project.stopReason ? { stopReason: st.project.stopReason } : {}),
		},
		runtime: {
			generation: stats.generation,
			turns: st.runtime?.turns ?? 0,
			totalTurns: stats.totalTurns,
			tokens: st.runtime?.tokens ?? 0,
			totalTokens: stats.totalTokens,
			...(stats.totalCostUsd !== undefined ? { totalCostUsd: stats.totalCostUsd } : {}),
			toolCalls: st.runtime?.toolCalls ?? 0,
			stall: st.runtime?.stall ?? 0,
			expansions: st.runtime?.expansions ?? 0,
		},
		summary: {
			flags: flags.length,
			confirmedVulns: vulnPart.confirmed.length,
			candidateVulns: vulnPart.candidate.length,
			rejectedVulns: vulnPart.rejected.length,
			assets: assets.length,
			hypotheses: hypotheses.length,
			doneIntents: doneIntents.length,
			blockedIntents: blockedIntents.length,
			openIntents: openIntents.length,
		},
		findings: {
			flags: flags.map(serializeFinding),
			confirmed: vulnPart.confirmed.map(serializeFinding),
			candidate: vulnPart.candidate.map(serializeFinding),
			rejected: vulnPart.rejected.map(serializeFinding),
		},
		assets,
		hypotheses,
		attackChain,
		blocked,
	};

	return redactDeep(report, root);
}

/**
 * 在 `<root>/.nuwa/poc-bundle/` 落盘审计就绪、全量脱敏的验证取证包（0o700 目录 / 0o600 文件）：
 * - `README.md`：摘要与合规复核指引；
 * - `report.sarif.json`：仅包含已确认漏洞的 SARIF 2.1.0 报告；
 * - `evidence-<factId>.json`：逐条已确认漏洞的脱敏审计验证记录（不含任何武器化利用脚本）；
 * - `manifest.json`：项目元数据、已确认数量及包内全部文件的 SHA-256 摘要。
 */
export function writePocBundle(root: string, st: NuwaState): PocBundleResult {
	const normRoot = resolve(root);
	const nuwaDir = join(normRoot, ".nuwa");
	const dir = join(nuwaDir, "poc-bundle");
	ensureSecureDir(nuwaDir);
	ensureSecureDir(dir);

	const confirmed = partitionFactsByVerifyStage(st.facts ?? {}, "vuln").confirmed.sort((a, b) =>
		a.id.localeCompare(b.id),
	);

	const manifestEntries: Array<{ name: string; sha256: string; bytes: number }> = [];
	const writtenFiles: string[] = [];

	const recordWrite = (name: string, content: string): string => {
		const safeContent = redactVaultSecrets(content, normRoot);
		const fullPath = join(dir, name);
		writeSecureFile(fullPath, safeContent);
		const bytes = Buffer.byteLength(safeContent, "utf8");
		manifestEntries.push({
			name,
			sha256: sha256Hex(safeContent),
			bytes,
		});
		writtenFiles.push(fullPath);
		return fullPath;
	};

	// 1. report.sarif.json
	const sarifObj = buildSarifReport(st, normRoot);
	const sarifPath = recordWrite("report.sarif.json", `${JSON.stringify(sarifObj, null, 2)}\n`);

	// 2. evidence-<factId>.json（仅包含已确认漏洞的脱敏审计取证记录）
	const evidenceNames: string[] = [];
	for (const fact of confirmed) {
		const meta = inferFindingRuleMeta(fact);
		const safeFactId = fact.id.replace(/[^a-zA-Z0-9._-]/g, "_");
		const fileName = `evidence-${safeFactId}.json`;
		const record = redactDeep(
			{
				id: fact.id,
				ruleId: meta.ruleId,
				...(meta.cwe ? { cwe: meta.cwe } : {}),
				level: meta.level,
				category: meta.category,
				title: fact.title,
				detail: fact.detail,
				command: fact.command ?? "",
				output: fact.output ?? "",
				verifyStage: fact.verifyStage ?? "confirmed",
				verifyNote: fact.verifyNote ?? "",
				...(fact.verifiedAt ? { verifiedAt: fact.verifiedAt } : {}),
				...(fact.verifiedBy ? { verifiedBy: fact.verifiedBy } : {}),
				createdAt: fact.createdAt,
			},
			normRoot,
		);
		recordWrite(fileName, `${JSON.stringify(record, null, 2)}\n`);
		evidenceNames.push(fileName);
	}

	// 3. README.md
	const generatedAt = new Date().toISOString();
	const readmeLines = [
		`# 审计取证包 (Evidence Bundle) — ${st.project.host}:${st.project.port}`,
		``,
		`- 项目 ID: ${st.project.id}`,
		`- 目标: ${st.project.url || st.project.target}`,
		`- 模式: ${st.project.mode} · 状态: ${st.project.status} · 阶段: ${st.project.phase}`,
		`- 生成时间: ${generatedAt}`,
		`- 已确认漏洞数: ${confirmed.length}`,
		``,
		`## 文件清单`,
		`- \`manifest.json\`: 项目元数据与本取证包全部文件的 SHA-256 完整性校验清单`,
		`- \`report.sarif.json\`: SARIF 2.1.0 静态/动态合规导入报告（仅含 confirmed 漏洞）`,
		...(evidenceNames.length > 0
			? evidenceNames.map((n) => `- \`${n}\`: 脱敏审计验证记录`)
			: [`- (当前无已确认漏洞证据记录)`]),
		``,
		`## 复核指引`,
		`1. 使用 \`sha256sum\` 对照 \`manifest.json\` 核验取证文件完整性。`,
		`2. 将 \`report.sarif.json\` 导入代码托管或安全治理平台跟踪修复闭环。`,
		`3. 本取证包仅包含经脱敏处理的只读审计验证记录，不包含任何明文凭据或自动化攻击脚本；复现核验须严格限定在书面授权范围内执行。`,
		``,
	];
	recordWrite("README.md", readmeLines.join("\n"));

	// 4. manifest.json（按文件名排序保证确定性，最后落盘）
	manifestEntries.sort((a, b) => a.name.localeCompare(b.name));
	const manifestObj = redactDeep(
		{
			schema: 1,
			version: st.version,
			generatedAt,
			project: {
				id: st.project.id,
				target: st.project.url || st.project.target,
				host: st.project.host,
				port: st.project.port,
				mode: st.project.mode,
				status: st.project.status,
				phase: st.project.phase,
			},
			confirmedCount: confirmed.length,
			files: manifestEntries,
		},
		normRoot,
	);
	const manifestContent = redactVaultSecrets(`${JSON.stringify(manifestObj, null, 2)}\n`, normRoot);
	const manifestPath = join(dir, "manifest.json");
	writeSecureFile(manifestPath, manifestContent);
	writtenFiles.push(manifestPath);

	return {
		dir,
		manifestPath,
		sarifPath,
		files: writtenFiles.sort(),
		confirmedCount: confirmed.length,
	};
}
