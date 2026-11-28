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
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AssetNode, Fact, HypothesisNode, NuwaState } from "./types";
import { partitionFactsByVerifyStage } from "./verifier-gate";
import { writeStandalonePovScript } from "./rgs-analyzer";
import { computeBodyHash, extractHitEvidenceMetrics, readFactEvidenceLog } from "./evidence";
import { loadSessionVault, redactVaultSecrets, type SessionVault } from "./session-vault";
import { redactTextForStorage, redactUnknownForStorage } from "./sqlite-schema";
import { NuwaSqliteStore, resolveStorageBackend, sqliteDbPath } from "./sqlite-store";
import { atomicWrite, cell, journalPath, loadState } from "./storage";

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

const EMPTY_REPORT_VAULT: SessionVault = { schema: 1, updatedAt: "", roles: {} };

function resolveReportVault(root?: string): SessionVault {
	if (!root || !root.trim()) return EMPTY_REPORT_VAULT;
	try {
		return loadSessionVault(root);
	} catch {
		return EMPTY_REPORT_VAULT;
	}
}

function maybeRedact(text: string | undefined, root?: string): string {
	const raw = String(text ?? "");
	if (!raw) return raw;
	const vault = resolveReportVault(root);
	return redactTextForStorage(raw, vault) ?? raw;
}

function redactDeep<T>(value: T, root?: string): T {
	const vault = resolveReportVault(root);
	return redactUnknownForStorage(value, vault);
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

	const effectiveStatus = st.runtime?.status === "sealed_negative" ? "sealed_negative" : p.status;
	const sealMeta = st.runtime?.sealMeta ?? p.sealMeta;

	let conclusionLine: string;
	if (flags.length > 0) {
		const vulnAddon = confirmedVulns.length > 0 ? `；确认漏洞 ${confirmedVulns.length} 条` : "";
		conclusionLine = `取得 flag ${flags.length} 个：${flags.map((f) => f.detail.replace(/^值:\s*/, "")).join(" / ")}${vulnAddon}${noteSuffix}`;
	} else if (confirmedVulns.length > 0) {
		conclusionLine = `未取得 flag；确认漏洞 ${confirmedVulns.length} 条${noteSuffix}，最高危害见下表。`;
	} else if (candidateVulns.length > 0) {
		const rejAddon = rejectedVulns.length > 0 ? `；已驳回误报 ${rejectedVulns.length} 条` : "";
		conclusionLine = `未取得可验收证据（当前仅有待复验候选漏洞 ${candidateVulns.length} 条，尚未通过双盲复验确认${rejAddon}）。`;
	} else if (effectiveStatus === "sealed_negative" && sealMeta) {
		conclusionLine = `负向封盘（sealed_negative）：${sealMeta.reason}${noteSuffix ? ` ${noteSuffix}` : ""}`;
	} else if (rejectedVulns.length > 0) {
		conclusionLine = `未取得可验收证据（已驳回误报 ${rejectedVulns.length} 条）。`;
	} else {
		conclusionLine = `未取得可验收证据。`;
	}

	const stats = computeCumulativeStats(st);
	const metaLines: string[] = [
		`- 目标: ${p.url}`,
		`- 模式: ${p.mode} · 状态: ${effectiveStatus} · 阶段: ${p.phase}`,
		`- 开始: ${p.createdAt} · 完成: ${p.completedAt ?? sealMeta?.sealedAt ?? "-"}`,
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

	if (effectiveStatus === "sealed_negative" && sealMeta) {
		extraSections.push(
			``,
			`## 负向封盘说明（Sealed Negative）`,
			`- 封盘时间: ${sealMeta.sealedAt}`,
			`- 封盘依据: ${sealMeta.reason}`,
			`- 已排除攻击面 (${sealMeta.excludedSurface.length}): ${sealMeta.excludedSurface.slice(0, 50).join(", ") || "无"}`,
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
						executionSuccessful:
							(st.runtime?.status === "sealed_negative" || st.project?.status === "sealed_negative"
								? "sealed_negative"
								: st.runtime?.status === "completed" || st.project?.status === "completed"
									? "completed"
									: st.project?.status ?? "active") !== "stopped" || !st.project?.stopReason,
						...(st.project?.createdAt ? { startTimeUtc: st.project.createdAt } : {}),
						...(() => {
							const sealMeta = st.runtime?.sealMeta ?? st.project?.sealMeta;
							const endAt = st.project?.completedAt ?? sealMeta?.sealedAt;
							return endAt ? { endTimeUtc: endAt } : {};
						})(),
						properties: {
							projectId: st.project?.id ?? "",
							mode: st.project?.mode ?? "pentest",
							status:
								st.runtime?.status === "sealed_negative" || st.project?.status === "sealed_negative"
									? "sealed_negative"
									: st.runtime?.status === "completed" || st.project?.status === "completed"
										? "completed"
										: (st.project?.status ?? "active"),
							phase: st.project?.phase ?? "report",
							target: maybeRedact(st.project?.url || st.project?.target || "", root),
							...((st.runtime?.sealMeta ?? st.project?.sealMeta)
								? { sealMeta: st.runtime?.sealMeta ?? st.project?.sealMeta }
								: {}),
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
	const effectiveStatus = st.runtime?.status === "sealed_negative" ? "sealed_negative" : st.project.status;
	const sealMeta = st.runtime?.sealMeta ?? st.project.sealMeta;

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
			status: effectiveStatus,
			phase: st.project.phase,
			episode: st.project.episode ?? 1,
			createdAt: st.project.createdAt,
			updatedAt: st.project.updatedAt,
			...(st.project.completedAt || sealMeta?.sealedAt
				? { completedAt: st.project.completedAt ?? sealMeta?.sealedAt }
				: {}),
			...(st.project.stopReason ? { stopReason: st.project.stopReason } : {}),
			...(sealMeta ? { sealMeta } : {}),
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

	const bundleVault = resolveReportVault(normRoot);
	const recordWrite = (name: string, content: string): string => {
		const safeContent = redactTextForStorage(content, bundleVault) ?? redactVaultSecrets(content, normRoot);
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

	// 2. evidence-<factId>.json 与零明文独立复验脚本 pov-<factId>.ts（仅包含已确认漏洞的脱敏记录）
	const evidenceNames: string[] = [];
	const povScriptNames: string[] = [];
	const fallbackBaseUrl =
		st.project.scheme === "local"
			? "http://127.0.0.1:8080"
			: st.project.url || st.project.target || "http://127.0.0.1:8080";
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

		try {
			const povWritten = writeStandalonePovScript(dir, {
				fact,
				ruleMeta: meta,
				baseUrl: fallbackBaseUrl,
				vaultRootOrVault: normRoot,
				scope: st.project.scope,
			});
			try {
				chmodSync(povWritten.filePath, 0o600);
			} catch {
				/* ignore chmod error */
			}
			manifestEntries.push({
				name: povWritten.fileName,
				sha256: povWritten.sha256,
				bytes: povWritten.bytes,
			});
			writtenFiles.push(povWritten.filePath);
			povScriptNames.push(povWritten.fileName);
		} catch {
			/* 非 HTTP 事实跳过脚本生成 */
		}
	}

	// 3. README.md
	const generatedAt = new Date().toISOString();
	const effectiveStatus =
		st.runtime?.status === "sealed_negative" || st.project.status === "sealed_negative"
			? "sealed_negative"
			: st.runtime?.status === "completed" || st.project.status === "completed"
				? "completed"
				: st.project.status;
	const readmeLines = [
		`# 审计取证包 (Evidence Bundle) — ${st.project.host}:${st.project.port}`,
		``,
		`- 项目 ID: ${st.project.id}`,
		`- 目标: ${st.project.url || st.project.target}`,
		`- 模式: ${st.project.mode} · 状态: ${effectiveStatus} · 阶段: ${st.project.phase}`,
		`- 生成时间: ${generatedAt}`,
		`- 已确认漏洞数: ${confirmed.length}`,
		``,
		`## 文件清单`,
		`- \`manifest.json\`: 项目元数据与本取证包全部文件的 SHA-256 完整性校验清单`,
		`- \`report.sarif.json\`: SARIF 2.1.0 静态/动态合规导入报告（仅含 confirmed 漏洞）`,
		...(evidenceNames.length > 0
			? evidenceNames.map((n) => `- \`${n}\`: 脱敏审计验证记录`)
			: [`- (当前无已确认漏洞证据记录)`]),
		...povScriptNames.map((n) => `- \`${n}\`: 零明文独立可运行复核脚本（凭据经环境变量按需注入）`),
		``,
		`## 复核指引`,
		`1. 使用 \`sha256sum\` 对照 \`manifest.json\` 核验取证文件完整性。`,
		`2. 将 \`report.sarif.json\` 导入代码托管或安全治理平台跟踪修复闭环。`,
		`3. 本取证包仅包含经脱敏处理的只读审计验证记录与零明文复核脚本（\`pov-*.ts\`），不包含任何硬编码凭据；复现核验须严格限定在书面授权范围内执行。`,
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
				status: effectiveStatus,
				phase: st.project.phase,
			},
			confirmedCount: confirmed.length,
			files: manifestEntries,
		},
		normRoot,
	);
	const manifestContent =
		redactTextForStorage(`${JSON.stringify(manifestObj, null, 2)}\n`, bundleVault) ??
		redactVaultSecrets(`${JSON.stringify(manifestObj, null, 2)}\n`, normRoot);
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

// ============================================================================
// v5.1 Episode 时间线导出与结构化归档索引检索
// 覆盖 Issues: #42 (NW-22), #52 (NW-32)
// ============================================================================

type FactWithExtendedRefs = Fact & {
	evidenceRef?: string;
	agentResult?: Record<string, unknown>;
	episode?: number;
};

export interface TimelineEventItem {
	ts: string;
	source: "fact" | "intent" | "journal" | "exec_ledger";
	episode: number;
	phase?: string;
	id?: string;
	kind?: string;
	status?: string;
	title: string;
	command?: string;
	summary?: string;
	evidenceRef?: string;
	evidenceExists?: boolean;
	evidenceBytes?: number;
	evidenceExcerpt?: string;
	blocked?: boolean;
}

export interface EpisodeTimelineData {
	schema: 1;
	projectId: string;
	target: string;
	episodeFilter?: number;
	currentEpisode: number;
	generatedAt: string;
	counts: {
		total: number;
		facts: number;
		intents: number;
		journal: number;
		execLedger: number;
		withEvidenceRef: number;
	};
	events: TimelineEventItem[];
}

export interface ExportEpisodeTimelineOptions {
	episode?: number;
	format?: "markdown" | "json";
	state?: NuwaState;
	includeEvidenceExcerpt?: boolean;
}

interface RawJournalLine {
	ts?: string;
	type?: string;
	episode?: number;
	phase?: string;
	id?: string;
	factId?: string;
	intentId?: string;
	title?: string;
	note?: string;
	reason?: string;
	command?: string;
	evidenceRef?: string;
	blocked?: boolean;
	[key: string]: unknown;
}

interface RawLedgerLine {
	seq?: number;
	ts?: string;
	tool?: string;
	command?: string;
	agentName?: string;
	sha1?: string;
	bytes?: number;
	snippet?: string;
}

function readJsonlRecords<T>(filePath: string): T[] {
	if (!existsSync(filePath)) return [];
	try {
		const raw = readFileSync(filePath, "utf8");
		const out: T[] = [];
		for (const line of raw.split("\n")) {
			const trimmed = line.trim();
			if (!trimmed) continue;
			try {
				const parsed = JSON.parse(trimmed) as T;
				if (parsed && typeof parsed === "object") out.push(parsed);
			} catch {
				/* 跳过损坏行 */
			}
		}
		return out;
	} catch {
		return [];
	}
}

function resolveEpisodeAtTimestamp(
	ts: string,
	boundaries: Array<{ tsMs: number; episode: number }>,
	fallbackEpisode: number,
): number {
	const ms = Date.parse(ts);
	if (!Number.isFinite(ms) || boundaries.length === 0) return fallbackEpisode;
	let ep = boundaries[0]!.episode;
	for (const b of boundaries) {
		if (b.tsMs <= ms) ep = b.episode;
		else break;
	}
	return ep;
}

function inspectEvidenceFile(
	normRoot: string,
	factId: string,
	explicitRef?: string,
	includeExcerpt = true,
): { evidenceRef?: string; evidenceExists?: boolean; evidenceBytes?: number; evidenceExcerpt?: string } {
	const safeId = factId.replace(/[^a-zA-Z0-9._-]/g, "_");
	const defaultRef = `.nuwa/evidence/${safeId}.log`;
	const ref = explicitRef?.trim() || (existsSync(join(normRoot, defaultRef)) ? defaultRef : undefined);
	if (!ref) return {};
	const full = resolve(normRoot, ref);
	const evBase = resolve(join(normRoot, ".nuwa", "evidence"));
	if (!full.startsWith(`${evBase}/`) && full !== evBase) {
		return { evidenceRef: ref, evidenceExists: false };
	}
	if (!existsSync(full)) {
		return { evidenceRef: ref, evidenceExists: false };
	}
	let bytes: number | undefined;
	try {
		bytes = statSync(full).size;
	} catch {
		bytes = undefined;
	}
	let excerpt: string | undefined;
	if (includeExcerpt) {
		const content = readFactEvidenceLog(normRoot, ref);
		if (content) {
			const compact = content.replace(/\r/g, "").trim();
			excerpt = compact.length > 240 ? `${compact.slice(0, 240)}...` : compact;
		}
	}
	return {
		evidenceRef: ref,
		evidenceExists: true,
		...(bytes !== undefined ? { evidenceBytes: bytes } : {}),
		...(excerpt ? { evidenceExcerpt: excerpt } : {}),
	};
}

const SOURCE_ORDER: Record<TimelineEventItem["source"], number> = {
	journal: 0,
	exec_ledger: 1,
	intent: 2,
	fact: 3,
};

/**
 * #42 (NW-22) 构建账本与落盘证据关联的结构化 Episode 时间线数据。
 */
export function buildEpisodeTimelineData(
	root: string,
	opts?: ExportEpisodeTimelineOptions,
): EpisodeTimelineData {
	const normRoot = resolve(root || process.cwd());
	const st = opts?.state ?? loadState(normRoot);
	const includeExcerpt = opts?.includeEvidenceExcerpt !== false;
	const currentEpisode = st?.project?.episode && st.project.episode > 0 ? st.project.episode : 1;
	const episodeFilter =
		typeof opts?.episode === "number" && Number.isFinite(opts.episode) && opts.episode > 0
			? Math.floor(opts.episode)
			: undefined;

	let rawJournal = readJsonlRecords<RawJournalLine>(journalPath(normRoot));
	let rawLedger = readJsonlRecords<RawLedgerLine>(join(normRoot, ".nuwa", "exec-ledger.jsonl"));
	const backend = resolveStorageBackend(normRoot);
	const dbFile = sqliteDbPath(normRoot);
	if ((rawJournal.length === 0 || rawLedger.length === 0) && existsSync(dbFile) && (backend === "sqlite" || backend === "dual")) {
		let store: NuwaSqliteStore | null = null;
		try {
			store = new NuwaSqliteStore(normRoot, { readonly: true });
			if (rawJournal.length === 0) {
				rawJournal = store.readJournalTail(5000) as RawJournalLine[];
			}
			if (rawLedger.length === 0) {
				rawLedger = store.listExecLedger(2000) as unknown as RawLedgerLine[];
			}
		} catch {
			/* 只读探测 SQLite 异常时平滑退回 */
		} finally {
			store?.close();
		}
	}

	// 从 journal 提取 episode 跃迁边界
	const boundaries: Array<{ tsMs: number; episode: number }> = [];
	for (const rec of rawJournal) {
		if (typeof rec.episode === "number" && Number.isFinite(rec.episode) && rec.episode > 0 && rec.ts) {
			const ms = Date.parse(rec.ts);
			if (Number.isFinite(ms)) {
				boundaries.push({ tsMs: ms, episode: Math.floor(rec.episode) });
			}
		}
	}
	boundaries.sort((a, b) => a.tsMs - b.tsMs);

	const events: TimelineEventItem[] = [];

	// 1. Journal 事件（跳过体积庞大的 snapshot 记录）
	for (const rec of rawJournal) {
		if (rec.type === "snapshot") continue;
		const ts = typeof rec.ts === "string" && rec.ts ? rec.ts : new Date(0).toISOString();
		const ep =
			typeof rec.episode === "number" && Number.isFinite(rec.episode) && rec.episode > 0
				? Math.floor(rec.episode)
				: resolveEpisodeAtTimestamp(ts, boundaries, currentEpisode);
		const summaryParts = [rec.title, rec.note, rec.reason]
			.filter((x): x is string => typeof x === "string" && x.trim().length > 0)
			.map((x) => x.trim());
		events.push({
			ts,
			source: "journal",
			episode: ep,
			...(typeof rec.phase === "string" ? { phase: rec.phase } : {}),
			...(typeof rec.id === "string"
				? { id: rec.id }
				: typeof rec.factId === "string"
					? { id: rec.factId }
					: typeof rec.intentId === "string"
						? { id: rec.intentId }
						: {}),
			kind: typeof rec.type === "string" ? rec.type : "event",
			title: summaryParts[0] || `journal:${String(rec.type ?? "event")}`,
			...(typeof rec.command === "string" && rec.command ? { command: rec.command } : {}),
			...(summaryParts.length > 0 ? { summary: summaryParts.join(" | ") } : {}),
			...(typeof rec.evidenceRef === "string" && rec.evidenceRef ? { evidenceRef: rec.evidenceRef } : {}),
			...(rec.blocked === true ? { blocked: true } : {}),
		});
	}

	// 2. 执行账本（exec-ledger.jsonl）
	for (const rec of rawLedger) {
		const ts = typeof rec.ts === "string" && rec.ts ? rec.ts : new Date(0).toISOString();
		const ep = resolveEpisodeAtTimestamp(ts, boundaries, currentEpisode);
		events.push({
			ts,
			source: "exec_ledger",
			episode: ep,
			id: rec.seq !== undefined ? `exec#${rec.seq}` : undefined,
			kind: rec.tool || "exec",
			title: `[${rec.tool || "exec"}${rec.agentName ? `/${rec.agentName}` : ""}] ${cell(rec.command || rec.snippet, 96)}`,
			...(rec.command ? { command: rec.command } : {}),
			summary: `bytes=${rec.bytes ?? 0} sha1=${(rec.sha1 ?? "").slice(0, 12)} ${cell(rec.snippet, 120)}`.trim(),
		});
	}

	// 3. Intents（含 done / blocked / claimed 节点）
	if (st?.intents) {
		for (const intent of Object.values(st.intents)) {
			if (!intent) continue;
			const ts = intent.doneAt || intent.claimedAt || intent.createdAt || new Date(0).toISOString();
			const ep = resolveEpisodeAtTimestamp(ts, boundaries, currentEpisode);
			const linkedFact = intent.to ? (st.facts?.[intent.to] as FactWithExtendedRefs | undefined) : undefined;
			const evMeta = linkedFact
				? inspectEvidenceFile(normRoot, linkedFact.id, linkedFact.evidenceRef, includeExcerpt)
				: {};
			events.push({
				ts,
				source: "intent",
				episode: ep,
				phase: intent.phase,
				id: intent.id,
				kind: intent.key,
				status: intent.status,
				title: intent.title,
				...(linkedFact?.command ? { command: linkedFact.command } : {}),
				summary:
					intent.status === "blocked"
						? `blocked: ${intent.note || "无说明"}`
						: intent.to
							? `-> ${intent.to} (${linkedFact?.kind ?? "fact"})`
							: intent.note || intent.status,
				blocked: intent.status === "blocked",
				...evMeta,
			});
		}
	}

	// 4. Facts（自动关联 .nuwa/evidence/<factId>.log）
	if (st?.facts) {
		for (const rawFact of Object.values(st.facts)) {
			const fact = rawFact as FactWithExtendedRefs;
			if (!fact || !fact.id) continue;
			const ts = fact.verifiedAt || fact.createdAt || new Date(0).toISOString();
			const ep =
				typeof fact.episode === "number" && Number.isFinite(fact.episode) && fact.episode > 0
					? Math.floor(fact.episode)
					: resolveEpisodeAtTimestamp(ts, boundaries, currentEpisode);
			const evMeta = inspectEvidenceFile(normRoot, fact.id, fact.evidenceRef, includeExcerpt);
			events.push({
				ts,
				source: "fact",
				episode: ep,
				id: fact.id,
				kind: fact.kind,
				status: fact.verifyStage ?? (fact.kind === "blocked" ? "blocked" : "recorded"),
				title: fact.title,
				...(fact.command ? { command: fact.command } : {}),
				summary: fact.detail || fact.output || "",
				blocked: fact.kind === "blocked",
				...evMeta,
			});
		}
	}

	const filtered =
		episodeFilter !== undefined ? events.filter((e) => e.episode === episodeFilter) : events;

	filtered.sort((a, b) => {
		const ta = Date.parse(a.ts);
		const tb = Date.parse(b.ts);
		if (Number.isFinite(ta) && Number.isFinite(tb) && ta !== tb) return ta - tb;
		if (a.ts !== b.ts) return a.ts.localeCompare(b.ts);
		if (SOURCE_ORDER[a.source] !== SOURCE_ORDER[b.source]) {
			return SOURCE_ORDER[a.source] - SOURCE_ORDER[b.source];
		}
		return String(a.id ?? "").localeCompare(String(b.id ?? ""));
	});

	const data: EpisodeTimelineData = {
		schema: 1,
		projectId: st?.project?.id ?? "unknown",
		target: st?.project?.url || st?.project?.target || "",
		...(episodeFilter !== undefined ? { episodeFilter } : {}),
		currentEpisode,
		generatedAt: new Date().toISOString(),
		counts: {
			total: filtered.length,
			facts: filtered.filter((e) => e.source === "fact").length,
			intents: filtered.filter((e) => e.source === "intent").length,
			journal: filtered.filter((e) => e.source === "journal").length,
			execLedger: filtered.filter((e) => e.source === "exec_ledger").length,
			withEvidenceRef: filtered.filter((e) => Boolean(e.evidenceRef)).length,
		},
		events: filtered,
	};

	return redactDeep(data, normRoot);
}

/**
 * #42 (NW-22) 导出账本与落盘证据关联的 Episode 时间线（支持 `markdown` 与 `json` 两种格式）。
 */
export function exportEpisodeTimeline(root: string, opts?: ExportEpisodeTimelineOptions): string {
	const data = buildEpisodeTimelineData(root, opts);
	const format = opts?.format ?? "markdown";
	if (format === "json") {
		return `${JSON.stringify(data, null, 2)}\n`;
	}

	const heading =
		data.episodeFilter !== undefined
			? `# Episode E${data.episodeFilter} 账本与证据时间线`
			: `# 全量账本与证据时间线 (当前 E${data.currentEpisode})`;

	const lines: string[] = [
		heading,
		``,
		`- 项目 ID: ${data.projectId}`,
		`- 目标: ${data.target || "(未记录)"}`,
		`- 导出时间: ${data.generatedAt}`,
		`- 统计: total=${data.counts.total} · facts=${data.counts.facts} · intents=${data.counts.intents} · exec=${data.counts.execLedger} · journal=${data.counts.journal} · evidenceRef=${data.counts.withEvidenceRef}`,
		``,
		`| 时间 | E# | 来源 | ID | 类型/状态 | 标题与摘要 | 命令 | 证据指针 |`,
		`|---|---|---|---|---|---|---|---|`,
	];

	if (data.events.length === 0) {
		lines.push(`| - | - | - | - | - | (无匹配时间线记录) | - | - |`);
	} else {
		for (const ev of data.events) {
			const kindStatus = [ev.kind, ev.status].filter(Boolean).join("/");
			const titleSummary = ev.summary && ev.summary !== ev.title ? `${ev.title} — ${ev.summary}` : ev.title;
			const evCell = ev.evidenceRef
				? `${ev.evidenceRef}${ev.evidenceExists ? ` (${ev.evidenceBytes ?? 0}B)` : " (missing)"}`
				: "-";
			lines.push(
				`| ${ev.ts} | E${ev.episode} | ${ev.source} | ${ev.id ?? "-"} | ${cell(kindStatus, 40)} | ${cell(titleSummary, 140)} | ${cell(ev.command, 90) || "-"} | ${cell(evCell, 80)} |`,
			);
		}
	}

	const excerptItems = data.events.filter((e) => e.evidenceRef && e.evidenceExcerpt);
	if (excerptItems.length > 0) {
		lines.push(``, `## 关联落盘证据摘录`);
		for (const item of excerptItems) {
			lines.push(
				``,
				`### ${item.id ?? item.title} (\`${item.evidenceRef}\`)`,
				"```text",
				item.evidenceExcerpt!,
				"```",
			);
		}
	}

	lines.push(``);
	return maybeRedact(lines.join("\n"), root);
}

// ----------------------------------------------------------------------------
// #52 (NW-32) 结构化归档索引器 writeEpisodeArchiveIndex 与检索器 searchArchiveIndexes
// ----------------------------------------------------------------------------

export interface ArchiveFactRecord {
	id: string;
	kind: string;
	title: string;
	detail?: string;
	target?: string;
	command?: string;
	statusCode?: number;
	bytes?: number;
	bodySha256?: string;
	evidenceRef?: string;
	verifyStage?: string;
	blocked?: boolean;
	createdAt?: string;
}

export interface ArchiveCommandRecord {
	cmd: string;
	statusCode?: number;
	bytes?: number;
	bodySha256?: string;
	remoteIp?: string;
	cfRay?: string;
	server?: string;
	timeTotal?: number;
	factId?: string;
	ts?: string;
}

export interface EpisodeArchiveInput {
	episode: number;
	projectId?: string;
	target?: string;
	phase?: string;
	summary?: string;
	state?: NuwaState;
	facts?: ArchiveFactRecord[];
	commands?: ArchiveCommandRecord[];
	generatedAt?: string;
}

export interface EpisodeArchiveIndex {
	schema: 1;
	episode: number;
	projectId: string;
	target: string;
	phase: string;
	summary: string;
	generatedAt: string;
	facts: ArchiveFactRecord[];
	commands: ArchiveCommandRecord[];
	stats: {
		factCount: number;
		commandCount: number;
		statusCodes: number[];
		hashes: string[];
	};
}

export interface WriteEpisodeArchiveResult {
	episode: number;
	jsonPath: string;
	markdownPath: string;
	index: EpisodeArchiveIndex;
}

export interface ArchiveSearchQuery {
	text?: string;
	factId?: string;
	kind?: string;
	episode?: number;
	statusCode?: number;
	hash?: string;
	command?: string;
	limit?: number;
}

export interface ArchiveSearchHit {
	episode: number;
	source: "fact" | "command";
	archiveFile: string;
	factId?: string;
	kind?: string;
	title?: string;
	command?: string;
	statusCode?: number;
	bytes?: number;
	bodySha256?: string;
	evidenceRef?: string;
	snippet: string;
	score: number;
}

function extractArchiveFactFromState(fact: FactWithExtendedRefs, normRoot: string): ArchiveFactRecord {
	const combinedText = `${fact.output ?? ""}\n${fact.detail ?? ""}`;
	const metrics = extractHitEvidenceMetrics(combinedText);
	const shaMatch = /\b(?:body_sha256|sha256)\s*[:=]\s*([a-fA-F0-9]{64})\b/i.exec(combinedText);
	const bytesMatch = /\b(\d+)\s*B\b/.exec(combinedText);
	const statusCode = fact.meta?.status ?? metrics.http_code;
	const bytes =
		metrics.size_download ??
		(bytesMatch?.[1] ? Number(bytesMatch[1]) : undefined) ??
		(fact.output !== undefined ? Buffer.byteLength(fact.output, "utf8") : undefined);
	const bodySha256 =
		shaMatch?.[1]?.toLowerCase() ??
		(fact.output && fact.output.trim() ? computeBodyHash(fact.output.trim(), "sha256") : undefined);
	const defaultEvRef = `.nuwa/evidence/${fact.id.replace(/[^a-zA-Z0-9._-]/g, "_")}.log`;
	const evidenceRef = fact.evidenceRef || (existsSync(join(normRoot, defaultEvRef)) ? defaultEvRef : undefined);
	const urlMatch = /https?:\/\/[^\s"'<>`]+/i.exec(`${fact.command ?? ""} ${fact.detail ?? ""}`);

	return {
		id: fact.id,
		kind: fact.kind,
		title: fact.title,
		...(fact.detail ? { detail: fact.detail } : {}),
		...(urlMatch?.[0] ? { target: urlMatch[0] } : {}),
		...(fact.command ? { command: fact.command } : {}),
		...(statusCode !== undefined ? { statusCode } : {}),
		...(bytes !== undefined ? { bytes } : {}),
		...(bodySha256 ? { bodySha256 } : {}),
		...(evidenceRef ? { evidenceRef } : {}),
		...(fact.verifyStage ? { verifyStage: fact.verifyStage } : {}),
		...(fact.kind === "blocked" ? { blocked: true } : {}),
		createdAt: fact.createdAt,
	};
}

function renderEpisodeArchiveMarkdown(index: EpisodeArchiveIndex): string {
	const lines: string[] = [
		`# Episode E${index.episode} 结构化归档索引`,
		``,
		`- 项目 ID: ${index.projectId}`,
		`- 目标: ${index.target || "(未记录)"}`,
		`- 阶段: ${index.phase}`,
		`- 生成时间: ${index.generatedAt}`,
		`- 统计: facts=${index.stats.factCount} · commands=${index.stats.commandCount} · statusCodes=[${index.stats.statusCodes.join(", ")}]`,
	];

	if (index.summary) {
		lines.push(``, `## 摘要`, index.summary);
	}

	lines.push(
		``,
		`## 事实索引表`,
		`| factId | kind | 标题 | 状态码 | 字节数 | 响应哈希 (SHA-256) | 证据指针 | 命令 |`,
		`|---|---|---|---|---|---|---|---|`,
	);
	if (index.facts.length === 0) {
		lines.push(`| - | - | (无事实记录) | - | - | - | - | - |`);
	} else {
		for (const f of index.facts) {
			lines.push(
				`| ${f.id} | ${f.kind} | ${cell(f.title, 90)} | ${f.statusCode ?? "-"} | ${f.bytes ?? "-"} | ${f.bodySha256 ?? "-"} | ${f.evidenceRef ?? "-"} | ${cell(f.command, 90) || "-"} |`,
			);
		}
	}

	lines.push(
		``,
		`## 命令与探针指标表`,
		`| 命令 | 状态码 | 字节数 | 响应哈希 (SHA-256) | remote_ip | cf_ray/server | 耗时(s) | 关联事实 |`,
		`|---|---|---|---|---|---|---|---|`,
	);
	if (index.commands.length === 0) {
		lines.push(`| (无命令记录) | - | - | - | - | - | - | - |`);
	} else {
		for (const c of index.commands) {
			const edge = [c.cfRay, c.server].filter(Boolean).join(" / ") || "-";
			lines.push(
				`| ${cell(c.cmd, 110)} | ${c.statusCode ?? "-"} | ${c.bytes ?? "-"} | ${c.bodySha256 ?? "-"} | ${c.remoteIp ?? "-"} | ${cell(edge, 48)} | ${c.timeTotal ?? "-"} | ${c.factId ?? "-"} |`,
			);
		}
	}

	lines.push(``);
	return lines.join("\n");
}

/**
 * #52 (NW-32) 结构化归档索引器：
 * 将 Episode 事实表、命令、状态码、字节数、响应哈希脱敏后持久化至
 * `<root>/.nuwa/archive/episode-<N>.json` 与 `.md`，防止长会话压缩丢失精确检索能力。
 */
export function writeEpisodeArchiveIndex(
	root: string,
	episodeData: EpisodeArchiveInput,
): WriteEpisodeArchiveResult {
	const normRoot = resolve(root || process.cwd());
	const st = episodeData.state;
	const rawEp = episodeData.episode ?? st?.project?.episode ?? 1;
	const episode = Number.isFinite(rawEp) && rawEp > 0 ? Math.floor(rawEp) : 1;

	const archiveDir = join(normRoot, ".nuwa", "archive");
	ensureSecureDir(join(normRoot, ".nuwa"));
	ensureSecureDir(archiveDir);

	// 合并显式传入与 state 中的 facts
	const factMap = new Map<string, ArchiveFactRecord>();
	if (st?.facts) {
		for (const f of Object.values(st.facts)) {
			if (!f || !f.id) continue;
			factMap.set(f.id, extractArchiveFactFromState(f as FactWithExtendedRefs, normRoot));
		}
	}
	for (const f of episodeData.facts ?? []) {
		if (!f || !f.id) continue;
		const prev = factMap.get(f.id);
		factMap.set(f.id, {
			...prev,
			...f,
			bodySha256: f.bodySha256 ? f.bodySha256.toLowerCase() : prev?.bodySha256,
		});
	}
	const facts = [...factMap.values()].sort((a, b) => a.id.localeCompare(b.id));

	// 合并显式 commands 与 facts 中携带的命令
	const commands: ArchiveCommandRecord[] = [];
	const cmdDedup = new Set<string>();
	const pushCmd = (c: ArchiveCommandRecord) => {
		const cmdText = String(c.cmd ?? "").trim();
		if (!cmdText) return;
		const key = `${cmdText}|${c.statusCode ?? ""}|${c.bytes ?? ""}|${c.bodySha256 ?? ""}|${c.factId ?? ""}`;
		if (cmdDedup.has(key)) return;
		cmdDedup.add(key);
		commands.push({
			...c,
			cmd: cmdText,
			...(c.bodySha256 ? { bodySha256: c.bodySha256.toLowerCase() } : {}),
		});
	};

	for (const c of episodeData.commands ?? []) {
		pushCmd(c);
	}
	for (const f of facts) {
		if (f.command) {
			pushCmd({
				cmd: f.command,
				statusCode: f.statusCode,
				bytes: f.bytes,
				bodySha256: f.bodySha256,
				factId: f.id,
				ts: f.createdAt,
			});
		}
	}

	const statusCodes = [
		...new Set(
			[
				...facts.map((f) => f.statusCode),
				...commands.map((c) => c.statusCode),
			].filter((n): n is number => typeof n === "number" && Number.isFinite(n)),
		),
	].sort((a, b) => a - b);

	const hashes = [
		...new Set(
			[
				...facts.map((f) => f.bodySha256),
				...commands.map((c) => c.bodySha256),
			].filter((h): h is string => typeof h === "string" && h.trim().length > 0),
		),
	].sort();

	const rawIndex: EpisodeArchiveIndex = {
		schema: 1,
		episode,
		projectId: episodeData.projectId ?? st?.project?.id ?? "unknown",
		target: episodeData.target ?? st?.project?.url ?? st?.project?.target ?? "",
		phase: episodeData.phase ?? st?.project?.phase ?? "report",
		summary: episodeData.summary ?? "",
		generatedAt: episodeData.generatedAt ?? new Date().toISOString(),
		facts,
		commands,
		stats: {
			factCount: facts.length,
			commandCount: commands.length,
			statusCodes,
			hashes,
		},
	};

	const safeIndex = redactDeep(rawIndex, normRoot);
	const jsonPath = join(archiveDir, `episode-${episode}.json`);
	const markdownPath = join(archiveDir, `episode-${episode}.md`);

	writeSecureFile(jsonPath, `${JSON.stringify(safeIndex, null, 2)}\n`);
	writeSecureFile(markdownPath, maybeRedact(renderEpisodeArchiveMarkdown(safeIndex), normRoot));

	return {
		episode,
		jsonPath,
		markdownPath,
		index: safeIndex,
	};
}

/**
 * #52 (NW-32) 结构化归档检索器：
 * 扫描 `<root>/.nuwa/archive/episode-*.json`，支持按关键词、factId、kind、episode、
 * statusCode、bodySha256（前缀/全匹配）与命令片段进行高速检索。
 */
export function searchArchiveIndexes(
	root: string,
	query: string | ArchiveSearchQuery,
): ArchiveSearchHit[] {
	const normRoot = resolve(root || process.cwd());
	const archiveDir = join(normRoot, ".nuwa", "archive");
	if (!existsSync(archiveDir)) return [];

	const q: ArchiveSearchQuery =
		typeof query === "string" ? { text: query } : query && typeof query === "object" ? query : {};

	const textTokens = (q.text ?? "")
		.trim()
		.toLowerCase()
		.split(/\s+/)
		.filter(Boolean);
	const factIdFilter = q.factId?.trim().toLowerCase();
	const kindFilter = q.kind?.trim().toLowerCase();
	const epFilter =
		typeof q.episode === "number" && Number.isFinite(q.episode) && q.episode > 0
			? Math.floor(q.episode)
			: undefined;
	const statusFilter =
		typeof q.statusCode === "number" && Number.isFinite(q.statusCode)
			? Math.floor(q.statusCode)
			: undefined;
	const hashFilter = q.hash?.trim().toLowerCase();
	const cmdFilter = q.command?.trim().toLowerCase();
	const limit =
		typeof q.limit === "number" && Number.isFinite(q.limit) && q.limit > 0 ? Math.floor(q.limit) : 50;

	let files: string[];
	try {
		files = readdirSync(archiveDir)
			.filter((name) => /^episode-\d+\.json$/i.test(name))
			.sort((a, b) => {
				const na = Number(/\d+/.exec(a)?.[0] ?? 0);
				const nb = Number(/\d+/.exec(b)?.[0] ?? 0);
				return na - nb;
			});
	} catch {
		return [];
	}

	const hits: ArchiveSearchHit[] = [];

	for (const fileName of files) {
		const fullPath = join(archiveDir, fileName);
		let idx: EpisodeArchiveIndex;
		try {
			idx = JSON.parse(readFileSync(fullPath, "utf8")) as EpisodeArchiveIndex;
		} catch {
			continue;
		}
		if (!idx || typeof idx.episode !== "number") continue;
		if (epFilter !== undefined && idx.episode !== epFilter) continue;

		const relArchive = `.nuwa/archive/${fileName}`;

		// 1. 检索 facts
		for (const f of idx.facts ?? []) {
			if (factIdFilter && f.id.toLowerCase() !== factIdFilter) continue;
			if (kindFilter && f.kind.toLowerCase() !== kindFilter) continue;
			if (statusFilter !== undefined && f.statusCode !== statusFilter) continue;
			if (hashFilter && !(f.bodySha256 ?? "").toLowerCase().includes(hashFilter)) continue;
			if (cmdFilter && !(f.command ?? "").toLowerCase().includes(cmdFilter)) continue;

			const haystack = [
				f.id,
				f.kind,
				f.title,
				f.detail ?? "",
				f.target ?? "",
				f.command ?? "",
				f.statusCode !== undefined ? String(f.statusCode) : "",
				f.bytes !== undefined ? String(f.bytes) : "",
				f.bodySha256 ?? "",
				f.evidenceRef ?? "",
			]
				.join(" ")
				.toLowerCase();

			if (textTokens.length > 0 && !textTokens.every((t) => haystack.includes(t))) continue;

			let score = 10;
			if (factIdFilter && f.id.toLowerCase() === factIdFilter) score += 50;
			if (hashFilter && f.bodySha256?.toLowerCase() === hashFilter) score += 40;
			if (statusFilter !== undefined && f.statusCode === statusFilter) score += 15;
			for (const t of textTokens) {
				if (f.id.toLowerCase() === t) score += 40;
				else if (f.title.toLowerCase().includes(t)) score += 15;
				else if ((f.command ?? "").toLowerCase().includes(t)) score += 10;
				else score += 5;
			}

			hits.push({
				episode: idx.episode,
				source: "fact",
				archiveFile: relArchive,
				factId: f.id,
				kind: f.kind,
				title: f.title,
				...(f.command ? { command: f.command } : {}),
				...(f.statusCode !== undefined ? { statusCode: f.statusCode } : {}),
				...(f.bytes !== undefined ? { bytes: f.bytes } : {}),
				...(f.bodySha256 ? { bodySha256: f.bodySha256 } : {}),
				...(f.evidenceRef ? { evidenceRef: f.evidenceRef } : {}),
				snippet: `${f.id} [${f.kind}] ${f.title}${f.statusCode !== undefined ? ` (${f.statusCode}/${f.bytes ?? "?"}B)` : ""}`,
				score,
			});
		}

		// 2. 检索 commands（当未限定非 command 专属 kindFilter 时）
		if (!kindFilter) {
			for (const c of idx.commands ?? []) {
				if (factIdFilter && (c.factId ?? "").toLowerCase() !== factIdFilter) continue;
				if (statusFilter !== undefined && c.statusCode !== statusFilter) continue;
				if (hashFilter && !(c.bodySha256 ?? "").toLowerCase().includes(hashFilter)) continue;
				if (cmdFilter && !c.cmd.toLowerCase().includes(cmdFilter)) continue;

				const haystack = [
					c.cmd,
					c.factId ?? "",
					c.statusCode !== undefined ? String(c.statusCode) : "",
					c.bytes !== undefined ? String(c.bytes) : "",
					c.bodySha256 ?? "",
					c.remoteIp ?? "",
					c.cfRay ?? "",
					c.server ?? "",
				]
					.join(" ")
					.toLowerCase();

				if (textTokens.length > 0 && !textTokens.every((t) => haystack.includes(t))) continue;

				let score = 8;
				if (hashFilter && c.bodySha256?.toLowerCase() === hashFilter) score += 35;
				if (cmdFilter && c.cmd.toLowerCase().includes(cmdFilter)) score += 20;
				if (statusFilter !== undefined && c.statusCode === statusFilter) score += 12;
				for (const t of textTokens) {
					if (c.cmd.toLowerCase().includes(t)) score += 12;
					else score += 4;
				}

				hits.push({
					episode: idx.episode,
					source: "command",
					archiveFile: relArchive,
					...(c.factId ? { factId: c.factId } : {}),
					command: c.cmd,
					...(c.statusCode !== undefined ? { statusCode: c.statusCode } : {}),
					...(c.bytes !== undefined ? { bytes: c.bytes } : {}),
					...(c.bodySha256 ? { bodySha256: c.bodySha256 } : {}),
					snippet: `${cell(c.cmd, 100)}${c.statusCode !== undefined ? ` => ${c.statusCode}/${c.bytes ?? "?"}B` : ""}`,
					score,
				});
			}
		}
	}

	hits.sort((a, b) => {
		if (b.score !== a.score) return b.score - a.score;
		if (b.episode !== a.episode) return b.episode - a.episode;
		if (a.source !== b.source) return a.source === "fact" ? -1 : 1;
		return (a.factId ?? a.command ?? "").localeCompare(b.factId ?? b.command ?? "");
	});

	return hits.slice(0, limit);
}
