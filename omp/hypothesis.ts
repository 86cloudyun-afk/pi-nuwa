/**
 * 女娲 v5.0 多资产与跳板可达拓扑图、跨事实结构化假设图及证伪自动剪枝引擎。
 *
 * 职责：
 * - 多资产拓扑（AssetNode）：维护主目标资产、SAN 子域、内网/跳板主机与网段、本地白盒仓库及可达跳板链；
 * - 跨事实推理（HypothesisNode）：组合多条非驳回事实生成高价值验证假设与可调度意图，并按收益/成本/置信度确定性评分；
 * - 证伪传播剪枝（propagateFactRejection）：当双盲复验驳回前置事实时，级联失效关联假设并阻塞所有未执行的依赖意图。
 *
 * 约束：
 * - 严禁运行时导入 `./nuwa`，仅依赖 `./types`、`./scope`、`./profiles`（纯类型）及 Node 内建模块。
 */
import { createHash } from "node:crypto";
import type { AssetNode, Fact, HypothesisNode, Intent, NuwaState, Phase } from "./types";
import { isHostInScope } from "./scope";
import type { DerivedIntentSpec } from "./profiles";

export interface UpsertAssetInput {
	id?: string;
	host?: string;
	target?: string;
	url?: string;
	port?: number;
	ports?: number[];
	scheme?: string;
	tech?: string[];
	tags?: string[];
	kind: AssetNode["kind"] | "internal";
	reachableVia?: string | string[];
	sourceFactId?: string;
	note?: string;
}

export interface AddHypothesisInput {
	id?: string;
	title: string;
	rationale?: string;
	statement?: string;
	requiredFacts: string[];
	falsificationTest?: string;
	targetPhase?: Phase;
	expectedGain: number;
	estimatedCost: number;
	confidence?: number;
	assetId?: string;
	linkedIntents?: string[];
	note?: string;
}

export interface CrossFactIntentSpec extends DerivedIntentSpec {
	hypothesisId: string;
	assetId?: string;
}

function nowIso(): string {
	return new Date().toISOString();
}

function sha(input: string, len = 12): string {
	return createHash("sha1").update(input).digest("hex").slice(0, len);
}

function oneLine(text: string | undefined, max = 140): string {
	return String(text ?? "")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, max);
}

function cell(text: string | undefined, max = 120): string {
	return oneLine(text, max).replace(/\|/g, "\\|");
}

function slugKey(raw: string): string {
	return (
		String(raw ?? "")
			.trim()
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 48) || "item"
	);
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

function isValidPort(n: unknown): n is number {
	return typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 65535;
}

function parseIpv4Parts(ip: string): [number, number, number, number] | null {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
	if (!m) return null;
	const parts: number[] = [];
	for (let i = 1; i <= 4; i++) {
		const p = m[i]!;
		if (p.length > 1 && p.startsWith("0")) return null;
		const n = Number(p);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		parts.push(n);
	}
	return [parts[0]!, parts[1]!, parts[2]!, parts[3]!];
}

function isPrivateOrMetadataIp(ip: string): boolean {
	const p = parseIpv4Parts(ip);
	if (!p) return false;
	const [b0, b1] = p;
	if (b0 === 10) return true;
	if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
	if (b0 === 192 && b1 === 168) return true;
	if (b0 === 169 && b1 === 254) return true;
	return false;
}

function isPrivateCidr(cidr: string): boolean {
	const slash = cidr.indexOf("/");
	if (slash < 0) return false;
	const ip = cidr.slice(0, slash).trim();
	const prefixStr = cidr.slice(slash + 1).trim();
	if (!/^\d{1,2}$/.test(prefixStr)) return false;
	const prefix = Number(prefixStr);
	if (prefix < 8 || prefix > 32) return false;
	return isPrivateOrMetadataIp(ip);
}

function isLocalProjectTarget(st: NuwaState): boolean {
	const p = st.project;
	if (!p) return false;
	if (p.scheme === "local") return true;
	const url = String(p.url ?? "").trim();
	const target = String(p.target ?? "").trim();
	if (/^(?:local|file):\/\//i.test(url) || /^(?:local|file):\/\//i.test(target)) return true;
	if (!/^https?:\/\//i.test(url) && /^(?:\.{1,2}(?:[\\/]|$)|[\\/]|~[\\/])/.test(target)) return true;
	return false;
}

function extractHostnameFromUrl(raw: string | undefined): string | undefined {
	const s = String(raw ?? "").trim();
	if (!s || !/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^local:\/\//i.test(s)) return undefined;
	try {
		const u = new URL(s);
		return u.hostname.toLowerCase() || undefined;
	} catch {
		return undefined;
	}
}

function extractSchemeFromUrl(raw: string | undefined): string | undefined {
	const s = String(raw ?? "").trim();
	const m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s);
	return m ? m[1]!.toLowerCase() : undefined;
}

function resolveAssetKind(kind: UpsertAssetInput["kind"], targetOrHost: string): { kind: AssetNode["kind"]; isInternal: boolean } {
	if (kind === "internal") {
		const isCidr = isPrivateCidr(targetOrHost) || /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(targetOrHost.trim());
		return { kind: isCidr ? "subnet" : "host", isInternal: true };
	}
	return { kind, isInternal: false };
}

function extractAssetPorts(node: AssetNode): number[] {
	const ports = new Set<number>();
	if (isValidPort(node.port)) ports.add(node.port);
	for (const tag of node.tags ?? []) {
		const m = /^port:(\d{1,5})$/.exec(tag);
		if (m) {
			const n = Number(m[1]);
			if (isValidPort(n)) ports.add(n);
		}
	}
	return [...ports].sort((a, b) => a - b);
}

function extractAssetTechAndLabels(node: AssetNode): string[] {
	const out: string[] = [];
	const seen = new Set<string>();
	const push = (v: string) => {
		if (!v || seen.has(v)) return;
		seen.add(v);
		out.push(v);
	};
	for (const tag of node.tags ?? []) {
		if (tag.startsWith("port:") || tag.startsWith("source:") || tag.startsWith("note:")) continue;
		if (tag.startsWith("tech:")) {
			push(tag.slice(5));
		} else {
			push(tag);
		}
	}
	return out;
}

function assetStateSignature(node: AssetNode | undefined): string {
	if (!node) return "";
	return JSON.stringify({
		id: node.id,
		kind: node.kind,
		target: node.target,
		host: node.host ?? null,
		port: node.port ?? null,
		scheme: node.scheme ?? null,
		reachableVia: node.reachableVia ?? [],
		tags: node.tags ?? [],
		sourceFactId: node.sourceFactId ?? null,
	});
}

// ============================================================================
// 多资产与跳板可达拓扑（Multi-Asset & Pivot Reachability Topology）
// ============================================================================

/** 确保 `st.assets` 存在且包含由 `st.project` 派生的主资产节点 `asset:primary`。 */
export function ensurePrimaryAsset(st: NuwaState): AssetNode {
	st.assets = st.assets ?? {};
	const p = st.project;
	const local = isLocalProjectTarget(st);
	const kind: AssetNode["kind"] = local ? "repo" : "web";
	const target = (p.url || p.target || p.host || "unknown").trim();
	const host = (p.host || extractHostnameFromUrl(target) || "").trim() || undefined;
	const port = isValidPort(p.port) ? p.port : undefined;
	const scheme = (p.scheme || extractSchemeFromUrl(target) || (local ? "local" : undefined))?.trim() || undefined;

	return upsertAssetNode(st, {
		id: "asset:primary",
		kind,
		target,
		host,
		url: p.url || undefined,
		port,
		ports: port !== undefined ? [port] : [],
		scheme,
		reachableVia: ["direct"],
	});
}

/** 幂等新增或合并资产节点（ports/tech/tags/reachableVia/sourceFactId 去重合并）。 */
export function upsertAssetNode(st: NuwaState, input: UpsertAssetInput): AssetNode {
	st.assets = st.assets ?? {};

	const rawTarget = (input.target ?? input.url ?? input.host ?? "").trim() || "unknown";
	const rawHost = (input.host ?? extractHostnameFromUrl(input.url ?? input.target) ?? "").trim();
	const normHost = rawHost ? rawHost.toLowerCase() : undefined;
	const resolved = resolveAssetKind(input.kind, rawTarget || rawHost);
	const scheme = (input.scheme ?? extractSchemeFromUrl(input.url ?? input.target) ?? (resolved.kind === "repo" ? "local" : undefined))
		?.trim()
		.toLowerCase();

	const id =
		input.id?.trim() ||
		`asset:${resolved.kind}:${slugKey(resolved.kind === "repo" ? rawTarget : normHost || rawTarget)}`;

	const existing = st.assets[id];

	const incomingPorts = [
		...(Array.isArray(input.ports) ? input.ports : []),
		...(input.port !== undefined ? [input.port] : []),
	].filter(isValidPort);
	const mergedPorts = [
		...new Set([...(existing ? extractAssetPorts(existing) : []), ...incomingPorts]),
	].sort((a, b) => a - b);

	const incomingReach = Array.isArray(input.reachableVia)
		? input.reachableVia
		: typeof input.reachableVia === "string" && input.reachableVia.trim()
			? [input.reachableVia.trim()]
			: [];
	const mergedReach = uniqStrings([...(existing?.reachableVia ?? []), ...incomingReach]);

	const tagList: string[] = [...(existing?.tags ?? [])];
	for (const p of mergedPorts) {
		tagList.push(`port:${p}`);
	}
	for (const t of input.tech ?? []) {
		const clean = String(t ?? "")
			.trim()
			.toLowerCase();
		if (clean) tagList.push(`tech:${clean}`);
	}
	if (resolved.isInternal) {
		tagList.push("internal");
	}
	for (const tag of input.tags ?? []) {
		const clean = String(tag ?? "").trim();
		if (clean) tagList.push(clean);
	}
	const srcFact = input.sourceFactId?.trim();
	if (srcFact && existing?.sourceFactId && existing.sourceFactId !== srcFact) {
		tagList.push(`source:${srcFact}`);
	}
	const cleanNote = oneLine(input.note, 120);
	if (cleanNote) {
		tagList.push(`note:${cleanNote}`);
	}

	const mergedTags = uniqStrings(tagList);
	const primaryPort = existing?.port ?? (isValidPort(input.port) ? input.port : mergedPorts[0]);

	const node: AssetNode = {
		id,
		kind: existing?.kind ?? resolved.kind,
		target: existing?.target && existing.target !== "unknown" ? existing.target : rawTarget,
		...(existing?.host || normHost ? { host: existing?.host ?? normHost } : {}),
		...(primaryPort !== undefined ? { port: primaryPort } : {}),
		...(existing?.scheme || scheme ? { scheme: existing?.scheme ?? scheme } : {}),
		...(mergedReach.length > 0 ? { reachableVia: mergedReach } : {}),
		...(mergedTags.length > 0 ? { tags: mergedTags } : {}),
		...(existing?.sourceFactId || srcFact ? { sourceFactId: existing?.sourceFactId ?? srcFact } : {}),
		createdAt: existing?.createdAt ?? nowIso(),
	};

	st.assets[id] = node;
	return node;
}

const NON_DOMAIN_EXTS = new Set([
	"json",
	"jsonl",
	"md",
	"ts",
	"tsx",
	"js",
	"jsx",
	"py",
	"go",
	"rs",
	"java",
	"php",
	"rb",
	"sh",
	"yml",
	"yaml",
	"toml",
	"ini",
	"conf",
	"cfg",
	"env",
	"bak",
	"old",
	"tmp",
	"log",
	"txt",
	"csv",
	"sql",
	"db",
	"html",
	"htm",
	"css",
	"xml",
	"svg",
	"png",
	"jpg",
	"jpeg",
	"gif",
	"pdf",
	"zip",
	"tar",
	"gz",
	"jar",
	"war",
]);

const ASSET_TECH_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
	{ name: "nginx", re: /\bnginx(?:\/[\d.]+)?\b/i },
	{ name: "apache", re: /\b(?:apache|httpd)(?:\/[\d.]+)?\b/i },
	{ name: "tomcat", re: /\btomcat(?:\/[\d.]+)?\b/i },
	{ name: "php", re: /\bphp(?:\/[\d.]+)?\b/i },
	{ name: "spring", re: /\bspring(?:[\s-]*boot|[\s-]*cloud|framework)?\b|\bactuator\b/i },
	{ name: "express", re: /\bexpress(?:\.js)?\b/i },
	{ name: "nextjs", re: /\bnext\.?js\b|__NEXT_DATA__/i },
	{ name: "react", re: /\breact\b|data-reactroot/i },
	{ name: "vue", re: /\bvue(?:\.js)?\b|__NUXT__/i },
	{ name: "django", re: /\bdjango\b/i },
	{ name: "flask", re: /\bflask\b|\bwerkzeug\b/i },
	{ name: "redis", re: /\bredis(?:[\s/-]*server)?\b/i },
	{ name: "mysql", re: /\bmysql(?:d)?\b|\bmariadb\b/i },
	{ name: "postgres", re: /\bpostgres(?:ql)?\b/i },
	{ name: "mongodb", re: /\bmongodb?\b/i },
	{ name: "elasticsearch", re: /\belasticsearch\b/i },
	{ name: "graphql", re: /\bgraphql\b/i },
	{ name: "swagger", re: /\bswagger\b|\bopenapi\b/i },
	{ name: "docker", re: /\bdocker\b/i },
	{ name: "openssh", re: /\bopenssh\b/i },
	{ name: "grafana", re: /\bgrafana\b/i },
	{ name: "jenkins", re: /\bjenkins\b/i },
	{ name: "gitlab", re: /\bgitlab\b/i },
	{ name: "wordpress", re: /\bwordpress\b|\bwp-(?:content|admin|json)\b/i },
	{ name: "minio", re: /\bminio\b/i },
];

const INTERNAL_HOST_RE =
	/\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.(?:internal|local|lan|corp|intranet|intra|priv|private|svc|cluster\.local))(?::(\d{1,5}))?\b/gi;

const IPV4_OR_CIDR_PORT_RE =
	/(?<![0-9a-zA-Z._-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?:\/(\d{1,2})|:(\d{1,5}))?(?![0-9a-zA-Z._-])/g;

const PIVOT_MENTION_RE = /\b(?:pivot|internal|intranet|subnet|lateral|metadata|bastion|jumphost)\b|内网|跳板|横向|网段/i;

function isValidSanDomain(raw: string): string | null {
	const d = raw.trim().replace(/^\*\./, "").replace(/\.+$/, "").toLowerCase();
	if (!d || d.length > 253) return null;
	if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) return null;
	const tld = d.split(".").pop() ?? "";
	if (!/^[a-z]{2,24}$/.test(tld) || NON_DOMAIN_EXTS.has(tld)) return null;
	return d;
}

function extractFactPorts(f: Fact, blob: string): number[] {
	const ports = new Set<number>();
	for (const p of f.meta?.ports ?? []) {
		const n = Number(p);
		if (isValidPort(n)) ports.add(n);
	}
	for (const m of blob.matchAll(/\b(\d{1,5})\/(?:tcp|udp)\b/gi)) {
		const n = Number(m[1]);
		if (isValidPort(n)) ports.add(n);
	}
	return [...ports].sort((a, b) => a - b);
}

function extractFactTech(f: Fact, blob: string): string[] {
	const tech = new Set<string>();
	for (const t of f.meta?.tech ?? []) {
		const clean = String(t ?? "").trim().toLowerCase();
		if (clean) tech.add(clean);
	}
	if (f.meta?.server) {
		const prod = String(f.meta.server).trim().split(/[\s/]+/)[0]?.toLowerCase();
		if (prod && prod.length >= 2) tech.add(prod);
	}
	for (const { name, re } of ASSET_TECH_PATTERNS) {
		if (re.test(blob)) tech.add(name);
	}
	return [...tech];
}

function extractLocalRepoPaths(blob: string): string[] {
	const found = new Set<string>();
	const addPath = (raw: string) => {
		const clean = raw
			.trim()
			.replace(/^local:\/\//i, "")
			.replace(/['"`),;:\]]+$/, "")
			.replace(/\/+$/, "");
		if (!clean || clean.length < 2) return;
		if (/^\/(?:tmp\/nuwa|dev|proc|sys)(?:\/|$)/i.test(clean)) return;
		if (/^https?:\/\//i.test(clean)) return;
		found.add(clean);
	};

	for (const m of blob.matchAll(/\blocal:\/\/([^\s'"`,;)]+)/gi)) {
		if (m[1]) addPath(m[1]);
	}
	for (const m of blob.matchAll(
		/(?:repo|repository|workspace|project|workdir|cwd|root|dir|directory|source|源码|仓库|工作区|目录)\s*[:=：]\s*['"]?((?:\/|\.{1,2}\/|~\/)[A-Za-z0-9._/@-]+)['"]?/gi,
	)) {
		if (m[1]) addPath(m[1]);
	}
	for (const m of blob.matchAll(
		/(?:^|[\s('"`])((?:\/(?:home|Users|opt|srv|workspace|workspaces|app|repo|repos|var\/www|code|projects)\/[A-Za-z0-9._/@-]+)|(?:\.{1,2}\/[A-Za-z0-9._/@-]+)|(?:~\/[A-Za-z0-9._/@-]+))/gm,
	)) {
		if (m[1]) addPath(m[1]);
	}
	return [...found];
}

/**
 * 扫描全部非驳回事实并增量同步多资产与跳板可达拓扑图，返回本次新建或更新的 `AssetNode` 列表。
 */
export function syncAssetsFromFacts(st: NuwaState): AssetNode[] {
	st.assets = st.assets ?? {};
	const changed = new Map<string, AssetNode>();

	const trackUpsert = (input: UpsertAssetInput): AssetNode => {
		const rawTarget = (input.target ?? input.url ?? input.host ?? "").trim() || "unknown";
		const normHost = (input.host ?? extractHostnameFromUrl(input.url ?? input.target) ?? "").trim().toLowerCase();
		const resolved = resolveAssetKind(input.kind, rawTarget || normHost);
		const predictedId =
			input.id?.trim() ||
			`asset:${resolved.kind}:${slugKey(resolved.kind === "repo" ? rawTarget : normHost || rawTarget)}`;
		const before = assetStateSignature(st.assets?.[predictedId]);
		const node = upsertAssetNode(st, input);
		const after = assetStateSignature(node);
		if (before !== after) {
			changed.set(node.id, node);
		}
		return node;
	};

	// 1. 确保主资产存在
	const beforePrimary = assetStateSignature(st.assets["asset:primary"]);
	const primary = ensurePrimaryAsset(st);
	if (beforePrimary !== assetStateSignature(primary)) {
		changed.set(primary.id, primary);
	}

	const primaryHost = (st.project.host ?? "").trim().toLowerCase();
	const primaryTargetNorm = (st.project.url || st.project.target || "")
		.trim()
		.replace(/^local:\/\//i, "")
		.replace(/\/+$/, "");
	const mode = st.project.mode;
	const facts = Object.values(st.facts ?? {}).sort((a, b) => a.id.localeCompare(b.id));

	for (const f of facts) {
		if (f.verifyStage === "rejected" || f.kind === "blocked") continue;
		const blob = [
			f.title ?? "",
			f.detail ?? "",
			f.output ?? "",
			...(f.meta?.san ?? []),
			...(f.meta?.tech ?? []),
			f.meta?.server ?? "",
		].join("\n");

		// 2. 用非跳板 service/endpoint 事实更新主资产端口与技术栈
		const isDistinctPivotService =
			(f.kind === "service" || f.kind === "endpoint") &&
			PIVOT_MENTION_RE.test(blob) &&
			[...blob.matchAll(IPV4_OR_CIDR_PORT_RE)].some((m) => {
				const ip = m[1]!;
				return m[2] !== undefined ? isPrivateCidr(`${ip}/${m[2]}`) : isPrivateOrMetadataIp(ip) && ip.toLowerCase() !== primaryHost;
			});

		if ((f.kind === "service" || f.kind === "endpoint") && !isDistinctPivotService) {
			const ports = extractFactPorts(f, blob);
			const tech = extractFactTech(f, blob);
			if (ports.length > 0 || tech.length > 0) {
				trackUpsert({
					id: "asset:primary",
					kind: primary.kind,
					target: primary.target,
					host: primary.host,
					ports,
					tech,
					reachableVia: ["direct"],
					sourceFactId: f.id,
				});
			}
		}

		// 3. 提取证书 SAN 域名 -> kind: "web", reachableVia: ["direct"]
		const rawSans = [
			...(f.meta?.san ?? []),
			...[...blob.matchAll(/\bDNS:([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,24})\b/gi)].map((m) => m[1]!),
		];
		for (const rawSan of rawSans) {
			const domain = isValidSanDomain(rawSan);
			if (!domain || domain === primaryHost) continue;
			if (st.project.scope && !isHostInScope(domain, st.project.scope).ok) continue;
			trackUpsert({
				kind: "web",
				host: domain,
				target: `https://${domain}`,
				url: `https://${domain}`,
				scheme: "https",
				reachableVia: ["direct"],
				sourceFactId: f.id,
				tags: ["san"],
			});
		}

		// 4. 提取内网/跳板主机与网段 -> asset/loot/vuln 事实（或显式提及 pivot/internal/subnet 的服务事实）
		const scanPivot =
			f.kind === "asset" ||
			f.kind === "loot" ||
			f.kind === "vuln" ||
			((f.kind === "service" || f.kind === "endpoint") && PIVOT_MENTION_RE.test(blob));

		if (scanPivot) {
			const tech = extractFactTech(f, blob);
			const factPorts = extractFactPorts(f, blob);
			const hostMatches: Array<{ host: string; inlinePort?: number }> = [];

			for (const m of blob.matchAll(IPV4_OR_CIDR_PORT_RE)) {
				const ip = m[1]!;
				const prefixStr = m[2];
				const portStr = m[3];
				if (prefixStr !== undefined) {
					const cidr = `${ip}/${prefixStr}`;
					if (!isPrivateCidr(cidr)) continue;
					trackUpsert({
						kind: "subnet",
						host: cidr,
						target: cidr,
						reachableVia: [f.id],
						sourceFactId: f.id,
						tags: ["internal", "pivot"],
					});
					continue;
				}
				if (!isPrivateOrMetadataIp(ip)) continue;
				if (ip.toLowerCase() === primaryHost) continue;
				const portNum = portStr ? Number(portStr) : undefined;
				hostMatches.push({ host: ip, inlinePort: isValidPort(portNum) ? portNum : undefined });
			}

			for (const m of blob.matchAll(INTERNAL_HOST_RE)) {
				const host = m[1]!.toLowerCase();
				if (!host || host === primaryHost) continue;
				const portNum = m[2] ? Number(m[2]) : undefined;
				hostMatches.push({ host, inlinePort: isValidPort(portNum) ? portNum : undefined });
			}

			const distinctPivotHosts = new Set(hostMatches.map((h) => h.host));
			for (const item of hostMatches) {
				const ports = item.inlinePort !== undefined
					? [item.inlinePort]
					: distinctPivotHosts.size === 1
						? factPorts
						: [];
				const primaryHostPort = item.inlinePort ?? ports[0];
				trackUpsert({
					kind: "host",
					host: item.host,
					target: primaryHostPort ? `${item.host}:${primaryHostPort}` : item.host,
					port: primaryHostPort,
					ports,
					tech,
					reachableVia: [f.id],
					sourceFactId: f.id,
					tags: ["internal", "pivot"],
				});
			}
		}

		// 5. audit / coding 模式提取本地代码仓/目录路径作为 repo 资产
		if (mode === "audit" || mode === "coding") {
			for (const repoPath of extractLocalRepoPaths(blob)) {
				if (repoPath === primaryTargetNorm) continue;
				trackUpsert({
					kind: "repo",
					target: repoPath,
					scheme: "local",
					reachableVia: ["direct"],
					sourceFactId: f.id,
				});
			}
		}
	}

	return [...changed.values()];
}

/** 将多资产与跳板可达拓扑渲染为简洁 Markdown 表格。 */
export function formatAssetTopology(st: NuwaState): string {
	const assets = Object.values(st?.assets ?? {});
	if (assets.length === 0) {
		return "资产拓扑: (空)";
	}
	assets.sort((a, b) => {
		if (a.id === "asset:primary") return -1;
		if (b.id === "asset:primary") return 1;
		return a.id.localeCompare(b.id);
	});

	const rows = assets.map((a) => {
		const ports = extractAssetPorts(a);
		const tech = extractAssetTechAndLabels(a);
		const reachList = a.reachableVia ?? [];
		const pivots = reachList.filter((r) => r !== "direct");
		const hasDirect = reachList.includes("direct") || reachList.length === 0;
		const reachStr =
			pivots.length === 0
				? "direct"
				: hasDirect && reachList.includes("direct")
					? `direct, via ${pivots.join(", ")}`
					: `via ${pivots.join(", ")}`;
		const hostOrTarget = a.target || a.host || "-";
		return `| ${cell(a.id, 48)} | ${cell(a.kind, 16)} | ${cell(hostOrTarget, 64)} | ${cell(ports.join(", ") || "-", 32)} | ${cell(tech.join(", ") || "-", 48)} | ${cell(reachStr, 36)} |`;
	});

	return [
		`| ID | 类型 | 主机/目标 | 端口 | 技术栈/标签 | 可达性 |`,
		`|---|---|---|---|---|---|`,
		...rows,
	].join("\n");
}

// ============================================================================
// 跨事实结构化假设图与收益/成本优先级评分
// ============================================================================

/**
 * 基于 `expectedGain / Math.max(1, estimatedCost)` 与 `confidence (0..1)` 计算确定性整数优先级 `[40, 95]`。
 * 收益越高、置信度越高、成本越低，优先级越高。
 */
export function scoreHypothesisPriority(h: {
	expectedGain: number;
	estimatedCost: number;
	confidence?: number;
}): number {
	const gain = Number.isFinite(h.expectedGain) ? Math.max(0, h.expectedGain) : 0;
	const cost = Number.isFinite(h.estimatedCost) ? Math.max(1, h.estimatedCost) : 1;
	const rawConf = h.confidence === undefined ? 0.75 : h.confidence;
	const conf = Number.isFinite(rawConf) ? Math.max(0, Math.min(1, rawConf)) : 0;
	const weighted = (gain / cost) * conf;
	const normalized = weighted / (weighted + 2.5);
	return Math.max(40, Math.min(95, Math.round(40 + 55 * normalized)));
}

/** 初始化/写入假设节点（按确定性 ID 幂等去重）。 */
export function addHypothesis(st: NuwaState, input: AddHypothesisInput): HypothesisNode {
	st.hypotheses = st.hypotheses ?? {};

	const reqFacts = uniqStrings(input.requiredFacts ?? []);
	const title = oneLine(input.title, 140) || "未命名假设";
	const id = input.id?.trim() || `hyp:${sha(`${title}|${[...reqFacts].sort().join(",")}`)}`;
	const existing = st.hypotheses[id];
	const now = nowIso();

	if (existing) {
		const mergedFacts = uniqStrings([...existing.requiredFacts, ...reqFacts]);
		const mergedIntents = uniqStrings([...existing.linkedIntents, ...(input.linkedIntents ?? [])]);
		const changed =
			mergedFacts.length !== existing.requiredFacts.length ||
			mergedIntents.length !== existing.linkedIntents.length;
		if (changed) {
			existing.requiredFacts = mergedFacts;
			existing.linkedIntents = mergedIntents;
			existing.updatedAt = now;
		}
		return existing;
	}

	const statement = (input.statement ?? input.rationale ?? title).trim();
	const targetPhase: Phase = input.targetPhase ?? "vuln";
	const falsificationTest =
		(input.falsificationTest ?? "").trim() ||
		`在 ${targetPhase} 阶段对前置事实 (${reqFacts.join(", ") || "无"}) 执行最小非破坏性复验以证实或证伪：${oneLine(title, 90)}`;
	const expectedGain = Number.isFinite(input.expectedGain) ? Math.max(0, input.expectedGain) : 50;
	const estimatedCost = Number.isFinite(input.estimatedCost) ? Math.max(1, input.estimatedCost) : 5;
	const metaParts: string[] = [];
	if (input.targetPhase) metaParts.push(`phase=${input.targetPhase}`);
	if (Number.isFinite(input.confidence)) {
		metaParts.push(`confidence=${Math.max(0, Math.min(1, Number(input.confidence))).toFixed(2)}`);
	}
	if (input.assetId?.trim()) metaParts.push(`asset=${input.assetId.trim()}`);
	const note = input.note?.trim() || (metaParts.length > 0 ? metaParts.join(" ") : undefined);

	const node: HypothesisNode = {
		id,
		title,
		statement,
		requiredFacts: reqFacts,
		falsificationTest,
		expectedGain,
		estimatedCost,
		status: "open",
		linkedIntents: uniqStrings(input.linkedIntents ?? []),
		createdAt: now,
		updatedAt: now,
		...(note ? { note } : {}),
	};

	st.hypotheses[id] = node;
	return node;
}

const SSRF_FACT_RE =
	/\b(?:ssrf|url[\s_-]*fetch|fetch(?:er)?|webhook|reverse[\s_-]*proxy|open[\s_-]*redirect|redirect|proxy)\b|服务端请求伪造|出向请求|回调抓取/i;
const INTERNAL_SVC_FACT_RE =
	/\b(?:redis|6379|metadata|169\.254(?:\.\d{1,3}){2}|intranet|internal|consul|etcd|2375|10250|10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b|内网|云元数据|元数据服务|跳板/i;

const FILE_READ_FACT_RE =
	/\b(?:lfi|path[\s_-]*traversal|directory[\s_-]*traversal|traversal|file[\s_-]*read|arbitrary[\s_-]*read|file[\s_-]*inclusion|download)\b|\.\.\/|\.\.\\|目录遍历|任意文件读取|文件包含/i;
const CONFIG_UPLOAD_FACT_RE =
	/(?:^|[\s/'"`(=:])\.env(?:\.[a-z0-9_-]+)?\b|\b(?:upload|uploads|config|configuration|settings|secret|secrets|backup|backups|web\.config|application\.ya?ml|config\.php)\b|文件上传|上传点|配置文件|密钥|备份/i;

const PRIV_SURFACE_RE =
	/(?:\/admin|\/api\b|\/graphql\b|\/internal\b|\/actuator\b|\/swagger|\/console\b|\/manage\b|\/dashboard\b|\/v[12]\/)/i;

const WHITEBOX_SINK_RE =
	/\b(?:sink|ast|source[\s_-]*audit|whitebox|taint|sql\s*query|raw\s*sql|exec\s*\(|spawn\s*\(|eval\s*\(|system\s*\(|template|render_template_string|deserialize|pickle|unserialize|innerHTML|dangerouslySetInnerHTML)\b|白盒|危险函数|代码审计|污点/i;
const LIVE_HTTP_HINT_RE =
	/https?:\/\/|\bHTTP\/[12](?:\.\d)?\b|\b(?:200|201|204|301|302|401|403|405|500)\b|\/[A-Za-z0-9._-]+/i;

const HTTP_COMMON_PORTS = new Set([80, 443, 8000, 8080, 8443, 3000]);
const NON_HTTP_SERVICE_RE =
	/\b(?:redis|mysql|mariadb|postgres(?:ql)?|ssh|openssh|ftp|smb|samba|ldap|mssql|oracle|mongodb|memcached|elasticsearch|rabbitmq|zookeeper|docker|2375|9200|6379|3306|5432|27017|22\/tcp)\b/i;
const CVE_OR_CONFIG_FACT_RE =
	/\bCVE-\d{4}-\d{4,7}\b|\b(?:config|\.env|password|passwd|secret|credential|token|unauth|default\s+cred|misconfig|weak\s+auth)\b|凭据|配置|未授权|漏洞/i;

function buildFactBlob(f: Fact): string {
	return [
		f.title ?? "",
		f.detail ?? "",
		f.output ?? "",
		f.command ?? "",
		...(f.meta?.paths ?? []),
		...(f.meta?.routes ?? []),
		...(f.meta?.tech ?? []),
		...(f.meta?.san ?? []),
		...(f.meta?.ports ?? []).map((p) => `${p}/tcp`),
		f.meta?.server ?? "",
	].join("\n");
}

function hasNonHttpService(f: Fact, blob: string): boolean {
	if (f.kind !== "service" && f.kind !== "asset") return false;
	const ports = extractFactPorts(f, blob);
	if (ports.some((p) => !HTTP_COMMON_PORTS.has(p))) return true;
	return NON_HTTP_SERVICE_RE.test(blob);
}

function isLiveHttpFact(f: Fact, blob: string): boolean {
	if (f.kind !== "endpoint" && f.kind !== "service") return false;
	if (
		f.meta?.status !== undefined ||
		(f.meta?.paths?.length ?? 0) > 0 ||
		(f.meta?.routes?.length ?? 0) > 0 ||
		(f.meta?.ports?.length ?? 0) > 0
	) {
		return true;
	}
	return LIVE_HTTP_HINT_RE.test(blob);
}

function resolveRelatedAssetId(st: NuwaState, facts: Fact[]): string | undefined {
	for (const f of facts) {
		if (f.assetId && st.assets?.[f.assetId]) return f.assetId;
	}
	const assets = Object.values(st.assets ?? {});
	for (const f of facts) {
		const hit = assets.find((a) => a.sourceFactId === f.id && a.id !== "asset:primary");
		if (hit) return hit.id;
	}
	if (st.assets?.["asset:primary"]) return "asset:primary";
	return undefined;
}

interface CandidateHypothesis {
	hypInput: AddHypothesisInput;
	phase: Phase;
	key: string;
	title: string;
	detail: string;
	priority: number;
	from: string[];
	assetId?: string;
}

/**
 * 跨事实组合推理引擎：从多条非驳回事实中合成结构化假设节点与高价值核验意图。
 *
 * 覆盖 5 类高价值组合链：
 * 1. SSRF / 出向抓取 + 内网服务/云元数据链 (`hyp:ssrf-internal:<f1>:<f2>`)
 * 2. 文件读取/目录遍历 + 配置/上传链 (`hyp:file-chain:<f1>:<f2>`)
 * 3. 凭据/会话角色 + 特权/API 表面链 (`hyp:auth-priv:<f1>:<f2>`)
 * 4. 白盒危险汇点 + 存活 HTTP 端点灰盒链 (`hyp:greybox:<f1>:<f2>`)
 * 5. 非 HTTP 开放服务 + 配置/凭据/CVE 链 (`hyp:svc-cve:<f1>:<f2>`)
 */
export function synthesizeCrossFactHypotheses(
	st: NuwaState,
	maxNew = 6,
): { hypotheses: HypothesisNode[]; intents: CrossFactIntentSpec[] } {
	const limit = Number.isFinite(maxNew) ? Math.max(0, Math.floor(maxNew)) : 6;
	if (limit <= 0) return { hypotheses: [], intents: [] };

	const activeFacts = Object.values(st.facts ?? {})
		.filter((f) => f.verifyStage !== "rejected" && f.kind !== "blocked")
		.sort((a, b) => a.id.localeCompare(b.id));
	if (activeFacts.length === 0) return { hypotheses: [], intents: [] };

	const blobs = new Map<string, string>();
	for (const f of activeFacts) {
		blobs.set(f.id, buildFactBlob(f));
	}

	const existingHypIds = new Set(Object.keys(st.hypotheses ?? {}));
	const existingIntentKeys = new Set<string>();
	const existingIntentHypIds = new Set<string>();
	for (const it of Object.values(st.intents ?? {})) {
		existingIntentKeys.add(it.key);
		if (it.hypothesisId) existingIntentHypIds.add(it.hypothesisId);
	}

	const candidates: CandidateHypothesis[] = [];
	const seenHypIds = new Set<string>();
	const perRuleLimit = Math.max(limit, 4);

	const canEmit = (hypId: string, intentKey: string): boolean => {
		if (seenHypIds.has(hypId)) return false;
		if (existingHypIds.has(hypId)) return false;
		if (existingIntentKeys.has(intentKey) || existingIntentKeys.has(hypId)) return false;
		if (existingIntentHypIds.has(hypId)) return false;
		return true;
	};

	const pushCandidate = (c: CandidateHypothesis) => {
		const hypId = c.hypInput.id!;
		if (!canEmit(hypId, c.key)) return;
		seenHypIds.add(hypId);
		candidates.push(c);
	};

	// Rule 1: SSRF + Internal Service / Metadata Chain
	{
		const ssrfFacts = activeFacts.filter((f) => SSRF_FACT_RE.test(blobs.get(f.id)!));
		const internalFacts = activeFacts.filter(
			(f) => f.kind === "asset" || INTERNAL_SVC_FACT_RE.test(blobs.get(f.id)!),
		);
		const seenPairs = new Set<string>();
		let count = 0;
		for (const f1 of ssrfFacts) {
			for (const f2 of internalFacts) {
				if (count >= perRuleLimit) break;
				if (f1.id === f2.id) continue;
				const pairKey = [f1.id, f2.id].sort().join("|");
				if (seenPairs.has(pairKey)) continue;
				seenPairs.add(pairKey);

				const hypId = `hyp:ssrf-internal:${f1.id}:${f2.id}`;
				const expectedGain = 95;
				const estimatedCost = 4;
				const confidence = 0.9;
				const priority = scoreHypothesisPriority({ expectedGain, estimatedCost, confidence });
				const assetId = resolveRelatedAssetId(st, [f2, f1]);
				const title = `跨事实链验证: SSRF 探测内网/元数据 (${f1.id} + ${f2.id})`;
				const rationale = `结合出向请求/SSRF 线索 ${f1.id} (${oneLine(f1.title, 60)}) 与内网资产/元数据线索 ${f2.id} (${oneLine(f2.title, 60)})，验证是否可经服务端出向访问受限内网服务。`;

				pushCandidate({
					hypInput: {
						id: hypId,
						title,
						rationale,
						requiredFacts: [f1.id, f2.id],
						falsificationTest: `通过 ${f1.id} 对 ${f2.id} 目标发起最小只读探活（严格遵守 Scope 护栏），若协议/网段被拦截或无特征响应则证伪。`,
						targetPhase: "exploit",
						expectedGain,
						estimatedCost,
						confidence,
						assetId,
					},
					phase: "exploit",
					key: hypId,
					title,
					detail: [
						`假设 ID: ${hypId}（预期收益=${expectedGain} / 成本=${estimatedCost} / 置信度=${confidence} / 优先级=${priority}）`,
						`关联事实: ${f1.id} [${f1.kind}] ${oneLine(f1.title, 70)} + ${f2.id} [${f2.kind}] ${oneLine(f2.title, 70)}`,
						`推演逻辑: ${rationale}`,
						`验证步骤: 构造最小化只读请求验证出向可达性、响应长度差异或服务 Banner 回显；禁止对内网服务执行写操作。`,
						`证伪判据: 若目标对私网/元数据地址严格拦截或回显完全一致，通过 nuwa_commit(blocked=true) 记录拦截细节并收口。`,
					].join("\n"),
					priority,
					from: [f1.id, f2.id],
					assetId,
				});
				count++;
			}
		}
	}

	// Rule 2: File Exposure / Traversal + Config or Upload Chain
	{
		const fileReadFacts = activeFacts.filter((f) => FILE_READ_FACT_RE.test(blobs.get(f.id)!));
		const cfgUploadFacts = activeFacts.filter((f) => CONFIG_UPLOAD_FACT_RE.test(blobs.get(f.id)!));
		const seenPairs = new Set<string>();
		let count = 0;
		for (const f1 of fileReadFacts) {
			for (const f2 of cfgUploadFacts) {
				if (count >= perRuleLimit) break;
				if (f1.id === f2.id) continue;
				const pairKey = [f1.id, f2.id].sort().join("|");
				if (seenPairs.has(pairKey)) continue;
				seenPairs.add(pairKey);

				const hypId = `hyp:file-chain:${f1.id}:${f2.id}`;
				const expectedGain = 88;
				const estimatedCost = 5;
				const confidence = 0.85;
				const priority = scoreHypothesisPriority({ expectedGain, estimatedCost, confidence });
				const assetId = resolveRelatedAssetId(st, [f1, f2]);
				const title = `跨事实链验证: 文件读取串联配置/上传面 (${f1.id} + ${f2.id})`;
				const rationale = `结合文件读取/路径遍历线索 ${f1.id} (${oneLine(f1.title, 60)}) 与配置/上传入口 ${f2.id} (${oneLine(f2.title, 60)})，验证敏感配置读取或上传文件路径联动影响。`;

				pushCandidate({
					hypInput: {
						id: hypId,
						title,
						rationale,
						requiredFacts: [f1.id, f2.id],
						falsificationTest: `通过 ${f1.id} 读取 ${f2.id} 指向的非破坏性配置文件或校验上传隔离边界，若规范化拦截则返回 400/403/404 即证伪。`,
						targetPhase: "exploit",
						expectedGain,
						estimatedCost,
						confidence,
						assetId,
					},
					phase: "exploit",
					key: hypId,
					title,
					detail: [
						`假设 ID: ${hypId}（预期收益=${expectedGain} / 成本=${estimatedCost} / 置信度=${confidence} / 优先级=${priority}）`,
						`关联事实: ${f1.id} [${f1.kind}] ${oneLine(f1.title, 70)} + ${f2.id} [${f2.kind}] ${oneLine(f2.title, 70)}`,
						`推演逻辑: ${rationale}`,
						`验证步骤: 验证路径遍历能否读取 .env/应用配置/备份文件或定位上传目录映射；敏感凭据入账前须脱敏。`,
						`证伪判据: 若路径规范化/白名单阻断跨目录读取，记录实测响应并收口。`,
					].join("\n"),
					priority,
					from: [f1.id, f2.id],
					assetId,
				});
				count++;
			}
		}
	}

	// Rule 3: Credential / Auth Session + Privileged Surface Chain
	{
		const credFacts = activeFacts.filter((f) => f.kind === "cred");
		const privFacts = activeFacts.filter(
			(f) => f.kind !== "cred" && PRIV_SURFACE_RE.test(blobs.get(f.id)!),
		);
		let count = 0;

		for (const f1 of credFacts) {
			for (const f2 of privFacts) {
				if (count >= perRuleLimit) break;
				if (f1.id === f2.id) continue;
				const hypId = `hyp:auth-priv:${f1.id}:${f2.id}`;
				const expectedGain = 84;
				const estimatedCost = 6;
				const confidence = 0.85;
				const priority = scoreHypothesisPriority({ expectedGain, estimatedCost, confidence });
				const assetId = resolveRelatedAssetId(st, [f2, f1]);
				const title = `跨事实链验证: 认证凭据访问特权接口矩阵 (${f1.id} + ${f2.id})`;
				const rationale = `结合已获凭据/会话 ${f1.id} (${oneLine(f1.title, 60)}) 与特权/API 表面 ${f2.id} (${oneLine(f2.title, 60)})，核验认证态访问控制与越权边界（BOLA/BFLA）。`;

				pushCandidate({
					hypInput: {
						id: hypId,
						title,
						rationale,
						requiredFacts: [f1.id, f2.id],
						falsificationTest: `携带 ${f1.id} 凭据与匿名态对比访问 ${f2.id} 只读接口，若严格执行 RBAC 返回 401/403 且无数据泄露则证伪越权假设。`,
						targetPhase: "vuln",
						expectedGain,
						estimatedCost,
						confidence,
						assetId,
					},
					phase: "vuln",
					key: hypId,
					title,
					detail: [
						`假设 ID: ${hypId}（预期收益=${expectedGain} / 成本=${estimatedCost} / 置信度=${confidence} / 优先级=${priority}）`,
						`关联事实: ${f1.id} [${f1.kind}] ${oneLine(f1.title, 70)} + ${f2.id} [${f2.kind}] ${oneLine(f2.title, 70)}`,
						`推演逻辑: ${rationale}`,
						`验证步骤: 对比匿名态与已认证态访问特权路由的 HTTP 状态码、响应体结构与对象归属校验，避免破坏性写入。`,
						`证伪判据: 若权限校验一致且无水平/垂直越权响应差异，记录矩阵结果并收口。`,
					].join("\n"),
					priority,
					from: [f1.id, f2.id],
					assetId,
				});
				count++;
			}
		}

		// 若尚未出现 cred 事实但会话保险箱已有活跃角色，使用 activeRoles 与特权面合成认证矩阵验证
		const activeRoles = uniqStrings(st.project.activeRoles ?? []);
		if (credFacts.length === 0 && activeRoles.length > 0) {
			for (const role of activeRoles) {
				for (const f2 of privFacts) {
					if (count >= perRuleLimit) break;
					const roleSlug = slugKey(role);
					const hypId = `hyp:auth-priv:role-${roleSlug}:${f2.id}`;
					const expectedGain = 84;
					const estimatedCost = 6;
					const confidence = 0.85;
					const priority = scoreHypothesisPriority({ expectedGain, estimatedCost, confidence });
					const assetId = resolveRelatedAssetId(st, [f2]);
					const title = `跨事实链验证: 保险箱角色 ${role} 核验特权接口 (${f2.id})`;
					const rationale = `结合会话保险箱活跃角色 ${role} 与特权/API 表面 ${f2.id} (${oneLine(f2.title, 60)})，执行多角色鉴权差分与越权矩阵核验。`;

					pushCandidate({
						hypInput: {
							id: hypId,
							title,
							rationale,
							requiredFacts: [f2.id],
							falsificationTest: `使用保险箱角色 ${role} 与匿名态对比重放 ${f2.id} 只读接口，确认是否存在越权或鉴权绕过。`,
							targetPhase: "vuln",
							expectedGain,
							estimatedCost,
							confidence,
							assetId,
						},
						phase: "vuln",
						key: hypId,
						title,
						detail: [
							`假设 ID: ${hypId}（预期收益=${expectedGain} / 成本=${estimatedCost} / 置信度=${confidence} / 优先级=${priority}）`,
							`关联角色/事实: vault role=${role} + ${f2.id} [${f2.kind}] ${oneLine(f2.title, 70)}`,
							`推演逻辑: ${rationale}`,
							`验证步骤: 使用会话保险箱零明文注入角色 ${role} 对比匿名态响应，验证权限矩阵与对象归属校验。`,
						].join("\n"),
						priority,
						from: [f2.id],
						assetId,
					});
					count++;
				}
			}
		}
	}

	// Rule 4: Whitebox Sink + Live Endpoint Greybox Chain
	{
		const sinkFacts = activeFacts.filter((f) => WHITEBOX_SINK_RE.test(blobs.get(f.id)!));
		const liveHttpFacts = activeFacts.filter((f) => isLiveHttpFact(f, blobs.get(f.id)!));
		const seenPairs = new Set<string>();
		let count = 0;
		for (const f1 of sinkFacts) {
			for (const f2 of liveHttpFacts) {
				if (count >= perRuleLimit) break;
				if (f1.id === f2.id) continue;
				const pairKey = [f1.id, f2.id].sort().join("|");
				if (seenPairs.has(pairKey)) continue;
				seenPairs.add(pairKey);

				const hypId = `hyp:greybox:${f1.id}:${f2.id}`;
				const expectedGain = 82;
				const estimatedCost = 7;
				const confidence = 0.8;
				const priority = scoreHypothesisPriority({ expectedGain, estimatedCost, confidence });
				const assetId = resolveRelatedAssetId(st, [f2, f1]);
				const title = `跨事实链验证: 白盒汇点到存活端点灰盒复验 (${f1.id} + ${f2.id})`;
				const rationale = `将白盒静态汇点线索 ${f1.id} (${oneLine(f1.title, 60)}) 映射至存活 HTTP 表面 ${f2.id} (${oneLine(f2.title, 60)})，验证源码风险在运行态是否可达。`;

				pushCandidate({
					hypInput: {
						id: hypId,
						title,
						rationale,
						requiredFacts: [f1.id, f2.id],
						falsificationTest: `向 ${f2.id} 存活入口发送针对 ${f1.id} 汇点参数特征的最小非破坏性探针，若输入在网关/校验层被拦截则证伪运行态可达性。`,
						targetPhase: "vuln",
						expectedGain,
						estimatedCost,
						confidence,
						assetId,
					},
					phase: "vuln",
					key: hypId,
					title,
					detail: [
						`假设 ID: ${hypId}（预期收益=${expectedGain} / 成本=${estimatedCost} / 置信度=${confidence} / 优先级=${priority}）`,
						`关联事实: ${f1.id} [${f1.kind}] ${oneLine(f1.title, 70)} + ${f2.id} [${f2.kind}] ${oneLine(f2.title, 70)}`,
						`推演逻辑: ${rationale}`,
						`验证步骤: 对照源码参数名、HTTP 方法与路由路径，向存活端点发送最小非破坏性边界输入验证汇点触发表现。`,
						`证伪判据: 若框架参数校验/WAF/补偿控制完全阻断污点到达汇点，记录实测回显并标注不可达。`,
					].join("\n"),
					priority,
					from: [f1.id, f2.id],
					assetId,
				});
				count++;
			}
		}
	}

	// Rule 5: Multi-Port Service + Known Tech/CVE/Config/Cred Chain
	{
		const svcFacts = activeFacts.filter((f) => hasNonHttpService(f, blobs.get(f.id)!));
		const techCveFacts = activeFacts.filter(
			(f) =>
				f.kind === "cred" ||
				f.kind === "vuln" ||
				f.kind === "loot" ||
				CVE_OR_CONFIG_FACT_RE.test(blobs.get(f.id)!),
		);
		const seenPairs = new Set<string>();
		let count = 0;
		for (const f1 of svcFacts) {
			for (const f2 of techCveFacts) {
				if (count >= perRuleLimit) break;
				if (f1.id === f2.id) continue;
				const pairKey = [f1.id, f2.id].sort().join("|");
				if (seenPairs.has(pairKey)) continue;
				seenPairs.add(pairKey);

				const hypId = `hyp:svc-cve:${f1.id}:${f2.id}`;
				const expectedGain = 76;
				const estimatedCost = 8;
				const confidence = 0.75;
				const priority = scoreHypothesisPriority({ expectedGain, estimatedCost, confidence });
				const assetId = resolveRelatedAssetId(st, [f1, f2]);
				const title = `跨事实链验证: 非 HTTP 服务与配置/CVE 联动核验 (${f1.id} + ${f2.id})`;
				const rationale = `结合开放非 HTTP 服务 ${f1.id} (${oneLine(f1.title, 60)}) 与凭据/配置/CVE 线索 ${f2.id} (${oneLine(f2.title, 60)})，核验服务鉴权、未授权访问或版本缺陷。`;

				pushCandidate({
					hypInput: {
						id: hypId,
						title,
						rationale,
						requiredFacts: [f1.id, f2.id],
						falsificationTest: `对 ${f1.id} 服务执行非破坏性只读版本/认证核验（结合 ${f2.id} 线索），若认证隔离且版本已修复则证伪。`,
						targetPhase: "vuln",
						expectedGain,
						estimatedCost,
						confidence,
						assetId,
					},
					phase: "vuln",
					key: hypId,
					title,
					detail: [
						`假设 ID: ${hypId}（预期收益=${expectedGain} / 成本=${estimatedCost} / 置信度=${confidence} / 优先级=${priority}）`,
						`关联事实: ${f1.id} [${f1.kind}] ${oneLine(f1.title, 70)} + ${f2.id} [${f2.kind}] ${oneLine(f2.title, 70)}`,
						`推演逻辑: ${rationale}`,
						`验证步骤: 针对已识别端口与协议执行只读版本核对、配置/凭据最小认证验证或 CVE 触发条件检查；禁止高危写操作或爆破锁号。`,
					].join("\n"),
					priority,
					from: [f1.id, f2.id],
					assetId,
				});
				count++;
			}
		}
	}

	// 按收益/成本/置信度优先级降序择优截断至 maxNew
	candidates.sort((a, b) => b.priority - a.priority || a.key.localeCompare(b.key));
	const selected = candidates.slice(0, limit);

	const hypotheses: HypothesisNode[] = [];
	const intents: CrossFactIntentSpec[] = [];
	for (const c of selected) {
		const node = addHypothesis(st, c.hypInput);
		hypotheses.push(node);
		intents.push({
			key: c.key,
			phase: c.phase,
			title: c.title,
			detail: c.detail,
			priority: c.priority,
			from: c.from,
			hypothesisId: node.id,
			...(c.assetId ? { assetId: c.assetId } : {}),
		});
	}

	return { hypotheses, intents };
}

/**
 * 事实证伪自动传播剪枝：
 * - 将所有依赖 `rejectedFactId` 且处于 `open`/`active` 的假设节点置为 `invalidated`；
 * - 将所有依赖 `rejectedFactId` 或关联已失效假设且仍处于 `open` 的意图自动置为 `blocked` 并写明 `invalidatedReason`；
 * - 严禁触碰 `done`、`claimed`、已 `blocked` 或无关意图。
 */
export function propagateFactRejection(
	st: NuwaState,
	rejectedFactId: string,
	reason?: string,
): { invalidatedHypotheses: string[]; invalidatedIntents: string[] } {
	const fid = String(rejectedFactId ?? "").trim();
	if (!fid) return { invalidatedHypotheses: [], invalidatedIntents: [] };

	const cleanReason = (reason ?? "").trim() || "前置事实被双盲复验驳回";
	const now = nowIso();
	const invalidatedHypotheses: string[] = [];
	const invalidatedIntents: string[] = [];

	const hypotheses = Object.values(st.hypotheses ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	for (const h of hypotheses) {
		if (!Array.isArray(h.requiredFacts) || !h.requiredFacts.includes(fid)) continue;
		const curStatus = h.status as string;
		if (curStatus !== "open" && curStatus !== "active") continue;
		h.status = "invalidated";
		h.updatedAt = now;
		h.note = h.note ? `${h.note} | invalidated: ${cleanReason}` : `invalidated: ${cleanReason}`;
		invalidatedHypotheses.push(h.id);
	}

	const invalidatedHypSet = new Set(invalidatedHypotheses);
	const intents: Intent[] = Object.values(st.intents ?? {}).sort((a, b) => a.id.localeCompare(b.id));
	for (const it of intents) {
		if (it.status !== "open") continue;
		const dependsOnFact = Array.isArray(it.from) && it.from.includes(fid);
		const dependsOnHyp = Boolean(it.hypothesisId && invalidatedHypSet.has(it.hypothesisId));
		if (!dependsOnFact && !dependsOnHyp) continue;

		it.status = "blocked";
		it.invalidatedReason = cleanReason;
		it.note = `剪枝: 前置事实 ${fid} 已驳回 (${cleanReason})`;
		it.doneAt = now;
		invalidatedIntents.push(it.id);
	}

	return { invalidatedHypotheses, invalidatedIntents };
}
