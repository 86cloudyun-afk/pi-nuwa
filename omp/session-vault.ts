/**
 * 女娲 v4.0 多角色会话保险箱（Session Vault）。
 *
 * 职责：
 * 1. 以 0o700 目录 + 0o600 文件权限原子持久化多角色认证会话至 `<root>/.nuwa/sessions/vault.json`。
 * 2. 提供严格的值级掩码（<=8 全掩码，否则保留前 3 后 2）与全文本脱敏能力，杜绝明文凭据进入日志、状态栏或派单提示。
 * 3. 将角色认证头物化为 `/tmp/nuwa/<projectId>/sessions/<role>.headers`（0o600），供 `curl -H @<file>` 零明文重放。
 * 4. 对 `idor`/`authbypass`/`auth`/`ep:*`/`api` 类意图自动生成合规的多角色差分鉴权重放指引。
 * 5. 支持将 `kind="cred"` 的事实自动提取并收纳至会话保险箱。
 *
 * 约束：仅使用 `import type` 引用 `./types`，严禁运行时 import `./nuwa`。
 */
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { Fact } from "./types";

export interface SessionRoleEntry {
	role: string;
	cookie?: string;
	bearer?: string;
	headers?: Record<string, string>;
	username?: string;
	password?: string;
	note?: string;
	sourceFactId?: string;
	updatedAt: string;
}

export interface SessionVault {
	schema: 1;
	updatedAt: string;
	roles: Record<string, SessionRoleEntry>;
}

export type SessionRoleInput = Omit<SessionRoleEntry, "updatedAt"> & {
	updatedAt?: string;
};

export type CredFactLike = Pick<Fact, "kind" | "title" | "detail"> & {
	id?: string;
	output?: string;
	role?: string;
};

const VAULT_SCHEMA = 1 as const;
const ROLE_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SAFE_SEGMENT_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

const COOKIE_ATTR_NAMES = new Set([
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

const GENERIC_NON_SECRET_HEADER_VALUES = new Set([
	"application/json",
	"application/x-www-form-urlencoded",
	"multipart/form-data",
	"text/html",
	"text/plain",
	"text/xml",
	"application/xml",
	"*/*",
	"gzip",
	"deflate",
	"br",
	"keep-alive",
	"close",
	"no-cache",
	"no-store",
	"utf-8",
	"zh-cn",
	"en-us",
	"xmlhttprequest",
]);

const SENSITIVE_HEADER_NAME_RE =
	/(?:auth|token|key|secret|cookie|session|jwt|csrf|xsrf|pass|cred|sign|bearer|ticket|access)/i;

const GENERIC_SHORT_COOKIE_VALUES = new Set([
	"1",
	"0",
	"true",
	"false",
	"on",
	"off",
	"yes",
	"no",
	"dark",
	"light",
	"en",
	"zh",
	"cn",
	"us",
	"lax",
	"strict",
	"none",
]);

const AUTH_DIFF_KEY_RE = /(?:^|:)(?:idor|authbypass|auth|api)(?:$|:)/i;
const AUTH_DIFF_EP_RE = /(?:^|:)ep:/i;

let atomicSeq = 0;

function nowIso(): string {
	return new Date().toISOString();
}

function stripCrlf(value: string): string {
	return String(value ?? "").replace(/[\r\n]+/g, " ").trim();
}

function sanitizeRoleName(role: string): string {
	const norm = String(role ?? "").trim().toLowerCase();
	if (!norm || norm === "." || norm === ".." || !ROLE_NAME_RE.test(norm)) {
		throw new Error(`非法角色名: ${JSON.stringify(role)}（仅允许字母/数字开头及 . _ -）`);
	}
	return norm;
}

function assertSafeProjectId(projectId: string): string {
	const safe = String(projectId ?? "").trim();
	if (!safe || safe === "." || safe === ".." || /[\\/]|\.\./.test(safe) || !SAFE_SEGMENT_RE.test(safe)) {
		throw new Error(`非法 projectId: ${JSON.stringify(projectId)}（禁止路径穿越字符）`);
	}
	return safe;
}

function vaultDirPath(root: string): string {
	return join(resolve(root), ".nuwa", "sessions");
}

function vaultFilePath(root: string): string {
	return join(vaultDirPath(root), "vault.json");
}

function emptyVault(): SessionVault {
	return {
		schema: VAULT_SCHEMA,
		updatedAt: "",
		roles: {},
	};
}

function ensureSecureDir(dirPath: string): void {
	mkdirSync(dirPath, { recursive: true, mode: 0o700 });
	try {
		chmodSync(dirPath, 0o700);
	} catch {
		/* 部分只读或非 POSIX 文件系统忽略 chmod 失败 */
	}
}

function atomicWriteSecureFile(filePath: string, content: string): void {
	const dir = dirname(filePath);
	ensureSecureDir(dir);
	const tmp = `${filePath}.tmp-${process.pid}-${Date.now()}-${atomicSeq++}`;
	writeFileSync(tmp, content, { encoding: "utf8", mode: 0o600 });
	try {
		chmodSync(tmp, 0o600);
	} catch {
		/* 忽略非 POSIX 权限异常 */
	}
	renameSync(tmp, filePath);
	try {
		chmodSync(filePath, 0o600);
	} catch {
		/* 忽略非 POSIX 权限异常 */
	}
}

function sanitizeHeadersMap(headers?: Record<string, string>): Record<string, string> | undefined {
	if (!headers || typeof headers !== "object") return undefined;
	const out: Record<string, string> = {};
	for (const [rawK, rawV] of Object.entries(headers)) {
		const k = stripCrlf(rawK).replace(/:\s*$/, "");
		const v = stripCrlf(rawV);
		if (!k || !v) continue;
		out[k] = v;
	}
	return Object.keys(out).length > 0 ? out : undefined;
}

function normalizeStoredEntry(roleKey: string, raw: unknown): SessionRoleEntry | null {
	if (!raw || typeof raw !== "object") return null;
	const obj = raw as Record<string, unknown>;
	let role: string;
	try {
		role = sanitizeRoleName(typeof obj.role === "string" && obj.role.trim() ? obj.role : roleKey);
	} catch {
		return null;
	}
	const entry: SessionRoleEntry = {
		role,
		updatedAt: typeof obj.updatedAt === "string" ? obj.updatedAt : "",
	};
	if (typeof obj.cookie === "string" && obj.cookie.trim()) entry.cookie = stripCrlf(obj.cookie);
	if (typeof obj.bearer === "string" && obj.bearer.trim()) entry.bearer = stripCrlf(obj.bearer);
	if (obj.headers && typeof obj.headers === "object" && !Array.isArray(obj.headers)) {
		const cleaned = sanitizeHeadersMap(obj.headers as Record<string, string>);
		if (cleaned) entry.headers = cleaned;
	}
	if (typeof obj.username === "string" && obj.username.trim()) entry.username = stripCrlf(obj.username);
	if (typeof obj.password === "string" && obj.password.trim()) entry.password = stripCrlf(obj.password);
	if (typeof obj.note === "string" && obj.note.trim()) entry.note = stripCrlf(obj.note);
	if (typeof obj.sourceFactId === "string" && obj.sourceFactId.trim()) {
		entry.sourceFactId = stripCrlf(obj.sourceFactId);
	}
	return entry;
}

function resolveVault(rootOrVault: string | SessionVault): SessionVault {
	if (typeof rootOrVault === "string") {
		return loadSessionVault(rootOrVault);
	}
	if (rootOrVault && typeof rootOrVault === "object" && rootOrVault.roles && typeof rootOrVault.roles === "object") {
		return rootOrVault;
	}
	return emptyVault();
}

/**
 * 读取项目会话保险箱 `<root>/.nuwa/sessions/vault.json`。
 * 文件不存在或损坏时安全返回空保险箱结构。
 */
export function loadSessionVault(root: string): SessionVault {
	const file = vaultFilePath(root);
	if (!existsSync(file)) return emptyVault();
	try {
		const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
		if (!parsed || typeof parsed !== "object") return emptyVault();
		const rawRoles = parsed.roles;
		const roles: Record<string, SessionRoleEntry> = {};
		if (rawRoles && typeof rawRoles === "object" && !Array.isArray(rawRoles)) {
			for (const [k, v] of Object.entries(rawRoles as Record<string, unknown>)) {
				const norm = normalizeStoredEntry(k, v);
				if (norm) roles[norm.role] = norm;
			}
		}
		return {
			schema: VAULT_SCHEMA,
			updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : "",
			roles,
		};
	} catch {
		return emptyVault();
	}
}

function saveSessionVault(root: string, vault: SessionVault): void {
	const file = vaultFilePath(root);
	const payload: SessionVault = {
		schema: VAULT_SCHEMA,
		updatedAt: vault.updatedAt || nowIso(),
		roles: vault.roles,
	};
	atomicWriteSecureFile(file, `${JSON.stringify(payload, null, 2)}\n`);
}

/**
 * 新增或更新指定角色的会话凭据，并以 0o700 目录 / 0o600 文件原子写入磁盘。
 */
export function upsertSessionRole(root: string, input: SessionRoleInput): SessionRoleEntry {
	const role = sanitizeRoleName(input.role);
	const vault = loadSessionVault(root);
	const prev = vault.roles[role];
	const ts = input.updatedAt?.trim() || nowIso();

	const mergeField = (incoming: string | undefined, existing: string | undefined): string | undefined => {
		if (incoming === undefined) return existing;
		const cleaned = stripCrlf(incoming);
		return cleaned ? cleaned : undefined;
	};

	let mergedHeaders: Record<string, string> | undefined = prev?.headers ? { ...prev.headers } : undefined;
	if (input.headers !== undefined) {
		const nextMap: Record<string, string> = mergedHeaders ? { ...mergedHeaders } : {};
		for (const [rawK, rawV] of Object.entries(input.headers)) {
			const k = stripCrlf(rawK).replace(/:\s*$/, "");
			if (!k) continue;
			const v = stripCrlf(rawV);
			if (!v) {
				delete nextMap[k];
			} else {
				nextMap[k] = v;
			}
		}
		mergedHeaders = Object.keys(nextMap).length > 0 ? nextMap : undefined;
	}

	const entry: SessionRoleEntry = {
		role,
		updatedAt: ts,
	};
	const cookie = mergeField(input.cookie, prev?.cookie);
	if (cookie) entry.cookie = cookie;
	const bearer = mergeField(input.bearer, prev?.bearer);
	if (bearer) entry.bearer = bearer;
	if (mergedHeaders) entry.headers = mergedHeaders;
	const username = mergeField(input.username, prev?.username);
	if (username) entry.username = username;
	const password = mergeField(input.password, prev?.password);
	if (password) entry.password = password;
	const note = mergeField(input.note, prev?.note);
	if (note) entry.note = note;
	const sourceFactId = mergeField(input.sourceFactId, prev?.sourceFactId);
	if (sourceFactId) entry.sourceFactId = sourceFactId;

	vault.roles[role] = entry;
	vault.updatedAt = ts;
	saveSessionVault(root, vault);
	return entry;
}

/**
 * 从会话保险箱中移除指定角色；存在并删除时返回 true。
 */
export function removeSessionRole(root: string, role: string): boolean {
	const norm = sanitizeRoleName(role);
	const vault = loadSessionVault(root);
	if (!vault.roles[norm]) return false;
	delete vault.roles[norm];
	vault.updatedAt = nowIso();
	saveSessionVault(root, vault);
	return true;
}

/**
 * 清空项目会话保险箱（删除 vault.json；若提供 projectId 则一并清理 `/tmp/nuwa/<projectId>/sessions/` 物化头目录）。
 */
export function clearSessionVault(root: string, projectId?: string): void {
	const file = vaultFilePath(root);
	if (existsSync(file)) {
		rmSync(file, { force: true });
	}
	if (projectId) {
		const safeId = assertSafeProjectId(projectId);
		const matDir = join("/tmp/nuwa", safeId, "sessions");
		if (existsSync(matDir)) {
			rmSync(matDir, { recursive: true, force: true });
		}
	}
}

/**
 * 敏感值掩码：长度 <= 8 全掩码（不泄露任何原字符），长度 > 8 保留前 3 位与后 2 位。
 */
export function maskSecretValue(value: string): string {
	const s = String(value ?? "").trim();
	if (!s) return "";
	if (s.length <= 8) {
		return "*".repeat(Math.max(4, s.length));
	}
	return `${s.slice(0, 3)}***${s.slice(-2)}`;
}

function maskCookieString(cookieStr: string): string {
	const raw = String(cookieStr ?? "").trim();
	if (!raw) return "";
	if (!raw.includes("=")) return maskSecretValue(raw);
	return raw
		.split(";")
		.map((part) => {
			const seg = part.trim();
			if (!seg) return "";
			const eq = seg.indexOf("=");
			if (eq <= 0) return maskSecretValue(seg);
			const ck = seg.slice(0, eq).trim();
			const cv = seg.slice(eq + 1).trim();
			if (!ck || COOKIE_ATTR_NAMES.has(ck.toLowerCase())) return seg;
			return `${ck}=${maskSecretValue(cv)}`;
		})
		.filter(Boolean)
		.join("; ");
}

function maskAuthSchemeValue(authStr: string): string {
	const raw = String(authStr ?? "").trim();
	if (!raw) return "";
	const m = /^(Bearer|Token|Basic|JWT)\s+(.+)$/i.exec(raw);
	if (m?.[1] && m[2]) {
		return `${m[1]} ${maskSecretValue(m[2].trim())}`;
	}
	return maskSecretValue(raw);
}

function collectVaultSecrets(vault: SessionVault): Array<{ raw: string; masked: string }> {
	const map = new Map<string, string>();
	const addReplacement = (raw: string | undefined, masked: string, minLen = 3) => {
		const s = String(raw ?? "").trim();
		if (!s || s.length < minLen) return;
		if (!map.has(s)) {
			map.set(s, masked);
		}
		try {
			const encoded = encodeURIComponent(s);
			if (encoded !== s && encoded.length >= minLen && !map.has(encoded)) {
				map.set(encoded, masked);
			}
		} catch {
			/* 忽略编码异常 */
		}
	};
	const addSecret = (raw: string | undefined, minLen = 3) => {
		const s = String(raw ?? "").trim();
		if (!s || s.length < minLen) return;
		addReplacement(s, maskSecretValue(s), minLen);
	};

	const addCookieSecrets = (rawCookie: string) => {
		addReplacement(rawCookie, maskCookieString(rawCookie), 3);
		for (const part of rawCookie.split(";")) {
			const seg = part.trim();
			if (!seg) continue;
			const eq = seg.indexOf("=");
			if (eq <= 0) continue;
			const ck = seg.slice(0, eq).trim();
			const cv = seg.slice(eq + 1).trim();
			if (!ck || !cv || COOKIE_ATTR_NAMES.has(ck.toLowerCase())) continue;
			const pair = `${ck}=${cv}`;
			addReplacement(pair, `${ck}=${maskSecretValue(cv)}`, 3);
			if (cv.length >= 4 && !GENERIC_SHORT_COOKIE_VALUES.has(cv.toLowerCase())) {
				addSecret(cv, 4);
			}
		}
	};

	for (const entry of Object.values(vault.roles ?? {})) {
		if (!entry) continue;

		if (entry.cookie) {
			addCookieSecrets(entry.cookie);
		}

		if (entry.bearer) {
			addReplacement(entry.bearer, maskAuthSchemeValue(entry.bearer), 3);
			const bare = entry.bearer.replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
			if (bare && bare !== entry.bearer) {
				addSecret(bare, 3);
			}
		}

		if (entry.password) {
			addSecret(entry.password, 3);
			if (entry.username) {
				const basic = Buffer.from(`${entry.username}:${entry.password}`, "utf8").toString("base64");
				addSecret(basic, 4);
			}
		}

		if (entry.headers) {
			for (const [hk, hv] of Object.entries(entry.headers)) {
				const val = String(hv ?? "").trim();
				if (!val) continue;
				const lowerVal = val.toLowerCase();
				if (GENERIC_NON_SECRET_HEADER_VALUES.has(lowerVal)) continue;
				const isSensitiveName = SENSITIVE_HEADER_NAME_RE.test(hk);
				if (hk.toLowerCase() === "cookie") {
					addCookieSecrets(val);
				} else if (isSensitiveName || val.length >= 8) {
					addReplacement(val, maskAuthSchemeValue(val), isSensitiveName ? 3 : 8);
					const bare = val.replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
					if (bare && bare !== val) {
						addSecret(bare, 3);
					}
				}
			}
		}
	}

	// 按长度降序替换，确保长凭据先被脱敏，避免短子串提前截断破坏完整替换
	return [...map.entries()]
		.sort((a, b) => b[0].length - a[0].length)
		.map(([raw, masked]) => ({ raw, masked }));
}

/**
 * 使用保险箱中全部敏感凭据对任意文本执行全量脱敏替换。
 */
export function redactVaultSecrets(text: string, rootOrVault: string | SessionVault): string {
	const src = String(text ?? "");
	if (!src) return src;
	const vault = resolveVault(rootOrVault);
	const secrets = collectVaultSecrets(vault);
	if (secrets.length === 0) return src;

	let out = src;
	for (const { raw, masked } of secrets) {
		if (out.includes(raw)) {
			out = out.split(raw).join(masked);
		}
	}
	return out;
}

/**
 * 渲染纯脱敏的会话保险箱摘要，可供状态面板、派单上下文与报告展示。
 */
export function formatSessionVaultSummary(rootOrVault: string | SessionVault): string {
	const vault = resolveVault(rootOrVault);
	const entries = Object.values(vault.roles ?? {}).sort((a, b) => a.role.localeCompare(b.role));
	if (entries.length === 0) {
		return "会话保险箱: (空)";
	}

	const lines = [`会话保险箱 (${entries.length} 个角色，已全量脱敏):`];
	for (const e of entries) {
		const parts: string[] = [`role=${e.role}`];
		if (e.username) parts.push(`user=${e.username}`);
		if (e.password) parts.push(`pass=${maskSecretValue(e.password)}`);
		if (e.cookie) parts.push(`cookie=${maskCookieString(e.cookie)}`);
		if (e.bearer) {
			const bare = e.bearer.replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
			parts.push(`bearer=${maskSecretValue(bare || e.bearer)}`);
		}
		if (e.headers && Object.keys(e.headers).length > 0) {
			const hList = Object.entries(e.headers)
				.sort(([a], [b]) => a.localeCompare(b))
				.map(([k, v]) => `${k}(${k.toLowerCase() === "cookie" ? maskCookieString(v) : maskAuthSchemeValue(v)})`)
				.join(",");
			parts.push(`headers=${hList}`);
		}
		if (e.sourceFactId) parts.push(`from=${e.sourceFactId}`);
		lines.push(`- ${parts.join(" | ")}`);
	}
	return redactVaultSecrets(lines.join("\n"), vault);
}

/**
 * 将指定角色的 HTTP 认证头物化至 `/tmp/nuwa/<projectId>/sessions/<role>.headers`（权限 0o600）。
 * 可直接配合 `curl -H @<path>` 使用，避免命令行暴露明文凭据。
 */
export function materializeRoleHeaderFile(
	rootOrVault: string | SessionVault,
	projectId: string,
	role: string,
): string | null {
	const safeProjectId = assertSafeProjectId(projectId);
	const normRole = sanitizeRoleName(role);
	const vault = resolveVault(rootOrVault);
	const entry = vault.roles[normRole];
	if (!entry) return null;

	const headerLines: string[] = [];
	const seenLower = new Set<string>();

	const pushHeader = (name: string, val: string) => {
		const cleanName = stripCrlf(name).replace(/:\s*$/, "");
		const cleanVal = stripCrlf(val);
		if (!cleanName || !cleanVal) return;
		const key = cleanName.toLowerCase();
		if (seenLower.has(key)) return;
		seenLower.add(key);
		headerLines.push(`${cleanName}: ${cleanVal}`);
	};

	if (entry.cookie) {
		pushHeader("Cookie", entry.cookie);
	}
	if (entry.bearer) {
		const val = /^(?:Bearer|Basic|Token|JWT)\s+/i.test(entry.bearer)
			? entry.bearer
			: `Bearer ${entry.bearer}`;
		pushHeader("Authorization", val);
	}
	if (entry.headers) {
		for (const [k, v] of Object.entries(entry.headers)) {
			pushHeader(k, v);
		}
	}
	if (headerLines.length === 0 && entry.username && entry.password) {
		const b64 = Buffer.from(`${entry.username}:${entry.password}`, "utf8").toString("base64");
		pushHeader("Authorization", `Basic ${b64}`);
	}

	const sessionsDir = join("/tmp/nuwa", safeProjectId, "sessions");
	const filePath = join(sessionsDir, `${normRole}.headers`);
	const body = headerLines.length > 0 ? `${headerLines.join("\n")}\n` : "";
	atomicWriteSecureFile(filePath, body);
	return filePath;
}

function isAuthDiffIntentKey(intentKey: string): boolean {
	const k = String(intentKey ?? "").trim().toLowerCase();
	if (!k) return false;
	return AUTH_DIFF_KEY_RE.test(k) || AUTH_DIFF_EP_RE.test(k);
}

/**
 * 对 `idor`/`authbypass`/`auth`/`ep:*`/`api` 类意图自动附加多角色差分鉴权重放步骤。
 * 绝不在输出中暴露任何明文凭据；若提供 `projectId`，自动物化各角色 0o600 头文件供引用。
 */
export function buildAuthDiffPacketSection(
	rootOrVault: string | SessionVault,
	intentKey: string,
	projectId?: string,
): string {
	if (!isAuthDiffIntentKey(intentKey)) return "";

	const vault = resolveVault(rootOrVault);
	const entries = Object.values(vault.roles ?? {}).sort((a, b) => a.role.localeCompare(b.role));
	if (entries.length === 0) return "";

	const safeProjectId = projectId && projectId.trim() ? assertSafeProjectId(projectId) : "";
	const roleLines: string[] = [];
	const exampleHeaderPaths: Array<{ role: string; path: string }> = [];

	for (const e of entries) {
		const matPath = safeProjectId
			? materializeRoleHeaderFile(vault, safeProjectId, e.role)
			: null;
		const pathHint = matPath ?? `/tmp/nuwa/<projectId>/sessions/${e.role}.headers`;
		exampleHeaderPaths.push({ role: e.role, path: pathHint });

		const kinds: string[] = [];
		if (e.cookie) kinds.push(`cookie=${maskCookieString(e.cookie)}`);
		if (e.bearer) {
			const bare = e.bearer.replace(/^(?:Bearer|Token|Basic|JWT)\s+/i, "").trim();
			kinds.push(`bearer=${maskSecretValue(bare || e.bearer)}`);
		}
		if (e.headers && Object.keys(e.headers).length > 0) {
			kinds.push(`headers=[${Object.keys(e.headers).sort().join(",")}]`);
		}
		if (e.username) kinds.push(`user=${e.username}`);
		roleLines.push(`- 角色 ${e.role}: ${kinds.join(", ") || "基础会话"} | 头文件: ${pathHint}`);
	}

	const sampleCmds = [
		`  - 匿名基线: curl -k -sS -o /dev/null -w "anon %{http_code} %{size_download}\\n" "<TARGET_ENDPOINT>"`,
		...exampleHeaderPaths.map(
			({ role, path }) =>
				`  - 角色 ${role}: curl -k -sS -H @"${path}" -o /dev/null -w "${role} %{http_code} %{size_download}\\n" "<TARGET_ENDPOINT>"`,
		),
	];

	const section = [
		`[多角色会话差分重放指引 (${intentKey})]`,
		`当前可用角色会话（严禁在命令、日志或回显中打印明文凭据）:`,
		...roleLines,
		`差分验证步骤:`,
		`1. 对目标接口分别以「匿名」与上述各角色头文件执行只读请求对照（禁止破坏性修改）。`,
		...sampleCmds,
		`2. 对比各角色的状态码、响应字节数及关键业务字段归属（特别核验低权限/同级角色访问高权限或他人资源 ID 是否返回非预期 200 及敏感数据）。`,
		`3. 若仅出现统一 401/403 或重定向登录页则判定鉴权一致；若存在越权访问差异，请保存脱敏响应摘要并按 nuwa_commit 入账。`,
	].join("\n");

	return redactVaultSecrets(section, vault);
}

function inferRoleFromCredText(text: string, explicitRole?: string, username?: string): string {
	if (explicitRole && explicitRole.trim()) {
		try {
			return sanitizeRoleName(explicitRole);
		} catch {
			/* 回退到自动推断 */
		}
	}

	const roleMatch = /(?:^|[\s,;|(（])(?:role|角色)\s*[:=：]\s*([a-zA-Z0-9][a-zA-Z0-9._-]{0,31})/i.exec(text);
	if (roleMatch?.[1]) {
		try {
			return sanitizeRoleName(roleMatch[1]);
		} catch {
			/* ignore */
		}
	}

	if (username) {
		try {
			return sanitizeRoleName(username);
		} catch {
			/* ignore */
		}
	}

	const commonRole = /\b(superadmin|admin|administrator|root|staff|manager|operator|editor|moderator|user[_-]?[a-z0-9]|alice|bob|guest|member)\b/i.exec(
		text,
	);
	if (commonRole?.[1]) {
		try {
			return sanitizeRoleName(commonRole[1]);
		} catch {
			/* ignore */
		}
	}

	return "default";
}

/**
 * 将 `kind="cred"` 的事实文本解析为结构化角色凭据并入库会话保险箱。
 * 非 cred 事实或未提取到有效凭据字段时返回 null。
 */
export function ingestCredFactToVault(root: string, fact: CredFactLike): SessionRoleEntry | null {
	if (!fact || fact.kind !== "cred") return null;

	const combined = [fact.title ?? "", fact.detail ?? "", fact.output ?? ""].filter(Boolean).join("\n");
	if (!combined.trim()) return null;

	let cookie: string | undefined;
	let bearer: string | undefined;
	let username: string | undefined;
	let password: string | undefined;
	const headers: Record<string, string> = {};

	// 1. 提取 Set-Cookie（支持多行 Set-Cookie 合并为单条 Cookie 串）
	const setCookiePairs: string[] = [];
	for (const m of combined.matchAll(/(?:^|\n)\s*Set-Cookie\s*:\s*([^;\r\n]+)/gi)) {
		const pair = m[1]?.trim();
		if (pair && pair.includes("=")) {
			setCookiePairs.push(pair);
		}
	}
	if (setCookiePairs.length > 0) {
		cookie = [...new Set(setCookiePairs)].join("; ");
	} else {
		const cookieLine = /(?:^|\n|\s)Cookie\s*[:=]\s*([^\r\n]+)/i.exec(combined);
		if (cookieLine?.[1]) {
			const cleaned = cookieLine[1].trim().replace(/^['"]|['"]$/g, "");
			if (cleaned.includes("=")) cookie = cleaned;
		}
	}

	// 2. 提取 Authorization: Bearer / Token / 裸 JWT
	const authBearer = /Authorization\s*:\s*(?:Bearer|Token|JWT)\s+([A-Za-z0-9._~+/=-]{6,})/i.exec(combined);
	if (authBearer?.[1]) {
		bearer = authBearer[1].trim();
	} else {
		const bareBearer = /\bBearer\s+([A-Za-z0-9._~+/=-]{8,})/i.exec(combined);
		if (bareBearer?.[1]) {
			bearer = bareBearer[1].trim();
		} else {
			const jwt = /\b(eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,})\b/.exec(combined);
			if (jwt?.[1]) {
				bearer = jwt[1].trim();
			}
		}
	}

	// 3. 提取常见 API Key / 自定义认证头
	for (const m of combined.matchAll(
		/(?:^|\n)\s*(X-API-Key|X-Auth-Token|X-Access-Token|X-Token|X-Session-Token|Api-Key)\s*:\s*([^\r\n]+)/gi,
	)) {
		const hk = m[1]?.trim();
		const hv = m[2]?.trim().replace(/^['"]|['"]$/g, "");
		if (hk && hv) headers[hk] = hv;
	}

	// 4. 提取用户名与密码
	const userMatch = /\b(?:username|user|login|account)\s*[:=]\s*([^\s,;'"\r\n]+)/i.exec(combined);
	if (userMatch?.[1]) username = userMatch[1].trim();
	const passMatch = /\b(?:password|passwd|pass|pwd)\s*[:=]\s*([^\s,;'"\r\n]+)/i.exec(combined);
	if (passMatch?.[1]) password = passMatch[1].trim();

	if (!username && !password) {
		// 仅在独立凭据行或明确标注凭据前缀后匹配 user:pass，避免误匹配 URL 与 HTTP Header
		const credPair =
			/(?:^|[\n\s])(?:cred(?:ential)?s?|账号|凭据|login)\s*[:：]\s*([a-zA-Z0-9._-]{2,32}):([^\s:'",;]{3,64})(?=\s|$)/i.exec(
				combined,
			);
		if (credPair?.[1] && credPair?.[2] && !/^(?:https?|ftp|ws|wss|tcp|udp)$/i.test(credPair[1])) {
			username = credPair[1].trim();
			password = credPair[2].trim();
		}
	}

	const hasAnySecret = Boolean(cookie || bearer || password || Object.keys(headers).length > 0);
	if (!hasAnySecret) return null;

	const role = inferRoleFromCredText(combined, fact.role, username);
	return upsertSessionRole(root, {
		role,
		...(cookie ? { cookie } : {}),
		...(bearer ? { bearer } : {}),
		...(Object.keys(headers).length > 0 ? { headers } : {}),
		...(username ? { username } : {}),
		...(password ? { password } : {}),
		...(fact.id ? { sourceFactId: fact.id } : {}),
		note: fact.title ? stripCrlf(fact.title).slice(0, 100) : undefined,
	});
}
