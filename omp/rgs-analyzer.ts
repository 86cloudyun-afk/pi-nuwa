/**
 * 女娲 v8.0 跨文件 Route-Guard-Service-Sink (RGS) 代码数据流引擎与独立验证脚本生成器。
 *
 * 职责：
 * 1. 7 语言（TS/JS、Python、Go、Java/Spring Boot、PHP、Rust）+ Webpack/Vite 前端混淆 Bundle 路由/GraphQL/参数反解；
 * 2. 跨文件 `Route → Guard → Service → Sink` 图谱构建（`analyzeCrossFileRgs`），计算全局过滤器/拦截器与前缀路由组继承差集，
 *    消除“已被上层全局路由守卫保护的控制器误报为未鉴权”的假阳性，串联跨文件 Controller→Service→Repository 污点流与 `<file>:<line>` 锚点；
 * 3. `bridgeRgsToVerificationIntents`：将跨文件鉴权缺口、污点链与混淆 Bundle 暴露面转化为待验证意图与假设；
 * 4. `generateStandalonePovScript` / `writeStandalonePovScript`：仅为 `verifyStage === "confirmed"` 或明确构造规范生成
 *    零外部依赖、零明文硬编码凭据的 `pov-<factId>.ts` 脚本（运行时从 `NUWA_POV_HEADERS_FILE` / `NUWA_POV_TOKEN_<ROLE>` 读取）。
 *
 * 约束：零第三方 npm 依赖，严禁引用 `./nuwa`，类型仅 `import type` 自 `./types`，不包含任何自动补丁修补功能。
 */
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import type { Fact, FactKind, Phase, ScopePolicy, VerifyStage } from "./types";
import {
	extractFromSourceMap,
	type CodeSurfaceInput,
	type HybridHypothesisSpec,
	type HybridVerificationIntentSpec,
	type VirtualSourceFile,
} from "./hybrid-audit";
import { inferFindingRuleMeta } from "./reporting";
import { isHostInScope } from "./scope";
import { loadSessionVault, redactVaultSecrets, type SessionVault } from "./session-vault";

const DEFAULT_IGNORED_DIRS = new Set([
	"node_modules", ".git", ".hg", ".svn", ".next", ".nuxt", ".svelte-kit",
	".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
	"vendor", "coverage", "target", ".nuwa", ".idea", ".vscode",
]);

const SUPPORTED_RGS_EXTS = new Set([
	".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
	".py", ".go", ".java", ".xml", ".php", ".phtml", ".rs", ".map",
]);

const DEFAULT_MAX_FILE_BYTES = 3 * 1024 * 1024;

export type RgsLanguage = "typescript" | "javascript" | "python" | "go" | "java" | "php" | "rust" | "bundle";

export type RgsFramework =
	| "express" | "fastify" | "koa" | "nextjs" | "nestjs"
	| "flask" | "fastapi" | "django"
	| "gin" | "echo" | "net/http"
	| "spring-boot"
	| "laravel" | "symfony" | "php-native"
	| "actix-web" | "axum"
	| "webpack-bundle" | "vite-bundle" | "sourcemap-client";

export type RgsSinkKind = "unparameterized_sql" | "dangerous_exec_call" | "unchecked_path_join" | "dynamic_outbound_url";
export type RgsRouteRiskFlag = "missing_auth_guard" | RgsSinkKind;
export type RgsGuardKind =
	| "global_filter" | "prefix_interceptor" | "router_mount_guard"
	| "route_middleware" | "method_annotation" | "public_exempt";

export interface RgsGuardRule { pattern: string; httpMethod?: string; effect: "authenticated" | "permit_all"; guardName: string; order: number; }
export interface RgsGuardNode {
	id: string; name: string; kind: RgsGuardKind; language: RgsLanguage; framework: RgsFramework;
	file: string; line: number; anchor: string; pathPatterns: string[]; exemptPatterns: string[]; orderedRules?: RgsGuardRule[];
}
export interface RgsSinkNode {
	id: string; kind: RgsSinkKind; severity: "high" | "medium"; language: RgsLanguage; framework?: RgsFramework;
	file: string; line: number; anchor: string; snippet: string; enclosingSymbol?: string; enclosingMethod?: string;
	taintedExprs: string[]; message: string;
}
export interface RgsCallSite { calleeObject?: string; calleeMethod: string; argExprs: string[]; line: number; anchor: string; }
export interface RgsServiceNode {
	id: string; language: RgsLanguage; className?: string; methodName: string; qualifiedName: string;
	role: "controller" | "service" | "repository" | "handler"; file: string; line: number; anchor: string;
	params: string[]; fieldTypes: Record<string, string>; imports: Record<string, string>;
	calls: RgsCallSite[]; localSinks: RgsSinkNode[]; paramToLocalAliases: Record<string, string[]>;
}
export interface RgsTaintHop {
	step: "route" | "controller" | "service" | "repository" | "sink";
	symbol: string; file: string; line: number; anchor: string; taintedVar: string; detail?: string;
}
export interface RgsDataflowChain {
	id: string; routeId: string; sinkId: string; sinkKind: RgsSinkKind; method: string; routePath: string;
	sourceParam: string; hops: RgsTaintHop[]; crossFile: boolean; confidence: "high" | "medium";
}
export interface RgsGraphqlOperation {
	operationName: string; kind: "query" | "mutation" | "subscription";
	variables: string[]; fields: string[]; file: string; line: number; anchor: string;
}
export interface RgsBundleEndpoint { method: string; path: string; file: string; line: number; anchor: string; params: string[]; headers: string[]; }
export interface RgsBundleExtraction { file: string; bundler: "webpack" | "vite" | "generic"; endpoints: RgsBundleEndpoint[]; graphqlOperations: RgsGraphqlOperation[]; }
export interface RgsRouteNode {
	id: string; method: string; path: string; rawLocalPath: string; language: RgsLanguage; framework: RgsFramework;
	file: string; line: number; anchor: string; controllerClass?: string; handlerName?: string;
	sourceParams: string[]; directGuards: string[]; inheritedGuards: string[]; effectiveGuards: string[];
	isExplicitlyPublic: boolean; hasEffectiveGuard: boolean; suppressedByGlobalGuard: boolean; guardCoverageReason: string;
	reachableSinks: RgsSinkNode[]; dataflowChains: RgsDataflowChain[]; riskFlags: RgsRouteRiskFlag[];
	graphqlOperation?: RgsGraphqlOperation; bundleParams?: string[];
}
export interface AnalyzeRgsOptions { ignoreDirs?: string[]; maxFileBytes?: number; includeSourceMaps?: boolean; includeBundles?: boolean; maxCallDepth?: number; }
export interface RgsGraphResult {
	scannedFiles: number; routes: RgsRouteNode[]; guards: RgsGuardNode[]; services: RgsServiceNode[];
	sinks: RgsSinkNode[]; chains: RgsDataflowChain[]; bundles: RgsBundleExtraction[];
	unauthenticatedRoutes: RgsRouteNode[]; suppressedByGlobalGuardCount: number;
	summary: {
		totalRoutes: number; guardedRoutes: number; unauthenticatedRoutes: number; suppressedFalsePositives: number;
		totalSinks: number; crossFileChains: number; bundleEndpoints: number; graphqlOperations: number;
		byLanguage: Record<string, number>; byFramework: Record<string, number>;
	};
}
export interface RgsBridgeOptions { phase?: Phase; includePublicLifecycleRoutes?: boolean; includeBundleEndpoints?: boolean; scope?: ScopePolicy; }
export interface RgsBridgeResult {
	baseUrl: string; intents: HybridVerificationIntentSpec[]; hypotheses: HybridHypothesisSpec[];
	skippedGuardedCount: number; skippedPublicLifecycleCount: number;
}
export interface ExplicitPovTargetSpec {
	factId?: string; title: string; baseUrl: string; path: string; method?: string; role?: string;
	queryParams?: Record<string, string>; headers?: Record<string, string>; body?: string | Record<string, unknown>;
	expectedStatus?: number; expectedBodyIncludes?: string[]; expectedJsonKeys?: string[]; forbiddenBodyIncludes?: string[];
	negativeControlPath?: string; negativeExpectedStatuses?: number[]; protectedControlPath?: string;
	protectedExpectedStatuses?: number[]; sourceAnchor?: string;
}
export interface GenerateStandalonePovInput {
	fact?: Pick<Fact, "id" | "kind" | "title" | "detail" | "command" | "output" | "verifyStage" | "verified" | "targetKey" | "sourceAnchor">;
	explicit?: ExplicitPovTargetSpec; baseUrl?: string; role?: string;
	vaultRootOrVault?: string | SessionVault; knownSecretsToScrub?: readonly string[]; scope?: ScopePolicy;
}
export interface StandalonePovArtifact {
	factId: string; fileName: string; ruleId: string; cwe?: string; targetUrl: string; method: string;
	roleEnvVar: string; headersFileEnvVar: "NUWA_POV_HEADERS_FILE"; requiredEnvVars: string[];
	redactedSecretsCount: number; scriptContent: string;
}
export interface StandalonePovWriteResult extends StandalonePovArtifact { filePath: string; sha256: string; bytes: number; }

// ==================== 内部词法、路径与安全辅助 ====================

const AUTH_GUARD_TOKEN_RE =
	/\b(?:auth|authenticate|authenticated|is_authenticated|isAuthenticated|require_auth|requireAuth|requires_auth|require_login|requireLogin|login_required|jwt_required|auth_required|permission_required|admin_required|verify_token|verifyToken|verify_jwt|verifyJwt|check_jwt|checkJwt|passport|authGuard|AuthGuard|useGuard|UseGuards|requireRole|require_role|requireAdmin|require_admin|checkPermission|check_permission|rbac|RBAC|sessionAuth|bearerAuth|apiKeyAuth|getServerSession|currentUser|current_user|get_current_user|get_current_active_user|IsAuthenticated|IsAdminUser|JWTAuth|TokenAuth|PreAuthorize|Secured|RolesAllowed|IsGranted|auth:sanctum|auth:api|Authenticate|CheckRole|JwtMiddleware|AuthMiddleware|RequireAuthorization)\b|[A-Za-z0-9_]*(?:Auth|JWT|Jwt|OAuth|RBAC|Role|Admin|Session|Token)(?:Middleware|Guard|Required|Filter|Interceptor|Dependency|Layer|Extractor|Check|Verify)\b|\b(?!(?:no|skip|without|un)_)[a-z0-9_]*(?:auth|jwt|oauth|rbac|bearer|admin)_(?:guard|middleware|filter|layer|check|verify|required|extractor)\b/;

const EXPLICIT_PERMIT_ALL_RE = /\b(?:permitAll\s*\(\s*\)|anonymous\s*\(\s*\)|AllowAny|allow_anonymous|AllowAnonymous|PermitAll|publicRoute|skipAuth|withoutMiddleware)\b/;
const LIFECYCLE_PUBLIC_ROUTE_RE = /^\/(?:health|healthz|readyz|livez|ping|metrics|login|signin|signup|register|logout|auth\/login|auth\/token|auth\/callback|oauth\/callback|favicon\.ico)(?:\/|$)/i;
const SENSITIVE_HEADER_KEY_RE = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-session-id|x-csrf-token|x-xsrf-token|api-key|token|secret)$/i;
const SENSITIVE_PARAM_KEY_RE = /(?:password|passwd|secret|token|cookie|credential|authorization|jwt|apikey|(?:api|private|access|client|auth|session|csrf|xsrf|master|signing)[_-]?key|session[_-]?id|^(?:auth|key|pwd|pass|session|sid)$|(?:^|[_-])(?:pwd|pass|auth|sid)(?:$|[_-]))/i;
const isSensitiveParamKey = (k: string): boolean => SENSITIVE_PARAM_KEY_RE.test(k) || /[a-z0-9](?:Pwd|Pass|Auth|Sid)$/.test(k);
const INLINE_CREDENTIAL_PATTERNS: readonly RegExp[] = [
	/https?:\/\/[^/\s'"]+:[^/\s'"]+@/gi,
	/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g,
	/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi,
	/\b(?:sk|rk|pk|tok|sec|key|pat|ghp|gho|glpat)-[A-Za-z0-9_-]{8,}/g,
	/(?:--cookie|-b)\s+['"]?[^'"\s]+['"]?/gi,
	/(?:--user|-u)\s+['"]?[^'"\s]+:[^'"\s]+['"]?/gi,
	/\b(?:Cookie|Authorization|X-Api-Key|X-Auth-Token|X-Access-Token)\s*:\s*[^\r\n'"]+/gi,
	/\b(?:[A-Za-z0-9_.-]*(?:password|passwd|secret|token|apikey|api_key|session_id)|pwd)=(?!<REDACTED)[^\s&'"]+/gi,
];

function sha256Short(input: string, len = 12): string { return createHash("sha256").update(input).digest("hex").slice(0, len); }

function normalizeRelPath(p: string): string {
	const cleaned = String(p ?? "").replace(/\\/g, "/").replace(/^(?:webpack|vite|rollup|turbopack|ng):\/\/[^/]*\/?/i, "").replace(/^file:\/\/\/?/i, "").replace(/^\.\//, "");
	const out: string[] = [];
	for (const seg of cleaned.split("/")) {
		if (!seg || seg === ".") continue;
		if (seg === "..") { if (out.length > 0) out.pop(); continue; }
		out.push(seg);
	}
	return out.join("/") || "anonymous.txt";
}

function resolveRelativeModulePath(fromFile: string, spec: string): string {
	const dir = dirname(fromFile).replace(/\\/g, "/");
	return normalizeRelPath(dir === "." ? spec : `${dir}/${spec}`);
}

function joinRoutePaths(prefix: string, subPath: string): string {
	const p1 = (prefix || "").trim();
	const p2 = (subPath || "").trim();
	if (!p1 || p1 === "/") return !p2 || p2 === "/" ? "/" : (p2.startsWith("/") ? p2 : `/${p2}`).replace(/\/{2,}/g, "/");
	const left = p1.startsWith("/") ? p1.replace(/\/+$/, "") : `/${p1.replace(/\/+$/, "")}`;
	return !p2 || p2 === "/" ? (left || "/") : `${left}/${p2.replace(/^\/+/, "")}`.replace(/\/{2,}/g, "/");
}

function buildLineStarts(content: string): number[] {
	const starts = [0];
	for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
	return starts;
}

function offsetToLine(lineStarts: number[], offset: number): number {
	let lo = 0, hi = lineStarts.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >>> 1;
		if (lineStarts[mid]! <= offset) lo = mid + 1;
		else hi = mid - 1;
	}
	return Math.max(1, hi + 1);
}

function lineSnippet(rawContent: string, lineStarts: number[], line: number, maxLen = 180): string {
	const start = lineStarts[Math.max(0, line - 1)] ?? 0;
	const end = line < lineStarts.length ? lineStarts[line]! - 1 : rawContent.length;
	return rawContent.slice(start, end).trim().slice(0, maxLen);
}

function isLikelyMinifiedBundle(filePath: string, content: string): boolean {
	const lower = filePath.toLowerCase();
	if (/\.(?:bundle|chunk|min)\.(?:js|mjs|cjs)$/.test(lower)) return true;
	if (/(?:^|\/)(?:assets|dist|build|static)\/[^/]*-[a-f0-9]{6,}\.(?:js|mjs)$/.test(lower)) return true;
	if (/\b(?:__webpack_require__|webpackChunk|__vite_ssr_import__|import\.meta\.hot)\b/.test(content)) return true;
	return /\.(?:js|mjs|cjs)$/.test(lower) && content.length >= 260 && content.length / Math.max(1, content.split("\n").length) > 200;
}

function detectRgsLanguage(filePath: string, content: string, includeBundles: boolean): RgsLanguage | null {
	const ext = extname(filePath).toLowerCase();
	if (ext === ".java") return "java";
	if (ext === ".xml") return /<mapper\b[^>]*namespace\s*=/i.test(content) ? "java" : null;
	if (ext === ".php" || ext === ".phtml") return "php";
	if (ext === ".rs") return "rust";
	if (ext === ".py") return "python";
	if (ext === ".go") return "go";
	if (ext === ".ts" || ext === ".tsx") return "typescript";
	if (ext === ".js" || ext === ".jsx" || ext === ".mjs" || ext === ".cjs") return includeBundles && isLikelyMinifiedBundle(filePath, content) ? "bundle" : "javascript";
	return null;
}

const JS_REGEX_PRECEDING_KW = new Set(["return", "case", "throw", "typeof", "void", "delete", "in", "of", "instanceof", "await", "yield"]);
function canStartJsRegexAt(chars: string[], slashIdx: number): boolean {
	let p = slashIdx - 1;
	while (p >= 0 && (chars[p] === " " || chars[p] === "\t" || chars[p] === "\r" || chars[p] === "\n")) p--;
	if (p < 0) return true;
	const prev = chars[p]!;
	if ("=(,[!:;&|?{}~+-*%^<>".includes(prev)) return true;
	if (/[A-Za-z_$]/.test(prev)) {
		const end = p;
		while (p >= 0 && /[A-Za-z0-9_$]/.test(chars[p]!)) p--;
		return JS_REGEX_PRECEDING_KW.has(chars.slice(p + 1, end + 1).join(""));
	}
	return false;
}

/** 保持字符偏移与换行符 100% 不变剥离注释（保护 JS/TS 正则字面量、PHP 8 `#[...]` 注解与 Rust 生命周期 `'a`）。 */
function stripCommentsPreservingOffsets(src: string, lang: RgsLanguage): string {
	const chars = Array.from(src);
	const len = chars.length;
	let i = 0;
	while (i < len) {
		const ch = chars[i]!, next = i + 1 < len ? chars[i + 1]! : "";
		if (lang === "python") {
			if ((ch === "'" || ch === '"') && next === ch && chars[i + 2] === ch) {
				const q = ch; i += 3;
				while (i < len) {
					if (chars[i] === "\\") { i += 2; continue; }
					if (chars[i] === q && chars[i + 1] === q && chars[i + 2] === q) { i += 3; break; }
					i++;
				}
				continue;
			}
			if (ch === "'" || ch === '"') {
				const q = ch; i++;
				while (i < len && chars[i] !== "\n" && chars[i] !== "\r") {
					if (chars[i] === "\\") { i += 2; continue; }
					if (chars[i] === q) { i++; break; }
					i++;
				}
				continue;
			}
			if (ch === "#") { while (i < len && chars[i] !== "\n" && chars[i] !== "\r") { chars[i] = " "; i++; } continue; }
			i++; continue;
		}
		if (ch === "/" && next === "/") { while (i < len && chars[i] !== "\n" && chars[i] !== "\r") { chars[i] = " "; i++; } continue; }
		if (ch === "/" && next === "*") {
			chars[i] = " "; chars[i + 1] = " "; i += 2;
			while (i < len) {
				if (chars[i] === "*" && chars[i + 1] === "/") { chars[i] = " "; chars[i + 1] = " "; i += 2; break; }
				if (chars[i] !== "\n" && chars[i] !== "\r") chars[i] = " ";
				i++;
			}
			continue;
		}
		if ((lang === "typescript" || lang === "javascript" || lang === "bundle") && ch === "/" && canStartJsRegexAt(chars, i)) {
			let j = i + 1, inClass = false, closed = false;
			while (j < len && chars[j] !== "\n" && chars[j] !== "\r") {
				const rc = chars[j]!;
				if (rc === "\\") { j += 2; continue; }
				if (rc === "[") inClass = true;
				else if (rc === "]" && inClass) inClass = false;
				else if (rc === "/" && !inClass) { closed = true; j++; while (j < len && /[a-z]/i.test(chars[j]!)) j++; break; }
				j++;
			}
			if (closed) { i = j; continue; }
		}
		if (lang === "php" && ch === "#" && next !== "[") { while (i < len && chars[i] !== "\n" && chars[i] !== "\r") { chars[i] = " "; i++; } continue; }
		if (lang === "java" && ch === '"' && next === '"' && chars[i + 2] === '"') {
			i += 3;
			while (i < len) {
				if (chars[i] === "\\") { i += 2; continue; }
				if (chars[i] === '"' && chars[i + 1] === '"' && chars[i + 2] === '"') { i += 3; break; }
				i++;
			}
			continue;
		}
		if (lang === "rust" && ch === "r" && (next === "#" || next === '"')) {
			let hashes = 0, p = i + 1;
			while (p < len && chars[p] === "#") { hashes++; p++; }
			if (p < len && chars[p] === '"') {
				i = p + 1;
				while (i < len) {
					if (chars[i] === '"') {
						let ok = true;
						for (let h = 1; h <= hashes; h++) if (chars[i + h] !== "#") { ok = false; break; }
						if (ok) { i += 1 + hashes; break; }
					}
					i++;
				}
				continue;
			}
		}
		if (lang === "rust" && ch === "'") {
			if (next === "\\") { i += 2; while (i < len && chars[i] !== "'" && chars[i] !== "\n") i++; if (i < len && chars[i] === "'") i++; continue; }
			i += i + 2 < len && chars[i + 2] === "'" ? 3 : 1; continue;
		}
		if (ch === "`" && (lang === "typescript" || lang === "javascript" || lang === "go" || lang === "bundle")) {
			i++;
			while (i < len) {
				if (lang !== "go" && chars[i] === "\\") { i += 2; continue; }
				if (chars[i] === "`") { i++; break; }
				i++;
			}
			continue;
		}
		if (ch === '"' || ch === "'") {
			const q = ch; i++;
			while (i < len && chars[i] !== "\n" && chars[i] !== "\r") {
				if (chars[i] === "\\") { i += 2; continue; }
				if (chars[i] === q) { i++; break; }
				i++;
			}
			continue;
		}
		i++;
	}
	return chars.join("");
}

function isRustLifetimeAt(src: string, idx: number): boolean {
	if (src[idx] !== "'") return false;
	let p = idx + 1;
	if (p >= src.length || !/[A-Za-z_]/.test(src[p]!)) return false;
	while (p < src.length && /[A-Za-z0-9_]/.test(src[p]!)) p++;
	// 若紧随标识符之后是闭合单引号 `'foo'`，则是普通单引号字符串而非 Rust 生命周期
	return src[p] !== "'";
}

function extractBalanced(src: string, openIdx: number, openChar: "(" | "{" | "[", closeChar: ")" | "}" | "]", maxScan = 16000, rustMode = false): { inner: string; endIdx: number } | null {
	if (src[openIdx] !== openChar) return null;
	const limit = Math.min(src.length, openIdx + maxScan);
	let depth = 1, quote: string | null = null;
	for (let i = openIdx + 1; i < limit; i++) {
		const ch = src[i]!;
		if (quote) {
			if (ch === "\\") { i++; continue; }
			if (quote !== "`" && (ch === "\n" || ch === "\r")) { quote = null; continue; }
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			if (rustMode && ch === "'" && isRustLifetimeAt(src, i)) continue;
			quote = ch; continue;
		}
		if (ch === openChar) depth++;
		else if (ch === closeChar && --depth === 0) return { inner: src.slice(openIdx + 1, i), endIdx: i };
	}
	return null;
}

function splitTopLevelCommas(inner: string, rustMode = false): string[] {
	const parts: string[] = [];
	let start = 0, depth = 0, quote: string | null = null;
	for (let i = 0; i < inner.length; i++) {
		const ch = inner[i]!;
		if (quote) {
			if (ch === "\\") { i++; continue; }
			if (quote !== "`" && (ch === "\n" || ch === "\r")) { quote = null; continue; }
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === '"' || ch === "'" || ch === "`") {
			if (rustMode && ch === "'" && isRustLifetimeAt(inner, i)) continue;
			quote = ch; continue;
		}
		if (ch === "(" || ch === "{" || ch === "[" || ch === "<") depth++;
		else if (ch === ")" || ch === "}" || ch === "]" || ch === ">") depth = Math.max(0, depth - 1);
		else if (ch === "," && depth === 0) {
			const seg = inner.slice(start, i).trim();
			if (seg) parts.push(seg);
			start = i + 1;
		}
	}
	const tail = inner.slice(start).trim();
	if (tail) parts.push(tail);
	return parts;
}

/** Ant 风格与前缀路由守卫路径模式匹配（支持 `/**`, `/*`, `{id}`, `:id` 及纯前缀 `/` 边界校验）。 */
export function matchGuardPathPattern(pattern: string, routePath: string): boolean {
	const rawPat = (pattern || "").trim();
	const normRoute = joinRoutePaths("/", routePath || "/");
	if (!rawPat || rawPat === "/**" || rawPat === "/*") {
		return rawPat === "/*" ? normRoute.split("/").filter(Boolean).length <= 1 : true;
	}
	const normPat = rawPat.startsWith("/") ? rawPat : `/${rawPat}`;
	if (!normPat.includes("*") && !normPat.includes("?") && !normPat.includes("{") && !normPat.includes(":")) {
		const clean = normPat.replace(/\/+$/, "") || "/";
		return clean === "/" ? true : normRoute === clean || normRoute.startsWith(`${clean}/`);
	}
	const patSegs = normPat.replace(/\/+$/, "").split("/").filter(Boolean);
	const routeSegs = normRoute.replace(/\/+$/, "").split("/").filter(Boolean);

	function matchSegs(pi: number, ri: number): boolean {
		while (pi < patSegs.length) {
			const ps = patSegs[pi]!;
			if (ps === "**") {
				if (pi === patSegs.length - 1) return true;
				for (let k = ri; k <= routeSegs.length; k++) if (matchSegs(pi + 1, k)) return true;
				return false;
			}
			if (ri >= routeSegs.length) return false;
			const rs = routeSegs[ri]!;
			if (ps === "*" || /^\{[^/]+\}$/.test(ps) || /^:[A-Za-z0-9_]+$/.test(ps)) { pi++; ri++; continue; }
			const reStr = `^${ps.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")}$`;
			if (!new RegExp(reStr).test(rs)) return false;
			pi++; ri++;
		}
		return ri === routeSegs.length;
	}
	return matchSegs(0, 0);
}

// ==================== 文件加载与中间结构 ====================

interface LoadedRgsFile { file: string; raw: string; clean: string; lang: RgsLanguage; lineStarts: number[]; isXmlMapper?: boolean; }
interface RawCrossMountEdge {
	parentFile: string; parentRouterVar?: string; targetModuleRel?: string; targetSymbol?: string;
	prefix: string; guards: string[]; exempts: string[]; framework: RgsFramework; language: RgsLanguage; line: number;
}
interface RawRouteDraft {
	method: string; localPath: string; routerVar?: string; controllerClass?: string; handlerName?: string;
	language: RgsLanguage; framework: RgsFramework; file: string; line: number;
	sourceParams: string[]; directGuards: string[]; isExplicitlyPublic: boolean;
	graphqlOperation?: RgsGraphqlOperation; bundleParams?: string[];
}

function collectRgsFiles(input: CodeSurfaceInput, opts?: AnalyzeRgsOptions): LoadedRgsFile[] {
	const ignoreSet = new Set(DEFAULT_IGNORED_DIRS);
	for (const d of opts?.ignoreDirs ?? []) ignoreSet.add(d);
	const maxBytes = opts?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
	const includeSourceMaps = opts?.includeSourceMaps !== false;
	const includeBundles = opts?.includeBundles !== false;
	const virtuals: VirtualSourceFile[] = [];

	const addDiskPath = (targetPath: string, rootBase: string): void => {
		if (!existsSync(targetPath)) return;
		let st;
		try { st = lstatSync(targetPath); } catch { return; }
		if (st.isSymbolicLink()) return;
		if (st.isDirectory()) {
			let entries: string[] = [];
			try { entries = readdirSync(targetPath); } catch { return; }
			entries.sort();
			for (const name of entries) {
				if (!ignoreSet.has(name)) addDiskPath(join(targetPath, name), rootBase);
			}
			return;
		}
		if (!st.isFile() || st.size > maxBytes || !SUPPORTED_RGS_EXTS.has(extname(targetPath).toLowerCase())) return;
		try {
			const content = readFileSync(targetPath, "utf8");
			virtuals.push({ path: normalizeRelPath(relative(rootBase, targetPath) || basename(targetPath)), content });
		} catch { /* ignore */ }
	};

	if (typeof input === "string") {
		const abs = resolve(input);
		addDiskPath(abs, existsSync(abs) && lstatSync(abs).isDirectory() ? abs : dirname(abs));
	} else if (Array.isArray(input)) {
		for (const item of input) {
			if (typeof item === "string") {
				const abs = resolve(item);
				addDiskPath(abs, existsSync(abs) && lstatSync(abs).isDirectory() ? abs : dirname(abs));
			} else if (item && typeof item === "object" && typeof item.path === "string") {
				virtuals.push({ path: normalizeRelPath(item.path), content: String(item.content ?? "") });
			}
		}
	} else if (input && typeof input === "object") {
		for (const [k, v] of Object.entries(input)) virtuals.push({ path: normalizeRelPath(k), content: String(v ?? "") });
	}

	const loaded: LoadedRgsFile[] = [];
	for (const vf of virtuals) {
		const ext = extname(vf.path).toLowerCase();
		if (ext === ".map") {
			if (!includeSourceMaps) continue;
			try {
				const parsedMap = JSON.parse(vf.content) as { sources?: unknown[]; sourcesContent?: unknown[] };
				const sources = Array.isArray(parsedMap.sources) ? parsedMap.sources : [];
				const contents = Array.isArray(parsedMap.sourcesContent) ? parsedMap.sourcesContent : [];
				for (let idx = 0; idx < contents.length; idx++) {
					const subContent = typeof contents[idx] === "string" ? (contents[idx] as string) : "";
					if (!subContent) continue;
					const subPath = normalizeRelPath(typeof sources[idx] === "string" ? (sources[idx] as string) : `map-src-${idx}.js`);
					const subLang = detectRgsLanguage(subPath, subContent, includeBundles);
					if (subLang) loaded.push({ file: subPath, raw: subContent, clean: stripCommentsPreservingOffsets(subContent, subLang), lang: subLang, lineStarts: buildLineStarts(subContent) });
				}
			} catch { /* ignore invalid map */ }
			continue;
		}
		const lang = detectRgsLanguage(vf.path, vf.content, includeBundles);
		if (!lang) continue;
		const isXmlMapper = ext === ".xml";
		loaded.push({ file: vf.path, raw: vf.content, clean: isXmlMapper ? vf.content : stripCommentsPreservingOffsets(vf.content, lang), lang, lineStarts: buildLineStarts(vf.content), ...(isXmlMapper ? { isXmlMapper: true } : {}) });
	}
	return loaded.sort((a, b) => a.file.localeCompare(b.file));
}

// ==================== 通用方法体内 Sink 与调用扫描 ====================

function containsIdentifier(expr: string, ident: string): boolean {
	if (!expr || !ident) return false;
	const escaped = ident.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	return ident.startsWith("$") ? new RegExp(`${escaped}(?![A-Za-z0-9_])`).test(expr) : new RegExp(`\\b${escaped}\\b`).test(expr);
}

function scanBodyForSinksAndCalls(opts: {
	rawFileContent: string; bodyClean: string; bodyRaw: string; bodyStartOffset: number; lineStarts: number[];
	file: string; lang: RgsLanguage; framework?: RgsFramework; enclosingSymbol?: string; enclosingMethod?: string; knownParams: string[];
}): { sinks: RgsSinkNode[]; calls: RgsCallSite[]; paramAliases: Record<string, string[]> } {
	const { rawFileContent, bodyClean, bodyRaw, bodyStartOffset, lineStarts, file, lang, framework, enclosingSymbol, enclosingMethod, knownParams } = opts;
	const sinks: RgsSinkNode[] = [], calls: RgsCallSite[] = [], paramAliases: Record<string, string[]> = {};
	for (const p of knownParams) paramAliases[p] = [p];

	const assignPatterns: RegExp[] = [
		/\b(?:const|let|var|val|mut)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:?=\s*([^\n;]+)/g,
		/\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\n;]+)/g,
		/\b(?:String|int|long|Object|var|final\s+String)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\n;]+)/g,
	];
	for (let pass = 0; pass < 2; pass++) {
		for (const re of assignPatterns) {
			re.lastIndex = 0;
			for (const m of bodyClean.matchAll(re)) {
				const lhs = m[1]!;
				const rhs = m[2]!;
				const fullLhs = re === assignPatterns[1] ? `$${lhs}` : lhs;
				for (const [rootParam, aliases] of Object.entries(paramAliases)) {
					if (aliases.some((al) => containsIdentifier(rhs, al))) {
						if (!aliases.includes(fullLhs)) aliases.push(fullLhs);
					}
				}
				if (lang === "php" && /\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|query|post|get|all)\b/.test(rhs)) {
					const srcKey =
						/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['"]([^'"]+)['"]\s*\]/.exec(rhs)?.[1] ??
						/\$request->(?:input|query|post|get)\s*\(\s*['"]([^'"]+)['"]/.exec(rhs)?.[1] ??
						"_superglobal";
					paramAliases[srcKey] = paramAliases[srcKey] ?? [srcKey];
					if (!paramAliases[srcKey]!.includes(fullLhs)) paramAliases[srcKey]!.push(fullLhs);
				}
			}
		}
	}

	const pushSink = (kind: RgsSinkKind, relOffset: number, exprText: string, message: string, severity: "high" | "medium" = "high") => {
		const line = offsetToLine(lineStarts, bodyStartOffset + relOffset);
		const anchor = `${file}:${line}`;
		const matchedTaints: string[] = [];
		for (const [rootParam, aliases] of Object.entries(paramAliases)) {
			if (aliases.some((al) => containsIdentifier(exprText, al))) matchedTaints.push(rootParam);
		}
		if (matchedTaints.length === 0) {
			if (lang === "php" && /\$_(?:GET|POST|REQUEST|COOKIE)\b|\$request->(?:input|query|post|get)\b/.test(exprText)) matchedTaints.push("request_input");
			else if ((lang === "typescript" || lang === "javascript") && /\breq\.(?:query|body|params|headers)\b/.test(exprText)) matchedTaints.push("req_input");
			else if (lang === "python" && /\brequest\.(?:args|form|json|values|GET|POST)\b/.test(exprText)) matchedTaints.push("request_input");
			else if (lang === "go" && /\b(?:c\.(?:Query|Param|PostForm)|r\.URL\.Query|r\.FormValue)\b/.test(exprText)) matchedTaints.push("request_input");
		}
		sinks.push({
			id: `sink-${sha256Short(`${anchor}:${kind}:${sinks.length}`)}`,
			kind, severity, language: lang, ...(framework ? { framework } : {}),
			file, line, anchor, snippet: lineSnippet(rawFileContent, lineStarts, line),
			...(enclosingSymbol ? { enclosingSymbol } : {}),
			...(enclosingMethod ? { enclosingMethod } : {}),
			taintedExprs: matchedTaints, message,
		});
	};

	const sqlPatterns: Array<{ re: RegExp; msg: string }> = [
		{ re: /\b(?:jdbcTemplate|namedParameterJdbcTemplate|statement|stmt|entityManager)\s*\.\s*(?:query|queryForList|queryForMap|queryForObject|update|execute|executeQuery|createNativeQuery)\s*\(\s*([^;)]+\+[^;)]+)\)/g, msg: "Java SQL 查询使用字符串拼接构造动态语句" },
		{ re: /@(?:Select|Update|Delete|Insert)\s*\(\s*["'][^"']*\$\{([^}]+)\}[^"']*["']\s*\)/g, msg: "MyBatis 注解 SQL 使用非参数化 ${...} 动态插值" },
		{ re: /\b(?:DB::(?:raw|select|statement)|->(?:whereRaw|orWhereRaw|orderByRaw|havingRaw|selectRaw)|mysqli_query|mysql_query|->query|->exec)\s*\(\s*([^;\n)]*(?:\.\s*\$|\$_(?:GET|POST|REQUEST)|"[^"]*\$[A-Za-z_])[^;\n)]*)\)/g, msg: "PHP 数据库查询直接拼接或内插外部变量" },
		{ re: /\b(?:sqlx::query(?:_as|_scalar)?|sql_query)\s*\(\s*&?\s*format!\s*\(([^)]+)\)/g, msg: "Rust SQL 查询通过 format! 动态格式化构造语句" },
		{ re: /\b(?:query|queryRaw|queryRawUnsafe|execute|executemany|raw|Raw|Exec|Query|QueryRow)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|f["'][^"']*\{[^}]+\}[^"']*["']|fmt\.Sprintf\s*\([^)]+\)|["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+[^)]+)\)/gi, msg: "动态 SQL 字符串插值或拼接调用" },
	];
	for (const sp of sqlPatterns) for (const m of bodyClean.matchAll(sp.re)) pushSink("unparameterized_sql", m.index ?? 0, m[0], sp.msg, "high");

	const execPatterns: Array<{ re: RegExp; msg: string }> = [
		{ re: /\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(([^)]+)\)/g, msg: "Java 操作系统进程命令调用" },
		{ re: /\b(?:shell_exec|passthru|system|popen|proc_open|exec)\s*\(\s*([^)]*\$[^)]*)\)/g, msg: "PHP 系统命令执行函数传入动态变量" },
		{ re: /\bCommand::new\s*\(([^)]+)\)/g, msg: "Rust Process Command 构造调用" },
		{ re: /\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(([^)]+)\)|\b(?:os\.system|subprocess\.(?:Popen|run|call|check_output)|exec\.Command)\s*\(([^)]+)\)/g, msg: "系统子进程命令执行调用" },
	];
	for (const ep of execPatterns) {
		for (const m of bodyClean.matchAll(ep.re)) {
			if ((lang === "typescript" || lang === "javascript") && /\/[^/\n]+\/[gimsuy]*\.exec\s*\(/.test(m[0])) continue;
			pushSink("dangerous_exec_call", m.index ?? 0, m[0], ep.msg, "high");
		}
	}

	const pathPatterns: Array<{ re: RegExp; msg: string }> = [
		{ re: /\b(?:file_get_contents|file_put_contents|readfile|unlink|fopen|include|include_once|require|require_once)\s*\(\s*([^)]*\$[^)]*)\)/g, msg: "PHP 文件读取/包含操作传入动态变量" },
		{ re: /\b(?:Files\.(?:readString|readAllBytes|newInputStream|delete)|new\s+File(?:InputStream|OutputStream)?|Paths\.get)\s*\(([^)]+)\)/g, msg: "Java 文件系统路径构造访问" },
		{ re: /\b(?:std::fs|tokio::fs)::(?:read_to_string|read|write|remove_file|File::open)\s*\(([^)]+)\)/g, msg: "Rust 文件系统动态路径访问" },
		{ re: /\b(?:readFileSync|readFile|createReadStream|unlinkSync|os\.Open|ioutil\.ReadFile|os\.ReadFile|open)\s*\(([^)]+)\)/g, msg: "文件系统读取操作" },
	];
	for (const pp of pathPatterns) {
		for (const m of bodyClean.matchAll(pp.re)) {
			if (!/^['"`][^'"`$#{]+['"`]$/.test((m[1] ?? "").trim())) pushSink("unchecked_path_join", m.index ?? 0, m[0], pp.msg, "medium");
		}
	}

	const outboundPatterns: Array<{ re: RegExp; msg: string }> = [
		{ re: /\b(?:restTemplate\.(?:getForObject|getForEntity|postForObject|exchange)|HttpRequest\.newBuilder|URI\.create|new\s+URL)\s*\(([^)]+)\)/g, msg: "Java 动态 URL 出站 HTTP 请求" },
		{ re: /\b(?:curl_init|Http::get|Http::post)\s*\(\s*([^)]*\$[^)]*)\)/g, msg: "PHP 动态 URL 出站请求" },
		{ re: /\b(?:reqwest::get|client\.(?:get|post))\s*\(([^)]+)\)/g, msg: "Rust 动态出站 HTTP 请求" },
		{ re: /\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post|request)|http\.Get|http\.NewRequest)\s*\(([^)]+)\)/g, msg: "动态目标 URL 出站请求" },
	];
	for (const op of outboundPatterns) {
		for (const m of bodyClean.matchAll(op.re)) {
			if (!/^['"`](?:\/|https?:\/\/[^'"`$#{]+)['"`]$/.test((m[1] ?? "").trim())) pushSink("dynamic_outbound_url", m.index ?? 0, m[0], op.msg, "high");
		}
	}

	const rustMode = lang === "rust";
	const skipKw = new Set(["if", "for", "while", "switch", "catch", "return", "sizeof", "isset", "empty", "array", "vec", "Some", "Ok", "Err", "println", "format", "String", "Number", "Boolean", "Promise"]);
	const callRe = /(?:\$this->([A-Za-z_][A-Za-z0-9_]*)->([A-Za-z_][A-Za-z0-9_]*)|(?:\bthis\.)?([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:\.|::|->)\s*([A-Za-z_$][A-Za-z0-9_$]*)|\b([A-Za-z_][A-Za-z0-9_]*))\s*\(/g;
	for (const m of bodyClean.matchAll(callRe)) {
		const relIdx = m.index ?? 0;
		const openParen = relIdx + m[0].length - 1;
		// bodyClean 与 bodyRaw 严格保持 1:1 长度零偏移对齐
		const bal = extractBalanced(bodyRaw, openParen, "(", ")", 2400, rustMode);
		if (!bal) continue;
		const calleeObject = m[1] ?? m[3] ?? undefined;
		const calleeMethod = m[2] ?? m[4] ?? m[5] ?? "";
		if (!calleeMethod || skipKw.has(calleeMethod)) continue;
		const line = offsetToLine(lineStarts, bodyStartOffset + relIdx);
		calls.push({
			...(calleeObject ? { calleeObject } : {}),
			calleeMethod,
			argExprs: splitTopLevelCommas(bal.inner, rustMode),
			line,
			anchor: `${file}:${line}`,
		});
	}

	return { sinks, calls, paramAliases };
}

function extractStringLiterals(src: string): string[] {
	const out: string[] = [];
	for (const m of src.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'/g)) {
		const val = (m[1] ?? m[2] ?? "").trim();
		if (val) out.push(val);
	}
	return out;
}

// ==================== 1. Java / Spring Boot + MyBatis 解析器 ====================

function parseJavaAndSpringFile(lf: LoadedRgsFile, routesOut: RawRouteDraft[], guardsOut: RgsGuardNode[], servicesOut: RgsServiceNode[], sinksOut: RgsSinkNode[]): void {
	const { file, raw, clean, lineStarts } = lf;
	if (lf.isXmlMapper) {
		const nsMatch = /<mapper\b[^>]*\bnamespace\s*=\s*["']([^"']+)["']/i.exec(raw);
		if (!nsMatch?.[1]) return;
		const shortClass = nsMatch[1].trim().split(".").pop()!;
		for (const m of raw.matchAll(/<(select|insert|update|delete)\b[^>]*\bid\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/\1>/gi)) {
			const methodId = m[2]!.trim(), sqlBody = m[3] ?? "", bodyOffsetInMatch = Math.max(0, m[0].indexOf(sqlBody));
			const stmtLine = offsetToLine(lineStarts, m.index ?? 0), localSinks: RgsSinkNode[] = [], params: string[] = [];
			for (const interp of sqlBody.matchAll(/\$\{\s*([A-Za-z0-9_.]+)\s*\}/g)) {
				const paramName = interp[1]!.split(".")[0]!;
				if (!params.includes(paramName)) params.push(paramName);
				const sinkLine = offsetToLine(lineStarts, (m.index ?? 0) + bodyOffsetInMatch + (interp.index ?? 0));
				const sinkNode: RgsSinkNode = {
					id: `sink-${sha256Short(`${file}:${sinkLine}:${methodId}`)}`, kind: "unparameterized_sql", severity: "high",
					language: "java", framework: "spring-boot", file, line: sinkLine, anchor: `${file}:${sinkLine}`,
					snippet: lineSnippet(raw, lineStarts, sinkLine), enclosingSymbol: shortClass, enclosingMethod: methodId,
					taintedExprs: [paramName], message: `MyBatis XML Mapper (${shortClass}.${methodId}) 使用非参数化 \${${interp[1]}} 拼接 SQL`,
				};
				localSinks.push(sinkNode); sinksOut.push(sinkNode);
			}
			const effParams = params.length > 0 ? params : ["arg0"];
			servicesOut.push({
				id: `svc-${sha256Short(`${file}:${shortClass}.${methodId}`)}`, language: "java", className: shortClass,
				methodName: methodId, qualifiedName: `${shortClass}.${methodId}`, role: "repository", file, line: stmtLine,
				anchor: `${file}:${stmtLine}`, params: effParams, fieldTypes: {}, imports: {}, calls: [], localSinks,
				paramToLocalAliases: Object.fromEntries(effParams.map((p) => [p, [p]])),
			});
		}
		return;
	}

	const imports: Record<string, string> = {};
	for (const im of clean.matchAll(/\bimport\s+([A-Za-z0-9_.]+)\.([A-Za-z0-9_]+)\s*;/g)) {
		imports[im[2]!] = `${im[1]}.${im[2]}`;
	}

	if (/\b(?:SecurityFilterChain|HttpSecurity|WebSecurityCustomizer)\b/.test(clean)) {
		const orderedRules: RgsGuardRule[] = [];
		let orderSeq = 0;
		for (const ig of clean.matchAll(/\.ignoring\s*\(\s*\)\s*\.\s*(?:requestMatchers|antMatchers)\s*\(([^)]+)\)/g)) {
			for (const pat of extractStringLiterals(ig[1] ?? "")) orderedRules.push({ pattern: pat, effect: "permit_all", guardName: "WebSecurityCustomizer.ignoring", order: orderSeq++ });
		}
		const matcherRuleRe = /\.(?:requestMatchers|antMatchers|mvcMatchers)\s*\(([^)]+)\)\s*\.\s*(permitAll|anonymous|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|access)\s*\(([^)]*)\)/g;
		for (const mr of clean.matchAll(matcherRuleRe)) {
			const rawParts = splitTopLevelCommas(mr[1] ?? "");
			let httpMethod: string | undefined;
			let pathParts = rawParts;
			if (rawParts.length >= 1) {
				const mEnum = /\bHttpMethod\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/.exec(rawParts[0]!);
				const mStr = rawParts.length >= 2 ? /^['"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['"]$/i.exec(rawParts[0]!.trim()) : null;
				if (mEnum) { httpMethod = mEnum[1]!.toUpperCase(); pathParts = rawParts.slice(1); }
				else if (mStr) { httpMethod = mStr[1]!.toUpperCase(); pathParts = rawParts.slice(1); }
			}
			const pats = pathParts.length > 0 ? extractStringLiterals(pathParts.join(",")) : ["/**"];
			const action = mr[2]!, actionArg = (mr[3] ?? "").trim();
			const isPermit = action === "permitAll" || action === "anonymous" || (action === "access" && /permitAll/i.test(actionArg));
			for (const pat of pats) {
				orderedRules.push({
					pattern: pat, ...(httpMethod ? { httpMethod } : {}),
					effect: isPermit ? "permit_all" : "authenticated",
					guardName: isPermit ? `SecurityFilterChain:${action}` : `SecurityFilterChain:${action}(${actionArg})`,
					order: orderSeq++,
				});
			}
		}
		for (const ar of clean.matchAll(/\.anyRequest\s*\(\s*\)\s*\.\s*(authenticated|permitAll|hasRole|hasAuthority)\s*\(([^)]*)\)/g)) {
			const isPermit = ar[1] === "permitAll";
			orderedRules.push({ pattern: "/**", effect: isPermit ? "permit_all" : "authenticated", guardName: isPermit ? "SecurityFilterChain:anyRequest.permitAll" : `SecurityFilterChain:anyRequest.${ar[1]}`, order: orderSeq++ });
		}
		if (orderedRules.length > 0) {
			const chainLine = offsetToLine(lineStarts, clean.search(/\b(?:SecurityFilterChain|HttpSecurity)\b/));
			guardsOut.push({
				id: `guard-${sha256Short(`${file}:${chainLine}:spring-security`)}`,
				name: "SpringSecurityFilterChain", kind: "global_filter", language: "java", framework: "spring-boot",
				file, line: chainLine, anchor: `${file}:${chainLine}`,
				pathPatterns: orderedRules.filter((r) => r.effect === "authenticated").map((r) => r.pattern),
				exemptPatterns: orderedRules.filter((r) => r.effect === "permit_all").map((r) => r.pattern),
				orderedRules,
			});
		}
	}

	if (/\baddInterceptors\b/.test(clean) && /\baddInterceptor\b/.test(clean)) {
		for (const rm of clean.matchAll(/\.addInterceptor\s*\(\s*([^)]+)\s*\)([\s\S]{0,600}?);/g)) {
			const interceptorExpr = rm[1]!.trim();
			if (!AUTH_GUARD_TOKEN_RE.test(interceptorExpr)) continue;
			const tail = rm[2] ?? "";
			const addPats = [...tail.matchAll(/\.addPathPatterns\s*\(([^)]+)\)/g)].flatMap((m) => extractStringLiterals(m[1] ?? ""));
			const excPats = [...tail.matchAll(/\.excludePathPatterns\s*\(([^)]+)\)/g)].flatMap((m) => extractStringLiterals(m[1] ?? ""));
			const line = offsetToLine(lineStarts, rm.index ?? 0);
			guardsOut.push({
				id: `guard-${sha256Short(`${file}:${line}:${interceptorExpr}`)}`,
				name: `SpringInterceptor(${interceptorExpr.replace(/\s+/g, "")})`, kind: "prefix_interceptor",
				language: "java", framework: "spring-boot", file, line, anchor: `${file}:${line}`,
				pathPatterns: addPats.length > 0 ? addPats : ["/**"], exemptPatterns: excPats,
			});
		}
	}

	const classRe = /((?:@[A-Za-z0-9_.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?\s*)*)\b(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+)*(class|interface)\s+([A-Za-z0-9_]+)[^{]*\{/g;
	for (const cm of clean.matchAll(classRe)) {
		const classAnnsClean = clean.slice(cm.index ?? 0, (cm.index ?? 0) + (cm[1]?.length ?? 0));
		const kindWord = cm[2]!;
		const className = cm[3]!;
		const openBraceIdx = (cm.index ?? 0) + cm[0].length - 1;
		const classBodyBal = extractBalanced(clean, openBraceIdx, "{", "}", 120000);
		if (!classBodyBal) continue;
		const classBodyRaw = raw.slice(openBraceIdx + 1, classBodyBal.endIdx);
		const classBodyClean = classBodyBal.inner;
		const classBodyOffset = openBraceIdx + 1;
		const isController = /@(?:RestController|Controller)\b/.test(classAnnsClean);
		const classBasePaths = extractSpringMappingPaths(classAnnsClean, "RequestMapping");
		const classGuardInfo = extractJavaAuthAnnotations(classAnnsClean);
		const fieldTypes: Record<string, string> = {};
		for (const fm of classBodyClean.matchAll(/\b(?:private|protected|public)\s+(?:final\s+)?([A-Za-z0-9_]+)(?:<[^>]+>)?\s+([A-Za-z0-9_]+)\s*;/g)) fieldTypes[fm[2]!] = fm[1]!;
		const role: RgsServiceNode["role"] = isController ? "controller" : /@(?:Repository|Mapper)\b|(?:Repository|Mapper|Dao)$/.test(classAnnsClean + className) ? "repository" : "service";

		const methodRe = /((?:@[A-Za-z0-9_.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?\s*)+|(?:public|protected|private)[ \t]+)(?:(?:public|protected|private|static|final|synchronized|default)[ \t]+)*[A-Za-z0-9_<>,?[\] \t]+[ \t]+([A-Za-z0-9_]+)\s*\(((?:[^()]|\([^()]*\))*)\)\s*(?:throws\s+[A-Za-z0-9_.,\s]+)?(\{|;)/g;
		for (const mm of classBodyClean.matchAll(methodRe)) {
			const methodName = mm[2]!;
			if (methodName === className || methodName === "if" || methodName === "for") continue;
			const methodStartInFile = classBodyOffset + (mm.index ?? 0);
			const methodAnnsClean = clean.slice(methodStartInFile, methodStartInFile + (mm[1]?.length ?? 0));
			const paramsClean = mm[3] ?? "";
			const terminator = mm[4]!;
			const methodLine = offsetToLine(lineStarts, methodStartInFile);
			const parsedParams = parseJavaMethodParams(paramsClean);

			let methodBodyClean = "";
			let methodBodyRaw = "";
			let bodyAbsOffset = methodStartInFile;
			if (terminator === "{") {
				const braceInClass = (mm.index ?? 0) + mm[0].length - 1;
				const mBal = extractBalanced(classBodyClean, braceInClass, "{", "}", 24000);
				if (mBal) {
					methodBodyClean = mBal.inner;
					methodBodyRaw = classBodyRaw.slice(braceInClass + 1, mBal.endIdx);
					bodyAbsOffset = classBodyOffset + braceInClass + 1;
				}
			}

			const scanned = scanBodyForSinksAndCalls({
				rawFileContent: raw, bodyClean: methodBodyClean, bodyRaw: methodBodyRaw,
				bodyStartOffset: bodyAbsOffset, lineStarts, file, lang: "java", framework: "spring-boot",
				enclosingSymbol: className, enclosingMethod: methodName, knownParams: parsedParams.allNames,
			});

			for (const annSql of methodAnnsClean.matchAll(/@(?:Select|Update|Delete|Insert)\s*\(\s*["'][^"']*\$\{([^}]+)\}[^"']*["']\s*\)/g)) {
				const tParam = annSql[1]!.split(".")[0]!;
				const annLine = offsetToLine(lineStarts, methodStartInFile + (annSql.index ?? 0));
				scanned.sinks.push({
					id: `sink-${sha256Short(`${file}:${annLine}:${methodName}`)}`,
					kind: "unparameterized_sql", severity: "high", language: "java", framework: "spring-boot",
					file, line: annLine, anchor: `${file}:${annLine}`, snippet: lineSnippet(raw, lineStarts, annLine),
					enclosingSymbol: className, enclosingMethod: methodName,
					taintedExprs: [tParam], message: "MyBatis 注解 SQL 使用非参数化 ${...} 动态插值",
				});
			}

			for (const sk of scanned.sinks) sinksOut.push(sk);
			servicesOut.push({
				id: `svc-${sha256Short(`${file}:${className}.${methodName}:${methodLine}`)}`,
				language: "java", className, methodName, qualifiedName: `${className}.${methodName}`,
				role, file, line: methodLine, anchor: `${file}:${methodLine}`,
				params: parsedParams.allNames, fieldTypes, imports, calls: scanned.calls,
				localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
			});

			if (isController && kindWord === "class") {
				const mappings = extractSpringMethodMappings(methodAnnsClean);
				if (mappings.length > 0) {
					const methodGuardInfo = extractJavaAuthAnnotations(methodAnnsClean);
					const directGuards = [...classGuardInfo.guards, ...methodGuardInfo.guards];
					const isExplicitlyPublic = methodGuardInfo.explicitPublic || (classGuardInfo.explicitPublic && methodGuardInfo.guards.length === 0);
					const baseList = classBasePaths.length > 0 ? classBasePaths : ["/"];
					for (const baseP of baseList) {
						for (const mp of mappings) {
							routesOut.push({
								method: mp.method, localPath: joinRoutePaths(baseP, mp.path),
								controllerClass: className, handlerName: `${className}.${methodName}`,
								language: "java", framework: "spring-boot", file, line: methodLine,
								sourceParams: parsedParams.webInputNames.length > 0 ? parsedParams.webInputNames : parsedParams.allNames,
								directGuards, isExplicitlyPublic,
							});
						}
					}
				}
			}
		}
	}
}

function extractSpringMappingPaths(annsText: string, annName: string): string[] {
	const paths: string[] = [];
	for (const m of annsText.matchAll(new RegExp(`@${annName}\\s*(?:\\(([^)]*)\\))?`, "g"))) {
		const args = (m[1] ?? "").trim();
		if (!args) { paths.push("/"); continue; }
		const kvMatch = /\b(?:value|path)\s*=\s*(\{[^}]*\}|"[^"]*")/.exec(args);
		const lits = extractStringLiterals(kvMatch ? kvMatch[1]! : args);
		paths.push(...(lits.length > 0 ? lits : ["/"]));
	}
	return paths;
}

function extractSpringMethodMappings(annsText: string): Array<{ method: string; path: string }> {
	const results: Array<{ method: string; path: string }> = [];
	for (const [ann, httpMethod] of [["GetMapping", "GET"], ["PostMapping", "POST"], ["PutMapping", "PUT"], ["PatchMapping", "PATCH"], ["DeleteMapping", "DELETE"]] as const) {
		if (new RegExp(`@${ann}\\b`).test(annsText)) {
			for (const p of extractSpringMappingPaths(annsText, ann)) results.push({ method: httpMethod, path: p });
		}
	}
	if (/@RequestMapping\b/.test(annsText)) {
		const httpMethod = /RequestMethod\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)/.exec(annsText)?.[1] ?? "GET";
		for (const p of extractSpringMappingPaths(annsText, "RequestMapping")) results.push({ method: httpMethod, path: p });
	}
	return results;
}

function extractJavaAuthAnnotations(annsText: string): { guards: string[]; explicitPublic: boolean } {
	const guards: string[] = [];
	let explicitPublic = /@(?:PermitAll|AllowAnonymous)\b/.test(annsText);
	for (const pm of annsText.matchAll(/@PreAuthorize\s*\(\s*"([^"]*)"\s*\)/g)) {
		const expr = pm[1]!.trim();
		if (/^(?:permitAll|isAnonymous)\s*\(\s*\)$/i.test(expr)) explicitPublic = true;
		else guards.push(`@PreAuthorize(${expr})`);
	}
	for (const sm of annsText.matchAll(/@(?:Secured|RolesAllowed)\s*\(([^)]+)\)/g)) {
		guards.push(`@Secured(${sm[1]!.trim()})`);
	}
	return { guards, explicitPublic };
}

function parseJavaMethodParams(paramsRaw: string): { allNames: string[]; webInputNames: string[] } {
	const allNames: string[] = [], webInputNames: string[] = [];
	for (const seg of splitTopLevelCommas(paramsRaw)) {
		const stripped = seg.replace(/@[A-Za-z0-9_.]+(?:\s*\([^)]*\))?\s*/g, " ").trim();
		const tokens = stripped.split(/\s+/).filter(Boolean);
		const paramName = tokens[tokens.length - 1]?.replace(/\[\]$/, "");
		if (!paramName || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(paramName)) continue;
		if (/\b(?:Model|HttpServletResponse|BindingResult|Principal|Authentication)\b/.test(stripped)) continue;
		allNames.push(paramName);
		if (/@(?:RequestParam|PathVariable|RequestBody|RequestHeader|ModelAttribute)\b/.test(seg) || /\bHttpServletRequest\b/.test(stripped)) webInputNames.push(paramName);
	}
	return { allNames, webInputNames };
}

// ==================== 2. PHP（Laravel / Symfony / 原生）解析器 ====================

function parsePhpFile(lf: LoadedRgsFile, routesOut: RawRouteDraft[], mountsOut: RawCrossMountEdge[], servicesOut: RgsServiceNode[], sinksOut: RgsSinkNode[]): void {
	const { file, raw, clean, lineStarts } = lf;
	const imports: Record<string, string> = {};
	for (const um of clean.matchAll(/\buse\s+([A-Za-z0-9_\\]+)(?:\s+as\s+([A-Za-z0-9_]+))?\s*;/g)) imports[um[2] ?? um[1]!.split("\\").pop()!] = um[1]!;
	const isLaravel = /\bRoute::/.test(clean) || /\bIlluminate\\/.test(clean);
	const isSymfony = /#\[Route\s*\(/.test(clean) || /\bSymfony\\Component\\Routing/.test(clean);
	const framework: RgsFramework = isLaravel ? "laravel" : isSymfony ? "symfony" : "php-native";
	if (/\bRoute::/.test(clean)) parseLaravelRoutesBlock(clean, 0, "", [], file, lineStarts, routesOut, mountsOut);

	const classRe = /((?:#\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*)\bclass\s+([A-Za-z0-9_]+)[^{]*\{/g;
	let hasClass = false;
	for (const cm of clean.matchAll(classRe)) {
		hasClass = true;
		const classAttrs = clean.slice(cm.index ?? 0, (cm.index ?? 0) + (cm[1]?.length ?? 0));
		const className = cm[2]!;
		const openBrace = (cm.index ?? 0) + cm[0].length - 1;
		const cBal = extractBalanced(clean, openBrace, "{", "}", 80000);
		if (!cBal) continue;
		const cBodyClean = cBal.inner;
		const cBodyRaw = raw.slice(openBrace + 1, cBal.endIdx);
		const cOffset = openBrace + 1;

		const symClassPrefix = extractSymfonyRouteAttr(classAttrs)?.path ?? "";
		const symClassGuards = extractSymfonyGuards(classAttrs);
		const fieldTypes: Record<string, string> = {};
		for (const pm of cBodyClean.matchAll(/\b(?:private|protected|public)\s+(?:readonly\s+)?\??([A-Za-z0-9_\\]+)\s+\$([A-Za-z0-9_]+)/g)) {
			fieldTypes[pm[2]!] = pm[1]!.split("\\").pop()!;
		}

		const fnRe = /((?:#\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*)\b(?:public|protected|private)?\s*function\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)[^{]*\{/g;
		for (const fm of cBodyClean.matchAll(fnRe)) {
			const fnAttrs = cBodyClean.slice(fm.index ?? 0, (fm.index ?? 0) + (fm[1]?.length ?? 0));
			const fnName = fm[2]!;
			const fnParamsClean = fm[3] ?? "";
			const fnBrace = (fm.index ?? 0) + fm[0].length - 1;
			const fnBal = extractBalanced(cBodyClean, fnBrace, "{", "}", 24000);
			if (!fnBal) continue;
			const fnLine = offsetToLine(lineStarts, cOffset + (fm.index ?? 0));

			if (fnName === "__construct") {
				for (const cp of splitTopLevelCommas(fnParamsClean)) {
					const m = /([A-Za-z0-9_\\]+)\s+\$([A-Za-z0-9_]+)/.exec(cp);
					if (m) fieldTypes[m[2]!] = m[1]!.split("\\").pop()!;
				}
			}
			const paramNames = splitTopLevelCommas(fnParamsClean)
				.map((cp) => /\$([A-Za-z0-9_]+)/.exec(cp)?.[1])
				.filter((s): s is string => Boolean(s))
				.map((s) => `$${s}`);

			const scanned = scanBodyForSinksAndCalls({
				rawFileContent: raw, bodyClean: fnBal.inner, bodyRaw: cBodyRaw.slice(fnBrace + 1, fnBal.endIdx),
				bodyStartOffset: cOffset + fnBrace + 1, lineStarts, file, lang: "php", framework,
				enclosingSymbol: className, enclosingMethod: fnName, knownParams: paramNames,
			});
			for (const sk of scanned.sinks) sinksOut.push(sk);

			servicesOut.push({
				id: `svc-${sha256Short(`${file}:${className}.${fnName}:${fnLine}`)}`,
				language: "php", className, methodName: fnName, qualifiedName: `${className}.${fnName}`,
				role: /Controller$/i.test(className) ? "controller" : "service",
				file, line: fnLine, anchor: `${file}:${fnLine}`, params: paramNames, fieldTypes, imports,
				calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
			});

			const symRoute = extractSymfonyRouteAttr(fnAttrs);
			if (symRoute) {
				const fnGuards = [...symClassGuards, ...extractSymfonyGuards(fnAttrs)];
				for (const mth of symRoute.methods) {
					routesOut.push({
						method: mth, localPath: joinRoutePaths(symClassPrefix, symRoute.path),
						controllerClass: className, handlerName: `${className}.${fnName}`,
						language: "php", framework: "symfony", file, line: fnLine,
						sourceParams: paramNames, directGuards: fnGuards, isExplicitlyPublic: EXPLICIT_PERMIT_ALL_RE.test(fnAttrs),
					});
				}
			}
		}
	}

	if (!hasClass && !isLaravel && /\$_(?:GET|POST|REQUEST|COOKIE)\b/.test(clean)) {
		const scriptSym = basename(file, extname(file));
		const scanned = scanBodyForSinksAndCalls({
			rawFileContent: raw, bodyClean: clean, bodyRaw: raw, bodyStartOffset: 0,
			lineStarts, file, lang: "php", framework: "php-native",
			enclosingSymbol: scriptSym, enclosingMethod: "main", knownParams: [],
		});
		for (const sk of scanned.sinks) sinksOut.push(sk);
		const hasSessionGuard = /\b(?:isset\s*\(\s*\$_SESSION\s*\[\s*['"](?:user|uid|admin|auth|role)|check_auth|require_login)\b/i.test(clean);
		servicesOut.push({
			id: `svc-${sha256Short(`${file}:main`)}`,
			language: "php", className: scriptSym, methodName: "main", qualifiedName: `${scriptSym}.main`,
			role: "handler", file, line: 1, anchor: `${file}:1`,
			params: Object.keys(scanned.paramAliases), fieldTypes: {}, imports,
			calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
		});
		routesOut.push({
			method: /\$_POST\b/.test(clean) && !/\$_GET\b/.test(clean) ? "POST" : "GET",
			localPath: `/${file.replace(/^public\//, "")}`,
			controllerClass: scriptSym, handlerName: `${scriptSym}.main`,
			language: "php", framework: "php-native", file, line: 1,
			sourceParams: Object.keys(scanned.paramAliases),
			directGuards: hasSessionGuard ? ["php_session_check"] : [], isExplicitlyPublic: false,
		});
	}
}

function parseLaravelRoutesBlock(
	blockClean: string,
	baseOffset: number,
	inheritedPrefix: string,
	inheritedGuards: string[],
	file: string,
	lineStarts: number[],
	routesOut: RawRouteDraft[],
	mountsOut: RawCrossMountEdge[],
): void {
	const groupRanges: Array<[number, number]> = [];
	for (const gm of blockClean.matchAll(/\bRoute::(?:middleware|prefix|group|name|domain)\b/g)) {
		const startIdx = gm.index ?? 0;
		if (groupRanges.some(([s, e]) => startIdx >= s && startIdx < e)) continue;
		const windowSlice = blockClean.slice(startIdx, Math.min(blockClean.length, startIdx + 500));
		const grpCallMatch = /(?:::|->)\s*group\s*\(/.exec(windowSlice);
		if (!grpCallMatch) continue;
		const headerClean = blockClean.slice(startIdx, startIdx + grpCallMatch.index);
		if (headerClean.includes(";")) continue;

		const openParen = startIdx + grpCallMatch.index + grpCallMatch[0].length - 1;
		const gBal = extractBalanced(blockClean, openParen, "(", ")", 50000);
		if (!gBal) continue;
		groupRanges.push([startIdx, gBal.endIdx + 1]);

		const braceIdx = gBal.inner.indexOf("{");
		const groupArgsHead = braceIdx >= 0 ? blockClean.slice(openParen, openParen + 1 + braceIdx) : blockClean.slice(openParen, gBal.endIdx + 1);
		const fullGroupHeader = `${headerClean}${groupArgsHead}`;
		let nextPrefix = inheritedPrefix;
		const nextGuards = [...inheritedGuards];

		for (const pm of fullGroupHeader.matchAll(/prefix\s*(?:\(\s*['"]([^'"]+)['"]\s*\)|['"]\s*=>\s*['"]([^'"]+)['"])/g)) {
			nextPrefix = joinRoutePaths(nextPrefix, pm[1] ?? pm[2] ?? "");
		}
		for (const mm of fullGroupHeader.matchAll(/middleware\s*(?:\(([^)]+)\)|['"]\s*=>\s*(\[[^\]]+\]|['"][^'"]+['"]))/g)) {
			for (const tok of extractStringLiterals(mm[1] ?? mm[2] ?? "")) {
				if (AUTH_GUARD_TOKEN_RE.test(tok) || /^auth(?::|$)/i.test(tok)) nextGuards.push(`laravel:${tok}`);
			}
		}

		const baseFileMatch = /base_path\s*\(\s*['"]([^'"]+)['"]\s*\)/.exec(gBal.inner);
		if (baseFileMatch?.[1]) {
			mountsOut.push({
				parentFile: file, targetModuleRel: normalizeRelPath(baseFileMatch[1]),
				prefix: nextPrefix || "/", guards: nextGuards, exempts: [],
				framework: "laravel", language: "php", line: offsetToLine(lineStarts, baseOffset + startIdx),
			});
			continue;
		}
		if (braceIdx >= 0) {
			const innerBraceBal = extractBalanced(gBal.inner, braceIdx, "{", "}", 50000);
			if (innerBraceBal) {
				parseLaravelRoutesBlock(
					innerBraceBal.inner,
					baseOffset + openParen + 1 + braceIdx + 1,
					nextPrefix, nextGuards, file, lineStarts, routesOut, mountsOut,
				);
			}
		}
	}

	for (const rm of blockClean.matchAll(/\bRoute::(get|post|put|patch|delete|any)\s*\(/gi)) {
		const rIdx = rm.index ?? 0;
		if (groupRanges.some(([s, e]) => rIdx >= s && rIdx < e)) continue;
		const method = rm[1]!.toUpperCase() === "ANY" ? "GET" : rm[1]!.toUpperCase();
		const openParen = rIdx + rm[0].length - 1;
		const rBal = extractBalanced(blockClean, openParen, "(", ")", 4000);
		if (!rBal) continue;
		const afterTail = blockClean.slice(rBal.endIdx + 1, Math.min(blockClean.length, rBal.endIdx + 240)).split(";")[0] ?? "";
		const args = splitTopLevelCommas(rBal.inner);
		const pathLit = extractStringLiterals(args[0] ?? "")[0];
		if (!pathLit) continue;

		let guards = [...inheritedGuards];
		let explicitPublic = false;
		for (const mm of afterTail.matchAll(/->middleware\s*\(([^)]+)\)/g)) {
			for (const tok of extractStringLiterals(mm[1] ?? "")) {
				if (AUTH_GUARD_TOKEN_RE.test(tok) || /^auth(?::|$)/i.test(tok)) guards.push(`laravel:${tok}`);
			}
		}
		const wmMatch = /->withoutMiddleware\s*\(([^)]*)\)/.exec(afterTail);
		if (wmMatch) {
			const wmInner = (wmMatch[1] ?? "").trim();
			if (!wmInner) {
				guards = []; explicitPublic = true;
			} else {
				const removedTokens = [
					...extractStringLiterals(wmInner),
					...[...wmInner.matchAll(/([A-Za-z0-9_]+)::class/g)].map((m) => m[1]!),
				];
				const removedAuth = removedTokens.filter((t) => AUTH_GUARD_TOKEN_RE.test(t) || /^auth(?::|$)/i.test(t) || /^Authenticate$/i.test(t));
				if (removedAuth.length > 0) {
					guards = guards.filter((g) => !removedAuth.some((rem) => g.toLowerCase().includes(rem.toLowerCase()) || (/^Authenticate$/i.test(rem) && g.startsWith("laravel:auth"))));
					if (guards.length === 0) explicitPublic = true;
				}
			}
		}
		let controllerClass: string | undefined;
		let handlerName: string | undefined;
		const handlerArg = args[1] ?? "";
		const arrCtrl = /([A-Za-z0-9_\\]+)::class\s*,\s*['"]([A-Za-z0-9_]+)['"]/.exec(handlerArg);
		const strCtrl = /['"]([A-Za-z0-9_\\]+)@([A-Za-z0-9_]+)['"]/.exec(handlerArg);
		if (arrCtrl) { controllerClass = arrCtrl[1]!.split("\\").pop()!; handlerName = `${controllerClass}.${arrCtrl[2]!}`; }
		else if (strCtrl) { controllerClass = strCtrl[1]!.split("\\").pop()!; handlerName = `${controllerClass}.${strCtrl[2]!}`; }

		routesOut.push({
			method, localPath: joinRoutePaths(inheritedPrefix, pathLit),
			...(controllerClass ? { controllerClass } : {}), ...(handlerName ? { handlerName } : {}),
			language: "php", framework: "laravel", file, line: offsetToLine(lineStarts, baseOffset + rIdx),
			sourceParams: [...pathLit.matchAll(/\{([A-Za-z0-9_]+)\??\}/g)].map((m) => `$${m[1]}`),
			directGuards: guards, isExplicitlyPublic: explicitPublic,
		});
	}
}

function extractSymfonyRouteAttr(attrs: string): { path: string; methods: string[] } | null {
	const m = /#\[Route\s*\(((?:[^()[\]]|\[[^\]]*\])*)\)\]/.exec(attrs);
	if (!m) return null;
	const inner = m[1] ?? "";
	const routePath = /\bpath\s*:\s*['"]([^'"]+)['"]/.exec(inner)?.[1] ?? extractStringLiterals(inner.split(",")[0] ?? "")[0];
	if (!routePath) return null;
	const methodsMatch = /\bmethods\s*:\s*\[([^\]]*)\]/.exec(inner);
	const methods = methodsMatch ? extractStringLiterals(methodsMatch[1]!).map((s) => s.toUpperCase()) : ["GET"];
	return { path: routePath, methods: methods.length > 0 ? methods : ["GET"] };
}

function extractSymfonyGuards(attrs: string): string[] {
	const out: string[] = [];
	for (const m of attrs.matchAll(/#\[(?:IsGranted|Security)\s*\(((?:[^()[\]]|\[[^\]]*\])+)\)\]/g)) {
		if (!/PUBLIC_ACCESS/i.test(m[1]!)) out.push(`#[IsGranted(${m[1]!.trim()})]`);
	}
	return out;
}

// ==================== 3. Rust（Actix-web / Axum）解析器 ====================

function parseRustFile(lf: LoadedRgsFile, routesOut: RawRouteDraft[], mountsOut: RawCrossMountEdge[], servicesOut: RgsServiceNode[], sinksOut: RgsSinkNode[]): void {
	const { file, raw, clean, lineStarts } = lf;
	const framework: RgsFramework = /\baxum\b|\bRouter::new\s*\(/.test(clean) ? "axum" : "actix-web";
	const imports: Record<string, string> = {};
	for (const um of clean.matchAll(/\buse\s+(?:crate::)?([A-Za-z0-9_:]+)\s*;/g)) imports[um[1]!.split("::").pop()!] = um[1]!;

	const fnRe = /((?:#\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*)\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*(?:<[^>]*>)?\s*\(((?:[^()]|\([^()]*\))*)\)(?:\s*->\s*[^{]+)?\{/g;
	for (const fm of clean.matchAll(fnRe)) {
		const attrsClean = clean.slice(fm.index ?? 0, (fm.index ?? 0) + (fm[1]?.length ?? 0));
		const fnName = fm[2]!, paramsClean = fm[3] ?? "";
		const openBrace = (fm.index ?? 0) + fm[0].length - 1;
		const fBal = extractBalanced(clean, openBrace, "{", "}", 40000, true);
		if (!fBal) continue;
		const fnLine = offsetToLine(lineStarts, fm.index ?? 0);

		const paramInfo = parseRustFnParams(paramsClean);
		const scanned = scanBodyForSinksAndCalls({
			rawFileContent: raw, bodyClean: fBal.inner, bodyRaw: raw.slice(openBrace + 1, fBal.endIdx),
			bodyStartOffset: openBrace + 1, lineStarts, file, lang: "rust", framework,
			enclosingSymbol: basename(file, ".rs"), enclosingMethod: fnName, knownParams: paramInfo.params,
		});
		for (const sk of scanned.sinks) sinksOut.push(sk);

		servicesOut.push({
			id: `svc-${sha256Short(`${file}:${fnName}:${fnLine}`)}`,
			language: "rust", className: basename(file, ".rs"), methodName: fnName, qualifiedName: fnName,
			role: "handler", file, line: fnLine, anchor: `${file}:${fnLine}`,
			params: paramInfo.params, fieldTypes: {}, imports,
			calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
		});

		const actixMacro = /#\[(get|post|put|patch|delete)\s*\(([^)]+)\)\]/i.exec(attrsClean);
		if (actixMacro) {
			const routePath = extractStringLiterals(actixMacro[2]!)[0];
			if (routePath) {
				const guards = [...paramInfo.extractorGuards];
				const wrapMatch = /\bwrap\s*=\s*"([^"]+)"/.exec(actixMacro[2]!);
				if (wrapMatch?.[1] && AUTH_GUARD_TOKEN_RE.test(wrapMatch[1])) guards.push(`actix:wrap(${wrapMatch[1]})`);
				routesOut.push({
					method: actixMacro[1]!.toUpperCase(), localPath: routePath, handlerName: fnName,
					language: "rust", framework: "actix-web", file, line: fnLine,
					sourceParams: paramInfo.params, directGuards: guards, isExplicitlyPublic: false,
				});
			}
		}
	}

	for (const sm of clean.matchAll(/\bweb::scope\s*\(\s*"([^"]+)"\s*\)/g)) {
		const scopePrefix = sm[1]!;
		const tailSlice = clean.slice(sm.index ?? 0, Math.min(clean.length, (sm.index ?? 0) + 1200));
		const scopeGuards = [...tailSlice.matchAll(/\.wrap\s*\(\s*([^)]+)\s*\)/g)]
			.filter((wm) => AUTH_GUARD_TOKEN_RE.test(wm[1]!))
			.map((wm) => `actix:wrap(${wm[1]!.trim()})`);
		for (const svcM of tailSlice.matchAll(/\.service\s*\(\s*([A-Za-z0-9_:]+)\s*\)/g)) {
			mountsOut.push({
				parentFile: file, targetSymbol: svcM[1]!.split("::").pop()!, prefix: scopePrefix,
				guards: scopeGuards, exempts: [], framework: "actix-web", language: "rust",
				line: offsetToLine(lineStarts, sm.index ?? 0),
			});
		}
		for (const rm of tailSlice.matchAll(/\.route\s*\(\s*"([^"]+)"\s*,\s*web::(get|post|put|patch|delete)\s*\(\s*\)\s*\.to\s*\(\s*([A-Za-z0-9_:]+)\s*\)/g)) {
			routesOut.push({
				method: rm[2]!.toUpperCase(), localPath: joinRoutePaths(scopePrefix, rm[1]!),
				handlerName: rm[3]!.split("::").pop()!, language: "rust", framework: "actix-web",
				file, line: offsetToLine(lineStarts, (sm.index ?? 0) + (rm.index ?? 0)),
				sourceParams: ["input"], directGuards: scopeGuards, isExplicitlyPublic: false,
			});
		}
	}

	for (const axm of clean.matchAll(/\bRouter::new\s*\(\s*\)/g)) {
		const startIdx = axm.index ?? 0;
		const stmtSlice = extractRustStatementChain(clean, startIdx);
		const pendingRoutes: RawRouteDraft[] = [];
		const pendingMounts: RawCrossMountEdge[] = [];

		for (const op of stmtSlice.matchAll(/\.(route|nest|layer|route_layer)\s*\(/g)) {
			const kind = op[1]!;
			const bal = extractBalanced(stmtSlice, (op.index ?? 0) + op[0].length - 1, "(", ")", 2000, true);
			if (!bal) continue;
			const opLine = offsetToLine(lineStarts, startIdx + (op.index ?? 0));
			const args = splitTopLevelCommas(bal.inner, true);
			if (kind === "route") {
				const pathStr = extractStringLiterals(args[0] ?? "")[0];
				if (pathStr) {
					for (const mc of (args[1] ?? "").matchAll(/\b(get|post|put|patch|delete)\s*\(\s*([A-Za-z0-9_:]+)\s*\)/g)) {
						const draft: RawRouteDraft = {
							method: mc[1]!.toUpperCase(), localPath: pathStr, handlerName: mc[2]!.split("::").pop()!,
							language: "rust", framework: "axum", file, line: opLine,
							sourceParams: ["input"], directGuards: [], isExplicitlyPublic: false,
						};
						pendingRoutes.push(draft);
						routesOut.push(draft);
					}
				}
			} else if (kind === "nest") {
				const nestPrefix = extractStringLiterals(args[0] ?? "")[0];
				const subSym = (args[1] ?? "").trim().replace(/\(\s*\)$/, "").split("::").pop()!;
				if (nestPrefix && subSym) {
					const mEdge: RawCrossMountEdge = {
						parentFile: file, targetSymbol: subSym, prefix: nestPrefix,
						guards: [], exempts: [], framework: "axum", language: "rust", line: opLine,
					};
					pendingMounts.push(mEdge);
					mountsOut.push(mEdge);
				}
			} else if ((kind === "layer" || kind === "route_layer") && AUTH_GUARD_TOKEN_RE.test(bal.inner)) {
				const gLabel = `axum:${kind}(${bal.inner.trim().slice(0, 48)})`;
				for (const pr of pendingRoutes) if (!pr.directGuards.includes(gLabel)) pr.directGuards.push(gLabel);
				for (const pm of pendingMounts) if (!pm.guards.includes(gLabel)) pm.guards.push(gLabel);
			}
		}
	}
}

function extractRustStatementChain(raw: string, startIdx: number): string {
	let depth = 0;
	const limit = Math.min(raw.length, startIdx + 6000);
	for (let i = startIdx; i < limit; i++) {
		const ch = raw[i]!;
		if (ch === "(" || ch === "{" || ch === "[") depth++;
		else if (ch === ")" || ch === "}" || ch === "]") { if (depth === 0) return raw.slice(startIdx, i); depth--; }
		else if (ch === ";" && depth === 0) return raw.slice(startIdx, i);
	}
	return raw.slice(startIdx, limit);
}

function parseRustFnParams(paramsRaw: string): { params: string[]; extractorGuards: string[] } {
	const params: string[] = [];
	const extractorGuards: string[] = [];
	for (const seg of splitTopLevelCommas(paramsRaw, true)) {
		const colonIdx = seg.indexOf(":");
		if (colonIdx < 0) continue;
		const patPart = seg.slice(0, colonIdx).trim();
		const typePart = seg.slice(colonIdx + 1).trim();
		if (AUTH_GUARD_TOKEN_RE.test(typePart) || /\b(?:AuthenticatedUser|Claims|AuthUser|AdminGuard)\b/.test(typePart)) extractorGuards.push(`rust-extractor:${typePart}`);
		const innerIdent = /(?:Path|Query|Json|Form)\s*\(\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\)/.exec(patPart)?.[1] ?? /([A-Za-z_][A-Za-z0-9_]*)$/.exec(patPart)?.[1];
		if (innerIdent && innerIdent !== "self") params.push(innerIdent);
	}
	return { params, extractorGuards };
}

// ==================== 4. TS/JS、Python、Go 跨文件 RGS 解析器 ====================

function parseJsTsPyGoFile(
	lf: LoadedRgsFile,
	routesOut: RawRouteDraft[],
	guardsOut: RgsGuardNode[],
	mountsOut: RawCrossMountEdge[],
	servicesOut: RgsServiceNode[],
	sinksOut: RgsSinkNode[],
): void {
	const { file, raw, clean, lang, lineStarts } = lf;

	if (lang === "typescript" || lang === "javascript") {
		const imports: Record<string, string> = {};
		for (const im of clean.matchAll(/\bimport\s+(?:\{\s*([^}]+)\s*\}|([A-Za-z_$][A-Za-z0-9_$]*))\s+from\s+['"]([^'"]+)['"]/g)) {
			const modSpec = im[3]!;
			const resolvedMod = modSpec.startsWith(".") ? resolveRelativeModulePath(file, modSpec) : modSpec;
			if (im[2]) imports[im[2]] = resolvedMod;
			if (im[1]) {
				for (const item of im[1].split(",")) {
					const parts = item.trim().split(/\s+as\s+/);
					const local = (parts[1] ?? parts[0] ?? "").trim();
					if (local) imports[local] = resolvedMod;
				}
			}
		}
		for (const reqM of clean.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
			imports[reqM[1]!] = reqM[2]!.startsWith(".") ? resolveRelativeModulePath(file, reqM[2]!) : reqM[2]!;
		}

		const defaultFw: RgsFramework = /\bfastify\b/i.test(clean)
			? "fastify" : /\bkoa-router|@koa\/router\b/i.test(clean) ? "koa" : "express";

		const nextAppMatch = /(?:^|\/)app\/(.*\/)?route\.(?:ts|tsx|js|jsx|mjs)$/.exec(file);
		if (nextAppMatch) {
			const segs = (nextAppMatch[1] ?? "").split("/").filter(Boolean)
				.filter((s) => !(s.startsWith("(") && s.endsWith(")")) && !s.startsWith("@"));
			const nextPath = segs.length === 0 ? "/" : `/${segs.join("/")}`;
			for (const em of clean.matchAll(/\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(([^)]*)\)\s*\{/g)) {
				const mth = em[1]!.toUpperCase();
				const openB = (em.index ?? 0) + em[0].length - 1;
				const bal = extractBalanced(clean, openB, "{", "}", 20000);
				const line = offsetToLine(lineStarts, em.index ?? 0);
				const bodyClean = bal?.inner ?? "";
				const bodyRaw = bal ? raw.slice(openB + 1, bal.endIdx) : "";
				const pName = em[2]?.trim().split(/[,\s:]/)[0] || "req";
				const scanned = scanBodyForSinksAndCalls({
					rawFileContent: raw, bodyClean, bodyRaw, bodyStartOffset: openB + 1,
					lineStarts, file, lang, framework: "nextjs", enclosingMethod: mth, knownParams: [pName],
				});
				for (const sk of scanned.sinks) sinksOut.push(sk);
				servicesOut.push({
					id: `svc-${sha256Short(`${file}:${mth}:${line}`)}`,
					language: lang, methodName: mth, qualifiedName: mth, role: "controller",
					file, line, anchor: `${file}:${line}`, params: [pName], fieldTypes: {}, imports,
					calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
				});
				routesOut.push({
					method: mth, localPath: nextPath, handlerName: mth, language: lang, framework: "nextjs",
					file, line, sourceParams: [pName],
					directGuards: AUTH_GUARD_TOKEN_RE.test(bodyClean) ? ["nextjs-inline-auth"] : [],
					isExplicitlyPublic: EXPLICIT_PERMIT_ALL_RE.test(bodyClean),
				});
			}
		}

		const localRouterGuards = new Map<string, string[]>();
		const localRouterPrefixes = new Map<string, string>();
		const localDeclaredRouters = new Set<string>();
		for (const dr of clean.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:(?:express\.)?Router\s*\(|new\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*)?Router\s*\()/g)) {
			localDeclaredRouters.add(dr[1]!);
		}
		for (const km of clean.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+Router\s*\(\s*\{\s*prefix\s*:\s*['"`]([^'"`]+)['"`]/g)) {
			localRouterPrefixes.set(km[1]!, km[2]!);
		}

		for (const um of clean.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(use|register)\s*\(/g)) {
			const obj = um[1]!;
			const bal = extractBalanced(clean, (um.index ?? 0) + um[0].length - 1, "(", ")", 3000);
			if (!bal) continue;
			const args = splitTopLevelCommas(bal.inner);
			if (args.length === 0) continue;
			const firstLit = /^['"`](\/[^'"`]*)['"`]$/.exec(args[0]!)?.[1];
			const rest = firstLit ? args.slice(1) : args;
			const line = offsetToLine(lineStarts, um.index ?? 0);
			if (rest.length === 0) continue;

			const lastArg = rest[rest.length - 1]!.trim();
			const middleGuards = rest.slice(0, -1).filter((a) => AUTH_GUARD_TOKEN_RE.test(a)).map((a) => a.trim());
			const inheritedOnObj = localRouterGuards.get(obj) ?? [];
			const isKnownSubRouter = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(lastArg) && lastArg !== obj && Boolean(imports[lastArg] || localDeclaredRouters.has(lastArg));

			if (isKnownSubRouter) {
				const fastifyPrefix = um[2] === "register" && rest.length >= 2
					? /\bprefix\s*:\s*['"`]([^'"`]+)['"`]/.exec(rest[rest.length - 1]!)?.[1] : undefined;
				mountsOut.push({
					parentFile: file, parentRouterVar: obj,
					targetModuleRel: imports[lastArg] ?? file, targetSymbol: lastArg,
					prefix: joinRoutePaths(localRouterPrefixes.get(obj) ?? "", firstLit ?? fastifyPrefix ?? "/"),
					guards: [...inheritedOnObj, ...middleGuards], exempts: [], framework: defaultFw, language: lang, line,
				});
			} else if (um[2] === "register" && (imports[args[0]!.trim()] || localDeclaredRouters.has(args[0]!.trim()))) {
				const regTarget = args[0]!.trim();
				const optPrefix = /\bprefix\s*:\s*['"`]([^'"`]+)['"`]/.exec(args[1] ?? "")?.[1] ?? "/";
				mountsOut.push({
					parentFile: file, parentRouterVar: obj,
					targetModuleRel: imports[regTarget] ?? file, targetSymbol: regTarget,
					prefix: optPrefix, guards: [...inheritedOnObj], exempts: [], framework: "fastify", language: lang, line,
				});
			} else if (!firstLit && AUTH_GUARD_TOKEN_RE.test(bal.inner)) {
				const prev = localRouterGuards.get(obj) ?? [];
				prev.push(bal.inner.trim().slice(0, 48));
				localRouterGuards.set(obj, prev);
			} else if (firstLit && AUTH_GUARD_TOKEN_RE.test(rest.join(","))) {
				guardsOut.push({
					id: `guard-${sha256Short(`${file}:${line}:${firstLit}`)}`,
					name: `express.use(${firstLit})`, kind: "prefix_interceptor", language: lang, framework: defaultFw,
					file, line, anchor: `${file}:${line}`, pathPatterns: [firstLit], exemptPatterns: [],
				});
			}
		}

		for (const rm of clean.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(get|post|put|patch|delete)\s*\(/g)) {
			const obj = rm[1]!;
			if (/^(?:axios|http|https|Math|Map|Set|Reflect|FormData|URLSearchParams|headers|cookies|cache|redis|store)$/i.test(obj)) continue;
			const mth = rm[2]!.toUpperCase();
			const openP = (rm.index ?? 0) + rm[0].length - 1;
			const bal = extractBalanced(clean, openP, "(", ")", 12000);
			if (!bal) continue;
			const rawBal = extractBalanced(raw, openP, "(", ")", 12000);
			const args = splitTopLevelCommas(bal.inner);
			const pathLit = /^['"`](\/[^'"`]*)['"`]$/.exec(args[0] ?? "")?.[1];
			if (!pathLit) continue;

			const line = offsetToLine(lineStarts, rm.index ?? 0);
			const mws = args.slice(1, -1).filter((a) => AUTH_GUARD_TOKEN_RE.test(a)).map((a) => a.trim());
			if (args.length >= 3 && args[1]?.startsWith("{") && AUTH_GUARD_TOKEN_RE.test(args[1]!)) mws.push("fastify:preHandlerAuth");

			const lastHandler = args[args.length - 1] ?? "";
			const handlerIdent = /^[A-Za-z_$][A-Za-z0-9_$.]*$/.test(lastHandler.trim()) ? lastHandler.trim() : `inline_${mth}_${line}`;
			if (lastHandler.includes("{")) {
				const hBrace = bal.inner.lastIndexOf(lastHandler) + lastHandler.indexOf("{");
				const hBal = extractBalanced(bal.inner, hBrace, "{", "}", 10000);
				if (hBal) {
					const rawInnerSlice = rawBal ? rawBal.inner.slice(hBrace + 1, hBal.endIdx) : hBal.inner;
					const scanned = scanBodyForSinksAndCalls({
						rawFileContent: raw, bodyClean: hBal.inner, bodyRaw: rawInnerSlice,
						bodyStartOffset: openP + 1 + hBrace + 1, lineStarts, file, lang, framework: defaultFw,
						enclosingMethod: handlerIdent, knownParams: ["req"],
					});
					for (const sk of scanned.sinks) sinksOut.push(sk);
					servicesOut.push({
						id: `svc-${sha256Short(`${file}:${handlerIdent}:${line}`)}`,
						language: lang, methodName: handlerIdent, qualifiedName: handlerIdent, role: "controller",
						file, line, anchor: `${file}:${line}`, params: ["req"], fieldTypes: {}, imports,
						calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
					});
				}
			}

			routesOut.push({
				method: mth, localPath: joinRoutePaths(localRouterPrefixes.get(obj) ?? "", pathLit),
				routerVar: obj, handlerName: handlerIdent, language: lang, framework: defaultFw,
				file, line, sourceParams: ["req"],
				directGuards: [...(localRouterGuards.get(obj) ?? []), ...mws],
				isExplicitlyPublic: EXPLICIT_PERMIT_ALL_RE.test(bal.inner),
			});
		}

		for (const fnm of clean.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)[^{]*\{/g)) {
			const fnName = fnm[1]!;
			if (/^(?:GET|POST|PUT|PATCH|DELETE)$/.test(fnName) && nextAppMatch) continue;
			const openB = (fnm.index ?? 0) + fnm[0].length - 1;
			const bal = extractBalanced(clean, openB, "{", "}", 20000);
			if (!bal) continue;
			const line = offsetToLine(lineStarts, fnm.index ?? 0);
			const params = splitTopLevelCommas(fnm[2] ?? "").map((p) => p.split(":")[0]!.split("=")[0]!.trim()).filter((p) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(p));
			const scanned = scanBodyForSinksAndCalls({
				rawFileContent: raw, bodyClean: bal.inner, bodyRaw: raw.slice(openB + 1, bal.endIdx),
				bodyStartOffset: openB + 1, lineStarts, file, lang, enclosingMethod: fnName, knownParams: params,
			});
			for (const sk of scanned.sinks) sinksOut.push(sk);
			servicesOut.push({
				id: `svc-${sha256Short(`${file}:${fnName}:${line}`)}`,
				language: lang, methodName: fnName, qualifiedName: fnName,
				role: /Repo|Dao|Store/i.test(file + fnName) ? "repository" : "service",
				file, line, anchor: `${file}:${line}`, params, fieldTypes: {}, imports,
				calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
			});
		}
		return;
	}

	if (lang === "python") {
		const imports: Record<string, string> = {};
		for (const pm of clean.matchAll(/\bfrom\s+([A-Za-z0-9_.]+)\s+import\s+([^\n]+)/g)) {
			const modRel = pm[1]!.replace(/^\.+/, "").replace(/\./g, "/");
			for (const part of pm[2]!.split(",")) {
				const tokens = part.trim().split(/\s+as\s+/);
				const origSym = tokens[0]?.trim() ?? "";
				const localSym = tokens[tokens.length - 1]?.trim() ?? "";
				if (localSym) {
					// 兼顾 `from routers import secret_admin`（子模块路径 `py/routers/secret_admin`）与直接导入函数
					imports[localSym] = resolveRelativeModulePath(file, modRel ? `${modRel}/${origSym}` : origSym);
				}
			}
		}

		const routerMeta = new Map<string, { prefix: string; guards: string[] }>();
		for (const rm of clean.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:APIRouter|Blueprint)\s*\(([^)]*)\)/g)) {
			const pref = /\b(?:prefix|url_prefix)\s*=\s*['"]([^'"]+)['"]/.exec(rm[2] ?? "")?.[1] ?? "";
			const gs = AUTH_GUARD_TOKEN_RE.test(rm[2] ?? "") ? [`router_dep(${rm[1]!})`] : [];
			routerMeta.set(rm[1]!, { prefix: pref, guards: gs });
		}
		for (const bm of clean.matchAll(/@([A-Za-z_][A-Za-z0-9_]*)\.before_request\b[\s\S]{0,260}?def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*:([\s\S]{0,400})/g)) {
			if (AUTH_GUARD_TOKEN_RE.test(bm[2] ?? "")) {
				const meta = routerMeta.get(bm[1]!) ?? { prefix: "", guards: [] };
				meta.guards.push(`flask:before_request(${bm[1]!})`);
				routerMeta.set(bm[1]!, meta);
			}
		}
		for (const im of clean.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\.(include_router|register_blueprint)\s*\(([^)]+)\)/g)) {
			const args = splitTopLevelCommas(im[2] ?? "");
			const targetExpr = (args[0] ?? "").trim();
			const rootSym = targetExpr.split(".")[0]!;
			const pref = /\b(?:prefix|url_prefix)\s*=\s*['"]([^'"]+)['"]/.exec(im[2] ?? "")?.[1] ?? "/";
			const gs = AUTH_GUARD_TOKEN_RE.test(im[2] ?? "") ? ["fastapi:include_router_dep"] : [];
			if (imports[rootSym]) {
				mountsOut.push({
					parentFile: file, targetModuleRel: imports[rootSym], targetSymbol: targetExpr,
					prefix: pref, guards: gs, exempts: [],
					framework: im[1] === "include_router" ? "fastapi" : "flask",
					language: "python", line: offsetToLine(lineStarts, im.index ?? 0),
				});
			}
		}

		const pyDefRe = /((?:@[A-Za-z0-9_.]+(?:\([^)]*\))?\s*\n\s*)*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(((?:[^()]|\([^()]*\))*)\)(?:\s*->\s*[^:]+)?\s*:/g;
		const defMatches = [...clean.matchAll(pyDefRe)];
		for (let idx = 0; idx < defMatches.length; idx++) {
			const dm = defMatches[idx]!;
			const nextStart = idx + 1 < defMatches.length ? (defMatches[idx + 1]!.index ?? clean.length) : clean.length;
			const decClean = clean.slice(dm.index ?? 0, (dm.index ?? 0) + (dm[1]?.length ?? 0));
			const fnName = dm[2]!, paramsClean = dm[3] ?? "";
			const bodyStart = (dm.index ?? 0) + dm[0].length;
			const fnLine = offsetToLine(lineStarts, dm.index ?? 0);
			const params = splitTopLevelCommas(paramsClean).map((p) => p.split(":")[0]!.split("=")[0]!.trim()).filter((p) => p && p !== "self" && p !== "cls");

			const scanned = scanBodyForSinksAndCalls({
				rawFileContent: raw, bodyClean: clean.slice(bodyStart, nextStart), bodyRaw: raw.slice(bodyStart, nextStart),
				bodyStartOffset: bodyStart, lineStarts, file, lang: "python", enclosingMethod: fnName, knownParams: params,
			});
			for (const sk of scanned.sinks) sinksOut.push(sk);
			servicesOut.push({
				id: `svc-${sha256Short(`${file}:${fnName}:${fnLine}`)}`,
				language: "python", methodName: fnName, qualifiedName: fnName, role: "service",
				file, line: fnLine, anchor: `${file}:${fnLine}`, params, fieldTypes: {}, imports,
				calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
			});

			const routeDec = /@([A-Za-z_][A-Za-z0-9_]*)\.(route|get|post|put|patch|delete)\s*\(([^)]*)\)/.exec(decClean);
			if (routeDec) {
				const rObj = routeDec[1]!, rKind = routeDec[2]!.toLowerCase(), rInner = routeDec[3] ?? "";
				const pathStr = extractStringLiterals(rInner)[0] ?? "/";
				const methodsMatch = /\bmethods\s*=\s*\[([^\]]+)\]/.exec(rInner);
				const methods = rKind === "route" ? (methodsMatch ? extractStringLiterals(methodsMatch[1]!).map((s) => s.toUpperCase()) : ["GET"]) : [rKind.toUpperCase()];
				const rMeta = routerMeta.get(rObj);
				const guards = [...(rMeta?.guards ?? [])];
				if (AUTH_GUARD_TOKEN_RE.test(decClean) || AUTH_GUARD_TOKEN_RE.test(paramsClean)) guards.push("python:auth_dependency");
				for (const mth of methods) {
					routesOut.push({
						method: mth, localPath: joinRoutePaths(rMeta?.prefix ?? "", pathStr),
						routerVar: rObj, handlerName: fnName, language: "python",
						framework: rKind === "route" ? "flask" : "fastapi",
						file, line: fnLine, sourceParams: params, directGuards: guards,
						isExplicitlyPublic: EXPLICIT_PERMIT_ALL_RE.test(decClean),
					});
				}
			}
		}
		return;
	}

	if (lang === "go") {
		const fw: RgsFramework = /\becho\.New\b|\*echo\.Group/.test(clean)
			? "echo" : /\bgin\.(?:Default|New|RouterGroup)\b/.test(clean) ? "gin" : "net/http";
		const groupMeta = new Map<string, { prefix: string; guards: string[] }>();
		for (const gm of clean.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*([A-Za-z_][A-Za-z0-9_]*)\.Group\s*\(([^)]+)\)/g)) {
			const args = splitTopLevelCommas(gm[3]!);
			const pref = extractStringLiterals(args[0] ?? "")[0] ?? "/";
			const parentMeta = groupMeta.get(gm[2]!);
			const gs = [...(parentMeta?.guards ?? []), ...args.slice(1).filter((a) => AUTH_GUARD_TOKEN_RE.test(a)).map((a) => a.trim())];
			groupMeta.set(gm[1]!, { prefix: joinRoutePaths(parentMeta?.prefix ?? "", pref), guards: gs });
		}
		for (const um of clean.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.Use\s*\(([^)]+)\)/g)) {
			if (AUTH_GUARD_TOKEN_RE.test(um[2]!)) {
				const prev = groupMeta.get(um[1]!) ?? { prefix: "", guards: [] };
				prev.guards.push(`go:Use(${um[2]!.trim()})`);
				groupMeta.set(um[1]!, prev);
			}
		}
		for (const cm of clean.matchAll(/\b([A-Z][A-Za-z0-9_]*Routes[A-Za-z0-9_]*|register[A-Za-z0-9_]*Routes)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/g)) {
			const gMeta = groupMeta.get(cm[2]!);
			if (gMeta) {
				mountsOut.push({
					parentFile: file, targetSymbol: cm[1]!, prefix: gMeta.prefix || "/",
					guards: gMeta.guards, exempts: [], framework: fw, language: "go",
					line: offsetToLine(lineStarts, cm.index ?? 0),
				});
			}
		}
		for (const fm of clean.matchAll(/\bfunc\s+(?:\(\s*[A-Za-z0-9_]+\s+\*?([A-Za-z0-9_]+)\s*\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)[^{]*\{/g)) {
			const recvType = fm[1], fnName = fm[2]!, openB = (fm.index ?? 0) + fm[0].length - 1;
			const bal = extractBalanced(clean, openB, "{", "}", 28000);
			if (!bal) continue;
			const fnLine = offsetToLine(lineStarts, fm.index ?? 0);
			const params = splitTopLevelCommas(fm[3] ?? "").map((p) => p.trim().split(/\s+/)[0]!).filter(Boolean);
			const bodyRaw = raw.slice(openB + 1, bal.endIdx);
			const scanned = scanBodyForSinksAndCalls({
				rawFileContent: raw, bodyClean: bal.inner, bodyRaw, bodyStartOffset: openB + 1,
				lineStarts, file, lang: "go", framework: fw, enclosingSymbol: recvType, enclosingMethod: fnName, knownParams: params,
			});
			for (const sk of scanned.sinks) sinksOut.push(sk);
			servicesOut.push({
				id: `svc-${sha256Short(`${file}:${recvType ?? ""}.${fnName}:${fnLine}`)}`,
				language: "go", ...(recvType ? { className: recvType } : {}),
				methodName: fnName, qualifiedName: recvType ? `${recvType}.${fnName}` : fnName,
				role: "service", file, line: fnLine, anchor: `${file}:${fnLine}`, params, fieldTypes: {}, imports: {},
				calls: scanned.calls, localSinks: scanned.sinks, paramToLocalAliases: scanned.paramAliases,
			});

			for (const rm of bal.inner.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.(GET|POST|PUT|PATCH|DELETE|HandleFunc)\s*\(([^)]+)\)/g)) {
				const args = splitTopLevelCommas(rm[3]!);
				const pathStr = extractStringLiterals(args[0] ?? "")[0];
				if (!pathStr) continue;
				const gMeta = groupMeta.get(rm[1]!);
				const inlineMws = args.slice(1, -1).filter((a) => AUTH_GUARD_TOKEN_RE.test(a)).map((a) => a.trim());
				routesOut.push({
					method: rm[2] === "HandleFunc" ? "GET" : rm[2]!.toUpperCase(),
					localPath: joinRoutePaths(gMeta?.prefix ?? "", pathStr),
					routerVar: fnName, handlerName: (args[args.length - 1] ?? "").trim().split(".").pop()!,
					language: "go", framework: fw, file, line: offsetToLine(lineStarts, openB + 1 + (rm.index ?? 0)),
					sourceParams: ["c"], directGuards: [...(gMeta?.guards ?? []), ...inlineMws], isExplicitlyPublic: false,
				});
			}
		}
	}
}

// ==================== 5. Webpack / Vite 前端混淆 Bundle 反解引擎 ====================

function parseMinifiedBundleFile(lf: LoadedRgsFile, routesOut: RawRouteDraft[], bundlesOut: RgsBundleExtraction[]): void {
	const { file, raw, lineStarts } = lf;
	const bundler: RgsBundleExtraction["bundler"] = /\b(?:__webpack_require__|webpackChunk)\b/.test(raw)
		? "webpack" : /\b(?:__vite|import\.meta)\b/.test(raw) || /-[a-f0-9]{6,}\.js$/i.test(file) ? "vite" : "generic";
	const fw: RgsFramework = bundler === "vite" ? "vite-bundle" : "webpack-bundle";
	const endpoints: RgsBundleEndpoint[] = [];
	const graphqlOperations: RgsGraphqlOperation[] = [];
	const seenEp = new Set<string>();

	const recordEp = (method: string, rawPath: string, offset: number, nearContext: string) => {
		const normPath = rawPath.trim().replace(/^\$\{[^}]+\}/, "").replace(/^https?:\/\/[^/]+/i, "").replace(/\$\{([^}]+)\}/g, ":param").split("?")[0]?.replace(/\/{2,}/g, "/") ?? "";
		if (!normPath.startsWith("/") || !/^\/(?:api|graphql|v\d+|internal|admin|auth|rpc|_rsc)\b/i.test(normPath)) return;
		const mth = method.toUpperCase();
		if (seenEp.has(`${mth}:${normPath}`)) return;
		seenEp.add(`${mth}:${normPath}`);

		const line = offsetToLine(lineStarts, offset);
		const params = extractBundleObjectKeysAndQueryParams(rawPath, nearContext);
		const headers = [...new Set([...nearContext.matchAll(/['"]((?:X-|Authorization|Next-Action|Grpc-)[A-Za-z0-9_-]*)['"]\s*:/gi)].map((h) => h[1]!))];
		endpoints.push({ method: mth, path: normPath, file, line, anchor: `${file}:${line}`, params, headers });
		routesOut.push({
			method: mth, localPath: normPath, language: "bundle", framework: fw, file, line,
			sourceParams: params, directGuards: headers.some((h) => SENSITIVE_HEADER_KEY_RE.test(h)) ? [`bundle-header:${headers[0]}`] : [],
			isExplicitlyPublic: false, bundleParams: params,
		});
	};

	for (const m of raw.matchAll(/\.\s*(get|post|put|patch|delete)\s*\(\s*(?:['"]([^'"]+)['"]|`([^`]+)`)/gi)) {
		recordEp(m[1]!, m[2] ?? m[3] ?? "", m.index ?? 0, raw.slice(m.index ?? 0, Math.min(raw.length, (m.index ?? 0) + 360)));
	}
	for (const m of raw.matchAll(/\bfetch\s*\(\s*(?:['"]([^'"]+)['"]|`([^`]+)`|""\.concat\([^)]*['"](\/[A-Za-z0-9_/-]+[^'"]*)['"][^)]*\))/g)) {
		const near = raw.slice(m.index ?? 0, Math.min(raw.length, (m.index ?? 0) + 420));
		recordEp(/\bmethod\s*:\s*['"]([A-Za-z]+)['"]/i.exec(near)?.[1] ?? "GET", m[1] ?? m[2] ?? m[3] ?? "", m.index ?? 0, near);
	}
	for (const m of raw.matchAll(/['"](\/(?:api|internal|v\d+)\/[A-Za-z0-9_./:-]{2,96}(?:\?[A-Za-z0-9_=&]+)*)['"]/g)) {
		const near = raw.slice(Math.max(0, (m.index ?? 0) - 80), Math.min(raw.length, (m.index ?? 0) + 260));
		recordEp(/\bmethod\s*:\s*['"](POST|PUT|PATCH|DELETE|GET)['"]/i.exec(near)?.[1] ?? "GET", m[1]!, m.index ?? 0, near);
	}

	const seenGql = new Set<string>();
	for (const gm of raw.matchAll(/\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^)]*)\))?\s*\{([\s\S]{1,800}?)\}/g)) {
		const kind = gm[1]! as RgsGraphqlOperation["kind"];
		const opName = gm[2]!;
		if (seenGql.has(opName)) continue;
		seenGql.add(opName);
		const vars = [...(gm[3] ?? "").matchAll(/\$([A-Za-z_][A-Za-z0-9_]*)/g)].map((v) => v[1]!);
		const fields = [...(gm[4] ?? "").matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)].map((f) => f[1]!).filter((f) => !/^(?:on|true|false|null|__typename)$/.test(f)).slice(0, 12);
		const line = offsetToLine(lineStarts, gm.index ?? 0);
		const opObj: RgsGraphqlOperation = { operationName: opName, kind, variables: vars, fields, file, line, anchor: `${file}:${line}` };
		graphqlOperations.push(opObj);
		routesOut.push({
			method: "POST", localPath: `/graphql#${opName}`, handlerName: opName, language: "bundle", framework: fw,
			file, line, sourceParams: vars, directGuards: [], isExplicitlyPublic: false, graphqlOperation: opObj, bundleParams: vars,
		});
	}

	const gqlAstRe = /kind\s*:\s*["']OperationDefinition["']\s*,\s*operation\s*:\s*["'](query|mutation|subscription)["'][\s\S]{0,200}?name\s*:\s*\{\s*kind\s*:\s*["']Identifier["']\s*,\s*value\s*:\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g;
	for (const am of raw.matchAll(gqlAstRe)) {
		const kind = am[1]! as RgsGraphqlOperation["kind"];
		const opName = am[2]!;
		if (seenGql.has(opName)) continue;
		seenGql.add(opName);
		const nearAst = raw.slice(am.index ?? 0, Math.min(raw.length, (am.index ?? 0) + 1200));
		const vars = [...new Set([...nearAst.matchAll(/kind\s*:\s*["']Variable["'][\s\S]{0,90}?value\s*:\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g)].map((v) => v[1]!))];
		const fields = [...new Set([...nearAst.matchAll(/kind\s*:\s*["']Field["'][\s\S]{0,120}?value\s*:\s*["']([A-Za-z_][A-Za-z0-9_]*)["']/g)].map((f) => f[1]!))].slice(0, 12);
		const line = offsetToLine(lineStarts, am.index ?? 0);
		const opObj: RgsGraphqlOperation = { operationName: opName, kind, variables: vars, fields, file, line, anchor: `${file}:${line}` };
		graphqlOperations.push(opObj);
		routesOut.push({
			method: "POST", localPath: `/graphql#${opName}`, handlerName: opName, language: "bundle", framework: fw,
			file, line, sourceParams: vars, directGuards: [], isExplicitlyPublic: false, graphqlOperation: opObj, bundleParams: vars,
		});
	}
	bundlesOut.push({ file, bundler, endpoints, graphqlOperations });
}

function extractBundleObjectKeysAndQueryParams(rawPath: string, nearContext: string): string[] {
	const params = new Set<string>();
	for (const qm of (rawPath.split("?")[1] ?? "").matchAll(/([A-Za-z_][A-Za-z0-9_]*)=/g)) params.add(qm[1]!);
	for (const cm of nearContext.matchAll(/[?&]([A-Za-z_][A-Za-z0-9_]*)=/g)) params.add(cm[1]!);
	const skipMeta = new Set(["method", "headers", "body", "credentials", "mode", "cache", "signal", "Content-Type", "Accept"]);
	for (const km of nearContext.matchAll(/[{,]\s*([A-Za-z_][A-Za-z0-9_]{1,40})\s*:/g)) {
		if (!skipMeta.has(km[1]!)) params.add(km[1]!);
	}
	return [...params].slice(0, 16);
}

// ==================== 核心 API 1：跨文件 RGS 图谱构建 ====================

export function analyzeCrossFileRgs(input: CodeSurfaceInput, opts?: AnalyzeRgsOptions): RgsGraphResult {
	const loadedFiles = collectRgsFiles(input, opts);
	const maxCallDepth = Math.min(8, Math.max(1, opts?.maxCallDepth ?? 5));

	const rawRoutes: RawRouteDraft[] = [], guards: RgsGuardNode[] = [], mounts: RawCrossMountEdge[] = [];
	const services: RgsServiceNode[] = [], sinks: RgsSinkNode[] = [], bundles: RgsBundleExtraction[] = [];
	for (const lf of loadedFiles) {
		if (lf.lang === "java") parseJavaAndSpringFile(lf, rawRoutes, guards, services, sinks);
		else if (lf.lang === "php") parsePhpFile(lf, rawRoutes, mounts, services, sinks);
		else if (lf.lang === "rust") parseRustFile(lf, rawRoutes, mounts, services, sinks);
		else if (lf.lang === "bundle") parseMinifiedBundleFile(lf, rawRoutes, bundles);
		else parseJsTsPyGoFile(lf, rawRoutes, guards, mounts, services, sinks);
	}
	const stripExt = (p: string) => p.replace(/\.(?:ts|tsx|js|jsx|mjs|cjs|py|php|rs|go)$/i, "").replace(/\/index$/i, "");
	const resolveMountChainForRoute = (draft: RawRouteDraft): { fullPath: string; inheritedGuards: string[] } => {
		let curPath = draft.localPath, curFile = draft.file, curSymbol = draft.handlerName, curRouterVar = draft.routerVar;
		const inherited: string[] = [], visited = new Set<string>();
		for (let depth = 0; depth < 5; depth++) {
			const fileNoExt = stripExt(curFile);
			const matchedEdge = mounts.find((edge) => {
				const edgeKey = `${edge.parentFile}:${edge.line}:${edge.prefix}:${edge.targetSymbol ?? ""}`;
				if (visited.has(edgeKey) || edge.language !== draft.language) return false;
				// 同文件局部子路由器挂载（如 Express `app.use("/api/admin", requireAuth, adminRouter)`）必须精确匹配子路由器变量或符号名
				if (edge.parentFile === curFile && edge.targetModuleRel === curFile) {
					return Boolean(edge.targetSymbol && (curRouterVar === edge.targetSymbol || curSymbol === edge.targetSymbol));
				}
				if (edge.targetModuleRel) {
					const targetNoExt = stripExt(edge.targetModuleRel);
					if (fileNoExt === targetNoExt || fileNoExt.endsWith(`/${targetNoExt}`)) return true;
				}
				if (edge.targetSymbol) {
					if ((curSymbol && edge.targetSymbol === curSymbol) || (curRouterVar && edge.targetSymbol === curRouterVar)) return true;
					if (fileNoExt.endsWith(`/${edge.targetSymbol}`) || basename(fileNoExt) === edge.targetSymbol) return true;
				}
				return false;
			});
			if (!matchedEdge) break;
			visited.add(`${matchedEdge.parentFile}:${matchedEdge.line}:${matchedEdge.prefix}:${matchedEdge.targetSymbol ?? ""}`);
			curPath = joinRoutePaths(matchedEdge.prefix, curPath);
			for (const g of matchedEdge.guards) if (!inherited.includes(g)) inherited.push(g);
			curFile = matchedEdge.parentFile; curRouterVar = matchedEdge.parentRouterVar; curSymbol = undefined;
		}
		return { fullPath: curPath, inheritedGuards: inherited };
	};

	const servicesByQualified = new Map<string, RgsServiceNode[]>(), servicesByMethod = new Map<string, RgsServiceNode[]>();
	for (const svc of services) {
		const qList = servicesByQualified.get(svc.qualifiedName) ?? []; qList.push(svc); servicesByQualified.set(svc.qualifiedName, qList);
		const mList = servicesByMethod.get(svc.methodName) ?? []; mList.push(svc); servicesByMethod.set(svc.methodName, mList);
	}

	const routes: RgsRouteNode[] = [];
	const allChains: RgsDataflowChain[] = [];
	let suppressedByGlobalGuardCount = 0;

	for (const draft of rawRoutes) {
		const mounted = resolveMountChainForRoute(draft);
		const fullPath = mounted.fullPath;
		const inheritedGuards = [...mounted.inheritedGuards];
		let isExplicitlyPublic = draft.isExplicitlyPublic;
		let guardReason = "";

		for (const gNode of guards) {
			if (gNode.language !== draft.language) continue;
			if (gNode.orderedRules && gNode.orderedRules.length > 0) {
				const firstHit = gNode.orderedRules.find((r) => (!r.httpMethod || r.httpMethod === draft.method) && matchGuardPathPattern(r.pattern, fullPath));
				if (firstHit) {
					if (firstHit.effect === "permit_all") {
						isExplicitlyPublic = true;
						guardReason = `命中全局规则豁免 ${firstHit.guardName} (${firstHit.pattern}) @ ${gNode.anchor}`;
					} else if (!draft.isExplicitlyPublic) {
						inheritedGuards.push(`${firstHit.guardName}@${gNode.anchor}`);
						guardReason = `受全局安全过滤链 ${firstHit.guardName} (${firstHit.pattern}) @ ${gNode.anchor} 覆盖保护`;
					}
				}
				continue;
			}
			if (gNode.exemptPatterns.some((ep) => matchGuardPathPattern(ep, fullPath))) {
				if (!guardReason) guardReason = `落入拦截器排除差集 excludePathPatterns @ ${gNode.anchor}`;
				continue;
			}
			if (gNode.pathPatterns.some((pp) => matchGuardPathPattern(pp, fullPath)) && !draft.isExplicitlyPublic) {
				inheritedGuards.push(`${gNode.name}@${gNode.anchor}`);
				guardReason = `受上层前缀拦截器 ${gNode.name} @ ${gNode.anchor} 覆盖保护`;
			}
		}

		const effectiveGuards = isExplicitlyPublic && draft.directGuards.length === 0
			? [] : [...new Set([...draft.directGuards, ...inheritedGuards])];
		const hasEffectiveGuard = effectiveGuards.length > 0;
		const suppressedByGlobalGuard = draft.directGuards.length === 0 && inheritedGuards.length > 0 && hasEffectiveGuard;
		if (suppressedByGlobalGuard) suppressedByGlobalGuardCount++;

		if (!guardReason) {
			if (draft.directGuards.length > 0) guardReason = `路由直接挂载鉴权守卫: ${draft.directGuards.join(", ")}`;
			else if (inheritedGuards.length > 0 && hasEffectiveGuard) guardReason = `继承跨文件路由组鉴权守卫: ${inheritedGuards.join(", ")}`;
			else if (isExplicitlyPublic) guardReason = "显式声明公开豁免（无有效鉴权拦截）";
			else guardReason = "未检测到直接、继承或全局鉴权守卫覆盖";
		}

		const routeAnchor = `${draft.file}:${draft.line}`;
		const routeId = `route-${sha256Short(`${draft.method}:${fullPath}:${routeAnchor}`)}`;
		const entrySvc = findEntryServiceForRoute(draft, servicesByQualified, servicesByMethod);
		const { reachableSinks, chains } = traceCrossFileDataflow({
			routeId, method: draft.method, routePath: fullPath, routeFile: draft.file, routeLine: draft.line,
			sourceParams: draft.sourceParams, entrySvc, servicesByQualified, servicesByMethod, maxCallDepth,
		});
		for (const c of chains) allChains.push(c);

		const riskFlags: RgsRouteRiskFlag[] = [];
		if (!hasEffectiveGuard && !LIFECYCLE_PUBLIC_ROUTE_RE.test(fullPath) && draft.language !== "bundle") {
			riskFlags.push("missing_auth_guard");
		}
		for (const sk of reachableSinks) if (!riskFlags.includes(sk.kind)) riskFlags.push(sk.kind);

		routes.push({
			id: routeId, method: draft.method, path: fullPath, rawLocalPath: draft.localPath,
			language: draft.language, framework: draft.framework, file: draft.file, line: draft.line, anchor: routeAnchor,
			...(draft.controllerClass ? { controllerClass: draft.controllerClass } : {}),
			...(draft.handlerName ? { handlerName: draft.handlerName } : {}),
			sourceParams: draft.sourceParams, directGuards: draft.directGuards, inheritedGuards, effectiveGuards,
			isExplicitlyPublic, hasEffectiveGuard, suppressedByGlobalGuard, guardCoverageReason: guardReason,
			reachableSinks, dataflowChains: chains, riskFlags,
			...(draft.graphqlOperation ? { graphqlOperation: draft.graphqlOperation } : {}),
			...(draft.bundleParams ? { bundleParams: draft.bundleParams } : {}),
		});
	}

	const unauthenticatedRoutes = routes.filter((r) => r.riskFlags.includes("missing_auth_guard"));
	const byLanguage: Record<string, number> = {}, byFramework: Record<string, number> = {};
	for (const r of routes) {
		byLanguage[r.language] = (byLanguage[r.language] ?? 0) + 1;
		byFramework[r.framework] = (byFramework[r.framework] ?? 0) + 1;
	}
	return {
		scannedFiles: loadedFiles.length, routes, guards, services, sinks, chains: allChains, bundles,
		unauthenticatedRoutes, suppressedByGlobalGuardCount,
		summary: {
			totalRoutes: routes.length, guardedRoutes: routes.filter((r) => r.hasEffectiveGuard).length,
			unauthenticatedRoutes: unauthenticatedRoutes.length, suppressedFalsePositives: suppressedByGlobalGuardCount,
			totalSinks: sinks.length, crossFileChains: allChains.filter((c) => c.crossFile).length,
			bundleEndpoints: bundles.reduce((acc, b) => acc + b.endpoints.length, 0),
			graphqlOperations: bundles.reduce((acc, b) => acc + b.graphqlOperations.length, 0),
			byLanguage, byFramework,
		},
	};
}

function findEntryServiceForRoute(draft: RawRouteDraft, byQualified: Map<string, RgsServiceNode[]>, byMethod: Map<string, RgsServiceNode[]>): RgsServiceNode | undefined {
	if (!draft.handlerName) return undefined;
	const exactList = byQualified.get(draft.handlerName);
	if (exactList && exactList.length > 0) {
		return exactList.find((s) => s.file === draft.file && s.line === draft.line) ?? exactList.find((s) => s.file === draft.file) ?? exactList[0];
	}
	const mList = byMethod.get(draft.handlerName.split(".").pop()!);
	if (!mList || mList.length === 0) return undefined;
	return mList.find((s) => s.file === draft.file) ?? mList.find((s) => s.language === draft.language) ?? mList[0];
}

function traceCrossFileDataflow(opts: {
	routeId: string; method: string; routePath: string; routeFile: string; routeLine: number;
	sourceParams: string[]; entrySvc: RgsServiceNode | undefined;
	servicesByQualified: Map<string, RgsServiceNode[]>; servicesByMethod: Map<string, RgsServiceNode[]>;
	maxCallDepth: number;
}): { reachableSinks: RgsSinkNode[]; chains: RgsDataflowChain[] } {
	const { routeId, method, routePath, routeFile, routeLine, sourceParams, entrySvc, servicesByQualified, servicesByMethod, maxCallDepth } = opts;
	if (!entrySvc) return { reachableSinks: [], chains: [] };

	const reachableSinksMap = new Map<string, RgsSinkNode>();
	const chains: RgsDataflowChain[] = [];
	const rootSourceLabel = sourceParams[0] ?? "request_input";

	const dfs = (svc: RgsServiceNode, activeTaintedParams: Set<string>, hopsSoFar: RgsTaintHop[], visitedIds: Set<string>, depth: number) => {
		if (depth > maxCallDepth || visitedIds.has(svc.id)) return;
		const nextVisited = new Set(visitedIds);
		nextVisited.add(svc.id);

		const stepRole: RgsTaintHop["step"] = svc.role === "repository" ? "repository" : svc.role === "controller" ? "controller" : "service";
		const nextHops: RgsTaintHop[] = [...hopsSoFar, {
			step: stepRole, symbol: svc.qualifiedName, file: svc.file, line: svc.line, anchor: svc.anchor,
			taintedVar: [...activeTaintedParams][0] ?? rootSourceLabel,
		}];

		for (const sk of svc.localSinks) {
			const isTaintedHit = sk.taintedExprs.length > 0 && (sk.taintedExprs.includes("request_input")
				|| sk.taintedExprs.includes("req_input") || sk.taintedExprs.some((te) => activeTaintedParams.has(te)));
			if (!isTaintedHit) continue;

			reachableSinksMap.set(sk.id, sk);
			const fullHops: RgsTaintHop[] = [
				{ step: "route", symbol: `${method} ${routePath}`, file: routeFile, line: routeLine, anchor: `${routeFile}:${routeLine}`, taintedVar: rootSourceLabel },
				...nextHops,
				{ step: "sink", symbol: sk.kind, file: sk.file, line: sk.line, anchor: sk.anchor, taintedVar: sk.taintedExprs[0] ?? rootSourceLabel, detail: sk.message },
			];
			chains.push({
				id: `chain-${sha256Short(`${routeId}:${sk.id}:${fullHops.length}`)}`,
				routeId, sinkId: sk.id, sinkKind: sk.kind, method, routePath, sourceParam: rootSourceLabel,
				hops: fullHops, crossFile: new Set(fullHops.map((h) => h.file)).size > 1,
				confidence: sk.taintedExprs.length > 0 ? "high" : "medium",
			});
		}

		const localTaintedVars = new Set<string>(activeTaintedParams);
		for (const p of activeTaintedParams) for (const al of svc.paramToLocalAliases[p] ?? []) localTaintedVars.add(al);

		for (const call of svc.calls) {
			const targetNode = resolveCalleeService(svc, call, servicesByQualified, servicesByMethod);
			if (!targetNode) continue;
			const nextParamSet = new Set<string>();
			call.argExprs.forEach((argExpr, argIdx) => {
				const argHasTaint = [...localTaintedVars].some((tv) => containsIdentifier(argExpr, tv))
					|| (depth === 0 && /\b(?:req\.(?:query|body|params)|request\.(?:args|json|form)|c\.(?:Query|Param|PostForm)|\$_(?:GET|POST|REQUEST)|\$request->(?:input|query))\b/.test(argExpr));
				if (argHasTaint) nextParamSet.add(targetNode.params[argIdx] ?? targetNode.params[0] ?? "arg0");
			});
			if (nextParamSet.size > 0) dfs(targetNode, nextParamSet, nextHops, nextVisited, depth + 1);
		}
	};

	dfs(entrySvc, new Set<string>(entrySvc.params.length > 0 ? entrySvc.params : sourceParams), [], new Set<string>(), 0);
	return { reachableSinks: [...reachableSinksMap.values()], chains };
}

function resolveCalleeService(
	caller: RgsServiceNode, call: RgsCallSite,
	byQualified: Map<string, RgsServiceNode[]>, byMethod: Map<string, RgsServiceNode[]>,
): RgsServiceNode | undefined {
	if (call.calleeObject) {
		const mappedType = caller.fieldTypes[call.calleeObject] ?? call.calleeObject;
		for (const qKey of [`${mappedType}.${call.calleeMethod}`, `${mappedType}Impl.${call.calleeMethod}`]) {
			const qCandidates = byQualified.get(qKey);
			if (qCandidates && qCandidates.length > 0) return qCandidates.find((c) => c.language === caller.language) ?? qCandidates[0];
		}
	}
	const mCandidates = (byMethod.get(call.calleeMethod) ?? []).filter((c) => c.language === caller.language && c.id !== caller.id);
	if (mCandidates.length === 0) return undefined;
	if (call.calleeObject && caller.imports[call.calleeObject]) {
		const impRel = caller.imports[call.calleeObject]!.replace(/\.(?:ts|js|py|php|rs)$/, "");
		const byImp = mCandidates.find((c) => c.file.replace(/\.(?:ts|js|py|php|rs)$/, "").endsWith(impRel));
		if (byImp) return byImp;
	}
	return mCandidates[0];
}

// ==================== 核心 API 2：RGS 图谱转待验证意图 ====================

export function bridgeRgsToVerificationIntents(
	rgs: RgsGraphResult,
	baseUrl: string,
	opts?: RgsBridgeOptions,
): RgsBridgeResult {
	const cleanBase = (baseUrl || "http://127.0.0.1").trim().replace(/\/+$/, "");
	if (opts?.scope) {
		const parsed = new URL(cleanBase);
		const check = isHostInScope(parsed.hostname, opts.scope);
		if (!check.ok) throw new Error(`目标基础地址不在授权 Scope 内: ${check.reason ?? parsed.hostname}`);
	}

	const phase: Phase = opts?.phase ?? "vuln";
	const includePublic = Boolean(opts?.includePublicLifecycleRoutes);
	const includeBundles = opts?.includeBundleEndpoints !== false;
	const intents: HybridVerificationIntentSpec[] = [];
	const hypotheses: HybridHypothesisSpec[] = [];
	const seenKeys = new Set<string>();
	let skippedGuardedCount = 0;
	let skippedPublicLifecycleCount = 0;

	for (const route of rgs.routes) {
		if (!includePublic && LIFECYCLE_PUBLIC_ROUTE_RE.test(route.path)) { skippedPublicLifecycleCount++; continue; }
		if (route.language === "bundle" && !includeBundles) continue;
		const hasChains = route.dataflowChains.length > 0;
		const missingGuard = route.riskFlags.includes("missing_auth_guard");
		const isBundleTarget = route.language === "bundle";
		if (!missingGuard && !hasChains && !isBundleTarget) {
			if (route.hasEffectiveGuard) skippedGuardedCount++;
			continue;
		}

		const primaryRisk = hasChains ? route.dataflowChains[0]!.sinkKind : "missing_auth_middleware";
		const normPath = route.path.split("#")[0] || "/";
		const fullUrl = `${cleanBase}${normPath}`;
		const key = `rgs:${primaryRisk}:${route.method}:${route.path}`;
		if (seenKeys.has(key)) continue;
		seenKeys.add(key);

		const hypId = `hyp-rgs-${sha256Short(`${route.anchor}:${key}`)}`;
		const chainSummary = hasChains
			? route.dataflowChains.map((c) => c.hops.map((h) => `${h.symbol}(${h.anchor})`).join(" -> ")).join(" | ")
			: "无高危汇点直连";

		const title = hasChains
			? `[RGS 跨文件污点链] 验证 ${route.method} ${route.path} -> ${route.dataflowChains[0]!.sinkKind} (${route.anchor})`
			: isBundleTarget && route.graphqlOperation
				? `[RGS Bundle GraphQL] 验证操作 ${route.graphqlOperation.operationName} (${route.graphqlOperation.kind}) 权限边界`
				: isBundleTarget
					? `[RGS Bundle 路由] 验证隐藏接口 ${route.method} ${route.path} 参数契约 (${route.anchor})`
					: `[RGS 鉴权缺口] 验证 ${route.method} ${route.path} 缺失有效守卫 (${route.anchor})`;

		intents.push({
			key, phase, title,
			detail: `框架=${route.framework}(${route.language}) | 锚点=${route.anchor} | 守卫=${route.guardCoverageReason} | 参数=[${route.sourceParams.join(",")}] | 数据流=${chainSummary}`,
			priority: hasChains ? 94 : missingGuard ? 88 : 80,
			expectedKind: "vuln" as FactKind, surfaceDomain: "path", targetKey: route.path,
			method: route.method, path: normPath, url: fullUrl, file: route.file, line: route.line, anchor: route.anchor,
			riskCategory: primaryRisk,
			verificationAdvice: hasChains
				? `在授权范围内使用良性只读对比输入验证跨文件链路 (${chainSummary}) 的响应差异，禁止破坏性载荷。`
				: `使用多角色会话保险箱与匿名基线对比 ${route.method} ${normPath} 的 HTTP 状态码与业务字段隔离（守卫判定: ${route.guardCoverageReason}）。`,
			hypothesisId: hypId,
		});
		hypotheses.push({
			id: hypId, title: `RGS 假设: ${route.method} ${route.path} (${route.anchor})`,
			statement: `${route.anchor} 处的路由 ${route.method} ${route.path} 检出 ${route.riskFlags.join(",") || "bundle_surface"}（${route.guardCoverageReason}）`,
			falsificationTest: `发送合规对照请求至 ${fullUrl}，若匿名返回 401 且非授权角色返回 403 且无越权回显，则证伪该假设`,
			expectedGain: hasChains ? 0.92 : 0.85, estimatedCost: 0.2, status: "open",
			file: route.file, line: route.line, anchor: route.anchor, linkedIntentKeys: [key],
		});
	}
	void extractFromSourceMap;
	return { baseUrl: cleanBase, intents, hypotheses, skippedGuardedCount, skippedPublicLifecycleCount };
}

// ==================== 核心 API 3：独立可重放验证脚本生成器 ====================

function sanitizeRoleEnvSuffix(role: string): string {
	return String(role || "MEMBER").trim().toUpperCase().replace(/[^A-Z0-9_]+/g, "_").replace(/^_+|_+$/g, "") || "MEMBER";
}

function scrubCredentialStrings(rawText: string, vaultRootOrVault?: string | SessionVault, extraSecrets?: readonly string[]): { cleaned: string; hits: number } {
	let text = String(rawText ?? ""), hits = 0;
	if (vaultRootOrVault) {
		const before = text;
		text = redactVaultSecrets(text, vaultRootOrVault);
		if (text !== before) hits++;
	}
	for (const sec of extraSecrets ?? []) {
		if (sec && sec.length >= 6 && text.includes(sec)) { text = text.split(sec).join("<REDACTED_BY_POV_GENERATOR>"); hits++; }
	}
	for (const re of INLINE_CREDENTIAL_PATTERNS) text = text.replace(re, () => { hits++; return "<REDACTED_CREDENTIAL>"; });
	return { cleaned: text, hits };
}

function collectVaultRawSecrets(vaultRootOrVault?: string | SessionVault): string[] {
	if (!vaultRootOrVault) return [];
	try {
		const v = typeof vaultRootOrVault === "string" ? loadSessionVault(vaultRootOrVault) : vaultRootOrVault;
		const out = new Set<string>();
		for (const r of Object.values(v.roles ?? {})) {
			for (const cand of [r.bearer, r.cookie, r.password, ...Object.values(r.headers ?? {})]) {
				if (typeof cand === "string" && cand.trim().length >= 6) out.add(cand.trim());
			}
		}
		return [...out];
	} catch { return []; }
}

function assertZeroPlaintextSecretsInScript(script: string, vaultRootOrVault?: string | SessionVault, extraSecrets?: readonly string[]): void {
	for (const sec of [...collectVaultRawSecrets(vaultRootOrVault), ...(extraSecrets ?? [])]) {
		if (sec && sec.length >= 6 && script.includes(sec)) throw new Error("安全门禁阻断：生成的 PoV 脚本检测到残留敏感凭据字面量");
	}
	for (const re of INLINE_CREDENTIAL_PATTERNS) {
		re.lastIndex = 0;
		if (re.test(script)) throw new Error("安全门禁阻断：生成的 PoV 脚本检测到疑似明文凭据 / URL userinfo / 敏感参数残留");
	}
}

export function generateStandalonePovScript(input: GenerateStandalonePovInput): StandalonePovArtifact {
	const { fact, explicit, vaultRootOrVault, knownSecretsToScrub, scope } = input;
	if (!fact && !explicit) throw new Error("generateStandalonePovScript 需要提供已确认的 fact 或明确的 explicit 验证规范");
	if (fact) {
		const stage: VerifyStage | undefined = fact.verifyStage ?? (fact.verified ? "confirmed" : undefined);
		if (stage !== "confirmed") {
			throw new Error(`仅允许为已确认发现（verifyStage === "confirmed"）生成独立验证脚本，当前状态: ${String(fact.verifyStage ?? "unconfirmed")}`);
		}
	}

	const safeFactId = (explicit?.factId ?? fact?.id ?? "manual").replace(/[^a-zA-Z0-9._-]/g, "_") || "manual";
	const fileName = `pov-${safeFactId}.ts`;
	let redactedCount = 0;
	const scrub = (s: string): string => {
		const r = scrubCredentialStrings(s, vaultRootOrVault, knownSecretsToScrub);
		redactedCount += r.hits;
		return r.cleaned;
	};

	const sanitizeBaseOrigin = (rawOrigin: string): string => {
		const u = new URL(rawOrigin);
		if (u.username || u.password) { u.username = ""; u.password = ""; redactedCount++; }
		return `${u.protocol}//${u.host}`;
	};

	let resolvedBaseUrl = (explicit?.baseUrl ?? input.baseUrl ?? "").trim().replace(/\/+$/, "");
	let resolvedPath = (explicit?.path ?? "").trim();
	let resolvedMethod = (explicit?.method ?? "").trim().toUpperCase();

	if (fact && (!resolvedBaseUrl || !resolvedPath)) {
		const urlMatch = /https?:\/\/[^\s'"<>`]+/i.exec(`${fact.command ?? ""} ${fact.detail ?? ""}`);
		if (urlMatch?.[0]) {
			try {
				const u = new URL(urlMatch[0].replace(/[),.;]+$/, ""));
				if (u.username || u.password) { u.username = ""; u.password = ""; redactedCount++; }
				if (!resolvedBaseUrl) resolvedBaseUrl = `${u.protocol}//${u.host}`;
				if (!resolvedPath) resolvedPath = `${u.pathname}${u.search}`;
			} catch { /* ignore */ }
		}
		if (!resolvedPath && fact.targetKey?.startsWith("/")) resolvedPath = fact.targetKey;
		if (!resolvedMethod && fact.command) {
			const mMatch = /-X\s+(GET|POST|PUT|PATCH|DELETE)/i.exec(fact.command);
			if (mMatch?.[1]) resolvedMethod = mMatch[1].toUpperCase();
		}
	}

	if (!resolvedBaseUrl) resolvedBaseUrl = "http://127.0.0.1:8080";
	else resolvedBaseUrl = sanitizeBaseOrigin(resolvedBaseUrl);
	if (!resolvedPath) resolvedPath = "/";
	if (!resolvedPath.startsWith("/")) resolvedPath = `/${resolvedPath}`;
	if (!resolvedMethod) resolvedMethod = "GET";

	if (scope) {
		const hostCheck = isHostInScope(new URL(resolvedBaseUrl).hostname, scope);
		if (!hostCheck.ok) throw new Error(`目标地址不在授权 Scope 内，拒绝生成验证脚本: ${hostCheck.reason ?? resolvedBaseUrl}`);
	}

	const parsedTargetUrl = new URL(`${resolvedBaseUrl}${resolvedPath}`);
	if (explicit?.queryParams) {
		for (const [qk, qv] of Object.entries(explicit.queryParams)) parsedTargetUrl.searchParams.set(qk, scrub(qv));
	}
	for (const [qk, qv] of [...parsedTargetUrl.searchParams.entries()]) {
		if (isSensitiveParamKey(qk)) {
			parsedTargetUrl.searchParams.delete(qk);
			redactedCount++;
		} else {
			const cleanedV = scrub(qv);
			if (cleanedV !== qv) parsedTargetUrl.searchParams.set(qk, cleanedV);
		}
	}

	const cleanPathWithQuery = `${parsedTargetUrl.pathname}${parsedTargetUrl.search}`;
	const cleanTargetUrl = `${resolvedBaseUrl}${cleanPathWithQuery}`;

	const safeStaticHeaders: Record<string, string> = {};
	for (const [hk, hv] of Object.entries(explicit?.headers ?? {})) {
		const trimmedKey = hk.trim();
		if (!trimmedKey) continue;
		if (SENSITIVE_HEADER_KEY_RE.test(trimmedKey) || isSensitiveParamKey(trimmedKey) || /auth|token|secret|cookie|key|jwt|session/i.test(trimmedKey)) {
			redactedCount++;
			continue;
		}
		safeStaticHeaders[trimmedKey] = scrub(hv);
	}

	const scrubJsonFields = (val: unknown): unknown => {
		if (typeof val === "string") return scrub(val);
		if (Array.isArray(val)) return val.map(scrubJsonFields);
		if (val && typeof val === "object") {
			const out: Record<string, unknown> = {};
			for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
				if (isSensitiveParamKey(k)) { redactedCount++; continue; }
				out[k] = scrubJsonFields(v);
			}
			return out;
		}
		return val;
	};

	const scrubFormEncodedOrTextBody = (rawBody: string): string => {
		if (/^[^=\s&]+=[^]*$/.test(rawBody) && !rawBody.trim().startsWith("{")) {
			const kept: string[] = [];
			for (const pair of rawBody.split("&")) {
				const eqIdx = pair.indexOf("=");
				if (eqIdx <= 0) { kept.push(scrub(pair)); continue; }
				const rawKey = pair.slice(0, eqIdx);
				let decodedKey = rawKey;
				try { decodedKey = decodeURIComponent(rawKey); } catch { /* ignore */ }
				if (isSensitiveParamKey(decodedKey.trim())) { redactedCount++; continue; }
				kept.push(`${rawKey}=${scrub(pair.slice(eqIdx + 1))}`);
			}
			return kept.join("&");
		}
		return scrub(rawBody);
	};

	let serializedBody: string | null = null;
	if (explicit?.body !== undefined) {
		if (typeof explicit.body === "string") {
			try { serializedBody = JSON.stringify(scrubJsonFields(JSON.parse(explicit.body))); }
			catch { serializedBody = scrubFormEncodedOrTextBody(explicit.body); }
		} else {
			serializedBody = JSON.stringify(scrubJsonFields(explicit.body));
			if (!safeStaticHeaders["Content-Type"] && !safeStaticHeaders["content-type"]) safeStaticHeaders["Content-Type"] = "application/json";
		}
	}

	const roleSuffix = sanitizeRoleEnvSuffix(explicit?.role ?? input.role ?? "MEMBER");
	const roleTokenEnv = `NUWA_POV_TOKEN_${roleSuffix}`;
	const roleCookieEnv = `NUWA_POV_COOKIE_${roleSuffix}`;
	const headersFileEnv = "NUWA_POV_HEADERS_FILE" as const;
	const ruleMeta = inferFindingRuleMeta({ kind: fact?.kind ?? "vuln", title: explicit?.title ?? fact?.title ?? "", detail: fact?.detail ?? "" });
	const safeTitle = scrub(explicit?.title ?? fact?.title ?? `Finding ${safeFactId}`).replace(/\r?\n/g, " ");
	const safeAnchor = scrub(explicit?.sourceAnchor ?? fact?.sourceAnchor ?? "").replace(/\r?\n/g, " ");

	const povConfigJson = JSON.stringify({
		factId: safeFactId, ruleId: ruleMeta.ruleId, defaultBaseUrl: resolvedBaseUrl, targetPath: cleanPathWithQuery,
		method: resolvedMethod, staticHeaders: safeStaticHeaders, body: serializedBody,
		expectedStatus: explicit?.expectedStatus ?? 200,
		expectedBodyIncludes: (explicit?.expectedBodyIncludes ?? []).map(scrub).filter(Boolean),
		expectedJsonKeys: (explicit?.expectedJsonKeys ?? []).map(scrub).filter(Boolean),
		forbiddenBodyIncludes: (explicit?.forbiddenBodyIncludes ?? []).map(scrub).filter(Boolean),
		negativeControlPath: explicit?.negativeControlPath ?? `/.nuwa-pov-neg-control-${safeFactId}`,
		negativeExpectedStatuses: explicit?.negativeExpectedStatuses ?? [400, 401, 403, 404, 405],
		protectedControlPath: explicit?.protectedControlPath ?? "",
		protectedExpectedStatuses: explicit?.protectedExpectedStatuses ?? [401, 403],
	});

	const scriptContent = [
		"#!/usr/bin/env bun",
		`// 女娲 v8.0 独立可重放安全验证脚本 (${fileName}) | 事实: ${safeFactId} | 规则: ${ruleMeta.ruleId}${ruleMeta.cwe ? ` (${ruleMeta.cwe})` : ""}`,
		`// 标题: ${safeTitle}${safeAnchor ? ` | 锚点: ${safeAnchor}` : ""}`,
		`// 凭据环境变量（严禁明文硬编码）: ${headersFileEnv} / ${roleTokenEnv} / ${roleCookieEnv} / NUWA_POV_BASE_URL`,
		'import { existsSync, readFileSync } from "node:fs";',
		`const CONFIG = ${povConfigJson} as const;`,
		"function loadRuntimeAuthHeaders(): Record<string, string> {",
		"\tconst headers: Record<string, string> = { ...CONFIG.staticHeaders };",
		`\tconst hf = (process.env.${headersFileEnv} ?? "").trim();`,
		"\tif (hf && existsSync(hf)) {",
		'\t\tconst raw = readFileSync(hf, "utf8").trim();',
		'\t\tif (raw.startsWith("{")) {',
		'\t\t\tfor (const [k, v] of Object.entries(JSON.parse(raw) as Record<string, unknown>)) if (typeof v === "string" && v.trim()) headers[k.trim()] = v.trim();',
		"\t\t} else {",
		'\t\t\tfor (const ln of raw.split(/\\r?\\n/)) { const i = ln.indexOf(":"); if (i > 0) headers[ln.slice(0, i).trim()] = ln.slice(i + 1).trim(); }',
		"\t\t}",
		"\t}",
		`\tconst tok = (process.env.${roleTokenEnv} ?? "").trim();`,
		'\tif (tok && !headers.Authorization && !headers.authorization) headers.Authorization = tok.toLowerCase().startsWith("bearer ") ? tok : `Bearer ${tok}`;',
		`\tconst ck = (process.env.${roleCookieEnv} ?? "").trim();`,
		"\tif (ck && !headers.Cookie && !headers.cookie) headers.Cookie = ck;",
		"\treturn headers;",
		"}",
		"async function runPov(): Promise<void> {",
		'\tconst baseUrl = (process.env.NUWA_POV_BASE_URL ?? CONFIG.defaultBaseUrl).trim().replace(/\\/+$/, "");',
		"\tconst runtimeHeaders = loadRuntimeAuthHeaders();",
		'\tconst negRes = await fetch(`${baseUrl}${CONFIG.negativeControlPath}`, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(8000) });',
		"\tconst negBody = await negRes.text();",
		'\tconst posRes = await fetch(`${baseUrl}${CONFIG.targetPath}`, { method: CONFIG.method, headers: runtimeHeaders, ...(CONFIG.body !== null ? { body: CONFIG.body } : {}), redirect: "manual", signal: AbortSignal.timeout(8000) });',
		"\tconst posBody = await posRes.text();",
		"\tconst failures: string[] = [];",
		"\tif (posRes.status !== CONFIG.expectedStatus) failures.push(`正向状态码不匹配: 期望 ${CONFIG.expectedStatus}, 实际 ${posRes.status}`);",
		"\tif (!(CONFIG.negativeExpectedStatuses as readonly number[]).includes(negRes.status)) failures.push(`负向对照路径状态码异常: 期望 [${CONFIG.negativeExpectedStatuses.join(\",\")}], 实际 ${negRes.status}`);",
		'\tif (negRes.status === 200 && negBody.trim() === posBody.trim()) failures.push("负向随机路径返回同构 200 响应体");',
		"\tfor (const m of CONFIG.expectedBodyIncludes) if (!posBody.includes(m)) failures.push(`缺失预期特征串: ${m}`);",
		"\tfor (const b of CONFIG.forbiddenBodyIncludes) if (posBody.includes(b)) failures.push(`命中禁止特征串: ${b}`);",
		"\tif (CONFIG.expectedJsonKeys.length > 0) {",
		'\t\ttry { const pj = JSON.parse(posBody) as Record<string, unknown>; for (const jk of CONFIG.expectedJsonKeys) if (!(jk in pj)) failures.push(`JSON 缺失预期字段: ${jk}`); } catch { failures.push("正向响应并非合法 JSON"); }',
		"\t}",
		"\tlet protectedStatus: number | null = null;",
		"\tif (CONFIG.protectedControlPath) {",
		'\t\tconst protRes = await fetch(`${baseUrl}${CONFIG.protectedControlPath}`, { method: "GET", headers: runtimeHeaders, redirect: "manual", signal: AbortSignal.timeout(8000) });',
		"\t\tawait protRes.text(); protectedStatus = protRes.status;",
		"\t\tif (!(CONFIG.protectedExpectedStatuses as readonly number[]).includes(protRes.status)) failures.push(`受保护对照端点状态码异常: ${protRes.status}`);",
		"\t}",
		"\tconst ok = failures.length === 0;",
		"\tconsole.log(JSON.stringify({ ok, factId: CONFIG.factId, ruleId: CONFIG.ruleId, positiveStatus: posRes.status, negativeControlStatus: negRes.status, ...(protectedStatus !== null ? { protectedControlStatus: protectedStatus } : {}), failures }));",
		"\tprocess.exit(ok ? 0 : 1);",
		"}",
		'runPov().catch((err) => { console.error(JSON.stringify({ ok: false, factId: CONFIG.factId, error: err instanceof Error ? err.message : String(err) })); process.exit(1); });',
		"",
	].join("\n");

	assertZeroPlaintextSecretsInScript(scriptContent, vaultRootOrVault, knownSecretsToScrub);

	return {
		factId: safeFactId, fileName, ruleId: ruleMeta.ruleId, ...(ruleMeta.cwe ? { cwe: ruleMeta.cwe } : {}),
		targetUrl: cleanTargetUrl, method: resolvedMethod, roleEnvVar: roleTokenEnv,
		headersFileEnvVar: headersFileEnv, requiredEnvVars: [headersFileEnv, roleTokenEnv, roleCookieEnv],
		redactedSecretsCount: redactedCount, scriptContent,
	};
}

export function writeStandalonePovScript(outputDir: string, input: GenerateStandalonePovInput): StandalonePovWriteResult {
	const artifact = generateStandalonePovScript(input);
	const absDir = resolve(outputDir);
	mkdirSync(absDir, { recursive: true, mode: 0o700 });
	try { chmodSync(absDir, 0o700); } catch { /* ignore */ }
	const filePath = join(absDir, artifact.fileName);
	writeFileSync(filePath, artifact.scriptContent, { encoding: "utf8", mode: 0o600 });
	try { chmodSync(filePath, 0o600); } catch { /* ignore */ }
	return {
		...artifact,
		filePath,
		sha256: createHash("sha256").update(artifact.scriptContent, "utf8").digest("hex"),
		bytes: Buffer.byteLength(artifact.scriptContent, "utf8"),
	};
}
