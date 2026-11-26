/**
 * 女娲 v6.0 静态源码路由审计与动态合规验证双向协同引擎（Hybrid Audit）。
 *
 * 核心职责：
 * 1. extractCodeAttackSurface：零外部依赖递归扫描代码目录（自动跳过 node_modules/.git/dist 等）
 *    或内存源码映射，提取 TS/JS（Express/Fastify/Koa/Next.js App Router）、Python（Flask/FastAPI/Django）、
 *    Go（Gin/Echo/net/http）的路由定义、HTTP 方法、文件路径与精确行号，检查是否挂载鉴权中间件
 *    （hasAuthMiddleware / missing_auth_middleware 风险提示），并识别潜在不安全代码模式告警；
 * 2. extractFromSourceMap：安全解析 `.js.map` 的 sources / sourcesContent 进行同套静态路由与风险审计；
 * 3. bridgeWhiteboxToBlackboxIntents：将静态检出的缺鉴权路由与高风险代码点转化为结构化、去重的待核验意图清单
 *    （含文件行号与纯只读合规验证建议）及关联假设描述；
 * 4. correlateBlackboxFindingToSource：将动态核验确认的异常接口精确或参数化反向映射回源码文件与行号锚点。
 *
 * 约束：仅使用 `import type` 引用 `./types`，严禁运行时 import `./nuwa`。
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { basename, extname, join, relative, resolve } from "node:path";
import type { Fact, FactKind, Phase } from "./types";

/** 递归扫描目录时默认跳过的构建产物与依赖目录集合。 */
const DEFAULT_IGNORED_DIRS = new Set([
	"node_modules",
	".git",
	"dist",
	"build",
	"out",
	".next",
	".nuxt",
	".svelte-kit",
	".venv",
	"venv",
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	"vendor",
	"coverage",
	"target",
	".nuwa",
	".idea",
	".vscode",
]);

const SUPPORTED_SOURCE_EXTS = new Set([
	".ts",
	".tsx",
	".js",
	".jsx",
	".mjs",
	".cjs",
	".py",
	".go",
	".map",
]);

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;

export type SupportedLanguage = "typescript" | "javascript" | "python" | "go";

export type DetectedFramework =
	| "express"
	| "fastify"
	| "koa"
	| "nextjs"
	| "flask"
	| "fastapi"
	| "django"
	| "gin"
	| "echo"
	| "net/http"
	| "sourcemap-client";

export type CodeSinkKind =
	| "unparameterized_sql"
	| "dynamic_outbound_url"
	| "unchecked_path_join"
	| "dangerous_exec_call";

export type RouteRiskFlag = "missing_auth_middleware" | CodeSinkKind;

export interface ExtractedRoute {
	method: string;
	path: string;
	framework: DetectedFramework;
	language: SupportedLanguage;
	file: string;
	line: number;
	hasAuthMiddleware: boolean;
	middlewares: string[];
	riskFlags: RouteRiskFlag[];
	handlerHint?: string;
	sourceMapOrigin?: string;
}

export interface CodeSinkWarning {
	kind: CodeSinkKind;
	severity: "high" | "medium";
	file: string;
	line: number;
	snippet: string;
	message: string;
	language: SupportedLanguage;
	relatedRoute?: {
		method: string;
		path: string;
		line: number;
	};
	sourceMapOrigin?: string;
}

export interface CodeAttackSurface {
	scannedFiles: number;
	routes: ExtractedRoute[];
	warnings: CodeSinkWarning[];
	sourceMapsParsed: number;
	summary: {
		totalRoutes: number;
		unauthenticatedRoutes: number;
		totalWarnings: number;
		byFramework: Record<string, number>;
	};
}

export interface VirtualSourceFile {
	path: string;
	content: string;
	sourceMapOrigin?: string;
}

export type CodeSurfaceInput =
	| string
	| string[]
	| Record<string, string>
	| VirtualSourceFile[];

export interface ExtractSurfaceOptions {
	ignoreDirs?: string[];
	maxFileBytes?: number;
	includeSourceMaps?: boolean;
	includeClientApiHintsInSourceMap?: boolean;
}

export interface HybridVerificationIntentSpec {
	key: string;
	phase: Phase;
	title: string;
	detail: string;
	priority: number;
	expectedKind: FactKind;
	surfaceDomain: "path";
	targetKey: string;
	method: string;
	path: string;
	url: string;
	file: string;
	line: number;
	anchor: string;
	framework?: DetectedFramework;
	riskCategory: RouteRiskFlag;
	verificationAdvice: string;
	hypothesisId: string;
}

export interface HybridHypothesisSpec {
	id: string;
	title: string;
	statement: string;
	falsificationTest: string;
	expectedGain: number;
	estimatedCost: number;
	status: "open";
	file: string;
	line: number;
	anchor: string;
	linkedIntentKeys: string[];
}

export interface WhiteboxBridgeOptions {
	phase?: Phase;
	includePublicHealthRoutes?: boolean;
	includeUnboundWarnings?: boolean;
}

export interface WhiteboxBridgeResult {
	baseUrl: string;
	intents: HybridVerificationIntentSpec[];
	hypotheses: HybridHypothesisSpec[];
	skippedCount: number;
}

export type BlackboxFindingLike =
	| Partial<Fact>
	| {
			url?: string;
			path?: string;
			method?: string;
			title?: string;
			detail?: string;
			targetKey?: string;
			findingCode?: string;
			mode?: string;
	  };

export interface SourceCorrelationCandidate {
	file: string;
	line: number;
	anchor: string;
	method: string;
	routePath: string;
	framework: DetectedFramework;
	matchType: "exact" | "route_param" | "path_only";
	score: number;
	hasAuthMiddleware: boolean;
	riskFlags: RouteRiskFlag[];
}

export interface SourceCorrelationResult {
	matched: boolean;
	confidence: "exact" | "route_param" | "path_only" | "sink_heuristic" | "none";
	score: number;
	file?: string;
	line?: number;
	anchor?: string;
	route?: ExtractedRoute;
	relatedWarnings: CodeSinkWarning[];
	candidates: SourceCorrelationCandidate[];
}

// ==================== 内部词法/行号与鉴权识别辅助 ====================

const AUTH_IDENTIFIER_RE =
	/\b(?:auth|authenticate|authenticated|is_authenticated|isAuthenticated|require_auth|requireAuth|requires_auth|require_login|requireLogin|login_required|jwt_required|auth_required|permission_required|staff_member_required|admin_required|verify_token|verifyToken|verify_jwt|verifyJwt|check_jwt|checkJwt|passport|authGuard|AuthGuard|useGuard|UseGuards|requireRole|require_role|requireAdmin|require_admin|checkPermission|check_permission|rbac|RBAC|acl|protect|sessionAuth|session_auth|bearerAuth|apiKeyAuth|getServerSession|currentUser|current_user|getAuth|oauth2_scheme|get_current_user|get_current_active_user|IsAuthenticated|IsAdminUser|BasicAuth|JWTAuth|TokenAuth|JWT)\b|[A-Za-z0-9_]*(?:Auth|JWT|Jwt|OAuth|RBAC)(?:Middleware|Guard|Required|Filter|Interceptor|Dependency|Wrap|Check|Verify|Handler)?\b|[A-Za-z0-9_]*(?:Token|Role|Admin|Session|Login)(?:Middleware|Guard|Required|Filter|Interceptor)\b/;

const EXPLICIT_PUBLIC_EXEMPT_RE =
	/\b(?:AllowAny|allow_anonymous|publicRoute|skipAuth)\b/i;

const LIFECYCLE_PUBLIC_PATH_RE =
	/^\/(?:health|healthz|readyz|livez|ping|login|signin|logout|auth\/login|auth\/callback)(?:\/|$)/i;

function normalizePosixRelPath(p: string): string {
	const cleaned = p
		.replace(/\\/g, "/")
		.replace(/^(?:webpack|vite|rollup|turbopack|ng):\/\/[^/]*\/?/i, "")
		.replace(/^file:\/\/\/?/i, "")
		.replace(/^\.\//, "");
	const parts: string[] = [];
	for (const seg of cleaned.split("/")) {
		if (!seg || seg === ".") continue;
		if (seg === "..") continue; // 剥离 .. 防止虚拟 SourceMap 路径越界逃逸
		parts.push(seg);
	}
	return parts.join("/") || "anonymous.js";
}

function joinUrlRoutePaths(prefix: string, subPath: string): string {
	const p1 = (prefix || "").trim();
	const p2 = (subPath || "").trim();
	if (!p1 || p1 === "/") return p2.startsWith("/") ? p2 : `/${p2}`;
	if (!p2 || p2 === "/") return p1.startsWith("/") ? p1 : `/${p1}`;
	const left = p1.startsWith("/") ? p1.replace(/\/+$/, "") : `/${p1.replace(/\/+$/, "")}`;
	const right = p2.replace(/^\/+/, "");
	return `${left}/${right}`;
}

function buildLineStarts(content: string): number[] {
	const starts = [0];
	for (let i = 0; i < content.length; i++) {
		if (content.charCodeAt(i) === 10) {
			starts.push(i + 1);
		}
	}
	return starts;
}

function offsetToLineNumber(lineStarts: number[], offset: number): number {
	let lo = 0;
	let hi = lineStarts.length - 1;
	while (lo <= hi) {
		const mid = (lo + hi) >>> 1;
		const start = lineStarts[mid]!;
		if (start <= offset) {
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}
	return Math.max(1, hi + 1);
}

function detectLanguageByPath(filePath: string): SupportedLanguage | null {
	const ext = extname(filePath).toLowerCase();
	if (ext === ".ts" || ext === ".tsx") return "typescript";
	if (ext === ".js" || ext === ".jsx" || ext === ".mjs" || ext === ".cjs") return "javascript";
	if (ext === ".py") return "python";
	if (ext === ".go") return "go";
	return null;
}

const JS_REGEX_PRECEDING_KEYWORDS = new Set([
	"return",
	"case",
	"throw",
	"typeof",
	"void",
	"delete",
	"in",
	"of",
	"instanceof",
	"await",
	"yield",
]);

function canStartJsRegexAt(chars: string[], slashIdx: number): boolean {
	let p = slashIdx - 1;
	while (p >= 0 && (chars[p] === " " || chars[p] === "\t" || chars[p] === "\r" || chars[p] === "\n")) {
		p--;
	}
	if (p < 0) return true;
	const prev = chars[p]!;
	if ("=(,[!:;&|?{}~+-*%^<>".includes(prev)) return true;
	if (/[A-Za-z_$]/.test(prev)) {
		let wordEnd = p;
		while (p >= 0 && /[A-Za-z0-9_$]/.test(chars[p]!)) p--;
		const word = chars.slice(p + 1, wordEnd + 1).join("");
		return JS_REGEX_PRECEDING_KEYWORDS.has(word);
	}
	return false;
}

/**
 * 在保持每个字符索引与换行符 `\n` 位置 100% 不变的前提下，将源码中的行注释与块注释替换为空格，
 * 既彻底避免提取被注释掉的废弃路由，又保证提取出的 `line` 行号精确零偏移。
 */
function stripCommentsPreservingOffsets(src: string, lang: SupportedLanguage): string {
	const chars = Array.from(src);
	const len = chars.length;
	let i = 0;

	while (i < len) {
		const ch = chars[i]!;
		const next = i + 1 < len ? chars[i + 1] : "";

		if (lang === "python") {
			// 处理三引号字符串与普通单/双引号字符串，保护其中的 # 不被误判为注释
			if (
				(ch === "'" && next === "'" && chars[i + 2] === "'") ||
				(ch === '"' && next === '"' && chars[i + 2] === '"')
			) {
				const q = ch;
				i += 3;
				while (i < len) {
					if (chars[i] === "\\") {
						i += 2;
						continue;
					}
					if (chars[i] === q && chars[i + 1] === q && chars[i + 2] === q) {
						i += 3;
						break;
					}
					i++;
				}
				continue;
			}
			if (ch === "'" || ch === '"') {
				const q = ch;
				i++;
				while (i < len && chars[i] !== "\n" && chars[i] !== "\r") {
					if (chars[i] === "\\") {
						i += 2;
						continue;
					}
					if (chars[i] === q) {
						i++;
						break;
					}
					i++;
				}
				continue;
			}
			if (ch === "#") {
				while (i < len && chars[i] !== "\n" && chars[i] !== "\r") {
					chars[i] = " ";
					i++;
				}
				continue;
			}
			i++;
			continue;
		}

		// 单行注释 //（优先于正则判定）
		if (ch === "/" && next === "/") {
			while (i < len && chars[i] !== "\n" && chars[i] !== "\r") {
				chars[i] = " ";
				i++;
			}
			continue;
		}

		// 多行块注释 /* ... */
		if (ch === "/" && next === "*") {
			chars[i] = " ";
			chars[i + 1] = " ";
			i += 2;
			while (i < len) {
				if (chars[i] === "*" && chars[i + 1] === "/") {
					chars[i] = " ";
					chars[i + 1] = " ";
					i += 2;
					break;
				}
				if (chars[i] !== "\n" && chars[i] !== "\r") {
					chars[i] = " ";
				}
				i++;
			}
			continue;
		}

		// TS / JS 正则表达式字面量 `/.../[flags]` 保护（防止 `/https?:\/\/x/` 或 `/'/` 干扰后续注释识别）
		if ((lang === "typescript" || lang === "javascript") && ch === "/" && canStartJsRegexAt(chars, i)) {
			let j = i + 1;
			let inClass = false;
			let closed = false;
			while (j < len && chars[j] !== "\n" && chars[j] !== "\r") {
				const rc = chars[j]!;
				if (rc === "\\") {
					j += 2;
					continue;
				}
				if (rc === "[") {
					inClass = true;
				} else if (rc === "]" && inClass) {
					inClass = false;
				} else if (rc === "/" && !inClass) {
					closed = true;
					j++;
					while (j < len && /[a-z]/i.test(chars[j]!)) j++;
					break;
				}
				j++;
			}
			if (closed) {
				i = j;
				continue;
			}
		}

		// TS / JS / Go 反引号与单/双引号字符串字面量保护
		if (ch === "`") {
			i++;
			while (i < len) {
				// Go 反引号为原始字符串（不支持反斜杠转义，如 `c:\`）；JS/TS 模板字符串支持 `\` 转义
				if (lang !== "go" && chars[i] === "\\") {
					i += 2;
					continue;
				}
				if (chars[i] === "`") {
					i++;
					break;
				}
				i++;
			}
			continue;
		}

		if (ch === "'" || ch === '"') {
			const q = ch;
			i++;
			// 单/双引号字面量不可无转义跨行，遇到未转义 \n/\r 强制闭合防整文件污染
			while (i < len && chars[i] !== "\n" && chars[i] !== "\r") {
				if (chars[i] === "\\") {
					i += 2;
					continue;
				}
				if (chars[i] === q) {
					i++;
					break;
				}
				i++;
			}
			continue;
		}

		i++;
	}

	return chars.join("");
}

function isCommentLine(trimmedLine: string, lang: SupportedLanguage): boolean {
	if (!trimmedLine) return true;
	if (lang === "python") {
		return trimmedLine.startsWith("#");
	}
	return (
		trimmedLine.startsWith("//") ||
		trimmedLine.startsWith("/*") ||
		trimmedLine.startsWith("*") ||
		trimmedLine.startsWith("*/")
	);
}

function extractMiddlewareTokens(argsText: string): string[] {
	const cleaned = argsText
		.replace(/`[^`]*`|'[^']*'|"[^"]*"/g, " ")
		.replace(/\s+/g, " ")
		.trim();
	if (!cleaned) return [];
	const hits = cleaned.match(/[A-Za-z_$][A-Za-z0-9_$.]*(?:\s*\([^()]*\))?/g) ?? [];
	return hits
		.map((s) => s.trim())
		.filter(
			(s) =>
				s.length > 1 &&
				!/^(?:async|function|req|res|next|ctx|reply|request|response|c|w|r|err|true|false|null|undefined|return)$/.test(
					s,
				),
		)
		.slice(0, 8);
}

function hasAuthInSnippet(text: string): boolean {
	if (!text) return false;
	if (EXPLICIT_PUBLIC_EXEMPT_RE.test(text) && !AUTH_IDENTIFIER_RE.test(text.replace(EXPLICIT_PUBLIC_EXEMPT_RE, ""))) {
		return false;
	}
	return AUTH_IDENTIFIER_RE.test(text);
}

/**
 * 从左括号 `(` 起始偏移处执行括号平衡扫描（自动跳过引号/反引号字符串字面量），
 * 返回匹配的右括号之前的内部参数子串与结束位置，彻底避免中间件调用 `auth()` 内嵌括号截断。
 */
function extractBalancedParens(
	src: string,
	openParenIdx: number,
	maxScanChars = 2400,
	rawBacktick = false,
): { inner: string; endIdx: number } | null {
	if (src[openParenIdx] !== "(") return null;
	const limit = Math.min(src.length, openParenIdx + maxScanChars);
	let depth = 1;
	let quote: string | null = null;

	for (let i = openParenIdx + 1; i < limit; i++) {
		const ch = src[i]!;
		if (quote) {
			if ((quote !== "`" || !rawBacktick) && ch === "\\") {
				i++;
				continue;
			}
			if (quote !== "`" && (ch === "\n" || ch === "\r")) {
				quote = null;
				continue;
			}
			if (ch === quote) {
				quote = null;
			}
			continue;
		}
		if (ch === "'" || ch === '"' || ch === "`") {
			quote = ch;
			continue;
		}
		if (ch === "(") {
			depth++;
		} else if (ch === ")") {
			depth--;
			if (depth === 0) {
				return {
					inner: src.slice(openParenIdx + 1, i),
					endIdx: i,
				};
			}
		}
	}
	return null;
}

/** 按括号深度为 0 的顶层逗号切分调用参数列表（保留内嵌函数调用如 `requireAuth()` 完整性）。 */
function splitTopLevelArgs(inner: string): string[] {
	const parts: string[] = [];
	let start = 0;
	let depth = 0;
	let quote: string | null = null;

	for (let i = 0; i < inner.length; i++) {
		const ch = inner[i]!;
		if (quote) {
			if (ch === "\\") {
				i++;
				continue;
			}
			if (quote !== "`" && (ch === "\n" || ch === "\r")) {
				quote = null;
				continue;
			}
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === "'" || ch === '"' || ch === "`") {
			quote = ch;
			continue;
		}
		if (ch === "(" || ch === "[" || ch === "{") depth++;
		else if (ch === ")" || ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
		else if (ch === "," && depth === 0) {
			parts.push(inner.slice(start, i).trim());
			start = i + 1;
		}
	}
	const tail = inner.slice(start).trim();
	if (tail) parts.push(tail);
	return parts;
}

/** 剥离 JS/TS 路由调用末尾处理器函数体 `{ ... }`，仅保留中间件列表与路由选项头（如 Fastify `{ preHandler }`）。 */
function extractMiddlewareHeaderPortion(restArgs: string): string {
	const arrowIdx = restArgs.search(/=>\s*\{|\bfunction\b[^{]*\{/);
	if (arrowIdx >= 0) {
		return restArgs.slice(0, arrowIdx);
	}
	return restArgs;
}

/** 提取函数或箭头声明起始位置后的首个平衡花括号块 `{ ... }`（或截断至下一个顶层路由导出），防止跨函数串扰。 */
function extractScopedFunctionBody(src: string, startIdx: number, maxScanChars = 3200): string {
	const limit = Math.min(src.length, startIdx + maxScanChars);
	const nextExportRe =
		/\n\s*export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/g;
	nextExportRe.lastIndex = startIdx + 6;
	const nextMatch = nextExportRe.exec(src);
	const hardEnd = nextMatch ? Math.min(limit, nextMatch.index) : limit;

	let openBrace = -1;
	let parenDepth = 0;
	for (let i = startIdx; i < hardEnd; i++) {
		const ch = src[i]!;
		if (ch === "(") parenDepth++;
		else if (ch === ")" && parenDepth > 0) parenDepth--;
		else if (ch === "{" && parenDepth === 0) {
			openBrace = i;
			break;
		}
	}
	if (openBrace < 0) return src.slice(startIdx, hardEnd);

	let depth = 1;
	let quote: string | null = null;
	for (let i = openBrace + 1; i < hardEnd; i++) {
		const ch = src[i]!;
		if (quote) {
			if (ch === "\\") {
				i++;
				continue;
			}
			if (ch === quote) quote = null;
			continue;
		}
		if (ch === "'" || ch === '"' || ch === "`") {
			quote = ch;
			continue;
		}
		if (ch === "{") depth++;
		else if (ch === "}") {
			depth--;
			if (depth === 0) {
				return src.slice(startIdx, i + 1);
			}
		}
	}
	return src.slice(startIdx, hardEnd);
}

// ==================== 各语言路由静态提取器 ====================

function deriveNextJsAppRoutePath(relFile: string): string | null {
	const norm = relFile.replace(/\\/g, "/");
	const m = /(?:^|\/)app\/(.*\/)?route\.(?:ts|tsx|js|jsx|mjs)$/.exec(norm);
	if (!m) return null;
	const rawMiddle = m[1] ?? "";
	const segments = rawMiddle
		.split("/")
		.filter(Boolean)
		// 剥离 Next.js App Router 路由组 `(marketing)` 与平行路由槽 `@modal`
		.filter((seg) => !(seg.startsWith("(") && seg.endsWith(")")) && !seg.startsWith("@"));
	return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

function extractJsTsRoutes(
	file: string,
	content: string,
	lang: "typescript" | "javascript",
	lineStarts: number[],
	sourceMapOrigin?: string,
): ExtractedRoute[] {
	const routes: ExtractedRoute[] = [];

	// 1. Next.js App Router 文件约定路由：`app/**/route.{ts,js,tsx,jsx}`
	const nextAppPath = deriveNextJsAppRoutePath(file);
	if (nextAppPath !== null) {
		const exportMethodRe =
			/\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*\(|\bexport\s+const\s+(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*=/g;
		for (const match of content.matchAll(exportMethodRe)) {
			const method = (match[1] ?? match[2] ?? "GET").toUpperCase();
			const startIdx = match.index ?? 0;
			const line = offsetToLineNumber(lineStarts, startIdx);
			// 精确提取当前 HTTP 方法导出函数自身的作用域块，避免跨进同文件相邻导出方法造成误判
			const bodyWindow = extractScopedFunctionBody(content, startIdx, 3200);
			const hasAuth =
				hasAuthInSnippet(bodyWindow) ||
				/\b(?:headers|cookies)\s*\(\s*\)[\s\S]{0,200}(?:authorization|session|token)/i.test(bodyWindow);
			const middlewares = hasAuth ? ["nextjs-inline-auth"] : [];
			routes.push({
				method,
				path: nextAppPath,
				framework: "nextjs",
				language: lang,
				file,
				line,
				hasAuthMiddleware: hasAuth,
				middlewares,
				riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
				handlerHint: method,
				...(sourceMapOrigin ? { sourceMapOrigin } : {}),
			});
		}
	}

	// 2. Express / Fastify / Koa 路由器实例前缀与全局鉴权中间件扫描
	const hasExpressHint = /\bexpress\b/i.test(content);
	const isKoaFile =
		/(?:['"`](?:koa-router|@koa\/router|koa)['"`]|\bnew\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*)?Router\s*\()/i.test(
			content,
		);
	const isFastifyFile = /\bfastify\b/i.test(content) && !hasExpressHint && !isKoaFile;
	const defaultFramework: DetectedFramework = isFastifyFile
		? "fastify"
		: isKoaFile && !hasExpressHint
			? "koa"
			: "express";

	const routerPrefixes = new Map<string, string>();
	const routerFrameworks = new Map<string, DetectedFramework>();

	// Express Router: const router = express.Router()
	for (const m of content.matchAll(
		/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:express\.)?Router\s*\(/g,
	)) {
		if (m[1]) routerFrameworks.set(m[1], "express");
	}
	// Fastify instance: const app = fastify() / Fastify()
	for (const m of content.matchAll(
		/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*fastify\s*\(/gi,
	)) {
		if (m[1]) routerFrameworks.set(m[1], "fastify");
	}
	// Koa Router: const router = new Router({ prefix: '/api/v1' }) / new KoaRouter(...)
	for (const m of content.matchAll(
		/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*new\s+(?:[A-Za-z_$][A-Za-z0-9_$.]*)?Router\s*\((?:\s*\{([^}]*)\})?/g,
	)) {
		if (m[1]) {
			routerFrameworks.set(m[1], "koa");
			const prefixMatch = m[2] ? /\bprefix\s*:\s*['"`]([^'"`]+)['"`]/.exec(m[2]) : null;
			if (prefixMatch?.[1]) {
				routerPrefixes.set(m[1], prefixMatch[1]);
			}
		}
	}
	// Express 挂载与全局/路径级鉴权中间件扫描（使用括号平衡解析支持 `app.use("/api/admin", requireAuth(), adminRouter)`）
	const routerAuthFromOffset = new Map<string, number>();
	const mountedAuthRouters = new Set<string>();
	const pathScopedAuthGuards: Array<{ receiver: string; prefix: string; offset: number }> = [];

	for (const m of content.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(use|addHook)\s*\(/g)) {
		const objName = m[1]!;
		const methodKind = m[2]!;
		const callOffset = m.index ?? 0;
		const openParenIdx = callOffset + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 2000);
		if (!balanced) continue;

		const topArgs = splitTopLevelArgs(balanced.inner);
		if (topArgs.length === 0) continue;

		const firstArg = topArgs[0]!;
		const pathLitMatch =
			methodKind === "use" ? /^(['"`])(\/[^'"`\r\n]*)\1$/.exec(firstArg) : null;

		if (pathLitMatch) {
			const rawMountPrefix = pathLitMatch[2]!;
			const combinedPrefix = joinUrlRoutePaths(routerPrefixes.get(objName) ?? "", rawMountPrefix);
			const restArgs = topArgs.slice(1);
			if (restArgs.length > 0) {
				const lastArg = restArgs[restArgs.length - 1]!;
				const isPlainRouterId = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(lastArg);
				const middleSlice = restArgs.slice(0, -1).join(", ");
				const parentAlreadyAuthed =
					mountedAuthRouters.has(objName) ||
					(routerAuthFromOffset.get(objName) !== undefined &&
						routerAuthFromOffset.get(objName)! < callOffset);

				if (isPlainRouterId && (restArgs.length >= 2 || !hasAuthInSnippet(lastArg))) {
					routerPrefixes.set(lastArg, combinedPrefix);
					if (parentAlreadyAuthed || hasAuthInSnippet(middleSlice)) {
						mountedAuthRouters.add(lastArg);
					}
				}
				if (hasAuthInSnippet(restArgs.join(", "))) {
					pathScopedAuthGuards.push({
						receiver: objName,
						prefix: combinedPrefix,
						offset: callOffset,
					});
				}
			}
		} else if (hasAuthInSnippet(balanced.inner)) {
			const prev = routerAuthFromOffset.get(objName);
			if (prev === undefined || callOffset < prev) {
				routerAuthFromOffset.set(objName, callOffset);
			}
		}
	}

	// 3. 提取 app/router/fastify.<method>('/path', ...middlewares, handler)（支持嵌套括号中间件与多行配置）
	const routeHeadRe =
		/\b([A-Za-z_$][A-Za-z0-9_$]*)\.(get|post|put|patch|delete|options|head|all)\s*\(/gi;
	for (const m of content.matchAll(routeHeadRe)) {
		const receiver = m[1]!;
		const rawMethod = m[2]!.toUpperCase();
		const callOffset = m.index ?? 0;
		const openParenIdx = callOffset + m[0].length - 1;

		if (/^(?:axios|http|https|got|superagent|client|fetch|headers|map|cache|store|cookies|params|Reflect|Object|formData|searchParams)$/i.test(receiver)) {
			continue;
		}

		const balanced = extractBalancedParens(content, openParenIdx, 3200);
		if (!balanced) continue;

		const argMatch = /^\s*(['"`])(\/[^'"`\r\n]*)\1\s*,\s*([\s\S]+)$/.exec(balanced.inner);
		if (!argMatch) continue;
		const subPath = argMatch[2]!;
		const restArgs = argMatch[3]!;
		const mwPortion = extractMiddlewareHeaderPortion(restArgs);

		const line = offsetToLineNumber(lineStarts, callOffset);
		const prefix = routerPrefixes.get(receiver) ?? "";
		const fullPath = joinUrlRoutePaths(prefix, subPath);

		const inheritedAuthOffset = routerAuthFromOffset.get(receiver);
		const pathGuardMatched = pathScopedAuthGuards.some(
			(g) =>
				g.receiver === receiver &&
				g.offset < callOffset &&
				(fullPath === g.prefix || fullPath.startsWith(`${g.prefix}/`)),
		);
		const inheritedAuth =
			mountedAuthRouters.has(receiver) ||
			(inheritedAuthOffset !== undefined && inheritedAuthOffset < callOffset) ||
			pathGuardMatched;
		const inlineAuth = hasAuthInSnippet(mwPortion);
		const hasAuth = inheritedAuth || inlineAuth;
		const mwTokens = extractMiddlewareTokens(mwPortion);
		if (inheritedAuth) mwTokens.unshift(`${receiver}:inherited-auth`);

		const routeFramework: DetectedFramework =
			routerFrameworks.get(receiver) ??
			(receiver.toLowerCase().includes("fastify")
				? "fastify"
				: receiver.toLowerCase().includes("koa")
					? "koa"
					: defaultFramework);

		routes.push({
			method: rawMethod === "ALL" ? "ALL" : rawMethod,
			path: fullPath,
			framework: routeFramework,
			language: lang,
			file,
			line,
			hasAuthMiddleware: hasAuth,
			middlewares: mwTokens,
			riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
			...(sourceMapOrigin ? { sourceMapOrigin } : {}),
		});
	}

	// 4. Express链式路由：router.route('/items/:id').get(...).post(...)
	const chainedRouteRe =
		/\b([A-Za-z_$][A-Za-z0-9_$]*)\.route\s*\(\s*(['"`])(\/[^'"`\r\n]*)\2\s*\)([\s\S]{1,500}?)(?:;|\r?\n\r?\n|$)/g;
	for (const m of content.matchAll(chainedRouteRe)) {
		const receiver = m[1]!;
		const baseSubPath = m[3]!;
		const chainBody = m[4] ?? "";
		const baseOffset = m.index ?? 0;
		const prefix = routerPrefixes.get(receiver) ?? "";
		const fullPath = joinUrlRoutePaths(prefix, baseSubPath);
		const inheritedAuthOffset = routerAuthFromOffset.get(receiver);
		const inheritedAuth =
			mountedAuthRouters.has(receiver) ||
			(inheritedAuthOffset !== undefined && inheritedAuthOffset < baseOffset);

		for (const sub of chainBody.matchAll(/\.(get|post|put|patch|delete)\s*\(([^)]{1,260})\)/gi)) {
			const method = sub[1]!.toUpperCase();
			const subArgs = sub[2] ?? "";
			const line = offsetToLineNumber(lineStarts, baseOffset + (sub.index ?? 0));
			const hasAuth = inheritedAuth || hasAuthInSnippet(subArgs);
			routes.push({
				method,
				path: fullPath,
				framework: defaultFramework,
				language: lang,
				file,
				line,
				hasAuthMiddleware: hasAuth,
				middlewares: extractMiddlewareTokens(subArgs),
				riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
				...(sourceMapOrigin ? { sourceMapOrigin } : {}),
			});
		}
	}

	return routes;
}

function extractPythonRoutes(
	file: string,
	content: string,
	lineStarts: number[],
	sourceMapOrigin?: string,
): ExtractedRoute[] {
	const routes: ExtractedRoute[] = [];
	const isFastApi = /\b(?:FastAPI|APIRouter|Depends)\b/.test(content);

	// 识别 APIRouter / Blueprint 前缀及路由器级 dependencies（使用括号平衡扫描防止 Depends(...) 内嵌括号截断）
	const routerMeta = new Map<string, { prefix: string; hasAuth: boolean; framework: "fastapi" | "flask" }>();
	for (const m of content.matchAll(
		/\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(APIRouter|Blueprint|FastAPI|Flask)\s*\(/g,
	)) {
		const varName = m[1]!;
		const ctor = m[2]!;
		const openParenIdx = (m.index ?? 0) + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 1000);
		if (!balanced) continue;
		const args = balanced.inner;
		const prefixMatch = /\b(?:url_prefix|prefix)\s*=\s*['"]([^'"]+)['"]/.exec(args);
		routerMeta.set(varName, {
			prefix: prefixMatch?.[1] ?? "",
			hasAuth: hasAuthInSnippet(args),
			framework: ctor === "APIRouter" || ctor === "FastAPI" ? "fastapi" : "flask",
		});
	}

	// 1. Flask / FastAPI 装饰器路由：@app.route('/x', methods=['GET','POST']) 或 @router.get('/x', dependencies=[Depends(...)])
	const pyLines = content.split(/\r?\n/);
	const pyDecoratorHeadRe =
		/@([A-Za-z_][A-Za-z0-9_]*)\.(route|get|post|put|patch|delete|options|head|api_route)\s*\(/gi;
	for (const m of content.matchAll(pyDecoratorHeadRe)) {
		const objName = m[1]!;
		const decMethod = m[2]!.toLowerCase();
		const decOffset = m.index ?? 0;
		const openParenIdx = decOffset + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 1200);
		if (!balanced) continue;

		const pathArgMatch = /^\s*['"]([^'"]+)['"]([\s\S]*)$/.exec(balanced.inner);
		if (!pathArgMatch) continue;
		const subPath = pathArgMatch[1]!;
		const extraArgs = pathArgMatch[2] ?? "";
		const line = offsetToLineNumber(lineStarts, decOffset);
		const endLine = offsetToLineNumber(lineStarts, balanced.endIdx);

		const meta = routerMeta.get(objName);
		const framework: DetectedFramework = meta?.framework ?? (isFastApi ? "fastapi" : "flask");
		const fullPath = joinUrlRoutePaths(meta?.prefix ?? "", subPath);

		let methods = ["GET"];
		if (decMethod === "route" || decMethod === "api_route") {
			const methodsMatch = /\bmethods\s*=\s*\[([^\]]+)\]/.exec(extraArgs);
			if (methodsMatch?.[1]) {
				const parsedMethods = [...methodsMatch[1].matchAll(/['"]([A-Za-z]+)['"]/g)].map((x) =>
					x[1]!.toUpperCase(),
				);
				if (parsedMethods.length > 0) methods = parsedMethods;
			}
		} else {
			methods = [decMethod.toUpperCase()];
		}

		// 严格向上收集紧贴当前路由装饰器的连续 `@` 装饰器行（遇到空行或任何非 `@` 代码行立即停止，杜绝跨函数串扰）
		const prevDecoratorLines: string[] = [];
		for (let r = line - 2; r >= 0; r--) {
			const prevTrimmed = (pyLines[r] ?? "").trim();
			if (!prevTrimmed || !prevTrimmed.startsWith("@")) break;
			if (/^@[A-Za-z_][A-Za-z0-9_]*\.(?:route|get|post|put|patch|delete|options|head|api_route)\s*\(/i.test(prevTrimmed)) {
				break;
			}
			prevDecoratorLines.unshift(prevTrimmed);
		}
		const prevDecorators = prevDecoratorLines.join("\n");

		// 严格向下收集当前视图函数自身的紧邻装饰器、函数参数签名（Depends）与直属函数体，遇下一顶层 `@`/`def`/`class` 立即截断
		const afterScopedLines: string[] = [];
		let seenDef = false;
		let defIndent = 0;
		let sigParenDepth = 0;
		const maxScanRow = Math.min(pyLines.length, endLine + 35);

		for (let r = endLine; r < maxScanRow; r++) {
			const rawRow = pyLines[r] ?? "";
			const trimmedRow = rawRow.trim();

			if (!seenDef) {
				if (!trimmedRow) break;
				if (trimmedRow.startsWith("@")) {
					if (/^@[A-Za-z_][A-Za-z0-9_]*\.(?:route|get|post|put|patch|delete|options|head|api_route)\s*\(/i.test(trimmedRow)) {
						break;
					}
					afterScopedLines.push(trimmedRow);
					continue;
				}
				const defMatch = /^(\s*)(?:async\s+)?def\s+[A-Za-z_][A-Za-z0-9_]*\s*(\([\s\S]*)$/.exec(rawRow);
				if (defMatch) {
					seenDef = true;
					defIndent = (defMatch[1] ?? "").length;
					// 仅纳入参数列表部分 `(...)`，避免视图函数自身命名（如 `def auth_dashboard()`）被误认为鉴权中间件
					afterScopedLines.push(defMatch[2] ?? "");
					for (const ch of rawRow) {
						if (ch === "(") sigParenDepth++;
						else if (ch === ")") sigParenDepth = Math.max(0, sigParenDepth - 1);
					}
					continue;
				}
				break;
			}

			// 已进入当前 def 函数：若仍在跨行函数参数括号内则继续读取
			if (sigParenDepth > 0) {
				afterScopedLines.push(rawRow);
				for (const ch of rawRow) {
					if (ch === "(") sigParenDepth++;
					else if (ch === ")") sigParenDepth = Math.max(0, sigParenDepth - 1);
				}
				continue;
			}

			if (!trimmedRow) continue;
			const rowIndent = rawRow.length - rawRow.trimStart().length;
			if (rowIndent <= defIndent) {
				// 遇到同级或更外层的下一个 @decorator / def / class / 语句，立即终止当前函数作用域
				break;
			}
			afterScopedLines.push(rawRow);
		}
		const boundedAfter = afterScopedLines.join("\n");

		const hasAuth =
			Boolean(meta?.hasAuth) ||
			hasAuthInSnippet(extraArgs) ||
			(prevDecorators.length > 0 && hasAuthInSnippet(prevDecorators)) ||
			hasAuthInSnippet(boundedAfter);

		const middlewares: string[] = [];
		if (meta?.hasAuth) middlewares.push(`${objName}:router-auth`);
		if (hasAuth && middlewares.length === 0) middlewares.push(`${framework}-auth-dependency`);

		for (const method of methods) {
			routes.push({
				method,
				path: fullPath,
				framework,
				language: "python",
				file,
				line,
				hasAuthMiddleware: hasAuth,
				middlewares,
				riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
				...(sourceMapOrigin ? { sourceMapOrigin } : {}),
			});
		}
	}

	// 2. Django urls.py: path('api/orders/<int:pk>/', login_required(views.order_detail)) / re_path(...)
	const djangoHeadRe = /\b(?:path|re_path|url)\s*\(/g;
	for (const m of content.matchAll(djangoHeadRe)) {
		const callOffset = m.index ?? 0;
		const openParenIdx = callOffset + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 800);
		if (!balanced) continue;
		const djMatch = /^\s*r?['"]([^'"]*)['"]\s*,\s*([\s\S]+)$/.exec(balanced.inner);
		if (!djMatch) continue;
		const rawRoute = djMatch[1] ?? "";
		const viewExpr = djMatch[2] ?? "";
		if (/\binclude\s*\(/.test(viewExpr)) continue;
		const normalizedPath = `/${rawRoute.replace(/^\^/, "").replace(/\$$/, "").replace(/^\/+/, "")}`;
		const line = offsetToLineNumber(lineStarts, callOffset);
		const hasAuth = hasAuthInSnippet(viewExpr);
		routes.push({
			method: "ALL",
			path: normalizedPath,
			framework: "django",
			language: "python",
			file,
			line,
			hasAuthMiddleware: hasAuth,
			middlewares: hasAuth ? [viewExpr.split(",")[0]!.trim()] : [],
			riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
			handlerHint: viewExpr.split(",")[0]!.trim(),
			...(sourceMapOrigin ? { sourceMapOrigin } : {}),
		});
	}

	return routes;
}

function extractGoRoutes(
	file: string,
	content: string,
	lineStarts: number[],
	sourceMapOrigin?: string,
): ExtractedRoute[] {
	const routes: ExtractedRoute[] = [];
	const isEcho = /\blabstack\/echo\b|\becho\.New\s*\(/.test(content);

	// 追踪 Gin / Echo 路由分组：v1 := r.Group("/api/v1", AuthMiddleware()) 与 v1.Use(JWTAuth())
	const groupMeta = new Map<string, { prefix: string; hasAuth: boolean; framework: "gin" | "echo" }>();
	for (const m of content.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*([A-Za-z_][A-Za-z0-9_]*)\.Group\s*\(/g)) {
		const groupVar = m[1]!;
		const parentVar = m[2]!;
		const openParenIdx = (m.index ?? 0) + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 600, true);
		if (!balanced) continue;
		const gMatch = /^\s*["`]([^"`]*)["`]([\s\S]*)$/.exec(balanced.inner);
		if (!gMatch) continue;
		const subPrefix = gMatch[1] ?? "";
		const groupArgs = gMatch[2] ?? "";
		const parent = groupMeta.get(parentVar);
		groupMeta.set(groupVar, {
			prefix: joinUrlRoutePaths(parent?.prefix ?? "", subPrefix),
			hasAuth: Boolean(parent?.hasAuth) || hasAuthInSnippet(groupArgs),
			framework: parent?.framework ?? (isEcho ? "echo" : "gin"),
		});
	}

	for (const m of content.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\.Use\s*\(/g)) {
		const groupVar = m[1]!;
		const openParenIdx = (m.index ?? 0) + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 600, true);
		if (!balanced) continue;
		const useArgs = balanced.inner;
		if (hasAuthInSnippet(useArgs)) {
			const existing = groupMeta.get(groupVar);
			if (existing) {
				existing.hasAuth = true;
			} else {
				groupMeta.set(groupVar, {
					prefix: "",
					hasAuth: true,
					framework: isEcho ? "echo" : "gin",
				});
			}
		}
	}

	// 1. Gin / Echo 路由注册：r.GET("/users/:id", AuthMiddleware(), handler)
	const ginEchoHeadRe =
		/\b([A-Za-z_][A-Za-z0-9_]*)\.(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)\s*\(/g;
	for (const m of content.matchAll(ginEchoHeadRe)) {
		const receiver = m[1]!;
		const rawMethod = m[2]!.toUpperCase();
		const callOffset = m.index ?? 0;
		const openParenIdx = callOffset + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 2000, true);
		if (!balanced) continue;

		const argMatch = /^\s*["`]([^"`\r\n]+)["`]\s*,\s*([\s\S]+)$/.exec(balanced.inner);
		if (!argMatch) continue;
		const subPath = argMatch[1]!;
		const handlersText = extractMiddlewareHeaderPortion(argMatch[2]!);
		// 对内联 Go `func(c *gin.Context) { ... }` 剥离函数体，只分析中间件参数列表
		const inlineFuncIdx = handlersText.search(/\bfunc\s*\(/);
		const mwSlice = inlineFuncIdx >= 0 ? handlersText.slice(0, inlineFuncIdx) : handlersText;

		const line = offsetToLineNumber(lineStarts, callOffset);
		const g = groupMeta.get(receiver);
		const framework: DetectedFramework = g?.framework ?? (isEcho ? "echo" : "gin");
		const fullPath = joinUrlRoutePaths(g?.prefix ?? "", subPath);
		const hasAuth = Boolean(g?.hasAuth) || hasAuthInSnippet(mwSlice);
		const mw = extractMiddlewareTokens(mwSlice);
		if (g?.hasAuth) mw.unshift(`${receiver}:group-auth`);

		routes.push({
			method: rawMethod === "ANY" ? "ALL" : rawMethod,
			path: fullPath,
			framework,
			language: "go",
			file,
			line,
			hasAuthMiddleware: hasAuth,
			middlewares: mw,
			riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
			...(sourceMapOrigin ? { sourceMapOrigin } : {}),
		});
	}

	// 2. Go 标准库 net/http（支持传统 "/path" 与 Go 1.22 "POST /path" 路由模式及中间件包装器）
	const netHttpHeadRe = /\b(?:http|[A-Za-z_][A-Za-z0-9_]*)\.(?:HandleFunc|Handle)\s*\(/g;
	for (const m of content.matchAll(netHttpHeadRe)) {
		const callOffset = m.index ?? 0;
		const openParenIdx = callOffset + m[0].length - 1;
		const balanced = extractBalancedParens(content, openParenIdx, 2000, true);
		if (!balanced) continue;

		const nhMatch = /^\s*["`](?:(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+)?(\/[^"`\r\n]*)["`]\s*,\s*([\s\S]+)$/.exec(
			balanced.inner,
		);
		if (!nhMatch) continue;
		const method = (nhMatch[1] ?? "ALL").toUpperCase();
		const routePath = nhMatch[2]!;
		const handlerExpr = nhMatch[3]!;
		const inlineFuncIdx = handlerExpr.search(/\bfunc\s*\(/);
		const wrapperSlice = inlineFuncIdx >= 0 ? handlerExpr.slice(0, inlineFuncIdx) : handlerExpr;

		const line = offsetToLineNumber(lineStarts, callOffset);
		const hasAuth = hasAuthInSnippet(wrapperSlice);
		routes.push({
			method,
			path: routePath,
			framework: "net/http",
			language: "go",
			file,
			line,
			hasAuthMiddleware: hasAuth,
			middlewares: hasAuth ? extractMiddlewareTokens(wrapperSlice) : [],
			riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
			handlerHint: wrapperSlice.trim() || "inline-func",
			...(sourceMapOrigin ? { sourceMapOrigin } : {}),
		});
	}

	return routes;
}

// ==================== 静态不安全代码模式规则扫描 ====================

interface SinkRuleSpec {
	kind: CodeSinkKind;
	severity: "high" | "medium";
	languages: SupportedLanguage[];
	re: RegExp;
	message: string;
}

const STATIC_SINK_RULES: readonly SinkRuleSpec[] = [
	// 1. 未参数化 SQL 查询拼接
	{
		kind: "unparameterized_sql",
		severity: "high",
		languages: ["typescript", "javascript"],
		re: /\b(?:query|execute|exec|raw|all|get)\s*\(\s*(?:`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^`]*\$\{|['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^'"]*['"]\s*\+)/i,
		message: "检测到 SQL 语句使用模板插值或字符串拼接，存在未参数化查询注入风险",
	},
	{
		kind: "unparameterized_sql",
		severity: "high",
		languages: ["python"],
		re: /\b(?:execute|executemany|raw)\s*\(\s*(?:f['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b|['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^'"]*['"]\s*(?:%|\.format\s*\(|\+))/i,
		message: "检测到 Python 数据库查询使用 f-string / % / format 字符串拼接，未使用参数化占位符",
	},
	{
		kind: "unparameterized_sql",
		severity: "high",
		languages: ["go"],
		re: /\b(?:Query|QueryRow|QueryContext|Exec|ExecContext|Raw)\s*\(\s*(?:fmt\.Sprintf\s*\(\s*["`][^"`]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b|["`][^"`]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b[^"`]*["`]\s*\+)/i,
		message: "检测到 Go SQL 查询通过 fmt.Sprintf 或字符串 + 拼接构造，缺少参数化绑定",
	},

	// 2. 动态外部 URL 请求（潜在 SSRF 风险点）
	{
		kind: "dynamic_outbound_url",
		severity: "high",
		languages: ["typescript", "javascript"],
		re: /\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|undici\.request)\s*\(\s*(?:`[^`]*\$\{[^`]+`|(?![\s'"`])(?:req\.|request\.|params\.|query\.|body\.|[A-Za-z_$][A-Za-z0-9_$.]*))/,
		message: "检测到外部 HTTP 请求使用动态变量或插值 URL，需核验目标白名单与内网地址阻断（SSRF 防护）",
	},
	{
		kind: "dynamic_outbound_url",
		severity: "high",
		languages: ["python"],
		re: /\b(?:requests\.(?:get|post|put|delete|request)|httpx\.(?:get|post|request)|urllib\.request\.urlopen)\s*\(\s*(?:f['"][^'"]*\{|(?![\s'"])[A-Za-z_][A-Za-z0-9_.]*)/,
		message: "检测到 Python HTTP 客户端向动态目标发起请求，需核验 URL 协议与私网地址校验",
	},
	{
		kind: "dynamic_outbound_url",
		severity: "high",
		languages: ["go"],
		re: /\bhttp\.(?:Get|Post|Head)\s*\(\s*(?![\s"`])[A-Za-z_][A-Za-z0-9_.()]*|\bhttp\.NewRequest(?:WithContext)?\s*\([^,]+,\s*(?:[^,]+,\s*)?(?![\s"`])(?:fmt\.Sprintf|[A-Za-z_][A-Za-z0-9_.()]*)/,
		message: "检测到 Go net/http 使用动态 URL 发起外连请求，需核验出网白名单防止 SSRF",
	},

	// 3. 未校验路径拼接（潜在目录穿越风险点）
	{
		kind: "unchecked_path_join",
		severity: "medium",
		languages: ["typescript", "javascript"],
		re: /\b(?:readFileSync|readFile|createReadStream|sendFile|unlinkSync|writeFileSync)\s*\(\s*(?:`[^`]*\$\{|[^)]*(?:\+|join\s*\([^)]*(?:req\.|query|params|body|file|name)))/i,
		message: "检测到文件读取/发送操作直接拼接动态路径参数，需核验 realpath 与根目录边界防路径穿越",
	},
	{
		kind: "unchecked_path_join",
		severity: "medium",
		languages: ["python"],
		re: /\b(?:open|send_file|os\.remove)\s*\(\s*(?:f['"][^'"]*\{|[^)]*(?:os\.path\.join|\+)[^)]*(?:request\.|filename|path|file))/i,
		message: "检测到 Python 文件访问拼接外部参数，需使用 realpath / safe_join 校验路径边界",
	},
	{
		kind: "unchecked_path_join",
		severity: "medium",
		languages: ["go"],
		re: /\b(?:os\.ReadFile|ioutil\.ReadFile|os\.Open|http\.ServeFile)\s*\(\s*(?:filepath\.Join\s*\([^)]*(?:Param|Query|FormValue|URL)|[^)"`]*\+)/,
		message: "检测到 Go 文件读取直接拼接请求参数，需校验 Clean/Rel 根目录包含关系",
	},

	// 4. 危险命令/动态代码执行调用
	{
		kind: "dangerous_exec_call",
		severity: "high",
		languages: ["typescript", "javascript"],
		re: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|(?![\s'"`])[^)]+)|\b(?:eval|Function)\s*\(\s*(?![\s'"`)\]])/,
		message: "检测到动态 Shell 命令执行或动态代码求值调用，存在命令/代码注入高风险",
	},
	{
		kind: "dangerous_exec_call",
		severity: "high",
		languages: ["python"],
		re: /\bos\.system\s*\(|\bsubprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True|\b(?:eval|exec)\s*\(\s*(?![\s'")\]])/,
		message: "检测到 Python os.system / shell=True 子进程或动态 eval/exec 调用",
	},
	{
		kind: "dangerous_exec_call",
		severity: "high",
		languages: ["go"],
		re: /\bexec\.Command(?:Context)?\s*\(\s*(?:["`](?:sh|bash|cmd|powershell)["`]\s*,\s*["`](?:-c|\/c)["`]|(?![\s"`])(?!ctx\b)[A-Za-z_][A-Za-z0-9_.]*)/,
		message: "检测到 Go exec.Command 通过 sh -c 或动态命令名执行子进程",
	},
];

function scanStaticSinkWarnings(
	file: string,
	content: string,
	lang: SupportedLanguage,
	fileRoutes: ExtractedRoute[],
	sourceMapOrigin?: string,
): CodeSinkWarning[] {
	const warnings: CodeSinkWarning[] = [];
	const lines = content.split(/\r?\n/);
	const sortedRoutes = [...fileRoutes].sort((a, b) => a.line - b.line);

	for (let idx = 0; idx < lines.length; idx++) {
		const rawLine = lines[idx]!;
		const trimmed = rawLine.trim();
		if (isCommentLine(trimmed, lang)) continue;
		const lineNo = idx + 1;

		for (const rule of STATIC_SINK_RULES) {
			if (!rule.languages.includes(lang)) continue;
			if (!rule.re.test(trimmed)) continue;

			// 查找同文件中位于当前行上方最近（距离 <= 120 行）的路由处理器进行上下文绑定
			let nearestRoute: ExtractedRoute | undefined;
			for (const r of sortedRoutes) {
				if (r.line <= lineNo && lineNo - r.line <= 120) {
					nearestRoute = r;
				}
			}

			warnings.push({
				kind: rule.kind,
				severity: rule.severity,
				file,
				line: lineNo,
				snippet: trimmed.slice(0, 220),
				message: rule.message,
				language: lang,
				...(nearestRoute
					? {
							relatedRoute: {
								method: nearestRoute.method,
								path: nearestRoute.path,
								line: nearestRoute.line,
							},
						}
					: {}),
				...(sourceMapOrigin ? { sourceMapOrigin } : {}),
			});

			// 将静态代码风险同步挂载至所属路由的 riskFlags，便于前后端一体化研判
			if (nearestRoute && !nearestRoute.riskFlags.includes(rule.kind)) {
				nearestRoute.riskFlags.push(rule.kind);
			}
		}
	}

	return warnings;
}

// ==================== 1. SourceMap 与源码攻击面提取 ====================

function extractClientApiRoutesFromSourceMapSource(
	file: string,
	content: string,
	lang: "typescript" | "javascript",
	lineStarts: number[],
	sourceMapOrigin?: string,
): ExtractedRoute[] {
	const routes: ExtractedRoute[] = [];
	const seen = new Set<string>();

	// 从前端/全栈 SourceMap 还原代码中识别显式 API 路径调用（如 fetch('/api/admin/export', { method: 'POST' })）
	const clientApiRe =
		/\b(?:fetch|axios(?:\.(get|post|put|patch|delete))?)\s*\(\s*(['"`])(\/(?:api|admin|internal|v\d+|debug|graphql)[^'"`\s?#]*)\2([\s\S]{0,220}?\))?/gi;
	for (const m of content.matchAll(clientApiRe)) {
		const axiosVerb = m[1]?.toUpperCase();
		const apiPath = m[3]!;
		const tailOpts = m[4] ?? "";
		const methodMatch = /\bmethod\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE)['"`]/i.exec(tailOpts);
		const method = methodMatch?.[1]?.toUpperCase() ?? axiosVerb ?? "GET";
		const key = `${method} ${apiPath}`;
		if (seen.has(key)) continue;
		seen.add(key);

		const line = offsetToLineNumber(lineStarts, m.index ?? 0);
		const hasAuth =
			/\b(?:Authorization|Bearer|x-api-key|x-auth-token|credentials\s*:\s*['"`]include['"`])\b/i.test(
				tailOpts,
			);
		routes.push({
			method,
			path: apiPath,
			framework: "sourcemap-client",
			language: lang,
			file,
			line,
			hasAuthMiddleware: hasAuth,
			middlewares: hasAuth ? ["client-auth-header"] : [],
			riskFlags: hasAuth ? [] : ["missing_auth_middleware"],
			...(sourceMapOrigin ? { sourceMapOrigin } : {}),
		});
	}

	return routes;
}

/**
 * 安全解析 `.js.map` SourceMap JSON 字符串或对象：
 * 提取 `sources` 与 `sourcesContent`（自动过滤第三方 `node_modules` 并清洗防穿越虚拟路径），
 * 执行与本地源码完全一致的静态路由审计与不安全代码模式检测。
 */
export function extractFromSourceMap(
	rawJson: string | Record<string, unknown>,
	sourceUrl?: string,
	opts?: ExtractSurfaceOptions,
): CodeAttackSurface {
	let parsed: Record<string, unknown>;
	try {
		parsed =
			typeof rawJson === "string"
				? (JSON.parse(rawJson) as Record<string, unknown>)
				: rawJson;
	} catch {
		return buildSurfaceSummary([], [], 0, 0);
	}

	if (!parsed || typeof parsed !== "object") {
		return buildSurfaceSummary([], [], 0, 0);
	}

	const sources = Array.isArray(parsed.sources) ? parsed.sources : [];
	const sourcesContent = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];
	const virtualFiles: VirtualSourceFile[] = [];

	const count = Math.min(sources.length, sourcesContent.length);
	for (let i = 0; i < count; i++) {
		const rawPath = typeof sources[i] === "string" ? (sources[i] as string) : `source_${i}.js`;
		const rawCode = sourcesContent[i];
		if (typeof rawCode !== "string" || !rawCode.trim()) continue;

		const safeRelPath = normalizePosixRelPath(rawPath);
		if (
			safeRelPath.includes("node_modules/") ||
			safeRelPath.startsWith("webpack/runtime") ||
			safeRelPath.startsWith("vite/")
		) {
			continue;
		}

		// 若虚拟路径无常见代码后缀，默认按 .ts 解析以便覆盖 TS/JS 语法
		const hasKnownExt = Boolean(detectLanguageByPath(safeRelPath));
		virtualFiles.push({
			path: hasKnownExt ? safeRelPath : `${safeRelPath}.ts`,
			content: rawCode,
			sourceMapOrigin: sourceUrl ?? "inline.js.map",
		});
	}

	const baseSurface = analyzeVirtualFiles(virtualFiles, {
		...opts,
		includeClientApiHintsInSourceMap: opts?.includeClientApiHintsInSourceMap ?? true,
	});
	return {
		...baseSurface,
		sourceMapsParsed: 1,
	};
}

function collectFilesFromDirectory(
	rootDir: string,
	ignoredDirs: Set<string>,
	maxFileBytes: number,
): string[] {
	const absRoot = resolve(rootDir);
	if (!existsSync(absRoot)) return [];

	let rootStat;
	try {
		rootStat = lstatSync(absRoot);
	} catch {
		return [];
	}

	if (rootStat.isSymbolicLink()) return [];
	if (rootStat.isFile()) {
		return rootStat.size <= maxFileBytes ? [absRoot] : [];
	}
	if (!rootStat.isDirectory()) return [];

	const collected: string[] = [];
	const stack: string[] = [absRoot];

	while (stack.length > 0) {
		const currentDir = stack.pop()!;
		let entries;
		try {
			entries = readdirSync(currentDir, { withFileTypes: true });
		} catch {
			continue;
		}

		entries.sort((a, b) => a.name.localeCompare(b.name));
		for (const entry of entries) {
			const fullPath = join(currentDir, entry.name);
			let st;
			try {
				st = lstatSync(fullPath);
			} catch {
				continue;
			}
			// 跳过符号链接防止目录环路与越界文件读取
			if (st.isSymbolicLink()) continue;

			if (st.isDirectory()) {
				if (!ignoredDirs.has(entry.name)) {
					stack.push(fullPath);
				}
				continue;
			}

			if (!st.isFile() || st.size > maxFileBytes) continue;
			const lowerName = entry.name.toLowerCase();
			const ext = extname(lowerName);
			if (SUPPORTED_SOURCE_EXTS.has(ext) || lowerName.endsWith(".js.map")) {
				collected.push(fullPath);
			}
		}
	}

	return collected.sort();
}

function buildSurfaceSummary(
	routes: ExtractedRoute[],
	warnings: CodeSinkWarning[],
	scannedFiles: number,
	sourceMapsParsed: number,
): CodeAttackSurface {
	const byFramework: Record<string, number> = {};
	let unauthenticatedRoutes = 0;
	for (const r of routes) {
		byFramework[r.framework] = (byFramework[r.framework] ?? 0) + 1;
		if (!r.hasAuthMiddleware) unauthenticatedRoutes++;
	}
	return {
		scannedFiles,
		routes,
		warnings,
		sourceMapsParsed,
		summary: {
			totalRoutes: routes.length,
			unauthenticatedRoutes,
			totalWarnings: warnings.length,
			byFramework,
		},
	};
}

function analyzeVirtualFiles(
	files: VirtualSourceFile[],
	opts?: ExtractSurfaceOptions,
): CodeAttackSurface {
	const allRoutes: ExtractedRoute[] = [];
	const allWarnings: CodeSinkWarning[] = [];
	let scannedFiles = 0;
	let sourceMapsParsed = 0;

	for (const vf of files) {
		const normPath = vf.path.replace(/\\/g, "/");
		if (
			(opts?.includeSourceMaps ?? true) &&
			(normPath.endsWith(".js.map") || normPath.endsWith(".mjs.map") || normPath.endsWith(".map"))
		) {
			const sub = extractFromSourceMap(vf.content, vf.sourceMapOrigin ?? normPath, opts);
			scannedFiles += sub.scannedFiles;
			sourceMapsParsed += sub.sourceMapsParsed;
			allRoutes.push(...sub.routes);
			allWarnings.push(...sub.warnings);
			continue;
		}

		const lang = detectLanguageByPath(normPath);
		if (!lang) continue;
		scannedFiles++;

		const lineStarts = buildLineStarts(vf.content);
		const codeWithoutComments = stripCommentsPreservingOffsets(vf.content, lang);
		let fileRoutes: ExtractedRoute[] = [];
		if (lang === "typescript" || lang === "javascript") {
			fileRoutes = extractJsTsRoutes(
				normPath,
				codeWithoutComments,
				lang,
				lineStarts,
				vf.sourceMapOrigin,
			);
			if (vf.sourceMapOrigin && (opts?.includeClientApiHintsInSourceMap ?? true)) {
				const existingKeys = new Set(fileRoutes.map((r) => `${r.method} ${r.path}`));
				const clientHints = extractClientApiRoutesFromSourceMapSource(
					normPath,
					codeWithoutComments,
					lang,
					lineStarts,
					vf.sourceMapOrigin,
				);
				for (const ch of clientHints) {
					if (!existingKeys.has(`${ch.method} ${ch.path}`)) {
						fileRoutes.push(ch);
					}
				}
			}
		} else if (lang === "python") {
			fileRoutes = extractPythonRoutes(
				normPath,
				codeWithoutComments,
				lineStarts,
				vf.sourceMapOrigin,
			);
		} else if (lang === "go") {
			fileRoutes = extractGoRoutes(
				normPath,
				codeWithoutComments,
				lineStarts,
				vf.sourceMapOrigin,
			);
		}

		const fileWarnings = scanStaticSinkWarnings(
			normPath,
			codeWithoutComments,
			lang,
			fileRoutes,
			vf.sourceMapOrigin,
		);

		allRoutes.push(...fileRoutes);
		allWarnings.push(...fileWarnings);
	}

	return buildSurfaceSummary(allRoutes, allWarnings, scannedFiles, sourceMapsParsed);
}

/**
 * 递归分析本地代码目录、文件列表或内存虚拟源码映射，提取多语言路由表、鉴权状态与高风险代码模式告警。
 */
export function extractCodeAttackSurface(
	targetDirOrFiles: CodeSurfaceInput,
	opts?: ExtractSurfaceOptions,
): CodeAttackSurface {
	const ignoredDirs = new Set([...DEFAULT_IGNORED_DIRS, ...(opts?.ignoreDirs ?? [])]);
	const maxFileBytes = opts?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;

	// 形态 1：内存对象映射 Record<filePath, sourceCode>
	if (
		targetDirOrFiles &&
		typeof targetDirOrFiles === "object" &&
		!Array.isArray(targetDirOrFiles)
	) {
		const virtualFiles: VirtualSourceFile[] = Object.entries(targetDirOrFiles).map(
			([filePath, content]) => ({
				path: normalizePosixRelPath(filePath),
				content: String(content ?? ""),
			}),
		);
		return analyzeVirtualFiles(virtualFiles, opts);
	}

	// 形态 2：VirtualSourceFile[] 数组
	if (
		Array.isArray(targetDirOrFiles) &&
		targetDirOrFiles.length > 0 &&
		typeof targetDirOrFiles[0] === "object"
	) {
		return analyzeVirtualFiles(targetDirOrFiles as VirtualSourceFile[], opts);
	}

	// 形态 3：本地目录路径或文件路径数组
	let baseRoot = "";
	let absFiles: string[] = [];

	if (typeof targetDirOrFiles === "string") {
		const resolved = resolve(targetDirOrFiles);
		if (!existsSync(resolved)) {
			return buildSurfaceSummary([], [], 0, 0);
		}
		const st = lstatSync(resolved);
		baseRoot = st.isDirectory() ? resolved : resolve(resolved, "..");
		absFiles = collectFilesFromDirectory(resolved, ignoredDirs, maxFileBytes);
	} else if (Array.isArray(targetDirOrFiles)) {
		const strPaths = targetDirOrFiles as string[];
		for (const p of strPaths) {
			const resolved = resolve(p);
			if (!baseRoot) baseRoot = resolve(resolved, "..");
			absFiles.push(...collectFilesFromDirectory(resolved, ignoredDirs, maxFileBytes));
		}
	}

	const virtualFiles: VirtualSourceFile[] = [];
	for (const absPath of absFiles) {
		let content = "";
		try {
			content = readFileSync(absPath, "utf8");
		} catch {
			continue;
		}
		const rel = baseRoot ? relative(baseRoot, absPath).replace(/\\/g, "/") : basename(absPath);
		virtualFiles.push({
			path: rel && !rel.startsWith("..") ? rel : basename(absPath),
			content,
		});
	}

	return analyzeVirtualFiles(virtualFiles, opts);
}

// ==================== 2. 白盒审计 -> 黑盒合规核验意图桥接 ====================

function materializeSampleRoutePath(routePath: string): string {
	return routePath
		.replace(/\[\.\.\.([A-Za-z0-9_]+)\]/g, "sample")
		.replace(/\[([A-Za-z0-9_]+)\]/g, "1")
		.replace(/<(?:int|slug|uuid|str|path):([A-Za-z0-9_]+)>/g, "1")
		.replace(/<([A-Za-z0-9_]+)>/g, "1")
		.replace(/\{([A-Za-z0-9_]+)\}/g, "1")
		.replace(/:([A-Za-z0-9_]+)/g, "1")
		.replace(/\*([A-Za-z0-9_]*)/g, "sample");
}

function buildAdviceForRisk(risk: RouteRiskFlag, method: string, routePath: string, anchor: string): string {
	switch (risk) {
		case "missing_auth_middleware":
			return `源码锚点 ${anchor} 定义的路由 ${method} ${routePath} 未检测到鉴权中间件。建议在授权 Scope 内使用只读契约校验（auth_strip / 无凭据请求）核验接口是否按预期返回 401/403，严禁执行破坏性写操作。`;
		case "unparameterized_sql":
			return `源码锚点 ${anchor} 存在未参数化 SQL 拼接特征。建议通过纯良性类型边界输入对比响应状态码与错误信封一致性，并推动源码改为参数化预编译绑定。`;
		case "dynamic_outbound_url":
			return `源码锚点 ${anchor} 存在动态外部 URL 请求特征。建议仅使用授权受控回路/OOB Canary 地址验证服务端是否校验出网协议与私网地址白名单。`;
		case "unchecked_path_join":
			return `源码锚点 ${anchor} 存在未校验路径拼接特征。建议核验服务端是否对文件参数执行 realpath 根目录前缀约束并返回 400/403。`;
		case "dangerous_exec_call":
			return `源码锚点 ${anchor} 存在动态 Shell / 代码执行调用。建议优先开展静态数据流复核与沙盒只读契约校验，消除 shell=True / sh -c 拼接。`;
	}
}

/**
 * 将静态源码审计检出的缺鉴权路由与高风险代码点转化为结构化、去重的黑盒待核验意图清单与假设节点描述。
 */
export function bridgeWhiteboxToBlackboxIntents(
	surface: CodeAttackSurface,
	baseUrl: string,
	opts?: WhiteboxBridgeOptions,
): WhiteboxBridgeResult {
	const normalizedBase = String(baseUrl || "http://127.0.0.1").replace(/\/+$/, "");
	const phase: Phase = opts?.phase ?? "vuln";
	const includePublicHealth = opts?.includePublicHealthRoutes ?? false;
	const includeUnbound = opts?.includeUnboundWarnings ?? true;

	const intents: HybridVerificationIntentSpec[] = [];
	const hypotheses: HybridHypothesisSpec[] = [];
	const seenKeys = new Set<string>();
	let skippedCount = 0;
	let hypCounter = 0;

	const addBridgedItem = (params: {
		method: string;
		routePath: string;
		file: string;
		line: number;
		framework?: DetectedFramework;
		risk: RouteRiskFlag;
		extraNote?: string;
	}) => {
		const normMethod = params.method === "ALL" ? "GET" : params.method.toUpperCase();
		const dedupSig = `${normMethod}|${params.routePath}|${params.risk}`;
		if (seenKeys.has(dedupSig)) {
			skippedCount++;
			return;
		}
		seenKeys.add(dedupSig);

		const shortHash = createHash("sha256").update(dedupSig).digest("hex").slice(0, 8);
		const intentKey = `hybrid:${params.risk}:${normMethod}:${params.routePath}:${shortHash}`;
		const hypId = `hyp_hybrid_${String(++hypCounter).padStart(3, "0")}`;
		const anchor = `${params.file}:${params.line}`;
		const concretePath = materializeSampleRoutePath(params.routePath);
		const fullUrl = `${normalizedBase}${concretePath.startsWith("/") ? concretePath : `/${concretePath}`}`;
		const advice = buildAdviceForRisk(params.risk, normMethod, params.routePath, anchor);

		const isHighPriorityPath = /\/(?:admin|internal|debug|export|config|users|orders|transfer|graphql)/i.test(
			params.routePath,
		);
		const basePriority =
			params.risk === "missing_auth_middleware"
				? isHighPriorityPath
					? 92
					: 84
				: 90;

		const title =
			params.risk === "missing_auth_middleware"
				? `[白盒协同] 核验未绑定鉴权路由 ${normMethod} ${params.routePath} (${anchor})`
				: `[白盒协同] 核验静态高风险点 ${params.risk} @ ${normMethod} ${params.routePath} (${anchor})`;

		const detail = [
			`目标 URL: ${fullUrl}`,
			`路由模板: ${normMethod} ${params.routePath}${params.framework ? ` [${params.framework}]` : ""}`,
			`源码锚点: ${anchor}`,
			`风险类别: ${params.risk}`,
			...(params.extraNote ? [`静态摘要: ${params.extraNote}`] : []),
			`验证建议: ${advice}`,
		].join("\n");

		intents.push({
			key: intentKey,
			phase,
			title,
			detail,
			priority: basePriority,
			expectedKind: "vuln",
			surfaceDomain: "path",
			targetKey: `${normMethod} ${params.routePath}`,
			method: normMethod,
			path: params.routePath,
			url: fullUrl,
			file: params.file,
			line: params.line,
			anchor,
			...(params.framework ? { framework: params.framework } : {}),
			riskCategory: params.risk,
			verificationAdvice: advice,
			hypothesisId: hypId,
		});

		hypotheses.push({
			id: hypId,
			title: `静态审计假设: ${normMethod} ${params.routePath} 存在 ${params.risk}`,
			statement: `静态代码分析在 ${anchor} 检出 ${params.risk}，假设线上端点 ${fullUrl} 在未授权或边界契约请求下缺乏有效访问控制或输入安全约束。`,
			falsificationTest: `向 ${fullUrl} 发送授权 Scope 内的纯只读合规契约探针；若返回 401/403/404 或严格参数校验拒绝，则证伪该风险假设。`,
			expectedGain: isHighPriorityPath ? 90 : 75,
			estimatedCost: 15,
			status: "open",
			file: params.file,
			line: params.line,
			anchor,
			linkedIntentKeys: [intentKey],
		});
	};

	// 1. 桥接缺少鉴权中间件的路由
	for (const route of surface.routes) {
		if (!route.hasAuthMiddleware) {
			if (!includePublicHealth && LIFECYCLE_PUBLIC_PATH_RE.test(route.path)) {
				skippedCount++;
				continue;
			}
			addBridgedItem({
				method: route.method,
				routePath: route.path,
				file: route.file,
				line: route.line,
				framework: route.framework,
				risk: "missing_auth_middleware",
			});
		}
	}

	// 2. 桥接静态高风险 Sink 告警（优先关联同文件路由端点）
	for (const warn of surface.warnings) {
		if (warn.relatedRoute) {
			const matchedRoute = surface.routes.find(
				(r) =>
					r.file === warn.file &&
					r.path === warn.relatedRoute!.path &&
					r.line === warn.relatedRoute!.line,
			);
			addBridgedItem({
				method: warn.relatedRoute.method,
				routePath: warn.relatedRoute.path,
				file: warn.file,
				line: warn.line,
				framework: matchedRoute?.framework,
				risk: warn.kind,
				extraNote: warn.snippet,
			});
		} else if (includeUnbound) {
			// 同文件若仅有一个路由则自动关联，否则以模块路径作为待核验目标锚点
			const sameFileRoutes = surface.routes.filter((r) => r.file === warn.file);
			if (sameFileRoutes.length === 1) {
				const r = sameFileRoutes[0]!;
				addBridgedItem({
					method: r.method,
					routePath: r.path,
					file: warn.file,
					line: warn.line,
					framework: r.framework,
					risk: warn.kind,
					extraNote: warn.snippet,
				});
			} else {
				addBridgedItem({
					method: "GET",
					routePath: `/__source_sink__/${warn.file}`,
					file: warn.file,
					line: warn.line,
					risk: warn.kind,
					extraNote: warn.snippet,
				});
			}
		} else {
			skippedCount++;
		}
	}

	intents.sort((a, b) => b.priority - a.priority || a.anchor.localeCompare(b.anchor));

	return {
		baseUrl: normalizedBase,
		intents,
		hypotheses,
		skippedCount,
	};
}

// ==================== 3. 黑盒异常发现 -> 静态源码行号锚点反向定位 ====================

function cleanComparablePath(rawPath: string): string {
	const withoutQuery = (rawPath.split(/[?#]/)[0] ?? "/").trim();
	const withSlash = withoutQuery.startsWith("/") ? withoutQuery : `/${withoutQuery}`;
	return withSlash.length > 1 ? withSlash.replace(/\/+$/, "") : "/";
}

function compileRouteTemplateRegex(routeTemplate: string): RegExp {
	const clean = cleanComparablePath(routeTemplate);
	if (clean === "/") return /^\/$/;

	const segPatterns = clean
		.split("/")
		.filter(Boolean)
		.map((seg) => {
			// Next.js catch-all [...slug] / [[...slug]] 或 Gin *filepath
			if (/^\[\[?\.\.\.[A-Za-z0-9_]+\]?\]$/.test(seg) || /^\*[A-Za-z0-9_]*$/.test(seg)) {
				return ".+";
			}
			// Express/Gin/Echo `:id`、Next.js `[id]`、FastAPI/Go `{id}`、Django `<int:pk>` / `<pk>`
			if (
				/^:[A-Za-z0-9_]+$/.test(seg) ||
				/^\[[A-Za-z0-9_]+\]$/.test(seg) ||
				/^\{[A-Za-z0-9_:]+\}$/.test(seg) ||
				/^<(?:[A-Za-z0-9_]+:)?[A-Za-z0-9_]+>$/.test(seg)
			) {
				return "[^/]+";
			}
			return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
		});

	return new RegExp(`^/${segPatterns.join("/")}$`, "i");
}

function extractMethodAndPathFromFinding(finding: BlackboxFindingLike): {
	method?: string;
	path?: string;
	textBlob: string;
} {
	const obj = finding as Record<string, unknown>;
	let method = typeof obj.method === "string" ? obj.method.trim().toUpperCase() : undefined;
	let path: string | undefined;

	if (typeof obj.path === "string" && obj.path.trim()) {
		path = cleanComparablePath(obj.path);
	}

	if (!path && typeof obj.url === "string" && obj.url.trim()) {
		try {
			path = cleanComparablePath(new URL(obj.url).pathname);
		} catch {
			if (obj.url.startsWith("/")) path = cleanComparablePath(obj.url);
		}
	}

	if (typeof obj.targetKey === "string" && obj.targetKey.trim()) {
		// 兼容剥离女娲标准表面分域前缀（如 "path:/api/admin/export"、"endpoint:GET /api/x"、"route:/v1/items"）
		const tk = obj.targetKey
			.trim()
			.replace(/^(?:path|endpoint|route|api|url):+/i, "")
			.trim();
		const m = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S*)/i.exec(tk);
		if (m) {
			if (!method) method = m[1]!.toUpperCase();
			if (!path) path = cleanComparablePath(m[2]!);
		} else if (!path && tk.startsWith("/")) {
			path = cleanComparablePath(tk);
		} else if (!path && /^https?:\/\//i.test(tk)) {
			try {
				path = cleanComparablePath(new URL(tk).pathname);
			} catch {
				/* ignore */
			}
		}
	}

	const textBlob = [obj.title, obj.detail, obj.command, obj.targetKey]
		.filter((x): x is string => typeof x === "string" && x.length > 0)
		.join("\n");

	if (!path && textBlob) {
		const urlMatch = /https?:\/\/[^/\s'"]+(\/[^\s'"?#]*)/i.exec(textBlob);
		if (urlMatch?.[1]) {
			path = cleanComparablePath(urlMatch[1]);
		} else {
			const methodPathMatch = /\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_./:-]+)/i.exec(textBlob);
			if (methodPathMatch) {
				if (!method) method = methodPathMatch[1]!.toUpperCase();
				path = cleanComparablePath(methodPathMatch[2]!);
			}
		}
	}

	if (!method && textBlob) {
		const m = /\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/.exec(textBlob);
		if (m?.[1]) method = m[1].toUpperCase();
	}

	return { method, path, textBlob };
}

/**
 * 将黑盒动态核验确认的异常接口（Fact、MutationAnomaly 或 URL/路径描述）
 * 反向映射回静态源码表中的精确文件、行号锚点与邻近高危代码模式告警。
 */
export function correlateBlackboxFindingToSource(
	finding: BlackboxFindingLike,
	surface: CodeAttackSurface,
): SourceCorrelationResult {
	const { method, path, textBlob } = extractMethodAndPathFromFinding(finding);
	if (!path) {
		return {
			matched: false,
			confidence: "none",
			score: 0,
			relatedWarnings: [],
			candidates: [],
		};
	}

	const scored: Array<{ candidate: SourceCorrelationCandidate; route: ExtractedRoute }> = [];

	for (const route of surface.routes) {
		const normRoutePath = cleanComparablePath(route.path);
		const methodExact =
			!method || route.method === "ALL" || route.method.toUpperCase() === method.toUpperCase();

		let matchType: "exact" | "route_param" | "path_only" | null = null;
		let baseScore = 0;

		if (normRoutePath.toLowerCase() === path.toLowerCase()) {
			matchType = methodExact ? "exact" : "path_only";
			baseScore = methodExact ? 1.0 : 0.78;
		} else {
			const paramRe = compileRouteTemplateRegex(normRoutePath);
			if (paramRe.test(path)) {
				matchType = methodExact ? "route_param" : "path_only";
				baseScore = methodExact ? 0.92 : 0.72;
			}
		}

		if (!matchType) continue;

		// 服务端真实路由框架优先于 sourcemap 客户端调用线索
		const frameworkBonus = route.framework === "sourcemap-client" ? -0.05 : 0.02;
		const riskBonus = !route.hasAuthMiddleware ? 0.02 : 0;
		const finalScore = Number(Math.min(1, Math.max(0, baseScore + frameworkBonus + riskBonus)).toFixed(4));

		scored.push({
			route,
			candidate: {
				file: route.file,
				line: route.line,
				anchor: `${route.file}:${route.line}`,
				method: route.method,
				routePath: route.path,
				framework: route.framework,
				matchType,
				score: finalScore,
				hasAuthMiddleware: route.hasAuthMiddleware,
				riskFlags: [...route.riskFlags],
			},
		});
	}

	scored.sort(
		(a, b) =>
			b.candidate.score - a.candidate.score ||
			a.candidate.line - b.candidate.line ||
			a.candidate.file.localeCompare(b.candidate.file),
	);

	if (scored.length === 0) {
		// 兜底：若 finding 文本中包含源码文件名，尝试启发式关联静态告警
		const heuristicWarn = surface.warnings.find((w) => textBlob.includes(w.file));
		if (heuristicWarn) {
			return {
				matched: true,
				confidence: "sink_heuristic",
				score: 0.55,
				file: heuristicWarn.file,
				line: heuristicWarn.line,
				anchor: `${heuristicWarn.file}:${heuristicWarn.line}`,
				relatedWarnings: [heuristicWarn],
				candidates: [],
			};
		}
		return {
			matched: false,
			confidence: "none",
			score: 0,
			relatedWarnings: [],
			candidates: [],
		};
	}

	const best = scored[0]!;
	const relatedWarnings = surface.warnings.filter(
		(w) =>
			w.file === best.route.file &&
			((w.relatedRoute &&
				w.relatedRoute.path === best.route.path &&
				w.relatedRoute.line === best.route.line) ||
				(w.line >= best.route.line && w.line - best.route.line <= 120)),
	);

	return {
		matched: true,
		confidence: best.candidate.matchType,
		score: best.candidate.score,
		file: best.route.file,
		line: best.route.line,
		anchor: `${best.route.file}:${best.route.line}`,
		route: best.route,
		relatedWarnings,
		candidates: scored.map((s) => s.candidate),
	};
}
