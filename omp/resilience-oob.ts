/**
 * 女娲 v7.0 韧性层：网关自适应轮换、同构蜜罐陷阱识别与嵌入式带外（OOB）回调关联。
 *
 * 三大职责：
 * 1. `GatewayAdaptiveController` —— 识别 403/429/503 与 Cloudflare / AWS WAF / ModSecurity / Akamai /
 *    Imperva / Sucuri 等网关挑战签名，对出口代理池维护健康分与指数退避冷却窗口，并生成符合正常
 *    HTTP 语义的请求头 / 路径归一化变体（不复用任何伪造头或协议违规技巧）。
 * 2. `IsomorphicTrapDetector` —— 跨多条无关路径统计状态码一致性、Shannon 熵、模板指纹与正文指纹
 *    重合度、误导性高信号关键词密度与延迟单调膨胀，识别“同构蜜罐 / tarpit”并给出熔断建议；
 *    内建校准护栏：4 条基线 404 + 1 条真实 200 的常规站点绝不误报。
 * 3. `EmbeddedOobListener` / `OobCorrelator` —— 基于 `node:http` 的 127.0.0.1:0 临时端口回调监听器，
 *    HMAC 签名 Canary、伪造请求计数丢弃、完整连接回收（`closeAllConnections` + socket 摧毁），
 *    跨轮次延迟回调匹配并输出脱敏证据摘要与高信息熵唤醒信号。
 *
 * 约束：零第三方依赖；严禁运行时 import `./nuwa`；仅复用 `./scope` / `./oob` / `./autoexec` 的安全能力。
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { Socket } from "node:net";

import { computeBodyHash, computeTemplateFingerprint } from "./autoexec";
import type { OobCallbackHit } from "./oob";

type HeaderBag = Record<string, string | string[] | undefined>;
const clamp = (value: number, min: number, max: number): number => (value < min ? min : value > max ? max : value);
const sha256Hex = (input: string): string => createHash("sha256").update(input, "utf8").digest("hex");

/** 纯 TS RFC 2104 HMAC-SHA256，适配精简 `omp/env.d.ts` 中 `node:crypto` 类型约束。 */
function hmacSha256Hex(secret: string, payload: string): string {
	let keyBuf = Buffer.from(secret, "utf8");
	if (keyBuf.length > 64) keyBuf = createHash("sha256").update(keyBuf).digest();
	const ipad = Buffer.alloc(64, 0x36);
	const opad = Buffer.alloc(64, 0x5c);
	for (let i = 0; i < keyBuf.length; i += 1) {
		ipad[i] = (ipad[i] ?? 0) ^ (keyBuf[i] ?? 0);
		opad[i] = (opad[i] ?? 0) ^ (keyBuf[i] ?? 0);
	}
	const inner = createHash("sha256").update(Buffer.concat([ipad, Buffer.from(payload, "utf8")])).digest();
	return createHash("sha256").update(Buffer.concat([opad, inner])).digest("hex");
}

function safeEqual(a: string, b: string): boolean {
	const ba = Buffer.from(a, "utf8");
	const bb = Buffer.from(b, "utf8");
	if (ba.length !== bb.length || ba.length === 0) return false;
	let diff = 0;
	for (let i = 0; i < ba.length; i += 1) diff |= (ba[i] ?? 0) ^ (bb[i] ?? 0);
	return diff === 0;
}

function headerValue(headers: HeaderBag | undefined, name: string): string | undefined {
	if (!headers) return undefined;
	const wanted = name.toLowerCase();
	for (const key of Object.keys(headers)) {
		if (key.toLowerCase() !== wanted) continue;
		const raw = headers[key];
		if (raw === undefined) return undefined;
		return Array.isArray(raw) ? raw.join(", ") : raw;
	}
	return undefined;
}

function headerText(headers: HeaderBag | undefined): string {
	if (!headers) return "";
	const parts: string[] = [];
	for (const key of Object.keys(headers)) {
		const raw = headers[key];
		if (raw === undefined) continue;
		parts.push(`${key.toLowerCase()}: ${Array.isArray(raw) ? raw.join(",") : raw}`);
	}
	return parts.join("\n").toLowerCase();
}

function parseRetryAfterMs(raw: string | undefined, now: number): number | undefined {
	if (!raw) return undefined;
	const text = raw.trim();
	if (!text) return undefined;
	if (/^\d+(?:\.\d+)?$/.test(text)) {
		const secs = Number(text);
		if (!Number.isFinite(secs) || secs < 0) return undefined;
		return Math.round(clamp(secs, 0, 24 * 3600) * 1000);
	}
	const at = Date.parse(text);
	if (!Number.isFinite(at)) return undefined;
	return Math.round(clamp(at - now, 0, 24 * 3600 * 1000));
}

function parseResetWindowMs(raw: string | undefined, now: number): number | undefined {
	if (!raw) return undefined;
	const text = raw.trim();
	if (!text) return undefined;
	if (!/^\d+(?:\.\d+)?$/.test(text)) {
		const at = Date.parse(text);
		return Number.isFinite(at) ? Math.round(clamp(at - now, 0, 24 * 3600 * 1000)) : undefined;
	}
	const num = Number(text);
	if (!Number.isFinite(num) || num < 0) return undefined;
	const looksEpochMs = text.length === 13;
	const looksEpochSec = text.length === 10;
	if (looksEpochMs) return Math.round(clamp(num - now, 0, 24 * 3600 * 1000));
	if (looksEpochSec) return Math.round(clamp(num * 1000 - now, 0, 24 * 3600 * 1000));
	return Math.round(clamp(num, 0, 24 * 3600) * 1000);
}

function shannonEntropyFromCounts(counts: Iterable<number>): number {
	let total = 0;
	const list: number[] = [];
	for (const c of counts) {
		if (!Number.isFinite(c) || c <= 0) continue;
		list.push(c);
		total += c;
	}
	if (total <= 0 || list.length === 0) return 0;
	let entropy = 0;
	for (const c of list) {
		const p = c / total;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

function normalizeRemoteAddress(raw: string | undefined): string | undefined {
	if (!raw) return undefined;
	const trimmed = raw.startsWith("::ffff:") ? raw.slice(7) : raw;
	return trimmed.length > 0 ? trimmed : undefined;
}

// ---------------------------------------------------------------------------
// 1. GatewayAdaptiveController
// ---------------------------------------------------------------------------

export type GatewayVendor =
	| "cloudflare"
	| "aws_waf"
	| "modsecurity"
	| "akamai"
	| "imperva"
	| "sucuri"
	| "generic"
	| "unknown";

export type GatewayBlockKind = "none" | "soft" | "hard";

export interface GatewaySignalInput {
	status?: number;
	headers?: HeaderBag;
	body?: string;
	networkError?: boolean;
}

export interface GatewaySignal {
	blocked: boolean;
	kind: GatewayBlockKind;
	vendor: GatewayVendor;
	status?: number;
	retryAfterMs?: number;
	reasons: string[];
	/** 0..1，签名识别置信度。 */
	confidence: number;
}

const CF_BODY_MARKERS = [
	"attention required! | cloudflare",
	"just a moment...",
	"cf-error-details",
	"checking your browser before accessing",
];
const MODSEC_BODY_MARKERS = ["mod_security", "modsecurity", "not acceptable!", "this error was generated by mod_security"];
const AKAMAI_BODY_MARKERS = ["reference #", "access denied reference", "akamai ghost"];
const IMPERVA_BODY_MARKERS = ["incapsula", "request unsuccessful. incapsula", "incap_ses"];
const SUCURI_BODY_MARKERS = ["sucuri website firewall", "access denied - sucuri"];
const AWS_BODY_MARKERS = ["request blocked", "aws waf", "x-amzn-waf"];

/**
 * 识别网关 / CDN 层的限流与挑战签名。
 * 裸 403 视为“软阻断”（应用级鉴权失败亦可能返回 403），429/503 与任意厂商签名视为“硬阻断”。
 */
export function detectGatewaySignature(input: GatewaySignalInput): GatewaySignal {
	const now = Date.now();
	const status = typeof input.status === "number" && Number.isFinite(input.status) ? input.status : undefined;
	const headers = input.headers;
	const body = typeof input.body === "string" ? input.body.slice(0, 65536).toLowerCase() : "";
	const htext = headerText(headers);
	const server = (headerValue(headers, "server") ?? "").toLowerCase();

	const reasons: string[] = [];
	let vendor: GatewayVendor = "unknown";
	let confidence = 0;

	const retryAfterMs =
		parseRetryAfterMs(headerValue(headers, "retry-after"), now) ??
		parseResetWindowMs(headerValue(headers, "x-ratelimit-reset"), now) ??
		parseResetWindowMs(headerValue(headers, "ratelimit-reset"), now) ??
		parseResetWindowMs(headerValue(headers, "x-rate-limit-reset"), now);

	const statusBlock = status === 403 || status === 429 || status === 503;
	if (statusBlock) {
		reasons.push(`status=${status}`);
		confidence += status === 429 ? 0.5 : 0.35;
	}

	const markVendor = (v: GatewayVendor, detail: string, weight: number): void => {
		if (vendor === "unknown") vendor = v;
		reasons.push(detail);
		confidence += weight;
	};

	// Cloudflare
	if (headerValue(headers, "cf-mitigated")) {
		markVendor("cloudflare", `cf-mitigated=${headerValue(headers, "cf-mitigated")}`, 0.55);
	}
	if (!statusBlock && (headerValue(headers, "cf-ray") || server.includes("cloudflare"))) {
		// 仅存在 CDN 头但未被阻断，不改变判定
	}
	if (statusBlock && (headerValue(headers, "cf-ray") || server.includes("cloudflare"))) {
		markVendor("cloudflare", "cf-ray/server=cloudflare", 0.35);
	}
	if (body && CF_BODY_MARKERS.some((m) => body.includes(m))) {
		markVendor("cloudflare", "cloudflare 挑战页标记", 0.4);
	}

	// AWS WAF / ALB
	if (headerValue(headers, "x-amzn-waf-action")) {
		markVendor("aws_waf", `x-amzn-waf-action=${headerValue(headers, "x-amzn-waf-action")}`, 0.5);
	}
	if (body && AWS_BODY_MARKERS.some((m) => body.includes(m)) && (htext.includes("x-amzn-requestid") || statusBlock)) {
		markVendor("aws_waf", "aws waf 阻断页标记", 0.35);
	}

	// ModSecurity
	if (htext.includes("x-modsecurity") || body && MODSEC_BODY_MARKERS.some((m) => body.includes(m))) {
		markVendor("modsecurity", "ModSecurity 拦截标记", 0.5);
	}

	// Akamai：常态头仅在出现 403/429/503 或阻断特征页时计入阻断，避免误杀正常 200 CDN 响应
	if (statusBlock && (headerValue(headers, "akamai-grn") || htext.includes("x-akamai-") || server.includes("akamaighost"))) {
		markVendor("akamai", "akamai-grn/x-akamai-*/AkamaiGHost", 0.5);
	}
	if (body && body.includes("reference #") && (body.includes("access denied") || statusBlock)) {
		markVendor("akamai", "AkamaiGHost / Reference # 拦截页", 0.4);
	}

	// Imperva / Incapsula
	if (statusBlock && headerValue(headers, "x-iinfo")) {
		markVendor("imperva", "x-iinfo", 0.5);
	}
	if (body && IMPERVA_BODY_MARKERS.some((m) => body.includes(m)) && (statusBlock || body.includes("unsuccessful") || body.includes("blocked") || body.includes("access denied"))) {
		markVendor("imperva", "Incapsula 拦截标记", 0.5);
	}

	// Sucuri
	if (statusBlock && headerValue(headers, "x-sucuri-id")) {
		markVendor("sucuri", "x-sucuri-id", 0.45);
	}
	if (body && SUCURI_BODY_MARKERS.some((m) => body.includes(m))) {
		markVendor("sucuri", "Sucuri 防火墙标记", 0.45);
	}

	// 通用限流
	const remaining = headerValue(headers, "x-ratelimit-remaining");
	if (remaining !== undefined && remaining.trim() === "0") {
		markVendor("generic", "x-ratelimit-remaining=0", 0.4);
	}
	if (retryAfterMs !== undefined) {
		reasons.push(`retry-after≈${retryAfterMs}ms`);
		confidence += 0.3;
	}
	if (status === 429 && vendor === "unknown") vendor = "generic";
	if (input.networkError) {
		reasons.push("network-error");
		confidence += 0.45;
	}

	const blocked = statusBlock || vendor !== "unknown" || retryAfterMs !== undefined || Boolean(input.networkError);
	const hard = Boolean(input.networkError) || status === 429 || status === 503 || vendor !== "unknown" || retryAfterMs !== undefined;
	const kind: GatewayBlockKind = !blocked ? "none" : hard ? "hard" : "soft";

	return {
		blocked,
		kind,
		vendor,
		reasons,
		confidence: clamp(confidence, 0, 1),
		...(status !== undefined ? { status } : {}),
		...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
	};
}

export type EgressProxyInput = string | { id: string; label?: string };

export interface EgressProxyState {
	id: string;
	label: string;
	healthScore: number;
	consecutiveBlocks: number;
	consecutiveOk: number;
	cooldownUntil: number;
	totalRequests: number;
	totalBlocks: number;
	lastStatus: number | null;
	lastVendor: GatewayVendor;
	lastUsedAt: number;
	lastReportedAt: number;
	latencyMs: number | null;
}

export interface GatewayOutcome {
	status?: number;
	headers?: HeaderBag;
	body?: string;
	latencyMs?: number;
	networkError?: boolean;
}

export interface GatewayAdaptiveOptions {
	proxies?: EgressProxyInput[];
	now?: () => number;
	/** 首次冷却基准窗口（毫秒），默认 2s。 */
	baseCooldownMs?: number;
	/** 单次冷却上限（毫秒），默认 60s。 */
	maxCooldownMs?: number;
	/** 软阻断连续命中多少次后进入冷却，默认 2。 */
	blockThreshold?: number;
}

interface MutableProxy extends EgressProxyState {
	latencyEwma: number | null;
}

/**
 * 出口代理池健康度与冷却窗口自适应控制器。
 * 阻断时按连续失败次数做指数退避并轮换到下一个健康出口；成功响应线性恢复健康分。
 */
export class GatewayAdaptiveController {
	private readonly proxies: MutableProxy[] = [];
	private readonly now: () => number;
	private readonly baseCooldownMs: number;
	private readonly maxCooldownMs: number;
	private readonly blockThreshold: number;
	private readonly index = new Map<string, MutableProxy>();

	constructor(options: GatewayAdaptiveOptions = {}) {
		this.now = options.now ?? (() => Date.now());
		this.baseCooldownMs = Math.max(250, Math.trunc(options.baseCooldownMs ?? 2000));
		this.maxCooldownMs = Math.max(this.baseCooldownMs, Math.trunc(options.maxCooldownMs ?? 60_000));
		this.blockThreshold = Math.max(1, Math.trunc(options.blockThreshold ?? 2));

		const inputs = options.proxies && options.proxies.length > 0 ? options.proxies : ["direct"];
		for (const entry of inputs) {
			const id = typeof entry === "string" ? entry : entry.id;
			const label = typeof entry === "string" ? entry : entry.label ?? entry.id;
			if (!id || this.index.has(id)) continue;
			const proxy: MutableProxy = {
				id,
				label,
				healthScore: 100,
				consecutiveBlocks: 0,
				consecutiveOk: 0,
				cooldownUntil: 0,
				totalRequests: 0,
				totalBlocks: 0,
				lastStatus: null,
				lastVendor: "unknown",
				lastUsedAt: 0,
				lastReportedAt: 0,
				latencyMs: null,
				latencyEwma: null,
			};
			this.proxies.push(proxy);
			this.index.set(id, proxy);
		}
	}

	/** 选择下一个健康出口；全部冷却中则返回 `null`。 */
	selectHealthyEgress(now: number = this.now()): EgressProxyState | null {
		const usable = this.proxies.filter((p) => p.cooldownUntil <= now);
		if (usable.length === 0) return null;
		usable.sort((a, b) => {
			if (b.healthScore !== a.healthScore) return b.healthScore - a.healthScore;
			if (a.lastUsedAt !== b.lastUsedAt) return a.lastUsedAt - b.lastUsedAt;
			return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
		});
		const chosen = usable[0];
		if (!chosen) return null;
		chosen.lastUsedAt = now;
		return this.view(chosen);
	}

	/** 距离最近一次冷却到期还需等待多久（毫秒）；存在健康出口时返回 0。 */
	nextCooldownRemainingMs(now: number = this.now()): number {
		let best = Number.POSITIVE_INFINITY;
		for (const p of this.proxies) {
			if (p.cooldownUntil <= now) return 0;
			best = Math.min(best, p.cooldownUntil - now);
		}
		return Number.isFinite(best) ? Math.max(0, best) : 0;
	}

	/** 上报一次经该出口发出的请求结果，返回更新后的出口状态。 */
	reportOutcome(proxyId: string, outcome: GatewayOutcome = {}): EgressProxyState {
		const proxy = this.index.get(proxyId);
		if (!proxy) throw new Error(`未知出口代理: ${proxyId}`);
		const now = this.now();
		proxy.totalRequests += 1;
		proxy.lastReportedAt = now;

		if (typeof outcome.latencyMs === "number" && Number.isFinite(outcome.latencyMs) && outcome.latencyMs >= 0) {
			const sample = outcome.latencyMs;
			proxy.latencyMs = sample;
			proxy.latencyEwma = proxy.latencyEwma === null ? sample : proxy.latencyEwma * 0.7 + sample * 0.3;
		}

		const signal = detectGatewaySignature({
			...(outcome.status !== undefined ? { status: outcome.status } : {}),
			...(outcome.headers !== undefined ? { headers: outcome.headers } : {}),
			...(outcome.body !== undefined ? { body: outcome.body } : {}),
			...(outcome.networkError ? { networkError: true } : {}),
		});

		if (signal.blocked) {
			proxy.consecutiveBlocks += 1;
			proxy.consecutiveOk = 0;
			proxy.totalBlocks += 1;
			proxy.lastVendor = signal.vendor;
			proxy.lastStatus = outcome.status ?? null;

			const hard = signal.kind === "hard";
			proxy.healthScore = clamp(proxy.healthScore - (hard ? 30 : 12), 0, 100);

			const triggerCooldown = hard || proxy.consecutiveBlocks >= this.blockThreshold;
			if (triggerCooldown) {
				const exponent = hard
					? proxy.consecutiveBlocks
					: Math.max(1, proxy.consecutiveBlocks - this.blockThreshold + 1);
				const backoff = Math.min(this.maxCooldownMs, this.baseCooldownMs * 2 ** Math.min(exponent - 1, 10));
				const retryAfter = Math.min(signal.retryAfterMs ?? 0, 10 * 60 * 1000);
				const wait = Math.max(backoff, retryAfter, this.baseCooldownMs);
				proxy.cooldownUntil = Math.max(proxy.cooldownUntil, now + wait);
			}
			return this.view(proxy);
		}

		proxy.consecutiveBlocks = 0;
		proxy.lastStatus = outcome.status ?? null;
		proxy.lastVendor = "unknown";

		if (outcome.status === undefined) {
			proxy.healthScore = clamp(proxy.healthScore + 1, 0, 100);
			return this.view(proxy);
		}
		if (outcome.status >= 400) {
			// 非阻断型 4xx（401/404 等）保持中性
			proxy.healthScore = clamp(proxy.healthScore + 1, 0, 100);
			return this.view(proxy);
		}
		proxy.consecutiveOk += 1;
		proxy.healthScore = clamp(proxy.healthScore + 6, 0, 100);
		proxy.cooldownUntil = 0;
		return this.view(proxy);
	}

	getState(proxyId: string): EgressProxyState | null {
		const proxy = this.index.get(proxyId);
		return proxy ? this.view(proxy) : null;
	}

	getStates(): EgressProxyState[] {
		return this.proxies.map((p) => this.view(p));
	}

	reset(): void {
		for (const p of this.proxies) {
			p.healthScore = 100;
			p.consecutiveBlocks = 0;
			p.consecutiveOk = 0;
			p.cooldownUntil = 0;
			p.totalRequests = 0;
			p.totalBlocks = 0;
			p.lastStatus = null;
			p.lastVendor = "unknown";
			p.lastUsedAt = 0;
			p.lastReportedAt = 0;
			p.latencyMs = null;
			p.latencyEwma = null;
		}
	}

	private view(proxy: MutableProxy): EgressProxyState {
		return {
			id: proxy.id,
			label: proxy.label,
			healthScore: proxy.healthScore,
			consecutiveBlocks: proxy.consecutiveBlocks,
			consecutiveOk: proxy.consecutiveOk,
			cooldownUntil: proxy.cooldownUntil,
			totalRequests: proxy.totalRequests,
			totalBlocks: proxy.totalBlocks,
			lastStatus: proxy.lastStatus,
			lastVendor: proxy.lastVendor,
			lastUsedAt: proxy.lastUsedAt,
			lastReportedAt: proxy.lastReportedAt,
			latencyMs: proxy.latencyMs,
		};
	}
}

// ---------------------------------------------------------------------------
// 1.b 合规请求变体生成
// ---------------------------------------------------------------------------

export interface AdaptiveRequestShape {
	url?: string;
	path?: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string;
}

export interface AdaptiveVariant {
	label: string;
	url: string;
	path: string;
	method: string;
	headers: Record<string, string>;
}

interface RequestParts {
	origin: string;
	path: string;
	query: string;
	method: string;
	headers: Record<string, string>;
}

interface VariantMutation {
	path?: string;
	query?: string;
	headers?: Record<string, string>;
}

const DEFAULT_DESKTOP_UA =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

function collapseSlashes(path: string): string {
	const collapsed = path.replace(/\/{2,}/g, "/");
	return collapsed.length > 0 ? collapsed : "/";
}

function toggleTrailingSlash(path: string): string {
	if (path === "" || path === "/") return "/";
	return path.endsWith("/") ? path.replace(/\/+$/, "") || "/" : `${path}/`;
}

function stripDotSegments(path: string): string {
	const segments = path.split("/");
	const out: string[] = [];
	for (const segment of segments) {
		if (segment === ".") continue;
		if (segment === "..") {
			out.pop();
			continue;
		}
		out.push(segment);
	}
	let result = out.join("/");
	if (!result.startsWith("/")) result = `/${result}`;
	return result.length > 0 ? result : "/";
}

function normalizePercentEncoding(path: string): string {
	return path.replace(/%([0-9A-Fa-f]{2})/g, (_match, hex: string) => {
		const code = Number.parseInt(hex, 16);
		if (!Number.isFinite(code)) return `%${hex.toUpperCase()}`;
		const ch = String.fromCharCode(code);
		if (/[A-Za-z0-9\-._~]/.test(ch)) return ch;
		return `%${hex.toUpperCase()}`;
	});
}

const VARIANT_BUILDERS: { label: string; apply: (parts: RequestParts) => VariantMutation }[] = [
	{ label: "identity", apply: () => ({}) },
	{ label: "path:collapse-slashes", apply: (p) => ({ path: collapseSlashes(p.path) }) },
	{ label: "path:trailing-slash", apply: (p) => ({ path: toggleTrailingSlash(p.path) }) },
	{ label: "path:dot-segments", apply: (p) => ({ path: stripDotSegments(p.path) }) },
	{ label: "path:percent-normalize", apply: (p) => ({ path: normalizePercentEncoding(p.path) }) },
	{ label: "headers:accept-json", apply: () => ({ headers: { Accept: "application/json, text/plain, */*" } }) },
	{ label: "headers:accept-html", apply: () => ({ headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" } }) },
	{ label: "headers:cache-bypass", apply: () => ({ headers: { "Cache-Control": "no-cache", Pragma: "no-cache" } }) },
	{ label: "headers:language", apply: () => ({ headers: { "Accept-Language": "en-US,en;q=0.9" } }) },
	{ label: "headers:connection-close", apply: () => ({ headers: { Connection: "close" } }) },
	{ label: "headers:desktop-ua", apply: () => ({ headers: { "User-Agent": DEFAULT_DESKTOP_UA } }) },
];

function parseRequestParts(req: AdaptiveRequestShape): RequestParts {
	let origin = "";
	let path = req.path ?? "";
	let query = "";
	if (req.url && req.url.length > 0) {
		const raw = req.url;
		try {
			const abs = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
			const parsed = new URL(raw, "http://nuwa.local");
			if (abs) origin = parsed.origin;
			if (!path) path = parsed.pathname;
			query = parsed.search;
		} catch {
			if (!path) path = raw.split(/[?#]/)[0] ?? "/";
			const q = raw.indexOf("?");
			if (q >= 0) query = raw.slice(q);
		}
	}
	if (!path) path = "/";
	if (!path.startsWith("/")) path = `/${path}`;
	const headers: Record<string, string> = {};
	for (const key of Object.keys(req.headers ?? {})) {
		const value = req.headers?.[key];
		if (typeof value === "string") headers[key] = value;
	}
	return { origin, path, query, method: (req.method ?? "GET").toUpperCase(), headers };
}

function buildVariant(parts: RequestParts, label: string, mutation: VariantMutation): AdaptiveVariant {
	const path = mutation.path ?? parts.path;
	const query = mutation.query ?? parts.query;
	const headers: Record<string, string> = { ...parts.headers };
	for (const key of Object.keys(mutation.headers ?? {})) {
		const value = mutation.headers?.[key];
		if (typeof value === "string") headers[key] = value;
	}
	return {
		label,
		url: `${parts.origin}${path}${query}`,
		path,
		method: parts.method,
		headers,
	};
}

function variantKey(variant: AdaptiveVariant): string {
	const headerSig = Object.keys(variant.headers)
		.map((k) => `${k.toLowerCase()}:${variant.headers[k] ?? ""}`)
		.sort()
		.join("&");
	return `${variant.path}${variant.method}|${headerSig}`;
}

/**
 * 生成符合正常 HTTP 语义的请求变体（路径 RFC 3986 归一化 + 头部内容协商），
 * 严禁使用头部伪造、协议走私或越权绕过类技巧。
 */
export function buildAdaptiveVariants(req: AdaptiveRequestShape, attempt = 0): AdaptiveVariant[] {
	const parts = parseRequestParts(req);
	const total = VARIANT_BUILDERS.length;
	const normalizedAttempt = Number.isFinite(attempt) ? Math.trunc(attempt) : 0;
	const start = ((normalizedAttempt % total) + total) % total;

	const out: AdaptiveVariant[] = [];
	const seen = new Set<string>();
	for (let offset = 0; offset < 3 && out.length < 3; offset += 1) {
		const builder = VARIANT_BUILDERS[(start + offset) % total];
		if (!builder) continue;
		const variant = buildVariant(parts, builder.label, builder.apply(parts));
		const key = variantKey(variant);
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(variant);
	}
	if (out.length === 0) {
		out.push(buildVariant(parts, "identity", {}));
	}
	return out;
}

// ---------------------------------------------------------------------------
// 2. IsomorphicTrapDetector
// ---------------------------------------------------------------------------

export type TrapConfidence = "none" | "low" | "medium" | "high";

export interface TrapSampleInput {
	path: string;
	status: number;
	body?: string | Buffer | Uint8Array;
	contentType?: string;
	latencyMs?: number;
	size?: number;
	bodyHash?: string;
	templateHash?: string;
	recordedAt?: number;
}

export interface TrapEvaluationMetrics {
	sampleCount: number;
	distinctPaths: number;
	statusUniformity: number;
	dominantStatus: number | null;
	templateCollisionRatio: number;
	dominantTemplateHash: string | null;
	bodyCollisionRatio: number;
	titleCollisionRatio: number;
	successSampleCount: number;
	successDistinctPaths: number;
	successTemplateRatio: number;
	keywordDensity: number;
	latencySampleCount: number;
	latencyMonotonicRatio: number;
	latencyInflationFactor: number;
	latencyIncreaseMs: number;
	shannonEntropy: number;
}

export interface TrapEvaluation {
	isTrapDetected: boolean;
	confidence: TrapConfidence;
	circuitBreak: boolean;
	reasons: string[];
	metrics: TrapEvaluationMetrics;
}

export interface TrapDetectorOptions {
	minSamples?: number;
	minDistinctPaths?: number;
	isomorphismThreshold?: number;
	latencyMonotonicThreshold?: number;
	latencyInflationFactor?: number;
	minLatencyInflationMs?: number;
	maxSamples?: number;
	now?: () => number;
}

interface NormalizedTrapSample {
	seq: number;
	path: string;
	normPath: string;
	status: number;
	contentType: string;
	size: number;
	bodyHash: string;
	templateHash: string;
	titleSig: string;
	keywordHits: number;
	latencyMs: number;
	recordedAt: number;
}

interface DistributionResult {
	top: string | null;
	topCount: number;
	total: number;
	buckets: number[];
}

const HIGH_SIGNAL_KEYWORD_RE =
	/\b(?:admin|administrator|superuser|sudo|secret|confidential|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|credentials|internal|honeypot|tarpit|decoy|canary|vulnerable|vulnerability|exploit|payload|reverse[_-]?shell|sql[_-]?injection|remote[_-]?code)\b|\bflag\{/gi;

const TITLE_RE = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i;
const MAX_SCAN_CHARS = 200_000;

function bodyToText(body: string | Buffer | Uint8Array | undefined): string {
	if (body === undefined) return "";
	if (typeof body === "string") return body.length > MAX_SCAN_CHARS ? body.slice(0, MAX_SCAN_CHARS) : body;
	try {
		const buf = Buffer.isBuffer(body) ? body : Buffer.from(body);
		const slice = buf.subarray(0, MAX_SCAN_CHARS);
		return slice.toString("utf8");
	} catch {
		return "";
	}
}

function countHighSignalKeywords(text: string): number {
	if (!text) return 0;
	const matches = text.match(HIGH_SIGNAL_KEYWORD_RE);
	if (!matches || matches.length === 0) return 0;
	const unique = new Set<string>();
	for (const m of matches) unique.add(m.toLowerCase());
	return unique.size;
}

function extractTitleSig(text: string): string {
	if (!text) return "";
	const m = TITLE_RE.exec(text);
	if (!m) return "";
	const raw = (m[1] ?? "").replace(/\s+/g, " ").trim().toLowerCase();
	return raw.slice(0, 64);
}

function normalizePathKey(raw: string): string {
	let path = String(raw ?? "").trim();
	if (!path) return "/";
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(path)) {
		try {
			path = new URL(path).pathname;
		} catch {
			/* ignore */
		}
	}
	const hash = path.indexOf("#");
	if (hash >= 0) path = path.slice(0, hash);
	const q = path.indexOf("?");
	if (q >= 0) path = path.slice(0, q);
	path = path.replace(/\/{2,}/g, "/").toLowerCase();
	if (path.length > 1 && path.endsWith("/")) path = path.replace(/\/+$/, "");
	return path.length > 0 ? path : "/";
}

function isSuccessishStatus(status: number): boolean {
	return status >= 200 && status < 400;
}

/**
 * 同构蜜罐 / tarpit 探测器。
 *
 * 校准护栏（必须成立）：4 条无关基线路径返回 404（即使页面模板完全一致）+ 1 条真实端点返回 200 时，
 * 由于 dominantStatus 非成功态、`successDistinctPaths < 3` 且状态一致性 < 0.95，绝不触发误报。
 */
export class IsomorphicTrapDetector {
	private readonly samples: NormalizedTrapSample[] = [];
	private readonly now: () => number;
	private readonly minSamples: number;
	private readonly minDistinctPaths: number;
	private readonly isomorphismThreshold: number;
	private readonly latencyMonotonicThreshold: number;
	private readonly latencyInflationFactor: number;
	private readonly minLatencyInflationMs: number;
	private readonly maxSamples: number;
	private seq = 0;

	constructor(options: TrapDetectorOptions = {}) {
		this.now = options.now ?? (() => Date.now());
		this.minSamples = Math.max(3, Math.trunc(options.minSamples ?? 5));
		this.minDistinctPaths = Math.max(3, Math.trunc(options.minDistinctPaths ?? 5));
		this.isomorphismThreshold = clamp(options.isomorphismThreshold ?? 0.85, 0.5, 1);
		this.latencyMonotonicThreshold = clamp(options.latencyMonotonicThreshold ?? 0.8, 0.5, 1);
		this.latencyInflationFactor = Math.max(1.2, options.latencyInflationFactor ?? 2);
		this.minLatencyInflationMs = Math.max(50, options.minLatencyInflationMs ?? 300);
		this.maxSamples = Math.max(this.minSamples, Math.trunc(options.maxSamples ?? 96));
	}

	recordResponse(sample: TrapSampleInput): void {
		const status = Number(sample.status);
		if (!Number.isFinite(status)) return;
		const rawPath = sample.path && sample.path.length > 0 ? sample.path : "/";
		const body = sample.body;
		const hashInfo = body !== undefined ? computeBodyHash(body) : undefined;
		const text = bodyToText(body);

		const normalized: NormalizedTrapSample = {
			seq: this.seq++,
			path: rawPath,
			normPath: normalizePathKey(rawPath),
			status,
			contentType: sample.contentType ?? "",
			size: typeof sample.size === "number" && Number.isFinite(sample.size) ? sample.size : hashInfo?.bodyBytes ?? 0,
			bodyHash: sample.bodyHash ?? hashInfo?.bodyHash ?? "",
			templateHash: sample.templateHash ?? (body !== undefined ? computeTemplateFingerprint(body, rawPath) : ""),
			titleSig: extractTitleSig(text),
			keywordHits: countHighSignalKeywords(text),
			latencyMs:
				typeof sample.latencyMs === "number" && Number.isFinite(sample.latencyMs) && sample.latencyMs > 0
					? sample.latencyMs
					: 0,
			recordedAt:
				typeof sample.recordedAt === "number" && Number.isFinite(sample.recordedAt) ? sample.recordedAt : this.now(),
		};

		this.samples.push(normalized);
		if (this.samples.length > this.maxSamples) {
			this.samples.splice(0, this.samples.length - this.maxSamples);
		}
	}

	reset(): void {
		this.samples.length = 0;
		this.seq = 0;
	}

	getSampleCount(): number {
		return this.samples.length;
	}

	evaluate(): TrapEvaluation {
		const samples = this.samples;
		const n = samples.length;
		const reasons: string[] = [];
		const distinctPaths = new Set(samples.map((s) => s.normPath)).size;

		const statusDist = this.distribution(samples.map((s) => String(s.status)));
		const templateDist = this.distribution(samples.map((s) => s.templateHash).filter((h): h is string => h.length > 0));
		const bodyDist = this.distribution(samples.map((s) => s.bodyHash).filter((h): h is string => h.length > 0));
		const titleDist = this.distribution(samples.map((s) => s.titleSig).filter((t): t is string => t.length > 0));

		const statusUniformity = n > 0 ? statusDist.topCount / n : 0;
		const templateCollisionRatio = templateDist.total > 0 ? templateDist.topCount / templateDist.total : 0;
		const bodyCollisionRatio = bodyDist.total > 0 ? bodyDist.topCount / bodyDist.total : 0;
		const titleCollisionRatio = titleDist.total > 0 ? titleDist.topCount / titleDist.total : 0;

		const dominantStatus = statusDist.top !== null ? Number(statusDist.top) : null;
		const dominantTemplateHash = templateDist.top;

		const successSamples = samples.filter((s) => isSuccessishStatus(s.status));
		const successDistinctPaths = new Set(successSamples.map((s) => s.normPath)).size;
		const successTemplateDist = this.distribution(
			successSamples.map((s) => s.templateHash).filter((h): h is string => h.length > 0),
		);
		const successBodyDist = this.distribution(
			successSamples.map((s) => s.bodyHash).filter((h): h is string => h.length > 0),
		);
		const successTemplateRatio =
			successTemplateDist.total > 0 ? successTemplateDist.topCount / successTemplateDist.total : 0;
		const successBodyRatio = successBodyDist.total > 0 ? successBodyDist.topCount / successBodyDist.total : 0;
		const keywordHits = successSamples.filter((s) => s.keywordHits >= 2).length;
		const keywordDensity = successSamples.length > 0 ? keywordHits / successSamples.length : 0;

		const bucketMap = new Map<string, number>();
		for (const s of samples) {
			const key = `${s.status}|${s.templateHash}`;
			bucketMap.set(key, (bucketMap.get(key) ?? 0) + 1);
		}
		const shannonEntropy = shannonEntropyFromCounts(bucketMap.values());

		const latencySeries = samples
			.filter((s) => s.latencyMs > 0)
			.slice()
			.sort((a, b) => a.recordedAt - b.recordedAt || a.seq - b.seq)
			.map((s) => s.latencyMs);

		let monotonicSteps = 0;
		for (let i = 1; i < latencySeries.length; i += 1) {
			const prev = latencySeries[i - 1] ?? 0;
			const cur = latencySeries[i] ?? 0;
			if (cur >= prev) monotonicSteps += 1;
		}
		const latencyDeltas = Math.max(0, latencySeries.length - 1);
		const latencyMonotonicRatio = latencyDeltas > 0 ? monotonicSteps / latencyDeltas : 0;
		const firstLatency = latencySeries[0] ?? 0;
		const lastLatency = latencySeries[latencySeries.length - 1] ?? 0;
		const latencyInflationFactor = firstLatency > 0 ? lastLatency / firstLatency : 0;
		const latencyIncreaseMs = Math.max(0, lastLatency - firstLatency);

		const enoughSamples = n >= this.minSamples;

		// R1：多条不同路径返回同构“成功”响应且布满误导性高信号关键词 → 蜜罐农场
		if (
			enoughSamples &&
			successDistinctPaths >= 3 &&
			successSamples.length >= 3 &&
			successTemplateRatio >= this.isomorphismThreshold &&
			keywordDensity >= 0.5
		) {
			reasons.push(
				`同构蜜罐农场：${successDistinctPaths} 条不同路径共享模板指纹 ${(successTemplateRatio * 100).toFixed(0)}%，` +
					`高信号关键词覆盖率 ${(keywordDensity * 100).toFixed(0)}%`,
			);
		}

		// R2：随机路径全部返回同一“成功”响应体且关键词密度极高
		if (
			enoughSamples &&
			distinctPaths >= this.minDistinctPaths &&
			statusUniformity >= 0.95 &&
			dominantStatus !== null &&
			isSuccessishStatus(dominantStatus) &&
			bodyCollisionRatio >= 0.9 &&
			keywordDensity >= 0.6
		) {
			reasons.push(
				`统一诱饵页面：${distinctPaths} 条路径状态码一致度 ${(statusUniformity * 100).toFixed(0)}%，` +
					`正文指纹重合 ${(bodyCollisionRatio * 100).toFixed(0)}%，关键词密度 ${(keywordDensity * 100).toFixed(0)}%`,
			);
		}

		// R3：tarpit —— 单调递增的延迟膨胀
		if (
			latencySeries.length >= 5 &&
			(distinctPaths >= 3 || latencySeries.length >= 6) &&
			latencyMonotonicRatio >= this.latencyMonotonicThreshold &&
			latencyInflationFactor >= this.latencyInflationFactor &&
			latencyIncreaseMs >= this.minLatencyInflationMs
		) {
			reasons.push(
				`渐进式延迟膨胀（tarpit）：${latencySeries.length} 次探测中 ${(latencyMonotonicRatio * 100).toFixed(0)}% 单调递增，` +
					`首末延迟 ${Math.round(firstLatency)}ms → ${Math.round(lastLatency)}ms（×${latencyInflationFactor.toFixed(2)}）`,
			);
		}

		const isTrapDetected = reasons.length > 0;
		let confidence: TrapConfidence = isTrapDetected ? (reasons.length >= 2 ? "high" : "medium") : "none";

		// 证据不足但高度可疑：仅给出低置信度提示，不触发熔断
		if (
			!isTrapDetected &&
			enoughSamples &&
			distinctPaths >= this.minDistinctPaths &&
			statusUniformity >= 0.95 &&
			dominantStatus !== null &&
			isSuccessishStatus(dominantStatus) &&
			templateCollisionRatio >= 0.7
		) {
			confidence = "low";
			reasons.push("疑似同构响应（模板高度一致但缺少高信号关键词或指纹证据），不触发熔断");
		}

		const metrics: TrapEvaluationMetrics = {
			sampleCount: n,
			distinctPaths,
			statusUniformity,
			dominantStatus,
			templateCollisionRatio,
			dominantTemplateHash,
			bodyCollisionRatio,
			titleCollisionRatio,
			successSampleCount: successSamples.length,
			successDistinctPaths,
			successTemplateRatio,
			keywordDensity,
			latencySampleCount: latencySeries.length,
			latencyMonotonicRatio,
			latencyInflationFactor,
			latencyIncreaseMs,
			shannonEntropy,
		};

		return {
			isTrapDetected,
			confidence,
			circuitBreak: isTrapDetected && confidence !== "low",
			reasons,
			metrics,
		};
	}

	private distribution(values: string[]): DistributionResult {
		const map = new Map<string, number>();
		for (const value of values) map.set(value, (map.get(value) ?? 0) + 1);
		let top: string | null = null;
		let topCount = 0;
		for (const [key, count] of map) {
			if (count > topCount || (count === topCount && top !== null && key < top)) {
				top = key;
				topCount = count;
			}
		}
		return { top, topCount, total: values.length, buckets: [...map.values()] };
	}
}

// ---------------------------------------------------------------------------
// 3. EmbeddedOobListener
// ---------------------------------------------------------------------------

export interface EmbeddedOobListenerOptions {
	/** 默认 `127.0.0.1`；仅绑定本机回环以避免暴露面。 */
	host?: string;
	/** 默认 0，由内核分配空闲端口。 */
	port?: number;
	hmacSecret?: string;
	pathPrefix?: string;
	maxHits?: number;
	now?: () => number;
}

export interface EmbeddedOobEndpoint {
	host: string;
	port: number;
	baseUrl: string;
	startedAt: string;
}

export interface OobCanaryRegistrationInput {
	canaryId?: string;
	projectId: string;
	intentId?: string;
}

export interface OobCanaryRegistration {
	canaryId: string;
	projectId: string;
	token: string;
	signature: string;
	path: string;
	callbackUrl: string;
	createdAt: string;
	intentId?: string;
}

export interface OobForgedRejection {
	canaryId: string | null;
	reason: string;
	path: string;
	remoteAddress?: string;
	receivedAt: string;
}

export interface OobHttpHit {
	id: string;
	protocol: "http";
	fullId: string;
	canaryId: string;
	projectId: string;
	tokenHash: string;
	method: string;
	path: string;
	query: Record<string, string>;
	timestamp: string;
	receivedAt: string;
	intentId?: string;
	userAgent?: string;
	remoteAddress?: string;
}

interface OobCanarySecret {
	canaryId: string;
	projectId: string;
	token: string;
	signature: string;
	intentId?: string;
}

/** 将嵌入式监听命中转换为 `./oob` 的通用回调结构，便于复用 `verifyExecutionEvidence`。 */
export function toCallbackHit(hit: OobHttpHit): OobCallbackHit {
	return {
		id: hit.id,
		protocol: "http",
		fullId: hit.fullId,
		timestamp: hit.timestamp,
		matchedCanaryId: hit.canaryId,
		matchedToken: hit.tokenHash,
		...(hit.remoteAddress ? { remoteAddress: hit.remoteAddress } : {}),
		...(hit.userAgent ? { rawRequest: hit.userAgent } : {}),
	};
}

/**
 * 本机回环临时端口 OOB 回调监听器。
 * - HMAC-SHA256 签名绑定 `{canaryId, projectId, intentId}` 与高熵 token，篡改 / 伪造请求只计数不关联；
 * - `stop()` 回收全部 keep-alive 连接与残留 socket，确保零端口、零句柄泄漏。
 */
export class EmbeddedOobListener {
	private readonly host: string;
	private readonly requestedPort: number;
	private readonly hmacSecret: string;
	private readonly pathPrefix: string;
	private readonly maxHits: number;
	private readonly now: () => number;

	private server: Server | null = null;
	private listeningFlag = false;
	private port: number | null = null;
	private startedAt: string | null = null;
	private starting: Promise<EmbeddedOobEndpoint> | null = null;
	private readonly sockets = new Set<Socket>();
	private readonly hits: OobHttpHit[] = [];
	private readonly forged: OobForgedRejection[] = [];
	private readonly registrations = new Map<string, OobCanarySecret>();
	private hitSeq = 0;
	private forgedCount = 0;
	private lastError: string | null = null;

	constructor(options: EmbeddedOobListenerOptions = {}) {
		this.host = (options.host ?? "127.0.0.1").trim() || "127.0.0.1";
		this.requestedPort = Number.isFinite(options.port ?? 0) ? Math.max(0, Math.trunc(options.port ?? 0)) : 0;
		this.hmacSecret = options.hmacSecret ?? randomBytes(32).toString("hex");
		const rawPrefix = (options.pathPrefix ?? "/oob").trim();
		const prefix = (rawPrefix.startsWith("/") ? rawPrefix : `/${rawPrefix}`).replace(/\/+$/, "");
		this.pathPrefix = prefix.length > 0 ? prefix : "/oob";
		this.maxHits = Math.max(16, Math.trunc(options.maxHits ?? 512));
		this.now = options.now ?? (() => Date.now());
	}

	get rejectedForgedCount(): number { return this.forgedCount; }
	get error(): string | null { return this.lastError; }

	async start(): Promise<EmbeddedOobEndpoint> {
		if (this.server && this.listeningFlag && this.port !== null) return this.endpoint(this.port);
		if (this.starting) return this.starting;

		const promise = new Promise<EmbeddedOobEndpoint>((resolve, reject) => {
			const server = createServer((req, res) => this.handle(req, res));
			this.server = server;
			let settled = false;

			server.on("connection", (socket: Socket) => {
				this.sockets.add(socket);
				socket.on("close", () => this.sockets.delete(socket));
				socket.on("error", () => this.sockets.delete(socket));
			});
			server.on("clientError", (_err: Error, socket: Socket) => {
				try { socket.destroy(); } catch {}
				this.sockets.delete(socket);
			});
			server.on("error", (err: Error) => {
				this.lastError = err.message;
				if (!settled) {
					settled = true;
					this.listeningFlag = false;
					this.server = null;
					this.port = null;
					reject(err);
				}
			});
			server.listen(this.requestedPort, this.host, () => {
				settled = true;
				this.listeningFlag = true;
				const address = server.address();
				const port = address && typeof address === "object" ? address.port : this.requestedPort;
				this.port = port;
				this.startedAt = new Date(this.now()).toISOString();
				resolve(this.endpoint(port));
			});
		});

		this.starting = promise.finally(() => { this.starting = null; });
		return this.starting;
	}

	async stop(): Promise<void> {
		const server = this.server;
		this.server = null;
		this.listeningFlag = false;
		this.port = null;
		this.startedAt = null;
		if (!server) {
			this.destroySockets();
			return;
		}
		await new Promise<void>((resolve) => {
			let settled = false;
			let timer: ReturnType<typeof setTimeout> | null = null;
			const finish = (): void => {
				if (settled) return;
				settled = true;
				if (timer !== null) clearTimeout(timer);
				resolve();
			};
			timer = setTimeout(finish, 750);
			(timer as { unref?: () => void }).unref?.();
			try { server.close(() => finish()); } catch { finish(); }
			const closer = (server as Server & { closeAllConnections?: () => void }).closeAllConnections;
			if (typeof closer === "function") {
				try { closer.call(server); } catch {}
			}
			this.destroySockets();
		});
		this.destroySockets();
	}

	/** `stop()` 的别名。 */
	async close(): Promise<void> { await this.stop(); }
	getPort(): number | null { return this.port; }
	getBaseUrl(): string | null { return this.port === null ? null : `http://${this.hostForUrl}:${this.port}`; }
	getEndpoint(): EmbeddedOobEndpoint | null { return this.port === null ? null : this.endpoint(this.port); }
	isListening(): boolean { return this.server !== null && this.listeningFlag && this.port !== null; }

	/** 注册（或幂等复用）Canary 并返回签名凭证。 */
	registerCanary(input: OobCanaryRegistrationInput): OobCanaryRegistration {
		const projectId = String(input.projectId ?? "").trim();
		if (!projectId) throw new Error("OobCorrelator: projectId 不能为空");
		const canaryId = (input.canaryId ?? "").trim() || `cnry_${randomBytes(8).toString("hex")}`;
		const intentId = input.intentId?.trim() || undefined;
		const { token, signature } = this.signToken(canaryId, projectId, intentId);
		const path = `${this.pathPrefix}/${encodeURIComponent(canaryId)}/${token}/${signature}`;
		const base = this.getBaseUrl();
		return {
			canaryId,
			projectId,
			token,
			signature,
			path,
			callbackUrl: base ? `${base}${path}` : path,
			createdAt: new Date(this.now()).toISOString(),
			...(intentId ? { intentId } : {}),
		};
	}

	/** 生成 / 复用高熵 token 与 HMAC 签名；禁止同 `canaryId` 跨项目覆写。 */
	signToken(canaryId: string, projectId: string, intentId?: string): { token: string; signature: string } {
		const existing = this.registrations.get(canaryId);
		if (existing) {
			if (existing.projectId !== projectId) {
				throw new Error(`EmbeddedOobListener: canaryId "${canaryId}" 已绑定至项目 "${existing.projectId}"，禁止跨项目覆写`);
			}
			if ((existing.intentId ?? "") === (intentId ?? "")) {
				return { token: existing.token, signature: existing.signature };
			}
			if (existing.intentId && intentId && existing.intentId !== intentId) {
				throw new Error(`EmbeddedOobListener: canaryId "${canaryId}" 已绑定至意图 "${existing.intentId}"，禁止覆写`);
			}
		}
		const token = randomBytes(18).toString("hex");
		const signature = this.computeSignature(canaryId, projectId, intentId, token);
		this.registrations.set(canaryId, {
			canaryId,
			projectId,
			token,
			signature,
			...(intentId ? { intentId } : {}),
		});
		return { token, signature };
	}

	/** 校验回调签名；伪造、篡改、未注册或跨项目一律返回 false。 */
	verifySignature(canaryId: string, projectId: string, token: string, signature: string): boolean {
		const reg = this.registrations.get(canaryId);
		if (!reg) return false;
		if (reg.projectId !== projectId) return false;
		if (!safeEqual(reg.token, token)) return false;
		const expected = this.computeSignature(canaryId, projectId, reg.intentId, token);
		return safeEqual(expected, signature);
	}

	getRegistration(canaryId: string): OobCanarySecret | null {
		const reg = this.registrations.get(canaryId);
		return reg ? { ...reg } : null;
	}

	getHits(): OobHttpHit[] {
		return this.hits.slice();
	}

	getForgedRejections(): OobForgedRejection[] {
		return this.forged.slice();
	}

	get pathPrefixValue(): string {
		return this.pathPrefix;
	}

	private get hostForUrl(): string {
		return this.host === "0.0.0.0" || this.host === "::" || this.host === "" ? "127.0.0.1" : this.host;
	}

	private endpoint(port: number): EmbeddedOobEndpoint {
		return {
			host: this.host,
			port,
			baseUrl: `http://${this.hostForUrl}:${port}`,
			startedAt: this.startedAt ?? new Date(this.now()).toISOString(),
		};
	}

	private computeSignature(canaryId: string, projectId: string, intentId: string | undefined, token: string): string {
		const payload = `${canaryId}\n${projectId}\n${intentId ?? ""}\n${token}`;
		return hmacSha256Hex(this.hmacSecret, payload);
	}

	private destroySockets(): void {
		for (const socket of this.sockets) {
			try { socket.destroy(); } catch {}
		}
		this.sockets.clear();
	}

	private parseCallback(url: URL): { canaryId: string; token: string; signature: string } | null {
		const prefix = this.pathPrefix;
		if (url.pathname.startsWith(`${prefix}/`)) {
			const rest = url.pathname.slice(prefix.length + 1).split("/");
			if (rest.length === 3) {
				try {
					const canaryId = decodeURIComponent(rest[0] ?? "");
					const token = (rest[1] ?? "").trim();
					const signature = (rest[2] ?? "").trim();
					if (canaryId && token && signature) return { canaryId, token, signature };
				} catch {}
			}
			return null;
		}
		const cid = url.searchParams.get("cid") ?? url.searchParams.get("canaryId");
		const tok = url.searchParams.get("tok") ?? url.searchParams.get("token");
		const sig = url.searchParams.get("sig") ?? url.searchParams.get("signature");
		if (cid && tok && sig) return { canaryId: cid, token: tok, signature: sig };
		return null;
	}

	private handle(req: IncomingMessage, res: ServerResponse): void {
		try {
			if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "POST") {
				this.respond(res, 405, "method not allowed");
				return;
			}
			const remote = normalizeRemoteAddress(req.socket?.remoteAddress);
			const url = new URL(req.url ?? "/", `http://${this.hostForUrl}`);
			const parsed = this.parseCallback(url);
			if (!parsed) {
				this.recordForged({
					canaryId: null,
					reason: "回调路径不匹配",
					path: url.pathname,
					...(remote ? { remoteAddress: remote } : {}),
				});
				this.respond(res, 404, "not found");
				return;
			}

			const reg = this.registrations.get(parsed.canaryId);
			if (!reg) {
				this.recordForged({
					canaryId: parsed.canaryId,
					reason: "未注册的 Canary",
					path: url.pathname,
					...(remote ? { remoteAddress: remote } : {}),
				});
				this.respond(res, 403, "forbidden");
				return;
			}

			const tokenOk = safeEqual(reg.token, parsed.token);
			const sigOk = this.verifySignature(parsed.canaryId, reg.projectId, parsed.token, parsed.signature);
			if (!tokenOk || !sigOk) {
				const safeForgedPath = url.pathname.split(reg.token).join("[REDACTED]").split(reg.signature).join("[REDACTED]");
				this.recordForged({
					canaryId: parsed.canaryId,
					reason: "HMAC 签名校验失败（伪造或篡改）",
					path: safeForgedPath,
					...(remote ? { remoteAddress: remote } : {}),
				});
				this.respond(res, 403, "forbidden");
				return;
			}

			const receivedAt = new Date(this.now()).toISOString();
			const query: Record<string, string> = {};
			for (const [key, value] of url.searchParams) {
				const sensitiveKey = /^(?:tok|token|sig|signature|secret|hmac|mac|sign|auth)$/i.test(key);
				const sensitiveVal = safeEqual(value, reg.token) || safeEqual(value, reg.signature);
				query[key] = sensitiveKey || sensitiveVal ? "[REDACTED]" : value;
			}
			const safePath = url.pathname.startsWith(`${this.pathPrefix}/`)
				? `${this.pathPrefix}/${encodeURIComponent(parsed.canaryId)}/[REDACTED]/[REDACTED]`
				: url.pathname.split(reg.token).join("[REDACTED]").split(reg.signature).join("[REDACTED]");
			const userAgent = headerValue(req.headers as HeaderBag, "user-agent");
			this.hitSeq += 1;

			const hit: OobHttpHit = {
				id: `hit_${this.hitSeq}_${randomBytes(4).toString("hex")}`,
				protocol: "http",
				fullId: `${this.hostForUrl}:${this.port ?? 0}`,
				canaryId: parsed.canaryId,
				projectId: reg.projectId,
				tokenHash: sha256Hex(reg.token).slice(0, 16),
				method: req.method ?? "GET",
				path: safePath,
				query,
				timestamp: receivedAt,
				receivedAt,
				...(reg.intentId ? { intentId: reg.intentId } : {}),
				...(userAgent ? { userAgent } : {}),
				...(remote ? { remoteAddress: remote } : {}),
			};

			this.hits.push(hit);
			if (this.hits.length > this.maxHits) this.hits.splice(0, this.hits.length - this.maxHits);
			this.respond(res, 200, "ok");
		} catch (err) {
			this.lastError = err instanceof Error ? err.message : String(err);
			this.respond(res, 500, "error");
		}
	}

	private recordForged(entry: { canaryId: string | null; reason: string; path: string; remoteAddress?: string }): void {
		this.forgedCount += 1;
		if (this.forged.length >= 256) this.forged.shift();
		this.forged.push({
			canaryId: entry.canaryId,
			reason: entry.reason,
			path: entry.path,
			receivedAt: new Date(this.now()).toISOString(),
			...(entry.remoteAddress ? { remoteAddress: entry.remoteAddress } : {}),
		});
	}

	private respond(res: ServerResponse, status: number, body: string): void {
		try {
			if (!res.headersSent) {
				res.statusCode = status;
				res.setHeader("content-type", "text/plain; charset=utf-8");
				res.setHeader("cache-control", "no-store");
				res.setHeader("connection", "close");
			}
			res.end(body);
		} catch {}
	}
}

export interface OobCanaryRegisterInput {
	canaryId?: string;
	projectId: string;
	intentId?: string;
	endpoint?: string;
	paramName?: string;
	templateHash?: string;
	authRole?: string;
}
export interface OobCanaryContext {
	canaryId: string;
	token: string;
	signature: string;
	callbackUrl: string;
	projectId: string;
	createdAt: string;
	intentId?: string;
	endpoint?: string;
	paramName?: string;
	templateHash?: string;
	authRole?: string;
}
export interface CorrelationHit {
	id: string;
	canaryId: string;
	token?: string;
	protocol?: string;
	remoteAddress?: string;
	timestamp?: string;
	path?: string;
	method?: string;
}
export interface OobMatchedEvidence {
	canaryId: string;
	projectId: string;
	intentId: string | null;
	endpoint: string | null;
	paramName: string | null;
	authRole: string | null;
	templateHash: string | null;
	canaryRedacted: string;
	hitCount: number;
	firstSeenAt: string;
	lastSeenAt: string;
	remoteAddresses: string[];
	protocols: string[];
	paths: string[];
	evidenceHash: string;
	summary: string;
}
export interface OobWakeSignal {
	wakeProject: true;
	projectId: string;
	intentId: string | null;
	matchedCanaryId: string;
	evidenceHash: string;
	hitCount: number;
	firstSeenAt: string;
	lastSeenAt: string;
	summary: string;
	createdAt: string;
}
export interface OobCorrelationFilter { projectId?: string; intentId?: string; canaryIds?: string[]; minHits?: number; }
export interface OobCorrelationResult { matches: OobMatchedEvidence[]; wakeSignals: OobWakeSignal[]; unmatchedHitCount: number; rejectedForgedCount: number; }
interface MutableAggregate { canaryId: string; hitCount: number; firstSeenAt: string; lastSeenAt: string; remoteAddresses: Set<string>; protocols: Set<string>; paths: Set<string>; dirty: boolean; }
function redactToken(token: string): string { return !token || token.length <= 8 ? "****" : `${token.slice(0, 4)}…${token.slice(-4)}`; }

/**
 * 带外回调关联器：注册完整来源上下文（端点 / 参数名 / 模板指纹 / 鉴权角色），
 * 跨轮次延迟匹配回调，输出脱敏证据摘要与高信息熵唤醒信号。
 */
export class OobCorrelator {
	private readonly listener: EmbeddedOobListener;
	private readonly ownsListener: boolean;
	private readonly now: () => number;
	private readonly contexts = new Map<string, OobCanaryContext>();
	private readonly aggregates = new Map<string, MutableAggregate>();
	private readonly seenHitIds = new Set<string>();
	private readonly externalHits: CorrelationHit[] = [];
	private unmatchedHitCount = 0;
	private correlatorForgedCount = 0;

	constructor(options: { listener?: EmbeddedOobListener; now?: () => number } = {}) {
		this.ownsListener = options.listener === undefined;
		this.listener = options.listener ?? new EmbeddedOobListener();
		this.now = options.now ?? (() => Date.now());
	}

	/** 获取（必要时创建）内部监听器，便于测试或复用端口。 */
	getListener(): EmbeddedOobListener {
		return this.listener;
	}

	/** 注册 Canary 并返回完整来源上下文。 */
	register(input: OobCanaryRegisterInput): OobCanaryContext {
		const reg = this.listener.registerCanary({
			...(input.canaryId ? { canaryId: input.canaryId } : {}),
			projectId: input.projectId,
			...(input.intentId ? { intentId: input.intentId } : {}),
		});
		const intentId = input.intentId?.trim() || reg.intentId;
		const context: OobCanaryContext = {
			canaryId: reg.canaryId,
			token: reg.token,
			signature: reg.signature,
			callbackUrl: reg.callbackUrl,
			projectId: input.projectId,
			createdAt: new Date(this.now()).toISOString(),
			...(intentId ? { intentId } : {}),
			...(input.endpoint ? { endpoint: input.endpoint } : {}),
			...(input.paramName ? { paramName: input.paramName } : {}),
			...(input.templateHash ? { templateHash: input.templateHash } : {}),
			...(input.authRole ? { authRole: input.authRole } : {}),
		};
		this.contexts.set(context.canaryId, context);
		return context;
	}

	unregister(canaryId: string): boolean {
		this.aggregates.delete(canaryId);
		return this.contexts.delete(canaryId);
	}

	getContexts(): OobCanaryContext[] {
		return [...this.contexts.values()].map((ctx) => ({ ...ctx }));
	}

	/** 摄入外部（`./oob` 轮询）回调，`matchedCanaryId` 缺省的条目直接忽略。 */
	ingestCallbackHits(hits: readonly OobCallbackHit[]): number {
		let ingested = 0;
		for (const hit of hits) {
			if (!hit.matchedCanaryId) continue;
			const mapped: CorrelationHit = {
				id: hit.id,
				canaryId: hit.matchedCanaryId,
				protocol: hit.protocol,
				...(hit.remoteAddress ? { remoteAddress: hit.remoteAddress } : {}),
				timestamp: hit.timestamp,
			};
			this.externalHits.push(mapped);
			ingested += 1;
		}
		return ingested;
	}

	/** 摄入单条回调（内部收件箱或人工注入）；传入 `token` 时强制作恒定时间校验。 */
	ingestHit(hit: CorrelationHit): boolean {
		if (!hit || typeof hit.id !== "string" || hit.id.length === 0) return false;
		if (this.seenHitIds.has(hit.id)) return false;
		if (this.seenHitIds.size > 8192) this.seenHitIds.clear();
		this.seenHitIds.add(hit.id);

		const canaryId = hit.canaryId ?? "";
		if (!canaryId) {
			this.unmatchedHitCount += 1;
			return false;
		}
		const context = this.contexts.get(canaryId);
		if (!context) {
			this.unmatchedHitCount += 1;
			return false;
		}
		if (hit.token !== undefined && (typeof hit.token !== "string" || !safeEqual(hit.token, context.token))) {
			this.unmatchedHitCount += 1;
			this.correlatorForgedCount += 1;
			return false;
		}
		this.touch(hit, context);
		return true;
	}

	/** 抽取并匹配所有新到达的回调；返回本轮新增证据与唤醒信号（drain 语义）。 */
	correlateCallbacks(filter: OobCorrelationFilter = {}): OobCorrelationResult {
		for (const hit of this.listener.getHits()) this.ingestHit(hit);
		while (this.externalHits.length > 0) {
			const queued = this.externalHits.shift();
			if (queued) this.ingestHit(queued);
		}

		const matches: OobMatchedEvidence[] = [];
		const wakeSignals: OobWakeSignal[] = [];

		for (const aggregate of this.aggregates.values()) {
			if (!aggregate.dirty) continue;
			const context = this.contexts.get(aggregate.canaryId);
			if (!context) continue;
			if (!this.matchesFilter(context, aggregate, filter)) continue;

			const evidence = this.buildEvidence(aggregate, context);
			matches.push(evidence);
			wakeSignals.push({
				wakeProject: true,
				projectId: context.projectId,
				intentId: context.intentId ?? null,
				matchedCanaryId: context.canaryId,
				evidenceHash: evidence.evidenceHash,
				hitCount: evidence.hitCount,
				firstSeenAt: evidence.firstSeenAt,
				lastSeenAt: evidence.lastSeenAt,
				summary: evidence.summary,
				createdAt: new Date(this.now()).toISOString(),
			});
			aggregate.dirty = false;
		}

		matches.sort((a, b) => (a.lastSeenAt < b.lastSeenAt ? 1 : a.lastSeenAt > b.lastSeenAt ? -1 : 0));

		return {
			matches,
			wakeSignals,
			unmatchedHitCount: this.unmatchedHitCount,
			rejectedForgedCount: this.listener.rejectedForgedCount + this.correlatorForgedCount,
		};
	}

	/** 查看当前累计证据（不清空 dirty 标记）。 */
	getEvidence(): OobMatchedEvidence[] {
		const out: OobMatchedEvidence[] = [];
		for (const aggregate of this.aggregates.values()) {
			const context = this.contexts.get(aggregate.canaryId);
			if (!context) continue;
			out.push(this.buildEvidence(aggregate, context));
		}
		out.sort((a, b) => (a.lastSeenAt < b.lastSeenAt ? 1 : a.lastSeenAt > b.lastSeenAt ? -1 : 0));
		return out;
	}

	reset(): void {
		this.aggregates.clear();
		this.seenHitIds.clear();
		this.externalHits.length = 0;
		this.unmatchedHitCount = 0;
		this.correlatorForgedCount = 0;
	}

	/** 关闭内部监听器（若由本关联器创建）。 */
	async close(): Promise<void> {
		if (this.ownsListener) await this.listener.close();
	}

	private matchesFilter(
		context: OobCanaryContext,
		aggregate: MutableAggregate,
		filter: OobCorrelationFilter,
	): boolean {
		if (filter.projectId && filter.projectId !== context.projectId) return false;
		if (filter.intentId && filter.intentId !== (context.intentId ?? "")) return false;
		if (filter.canaryIds && filter.canaryIds.length > 0 && !filter.canaryIds.includes(context.canaryId)) return false;
		if (typeof filter.minHits === "number" && aggregate.hitCount < filter.minHits) return false;
		return true;
	}

	private scrubPath(rawPath: string, context: OobCanaryContext): string {
		let safe = rawPath;
		if (context.token && safe.includes(context.token)) safe = safe.split(context.token).join("[REDACTED]");
		if (context.signature && safe.includes(context.signature)) safe = safe.split(context.signature).join("[REDACTED]");
		const prefix = this.listener.pathPrefixValue;
		if (safe.startsWith(`${prefix}/`)) {
			const rest = safe.slice(prefix.length + 1).split("/");
			if (rest.length >= 2) {
				return `${prefix}/${rest[0]}/[REDACTED]${rest.length >= 3 ? "/[REDACTED]" : ""}`;
			}
		}
		return safe.replace(/([?&](?:tok|token|sig|signature|secret|hmac|mac|sign|auth)=)[^&]*/gi, "$1[REDACTED]");
	}

	private touch(hit: CorrelationHit, context: OobCanaryContext): void {
		const timestamp = hit.timestamp && hit.timestamp.length > 0 ? hit.timestamp : new Date(this.now()).toISOString();
		let aggregate = this.aggregates.get(context.canaryId);
		if (!aggregate) {
			aggregate = {
				canaryId: context.canaryId,
				hitCount: 0,
				firstSeenAt: timestamp,
				lastSeenAt: timestamp,
				remoteAddresses: new Set<string>(),
				protocols: new Set<string>(),
				paths: new Set<string>(),
				dirty: true,
			};
			this.aggregates.set(context.canaryId, aggregate);
		}
		aggregate.hitCount += 1;
		if (timestamp < aggregate.firstSeenAt) aggregate.firstSeenAt = timestamp;
		if (timestamp > aggregate.lastSeenAt) aggregate.lastSeenAt = timestamp;
		if (hit.remoteAddress) aggregate.remoteAddresses.add(hit.remoteAddress);
		if (hit.protocol) aggregate.protocols.add(hit.protocol);
		if (hit.path) aggregate.paths.add(this.scrubPath(hit.path, context));
		aggregate.dirty = true;
	}

	private buildEvidence(aggregate: MutableAggregate, context: OobCanaryContext): OobMatchedEvidence {
		const remoteAddresses = [...aggregate.remoteAddresses].sort();
		const protocols = [...aggregate.protocols].sort();
		const paths = [...aggregate.paths].sort();
		const evidenceHash = sha256Hex(
			JSON.stringify({
				v: 1,
				canaryId: context.canaryId,
				projectId: context.projectId,
				intentId: context.intentId ?? null,
				endpoint: context.endpoint ?? null,
				paramName: context.paramName ?? null,
				templateHash: context.templateHash ?? null,
				authRole: context.authRole ?? null,
				hitCount: aggregate.hitCount,
				firstSeenAt: aggregate.firstSeenAt,
				lastSeenAt: aggregate.lastSeenAt,
				remoteAddresses,
				protocols,
				paths,
			}),
		);

		const canaryRedacted = `${context.canaryId}@${redactToken(context.token)}`;
		const targetBits: string[] = [];
		if (context.endpoint) targetBits.push(`端点=${context.endpoint}`);
		if (context.paramName) targetBits.push(`参数=${context.paramName}`);
		if (context.authRole) targetBits.push(`角色=${context.authRole}`);
		const summary =
			`OOB 回调命中 canary ${canaryRedacted}（项目=${context.projectId}` +
			`${context.intentId ? `，意图=${context.intentId}` : ""}）共 ${aggregate.hitCount} 次` +
			`${remoteAddresses.length > 0 ? `，来源 ${remoteAddresses.join(",")}` : ""}` +
			`${targetBits.length > 0 ? `，${targetBits.join(" ")}` : ""}`;

		return {
			canaryId: context.canaryId,
			projectId: context.projectId,
			intentId: context.intentId ?? null,
			endpoint: context.endpoint ?? null,
			paramName: context.paramName ?? null,
			authRole: context.authRole ?? null,
			templateHash: context.templateHash ?? null,
			canaryRedacted,
			hitCount: aggregate.hitCount,
			firstSeenAt: aggregate.firstSeenAt,
			lastSeenAt: aggregate.lastSeenAt,
			remoteAddresses,
			protocols,
			paths,
			evidenceHash,
			summary,
		};
	}
}
