import * as nodeCrypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { closeCdpSession, launchCdpSession, type BlockedCdpRequest, type CdpCookieParam, type CdpSession, type LaunchCdpSessionOptions } from "./cdp-bridge";
import { formatScopeBlockReason } from "./scope";
import { checkRoleHealth, decodeJwtExpiryIso, formatSessionVaultSummary, getRoleHeadersMap, loadSessionVault, upsertSessionRole, type RoleHealthFetchLike } from "./session-vault";
import { redactTrafficUrl, TrafficRecorder } from "./traffic-workbench";
import type { Mode, ScopePolicy } from "./types";
import { checkHttpTargetScope, ensureStatefulCapableInterceptor, extractSecretsFromHeadersMap, normalizeCdpHeadersObject, scrubTextWithExtraSecrets } from "./cdp-signed-probe";

/**
 * 女娲 v7.0 交互式登录剧本、纯本地 TOTP 动态口令与会话保鲜。
 *
 * 约束：零外部依赖；仅复用本地模块与 node:crypto；任何日志、错误、步骤摘要、凭据来源
 * 与 AutoFact 均经过 SessionVault / 额外运行时密钥 / URL 参数 / Cookie 全量脱敏，
 * 返回结构中零明文凭据值。
 */

export const DEFAULT_SESSION_MIN_TTL_SECONDS = 120 as const;

export const DEFAULT_AUTH_FAILURE_THRESHOLD = 2 as const;

export type CanonicalTotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export type TotpAlgorithmInput =
	| CanonicalTotpAlgorithm
	| "sha1"
	| "sha256"
	| "sha512"
	| "HMAC-SHA1"
	| "HMAC-SHA256"
	| "HMAC-SHA512";

export interface TotpOptions {
	digits?: number;
	period?: number;
	algorithm?: TotpAlgorithmInput;
	timestampMs?: number;
	t0?: number;
	counterOffset?: number;
}

export interface ParsedOtpAuthUri {
	secret: string;
	algorithm?: CanonicalTotpAlgorithm;
	digits?: number;
	period?: number;
	issuer?: string;
	account?: string;
}

export interface TotpTokenResult {
	code: string;
	counter: number;
	period: number;
	digits: number;
	algorithm: CanonicalTotpAlgorithm;
	remainingSeconds: number;
	expiresAtMs: number;
}

export interface TotpVerifyResult {
	valid: boolean;
	matchedOffset?: number;
	counter?: number;
}

export type AuthPlaybookStep =
	| { action: "goto"; url: string; waitUntilLoad?: boolean; timeoutMs?: number; settleMs?: number }
	| { action: "waitForSelector"; selector: string; visible?: boolean; timeoutMs?: number }
	| {
			action: "fill";
			selector: string;
			value: string;
			isSecret?: boolean;
			clearFirst?: boolean;
			timeoutMs?: number;
	  }
	| {
			action: "click";
			selector: string;
			waitForNavigation?: boolean;
			timeoutMs?: number;
			settleMs?: number;
	  }
	| {
			action: "fillTotp";
			selector: string;
			secret: string;
			totpOptions?: TotpOptions;
			timeoutMs?: number;
	  }
	| {
			action: "submit";
			selector?: string;
			waitForNavigation?: boolean;
			timeoutMs?: number;
			settleMs?: number;
	  }
	| {
			action: "captureStorage";
			tokenKeys?: string[];
			includeSessionStorage?: boolean;
			timeoutMs?: number;
	  };

export interface AuthPlaybookStepSummary {
	stepIndex: number;
	action: AuthPlaybookStep["action"];
	target: string;
	ok: boolean;
	blockedByScope?: boolean;
	durationMs: number;
	currentUrl?: string;
	error?: string;
}

export interface InteractiveAuthPlaybookOptions {
	session?: CdpSession;
	role: string;
	steps: readonly AuthPlaybookStep[];
	root: string;
	scope: ScopePolicy;
	mode?: Mode | string;
	username?: string;
	checkUrl?: string;
	initialCookies?: CdpCookieParam[];
	extraHeaders?: Record<string, string>;
	extraSecrets?: string[];
	recorder?: TrafficRecorder;
	launchOptions?: LaunchCdpSessionOptions;
	stepTimeoutMs?: number;
	closeSessionOnSuccess?: boolean;
	keepSessionOnFailure?: boolean;
}

export interface InteractiveAuthPlaybookResult {
	ok: boolean;
	role: string;
	blockedByScope: boolean;
	blockReason?: string;
	finalUrl: string;
	navigationChain: string[];
	steps: AuthPlaybookStepSummary[];
	blockedRequests: BlockedCdpRequest[];
	capturedCredentialSources: string[];
	expiresAt?: string;
	sessionClosed: boolean;
	vaultSummary: string;
	error?: string;
}

// ---------------------------------------------------------------------------
// 纯 node:crypto 的 RFC 4226 / RFC 6238 实现
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const BASE32_LOOKUP: Readonly<Record<string, number>> = (() => {
	const table: Record<string, number> = {};
	for (let i = 0; i < BASE32_ALPHABET.length; i += 1) table[BASE32_ALPHABET[i]!] = i;
	return table;
})();

interface HashLike {
	update(data: Buffer | string, encoding?: string): HashLike;
	digest(): Uint8Array;
}

const cryptoBridge = nodeCrypto as unknown as {
	createHmac?: (algorithm: string, key: Buffer | string) => HashLike;
	createHash?: (algorithm: string) => HashLike;
	timingSafeEqual?: (a: Uint8Array, b: Uint8Array) => boolean;
};

function toBuffer(raw: unknown): Buffer {
	if (Buffer.isBuffer(raw)) return raw;
	if (raw instanceof Uint8Array) return Buffer.from(raw);
	if (typeof raw === "string") return Buffer.from(raw, "utf8");
	throw new Error("摘要结果类型异常，无法转换为 Buffer。");
}

function safeDecode(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

function parsePositiveInt(raw: string | null, min: number, max: number): number | undefined {
	if (!raw) return undefined;
	const parsed = Number.parseInt(raw, 10);
	if (!Number.isFinite(parsed) || parsed < min || parsed > max) return undefined;
	return parsed;
}

function normalizeTotpAlgorithm(input: TotpAlgorithmInput | string | undefined): CanonicalTotpAlgorithm {
	const raw = String(input ?? "SHA1").trim().toUpperCase();
	if (raw.includes("512")) return "SHA512";
	if (raw.includes("256")) return "SHA256";
	return "SHA1";
}

function clampDigits(digits: number | undefined): number {
	const value = Number.isFinite(digits ?? NaN) ? Math.trunc(digits as number) : 6;
	return Math.min(10, Math.max(6, value));
}

function clampPeriod(period: number | undefined): number {
	const value = Number.isFinite(period ?? NaN) ? Math.trunc(period as number) : 30;
	return Math.min(600, Math.max(1, value));
}

export function parseOtpAuthUri(uri: string): ParsedOtpAuthUri {
	const trimmed = uri.trim();
	if (!/^otpauth:\/\//i.test(trimmed)) throw new Error("不是合法的 otpauth:// URI。");
	let parsed: URL;
	try {
		parsed = new URL(trimmed);
	} catch {
		throw new Error("otpauth:// URI 语法错误，无法解析。");
	}
	if (parsed.host.toLowerCase() !== "totp") throw new Error("当前仅支持 otpauth://totp 动态口令。");
	const secret = (parsed.searchParams.get("secret") ?? "").replace(/[\s-]/g, "").toUpperCase();
	if (!secret) throw new Error("otpauth:// URI 缺少 secret 参数。");
	const rawAlgorithm = parsed.searchParams.get("algorithm");
	const label = safeDecode(parsed.pathname.replace(/^\/+/, ""));
	const colon = label.indexOf(":");
	const issuerParam = parsed.searchParams.get("issuer")?.trim();
	return {
		secret,
		algorithm: rawAlgorithm ? normalizeTotpAlgorithm(rawAlgorithm) : undefined,
		digits: parsePositiveInt(parsed.searchParams.get("digits"), 6, 10),
		period: parsePositiveInt(parsed.searchParams.get("period"), 1, 600),
		issuer: issuerParam || (colon > 0 ? label.slice(0, colon).trim() : undefined),
		account: colon >= 0 ? label.slice(colon + 1).trim() || undefined : label || undefined,
	};
}

export function decodeBase32Secret(secretOrUri: string): Buffer {
	const source = secretOrUri.trim().startsWith("otpauth://")
		? parseOtpAuthUri(secretOrUri).secret
		: secretOrUri;
	const normalized = source.replace(/[\s-]/g, "").toUpperCase().replace(/=+$/g, "");
	if (!normalized) throw new Error("动态口令密钥为空，无法解码。");
	const bytes: number[] = [];
	let bits = 0;
	let value = 0;
	for (const char of normalized) {
		const index = BASE32_LOOKUP[char];
		if (index === undefined) throw new Error("动态口令密钥包含非法 Base32 字符，已拒绝解码。");
		value = (value << 5) | index;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			bytes.push((value >>> bits) & 0xff);
		}
	}
	if (bytes.length === 0) throw new Error("动态口令密钥解码结果为空。");
	return Buffer.from(bytes);
}

function hmacDigest(key: Buffer, data: Buffer, algorithm: CanonicalTotpAlgorithm): Buffer {
	const algorithmName = algorithm.toLowerCase();
	const createHmac = cryptoBridge.createHmac;
	if (typeof createHmac === "function") {
		try {
			return toBuffer(createHmac(algorithmName, key).update(data).digest());
		} catch {
			// 回退到标准 RFC 2104 实现
		}
	}
	const createHash = cryptoBridge.createHash;
	if (typeof createHash !== "function") {
		throw new Error("当前运行时缺少 node:crypto 摘要能力，无法生成动态口令。");
	}
	const blockSize = algorithm === "SHA512" ? 128 : 64;
	let keyBlock = key.length > blockSize ? toBuffer(createHash(algorithmName).update(key).digest()) : key;
	if (keyBlock.length < blockSize) {
		keyBlock = Buffer.concat([keyBlock, Buffer.alloc(blockSize - keyBlock.length)]);
	}
	const innerPad = Buffer.alloc(blockSize);
	const outerPad = Buffer.alloc(blockSize);
	for (let i = 0; i < blockSize; i += 1) {
		innerPad[i] = keyBlock[i]! ^ 0x36;
		outerPad[i] = keyBlock[i]! ^ 0x5c;
	}
	const inner = toBuffer(createHash(algorithmName).update(Buffer.concat([innerPad, data])).digest());
	return toBuffer(createHash(algorithmName).update(Buffer.concat([outerPad, inner])).digest());
}

export function generateHotpCode(
	secret: string | Buffer,
	counter: number,
	opts?: { digits?: number; algorithm?: TotpAlgorithmInput },
): string {
	if (!Number.isSafeInteger(counter) || counter < 0) {
		throw new Error("HOTP 计数器必须为非负安全整数。");
	}
	const digits = clampDigits(opts?.digits);
	const algorithm = normalizeTotpAlgorithm(opts?.algorithm);
	const key = Buffer.isBuffer(secret) ? secret : decodeBase32Secret(secret);
	const counterBuffer = Buffer.alloc(8);
	let remaining = counter;
	for (let i = 7; i >= 0; i -= 1) {
		counterBuffer[i] = remaining & 0xff;
		remaining = Math.floor(remaining / 256);
	}
	const digest = hmacDigest(key, counterBuffer, algorithm);
	const offset = digest[digest.length - 1]! & 0x0f;
	const binary =
		((digest[offset]! & 0x7f) << 24) |
		(digest[offset + 1]! << 16) |
		(digest[offset + 2]! << 8) |
		digest[offset + 3]!;
	const truncated = binary % 10 ** digits;
	return String(truncated).padStart(digits, "0");
}

export function generateTotpCode(secret: string, opts: TotpOptions = {}): TotpTokenResult {
	const parsed = secret.trim().startsWith("otpauth://") ? parseOtpAuthUri(secret) : undefined;
	const period = clampPeriod(opts.period ?? parsed?.period ?? 30);
	const digits = clampDigits(opts.digits ?? parsed?.digits ?? 6);
	const algorithm = normalizeTotpAlgorithm(opts.algorithm ?? parsed?.algorithm ?? "SHA1");
	const t0 = Number.isFinite(opts.t0 ?? NaN) ? Math.trunc(opts.t0 as number) : 0;
	const nowMs = Number.isFinite(opts.timestampMs ?? NaN) ? Math.trunc(opts.timestampMs as number) : Date.now();
	const elapsedSeconds = Math.floor(nowMs / 1000) - t0;
	const rawCounter = Math.floor(elapsedSeconds / period) + Math.trunc(opts.counterOffset ?? 0);
	const counter = Math.max(0, rawCounter);
	const code = generateHotpCode(secret, counter, { digits, algorithm });
	const remainingSeconds = period - (((elapsedSeconds % period) + period) % period);
	return {
		code,
		counter,
		period,
		digits,
		algorithm,
		remainingSeconds,
		expiresAtMs: nowMs + remainingSeconds * 1000,
	};
}

export function computeTotpToken(secret: string, opts?: TotpOptions): string {
	return generateTotpCode(secret, opts).code;
}

function timingSafeEqualText(left: string, right: string): boolean {
	if (left.length !== right.length) return false;
	const comparator = cryptoBridge.timingSafeEqual;
	if (typeof comparator === "function") {
		try {
			return comparator(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
		} catch {
			return false;
		}
	}
	let diff = 0;
	for (let i = 0; i < left.length; i += 1) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
	return diff === 0;
}

export function verifyTotpCode(
	secret: string,
	code: string,
	opts: TotpOptions & { window?: number } = {},
): TotpVerifyResult {
	const expected = (code ?? "").replace(/[\s-]/g, "");
	if (!expected) return { valid: false };
	const window = Math.min(10, Math.max(0, Math.trunc(opts.window ?? 1)));
	const baseOffset = Math.trunc(opts.counterOffset ?? 0);
	for (let offset = -window; offset <= window; offset += 1) {
		const candidate = generateTotpCode(secret, { ...opts, counterOffset: baseOffset + offset });
		if (candidate.code.length !== expected.length) continue;
		if (timingSafeEqualText(candidate.code, expected)) {
			return { valid: true, matchedOffset: offset, counter: candidate.counter };
		}
	}
	return { valid: false };
}

function scrubWithSet(text: string, secrets: ReadonlySet<string>, root?: string): string {
	if (!text) return "";
	try {
		return scrubTextWithExtraSecrets(text, Array.from(secrets), root);
	} catch {
		return text;
	}
}

function rawErrorMessage(err: unknown): string {
	if (err instanceof Error && err.message) return err.message;
	if (typeof err === "string" && err) return err;
	return "未知错误";
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

function sleep(ms: number): Promise<void> {
	return new Promise((done) => setTimeout(done, Math.max(0, Math.min(ms, 60_000))));
}

function stepTarget(step: AuthPlaybookStep): string {
	switch (step.action) {
		case "goto":
			return step.url;
		case "captureStorage":
			return "storage";
		default:
			return step.selector ?? "";
	}
}

function looksSensitiveSelector(selector: string): boolean {
	return /pass(word)?|pwd|otp|totp|token|secret|code/i.test(selector);
}

function resolveTargetUrl(raw: string, base: string): string | undefined {
	const trimmed = raw.trim();
	if (!trimmed) return undefined;
	if (/^https?:\/\//i.test(trimmed)) return trimmed;
	if (!base || !/^https?:\/\//i.test(base)) return undefined;
	try {
		return new URL(trimmed, base).toString();
	} catch {
		return undefined;
	}
}

function extractUrlTokens(rawUrl: string): Array<{ key: string; value: string }> {
	const out: Array<{ key: string; value: string }> = [];
	const keys = ["access_token", "refresh_token", "id_token", "code", "token", "oauth_token", "oauth_verifier", "client_secret", "session_state"];
	try {
		const parsed = new URL(rawUrl);
		for (const key of keys) {
			for (const value of parsed.searchParams.getAll(key)) {
				if (value && value.length >= 4) out.push({ key, value });
			}
		}
		if (parsed.hash && parsed.hash.length > 1) {
			const frag = parsed.hash.slice(1);
			const qPart = frag.includes("?") ? frag.slice(frag.indexOf("?") + 1) : frag;
			if (qPart.includes("=")) {
				const fp = new URLSearchParams(qPart);
				for (const key of keys) {
					for (const value of fp.getAll(key)) {
						if (value && value.length >= 4) out.push({ key, value });
					}
				}
			}
		}
	} catch {
		return out;
	}
	return out;
}

function pushNavigation(chain: string[], url: string): void {
	if (!url) return;
	if (chain[chain.length - 1] === url) return;
	chain.push(url);
}

// ---------------------------------------------------------------------------
// 页内执行工具
// ---------------------------------------------------------------------------

interface EvalOutcome {
	ok: boolean;
	value?: unknown;
	error?: string;
}

async function evaluateInPage(session: CdpSession, expression: string, timeoutMs: number): Promise<EvalOutcome> {
	try {
		const response = await session.client.send<Record<string, unknown>>("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, { sessionId: session.sessionId, timeoutMs });
		if (response.exceptionDetails) return { ok: false, error: "页面脚本执行异常" };
		const remote = asRecord(response.result);
		return { ok: true, value: remote?.value };
	} catch (err) {
		return { ok: false, error: rawErrorMessage(err) };
	}
}

async function safeSend(session: CdpSession, method: string, params?: Record<string, unknown>): Promise<void> {
	try { await session.client.send(method, params, { sessionId: session.sessionId }); } catch { /* 忽略 */ }
}

async function safeSendResult<T>(session: CdpSession, method: string, params?: Record<string, unknown>): Promise<T | undefined> {
	try { return await session.client.send<T>(method, params, { sessionId: session.sessionId }); } catch { return undefined; }
}

async function readCurrentUrl(session: CdpSession, fallback: string): Promise<string> {
	const outcome = await evaluateInPage(session, "String((window.location && window.location.href) || '')", 5_000);
	return outcome.ok && typeof outcome.value === "string" && outcome.value ? outcome.value : fallback;
}

async function waitForDocumentReady(session: CdpSession, timeoutMs: number): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const outcome = await evaluateInPage(session, "String(document.readyState || '')", 3_000);
		if (outcome.ok && (outcome.value === "complete" || outcome.value === "interactive")) return;
		if (Date.now() >= deadline) return;
		await sleep(120);
	}
}

async function navigateTo(session: CdpSession, url: string, waitUntilLoad: boolean, timeoutMs: number): Promise<void> {
	try { await session.client.send("Page.navigate", { url }, { sessionId: session.sessionId, timeoutMs }); }
	catch (err) { throw new Error(`页面导航失败：${rawErrorMessage(err)}`); }
	if (waitUntilLoad) await waitForDocumentReady(session, timeoutMs);
}

async function waitForSelectorInPage(session: CdpSession, selector: string, visible: boolean, timeoutMs: number): Promise<void> {
	const expression = `(() => {
		const el = document.querySelector(${JSON.stringify(selector)});
		if (!el) return { ok: false };
		if (${visible ? "true" : "false"}) {
			const rect = el.getBoundingClientRect();
			const style = window.getComputedStyle(el);
			if (!(rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none")) return { ok: false };
		}
		return { ok: true };
	})()`;
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const outcome = await evaluateInPage(session, expression, 3_000);
		if (outcome.ok && asRecord(outcome.value)?.ok === true) return;
		if (Date.now() >= deadline) throw new Error("等待页面元素超时，登录剧本中止。");
		await sleep(120);
	}
}

async function waitForNavigation(session: CdpSession, previousUrl: string, timeoutMs: number): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		await sleep(150);
		const current = await readCurrentUrl(session, previousUrl);
		if ((current && current !== previousUrl) || Date.now() >= deadline) return;
	}
}

async function fillInPage(session: CdpSession, selector: string, value: string, clearFirst: boolean, timeoutMs: number): Promise<void> {
	const expression = `(() => {
		const el = document.querySelector(${JSON.stringify(selector)});
		if (!el) return { ok: false, error: "未找到目标输入框" };
		if (${clearFirst ? "true" : "false"}) el.value = "";
		if (typeof el.focus === "function") el.focus();
		el.value = ${JSON.stringify(value)};
		el.dispatchEvent(new Event("input", { bubbles: true }));
		el.dispatchEvent(new Event("change", { bubbles: true }));
		return { ok: true };
	})()`;
	const outcome = await evaluateInPage(session, expression, timeoutMs);
	const payload = asRecord(outcome.value);
	if (!outcome.ok || payload?.ok !== true) throw new Error(typeof payload?.error === "string" ? payload.error : outcome.error ?? "填充输入框失败");
}

async function clickInPage(session: CdpSession, selector: string, timeoutMs: number): Promise<void> {
	const expression = `(() => {
		const el = document.querySelector(${JSON.stringify(selector)});
		if (!el) return { ok: false, error: "未找到可点击元素" };
		if (typeof el.scrollIntoView === "function") el.scrollIntoView({ block: "center" });
		if (typeof el.click !== "function") return { ok: false, error: "元素不可点击" };
		el.click();
		return { ok: true };
	})()`;
	const outcome = await evaluateInPage(session, expression, timeoutMs);
	const payload = asRecord(outcome.value);
	if (!outcome.ok || payload?.ok !== true) {
		throw new Error(typeof payload?.error === "string" ? payload.error : outcome.error ?? "点击元素失败");
	}
}

async function submitInPage(
	session: CdpSession,
	selector: string | undefined,
	timeoutMs: number,
): Promise<void> {
	const expression = `(() => {
		const sel = ${JSON.stringify(selector ?? "")};
		let target = sel ? document.querySelector(sel) : document.activeElement;
		if (!target) return { ok: false, error: "未找到提交目标" };
		const form = target.form || (target.tagName === "FORM" ? target : (target.closest ? target.closest("form") : null));
		if (form) {
			if (typeof form.requestSubmit === "function") { form.requestSubmit(); return { ok: true }; }
			if (typeof form.submit === "function") { form.submit(); return { ok: true }; }
			return { ok: false, error: "表单不可提交" };
		}
		if (typeof target.click === "function") { target.click(); return { ok: true }; }
		return { ok: false, error: "提交目标不可用" };
	})()`;
	const outcome = await evaluateInPage(session, expression, timeoutMs);
	const payload = asRecord(outcome.value);
	if (!outcome.ok || payload?.ok !== true) {
		throw new Error(typeof payload?.error === "string" ? payload.error : outcome.error ?? "提交表单失败");
	}
}

interface CapturedStorageItem {
	storage: "localStorage" | "sessionStorage";
	key: string;
	value: string;
}

async function captureStorageInPage(
	session: CdpSession,
	tokenKeys: readonly string[] | undefined,
	includeSessionStorage: boolean,
	timeoutMs: number,
): Promise<CapturedStorageItem[]> {
	const expression = `(() => {
		const wanted = ${JSON.stringify(tokenKeys ?? [])};
		const pattern = /token|jwt|auth|bearer|session|csrf|xsrf|credential|secret/i;
		const collect = (store, name) => {
			const out = [];
			try {
				for (let i = 0; i < store.length; i += 1) {
					const key = store.key(i);
					if (!key) continue;
					const matched = wanted.length > 0 ? wanted.indexOf(key) >= 0 : pattern.test(key);
					if (!matched) continue;
					const value = store.getItem(key);
					if (typeof value === "string" && value.length > 0) out.push({ storage: name, key, value });
				}
			} catch (err) { /* 忽略不可访问的存储 */ }
			return out;
		};
		const items = collect(window.localStorage, "localStorage");
		if (${includeSessionStorage ? "true" : "false"}) items.push(...collect(window.sessionStorage, "sessionStorage"));
		return { ok: true, items };
	})()`;
	const outcome = await evaluateInPage(session, expression, timeoutMs);
	const payload = asRecord(outcome.value);
	const items = payload?.items;
	if (!Array.isArray(items)) return [];
	const results: CapturedStorageItem[] = [];
	for (const raw of items) {
		const record = asRecord(raw);
		if (!record) continue;
		const storage = record.storage === "sessionStorage" ? "sessionStorage" : "localStorage";
		if (typeof record.key !== "string" || typeof record.value !== "string") continue;
		results.push({ storage, key: record.key, value: record.value });
	}
	return results;
}

function cookieNameValue(cookie: CdpCookieParam): { name: string; value: string; expires?: number } {
	const record = cookie as unknown as Record<string, unknown>;
	const name = typeof record.name === "string" ? record.name : "";
	const value = typeof record.value === "string" ? record.value : "";
	const expires =
		typeof record.expires === "number" && Number.isFinite(record.expires) ? record.expires : undefined;
	return { name, value, expires };
}

async function collectCookies(session: CdpSession, currentUrl: string): Promise<CdpCookieParam[]> {
	const all = await safeSendResult<Record<string, unknown>>(session, "Network.getAllCookies");
	const allCookies = all?.cookies;
	if (Array.isArray(allCookies) && allCookies.length > 0) return allCookies as CdpCookieParam[];
	if (currentUrl) {
		const scoped = await safeSendResult<Record<string, unknown>>(session, "Network.getCookies", {
			urls: [currentUrl],
		});
		const scopedCookies = scoped?.cookies;
		if (Array.isArray(scopedCookies) && scopedCookies.length > 0) {
			return scopedCookies as CdpCookieParam[];
		}
	}
	const outcome = await evaluateInPage(session, "String(document.cookie || '')", 3_000);
	const raw = outcome.ok && typeof outcome.value === "string" ? outcome.value : "";
	const fallback: CdpCookieParam[] = [];
	for (const part of raw.split(";")) {
		const pair = part.trim();
		if (!pair) continue;
		const index = pair.indexOf("=");
		const name = index >= 0 ? pair.slice(0, index).trim() : pair;
		const value = index >= 0 ? pair.slice(index + 1).trim() : "";
		if (!name) continue;
		fallback.push({ name, value } as unknown as CdpCookieParam);
	}
	return fallback;
}

function earliestCookieExpiryIso(cookies: readonly CdpCookieParam[]): string | undefined {
	let earliest: number | undefined;
	for (const cookie of cookies) {
		const { expires } = cookieNameValue(cookie);
		if (!expires || expires <= 0) continue;
		const ms = expires > 10_000_000_000 ? expires : expires * 1000;
		if (earliest === undefined || ms < earliest) earliest = ms;
	}
	return earliest === undefined ? undefined : new Date(earliest).toISOString();
}

function safeVaultSummary(root: string, scrub: (text: string) => string): string {
	try {
		return scrub(formatSessionVaultSummary(root));
	} catch {
		return "（会话仓库暂不可读）";
	}
}

function safeUpsertRole(
	root: string,
	input: Parameters<typeof upsertSessionRole>[1],
): ReturnType<typeof upsertSessionRole> | undefined {
	try {
		return upsertSessionRole(root, input);
	} catch {
		return undefined;
	}
}

// ---------------------------------------------------------------------------
// 交互式登录剧本
// ---------------------------------------------------------------------------

export async function runInteractiveAuthPlaybook(
	opts: InteractiveAuthPlaybookOptions,
): Promise<InteractiveAuthPlaybookResult> {
	const root = resolve(opts.root);
	const mode = opts.mode;
	const stepTimeoutDefault = Math.max(1_000, Math.trunc(opts.stepTimeoutMs ?? 20_000));
	const secrets = new Set<string>();
	const scrub = (text: string): string => scrubWithSet(text, secrets, root);
	const scrubUrl = (rawUrl: string): string =>
		scrub(redactTrafficUrl(rawUrl, { root, extraSecrets: Array.from(secrets) }));

	const registerSecret = (value: string | undefined): void => {
		if (typeof value !== "string") return;
		const trimmed = value.trim();
		if (trimmed.length < 4) return;
		secrets.add(trimmed);
		try {
			opts.recorder?.registerTransientSecret(trimmed);
		} catch {
			// 登记失败不影响主流程
		}
	};

	for (const extra of opts.extraSecrets ?? []) registerSecret(extra);

	const stepSummaries: AuthPlaybookStepSummary[] = [];
	const navigationChain: string[] = [];
	const capturedSources = new Set<string>();
	const blockedRequests: BlockedCdpRequest[] = [];
	const collectedCookies = new Map<string, string>();
	const storageTokens = new Map<string, string>();
	let csrfHeaderName: string | undefined;
	let csrfCookieName: string | undefined;
	let bearerToken: string | undefined;
	let ok = false;
	let error: string | undefined;
	let finalUrl = "";
	let blockedByScope = false;
	let blockReason: string | undefined;
	let expiresAt: string | undefined;
	let sessionClosed = false;
	let session: CdpSession | undefined = opts.session;
	const ownsSession = !opts.session;

	// 1) 授权范围前置校验：绝对 URL 立即校验，相对路径待补齐 origin 后校验
	for (const step of opts.steps) {
		if (step.action !== "goto") continue;
		const target = step.url.trim();
		if (!target) {
			blockedByScope = true;
			blockReason = formatScopeBlockReason("egress-proxy", "登录剧本的 goto 步骤缺少目标地址");
			break;
		}
		if (!/^https?:\/\//i.test(target)) continue;
		const verdict = checkHttpTargetScope(target, "GET", opts.scope, mode, "登录剧本目标");
		if (!verdict.ok) {
			blockedByScope = true;
			blockReason = verdict.reason;
			break;
		}
	}
	if (blockedByScope) {
		return {
			ok: false,
			role: opts.role,
			blockedByScope: true,
			blockReason: scrub(blockReason ?? "登录剧本被授权范围拦截"),
			finalUrl: "",
			navigationChain: [],
			steps: [],
			blockedRequests: [],
			capturedCredentialSources: [],
			sessionClosed: false,
			vaultSummary: safeVaultSummary(root, scrub),
			error: scrub(blockReason ?? "登录剧本被授权范围拦截"),
		};
	}

	const disposers: Array<() => void> = [];
	let interceptorState: Awaited<ReturnType<typeof ensureStatefulCapableInterceptor>> | undefined;
	try {
		const activeSession: CdpSession = session ?? (await launchCdpSession(opts.launchOptions));
		session = activeSession;

		// 2) 安装有状态拦截器并启用所需域
		interceptorState = await ensureStatefulCapableInterceptor(activeSession, opts.scope, mode);
		await safeSend(activeSession, "Page.enable");
		await safeSend(activeSession, "Runtime.enable");
		await safeSend(activeSession, "Network.enable");

		// 3) 初始 Cookie 与额外请求头
		if (opts.initialCookies && opts.initialCookies.length > 0) {
			await safeSend(activeSession, "Network.setCookies", { cookies: opts.initialCookies });
		}
		if (opts.extraHeaders) {
			const normalized = normalizeCdpHeadersObject(opts.extraHeaders);
			for (const value of Object.values(normalized)) registerSecret(value);
			for (const secret of extractSecretsFromHeadersMap(normalized)) registerSecret(secret);
			await safeSend(activeSession, "Network.setExtraHTTPHeaders", { headers: normalized });
		}

		// 4) 网络事件监听：记录脱敏流量
		const recorder = opts.recorder;
		if (recorder) {
			const pending = new Map<string, { method: string; url: string; headers: Record<string, string>; body?: string; startedAt: number; role: string }>();
			const onRequest = (params: Record<string, unknown>): void => {
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				const request = asRecord(params.request);
				const rawUrl = typeof request?.url === "string" ? request.url : "";
				if (!requestId || !rawUrl) return;
				const method = typeof request?.method === "string" ? request.method : "GET";
				const headers = normalizeCdpHeadersObject(request?.headers);
				const postData = typeof request?.postData === "string" ? request.postData : undefined;
				pending.set(requestId, { method, url: rawUrl, headers, body: postData, startedAt: Date.now(), role: opts.role });
			};
			const onResponse = (params: Record<string, unknown>): void => {
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				const entry = requestId ? pending.get(requestId) : undefined;
				if (!entry) return;
				pending.delete(requestId);
				const response = asRecord(params.response);
				const status = typeof response?.status === "number" ? response.status : 0;
				const responseHeaders = normalizeCdpHeadersObject(response?.headers);
				for (const sec of extractSecretsFromHeadersMap(responseHeaders)) registerSecret(sec);
				try {
					recorder.record({ method: entry.method, url: entry.url, requestHeaders: entry.headers, requestBody: entry.body, status, responseHeaders, durationMs: Date.now() - entry.startedAt, tags: ["auth-playbook"], role: entry.role });
				} catch { /* 忽略 */ }
			};
			const onFailed = (params: Record<string, unknown>): void => {
				const requestId = typeof params.requestId === "string" ? params.requestId : "";
				if (requestId) pending.delete(requestId);
			};
			disposers.push(activeSession.client.on("Network.requestWillBeSent", onRequest));
			disposers.push(activeSession.client.on("Network.responseReceived", onResponse));
			disposers.push(activeSession.client.on("Network.loadingFailed", onFailed));
		}

		// 5) 逐步骤执行选定的动作集合
		for (let index = 0; index < opts.steps.length; index += 1) {
			const step = opts.steps[index]!;
			const target = stepTarget(step);
			const startedAt = Date.now();
			const stepTimeout = Math.max(1_000, Math.trunc(typeof step.timeoutMs === "number" ? step.timeoutMs : stepTimeoutDefault));
			let currentUrl = navigationChain[navigationChain.length - 1] ?? finalUrl;
			try {
				switch (step.action) {
					case "goto": {
						const targetUrl = resolveTargetUrl(step.url, currentUrl);
						if (!targetUrl) throw new Error("无法解析 goto 目标地址");
						const verdict = checkHttpTargetScope(targetUrl, "GET", opts.scope, mode, "登录剧本目标");
						if (!verdict.ok) {
							blockedByScope = true;
							blockReason = verdict.reason;
							throw new Error(blockReason);
						}
						await navigateTo(activeSession, targetUrl, step.waitUntilLoad !== false, stepTimeout);
						if (step.settleMs && step.settleMs > 0) await sleep(step.settleMs);
						currentUrl = await readCurrentUrl(activeSession, targetUrl);
						pushNavigation(navigationChain, currentUrl);
						break;
					}
					case "waitForSelector": {
						await waitForSelectorInPage(activeSession, step.selector, step.visible !== false, stepTimeout);
						break;
					}
					case "fill": {
						const isSensitive = step.isSecret !== false || looksSensitiveSelector(step.selector);
						if (isSensitive) registerSecret(step.value);
						await fillInPage(activeSession, step.selector, step.value, step.clearFirst !== false, stepTimeout);
						break;
					}
					case "click": {
						const previousUrl = await readCurrentUrl(activeSession, currentUrl);
						await clickInPage(activeSession, step.selector, stepTimeout);
						if (step.waitForNavigation !== false) await waitForNavigation(activeSession, previousUrl, stepTimeout);
						if (step.settleMs && step.settleMs > 0) await sleep(step.settleMs);
						const next = await readCurrentUrl(activeSession, previousUrl);
						pushNavigation(navigationChain, next);
						for (const oauth of extractUrlTokens(next)) {
							registerSecret(oauth.value);
							capturedSources.add(`url:${oauth.key}`);
						}
						break;
					}
					case "fillTotp": {
						registerSecret(step.secret);
						const token = generateTotpCode(step.secret, step.totpOptions);
						registerSecret(token.code);
						await fillInPage(activeSession, step.selector, token.code, true, stepTimeout);
						break;
					}
					case "submit": {
						const previousUrl = await readCurrentUrl(activeSession, currentUrl);
						await submitInPage(activeSession, step.selector, stepTimeout);
						if (step.waitForNavigation !== false) await waitForNavigation(activeSession, previousUrl, stepTimeout);
						if (step.settleMs && step.settleMs > 0) await sleep(step.settleMs);
						const next = await readCurrentUrl(activeSession, previousUrl);
						pushNavigation(navigationChain, next);
						for (const oauth of extractUrlTokens(next)) {
							registerSecret(oauth.value);
							capturedSources.add(`url:${oauth.key}`);
						}
						break;
					}
					case "captureStorage": {
						const items = await captureStorageInPage(activeSession, step.tokenKeys, step.includeSessionStorage !== false, stepTimeout);
						for (const item of items) {
							registerSecret(item.value);
							const stripped = item.value.replace(/^bearer\s+/i, "").trim();
							if (stripped && stripped !== item.value) registerSecret(stripped);
							storageTokens.set(`${item.storage}:${item.key}`, item.value);
							capturedSources.add(`${item.storage}:${item.key}`);
							if (!bearerToken && stripped && /^bearer\s+/i.test(item.value)) bearerToken = stripped;
						}
						break;
					}
					default: {
						const neverStep: never = step;
						throw new Error(`未支持的步骤动作：${String((neverStep as { action?: unknown }).action ?? "unknown")}`);
					}
				}
				currentUrl = await readCurrentUrl(activeSession, currentUrl);
				pushNavigation(navigationChain, currentUrl);
				for (const oauth of extractUrlTokens(currentUrl)) {
					registerSecret(oauth.value);
					capturedSources.add(`url:${oauth.key}`);
				}
				stepSummaries.push({ stepIndex: index, action: step.action, target: scrubUrl(target), ok: true, durationMs: Date.now() - startedAt, currentUrl: scrubUrl(currentUrl) });
			} catch (err) {
				const message = scrub(rawErrorMessage(err));
				stepSummaries.push({ stepIndex: index, action: step.action, target: scrubUrl(target), ok: false, blockedByScope: blockedByScope || undefined, durationMs: Date.now() - startedAt, currentUrl: scrubUrl(currentUrl), error: message });
				if (blockedByScope) blockReason = message;
				throw new Error(message);
			}
		}

		// 6) 提取 Cookie / Bearer / CSRF
		finalUrl =
			navigationChain[navigationChain.length - 1] ??
			(await readCurrentUrl(activeSession, finalUrl));
		const cookies = await collectCookies(activeSession, finalUrl);
		let cookieHeaderValue = "";
		for (const cookie of cookies) {
			const { name, value } = cookieNameValue(cookie);
			if (!name) continue;
			collectedCookies.set(name, value);
			registerSecret(value);
			capturedSources.add(`cookie:${name}`);
			if (/csrf|xsrf/i.test(name)) {
				csrfCookieName = csrfCookieName ?? name;
			}
			cookieHeaderValue += `${cookieHeaderValue ? "; " : ""}${name}=${value}`;
		}
		if (cookieHeaderValue) {
			for (const secret of extractSecretsFromHeadersMap({ cookie: cookieHeaderValue })) registerSecret(secret);
		}

		// storage 中的 Bearer / CSRF 提取
		for (const [key, value] of storageTokens) {
			if (!bearerToken && /token|jwt|bearer/i.test(key)) {
				const trimmed = value.replace(/^bearer\s+/i, "").trim();
				if (trimmed) bearerToken = trimmed;
			}
			if (!csrfHeaderName && /csrf|xsrf/i.test(key)) {
				csrfHeaderName = key.replace(/^localStorage:|^sessionStorage:/, "");
			}
		}
		if (csrfHeaderName) {
			const fromLocal = storageTokens.get(`localStorage:${csrfHeaderName}`);
			const fromSession = storageTokens.get(`sessionStorage:${csrfHeaderName}`);
			if (fromLocal) registerSecret(fromLocal);
			if (fromSession) registerSecret(fromSession);
		}

		// 7) 计算过期时间（优先 Bearer JWT，其次 Cookie 最早失效）
		if (bearerToken) {
			try {
				expiresAt = decodeJwtExpiryIso(bearerToken);
			} catch {
				expiresAt = undefined;
			}
		}
		if (!expiresAt) expiresAt = earliestCookieExpiryIso(cookies);

		// 8) 写入 SessionVault
		const roleHeaders: Record<string, string> = {};
		if (bearerToken) roleHeaders.Authorization = `Bearer ${bearerToken}`;
		const csrfTokenValue =
			(csrfHeaderName ? storageTokens.get(`localStorage:${csrfHeaderName}`) : undefined) ??
			(csrfHeaderName ? storageTokens.get(`sessionStorage:${csrfHeaderName}`) : undefined);
		if (csrfHeaderName && csrfTokenValue) roleHeaders[csrfHeaderName] = csrfTokenValue;
		safeUpsertRole(root, {
			role: opts.role,
			cookie: cookieHeaderValue || undefined,
			bearer: bearerToken,
			headers: Object.keys(roleHeaders).length > 0 ? roleHeaders : undefined,
			username: opts.username,
			checkUrl: opts.checkUrl,
			csrfHeader: csrfHeaderName,
			csrfCookie: csrfCookieName,
			updatedAt: new Date().toISOString(),
		});

		ok = true;
	} catch (err) {
		ok = false;
		error = scrub(rawErrorMessage(err));
	} finally {
		if (interceptorState?.blockedRequests?.length) {
			blockedRequests.push(...interceptorState.blockedRequests);
		}
		for (const dispose of disposers) {
			try {
				dispose();
			} catch {
				// 忽略
			}
		}
		const shouldClose = ownsSession
			? true
			: ok
				? opts.closeSessionOnSuccess === true
				: opts.keepSessionOnFailure !== true;
		if (session && shouldClose) {
			try {
				await closeCdpSession(session);
				sessionClosed = true;
			} catch {
				sessionClosed = false;
			}
		}
	}

	const safeFinalUrl = scrubUrl(
		finalUrl || (navigationChain[navigationChain.length - 1] ?? ""),
	);
	const safeChain = navigationChain.map((item) => scrubUrl(item)).filter(Boolean);
	const safeSteps = stepSummaries.map((item) => ({
		...item,
		target: scrubUrl(item.target),
		currentUrl: item.currentUrl ? scrubUrl(item.currentUrl) : undefined,
		error: item.error ? scrub(item.error) : undefined,
	}));
	const safeBlockedRequests: BlockedCdpRequest[] = blockedRequests.map((item) => {
		const record = item as unknown as Record<string, unknown>;
		const sanitized: Record<string, unknown> = { ...record };
		if (typeof sanitized.url === "string") sanitized.url = scrubUrl(sanitized.url);
		if (typeof sanitized.reason === "string") sanitized.reason = scrub(sanitized.reason);
		return sanitized as unknown as BlockedCdpRequest;
	});
	return {
		ok,
		role: opts.role,
		blockedByScope,
		blockReason: blockReason ? scrub(blockReason) : undefined,
		finalUrl: safeFinalUrl,
		navigationChain: safeChain,
		steps: safeSteps,
		blockedRequests: safeBlockedRequests,
		capturedCredentialSources: Array.from(capturedSources).sort(),
		expiresAt,
		sessionClosed,
		vaultSummary: safeVaultSummary(root, scrub),
		error,
	};
}
/* Part 2：会话续期触发器、401/403 失败计数与 ensureSessionFresh 编排。 */

export type SessionRefreshTriggerReason = "missing_credentials" | "already_expired" | "jwt_expiring_soon" | "consecutive_401_403" | "health_check_failed" | "forced";

export interface EnsureSessionFreshOptions {
	session?: CdpSession; steps?: readonly AuthPlaybookStep[]; refreshRunner?: () => Promise<InteractiveAuthPlaybookResult>;
	minRemainingSeconds?: number; authFailureThreshold?: number; recentStatuses?: readonly number[]; observedStatus?: number;
	checkUrl?: string; healthFetchFn?: RoleHealthFetchLike; nowMs?: number; forceRefresh?: boolean; mode?: Mode | string;
	username?: string; extraSecrets?: string[]; recorder?: TrafficRecorder; launchOptions?: LaunchCdpSessionOptions;
}

export interface EnsureSessionFreshResult {
	ok: boolean; role: string; fresh: boolean; refreshed: boolean; triggerReason?: SessionRefreshTriggerReason;
	remainingSecondsBefore?: number; remainingSecondsAfter?: number; expiresAt?: string;
	consecutiveFailuresBefore: number; consecutiveFailuresAfter: number;
	playbookResult?: InteractiveAuthPlaybookResult; vaultSummary: string; error?: string;
}

interface AuthFailureLedger { schema: 1; updatedAt: string; roles: Record<string, number>; }
const AUTH_LEDGER_RELATIVE_PATH = ".nuwa/sessions/auth-failures.json" as const;

function isPlainRecord(value: unknown): value is Record<string, unknown> { return typeof value === "object" && value !== null && !Array.isArray(value); }
function authLedgerPath(root: string): string { return `${root.replace(/[\\/]+$/u, "")}/${AUTH_LEDGER_RELATIVE_PATH}`; }

function readAuthLedger(root: string): AuthFailureLedger {
	const roles: Record<string, number> = {};
	try {
		const parsed: unknown = JSON.parse(readFileSync(authLedgerPath(root), "utf8"));
		if (isPlainRecord(parsed) && isPlainRecord(parsed["roles"])) {
			for (const [key, value] of Object.entries(parsed["roles"])) {
				if (typeof value === "number" && Number.isFinite(value) && value > 0) roles[key] = Math.floor(value);
			}
		}
		const updatedAt = isPlainRecord(parsed) && typeof parsed["updatedAt"] === "string" ? parsed["updatedAt"] : new Date(0).toISOString();
		return { schema: 1, updatedAt, roles };
	} catch {
		return { schema: 1, updatedAt: new Date(0).toISOString(), roles };
	}
}

function writeAuthLedger(root: string, ledger: AuthFailureLedger): void {
	const file = authLedgerPath(root);
	const dir = dirname(file);
	if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
	const tmp = `${file}.${nodeCrypto.randomUUID()}.tmp`;
	try {
		writeFileSync(tmp, `${JSON.stringify(ledger, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
		renameSync(tmp, file);
	} catch (err) {
		try { unlinkSync(tmp); } catch { /* 忽略 */ }
		throw err;
	}
}

export function recordRoleAuthStatus(root: string, role: string, status: number): number {
	const key = role.trim();
	const ledger = readAuthLedger(root);
	const current = ledger.roles[key] ?? 0;
	if (!(status > 0)) return current;
	const next = status === 401 || status === 403 ? current + 1 : 0;
	if (next === current) return current;
	ledger.roles[key] = next; ledger.updatedAt = new Date().toISOString();
	writeAuthLedger(root, ledger);
	return next;
}

export function getRoleConsecutiveAuthFailures(root: string, role: string): number { return readAuthLedger(root).roles[role.trim()] ?? 0; }
export function resetRoleAuthFailures(root: string, role: string): void {
	const key = role.trim();
	const ledger = readAuthLedger(root);
	if (ledger.roles[key] === undefined) return;
	delete ledger.roles[key]; ledger.updatedAt = new Date().toISOString();
	writeAuthLedger(root, ledger);
}

type VaultSnapshot = ReturnType<typeof loadSessionVault>;
type VaultRoleEntry = VaultSnapshot["roles"][string] | undefined;

function resolveMode(input: Mode | string | undefined): Mode {
	return input === "ctf" || input === "pentest" || input === "audit" || input === "coding" || input === "ops" ? input : "pentest";
}

function entryHasCredentials(entry: VaultRoleEntry): boolean {
	if (!entry) return false;
	return Boolean((typeof entry.cookie === "string" && entry.cookie.trim()) || (typeof entry.bearer === "string" && entry.bearer.trim()) || (entry.headers && Object.keys(entry.headers).length > 0));
}

function entryExpiresAt(entry: VaultRoleEntry): string | undefined {
	if (!entry) return undefined;
	if (typeof entry.expiresAt === "string" && entry.expiresAt.length > 0) return entry.expiresAt;
	return typeof entry.bearer === "string" && entry.bearer.length > 0 ? decodeJwtExpiryIso(entry.bearer) : undefined;
}

function remainingSecondsOf(expiresAt: string | undefined, nowMs: number): number | undefined {
	if (!expiresAt) return undefined;
	const parsed = Date.parse(expiresAt);
	return Number.isFinite(parsed) ? Math.round((parsed - nowMs) / 1000) : undefined;
}

function countTrailingAuthFailures(statuses: readonly number[]): number {
	let count = 0;
	for (let i = statuses.length - 1; i >= 0; i -= 1) {
		if (statuses[i] !== 401 && statuses[i] !== 403) break;
		count += 1;
	}
	return count;
}

function collectSecrets(opts: EnsureSessionFreshOptions, entry: VaultRoleEntry): string[] {
	const secrets = new Set<string>();
	const push = (value: string | undefined): void => { if (typeof value === "string" && value.length >= 3) secrets.add(value); };
	for (const secret of opts.extraSecrets ?? []) push(secret);
	push(opts.username); push(entry?.username); push(entry?.password);
	return [...secrets];
}

async function probeRoleHealth(root: string, role: string, scope: ScopePolicy, mode: Mode, checkUrl: string, opts: EnsureSessionFreshOptions, secrets: readonly string[]) {
	const vault = loadSessionVault(root);
	const scopeVerdict = checkHttpTargetScope(checkUrl, "GET", scope, mode, "健康检查目标");
	if (!scopeVerdict.ok) {
		const blocked = formatScopeBlockReason("egress-proxy", scopeVerdict.reason ?? `${role} 的 checkUrl 不在授权范围内`);
		return { ok: false, scopeBlocked: true, detail: scrubTextWithExtraSecrets(blocked, [...secrets], vault) };
	}
	const health = await checkRoleHealth(root, role, { checkUrl, scope, fetchFn: opts.healthFetchFn, nowMs: opts.nowMs });
	const healthy = health.healthy === true;
	const raw = healthy ? `${role} 在线健康检查通过` : `${role} 在线健康检查失败（${health.reason}）`;
	return { ok: healthy, scopeBlocked: false, detail: scrubTextWithExtraSecrets(raw, [...secrets], vault) };
}

async function runSessionRefresh(root: string, role: string, scope: ScopePolicy, mode: Mode, opts: EnsureSessionFreshOptions, secrets: readonly string[]): Promise<InteractiveAuthPlaybookResult> {
	if (opts.refreshRunner) return await opts.refreshRunner();
	const steps = opts.steps ?? [];
	if (steps.length === 0) throw new Error("缺少续期执行器：opts.refreshRunner 与 opts.steps 均为空");
	return await runInteractiveAuthPlaybook({ session: opts.session, role, steps, root, scope, mode, username: opts.username, checkUrl: opts.checkUrl, extraSecrets: [...secrets], recorder: opts.recorder, launchOptions: opts.launchOptions });
}

export async function ensureSessionFresh(root: string, role: string, scope: ScopePolicy, opts: EnsureSessionFreshOptions = {}): Promise<EnsureSessionFreshResult> {
	const nowMs = opts.nowMs ?? Date.now();
	const minRemainingSeconds = opts.minRemainingSeconds ?? DEFAULT_SESSION_MIN_TTL_SECONDS;
	const failureThreshold = opts.authFailureThreshold ?? DEFAULT_AUTH_FAILURE_THRESHOLD;
	const mode = resolveMode(opts.mode);
	let vault = loadSessionVault(root);
	let entry = vault.roles[role];
	const secrets = collectSecrets(opts, entry);

	let failuresBefore = getRoleConsecutiveAuthFailures(root, role);
	if (typeof opts.observedStatus === "number" && opts.observedStatus > 0) failuresBefore = recordRoleAuthStatus(root, role, opts.observedStatus);
	const effectiveFailures = Math.max(failuresBefore, countTrailingAuthFailures(opts.recentStatuses ?? []));
	const expiresAtBefore = entryExpiresAt(entry);
	const remainingBefore = remainingSecondsOf(expiresAtBefore, nowMs);

	let triggerReason: SessionRefreshTriggerReason | undefined;
	if (opts.forceRefresh === true) triggerReason = "forced";
	else if (!entryHasCredentials(entry)) triggerReason = "missing_credentials";
	else if (remainingBefore !== undefined && remainingBefore <= 0) triggerReason = "already_expired";
	else if (remainingBefore !== undefined && remainingBefore < minRemainingSeconds) triggerReason = "jwt_expiring_soon";
	if (!triggerReason && effectiveFailures >= failureThreshold) triggerReason = "consecutive_401_403";

	let healthDetail: string | undefined;
	const effectiveCheckUrl = opts.checkUrl ?? entry?.checkUrl;
	if (!triggerReason && typeof effectiveCheckUrl === "string" && effectiveCheckUrl.length > 0) {
		const health = await probeRoleHealth(root, role, scope, mode, effectiveCheckUrl, opts, secrets);
		if (health.scopeBlocked) {
			return { ok: false, role, fresh: false, refreshed: false, consecutiveFailuresBefore: failuresBefore, consecutiveFailuresAfter: failuresBefore, vaultSummary: formatSessionVaultSummary(vault), error: health.detail };
		}
		if (!health.ok) { triggerReason = "health_check_failed"; healthDetail = health.detail; }
	}

	if (!triggerReason) {
		return { ok: true, role, fresh: true, refreshed: false, remainingSecondsBefore: remainingBefore, remainingSecondsAfter: remainingBefore, expiresAt: expiresAtBefore, consecutiveFailuresBefore: failuresBefore, consecutiveFailuresAfter: failuresBefore, vaultSummary: formatSessionVaultSummary(vault) };
	}

	let playbookResult: InteractiveAuthPlaybookResult | undefined;
	let error: string | undefined;
	try { playbookResult = await runSessionRefresh(root, role, scope, mode, opts, secrets); }
	catch (err) { error = err instanceof Error ? err.message : String(err); }

	const refreshed = playbookResult?.ok === true;
	if (refreshed) {
		resetRoleAuthFailures(root, role);
		vault = loadSessionVault(root);
		entry = vault.roles[role];
	} else if (!error) error = playbookResult?.error ?? healthDetail ?? "续期剧本未返回成功状态";

	const expiresAtAfter = refreshed ? entryExpiresAt(entry) : expiresAtBefore;
	const remainingAfter = refreshed ? remainingSecondsOf(expiresAtAfter, nowMs) : remainingBefore;
	return { ok: refreshed, role, fresh: refreshed, refreshed, triggerReason, remainingSecondsBefore: remainingBefore, remainingSecondsAfter: remainingAfter, expiresAt: expiresAtAfter, consecutiveFailuresBefore: failuresBefore, consecutiveFailuresAfter: refreshed ? 0 : failuresBefore, playbookResult, vaultSummary: formatSessionVaultSummary(vault), error: error === undefined ? undefined : scrubTextWithExtraSecrets(error, secrets, vault) };
}

export * from "./cdp-signed-probe";
