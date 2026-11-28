/**
 * 女娲 v8.0.0 内置零信任抗 DNS 重绑定 Scoped Egress Proxy 服务模块（HTTP 正向代理 + HTTPS CONNECT 隧道）。
 *
 * 约束：纯底层模块，仅依赖 Node 内置网络/DNS 模块、`./scope` 与 `./types`，严禁导入 `./nuwa` 或 `./sandbox`。
 */
import { lookup as dnsLookupAll } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { isHostInScope } from "./scope";
import type { ScopePolicy } from "./types";

// ══════════════════════════════════════════════════════════════════════════════
// v5.0 内置 Scoped Egress Proxy（HTTP 正向代理 + HTTPS CONNECT 隧道 + 防 DNS 重绑定）
// ══════════════════════════════════════════════════════════════════════════════

export interface EgressTrafficRecord {
	ts: string;
	method: string;
	url: string;
	host: string;
	port: number;
	resolvedIps?: string[];
	status: number;
	allowed: boolean;
	reason?: string;
	responsePreview?: string;
}

export interface EgressProxyOptions {
	host?: string;
	port?: number;
	timeoutMs?: number;
	dnsLookup?: (hostname: string) => Promise<string[]>;
	onTraffic?: (rec: EgressTrafficRecord) => void;
}

export interface ScopedEgressProxyHandle {
	host: string;
	port: number;
	url: string;
	stats: () => { allowed: number; blocked: number; total: number };
	close: () => Promise<void>;
}

export interface EgressTargetValidation {
	ok: boolean;
	hostname: string;
	resolvedIps: string[];
	reason?: string;
}

function normalizeEgressHost(raw: string): string {
	let s = String(raw ?? "").trim();
	if (s.startsWith("[") && s.endsWith("]")) {
		s = s.slice(1, -1);
	}
	return s.replace(/\.+$/, "").toLowerCase();
}

function parseIpv4Int(ip: string): number | null {
	const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
	if (!m) return null;
	let acc = 0;
	for (let i = 1; i <= 4; i++) {
		const part = m[i]!;
		if (part.length > 1 && part.startsWith("0")) return null;
		const n = Number(part);
		if (!Number.isInteger(n) || n < 0 || n > 255) return null;
		acc = ((acc << 8) | n) >>> 0;
	}
	return acc >>> 0;
}

function parseIpv4Cidr(cidr: string): { net: number; mask: number } | null {
	const slash = cidr.indexOf("/");
	if (slash < 0) return null;
	const ipPart = cidr.slice(0, slash).trim();
	const prefixPart = cidr.slice(slash + 1).trim();
	if (!/^\d{1,2}$/.test(prefixPart)) return null;
	const prefix = Number(prefixPart);
	if (prefix < 0 || prefix > 32) return null;
	const ip = parseIpv4Int(ipPart);
	if (ip === null) return null;
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return { net: (ip & mask) >>> 0, mask };
}

/** 提取纯 IPv4 或 IPv4-mapped IPv6（如 ::ffff:169.254.169.254 / ::ffff:a9fe:a9fe）对应的 32 位 IPv4 整数。 */
function extractMappedIpv4Int(ip: string): number | null {
	const norm = normalizeEgressHost(ip);
	const direct = parseIpv4Int(norm);
	if (direct !== null) return direct;
	if (norm.startsWith("::ffff:")) {
		const tail = norm.slice(7);
		const dotted = parseIpv4Int(tail);
		if (dotted !== null) return dotted;
		const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(tail);
		if (hexMatch) {
			const hi = Number.parseInt(hexMatch[1]!, 16);
			const lo = Number.parseInt(hexMatch[2]!, 16);
			return (((hi << 16) | lo) >>> 0);
		}
	}
	return null;
}

function isLinkLocalOrMetadataIp(ip: string): boolean {
	const v4 = extractMappedIpv4Int(ip);
	if (v4 !== null) {
		const b0 = (v4 >>> 24) & 0xff;
		const b1 = (v4 >>> 16) & 0xff;
		// 169.254.0.0/16 链路本地与云元数据（169.254.169.254 / 169.254.170.2 等）
		return b0 === 169 && b1 === 254;
	}
	const norm = normalizeEgressHost(ip);
	// IPv6 链路本地 fe80::/10
	return /^fe[89ab][0-9a-f]:/i.test(norm) || norm === "fe80::";
}

function isLoopbackOrUnspecifiedIp(ip: string): boolean {
	const v4 = extractMappedIpv4Int(ip);
	if (v4 !== null) {
		const b0 = (v4 >>> 24) & 0xff;
		return b0 === 127 || b0 === 0;
	}
	const norm = normalizeEgressHost(ip);
	return (
		norm === "::1" ||
		norm === "::" ||
		norm === "0:0:0:0:0:0:0:1" ||
		norm === "0:0:0:0:0:0:0:0"
	);
}

function isPrivateRangeIp(ip: string): boolean {
	const v4 = extractMappedIpv4Int(ip);
	if (v4 !== null) {
		const b0 = (v4 >>> 24) & 0xff;
		const b1 = (v4 >>> 16) & 0xff;
		if (b0 === 10) return true;
		if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
		if (b0 === 192 && b1 === 168) return true;
		return false;
	}
	const norm = normalizeEgressHost(ip);
	// IPv6 Unique Local Address fc00::/7
	return /^f[cd][0-9a-f]{2}:/i.test(norm);
}

function ipMatchesExplicitPattern(ip: string, rawPattern: string): boolean {
	const pat = normalizeEgressHost(rawPattern);
	if (!pat || pat === "*" || pat.startsWith("*.")) return false;
	const normIp = normalizeEgressHost(ip);
	if (normIp === pat) return true;

	const v4 = extractMappedIpv4Int(normIp);
	if (v4 !== null) {
		const patV4 = extractMappedIpv4Int(pat);
		if (patV4 !== null && patV4 === v4) return true;
		const cidr = parseIpv4Cidr(pat);
		if (cidr && ((v4 & cidr.mask) >>> 0) === cidr.net) return true;
	}
	return false;
}

function isIpExplicitlyAllowed(ip: string, scope: ScopePolicy): boolean {
	for (const a of scope.allowHosts ?? []) {
		if (ipMatchesExplicitPattern(ip, a)) return true;
	}
	for (const c of scope.allowCidrs ?? []) {
		if (ipMatchesExplicitPattern(ip, c)) return true;
	}
	return false;
}

function isIpInDenyHosts(ip: string, scope: ScopePolicy): string | null {
	const normIp = normalizeEgressHost(ip);
	const ipLoopback = isLoopbackOrUnspecifiedIp(normIp);
	for (const rawDeny of scope.denyHosts ?? []) {
		const deny = normalizeEgressHost(rawDeny);
		if (!deny) continue;
		if (deny === "*") return rawDeny;
		if (ipMatchesExplicitPattern(normIp, deny)) return rawDeny;
		if (ipLoopback && (deny === "localhost" || deny.endsWith(".localhost") || isLoopbackOrUnspecifiedIp(deny))) {
			return rawDeny;
		}
	}
	return null;
}

async function defaultDnsLookup(hostname: string): Promise<string[]> {
	const records = await dnsLookupAll(hostname, { all: true, verbatim: true });
	const seen = new Set<string>();
	const out: string[] = [];
	for (const rec of records) {
		const addr = normalizeEgressHost(rec.address);
		if (addr && !seen.has(addr)) {
			seen.add(addr);
			out.push(addr);
		}
	}
	return out;
}

/**
 * 校验出站代理目标主机名与真实 DNS 解析结果，防止 DNS 重绑定至云元数据、禁用的回环或未授权私网。
 */
export async function validateEgressTarget(
	hostname: string,
	scope: ScopePolicy,
	dnsLookup?: (hostname: string) => Promise<string[]>,
): Promise<EgressTargetValidation> {
	const normHost = normalizeEgressHost(hostname);
	if (!normHost) {
		return { ok: false, hostname: "", resolvedIps: [], reason: "nuwa-egress N-007: 目标主机为空" };
	}

	const hostRes = isHostInScope(normHost, scope);
	if (!hostRes.ok) {
		return {
			ok: false,
			hostname: normHost,
			resolvedIps: [],
			reason: `nuwa-egress N-007: ${hostRes.reason ?? "目标不在授权 Scope 内"}`,
		};
	}

	// 1. 若目标本身为 IP 字面量，仍需强制拦截未显式授权的链路本地/云元数据地址（即使 allowHosts 含 *）
	if (net.isIP(normHost) !== 0) {
		if (isLinkLocalOrMetadataIp(normHost) && !isIpExplicitlyAllowed(normHost, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps: [normHost],
				reason: `nuwa-egress N-007: 禁止访问链路本地/云元数据地址 (${normHost})`,
			};
		}
		return { ok: true, hostname: normHost, resolvedIps: [normHost] };
	}

	// 2. 域名目标：解析真实 IP 并逐一核验，消除 TOCTOU DNS 重绑定窗口
	const resolver = dnsLookup ?? defaultDnsLookup;
	let rawIps: string[];
	try {
		rawIps = await resolver(normHost);
	} catch (err) {
		return {
			ok: false,
			hostname: normHost,
			resolvedIps: [],
			reason: `nuwa-egress N-007: DNS 解析失败 (${normHost}) — ${err instanceof Error ? err.message : String(err)}`,
		};
	}

	const resolvedIps: string[] = [];
	const seen = new Set<string>();
	for (const raw of rawIps ?? []) {
		const ip = normalizeEgressHost(raw);
		if (!ip || net.isIP(ip) === 0) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 返回非法 IP 地址 (${String(raw)})`,
			};
		}
		if (!seen.has(ip)) {
			seen.add(ip);
			resolvedIps.push(ip);
		}
	}

	if (resolvedIps.length === 0) {
		return {
			ok: false,
			hostname: normHost,
			resolvedIps: [],
			reason: `nuwa-egress N-007: DNS 未解析到有效 IP (${normHost})`,
		};
	}

	for (const ip of resolvedIps) {
		const deniedBy = isIpInDenyHosts(ip, scope);
		if (deniedBy) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 命中 denyHosts ${deniedBy})`,
			};
		}
		if (isLinkLocalOrMetadataIp(ip) && !isIpExplicitlyAllowed(ip, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 为云元数据/链路本地地址)`,
			};
		}
		if (isLoopbackOrUnspecifiedIp(ip) && scope.allowLoopback === false && !isIpExplicitlyAllowed(ip, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 为回环地址且 allowLoopback=false)`,
			};
		}
		if (isPrivateRangeIp(ip) && !scope.allowPrivateNetwork && !isIpExplicitlyAllowed(ip, scope)) {
			return {
				ok: false,
				hostname: normHost,
				resolvedIps,
				reason: `nuwa-egress N-007: DNS 重绑定拦截 (${normHost} -> ${ip} 为未授权私网地址且 allowPrivateNetwork=false)`,
			};
		}
	}

	return { ok: true, hostname: normHost, resolvedIps };
}

function parseConnectAuthority(raw: string): { host: string; port: number } | null {
	const s = String(raw ?? "").trim();
	if (!s) return null;
	if (s.startsWith("[")) {
		const m = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(s);
		if (!m) return null;
		const port = m[2] ? Number(m[2]) : 443;
		if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
		return { host: m[1]!, port };
	}
	const lastColon = s.lastIndexOf(":");
	if (lastColon > 0) {
		const host = s.slice(0, lastColon);
		const portStr = s.slice(lastColon + 1);
		if (!/^\d{1,5}$/.test(portStr)) return null;
		const port = Number(portStr);
		if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
		return { host, port };
	}
	return { host: s, port: 443 };
}

const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);
const PREVIEW_MAX_BYTES = 2048;

/**
 * 启动内置零信任 Scoped Egress Proxy（HTTP 正向代理 + HTTPS CONNECT 隧道）：
 * - 对目标主机名与真实 DNS 解析 IP 执行防 DNS 重绑定校验，并直连已校验 IP 消除 TOCTOU；
 * - 拦截越界主机、云元数据（169.254.0.0/16）、未授权私网/回环与越界 30x 重定向（返回 403 `nuwa-egress N-007`）；
 * - 支持 `onTraffic` 回调采集响应前 2048 字节预览与统计计数；
 * - `close()` 立即销毁所有活跃连接并释放监听端口。
 */
export async function startScopedEgressProxy(
	scope: ScopePolicy,
	opts?: EgressProxyOptions,
): Promise<ScopedEgressProxyHandle> {
	const bindHost = opts?.host ?? "127.0.0.1";
	const bindPort = opts?.port ?? 0;
	const timeoutMs =
		typeof opts?.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0
			? Math.floor(opts.timeoutMs)
			: 15_000;

	let allowedCount = 0;
	let blockedCount = 0;
	let closed = false;
	const openSockets = new Set<net.Socket>();

	const trackSocket = (sock: net.Socket): void => {
		openSockets.add(sock);
		sock.once("close", () => {
			openSockets.delete(sock);
		});
	};

	const emitTraffic = (rec: EgressTrafficRecord): void => {
		if (!opts?.onTraffic) return;
		try {
			opts.onTraffic(rec);
		} catch {
			/* 观测回调异常不影响代理主流程 */
		}
	};

	const httpServer = http.createServer();
	httpServer.on("connection", (sock) => {
		trackSocket(sock);
	});

	const sendErrorAndClose = (
		req: http.IncomingMessage,
		res: http.ServerResponse,
		statusCode: number,
		body: string,
	): void => {
		res.shouldKeepAlive = false;
		if (!res.headersSent) {
			res.writeHead(statusCode, { "Content-Type": "text/plain; charset=utf-8", Connection: "close" });
		}
		if (!res.writableEnded) {
			res.end(body, () => {
				try {
					req.socket?.end();
				} catch {
					/* ignore */
				}
			});
		}
	};

	httpServer.on("request", async (req, res) => {
		req.pause();
		const method = req.method ?? "GET";
		const rawReqUrl = String(req.url ?? "");
		const clientWantsClose = String(req.headers.connection ?? "").toLowerCase().includes("close");
		let targetUrl: URL;
		try {
			if (/^https?:\/\//i.test(rawReqUrl)) {
				targetUrl = new URL(rawReqUrl);
			} else if (req.headers.host) {
				targetUrl = new URL(rawReqUrl || "/", `http://${req.headers.host}`);
			} else {
				throw new Error("缺少有效绝对代理 URL");
			}
		} catch (err) {
			blockedCount++;
			const reason = `nuwa-egress N-007: 非法代理请求 URL (${rawReqUrl}) — ${err instanceof Error ? err.message : String(err)}`;
			sendErrorAndClose(req, res, 400, reason);
			emitTraffic({
				ts: new Date().toISOString(),
				method,
				url: rawReqUrl,
				host: "",
				port: 0,
				status: 400,
				allowed: false,
				reason,
			});
			return;
		}

		const hostname = normalizeEgressHost(targetUrl.hostname);
		const isHttps = targetUrl.protocol === "https:";
		const port = targetUrl.port ? Number(targetUrl.port) : isHttps ? 443 : 80;
		const fullUrlStr = targetUrl.toString();

		const check = await validateEgressTarget(hostname, scope, opts?.dnsLookup);
		if (!check.ok || check.resolvedIps.length === 0) {
			blockedCount++;
			const reason = check.reason ?? `nuwa-egress N-007: 目标越界 (${hostname})`;
			sendErrorAndClose(req, res, 403, reason);
			emitTraffic({
				ts: new Date().toISOString(),
				method,
				url: fullUrlStr,
				host: hostname,
				port,
				...(check.resolvedIps.length > 0 ? { resolvedIps: check.resolvedIps } : {}),
				status: 403,
				allowed: false,
				reason,
			});
			return;
		}

		const targetIp = check.resolvedIps[0]!;
		const outHeaders: http.OutgoingHttpHeaders = {};
		for (const [k, v] of Object.entries(req.headers)) {
			const lower = k.toLowerCase();
			if (lower === "proxy-connection" || lower === "proxy-authorization" || lower === "proxy-authenticate") {
				continue;
			}
			if (typeof v === "string" || Array.isArray(v)) outHeaders[k] = v;
		}
		outHeaders.host = req.headers.host ?? targetUrl.host;

		let handled = false;
		let recorded = false;
		const recordOnce = (rec: Omit<EgressTrafficRecord, "ts" | "method" | "url" | "host" | "port" | "resolvedIps">) => {
			if (recorded) return;
			recorded = true;
			emitTraffic({
				ts: new Date().toISOString(),
				method,
				url: fullUrlStr,
				host: hostname,
				port,
				resolvedIps: check.resolvedIps,
				...rec,
			});
		};

		const reqOpts: http.RequestOptions & https.RequestOptions = {
			protocol: targetUrl.protocol,
			host: targetIp,
			port,
			method,
			path: `${targetUrl.pathname}${targetUrl.search}`,
			headers: outHeaders,
			timeout: timeoutMs,
			...(isHttps && net.isIP(hostname) === 0 ? { servername: hostname } : {}),
		};

		const upReq = (isHttps ? https.request : http.request)(reqOpts, async (upRes) => {
			upRes.pause();
			const status = upRes.statusCode ?? 502;

			if (REDIRECT_STATUS_CODES.has(status) && upRes.headers.location) {
				const rawLoc = Array.isArray(upRes.headers.location)
					? upRes.headers.location[0]
					: upRes.headers.location;
				if (rawLoc) {
					let nextUrl: URL | null = null;
					try {
						nextUrl = new URL(rawLoc, fullUrlStr);
					} catch {
						nextUrl = null;
					}
					if (!nextUrl || (nextUrl.protocol !== "http:" && nextUrl.protocol !== "https:")) {
						handled = true;
						upRes.destroy();
						upReq.destroy();
						blockedCount++;
						const reason = `nuwa-egress N-007: 阻断越界 30x 重定向至非法协议 (${rawLoc})`;
						sendErrorAndClose(req, res, 403, reason);
						recordOnce({ status: 403, allowed: false, reason });
						return;
					}
					const nextHost = normalizeEgressHost(nextUrl.hostname);
					const redirCheck = await validateEgressTarget(nextHost, scope, opts?.dnsLookup);
					if (!redirCheck.ok) {
						handled = true;
						upRes.destroy();
						upReq.destroy();
						blockedCount++;
						const reason = `nuwa-egress N-007: 阻断越界 30x 重定向至 ${nextHost} (${redirCheck.reason ?? "不在授权范围内"})`;
						sendErrorAndClose(req, res, 403, reason);
						recordOnce({ status: 403, allowed: false, reason });
						return;
					}
				}
			}

			allowedCount++;
			const previewChunks: Buffer[] = [];
			let previewLen = 0;

			if (clientWantsClose) {
				res.shouldKeepAlive = false;
			}
			if (upRes.headers.date) {
				res.sendDate = false;
			}
			if (!res.headersSent) {
				res.writeHead(status, upRes.headers);
			}

			upRes.on("data", (chunk: Buffer | string) => {
				const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
				if (previewLen < PREVIEW_MAX_BYTES) {
					const remaining = PREVIEW_MAX_BYTES - previewLen;
					previewChunks.push(buf.length <= remaining ? buf : buf.subarray(0, remaining));
					previewLen += Math.min(buf.length, remaining);
				}
				if (!res.destroyed) {
					const ok = res.write(buf);
					if (!ok) {
						upRes.pause();
						res.once("drain", () => {
							if (!upRes.destroyed) upRes.resume();
						});
					}
				}
			});

			upRes.on("end", () => {
				handled = true;
				if (!res.writableEnded) {
					res.end(() => {
						if (clientWantsClose) {
							try {
								req.socket?.end();
							} catch {
								/* ignore */
							}
						}
					});
				}
				const responsePreview =
					previewChunks.length > 0 ? Buffer.concat(previewChunks).toString("utf8") : undefined;
				recordOnce({
					status,
					allowed: true,
					...(responsePreview !== undefined ? { responsePreview } : {}),
				});
			});

			upRes.on("error", (err) => {
				if (handled) return;
				handled = true;
				if (!res.writableEnded) {
					res.destroy(err);
				}
				const responsePreview =
					previewChunks.length > 0 ? Buffer.concat(previewChunks).toString("utf8") : undefined;
				recordOnce({
					status,
					allowed: true,
					reason: err.message,
					...(responsePreview !== undefined ? { responsePreview } : {}),
				});
			});

			upRes.resume();
		});

		upReq.on("timeout", () => {
			upReq.destroy(new Error(`上游连接超时 (${timeoutMs}ms)`));
		});

		upReq.on("error", (err) => {
			if (handled) return;
			handled = true;
			sendErrorAndClose(req, res, 502, `nuwa-egress 502: ${err.message}`);
			recordOnce({ status: 502, allowed: true, reason: err.message });
		});

		req.on("error", () => {
			upReq.destroy();
		});
		res.on("close", () => {
			if (!res.writableEnded) {
				upReq.destroy();
			}
		});

		req.pipe(upReq);
		req.resume();
	});

	const handleConnect = async (rawTarget: string, sock: net.Socket, head: Buffer): Promise<void> => {
		const parsed = parseConnectAuthority(rawTarget);
		if (!parsed) {
			blockedCount++;
			const reason = `nuwa-egress N-007: 非法 CONNECT 目标 (${rawTarget})`;
			if (!sock.destroyed) {
				sock.end(
					`HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n${reason}\r\n`,
				);
			}
			emitTraffic({
				ts: new Date().toISOString(),
				method: "CONNECT",
				url: rawTarget,
				host: "",
				port: 0,
				status: 400,
				allowed: false,
				reason,
			});
			return;
		}

		const hostname = normalizeEgressHost(parsed.host);
		const port = parsed.port;
		const check = await validateEgressTarget(hostname, scope, opts?.dnsLookup);
		if (!check.ok || check.resolvedIps.length === 0) {
			blockedCount++;
			const reason = check.reason ?? `nuwa-egress N-007: 目标越界 (${hostname})`;
			if (!sock.destroyed) {
				sock.end(
					`HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n${reason}\r\n`,
				);
			}
			emitTraffic({
				ts: new Date().toISOString(),
				method: "CONNECT",
				url: `${hostname}:${port}`,
				host: hostname,
				port,
				...(check.resolvedIps.length > 0 ? { resolvedIps: check.resolvedIps } : {}),
				status: 403,
				allowed: false,
				reason,
			});
			return;
		}

		const targetIp = check.resolvedIps[0]!;
		const upstream = net.connect({ host: targetIp, port });
		trackSocket(upstream);
		upstream.setTimeout(timeoutMs);

		let established = false;
		let recorded = false;
		const recordConnectOnce = (status: number, allowed: boolean, reason?: string) => {
			if (recorded) return;
			recorded = true;
			emitTraffic({
				ts: new Date().toISOString(),
				method: "CONNECT",
				url: `${hostname}:${port}`,
				host: hostname,
				port,
				resolvedIps: check.resolvedIps,
				status,
				allowed,
				...(reason ? { reason } : {}),
			});
		};

		upstream.once("connect", () => {
			established = true;
			allowedCount++;
			upstream.setTimeout(0);
			if (sock.destroyed) {
				upstream.destroy();
				return;
			}
			sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			if (head && head.length > 0) {
				upstream.write(head);
			}
			upstream.pipe(sock);
			sock.pipe(upstream);
			sock.resume();
			recordConnectOnce(200, true);
		});

		upstream.on("timeout", () => {
			upstream.destroy(new Error(`CONNECT 上游超时 (${timeoutMs}ms)`));
		});

		upstream.on("error", (err) => {
			if (!established && !sock.destroyed) {
				sock.end(
					`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nnuwa-egress 502: ${err.message}\r\n`,
				);
			} else if (!sock.destroyed) {
				sock.destroy();
			}
			recordConnectOnce(502, true, err.message);
		});

		sock.on("error", () => {
			if (!upstream.destroyed) upstream.destroy();
		});
		sock.on("close", () => {
			if (!upstream.destroyed) upstream.destroy();
		});
		upstream.on("close", () => {
			if (!sock.destroyed) sock.destroy();
		});
	};

	await new Promise<void>((resolve, reject) => {
		const onError = (err: Error) => {
			httpServer.off("listening", onListening);
			reject(err);
		};
		const onListening = () => {
			httpServer.off("error", onError);
			resolve();
		};
		httpServer.once("error", onError);
		httpServer.once("listening", onListening);
		httpServer.listen(0, "127.0.0.1");
	});

	const innerAddr = httpServer.address();
	const httpPort = typeof innerAddr === "object" && innerAddr ? innerAddr.port : 0;

	const CONNECT_PREFIX = "CONNECT ";
	const MAX_CONNECT_HEADER_BYTES = 16 * 1024;

	const tcpServer = net.createServer((clientSock) => {
		trackSocket(clientSock);
		clientSock.setTimeout(timeoutMs);

		let peekBuf: Buffer = Buffer.alloc(0);
		let routed = false;

		const cleanupSniff = () => {
			clientSock.off("data", onSniffData);
			clientSock.off("timeout", onSniffTimeout);
		};

		const onSniffTimeout = () => {
			if (!routed) {
				cleanupSniff();
				clientSock.destroy();
			}
		};

		const routeToHttp = (initialBuf: Buffer) => {
			routed = true;
			cleanupSniff();
			clientSock.pause();
			clientSock.setTimeout(0);
			const inner = net.connect({ host: "127.0.0.1", port: httpPort });
			trackSocket(inner);
			inner.once("connect", () => {
				if (clientSock.destroyed) {
					inner.destroy();
					return;
				}
				if (initialBuf.length > 0) {
					inner.write(initialBuf);
				}
				clientSock.pipe(inner);
				inner.pipe(clientSock);
				clientSock.resume();
			});
			inner.on("error", () => {
				if (!clientSock.destroyed) clientSock.destroy();
			});
			clientSock.on("error", () => {
				if (!inner.destroyed) inner.destroy();
			});
			clientSock.on("close", () => {
				if (!inner.destroyed) inner.destroy();
			});
			inner.on("close", () => {
				if (!clientSock.destroyed) clientSock.destroy();
			});
		};

		const onSniffData = (chunk: Buffer | string) => {
			if (routed) return;
			const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
			peekBuf = peekBuf.length === 0 ? buf : Buffer.concat([peekBuf, buf]);

			const prefixSample = peekBuf
				.subarray(0, Math.min(peekBuf.length, CONNECT_PREFIX.length))
				.toString("latin1")
				.toUpperCase();

			if (!CONNECT_PREFIX.startsWith(prefixSample)) {
				routeToHttp(peekBuf);
				return;
			}

			if (peekBuf.length >= CONNECT_PREFIX.length) {
				const headerEnd = peekBuf.indexOf("\r\n\r\n");
				if (headerEnd >= 0) {
					routed = true;
					cleanupSniff();
					clientSock.pause();
					clientSock.setTimeout(0);
					const headerStr = peekBuf.subarray(0, headerEnd).toString("latin1");
					const firstLine = headerStr.split("\r\n")[0] ?? "";
					const m = /^CONNECT\s+(\S+)\s+HTTP\/1\.[01]$/i.exec(firstLine.trim());
					const head = peekBuf.subarray(headerEnd + 4);
					void handleConnect(m?.[1] ?? "", clientSock, head);
					return;
				}
				if (peekBuf.length > MAX_CONNECT_HEADER_BYTES) {
					routed = true;
					cleanupSniff();
					clientSock.end("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n");
					clientSock.destroy();
				}
			}
		};

		clientSock.on("data", onSniffData);
		clientSock.once("timeout", onSniffTimeout);
		clientSock.on("error", () => {
			cleanupSniff();
		});
	});

	try {
		await new Promise<void>((resolve, reject) => {
			const onError = (err: Error) => {
				tcpServer.off("listening", onListening);
				reject(err);
			};
			const onListening = () => {
				tcpServer.off("error", onError);
				resolve();
			};
			tcpServer.once("error", onError);
			tcpServer.once("listening", onListening);
			tcpServer.listen(bindPort, bindHost);
		});
	} catch (err) {
		try {
			httpServer.close();
		} catch {
			/* ignore */
		}
		throw err;
	}

	const addr = tcpServer.address();
	const actualPort = typeof addr === "object" && addr ? addr.port : bindPort;
	const actualHost = typeof addr === "object" && addr && addr.address ? addr.address : bindHost;
	const urlHost = actualHost.includes(":") ? `[${actualHost}]` : actualHost;
	const url = `http://${urlHost}:${actualPort}`;

	const closeServer = (srv: net.Server | http.Server): Promise<void> =>
		new Promise<void>((resolve) => {
			const maybeCloseAll = (srv as unknown as { closeAllConnections?: () => void }).closeAllConnections;
			if (typeof maybeCloseAll === "function") {
				try {
					maybeCloseAll.call(srv);
				} catch {
					/* ignore */
				}
			}
			try {
				srv.close(() => resolve());
			} catch {
				resolve();
			}
		});

	return {
		host: actualHost,
		port: actualPort,
		url,
		stats: () => ({
			allowed: allowedCount,
			blocked: blockedCount,
			total: allowedCount + blockedCount,
		}),
		close: async () => {
			if (closed) return;
			closed = true;
			for (const sock of [...openSockets]) {
				try {
					sock.destroy();
				} catch {
					/* ignore */
				}
			}
			openSockets.clear();
			await Promise.all([closeServer(tcpServer), closeServer(httpServer)]);
		},
	};
}

// ══════════════════════════════════════════════════════════════════════════════
// v5.1 任务级出口注入（#23）与多出口健康度管理池 EgressPoolManager（#36）
// ══════════════════════════════════════════════════════════════════════════════
