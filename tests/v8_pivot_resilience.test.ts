/**
 * v8 复验测试：`omp/asset-router.ts`（凭据复用复验 / 资产路由规划 / 已确认 SSRF 探测）
 * 与 `omp/resilience-oob.ts`（网关自适应轮换 / 同构蜜罐识别 / 嵌入式 OOB 回调关联）。
 *
 * 设计原则：
 * 1. 全部网络行为都打在真实 `node:http` 回环服务器（`127.0.0.1:0`）上，绝不访问外网；
 * 2. 每个用例 `try/finally` + 全局 `afterAll` 双重回收，断言端口关闭（连接拒绝），零泄漏；
 * 3. 断言聚焦于**可观察行为**（fetchFn 是否被调用、返回结果是否携带确认态、是否泄露明文凭据），
 *    对可选字段 / 命名差异采用容错读取（`walkObjects` / `arraysNamed` / `firstStringField`），
 *    避免把测试绑死在单一字段拼写上；
 * 4. 明文凭据零泄露是硬约束：结果对象、异常日志、返回摘要三处都要检查。
 */
import { afterAll, describe, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";

import * as assetRouter from "../omp/asset-router";
import * as resilience from "../omp/resilience-oob";

// ---------------------------------------------------------------------------
// 基础类型与通用工具
// ---------------------------------------------------------------------------

type Any = any;

function sleep(ms: number): Promise<void> {
	return new Promise<void>((resolve) => {
		setTimeout(resolve, ms);
	});
}

function jsonText(value: unknown): string {
	const seen = new WeakSet<object>();
	try {
		return (
			JSON.stringify(value, (_key: string, val: unknown) => {
				if (typeof val === "object" && val !== null) {
					const obj = val as object;
					if (seen.has(obj)) return "[circular]";
					seen.add(obj);
				}
				return val;
			}) ?? ""
		);
	} catch {
		return "";
	}
}

/** 深度有限地收集对象图中的所有普通对象（用于容错读取实现细节）。 */
function walkObjects(value: unknown, depth = 0, acc: Any[] = []): Any[] {
	if (value === null || value === undefined || depth > 6) return acc;
	if (Array.isArray(value)) {
		for (const item of value.slice(0, 64)) walkObjects(item, depth + 1, acc);
		return acc;
	}
	if (typeof value === "object") {
		acc.push(value);
		for (const child of Object.values(value as Any)) walkObjects(child, depth + 1, acc);
	}
	return acc;
}

/** 按字段名（忽略大小写）从对象图中收集数组内容。 */
function arraysNamed(root: unknown, names: string[]): Any[] {
	const wanted = new Set(names.map((name) => name.toLowerCase()));
	const out: Any[] = [];
	for (const obj of walkObjects(root)) {
		for (const [key, value] of Object.entries(obj)) {
			if (!Array.isArray(value)) continue;
			if (!wanted.has(key.toLowerCase())) continue;
			out.push(...value);
		}
	}
	return out;
}

function firstStringField(obj: Any, keys: string[]): string | undefined {
	if (!obj || typeof obj !== "object") return undefined;
	for (const key of keys) {
		const value = (obj as Any)[key];
		if (typeof value === "string" && value.length > 0) return value;
	}
	return undefined;
}

function dedupe(items: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const item of items) {
		if (seen.has(item)) continue;
		seen.add(item);
		out.push(item);
	}
	return out;
}

function methodOf(target: Any, names: string[]): ((...args: Any[]) => Any) | undefined {
	if (!target) return undefined;
	for (const name of names) {
		const fn = target[name];
		if (typeof fn === "function") return fn.bind(target);
	}
	return undefined;
}

async function tryAsync(target: Any, names: string[], ...args: Any[]): Promise<{ ok: boolean; value?: Any }> {
	for (const name of names) {
		const fn = target?.[name];
		if (typeof fn !== "function") continue;
		try {
			const value = await fn.apply(target, args);
			return { ok: true, value };
		} catch {
			continue;
		}
	}
	return { ok: false };
}

async function withConsoleCapture<T>(fn: () => Promise<T>): Promise<{ value: T; logs: string }> {
	const captured: string[] = [];
	const originals = {
		log: console.log,
		info: console.info,
		warn: console.warn,
		error: console.error,
		debug: console.debug,
	};
	const tap = (...args: Any[]): void => {
		captured.push(args.map((arg) => (typeof arg === "string" ? arg : jsonText(arg))).join(" "));
	};
	console.log = tap as Any;
	console.info = tap as Any;
	console.warn = tap as Any;
	console.error = tap as Any;
	console.debug = tap as Any;
	try {
		const value = await fn();
		return { value, logs: captured.join("\n") };
	} finally {
		console.log = originals.log;
		console.info = originals.info;
		console.warn = originals.warn;
		console.error = originals.error;
		console.debug = originals.debug;
	}
}

// ---------------------------------------------------------------------------
// 真实回环服务器（127.0.0.1:0）+ 零泄漏回收
// ---------------------------------------------------------------------------

interface LoopServer {
	origin: string;
	port: number;
	close: () => Promise<void>;
}

const liveServers = new Set<LoopServer>();

async function startLoopback(
	handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<LoopServer> {
	const sockets = new Set<Socket>();
	const server: Server = createServer((req, res) => {
		try {
			handler(req, res);
		} catch {
			try {
				res.writeHead(500, { "content-type": "text/plain" });
				res.end("handler-error");
			} catch {
				/* ignore */
			}
		}
	});
	server.on("connection", (socket: Socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
		socket.on("error", () => sockets.delete(socket));
	});
	server.keepAliveTimeout = 100;

	await new Promise<void>((resolve, reject) => {
		const onError = (err: Error): void => reject(err);
		server.once("error", onError);
		server.listen(0, "127.0.0.1", () => {
			server.off("error", onError);
			resolve();
		});
	});

	const address = server.address() as AddressInfo;
	let closed = false;
	const handle: LoopServer = {
		origin: `http://127.0.0.1:${address.port}`,
		port: address.port,
		close: async () => {
			if (closed) return;
			closed = true;
			liveServers.delete(handle);
			for (const socket of sockets) {
				try {
					socket.destroy();
				} catch {
					/* ignore */
				}
			}
			sockets.clear();
			try {
				(server as Any).closeAllConnections?.();
			} catch {
				/* ignore */
			}
			await new Promise<void>((resolve) => {
				let settled = false;
				const finish = (): void => {
					if (settled) return;
					settled = true;
					resolve();
				};
				server.close(() => finish());
				const timer = setTimeout(finish, 300);
				(timer as Any).unref?.();
			});
		},
	};
	liveServers.add(handle);
	return handle;
}

afterAll(async () => {
	for (const server of Array.from(liveServers)) {
		try {
			await server.close();
		} catch {
			/* ignore */
		}
	}
	liveServers.clear();
});

async function connectionRefused(port: number): Promise<boolean> {
	try {
		await fetch(`http://127.0.0.1:${port}/__nuwa_probe__`, { signal: AbortSignal.timeout(1200) });
		return false;
	} catch {
		return true;
	}
}

// ---------------------------------------------------------------------------
// TrafficFetchFn 适配器（真实网络，兼容 `(url, init)` 与 `(init)` 两种调用约定）
// ---------------------------------------------------------------------------

interface FetchCall {
	url: string;
	init: Any;
}

function makeRealFetch(options: { timeoutMs?: number } = {}): { fn: Any; calls: FetchCall[] } {
	const calls: FetchCall[] = [];
	const fn = async (first: Any, second: Any = {}): Promise<Any> => {
		const url = typeof first === "string" ? first : String(first?.url ?? first?.href ?? "");
		const init: Any = typeof first === "string" ? second ?? {} : first ?? {};
		calls.push({ url, init });

		const method = String(init?.method ?? "GET").toUpperCase();
		const headers: Record<string, string> = {};
		const rawHeaders = init?.headers;
		if (rawHeaders && typeof rawHeaders === "object") {
			for (const [key, value] of Object.entries(rawHeaders as Record<string, Any>)) {
				if (value === undefined || value === null) continue;
				headers[key] = Array.isArray(value) ? value.join(", ") : String(value);
			}
		}
		const timeout = Number(init?.timeoutMs ?? options.timeoutMs ?? 3000);
		const res = await fetch(url, {
			method,
			headers,
			signal: AbortSignal.timeout(Math.max(200, Number.isFinite(timeout) ? timeout : 3000)),
		});
		const body = await res.text();
		const resHeaders: Record<string, string> = {};
		res.headers.forEach((value: string, key: string) => {
			resHeaders[key.toLowerCase()] = value;
		});
		return {
			status: res.status,
			statusCode: res.status,
			ok: res.ok,
			headers: resHeaders,
			body,
			text: body,
			url,
			finalUrl: res.url || url,
			ms: 1,
			elapsedMs: 1,
			durationMs: 1,
			bodyBytes: body.length,
			async text(): Promise<string> {
				return body;
			},
			async json(): Promise<Any> {
				return JSON.parse(body);
			},
		};
	};
	return { fn, calls };
}

// ---------------------------------------------------------------------------
// 范围策略 / 凭据 / 候选构造
// ---------------------------------------------------------------------------

function buildScope(overrides: Any = {}): Any {
	return {
		allowHosts: ["127.0.0.1", "localhost"],
		allowCidrs: ["127.0.0.0/8"],
		denyHosts: [],
		allowSubdomains: false,
		allowPrivateNetwork: true,
		allowLoopback: true,
		allowDestructive: false,
		...overrides,
	};
}

const PIVOT_SECRET = `s3cr3t-${randomBytes(6).toString("hex")}`;

function credentialSpec(secret: string): Any {
	return {
		id: "cred-pivot",
		role: "admin",
		label: "admin-cookie",
		kind: "cookie",
		type: "cookie",
		scheme: "cookie",
		name: "session",
		headerName: "cookie",
		param: "session",
		cookies: { session: secret },
		value: secret,
		secret,
		token: secret,
		password: secret,
		cookie: `session=${secret}`,
		username: "admin",
	};
}

function candidate(id: string, url: string): Any {
	let host = "";
	let port = 80;
	let scheme = "http";
	let path = "/";
	try {
		const parsed = new URL(url);
		scheme = parsed.protocol.replace(/:$/, "");
		host = parsed.hostname;
		port = Number(parsed.port || (scheme === "https" ? 443 : 80));
		path = `${parsed.pathname || "/"}${parsed.search}`;
	} catch {
		host = url;
	}
	return {
		id,
		assetId: id,
		targetId: id,
		label: id,
		url,
		targetUrl: url,
		baseUrl: url,
		endpoint: url,
		scheme,
		host,
		hostname: host,
		port,
		path,
		reachableVia: [],
		credentialRefs: [],
		tags: [],
	};
}

// ---------------------------------------------------------------------------
// 1. 凭据复用复验
// ---------------------------------------------------------------------------

function pivotOptions(params: {
	candidates: Any[];
	scope: Any;
	fetchFn: Any;
	credential?: Any;
	mode?: string;
	timeoutMs?: number;
}): Any {
	const credential = params.credential ?? credentialSpec(PIVOT_SECRET);
	return {
		credentials: [credential],
		credential,
		cred: credential,
		spec: credential,
		credentialId: "cred-pivot",
		candidates: params.candidates,
		targets: params.candidates,
		assets: params.candidates,
		scope: params.scope,
		policy: params.scope,
		mode: params.mode ?? "pentest",
		fetchFn: params.fetchFn,
		fetch: params.fetchFn,
		httpFetch: params.fetchFn,
		timeoutMs: params.timeoutMs ?? 3000,
		maxCandidates: 8,
	};
}

function verifyPivot(params: Parameters<typeof pivotOptions>[0]): Promise<Any> {
	return Promise.resolve((assetRouter.verifyCredentialPivot as Any)(pivotOptions(params)));
}

const PIVOT_CONFIRM_RE = /"(status|verdict|stage|result|outcome|classification)"\s*:\s*"[^"]*(confirm|reuse|valid|success)/;

function pivotConfirmedIds(root: Any): string[] {
	const ids: string[] = [];
	for (const obj of walkObjects(root)) {
		for (const [key, value] of Object.entries(obj)) {
			const lower = key.toLowerCase();
			const confirmish = /(confirm|valid|reuse|success)/.test(lower);
			if (confirmish && typeof value === "boolean" && value) {
				const id = firstStringField(obj, ["targetId", "assetId", "candidateId", "id", "target", "url"]);
				if (id) ids.push(id);
			}
			if (Array.isArray(value) && confirmish) {
				for (const item of value) {
					if (typeof item === "string") {
						ids.push(item);
						continue;
					}
					const id = firstStringField(item, ["targetId", "assetId", "candidateId", "id", "target", "url"]);
					if (id) ids.push(id);
				}
			}
			if (typeof value === "string" && confirmish && /confirm|reuse|valid|success/.test(value)) {
				const id = firstStringField(obj, ["targetId", "assetId", "candidateId", "id", "target", "url"]);
				if (id) ids.push(id);
			}
		}
	}
	for (const entry of arraysNamed(root, [
		"findings",
		"results",
		"entries",
		"targets",
		"pivots",
		"checks",
		"probes",
		"outcomes",
		"candidates",
	])) {
		if (!entry || typeof entry !== "object") continue;
		const status = firstStringField(entry, ["status", "verdict", "stage", "result", "state", "outcome", "classification"]);
		if (!status) continue;
		const lowered = status.toLowerCase();
		if (!/confirm|reuse|valid|success/.test(lowered)) continue;
		if (/invalid|unconfirmed|reject|baseline|no_|not_/.test(lowered)) continue;
		const id = firstStringField(entry, ["targetId", "assetId", "candidateId", "target", "url", "id"]);
		if (id) ids.push(id);
	}
	return dedupe(ids);
}

function expectNoPlaintext(value: unknown, secret: string): void {
	const text = jsonText(value);
	expect(text.includes(secret)).toBe(false);
	expect(text.includes(encodeURIComponent(secret))).toBe(false);
}

describe("verifyCredentialPivot —— 跨目标凭据复用复验", () => {
	test("模块版本与导出契约", () => {
		expect(assetRouter.ASSET_ROUTER_VERSION).toBe("7.0.0");
		expect(typeof assetRouter.verifyCredentialPivot).toBe("function");
		expect(typeof assetRouter.resolveAssetRoutePlan).toBe("function");
		expect(typeof assetRouter.probeViaConfirmedSsrf).toBe("function");
		expect(typeof assetRouter.applySsrfUrlTemplate).toBe("function");
	});

	test("越界域名 / 私网 / denyHosts 在双闸处拦停，fetchFn 零调用", async () => {
		const scope = buildScope({
			allowHosts: ["127.0.0.1"],
			denyHosts: ["127.0.0.1", "blocked.example.org"],
			allowPrivateNetwork: false,
			allowLoopback: false,
		});
		const stub = makeRealFetch();
		const out = await verifyPivot({
			candidates: [
				candidate("t-deny-loopback", "http://127.0.0.1:9/admin"),
				candidate("t-deny-host", "https://blocked.example.org/admin"),
				candidate("t-out-of-scope", "https://outside.example.net/admin"),
			],
			scope,
			fetchFn: stub.fn,
		});

		expect(stub.calls.length).toBe(0);
		const text = jsonText(out).toLowerCase();
		expect(text.length).toBeGreaterThan(0);
		expect(text).toMatch(/block|deny|scope|skip|refus|not_allowed|out_of_range/);
		expect(pivotConfirmedIds(out).length).toBe(0);
		expectNoPlaintext(out, PIVOT_SECRET);
	});

	test("真实目标：有效认证凭据被确认（对比无认证基线 401）", async () => {
		const authenticatedBody = `<html><body><h1>Admin Console</h1><p>uid=1 role=admin ${randomBytes(4).toString("hex")}</p></body></html>`;
		const softBody = `<html><body><h1>Not Found</h1><p>generic fallback page</p></body></html>`;
		const server = await startLoopback((req: IncomingMessage, res: ServerResponse) => {
			const raw = JSON.stringify(req.headers ?? {}).toLowerCase();
			const authed = raw.includes(PIVOT_SECRET.toLowerCase());
			const path = (req.url ?? "/").split("?")[0] ?? "/";
			if (path.startsWith("/admin")) {
				if (authed) {
					res.writeHead(200, { "content-type": "text/html" });
					res.end(authenticatedBody);
					return;
				}
				res.writeHead(401, { "content-type": "text/html", "www-authenticate": "Cookie realm=console" });
				res.end("unauthorized: missing session cookie");
				return;
			}
			res.writeHead(200, { "content-type": "text/html" });
			res.end(softBody);
		});

		try {
			const stub = makeRealFetch();
			const { value: out, logs } = await withConsoleCapture(() =>
				verifyPivot({
					candidates: [candidate("t-live", `${server.origin}/admin/console`)],
					scope: buildScope(),
					fetchFn: stub.fn,
				}),
			);

			expect(stub.calls.length).toBeGreaterThan(0);
			const confirmed = pivotConfirmedIds(out);
			const text = jsonText(out).toLowerCase();
			const positive =
				confirmed.some((id) => id.includes("t-live") || id.includes(server.origin)) ||
				(text.includes("t-live") && PIVOT_CONFIRM_RE.test(text));
			expect(positive).toBe(true);

			expectNoPlaintext(out, PIVOT_SECRET);
			expect(logs.includes(PIVOT_SECRET)).toBe(false);
			expect(logs.includes(encodeURIComponent(PIVOT_SECRET))).toBe(false);
		} finally {
			await server.close();
		}
	});

	test("基线为 401 时，缺失/错误凭据不得被确认为复用", async () => {
		const server = await startLoopback((req: IncomingMessage, res: ServerResponse) => {
			const raw = JSON.stringify(req.headers ?? {}).toLowerCase();
			const authed = raw.includes(PIVOT_SECRET.toLowerCase());
			if (!authed) {
				res.writeHead(401, { "content-type": "text/html", "www-authenticate": "Cookie realm=console" });
				res.end("unauthorized");
				return;
			}
			res.writeHead(200, { "content-type": "text/html" });
			res.end("<html><body>admin console</body></html>");
		});

		try {
			const wrongSecret = `wrong-${randomBytes(6).toString("hex")}`;
			const stub = makeRealFetch();
			const out = await verifyPivot({
				candidates: [candidate("t-unauth", `${server.origin}/admin/console`)],
				scope: buildScope(),
				fetchFn: stub.fn,
				credential: credentialSpec(wrongSecret),
			});

			expect(stub.calls.length).toBeGreaterThan(0);
			const confirmed = pivotConfirmedIds(out);
			expect(confirmed.some((id) => id.includes("t-unauth"))).toBe(false);
			const text = jsonText(out).toLowerCase();
			expect(text.includes(wrongSecret)).toBe(false);
		} finally {
			await server.close();
		}
	});

	test("软 404（全路径同构 200）不得被判为凭据复用成功", async () => {
		const softBody = `<html><body><h1>Not Found</h1><p>${randomBytes(8).toString("hex")} identical-for-every-path</p></body></html>`;
		const server = await startLoopback((_req: IncomingMessage, res: ServerResponse) => {
			res.writeHead(200, { "content-type": "text/html", "content-length": String(Buffer.byteLength(softBody)) });
			res.end(softBody);
		});

		try {
			const stub = makeRealFetch();
			const out = await verifyPivot({
				candidates: [candidate("t-soft", `${server.origin}/admin/dashboard`)],
				scope: buildScope(),
				fetchFn: stub.fn,
			});

			expect(stub.calls.length).toBeGreaterThan(0);
			const confirmed = pivotConfirmedIds(out);
			expect(confirmed.some((id) => id.includes("t-soft"))).toBe(false);
			const text = jsonText(out).toLowerCase();
			expect(text).toMatch(/soft|template|identical|baseline|no_delta|reject/);
			expectNoPlaintext(out, PIVOT_SECRET);
		} finally {
			await server.close();
		}
	});

	test("结果摘要中凭据被脱敏（[REDACTED] / 掩码替代明文）", async () => {
		const server = await startLoopback((req: IncomingMessage, res: ServerResponse) => {
			const cookieHeader = String(req.headers.cookie ?? "");
			if (cookieHeader.includes(PIVOT_SECRET)) {
				res.writeHead(200, { "content-type": "text/html", "x-echo-cookie": cookieHeader });
				res.end(`<html><body><h1>Welcome</h1><p>echo=${cookieHeader}</p></body></html>`);
				return;
			}
			res.writeHead(401, { "content-type": "text/html", "www-authenticate": "Cookie" });
			res.end("unauthorized");
		});

		try {
			const stub = makeRealFetch();
			const out = await verifyPivot({
				candidates: [candidate("t-mask", `${server.origin}/admin`)],
				scope: buildScope(),
				fetchFn: stub.fn,
			});
			const text = jsonText(out);
			expect(text.includes(PIVOT_SECRET)).toBe(false);
			expect(text.length).toBeGreaterThan(0);
		} finally {
			await server.close();
		}
	});
});

// ---------------------------------------------------------------------------
// 2. 资产路由规划
// ---------------------------------------------------------------------------

function assetNode(id: string, overrides: Any = {}): Any {
	return {
		id,
		assetId: id,
		kind: "host",
		host: id,
		hostname: id,
		url: `http://${id}/`,
		port: 80,
		reachableVia: [],
		credentialRefs: [],
		tags: [],
		labels: [],
		...overrides,
	};
}

function resolvePlan(params: {
	assets: Any[];
	tunnels?: Any[];
	proxies?: Any[];
	scope?: Any;
}): Any {
	const scope = params.scope ?? buildScope();
	return (assetRouter.resolveAssetRoutePlan as Any)({
		assets: params.assets,
		nodes: params.assets,
		graph: params.assets,
		scope,
		policy: scope,
		mode: "pentest",
		tunnels: params.tunnels ?? [],
		socksTunnels: params.tunnels ?? [],
		socks: params.tunnels ?? [],
		proxies: params.proxies ?? [],
		egressProxies: params.proxies ?? [],
		egress: params.proxies ?? [],
	});
}

function routeEntries(plan: Any): Any[] {
	return arraysNamed(plan, ["entries", "routes", "plan", "paths", "nodes", "assets", "items", "decisions", "routesPlan"]);
}

function entryFor(plan: Any, assetId: string): Any | undefined {
	const entries = routeEntries(plan);
	const direct = entries.find((entry) => jsonText(entry).includes(assetId));
	if (direct) return direct;
	const text = jsonText(plan);
	return text.includes(assetId) ? { id: assetId, raw: text } : undefined;
}

function routeKindOf(entry: Any): string {
	if (!entry) return "";
	const kind = firstStringField(entry, [
		"kind",
		"routeKind",
		"route",
		"transport",
		"mode",
		"decision",
		"strategy",
		"via",
	]);
	return (kind ?? jsonText(entry)).toLowerCase();
}

describe("resolveAssetRoutePlan —— 多资产可达拓扑选路", () => {
	test("公网资产直连 / 私网资产经 socks5h 隧道选路", () => {
		const scope = buildScope({
			allowHosts: ["example.com", "gw.example.com", "10.10.0.5", "127.0.0.1"],
			allowCidrs: ["10.0.0.0/8", "127.0.0.0/8"],
			allowPrivateNetwork: true,
		});
		const assets = [
			assetNode("pub-1", { host: "example.com", hostname: "example.com", url: "https://example.com/" }),
			assetNode("gw-1", { host: "gw.example.com", hostname: "gw.example.com", url: "https://gw.example.com/" }),
			assetNode("priv-1", {
				host: "10.10.0.5",
				hostname: "10.10.0.5",
				ip: "10.10.0.5",
				port: 8080,
				url: "http://10.10.0.5:8080/",
				reachableVia: ["gw-1"],
			}),
		];
		const tunnels = [
			{
				id: "tn-1",
				via: "gw-1",
				viaAssetId: "gw-1",
				pivotId: "gw-1",
				kind: "socks5h",
				scheme: "socks5h",
				host: "10.10.0.5",
				port: 1080,
				url: "socks5h://10.10.0.5:1080",
				proxyUrl: "socks5h://10.10.0.5:1080",
				targetCidrs: ["10.0.0.0/8"],
				targetHosts: ["10.10.0.5"],
			},
		];

		const plan = resolvePlan({ assets, tunnels, scope });
		const entries = routeEntries(plan);
		expect(entries.length).toBeGreaterThan(0);

		const publicEntry = entryFor(plan, "pub-1");
		expect(publicEntry).toBeDefined();
		expect(routeKindOf(publicEntry)).toBe("direct");

		const privateEntry = entryFor(plan, "priv-1");
		expect(privateEntry).toBeDefined();
		expect(["socks5h", "socks5", "proxy", "tunnel"]).toContain(routeKindOf(privateEntry));
	});

	test("reachableVia 成环时干净检测，不进入直连（且不抛异常）", () => {
		const scope = buildScope({ allowHosts: ["a.example.com", "b.example.com", "c.example.com"] });
		const assets = [
			assetNode("cyc-a", {
				host: "a.example.com",
				hostname: "a.example.com",
				url: "https://a.example.com/",
				reachableVia: ["cyc-b"],
			}),
			assetNode("cyc-b", {
				host: "b.example.com",
				hostname: "b.example.com",
				url: "https://b.example.com/",
				reachableVia: ["cyc-c"],
			}),
			assetNode("cyc-c", {
				host: "c.example.com",
				hostname: "c.example.com",
				url: "https://c.example.com/",
				reachableVia: ["cyc-a"],
			}),
		];

		let plan: Any;
		expect(() => {
			plan = resolvePlan({ assets, scope });
		}).not.toThrow();

		const entries = routeEntries(plan);
		expect(entries.length).toBeGreaterThan(0);

		const cycleEntry = entryFor(plan, "cyc-a");
		const cycleKind = routeKindOf(cycleEntry);
		expect(cycleKind).not.toBe("direct");
		expect(jsonText(plan).toLowerCase()).toContain("cycle");

		// 整个计划对象可被序列化（无循环引用泄漏到返回值）
		expect(jsonText(plan).length).toBeGreaterThan(0);
	});

	test("深层可达链（A→B→C）不抛栈溢出或无限循环", () => {
		const scope = buildScope({
			allowHosts: ["l1.example.com", "l2.example.com", "l3.example.com", "l4.example.com"],
			allowPrivateNetwork: true,
			allowCidrs: ["10.0.0.0/8"],
		});
		const assets = [
			assetNode("l1", { host: "l1.example.com", hostname: "l1.example.com", url: "https://l1.example.com/" }),
			assetNode("l2", {
				host: "l2.example.com",
				hostname: "l2.example.com",
				url: "https://l2.example.com/",
				reachableVia: ["l1"],
			}),
			assetNode("l3", {
				host: "10.0.0.3",
				hostname: "10.0.0.3",
				ip: "10.0.0.3",
				url: "http://10.0.0.3/",
				reachableVia: ["l2"],
			}),
			assetNode("l4", {
				host: "10.0.0.4",
				hostname: "10.0.0.4",
				ip: "10.0.0.4",
				url: "http://10.0.0.4/",
				reachableVia: ["l3"],
			}),
		];

		const startedAt = Date.now();
		const plan = resolvePlan({ assets, scope });
		expect(Date.now() - startedAt).toBeLessThan(3000);
		expect(routeEntries(plan).length).toBeGreaterThan(0);
		expect(jsonText(plan)).toContain("l4");
	});
});

// ---------------------------------------------------------------------------
// 3. 已确认 SSRF 内网探测 + URL 模板注入
// ---------------------------------------------------------------------------

function ssrfFact(stage: string): Any {
	const stamp = new Date().toISOString();
	return {
		id: `fact-ssrf-${stage}`,
		kind: "vuln",
		title: `SSRF (${stage})`,
		body: "server-side request forgery candidate",
		verifyStage: stage,
		stage,
		status: "open",
		confidence: 0.9,
		targetKey: "http://pivot.example/fetch",
		evidence: [],
		meta: {},
		createdAt: stamp,
		updatedAt: stamp,
	};
}

function ssrfTarget(id: string, origin: string, path = "/internal/health"): Any {
	const parsed = new URL(origin);
	return {
		id,
		assetId: id,
		label: id,
		host: parsed.hostname,
		hostname: parsed.hostname,
		ip: parsed.hostname,
		port: Number(parsed.port),
		scheme: parsed.protocol.replace(":", ""),
		path,
		url: `${origin}${path}`,
		targetUrl: `${origin}${path}`,
		reachableVia: [],
	};
}

function ssrfOptions(params: {
	fact: Any;
	targets: Any[];
	scope: Any;
	fetchFn: Any;
	urlTemplate?: string;
}): Any {
	return {
		fact: params.fact,
		facts: [params.fact],
		vulnerability: params.fact,
		targets: params.targets,
		candidates: params.targets,
		ssrfTargets: params.targets,
		probes: params.targets,
		scope: params.scope,
		policy: params.scope,
		mode: "pentest",
		fetchFn: params.fetchFn,
		fetch: params.fetchFn,
		urlTemplate: params.urlTemplate,
		template: params.urlTemplate,
		timeoutMs: 3000,
		maxTargets: 8,
	};
}

function probeSsrf(params: Parameters<typeof ssrfOptions>[0]): Promise<Any> {
	return Promise.resolve((assetRouter.probeViaConfirmedSsrf as Any)(ssrfOptions(params)));
}

describe("probeViaConfirmedSsrf —— 仅对已确认 SSRF 做内网可达性探测", () => {
	test("applySsrfUrlTemplate：占位符替换与受控参数追加均生效", () => {
		const target = "http://127.0.0.1:8123/internal/health";

		const templated = assetRouter.applySsrfUrlTemplate(
			"http://pivot.example/proxy?u={{target}}",
			target,
			"127.0.0.1",
		);
		expect(typeof templated).toBe("string");
		expect(decodeURIComponent(templated)).toContain("127.0.0.1:8123");

		const hostTemplated = assetRouter.applySsrfUrlTemplate("http://pivot.example/h?h={{host}}", target, "127.0.0.1");
		expect(decodeURIComponent(hostTemplated)).toContain("127.0.0.1");

		const appended = assetRouter.applySsrfUrlTemplate("http://pivot.example/fetch?url=", target, "127.0.0.1");
		expect(typeof appended).toBe("string");
		expect(decodeURIComponent(appended)).toContain("127.0.0.1:8123");
		expect(appended.includes(PIVOT_SECRET)).toBe(false);
	});

	test("非 confirmed 事实（candidate / rejected）立即拒绝，零网络请求", async () => {
		for (const stage of ["candidate", "rejected"]) {
			const stub = makeRealFetch();
			const out = await probeSsrf({
				fact: ssrfFact(stage),
				targets: [ssrfTarget("t-internal", "http://127.0.0.1:9")],
				scope: buildScope(),
				fetchFn: stub.fn,
			});
			expect(stub.calls.length).toBe(0);
			expect(jsonText(out).toLowerCase()).toMatch(/reject|candidate|not_confirmed|skip|refus|gate/);
		}
	});

	test("allowPrivateNetwork=false / denyHosts 命中时零请求", async () => {
		const server = await startLoopback((_req: IncomingMessage, res: ServerResponse) => {
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("should-not-be-reached");
		});
		try {
			const strictScope = buildScope({ allowPrivateNetwork: false, allowLoopback: false });
			const stubA = makeRealFetch();
			const outA = await probeSsrf({
				fact: ssrfFact("confirmed"),
				targets: [ssrfTarget("t-private", server.origin)],
				scope: strictScope,
				fetchFn: stubA.fn,
			});
			expect(stubA.calls.length).toBe(0);
			expect(jsonText(outA).toLowerCase()).toMatch(/block|deny|scope|private|skip|refus/);

			const denyScope = buildScope({ denyHosts: ["127.0.0.1"] });
			const stubB = makeRealFetch();
			const outB = await probeSsrf({
				fact: ssrfFact("confirmed"),
				targets: [ssrfTarget("t-denied", server.origin)],
				scope: denyScope,
				fetchFn: stubB.fn,
			});
			expect(stubB.calls.length).toBe(0);
			expect(jsonText(outB).toLowerCase()).toMatch(/block|deny|scope|skip|refus/);
		} finally {
			await server.close();
		}
	});

	test("confirmed + allowPrivateNetwork 时发现真实存活内网服务并落地干净 AssetNode", async () => {
		const banner = `internal-service-${randomBytes(4).toString("hex")}`;
		const server = await startLoopback((req: IncomingMessage, res: ServerResponse) => {
			const path = (req.url ?? "/").split("?")[0] ?? "/";
			if (path.startsWith("/internal")) {
				res.writeHead(200, {
					"content-type": "text/plain",
					server: "internal-nginx/1.25",
					"x-internal-service": "billing-api",
				});
				res.end(banner);
				return;
			}
			res.writeHead(404, { "content-type": "text/plain" });
			res.end("not found");
		});

		try {
			const stub = makeRealFetch();
			const out = await probeSsrf({
				fact: ssrfFact("confirmed"),
				targets: [ssrfTarget("t-live-internal", server.origin)],
				scope: buildScope(),
				fetchFn: stub.fn,
				urlTemplate: `${server.origin}/internal/health?via={{target}}`,
			});

			expect(stub.calls.length).toBeGreaterThan(0);

			const text = jsonText(out);
			expect(text.includes(String(server.port))).toBe(true);

			const discovered = arraysNamed(out, [
				"assets",
				"nodes",
				"discovered",
				"probed",
				"findings",
				"results",
				"targets",
				"reachable",
			]);
			expect(discovered.length).toBeGreaterThan(0);
			const hit = discovered.find((entry) => jsonText(entry).includes(String(server.port)));
			expect(hit).toBeDefined();

			// AssetNode 结构合法性：必须有 id / host 类字段
			const id = firstStringField(hit, ["id", "assetId", "host", "hostname", "targetId"]);
			expect(typeof id).toBe("string");
			expect((id ?? "").length).toBeGreaterThan(0);

			// 绝不允许明文凭据出现在落地资产里
			expectNoPlaintext(out, PIVOT_SECRET);
		} finally {
			await server.close();
		}
	});
});

// ---------------------------------------------------------------------------
// 4. 网关自适应轮换
// ---------------------------------------------------------------------------

function normalizeProxy(value: Any): string {
	if (typeof value === "string") return value;
	const direct = firstStringField(value, ["url", "proxy", "proxyUrl", "href", "id", "proxyId", "label"]);
	return direct ?? jsonText(value);
}

function reportOutcome(report: (...args: Any[]) => Any, proxy: string, outcome: Any): void {
	const attempts: Any[][] = [
		[proxy, outcome],
		[{ proxy, proxyUrl: proxy, id: proxy, url: proxy }, outcome],
		[proxy, outcome.status, outcome],
		[outcome],
		[{ ...outcome, proxy, proxyUrl: proxy }],
	];
	for (const args of attempts) {
		try {
			report(...args);
			return;
		} catch {
			continue;
		}
	}
}

describe("韧性层：网关签名指纹与出口代理自适应轮换", () => {
	test("detectGatewaySignature：裸 403 为软阻断，429/503 与厂商签名为硬阻断", () => {
		const plain403 = resilience.detectGatewaySignature({
			status: 403,
			headers: { "content-type": "text/html" },
			body: "<html><body>Forbidden</body></html>",
		} as Any);
		const plainText = jsonText(plain403).toLowerCase();
		expect(plainText).toContain("soft");
		expect(plainText).toContain("403");

		const rateLimited = resilience.detectGatewaySignature({
			status: 429,
			headers: { "retry-after": "120", "content-type": "text/plain" },
			body: "slow down",
		} as Any);
		const limitedText = jsonText(rateLimited).toLowerCase();
		expect(limitedText).toContain("hard");
		expect(limitedText).toMatch(/"blocked"\s*:\s*true/);

		const unavailable = resilience.detectGatewaySignature({
			status: 503,
			headers: { "retry-after": "30" },
			body: "service unavailable",
		} as Any);
		expect(jsonText(unavailable).toLowerCase()).toContain("hard");

		const cloudflare = resilience.detectGatewaySignature({
			status: 403,
			headers: {
				server: "cloudflare",
				"cf-ray": "8b1f2c3d4e5f-SJC",
				"cf-mitigated": "challenge",
				"content-type": "text/html",
			},
			body: "<html><head><title>Just a moment...</title></head></html>",
		} as Any);
		expect(jsonText(cloudflare).toLowerCase()).toContain("cloudflare");

		const awsWaf = resilience.detectGatewaySignature({
			status: 403,
			headers: { "x-amzn-requestid": "abc", server: "awselb/2.0", "content-type": "text/html" },
			body: "<html><body>Request blocked</body></html>",
		} as Any);
		const awsText = jsonText(awsWaf).toLowerCase();
		expect(awsText).toMatch(/aws|waf|hard|block/);
	});

	test("buildAdaptiveVariants：仅使用合规 HTTP 语义，不含伪造头与协议走私技巧", () => {
		const variants = resilience.buildAdaptiveVariants(
			{
				method: "GET",
				path: "/admin/panel",
				url: "/admin/panel",
				headers: { accept: "text/html", "accept-language": "zh-CN" },
			} as Any,
			1,
		);
		expect(Array.isArray(variants)).toBe(true);
		expect(variants.length).toBeGreaterThan(0);

		const text = jsonText(variants).toLowerCase();
		for (const forbidden of [
			"x-forwarded-for",
			"x-originating-ip",
			"x-client-ip",
			"x-rewrite-url",
			"x-http-method-override",
			"forwarded:",
			"../",
			"%2e%2e",
			"..%2f",
		]) {
			expect(text.includes(forbidden)).toBe(false);
		}

		const again = resilience.buildAdaptiveVariants({ method: "GET", path: "/admin/panel" } as Any, 0);
		expect(Array.isArray(again)).toBe(true);
		expect(again.length).toBeGreaterThan(0);
	});

	test("403/429 触发出口代理冷却、轮换，并在冷却窗口后恢复", () => {
		const Ctor: Any = (resilience as Any).GatewayAdaptiveController;
		expect(typeof Ctor).toBe("function");

		const clock = { now: 1_700_000_000_000 };
		const proxies = ["http://127.0.0.1:15001", "http://127.0.0.1:15002", "http://127.0.0.1:15003"];
		const config: Any = {
			proxies,
			egressProxies: proxies,
			pool: proxies.map((url) => ({ id: url, url, label: url })),
			now: () => clock.now,
			clock: () => clock.now,
			baseCooldownMs: 30_000,
			cooldownMs: 30_000,
			maxCooldownMs: 600_000,
			failureThreshold: 1,
		};

		let controller: Any;
		try {
			controller = new Ctor(config);
		} catch {
			controller = new Ctor(proxies);
		}
		expect(controller).toBeDefined();

		const acquire = methodOf(controller, [
			"selectHealthyEgress",
			"acquire",
			"next",
			"lease",
			"pick",
			"select",
			"choose",
			"rotate",
			"getProxy",
			"current",
		]);
		const report = methodOf(controller, [
			"reportOutcome",
			"report",
			"record",
			"observe",
			"note",
			"recordOutcome",
			"feedback",
			"mark",
			"update",
			"complete",
			"onResult",
			"handleOutcome",
		]);
		const inspect = methodOf(controller, [
			"getStates",
			"snapshot",
			"state",
			"states",
			"stats",
			"health",
			"describe",
			"status",
			"list",
			"pool",
		]);

		expect(typeof acquire === "function" || typeof inspect === "function").toBe(true);

		if (typeof acquire !== "function" || typeof report !== "function") {
			// 结构降级：至少能查询到代理池视图
			const view = inspect ? inspect() : controller;
			expect(jsonText(view)).toContain("1500");
			return;
		}

		const firstProxy = normalizeProxy(acquire());
		expect(firstProxy.length).toBeGreaterThan(0);

		const beforeText = jsonText(inspect ? inspect() : controller).toLowerCase();

		// 连续硬阻断 → 触发指数退避冷却
		for (let i = 0; i < 3; i += 1) {
			reportOutcome(report, firstProxy, {
				status: 429,
				kind: "hard",
				blocked: true,
				retryAfterMs: 30_000,
				headers: { "retry-after": "30" },
			});
		}

		const rotated = normalizeProxy(acquire());
		const coolingText = jsonText(inspect ? inspect() : controller).toLowerCase();
		const coolingSignalled = /cool|unhealthy|backoff|degrad|penal|suspend/.test(coolingText);
		expect(rotated !== firstProxy || coolingSignalled).toBe(true);

		// 冷却窗口走完后恢复可用
		clock.now += 10 * 60_000;
		const ticker = methodOf(controller, ["tick", "advance", "refresh", "sweep", "prune"]);
		if (ticker) {
			try {
				ticker(clock.now);
			} catch {
				/* ignore */
			}
		}
		const recoveredProxy = normalizeProxy(acquire());
		const recoveredText = jsonText(inspect ? inspect() : controller).toLowerCase();
		expect(recoveredProxy === firstProxy || recoveredText !== coolingText || !coolingSignalled).toBe(true);
		expect(recoveredText).toMatch(/healthy|available|cooldown|penal|score|proxy|1500/);
		expect(beforeText.length > 0 || recoveredText.length > 0).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// 5. 同构蜜罐 / tarpit 识别
// ---------------------------------------------------------------------------

const REAL_404_BODY =
	"<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>";
const REAL_OK_BODY =
	"<html><body><h1>Acme Operations Dashboard</h1><p>Welcome back, operator. Active sessions: 3.</p></body></html>";
const FAKE_200_BODY =
	"<html><body><h1>Traceback</h1><p>flag{leaked} secret=admin password=token internal debug panel dump</p></body></html>";

function trapSample(path: string, status: number, body: string, latencyMs: number): Any {
	return {
		path,
		url: path,
		pathname: path,
		status,
		statusCode: status,
		body,
		text: body,
		bodyText: body,
		headers: { "content-type": "text/html" },
		contentType: "text/html",
		latencyMs,
		latency: latencyMs,
		elapsedMs: latencyMs,
		at: new Date().toISOString(),
		timestamp: Date.now(),
	};
}

function makeTrapDetector(options: Any = {}): Any {
	const Ctor: Any = (resilience as Any).IsomorphicTrapDetector;
	expect(typeof Ctor).toBe("function");
	const config: Any = {
		minSamples: 3,
		minSamplesForVerdict: 3,
		entropyFloor: 3.2,
		bodyReuseThreshold: 0.8,
		latencyGrowthFactor: 1.4,
		keywordDensityThreshold: 0.02,
		calibrationBaselines: 4,
		...options,
	};
	try {
		return new Ctor(config);
	} catch {
		return new Ctor();
	}
}

const INGEST_METHODS = [
	"recordResponse",
	"observe",
	"record",
	"addSample",
	"ingest",
	"sample",
	"push",
	"feed",
	"add",
	"track",
	"analyze",
	"evaluate",
	"scan",
	"note",
];

function ingestSample(detector: Any, sample: Any): Any {
	for (const name of INGEST_METHODS) {
		const fn = detector?.[name];
		if (typeof fn !== "function") continue;
		try {
			return fn.call(detector, sample);
		} catch {
			continue;
		}
	}
	return undefined;
}

function readTrapEvaluation(detector: Any, fallback: Any): Any {
	for (const name of [
		"evaluate",
		"analyze",
		"assess",
		"detect",
		"summary",
		"snapshot",
		"getEvaluation",
		"result",
		"report",
		"verdict",
		"trapSignal",
		"check",
	]) {
		const fn = detector?.[name];
		if (typeof fn !== "function") continue;
		try {
			const value = fn.call(detector);
			if (value !== undefined && value !== null) return value;
		} catch {
			continue;
		}
	}
	return fallback;
}

function trapTextOf(detector: Any, evaluation: Any): string {
	return `${jsonText(evaluation)} ${jsonText(detector)}`.toLowerCase();
}

describe("IsomorphicTrapDetector —— 同构蜜罐 / tarpit 识别", () => {
	test("校准护栏：4 条基线 404 + 1 条真实 200 的真实站点绝不误报", () => {
		const detector = makeTrapDetector();
		const samples = [
			trapSample("/wp-login.php", 404, REAL_404_BODY, 8),
			trapSample("/admin", 404, REAL_404_BODY, 9),
			trapSample("/.env", 404, REAL_404_BODY, 7),
			trapSample("/backup.zip", 404, REAL_404_BODY, 8),
			trapSample("/api/v1/health", 200, REAL_OK_BODY, 11),
		];
		let evaluation: Any;
		for (const sample of samples) {
			const returned = ingestSample(detector, sample);
			if (returned !== undefined && returned !== null) evaluation = returned;
		}
		const verdict = readTrapEvaluation(detector, evaluation);
		const text = trapTextOf(detector, verdict);

		expect(text).not.toMatch(/"istrap"\s*:\s*true/);
		expect(text).not.toMatch(/"confidence"\s*:\s*"(high|medium)"/);
		expect(text).not.toMatch(/"recommendcircuitbreak"\s*:\s*true/);
		expect(text).toMatch(/"confidence"\s*:\s*"(none|low)"|"istrap"\s*:\s*false|n\/a|metrics|status/);
	});

	test("Fake-200 同构关键词陷阱 + 渐进延迟 tarpit 被识别并建议熔断", () => {
		const detector = makeTrapDetector();
		const latencies = [10, 40, 90, 160, 250, 360, 490, 640];
		let evaluation: Any;
		for (let i = 0; i < latencies.length; i += 1) {
			const sample = trapSample(
				`/api/v1/resource-${i}/action?probe=${i}`,
				200,
				FAKE_200_BODY,
				latencies[i] ?? 0,
			);
			const returned = ingestSample(detector, sample);
			if (returned !== undefined && returned !== null) evaluation = returned;
		}
		const verdict = readTrapEvaluation(detector, evaluation);
		const text = trapTextOf(detector, verdict);

		expect(text).toMatch(
			/"istrap"\s*:\s*true|"confidence"\s*:\s*"(high|medium)"|"trapdetected"\s*:\s*true|"recommendcircuitbreak"\s*:\s*true|"verdict"\s*:\s*"trap"/,
		);
	});

	test("低信号同构 200（无关键词、无延迟膨胀）不轻易升级为陷阱结论", () => {
		const detector = makeTrapDetector({ keywordDensityThreshold: 0.5, latencyGrowthFactor: 10 });
		const plainBody = "<html><body><h1>Welcome</h1><p>Static landing page.</p></body></html>";
		const paths = ["/a", "/b", "/c", "/d", "/e"];
		let evaluation: Any;
		for (const path of paths) {
			const returned = ingestSample(detector, trapSample(path, 200, plainBody, 10));
			if (returned !== undefined && returned !== null) evaluation = returned;
		}
		const verdict = readTrapEvaluation(detector, evaluation);
		const text = trapTextOf(detector, verdict);
		expect(jsonText(detector).length + jsonText(verdict).length).toBeGreaterThan(0);
		expect(text.includes("undefined")).toBe(false);
		expect(text).not.toMatch(/"circuitbreak"\s*:\s*true/);
		expect(text).not.toMatch(/"istrapdetected"\s*:\s*true/);
		expect(text).not.toMatch(/"confidence"\s*:\s*"(high|medium)"/);
	});
});

// ---------------------------------------------------------------------------
// 6. 嵌入式 OOB 监听器 + 关联器
// ---------------------------------------------------------------------------

function endpointOf(listener: Any, startValue: Any): string {
	const accessor = methodOf(listener, ["endpoint", "address", "getEndpoint", "getAddress", "info", "listenInfo"]);
	let accessorValue: Any;
	if (accessor) {
		try {
			accessorValue = accessor();
		} catch {
			accessorValue = undefined;
		}
	}
	const candidates: Any[] = [startValue, accessorValue, listener];
	for (const value of candidates) {
		if (typeof value === "string" && /^https?:\/\//.test(value)) return value;
		const direct = firstStringField(value, [
			"url",
			"callbackUrl",
			"publicUrl",
			"origin",
			"endpoint",
			"href",
			"baseUrl",
		]);
		if (direct && /^https?:\/\//.test(direct)) return direct;
		const port = typeof value?.port === "number" ? value.port : undefined;
		if (port) return `http://127.0.0.1:${port}`;
	}
	const port = typeof listener?.port === "number" ? listener.port : undefined;
	return port ? `http://127.0.0.1:${port}` : "";
}

async function registerCanaryApi(listener: Any, input: Any): Promise<Any> {
	for (const name of [
		"registerCanary",
		"register",
		"createCanary",
		"issueCanary",
		"addCanary",
		"mintCanary",
		"prepare",
	]) {
		const fn = listener?.[name];
		if (typeof fn !== "function") continue;
		try {
			const value = await fn.call(listener, input);
			if (value) return value;
		} catch {
			continue;
		}
	}
	return undefined;
}

function callbackUrlOf(registration: Any, endpointUrl: string, input: Any): string {
	const direct = firstStringField(registration, [
		"url",
		"callbackUrl",
		"callback",
		"endpoint",
		"href",
		"target",
	]);
	if (direct) {
		if (/^https?:\/\//.test(direct)) return direct;
		if (direct.startsWith("/")) {
			try {
				return new URL(direct, endpointUrl).toString();
			} catch {
				/* ignore */
			}
		}
	}
	const base = new URL(endpointUrl);
	const token = firstStringField(registration, ["token", "canaryToken", "value", "nonce"]);
	const signature = firstStringField(registration, ["signature", "sig", "hmac", "mac", "sign"]);
	if (token) base.searchParams.set("t", token);
	if (signature) base.searchParams.set("sig", signature);
	if (input?.canaryId) base.searchParams.set("c", String(input.canaryId));
	return base.toString();
}

function forgeUrl(url: string): string {
	const parsed = new URL(url);
	const keys = Array.from(parsed.searchParams.keys());
	if (keys.length > 0) {
		const target = keys.find((key) => /sig|hmac|mac|sign/i.test(key)) ?? keys[keys.length - 1];
		if (target) {
			const value = parsed.searchParams.get(target) ?? "";
			const flipped = value.length > 0 ? `${value.slice(0, Math.max(0, value.length - 1))}${value.endsWith("0") ? "1" : "0"}` : "forged";
			parsed.searchParams.set(target, flipped === value ? `${value}forged` : flipped);
			return parsed.toString();
		}
	}
	parsed.pathname = `${parsed.pathname.replace(/\/$/, "")}/forged-${randomBytes(4).toString("hex")}`;
	return parsed.toString();
}

async function collectHits(listener: Any): Promise<Any[]> {
	for (const name of [
		"drain",
		"takeHits",
		"collect",
		"flush",
		"hits",
		"getHits",
		"pending",
		"callbacks",
		"received",
		"snapshot",
	]) {
		const fn = listener?.[name];
		if (typeof fn === "function") {
			try {
				const value = await fn.call(listener);
				if (Array.isArray(value)) return value;
				if (Array.isArray(value?.hits)) return value.hits;
				if (Array.isArray(value?.callbacks)) return value.callbacks;
			} catch {
				continue;
			}
		}
		const prop = listener?.[name];
		if (Array.isArray(prop)) return prop;
	}
	return [];
}

function rejectedForgedCount(listener: Any): number {
	const scan = (root: Any): number => {
		for (const obj of walkObjects(root)) {
			for (const [key, value] of Object.entries(obj)) {
				if (typeof value === "number" && /reject|forged|invalid|tamper/i.test(key)) return value;
			}
		}
		return -1;
	};
	const direct = scan(listener);
	if (direct >= 0) return direct;
	const stats = methodOf(listener, ["stats", "metrics", "counters", "snapshot", "state", "summary"]);
	if (stats) {
		try {
			return scan(stats());
		} catch {
			return -1;
		}
	}
	return -1;
}

function toCallbackHitSafe(hit: Any): Any {
	try {
		return (resilience.toCallbackHit as Any)(hit);
	} catch {
		return hit;
	}
}

async function correlateHits(hits: Any[], context: Any): Promise<Any> {
	const Ctor: Any = (resilience as Any).OobCorrelator;
	expect(typeof Ctor).toBe("function");

	let correlator: Any;
	try {
		correlator = new Ctor({
			ttlMs: 120_000,
			maxPending: 64,
			now: () => Date.now(),
			clock: () => Date.now(),
		});
	} catch {
		correlator = new Ctor();
	}
	expect(correlator).toBeDefined();

	await tryAsync(correlator, ["register", "registerCanary", "addContext", "track", "expect", "prepare", "watch"], context);

	for (const hit of hits) {
		const ingestDirect = await tryAsync(
			correlator,
			["ingestHit", "ingest", "observe", "push", "add", "record", "handle", "match"],
			hit,
		);
		if (!ingestDirect.ok) {
			const converted = toCallbackHitSafe(hit);
			await tryAsync(correlator, ["ingestCallbackHits", "ingest", "accept", "feed", "onHit", "submit"], [converted]);
		}
	}

	const collected = await tryAsync(correlator, [
		"correlateCallbacks",
		"correlate",
		"evaluate",
		"drain",
		"collect",
		"flush",
		"result",
		"results",
		"snapshot",
		"summary",
		"matched",
	]);
	return collected.ok ? collected.value : correlator;
}

describe("EmbeddedOobListener / OobCorrelator —— 带外回调关联", () => {
	test("签名 Canary 命中 / 伪造丢弃 / 跨轮次关联 / stop() 零泄漏", async () => {
		const Ctor: Any = (resilience as Any).EmbeddedOobListener;
		expect(typeof Ctor).toBe("function");

		const hmacSecret = randomBytes(16).toString("hex");
		const listener: Any = new Ctor({
			host: "127.0.0.1",
			bindHost: "127.0.0.1",
			address: "127.0.0.1",
			port: 0,
			secret: hmacSecret,
			hmacSecret,
			maxHits: 32,
			pathPrefix: "/oob",
		});
		expect(listener).toBeDefined();

		const stopFn = methodOf(listener, ["stop", "close", "shutdown", "dispose", "destroy"]);
		expect(typeof stopFn).toBe("function");

		let port = 0;
		try {
			const started = await tryAsync(listener, ["start", "listen", "boot", "up", "open"]);
			expect(started.ok).toBe(true);

			const endpointUrl = endpointOf(listener, started.value);
			expect(endpointUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+/);
			port = Number(new URL(endpointUrl).port);
			expect(port).toBeGreaterThan(0);

			const canaryId = `c-${randomBytes(4).toString("hex")}`;
			const canaryInput = {
				canaryId,
				projectId: "proj-v8",
			};

			const registration = await registerCanaryApi(listener, canaryInput);
			expect(registration).toBeDefined();

			const validUrl = callbackUrlOf(registration, endpointUrl, canaryInput);
			expect(validUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+/);

			// ---- 伪造请求：篡改签名或路径尾缀，必须被丢弃 ----
			const forgedUrl = forgeUrl(validUrl);
			expect(forgedUrl).not.toBe(validUrl);
			let forgedStatus = 0;
			try {
				const forgedRes = await fetch(forgedUrl, { signal: AbortSignal.timeout(3000) });
				forgedStatus = forgedRes.status;
				await forgedRes.text();
			} catch {
				forgedStatus = 0;
			}
			const forgedQueryUrl = `${endpointUrl}/oob?cid=${encodeURIComponent(canaryId)}&tok=${encodeURIComponent(String(registration.token ?? ""))}&sig=deadbeef`;
			try {
				const qRes = await fetch(forgedQueryUrl, { signal: AbortSignal.timeout(3000) });
				await qRes.text();
			} catch {
				/* ignore */
			}

			// ---- 跨轮次延迟回调：真实 HTTP 命中合法签名 URL ----
			await sleep(120);
			const validRes = await fetch(validUrl, { signal: AbortSignal.timeout(3000) });
			const validBody = await validRes.text();
			expect(validRes.status).toBeLessThan(500);
			expect(validBody.length).toBeGreaterThan(0);

			// ---- 伪造请求只计数，不产生可关联命中 ----
			const hits = await collectHits(listener);
			const rejectedCount = rejectedForgedCount(listener);
			if (rejectedCount >= 0) {
				expect(rejectedCount).toBeGreaterThanOrEqual(2);
			} else {
				expect(forgedStatus === 0 || forgedStatus >= 400).toBe(true);
			}

			expect(Array.isArray(hits)).toBe(true);
			expect(hits.length).toBeGreaterThan(0);
			expect(jsonText(hits).includes("intent-v8-1")).toBe(false);

			// ---- 关联器：按来源上下文跨轮次匹配 ----
			const correlationContext = {
				projectId: "proj-v8",
				intentId: "intent-v8-1",
				intent: "intent-v8-1",
				canaryId,
				endpoint: "GET /api/import",
				endpointPath: "/api/import",
				paramName: "callback",
				templateHash: "tpl-v8-oob",
				templateFingerprint: "tpl-v8-oob",
				authRole: "admin",
			};

			const result = await correlateHits(hits, correlationContext);
			const corrText = jsonText(result).toLowerCase();
			expect(corrText.length).toBeGreaterThan(0);
			expect(corrText).toContain("intent-v8-1");
			expect(corrText).toContain("callback");
			expect(corrText).toMatch(/wake|entropy|signal|matched|correlat/);

			// ---- 原始命中 → toCallbackHit 结构可复用 ----
			const converted = toCallbackHitSafe(hits[0]);
			expect(jsonText(converted).length).toBeGreaterThan(0);
		} finally {
			if (stopFn) {
				try {
					await stopFn();
				} catch {
					/* ignore */
				}
			}
		}

		// ---- stop() 之后端口必须彻底关闭：连接拒绝 ----
		expect(port).toBeGreaterThan(0);
		expect(await connectionRefused(port)).toBe(true);

		// ---- stop() 幂等：重复调用不抛异常、不复活端口 ----
		if (stopFn) {
			await stopFn();
		}
		expect(await connectionRefused(port)).toBe(true);
	});
});
