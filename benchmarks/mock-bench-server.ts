/**
 * 离线确定性本地靶场模拟服务（仅绑定 127.0.0.1 随机空闲端口，返回良性合成响应）。
 *
 * 提供以下测试端点：
 * - `/spa/*`：对未知路径统一返回 200 React SPA HTML 壳（Soft-404 陷阱）；
 *   `/spa/app.js` 包含 `/api/v2/invoices` 与 `/graphql`；
 *   `/spa/admin-panel.js` 仅在携带 `Authorization: Bearer bench_admin_tok_12345` 时返回 200。
 * - `/api/orders/1001`：匿名 401，对 `user_a` 与 `user_b` 均返回 200 同一订单对象（合成 BOLA 夹具）。
 * - `/api/admin/metrics`：匿名 401，对 `admin` 与 `user_a` 均返回 200 管理指标（合成 BFLA 夹具）。
 * - `/waf/probe`：返回 429 Too Many Requests + Retry-After + X-RateLimit-Remaining。
 * - `/oob/trigger?canary=<host>` 与 `/oob/poll`：内存记录良性 OOB 金丝雀命中并返回 Interactsh 兼容 JSON。
 */

export interface MockOobHit {
	id: string;
	host: string;
	ts: string;
}

export interface MockBenchServer {
	baseUrl: string;
	port: number;
	stop: () => void;
	getOobHits: () => Array<{ id: string; host: string; ts: string }>;
}

export const BENCH_TOKENS = {
	admin: "bench_admin_tok_12345",
	userA: "bench_user_a_tok_11111",
	userB: "bench_user_b_tok_22222",
} as const;

const SPA_SHELL_HTML = [
	"<!doctype html>",
	"<html>",
	"<head><meta charset=\"utf-8\"><title>Bench SPA</title></head>",
	"<body>",
	"<div id=\"root\" data-reactroot></div>",
	"<script src=\"/spa/app.js\"></script>",
	"<script src=\"/spa/admin-panel.js\"></script>",
	"</body>",
	"</html>",
].join("");

const SPA_APP_JS = [
	"// Benign synthetic SPA bundle for offline deterministic benchmark",
	"export const APP_ROUTES = ['/spa/dashboard', '/spa/invoices'];",
	"export async function fetchInvoices(page, limit) {",
	"  return fetch('/api/v2/invoices?page=' + page + '&limit=' + limit);",
	"}",
	"export async function runGraphql(query) {",
	"  return fetch('/graphql', {",
	"    method: 'POST',",
	"    headers: { 'Content-Type': 'application/json' },",
	"    body: JSON.stringify({ query, operationName: 'ViewerSummary' }),",
	"  });",
	"}",
].join("\n");

const SPA_ADMIN_PANEL_JS = [
	"// Benign synthetic authenticated admin bundle",
	"export const ADMIN_ROUTES = ['/spa/admin/audit', '/spa/admin/users'];",
	"export async function fetchAuditLogs() {",
	"  return fetch('/api/v2/admin/audit-logs?limit=50');",
	"}",
	"export async function fetchAdminUsers() {",
	"  return fetch('/api/v2/admin/users');",
	"}",
].join("\n");

function resolveBenchRole(req: Request): "admin" | "user_a" | "user_b" | null {
	const auth = (req.headers.get("authorization") ?? "").trim();
	const cookie = (req.headers.get("cookie") ?? "").trim();

	if (auth === `Bearer ${BENCH_TOKENS.admin}` || cookie.includes(`sid=${BENCH_TOKENS.admin}`)) {
		return "admin";
	}
	if (auth === `Bearer ${BENCH_TOKENS.userA}` || cookie.includes(`sid=${BENCH_TOKENS.userA}`)) {
		return "user_a";
	}
	if (auth === `Bearer ${BENCH_TOKENS.userB}` || cookie.includes(`sid=${BENCH_TOKENS.userB}`)) {
		return "user_b";
	}
	return null;
}

function jsonResp(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json; charset=utf-8",
			...extraHeaders,
		},
	});
}

export function startMockBenchServer(): MockBenchServer {
	const oobHits: MockOobHit[] = [];
	let oobSeq = 0;

	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch(req: Request): Response {
			const url = new URL(req.url);
			const pathname = url.pathname;

			if (pathname === "/health") {
				return jsonResp({ status: "ok", bench: true }, 200);
			}

			// SPA static bundles & Soft-404 catch-all trap
			if (pathname === "/spa/app.js") {
				return new Response(SPA_APP_JS, {
					status: 200,
					headers: { "Content-Type": "application/javascript; charset=utf-8" },
				});
			}

			if (pathname === "/spa/admin-panel.js") {
				const role = resolveBenchRole(req);
				if (role !== "admin") {
					return jsonResp({ error: "unauthorized", message: "Admin token required" }, 401);
				}
				return new Response(SPA_ADMIN_PANEL_JS, {
					status: 200,
					headers: { "Content-Type": "application/javascript; charset=utf-8" },
				});
			}

			if (pathname === "/spa" || pathname.startsWith("/spa/")) {
				return new Response(SPA_SHELL_HTML, {
					status: 200,
					headers: { "Content-Type": "text/html; charset=utf-8" },
				});
			}

			// Synthetic BOLA/IDOR fixture
			if (pathname === "/api/orders/1001") {
				const role = resolveBenchRole(req);
				if (!role) {
					return jsonResp({ error: "unauthorized", message: "Authentication required" }, 401);
				}
				if (role === "user_a" || role === "user_b" || role === "admin") {
					return jsonResp({ orderId: 1001, owner: "alice", total: 99 }, 200);
				}
				return jsonResp({ error: "forbidden" }, 403);
			}

			// Synthetic vertical BFLA fixture
			if (pathname === "/api/admin/metrics") {
				const role = resolveBenchRole(req);
				if (!role) {
					return jsonResp({ error: "unauthorized", message: "Authentication required" }, 401);
				}
				if (role === "admin" || role === "user_a") {
					return jsonResp({ cluster: "bench", activeNodes: 3 }, 200);
				}
				return jsonResp({ error: "forbidden" }, 403);
			}

			// Synthetic WAF / HTTP 429 rate-limit fixture
			if (pathname === "/waf/probe") {
				return jsonResp(
					{ error: "rate limit exceeded", message: "Too Many Requests" },
					429,
					{
						"Retry-After": "5",
						"X-RateLimit-Remaining": "0",
					},
				);
			}

			// Synthetic Interactsh-compatible OOB canary trigger & poll
			if (pathname === "/oob/trigger") {
				const canary = (url.searchParams.get("canary") ?? "").trim();
				if (!canary) {
					return jsonResp({ error: "missing canary parameter" }, 400);
				}
				const hit: MockOobHit = {
					id: `oob-${String(++oobSeq).padStart(4, "0")}`,
					host: canary,
					ts: new Date().toISOString(),
				};
				oobHits.push(hit);
				return jsonResp({ ok: true, recorded: hit }, 200);
			}

			if (pathname === "/oob/poll") {
				const filter = (url.searchParams.get("canary") ?? "").trim().toLowerCase();
				const matched = filter
					? oobHits.filter((h) => h.host.toLowerCase().includes(filter))
					: oobHits;
				return jsonResp(
					{
						data: matched.map((h) => ({
							id: h.id,
							host: h.host,
							ts: h.ts,
							protocol: "http",
							"unique-id": h.id,
							"full-id": h.host,
							"remote-address": "127.0.0.1",
							timestamp: h.ts,
						})),
						extra: null,
					},
					200,
				);
			}

			return jsonResp({ error: "not_found", path: pathname }, 404);
		},
	});

	const port = server.port ?? 0;
	const baseUrl = `http://127.0.0.1:${port}`;

	return {
		baseUrl,
		port,
		stop: () => {
			server.stop(true);
		},
		getOobHits: () => oobHits.map((h) => ({ ...h })),
	};
}
