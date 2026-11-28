import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	analyzeCrossFileRgs,
	bridgeRgsToVerificationIntents,
	generateStandalonePovScript,
	matchGuardPathPattern,
	writeStandalonePovScript,
} from "../omp/rgs-analyzer";
import { defaultScopeForTarget } from "../omp/scope";
import { materializeRoleHeaderFile, upsertSessionRole } from "../omp/session-vault";
import type { Fact } from "../omp/types";

describe("v8 跨文件 RGS 代码数据流引擎 (omp/rgs-analyzer.ts)", () => {
	test("Ant 与前缀路由守卫路径模式匹配边界精准无误判", () => {
		expect(matchGuardPathPattern("/api/v1", "/api/v1/users")).toBe(true);
		expect(matchGuardPathPattern("/api/v1", "/api/v1")).toBe(true);
		// 严禁把 /api/v1 前缀误匹配到 /api/v10
		expect(matchGuardPathPattern("/api/v1", "/api/v10/users")).toBe(false);
		expect(matchGuardPathPattern("/api/admin/**", "/api/admin/roles/1/permissions")).toBe(true);
		expect(matchGuardPathPattern("/api/*/detail", "/api/orders/detail")).toBe(true);
		expect(matchGuardPathPattern("/api/*/detail", "/api/orders/sub/detail")).toBe(false);
	});

	test("Java / Spring Boot: SecurityFilterChain + WebMvcConfigurer 覆盖差集与 MyBatis/JdbcTemplate 跨文件链路", () => {
		const springProject: Record<string, string> = {
			"src/main/java/com/acme/config/SecurityConfig.java": [
				"package com.acme.config;",
				"import org.springframework.context.annotation.Bean;",
				"import org.springframework.security.config.annotation.web.builders.HttpSecurity;",
				"import org.springframework.security.web.SecurityFilterChain;",
				"public class SecurityConfig {",
				"    @Bean",
				"    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {",
				"        http.authorizeHttpRequests(auth -> auth",
				'            .requestMatchers("/api/v1/legacy/**", "/healthz").permitAll()',
				'            .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")',
				"            .anyRequest().authenticated()",
				"        );",
				"        return http.build();",
				"    }",
				"}",
			].join("\n"),
			"src/main/java/com/acme/controller/AdminController.java": [
				"package com.acme.controller;",
				"import org.springframework.web.bind.annotation.*;",
				"@RestController",
				'@RequestMapping("/api/v1/admin")',
				"public class AdminController {",
				"    // 单文件内未标 @PreAuthorize，但受 SecurityConfig /api/v1/admin/** 全局保护，绝不应误报",
				'    @GetMapping("/tenants")',
				"    public String listTenants() {",
				'        return "ok";',
				"    }",
				"}",
			].join("\n"),
			"src/main/java/com/acme/controller/LegacyReportController.java": [
				"package com.acme.controller;",
				"import com.acme.service.ReportService;",
				"import org.springframework.web.bind.annotation.*;",
				"@RestController",
				'@RequestMapping("/api/v1/legacy")',
				"public class LegacyReportController {",
				"    private final ReportService reportService;",
				"    public LegacyReportController(ReportService reportService) { this.reportService = reportService; }",
				'    @GetMapping("/orders")',
				"    public Object exportOrders(@RequestParam String sortCol) {",
				"        return reportService.querySortedOrders(sortCol);",
				"    }",
				"}",
			].join("\n"),
			"src/main/java/com/acme/service/ReportService.java": [
				"package com.acme.service;",
				"import com.acme.mapper.OrderMapper;",
				"public class ReportService {",
				"    private final OrderMapper orderMapper;",
				"    public ReportService(OrderMapper orderMapper) { this.orderMapper = orderMapper; }",
				"    public Object querySortedOrders(String sortField) {",
				"        return orderMapper.selectByDynamicOrder(sortField);",
				"    }",
				"}",
			].join("\n"),
			"src/main/resources/mapper/OrderMapper.xml": [
				'<?xml version="1.0" encoding="UTF-8" ?>',
				'<mapper namespace="com.acme.mapper.OrderMapper">',
				'    <select id="selectBySafeId" resultType="map">',
				"        SELECT id, amount FROM orders WHERE id = #{orderId}",
				"    </select>",
				'    <select id="selectByDynamicOrder" resultType="map">',
				"        SELECT id, amount FROM orders ORDER BY ${sortCol} DESC",
				"    </select>",
				"</mapper>",
			].join("\n"),
		};

		const rgs = analyzeCrossFileRgs(springProject);
		expect(rgs.scannedFiles).toBe(5);

		const adminRoute = rgs.routes.find((r) => r.path === "/api/v1/admin/tenants");
		expect(adminRoute).toBeDefined();
		expect(adminRoute!.hasEffectiveGuard).toBe(true);
		expect(adminRoute!.suppressedByGlobalGuard).toBe(true);
		expect(adminRoute!.riskFlags).not.toContain("missing_auth_guard");

		const legacyRoute = rgs.routes.find((r) => r.path === "/api/v1/legacy/orders");
		expect(legacyRoute).toBeDefined();
		expect(legacyRoute!.hasEffectiveGuard).toBe(false);
		expect(legacyRoute!.riskFlags).toContain("missing_auth_guard");
		expect(legacyRoute!.riskFlags).toContain("unparameterized_sql");
		expect(legacyRoute!.anchor).toBe("src/main/java/com/acme/controller/LegacyReportController.java:9");

		// 验证安全的 #{orderId} 未误报 Sink，而危险的 ${sortCol} 形成跨 3 文件链路
		expect(rgs.sinks.length).toBe(1);
		expect(rgs.sinks[0]!.anchor).toBe("src/main/resources/mapper/OrderMapper.xml:7");
		expect(legacyRoute!.dataflowChains.length).toBe(1);
		const chain = legacyRoute!.dataflowChains[0]!;
		expect(chain.crossFile).toBe(true);
		expect(chain.hops.map((h) => h.step)).toEqual(["route", "controller", "service", "repository", "sink"]);
	});

	test("Spring WebMvcConfigurer excludePathPatterns 差集、@PreAuthorize(permitAll) 与 JdbcTemplate 拼接", () => {
		const mvcRepo: Record<string, string> = {
			"WebConfig.java": [
				"public class WebConfig implements WebMvcConfigurer {",
				"    public void addInterceptors(InterceptorRegistry registry) {",
				'        registry.addInterceptor(jwtAuthInterceptor).addPathPatterns("/api/**").excludePathPatterns("/api/webhook/**");',
				"    }",
				"}",
			].join("\n"),
			"SyncController.java": [
				"@RestController",
				'@RequestMapping("/api")',
				"public class SyncController {",
				'    @GetMapping("/orders/list")',
				"    public String list() { return \"ok\"; }",
				'    @PostMapping("/webhook/notify")',
				"    public String hook(@RequestParam String filter) {",
				'        jdbcTemplate.queryForList("SELECT * FROM hooks WHERE tag = \'" + filter + "\'");',
				"        return \"done\";",
				"    }",
				'    @GetMapping("/orders/public-preview")',
				'    @PreAuthorize("permitAll()")',
				"    public String preview() { return \"pub\"; }",
				"}",
			].join("\n"),
		};
		const rgs = analyzeCrossFileRgs(mvcRepo);
		const guarded = rgs.routes.find((r) => r.path === "/api/orders/list");
		const excluded = rgs.routes.find((r) => r.path === "/api/webhook/notify");
		const permitAll = rgs.routes.find((r) => r.path === "/api/orders/public-preview");

		expect(guarded?.hasEffectiveGuard).toBe(true);
		expect(guarded?.suppressedByGlobalGuard).toBe(true);
		expect(excluded?.hasEffectiveGuard).toBe(false);
		expect(excluded?.riskFlags).toContain("unparameterized_sql");
		expect(permitAll?.hasEffectiveGuard).toBe(false);
		expect(permitAll?.isExplicitlyPublic).toBe(true);
	});

	test("对抗边界：被注释掉的 SecurityFilterChain 守卫与废弃 SQL Sink 绝不产生漏报或误报，且 PoV 剥离嵌套 Body 密钥", () => {
		const commentedTrapRepo: Record<string, string> = {
			"SecurityConfig.java": [
				"public class SecurityConfig {",
				"    public SecurityFilterChain filterChain(HttpSecurity http) {",
				"        // .anyRequest().authenticated()",
				'        http.authorizeHttpRequests(a -> a.requestMatchers("/api/secure/**").authenticated());',
				"        return http.build();",
				"    }",
				"}",
			].join("\n"),
			"DataController.java": [
				"@RestController",
				"public class DataController {",
				'    @GetMapping("/api/open/items")',
				"    public String items(@RequestParam String q) {",
				'        // jdbcTemplate.query("SELECT * FROM old WHERE name = \'" + q + "\'");',
				'        return "safe";',
				"    }",
				"}",
			].join("\n"),
		};
		const rgs = analyzeCrossFileRgs(commentedTrapRepo);
		const openItems = rgs.routes.find((r) => r.path === "/api/open/items")!;
		// 注释中的 .anyRequest().authenticated() 不生效，因此 /api/open/items 必须正确检出 missing_auth_guard
		expect(openItems.hasEffectiveGuard).toBe(false);
		// 注释中的 jdbcTemplate 拼接不生效，因此 sinks 必须为 0
		expect(rgs.sinks.length).toBe(0);

		const rawBodySecret = "plain_unprefixed_custom_password_val_9988";
		const rawCookieVal = "PHPSESSID=abcdef0123456789secret";
		const pov = generateStandalonePovScript({
			fact: {
				id: "f-adv",
				kind: "vuln",
				title: "鉴权缺失",
				detail: "测试",
				command: `curl -b "${rawCookieVal}" -u admin:${rawBodySecret} http://127.0.0.1:8080/api/open/items`,
				verifyStage: "confirmed",
			},
			explicit: {
				factId: "f-adv",
				title: "测试",
				baseUrl: "http://127.0.0.1:8080",
				path: "/api/open/items",
				method: "POST",
				body: { filter: "active", apiKey: rawBodySecret, nested: { password: rawBodySecret, page: 1 } },
			},
		});
		expect(pov.scriptContent).not.toContain(rawBodySecret);
		expect(pov.scriptContent).not.toContain("abcdef0123456789secret");
		expect(pov.redactedSecretsCount).toBeGreaterThanOrEqual(2);
	});

	test("TS/Express + Python/FastAPI + Go/Gin 跨文件路由组守卫继承与污点串联", () => {
		const polyglotRepo: Record<string, string> = {
			// TS Express: app.ts 挂载 requireAuth 到 ./routes/billing
			"ts/app.ts": [
				'import express from "express";',
				'import billingRouter from "./routes/billing";',
				'import debugRouter from "./routes/debug";',
				"const app = express();",
				'app.use("/api/billing", requireAuthMiddleware, billingRouter);',
				'app.use("/api/debug", debugRouter);',
			].join("\n"),
			"ts/routes/billing.ts": [
				'import { Router } from "express";',
				"const router = Router();",
				'router.get("/invoices", (req, res) => { res.json({ ok: true }); });',
				"export default router;",
			].join("\n"),
			"ts/routes/debug.ts": [
				'import { Router } from "express";',
				'import { runRawLookup } from "../services/lookup";',
				"const router = Router();",
				'router.get("/search", (req, res) => { return runRawLookup(req.query.filter); });',
				"export default router;",
			].join("\n"),
			"ts/services/lookup.ts": [
				"export function runRawLookup(filterExpr: string) {",
				"  return db.query(`SELECT * FROM logs WHERE tag = '${filterExpr}'`);",
				"}",
			].join("\n"),

			// Python FastAPI: main.py include_router 注入 Depends(get_current_user)
			"py/main.py": [
				"from fastapi import FastAPI, Depends",
				"from routers import secret_admin, open_export",
				"app = FastAPI()",
				'app.include_router(secret_admin.router, prefix="/py/admin", dependencies=[Depends(get_current_user)])',
				'app.include_router(open_export.router, prefix="/py/open")',
			].join("\n"),
			"py/routers/secret_admin.py": [
				"from fastapi import APIRouter",
				"router = APIRouter()",
				'@router.get("/stats")',
				"async def read_stats():",
				"    return {'ok': True}",
			].join("\n"),
			"py/routers/open_export.py": [
				"from fastapi import APIRouter",
				"import os",
				"router = APIRouter()",
				'@router.post("/archive")',
				"async def make_archive(target_name: str):",
				"    os.system(f'tar -cf /tmp/out.tar {target_name}')",
				"    return {'queued': True}",
			].join("\n"),

			// Go Gin: main.go 创建带 JWTAuthMiddleware 的 Group 并跨文件传入 RegisterProtectedRoutes
			"go/main.go": [
				"package main",
				"func setupServer() {",
				"    r := gin.Default()",
				'    sec := r.Group("/go/secure", JWTAuthMiddleware())',
				"    RegisterProtectedRoutes(sec)",
				'    pub := r.Group("/go/public")',
				"    RegisterOpenRoutes(pub)",
				"}",
			].join("\n"),
			"go/routes.go": [
				"package main",
				"import \"os/exec\"",
				"func RegisterProtectedRoutes(rg *gin.RouterGroup) {",
				'    rg.GET("/keys", ListKeysHandler)',
				"}",
				"func RegisterOpenRoutes(rg *gin.RouterGroup) {",
				'    rg.POST("/diag", RunDiagHandler)',
				"}",
				"func ListKeysHandler(c *gin.Context) {}",
				"func RunDiagHandler(c *gin.Context) {",
				'    host := c.Query("host")',
				'    exec.Command("ping", "-c", "1", host)',
				"}",
			].join("\n"),
		};

		const rgs = analyzeCrossFileRgs(polyglotRepo);

		// TS Express 验证
		const tsGuarded = rgs.routes.find((r) => r.path === "/api/billing/invoices");
		const tsOpen = rgs.routes.find((r) => r.path === "/api/debug/search");
		expect(tsGuarded?.hasEffectiveGuard).toBe(true);
		expect(tsGuarded?.suppressedByGlobalGuard).toBe(true);
		expect(tsOpen?.hasEffectiveGuard).toBe(false);
		expect(tsOpen?.riskFlags).toContain("unparameterized_sql");
		expect(tsOpen?.dataflowChains[0]?.crossFile).toBe(true);

		// Python FastAPI 验证
		const pyGuarded = rgs.routes.find((r) => r.path === "/py/admin/stats");
		const pyOpen = rgs.routes.find((r) => r.path === "/py/open/archive");
		expect(pyGuarded?.hasEffectiveGuard).toBe(true);
		expect(pyOpen?.hasEffectiveGuard).toBe(false);
		expect(pyOpen?.riskFlags).toContain("dangerous_exec_call");

		// Go Gin 验证
		const goGuarded = rgs.routes.find((r) => r.path === "/go/secure/keys");
		const goOpen = rgs.routes.find((r) => r.path === "/go/public/diag");
		expect(goGuarded?.hasEffectiveGuard).toBe(true);
		expect(goOpen?.hasEffectiveGuard).toBe(false);
		expect(goOpen?.riskFlags).toContain("dangerous_exec_call");
	});

	test("PHP (Laravel/Symfony/原生) 与 Rust (Actix-web/Axum) 路由、属性宏与汇点精确分析", () => {
		const phpRustRepo: Record<string, string> = {
			"php/routes/api.php": [
				"<?php",
				"use App\\Http\\Controllers\\AuditController;",
				"Route::middleware(['auth:sanctum'])->prefix('api/v1')->group(function () {",
				"    Route::get('/profile', [AuditController::class, 'profile']);",
				"    Route::get('/raw-export', [AuditController::class, 'rawExport'])->withoutMiddleware();",
				"});",
			].join("\n"),
			"php/app/Http/Controllers/AuditController.php": [
				"<?php",
				"namespace App\\Http\\Controllers;",
				"use Symfony\\Component\\Routing\\Annotation\\Route;",
				"use Symfony\\Component\\Security\\Http\\Attribute\\IsGranted;",
				"class AuditController {",
				"    public function profile($req) { return ['ok' => true]; }",
				"    public function rawExport($request) {",
				"        $sort = $request->input('sort');",
				'        return DB::select("SELECT * FROM audits ORDER BY " . $sort);',
				"    }",
				"    #[Route('/sym/admin/config', methods: ['POST'])]",
				"    #[IsGranted('ROLE_ADMIN')]",
				"    public function symAdmin() { return []; }",
				"}",
			].join("\n"),
			"php/legacy/download.php": [
				"<?php",
				"// 原生超全局无会话校验读取文件",
				"$target = $_GET['file'];",
				"echo file_get_contents('/var/data/' . $target);",
			].join("\n"),
			"rust/src/main.rs": [
				"use axum::{Router, routing::{get, post}, extract::Query, middleware};",
				"use std::process::Command;",
				"pub fn build_app() -> Router {",
				"    // Axum .layer 仅保护其前方已注册的 /axum/protected，后方 /axum/unprotected 裸露",
				"    Router::new()",
				'        .route("/axum/protected", get(protected_handler))',
				"        .layer(middleware::from_fn(jwt_auth_guard))",
				'        .route("/axum/unprotected", post(unprotected_query))',
				"}",
				"async fn protected_handler<'a>() -> &'static str { \"ok\" }",
				"async fn unprotected_query(Query(q): Query<String>) -> String {",
				'    let _ = sqlx::query(&format!("SELECT * FROM items WHERE name = \'{}\'", q));',
				'    let _ = Command::new(q);',
				'    String::from("done")',
				"}",
			].join("\n"),
			"rust/src/actix_mod.rs": [
				"use actix_web::{get, web, HttpResponse};",
				'#[get("/users/{id}")]',
				"async fn get_user_detail<'a>(id: web::Path<String>) -> HttpResponse { HttpResponse::Ok().finish() }",
				"pub fn cfg(app: &mut web::ServiceConfig) {",
				'    web::scope("/actix/secure").wrap(JwtAuthMiddleware).service(get_user_detail);',
				"}",
			].join("\n"),
		};

		const rgs = analyzeCrossFileRgs(phpRustRepo);

		// PHP Laravel: /api/v1/profile 继承 auth:sanctum；/api/v1/raw-export 因 withoutMiddleware 暴露且带 SQL Sink
		const lvProfile = rgs.routes.find((r) => r.path === "/api/v1/profile");
		const lvRawExport = rgs.routes.find((r) => r.path === "/api/v1/raw-export");
		expect(lvProfile?.hasEffectiveGuard).toBe(true);
		expect(lvRawExport?.hasEffectiveGuard).toBe(false);
		expect(lvRawExport?.riskFlags).toContain("unparameterized_sql");

		// PHP Symfony 8 `#[Route]` 未被 `#` 注释剥离误伤，且识别 `#[IsGranted]`
		const symAdmin = rgs.routes.find((r) => r.path === "/sym/admin/config");
		expect(symAdmin?.method).toBe("POST");
		expect(symAdmin?.hasEffectiveGuard).toBe(true);

		// PHP 原生脚本超全局 -> 文件读取汇点
		const nativePhp = rgs.routes.find((r) => r.path === "/php/legacy/download.php");
		expect(nativePhp?.hasEffectiveGuard).toBe(false);
		expect(nativePhp?.riskFlags).toContain("unchecked_path_join");

		// Rust Axum 顺序敏感 `.layer()` 验证 + Rust 生命周期 `'a` 不吞后续源码
		const axProtected = rgs.routes.find((r) => r.path === "/axum/protected");
		const axUnprotected = rgs.routes.find((r) => r.path === "/axum/unprotected");
		expect(axProtected?.hasEffectiveGuard).toBe(true);
		expect(axUnprotected?.hasEffectiveGuard).toBe(false);
		expect(axUnprotected?.riskFlags).toContain("unparameterized_sql");
		expect(axUnprotected?.riskFlags).toContain("dangerous_exec_call");

		// Rust Actix-web scope wrap 继承验证
		const actixSecured = rgs.routes.find((r) => r.path === "/actix/secure/users/{id}");
		expect(actixSecured?.hasEffectiveGuard).toBe(true);
	});

	test("Webpack / Vite 前端混淆 Bundle 隐藏路由、参数与预编译 GraphQL AST 反解及意图桥接", () => {
		const bundleInput: Record<string, string> = {
			"dist/assets/index-8f3a2c1b.js":
				'(()=>{var __webpack_require__={};const a="/api/v2";e.patch("/api/v2/org/roles",{targetUserId:t,newRole:n,isSuperAdmin:r},{headers:{"X-Client-Sig":s,"X-Tenant-Id":o}});fetch("".concat(a,"/internal/billing/export?tenant=").concat(u,"&includeHidden=1"),{method:"POST"});const doc={kind:"Document",definitions:[{kind:"OperationDefinition",operation:"mutation",name:{kind:"Identifier",value:"ElevateWorkspaceRole"},variableDefinitions:[{kind:"VariableDefinition",variable:{kind:"Variable",name:{kind:"Identifier",value:"workspaceId"}}},{kind:"VariableDefinition",variable:{kind:"Variable",name:{kind:"Identifier",value:"roleCode"}}}],selectionSet:{kind:"SelectionSet",selections:[{kind:"Field",name:{kind:"Identifier",value:"elevateRole"}}]}}]};const q=`query GetSecretKeys($orgId: ID!) { orgKeys(orgId: $orgId) { keyId secretPreview } }`;})();',
		};

		const rgs = analyzeCrossFileRgs(bundleInput);
		expect(rgs.bundles.length).toBe(1);
		const b = rgs.bundles[0]!;
		expect(b.bundler).toBe("webpack");

		const patchEp = b.endpoints.find((e) => e.path === "/api/v2/org/roles");
		expect(patchEp).toBeDefined();
		expect(patchEp!.method).toBe("PATCH");
		expect(patchEp!.params).toEqual(expect.arrayContaining(["targetUserId", "newRole", "isSuperAdmin"]));
		expect(patchEp!.headers).toEqual(expect.arrayContaining(["X-Client-Sig", "X-Tenant-Id"]));

		const gqlNames = b.graphqlOperations.map((g) => g.operationName);
		expect(gqlNames).toContain("ElevateWorkspaceRole");
		expect(gqlNames).toContain("GetSecretKeys");
		const astOp = b.graphqlOperations.find((g) => g.operationName === "ElevateWorkspaceRole")!;
		expect(astOp.kind).toBe("mutation");
		expect(astOp.variables).toEqual(["workspaceId", "roleCode"]);

		const scope = defaultScopeForTarget("http://127.0.0.1:18080", "pentest");
		const bridged = bridgeRgsToVerificationIntents(rgs, "http://127.0.0.1:18080", { scope });
		expect(bridged.intents.length).toBeGreaterThanOrEqual(3);
		expect(bridged.hypotheses.length).toBe(bridged.intents.length);
	});

	test("generateStandalonePovScript: 强门禁拒绝未确认事实、100% 零明文凭据并实跑独立进程验证退出码 0/1", async () => {
		const tmpRoot = mkdtempSync(join(tmpdir(), "nuwa-v8-pov-test-"));
		const secretJwt =
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtZW1iZXJfMSIsInJvbGUiOiJtZW1iZXIifQ.super_secret_sig_998877";
		const secretCookie = "sid_secret_cookie_value_44556677";

		const srv = Bun.serve({
			hostname: "127.0.0.1",
			port: 0,
			fetch(req: Request): Response {
				const u = new URL(req.url);
				const auth = req.headers.get("authorization") ?? "";
				const cookie = req.headers.get("cookie") ?? "";
				const authed = auth === `Bearer ${secretJwt}` || cookie.includes(secretCookie);

				if (u.pathname === "/api/v1/legacy/audit-dump") {
					if (!authed) return new Response('{"error":"unauthorized"}', { status: 401 });
					return new Response(
						JSON.stringify({
							exportId: "exp-2026-88",
							records: 42,
							confidentialTier: "internal-only",
						}),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					);
				}
				if (u.pathname === "/api/v1/admin/strict") {
					return new Response('{"error":"forbidden_admin_only"}', { status: 403 });
				}
				return new Response('{"error":"not_found"}', { status: 404 });
			},
		});

		try {
			const baseUrl = `http://127.0.0.1:${srv.port}`;
			upsertSessionRole(tmpRoot, {
				role: "member",
				bearer: secretJwt,
				cookie: `nuwa_sid=${secretCookie}`,
			});

			// 1. 拒绝 candidate / rejected 未确认事实
			const candidateFact: Fact = {
				id: "f001",
				kind: "vuln",
				title: "候选未确认发现",
				detail: `${baseUrl}/api/v1/legacy/audit-dump`,
				verifyStage: "candidate",
				createdAt: new Date().toISOString(),
			};
			expect(() => generateStandalonePovScript({ fact: candidateFact })).toThrow(/confirmed/);

			const rejectedFact: Fact = {
				...candidateFact,
				id: "f002",
				verifyStage: "rejected",
			};
			expect(() => generateStandalonePovScript({ fact: rejectedFact })).toThrow(/confirmed/);

			// 2. 已确认事实中包含明文 Token、Cookie、敏感头与 URL token 参数时，生成脚本必须 100% 剥离
			const confirmedFact: Fact = {
				id: "f009",
				kind: "vuln",
				title: `Spring 路由鉴权遗漏 ${secretJwt}`,
				detail: `普通成员凭据 ${secretCookie} 成功读取 ${baseUrl}/api/v1/legacy/audit-dump?dept=fin&token=${secretJwt}`,
				command: `curl -H "Authorization: Bearer ${secretJwt}" "${baseUrl}/api/v1/legacy/audit-dump?dept=fin"`,
				verifyStage: "confirmed",
				verified: true,
				sourceAnchor: "LegacyController.java:24",
				createdAt: new Date().toISOString(),
			};

			const povOutDir = join(tmpRoot, "povs");
			const written = writeStandalonePovScript(povOutDir, {
				fact: confirmedFact,
				explicit: {
					factId: "f009",
					title: confirmedFact.title,
					baseUrl,
					path: "/api/v1/legacy/audit-dump?dept=fin",
					method: "GET",
					role: "member",
					headers: {
						Authorization: `Bearer ${secretJwt}`,
						Cookie: `nuwa_sid=${secretCookie}`,
						"X-Accept-Version": "2026-11",
					},
					expectedStatus: 200,
					expectedJsonKeys: ["exportId", "confidentialTier"],
					expectedBodyIncludes: ["internal-only"],
					protectedControlPath: "/api/v1/admin/strict",
					protectedExpectedStatuses: [403],
				},
				vaultRootOrVault: tmpRoot,
				knownSecretsToScrub: [secretJwt, secretCookie],
			});

			expect(written.fileName).toBe("pov-f009.ts");
			expect(written.redactedSecretsCount).toBeGreaterThan(0);

			const diskContent = readFileSync(written.filePath, "utf8");
			expect(diskContent).not.toContain(secretJwt);
			expect(diskContent).not.toContain(secretCookie);
			expect(diskContent).not.toContain("super_secret_sig_998877");
			expect(diskContent).toContain("NUWA_POV_HEADERS_FILE");
			expect(diskContent).toContain("NUWA_POV_TOKEN_MEMBER");
			expect(statSync(written.filePath).mode & 0o777).toBe(0o600);

			// 3. 子进程实跑验证 1：通过 NUWA_POV_TOKEN_MEMBER 注入，验证正向+负向+保护对照全过，退出码 === 0
			const proc1 = Bun.spawn(["bun", written.filePath], {
				env: {
					...process.env,
					NUWA_POV_TOKEN_MEMBER: secretJwt,
				},
				stdout: "pipe",
				stderr: "pipe",
			});
			const exit1 = await proc1.exited;
			const out1 = await new Response(proc1.stdout).text();
			expect(exit1).toBe(0);
			expect(out1).not.toContain(secretJwt);
			expect(JSON.parse(out1.trim()).ok).toBe(true);

			// 4. 子进程实跑验证 2：通过 SessionVault 物化的 .headers 文件注入 NUWA_POV_HEADERS_FILE，退出码 === 0
			const hdrFile = materializeRoleHeaderFile(tmpRoot, "pov-proj-1", "member");
			const proc2 = Bun.spawn(["bun", written.filePath], {
				env: {
					...process.env,
					NUWA_POV_HEADERS_FILE: hdrFile,
				},
				stdout: "pipe",
				stderr: "pipe",
			});
			expect(await proc2.exited).toBe(0);
			rmSync("/tmp/nuwa/pov-proj-1", { recursive: true, force: true });

			// 5. 子进程实跑验证 3：不注入任何有效凭据时，目标返回 401，断言失败退出码 === 1
			const procFail = Bun.spawn(["bun", written.filePath], {
				env: {
					PATH: process.env.PATH,
					HOME: process.env.HOME,
				},
				stdout: "pipe",
				stderr: "pipe",
			});
			expect(await procFail.exited).toBe(1);
		} finally {
			srv.stop(true);
			rmSync(tmpRoot, { recursive: true, force: true });
		}
	});
});
