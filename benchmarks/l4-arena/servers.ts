#!/usr/bin/env bun
/**
 * 女娲 v8.0 L4 真实有状态综合评估演武场服务集群（严格仅绑定 127.0.0.1:0，零硬编码端口，零残留）。
 *
 * 覆盖 12 个真实有状态应用安全评估基准场景：
 *  1) s01-second-order-store-read      : 二阶 Write-then-Read 存储型关联触发
 *  2) s02-mass-assignment-priv-esc     : POST/PATCH Mass Assignment 批量字段绑定提权
 *  3) s03-graphql-blind-schema-bola    : GraphQL 禁内省字段建议 Schema 盲还原 + 嵌套 BOLA
 *  4) s04-websocket-tenant-leak        : WebSocket 订阅未校验租户实时推送越权
 *  5) s05-barrier-race-toctou          : 单连接屏障同步并发时序竞争（TOCTOU 双花）
 *  6) s06-short-jwt-401-reauth         : 短期过期 JWT 触发 401 后交互式 TOTP 认证续期继续打穿
 *  7) s07-inpage-hmac-signed-diff      : 页面内全方法带动态 HMAC 签名接口差分突破
 *  8) s08-rsc-flight-grpc-web-bola     : Next.js RSC Flight / gRPC-Web 字段参数解析越权
 *  9) s09-cross-origin-cred-pivot      : 跨子域/多端口凭据横向复用检测（含越界零发包断言）
 * 10) s10-confirmed-ssrf-internal-pivot: 已确认 SSRF 桥接与内网隔离服务测绘分流
 * 11) s11-spring-rgs-standalone-pov    : Java/Spring Boot 跨文件路由鉴权缺口定位 + 独立 PoV 脚本实跑
 * 12) s12-fake200-trap-delayed-oob     : Fake-200 同构陷阱识别熔断 + 延迟异步 OOB 回调因果归因实锤
 */
import { createHash, randomBytes } from "node:crypto";

export type L4ScenarioId =
	| "s01-second-order-store-read"
	| "s02-mass-assignment-priv-esc"
	| "s03-graphql-blind-schema-bola"
	| "s04-websocket-tenant-leak"
	| "s05-barrier-race-toctou"
	| "s06-short-jwt-401-reauth"
	| "s07-inpage-hmac-signed-diff"
	| "s08-rsc-flight-grpc-web-bola"
	| "s09-cross-origin-cred-pivot"
	| "s10-confirmed-ssrf-internal-pivot"
	| "s11-spring-rgs-standalone-pov"
	| "s12-fake200-trap-delayed-oob";

export interface L4ScenarioSpec {
	id: L4ScenarioId;
	index: number;
	name: string;
	category: string;
	expectedFindings: number;
	description: string;
}

export const L4_SCENARIO_SPECS: readonly L4ScenarioSpec[] = [
	{ id: "s01-second-order-store-read", index: 1, name: "二阶 Write-then-Read 存储型关联触发", category: "stateful-workflow", expectedFindings: 1, description: "验证前置配置写入盲响应后，在二次报表预览端点触发存储型内部上下文暴露及自动清理" },
	{ id: "s02-mass-assignment-priv-esc", index: 2, name: "POST/PATCH Mass Assignment 批量字段绑定提权", category: "mass-assignment", expectedFindings: 1, description: "验证 PATCH 资料更新未过滤受保护 orgRole 属性导致写后读垂直提权访问组织审计导出" },
	{ id: "s03-graphql-blind-schema-bola", index: 3, name: "GraphQL 禁内省字段建议盲还原与嵌套 BOLA", category: "graphql-protocol", expectedFindings: 1, description: "在禁用 __schema 内省条件下通过 Did you mean 建议盲还原查询拓扑并检出跨租户嵌套对象越权" },
	{ id: "s04-websocket-tenant-leak", index: 4, name: "WebSocket 订阅未校验租户实时推送越权", category: "websocket-protocol", expectedFindings: 1, description: "验证 WebSocket 握手鉴权后 subscribe 帧漏检目标租户频道归属导致跨租户结算消息泄露" },
	{ id: "s05-barrier-race-toctou", index: 5, name: "单连接屏障同步并发时序竞争 TOCTOU 双花", category: "concurrency-race", expectedFindings: 1, description: "验证同步屏障并发齐射突破非原子余额校验产生多次兑换凭证，且对加锁幂等端点保持零误报" },
	{ id: "s06-short-jwt-401-reauth", index: 6, name: "短期过期 JWT 触发 401 后交互式认证续期打穿", category: "cdp-reauth", expectedFindings: 1, description: "验证短期过期令牌收到 401 后自动执行表单 + RFC 6238 TOTP 登录续期并继续检出账单 BOLA" },
	{ id: "s07-inpage-hmac-signed-diff", index: 7, name: "页面内全方法动态 HMAC 签名接口差分突破", category: "inpage-signed-probe", expectedFindings: 1, description: "验证提取同源动态 Nonce + HMAC-SHA256 签名逻辑对 PATCH 接口执行多角色签名差分检出越权" },
	{ id: "s08-rsc-flight-grpc-web-bola", index: 8, name: "Next.js RSC Flight 与 gRPC-Web 参数解析越权", category: "modern-protocols", expectedFindings: 2, description: "验证 RSC Flight 流协议与 gRPC-Web 5 字节帧 Protobuf 编解码及跨组织字段变异越权" },
	{ id: "s09-cross-origin-cred-pivot", index: 9, name: "跨子域/多端口凭据横向复用与 Scope 强门禁", category: "credential-pivoting", expectedFindings: 1, description: "验证授权兄弟端口检出凭据横向复用提权，同时严格阻断向未授权外部资产发送任何凭据请求" },
	{ id: "s10-confirmed-ssrf-internal-pivot", index: 10, name: "已确认 SSRF 桥接与内网隔离服务测绘分流", category: "ssrf-bridge-pivot", expectedFindings: 1, description: "验证通过已确认 SSRF 节点安全桥接测绘仅限内部网关可达的隔离微服务目录" },
	{ id: "s11-spring-rgs-standalone-pov", index: 11, name: "Spring Boot 跨文件 RGS 缺口定位与独立 PoV 实跑", category: "rgs-standalone-pov", expectedFindings: 1, description: "验证跨文件 SecurityFilterChain 抑制全局守卫假阳性、定位遗漏路由并生成零明文 PoV 脚本实跑返回 0" },
	{ id: "s12-fake200-trap-delayed-oob", index: 12, name: "Fake-200 同构陷阱熔断与延迟异步 OOB 因果归因", category: "resilience-delayed-oob", expectedFindings: 1, description: "验证识别动态随机 ID 的 Fake-200 同构诱饵实现零误报熔断，并将延迟异步回调精确归因至原注入点" },
] as const;

/** 评测专用良性合成凭据字典（全部写入 SessionVault 接受全量报告零明文泄露扫描）。 */
export const L4_SYNTHETIC_SECRETS = {
	s01AuthorBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDFfYXV0aG9yIn0.l4_s01_secret_tok_9101",
	s02AliceBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDJfYWxpY2UifQ.l4_s02_secret_tok_9102",
	s03AliceBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDNfYWxpY2UifQ.l4_s03_alice_tok_9103",
	s03BobBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDNfYm9iIn0.l4_s03_bob_tok_9104",
	s04BobWsToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDRfYm9iIiwidGVuYW50IjoidGVuYW50LWJvYiJ9.l4_s04_ws_9105",
	s05MemberBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDVfbWVtYmVyIn0.l4_s05_race_tok_9106",
	s06ExpiredJwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDZfbWVtYmVyIiwiZXhwIjoxNzAwMDAwMDAwfQ.l4_s06_expired_9107",
	s06FreshJwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDZfbWVtYmVyIiwiZXhwIjo0MTAyNDQ0ODAwfQ.l4_s06_fresh_9108",
	s06Password: "L4_Synth_Pass_#9108_Secure!",
	s06TotpSeedHex: "3132333435363738393031323334353637383930",
	s07OperatorBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDdfb3BlcmF0b3IifQ.l4_s07_op_tok_9109",
	s07AdminBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDdfYWRtaW4ifQ.l4_s07_adm_tok_9110",
	s07PageSigningKey: "l4_s07_inpage_hmac_signing_salt_887766",
	s08BetaBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDhfYmV0YSIsIm9yZyI6Im9yZy1iZXRhIn0.l4_s08_tok_9111",
	s09PortalSsoToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMDlfc3NvX3VzZXIifQ.l4_s09_sso_pivot_9112",
	s10OperatorBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMTBfb3BfMSJ9.l4_s10_ssrf_tok_9113",
	s11MemberBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMTFfbWVtYmVyIiwicm9sZSI6IlJPTEVfVVNFUiJ9.l4_s11_spring_9114",
	s11AdminBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMTFfYWRtaW4iLCJyb2xlIjoiUk9MRV9BRE1JTiJ9.l4_s11_admin_9115",
	s12JobAuthBearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzMTJfam9iX3VzZXIifQ.l4_s12_oob_tok_9116",
} as const;

export interface L4DelayedOobHit {
	id: string;
	canaryToken: string;
	contextSig: string;
	receivedAtMs: number;
	path: string;
	query: string;
}

export interface L4ScenarioServerHandle {
	scenarioId: L4ScenarioId;
	baseUrl: string;
	port: number;
	wsUrl?: string;
	peerUrl?: string;
	peerPort?: number;
	outOfScopeUrl?: string;
	outOfScopePort?: number;
	internalUrl?: string;
	internalPort?: number;
	oobCollectorUrl?: string;
	oobCollectorPort?: number;
	springVirtualFiles?: Record<string, string>;
	getOutOfScopeHits: () => number;
	getDirectInternalBlockedHits: () => number;
	getDelayedOobHits: () => L4DelayedOobHit[];
	stop: () => void;
}

// ==================== 零外部依赖标准密码学与协议编解码工具 ====================

/** 基于 node:crypto `createHash` 的标准 RFC 2104 HMAC 实现（兼容离线类型声明 `omp/env.d.ts`）。 */
export function computeRfc2104Hmac(alg: "sha256" | "sha1", key: string | Uint8Array, message: string | Uint8Array): Buffer {
	const blockSize = 64;
	let keyBuf = typeof key === "string" ? Buffer.from(key, "utf8") : Buffer.from(key);
	if (keyBuf.length > blockSize) keyBuf = createHash(alg).update(keyBuf).digest();
	const paddedKey = Buffer.alloc(blockSize, 0);
	for (let i = 0; i < keyBuf.length; i++) paddedKey[i] = keyBuf[i]!;

	const oKeyPad = Buffer.alloc(blockSize, 0);
	const iKeyPad = Buffer.alloc(blockSize, 0);
	for (let i = 0; i < blockSize; i++) {
		oKeyPad[i] = paddedKey[i]! ^ 0x5c;
		iKeyPad[i] = paddedKey[i]! ^ 0x36;
	}
	const msgBuf = typeof message === "string" ? Buffer.from(message, "utf8") : Buffer.from(message);
	const innerDigest = createHash(alg).update(Buffer.concat([iKeyPad, msgBuf])).digest();
	return createHash(alg).update(Buffer.concat([oKeyPad, innerDigest])).digest();
}

/** 计算标准 RFC 6238 6 位动态 TOTP 验证码（步长 30s，HMAC-SHA1）。 */
export function generateRfc6238Totp(seedHex: string, nowMs = Date.now(), stepSec = 30): string {
	const keyBytes = Buffer.from(seedHex, "hex");
	let counter = Math.floor(Math.floor(nowMs / 1000) / stepSec);
	const counterBuf = Buffer.alloc(8, 0);
	for (let i = 7; i >= 0; i--) {
		counterBuf[i] = counter & 0xff;
		counter = Math.floor(counter / 256);
	}
	const digest = computeRfc2104Hmac("sha1", keyBytes, counterBuf);
	const offset = digest[digest.length - 1]! & 0x0f;
	const binCode =
		((digest[offset]! & 0x7f) << 24) |
		((digest[offset + 1]! & 0xff) << 16) |
		((digest[offset + 2]! & 0xff) << 8) |
		(digest[offset + 3]! & 0xff);
	return String(binCode % 1_000_000).padStart(6, "0");
}

/** 计算场景 7 页面内抗重放动态请求签名。 */
export function computeInPageRequestSignature(
	signingKey: string,
	method: string,
	path: string,
	timestamp: string,
	nonce: string,
	bodyText: string,
): string {
	const bodySha = createHash("sha256").update(bodyText, "utf8").digest("hex");
	const canonical = `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodySha}`;
	return computeRfc2104Hmac("sha256", signingKey, canonical).toString("hex");
}

function encodeProtobufVarint(value: number): Buffer {
	const bytes: number[] = [];
	let v = value >>> 0;
	while (v >= 0x80) {
		bytes.push((v & 0x7f) | 0x80);
		v >>>= 7;
	}
	bytes.push(v & 0x7f);
	return Buffer.from(bytes);
}

function decodeProtobufVarint(buf: Uint8Array, startOffset: number): { value: number; nextOffset: number } | null {
	let value = 0;
	let shift = 0;
	let i = startOffset;
	while (i < buf.length && shift < 35) {
		const b = buf[i++]!;
		value += (b & 0x7f) * (2 ** shift);
		if ((b & 0x80) === 0) return { value, nextOffset: i };
		shift += 7;
	}
	return null;
}

/** 编码 gRPC-Web 5 字节帧 + Protobuf 消息（field 1: string orgId, field 2: varint includeAudit，支持任意 Varint 长度）。 */
export function encodeGrpcWebOrgRequest(orgId: string, includeAudit: boolean): Uint8Array {
	const strBytes = Buffer.from(orgId, "utf8");
	const protoPayload = Buffer.concat([
		Buffer.from([0x0a]),
		encodeProtobufVarint(strBytes.length),
		strBytes,
		Buffer.from([0x10, includeAudit ? 1 : 0]),
	]);
	const header = Buffer.alloc(5, 0);
	header[0] = 0x00;
	header[1] = (protoPayload.length >>> 24) & 0xff;
	header[2] = (protoPayload.length >>> 16) & 0xff;
	header[3] = (protoPayload.length >>> 8) & 0xff;
	header[4] = protoPayload.length & 0xff;
	return Buffer.concat([header, protoPayload]);
}

/** 解码 gRPC-Web 请求帧中的 Protobuf 字段（真实校验 5 字节帧头与 Base-128 Varint 长度边界）。 */
export function decodeGrpcWebOrgRequest(rawBuf: Uint8Array): { ok: boolean; orgId: string; includeAudit: boolean } {
	if (rawBuf.length < 5 || rawBuf[0] !== 0x00) return { ok: false, orgId: "", includeAudit: false };
	const frameLen = ((rawBuf[1]! << 24) >>> 0) + (rawBuf[2]! << 16) + (rawBuf[3]! << 8) + rawBuf[4]!;
	if (rawBuf.length < 5 + frameLen) return { ok: false, orgId: "", includeAudit: false };
	const msg = rawBuf.slice(5, 5 + frameLen);
	let i = 0;
	let orgId = "";
	let includeAudit = false;
	while (i < msg.length) {
		const tagVar = decodeProtobufVarint(msg, i);
		if (!tagVar) break;
		i = tagVar.nextOffset;
		const fieldNo = tagVar.value >>> 3;
		const wireType = tagVar.value & 0x07;
		if (wireType === 2) {
			const lenVar = decodeProtobufVarint(msg, i);
			if (!lenVar || lenVar.nextOffset + lenVar.value > msg.length) return { ok: false, orgId: "", includeAudit: false };
			i = lenVar.nextOffset;
			const val = Buffer.from(msg.slice(i, i + lenVar.value)).toString("utf8");
			i += lenVar.value;
			if (fieldNo === 1) orgId = val;
		} else if (wireType === 0) {
			const vVar = decodeProtobufVarint(msg, i);
			if (!vVar) break;
			i = vVar.nextOffset;
			if (fieldNo === 2) includeAudit = vVar.value !== 0;
		} else {
			break;
		}
	}
	return { ok: Boolean(orgId), orgId, includeAudit };
}

/** 构造真实 gRPC-Web Data Frame (0x00) + Trailer Frame (0x80 `grpc-status: 0`) 二进制响应（标准 Varint 长度前缀）。 */
export function encodeGrpcWebJsonFrameResponse(jsonPayload: Record<string, unknown>, grpcStatus = 0): Uint8Array {
	const jsonBytes = Buffer.from(JSON.stringify(jsonPayload), "utf8");
	const dataFrame = Buffer.concat([Buffer.from([0x0a]), encodeProtobufVarint(jsonBytes.length), jsonBytes]);
	const dataHdr = Buffer.from([
		0x00,
		(dataFrame.length >>> 24) & 0xff,
		(dataFrame.length >>> 16) & 0xff,
		(dataFrame.length >>> 8) & 0xff,
		dataFrame.length & 0xff,
	]);
	const trailerBytes = Buffer.from(`grpc-status: ${grpcStatus}\r\ngrpc-message: OK\r\n`, "utf8");
	const trailerHdr = Buffer.from([
		0x80,
		(trailerBytes.length >>> 24) & 0xff,
		(trailerBytes.length >>> 16) & 0xff,
		(trailerBytes.length >>> 8) & 0xff,
		trailerBytes.length & 0xff,
	]);
	return Buffer.concat([dataHdr, dataFrame, trailerHdr, trailerBytes]);
}

/** 解码 gRPC-Web 响应中的 Data Frame（标准 Protobuf Base-128 Varint）与 Trailer Frame 状态码。 */
export function decodeGrpcWebFrameResponse(raw: Uint8Array): { grpcStatus: number; payloadText: string } {
	let offset = 0;
	let payloadText = "";
	let grpcStatus = -1;
	while (offset + 5 <= raw.length) {
		const flag = raw[offset]!;
		const len = ((raw[offset + 1]! << 24) >>> 0) + (raw[offset + 2]! << 16) + (raw[offset + 3]! << 8) + raw[offset + 4]!;
		offset += 5;
		if (offset + len > raw.length) break;
		const chunk = raw.slice(offset, offset + len);
		offset += len;
		if (flag === 0x00) {
			if (chunk[0] === 0x0a && chunk.length >= 2) {
				const lenVar = decodeProtobufVarint(chunk, 1);
				const inner = lenVar && lenVar.nextOffset + lenVar.value <= chunk.length
					? chunk.slice(lenVar.nextOffset, lenVar.nextOffset + lenVar.value)
					: chunk.slice(2);
				payloadText = Buffer.from(inner).toString("utf8");
			} else {
				payloadText = Buffer.from(chunk).toString("utf8");
			}
		} else if (flag === 0x80) {
			const tr = Buffer.from(chunk).toString("utf8");
			const m = /grpc-status:\s*(\d+)/i.exec(tr);
			if (m) grpcStatus = Number(m[1]);
		}
	}
	return { grpcStatus, payloadText };
}

function jsonRes(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders },
	});
}

function bearerOf(req: Request): string {
	const h = (req.headers.get("authorization") ?? "").trim();
	return h.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : "";
}

function editDistance(a: string, b: string): number {
	const la = a.toLowerCase(), lb = b.toLowerCase();
	const dp: number[][] = Array.from({ length: la.length + 1 }, (_, i) =>
		Array.from({ length: lb.length + 1 }, (__, j) => (i === 0 ? j : j === 0 ? i : 0)),
	);
	for (let i = 1; i <= la.length; i++) {
		for (let j = 1; j <= lb.length; j++) {
			dp[i]![j] = la[i - 1] === lb[j - 1]
				? dp[i - 1]![j - 1]!
				: 1 + Math.min(dp[i - 1]![j - 1]!, dp[i - 1]![j]!, dp[i]![j - 1]!);
		}
	}
	return dp[la.length]![lb.length]!;
}

function baseHandle(
	scenarioId: L4ScenarioId,
	srv: { port: number; stop(closeActive?: boolean): void },
	extras?: Partial<L4ScenarioServerHandle>,
): L4ScenarioServerHandle {
	let stopped = false;
	const customStop = extras?.stop;
	return {
		scenarioId,
		baseUrl: `http://127.0.0.1:${srv.port}`,
		port: srv.port,
		getOutOfScopeHits: () => 0,
		getDirectInternalBlockedHits: () => 0,
		getDelayedOobHits: () => [],
		...extras,
		stop: () => {
			if (stopped) return;
			stopped = true;
			try { customStop?.(); } catch { /* ignore */ }
			try { srv.stop(true); } catch { /* ignore */ }
		},
	};
}

// ==================== 场景 11 跨文件 Spring Boot 源码夹具 ====================

export const S11_SPRING_BOOT_FILES: Record<string, string> = {
	"src/main/java/com/nuwa/l4/config/SecurityConfig.java": [
		"package com.nuwa.l4.config;",
		"import org.springframework.context.annotation.Bean;",
		"import org.springframework.security.config.annotation.web.builders.HttpSecurity;",
		"import org.springframework.security.web.SecurityFilterChain;",
		"public class SecurityConfig {",
		"    @Bean",
		"    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {",
		"        http.authorizeHttpRequests(reg -> reg",
		'            .requestMatchers("/healthz", "/api/v1/legacy-bridge/**").permitAll()',
		'            .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")',
		"            .anyRequest().authenticated()",
		"        );",
		"        return http.build();",
		"    }",
		"}",
	].join("\n"),
	"src/main/java/com/nuwa/l4/web/AdminUserController.java": [
		"package com.nuwa.l4.web;",
		"import org.springframework.web.bind.annotation.*;",
		"@RestController",
		'@RequestMapping("/api/v1/admin")',
		"public class AdminUserController {",
		"    // 虽无局部注解，但被 SecurityConfig /api/v1/admin/** 全局守卫保护",
		'    @GetMapping("/users")',
		"    public String listAdminUsers() { return \"ok\"; }",
		"}",
	].join("\n"),
	"src/main/java/com/nuwa/l4/web/LegacyExportController.java": [
		"package com.nuwa.l4.web;",
		"import com.nuwa.l4.service.ExportService;",
		"import org.springframework.web.bind.annotation.*;",
		"@RestController",
		'@RequestMapping("/api/v1/legacy-bridge")',
		"public class LegacyExportController {",
		"    private final ExportService exportService;",
		"    public LegacyExportController(ExportService exportService) { this.exportService = exportService; }",
		'    @GetMapping("/tenant-ledger")',
		"    public Object dumpLedger(@RequestParam String sortBy) {",
		"        return exportService.fetchLedger(sortBy);",
		"    }",
		"}",
	].join("\n"),
	"src/main/java/com/nuwa/l4/service/ExportService.java": [
		"package com.nuwa.l4.service;",
		"import com.nuwa.l4.mapper.LedgerMapper;",
		"public class ExportService {",
		"    private final LedgerMapper ledgerMapper;",
		"    public ExportService(LedgerMapper ledgerMapper) { this.ledgerMapper = ledgerMapper; }",
		"    public Object fetchLedger(String orderCol) {",
		"        return ledgerMapper.queryLedgerRaw(orderCol);",
		"    }",
		"}",
	].join("\n"),
	"src/main/resources/mapper/LedgerMapper.xml": [
		'<?xml version="1.0" encoding="UTF-8" ?>',
		'<mapper namespace="com.nuwa.l4.mapper.LedgerMapper">',
		'    <select id="queryLedgerRaw" resultType="map">',
		"        SELECT id, dept, total_amount FROM tenant_ledger ORDER BY ${orderCol} DESC",
		"    </select>",
		"</mapper>",
	].join("\n"),
};

// ==================== 12 个真实有状态靶场工厂实现 ====================

export function startL4ScenarioServer(scenarioId: L4ScenarioId): L4ScenarioServerHandle {
	switch (scenarioId) {
		case "s01-second-order-store-read": {
			const profiles = new Map<string, { displayName: string; headerTemplate: string; owner: string }>();
			let seq = 100;
			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s01AuthorBearer) {
						return jsonRes({ error: "unauthorized" }, 401);
					}
					if (u.pathname === "/api/v1/profiles/preferences" && req.method === "POST") {
						const body = (await req.json()) as { displayName?: string; headerTemplate?: string };
						const profileId = `prof-${++seq}`;
						profiles.set(profileId, {
							displayName: String(body.displayName ?? "default"),
							headerTemplate: String(body.headerTemplate ?? "Report Header"),
							owner: "s01_author",
						});
						// 一阶写入仅返回盲保存回执，无任何直接敏感回显
						return jsonRes({ saved: true, profileId }, 201);
					}
					if (u.pathname.startsWith("/api/v1/profiles/preferences/") && req.method === "DELETE") {
						const pid = u.pathname.split("/").pop() ?? "";
						const deleted = profiles.delete(pid);
						return jsonRes({ deleted, profileId: pid });
					}
					if (u.pathname === "/api/v1/reports/preview" && req.method === "GET") {
						const pid = u.searchParams.get("profileId") ?? "";
						const rec = profiles.get(pid);
						if (!rec) return jsonRes({ error: "profile_not_found" }, 404);
						// 二阶读取：当存储字段包含内部上下文插值引用时，渲染引擎未隔离系统上下文变量
						const renderedHeader = rec.headerTemplate.replace(
							/\{\{\s*sys\.cluster_audit_marker\s*\}\}/g,
							"CLUSTER_AUDIT_MARKER_L4_S01_CONFIRMED",
						);
						return jsonRes({
							profileId: pid,
							renderedHeader,
							activeProfilesCount: profiles.size,
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s02-mass-assignment-priv-esc": {
			const userState = {
				userId: "u-alice",
				displayName: "Alice Standard",
				department: "engineering",
				orgRole: "viewer",
				exportPrivilege: false,
			};
			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s02AliceBearer) {
						return jsonRes({ error: "unauthorized" }, 401);
					}
					if (u.pathname === "/api/v1/users/me/profile" && req.method === "GET") {
						return jsonRes({ ...userState });
					}
					if (u.pathname === "/api/v1/users/me/profile" && (req.method === "PATCH" || req.method === "POST")) {
						const patch = (await req.json()) as Record<string, unknown>;
						// 缺陷：直接将未白名单过滤的 JSON 字段合并至持久用户模型（Mass Assignment）
						for (const [k, v] of Object.entries(patch)) {
							if (k in userState && (typeof v === "string" || typeof v === "boolean")) {
								(userState as Record<string, unknown>)[k] = v;
							}
						}
						return jsonRes({ updated: true, profile: { ...userState } });
					}
					if (u.pathname === "/api/v1/org/audit-export" && req.method === "GET") {
						if (userState.orgRole !== "org_owner" && !userState.exportPrivilege) {
							return jsonRes({ error: "forbidden", requiredRole: "org_owner", currentRole: userState.orgRole }, 403);
						}
						return jsonRes({
							exportBatch: "org-audit-2026-l4-s02",
							effectiveRole: userState.orgRole,
							records: [{ id: "aud-1", scope: "enterprise-wide-compliance" }],
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s03-graphql-blind-schema-bola": {
			const rootFields = ["currentViewer", "tenantWorkspace", "systemVersion"];
			const workspaceSubFields = ["id", "ownerTenant", "planName", "apiKeyMetadata"];
			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (u.pathname !== "/graphql" || req.method !== "POST") return jsonRes({ error: "not_found" }, 404);

					const tok = bearerOf(req);
					const caller = tok === L4_SYNTHETIC_SECRETS.s03AliceBearer ? "tenant-alice" : tok === L4_SYNTHETIC_SECRETS.s03BobBearer ? "tenant-bob" : null;
					if (!caller) return jsonRes({ errors: [{ message: "Authentication required" }] }, 401);

					const payload = (await req.json()) as { query?: string; variables?: Record<string, unknown> };
					const q = String(payload.query ?? "").trim();

					// 严格禁止内省
					if (/\b__(?:schema|type)\b/.test(q)) {
						return jsonRes({ errors: [{ message: "GraphQL introspection is disabled by policy" }] }, 400);
					}

					// 提取顶层请求字段
					const outerBody = /\{([\s\S]*)\}/.exec(q)?.[1]?.trim() ?? "";
					const rootFieldMatch = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(outerBody);
					const reqRoot = rootFieldMatch?.[1] ?? "";
					if (!rootFields.includes(reqRoot)) {
						const suggestions = rootFields.filter((cand) => cand.toLowerCase().includes(reqRoot.toLowerCase().slice(0, 4)) || editDistance(reqRoot, cand) <= 8);
						const hint = suggestions.length > 0 ? ` Did you mean "${suggestions.join('", "')}"?` : "";
						return jsonRes({ errors: [{ message: `Cannot query field "${reqRoot}" on type "Query".${hint}` }] }, 400);
					}

					if (reqRoot === "tenantWorkspace") {
						const argId =
							/\bid\s*:\s*"([^"]+)"/.exec(outerBody)?.[1] ??
							(typeof payload.variables?.id === "string" ? payload.variables.id : "");
						if (!argId) {
							return jsonRes({ errors: [{ message: 'Field "tenantWorkspace" argument "id" of type "ID!" is required.' }] }, 400);
						}
						const innerBraceIdx = outerBody.indexOf("{");
						const innerFieldsRaw = innerBraceIdx >= 0 ? outerBody.slice(innerBraceIdx + 1, outerBody.lastIndexOf("}")) : "";
						const subTokens = [...innerFieldsRaw.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g)].map((m) => m[1]!);
						const allowedNested = new Set([...workspaceSubFields, "keyId", "maskedKey", "scopeTier"]);
						for (const st of subTokens) {
							if (!allowedNested.has(st)) {
								const sug = workspaceSubFields.filter((c) => c.toLowerCase().includes(st.toLowerCase().slice(0, 3)) || editDistance(st, c) <= 9);
								const hint = sug.length > 0 ? ` Did you mean "${sug.join('", "')}"?` : "";
								return jsonRes({ errors: [{ message: `Cannot query field "${st}" on type "TenantWorkspace".${hint}` }] }, 400);
							}
						}
						// 嵌套对象级越权缺陷（BOLA）：未校验 caller 是否等于 ws-alpha 的属主 tenant-alice
						if (argId === "ws-alpha") {
							return jsonRes({
								data: {
									tenantWorkspace: {
										id: "ws-alpha",
										ownerTenant: "tenant-alice",
										planName: "enterprise-isolated",
										apiKeyMetadata: [{ keyId: "ak-alpha-01", maskedKey: "ak_live_***99a", scopeTier: "root-billing-admin" }],
									},
								},
							});
						}
						return jsonRes({
							data: {
								tenantWorkspace: {
									id: argId,
									ownerTenant: "tenant-bob",
									planName: "starter",
									apiKeyMetadata: [],
								},
							},
						});
					}

					return jsonRes({ data: { [reqRoot]: "v8.0-l4" } });
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s04-websocket-tenant-leak": {
			interface WsClientData { tenantId: string; subscriptions: Set<string> }
			const clients = new Set<{ data: WsClientData; send(msg: string): void; close(): void }>();

			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request, server: any): Promise<Response | undefined> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (u.pathname === "/ws/events") {
						const tok = u.searchParams.get("token") ?? bearerOf(req);
						if (tok !== L4_SYNTHETIC_SECRETS.s04BobWsToken) {
							return jsonRes({ error: "ws_unauthorized" }, 401);
						}
						const upgraded = server.upgrade(req, {
							data: { tenantId: "tenant-bob", subscriptions: new Set<string>() },
						});
						if (upgraded) return undefined;
						return jsonRes({ error: "upgrade_failed" }, 400);
					}
					if (u.pathname === "/api/v1/events/trigger-settlement" && req.method === "POST") {
						const body = (await req.json()) as { targetTenant?: string };
						const targetTenant = body.targetTenant ?? "tenant-alpha";
						const channel = `tenant:${targetTenant}:settlements`;
						const eventMsg = JSON.stringify({
							type: "settlement_push",
							channel,
							ownerTenant: targetTenant,
							batchRef: "STL-ALPHA-2026-L4S04",
							amountCents: 985000,
						});
						let delivered = 0;
						for (const ws of clients) {
							if (ws.data.subscriptions.has(channel)) {
								ws.send(eventMsg);
								delivered++;
							}
						}
						return jsonRes({ published: true, channel, delivered });
					}
					return jsonRes({ error: "not_found" }, 404);
				},
				websocket: {
					open(ws: any) {
						clients.add(ws);
					},
					message(ws: any, rawMsg: string | Uint8Array) {
						try {
							const text = typeof rawMsg === "string" ? rawMsg : Buffer.from(rawMsg).toString("utf8");
							const parsed = JSON.parse(text) as { action?: string; channel?: string };
							if (parsed.action === "subscribe" && typeof parsed.channel === "string") {
								// 缺陷：仅在连接升级时验证了登录态，订阅任意 tenant:<other>:settlements 频道未做租户归属校验
								ws.data.subscriptions.add(parsed.channel);
								ws.send(JSON.stringify({ type: "subscribed_ack", channel: parsed.channel, callerTenant: ws.data.tenantId }));
							}
						} catch {
							ws.send(JSON.stringify({ type: "error", message: "invalid_frame" }));
						}
					},
					close(ws: any) {
						clients.delete(ws);
					},
				},
			});
			return baseHandle(scenarioId, srv, {
				wsUrl: `ws://127.0.0.1:${srv.port}/ws/events`,
				stop: () => {
					for (const c of clients) {
						try { c.close(); } catch { /* ignore */ }
					}
					clients.clear();
				},
			});
		}

		case "s05-barrier-race-toctou": {
			let vulnBalance = 100;
			let lockedBalance = 100;
			let mutexBusy = false;
			let receiptSeq = 0;

			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s05MemberBearer) return jsonRes({ error: "unauthorized" }, 401);

					if (u.pathname === "/api/v1/vouchers/state" && req.method === "GET") {
						return jsonRes({ vulnBalance, lockedBalance });
					}
					if (u.pathname === "/api/v1/vouchers/reset" && req.method === "POST") {
						vulnBalance = 100;
						lockedBalance = 100;
						return jsonRes({ reset: true, vulnBalance, lockedBalance });
					}
					// 加固互斥对照端点：并发下严格仅允许 1 次扣款成功，用于校验评估器零误报
					if (u.pathname === "/api/v1/vouchers/redeem-locked" && req.method === "POST") {
						while (mutexBusy) await Bun.sleep(2);
						mutexBusy = true;
						try {
							if (lockedBalance < 100) return jsonRes({ error: "insufficient_balance", remaining: lockedBalance }, 409);
							await Bun.sleep(15);
							lockedBalance -= 100;
							return jsonRes({ redeemed: true, receiptId: `LOCKED-${++receiptSeq}`, remaining: lockedBalance });
						} finally {
							mutexBusy = false;
						}
					}
					// 存在 TOCTOU 竞争窗口的兑换端点：Check 与扣减之间存在异步账本延迟且无行锁
					if (u.pathname === "/api/v1/vouchers/redeem" && req.method === "POST") {
						const observed = vulnBalance;
						if (observed < 100) {
							return jsonRes({ error: "insufficient_balance", remaining: observed }, 409);
						}
						await Bun.sleep(25);
						vulnBalance = observed - 100;
						return jsonRes({
							redeemed: true,
							receiptId: `RACE-RCPT-${++receiptSeq}`,
							deducted: 100,
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s06-short-jwt-401-reauth": {
			const pendingLoginSessions = new Map<string, { csrf: string; step1Passed: boolean }>();
			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });

					if (u.pathname === "/auth/login" && req.method === "GET") {
						const loginSid = `lsid_${randomBytes(6).toString("hex")}`;
						const csrf = `csrf_${randomBytes(6).toString("hex")}`;
						pendingLoginSessions.set(loginSid, { csrf, step1Passed: false });
						return new Response(
							`<!doctype html><html><body><form id="loginForm"><input name="_csrf" value="${csrf}"/></form></body></html>`,
							{
								status: 200,
								headers: { "Content-Type": "text/html", "Set-Cookie": `l4_login_sid=${loginSid}; Path=/; HttpOnly` },
							},
						);
					}
					if (u.pathname === "/auth/login/step1" && req.method === "POST") {
						const cookieHdr = req.headers.get("cookie") ?? "";
						const sid = /l4_login_sid=([A-Za-z0-9_]+)/.exec(cookieHdr)?.[1] ?? "";
						const sess = pendingLoginSessions.get(sid);
						const body = (await req.json()) as { username?: string; password?: string; csrf?: string };
						if (!sess || body.csrf !== sess.csrf || body.username !== "s06_member" || body.password !== L4_SYNTHETIC_SECRETS.s06Password) {
							return jsonRes({ error: "invalid_credentials_or_csrf" }, 401);
						}
						sess.step1Passed = true;
						return jsonRes({ mfaRequired: true, mfaType: "totp-rfc6238" });
					}
					if (u.pathname === "/auth/login/totp" && req.method === "POST") {
						const cookieHdr = req.headers.get("cookie") ?? "";
						const sid = /l4_login_sid=([A-Za-z0-9_]+)/.exec(cookieHdr)?.[1] ?? "";
						const sess = pendingLoginSessions.get(sid);
						const body = (await req.json()) as { totpCode?: string };
						if (!sess?.step1Passed) return jsonRes({ error: "step1_incomplete" }, 401);
						const nowMs = Date.now();
						const validCodes = new Set([
							generateRfc6238Totp(L4_SYNTHETIC_SECRETS.s06TotpSeedHex, nowMs - 30_000),
							generateRfc6238Totp(L4_SYNTHETIC_SECRETS.s06TotpSeedHex, nowMs),
							generateRfc6238Totp(L4_SYNTHETIC_SECRETS.s06TotpSeedHex, nowMs + 30_000),
						]);
						if (!body.totpCode || !validCodes.has(body.totpCode.trim())) {
							return jsonRes({ error: "invalid_totp_code" }, 401);
						}
						pendingLoginSessions.delete(sid);
						return jsonRes({ accessToken: L4_SYNTHETIC_SECRETS.s06FreshJwt, expiresIn: 3600 });
					}

					if (u.pathname === "/api/v1/ledger/statements/2026-q4") {
						const tok = bearerOf(req);
						if (!tok || tok === L4_SYNTHETIC_SECRETS.s06ExpiredJwt) {
							return jsonRes({ error: "token_expired", message: "JWT expired, interactive re-authentication required" }, 401);
						}
						if (tok !== L4_SYNTHETIC_SECRETS.s06FreshJwt) {
							return jsonRes({ error: "invalid_token" }, 401);
						}
						// 续期拿到新鲜令牌后暴露水平越权（s06_member 读取属主 cfo_office 的财务报表）
						return jsonRes({
							statementId: "stmt-2026-q4",
							ownerRole: "cfo_office",
							reserveSummary: "L4_S06_REAUTH_BOLA_CONFIRMED",
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s07-inpage-hmac-signed-diff": {
			const usedNonces = new Set<string>();
			let requireDualApproval = true;

			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (u.pathname === "/app/treasury.js" && req.method === "GET") {
						return new Response(
							[
								"// 同源前端签名运行时钩子",
								`window.__TREASURY_SIGN_KEY__ = "${L4_SYNTHETIC_SECRETS.s07PageSigningKey}";`,
								"// Canonical: METHOD\\nPATH\\nX-Timestamp\\nX-Nonce\\nSHA256(BODY)",
								"export const ENDPOINTS = ['/api/v2/treasury/approval-policy', '/api/v2/treasury/vault-master-rotate'];",
							].join("\n"),
							{ status: 200, headers: { "Content-Type": "application/javascript" } },
						);
					}

					if (u.pathname.startsWith("/api/v2/treasury/")) {
						const tok = bearerOf(req);
						const role = tok === L4_SYNTHETIC_SECRETS.s07AdminBearer ? "treasury_admin" : tok === L4_SYNTHETIC_SECRETS.s07OperatorBearer ? "operator" : null;
						if (!role) return jsonRes({ error: "unauthorized" }, 401);

						const ts = (req.headers.get("x-timestamp") ?? "").trim();
						const nonce = (req.headers.get("x-nonce") ?? "").trim();
						const sig = (req.headers.get("x-client-sig") ?? "").trim();
						const rawBody = req.method === "GET" || req.method === "HEAD" ? "" : await req.text();

						if (!ts || !nonce || !sig || usedNonces.has(nonce)) {
							return jsonRes({ error: "invalid_or_replayed_signature" }, 403);
						}
						const expectedSig = computeInPageRequestSignature(
							L4_SYNTHETIC_SECRETS.s07PageSigningKey,
							req.method,
							u.pathname,
							ts,
							nonce,
							rawBody,
						);
						if (sig !== expectedSig) {
							return jsonRes({ error: "hmac_signature_mismatch" }, 403);
						}
						usedNonces.add(nonce);

						if (u.pathname === "/api/v2/treasury/vault-master-rotate") {
							if (role !== "treasury_admin") return jsonRes({ error: "admin_only" }, 403);
							return jsonRes({ rotated: true });
						}
						if (u.pathname === "/api/v2/treasury/approval-policy" && req.method === "PATCH") {
							// 缺陷：通过页面级动态 HMAC 签名校验后，PATCH 审批策略接口漏检 treasury_admin 角色
							const parsed = JSON.parse(rawBody || "{}") as { requireDualApproval?: boolean };
							if (typeof parsed.requireDualApproval === "boolean") requireDualApproval = parsed.requireDualApproval;
							return jsonRes({
								updatedByRole: role,
								requireDualApproval,
								policyAuditTag: "L4_S07_SIGNED_PATCH_BFLA_CONFIRMED",
							});
						}
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s08-rsc-flight-grpc-web-bola": {
			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });
					if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s08BetaBearer) {
						return jsonRes({ error: "unauthorized" }, 401);
					}

					// 协议 1: Next.js RSC Server Action Flight 流协议
					if (u.pathname === "/_rsc/action" && req.method === "POST") {
						const actionId = (req.headers.get("next-action") ?? "").trim();
						if (actionId !== "act_fetch_org_billing_7f2c") {
							return jsonRes({ error: "unknown_server_action" }, 400);
						}
						const text = await req.text();
						const lineMatch = /^0:(\[[\s\S]+\])$/m.exec(text.trim());
						if (!lineMatch) return jsonRes({ error: "malformed_rsc_flight_payload" }, 400);
						const arr = JSON.parse(lineMatch[1]!) as Array<{ orgId?: string }>;
						const targetOrg = arr.find((x) => x && typeof x === "object" && "orgId" in x)?.orgId ?? "";
						// 缺陷：未校验调用者所属 org-beta 与 Flight 参数 orgId 一致性
						const flightOut = [
							`0:{"action":"${actionId}","status":"resolved"}`,
							`1:${JSON.stringify({
								orgId: targetOrg,
								ownerOrg: targetOrg === "org-alpha" ? "enterprise-alpha" : "beta",
								rscBillingSecretTag: targetOrg === "org-alpha" ? "RSC_FLIGHT_ALPHA_BOLA_L4S08" : "self",
							})}`,
						].join("\n");
						return new Response(flightOut, {
							status: 200,
							headers: { "Content-Type": "text/x-component; charset=utf-8" },
						});
					}

					// 协议 2: gRPC-Web 5 字节帧 + Protobuf 二进制协议
					if (u.pathname === "/nuwa.l4.OrgService/GetOrgSecretMeta" && req.method === "POST") {
						const ct = (req.headers.get("content-type") ?? "").toLowerCase();
						if (!ct.includes("application/grpc-web")) {
							return jsonRes({ error: "unsupported_media_type" }, 415);
						}
						const rawBytes = new Uint8Array(await req.arrayBuffer());
						const decoded = decodeGrpcWebOrgRequest(rawBytes);
						if (!decoded.ok) {
							const errFrame = encodeGrpcWebJsonFrameResponse({ error: "invalid_protobuf" }, 3);
							return new Response(errFrame.slice().buffer as ArrayBuffer, {
								status: 200,
								headers: { "Content-Type": "application/grpc-web+proto" },
							});
						}
						const frameOut = encodeGrpcWebJsonFrameResponse(
							{
								orgId: decoded.orgId,
								includeAudit: decoded.includeAudit,
								grpcSecretMarker: decoded.orgId === "org-alpha" ? "GRPC_WEB_ALPHA_BOLA_L4S08" : "beta-normal",
							},
							0,
						);
						return new Response(frameOut.slice().buffer as ArrayBuffer, {
							status: 200,
							headers: { "Content-Type": "application/grpc-web+proto" },
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});
			return baseHandle(scenarioId, srv);
		}

		case "s09-cross-origin-cred-pivot": {
			let outOfScopeHits = 0;

			// 1. 未授权外部资产对照服务（用于硬性验证凭据横向复用引擎严格执行 Scope 阻断，请求计数必须 === 0）
			const outOfScopeSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(): Response {
					outOfScopeHits++;
					return jsonRes({ warning: "OUT_OF_SCOPE_ASSET_TOUCHED" });
				},
			});

			// 2. 授权范围内的兄弟端口管理节点（信任同一 SSO 令牌但漏检管理角色）
			const peerSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(req: Request): Response {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", node: "staging-admin-peer" });
					if (u.pathname === "/api/internal/cluster-keys") {
						if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s09PortalSsoToken) {
							return jsonRes({ error: "unauthorized" }, 401);
						}
						return jsonRes({
							service: "staging-admin-peer",
							acceptedPivotToken: true,
							clusterKeyRef: "PIVOT_CLUSTER_KEY_L4_S09_CONFIRMED",
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});

			// 3. 主门户服务（仅具备普通个人资料权限）
			const portalSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(req: Request): Response {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", node: "main-portal" });
					if (u.pathname === "/api/v1/portal/me") {
						if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s09PortalSsoToken) return jsonRes({ error: "unauthorized" }, 401);
						return jsonRes({ user: "s09_sso_user", portalRole: "member" });
					}
					if (u.pathname === "/api/internal/cluster-keys") {
						return jsonRes({ error: "forbidden_on_main_portal" }, 403);
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});

			return baseHandle(scenarioId, portalSrv, {
				peerUrl: `http://127.0.0.1:${peerSrv.port}`,
				peerPort: peerSrv.port,
				outOfScopeUrl: `http://localhost:${outOfScopeSrv.port}`,
				outOfScopePort: outOfScopeSrv.port,
				getOutOfScopeHits: () => outOfScopeHits,
				stop: () => {
					peerSrv.stop(true);
					outOfScopeSrv.stop(true);
				},
			});
		}

		case "s10-confirmed-ssrf-internal-pivot": {
			let directInternalBlockedHits = 0;
			const internalBridgeSecret = `edge_bridge_${randomBytes(8).toString("hex")}`;

			// 内网隔离微服务（仅信任来自边界网关的桥接请求，直接外部访问一律返回 403）
			const internalSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(req: Request): Response {
					const u = new URL(req.url);
					if (req.headers.get("x-edge-mesh-hop") !== internalBridgeSecret) {
						directInternalBlockedHits++;
						return jsonRes({ error: "isolated_mesh_only" }, 403);
					}
					if (u.pathname === "/internal/v1/service-catalog") {
						return jsonRes({
							meshZone: "isolated-core-tier",
							services: ["settlement-ledger-grpc", "kms-signer-internal"],
							discoveryMarker: "SSRF_MESH_CATALOG_L4_S10_CONFIRMED",
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});

			// 边界网关（存在受控回环 SSRF 预览转发端点，安全护栏仅允许访问本场景 internalSrv.port）
			const edgeSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", node: "edge-gateway" });
					if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s10OperatorBearer) return jsonRes({ error: "unauthorized" }, 401);

					if (u.pathname === "/api/v1/proxy/preview" && req.method === "GET") {
						const upstream = (u.searchParams.get("upstream") ?? "").trim();
						let parsed: URL;
						try { parsed = new URL(upstream); } catch { return jsonRes({ error: "invalid_upstream" }, 400); }
						if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || Number(parsed.port) !== internalSrv.port) {
							return jsonRes({ error: "sandbox_guard_blocked_external_target" }, 400);
						}
						const proxied = await fetch(parsed.toString(), {
							headers: { "X-Edge-Mesh-Hop": internalBridgeSecret },
						});
						const bodyText = await proxied.text();
						return new Response(bodyText, {
							status: proxied.status,
							headers: { "Content-Type": "application/json", "X-Proxied-Via": "edge-preview" },
						});
					}
					return jsonRes({ error: "not_found" }, 404);
				},
			});

			return baseHandle(scenarioId, edgeSrv, {
				internalUrl: `http://127.0.0.1:${internalSrv.port}`,
				internalPort: internalSrv.port,
				getDirectInternalBlockedHits: () => directInternalBlockedHits,
				stop: () => internalSrv.stop(true),
			});
		}

		case "s11-spring-rgs-standalone-pov": {
			const srv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(req: Request): Response {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "UP", framework: "spring-boot-sim" });
					const tok = bearerOf(req);
					const isAdmin = tok === L4_SYNTHETIC_SECRETS.s11AdminBearer;
					const isMember = tok === L4_SYNTHETIC_SECRETS.s11MemberBearer;

					// 对应 AdminUserController + SecurityConfig `.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")`
					if (u.pathname === "/api/v1/admin/users") {
						if (!isAdmin && !isMember) return jsonRes({ error: "Unauthorized" }, 401);
						if (!isAdmin) return jsonRes({ error: "Forbidden", requiredRole: "ROLE_ADMIN" }, 403);
						return jsonRes({ users: ["admin"] });
					}
					// 对应 LegacyExportController 落入 SecurityConfig `.requestMatchers("/api/v1/legacy-bridge/**").permitAll()` 缺口
					if (u.pathname === "/api/v1/legacy-bridge/tenant-ledger") {
						const sortBy = u.searchParams.get("sortBy") ?? "id";
						return jsonRes({
							controller: "LegacyExportController",
							sortApplied: sortBy,
							ledgerRows: [{ id: 1, dept: "treasury", total_amount: 420000 }],
							auditMarker: "SPRING_RGS_POV_L4_S11_CONFIRMED",
						});
					}
					return jsonRes({ error: "Not Found", status: 404 }, 404);
				},
			});
			return baseHandle(scenarioId, srv, { springVirtualFiles: S11_SPRING_BOOT_FILES });
		}

		case "s12-fake200-trap-delayed-oob": {
			const oobHits: L4DelayedOobHit[] = [];
			const activeTimers = new Set<ReturnType<typeof setTimeout>>();

			// 本机 127.0.0.1:0 延迟 OOB 回调接收监听器
			const oobSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				fetch(req: Request): Response {
					const u = new URL(req.url);
					if (u.pathname === "/oob/events") {
						return jsonRes({ hits: oobHits });
					}
					const canaryToken = u.pathname.replace(/^\/cb\//, "").trim();
					const contextSig = u.searchParams.get("sig") ?? "";
					const hit: L4DelayedOobHit = {
						id: `oob-hit-${oobHits.length + 1}`,
						canaryToken,
						contextSig,
						receivedAtMs: Date.now(),
						path: u.pathname,
						query: u.search,
					};
					oobHits.push(hit);
					return jsonRes({ received: true, id: hit.id });
				},
			});

			const mainSrv = Bun.serve({
				hostname: "127.0.0.1",
				port: 0,
				async fetch(req: Request): Promise<Response> {
					const u = new URL(req.url);
					if (u.pathname === "/healthz") return jsonRes({ status: "ok", scenario: scenarioId });

					// 异步延迟 Webhook 校验任务接口（立即返回盲 202，延迟 45ms 后在后台向本机 OOB 接收器发起回调）
					if (u.pathname === "/api/v1/jobs/webhook-verify" && req.method === "POST") {
						if (bearerOf(req) !== L4_SYNTHETIC_SECRETS.s12JobAuthBearer) {
							return jsonRes({ error: "unauthorized" }, 401);
						}
						const body = (await req.json()) as { webhookUrl?: string };
						const webhookUrl = String(body.webhookUrl ?? "").trim();
						let parsed: URL;
						try { parsed = new URL(webhookUrl); } catch { return jsonRes({ error: "invalid_url" }, 400); }
						if (parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || Number(parsed.port) !== oobSrv.port) {
							return jsonRes({ error: "loopback_oob_collector_only" }, 400);
						}
						const targetStr = parsed.toString();
						const timer = setTimeout(() => {
							activeTimers.delete(timer);
							fetch(targetStr).catch(() => {});
						}, 45);
						activeTimers.add(timer);
						return jsonRes({ queued: true, note: "Verification scheduled asynchronously" }, 202);
					}

					// Fake-200 同构欺骗陷阱：对任意未知探测路径（如 /.env, /admin/config, /backup.sql, /trap/*）一律返回带随机 reqId 的同构 200 JSON
					return jsonRes({
						status: "ok",
						environment: "production-decoy",
						module: "deception-honeypot-shell",
						hint: "admin_debug_enabled",
						reqId: randomBytes(8).toString("hex"),
					}, 200);
				},
			});

			return baseHandle(scenarioId, mainSrv, {
				oobCollectorUrl: `http://127.0.0.1:${oobSrv.port}`,
				oobCollectorPort: oobSrv.port,
				getDelayedOobHits: () => [...oobHits],
				stop: () => {
					for (const t of activeTimers) clearTimeout(t);
					activeTimers.clear();
					oobSrv.stop(true);
				},
			});
		}
	}
}
