import { describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import {
	L4_SCENARIO_SPECS,
	computeRfc2104Hmac,
	decodeGrpcWebFrameResponse,
	decodeGrpcWebOrgRequest,
	encodeGrpcWebJsonFrameResponse,
	encodeGrpcWebOrgRequest,
	generateRfc6238Totp,
	startL4ScenarioServer,
} from "../benchmarks/l4-arena/servers";
import { parseL4CliArgs, runL4BenchmarkSuite } from "../benchmarks/l4-arena/run-l4-eval";

describe("v8 L4 真实有状态 12 场景综合演武场 (benchmarks/l4-arena)", () => {
	test("CLI 参数解析器支持 --json / --deterministic / --scenario / --help 并拦截未知参数", () => {
		expect(parseL4CliArgs(["--json", "--deterministic"])).toEqual({
			json: true,
			deterministic: true,
			scenario: undefined,
			help: false,
		});
		expect(parseL4CliArgs(["--scenario", "s11-spring-rgs-standalone-pov"])).toEqual({
			json: false,
			deterministic: false,
			scenario: "s11-spring-rgs-standalone-pov",
			help: false,
		});
		expect(parseL4CliArgs(["--scenario=s04-websocket-tenant-leak", "-h"])).toEqual({
			json: false,
			deterministic: false,
			scenario: "s04-websocket-tenant-leak",
			help: true,
		});
		expect(() => parseL4CliArgs(["--unknown-flag"])).toThrow(/未知命令行参数/);
		expect(() => parseL4CliArgs(["--scenario"])).toThrow(/需要传入场景 ID/);
	});

	test("RFC 6238 TOTP 标准测试向量与 gRPC-Web 5 字节帧 Protobuf 往返编解码准确无误", () => {
		// RFC 6238 Appendix B 标准 SHA1 测试向量：T = 59s -> 287082 (8位末6位为 287082)
		const rfcSeedHex = "3132333435363738393031323334353637383930";
		expect(generateRfc6238Totp(rfcSeedHex, 59_000, 30)).toBe("287082");

		const hmacHex = computeRfc2104Hmac("sha256", "key", "The quick brown fox jumps over the lazy dog").toString("hex");
		expect(hmacHex).toBe("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");

		const reqBytes = encodeGrpcWebOrgRequest("org-alpha", true);
		expect(reqBytes[0]).toBe(0x00);
		const decodedReq = decodeGrpcWebOrgRequest(reqBytes);
		expect(decodedReq).toEqual({ ok: true, orgId: "org-alpha", includeAudit: true });
		expect(decodeGrpcWebOrgRequest(new Uint8Array([0x01, 0x00]))).toEqual({
			ok: false,
			orgId: "",
			includeAudit: false,
		});

		const respBytes = encodeGrpcWebJsonFrameResponse({ orgId: "org-alpha", marker: "ok" }, 0);
		const decodedResp = decodeGrpcWebFrameResponse(respBytes);
		expect(decodedResp.grpcStatus).toBe(0);
		expect(JSON.parse(decodedResp.payloadText)).toEqual({ orgId: "org-alpha", marker: "ok" });
	});

	test("多端口场景服务绑定 127.0.0.1:0 且 stop() 后零孤儿端口残留", async () => {
		expect(L4_SCENARIO_SPECS.length).toBe(12);
		const srv = startL4ScenarioServer("s09-cross-origin-cred-pivot");
		const mainHealthUrl = `${srv.baseUrl}/healthz`;
		const peerHealthUrl = `${srv.peerUrl}/healthz`;

		try {
			expect(srv.port).toBeGreaterThan(0);
			expect(srv.peerPort).toBeGreaterThan(0);
			expect(srv.outOfScopePort).toBeGreaterThan(0);
			const r1 = await fetch(mainHealthUrl);
			const r2 = await fetch(peerHealthUrl);
			expect(r1.status).toBe(200);
			expect(r2.status).toBe(200);
		} finally {
			srv.stop();
		}

		// 验证 stop() 后端口立即释放不可再连接
		let closedMain = false;
		try {
			await fetch(mainHealthUrl);
		} catch {
			closedMain = true;
		}
		expect(closedMain).toBe(true);
	});

	test("全量 12 场景 L4 综合演武场套件端到端闭环 12/12 全绿通过硬门禁", async () => {
		const summary = await runL4BenchmarkSuite({ deterministic: true });

		expect(summary.totalScenarios).toBe(12);
		expect(summary.passedScenarios).toBe(12);
		expect(summary.recallRate).toBe(1);
		expect(summary.falsePositiveRate).toBe(0);
		expect(summary.vaultLeakCount).toBe(0);
		expect(summary.allPassed).toBe(true);
		expect(summary.gates.allPassed).toBe(true);
		expect(summary.metrics.standalonePovExitZero).toBe(true);
		expect(summary.metrics.outOfScopeLeakRequests).toBe(0);

		for (const sc of summary.scenarios) {
			expect(sc.passed).toBe(true);
			expect(sc.falsePositives).toBe(0);
			expect(sc.vaultLeaks).toBe(0);
		}
	}, 30_000);

	test("CLI 子进程执行 --json --deterministic 返回退出码 0 且 JSON 硬门禁成立", async () => {
		const cliScript = resolve(import.meta.dir, "../benchmarks/l4-arena/run-l4-eval.ts");
		const proc = Bun.spawn(["bun", cliScript, "--json", "--deterministic"], {
			env: { ...process.env, BUN_OPTIONS: undefined },
			stdout: "pipe",
			stderr: "pipe",
		});
		const exitCode = await proc.exited;
		const stdoutText = await new Response(proc.stdout).text();
		expect(exitCode).toBe(0);

		const parsed = JSON.parse(stdoutText);
		expect(
			parsed.allPassed === true &&
				parsed.passedScenarios === 12 &&
				parsed.recallRate === 1 &&
				parsed.falsePositiveRate === 0 &&
				parsed.vaultLeakCount === 0,
		).toBe(true);
	}, 30_000);
});
