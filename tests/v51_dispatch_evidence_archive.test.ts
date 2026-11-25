/**
 * 女娲 v5.1 派单守卫、证据门禁与归档检索全量单元测试
 * 覆盖 GitHub Issues: #24 (NW-04), #26 (NW-06), #27 (NW-07), #28 (NW-08),
 *                    #39 (NW-19), #42 (NW-22), #50 (NW-30), #51 (NW-31), #52 (NW-32)
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { NuwaState } from "../omp/types";
import {
	REQUIRED_CURL_WRITE_OUT,
	computeBodyHash,
	evaluatePositiveEvidenceGate,
	extractHitEvidenceMetrics,
	isTinyErrorEnvelope,
	parseAgentResult,
	readFactEvidenceLog,
	recordToolExecution,
	saveFactEvidenceLog,
	validateDeliverableRealism,
	validateHitEvidenceFields,
	verifyExecutionEvidence,
} from "../omp/evidence";
import {
	buildDoubleBlindVerifyIntentSpec,
	buildFalsePositiveNote,
	resolveVerificationOutcome,
	validateVerificationCommit,
	verifyPositiveConclusion,
	type VerifiableFact,
} from "../omp/verifier-gate";
import {
	DEFAULT_BATCH_MAX_BYTES,
	DispatchReceiptRegistry,
	InflightTargetRegistry,
	buildDispatchPacket,
	chunkBatchTasks,
	coalesceProbesByTarget,
	injectResolvedTargetContext,
	normalizeDispatchTargetKey,
	readSpilledBatchTasks,
	validateSubagentDispatch,
} from "../omp/lineage";
import {
	buildEpisodeTimelineData,
	exportEpisodeTimeline,
	searchArchiveIndexes,
	writeEpisodeArchiveIndex,
} from "../omp/reporting";
import { newState } from "../omp/graph";
import { journalAppend, nowIso, readCfg, saveState } from "../omp/storage";
import { upsertSessionRole } from "../omp/session-vault";

const REPO_ROOT = resolve(import.meta.dir, "..");
const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-v51-suite-home-"));
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
process.env.NUWA_KB_DB = join(SUITE_AGENT_HOME, "nuwa-kb", "kb.db");

const tmpDirs: string[] = [];
function makeTmpDir(prefix = "nuwa-v51-"): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(d);
	return d;
}

afterEach(() => {
	while (tmpDirs.length > 0) {
		const d = tmpDirs.pop()!;
		try {
			rmSync(d, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

afterAll(() => {
	rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
});

function makeTestState(target = "http://rggo5269.com:80", episode = 1): NuwaState {
	const st = newState(target, "v5.1 测试目标", "pentest", readCfg(), "sess-v51");
	st.project.episode = episode;
	return st;
}

describe("架构硬性契约：子模块零运行时 import ./nuwa", () => {
	test("evidence.ts / verifier-gate.ts / lineage.ts / reporting.ts 均不运行时导入 ./nuwa", () => {
		for (const rel of ["omp/evidence.ts", "omp/verifier-gate.ts", "omp/lineage.ts", "omp/reporting.ts"]) {
			const src = readFileSync(join(REPO_ROOT, rel), "utf8");
			const stripped = src.replace(/^\s*import\s+type\s+[^;]+from\s+["']\.\/nuwa["'];?\s*$/gm, "");
			expect(stripped).not.toMatch(/from\s+["']\.\/nuwa["']|import\s*\(\s*["']\.\/nuwa["']\s*\)|require\s*\(\s*["']\.\/nuwa["']\s*\)/);
		}
	});
});

describe("Issue #24 (NW-04): 假阳性复核门禁（evidence + verifier-gate）", () => {
	test("拦截 HTTP 200 + 微小错误壳、空壳与 Soft-404，返回 falsePositive=true 并建议 note 记账", () => {
		// 1. {"detail":"Not Found"} 微小错误壳
		for (const kind of ["vuln", "bypass", "cred", "loot"]) {
			const res = evaluatePositiveEvidenceGate({
				kind,
				output: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"detail":"Not Found"}',
			});
			expect(res.ok).toBe(false);
			expect(res.falsePositive).toBe(true);
			expect(res.suggestedKind).toBe("note");
			expect(res.recommendedAction).toBe("downgrade_to_note");
		}

		// 2. HTTP 200 + <64B 空壳
		const tinyShell = evaluatePositiveEvidenceGate({
			kind: "bypass",
			response: { statusCode: 200, body: '{"code":200,"msg":"ok","data":[]}', bodyBytes: 33 },
		});
		expect(tinyShell.ok).toBe(false);
		expect(tinyShell.falsePositive).toBe(true);
		expect(tinyShell.suggestedKind).toBe("note");

		const bareOk = evaluatePositiveEvidenceGate({
			kind: "vuln",
			response: { statusCode: 200, body: "OK", bodyBytes: 2 },
		});
		expect(bareOk.ok).toBe(false);
		expect(bareOk.falsePositive).toBe(true);

		// 3. RSC NEXT_HTTP_ERROR_FALLBACK Soft-404
		const rsc404 = isTinyErrorEnvelope('0:{"a":"$@1"}\n1:E{"digest":"NEXT_HTTP_ERROR_FALLBACK;404"}', 200);
		expect(rsc404.isEnvelope).toBe(true);
	});

	test("拦截与未授权/404 基线响应体哈希完全一致的假阳性，放行含真实业务数据的正向发现", () => {
		const baselineBody = '{"code":404,"message":"route not registered","data":null}';
		const baselineSha256 = computeBodyHash(baselineBody, "sha256");

		// 与基线哈希完全一致
		const sameHash = verifyPositiveConclusion({
			kind: "bypass",
			response: { statusCode: 200, body: baselineBody, bodySha256: baselineSha256 },
			baseline: { statusCode: 404, bodySha256: baselineSha256 },
		});
		expect(sameHash.ok).toBe(false);
		expect(sameHash.falsePositive).toBe(true);
		expect(sameHash.suggestedKind).toBe("note");
		expect(sameHash.matchedSignals).toContain("baseline_body_hash_identical");

		// 含真实业务数据且哈希不同于基线 -> 通过
		const realBody = '{"code":0,"data":[{"uid":1001,"username":"alice","email":"alice@rggo5269.com","balance":9820}]}';
		const validPos = verifyPositiveConclusion({
			kind: "vuln",
			response: { statusCode: 200, body: realBody },
			baseline: { statusCode: 401, body: '{"detail":"Unauthorized"}' },
		});
		expect(validPos.ok).toBe(true);
		expect(validPos.falsePositive).toBe(false);
		expect(validPos.recommendedAction).toBe("accept");

		// note 类型不受正向假阳性门禁拦截
		const notePass = evaluatePositiveEvidenceGate({
			kind: "note",
			response: { statusCode: 200, body: '{"detail":"Not Found"}' },
		});
		expect(notePass.ok).toBe(true);
		expect(notePass.falsePositive).toBe(false);

		// curl -I 仅含安全响应头（如 Set-Cookie）的 cred 实锤不被误判为 0B 空壳
		const headCredPass = evaluatePositiveEvidenceGate({
			kind: "cred",
			output: "HTTP/1.1 200 OK\nSet-Cookie: sid=real_session_token_99887766",
		});
		expect(headCredPass.ok).toBe(true);
		expect(headCredPass.falsePositive).toBe(false);
	});

	test("verifyExecutionEvidence 与 verifier-gate 联动阻断误报升格并输出 note 降级建议", () => {
		const root = makeTmpDir("nuwa-fp-");
		const fakeResp = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"detail":"Not Found"}';

		// 即便真实执行账本记录了该输出，正向 vuln/bypass 仍必须被假阳性门禁拦截
		recordToolExecution(root, {
			tool: "bash",
			command: "curl -i -H 'x-middleware-subrequest: pages/_middleware' http://rggo5269.com/api/v1/member/activityDailyDrawInfo",
			output: fakeResp,
			agentName: "nuwa-verifier",
		});

		const evRes = verifyExecutionEvidence(root, {
			projectId: "proj-fp-1",
			kind: "bypass",
			output: fakeResp,
			baselineBody: '{"detail":"Not Found"}',
		});
		expect(evRes.ok).toBe(false);
		expect(evRes.verified).toBe(false);
		expect(evRes.falsePositive).toBe(true);
		expect(evRes.suggestedKind).toBe("note");

		// validateVerificationCommit 阻断含错误壳的升格提交
		const commitGate = validateVerificationCommit({
			intentKey: "verify-vuln:f010",
			kind: "vuln",
			worker: "nuwa-verifier",
			hasFreshExecution: true,
			requireVerifierWorker: true,
			response: { statusCode: 200, body: '{"detail":"Not Found"}' },
			baseline: { statusCode: 404, body: '{"detail":"Not Found"}' },
		});
		expect(commitGate.ok).toBe(false);
		expect(commitGate.falsePositive).toBe(true);
		expect(commitGate.suggestedKind).toBe("note");

		// resolveVerificationOutcome 遇到假阳性响应时拒绝升格为 confirmed，降级为 rejected 并附 downgradeNote
		const st = makeTestState();
		const cand: VerifiableFact = {
			id: "f010",
			kind: "vuln",
			title: "疑似 CVE-2025-29927 中间件绕过",
			detail: "带 x-middleware-subrequest 返回 200/22B",
			output: '{"detail":"Not Found"}',
			createdAt: nowIso(),
			verifyStage: "candidate",
		};
		st.facts.f010 = cand;

		const spec = buildDoubleBlindVerifyIntentSpec(st, cand);
		expect(spec).not.toBeNull();
		expect(spec!.detail).toContain("body_sha256");

		const outcome = resolveVerificationOutcome(st, "verify-vuln:f010", false, "尝试直接升格", {
			response: { statusCode: 200, body: '{"detail":"Not Found"}' },
			baseline: { statusCode: 404, body: '{"detail":"Not Found"}' },
		});
		expect(outcome.matched).toBe(true);
		expect(outcome.stage).toBe("rejected");
		expect(outcome.falsePositive).toBe(true);
		expect(outcome.suggestedKind).toBe("note");
		expect(outcome.downgraded).toBe(true);
		expect(outcome.downgradeNote?.kind).toBe("note");
		expect(cand.verifyStage).toBe("rejected");
		expect(cand.verified).toBe(false);

		const fpNote = buildFalsePositiveNote(cand, "与 404 基线哈希一致");
		expect(fpNote.kind).toBe("note");
		expect(fpNote.title).toContain("false_positive(f010)");
	});
});

describe("Issue #26 (NW-06): 交付真实性校验与派单目标上下文自动注入", () => {
	test("validateDeliverableRealism 拦截占位符、未展开 TARGET/$U、仅脚本无状态码、缺指标与主机错配", () => {
		// a) 方括号占位符 [TARGET] / [BOOL_DELTA]
		const r1 = validateDeliverableRealism(
			"目标 [TARGET] 测试完成，布尔差异 [BOOL_DELTA]B，耗时 [TIME_DELTA]s，http_code=200 remote_ip=1.2.3.4",
			"rggo5269.com",
		);
		expect(r1.ok).toBe(false);
		expect(r1.reject).toBe(true);
		expect(r1.violations).toContain("placeholder_bracket");
		expect(r1.matchedPlaceholders).toContain("[TARGET]");
		expect(r1.matchedPlaceholders).toContain("[BOOL_DELTA]");

		// b) 未展开字面量 TARGET / HOST / DOMAIN / $U
		const r2 = validateDeliverableRealism(
			"curl -sS http://TARGET:3000/api/v1 && curl -sS $U/login",
			"rggo5269.com",
		);
		expect(r2.ok).toBe(false);
		expect(r2.violations).toContain("unexpanded_target_literal");
		expect(r2.violations).toContain("script_only_no_status");

		// c) 仅脚本无状态码
		const r3 = validateDeliverableRealism(
			"#!/bin/bash\nU=https://rggo5269.com\nfor p in /admin /login; do curl -sS $U$p; done",
			"rggo5269.com",
		);
		expect(r3.ok).toBe(false);
		expect(r3.violations).toContain("script_only_no_status");

		// d) 有状态码但缺少实际探针指标
		const r4 = validateDeliverableRealism(
			"HTTP/1.1 200 OK\n一切正常，未发现漏洞",
			"rggo5269.com",
		);
		expect(r4.ok).toBe(false);
		expect(r4.violations).toContain("missing_probe_metrics");

		// e) 目标主机错配
		const r5 = validateDeliverableRealism(
			"curl -sS https://wrong-domain.invalid/api -> HTTP/2 200 http_code=200 size_download=512 remote_ip=9.9.9.9 server=nginx time_total=0.22",
			"rggo5269.com",
		);
		expect(r5.ok).toBe(false);
		expect(r5.violations).toContain("target_host_mismatch");

		// f) 合规真实探针回包通过
		const rOk = validateDeliverableRealism(
			"curl -sS -D - https://rggo5269.com/zh-tw\nHTTP/2 200\ncf-ray: 8f12ab34cd56-HKG\nhttp_code=200 size_download=87815 remote_ip=104.21.10.20 time_total=1.24",
			"rggo5269.com",
		);
		expect(rOk.ok).toBe(true);
		expect(rOk.reject).toBe(false);
		expect(rOk.violations).toEqual([]);
	});

	test("buildDispatchPacket 与 injectResolvedTargetContext 自动注入 resolved_host 与目标 URL 并展开占位符", () => {
		const pkt = buildDispatchPacket({
			task: "请对 https://TARGET/api/v1 与 [TARGET] 执行路径枚举，基准变量 $U",
			target: {
				url: "https://rggo5269.com/zh-tw",
				resolvedIp: "104.21.10.20",
				egress: "socks5h://127.0.0.1:7890",
			},
			intentId: "i101",
			agent: "fujiang",
		});

		expect(pkt.injected).toBe(true);
		expect(pkt.resolvedHost).toBe("rggo5269.com");
		expect(pkt.targetUrl).toBe("https://rggo5269.com/zh-tw");
		expect(pkt.replacedPlaceholders).toBeGreaterThanOrEqual(3);
		expect(pkt.task).toContain("resolved_host: rggo5269.com");
		expect(pkt.task).toContain("target_url: https://rggo5269.com/zh-tw");
		expect(pkt.task).toContain("egress: socks5h://127.0.0.1:7890");
		expect(pkt.task).not.toContain("[TARGET]");
		expect(pkt.task).not.toContain("$U");
		expect(pkt.task).not.toContain("https://TARGET");

		const plain = injectResolvedTargetContext("检查 /robots.txt", { host: "app.corp.test", port: 8443, scheme: "https" });
		expect(plain.resolvedHost).toBe("app.corp.test");
		expect(plain.targetUrl).toBe("https://app.corp.test:8443");
		expect(plain.task).toContain("resolved_host: app.corp.test");
	});
});

describe("Issue #27 (NW-07): 子代理派单守卫与派单回执登记表", () => {
	test("validateSubagentDispatch 拒收空任务/缺失上下文并标记重排，放行完整派单", () => {
		const empty1 = validateSubagentDispatch({ spawnId: "sp-1", task: "" });
		expect(empty1.ok).toBe(false);
		expect(empty1.accepted).toBe(false);
		expect(empty1.requeue).toBe(true);

		const empty2 = validateSubagentDispatch({
			spawnId: "sp-2",
			task: "no assigned task in context; awaiting work item",
		});
		expect(empty2.ok).toBe(false);
		expect(empty2.requeue).toBe(true);

		const noCtx = validateSubagentDispatch({
			spawnId: "sp-3",
			task: "run quick check",
			context: {},
		});
		expect(noCtx.ok).toBe(false);
		expect(noCtx.requeue).toBe(true);

		const valid = validateSubagentDispatch({
			spawnId: "sp-4",
			agent: "fujiang",
			intentId: "i201",
			targetUrl: "https://rggo5269.com/api/v1/member/profile",
			task: "探测 https://rggo5269.com/api/v1/member/profile 的鉴权响应并采集 curl -w 指标",
		});
		expect(valid.ok).toBe(true);
		expect(valid.accepted).toBe(true);
		expect(valid.requeue).toBe(false);
		expect(valid.taskHash?.length).toBe(16);
		expect(valid.targetKey).toBe("https://rggo5269.com/api/v1/member/profile");
	});

	test("DispatchReceiptRegistry 记录 spawnId 回执、校验首条 context 并支持持久化恢复", () => {
		const root = makeTmpDir("nuwa-receipts-");
		const persistPath = join(root, ".nuwa", "dispatch-receipts.json");
		const reg = new DispatchReceiptRegistry(persistPath);

		// 空任务拒收并标记 requeued
		const bad = reg.register("spawn-empty", { agent: "fujiang", task: "   " });
		expect(bad.ok).toBe(false);
		expect(bad.requeue).toBe(true);
		expect(reg.get("spawn-empty")?.status).toBe("requeued");

		// 正常任务登记
		const good = reg.register("spawn-ok-1", {
			agent: "fujiang",
			intentId: "i301",
			targetUrl: "https://rggo5269.com/admin",
			task: "对 https://rggo5269.com/admin 执行只读访问核查并附 curl -w 指标",
		});
		expect(good.ok).toBe(true);
		expect(good.requeue).toBe(false);
		expect(good.receipt?.spawnId).toBe("spawn-ok-1");
		expect(good.receipt?.taskHash).toHaveLength(16);
		expect(good.receipt?.targetKey).toBe("https://rggo5269.com/admin");
		expect(good.receipt?.dispatchedAt).toBeTruthy();

		// spawn 后回读空 context -> 标记重排
		const ackFail = reg.acknowledge("spawn-ok-1", "no assigned task in context");
		expect(ackFail.ok).toBe(false);
		expect(ackFail.requeue).toBe(true);
		expect(reg.get("spawn-ok-1")?.status).toBe("requeued");

		// 重排后回读有效首条 context -> 确认入列
		const ackOk = reg.acknowledge("spawn-ok-1", "已收到派单 i301，正在探测 https://rggo5269.com/admin");
		expect(ackOk.ok).toBe(true);
		expect(ackOk.requeue).toBe(false);
		expect(ackOk.receipt?.status).toBe("acknowledged");

		// 磁盘持久化恢复验证
		const reloaded = new DispatchReceiptRegistry(persistPath);
		expect(reloaded.get("spawn-ok-1")?.taskHash).toBe(good.receipt?.taskHash);
		expect(reloaded.get("spawn-ok-1")?.status).toBe("acknowledged");
	});
});

describe("Issue #28 (NW-08): 批派单分片保护 chunkBatchTasks 与 tasks_file 溢写", () => {
	test("小于 6000B 保持 inline，超过 6000B 自动分片且不丢任务", () => {
		expect(DEFAULT_BATCH_MAX_BYTES).toBe(6000);

		const smallTasks = [
			{ id: "t1", targetKey: "/admin", task: "检查 /admin 响应" },
			{ id: "t2", targetKey: "/login", task: "检查 /login 响应" },
		];
		const smallRes = chunkBatchTasks(smallTasks);
		expect(smallRes.exceeded).toBe(false);
		expect(smallRes.mode).toBe("inline");
		expect(smallRes.chunks.length).toBe(1);
		expect(smallRes.chunks[0]?.tasks?.length).toBe(2);

		// 构造 6 条 ~1800B 的 packet，总计 > 10KB（复现 NW-08 实战截断场景）
		const bigTasks = Array.from({ length: 6 }, (_, i) => ({
			id: `pkt-${i + 1}`,
			intentId: `i70${i + 1}`,
			targetKey: `https://rggo5269.com/api/v1/mod${i + 1}`,
			task: `Packet #${i + 1} 详细探测指令：` + "A".repeat(1750),
		}));

		const chunked = chunkBatchTasks(bigTasks, { maxBytes: 6000 });
		expect(chunked.exceeded).toBe(true);
		expect(chunked.mode).toBe("chunked");
		expect(chunked.totalBytes).toBeGreaterThan(10_000);
		expect(chunked.chunks.length).toBeGreaterThanOrEqual(2);

		const restoredIds: string[] = [];
		for (const c of chunked.chunks) {
			expect(c.bytes).toBeLessThanOrEqual(6000);
			expect(c.spilled).toBe(false);
			for (const t of c.tasks ?? []) restoredIds.push(t.id!);
		}
		expect(restoredIds).toEqual(bigTasks.map((t) => t.id));
	});

	test("指定 spillDir 或 root 时溢写 .nuwa/dispatches/batch-<id>.json 并返回轻量 tasks_file 引用", () => {
		const root = makeTmpDir("nuwa-spill-");
		const spillDir = join(root, ".nuwa", "dispatches");
		const bigTasks = Array.from({ length: 6 }, (_, i) => ({
			id: `spill-${i + 1}`,
			targetKey: `https://rggo5269.com/chunk-${i + 1}.js`,
			task: `分析静态资源 chunk-${i + 1}.js ` + "B".repeat(1600),
		}));

		const spilled = chunkBatchTasks(bigTasks, { maxBytes: 6000, spillDir, batchId: "e6-demo" });
		expect(spilled.exceeded).toBe(true);
		expect(spilled.mode).toBe("spilled");
		expect(spilled.tasks_file).toBe(join(spillDir, "batch-e6-demo.json"));
		expect(existsSync(spilled.tasks_file!)).toBe(true);
		expect(statSync(spilled.tasks_file!).mode & 0o777).toBe(0o600);

		const restored = readSpilledBatchTasks<{ id: string }>(spilled.tasks_file!);
		expect(restored.map((t) => t.id)).toEqual(bigTasks.map((t) => t.id));

		// 每个分片引用对象自身远小于 6000B，可无损逐片还原
		const partIds: string[] = [];
		for (const chunk of spilled.chunks) {
			expect(chunk.spilled).toBe(true);
			expect(chunk.tasks_file).toBeTruthy();
			expect(chunk.bytes).toBeLessThan(512);
			for (const t of readSpilledBatchTasks<{ id: string }>(chunk.tasks_file!)) {
				partIds.push(t.id);
			}
		}
		expect(partIds).toEqual(bigTasks.map((t) => t.id));
	});
});

describe("Issue #39 (NW-19): 子代理命中证据必需字段校验与代理模板规范", () => {
	test("validateHitEvidenceFields 强检 5 项必需指标并区分边缘与源站", () => {
		expect(REQUIRED_CURL_WRITE_OUT).toContain("%{http_code}");
		expect(REQUIRED_CURL_WRITE_OUT).toContain("%{size_download}");
		expect(REQUIRED_CURL_WRITE_OUT).toContain("%{remote_ip}");
		expect(REQUIRED_CURL_WRITE_OUT).toContain("%{time_total}");

		// 1. 原始 curl 输出：带 cf-ray -> cloudflare_edge
		const rawCf = [
			"HTTP/2 403",
			"cf-ray: 8e45ab12cd90-HKG",
			"server: cloudflare",
			"http_code=403 size_download=4549 remote_ip=104.21.10.20 time_total=0.382",
		].join("\n");
		const vCf = validateHitEvidenceFields(rawCf);
		expect(vCf.ok).toBe(true);
		expect(vCf.missingFields).toEqual([]);
		expect(vCf.edgeOrOrigin).toBe("cloudflare_edge");
		expect(vCf.metrics.http_code).toBe(403);
		expect(vCf.metrics.size_download).toBe(4549);

		// 2. 结构化对象：仅带 server（无 cf_ray）同样满足 cf_ray|server 要求 -> origin_or_proxy
		const vOrigin = validateHitEvidenceFields({
			http_code: 200,
			size_download: 1204,
			remote_ip: "10.0.1.8",
			server: "nginx/1.25.3",
			time_total: 0.041,
		});
		expect(vOrigin.ok).toBe(true);
		expect(vOrigin.edgeOrOrigin).toBe("origin_or_proxy");

		// 3. 缺 remote_ip、cf_ray/server、time_total -> 判定失败并精准列出缺项
		const vMissing = validateHitEvidenceFields({
			http_code: 200,
			size_download: 63,
		});
		expect(vMissing.ok).toBe(false);
		expect(vMissing.missingFields).toEqual(["remote_ip", "cf_ray|server", "time_total"]);

		// extractHitEvidenceMetrics 拒绝占位符值
		const extracted = extractHitEvidenceMetrics({
			http_code: 200,
			size_download: 100,
			remote_ip: "[REMOTE_IP]",
			cf_ray: "N/A",
			time_total: 0.2,
		});
		expect(extracted.remote_ip).toBeUndefined();
		expect(extracted.cf_ray).toBeUndefined();
	});

	test("agents/fujiang.md 与 agents/nuwa-verifier.md 包含 curl -w 必需指标与 JSON AgentResult 契约", () => {
		for (const file of ["agents/fujiang.md", "agents/nuwa-verifier.md"]) {
			const content = readFileSync(join(REPO_ROOT, file), "utf8");
			expect(content).toContain("%{http_code}");
			expect(content).toContain("%{size_download}");
			expect(content).toContain("%{remote_ip}");
			expect(content).toContain("%{time_total}");
			expect(content).toContain("cf_ray");
			expect(content).toContain("body_sha256");
			expect(content).toContain('"evidence"');
			expect(content).toContain('"summary"');
			expect(content).toContain('"next"');
			// 保留旧版 5 行兼容字段
			expect(content).toContain("结论:");
			expect(content).toContain("证据:");
			expect(content).toContain("命令:");
			expect(content).toContain("阻断:");
			expect(content).toContain("下一步:");
		}
	});
});

describe("Issue #42 (NW-22): 原始证据落盘与 Episode 时间线导出", () => {
	test("saveFactEvidenceLog 脱敏落盘至 .nuwa/evidence/<factId>.log 并返回相对 evidenceRef", () => {
		const root = makeTmpDir("nuwa-evlog-");
		upsertSessionRole(root, {
			role: "admin",
			headers: { Authorization: "Bearer super-secret-vault-token-998877" },
		});

		const saved = saveFactEvidenceLog(root, {
			factId: "f040",
			command: "curl -sS -H 'Authorization: Bearer super-secret-vault-token-998877' https://rggo5269.com/zh-tw",
			output: "HTTP/2 200\nNext.js 16.3.3 token=super-secret-vault-token-998877",
			headers: { "cf-ray": "8f12-HKG", server: "cloudflare" },
			metadata: { episode: 2, http_code: 200 },
		});

		expect(saved.evidenceRef).toBe(".nuwa/evidence/f040.log");
		expect(existsSync(saved.absolutePath)).toBe(true);
		expect(statSync(saved.absolutePath).mode & 0o777).toBe(0o600);

		const content = readFactEvidenceLog(root, saved.evidenceRef);
		expect(content).not.toBeNull();
		expect(content!).toContain("Next.js 16.3.3");
		expect(content!).not.toContain("super-secret-vault-token-998877");

		// 阻断路径穿越读取
		expect(readFactEvidenceLog(root, "../../etc/passwd")).toBeNull();
	});

	test("exportEpisodeTimeline 聚合账本与落盘证据并支持按 episode 与 markdown/json 导出", () => {
		const root = makeTmpDir("nuwa-timeline-");
		const st = makeTestState("https://rggo5269.com", 2);

		journalAppend(root, { ts: "2026-11-25T10:00:00.000Z", type: "init", episode: 1, phase: "recon", title: "开始 E1" });
		journalAppend(root, { ts: "2026-11-25T11:00:00.000Z", type: "episode_advance", episode: 2, phase: "vuln", title: "进入 E2" });

		recordToolExecution(root, {
			tool: "bash",
			command: "curl -sS https://rggo5269.com/api/v1/member/profile",
			output: "HTTP/2 405 allow: POST",
			agentName: "fujiang",
		});

		const ev1 = saveFactEvidenceLog(root, {
			factId: "f001",
			command: "curl -sS https://rggo5269.com/zh-tw",
			output: "HTTP/2 200 Next.js 16.3.3",
			ts: "2026-11-25T10:05:00.000Z",
		});
		const ev2 = saveFactEvidenceLog(root, {
			factId: "f002",
			command: "curl -sS https://rggo5269.com/api/v1/member/profile",
			output: "HTTP/2 405 allow: POST",
			ts: "2026-11-25T11:10:00.000Z",
		});

		(st.facts as Record<string, any>).f001 = {
			id: "f001",
			kind: "service",
			title: "识别 Next.js 16.3.3 栈",
			detail: "RSC 响应 87815B",
			command: "curl -sS https://rggo5269.com/zh-tw",
			output: "HTTP/2 200 Next.js 16.3.3",
			createdAt: "2026-11-25T10:05:00.000Z",
			evidenceRef: ev1.evidenceRef,
		};
		(st.facts as Record<string, any>).f002 = {
			id: "f002",
			kind: "endpoint",
			title: "member/profile 存在需 POST+Token",
			detail: "405 allow: POST",
			command: "curl -sS https://rggo5269.com/api/v1/member/profile",
			output: "HTTP/2 405 allow: POST",
			createdAt: "2026-11-25T11:10:00.000Z",
			evidenceRef: ev2.evidenceRef,
		};
		st.intents.i001 = {
			id: "i001",
			phase: "vuln",
			key: "vuln:profile",
			title: "探测 member/profile",
			detail: "检查接口方法与鉴权",
			from: ["f001"],
			to: "f002",
			status: "done",
			priority: 80,
			attempts: 1,
			createdAt: "2026-11-25T11:08:00.000Z",
			doneAt: "2026-11-25T11:10:00.000Z",
		};
		saveState(root, st);

		const allData = buildEpisodeTimelineData(root);
		expect(allData.counts.facts).toBe(2);
		expect(allData.counts.withEvidenceRef).toBeGreaterThanOrEqual(2);

		const ep2JsonRaw = exportEpisodeTimeline(root, { episode: 2, format: "json" });
		const ep2Json = JSON.parse(ep2JsonRaw);
		expect(ep2Json.episodeFilter).toBe(2);
		expect(ep2Json.events.every((e: { episode: number }) => e.episode === 2)).toBe(true);
		expect(ep2Json.events.some((e: { id?: string; evidenceRef?: string }) => e.id === "f002" && e.evidenceRef === ".nuwa/evidence/f002.log")).toBe(true);
		expect(ep2Json.events.some((e: { id?: string }) => e.id === "f001")).toBe(false);

		const md = exportEpisodeTimeline(root, { format: "markdown" });
		expect(md).toContain("# 全量账本与证据时间线");
		expect(md).toContain(".nuwa/evidence/f001.log");
		expect(md).toContain(".nuwa/evidence/f002.log");
		expect(md).toContain("## 关联落盘证据摘录");
	});
});

describe("Issue #50 (NW-30): 跨子代理在途目标去重池与探针合并", () => {
	test("InflightTargetRegistry 规范化 targetKey 去重、过滤重复派单并支持释放与持久化", () => {
		expect(normalizeDispatchTargetKey("HTTP://RGGO5269.COM:80/Admin/")).toBe("http://rggo5269.com/Admin");
		expect(normalizeDispatchTargetKey("https://rggo5269.com:443/api/v1/")).toBe("https://rggo5269.com/api/v1");

		const root = makeTmpDir("nuwa-inflight-");
		const persistPath = join(root, ".nuwa", "inflight-targets.json");
		const reg = new InflightTargetRegistry({ persistPath, ttlMs: 60_000 });

		const c1 = reg.claim("https://rggo5269.com/chunks/app-123.js", {
			intentId: "i501",
			worker: "ChunkHunt",
		});
		expect(c1.claimed).toBe(true);

		// 另一子代理试图声明同目标被拦截
		const c2 = reg.claim("https://rggo5269.com:443/chunks/app-123.js/", {
			intentId: "i502",
			worker: "ChunkRoutes",
		});
		expect(c2.claimed).toBe(false);
		expect(c2.existing?.worker).toBe("ChunkHunt");
		expect(c2.existing?.intentId).toBe("i501");

		// 派单前过滤：过滤在途重复与批内重复
		const filtered = reg.filterTasks(
			[
				{ intentId: "i502", url: "https://rggo5269.com/chunks/app-123.js", task: "重复抽 chunk" },
				{ intentId: "i503", url: "https://rggo5269.com/admin/", task: "首次打 /admin" },
				{ intentId: "i504", url: "https://rggo5269.com:443/admin", task: "同批重复打 /admin" },
				{ intentId: "i505", url: "https://rggo5269.com/login", task: "打 /login" },
			],
			{ autoClaim: true, defaultWorker: "fujiang" },
		);
		expect(filtered.accepted.map((t) => t.intentId)).toEqual(["i503", "i505"]);
		expect(filtered.skipped.map((s) => ({ id: s.task.intentId, reason: s.reason }))).toEqual([
			{ id: "i502", reason: "inflight_duplicate" },
			{ id: "i504", reason: "batch_duplicate" },
		]);

		// 持久化重启校验与释放
		const reg2 = new InflightTargetRegistry({ persistPath });
		expect(reg2.isInflight("https://rggo5269.com/admin")).toBe(true);
		expect(reg2.releaseByWorker("ChunkHunt")).toBe(1);
		expect(reg2.isInflight("https://rggo5269.com/chunks/app-123.js")).toBe(false);
	});

	test("coalesceProbesByTarget 按规范化目标合并多条探针", () => {
		const merged = coalesceProbesByTarget([
			{
				id: "t1",
				intentId: "i601",
				url: "https://rggo5269.com/chunks/main.js",
				probe: "提取 API 路由前缀",
				priority: 70,
			},
			{
				id: "t2",
				intentId: "i602",
				url: "https://rggo5269.com:443/chunks/main.js/",
				probe: "排查硬编码密钥与管理模块键",
				priority: 90,
			},
			{
				id: "t3",
				intentId: "i603",
				url: "https://rggo5269.com/api/v1/member/profile",
				probe: "核验 405 allow 与鉴权头",
				priority: 80,
			},
		]);

		expect(merged.length).toBe(2);
		expect(merged[0]?.targetKey).toBe("https://rggo5269.com/chunks/main.js");
		expect(merged[0]?.sourceCount).toBe(2);
		expect(merged[0]?.priority).toBe(90);
		expect(merged[0]?.intentIds).toEqual(["i601", "i602"]);
		expect(merged[0]?.probes).toEqual(["提取 API 路由前缀", "排查硬编码密钥与管理模块键"]);
		expect(merged[0]?.mergedTask).toContain("合并 2 条任务");
		expect(merged[1]?.targetKey).toBe("https://rggo5269.com/api/v1/member/profile");
	});
});

describe("Issue #51 (NW-31): 结构化 AgentResult 与 parseAgentResult 解析器", () => {
	test("解析纯 JSON、Markdown fenced JSON（含 Σ 尾注）与旧版 5 行降级，拒绝无效脚本", () => {
		const payload = {
			status: "hit",
			target: "https://rggo5269.com/zh-tw",
			evidence: [
				{
					cmd: "curl -sS -D - -w 'http_code=%{http_code}' https://rggo5269.com/zh-tw",
					http_code: 200,
					size_download: 87815,
					remote_ip: "104.21.10.20",
					cf_ray: "8f12ab34cd56-HKG",
					time_total: 1.42,
					body_sha256: "a".repeat(64),
				},
			],
			blocked: false,
			summary: "确认 Next.js 16.3.3 且 RSC 正常响应",
			next: "核验 buildManifest 中的反代前缀",
		};

		// 1. 纯 JSON
		const p1 = parseAgentResult(JSON.stringify(payload));
		expect(p1.ok).toBe(true);
		expect(p1.format).toBe("json");
		expect(p1.warnings).toEqual([]);
		expect(p1.result?.status).toBe("hit");
		expect(p1.result?.evidence[0]?.cf_ray).toBe("8f12ab34cd56-HKG");
		expect(p1.result?.evidence[0]?.body_sha256).toBe("a".repeat(64));

		// 2. Markdown fenced JSON + 前后杂项文本 + Σ 尾注
		const fenced = [
			"已完成探测，结构化回包如下：",
			"```json",
			JSON.stringify(payload, null, 2),
			"```",
			"Σ tokens=1240 duration=4.2s",
		].join("\n");
		const p2 = parseAgentResult(fenced);
		expect(p2.ok).toBe(true);
		expect(p2.format).toBe("fenced_json");
		expect(p2.result?.target).toBe("https://rggo5269.com/zh-tw");
		expect(p2.result?.blocked).toBe(false);

		// 3. 旧版 5 行摘要兼容降级
		const legacy5 = [
			"结论: CONFIRMED — 确认接口存在越权",
			"证据: http_code=200 size_download=512 remote_ip=10.0.0.5 server=nginx time_total=0.12",
			"命令: curl -sS http://10.0.0.5/api/orders/42",
			"阻断: 无",
			"下一步: 评估影响范围",
		].join("\n");
		const p3 = parseAgentResult(legacy5);
		expect(p3.ok).toBe(true);
		expect(p3.format).toBe("legacy_5line");
		expect(p3.result?.status).toBe("confirmed");
		expect(p3.result?.evidence[0]?.http_code).toBe(200);

		// 4. 纯脚本无效内容被拒
		const bad = parseAgentResult("#!/bin/bash\nU=https://TARGET\ncurl -sS $U/admin");
		expect(bad.ok).toBe(false);
		expect(bad.format).toBe("invalid");
	});
});

describe("Issue #52 (NW-32): 结构化 Episode 归档索引器与跨轮检索器", () => {
	test("writeEpisodeArchiveIndex 落盘 .json 与 .md（含脱敏），searchArchiveIndexes 支持多维精准检索", () => {
		const root = makeTmpDir("nuwa-archive-");
		upsertSessionRole(root, {
			role: "member",
			headers: { Authorization: "Bearer member-archive-secret-5566" },
		});

		const hashNext = computeBodyHash("Next.js 16.3.3 RSC payload", "sha256");
		const hash405 = computeBodyHash("405 Method Not Allowed", "sha256");

		const ep1 = writeEpisodeArchiveIndex(root, {
			episode: 1,
			projectId: "proj-rggo",
			target: "https://rggo5269.com",
			phase: "recon",
			summary: "E1 识别栈与反代前缀",
			facts: [
				{
					id: "f040",
					kind: "service",
					title: "Next.js 16.3.3 + React 19.3.0-canary",
					detail: "RSC:1 返回 87815B，token=member-archive-secret-5566",
					command: "curl -sS -H 'RSC: 1' https://rggo5269.com/zh-tw",
					statusCode: 200,
					bytes: 87815,
					bodySha256: hashNext,
					evidenceRef: ".nuwa/evidence/f040.log",
				},
			],
			commands: [
				{
					cmd: "curl -sS -H 'RSC: 1' https://rggo5269.com/zh-tw",
					statusCode: 200,
					bytes: 87815,
					bodySha256: hashNext,
					remoteIp: "104.21.10.20",
					cfRay: "8f12-HKG",
					timeTotal: 1.18,
					factId: "f040",
				},
			],
		});

		const ep2 = writeEpisodeArchiveIndex(root, {
			episode: 2,
			projectId: "proj-rggo",
			target: "https://rggo5269.com",
			phase: "surface",
			summary: "E2 核实 member 鉴权接口",
			facts: [
				{
					id: "f045",
					kind: "endpoint",
					title: "member/profile 需认证且仅限 POST",
					detail: "GET 返回 405 allow: POST",
					command: "curl -sS https://rggo5269.com/api/v1/member/profile",
					statusCode: 405,
					bytes: 128,
					bodySha256: hash405,
					evidenceRef: ".nuwa/evidence/f045.log",
				},
			],
		});

		// 验证 .json 与 .md 落盘、权限及脱敏
		expect(existsSync(ep1.jsonPath)).toBe(true);
		expect(existsSync(ep1.markdownPath)).toBe(true);
		expect(ep1.jsonPath).toBe(join(root, ".nuwa", "archive", "episode-1.json"));
		expect(ep1.markdownPath).toBe(join(root, ".nuwa", "archive", "episode-1.md"));
		expect(existsSync(ep2.jsonPath)).toBe(true);
		expect(statSync(ep1.jsonPath).mode & 0o777).toBe(0o600);

		const jsonRaw = readFileSync(ep1.jsonPath, "utf8");
		const mdRaw = readFileSync(ep1.markdownPath, "utf8");
		expect(jsonRaw).not.toContain("member-archive-secret-5566");
		expect(mdRaw).not.toContain("member-archive-secret-5566");
		expect(mdRaw).toContain("f040");
		expect(mdRaw).toContain("87815");
		expect(mdRaw).toContain(hashNext);

		// 1. 按 factId 字符串检索（防止会话图片化丢失 f0xx 详情）
		const hitF040 = searchArchiveIndexes(root, "f040");
		expect(hitF040.length).toBeGreaterThanOrEqual(1);
		expect(hitF040[0]?.factId).toBe("f040");
		expect(hitF040[0]?.episode).toBe(1);
		expect(hitF040[0]?.bytes).toBe(87815);

		// 2. 按状态码检索
		const hit405 = searchArchiveIndexes(root, { statusCode: 405 });
		expect(hit405.some((h) => h.factId === "f045" && h.episode === 2)).toBe(true);
		expect(hit405.some((h) => h.factId === "f040")).toBe(false);

		// 3. 按响应哈希前缀检索
		const hitHash = searchArchiveIndexes(root, { hash: hashNext.slice(0, 12) });
		expect(hitHash.some((h) => h.factId === "f040" && h.bodySha256 === hashNext)).toBe(true);

		// 4. 按命令片段 + episode 联合检索
		const hitCmd = searchArchiveIndexes(root, { episode: 2, command: "member/profile" });
		expect(hitCmd.length).toBeGreaterThanOrEqual(1);
		expect(hitCmd.every((h) => h.episode === 2)).toBe(true);
	});
});
