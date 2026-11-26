/**
 * 女娲 v6.0 信念驱动攻击图搜索引擎（belief-search）与反自证机械对账校准核（calibration）严格数学与边界测试套件。
 */
import { afterEach, describe, expect, test } from "bun:test";
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { NuwaState } from "../omp/types";
import { upsertSessionRole } from "../omp/session-vault";
import {
	DEFAULT_PRUNE_THRESHOLD,
	computeBetaPosterior,
	computeExpectedInfoGain,
	computeNodeUncertainty,
	computeOneStepEntropyReduction,
	initBeliefGraphFromState,
	propagateBeliefUpdate,
	pruneLowYieldSubtree,
	rankFrontierByBelief,
	recommendSearchPivot,
	shannonBinaryEntropy,
	updateBeliefPosterior,
	type BeliefNode,
	type BeliefObservationType,
} from "../omp/belief-search";
import {
	CalibrationError,
	calibrationLedgerPath,
	computeCalibrationSummary,
	formatCalibrationReport,
	loadCalibrationRecords,
	recommendAdaptiveModelRoute,
	recordPrediction,
	redactCalibrationText,
	safeSettlePrediction,
	settlePrediction,
	validateSettlementSource,
} from "../omp/calibration";

const tmpDirs: string[] = [];

function makeTmpDir(prefix = "nuwa-v6-belief-calib-"): string {
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

function createMockState(): NuwaState {
	const ts = "2026-11-25T12:00:00.000Z";
	return {
		schema: 1,
		version: "5.1.0",
		project: {
			id: "proj-v6-test",
			target: "http://127.0.0.1:18080",
			url: "http://127.0.0.1:18080",
			host: "127.0.0.1",
			port: 18080,
			scheme: "http",
			goal: "验证信念搜索与校准引擎",
			mode: "pentest",
			status: "active",
			phase: "surface",
			createdAt: ts,
			updatedAt: ts,
		},
		facts: {},
		intents: {},
		seq: { fact: 0, intent: 0 },
		runtime: {
			startedAt: 1700000000000,
			turns: 1,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 2,
			lastToolCalls: 2,
			tokens: 1500,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
			noveltyStall: 0,
		},
		assets: {},
		hypotheses: {},
	};
}

function makeStandaloneNode(overrides: Partial<BeliefNode> = {}): BeliefNode {
	const alpha = overrides.alpha ?? 1;
	const beta = overrides.beta ?? 1;
	const node: BeliefNode = {
		id: overrides.id ?? "n1",
		kind: overrides.kind ?? "intent",
		sourceId: overrides.sourceId ?? "i001",
		title: overrides.title ?? "测试节点",
		alpha,
		beta,
		posterior: computeBetaPosterior(alpha, beta),
		uncertainty: computeNodeUncertainty(alpha, beta),
		expectedInfoGain: 0,
		estimatedCost: overrides.estimatedCost ?? 3,
		utilityScore: 0,
		pruned: overrides.pruned ?? false,
		pruneReason: overrides.pruneReason,
		parentIds: overrides.parentIds ?? [],
		childIds: overrides.childIds ?? [],
		surfaceDomain: overrides.surfaceDomain ?? "path",
		observations: overrides.observations ?? 0,
		breakthroughBoost: overrides.breakthroughBoost ?? 0,
		updatedAt: overrides.updatedAt ?? "2026-11-25T12:00:00.000Z",
	};
	node.expectedInfoGain = computeExpectedInfoGain(node);
	return node;
}

describe("模块一：omp/belief-search.ts 信念驱动攻击图搜索引擎", () => {
	test("Beta 后验、二元香农熵、一步预期熵减与数值边界稳定性验证", () => {
		// 1. 精确手算 Beta 均值对拍
		expect(Math.abs(computeBetaPosterior(2, 3) - 0.4)).toBeLessThanOrEqual(1e-12);
		expect(Math.abs(computeBetaPosterior(7, 1) - 0.875)).toBeLessThanOrEqual(1e-12);
		expect(Math.abs(computeBetaPosterior(1, 1) - 0.5)).toBeLessThanOrEqual(1e-12);

		// 2. 极端异常输入保护（绝不产生 NaN / Infinity / 越界值）
		for (const [a, b] of [
			[0, 0],
			[-10, -5],
			[Number.NaN, 2],
			[2, Number.NaN],
			[Number.POSITIVE_INFINITY, 1],
			[1, Number.POSITIVE_INFINITY],
			[Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY],
		] as const) {
			const p = computeBetaPosterior(a, b);
			expect(Number.isFinite(p)).toBe(true);
			expect(p).toBeGreaterThan(0);
			expect(p).toBeLessThan(1);
		}

		// 3. 香农熵精确手算与凹凸单调性验证
		expect(shannonBinaryEntropy(0)).toBe(0);
		expect(shannonBinaryEntropy(1)).toBe(0);
		expect(Math.abs(shannonBinaryEntropy(0.5) - 1.0)).toBeLessThanOrEqual(1e-12);
		const expectedH025 = -(0.25 * Math.log2(0.25) + 0.75 * Math.log2(0.75));
		expect(Math.abs(shannonBinaryEntropy(0.25) - expectedH025)).toBeLessThanOrEqual(1e-12);
		expect(shannonBinaryEntropy(0.1)).toBeLessThan(shannonBinaryEntropy(0.3));
		expect(shannonBinaryEntropy(0.3)).toBeLessThan(shannonBinaryEntropy(0.5));
		expect(shannonBinaryEntropy(0.5)).toBeGreaterThan(shannonBinaryEntropy(0.7));
		expect(shannonBinaryEntropy(0.7)).toBeGreaterThan(shannonBinaryEntropy(0.9));

		// 4. Beta(1,1) 一步预期熵减精确手算：1 - H_2(2/3)
		const expectedDeltaH11 = 1 - shannonBinaryEntropy(2 / 3);
		expect(Math.abs(computeOneStepEntropyReduction(1, 1) - expectedDeltaH11)).toBeLessThanOrEqual(1e-12);
		expect(computeOneStepEntropyReduction(100, 100)).toBeGreaterThanOrEqual(0);
		expect(computeOneStepEntropyReduction(1, 1)).toBeGreaterThan(computeOneStepEntropyReduction(20, 20));
	});

	test("全部 7 类观测的共轭 Beta 更新公式与 VoI 单调性/非负性验证", () => {
		const deltas: Record<BeliefObservationType, [number, number]> = {
			confirmed_hit: [4.5, 0],
			breakthrough_signal: [6.5, 0],
			partial_signal: [1.5, 0.25],
			timeout: [0, 0.8],
			soft404_miss: [0, 2.5],
			waf_block: [0, 7.5],
			verifier_reject: [0, 10.0],
		};

		for (const [obsType, [da, db]] of Object.entries(deltas) as Array<[BeliefObservationType, [number, number]]>) {
			const node = makeStandaloneNode({ alpha: 2.0, beta: 2.0 });
			const updated = updateBeliefPosterior(node, { type: obsType, weight: 1.5 });
			const expectedAlpha = 2.0 + da * 1.5;
			const expectedBeta = 2.0 + db * 1.5;
			const expectedPosterior = expectedAlpha / (expectedAlpha + expectedBeta);
			expect(Math.abs(updated.alpha - expectedAlpha)).toBeLessThanOrEqual(1e-9);
			expect(Math.abs(updated.beta - expectedBeta)).toBeLessThanOrEqual(1e-9);
			expect(Math.abs(updated.posterior - expectedPosterior)).toBeLessThanOrEqual(1e-9);
			expect(updated.expectedInfoGain).toBeGreaterThanOrEqual(0);
			expect(updated.utilityScore).toBeGreaterThanOrEqual(0);
		}

		// 非法观测类型与非法权重必须显式抛出错误
		const nErr = makeStandaloneNode();
		expect(() => updateBeliefPosterior(nErr, "invalid_obs" as any)).toThrow(/非法信念观测/);
		expect(() => updateBeliefPosterior(nErr, { type: "confirmed_hit", weight: 0 })).toThrow(/正数/);
		expect(() => updateBeliefPosterior(nErr, { type: "confirmed_hit", weight: -2 })).toThrow(/正数/);

		// VoI 单调性：高不确定性 > 低不确定性；少样本 > 多样本；广子树 > 孤立叶节点；已剪枝 === 0
		const uncertainNode = makeStandaloneNode({ id: "u", alpha: 1, beta: 1 });
		const certainPosNode = makeStandaloneNode({ id: "cp", alpha: 9, beta: 1 });
		const certainNegNode = makeStandaloneNode({ id: "cn", alpha: 1, beta: 9 });
		const saturatedNode = makeStandaloneNode({ id: "sat", alpha: 12, beta: 12 });
		const prunedNode = makeStandaloneNode({ id: "pr", alpha: 1, beta: 1, pruned: true });

		expect(computeExpectedInfoGain(uncertainNode)).toBeGreaterThan(computeExpectedInfoGain(certainPosNode));
		expect(computeExpectedInfoGain(uncertainNode)).toBeGreaterThan(computeExpectedInfoGain(certainNegNode));
		expect(computeExpectedInfoGain(uncertainNode)).toBeGreaterThan(computeExpectedInfoGain(saturatedNode));
		expect(computeExpectedInfoGain(prunedNode)).toBe(0);

		const st = createMockState();
		st.facts.f001 = {
			id: "f001",
			kind: "endpoint",
			title: "发现网关入口 /api/v1",
			detail: "返回 200 JSON",
			createdAt: st.project.createdAt,
		};
		st.facts.f002 = {
			id: "f002",
			kind: "endpoint",
			title: "发现静态健康检查 /healthz",
			detail: "返回 ok",
			createdAt: st.project.createdAt,
		};
		for (let idx = 1; idx <= 3; idx++) {
			const iid = `i00${idx}`;
			st.intents[iid] = {
				id: iid,
				phase: "vuln",
				key: `vuln:api:${idx}`,
				title: `下游接口测试 ${idx}`,
				detail: "依赖 f001",
				from: ["f001"],
				status: "open",
				priority: 70,
				attempts: 0,
				createdAt: st.project.createdAt,
			};
		}
		const graph = initBeliefGraphFromState(st);
		expect(graph.nodes.f001!.expectedInfoGain).toBeGreaterThan(graph.nodes.f002!.expectedInfoGain);
	});

	test("WAF 硬阻断与双盲复验驳回沿拓扑级联衰减剪枝，且有向环路安全终止不死循环", () => {
		const st = createMockState();
		const ts = st.project.createdAt;

		st.facts.f001 = {
			id: "f001",
			kind: "endpoint",
			title: "管理后台网关 /admin",
			detail: "发现 /admin 路径前缀",
			targetKey: "path:/admin",
			surfaceDomain: "path",
			createdAt: ts,
		};
		st.facts.f002 = {
			id: "f002",
			kind: "vuln",
			title: "疑似 SQL 注入候选",
			detail: "参数 id 疑似报错",
			verifyStage: "candidate",
			createdAt: ts,
		};

		// 依赖 f001 的下游两层 open 意图 + 1 个 done 意图 + 1 个 claimed 意图 + 1 个跨分域无关 open 意图
		st.intents.i001 = {
			id: "i001",
			phase: "vuln",
			key: "vuln:admin:users",
			title: "探测 /admin/users 未授权访问",
			detail: "依赖 f001",
			from: ["f001"],
			targetKey: "path:/admin/users",
			surfaceDomain: "path",
			status: "open",
			priority: 65,
			attempts: 0,
			createdAt: ts,
		};
		st.intents.i002 = {
			id: "i002",
			phase: "exploit",
			key: "exploit:admin:export",
			title: "利用 /admin/users 导出敏感数据",
			detail: "下游孙节点",
			from: ["f001"],
			targetKey: "path:/admin/users/export",
			surfaceDomain: "path",
			status: "open",
			priority: 60,
			attempts: 0,
			createdAt: ts,
		};
		st.intents.i003 = {
			id: "i003",
			phase: "recon",
			key: "recon:admin:done",
			title: "已完成的侦察意图",
			detail: "status=done 严禁被列入可阻塞 open 清单",
			from: ["f001"],
			status: "done",
			priority: 50,
			attempts: 1,
			createdAt: ts,
		};
		st.intents.i004 = {
			id: "i004",
			phase: "vuln",
			key: "vuln:admin:claimed",
			title: "正在执行中的意图",
			detail: "status=claimed 严禁被误阻塞",
			from: ["f001"],
			status: "claimed",
			priority: 70,
			attempts: 1,
			claimedAt: ts,
			createdAt: ts,
		};
		st.intents.i005 = {
			id: "i005",
			phase: "surface",
			key: "portscan:tcp",
			title: "独立端口扫描任务",
			detail: "port 分域无关任务保持高信念与未剪枝",
			from: [],
			targetKey: "port:127.0.0.1:6379",
			surfaceDomain: "port",
			status: "open",
			priority: 72,
			attempts: 0,
			createdAt: ts,
		};
		// 依赖候选漏洞 f002 的深入利用意图
		st.intents.i006 = {
			id: "i006",
			phase: "exploit",
			key: "exploit:sqli:dump",
			title: "基于候选 SQLi 提取库表元数据",
			detail: "依赖 f002",
			from: ["f002"],
			status: "open",
			priority: 80,
			attempts: 0,
			createdAt: ts,
		};

		const graph = initBeliefGraphFromState(st);
		// 建立 i001 -> i002 级联边，并刻意注入 i002 -> f001 的人工回边构成有向环 f001 -> i001 -> i002 -> f001！
		graph.nodes.i001!.childIds.push("i002");
		graph.nodes.i002!.parentIds = ["i001"];
		graph.nodes.i002!.childIds.push("f001");
		graph.nodes.f001!.parentIds.push("i002");

		// 即使存在有向环，computeExpectedInfoGain 与 propagateBeliefUpdate 必须安全终止
		const voiBefore = computeExpectedInfoGain(graph.nodes.f001!, st, graph);
		expect(Number.isFinite(voiBefore)).toBe(true);
		expect(voiBefore).toBeGreaterThan(0);

		const beforePortPosterior = graph.nodes.i005!.posterior;

		// 1) 触发 WAF 硬阻断传播
		const wafRes = propagateBeliefUpdate(graph, st, {
			nodeId: "f001",
			observation: "waf_block",
			reason: "Cloudflare WAF 403 硬拦截 /admin/* 路径",
		});

		expect(graph.nodes.f001!.posterior).toBeLessThan(DEFAULT_PRUNE_THRESHOLD);
		expect(graph.nodes.f001!.pruned).toBe(true);
		expect(graph.nodes.i001!.pruned).toBe(true);
		expect(graph.nodes.i002!.pruned).toBe(true);
		// 只返回 status === "open" 的下游受阻意图 i001、i002，绝不包含 done(i003)、claimed(i004) 或跨分域 port(i005)
		expect(wafRes.blockableOpenIntentIds).toEqual(["i001", "i002"]);
		expect(graph.nodes.i005!.pruned).toBe(false);
		expect(graph.nodes.i005!.posterior).toBeCloseTo(beforePortPosterior, 9);

		// 2) 触发双盲复验驳回（verifier_reject）并开启 applyToState=true 自动同步阻塞下游 open 意图
		const rejectRes = propagateBeliefUpdate(graph, st, {
			nodeId: "f002",
			observation: "verifier_reject",
			reason: "双盲正负对照一致，确认为静态报错模板误报",
			applyToState: true,
		});
		expect(rejectRes.blockableOpenIntentIds).toContain("i006");
		expect(graph.nodes.f002!.pruned).toBe(true);
		expect(graph.nodes.i006!.pruned).toBe(true);
		expect(st.intents.i006!.status).toBe("blocked");
		expect(st.intents.i006!.invalidatedReason).toContain("误报");
		expect(st.intents.i003!.status).toBe("done");
		expect(st.intents.i004!.status).toBe("claimed");
		expect(st.intents.i005!.status).toBe("open");
	});

	test("关键跃迁信号（.js.map 源码泄露与获取 cred）触发关联子树先验跃升、全局重排与负向封盘建议衔接", () => {
		const st = createMockState();
		const ts = st.project.createdAt;

		// 初始前沿：常规目录枚举优先级 78 > 灰盒隐藏 API 审计优先级 58
		st.intents.i001 = {
			id: "i001",
			phase: "surface",
			key: "surface:common-dirs",
			title: "常规静态目录字典枚举",
			detail: "枚举通用静态资源路径",
			from: [],
			status: "open",
			priority: 78,
			attempts: 0,
			createdAt: ts,
		};
		st.intents.i002 = {
			id: "i002",
			phase: "vuln",
			key: "vuln:greybox:hidden-admin-export",
			title: "灰盒审计前端 bundle 隐藏管理导出 API 路由",
			detail: "结合 JS 源码映射提取内部未鉴权路由参数与 Sink",
			from: [],
			status: "open",
			priority: 58,
			attempts: 0,
			createdAt: ts,
		};

		const graph = initBeliefGraphFromState(st);
		const initialRank = rankFrontierByBelief(st, undefined, { graph });
		expect(initialRank[0]!.intent.id).toBe("i001");
		const initialPivot = recommendSearchPivot(st, graph);
		expect(initialPivot.topDirection?.intentId).toBe("i001");
		expect(initialPivot.recommendSeal).toBe(false);

		// 新增 .js.map 源码泄露事实并广播 breakthrough_signal
		st.facts.f010 = {
			id: "f010",
			kind: "loot",
			title: "发现 main.chunk.js.map 完整前端 SourceMap 源码泄露",
			detail: "泄露内部 /api/internal/export 管理路由定义",
			createdAt: ts,
		};
		const syncedGraph = initBeliefGraphFromState(st, graph);
		const prop = propagateBeliefUpdate(syncedGraph, st, {
			nodeId: "f010",
			observation: { type: "breakthrough_signal", weight: 1.2, note: ".js.map 源码泄露" },
			reason: "发现 .js.map 暴露未鉴权管理接口",
		});

		expect(prop.isBreakthrough).toBe(true);
		expect(prop.boostedNodeIds).toContain("i002");
		// 全局重排后，灰盒源码路由审计意图 i002 瞬时超越常规目录枚举跃居第一！
		expect(prop.rerankedFrontier[0]!.intent.id).toBe("i002");
		expect(prop.rerankedFrontier[0]!.explanation).toContain("跃迁信号加成");

		// 测试搜索转向建议：当前应推荐探索高价值活跃方向
		const pivotActive = recommendSearchPivot(st, syncedGraph);
		expect(pivotActive.recommendSeal).toBe(false);
		expect(pivotActive.topDirection?.intentId).toBe("i002");

		// 测试硬化零洞靶机场景下的负向封盘（sealed_negative）置信度衔接
		const hardenedState = createMockState();
		hardenedState.runtime.noveltyStall = 9;
		hardenedState.runtime.completionRejects = 2;
		hardenedState.intents.i101 = {
			id: "i101",
			phase: "vuln",
			key: "vuln:api:probe1",
			title: "探测受保护接口 1",
			detail: "统一返回 401",
			from: [],
			targetKey: "path:/api/orders",
			status: "blocked",
			priority: 70,
			attempts: 3,
			createdAt: ts,
		};
		hardenedState.intents.i102 = {
			id: "i102",
			phase: "vuln",
			key: "vuln:api:probe2",
			title: "探测受保护接口 2",
			detail: "WAF 阻断",
			from: [],
			targetKey: "path:/api/admin",
			status: "open",
			priority: 45,
			attempts: 2,
			createdAt: ts,
		};
		const hardenedGraph = initBeliefGraphFromState(hardenedState);
		pruneLowYieldSubtree(hardenedGraph, hardenedState, 0.5, {
			rootNodeId: "i102",
			reason: "硬化接口统一鉴权拒绝",
		});

		const sealPivot = recommendSearchPivot(hardenedState, hardenedGraph);
		expect(sealPivot.recommendSeal).toBe(true);
		expect(sealPivot.action).toBe("seal_negative");
		expect(sealPivot.negativeSealConfidence).toBeGreaterThanOrEqual(0.75);
		expect(sealPivot.sealReason).toContain("负向封盘置信度");
		expect(sealPivot.excludedSurface.length).toBeGreaterThan(0);

		// 若此时新增一个待复验 candidate 漏洞，必须立即阻止负向封盘并要求先双盲复验！
		hardenedState.facts.f999 = {
			id: "f999",
			kind: "vuln",
			title: "待核实异常响应",
			detail: "需双盲复验",
			verifyStage: "candidate",
			createdAt: ts,
		};
		const candidatePivot = recommendSearchPivot(hardenedState, initBeliefGraphFromState(hardenedState, hardenedGraph));
		expect(candidatePivot.recommendSeal).toBe(false);
		expect(candidatePivot.action).toBe("verify_candidates");
		expect(candidatePivot.negativeSealConfidence).toBeLessThanOrEqual(0.35);
	});
});

describe("模块二：omp/calibration.ts 反自证机械对账校准核与自适应模型路由", () => {
	test("反自证原则强制拦截（拒绝 self/model/agent/未知源）、输入边界校验与防重复结算", () => {
		const root = makeTmpDir();

		// 1. 事前置信度严格校验 [0, 1]
		expect(() =>
			recordPrediction(root, {
				predictionId: "p-bad-1",
				intentId: "i001",
				taskCategory: "vuln" as any, // 非法类别同样拦截
				modelId: "gemini-4-neon-xhigh",
				predictedConfidence: 0.5,
				estimatedTokens: 1000,
			}),
		).toThrow(CalibrationError);

		for (const badConf of [-0.01, 1.0001, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
			expect(() =>
				recordPrediction(root, {
					intentId: "i001",
					taskCategory: "exploit",
					modelId: "gemini-4-neon-xhigh",
					predictedConfidence: badConf,
					estimatedTokens: 1000,
				}),
			).toThrow(CalibrationError);
		}

		// 合法登记边界 p=0 与 p=1
		const pZero = recordPrediction(root, {
			predictionId: "pred-001",
			intentId: "i001",
			taskCategory: "recon",
			modelId: "gemini-4-hydrogen-xhigh",
			predictedConfidence: 0,
			estimatedTokens: 500,
		});
		expect(pZero.settled).toBe(false);

		// 禁止重复登记同一 predictionId
		expect(() =>
			recordPrediction(root, {
				predictionId: "pred-001",
				intentId: "i001",
				taskCategory: "recon",
				modelId: "gemini-4-hydrogen-xhigh",
				predictedConfidence: 0.8,
				estimatedTokens: 500,
			}),
		).toThrow(/重复预测登记拦截/);

		// 2. 反自证硬约束：所有自评/未知来源一律拒绝并给出明确错误原因
		for (const forbiddenSource of [
			"self",
			"SELF",
			"model",
			"Model:gpt",
			"agent",
			"agent:fujiang",
			"llm",
			"assistant",
			"subagent",
			"",
			"untrusted-custom-source",
		]) {
			expect(() => validateSettlementSource(forbiddenSource)).toThrow(CalibrationError);
			const res = safeSettlePrediction(root, {
				predictionId: "pred-001",
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 600,
				durationMs: 1200,
				source: forbiddenSource as any,
			});
			expect(res.ok).toBe(false);
			if (!res.ok) {
				expect(res.error.length).toBeGreaterThan(8);
			}
		}

		// 验证被拒后账本中 pred-001 依然保持未结算状态
		expect(loadCalibrationRecords(root)[0]!.settled).toBe(false);

		// 3. 矛盾假阳性输入拦截：isFalsePositive=true 时 outcome 不得为 1
		expect(() =>
			settlePrediction(root, {
				predictionId: "pred-001",
				outcome: 1,
				isFalsePositive: true,
				actualTokens: 600,
				durationMs: 800,
				source: "verifier-gate",
			}),
		).toThrow(/语义矛盾/);

		// 4. 合法授信机械核验源结算成功，且严禁二次重复结算
		const settled = settlePrediction(root, {
			predictionId: "pred-001",
			outcome: 0,
			isFalsePositive: false,
			actualTokens: 540,
			durationMs: 950,
			source: "verifier-gate",
		});
		expect(settled.settled).toBe(true);
		expect(settled.source).toBe("verifier-gate");

		expect(() =>
			settlePrediction(root, {
				predictionId: "pred-001",
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 100,
				durationMs: 100,
				source: "human",
			}),
		).toThrow(/重复结算防重拦截/);
	});

	test("Brier Score、10-bin ECE（含 p=0 与 p=1 精确分桶边界）、Precision、FPR 与 Tokens/Finding 手算对拍精度 <= 1e-6", () => {
		const root = makeTmpDir();

		// 精心构造 6 条跨桶样本，覆盖 p=0.0 (bin 0)、p=0.1 (bin 1)、p=0.25 (bin 2)、p=0.75 (bin 7)、p=0.9 (bin 9)、p=1.0 (bin 9)
		const dataset: Array<{
			id: string;
			cat: "exploit" | "verify" | "auth";
			model: string;
			p: number;
			y: 0 | 1;
			fp: boolean;
			tokens: number;
			source: "verifier-gate" | "exec-ledger" | "autoexec" | "benchmark";
		}> = [
			// bin 0: [0.0, 0.1) -> count=1, conf=0.0, acc=0.0 -> gap=0.0, (p-y)^2 = 0.0
			{ id: "s1", cat: "verify", model: "model-alpha", p: 0.0, y: 0, fp: false, tokens: 1000, source: "verifier-gate" },
			// bin 1: [0.1, 0.2) -> count=1, conf=0.1, acc=0.0 -> gap=0.1, (p-y)^2 = 0.01
			{ id: "s2", cat: "verify", model: "model-alpha", p: 0.1, y: 0, fp: false, tokens: 1200, source: "exec-ledger" },
			// bin 2: [0.2, 0.3) -> count=1, conf=0.25, acc=1.0 -> gap=0.75, (p-y)^2 = (-0.75)^2 = 0.5625
			{ id: "s3", cat: "auth", model: "model-alpha", p: 0.25, y: 1, fp: false, tokens: 1800, source: "autoexec" },
			// bin 7: [0.7, 0.8) -> count=1, conf=0.75, acc=0.0 (FP!) -> gap=0.75, (p-y)^2 = 0.5625
			{ id: "s4", cat: "exploit", model: "model-beta", p: 0.75, y: 0, fp: true, tokens: 3000, source: "verifier-gate" },
			// bin 9: [0.9, 1.0] -> 包含 s5(p=0.9, y=1) 与 s6(p=1.0, y=1) 共 2 条！
			// bin 9 内 avgConf = (0.9 + 1.0)/2 = 0.95, avgAcc = (1 + 1)/2 = 1.0 -> gap = 0.05
			// s5: (0.9 - 1)^2 = 0.01; s6: (1.0 - 1)^2 = 0.0
			{ id: "s5", cat: "exploit", model: "model-alpha", p: 0.9, y: 1, fp: false, tokens: 2000, source: "verifier-gate" },
			{ id: "s6", cat: "auth", model: "model-beta", p: 1.0, y: 1, fp: false, tokens: 3000, source: "benchmark" },
		];

		for (const row of dataset) {
			recordPrediction(root, {
				predictionId: row.id,
				intentId: `intent-${row.id}`,
				taskCategory: row.cat,
				modelId: row.model,
				predictedConfidence: row.p,
				estimatedTokens: row.tokens,
			});
			settlePrediction(root, {
				predictionId: row.id,
				outcome: row.y,
				isFalsePositive: row.fp,
				actualTokens: row.tokens,
				durationMs: 500,
				source: row.source,
			});
		}

		// 额外登记 1 条未结算 pending 记录，验证不会污染已结算统计分母
		recordPrediction(root, {
			predictionId: "s-pending",
			intentId: "intent-pending",
			taskCategory: "recon",
			modelId: "model-alpha",
			predictedConfidence: 0.6,
			estimatedTokens: 9999,
		});

		const records = loadCalibrationRecords(root);
		const summary = computeCalibrationSummary(records);
		const g = summary.global;

		expect(g.totalPredictions).toBe(7);
		expect(g.settledCount).toBe(6);
		expect(g.pendingCount).toBe(1);

		// 手算精确值：
		// Brier = (0 + 0.01 + 0.5625 + 0.5625 + 0.01 + 0) / 6 = 1.145 / 6
		const expectedBrier = 1.145 / 6;
		// 10-bin ECE = (1/6)*0.0 + (1/6)*0.1 + (1/6)*0.75 + (1/6)*0.75 + (2/6)*0.05 = (0 + 0.1 + 0.75 + 0.75 + 0.1) / 6 = 1.7 / 6
		const expectedEce = 1.7 / 6;
		// Confirmed (TP) = 3 (s3, s5, s6), FalsePositives (FP) = 1 (s4), CleanNegatives (TN) = 2 (s1, s2)
		// Precision = 3 / (3 + 1) = 0.75
		const expectedPrecision = 3 / 4;
		// False Positive Rate = 1 / 6
		const expectedFpr = 1 / 6;
		// Total Actual Tokens = 1000 + 1200 + 1800 + 3000 + 2000 + 3000 = 12000 -> Tokens per Confirmed Finding = 12000 / 3 = 4000
		const expectedTokensPerFinding = 12000 / 3;

		expect(Math.abs(g.brierScore - expectedBrier)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(g.ece - expectedEce)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(g.precision - expectedPrecision)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(g.falsePositiveRate - expectedFpr)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(g.tokensPerConfirmedFinding - expectedTokensPerFinding)).toBeLessThanOrEqual(1e-6);

		// 验证分桶边界：p=0 在 bin[0]，p=0.1 在 bin[1]，p=0.9 与 p=1.0 均在 bin[9]
		expect(g.bins[0]!.count).toBe(1);
		expect(g.bins[1]!.count).toBe(1);
		expect(g.bins[9]!.count).toBe(2);
		expect(Math.abs(g.bins[9]!.avgConfidence - 0.95)).toBeLessThanOrEqual(1e-6);

		// 验证按 modelId 与 taskCategory 分维度手算对拍
		// model-beta: s4 (p=0.75, y=0, fp=true, 3000t) + s6 (p=1.0, y=1, fp=false, 3000t)
		// Brier(beta) = (0.5625 + 0) / 2 = 0.28125; ECE(beta) = 0.5 * 0.75 + 0.5 * 0 = 0.375; Precision = 0.5; FPR = 0.5
		const mBeta = summary.byModel["model-beta"]!;
		expect(Math.abs(mBeta.brierScore - 0.28125)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(mBeta.ece - 0.375)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(mBeta.precision - 0.5)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(mBeta.falsePositiveRate - 0.5)).toBeLessThanOrEqual(1e-6);
		expect(Math.abs(mBeta.tokensPerConfirmedFinding - 6000)).toBeLessThanOrEqual(1e-6);

		// 格式化中文看板报告校验
		const report = formatCalibrationReport(summary);
		expect(report).toContain("女娲机械对账认知校准看板");
		expect(report).toContain("model-alpha");
		expect(report).toContain("exploit");
	});

	test("持久化账本零明文凭据泄露、损坏行容错恢复与并发结算原子性", async () => {
		const root = makeTmpDir();
		const secretJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTk5OTk5OTk5OX0.superSecretSig99";
		const secretPass = "MyUltraSecretPass!2026";
		const inlineKey = "sk-live-998877665544332211secret";

		upsertSessionRole(root, {
			role: "admin",
			bearer: `Bearer ${secretJwt}`,
			username: "admin",
			password: secretPass,
		});

		recordPrediction(root, {
			predictionId: "pred-sec-1",
			intentId: "i-auth-1",
			taskCategory: "auth",
			modelId: "gemini-4-neon-xhigh",
			predictedConfidence: 0.85,
			estimatedTokens: 1500,
			note: `携带 Bearer ${secretJwt} 与 password=${secretPass} 及 api_key=${inlineKey} 探测管理端`,
		});

		// 向 JSONL 手工追加半截崩溃损坏行 + 伪造绕过 API 的 self 自评结算行
		const ledgerFile = calibrationLedgerPath(root);
		appendFileSync(ledgerFile, `{"schema":1,"kind":"prediction","broken_json\n`, "utf8");
		appendFileSync(
			ledgerFile,
			`${JSON.stringify({
				schema: 1,
				kind: "settlement",
				predictionId: "pred-sec-1",
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 100,
				durationMs: 50,
				source: "self",
				settledAt: "2026-11-25T12:05:00.000Z",
			})}\n`,
			"utf8",
		);

		// 读取验证：损坏行被容错忽略，磁盘伪造的 source="self" 行被读取层二次拦截丢弃！
		const beforeValidSettle = loadCalibrationRecords(root);
		expect(beforeValidSettle.length).toBe(1);
		expect(beforeValidSettle[0]!.settled).toBe(false);

		// 并发抢占结算同一 predictionId：5 个并发请求只能有 1 个成功，其余 4 个被防重锁拦截
		const concurrentAttempts = await Promise.all(
			Array.from({ length: 5 }, (_, idx) =>
				Promise.resolve().then(() =>
					safeSettlePrediction(root, {
						predictionId: "pred-sec-1",
						outcome: 1,
						isFalsePositive: false,
						actualTokens: 1600 + idx,
						durationMs: 700,
						source: "verifier-gate",
						note: `复验回显脱敏检查 ${secretPass} ${secretJwt}`,
					}),
				),
			),
		);
		const successes = concurrentAttempts.filter((r) => r.ok);
		const duplicates = concurrentAttempts.filter((r) => !r.ok && r.code === "DUPLICATE_SETTLEMENT");
		expect(successes.length).toBe(1);
		expect(duplicates.length).toBe(4);

		// 检查磁盘原始文本：零明文凭据泄露！
		const rawDisk = readFileSync(ledgerFile, "utf8");
		expect(rawDisk).not.toContain(secretJwt);
		expect(rawDisk).not.toContain(secretPass);
		expect(rawDisk).not.toContain(inlineKey);
	});

	test("自适应模型路由：冷启动最小样本保护、高误报/低 ROI 降权、同家族优先切换与严格白名单不越界", () => {
		const root = makeTmpDir();
		let seq = 1;
		const addSample = (
			modelId: string,
			taskCategory: "vuln" | "exploit" | "verify" | "auth",
			p: number,
			y: 0 | 1,
			fp: boolean,
			tokens: number,
		) => {
			const pid = `r-${seq++}`;
			recordPrediction(root, {
				predictionId: pid,
				intentId: `i-${seq}`,
				taskCategory: taskCategory === "vuln" ? "exploit" : taskCategory,
				modelId,
				predictedConfidence: p,
				estimatedTokens: tokens,
			});
			settlePrediction(root, {
				predictionId: pid,
				outcome: y,
				isFalsePositive: fp,
				actualTokens: tokens,
				durationMs: 400,
				source: "verifier-gate",
			});
		};

		// 1. 注入一个不在 allowedModels 白名单内但表现满分的“诱惑模型” external-god-model（10 连中，0 误报）
		for (let i = 0; i < 10; i++) {
			addSample("external-god-model", "exploit", 0.95, 1, false, 800);
		}

		// 2. 冷启动阶段：默认模型 gemini-4-hydrogen-xhigh 仅有 3 条记录（< minSamples=5），哪怕 3 条全误报也不得过早降权，且绝不越界选 external-god-model
		for (let i = 0; i < 3; i++) {
			addSample("gemini-4-hydrogen-xhigh", "exploit", 0.85, 0, true, 1500);
		}

		const allowed = ["gemini-4-hydrogen-xhigh", "gemini-4-neon-xhigh", "gpt-5-mini"] as const;
		const coldDecision = recommendAdaptiveModelRoute(loadCalibrationRecords(root), {
			allowedModels: allowed,
			defaultModel: "gemini-4-hydrogen-xhigh",
			taskCategory: "exploit",
			minSamples: 5,
		});
		expect(coldDecision.coldStart).toBe(true);
		expect(coldDecision.downgraded).toBe(false);
		expect(coldDecision.recommendedModel).toBe("gemini-4-hydrogen-xhigh");
		expect(allowed.includes(coldDecision.recommendedModel as any)).toBe(true);

		// 3. 补齐至 6 条样本（共 5 次误报，FPR = 5/6 = 83.3% > 30%），同时给同家族 gemini-4-neon-xhigh 与异家族 gpt-5-mini 注入同等健康样本
		addSample("gemini-4-hydrogen-xhigh", "exploit", 0.88, 0, true, 1500);
		addSample("gemini-4-hydrogen-xhigh", "exploit", 0.9, 0, true, 1500);
		addSample("gemini-4-hydrogen-xhigh", "exploit", 0.8, 1, false, 1500);

		for (let i = 0; i < 6; i++) {
			addSample("gemini-4-neon-xhigh", "exploit", 0.9, 1, false, 1800);
			addSample("gpt-5-mini", "exploit", 0.9, 1, false, 1800);
		}

		const demoteDecision = recommendAdaptiveModelRoute(loadCalibrationRecords(root), {
			allowedModels: allowed,
			defaultModel: "gemini-4-hydrogen-xhigh",
			taskCategory: "exploit",
			minSamples: 5,
		});
		expect(demoteDecision.coldStart).toBe(false);
		expect(demoteDecision.downgraded).toBe(true);
		expect(demoteDecision.demotedModels).toContain("gemini-4-hydrogen-xhigh");
		// 同等健康指标下优先推荐同家族（gemini）候选 gemini-4-neon-xhigh，且绝对不推荐白名单外的 external-god-model！
		expect(demoteDecision.recommendedModel).toBe("gemini-4-neon-xhigh");
		expect(demoteDecision.reason).toContain("误报率过高");
		expect(demoteDecision.reason).toContain("同家族");

		// 4. 低 ROI 模型自动降权测试 + 故意传入不在 allowedModels 内的越界 defaultModel 护栏测试
		for (let i = 0; i < 6; i++) {
			// model-token-burner: 零误报但每次烧 80,000 tokens 且 0 产出 -> ROI 极低触发降权
			addSample("qwen-burner", "auth", 0.4, 0, false, 80000);
			addSample("qwen-efficient", "auth", 0.9, 1, false, 1600);
		}
		const strictWhitelist = ["qwen-burner", "qwen-efficient"] as const;
		const lowRoiDecision = recommendAdaptiveModelRoute(loadCalibrationRecords(root), {
			allowedModels: strictWhitelist,
			defaultModel: "outside-unlisted-model", // 故意越界传入 defaultModel！
			taskCategory: "auth",
			minSamples: 5,
		});
		expect(strictWhitelist.includes(lowRoiDecision.recommendedModel as any)).toBe(true);
		expect(lowRoiDecision.recommendedModel).toBe("qwen-efficient");
		expect(lowRoiDecision.downgraded).toBe(true);
		expect(lowRoiDecision.reason).toContain("ROI过低");
		expect(lowRoiDecision.reason).toContain("白名单");
	});

	test("Boost 回归测试（belief-search）：菱形 DAG 不动点剪枝、WAF 同前缀 Peer/高后验根子图扫描、空状态防误封盘与 priority=0 单调性", () => {
		const ts = "2026-11-25T12:00:00.000Z";

		// 1. P1-1 回归：菱形 DAG 多父节点汇合剪枝（fA.childIds = ["iC", "iB"]，iC 同时依赖 fA 与 iB）
		const stDag = createMockState();
		stDag.facts.fA = { id: "fA", kind: "endpoint", title: "入口 A", detail: "低后验根", createdAt: ts };
		stDag.intents.iB = {
			id: "iB",
			phase: "vuln",
			key: "vuln:b",
			title: "中间节点 B",
			detail: "依赖 fA",
			from: ["fA"],
			status: "open",
			priority: 85,
			attempts: 0,
			createdAt: ts,
		};
		stDag.intents.iC = {
			id: "iC",
			phase: "exploit",
			key: "exploit:c",
			title: "汇合节点 C",
			detail: "同时依赖 fA 与 iB",
			from: ["fA"],
			status: "open",
			priority: 90,
			attempts: 0,
			createdAt: ts,
		};
		const gDag = initBeliefGraphFromState(stDag);
		// 强制构造 fA -> iC 在前、fA -> iB 在后，且 iB -> iC 的菱形拓扑
		gDag.nodes.fA!.alpha = 0.2;
		gDag.nodes.fA!.beta = 5.0;
		gDag.nodes.fA!.posterior = computeBetaPosterior(0.2, 5.0); // ~0.038 < 0.2
		gDag.nodes.fA!.childIds = ["iC", "iB"];
		gDag.nodes.iB!.parentIds = ["fA"];
		gDag.nodes.iB!.childIds = ["iC"];
		gDag.nodes.iC!.parentIds = ["fA", "iB"];

		const dagPrune = pruneLowYieldSubtree(gDag, stDag, 0.2);
		expect(gDag.nodes.fA!.pruned).toBe(true);
		expect(gDag.nodes.iB!.pruned).toBe(true);
		expect(gDag.nodes.iC!.pruned).toBe(true);
		expect(dagPrune.blockableOpenIntentIds).toEqual(["iB", "iC"]);

		// 2. P1-2a 回归：WAF 同路径前缀独立 Peer（from=[] 不在 childIds 内）及下游必须同步剪枝
		const stWaf = createMockState();
		stWaf.facts.fAdmin = {
			id: "fAdmin",
			kind: "endpoint",
			title: "管理根路径",
			detail: "/admin",
			targetKey: "path:/admin",
			surfaceDomain: "path",
			createdAt: ts,
		};
		stWaf.intents.iPeer = {
			id: "iPeer",
			phase: "vuln",
			key: "vuln:admin:secret",
			title: "独立同前缀探测 /admin/secret",
			detail: "from 为空但共享受阻路径前缀",
			from: [],
			targetKey: "path:/admin/secret",
			surfaceDomain: "path",
			status: "open",
			priority: 55,
			attempts: 0,
			createdAt: ts,
		};
		const gWaf = initBeliefGraphFromState(stWaf);
		const wafProp = propagateBeliefUpdate(gWaf, stWaf, {
			nodeId: "fAdmin",
			observation: "waf_block",
			reason: "WAF 拦截 /admin 前缀",
		});
		expect(gWaf.nodes.iPeer!.posterior).toBeLessThan(0.2);
		expect(gWaf.nodes.iPeer!.pruned).toBe(true);
		expect(wafProp.blockableOpenIntentIds).toContain("iPeer");

		// 3. P1-2b 回归：指定高后验 rootNodeId 时，仍能完整扫描可达子图剪枝低后验子节点
		const stSub = createMockState();
		stSub.facts.fHighRoot = {
			id: "fHighRoot",
			kind: "cred",
			title: "高后验根事实",
			detail: "confirmed",
			createdAt: ts,
		};
		stSub.intents.iLowChild = {
			id: "iLowChild",
			phase: "vuln",
			key: "vuln:low",
			title: "低后验子意图",
			detail: "依赖 fHighRoot",
			from: ["fHighRoot"],
			status: "open",
			priority: 20,
			attempts: 5,
			createdAt: ts,
		};
		const gSub = initBeliefGraphFromState(stSub);
		expect(gSub.nodes.fHighRoot!.posterior).toBeGreaterThan(0.7);
		expect(gSub.nodes.iLowChild!.posterior).toBeLessThan(0.2);
		const subPrune = pruneLowYieldSubtree(gSub, stSub, 0.2, { rootNodeId: "fHighRoot" });
		expect(gSub.nodes.fHighRoot!.pruned).toBe(false);
		expect(gSub.nodes.iLowChild!.pruned).toBe(true);
		expect(subPrune.blockableOpenIntentIds).toEqual(["iLowChild"]);

		// 4. P1-3 回归：全新空状态与零停滞阶段切换间隙严禁误报 seal_negative
		const emptyState = createMockState();
		const emptyPivot = recommendSearchPivot(emptyState);
		expect(emptyPivot.recommendSeal).toBe(false);
		expect(emptyPivot.action).not.toBe("seal_negative");
		expect(emptyPivot.negativeSealConfidence).toBe(0);

		const zeroStallDoneState = createMockState();
		zeroStallDoneState.runtime.noveltyStall = 0;
		zeroStallDoneState.runtime.completionRejects = 0;
		zeroStallDoneState.intents.iDone = {
			id: "iDone",
			phase: "recon",
			key: "recon:seed",
			title: "刚完成的侦察意图",
			detail: "零停滞",
			from: [],
			status: "done",
			priority: 60,
			attempts: 1,
			createdAt: ts,
		};
		const zeroStallPivot = recommendSearchPivot(zeroStallDoneState);
		expect(zeroStallPivot.recommendSeal).toBe(false);
		expect(zeroStallPivot.action).not.toBe("seal_negative");
		// 已 done 历史节点不应污染 pruneSuggestions
		expect(zeroStallPivot.pruneSuggestions.some((s) => s.nodeId === "iDone")).toBe(false);

		// 5. P2-1 & P2-2 回归：priority=0 严格低于 priority=20，且 verify_candidates 分支备选列表不重复
		const stPrio = createMockState();
		stPrio.facts.fCand = {
			id: "fCand",
			kind: "vuln",
			title: "待复验候选",
			detail: "candidate",
			verifyStage: "candidate",
			createdAt: ts,
		};
		stPrio.intents.iZero = {
			id: "iZero",
			phase: "surface",
			key: "surface:p0",
			title: "零优先级任务",
			detail: "priority=0",
			from: [],
			status: "open",
			priority: 0,
			attempts: 0,
			createdAt: ts,
		};
		stPrio.intents.iTwenty = {
			id: "iTwenty",
			phase: "surface",
			key: "surface:p20",
			title: "低优先级任务 20",
			detail: "priority=20",
			from: [],
			status: "open",
			priority: 20,
			attempts: 0,
			createdAt: ts,
		};
		stPrio.intents.iTop = {
			id: "iTop",
			phase: "exploit",
			key: "exploit:top",
			title: "极高加成任务",
			detail: "排首位测试",
			from: [],
			status: "open",
			priority: 99,
			attempts: 0,
			createdAt: ts,
		};
		stPrio.intents.iVerify = {
			id: "iVerify",
			phase: "vuln",
			key: "verify-vuln:fCand",
			title: "双盲复验任务",
			detail: "排第二测试去重",
			from: ["fCand"],
			status: "open",
			priority: 10,
			attempts: 2,
			createdAt: ts,
		};
		const gPrio = initBeliefGraphFromState(stPrio);
		gPrio.nodes.iTop!.breakthroughBoost = 0.6;
		const rankedPrio = rankFrontierByBelief(stPrio, [stPrio.intents.iZero!, stPrio.intents.iTwenty!], {
			graph: gPrio,
		});
		expect(rankedPrio[0]!.intent.id).toBe("iTwenty");
		expect(rankedPrio[1]!.intent.id).toBe("iZero");
		expect(rankedPrio[1]!.priorityScore).toBe(0);

		const candPivot = recommendSearchPivot(stPrio, gPrio);
		expect(candPivot.action).toBe("verify_candidates");
		expect(candPivot.topDirection?.intentId).toBe("iVerify");
		expect(candPivot.alternativeDirections.some((d) => d.intentId === "iVerify")).toBe(false);
		expect(candPivot.alternativeDirections.some((d) => d.intentId === "iTop")).toBe(true);
	});

	test("Boost 回归测试（calibration）：非字符串结算源拦截、内存直传 NaN/self 防崩溃防污染与 JSON 引号密钥脱敏", () => {
		// 1. P1-4c 回归：数组与自定义 toString 对象不得绕过 validateSettlementSource
		for (const nonStr of [["verifier-gate"], { toString: () => "verifier-gate" }, 123, true, null, undefined]) {
			expect(() => validateSettlementSource(nonStr)).toThrow(CalibrationError);
		}

		// 2. P1-4a & P1-4b 回归：内存直传 NaN/Infinity 置信度不崩溃，且内存直传 self/未知源记录不污染汇总与路由
		const pollutedRecords: any[] = [
			{
				predictionId: "nan-1",
				intentId: "i1",
				taskCategory: "exploit",
				modelId: "gemini-clean",
				predictedConfidence: Number.NaN,
				estimatedTokens: 1000,
				createdAt: "2026-11-25T12:00:00Z",
				settled: true,
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 1000,
				durationMs: 200,
				source: "verifier-gate",
			},
			// 注入 6 条伪造 source="self" 的误报记录企图拉垮 gemini-clean
			...Array.from({ length: 6 }, (_, idx) => ({
				predictionId: `self-fake-${idx}`,
				intentId: `i-fake-${idx}`,
				taskCategory: "exploit",
				modelId: "gemini-clean",
				predictedConfidence: 0.95,
				estimatedTokens: 1000,
				createdAt: "2026-11-25T12:00:00Z",
				settled: true,
				outcome: 0,
				isFalsePositive: true,
				actualTokens: 1000,
				durationMs: 200,
				source: "self",
			})),
			// 注入 6 条真实 verifier-gate 实锤记录
			...Array.from({ length: 6 }, (_, idx) => ({
				predictionId: `real-ok-${idx}`,
				intentId: `i-ok-${idx}`,
				taskCategory: "exploit",
				modelId: "gemini-clean",
				predictedConfidence: 0.9,
				estimatedTokens: 1200,
				createdAt: "2026-11-25T12:00:00Z",
				settled: true,
				outcome: 1,
				isFalsePositive: false,
				actualTokens: 1200,
				durationMs: 300,
				source: "verifier-gate",
			})),
		];

		const summary = computeCalibrationSummary(pollutedRecords);
		expect(summary.global.settledCount).toBe(6);
		expect(summary.global.falsePositiveCount).toBe(0);
		expect(summary.byModel["gemini-clean"]!.settledCount).toBe(6);
		expect(summary.byModel["gemini-clean"]!.falsePositiveRate).toBe(0);

		const route = recommendAdaptiveModelRoute(pollutedRecords, {
			allowedModels: ["gemini-clean", "gemini-alt"],
			defaultModel: "gemini-clean",
			taskCategory: "exploit",
			minSamples: 5,
		});
		expect(route.downgraded).toBe(false);
		expect(route.recommendedModel).toBe("gemini-clean");

		// 3. P2-3 回归：JSON 双引号/单引号包裹的密码与密钥及 URL userinfo 必须彻底脱敏
		const rawJsonSecret =
			'payload={"password":"MySuperSecretPassword999","api_key":"abc123456789xyz"} url=https://admin:UrlInlinePass888@corp.local/api';
		const redacted = redactCalibrationText(rawJsonSecret);
		expect(redacted).not.toContain("MySuperSecretPassword999");
		expect(redacted).not.toContain("abc123456789xyz");
		expect(redacted).not.toContain("UrlInlinePass888");
		expect(redacted).toContain('"password":');
		expect(redacted).toContain('"api_key":');
	});
});
