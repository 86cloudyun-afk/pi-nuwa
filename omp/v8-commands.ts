/**
 * 女娲 v8.0.0 全栈协议/路由/RGS 斜杠命令与 SQLite v2 持久化接线编排器。
 *
 * 职责：
 * 1. 实现 `/nuwa proto`、`/nuwa pivot`、`/nuwa rgs` 三个 v8 新增子命令：
 *    - 严守红线：所有只读子命令（默认/status/frames/routes/scan）在未初始化目录或遗留纯 `state.json` 目录下
 *      严格保持 **0 字节磁盘写入**（不创建 `.nuwa`、不创建 `nuwa.db`/`-wal`/`-shm`、不改写 `mtime`）。
 * 2. 提供 SQLite Schema v2 四张扩展表（`protocol_frames`、`asset_credentials`、`oob_correlations`、`workflow_runs`）
 *    的安全落库与只读汇总桥接函数，供 `cdp-bridge`、`traffic-workbench`、`auto-loops`、`oob`、`hybrid-audit` 调用。
 *
 * 约束：单向无环模块，严禁运行时 `import "./nuwa"` 或 `import "./graph"`。
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import {
	resolveAssetRoutePlan,
	verifyCredentialPivot,
	type AssetRoutePlan,
	type CredentialCandidateTarget,
	type CredentialSpec,
	type VerifyCredentialPivotResult,
} from "./asset-router";
import { generateTotpCode } from "./cdp-auth";
import { appendIntentSpecs } from "./graph-planner";
import { addHypothesis, syncAssetsFromFacts } from "./hypothesis";
import { inspectGraphQLSchema } from "./protocol-inspector";
import {
	analyzeCrossFileRgs,
	bridgeRgsToVerificationIntents,
	writeStandalonePovScript,
} from "./rgs-analyzer";
import type { OobCorrelationResult } from "./resilience-oob";
import { defaultScopeForTarget } from "./scope";
import { getRoleHeadersMap, loadSessionVault } from "./session-vault";
import {
	NuwaSqliteStore,
	loadStateFromSqlite,
	redactTextForStorage,
	sqliteDbPath,
	type AssetCredentialRow,
	type OobCorrelationRow,
	type ProtocolFrameRow,
	type WorkflowRunRow,
} from "./sqlite-store";
import type { StatefulWorkflowResult } from "./stateful-workflow";
import {
	SCHEMA,
	bindLoadedStateRoot,
	journalPath,
	loadState,
	normalizeState,
	nowIso,
	readJson,
	resolveStorageBackend,
	saveState,
	statePath,
	withLock,
} from "./storage";
import type { AssetNode, NuwaState, ScopePolicy } from "./types";

export interface V8CommandResult {
	msg: string;
	level: "info" | "error";
}

function isTerminalState(st: NuwaState | null | undefined): boolean {
	if (!st) return false;
	return (
		st.project.status === "completed" ||
		st.project.status === "sealed_negative" ||
		st.runtime?.status === "completed" ||
		st.runtime?.status === "sealed_negative"
	);
}

/** 纯只读加载项目状态：绝不调用 `loadStateJsonOnly` 或 `atomicWrite`，即使 `state.json` 损坏且存在 `.nuwa/snap` 快照也严格 0 字节写盘。 */
export function loadStateZeroWriteV8(root: string | null | undefined): NuwaState | null {
	if (!root) return null;
	const normRoot = resolve(root);
	const backend = resolveStorageBackend(normRoot);
	const dbFile = sqliteDbPath(normRoot);

	if ((backend === "sqlite" || backend === "dual") && existsSync(dbFile)) {
		try {
			if (statSync(dbFile).size > 0) {
				const sqlSt = loadStateFromSqlite(normRoot, { fallbackToJson: false });
				if (sqlSt) return bindLoadedStateRoot(normalizeState(sqlSt), normRoot);
			}
		} catch {
			/* 回退纯内存只读 JSON */
		}
	}

	const sp = statePath(normRoot);
	if (existsSync(sp)) {
		const direct = readJson<NuwaState>(sp);
		if (direct && direct.schema === SCHEMA && direct.project) {
			const cloned = JSON.parse(JSON.stringify(direct)) as NuwaState;
			return bindLoadedStateRoot(normalizeState(cloned), normRoot);
		}
	}

	if (existsSync(dbFile)) {
		try {
			if (statSync(dbFile).size > 0) {
				const fbSql = loadStateFromSqlite(normRoot, { fallbackToJson: false });
				if (fbSql) return bindLoadedStateRoot(normalizeState(fbSql), normRoot);
			}
		} catch {
			/* ignore */
		}
	}

	const jp = journalPath(normRoot);
	if (existsSync(jp)) {
		try {
			const lines = readFileSync(jp, "utf8").trim().split("\n").reverse();
			for (const line of lines) {
				if (!line) continue;
				const parsed = JSON.parse(line) as { type?: string; state?: NuwaState };
				if (parsed.type === "snapshot" && parsed.state?.schema === SCHEMA && parsed.state.project) {
					const cloned = JSON.parse(JSON.stringify(parsed.state)) as NuwaState;
					return bindLoadedStateRoot(normalizeState(cloned), normRoot);
				}
			}
		} catch {
			/* ignore */
		}
	}
	return null;
}

function isNuwaProtectedPath(targetPath: string): boolean {
	const norm = String(targetPath ?? "").replace(/\\/g, "/");
	return /(?:^|\/)\.nuwa(?:\/|$)/i.test(norm);
}

function resolveRgsTargetDir(rawToken: string | undefined, root: string | null | undefined, st: NuwaState | null): string {
	if (rawToken && rawToken.trim()) {
		const trimmed = rawToken.trim();
		if (isAbsolute(trimmed)) return resolve(trimmed);
		if (root) {
			const relToRoot = resolve(root, trimmed);
			if (existsSync(relToRoot) || isNuwaProtectedPath(relToRoot)) return relToRoot;
		}
		return resolve(trimmed);
	}
	if (st?.project.scheme === "local" && st.project.target) {
		return resolve(st.project.target);
	}
	return root ? resolve(root) : "";
}

function resolveCandidateScheme(asset: AssetNode, projectScheme?: string): string {
	const assetScheme = (asset as { scheme?: string }).scheme;
	if (assetScheme === "http" || assetScheme === "https") return assetScheme;
	return projectScheme === "https" ? "https" : "http";
}

function withReadonlySqliteStore<T>(root: string | null | undefined, fn: (store: NuwaSqliteStore) => T, fallback: T): T {
	if (!root) return fallback;
	const normRoot = resolve(root);
	const dbFile = sqliteDbPath(normRoot);
	try {
		if (!existsSync(dbFile) || statSync(dbFile).size <= 0) return fallback;
	} catch {
		return fallback;
	}
	let store: NuwaSqliteStore | null = null;
	try {
		store = new NuwaSqliteStore(normRoot, { readonly: true });
		return fn(store);
	} catch {
		return fallback;
	} finally {
		store?.close();
	}
}

function canWriteSqlite(root: string): boolean {
	const backend = resolveStorageBackend(root);
	return backend === "sqlite" || backend === "dual";
}

/** 安全记录协议帧审计行至 SQLite `protocol_frames`（JSON 模式下安全跳过，零异常）。 */
export function recordProtocolAuditFrame(root: string | undefined, frame: ProtocolFrameRow): boolean {
	if (!root || !canWriteSqlite(root)) return false;
	let store: NuwaSqliteStore | null = null;
	try {
		store = new NuwaSqliteStore(resolve(root));
		store.upsertProtocolFrame(frame);
		return true;
	} catch {
		return false;
	} finally {
		store?.close();
	}
}

/** 安全记录有状态工作流运行摘要至 SQLite `workflow_runs`。 */
export function recordStatefulWorkflowSummary(
	root: string | undefined,
	runId: string,
	workflowKind: string,
	targetUrl: string,
	wfRes: StatefulWorkflowResult,
	extra?: { role?: string; intentId?: string; candidateFactId?: string; cleanupExecuted?: boolean },
): boolean {
	if (!root || !canWriteSqlite(root)) return false;
	let store: NuwaSqliteStore | null = null;
	try {
		const highestTier = wfRes.steps.reduce<WorkflowRunRow["actionLevel"]>((acc, step) => {
			const order: Record<string, number> = {
				L0_PHYSICAL_READ: 0,
				L1_SEMANTIC_READ: 1,
				L2_SCOPED_STATEFUL: 2,
				L3_RESTRICTED_DESTRUCTIVE: 3,
			};
			return (order[step.tier] ?? 0) > (order[acc] ?? 0) ? step.tier : acc;
		}, "L0_PHYSICAL_READ");
		const brokenIdx = wfRes.steps.findIndex((s) => !s.ok);
		store = new NuwaSqliteStore(resolve(root));
		store.upsertWorkflowRun({
			runId,
			workflowKind,
			actionLevel: highestTier,
			intentId: extra?.intentId,
			targetUrl,
			role: extra?.role,
			status: wfRes.blocked ? "blocked" : wfRes.ok ? "passed" : "failed",
			stepCount: wfRes.steps.length,
			...(brokenIdx >= 0 ? { brokenAtStep: brokenIdx } : {}),
			cleanupExecuted: Boolean(extra?.cleanupExecuted),
			...(extra?.candidateFactId ? { candidateFactId: extra.candidateFactId } : {}),
			startedAt: nowIso(),
			finishedAt: nowIso(),
			summary: wfRes.error ?? `steps=${wfRes.steps.length} requests=${wfRes.totalRequests} ok=${wfRes.ok}`,
			steps: wfRes.steps.map((s) => ({
				id: s.id,
				method: s.method,
				url: s.resolvedUrl,
				status: s.status,
				ok: s.ok,
				tier: s.tier,
			})),
		});
		return true;
	} catch {
		return false;
	} finally {
		store?.close();
	}
}

/** 将跨资产凭据验证结果脱敏持久化至 SQLite `asset_credentials` 表。 */
export function recordPivotCredentialResults(
	root: string | undefined,
	pivotRes: VerifyCredentialPivotResult,
): number {
	if (!root || !canWriteSqlite(root) || pivotRes.results.length === 0) return 0;
	let store: NuwaSqliteStore | null = null;
	let count = 0;
	try {
		store = new NuwaSqliteStore(resolve(root));
		const ts = pivotRes.generatedAt || nowIso();
		for (const item of pivotRes.results) {
			let parsedPort: number | undefined;
			try {
				const u = new URL(item.target);
				if (u.port) parsedPort = Number(u.port);
			} catch {
				/* ignore */
			}
			const statusMap: Record<string, AssetCredentialRow["status"]> = {
				valid: "valid",
				invalid: "rejected",
				blocked_by_scope: "scope_blocked",
				soft_404: "rejected",
				no_difference: "rejected",
				error: "unverified",
			};
			store.upsertAssetCredential({
				id: `ac-${item.role}-${item.host}-${parsedPort ?? 0}`,
				assetId: item.assetId ?? `host:${item.host}`,
				host: item.host,
				...(parsedPort ? { port: parsedPort } : {}),
				role: item.role,
				credKind: "session",
				credFingerprint: `${item.role}@${item.host}:${item.authHash ?? "none"}`,
				status: statusMap[item.status] ?? "unverified",
				verifiedEndpoint: item.target,
				...(item.authStatus !== undefined ? { verifiedStatusCode: item.authStatus } : {}),
				lastVerifiedAt: ts,
				createdAt: ts,
				updatedAt: ts,
				extra: {
					diffScore: item.diffScore,
					reason: item.reason,
					soft404: Boolean(item.soft404),
				},
			});
			count += 1;
		}
		return count;
	} catch {
		return count;
	} finally {
		store?.close();
	}
}

/** 将延迟回调因果关联命中持久化至 SQLite `oob_correlations` 表。 */
export function recordOobCorrelationMatches(
	root: string | undefined,
	corrRes: OobCorrelationResult,
): number {
	if (!root || !canWriteSqlite(root) || corrRes.matches.length === 0) return 0;
	let store: NuwaSqliteStore | null = null;
	let count = 0;
	try {
		store = new NuwaSqliteStore(resolve(root));
		for (const m of corrRes.matches) {
			const row: OobCorrelationRow = {
				canaryId: m.canaryId,
				projectId: m.projectId,
				...(m.intentId ? { intentId: m.intentId } : {}),
				endpoint: m.endpoint ?? "/",
				...(m.paramName ? { paramName: m.paramName } : {}),
				...(m.templateHash ? { templateHash: m.templateHash } : {}),
				...(m.authRole ? { authRole: m.authRole } : {}),
				channel: m.protocols[0] ?? "http",
				tokenSig: m.evidenceHash,
				status: "correlated",
				callbackTs: m.lastSeenAt,
				...(m.remoteAddresses[0] ? { callbackSourceIp: m.remoteAddresses[0] } : {}),
				callbackDetail: m.summary,
				createdAt: m.firstSeenAt || nowIso(),
				extra: {
					hitCount: m.hitCount,
					paths: m.paths,
					protocols: m.protocols,
				},
			};
			store.upsertOobCorrelation(row);
			count += 1;
		}
		return count;
	} catch {
		return count;
	} finally {
		store?.close();
	}
}

/**
 * `/nuwa proto [status | frames [limit] | graphql [url] | totp <secret>]`
 * - 默认 / `status` / `frames` 为严格纯只读视图：未初始化目录或遗留 `state.json`-only 目录 100% 零磁盘写入。
 */
export async function executeProtoCommand(root: string | null, rawSubArgs: string): Promise<V8CommandResult> {
	const sub = (rawSubArgs ?? "").trim();
	const tokens = sub.split(/\s+/).filter(Boolean);
	const action = (tokens[0] ?? "status").toLowerCase();

	if (action === "status" || action === "list" || action === "frames") {
		const st = loadStateZeroWriteV8(root);
		const limit = Math.max(1, Math.min(50, Number(tokens[1]) || 10));
		const dbSummary = withReadonlySqliteStore(
			root,
			(store) => ({
				frames: store.listProtocolFrames({ limit }),
				workflows: store.listWorkflowRuns({ limit: 5 }),
			}),
			{ frames: [] as ProtocolFrameRow[], workflows: [] as WorkflowRunRow[] },
		);

		if (!st) {
			return {
				level: "info",
				msg: [
					"[协议审计栈 /nuwa proto] 状态: 待命（当前目录未初始化项目，只读零写入模式）",
					"已就绪引擎: GraphQL (内省/建议还原/批量别名) · WebSocket 双向帧对比 · Next.js RSC Flight · gRPC-Web Protobuf · CDP TOTP/加签探针",
					"用法: /nuwa proto [status | frames [limit] | graphql [url]]",
				].join("\n"),
			};
		}

		const frameLines = dbSummary.frames.map(
			(f) =>
				`  - [${f.protocol}] ${f.direction} ${f.url}${f.operationName ? ` op=${f.operationName}` : ""}${f.status ? ` status=${f.status}` : ""}${f.anomalyTag ? ` tag=${f.anomalyTag}` : ""}`,
		);
		return {
			level: "info",
			msg: [
				`[协议审计栈 /nuwa proto] 项目=${st.project.id} · 目标=${st.project.url || st.project.target} · 模式=${st.project.mode}`,
				`记录统计: protocol_frames=${dbSummary.frames.length} · workflow_runs=${dbSummary.workflows.length}`,
				...(frameLines.length > 0 ? ["最近协议帧:", ...frameLines] : ["最近协议帧: (暂无记录)"]),
			].join("\n"),
		};
	}

	if (action === "totp") {
		const secretInput = tokens[1] ?? "";
		if (!secretInput) {
			return { level: "error", msg: "用法: /nuwa proto totp <base32SecretOrOtpAuthUri>" };
		}
		try {
			const res = generateTotpCode(secretInput);
			return {
				level: "info",
				msg: `RFC 6238 TOTP 生成就绪: digits=${res.digits} period=${res.period}s remaining=${res.remainingSeconds}s code=${res.code}`,
			};
		} catch (e) {
			return { level: "error", msg: `TOTP 计算失败: ${e instanceof Error ? e.message : String(e)}` };
		}
	}

	if (action === "graphql") {
		if (!root) return { level: "error", msg: "当前目录没有女娲项目，无法执行 GraphQL 探测落库" };
		const st = loadStateZeroWriteV8(root);
		if (!st) return { level: "error", msg: "state 读取失败" };
		if (isTerminalState(st)) {
			return { level: "error", msg: `该项目已处于终态 (${st.project.status})，禁止执行 /nuwa proto graphql 写操作` };
		}
		const baseUrl = st.project.url || st.project.target;
		const endpointUrl = tokens[1] || `${baseUrl.replace(/\/+$/, "")}/graphql`;
		const vault = loadSessionVault(root);
		const safeEndpointUrl = redactTextForStorage(endpointUrl, vault) ?? endpointUrl;
		const scope: ScopePolicy = st.project.scope ?? defaultScopeForTarget(baseUrl, st.project.mode);
		const inspected = await inspectGraphQLSchema(endpointUrl, scope, { root, mode: st.project.mode });
		if (inspected.blockedByScope) {
			const safeBlockReason = redactTextForStorage(inspected.blockReason ?? endpointUrl, vault) ?? safeEndpointUrl;
			return { level: "error", msg: `GraphQL 探测被 Scope 拦截: ${safeBlockReason}` };
		}
		let host = st.project.host || "127.0.0.1";
		try {
			host = new URL(endpointUrl).hostname;
		} catch {
			/* ignore */
		}
		recordProtocolAuditFrame(root, {
			id: `pf-gql-${Date.now()}`,
			ts: nowIso(),
			protocol: "graphql",
			direction: "response",
			url: endpointUrl,
			host,
			operationName: inspected.introspectionEnabled ? "__schema" : "field_suggestion",
			status: inspected.ok ? 200 : 400,
			schemaSummary: {
				introspectionEnabled: inspected.introspectionEnabled,
				queries: inspected.discoveredQueries.slice(0, 30),
				mutations: inspected.discoveredMutations.slice(0, 30),
			},
		});
		return {
			level: inspected.ok ? "info" : "error",
			msg: `GraphQL 探测完成 (${safeEndpointUrl}): introspection=${inspected.introspectionEnabled} queries=${inspected.discoveredQueries.length} mutations=${inspected.discoveredMutations.length}`,
		};
	}

	return { level: "error", msg: "用法: /nuwa proto [status | frames [limit] | graphql [url] | totp <secret>]" };
}

/**
 * `/nuwa pivot [status | routes | verify]`
 * - 默认 / `status` / `routes` 为严格纯只读视图：未初始化或遗留 `state.json`-only 目录 100% 零磁盘写入。
 */
export async function executePivotCommand(root: string | null, rawSubArgs: string): Promise<V8CommandResult> {
	const sub = (rawSubArgs ?? "").trim();
	const tokens = sub.split(/\s+/).filter(Boolean);
	const action = (tokens[0] ?? "status").toLowerCase();

	if (action === "status" || action === "routes" || action === "list") {
		const st = loadStateZeroWriteV8(root);
		if (!st) {
			return {
				level: "info",
				msg: [
					"[资产路由与韧性栈 /nuwa pivot] 状态: 待命（当前目录未初始化项目，只读零写入模式）",
					"已就绪组件: AssetRouter 公私网双轨分流 · 跨资产凭据校验 · GatewayAdaptiveController · IsomorphicTrapDetector · EmbeddedOobListener",
					"用法: /nuwa pivot [status | routes | verify]",
				].join("\n"),
			};
		}

		const assets = Object.values(st.assets ?? {});
		const plan: AssetRoutePlan = resolveAssetRoutePlan({ assets });
		const ledger = withReadonlySqliteStore(
			root,
			(store) => ({
				creds: store.listAssetCredentials({ limit: 20 }),
				oob: store.listOobCorrelations({ limit: 20 }),
			}),
			{ creds: [] as AssetCredentialRow[], oob: [] as OobCorrelationRow[] },
		);

		const routeLines = plan.entries.slice(0, 15).map(
			(e) =>
				`  - ${e.assetId} (${e.host}) -> route=${e.route}${e.cycleDetected ? " [CYCLE]" : ""} (${e.reason})`,
		);
		return {
			level: "info",
			msg: [
				`[资产路由与韧性栈 /nuwa pivot] 项目=${st.project.id} · 资产总数=${assets.length}`,
				`路由分流: direct=${plan.directCount} · proxy=${plan.proxyCount} · socks5h=${plan.socksCount} · blocked=${plan.blockedCount} · cycles=${plan.cycles.length}`,
				`台账统计: asset_credentials=${ledger.creds.length} · oob_correlations=${ledger.oob.length}`,
				...(routeLines.length > 0 ? ["路由明细:", ...routeLines] : ["路由明细: (暂无已登记资产)"]),
			].join("\n"),
		};
	}

	if (action === "verify") {
		if (!root) return { level: "error", msg: "当前目录没有女娲项目，无法执行跨资产凭据验证" };
		const preSt = loadStateZeroWriteV8(root);
		if (!preSt) return { level: "error", msg: "state 读取失败" };
		if (isTerminalState(preSt)) {
			return { level: "error", msg: `该项目已处于终态 (${preSt.project.status})，禁止执行 /nuwa pivot verify` };
		}
		const vault = loadSessionVault(root);
		const credentials: CredentialSpec[] = Object.keys(vault.roles).map((role) => {
			const hdrs = getRoleHeadersMap(vault, role);
			return {
				role,
				...(hdrs ? { headers: hdrs } : {}),
			};
		});
		const candidates: CredentialCandidateTarget[] = Object.values(preSt.assets ?? {})
			.filter((a) => typeof a.host === "string" && a.host.length > 0)
			.map((a) => ({
				host: a.host!,
				...(a.port ? { port: a.port } : {}),
				scheme: resolveCandidateScheme(a, preSt.project.scheme),
				path: "/",
				assetId: a.id,
			}));
		if (credentials.length === 0 || candidates.length === 0) {
			return {
				level: "info",
				msg: `跨资产凭据验证跳过: roles=${credentials.length} assets=${candidates.length}（需至少 1 个角色与 1 个资产）`,
			};
		}
		const scope = preSt.project.scope ?? defaultScopeForTarget(preSt.project.url || preSt.project.target, preSt.project.mode);
		const pivotRes = await verifyCredentialPivot({
			root,
			projectId: preSt.project.id,
			scope,
			mode: preSt.project.mode,
			credentials,
			candidates,
		});
		const saved = recordPivotCredentialResults(root, pivotRes);
		return {
			level: "info",
			msg: `跨资产凭据验证完成: validReuses=${pivotRes.validReuses.length} blocked=${pivotRes.blockedTargets.length} persisted=${saved}`,
		};
	}

	return { level: "error", msg: "用法: /nuwa pivot [status | routes | verify]" };
}

/**
 * `/nuwa rgs [status | scan [dir] | plan [dir] | pov <factId>]`
 * - 默认 / `status` / `scan` 为严格纯只读视图：未初始化或遗留 `state.json`-only 目录 100% 零磁盘写入。
 */
export function executeRgsCommand(root: string | null, rawSubArgs: string): V8CommandResult {
	const sub = (rawSubArgs ?? "").trim();
	const tokens = sub.split(/\s+/).filter(Boolean);
	const action = (tokens[0] ?? "status").toLowerCase();

	if (action === "status") {
		const st = loadStateZeroWriteV8(root);
		if (!st) {
			return {
				level: "info",
				msg: [
					"[跨文件 RGS 代码图谱与独立复核栈 /nuwa rgs] 状态: 待命（当前目录未初始化项目，只读零写入模式）",
					"支持语言: TypeScript · JavaScript · Python · Go · Java · PHP · Rust · SPA Bundle/SourceMap",
					"用法: /nuwa rgs [status | scan <dir> | plan [dir] | pov <factId>]",
				].join("\n"),
			};
		}
		const confirmedCount = Object.values(st.facts ?? {}).filter(
			(f) => f.kind === "vuln" && f.verifyStage === "confirmed",
		).length;
		return {
			level: "info",
			msg: [
				`[跨文件 RGS 代码图谱 /nuwa rgs] 项目=${st.project.id} · 模式=${st.project.mode} · confirmed=${confirmedCount}`,
				"用法: /nuwa rgs scan <dir>（只读扫描） | /nuwa rgs plan [dir]（派生验证意图） | /nuwa rgs pov <factId>（生成零明文独立脚本）",
			].join("\n"),
		};
	}

	if (action === "scan") {
		const st = loadStateZeroWriteV8(root);
		const targetDir = resolveRgsTargetDir(tokens[1], root, st);
		if (isNuwaProtectedPath(targetDir)) {
			return { level: "error", msg: `[N-003] 安全护栏阻断：禁止扫描或读取 .nuwa 内部状态与会话凭据目录 (${targetDir})` };
		}
		if (!targetDir || !existsSync(targetDir)) {
			return { level: "error", msg: "用法: /nuwa rgs scan <源码目录路径>" };
		}
		let graph;
		try {
			graph = analyzeCrossFileRgs(targetDir);
		} catch (e) {
			return { level: "error", msg: `RGS 扫描被拒绝: ${e instanceof Error ? e.message : String(e)}` };
		}
		const topUnauth = graph.unauthenticatedRoutes.slice(0, 10).map(
			(r) => `  - [${r.framework}] ${r.method} ${r.path} (${r.anchor}) flags=[${r.riskFlags.join(",")}]`,
		);
		return {
			level: "info",
			msg: [
				`[RGS 只读跨文件分析] 目录=${targetDir} · 扫描文件=${graph.scannedFiles}`,
				`统计: routes=${graph.summary.totalRoutes} · guarded=${graph.summary.guardedRoutes} · unauth=${graph.summary.unauthenticatedRoutes} · suppressed=${graph.summary.suppressedFalsePositives} · sinks=${graph.summary.totalSinks} · chains=${graph.summary.crossFileChains} · bundleEndpoints=${graph.summary.bundleEndpoints}`,
				...(topUnauth.length > 0 ? ["待复核未受保护路由:", ...topUnauth] : ["待复核未受保护路由: (无)"]),
			].join("\n"),
		};
	}

	if (action === "plan") {
		if (!root) return { level: "error", msg: "当前目录没有女娲项目，无法写入 RGS 验证意图" };
		const preSt = loadStateZeroWriteV8(root);
		if (!preSt) return { level: "error", msg: "state 读取失败" };
		if (isTerminalState(preSt)) {
			return { level: "error", msg: `该项目已处于终态 (${preSt.project.status})，禁止执行 /nuwa rgs plan` };
		}
		const targetDir = resolveRgsTargetDir(tokens[1], root, preSt);
		if (isNuwaProtectedPath(targetDir)) {
			return { level: "error", msg: `[N-003] 安全护栏阻断：禁止扫描或读取 .nuwa 内部状态与会话凭据目录 (${targetDir})` };
		}
		if (!targetDir || !existsSync(targetDir)) {
			return { level: "error", msg: "用法: /nuwa rgs plan [源码目录路径]" };
		}
		let graph;
		try {
			graph = analyzeCrossFileRgs(targetDir);
		} catch (e) {
			return { level: "error", msg: `RGS 分析被拒绝: ${e instanceof Error ? e.message : String(e)}` };
		}
		const baseUrl = preSt.project.scheme === "local" ? "http://127.0.0.1:8080" : preSt.project.url || preSt.project.target;
		const resolvedScope = preSt.project.scope ?? defaultScopeForTarget(baseUrl, preSt.project.mode);
		const bridged = bridgeRgsToVerificationIntents(graph, baseUrl, {
			phase: preSt.project.phase,
			scope: resolvedScope,
		});
		const added = withLock(root, () => {
			const s = loadState(root);
			if (!s || isTerminalState(s)) return { intents: [] as string[], hyps: 0 };
			syncAssetsFromFacts(s);
			let hyps = 0;
			for (const h of bridged.hypotheses) {
				addHypothesis(s, {
					title: h.title,
					statement: h.statement,
					falsificationTest: h.falsificationTest,
					requiredFacts: [],
					expectedGain: h.expectedGain,
					estimatedCost: h.estimatedCost,
				});
				hyps += 1;
			}
			const createdIds = appendIntentSpecs(
				s,
				bridged.intents.map((it) => ({
					from: [],
					...it,
				})),
			);
			saveState(root, s);
			return { intents: createdIds, hyps };
		});
		return {
			level: "info",
			msg: `RGS 审计桥接完成: routes=${graph.summary.totalRoutes} 新增意图=${added.intents.length} 新增假设=${added.hyps}`,
		};
	}

	if (action === "pov") {
		if (!root) return { level: "error", msg: "当前目录没有女娲项目" };
		const factId = tokens[1] ?? "";
		if (!factId) return { level: "error", msg: "用法: /nuwa rgs pov <factId>" };
		const st = loadStateZeroWriteV8(root);
		if (!st) return { level: "error", msg: "state 读取失败" };
		if (isTerminalState(st)) {
			return { level: "error", msg: `该项目已处于终态 (${st.project.status})，禁止执行 /nuwa rgs pov 写操作` };
		}
		const fact = st.facts[factId];
		if (!fact) return { level: "error", msg: `未找到事实: ${factId}` };
		const outDir = join(resolve(root), ".nuwa", "poc-bundle");
		const baseUrl = st.project.scheme === "local" ? "http://127.0.0.1:8080" : st.project.url || st.project.target;
		try {
			const res = writeStandalonePovScript(outDir, {
				fact,
				baseUrl,
				vaultRootOrVault: resolve(root),
				scope: st.project.scope,
			});
			return {
				level: "info",
				msg: `已生成零明文独立验证脚本: ${res.filePath} (sha256=${res.sha256.slice(0, 16)}... redacted=${res.redactedSecretsCount})`,
			};
		} catch (e) {
			return { level: "error", msg: `生成验证脚本失败: ${e instanceof Error ? e.message : String(e)}` };
		}
	}

	return { level: "error", msg: "用法: /nuwa rgs [status | scan <dir> | plan [dir] | pov <factId>]" };
}

// ============================================================================
// 单向无环编排桥接函数（供 graph-commands / auto-loops / engine / nuwa 统一调用）
// ============================================================================
import {
	ensureSessionFresh,
	type EnsureSessionFreshOptions,
	type EnsureSessionFreshResult,
} from "./cdp-auth";
import {
	runCdpStatefulSignedAuthDiff,
	type RunCdpStatefulSignedAuthDiffOptions,
	type RunCdpStatefulSignedAuthDiffResult,
	type StatefulEndpointTargetSpec,
} from "./cdp-signed-probe";
import type { CodeSurfaceInput } from "./hybrid-audit";
import type { AnalyzeRgsOptions, RgsBridgeOptions, RgsBridgeResult, RgsGraphResult } from "./rgs-analyzer";
import {
	EmbeddedOobListener,
	OobCorrelator,
	type EmbeddedOobListenerOptions,
	type OobCorrelationFilter,
} from "./resilience-oob";
import {
	executeStatefulWorkflowChain,
	verifySecondOrderWorkflow,
	type ExecuteStatefulWorkflowOptions,
	type SecondOrderWorkflowResult,
	type VerifySecondOrderWorkflowOptions,
} from "./stateful-workflow";

export async function runCdpStatefulAuthDiffWithPersistence(
	targetUrl: string,
	targets: StatefulEndpointTargetSpec[],
	root: string,
	scope: ScopePolicy,
	opts?: RunCdpStatefulSignedAuthDiffOptions & { refreshRole?: string; refreshOpts?: EnsureSessionFreshOptions },
): Promise<RunCdpStatefulSignedAuthDiffResult & { sessionRefresh?: EnsureSessionFreshResult }> {
	let sessionRefresh: EnsureSessionFreshResult | undefined;
	if (opts?.refreshRole) {
		sessionRefresh = await ensureSessionFresh(root, opts.refreshRole, scope, opts.refreshOpts);
	}
	const diffRes = await runCdpStatefulSignedAuthDiff(targetUrl, targets, root, scope, opts);
	let host = "127.0.0.1";
	try {
		host = new URL(targetUrl).hostname;
	} catch {
		/* ignore */
	}
	for (const finding of diffRes.findings) {
		recordProtocolAuditFrame(root, {
			id: `pf-cdp-signed-${Date.now()}-${finding.method}-${finding.path}`.slice(0, 96),
			ts: nowIso(),
			protocol: "http",
			direction: "response",
			url: `${targetUrl.replace(/\/+$/, "")}${finding.path}`,
			host,
			operationName: `${finding.method} ${finding.path}`,
			role: finding.testedRole,
			status: 200,
			anomalyTag: finding.kind,
			extra: { baselineRole: finding.baselineRole, similarity: finding.similarity },
		});
	}
	return { ...diffRes, ...(sessionRefresh ? { sessionRefresh } : {}) };
}

export function analyzeHybridRgsSurface(
	input: CodeSurfaceInput,
	baseUrl: string,
	opts?: { rgsOptions?: AnalyzeRgsOptions; bridgeOptions?: RgsBridgeOptions },
): { rgs: RgsGraphResult; bridged: RgsBridgeResult } {
	const rgs = analyzeCrossFileRgs(input, opts?.rgsOptions);
	const bridged = bridgeRgsToVerificationIntents(rgs, baseUrl, opts?.bridgeOptions);
	return { rgs, bridged };
}

export async function replayStatefulTrafficWorkflow(
	opts: ExecuteStatefulWorkflowOptions & { runId?: string; workflowKind?: string; intentId?: string },
): Promise<StatefulWorkflowResult> {
	const res = await executeStatefulWorkflowChain(opts);
	if (opts.root) {
		const targetUrl = opts.steps[0]?.url ?? "http://127.0.0.1";
		recordStatefulWorkflowSummary(
			opts.root,
			opts.runId ?? `wf-traffic-${Date.now()}`,
			opts.workflowKind ?? "stateful_chain",
			targetUrl,
			res,
			{ role: opts.role, intentId: opts.intentId },
		);
	}
	return res;
}

export async function executeSecondOrderChainVerification(
	opts: VerifySecondOrderWorkflowOptions & { runId?: string; intentId?: string },
): Promise<SecondOrderWorkflowResult> {
	const res = await verifySecondOrderWorkflow(opts);
	if (opts.root) {
		const targetUrl = opts.writeSteps[0]?.url ?? "http://127.0.0.1";
		recordStatefulWorkflowSummary(
			opts.root,
			opts.runId ?? `wf-2nd-${Date.now()}`,
			"second_order",
			targetUrl,
			{
				ok: res.verified,
				blocked: res.abortedByScope,
				abortedByScope: res.abortedByScope,
				...(res.verified ? {} : { error: res.reason }),
				steps: res.stepTraces,
				variables: res.redactedVariables,
				cookies: {},
				totalRequests: res.stepTraces.length + res.cleanupTraces.length,
				durationMs: res.stepTraces.reduce((acc, s) => acc + s.durationMs, 0),
				redacted: true,
			},
			{
				intentId: opts.intentId,
				cleanupExecuted: res.cleanupExecuted,
				candidateFactId: res.candidateFact?.id ?? res.candidateFact?.key,
			},
		);
	}
	return res;
}

export function createEmbeddedOobCorrelator(opts?: EmbeddedOobListenerOptions): {
	listener: EmbeddedOobListener;
	correlator: OobCorrelator;
} {
	const listener = new EmbeddedOobListener(opts);
	const correlator = new OobCorrelator({ listener });
	return { listener, correlator };
}

export function correlateEmbeddedOobCallbacks(
	correlator: OobCorrelator,
	filter?: OobCorrelationFilter,
): OobCorrelationResult {
	return correlator.correlateCallbacks(filter);
}

import {
	GatewayAdaptiveController,
	IsomorphicTrapDetector,
	type GatewayAdaptiveOptions,
	type TrapDetectorOptions,
} from "./resilience-oob";
import {
	probeMassAssignment,
	runBarrierRaceProbe,
	type BarrierRaceProbeOptions,
	type BarrierRaceProbeResult,
	type MassAssignmentProbeOptions,
	type MassAssignmentProbeResult,
} from "./stateful-workflow";

export interface RunAutonomousV8PivotOptions {
	timeoutMs?: number;
	gatewayOptions?: GatewayAdaptiveOptions;
	trapOptions?: TrapDetectorOptions;
	correlator?: OobCorrelator;
}

export interface AutonomousV8PivotResult {
	pivotResult?: VerifyCredentialPivotResult;
	persistedCredentials: number;
	persistedCorrelations: number;
	gatewayController: GatewayAdaptiveController;
	trapDetector: IsomorphicTrapDetector;
}

export async function runAutonomousV8PivotAndOobLoop(
	state: NuwaState,
	root: string,
	scope: ScopePolicy,
	opts?: RunAutonomousV8PivotOptions,
): Promise<AutonomousV8PivotResult> {
	const normRoot = resolve(root);
	const gatewayController = new GatewayAdaptiveController(opts?.gatewayOptions);
	const trapDetector = new IsomorphicTrapDetector(opts?.trapOptions);
	let persistedCredentials = 0;
	let persistedCorrelations = 0;
	let pivotResult: VerifyCredentialPivotResult | undefined;

	const vault = loadSessionVault(normRoot);
	const roles = Object.keys(vault.roles);
	if (roles.length > 0 && state.project?.scheme !== "local") {
		const baseUrl = state.project.url || state.project.target;
		if (baseUrl) {
			await ensureSessionFresh(normRoot, roles[0]!, scope).catch(() => undefined);
		}
		const credentials: CredentialSpec[] = roles.map((r) => {
			const hdrs = getRoleHeadersMap(vault, r);
			return {
				role: r,
				...(hdrs ? { headers: hdrs } : {}),
			};
		});
		const candidates: CredentialCandidateTarget[] = Object.values(state.assets ?? {})
			.filter((a) => typeof a.host === "string" && a.host.length > 0)
			.map((a) => ({
				host: a.host!,
				...(a.port ? { port: a.port } : {}),
				scheme: resolveCandidateScheme(a, state.project.scheme),
				path: "/",
				assetId: a.id,
			}));
		if (candidates.length > 0) {
			pivotResult = await verifyCredentialPivot({
				root: normRoot,
				projectId: state.project.id,
				scope,
				mode: state.project.mode,
				credentials,
				candidates,
				timeoutMs: opts?.timeoutMs,
			});
			persistedCredentials = recordPivotCredentialResults(normRoot, pivotResult);
		}
	}

	if (opts?.correlator) {
		const corr = opts.correlator.correlateCallbacks({ projectId: state.project.id });
		persistedCorrelations = recordOobCorrelationMatches(normRoot, corr);
	}

	return {
		...(pivotResult ? { pivotResult } : {}),
		persistedCredentials,
		persistedCorrelations,
		gatewayController,
		trapDetector,
	};
}

export async function runAutonomousStatefulProbes(opts: {
	massAssignment?: MassAssignmentProbeOptions;
	barrierRace?: BarrierRaceProbeOptions;
}): Promise<{
	massAssignmentResult?: MassAssignmentProbeResult;
	barrierRaceResult?: BarrierRaceProbeResult;
}> {
	const out: {
		massAssignmentResult?: MassAssignmentProbeResult;
		barrierRaceResult?: BarrierRaceProbeResult;
	} = {};
	if (opts.massAssignment) {
		out.massAssignmentResult = await probeMassAssignment(opts.massAssignment);
	}
	if (opts.barrierRace) {
		out.barrierRaceResult = await runBarrierRaceProbe(opts.barrierRace);
	}
	return out;
}
