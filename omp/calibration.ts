/**
 * 女娲 v6.0 反自证机械对账校准核与自适应模型路由器（融合 hermes-zhulong 设计）。
 *
 * 核心职责：
 * 1. 硬性执行“不可自证原则（Anti-Self-Certification）”：结算来源严格限定为
 *    `verifier-gate | exec-ledger | autoexec | benchmark | human`，任何 `self / model / agent`
 *    或未知自评来源一律显式抛出 `CalibrationError` 拒绝入账；
 * 2. 维护持久化追加账本 `.nuwa/calibration.jsonl`：跨进程/同进程可重入文件锁并发保护、
 *    容错折叠读取、重复结算防重拦截，并结合 `session-vault` 与正则脱敏确保零明文凭据落盘；
 * 3. 精确计算全局及分维度（按 `modelId` 与 `taskCategory`）的 Brier Score、10-bin ECE、
 *    Precision、False Positive Rate、Tokens per Confirmed Finding 与 ROI 分数；
 * 4. 在 `allowedModels` 硬白名单内带冷启动最小样本门槛（`minSamples = 5`）自适应降权高误报/低 ROI 模型，
 *    优先推荐同家族健康候选模型并输出简体中文透明决策报告。
 *
 * 约束：严禁运行时导入 `./nuwa`，仅依赖 `./session-vault` 与 Node 内置模块，保持零循环依赖。
 */
import { createHash, randomBytes } from "node:crypto";
import {
	chmodSync,
	closeSync,
	existsSync,
	fsyncSync,
	linkSync,
	mkdirSync,
	openSync,
	readFileSync,
	statSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { maskSecretValue, redactVaultSecrets } from "./session-vault";
import { NuwaSqliteStore, migrateJsonToSqlite, resolveStorageBackend, sqliteDbPath } from "./sqlite-store";

export type CalibrationSettlementSource =
	| "verifier-gate"
	| "exec-ledger"
	| "autoexec"
	| "benchmark"
	| "human";

export const ALLOWED_SETTLEMENT_SOURCES: ReadonlySet<CalibrationSettlementSource> = new Set([
	"verifier-gate",
	"exec-ledger",
	"autoexec",
	"benchmark",
	"human",
]);

export type CalibrationTaskCategory =
	| "recon"
	| "auth"
	| "js-audit"
	| "verify"
	| "exploit"
	| "whitebox"
	| "general";

export const VALID_TASK_CATEGORIES: ReadonlySet<CalibrationTaskCategory> = new Set([
	"recon",
	"auth",
	"js-audit",
	"verify",
	"exploit",
	"whitebox",
	"general",
]);

export type CalibrationErrorCode =
	| "SELF_CERTIFICATION_FORBIDDEN"
	| "INVALID_SETTLEMENT_SOURCE"
	| "DUPLICATE_PREDICTION"
	| "PREDICTION_NOT_FOUND"
	| "DUPLICATE_SETTLEMENT"
	| "INVALID_CONFIDENCE"
	| "INVALID_INPUT";

export class CalibrationError extends Error {
	readonly code: CalibrationErrorCode;
	readonly reason: string;

	constructor(code: CalibrationErrorCode, reason: string) {
		super(reason);
		this.name = "CalibrationError";
		this.code = code;
		this.reason = reason;
	}
}

export interface CalibrationPredictionInput {
	predictionId?: string;
	intentId: string;
	taskCategory: CalibrationTaskCategory;
	modelId: string;
	/** 事前预测命中置信度，严格要求位于闭区间 [0, 1]。 */
	predictedConfidence: number;
	/** 事前预估消耗 Token 数（>= 0）。 */
	estimatedTokens: number;
	/** 可选脱敏说明备注（严禁含明文凭据，内部强制执行脱敏清洗）。 */
	note?: string;
	createdAt?: string;
}

export interface CalibrationSettlementInput {
	predictionId: string;
	/** 机械核验布尔命中结果：0 = 未命中，1 = 真实命中。 */
	outcome: 0 | 1;
	/** 是否被机械门禁判定为假阳性误报（若为 true，则 outcome 必须为 0）。 */
	isFalsePositive: boolean;
	/** 实际消耗 Token 数（>= 0）。 */
	actualTokens: number;
	/** 实际执行耗时毫秒数（>= 0）。 */
	durationMs: number;
	/** 机械核验结算源（严禁传入 self / model / agent 等自评源）。 */
	source: CalibrationSettlementSource;
	note?: string;
	settledAt?: string;
}

export interface CalibrationRecord {
	predictionId: string;
	intentId: string;
	taskCategory: CalibrationTaskCategory;
	modelId: string;
	predictedConfidence: number;
	estimatedTokens: number;
	createdAt: string;
	note?: string;
	settled: boolean;
	outcome?: 0 | 1;
	isFalsePositive?: boolean;
	actualTokens?: number;
	durationMs?: number;
	source?: CalibrationSettlementSource;
	settledAt?: string;
	settlementNote?: string;
}

export interface CalibrationBinStat {
	binIndex: number;
	/** 分桶下界（含）：b / M。 */
	lower: number;
	/** 分桶上界（第 0..M-2 桶为左闭右开，最后一桶 M-1 包含 1.0）。 */
	upper: number;
	count: number;
	avgConfidence: number;
	avgAccuracy: number;
	gap: number;
}

export interface CalibrationDimensionMetrics {
	totalPredictions: number;
	settledCount: number;
	pendingCount: number;
	confirmedCount: number;
	falsePositiveCount: number;
	cleanNegativeCount: number;
	/** Brier Score = mean((p - y)^2) ∈ [0, 1]，越小校准越准。 */
	brierScore: number;
	/** 10-bin Expected Calibration Error = sum((|B_b| / N) * |acc(B_b) - conf(B_b)|) ∈ [0, 1]。 */
	ece: number;
	/** 正向精确率 TP / (TP + FP)。 */
	precision: number;
	/** 已结算任务误报率 FP / settledCount（与女娲评测基准口径一致）。 */
	falsePositiveRate: number;
	/** 负样本假阳性率 FP / (FP + TN)（辅助诊断指标）。 */
	negativeFalloutRate: number;
	totalEstimatedTokens: number;
	totalActualTokens: number;
	totalDurationMs: number;
	/** 每实锤发现消耗 Token 数（confirmedCount > 0 时为 totalActualTokens / confirmedCount，否则为 totalActualTokens）。 */
	tokensPerConfirmedFinding: number;
	/** 综合投入产出比得分（融合实锤产出、误报重罚、校准质量与千 Token 成本）。 */
	roiScore: number;
	bins: CalibrationBinStat[];
}

export interface ComputeCalibrationOptions {
	/** ECE 等宽分桶数量（默认 10）。 */
	numBins?: number;
	/** 未显式标记 isFalsePositive 时辅助判定高置信负例的正向置信度阈值（可选）。 */
	countHighConfMissAsFp?: boolean;
	highConfThreshold?: number;
}

export interface CalibrationSummary {
	generatedAt: string;
	global: CalibrationDimensionMetrics;
	byModel: Record<string, CalibrationDimensionMetrics>;
	byCategory: Record<CalibrationTaskCategory, CalibrationDimensionMetrics>;
	byModelAndCategory: Record<string, CalibrationDimensionMetrics>;
}

export interface AdaptiveModelRouteInput {
	/** 候选模型严格白名单（硬边界：绝对禁止推荐此列表之外的任何模型！）。 */
	allowedModels: readonly string[];
	/** 默认模型（若不在 allowedModels 中，将强制钳制到 allowedModels[0]）。 */
	defaultModel: string;
	/** 当前任务类别（默认 "general"）。 */
	taskCategory?: CalibrationTaskCategory;
	/** 冷启动最小已结算样本门槛（默认 5）。 */
	minSamples?: number;
	/** 触发自动降权的最高允许误报率阈值（默认 0.30）。 */
	maxFalsePositiveRate?: number;
	/** 触发自动降权的最低可接受 ROI 分数阈值（默认 0.12）。 */
	minRoiScore?: number;
}

export interface ModelCandidateEvaluation {
	modelId: string;
	family: string;
	settledCount: number;
	categorySettledCount: number;
	brierScore: number;
	ece: number;
	precision: number;
	falsePositiveRate: number;
	roiScore: number;
	routeWeight: number;
	coldStart: boolean;
	demoted: boolean;
	demoteReasons: string[];
}

export interface AdaptiveModelRouteDecision {
	/** 最终推荐模型（100% 保证属于 input.allowedModels）。 */
	recommendedModel: string;
	defaultModel: string;
	effectiveDefaultModel: string;
	taskCategory: CalibrationTaskCategory;
	coldStart: boolean;
	downgraded: boolean;
	switched: boolean;
	demotedModels: string[];
	candidates: ModelCandidateEvaluation[];
	reason: string;
}

interface StoredPredictionEvent {
	schema: 1;
	kind: "prediction";
	predictionId: string;
	intentId: string;
	taskCategory: CalibrationTaskCategory;
	modelId: string;
	predictedConfidence: number;
	estimatedTokens: number;
	createdAt: string;
	note?: string;
}

interface StoredSettlementEvent {
	schema: 1;
	kind: "settlement";
	predictionId: string;
	outcome: 0 | 1;
	isFalsePositive: boolean;
	actualTokens: number;
	durationMs: number;
	source: CalibrationSettlementSource;
	settledAt: string;
	note?: string;
}

type StoredCalibrationEvent = StoredPredictionEvent | StoredSettlementEvent;

const SELF_CERT_PATTERNS =
	/^(?:self|model|agent|llm|assistant|subagent|fujiang|ai|auto-self|self-eval|self_check)(?:$|:|-|_)/i;

const INLINE_SECRET_PATTERNS: ReadonlyArray<{ re: RegExp; replacer: (...args: string[]) => string }> = [
	{
		re: /\b(Bearer|Basic|Token|JWT)\s+([A-Za-z0-9._~+/=-]{6,})/gi,
		replacer: (_m, scheme, tok) => `${scheme} ${maskSecretValue(tok)}`,
	},
	{
		re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g,
		replacer: (m) => maskSecretValue(m),
	},
	{
		re: /\b((?:sk|rk|pk|ghp|gho|ghs|glpat|xoxb|xoxp)-[A-Za-z0-9_-]{8,})\b/g,
		replacer: (m) => maskSecretValue(m),
	},
	{
		re: /\b(AKIA[0-9A-Z]{12,20})\b/g,
		replacer: (m) => maskSecretValue(m),
	},
	{
		re: /\b([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)([^/\s@]{3,})(@)/gi,
		replacer: (_m, prefix, pass, at) => `${prefix}${maskSecretValue(pass)}${at}`,
	},
	{
		re: /(["'`]?)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?token|client[_-]?secret|cookie|session[_-]?id)\b\1\s*([:=])\s*(["'`])([^"'`\r\n]{4,})\4/gi,
		replacer: (_m, qk, k, sep, qv, v) => `${qk}${k}${qk}${sep}${qv}${maskSecretValue(v)}${qv}`,
	},
	{
		re: /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?token|client[_-]?secret|cookie|session[_-]?id)\s*([:=])\s*([^\s,;&'"`}\]]{4,})/gi,
		replacer: (_m, k, sep, v) => `${k}${sep}${maskSecretValue(v)}`,
	},
];

const heldCalibLocks = new Set<string>();
let calibLockSeq = 0;
let predSeq = 0;

function nowIso(): string {
	return new Date().toISOString();
}

function shaShort(text: string, len = 10): string {
	return createHash("sha256").update(text).digest("hex").slice(0, len);
}

/**
 * 返回指定项目根目录下的持久化校准账本路径 `<root>/.nuwa/calibration.jsonl`。
 */
export function calibrationLedgerPath(root: string): string {
	if (!root || typeof root !== "string" || !root.trim()) {
		throw new CalibrationError("INVALID_INPUT", "calibrationLedgerPath 需要有效的项目根目录 root");
	}
	return join(resolve(root), ".nuwa", "calibration.jsonl");
}

function calibrationLockPath(root: string): string {
	return join(resolve(root), ".nuwa", "calibration.lock");
}

function pidAlive(pid: number): boolean {
	if (!Number.isInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
}

function procStartTime(pid: number): string | null {
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		const close = stat.lastIndexOf(")");
		if (close < 0) return null;
		const fields = stat.slice(close + 2).split(" ");
		return fields[19] ?? null;
	} catch {
		return null;
	}
}

function sleepSync(ms: number): void {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function ensureSecureNuwaDir(root: string): string {
	const dir = join(resolve(root), ".nuwa");
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	try {
		chmodSync(dir, 0o700);
	} catch {
		/* 非 POSIX 文件系统忽略 */
	}
	return dir;
}

function readCalibrationLockHolder(
	lockFile: string,
): { pid?: number; ts?: number; start?: string | null; nonce?: string } | null {
	try {
		const raw = readFileSync(lockFile, "utf8").trim();
		if (!raw) return null;
		const parsed = JSON.parse(raw) as { pid?: number; ts?: number; start?: string | null; nonce?: string };
		return parsed && typeof parsed === "object" ? parsed : null;
	} catch {
		return null;
	}
}

/**
 * 跨进程 + 同进程可重入校准账本文件锁：
 * 使用临时文件 + fsync + linkSync 原子落锁、300ms 空锁宽限、独占 `.reclaim` 死锁二次核验及 nonce 释放校验，
 * 保证并发追加与防重结算临界区的严格原子性。
 */
function withCalibrationLock<T>(root: string, fn: () => T, timeoutMs = 8000): T {
	ensureSecureNuwaDir(root);
	const lockFile = resolve(calibrationLockPath(root));
	if (heldCalibLocks.has(lockFile)) {
		return fn();
	}

	const deadline = Date.now() + timeoutMs;
	let backoff = 4;
	const myNonce = `${process.pid}-${Date.now()}-${randomBytes(6).toString("hex")}`;
	const lockPayload = JSON.stringify({
		pid: process.pid,
		ts: Date.now(),
		start: procStartTime(process.pid),
		nonce: myNonce,
	});

	for (;;) {
		const tmp = `${lockFile}.tmp-${process.pid}-${calibLockSeq++}`;
		let acquired = false;
		let useFallback = false;
		let tfd = -1;
		try {
			tfd = openSync(tmp, "wx", 0o600);
			writeSync(tfd, lockPayload);
			fsyncSync(tfd);
			closeSync(tfd);
			tfd = -1;
			try {
				linkSync(tmp, lockFile);
				acquired = true;
			} catch (linkErr) {
				const lcode = (linkErr as NodeJS.ErrnoException)?.code;
				if (lcode === "EEXIST") {
					acquired = false;
				} else if (lcode === "EXDEV" || lcode === "EPERM" || lcode === "ENOSYS" || lcode === "EOPNOTSUPP") {
					useFallback = true;
				} else {
					throw linkErr;
				}
			}
		} finally {
			if (tfd >= 0) {
				try {
					closeSync(tfd);
				} catch {
					/* ignore */
				}
			}
			try {
				unlinkSync(tmp);
			} catch {
				/* ignore */
			}
		}

		if (useFallback) {
			let fd = -1;
			try {
				fd = openSync(lockFile, "wx", 0o600);
				writeSync(fd, lockPayload);
				fsyncSync(fd);
				closeSync(fd);
				fd = -1;
				acquired = true;
			} catch (err) {
				if (fd >= 0) {
					try {
						closeSync(fd);
					} catch {
						/* ignore */
					}
					try {
						unlinkSync(lockFile);
					} catch {
						/* ignore */
					}
					throw err;
				}
				const code = (err as NodeJS.ErrnoException)?.code;
				if (code !== "EEXIST") throw err;
				acquired = false;
			}
		}

		if (!acquired) {
			const held = readCalibrationLockHolder(lockFile);
			let emptyMtimeMs: number | null = null;
			if (held) {
				const heldPid = typeof held.pid === "number" ? held.pid : 0;
				const heldStart = typeof held.start === "string" ? held.start : null;
				const sameProcess = heldPid > 0 && pidAlive(heldPid) && (!heldStart || heldStart === procStartTime(heldPid));
				if (sameProcess) {
					if (Date.now() >= deadline) {
						throw new CalibrationError("INVALID_INPUT", `获取校准账本锁超时 (${lockFile})`);
					}
					sleepSync(backoff);
					backoff = Math.min(64, backoff * 2);
					continue;
				}
			} else {
				let recentlyCreated = false;
				try {
					emptyMtimeMs = statSync(lockFile).mtimeMs;
					recentlyCreated = Date.now() - emptyMtimeMs < 300;
				} catch {
					emptyMtimeMs = null;
					recentlyCreated = false;
				}
				if (recentlyCreated && Date.now() < deadline) {
					sleepSync(backoff);
					backoff = Math.min(32, backoff * 2);
					continue;
				}
			}

			const reclaimPath = `${lockFile}.reclaim`;
			const reclaimTmp = `${lockFile}.reclaim.tmp-${process.pid}-${calibLockSeq++}`;
			const reclaimNonce = `${process.pid}-${Date.now()}-${randomBytes(4).toString("hex")}`;
			const reclaimPayload = JSON.stringify({
				pid: process.pid,
				ts: Date.now(),
				start: procStartTime(process.pid),
				nonce: reclaimNonce,
			});
			let reclaimAcquired = false;
			let rfd = -1;
			try {
				rfd = openSync(reclaimTmp, "wx", 0o600);
				writeSync(rfd, reclaimPayload);
				fsyncSync(rfd);
				closeSync(rfd);
				rfd = -1;
				try {
					linkSync(reclaimTmp, reclaimPath);
					reclaimAcquired = true;
				} catch (rErr) {
					const rc = (rErr as NodeJS.ErrnoException)?.code;
					if (rc === "EXDEV" || rc === "EPERM" || rc === "ENOSYS" || rc === "EOPNOTSUPP") {
						try {
							const rfdFb = openSync(reclaimPath, "wx", 0o600);
							writeSync(rfdFb, reclaimPayload);
							fsyncSync(rfdFb);
							closeSync(rfdFb);
							reclaimAcquired = true;
						} catch {
							reclaimAcquired = false;
						}
					}
				}
			} catch {
				reclaimAcquired = false;
			} finally {
				if (rfd >= 0) {
					try {
						closeSync(rfd);
					} catch {
						/* ignore */
					}
				}
				try {
					unlinkSync(reclaimTmp);
				} catch {
					/* ignore */
				}
			}

			if (reclaimAcquired) {
				try {
					const nowHeld = readCalibrationLockHolder(lockFile);
					let stillSameDead = false;
					if (held && nowHeld) {
						const sameHolder = held.nonce
							? nowHeld.nonce === held.nonce
							: !nowHeld.nonce && nowHeld.pid === held.pid && nowHeld.start === held.start;
						const nowPid = typeof nowHeld.pid === "number" ? nowHeld.pid : 0;
						const nowStart = typeof nowHeld.start === "string" ? nowHeld.start : null;
						const nowAlive = nowPid > 0 && pidAlive(nowPid) && (!nowStart || nowStart === procStartTime(nowPid));
						stillSameDead = sameHolder && !nowAlive;
					} else if (!held && !nowHeld && emptyMtimeMs !== null) {
						try {
							stillSameDead = Math.abs(statSync(lockFile).mtimeMs - emptyMtimeMs) < 1;
						} catch {
							stillSameDead = false;
						}
					}
					if (stillSameDead) {
						try {
							unlinkSync(lockFile);
						} catch {
							/* ignore */
						}
					}
				} finally {
					try {
						const curReclaim = readCalibrationLockHolder(reclaimPath);
						if (curReclaim?.nonce === reclaimNonce) unlinkSync(reclaimPath);
					} catch {
						/* ignore */
					}
				}
			} else {
				const oldReclaim = readCalibrationLockHolder(reclaimPath);
				const oldDead = oldReclaim
					? !oldReclaim.pid ||
						!pidAlive(oldReclaim.pid) ||
						Boolean(oldReclaim.start && oldReclaim.start !== procStartTime(oldReclaim.pid))
					: (() => {
							try {
								return Date.now() - statSync(reclaimPath).mtimeMs >= 5000;
							} catch {
								return false;
							}
						})();
				if (oldDead) {
					try {
						unlinkSync(reclaimPath);
					} catch {
						/* ignore */
					}
				} else {
					sleepSync(Math.min(backoff, 16));
				}
			}
			if (Date.now() >= deadline) {
				throw new CalibrationError("INVALID_INPUT", `获取校准账本锁超时 (${lockFile})`);
			}
			continue;
		}

		heldCalibLocks.add(lockFile);
		try {
			return fn();
		} finally {
			heldCalibLocks.delete(lockFile);
			try {
				const cur = readCalibrationLockHolder(lockFile);
				if (cur?.nonce === myNonce) {
					unlinkSync(lockFile);
				}
			} catch {
				/* ignore */
			}
		}
	}
}

function appendJsonlEvent(filePath: string, event: StoredCalibrationEvent): void {
	mkdirSync(dirname(filePath), { recursive: true, mode: 0o700 });
	const line = `${JSON.stringify(event)}\n`;
	const fd = openSync(filePath, "a", 0o600);
	try {
		writeSync(fd, line);
		fsyncSync(fd);
	} finally {
		closeSync(fd);
	}
	try {
		chmodSync(filePath, 0o600);
	} catch {
		/* 非 POSIX 忽略 */
	}
}

/**
 * 对校准账本中的任意文本字段执行保险箱凭据脱敏与通用密钥模式掩码，确保零明文凭据落盘。
 */
export function redactCalibrationText(text: string | undefined, root?: string): string {
	let cleaned = String(text ?? "")
		.replace(/[\r\n]+/g, " ")
		.trim();
	if (!cleaned) return "";

	if (root && root.trim()) {
		try {
			cleaned = redactVaultSecrets(cleaned, root);
		} catch {
			/* 保险箱不存在时继续执行正则脱敏 */
		}
	}

	for (const { re, replacer } of INLINE_SECRET_PATTERNS) {
		cleaned = cleaned.replace(re, replacer);
	}
	return cleaned.slice(0, 400);
}

/**
 * 机械对账反自证护栏校验：
 * 严格只允许 `"verifier-gate" | "exec-ledger" | "autoexec" | "benchmark" | "human"`；
 * 对 `"self"` / `"model"` / `"agent"` 及任何非授信来源显式抛出 `CalibrationError`。
 */
export function validateSettlementSource(source: unknown): CalibrationSettlementSource {
	if (typeof source !== "string") {
		throw new CalibrationError(
			"INVALID_SETTLEMENT_SOURCE",
			`反自证护栏拦截：结算来源 source 必须为字符串类型，收到 ${typeof source}`,
		);
	}
	const norm = source.trim();
	if (!norm) {
		throw new CalibrationError(
			"INVALID_SETTLEMENT_SOURCE",
			"反自证护栏拦截：结算来源 source 不能为空，必须提供授信机械核验源",
		);
	}
	if (SELF_CERT_PATTERNS.test(norm)) {
		throw new CalibrationError(
			"SELF_CERTIFICATION_FORBIDDEN",
			`反自证护栏强制拒绝：严禁模型或代理自评结算 (source=${JSON.stringify(source)})；仅允许机械核验源 [${[...ALLOWED_SETTLEMENT_SOURCES].join(", ")}]`,
		);
	}
	if (!ALLOWED_SETTLEMENT_SOURCES.has(norm as CalibrationSettlementSource)) {
		throw new CalibrationError(
			"INVALID_SETTLEMENT_SOURCE",
			`非法结算来源: ${JSON.stringify(source)}；仅允许授信来源 [${[...ALLOWED_SETTLEMENT_SOURCES].join(", ")}]`,
		);
	}
	return norm as CalibrationSettlementSource;
}

function validateTaskCategory(category: unknown): CalibrationTaskCategory {
	if (typeof category !== "string") {
		throw new CalibrationError(
			"INVALID_INPUT",
			`非法任务类别 taskCategory：必须为字符串，收到 ${typeof category}`,
		);
	}
	const norm = category.trim() as CalibrationTaskCategory;
	if (!VALID_TASK_CATEGORIES.has(norm)) {
		throw new CalibrationError(
			"INVALID_INPUT",
			`非法任务类别 taskCategory=${JSON.stringify(category)}；允许值: [${[...VALID_TASK_CATEGORIES].join(", ")}]`,
		);
	}
	return norm;
}

function validatePredictedConfidence(confidence: unknown): number {
	if (typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
		throw new CalibrationError(
			"INVALID_CONFIDENCE",
			`非法事前预测置信度 predictedConfidence=${String(confidence)}：必须为闭区间 [0, 1] 内的有限实数`,
		);
	}
	return confidence;
}

function validateNonNegativeNumber(val: unknown, fieldName: string): number {
	if (typeof val !== "number" || !Number.isFinite(val) || val < 0) {
		throw new CalibrationError(
			"INVALID_INPUT",
			`非法数值字段 ${fieldName}=${String(val)}：必须为 >= 0 的有限实数`,
		);
	}
	return val;
}

function syncCalibrationRecordToSqlite(root: string, record: CalibrationRecord): void {
	const backend = resolveStorageBackend(root);
	const dbFile = sqliteDbPath(root);
	const hasDb = existsSync(dbFile);
	if (backend !== "sqlite" && backend !== "dual" && !hasDb) return;
	const stateJsonFile = join(resolve(root), ".nuwa", "state.json");
	if (!hasDb && !existsSync(stateJsonFile)) {
		// 尚未创建任何项目状态（如纯校准算法独立测试目录）时不误创建半空 nuwa.db，待项目初始化/迁移时自动全量摄入 calibration.jsonl
		return;
	}
	let store: NuwaSqliteStore | null = null;
	try {
		if (!hasDb && existsSync(stateJsonFile)) {
			migrateJsonToSqlite(root);
		}
		store = new NuwaSqliteStore(root);
		store.upsertCalibrationRecord({
			predictionId: record.predictionId,
			intentId: record.intentId,
			taskCategory: record.taskCategory,
			modelId: record.modelId,
			predictedConfidence: record.predictedConfidence,
			estimatedTokens: record.estimatedTokens,
			...(record.outcome !== undefined ? { outcome: record.outcome } : {}),
			...(record.isFalsePositive !== undefined ? { isFalsePositive: record.isFalsePositive } : {}),
			...(record.actualTokens !== undefined ? { actualTokens: record.actualTokens } : {}),
			...(record.durationMs !== undefined ? { durationMs: record.durationMs } : {}),
			...(record.source !== undefined ? { source: record.source } : {}),
			settled: record.settled,
			createdAt: record.createdAt,
			...(record.settledAt !== undefined ? { settledAt: record.settledAt } : {}),
			...(record.note || record.settlementNote
				? {
						payload: {
							...(record.note ? { note: record.note } : {}),
							...(record.settlementNote ? { settlementNote: record.settlementNote } : {}),
						},
					}
				: {}),
		});
	} catch {
		/* SQLite 同步失败不中断 JSONL 账本主路径 */
	} finally {
		store?.close();
	}
}

/**
 * 判断指定项目是否存在校准记录（兼容 `.nuwa/calibration.jsonl` 与纯 SQLite `.nuwa/nuwa.db` 的 `calibration_records` 表）。
 */
export function hasCalibrationRecords(root: string): boolean {
	if (!root || typeof root !== "string" || !root.trim()) return false;
	const jsonl = calibrationLedgerPath(root);
	if (existsSync(jsonl)) return true;
	const dbFile = sqliteDbPath(root);
	if (!existsSync(dbFile)) return false;
	let store: NuwaSqliteStore | null = null;
	try {
		store = new NuwaSqliteStore(root, { readonly: true });
		return store.listCalibrationRecords({ limit: 1 }).length > 0;
	} catch {
		return false;
	} finally {
		store?.close();
	}
}

/**
 * 容错读取并折叠 `.nuwa/calibration.jsonl` 及 SQLite `calibration_records` 账本记录：
 * - 自动忽略空行、尾部异常截断损坏 JSON 行或非法篡改的自评结算行；
 * - 严格在读取端复核 `ALLOWED_SETTLEMENT_SOURCES` 与数值语义不变量，防范绕过 API 篡改持久化表；
 * - 按登记顺序确定性返回全部 `CalibrationRecord`。
 */
export function loadCalibrationRecords(root: string): CalibrationRecord[] {
	const file = calibrationLedgerPath(root);
	const map = new Map<string, CalibrationRecord>();

	if (existsSync(file)) {
		let rawText = "";
		try {
			rawText = readFileSync(file, "utf8");
		} catch {
			rawText = "";
		}
		const lines = rawText.split("\n");

		for (const rawLine of lines) {
			const line = rawLine.trim();
			if (!line) continue;

			let parsed: Partial<StoredCalibrationEvent> | null = null;
			try {
				parsed = JSON.parse(line) as Partial<StoredCalibrationEvent>;
			} catch {
				// 容错跳过半截崩溃行或损坏 JSON 行
				continue;
			}
			if (!parsed || typeof parsed !== "object") continue;

			if (parsed.kind === "prediction") {
				const pid = typeof parsed.predictionId === "string" ? parsed.predictionId.trim() : "";
				const iid = typeof parsed.intentId === "string" ? parsed.intentId.trim() : "";
				const mid = typeof parsed.modelId === "string" ? parsed.modelId.trim() : "";
				const cat = parsed.taskCategory;
				const conf = parsed.predictedConfidence;
				const estTokens = parsed.estimatedTokens;
				if (
					!pid ||
					!iid ||
					!mid ||
					!VALID_TASK_CATEGORIES.has(cat as CalibrationTaskCategory) ||
					typeof conf !== "number" ||
					!Number.isFinite(conf) ||
					conf < 0 ||
					conf > 1 ||
					typeof estTokens !== "number" ||
					!Number.isFinite(estTokens) ||
					estTokens < 0
				) {
					continue;
				}
				if (map.has(pid)) continue;
				map.set(pid, {
					predictionId: pid,
					intentId: iid,
					taskCategory: cat as CalibrationTaskCategory,
					modelId: mid,
					predictedConfidence: conf,
					estimatedTokens: estTokens,
					createdAt: typeof parsed.createdAt === "string" && parsed.createdAt ? parsed.createdAt : "",
					...(typeof parsed.note === "string" && parsed.note ? { note: parsed.note } : {}),
					settled: false,
				});
			} else if (parsed.kind === "settlement") {
				const pid = typeof parsed.predictionId === "string" ? parsed.predictionId.trim() : "";
				if (!pid) continue;
				const rec = map.get(pid);
				// 忽略孤儿结算行、重复结算行或绕过 API 塞入磁盘的非授信自评行
				if (!rec || rec.settled) continue;
				if (!ALLOWED_SETTLEMENT_SOURCES.has(parsed.source as CalibrationSettlementSource)) continue;
				if (parsed.outcome !== 0 && parsed.outcome !== 1) continue;
				if (typeof parsed.isFalsePositive !== "boolean") continue;
				if (parsed.isFalsePositive && parsed.outcome === 1) continue;
				if (
					typeof parsed.actualTokens !== "number" ||
					!Number.isFinite(parsed.actualTokens) ||
					parsed.actualTokens < 0 ||
					typeof parsed.durationMs !== "number" ||
					!Number.isFinite(parsed.durationMs) ||
					parsed.durationMs < 0
				) {
					continue;
				}

				rec.settled = true;
				rec.outcome = parsed.outcome;
				rec.isFalsePositive = parsed.isFalsePositive;
				rec.actualTokens = parsed.actualTokens;
				rec.durationMs = parsed.durationMs;
				rec.source = parsed.source as CalibrationSettlementSource;
				rec.settledAt = typeof parsed.settledAt === "string" && parsed.settledAt ? parsed.settledAt : "";
				if (typeof parsed.note === "string" && parsed.note) {
					rec.settlementNote = parsed.note;
				}
			}
		}
	}

	const dbFile = sqliteDbPath(root);
	if (existsSync(dbFile)) {
		let store: NuwaSqliteStore | null = null;
		try {
			store = new NuwaSqliteStore(root, { readonly: true });
			for (const row of store.listCalibrationRecords({ limit: 5000 })) {
				const pid = typeof row.predictionId === "string" ? row.predictionId.trim() : "";
				const iid = typeof row.intentId === "string" ? row.intentId.trim() : "";
				const mid = typeof row.modelId === "string" ? row.modelId.trim() : "";
				const cat = row.taskCategory as CalibrationTaskCategory;
				const conf = row.predictedConfidence;
				const estTokens = typeof row.estimatedTokens === "number" ? row.estimatedTokens : 0;
				if (
					!pid ||
					!iid ||
					!mid ||
					!VALID_TASK_CATEGORIES.has(cat) ||
					typeof conf !== "number" ||
					!Number.isFinite(conf) ||
					conf < 0 ||
					conf > 1 ||
					!Number.isFinite(estTokens) ||
					estTokens < 0
				) {
					continue;
				}
				const payload = row.payload && typeof row.payload === "object" ? row.payload : {};
				const note = typeof payload.note === "string" && payload.note ? payload.note : undefined;
				const settlementNote =
					typeof payload.settlementNote === "string" && payload.settlementNote ? payload.settlementNote : undefined;

				let rec = map.get(pid);
				if (!rec) {
					rec = {
						predictionId: pid,
						intentId: iid,
						taskCategory: cat,
						modelId: mid,
						predictedConfidence: conf,
						estimatedTokens: estTokens,
						createdAt: typeof row.createdAt === "string" ? row.createdAt : "",
						...(note ? { note } : {}),
						settled: false,
					};
					map.set(pid, rec);
				}

				if (
					!rec.settled &&
					row.settled &&
					ALLOWED_SETTLEMENT_SOURCES.has(row.source as CalibrationSettlementSource) &&
					(row.outcome === 0 || row.outcome === 1) &&
					typeof row.isFalsePositive === "boolean" &&
					!(row.isFalsePositive && row.outcome === 1) &&
					typeof row.actualTokens === "number" &&
					Number.isFinite(row.actualTokens) &&
					row.actualTokens >= 0 &&
					typeof row.durationMs === "number" &&
					Number.isFinite(row.durationMs) &&
					row.durationMs >= 0
				) {
					rec.settled = true;
					rec.outcome = row.outcome;
					rec.isFalsePositive = row.isFalsePositive;
					rec.actualTokens = row.actualTokens;
					rec.durationMs = row.durationMs;
					rec.source = row.source as CalibrationSettlementSource;
					rec.settledAt = typeof row.settledAt === "string" && row.settledAt ? row.settledAt : "";
					if (settlementNote) rec.settlementNote = settlementNote;
				}
			}
		} catch {
			/* 只读探测 SQLite 校准表异常时平滑保留 JSONL 读取结果 */
		} finally {
			store?.close();
		}
	}

	return [...map.values()];
}

/**
 * 事前登记校准预测快照至 `.nuwa/calibration.jsonl`。
 * 严格校验 `predictedConfidence ∈ [0, 1]`、任务分类、非负 Token 预估与 `predictionId` 唯一性，并对所有文本脱敏。
 */
export function recordPrediction(root: string, input: CalibrationPredictionInput): CalibrationRecord {
	if (!input || typeof input !== "object") {
		throw new CalibrationError("INVALID_INPUT", "recordPrediction 需要有效的输入对象");
	}

	const intentId = redactCalibrationText(input.intentId, root);
	if (!intentId) {
		throw new CalibrationError("INVALID_INPUT", "recordPrediction 需要非空 intentId");
	}
	const modelId = redactCalibrationText(input.modelId, root);
	if (!modelId) {
		throw new CalibrationError("INVALID_INPUT", "recordPrediction 需要非空 modelId");
	}
	const taskCategory = validateTaskCategory(input.taskCategory);
	const predictedConfidence = validatePredictedConfidence(input.predictedConfidence);
	const estimatedTokens = validateNonNegativeNumber(input.estimatedTokens, "estimatedTokens");
	const createdAt = input.createdAt?.trim() || nowIso();
	const rawPredId = input.predictionId ? redactCalibrationText(input.predictionId, root) : "";
	const predictionId =
		rawPredId ||
		`pred-${Date.now()}-${predSeq++}-${shaShort(`${intentId}|${modelId}|${createdAt}`, 8)}`;
	const cleanNote = input.note ? redactCalibrationText(input.note, root) : undefined;

	return withCalibrationLock(root, () => {
		const existing = loadCalibrationRecords(root);
		if (existing.some((r) => r.predictionId === predictionId)) {
			throw new CalibrationError(
				"DUPLICATE_PREDICTION",
				`重复预测登记拦截：predictionId=${JSON.stringify(predictionId)} 已存在，禁止覆盖事前置信度`,
			);
		}

		const event: StoredPredictionEvent = {
			schema: 1,
			kind: "prediction",
			predictionId,
			intentId,
			taskCategory,
			modelId,
			predictedConfidence,
			estimatedTokens,
			createdAt,
			...(cleanNote ? { note: cleanNote } : {}),
		};
		appendJsonlEvent(calibrationLedgerPath(root), event);

		const rec: CalibrationRecord = {
			predictionId,
			intentId,
			taskCategory,
			modelId,
			predictedConfidence,
			estimatedTokens,
			createdAt,
			...(cleanNote ? { note: cleanNote } : {}),
			settled: false,
		};
		syncCalibrationRecordToSqlite(root, rec);
		return rec;
	});
}

/**
 * 由授信机械核验源对已登记预测做不可篡改对账结算：
 * - 强制拦截 `self / model / agent` 及未知来源（抛出 `CalibrationError`）；
 * - 强制拦截重复结算（同一 `predictionId` 只允许结算一次）；
 * - 强制校验 `outcome ∈ {0, 1}` 且 `isFalsePositive === true` 时 `outcome` 必为 `0`。
 */
export function settlePrediction(root: string, input: CalibrationSettlementInput): CalibrationRecord {
	if (!input || typeof input !== "object") {
		throw new CalibrationError("INVALID_INPUT", "settlePrediction 需要有效的输入对象");
	}

	// 第一时间执行反自证来源校验，确保非法自评在任何路径下均被第一时间拦截
	const source = validateSettlementSource(input.source);

	const predictionId = String(input.predictionId ?? "").trim();
	if (!predictionId) {
		throw new CalibrationError("INVALID_INPUT", "settlePrediction 需要非空 predictionId");
	}

	if (input.outcome !== 0 && input.outcome !== 1) {
		throw new CalibrationError(
			"INVALID_INPUT",
			`非法结算结果 outcome=${String(input.outcome)}：必须严格为 0 或 1`,
		);
	}
	if (typeof input.isFalsePositive !== "boolean") {
		throw new CalibrationError("INVALID_INPUT", "isFalsePositive 必须为布尔值");
	}
	if (input.isFalsePositive && input.outcome === 1) {
		throw new CalibrationError(
			"INVALID_INPUT",
			"结算语义矛盾：当 isFalsePositive=true（假阳性误报）时，真实命中 outcome 必须为 0",
		);
	}

	const actualTokens = validateNonNegativeNumber(input.actualTokens, "actualTokens");
	const durationMs = validateNonNegativeNumber(input.durationMs, "durationMs");
	const settledAt = input.settledAt?.trim() || nowIso();
	const cleanNote = input.note ? redactCalibrationText(input.note, root) : undefined;

	return withCalibrationLock(root, () => {
		const records = loadCalibrationRecords(root);
		const target = records.find((r) => r.predictionId === predictionId);
		if (!target) {
			throw new CalibrationError(
				"PREDICTION_NOT_FOUND",
				`未找到待结算的预测记录: predictionId=${JSON.stringify(predictionId)}`,
			);
		}
		if (target.settled) {
			throw new CalibrationError(
				"DUPLICATE_SETTLEMENT",
				`重复结算防重拦截：predictionId=${JSON.stringify(predictionId)} 已由 ${target.source} 在 ${target.settledAt} 完成结算，严禁二次改写`,
			);
		}

		const event: StoredSettlementEvent = {
			schema: 1,
			kind: "settlement",
			predictionId,
			outcome: input.outcome,
			isFalsePositive: input.isFalsePositive,
			actualTokens,
			durationMs,
			source,
			settledAt,
			...(cleanNote ? { note: cleanNote } : {}),
		};
		appendJsonlEvent(calibrationLedgerPath(root), event);

		const settledRec: CalibrationRecord = {
			...target,
			settled: true,
			outcome: input.outcome,
			isFalsePositive: input.isFalsePositive,
			actualTokens,
			durationMs,
			source,
			settledAt,
			...(cleanNote ? { settlementNote: cleanNote } : {}),
		};
		syncCalibrationRecordToSqlite(root, settledRec);
		return settledRec;
	});
}

/**
 * `settlePrediction` 的结构化无异常包装版本，便于上层按 `{ ok, error, code }` 模式消费。
 */
export function safeSettlePrediction(
	root: string,
	input: CalibrationSettlementInput,
): { ok: true; record: CalibrationRecord } | { ok: false; code: CalibrationErrorCode; error: string } {
	try {
		const record = settlePrediction(root, input);
		return { ok: true, record };
	} catch (err) {
		if (err instanceof CalibrationError) {
			return { ok: false, code: err.code, error: err.reason };
		}
		return {
			ok: false,
			code: "INVALID_INPUT",
			error: err instanceof Error ? err.message : String(err),
		};
	}
}

function computeMetricsForSlice(
	slice: readonly CalibrationRecord[],
	numBins: number,
	opts?: ComputeCalibrationOptions,
): CalibrationDimensionMetrics {
	const bins: CalibrationBinStat[] = [];
	for (let b = 0; b < numBins; b++) {
		bins.push({
			binIndex: b,
			lower: b / numBins,
			upper: (b + 1) / numBins,
			count: 0,
			avgConfidence: 0,
			avgAccuracy: 0,
			gap: 0,
		});
	}

	const validRecords = slice.filter(
		(r) =>
			Boolean(r) &&
			typeof r === "object" &&
			typeof r.predictedConfidence === "number" &&
			Number.isFinite(r.predictedConfidence) &&
			r.predictedConfidence >= 0 &&
			r.predictedConfidence <= 1,
	);
	const totalPredictions = validRecords.length;
	const settledRecords = validRecords.filter(
		(r) =>
			r.settled === true &&
			(r.outcome === 0 || r.outcome === 1) &&
			typeof r.source === "string" &&
			ALLOWED_SETTLEMENT_SOURCES.has(r.source as CalibrationSettlementSource) &&
			!(r.isFalsePositive === true && r.outcome === 1),
	);
	const settledCount = settledRecords.length;
	const pendingCount = totalPredictions - settledCount;

	const totalEstimatedTokens = validRecords.reduce(
		(acc, r) => acc + (Number.isFinite(r.estimatedTokens) ? Math.max(0, r.estimatedTokens) : 0),
		0,
	);

	if (settledCount === 0) {
		return {
			totalPredictions,
			settledCount: 0,
			pendingCount,
			confirmedCount: 0,
			falsePositiveCount: 0,
			cleanNegativeCount: 0,
			brierScore: 0,
			ece: 0,
			precision: 0,
			falsePositiveRate: 0,
			negativeFalloutRate: 0,
			totalEstimatedTokens,
			totalActualTokens: 0,
			totalDurationMs: 0,
			tokensPerConfirmedFinding: 0,
			roiScore: 0,
			bins,
		};
	}

	const binConfSums = new Array<number>(numBins).fill(0);
	const binAccSums = new Array<number>(numBins).fill(0);

	let brierSum = 0;
	let confirmedCount = 0;
	let falsePositiveCount = 0;
	let cleanNegativeCount = 0;
	let totalActualTokens = 0;
	let totalDurationMs = 0;

	const countHighConfMiss = opts?.countHighConfMissAsFp === true;
	const highConfThresh = opts?.highConfThreshold ?? 0.8;

	for (const rec of settledRecords) {
		const p = Math.max(0, Math.min(1, rec.predictedConfidence));
		const y = rec.outcome === 1 ? 1 : 0;
		const diff = p - y;
		brierSum += diff * diff;

		// 分桶边界严格遵循等宽划分：第 0..M-2 桶为 [b/M, (b+1)/M)，第 M-1 桶为 [(M-1)/M, 1.0]，
		// 确保 p=0 精确落入第 0 桶，p=1 精确落入第 M-1 桶。
		const binIdx = p >= 1 ? numBins - 1 : Math.max(0, Math.min(numBins - 1, Math.floor(p * numBins)));
		bins[binIdx]!.count += 1;
		binConfSums[binIdx] = (binConfSums[binIdx] ?? 0) + p;
		binAccSums[binIdx] = (binAccSums[binIdx] ?? 0) + y;

		const isFp =
			rec.isFalsePositive === true || (y === 0 && countHighConfMiss && p >= highConfThresh);
		if (y === 1) {
			confirmedCount += 1;
		} else if (isFp) {
			falsePositiveCount += 1;
		} else {
			cleanNegativeCount += 1;
		}

		totalActualTokens += Number.isFinite(rec.actualTokens)
			? Math.max(0, rec.actualTokens!)
			: Math.max(0, rec.estimatedTokens || 0);
		totalDurationMs += Number.isFinite(rec.durationMs) ? Math.max(0, rec.durationMs!) : 0;
	}

	const brierScore = brierSum / settledCount;

	let ece = 0;
	for (let b = 0; b < numBins; b++) {
		const stat = bins[b]!;
		if (stat.count > 0) {
			stat.avgConfidence = binConfSums[b]! / stat.count;
			stat.avgAccuracy = binAccSums[b]! / stat.count;
			stat.gap = Math.abs(stat.avgAccuracy - stat.avgConfidence);
			ece += (stat.count / settledCount) * stat.gap;
		}
	}

	const positiveClaims = confirmedCount + falsePositiveCount;
	const precision = positiveClaims > 0 ? confirmedCount / positiveClaims : 0;
	const falsePositiveRate = falsePositiveCount / settledCount;
	const negativeTotal = falsePositiveCount + cleanNegativeCount;
	const negativeFalloutRate = negativeTotal > 0 ? falsePositiveCount / negativeTotal : 0;
	const tokensPerConfirmedFinding =
		confirmedCount > 0 ? totalActualTokens / confirmedCount : totalActualTokens;

	// 综合 ROI 评分：奖励真实发现与良好校准的诚实阴性，严惩假阳性误报与高 Token 浪费
	const effectiveYield = Math.max(
		0,
		confirmedCount +
			0.25 * cleanNegativeCount * Math.max(0, 1 - brierScore) -
			1.25 * falsePositiveCount,
	);
	const costUnits = Math.max(0.5, totalActualTokens / 2000);
	const calibrationQuality = Math.max(0.05, 1 - 0.5 * brierScore - 0.5 * ece);
	const roiScore = (effectiveYield / costUnits) * calibrationQuality;

	return {
		totalPredictions,
		settledCount,
		pendingCount,
		confirmedCount,
		falsePositiveCount,
		cleanNegativeCount,
		brierScore,
		ece,
		precision,
		falsePositiveRate,
		negativeFalloutRate,
		totalEstimatedTokens,
		totalActualTokens,
		totalDurationMs,
		tokensPerConfirmedFinding,
		roiScore,
		bins,
	};
}

/**
 * 精确计算全局及按 `modelId`、`taskCategory`、`<modelId>::<taskCategory>` 分维度的校准指标汇总。
 */
export function computeCalibrationSummary(
	records: readonly CalibrationRecord[],
	opts?: ComputeCalibrationOptions,
): CalibrationSummary {
	const list = Array.isArray(records) ? records : [];
	const numBins =
		typeof opts?.numBins === "number" && Number.isInteger(opts.numBins) && opts.numBins >= 2
			? opts.numBins
			: 10;

	const global = computeMetricsForSlice(list, numBins, opts);

	const modelBuckets = new Map<string, CalibrationRecord[]>();
	const catBuckets = new Map<CalibrationTaskCategory, CalibrationRecord[]>();
	const jointBuckets = new Map<string, CalibrationRecord[]>();

	for (const cat of VALID_TASK_CATEGORIES) {
		catBuckets.set(cat, []);
	}

	for (const rec of list) {
		if (!rec || typeof rec !== "object") continue;
		const mid = String(rec.modelId ?? "").trim();
		if (mid) {
			const mArr = modelBuckets.get(mid) ?? [];
			mArr.push(rec);
			modelBuckets.set(mid, mArr);
		}
		if (VALID_TASK_CATEGORIES.has(rec.taskCategory)) {
			const cArr = catBuckets.get(rec.taskCategory)!;
			cArr.push(rec);
			if (mid) {
				const jKey = `${mid}::${rec.taskCategory}`;
				const jArr = jointBuckets.get(jKey) ?? [];
				jArr.push(rec);
				jointBuckets.set(jKey, jArr);
			}
		}
	}

	const byModel: Record<string, CalibrationDimensionMetrics> = {};
	for (const [mid, arr] of [...modelBuckets.entries()].sort(([a], [b]) => a.localeCompare(b))) {
		byModel[mid] = computeMetricsForSlice(arr, numBins, opts);
	}

	const byCategory = {} as Record<CalibrationTaskCategory, CalibrationDimensionMetrics>;
	for (const cat of VALID_TASK_CATEGORIES) {
		byCategory[cat] = computeMetricsForSlice(catBuckets.get(cat) ?? [], numBins, opts);
	}

	const byModelAndCategory: Record<string, CalibrationDimensionMetrics> = {};
	for (const [jKey, arr] of [...jointBuckets.entries()].sort(([a], [b]) => a.localeCompare(b))) {
		byModelAndCategory[jKey] = computeMetricsForSlice(arr, numBins, opts);
	}

	return {
		generatedAt: nowIso(),
		global,
		byModel,
		byCategory,
		byModelAndCategory,
	};
}

function extractModelFamily(modelId: string): string {
	const cleaned = String(modelId ?? "")
		.trim()
		.toLowerCase()
		.split("/")
		.pop()!;
	const m = /^([a-z]+)/.exec(cleaned);
	return m?.[1] || "unknown";
}

/**
 * 自适应模型路由推荐器：
 * - 硬白名单护栏：返回结果 **100% 限定在 `input.allowedModels` 内**，即使历史记录存在白名单外高分模型或
 *   `defaultModel` 越界，也绝不越界返回；
 * - 冷启动保护：在有效已结算样本达到 `minSamples`（默认 5）前保持基准默认模型不盲目漂移；
 * - 动态调权：对高误报率（`> maxFalsePositiveRate`）或低 ROI（`< minRoiScore`）模型自动降权，
 *   优先推荐同家族健康候选模型，否则推荐 `allowedModels` 内最高权重健康模型，并给出清晰简体中文决策依据。
 */
export function recommendAdaptiveModelRoute(
	records: readonly CalibrationRecord[],
	input: AdaptiveModelRouteInput,
): AdaptiveModelRouteDecision {
	if (!input || !Array.isArray(input.allowedModels)) {
		throw new CalibrationError("INVALID_INPUT", "recommendAdaptiveModelRoute 需要提供 allowedModels 数组");
	}

	const allowed: string[] = [];
	const allowedSet = new Set<string>();
	for (const raw of input.allowedModels) {
		const m = String(raw ?? "").trim();
		if (m && !allowedSet.has(m)) {
			allowedSet.add(m);
			allowed.push(m);
		}
	}
	if (allowed.length === 0) {
		throw new CalibrationError(
			"INVALID_INPUT",
			"recommendAdaptiveModelRoute 需要至少包含 1 个有效模型的 allowedModels 白名单",
		);
	}

	const requestedDefault = String(input.defaultModel ?? "").trim();
	const defaultWasClamped = !allowedSet.has(requestedDefault);
	const effectiveDefaultModel = defaultWasClamped ? allowed[0]! : requestedDefault;
	const taskCategory: CalibrationTaskCategory =
		input.taskCategory && VALID_TASK_CATEGORIES.has(input.taskCategory)
			? input.taskCategory
			: "general";
	const minSamples =
		typeof input.minSamples === "number" && Number.isFinite(input.minSamples) && input.minSamples >= 1
			? Math.floor(input.minSamples)
			: 5;
	const maxFpRate =
		typeof input.maxFalsePositiveRate === "number" && Number.isFinite(input.maxFalsePositiveRate)
			? Math.max(0, Math.min(1, input.maxFalsePositiveRate))
			: 0.30;
	const minRoiScore =
		typeof input.minRoiScore === "number" && Number.isFinite(input.minRoiScore)
			? Math.max(0, input.minRoiScore)
			: 0.12;

	// 仅保留 allowedModels 内的记录进入候选评估，彻底隔离白名单外历史模型干扰
	const summary = computeCalibrationSummary(records);
	const defaultFamily = extractModelFamily(effectiveDefaultModel);

	const candidates: ModelCandidateEvaluation[] = [];
	const demotedModels: string[] = [];

	for (const modelId of allowed) {
		const globalMetrics = summary.byModel[modelId];
		const catMetrics = summary.byModelAndCategory[`${modelId}::${taskCategory}`];
		const globalSettled = globalMetrics?.settledCount ?? 0;
		const catSettled = catMetrics?.settledCount ?? 0;

		// 若当前任务类别样本已达标，优先采用同类别专属表现，否则采用该模型全局已结算表现
		const activeMetrics =
			catSettled >= minSamples
				? catMetrics!
				: globalSettled >= minSamples
					? globalMetrics!
					: catSettled > 0
						? catMetrics!
						: globalMetrics;

		const settledCount = globalSettled;
		const isCold = settledCount < minSamples;
		const fpRate = activeMetrics?.falsePositiveRate ?? 0;
		const roi = activeMetrics?.roiScore ?? 0;
		const brier = activeMetrics?.brierScore ?? 0;
		const ece = activeMetrics?.ece ?? 0;
		const precision = activeMetrics?.precision ?? 0;
		const family = extractModelFamily(modelId);

		const demoteReasons: string[] = [];
		if (!isCold) {
			if (fpRate > maxFpRate) {
				demoteReasons.push(`误报率过高(${(fpRate * 100).toFixed(1)}% > ${(maxFpRate * 100).toFixed(1)}%)`);
			}
			if (roi < minRoiScore) {
				demoteReasons.push(`ROI过低(${roi.toFixed(3)} < ${minRoiScore.toFixed(3)})`);
			}
			if (brier > 0.45) {
				demoteReasons.push(`概率校准偏差过大(Brier=${brier.toFixed(3)})`);
			}
		}

		const demoted = demoteReasons.length > 0;
		if (demoted) {
			demotedModels.push(modelId);
		}

		let routeWeight: number;
		if (isCold) {
			// 未达最小样本数的候选维持中性探索基线权重，同家族赋予微弱平滑亲和度
			routeWeight = 0.50 + (family === defaultFamily ? 0.06 : 0) + (modelId === effectiveDefaultModel ? 0.04 : 0);
		} else {
			const roiNorm = roi / (roi + 0.5);
			const fpScore = 1 - fpRate;
			const calibScore = Math.max(0, 1 - 0.6 * brier - 0.4 * ece);
			routeWeight = 0.40 * roiNorm + 0.35 * fpScore + 0.25 * calibScore;
			if (family === defaultFamily) {
				routeWeight += 0.06;
			}
			if (demoted) {
				routeWeight *= 0.22;
			}
		}

		candidates.push({
			modelId,
			family,
			settledCount,
			categorySettledCount: catSettled,
			brierScore: brier,
			ece,
			precision,
			falsePositiveRate: fpRate,
			roiScore: roi,
			routeWeight,
			coldStart: isCold,
			demoted,
			demoteReasons,
		});
	}

	const defaultEval = candidates.find((c) => c.modelId === effectiveDefaultModel)!;
	const clampNote = defaultWasClamped
		? `（原传入 defaultModel=${JSON.stringify(requestedDefault)} 不在 allowedModels 白名单内，已强制钳制为 ${effectiveDefaultModel}）`
		: "";

	// 冷启动保护：只要默认模型自身已结算样本数尚未达到最小样本门槛 minSamples，严格保持默认模型不盲目切换
	const matureHealthyCandidates = candidates.filter((c) => !c.coldStart && !c.demoted);
	if (defaultEval.coldStart) {
		return {
			recommendedModel: effectiveDefaultModel,
			defaultModel: requestedDefault,
			effectiveDefaultModel,
			taskCategory,
			coldStart: true,
			downgraded: false,
			switched: defaultWasClamped,
			demotedModels,
			candidates,
			reason:
				`冷启动保护生效：模型 ${effectiveDefaultModel} 已结算样本数 (${defaultEval.settledCount}) 未达最小门槛 (minSamples=${minSamples})，` +
				`保持白名单默认模型不变${clampNote}。`,
		};
	}

	// 若默认模型已被标记高误报/低 ROI 降权：优先挑选未降权的同家族最高权重候选，其次挑选白名单内未降权最高权重候选
	if (defaultEval.demoted) {
		const nonDemoted = candidates.filter((c) => !c.demoted && c.modelId !== effectiveDefaultModel);
		if (nonDemoted.length > 0) {
			const sameFamilyHealthy = nonDemoted
				.filter((c) => c.family === defaultFamily)
				.sort((a, b) => b.routeWeight - a.routeWeight);
			const chosen =
				sameFamilyHealthy[0] ??
				[...nonDemoted].sort((a, b) => b.routeWeight - a.routeWeight)[0]!;

			// 终极白名单断言防线
			const safeRecommended = allowedSet.has(chosen.modelId) ? chosen.modelId : effectiveDefaultModel;
			const familyTag = chosen.family === defaultFamily ? "同家族" : "白名单内";
			return {
				recommendedModel: safeRecommended,
				defaultModel: requestedDefault,
				effectiveDefaultModel,
				taskCategory,
				coldStart: false,
				downgraded: true,
				switched: safeRecommended !== effectiveDefaultModel || defaultWasClamped,
				demotedModels,
				candidates,
				reason:
					`自适应降权路由：默认模型 ${effectiveDefaultModel} 因 [${defaultEval.demoteReasons.join("、")}] 被自动降权，` +
					`已切换至更优${familyTag}候选模型 ${safeRecommended}（weight=${chosen.routeWeight.toFixed(3)}, ` +
					`FPR=${(chosen.falsePositiveRate * 100).toFixed(1)}%, ROI=${chosen.roiScore.toFixed(3)}）${clampNote}。`,
			};
		}

		// 若白名单内所有候选均被降权，仍挑选相对权重最高（损害最小）的白名单模型
		const leastBad = [...candidates].sort((a, b) => b.routeWeight - a.routeWeight)[0]!;
		const safeLeastBad = allowedSet.has(leastBad.modelId) ? leastBad.modelId : effectiveDefaultModel;
		return {
			recommendedModel: safeLeastBad,
			defaultModel: requestedDefault,
			effectiveDefaultModel,
			taskCategory,
			coldStart: false,
			downgraded: true,
			switched: safeLeastBad !== effectiveDefaultModel || defaultWasClamped,
			demotedModels,
			candidates,
			reason:
				`全候选受限择优：默认模型 ${effectiveDefaultModel} 触发降权 [${defaultEval.demoteReasons.join("、")}]，` +
				`在 allowedModels 白名单内择优保留风险最低模型 ${safeLeastBad}${clampNote}。`,
		};
	}

	// 默认模型未降权（或默认模型仍处冷启动但存在样本充足的高优候选）：仅当存在样本充足的健康候选且明显领先时平滑升级
	const bestMature = [...matureHealthyCandidates].sort((a, b) => b.routeWeight - a.routeWeight)[0];
	const upgradeMargin = 0.12;
	if (bestMature && bestMature.modelId !== effectiveDefaultModel && bestMature.routeWeight >= defaultEval.routeWeight + upgradeMargin) {
		const safeBest = allowedSet.has(bestMature.modelId) ? bestMature.modelId : effectiveDefaultModel;
		return {
			recommendedModel: safeBest,
			defaultModel: requestedDefault,
			effectiveDefaultModel,
			taskCategory,
			coldStart: false,
			downgraded: false,
			switched: true,
			demotedModels,
			candidates,
			reason:
				`自适应择优路由：候选模型 ${safeBest} 在任务类别 [${taskCategory}] 上校准与 ROI 显著更优 ` +
				`（weight=${bestMature.routeWeight.toFixed(3)} vs ${defaultEval.routeWeight.toFixed(3)}, ` +
				`Brier=${bestMature.brierScore.toFixed(3)}, ROI=${bestMature.roiScore.toFixed(3)}）${clampNote}。`,
		};
	}

	return {
		recommendedModel: effectiveDefaultModel,
		defaultModel: requestedDefault,
		effectiveDefaultModel,
		taskCategory,
		coldStart: defaultEval.coldStart,
		downgraded: false,
		switched: defaultWasClamped,
		demotedModels,
		candidates,
		reason:
			`默认模型表现健康：维持 ${effectiveDefaultModel}（样本=${defaultEval.settledCount}, ` +
			`Brier=${defaultEval.brierScore.toFixed(3)}, ECE=${defaultEval.ece.toFixed(3)}, ` +
			`FPR=${(defaultEval.falsePositiveRate * 100).toFixed(1)}%, ROI=${defaultEval.roiScore.toFixed(3)}）${clampNote}。`,
	};
}

function fmtPct(v: number): string {
	return `${(v * 100).toFixed(1)}%`;
}

/**
 * 将 `CalibrationSummary` 格式化为清晰直观的简体中文机械对账校准看板摘要。
 */
export function formatCalibrationReport(summary: CalibrationSummary): string {
	const g = summary.global;
	const lines: string[] = [
		`## 女娲机械对账认知校准看板`,
		`- 账本总览：总预测登记 **${g.totalPredictions}** 条 | 已机械结算 **${g.settledCount}** 条 | 待结算 **${g.pendingCount}** 条`,
		`- 核验结果：实锤命中 **${g.confirmedCount}** | 假阳性误报 **${g.falsePositiveCount}** | 诚实阴性 **${g.cleanNegativeCount}**`,
		`- 校准精度：Brier Score = **${g.brierScore.toFixed(4)}** | 10-bin ECE = **${g.ece.toFixed(4)}** | 精确率 Precision = **${fmtPct(g.precision)}** | 误报率 FPR = **${fmtPct(g.falsePositiveRate)}**`,
		`- 算力效用：总消耗 Token = **${g.totalActualTokens}** | 单洞成本 Tokens/Finding = **${Math.round(g.tokensPerConfirmedFinding)}** | 综合 ROI = **${g.roiScore.toFixed(4)}**`,
	];

	const modelKeys = Object.keys(summary.byModel).sort((a, b) => a.localeCompare(b));
	if (modelKeys.length > 0) {
		lines.push("", "### 按模型校准表现", "| 模型 ID | 已结算 | 实锤/误报 | Brier | 10-bin ECE | 精确率 | 误报率 | Tokens/洞 | ROI |");
		lines.push("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
		for (const mid of modelKeys) {
			const m = summary.byModel[mid]!;
			const safeId = redactCalibrationText(mid).replace(/\|/g, "\\|");
			lines.push(
				`| ${safeId} | ${m.settledCount} | ${m.confirmedCount}/${m.falsePositiveCount} | ${m.brierScore.toFixed(4)} | ${m.ece.toFixed(4)} | ${fmtPct(m.precision)} | ${fmtPct(m.falsePositiveRate)} | ${Math.round(m.tokensPerConfirmedFinding)} | ${m.roiScore.toFixed(4)} |`,
			);
		}
	}

	const activeCats = [...VALID_TASK_CATEGORIES].filter(
		(cat) => (summary.byCategory[cat]?.totalPredictions ?? 0) > 0,
	);
	if (activeCats.length > 0) {
		lines.push("", "### 按任务类别校准表现", "| 任务类别 | 已结算 | 实锤/误报 | Brier | 10-bin ECE | 误报率 | ROI |");
		lines.push("|---|---:|---:|---:|---:|---:|---:|");
		for (const cat of activeCats) {
			const c = summary.byCategory[cat]!;
			lines.push(
				`| ${cat} | ${c.settledCount} | ${c.confirmedCount}/${c.falsePositiveCount} | ${c.brierScore.toFixed(4)} | ${c.ece.toFixed(4)} | ${fmtPct(c.falsePositiveRate)} | ${c.roiScore.toFixed(4)} |`,
			);
		}
	}

	return lines.join("\n");
}
