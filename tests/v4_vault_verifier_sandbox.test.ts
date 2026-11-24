/**
 * 女娲 v4.0 多角色会话保险箱（session-vault）、双盲复验闸门（verifier-gate）、
 * 零信任 Docker 沙盒（sandbox）与守护器健康自检（bin/nuwa-autonomous）单元测试。
 */
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { spawnSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdtempSync,
	mkdirSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { NuwaState, ScopePolicy } from "../omp/types";
import {
	buildAuthDiffPacketSection,
	clearSessionVault,
	formatSessionVaultSummary,
	ingestCredFactToVault,
	loadSessionVault,
	maskSecretValue,
	materializeRoleHeaderFile,
	redactVaultSecrets,
	removeSessionRole,
	upsertSessionRole,
} from "../omp/session-vault";
import {
	DOUBLE_BLIND_VERIFY_PRIORITY,
	buildDoubleBlindVerifyIntentSpec,
	filterConfirmedProofs,
	isDoubleBlindEnabled,
	isVerifyVulnIntentKey,
	resolveVerificationOutcome,
	shouldStageAsCandidate,
	type VerifiableFact,
} from "../omp/verifier-gate";
import {
	buildContainerScopePreflightScript,
	buildDockerRunArgs,
	probeDockerAvailable,
	readSandboxConfig,
	wrapCommandInDockerSandbox,
} from "../omp/sandbox";

const REPO_ROOT = resolve(import.meta.dir, "..");
const DAEMON_BIN = join(REPO_ROOT, "bin", "nuwa-autonomous");
const DOCKERFILE_PATH = join(REPO_ROOT, "docker", "Dockerfile.sandbox");

const tmpDirs: string[] = [];
const tmpNuwaProjectIds: string[] = [];
const savedEnv = new Map<string, string | undefined>();
const SUITE_AGENT_HOME = mkdtempSync(join(tmpdir(), "nuwa-vault-suite-home-"));
process.env.PI_AGENT_HOME = SUITE_AGENT_HOME;
delete process.env.NUWA_KB_DB;

afterAll(() => {
	rmSync(SUITE_AGENT_HOME, { recursive: true, force: true });
});

function makeTmpDir(prefix: string): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	tmpDirs.push(dir);
	return dir;
}

function makeTestProjectId(tag: string): string {
	const id = `v4test-${tag}-${process.pid}-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
	tmpNuwaProjectIds.push(id);
	return id;
}

function setTempEnv(key: string, value: string | undefined): void {
	if (!savedEnv.has(key)) {
		savedEnv.set(key, process.env[key]);
	}
	if (value === undefined) {
		delete process.env[key];
	} else {
		process.env[key] = value;
	}
}

afterEach(() => {
	for (const [k, v] of savedEnv.entries()) {
		if (v === undefined) delete process.env[k];
		else process.env[k] = v;
	}
	savedEnv.clear();

	while (tmpNuwaProjectIds.length > 0) {
		const id = tmpNuwaProjectIds.pop()!;
		try {
			rmSync(join("/tmp/nuwa", id), { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}

	while (tmpDirs.length > 0) {
		const dir = tmpDirs.pop()!;
		try {
			rmSync(dir, { recursive: true, force: true });
		} catch {
			/* ignore */
		}
	}
});

function makeMockState(mode: NuwaState["project"]["mode"] = "pentest"): NuwaState {
	const ts = "2026-11-24T00:00:00.000Z";
	return {
		schema: 1,
		version: "4.0.0",
		project: {
			id: "target-demo-8080",
			target: "http://target.example.test:8080",
			url: "http://target.example.test:8080",
			host: "target.example.test",
			port: 8080,
			scheme: "http",
			goal: "安全评估双盲复验测试",
			mode,
			status: "active",
			phase: "vuln",
			episode: 1,
			createdAt: ts,
			updatedAt: ts,
		},
		facts: {},
		intents: {},
		seq: { fact: 0, intent: 0 },
		runtime: {
			startedAt: Date.now(),
			turns: 2,
			stall: 0,
			idle: 0,
			blockStreak: 0,
			toolCalls: 2,
			lastToolCalls: 0,
			tokens: 2048,
			lastSig: "",
			lastDirective: "",
			completionRejects: 0,
			emptyRounds: 0,
		},
	};
}

function runDaemon(args: string[], extraEnv: Record<string, string | undefined> = {}) {
	const env: Record<string, string> = {};
	for (const [k, v] of Object.entries(process.env)) {
		if (k === "BUN_OPTIONS" || v === undefined) continue;
		env[k] = v;
	}
	for (const [k, v] of Object.entries(extraEnv)) {
		if (v === undefined) delete env[k];
		else env[k] = v;
	}
	return spawnSync(DAEMON_BIN, args, {
		encoding: "utf8",
		env,
		timeout: 20_000,
	});
}

describe("模块边界约束与 Dockerfile.sandbox 合规校验", () => {
	test("新建 omp 子模块严禁运行时 import ./nuwa", () => {
		for (const file of ["omp/session-vault.ts", "omp/verifier-gate.ts", "omp/sandbox.ts"]) {
			const src = readFileSync(join(REPO_ROOT, file), "utf8");
			expect(src).not.toMatch(/import\s+(?!type\b)[^;\n]*from\s+["']\.\/nuwa["']/);
			expect(src).not.toMatch(/require\s*\(\s*["']\.\/nuwa["']\s*\)/);
		}
	});

	test("docker/Dockerfile.sandbox 使用非 root nuwa 用户并包含标准工具集", () => {
		expect(existsSync(DOCKERFILE_PATH)).toBe(true);
		const df = readFileSync(DOCKERFILE_PATH, "utf8");
		expect(df).toMatch(/^FROM\s+(?:alpine|debian)/m);
		expect(df).toMatch(/\bUSER\s+nuwa\b/);
		expect(df).not.toMatch(/\bUSER\s+root\s*$/m);
		for (const pkg of ["curl", "openssl", "nmap", "python3", "jq", "sqlite", "netcat"]) {
			expect(df).toContain(pkg);
		}
	});
});

describe("omp/session-vault.ts 多角色会话保险箱", () => {
	test("0o700 目录与 0o600 文件权限原子持久化、更新、删除与清空", () => {
		const root = makeTmpDir("nuwa-vault-");
		expect(loadSessionVault(root).roles).toEqual({});

		const admin = upsertSessionRole(root, {
			role: "Admin",
			cookie: "sid=admin_secret_cookie_999",
			bearer: "eyJhbGciOiJIUzI1NiJ9.payload123.sig999",
			headers: { "X-API-Key": "sk-live-secret-key-8888" },
			username: "admin",
			password: "Sup3rSecret!Password",
		});
		expect(admin.role).toBe("admin");

		const sessionsDir = join(root, ".nuwa", "sessions");
		const vaultFile = join(sessionsDir, "vault.json");
		expect(statSync(sessionsDir).mode & 0o777).toBe(0o700);
		expect(statSync(vaultFile).mode & 0o777).toBe(0o600);

		// 增量更新保留既有字段
		const updated = upsertSessionRole(root, {
			role: "admin",
			note: "管理员会话已刷新",
		});
		expect(updated.cookie).toBe("sid=admin_secret_cookie_999");
		expect(updated.note).toBe("管理员会话已刷新");

		// 新增普通用户角色
		upsertSessionRole(root, {
			role: "user_a",
			cookie: "sid=short12",
		});
		const loaded = loadSessionVault(root);
		expect(Object.keys(loaded.roles).sort()).toEqual(["admin", "user_a"]);

		// 删除与清空
		expect(removeSessionRole(root, "user_a")).toBe(true);
		expect(removeSessionRole(root, "nonexistent")).toBe(false);
		expect(Object.keys(loadSessionVault(root).roles)).toEqual(["admin"]);

		clearSessionVault(root);
		expect(loadSessionVault(root).roles).toEqual({});
	});

	test("maskSecretValue 严格遵守 <=8 全掩码、>8 保留前 3 后 2", () => {
		expect(maskSecretValue("")).toBe("");
		expect(maskSecretValue("a")).toMatch(/^\*+$/);
		expect(maskSecretValue("pass1234")).toBe("********");
		expect(maskSecretValue("short12")).not.toContain("sh");
		expect(maskSecretValue("short12")).not.toContain("12");
		expect(maskSecretValue("123456789")).toBe("123***89");
		expect(maskSecretValue("eyJhbGciOiJIUzI1NiJ9")).toBe("eyJ***J9");
	});

	test("redactVaultSecrets 与 formatSessionVaultSummary 在所有渲染出口全量脱敏（含短 Cookie/Basic/URL 编码）", () => {
		const root = makeTmpDir("nuwa-redact-");
		const jwt = "eyJhbGciOiJIUzI1NiJ9.supersecretbody.abcdef99";
		const apiKey = "ak_prod_9876543210zz";
		const pass = "P@ssw0rd!2026";
		const shortCookieVal = "s12345"; // 长度 6 <= 8，绝不能露出后两位 "45"
		const basicB64 = Buffer.from(`alice:${pass}`, "utf8").toString("base64");

		upsertSessionRole(root, {
			role: "alice",
			cookie: `sid=${shortCookieVal}; csrf=csrf_token_very_long_1234`,
			bearer: `Bearer ${jwt}`,
			headers: {
				"X-API-Key": apiKey,
				"Content-Type": "application/json",
				Cookie: "extra_sess=hdr_cookie_secret_445566",
			},
			username: "alice",
			password: pass,
		});

		const rawLog = [
			`Cookie: sid=${shortCookieVal}; csrf=csrf_token_very_long_1234`,
			`Authorization: Bearer ${jwt}`,
			`Basic ${basicB64}`,
			`X-API-Key: ${apiKey}`,
			`login user=alice password=${pass} encoded=${encodeURIComponent(pass)}`,
			`raw short cookie value leak: ${shortCookieVal}`,
			`header cookie fragment leak: hdr_cookie_secret_445566`,
		].join("\n");

		const redacted = redactVaultSecrets(rawLog, root);
		expect(redacted).not.toContain(jwt);
		expect(redacted).not.toContain("supersecretbody");
		expect(redacted).not.toContain(apiKey);
		expect(redacted).not.toContain(pass);
		expect(redacted).not.toContain(encodeURIComponent(pass));
		expect(redacted).not.toContain(basicB64);
		expect(redacted).not.toContain(shortCookieVal);
		expect(redacted).not.toContain("hdr_cookie_secret_445566");
		expect(redacted).not.toContain("sid***45"); // 严禁因前缀撑长导致短 Cookie 泄露后两位
		expect(redacted).toContain("sid=******");
		expect(redacted).toContain("Bearer eyJ***99");

		const summary = formatSessionVaultSummary(root);
		expect(summary).toContain("role=alice");
		expect(summary).not.toContain(jwt);
		expect(summary).not.toContain(apiKey);
		expect(summary).not.toContain(pass);
		expect(summary).not.toContain(shortCookieVal);
	});

	test("materializeRoleHeaderFile 写入 0o600 头文件并阻断路径穿越", () => {
		const root = makeTmpDir("nuwa-mat-");
		const projectId = makeTestProjectId("vault");

		upsertSessionRole(root, {
			role: "editor",
			cookie: "session=editor_cookie_abcdef1234",
			bearer: "token_abcdef123456",
			headers: { "X-Tenant-Id": "tenant-42" },
		});

		const headerPath = materializeRoleHeaderFile(root, projectId, "editor");
		expect(headerPath).toBe(join("/tmp/nuwa", projectId, "sessions", "editor.headers"));
		expect(statSync(join("/tmp/nuwa", projectId, "sessions")).mode & 0o777).toBe(0o700);
		expect(statSync(headerPath!).mode & 0o777).toBe(0o600);

		const content = readFileSync(headerPath!, "utf8");
		expect(content).toContain("Cookie: session=editor_cookie_abcdef1234");
		expect(content).toContain("Authorization: Bearer token_abcdef123456");
		expect(content).toContain("X-Tenant-Id: tenant-42");

		expect(materializeRoleHeaderFile(root, projectId, "missing_role")).toBeNull();
		expect(() => materializeRoleHeaderFile(root, "../escape", "editor")).toThrow();
		expect(() => materializeRoleHeaderFile(root, projectId, "../root")).toThrow();

		clearSessionVault(root, projectId);
		expect(existsSync(headerPath!)).toBe(false);
	});

	test("buildAuthDiffPacketSection 仅对鉴权/接口意图触发、物化头文件且绝不泄漏明文", () => {
		const root = makeTmpDir("nuwa-diff-");
		const projectId = makeTestProjectId("diff");

		// 空保险箱不附加
		expect(buildAuthDiffPacketSection(root, "vuln:idor", projectId)).toBe("");

		const adminTok = "admin_super_secret_token_778899";
		const userCookie = "sid=user_b_secret_cookie_556677";
		upsertSessionRole(root, { role: "admin", bearer: adminTok });
		upsertSessionRole(root, { role: "user_b", cookie: userCookie });

		// 非鉴权意图不附加
		expect(buildAuthDiffPacketSection(root, "recon:ports", projectId)).toBe("");
		expect(buildAuthDiffPacketSection(root, "vuln:xss", projectId)).toBe("");

		// 命中 idor / authbypass / auth / ep:* / api
		for (const key of ["idor", "vuln:idor", "authbypass", "surface:auth", "ep:/api/v1/orders", "api"]) {
			const section = buildAuthDiffPacketSection(root, key, projectId);
			expect(section).toContain("多角色会话差分重放指引");
			expect(section).toContain(`/tmp/nuwa/${projectId}/sessions/admin.headers`);
			expect(section).toContain(`/tmp/nuwa/${projectId}/sessions/user_b.headers`);
			expect(section).toContain("curl -k -sS -H @");
			expect(section).not.toContain(adminTok);
			expect(section).not.toContain(userCookie);
		}
	});

	test("ingestCredFactToVault 自动提取 Set-Cookie / Bearer / API-Key / 账号密码入库", () => {
		const root = makeTmpDir("nuwa-ingest-");

		// 非 cred 事实忽略
		expect(
			ingestCredFactToVault(root, {
				id: "f001",
				kind: "service",
				title: "HTTP 200",
				detail: "Set-Cookie: sid=ignored_non_cred_12345",
			}),
		).toBeNull();

		const entry = ingestCredFactToVault(root, {
			id: "f002",
			kind: "cred",
			title: "获取普通用户登录会话",
			detail: "role: alice username=alice password=AliceSecret#99",
			output: [
				"HTTP/1.1 200 OK",
				"Set-Cookie: sessionid=alice_sess_token_12345; HttpOnly; Path=/",
				"Set-Cookie: csrftoken=csrf_9988776655; Path=/",
				"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.alicepayload.sig1234",
				"X-API-Key: ak_alice_99887766",
			].join("\n"),
		});

		expect(entry).not.toBeNull();
		expect(entry!.role).toBe("alice");
		expect(entry!.cookie).toBe("sessionid=alice_sess_token_12345; csrftoken=csrf_9988776655");
		expect(entry!.bearer).toBe("eyJhbGciOiJIUzI1NiJ9.alicepayload.sig1234");
		expect(entry!.headers?.["X-API-Key"]).toBe("ak_alice_99887766");
		expect(entry!.username).toBe("alice");
		expect(entry!.password).toBe("AliceSecret#99");
		expect(entry!.sourceFactId).toBe("f002");
	});
});

describe("omp/verifier-gate.ts 双盲独立复验闸门", () => {
	test("isDoubleBlindEnabled 开关与 isVerifyVulnIntentKey 判定", () => {
		setTempEnv("NUWA_DOUBLE_BLIND", undefined);
		expect(isDoubleBlindEnabled()).toBe(true);
		setTempEnv("NUWA_DOUBLE_BLIND", "1");
		expect(isDoubleBlindEnabled()).toBe(true);
		setTempEnv("NUWA_DOUBLE_BLIND", "0");
		expect(isDoubleBlindEnabled()).toBe(false);

		expect(isVerifyVulnIntentKey("verify-vuln:f001")).toBe(true);
		expect(isVerifyVulnIntentKey("vuln:verify-vuln:f002")).toBe(true);
		expect(isVerifyVulnIntentKey("exploit:verify-vuln:f099")).toBe(true);
		expect(isVerifyVulnIntentKey("vuln:sqli")).toBe(false);
		expect(isVerifyVulnIntentKey("exploit:verify")).toBe(false);
		expect(isVerifyVulnIntentKey("")).toBe(false);
	});

	test("shouldStageAsCandidate 仅对非自动批、非 verify-vuln:* 的 vuln 生效", () => {
		setTempEnv("NUWA_DOUBLE_BLIND", "1");
		expect(shouldStageAsCandidate({ kind: "vuln", intentKey: "vuln:idor" })).toBe(true);
		expect(shouldStageAsCandidate({ kind: "vuln", intentKey: "vuln:idor", autoVerified: true })).toBe(false);
		expect(shouldStageAsCandidate({ kind: "vuln", intentKey: "vuln:idor", isAuto: true })).toBe(false);
		expect(shouldStageAsCandidate({ kind: "vuln", intentKey: "verify-vuln:f001" })).toBe(false);
		expect(shouldStageAsCandidate({ kind: "vuln", intentKey: "vuln:verify-vuln:f001" })).toBe(false);
		expect(shouldStageAsCandidate({ kind: "flag", intentKey: "exploit:verify" })).toBe(false);
		expect(shouldStageAsCandidate({ kind: "service", intentKey: "recon:http" })).toBe(false);

		setTempEnv("NUWA_DOUBLE_BLIND", "0");
		expect(shouldStageAsCandidate({ kind: "vuln", intentKey: "vuln:idor" })).toBe(false);
	});

	test("candidate -> P96 独立复验意图 -> confirmed / rejected 结算与 filterConfirmedProofs 门禁", () => {
		setTempEnv("NUWA_DOUBLE_BLIND", "1");
		const st = makeMockState("audit");

		const cand1: VerifiableFact = {
			id: "f001",
			kind: "vuln",
			title: "疑似越权读取 /api/orders/1002",
			detail: "user_a 请求返回 200",
			command: "curl -sS http://target.example.test:8080/api/orders/1002",
			output: '{"orderId":1002,"owner":"user_b"}',
			createdAt: "2026-11-24T00:01:00.000Z",
			verifyStage: "candidate",
		};
		const cand2: VerifiableFact = {
			id: "f002",
			kind: "vuln",
			title: "疑似未授权调试页",
			detail: "返回 200 但疑似通用首页",
			createdAt: "2026-11-24T00:02:00.000Z",
			verifyStage: "candidate",
		};
		st.facts.f001 = cand1;
		st.facts.f002 = cand2;

		// 仅有 candidate 漏洞时，filterConfirmedProofs 必须拒绝过早验收
		expect(filterConfirmedProofs(st.facts, ["vuln", "loot"])).toEqual([]);

		// 生成 P96 双盲复验意图（推荐 nuwa-verifier + 正负对照）
		const spec1 = buildDoubleBlindVerifyIntentSpec(st, cand1);
		expect(spec1).not.toBeNull();
		expect(spec1!.key).toBe("verify-vuln:f001");
		expect(spec1!.priority).toBe(DOUBLE_BLIND_VERIFY_PRIORITY);
		expect(spec1!.priority).toBe(96);
		expect(spec1!.recommendedAgent).toBe("nuwa-verifier");
		expect(spec1!.from).toEqual(["f001"]);
		expect(spec1!.detail).toContain("nuwa-verifier");
		expect(spec1!.detail).toContain("正例");
		expect(spec1!.detail).toContain("负例");

		// 落入 intents 后同目标去重
		st.intents.i010 = {
			id: "i010",
			phase: spec1!.phase,
			key: spec1!.key,
			title: spec1!.title,
			detail: spec1!.detail,
			from: spec1!.from,
			status: "open",
			priority: spec1!.priority,
			attempts: 0,
			createdAt: "2026-11-24T00:03:00.000Z",
		};
		expect(buildDoubleBlindVerifyIntentSpec(st, cand1)).toBeNull();

		// 复验驳回 f002 -> rejected，仍然不予验收
		const rej = resolveVerificationOutcome(st, "verify-vuln:f002", true, "负例对照与随机路径响应完全一致，属于 Soft-404 误报");
		expect(rej.matched).toBe(true);
		expect(rej.stage).toBe("rejected");
		expect(cand2.verifyStage).toBe("rejected");
		expect(cand2.verified).toBe(false);
		expect(cand2.verifyNote).toContain("Soft-404");
		expect(filterConfirmedProofs(Object.values(st.facts), ["vuln"])).toEqual([]);

		// 复验确认 f001 -> confirmed，验收放行
		const conf = resolveVerificationOutcome(st, "verify-vuln:f001", false, "正负对照差异显著，稳定复现");
		expect(conf.matched).toBe(true);
		expect(conf.stage).toBe("confirmed");
		expect(cand1.verifyStage).toBe("confirmed");
		expect(cand1.verified).toBe(true);
		const confirmedProofs = filterConfirmedProofs(st.facts, ["vuln", "loot"]);
		expect(confirmedProofs.map((f) => f.id)).toEqual(["f001"]);

		// 历史无 verifyStage 事实（如自动批实锤 vuln 或旧版已实锤事实）正常放行
		st.facts.f003 = {
			id: "f003",
			kind: "vuln",
			title: "历史版本实锤漏洞",
			detail: "自动批已实锤",
			createdAt: "2026-11-24T00:04:00.000Z",
		};
		const proofsWithLegacy = filterConfirmedProofs(st.facts, ["vuln"]);
		expect(proofsWithLegacy.map((f) => f.id).sort()).toEqual(["f001", "f003"]);

		// 非 verify-vuln 键不误改任何状态
		expect(resolveVerificationOutcome(st, "vuln:idor", false).matched).toBe(false);
	});
});

describe("omp/sandbox.ts 零信任 Docker 沙盒与容器侧 Scope 白名单", () => {
	test("readSandboxConfig 解析默认值并强制禁用 host 网络模式", () => {
		const def = readSandboxConfig({});
		expect(def.mode).toBe("none");
		expect(def.image).toBe("nuwa-sandbox:latest");
		expect(def.memory).toBe("512m");
		expect(def.cpus).toBe("1");
		expect(def.pidsLimit).toBe(256);
		expect(def.network).toBe("bridge");

		const custom = readSandboxConfig({
			NUWA_SANDBOX: "docker",
			NUWA_SANDBOX_IMAGE: "corp/nuwa-box:v4",
			NUWA_SANDBOX_MEMORY: "1g",
			NUWA_SANDBOX_CPUS: "2",
			NUWA_SANDBOX_PIDS_LIMIT: "128",
			NUWA_SANDBOX_NETWORK: "host", // 零信任强降级为 bridge
		});
		expect(custom.mode).toBe("docker");
		expect(custom.image).toBe("corp/nuwa-box:v4");
		expect(custom.memory).toBe("1g");
		expect(custom.cpus).toBe("2");
		expect(custom.pidsLimit).toBe(128);
		expect(custom.network).toBe("bridge");
	});

	test("buildDockerRunArgs 与 wrapCommandInDockerSandbox 严格执行零信任挂载、权限与环境变量隔离", () => {
		setTempEnv("OPENAI_API_KEY", "sk-openai-super-secret-value-9999");
		setTempEnv("ANTHROPIC_API_KEY", "sk-ant-super-secret-value-8888");
		setTempEnv("GEMINI_API_KEY", "AIzaSy-super-secret-gemini-7777");
		setTempEnv("AWS_SECRET_ACCESS_KEY", "aws-secret-value-66665555");

		const projectId = "proj-zero-trust-1";
		const scope: ScopePolicy = {
			allowHosts: ["target.example.test"],
			allowCidrs: ["10.20.0.0/24"],
			denyHosts: ["blocked.example.test"],
			allowSubdomains: true,
			allowPrivateNetwork: false,
			allowDestructive: false,
		};

		const args = buildDockerRunArgs({
			projectId,
			command: "curl -sS http://target.example.test/",
			scope,
			config: { mode: "docker", image: "nuwa-sandbox:v4" },
			extraEnv: {
				SAFE_TRACE_TAG: "trace-01",
				OPENAI_API_KEY: "should-never-pass",
				MY_TOKEN: "should-never-pass-2",
				SNEAKY_ALIAS: "sk-openai-super-secret-value-9999", // 与宿主敏感值相等，必须剔除
			},
		});

		expect(args).toContain("--cap-drop=ALL");
		expect(args).toContain("--security-opt=no-new-privileges");
		expect(args).toContain("--pids-limit=256");
		expect(args).toContain("--memory=512m");
		expect(args).toContain("--cpus=1");
		expect(args).toContain("--read-only");
		expect(args).toContain("--network=bridge");
		expect(args).not.toContain("--privileged");
		expect(args).not.toContain("--network=host");
		expect(args).not.toContain("--pid=host");

		// 仅挂载唯一 /tmp/nuwa/<projectId>
		const mountIndices = args.map((v, i) => (v === "-v" || v === "--volume" || v === "--mount" ? i : -1)).filter((i) => i >= 0);
		expect(mountIndices.length).toBe(1);
		expect(args[mountIndices[0]! + 1]).toBe(`/tmp/nuwa/${projectId}:/tmp/nuwa/${projectId}:rw`);

		// 严禁出现敏感宿主机路径与任何 API Key
		const joined = args.join(" ");
		expect(joined).not.toContain(homedir());
		expect(joined).not.toContain(".ssh");
		expect(joined).not.toContain(".omp");
		expect(joined).not.toContain("docker.sock");
		expect(joined).not.toContain("OPENAI_API_KEY");
		expect(joined).not.toContain("ANTHROPIC_API_KEY");
		expect(joined).not.toContain("GEMINI_API_KEY");
		expect(joined).not.toContain("AWS_SECRET_ACCESS_KEY");
		expect(joined).not.toContain("sk-openai-super-secret-value-9999");
		expect(joined).not.toContain("MY_TOKEN");
		expect(joined).not.toContain("SNEAKY_ALIAS");
		expect(joined).toContain("SAFE_TRACE_TAG=trace-01");
		expect(joined).toContain("NUWA_SCOPE_ALLOW_HOSTS=target.example.test");

		// 非法 projectId 拦截
		expect(() => buildDockerRunArgs({ projectId: "../etc", command: "id" })).toThrow();
		expect(() => buildDockerRunArgs({ projectId: "a/b", command: "id" })).toThrow();

		// mode="none" 原样透传；mode="docker" 返回完整包装命令
		const rawCmd = "curl -sS http://target.example.test/";
		expect(wrapCommandInDockerSandbox(rawCmd, { projectId, config: { mode: "none" } })).toBe(rawCmd);

		const wrapped = wrapCommandInDockerSandbox(rawCmd, {
			projectId,
			scope,
			config: { mode: "docker", image: "nuwa-sandbox:v4" },
		});
		expect(wrapped).toContain("'docker' 'run'");
		expect(wrapped).toContain("'--cap-drop=ALL'");
		expect(wrapped).toContain("'--security-opt=no-new-privileges'");
		expect(wrapped).toContain("'--pids-limit=256'");
		expect(wrapped).not.toContain("sk-openai-super-secret-value-9999");
	});

	test("容器侧 ScopePolicy 外连白名单前置脚本真实执行放行与拦截", () => {
		const script = buildContainerScopePreflightScript();
		const runPreflight = (cmd: string, envOverrides: Record<string, string>) =>
			spawnSync("sh", ["-c", script, "nuwa-sandbox", cmd], {
				encoding: "utf8",
				env: {
					PATH: process.env.PATH ?? "/usr/bin:/bin",
					NUWA_SCOPE_ALLOW_HOSTS: "target.example.test",
					NUWA_SCOPE_ALLOW_CIDRS: "10.20.0.0/24",
					NUWA_SCOPE_DENY_HOSTS: "admin.target.example.test",
					NUWA_SCOPE_ALLOW_SUBDOMAINS: "1",
					NUWA_SCOPE_ALLOW_PRIVATE: "0",
					...envOverrides,
				},
				timeout: 10_000,
			});

		// 1. 授权域名与子域名放行（用 echo 模拟只读命令避免真实发外网）
		const okAllowed = runPreflight("echo http://api.target.example.test/health 10.20.0.15", {});
		expect(okAllowed.status).toBe(0);
		expect(okAllowed.stdout).toContain("api.target.example.test");

		// 2. 越界 URL 拦截 (exit 126)
		const blockedUrl = runPreflight("curl -sS https://evil.outside.test/leak", {});
		expect(blockedUrl.status).toBe(126);
		expect(blockedUrl.stderr).toContain("nuwa-sandbox N-007");
		expect(blockedUrl.stderr).toContain("evil.outside.test");

		// 3. 越界裸域名（nmap）拦截 (exit 126)
		const blockedBare = runPreflight("nmap -p 80 evil.outside.test", {});
		expect(blockedBare.status).toBe(126);
		expect(blockedBare.stderr).toContain("nuwa-sandbox N-007");

		// 4. denyHosts 黑名单优先级高于 allowSubdomains
		const blockedDeny = runPreflight("curl -sS https://admin.target.example.test/", {});
		expect(blockedDeny.status).toBe(126);
		expect(blockedDeny.stderr).toContain("denyHosts");

		// 5. 未授权私网 IP 拦截
		const blockedPriv = runPreflight("curl -sS http://192.168.1.10/", {});
		expect(blockedPriv.status).toBe(126);
		expect(blockedPriv.stderr).toContain("私网");

		// 6. Python socket 越界外连拦截
		const blockedPySock = runPreflight(
			`python3 -c "import socket; socket.create_connection(('evil.outside.test', 80))"`,
			{},
		);
		expect(blockedPySock.status).toBe(126);
		expect(blockedPySock.stderr).toContain("nuwa-sandbox N-007");
	});

	test("probeDockerAvailable 使用 stub 核验不可用、缺镜像与完全就绪三种状态", () => {
		const missing = probeDockerAvailable({ dockerBin: "/nonexistent/docker-bin-xyz" });
		expect(missing.available).toBe(false);
		expect(missing.daemonRunning).toBe(false);
		expect(missing.imagePresent).toBe(false);

		const work = makeTmpDir("nuwa-docker-stub-");
		const stubOk = join(work, "docker-ok.sh");
		writeFileSync(
			stubOk,
			`#!/usr/bin/env sh
if [ "$1" = "info" ]; then
  echo "27.3.1"
  exit 0
fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ] && [ "$3" = "nuwa-sandbox:latest" ]; then
  echo "[]"
  exit 0
fi
exit 1
`,
			"utf8",
		);
		chmodSync(stubOk, 0o755);

		const okRes = probeDockerAvailable({ dockerBin: stubOk, image: "nuwa-sandbox:latest" });
		expect(okRes.available).toBe(true);
		expect(okRes.daemonRunning).toBe(true);
		expect(okRes.imagePresent).toBe(true);
		expect(okRes.serverVersion).toBe("27.3.1");

		const noImgRes = probeDockerAvailable({ dockerBin: stubOk, image: "nuwa-sandbox:missing" });
		expect(noImgRes.available).toBe(true);
		expect(noImgRes.daemonRunning).toBe(true);
		expect(noImgRes.imagePresent).toBe(false);
		expect(noImgRes.reason).toContain("缺少镜像");
	});
});

describe("bin/nuwa-autonomous v4 沙盒/模型路由透传与 doctor [--json]", () => {
	test("--sandbox / --sandbox-image / --fast-model / --deep-model / --verify-model 透传与非法值校验", () => {
		const root = makeTmpDir("nuwa-v4-cli-");

		const badSandbox = runDaemon(["--target", "http://127.0.0.1:8080", "--root", root, "--sandbox", "vm"]);
		expect(badSandbox.status).toBe(2);
		expect(badSandbox.stderr).toContain("--sandbox");

		const badImage = runDaemon([
			"--target",
			"http://127.0.0.1:8080",
			"--root",
			root,
			"--sandbox",
			"docker",
			"--sandbox-image",
			"--privileged",
		]);
		expect(badImage.status).toBe(2);
		expect(badImage.stderr).toContain("--sandbox-image");

		const dry = runDaemon([
			"--target",
			"http://127.0.0.1:18090",
			"--root",
			root,
			"--sandbox",
			"docker",
			"--sandbox-image",
			"nuwa-sandbox:v4",
			"--fast-model",
			"gemini-fast",
			"--deep-model",
			"gemini-deep",
			"--verify-model",
			"gemini-verify",
			"--dry-run",
		]);
		expect(dry.status).toBe(0);
		expect(dry.stdout).toContain('"NUWA_SANDBOX": "docker"');
		expect(dry.stdout).toContain('"NUWA_SANDBOX_IMAGE": "nuwa-sandbox:v4"');
		expect(dry.stdout).toContain('"NUWA_MODEL_FAST": "gemini-fast"');
		expect(dry.stdout).toContain('"NUWA_MODEL_DEEP": "gemini-deep"');
		expect(dry.stdout).toContain('"NUWA_MODEL_VERIFY": "gemini-verify"');

		// 实际拉起 stub omp 验证子进程环境变量透传与 daemon-config.json 落盘
		const envDump = join(root, "child-env.json");
		const stubOmp = join(root, "omp-env-stub.py");
		writeFileSync(
			stubOmp,
			`#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["NUWA_PROJECT"])
(root / ".nuwa").mkdir(parents=True, exist_ok=True)
keys = ["NUWA_SANDBOX", "NUWA_SANDBOX_IMAGE", "NUWA_MODEL_FAST", "NUWA_MODEL_DEEP", "NUWA_MODEL_VERIFY"]
pathlib.Path(${JSON.stringify(envDump)}).write_text(json.dumps({k: os.environ.get(k) for k in keys}), encoding="utf-8")
st = {
    "schema": 1, "version": "4.0.0",
    "project": {"id": "p1", "target": "http://127.0.0.1:18090", "url": "http://127.0.0.1:18090", "mode": "ctf", "status": "completed", "phase": "report"},
    "facts": {"f001": {"id": "f001", "kind": "flag", "title": "flag", "detail": "flag{ok}"}},
    "intents": {}, "seq": {"fact": 1, "intent": 0}, "runtime": {"generation": 1}
}
(root / ".nuwa" / "state.json").write_text(json.dumps(st), encoding="utf-8")
sys.exit(0)
`,
			"utf8",
		);
		chmodSync(stubOmp, 0o755);

		const runRes = runDaemon([
			"--target",
			"http://127.0.0.1:18090",
			"--root",
			root,
			"--sandbox",
			"docker",
			"--sandbox-image",
			"nuwa-sandbox:v4",
			"--fast-model",
			"m-fast",
			"--deep-model",
			"m-deep",
			"--verify-model",
			"m-verify",
			"--omp-bin",
			stubOmp,
		]);
		expect(runRes.status).toBe(0);

		const receivedEnv = JSON.parse(readFileSync(envDump, "utf8"));
		expect(receivedEnv).toEqual({
			NUWA_SANDBOX: "docker",
			NUWA_SANDBOX_IMAGE: "nuwa-sandbox:v4",
			NUWA_MODEL_FAST: "m-fast",
			NUWA_MODEL_DEEP: "m-deep",
			NUWA_MODEL_VERIFY: "m-verify",
		});

		const persistedCfg = JSON.parse(readFileSync(join(root, ".nuwa", "daemon-config.json"), "utf8"));
		expect(persistedCfg.sandbox).toBe("docker");
		expect(persistedCfg.sandboxImage).toBe("nuwa-sandbox:v4");
		expect(persistedCfg.fastModel).toBe("m-fast");
		expect(persistedCfg.deepModel).toBe("m-deep");
		expect(persistedCfg.verifyModel).toBe("m-verify");
	});

	test("doctor [--json] 在核心依赖就绪时退出 0 并准确统计 12 工具、KB 记录数、模板与沙盒；缺失核心依赖退出 1", () => {
		const work = makeTmpDir("nuwa-doctor-");
		const agentHome = join(work, "agent-home");
		const extDir = join(agentHome, "extensions", "nuwa-omp");
		const agentsDir = join(agentHome, "agents");
		const kbDir = join(agentHome, "nuwa-kb");
		mkdirSync(extDir, { recursive: true });
		mkdirSync(agentsDir, { recursive: true });
		mkdirSync(kbDir, { recursive: true });

		// 构造完整扩展（12 个工具 + 8 核心模块 + 3 个本分支 v4 模块）
		const toolDefs = [
			"nuwa_init",
			"nuwa_plan",
			"nuwa_frontier",
			"nuwa_claim",
			"nuwa_commit",
			"nuwa_flag",
			"nuwa_complete",
			"nuwa_status",
			"nuwa_report",
			"nuwa_expand",
			"nuwa_stop",
			"nuwa_kb",
		]
			.map((t) => `registerTool({ name: "${t}" });`)
			.join("\n");
		writeFileSync(join(extDir, "index.ts"), `export const VERSION = "4.0.0";\n${toolDefs}\n`, "utf8");
		for (const mod of [
			"types.ts",
			"ui.ts",
			"ui-native.ts",
			"autoexec.ts",
			"scope.ts",
			"evidence.ts",
			"profiles.ts",
			"reincarnate.ts",
			"session-vault.ts",
			"verifier-gate.ts",
			"sandbox.ts",
		]) {
			writeFileSync(join(extDir, mod), `export const mod = ${JSON.stringify(mod)};\n`, "utf8");
		}

		// 构造子代理模板
		writeFileSync(join(agentsDir, "fujiang.md"), "---\nname: fujiang\n---\n合规执行子代理\n", "utf8");
		writeFileSync(join(agentsDir, "nuwa-verifier.md"), "---\nname: nuwa-verifier\n---\n双盲复验审查子代理\n", "utf8");

		// 构造真实 SQLite KB 并写入记录
		const kbPath = join(kbDir, "kb.db");
		const db = new Database(kbPath);
		db.run("CREATE TABLE card (id INTEGER PRIMARY KEY, name TEXT);");
		db.run("CREATE TABLE cve (id INTEGER PRIMARY KEY, cve_id TEXT);");
		db.run("CREATE TABLE technique (id INTEGER PRIMARY KEY, tid TEXT);");
		db.run("CREATE TABLE experience (id INTEGER PRIMARY KEY, tech_key TEXT);");
		db.run("INSERT INTO card (name) VALUES ('nginx'), ('spring');");
		db.run("INSERT INTO cve (cve_id) VALUES ('CVE-2021-44228'), ('CVE-2022-22965'), ('CVE-2023-22515');");
		db.run("INSERT INTO technique (tid) VALUES ('T1190');");
		db.run("INSERT INTO experience (tech_key) VALUES ('nginx');");
		db.close();

		// 构造 stub omp 与 stub docker
		const ompStub = join(work, "omp-stub.sh");
		writeFileSync(ompStub, "#!/usr/bin/env sh\necho 'omp/18.20.0'\nexit 0\n", "utf8");
		chmodSync(ompStub, 0o755);

		const dockerStub = join(work, "docker-stub.sh");
		writeFileSync(
			dockerStub,
			`#!/usr/bin/env sh
if [ "$1" = "info" ]; then echo "27.4.0"; exit 0; fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then echo "[]"; exit 0; fi
exit 1
`,
			"utf8",
		);
		chmodSync(dockerStub, 0o755);

		// 1. 完整就绪场景 (--json) -> exit 0
		const okJson = runDaemon([
			"doctor",
			"--json",
			"--agent-home",
			agentHome,
			"--omp-bin",
			ompStub,
			"--docker-bin",
			dockerStub,
			"--sandbox-image",
			"nuwa-sandbox:latest",
		]);
		expect(okJson.status).toBe(0);
		const parsed = JSON.parse(okJson.stdout);
		expect(parsed.ok).toBe(true);
		expect(parsed.exitCode).toBe(0);
		expect(parsed.checks.bun.ok).toBe(true);
		expect(parsed.checks.omp.ok).toBe(true);
		expect(parsed.checks.omp.version).toContain("18.20.0");
		expect(parsed.checks.extension.ok).toBe(true);
		expect(parsed.checks.extension.toolsCount).toBe(12);
		expect(parsed.checks.extension.v4ModulesFound).toContain("session-vault.ts");
		expect(parsed.checks.extension.v4ModulesFound).toContain("verifier-gate.ts");
		expect(parsed.checks.extension.v4ModulesFound).toContain("sandbox.ts");
		expect(parsed.checks.kb.ok).toBe(true);
		expect(parsed.checks.kb.totalRecords).toBe(7);
		expect(parsed.checks.kb.counts.card).toBe(2);
		expect(parsed.checks.kb.counts.cve).toBe(3);
		expect(parsed.checks.agents.ok).toBe(true);
		expect(parsed.checks.agents.fujiang.exists).toBe(true);
		expect(parsed.checks.agents.nuwaVerifier.exists).toBe(true);
		expect(parsed.checks.toolchain.available.length).toBeGreaterThan(0);
		expect(parsed.checks.docker.ok).toBe(true);
		expect(parsed.checks.docker.serverVersion).toBe("27.4.0");

		// 2. 人类可读文本模式 -> exit 0
		const okText = runDaemon([
			"doctor",
			"--agent-home",
			agentHome,
			"--omp-bin",
			ompStub,
			"--docker-bin",
			dockerStub,
		]);
		expect(okText.status).toBe(0);
		expect(okText.stdout).toContain("女娲环境健康体检");
		expect(okText.stdout).toContain("[OK] bun:");
		expect(okText.stdout).toContain("[OK] omp:");
		expect(okText.stdout).toContain("工具 12/12");
		expect(okText.stdout).toContain("总记录 7");

		// 3. 缺失核心依赖 omp -> exit 1
		const noOmp = runDaemon([
			"doctor",
			"--json",
			"--agent-home",
			agentHome,
			"--omp-bin",
			"/nonexistent/omp-missing",
			"--docker-bin",
			dockerStub,
		]);
		expect(noOmp.status).toBe(1);
		const noOmpJson = JSON.parse(noOmp.stdout);
		expect(noOmpJson.ok).toBe(false);
		expect(noOmpJson.summary.criticalFailed).toContain("omp");

		// 4. 缺失核心扩展 -> exit 1
		const emptyAgentHome = makeTmpDir("nuwa-empty-agent-");
		const noExt = runDaemon([
			"doctor",
			"--json",
			"--agent-home",
			emptyAgentHome,
			"--omp-bin",
			ompStub,
			"--docker-bin",
			dockerStub,
		]);
		expect(noExt.status).toBe(1);
		const noExtJson = JSON.parse(noExt.stdout);
		expect(noExtJson.ok).toBe(false);
		expect(noExtJson.summary.criticalFailed).toContain("extension");

		// 5. 显式要求 --sandbox docker 但 docker 缺失 -> exit 1
		const noDockerStrict = runDaemon([
			"doctor",
			"--json",
			"--agent-home",
			agentHome,
			"--omp-bin",
			ompStub,
			"--sandbox",
			"docker",
			"--docker-bin",
			"/nonexistent/docker-missing",
		]);
		expect(noDockerStrict.status).toBe(1);
		const noDockerJson = JSON.parse(noDockerStrict.stdout);
		expect(noDockerJson.ok).toBe(false);
		expect(noDockerJson.summary.criticalFailed).toContain("docker");

		// 6. 默认主机模式（--sandbox none）下 docker 缺失仅作非阻断提醒 -> exit 0
		const noDockerSoft = runDaemon([
			"doctor",
			"--json",
			"--agent-home",
			agentHome,
			"--omp-bin",
			ompStub,
			"--docker-bin",
			"/nonexistent/docker-missing",
		]);
		expect(noDockerSoft.status).toBe(0);
		const noDockerSoftJson = JSON.parse(noDockerSoft.stdout);
		expect(noDockerSoftJson.ok).toBe(true);
		expect(noDockerSoftJson.checks.docker.ok).toBe(false);
	});
});
