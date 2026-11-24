/**
 * v3.0 靶标范围护栏（omp/scope.ts）与真实执行证据复验/工具链探针（omp/evidence.ts）单元测试。
 *
 * 安全红线：仅使用本地纯函数校验、内存/临时目录 stub，不向任何公网目标发起请求。
 */
import { afterAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	checkNuwaDirTamper,
	checkScopeAndRisk,
	defaultScopeForTarget,
	extractCommandTargets,
	isHostInScope,
	type ScopePolicy,
} from "../omp/scope";
import {
	adaptPacketForToolchain,
	hasExecutionHistory,
	probeToolchain,
	recordToolExecution,
	verifyExecutionEvidence,
} from "../omp/evidence";

const tempPaths: string[] = [];

function makeTempDir(prefix: string): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	tempPaths.push(d);
	return d;
}

afterAll(() => {
	for (const p of tempPaths) {
		rmSync(p, { recursive: true, force: true });
	}
});

describe("omp/scope.ts — ScopePolicy 与目标提取", () => {
	test("defaultScopeForTarget 解析 URL、host:port、IPv6 与环境变量覆盖", () => {
		const s1 = defaultScopeForTarget("https://App.Target.Test:8443/v1/login", "pentest");
		expect(s1.allowHosts).toEqual(["app.target.test"]);
		expect(s1.allowSubdomains).toBe(false);
		expect(s1.allowPrivateNetwork).toBe(false);
		expect(s1.allowDestructive).toBe(false);

		const s2 = defaultScopeForTarget("10.20.30.40:8080", "ctf", {
			allowCidrs: ["10.20.30.0/24"],
			denyHosts: ["10.20.30.99"],
		});
		expect(s2.allowHosts).toEqual(["10.20.30.40"]);
		expect(s2.allowCidrs).toEqual(["10.20.30.0/24"]);
		expect(s2.denyHosts).toEqual(["10.20.30.99"]);

		const sIpv6 = defaultScopeForTarget("http://[::1]:18080/health", "ctf");
		expect(sIpv6.allowHosts).toEqual(["::1"]);

		const sCoding = defaultScopeForTarget("./local-project", "coding");
		expect(sCoding.allowHosts).toContain("127.0.0.1");

		const prevSub = process.env.NUWA_SCOPE_ALLOW_SUBDOMAINS;
		const prevCidr = process.env.NUWA_SCOPE_ALLOW_CIDRS;
		process.env.NUWA_SCOPE_ALLOW_SUBDOMAINS = "1";
		process.env.NUWA_SCOPE_ALLOW_CIDRS = "192.168.50.0/24, 172.16.0.0/16";
		try {
			const sEnv = defaultScopeForTarget("target.test", "audit");
			expect(sEnv.allowSubdomains).toBe(true);
			expect(sEnv.allowCidrs).toEqual(["192.168.50.0/24", "172.16.0.0/16"]);
		} finally {
			if (prevSub === undefined) delete process.env.NUWA_SCOPE_ALLOW_SUBDOMAINS;
			else process.env.NUWA_SCOPE_ALLOW_SUBDOMAINS = prevSub;
			if (prevCidr === undefined) delete process.env.NUWA_SCOPE_ALLOW_CIDRS;
			else process.env.NUWA_SCOPE_ALLOW_CIDRS = prevCidr;
		}
	});

	test("extractCommandTargets 覆盖 curl / nmap / openssl / python / URL / IP 且不误提取文件名与代码属性", () => {
		expect(extractCommandTargets("curl -k -sS https://api.target.test:8443/v1/users?redirect=http://inner.local")).toEqual(
			["api.target.test"],
		);

		expect(extractCommandTargets("nmap -sV -p 80,443 -oN /tmp/scan.nmap 10.0.0.5 target.test")).toEqual([
			"10.0.0.5",
			"target.test",
		]);

		expect(
			extractCommandTargets("openssl s_client -connect tls.target.test:443 -servername sni.target.test </dev/null"),
		).toEqual(["tls.target.test", "sni.target.test"]);

		// 验证 Python 端口扫描命令只提取目标参数，不把 socket.create_connection / concurrent.futures 当成域名
		const pyCmd =
			"python3 -c 'import socket, sys; from concurrent.futures import ThreadPoolExecutor; socket.create_connection((sys.argv[1], 80), 0.5)' '127.0.0.1'";
		expect(extractCommandTargets(pyCmd)).toEqual(["127.0.0.1"]);

		const pySocketLiteral = `python3 -c "import socket; socket.create_connection(('box.custom-domain', 8080))"`;
		expect(extractCommandTargets(pySocketLiteral)).toEqual(["box.custom-domain"]);

		expect(extractCommandTargets("curl --connect-to ::out-of-scope.org:443 https://target.test/")).toContain(
			"out-of-scope.org",
		);
	});

	test("isHostInScope：黑名单优先、精确匹配、*.domain、allowSubdomains、CIDR 掩码与回环处理", () => {
		const scope: ScopePolicy = {
			allowHosts: ["target.test", "*.corp.test"],
			allowCidrs: ["10.10.20.0/24"],
			denyHosts: ["forbidden.corp.test", "10.10.20.250"],
			allowSubdomains: false,
			allowPrivateNetwork: false,
			allowDestructive: false,
		};

		// 精确与通配子域
		expect(isHostInScope("target.test", scope).ok).toBe(true);
		expect(isHostInScope("api.target.test", scope).ok).toBe(false);
		expect(isHostInScope("dev.corp.test", scope).ok).toBe(true);
		expect(isHostInScope("a.b.corp.test", scope).ok).toBe(true);
		expect(isHostInScope("evil-corp.test", scope).ok).toBe(false);

		// 黑名单优先于 *.domain 与 CIDR
		expect(isHostInScope("forbidden.corp.test", scope).ok).toBe(false);
		expect(isHostInScope("10.10.20.250", scope).ok).toBe(false);

		// IPv4 CIDR 掩码
		expect(isHostInScope("10.10.20.1", scope).ok).toBe(true);
		expect(isHostInScope("10.10.20.254", scope).ok).toBe(true);
		expect(isHostInScope("10.10.21.1", scope).ok).toBe(false);

		// 回环地址默认允许，被显式拉黑时拦截
		expect(isHostInScope("127.0.0.1", scope).ok).toBe(true);
		expect(isHostInScope("localhost", scope).ok).toBe(true);
		expect(isHostInScope("::1", scope).ok).toBe(true);
		expect(isHostInScope("127.0.0.1", { ...scope, denyHosts: ["127.0.0.1"] }).ok).toBe(false);

		// allowSubdomains 开关与 allowPrivateNetwork 开关
		expect(isHostInScope("sub.target.test", { ...scope, allowSubdomains: true }).ok).toBe(true);
		expect(isHostInScope("192.168.1.88", scope).ok).toBe(false);
		expect(isHostInScope("192.168.1.88", { ...scope, allowPrivateNetwork: true }).ok).toBe(true);
	});
});

describe("omp/scope.ts — .nuwa 防篡改与 N-007 / N-008 拦截", () => {
	test("checkNuwaDirTamper 拦截 rm/mv/cp/sed -i/truncate/重定向/脚本篡改权威文件", () => {
		const tamperCmds = [
			"rm -f .nuwa/state.json",
			"rm -rf /tmp/work/.nuwa",
			"mv .nuwa/journal.jsonl /tmp/j.bak",
			"cp /tmp/fake.json .nuwa/state.json",
			"sed -i 's/active/completed/' .nuwa/state.json",
			"sed -i '' 's/active/completed/' .nuwa/state.json",
			"truncate -s 0 .nuwa/state.lock",
			"rm -f .nuwa/snap/170000-1.json.gz",
			"echo '{}' > .nuwa/state.json",
			"echo '{}' | tee -a .nuwa/exec-ledger.jsonl",
			`python3 -c "open('.nuwa/state.json', 'w').write('{}')"`,
			`node -e "require('fs').writeFileSync('.nuwa/journal.jsonl', '')"`,
		];
		for (const cmd of tamperCmds) {
			const v = checkNuwaDirTamper(cmd);
			expect(v?.block).toBe(true);
		}

		// 正常无关命令与非权威文档放行
		expect(checkNuwaDirTamper("curl -sS http://127.0.0.1:8080/api")).toBeNull();
		expect(checkNuwaDirTamper("rm -f /tmp/nuwa/p1/temp.txt")).toBeNull();
		expect(checkNuwaDirTamper("ls -la .nuwa/notes.md")).toBeNull();
	});

	test("checkScopeAndRisk：越界返回 N-007，高危破坏命令返回 N-008，合规命令返回 null", () => {
		const scope = defaultScopeForTarget("http://10.0.0.5:8080", "ctf");

		// Scope 内与本地回环放行
		expect(checkScopeAndRisk("curl -k -sS http://10.0.0.5:8080/login", scope, "ctf")).toBeNull();
		expect(checkScopeAndRisk("curl -sS http://127.0.0.1:9000/health", scope, "ctf")).toBeNull();
		expect(checkScopeAndRisk('h=$(mktemp); rm -f "$h"', scope, "ctf")).toBeNull();

		// 越界目标返回 N-007
		const out1 = checkScopeAndRisk("curl -sS https://example.com/api", scope, "ctf");
		expect(out1?.block).toBe(true);
		expect(out1?.reason).toContain("nuwa N-007");

		const out2 = checkScopeAndRisk("nmap -sV 8.8.8.8", scope, "pentest");
		expect(out2?.block).toBe(true);
		expect(out2?.reason).toContain("nuwa N-007");

		// 高危破坏命令返回 N-008
		const riskyCmds = [
			"rm -rf /var/www/html",
			"mkfs.ext4 /dev/sdb1",
			"dd if=/dev/zero of=/dev/sda bs=1M",
			"shutdown -h now",
			"sudo reboot",
			`mysql -h 127.0.0.1 -u root -e "DROP TABLE users;"`,
			`psql -h 127.0.0.1 -c "TRUNCATE TABLE accounts;"`,
		];
		for (const cmd of riskyCmds) {
			const v = checkScopeAndRisk(cmd, scope, "pentest");
			expect(v?.block).toBe(true);
			expect(v?.reason).toContain("nuwa N-008");
		}

		// 显式开启 allowDestructive 时放行破坏指令，但越界依然拦截
		const destructiveScope = { ...scope, allowDestructive: true };
		expect(checkScopeAndRisk("rm -rf /tmp/nuwa-sandbox-build", destructiveScope, "ops")).toBeNull();
		expect(checkScopeAndRisk("curl https://unauthorized.org", destructiveScope, "ops")?.reason).toContain("nuwa N-007");
	});
});

describe("omp/evidence.ts — 执行账本复验与工具链探针", () => {
	test("recordToolExecution 滚动保留最近 200 条摘要及 SHA1，verifyExecutionEvidence 拦截伪造 flag", () => {
		const root = makeTempDir("nuwa-ev-");
		const projectId = `proj-ev-${Date.now()}`;
		const prevStrict = process.env.NUWA_STRICT_EVIDENCE;
		delete process.env.NUWA_STRICT_EVIDENCE;

		try {
			expect(hasExecutionHistory(root)).toBe(false);

			// 无执行历史且非 strict 时保持向后兼容软放行
			const soft = verifyExecutionEvidence(root, {
				projectId,
				kind: "flag",
				flagValue: "flag{compat_legacy}",
				output: "flag{compat_legacy}",
			});
			expect(soft.ok).toBe(true);
			expect(soft.verified).toBe(false);

			// strict=true 时即使无历史也严格拒绝无依据证据
			const strictFail = verifyExecutionEvidence(root, {
				projectId,
				kind: "vuln",
				output: "uid=0(root) fabricated",
				strict: true,
			});
			expect(strictFail.ok).toBe(false);
			expect(strictFail.verified).toBe(false);

			// 写入 225 条执行记录，测试环形缓冲与磁盘 200 条滚动上限
			for (let i = 1; i <= 225; i++) {
				recordToolExecution(root, {
					tool: "bash",
					command: `curl -s http://127.0.0.1:8080/item/${i}`,
					output: i === 210 ? `HTTP 200\nsecret=flag{verified_real_210}\n` : `item-response-${i}`,
					sessionId: "sess-1",
				});
			}

			expect(hasExecutionHistory(root)).toBe(true);
			const ledgerPath = join(root, ".nuwa", "exec-ledger.jsonl");
			expect(existsSync(ledgerPath)).toBe(true);
			const lines = readFileSync(ledgerPath, "utf8").trim().split("\n");
			expect(lines.length).toBe(200);
			const firstEntry = JSON.parse(lines[0]);
			expect(typeof firstEntry.sha1).toBe("string");
			expect(firstEntry.sha1.length).toBe(40);
			expect(firstEntry.snippet).toContain("item-response-26");

			// 真实出现过的 flag 核验通过
			const okFlag = verifyExecutionEvidence(root, {
				projectId,
				kind: "flag",
				flagValue: "flag{verified_real_210}",
				output: "secret=flag{verified_real_210}",
			});
			expect(okFlag).toEqual({ ok: true, verified: true });

			// 从未在执行流出现过的伪造 flag 被拦截
			const fakeFlag = verifyExecutionEvidence(root, {
				projectId,
				kind: "flag",
				flagValue: "flag{never_executed_hallucination}",
				output: "flag{never_executed_hallucination}",
			});
			expect(fakeFlag.ok).toBe(false);
			expect(fakeFlag.verified).toBe(false);

			// /tmp/nuwa/<projectId>/ 产物文件命中核验
			const artDir = join("/tmp/nuwa", projectId);
			tempPaths.push(artDir);
			mkdirSync(artDir, { recursive: true });
			writeFileSync(join(artDir, "dump.txt"), "loot_row: flag{from_tmp_artifact_777}\n", "utf8");

			const artFlag = verifyExecutionEvidence(root, {
				projectId,
				kind: "flag",
				flagValue: "flag{from_tmp_artifact_777}",
				output: "flag{from_tmp_artifact_777}",
			});
			expect(artFlag).toEqual({ ok: true, verified: true });

			// NUWA_STRICT_EVIDENCE=0 显式放行
			process.env.NUWA_STRICT_EVIDENCE = "0";
			const bypassed = verifyExecutionEvidence(root, {
				projectId,
				kind: "flag",
				flagValue: "flag{bypass_when_disabled}",
				output: "flag{bypass_when_disabled}",
				strict: true,
			});
			expect(bypassed.ok).toBe(true);
			expect(bypassed.verified).toBe(false);
		} finally {
			if (prevStrict === undefined) delete process.env.NUWA_STRICT_EVIDENCE;
			else process.env.NUWA_STRICT_EVIDENCE = prevStrict;
		}
	});

	test("probeToolchain 与 adaptPacketForToolchain 探测并生成合规本地替代建议", () => {
		const defaultCaps = probeToolchain();
		expect(defaultCaps.available.length + defaultCaps.missing.length).toBe(11);
		expect(typeof defaultCaps.probedAt).toBe("string");

		const customCaps = probeToolchain(["python3", "curl", "nuwa_missing_scanner_xyz", "ffuf"]);
		expect(customCaps.available).toContain("python3");
		expect(customCaps.missing).toContain("nuwa_missing_scanner_xyz");

		const fakeCaps = {
			available: ["curl", "python3", "openssl"],
			missing: ["ffuf", "nmap", "sqlmap"],
			probedAt: new Date().toISOString(),
		};

		// 含缺失工具时附加提示
		const rawPacket = "执行内容:\n  nmap -sV 127.0.0.1\n  ffuf -u http://127.0.0.1/FUZZ";
		const adapted = adaptPacketForToolchain(rawPacket, fakeCaps);
		expect(adapted).toContain("[本地工具链适配提示]");
		expect(adapted).toContain("nmap");
		expect(adapted).toContain("ffuf");
		expect(adapted).toContain("python3");
		expect(adapted).toContain("curl");

		// 不含缺失工具时原样返回
		const cleanPacket = "执行内容:\n  curl -k -sS http://127.0.0.1:8080/";
		expect(adaptPacketForToolchain(cleanPacket, fakeCaps)).toBe(cleanPacket);
	});
});
