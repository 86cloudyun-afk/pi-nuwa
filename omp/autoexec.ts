/**
 * 确定性侦察执行器（2.6.0）：omp 扩展自己跑命令、自己入账，模型只做判断类意图。
 *
 * 边界：
 * - 只覆盖秒级、可解析、低风险的面（HTTP 指纹、TCP 连通、常见路径、TLS、敏感文件、API 文档）。
 * - 不跑 nmap 全端口 / ffuf 大字典 / 任何写操作；那些仍交给 fujiang 子代理。
 * - 脚本用 bash -lc 执行，参数走 shellQuote；每条 8–45s 超时。
 * - 解析器是纯函数，测试直接喂 stdout/stderr。
 */
import type { Cfg, NuwaState, Phase } from "./nuwa";

export interface ExecLikeResult {
	stdout: string;
	stderr: string;
	code: number;
	killed?: boolean;
}

export type ExecLike = (
	command: string,
	args: string[],
	options?: { timeout?: number; cwd?: string },
) => Promise<ExecLikeResult>;

export type AutoKind = "service" | "endpoint" | "asset" | "vuln" | "note" | "cred" | "loot";

export interface AutoFact {
	kind: AutoKind;
	title: string;
	detail: string;
	command: string;
	output: string;
}

export interface AutoRule {
	key: string;
	phase: Phase;
	timeoutMs: number;
	script(st: NuwaState): string;
	parse(res: ExecLikeResult, st: NuwaState): AutoFact | null;
}

export const AUTO_KEYS = [
	"recon:http",
	"recon:ports",
	"recon:dirs",
	"recon:tlsjs",
	"surface:sensitive",
	"surface:api",
] as const;

const AUTO_KEY_SET = new Set<string>(AUTO_KEYS);

export function isAutoKey(key: string): boolean {
	return AUTO_KEY_SET.has(key);
}

/** 单引号转义，供 bash -lc 内联使用。 */
export function shellQuote(value: string): string {
	return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

export function originOf(st: NuwaState): string {
	try {
		const u = new URL(st.project.url);
		return `${u.protocol}//${u.host}`;
	} catch {
		return st.project.url;
	}
}

function clip(text: string, max: number): string {
	const s = String(text ?? "").replace(/\r/g, "").trim();
	return s.length > max ? `${s.slice(0, max)}…` : s;
}

function headerValue(headers: string, name: string): string {
	const re = new RegExp(`^${name}:\\s*(.+)$`, "im");
	return headers.match(re)?.[1]?.trim() ?? "";
}

function titleOf(body: string): string {
	return body.match(/<title[^>]*>([^<]{0,120})<\/title>/i)?.[1]?.trim() ?? "";
}

const DIR_PATHS = [
	"/admin",
	"/login",
	"/api",
	"/api/v1",
	"/swagger-ui.html",
	"/swagger/index.html",
	"/openapi.json",
	"/robots.txt",
	"/.git/HEAD",
	"/.env",
	"/backup.zip",
	"/config.json",
	"/actuator",
	"/actuator/health",
	"/graphql",
	"/health",
	"/metrics",
	"/debug",
	"/console",
	"/uploads/",
	"/files/",
	"/download",
	"/test",
];

const PORT_LIST = [
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389,
	5432, 6379, 8080, 8443, 9000, 9200, 11211, 27017,
];

function httpRule(): AutoRule {
	return {
		key: "recon:http",
		phase: "recon",
		timeoutMs: 18_000,
		script(st) {
			const url = shellQuote(st.project.url);
			return [
				`h=$(mktemp); b=$(mktemp)`,
				`curl -k -sS -D "$h" -o "$b" --max-time 12 -w 'FINAL %{http_code} %{size_download} %{url_effective}\\n' ${url}`,
				`echo '---HEAD---'`,
				`cat "$h"`,
				`echo '---BODY---'`,
				`head -c 400 "$b"`,
				`rm -f "$h" "$b"`,
			].join("\n");
		},
		parse(res, st) {
			const head = res.stdout.split("---HEAD---")[1]?.split("---BODY---")[0] ?? "";
			const body = res.stdout.split("---BODY---")[1] ?? "";
			const fin = res.stdout.match(/^FINAL\s+(\d{3})\s+(\d+)\s+(\S+)/m);
			const code = fin?.[1] ?? "000";
			const size = fin?.[2] ?? "0";
			if (code === "000" && !head.trim()) return null;
			const server = headerValue(head, "server") || "-";
			const powered = headerValue(head, "x-powered-by") || "-";
			const location = headerValue(head, "location") || "-";
			const title = titleOf(body) || "-";
			return {
				kind: "service",
				title: `HTTP ${code} ${server}`.slice(0, 120),
				detail: `url=${fin?.[3] ?? st.project.url} size=${size} server=${server} x-powered-by=${powered} location=${location} title=${title}`,
				command: clip(`curl -k -sS -D - ${st.project.url}`, 400),
				output: clip(head.trim() || `code=${code}`, 800),
			};
		},
	};
}

function portsRule(): AutoRule {
	return {
		key: "recon:ports",
		phase: "recon",
		timeoutMs: 50_000,
		script(st) {
			return `for p in ${PORT_LIST.join(" ")}; do timeout 1 bash -c "echo >/dev/tcp/${st.project.host}/$p" 2>/dev/null && echo "open $p"; done`;
		},
		parse(res, st) {
			const ports = [...res.stdout.matchAll(/^open\s+(\d{1,5})$/gm)].map((m) => m[1]);
			if (ports.length === 0) return null;
			return {
				kind: "service",
				title: `${st.project.host} TCP 开放 ${ports.length} 端口`,
				detail: `tcp connect only: ${ports.join(",")}`,
				command: clip(`bash /dev/tcp connect scan ${st.project.host} ${PORT_LIST.length} ports`, 400),
				output: clip(ports.map((p) => `${p}/tcp open`).join("\n"), 800),
			};
		},
	};
}

function dirsRule(): AutoRule {
	return {
		key: "recon:dirs",
		phase: "recon",
		timeoutMs: 45_000,
		script(st) {
			const base = shellQuote(originOf(st));
			return [
				`BASE=${base}`,
				`for p in ${DIR_PATHS.map(shellQuote).join(" ")}; do`,
				`  out=$(curl -k -sS -o /dev/null --max-time 6 -w '%{http_code} %{size_download} %{redirect_url}' "$BASE$p" 2>/dev/null)`,
				`  code=\${out%% *}`,
				`  case "$code" in 200|204|301|302|307|401|403|405|500) echo "$p $out";; esac`,
				`done`,
			].join("\n");
		},
		parse(res, st) {
			const rows = res.stdout
				.split("\n")
				.map((l) => l.trim())
				.filter((l) => /^\/\S*\s+(200|204|301|302|307|401|403|405|500)\s+\d+/.test(l));
			if (rows.length === 0) return null;
			return {
				kind: "endpoint",
				title: `发现 ${rows.length} 条路径`,
				detail: rows.map((r) => r.replace(/\s+/g, " ")).join(" | ").slice(0, 600),
				command: clip(`curl HEAD ${DIR_PATHS.length} paths @ ${originOf(st)}`, 400),
				output: clip(rows.join("\n"), 800),
			};
		},
	};
}

function tlsRule(): AutoRule {
	return {
		key: "recon:tlsjs",
		phase: "recon",
		timeoutMs: 15_000,
		script(st) {
			const port = st.project.port || 443;
			return `echo | openssl s_client -connect ${st.project.host}:${port} -servername ${st.project.host} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null`;
		},
		parse(res, st) {
			const out = res.stdout;
			if (!/subject=/i.test(out) && !/notAfter=/i.test(out)) return null;
			const subject = out.match(/subject=\s*(.+)/i)?.[1]?.trim() ?? "-";
			const issuer = out.match(/issuer=\s*(.+)/i)?.[1]?.trim() ?? "-";
			const notAfter = out.match(/notAfter=\s*(.+)/i)?.[1]?.trim() ?? "-";
			const san = out.match(/X509v3 Subject Alternative Name:\s*\n?\s*(.+)/i)?.[1]?.trim() ?? "-";
			return {
				kind: "service",
				title: `TLS ${subject}`.slice(0, 120),
				detail: `subject=${subject} issuer=${issuer} notAfter=${notAfter} san=${san}`,
				command: clip(`openssl s_client -connect ${st.project.host}:${st.project.port || 443}`, 400),
				output: clip(out, 800),
			};
		},
	};
}

function probePaths(key: string, phase: Phase, paths: string[], timeoutMs: number): AutoRule {
	return {
		key,
		phase,
		timeoutMs,
		script(st) {
			const base = shellQuote(originOf(st));
			return [
				`BASE=${base}`,
				`for p in ${paths.map(shellQuote).join(" ")}; do`,
				`  body=$(curl -k -sS --max-time 6 -w '\\n%{http_code}' "$BASE$p" 2>/dev/null)`,
				`  code=$(printf '%s' "$body" | tail -n1)`,
				`  content=$(printf '%s' "$body" | sed '$d')`,
				`  [ "$code" = "200" ] && echo "$p $content"`,
				`done`,
			].join("\n");
		},
		parse(res, st) {
			const rows = res.stdout.split("\n").filter((l) => /^\/\S*\s+/.test(l.trim()));
			if (rows.length === 0) return null;
			const isSensitive = key === "surface:sensitive";
			const hasGit = rows.some((r) => r.startsWith("/.git/HEAD"));
			const hasEnv = rows.some((r) => r.startsWith("/.env"));
			const openapi = rows.some((r) => /"(openapi|swagger)"\s*:/.test(r));
			const title = isSensitive
				? hasGit || hasEnv
					? `敏感文件暴露 ${rows.length} 条`
					: `敏感路径可读 ${rows.length} 条`
				: openapi
					? "API 文档暴露"
					: `API 面可达 ${rows.length} 条`;
			return {
				kind: isSensitive && (hasGit || hasEnv) ? "vuln" : "endpoint",
				title,
				detail: rows.map((r) => r.trim().slice(0, 180)).join(" | ").slice(0, 700),
				command: clip(`curl ${paths.length} paths @ ${originOf(st)}`, 400),
				output: clip(rows.join("\n"), 800),
			};
		},
	};
}

export const AUTO_RULES: readonly AutoRule[] = [
	httpRule(),
	portsRule(),
	dirsRule(),
	tlsRule(),
	probePaths("surface:sensitive", "surface", ["/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/backup.zip", "/config.json"], 32_000),
	probePaths("surface:api", "surface", ["/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/api/v1", "/graphql"], 28_000),
];

const RULE_BY_KEY = new Map(AUTO_RULES.map((r) => [r.key, r]));

export function ruleFor(key: string): AutoRule | undefined {
	return RULE_BY_KEY.get(key);
}

/** 选本轮自动执行的意图：白名单 key、open、依赖满足、尝试次数未超限。 */
export function pickAuto(st: NuwaState, cfg: Cfg, max: number): string[] {
	const out: Array<{ id: string; priority: number }> = [];
	for (const it of Object.values(st.intents)) {
		if (it.status !== "open") continue;
		if (!isAutoKey(it.key)) continue;
		if (it.attempts >= cfg.maxAttempts) continue;
		if (!it.from.every((f) => st.facts[f])) continue;
		out.push({ id: it.id, priority: it.priority });
	}
	out.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
	return out.slice(0, Math.max(0, max)).map((x) => x.id);
}

export interface AutoRunResult {
	ok: boolean;
	fact?: AutoFact;
	error?: string;
}

/** 执行一条自动意图：跑脚本 → 解析。入账由调用方在锁内完成。 */
export async function runAutoIntent(
	rule: AutoRule,
	st: NuwaState,
	exec: ExecLike,
	cwd: string,
): Promise<AutoRunResult> {
	try {
		const res = await exec("bash", ["-lc", rule.script(st)], { timeout: rule.timeoutMs, cwd });
		const fact = rule.parse(res, st);
		if (!fact) {
			return { ok: false, error: `无产出 code=${res.code}${res.killed ? " killed" : ""}` };
		}
		return { ok: true, fact };
	} catch (err) {
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}
