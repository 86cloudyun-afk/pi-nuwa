/**
 * 女娲 v7.0 L3 靶场零依赖 RFC 1928 SOCKS5 / SOCKS5h + RFC 1929 认证测试代理桩。
 *
 * 核心特性与安全红线：
 * 1. 纯 `node:net`（Bun/Node 原生兼容）实现标准 SOCKS5 协议：
 *    - 支持 `0x00`（无认证）与 `0x02`（RFC 1929 用户名/密码子协商）；
 *    - 支持 `CMD=0x01` (`CONNECT`) 下的 `ATYP=0x03`（`socks5h://` 域名透传）与 `ATYP=0x01`（IPv4）；
 * 2. 严格本地白名单硬隔离（严禁沦为开放公网代理）：
 *    - 服务端强制仅绑定 `127.0.0.1` 回环网卡（拒绝 `0.0.0.0` 或外部网卡）；
 *    - 目标地址仅允许 `127.0.0.1` 或 `domainMap` 中显式映射至 `127.0.0.1` 的白名单测试域名（如 `l3-target.internal`）；
 *    - 目标端口必须命中 `allowedPorts` 白名单，任何公网 IP、未授权域名或非白名单本机端口一律立即返回 `REP=0x02`
 *      (`Connection not allowed by ruleset`) 并断开，确保 0 字节越界外连；
 * 3. 精确统计 `socks5HandshakeCount`、`socks5DomainRequests` 等遥测指标，并在 `stop()` 时销毁回收全部活跃 Socket。
 */
import { connect, createServer, type Server, type Socket } from "node:net";

export interface Socks5AuthCredentials {
	username: string;
	password: string;
}

export interface LocalSocks5ServerOptions {
	/** 监听端口（默认 `0` 由内核分配随机空闲端口）。 */
	port?: number;
	/** 监听地址（安全锁死：仅允许 `"127.0.0.1"`，默认 `"127.0.0.1"`）。 */
	host?: string;
	/** 允许转发的本机 `127.0.0.1` 目标端口白名单。 */
	allowedPorts?: Iterable<number>;
	/** 允许在代理侧解析至 `127.0.0.1` 的测试域名映射表（默认含 `l3-target.internal` 与 `localhost`）。 */
	domainMap?: Record<string, string>;
	/** 可选 RFC 1929 用户名/密码认证配置。 */
	auth?: Socks5AuthCredentials;
	/** 单连接空闲超时毫秒数（默认 `15_000`）。 */
	socketTimeoutMs?: number;
}

export interface Socks5ServerStats {
	/** 成功完成 SOCKS5 CONNECT 握手并建立本地转发隧道的次数。 */
	socks5HandshakeCount: number;
	/** 收到 `ATYP=0x03` 域名透传请求（`socks5h://`）的次数。 */
	socks5DomainRequests: number;
	/** 收到 `ATYP=0x01` IPv4 请求的次数。 */
	socks5Ipv4Requests: number;
	/** 收到的域名列表快照。 */
	requestedDomains: string[];
	/** RFC 1929 用户名/密码认证成功次数。 */
	authSuccessCount: number;
	/** RFC 1929 认证失败拦截次数。 */
	authFailureCount: number;
	/** 命中安全规则集（公网地址/未授权域名/非白名单端口）被 `REP=0x02` 拒绝的次数。 */
	blockedCount: number;
	/** 当前仍处于打开状态的 Socket 数量（`stop()` 后应为 `0`）。 */
	activeSocketCount: number;
}

export interface LocalSocks5ServerHandle {
	readonly host: "127.0.0.1";
	readonly port: number;
	/** 不含明文口令的安全代理 URL（`socks5h://127.0.0.1:<port>`）。 */
	readonly proxyUrl: string;
	/** 构造代理 URL（`includeAuth=true` 时附带用户名与密码，仅供受测客户端拨号）。 */
	buildProxyUrl(includeAuth?: boolean, scheme?: "socks5h" | "socks5"): string;
	/** 动态添加允许转发的本机靶标端口。 */
	allowPort(port: number): void;
	/** 动态移除本机靶标端口授权。 */
	revokePort(port: number): void;
	/** 读取当前代理遥测统计快照。 */
	getStats(): Socks5ServerStats;
	/** 关闭监听并强制销毁回收全部客户端与上游 Socket。 */
	stop(): Promise<void>;
}

const DEFAULT_DOMAIN_MAP: Readonly<Record<string, string>> = {
	"l3-target.internal": "127.0.0.1",
	localhost: "127.0.0.1",
};

function buildSocks5Reply(rep: number, bindPort = 0): Buffer {
	return Buffer.from([
		0x05,
		rep & 0xff,
		0x00,
		0x01,
		127,
		0,
		0,
		1,
		(bindPort >> 8) & 0xff,
		bindPort & 0xff,
	]);
}

/**
 * 启动受本机白名单严格约束的本地 SOCKS5 / SOCKS5h 测试代理桩。
 */
export async function startLocalSocks5Server(opts?: LocalSocks5ServerOptions): Promise<LocalSocks5ServerHandle> {
	const bindHost = (opts?.host ?? "127.0.0.1").trim();
	if (bindHost !== "127.0.0.1") {
		throw new Error(`SOCKS5 测试代理安全限制：仅允许监听 127.0.0.1，拒绝绑定 ${bindHost}`);
	}

	const allowedPorts = new Set<number>();
	for (const p of opts?.allowedPorts ?? []) {
		if (Number.isInteger(p) && p > 0 && p <= 65535) {
			allowedPorts.add(p);
		}
	}

	const domainMap = new Map<string, "127.0.0.1">();
	const mergedDomains = { ...DEFAULT_DOMAIN_MAP, ...(opts?.domainMap ?? {}) };
	for (const [rawDomain, rawIp] of Object.entries(mergedDomains)) {
		const cleanDomain = rawDomain.trim().toLowerCase();
		const cleanIp = String(rawIp ?? "").trim();
		if (!cleanDomain) continue;
		if (cleanIp !== "127.0.0.1") {
			throw new Error(`SOCKS5 测试代理安全限制：域名 ${cleanDomain} 仅允许映射至 127.0.0.1，拒绝 ${cleanIp}`);
		}
		domainMap.set(cleanDomain, "127.0.0.1");
	}

	const authCfg = opts?.auth
		? {
				username: opts.auth.username,
				password: opts.auth.password,
			}
		: undefined;
	const socketTimeoutMs = opts?.socketTimeoutMs ?? 15_000;

	let socks5HandshakeCount = 0;
	let socks5DomainRequests = 0;
	let socks5Ipv4Requests = 0;
	let authSuccessCount = 0;
	let authFailureCount = 0;
	let blockedCount = 0;
	const requestedDomains: string[] = [];
	const activeSockets = new Set<Socket>();
	let stopped = false;

	const trackSocket = (sock: Socket): void => {
		activeSockets.add(sock);
		sock.setTimeout(socketTimeoutMs, () => {
			sock.destroy();
		});
		const cleanup = () => {
			activeSockets.delete(sock);
		};
		sock.once("close", cleanup);
		sock.on("error", () => {
			/* 防止 ECONNRESET 未捕获异常崩溃测试进程 */
		});
	};

	const server: Server = createServer((client: Socket) => {
		if (stopped) {
			client.destroy();
			return;
		}
		trackSocket(client);

		type Stage = "greeting" | "auth" | "request" | "connecting" | "piping" | "closed";
		let stage: Stage = "greeting";
		let buf = Buffer.alloc(0);
		let upstream: Socket | null = null;

		const closePair = () => {
			stage = "closed";
			if (!client.destroyed) client.destroy();
			if (upstream && !upstream.destroyed) upstream.destroy();
		};

		const endAndDestroyClient = (payload: Buffer) => {
			stage = "closed";
			if (client.destroyed) return;
			try {
				client.once("finish", () => {
					if (!client.destroyed) client.destroy();
				});
				client.end(payload);
			} catch {
				client.destroy();
			}
		};

		const failWithReply = (rep: number) => {
			endAndDestroyClient(buildSocks5Reply(rep, 0));
		};

		const processBuffer = () => {
			while (stage !== "connecting" && stage !== "piping" && stage !== "closed") {
				if (stage === "greeting") {
					if (buf.length < 2) return;
					const ver = buf[0]!;
					const nmethods = buf[1]!;
					if (ver !== 0x05 || nmethods <= 0) {
						closePair();
						return;
					}
					if (buf.length < 2 + nmethods) return;
					const methods = buf.subarray(2, 2 + nmethods);
					buf = buf.subarray(2 + nmethods);

					let hasNoAuth = false;
					let hasUserPass = false;
					for (let i = 0; i < methods.length; i++) {
						if (methods[i] === 0x00) hasNoAuth = true;
						if (methods[i] === 0x02) hasUserPass = true;
					}

					if (authCfg) {
						if (!hasUserPass) {
							authFailureCount += 1;
							endAndDestroyClient(Buffer.from([0x05, 0xff]));
							return;
						}
						client.write(Buffer.from([0x05, 0x02]));
						stage = "auth";
						continue;
					}

					if (!hasNoAuth) {
						endAndDestroyClient(Buffer.from([0x05, 0xff]));
						return;
					}
					client.write(Buffer.from([0x05, 0x00]));
					stage = "request";
					continue;
				}

				if (stage === "auth") {
					// RFC 1929: [VER=0x01, ULEN, UNAME, PLEN, PASSWD]
					if (buf.length < 2) return;
					const subVer = buf[0]!;
					const ulen = buf[1]!;
					if (subVer !== 0x01) {
						authFailureCount += 1;
						closePair();
						return;
					}
					if (buf.length < 2 + ulen + 1) return;
					const plen = buf[2 + ulen]!;
					const totalAuthLen = 3 + ulen + plen;
					if (buf.length < totalAuthLen) return;

					const uname = buf.subarray(2, 2 + ulen).toString("utf8");
					const passwd = buf.subarray(3 + ulen, totalAuthLen).toString("utf8");
					buf = buf.subarray(totalAuthLen);

					if (authCfg && uname === authCfg.username && passwd === authCfg.password) {
						authSuccessCount += 1;
						client.write(Buffer.from([0x01, 0x00]));
						stage = "request";
						continue;
					}
					authFailureCount += 1;
					endAndDestroyClient(Buffer.from([0x01, 0x01]));
					return;
				}

				if (stage === "request") {
					if (buf.length < 4) return;
					const ver = buf[0]!;
					const cmd = buf[1]!;
					const atyp = buf[3]!;
					if (ver !== 0x05) {
						closePair();
						return;
					}

					let reqLen = 0;
					if (atyp === 0x01) {
						reqLen = 10;
					} else if (atyp === 0x03) {
						if (buf.length < 5) return;
						const dlen = buf[4]!;
						reqLen = 4 + 1 + dlen + 2;
					} else if (atyp === 0x04) {
						reqLen = 22;
					} else {
						failWithReply(0x08); // Address type not supported
						return;
					}

					if (buf.length < reqLen) return;
					const reqFrame = buf.subarray(0, reqLen);
					const pendingAppBytes = buf.subarray(reqLen);
					buf = Buffer.alloc(0);

					if (cmd !== 0x01) {
						failWithReply(0x07); // Command not supported
						return;
					}

					let resolvedTargetHost: "127.0.0.1" | null = null;
					let dstPort = 0;

					if (atyp === 0x01) {
						socks5Ipv4Requests += 1;
						const ipStr = `${reqFrame[4]!}.${reqFrame[5]!}.${reqFrame[6]!}.${reqFrame[7]!}`;
						dstPort = (reqFrame[8]! << 8) | reqFrame[9]!;
						if (ipStr === "127.0.0.1") {
							resolvedTargetHost = "127.0.0.1";
						}
					} else if (atyp === 0x03) {
						socks5DomainRequests += 1;
						const dlen = reqFrame[4]!;
						const rawDomain = reqFrame.subarray(5, 5 + dlen).toString("utf8").trim().toLowerCase();
						dstPort = (reqFrame[5 + dlen]! << 8) | reqFrame[5 + dlen + 1]!;
						requestedDomains.push(rawDomain);
						if (rawDomain === "127.0.0.1" || domainMap.get(rawDomain) === "127.0.0.1") {
							resolvedTargetHost = "127.0.0.1";
						}
					} else {
						// IPv6 在本靶场严格拒绝，确保零绕过
						resolvedTargetHost = null;
					}

					if (!resolvedTargetHost || dstPort <= 0 || !allowedPorts.has(dstPort)) {
						blockedCount += 1;
						failWithReply(0x02); // Connection not allowed by ruleset
						return;
					}

					stage = "connecting";
					client.pause();
					const targetSock = connect({ host: "127.0.0.1", port: dstPort }, () => {
						if (stopped || client.destroyed) {
							targetSock.destroy();
							return;
						}
						socks5HandshakeCount += 1;
						stage = "piping";
						client.write(buildSocks5Reply(0x00, dstPort));
						if (pendingAppBytes.length > 0) {
							targetSock.write(pendingAppBytes);
						}
						if (buf.length > 0) {
							targetSock.write(buf);
							buf = Buffer.alloc(0);
						}
						client.pipe(targetSock);
						targetSock.pipe(client);
						client.resume();
					});
					upstream = targetSock;
					trackSocket(targetSock);

					targetSock.once("error", () => {
						if (stage === "connecting" && !client.destroyed) {
							failWithReply(0x05); // Connection refused
						} else {
							closePair();
						}
					});
					targetSock.once("close", () => {
						if (!client.destroyed) client.end();
					});
					client.once("close", () => {
						if (!targetSock.destroyed) targetSock.destroy();
					});
					return;
				}
			}
		};

		client.on("data", (chunk: Buffer | string) => {
			if (stage === "piping" || stage === "closed") return;
			const bufChunk = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
			buf = buf.length === 0 ? bufChunk : Buffer.concat([buf, bufChunk]);
			if (buf.length > 65536) {
				// 握手阶段包体异常膨胀保护
				closePair();
				return;
			}
			processBuffer();
		});
	});

	const listenPort = opts?.port ?? 0;
	await new Promise<void>((resolveReady, rejectReady) => {
		server.once("error", rejectReady);
		server.listen(listenPort, "127.0.0.1", () => {
			server.off("error", rejectReady);
			resolveReady();
		});
	});

	const addr = server.address();
	if (!addr || typeof addr === "string") {
		server.close();
		throw new Error("无法获取本地 SOCKS5 测试代理监听端口");
	}
	const boundPort = addr.port;

	return {
		host: "127.0.0.1",
		port: boundPort,
		proxyUrl: `socks5h://127.0.0.1:${boundPort}`,
		buildProxyUrl(includeAuth = false, scheme: "socks5h" | "socks5" = "socks5h"): string {
			if (includeAuth && authCfg) {
				const u = encodeURIComponent(authCfg.username);
				const p = encodeURIComponent(authCfg.password);
				return `${scheme}://${u}:${p}@127.0.0.1:${boundPort}`;
			}
			return `${scheme}://127.0.0.1:${boundPort}`;
		},
		allowPort(port: number): void {
			if (Number.isInteger(port) && port > 0 && port <= 65535) {
				allowedPorts.add(port);
			}
		},
		revokePort(port: number): void {
			allowedPorts.delete(port);
		},
		getStats(): Socks5ServerStats {
			return {
				socks5HandshakeCount,
				socks5DomainRequests,
				socks5Ipv4Requests,
				requestedDomains: [...requestedDomains],
				authSuccessCount,
				authFailureCount,
				blockedCount,
				activeSocketCount: activeSockets.size,
			};
		},
		async stop(): Promise<void> {
			if (stopped) return;
			stopped = true;
			for (const sock of [...activeSockets]) {
				try {
					sock.destroy();
				} catch {
					/* ignore */
				}
			}
			activeSockets.clear();
			await new Promise<void>((resolveClose) => {
				server.close(() => resolveClose());
			});
		},
	};
}

export interface Socks5ClientProbeOptions {
	proxyHost?: string;
	proxyPort: number;
	targetHost: string;
	targetPort: number;
	/** `"domain"` 强制发送 `ATYP=0x03`（即 `socks5h://` 语义）；`"ipv4"` 发送 `ATYP=0x01`。 */
	addressType?: "domain" | "ipv4";
	auth?: Socks5AuthCredentials;
	httpPath?: string;
	httpMethod?: "GET" | "HEAD";
	headers?: Record<string, string>;
	timeoutMs?: number;
}

export interface Socks5ClientProbeResult {
	ok: boolean;
	socksReplyCode: number;
	authReplyCode?: number;
	httpStatus?: number;
	rawHttpResponse?: string;
	body?: string;
	error?: string;
}

/**
 * 纯原生 TCP 实现的 SOCKS5 / SOCKS5h 客户端探针：
 * 用于单测精确断言协议字节帧握手（含 `0x00`/`0x02` 认证、`ATYP=0x03`/`0x01` 与 `REP=0x02` 拦截码）及子进程无 curl 环境兜底。
 */
export async function requestViaSocks5Http(opts: Socks5ClientProbeOptions): Promise<Socks5ClientProbeResult> {
	const proxyHost = opts.proxyHost ?? "127.0.0.1";
	const timeoutMs = opts.timeoutMs ?? 5000;
	const atypMode =
		opts.addressType ?? (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(opts.targetHost) ? "ipv4" : "domain");

	return new Promise<Socks5ClientProbeResult>((resolveDone) => {
		let settled = false;
		const finish = (res: Socks5ClientProbeResult, sock?: Socket) => {
			if (settled) return;
			settled = true;
			if (sock && !sock.destroyed) sock.destroy();
			resolveDone(res);
		};

		const sock = connect({ host: proxyHost, port: opts.proxyPort });
		sock.setTimeout(timeoutMs, () => {
			finish({ ok: false, socksReplyCode: -1, error: "SOCKS5 client timeout" }, sock);
		});
		sock.once("error", (err: Error) => {
			finish({ ok: false, socksReplyCode: -1, error: err.message }, sock);
		});

		type ClientStage = "greeting_reply" | "auth_reply" | "connect_reply" | "http_response";
		let stage: ClientStage = "greeting_reply";
		let rx = Buffer.alloc(0);
		let authReplyCode: number | undefined;
		let socksReplyCode = -1;

		const sendConnectRequest = () => {
			const portHi = (opts.targetPort >> 8) & 0xff;
			const portLo = opts.targetPort & 0xff;
			if (atypMode === "ipv4") {
				const parts = opts.targetHost.split(".").map((x) => Number(x) & 0xff);
				sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, parts[0]!, parts[1]!, parts[2]!, parts[3]!, portHi, portLo]));
			} else {
				const domBytes = Buffer.from(opts.targetHost, "utf8");
				sock.write(
					Buffer.concat([
						Buffer.from([0x05, 0x01, 0x00, 0x03, domBytes.length]),
						domBytes,
						Buffer.from([portHi, portLo]),
					]),
				);
			}
			stage = "connect_reply";
		};

		const sendHttpRequest = () => {
			if (!opts.httpPath) {
				finish({ ok: true, socksReplyCode: 0x00, ...(authReplyCode !== undefined ? { authReplyCode } : {}) }, sock);
				return;
			}
			const method = opts.httpMethod ?? "GET";
			const hdrLines = [
				`${method} ${opts.httpPath} HTTP/1.1`,
				`Host: ${opts.targetHost}:${opts.targetPort}`,
				`Connection: close`,
				`User-Agent: nuwa-l3-socks5h-probe/7.0`,
			];
			for (const [k, v] of Object.entries(opts.headers ?? {})) {
				hdrLines.push(`${k}: ${v}`);
			}
			sock.write(`${hdrLines.join("\r\n")}\r\n\r\n`);
			stage = "http_response";
		};

		sock.once("connect", () => {
			if (opts.auth) {
				sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02]));
			} else {
				sock.write(Buffer.from([0x05, 0x01, 0x00]));
			}
		});

		sock.on("data", (chunk: Buffer | string) => {
			const bufChunk = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : Buffer.from(chunk);
			rx = rx.length === 0 ? bufChunk : Buffer.concat([rx, bufChunk]);

			while (!settled) {
				if (stage === "greeting_reply") {
					if (rx.length < 2) return;
					const ver = rx[0]!;
					const method = rx[1]!;
					rx = rx.subarray(2);
					if (ver !== 0x05 || method === 0xff) {
						finish({ ok: false, socksReplyCode: 0xff, error: `SOCKS5 method rejected (0x${method.toString(16)})` }, sock);
						return;
					}
					if (method === 0x02) {
						if (!opts.auth) {
							finish({ ok: false, socksReplyCode: 0xff, error: "Server required auth but none provided" }, sock);
							return;
						}
						const uBytes = Buffer.from(opts.auth.username, "utf8");
						const pBytes = Buffer.from(opts.auth.password, "utf8");
						sock.write(
							Buffer.concat([
								Buffer.from([0x01, uBytes.length]),
								uBytes,
								Buffer.from([pBytes.length]),
								pBytes,
							]),
						);
						stage = "auth_reply";
						continue;
					}
					sendConnectRequest();
					continue;
				}

				if (stage === "auth_reply") {
					if (rx.length < 2) return;
					const status = rx[1]!;
					authReplyCode = status;
					rx = rx.subarray(2);
					if (status !== 0x00) {
						finish(
							{ ok: false, socksReplyCode: -1, authReplyCode: status, error: `SOCKS5 auth failed (${status})` },
							sock,
						);
						return;
					}
					sendConnectRequest();
					continue;
				}

				if (stage === "connect_reply") {
					if (rx.length < 4) return;
					const atyp = rx[3]!;
					const needLen = atyp === 0x01 ? 10 : atyp === 0x03 ? (rx.length >= 5 ? 7 + rx[4]! : 999) : 22;
					if (rx.length < needLen) return;
					const rep = rx[1]!;
					socksReplyCode = rep;
					rx = rx.subarray(needLen);
					if (rep !== 0x00) {
						finish(
							{
								ok: false,
								socksReplyCode: rep,
								...(authReplyCode !== undefined ? { authReplyCode } : {}),
								error: `SOCKS5 connect rejected: REP=0x${rep.toString(16).padStart(2, "0")}`,
							},
							sock,
						);
						return;
					}
					sendHttpRequest();
					continue;
				}

				if (stage === "http_response") {
					// 等待对端 Connection: close 发送完毕在 end/close 中汇总
					return;
				}
			}
		});

		sock.once("close", () => {
			if (settled) return;
			if (stage === "http_response") {
				const rawText = rx.toString("utf8");
				const sepIdx = rawText.indexOf("\r\n\r\n");
				const head = sepIdx >= 0 ? rawText.slice(0, sepIdx) : rawText;
				const body = sepIdx >= 0 ? rawText.slice(sepIdx + 4) : "";
				const statusMatch = /^HTTP\/1\.[01]\s+(\d{3})\b/.exec(head);
				const httpStatus = statusMatch ? Number(statusMatch[1]) : undefined;
				finish({
					ok: true,
					socksReplyCode: 0x00,
					...(authReplyCode !== undefined ? { authReplyCode } : {}),
					...(httpStatus !== undefined ? { httpStatus } : {}),
					rawHttpResponse: rawText,
					body,
				});
			} else {
				finish({
					ok: false,
					socksReplyCode,
					...(authReplyCode !== undefined ? { authReplyCode } : {}),
					error: "Socket closed before SOCKS5 completion",
				});
			}
		});
	});
}
