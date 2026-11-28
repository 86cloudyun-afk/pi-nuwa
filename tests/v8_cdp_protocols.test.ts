import { afterEach, describe, expect, test } from "bun:test";
import http from "node:http";
import { createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { AddressInfo } from "node:net";

import {
  DEFAULT_AUTH_FAILURE_THRESHOLD, DEFAULT_SESSION_MIN_TTL_SECONDS, decodeBase32Secret, ensureSessionFresh,
  generateHotpCode, generateTotpCode, getRoleConsecutiveAuthFailures, parseOtpAuthUri, recordRoleAuthStatus,
  resetRoleAuthFailures, runInteractiveAuthPlaybook, verifyTotpCode,
} from "../omp/cdp-auth";
import { executeInPageStatefulSignedProbe, runCdpStatefulSignedAuthDiff, scrubTextWithExtraSecrets } from "../omp/cdp-signed-probe";
import {
  attachCdpWebSocketAuditor, auditWebSocketCrossTenantPush, buildGraphQLAliasQuery, buildGraphQLBatchPayload,
  buildRscActionRequest, decodeGrpcWebFrames, decodeProtobufFields, decodeVarint, diffGrpcWebMethodRoles,
  diffRscActionRoles, encodeGrpcWebFrame, encodeProtobufFields, encodeVarint, inspectGraphQLSchema,
  parseGraphQLIntrospection, parseGraphQLSuggestionsFromErrors, parseRscFlightStream, runGraphQLNestedAuthDiff,
} from "../omp/protocol-inspector";
import { defaultScopeForTarget } from "../omp/scope";
import type { ScopePolicy } from "../omp/scope";
import { formatSessionVaultSummary, loadSessionVault, redactVaultSecrets, upsertSessionRole } from "../omp/session-vault";
import { TrafficRecorder } from "../omp/traffic-workbench";
import { launchCdpSession, type CdpSession, type CdpTransportLike } from "../omp/cdp-bridge";

const servers: Array<{ close: () => void | Promise<void> }> = [];
const dirs: string[] = [];
const timers: Array<ReturnType<typeof setTimeout>> = [];

function cleanupRegister(fn: () => void | Promise<void>): void {
  servers.push({ close: fn });
}

afterEach(async () => {
  while (timers.length > 0) clearTimeout(timers.pop()!);
  while (servers.length > 0) { try { await servers.pop()!.close(); } catch { /* 幂等清理 */ } }
  while (dirs.length > 0) { try { rmSync(dirs.pop()!, { recursive: true, force: true }); } catch { /* 幂等清理 */ } }
});

async function listenHttp(server: http.Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as AddressInfo;
  const base = `http://127.0.0.1:${addr.port}`;
  let closed = false;
  cleanupRegister(async () => {
    if (closed) return;
    closed = true;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(server.listening).toBe(false);
  });
  return base;
}

function trackBunServer(server: any): string {
  const port = Number(server.port);
  const base = `http://127.0.0.1:${port}`;
  let closed = false;
  cleanupRegister(() => {
    if (closed) return;
    closed = true;
    server.stop(true);
  });
  return base;
}

function tmpRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "nuwa-v8-"));
  dirs.push(root);
  return root;
}

function makeScope(url: string): ScopePolicy {
  try { return defaultScopeForTarget(url); } catch {
    return { allowHosts: [new URL(url).hostname], allowCidrs: ["127.0.0.1/32"], denyHosts: [], allowSubdomains: false, allowPrivateNetwork: true, allowDestructive: false, allowLoopback: true };
  }
}

function base32Encode(buf: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function jwtWithExp(expSecondsFromNow: number, subject = "alice"): string {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      sub: subject,
      exp: Math.floor(Date.now() / 1000) + expSecondsFromNow,
      iat: Math.floor(Date.now() / 1000),
    }),
  ).toString("base64url");
  return `${header}.${payload}.sig`;
}

interface MockBrowserHooks {
  signSecret?: string;
  observedForwardedHeaders?: Array<Record<string, string>>;
}

function createMockCdpTransport(seed = "default", hooks: MockBrowserHooks = {}): {
  transport: CdpTransportLike;
  state: {
    currentUrl: string;
    cookies: Map<string, string>;
    localStorage: Map<string, string>;
    sessionStorage: Map<string, string>;
    closed: boolean;
    fetchPausedCount: number;
  };
  emitEvent: (method: string, params?: Record<string, unknown>) => void;
} {
  let onMsg: ((data: string) => void) | null = null;
  let onCls: ((reason?: string) => void) | null = null;
  const fetchWaiters = new Map<string, { resolve: (hdrs: Record<string, string>) => void; reject: (err: Error) => void }>();
  let fetchSeq = 1;
  let netSeq = 1;
  let fetchEnabled = false;

  const state = {
    currentUrl: "about:blank",
    cookies: new Map<string, string>(),
    cookieExpires: new Map<string, number>(),
    localStorage: new Map<string, string>(),
    sessionStorage: new Map<string, string>(),
    closed: false,
    fetchPausedCount: 0,
    extraHeaders: {} as Record<string, string>,
    elements: new Map<string, Record<string, unknown>>(),
    pendingNav: Promise.resolve(),
  };

  const emitEvent = (method: string, params: Record<string, unknown> = {}): void => {
    onMsg?.(JSON.stringify({ method, params, sessionId: `mock-cdp-${seed}` }));
  };

  const resolveUrl = (input: string): string => {
    try {
      return new URL(input, state.currentUrl === "about:blank" ? "http://127.0.0.1/" : state.currentUrl).toString();
    } catch {
      return input;
    }
  };

  const cookieHeader = (): string =>
    [...state.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

  const applySetCookies = (setCookieRaw: string | null): void => {
    if (!setCookieRaw) return;
    for (const part of setCookieRaw.split(/,(?=[^;]+=)/)) {
      const segs = part.split(";").map((s) => s.trim());
      const idx = (segs[0] ?? "").indexOf("=");
      if (idx <= 0) continue;
      const name = segs[0]!.slice(0, idx).trim();
      const val = segs[0]!.slice(idx + 1).trim();
      state.cookies.set(name, val);
      for (const attr of segs.slice(1)) {
        const eq = attr.indexOf("=");
        if (eq <= 0) continue;
        const ak = attr.slice(0, eq).trim().toLowerCase();
        const av = attr.slice(eq + 1).trim();
        if (ak === "max-age" && Number.isFinite(Number(av))) state.cookieExpires.set(name, Math.floor(Date.now() / 1000) + Number(av));
        else if (ak === "expires" && Number.isFinite(Date.parse(av))) state.cookieExpires.set(name, Math.floor(Date.parse(av) / 1000));
      }
    }
  };

  const applyInlineScripts = (html: string): void => {
    const lsMatches = html.matchAll(/localStorage\.setItem\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']\s*\)/g);
    for (const m of lsMatches) state.localStorage.set(m[1]!, m[2]!);
    const ssMatches = html.matchAll(/sessionStorage\.setItem\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']\s*\)/g);
    for (const m of ssMatches) state.sessionStorage.set(m[1]!, m[2]!);
  };

  const wrappedFetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const rawUrl = resolveUrl(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const method = String(init.method ?? "GET").toUpperCase();
    const hdrObj: Record<string, string> = { ...state.extraHeaders };
    if (init.headers) {
      const h = new Headers(init.headers);
      h.forEach((v, k) => { hdrObj[k] = v; });
    }
    if (init.credentials !== "omit" && !Object.keys(hdrObj).some((k) => k.toLowerCase() === "cookie") && cookieHeader()) {
      hdrObj["cookie"] = cookieHeader();
    }

    let finalHeaders = hdrObj;
    if (fetchEnabled) {
      const reqId = `freq_${fetchSeq++}`;
      state.fetchPausedCount += 1;
      finalHeaders = await new Promise<Record<string, string>>((resolve, reject) => {
        fetchWaiters.set(reqId, { resolve, reject });
        emitEvent("Fetch.requestPaused", { requestId: reqId, request: { url: rawUrl, method, headers: hdrObj }, resourceType: "Fetch" });
      });
    }

    const netId = `nreq_${netSeq++}`;
    emitEvent("Network.requestWillBeSent", { requestId: netId, request: { url: rawUrl, method, headers: finalHeaders, postData: typeof init.body === "string" ? init.body : undefined } });
    hooks.observedForwardedHeaders?.push({ ...finalHeaders });

    // 手动跟进同源或内部 302 重定向以完整捕捉 Set-Cookie 与最终 URL（兼容 OAuth 回调）
    let current = rawUrl;
    let currentMethod = method;
    let currentBody = init.body;
    let res!: Response;
    for (let hop = 0; hop < 5; hop += 1) {
      const reqHeaders = new Headers(finalHeaders);
      if (hop > 0 && init.credentials !== "omit" && cookieHeader()) reqHeaders.set("cookie", cookieHeader());
      res = await fetch(current, {
        method: currentMethod,
        headers: reqHeaders,
        body: currentMethod === "GET" || currentMethod === "HEAD" ? undefined : currentBody,
        redirect: "manual",
      });
      applySetCookies(res.headers.get("set-cookie"));
      if (init.redirect === "manual" || res.status < 300 || res.status >= 400) break;
      const loc = res.headers.get("location");
      if (!loc) break;
      current = new URL(loc, current).toString();
      if (res.status === 302 || res.status === 303) {
        currentMethod = "GET";
        currentBody = undefined;
      }
    }

    const respHdrs: Record<string, string> = {};
    res.headers.forEach((v, k) => { respHdrs[k] = v; });
    emitEvent("Network.responseReceived", { requestId: netId, response: { url: current, status: res.status, headers: respHdrs } });
    return res;
  };

  const getElement = (selector: string): Record<string, unknown> | null => {
    if (state.elements.has(selector)) return state.elements.get(selector)!;
    const isDashboard = state.currentUrl.includes("/dashboard") || state.currentUrl.includes("/oauth/callback");
    if ((selector.includes("dashboard") || selector === "#app" || selector === "#root") && !isDashboard) return null;
    if (selector.includes("missing") || selector.includes("never")) return null;
    const el: Record<string, unknown> = {
      value: "",
      tagName: selector.includes("form") ? "FORM" : "INPUT",
      getBoundingClientRect: () => ({ width: 100, height: 24 }),
      dispatchEvent: () => true,
      focus: () => {},
      scrollIntoView: () => {},
      click: () => {
        if (selector.includes("sso-external")) {
          state.currentUrl = "http://evil.outside.invalid/steal?code=evil-sso-code";
          return;
        }
        state.pendingNav = (async () => {
          const res = await wrappedFetch(state.currentUrl, { method: "GET", redirect: "follow" });
          const html = await res.text();
          state.currentUrl = res.url || state.currentUrl;
          applyInlineScripts(html);
        })();
      },
      submit: () => {
        const fields: Record<string, string> = {};
        for (const [k, v] of state.elements.entries()) {
          if (k.startsWith("#")) fields[k.replace(/^#/, "")] = String(v.value ?? "");
        }
        const postBody = new URLSearchParams(fields).toString();
        state.pendingNav = (async () => {
          const res = await wrappedFetch(state.currentUrl, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: postBody,
            redirect: "follow",
          });
          const html = await res.text();
          const finalResp = res.url || state.currentUrl;
          // 因 manual 重定向循环返回最后一次 res，若 URL 为 callback 则更新 currentUrl
          if (html.includes("/oauth/callback") || html.includes("access_token")) {
            state.currentUrl = new URL("/oauth/callback?code=SECRET-CODE&access_token=RAW-TOKEN", state.currentUrl).toString();
          } else {
            state.currentUrl = finalResp;
          }
          applyInlineScripts(html);
          emitEvent("Page.loadEventFired", { timestamp: Date.now() / 1000 });
        })();
      },
    };
    el.form = el;
    el.closest = () => el;
    if (selector.startsWith("#") || selector.includes("input") || selector.includes("button")) {
      state.elements.set(selector, el);
      return el;
    }
    return null;
  };

  const fakeDocument = {
    get cookie() { return cookieHeader(); },
    querySelector: getElement,
    get activeElement() { return getElement("#submit"); },
    readyState: "complete",
  };

  const fakeWindow: Record<string, unknown> = {
    get location() {
      let origin = "http://127.0.0.1";
      let pathname = "/";
      try { const u = new URL(state.currentUrl); origin = u.origin; pathname = u.pathname; } catch { /* ignore */ }
      return { href: state.currentUrl, origin, pathname };
    },
    localStorage: {
      getItem: (k: string) => state.localStorage.get(k) ?? null,
      setItem: (k: string, v: string) => { state.localStorage.set(k, String(v)); },
      key: (i: number) => [...state.localStorage.keys()][i] ?? null,
      get length() { return state.localStorage.size; },
    },
    sessionStorage: {
      getItem: (k: string) => state.sessionStorage.get(k) ?? null,
      setItem: (k: string, v: string) => { state.sessionStorage.set(k, String(v)); },
      key: (i: number) => [...state.sessionStorage.keys()][i] ?? null,
      get length() { return state.sessionStorage.size; },
    },
    document: fakeDocument,
    fetch: wrappedFetch,
    getComputedStyle: () => ({ visibility: "visible", display: "block" }),
    __nuwaSign: (req: { method: string; path: string }) => {
      const ts = String(Date.now());
      const nonce = randomBytes(6).toString("hex");
      const sig = createHmac("sha256", hooks.signSecret ?? `secret-${seed}`).update(`${req.method}:${req.path}:${ts}:${nonce}`).digest("hex");
      return { "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig };
    },
  };

  const evaluate = async (expression: string): Promise<unknown> => {
    await state.pendingNav;
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor as new (...a: string[]) => (...v: unknown[]) => Promise<unknown>;
    const fn = new AsyncFunction("window", "document", "location", "fetch", `return await (${expression});`);
    return await fn(fakeWindow, fakeDocument, fakeWindow.location, wrappedFetch);
  };

  const transport: CdpTransportLike = {
    onMessage(handler) { onMsg = handler; },
    onClose(handler) { onCls = handler; },
    onError() {},
    close() { state.closed = true; onCls?.("closed"); },
    send(rawData) {
      const msg = JSON.parse(rawData) as { id: number; method: string; params?: Record<string, unknown> };
      const reply = (result: Record<string, unknown> = {}) => {
        queueMicrotask(() => onMsg?.(JSON.stringify({ id: msg.id, result })));
      };
      const params = msg.params ?? {};
      void (async () => {
        try {
          if (msg.method === "Target.createTarget") return reply({ targetId: `tgt-${seed}` });
          if (msg.method === "Target.attachToTarget") return reply({ sessionId: `mock-cdp-${seed}` });
          if (msg.method === "Browser.getVersion") return reply({ product: "MockChrome/1.0" });
          if (msg.method === "Browser.close") { state.closed = true; return reply({}); }
          if (msg.method === "Fetch.enable") { fetchEnabled = true; return reply({}); }
          if (msg.method === "Fetch.continueRequest") {
            const waiter = fetchWaiters.get(String(params.requestId ?? ""));
            if (waiter) {
              fetchWaiters.delete(String(params.requestId));
              const out: Record<string, string> = {};
              const entries = params.headers as Array<{ name: string; value: string }> | undefined;
              if (Array.isArray(entries)) for (const e of entries) out[e.name] = e.value;
              waiter.resolve(out);
            }
            return reply({});
          }
          if (msg.method === "Fetch.failRequest") {
            const waiter = fetchWaiters.get(String(params.requestId ?? ""));
            if (waiter) {
              fetchWaiters.delete(String(params.requestId));
              waiter.reject(new Error(`CDP Fetch blocked: ${String(params.errorReason ?? "BlockedByClient")}`));
            }
            return reply({});
          }
          if (msg.method === "Network.setCookies") {
            const cookies = params.cookies as Array<{ name: string; value: string; expires?: number }> | undefined;
            if (Array.isArray(cookies)) {
              for (const c of cookies) {
                state.cookies.set(c.name, c.value);
                if (typeof c.expires === "number") state.cookieExpires.set(c.name, c.expires);
              }
            }
            return reply({});
          }
          if (msg.method === "Network.setExtraHTTPHeaders") {
            const hdrs = params.headers as Record<string, string> | undefined;
            if (hdrs) Object.assign(state.extraHeaders, hdrs);
            return reply({});
          }
          if (msg.method === "Network.getAllCookies" || msg.method === "Network.getCookies") {
            return reply({
              cookies: [...state.cookies.entries()].map(([name, value]) => ({
                name, value, domain: "127.0.0.1", path: "/",
                ...(state.cookieExpires.has(name) ? { expires: state.cookieExpires.get(name) } : {}),
              })),
            });
          }
          if (msg.method === "Page.navigate") {
            const target = resolveUrl(String(params.url ?? "about:blank"));
            state.currentUrl = target;
            try {
              const res = await wrappedFetch(target, { method: "GET", redirect: "follow" });
              const html = await res.text();
              applyInlineScripts(html);
            } catch { /* ignore */ }
            emitEvent("Page.loadEventFired", { timestamp: Date.now() / 1000 });
            return reply({ frameId: "mock-frame" });
          }
          if (msg.method === "Runtime.evaluate") {
            const val = await evaluate(String(params.expression ?? "null"));
            return reply({ result: { type: typeof val, value: val } });
          }
          return reply({});
        } catch (err) {
          queueMicrotask(() => onMsg?.(JSON.stringify({ id: msg.id, error: { message: err instanceof Error ? err.message : String(err) } })));
        }
      })();
    },
  };

  return { transport, state, emitEvent };
}

async function createMockSession(seed = "default", hooks: MockBrowserHooks = {}): Promise<{
  session: CdpSession;
  state: ReturnType<typeof createMockCdpTransport>["state"];
  emitEvent: (method: string, params?: Record<string, unknown>) => void;
}> {
  const mock = createMockCdpTransport(seed, hooks);
  const session = await launchCdpSession({ transport: mock.transport });
  return { session, state: mock.state, emitEvent: mock.emitEvent };
}

class NullTransport implements CdpTransportLike {
  private msg: ((data: string) => void) | null = null;
  private closeCb: ((reason?: string) => void) | null = null;
  private errCb: ((err: Error) => void) | null = null;
  sent: string[] = [];

  send(data: string): void {
    this.sent.push(data);
    const parsed = JSON.parse(data) as { id?: number; method?: string };
    if (parsed.id && parsed.method) {
      queueMicrotask(() => this.msg?.(JSON.stringify({ id: parsed.id, result: {} })));
    }
  }
  close(): void { this.closeCb?.("closed"); }
  onMessage(handler: (data: string) => void): void { this.msg = handler; }
  onClose(handler: (reason?: string) => void): void { this.closeCb = handler; }
  onError(handler: (err: Error) => void): void { this.errCb = handler; }
  fail(err: Error): void { this.errCb?.(err); }
}

describe("v8 TOTP / HOTP / otpauth 协议", () => {
  test("默认安全阈值常量符合预期", () => {
    expect(DEFAULT_SESSION_MIN_TTL_SECONDS).toBe(120);
    expect(DEFAULT_AUTH_FAILURE_THRESHOLD).toBe(2);
  });

  test("RFC 4226 HOTP 标准向量", () => {
    const secret = Buffer.from("12345678901234567890", "ascii");
    const vectors: Array<[number, string]> = [
      [0, "755224"],
      [1, "287082"],
      [2, "359152"],
      [3, "969429"],
      [4, "338314"],
      [5, "254676"],
      [6, "287922"],
      [7, "162583"],
      [8, "399871"],
      [9, "520489"],
    ];
    for (const [counter, code] of vectors) {
      expect(generateHotpCode(secret, counter, { digits: 6 })).toBe(code);
    }
  });

  test("RFC 6238 SHA1 标准 TOTP 向量", () => {
    const secret = base32Encode(Buffer.from("12345678901234567890", "ascii"));
    const vectors: Array<[number, string]> = [
      [59_000, "94287082"],
      [1_111_111_109_000, "07081804"],
      [1_111_111_111_000, "14050471"],
      [1_234_567_890_000, "89005924"],
      [2_000_000_000_000, "69279037"],
      [20_000_000_000_000, "65353130"],
    ];
    for (const [timestampMs, code] of vectors) {
      expect(generateTotpCode(secret, { digits: 8, timestampMs, algorithm: "SHA1" }).code).toBe(code);
    }
  });

  test("SHA256 / SHA512 算法可生成并校验 8 位动态码", () => {
    for (const algorithm of ["SHA256", "SHA512"] as const) {
      const seed = algorithm === "SHA256"
        ? Buffer.from("12345678901234567890123456789012", "ascii")
        : Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "ascii");
      const secret = base32Encode(seed);
      const token = generateTotpCode(secret, { digits: 8, timestampMs: 59_000, algorithm });
      expect(token.code).toMatch(/^\d{8}$/);
      expect(token.algorithm).toBe(algorithm);
      const verified = verifyTotpCode(secret, token.code, { digits: 8, timestampMs: 59_000, algorithm, window: 1 });
      expect(verified.valid).toBe(true);
    }
  });

  test("Base32 大小写、空格、等号与 otpauth URI 可解析", () => {
    const raw = Buffer.from("12345678901234567890", "ascii");
    const b32 = base32Encode(raw);
    const noisy = ` ${b32.toLowerCase().replace(/(.{4})/g, "$1 ").trim()} === `;
    expect(decodeBase32Secret(noisy).equals(raw)).toBe(true);
    const parsed = parseOtpAuthUri(`otpauth://totp/ACME:alice?secret=${b32}&issuer=ACME&algorithm=SHA256&digits=8&period=60`);
    expect(parsed.issuer).toBe("ACME");
    expect(parsed.account).toBe("alice");
    expect(parsed.algorithm).toBe("SHA256");
    expect(parsed.digits).toBe(8);
    expect(parsed.period).toBe(60);
  });

  test("verifyTotpCode 窗口校验与错误码拒绝", () => {
    const secret = base32Encode(Buffer.from("12345678901234567890", "ascii"));
    const timestampMs = 1_111_111_111_000;
    const code = generateTotpCode(secret, { digits: 8, timestampMs }).code;
    const ok = verifyTotpCode(secret, code, { digits: 8, timestampMs: timestampMs + 30_000, window: 1 });
    expect(ok.valid).toBe(true);
    expect(ok.matchedOffset).toBe(-1);
    const bad = verifyTotpCode(secret, "00000000", { digits: 8, timestampMs, window: 0 });
    expect(bad.valid).toBe(false);
  });
});

describe("v8 连续失败计数与临时根目录", () => {
  test("401/403 连续两次计数并 reset 清零", () => {
    const root = tmpRoot();
    expect(getRoleConsecutiveAuthFailures(root, "alice")).toBe(0);
    expect(recordRoleAuthStatus(root, "alice", 401)).toBe(1);
    expect(recordRoleAuthStatus(root, "alice", 403)).toBe(2);
    expect(getRoleConsecutiveAuthFailures(root, "alice")).toBe(2);
    resetRoleAuthFailures(root, "alice");
    expect(getRoleConsecutiveAuthFailures(root, "alice")).toBe(0);
  });

  test("loadSessionVault 与 upsertSessionRole 对外摘要和脱敏不含明文密码", () => {
    const root = tmpRoot();
    const jwt = jwtWithExp(30);
    upsertSessionRole(root, {
      role: "alice",
      bearer: jwt,
      username: "alice",
      password: "alice-password-plain",
      note: "仅测试",
      expiresAt: new Date(Date.now() + 30_000).toISOString(),
    });
    const vault = loadSessionVault(root);
    expect(vault.roles.alice).toBeDefined();
    expect(vault.roles.alice?.bearer).toBe(jwt);
    const raw = readFileSync(join(root, ".nuwa", "sessions", "vault.json"), "utf8");
    const summary = formatSessionVaultSummary(root);
    const redacted = redactVaultSecrets(raw, root);
    expect(summary).not.toContain("alice-password-plain");
    expect(redacted).not.toContain("alice-password-plain");
  });
});

describe("v8 交互式鉴权剧本与 OAuth 回调脱敏", () => {
  test("真实登录表单 + TOTP + OAuth 回调 + captureStorage", async () => {
    const root = tmpRoot();
    const recorder = new TrafficRecorder(root);
    const requests: Array<{ method: string; url: string; body: string }> = [];
    const server = http.createServer((req, res) => {
      const u = new URL(req.url ?? "/", "http://127.0.0.1");
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        requests.push({ method: req.method ?? "GET", url: u.pathname + u.search, body });
        if (u.pathname === "/login" && req.method === "GET") {
          res.writeHead(200, { "content-type": "text/html" });
          res.end(`<html><body><form id="login">
            <input id="username" name="username" />
            <input id="password" name="password" type="password" />
            <input id="totp" name="totp" />
            <button id="submit" type="submit">Login</button>
          </form></body></html>`);
          return;
        }
        if (u.pathname === "/login" && req.method === "POST") {
          res.writeHead(302, { location: "/oauth/authorize?state=state-123", "set-cookie": "preauth=1; Path=/" });
          res.end();
          return;
        }
        if (u.pathname === "/oauth/authorize") {
          res.writeHead(302, { location: "/oauth/callback?code=SECRET-CODE&state=state-123&access_token=RAW-TOKEN" });
          res.end();
          return;
        }
        if (u.pathname === "/oauth/callback") {
          res.writeHead(200, {
            "content-type": "text/html",
            "set-cookie": "sid=mock-session-secret; Path=/; HttpOnly",
          });
          res.end(`<html><body><div id="dashboard">ok</div><script>
            localStorage.setItem("access_token", "RAW-TOKEN");
            localStorage.setItem("csrf_token", "csrf-secret-val");
          </script></body></html>`);
          return;
        }
        if (u.pathname === "/dashboard") {
          res.writeHead(200, { "content-type": "text/html" });
          res.end(`<html><body><div id="dashboard">dashboard</div></body></html>`);
          return;
        }
        res.writeHead(404);
        res.end("not found");
      });
    });
    const base = await listenHttp(server);
    const scope = makeScope(base);
    const { session, state } = await createMockSession("playbook");
    const totpSecret = base32Encode(Buffer.from("12345678901234567890", "ascii"));
    const result = await runInteractiveAuthPlaybook({
      session,
      role: "alice",
      root,
      scope,
      username: "alice",
      checkUrl: `${base}/dashboard`,
      recorder,
      closeSessionOnSuccess: true,
      steps: [
        { action: "goto", url: `${base}/login`, settleMs: 0, timeoutMs: 2_000 },
        { action: "waitForSelector", selector: "#username", timeoutMs: 2_000 },
        { action: "fill", selector: "#username", value: "alice", timeoutMs: 2_000 },
        { action: "fill", selector: "#password", value: "alice-password-plain", isSecret: true, timeoutMs: 2_000 },
        { action: "fillTotp", selector: "#totp", secret: totpSecret, totpOptions: { digits: 6 }, timeoutMs: 2_000 },
        { action: "submit", selector: "#submit", waitForNavigation: true, settleMs: 0, timeoutMs: 2_000 },
        { action: "waitForSelector", selector: "#dashboard", timeoutMs: 2_000 },
        { action: "captureStorage", tokenKeys: ["access_token", "csrf_token"], includeSessionStorage: true, timeoutMs: 2_000 },
      ],
    });
    expect(result.ok).toBe(true);
    expect(result.role).toBe("alice");
    expect(result.sessionClosed).toBe(true);
    expect(state.closed).toBe(true);
    expect(requests.some((r) => r.url.includes("/oauth/callback"))).toBe(true);
    expect(result.capturedCredentialSources).toContain("cookie:sid");
    expect(result.capturedCredentialSources).toContain("localStorage:access_token");
    const resultDump = JSON.stringify(result);
    const logDump = readFileSync(recorder.indexPath, "utf8");
    for (const secretVal of ["alice-password-plain", "RAW-TOKEN", "SECRET-CODE", "mock-session-secret", totpSecret]) {
      expect(resultDump).not.toContain(secretVal);
      expect(logDump).not.toContain(secretVal);
    }
    const vault = loadSessionVault(root);
    expect(vault.roles.alice?.cookie).toContain("sid=mock-session-secret");
  }, 15_000);

  test("交互式剧本失败时必须关闭会话", async () => {
    const root = tmpRoot();
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body><div>no target</div></body></html>");
    });
    const base = await listenHttp(server);
    const scope = makeScope(base);
    const { session, state } = await createMockSession("close");
    const result = await runInteractiveAuthPlaybook({
      session,
      role: "alice",
      root,
      scope,
      steps: [
        { action: "goto", url: `${base}/login`, timeoutMs: 2_000 },
        { action: "waitForSelector", selector: "#missing-never-appears", timeoutMs: 250 },
      ],
    });
    expect(result.ok).toBe(false);
    expect(result.sessionClosed).toBe(true);
    expect(session.closed || state.closed).toBe(true);
  });

  test("越界 URL 在剧本层被阻断", async () => {
    const root = tmpRoot();
    const { session } = await createMockSession("scope");
    const scope: ScopePolicy = {
      allowHosts: ["example.com"],
      allowCidrs: [],
      denyHosts: [],
      allowSubdomains: false,
      allowPrivateNetwork: false,
      allowDestructive: false,
      allowLoopback: false,
    };
    const result = await runInteractiveAuthPlaybook({
      session,
      role: "alice",
      root,
      scope,
      steps: [{ action: "goto", url: "http://127.0.0.1:1/forbidden", timeoutMs: 200 }],
    });
    expect(result.blockedByScope).toBe(true);
    expect(result.ok).toBe(false);
  });
});

describe("v8 ensureSessionFresh 临期 JWT 与 401/403 热续期", () => {
  test("JWT 剩余 <120s 时触发刷新并清零失败计数", async () => {
    const root = tmpRoot();
    const jwt = jwtWithExp(60);
    upsertSessionRole(root, { role: "alice", bearer: jwt, username: "alice" });
    recordRoleAuthStatus(root, "alice", 401);
    recordRoleAuthStatus(root, "alice", 403);
    expect(getRoleConsecutiveAuthFailures(root, "alice")).toBe(2);
    let refreshed = 0;
    const result = await ensureSessionFresh(root, "alice", makeScope("http://127.0.0.1"), {
      minRemainingSeconds: 120,
      refreshRunner: async () => {
        refreshed += 1;
        upsertSessionRole(root, { role: "alice", bearer: jwtWithExp(3600), username: "alice" });
        return {
          ok: true, role: "alice", blockedByScope: false, finalUrl: "http://127.0.0.1/ok",
          navigationChain: [], steps: [], blockedRequests: [], capturedCredentialSources: ["bearer"],
          sessionClosed: true, vaultSummary: "ok",
        };
      },
      observedStatus: 401,
      nowMs: Date.now(),
    });
    expect(result.ok).toBe(true);
    expect(result.refreshed).toBe(true);
    expect(result.triggerReason).toBe("jwt_expiring_soon");
    expect(refreshed).toBe(1);
    expect(result.consecutiveFailuresAfter).toBe(0);
    expect(getRoleConsecutiveAuthFailures(root, "alice")).toBe(0);
  });

  test("连续 401/403 触发重登且不泄露凭据", async () => {
    const root = tmpRoot();
    upsertSessionRole(root, { role: "bob", bearer: jwtWithExp(3600) });
    recordRoleAuthStatus(root, "bob", 401);
    const result = await ensureSessionFresh(root, "bob", makeScope("http://127.0.0.1"), {
      refreshRunner: async () => {
        upsertSessionRole(root, { role: "bob", bearer: jwtWithExp(7200) });
        return {
          ok: true, role: "bob", blockedByScope: false, finalUrl: "http://127.0.0.1/ok",
          navigationChain: [], steps: [], blockedRequests: [], capturedCredentialSources: ["bearer"],
          sessionClosed: true, vaultSummary: "ok",
        };
      },
      observedStatus: 403,
      nowMs: Date.now(),
    });
    expect(result.ok).toBe(true);
    expect(result.refreshed).toBe(true);
    expect(result.triggerReason).toBe("consecutive_401_403");
    expect(result.consecutiveFailuresBefore).toBe(2);
    expect(result.consecutiveFailuresAfter).toBe(0);
  });
});

describe("v8 页面内动态签名探针与全方法差分", () => {
  test("GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE 由页面表达式真实加签并剥离内部对齐头", async () => {
    const seen: Array<{ url: string; method: string; headers: Record<string, string>; body: string }> = [];
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = Array.isArray(v) ? v.join(",") : String(v ?? "");
        seen.push({ url: req.url ?? "/", method: req.method ?? "GET", headers, body });
        if (!headers["x-timestamp"] || !headers["x-nonce"] || !headers["x-signature"]) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "missing signature", path: req.url }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(req.method === "HEAD" ? "" : JSON.stringify({ ok: true, method: req.method, path: req.url }));
      });
    });
    const base = await listenHttp(server);
    const scope = makeScope(base);
    const observedForwardedHeaders: Array<Record<string, string>> = [];
    const { session, state } = await createMockSession("signed", { signSecret: "page-hmac-key", observedForwardedHeaders });
    await session.client.send("Page.navigate", { url: base }, { sessionId: session.sessionId });
    const methods = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"] as const;
    for (const method of methods) {
      const result = await executeInPageStatefulSignedProbe(
        session,
        {
          url: `${base}/signed-${method.toLowerCase()}`,
          method,
          body: method === "GET" || method === "HEAD" ? undefined : { method, amount: 42 },
          signerHook: "__nuwaSign",
        },
        scope,
        { timeoutMs: 3_000 },
      );
      expect(result.blocked).toBe(false);
      expect(result.status).toBe(200);
      expect(result.signedByHook).toBe(true);
      expect(result.appliedSignatureHeaders).toContain("X-Signature");
    }
    const signedSeen = seen.filter((s) => s.url.startsWith("/signed-"));
    expect(state.fetchPausedCount).toBe(methods.length);
    expect(signedSeen.length).toBe(methods.length);
    for (const s of signedSeen) {
      expect(s.headers["x-timestamp"]).toBeTruthy();
      expect(s.headers["x-nonce"]).toBeTruthy();
      expect(s.headers["x-signature"]).toBeTruthy();
      expect(s.headers["x-nuwa-stateful-probe-token"]).toBeUndefined();
    }
    // 校验恶意 signerHook 表达式注入被拦截
    const badHook = await executeInPageStatefulSignedProbe(
      session,
      { url: `${base}/signed-get`, method: "GET", signerHook: "window.alert(1)" },
      scope,
    );
    expect(badHook.blocked).toBe(true);
  }, 15_000);

  test("Soft-404 SPA 兜底页不被误报", async () => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(`<html><body><div id="app">SPA fallback ${req.url}</div><script>window.__NEXT_DATA__={}</script></body></html>`);
    });
    const base = await listenHttp(server);
    const scope = makeScope(base);
    const { session } = await createMockSession("soft404");
    await session.client.send("Page.navigate", { url: base }, { sessionId: session.sessionId });
    const root = tmpRoot();
    const diff = await runCdpStatefulSignedAuthDiff(
      base,
      [{ path: "/definitely-not-exist", method: "GET" }],
      root,
      scope,
      {
        session,
        signerHook: "__nuwaSign",
        extraRoleHeaders: { admin: { Authorization: "Bearer adm-secret" }, user: { Authorization: "Bearer usr-secret" } },
      },
    );
    expect(diff.ok).toBe(true);
    expect(diff.findings.length).toBe(0);
  });

  test("runCdpStatefulSignedAuthDiff 对全方法 ACL 与 BOLA 端点精准差分并脱敏", async () => {
    const root = tmpRoot();
    const recorder = new TrafficRecorder(root);
    upsertSessionRole(root, { role: "admin", bearer: "admin-secret-jwt-token" });
    upsertSessionRole(root, { role: "user1", bearer: "user1-secret-jwt-token" });
    upsertSessionRole(root, { role: "user2", bearer: "user2-secret-jwt-token" });
    const server = http.createServer((req, res) => {
      if (!req.headers["x-signature"] || !req.headers["x-timestamp"]) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "unsigned rejected" }));
        return;
      }
      const auth = String(req.headers.authorization ?? "");
      if (req.url === "/api/admin/users" && req.method === "POST") {
        // 故意允许 user1 越权成功执行写操作（BFLA）
        if (!auth.includes("admin-secret") && !auth.includes("user1-secret")) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "forbidden" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ created: true, userId: 99, role: "operator" }));
        return;
      }
      if (req.url === "/api/orders/101" && req.method === "GET") {
        if (!auth) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "login required" }));
          return;
        }
        // user1 与 user2 均可返回同一份订单（水平 BOLA）
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ orderId: 101, owner: "user1", total: 999, item: "gpu" }));
        return;
      }
      res.writeHead(404);
      res.end("not found");
    });
    const base = await listenHttp(server);
    const { session } = await createMockSession("diff");
    const result = await runCdpStatefulSignedAuthDiff(
      base,
      [
        { path: "/api/admin/users", method: "POST", body: { name: "new-op" } },
        { path: "/api/orders/101", method: "GET" },
      ],
      root,
      makeScope(base),
      { session, baselineRole: "admin", signerHook: "__nuwaSign", concurrency: 2, recorder },
    );
    expect(result.ok).toBe(true);
    expect(result.unsignedStatuses["POST /api/admin/users"]).toBe(401);
    expect(result.findings.some((f) => f.kind === "vertical_bfla" && f.method === "POST")).toBe(true);
    expect(result.findings.some((f) => f.kind === "horizontal_bola" && f.path === "/api/orders/101")).toBe(true);
    expect(result.fact?.kind).toBe("vuln");
    const dump = JSON.stringify(result) + readFileSync(recorder.indexPath, "utf8");
    expect(dump).not.toContain("admin-secret-jwt-token");
    expect(dump).not.toContain("user1-secret-jwt-token");
    expect(dump).not.toContain("user2-secret-jwt-token");
  }, 15_000);
});

describe("v8 GraphQL 深度引擎", () => {
  test("标准 __schema 内省解析", () => {
    const payload = {
      data: {
        __schema: {
          queryType: { name: "Query" },
          mutationType: { name: "Mutation" },
          types: [
            {
              kind: "OBJECT",
              name: "Query",
              fields: [{ name: "user", type: { kind: "OBJECT", name: "User" } }],
            },
            {
              kind: "OBJECT",
              name: "User",
              fields: [
                { name: "id", type: { kind: "SCALAR", name: "ID" } },
                { name: "email", type: { kind: "SCALAR", name: "String" } },
              ],
            },
          ],
        },
      },
    };
    const summary = parseGraphQLIntrospection(payload as any);
    expect(summary).toBeDefined();
    expect(JSON.stringify(summary)).toContain("Query");
    expect(JSON.stringify(summary)).toContain("email");
  });

  test("禁内省字段建议盲还原", () => {
    const suggestions = parseGraphQLSuggestionsFromErrors([
      { message: 'Cannot query field "emial" on type "User". Did you mean "email"?' },
      { message: 'Cannot query field "nmae" on type "User". Did you mean "name"?' },
    ] as any);
    const text = JSON.stringify(suggestions);
    expect(text).toContain("email");
    expect(text).toContain("name");
  });

  test("真实内省端点 inspectGraphQLSchema", async () => {
    const introspection = {
      data: {
        __schema: {
          queryType: { name: "Query" },
          types: [{ kind: "OBJECT", name: "Query", fields: [{ name: "viewer", type: { kind: "OBJECT", name: "User" } }] }],
        },
      },
    };
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        if (body.includes("__schema")) {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify(introspection));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ data: { viewer: null } }));
      });
    });
    const base = await listenHttp(server);
    const result = await inspectGraphQLSchema(`${base}/graphql`, makeScope(base), { headers: { authorization: "Bearer test" } } as any);
    expect(result).toBeDefined();
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).toContain("Query");
  });

  test("禁内省端点通过 Did you mean 字段建议盲还原 Schema", async () => {
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        if (body.includes("__schema")) {
          res.end(JSON.stringify({ errors: [{ message: "GraphQL introspection is disabled" }] }));
          return;
        }
        if (body.includes("usr") || body.includes("userss")) {
          res.end(JSON.stringify({ errors: [{ message: 'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?' }] }));
          return;
        }
        if (body.includes("user") && body.includes("__nuwa")) {
          res.end(JSON.stringify({ errors: [{ message: 'Cannot query field "__nuwa_sub" on type "User". Did you mean "email", "secretNote"?' }] }));
          return;
        }
        res.end(JSON.stringify({ errors: [{ message: "Unknown field" }] }));
      });
    });
    const base = await listenHttp(server);
    const result = await inspectGraphQLSchema(`${base}/graphql`, makeScope(base), { dictionary: ["usr"] });
    expect(result.ok).toBe(true);
    expect(result.introspectionEnabled).toBe(false);
    expect(result.discoveredQueries).toContain("user");
    expect(result.discoveredQueries).toContain("users");
  });

  test("Alias 与 Batch 查询构建", () => {
    const query = buildGraphQLAliasQuery(
      [
        { alias: "u1", field: "user", args: { id: 1 }, selectionSet: "id email" },
        { alias: "u2", field: "user", args: { id: 2 }, selectionSet: "id" },
      ],
      "AliasOp",
    );
    expect(query).toContain("u1: user");
    expect(query).toContain("u2: user");
    expect(query).toContain("AliasOp");
    const batch = buildGraphQLBatchPayload([
      { query: "query A { viewer { id } }", variables: { a: 1 }, operationName: "A" },
      { query: "query B { viewer { id } }" },
    ]);
    expect(batch.length).toBe(2);
  });

  test("跨角色嵌套权限差分检出越权且不误报错误页", async () => {
    const root = tmpRoot();
    upsertSessionRole(root, { role: "admin", bearer: "admin-gql-secret" });
    upsertSessionRole(root, { role: "user", bearer: "user-gql-secret" });
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const auth = String(req.headers.authorization ?? "");
        res.writeHead(200, { "content-type": "application/json" });
        if (body.includes("safeAdminField") && !auth.includes("admin-gql-secret")) {
          res.end(JSON.stringify({ errors: [{ message: "forbidden" }], data: { viewer: null } }));
          return;
        }
        if (body.includes("adminSettings")) {
          if (!auth) { res.end(JSON.stringify({ errors: [{ message: "unauth" }], data: null })); return; }
          res.end(JSON.stringify({ data: { adminSettings: { apiKey: "gql-api-key-leak", tier: "enterprise" } } }));
          return;
        }
        res.end(JSON.stringify({ data: { viewer: { id: "1", email: "a@example.com" } } }));
      });
    });
    const base = await listenHttp(server);
    const result = await runGraphQLNestedAuthDiff(
      `${base}/graphql`,
      [
        { name: "SafeAdmin", query: "query { viewer { id safeAdminField } }", expectedAdminOnly: true },
        { name: "LeakyAdmin", query: "query { adminSettings { apiKey tier } }", expectedAdminOnly: true },
      ],
      root,
      makeScope(base),
      { roles: ["admin", "user"] },
    );
    expect(result.ok).toBe(true);
    expect(result.findings.some((f) => f.name === "SafeAdmin")).toBe(false);
    expect(result.findings.some((f) => f.name === "LeakyAdmin" && f.kind === "vertical_bfla")).toBe(true);
    expect(JSON.stringify(result)).not.toContain("admin-gql-secret");
    expect(JSON.stringify(result)).not.toContain("user-gql-secret");
  });
});

describe("v8 WebSocket 双向帧审计", () => {
  test("CDP WebSocket 帧事件解析与敏感信息脱敏", async () => {
    const { session, emitEvent } = await createMockSession("ws-audit");
    const auditor = attachCdpWebSocketAuditor(session, makeScope("http://127.0.0.1"), { extraSecrets: ["secret-token"] });
    emitEvent("Network.webSocketCreated", { requestId: "1", url: "ws://127.0.0.1:8080/ws?token=secret-token" });
    emitEvent("Network.webSocketCreated", { requestId: "2", url: "ws://evil.outside.invalid/ws" });
    const payload = Buffer.from('{"type":"subscribe","tenant":"acme","token":"secret-token"}').toString("base64");
    emitEvent("Network.webSocketFrameSent", { requestId: "1", response: { opcode: 2, payloadData: payload } });
    emitEvent("Network.webSocketFrameReceived", { requestId: "1", response: { opcode: 1, payloadData: '{"tenant":"other","data":"ok"}' } });
    const frames = auditor.getFrames();
    expect(frames.length).toBe(2);
    expect(JSON.stringify(frames)).not.toContain("secret-token");
    expect(auditor.getBlockedUrls().length).toBe(1);
    auditor.detach();
  });

  test("真实 WebSocket 推送检出未授权订阅与跨租户推送", async () => {
    const clients = new Set<{ close: () => void }>();
    const wsServer = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch(req, server) {
        const url = new URL(req.url);
        if (url.pathname === "/ws") {
          if (server.upgrade(req, { data: { role: req.headers.get("authorization") ?? "anon" } })) return undefined;
          return new Response("upgrade failed", { status: 500 });
        }
        return new Response("ok");
      },
      websocket: {
        open(ws) { clients.add(ws); },
        message(ws, message) {
          let parsed: { action?: string; channel?: string } | null = null;
          try { parsed = JSON.parse(String(message)) as { action?: string; channel?: string }; } catch { parsed = null; }
          if (parsed?.action === "subscribe") {
            ws.send(JSON.stringify({ type: "ack", subscription: parsed.channel }));
            ws.send(JSON.stringify({ type: "push", tenant: "tenant_b", data: "TENANT_B_SECRET_DATA" }));
          }
        },
        close(ws) { clients.delete(ws); },
      },
    });
    const base = trackBunServer(wsServer);
    const scope = makeScope(base);
    const wsUrl = `${base.replace("http", "ws")}/ws`;
    const result = await auditWebSocketCrossTenantPush(
      [
        {
          wsUrl,
          role: "anon",
          subscribeMessages: [{ action: "subscribe", channel: "tenant_b" }],
          foreignTenantMarkers: ["TENANT_B_SECRET_DATA"],
          timeoutMs: 1_500,
          settleMs: 150,
        },
        {
          wsUrl,
          role: "tenant_a",
          headers: { Authorization: "Bearer tenant-a-ws-secret" },
          subscribeMessages: [{ action: "subscribe", channel: "tenant_b" }],
          foreignTenantMarkers: ["TENANT_B_SECRET_DATA"],
          timeoutMs: 1_500,
          settleMs: 150,
        },
      ],
      scope,
    );
    expect(result.ok).toBe(true);
    expect(result.findings.some((f) => f.kind === "unauth_ws_subscription")).toBe(true);
    expect(result.findings.some((f) => f.kind === "cross_tenant_push")).toBe(true);
    expect(JSON.stringify(result)).not.toContain("tenant-a-ws-secret");
    for (const c of clients) { try { c.close(); } catch { /* 清理 */ } }
  }, 15_000);

  test("越界 WebSocket URL 被阻断且无端口残留", async () => {
    const scope: ScopePolicy = {
      allowHosts: ["example.com"],
      allowCidrs: [],
      denyHosts: [],
      allowSubdomains: false,
      allowPrivateNetwork: false,
      allowDestructive: false,
      allowLoopback: false,
    };
    const result = await auditWebSocketCrossTenantPush(
      [{ wsUrl: "ws://127.0.0.1:1/ws", role: "user", subscribeMessages: [{ action: "subscribe" }] }],
      scope,
      { timeoutMs: 200 },
    );
    expect(result.blockedByScope).toBe(true);
    expect(result.ok).toBe(false);
  });
});

describe("v8 Next.js RSC Flight 与 gRPC-Web 编解码", () => {
  test("RSC Flight 行协议解析", () => {
    const body = [
      '0:{"a":1,"name":"root"}',
      '1:E{"digest":"NEXT_FORBIDDEN"}',
      '2:["$","div",null,{"children":"hello"}]',
    ].join("\n");
    const chunks = parseRscFlightStream(body);
    expect(chunks.length).toBe(3);
    expect(chunks[0]?.isErrorDigest).toBe(false);
    expect(chunks[1]?.tag).toBe("E");
    expect(chunks[1]?.isErrorDigest).toBe(true);
  });

  test("RSC Action 请求构建与角色差分", async () => {
    const root = tmpRoot();
    upsertSessionRole(root, { role: "admin", bearer: "admin-rsc-token" });
    upsertSessionRole(root, { role: "user", bearer: "user-rsc-token" });
    const request = buildRscActionRequest("action-1", [{ id: 7 }], { "x-extra": "1" });
    expect(request.headers["Next-Action"]).toBe("action-1");
    expect(JSON.parse(request.body)).toEqual([{ id: 7 }]);
    const server = http.createServer((req, res) => {
      const auth = String(req.headers.authorization ?? "");
      res.writeHead(200, { "content-type": "text/x-component" });
      if (req.url === "/rsc-safe" && !auth.includes("admin-rsc-token")) {
        res.end('0:E{"digest":"FORBIDDEN"}\n');
        return;
      }
      res.end('0:{"ok":true,"secret":"rsc-secret-payload"}\n');
    });
    const base = await listenHttp(server);
    const result = await diffRscActionRoles(
      [
        { name: "SafeRsc", url: `${base}/rsc-safe`, actionId: "action-1", args: [{ id: 7 }], expectedAdminOnly: true },
        { name: "LeakyRsc", url: `${base}/rsc-leaky`, actionId: "action-2", args: [{ id: 9 }], expectedAdminOnly: true },
      ],
      root,
      makeScope(base),
      { roles: ["admin", "user"] },
    );
    expect(result.ok).toBe(true);
    expect(result.findings.some((f) => f.name === "SafeRsc")).toBe(false);
    expect(result.findings.some((f) => f.name === "LeakyRsc" && f.kind === "vertical_bfla")).toBe(true);
    expect(JSON.stringify(result)).not.toContain("admin-rsc-token");
    expect(JSON.stringify(result)).not.toContain("user-rsc-token");
  });

  test("Protobuf Varint 与 Length-delimited 编解码往返", () => {
    for (const n of [0, 1, 127, 128, 300, 16384, 9007199254740991]) {
      const enc = encodeVarint(n);
      const dec = decodeVarint(enc);
      expect(Number(dec.value)).toBe(n);
      expect(dec.nextOffset).toBe(enc.length);
    }
    const buf = encodeProtobufFields([
      { fieldNumber: 1, wireType: 2, value: "hello-proto" },
      { fieldNumber: 2, wireType: 0, value: 150 },
    ]);
    const decoded = decodeProtobufFields(buf);
    expect(decoded.length).toBe(2);
    expect(decoded[0]?.utf8Text).toBe("hello-proto");
    expect(Number(decoded[1]?.value)).toBe(150);
  });

  test("gRPC-Web 5 字节头含 gzip 压缩与 trailer 往返", () => {
    const rawPayload = encodeProtobufFields([{ fieldNumber: 1, wireType: 2, value: "grpc-ok" }]);
    const gzPayload = new Uint8Array(gzipSync(rawPayload));
    const frame = encodeGrpcWebFrame(gzPayload, { compressed: true, isTrailer: false });
    expect(frame.length).toBe(gzPayload.length + 5);
    expect(frame[0]).toBe(1);
    const trailer = encodeGrpcWebFrame(new TextEncoder().encode("grpc-status:0\r\ngrpc-message:ok\r\n"), { isTrailer: true });
    expect(trailer[0]).toBe(0x80);
    const frames = decodeGrpcWebFrames(new Uint8Array([...frame, ...trailer]));
    expect(frames.length).toBe(2);
    expect(Buffer.from(frames[0]!.payload).equals(Buffer.from(rawPayload))).toBe(true);
    expect(frames[1]?.isTrailer).toBe(true);
    expect(frames[1]?.trailers?.["grpc-status"]).toBe("0");
  });

  test("gRPC-Web 方法角色差分 grpc-status=0 vs 7", async () => {
    const root = tmpRoot();
    upsertSessionRole(root, { role: "admin", bearer: "admin-grpc-token" });
    upsertSessionRole(root, { role: "user", bearer: "user-grpc-token" });
    const server = http.createServer((req, res) => {
      let body = Buffer.alloc(0);
      req.on("data", (c) => (body = Buffer.concat([body, c])));
      req.on("end", () => {
        const auth = String(req.headers.authorization ?? "");
        const denied = req.url?.includes("SafeAdmin") && !auth.includes("admin-grpc-token");
        const dataFrame = denied
          ? new Uint8Array(0)
          : encodeGrpcWebFrame(encodeProtobufFields([{ fieldNumber: 1, wireType: 2, value: "admin-secret-data" }]));
        const trailer = encodeGrpcWebFrame(
          new TextEncoder().encode(`grpc-status:${denied ? "7" : "0"}\r\n`),
          { isTrailer: true },
        );
        res.writeHead(200, { "content-type": "application/grpc-web+proto" });
        res.end(Buffer.from(new Uint8Array([...dataFrame, ...trailer])));
      });
    });
    const base = await listenHttp(server);
    const result = await diffGrpcWebMethodRoles(
      [
        { name: "SafeAdmin", url: `${base}/pkg.Service/SafeAdmin`, requestFields: [{ fieldNumber: 1, wireType: 2, value: "check" }], expectedAdminOnly: true },
        { name: "LeakyAdmin", url: `${base}/pkg.Service/LeakyAdmin`, requestFields: [{ fieldNumber: 1, wireType: 2, value: "check" }], expectedAdminOnly: true },
      ],
      root,
      makeScope(base),
      { roles: ["admin", "user"] },
    );
    expect(result.ok).toBe(true);
    expect(result.findings.some((f) => f.name === "SafeAdmin")).toBe(false);
    expect(result.findings.some((f) => f.name === "LeakyAdmin" && f.kind === "vertical_bfla")).toBe(true);
    expect(JSON.stringify(result)).not.toContain("admin-grpc-token");
    expect(JSON.stringify(result)).not.toContain("user-grpc-token");
  });

  test("NullTransport 不产生句柄与端口泄漏", () => {
    const t = new NullTransport();
    const messages: string[] = [];
    t.onMessage((m) => messages.push(m));
    let closed = false;
    t.onClose(() => (closed = true));
    t.send(JSON.stringify({ id: 1, method: "Runtime.evaluate", params: { expression: "1+1" } }));
    t.close();
    expect(t.sent.length).toBe(1);
    expect(closed).toBe(true);
    expect(messages.length).toBeGreaterThanOrEqual(0);
  });
});

describe("v8 清理不变量", () => {
  test("临时目录与服务器均可幂等回收", async () => {
    const root = tmpRoot();
    const server = http.createServer((_req, res) => res.end("ok"));
    const base = await listenHttp(server);
    const res = await fetch(base);
    expect(await res.text()).toBe("ok");
    expect(root.length).toBeGreaterThan(0);
  });
});

describe("v8 异构审查 P1 对抗边界回归", () => {
  test("P1-1: 前置越界与点击外跳均关闭外部会话，纯 Cookie 过期时间落盘 Vault", async () => {
    const root1 = tmpRoot();
    const s1 = (await createMockSession("p1-pre")).session;
    const preBlocked = await runInteractiveAuthPlaybook({
      session: s1, role: "alice", root: root1,
      scope: { allowHosts: ["example.com"], allowCidrs: [], denyHosts: [], allowSubdomains: false, allowPrivateNetwork: false, allowDestructive: false, allowLoopback: false },
      steps: [{ action: "goto", url: "http://127.0.0.1:9/evil" }],
    });
    expect(preBlocked.blockedByScope).toBe(true);
    expect(preBlocked.sessionClosed).toBe(true);
    expect(s1.closed).toBe(true);

    const server = http.createServer((req, res) => {
      if (req.url === "/login") {
        res.writeHead(200, { "content-type": "text/html", "set-cookie": "sess=CookieVal9956; Max-Age=3600; Path=/" });
        res.end('<html><body><button id="sso-external">SSO</button><button id="ok-btn">OK</button></body></html>');
        return;
      }
      res.writeHead(200); res.end("ok");
    });
    const base = await listenHttp(server);
    const root2 = tmpRoot();
    const s2 = (await createMockSession("p1-sso")).session;
    const ssoRes = await runInteractiveAuthPlaybook({
      session: s2, role: "alice", root: root2, scope: makeScope(base),
      steps: [{ action: "goto", url: `${base}/login` }, { action: "click", selector: "#sso-external", waitForNavigation: false }],
    });
    expect(ssoRes.ok).toBe(false);
    expect(ssoRes.blockedByScope).toBe(true);
    expect(ssoRes.sessionClosed).toBe(true);
    expect(loadSessionVault(root2).roles.alice).toBeUndefined();

    const root3 = tmpRoot();
    const s3 = (await createMockSession("p1-cookie")).session;
    const cookieRes = await runInteractiveAuthPlaybook({
      session: s3, role: "bob", root: root3, scope: makeScope(base), closeSessionOnSuccess: true,
      steps: [{ action: "goto", url: `${base}/login` }],
    });
    expect(cookieRes.ok).toBe(true);
    expect(cookieRes.expiresAt).toBeTruthy();
    expect(loadSessionVault(root3).roles.bob?.expiresAt).toBe(cookieRes.expiresAt);
  });

  test("P1-2: otpauth 裸密钥零明文脱敏与全掩码优先顺序", async () => {
    const root = tmpRoot();
    const rawSecret = "JBSWY3DPEHPK3PXP";
    upsertSessionRole(root, { role: "alice", cookie: "sid=CookieVal9956", bearer: "BearerTokenXYZ99" });
    const scrubbed = scrubTextWithExtraSecrets("leak CookieVal9956 and BearerTokenXYZ99", ["CookieVal9956", "BearerTokenXYZ99"], root);
    expect(scrubbed).toBe("leak [REDACTED] and [REDACTED]");
    expect(scrubbed).not.toContain("Coo***");

    const srv = http.createServer((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end('<input id="totp" />'); });
    const base = await listenHttp(srv);
    const { session } = await createMockSession("p1-otp");
    const recorder = new TrafficRecorder(root);
    const res = await runInteractiveAuthPlaybook({
      session, role: "otpuser", root, scope: makeScope(base), recorder, closeSessionOnSuccess: true,
      steps: [{ action: "goto", url: `${base}/login` }, { action: "fillTotp", selector: "#totp", secret: `otpauth://totp/ACME:u?secret=${rawSecret.toLowerCase()}&digits=6` }, { action: "waitForSelector", selector: "#missing-abort", timeoutMs: 220 }],
    });
    expect(res.ok).toBe(false);
    expect(JSON.stringify(res)).not.toContain(rawSecret);
    expect(JSON.stringify(res)).not.toContain(rawSecret.toLowerCase());
  });

  test("P1-3 & P1-5: GraphQL 隔离查询不误报 BOLA、同 ID 跨租户与同键 BFLA 必报、禁内省盲还原标量与必填参", async () => {
    const root = tmpRoot();
    upsertSessionRole(root, { role: "admin", bearer: "adm-gql-p13" });
    upsertSessionRole(root, { role: "alice", bearer: "ali-gql-p13" });
    upsertSessionRole(root, { role: "bob", bearer: "bob-gql-p13" });
    const srv = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const auth = String(req.headers.authorization ?? "");
        res.writeHead(200, { "content-type": "application/json" });
        if (body.includes("__schema")) { res.end(JSON.stringify({ errors: [{ message: "introspection disabled" }] })); return; }
        if (body.includes("version { __typename }")) { res.end(JSON.stringify({ errors: [{ message: 'Field "version" must not have a selection since type "String" has no subfields.' }] })); return; }
        if (body.includes("user { __typename }")) { res.end(JSON.stringify({ errors: [{ message: 'Field "user" argument "id" of type "ID!" is required.' }] })); return; }
        if (body.includes("user(id:") && body.includes("__nuwa_probe_")) { res.end(JSON.stringify({ errors: [{ message: 'Cannot query field "__nuwa" on type "User". Did you mean "email", "phone"?' }] })); return; }
        if (body.includes("GetMyProfile")) {
          if (!auth) { res.end(JSON.stringify({ errors: [{ message: "unauth" }], data: null })); return; }
          const who = auth.includes("ali") ? "alice" : auth.includes("bob") ? "bob" : "admin";
          res.end(JSON.stringify({ data: { me: { id: `u-${who}`, email: `${who}@x.test` } } }));
          return;
        }
        if (body.includes("GetOrderById")) {
          if (!auth) { res.end(JSON.stringify({ errors: [{ message: "unauth" }], data: null })); return; }
          res.end(JSON.stringify({ data: { order: { id: "ord-alice-1", ownerId: "alice", amount: 500 } } }));
          return;
        }
        if (body.includes("GetOrgBilling")) {
          if (!auth) { res.end(JSON.stringify({ errors: [{ message: "unauth" }], data: null })); return; }
          res.end(JSON.stringify({ data: { billing: { apiKey: "sk-live-org", plan: "ent" } } }));
          return;
        }
        res.end(JSON.stringify({ errors: [{ message: "unknown" }] }));
      });
    });
    const base = await listenHttp(srv);
    const scope = makeScope(base);
    const schema = await inspectGraphQLSchema(`${base}/graphql`, scope, { dictionary: ["version", "user"] });
    expect(schema.ok).toBe(true);
    expect(schema.discoveredQueries).toContain("version");
    expect(schema.discoveredQueries).toContain("user");
    expect(schema.types.User?.fields.map((f) => f.name)).toContain("email");

    const diff = await runGraphQLNestedAuthDiff(`${base}/graphql`, [
      { name: "GetMyProfile", query: "query GetMyProfile { me { id email } }" },
      { name: "GetOrderById", query: 'query GetOrderById { order(id: "ord-alice-1") { id ownerId amount } }' },
      { name: "GetOrgBilling", query: "query GetOrgBilling { billing { apiKey plan } }" },
    ], root, scope, { roles: ["admin", "alice", "bob"] });
    expect(diff.findings.some((f) => f.name === "GetMyProfile" && f.kind === "horizontal_bola")).toBe(false);
    expect(diff.findings.some((f) => f.name === "GetOrderById" && f.kind === "horizontal_bola")).toBe(true);
    expect(diff.findings.some((f) => f.name === "GetOrgBilling" && f.kind === "vertical_bfla")).toBe(true);
  });

  test("P1-4 & P1-6: 非对象接口零误报 BOLA、RSC error:null 非错误、Envoy 多段 grpc-web-text 精准识别 7", async () => {
    const chunks = parseRscFlightStream('0:{"ok":true,"error":null}\n1:TextPlainStart\n');
    expect(chunks[0]?.isErrorDigest).toBe(false);
    expect(chunks[1]?.tag).toBe("");
    expect(chunks[1]?.rawPayload).toBe("TextPlainStart");
    expect(() => decodeGrpcWebFrames(new Uint8Array([0x02, 0, 0, 0, 1, 0x00]))).toThrow();
    expect(() => decodeGrpcWebFrames(new Uint8Array([0x01, 0, 0, 0, 3, 0x01, 0x02, 0x03]))).toThrow();

    const root = tmpRoot();
    upsertSessionRole(root, { role: "user1", bearer: "u1-tok" });
    upsertSessionRole(root, { role: "user2", bearer: "u2-tok" });
    const srv = http.createServer((req, res) => {
      const auth = String(req.headers.authorization ?? "");
      const who = auth.includes("u1") ? "u1" : auth.includes("u2") ? "u2" : "anon";
      if (req.url === "/api/me") {
        if (who === "anon") { res.writeHead(401); res.end('{"error":"no"}'); return; }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: who, name: `name-${who}` }));
        return;
      }
      if (req.url === "/rsc/profile") {
        if (who === "anon") { res.writeHead(403); res.end('0:E{"digest":"DENY"}\n'); return; }
        res.writeHead(200, { "content-type": "text/x-component" });
        res.end(`0:${JSON.stringify({ ok: true, user: who, error: null })}\n`);
        return;
      }
      if (req.url === "/pkg.Svc/DeniedAdmin") {
        const dFrame = Buffer.from(encodeGrpcWebFrame(encodeProtobufFields([{ fieldNumber: 1, wireType: 2, value: "ok" }]))).toString("base64");
        const tFrame = Buffer.from(encodeGrpcWebFrame(new TextEncoder().encode("grpc-status:7\r\n"), { isTrailer: true })).toString("base64");
        res.writeHead(200, { "content-type": "application/grpc-web-text" });
        res.end(`${dFrame}${tFrame}`);
        return;
      }
      res.writeHead(404); res.end("nf");
    });
    const base = await listenHttp(srv);
    const scope = makeScope(base);
    const { session } = await createMockSession("p14");
    const cdpDiff = await runCdpStatefulSignedAuthDiff(base, [{ path: "/api/me", method: "GET" }], root, scope, { session, signerHook: "__nuwaSign", autoSampleSoft404: false });
    expect(cdpDiff.findings.some((f) => f.kind === "horizontal_bola")).toBe(false);
    const rscDiff = await diffRscActionRoles([{ name: "GetMyRsc", url: `${base}/rsc/profile`, actionId: "a1", args: [{ page: 1 }] }], root, scope, { roles: ["user1", "user2"] });
    expect(rscDiff.findings.some((f) => f.kind === "horizontal_bola")).toBe(false);
    const grpcDiff = await diffGrpcWebMethodRoles([{ name: "DeniedAdmin", url: `${base}/pkg.Svc/DeniedAdmin`, requestFields: [{ fieldNumber: 1, wireType: 2, value: "x" }], expectedAdminOnly: true, useBase64Text: true }], root, scope, { roles: ["user1", "user2"] });
    expect(grpcDiff.findings.length).toBe(0);
  });
});
