// nuwa B 层靶场：单文件 HTTP 服务，多模式覆盖不同响应类型。
// 所有请求写 /logs/access.jsonl，供压力测试后做时序与路径分析。
const http = require("http");
const fs = require("fs");
const zlib = require("zlib");

const MODE = process.env.MODE || "static";
const FLAG = process.env.FLAG || "flag{nuwa-default}";
const DELAY = Number(process.env.DELAY_MS || 0);
const PORT = Number(process.env.PORT || 8000);
const LOG = process.env.LOG || "/logs/access.jsonl";
const REALM = process.env.REALM || "nuwa";

function record(req, extra) {
  const rec = {
    ts: Date.now(),
    ip: (req.socket.remoteAddress || "").replace(/^::ffff:/, ""),
    method: req.method,
    url: req.url,
    ua: req.headers["user-agent"] || "",
    ...extra,
  };
  try {
    fs.appendFileSync(LOG, JSON.stringify(rec) + "\n");
  } catch {}
}

const server = http.createServer((req, res) => {
  record(req, { mode: MODE });

  // 统一的健康检查：永远 200，不做业务处理
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, mode: MODE }));
    return;
  }

  if (MODE === "deny") {
    res.writeHead(403, { "content-type": "text/plain" });
    res.end("forbidden\n");
    return;
  }

  if (MODE === "basicauth") {
    const auth = req.headers["authorization"] || "";
    const expect = "Basic " + Buffer.from("admin:admin").toString("base64");
    if (auth !== expect) {
      res.writeHead(401, {
        "content-type": "text/plain",
        "www-authenticate": `Basic realm="${REALM}"`,
      });
      res.end("unauthorized\n");
      return;
    }
  }

  if (MODE === "redirect") {
    // 故意做成两跳循环，测试工具的跟随与超时
    const target = req.url.startsWith("/a") ? "/b" : "/a";
    res.writeHead(302, { location: target });
    res.end();
    return;
  }

  if (MODE === "notfound") {
    res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
    res.end("<html><body><h1>404</h1><p>nothing here</p></body></html>");
    return;
  }

  const send = () => {
    if (req.url === "/flag") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(FLAG + "\n");
      return;
    }
    if (MODE === "echo") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        method: req.method,
        url: req.url,
        headers: req.headers,
        ua: req.headers["user-agent"] || "",
      }));
      return;
    }
    const body =
      `<html><body><h1>nuwa target</h1>` +
      `<p>mode: ${MODE}</p><p>path: ${req.url}</p>` +
      `<p>hint: try /flag</p></body></html>`;
    if (MODE === "gzip") {
      const buf = zlib.gzipSync(Buffer.from(body));
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-encoding": "gzip",
        "content-length": String(buf.length),
      });
      res.end(buf);
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(body);
  };

  if (DELAY > 0) setTimeout(send, DELAY);
  else send();
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[nuwa-target] mode=${MODE} port=${PORT} delay=${DELAY}ms`);
});
