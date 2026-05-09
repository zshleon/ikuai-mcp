#!/usr/bin/env node
/**
 * iKuai Router MCP Server — 动态全量覆盖版
 * 自动支持基于 OpenAPI 规范提取的所有 API（400+ 个）
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import crypto from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── 配置 ────────────────────────────────────────────────────────────────────
const HOST = process.env.IKUAI_HOST || "192.168.1.1";
const STATIC_TOKEN = process.env.IKUAI_TOKEN || "";
const SCHEME = (process.env.IKUAI_SCHEME || (STATIC_TOKEN ? "https" : "http")).toLowerCase();
const PORT = process.env.IKUAI_PORT || (SCHEME === "https" ? "443" : "80");
const USERNAME = process.env.IKUAI_USER || "admin";
const PASSWORD = process.env.IKUAI_PASS || "";
const BASE = `${SCHEME}://${HOST}:${PORT}`;
const API = `${BASE}/api/v4.0`;
const INSECURE_TLS = (process.env.IKUAI_INSECURE_TLS ?? "1") === "1";

if (SCHEME === "https" && INSECURE_TLS) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

let _token = STATIC_TOKEN || null;
let _tokenExp = STATIC_TOKEN ? Number.MAX_SAFE_INTEGER : 0;
const _isStatic = !!STATIC_TOKEN;

// ─── 认证 ─────────────────────────────────────────────────────────────────────
async function login() {
  if (_isStatic) {
    _token = STATIC_TOKEN;
    _tokenExp = Number.MAX_SAFE_INTEGER;
    return;
  }
  const md5 = crypto.createHash("md5").update(PASSWORD).digest("hex");
  try {
    const r = await fetch(`${API}/system/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: USERNAME, password: md5 }),
    });
    const d = await r.json();
    if (d.token || d.data?.token) {
      _token = d.token ?? d.data.token;
      _tokenExp = Date.now() + 3500 * 1000;
      return;
    }
  } catch (_) {}
  
  const r2 = await fetch(`${BASE}/Action/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: USERNAME, passwd: md5, pass: PASSWORD }),
  });
  const d2 = await r2.json();
  if (d2.Result !== 10000 && !d2.token)
    throw new Error(`登录失败: ${JSON.stringify(d2)}`);
  _token = d2.token ?? d2.data?.token ?? "session";
  _tokenExp = Date.now() + 3500 * 1000;
}

async function req(method, reqPath, body) {
  if (!_token || Date.now() > _tokenExp) await login();
  const opts = {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${_token}` },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(`${API}${reqPath}`, opts);
  if (r.status === 401 && !_isStatic) { _token = null; return req(method, reqPath, body); }
  const text = await r.text();
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

// ─── 工具加载与动态路由 ──────────────────────────────────────────────────────
const toolsDefPath = path.join(__dirname, "tools.json");
const TOOLS_DEFS = JSON.parse(fs.readFileSync(toolsDefPath, "utf-8"));

const FULL_TOOLS = TOOLS_DEFS.map(t => {
  const { _meta, ...mcpTool } = t;
  return mcpTool;
});

const TOOL_META = Object.fromEntries(TOOLS_DEFS.map(t => [t.name, t._meta]));
const TOOL_DEF_BY_NAME = Object.fromEntries(TOOLS_DEFS.map(t => [t.name, t]));
const MODE = (process.env.IKUAI_MCP_MODE || "compact").toLowerCase();
const COMPACT_LIMIT = Number(process.env.IKUAI_MCP_COMPACT_LIMIT || "60");
const COMPACT_KEYWORDS = [
  "client", "host", "online", "interface", "ifstat", "wan", "lan", "dhcp",
  "lease", "monitor", "traffic", "flow", "rate", "sysstat", "system", "dns",
  "nat", "static", "route", "acl", "pppoe", "arp", "gateway", "connect", "status"
];

function toolHaystack(tool) {
  const meta = TOOL_META[tool.name] || {};
  return [tool.name, tool.description, meta.path, meta.method].filter(Boolean).join(" ").toLowerCase();
}

function isCompactDirectTool(tool) {
  const meta = TOOL_META[tool.name] || {};
  if (String(meta.method || "").toLowerCase() !== "get") return false;
  const haystack = toolHaystack(tool);
  const risky = ["backup", "restore", "upgrade", "reboot", "delete", "format", "reset"];
  if (risky.some(keyword => haystack.includes(keyword))) return false;
  return COMPACT_KEYWORDS.some(keyword => haystack.includes(keyword));
}

const DIRECT_TOOLS = MODE === "full"
  ? FULL_TOOLS
  : FULL_TOOLS.filter(isCompactDirectTool).slice(0, Number.isFinite(COMPACT_LIMIT) ? COMPACT_LIMIT : 60);

const VIRTUAL_TOOLS = [
  {
    name: "ikuai_list_api_tools",
    description: "Search/list all iKuai API tools without exposing every endpoint as a separate MCP tool. Use this first when you need an iKuai capability that is not in the compact direct tool list.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Keyword to search in tool name, description, method, or API path. Empty returns the first results." },
        limit: { type: "number", description: "Maximum results to return. Default 30, max 100." }
      }
    }
  },
  {
    name: "ikuai_call_api",
    description: "Call any iKuai API endpoint. Prefer the 'tool' form after using ikuai_list_api_tools; use method/path only when you know the endpoint.",
    inputSchema: {
      type: "object",
      properties: {
        tool: { type: "string", description: "Existing generated tool name from tools.json, for example getSystemBasicConfig." },
        arguments: { type: "object", description: "Arguments for the named tool, including path/query/body fields when required." },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE", "get", "post", "put", "patch", "delete"] },
        path: { type: "string", description: "API path under /api/v4.0, for example /system/basic/config." },
        query: { type: "object", description: "Query string parameters for method/path calls." },
        body: { description: "JSON body for POST/PUT/PATCH method/path calls." }
      }
    }
  }
];

const TOOLS = [...VIRTUAL_TOOLS, ...DIRECT_TOOLS];

async function handle(name, args) {
  const meta = TOOL_META[name];
  if (!meta) throw new Error(`未知工具: ${name}`);
  
  let reqPath = meta.path;
  const query = {};
  
  // 处理 Path Params
  for (const param of meta.pathParams) {
    if (args[param] === undefined) throw new Error(`缺少路径参数: ${param}`);
    reqPath = reqPath.replace(`{${param}}`, encodeURIComponent(args[param]));
    delete args[param];
  }
  
  // 处理 Query Params
  for (const param of meta.queryParams) {
    if (args[param] !== undefined) {
      query[param] = args[param];
      delete args[param];
    }
  }
  const qs = new URLSearchParams(query).toString();
  const finalPath = qs ? `${reqPath}?${qs}` : reqPath;
  
  // GET 和 DELETE 不带 body
  if (['get', 'delete'].includes(meta.method)) {
     return req(meta.method.toUpperCase(), finalPath);
  }
  
  // POST/PUT/PATCH 处理 body
  // 如果 OpenAPI 指定了 body 对象，它会被展平传入 args（如果 body 不是对象，我们在生成时包了一层 'body'）
  let bodyPayload = undefined;
  if (meta.hasBody && Object.keys(args).length > 0) {
      bodyPayload = args.body !== undefined && Object.keys(args).length === 1 ? args.body : args;
  } else if (meta.hasBody) {
      bodyPayload = {}; // 允许空的 body 对象
  }
  
  return req(meta.method.toUpperCase(), finalPath, bodyPayload);
}

// ─── MCP Server 启动 ─────────────────────────────────────────────────────────
const server = new Server(
  { name: "ikuai-mcp", version: "3.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    if (name === "ikuai_list_api_tools") {
      const query = String((args || {}).query || "").toLowerCase();
      const limitRaw = Number((args || {}).limit || 30);
      const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? limitRaw : 30, 1), 100);
      const matches = FULL_TOOLS
        .filter(tool => !query || toolHaystack(tool).includes(query))
        .slice(0, limit)
        .map(tool => {
          const meta = TOOL_META[tool.name] || {};
          return {
            name: tool.name,
            method: meta.method,
            path: meta.path,
            description: tool.description,
            pathParams: meta.pathParams || [],
            queryParams: meta.queryParams || [],
            hasBody: !!meta.hasBody,
          };
        });
      return { content: [{ type: "text", text: JSON.stringify({ totalAvailable: FULL_TOOLS.length, returned: matches.length, results: matches }, null, 2) }] };
    }

    if (name === "ikuai_call_api") {
      const callArgs = args || {};
      if (callArgs.tool) {
        if (!TOOL_DEF_BY_NAME[callArgs.tool]) throw new Error(`未知工具: ${callArgs.tool}`);
        const toolArgs = callArgs.arguments || callArgs.params || {};
        const result = await handle(callArgs.tool, { ...toolArgs });
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      const method = String(callArgs.method || "GET").toUpperCase();
      const allowedMethods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
      if (!allowedMethods.has(method)) throw new Error(`不支持的 HTTP 方法: ${method}`);
      let reqPath = String(callArgs.path || "");
      if (!reqPath.startsWith("/")) throw new Error("path 必须以 / 开头，例如 /system/basic/config");
      if (reqPath.startsWith("/api/v4.0/")) reqPath = reqPath.slice("/api/v4.0".length);
      const qs = new URLSearchParams(callArgs.query || {}).toString();
      const finalPath = qs ? `${reqPath}?${qs}` : reqPath;
      const result = await req(method, finalPath, ["GET", "DELETE"].includes(method) ? undefined : callArgs.body);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    }

    const result = await handle(name, args || {});
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return {
      content: [{ type: "text", text: `错误: ${err.message}` }],
      isError: true,
    };
  }
});

await server.connect(new StdioServerTransport());
console.error(`iKuai MCP Server v3.1 已启动 (mode=${MODE}, exposed=${TOOLS.length}/${FULL_TOOLS.length}) — ${BASE}`);
