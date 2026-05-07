#!/usr/bin/env node
/**
 * iKuai Router MCP Server — 完整版
 * 覆盖爱快4.0全部40个API模块的所有操作
 *
 * 环境变量:
 *   IKUAI_HOST    路由器IP，默认 192.168.1.1
 *   IKUAI_USER    用户名，默认 admin
 *   IKUAI_PASS    密码（明文，自动MD5加密）
 *   IKUAI_PORT    端口，默认随scheme（http=80, https=443）
 *   IKUAI_SCHEME  http 或 https。默认 http；传 IKUAI_TOKEN 时强制 https
 *   IKUAI_TOKEN   爱快 4.0 Open API 静态令牌。设置后跳过登录、直接以
 *                 Authorization: Bearer <TOKEN> 调用 /api/v4.0/*（需HTTPS）
 *   IKUAI_INSECURE_TLS  设为 1 时忽略自签证书校验（默认忽略）
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import crypto from "crypto";

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

// 自签证书的iKuai管理面板默认走HTTPS需要忽略校验
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
  // 尝试4.0接口
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
  // 回退旧接口
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

async function req(method, path, body) {
  if (!_token || Date.now() > _tokenExp) await login();
  const opts = {
    method,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${_token}` },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(`${API}${path}`, opts);
  if (r.status === 401 && !_isStatic) { _token = null; return req(method, path, body); }
  const text = await r.text();
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

const GET    = (p)    => req("GET",    p);
const POST   = (p, b) => req("POST",   p, b);
const PUT    = (p, b) => req("PUT",    p, b);
const PATCH  = (p, b) => req("PATCH",  p, b);
const DELETE = (p)    => req("DELETE", p);

// ─── 工具定义 ─────────────────────────────────────────────────────────────────
const TOOLS = [

  // ══════════════════════════════════════════════════════════════
  // 1. 监控类
  // ══════════════════════════════════════════════════════════════
  {
    name: "monitor_clients_online",
    description: "获取当前IPv4在线终端列表。支持按mac/ip/设备名/厂商模糊搜索，支持精确过滤（如 client_vendor:Apple）。返回每个终端的IP、MAC、上下行速率、连接时长、厂商型号等。",
    inputSchema: {
      type: "object",
      properties: {
        key:     { type: "string", description: "模糊搜索字段: ssid|mac|ip_addr|termname|client_vendor|client_model" },
        pattern: { type: "string", description: "模糊搜索内容" },
        filter:  { type: "string", description: "精确过滤，如 client_vendor:Apple 或 interface==lan1" },
      },
    },
  },
  {
    name: "monitor_clients_online_ipv6",
    description: "获取当前IPv6在线终端列表。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_clients_offline",
    description: "获取曾经连接过但当前离线的IPv4终端历史记录。",
    inputSchema: { type: "object", properties: { filter: { type: "string" } } },
  },
  {
    name: "monitor_client_traffic_today",
    description: "获取所有终端今日累计流量统计。可按IP或MAC过滤某个设备。",
    inputSchema: {
      type: "object",
      properties: { filter: { type: "string", description: "如 ip_addr==192.168.1.100 或 mac==AA:BB:CC:DD:EE:FF" } },
    },
  },
  {
    name: "monitor_client_traffic_realtime",
    description: "获取指定终端的5分钟实时流量负载曲线。需指定IP或MAC。",
    inputSchema: {
      type: "object",
      properties: { filter: { type: "string", description: "如 ip_addr==192.168.1.100" } },
      required: ["filter"],
    },
  },
  {
    name: "monitor_client_protocol_traffic",
    description: "获取指定终端的协议分类流量（微信/抖音/YouTube等分别占多少）。",
    inputSchema: {
      type: "object",
      properties: { filter: { type: "string", description: "如 ip_addr==192.168.1.100" } },
      required: ["filter"],
    },
  },
  {
    name: "monitor_client_app_speed",
    description: "获取指定终端当前各应用协议的实时速率。",
    inputSchema: {
      type: "object",
      properties: { filter: { type: "string" } },
      required: ["filter"],
    },
  },
  {
    name: "monitor_system_load",
    description: "获取路由器完整系统负载：CPU使用率、内存、磁盘、CPU温度、在线终端数、并发连接数、网络吞吐。一次调用返回所有数据。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_wan_status",
    description: "获取所有WAN口实时状态：连通性、IP地址、上下行速率、24小时流量曲线。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_interfaces_config",
    description: "获取所有内外网接口的配置信息（IP、子网掩码、接口类型等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_physical_nics",
    description: "获取物理网卡列表（网卡名称、驱动、链路状态等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_app_protocols_summary",
    description: "获取最近24小时全局应用协议流量统计（各协议用了多少流量）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_app_protocols_realtime",
    description: "获取当前各应用协议的实时速率。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_protocol_categories",
    description: "获取最近24小时协议分类流量汇总（P2P/视频/游戏/社交等大类）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_flow_shunting",
    description: "查询分流统计数据，了解各WAN口实际承载的流量分布。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "monitor_cameras",
    description: "获取摄像头设备列表（如路由器接入了摄像头监控）。",
    inputSchema: { type: "object", properties: {} },
  },

  // ══════════════════════════════════════════════════════════════
  // 2. 终端名称管理
  // ══════════════════════════════════════════════════════════════
  {
    name: "terminal_list",
    description: "获取所有已命名的终端设备列表（MAC→名称映射）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "terminal_rename",
    description: "为指定MAC地址的终端设置自定义名称，方便识别。",
    inputSchema: {
      type: "object",
      properties: {
        mac:     { type: "string", description: "设备MAC地址" },
        name:    { type: "string", description: "自定义名称，如'儿子的iPad'" },
        comment: { type: "string", description: "备注" },
      },
      required: ["mac", "name"],
    },
  },
  {
    name: "terminal_rename_update",
    description: "更新已有终端名称记录。",
    inputSchema: {
      type: "object",
      properties: {
        id:      { type: "string", description: "记录ID（从terminal_list获取）" },
        mac:     { type: "string" },
        name:    { type: "string" },
        comment: { type: "string" },
      },
      required: ["id", "mac", "name"],
    },
  },
  {
    name: "terminal_rename_delete",
    description: "删除终端名称记录。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 3. MAC限速 QoS
  // ══════════════════════════════════════════════════════════════
  {
    name: "qos_mac_list",
    description: "查看所有MAC限速规则。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "qos_mac_create",
    description: "为指定MAC地址设置上下行限速。upload/download单位为kbps，0表示不限。",
    inputSchema: {
      type: "object",
      properties: {
        mac_addr:      { type: "string", description: "设备MAC，如 AA:BB:CC:DD:EE:FF" },
        upload_kbps:   { type: "number", description: "上传限速(kbps)，1024=1Mbps" },
        download_kbps: { type: "number", description: "下载限速(kbps)，10240=10Mbps" },
        interface:     { type: "string", description: "WAN接口，如 wan1", default: "wan1" },
        comment:       { type: "string" },
        enabled:       { type: "boolean", default: true },
      },
      required: ["mac_addr", "upload_kbps", "download_kbps"],
    },
  },
  {
    name: "qos_mac_update",
    description: "更新已有MAC限速规则。",
    inputSchema: {
      type: "object",
      properties: {
        id:            { type: "string", description: "规则ID" },
        mac_addr:      { type: "string" },
        upload_kbps:   { type: "number" },
        download_kbps: { type: "number" },
        interface:     { type: "string" },
        comment:       { type: "string" },
        enabled:       { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "qos_mac_toggle",
    description: "启用或停用某条MAC限速规则。",
    inputSchema: {
      type: "object",
      properties: {
        id:      { type: "string" },
        enabled: { type: "boolean" },
      },
      required: ["id", "enabled"],
    },
  },
  {
    name: "qos_mac_delete",
    description: "删除MAC限速规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 4. 域名黑名单
  // ══════════════════════════════════════════════════════════════
  {
    name: "domain_blacklist_list",
    description: "查看所有域名黑名单规则。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "domain_blacklist_create",
    description: "添加域名黑名单策略，阻止内网访问指定域名组。",
    inputSchema: {
      type: "object",
      properties: {
        domain_group: { type: "string", description: "域名或域名组，如 ads.example.com" },
        src_addr:     { type: "string", description: "限制来源IP段，留空表示全部内网" },
        comment:      { type: "string" },
        enabled:      { type: "boolean", default: true },
      },
      required: ["domain_group"],
    },
  },
  {
    name: "domain_blacklist_update",
    description: "更新域名黑名单策略。",
    inputSchema: {
      type: "object",
      properties: {
        id:           { type: "string" },
        domain_group: { type: "string" },
        src_addr:     { type: "string" },
        comment:      { type: "string" },
        enabled:      { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "domain_blacklist_toggle",
    description: "启用或停用域名黑名单规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "domain_blacklist_delete",
    description: "删除域名黑名单规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 5. ACL访问控制
  // ══════════════════════════════════════════════════════════════
  {
    name: "acl_list",
    description: "查看所有ACL访问控制规则。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "acl_create",
    description: "创建ACL规则，精确控制内网设备的访问权限。可以按IP段、端口、协议允许或拒绝流量。",
    inputSchema: {
      type: "object",
      properties: {
        action:     { type: "string", enum: ["accept","drop"], description: "accept=允许 drop=拒绝" },
        src_addr:   { type: "string", description: "源IP或CIDR，如 192.168.1.100 或 192.168.1.0/24" },
        dst_addr:   { type: "string", description: "目的IP，留空=所有外网" },
        src_port:   { type: "string", description: "源端口，如 80 或 1024-2048" },
        dst_port:   { type: "string", description: "目的端口，如 443,80" },
        protocol:   { type: "string", enum: ["tcp","udp","icmp","all"], description: "协议，默认all" },
        iinterface: { type: "string", description: "入方向接口，如 lan1" },
        ointerface: { type: "string", description: "出方向接口，如 wan1" },
        ip_type:    { type: "string", enum: ["4","6"], description: "IP版本，默认4" },
        comment:    { type: "string" },
        enabled:    { type: "boolean", default: true },
      },
      required: ["action", "src_addr"],
    },
  },
  {
    name: "acl_update",
    description: "更新ACL规则。",
    inputSchema: {
      type: "object",
      properties: {
        id:         { type: "string" },
        action:     { type: "string", enum: ["accept","drop"] },
        src_addr:   { type: "string" },
        dst_addr:   { type: "string" },
        src_port:   { type: "string" },
        dst_port:   { type: "string" },
        protocol:   { type: "string" },
        iinterface: { type: "string" },
        ointerface: { type: "string" },
        comment:    { type: "string" },
        enabled:    { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "acl_toggle",
    description: "启用或停用ACL规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "acl_delete",
    description: "删除ACL规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 6. MAC黑白名单
  // ══════════════════════════════════════════════════════════════
  {
    name: "mac_acl_get_mode",
    description: "获取当前MAC黑白名单模式（whitelist=只允许白名单设备，blacklist=只拦截黑名单设备）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "mac_acl_set_mode",
    description: "设置MAC黑白名单模式。whitelist模式下只有白名单内的MAC才能上网。",
    inputSchema: {
      type: "object",
      properties: {
        mode: { type: "string", enum: ["whitelist","blacklist","none"], description: "none=关闭" },
      },
      required: ["mode"],
    },
  },
  {
    name: "mac_acl_list",
    description: "获取MAC黑白名单规则列表。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "mac_acl_create",
    description: "添加MAC到黑/白名单。",
    inputSchema: {
      type: "object",
      properties: {
        mac:      { type: "string", description: "设备MAC地址" },
        name:     { type: "string", description: "设备备注名称" },
        comment:  { type: "string" },
        enabled:  { type: "boolean", default: true },
        expires:  { type: "string", description: "过期时间，留空永久" },
      },
      required: ["mac"],
    },
  },
  {
    name: "mac_acl_toggle",
    description: "启用或停用MAC黑白名单规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "mac_acl_delete",
    description: "从黑/白名单中删除设备。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 7. 应用协议控制
  // ══════════════════════════════════════════════════════════════
  {
    name: "app_proto_control_list",
    description: "查看应用协议控制策略（哪些协议被限速或封禁）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "app_proto_control_create",
    description: "创建应用协议控制策略，可以允许/拒绝/限速特定应用（如封禁BT下载、限制抖音）。",
    inputSchema: {
      type: "object",
      properties: {
        action:    { type: "string", enum: ["accept","drop","limit"], description: "allow/拒绝/限速" },
        app_proto: { type: "string", description: "应用协议名称，如 bt、douyin、youtube" },
        src_addr:  { type: "string", description: "来源IP段，留空=全部" },
        dst_addr:  { type: "string", description: "目标IP段，留空=全部" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["action", "app_proto"],
    },
  },
  {
    name: "app_proto_control_toggle",
    description: "启用或停用应用协议控制策略。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "app_proto_control_delete",
    description: "删除应用协议控制策略。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 8. DHCP管理
  // ══════════════════════════════════════════════════════════════
  {
    name: "dhcp_clients_list",
    description: "获取当前所有DHCP客户端租约列表（获取了IP的设备）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dhcp_static_list",
    description: "查看所有DHCP静态IP绑定（MAC→固定IP映射）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dhcp_static_create",
    description: "为指定MAC地址绑定固定IP，让设备每次获得相同IP。",
    inputSchema: {
      type: "object",
      properties: {
        mac:       { type: "string", description: "设备MAC地址" },
        ip_addr:   { type: "string", description: "要绑定的固定IP，如 192.168.1.50" },
        hostname:  { type: "string", description: "主机名" },
        interface: { type: "string", description: "所属LAN接口，默认 lan1" },
        gateway:   { type: "string", description: "自定义网关，留空使用默认" },
        dns1:      { type: "string", description: "自定义DNS1" },
        dns2:      { type: "string", description: "自定义DNS2" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["mac", "ip_addr"],
    },
  },
  {
    name: "dhcp_static_update",
    description: "更新DHCP静态绑定。",
    inputSchema: {
      type: "object",
      properties: {
        id:        { type: "string" },
        mac:       { type: "string" },
        ip_addr:   { type: "string" },
        hostname:  { type: "string" },
        interface: { type: "string" },
        gateway:   { type: "string" },
        dns1:      { type: "string" },
        dns2:      { type: "string" },
        comment:   { type: "string" },
        enabled:   { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "dhcp_static_toggle",
    description: "启用或停用DHCP静态绑定。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "dhcp_static_delete",
    description: "删除DHCP静态IP绑定。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "dhcp_access_mode_get",
    description: "获取DHCP访问控制模式（白名单/黑名单/关闭）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dhcp_access_mode_set",
    description: "设置DHCP访问控制模式。whitelist模式下只有名单内的MAC才能获取IP。",
    inputSchema: {
      type: "object",
      properties: { mode: { type: "string", enum: ["whitelist","blacklist","none"] } },
      required: ["mode"],
    },
  },
  {
    name: "dhcp_access_rules_list",
    description: "查看DHCP访问控制规则（允许/拒绝获取IP的MAC列表）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dhcp_access_rule_create",
    description: "添加DHCP访问控制规则（允许或拒绝某MAC获取IP）。",
    inputSchema: {
      type: "object",
      properties: {
        mac:     { type: "string" },
        name:    { type: "string" },
        comment: { type: "string" },
        enabled: { type: "boolean", default: true },
      },
      required: ["mac"],
    },
  },
  {
    name: "dhcp_access_rule_delete",
    description: "删除DHCP访问控制规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "dhcp_services_list",
    description: "查看所有DHCP服务策略（各LAN接口的地址池配置）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dhcp_service_update",
    description: "更新DHCP服务策略（修改地址池范围、DNS、网关等）。",
    inputSchema: {
      type: "object",
      properties: {
        id:        { type: "string" },
        addr_pool: { type: "string", description: "地址池范围，如 192.168.1.100-192.168.1.200" },
        netmask:   { type: "string", description: "子网掩码，如 255.255.255.0" },
        gateway:   { type: "string", description: "网关IP" },
        dns1:      { type: "string" },
        dns2:      { type: "string" },
        lease:     { type: "number", description: "租约时间（秒）" },
        enabled:   { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "dhcp_service_restart",
    description: "重启DHCP服务（修改配置后生效）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dhcp_log_list",
    description: "查看DHCP日志（设备获取IP的记录）。",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", default: 50 } },
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 9. DNS管理
  // ══════════════════════════════════════════════════════════════
  {
    name: "dns_config_get",
    description: "获取DNS服务配置（上游DNS、缓存设置等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dns_config_update",
    description: "更新DNS配置，可修改上游DNS服务器、缓存TTL等。",
    inputSchema: {
      type: "object",
      properties: {
        dns1:        { type: "string", description: "主DNS，如 119.29.29.29" },
        dns2:        { type: "string", description: "备DNS，如 223.5.5.5" },
        cache_ttl:   { type: "number", description: "缓存TTL（秒）" },
        enabled:     { type: "boolean" },
        proxy_force: { type: "boolean", description: "强制代理所有DNS查询" },
      },
    },
  },
  {
    name: "dns_stats_get",
    description: "获取DNS缓存状态（命中率、缓存条目数等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dns_proxy_rules_list",
    description: "查看DNS代理规则（特定域名走指定DNS）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dns_proxy_rule_create",
    description: "添加DNS代理规则，让指定域名走特定DNS服务器解析。",
    inputSchema: {
      type: "object",
      properties: {
        domain:     { type: "string", description: "域名，如 google.com" },
        dns_addr:   { type: "string", description: "指定DNS，如 8.8.8.8" },
        src_addr:   { type: "string", description: "来源IP段，留空=全部" },
        is_ipv6:    { type: "boolean", description: "是否IPv6 DNS" },
        comment:    { type: "string" },
        enabled:    { type: "boolean", default: true },
      },
      required: ["domain", "dns_addr"],
    },
  },
  {
    name: "dns_proxy_rule_toggle",
    description: "启用或停用DNS代理规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "dns_proxy_rule_delete",
    description: "删除DNS代理规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "dns_multi_rules_list",
    description: "查看多线DNS策略（不同WAN口使用不同DNS）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dns_multi_rule_create",
    description: "添加多线DNS策略，为指定WAN接口设置专属DNS。",
    inputSchema: {
      type: "object",
      properties: {
        interface: { type: "string", description: "WAN接口，如 wan1" },
        dns1:      { type: "string" },
        dns2:      { type: "string" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["interface", "dns1"],
    },
  },
  {
    name: "dns_multi_rule_delete",
    description: "删除多线DNS策略。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 10. 端口映射 DNAT
  // ══════════════════════════════════════════════════════════════
  {
    name: "dnat_list",
    description: "查看所有端口映射规则（DNAT/端口转发）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "dnat_create",
    description: "添加端口映射规则，将外网端口转发到内网服务器。",
    inputSchema: {
      type: "object",
      properties: {
        wan_port:   { type: "string", description: "外网端口，如 8080 或 8080-8090" },
        lan_addr:   { type: "string", description: "内网目标IP，如 192.168.1.100" },
        lan_port:   { type: "string", description: "内网目标端口，如 80" },
        protocol:   { type: "string", enum: ["tcp","udp","tcp/udp"], default: "tcp" },
        interface:  { type: "string", description: "WAN接口，如 wan1，留空=所有WAN" },
        src_addr:   { type: "string", description: "限制来源IP，留空=所有" },
        comment:    { type: "string" },
        enabled:    { type: "boolean", default: true },
      },
      required: ["wan_port", "lan_addr", "lan_port"],
    },
  },
  {
    name: "dnat_update",
    description: "更新端口映射规则。",
    inputSchema: {
      type: "object",
      properties: {
        id:        { type: "string" },
        wan_port:  { type: "string" },
        lan_addr:  { type: "string" },
        lan_port:  { type: "string" },
        protocol:  { type: "string" },
        interface: { type: "string" },
        comment:   { type: "string" },
        enabled:   { type: "boolean" },
      },
      required: ["id"],
    },
  },
  {
    name: "dnat_toggle",
    description: "启用或停用端口映射规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "dnat_delete",
    description: "删除端口映射规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 11. NAT规则
  // ══════════════════════════════════════════════════════════════
  {
    name: "nat_rules_list",
    description: "查看NAT策略规则列表（源NAT/目的NAT等高级NAT策略）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "nat_rule_create",
    description: "创建NAT规则（高级NAT策略，如SNAT指定出口IP）。",
    inputSchema: {
      type: "object",
      properties: {
        action:     { type: "string", enum: ["snat","dnat","masquerade"] },
        iinterface: { type: "string", description: "入接口" },
        ointerface: { type: "string", description: "出接口" },
        src_addr:   { type: "string", description: "源IP段" },
        dst_addr:   { type: "string", description: "目的IP段" },
        nat_addr:   { type: "string", description: "NAT后的地址" },
        nat_port:   { type: "string", description: "NAT后的端口" },
        protocol:   { type: "string" },
        comment:    { type: "string" },
        enabled:    { type: "boolean", default: true },
      },
      required: ["action"],
    },
  },
  {
    name: "nat_rule_toggle",
    description: "启用或停用NAT规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "nat_rule_delete",
    description: "删除NAT规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 12. 路由分流
  // ══════════════════════════════════════════════════════════════
  {
    name: "route_domain_list",
    description: "查看域名分流策略（指定域名走哪个WAN）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "route_domain_create",
    description: "添加域名分流策略，让指定域名的流量走特定WAN口出。",
    inputSchema: {
      type: "object",
      properties: {
        domain:    { type: "string", description: "域名，如 netflix.com" },
        interface: { type: "string", description: "出口WAN，如 wan1 或 wan2" },
        src_addr:  { type: "string", description: "仅对指定来源IP生效，留空=全部" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["domain", "interface"],
    },
  },
  {
    name: "route_domain_toggle",
    description: "启用或停用域名分流规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "route_domain_delete",
    description: "删除域名分流规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "route_protocol_list",
    description: "查看协议分流策略（某应用协议走哪个WAN）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "route_protocol_create",
    description: "添加协议分流策略，让特定应用流量走指定WAN（如游戏走低延迟WAN）。",
    inputSchema: {
      type: "object",
      properties: {
        app_proto: { type: "string", description: "应用协议名称，如 game、video" },
        interface: { type: "string", description: "出口WAN" },
        src_addr:  { type: "string", description: "来源IP段，留空=全部" },
        mode:      { type: "string", description: "分流模式" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["app_proto", "interface"],
    },
  },
  {
    name: "route_protocol_toggle",
    description: "启用或停用协议分流规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "route_protocol_delete",
    description: "删除协议分流规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "route_fivetuple_list",
    description: "查看五元组端口分流策略（按源IP/目的IP/端口/协议精细分流）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "route_fivetuple_create",
    description: "添加五元组分流策略，可精确控制某个IP的某个端口走哪个WAN出。",
    inputSchema: {
      type: "object",
      properties: {
        interface: { type: "string", description: "出口WAN" },
        src_addr:  { type: "string", description: "源IP段" },
        dst_addr:  { type: "string", description: "目的IP段" },
        protocol:  { type: "string", description: "协议 tcp/udp/all" },
        src_port:  { type: "string", description: "源端口" },
        dst_port:  { type: "string", description: "目的端口，如 80,443" },
        mode:      { type: "string" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["interface"],
    },
  },
  {
    name: "route_fivetuple_toggle",
    description: "启用或停用五元组分流规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "route_fivetuple_delete",
    description: "删除五元组分流规则。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "route_static_list",
    description: "查看静态路由策略。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "route_static_create",
    description: "添加静态路由，将某个目标网段的流量指向指定网关。",
    inputSchema: {
      type: "object",
      properties: {
        dst_addr:  { type: "string", description: "目标网段，如 10.0.0.0/8" },
        gateway:   { type: "string", description: "下一跳网关IP" },
        interface: { type: "string", description: "出口接口" },
        comment:   { type: "string" },
        enabled:   { type: "boolean", default: true },
      },
      required: ["dst_addr", "gateway"],
    },
  },
  {
    name: "route_static_toggle",
    description: "启用或停用静态路由。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, enabled: { type: "boolean" } },
      required: ["id", "enabled"],
    },
  },
  {
    name: "route_static_delete",
    description: "删除静态路由。",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 13. WAN / LAN 接口
  // ══════════════════════════════════════════════════════════════
  {
    name: "wan_config_list",
    description: "查看所有WAN接口配置（IP、拨号方式、带宽上限等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "wan_config_update",
    description: "更新WAN接口配置（如修改带宽上限）。",
    inputSchema: {
      type: "object",
      properties: {
        id:      { type: "string", description: "WAN接口ID" },
        comment: { type: "string" },
      },
      required: ["id"],
    },
  },
  {
    name: "lan_config_list",
    description: "查看所有LAN接口配置。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "lan_config_update",
    description: "更新LAN接口配置（IP、子网掩码等）。",
    inputSchema: {
      type: "object",
      properties: {
        id:      { type: "string" },
        ip_mask: { type: "string", description: "IP/掩码，如 192.168.1.1/24" },
        comment: { type: "string" },
      },
      required: ["id"],
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 14. 系统管理
  // ══════════════════════════════════════════════════════════════
  {
    name: "system_basic_get",
    description: "获取系统基础设置（主机名、时区、NTP、NAT开关等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_basic_update",
    description: "更新系统基础设置。",
    inputSchema: {
      type: "object",
      properties: {
        hostname:   { type: "string", description: "路由器主机名" },
        time_zone:  { type: "string", description: "时区，如 Asia/Shanghai" },
        switch_ntp: { type: "string", description: "NTP开关 on/off" },
        fast_nat:   { type: "boolean", description: "快速NAT开关" },
      },
    },
  },
  {
    name: "system_ntp_sync",
    description: "立即执行NTP时间同步。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_backup_info",
    description: "查看备份信息（上次备份时间、备份文件列表）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_backup_create",
    description: "立即创建配置备份。建议在任何变更操作前执行。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_backup_auto_get",
    description: "查看自动备份策略配置。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_backup_auto_update",
    description: "配置自动备份策略（备份频率、保留天数等）。",
    inputSchema: {
      type: "object",
      properties: {
        enabled:    { type: "boolean" },
        strategy:   { type: "string", description: "备份策略" },
        time:       { type: "string", description: "执行时间，如 03:00" },
        valid_days: { type: "number", description: "保留天数" },
      },
    },
  },
  {
    name: "firmware_check",
    description: "检查是否有新固件版本可用。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "firmware_info",
    description: "获取当前固件版本信息。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_cpu_freq_get",
    description: "获取CPU当前实时频率。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_cpu_mode_get",
    description: "获取CPU工作模式（performance/powersave等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_cpu_mode_set",
    description: "设置CPU工作模式。performance=性能优先，powersave=节能。",
    inputSchema: {
      type: "object",
      properties: {
        mode:  { type: "string", enum: ["performance","powersave","ondemand","schedutil"] },
        turbo: { type: "boolean", description: "是否开启睿频" },
      },
      required: ["mode"],
    },
  },
  {
    name: "system_disks_info",
    description: "获取系统磁盘信息（容量、使用率等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_remote_access_get",
    description: "获取远程访问配置（SSH/Telnet/WebUI远程访问开关和端口）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_remote_access_update",
    description: "更新远程访问配置（开启/关闭SSH，修改端口等）。",
    inputSchema: {
      type: "object",
      properties: {
        open_sshd:    { type: "boolean", description: "开启SSH" },
        sshd_port:    { type: "number", description: "SSH端口，默认22" },
        open_wanweb:  { type: "boolean", description: "开启WAN侧WebUI访问" },
        http_port:    { type: "number", description: "HTTP端口" },
        https_port:   { type: "number", description: "HTTPS端口" },
        force_https:  { type: "boolean", description: "强制HTTPS" },
        open_telnetd: { type: "boolean", description: "开启Telnet（不建议）" },
      },
    },
  },
  {
    name: "system_kernel_params_get",
    description: "获取内核网络参数（连接超时、TCP优化参数等）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "system_kernel_params_update",
    description: "更新内核网络参数，可优化TCP连接超时、开启BBR等。",
    inputSchema: {
      type: "object",
      properties: {
        bbr:                  { type: "boolean", description: "开启BBR拥塞控制" },
        established_timeout:  { type: "number", description: "TCP established超时（秒）" },
        time_wait_timeout:    { type: "number", description: "TIME_WAIT超时（秒）" },
        udp_timeout:          { type: "number", description: "UDP超时（秒）" },
      },
    },
  },
  {
    name: "alg_config_get",
    description: "获取ALG（应用层网关）配置，如FTP/SIP/H.323穿透支持。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "alg_config_update",
    description: "更新ALG配置，开启/关闭FTP/SIP/TFTP等协议的NAT穿透。",
    inputSchema: {
      type: "object",
      properties: {
        support_ftp:  { type: "boolean" },
        support_sip:  { type: "boolean" },
        support_h323: { type: "boolean" },
        support_tftp: { type: "boolean" },
        ftp_ports:    { type: "string", description: "FTP数据端口，默认21" },
        sip_ports:    { type: "string", description: "SIP端口，默认5060" },
      },
    },
  },
  {
    name: "snmp_config_get",
    description: "获取SNMP服务配置。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "snmp_config_update",
    description: "更新SNMP服务配置（开启SNMP监控、设置community等）。",
    inputSchema: {
      type: "object",
      properties: {
        enabled:     { type: "boolean" },
        listen_port: { type: "number", description: "SNMP端口，默认161" },
        community:   { type: "string", description: "community字符串" },
        version:     { type: "string", description: "SNMP版本 v1/v2c/v3" },
        sysname:     { type: "string" },
        syslocation: { type: "string" },
        syscontact:  { type: "string" },
      },
    },
  },

  // ══════════════════════════════════════════════════════════════
  // 15. 日志
  // ══════════════════════════════════════════════════════════════
  {
    name: "log_system_list",
    description: "查看系统日志。",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", default: 100 } },
    },
  },
  {
    name: "log_system_clear",
    description: "清空系统日志。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "log_arp_list",
    description: "查看ARP日志（设备入网/离网、IP变化记录）。",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", default: 100 } },
    },
  },
  {
    name: "log_arp_clear",
    description: "清空ARP日志。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "log_web_activity_list",
    description: "查看WebUI操作日志（谁在什么时候做了什么配置变更）。",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", default: 100 } },
    },
  },
  {
    name: "log_dhcp_list",
    description: "查看DHCP日志（IP地址分配记录）。",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", default: 100 } },
    },
  },
];

// ─── 工具处理函数 ─────────────────────────────────────────────────────────────
async function handle(name, a) {
  const qs = (o) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(o)) if (v !== undefined) p.append(k, v);
    const s = p.toString();
    return s ? `?${s}` : "";
  };

  switch (name) {
    // ── 监控 ──────────────────────────────────────────────────────
    case "monitor_clients_online":
      return GET(`/monitoring/clients-online${qs({key:a.key,pattern:a.pattern,filter:a.filter})}`);
    case "monitor_clients_online_ipv6":
      return GET("/monitoring/clients-ip6-online");
    case "monitor_clients_offline":
      return GET(`/monitoring/clients-offline${qs({filter:a.filter})}`);
    case "monitor_client_traffic_today":
      return GET(`/monitoring/clients-traffic-summary${qs({filter:a.filter})}`);
    case "monitor_client_traffic_realtime":
      return GET(`/monitoring/clients-traffic-load${qs({filter:a.filter})}`);
    case "monitor_client_protocol_traffic":
      return GET(`/monitoring/clients/protocols${qs({filter:a.filter})}`);
    case "monitor_client_app_speed":
      return GET(`/monitoring/clients/app-protocols/load${qs({filter:a.filter})}`);
    case "monitor_system_load": {
      const [sys,cpu,mem,disk,temp,conn,term,net] = await Promise.all([
        GET("/monitoring/system"), GET("/monitoring/cpu"),
        GET("/monitoring/memory"), GET("/monitoring/disk"),
        GET("/monitoring/cputemp"), GET("/monitoring/connections"),
        GET("/monitoring/terminals"), GET("/monitoring/network"),
      ]);
      return {system:sys,cpu,memory:mem,disk,temperature:temp,connections:conn,terminals:term,network:net};
    }
    case "monitor_wan_status":
      return GET("/monitoring/interfaces-status");
    case "monitor_interfaces_config":
      return GET("/monitoring/interfaces-config");
    case "monitor_physical_nics":
      return GET("/monitoring/interfaces-physical");
    case "monitor_app_protocols_summary":
      return GET("/monitoring/app-traffic-summary");
    case "monitor_app_protocols_realtime":
      return GET("/monitoring/app-protocols/load");
    case "monitor_protocol_categories":
      return GET("/monitoring/protocols");
    case "monitor_flow_shunting":
      return GET("/monitoring/flow-shunting");
    case "monitor_cameras":
      return GET("/monitoring/cameras");

    // ── 终端名称 ──────────────────────────────────────────────────
    case "terminal_list":
      return GET("/security/terminals");
    case "terminal_rename":
      return POST("/security/terminals", {mac:a.mac,tagname:a.name,comment:a.comment||""});
    case "terminal_rename_update":
      return PUT(`/security/terminals/${a.id}`, {mac:a.mac,tagname:a.name,comment:a.comment||""});
    case "terminal_rename_delete":
      return DELETE(`/security/terminals/${a.id}`);

    // ── QoS MAC限速 ───────────────────────────────────────────────
    case "qos_mac_list":
      return GET("/network/qos/mac");
    case "qos_mac_create":
      return POST("/network/qos/mac", {
        mac_addr:{custom:[a.mac_addr]},
        upload:String(a.upload_kbps), download:String(a.download_kbps),
        interface:a.interface||"wan1", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes", ip_type:"4",
      });
    case "qos_mac_update":
      return PUT(`/network/qos/mac/${a.id}`, {
        ...(a.mac_addr && {mac_addr:{custom:[a.mac_addr]}}),
        ...(a.upload_kbps !== undefined && {upload:String(a.upload_kbps)}),
        ...(a.download_kbps !== undefined && {download:String(a.download_kbps)}),
        ...(a.interface && {interface:a.interface}),
        ...(a.comment !== undefined && {comment:a.comment}),
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
      });
    case "qos_mac_toggle":
      return PATCH(`/network/qos/mac/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "qos_mac_delete":
      return DELETE(`/network/qos/mac/${a.id}`);

    // ── 域名黑名单 ────────────────────────────────────────────────
    case "domain_blacklist_list":
      return GET("/security/domain-blacklist/rules");
    case "domain_blacklist_create":
      return POST("/security/domain-blacklist/rules", {
        domain_group:a.domain_group, src_addr:a.src_addr||"",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "domain_blacklist_update":
      return PUT(`/security/domain-blacklist/rules/${a.id}`, {
        domain_group:a.domain_group, src_addr:a.src_addr||"",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "domain_blacklist_toggle":
      return PATCH(`/security/domain-blacklist/rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "domain_blacklist_delete":
      return DELETE(`/security/domain-blacklist/rules/${a.id}`);

    // ── ACL ───────────────────────────────────────────────────────
    case "acl_list":
      return GET("/security/acl-rules");
    case "acl_create":
      return POST("/security/acl-rules", {
        action:a.action, src_addr:a.src_addr, dst_addr:a.dst_addr||"",
        src_port:a.src_port||"", dst_port:a.dst_port||"",
        protocol:a.protocol||"all", iinterface:a.iinterface||"",
        ointerface:a.ointerface||"", ip_type:a.ip_type||"4",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "acl_update":
      return PUT(`/security/acl-rules/${a.id}`, {
        ...(a.action && {action:a.action}),
        ...(a.src_addr && {src_addr:a.src_addr}),
        ...(a.dst_addr !== undefined && {dst_addr:a.dst_addr}),
        ...(a.protocol && {protocol:a.protocol}),
        ...(a.comment !== undefined && {comment:a.comment}),
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
      });
    case "acl_toggle":
      return PATCH(`/security/acl-rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "acl_delete":
      return DELETE(`/security/acl-rules/${a.id}`);

    // ── MAC黑白名单 ───────────────────────────────────────────────
    case "mac_acl_get_mode":
      return GET("/security/mac-mode");
    case "mac_acl_set_mode":
      return PUT("/security/mac-mode", {acl_mac:a.mode});
    case "mac_acl_list":
      return GET("/security/mac-rules");
    case "mac_acl_create":
      return POST("/security/mac-rules", {
        mac:a.mac, termname:a.name||"", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes", expires:a.expires||"",
      });
    case "mac_acl_toggle":
      return PATCH(`/security/mac-rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "mac_acl_delete":
      return DELETE(`/security/mac-rules/${a.id}`);

    // ── 应用协议控制 ──────────────────────────────────────────────
    case "app_proto_control_list":
      return GET("/security/app-protocols/professional/rules");
    case "app_proto_control_create":
      return POST("/security/app-protocols/professional/rules", {
        action:a.action, app_proto:a.app_proto,
        src_addr:a.src_addr||"", dst_addr:a.dst_addr||"",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "app_proto_control_toggle":
      return PATCH(`/security/app-protocols/professional/rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "app_proto_control_delete":
      return DELETE(`/security/app-protocols/professional/rules/${a.id}`);

    // ── DHCP ─────────────────────────────────────────────────────
    case "dhcp_clients_list":
      return GET("/network/dhcp/clients");
    case "dhcp_static_list":
      return GET("/network/dhcp/static");
    case "dhcp_static_create":
      return POST("/network/dhcp/static", {
        mac:a.mac, ip_addr:a.ip_addr, hostname:a.hostname||"",
        interface:a.interface||"lan1", gateway:a.gateway||"",
        dns1:a.dns1||"", dns2:a.dns2||"", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes",
      });
    case "dhcp_static_update":
      return PUT(`/network/dhcp/static/${a.id}`, {
        ...(a.mac && {mac:a.mac}),
        ...(a.ip_addr && {ip_addr:a.ip_addr}),
        ...(a.hostname !== undefined && {hostname:a.hostname}),
        ...(a.gateway !== undefined && {gateway:a.gateway}),
        ...(a.dns1 !== undefined && {dns1:a.dns1}),
        ...(a.dns2 !== undefined && {dns2:a.dns2}),
        ...(a.comment !== undefined && {comment:a.comment}),
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
      });
    case "dhcp_static_toggle":
      return PATCH(`/network/dhcp/static/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "dhcp_static_delete":
      return DELETE(`/network/dhcp/static/${a.id}`);
    case "dhcp_access_mode_get":
      return GET("/network/dhcp/access-control/mode");
    case "dhcp_access_mode_set":
      return PUT("/network/dhcp/access-control/mode", {mode:a.mode});
    case "dhcp_access_rules_list":
      return GET("/network/dhcp/access-control/rules");
    case "dhcp_access_rule_create":
      return POST("/network/dhcp/access-control/rules", {
        mac:a.mac, tagname:a.name||"", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes",
      });
    case "dhcp_access_rule_delete":
      return DELETE(`/network/dhcp/access-control/rules/${a.id}`);
    case "dhcp_services_list":
      return GET("/network/dhcp/services");
    case "dhcp_service_update":
      return PUT(`/network/dhcp/services/${a.id}`, {
        ...(a.addr_pool && {addr_pool:a.addr_pool}),
        ...(a.netmask && {netmask:a.netmask}),
        ...(a.gateway && {gateway:a.gateway}),
        ...(a.dns1 !== undefined && {dns1:a.dns1}),
        ...(a.dns2 !== undefined && {dns2:a.dns2}),
        ...(a.lease && {lease:a.lease}),
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
      });
    case "dhcp_service_restart":
      return POST("/network/dhcp/services:restart", {});
    case "dhcp_log_list":
      return GET(`/log/dhcp${qs({limit:a.limit||50})}`);

    // ── DNS ───────────────────────────────────────────────────────
    case "dns_config_get":
      return GET("/network/dns/config");
    case "dns_config_update":
      return PUT("/network/dns/config", {
        ...(a.dns1 && {dns1:a.dns1}),
        ...(a.dns2 && {dns2:a.dns2}),
        ...(a.cache_ttl && {cache_ttl:a.cache_ttl}),
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
        ...(a.proxy_force !== undefined && {proxy_force:a.proxy_force?"yes":"no"}),
      });
    case "dns_stats_get":
      return GET("/network/dns/stats");
    case "dns_proxy_rules_list":
      return GET("/network/dns/proxy/rules");
    case "dns_proxy_rule_create":
      return POST("/network/dns/proxy/rules", {
        domain:a.domain, dns_addr:a.dns_addr,
        src_addr:a.src_addr||"", is_ipv6:a.is_ipv6||false,
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "dns_proxy_rule_toggle":
      return PATCH(`/network/dns/proxy/rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "dns_proxy_rule_delete":
      return DELETE(`/network/dns/proxy/rules/${a.id}`);
    case "dns_multi_rules_list":
      return GET("/network/multi-dns/rules");
    case "dns_multi_rule_create":
      return POST("/network/multi-dns/rules", {
        interface:a.interface, dns1:a.dns1, dns2:a.dns2||"",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "dns_multi_rule_delete":
      return DELETE(`/network/multi-dns/rules/${a.id}`);

    // ── DNAT 端口映射 ─────────────────────────────────────────────
    case "dnat_list":
      return GET("/network/dnat/rules");
    case "dnat_create":
      return POST("/network/dnat/rules", {
        wan_port:a.wan_port, lan_addr:a.lan_addr, lan_port:a.lan_port,
        protocol:a.protocol||"tcp", interface:a.interface||"",
        src_addr:a.src_addr||"", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes",
      });
    case "dnat_update":
      return PUT(`/network/dnat/rules/${a.id}`, {
        ...(a.wan_port && {wan_port:a.wan_port}),
        ...(a.lan_addr && {lan_addr:a.lan_addr}),
        ...(a.lan_port && {lan_port:a.lan_port}),
        ...(a.protocol && {protocol:a.protocol}),
        ...(a.comment !== undefined && {comment:a.comment}),
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
      });
    case "dnat_toggle":
      return PATCH(`/network/dnat/rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "dnat_delete":
      return DELETE(`/network/dnat/rules/${a.id}`);

    // ── NAT ───────────────────────────────────────────────────────
    case "nat_rules_list":
      return GET("/network/nat/rules");
    case "nat_rule_create":
      return POST("/network/nat/rules", {
        action:a.action, iinterface:a.iinterface||"",
        ointerface:a.ointerface||"", src_addr:a.src_addr||"",
        dst_addr:a.dst_addr||"", nat_addr:a.nat_addr||"",
        nat_port:a.nat_port||"", protocol:a.protocol||"all",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "nat_rule_toggle":
      return PATCH(`/network/nat/rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "nat_rule_delete":
      return DELETE(`/network/nat/rules/${a.id}`);

    // ── 路由分流 ──────────────────────────────────────────────────
    case "route_domain_list":
      return GET("/routing/domain-rules");
    case "route_domain_create":
      return POST("/routing/domain-rules", {
        domain:a.domain, interface:a.interface, src_addr:a.src_addr||"",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "route_domain_toggle":
      return PATCH(`/routing/domain-rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "route_domain_delete":
      return DELETE(`/routing/domain-rules/${a.id}`);
    case "route_protocol_list":
      return GET("/routing/app-protocols");
    case "route_protocol_create":
      return POST("/routing/app-protocols", {
        app_proto:a.app_proto, interface:a.interface,
        src_addr:a.src_addr||"", mode:a.mode||"",
        comment:a.comment||"", enabled:a.enabled===false?"no":"yes",
      });
    case "route_protocol_toggle":
      return PATCH(`/routing/app-protocols/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "route_protocol_delete":
      return DELETE(`/routing/app-protocols/${a.id}`);
    case "route_fivetuple_list":
      return GET("/routing/five-tuple-rules");
    case "route_fivetuple_create":
      return POST("/routing/five-tuple-rules", {
        interface:a.interface, src_addr:a.src_addr||"",
        dst_addr:a.dst_addr||"", protocol:a.protocol||"all",
        src_port:a.src_port||"", dst_port:a.dst_port||"",
        mode:a.mode||"", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes",
      });
    case "route_fivetuple_toggle":
      return PATCH(`/routing/five-tuple-rules/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "route_fivetuple_delete":
      return DELETE(`/routing/five-tuple-rules/${a.id}`);
    case "route_static_list":
      return GET("/routing/static-routes");
    case "route_static_create":
      return POST("/routing/static-routes", {
        dst_addr:a.dst_addr, gateway:a.gateway,
        interface:a.interface||"", comment:a.comment||"",
        enabled:a.enabled===false?"no":"yes",
      });
    case "route_static_toggle":
      return PATCH(`/routing/static-routes/${a.id}`, {enabled:a.enabled?"yes":"no"});
    case "route_static_delete":
      return DELETE(`/routing/static-routes/${a.id}`);

    // ── WAN/LAN ───────────────────────────────────────────────────
    case "wan_config_list":
      return GET("/interfaces/wan-config");
    case "wan_config_update":
      return PUT(`/interfaces/wan-config/${a.id}`, {comment:a.comment||""});
    case "lan_config_list":
      return GET("/interfaces/lan-config");
    case "lan_config_update":
      return PUT(`/interfaces/lan-config/${a.id}`, {
        ...(a.ip_mask && {ip_mask:a.ip_mask}),
        ...(a.comment !== undefined && {comment:a.comment}),
      });

    // ── 系统管理 ──────────────────────────────────────────────────
    case "system_basic_get":
      return GET("/system/basic/config");
    case "system_basic_update":
      return PUT("/system/basic/config", {
        ...(a.hostname && {hostname:a.hostname}),
        ...(a.time_zone && {time_zone:a.time_zone}),
        ...(a.switch_ntp !== undefined && {switch_ntp:a.switch_ntp}),
        ...(a.fast_nat !== undefined && {fast_nat:a.fast_nat?"on":"off"}),
      });
    case "system_ntp_sync":
      return POST("/system/basic/ntp:sync", {});
    case "system_backup_info":
      return GET("/system/backup");
    case "system_backup_create":
      return POST("/system/backup", {});
    case "system_backup_auto_get":
      return GET("/system/backup-auto");
    case "system_backup_auto_update":
      return PUT("/system/backup-auto", {
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
        ...(a.strategy && {strategy:a.strategy}),
        ...(a.time && {time:a.time}),
        ...(a.valid_days && {valid_days:a.valid_days}),
      });
    case "firmware_check":
      return POST("/system/upgrade:check", {});
    case "firmware_info":
      return GET("/system/upgrade");
    case "system_cpu_freq_get":
      return GET("/system/cpufreq");
    case "system_cpu_mode_get":
      return GET("/system/cpufreq/mode");
    case "system_cpu_mode_set":
      return PUT("/system/cpufreq/mode", {mode:a.mode, turbo:a.turbo??true});
    case "system_disks_info":
      return GET("/system/disks");
    case "system_remote_access_get":
      return GET("/system/remote-access");
    case "system_remote_access_update":
      return PUT("/system/remote-access", {
        ...(a.open_sshd !== undefined && {open_sshd:a.open_sshd?"yes":"no"}),
        ...(a.sshd_port && {sshd_port:String(a.sshd_port)}),
        ...(a.open_wanweb !== undefined && {open_wanweb:a.open_wanweb?"yes":"no"}),
        ...(a.http_port && {http_port:String(a.http_port)}),
        ...(a.https_port && {https_port:String(a.https_port)}),
        ...(a.force_https !== undefined && {force_https:a.force_https?"yes":"no"}),
        ...(a.open_telnetd !== undefined && {open_telnetd:a.open_telnetd?"yes":"no"}),
      });
    case "system_kernel_params_get":
      return GET("/system/kernel-params");
    case "system_kernel_params_update":
      return PUT("/system/kernel-params", {
        ...(a.bbr !== undefined && {bbr:a.bbr?"yes":"no"}),
        ...(a.established_timeout && {established_timeout:a.established_timeout}),
        ...(a.time_wait_timeout && {time_wait_timeout:a.time_wait_timeout}),
        ...(a.udp_timeout && {udp_timeout:a.udp_timeout}),
      });
    case "alg_config_get":
      return GET("/system/alg");
    case "alg_config_update":
      return PUT("/system/alg", {
        ...(a.support_ftp !== undefined && {support_ftp:a.support_ftp?"yes":"no"}),
        ...(a.support_sip !== undefined && {support_sip:a.support_sip?"yes":"no"}),
        ...(a.support_h323 !== undefined && {support_h323:a.support_h323?"yes":"no"}),
        ...(a.support_tftp !== undefined && {support_tftp:a.support_tftp?"yes":"no"}),
        ...(a.ftp_ports && {ftp_ports:a.ftp_ports}),
        ...(a.sip_ports && {sip_ports:a.sip_ports}),
      });
    case "snmp_config_get":
      return GET("/advanced-service/snmpd-config");
    case "snmp_config_update":
      return PUT("/advanced-service/snmpd-config", {
        ...(a.enabled !== undefined && {enabled:a.enabled?"yes":"no"}),
        ...(a.listen_port && {listen_port:a.listen_port}),
        ...(a.community && {community:a.community}),
        ...(a.version && {version:a.version}),
        ...(a.sysname && {sysname:a.sysname}),
        ...(a.syslocation && {syslocation:a.syslocation}),
        ...(a.syscontact && {syscontact:a.syscontact}),
      });

    // ── 日志 ──────────────────────────────────────────────────────
    case "log_system_list":
      return GET(`/log/system${qs({limit:a.limit||100})}`);
    case "log_system_clear":
      return DELETE("/log/system");
    case "log_arp_list":
      return GET(`/log/arp${qs({limit:a.limit||100})}`);
    case "log_arp_clear":
      return DELETE("/log/arp");
    case "log_web_activity_list":
      return GET(`/log/web_activity${qs({limit:a.limit||100})}`);
    case "log_dhcp_list":
      return GET(`/log/dhcp${qs({limit:a.limit||50})}`);

    default:
      throw new Error(`未知工具: ${name}`);
  }
}

// ─── MCP Server 启动 ─────────────────────────────────────────────────────────
const server = new Server(
  { name: "ikuai-mcp", version: "2.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
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
console.error(`iKuai MCP Server v2.0 已启动 (${TOOLS.length}个工具) — ${BASE}`);
