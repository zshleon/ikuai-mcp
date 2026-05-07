# iKuai MCP Server

爱快路由器 (iKuai 4.0) 的 MCP Server，让 Claude Code 等 AI CLI 工具通过自然语言管理路由器。

**覆盖爱快4.0全部40个API模块，共120+个工具。**

## 功能一览

| 类别 | 工具数 | 能做什么 |
|------|--------|----------|
| 监控 | 16 | 在线设备、流量统计、WAN状态、系统负载 |
| 安全控制 | 22 | MAC限速、域名黑名单、ACL、MAC白名单、协议封禁 |
| DHCP管理 | 14 | 静态绑定、访问控制、服务配置 |
| DNS管理 | 12 | 代理规则、多线DNS、缓存配置 |
| 端口映射 | 5 | DNAT规则增删改查 |
| NAT规则 | 4 | 高级NAT策略 |
| 路由分流 | 16 | 域名/协议/五元组/静态路由 |
| WAN/LAN接口 | 4 | 接口配置查看与修改 |
| 系统管理 | 14 | 备份、固件、CPU模式、SSH、内核参数 |
| 日志 | 6 | 系统/ARP/DHCP/操作日志 |

## 快速开始

### 方式一：npx 直接运行（推荐）

在 Claude Code 配置文件（通常是 `~/.claude.json`）中加入：

```json
{
  "mcpServers": {
    "ikuai": {
      "command": "npx",
      "args": ["github:zshleon/ikuai-mcp"],
      "env": {
        "IKUAI_HOST": "192.168.1.1",
        "IKUAI_USER": "admin",
        "IKUAI_PASS": "你的密码"
      }
    }
  }
}
```

### 方式二：克隆后本地运行

```bash
git clone https://github.com/zshleon/ikuai-mcp.git
cd ikuai-mcp
npm install

# 配置环境变量
export IKUAI_HOST=192.168.1.1
export IKUAI_USER=admin
export IKUAI_PASS=你的密码
```

Claude Code 配置：

```json
{
  "mcpServers": {
    "ikuai": {
      "command": "node",
      "args": ["/path/to/ikuai-mcp/server.js"],
      "env": {
        "IKUAI_HOST": "192.168.1.1",
        "IKUAI_USER": "admin",
        "IKUAI_PASS": "你的密码"
      }
    }
  }
}
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `IKUAI_HOST` | 路由器IP | `192.168.1.1` |
| `IKUAI_PORT` | 管理端口 | `80` |
| `IKUAI_USER` | 用户名 | `admin` |
| `IKUAI_PASS` | 密码（明文，自动MD5加密） | — |

## 使用示例

启动 Claude Code 后，直接用中文指令：

```
# 监控
现在有哪些设备在线？有没有我不认识的设备？
路由器的CPU温度和内存使用率是多少？
哪个设备今天用了最多流量？
WAN1和WAN2都正常吗？

# 设备管控
把MAC地址为AA:BB:CC:DD:EE:FF的设备限速到5Mbps下载，2Mbps上传
给这台设备起个名字叫"儿子的iPad"
临时封禁设备192.168.1.100访问外网

# 安全
封禁域名 ads.example.com
封禁所有P2P下载流量
把MAC AA:BB:CC:DD:EE:FF加入白名单

# 网络配置
给MAC AA:BB:CC:DD:EE:FF绑定固定IP 192.168.1.50
把外网8080端口转发到内网192.168.1.100:80
让Netflix的流量走WAN2

# 系统
在做变更之前先备份配置
查一下有没有新固件
把CPU改成节能模式
查看最近的系统日志
```

## 注意事项

- **仅支持爱快 4.0**，API路径为 `/api/v4.0/`，3.x版本不兼容
- 密码通过环境变量传入，服务端自动MD5加密，不存储明文
- JWT Token 有效期约1小时，过期自动续签
- 写操作（限速、封禁、端口映射等）会立即生效，请谨慎操作
- 建议重要变更前先调用 `system_backup_create` 备份配置

## 需求

- Node.js >= 18
- 爱快路由器 4.0 版本
- Claude Code 或其他支持 MCP 的 AI CLI
