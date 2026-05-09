# iKuai MCP Server

爱快路由器 (iKuai 4.0) 的 MCP Server，让 AI CLI 工具通过自然语言查看和管理路由器。

当前版本基于 OpenAPI 生成 **449 个底层 API**，但默认使用 compact 模式，避免把全部接口一次性塞进每个 AI 会话。

## 推荐用法

### 1. 日常默认：不要常驻 MCP

如果只是偶尔让 AI 查看爱快状态，推荐使用零常驻 CLI：

```bash
IKUAI_HOST=192.168.1.1 IKUAI_TOKEN=你的OpenAPI令牌 npx --package github:zshleon/ikuai-mcp ikuai-ai search interface
IKUAI_HOST=192.168.1.1 IKUAI_TOKEN=你的OpenAPI令牌 npx --package github:zshleon/ikuai-mcp ikuai-ai call getInterfaceStatus
```

工作流：先 `search <keyword>` 找到合适 API，再 `call <toolName>` 调用。这样不会影响 Gemini、Hermes、Claude 等其他 AI 的默认工具上下文。

常用关键词：`interface`、`traffic`、`dhcp`、`client`、`wan`、`route`、`dns`、`nat`、`acl`、`system`。

### 2. 需要 MCP 时：compact 模式

MCP 默认也是 compact 模式，只暴露：

- `ikuai_list_api_tools`：搜索全部 449 个底层 API
- `ikuai_call_api`：按工具名或 method/path 调用任意底层 API
- 一组常用、只读、低风险的直显工具

需要完整暴露 449 个直显工具时，显式设置 `IKUAI_MCP_MODE=full`。

## MCP 配置示例

### Gemini CLI / Claude Code

```json
{
  "mcpServers": {
    "ikuai": {
      "command": "npx",
      "args": ["github:zshleon/ikuai-mcp"],
      "env": {
        "IKUAI_HOST": "192.168.1.1",
        "IKUAI_TOKEN": "你的OpenAPI令牌",
        "IKUAI_MCP_MODE": "compact",
        "IKUAI_MCP_COMPACT_LIMIT": "60"
      }
    }
  }
}
```

### OpenAI Codex CLI

```toml
[mcp_servers.ikuai]
command = "npx"
args = ["github:zshleon/ikuai-mcp"]

[mcp_servers.ikuai.env]
IKUAI_HOST = "192.168.1.1"
IKUAI_TOKEN = "你的OpenAPI令牌"
IKUAI_MCP_MODE = "compact"
IKUAI_MCP_COMPACT_LIMIT = "60"
```

## 本地克隆运行

```bash
git clone https://github.com/zshleon/ikuai-mcp.git
cd ikuai-mcp
npm install
node server.js
```

零常驻 CLI：

```bash
IKUAI_HOST=192.168.1.1 IKUAI_TOKEN=你的OpenAPI令牌 ./scripts/ikuai-ai search dhcp
IKUAI_HOST=192.168.1.1 IKUAI_TOKEN=你的OpenAPI令牌 ./scripts/ikuai-ai call getInterfaceStatus
IKUAI_HOST=192.168.1.1 IKUAI_TOKEN=你的OpenAPI令牌 ./scripts/ikuai-ai raw GET /monitoring/interfaces-status
```

如果本机已有 Gemini/Hermes 配置，`ikuai-ai` 也会尝试从已保存的 enabled/disabled iKuai 配置读取环境变量；环境变量始终优先。

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `IKUAI_HOST` | 路由器 IP 或域名 | `192.168.1.1` |
| `IKUAI_PORT` | 管理端口 | `80` 或 `443` |
| `IKUAI_USER` | 用户名，密码认证时使用 | `admin` |
| `IKUAI_PASS` | 密码，密码认证时自动 MD5 | - |
| `IKUAI_TOKEN` | Open API 静态 Bearer Token，推荐 | - |
| `IKUAI_SCHEME` | `http` 或 `https`；设置 token 时默认 https | 自动 |
| `IKUAI_INSECURE_TLS` | `1` 时忽略自签证书错误 | `1` |
| `IKUAI_MCP_MODE` | `compact` 或 `full` | `compact` |
| `IKUAI_MCP_COMPACT_LIMIT` | compact 模式直显工具数量上限 | `60` |

## MCP 工具

### `ikuai_list_api_tools`

搜索完整 API 目录，不把全部 449 个接口暴露成独立工具。

参数：

```json
{"query":"interface","limit":10}
```

### `ikuai_call_api`

调用任意底层 API。推荐先用 `ikuai_list_api_tools` 找工具名，再按工具名调用：

```json
{"tool":"getInterfaceStatus","arguments":{}}
```

也可以按 method/path 调用：

```json
{"method":"GET","path":"/monitoring/interfaces-status"}
```

## 安全建议

- 默认用 compact 或零常驻 CLI，避免影响普通 AI 会话。
- 检查状态优先使用只读 GET 接口。
- POST/PUT/PATCH/DELETE 会立即影响路由器配置，执行前应确认意图。
- 不要把 `IKUAI_TOKEN` 写入仓库或日志。

## 系统要求

- Node.js >= 18
- Python 3（仅 `scripts/ikuai-ai` 需要）
- iKuai 4.0 Open API

## License

MIT
