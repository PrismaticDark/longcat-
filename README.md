# 🛡️ LongCat Sentinel (龙猫熔断哨兵)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Model](https://img.shields.io/badge/Model-Meituan%20LongCat--2.5--Preview-orange.svg)
![Security](https://img.shields.io/badge/Security-Hardened-red.svg)
![Tests](https://img.shields.io/badge/Tests-100%20Passed-brightgreen.svg)

**专为美团 LongCat-2.5-Preview 万亿 MoE 大模型定制的抗死循环与智能熔断网关**

[快速上手](#快速上手) • [客户端接入](#客户端接入指南) • [核心能力](#核心能力) • [安全模型](#安全模型) • [安全修复记录](#v231-安全修复记录)

</div>

---

## 📖 项目简介

**LongCat Sentinel（龙猫熔断哨兵）** 旨在解决美团 **LongCat-2.5-Preview** 在长程编码、复杂推理（Thinking）与智能体交互中容易陷入 **N-gram 文本复读、Tool Call 相同入参死循环与破坏性命令误执行** 的问题。

网关提供**双轨原生协议路由**，在不篡改协议的前提下，为 **Claude Code** 与 **Hermes / Cursor / Cline** 提供流式循环拦截防护。

---

## ✨ 核心能力

以下能力**全部已接入生产路由**（v2.3.1 起，此前部分模块仅存在于离线仿真中）：

- 🚀 **双轨原生直通路由**
  - **Anthropic 管道 (`/v1/messages`)**：原生保全 Thinking 与 SSE 事件，为 **Claude Code** 打造；
  - **OpenAI 管道 (`/v1/chat/completions`)**：支持 **Hermes**、**Cursor**、**Cline** 等。
- 🛡️ **工具调用深度防御**
  - 按**入参语法树**扫描破坏性命令（`rm -rf /`、`DROP TABLE`、`chmod 777`、`curl | bash`、`Remove-Item -Recurse -Force`、fork bomb 等）；
  - 正常命令（`ls`、`git status`、`pytest`）**不会被误杀**；
  - 相同工具 + 相同入参重复调用、A→B→A→B 乒乓循环会被熔断。
- ⚡ **协议合规流式中断**
  - 中断时按实际累积的参数**精确补全合法 JSON**（支持未闭合字符串与嵌套容器），再开启独立文本块注入干预提示，保证客户端解析器不崩溃。
- 🧠 **增量式 LoopScore**
  - 精确 + 模糊（rapidfuzz）双通道周期检测；Markdown 分隔符与空白缩进免疫；未闭合代码块内自动放宽阈值。
- ⏱️ **解耦超时与资源上限**
  - TTFT（首包）与流空闲超时独立配置；请求体上限与并发流上限强制生效（413 / 429）。
- 🔒 **企业级安全硬化**
  - 管理接口强制 `X-Admin-Token`，网关 Token 与管理 Token 权限彻底分离；
  - Origin 校验 + Host 头 DNS 重绑定防御覆盖全部业务与管理路由；
  - 零明文密钥：配置文件中不存在任何默认口令。

---

## 🚀 快速上手

### 1. 安装依赖
```bash
git clone https://github.com/PrismaticDark/longcat-.git
cd longcat-
pip install -r requirements.txt
```

### 2. 配置环境变量（三项均为必填，无任何默认值）

在项目根目录创建 `.env`（可复制 `.env.example`）：

```ini
LONGCAT_API_KEY=sk-meituan-你的真实密钥
SENTINEL_GATEWAY_TOKEN=请填入至少32位高强度随机串
SENTINEL_ADMIN_TOKEN=请填入另一条至少32位高强度随机串
```

生成强随机口令：

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

> ⚠️ 网关**拒绝启动**，如果：
> - 上述任一变量缺失或为空白；
> - Token 短于 32 字符、字符种类过少；
> - Token 命中已知弱口令 / 文档占位值 / 历史版本内置默认口令；
> - `SENTINEL_ADMIN_TOKEN` 与 `SENTINEL_GATEWAY_TOKEN` 相同。

### 3. 一键启动

- **Windows**：双击 `run_gateway.bat`（首次运行会自动生成随机凭证模板，请先填入 `LONGCAT_API_KEY`）
- **命令行**：
```bash
python main.py
```

启动后访问 `http://127.0.0.1:8080/dashboard` 查看监控大屏。

> 大屏的配置/指标接口受 `SENTINEL_ADMIN_TOKEN` 保护，需在页面顶部「管理口令」处粘贴该值后才能读取与保存配置。口令仅保存在当前标签页内存中。

> **使用打包版 exe**：直接运行 `dist/LongCatSentinel/LongCatSentinel.exe`。
> 首次运行前请在 **exe 同级目录**创建 `.env`（三项必填，格式见 `.env.example`）。
> 打包版内置的 `config.yaml` 位于 `_internal/`；如需自定义配置，把修改后的 `config.yaml`
> 放到 exe 同级目录即可——同级目录会被优先加载。

---

## 🔌 客户端接入指南

### 1. Claude Code（Anthropic 原生路由）
```bash
# Windows PowerShell
$env:ANTHROPIC_BASE_URL="http://127.0.0.1:8080"
$env:ANTHROPIC_API_KEY="<你的 SENTINEL_GATEWAY_TOKEN 完整值>"
claude
```

### 2. Hermes Agent / Cursor / Cline（OpenAI 原生路由）
- **Base URL**：`http://127.0.0.1:8080/v1`
- **API Key**：`<你的 SENTINEL_GATEWAY_TOKEN 完整值>`
- **Model**：`longcat-2.5-preview`

> 凭证必须与 `SENTINEL_GATEWAY_TOKEN` **完全一致**：网关不再接受省略 `sk-ant-sentinel-` 等前缀的简化写法。

### 3. Cherry Studio / NextChat / Chatbox
添加自定义提供商，接口地址填入 `http://127.0.0.1:8080`。

---

## 🧪 自动化测试与本地仿真

```bash
# 100 项自动化测试（安全边界 / 检测引擎 / 端到端流式）
python -m tests.run_all_tests

# 零成本本地仿真（无需 API Key）
python -m tests.mock_simulator
```

测试直接针对 `longcat_sentinel.server.create_app` 构建的**真实应用**，不依赖任何手写的"影子应用"。

---

## 🔐 安全模型

| 边界 | 策略 |
|---|---|
| `/v1/*` | 必须携带与配置完全一致的网关 Token（`Authorization: Bearer` / `X-Api-Key` / `anthropic-api-key`），并校验 Origin 与 Host |
| `/api/admin/*` | 必须携带 `X-Admin-Token`；网关 Token 不能用于管理接口，管理 Token 也不能访问 `/v1/*` |
| 浏览器跨域 | 仅允许配置中显式列出的来源；回环来源动态放行；不使用通配来源 |
| `/docs`、`/openapi.json` | 默认关闭，需要时通过 `security.enable_api_docs: true` 显式开启 |
| 密钥持久化 | 仅管理接口（已鉴权）可写入 `.env`；客户端请求**永远不会**改写已配置的上游密钥 |
| 日志与指标 | 审计文本经 `DeepRedactor` 脱敏；业务数据流保持字节精确、绝不被篡改 |

> 说明：如需让某个客户端临时使用自己的上游密钥，可通过请求头 `X-Upstream-Api-Key` 传入，该值**仅对本次请求生效**，不会落盘。

---

## 🩹 v2.3.1 安全修复记录

本次版本修复了以下问题（完整证据见 `审查报告-LongCat-Sentinel.md`）：

1. **管理接口完全无鉴权** —— 任何人可读取明文上游密钥并篡改配置、写入 `.env`。
2. **`/v1/*` 认证通配放行** —— 任意 `ak_` 开头字符串即通过认证。
3. **Token 前缀降级匹配** —— 省略前缀后仅凭后缀即可通过。
4. **内置默认凭证** —— 配置文件、启动脚本、前端页面均硬编码了同一套公开口令。
5. **TLS 校验通过但从未启用** —— 外部绑定仍以明文 HTTP 监听。
6. **CORS 通配 + 携带凭证** —— 任意网站可读取管理接口。
7. **鉴权依赖从未接入真实路由** —— Origin/Host 校验在生产中不生效；测试测的是自建"影子应用"。
8. **工具防御 / 思考链 / 脱敏 / 限流 / 超时配置全部未接线**。
9. **Anthropic 并行工具块中断不合规** —— 打开的工具调用缺少 JSON 闭合。
10. **工具能力判定 100% 误杀** —— `terminal("ls")` 被判为破坏性。
11. **非流式分支缺少异常处理**、非法 JSON 返回 500、上游失败被记为"安全放行"。
12. **每 token 同步阻塞约 1.6ms** —— 现改为增量检测（实测提升约 950 倍）。

---

## 📄 开源许可证

本项目采用 [MIT License](LICENSE) 授权许可。
