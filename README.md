# 🛡️ LongCat Sentinel (龙猫熔断哨兵)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Model](https://img.shields.io/badge/Model-Meituan%20LongCat--2.5--Preview-orange.svg)
![Security](https://img.shields.io/badge/Security-OWASP%20Hardened-red.svg)
![Tests](https://img.shields.io/badge/Tests-77%20Passed-brightgreen.svg)

**专为美团 LongCat-2.5-Preview 万亿 MoE 大模型定制的官方级企业智能熔断与抗死循环网关**

[快速上手](#快速上手) • [客户端接入](#客户端接入指南) • [核心架构](#核心架构与特性) • [安全硬化](#15项生产安全硬化)

</div>

---

## 📖 项目简介

**LongCat Sentinel（龙猫熔断哨兵）** 旨在彻底解决美团 **LongCat-2.5-Preview**（1.6T MoE 架构、1M 超长上下文）在长程编码、复杂推理（Thinking）与智能体交互中极易陷入 **N-gram 文本复读、Tool Call 相同入参死循环与破坏性命令误执行** 的痛点。

网关采用**双轨原生协议路由**，在不篡改协议的前提下，为 **Claude Code** 与 **Hermes / Cursor** 提供零死角、自愈式、零误伤的流式循环拦截防护。

---

## ✨ 核心特性

- 🚀 **双轨原生直通路由**：
  - **Anthropic 管道 (`/v1/messages`)**：原生保全 Thinking 签名与 SSE 流式事件，为 **Claude Code** 量身打造；
  - **OpenAI 管道 (`/v1/chat/completions`)**：原生支持 **Hermes**、**Cursor**、**Cline** 等。
- 🛡️ **Tool 6 大能力元与深度命令防御**：
  - 彻底废弃单纯看名字分类，深入参数语法树与命令正则；
  - 毫秒级阻断 `terminal("rm -rf /")`、`DROP TABLE`、`chmod 777`、`curl | bash` 等隐蔽危险调用。
- ⚡ **协议合规流式平滑中断**：
  - 流式 Tool 生成中途中断时，**自动补全合法的 JSON 闭合**，再开启独立文本块注入干预系统提示，**保证客户端解析器 0 崩溃**。
- 🧠 **语义状态增量 LoopScore**：
  - 过滤时间戳伪差异，以文件 Hash 变动、Git 状态变动等真实进展指标判断循环，消除误杀。
- 🔒 **OWASP 企业级安全硬化**：
  - 零明文密钥管理、动态回环 Origin 泛端口自适应、2MB 环形队列防内存爆破、日志深度脱敏。

---

## 🚀 快速上手

### 1. 克隆与安装依赖
```bash
git clone https://github.com/PrismaticDark/longcat-sentinel.git
cd longcat-sentinel
pip install -r requirements.txt
```

### 2. 配置环境变量
在终端中设置（或复制 `.env.example` 为 `.env`）：
```powershell
# Windows PowerShell
$env:LONGCAT_API_KEY="sk-meituan-your-real-key"
$env:SENTINEL_GATEWAY_TOKEN="sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a"
$env:SENTINEL_ADMIN_TOKEN="adm-sentinel-99e8d7c6b5a4"

# Linux / macOS
export LONGCAT_API_KEY="sk-meituan-your-real-key"
export SENTINEL_GATEWAY_TOKEN="sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a"
export SENTINEL_ADMIN_TOKEN="adm-sentinel-99e8d7c6b5a4"
```

### 3. 一键启动
- **Windows**：直接双击运行根目录下的 `run_gateway.bat`
- **命令行启动**：
```bash
python main.py
```
启动成功后，浏览器打开 `http://127.0.0.1:8080/dashboard` 即可查看美团经典黄+深黑赛博极客监控大屏！

---

## 🔌 客户端接入指南

### 1. Claude Code 接入 (Anthropic 原生路由)
```bash
# Windows PowerShell
$env:ANTHROPIC_BASE_URL="http://127.0.0.1:8080"
$env:ANTHROPIC_API_KEY="sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a"
claude

# Linux / macOS
export ANTHROPIC_BASE_URL="http://127.0.0.1:8080"
export ANTHROPIC_API_KEY="sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a"
claude
```

### 2. Hermes Agent / Cursor / Cline 接入 (OpenAI 原生路由)
- **Base URL**: `http://127.0.0.1:8080/v1`
- **API Key**: `sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a`
- **Model**: `longcat-2.5-preview`

### 3. Cherry Studio / NextChat / Chatbox
- 添加自定义提供商，接口地址填入 `http://127.0.0.1:8080` 即可畅爽对话。

---

## 🧪 自动化测试与本地仿真

无需消耗真实 API Key，运行本地 5 组死循环仿真器：
```bash
python -m tests.mock_simulator
```

运行全量 77 项安全与配置测试集：
```bash
python -m unittest tests/test_config_and_auth.py
```

---

## 📄 开源许可证

本项目采用 [MIT License](LICENSE) 授权许可。
