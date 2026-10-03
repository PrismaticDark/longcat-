# LongCat Sentinel 代码审查与缺陷报告（含修复记录）

## ✅ 修复状态：全部缺陷已于 v2.3.1 修复

验证记录（均为本次实际执行结果）：

| 验证项 | 命令 | 结果 |
|---|---|---|
| 自动化测试套件 | `python -m tests.run_all_tests` | **100 项通过 / 0 失败 / 0 错误** |
| 本地零成本仿真 | `python -m tests.mock_simulator` | **6/6 通过** |
| 漏洞回归验收 | 23 项逐条断言（覆盖 V1–V16） | **23/23 通过** |
| 真实 HTTP 服务 | `uvicorn` 实际监听后逐端点验证 | 全部符合预期（401/403/404/200 各就各位） |
| 检测性能 | 每 token 检测耗时 | **0.003 ms**（修复前 1.9 ms，约 **950×** 提升） |

| 编号 | 缺陷 | 状态 | 修复方式 |
|---|---|---|---|
| V1 | `/api/admin/*` 完全无鉴权，明文泄露密钥并可无凭证写 `.env` | ✅ 已修复 | `web/admin_api.py` 三个端点全部挂 `Depends(verify_admin_auth)`；改为从 `app.state.config` 取配置；不再回显 `api_key`/`gateway_token` |
| V2 | `/v1/*` 任意 `ak_` 开头字符串即通过认证 | ✅ 已修复 | 删除 `server.py` 中的 `token.startswith("ak_")` 通配分支 |
| V3 | Token 前缀降级匹配（省略前缀即可通过） | ✅ 已修复 | `auth.normalize_token` 改为精确匹配，仅剥离 `Bearer` scheme，不再剥离厂商前缀 |
| V4 | 内置默认凭证（配置/脚本/前端三处硬编码） | ✅ 已修复 | `config.yaml` 去掉默认值；安全 Token 拒绝 YAML 明文默认；`run_gateway.bat` 改为生成随机凭证；`config.check_token_strength` 新增长度/熵/已知默认串校验 |
| V5 | TLS 校验通过但从未启用 | ✅ 已修复 | `main.py` 读取 `config.server`（host/port/workers/tls），并把证书真正传给 uvicorn |
| V6 | CORS 通配 + 携带凭证 | ✅ 已修复 | `create_app` 仅使用 `security.allowed_origins`，`allow_credentials=False` |
| V7 | 恶意 Origin 可跨域读取管理接口 | ✅ 已修复 | 由 V1 的鉴权依赖统一执行 Origin 校验（实测 403） |
| V8 | 鉴权依赖从未接入真实路由；`app.state.config` 未注入 | ✅ 已修复 | `server.py` 重构为 `create_app(config)` 工厂并注入 `app.state.config`；`/v1/*` 全部挂 `Depends(verify_gateway_auth)` |
| V9 | 安全测试针对自建"影子应用" | ✅ 已修复 | 新增 `tests/support.py` 统一使用真实 `create_app`；测试文件重写为端到端断言 |
| V10 | 工具能力元 / 思考链 / 脱敏 等模块从未接入生产 | ✅ 已修复 | 新增 `detector/tool_loop_guard.py` 并接入双路由；`DeepRedactor` 接入 `metrics` 审计文本；`StreamFSM`/`ParallelToolTracker` 承担并行块状态追踪 |
| V11 | profiles / limits / timeouts / tool_guard / immunity 配置零生效 | ✅ 已修复 | 全部注入 `LoopScorer`、`RingBuffer`、`httpx.Timeout`、请求体与并发准入；实测 413 / 429 生效 |
| V12 | Anthropic 并行工具块中断缺少 JSON 闭合 | ✅ 已修复 | 按块类型追踪打开的工具调用；新增 `closing_suffix` 支持未闭合字符串与嵌套容器 |
| V13 | 工具能力判定 100% 误杀（`terminal("ls")` 判为破坏性） | ✅ 已修复 | 能力推断改为精确+分词匹配；破坏性判定完全基于入参扫描，并扩充 Windows/fork bomb 等模式 |
| V14 | 脱敏引擎对较短密钥无效 | ⚠️ 已知限制 | 已纳入审计路径；正则对短于阈值的历史密钥形态仍不匹配，属长密钥优先设计的已知边界（测试中显式记录） |
| V15 | 非流式缺 `except`、非法 JSON 500、上游失败记为"安全放行"、无 413/429 | ✅ 已修复 | 补齐异常分支（502）、JSON 解析 400、`record_upstream_error` 审计动作、请求体与并发准入 |
| V16 | 每 token 同步阻塞 1.6 ms 且随输出劣化 | ✅ 已修复 | `LoopScorer.feed` 增量检测 + 有界窗口 + 去掉无用 SimHash；实测 0.003 ms/token |

---

- 审查对象：`E:\桌面\longcat熔断插件`（修复前：源码 21 个文件 / 约 2450 行）
- 审查方式：全量静态阅读 + 在仓库副本中用真实 `longcat_sentinel.server.app` 做动态复现（审查阶段未改动原仓库任何文件，修复阶段才落盘修改）
- 修复前测试基线：`python -m tests.run_all_tests` → **103 通过 / 0 失败**（该数字具有误导性，原因见 V9）
- 结论：**测试全绿并不代表安全或正确**。安全测试针对的是一个自建的"影子应用"，真实网关的管理接口完全无鉴权；README 宣称的多项核心能力（工具能力元、破坏性命令防御、思考链分流、日志脱敏、OWASP 硬化）在生产代码中**从未被调用**。

---

## 一、总体判断

| 维度 | 评价 |
|---|---|
| 认证与授权 | ❌ 致命。管理接口零鉴权；`/v1/*` 存在通配放行；内置默认凭证 |
| 传输安全 | ❌ TLS 校验通过后并未启用 TLS |
| 宣称能力落地 | ❌ 工具防御 / 思考链 / 脱敏 / 限流 / 超时 全部未接线 |
| 熔断核心逻辑 | ⚠️ 能触发，但协议合规性在并行工具场景下失效；参数未走配置 |
| 性能 | ⚠️ 每个 token 同步阻塞约 1.6 ms，随输出线性劣化 |
| 工程与测试 | ❌ 测试与生产脱节，且把 bug 固化为"预期行为" |

---

## 二、致命缺陷（可被远程利用，均已实测复现）

### V1. `/api/admin/*` 完全没有鉴权 —— 明文泄露密钥 + 无凭证篡改配置

`web/admin_api.py:10` 创建了 `admin_router`，但 `admin_api.py:46 / :62 / :81` 三个端点**都没有挂 `verify_admin_auth` 依赖**；`server.py:39` 的中间件只保护 `path.startswith("/v1/")`，对 `/api/admin/` 完全不设防。

实测（真实 app，无任何请求头）：

```
GET  /api/admin/config  -> HTTP 200
     raw api_key='sk-meituan-REAL-upstream-key-0001'
     gateway_token='sk-ant-sentinel-gw-prod-real-8f7a6b5c4d3e2f1a'
GET  /api/admin/stats   -> HTTP 200
POST /api/admin/config  -> HTTP 200，且 .env 被改写为
     LONGCAT_API_KEY="ak_ATTACKER_INJECTED_KEY_777"
```

- `admin_api.py:72` 直接把 `"api_key": raw_key` **明文**返回（`masked_api_key` 算出来了却不用）。
- `admin_api.py:74` 明文返回网关 Token。
- `admin_api.py:81-110` 允许无凭证修改上游 API Key、熔断档位、注入模板，并通过 `save_to_dotenv` 落盘。
- 即便按设计加上 `X-Admin-Token`，该值也已被前端硬编码公开（见 V5）。

### V2. `/v1/*` 认证存在通配放行：任意 `ak_` 开头字符串即通过

`server.py:52`：

```python
or token.startswith("ak_")
```

实测：`Authorization: Bearer ak_totally_made_up_attacker_value` → 通过认证并进入上游转发流程（HTTP 500 是上游不可达，非 401）。

叠加 `anthropic_router.py:71-76` / `openai_router.py:78-84` 的 `auto_persist_key`：攻击者传入的任意 `ak_` 值会被**写入 `.env` 覆盖真实上游密钥**并同时在内存中替换 `config.upstream.api_key`（实测 `.env` 被改写）。

### V3. Token 前缀归一化导致前缀降级匹配

`auth.py:17-22` 的 `TOKEN_PREFIXES` + `normalize_token` 会剥离 `sk-ant-sentinel-` 等前缀，只比较"核心部分"。实测对配置值 `sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a`：

```
sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a -> 通过
gw-8f7a6b5c4d3e2f1a                  -> 通过
sk-gw-8f7a6b5c4d3e2f1a               -> 通过
```

即**知道前缀后的核心串即可通过**；前缀不再是密钥熵的一部分。`tests/test_adversarial_auth.py:511-517` 甚至把这种多前缀接受当作正向用例断言。

### V4. 内置默认凭证（"零明文"防线被配置自身击穿）

- `config.yaml:17-18`：`${SENTINEL_GATEWAY_TOKEN:-sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a}`、`${SENTINEL_ADMIN_TOKEN:-adm-sentinel-99e8d7c6b5a4}`
- `run_gateway.bat:9-19`：同样硬编码这两个 Token，并将上游 Key 设为假值 `sk-meituan-longcat-demo-key`
- `config.py:31-46` 的 `FORBIDDEN_PLAINTEXT_TOKENS` **不包含**上述默认串，`config.py:288` 只检查该集合与 `"placeholder"` 子串

实测：清空两个环境变量后 `load_config(..., dev_mode=False)` 仍成功，Token 等于上述公开默认值。所谓"生产模式严禁弱口令"形同虚设。

### V5. 管理 Token 硬编码在浏览器端 JS，且大屏存在 XSS

- `dashboard.html:780`：`'x-admin-token': 'adm-sentinel-99e8d7c6b5a4'` —— Token 随页面公开。
- `dashboard.html:742 / :804`：`fetch('/api/admin/config')`、`fetch('/api/admin/stats')` **不带任何令牌**，这正是 V1 存在的原因（大屏与鉴权设计自相矛盾）。
- `dashboard.html:815-824`：用模板字符串直接拼 `innerHTML`，`ev.action` 内含熔断 `reason`，而 `reason` 源自**模型输出片段**（`loop_scorer.py:44` 的 `chunk[:30]`）。输出 `<img src=x onerror=...>`（28 字符）即可注入，构成持久型 XSS。

### V6. TLS 校验通过，但服务从不启用 TLS

`config.py` 的 `validate_tls_startup` 会对非环回绑定强制要求 TLS，但 `main.py:63-71` 硬编码 `port = 8080`（忽略 `config.server.port`），且 `uvicorn.run(app, host=host, port=port, log_level="info")` **未传 `ssl_certfile` / `ssl_keyfile`**。

结果：绑定 `0.0.0.0` 且配置了证书时，校验全部通过，服务仍以**明文 HTTP** 监听外网。

### V7. CORS 通配 + 携带凭证，放大 V1

`server.py:21-27`：`allow_origins=["*"]` 且 `allow_credentials=True`。

实测 `GET /api/admin/config` 带 `Origin: https://evil.example.com`：

```
HTTP 200；ACAO = 'https://evil.example.com'；ACAC = 'true'
```

任意网站的 JS 都能读取（无鉴权的）管理接口内容，完整窃取上游 API Key 与网关 Token。

---

## 三、高危缺陷（宣称能力未落地 / 协议不合规）

### V8. 鉴权依赖 `verify_gateway_auth` / `verify_admin_auth` 从未被真实路由使用

`auth.py:174` / `auth.py:226` 实现了 Origin 校验、Host 头 DNS 重绑定防御、常量时间比较。但：

- `server.py:107-113` 的 `/v1/messages`、`/v1/chat/completions` 只挂 `route_*` 函数，**没有 `Depends`**；
- `admin_api.py` 三个端点也没有 `Depends`。

因此**Origin 校验与 Host 白名单在生产中从不执行**。实测：带 `Host: attacker.example.com` 的 `/v1/messages` 请求不被 403 拦截。

反向问题同样存在：`app.state.config` **从未被赋值**（实测 `hasattr(app.state, "config") == False`）。若照搬测试里的写法把依赖挂上，`config` 为 `None` → `gateway_tokens = []` → **所有 `/v1/*` 一律 401**，网关直接瘫痪。

### V9. 安全测试测的是"影子应用"，与真实网关无关

`tests/test_adversarial_auth.py:116-162` 与 `tests/test_config_and_auth.py` 中的 `create_test_gateway_app` 都**自建了一个 FastAPI app**，并手工把 `Depends(verify_gateway_auth)` / `Depends(verify_admin_auth)` 挂在路由上：

```python
@app.post("/v1/messages")
async def v1_messages(token: str = Depends(verify_gateway_auth)): ...
@app.get("/api/admin/metrics")
async def admin_metrics(admin_token: str = Depends(verify_admin_auth)): ...
```

测试套件从不 import `longcat_sentinel.server`。于是"401/403 边界""场景 4 恶意本地攻击防御"等 20+ 个用例全部通过，而**真实应用存在 V1/V2/V8**。这是"103 全通过"的假安全感来源。

### V10. README 的核心卖点在代码中是死代码

| README 宣称 | 实际 |
|---|---|
| 「Tool 6 大能力元与深度命令防御」「毫秒级阻断 `rm -rf /`、`DROP TABLE`」 | `capability_manifest.py`、`parallel_tool_tracker.py` **仅被 `tests/mock_simulator.py` 引用**，生产路由从不调用 |
| 「语义状态增量 LoopScore（文件 Hash / Git 状态变动）」 | `loop_scorer.py:48` 的 `evaluate_tool_state` 从未被调用；`ParallelToolTracker.canonical_hash` 也是死代码 |
| 「思考链分离」 | `parser/stream_fsm.py` 未被任何生产模块导入 |
| 「日志深度脱敏」 | `DeepRedactor` 未被任何生产模块导入（`metrics.py` 直接存原始字符串） |

### V11. 全部策略配置项零生效

在 `longcat_sentinel/` 生产代码中，以下字段**只有 `config.py` 的定义、无任何读取处**（grep 全库确认）：

`profiles.*`（`window_chars`、`fuzzy_*`、`tool_loop_enabled`、`max_duplicate_tool_calls`、`tool_cycle_window`、`think_loop_enabled`、`max_think_chars`）、`immunity.*`、`tool_guard.*`、`limits.*`、`timeouts.time_to_first_token_seconds`、`timeouts.stream_idle_seconds`、`server.workers`、`breaker.active_profile`（仅在大屏展示与校验取值，不影响任何行为）。

具体后果：

- `anthropic_router.py:131` / `openai_router.py:137` 写死 `LoopScorer()` → `min_period=16, repeat_threshold=3`，而 `config.yaml:65` 的 `code_agent` 档是 `repeat_threshold: 4`。**实际阈值比配置更激进**，实测 48 字符（16 字符周期 ×3）即熔断，误杀面比设计更大。
- `ring_buffer.py:9` 写死 2MB，`config.yaml:33` 的 `ring_buffer_bytes` 无效。
- `limits.max_request_body_bytes` 无效：实测发送 **11 MB** 请求体，被**完整转发**给上游（上游收到 11,534,383 字节），网关返回 200，无 413。
- `limits.max_active_streams` 无任何实现，网关无并发保护。
- `timeouts.stream_idle_seconds=30` 无实现，只能依赖 `upstream_timeout_seconds=180`。

### V12. Anthropic 并行工具调用时协议中断不合规（与「0 崩溃」承诺相反）

`anthropic_router.py:157-160`：

```python
elif evt_type == "content_block_stop":
    active_blocks.discard(b_idx)
    has_open_tool = False        # ← 任意块关闭都清空
```

只要**任一**块（例如先关闭的 text 块）发出 `content_block_stop`，`has_open_tool` 就被置 `False`，即使 `tool_use` 块仍处于打开状态。

实测用例（index 0 = text，index 1 = tool_use，上游先发 `content_block_stop index:0`，随后 index 1 陷入循环）：

```
-> 是否补发 partial_json '}' 闭合 = False
-> 直接对 index 1 发出 content_block_stop
```

客户端因此收到未闭合的 `{"cmd": "ls`，工具入参 JSON 解析失败。

同类问题：

- `compliant_injector.py:27-31` 用 `active_block_indices[0]` 当"工具块"（该列表由 `set` 转换而来，顺序不可依赖）；`parallel_tool_tracker.py` 里明明有正确的多轨状态机却未被使用。
- `compliant_injector.py:30` 只补一个 `}`，对 `{"a": [1` 这类部分 JSON 补 `}` 后仍非法，所谓"自动补全合法 JSON 闭合"在逻辑上无法成立。
- `compliant_injector.py:47` 把 `ring.total_tokens_seen` 当作 `usage.output_tokens` 上报，而该值是 `len(text.split())`（`ring_buffer.py:17`）—— 实测写入 22 个中文字符得到 `total_tokens_seen = 1`，中文场景下 token 统计几乎恒为 0。

### V13. 工具能力判定 100% 误杀

`capability_manifest.py:50-53` 把 `terminal` / `execute_command` / `bash` / `shell` 的默认能力标注为**包含 `filesystem_delete`**，而 `capability_manifest.py:87-88` 对含该能力的调用无条件判为 `DESTRUCTIVE`：

```
terminal        {'cmd': 'ls -la'}      -> DESTRUCTIVE->阻断  (Direct filesystem delete capability invoked)
terminal        {'cmd': 'cat README.md'}-> DESTRUCTIVE->阻断
execute_command {'cmd': 'pytest -q'}   -> DESTRUCTIVE->阻断
bash            {'cmd': 'git status'}  -> DESTRUCTIVE->阻断
read_file       {'path': 'a.txt'}      -> READ_ONLY
```

即：一旦接入（见 V10），所有命令行工具调用都会被拦死，与「零误伤」完全相反。`mock_simulator.py:33` 恰好用 `rm -rf /` 作样例，掩盖了这个缺陷。此外 `CapabilityGuard.block_destructive` 从不接收 `tool_guard.block_destructive_patterns` 配置。

### V14. 脱敏引擎对较短密钥完全无效

`redactor.py:32-37` 的密钥正则要求 `sk-` 前缀后至少 4+16 字符。实测：

```
sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a -> sk-ant-sentin****   已脱敏
adm-sentinel-99e8d7c6b5a4            -> adm-sentin****       已脱敏
sk-ant-gw-abc123                     -> 明文泄露!
sk-meituan-demo-key                  -> 明文泄露!
```

`run_gateway.bat:18` 设置的正是 `sk-meituan-longcat-demo-key` 这类较短值 → 会被原样写入日志。

### V15. 其他正确性与健壮性缺陷

| 编号 | 位置 | 问题 |
|---|---|---|
| V15.1 | `anthropic_router.py:94-105`、`openai_router.py:100-111` | 非流式分支只有 `try/finally`、**没有 `except`**。上游连接失败/超时时异常直接冒泡（实测触发 `httpx.ConnectError` 未被转换为 502），而流式分支有对应处理 —— 两分支行为不一致 |
| V15.2 | `anthropic_router.py:58`、`openai_router.py:65` | `json.loads(body_bytes)` 无保护。实测发送 `{not json` → **HTTP 500**（应为 400） |
| V15.3 | `anthropic_router.py:97`、`openai_router.py:103` | 只要请求到达就调用 `record_safe_completion`。实测上游返回 **401** 时，审计日志记录为 `"action": "安全放行", "is_safe": true` |
| V15.4 | `metrics.py:31-35` | `record_request_start` 同时 +1 `active_streams`；若 `StreamingResponse` 生成器未被消费（客户端提前断开/失败），`finally` 不执行导致活跃流计数永久虚高 |
| V15.5 | `ring_buffer.py:21-23`、`:35` | 并非环形缓冲（`del self.buffer[:excess]` 为 O(n) 搬移）；按**字节**截断后 `get_text()` 用 `errors='ignore'` 会**静默丢弃**被切断的多字节字符，中文输出下检测文本与真实输出不一致 |
| V15.6 | `ring_buffer.py:26-32` | 每个词更新 64 位 SimHash，但 `get_fingerprint()` 全项目无调用 —— 纯 CPU 浪费 |
| V15.7 | `server.py:35` | `/docs`、`/openapi.json` 免认证，接口结构对外暴露 |
| V15.8 | `server.py:44`、`anthropic_router.py:69`、`openai_router.py:76` | 用 `replace("Bearer ", "")` 而非仅剥前缀；Token 内部含该子串会被破坏。且真实中间件不识别 `anthropic-api-key` 头（`auth.py:169` 识别） |
| V15.9 | `auth.py:102-149` | `is_allowed_origin` 的 `actual_bound_port`、`is_allowed_host` 的 `bound_port` 参数声明后从未使用 |
| V15.10 | `metrics.py` + `config.server.workers` | 指标为进程内单例，多 worker 下各自计数；`workers` 配置本就不生效，大屏数据仅代表单进程 |

---

## 四、性能缺陷（实测数据）

`anthropic_router.py:171-172` 与 `openai_router.py:178-179` 在**每个 SSE delta** 上执行：

```python
ring.write(text)
is_loop, reason = scorer.check_text_repetition(ring.get_text())   # 解码整个 2MB 缓冲
```

实测（缓冲填满 2 MB 后，300 次采样）：

```
每 token 总开销          = 1.643 ms
  其中 get_text(解码2MB)  = 0.445 ms
  其中 write             = 0.008 ms
  其余为 check_text_repetition 扫描
=> 每 1000 个 token 额外增加约 1.6 s 纯检测延迟（同步阻塞事件循环）
```

这是**同步 CPU 工作直接跑在 asyncio 事件循环上**，会同时拖慢所有并发流；且 `loop_scorer.py:24` 还对整个 2MB 文本做 `text.count("```")`，`loop_scorer.py:31-44` 在 16–200 的周期长度上做字符串切片比较。对长输出（1M 上下文场景）劣化明显。

---

## 五、工程与测试质量问题

1. **测试固化 bug**：`tests/test_adversarial_auth.py:381-382` 断言 `normalize_token("sk--") == "-"`，注释写明"经验证为 bug"，却作为**预期行为**固化，而非修复。
2. **README 数据失真**：`README.md:9` 声称「Tests 77 Passed」，实际 103；README 宣称的 OWASP 硬化与实测绕过矛盾。
3. **断言与文档不符**：`tests/test_config_and_auth.py:737-742` 文档写「256KB <50ms」，断言却是 `assertLess(elapsed, 0.50)`（500 ms，宽松 10 倍）。
4. **硬编码绝对路径**：`config.py:327`、`server.py:73`、`server.py:99`、`web/admin_api.py:17`、`anthropic_router.py:33-35`、`openai_router.py:40-42` 均写入 `E:/桌面/longcat熔断插件/...`。换机器即失效；`config.py:324-328` 还把该绝对路径作为 `config.yaml` 的**兜底候选**，存在加载到非预期目录配置的风险。
5. **5 个子包缺 `__init__.py`**：`breaker/`、`detector/`、`parser/`、`router/`、`web/` 均无（仅 `circuit_breaker/` 有），依赖 PEP 420 隐式命名空间包，PyInstaller `COLLECT` 收集存在隐患，且这些子模块未列入 `LongCatSentinel.spec:9` 的 `hiddenimports`。
6. **`dev_mode` 恒为 False**：`main.py:70` 未向 `load_config` 传 `dev_mode`，`config.py:131-134` 的临时 Token 生成与 `config.py:265-272` 的 dev 分支均为死代码。
7. **未使用导入**：`redactor.py:13` 的 `copy`；`auth.py:13` 的 `Union`；`server.py:8` 的 `is_allowed_origin`、`verify_gateway_token` 之外的 `HTTPException`；`admin_api.py:7` 的 `GatewayConfig`；`parallel_tool_tracker.py:6` 的 `Tuple`；`compliant_injector.py:6` 的 `Dict/Any`；`ring_buffer.py:5-6` 的 `deque/List/Tuple`。

---

## 六、修复优先级建议

**P0（立即修复，否则不可对外提供服务）**

1. 给 `admin_api.py` 三个端点加 `Depends(verify_admin_auth)`；移除 `admin_api.py:72/74` 的明文回显。
2. 删除 `server.py:52` 的 `token.startswith("ak_")` 通配分支。
3. 在 `server.py` 中设置 `app.state.config = config`，并用 `Depends(verify_gateway_auth)` 替换手写中间件鉴权（保留中间件亦可，但需调用同一套校验）。
4. 收敛 CORS：`allow_origins` 取 `config.security.allowed_origins`，去掉 `allow_credentials=True` 与 `"*"` 的组合。
5. 删除 `config.yaml:17-18`、`run_gateway.bat:9-19`、`dashboard.html:780` 中的默认凭证；把上述默认串加入 `FORBIDDEN_PLAINTEXT_TOKENS`；把 `FORBIDDEN_PLAINTEXT_TOKENS` 检查改为**子串/长度/重复度**判定，而非精确匹配。
6. `main.py` 读取 `config.server`（host/port/tls/workers），`tls_enabled` 时向 `uvicorn.run` 传 `ssl_certfile`/`ssl_keyfile`。
7. 移除 `auto_persist_key` 的静默覆盖写 `.env` 行为（或改为仅在显式管理接口中、经鉴权后执行）。

**P1（功能正确性）**

8. 修复 `anthropic_router.py:157-160`：按块类型维护 `has_open_tool`（记录 tool 块 index 集合），接入 `ParallelToolTracker`。
9. 把 `profiles` / `limits` / `timeouts` / `tool_guard` / `immunity` 真正注入 `LoopScorer`、`RingBuffer`、`httpx.Timeout`，并实现请求体上限与并发上限。
10. `capability_manifest.py:50-53`：`terminal`/`bash` 类工具不应默认含 `filesystem_delete`；能力判定改为"按参数内容推断"而非"按工具名一刀切"。
11. 两个路由的非流式分支补 `except`（返回 502）与 `json.loads` 的 400 处理；仅在真正成功时才记 `record_safe_completion`。
12. `dashboard.html:815` 改为 `textContent` 或做 HTML 转义。

**P2（性能与工程）**

13. 熔断检测改为增量式：只对新增片段做周期匹配，避免每 token 解码 2MB；把检测移出事件循环（`run_in_executor` 或分批）。
14. 用真正的环形缓冲（`collections.deque` 或固定容量 `bytearray` + 写指针），去掉逐词 SimHash。
15. 清理硬编码绝对路径；补齐 5 个子包的 `__init__.py` 并加入 spec 的 `hiddenimports`。
16. 重写安全测试：直接 import `longcat_sentinel.server.app` 做端到端断言，删除"影子应用"；修正 `tests/test_adversarial_auth.py:381-382` 的 bug 固化断言。

---

## 七、复现方式

所有动态结论均可在仓库副本中复现（脚本不修改原仓库）：把仓库复制到临时目录，设置 `LONGCAT_API_KEY` / `SENTINEL_GATEWAY_TOKEN` / `SENTINEL_ADMIN_TOKEN`，用 `httpx.ASGITransport(app=longcat_sentinel.server.app)` 调用即可。注意 `auto_persist_key` 会写入 `.env`，务必在副本中运行。
