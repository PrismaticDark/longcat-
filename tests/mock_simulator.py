# ==============================================================================
# LongCat Sentinel - Mock Simulator & Offline Verification Suite
#
# Zero-cost behavioural smoke test: no network, no API key. Each row exercises the
# same primitives the live routers use.
# ==============================================================================
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from longcat_sentinel.breaker.compliant_injector import CompliantInjector, closing_suffix
from longcat_sentinel.detector.capability_manifest import CapabilityGuard, ToolSafetyTier
from longcat_sentinel.detector.loop_scorer import LoopScorer
from longcat_sentinel.detector.tool_loop_guard import ToolLoopGuard
from longcat_sentinel.parser.stream_fsm import StreamFSM
from longcat_sentinel.auth import verify_gateway_token

console = Console()


def run_all_simulations() -> int:
    console.print(Panel.fit("[bold yellow]LongCat Sentinel v2.3.1 零成本本地死循环仿真测试[/bold yellow]"))
    table = Table(title="测试用例执行结果", style="cyan")
    table.add_column("用例编号", style="bold")
    table.add_column("场景描述")
    table.add_column("预期行为")
    table.add_column("实测结果", style="bold green")

    failures = []

    def record(case_id, description, expectation, passed):
        if not passed:
            failures.append(case_id)
        table.add_row(
            case_id,
            description,
            expectation,
            "● PASS" if passed else "[bold red]FAILED[/bold red]",
        )

    # 1. 文本复读死循环拦截
    scorer = LoopScorer(min_period=10, repeat_threshold=3)
    looping_text = "这是美团大模型陷入循环的一句话。" * 3
    is_loop, _reason = scorer.check_text_repetition(looping_text)
    record("TC-01", "长文本连续周期复读", "精确触发 N-gram 熔断", is_loop)

    # 2. 伪装破坏性命令拦截
    guard = CapabilityGuard()
    tier, _ = guard.inspect_tool_call("terminal", {"cmd": "rm -rf / --no-preserve-root"})
    record("TC-02", "破坏性命令 (rm -rf /)", "判定为 DESTRUCTIVE 阻断", tier == ToolSafetyTier.DESTRUCTIVE)

    # 2b. 正常 shell 命令不得误杀（旧版 100% 误报的回归点）
    benign_tier, _ = guard.inspect_tool_call("terminal", {"cmd": "ls -la"})
    record("TC-02b", "正常命令 (terminal: ls -la)", "不误报为 DESTRUCTIVE", benign_tier != ToolSafetyTier.DESTRUCTIVE)

    # 3. 跨 Chunk 拆分标签 <think> 状态机解析
    fsm = StreamFSM()
    c1, _t1 = fsm.feed_chunk("分析问题：<th")
    c2, t2 = fsm.feed_chunk("ink>正在思考模型循环原因...</think>得出结论。")
    parsed_ok = (c1 == "分析问题：" and t2 == "正在思考模型循环原因..." and c2 == "得出结论。")
    record("TC-03", "跨 Chunk 拆分标签 (<th + ink>)", "有限状态机精准拼合分流", parsed_ok)

    # 4. 流式 Tool 中途中断合规收尾
    fragment = '{"cmd": "ls'
    events = CompliantInjector.build_anthropic_interruption(
        active_block_indices=[0],
        open_tool_blocks={0: fragment},
        reason="Tool Loop Detected",
    )
    joined = "".join(events)
    valid_json = True
    try:
        import json as _json

        _json.loads(fragment + closing_suffix(fragment))
    except Exception:
        valid_json = False
    text_opened = 'content_block_start' in joined and '"type": "text"' in joined
    record("TC-04", "流式 Tool 中途中断协议", "补全合法 JSON 并开独立文本块", valid_json and text_opened)

    # 5. Token 精确匹配（不再做会导致降级匹配的前缀剥离）
    tokens = ["sk-sentinel-gw-12345678abcdef"]
    exact = verify_gateway_token("sk-sentinel-gw-12345678abcdef", tokens)
    degraded = verify_gateway_token("gw-12345678abcdef", tokens)
    record("TC-05", "Token 精确匹配", "完整凭证通过 / 省略前缀被拒绝", exact and not degraded)

    # 6. 重复相同工具调用熔断
    ToolLoopGuard.reset()
    loop_guard = ToolLoopGuard(guard=CapabilityGuard(), max_duplicate_calls=3, cycle_window=8)
    violations = [loop_guard.inspect("read_file", {"path": "a.txt"})[0] for _ in range(4)]
    ToolLoopGuard.reset()
    record("TC-06", "相同工具与入参重复调用", "触发 tool_loop 熔断", "tool_loop" in violations)

    console.print(table)

    if failures:
        console.print(f"\n[bold red]>>> 仿真测试失败: {', '.join(failures)}[/bold red]\n")
        return 1

    console.print("\n[bold green]>>> 全量 6 组核心仿真与安全场景全部通过！[/bold green]\n")
    return 0


if __name__ == "__main__":
    sys.exit(run_all_simulations())
