# ==============================================================================
# LongCat Sentinel - Protocol-Compliant Stream Interrupter & Synthetic Injector
#
# The interrupter must leave the client's parser in a valid state: every block that
# was open gets closed, tool-call JSON is completed with the exact suffix that makes
# it parseable, and the message is terminated with the protocol's terminal events.
# ==============================================================================
from __future__ import annotations

import json
import time
from typing import List, Optional

DEFAULT_ANTHROPIC_TEMPLATE = "\n\n[LongCat Sentinel 保护性中断] ⚠️ 检测到输出内容/思考链陷入高频周期循环或触发高危拦截（原因：{reason}）。网关已保护性截断以节约 Token。"
DEFAULT_OPENAI_TEMPLATE = "\n\n[LongCat Sentinel 保护性中断] ⚠️ 检测到模型陷入循环（触发原因：{reason}）。网关已保护性截断，避免无效消耗。"


def render_template(template: Optional[str], reason: str) -> str:
    """Renders the configured injection template, tolerating a missing placeholder."""
    base = template or DEFAULT_ANTHROPIC_TEMPLATE
    try:
        return base.replace("{reason}", str(reason))
    except Exception:
        return DEFAULT_ANTHROPIC_TEMPLATE.replace("{reason}", str(reason))


def closing_suffix(partial_json: str) -> str:
    """
    Computes the exact suffix needed to turn a truncated JSON fragment into valid JSON.

    Handles unclosed strings and nested objects/arrays, so `{"cmd": "ls` becomes
    `{"cmd": "ls"}` instead of the meaningless single `}` an earlier version emitted.
    """
    if not partial_json:
        return ""

    stack: List[str] = []
    in_string = False
    escaped = False

    for ch in partial_json:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            if in_string:
                escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if stack:
                stack.pop()

    suffix = '"' if in_string else ""
    for opener in reversed(stack):
        suffix += "}" if opener == "{" else "]"
    return suffix


class CompliantInjector:
    @staticmethod
    def build_anthropic_interruption(
        active_block_indices: List[int],
        open_tool_blocks: Optional[dict] = None,
        reason: str = "",
        accumulated_tokens: int = 0,
        injection_template: Optional[str] = None,
    ) -> List[str]:
        """
        构建 100% 协议合规的 Anthropic 流式中断事件序列:
        1. 对每个仍在打开状态的 tool_use 块补齐合法 JSON 后缀并 content_block_stop
        2. 关闭其余所有未关闭块
        3. 开启新 text 块注入中断警告，并合法闭合
        4. 发送 message_delta(stop_reason=end_turn) 与 message_stop

        `open_tool_blocks` maps a block index to the argument fragment received so
        far, so the tool-call JSON can be completed with exactly the right suffix.
        """
        events: List[str] = []
        active = sorted(set(active_block_indices or []))
        tool_map = {int(k): (v or "") for k, v in (open_tool_blocks or {}).items()}
        tool_open_set = set(tool_map)

        max_idx = max(active) if active else 0

        # 1. 安全闭合未完成的工具块（补齐 JSON 使其合法）
        for index in sorted(tool_map):
            events.extend(
                CompliantInjector.build_anthropic_tool_closure(index, tool_map[index])
            )

        # 2. 关闭所有其余活动块
        for index in sorted(active, reverse=True):
            if index in tool_open_set:
                continue
            events.append(
                "event: content_block_stop\ndata: "
                + json.dumps({"type": "content_block_stop", "index": index})
                + "\n\n"
            )

        # 3. 新开独立文本块注入干预系统提示
        new_text_idx = max_idx + 1
        warning_text = render_template(injection_template, reason)
        events.append(
            "event: content_block_start\ndata: "
            + json.dumps(
                {
                    "type": "content_block_start",
                    "index": new_text_idx,
                    "content_block": {"type": "text", "text": ""},
                }
            )
            + "\n\n"
        )
        events.append(
            "event: content_block_delta\ndata: "
            + json.dumps(
                {
                    "type": "content_block_delta",
                    "index": new_text_idx,
                    "delta": {"type": "text_delta", "text": warning_text},
                }
            )
            + "\n\n"
        )
        events.append(
            "event: content_block_stop\ndata: "
            + json.dumps({"type": "content_block_stop", "index": new_text_idx})
            + "\n\n"
        )

        # 4. 合法结束消息
        events.append(
            "event: message_delta\ndata: "
            + json.dumps(
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": max(0, int(accumulated_tokens))},
                }
            )
            + "\n\n"
        )
        events.append('event: message_stop\ndata: {"type": "message_stop"}\n\n')

        return events

    @staticmethod
    def build_anthropic_tool_closure(index: int, partial_json: str) -> List[str]:
        """
        Emits the JSON-completing delta + stop event for a single open tool_use block.

        Kept separate so the stream router can close a tool block the moment it detects
        an interruption, using the real accumulated argument fragment.
        """
        events: List[str] = []
        suffix = closing_suffix(partial_json)
        if suffix:
            events.append(
                "event: content_block_delta\ndata: "
                + json.dumps(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "input_json_delta", "partial_json": suffix},
                    }
                )
                + "\n\n"
            )
        events.append(
            "event: content_block_stop\ndata: "
            + json.dumps({"type": "content_block_stop", "index": index})
            + "\n\n"
        )
        return events

    @staticmethod
    def build_openai_interruption(
        response_id: str,
        model: str,
        reason: str,
        accumulated_tokens: int = 0,
        finish_reason: str = "stop",
        injection_template: Optional[str] = None,
    ) -> List[str]:
        """构建 100% 协议合规且携带 usage 统计与明确熔断停止状态的 OpenAI Chat Completions 流式中断 chunk 序列。"""
        warning_text = render_template(
            injection_template or DEFAULT_OPENAI_TEMPLATE, reason
        )
        ts = int(time.time())

        chunk_1: dict = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": ts,
            "model": model,
            "choices": [
                {"index": 0, "delta": {"content": warning_text}, "finish_reason": None}
            ],
        }

        chunk_2: dict = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": ts,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": finish_reason,
                    "stop_reason": "sentinel_circuit_break",
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": max(0, int(accumulated_tokens)),
                "total_tokens": max(0, int(accumulated_tokens)),
            },
        }

        return [
            f"data: {json.dumps(chunk_1)}\n\n",
            f"data: {json.dumps(chunk_2)}\n\n",
            "data: [DONE]\n\n",
        ]
