# ==============================================================================
# LongCat Sentinel - Protocol-Compliant Stream Interrupter & Synthetic Injector
# ==============================================================================
import json
import time
from typing import List, Dict, Any

class CompliantInjector:
    @staticmethod
    def build_anthropic_interruption(
        active_block_indices: List[int],
        has_open_tool_block: bool,
        reason: str,
        accumulated_tokens: int = 0
    ) -> List[str]:
        """
        构建 100% 协议合规的 Anthropic 流式中断事件序列:
        1. 若有打开的 tool_use 块，先补齐合法 JSON '}' 并发出 content_block_stop
        2. 遍历关闭其他所有未关闭块
        3. 开启新 text 块注入中断警告，并合法闭合
        4. 发送带有 stop_reason="end_turn" 的 message_delta 与 message_stop
        """
        events = []
        max_idx = max(active_block_indices) if active_block_indices else 0

        # 1. 安全闭合未完成的工具块
        if has_open_tool_block and active_block_indices:
            tool_idx = active_block_indices[0]
            # 补齐合法空对象或闭合括号
            events.append(f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': tool_idx, 'delta': {'type': 'input_json_delta', 'partial_json': '}'}})}\n\n")
            events.append(f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': tool_idx})}\n\n")

        # 2. 关闭所有其余活动块
        for idx in sorted(active_block_indices, reverse=True):
            if not has_open_tool_block or idx != active_block_indices[0]:
                events.append(f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': idx})}\n\n")

        # 3. 新开独立文本块注入干预系统提示
        new_text_idx = max_idx + 1
        warning_text = f"\n\n[LongCat Sentinel 保护性中断] ⚠️ 检测到模型陷入高频循环（触发原因：{reason}）。网关已安全阻断后续输出，避免无效消耗。请更换工具或调整思路。"
        
        events.append(f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': new_text_idx, 'content_block': {'type': 'text', 'text': ''}})}\n\n")
        events.append(f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': new_text_idx, 'delta': {'type': 'text_delta', 'text': warning_text}})}\n\n")
        events.append(f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': new_text_idx})}\n\n")

        # 4. 合法结束消息
        events.append(f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None}, 'usage': {'output_tokens': accumulated_tokens}})}\n\n")
        events.append("event: message_stop\ndata: {\"type\": \"message_stop\"}\n\n")

        return events

    @staticmethod
    def build_openai_interruption(
        response_id: str,
        model: str,
        reason: str
    ) -> List[str]:
        """
        构建 100% 协议合规的 OpenAI Chat Completions 流式中断 chunk 序列
        """
        warning_text = f"\n\n[LongCat Sentinel 保护性中断] ⚠️ 检测到模型陷入循环（触发原因：{reason}）。网关已保护性截断，避免无效消耗。"
        ts = int(time.time())

        chunk_1 = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": ts,
            "model": model,
            "choices": [{"index": 0, "delta": {"content": warning_text}, "finish_reason": None}]
        }

        chunk_2 = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": ts,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        }

        return [
            f"data: {json.dumps(chunk_1)}\n\n",
            f"data: {json.dumps(chunk_2)}\n\n",
            "data: [DONE]\n\n"
        ]
