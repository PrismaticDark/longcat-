# ==============================================================================
# LongCat Sentinel - Anthropic Native Router (/v1/messages)
# ==============================================================================
import httpx
import json
import os
from pathlib import Path
from typing import AsyncGenerator
from fastapi import Request, Response
from fastapi.responses import StreamingResponse
from ..config import GatewayConfig
from ..breaker.compliant_injector import CompliantInjector
from ..detector.loop_scorer import LoopScorer
from ..detector.ring_buffer import RingBuffer
from ..metrics import metrics


def normalize_anthropic_model(raw_model: str) -> str:
    """标准化 Anthropic 模型名称为美团 LongCat 官方集群标识"""
    if not raw_model:
        return "LongCat-2.5-Preview"
    m_lower = raw_model.lower().strip()
    if "2.0" in m_lower:
        return "LongCat-2.0"
    return "LongCat-2.5-Preview"


def auto_persist_key(api_key: str):
    """自动将客户端传入的有效美团 API Key 持久化到 .env 文件中"""
    if not api_key or not api_key.startswith("ak_"):
        return
    try:
        env_path = Path(__file__).parent.parent.parent / ".env"
        if not env_path.parent.exists():
            env_path = Path("E:/桌面/longcat熔断插件/.env")
        lines = []
        if env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        updated = False
        new_lines = []
        for line in lines:
            if line.strip().startswith("LONGCAT_API_KEY="):
                new_lines.append(f'LONGCAT_API_KEY="{api_key}"\n')
                updated = True
            else:
                new_lines.append(line)
        if not updated:
            new_lines.append(f'LONGCAT_API_KEY="{api_key}"\n')
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except Exception:
        pass


async def route_anthropic_messages(request: Request, config: GatewayConfig) -> Response:
    body_bytes = await request.body()
    body_json = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
    is_streaming = body_json.get("stream", False)

    # 1. 模型标准化
    raw_model = body_json.get("model", "LongCat-2.5-Preview")
    normalized_model = normalize_anthropic_model(raw_model)
    body_json["model"] = normalized_model
    body_bytes = json.dumps(body_json).encode("utf-8")

    # 2. 凭证透传与自动持久化
    client_auth = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    client_token = client_auth.replace("Bearer ", "").replace("bearer ", "").strip()
    upstream_key = config.upstream.api_key
    if client_token.startswith("ak_"):
        upstream_key = client_token
        if not config.upstream.api_key or config.upstream.api_key != client_token:
            config.upstream.api_key = client_token
            os.environ["LONGCAT_API_KEY"] = client_token
            auto_persist_key(client_token)
    elif not upstream_key:
        upstream_key = client_token

    # 记录接入请求 (总接管数 +1, 活跃流 +1)
    metrics.record_request_start("Anthropic (/v1/messages)", normalized_model)

    upstream_url = f"{config.upstream.base_url.rstrip('/')}/anthropic/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {upstream_key}",
        "x-api-key": upstream_key,
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01")
    }

    client = httpx.AsyncClient(timeout=config.upstream.upstream_timeout_seconds)

    # 非流式处理
    if not is_streaming:
        try:
            resp = await client.post(upstream_url, content=body_bytes, headers=headers)
            metrics.record_safe_completion("Anthropic (非流式)", normalized_model)
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type=resp.headers.get("content-type", "application/json")
            )
        finally:
            metrics.record_stream_closed()
            await client.aclose()

    # 流式处理
    req = client.build_request("POST", upstream_url, content=body_bytes, headers=headers)
    try:
        upstream_resp = await client.send(req, stream=True)
    except Exception as e:
        metrics.record_stream_closed()
        await client.aclose()
        err_msg = json.dumps({"error": {"message": f"网关向 Anthropic 上游转发失败: {str(e)}", "type": "gateway_upstream_error"}})
        return Response(content=err_msg.encode("utf-8"), status_code=502, media_type="application/json")

    # 若上游返回非 200 状态码，直接作为 JSON 响应返回
    if upstream_resp.status_code != 200:
        metrics.record_stream_closed()
        err_bytes = await upstream_resp.aread()
        await upstream_resp.aclose()
        await client.aclose()
        return Response(
            content=err_bytes,
            status_code=upstream_resp.status_code,
            media_type=upstream_resp.headers.get("content-type", "application/json")
        )

    async def sse_generator() -> AsyncGenerator[bytes, None]:
        ring = RingBuffer()
        scorer = LoopScorer()
        active_blocks = set()
        has_open_tool = False
        tripped = False

        try:
            async for line in upstream_resp.aiter_lines():
                if not line:
                    yield b"\n"
                    continue

                if line.startswith("data: "):
                    raw_data = line[6:].strip()
                    if raw_data == "[DONE]":
                        yield line.encode('utf-8') + b"\n\n"
                        break
                    try:
                        evt = json.loads(raw_data)
                        evt_type = evt.get("type", "")

                        if evt_type == "content_block_start":
                            b_idx = evt.get("index", 0)
                            active_blocks.add(b_idx)
                            if evt.get("content_block", {}).get("type") == "tool_use":
                                has_open_tool = True

                        elif evt_type == "content_block_stop":
                            b_idx = evt.get("index", 0)
                            active_blocks.discard(b_idx)
                            has_open_tool = False

                        elif evt_type == "content_block_delta":
                            delta = evt.get("delta", {})
                            text = ""
                            if delta.get("type") == "text_delta":
                                text = delta.get("text", "")
                            elif delta.get("type") == "thinking_delta":
                                text = delta.get("thinking", "")
                            
                            if text:
                                ring.write(text)
                                is_loop, reason = scorer.check_text_repetition(ring.get_text())
                                if is_loop:
                                    tripped = True
                                    # 毫秒级瞬时记录熔断事件
                                    metrics.record_circuit_trip(
                                        protocol="Anthropic (/v1/messages)",
                                        model=normalized_model,
                                        reason=reason,
                                        saved_tokens=4096
                                    )
                                    events = CompliantInjector.build_anthropic_interruption(
                                        active_block_indices=list(active_blocks),
                                        has_open_tool_block=has_open_tool,
                                        reason=reason,
                                        accumulated_tokens=ring.total_tokens_seen
                                    )
                                    for e in events:
                                        yield e.encode('utf-8')
                                    break
                    except Exception:
                        pass

                yield line.encode('utf-8') + b"\n"
        finally:
            if not tripped:
                metrics.record_safe_completion("Anthropic (流式)", normalized_model)
            metrics.record_stream_closed()
            await upstream_resp.aclose()
            await client.aclose()

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
