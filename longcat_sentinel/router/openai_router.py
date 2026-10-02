# ==============================================================================
# LongCat Sentinel - OpenAI Native Router (/v1/chat/completions)
# ==============================================================================
import httpx
import json
import time
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


def normalize_openai_model(raw_model: str) -> str:
    """标准化模型名称，确保符合美团官方集群精确大小写区分 (LongCat-2.5-Preview)"""
    if not raw_model:
        return "LongCat-2.5-Preview"
    m_lower = raw_model.lower().strip()
    if m_lower in ("longcat-2.5-preview", "longcat-2.5", "default", "gpt-3.5-turbo", "gpt-4", "gpt-4o"):
        return "LongCat-2.5-Preview"
    if m_lower in ("longcat-2.0", "longcat-2"):
        return "LongCat-2.0"
    if "2.5" in m_lower:
        return "LongCat-2.5-Preview"
    if "2.0" in m_lower:
        return "LongCat-2.0"
    return raw_model


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


async def route_openai_completions(request: Request, config: GatewayConfig) -> Response:
    body_bytes = await request.body()
    body_json = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
    is_streaming = body_json.get("stream", False)

    # 1. 模型名称大小写归一化
    raw_model = body_json.get("model", "LongCat-2.5-Preview")
    normalized_model = normalize_openai_model(raw_model)
    body_json["model"] = normalized_model
    body_bytes = json.dumps(body_json).encode("utf-8")

    # 2. 凭证透传与自动记忆保存
    client_auth = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    client_token = client_auth.replace("Bearer ", "").replace("bearer ", "").strip()
    upstream_key = config.upstream.api_key
    if client_token.startswith("ak_"):
        upstream_key = client_token
        # 客户端首次传入真实美团 Key 时，网关自动写入配置并落盘保存
        if not config.upstream.api_key or config.upstream.api_key != client_token:
            config.upstream.api_key = client_token
            os.environ["LONGCAT_API_KEY"] = client_token
            auto_persist_key(client_token)
    elif not upstream_key:
        upstream_key = client_token

    # 记录接入请求 (总接管数 +1, 活跃流 +1)
    metrics.record_request_start("OpenAI (/v1/chat/completions)", normalized_model)

    upstream_url = f"{config.upstream.base_url.rstrip('/')}/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {upstream_key}"
    }

    client = httpx.AsyncClient(timeout=config.upstream.upstream_timeout_seconds)

    # 非流式处理
    if not is_streaming:
        try:
            resp = await client.post(upstream_url, content=body_bytes, headers=headers)
            metrics.record_safe_completion("OpenAI (非流式)", normalized_model)
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                media_type=resp.headers.get("content-type", "application/json")
            )
        finally:
            metrics.record_stream_closed()
            await client.aclose()

    # 流式处理：预建请求，检测上游状态码
    req = client.build_request("POST", upstream_url, content=body_bytes, headers=headers)
    try:
        upstream_resp = await client.send(req, stream=True)
    except Exception as e:
        metrics.record_stream_closed()
        await client.aclose()
        err_msg = json.dumps({"error": {"message": f"网关向上游转发失败: {str(e)}", "type": "gateway_upstream_error"}})
        return Response(content=err_msg.encode("utf-8"), status_code=502, media_type="application/json")

    # 若上游直接返回 4xx/5xx 错误，立即返回对应错误码和 JSON，严禁误作为 SSE 流输出
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
        resp_id = "chatcmpl-sentinel"
        has_emitted_finish = False
        tripped = False

        try:
            async for line in upstream_resp.aiter_lines():
                if not line:
                    yield b"\n"
                    continue

                if line.startswith("data: "):
                    raw_data = line[6:].strip()
                    if raw_data == "[DONE]":
                        if not has_emitted_finish and not tripped:
                            # 补全保底 finish_reason: "stop"，防止 DSH 等客户端因缺少 finish_reason 报错
                            fallback_finish = {
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": int(time.time()),
                                "model": normalized_model,
                                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                            }
                            yield f"data: {json.dumps(fallback_finish)}\n\n".encode("utf-8")
                            has_emitted_finish = True
                        yield b"data: [DONE]\n\n"
                        break

                    try:
                        chunk = json.loads(raw_data)
                        resp_id = chunk.get("id", resp_id)
                        choices = chunk.get("choices", [])
                        if choices:
                            choice0 = choices[0]
                            if choice0.get("finish_reason"):
                                has_emitted_finish = True

                            delta = choice0.get("delta", {})
                            # 兼容常规输出与 LongCat 2.5 思考链 (reasoning_content)
                            text_content = delta.get("content", "") or delta.get("reasoning_content", "")
                            if text_content:
                                ring.write(text_content)
                                is_loop, reason = scorer.check_text_repetition(ring.get_text())
                                if is_loop:
                                    tripped = True
                                    # 毫秒级瞬时记录熔断事件，确保无论客户端何时断开大屏均已实时累加
                                    metrics.record_circuit_trip(
                                        protocol="OpenAI (/v1/chat/completions)",
                                        model=normalized_model,
                                        reason=reason,
                                        saved_tokens=4096
                                    )
                                    events = CompliantInjector.build_openai_interruption(
                                        response_id=resp_id,
                                        model=normalized_model,
                                        reason=reason
                                    )
                                    for e in events:
                                        yield e.encode('utf-8')
                                    has_emitted_finish = True
                                    break
                    except Exception:
                        pass

                yield line.encode('utf-8') + b"\n"

            # 上游流正常结束若无 [DONE] 和 finish_reason，安全补齐
            if not has_emitted_finish and not tripped:
                fallback_finish = {
                    "id": resp_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": normalized_model,
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
                }
                yield f"data: {json.dumps(fallback_finish)}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"

        finally:
            if not tripped:
                metrics.record_safe_completion("OpenAI (流式)", normalized_model)
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
