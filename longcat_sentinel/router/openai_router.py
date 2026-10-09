# ==============================================================================
# LongCat Sentinel - OpenAI Native Router (/v1/chat/completions)
#
# Mirrors the Anthropic pipeline: admission control, decoupled timeouts,
# config-driven detection, incremental loop scoring and real tool-call guarding
# (including streaming `tool_calls` deltas).
# ==============================================================================
from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator, Dict, Optional

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from ..breaker.compliant_injector import CompliantInjector
from ..config import GatewayConfig
from ..detector.parallel_tool_tracker import ParallelToolTracker
from ..detector.ring_buffer import RingBuffer
from ..metrics import metrics
from . import (
    bad_gateway,
    build_scorer,
    build_tool_guard,
    parse_json_body,
    payload_too_large,
    resolve_profile,
    resolve_upstream_key,
    too_large_declared,
    too_many_streams,
)

PROTOCOL_LABEL = "OpenAI (/v1/chat/completions)"
STREAM_BLOCK_LABEL = "OpenAI (流式)"
NONSTREAM_BLOCK_LABEL = "OpenAI (非流式)"

ESTIMATED_SAVED_TOKENS = 4096
CONNECT_TIMEOUT_SECONDS = 15.0
POOL_TIMEOUT_SECONDS = 15.0


def normalize_openai_model(raw_model: str) -> str:
    """标准化模型名称，确保符合美团官方集群精确大小写区分 (LongCat-2.5-Preview)"""
    if not raw_model:
        return "LongCat-2.5-Preview"
    m_lower = str(raw_model).lower().strip()
    if m_lower in ("longcat-2.5-preview", "longcat-2.5", "default", "gpt-3.5-turbo", "gpt-4", "gpt-4o"):
        return "LongCat-2.5-Preview"
    if m_lower in ("longcat-2.0", "longcat-2"):
        return "LongCat-2.0"
    if "2.5" in m_lower:
        return "LongCat-2.5-Preview"
    if "2.0" in m_lower:
        return "LongCat-2.0"
    return raw_model


async def _iter_lines_with_deadlines(
    response: httpx.Response,
    ttft_seconds: float,
    idle_seconds: float,
) -> AsyncGenerator[str, None]:
    """Yields upstream SSE lines with independent first-token and idle budgets."""
    iterator = response.aiter_lines()
    budget = ttft_seconds
    while True:
        try:
            line = await asyncio.wait_for(iterator.__anext__(), timeout=budget)
        except StopAsyncIteration:
            return
        except asyncio.TimeoutError:
            label = "首包(TTFT)" if budget == ttft_seconds else "相邻数据块"
            raise TimeoutError(f"上游{label}超时 ({budget}s)")
        budget = idle_seconds
        yield line


async def route_openai_completions(request: Request, config: GatewayConfig) -> Response:
    limit = config.limits.max_request_body_bytes

    declared = too_large_declared(request, limit)
    if declared is not None:
        return declared

    body_bytes = await request.body()
    if len(body_bytes) > limit:
        return payload_too_large(limit)

    body_json, error = parse_json_body(body_bytes)
    if error is not None:
        return error

    is_streaming = bool(body_json.get("stream", False))

    raw_model = body_json.get("model", "LongCat-2.5-Preview")
    normalized_model = normalize_openai_model(raw_model)
    body_json["model"] = normalized_model
    body_bytes = json.dumps(body_json).encode("utf-8")

    profile = resolve_profile(config)

    if not metrics.acquire_stream(config.limits.max_active_streams):
        return too_many_streams(config.limits.max_active_streams)

    metrics.record_request_start(PROTOCOL_LABEL, normalized_model)

    upstream_key = resolve_upstream_key(request, config)
    upstream_url = f"{config.upstream.base_url.rstrip('/')}/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {upstream_key}",
    }

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=CONNECT_TIMEOUT_SECONDS,
            read=config.timeouts.stream_idle_seconds,
            write=config.upstream.upstream_timeout_seconds,
            pool=POOL_TIMEOUT_SECONDS,
        )
    )

    # 非流式处理
    if not is_streaming:
        try:
            resp = await asyncio.wait_for(
                client.post(upstream_url, content=body_bytes, headers=headers),
                timeout=config.upstream.upstream_timeout_seconds,
            )
        except asyncio.TimeoutError:
            metrics.record_upstream_error(NONSTREAM_BLOCK_LABEL, normalized_model, "timeout")
            return bad_gateway("upstream timeout", "OpenAI")
        except httpx.HTTPError as exc:
            metrics.record_upstream_error(
                NONSTREAM_BLOCK_LABEL, normalized_model, type(exc).__name__
            )
            return bad_gateway(type(exc).__name__, "OpenAI")
        finally:
            metrics.release_stream()
            await client.aclose()

        if resp.status_code < 400:
            metrics.record_safe_completion(NONSTREAM_BLOCK_LABEL, normalized_model)
        else:
            metrics.record_upstream_error(
                NONSTREAM_BLOCK_LABEL, normalized_model, f"HTTP {resp.status_code}"
            )

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )

    # 流式处理
    req = client.build_request("POST", upstream_url, content=body_bytes, headers=headers)
    try:
        upstream_resp = await client.send(req, stream=True)
    except httpx.HTTPError as exc:
        metrics.record_upstream_error(
            STREAM_BLOCK_LABEL, normalized_model, type(exc).__name__
        )
        metrics.release_stream()
        await client.aclose()
        return bad_gateway(type(exc).__name__, "OpenAI")

    if upstream_resp.status_code >= 400:
        err_bytes = await upstream_resp.aread()
        content_type = upstream_resp.headers.get("content-type", "application/json")
        status_code = upstream_resp.status_code
        await upstream_resp.aclose()
        await client.aclose()
        metrics.record_upstream_error(
            STREAM_BLOCK_LABEL, normalized_model, f"HTTP {status_code}"
        )
        metrics.release_stream()
        return Response(
            content=err_bytes, status_code=status_code, media_type=content_type
        )

    async def sse_generator() -> AsyncGenerator[bytes, None]:
        ring = RingBuffer(capacity_bytes=config.limits.ring_buffer_bytes)
        scorer = build_scorer(profile, config.immunity)
        tool_guard = build_tool_guard(config, profile)
        tracker = ParallelToolTracker(guard=tool_guard.guard)

        resp_id = "chatcmpl-sentinel"
        think_chars = 0
        hard_think_cap = max(int(profile.max_think_chars * 2), 32000)
        has_emitted_finish = False
        tripped = False
        stream_finished_normally = False
        trip_reason: Optional[str] = None
        trip_tier = "READ_ONLY"
        highest_tool_tier = "READ_ONLY"

        def fallback_finish_chunk() -> bytes:
            payload = {
                "id": resp_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": normalized_model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            return f"data: {json.dumps(payload)}\n\n".encode("utf-8")

        def finalize_tool_calls() -> Optional[tuple]:
            """Finalizes every open tool call and returns the first violation found."""
            nonlocal highest_tool_tier
            for index in tracker.get_open_indices():
                instance = tracker.finish_tool(index)
                if instance is None:
                    continue
                if instance.safety_tier.value != "READ_ONLY":
                    highest_tool_tier = instance.safety_tier.value
                violation, reason = tool_guard.inspect(
                    instance.name, instance.arguments_buffer
                )
                if violation:
                    return reason or violation, instance.safety_tier.value
            return None

        try:
            async for line in _iter_lines_with_deadlines(
                upstream_resp,
                config.timeouts.time_to_first_token_seconds,
                config.timeouts.stream_idle_seconds,
            ):
                if not line:
                    yield b"\n"
                    continue

                if line.startswith("data: "):
                    raw_data = line[6:].strip()
                    if raw_data == "[DONE]":
                        # 收尾冲洗评估：防范长单段或尾部文本未触发
                        if not tripped:
                            is_loop, reason = scorer.flush()
                            if is_loop:
                                tripped = True
                                trip_reason = reason
                                trip_tier = "READ_ONLY"

                        violation = finalize_tool_calls()
                        if violation:
                            tripped = True
                            trip_reason, trip_tier = violation
                        if not has_emitted_finish and not tripped:
                            yield fallback_finish_chunk()
                            has_emitted_finish = True
                        if tripped:
                            saved_toks = max(1024, 8192 - ring.total_tokens_seen)
                            metrics.record_circuit_trip(
                                protocol=PROTOCOL_LABEL,
                                model=normalized_model,
                                reason=trip_reason or "",
                                saved_tokens=saved_toks,
                                tool_tier=trip_tier,
                            )
                            for event in CompliantInjector.build_openai_interruption(
                                response_id=resp_id,
                                model=normalized_model,
                                reason=trip_reason or "",
                                accumulated_tokens=ring.total_tokens_seen,
                                injection_template=config.breaker.injection_template,
                            ):
                                yield event.encode("utf-8")
                            break
                        stream_finished_normally = True
                        yield b"data: [DONE]\n\n"
                        break

                    try:
                        chunk = json.loads(raw_data)
                    except json.JSONDecodeError:
                        chunk = None

                    if isinstance(chunk, dict):
                        resp_id = chunk.get("id", resp_id)
                        choices = chunk.get("choices") or []
                        if choices:
                            choice0 = choices[0] or {}
                            finish_reason = choice0.get("finish_reason")
                            if finish_reason:
                                has_emitted_finish = True
                                violation = finalize_tool_calls()
                                if violation:
                                    tripped = True
                                    trip_reason, trip_tier = violation

                            delta = choice0.get("delta") or {}

                            # 1) 流式工具调用增量
                            tool_calls = delta.get("tool_calls") or []
                            for position, tool_call in enumerate(tool_calls):
                                if not isinstance(tool_call, dict):
                                    continue
                                call_index = int(tool_call.get("index", position))
                                function = tool_call.get("function") or {}
                                instance = tracker.get_or_start(
                                    call_index,
                                    str(tool_call.get("id", "") or ""),
                                    str(function.get("name", "") or ""),
                                )
                                if instance and instance.safety_tier.value != "READ_ONLY":
                                    highest_tool_tier = instance.safety_tier.value
                                arguments_delta = function.get("arguments")
                                if arguments_delta:
                                    instance.append_arguments(str(arguments_delta))

                            # 2) 文本与思考链增量
                            if not tripped:
                                content = delta.get("content")
                                reasoning = delta.get("reasoning_content")
                                if not isinstance(content, str):
                                    content = ""
                                if not isinstance(reasoning, str):
                                    reasoning = ""

                                if reasoning:
                                    think_chars += len(reasoning)

                                if content and not tripped:
                                    ring.write(content)
                                    is_loop, reason = scorer.feed(content)
                                    if is_loop:
                                        tripped = True
                                        trip_reason = reason
                                        trip_tier = "READ_ONLY"

                                if (
                                    reasoning
                                    and not tripped
                                    and profile.think_loop_enabled
                                ):
                                    ring.write(reasoning)
                                    is_loop, reason = scorer.feed(reasoning)
                                    if is_loop:
                                        tripped = True
                                        trip_reason = reason
                                        trip_tier = "READ_ONLY"
                                    elif think_chars > hard_think_cap:
                                        # 极端超长兜底保护：仅当超过极端安全硬上限且未处于行动就绪状态时才截断
                                        tail_ready = scorer.longcat_guard.is_action_ready(scorer.longcat_guard._tail_window)
                                        if not tail_ready:
                                            tripped = True
                                            trip_reason = (
                                                f"思考链达到极端安全上限保护 ({think_chars} > "
                                                f"{hard_think_cap} chars)"
                                            )
                                            trip_tier = "READ_ONLY"

                        if tripped:
                            saved_toks = max(1024, 8192 - ring.total_tokens_seen)
                            metrics.record_circuit_trip(
                                protocol=PROTOCOL_LABEL,
                                model=normalized_model,
                                reason=trip_reason or "",
                                saved_tokens=saved_toks,
                                tool_tier=trip_tier,
                            )
                            for event in CompliantInjector.build_openai_interruption(
                                response_id=resp_id,
                                model=normalized_model,
                                reason=trip_reason or "",
                                accumulated_tokens=ring.total_tokens_seen,
                                injection_template=config.breaker.injection_template,
                            ):
                                yield event.encode("utf-8")
                            break

                yield line.encode("utf-8") + b"\n"
            else:
                violation = finalize_tool_calls()
                if violation and not tripped:
                    tripped = True
                    trip_reason, trip_tier = violation
                    metrics.record_circuit_trip(
                        protocol=PROTOCOL_LABEL,
                        model=normalized_model,
                        reason=trip_reason or "",
                        saved_tokens=ESTIMATED_SAVED_TOKENS,
                        tool_tier=trip_tier,
                    )
                    for event in CompliantInjector.build_openai_interruption(
                        response_id=resp_id,
                        model=normalized_model,
                        reason=trip_reason or "",
                        injection_template=config.breaker.injection_template,
                    ):
                        yield event.encode("utf-8")
                elif not has_emitted_finish and not tripped:
                    stream_finished_normally = True
                    yield fallback_finish_chunk()
                    yield b"data: [DONE]\n\n"
                else:
                    stream_finished_normally = not tripped

        except asyncio.CancelledError:
            metrics.record_client_cancelled(
                STREAM_BLOCK_LABEL, normalized_model, tool_tier=highest_tool_tier
            )
            raise
        except TimeoutError as exc:
            metrics.record_upstream_error(STREAM_BLOCK_LABEL, normalized_model, str(exc))
        except httpx.HTTPError as exc:
            metrics.record_upstream_error(
                STREAM_BLOCK_LABEL, normalized_model, type(exc).__name__
            )
        finally:
            if stream_finished_normally and not tripped:
                score_desc = f"{scorer.current_score} / 100 (安全)"
                metrics.record_safe_completion(
                    STREAM_BLOCK_LABEL,
                    normalized_model,
                    tool_tier=highest_tool_tier,
                    loop_score=score_desc,
                )
            metrics.release_stream()
            await upstream_resp.aclose()
            await client.aclose()

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
