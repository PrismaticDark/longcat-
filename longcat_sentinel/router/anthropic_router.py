# ==============================================================================
# LongCat Sentinel - Anthropic Native Router (/v1/messages)
#
# Responsibilities:
#   * admission control (body size, concurrency)
#   * model normalization
#   * upstream forwarding with decoupled TTFT / idle timeouts
#   * incremental loop detection and tool-call guarding driven by live config
#   * protocol-compliant interruption (every open block is closed correctly)
# ==============================================================================
from __future__ import annotations

import asyncio
import json
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

PROTOCOL_LABEL = "Anthropic (/v1/messages)"
TEXT_BLOCK_LABEL = "Anthropic (流式)"
NONSTREAM_BLOCK_LABEL = "Anthropic (非流式)"

ESTIMATED_SAVED_TOKENS = 4096
CONNECT_TIMEOUT_SECONDS = 15.0
POOL_TIMEOUT_SECONDS = 15.0


def normalize_anthropic_model(raw_model: str) -> str:
    """标准化 Anthropic 模型名称为美团 LongCat 官方集群标识"""
    if not raw_model:
        return "LongCat-2.5-Preview"
    m_lower = str(raw_model).lower().strip()
    if "2.0" in m_lower:
        return "LongCat-2.0"
    return "LongCat-2.5-Preview"


async def _iter_lines_with_deadlines(
    response: httpx.Response,
    ttft_seconds: float,
    idle_seconds: float,
) -> AsyncGenerator[str, None]:
    """
    Yields upstream SSE lines, enforcing a dedicated time-to-first-token budget and a
    per-chunk idle budget. The idle budget is the one advertised as
    `timeouts.stream_idle_seconds`; previously only a single 180s httpx timeout existed.
    """
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


async def route_anthropic_messages(request: Request, config: GatewayConfig) -> Response:
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

    # 1. 模型标准化
    raw_model = body_json.get("model", "LongCat-2.5-Preview")
    normalized_model = normalize_anthropic_model(raw_model)
    body_json["model"] = normalized_model
    body_bytes = json.dumps(body_json).encode("utf-8")

    profile = resolve_profile(config)

    # 2. 并发准入（原子计数，_流_结束后释放）
    if not metrics.acquire_stream(config.limits.max_active_streams):
        return too_many_streams(config.limits.max_active_streams)

    metrics.record_request_start(PROTOCOL_LABEL, normalized_model)

    upstream_key = resolve_upstream_key(request, config)
    upstream_url = f"{config.upstream.base_url.rstrip('/')}/anthropic/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {upstream_key}",
        "x-api-key": upstream_key,
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
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
            return bad_gateway("upstream timeout", "Anthropic")
        except httpx.HTTPError as exc:
            metrics.record_upstream_error(
                NONSTREAM_BLOCK_LABEL, normalized_model, type(exc).__name__
            )
            return bad_gateway(type(exc).__name__, "Anthropic")
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
        metrics.record_upstream_error(TEXT_BLOCK_LABEL, normalized_model, type(exc).__name__)
        metrics.release_stream()
        await client.aclose()
        return bad_gateway(type(exc).__name__, "Anthropic")

    # 上游返回非成功状态码时，原样作为 JSON 响应返回，绝不当作 SSE 流输出
    if upstream_resp.status_code >= 400:
        err_bytes = await upstream_resp.aread()
        content_type = upstream_resp.headers.get("content-type", "application/json")
        status_code = upstream_resp.status_code
        await upstream_resp.aclose()
        await client.aclose()
        metrics.record_upstream_error(
            TEXT_BLOCK_LABEL, normalized_model, f"HTTP {status_code}"
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

        active_blocks: set = set()
        block_types: Dict[int, str] = {}

        think_chars = 0
        tripped = False
        stream_finished_normally = False
        trip_reason: Optional[str] = None
        trip_tier = "READ_ONLY"

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
                        stream_finished_normally = True
                        yield line.encode("utf-8") + b"\n\n"
                        break

                    try:
                        evt = json.loads(raw_data)
                    except json.JSONDecodeError:
                        evt = None

                    if isinstance(evt, dict):
                        evt_type = evt.get("type", "")

                        if evt_type == "content_block_start":
                            block_index = int(evt.get("index", 0))
                            block = evt.get("content_block") or {}
                            block_type = str(block.get("type", ""))
                            active_blocks.add(block_index)
                            block_types[block_index] = block_type
                            if block_type == "tool_use":
                                tracker.start_tool(
                                    block_index,
                                    str(block.get("id", "")),
                                    str(block.get("name", "")),
                                )

                        elif evt_type == "content_block_stop":
                            block_index = int(evt.get("index", 0))
                            if block_types.get(block_index) == "tool_use":
                                instance = tracker.finish_tool(block_index)
                                if instance is not None:
                                    violation, reason = tool_guard.inspect(
                                        instance.name, instance.arguments_buffer
                                    )
                                    if violation:
                                        tripped = True
                                        trip_reason = reason or violation
                                        trip_tier = instance.safety_tier.value
                            active_blocks.discard(block_index)

                        elif evt_type == "content_block_delta":
                            block_index = int(evt.get("index", 0))
                            delta = evt.get("delta") or {}
                            delta_type = delta.get("type")

                            if delta_type == "input_json_delta":
                                tracker.append_chunk(
                                    block_index, str(delta.get("partial_json", ""))
                                )
                            else:
                                if delta_type == "text_delta":
                                    text = str(delta.get("text", ""))
                                elif delta_type == "thinking_delta":
                                    text = str(delta.get("thinking", ""))
                                else:
                                    text = ""

                                if text:
                                    if delta_type == "thinking_delta":
                                        think_chars += len(text)
                                        if (
                                            profile.think_loop_enabled
                                            and think_chars > profile.max_think_chars
                                        ):
                                            tripped = True
                                            trip_reason = (
                                                f"思考链超长 ({think_chars} > "
                                                f"{profile.max_think_chars} chars)"
                                            )
                                            trip_tier = "READ_ONLY"

                                    if not tripped:
                                        ring.write(text)
                                        if delta_type == "text_delta" or (
                                            delta_type == "thinking_delta"
                                            and profile.think_loop_enabled
                                        ):
                                            is_loop, reason = scorer.feed(text)
                                            if is_loop:
                                                tripped = True
                                                trip_reason = reason
                                                trip_tier = "READ_ONLY"

                        if tripped:
                            metrics.record_circuit_trip(
                                protocol=PROTOCOL_LABEL,
                                model=normalized_model,
                                reason=trip_reason or "",
                                saved_tokens=ESTIMATED_SAVED_TOKENS,
                                tool_tier=trip_tier,
                            )
                            open_tool_blocks = {
                                idx: (
                                    tracker.active_tools[idx].arguments_buffer
                                    if idx in tracker.active_tools
                                    else ""
                                )
                                for idx in tracker.get_open_tool_indices()
                            }
                            events = CompliantInjector.build_anthropic_interruption(
                                active_block_indices=list(active_blocks),
                                open_tool_blocks=open_tool_blocks,
                                reason=trip_reason or "",
                                accumulated_tokens=ring.total_tokens_seen,
                                injection_template=config.breaker.injection_template,
                            )
                            for event in events:
                                yield event.encode("utf-8")
                            break

                yield line.encode("utf-8") + b"\n"
            else:
                stream_finished_normally = True

        except TimeoutError as exc:
            metrics.record_upstream_error(TEXT_BLOCK_LABEL, normalized_model, str(exc))
        except httpx.HTTPError as exc:
            metrics.record_upstream_error(
                TEXT_BLOCK_LABEL, normalized_model, type(exc).__name__
            )
        finally:
            if stream_finished_normally and not tripped:
                metrics.record_safe_completion(TEXT_BLOCK_LABEL, normalized_model)
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
