# ==============================================================================
# LongCat Sentinel - Router Shared Helpers
#
# Logic shared by the Anthropic and OpenAI pipelines: request admission, upstream
# credential resolution, and construction of the detector stack from live config.
# ==============================================================================
from __future__ import annotations

import json
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from ..config import GatewayConfig, ProfileConfig
from ..detector.capability_manifest import CapabilityGuard
from ..detector.loop_scorer import LoopScorer
from ..detector.tool_loop_guard import ToolLoopGuard

# Optional per-request upstream credential override. It is never persisted.
UPSTREAM_KEY_HEADER = "x-upstream-api-key"


def error_response(
    status_code: int, message: str, error_type: str = "invalid_request_error"
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"type": error_type, "message": message}},
    )


def payload_too_large(limit: int) -> JSONResponse:
    return error_response(
        413,
        f"Request body exceeds the configured limit of {limit} bytes",
        "payload_too_large",
    )


def too_many_streams(max_active: int) -> JSONResponse:
    return error_response(
        429,
        f"Too many concurrent streams (limit {max_active}); retry shortly",
        "rate_limit_error",
    )


def bad_gateway(detail: str, protocol: str) -> JSONResponse:
    return error_response(
        502,
        f"网关向上游({protocol})转发失败: {detail}",
        "gateway_upstream_error",
    )


def resolve_profile(config: GatewayConfig) -> ProfileConfig:
    """Resolves the active profile, falling back to code_agent then schema defaults."""
    profile = config.profiles.get(config.breaker.active_profile)
    if profile is None:
        profile = config.profiles.get("code_agent")
    if profile is None:
        profile = ProfileConfig()
    return profile


def build_scorer(profile: ProfileConfig, immunity=None) -> LoopScorer:
    """Builds a detector from the active profile plus the immunity policy."""
    return LoopScorer(
        min_period=profile.min_period_chars,
        repeat_threshold=profile.repeat_threshold,
        window_chars=profile.window_chars,
        fuzzy_enabled=profile.fuzzy_enabled,
        fuzzy_similarity_ratio=profile.fuzzy_similarity_ratio,
        fuzzy_repeat_threshold=profile.fuzzy_repeat_threshold,
        max_period=profile.max_period_chars,
        block_loop_enabled=profile.block_loop_enabled,
        block_repeat_threshold=profile.block_repeat_threshold,
        min_block_chars=profile.min_block_chars,
        self_loop_heuristics_enabled=profile.self_loop_heuristics_enabled,
        self_loop_threshold=profile.self_loop_threshold,
        longcat_reasoning_guard_enabled=profile.longcat_reasoning_guard_enabled,
        longcat_plan_churn_threshold=profile.longcat_plan_churn_threshold,
        longcat_second_guessing_threshold=profile.longcat_second_guessing_threshold,
        longcat_constraint_threshold=profile.longcat_constraint_threshold,
        longcat_min_reasoning_chars=profile.longcat_min_reasoning_chars,
        longcat_memory_search_threshold=profile.longcat_memory_search_threshold,
        longcat_hesitation_threshold=profile.longcat_hesitation_threshold,
        longcat_standalone_hesitation_threshold=profile.longcat_standalone_hesitation_threshold,
        code_block_multiplier=(
            immunity.code_block_multiplier if immunity is not None else 1.5
        ),
        ignore_whitespaces=(
            immunity.ignore_whitespaces if immunity is not None else True
        ),
        ignore_markdown_separators=(
            immunity.ignore_markdown_separators if immunity is not None else True
        ),
    )


def build_capability_guard(config: GatewayConfig) -> CapabilityGuard:
    scan_enabled = (
        config.tool_guard.enable_argument_intent_scan
        and config.tool_guard.block_destructive_patterns
    )
    return CapabilityGuard(block_destructive=scan_enabled)


def build_tool_guard(config: GatewayConfig, profile: ProfileConfig) -> ToolLoopGuard:
    return ToolLoopGuard(
        guard=build_capability_guard(config),
        loop_enabled=profile.tool_loop_enabled,
        max_duplicate_calls=profile.max_duplicate_tool_calls,
        cycle_window=profile.tool_cycle_window,
        freeze_on_destructive=config.tool_guard.action_on_destructive
        == "block_and_freeze",
        tool_skeleton_enabled=profile.tool_skeleton_enabled,
        max_duplicate_skeleton_calls=profile.max_duplicate_skeleton_calls,
    )


def resolve_upstream_key(request: Request, config: GatewayConfig) -> str:
    """
    Returns the upstream credential for this request.

    A caller-supplied override is honoured for this request only: it is never written
    to disk and never replaces the configured key, which previously allowed any
    unauthenticated value starting with `ak_` to hijack the persisted upstream key.
    """
    override = (request.headers.get(UPSTREAM_KEY_HEADER) or "").strip()
    if override:
        return override
    return config.upstream.api_key


def parse_json_body(body_bytes: bytes):
    """Returns (payload, error_response). Exactly one of the two is None."""
    if not body_bytes:
        return {}, None
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, error_response(400, "Request body must be valid UTF-8 JSON")
    if not isinstance(payload, dict):
        return None, error_response(400, "Request body must be a JSON object")
    return payload, None


def too_large_declared(request: Request, limit: int) -> Optional[JSONResponse]:
    """Rejects oversized bodies from the Content-Length header before reading them."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        return payload_too_large(limit)
    return None
