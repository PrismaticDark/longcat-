# ==============================================================================
# LongCat Sentinel - Admin API & Management Routes
#
# Every route below is protected by `Depends(verify_admin_auth)`. The router never
# reads a module-level config object: it uses the configuration carried on
# `app.state`, so a test harness exercises exactly the production wiring.
# ==============================================================================
from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

from .. import __version__
from ..auth import verify_admin_auth

admin_router = APIRouter(prefix="/api/admin")

# Never expose a raw secret through this API.
REDACTED = "[REDACTED]"


def _env_path() -> Path:
    """Location of the .env file that lives beside the project root or the executable."""
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / ".env"
    return Path(__file__).resolve().parent.parent.parent / ".env"


def save_to_dotenv(api_key: str) -> None:
    """Persists the upstream API key into .env without ever embedding a machine path."""
    clean_key = api_key.strip().strip('"').strip("'")
    env_path = _env_path()
    env_path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()

    updated = False
    new_lines = []
    for line in lines:
        if line.strip().startswith("LONGCAT_API_KEY="):
            new_lines.append(f'LONGCAT_API_KEY="{clean_key}"\n')
            updated = True
        else:
            new_lines.append(line)
    if not updated:
        new_lines.append(f'LONGCAT_API_KEY="{clean_key}"\n')

    with open(env_path, "w", encoding="utf-8") as handle:
        handle.writelines(new_lines)


@admin_router.get("/stats")
async def get_stats(request: Request, _admin: str = Depends(verify_admin_auth)):
    from ..metrics import metrics

    snapshot = metrics.get_stats()
    return {
        "status": "healthy",
        "version": __version__,
        "total_requests": snapshot["total_requests"],
        "active_streams": snapshot["active_streams"],
        "tripped_circuits": snapshot["tripped_circuits"],
        "saved_tokens_estimate": snapshot["saved_tokens_estimate"],
        "total_tokens_processed": snapshot.get("total_tokens_processed", 0),
        "upstream_model": request.app.state.config.upstream.default_model,
        "audit_events": snapshot["audit_events"],
    }


@admin_router.get("/config")
async def get_config(request: Request, _admin: str = Depends(verify_admin_auth)):
    config = request.app.state.config

    raw_key = config.upstream.api_key or os.getenv("LONGCAT_API_KEY", "")
    if raw_key:
        masked_key = (
            raw_key[:7] + "..." + raw_key[-4:] if len(raw_key) > 12 else "****"
        )
    else:
        masked_key = ""

    active_p = config.profiles.get(config.breaker.active_profile)

    return {
        "api_key_configured": bool(raw_key),
        "masked_api_key": masked_key,
        "admin_token": "[REDACTED]",
        "gateway_token": "[REDACTED]",
        "upstream_url": config.upstream.base_url,
        "default_model": config.upstream.default_model,
        "active_profile": config.breaker.active_profile,
        "available_profiles": sorted(config.profiles.keys()),
        "bypass_mode": getattr(config, "bypass_mode", False),
        "tool_guard_enabled": getattr(active_p, "tool_loop_enabled", True) if active_p else True,
        "text_guard_enabled": getattr(active_p, "think_loop_enabled", True) if active_p else True,
        "semantic_guard_enabled": getattr(active_p, "semantic_guard_enabled", True) if active_p else True,
        "block_destructive": config.tool_guard.block_destructive_patterns,
        "action_on_destructive": config.tool_guard.action_on_destructive,
        "consecutive_violations_to_trip": config.breaker.consecutive_violations_to_trip,
        "injection_template": config.breaker.injection_template,
        "max_request_body_bytes": config.limits.max_request_body_bytes,
        "max_active_streams": config.limits.max_active_streams,
    }


@admin_router.post("/config")
async def update_config(request: Request, _admin: str = Depends(verify_admin_auth)):
    config = request.app.state.config

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    new_api_key = body.get("api_key")
    new_profile = body.get("active_profile")
    block_destructive = body.get("block_destructive")
    consecutive_violations = body.get("consecutive_violations_to_trip")
    injection_template = body.get("injection_template")
    bypass_mode = body.get("bypass_mode")
    tool_guard_enabled = body.get("tool_guard_enabled")
    text_guard_enabled = body.get("text_guard_enabled")
    semantic_guard_enabled = body.get("semantic_guard_enabled")

    if bypass_mode is not None:
        config.bypass_mode = bool(bypass_mode)

    active_p = config.profiles.get(config.breaker.active_profile)
    if active_p:
        if tool_guard_enabled is not None:
            setattr(active_p, "tool_loop_enabled", bool(tool_guard_enabled))
        if text_guard_enabled is not None:
            setattr(active_p, "think_loop_enabled", bool(text_guard_enabled))
        if semantic_guard_enabled is not None:
            setattr(active_p, "semantic_guard_enabled", bool(semantic_guard_enabled))

    if new_api_key:
        clean_key = str(new_api_key).strip()
        if not clean_key:
            raise HTTPException(status_code=400, detail="api_key must not be blank")
        config.upstream.api_key = clean_key
        os.environ["LONGCAT_API_KEY"] = clean_key
        try:
            save_to_dotenv(clean_key)
        except OSError as exc:
            raise HTTPException(
                status_code=500, detail=f"Failed to persist .env: {exc}"
            )

    if new_profile:
        if new_profile not in config.profiles:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown profile '{new_profile}'. Available: {sorted(config.profiles.keys())}",
            )
        config.breaker.active_profile = new_profile

    if block_destructive is not None:
        config.tool_guard.block_destructive_patterns = bool(block_destructive)

    if consecutive_violations is not None:
        try:
            c_val = int(consecutive_violations)
            if 1 <= c_val <= 5:
                config.breaker.consecutive_violations_to_trip = c_val
        except (ValueError, TypeError):
            pass

    if injection_template:
        template = str(injection_template)
        if "{reason}" not in template:
            raise HTTPException(
                status_code=400,
                detail="injection_template must contain the '{reason}' placeholder",
            )
        config.breaker.injection_template = template

    return {
        "status": "success",
        "message": "配置已成功保存并立即生效！",
        "active_profile": config.breaker.active_profile,
        "bypass_mode": getattr(config, "bypass_mode", False),
    }


@admin_router.post("/toggle-bypass")
async def toggle_bypass(request: Request, _admin: str = Depends(verify_admin_auth)):
    config = request.app.state.config
    current = getattr(config, "bypass_mode", False)
    config.bypass_mode = not current
    return {
        "status": "success",
        "bypass_mode": config.bypass_mode,
        "message": "已切换为纯透明直通转发模式 (Bypass)" if config.bypass_mode else "已恢复全功能智能熔断防御模式 (Active Protection)",
    }


@admin_router.post("/clear-audit")
async def clear_audit_events(_admin: str = Depends(verify_admin_auth)):
    from ..metrics import metrics

    metrics.clear_audit_events()
    return {"status": "success", "message": "审计日志已成功清空！"}
