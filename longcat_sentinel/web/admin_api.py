# ==============================================================================
# LongCat Sentinel - Admin API & Management Routes
# ==============================================================================
import os
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException
from ..config import GatewayConfig
from ..auth import verify_admin_auth, is_allowed_origin

admin_router = APIRouter(prefix="/api/admin")

def save_to_dotenv(api_key: str, gateway_token: str = None):
    """持久化保存 API 密钥至 .env 文件"""
    clean_key = api_key.strip().strip('"').strip("'")
    env_path = Path(__file__).parent.parent.parent / ".env"
    if not env_path.parent.exists():
        env_path = Path("E:/桌面/longcat熔断插件/.env")

    lines = []
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    updated_key = False
    updated_token = False
    new_lines = []

    for line in lines:
        if line.strip().startswith("LONGCAT_API_KEY="):
            new_lines.append(f'LONGCAT_API_KEY="{clean_key}"\n')
            updated_key = True
        elif gateway_token and line.strip().startswith("SENTINEL_GATEWAY_TOKEN="):
            new_lines.append(f'SENTINEL_GATEWAY_TOKEN="{gateway_token}"\n')
            updated_token = True
        else:
            new_lines.append(line)

    if not updated_key:
        new_lines.append(f'LONGCAT_API_KEY="{clean_key}"\n')
    if gateway_token and not updated_token:
        new_lines.append(f'SENTINEL_GATEWAY_TOKEN="{gateway_token}"\n')

    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

@admin_router.get("/stats")
async def get_stats(request: Request):
    from ..server import config
    from ..metrics import metrics
    snapshot = metrics.get_stats()
    return {
        "status": "healthy",
        "version": "2.3.0",
        "total_requests": snapshot["total_requests"],
        "active_streams": snapshot["active_streams"],
        "tripped_circuits": snapshot["tripped_circuits"],
        "saved_tokens_estimate": snapshot["saved_tokens_estimate"],
        "upstream_model": config.upstream.default_model,
        "audit_events": snapshot["audit_events"]
    }

@admin_router.get("/config")
async def get_config(request: Request):
    from ..server import config
    # 获取当前配置供前端展示
    masked_key = ""
    raw_key = config.upstream.api_key or os.getenv("LONGCAT_API_KEY", "")
    if raw_key:
        masked_key = raw_key[:7] + "..." + raw_key[-4:] if len(raw_key) > 12 else raw_key

    return {
        "api_key": raw_key,
        "masked_api_key": masked_key,
        "gateway_token": config.auth.gateway_tokens[0] if config.auth.gateway_tokens else "sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a",
        "upstream_url": config.upstream.base_url,
        "active_profile": config.breaker.active_profile,
        "block_destructive": config.tool_guard.block_destructive_patterns,
        "injection_template": config.breaker.injection_template
    }

@admin_router.post("/config")
async def update_config(request: Request):
    from ..server import config
    origin = request.headers.get("origin", "")
    if origin and not is_allowed_origin(origin):
        raise HTTPException(status_code=403, detail="Cross-origin admin modification forbidden")

    body = await request.json()
    new_api_key = body.get("api_key")
    new_profile = body.get("active_profile")
    block_destructive = body.get("block_destructive")
    injection_template = body.get("injection_template")

    if new_api_key:
        clean_key = new_api_key.strip()
        config.upstream.api_key = clean_key
        os.environ["LONGCAT_API_KEY"] = clean_key
        try:
            save_to_dotenv(clean_key)
        except Exception:
            pass

    if new_profile and new_profile in ("code_agent", "strict", "balanced"):
        config.breaker.active_profile = new_profile

    if block_destructive is not None:
        config.tool_guard.block_destructive_patterns = bool(block_destructive)

    if injection_template:
        config.breaker.injection_template = injection_template

    return {
        "status": "success",
        "message": "配置已成功保存并立即生效！",
        "active_profile": config.breaker.active_profile
    }
