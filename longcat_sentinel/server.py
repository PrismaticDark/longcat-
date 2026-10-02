import os
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from .config import GatewayConfig, load_config
from .auth import verify_gateway_token, verify_token, is_allowed_origin
from .router.anthropic_router import route_anthropic_messages
from .router.openai_router import route_openai_completions
from .web.admin_api import admin_router

load_dotenv()
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

app = FastAPI(title="LongCat Sentinel", version="2.3.0")

config = load_config()

# 跨域配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(admin_router)

@app.middleware("http")
async def security_and_auth_middleware(request: Request, call_next):
    path = request.url.path
    # 静态大屏、Logo与健康检查免认证
    if path in ("/dashboard", "/logo.jpg", "/health", "/docs", "/openapi.json"):
        return await call_next(request)

    # 1. 保护 /v1/* 业务接口强制 Bearer 鉴权
    if path.startswith("/v1/"):
        auth_header = request.headers.get("authorization") or request.headers.get("x-api-key")
        if not auth_header:
            return JSONResponse(status_code=401, content={"error": {"message": "Missing Authorization header", "type": "authentication_error"}})
        
        token = auth_header.replace("Bearer ", "").replace("bearer ", "").strip()
        # 兼容三种凭证校验模式：
        # 1) 网关本地 Token (sk-ant-sentinel-gw-...)
        # 2) 客户端直传美团官方 API Key (ak_...)
        # 3) 配置的上游 API Key 一致性校验
        is_valid = (
            verify_gateway_token(token, config.auth.gateway_tokens)
            or (config.upstream.api_key and verify_token(token, config.upstream.api_key))
            or token.startswith("ak_")
        )
        if not is_valid:
            return JSONResponse(status_code=401, content={"error": {"message": "Invalid Gateway API Token", "type": "authentication_error"}})

    return await call_next(request)

@app.get("/logo.jpg")
async def get_logo_image():
    import sys
    candidates = []
    if getattr(sys, "frozen", False):
        bundle_dir = getattr(sys, "_MEIPASS", "")
        exe_dir = str(Path(sys.executable).parent)
        candidates.extend([
            os.path.join(bundle_dir, "mmexport1790941560209.jpg"),
            os.path.join(bundle_dir, "logo.jpg"),
            os.path.join(exe_dir, "mmexport1790941560209.jpg"),
            os.path.join(exe_dir, "logo.jpg"),
        ])
    candidates.extend([
        "E:/桌面/longcat熔断插件/mmexport1790941560209.jpg",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "mmexport1790941560209.jpg")
    ])
    for p in candidates:
        if os.path.exists(p):
            return FileResponse(p, media_type="image/jpeg")
    return JSONResponse(status_code=404, content={"detail": "Logo image not found"})

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "LongCat Sentinel", "version": "2.3.0"}

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    import sys
    candidates = []
    if getattr(sys, "frozen", False):
        bundle_dir = getattr(sys, "_MEIPASS", "")
        exe_dir = str(Path(sys.executable).parent)
        candidates.extend([
            os.path.join(bundle_dir, "longcat_sentinel", "web", "dashboard.html"),
            os.path.join(bundle_dir, "dashboard.html"),
            os.path.join(exe_dir, "dashboard.html"),
        ])
    candidates.extend([
        os.path.join(os.path.dirname(__file__), "web", "dashboard.html"),
        "E:/桌面/longcat熔断插件/longcat_sentinel/web/dashboard.html"
    ])
    for html_path in candidates:
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                return f.read()
    return "<h1>Dashboard file not found</h1>"

@app.post("/v1/messages")
async def handle_anthropic_messages(request: Request):
    return await route_anthropic_messages(request, config)

@app.post("/v1/chat/completions")
async def handle_openai_completions(request: Request):
    return await route_openai_completions(request, config)

@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {"id": "LongCat-2.5-Preview", "object": "model", "owned_by": "meituan", "display_name": "LongCat-2.5-Preview (1M Context)"},
            {"id": "longcat-2.5-preview", "object": "model", "owned_by": "meituan", "display_name": "longcat-2.5-preview (Alias)"},
            {"id": "LongCat-2.0", "object": "model", "owned_by": "meituan", "display_name": "LongCat-2.0"},
            {"id": "longcat-2.0", "object": "model", "owned_by": "meituan", "display_name": "longcat-2.0 (Alias)"}
        ]
    }

