# ==============================================================================
# LongCat Sentinel - Application Assembly
#
# Security invariant: every /v1/* route and every /api/admin/* route is protected
# by an explicit FastAPI dependency. There is no path-based auth shortcut, and the
# configuration the dependencies read is the same object the routes use, injected
# through `app.state.config` so tests can exercise the *real* application.
# ==============================================================================
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import __version__
from .auth import verify_gateway_auth
from .config import GatewayConfig, load_config
from .router.anthropic_router import route_anthropic_messages
from .router.openai_router import route_openai_completions
from .web.admin_api import admin_router

load_dotenv()
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

SERVICE_NAME = "LongCat Sentinel"


def resolve_asset(relative_path: str) -> Optional[str]:
    """
    Locates a static asset across source checkouts, PyInstaller onedir and
    PyInstaller onefile layouts. No machine-specific absolute path is ever used.
    """
    candidates = []
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).parent
        bundle_dir = Path(getattr(sys, "_MEIPASS", exe_dir))
        candidates.extend([bundle_dir / relative_path, exe_dir / relative_path])
    project_root = Path(__file__).resolve().parent.parent
    candidates.append(project_root / relative_path)
    candidates.append(Path.cwd() / relative_path)

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def create_app(config: GatewayConfig) -> FastAPI:
    """Builds a fully wired gateway application for the supplied configuration."""
    docs_enabled = bool(config.security.enable_api_docs)
    app = FastAPI(
        title=SERVICE_NAME,
        version=__version__,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    # The authentication dependencies resolve the configuration from application
    # state, so a test harness can inject a real config and exercise real routes.
    app.state.config = config

    # A wildcard origin combined with credentials would let any website read the
    # admin API. Only explicit origins from configuration are ever allowed.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.security.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Admin-Token",
            "X-Api-Key",
            "anthropic-api-key",
            "anthropic-version",
        ],
    )

    app.include_router(admin_router)

    @app.get("/logo.jpg")
    async def get_logo_image():
        path = resolve_asset("mmexport1790941560209.jpg") or resolve_asset("logo.jpg")
        if path:
            return FileResponse(path, media_type="image/jpeg")
        return JSONResponse(status_code=404, content={"detail": "Logo image not found"})

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "service": SERVICE_NAME, "version": __version__}

    @app.get("/dashboard", response_class=HTMLResponse)
    async def serve_dashboard():
        path = resolve_asset("longcat_sentinel/web/dashboard.html") or resolve_asset(
            "dashboard.html"
        )
        if path:
            with open(path, "r", encoding="utf-8") as handle:
                return HTMLResponse(handle.read())
        return HTMLResponse("<h1>Dashboard file not found</h1>", status_code=404)

    @app.post("/v1/messages")
    async def handle_anthropic_messages(
        request: Request, _token: str = Depends(verify_gateway_auth)
    ):
        return await route_anthropic_messages(request, config)

    @app.post("/v1/chat/completions")
    async def handle_openai_completions(
        request: Request, _token: str = Depends(verify_gateway_auth)
    ):
        return await route_openai_completions(request, config)

    @app.get("/v1/models")
    async def list_models(_token: str = Depends(verify_gateway_auth)):
        return {
            "object": "list",
            "data": [
                {
                    "id": "LongCat-2.5-Preview",
                    "object": "model",
                    "owned_by": "meituan",
                    "display_name": "LongCat-2.5-Preview (1M Context)",
                },
                {
                    "id": "longcat-2.5-preview",
                    "object": "model",
                    "owned_by": "meituan",
                    "display_name": "longcat-2.5-preview (Alias)",
                },
                {"id": "LongCat-2.0", "object": "model", "owned_by": "meituan", "display_name": "LongCat-2.0"},
                {"id": "longcat-2.0", "object": "model", "owned_by": "meituan", "display_name": "longcat-2.0 (Alias)"},
            ],
        }

    return app


config = load_config()
app = create_app(config)
