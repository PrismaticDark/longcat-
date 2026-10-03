"""
tests/support.py
~~~~~~~~~~~~~~~~
Shared test scaffolding.

CRITICAL: this module configures the environment *before* importing
`longcat_sentinel`, then builds the application with the real
`longcat_sentinel.server.create_app` factory. Tests therefore exercise the same
wiring production uses, instead of a hand-assembled look-alike app.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Strong, obviously-fake credentials. All three are mandatory in production mode.
TEST_GATEWAY_TOKEN = "sk-ant-sentinel-gw-TestGatewayToken0123456789abcdef"
TEST_ADMIN_TOKEN = "adm-sentinel-TestAdminToken0123456789abcdef"
TEST_UPSTREAM_KEY = "sk-meituan-testkey-abc123"

def ensure_environment() -> None:
    """
    (Re)installs the mandatory credentials. Called at import time and before every
    config load so a pytest environment-restoring fixture cannot starve a test.
    """
    os.environ["SENTINEL_GATEWAY_TOKEN"] = TEST_GATEWAY_TOKEN
    os.environ["SENTINEL_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
    os.environ["LONGCAT_API_KEY"] = TEST_UPSTREAM_KEY


ensure_environment()

from httpx import ASGITransport, AsyncClient  # noqa: E402

from longcat_sentinel.config import GatewayConfig, load_config  # noqa: E402
from longcat_sentinel.metrics import metrics  # noqa: E402
from longcat_sentinel.server import create_app  # noqa: E402

CONFIG_PATH = PROJECT_ROOT / "config.yaml"


def build_config(dev_mode: bool = False) -> GatewayConfig:
    """Loads the shipped config.yaml through the real loader and validator."""
    ensure_environment()
    return load_config(CONFIG_PATH, dev_mode=dev_mode)


def build_app(config: Optional[GatewayConfig] = None):
    """Creates the real application for the supplied (or shipped) configuration."""
    return create_app(config or build_config())


def make_client(app, base_url: str = "http://127.0.0.1:8080") -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url=base_url,
        timeout=60,
    )


def gateway_headers(token: str = TEST_GATEWAY_TOKEN) -> dict:
    return {"Authorization": f"Bearer {token}"}


def admin_headers(token: str = TEST_ADMIN_TOKEN, extra: Optional[dict] = None) -> dict:
    headers = {"X-Admin-Token": token}
    if extra:
        headers.update(extra)
    return headers


def reset_process_state() -> None:
    """Clears the singleton metrics collector and the tool-loop ledger between tests."""
    from longcat_sentinel.detector.tool_loop_guard import ToolLoopGuard

    metrics.reset()
    ToolLoopGuard.reset()
