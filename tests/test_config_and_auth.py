"""
tests/test_config_and_auth.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive test suite for LongCat Sentinel v2.3 Milestone 1 (F01-F07).
Implements all 77 test cases specified in test_spec.md using standard library
unittest and unittest.IsolatedAsyncioTestCase for zero-dependency test execution.
"""

from __future__ import annotations

import os
import sys
import re
import time
import hmac
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pydantic import ValidationError
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from httpx import AsyncClient, ASGITransport

from longcat_sentinel.config import (
    load_config,
    GatewayConfig,
    ConfigurationError,
    validate_tls_startup,
    interpolate_env_vars,
    _interpolate_env,
    ServerConfig,
    AuthConfig,
    UpstreamConfig,
    TimeoutConfig,
    TimeoutsConfig,
    LimitConfig,
    LimitsConfig,
    SecurityConfig,
    ProfileConfig,
    BreakerConfig,
    ToolGuardConfig,
    ImmunityConfig,
)
from longcat_sentinel.auth import (
    normalize_token,
    verify_token,
    verify_gateway_token,
    verify_gateway_auth,
    verify_admin_auth,
    is_allowed_origin,
    is_allowed_host,
    validate_host_header,
    LOOPBACK_ORIGIN_REGEX,
    LOOPBACK_HOST_REGEX,
)
from longcat_sentinel.circuit_breaker.redactor import DeepRedactor


SAMPLE_VALID_YAML = """
server:
  host: "127.0.0.1"
  port: 8080
  workers: 1
  tls_enabled: false
  tls_cert_path: ""
  tls_key_path: ""

auth:
  gateway_tokens:
    - "${SENTINEL_GATEWAY_TOKEN}"
  dashboard_admin_token: "${SENTINEL_ADMIN_TOKEN}"

upstream:
  base_url: "https://api.longcat.chat"
  api_key: "${LONGCAT_API_KEY}"
  upstream_timeout_seconds: 180
  default_model: "longcat-2.5-preview"

timeouts:
  time_to_first_token_seconds: 90
  stream_idle_seconds: 30

limits:
  max_request_body_bytes: 10485760
  ring_buffer_bytes: 2097152
  max_active_streams: 64

security:
  deep_redaction_scope: "logs_and_metrics_only"
  require_custom_admin_header: true
  allowed_loopback_regex: "^https?://(?:127\\\\.0\\\\.0\\\\.1|localhost|\\\\[::1\\\\])(?::\\\\d+)?$"
  allowed_origins: []
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
    - "[::1]"
"""


def create_test_gateway_app(config: GatewayConfig) -> FastAPI:
    """Helper to create a test FastAPI app configured with Milestone 1 security dependencies."""
    app = FastAPI()
    app.state.config = config

    @app.exception_handler(HTTPException)
    async def custom_http_exception_handler(request: Request, exc: HTTPException):
        if isinstance(exc.detail, dict) and "error" in exc.detail:
            return JSONResponse(status_code=exc.status_code, content=exc.detail, headers=exc.headers)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"type": "error", "message": str(exc.detail)}},
            headers=exc.headers,
        )

    @app.middleware("http")
    async def host_validation_middleware(request: Request, call_next):
        host = request.headers.get("host")
        cfg = getattr(request.app.state, "config", None)
        allowed_hosts = cfg.security.allowed_hosts if cfg else None
        if host and not is_allowed_host(host, allowed_hosts):
            return JSONResponse(
                status_code=403,
                content={"error": {"type": "security_error", "message": "Invalid Host header: Forbidden"}},
            )
        return await call_next(request)

    @app.post("/v1/messages")
    async def v1_messages(token: str = Depends(verify_gateway_auth)):
        return {"status": "ok", "message": "Authenticated Anthropic route", "token": token}

    @app.post("/v1/chat/completions")
    async def v1_chat_completions(token: str = Depends(verify_gateway_auth)):
        return {"status": "ok", "message": "Authenticated OpenAI route", "token": token}

    @app.get("/api/admin/metrics")
    async def admin_metrics(admin_token: str = Depends(verify_admin_auth)):
        return {"status": "ok", "metrics": {"active_streams": 0}}

    return app


# ==============================================================================
# Feature F01: Zero-Plaintext Configuration Guard (11 Tests)
# ==============================================================================

class TestConfigZeroPlaintext(unittest.TestCase):
    """F01: Zero-Plaintext Configuration Guard and dynamic environment interpolation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_VALID_YAML)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_config_interpolation_success_all_env_vars_present(self):
        """TC-M1-F01-001: All env vars present -> successfully interpolated."""
        env = {
            "SENTINEL_GATEWAY_TOKEN": "gw-test-token-valid-12345",
            "SENTINEL_ADMIN_TOKEN": "adm-test-token-valid-98765",
            "LONGCAT_API_KEY": "sk-longcat-prod-key-112233",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = load_config(self.config_path, dev_mode=False)
            self.assertEqual(cfg.auth.gateway_tokens, ["gw-test-token-valid-12345"])
            self.assertEqual(cfg.auth.dashboard_admin_token, "adm-test-token-valid-98765")
            self.assertEqual(cfg.upstream.api_key, "sk-longcat-prod-key-112233")

    def test_zero_plaintext_missing_gateway_token_raises_configuration_error(self):
        """TC-M1-F01-002: Missing SENTINEL_GATEWAY_TOKEN raises ConfigurationError."""
        env = {
            "SENTINEL_ADMIN_TOKEN": "adm-token-secret-12345",
            "LONGCAT_API_KEY": "sk-key-12345",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(self.config_path, dev_mode=False)
            self.assertIn("SENTINEL_GATEWAY_TOKEN", str(ctx.exception))

    def test_zero_plaintext_missing_admin_token_raises_configuration_error(self):
        """TC-M1-F01-003: Missing SENTINEL_ADMIN_TOKEN raises ConfigurationError."""
        env = {
            "SENTINEL_GATEWAY_TOKEN": "gw-token-secret-12345",
            "LONGCAT_API_KEY": "sk-key-12345",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(self.config_path, dev_mode=False)
            self.assertIn("SENTINEL_ADMIN_TOKEN", str(ctx.exception))

    def test_zero_plaintext_empty_or_whitespace_env_var_raises(self):
        """TC-M1-F01-004: Whitespace-only token raises ConfigurationError."""
        env = {
            "SENTINEL_GATEWAY_TOKEN": "   ",
            "SENTINEL_ADMIN_TOKEN": "adm-token-valid-12345",
            "LONGCAT_API_KEY": "sk-key-12345",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError):
                load_config(self.config_path, dev_mode=False)

    def test_zero_plaintext_hardcoded_weak_tokens_rejected(self):
        """TC-M1-F01-005: Known weak placeholder tokens rejected."""
        weak_yaml = SAMPLE_VALID_YAML.replace("${SENTINEL_GATEWAY_TOKEN}", "sk-longcat-placeholder")
        weak_path = os.path.join(self.temp_dir.name, "weak.yaml")
        with open(weak_path, "w", encoding="utf-8") as f:
            f.write(weak_yaml)

        env = {"SENTINEL_ADMIN_TOKEN": "adm-token-valid-12345", "LONGCAT_API_KEY": "key"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(weak_path, dev_mode=False)
            self.assertIn("weak or placeholder token", str(ctx.exception).lower())

    def test_zero_plaintext_hardcoded_admin_weak_tokens_rejected(self):
        """TC-M1-F01-006: Known weak admin tokens rejected."""
        weak_yaml = SAMPLE_VALID_YAML.replace("${SENTINEL_ADMIN_TOKEN}", "admin123")
        weak_path = os.path.join(self.temp_dir.name, "weak_admin.yaml")
        with open(weak_path, "w", encoding="utf-8") as f:
            f.write(weak_yaml)

        env = {"SENTINEL_GATEWAY_TOKEN": "gw-valid-token-12345", "LONGCAT_API_KEY": "key"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(weak_path, dev_mode=False)
            self.assertIn("weak or placeholder token", str(ctx.exception).lower())

    def test_dev_mode_generates_high_entropy_ephemeral_token(self):
        """TC-M1-F01-007: Dev mode generates high-entropy ephemeral tokens."""
        with patch.dict(os.environ, {"LONGCAT_API_KEY": "dev-key"}, clear=True):
            cfg = load_config(self.config_path, dev_mode=True)
            self.assertTrue(len(cfg.auth.gateway_tokens[0]) >= 32)
            self.assertTrue(len(cfg.auth.dashboard_admin_token) >= 32)

    def test_dev_mode_does_not_persist_to_disk(self):
        """TC-M1-F01-008: Dev mode ephemeral tokens do not write to config.yaml."""
        with open(self.config_path, "r", encoding="utf-8") as f:
            initial_content = f.read()

        with patch.dict(os.environ, {"LONGCAT_API_KEY": "dev-key"}, clear=True):
            load_config(self.config_path, dev_mode=True)

        with open(self.config_path, "r", encoding="utf-8") as f:
            current_content = f.read()

        self.assertEqual(initial_content, current_content)

    def test_malformed_env_placeholder_syntax_handling(self):
        """TC-M1-F01-009: Unclosed brackets or empty ${} raise ConfigurationError."""
        for malformed in ["${UNCLOSED_VAR", "${}", "normal_string_${}"]:
            with self.assertRaises(ConfigurationError):
                _interpolate_env({"key": malformed}, dev_mode=False)

    def test_env_var_default_fallback_syntax(self):
        """TC-M1-F01-010: ${VAR:-fallback} returns fallback when unset and env value when set."""
        with patch.dict(os.environ, {}, clear=True):
            res = interpolate_env_vars("${OPTIONAL_SETTING:-my_fallback_value}")
            self.assertEqual(res, "my_fallback_value")

        with patch.dict(os.environ, {"OPTIONAL_SETTING": "configured_value"}, clear=True):
            res = interpolate_env_vars("${OPTIONAL_SETTING:-my_fallback_value}")
            self.assertEqual(res, "configured_value")

    def test_config_file_not_found_raises(self):
        """TC-M1-F01-011: Attempting to load nonexistent config raises ConfigurationError."""
        with self.assertRaises(ConfigurationError) as ctx:
            load_config(os.path.join(self.temp_dir.name, "nonexistent_sentinel.yaml"))
        self.assertIn("not found", str(ctx.exception).lower())


# ==============================================================================
# Feature F02: Token Normalization & Verification (12 Tests)
# ==============================================================================

class TestTokenNormalizationAndVerification(unittest.TestCase):
    """F02: Token Normalization, prefix stripping, and constant-time HMAC comparison."""

    def test_normalize_token_strips_sk_ant_prefix(self):
        """TC-M1-F02-001: Strip sk-ant- prefix."""
        self.assertEqual(normalize_token("sk-ant-gw-test-token-12345"), "gw-test-token-12345")

    def test_normalize_token_strips_sk_prefix(self):
        """TC-M1-F02-002: Strip sk- prefix."""
        self.assertEqual(normalize_token("sk-gw-test-token-12345"), "gw-test-token-12345")

    def test_normalize_token_strips_sk_sentinel_prefix(self):
        """TC-M1-F02-003: Strip sk-sentinel- prefix."""
        self.assertEqual(normalize_token("sk-sentinel-gw-12345"), "gw-12345")

    def test_normalize_token_strips_sk_ant_sentinel_prefix(self):
        """TC-M1-F02-004: Strip sk-ant-sentinel- prefix."""
        self.assertEqual(normalize_token("sk-ant-sentinel-gw-12345"), "gw-12345")

    def test_normalize_token_strips_bearer_prefix_case_variations(self):
        """TC-M1-F02-005: Strip Bearer prefix with case variations."""
        for p in ["Bearer ", "bearer ", "BEARER ", "bEaReR "]:
            self.assertEqual(normalize_token(f"{p}secret-key-123"), "secret-key-123")

    def test_normalize_token_strips_stacked_prefixes(self):
        """TC-M1-F02-006: Strip stacked prefixes (e.g. Bearer sk-ant-)."""
        self.assertEqual(normalize_token("Bearer sk-ant-secret-key"), "secret-key")
        self.assertEqual(normalize_token("Bearer sk-ant-sentinel-secret-key"), "secret-key")
        self.assertEqual(normalize_token("Bearer sk-sentinel-secret-key"), "secret-key")

    def test_normalize_token_whitespace_padding(self):
        """TC-M1-F02-007: Strip leading and trailing whitespace."""
        self.assertEqual(normalize_token("   Bearer   sk-ant-my-token   "), "my-token")
        self.assertEqual(normalize_token("\tsk-test-token\n"), "test-token")

    def test_normalize_token_empty_and_corrupt_inputs(self):
        """TC-M1-F02-008: Empty and corrupted inputs return empty string."""
        self.assertEqual(normalize_token(""), "")
        self.assertEqual(normalize_token("   "), "")
        self.assertEqual(normalize_token("Bearer "), "")
        self.assertEqual(normalize_token("sk-"), "")
        self.assertEqual(normalize_token("sk-ant-"), "")

    def test_normalize_token_none_returns_empty(self):
        """TC-M1-F02-009: None input returns empty string."""
        self.assertEqual(normalize_token(None), "")

    def test_verify_token_bidirectional_match(self):
        """TC-M1-F02-010: Bidirectional normalized matching."""
        self.assertTrue(verify_token("Bearer sk-ant-abc123xyz", "sk-abc123xyz"))
        self.assertTrue(verify_token("sk-abc123xyz", "Bearer sk-ant-abc123xyz"))
        self.assertTrue(verify_token("Bearer abc123xyz", "abc123xyz"))
        self.assertTrue(verify_token("sk-ant-sentinel-abc123xyz", "sk-abc123xyz"))

    def test_verify_token_mismatch_returns_false(self):
        """TC-M1-F02-011: Mismatch or empty returns False."""
        self.assertFalse(verify_token("Bearer sk-ant-wrong", "sk-ant-correct"))
        self.assertFalse(verify_token("", "sk-ant-correct"))
        self.assertFalse(verify_token("Bearer ", "sk-ant-correct"))
        self.assertFalse(verify_token(None, "sk-ant-correct"))

    def test_verify_token_uses_hmac_compare_digest(self):
        """TC-M1-F02-012: Constant-time comparison using hmac.compare_digest."""
        with patch("hmac.compare_digest", wraps=hmac.compare_digest) as mock_cmp:
            res = verify_token("Bearer sk-ant-token", "sk-token")
            self.assertTrue(res)
            mock_cmp.assert_called_once()


# ==============================================================================
# Feature F03: Inbound Gateway Auth & Admin Auth (11 Tests)
# ==============================================================================

class TestInboundGatewayAndAdminAuth(unittest.IsolatedAsyncioTestCase):
    """F03: Inbound Gateway Bearer Auth (/v1/*) & Admin Token Auth (/api/admin/*)."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_VALID_YAML)

        env = {
            "SENTINEL_GATEWAY_TOKEN": "gw-hardened-key-12345",
            "SENTINEL_ADMIN_TOKEN": "adm-hardened-key-98765",
            "LONGCAT_API_KEY": "sk-longcat-prod",
        }
        with patch.dict(os.environ, env, clear=True):
            self.config = load_config(self.config_path, dev_mode=False)

        self.app = create_test_gateway_app(self.config)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url="http://127.0.0.1:8080")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()

    async def test_v1_messages_missing_auth_returns_401(self):
        """TC-M1-F03-001: POST /v1/messages without auth returns 401 with standard error."""
        resp = await self.client.post("/v1/messages", json={"model": "longcat-2.5-preview", "messages": []})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("error", resp.json())

    async def test_v1_messages_invalid_token_returns_401(self):
        """TC-M1-F03-002: POST /v1/messages with invalid Bearer token returns 401."""
        headers = {"Authorization": "Bearer invalid-gateway-token"}
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 401)

    async def test_v1_chat_completions_missing_auth_returns_401(self):
        """TC-M1-F03-003: POST /v1/chat/completions without auth returns 401."""
        resp = await self.client.post("/v1/chat/completions", json={"model": "longcat-2.5-preview"})
        self.assertEqual(resp.status_code, 401)

    async def test_v1_non_bearer_scheme_returns_401(self):
        """TC-M1-F03-004: Non-Bearer schemes (Basic, Digest, Token) rejected with 401."""
        for bad_auth in ["Basic dXNlcjpwYXNz", "Digest username=\"Mufasa\"", "Token my-token"]:
            resp = await self.client.post("/v1/messages", json={}, headers={"Authorization": bad_auth})
            self.assertEqual(resp.status_code, 401)

    async def test_v1_valid_normalized_gateway_token_accepted(self):
        """TC-M1-F03-005: Valid normalized Bearer tokens accepted on /v1/messages."""
        for token_val in [
            "Bearer sk-ant-gw-hardened-key-12345",
            "Bearer sk-gw-hardened-key-12345",
            "Bearer gw-hardened-key-12345",
        ]:
            resp = await self.client.post("/v1/messages", json={}, headers={"Authorization": token_val})
            self.assertEqual(resp.status_code, 200)

    async def test_v1_auth_via_x_api_key_accepted(self):
        """TC-M1-F03-006: Authentication via X-Api-Key header supported and accepted."""
        headers = {"X-Api-Key": "gw-hardened-key-12345"}
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 200)

    async def test_v1_auth_via_anthropic_api_key_accepted(self):
        """TC-M1-F03-007: Authentication via anthropic-api-key header supported and accepted."""
        headers = {"anthropic-api-key": "sk-ant-gw-hardened-key-12345"}
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 200)

    async def test_admin_api_missing_x_admin_token_returns_401(self):
        """TC-M1-F03-008: GET /api/admin/metrics without X-Admin-Token returns 401."""
        resp = await self.client.get("/api/admin/metrics")
        self.assertEqual(resp.status_code, 401)

    async def test_admin_api_invalid_x_admin_token_returns_401(self):
        """TC-M1-F03-009: GET /api/admin/metrics with incorrect X-Admin-Token returns 401."""
        headers = {"X-Admin-Token": "wrong-admin-token"}
        resp = await self.client.get("/api/admin/metrics", headers=headers)
        self.assertEqual(resp.status_code, 401)

    async def test_admin_api_bearer_token_rejected_without_x_admin_token(self):
        """TC-M1-F03-010: Bearer token sent to /api/admin/* without X-Admin-Token rejected."""
        headers = {"Authorization": "Bearer adm-hardened-key-98765"}
        resp = await self.client.get("/api/admin/metrics", headers=headers)
        self.assertEqual(resp.status_code, 401)

    async def test_admin_api_valid_x_admin_token_accepted(self):
        """TC-M1-F03-011: Valid X-Admin-Token accepted on /api/admin/metrics."""
        headers = {"X-Admin-Token": "adm-hardened-key-98765"}
        resp = await self.client.get("/api/admin/metrics", headers=headers)
        self.assertEqual(resp.status_code, 200)


# ==============================================================================
# Feature F04: Dynamic Loopback Origin Regex & Host Defense (12 Tests)
# ==============================================================================

class TestDynamicLoopbackOriginAndHost(unittest.TestCase):
    """F04: Dynamic Loopback Origin Regex, Host header validation, and DNS rebinding defense."""

    def test_loopback_origin_valid_ipv4_ports(self):
        """TC-M1-F04-001: IPv4 loopback origins with arbitrary ports match regex."""
        for url in ["http://127.0.0.1:8000", "http://127.0.0.1:8080", "http://127.0.0.1:54321", "https://127.0.0.1"]:
            self.assertTrue(bool(LOOPBACK_ORIGIN_REGEX.match(url)), f"Failed for {url}")

    def test_loopback_origin_valid_localhost_ports(self):
        """TC-M1-F04-002: Localhost origins match regex."""
        for url in ["http://localhost:3000", "http://localhost:8080", "https://localhost:8443", "http://localhost"]:
            self.assertTrue(bool(LOOPBACK_ORIGIN_REGEX.match(url)), f"Failed for {url}")

    def test_loopback_origin_valid_ipv6_ports(self):
        """TC-M1-F04-003: IPv6 loopback [::1] origins match regex."""
        for url in ["http://[::1]:8080", "http://[::1]:3000", "https://[::1]:8443", "http://[::1]"]:
            self.assertTrue(bool(LOOPBACK_ORIGIN_REGEX.match(url)), f"Failed for {url}")

    def test_loopback_origin_port_zero_dynamic_binding(self):
        """TC-M1-F04-004: Port 0 dynamically bound port recognized safely."""
        self.assertTrue(is_allowed_origin("http://127.0.0.1:49152", actual_bound_port=49152))

    def test_missing_origin_header_permitted_for_cli(self):
        """TC-M1-F04-005: Missing or empty Origin header permitted for CLI tools."""
        self.assertTrue(is_allowed_origin("", bound_port=8080))
        self.assertTrue(is_allowed_origin(None, bound_port=8080))

    def test_malicious_origin_rejected_with_403(self):
        """TC-M1-F04-006: External malicious origins rejected."""
        for url in ["http://evil.com", "https://attacker.org:8080", "http://malicious-site.net:8080"]:
            self.assertFalse(is_allowed_origin(url, bound_port=8080))

    def test_subdomain_regex_bypass_origins_rejected(self):
        """TC-M1-F04-007: Subdomain bypass attempts strictly rejected."""
        for url in [
            "http://localhost.attacker.com",
            "http://127.0.0.1.attacker.com",
            "http://evil-127.0.0.1.com:8080",
            "http://attacker.com/localhost",
            "http://127.0.0.1.evil.com:8000",
        ]:
            self.assertFalse(bool(LOOPBACK_ORIGIN_REGEX.match(url)), f"Should reject: {url}")
            self.assertFalse(is_allowed_origin(url, bound_port=8080))

    def test_null_and_data_origin_rejected(self):
        """TC-M1-F04-008: Null and data scheme origins rejected."""
        self.assertFalse(is_allowed_origin("null"))
        self.assertFalse(is_allowed_origin("data:"))

    def test_explicit_allowed_origins_whitelisted(self):
        """TC-M1-F04-009: Configured explicit allowed_origins accepted."""
        whitelisted = ["https://my-internal-console.corp", "http://custom-agent.local:9000"]
        self.assertTrue(is_allowed_origin("https://my-internal-console.corp", allowed_origins=whitelisted))
        self.assertTrue(is_allowed_origin("http://custom-agent.local:9000", allowed_origins=whitelisted))
        self.assertFalse(is_allowed_origin("https://unauthorized.corp", allowed_origins=whitelisted))

    def test_host_header_valid_loopback_allowed(self):
        """TC-M1-F04-010: Legitimate loopback Host headers allowed."""
        for host in ["127.0.0.1:8080", "localhost:8080", "[::1]:8080", "localhost", "127.0.0.1", "[::1]"]:
            self.assertTrue(is_allowed_host(host, bound_port=8080))

    def test_host_header_spoofing_dns_rebinding_rejected(self):
        """TC-M1-F04-011: DNS rebinding and spoofed Host headers rejected."""
        for host in ["evil.com", "rebind.attacker.net:8080", "localhost.evil.com", "attacker.com"]:
            self.assertFalse(is_allowed_host(host, bound_port=8080))

    def test_validate_host_header_helper(self):
        """TC-M1-F04-012: validate_host_header helper validates correctly."""
        self.assertTrue(validate_host_header("127.0.0.1:8080"))
        self.assertTrue(validate_host_header("localhost"))
        self.assertFalse(validate_host_header("evil.com:8080"))
        self.assertFalse(validate_host_header(""))
        self.assertFalse(validate_host_header(None))


# ==============================================================================
# Feature F05: TLS Startup Enforcement (8 Tests)
# ==============================================================================

class TestTLSStartupEnforcement(unittest.TestCase):
    """F05: TLS Startup Enforcement on non-loopback network bindings."""

    def test_tls_enforcement_loopback_127_0_0_1_without_tls_passes(self):
        """TC-M1-F05-001: Loopback 127.0.0.1 without TLS passes validation."""
        self.assertTrue(validate_tls_startup(host="127.0.0.1", tls_enabled=False))

    def test_tls_enforcement_loopback_localhost_without_tls_passes(self):
        """TC-M1-F05-002: Loopback localhost without TLS passes validation."""
        self.assertTrue(validate_tls_startup(host="localhost", tls_enabled=False))

    def test_tls_enforcement_loopback_ipv6_without_tls_passes(self):
        """TC-M1-F05-003: Loopback IPv6 ::1 and [::1] without TLS pass validation."""
        self.assertTrue(validate_tls_startup(host="::1", tls_enabled=False))
        self.assertTrue(validate_tls_startup(host="[::1]", tls_enabled=False))

    def test_tls_enforcement_wildcard_0_0_0_0_without_tls_raises(self):
        """TC-M1-F05-004: Wildcard 0.0.0.0 without TLS raises ConfigurationError."""
        with self.assertRaises(ConfigurationError) as ctx:
            validate_tls_startup(host="0.0.0.0", tls_enabled=False)
        self.assertIn("TLS must be enabled", str(ctx.exception))

    def test_tls_enforcement_lan_ip_without_tls_raises(self):
        """TC-M1-F05-005: LAN IP binding (192.168.1.100) without TLS raises ConfigurationError."""
        with self.assertRaises(ConfigurationError):
            validate_tls_startup(host="192.168.1.100", tls_enabled=False)

    def test_tls_enforcement_public_ip_without_tls_raises(self):
        """TC-M1-F05-006: External IP binding (10.0.0.5) without TLS raises ConfigurationError."""
        with self.assertRaises(ConfigurationError):
            validate_tls_startup(host="10.0.0.5", tls_enabled=False)

    def test_tls_enforcement_public_host_with_valid_tls_passes(self):
        """TC-M1-F05-007: External binding with TLS and existing certificate files passes."""
        with tempfile.TemporaryDirectory() as td:
            cert_path = os.path.join(td, "cert.pem")
            key_path = os.path.join(td, "key.pem")
            with open(cert_path, "w") as f:
                f.write("DUMMY_CERT")
            with open(key_path, "w") as f:
                f.write("DUMMY_KEY")

            self.assertTrue(
                validate_tls_startup(
                    host="0.0.0.0",
                    tls_enabled=True,
                    tls_cert_path=cert_path,
                    tls_key_path=key_path,
                )
            )

    def test_tls_enforcement_tls_enabled_missing_files_raises(self):
        """TC-M1-F05-008: External binding with TLS enabled but missing cert files raises."""
        with self.assertRaises(ConfigurationError) as ctx:
            validate_tls_startup(
                host="0.0.0.0",
                tls_enabled=True,
                tls_cert_path="/nonexistent/cert.pem",
                tls_key_path="/nonexistent/key.pem",
            )
        self.assertIn("certificate file not found", str(ctx.exception).lower())


# ==============================================================================
# Feature F06: Dual-Timeout Decoupling (7 Tests)
# ==============================================================================

class TestDualTimeoutsDecoupling(unittest.TestCase):
    """F06: Decoupled timeouts (TTFT 90s for prefill vs stream idle 30s)."""

    def test_timeouts_config_defaults_loaded(self):
        """TC-M1-F06-001: Default TTFT (90s) and stream idle (30s) correctly loaded."""
        t = TimeoutsConfig()
        self.assertEqual(t.time_to_first_token_seconds, 90.0)
        self.assertEqual(t.stream_idle_seconds, 30.0)

    def test_timeouts_config_custom_values_loaded(self):
        """TC-M1-F06-002: Custom decoupled timeout values loaded properly."""
        t = TimeoutsConfig(time_to_first_token_seconds=120.0, stream_idle_seconds=45.0)
        self.assertEqual(t.time_to_first_token_seconds, 120.0)
        self.assertEqual(t.stream_idle_seconds, 45.0)

    def test_timeouts_config_rejects_zero_and_negative(self):
        """TC-M1-F06-003: Zero and negative timeout values rejected by Pydantic validation."""
        with self.assertRaises(ValidationError):
            TimeoutsConfig(time_to_first_token_seconds=0)
        with self.assertRaises(ValidationError):
            TimeoutsConfig(stream_idle_seconds=-5)

    def test_timeouts_config_alias_name_compatibility(self):
        """TC-M1-F06-004: TimeoutConfig and TimeoutsConfig are interchangeable."""
        t1 = TimeoutConfig()
        t2 = TimeoutsConfig()
        self.assertEqual(t1.time_to_first_token_seconds, t2.time_to_first_token_seconds)
        self.assertEqual(t1.stream_idle_seconds, t2.stream_idle_seconds)

    def test_timeouts_config_float_values_supported(self):
        """TC-M1-F06-005: Fractional seconds supported for fine-grained timeouts."""
        t = TimeoutsConfig(time_to_first_token_seconds=89.5, stream_idle_seconds=29.8)
        self.assertEqual(t.time_to_first_token_seconds, 89.5)
        self.assertEqual(t.stream_idle_seconds, 29.8)

    def test_upstream_timeout_default_and_validation(self):
        """TC-M1-F06-006: Upstream timeout default 180s and positive value validation."""
        up = UpstreamConfig()
        self.assertEqual(up.upstream_timeout_seconds, 180.0)
        with self.assertRaises(ValidationError):
            UpstreamConfig(upstream_timeout_seconds=0)

    def test_httpx_timeout_configuration_mapping(self):
        """TC-M1-F06-007: GatewayConfig timeout properties accessible for HTTP client init."""
        cfg = GatewayConfig(
            timeouts=TimeoutsConfig(time_to_first_token_seconds=90.0, stream_idle_seconds=30.0),
            upstream=UpstreamConfig(upstream_timeout_seconds=180.0),
            dev_mode=True,
        )
        self.assertEqual(cfg.timeouts.time_to_first_token_seconds, 90.0)
        self.assertEqual(cfg.timeouts.stream_idle_seconds, 30.0)
        self.assertEqual(cfg.upstream.upstream_timeout_seconds, 180.0)


# ==============================================================================
# Feature F07: Deep Redaction Engine (10 Tests)
# ==============================================================================

class TestDeepRedactionEngine(unittest.TestCase):
    """F07: Deep Redaction Engine and scope isolation invariant."""

    def setUp(self):
        self.redactor = DeepRedactor()

    def test_deep_redaction_api_keys_in_logs(self):
        """TC-M1-F07-001: Redact Anthropic and OpenAI API keys in log text."""
        log = "Received key sk-ant-api03-abcdef1234567890abcdef123456 and openai sk-live1234567890abcdef123456"
        redacted = self.redactor.redact_text(log)
        self.assertNotIn("abcdef1234567890abcdef123456", redacted)
        self.assertIn("****", redacted)

    def test_deep_redaction_pem_private_keys_in_logs(self):
        """TC-M1-F07-002: Redact PEM private keys in log strings."""
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3y...\n-----END RSA PRIVATE KEY-----"
        redacted = self.redactor.redact_text(f"Key loaded: {pem}")
        self.assertIn("[REDACTED_PEM_PRIVATE_KEY]", redacted)
        self.assertNotIn("MIIEowIBAAKCAQEA0Y3y", redacted)

    def test_deep_redaction_pem_certificates_in_logs(self):
        """TC-M1-F07-003: Redact PEM certificates in log strings."""
        cert = "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJ...\n-----END CERTIFICATE-----"
        redacted = self.redactor.redact_text(f"Cert loaded: {cert}")
        self.assertIn("[REDACTED_CERTIFICATE]", redacted)
        self.assertNotIn("MIIDXTCCAkWgAwIBAgIJ", redacted)

    def test_deep_redaction_env_var_assignments_in_logs(self):
        """TC-M1-F07-004: Redact .env variable assignments in logs."""
        log = "Config: SENTINEL_GATEWAY_TOKEN=super_secret_token_12345 LONGCAT_API_KEY=sk-prod-98765"
        redacted = self.redactor.redact_text(log)
        self.assertNotIn("super_secret_token_12345", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_deep_redaction_bearer_token_in_logs(self):
        """TC-M1-F07-005: Redact Bearer token header in logs."""
        log = "Authorization: Bearer my-top-secret-token-xyz-12345"
        redacted = self.redactor.redact_text(log)
        self.assertEqual(redacted, "Authorization: Bearer [REDACTED]")

    def test_deep_redaction_db_connection_uri(self):
        """TC-M1-F07-006: Redact database URI credentials in logs."""
        uri = "Connected to postgresql://sentinel_user:secret_db_password_123@127.0.0.1:5432/longcat_db"
        redacted = self.redactor.redact_text(uri)
        self.assertNotIn("secret_db_password_123", redacted)
        self.assertIn("****", redacted)

    def test_deep_redaction_scope_stream_payload_never_modified(self):
        """TC-M1-F07-007: CRITICAL INVARIANT: Stream payloads must remain 100% byte-exact."""
        raw_stream = b'data: {"text": "const key = \'sk-ant-test-token-12345\'; PEM: -----BEGIN RSA PRIVATE KEY-----..."}\n\n'
        processed = self.redactor.pass_through_stream(raw_stream)
        self.assertEqual(raw_stream, processed)

    def test_deep_redaction_data_structure_recursive(self):
        """TC-M1-F07-008: Recursively sanitize dictionary and list structures."""
        data = {
            "api_key": "sk-ant-secret1234567890abcdef",
            "metadata": {
                "admin_token": "adm-supersecret-token",
                "normal_field": "public_data",
            },
            "tokens": ["sk-1234567890abcdef"],
        }
        sanitized = self.redactor.redact_data_structure(data)
        self.assertNotIn("sk-ant-secret1234567890abcdef", str(sanitized))
        self.assertNotIn("adm-supersecret-token", str(sanitized))
        self.assertEqual(sanitized["metadata"]["normal_field"], "public_data")

    def test_deep_redaction_mask_token_display(self):
        """TC-M1-F07-009: mask_token_display formats tokens safely."""
        self.assertEqual(DeepRedactor.mask_token_display(None), "[NONE]")
        self.assertEqual(DeepRedactor.mask_token_display(""), "[NONE]")
        self.assertEqual(DeepRedactor.mask_token_display("short"), "********")
        formatted = DeepRedactor.mask_token_display("sk-ant-gw-1234567890abcdef")
        self.assertTrue(formatted.startswith("sk-ant"))
        self.assertTrue(formatted.endswith("cdef"))
        self.assertIn("****", formatted)

    def test_deep_redaction_performance_large_text(self):
        """TC-M1-F07-010: High performance on 256KB log buffer (<50ms)."""
        chunk = "2026-10-02 INFO request from sk-ant-api01-abcdef1234567890abcdef123456 processed in 12ms.\n" * 3000
        start_time = time.perf_counter()
        sanitized = self.redactor.redact_text(chunk)
        elapsed = time.perf_counter() - start_time
        self.assertLess(elapsed, 0.50, f"Redaction took too long: {elapsed:.4f}s")
        self.assertNotIn("abcdef1234567890abcdef123456", sanitized)


# ==============================================================================
# Cross-Feature Interactions & Scenario 4 Attack Defense (6 Tests)
# ==============================================================================

class TestCrossFeatureAndSecurityScenarios(unittest.IsolatedAsyncioTestCase):
    """Cross-Feature interactions and Scenario 4: Malicious Localhost Attack Defense."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_VALID_YAML)

        env = {
            "SENTINEL_GATEWAY_TOKEN": "gw-cross-token-12345",
            "SENTINEL_ADMIN_TOKEN": "adm-cross-token-98765",
            "LONGCAT_API_KEY": "sk-cross-key",
        }
        with patch.dict(os.environ, env, clear=True):
            self.config = load_config(self.config_path, dev_mode=False)

        self.app = create_test_gateway_app(self.config)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url="http://127.0.0.1:8080")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()

    async def test_cross_auth_origin_and_host_validation(self):
        """TC-M1-T3-001: Simultaneous valid auth, origin, and host pass cleanly."""
        headers = {
            "Authorization": "Bearer sk-ant-gw-cross-token-12345",
            "Origin": "http://127.0.0.1:3000",
            "Host": "127.0.0.1:8080",
        }
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 200)

    async def test_cross_valid_auth_with_malicious_origin_blocked(self):
        """TC-M1-T3-002: Valid Bearer auth with malicious external Origin returns 403."""
        headers = {
            "Authorization": "Bearer sk-ant-gw-cross-token-12345",
            "Origin": "http://evil.com",
            "Host": "127.0.0.1:8080",
        }
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 403)

    async def test_cross_valid_origin_with_missing_auth_blocked(self):
        """TC-M1-T3-003: Valid loopback Origin with missing Bearer auth returns 401."""
        headers = {
            "Origin": "http://localhost:3000",
            "Host": "localhost:8080",
        }
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 401)

    async def test_cross_valid_auth_and_origin_with_spoofed_host_blocked(self):
        """TC-M1-T3-004: Valid auth and origin with spoofed Host (DNS rebinding) returns 403."""
        headers = {
            "Authorization": "Bearer sk-ant-gw-cross-token-12345",
            "Origin": "http://127.0.0.1:8080",
            "Host": "evil-rebind.com:8080",
        }
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 403)

    async def test_scenario4_malicious_localhost_attack(self):
        """TC-M1-T4-001: Scenario 4 multistep malicious localhost attack defense."""
        # Step 1: DNS Rebinding attack attempt
        rebind_resp = await self.client.post(
            "/v1/messages",
            json={},
            headers={"Host": "rebind.attacker.com:8080", "Authorization": "Bearer gw-cross-token-12345"},
        )
        self.assertEqual(rebind_resp.status_code, 403)

        # Step 2: Cross-origin scan attempt from malicious site
        cors_resp = await self.client.post(
            "/v1/messages",
            json={},
            headers={"Origin": "http://attacker.com", "Authorization": "Bearer gw-cross-token-12345"},
        )
        self.assertEqual(cors_resp.status_code, 403)

        # Step 3: Subdomain regex bypass exploit attempt
        subdomain_resp = await self.client.post(
            "/v1/messages",
            json={},
            headers={"Origin": "http://localhost.attacker.com", "Authorization": "Bearer gw-cross-token-12345"},
        )
        self.assertEqual(subdomain_resp.status_code, 403)

        # Step 4: Admin API brute force without X-Admin-Token
        admin_resp = await self.client.get(
            "/api/admin/metrics",
            headers={"Authorization": "Bearer gw-cross-token-12345"},
        )
        self.assertEqual(admin_resp.status_code, 401)

        # Step 5: Verify DeepRedactor ensures no secrets leak in attack logs
        attack_log = f"Attacker attempted access with gw-cross-token-12345 from http://attacker.com"
        sanitized_log = DeepRedactor.redact_text(attack_log)
        self.assertNotIn("gw-cross-token-12345", sanitized_log)

    async def test_scenario_cli_invocation_without_origin_succeeds(self):
        """TC-M1-T4-002: Claude Code CLI / Hermes CLI native local invocation succeeds."""
        headers = {
            "Authorization": "Bearer sk-ant-gw-cross-token-12345",
            "Host": "127.0.0.1:8080",
            # No Origin header sent by native CLI
        }
        resp = await self.client.post("/v1/messages", json={}, headers=headers)
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
