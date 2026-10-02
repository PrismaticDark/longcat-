"""
tests/test_adversarial_auth.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Adversarial Empirical Challenge Harness for Milestone 1:
Authentication, Token Subsystem, and Route Boundary Verification.

Tests:
1. Adversarial inputs against normalize_token and verify_token:
   - Malformed Bearer tokens (prefix-only, space-only, mixed cases)
   - Excessive whitespace, tabs, newlines, zero-width characters
   - Prefix stacking (Bearer + sk-ant- + sk-)
   - Corrupt/prefix-only tokens (sk, sk-, sk-ant, sk-ant-sentinel)
   - Non-ASCII and Unicode tokens (CJK characters, emoji, UTF-8 symbols)
   - Timing difference / side-channel resilience (constant-time verification)
   - Extreme prefix recursion and performance stress
   - Bug reproduction: prefix-stacking collision in normalize_token (no-break loop)
   - Bug reproduction: extraneous 'sk-ant-sentinel-' prefix asymmetry
   - Bug reproduction: 'sk--' normalized to '-' instead of empty
2. Strict HTTP 401 enforcement on /v1/* unauthenticated requests:
   - Missing Authorization header
   - Empty and whitespace-only Authorization headers
   - Malformed Bearer schemes and prefix-only values
   - Non-Bearer schemes (Basic, Digest, Token, Negotiate, AWS4, etc.)
   - Invalid and forbidden weak tokens
   - Verification across multiple /v1 endpoints (/v1/messages, /v1/chat/completions, /v1/models)
   - Privilege boundary: Rejection of Admin Token when presented on /v1/*
3. Strict HTTP 401 enforcement on /api/admin/* endpoints:
   - Missing X-Admin-Token returns strict 401
   - Bearer gateway token in Authorization header rejected with 401
   - Bearer admin token in Authorization header rejected with 401 (must use X-Admin-Token)
   - Gateway token provided in X-Admin-Token header rejected with 401
   - Empty/whitespace X-Admin-Token rejected with 401
   - Valid X-Admin-Token accepted with 200 OK
   - Decoupled token authority: gateway token cannot admin, admin token cannot gateway.
"""

from __future__ import annotations

import os
import sys
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from httpx import AsyncClient, ASGITransport
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse

from longcat_sentinel.config import load_config, GatewayConfig
from longcat_sentinel.auth import (
    normalize_token,
    verify_token,
    verify_gateway_token,
    verify_gateway_auth,
    verify_admin_auth,
    is_allowed_origin,
    is_allowed_host,
)

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

breaker:
  active_profile: "code_agent"
  streaming_action: "protocol_compliant_inject"
  injection_template: "[Interrupted]"

tool_guard:
  enable_argument_intent_scan: true
  block_destructive_patterns: true
  action_on_destructive: "block_and_freeze"
"""

def create_adversarial_test_app(config: GatewayConfig) -> FastAPI:
    app = FastAPI(title="LongCat Sentinel Adversarial Verification App")
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
        return {"status": "ok", "route": "/v1/messages", "token": token}

    @app.post("/v1/chat/completions")
    async def v1_chat_completions(token: str = Depends(verify_gateway_auth)):
        return {"status": "ok", "route": "/v1/chat/completions", "token": token}

    @app.get("/v1/models")
    async def v1_models(token: str = Depends(verify_gateway_auth)):
        return {"status": "ok", "route": "/v1/models", "token": token}

    @app.get("/api/admin/metrics")
    async def admin_metrics(admin_token: str = Depends(verify_admin_auth)):
        return {"status": "ok", "route": "/api/admin/metrics", "admin_token": admin_token}

    @app.get("/api/admin/config")
    async def admin_config(admin_token: str = Depends(verify_admin_auth)):
        return {"status": "ok", "route": "/api/admin/config", "admin_token": admin_token}

    return app


# ==============================================================================
# Suite 1: normalize_token and verify_token Adversarial Stress Tests
# ==============================================================================

class TestTokenNormalizationAdversarial(unittest.TestCase):
    """Adversarial stress testing against normalize_token and verify_token."""

    def test_adv_normalize_empty_and_whitespace_variants(self):
        """Verify all variations of empty/whitespace input normalize to empty string."""
        empty_inputs = [
            None,
            "",
            " ",
            "   ",
            "\t",
            "\n",
            "\r\n",
            " \t \r\n \v \f ",
        ]
        for inp in empty_inputs:
            res = normalize_token(inp)
            self.assertEqual(res, "", f"Expected empty string for {inp!r}, got {res!r}")
            self.assertFalse(verify_token(inp, "valid-token"))
            self.assertFalse(verify_token("valid-token", inp))
            self.assertFalse(verify_token(inp, inp))

    def test_adv_normalize_bearer_casing_and_spacing(self):
        """Verify robust Bearer stripping with various casings and spacing patterns."""
        expected_secret = "secret-key-alpha-999"
        bearer_variants = [
            f"Bearer {expected_secret}",
            f"bearer {expected_secret}",
            f"BEARER {expected_secret}",
            f"bEaReR {expected_secret}",
            f"BeArEr {expected_secret}",
            f"Bearer  {expected_secret}",
            f"Bearer        {expected_secret}",
            f"  Bearer   {expected_secret}  ",
            f"\tBearer {expected_secret}\t",
        ]
        for var in bearer_variants:
            self.assertEqual(
                normalize_token(var),
                expected_secret,
                f"Failed to normalize Bearer variant: {var!r}",
            )
            self.assertTrue(verify_token(var, expected_secret))
            self.assertTrue(verify_token(var, f"Bearer {expected_secret}"))

    def test_adv_normalize_bearer_prefix_only_corrupt(self):
        """Verify prefix-only Bearer variants normalize strictly to empty string."""
        prefix_only = [
            "Bearer",
            "bearer",
            "BEARER",
            "bEaReR",
            "Bearer ",
            "bearer ",
            "BEARER   ",
            "  Bearer  ",
            "Bearer Bearer",
            "Bearer Bearer ",
            "bearer bearer bearer",
            "Bearer Bearer Bearer   ",
        ]
        for p in prefix_only:
            self.assertEqual(normalize_token(p), "", f"Expected empty for prefix-only: {p!r}")
            self.assertFalse(verify_token(p, "valid-token"))

    def test_adv_normalize_vendor_prefix_only_corrupt(self):
        """Verify prefix-only vendor tokens normalize strictly to empty string."""
        vendor_prefixes_only = [
            "sk",
            "sk-",
            "sk-ant",
            "sk-ant-",
            "sk-sentinel",
            "sk-sentinel-",
            "sk-ant-sentinel",
            "sk-ant-sentinel-",
            "Bearer sk-",
            "Bearer sk-ant-",
            "Bearer sk-sentinel-",
            "Bearer sk-ant-sentinel-",
            "Bearer Bearer sk-ant-",
        ]
        for v in vendor_prefixes_only:
            self.assertEqual(normalize_token(v), "", f"Expected empty for vendor prefix only: {v!r}")
            self.assertFalse(verify_token(v, "valid-token"))

    def test_adv_normalize_standard_vendor_prefixes(self):
        """Verify standard vendor prefix stripping for sk-ant- and sk-."""
        core_secret = "hardened-secret-9988"
        self.assertEqual(normalize_token(f"sk-ant-{core_secret}"), core_secret)
        self.assertEqual(normalize_token(f"sk-{core_secret}"), core_secret)
        self.assertEqual(normalize_token(f"Bearer sk-ant-{core_secret}"), core_secret)
        self.assertEqual(normalize_token(f"Bearer sk-{core_secret}"), core_secret)
        self.assertEqual(normalize_token(f"Bearer Bearer {core_secret}"), core_secret)

    def test_adv_normalize_unicode_and_non_ascii(self):
        """Verify non-ASCII, Unicode, emoji, and multi-byte UTF-8 tokens."""
        unicode_cases = [
            ("Bearer 龙猫Sentinel密钥_2026", "龙猫Sentinel密钥_2026"),
            ("sk-ant-猫猫安全网关", "猫猫安全网关"),
            ("Bearer 🔑_secret_shield_🛡️", "🔑_secret_shield_🛡️"),
            ("Bearer café_au_lait_token_☕", "café_au_lait_token_☕"),
            ("Bearer α_beta_gamma_Δ", "α_beta_gamma_Δ"),
            ("Bearer \u200bzero_width_space", "\u200bzero_width_space"),
        ]
        for raw, expected in unicode_cases:
            normalized = normalize_token(raw)
            self.assertEqual(normalized, expected, f"Unicode normalization failed for {raw!r}")
            self.assertTrue(verify_token(raw, expected))
            self.assertTrue(verify_token(raw, f"Bearer {expected}"))

    def test_adv_normalize_special_characters_and_delimiters(self):
        """Verify tokens containing symbols, colons, base64 paddings, and punctuation."""
        special_tokens = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5",
            "dGVzdC1zZWNyZXQtYmFzZTY0Cg==",
            "token:with:colons:and$symbols#%&*!",
            "token-with-dashes-and_underscores.and.dots",
            "Bearer sk-ant-token/with/slashes+plus==",
        ]
        for tok in special_tokens:
            expected_core = tok.replace("Bearer ", "").replace("sk-ant-", "")
            self.assertEqual(normalize_token(tok), expected_core)
            self.assertTrue(verify_token(tok, expected_core))

    def test_adv_timing_difference_constant_time(self):
        """
        Verify constant-time HMAC comparison properties.
        Compares average execution time between mismatch at first character vs mismatch at last character.
        """
        token_len = 64
        expected = "a" * token_len
        mismatch_first = "z" + ("a" * (token_len - 1))
        mismatch_last = ("a" * (token_len - 1)) + "z"

        # Warm up
        for _ in range(1000):
            verify_token(mismatch_first, expected)
            verify_token(mismatch_last, expected)

        iterations = 20_000

        # Measure mismatch at first character
        t0 = time.perf_counter()
        for _ in range(iterations):
            verify_token(mismatch_first, expected)
        t_first = time.perf_counter() - t0

        # Measure mismatch at last character
        t0 = time.perf_counter()
        for _ in range(iterations):
            verify_token(mismatch_last, expected)
        t_last = time.perf_counter() - t0

        # Both timings should be extremely close (ratio between 0.60 and 1.60 under system noise)
        ratio = t_first / t_last if t_last > 0 else 1.0
        self.assertGreater(ratio, 0.50, f"Timing ratio suspiciously skewed: {ratio:.3f}")
        self.assertLess(ratio, 2.00, f"Timing ratio suspiciously skewed: {ratio:.3f}")

    # --------------------------------------------------------------------------
    # EMPIRICAL BUG REPRODUCTION TESTS
    # --------------------------------------------------------------------------

    def test_bug_prefix_stacking_collision(self):
        """
        [EMPIRICAL BUG REPRODUCTION]
        Bug 1: In normalize_token(), the inner prefix loop does not 'break' after stripping.
        When 'sk-ant-sk-ant-secret' is normalized:
        1. 'sk-ant-' is stripped, leaving 'sk-ant-secret'.
        2. In the same iteration, the loop continues to 'sk-'.
        3. 'sk-' matches the beginning of 'sk-ant-secret', stripping 3 characters.
        4. The result is corrupted into 'ant-secret' instead of 'secret'!
        """
        raw_input = "sk-ant-sk-ant-my-secret"
        actual = normalize_token(raw_input)
        # We record that current implementation produces 'ant-my-secret' due to this bug!
        self.assertNotEqual(
            actual,
            "my-secret",
            "Confirmed: normalize_token suffers from prefix-collision bug when stacking vendor prefixes",
        )
        self.assertEqual(actual, "ant-my-secret", "Empirically verified exact bug artifact: 'ant-my-secret'")

    def test_bug_extraneous_sentinel_prefix_asymmetry(self):
        """
        [EMPIRICAL BUG REPRODUCTION]
        Bug 2: Worker M1 added extraneous 'sk-ant-sentinel-' to TOKEN_PREFIXES (violating v2.3 spec §4).
        If a gateway token is configured as 'sentinel-key-123':
        - Config side normalizes 'sentinel-key-123' -> 'sentinel-key-123' (not starting with 'sk-').
        - Client sends 'Bearer sk-ant-sentinel-key-123' -> normalizes to 'key-123' (stripping 'sk-ant-sentinel-').
        - Result: verify_token('Bearer sk-ant-sentinel-key-123', 'sentinel-key-123') FAILS!
        """
        cfg_token = "sentinel-key-123"
        client_token = "Bearer sk-ant-sentinel-key-123"

        norm_cfg = normalize_token(cfg_token)
        norm_client = normalize_token(client_token)

        self.assertEqual(norm_cfg, "sentinel-key-123")
        self.assertEqual(norm_client, "key-123")
        # Demonstrates the two-way verification breakdown:
        self.assertFalse(
            verify_token(client_token, cfg_token),
            "Confirmed: Asymmetric normalization rejects legitimate sentinel-prefixed token",
        )

    def test_bug_corrupted_dash_prefix(self):
        """
        [EMPIRICAL BUG REPRODUCTION]
        Bug 3: normalize_token('sk--') strips 'sk-' leaving '-', which is not caught
        by corrupt token filters and returned as a single dash '-' instead of empty string ''.
        """
        actual = normalize_token("sk--")
        self.assertEqual(actual, "-", "Empirically verified: 'sk--' returns '-' instead of empty string ''")


# ==============================================================================
# Suite 2: /v1/* Strict HTTP 401 Unauthenticated Access Tests
# ==============================================================================

class TestV1UnauthenticatedAccessAdversarial(unittest.IsolatedAsyncioTestCase):
    """Adversarial testing: /v1/* endpoints strictly return HTTP 401 when unauthenticated."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_VALID_YAML)

        self.gateway_token = "prod-gw-key-778899"
        self.admin_token = "prod-adm-key-112233"
        env = {
            "SENTINEL_GATEWAY_TOKEN": self.gateway_token,
            "SENTINEL_ADMIN_TOKEN": self.admin_token,
            "LONGCAT_API_KEY": "sk-longcat-prod",
        }
        with patch.dict(os.environ, env, clear=True):
            self.config = load_config(self.config_path, dev_mode=False)

        self.app = create_adversarial_test_app(self.config)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url="http://127.0.0.1:8080")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()

    async def test_adv_v1_messages_missing_auth_header(self):
        """Verify /v1/messages returns strict HTTP 401 when Authorization header is absent."""
        resp = await self.client.post("/v1/messages", json={"messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("error", resp.json())
        self.assertEqual(resp.json()["error"]["type"], "authentication_error")
        self.assertIn("WWW-Authenticate", resp.headers)
        self.assertEqual(resp.headers["WWW-Authenticate"], "Bearer")

    async def test_adv_v1_chat_completions_missing_auth_header(self):
        """Verify /v1/chat/completions returns strict HTTP 401 when Authorization is absent."""
        resp = await self.client.post("/v1/chat/completions", json={"model": "longcat-2.5-preview"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("error", resp.json())
        self.assertEqual(resp.json()["error"]["type"], "authentication_error")
        self.assertEqual(resp.headers.get("WWW-Authenticate"), "Bearer")

    async def test_adv_v1_models_missing_auth_header(self):
        """Verify GET /v1/models returns strict HTTP 401 when Authorization is absent."""
        resp = await self.client.get("/v1/models")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("error", resp.json())

    async def test_adv_v1_empty_and_whitespace_auth_headers(self):
        """Verify /v1/* returns strict HTTP 401 for empty or whitespace-only Authorization headers."""
        bad_headers = [
            {"Authorization": ""},
            {"Authorization": "   "},
            {"Authorization": "\t\t"},
            {"Authorization": "Bearer"},
            {"Authorization": "Bearer "},
            {"Authorization": "Bearer    "},
        ]
        for hdrs in bad_headers:
            resp = await self.client.post("/v1/messages", json={}, headers=hdrs)
            self.assertEqual(resp.status_code, 401, f"Failed for header: {hdrs}")
            self.assertEqual(resp.json()["error"]["type"], "authentication_error")

    async def test_adv_v1_non_bearer_schemes_rejected(self):
        """Verify /v1/* rejects non-Bearer authentication schemes with HTTP 401."""
        non_bearer_schemes = [
            "Basic dXNlcjpwYXNzd29yZA==",
            "Digest username=\"user\", realm=\"sentinel\", nonce=\"12345\"",
            "Token somerandomtoken123",
            "Negotiate a87421000492abf==",
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE",
            "Custom-Auth-Scheme credentials-here",
        ]
        for scheme_val in non_bearer_schemes:
            resp = await self.client.post("/v1/messages", json={}, headers={"Authorization": scheme_val})
            self.assertEqual(resp.status_code, 401, f"Expected 401 for scheme: {scheme_val}")
            self.assertEqual(resp.headers.get("WWW-Authenticate"), "Bearer")

    async def test_adv_v1_invalid_and_corrupt_bearer_tokens(self):
        """Verify /v1/* rejects invalid, corrupt, or prefix-only tokens with HTTP 401."""
        invalid_tokens = [
            "Bearer invalid-key-xyz",
            "Bearer sk-ant-wrong-secret",
            "Bearer sk-wrong-secret",
            "Bearer sk-",
            "Bearer sk-ant-",
            "Bearer sk-sentinel-",
            "Bearer sk-ant-sentinel-",
            "Bearer sk-placeholder",
            "Bearer default",
            "Bearer changeme",
            "Bearer admin",
            "Bearer 123456",
        ]
        for tok in invalid_tokens:
            resp = await self.client.post("/v1/messages", json={}, headers={"Authorization": tok})
            self.assertEqual(resp.status_code, 401, f"Expected 401 for token: {tok}")

    async def test_adv_v1_rejects_admin_token(self):
        """
        CRITICAL PRIVILEGE BOUNDARY TEST:
        Verify /v1/* strictly REJECTS the Admin Token when passed as Bearer token.
        Admin Token must NOT grant access to gateway routing endpoints.
        """
        admin_as_gateway = f"Bearer {self.admin_token}"
        resp = await self.client.post("/v1/messages", json={}, headers={"Authorization": admin_as_gateway})
        self.assertEqual(
            resp.status_code,
            401,
            "CRITICAL SECURITY FLAW: /v1/messages accepted admin token as gateway token!",
        )

        resp2 = await self.client.post("/v1/chat/completions", json={}, headers={"Authorization": admin_as_gateway})
        self.assertEqual(
            resp2.status_code,
            401,
            "CRITICAL SECURITY FLAW: /v1/chat/completions accepted admin token as gateway token!",
        )

    async def test_adv_v1_valid_gateway_token_accepted(self):
        """Verify /v1/* accepts valid gateway token across all supported normalizations."""
        valid_variants = [
            f"Bearer {self.gateway_token}",
            f"Bearer sk-ant-{self.gateway_token}",
            f"Bearer sk-{self.gateway_token}",
            f"bearer {self.gateway_token}",
            f"BEARER {self.gateway_token}",
        ]
        for v in valid_variants:
            resp = await self.client.post("/v1/messages", json={}, headers={"Authorization": v})
            self.assertEqual(resp.status_code, 200, f"Expected 200 for valid token: {v}")
            self.assertEqual(resp.json()["status"], "ok")


# ==============================================================================
# Suite 3: /api/admin/* Rejects Gateway Tokens & Requires X-Admin-Token
# ==============================================================================

class TestAdminAuthAdversarial(unittest.IsolatedAsyncioTestCase):
    """
    Adversarial testing: /api/admin/* endpoints strictly require X-Admin-Token
    and reject Bearer gateway tokens.
    """

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(SAMPLE_VALID_YAML)

        self.gateway_token = "gw-token-secret-alpha-1234"
        self.admin_token = "adm-token-secret-omega-5678"
        env = {
            "SENTINEL_GATEWAY_TOKEN": self.gateway_token,
            "SENTINEL_ADMIN_TOKEN": self.admin_token,
            "LONGCAT_API_KEY": "sk-longcat-prod",
        }
        with patch.dict(os.environ, env, clear=True):
            self.config = load_config(self.config_path, dev_mode=False)

        self.app = create_adversarial_test_app(self.config)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url="http://127.0.0.1:8080")

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()

    async def test_adv_admin_missing_all_headers_returns_401(self):
        """Verify GET /api/admin/metrics returns 401 when no headers are supplied."""
        for endpoint in ["/api/admin/metrics", "/api/admin/config"]:
            resp = await self.client.get(endpoint)
            self.assertEqual(resp.status_code, 401)
            self.assertIn("error", resp.json())
            self.assertIn("Missing X-Admin-Token header", resp.json()["error"]["message"])

    async def test_adv_admin_bearer_gateway_token_in_auth_header_rejected(self):
        """
        Verify sending valid Bearer Gateway Token in Authorization header to /api/admin/*
        is strictly rejected with HTTP 401 because X-Admin-Token is missing.
        """
        headers = {"Authorization": f"Bearer {self.gateway_token}"}
        for endpoint in ["/api/admin/metrics", "/api/admin/config"]:
            resp = await self.client.get(endpoint, headers=headers)
            self.assertEqual(
                resp.status_code,
                401,
                f"Bearer gateway token unexpectedly accepted on {endpoint}",
            )
            self.assertIn("Missing X-Admin-Token header", resp.json()["error"]["message"])

    async def test_adv_admin_bearer_admin_token_in_auth_header_rejected(self):
        """
        Verify sending Admin Token in Authorization header (instead of X-Admin-Token)
        is strictly rejected with HTTP 401. Enforces dedicated header contract.
        """
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        resp = await self.client.get("/api/admin/metrics", headers=headers)
        self.assertEqual(
            resp.status_code,
            401,
            "Admin token in Authorization header should be rejected; requires X-Admin-Token header",
        )
        self.assertIn("Missing X-Admin-Token header", resp.json()["error"]["message"])

    async def test_adv_admin_gateway_token_in_x_admin_token_rejected(self):
        """
        CRITICAL PRIVILEGE BOUNDARY TEST:
        Verify passing the valid Gateway Token inside X-Admin-Token header is rejected with 401.
        Gateway token MUST NOT grant administrative dashboard privileges.
        """
        headers = {"X-Admin-Token": self.gateway_token}
        resp = await self.client.get("/api/admin/metrics", headers=headers)
        self.assertEqual(
            resp.status_code,
            401,
            "CRITICAL SECURITY FLAW: Gateway token accepted as X-Admin-Token!",
        )
        self.assertIn("Invalid X-Admin-Token", resp.json()["error"]["message"])

    async def test_adv_admin_alternate_api_key_headers_rejected(self):
        """
        Verify X-Api-Key and anthropic-api-key headers are rejected on /api/admin/*
        even if carrying valid admin token. Only X-Admin-Token is permitted.
        """
        for alt_header in ["X-Api-Key", "anthropic-api-key"]:
            headers = {alt_header: self.admin_token}
            resp = await self.client.get("/api/admin/metrics", headers=headers)
            self.assertEqual(
                resp.status_code,
                401,
                f"Header {alt_header} unexpectedly accepted on /api/admin/*",
            )

    async def test_adv_admin_empty_and_corrupt_x_admin_token_rejected(self):
        """Verify empty, whitespace, and corrupt X-Admin-Token values return 401."""
        bad_admin_tokens = [
            "",
            "   ",
            "\t",
            "wrong-secret",
            "admin",
            "sk-",
            "Bearer ",
            "sk-ant-",
        ]
        for tok in bad_admin_tokens:
            headers = {"X-Admin-Token": tok}
            resp = await self.client.get("/api/admin/metrics", headers=headers)
            self.assertEqual(resp.status_code, 401, f"Expected 401 for X-Admin-Token: {tok!r}")

    async def test_adv_admin_valid_x_admin_token_accepted(self):
        """Verify valid X-Admin-Token is accepted and grants access."""
        valid_admin_headers = [
            {"X-Admin-Token": self.admin_token},
            {"X-Admin-Token": f"Bearer {self.admin_token}"},
            {"X-Admin-Token": f"  {self.admin_token}  "},
        ]
        for hdrs in valid_admin_headers:
            resp = await self.client.get("/api/admin/metrics", headers=hdrs)
            self.assertEqual(resp.status_code, 200, f"Expected 200 for headers: {hdrs}")
            self.assertEqual(resp.json()["status"], "ok")
            self.assertEqual(resp.json()["route"], "/api/admin/metrics")

            resp_cfg = await self.client.get("/api/admin/config", headers=hdrs)
            self.assertEqual(resp_cfg.status_code, 200)
            self.assertEqual(resp_cfg.json()["route"], "/api/admin/config")


if __name__ == "__main__":
    unittest.main(verbosity=2)
