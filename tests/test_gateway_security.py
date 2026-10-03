"""
tests/test_gateway_security.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
End-to-end security boundary tests against the REAL application produced by
`longcat_sentinel.server.create_app`.

Every assertion here drives the same FastAPI app that `main.py` serves; there is no
hand-assembled test app, so a route that forgets its authentication dependency fails
this suite.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.support import (
    TEST_ADMIN_TOKEN,
    TEST_GATEWAY_TOKEN,
    admin_headers,
    build_app,
    build_config,
    gateway_headers,
    make_client,
    reset_process_state,
)

V1_PAYLOAD = {"model": "claude-3", "messages": [], "stream": False}

ADMIN_ENDPOINTS = ("/api/admin/stats", "/api/admin/config")


class TestRealAppAssembly(unittest.TestCase):
    """TC-SEC-000: the app is wired the way production runs it."""

    def test_real_app_exposes_config_on_state(self):
        app = build_app()
        self.assertIsNotNone(getattr(app.state, "config", None))

    def test_docs_disabled_by_default(self):
        app = build_app()
        self.assertIsNone(app.docs_url)
        self.assertIsNone(app.openapi_url)

    def test_cors_is_not_wildcard_with_credentials(self):
        config = build_config()
        # The shipped configuration lists no origins at all; a hostile site must not
        # be able to read the admin API through a wildcard.
        self.assertEqual(config.security.allowed_origins, [])


class TestAdminApiAuthentication(unittest.IsolatedAsyncioTestCase):
    """TC-SEC-100: /api/admin/* strictly requires X-Admin-Token."""

    async def asyncSetUp(self):
        reset_process_state()
        self.app = build_app()
        self.client = make_client(self.app)

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_admin_endpoints_reject_missing_credentials(self):
        for endpoint in ADMIN_ENDPOINTS:
            resp = await self.client.get(endpoint)
            self.assertEqual(resp.status_code, 401, f"{endpoint} accepted an anonymous caller!")
            self.assertIn("Missing X-Admin-Token", resp.text)

    async def test_gateway_bearer_token_cannot_administer(self):
        for endpoint in ADMIN_ENDPOINTS:
            resp = await self.client.get(endpoint, headers=gateway_headers())
            self.assertEqual(resp.status_code, 401, f"{endpoint} accepted the gateway token!")

    async def test_wrong_admin_token_is_rejected(self):
        resp = await self.client.get(
            "/api/admin/stats", headers={"X-Admin-Token": "definitely-not-the-admin-token"}
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid X-Admin-Token", resp.text)

    async def test_alternate_headers_do_not_grant_admin(self):
        for header in ("X-Api-Key", "anthropic-api-key", "Authorization"):
            resp = await self.client.get(
                "/api/admin/stats", headers={header: TEST_ADMIN_TOKEN}
            )
            self.assertEqual(resp.status_code, 401, f"{header} granted admin access!")

    async def test_valid_admin_token_is_accepted(self):
        resp = await self.client.get("/api/admin/config", headers=admin_headers())
        self.assertEqual(resp.status_code, 200)
        resp_stats = await self.client.get("/api/admin/stats", headers=admin_headers())
        self.assertEqual(resp_stats.status_code, 200)

    async def test_admin_config_never_returns_raw_secrets(self):
        resp = await self.client.get("/api/admin/config", headers=admin_headers())
        body = resp.text
        self.assertNotIn("sk-meituan-testkey-abc123", body)
        self.assertNotIn(TEST_GATEWAY_TOKEN, body)
        self.assertNotIn(TEST_ADMIN_TOKEN, body)

        payload = resp.json()
        self.assertNotIn("api_key", payload)
        self.assertEqual(payload["admin_token"], "[REDACTED]")
        self.assertEqual(payload["gateway_token"], "[REDACTED]")
        self.assertTrue(payload["api_key_configured"])
        self.assertIn("...", payload["masked_api_key"])


class TestAdminOriginAndHostDefense(unittest.IsolatedAsyncioTestCase):
    """TC-SEC-200: DNS rebinding and cross-origin reads are blocked on real routes."""

    async def asyncSetUp(self):
        reset_process_state()
        self.client = make_client(build_app())

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_hostile_origin_is_blocked(self):
        resp = await self.client.get(
            "/api/admin/stats",
            headers=admin_headers(extra={"Origin": "https://evil.example.com"}),
        )
        self.assertEqual(resp.status_code, 403)

    async def test_loopback_origin_is_allowed(self):
        resp = await self.client.get(
            "/api/admin/stats",
            headers=admin_headers(extra={"Origin": "http://127.0.0.1:8080"}),
        )
        self.assertEqual(resp.status_code, 200)

    async def test_spoofed_host_is_blocked(self):
        resp = await self.client.get(
            "/api/admin/stats",
            headers=admin_headers(extra={"Host": "evil-rebind.example.com"}),
        )
        self.assertEqual(resp.status_code, 403)

    async def test_subdomain_bypass_origin_is_blocked(self):
        resp = await self.client.get(
            "/api/admin/stats",
            headers=admin_headers(extra={"Origin": "http://localhost.attacker.com"}),
        )
        self.assertEqual(resp.status_code, 403)


class TestV1Authentication(unittest.IsolatedAsyncioTestCase):
    """TC-SEC-300: /v1/* accepts only a matching gateway credential."""

    async def asyncSetUp(self):
        reset_process_state()
        self.client = make_client(build_app())

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_missing_credentials_are_rejected(self):
        resp = await self.client.post("/v1/messages", json=V1_PAYLOAD)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.headers.get("WWW-Authenticate"), "Bearer")

    async def test_arbitrary_ak_prefix_is_not_a_credential(self):
        """Regression: `token.startswith("ak_")` used to authenticate anyone."""
        forged = [
            "ak_totally_made_up_attacker_value",
            "ak_",
            "ak_1",
            "AK_uppercase_variant_value_here",
        ]
        for token in forged:
            resp = await self.client.post(
                "/v1/messages",
                json=V1_PAYLOAD,
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(resp.status_code, 401, f"forged token accepted: {token}")

    async def test_prefix_stripped_token_is_not_accepted(self):
        """Regression: prefix normalization used to accept the bare suffix."""
        suffix = TEST_GATEWAY_TOKEN.replace("sk-ant-sentinel-", "")
        for variant in (suffix, f"sk-{suffix}", f"sk-ant-{suffix}"):
            resp = await self.client.post(
                "/v1/messages",
                json=V1_PAYLOAD,
                headers={"Authorization": f"Bearer {variant}"},
            )
            self.assertEqual(resp.status_code, 401, f"prefix-degraded token accepted: {variant}")

    async def test_admin_token_cannot_call_v1(self):
        resp = await self.client.post(
            "/v1/messages", json=V1_PAYLOAD, headers=gateway_headers(TEST_ADMIN_TOKEN)
        )
        self.assertEqual(resp.status_code, 401)

    async def test_corrupt_tokens_are_rejected(self):
        corrupt = ["", "   ", "Bearer", "Bearer ", "sk-", "sk--", "bearer", "null"]
        for token in corrupt:
            resp = await self.client.post(
                "/v1/messages",
                json=V1_PAYLOAD,
                headers={"Authorization": token if token.strip() else " "},
            )
            self.assertEqual(resp.status_code, 401, f"corrupt token accepted: {token!r}")

    async def test_non_bearer_schemes_are_rejected(self):
        schemes = [
            "Basic dXNlcjpwYXNzd29yZA==",
            "Digest username=\"u\", realm=\"r\"",
            "Token some-random-token-value",
            "Negotiate a87421000492abf==",
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE",
        ]
        for scheme in schemes:
            resp = await self.client.post(
                "/v1/messages", json=V1_PAYLOAD, headers={"Authorization": scheme}
            )
            self.assertEqual(resp.status_code, 401, f"scheme accepted: {scheme}")

    async def test_valid_gateway_token_is_accepted(self):
        resp = await self.client.get("/v1/models", headers=gateway_headers())
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["object"], "list")

    async def test_x_api_key_header_is_accepted(self):
        resp = await self.client.get(
            "/v1/models", headers={"X-Api-Key": TEST_GATEWAY_TOKEN}
        )
        self.assertEqual(resp.status_code, 200)

    async def test_hostile_origin_blocked_on_v1(self):
        resp = await self.client.get(
            "/v1/models",
            headers=gateway_headers(TEST_GATEWAY_TOKEN) | {"Origin": "http://attacker.com"},
        )
        self.assertEqual(resp.status_code, 403)

    async def test_spoofed_host_blocked_on_v1(self):
        resp = await self.client.get(
            "/v1/models",
            headers=gateway_headers(TEST_GATEWAY_TOKEN) | {"Host": "rebind.attacker.com"},
        )
        self.assertEqual(resp.status_code, 403)


class TestRequestHygiene(unittest.IsolatedAsyncioTestCase):
    """TC-SEC-400: malformed or oversized requests are rejected with correct codes."""

    async def asyncSetUp(self):
        reset_process_state()
        self.config = build_config()
        self.config.upstream.base_url = "http://127.0.0.1:9"  # unreachable on purpose
        self.client = make_client(build_app(self.config))

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_invalid_json_body_returns_400(self):
        resp = await self.client.post(
            "/v1/messages", content=b"{not json", headers=gateway_headers()
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["error"]["type"], "invalid_request_error")

    async def test_json_array_body_returns_400(self):
        resp = await self.client.post(
            "/v1/messages", content=b"[1,2,3]", headers=gateway_headers()
        )
        self.assertEqual(resp.status_code, 400)

    async def test_oversized_body_returns_413(self):
        self.config.limits.max_request_body_bytes = 2048
        resp = await self.client.post(
            "/v1/messages",
            content=b'{"pad":"' + b"A" * 4096 + b'"}',
            headers=gateway_headers(),
        )
        self.assertEqual(resp.status_code, 413)
        self.assertEqual(resp.json()["error"]["type"], "payload_too_large")

    async def test_unreachable_upstream_returns_502_not_500(self):
        """Regression: the non-streaming branch had no except clause."""
        resp = await self.client.post("/v1/messages", json=V1_PAYLOAD, headers=gateway_headers())
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.json()["error"]["type"], "gateway_upstream_error")


class TestConcurrencyCeiling(unittest.IsolatedAsyncioTestCase):
    """TC-SEC-500: max_active_streams is enforced."""

    async def asyncSetUp(self):
        reset_process_state()
        self.config = build_config()
        self.config.upstream.base_url = "http://127.0.0.1:9"
        self.client = make_client(build_app(self.config))

    async def asyncTearDown(self):
        await self.client.aclose()
        reset_process_state()

    async def test_requests_are_rejected_once_the_ceiling_is_reached(self):
        from longcat_sentinel.metrics import metrics

        self.config.limits.max_active_streams = 1
        # Simulate one already-running stream.
        self.assertTrue(metrics.acquire_stream(self.config.limits.max_active_streams))

        resp = await self.client.post("/v1/messages", json=V1_PAYLOAD, headers=gateway_headers())
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp.json()["error"]["type"], "rate_limit_error")

        metrics.release_stream()


class TestAdminConfigMutation(unittest.IsolatedAsyncioTestCase):
    """TC-SEC-600: authenticated config mutation works and never touches the real .env."""

    async def asyncSetUp(self):
        reset_process_state()
        self.app = build_app()
        self.client = make_client(self.app)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env_path = Path(self.temp_dir.name) / ".env"

    async def asyncTearDown(self):
        await self.client.aclose()
        self.temp_dir.cleanup()
        reset_process_state()

    async def test_only_the_active_key_is_written_and_scoped_to_env_path(self):
        with patch(
            "longcat_sentinel.web.admin_api._env_path", return_value=self.env_path
        ):
            resp = await self.client.post(
                "/api/admin/config",
                headers=admin_headers(extra={"Content-Type": "application/json"}),
                json={"api_key": "ak_rotated-key-0123456789"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(self.env_path.exists())
        self.assertIn("ak_rotated-key-0123456789", self.env_path.read_text(encoding="utf-8"))

    async def test_unauthenticated_mutation_is_rejected_and_writes_nothing(self):
        with patch(
            "longcat_sentinel.web.admin_api._env_path", return_value=self.env_path
        ):
            resp = await self.client.post(
                "/api/admin/config",
                headers={"Content-Type": "application/json"},
                json={"api_key": "ak_attacker_key_999"},
            )
        self.assertEqual(resp.status_code, 401)
        self.assertFalse(self.env_path.exists(), "unauthenticated request wrote .env!")

    async def test_unknown_profile_is_rejected(self):
        resp = await self.client.post(
            "/api/admin/config",
            headers=admin_headers(extra={"Content-Type": "application/json"}),
            json={"active_profile": "not-a-real-profile"},
        )
        self.assertEqual(resp.status_code, 400)

    async def test_template_without_reason_placeholder_is_rejected(self):
        resp = await self.client.post(
            "/api/admin/config",
            headers=admin_headers(extra={"Content-Type": "application/json"}),
            json={"injection_template": "no placeholder here"},
        )
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
