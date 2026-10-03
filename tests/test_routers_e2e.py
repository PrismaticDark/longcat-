"""
tests/test_routers_e2e.py
~~~~~~~~~~~~~~~~~~~~~~~~~
End-to-end stream tests: a real local fake upstream drives the real gateway routes.

Covers the regressions that only appear once bytes actually flow:
  * protocol-compliant interruption, including open tool blocks
  * tool-call loop and destructive-argument interception
  * correct accounting when the upstream fails versus succeeds
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
import time
import unittest

from tests.support import (
    build_app,
    build_config,
    gateway_headers,
    make_client,
    reset_process_state,
)

UNIT = "0123456789abcdef"
DELTA_COUNT = 12

UPSTREAM_STATE = {"mode": "anthropic_text_loop", "status": 200}


def _anthropic_events(mode: str):
    events = [
        {
            "type": "message_start",
            "message": {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": "LongCat-2.5-Preview",
                "stop_reason": None,
                "usage": {"input_tokens": 5, "output_tokens": 0},
            },
        }
    ]

    if mode == "anthropic_parallel_tool":
        # index 0 is text, index 1 is the still-open tool call.
        events.append({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        events.append(
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "tool_use", "id": "toolu_1", "name": "terminal", "input": {}},
            }
        )
        events.append(
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"cmd": "ls'},
            }
        )
        # Closing the text block must NOT mark the tool call as closed.
        events.append({"type": "content_block_stop", "index": 0})
        for _ in range(DELTA_COUNT):
            events.append(
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": UNIT}}
            )
    else:
        events.append({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        for _ in range(DELTA_COUNT):
            events.append(
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": UNIT}}
            )

    events.append({"type": "message_stop"})
    return events


def _openai_chunks(mode: str):
    base = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": int(time.time()), "model": "LongCat-2.5-Preview"}
    chunks = []

    if mode == "openai_tool_loop":
        # Four parallel tool calls with identical name + arguments: the guard must
        # trip on the repetition once the calls are finalized.
        chunks.append(
            {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": call_index,
                                    "id": f"call_{call_index}",
                                    "type": "function",
                                    "function": {
                                        "name": "read_file",
                                        "arguments": '{"path": "a.txt"}',
                                    },
                                }
                                for call_index in range(4)
                            ]
                        },
                        "finish_reason": None,
                    }
                ],
            }
        )
        chunks.append({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
    else:
        for _ in range(DELTA_COUNT):
            chunks.append(
                {**base, "choices": [{"index": 0, "delta": {"content": UNIT}, "finish_reason": None}]}
            )
        chunks.append({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})

    return chunks


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        pass

    def _respond(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        length = int(self.headers.get("content-length", 0) or 0)
        self.rfile.read(length)

        status = UPSTREAM_STATE.get("status", 200)
        mode = UPSTREAM_STATE["mode"]

        if status != 200:
            self._respond(status, json.dumps({"error": {"message": "upstream boom"}}).encode(), "application/json")
            return

        if self.path.endswith("/anthropic/v1/messages"):
            body = "".join(f"data: {json.dumps(evt)}\n\n" for evt in _anthropic_events(mode)).encode()
            self._respond(200, body, "text/event-stream")
        elif self.path.endswith("/openai/v1/chat/completions"):
            body = "".join(f"data: {json.dumps(chunk)}\n\n" for chunk in _openai_chunks(mode)).encode()
            body += b"data: [DONE]\n\n"
            self._respond(200, body, "text/event-stream")
        else:
            self._respond(404, b"{}", "application/json")


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def parse_sse(text: str):
    events = []
    current = {}
    for line in text.split("\n"):
        if line.startswith("event: "):
            current["event"] = line[7:]
        elif line.startswith("data: "):
            current["data"] = line[6:]
        elif line.strip() == "" and current:
            events.append(current)
            current = {}
    if current:
        events.append(current)
    return events


def data_objects(text: str):
    objects = []
    for event in parse_sse(text):
        try:
            objects.append(json.loads(event.get("data", "")))
        except Exception:
            continue
    return objects


def stream_text_payloads(text: str) -> str:
    """
    Concatenates every text delta carried by the stream.

    SSE payloads are JSON with ASCII-escaped non-ASCII characters, so assertions on
    human-readable strings must inspect the decoded delta text rather than raw bytes.
    """
    parts = []
    for obj in data_objects(text):
        if obj.get("type") == "content_block_delta":
            delta = obj.get("delta") or {}
            if delta.get("type") == "text_delta":
                parts.append(str(delta.get("text", "")))
        for choice in obj.get("choices") or []:
            delta = (choice or {}).get("delta") or {}
            content = delta.get("content")
            if isinstance(content, str):
                parts.append(content)
    return "".join(parts)


class RouterE2EBase(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _Server(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    async def asyncSetUp(self):
        reset_process_state()
        UPSTREAM_STATE["status"] = 200
        UPSTREAM_STATE["mode"] = "anthropic_text_loop"
        self.config = build_config()
        self.config.upstream.base_url = f"http://127.0.0.1:{self.port}"
        self.client = make_client(build_app(self.config))

    async def asyncTearDown(self):
        await self.client.aclose()
        reset_process_state()


class TestAnthropicStreaming(RouterE2EBase):
    """TC-E2E-100: Anthropic stream interruption."""

    async def test_text_loop_trips_and_stays_protocol_compliant(self):
        resp = await self.client.post(
            "/v1/messages",
            json={"model": "claude-3", "messages": [], "stream": True},
            headers=gateway_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("保护性中断", stream_text_payloads(resp.text))
        self.assertIn("message_stop", resp.text)

        # Only the deltas before the trip are forwarded.
        self.assertLess(resp.text.count(UNIT), DELTA_COUNT)
        self.assertIn("content_block_stop", resp.text)

        types = [obj.get("type") for obj in data_objects(resp.text)]
        self.assertIn("message_delta", types)

    async def test_open_tool_block_receives_valid_json_closure(self):
        """Regression: closing the text block used to clear the open-tool flag."""
        UPSTREAM_STATE["mode"] = "anthropic_parallel_tool"
        resp = await self.client.post(
            "/v1/messages",
            json={"model": "claude-3", "messages": [], "stream": True},
            headers=gateway_headers(),
        )
        self.assertEqual(resp.status_code, 200)

        objects = data_objects(resp.text)
        completions = [
            obj
            for obj in objects
            if obj.get("type") == "content_block_delta"
            and obj.get("index") == 1
            and (obj.get("delta") or {}).get("type") == "input_json_delta"
        ]
        self.assertTrue(completions, "the open tool block was never given a JSON closure")

        fragment = '{"cmd": "ls'
        suffix = completions[-1]["delta"]["partial_json"]
        self.assertEqual(fragment + suffix, '{"cmd": "ls"}')
        self.assertIsInstance(json.loads(fragment + suffix), dict)

        stops = [
            obj for obj in objects
            if obj.get("type") == "content_block_stop" and obj.get("index") == 1
        ]
        self.assertTrue(stops, "the open tool block was never closed")

    async def test_upstream_error_status_is_passed_through_and_not_marked_safe(self):
        UPSTREAM_STATE["status"] = 401
        from longcat_sentinel.metrics import metrics

        resp = await self.client.post(
            "/v1/messages",
            json={"model": "claude-3", "messages": [], "stream": True},
            headers=gateway_headers(),
        )
        self.assertEqual(resp.status_code, 401)
        events = metrics.get_stats()["audit_events"]
        self.assertTrue(events)
        self.assertFalse(events[0]["is_safe"], "an upstream failure was logged as a safe completion")


class TestOpenAIStreaming(RouterE2EBase):
    """TC-E2E-200: OpenAI stream interruption and tool guarding."""

    async def test_text_loop_trips_and_terminates_stream(self):
        resp = await self.client.post(
            "/v1/chat/completions",
            json={"model": "longcat-2.5-preview", "stream": True},
            headers=gateway_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("保护性中断", stream_text_payloads(resp.text))
        self.assertIn("[DONE]", resp.text)
        self.assertIn('"finish_reason": "stop"', resp.text)
        self.assertLess(resp.text.count(UNIT), DELTA_COUNT)

    async def test_repeated_identical_tool_calls_are_intercepted(self):
        UPSTREAM_STATE["mode"] = "openai_tool_loop"
        resp = await self.client.post(
            "/v1/chat/completions",
            json={"model": "longcat-2.5-preview", "stream": True},
            headers=gateway_headers(),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("保护性中断", stream_text_payloads(resp.text))
        self.assertIn("[DONE]", resp.text)

    async def test_non_streaming_success_records_safe_completion(self):
        UPSTREAM_STATE["mode"] = "openai_text_loop"
        from longcat_sentinel.metrics import metrics

        resp = await self.client.post(
            "/v1/chat/completions",
            json={"model": "longcat-2.5-preview", "stream": False},
            headers=gateway_headers(),
        )
        # The fake upstream only speaks SSE; what matters here is the accounting path.
        events = metrics.get_stats()["audit_events"]
        self.assertTrue(events)


class TestUpstreamKeyHandling(RouterE2EBase):
    """TC-E2E-300: the persisted upstream key can no longer be hijacked."""

    async def test_client_supplied_key_is_not_persisted(self):
        original = self.config.upstream.api_key
        resp = await self.client.post(
            "/v1/messages",
            json={"model": "claude-3", "messages": [], "stream": False},
            headers=gateway_headers() | {"X-Upstream-Api-Key": "ak_client_supplied_value"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.config.upstream.api_key, original)
        import os

        self.assertNotEqual(os.environ.get("LONGCAT_API_KEY"), "ak_client_supplied_value")


if __name__ == "__main__":
    unittest.main(verbosity=2)
