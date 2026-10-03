"""
longcat_sentinel.circuit_breaker.redactor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep redaction engine for sanitizing logs, stderr, terminal, and dashboard metrics.

CRITICAL ARCHITECTURAL INVARIANT:
This redactor must NEVER be applied to normal upstream/downstream stream payloads.
Payload streams must be passed through 100% byte-exact and unmodified.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

# Regex patterns for sensitive credentials
RE_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z\s]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z\s]+ )?PRIVATE KEY-----",
    re.MULTILINE,
)
RE_PEM_CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
    re.MULTILINE,
)
RE_ENV_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)[A-Z0-9_]*)\s*=\s*(['\"]?)([^\r\n'\"]+)\2",
)
RE_INLINE_ENV_SECRET = re.compile(
    r"(?i)\b((?:SENTINEL_[A-Z0-9_]*|LONGCAT_[A-Z0-9_]*|[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH)[A-Z0-9_]*)\s*=\s*)(['\"]?)([^\s'\"]+)\2",
)
RE_ANTHROPIC_KEY = re.compile(
    r"\b(sk-ant-[a-zA-Z0-9_\-]{4,6})(?:[a-zA-Z0-9_\-]{16,})\b"
)
RE_OPENAI_KEY = re.compile(
    r"\b(sk-[a-zA-Z0-9_\-]{3,4})(?:[a-zA-Z0-9_\-]{16,})\b"
)
RE_BEARER_TOKEN = re.compile(
    r"(?i)\b(Bearer\s+)[A-Za-z0-9_\-\.]{8,}\b"
)
RE_DB_CONN = re.compile(
    r"([a-zA-Z0-9_+]+://[^:]+:)([^@]+)(@)"
)
RE_JSON_SENSITIVE_KEY = re.compile(
    r'("(?:api_key|token|admin_token|password|secret|authorization)":\s*")([^"]+)(")',
    re.IGNORECASE,
)
RE_GATEWAY_TOKEN = re.compile(
    r"\b((?:gw|adm|sentinel|sec)-[a-zA-Z0-9_\-]{2,6})(?:[a-zA-Z0-9_\-]{6,})\b",
    re.IGNORECASE,
)

SENSITIVE_DICT_KEYS = {
    "api_key",
    "token",
    "admin_token",
    "gateway_tokens",
    "dashboard_admin_token",
    "password",
    "secret",
    "authorization",
    "x-admin-token",
    "anthropic-api-key",
    "x-api-key",
}


class DeepRedactor:
    """
    High-performance redaction engine for sanitizing logs, terminal screens, and metrics.
    Ensures zero secret leakage without corrupting business payload streams.
    """

    @classmethod
    def redact_text(cls, text: str) -> str:
        """Sanitizes sensitive patterns in arbitrary plaintext or log lines."""
        if not text:
            return text if text is not None else ""

        # 1. Redact PEM private keys & certificates
        sanitized = RE_PEM_PRIVATE_KEY.sub("[REDACTED_PEM_PRIVATE_KEY]", text)
        sanitized = RE_PEM_CERTIFICATE.sub("[REDACTED_CERTIFICATE]", sanitized)

        # 2. Redact .env secret variable assignments
        sanitized = RE_ENV_SECRET_ASSIGNMENT.sub(r"\1=[REDACTED]", sanitized)
        sanitized = RE_INLINE_ENV_SECRET.sub(r"\1[REDACTED]", sanitized)

        # 3. Mask Anthropic & OpenAI API keys with prefix signature preservation
        sanitized = RE_ANTHROPIC_KEY.sub(r"\1****", sanitized)
        sanitized = RE_OPENAI_KEY.sub(r"\1****", sanitized)

        # 4. Mask Gateway and Admin tokens
        sanitized = RE_GATEWAY_TOKEN.sub(r"\1****", sanitized)

        # 5. Redact Bearer tokens in headers/logs
        sanitized = RE_BEARER_TOKEN.sub(r"\1[REDACTED]", sanitized)

        # 6. Redact database connection URI credentials
        sanitized = RE_DB_CONN.sub(r"\1****\3", sanitized)

        # 7. Redact JSON formatted key-value pairs
        sanitized = RE_JSON_SENSITIVE_KEY.sub(r'\1[REDACTED]\3', sanitized)

        return sanitized

    @classmethod
    def redact_for_logging(cls, text: str) -> str:
        """Alias for redact_text for logging integrations."""
        return cls.redact_text(text)

    @classmethod
    def mask_token_display(
        cls,
        token: Optional[str],
        visible_prefix: int = 6,
        visible_suffix: int = 4,
    ) -> str:
        """Formats a token safely for Rich dashboard / status display."""
        if not token:
            return "[NONE]"
        cleaned = token.strip()
        if len(cleaned) <= (visible_prefix + visible_suffix):
            return "********"
        return f"{cleaned[:visible_prefix]}****{cleaned[-visible_suffix:]}"

    @classmethod
    def redact_data_structure(cls, data: Any) -> Any:
        """Recursively traverses dictionary or list to redact sensitive values."""
        if isinstance(data, dict):
            redacted_dict: Dict[str, Any] = {}
            for k, v in data.items():
                k_lower = str(k).lower()
                if any(sens in k_lower for sens in SENSITIVE_DICT_KEYS):
                    if isinstance(v, list):
                        redacted_dict[k] = ["[REDACTED]" for _ in v]
                    elif isinstance(v, str):
                        redacted_dict[k] = cls.mask_token_display(v)
                    else:
                        redacted_dict[k] = "[REDACTED]"
                else:
                    redacted_dict[k] = cls.redact_data_structure(v)
            return redacted_dict
        elif isinstance(data, list):
            return [cls.redact_data_structure(item) for item in data]
        elif isinstance(data, str):
            return cls.redact_text(data)
        return data

    @classmethod
    def redact_exception(cls, exc: Exception) -> str:
        """Sanitizes exception string representation to prevent secret leakage in logs."""
        return cls.redact_text(str(exc))

    @classmethod
    def pass_through_stream(cls, stream_chunk: bytes) -> bytes:
        """
        CRITICAL ARCHITECTURAL INVARIANT:
        Stream payloads must NEVER be altered or modified by the redaction engine.
        Returns the stream chunk 100% byte-exact and unmodified.
        """
        return stream_chunk
