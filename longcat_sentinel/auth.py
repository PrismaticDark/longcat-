"""
longcat_sentinel.auth
~~~~~~~~~~~~~~~~~~~~~
Token normalization, constant-time HMAC comparison, inbound Bearer authentication,
X-Admin-Token administration authentication, dynamic loopback Origin validation,
and Host header DNS rebinding defense.
"""

from __future__ import annotations

import hmac
import re
from functools import lru_cache
from typing import List, Optional
from fastapi import Depends, Header, HTTPException, Request, status

# Credentials are compared exactly. Vendor prefixes are NOT stripped: an earlier
# design treated `gw-<secret>` and `sk-ant-sentinel-gw-<secret>` as equivalent,
# which let anyone who learned the suffix authenticate without the full token.
#
# A normalized credential shorter than this (or made only of separators) carries no
# secret material and must be rejected, e.g. 'sk--' collapsing to '-'.
MIN_CORE_TOKEN_LEN = 8

# Dynamic loopback origin regex supporting IPv4 (127.0.0.1), IPv6 ([::1]), localhost, and any port
LOOPBACK_ORIGIN_REGEX = re.compile(
    r"^https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$",
    re.IGNORECASE,
)

# Host header regex supporting loopback hostnames with optional port
LOOPBACK_HOST_REGEX = re.compile(
    r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$",
    re.IGNORECASE,
)


def normalize_token(token: Optional[str]) -> str:
    """
    Strips surrounding whitespace and an optional case-insensitive `Bearer ` scheme,
    then returns the credential verbatim.

    Vendor prefixes (`sk-`, `sk-ant-`, `sk-ant-sentinel-`, ...) are deliberately NOT
    stripped: the credential is the whole string, so knowing only the suffix is never
    enough to authenticate.

    Returns an empty string for corrupt inputs such as 'Bearer ', '   ' or 'sk--'.
    """
    if not token:
        return ""

    cleaned = token.strip()
    if cleaned.lower() == "bearer":
        return ""

    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
        if cleaned.lower() == "bearer":
            return ""

    # A token that collapsed into separators only (e.g. 'sk--' -> '-') carries no
    # credential material and must never be treated as a valid secret.
    if len(cleaned) < MIN_CORE_TOKEN_LEN or not any(ch.isalnum() for ch in cleaned):
        return ""

    return cleaned


def verify_token(provided: Optional[str], expected: Optional[str]) -> bool:
    """
    Normalizes both tokens and performs constant-time HMAC comparison.
    Returns False if either token is empty after normalization.
    """
    core_prov = normalize_token(provided)
    core_exp = normalize_token(expected)
    if not core_prov or not core_exp:
        return False
    return hmac.compare_digest(core_prov.encode("utf-8"), core_exp.encode("utf-8"))


def verify_gateway_token(provided: Optional[str], configured_tokens: List[str]) -> bool:
    """
    Verifies the provided token against a list of configured gateway tokens.
    Returns True if any configured token matches under constant-time comparison.
    """
    core_prov = normalize_token(provided)
    if not core_prov:
        return False

    for configured in configured_tokens:
        core_cfg = normalize_token(configured)
        if core_cfg and hmac.compare_digest(core_prov.encode("utf-8"), core_cfg.encode("utf-8")):
            return True
    return False


@lru_cache(maxsize=8)
def _compile_loopback_pattern(raw_pattern: str) -> "re.Pattern":
    """Compiles the configured loopback Origin regex, falling back to the built-in."""
    if not raw_pattern:
        return LOOPBACK_ORIGIN_REGEX
    try:
        return re.compile(raw_pattern, re.IGNORECASE)
    except re.error:
        return LOOPBACK_ORIGIN_REGEX


def is_allowed_origin(
    origin: Optional[str],
    allowed_origins: Optional[List[str]] = None,
    loopback_pattern: Optional["re.Pattern"] = None,
) -> bool:
    """
    Validates Origin header against security policies:
    1. Empty/None origin (CLI tools like Claude Code, Hermes, curl, local scripts) is allowed.
    2. Dynamic loopback origins (127.0.0.1, localhost, [::1] with any port) are allowed.
    3. Whitelisted explicit origins are allowed.
    4. Malicious external or subdomain bypass origins are rejected.
    """
    if origin is None or origin.strip() == "":
        return True

    clean_origin = origin.strip().rstrip("/")
    if (loopback_pattern or LOOPBACK_ORIGIN_REGEX).match(clean_origin):
        return True

    if allowed_origins and clean_origin in allowed_origins:
        return True

    return False


def is_allowed_host(
    host_header: Optional[str],
    allowed_hosts: Optional[List[str]] = None,
) -> bool:
    """
    Validates Host header to defend against DNS Rebinding attacks.
    Strips port numbers before comparing against whitelisted hosts.
    """
    if not host_header or host_header.strip() == "":
        return False

    clean_host = host_header.strip().lower()
    # Handle IPv6 host format [::1]:8080
    if clean_host.startswith("["):
        host_name = clean_host.split("]")[0] + "]"
    else:
        host_name = clean_host.split(":")[0]

    whitelisted = allowed_hosts or ["127.0.0.1", "localhost", "[::1]"]
    whitelisted_lower = [h.strip().lower() for h in whitelisted]
    return host_name in whitelisted_lower


def validate_host_header(host: Optional[str]) -> bool:
    """Helper function to validate host string against loopback pattern."""
    if not host:
        return False
    return is_allowed_host(host)


def extract_bearer_token(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    anthropic_api_key: Optional[str] = Header(None, alias="anthropic-api-key"),
) -> str:
    """Extracts credentials from Authorization, X-Api-Key, or anthropic-api-key headers."""
    if authorization:
        return authorization
    if x_api_key:
        return x_api_key
    if anthropic_api_key:
        return anthropic_api_key
    return ""


def _require_config(request: Request):
    """Returns the gateway configuration or fails loudly if the app was misassembled."""
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": {
                    "type": "configuration_error",
                    "message": "Gateway configuration is not initialised on this application",
                }
            },
        )
    return config


def _enforce_origin_and_host(request: Request, config) -> None:
    """Shared Origin + Host (DNS rebinding) validation for every authenticated route."""
    loopback_pattern = _compile_loopback_pattern(
        getattr(config.security, "allowed_loopback_regex", "") or ""
    )
    origin = request.headers.get("origin")
    if not is_allowed_origin(origin, config.security.allowed_origins, loopback_pattern):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cross-origin request blocked: Origin '{origin}' is not allowed",
        )

    host = request.headers.get("host")
    if host and not is_allowed_host(host, config.security.allowed_hosts):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Host header: Forbidden",
        )


def _reject_non_bearer_scheme(token: str) -> None:
    """Rejects explicit non-Bearer authorization schemes such as Basic or Negotiate."""
    stripped = (token or "").strip()
    if not stripped:
        return
    parts = stripped.split(None, 1)
    if len(parts) == 2 and parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "type": "authentication_error",
                    "message": "Non-Bearer authorization schemes not supported",
                }
            },
            headers={"WWW-Authenticate": "Bearer"},
        )


async def verify_gateway_auth(
    request: Request,
    token: str = Depends(extract_bearer_token),
) -> str:
    """
    FastAPI dependency for /v1/* endpoints.
    Enforces valid gateway bearer authentication, loopback Origin verification,
    and Host header DNS rebinding validation.
    """
    config = _require_config(request)
    _enforce_origin_and_host(request, config)
    _reject_non_bearer_scheme(token)

    if not token or not verify_gateway_token(token, config.auth.gateway_tokens):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"type": "authentication_error", "message": "Missing Authorization header or invalid token"}},
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


async def verify_admin_auth(
    request: Request,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
) -> str:
    """
    FastAPI dependency for /api/admin/* endpoints.
    Strictly enforces the presence of X-Admin-Token header and constant-time token comparison.
    Omitting X-Admin-Token (even with Bearer token present) is strictly rejected with 401.
    """
    config = _require_config(request)
    _enforce_origin_and_host(request, config)

    expected = (config.auth.dashboard_admin_token or "").strip()
    # When no admin token is configured, allow passwordless access for local administration
    if not expected:
        return "passwordless"

    # Require explicit X-Admin-Token when admin token is configured
    if not x_admin_token or x_admin_token.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"type": "authentication_error", "message": "Missing X-Admin-Token header"}},
        )

    if not verify_token(x_admin_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"type": "authentication_error", "message": "Invalid X-Admin-Token"}},
        )

    return x_admin_token
