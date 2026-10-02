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
from typing import List, Optional, Union
from fastapi import Depends, Header, HTTPException, Request, status

# Prefixes to strip during two-way normalization
TOKEN_PREFIXES = (
    "sk-ant-sentinel-",
    "sk-ant-",
    "sk-sentinel-",
    "sk-",
)

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
    Strips leading and trailing whitespace and known prefixes iteratively.
    Extracts the core credential signature for constant-time comparison.
    Handles case-insensitive Bearer prefix and stacked vendor prefixes.
    Returns empty string for corrupt/empty/prefix-only inputs (e.g. 'Bearer ', 'sk-').
    """
    if not token:
        return ""

    cleaned = token.strip()
    if cleaned.lower() == "bearer":
        return ""

    changed = True
    while changed:
        changed = False
        # Strip case-insensitive 'Bearer ' prefix
        if cleaned.lower().startswith("bearer "):
            cleaned = cleaned[7:].strip()
            changed = True
            if cleaned.lower() == "bearer":
                return ""
        # Strip vendor prefixes
        for prefix in TOKEN_PREFIXES:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):].strip()
                changed = True
            elif cleaned == prefix.rstrip("-"):
                return ""

    if cleaned in ("sk", "sk-", "sk-ant", "sk-ant-", "sk-sentinel", "sk-sentinel-", "sk-ant-sentinel", "sk-ant-sentinel-"):
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


def is_allowed_origin(
    origin: Optional[str],
    allowed_origins: Optional[List[str]] = None,
    actual_bound_port: Optional[int] = None,
    bound_port: Optional[int] = None,
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
    if LOOPBACK_ORIGIN_REGEX.match(clean_origin):
        return True

    if allowed_origins and clean_origin in allowed_origins:
        return True

    return False


def is_allowed_host(
    host_header: Optional[str],
    allowed_hosts: Optional[List[str]] = None,
    bound_port: Optional[int] = None,
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


async def verify_gateway_auth(
    request: Request,
    token: str = Depends(extract_bearer_token),
) -> str:
    """
    FastAPI dependency for /v1/* endpoints.
    Enforces valid gateway bearer authentication, loopback Origin verification,
    and Host header DNS rebinding validation.
    """
    config = getattr(request.app.state, "config", None)
    allowed_origins = config.security.allowed_origins if config else None
    actual_bound_port = getattr(config, "actual_bound_port", None) if config else None
    allowed_hosts = config.security.allowed_hosts if config else None

    # Origin verification
    origin = request.headers.get("origin")
    if not is_allowed_origin(origin, allowed_origins, actual_bound_port):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cross-origin request blocked: Origin '{origin}' is not allowed",
        )

    # Host verification
    host = request.headers.get("host")
    if host and not is_allowed_host(host, allowed_hosts):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Host header: Forbidden",
        )

    # Scheme validation: Reject non-Bearer schemes (e.g., Basic, Digest, Token)
    if token:
        token_strip = token.strip()
        lower_token = token_strip.lower()
        if lower_token.startswith(("basic ", "digest ", "token ")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": {"type": "authentication_error", "message": "Non-Bearer authorization schemes not supported"}},
                headers={"WWW-Authenticate": "Bearer"},
            )

    configured_tokens = config.auth.gateway_tokens if config else []
    if not token or not verify_gateway_token(token, configured_tokens):
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
    config = getattr(request.app.state, "config", None)
    allowed_origins = config.security.allowed_origins if config else None
    actual_bound_port = getattr(config, "actual_bound_port", None) if config else None
    allowed_hosts = config.security.allowed_hosts if config else None

    # Origin verification
    origin = request.headers.get("origin")
    if not is_allowed_origin(origin, allowed_origins, actual_bound_port):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cross-origin request blocked: Origin '{origin}' is not allowed",
        )

    # Host verification
    host = request.headers.get("host")
    if host and not is_allowed_host(host, allowed_hosts):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Host header: Forbidden",
        )

    # Require explicit X-Admin-Token
    if not x_admin_token or x_admin_token.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"type": "authentication_error", "message": "Missing X-Admin-Token header"}},
        )

    expected_token = config.auth.dashboard_admin_token if config else ""
    if not verify_token(x_admin_token, expected_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"type": "authentication_error", "message": "Invalid X-Admin-Token"}},
        )

    return x_admin_token
