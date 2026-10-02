"""
LongCat Sentinel v2.3 Enterprise Final Hardened Edition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enterprise-grade dual-track native API circuit breaker and loop prevention
gateway designed for Meituan's LongCat-2.5-Preview model, supporting local
coding agents (Claude Code, Hermes, Cursor) with zero-compromise security,
protocol fidelity, and accurate loop termination.
"""

__version__ = "2.3.0"
__author__ = "LongCat Sentinel Team"

from longcat_sentinel.config import (
    ConfigurationError,
    GatewayConfig,
    load_config,
    validate_tls_startup,
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
    interpolate_env_vars,
    _interpolate_env,
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

__all__ = [
    "__version__",
    "ConfigurationError",
    "GatewayConfig",
    "load_config",
    "validate_tls_startup",
    "ServerConfig",
    "AuthConfig",
    "UpstreamConfig",
    "TimeoutConfig",
    "TimeoutsConfig",
    "LimitConfig",
    "LimitsConfig",
    "SecurityConfig",
    "ProfileConfig",
    "BreakerConfig",
    "ToolGuardConfig",
    "ImmunityConfig",
    "interpolate_env_vars",
    "_interpolate_env",
    "normalize_token",
    "verify_token",
    "verify_gateway_token",
    "verify_gateway_auth",
    "verify_admin_auth",
    "is_allowed_origin",
    "is_allowed_host",
    "validate_host_header",
    "LOOPBACK_ORIGIN_REGEX",
    "LOOPBACK_HOST_REGEX",
    "DeepRedactor",
]
