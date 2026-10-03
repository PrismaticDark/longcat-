"""
LongCat Sentinel v2.3.1 Security Hardened Edition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Enterprise-grade dual-track native API circuit breaker and loop prevention
gateway designed for Meituan's LongCat-2.5-Preview model, supporting local
coding agents (Claude Code, Hermes, Cursor) with zero-compromise security,
protocol fidelity, and accurate loop termination.
"""

__version__ = "2.3.1"
__author__ = "LongCat Sentinel Team"

from longcat_sentinel.config import (
    ConfigurationError,
    GatewayConfig,
    load_config,
    validate_tls_startup,
    check_token_strength,
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
from longcat_sentinel.detector.capability_manifest import (
    CapabilityGuard,
    ToolSafetyTier,
    CAPABILITY_DIMENSIONS,
    DANGEROUS_PATTERNS,
)
from longcat_sentinel.detector.loop_scorer import LoopScorer
from longcat_sentinel.detector.parallel_tool_tracker import (
    ParallelToolTracker,
    ToolCallInstance,
)
from longcat_sentinel.detector.ring_buffer import RingBuffer
from longcat_sentinel.detector.tool_loop_guard import ToolLoopGuard, call_signature
from longcat_sentinel.breaker.compliant_injector import (
    CompliantInjector,
    closing_suffix,
)
from longcat_sentinel.parser.stream_fsm import StreamFSM
from longcat_sentinel.circuit_breaker.redactor import DeepRedactor

__all__ = [
    "__version__",
    "ConfigurationError",
    "GatewayConfig",
    "load_config",
    "validate_tls_startup",
    "check_token_strength",
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
    "CapabilityGuard",
    "ToolSafetyTier",
    "CAPABILITY_DIMENSIONS",
    "DANGEROUS_PATTERNS",
    "LoopScorer",
    "ParallelToolTracker",
    "ToolCallInstance",
    "RingBuffer",
    "ToolLoopGuard",
    "call_signature",
    "CompliantInjector",
    "closing_suffix",
    "StreamFSM",
    "DeepRedactor",
]
