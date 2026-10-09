"""
longcat_sentinel.config
~~~~~~~~~~~~~~~~~~~~~~~
Enterprise-grade configuration engine for LongCat Sentinel v2.3.
Provides Pydantic v2 schema validation, zero-plaintext security enforcement,
recursive ${ENV_VAR} interpolation, TLS startup enforcement, and decoupled timeouts.
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dotenv import load_dotenv
import yaml
from pydantic import BaseModel, Field, model_validator

# Automatically load .env file from root directory
load_dotenv()
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")


class ConfigurationError(Exception):
    """Raised when configuration loading, schema validation, or security compliance fails."""
    pass


# Disallowed weak/placeholder tokens in production (exact-match, case-insensitive)
FORBIDDEN_PLAINTEXT_TOKENS = {
    "sk-longcat-placeholder",
    "sk-placeholder",
    "placeholder",
    "default",
    "changeme",
    "admin",
    "admin123",
    "123456",
    "secret",
    "password",
    "test",
    "root",
    "none",
    "null",
}

# Credentials that shipped as defaults in earlier releases. They are public knowledge
# and must NEVER be accepted, no matter how they were supplied.
KNOWN_WEAK_DEFAULTS = {
    "sk-ant-sentinel-gw-8f7a6b5c4d3e2f1a",
    "adm-sentinel-99e8d7c6b5a4",
    "sk-meituan-longcat-demo-key",
    "sk-meituan-your-real-key-here",
    "sk-meituan-your-real-key",
}

# Substrings that always indicate a placeholder / documentation value
WEAK_TOKEN_SUBSTRINGS = (
    "placeholder",
    "your-real-key",
    "your-key-here",
    "changeme",
    "demo-key",
    "example",
    "sample",
    "xxxxxxxx",
    "aaaaaaa",
)

MIN_TOKEN_LENGTH = 32
MIN_TOKEN_UNIQUE_CHARS = 8


def check_token_strength(token: Optional[str], label: str = "token") -> Optional[str]:
    """
    Returns a human-readable rejection reason when the token is weak, or None when it
    is acceptable. Used for gateway/admin credentials in production mode.
    """
    if token is None or not str(token).strip():
        return f"{label} is empty or whitespace-only"

    value = str(token).strip()

    if value in KNOWN_WEAK_DEFAULTS:
        return (
            f"{label} is a well-known default credential shipped by an earlier release; "
            "it is public knowledge and strictly forbidden"
        )

    lowered = value.lower()
    if lowered in FORBIDDEN_PLAINTEXT_TOKENS:
        return f"{label} is a weak or placeholder value ('{value}')"
    for needle in WEAK_TOKEN_SUBSTRINGS:
        if needle in lowered:
            return f"{label} contains the placeholder marker '{needle}'"

    if len(value) < MIN_TOKEN_LENGTH:
        return (
            f"{label} is too short ({len(value)} chars); at least "
            f"{MIN_TOKEN_LENGTH} characters of high-entropy secret are required"
        )
    if len(set(value)) < MIN_TOKEN_UNIQUE_CHARS:
        return f"{label} has too few distinct characters to be high-entropy"

    return None

ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}

# Credentials that must always come from the real environment, never from a
# plaintext default embedded in config.yaml.
SENSITIVE_ENV_VARS = frozenset({"SENTINEL_GATEWAY_TOKEN"})


def validate_tls_startup(
    host: str,
    tls_enabled: bool,
    tls_cert_path: str = "",
    tls_key_path: str = "",
) -> bool:
    """
    Enforces TLS security rules:
    - Loopback interfaces (127.0.0.1, localhost, ::1, [::1]) are permitted without TLS.
    - Any non-loopback interface (0.0.0.0, LAN IP, public IP) requires TLS; otherwise raises ConfigurationError.
    - When TLS is enabled, certificate and private key files must exist on disk.
    """
    host_clean = host.strip().lower()
    if host_clean in LOOPBACK_HOSTS:
        return True

    if not tls_enabled:
        raise ConfigurationError(
            f"FATAL: Binding to external interface '{host}' requires TLS! "
            "TLS must be enabled for non-loopback bindings. "
            "Set tls_enabled: true and configure tls_cert_path and tls_key_path."
        )

    if not tls_cert_path or not os.path.exists(tls_cert_path):
        raise ConfigurationError(
            f"FATAL: TLS certificate file not found at: '{tls_cert_path}'"
        )
    if not tls_key_path or not os.path.exists(tls_key_path):
        raise ConfigurationError(
            f"FATAL: TLS private key file not found at: '{tls_key_path}'"
        )
    return True


def interpolate_env_vars(raw: Any, dev_mode: bool = False) -> Any:
    """
    Recursively replaces ${VAR_NAME} or ${VAR_NAME:-default} with environment variables.
    Enforces zero-plaintext invariants:
    - Missing or empty critical tokens (SENTINEL_GATEWAY_TOKEN, SENTINEL_ADMIN_TOKEN) raise ConfigurationError in production.
    - In dev mode (dev_mode=True), generates dynamic high-entropy ephemeral tokens in memory without writing to disk.
    - Malformed or empty placeholder syntax like ${} or unclosed brackets raises ConfigurationError.
    """
    if isinstance(raw, dict):
        return {k: interpolate_env_vars(v, dev_mode=dev_mode) for k, v in raw.items()}
    elif isinstance(raw, list):
        return [interpolate_env_vars(elem, dev_mode=dev_mode) for elem in raw]
    elif isinstance(raw, str):
        # Syntax check for malformed placeholders
        # 1. Empty placeholder ${} or whitespace-only ${  }
        if re.search(r"\$\{\s*\}", raw):
            raise ConfigurationError(f"FATAL: Malformed empty environment variable placeholder in '{raw}'")

        # 2. Check for unclosed ${...
        pos = 0
        while True:
            idx = raw.find("${", pos)
            if idx == -1:
                break
            end_idx = raw.find("}", idx + 2)
            if end_idx == -1:
                raise ConfigurationError(f"FATAL: Malformed unclosed environment variable placeholder in '{raw}'")
            pos = end_idx + 1

        def repl(match: re.Match) -> str:
            var_name = match.group(1)
            default_val = match.group(2)

            val = os.getenv(var_name)
            if val is not None:
                # Check for whitespace-only token
                if val.strip() == "":
                    if var_name in SENSITIVE_ENV_VARS:
                        raise ConfigurationError(
                            f"FATAL: Environment variable '${var_name}' is empty or whitespace-only! "
                            "Valid security tokens must be configured."
                        )
                return val

            # An explicitly empty default (${VAR:-}) for sensitive security credentials is a configuration error.
            if default_val is not None and default_val.strip() == "":
                if var_name in SENSITIVE_ENV_VARS:
                    raise ConfigurationError(
                        f"FATAL: Sensitive environment variable '${var_name}' cannot have an empty default; "
                        "provide a real value."
                    )
                return ""

            # Dev mode ephemeral token generation
            if dev_mode and var_name in SENSITIVE_ENV_VARS:
                ephemeral = f"dev-{var_name.lower().replace('_', '-')}-{secrets.token_urlsafe(32)}"
                os.environ[var_name] = ephemeral
                return ephemeral

            # Security credentials must never be satisfied by a plaintext default baked
            # into the configuration file: doing so would ship a public secret.
            if var_name in SENSITIVE_ENV_VARS:
                raise ConfigurationError(
                    f"FATAL: Required security environment variable '${var_name}' is not set. "
                    "Plaintext defaults for gateway/admin credentials are strictly prohibited; "
                    "export the variable with a high-entropy secret."
                )

            if default_val is not None:
                return default_val

            # Production strict failure for missing env vars
            raise ConfigurationError(
                f"FATAL: Required environment variable '${var_name}' is not set in environment! "
                "Plaintext tokens or missing credentials are strictly prohibited in production."
            )

        return ENV_VAR_PATTERN.sub(repl, raw)
    return raw


# Alias for backward compatibility / test suite access
_interpolate_env = interpolate_env_vars


class ServerConfig(BaseModel):
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080, ge=0, le=65535)
    workers: int = Field(default=1, ge=1)
    tls_enabled: bool = Field(default=False)
    tls_cert_path: str = Field(default="")
    tls_key_path: str = Field(default="")


class AuthConfig(BaseModel):
    gateway_tokens: List[str] = Field(default_factory=list)
    dashboard_admin_token: str = Field(default="")


class UpstreamConfig(BaseModel):
    base_url: str = Field(default="https://api.longcat.chat")
    api_key: str = Field(default="")
    upstream_timeout_seconds: float = Field(default=180.0, gt=0)
    default_model: str = Field(default="longcat-2.5-preview")


class TimeoutConfig(BaseModel):
    time_to_first_token_seconds: float = Field(default=90.0, gt=0)
    stream_idle_seconds: float = Field(default=30.0, gt=0)


# Alias
TimeoutsConfig = TimeoutConfig


class LimitConfig(BaseModel):
    max_request_body_bytes: int = Field(default=10485760, gt=0)  # 10MB
    ring_buffer_bytes: int = Field(default=2097152, gt=0)       # 2MB
    max_active_streams: int = Field(default=64, gt=0)


# Alias
LimitsConfig = LimitConfig


class SecurityConfig(BaseModel):
    deep_redaction_scope: str = Field(default="logs_and_metrics_only")
    enable_api_docs: bool = Field(default=False)
    allowed_loopback_regex: str = Field(
        default=r"^https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$"
    )
    allowed_origins: List[str] = Field(default_factory=list)
    allowed_hosts: List[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost", "[::1]"]
    )


class ProfileConfig(BaseModel):
    min_period_chars: int = Field(default=16, ge=1)
    repeat_threshold: int = Field(default=4, ge=1)
    window_chars: int = Field(default=4000, ge=100)
    fuzzy_enabled: bool = Field(default=True)
    fuzzy_similarity_ratio: float = Field(default=0.85, ge=0.0, le=1.0)
    fuzzy_repeat_threshold: int = Field(default=4, ge=1)
    max_period_chars: int = Field(default=2000, ge=16)
    block_loop_enabled: bool = Field(default=True)
    block_repeat_threshold: int = Field(default=3, ge=2)
    min_block_chars: int = Field(default=30, ge=10)
    self_loop_heuristics_enabled: bool = Field(default=True)
    self_loop_threshold: int = Field(default=3, ge=2)
    tool_loop_enabled: bool = Field(default=True)
    max_duplicate_tool_calls: int = Field(default=3, ge=1)
    tool_cycle_window: int = Field(default=8, ge=2)
    tool_skeleton_enabled: bool = Field(default=True)
    max_duplicate_skeleton_calls: int = Field(default=3, ge=2)
    think_loop_enabled: bool = Field(default=True)
    max_think_chars: int = Field(default=32000, ge=100)
    longcat_reasoning_guard_enabled: bool = Field(default=True)
    longcat_plan_churn_threshold: int = Field(default=3, ge=2)
    longcat_second_guessing_threshold: int = Field(default=3, ge=2)
    longcat_constraint_threshold: int = Field(default=5, ge=2)
    longcat_min_reasoning_chars: int = Field(default=6000, ge=100)
    longcat_memory_search_threshold: int = Field(default=8, ge=2)
    longcat_hesitation_threshold: int = Field(default=8, ge=2)
    longcat_standalone_hesitation_threshold: int = Field(default=10, ge=2)


class BreakerConfig(BaseModel):
    active_profile: str = Field(default="code_agent")
    streaming_action: str = Field(default="protocol_compliant_inject")
    injection_template: str = Field(
        default="\n\n[LongCat Sentinel 保护性中断] ⚠️ 检测到输出内容/思考链陷入高频周期循环或触发高危拦截（原因：{reason}）。网关已保护性截断以节约 Token。"
    )


class ToolGuardConfig(BaseModel):
    enable_argument_intent_scan: bool = Field(default=True)
    block_destructive_patterns: bool = Field(default=True)
    action_on_destructive: str = Field(default="block_and_freeze")


class ImmunityConfig(BaseModel):
    ignore_whitespaces: bool = Field(default=True)
    ignore_markdown_separators: bool = Field(default=True)
    code_block_multiplier: float = Field(default=1.5, ge=1.0)


class GatewayConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    limits: LimitConfig = Field(default_factory=LimitConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    breaker: BreakerConfig = Field(default_factory=BreakerConfig)
    tool_guard: ToolGuardConfig = Field(default_factory=ToolGuardConfig)
    profiles: Dict[str, ProfileConfig] = Field(default_factory=dict)
    immunity: ImmunityConfig = Field(default_factory=ImmunityConfig)

    # Dynamic runtime state
    dev_mode: bool = Field(default=False)
    actual_bound_port: Optional[int] = Field(default=None)

    @model_validator(mode="after")
    def validate_security_invariants(self) -> GatewayConfig:
        # Invariant 1 & 2: TLS validation
        if not self.dev_mode:
            validate_tls_startup(
                host=self.server.host,
                tls_enabled=self.server.tls_enabled,
                tls_cert_path=self.server.tls_cert_path,
                tls_key_path=self.server.tls_key_path,
            )
        else:
            # In dev mode, still check host loopback vs TLS if certs are specified
            host_clean = self.server.host.strip().lower()
            if host_clean not in LOOPBACK_HOSTS and not self.server.tls_enabled:
                raise ConfigurationError(
                    f"FATAL: Binding to external interface '{self.server.host}' requires TLS! "
                    "Set server.tls_enabled: true and configure tls_cert_path/tls_key_path."
                )

        # Invariant 3: Zero-plaintext enforcement in production
        if not self.dev_mode:
            if not self.auth.gateway_tokens:
                raise ConfigurationError(
                    "FATAL: No gateway tokens configured! SENTINEL_GATEWAY_TOKEN must be set."
                )

            for index, tok in enumerate(self.auth.gateway_tokens):
                reason = check_token_strength(tok, f"gateway_tokens[{index}]")
                if reason is not None:
                    # Never echo the secret itself into the error message.
                    raise ConfigurationError(
                        f"FATAL: Insecure gateway token rejected: {reason}. "
                        "Plaintext tokens or weak defaults are strictly prohibited in production."
                    )

            admin_val = (self.auth.dashboard_admin_token or "").strip()
            if admin_val:
                admin_reason = check_token_strength(admin_val, "dashboard_admin_token")
                if admin_reason is not None:
                    raise ConfigurationError(
                        f"FATAL: Insecure admin token rejected: {admin_reason}. "
                        "SENTINEL_ADMIN_TOKEN must be a high-entropy secret if configured."
                    )
                for index, gateway_token in enumerate(self.auth.gateway_tokens):
                    if gateway_token.strip() == admin_val:
                        raise ConfigurationError(
                            "FATAL: dashboard_admin_token must differ from every gateway token "
                            f"(collides with gateway_tokens[{index}])."
                        )

            upstream_key = (self.upstream.api_key or "").strip()
            if not upstream_key:
                raise ConfigurationError(
                    "FATAL: Upstream api_key is missing! LONGCAT_API_KEY must be set."
                )
            upstream_lower = upstream_key.lower()
            if upstream_key in KNOWN_WEAK_DEFAULTS or any(
                needle in upstream_lower
                for needle in ("placeholder", "your-real-key", "your-key-here", "demo-key")
            ):
                raise ConfigurationError(
                    "FATAL: Upstream api_key is a placeholder or well-known demo value; "
                    "configure a real LONGCAT_API_KEY."
                )

        return self


def load_config(path: Union[str, Path] = "config.yaml", dev_mode: bool = False) -> GatewayConfig:
    """
    Loads configuration from YAML path, interpolates environment variables,
    validates schema with Pydantic v2, and enforces zero-plaintext security invariants.
    Supports PyInstaller onefile execution and dynamic path discovery.
    """
    import sys
    config_path = Path(path)
    if not config_path.is_absolute():
        candidates = []
        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).parent
            bundle_dir = Path(getattr(sys, "_MEIPASS", exe_dir))
            candidates.extend([exe_dir / path, bundle_dir / path])
        # Prefer the packaged/project location over the current working directory so
        # an unrelated config.yaml elsewhere can never be picked up silently.
        candidates.extend([
            Path(__file__).parent.parent / path,
            Path.cwd() / path,
        ])
        found = False
        for c in candidates:
            if c.exists():
                config_path = c
                found = True
                break
        if not found:
            attempted = ", ".join(str(c) for c in candidates)
            raise ConfigurationError(
                f"FATAL: Configuration file '{path}' not found. Searched: {attempted}"
            )
    elif not config_path.exists():
        raise ConfigurationError(f"FATAL: Configuration file not found at: {config_path.resolve()}")

    with open(config_path, "r", encoding="utf-8") as f:
        raw_dict = yaml.safe_load(f) or {}

    interpolated = interpolate_env_vars(raw_dict, dev_mode=dev_mode)
    interpolated["dev_mode"] = dev_mode

    try:
        config = GatewayConfig.model_validate(interpolated)
    except Exception as e:
        if isinstance(e, ConfigurationError):
            raise
        raise ConfigurationError(f"FATAL: Configuration validation failed: {e}") from e

    return config

