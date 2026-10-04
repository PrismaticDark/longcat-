"""
longcat_sentinel.metrics
~~~~~~~~~~~~~~~~~~~~~~~~
Thread-safe metrics collector and security audit logger.

Tracks total requests, active concurrent streams, tripped circuits, estimated token
savings, and recent audit events. Stream admission is atomic so the active-stream
gauge cannot drift when a client disconnects early.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Dict, List

from .circuit_breaker.redactor import DeepRedactor


class MetricsCollector:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.total_requests = 0
                cls._instance.active_streams = 0
                cls._instance.tripped_circuits = 0
                cls._instance.saved_tokens_estimate = 0
                cls._instance.audit_events = deque(maxlen=50)
                cls._instance._stats_lock = threading.Lock()
        return cls._instance

    # -- request lifecycle ----------------------------------------------------
    def record_request_start(self, protocol: str, model: str) -> None:
        """记录请求开始：总接管数 +1（活跃流由 acquire_stream 单独计量）"""
        with self._stats_lock:
            self.total_requests += 1

    def acquire_stream(self, max_active: int) -> bool:
        """
        Atomically reserves a stream slot. Returns False when the configured
        concurrency ceiling is already reached.
        """
        with self._stats_lock:
            if max_active and self.active_streams >= max_active:
                return False
            self.active_streams += 1
            return True

    def release_stream(self) -> None:
        """连接释放：活跃并发流 -1，永不为负。"""
        with self._stats_lock:
            if self.active_streams > 0:
                self.active_streams -= 1

    # Backwards-compatible alias
    record_stream_closed = release_stream

    # -- audit events ---------------------------------------------------------
    def record_circuit_trip(
        self,
        protocol: str,
        model: str,
        reason: str = "",
        saved_tokens: int = 4096,
        tool_tier: str = "READ_ONLY",
    ) -> None:
        """毫秒级实时记录熔断事件：熔断计数 +1，节省 Token 累加，并生成审计日志"""
        with self._stats_lock:
            self.tripped_circuits += 1
            self.saved_tokens_estimate += max(0, int(saved_tokens))
            # 脱敏作用域 = logs_and_metrics_only：仅审计文本被清洗，业务流保持字节精确。
            safe_reason = DeepRedactor.redact_text(reason or "")
            self.audit_events.appendleft(
                {
                    "time": time.strftime("%H:%M:%S"),
                    "protocol": protocol,
                    "model": model,
                    "tool_tier": tool_tier,
                    "loop_score": "熔断触发 (95/100)",
                    "action": f"⚠️ 保护性截断 ({safe_reason})" if safe_reason else "⚠️ 保护性截断 (死循环熔断)",
                    "is_safe": False,
                }
            )
            # 实时终端可视化高亮呈现 (避免 Windows GBK 控制台编码异常)
            try:
                import sys
                print(
                    f"\n[SENTINEL CIRCUIT BREAKER TRIPPED] [!] {protocol} | Model: {model}\n"
                    f"  |- 触发原因: {safe_reason}\n"
                    f"  |- 预估节省 Token: +{saved_tokens}\n"
                    f"  `- 累计熔断次数: {self.tripped_circuits}\n",
                    flush=True,
                )
            except Exception:
                pass

    def record_safe_completion(self, protocol: str, model: str) -> None:
        """记录正常完成的安全审计日志"""
        with self._stats_lock:
            self.audit_events.appendleft(
                {
                    "time": time.strftime("%H:%M:%S"),
                    "protocol": protocol,
                    "model": model,
                    "tool_tier": "READ_ONLY",
                    "loop_score": "0 / 100 (安全)",
                    "action": "安全放行",
                    "is_safe": True,
                }
            )

    def record_upstream_error(self, protocol: str, model: str, detail: str = "") -> None:
        """Records a failed upstream exchange, which is neither safe nor a circuit trip."""
        with self._stats_lock:
            safe_detail = DeepRedactor.redact_text(detail or "")
            self.audit_events.appendleft(
                {
                    "time": time.strftime("%H:%M:%S"),
                    "protocol": protocol,
                    "model": model,
                    "tool_tier": "READ_ONLY",
                    "loop_score": "-",
                    "action": f"❌ 上游异常转发失败 ({safe_detail})" if safe_detail else "❌ 上游异常转发失败",
                    "is_safe": False,
                }
            )

    # -- snapshot -------------------------------------------------------------
    def get_stats(self) -> Dict[str, Any]:
        """获取当前指标快照"""
        with self._stats_lock:
            return {
                "total_requests": self.total_requests,
                "active_streams": self.active_streams,
                "tripped_circuits": self.tripped_circuits,
                "saved_tokens_estimate": self.saved_tokens_estimate,
                "audit_events": list(self.audit_events),
            }

    def reset(self) -> None:
        """Test helper: restores a clean slate without recreating the singleton."""
        with self._stats_lock:
            self.total_requests = 0
            self.active_streams = 0
            self.tripped_circuits = 0
            self.saved_tokens_estimate = 0
            self.audit_events.clear()


metrics = MetricsCollector()
