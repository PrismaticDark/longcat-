"""
longcat_sentinel.metrics
~~~~~~~~~~~~~~~~~~~~~~~~
High-performance, thread-safe metrics collector and security audit logger.
Tracks total requests, active concurrent streams, tripped circuits,
estimated token savings, and recent audit events.
"""

import time
import threading
from collections import deque
from typing import Any, Dict, List


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

    def record_request_start(self, protocol: str, model: str) -> None:
        """记录请求开始：总接管数立即 +1，活跃并发流 +1"""
        with self._stats_lock:
            self.total_requests += 1
            self.active_streams += 1

    def record_circuit_trip(
        self,
        protocol: str,
        model: str,
        reason: str = "",
        saved_tokens: int = 4096
    ) -> None:
        """毫秒级实时记录熔断事件：熔断计数立即 +1，节省 Token 立即累加，并生成审计日志"""
        with self._stats_lock:
            self.tripped_circuits += 1
            self.saved_tokens_estimate += saved_tokens
            current_time = time.strftime("%H:%M:%S")
            self.audit_events.appendleft({
                "time": current_time,
                "protocol": protocol,
                "model": model,
                "tool_tier": "READ_ONLY",
                "loop_score": "熔断触发 (95/100)",
                "action": f"⚠️ 保护性截断 ({reason})" if reason else "⚠️ 保护性截断 (死循环熔断)",
                "is_safe": False
            })

    def record_safe_completion(self, protocol: str, model: str) -> None:
        """记录正常完成的安全审计日志"""
        with self._stats_lock:
            current_time = time.strftime("%H:%M:%S")
            self.audit_events.appendleft({
                "time": current_time,
                "protocol": protocol,
                "model": model,
                "tool_tier": "READ_ONLY",
                "loop_score": "0 / 100 (安全)",
                "action": "安全放行",
                "is_safe": True
            })

    def record_stream_closed(self) -> None:
        """连接释放：活跃并发流 -1"""
        with self._stats_lock:
            if self.active_streams > 0:
                self.active_streams -= 1

    def get_stats(self) -> Dict[str, Any]:
        """获取当前指标快照"""
        with self._stats_lock:
            return {
                "total_requests": self.total_requests,
                "active_streams": self.active_streams,
                "tripped_circuits": self.tripped_circuits,
                "saved_tokens_estimate": self.saved_tokens_estimate,
                "audit_events": list(self.audit_events)
            }


metrics = MetricsCollector()
