# ==============================================================================
# LongCat Sentinel - Tool Call Loop Guard
#
# Bridges the capability manifest (argument-level destructive scan) with a process
# wide repetition ledger, so the gateway can actually stop an agent that keeps
# invoking the same tool with the same arguments, or that ping-pongs between two
# tools forever.
#
# This is the module the stream routers call; previously the capability engine was
# only reachable from the offline simulator.
# ==============================================================================
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import deque
from typing import Any, Deque, Optional, Tuple

from .capability_manifest import CapabilityGuard, ToolSafetyTier

# Call signatures are remembered for this long. Entries also age out by deque length.
DEFAULT_TTL_SECONDS = 600.0
MAX_LEDGER_ENTRIES = 512


def canonical_arguments(arguments: Any) -> str:
    """Stable representation of tool arguments: key order and whitespace never matter."""
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except Exception:
            return arguments.strip()
    try:
        return json.dumps(arguments, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(arguments)


def call_signature(tool_name: str, arguments: Any) -> str:
    material = f"{(tool_name or '').strip().lower()}:{canonical_arguments(arguments)}"
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


class ToolLoopGuard:
    """
    Inspects every tool call the model requests and reports whether it must be stopped.

    Returns a tuple `(violation, reason)` where `violation` is one of:
      * "destructive" - the arguments match a known destructive command pattern
      * "tool_cycle"  - an A->B->A->B ping-pong between tools
      * "tool_loop"   - the same tool + identical arguments repeated too often
      * None          - safe to continue
    """

    _lock = threading.Lock()
    _ledger: Deque[Tuple[float, str]] = deque(maxlen=MAX_LEDGER_ENTRIES)

    def __init__(
        self,
        guard: CapabilityGuard,
        loop_enabled: bool = True,
        max_duplicate_calls: int = 3,
        cycle_window: int = 8,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        freeze_on_destructive: bool = True,
    ):
        self.guard = guard
        self.loop_enabled = bool(loop_enabled)
        self.max_duplicate_calls = max(2, int(max_duplicate_calls))
        self.cycle_window = max(4, int(cycle_window))
        self.ttl_seconds = float(ttl_seconds)
        self.freeze_on_destructive = bool(freeze_on_destructive)

    # -- ledger helpers -------------------------------------------------------
    @classmethod
    def _prune(cls, now: float, ttl: float) -> None:
        while cls._ledger and (now - cls._ledger[0][0]) > ttl:
            cls._ledger.popleft()

    @classmethod
    def _recent_signatures(cls, limit: int) -> list:
        return [signature for _, signature in list(cls._ledger)[-limit:]]

    @classmethod
    def reset(cls) -> None:
        """Clears process-wide state; used by tests and by the admin API."""
        with cls._lock:
            cls._ledger.clear()

    # -- inspection -----------------------------------------------------------
    def inspect(self, tool_name: str, arguments: Any) -> Tuple[Optional[str], Optional[str]]:
        """
        Evaluates a single tool call and records it in the ledger. Call exactly once
        per completed tool call.
        """
        # 1. Argument-level destructive scan (highest priority, never gated by loop settings)
        hit = self.guard.scan_arguments(arguments)
        if hit:
            if self.freeze_on_destructive:
                self._record(tool_name, arguments)
                return "destructive", hit
            # Audited but not blocked: still record so repetition can be tracked.
            self._record(tool_name, arguments)
            return None, None

        signature = call_signature(tool_name, arguments)
        now = time.time()

        with self._lock:
            self._prune(now, self.ttl_seconds)

            if self.loop_enabled:
                # 2. Ping-pong cycle detection over the recent window
                cycle = self._detect_cycle(signature)
                if cycle is not None:
                    self._ledger.append((now, signature))
                    return "tool_cycle", cycle

                # 3. Same tool + identical arguments repeated too many times
                repeats = sum(1 for _, sig in self._ledger if sig == signature) + 1
                self._ledger.append((now, signature))
                if repeats >= self.max_duplicate_calls:
                    return "tool_loop", (
                        f"Repeated identical tool call: '{tool_name}' invoked "
                        f"{repeats}x with unchanged arguments"
                    )
                return None, None

            self._ledger.append((now, signature))
            return None, None

    def _record(self, tool_name: str, arguments: Any) -> None:
        now = time.time()
        with self._lock:
            self._prune(now, self.ttl_seconds)
            self._ledger.append((now, call_signature(tool_name, arguments)))

    def _detect_cycle(self, candidate: str) -> Optional[str]:
        """Detects X1..Xk X1..Xk (k >= 2) in the recent ledger plus the pending call."""
        window = self._recent_signatures(self.cycle_window)
        if not window:
            return None

        sequence = window + [candidate]
        n = len(sequence)
        for k in range(2, n // 2 + 1):
            if n < 2 * k:
                continue
            tail = sequence[-k:]
            head = sequence[-2 * k:-k]
            if tail == head and len(set(tail)) > 1:
                return (
                    f"Tool call cycle detected: a {k}-step pattern repeated "
                    f"(window={self.cycle_window})"
                )
        return None
