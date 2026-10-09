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


SHELL_TOOLS = frozenset(
    {"pwsh", "powershell", "bash", "sh", "cmd", "terminal", "execute_command", "run_command"}
)


def extract_command(arguments: Any) -> str:
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except Exception:
            return arguments
    if isinstance(arguments, dict):
        for k in ("command", "cmd", "script", "code"):
            if k in arguments and isinstance(arguments[k], str):
                return arguments[k]
    return ""


def normalize_tool_skeleton(tool_name: str, arguments: Any) -> str:
    """提取工具命令语义骨架，消除微调搜索后缀、重定向和管道限制器引起的虚假差异。"""
    import re
    t_lower = (tool_name or "").strip().lower()
    cmd = extract_command(arguments)
    if not cmd or t_lower not in SHELL_TOOLS:
        return canonical_arguments(arguments)

    c = cmd.lower()
    # 消除输出重定向差异
    c = re.sub(r"2>&1|2>\$null|2>/dev/null|>\$null|>/dev/null", "", c)
    # 消除管道行数限制器差异
    c = re.sub(r"\|\s*(select-object|head|tail|limit)\s+[^|;]+", "", c)
    # 消除调试探测打印差异 (如 print(p);)
    c = re.sub(r"print\([a-zA-Z0-9_.]+\);\s*", "", c)
    # 消除目录遍历中文件过滤表达式变动 (如 for f in fn if 'hand' vs f.endswith(...))
    c = re.sub(r"for\s+f\s+in\s+fn\s+if\s+.*\]", "for f in fn if <FILTER_EXPR>]", c)
    # 消除调试筛选关键字变动 (保留具体的后缀名区分，仅折叠通用标记)
    c = re.sub(r"['\"][^'\"]*hand[^'\"]*['\"]\s+in\s+f\.lower\(\)", "<SEARCH_FILTER>", c)
    c = re.sub(r"\s+", " ", c).strip()
    return f"{t_lower}:{c}"


def skeleton_signature(tool_name: str, arguments: Any) -> str:
    material = normalize_tool_skeleton(tool_name, arguments)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def call_signature(tool_name: str, arguments: Any) -> str:
    material = f"{(tool_name or '').strip().lower()}:{canonical_arguments(arguments)}"
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


class ToolLoopGuard:
    """
    Inspects every tool call the model requests and reports whether it must be stopped.

    Returns a tuple `(violation, reason)` where `violation` is one of:
      * "destructive" - the arguments match a known destructive command pattern
      * "tool_cycle"  - an A->B->A->B ping-pong between tools (exact or semantic skeleton)
      * "tool_loop"   - the same tool + identical or near-identical arguments repeated too often
      * None          - safe to continue
    """

    _active_instances: list[ToolLoopGuard] = []
    _instances_lock = threading.Lock()

    def __init__(
        self,
        guard: CapabilityGuard,
        loop_enabled: bool = True,
        max_duplicate_calls: int = 3,
        cycle_window: int = 8,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        freeze_on_destructive: bool = True,
        tool_skeleton_enabled: bool = True,
        max_duplicate_skeleton_calls: int = 3,
    ):
        self.guard = guard
        self.loop_enabled = bool(loop_enabled)
        self.max_duplicate_calls = max(2, int(max_duplicate_calls))
        self.cycle_window = max(4, int(cycle_window))
        self.ttl_seconds = float(ttl_seconds)
        self.freeze_on_destructive = bool(freeze_on_destructive)
        self.tool_skeleton_enabled = bool(tool_skeleton_enabled)
        self.max_duplicate_skeleton_calls = max(2, int(max_duplicate_skeleton_calls))

        self._lock = threading.Lock()
        self._ledger: Deque[Tuple[float, str]] = deque(maxlen=MAX_LEDGER_ENTRIES)
        self._skeleton_ledger: Deque[Tuple[float, str, str]] = deque(maxlen=MAX_LEDGER_ENTRIES)

        with ToolLoopGuard._instances_lock:
            ToolLoopGuard._active_instances.append(self)

    # -- ledger helpers -------------------------------------------------------
    def _prune(self, now: float, ttl: float) -> None:
        while self._ledger and (now - self._ledger[0][0]) > ttl:
            self._ledger.popleft()
        while self._skeleton_ledger and (now - self._skeleton_ledger[0][0]) > ttl:
            self._skeleton_ledger.popleft()

    def _recent_signatures(self, limit: int) -> list:
        return [signature for _, signature in list(self._ledger)[-limit:]]

    def _recent_skeletons(self, limit: int) -> list:
        return [signature for _, signature, _ in list(self._skeleton_ledger)[-limit:]]

    @classmethod
    def reset(cls) -> None:
        """Clears state across all active instances; used by tests and by the admin API."""
        with cls._instances_lock:
            for inst in cls._active_instances:
                with inst._lock:
                    inst._ledger.clear()
                    inst._skeleton_ledger.clear()
            cls._active_instances.clear()

    def reset_instance(self) -> None:
        """Clears state for this instance specifically."""
        with self._lock:
            self._ledger.clear()
            self._skeleton_ledger.clear()

    # -- inspection -----------------------------------------------------------
    def is_progress_action(self, tool_name: str, arguments: Any) -> bool:
        """Identify whether a tool call represents substantial progress (e.g. file writing, code editing)."""
        norm = str(tool_name).lower()
        if any(k in norm for k in ("write", "edit", "replace", "patch", "create", "save", "append", "modify")):
            return True
        capabilities = self.guard.infer_capabilities(tool_name)
        if "filesystem_write" in capabilities or "database_modify" in capabilities:
            return True
        return False

    def inspect(
        self, tool_name: str, arguments: Any
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Evaluates a single tool call and records it in the ledger. Call exactly once
        per completed tool call.
        """
        # 1. Argument-level destructive scan (highest priority, never gated by loop settings)
        tier, reason = self.guard.inspect_tool_call(tool_name, arguments)
        if tier == ToolSafetyTier.DESTRUCTIVE and reason:
            if self.freeze_on_destructive:
                self._record(tool_name, arguments)
                return "destructive", reason
            # Audited but not blocked: still record so repetition can be tracked.
            self._record(tool_name, arguments)
            return None, None

        signature = call_signature(tool_name, arguments)
        skeleton_sig = (
            skeleton_signature(tool_name, arguments)
            if self.tool_skeleton_enabled
            else signature
        )
        raw_cmd = extract_command(arguments) or canonical_arguments(arguments)
        cmd_sample = (raw_cmd[:60] + "...") if len(raw_cmd) > 60 else raw_cmd
        now = time.time()
        is_progress = self.is_progress_action(tool_name, arguments)

        with self._lock:
            self._prune(now, self.ttl_seconds)

            if self.loop_enabled:
                # 2. Ping-pong cycle detection over the recent window (exact)
                cycle = self._detect_cycle(signature)
                if cycle is not None:
                    self._ledger.append((now, signature))
                    if self.tool_skeleton_enabled:
                        self._skeleton_ledger.append((now, skeleton_sig, cmd_sample))
                    return "tool_cycle", cycle

                # 3. Same tool + identical arguments repeated in recent window (exact)
                recent_window = max(self.cycle_window, self.max_duplicate_calls * 2)
                recent_sigs = [sig for _, sig in list(self._ledger)[-recent_window:]]
                repeats = sum(1 for sig in recent_sigs if sig == signature) + 1
                self._ledger.append((now, signature))
                if repeats >= self.max_duplicate_calls:
                    if self.tool_skeleton_enabled:
                        self._skeleton_ledger.append((now, skeleton_sig, cmd_sample))
                    return "tool_loop", (
                        f"Repeated identical tool call: '{tool_name}' invoked "
                        f"{repeats}x with unchanged arguments"
                    )

                # 4. 语义命令骨架循环与重复检测 (微调搜索后缀、管道和重定向绕过识别)
                if self.tool_skeleton_enabled and skeleton_sig:
                    # 4a. 语义骨架周期性循环 (如 A->B->A->B)
                    sk_cycle = self._detect_skeleton_cycle(skeleton_sig)
                    if sk_cycle is not None:
                        self._skeleton_ledger.append((now, skeleton_sig, cmd_sample))
                        return "tool_cycle", sk_cycle

                    # 4b. 语义骨架在滑动窗口内的高频重复 (同义探测反复空转)
                    recent_sk_window = max(self.cycle_window, self.max_duplicate_skeleton_calls * 2)
                    recent_sks = [sig for _, sig, _ in list(self._skeleton_ledger)[-recent_sk_window:]]
                    sk_repeats = (
                        sum(1 for sig in recent_sks if sig == skeleton_sig)
                        + 1
                    )
                    self._skeleton_ledger.append((now, skeleton_sig, cmd_sample))
                    if sk_repeats >= self.max_duplicate_skeleton_calls:
                        return "tool_loop", (
                            f"Repeated semantic tool call: '{tool_name}' invoked "
                            f"{sk_repeats}x with near-identical command intent: '{cmd_sample}'"
                        )
                else:
                    self._skeleton_ledger.append((now, f"tool:{tool_name}", ""))

                # 5. 进展感知驱动的探测历史衰减 (Progress Tracking):
                # 若本次操作代表了实质性的文件/代码写入进展，且未触发死循环，
                # 则自动清空先前积累的只读与状态探测历史，让后续验证操作（如 git status, pytest, read_file）获得全新的探索预算
                if is_progress:
                    self._ledger = deque([(now, signature)], maxlen=MAX_LEDGER_ENTRIES)
                    self._skeleton_ledger = deque([(now, f"tool:{tool_name}", "")], maxlen=MAX_LEDGER_ENTRIES)

                return None, None

            self._ledger.append((now, signature))
            if self.tool_skeleton_enabled:
                self._skeleton_ledger.append((now, skeleton_sig, cmd_sample))
            return None, None

    def _record(self, tool_name: str, arguments: Any) -> None:
        now = time.time()
        with self._lock:
            self._prune(now, self.ttl_seconds)
            self._ledger.append((now, call_signature(tool_name, arguments)))
            if self.tool_skeleton_enabled:
                raw_cmd = extract_command(arguments) or canonical_arguments(arguments)
                cmd_sample = (raw_cmd[:60] + "...") if len(raw_cmd) > 60 else raw_cmd
                self._skeleton_ledger.append(
                    (now, skeleton_signature(tool_name, arguments), cmd_sample)
                )

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

    def _detect_skeleton_cycle(self, candidate: str) -> Optional[str]:
        """Detects semantic skeleton cycles over the recent ledger."""
        window = self._recent_skeletons(self.cycle_window)
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
                    f"Tool semantic cycle detected: a {k}-step command pattern repeated "
                    f"(window={self.cycle_window})"
                )
        return None
