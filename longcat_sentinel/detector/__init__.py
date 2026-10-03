"""
longcat_sentinel.detector
~~~~~~~~~~~~~~~~~~~~~~~~~
Loop, capability and tool-call detection primitives.

This package is a regular package (not an implicit namespace package) so
PyInstaller reliably collects it and every module is importable in a frozen build.
"""

from longcat_sentinel.detector.capability_manifest import (
    CAPABILITY_DIMENSIONS,
    DANGEROUS_PATTERNS,
    CapabilityGuard,
    ToolSafetyTier,
)
from longcat_sentinel.detector.loop_scorer import LoopScorer
from longcat_sentinel.detector.parallel_tool_tracker import (
    ParallelToolTracker,
    ToolCallInstance,
)
from longcat_sentinel.detector.ring_buffer import RingBuffer
from longcat_sentinel.detector.tool_loop_guard import ToolLoopGuard, call_signature

__all__ = [
    "CAPABILITY_DIMENSIONS",
    "DANGEROUS_PATTERNS",
    "CapabilityGuard",
    "ToolSafetyTier",
    "LoopScorer",
    "ParallelToolTracker",
    "ToolCallInstance",
    "RingBuffer",
    "ToolLoopGuard",
    "call_signature",
]
