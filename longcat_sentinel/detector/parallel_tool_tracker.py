# ==============================================================================
# LongCat Sentinel - Parallel Tool Call Multi-Track State Machine & Tracker
#
# Streams can interleave several tool calls (Anthropic `content_block` indices,
# OpenAI `tool_calls[].index`). Each open call gets its own instance so argument
# fragments are never mixed across tools, and `get_open_indices` tells the
# protocol-compliant injector exactly which blocks still need closing.
# ==============================================================================
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .capability_manifest import CapabilityGuard, ToolSafetyTier
from .tool_loop_guard import call_signature, canonical_arguments


class ToolCallInstance:
    def __init__(self, tool_id: str, index: int, name: str = ""):
        self.tool_id = tool_id
        self.index = index
        self.name = name
        self.arguments_buffer = ""
        self.is_complete = False
        self.safety_tier = ToolSafetyTier.READ_ONLY
        self.violation_reason: Optional[str] = None

    def append_arguments(self, delta_json: str) -> None:
        if delta_json:
            self.arguments_buffer += delta_json

    def set_name(self, name: str) -> None:
        if name:
            self.name = name

    @property
    def parsed_arguments(self) -> Any:
        if not self.arguments_buffer.strip():
            return {}
        try:
            return json.loads(self.arguments_buffer)
        except Exception:
            return self.arguments_buffer

    def finalize(self, guard: CapabilityGuard) -> None:
        self.is_complete = True
        tier, reason = guard.inspect_tool_call(self.name, self.parsed_arguments)
        self.safety_tier = tier
        self.violation_reason = reason

    @property
    def canonical_hash(self) -> str:
        return call_signature(self.name, self.arguments_buffer)

    @property
    def canonical_arguments(self) -> str:
        return canonical_arguments(self.arguments_buffer)


class ParallelToolTracker:
    def __init__(self, guard: Optional[CapabilityGuard] = None):
        self.guard = guard or CapabilityGuard()
        self.active_tools: Dict[int, ToolCallInstance] = {}
        self.history_hashes: List[str] = []

    def start_tool(self, index: int, tool_id: str, name: str = "") -> ToolCallInstance:
        instance = ToolCallInstance(tool_id=tool_id, index=index, name=name)
        self.active_tools[index] = instance
        return instance

    def get_or_start(self, index: int, tool_id: str = "", name: str = "") -> ToolCallInstance:
        instance = self.active_tools.get(index)
        if instance is None:
            instance = self.start_tool(index, tool_id, name)
        else:
            if name:
                instance.set_name(name)
            if tool_id and not instance.tool_id:
                instance.tool_id = tool_id
        return instance

    def append_chunk(self, index: int, delta_args: str) -> Optional[ToolCallInstance]:
        instance = self.active_tools.get(index)
        if instance is None:
            return None
        instance.append_arguments(delta_args)
        return instance

    def finish_tool(self, index: int) -> Optional[ToolCallInstance]:
        instance = self.active_tools.get(index)
        if instance is None:
            return None
        instance.finalize(self.guard)
        self.history_hashes.append(instance.canonical_hash)
        return instance

    def get_open_indices(self) -> List[int]:
        return sorted(
            [idx for idx, inst in self.active_tools.items() if not inst.is_complete],
            reverse=True,
        )

    def get_open_tool_indices(self) -> List[int]:
        """Indices whose block is a tool call (as opposed to text/thinking)."""
        return sorted(
            [
                idx
                for idx, inst in self.active_tools.items()
                if not inst.is_complete and (inst.name or inst.arguments_buffer)
            ],
            reverse=True,
        )
