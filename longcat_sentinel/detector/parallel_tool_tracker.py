# ==============================================================================
# LongCat Sentinel - Parallel Tool Call Multi-Track State Machine & Tracker
# ==============================================================================
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from .capability_manifest import CapabilityGuard, ToolSafetyTier

class ToolCallInstance:
    def __init__(self, tool_id: str, index: int, name: str = ""):
        self.tool_id = tool_id
        self.index = index
        self.name = name
        self.arguments_buffer = ""
        self.is_complete = False
        self.safety_tier = ToolSafetyTier.READ_ONLY
        self.violation_reason: Optional[str] = None

    def append_arguments(self, delta_json: str):
        self.arguments_buffer += delta_json

    def finalize(self, guard: CapabilityGuard):
        self.is_complete = True
        try:
            parsed = json.loads(self.arguments_buffer)
        except Exception:
            parsed = self.arguments_buffer
        tier, reason = guard.inspect_tool_call(self.name, parsed)
        self.safety_tier = tier
        self.violation_reason = reason

    @property
    def canonical_hash(self) -> str:
        raw = f"{self.name}:{self.arguments_buffer.strip()}"
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

class ParallelToolTracker:
    def __init__(self, guard: Optional[CapabilityGuard] = None):
        self.guard = guard or CapabilityGuard()
        self.active_tools: Dict[int, ToolCallInstance] = {}
        self.history_hashes: List[str] = []

    def start_tool(self, index: int, tool_id: str, name: str) -> ToolCallInstance:
        instance = ToolCallInstance(tool_id=tool_id, index=index, name=name)
        self.active_tools[index] = instance
        return instance

    def append_chunk(self, index: int, delta_args: str) -> Optional[ToolCallInstance]:
        if index in self.active_tools:
            self.active_tools[index].append_arguments(delta_args)
            return self.active_tools[index]
        return None

    def finish_tool(self, index: int) -> Optional[ToolCallInstance]:
        if index in self.active_tools:
            inst = self.active_tools[index]
            inst.finalize(self.guard)
            self.history_hashes.append(inst.canonical_hash)
            return inst
        return None

    def get_open_indices(self) -> List[int]:
        return sorted([idx for idx, inst in self.active_tools.items() if not inst.is_complete], reverse=True)
