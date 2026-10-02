# ==============================================================================
# LongCat Sentinel - Tool Capability Manifest & Argument Inspection Engine
# ==============================================================================
import re
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple

class ToolSafetyTier(str, Enum):
    READ_ONLY = "READ_ONLY"
    IDEMPOTENT_WRITE = "IDEMPOTENT_WRITE"
    NON_IDEMPOTENT_WRITE = "NON_IDEMPOTENT_WRITE"
    DESTRUCTIVE = "DESTRUCTIVE"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"

# 6 大基础能力元清单
CAPABILITY_DIMENSIONS = [
    "filesystem_write",
    "filesystem_delete",
    "process_execute",
    "network_access",
    "database_modify",
    "repository_modify"
]

# 高危破坏性模式库 (全量开启 re.IGNORECASE 与 词边界 \b)
DANGEROUS_PATTERNS = [
    # 1. 递归删除与文件抹除
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+|--recursive\s+|--force\s+)*(?:--no-preserve-root\s+)?(?:\/|\*|~|\$HOME|\.\.)\b", re.IGNORECASE), "Recursive file deletion on root or parent directory"),
    (re.compile(r"\bfind\s+(?:[\/\*~]|\$HOME).*-delete\b", re.IGNORECASE), "Dangerous find with -delete action"),
    (re.compile(r"\bpython(?:\d+)?\s+-c\s+.*(?:shutil\.rmtree|os\.remove|os\.unlink|os\.system)\b", re.IGNORECASE), "Python inline destructive execution"),
    
    # 2. 磁盘格式化与底层写入
    (re.compile(r"\bshred\b(?:\s+-[a-zA-Z]+)*\s+[\/\*~]", re.IGNORECASE), "File shredding command"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", re.IGNORECASE), "Filesystem format command"),
    (re.compile(r"\bdd\s+.*if=.*of=\/dev\/(?:sd|nvme|hd|vd|null|zero)", re.IGNORECASE), "Raw device block write via dd"),
    
    # 3. 提权与全局权限篡改
    (re.compile(r"\bchmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+)?(?:777|000)\b", re.IGNORECASE), "Insecure permissions override (777/000)"),
    (re.compile(r"\bchown\s+-[a-zA-Z]*R[a-zA-Z]*\s+", re.IGNORECASE), "Recursive ownership override"),
    
    # 4. 数据库毁灭性 DDL/DML
    (re.compile(r"\b(?:drop\s+(?:database|table|schema)|truncate\s+table|delete\s+from\s+\w+\s*(?:;|$|\s+where\s+1\s*=\s*1))\b", re.IGNORECASE), "Destructive SQL operation"),
    
    # 5. 危险管道远程执行
    (re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:bash|sh|python|zsh)\b", re.IGNORECASE), "Remote script pipe to shell"),
]

# 工具名默认映射的能力元推断
DEFAULT_TOOL_CAPABILITIES: Dict[str, List[str]] = {
    "terminal": ["process_execute", "filesystem_write", "filesystem_delete", "network_access"],
    "execute_command": ["process_execute", "filesystem_write", "filesystem_delete"],
    "bash": ["process_execute", "filesystem_write", "filesystem_delete", "network_access"],
    "shell": ["process_execute", "filesystem_write", "filesystem_delete", "network_access"],
    "write_file": ["filesystem_write"],
    "create_file": ["filesystem_write"],
    "delete_file": ["filesystem_delete"],
    "remove_file": ["filesystem_delete"],
    "read_file": [],
    "view_file": [],
    "search": ["network_access"],
    "fetch_url": ["network_access"],
}

class CapabilityGuard:
    def __init__(self, block_destructive: bool = True):
        self.block_destructive = block_destructive

    def infer_capabilities(self, tool_name: str) -> List[str]:
        name_lower = tool_name.lower()
        for k, caps in DEFAULT_TOOL_CAPABILITIES.items():
            if k in name_lower:
                return caps
        return []

    def inspect_tool_call(self, tool_name: str, arguments: Any) -> Tuple[ToolSafetyTier, Optional[str]]:
        """
        深度扫描 Tool Call 的名称和入参，返回其安全级别和潜在的拦截原因
        """
        caps = self.infer_capabilities(tool_name)
        arg_str = str(arguments) if arguments is not None else ""

        # 检查是否命中破坏性模式
        for pattern, desc in DANGEROUS_PATTERNS:
            if pattern.search(arg_str):
                return ToolSafetyTier.DESTRUCTIVE, f"Triggered destructive pattern: {desc}"

        if "filesystem_delete" in caps:
            return ToolSafetyTier.DESTRUCTIVE, "Direct filesystem delete capability invoked"

        if "process_execute" in caps or "repository_modify" in caps:
            return ToolSafetyTier.NON_IDEMPOTENT_WRITE, None

        if "filesystem_write" in caps or "database_modify" in caps:
            return ToolSafetyTier.IDEMPOTENT_WRITE, None

        if "network_access" in caps:
            return ToolSafetyTier.EXTERNAL_SIDE_EFFECT, None

        return ToolSafetyTier.READ_ONLY, None
