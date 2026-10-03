# ==============================================================================
# LongCat Sentinel - Tool Capability Manifest & Argument Inspection Engine
#
# Two-stage model:
#   1. `infer_capabilities` classifies a tool by NAME (exact, then token match).
#   2. `scan_arguments` inspects the ARGUMENTS, which is where real destructive
#      intent lives. A shell tool is not inherently destructive: `ls` and
#      `rm -rf /` must not share the same verdict.
# ==============================================================================
from __future__ import annotations

import re
from enum import Enum
from typing import Any, List, Optional, Tuple

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
    "repository_modify",
]

# 高危破坏性模式库 (全量开启 re.IGNORECASE 与 词边界 \b)
DANGEROUS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # 1. 递归删除与文件抹除 (POSIX)
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+|--recursive\s+|--force\s+)*(?:--no-preserve-root\s+)?(?:/|\*|~|\$HOME|\.\.)(?:\s|$)", re.IGNORECASE), "Recursive file deletion on root or parent directory"),
    (re.compile(r"\bfind\s+(?:[/\*~]|\$HOME).*-delete\b", re.IGNORECASE), "Dangerous find with -delete action"),
    (re.compile(r"\bpython(?:\d+)?\s+-c\s+.*(?:shutil\.rmtree|os\.remove|os\.unlink|os\.system)\b", re.IGNORECASE), "Python inline destructive execution"),
    (re.compile(r"\bgit\s+(?:reset\s+--hard|clean\s+-[a-zA-Z]*f[a-zA-Z]*d)", re.IGNORECASE), "Destructive git working-tree reset"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:", re.IGNORECASE), "Shell fork bomb"),

    # 1b. Windows 破坏性删除 / 格式化
    (re.compile(r"\b(?:del|erase)\s+(?:/[a-zA-Z]+\s+)*[a-zA-Z]:[\\/]", re.IGNORECASE), "Windows recursive delete on a drive root"),
    (re.compile(r"\b(?:rd|rmdir)\s+/[a-zA-Z]*s[a-zA-Z]*\s+[a-zA-Z]:[\\/]", re.IGNORECASE), "Windows recursive directory removal"),
    (re.compile(r"\bRemove-Item\b[^\n]*-(?:Recurse|Force)[^\n]*[a-zA-Z]:[\\/]", re.IGNORECASE), "PowerShell recursive forced removal"),
    (re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE), "Windows volume format command"),
    (re.compile(r"\bdiskpart\b", re.IGNORECASE), "Raw disk partitioning tool"),

    # 2. 磁盘格式化与底层写入
    (re.compile(r"\bshred\b(?:\s+-[a-zA-Z]+)*\s+[/\*~]", re.IGNORECASE), "File shredding command"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b", re.IGNORECASE), "Filesystem format command"),
    (re.compile(r"\bdd\s+.*if=.*of=/dev/(?:sd|nvme|hd|vd|null|zero)", re.IGNORECASE), "Raw device block write via dd"),
    (re.compile(r">\s*/dev/(?:sd|nvme|hd|vd)[a-z]?\b", re.IGNORECASE), "Redirection onto a raw block device"),

    # 3. 提权与全局权限篡改
    (re.compile(r"\bchmod\s+(?:-[a-zA-Z]*R[a-zA-Z]*\s+)?(?:777|000)\b", re.IGNORECASE), "Insecure permissions override (777/000)"),
    (re.compile(r"\bchown\s+-[a-zA-Z]*R[a-zA-Z]*\s+", re.IGNORECASE), "Recursive ownership override"),

    # 4. 数据库毁灭性 DDL/DML
    (re.compile(r"\b(?:drop\s+(?:database|table|schema)|truncate\s+table|delete\s+from\s+\w+\s*(?:;|$|\s+where\s+1\s*=\s*1))\b", re.IGNORECASE), "Destructive SQL operation"),

    # 5. 危险管道远程执行
    (re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:bash|sh|python|zsh|powershell)\b", re.IGNORECASE), "Remote script pipe to shell"),
    (re.compile(r"\b(?:Invoke-Expression|iex)\b[^\n]*\|", re.IGNORECASE), "PowerShell remote pipe execution"),
]

# 工具名 -> 能力元推断规则。
# 顺序敏感：先匹配到的规则生效。名称按 `_` 分词后做精确匹配，再做 token 匹配，
# 因此 "read_file" 不会因为包含 "file" 而被误判为写操作。
TOOL_CAPABILITY_RULES: List[Tuple[Tuple[str, ...], List[str]]] = [
    (
        ("terminal", "execute_command", "bash", "sh", "shell", "run_command", "exec",
         "cmd", "powershell", "pwsh", "spawn", "subprocess"),
        ["process_execute", "network_access"],
    ),
    (
        ("write_file", "create_file", "append_file", "edit_file", "str_replace",
         "apply_patch", "save_file", "mkdir", "touch"),
        ["filesystem_write"],
    ),
    (
        ("delete_file", "remove_file", "unlink", "rmdir"),
        ["filesystem_delete"],
    ),
    (
        ("read_file", "view_file", "open_file", "list_dir", "list_files", "glob",
         "grep", "search_code", "cat"),
        [],
    ),
    (
        ("fetch_url", "web_search", "web_fetch", "http_request", "browse", "download"),
        ["network_access"],
    ),
    (
        ("db_execute", "sql_query", "sql_execute", "database", "execute_sql"),
        ["database_modify"],
    ),
    (
        ("git_commit", "git_push", "git_reset", "git_apply", "git_merge", "git_rebase"),
        ["repository_modify"],
    ),
]


def _normalize_tool_name(tool_name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (tool_name or "").lower()).strip("_")


class CapabilityGuard:
    def __init__(self, block_destructive: bool = True):
        self.block_destructive = block_destructive

    # -- capability inference -------------------------------------------------
    def infer_capabilities(self, tool_name: str) -> List[str]:
        normalized = _normalize_tool_name(tool_name)
        if not normalized:
            return []

        tokens = set(normalized.split("_"))
        for names, capabilities in TOOL_CAPABILITY_RULES:
            if normalized in names:
                return list(capabilities)
        for names, capabilities in TOOL_CAPABILITY_RULES:
            if tokens.intersection(names):
                return list(capabilities)
        return []

    # -- argument inspection --------------------------------------------------
    @staticmethod
    def flatten_arguments(arguments: Any) -> str:
        """Recursively joins every key and scalar value so patterns cannot hide in nesting."""
        parts: List[str] = []

        def walk(node: Any) -> None:
            if node is None:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    parts.append(str(key))
                    walk(value)
            elif isinstance(node, (list, tuple, set)):
                for item in node:
                    walk(item)
            else:
                parts.append(str(node))

        walk(arguments)
        return " ".join(parts)

    def scan_arguments(self, arguments: Any) -> Optional[str]:
        """Returns the description of the first destructive pattern hit, else None."""
        if not self.block_destructive:
            return None
        arg_str = self.flatten_arguments(arguments)
        if not arg_str:
            return None
        for pattern, description in DANGEROUS_PATTERNS:
            if pattern.search(arg_str):
                return description
        return None

    def inspect_tool_call(self, tool_name: str, arguments: Any) -> Tuple[ToolSafetyTier, Optional[str]]:
        """
        深度扫描 Tool Call 的名称和入参，返回其安全级别和潜在的拦截原因。

        A shell tool is `NON_IDEMPOTENT_WRITE`, not `DESTRUCTIVE`: only concrete
        destructive argument patterns escalate the verdict.
        """
        capabilities = self.infer_capabilities(tool_name)

        hit = self.scan_arguments(arguments)
        if hit:
            return ToolSafetyTier.DESTRUCTIVE, f"Triggered destructive pattern: {hit}"

        if "filesystem_delete" in capabilities:
            return ToolSafetyTier.DESTRUCTIVE, "Direct filesystem delete capability invoked"

        if "process_execute" in capabilities or "repository_modify" in capabilities:
            return ToolSafetyTier.NON_IDEMPOTENT_WRITE, None

        if "filesystem_write" in capabilities or "database_modify" in capabilities:
            return ToolSafetyTier.IDEMPOTENT_WRITE, None

        if "network_access" in capabilities:
            return ToolSafetyTier.EXTERNAL_SIDE_EFFECT, None

        return ToolSafetyTier.READ_ONLY, None
