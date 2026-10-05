# ==============================================================================
# LongCat Sentinel - 1:1 Tailored Reasoning Guard for Meituan LongCat Models
# Version: 2.5 Hardened Edition (Cognitive Stalling & Memory Retrieval Aware)
#
# Dedicated Defense Architecture for LongCat MoE Thinking & Agent Workflows:
# - Meituan LongCat-2.5-Preview & LongCat-Flash-Thinking Architectures feature
#   Multi-Path Parallel Thinking and Recursive Reasoning / Iterative Refinement.
#
# Pathology Dimensions Detected:
# 1. Plan Churn & Abandonment: Re-planning >= 3x with explicit abandonment.
# 2. Memory Retrieval & Deliberation Loop (Cognitive Stalling): Endlessly cycling
#    through internal memory recall ("searching memory", "release notes", "recall harder")
#    without making empirical tool calls or progress.
#
# Anti-False-Positive Invariants:
# 1. Hard Minimum Threshold: Thinking chains under 3,500 characters are 100% exempt.
# 2. Action Readiness Exemption: Concrete checklist in tail 800 chars forces allowance.
# 3. Interval Convergence Awareness: Decreasing gaps between action announcements are exempt.
# ==============================================================================
from __future__ import annotations

import re
from typing import List, Optional, Tuple


# 待办清单项正则: 识别末尾阶段的具体行动条目 (例如 "- check python", "1. inspect cwd")
_CHECKLIST_ITEM_RE = re.compile(
    r"(?m)^[ \t]*(?:[-*•]|\d+[\.)])[ \t]+[A-Za-z0-9_\u4e00-\u9fa5]"
)

# 明确行动宣告与工具调用前瞻模式 (Action Initiation & Tool Handover Patterns)
_ACTION_INITIATION_PATTERNS = [
    re.compile(
        r"\b(?:let\s+me\s+(?:start\s+(?:by\s+)?|first\s+)?(?:check|run|inspect|explore|test|execute|try|investigate|verify|search)|"
        r"i\s*['’]?ll\s+(?:use|run|execute|check|inspect|start\s+with)|"
        r"i\s+will\s+(?:use|run|execute|check|inspect|start\s+with)|"
        r"i\s+need\s+to\s+(?:run|check|inspect|execute)|"
        r"let\s*['’]?s\s+(?:run|check|inspect|test|execute)|"
        r"now\s+let\s+me\s+(?:proceed|run|execute|check))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:开始执行|运行命令|先检查|开始排查|我将使用|接下来运行|先查看|通过终端|执行脚本|开始测试|开始探索|接下来开始|现在开始)",
        re.IGNORECASE,
    ),
]

# 计划拟定模式 (Plan Initiations)
_PLAN_CHURN_PATTERNS = [
    re.compile(
        r"\b(?:let\s+me\s+plan|the\s+plan\s*[:\s]|plan\s*:\s*|my\s+plan\s*[:\s]|"
        r"here\s+is\s+the\s+plan|the\s+proposed\s+plan|"
        r"let\s+me\s+start\s+by\s+checking|let\s+me\s+just\s+try\s+it\s+and\s+see\.\s+the\s+plan)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:计划如下|行动计划|方案如下|我的方案|让我制定计划|排查计划|我的计划是)",
        re.IGNORECASE,
    ),
]

# 元反思/方案自我推翻废弃模式 (Meta-Reflection / Abandonment / Second-Guessing)
_ABANDONMENT_PATTERNS = [
    re.compile(
        r"\b(?:wait,\s*(?:actually|let\s+me|re-read|reconsider|hold\s+on|but|maybe|rethink)|"
        r"actually,\s*wait|let\s+me\s+reconsider|reconsidering|on\s+second\s+thought|"
        r"but\s+wait|actually\s+wait|hold\s+on,\s*wait|wait\s+a\s+moment)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:等等，其实|等等，不对|让我重新考虑|重新审视|再想想|不过等等|等一下，不对|仔细一想|不对，等等)",
        re.IGNORECASE,
    ),
]

# 虚假记忆检索、知识反刍与认知打转自旋模式 (Memory Retrieval & Cognitive Deliberation Stalling)
_MEMORY_SEARCH_PATTERNS = [
    re.compile(
        r"\b(?:let\s+me\s+recall|recall\s+harder|searching\s+(?:my\s+)?memory|"
        r"in\s+memory|release\s+notes|changelog|actually,\s*i\s+recall|"
        r"i\s+remember\s+now|let\s+me\s+recall\s+the\s+actual|found\s+it\s+in\s+memory|"
        r"recall\s+that|recall\s+more\s+specifically|i\s+recall|i\s+now\s+recall|"
        r"let\s+me\s+check\s+my\s+memory|re-check\s+the\s+package|package\s+name|"
        r"file\s+list|version\s+history|re-verif(?:y|ying)\s+the\s+name|"
        r"what\s+was\s+the\s+exact|check\s+the\s+exact\s+name)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:回想|检索记忆|发版日志|更新日志|重新回忆|仔细回想|记忆中|确认包名|清单列表|重新确认|仔细核对)",
        re.IGNORECASE,
    ),
]

# 犹疑停滞打断与自我纠结特征 (Hesitation & Self-Interruption Patterns)
_HESITATION_PATTERNS = [
    re.compile(
        r"\b(?:wait,\s*(?:actually|but|let\s+me|is\s+it|maybe|what\s+if)|"
        r"actually,\s*(?:wait|i\s+recall|maybe|is\s+that|let\s+me)|"
        r"hmm,\s*(?:but|wait|is\s+that|maybe)|"
        r"hold\s+on,\s*(?:wait|is\s+it|let\s+me)?|"
        r"wait\s+a\s+moment|or\s+wait|wait\s+wait)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:等等，其实|不过等等|等一下|仔细一想|不对，等等|等等，难道|或者等等)", re.IGNORECASE),
]

# 思考链自认陷入死循环特征模式 (包含明确第一人称自白与反刍纠错特征)
_SELF_LOOP_PATTERNS = [
    re.compile(
        r"\b(?:stop\s+this\s+loop|stuck\s+in\s+a\s+loop|going\s+in\s+circles)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:i\s+am|i'm|we\s+are|we're)\s+(?:stuck|looping|going\s+in\s+circles)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:completely\s+different\s+approach|reconsider\s+the\s+problem|take\s+a\s+concrete\s+action)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(?:陷入(?:了)?死循环|自己在打转|一直在死循环|原地打转)"),
    re.compile(r"(?:让我换个思路|换个思路尝试|必须换个思路)"),
    re.compile(r"(?:重新审视(?:这个问题|整体思路)|重新审视自己的方案)"),
    re.compile(r"(?:停止(?:这个)?(?:死)?循环|不能再(?:这样)?循环下去)"),
]

# 否定、疑问、代码实体、外部引述、错误/系统提示排除前缀正则
_SELF_LOOP_EXCLUSION_PREFIX_RE = re.compile(
    r"(?:"
    r"没有|没|并未|并不是|并非|不是|不会|不用|无须|无需|避免|防止|免于|"  # 中文否定
    r"是否|是不是|能否|会否|有没有|"                             # 中文疑问/假设
    r"检查|排查|分析|判断|查看|定位|关于|"                         # 中文动作/主题分析
    r"用户|主人|提问|询问|问|说|"                                 # 中文外部引述
    r"提示|报错|警告|拦截|中断|消息|"                              # 中文错误/系统提示
    r"代码|程序|算法|函数|进程|线程|while|for|"                    # 代码实体
    r"not\s+|never\s+|avoid\s+|prevent\s+|check\s+if\s+|"        # 英文否定/检查
    r"whether\s+|user\s+(?:asked|said|wants)\s+|error\s+|warning\s+"  # 英文外部引述/报错
    r")\s*(?:(?:实际上|似乎|可能|会|已|经|针对|对于|actually|really|probably)\s*)*$",
    re.IGNORECASE,
)


def is_valid_self_loop_match(text: str, start: int, end: int) -> bool:
    """
    精确语义语境校验：排除否定句、用户问题复述、代码分析、引用系统提示等误报。
    """
    prefix = text[max(0, start - 40):start]

    # 1. 检查是否在引号中（引用上一轮系统报错或用户原话）
    extended_prefix = text[max(0, start - 60):start]
    for q_open, q_close in [('"', '"'), ("'", "'"), ('“', '”'), ('‘', '’')]:
        last_open = extended_prefix.rfind(q_open)
        last_close = extended_prefix.rfind(q_close)
        if last_open != -1 and last_open > last_close:
            return False

    # 2. 检查前缀是否有否定、疑问、代码分析、用户引述、报错引用
    if _SELF_LOOP_EXCLUSION_PREFIX_RE.search(prefix):
        return False

    # 3. 检查匹配点紧邻后方是否跟随疑问标记（例如 "陷入死循环？" 或 "陷入死循环吗"）
    suffix = text[end:min(len(text), end + 10)]
    if re.match(r"^\s*(?:\?|？|吗|呢|否)", suffix):
        return False

    return True


class LongCatReasoningGuard:
    """
    美团 LongCat 专属递归推理与认知自旋守卫 (v2.5 深度特化版).
    
    能够识别核心死锁形态：
    1. 方案推翻打转 (Plan Churn & Abandonment): 方案反复废弃并在千字跨度内犹疑徘徊；
    2. 认知停滞死锁 (Cognitive Stalling & Deliberation Loop):
       - 纯高频犹疑打断自旋 (Hesitation Loop: 干净单边信号，多次犹疑纠结未落地行动);
       - 知识/记忆反刍检索与犹疑交织自旋 (Memory Deliberation Loop).
    3. 自认死循环特征 (Self-acknowledged loop detected):
       - 结合语境有效性过滤与阈值判定，杜绝否定句、用户复述及代码分析误杀。
    """

    def __init__(
        self,
        enabled: bool = True,
        plan_churn_threshold: int = 3,
        second_guessing_threshold: int = 3,
        constraint_threshold: int = 5,
        min_reasoning_chars: int = 3500,
        memory_search_threshold: int = 6,
        hesitation_threshold: int = 5,
        standalone_hesitation_threshold: int = 6,
        self_loop_threshold: int = 3,
    ):
        self.enabled = bool(enabled)
        self.plan_churn_threshold = max(2, int(plan_churn_threshold))
        self.second_guessing_threshold = max(2, int(second_guessing_threshold))
        self.constraint_threshold = max(2, int(constraint_threshold))
        self.min_reasoning_chars = max(100, int(min_reasoning_chars))
        self.memory_search_threshold = max(3, int(memory_search_threshold))
        self.hesitation_threshold = max(2, int(hesitation_threshold))
        self.standalone_hesitation_threshold = max(2, int(standalone_hesitation_threshold))
        self.self_loop_threshold = max(1, int(self_loop_threshold))

        self.reset()

    def reset(self) -> None:
        """重置内部跟踪状态"""
        self.total_chars: int = 0
        self.plan_positions: List[int] = []
        self.abandon_positions: List[int] = []
        self.plan_samples: List[str] = []
        self.abandon_samples: List[str] = []
        self.memory_search_count: int = 0
        self.hesitation_count: int = 0
        self.question_count: int = 0
        self.self_loop_count: int = 0
        self.self_loop_samples: List[str] = []
        self._buffer: str = ""
        self._tail_window: str = ""
        self._scanned_chars: int = 0
        self._matched_plan_offsets: set[int] = set()
        self._matched_abandon_offsets: set[int] = set()
        self._matched_mem_offsets: set[int] = set()
        self._matched_hes_offsets: set[int] = set()
        self._matched_self_loop_offsets: set[int] = set()

    def _scan_buffer(self, force: bool = False) -> Tuple[bool, Optional[str]]:
        """
        对内部缓冲进行增量特征扫描与统计更新。
        即使文本中没有 '\\n\\n'（如纯单段、单换行或长列表），也会按步长推进扫描。
        """
        buf_len = len(self._buffer)
        unscanned = buf_len - self._scanned_chars

        # 如果未到步长且非强制，并且没有换行符，推迟扫描以保证性能
        if not force and unscanned < 200 and "\n" not in self._buffer[self._scanned_chars:]:
            return False, None

        # 扫描起点往前回溯 50 字符，以防模式跨切片截断
        scan_start = max(0, self._scanned_chars - 50)
        scan_slice = self._buffer[scan_start:]
        base_abs = self.total_chars - buf_len + scan_start

        # 检查自认死循环 (带精确语境校验与累积阈值，毫秒级掐断真实死锁并杜绝误杀)
        for pat in _SELF_LOOP_PATTERNS:
            for m in pat.finditer(scan_slice):
                abs_pos = base_abs + m.start()
                if abs_pos not in self._matched_self_loop_offsets:
                    local_start = scan_start + m.start()
                    local_end = scan_start + m.end()
                    if is_valid_self_loop_match(self._buffer, local_start, local_end):
                        self._matched_self_loop_offsets.add(abs_pos)
                        self.self_loop_count += 1
                        self.self_loop_samples.append(m.group()[:60].replace("\n", " "))
                        if self.self_loop_count >= self.self_loop_threshold:
                            sample = self.self_loop_samples[0]
                            return True, (
                                f"LongCat-2.5 思考链明确自认陷入死循环 (Self-acknowledged loop detected, "
                                f"{self.self_loop_count}x self-corrections): '{sample}'"
                            )

        for pat in _PLAN_CHURN_PATTERNS:
            for m in pat.finditer(scan_slice):
                abs_pos = base_abs + m.start()
                if abs_pos not in self._matched_plan_offsets:
                    self._matched_plan_offsets.add(abs_pos)
                    self.plan_positions.append(abs_pos)
                    self.plan_samples.append(m.group()[:60].replace("\n", " "))

        for pat in _ABANDONMENT_PATTERNS:
            for m in pat.finditer(scan_slice):
                abs_pos = base_abs + m.start()
                if abs_pos not in self._matched_abandon_offsets:
                    self._matched_abandon_offsets.add(abs_pos)
                    self.abandon_positions.append(abs_pos)
                    self.abandon_samples.append(m.group()[:60].replace("\n", " "))

        for pat in _MEMORY_SEARCH_PATTERNS:
            for m in pat.finditer(scan_slice):
                abs_pos = base_abs + m.start()
                if abs_pos not in self._matched_mem_offsets:
                    self._matched_mem_offsets.add(abs_pos)
                    self.memory_search_count += 1

        for pat in _HESITATION_PATTERNS:
            for m in pat.finditer(scan_slice):
                abs_pos = base_abs + m.start()
                if abs_pos not in self._matched_hes_offsets:
                    self._matched_hes_offsets.add(abs_pos)
                    self.hesitation_count += 1

        self._scanned_chars = buf_len

        # 内存安全截断：如果 buffer 超过 64k 字符，保留后 32k 字符
        if len(self._buffer) > 64000:
            trim_size = len(self._buffer) - 32000
            self._buffer = self._buffer[trim_size:]
            self._scanned_chars = max(0, self._scanned_chars - trim_size)
            min_keep = self.total_chars - len(self._buffer)
            self._matched_plan_offsets = {p for p in self._matched_plan_offsets if p >= min_keep}
            self._matched_abandon_offsets = {p for p in self._matched_abandon_offsets if p >= min_keep}
            self._matched_mem_offsets = {p for p in self._matched_mem_offsets if p >= min_keep}
            self._matched_hes_offsets = {p for p in self._matched_hes_offsets if p >= min_keep}
            self._matched_self_loop_offsets = {p for p in self._matched_self_loop_offsets if p >= min_keep}

        return False, None

    def feed(self, chunk: str) -> Tuple[bool, Optional[str]]:
        """
        增量推入流式生成的思考链片段，低开销维护状态并在达成多重严格条件时熔断。
        不再受制于 '\\n\\n'，支持长单段或密集流的准实时检测。
        """
        if not self.enabled or not chunk:
            return False, None

        self.total_chars += len(chunk)
        self._buffer += chunk
        self._tail_window = (self._tail_window + chunk)[-2000:]
        self.question_count += chunk.count("?")

        # 遇到潜在自认特征时强制立即精确扫描，确保毫秒级极速响应
        has_potential_self_loop = any(pat.search(self._tail_window) for pat in _SELF_LOOP_PATTERNS)
        is_self_loop, reason = self._scan_buffer(force=has_potential_self_loop)
        if is_self_loop:
            return True, reason

        # 防线 1: 字符数未达到硬门槛，100% 安全豁免
        if self.total_chars < self.min_reasoning_chars:
            return False, None

        # 评估是否触发死循环
        return self._evaluate_loop_state()

    def flush(self) -> Tuple[bool, Optional[str]]:
        """
        流式传输结束时的收尾冲洗检查。
        强制扫描残留 buffer 并做最终死锁评估，防止尾部无换行内容遗漏。
        """
        if not self.enabled or self.total_chars < self.min_reasoning_chars:
            return False, None

        is_self_loop, reason = self._scan_buffer(force=True)
        if is_self_loop:
            return True, reason

        return self._evaluate_loop_state()

    def inspect(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        无状态全量评估 (适用于非流式检查或当前窗口文本的快照评估)。
        与 feed()/flush() 共享 100% 相同的基础设施，消除双轨逻辑分叉。
        """
        if not self.enabled or not text or len(text) < self.min_reasoning_chars:
            return False, None

        g = LongCatReasoningGuard(
            enabled=self.enabled,
            plan_churn_threshold=self.plan_churn_threshold,
            second_guessing_threshold=self.second_guessing_threshold,
            constraint_threshold=self.constraint_threshold,
            min_reasoning_chars=self.min_reasoning_chars,
            memory_search_threshold=self.memory_search_threshold,
            hesitation_threshold=self.hesitation_threshold,
            standalone_hesitation_threshold=self.standalone_hesitation_threshold,
            self_loop_threshold=self.self_loop_threshold,
        )
        is_loop, reason = g.feed(text)
        if is_loop:
            return True, reason
        return g.flush()

    def is_action_ready(self, text: str) -> bool:
        """
        检查末尾文本是否包含行动就绪信号 (清单条目或明确工具/命令行动宣告) 且未被后续推翻。
        若满足，表明模型正在进行 plan->act 交接，即将发起工具调用，强制豁免。

        【防漏报修复】:
        若模型已经多次犹疑停滞 (hesitation_count >= hesitation_threshold)
        或多次方案自我推翻废弃 (len(abandon_positions) >= 2)
        或高频知识反刍 (memory_search_count >= memory_search_threshold)，
        末尾单纯口头复述 "Let me check/run" 属于死循环伪装措辞，绝不给予豁免！
        """
        if not text:
            return False
        tail = text[-1000:] if len(text) > 1000 else text

        # 极限停滞防线: 纯单边犹疑已经达到绝对高危阈值时，不予任何豁免
        if self.hesitation_count >= self.standalone_hesitation_threshold:
            return False

        # 1. 结构化待办清单 (- item, 1. item, >=2 条)
        items = _CHECKLIST_ITEM_RE.findall(tail)
        if len(items) >= 2:
            last_item_pos = max(tail.rfind(it) for it in items)
            subsequent = tail[last_item_pos:]
            if not any(pat.search(subsequent) for pat in _ABANDONMENT_PATTERNS):
                return True

        # 2. 明确的命令/工具执行宣告 (如 "I'll use pwsh to check", "Let me run some commands", "开始执行命令")
        # 严格约束：若已发生多次自我推翻或认知纠结自旋，纯口头宣告不再豁免
        if (
            self.hesitation_count >= self.hesitation_threshold
            or self.memory_search_count >= self.memory_search_threshold
            or len(self.abandon_positions) >= 2
        ):
            return False

        action_hits = []
        for pat in _ACTION_INITIATION_PATTERNS:
            for m in pat.finditer(tail):
                action_hits.append(m.start())
        if action_hits:
            last_action_pos = max(action_hits)
            subsequent = tail[last_action_pos:]
            if not any(pat.search(subsequent) for pat in _ABANDONMENT_PATTERNS):
                return True

        return False

    def _is_action_readiness_checklist(self, text: str) -> bool:
        """向后兼容别名"""
        return self.is_action_ready(text)

    def _evaluate_loop_state(self) -> Tuple[bool, Optional[str]]:
        """增量状态下评估是否发生死锁"""
        if self.total_chars < self.min_reasoning_chars:
            return False, None

        # 检查是否满足行动就绪豁免 (结合 tail window 与当前 buffer)
        combined_tail = self._tail_window or self._buffer
        if self.is_action_ready(combined_tail):
            return False, None

        # 判定 A: 记忆自旋与认知停滞 (Cognitive Stalling & Deliberation Loop)
        if self.hesitation_count >= self.standalone_hesitation_threshold:
            return True, (
                f"LongCat-2.5 思考链反思自旋打转锁死 (Cognitive Hesitation Stalling Loop: "
                f"{self.hesitation_count}x 犹疑停滞/打断徘徊且未采取行动)"
            )
        if (
            self.memory_search_count >= self.memory_search_threshold
            and self.hesitation_count >= self.hesitation_threshold
        ):
            return True, (
                f"LongCat-2.5 虚假记忆检索与反思自旋锁死 (Memory Retrieval & Deliberation Loop: "
                f"{self.memory_search_count}x 脑内检索/知识反刍, {self.hesitation_count}x 犹疑打断未采取行动)"
            )

        # 判定 B: 计划推翻与长距离徘徊 (Plan Churn & Abandonment)
        return self._evaluate_plan_churn(
            self.total_chars,
            self.plan_positions,
            self.abandon_positions,
            self.plan_samples,
            self.abandon_samples,
        )

    def _evaluate_plan_churn(
        self,
        total_chars: int,
        plan_positions: List[int],
        abandon_positions: List[int],
        plan_samples: List[str],
        abandon_samples: List[str],
    ) -> Tuple[bool, Optional[str]]:
        """
        综合研判：必须同时满足多次重拟、多次自我推翻、长距离千字徘徊打转且非收敛趋势。
        """
        if len(plan_positions) < 2 or len(abandon_positions) < 2:
            return False, None

        # 检查宣告间隔趋势:
        # 如果最近两个行动宣告之间间隔递减，且最后一个方案未被废弃推翻，说明正在加速收敛准备执行，放行
        if len(plan_positions) >= 3:
            gap1 = plan_positions[-2] - plan_positions[-3]
            gap2 = plan_positions[-1] - plan_positions[-2]
            last_plan = max(plan_positions)
            last_abandon = max(abandon_positions) if abandon_positions else -1
            if gap2 < gap1 and gap2 < 400 and last_abandon < last_plan:
                return False, None

        # 真正死锁判定:
        latest_plan_gap = plan_positions[-1] - plan_positions[-2]
        min_gap = min(800, max(50, self.min_reasoning_chars // 3))
        if latest_plan_gap >= min_gap and len(abandon_positions) >= 2:
            sample_plan = plan_samples[-1] if plan_samples else ""
            return True, (
                f"LongCat-2.5 递归计划推翻震荡 (Plan Churn & Abandonment: "
                f"{len(plan_positions)}x 重拟方案, {len(abandon_positions)}x 推翻废弃, "
                f"徘徊跨度 {latest_plan_gap} 字符未执行): '{sample_plan}...'"
            )

        # 超高频重拟兜底: 达到计划重拟阈值 (>= 3 次) 且推翻次数 >= 2
        if (
            len(plan_positions) >= self.plan_churn_threshold
            and len(abandon_positions) >= 2
        ):
            sample_plan = plan_samples[0] if plan_samples else ""
            return True, (
                f"LongCat-2.5 递归反思锁死 (Plan Churn: {len(plan_positions)}x 方案重构, "
                f"{len(abandon_positions)}x 自我推翻打断未落地工具): '{sample_plan}...'"
            )

        return False, None
