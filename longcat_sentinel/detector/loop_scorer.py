# ==============================================================================
# LongCat Sentinel - Semantic State-Aware LoopScore & Repetition Detector
#
# The detector is incremental: callers push newly streamed text through `feed()`
# and the periodic N-gram scan only runs once enough new characters accumulated.
# That keeps the per-token cost bounded instead of re-scanning the whole window on
# every single delta.
# ==============================================================================
from __future__ import annotations

import re
from collections import deque
from typing import List, Optional, Tuple

try:  # pragma: no cover - exercised implicitly depending on the environment
    from rapidfuzz import fuzz as _fuzz

    def _ratio(a: str, b: str) -> float:
        return _fuzz.ratio(a, b) / 100.0

except Exception:  # pragma: no cover
    from difflib import SequenceMatcher

    def _ratio(a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio()


# Markdown separator-only lines ('---', '===', '***', '___') carry no semantic
# content and must not influence repetition detection.
_SEPARATOR_LINE_RE = re.compile(r"(?m)^[ \t]*(?:-{3,}|={3,}|\*{3,}|_{3,})[ \t]*$")
# Runs of horizontal whitespace collapse so indentation width cannot mask a repeat.
_MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")


from .longcat_reasoning_guard import LongCatReasoningGuard

_SELF_LOOP_PATTERNS = [
    re.compile(r"\bstop\s+this\s+loop\b", re.IGNORECASE),
    re.compile(r"\bgoing\s+in\s+circles\b", re.IGNORECASE),
    re.compile(r"\bstuck\s+in\s+a\s+loop\b", re.IGNORECASE),
    re.compile(r"\bcompletely\s+different\s+approach\b", re.IGNORECASE),
    re.compile(r"\breconsider\s+the\s+problem\b", re.IGNORECASE),
    re.compile(r"\btake\s+a\s+concrete\s+action\b", re.IGNORECASE),
    re.compile(r"(?:陷入(?:了)?死循环|自己在打转|一直在死循环)"),
    re.compile(r"(?:让我换个思路|换个思路尝试|必须换个思路)"),
    re.compile(r"(?:重新审视(?:这个问题|整体思路)|重新审视自己的方案)"),
    re.compile(r"(?:停止(?:这个)?循环|不能再循环下去)"),
]


class LoopScorer:
    """Detects periodic N-gram, macro block, semantic self-acknowledgment, and LongCat recursive reasoning loops."""

    def __init__(
        self,
        min_period: int = 16,
        repeat_threshold: int = 4,
        score_threshold: int = 100,
        window_chars: int = 4000,
        fuzzy_enabled: bool = True,
        fuzzy_similarity_ratio: float = 0.85,
        fuzzy_repeat_threshold: int = 4,
        code_block_multiplier: float = 1.5,
        max_period: int = 2000,
        ignore_whitespaces: bool = True,
        ignore_markdown_separators: bool = True,
        block_loop_enabled: bool = True,
        block_repeat_threshold: int = 2,
        min_block_chars: int = 25,
        self_loop_heuristics_enabled: bool = True,
        self_loop_threshold: int = 3,
        longcat_reasoning_guard_enabled: bool = True,
        longcat_plan_churn_threshold: int = 3,
        longcat_second_guessing_threshold: int = 3,
        longcat_constraint_threshold: int = 5,
        longcat_min_reasoning_chars: int = 800,
        longcat_memory_search_threshold: int = 6,
        longcat_hesitation_threshold: int = 5,
        longcat_standalone_hesitation_threshold: int = 6,
    ):
        self.min_period = max(1, int(min_period))
        self.repeat_threshold = max(2, int(repeat_threshold))
        self.score_threshold = max(1, int(score_threshold))
        self.window_chars = max(self.min_period * 4, int(window_chars))
        self.fuzzy_enabled = bool(fuzzy_enabled)
        self.fuzzy_similarity_ratio = float(fuzzy_similarity_ratio)
        self.fuzzy_repeat_threshold = max(2, int(fuzzy_repeat_threshold))
        self.code_block_multiplier = max(1.0, float(code_block_multiplier))
        self.max_period = max(self.min_period + 1, int(max_period))
        self.ignore_whitespaces = bool(ignore_whitespaces)
        self.ignore_markdown_separators = bool(ignore_markdown_separators)
        self.block_loop_enabled = bool(block_loop_enabled)
        self.block_repeat_threshold = max(2, int(block_repeat_threshold))
        self.min_block_chars = max(10, int(min_block_chars))
        self.self_loop_heuristics_enabled = bool(self_loop_heuristics_enabled)
        self.self_loop_threshold = max(2, int(self_loop_threshold))

        # 1:1 美团 LongCat 专属递归推理与并行思考锁死守卫
        self.longcat_guard = LongCatReasoningGuard(
            enabled=longcat_reasoning_guard_enabled,
            plan_churn_threshold=longcat_plan_churn_threshold,
            second_guessing_threshold=longcat_second_guessing_threshold,
            constraint_threshold=longcat_constraint_threshold,
            min_reasoning_chars=longcat_min_reasoning_chars,
            memory_search_threshold=longcat_memory_search_threshold,
            hesitation_threshold=longcat_hesitation_threshold,
            standalone_hesitation_threshold=longcat_standalone_hesitation_threshold,
        )

        self.last_tool_outputs: List[str] = []
        self.current_score = 0

        # Incremental state
        self._window: deque[str] = deque()
        self._window_len = 0
        self._since_check = 0
        self._check_interval = max(self.min_period, 8)

    def reset(self) -> None:
        """Resets both window and internal LongCat reasoning guard states."""
        self._window.clear()
        self._window_len = 0
        self._since_check = 0
        self.longcat_guard.reset()
        self.last_tool_outputs.clear()
        self.current_score = 0

    # -- incremental API ------------------------------------------------------
    def feed(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Pushes newly streamed text and returns (is_loop, reason).

        The periodic scan runs at most once per `min_period` accumulated characters,
        which keeps the hot path cheap for long outputs.
        """
        if not text:
            return False, None

        # 1. 优先触发美团 LongCat 专属增量推理守卫 (毫秒级掐断计划反刍与推翻打转)
        is_guard_loop, guard_reason = self.longcat_guard.feed(text)
        if is_guard_loop:
            return True, guard_reason

        self._window.append(text)
        self._window_len += len(text)
        while self._window_len > self.window_chars and self._window:
            dropped = self._window.popleft()
            self._window_len -= len(dropped)

        self._since_check += len(text)
        if self._since_check < self._check_interval:
            return False, None
        self._since_check = 0

        return self.check_text_repetition(self.get_window_text())

    def get_window_text(self) -> str:
        return "".join(self._window)

    # -- detection ------------------------------------------------------------
    def check_text_repetition(self, text: str) -> Tuple[bool, Optional[str]]:
        """Detects strict (and optionally fuzzy, macro-block, self-loop, and LongCat reasoning) repetition in `text`."""
        if not text:
            return False, None

        raw_window = text[-self.window_chars:] if self.window_chars else text
        clean = self._normalize(raw_window)

        # 1. 美团 LongCat 专属递归推理与元反思震荡识别 (1:1 专属特化拦截)
        is_longcat_loop, longcat_reason = self.longcat_guard.inspect(clean)
        if is_longcat_loop:
            return True, longcat_reason

        # 2. 思考链自相矛盾/自白反刍死循环启发式识别 (最高优先级拦截，毫秒级掐断)
        if self.self_loop_heuristics_enabled:
            is_self_loop, reason = self._check_self_loop(clean)
            if is_self_loop:
                return True, reason

        # 3. 宏观语义段落/多行代码块哈希循环识别 (拦截 300~2000+ 字符长段落大循环)
        if self.block_loop_enabled:
            is_block_loop, reason = self._check_macro_blocks(raw_window)
            if is_block_loop:
                return True, reason

        # 3. 微观与中观 N-Gram / 模糊周期重复检测 (字符级滑动扫描)
        stripped = text.strip()
        required_repeats = self.repeat_threshold
        if self.fuzzy_enabled:
            required_repeats = min(required_repeats, self.fuzzy_repeat_threshold)
        required_repeats = max(2, required_repeats)
        if len(stripped) < self.min_period * required_repeats:
            return False, None

        multiplier = self.code_block_multiplier if (text.count("```") % 2 != 0) else 1.0
        effective_min = max(1, int(self.min_period * multiplier))
        n = len(clean)

        divisor = self.repeat_threshold
        if self.fuzzy_enabled:
            divisor = min(divisor, self.fuzzy_repeat_threshold)
        divisor = max(2, divisor)

        upper = min(self.max_period, n // divisor)
        if upper < effective_min:
            return False, None

        for p_len in range(effective_min, upper + 1):
            chunk = clean[-p_len:]
            if not any(c.isalnum() for c in chunk):
                continue

            count = 1
            idx = n - p_len * 2
            while idx >= 0 and clean[idx:idx + p_len] == chunk:
                count += 1
                idx -= p_len
                if count >= self.repeat_threshold:
                    return True, (
                        f"N-gram period repeat ({count}x of length {p_len}): "
                        f"'{chunk[:30]}...'"
                    )

            if self.fuzzy_enabled and self.fuzzy_repeat_threshold <= n // p_len:
                fuzzy_count = self._fuzzy_run(clean, chunk, p_len)
                if fuzzy_count >= self.fuzzy_repeat_threshold:
                    return True, (
                        f"Fuzzy N-gram repeat ({fuzzy_count}x of length {p_len}, "
                        f"similarity>={self.fuzzy_similarity_ratio}): '{chunk[:30]}...'"
                    )

        return False, None

    def _check_self_loop(self, text: str) -> Tuple[bool, Optional[str]]:
        """检测模型在思考链中频繁自认陷入死循环或反复自我纠错打转的语义特征"""
        total_hits = 0
        matched_samples: List[str] = []
        for pat in _SELF_LOOP_PATTERNS:
            matches = pat.findall(text)
            if matches:
                total_hits += len(matches)
                matched_samples.append(str(matches[0]))
                if total_hits >= self.self_loop_threshold:
                    sample = matched_samples[0]
                    return True, (
                        f"Thinking loop self-acknowledgment detected ({total_hits}x self-correction phrases): "
                        f"'{sample}'"
                    )
        return False, None

    def _check_macro_blocks(self, text: str) -> Tuple[bool, Optional[str]]:
        """检测段落级、大块代码级长周期循环 ($A -> B -> A -> B$ 或重复段落)"""
        # 优先按双换行分段，若长文本未规范双换行则按单换行且具备实质长度的行分块
        raw_paras = [p.strip() for p in text.split("\n\n") if len(p.strip()) >= self.min_block_chars]
        if len(raw_paras) < 2:
            raw_paras = [p.strip() for p in text.split("\n") if len(p.strip()) >= self.min_block_chars]

        if len(raw_paras) < 2:
            return False, None

        # 1. 相同长段落高频复现检测
        # 若处于代码块内部（未闭合三反引号）或通过单换行切分，则提高重复容忍门槛防止代码模板/表格误杀
        is_in_code = (text.count("```") % 2 != 0)
        effective_repeat_threshold = self.block_repeat_threshold
        if is_in_code:
            effective_repeat_threshold = max(effective_repeat_threshold + 1, int(effective_repeat_threshold * self.code_block_multiplier))

        seen: dict[str, int] = {}
        for p in raw_paras:
            clean = self._normalize(p).lower().strip()
            seen[clean] = seen.get(clean, 0) + 1
            if seen[clean] >= effective_repeat_threshold:
                sample = p[:50].replace("\n", " ").strip()
                return True, (
                    f"Macro block repeat ({seen[clean]}x of len {len(p)}): "
                    f"'{sample}...'"
                )

        # 2. 段落周期链循环检测 (如 A->B->C->A->B->C，支持 2 到 8 个段落组成的宏观周期)
        n = len(raw_paras)
        for k in range(2, min(9, n // 2 + 1)):
            tail = [self._normalize(p).lower().strip() for p in raw_paras[-k:]]
            prev = [self._normalize(p).lower().strip() for p in raw_paras[-2 * k : -k]]
            if tail == prev and len(set(tail)) > 1:
                sample = raw_paras[-k][:40].replace("\n", " ").strip()
                return True, (
                    f"Macro block cycle detected ({k}-block pattern repeated): "
                    f"'{sample}...'"
                )

        return False, None

    def _normalize(self, text: str) -> str:
        """Applies the configured immunity rules (markdown separators, whitespace runs)."""
        if self.ignore_markdown_separators:
            text = _SEPARATOR_LINE_RE.sub("", text)
        if self.ignore_whitespaces:
            text = _MULTI_SPACE_RE.sub(" ", text)
        return text

    def _fuzzy_run(self, clean: str, chunk: str, p_len: int) -> int:
        """Counts consecutive preceding blocks similar to `chunk` (>= configured ratio)."""
        count = 1
        idx = len(clean) - p_len * 2
        while idx >= 0:
            candidate = clean[idx:idx + p_len]
            if candidate == chunk or _ratio(candidate, chunk) >= self.fuzzy_similarity_ratio:
                count += 1
                idx -= p_len
            else:
                break
        return count

    # -- legacy tool-state scoring (kept for API compatibility) ---------------
    def evaluate_tool_state(
        self, current_args_hash: str, output_text: str, env_changed: bool = False
    ) -> Tuple[int, bool]:
        """Accumulates a LoopScore from repeated tool output, ignoring timestamp noise."""
        if env_changed:
            self.current_score = 0
            return 0, False

        clean_output = re.sub(
            r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", "", output_text
        )
        clean_output = re.sub(
            r"\btimestamp\s*[:=]\s*\d+\b", "", clean_output, flags=re.IGNORECASE
        )

        if self.last_tool_outputs and self.last_tool_outputs[-1] == clean_output:
            self.current_score += 40
        else:
            self.current_score = max(0, self.current_score - 20)

        self.last_tool_outputs.append(clean_output)
        if len(self.last_tool_outputs) > 5:
            self.last_tool_outputs.pop(0)

        tripped = self.current_score >= self.score_threshold
        return self.current_score, tripped
