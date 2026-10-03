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


class LoopScorer:
    """Detects periodic N-gram repetition (exact and fuzzy) in streamed text."""

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
        max_period: int = 200,
        ignore_whitespaces: bool = True,
        ignore_markdown_separators: bool = True,
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

        self.last_tool_outputs: List[str] = []
        self.current_score = 0

        # Incremental state
        self._window: deque[str] = deque()
        self._window_len = 0
        self._since_check = 0
        self._check_interval = max(self.min_period, 8)

    # -- incremental API ------------------------------------------------------
    def feed(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        Pushes newly streamed text and returns (is_loop, reason).

        The periodic scan runs at most once per `min_period` accumulated characters,
        which keeps the hot path cheap for long outputs.
        """
        if not text:
            return False, None

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
        """Detects strict (and optionally fuzzy) periodic repetition in `text`."""
        if not text:
            return False, None

        stripped = text.strip()
        required_repeats = self.repeat_threshold
        if self.fuzzy_enabled:
            required_repeats = min(required_repeats, self.fuzzy_repeat_threshold)
        required_repeats = max(2, required_repeats)
        if len(stripped) < self.min_period * required_repeats:
            return False, None

        # Inside an unterminated code fence, template code is expected to repeat, so
        # the minimum detectable period is widened instead of firing early.
        multiplier = self.code_block_multiplier if (text.count("```") % 2 != 0) else 1.0
        effective_min = max(1, int(self.min_period * multiplier))

        raw_window = text[-self.window_chars:] if self.window_chars else text
        clean = self._normalize(raw_window)
        n = len(clean)

        # A period is only worth testing if it could repeat often enough to trip.
        # When fuzzy detection is enabled its (usually lower) threshold also bounds
        # the period, otherwise a high exact threshold would hide long fuzzy repeats.
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
