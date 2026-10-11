# ==============================================================================
# LongCat Sentinel - Semantic Stagnation & Lexical Entropy Guard
#
# Inspired by GitHub open-source patterns (DeepEval Stagnation Spirals & Sotis Entropy Guard):
# - Multi-step cross-segment window comparison (defeating A -> B -> A ping-pong and A -> B -> C -> A cycles).
# - Shannon lexical entropy & Type-Token Ratio (TTR) collapse detection.
# - Anti-false-positive progression invariants (preserving step-by-step numbers, tables, code).
# - Ultra-lightweight (<0.2ms latency, zero heavy neural network/GPU dependencies).
# ==============================================================================
from __future__ import annotations

import math
import re
from collections import Counter, deque
from typing import List, Optional, Set, Tuple

# Common Chinese & English function words/stopwords to filter out
_STOPWORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "to", "of", "and", "in", "that", "it",
    "for", "on", "with", "as", "this", "by", "at", "from", "be", "or", "have", "from",
    "的", "了", "和", "是", "就", "都", "而", "及", "与", "着", "或", "一个", "没有", "我们",
    "你们", "他们", "它们", "这个", "那个", "之", "在", "于", "对", "把", "被", "从", "按"
})

def tokenize_content(text: str) -> List[str]:
    """Extracts meaningful lexical tokens from text, supporting both English words and Chinese n-grams."""
    raw_tokens: List[str] = []
    # 1. 英文单词
    eng_words = re.findall(r"[a-zA-Z0-9_]+", text.lower())
    for w in eng_words:
        if w not in _STOPWORDS and len(w) > 1:
            raw_tokens.append(w)

    # 2. 中文提取 (2-gram 与关键实词)
    han_text = "".join(re.findall(r"[\u4e00-\u9fa5]+", text))
    for i in range(len(han_text) - 1):
        bi = han_text[i:i+2]
        if bi not in _STOPWORDS:
            raw_tokens.append(bi)

    return raw_tokens


def compute_shannon_entropy(tokens: List[str]) -> float:
    """Calculates Shannon lexical information entropy H(X) in bits."""
    if not tokens:
        return 0.0
    total = len(tokens)
    counts = Counter(tokens)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def compute_ttr(tokens: List[str]) -> float:
    """Calculates Type-Token Ratio (unique vocabulary diversity ratio)."""
    if not tokens:
        return 1.0
    return len(set(tokens)) / len(tokens)


def compute_semantic_similarity(tokens_a: List[str], tokens_b: List[str], text_a: str, text_b: str) -> float:
    """Computes hybrid semantic similarity using token overlap and fuzzy ratio."""
    if not tokens_a or not tokens_b:
        return 0.0

    # 1. Jaccard on token sets
    set_a = set(tokens_a)
    set_b = set(tokens_b)
    jaccard = len(set_a.intersection(set_b)) / max(1, len(set_a.union(set_b)))

    # 2. String fuzzy ratio (rapidfuzz / difflib token sort)
    try:
        from rapidfuzz import fuzz
        fuzzy_sim = fuzz.token_sort_ratio(text_a, text_b) / 100.0
    except Exception:
        from difflib import SequenceMatcher
        fuzzy_sim = SequenceMatcher(None, " ".join(tokens_a), " ".join(tokens_b)).ratio()

    return max(jaccard, fuzzy_sim)


def is_progressive_content(text_a: str, text_b: str) -> bool:
    """
    Determines if two structurally similar segments represent legitimate progressive
    steps or enumeration rather than degenerate semantic repetition loops.
    """
    # 1. Number progression (e.g., Step 1 vs Step 2, 步骤 1 vs 步骤 2)
    num_re = re.compile(r"\b\d+\b")
    nums_a = num_re.findall(text_a)
    nums_b = num_re.findall(text_b)
    if nums_a and nums_b and nums_a != nums_b:
        return True

    # 2. Markdown numbered or itemized lists with different prefixes
    list_marker_re = re.compile(r"^\s*(?:[-*+•]|\d+[\.)]|- \[[ xX]\])\s*")
    has_marker_a = bool(list_marker_re.match(text_a))
    has_marker_b = bool(list_marker_re.match(text_b))
    if has_marker_a and has_marker_b:
        marker_a = list_marker_re.findall(text_a)
        marker_b = list_marker_re.findall(text_b)
        if marker_a != marker_b:
            return True

    return False


class SemanticSegment:
    __slots__ = ("text", "tokens", "token_set", "entropy", "ttr")

    def __init__(self, text: str, tokens: List[str]):
        self.text = text
        self.tokens = tokens
        self.token_set = set(tokens)
        self.entropy = compute_shannon_entropy(tokens)
        self.ttr = compute_ttr(tokens)


class SemanticStagnationGuard:
    """
    Monitors streaming or complete text segments for multi-step semantic stagnation,
    ping-pong cycles, and lexical entropy collapse.
    """

    def __init__(
        self,
        enabled: bool = True,
        similarity_threshold: float = 0.76,
        min_segment_chars: int = 25,
        max_history_segments: int = 6,
    ):
        self.enabled = bool(enabled)
        self.similarity_threshold = float(similarity_threshold)
        self.min_segment_chars = max(15, int(min_segment_chars))
        self.max_history_segments = max(3, int(max_history_segments))

        self._buffer: str = ""
        self._segments: deque[SemanticSegment] = deque(maxlen=self.max_history_segments)
        self._stagnation_count: int = 0

    def reset(self) -> None:
        self._buffer = ""
        self._segments.clear()
        self._stagnation_count = 0

    def feed(self, text: str) -> Tuple[bool, Optional[str]]:
        if not self.enabled or not text:
            return False, None

        self._buffer += text
        # Delimit by paragraph or logical statement breaks
        if "\n" in text or len(self._buffer) >= self.min_segment_chars * 2:
            return self._evaluate_buffer()

        return False, None

    def flush(self) -> Tuple[bool, Optional[str]]:
        if not self.enabled:
            return False, None
        if len(self._buffer.strip()) >= self.min_segment_chars:
            return self._evaluate_buffer(force=True)
        return False, None

    def _evaluate_buffer(self, force: bool = False) -> Tuple[bool, Optional[str]]:
        lines = [line.strip() for line in self._buffer.split("\n") if line.strip()]
        if not lines:
            return False, None

        # Process complete chunks
        if not force and len(self._buffer) < self.min_segment_chars:
            return False, None

        segment_text = " ".join(lines)
        if len(segment_text) < self.min_segment_chars:
            if force and len(segment_text) >= 20:
                pass
            else:
                return False, None

        self._buffer = ""
        tokens = tokenize_content(segment_text)
        if len(tokens) < 3:
            return False, None

        new_segment = SemanticSegment(segment_text, tokens)

        # Multi-step cross-segment window comparison
        # Evaluates distance k: 1 (adjacent), 2 (ping-pong), 3+ (cycle)
        for k, past_segment in enumerate(reversed(self._segments), start=1):
            step_threshold = self.similarity_threshold

            if k == 1:
                # Adjacent segment
                step_threshold = self.similarity_threshold
            elif k == 2:
                # A -> B -> A ping-pong cycle: slightly more sensitive
                step_threshold = max(0.68, self.similarity_threshold - 0.04)
            else:
                # k >= 3 cycle
                step_threshold = max(0.70, self.similarity_threshold - 0.02)

            # Shannon entropy / TTR collapse sensitivity boost:
            # When agent exhibits repetitive, impoverished vocabulary (TTR < 0.45 or entropy < 2.5),
            # lower threshold to trip churning agent.
            if new_segment.ttr < 0.45 or new_segment.entropy < 2.5:
                step_threshold = max(0.65, step_threshold - 0.05)

            sim = compute_semantic_similarity(
                new_segment.tokens, past_segment.tokens, new_segment.text, past_segment.text
            )

            if sim >= step_threshold:
                # Anti-false-positive check for legitimate progression
                if is_progressive_content(new_segment.text, past_segment.text):
                    continue

                self._stagnation_count += 1
                self._segments.append(new_segment)
                if k == 1:
                    return True, (
                        f"Semantic stagnation detected: consecutive reasoning segments exhibit "
                        f"{int(sim * 100)}% lexical overlap without substantial progress"
                    )
                else:
                    return True, (
                        f"Semantic loop detected: reasoning segment cycles back to step -{k} "
                        f"with {int(sim * 100)}% similarity (ping-pong/stagnant reasoning spiral)"
                    )

        self._segments.append(new_segment)
        return False, None
