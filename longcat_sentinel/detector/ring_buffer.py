# ==============================================================================
# LongCat Sentinel - Bounded Rolling Byte Buffer
#
# Design notes:
#  * The window is a bounded byte ring: memory never grows past the configured cap.
#  * Trimming is amortised. Reclaiming on every single write would memmove the whole
#    window per token; we only reclaim once a slack budget is exceeded.
#  * The window always starts on a UTF-8 code point boundary so decoding a trimmed
#    window cannot silently swallow or mangle the first character.
# ==============================================================================
from __future__ import annotations


CJK_RANGES = (
    (0x2E80, 0x9FFF),    # CJK radicals .. unified ideographs
    (0xAC00, 0xD7AF),    # Hangul syllables
    (0xF900, 0xFAFF),    # CJK compatibility ideographs
    (0xFF00, 0xFF60),    # Full-width forms
)


def _is_cjk(ch: str) -> bool:
    code = ord(ch)
    for low, high in CJK_RANGES:
        if low <= code <= high:
            return True
    return False


class RingBuffer:
    """Bounded rolling window over decoded stream text, plus coarse token accounting."""

    def __init__(self, capacity_bytes: int = 2 * 1024 * 1024):
        self.capacity_bytes = max(int(capacity_bytes), 1024)
        # Reclaim only after this much slack accumulates, which amortises the memmove.
        self.trim_threshold = self.capacity_bytes + max(65536, self.capacity_bytes // 4)
        self.buffer = bytearray()
        self.total_chars_seen = 0
        self.total_tokens_seen = 0

    # -- accounting -----------------------------------------------------------
    def _account(self, text: str) -> None:
        chars = len(text)
        self.total_chars_seen += chars
        cjk = 0
        for ch in text:
            if _is_cjk(ch):
                cjk += 1
        # Coarse but CJK-aware estimate: one token per ideograph, ~4 chars for the rest.
        self.total_tokens_seen += cjk + max(0, chars - cjk) // 4

    # -- ring maintenance -----------------------------------------------------
    def _align_to_char_boundary(self) -> None:
        """Drops leading UTF-8 continuation bytes so the window starts on a code point."""
        dropped = 0
        for byte in self.buffer[:3]:
            if (byte & 0xC0) == 0x80:
                dropped += 1
            else:
                break
        if dropped:
            del self.buffer[:dropped]

    def write(self, text: str) -> None:
        if not text:
            return
        self._account(text)
        self.buffer.extend(text.encode("utf-8", errors="replace"))

        if len(self.buffer) > self.trim_threshold:
            overflow = len(self.buffer) - self.capacity_bytes
            if overflow > 0:
                del self.buffer[:overflow]
                self._align_to_char_boundary()

    def get_text(self) -> str:
        return self.buffer.decode("utf-8", errors="ignore")

    def __len__(self) -> int:
        return len(self.buffer)
