# ==============================================================================
# LongCat Sentinel - 2MB In-Memory Ring Buffer with Rolling SimHash
# ==============================================================================
import hashlib
from collections import deque
from typing import List, Tuple

class RingBuffer:
    def __init__(self, capacity_bytes: int = 2 * 1024 * 1024):
        self.capacity_bytes = capacity_bytes
        self.buffer = bytearray()
        self.total_tokens_seen = 0
        self.simhash_vector = [0] * 64

    def write(self, text: str):
        encoded = text.encode('utf-8')
        self.total_tokens_seen += len(text.split())
        self.buffer.extend(encoded)

        # 超过 2MB 环形丢弃
        if len(self.buffer) > self.capacity_bytes:
            excess = len(self.buffer) - self.capacity_bytes
            del self.buffer[:excess]

        # 滚动更新简易 SimHash (64-bit)
        for word in text.split():
            h = int(hashlib.md5(word.encode('utf-8')).hexdigest()[:16], 16)
            for i in range(64):
                if (h >> i) & 1:
                    self.simhash_vector[i] += 1
                else:
                    self.simhash_vector[i] -= 1

    def get_text(self) -> str:
        return self.buffer.decode('utf-8', errors='ignore')

    def get_fingerprint(self) -> int:
        fp = 0
        for i in range(64):
            if self.simhash_vector[i] > 0:
                fp |= (1 << i)
        return fp
