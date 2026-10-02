# ==============================================================================
# LongCat Sentinel - Semantic State-Aware LoopScore & Repetition Detector
# ==============================================================================
import re
from typing import Tuple, Optional, List

class LoopScorer:
    def __init__(self, min_period: int = 16, repeat_threshold: int = 3, score_threshold: int = 100):
        self.min_period = min_period
        self.repeat_threshold = repeat_threshold
        self.score_threshold = score_threshold
        self.last_tool_outputs: List[str] = []
        self.current_score = 0

    def check_text_repetition(self, text: str) -> Tuple[bool, Optional[str]]:
        """
        检测文本是否陷入严格 N-gram 周期性重复
        """
        # 语法结构免疫：忽略连续空格、换行、水平线
        if len(text.strip()) < self.min_period * self.repeat_threshold:
            return False, None

        # 检查是否处于代码块内 (处于代码块时放宽周期限制)
        code_blocks = text.count("```")
        effective_min = self.min_period * 2 if (code_blocks % 2 != 0) else self.min_period

        # 滑动窗口周期串检测
        clean = text[-2000:] # 取最近 2000 字符加速
        n = len(clean)

        for p_len in range(effective_min, min(200, n // self.repeat_threshold + 1)):
            chunk = clean[-p_len:]
            # 必须包含非纯标点字符
            if not any(c.isalnum() for c in chunk):
                continue
            
            # 统计连续重复次数
            count = 1
            idx = n - p_len * 2
            while idx >= 0 and clean[idx:idx + p_len] == chunk:
                count += 1
                idx -= p_len
                if count >= self.repeat_threshold:
                    return True, f"N-gram period repeat ({count}x of length {p_len}): '{chunk[:30]}...'"

        return False, None

    def evaluate_tool_state(self, current_args_hash: str, output_text: str, env_changed: bool = False) -> Tuple[int, bool]:
        """
        根据工具入参、输出语义一致性与环境变化增量计算 LoopScore
        """
        if env_changed:
            self.current_score = 0
            return 0, False

        # 过滤时间戳等伪差异
        clean_output = re.sub(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?\b", "", output_text)
        clean_output = re.sub(r"\btimestamp\s*[:=]\s*\d+\b", "", clean_output, flags=re.IGNORECASE)

        # 检查是否与上次输出完全一致
        if self.last_tool_outputs and self.last_tool_outputs[-1] == clean_output:
            self.current_score += 40
        else:
            self.current_score = max(0, self.current_score - 20)

        self.last_tool_outputs.append(clean_output)
        if len(self.last_tool_outputs) > 5:
            self.last_tool_outputs.pop(0)

        tripped = self.current_score >= self.score_threshold
        return self.current_score, tripped
