# ==============================================================================
# LongCat Sentinel - Byte-level Incremental Stream Finite State Machine (FSM)
# ==============================================================================
from typing import Tuple, List, Optional

class StreamFSM:
    def __init__(self):
        self.in_think = False
        self.think_buffer = ""
        self.content_buffer = ""
        self.tag_buffer = "" # 缓冲跨 chunk 截断的标签前缀，如 '<th'

    def feed_chunk(self, chunk_text: str) -> Tuple[str, str]:
        """
        逐字符/块解析流式输出，精准分离思考链 <think>...</think> 与正式回答
        返回: (emitted_content, emitted_think)
        """
        emitted_content = []
        emitted_think = []

        full_text = self.tag_buffer + chunk_text
        self.tag_buffer = ""
        i = 0
        n = len(full_text)

        while i < n:
            if not self.in_think:
                # 寻找 <think> 标签
                if full_text[i] == '<':
                    # 检查是否足以判定完整标签
                    rem = full_text[i:]
                    if "<think>".startswith(rem):
                        # 处于分包边界，存入 tag_buffer
                        self.tag_buffer = rem
                        break
                    elif rem.startswith("<think>"):
                        self.in_think = True
                        i += len("<think>")
                        continue
                emitted_content.append(full_text[i])
                self.content_buffer += full_text[i]
                i += 1
            else:
                # 寻找 </think> 标签
                if full_text[i] == '<':
                    rem = full_text[i:]
                    if "</think>".startswith(rem):
                        self.tag_buffer = rem
                        break
                    elif rem.startswith("</think>"):
                        self.in_think = False
                        i += len("</think>")
                        continue
                emitted_think.append(full_text[i])
                self.think_buffer += full_text[i]
                i += 1

        return "".join(emitted_content), "".join(emitted_think)
