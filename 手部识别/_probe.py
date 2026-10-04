# -*- coding: utf-8 -*-
"""临时探针：验证本地模型 + 摄像头 + 中文路径读取。"""
import os
import sys
import time

import numpy as np

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(BASE, "models", "hand_landmarker.task")

print("cwd            :", os.getcwd())
print("base           :", BASE)
print("model exists   :", os.path.exists(MODEL), os.path.getsize(MODEL) if os.path.exists(MODEL) else "-")

import cv2  # noqa: E402
import mediapipe as mp  # noqa: E402
from mediapipe.tasks import python as mp_python  # noqa: E402
from mediapipe.tasks.python import vision  # noqa: E402

print("cv2            :", cv2.__version__)
print("mediapipe      :", mp.__version__)


def imread_unicode(path):
    """OpenCV 在 Windows 上无法直接读中文路径，用 np.fromfile 绕开。"""
    data = np.fromfile(path, dtype=np.uint8)
    if data.size == 0:
        raise IOError("文件为空: " + path)
    img = cv2.imdecode(data, cv2.IMREAD_COLOR)
    if img is None:
        raise IOError("解码失败: " + path)
    return img


def imwrite_unicode(path, img, ext=".png"):
    ok, buf = cv2.imencode(ext, img)
    if not ok:
        raise IOError("编码失败: " + path)
    buf.tofile(path)


with open(MODEL, "rb") as fh:
    MODEL_BYTES = fh.read()
print("model bytes    :", len(MODEL_BYTES))

t0 = time.time()
opts = vision.HandLandmarkerOptions(
    base_options=mp_python.BaseOptions(model_asset_buffer=MODEL_BYTES),
    running_mode=vision.RunningMode.IMAGE,
    num_hands=2,
    min_hand_detection_confidence=0.3,
    min_hand_presence_confidence=0.3,
    min_tracking_confidence=0.3,
)
landmarker = vision.HandLandmarker.create_from_options(opts)
print("model loaded   : %.3fs" % (time.time() - t0))

# 摄像头取帧
cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
frame = None
if cap.isOpened():
    for _ in range(30):
        ok, f = cap.read()
        if ok and f is not None:
            frame = f
        time.sleep(0.03)
cap.release()

if frame is None:
    print("NO FRAME")
    sys.exit(2)

raw_path = os.path.join(BASE, "_probe_frame.png")
imwrite_unicode(raw_path, frame)
print("frame saved    :", raw_path, frame.shape)

rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
mp_img = mp.Image(image_format=mp.ImageFormat.SRGB, data=np.ascontiguousarray(rgb))
t1 = time.time()
res = landmarker.detect(mp_img)
print("detect time    : %.3fs" % (time.time() - t1))
print("hands found    :", len(res.hand_landmarks))
for i, lm in enumerate(res.hand_landmarks):
    handed = res.handedness[i][0].category_name if res.handedness else "?"
    print("  hand %d: %s, %d landmarks, wrist=(%.3f, %.3f)" % (i, handed, len(lm), lm[0].x, lm[0].y))
landmarker.close()
