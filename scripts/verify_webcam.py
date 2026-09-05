import sys
from pathlib import Path
import cv2

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai.cctv.detector import YOLODetector

print("[1] Initializing YOLO Detector...")
detector = YOLODetector()
print("[1] YOLO Detector loaded successfully.")

print("[2] Probing laptop webcam (index 0)...")
cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
if not cap.isOpened():
    print("[2] DirectShow open failed, trying default backend...")
    cap = cv2.VideoCapture(0)

is_opened = cap.isOpened()
print(f"[2] Camera opened successfully: {is_opened}")

if is_opened:
    ret, frame = cap.read()
    print(f"[3] Captured frame: {ret}")
    if ret and frame is not None:
        print(f"[3] Frame dimensions: {frame.shape[1]}x{frame.shape[0]}")
        print("[4] Running test inference on captured frame...")
        detections = detector.detect(frame)
        print(f"[4] Detection inference complete. Found {len(detections)} object(s):")
        for d in detections:
            print(f"    - {d.class_name.upper()} (conf: {d.confidence*100:.1f}%) at {d.bbox}")
    else:
        print("[3] Warning: Frame capture returned False or None.")
    cap.release()
    print("[5] Camera released cleanly.")
else:
    print("[2] Error: Could not open camera at index 0.")
