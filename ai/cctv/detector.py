from dataclasses import dataclass
from typing import List, Tuple
import numpy as np

# Relevant COCO classes for RailSentinel station security
TARGET_CLASSES = {
    0: "person",
    24: "backpack",
    26: "handbag",
    28: "suitcase",
}

LUGGAGE_CLASSES = {"backpack", "handbag", "suitcase", "luggage"}


@dataclass
class DetectedObject:
    class_id: int
    class_name: str
    confidence: float
    bbox: Tuple[int, int, int, int]  # (x1, y1, x2, y2)
    center: Tuple[int, int]
    is_luggage: bool


class YOLODetector:
    """
    Ultralytics YOLO wrapper tailored for RailSentinel railway security monitoring.
    Filters frames for humans and potential unattended items (backpacks, suitcases, handbags).
    """

    def __init__(self, model_path: str = "yolov8n.pt", conf_threshold: float = 0.4):
        from ultralytics import YOLO

        self.conf_threshold = conf_threshold
        self.model = YOLO(model_path)
        self.target_class_ids = list(TARGET_CLASSES.keys())

    def detect(self, frame: np.ndarray) -> List[DetectedObject]:
        """
        Runs YOLO inference on a single BGR image/frame.
        Returns a list of DetectedObject instances matching target classes.
        """
        results = self.model.predict(
            frame,
            conf=self.conf_threshold,
            classes=self.target_class_ids,
            verbose=False,
        )

        detections: List[DetectedObject] = []
        if not results:
            return detections

        result = results[0]
        boxes = result.boxes

        if boxes is None or len(boxes) == 0:
            return detections

        for box in boxes:
            cls_id = int(box.cls[0].item())
            conf = float(box.conf[0].item())
            xyxy = box.xyxy[0].tolist()

            x1, y1, x2, y2 = int(xyxy[0]), int(xyxy[1]), int(xyxy[2]), int(xyxy[3])
            center = ((x1 + x2) // 2, (y1 + y2) // 2)

            class_name = TARGET_CLASSES.get(cls_id, "unknown")
            is_luggage = class_name in LUGGAGE_CLASSES

            detections.append(
                DetectedObject(
                    class_id=cls_id,
                    class_name=class_name,
                    confidence=conf,
                    bbox=(x1, y1, x2, y2),
                    center=center,
                    is_luggage=is_luggage,
                )
            )

        return detections
