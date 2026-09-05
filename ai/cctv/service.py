import argparse
import sys
import time
import cv2
import numpy as np

from ai.inference.scoring import calculate_threat
from ai.inference.models import DetectionEvidence, Severity
from .detector import YOLODetector
from .tracker import SecurityObjectTracker, TrackedItem
from .alert_manager import AlertManager


def draw_hud(frame: np.ndarray, fps: float, active_tracks_count: int, alert_count: int):
    """Draws top information banner."""
    h, w = frame.shape[:2]
    # Top overlay bar
    overlay = frame.copy()
    cv2.rectangle(overlay, (0, 0), (w, 42), (20, 24, 30), -1)
    cv2.addWeighted(overlay, 0.85, frame, 0.15, 0, frame)

    # Title and metrics
    cv2.putText(
        frame,
        "RAILSENTINEL - CCTV INGEST & THREAT SCREENING",
        (14, 26),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.65,
        (255, 255, 255),
        2,
        cv2.LINE_AA,
    )

    stats_text = f"FPS: {fps:.1f} | Tracks: {active_tracks_count} | Live Alerts: {alert_count}"
    cv2.putText(
        frame,
        stats_text,
        (w - 380, 26),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.55,
        (70, 215, 120),
        1,
        cv2.LINE_AA,
    )


def draw_track(frame: np.ndarray, track: TrackedItem, score: float, severity: Severity):
    """Draws bounding box, dwell time, and severity tags around tracked objects."""
    x1, y1, x2, y2 = track.bbox

    # Color coding based on severity
    if severity == Severity.RED:
        color = (50, 50, 240)      # Bright Red (BGR)
    elif severity == Severity.YELLOW:
        color = (40, 200, 245)     # Amber/Yellow (BGR)
    else:
        color = (100, 220, 100)    # Soft Green (BGR)

    # Bounding Box
    cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)

    # Label Text
    if track.is_luggage:
        if track.is_attended:
            status_str = "ATTENDED"
        elif track.person_left_object:
            status_str = f"UNATTENDED {track.unattended_seconds:.0f}s"
        else:
            status_str = f"HOLD {track.unattended_seconds:.0f}s"
        label = f"#{track.track_id} {track.class_name.upper()} | {status_str}"
    else:
        label = f"#{track.track_id} {track.class_name.upper()} ({track.confidence*100:.0f}%)"

    (text_w, text_h), baseline = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)
    tag_y1 = max(y1 - text_h - 10, 45)
    cv2.rectangle(frame, (x1, tag_y1), (x1 + text_w + 8, tag_y1 + text_h + 8), color, -1)
    cv2.putText(
        frame,
        label,
        (x1 + 4, tag_y1 + text_h + 3),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.5,
        (0, 0, 0),
        1,
        cv2.LINE_AA,
    )

    # If unattended luggage with confirmed owner separation, render alert warning
    if track.is_luggage and track.person_left_object and track.unattended_seconds >= 3.0:
        warning = f"ALERT: UNATTENDED ({track.unattended_seconds:.0f}s | Risk {score:.0f})"
        cv2.putText(
            frame,
            warning,
            (x1, min(y2 + 20, frame.shape[0] - 10)),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.55,
            color,
            2,
            cv2.LINE_AA,
        )


def run_cctv_service(
    camera_index: int = 0,
    model_name: str = "yolov8n.pt",
    conf_thresh: float = 0.35,
    api_url: str = "http://localhost:8000/api/v1",
    headless: bool = False,
):
    print("=" * 60)
    print("       RAILSENTINEL REAL-TIME YOLO CCTV DETECTION SERVICE")
    print("=" * 60)
    print(f"[Init] Connecting to Camera Index: {camera_index}...")
    print(f"[Init] Loading YOLO Model: {model_name}...")
    print(f"[Init] Target Backend API: {api_url}")

    # Initialize video capture (use DirectShow on Windows for fast startup)
    cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        print(f"[Warn] DirectShow capture failed, falling back to default backend...")
        cap = cv2.VideoCapture(camera_index)

    if not cap.isOpened():
        print(f"[Error] Could not open camera {camera_index}. Please check webcam connection.")
        sys.exit(1)

    # Configure webcam resolution (default standard 720p or 480p)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

    # Initialize modules
    detector = YOLODetector(model_path=model_name, conf_threshold=conf_thresh)
    tracker = SecurityObjectTracker(source_name="CCTV-GATE-1")
    alert_manager = AlertManager(base_url=api_url)

    print("[Ready] CCTV service running. Press 'q' or ESC in preview window to exit.")

    fps_timer = time.time()
    frame_count = 0
    fps = 0.0
    total_alerts_sent = 0

    try:
        while True:
            ret, frame = cap.read()
            if not ret or frame is None:
                print("[Warn] Empty frame received from camera. Retrying...")
                time.sleep(0.05)
                continue

            frame_count += 1
            if time.time() - fps_timer >= 1.0:
                fps = frame_count / (time.time() - fps_timer)
                frame_count = 0
                fps_timer = time.time()

            # 1. YOLO Detection
            detections = detector.detect(frame)

            # 2. Tracking & Dwell Analysis
            active_tracks, evidences = tracker.update(detections)

            # Build a lookup of scores per track
            track_scores = {}

            # 3. Contextual Threat Scoring & Backend Alert Dispatching
            for track in active_tracks:
                if track.is_luggage:
                    dwell_val = (
                        round(track.unattended_seconds, 1)
                        if track.person_left_object
                        else 0.0
                    )
                    evidence = DetectionEvidence(
                        object_type=track.class_name,
                        confidence=round(track.confidence, 2),
                        dwell_seconds=dwell_val,
                        person_left_object=track.person_left_object,
                        detection_source="CCTV-GATE-1",
                    )
                    analysis = calculate_threat(evidence)
                    track_scores[track.track_id] = (analysis.threat_score, analysis.severity)

                    # Only dispatch if confirmed unattended (person_left_object == True)
                    if track.person_left_object:
                        dispatched = alert_manager.dispatch(f"track_{track.track_id}", analysis)
                        if dispatched:
                            total_alerts_sent += 1

            # 4. Render Annotations & GUI Preview
            if not headless:
                draw_hud(frame, fps, len(active_tracks), total_alerts_sent)

                for track in active_tracks:
                    score, severity = track_scores.get(track.track_id, (0.0, Severity.GREEN))
                    draw_track(frame, track, score, severity)

                cv2.imshow("RailSentinel - Live CCTV Stream", frame)

                key = cv2.waitKey(1) & 0xFF
                if key in (ord("q"), 27):  # 'q' or ESC
                    print("\n[Exit] User terminated video stream.")
                    break

    except KeyboardInterrupt:
        print("\n[Exit] Keyboard interrupt received.")
    finally:
        cap.release()
        if not headless:
            cv2.destroyAllWindows()
        print("[Shutdown] CCTV service closed cleanly.")


def main():
    parser = argparse.ArgumentParser(description="RailSentinel Real-Time YOLO CCTV Detection Service")
    parser.add_argument("--camera", type=int, default=0, help="Camera index (default: 0)")
    parser.add_argument("--model", type=str, default="yolov8n.pt", help="YOLO model path (default: yolov8n.pt)")
    parser.add_argument("--conf", type=float, default=0.35, help="Confidence threshold (default: 0.35)")
    parser.add_argument("--api-url", type=str, default="http://localhost:8000/api/v1", help="Backend API URL")
    parser.add_argument("--headless", action="store_true", help="Run without preview GUI window")
    args = parser.parse_args()

    run_cctv_service(
        camera_index=args.camera,
        model_name=args.model,
        conf_thresh=args.conf,
        api_url=args.api_url,
        headless=args.headless,
    )


if __name__ == "__main__":
    main()
