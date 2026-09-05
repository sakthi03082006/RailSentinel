import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ai.inference.models import DetectionEvidence
from .detector import DetectedObject


@dataclass
class TrackedItem:
    track_id: int
    class_id: int
    class_name: str
    is_luggage: bool
    confidence: float
    bbox: Tuple[int, int, int, int]
    center: Tuple[int, int]
    first_seen: float
    last_seen: float
    dwell_seconds: float = 0.0
    missing_count: int = 0
    hits: int = 1
    is_attended: bool = False
    had_nearby_person: bool = False
    person_left_object: bool = False
    anchor_center: Optional[Tuple[int, int]] = None
    unattended_start_time: Optional[float] = None
    unattended_seconds: float = 0.0
    alert_dispatched: bool = False


class SecurityObjectTracker:
    """
    Tracks detected humans and baggage across video frames, calculates dwell duration,
    and analyzes owner-separation with temporal debouncing and stationary persistence
    to prevent false unattended-luggage alerts.
    """

    def __init__(
        self,
        max_distance_px: float = 80.0,
        max_missing_frames: int = 30,
        min_confirmation_hits: int = 3,
        owner_proximity_px: float = 180.0,
        separation_confirm_seconds: float = 3.0,
        max_stationary_drift_px: float = 35.0,
        source_name: str = "CCTV-WEBCAM-01",
    ):
        self.max_distance_px = max_distance_px
        self.max_missing_frames = max_missing_frames
        self.min_confirmation_hits = min_confirmation_hits
        self.owner_proximity_px = owner_proximity_px
        self.separation_confirm_seconds = separation_confirm_seconds
        self.max_stationary_drift_px = max_stationary_drift_px
        self.source_name = source_name

        self.next_track_id: int = 1
        self.tracks: Dict[int, TrackedItem] = {}

    def _euclidean_distance(self, p1: Tuple[int, int], p2: Tuple[int, int]) -> float:
        return math.hypot(p1[0] - p2[0], p1[1] - p2[1])

    def _is_person_near_or_holding(
        self,
        luggage_bbox: Tuple[int, int, int, int],
        luggage_center: Tuple[int, int],
        person_detections: List[DetectedObject],
    ) -> bool:
        """
        Determines whether a person is actively holding, wearing, or standing near the luggage.
        Evaluates both bounding-box overlap and centroid Euclidean proximity.
        """
        lx1, ly1, lx2, ly2 = luggage_bbox

        for p in person_detections:
            # 1. Centroid distance check
            dist = self._euclidean_distance(luggage_center, p.center)
            if dist <= self.owner_proximity_px:
                return True

            # 2. Bounding-box intersection (person holding or wearing the bag)
            px1, py1, px2, py2 = p.bbox
            inter_x1 = max(lx1, px1)
            inter_y1 = max(ly1, py1)
            inter_x2 = min(lx2, px2)
            inter_y2 = min(ly2, py2)

            if inter_x1 < inter_x2 and inter_y1 < inter_y2:
                return True

        return False

    def update(
        self,
        detections: List[DetectedObject],
        current_time: Optional[float] = None,
    ) -> Tuple[List[TrackedItem], List[DetectionEvidence]]:
        """
        Updates active tracks with detections from the current frame.
        Applies conservative temporal separation and stationary checks.
        """
        if current_time is None:
            current_time = time.time()

        # Separate persons and luggage in current frame
        person_detections = [d for d in detections if d.class_name == "person"]

        # Match all detections with existing tracks
        matched_track_ids = set()
        matched_detection_indices = set()

        for det_idx, det in enumerate(detections):
            best_id = None
            best_dist = float("inf")

            for t_id, track in self.tracks.items():
                if t_id in matched_track_ids:
                    continue
                # Same category (luggage to luggage, person to person)
                if track.is_luggage == det.is_luggage:
                    dist = self._euclidean_distance(track.center, det.center)
                    if dist < self.max_distance_px and dist < best_dist:
                        best_dist = dist
                        best_id = t_id

            if best_id is not None:
                track = self.tracks[best_id]
                track.hits += 1
                track.bbox = det.bbox
                track.center = det.center
                track.confidence = (track.confidence * 0.7) + (det.confidence * 0.3)
                track.last_seen = current_time
                track.dwell_seconds = max(0.0, current_time - track.first_seen)
                track.missing_count = 0
                matched_track_ids.add(best_id)
                matched_detection_indices.add(det_idx)

        # Create new tracks for unmatched detections
        for det_idx, det in enumerate(detections):
            if det_idx not in matched_detection_indices:
                new_id = self.next_track_id
                self.next_track_id += 1

                self.tracks[new_id] = TrackedItem(
                    track_id=new_id,
                    class_id=det.class_id,
                    class_name=det.class_name,
                    is_luggage=det.is_luggage,
                    confidence=det.confidence,
                    bbox=det.bbox,
                    center=det.center,
                    first_seen=current_time,
                    last_seen=current_time,
                    dwell_seconds=0.0,
                    missing_count=0,
                    hits=1,
                    anchor_center=det.center,
                )
                matched_track_ids.add(new_id)

        # Handle tracks that were not matched in this frame
        retired_ids = []
        for t_id, track in self.tracks.items():
            if t_id not in matched_track_ids:
                track.missing_count += 1
                if track.missing_count > self.max_missing_frames:
                    retired_ids.append(t_id)

        for t_id in retired_ids:
            del self.tracks[t_id]

        # Analyze owner proximity and stationary dwell for active luggage tracks
        evidences: List[DetectionEvidence] = []
        active_tracks: List[TrackedItem] = list(self.tracks.values())

        for track in active_tracks:
            if track.is_luggage:
                person_nearby = self._is_person_near_or_holding(
                    track.bbox, track.center, person_detections
                )

                if person_nearby:
                    # Person is holding or near the bag: definitely attended
                    track.is_attended = True
                    track.had_nearby_person = True
                    track.person_left_object = False
                    track.unattended_start_time = None
                    track.unattended_seconds = 0.0
                    track.anchor_center = track.center
                else:
                    # Person is not near: check stationary persistence
                    if track.anchor_center is None:
                        track.anchor_center = track.center

                    drift = self._euclidean_distance(track.center, track.anchor_center)
                    if drift > self.max_stationary_drift_px:
                        # Bag is moving/carried; reset unattended timer
                        track.anchor_center = track.center
                        track.unattended_start_time = current_time
                        track.unattended_seconds = 0.0
                        track.person_left_object = False
                        track.is_attended = False
                    else:
                        # Bag is stationary
                        if track.unattended_start_time is None:
                            track.unattended_start_time = current_time

                        track.unattended_seconds = max(
                            0.0, current_time - track.unattended_start_time
                        )

                        # Only confirm separation after sustained threshold
                        if track.unattended_seconds >= self.separation_confirm_seconds:
                            track.person_left_object = True
                            track.is_attended = False
                        else:
                            # In temporal debounce hold
                            track.person_left_object = False
                            track.is_attended = False

                # Generate evidence for threat evaluation
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
                    detection_source=self.source_name,
                )
                evidences.append(evidence)

        return active_tracks, evidences

