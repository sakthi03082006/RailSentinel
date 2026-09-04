from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"

class DetectionEvidence(BaseModel):
    """
    Evidence collected from computer vision systems (RGB/Thermal).
    Must not include chemical profiling.
    """
    object_type: str = Field(..., description="Type of object detected (e.g., luggage, person)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence 0-1")
    dwell_seconds: float = Field(0.0, description="Seconds the object has lingered in the frame")
    person_left_object: bool = Field(False, description="Whether a person was seen leaving this object")
    detection_source: str = Field(..., description="Source of the detection, e.g., 'RGB_CAM_1'")

class ThreatAnalysis(BaseModel):
    """
    Structured outcome of the AI module threat scoring and anomaly detection.
    """
    evidence: DetectionEvidence
    threat_score: float = Field(..., ge=0.0, le=100.0, description="Computed 0-100 risk score")
    severity: Severity
    explanation: str = Field(..., description="Reasoning for the assigned score")
