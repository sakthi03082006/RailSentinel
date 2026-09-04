# AI Inference Module

This directory contains the initial pipeline for the AI threat inference module. 
It includes data models, a simulator to generate mock detection events, and a risk scoring engine.

## Constraints & Scientific Boundaries
- **Threat Screening Only**: The logic bounds itself strictly to RGB/thermal computer vision paradigms (object detection, tracking, behavior/anomaly detection, and contextual risk scoring).
- **Prohibited Capabilities**: This module expressly **does not** claim to chemically identify narcotics, explosives, or perform any form of non-line-of-sight physical testing.

## Future Integration
The `simulator.py` component serves to bootstrap the event pipeline and dashboard components. Once the system matures, the Inference layer should be replaced or augmented by a real `YOLO_Adapter` or `OpenCV_Detector` pipeline that yields `DetectionEvidence` payloads structured identically to current Pydantic models.

## Structure
- `models.py`: Pydantic definitions for standard detection and threat payloads.
- `scoring.py`: Rules-based heuristic analysis yielding 1-100 severity scores based on behavioral patterns.
- `simulator.py`: Mock generation engine.
