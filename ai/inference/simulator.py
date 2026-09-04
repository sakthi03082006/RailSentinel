import random
from typing import List
from .models import DetectionEvidence, ThreatAnalysis
from .scoring import calculate_threat

class InferenceSimulator:
    """
    A simulated threat inference pipeline designed to stand in before
    the YOLO/OpenCV integration is complete.
    """
    
    def __init__(self, sources: List[str]):
        self.sources = sources
        self.object_types = ["luggage", "person", "bag", "package", "dog"]

    def generate_mock_evidence(self) -> DetectionEvidence:
        """
        Generates structured noise/evidence imitating a CV system.
        """
        obj = random.choice(self.object_types)
        conf = round(random.uniform(0.1, 0.99), 2)
        
        # Luggage might be abandoned more frequently in simulation scenarios
        left_obj = False
        dwell = random.uniform(0, 10.0)

        if obj in ["luggage", "package", "bag"] and random.random() > 0.7:
            left_obj = True
            dwell = random.uniform(20.0, 120.0)

        return DetectionEvidence(
            object_type=obj,
            confidence=conf,
            dwell_seconds=round(dwell, 1),
            person_left_object=left_obj,
            detection_source=random.choice(self.sources)
        )

    def run_cycle(self, count: int = 1) -> List[ThreatAnalysis]:
        """
        Runs the simulated pipeline producing a batch of analyses.
        """
        results = []
        for _ in range(count):
            evidence = self.generate_mock_evidence()
            analysis = calculate_threat(evidence)
            results.append(analysis)
        return results
