from .models import DetectionEvidence, ThreatAnalysis, Severity

def calculate_threat(evidence: DetectionEvidence) -> ThreatAnalysis:
    """
    Translates computer vision evidence into a contextual risk score (0-100)
    and a categorization (GREEN, YELLOW, RED), adhering to scientific boundaries
    (no chemical identification logic).
    """
    
    score = 0.0
    reasons = []

    # Baseline confidence impact
    if evidence.confidence > 0.8:
        score += 10.0
        reasons.append(f"High confidence ({evidence.confidence*100:.1f}%) detection.")
    elif evidence.confidence < 0.3:
        reasons.append("Low confidence detection.")
        return ThreatAnalysis(
            evidence=evidence,
            threat_score=score,
            severity=Severity.GREEN,
            explanation=" ".join(reasons)
        )

    # Behavior heuristics
    if evidence.object_type.lower() in ("luggage", "bag", "backpack", "package", "handbag", "suitcase"):
        if evidence.person_left_object:
            score += 40.0
            reasons.append("Person observed leaving the object.")
        
        if evidence.dwell_seconds > 60:
            score += 20.0
            reasons.append(f"Object dwelling for {evidence.dwell_seconds} seconds.")
        elif evidence.dwell_seconds > 30:
            score += 10.0
            reasons.append(f"Object dwelling for {evidence.dwell_seconds} seconds.")
    else:
        # General non-luggage objects
        if evidence.dwell_seconds > 120:
            score += 15.0
            reasons.append(f"Object lingering for {evidence.dwell_seconds} seconds.")

    # Bound the score
    score = min(max(score, 0.0), 100.0)

    # Determine Severity
    if score >= 60.0:
        severity = Severity.RED
    elif score >= 30.0:
        severity = Severity.YELLOW
    else:
        severity = Severity.GREEN

    if not reasons:
        reasons.append("No significant anomalies detected.")

    return ThreatAnalysis(
        evidence=evidence,
        threat_score=score,
        severity=severity,
        explanation=" ".join(reasons)
    )
