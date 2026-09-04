from app.core.config import Settings
from app.models.enums import SeverityBand


def severity_band_for_score(score, settings: Settings) -> SeverityBand:
    value = float(score)
    if value <= settings.threat_green_max:
        return SeverityBand.GREEN
    if value <= settings.threat_yellow_max:
        return SeverityBand.YELLOW
    return SeverityBand.RED
