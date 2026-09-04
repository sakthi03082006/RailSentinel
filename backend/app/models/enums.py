from enum import StrEnum

ROLE_NAMES = (
    "administrator",
    "supervisor",
    "control_room_operator",
    "rpf_officer",
)


class ZoneType(StrEnum):
    WAITING_AREA = "waiting_area"
    ENTRANCE = "entrance"
    RESTRICTED = "restricted"
    TRACK_SIDE = "track_side"
    YARD = "yard"
    MAINTENANCE = "maintenance"
    OTHER = "other"


class DeviceType(StrEnum):
    HANDHELD = "handheld"
    ROVER = "rover"
    CCTV_INGEST = "cctv_ingest"
    GATEWAY = "gateway"
    SIMULATOR = "simulator"


class DeviceStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    PENDING = "pending"


class EventType(StrEnum):
    UNATTENDED_OBJECT = "unattended_object"
    ANOMALY = "anomaly"
    DETECTION = "detection"
    PATROL = "patrol"
    HEARTBEAT_ALERT = "heartbeat_alert"
    OTHER = "other"


class EventStatus(StrEnum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    VERIFIED = "VERIFIED"
    DISMISSED = "DISMISSED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"


class SeverityBand(StrEnum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"
