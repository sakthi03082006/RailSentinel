from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password, verify_password
from app.db.ids import ADMIN_USER_ID, DEMO_CCTV_DEVICE_ID, DEMO_DEVICE_ID, DEMO_STATION_ID, DEMO_ZONE_ID
from app.models.audit import AuditChainHead
from app.models.device import Device
from app.models.enums import ROLE_NAMES, DeviceStatus, DeviceType, ZoneType
from app.models.role import Role
from app.models.station import Station, Zone
from app.models.user import User
from app.services.hash_chain import GENESIS_HASH
from sqlalchemy import select


def seed_if_empty(db: Session) -> None:
    """Idempotent demo seed. Safe on every API startup."""
    settings = get_settings()

    for name in ROLE_NAMES:
        existing = db.scalar(select(Role).where(Role.name == name))
        if existing is None:
            db.add(Role(name=name))
    db.flush()

    admin_role = db.scalar(select(Role).where(Role.name == "administrator"))
    admin = db.get(User, ADMIN_USER_ID)
    if admin is None:
        db.add(
            User(
                id=ADMIN_USER_ID,
                username=settings.admin_username,
                password_hash=hash_password(settings.admin_password),
                full_name="Demo Administrator",
                role_id=admin_role.id,
                is_active=True,
            )
        )
    else:
        admin.username = settings.admin_username
        admin.is_active = True
        if not verify_password(settings.admin_password, admin.password_hash):
            admin.password_hash = hash_password(settings.admin_password)
        admin.role_id = admin_role.id

    if db.get(Station, DEMO_STATION_ID) is None:
        db.add(
            Station(
                id=DEMO_STATION_ID,
                code="DEMO",
                name="Demo Station",
                timezone="Asia/Kolkata",
                is_active=True,
            )
        )

    if db.get(Zone, DEMO_ZONE_ID) is None:
        db.add(
            Zone(
                id=DEMO_ZONE_ID,
                station_id=DEMO_STATION_ID,
                name="Entrance",
                zone_type=ZoneType.ENTRANCE.value,
                sensitivity=1.0,
                dwell_threshold_seconds=30,
                is_active=True,
            )
        )

    if db.get(Device, DEMO_DEVICE_ID) is None:
        db.add(
            Device(
                id=DEMO_DEVICE_ID,
                device_uid="sim-cctv-demo-001",
                device_type=DeviceType.SIMULATOR.value,
                station_id=DEMO_STATION_ID,
                label="Demo simulator",
                status=DeviceStatus.ACTIVE.value,
            )
        )

    if db.get(Device, DEMO_CCTV_DEVICE_ID) is None:
        db.add(
            Device(
                id=DEMO_CCTV_DEVICE_ID,
                device_uid="cctv-webcam-01",
                device_type=DeviceType.CCTV_INGEST.value,
                station_id=DEMO_STATION_ID,
                label="Station Gate 1 - Laptop CCTV",
                status=DeviceStatus.ACTIVE.value,
            )
        )

    if db.get(AuditChainHead, 1) is None:
        db.add(AuditChainHead(id=1, head_hash=GENESIS_HASH, head_event_id=None))

    db.commit()
