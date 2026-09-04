from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api import audit, auth, events, health
from app.core.config import get_settings
from app.db.seed import seed_if_empty
from app.db.session import SessionLocal
from app.services.websocket import manager


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db = SessionLocal()

    try:
        seed_if_empty(db)
    finally:
        db.close()

    yield


def create_app() -> FastAPI:
    settings = get_settings()

    application = FastAPI(
        title="RailSentinel API",
        description=(
            "Authenticated security event pipeline (Milestone 1). "
            "SHA-256 is used as a hash, not encryption."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(events.router)
    application.include_router(audit.router)

    return application


app = create_app()


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)