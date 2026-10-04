"""
NetSentinel — AI-Powered Network Monitoring & Security System
Application entrypoint.

Wires together: configuration, structured logging, database
initialization, every API router, the background availability-monitor
lifecycle, and the static dashboard frontend.
"""

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api import alerts, auth, devices, interfaces, metrics, monitoring, traffic
from app.config import get_settings
from app.database import SessionLocal, init_db
from app.models.user import User, UserRole
from app.security.auth import hash_password

settings = get_settings()

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("netsentinel")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

def bootstrap_admin() -> None:
    """Create the initial admin from environment variables if configured."""
    username = settings.bootstrap_admin_username
    password = settings.bootstrap_admin_password

    if not username or not password:
        return

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.username == username).first()

        if existing_user:
            logger.info("Bootstrap admin '%s' already exists", username)
            return

        user = User(
            username=username,
            hashed_password=hash_password(password),
            role=UserRole.ADMIN,
        )

        db.add(user)
        db.commit()

        logger.info("Bootstrap admin '%s' created successfully", username)

    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: initialize the database schema (via SQLAlchemy
    create_all — Alembic migrations remain the source of truth for
    production-style schema evolution; this is a convenience for a
    fresh clone).
    Shutdown: cancel the background monitor task if it's still running,
    so the process exits cleanly instead of leaving a dangling task.
    """
    logger.info("%s starting up (env=%s)", settings.app_name, settings.app_env)
    logger.info("Configured monitor subnet: %s", settings.monitor_subnet)

    init_db()
    logger.info("Database ready at %s", settings.database_url)

    bootstrap_admin()

    app.state.start_time = time.time()
    app.state.monitor_task = None

    yield

    task = app.state.monitor_task
    if task is not None and not task.done():
        task.cancel()
    logger.info("%s shutting down", settings.app_name)


app = FastAPI(
    title="NetSentinel API",
    description=(
        "AI-Powered Network Monitoring & Security System — REST API for "
        "device discovery, monitoring, security alerting, and traffic "
        "analysis."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers ---
app.include_router(auth.router)
app.include_router(devices.router)
app.include_router(alerts.router)
app.include_router(traffic.router)
app.include_router(interfaces.router)
app.include_router(metrics.router)
app.include_router(monitoring.router)


@app.get("/api/health", tags=["system"])
async def health_check() -> dict:
    """Liveness/readiness endpoint — no auth required, for uptime tooling."""
    uptime_seconds = time.time() - app.state.start_time
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.app_env,
        "uptime_seconds": round(uptime_seconds, 2),
    }


# --- Dashboard (static frontend) ---
# Mounted last, at the root, so it doesn't shadow the /api/* routes above.
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
