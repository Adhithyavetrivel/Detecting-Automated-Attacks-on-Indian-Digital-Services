"""
Database engine and session management.

A single Engine is created at import time and reused everywhere (SQLAlchemy
engines are meant to be long-lived and manage their own connection pool —
creating a new one per request would be wasteful and can exhaust
connections under load).
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings

settings = get_settings()

# `connect_args` below is SQLite-specific: SQLite by default only allows
# the thread that created a connection to use it. FastAPI can serve a
# single request on a different thread than the one that opened the
# connection, so this flag relaxes that restriction. It is a no-op (and
# harmless to pass) once the URL points at PostgreSQL instead.
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Base class every ORM model inherits from."""
    pass


def get_db() -> Generator:
    """
    FastAPI dependency that yields a DB session and guarantees it is
    closed afterward, even if the request raises an exception.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Create all tables that don't exist yet.

    For this project we use Alembic migrations as the source of truth in
    normal operation, but init_db() is kept as a convenience so a fresh
    clone can run immediately with `python -m app.database` without first
    running migrations — useful for quick local testing.
    """
    # Import models here (not at module top-level) so that all model
    # classes are registered on Base.metadata before create_all() runs,
    # without creating a circular import between database.py and models.
    from app.models import (  # noqa: F401
        alert,
        audit_log,
        device,
        interface,
        metric,
        traffic,
        user,
    )

    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {settings.database_url}")
