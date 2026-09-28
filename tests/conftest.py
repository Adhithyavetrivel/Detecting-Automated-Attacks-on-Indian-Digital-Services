"""
Shared pytest fixtures.

Tests run against an isolated, file-based SQLite database (not the
developer's real netsentinel.db) so running the test suite never
touches real monitoring data, and each test function gets a clean
schema via the `db` fixture's create/drop cycle.
"""

import os

os.environ["DATABASE_URL"] = "sqlite:///./test_netsentinel.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.main import app
from app.security.auth import hash_password


@pytest.fixture()
def db_session():
    engine = create_engine(
        "sqlite:///./test_netsentinel.db", connect_args={"check_same_thread": False}
    )
    TestingSessionLocal = sessionmaker(bind=engine)

    from app.models import (  # noqa: F401  (registers models on Base.metadata)
        alert,
        audit_log,
        device,
        interface,
        metric,
        traffic,
        user,
    )

    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        if os.path.exists("test_netsentinel.db"):
            os.remove("test_netsentinel.db")


@pytest.fixture()
def client(db_session):
    from app.database import get_db

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def admin_token(db_session, client):
    """Create an admin user directly in the DB and return a valid JWT for it."""
    from app.models.user import User, UserRole

    user = User(
        username="testadmin",
        hashed_password=hash_password("testpass123"),
        role=UserRole.ADMIN,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/api/auth/login",
        data={"username": "testadmin", "password": "testpass123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]
