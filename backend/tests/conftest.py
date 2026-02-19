"""
Pytest fixtures for SafeNotes tests.

Provides isolated test database and client for each test.
"""

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment variables BEFORE importing app modules
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["ENCRYPTION_KEY"] = "ls7xKk/umNfSGP2E8zcx1AFl0isB88XFeaCvAfA9mFE="  # 32-byte test key
os.environ["APP_ENV"] = "development"
os.environ["DEBUG"] = "false"

from app.database import get_db
from app.main import app
from app.models import Base
from app.routes import limiter


# Module-level test engine and session factory for reuse
_test_engine = None
_test_session_factory = None


@pytest.fixture(scope="function")
def test_db():
    """
    Create an isolated in-memory SQLite database for each test.

    This ensures tests don't interfere with each other.
    """
    global _test_engine, _test_session_factory

    _test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    _test_session_factory = sessionmaker(
        autocommit=False, autoflush=False, bind=_test_engine
    )

    # Create tables
    Base.metadata.create_all(bind=_test_engine)

    db = _test_session_factory()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=_test_engine)
        _test_engine = None
        _test_session_factory = None


@pytest.fixture
def test_session_factory(test_db):
    """
    Provide the test session factory for scheduler tests.

    This must be used with test_db to ensure tables are created.
    """
    return _test_session_factory


@pytest.fixture(scope="function")
def client(test_db):
    """
    Create a test client with isolated database.

    Resets rate limiter storage between tests to prevent rate limit issues.
    """

    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    # Reset rate limiter storage for each test
    limiter.reset()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture
def sample_note_data():
    """Sample valid note data for tests."""
    return {
        "content": "This is a secret note for testing purposes.",
        "password": None,
        "expiration": "24h",
    }


@pytest.fixture
def sample_note_with_password():
    """Sample note data with password protection."""
    return {
        "content": "This is a password-protected secret note.",
        "password": "SecurePassword123!",
        "expiration": "1h",
    }
