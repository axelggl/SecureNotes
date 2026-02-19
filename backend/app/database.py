"""
Database connection and session management.

Uses SQLAlchemy 2.0 with async support capability.
Connection pooling and proper session handling for security.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()


def create_db_engine():
    """
    Create database engine with appropriate settings.

    Uses connection pooling for PostgreSQL but not for SQLite.
    """
    url = settings.database_url

    # SQLite doesn't support connection pooling options
    if url.startswith("sqlite"):
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=settings.debug,
        )

    # PostgreSQL with connection pooling
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=settings.debug,
    )


engine = create_db_engine()

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency that provides a database session.

    Yields:
        SQLAlchemy session

    Usage:
        @app.get("/")
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
