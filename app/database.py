import os
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Read the database URL from the environment. Defaults to a local SQLite file
# so the app runs without any external dependencies.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

# check_same_thread=False is required for SQLite when multiple FastAPI threads
# share a single connection during request handling.
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# autoflush=False prevents SQLAlchemy from flushing pending changes before
# every query, giving explicit control over when writes hit the database.
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Base class that all ORM models inherit from. SQLAlchemy uses it to track
# the full set of mapped tables for schema inspection and migration support.
Base = declarative_base()


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def utcnow_naive() -> datetime:
    """Return the current UTC time without timezone info.

    SQLite does not store timezone data, so all timestamps in the database
    use naive datetimes. Comparisons are always done in UTC.
    """
    return utcnow().replace(tzinfo=None)


def get_db():
    """FastAPI dependency that yields a database session per request.

    The session is always closed in the finally block, even if the handler
    raises an exception, to prevent connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
