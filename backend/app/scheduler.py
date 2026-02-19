"""
Scheduler for automatic cleanup of expired notes.

Runs periodically to delete notes that have passed their expiration time.
This ensures data minimization and reduces storage of sensitive information.
"""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Note

logger = logging.getLogger(__name__)

# Global scheduler instance
scheduler: BackgroundScheduler | None = None


def cleanup_expired_notes(session_factory=None) -> int:
    """
    Delete all expired notes from the database.

    Args:
        session_factory: Optional session factory for testing. Defaults to SessionLocal.

    Returns:
        Number of notes deleted

    Security note:
        - Only logs count, never content or tokens
        - Uses parameterized queries to prevent SQL injection
    """
    factory = session_factory or SessionLocal
    db: Session = factory()
    try:
        # Use naive UTC datetime for SQLite compatibility
        # PostgreSQL handles timezone-aware datetimes correctly
        now_utc = datetime.now(timezone.utc)
        now_naive = now_utc.replace(tzinfo=None)

        # Find expired notes
        expired_notes = db.query(Note).filter(Note.expires_at < now_naive).all()
        count = len(expired_notes)

        if count > 0:
            # Delete by IDs to avoid SQLAlchemy evaluation issues
            expired_ids = [note.id for note in expired_notes]
            db.query(Note).filter(Note.id.in_(expired_ids)).delete(
                synchronize_session=False
            )
            db.commit()
            logger.info(f"Cleanup completed: {count} expired note(s) deleted")
        else:
            logger.debug("Cleanup completed: no expired notes found")

        return count

    except Exception as e:
        db.rollback()
        logger.error(f"Cleanup failed: {e}")
        raise
    finally:
        db.close()


def start_scheduler(interval_minutes: int = 5) -> BackgroundScheduler:
    """
    Start the background scheduler for periodic cleanup.

    Args:
        interval_minutes: How often to run cleanup (default: 5 minutes)

    Returns:
        The scheduler instance
    """
    global scheduler

    if scheduler is not None and scheduler.running:
        logger.warning("Scheduler already running")
        return scheduler

    scheduler = BackgroundScheduler(
        job_defaults={
            "coalesce": True,  # Combine missed runs into one
            "max_instances": 1,  # Only one instance at a time
        }
    )

    scheduler.add_job(
        cleanup_expired_notes,
        "interval",
        minutes=interval_minutes,
        id="cleanup_expired_notes",
        name="Cleanup expired notes",
        replace_existing=True,
    )

    scheduler.start()
    logger.info(f"Scheduler started: cleanup every {interval_minutes} minutes")

    return scheduler


def stop_scheduler() -> None:
    """Stop the background scheduler."""
    global scheduler

    if scheduler is not None and scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
        scheduler = None


def get_scheduler() -> BackgroundScheduler | None:
    """Get the current scheduler instance."""
    return scheduler
