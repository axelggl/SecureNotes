"""
Tests for scheduler and expiration functionality.

Verifies:
- Expired notes are deleted
- Non-expired notes are preserved
- Scheduler runs correctly
"""

from datetime import datetime, timedelta, timezone

from app.models import Note
from app.scheduler import cleanup_expired_notes


class TestCleanupExpiredNotes:
    """Tests for the cleanup_expired_notes function."""

    def test_deletes_expired_notes(self, test_db, test_session_factory):
        """Expired notes should be deleted by cleanup."""
        # Create an expired note directly in DB
        expired_note = Note(
            token="expired_token_12345678901234567890123456789012",
            encrypted_content=b"encrypted_content",
            expires_at=datetime.utcnow() - timedelta(hours=1),
            burn_after_read=False,
        )
        test_db.add(expired_note)
        test_db.commit()

        # Verify note exists
        assert test_db.query(Note).count() == 1

        # Run cleanup with test session factory
        deleted_count = cleanup_expired_notes(session_factory=test_session_factory)

        # Refresh the session to see changes
        test_db.expire_all()

        # Verify note was deleted
        assert deleted_count == 1
        assert test_db.query(Note).count() == 0

    def test_preserves_non_expired_notes(self, test_db, test_session_factory):
        """Non-expired notes should not be deleted."""
        # Create a note that expires in the future
        valid_note = Note(
            token="valid_token_123456789012345678901234567890123",
            encrypted_content=b"encrypted_content",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            burn_after_read=False,
        )
        test_db.add(valid_note)
        test_db.commit()

        # Run cleanup
        deleted_count = cleanup_expired_notes(session_factory=test_session_factory)

        # Verify note was NOT deleted
        assert deleted_count == 0
        assert test_db.query(Note).count() == 1

    def test_deletes_only_expired_notes(self, test_db, test_session_factory):
        """Cleanup should only delete expired notes, not valid ones."""
        # Create mix of expired and valid notes
        expired_note = Note(
            token="expired_token_12345678901234567890123456789012",
            encrypted_content=b"expired_content",
            expires_at=datetime.utcnow() - timedelta(hours=1),
            burn_after_read=False,
        )
        valid_note = Note(
            token="valid_token_123456789012345678901234567890123",
            encrypted_content=b"valid_content",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            burn_after_read=False,
        )
        test_db.add(expired_note)
        test_db.add(valid_note)
        test_db.commit()

        # Verify both notes exist
        assert test_db.query(Note).count() == 2

        # Run cleanup
        deleted_count = cleanup_expired_notes(session_factory=test_session_factory)

        # Refresh to see changes
        test_db.expire_all()

        # Verify only expired note was deleted
        assert deleted_count == 1
        assert test_db.query(Note).count() == 1

        remaining = test_db.query(Note).first()
        assert remaining.token == "valid_token_123456789012345678901234567890123"

    def test_deletes_multiple_expired_notes(self, test_db, test_session_factory):
        """Multiple expired notes should all be deleted."""
        # Create multiple expired notes
        for i in range(5):
            expired_note = Note(
                token=f"expired_token_{i}_12345678901234567890123456789",
                encrypted_content=b"expired_content",
                expires_at=datetime.utcnow() - timedelta(hours=i + 1),
                burn_after_read=False,
            )
            test_db.add(expired_note)
        test_db.commit()

        # Verify notes exist
        assert test_db.query(Note).count() == 5

        # Run cleanup
        deleted_count = cleanup_expired_notes(session_factory=test_session_factory)

        # Refresh to see changes
        test_db.expire_all()

        # Verify all were deleted
        assert deleted_count == 5
        assert test_db.query(Note).count() == 0

    def test_no_notes_returns_zero(self, test_db, test_session_factory):
        """Cleanup with no notes should return 0."""
        assert test_db.query(Note).count() == 0

        deleted_count = cleanup_expired_notes(session_factory=test_session_factory)

        assert deleted_count == 0

    def test_cleanup_logs_count(self, test_db, test_session_factory, caplog):
        """Cleanup should log the number of deleted notes."""
        import logging

        # Create expired note
        expired_note = Note(
            token="expired_token_12345678901234567890123456789012",
            encrypted_content=b"expired_content",
            expires_at=datetime.utcnow() - timedelta(hours=1),
            burn_after_read=False,
        )
        test_db.add(expired_note)
        test_db.commit()

        with caplog.at_level(logging.INFO):
            cleanup_expired_notes(session_factory=test_session_factory)

        # Check logs
        log_messages = [record.message for record in caplog.records]
        assert any("1 expired note" in msg for msg in log_messages)


class TestNoteExpiration:
    """Tests for note expiration behavior via API."""

    def test_expired_note_returns_404(self, client, test_db):
        """Accessing an expired note should return 404."""
        # Create a note that's already expired (directly in DB)
        expired_note = Note(
            token="expired_api_token_1234567890123456789012345",
            encrypted_content=b"test_content",
            expires_at=datetime.utcnow() - timedelta(seconds=1),
            burn_after_read=False,
        )
        test_db.add(expired_note)
        test_db.commit()

        # Try to access it
        response = client.get("/api/notes/expired_api_token_1234567890123456789012345")

        # Should return 404 (not found, same as non-existent)
        assert response.status_code == 404
        assert response.json()["detail"] == "Note not found"

    def test_1h_expiration_sets_correct_time(self, client):
        """1-hour expiration should set expires_at ~1 hour from now."""
        response = client.post(
            "/api/notes",
            json={"content": "Test", "expiration": "1h"},
        )
        data = response.json()

        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        # Should expire in approximately 1 hour (allow 5 second tolerance)
        time_diff = (expires_at - now).total_seconds()
        assert 3595 < time_diff < 3605  # 1 hour ± 5 seconds

    def test_24h_expiration_sets_correct_time(self, client):
        """24-hour expiration should set expires_at ~24 hours from now."""
        response = client.post(
            "/api/notes",
            json={"content": "Test", "expiration": "24h"},
        )
        data = response.json()

        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        # Should expire in approximately 24 hours
        time_diff = (expires_at - now).total_seconds()
        expected_seconds = 24 * 60 * 60
        assert expected_seconds - 5 < time_diff < expected_seconds + 5

    def test_7d_expiration_sets_correct_time(self, client):
        """7-day expiration should set expires_at ~7 days from now."""
        response = client.post(
            "/api/notes",
            json={"content": "Test", "expiration": "7d"},
        )
        data = response.json()

        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        # Should expire in approximately 7 days
        time_diff = (expires_at - now).total_seconds()
        expected_seconds = 7 * 24 * 60 * 60
        assert expected_seconds - 5 < time_diff < expected_seconds + 5

    def test_burn_expiration_sets_far_future(self, client):
        """Burn-after-read should set far-future expiration."""
        response = client.post(
            "/api/notes",
            json={"content": "Test", "expiration": "burn"},
        )
        data = response.json()

        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        # Should expire in approximately 30 days
        time_diff = (expires_at - now).total_seconds()
        expected_seconds = 30 * 24 * 60 * 60
        assert expected_seconds - 5 < time_diff < expected_seconds + 5

    def test_default_expiration_is_24h(self, client):
        """Default expiration (no option specified) should be 24 hours."""
        response = client.post(
            "/api/notes",
            json={"content": "Test"},  # No expiration specified
        )
        data = response.json()

        expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)

        # Should default to 24 hours
        time_diff = (expires_at - now).total_seconds()
        expected_seconds = 24 * 60 * 60
        assert expected_seconds - 5 < time_diff < expected_seconds + 5
