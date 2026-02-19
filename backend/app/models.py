"""
SQLAlchemy database models for SafeNotes.

Security considerations:
- UUIDs used instead of sequential IDs (prevents enumeration)
- Token is indexed for fast lookups but stored separately from ID
- Encrypted content stored as binary (BYTEA)
- Password hash nullable (optional protection)
- Timestamps in UTC for consistency
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Note(Base):
    """
    Secure note model.

    Attributes:
        id: Internal UUID (never exposed to users)
        token: Public access token (high entropy, URL-safe)
        encrypted_content: AES-256-GCM encrypted note content
        password_hash: Argon2id hash of access password (optional)
        expires_at: When the note expires (UTC)
        burn_after_read: Delete immediately after first read
        created_at: Creation timestamp (UTC)
        accessed_at: Last access timestamp (UTC, nullable)
    """

    __tablename__ = "notes"

    # Primary key - internal use only, never exposed
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Access token - this is what users see in URLs
    # 43 chars for 32-byte base64url token
    token: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    # Encrypted note content (IV + ciphertext + auth tag)
    encrypted_content: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    # Optional password hash (Argon2id)
    # Nullable - not all notes require password
    password_hash: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True,
    )

    # Expiration settings
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,  # Index for cleanup queries
    )

    burn_after_read: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Audit timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    accessed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Composite index for cleanup query optimization
    __table_args__ = (
        Index("ix_notes_expires_at_burn", "expires_at", "burn_after_read"),
    )

    def __repr__(self) -> str:
        # Never include sensitive data in repr
        return f"<Note(token={self.token[:8]}..., expires_at={self.expires_at})>"
