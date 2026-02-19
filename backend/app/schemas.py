"""
Pydantic schemas for request/response validation.

All user inputs are strictly validated to prevent injection attacks.
Schemas follow the principle of minimal data exposure.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator


class ExpirationOption(str, Enum):
    """
    Allowed expiration options.

    Limited to predefined values to prevent abuse.
    No "never expires" option - all notes must expire.
    """

    ONE_HOUR = "1h"
    ONE_DAY = "24h"
    SEVEN_DAYS = "7d"
    BURN_AFTER_READ = "burn"


class NoteCreateRequest(BaseModel):
    """
    Request schema for creating a new note.

    Security validations:
    - Content limited to 10KB
    - Password optional but must be strong if provided
    - Expiration limited to predefined options
    """

    content: str = Field(
        ...,
        min_length=1,
        max_length=10240,  # 10 KB
        description="Note content (max 10KB)",
    )

    password: str | None = Field(
        default=None,
        min_length=8,
        max_length=128,
        description="Optional access password (8-128 chars)",
    )

    expiration: ExpirationOption = Field(
        default=ExpirationOption.ONE_DAY,
        description="Expiration option",
    )

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        # Strip null bytes (potential injection)
        v = v.replace("\x00", "")

        # Ensure not empty after stripping
        if not v.strip():
            raise ValueError("Content cannot be empty or whitespace only")

        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        if v is None:
            return None

        # Strip null bytes
        v = v.replace("\x00", "")

        # Check minimum length after stripping
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")

        return v


class NoteCreateResponse(BaseModel):
    """
    Response schema after creating a note.

    Only returns the access token - never expose internal IDs.
    """

    token: str = Field(
        ...,
        description="Unique access token for the note",
    )

    expires_at: datetime = Field(
        ...,
        description="When the note will expire (UTC)",
    )

    password_protected: bool = Field(
        ...,
        description="Whether the note requires a password",
    )

    burn_after_read: bool = Field(
        ...,
        description="Whether the note will be deleted after reading",
    )


class NoteAccessRequest(BaseModel):
    """
    Request schema for accessing a password-protected note.
    """

    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Access password",
    )


class NoteContentResponse(BaseModel):
    """
    Response schema when accessing a note.

    Returns decrypted content only after successful authentication.
    """

    content: str = Field(
        ...,
        description="Decrypted note content",
    )

    created_at: datetime = Field(
        ...,
        description="When the note was created (UTC)",
    )

    will_be_deleted: bool = Field(
        ...,
        description="Whether this access deletes the note",
    )


class ErrorResponse(BaseModel):
    """
    Standard error response schema.

    Generic messages to prevent information leakage.
    """

    detail: str = Field(
        ...,
        description="Error description",
    )


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(default="healthy")
    version: str = Field(default="1.0.0")
