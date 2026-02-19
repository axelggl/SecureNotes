"""
API routes for SafeNotes.

All endpoints follow security best practices:
- Input validation via Pydantic schemas
- No sensitive data in error messages
- Proper HTTP status codes
- Audit logging
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import CryptoError, NoteCrypto, generate_secure_token
from app.database import get_db
from app.models import Note
from app.schemas import (
    ExpirationOption,
    NoteContentResponse,
    NoteCreateRequest,
    NoteCreateResponse,
)

# Rate limiter instance
limiter = Limiter(key_func=get_remote_address)


def is_expired(expires_at: datetime) -> bool:
    """
    Check if a datetime is in the past.

    Handles both timezone-aware and naive datetimes (SQLite returns naive).
    """
    now = datetime.now(timezone.utc)
    # If expires_at is naive, assume it's UTC
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < now

# Configure logger - never log sensitive content
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/notes", tags=["notes"])

settings = get_settings()


def get_crypto() -> NoteCrypto:
    """Dependency that provides the crypto instance."""
    return NoteCrypto.from_base64_key(settings.encryption_key)


def calculate_expiration(option: ExpirationOption) -> tuple[datetime, bool]:
    """
    Calculate expiration timestamp and burn_after_read flag.

    Args:
        option: Expiration option from request

    Returns:
        Tuple of (expires_at datetime, burn_after_read bool)
    """
    now = datetime.now(timezone.utc)

    if option == ExpirationOption.BURN_AFTER_READ:
        # Burn after read: set far future expiration, flag for deletion on read
        return now + timedelta(days=30), True
    elif option == ExpirationOption.ONE_HOUR:
        return now + timedelta(hours=1), False
    elif option == ExpirationOption.ONE_DAY:
        return now + timedelta(days=1), False
    elif option == ExpirationOption.SEVEN_DAYS:
        return now + timedelta(days=7), False
    else:
        # Default to 24 hours
        return now + timedelta(days=1), False


@router.post(
    "",
    response_model=NoteCreateResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Note created successfully"},
        400: {"description": "Invalid request data"},
        429: {"description": "Rate limit exceeded"},
        500: {"description": "Internal server error"},
    },
)
@limiter.limit("10/minute")
def create_note(
    note_request: NoteCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    crypto: NoteCrypto = Depends(get_crypto),
) -> NoteCreateResponse:
    """
    Create a new encrypted note.

    Security measures:
    - Content is encrypted with AES-256-GCM before storage
    - Password (if provided) is hashed with Argon2id
    - Token is generated with 256-bit entropy
    - Input is validated and sanitized
    """
    # Generate unique token with high entropy
    token = generate_secure_token(32)

    # Encrypt the content
    try:
        encrypted_content = crypto.encrypt(note_request.content)
    except CryptoError as e:
        logger.error(f"Encryption failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to secure note content",
        )

    # Hash password if provided
    password_hash = None
    if note_request.password:
        from argon2 import PasswordHasher

        ph = PasswordHasher()
        password_hash = ph.hash(note_request.password)

    # Calculate expiration
    expires_at, burn_after_read = calculate_expiration(note_request.expiration)

    # Create note record
    note = Note(
        token=token,
        encrypted_content=encrypted_content,
        password_hash=password_hash,
        expires_at=expires_at,
        burn_after_read=burn_after_read,
    )

    try:
        db.add(note)
        db.commit()
        db.refresh(note)
    except Exception as e:
        db.rollback()
        logger.error(f"Database error creating note: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save note",
        )

    # Log creation (no sensitive data)
    logger.info(
        f"Note created: token={token[:8]}..., "
        f"expires_at={expires_at.isoformat()}, "
        f"password_protected={password_hash is not None}, "
        f"burn_after_read={burn_after_read}"
    )

    return NoteCreateResponse(
        token=token,
        expires_at=expires_at,
        password_protected=password_hash is not None,
        burn_after_read=burn_after_read,
    )


@router.get(
    "/{token}",
    response_model=NoteContentResponse,
    responses={
        200: {"description": "Note content retrieved"},
        404: {"description": "Note not found or expired"},
        403: {"description": "Password required"},
        429: {"description": "Rate limit exceeded"},
    },
)
@limiter.limit("5/minute")
def get_note(
    token: str,
    request: Request,
    password: str | None = None,
    db: Session = Depends(get_db),
    crypto: NoteCrypto = Depends(get_crypto),
) -> NoteContentResponse:
    """
    Retrieve a note by its token.

    Security measures:
    - Returns 404 for both missing and expired notes (prevents enumeration)
    - Password verified with constant-time comparison (Argon2)
    - Note deleted immediately if burn_after_read is set
    """
    # Validate token format (alphanumeric + URL-safe chars)
    if not token or len(token) > 64 or not all(c.isalnum() or c in "-_" for c in token):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        )

    # Query note
    note = db.query(Note).filter(Note.token == token).first()

    # Check existence and expiration (same error to prevent enumeration)
    if note is None or is_expired(note.expires_at):
        logger.info(f"Note access denied: token={token[:8]}..., reason=not_found_or_expired")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Note not found",
        )

    # Check password if required
    if note.password_hash:
        if not password:
            logger.info(f"Note access denied: token={token[:8]}..., reason=password_required")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password required",
            )

        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError

        ph = PasswordHasher()
        try:
            ph.verify(note.password_hash, password)
        except VerifyMismatchError:
            logger.warning(f"Note access denied: token={token[:8]}..., reason=invalid_password")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid password",
            )

    # Decrypt content
    try:
        content = crypto.decrypt(note.encrypted_content)
    except CryptoError as e:
        logger.error(f"Decryption failed for token={token[:8]}...: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve note content",
        )

    # Prepare response
    response = NoteContentResponse(
        content=content,
        created_at=note.created_at,
        will_be_deleted=note.burn_after_read,
    )

    # Update access timestamp
    note.accessed_at = datetime.now(timezone.utc)

    # Delete if burn_after_read
    if note.burn_after_read:
        db.delete(note)
        logger.info(f"Note deleted (burn_after_read): token={token[:8]}...")

    db.commit()

    logger.info(f"Note accessed: token={token[:8]}..., burn_after_read={note.burn_after_read}")

    return response
