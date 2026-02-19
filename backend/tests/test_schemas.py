"""
Tests for Pydantic schemas (input validation).

Verifies:
- Valid inputs are accepted
- Invalid inputs are rejected with proper errors
- Security constraints are enforced
"""

import pytest
from pydantic import ValidationError

from app.schemas import ExpirationOption, NoteCreateRequest


class TestNoteCreateRequest:
    """Tests for note creation request validation."""

    def test_valid_minimal_request(self):
        """Minimal valid request should be accepted."""
        request = NoteCreateRequest(content="Hello, World!")

        assert request.content == "Hello, World!"
        assert request.password is None
        assert request.expiration == ExpirationOption.ONE_DAY

    def test_valid_full_request(self):
        """Full valid request should be accepted."""
        request = NoteCreateRequest(
            content="Secret message",
            password="SecurePass123",
            expiration="1h",
        )

        assert request.content == "Secret message"
        assert request.password == "SecurePass123"
        assert request.expiration == ExpirationOption.ONE_HOUR

    def test_empty_content_rejected(self):
        """Empty content should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            NoteCreateRequest(content="")

        errors = exc_info.value.errors()
        assert any("content" in str(e).lower() for e in errors)

    def test_whitespace_only_content_rejected(self):
        """Whitespace-only content should be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            NoteCreateRequest(content="   \n\t  ")

        errors = exc_info.value.errors()
        assert any("empty" in str(e).lower() or "whitespace" in str(e).lower() for e in errors)

    def test_content_exceeding_max_size_rejected(self):
        """Content exceeding 10KB should be rejected."""
        large_content = "X" * 10241  # 10KB + 1 byte

        with pytest.raises(ValidationError) as exc_info:
            NoteCreateRequest(content=large_content)

        errors = exc_info.value.errors()
        assert any("max" in str(e).lower() or "length" in str(e).lower() for e in errors)

    def test_content_at_max_size_accepted(self):
        """Content at exactly 10KB should be accepted."""
        max_content = "X" * 10240

        request = NoteCreateRequest(content=max_content)
        assert len(request.content) == 10240

    def test_null_bytes_stripped_from_content(self):
        """Null bytes should be stripped from content."""
        request = NoteCreateRequest(content="Hello\x00World")
        assert "\x00" not in request.content
        assert request.content == "HelloWorld"

    def test_password_minimum_length_enforced(self):
        """Password must be at least 8 characters."""
        with pytest.raises(ValidationError) as exc_info:
            NoteCreateRequest(content="Test", password="short")

        errors = exc_info.value.errors()
        assert any("password" in str(e).lower() for e in errors)

    def test_password_at_minimum_length_accepted(self):
        """Password at exactly 8 characters should be accepted."""
        request = NoteCreateRequest(content="Test", password="12345678")
        assert request.password == "12345678"

    def test_password_exceeding_max_length_rejected(self):
        """Password exceeding 128 characters should be rejected."""
        long_password = "X" * 129

        with pytest.raises(ValidationError) as exc_info:
            NoteCreateRequest(content="Test", password=long_password)

        errors = exc_info.value.errors()
        assert any("password" in str(e).lower() for e in errors)

    def test_null_bytes_stripped_from_password(self):
        """Null bytes should be stripped from password."""
        request = NoteCreateRequest(content="Test", password="Pass\x00word123")
        assert "\x00" not in request.password
        assert request.password == "Password123"

    def test_password_too_short_after_null_strip_rejected(self):
        """Password that becomes too short after null strip should be rejected."""
        with pytest.raises(ValidationError):
            # "short\x00\x00\x00" = "short" after strip = 5 chars < 8
            NoteCreateRequest(content="Test", password="short\x00\x00\x00")

    def test_valid_expiration_options(self):
        """All valid expiration options should be accepted."""
        for exp in ["1h", "24h", "7d", "burn"]:
            request = NoteCreateRequest(content="Test", expiration=exp)
            assert request.expiration.value == exp

    def test_invalid_expiration_rejected(self):
        """Invalid expiration option should be rejected."""
        with pytest.raises(ValidationError):
            NoteCreateRequest(content="Test", expiration="30d")

    def test_unicode_content_accepted(self):
        """Unicode content should be accepted."""
        request = NoteCreateRequest(content="秘密のメッセージ 🔐")
        assert request.content == "秘密のメッセージ 🔐"


class TestExpirationOption:
    """Tests for expiration option enum."""

    def test_all_options_defined(self):
        """All expected options should be defined."""
        assert ExpirationOption.ONE_HOUR.value == "1h"
        assert ExpirationOption.ONE_DAY.value == "24h"
        assert ExpirationOption.SEVEN_DAYS.value == "7d"
        assert ExpirationOption.BURN_AFTER_READ.value == "burn"

    def test_no_never_expires_option(self):
        """There should be no 'never expires' option."""
        values = [e.value for e in ExpirationOption]
        assert "never" not in values
        assert "infinite" not in values
        assert "0" not in values
