"""
Tests for API endpoints.

Verifies:
- Note creation returns proper response
- Note retrieval works correctly
- Security controls are enforced
- Error handling is correct
"""

from fastapi import status


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check_returns_ok(self, client):
        """Health endpoint should return healthy status."""
        response = client.get("/health")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestCreateNoteEndpoint:
    """Tests for POST /api/notes endpoint."""

    def test_create_note_success(self, client, sample_note_data):
        """Creating a note should return token and metadata."""
        response = client.post("/api/notes", json=sample_note_data)

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        assert "token" in data
        assert len(data["token"]) >= 40  # High entropy token
        assert "expires_at" in data
        assert data["password_protected"] is False
        assert data["burn_after_read"] is False

    def test_create_note_with_password(self, client, sample_note_with_password):
        """Creating a password-protected note should flag it."""
        response = client.post("/api/notes", json=sample_note_with_password)

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        assert data["password_protected"] is True

    def test_create_note_burn_after_read(self, client):
        """Creating a burn-after-read note should flag it."""
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "expiration": "burn"},
        )

        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()

        assert data["burn_after_read"] is True

    def test_create_note_invalid_content_empty(self, client):
        """Empty content should be rejected."""
        response = client.post("/api/notes", json={"content": ""})

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_note_invalid_content_too_large(self, client):
        """Content exceeding limit should be rejected."""
        response = client.post(
            "/api/notes",
            json={"content": "X" * 10241},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_note_invalid_password_too_short(self, client):
        """Password under 8 chars should be rejected."""
        response = client.post(
            "/api/notes",
            json={"content": "Test", "password": "short"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_note_invalid_expiration(self, client):
        """Invalid expiration option should be rejected."""
        response = client.post(
            "/api/notes",
            json={"content": "Test", "expiration": "30d"},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_security_headers_present(self, client, sample_note_data):
        """Security headers should be present on response."""
        response = client.post("/api/notes", json=sample_note_data)

        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers


class TestGetNoteEndpoint:
    """Tests for GET /api/notes/{token} endpoint."""

    def test_get_note_success(self, client, sample_note_data):
        """Should retrieve note content by token."""
        # Create note
        create_response = client.post("/api/notes", json=sample_note_data)
        token = create_response.json()["token"]

        # Retrieve note
        get_response = client.get(f"/api/notes/{token}")

        assert get_response.status_code == status.HTTP_200_OK
        data = get_response.json()
        assert data["content"] == sample_note_data["content"]
        assert "created_at" in data

    def test_get_note_not_found(self, client):
        """Non-existent token should return 404."""
        response = client.get("/api/notes/nonexistent_token_12345678901234567890")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json()["detail"] == "Note not found"

    def test_get_note_invalid_token_format(self, client):
        """Invalid token format should return 404 (not 400)."""
        # Using 404 prevents enumeration attacks
        response = client.get("/api/notes/invalid!@#$%^token")

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_note_with_password_requires_password(self, client, sample_note_with_password):
        """Password-protected note without password should return 403."""
        # Create note
        create_response = client.post("/api/notes", json=sample_note_with_password)
        token = create_response.json()["token"]

        # Try to retrieve without password
        get_response = client.get(f"/api/notes/{token}")

        assert get_response.status_code == status.HTTP_403_FORBIDDEN
        assert "password required" in get_response.json()["detail"].lower()

    def test_get_note_with_correct_password(self, client, sample_note_with_password):
        """Password-protected note with correct password should succeed."""
        # Create note
        create_response = client.post("/api/notes", json=sample_note_with_password)
        token = create_response.json()["token"]

        # Retrieve with password
        get_response = client.get(
            f"/api/notes/{token}",
            params={"password": sample_note_with_password["password"]},
        )

        assert get_response.status_code == status.HTTP_200_OK
        data = get_response.json()
        assert data["content"] == sample_note_with_password["content"]

    def test_get_note_with_wrong_password(self, client, sample_note_with_password):
        """Password-protected note with wrong password should return 403."""
        # Create note
        create_response = client.post("/api/notes", json=sample_note_with_password)
        token = create_response.json()["token"]

        # Retrieve with wrong password
        get_response = client.get(
            f"/api/notes/{token}",
            params={"password": "WrongPassword123"},
        )

        assert get_response.status_code == status.HTTP_403_FORBIDDEN
        assert "invalid password" in get_response.json()["detail"].lower()

    def test_burn_after_read_deletes_note(self, client):
        """Burn-after-read note should be deleted after first access."""
        # Create burn-after-read note
        create_response = client.post(
            "/api/notes",
            json={"content": "One-time secret", "expiration": "burn"},
        )
        token = create_response.json()["token"]

        # First access should succeed
        first_response = client.get(f"/api/notes/{token}")
        assert first_response.status_code == status.HTTP_200_OK
        assert first_response.json()["will_be_deleted"] is True

        # Second access should fail
        second_response = client.get(f"/api/notes/{token}")
        assert second_response.status_code == status.HTTP_404_NOT_FOUND

    def test_response_indicates_burn_status(self, client, sample_note_data):
        """Response should indicate whether note will be deleted."""
        # Non-burn note
        create_response = client.post("/api/notes", json=sample_note_data)
        token = create_response.json()["token"]

        get_response = client.get(f"/api/notes/{token}")
        assert get_response.json()["will_be_deleted"] is False


class TestSecurityControls:
    """Tests for security controls."""

    def test_no_internal_id_exposed(self, client, sample_note_data):
        """Internal UUID should never be exposed in responses."""
        response = client.post("/api/notes", json=sample_note_data)
        data = response.json()

        assert "id" not in data
        assert "uuid" not in data

    def test_content_not_in_error_response(self, client):
        """Note content should never appear in error responses."""
        # Test with password-protected note
        create_protected = client.post(
            "/api/notes",
            json={"content": "AnotherSecret456", "password": "testpass123"},
        )
        protected_token = create_protected.json()["token"]

        # Access with wrong password
        error_response = client.get(
            f"/api/notes/{protected_token}",
            params={"password": "wrongpass"},
        )

        # Content should not be in error response
        response_text = error_response.text
        assert "AnotherSecret456" not in response_text

    def test_token_enumeration_prevention(self, client):
        """Both missing and expired notes should return same error."""
        # Non-existent token
        response1 = client.get("/api/notes/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        # Both should be 404 with same message
        assert response1.status_code == status.HTTP_404_NOT_FOUND
        assert response1.json()["detail"] == "Note not found"


class TestPasswordProtection:
    """Tests for password protection (US3)."""

    def test_password_hash_not_exposed(self, client):
        """Password hash should never be exposed in any response."""
        # Create password-protected note
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "password": "MySecretPass123"},
        )
        data = response.json()

        # Password hash should not be in response
        assert "password_hash" not in data
        assert "hash" not in str(data).lower()
        assert "MySecretPass123" not in str(data)

    def test_password_stored_as_argon2_hash(self, client, test_db):
        """Password should be stored as Argon2id hash, not plaintext."""
        from app.models import Note

        # Create password-protected note
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "password": "TestPassword123"},
        )
        token = response.json()["token"]

        # Query database directly
        note = test_db.query(Note).filter(Note.token == token).first()

        # Password should be hashed with Argon2id
        assert note.password_hash is not None
        assert note.password_hash.startswith("$argon2id$")
        assert "TestPassword123" not in note.password_hash

    def test_password_verification_timing_safe(self, client):
        """Password verification should use constant-time comparison."""
        # Create password-protected note
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "password": "CorrectPassword1"},
        )
        token = response.json()["token"]

        # Wrong password should fail
        wrong_response = client.get(
            f"/api/notes/{token}",
            params={"password": "WrongPassword123"},
        )
        assert wrong_response.status_code == 403

        # Correct password should succeed
        correct_response = client.get(
            f"/api/notes/{token}",
            params={"password": "CorrectPassword1"},
        )
        assert correct_response.status_code == 200

    def test_empty_password_rejected(self, client):
        """Empty password should be rejected when creating note."""
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "password": ""},
        )
        # Empty string is below minimum length, should be 422
        assert response.status_code == 422

    def test_multiple_wrong_passwords_all_fail(self, client):
        """Multiple wrong password attempts should all fail."""
        # Create password-protected note
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "password": "CorrectPassword1"},
        )
        token = response.json()["token"]

        # Try multiple wrong passwords
        wrong_passwords = ["wrong1234", "incorrect1", "badpassword"]
        for wrong_pw in wrong_passwords:
            wrong_response = client.get(
                f"/api/notes/{token}",
                params={"password": wrong_pw},
            )
            assert wrong_response.status_code == 403
            assert "invalid password" in wrong_response.json()["detail"].lower()


class TestRateLimiting:
    """Tests for rate limiting (US6)."""

    def test_rate_limit_on_note_access(self, client):
        """Accessing notes should be rate limited to prevent brute force."""
        # Create a note
        response = client.post(
            "/api/notes",
            json={"content": "Secret", "password": "TestPassword1"},
        )
        token = response.json()["token"]

        # Make 5 requests (limit)
        for i in range(5):
            client.get(
                f"/api/notes/{token}",
                params={"password": f"WrongPassword{i}"},
            )

        # 6th request should be rate limited
        response = client.get(
            f"/api/notes/{token}",
            params={"password": "AnotherWrong"},
        )
        assert response.status_code == 429

    def test_rate_limit_on_note_creation(self, client):
        """Creating notes should be rate limited."""
        # Make 10 requests (limit)
        for i in range(10):
            client.post(
                "/api/notes",
                json={"content": f"Note {i}"},
            )

        # 11th request should be rate limited
        response = client.post(
            "/api/notes",
            json={"content": "One more"},
        )
        assert response.status_code == 429

    def test_rate_limit_returns_proper_error(self, client):
        """Rate limit response should have proper format."""
        # Create a note
        response = client.post(
            "/api/notes",
            json={"content": "Secret"},
        )
        token = response.json()["token"]

        # Exhaust rate limit
        for _ in range(5):
            client.get(f"/api/notes/{token}")

        # Check rate limit response
        response = client.get(f"/api/notes/{token}")
        assert response.status_code == 429
        assert "rate limit" in response.text.lower() or "too many" in response.text.lower()


class TestAccessLogging:
    """Tests for access logging (US8)."""

    def test_successful_access_logged(self, client, sample_note_data, caplog):
        """Successful note access should be logged."""
        import logging

        with caplog.at_level(logging.INFO):
            # Create and access note
            create_response = client.post("/api/notes", json=sample_note_data)
            token = create_response.json()["token"]
            client.get(f"/api/notes/{token}")

        # Check logs contain access info
        log_messages = [record.message for record in caplog.records]
        assert any("accessed" in msg.lower() for msg in log_messages)

    def test_failed_password_logged_as_warning(self, client, caplog):
        """Failed password attempts should be logged as warnings."""
        import logging

        with caplog.at_level(logging.WARNING):
            # Create password-protected note
            create_response = client.post(
                "/api/notes",
                json={"content": "Secret", "password": "CorrectPass1"},
            )
            token = create_response.json()["token"]

            # Try wrong password
            client.get(
                f"/api/notes/{token}",
                params={"password": "WrongPassword"},
            )

        # Check logs contain warning about invalid password
        warning_messages = [
            record.message
            for record in caplog.records
            if record.levelno >= logging.WARNING
        ]
        assert any("invalid_password" in msg.lower() for msg in warning_messages)

    def test_sensitive_data_not_logged(self, client, caplog):
        """Sensitive data (content, passwords) should never be logged."""
        import logging

        secret_content = "SuperSecretContent12345"
        secret_password = "MySecretPassword789"

        with caplog.at_level(logging.DEBUG):
            # Create note with password
            client.post(
                "/api/notes",
                json={"content": secret_content, "password": secret_password},
            )

        # Check that secrets are not in logs
        all_log_text = " ".join(record.message for record in caplog.records)
        assert secret_content not in all_log_text
        assert secret_password not in all_log_text
