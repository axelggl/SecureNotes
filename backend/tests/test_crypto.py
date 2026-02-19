"""
Tests for cryptographic utilities.

Verifies:
- AES-256-GCM encryption/decryption
- Key generation
- Token generation
- Error handling
"""

import base64

import pytest

from app.crypto import CryptoError, NoteCrypto, generate_secure_token


class TestNoteCrypto:
    """Tests for NoteCrypto class."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted content should decrypt to original plaintext."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        plaintext = "Secret message for testing!"
        ciphertext = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_produces_different_ciphertext(self):
        """Each encryption should produce different ciphertext (unique IV)."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        plaintext = "Same message"
        ciphertext1 = crypto.encrypt(plaintext)
        ciphertext2 = crypto.encrypt(plaintext)

        # Ciphertexts should differ due to random IV
        assert ciphertext1 != ciphertext2

        # But both should decrypt to same plaintext
        assert crypto.decrypt(ciphertext1) == plaintext
        assert crypto.decrypt(ciphertext2) == plaintext

    def test_decrypt_with_wrong_key_fails(self):
        """Decryption with wrong key should raise CryptoError."""
        key1 = NoteCrypto.generate_key()
        key2 = NoteCrypto.generate_key()
        crypto1 = NoteCrypto(key1)
        crypto2 = NoteCrypto(key2)

        plaintext = "Secret message"
        ciphertext = crypto1.encrypt(plaintext)

        with pytest.raises(CryptoError) as exc_info:
            crypto2.decrypt(ciphertext)

        assert "invalid key or tampered" in str(exc_info.value).lower()

    def test_decrypt_tampered_ciphertext_fails(self):
        """Tampered ciphertext should fail authentication."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        plaintext = "Secret message"
        ciphertext = crypto.encrypt(plaintext)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF  # Flip bits in auth tag
        tampered = bytes(tampered)

        with pytest.raises(CryptoError):
            crypto.decrypt(tampered)

    def test_invalid_key_length_raises_error(self):
        """Key must be exactly 32 bytes."""
        with pytest.raises(CryptoError) as exc_info:
            NoteCrypto(b"short_key")

        assert "32 bytes" in str(exc_info.value)

    def test_invalid_key_type_raises_error(self):
        """Key must be bytes."""
        with pytest.raises(CryptoError):
            NoteCrypto("not_bytes")

    def test_from_base64_key(self):
        """Should create instance from base64-encoded key."""
        key = NoteCrypto.generate_key()
        key_b64 = base64.b64encode(key).decode()

        crypto = NoteCrypto.from_base64_key(key_b64)

        plaintext = "Test message"
        ciphertext = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_from_invalid_base64_key_raises_error(self):
        """Invalid base64 key should raise CryptoError."""
        with pytest.raises(CryptoError) as exc_info:
            NoteCrypto.from_base64_key("invalid!!!base64")

        assert "invalid" in str(exc_info.value).lower()

    def test_generate_key_returns_32_bytes(self):
        """Generated key should be 32 bytes."""
        key = NoteCrypto.generate_key()
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_key_is_random(self):
        """Generated keys should be unique."""
        keys = [NoteCrypto.generate_key() for _ in range(10)]
        # All keys should be unique
        assert len(set(keys)) == 10

    def test_generate_key_base64(self):
        """Should generate valid base64-encoded key."""
        key_b64 = NoteCrypto.generate_key_base64()

        # Should be valid base64
        key = base64.b64decode(key_b64)
        assert len(key) == 32

    def test_encrypt_empty_string(self):
        """Empty string should encrypt/decrypt correctly."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        # Note: Our schema rejects empty content, but crypto should handle it
        plaintext = ""
        ciphertext = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_unicode_content(self):
        """Unicode content should encrypt/decrypt correctly."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        plaintext = "Secret 秘密 🔐 émojis!"
        ciphertext = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_encrypt_large_content(self):
        """Large content should encrypt/decrypt correctly."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        plaintext = "X" * 10000  # 10KB
        ciphertext = crypto.encrypt(plaintext)
        decrypted = crypto.decrypt(ciphertext)

        assert decrypted == plaintext

    def test_ciphertext_too_short_raises_error(self):
        """Ciphertext shorter than IV + tag should fail."""
        key = NoteCrypto.generate_key()
        crypto = NoteCrypto(key)

        with pytest.raises(CryptoError) as exc_info:
            crypto.decrypt(b"short")

        assert "too short" in str(exc_info.value).lower()


class TestGenerateSecureToken:
    """Tests for secure token generation."""

    def test_default_token_length(self):
        """Default token should have sufficient length."""
        token = generate_secure_token()
        # 32 bytes = ~43 base64url characters
        assert len(token) >= 40

    def test_custom_token_length(self):
        """Custom length tokens should work."""
        token = generate_secure_token(16)
        # 16 bytes = ~22 base64url characters
        assert len(token) >= 20

    def test_tokens_are_unique(self):
        """Generated tokens should be unique."""
        tokens = [generate_secure_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_token_is_url_safe(self):
        """Token should only contain URL-safe characters."""
        for _ in range(10):
            token = generate_secure_token()
            # URL-safe base64 uses alphanumeric + '-' and '_'
            assert all(c.isalnum() or c in "-_" for c in token)
