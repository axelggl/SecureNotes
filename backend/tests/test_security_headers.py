"""
Tests for security headers (US10).

Verifies all OWASP-recommended security headers are present and correctly configured.
"""

from fastapi import status


class TestSecurityHeaders:
    """Tests for security headers on all responses."""

    def test_content_security_policy_present(self, client):
        """CSP header should be present and restrictive."""
        response = client.get("/health")

        assert "Content-Security-Policy" in response.headers
        csp = response.headers["Content-Security-Policy"]

        # Verify key directives
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_x_content_type_options(self, client):
        """X-Content-Type-Options should be nosniff."""
        response = client.get("/health")

        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"

    def test_x_frame_options(self, client):
        """X-Frame-Options should be DENY."""
        response = client.get("/health")

        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"

    def test_strict_transport_security(self, client):
        """HSTS header should be present with long max-age."""
        response = client.get("/health")

        assert "Strict-Transport-Security" in response.headers
        hsts = response.headers["Strict-Transport-Security"]

        # Should have at least 1 year max-age
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts

    def test_referrer_policy(self, client):
        """Referrer-Policy should be no-referrer."""
        response = client.get("/health")

        assert "Referrer-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "no-referrer"

    def test_x_xss_protection(self, client):
        """X-XSS-Protection should be enabled."""
        response = client.get("/health")

        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"

    def test_cache_control_no_store(self, client):
        """Cache-Control should prevent caching of API responses."""
        response = client.get("/health")

        assert "Cache-Control" in response.headers
        cache_control = response.headers["Cache-Control"]

        assert "no-store" in cache_control
        assert "no-cache" in cache_control

    def test_pragma_no_cache(self, client):
        """Pragma header should be no-cache for legacy compatibility."""
        response = client.get("/health")

        assert "Pragma" in response.headers
        assert response.headers["Pragma"] == "no-cache"

    def test_headers_on_post_request(self, client):
        """Security headers should be present on POST responses."""
        response = client.post(
            "/api/notes",
            json={"content": "Test note"},
        )

        # Verify key headers on POST response
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers

    def test_headers_on_error_response(self, client):
        """Security headers should be present on error responses."""
        response = client.get("/api/notes/nonexistent_token_1234567890123")

        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Verify headers still present on error
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers

    def test_headers_on_rate_limited_response(self, client):
        """Security headers should be present on rate-limited responses."""
        # Create a note first
        create_response = client.post(
            "/api/notes",
            json={"content": "Test"},
        )
        token = create_response.json()["token"]

        # Exhaust rate limit (5 requests)
        for _ in range(5):
            client.get(f"/api/notes/{token}")

        # 6th request should be rate limited
        response = client.get(f"/api/notes/{token}")

        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Verify headers still present
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"


class TestCSPDirectives:
    """Detailed tests for Content-Security-Policy directives."""

    def test_csp_default_src_self(self, client):
        """CSP default-src should only allow same origin."""
        response = client.get("/health")
        csp = response.headers["Content-Security-Policy"]

        assert "default-src 'self'" in csp

    def test_csp_script_src_self(self, client):
        """CSP script-src should only allow same origin scripts."""
        response = client.get("/health")
        csp = response.headers["Content-Security-Policy"]

        assert "script-src 'self'" in csp
        # Should not allow unsafe-inline for scripts
        assert "script-src 'unsafe-inline'" not in csp

    def test_csp_frame_ancestors_none(self, client):
        """CSP frame-ancestors should prevent embedding."""
        response = client.get("/health")
        csp = response.headers["Content-Security-Policy"]

        assert "frame-ancestors 'none'" in csp

    def test_csp_form_action_self(self, client):
        """CSP form-action should only allow same origin."""
        response = client.get("/health")
        csp = response.headers["Content-Security-Policy"]

        assert "form-action 'self'" in csp
