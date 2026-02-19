"""
SafeNotes FastAPI Application.

Security features:
- Security headers on all responses
- Rate limiting per IP
- CORS restrictions
- Input validation
- Structured logging
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings
from app.routes import limiter, router as notes_router
from app.schemas import HealthResponse

# Frontend directory path
FRONTEND_DIR = Path(__file__).parent.parent.parent / "frontend"

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    # Startup
    logger.info(f"SafeNotes starting in {settings.app_env} mode")

    # Create database tables (in production, use migrations)
    from app.database import engine
    from app.models import Base

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")

    # Start scheduler for cleanup (only in production/staging)
    if settings.app_env in ("production", "staging"):
        from app.scheduler import start_scheduler

        start_scheduler(interval_minutes=5)
        logger.info("Cleanup scheduler started")

    yield

    # Shutdown
    if settings.app_env in ("production", "staging"):
        from app.scheduler import stop_scheduler

        stop_scheduler()

    logger.info("SafeNotes shutting down")


# Create FastAPI application
app = FastAPI(
    title="SafeNotes API",
    description="Secure one-time note sharing service",
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,  # Disable docs in production
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan,
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    # Content Security Policy - strict
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Enable HSTS (1 year)
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )

    # Control referrer information
    response.headers["Referrer-Policy"] = "no-referrer"

    # Prevent XSS (legacy, but still useful)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Disable caching for API responses
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    return response


# CORS configuration - restrict to same origin in production
if settings.is_production:
    allowed_origins = []  # No cross-origin in production
else:
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# Global exception handler (prevent info leakage)
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions without leaking information."""
    logger.exception(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# Health check endpoint (no rate limit)
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["system"],
)
async def health_check() -> HealthResponse:
    """Health check endpoint for monitoring."""
    return HealthResponse(status="healthy", version="1.0.0")


# Include API routes with rate limiting
app.include_router(notes_router)


# Apply rate limiting to notes endpoints
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to sensitive endpoints."""
    # Rate limit only applies to /api/notes paths
    if request.url.path.startswith("/api/notes"):
        # The limiter decorator handles this, but we log attempts
        client_ip = get_remote_address(request)
        logger.debug(f"Request from {client_ip} to {request.url.path}")

    return await call_next(request)


# Serve static frontend files if the directory exists
if FRONTEND_DIR.exists():
    # Mount static files (CSS, JS)
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        """Serve the main frontend page."""
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/style.css", include_in_schema=False)
    async def serve_css():
        """Serve CSS file."""
        return FileResponse(
            FRONTEND_DIR / "style.css",
            media_type="text/css"
        )

    @app.get("/app.js", include_in_schema=False)
    async def serve_js():
        """Serve JavaScript file."""
        return FileResponse(
            FRONTEND_DIR / "app.js",
            media_type="application/javascript"
        )

    @app.get("/note/{token}", include_in_schema=False)
    async def serve_note_page(token: str):
        """Serve the frontend for note access (SPA routing)."""
        return FileResponse(FRONTEND_DIR / "index.html")
