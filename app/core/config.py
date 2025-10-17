# =============================================================================================
# APP/CORE/CONFIG.PY - CENTRALIZED CONFIGURATION WITH PYDANTIC SETTINGS
# =============================================================================================
# This module provides a type-safe, environment-driven configuration system using Pydantic.
#
# WHY PYDANTIC SETTINGS?
# - Automatic type validation and parsing (e.g., "900" string → 900 int)
# - Single source of truth for all environment variables
# - Clear error messages if required vars are missing
# - IDE autocomplete for settings across the entire codebase
# - Easy to test (override settings in tests without touching env vars)
#
# FLOW:
# 1. Docker Compose loads .env → container environment
# 2. This Settings class reads from os.environ at startup
# 3. FastAPI instantiates settings once (cached via @lru_cache)
# 4. Import get_settings() anywhere to access validated config
# =============================================================================================

from functools import lru_cache  # Cache settings instance (load once, reuse everywhere)
from pydantic_settings import BaseSettings, SettingsConfigDict


# -------------------------
# Settings class - Defines all configuration with types and defaults
# -------------------------
class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    Pydantic automatically:
    - Reads from environment variables matching these field names
    - Converts strings to the declared types (int, bool, etc.)
    - Validates required fields exist (raises error if missing)
    - Provides defaults for optional fields

    USAGE EXAMPLE:
        from app.core.config import get_settings
        settings = get_settings()
        print(settings.DATABASE_URL)  # Type: str, autocomplete works!
    """

    # -------------------------
    # DATABASE CONFIGURATION
    # -------------------------
    # SQLAlchemy connection string for SQLite
    # Format: sqlite:///./dev.db (relative path, creates file in project root)
    # For async support: sqlite+aiosqlite:///./dev.db
    DATABASE_URL: str = "sqlite:///./dev.db"

    # -------------------------
    # JWT (JSON WEB TOKEN) SETTINGS
    # -------------------------
    # Secret key for signing/verifying JWT tokens
    # CRITICAL: Must be kept secret! Compromise = attackers can forge tokens
    # Generate: openssl rand -hex 32
    JWT_SECRET: str

    # Algorithm used for JWT signing (HS256 = HMAC with SHA-256)
    # Don't change this unless you have a specific reason (e.g., switching to RS256 with public/private keys)
    JWT_ALGORITHM: str = "HS256"

    # How long access tokens are valid (in seconds)
    # Short-lived for security: if stolen, attacker has limited time
    # Default: 900s = 15 minutes
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 900

    # How long refresh tokens are valid (in seconds)
    # Longer-lived: users don't need to log in constantly
    # Default: 2592000s = 30 days
    REFRESH_TOKEN_EXPIRE_SECONDS: int = 2592000

    # -------------------------
    # PASSWORD HASHING (BCRYPT)
    # -------------------------
    # Cost factor for bcrypt hashing (higher = slower but more secure)
    # Each increment doubles computation time:
    #   10 → ~100ms per hash
    #   12 → ~400ms per hash (recommended for production)
    #   14 → ~1.6s per hash (high security, might slow down login)
    # Protects against brute-force attacks: attackers must spend the same time per guess
    BCRYPT_ROUNDS: int = 12

    # -------------------------
    # MINIO / S3 STORAGE SETTINGS
    # -------------------------
    STORAGE_ENDPOINT: str = "http://minio:9000"
    STORAGE_ACCESS_KEY: str = "miniouser"
    STORAGE_SECRET_KEY: str = "miniopassword123"
    STORAGE_BUCKET: str = "uploads"
    STORAGE_REGION: str = "us-east-1"

    # -------------------------
    # Pydantic configuration
    # -------------------------
    # Tell Pydantic where to find settings and how to behave
    model_config = SettingsConfigDict(
        # Read from .env file if present (useful for local dev without Docker)
        env_file=".env",
        # Don't fail if .env is missing (rely on environment variables from Docker)
        env_file_encoding="utf-8",
        # Allow extra fields in .env without validation errors
        extra="ignore",
    )


# -------------------------
# Cached settings instance - Load once, reuse everywhere
# -------------------------
@lru_cache
def get_settings() -> Settings:
    """
    Returns a singleton Settings instance (cached after first call).

    WHY CACHE?
    - Settings don't change during runtime (only on app restart)
    - Avoids re-reading environment variables on every request
    - Improves performance (dict lookup vs. file I/O)

    USAGE:
        from app.core.config import get_settings
        settings = get_settings()
        db_url = settings.DATABASE_URL

    TESTING:
    To override settings in tests, clear the cache and set env vars:
        get_settings.cache_clear()
        monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
        settings = get_settings()  # Now uses test database
    """
    return Settings()
