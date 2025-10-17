# =============================================================================================
# APP/MODELS/TOKEN.PY - REFRESH TOKEN DATABASE MODEL
# =============================================================================================
# This module defines the RefreshToken table for storing hashed refresh tokens.
#
# WHY STORE REFRESH TOKENS IN DATABASE?
# - Server-side revocation (logout, security breach, device removal)
# - Token rotation (issue new token, invalidate old one)
# - Audit trail (when/where tokens were issued)
# - Security: If DB shows revoked=True, reject token even if JWT signature is valid
#
# SECURITY MODEL:
# - Store hash (not raw token) → DB breach doesn't leak usable tokens
# - Associate with user_id → quick lookup of all user's sessions
# - Track expiration → cleanup old tokens, prevent long-lived sessions
# - Revocation flag → instant logout across all clients
#
# TOKEN ROTATION FLOW:
# 1. Client sends refresh token to /auth/refresh
# 2. Server finds token in DB by hash
# 3. If not revoked and not expired, issue new token pair
# 4. Mark old token as revoked (one-time use)
# 5. Store new refresh token hash in DB
# =============================================================================================

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.core.db import Base


# -------------------------
# RefreshToken model - Maps to "refresh_tokens" table
# -------------------------
class RefreshToken(Base):
    """
    Refresh token model for JWT token rotation and revocation.

    DATABASE TABLE (SQLite):
        CREATE TABLE refresh_tokens (
            id VARCHAR(36) PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash VARCHAR(64) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL
        );
        CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id);
        CREATE INDEX ix_refresh_tokens_token_hash ON refresh_tokens (token_hash);
        CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at);

    COLUMNS EXPLAINED:
    - id: UUID stored as string (unique identifier for each token record)
    - user_id: Foreign key to users table (who owns this token)
    - token_hash: SHA-256 hash of the refresh token JWT (64 hex chars)
    - expires_at: When this token becomes invalid (typically 30 days)
    - revoked: Whether token has been invalidated (logout, rotation, breach)
    - created_at: When token was issued (for audit logs)

    WHY HASH THE TOKEN?
    - Raw JWT is long-lived (30 days) and powerful (can get new access tokens)
    - If database is compromised, attacker gets hashes (not usable tokens)
    - Similar to password hashing, but SHA-256 is sufficient (tokens are high-entropy)

    INDEXES EXPLAINED:
    - user_id: Find all tokens for a user (for "logout all devices")
    - token_hash: Lookup token during /auth/refresh (must be fast!)
    - expires_at: Cleanup queries (delete expired tokens periodically)

    USAGE EXAMPLES:
        # Store new refresh token
        token_hash = hash_refresh_token(jwt_token)
        db_token = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db.add(db_token)
        db.commit()

        # Validate refresh token
        token_hash = hash_refresh_token(client_token)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        ).first()

        # Revoke token (logout)
        db_token.revoked = True
        db.commit()

        # Revoke all user tokens (logout all devices)
        db.query(RefreshToken).filter(RefreshToken.user_id == user.id).update({"revoked": True})
        db.commit()
    """

    # -------------------------
    # Table name in SQLite database
    # -------------------------
    __tablename__ = "refresh_tokens"

    # -------------------------
    # COLUMN 1: Primary key (UUID as string)
    # -------------------------
    # Auto-generated unique identifier for each token record
    # Not the same as the JWT token itself (which is hashed and stored in token_hash)
    # SQLite stores UUID as VARCHAR(36) string
    id: str = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
        nullable=False,
        comment="Unique identifier for this token record",
    )

    # -------------------------
    # COLUMN 2: User ID (foreign key)
    # -------------------------
    # ForeignKey("users.id") creates a constraint:
    # - This user_id must exist in users.id
    # - Prevents orphaned tokens (tokens for deleted users)
    # ondelete="CASCADE" means:
    # - If user is deleted, all their tokens are auto-deleted
    # - Cleanup happens at database level (reliable even if app crashes)
    #
    # ALTERNATIVE: Use ondelete="SET NULL" if you want to keep audit trail
    # NOTE: SQLite stores UUID as VARCHAR(36) string
    user_id: str = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),  # Delete tokens when user is deleted
        nullable=False,
        index=True,  # Index for fast "find all user's tokens" queries
        comment="User who owns this refresh token",
    )

    # -------------------------
    # COLUMN 3: Token hash (SHA-256)
    # -------------------------
    # SHA-256 hex digest is always 64 characters:
    #   hashlib.sha256(token.encode()).hexdigest()
    #   → "a3f2b4c8d9e1f7a6b5c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1"
    #
    # WHY NOT BCRYPT?
    # - Refresh tokens are already random (200+ char JWT)
    # - No brute force risk (can't guess a 200-char random string)
    # - SHA-256 is fast and sufficient for high-entropy data
    # - Bcrypt is for low-entropy user passwords
    #
    # WHY HASH AT ALL?
    # - Defense in depth: even if DB is breached, tokens are useless
    # - Similar to not storing plaintext passwords
    # - Best practice for storing sensitive credentials
    token_hash: str = Column(
        String(64),  # SHA-256 hex digest is exactly 64 chars
        nullable=False,
        unique=True,  # Each token hash must be unique
        index=True,  # Index for fast lookup during /auth/refresh
        comment="SHA-256 hash of the refresh token JWT",
    )

    # -------------------------
    # COLUMN 4: Expiration timestamp
    # -------------------------
    # When this token becomes invalid (typically 30 days from creation)
    # Server checks: if expires_at < now, reject the token
    # Cleanup job: DELETE FROM refresh_tokens WHERE expires_at < now
    #
    # WHY STORE EXPIRATION?
    # - JWT also has exp claim, but we can't trust client
    # - Database is source of truth for revocation and expiration
    # - Allows changing expiration policy without invalidating existing tokens
    # NOTE: SQLite stores datetime as ISO 8601 string
    expires_at: datetime = Column(
        DateTime,
        nullable=False,
        index=True,  # Index for cleanup queries and expiration checks
        comment="When this token expires (UTC timezone)",
    )

    # -------------------------
    # COLUMN 5: Revocation flag
    # -------------------------
    # True = token has been invalidated (logout, rotation, security breach)
    # False = token is still valid (can be used to get new access token)
    #
    # REVOCATION SCENARIOS:
    # - User clicks "logout" → revoke current token
    # - User clicks "logout all devices" → revoke all user's tokens
    # - Token rotation (after /auth/refresh) → revoke old token
    # - Security breach detected → revoke all tokens for affected users
    # - Password change → revoke all tokens (force re-login)
    #
    # WHY NOT DELETE?
    # - Keep audit trail (when/where token was used)
    # - Can see "user had 5 sessions, revoked 3, expired 1, active 1"
    # - Helps with security investigations
    revoked: bool = Column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether this token has been revoked (logout, rotation, etc.)",
    )

    # -------------------------
    # COLUMN 6: Creation timestamp
    # -------------------------
    # When this token was issued (for audit logs and analytics)
    # SQLite stores datetime as ISO 8601 string
    created_at: datetime = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        comment="When this token was issued (UTC timezone)",
    )

    # -------------------------
    # Relationships (ORM navigation)
    # -------------------------
    # Allows navigating from RefreshToken → User:
    #   token.user.email
    # And from User → RefreshToken:
    #   user.refresh_tokens  # List of all user's tokens
    #
    # back_populates creates bidirectional relationship:
    # - RefreshToken.user → User object
    # - User.refresh_tokens → list of RefreshToken objects
    #
    # lazy="select" means:
    # - Don't load related data automatically (avoid N+1 queries)
    # - Load on first access: token.user triggers SELECT
    # - Alternative: lazy="joined" (always JOIN), lazy="subquery" (use subquery)
    user = relationship(
        "User",
        back_populates="refresh_tokens",
        lazy="select",
    )

    # -------------------------
    # Additional indexes for query performance
    # -------------------------
    # Composite index for common query: "find non-revoked, non-expired tokens for user"
    # Single index can be used for queries filtering on user_id, or user_id + expires_at
    __table_args__ = (
        Index("ix_refresh_tokens_user_expires", "user_id", "expires_at"),
    )

    # -------------------------
    # String representation (for debugging)
    # -------------------------
    def __repr__(self) -> str:
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"


# -------------------------
# Add relationship to User model
# -------------------------
# This must be added to the User class in user.py:
#   from sqlalchemy.orm import relationship
#   class User(Base):
#       ...
#       refresh_tokens = relationship("RefreshToken", back_populates="user", lazy="select")
#
# This creates the bidirectional relationship between User and RefreshToken
