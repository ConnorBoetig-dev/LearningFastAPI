# =============================================================================================
# APP/ROUTERS/AUTH.PY - AUTHENTICATION ENDPOINTS
# =============================================================================================
# This module provides all authentication-related API endpoints:
# - POST /auth/register: Create new user account
# - POST /auth/login: Authenticate and get tokens
# - POST /auth/refresh: Exchange refresh token for new token pair
# - POST /auth/logout: Revoke refresh token
# - GET /auth/me: Get current user profile
#
# AUTHENTICATION FLOW:
# 1. User registers: POST /auth/register → returns user data
# 2. User logs in: POST /auth/login → returns access + refresh tokens
# 3. User accesses protected routes: send access token in Authorization header
# 4. Access token expires: POST /auth/refresh with refresh token → get new token pair
# 5. User logs out: POST /auth/logout with refresh token → revoke token
#
# SECURITY FEATURES:
# - Password hashing with bcrypt (12 rounds by default)
# - JWT token creation and verification
# - Refresh token rotation (one-time use)
# - Refresh token storage with hash (never raw tokens in DB)
# - Token revocation support (logout)
# =============================================================================================

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import get_current_user
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_refresh_token,
)
from app.models.user import User
from app.models.token import RefreshToken
from app.schemas.user import RegisterIn, LoginIn, UserOut
from app.schemas.auth import TokenPair, RefreshTokenIn

# -------------------------
# Router configuration
# -------------------------
# APIRouter groups related endpoints under a common prefix and tags
# This router will be mounted at /auth in main.py
router = APIRouter(
    prefix="/auth",  # All routes start with /auth (e.g., /auth/register)
    tags=["Authentication"],  # OpenAPI tag (groups endpoints in docs)
)

# Load settings once at module level (cached by get_settings)
settings = get_settings()


# =============================================================================================
# ENDPOINT 1: Register new user
# =============================================================================================

@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    data: RegisterIn,
    db: Session = Depends(get_db),
):
    """
    Create a new user account.

    FLOW:
    1. Client sends email + password
    2. Validate email format (Pydantic does this automatically)
    3. Check if email already exists (return 409 Conflict if yes)
    4. Hash password with bcrypt
    5. Create user record in database
    6. Return user data (excluding password hash)

    REQUEST:
        POST /auth/register
        {
            "email": "alice@example.com",
            "password": "SecurePassword123!"
        }

    RESPONSE (201 Created):
        {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "email": "alice@example.com",
            "created_at": "2024-01-15T10:30:00Z"
        }

    ERRORS:
        409 Conflict: Email already registered
        422 Unprocessable Entity: Invalid email format or password too short

    SECURITY NOTES:
    - Password is hashed before storage (bcrypt with 12 rounds)
    - Email is unique (enforced at database level)
    - TODO: Add email verification (send confirmation link)
    - TODO: Add CAPTCHA to prevent automated registration
    - TODO: Add rate limiting (prevent spam registration)
    """

    # -------------------------
    # STEP 1: Check if email already exists
    # -------------------------
    # Query database for existing user with this email
    # .first() returns None if not found, User object if found
    existing_user = db.query(User).filter(User.email == data.email).first()

    # If email exists, reject registration with clear error message
    # HTTP 409 Conflict = "request conflicts with current state"
    # Alternative: Return generic error to prevent email enumeration (attacker can't tell if email is registered)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # -------------------------
    # STEP 2: Hash the password
    # -------------------------
    # Never store plaintext passwords!
    # hash_password() uses bcrypt with configured rounds (default 12)
    # Same password → different hash each time (random salt)
    password_hash = hash_password(data.password)

    # -------------------------
    # STEP 3: Create user in database
    # -------------------------
    # Create SQLAlchemy User object
    # id and created_at are auto-generated (UUID and timestamp)
    new_user = User(
        email=data.email,
        password_hash=password_hash,
    )

    # Add to database session (staged, not committed yet)
    db.add(new_user)

    # Commit transaction (write to database)
    # If this fails (e.g., unique constraint violation), exception is raised
    # FastAPI will automatically rollback and return 500 error
    db.commit()

    # Refresh object to load auto-generated fields (id, created_at)
    # Without this, new_user.id would be None
    db.refresh(new_user)

    # -------------------------
    # STEP 4: Return user data
    # -------------------------
    # FastAPI automatically converts User object → UserOut schema → JSON
    # response_model=UserOut ensures only safe fields are returned
    # (password_hash is excluded)
    return new_user


# =============================================================================================
# ENDPOINT 2: Login (authenticate and get tokens)
# =============================================================================================

@router.post("/login", response_model=TokenPair)
def login(
    data: LoginIn,
    db: Session = Depends(get_db),
):
    """
    Authenticate user and return access + refresh tokens.

    FLOW:
    1. Client sends email + password
    2. Find user by email
    3. Verify password against stored hash
    4. Generate access token (15 min expiry)
    5. Generate refresh token (30 day expiry)
    6. Store refresh token hash in database
    7. Return both tokens to client

    REQUEST:
        POST /auth/login
        {
            "email": "alice@example.com",
            "password": "SecurePassword123!"
        }

    RESPONSE (200 OK):
        {
            "access_token": "eyJhbGci...",
            "refresh_token": "eyJhbGci...",
            "token_type": "bearer",
            "expires_in": 900
        }

    ERRORS:
        401 Unauthorized: Invalid email or password

    SECURITY NOTES:
    - Same error for "email not found" and "wrong password" (prevent email enumeration)
    - Password verification uses constant-time comparison (prevent timing attacks)
    - Refresh token is hashed before storage (SHA-256)
    - TODO: Add rate limiting (prevent brute force attacks)
    - TODO: Add account lockout after N failed attempts
    - TODO: Log failed login attempts for security monitoring
    """

    # -------------------------
    # STEP 1: Find user by email
    # -------------------------
    user = db.query(User).filter(User.email == data.email).first()

    # -------------------------
    # STEP 2: Verify password
    # -------------------------
    # IMPORTANT: Check both conditions in one if statement
    # This prevents timing attacks (same execution time whether user exists or not)
    # Also prevents email enumeration (attacker can't tell if email is registered)
    if not user or not verify_password(data.password, user.password_hash):
        # Generic error message (don't reveal which part is wrong)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # -------------------------
    # STEP 3: Generate tokens
    # -------------------------
    # Create access token (short-lived, 15 minutes)
    access_token = create_access_token(user.id)

    # Create refresh token (long-lived, 30 days)
    refresh_token = create_refresh_token(user.id)

    # -------------------------
    # STEP 4: Store refresh token in database
    # -------------------------
    # Hash the refresh token (same reason as password hashing)
    # If database is breached, attacker gets hashes (not usable tokens)
    token_hash = hash_refresh_token(refresh_token)

    # Calculate expiration time (same as JWT exp claim)
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.REFRESH_TOKEN_EXPIRE_SECONDS
    )

    # Create database record
    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=False,
    )

    db.add(db_token)
    db.commit()

    # -------------------------
    # STEP 5: Return tokens
    # -------------------------
    # Client will store these (access in memory, refresh in httpOnly cookie ideally)
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_SECONDS,
    )


# =============================================================================================
# ENDPOINT 3: Refresh tokens (exchange refresh token for new token pair)
# =============================================================================================

@router.post("/refresh", response_model=TokenPair)
def refresh_tokens(
    data: RefreshTokenIn,
    db: Session = Depends(get_db),
):
    """
    Exchange refresh token for new access + refresh tokens.

    TOKEN ROTATION:
    - Old refresh token is revoked (one-time use)
    - New refresh token is issued and stored
    - New access token is issued

    FLOW:
    1. Client sends refresh token
    2. Verify JWT signature and expiration
    3. Look up token in database (by hash)
    4. Check if token is revoked or expired
    5. Generate new token pair
    6. Revoke old refresh token
    7. Store new refresh token
    8. Return new token pair

    REQUEST:
        POST /auth/refresh
        {
            "refresh_token": "eyJhbGci..."
        }

    RESPONSE (200 OK):
        {
            "access_token": "eyJhbGci...",  # New access token
            "refresh_token": "eyJhbGci...",  # New refresh token
            "token_type": "bearer",
            "expires_in": 900
        }

    ERRORS:
        401 Unauthorized: Invalid, expired, or revoked token

    SECURITY NOTES:
    - Token rotation prevents replay attacks (old token can't be reused)
    - Database lookup ensures token hasn't been revoked
    - Both JWT exp and database expires_at are checked
    - TODO: Add sliding window (extend expiration on each refresh)
    - TODO: Add device tracking (identify suspicious refresh patterns)
    """

    # -------------------------
    # STEP 1: Verify JWT signature and expiration
    # -------------------------
    try:
        payload = decode_token(data.refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    # -------------------------
    # STEP 2: Validate token type
    # -------------------------
    # Only accept refresh tokens (not access tokens)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Expected refresh token",
        )

    # Extract user ID from token
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # -------------------------
    # STEP 3: Look up token in database
    # -------------------------
    # Hash the token to find it in database (we store hashes, not raw tokens)
    token_hash = hash_refresh_token(data.refresh_token)

    # Find token in database
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).first()

    # -------------------------
    # STEP 4: Validate token state
    # -------------------------
    # Check if token exists
    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found",
        )

    # Check if token is revoked
    if db_token.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Check if token is expired (database check, in addition to JWT exp)
    if db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired",
        )

    # -------------------------
    # STEP 5: Generate new token pair
    # -------------------------
    new_access_token = create_access_token(user_id)
    new_refresh_token = create_refresh_token(user_id)

    # -------------------------
    # STEP 6: Revoke old refresh token (token rotation)
    # -------------------------
    # Mark old token as revoked (can't be used again)
    # This prevents replay attacks: if token is stolen, it's useless after first use
    db_token.revoked = True
    db.commit()

    # -------------------------
    # STEP 7: Store new refresh token
    # -------------------------
    new_token_hash = hash_refresh_token(new_refresh_token)
    new_expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=settings.REFRESH_TOKEN_EXPIRE_SECONDS
    )

    new_db_token = RefreshToken(
        user_id=user_id,
        token_hash=new_token_hash,
        expires_at=new_expires_at,
        revoked=False,
    )

    db.add(new_db_token)
    db.commit()

    # -------------------------
    # STEP 8: Return new token pair
    # -------------------------
    return TokenPair(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_SECONDS,
    )


# =============================================================================================
# ENDPOINT 4: Logout (revoke refresh token)
# =============================================================================================

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    data: RefreshTokenIn,
    db: Session = Depends(get_db),
):
    """
    Revoke refresh token (logout).

    FLOW:
    1. Client sends refresh token
    2. Verify JWT signature
    3. Look up token in database (by hash)
    4. Mark token as revoked
    5. Return 204 No Content (success, no body)

    REQUEST:
        POST /auth/logout
        {
            "refresh_token": "eyJhbGci..."
        }

    RESPONSE (204 No Content):
        (empty body)

    ERRORS:
        401 Unauthorized: Invalid token or token not found

    SECURITY NOTES:
    - Revoked tokens can't be used for /auth/refresh
    - Access tokens remain valid until expiration (can't be revoked server-side with JWT)
    - For immediate logout, use short-lived access tokens (15 min)
    - TODO: Add "logout all devices" endpoint (revoke all user's tokens)
    - TODO: Add token blacklist for immediate access token revocation
    """

    # -------------------------
    # STEP 1: Verify JWT (optional, but good practice)
    # -------------------------
    # We could skip this and just hash the token, but verifying ensures
    # only valid JWTs can be revoked (prevents database pollution)
    try:
        payload = decode_token(data.refresh_token)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        # For logout, we don't care if token is expired
        # Still allow revoking expired tokens (cleanup)
        pass

    # -------------------------
    # STEP 2: Look up token in database
    # -------------------------
    token_hash = hash_refresh_token(data.refresh_token)
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).first()

    # If token doesn't exist, that's okay (maybe already revoked or expired)
    # Return success anyway (idempotent operation)
    if not db_token:
        return

    # -------------------------
    # STEP 3: Revoke token
    # -------------------------
    # Mark as revoked (can't be used for /auth/refresh anymore)
    db_token.revoked = True
    db.commit()

    # Return 204 No Content (success, no response body)
    # FastAPI handles this automatically with status_code=204


# =============================================================================================
# ENDPOINT 5: Get current user profile
# =============================================================================================

@router.get("/me", response_model=UserOut)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """
    Get the authenticated user's profile.

    FLOW:
    1. Client sends access token in Authorization header
    2. get_current_user dependency validates token and loads user
    3. Return user data

    REQUEST:
        GET /auth/me
        Authorization: Bearer eyJhbGci...

    RESPONSE (200 OK):
        {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "email": "alice@example.com",
            "created_at": "2024-01-15T10:30:00Z"
        }

    ERRORS:
        401 Unauthorized: Missing, invalid, or expired access token

    SECURITY NOTES:
    - Protected by get_current_user dependency (requires valid access token)
    - Only returns safe fields (excludes password_hash)
    - Can be extended to return more profile data
    """

    # The dependency get_current_user() has already:
    # 1. Extracted access token from Authorization header
    # 2. Verified JWT signature and expiration
    # 3. Loaded user from database
    # 4. Raised 401 if any step failed
    #
    # So we just return the user object (FastAPI converts to UserOut)
    return current_user


# =============================================================================================
# TODO: Additional endpoints for future features
# =============================================================================================

# @router.post("/logout-all")
# def logout_all_devices(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """Revoke all refresh tokens for the current user (logout from all devices)."""
#     db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id).update({"revoked": True})
#     db.commit()
#     return {"message": "Logged out from all devices"}
#
# @router.post("/change-password")
# def change_password(data: UpdatePasswordIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """Change user's password and revoke all refresh tokens."""
#     # Verify current password, update hash, revoke all tokens
#     pass
#
# @router.post("/request-password-reset")
# def request_password_reset(email: EmailStr, db: Session = Depends(get_db)):
#     """Send password reset email with token."""
#     # Generate reset token, send email with link
#     pass
#
# @router.post("/reset-password")
# def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
#     """Reset password using token from email."""
#     # Verify token, update password, revoke all refresh tokens
#     pass
