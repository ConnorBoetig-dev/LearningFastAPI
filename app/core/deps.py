# =============================================================================================
# APP/CORE/DEPS.PY - FASTAPI DEPENDENCIES FOR AUTHENTICATION
# =============================================================================================
# This module provides reusable FastAPI dependencies for protecting routes.
#
# KEY DEPENDENCY: get_current_user()
# - Extracts JWT token from Authorization header
# - Verifies token signature and expiration
# - Loads user from database
# - Returns User object to the route handler
# - Raises 401 Unauthorized if token is invalid/missing
#
# USAGE IN ROUTES:
#   @app.get("/protected")
#   def protected_route(current_user: User = Depends(get_current_user)):
#       return {"message": f"Hello {current_user.email}"}
#
# FLOW:
# 1. Client sends: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
# 2. get_current_user() extracts and verifies token
# 3. If valid, loads user from DB and injects into route handler
# 4. If invalid, raises HTTPException 401 (request never reaches route)
# =============================================================================================

import jwt  # For catching JWT-specific exceptions
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import decode_token

# -------------------------
# HTTP Bearer token security scheme
# -------------------------
# This tells FastAPI to:
# 1. Look for an "Authorization" header
# 2. Expect format: "Bearer <token>"
# 3. Extract the <token> part
# 4. Make it available to our dependency function
#
# WHAT IS BEARER AUTHENTICATION?
# - HTTP auth scheme where client sends token in Authorization header
# - Format: Authorization: Bearer <token>
# - "Bearer" means "the bearer of this token is authorized"
# - No username/password sent with each request (just the token)
#
# WHY NOT BASIC AUTH?
# - Basic auth sends username:password with every request (inefficient, risky)
# - Bearer auth sends a token (can be revoked, expires automatically)
#
# OpenAPI INTEGRATION:
# - FastAPI auto-generates docs showing "Authorize" button
# - Developers can test protected routes in /docs UI
bearer_scheme = HTTPBearer()


# -------------------------
# Dependency: Get current authenticated user
# -------------------------
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    """
    FastAPI dependency that authenticates requests and returns the current user.

    DEPENDENCY INJECTION FLOW:
    1. FastAPI calls bearer_scheme (extracts token from Authorization header)
    2. FastAPI calls get_db (provides database session)
    3. FastAPI calls this function with both dependencies resolved
    4. This function verifies token and loads user
    5. FastAPI injects User object into the route handler

    ERROR HANDLING:
    - Missing Authorization header → 403 Forbidden (bearer_scheme raises it)
    - Invalid token format → 401 Unauthorized
    - Expired token → 401 Unauthorized with "Token has expired"
    - User not found in DB → 401 Unauthorized with "User not found"

    SECURITY CHECKS PERFORMED:
    1. Token signature is valid (signed by our server)
    2. Token hasn't expired (exp claim check)
    3. Token type is "access" (not a refresh token)
    4. User exists in database (account not deleted)

    USAGE EXAMPLE:
        @app.get("/me")
        def get_my_profile(current_user: User = Depends(get_current_user)):
            return {"email": current_user.email, "id": str(current_user.id)}

        # Client request:
        # GET /me HTTP/1.1
        # Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

    TESTING:
        # Override dependency in tests:
        from fastapi.testclient import TestClient
        app.dependency_overrides[get_current_user] = lambda: fake_user
        response = client.get("/me")
        # Route receives fake_user instead of real authentication

    Args:
        credentials: HTTPAuthorizationCredentials from bearer_scheme
                    Contains .scheme ("Bearer") and .credentials (the token string)
        db: SQLAlchemy session from get_db dependency

    Returns:
        User: The authenticated user object from database

    Raises:
        HTTPException 401: If token is invalid, expired, or user doesn't exist
    """
    # -------------------------
    # STEP 1: Extract the raw token from credentials
    # -------------------------
    # credentials.credentials contains the JWT string (everything after "Bearer ")
    token = credentials.credentials

    # -------------------------
    # STEP 2: Decode and verify the JWT
    # -------------------------
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        # Token's exp claim is in the past
        # Return clear error message so client can refresh token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},  # Tell client to get a new token
        )
    except jwt.InvalidTokenError:
        # Signature invalid, format wrong, or algorithm mismatch
        # Generic error message for security (don't reveal why it failed)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # -------------------------
    # STEP 3: Validate token type (must be "access", not "refresh")
    # -------------------------
    # Refresh tokens should only be used with /auth/refresh endpoint
    # Prevents client from using long-lived refresh token for API access
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Expected access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # -------------------------
    # STEP 4: Extract user ID from token payload
    # -------------------------
    # The "sub" (subject) claim contains the user's UUID
    user_id: str | None = payload.get("sub")
    if user_id is None:
        # Malformed token (missing required claim)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # -------------------------
    # STEP 5: Load user from database
    # -------------------------
    # Import here to avoid circular dependency (models import deps, deps import models)
    from app.models.user import User

    # Query database for user with this ID
    # user_id is a string UUID from JWT, but DB column is UUID type (SQLAlchemy handles conversion)
    user = db.query(User).filter(User.id == user_id).first()

    # -------------------------
    # STEP 6: Validate user exists
    # -------------------------
    # User might have been deleted after token was issued
    # Or token was forged with a fake user_id
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # -------------------------
    # STEP 7: Return authenticated user
    # -------------------------
    # FastAPI injects this into the route handler parameter
    # Route handler receives a User object, not a token!
    return user


# -------------------------
# TODO: Additional dependencies for later
# -------------------------
# Future enhancements you might add:
#
# def get_current_active_user(current_user: User = Depends(get_current_user)):
#     """Ensure user account is not disabled/suspended."""
#     if not current_user.is_active:
#         raise HTTPException(status_code=400, detail="Inactive user")
#     return current_user
#
# def get_current_verified_user(current_user: User = Depends(get_current_user)):
#     """Ensure user has verified their email address."""
#     if not current_user.email_verified:
#         raise HTTPException(status_code=403, detail="Email not verified")
#     return current_user
#
# def require_admin(current_user: User = Depends(get_current_user)):
#     """Ensure user has admin role."""
#     if not current_user.is_admin:
#         raise HTTPException(status_code=403, detail="Admin access required")
#     return current_user
