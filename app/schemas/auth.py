# =============================================================================================
# APP/SCHEMAS/AUTH.PY - PYDANTIC SCHEMAS FOR AUTHENTICATION RESPONSES
# =============================================================================================
# This module defines Pydantic models for authentication-related API responses.
#
# SCHEMA:
# - TokenPair: Response from /auth/login and /auth/refresh containing both tokens
# - RefreshTokenIn: Input for /auth/refresh and /auth/logout (refresh token string)
#
# TOKEN LIFECYCLE:
# 1. Login: Server returns TokenPair (access + refresh tokens)
# 2. API calls: Client sends access token in Authorization header
# 3. Access expires: Client sends refresh token to /auth/refresh
# 4. Refresh: Server returns new TokenPair, marks old refresh token as revoked
# 5. Logout: Client sends refresh token to /auth/logout, server revokes it
# =============================================================================================

from pydantic import BaseModel, Field


# =============================================================================================
# OUTPUT SCHEMAS (Response bodies)
# =============================================================================================

class TokenPair(BaseModel):
    """
    Schema for token pair responses (login, refresh).

    USAGE:
        POST /auth/login → Returns TokenPair
        POST /auth/refresh → Returns TokenPair

    RESPONSE EXAMPLE:
        {
            "access_token": "eyJhbGci...",
            "refresh_token": "eyJhbGci...",
            "token_type": "bearer",
            "expires_in": 900
        }

    CLIENT USAGE:
        # Store tokens (best practice: access in memory, refresh in httpOnly cookie)
        const { access_token, refresh_token } = await response.json();
        localStorage.setItem('access_token', access_token);  // Or keep in memory
        // refresh_token should be set via httpOnly cookie by server

        # Use access token for API calls
        fetch('/api/protected', {
            headers: { 'Authorization': `Bearer ${access_token}` }
        });

        # When access token expires (401), use refresh token
        const newTokens = await fetch('/auth/refresh', {
            method: 'POST',
            body: JSON.stringify({ refresh_token })
        });

    SECURITY NOTES:
    - Access token should be short-lived (15 minutes) to limit damage if stolen
    - Refresh token should be stored securely (httpOnly cookie preferred)
    - Never send refresh token in URL params (logs, browser history)
    - Consider HTTPS-only to prevent token interception
    """

    # Short-lived token for API authentication (15 minutes)
    # Client sends this in Authorization: Bearer <token> header
    # Server validates signature and expiration on each request
    access_token: str = Field(
        ...,
        description="JWT access token for API authentication (short-lived, 15 min)",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0..."],
    )

    # Long-lived token for obtaining new access tokens (30 days)
    # Client sends this to /auth/refresh when access token expires
    # Server rotates this token (issues new one, revokes old one)
    refresh_token: str = Field(
        ...,
        description="JWT refresh token for obtaining new access tokens (long-lived, 30 days)",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0..."],
    )

    # Token type (always "bearer" for JWT)
    # This tells the client how to format the Authorization header:
    #   Authorization: Bearer <access_token>
    #
    # WHY "bearer"?
    # - HTTP auth scheme defined in RFC 6750
    # - "Bearer" means "the bearer (holder) of this token is authorized"
    # - Alternative schemes: Basic (username:password), Digest, etc.
    token_type: str = Field(
        default="bearer",
        description="Token type for Authorization header (always 'bearer')",
        examples=["bearer"],
    )

    # How long the access token is valid (in seconds)
    # Helps client know when to refresh the token
    # Client can schedule refresh before expiration (e.g., 30 seconds early)
    #
    # EXAMPLE CLIENT LOGIC:
    #   const expiresAt = Date.now() + (expires_in * 1000);
    #   if (Date.now() >= expiresAt - 30000) {  // 30 seconds before expiry
    #       await refreshTokens();
    #   }
    expires_in: int = Field(
        ...,
        description="How long the access token is valid (in seconds, typically 900 = 15 minutes)",
        examples=[900],
    )


# =============================================================================================
# INPUT SCHEMAS (Request bodies)
# =============================================================================================

class RefreshTokenIn(BaseModel):
    """
    Schema for refresh token requests.

    USAGE:
        POST /auth/refresh
        {
            "refresh_token": "eyJhbGci..."
        }

        POST /auth/logout
        {
            "refresh_token": "eyJhbGci..."
        }

    SECURITY NOTES:
    - Refresh token should be validated:
      1. JWT signature is valid
      2. Token hasn't expired
      3. Token exists in database (by hash)
      4. Token isn't revoked
    - After successful refresh, old token should be revoked (one-time use)
    - After logout, token should be marked as revoked immediately
    """

    # The refresh token JWT string
    # This is the same token returned in TokenPair.refresh_token
    refresh_token: str = Field(
        ...,
        description="Refresh token JWT obtained from login or previous refresh",
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0..."],
    )


# =============================================================================================
# TODO: Additional schemas for future features
# =============================================================================================
# class TokenBlacklist(BaseModel):
#     """Schema for token blacklist entries (if using blacklist instead of refresh_tokens table)."""
#     token_jti: str  # JWT ID (unique identifier for each token)
#     expires_at: datetime
#
# class MFAVerifyIn(BaseModel):
#     """Schema for multi-factor authentication verification."""
#     code: str = Field(min_length=6, max_length=6, pattern="^\d{6}$")  # 6-digit TOTP code
#
# class MFASetupOut(BaseModel):
#     """Schema for MFA setup response."""
#     secret: str  # TOTP secret for Google Authenticator
#     qr_code_url: str  # QR code image URL for easy scanning
