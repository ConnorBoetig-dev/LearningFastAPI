# =============================================================================================
# APP/CORE/SECURITY.PY - PASSWORD HASHING AND JWT TOKEN MANAGEMENT
# =============================================================================================
# This module provides cryptographic functions for authentication:
# 1. Password hashing with bcrypt (one-way, secure storage)
# 2. JWT token creation (access + refresh tokens)
# 3. JWT token verification and decoding
# 4. Refresh token hashing (for secure storage in database)
#
# SECURITY PRINCIPLES:
# - Never store plaintext passwords (use bcrypt hash)
# - Never store raw refresh tokens (use hash like passwords)
# - Use short-lived access tokens (15 min) to limit damage if stolen
# - Use long-lived refresh tokens (30 days) but revokable via database
# - Sign JWTs with a secret key (only our server can create/verify them)
# =============================================================================================

import hashlib  # For hashing refresh tokens (SHA-256)
from datetime import datetime, timedelta, timezone  # For token expiration
from typing import Any

import jwt  # PyJWT library for creating and decoding JSON Web Tokens
from passlib.context import CryptContext  # Bcrypt password hashing

from app.core.config import get_settings

# -------------------------
# Load configuration
# -------------------------
settings = get_settings()

# -------------------------
# PASSWORD HASHING SETUP (BCRYPT)
# -------------------------
# CryptContext is a high-level password hashing wrapper from passlib.
# It handles salting, rounds, and algorithm selection automatically.
#
# WHY BCRYPT?
# - Designed for passwords (slow by design to resist brute force)
# - Automatically includes a random salt (prevents rainbow table attacks)
# - Configurable cost factor (can increase security as hardware improves)
#
# WHAT IS A SALT?
# - Random data added to password before hashing
# - Same password → different hash each time (salt is stored in the hash)
# - Prevents attackers from pre-computing hashes (rainbow tables)
#
# Example hash (bcrypt format):
#   $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5Y28Y9Cw/.a
#   ││  ││  └─────────────────────────────────┬─────────────────────┘
#   ││  ││                                    └─ Hash (31 chars)
#   ││  │└─ Salt (22 chars)
#   ││  └─ Cost factor (2^12 = 4096 iterations)
#   │└─ Version (2b = bcrypt)
#   └─ Algorithm identifier
pwd_context = CryptContext(
    schemes=["bcrypt"],  # Use bcrypt algorithm
    deprecated="auto",   # Auto-deprecate old algorithms if we upgrade later
)


# =============================================================================================
# PASSWORD HASHING FUNCTIONS
# =============================================================================================

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    FLOW:
    1. Generate random salt (22 characters)
    2. Combine password + salt
    3. Run bcrypt with configured rounds (e.g., 12 = 4096 iterations)
    4. Return hash (includes salt + algorithm metadata)

    SECURITY NOTES:
    - Same password → different hash each time (due to random salt)
    - Hash is one-way: cannot reverse to get original password
    - Cost factor (rounds) makes brute force expensive:
      * 12 rounds = ~400ms per hash on modern CPU
      * Attacker guessing 1M passwords would take ~111 hours per account

    USAGE:
        hashed = hash_password("MySecurePassword123!")
        # Store `hashed` in database (NOT the plaintext password)

    Args:
        password: The plaintext password to hash (e.g., from registration form)

    Returns:
        Bcrypt hash string (60 characters, e.g., "$2b$12$...")
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against a stored bcrypt hash.

    FLOW:
    1. Extract salt from the stored hash
    2. Hash the plaintext password with the same salt
    3. Compare the two hashes (constant-time comparison to prevent timing attacks)
    4. Return True if they match, False otherwise

    SECURITY NOTES:
    - Uses constant-time comparison (prevents timing side-channel attacks)
    - Attacker can't learn anything from verification timing
    - Wrong password returns False (doesn't reveal which part is wrong)

    TIMING ATTACK EXPLAINED:
    - If we used `==` and returned early on first mismatch, attacker could:
      1. Try "a" → fast rejection (wrong first char)
      2. Try "p" → slightly slower (first char matches, second doesn't)
      3. Keep trying until first char is slowest → that's correct!
      4. Repeat for each character to extract password
    - Constant-time comparison always takes same time, preventing this

    USAGE:
        # During login
        stored_hash = db.query(User).filter_by(email="user@example.com").first().password_hash
        if verify_password("user_input_password", stored_hash):
            # Password correct → issue tokens
        else:
            # Password wrong → return 401 Unauthorized

    Args:
        plain_password: The password to check (e.g., from login form)
        hashed_password: The stored bcrypt hash from database

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


# =============================================================================================
# JWT TOKEN FUNCTIONS
# =============================================================================================

def create_access_token(user_id: str) -> str:
    """
    Create a short-lived JWT access token for API authentication.

    WHAT IS A JWT?
    - JSON Web Token: self-contained, signed JSON payload
    - Three parts separated by dots: header.payload.signature
    - Server signs with secret key → only server can create valid tokens
    - Client sends with each request → server verifies signature

    JWT STRUCTURE:
        eyJhbGci...  .  eyJzdWIi...  .  SflKxwRJ...
        └─ Header      └─ Payload      └─ Signature
        (algorithm)    (claims/data)   (HMAC-SHA256)

    CLAIMS IN OUR ACCESS TOKEN:
    - sub (subject): user_id (UUID) - who this token belongs to
    - iat (issued at): timestamp when token was created
    - exp (expires): timestamp when token becomes invalid
    - type: "access" (distinguishes from refresh tokens)

    WHY SHORT-LIVED?
    - If stolen, attacker has limited time to use it (15 minutes)
    - User must refresh regularly (keeps session active check)
    - Compromise detection: revoke refresh token → access token expires soon

    USAGE:
        access_token = create_access_token(user.id)
        # Return to client: {"access_token": "eyJ...", "token_type": "bearer"}
        # Client sends with requests: Authorization: Bearer eyJ...

    Args:
        user_id: UUID or string identifying the user

    Returns:
        Signed JWT string (e.g., "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
    """
    # Calculate expiration time (now + configured seconds)
    expire = datetime.now(timezone.utc) + timedelta(seconds=settings.ACCESS_TOKEN_EXPIRE_SECONDS)

    # Build JWT payload (claims)
    payload = {
        "sub": str(user_id),  # Subject: who this token identifies
        "exp": expire,        # Expiration: when token becomes invalid
        "iat": datetime.now(timezone.utc),  # Issued at: when token was created
        "type": "access",     # Token type: access vs refresh
    }

    # Sign and encode the payload with our secret key
    # Algorithm HS256 = HMAC with SHA-256
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """
    Create a long-lived JWT refresh token for obtaining new access tokens.

    DIFFERENCE FROM ACCESS TOKEN:
    - Longer expiration (30 days vs 15 minutes)
    - Type claim is "refresh" (not "access")
    - Hash is stored in database (allows revocation)
    - Only used for /auth/refresh endpoint (not for API access)

    REFRESH TOKEN FLOW:
    1. User logs in → get both access token (15m) and refresh token (30d)
    2. Access token expires after 15 minutes
    3. Client sends refresh token to /auth/refresh
    4. Server validates, checks database (not revoked), issues new token pair
    5. Old refresh token is marked revoked (one-time use, rotation)

    WHY STORE HASH IN DATABASE?
    - Allows server-side revocation (logout, security breach)
    - If DB shows revoked=True, reject token even if JWT signature is valid
    - Prevents stolen refresh tokens from being useful after logout

    SECURITY NOTES:
    - Never send refresh token in URL params (logs, browser history)
    - Ideally store in httpOnly cookie (JavaScript can't access)
    - For this API, we return it in JSON for testing (production: use cookies)

    USAGE:
        refresh_token = create_refresh_token(user.id)
        # Hash it for storage
        token_hash = hash_refresh_token(refresh_token)
        # Save to database
        db_token = RefreshToken(user_id=user.id, token_hash=token_hash, ...)
        db.add(db_token)
        db.commit()

    Args:
        user_id: UUID or string identifying the user

    Returns:
        Signed JWT string (30-day expiration)
    """
    # Calculate expiration time (now + configured seconds, typically 30 days)
    expire = datetime.now(timezone.utc) + timedelta(seconds=settings.REFRESH_TOKEN_EXPIRE_SECONDS)

    # Build JWT payload (claims)
    payload = {
        "sub": str(user_id),  # Subject: who this token identifies
        "exp": expire,        # Expiration: when token becomes invalid
        "iat": datetime.now(timezone.utc),  # Issued at: when token was created
        "type": "refresh",    # Token type: distinguishes from access tokens
    }

    # Sign and encode the payload with our secret key
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT token.

    WHAT DOES VERIFICATION CHECK?
    1. Signature is valid (token was signed by our server)
    2. Token hasn't been tampered with (signature matches payload)
    3. Token hasn't expired (exp claim is in the future)
    4. Algorithm matches expected (prevents algorithm substitution attacks)

    SECURITY NOTES:
    - Raises jwt.ExpiredSignatureError if token expired
    - Raises jwt.InvalidTokenError if signature invalid or payload tampered
    - Raises jwt.DecodeError if token format is malformed

    ALGORITHM SUBSTITUTION ATTACK EXPLAINED:
    - Attacker changes header from HS256 (symmetric) to none (no signature)
    - If server doesn't check algorithm, it accepts unsigned tokens
    - We specify `algorithms=[settings.JWT_ALGORITHM]` to prevent this

    USAGE:
        try:
            payload = decode_token(token)
            user_id = payload["sub"]
            token_type = payload["type"]
        except jwt.ExpiredSignatureError:
            # Token expired → return 401 with "token expired" message
        except jwt.InvalidTokenError:
            # Token invalid → return 401 with "invalid token" message

    Args:
        token: The JWT string to decode (from Authorization header)

    Returns:
        Decoded payload as dict (includes sub, exp, iat, type)

    Raises:
        jwt.ExpiredSignatureError: Token has expired
        jwt.InvalidTokenError: Token signature invalid or format wrong
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET,
        algorithms=[settings.JWT_ALGORITHM],  # Only accept our configured algorithm
    )


# =============================================================================================
# REFRESH TOKEN HASHING (FOR DATABASE STORAGE)
# =============================================================================================

def hash_refresh_token(token: str) -> str:
    """
    Hash a refresh token for secure storage in database.

    WHY HASH REFRESH TOKENS?
    - Same reason as passwords: database breach shouldn't leak usable tokens
    - If attacker gets DB access, they get hashes (not raw tokens)
    - They can't use hashes to authenticate (need the original token)

    WHY SHA-256 INSTEAD OF BCRYPT?
    - Refresh tokens are already random (high entropy, 200+ chars)
    - Bcrypt's slowness is unnecessary (no brute force risk for random data)
    - SHA-256 is fast and sufficient for high-entropy inputs

    BCRYPT VS SHA-256 COMPARISON:
    - Bcrypt: Slow by design, salted, for low-entropy user passwords
    - SHA-256: Fast, for high-entropy random data (UUIDs, tokens, etc.)

    USAGE:
        token = create_refresh_token(user.id)
        hashed = hash_refresh_token(token)
        # Store `hashed` in database
        db_token = RefreshToken(user_id=user.id, token_hash=hashed, ...)

        # Later, when client sends token, hash it again and compare:
        client_token_hash = hash_refresh_token(client_provided_token)
        db_token = db.query(RefreshToken).filter_by(token_hash=client_token_hash).first()

    Args:
        token: The raw refresh token JWT string

    Returns:
        SHA-256 hex digest (64 characters, e.g., "a3f2b...")
    """
    # Encode token to bytes, hash with SHA-256, return hex string
    return hashlib.sha256(token.encode()).hexdigest()
