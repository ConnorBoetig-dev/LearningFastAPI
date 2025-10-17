# =============================================================================================
# APP/SCHEMAS/USER.PY - PYDANTIC SCHEMAS FOR USER API REQUESTS/RESPONSES
# =============================================================================================
# This module defines Pydantic models for validating user data in API endpoints.
#
# PYDANTIC MODELS VS SQLALCHEMY MODELS:
# - SQLAlchemy models (app/models/user.py): Database schema (table structure)
# - Pydantic models (this file): API schema (request/response structure)
#
# WHY SEPARATE?
# - Database might have fields you don't want in API (password_hash, internal flags)
# - API might have fields not in database (password confirmation, CAPTCHA token)
# - Different validation rules (DB: nullable, API: required)
# - Security: control exactly what clients can read/write
#
# SCHEMA TYPES:
# - RegisterIn: Input for /auth/register (email + password)
# - LoginIn: Input for /auth/login (email + password)
# - UserOut: Output for /auth/me and other endpoints (public user data)
#
# FLOW:
# 1. Client sends JSON → Pydantic validates against RegisterIn/LoginIn
# 2. Route creates SQLAlchemy User object from validated data
# 3. Database operation (save, update, query)
# 4. Route returns UserOut (Pydantic serializes SQLAlchemy object to JSON)
# =============================================================================================

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, ConfigDict


# =============================================================================================
# INPUT SCHEMAS (Request bodies)
# =============================================================================================

class RegisterIn(BaseModel):
    """
    Schema for user registration requests.

    USAGE:
        POST /auth/register
        {
            "email": "alice@example.com",
            "password": "SecurePassword123!"
        }

    VALIDATION:
    - email: Valid email format (Pydantic's EmailStr validator)
    - password: Minimum 8 characters (configurable security requirement)

    SECURITY NOTES:
    - Password is never stored in plaintext (hashed before database insert)
    - Email is normalized (lowercase, trimmed whitespace) by EmailStr
    - Consider adding: password strength rules, disposable email blocking, CAPTCHA

    EXAMPLE USAGE IN ROUTE:
        @router.post("/register")
        def register(data: RegisterIn, db: Session = Depends(get_db)):
            # Pydantic has already validated email format and password length
            existing = db.query(User).filter(User.email == data.email).first()
            if existing:
                raise HTTPException(409, "Email already registered")
            hashed = hash_password(data.password)
            user = User(email=data.email, password_hash=hashed)
            db.add(user)
            db.commit()
            return user  # Auto-converts to UserOut
    """

    # Email address (validated format: user@domain.com)
    # EmailStr is a Pydantic type that:
    # - Validates email format using regex
    # - Normalizes to lowercase (Alice@Example.COM → alice@example.com)
    # - Requires @ symbol and domain
    # - Rejects obviously invalid emails
    #
    # NOTE: EmailStr doesn't verify domain exists (that requires DNS lookup)
    # For production, consider: email-validator library, disposable email blocklist
    email: EmailStr = Field(
        ...,  # Required field (... is Pydantic's way of saying "no default")
        description="User's email address (used for login)",
        examples=["alice@example.com"],
    )

    # Password (plaintext, will be hashed before storage)
    # min_length=8 is a basic security requirement:
    # - NIST recommends minimum 8 characters
    # - Longer is better (consider 12-16 for sensitive apps)
    # - Don't set max_length too low (passphrases can be long!)
    #
    # TODO: Add stronger password validation:
    # - At least one uppercase, lowercase, digit, special char
    # - Not in common password list (Have I Been Pwned API)
    # - Not same as email local part
    # - Use libraries like: password-strength, zxcvbn
    password: str = Field(
        ...,  # Required field
        min_length=8,  # Minimum security requirement
        description="User's password (will be hashed, minimum 8 characters)",
        examples=["SecurePassword123!"],
    )


class LoginIn(BaseModel):
    """
    Schema for user login requests.

    USAGE:
        POST /auth/login
        {
            "email": "alice@example.com",
            "password": "SecurePassword123!"
        }

    VALIDATION:
    - email: Valid email format
    - password: No length requirement (login accepts any password for verification)

    SECURITY NOTES:
    - Always return same error for "email not found" and "wrong password"
      (prevents attacker from enumerating valid emails)
    - Consider rate limiting login attempts (prevent brute force)
    - Consider CAPTCHA after N failed attempts
    - Log failed login attempts for security monitoring

    ERROR HANDLING EXAMPLE:
        # ❌ BAD: Reveals which part is wrong
        if not user:
            raise HTTPException(404, "Email not found")
        if not verify_password(data.password, user.password_hash):
            raise HTTPException(401, "Wrong password")

        # ✅ GOOD: Same error for both cases
        if not user or not verify_password(data.password, user.password_hash):
            raise HTTPException(401, "Invalid email or password")
    """

    # Email address (same validation as RegisterIn)
    email: EmailStr = Field(
        ...,
        description="User's email address",
        examples=["alice@example.com"],
    )

    # Password (no length requirement for login)
    # Why no min_length? User might have old password from before we added the rule
    # We validate during registration, not during login
    password: str = Field(
        ...,
        description="User's password",
        examples=["SecurePassword123!"],
    )


# =============================================================================================
# OUTPUT SCHEMAS (Response bodies)
# =============================================================================================

class UserOut(BaseModel):
    """
    Schema for user data in API responses.

    USAGE:
        GET /auth/me → Returns UserOut
        POST /auth/register → Returns UserOut
        GET /users/{id} → Returns UserOut

    SECURITY:
    - Excludes password_hash (never expose hashed passwords!)
    - Includes only safe, public user data
    - Can be extended with more fields (is_admin, email_verified, etc.)

    SQLALCHEMY INTEGRATION:
    - Pydantic can auto-convert SQLAlchemy User objects to this schema
    - from_attributes=True enables ORM mode (read from User.email, User.id, etc.)
    - FastAPI automatically serializes this to JSON

    EXAMPLE USAGE:
        @router.get("/me", response_model=UserOut)
        def get_me(current_user: User = Depends(get_current_user)):
            return current_user  # FastAPI auto-converts User → UserOut → JSON
    """

    # User's unique identifier (UUID)
    # UUID type is automatically serialized to string in JSON:
    #   UUID('123e4567-e89b-12d3-a456-426614174000') → "123e4567-e89b-12d3-a456-426614174000"
    id: UUID = Field(
        ...,
        description="User's unique identifier (UUID)",
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )

    # Email address (same type as input, but this is output)
    email: EmailStr = Field(
        ...,
        description="User's email address",
        examples=["alice@example.com"],
    )

    # Account creation timestamp (UTC)
    # datetime is serialized to ISO 8601 format in JSON:
    #   datetime(2024, 1, 15, 10, 30, 0) → "2024-01-15T10:30:00Z"
    created_at: datetime = Field(
        ...,
        description="When this account was created (UTC timezone)",
        examples=["2024-01-15T10:30:00Z"],
    )

    # -------------------------
    # Pydantic configuration
    # -------------------------
    # from_attributes=True enables "ORM mode":
    # - Pydantic reads from object attributes (user.email) instead of dict keys (user['email'])
    # - Allows converting SQLAlchemy models to Pydantic models
    # - Essential for FastAPI response_model to work with ORM objects
    #
    # BEFORE (Pydantic v1):
    #   class Config:
    #       orm_mode = True
    #
    # NOW (Pydantic v2):
    #   model_config = ConfigDict(from_attributes=True)
    model_config = ConfigDict(
        from_attributes=True,  # Enable ORM mode (read from SQLAlchemy objects)
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "alice@example.com",
                "created_at": "2024-01-15T10:30:00Z",
            }
        },
    )


# =============================================================================================
# TODO: Additional schemas for future features
# =============================================================================================
# class UpdatePasswordIn(BaseModel):
#     """Schema for password change requests."""
#     current_password: str
#     new_password: str = Field(min_length=8)
#     confirm_password: str  # Must match new_password
#
# class UpdateEmailIn(BaseModel):
#     """Schema for email change requests."""
#     new_email: EmailStr
#     password: str  # Confirm with current password
#
# class UserWithProfileOut(UserOut):
#     """Extended user output with profile data."""
#     is_admin: bool
#     email_verified: bool
#     last_login_at: datetime | None
