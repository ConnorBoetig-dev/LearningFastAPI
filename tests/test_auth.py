# =============================================================================================
# TESTS/TEST_AUTH.PY - AUTHENTICATION ENDPOINT TESTS
# =============================================================================================
# This module tests the full authentication flow using an in-memory SQLite database.
#
# TEST STRATEGY:
# - Use SQLite in-memory database (fast, isolated, no cleanup needed)
# - Override FastAPI dependencies to use test database
# - Test entire flow: register → login → me → refresh → logout
# - Test error cases: duplicate email, wrong password, invalid tokens
#
# WHY SQLite IN-MEMORY FOR TESTS?
# - Fast: Everything in memory, no disk I/O
# - Isolated: Each test gets a fresh database
# - Simple: No Docker containers or external dependencies
# - Perfect for unit tests (production also uses SQLite)
#
# RUNNING TESTS:
#   pytest tests/test_auth.py -v
#   pytest -v  # Run all tests
# =============================================================================================

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.db import Base, get_db

# -------------------------
# Test database setup
# -------------------------
# Create in-memory SQLite database for tests
# :memory: means database exists only in RAM (disappears after tests)
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

# Create engine with SQLite-specific configuration
# check_same_thread=False allows using database from different threads
# (SQLite normally restricts to single thread, but FastAPI is multi-threaded)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Enable SQLite foreign keys and WAL mode for test database
from sqlalchemy import event

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Enable SQLite foreign keys for CASCADE deletes to work in tests."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")
    cursor.close()

# Create session factory for test database
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# -------------------------
# Pytest fixture: Set up test database before each test
# -------------------------
@pytest.fixture
def test_db():
    """
    Create a fresh database for each test.

    FLOW:
    1. Create all tables (users, refresh_tokens)
    2. Yield database session to test
    3. After test: Drop all tables (cleanup)

    WHY FRESH DB PER TEST?
    - Tests don't interfere with each other
    - Predictable state (no leftover data)
    - Can run tests in parallel (each has own DB)
    """
    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Create session for this test
    db = TestingSessionLocal()

    try:
        # Provide session to test
        yield db
    finally:
        # Cleanup: close session and drop all tables
        db.close()
        Base.metadata.drop_all(bind=engine)


# -------------------------
# Pytest fixture: Override FastAPI's get_db dependency
# -------------------------
@pytest.fixture
def client(test_db):
    """
    Create FastAPI test client with test database.

    DEPENDENCY OVERRIDE:
    - Replace app's get_db() with our test_db
    - All endpoints now use test database instead of production Postgres
    - Cleanup: restore original dependency after test
    """
    # Override dependency: app's get_db → our test_db
    def override_get_db():
        try:
            yield test_db
        finally:
            test_db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Create test client (simulates HTTP requests)
    yield TestClient(app)

    # Cleanup: restore original dependency
    app.dependency_overrides.clear()


# =============================================================================================
# TEST CASES: Full authentication flow
# =============================================================================================

def test_register_login_me_refresh_logout(client):
    """
    Test complete auth flow: register → login → me → refresh → logout.

    This is the happy path test that verifies:
    1. New user can register
    2. User can log in and get tokens
    3. User can access protected endpoints with access token
    4. User can refresh tokens when access token expires
    5. User can logout (revoke refresh token)
    6. Revoked refresh token cannot be used
    """

    # -------------------------
    # STEP 1: Register new user
    # -------------------------
    register_data = {
        "email": "test@example.com",
        "password": "password123"
    }

    response = client.post("/auth/register", json=register_data)

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data  # UUID assigned
    assert "created_at" in data
    assert "password" not in data  # Password not exposed
    assert "password_hash" not in data  # Hash not exposed

    # -------------------------
    # STEP 2: Login and get tokens
    # -------------------------
    login_data = {
        "email": "test@example.com",
        "password": "password123"
    }

    response = client.post("/auth/login", json=login_data)

    assert response.status_code == 200
    tokens = response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == 900  # 15 minutes

    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # -------------------------
    # STEP 3: Access protected endpoint (/auth/me)
    # -------------------------
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/auth/me", headers=headers)

    assert response.status_code == 200
    user = response.json()
    assert user["email"] == "test@example.com"

    # -------------------------
    # STEP 4: Refresh tokens
    # -------------------------
    refresh_data = {"refresh_token": refresh_token}
    response = client.post("/auth/refresh", json=refresh_data)

    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens

    # New tokens should be different from old ones
    assert new_tokens["access_token"] != access_token
    assert new_tokens["refresh_token"] != refresh_token

    # Old refresh token should now be revoked (can't use again)
    response = client.post("/auth/refresh", json=refresh_data)
    assert response.status_code == 401  # Revoked

    # -------------------------
    # STEP 5: Logout (revoke current refresh token)
    # -------------------------
    logout_data = {"refresh_token": new_tokens["refresh_token"]}
    response = client.post("/auth/logout", json=logout_data)

    assert response.status_code == 204  # No content

    # Try to use revoked refresh token (should fail)
    response = client.post("/auth/refresh", json=logout_data)
    assert response.status_code == 401


def test_register_duplicate_email(client):
    """Test that registering with an existing email returns 409 Conflict."""

    register_data = {
        "email": "duplicate@example.com",
        "password": "password123"
    }

    # First registration: success
    response = client.post("/auth/register", json=register_data)
    assert response.status_code == 201

    # Second registration with same email: conflict
    response = client.post("/auth/register", json=register_data)
    assert response.status_code == 409
    assert "already registered" in response.json()["detail"].lower()


def test_login_wrong_password(client):
    """Test that login with wrong password returns 401 Unauthorized."""

    # Register user
    client.post("/auth/register", json={"email": "user@example.com", "password": "correctpassword"})

    # Login with wrong password
    response = client.post("/auth/login", json={"email": "user@example.com", "password": "wrongpassword"})

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()


def test_login_nonexistent_email(client):
    """Test that login with nonexistent email returns 401 Unauthorized."""

    response = client.post("/auth/login", json={"email": "nonexistent@example.com", "password": "password123"})

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()


def test_access_protected_endpoint_without_token(client):
    """Test that accessing /auth/me without token returns 403 Forbidden."""

    response = client.get("/auth/me")
    assert response.status_code == 403  # Bearer scheme raises 403 when no Authorization header


def test_access_protected_endpoint_with_invalid_token(client):
    """Test that accessing /auth/me with invalid token returns 401 Unauthorized."""

    headers = {"Authorization": "Bearer invalid.token.here"}
    response = client.get("/auth/me", headers=headers)

    assert response.status_code == 401
    assert "could not validate" in response.json()["detail"].lower()


# =============================================================================================
# TODO: Additional test ideas
# =============================================================================================
#
# def test_refresh_with_expired_token(client):
#     """Test that expired refresh token returns 401."""
#     # Would need to mock time or set very short expiry
#     pass
#
# def test_access_token_expires(client):
#     """Test that expired access token returns 401."""
#     # Would need to mock time or set very short expiry
#     pass
#
# def test_password_too_short(client):
#     """Test that password <8 chars returns 422 Unprocessable Entity."""
#     response = client.post("/auth/register", json={"email": "test@example.com", "password": "short"})
#     assert response.status_code == 422
#
# def test_invalid_email_format(client):
#     """Test that invalid email returns 422."""
#     response = client.post("/auth/register", json={"email": "not-an-email", "password": "password123"})
#     assert response.status_code == 422
