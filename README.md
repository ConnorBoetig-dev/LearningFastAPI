# Secure File Upload API with JWT Authentication

A production-ready FastAPI application demonstrating:
- **JWT Authentication** (access + refresh tokens with rotation)
- **SQLite** database with SQLAlchemy ORM
- **MinIO** S3-compatible object storage
- **Docker Compose** development environment
- **Comprehensive testing** with pytest

## Features

- **User Authentication**
  - Register with email/password
  - Login with JWT token issuance
  - Protected API endpoints
  - Refresh token rotation (30-day expiry)
  - Logout with token revocation

- **File Upload**
  - Authenticated file uploads to MinIO
  - Presigned download URLs (1-hour expiry)
  - Files scoped to user (via user ID in filename)

- **Security**
  - Bcrypt password hashing (12 rounds)
  - JWT tokens with HS256 signing
  - Refresh tokens stored as SHA-256 hashes
  - Database-level token revocation
  - Protected routes with Bearer auth

## Tech Stack

- **FastAPI** 0.115.0 - Modern Python web framework
- **SQLite** 3 - Lightweight embedded database
- **SQLAlchemy** 2.0 - Python ORM
- **MinIO** - S3-compatible object storage
- **Pydantic** 2.x - Data validation
- **PyJWT** - JWT token handling
- **Passlib** - Password hashing with bcrypt
- **Docker Compose** - Multi-container orchestration

## Project Structure

```
LearningFastAPI/
├── app/
│   ├── core/
│   │   ├── config.py       # Pydantic settings (env vars)
│   │   ├── db.py           # SQLAlchemy engine + session
│   │   ├── security.py     # Password hashing + JWT
│   │   └── deps.py         # FastAPI dependencies (get_current_user)
│   ├── models/
│   │   ├── user.py         # User database model
│   │   └── token.py        # RefreshToken database model
│   ├── schemas/
│   │   ├── user.py         # Pydantic schemas (RegisterIn, UserOut)
│   │   └── auth.py         # Auth schemas (TokenPair, RefreshTokenIn)
│   ├── routers/
│   │   └── auth.py         # Auth endpoints (register, login, etc.)
│   └── main.py             # FastAPI app + file upload endpoint
├── backend/
│   ├── Dockerfile          # API container build
│   └── requirements.txt    # Python dependencies
├── tests/
│   ├── test_upload_endpoint.py  # MinIO upload tests
│   └── test_auth.py        # Authentication flow tests
├── docker-compose.yml      # Services (Postgres, MinIO, API)
├── .env                    # Environment configuration
└── .env.example            # Example config with explanations
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional) Python 3.12+ for local development

### 1. Clone and Configure

```bash
git clone <repository>
cd LearningFastAPI

# Copy example environment file
cp .env.example .env

# (Optional) Generate secure JWT secret
openssl rand -hex 32  # Copy output to JWT_SECRET in .env
```

### 2. Start Services

```bash
# Build and start all containers (MinIO, FastAPI)
docker-compose up --build

# Wait for "Application startup complete" message
# SQLite database (dev.db) will be created automatically
```

### 3. Verify Running

- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs (Swagger UI)
- **MinIO Console**: http://localhost:9001 (login: miniouser/miniopassword123)

## API Usage Examples

### 1. Register New User

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response** (201 Created):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "alice@example.com",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### 2. Login (Get Tokens)

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 900
}
```

**Save the tokens** for subsequent requests!

### 3. Get Current User Profile

```bash
# Replace TOKEN with access_token from login response
curl -X GET http://localhost:8000/auth/me \
  -H "Authorization: Bearer TOKEN"
```

**Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "alice@example.com",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### 4. Upload File (Protected)

```bash
# Replace TOKEN with access_token
curl -X POST http://localhost:8000/upload \
  -H "Authorization: Bearer TOKEN" \
  -F "file=@/path/to/document.pdf"
```

**Response** (200 OK):
```json
{
  "filename": "document.pdf",
  "key": "1704067200-123e4567-document.pdf",
  "url": "http://minio:9000/uploads/1704067200-123e4567-document.pdf?...",
  "status": "uploaded"
}
```

### 5. Refresh Access Token

When your access token expires (after 15 minutes):

```bash
# Replace REFRESH_TOKEN with refresh_token from login
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "REFRESH_TOKEN"
  }'
```

**Response** (200 OK):
```json
{
  "access_token": "NEW_ACCESS_TOKEN",
  "refresh_token": "NEW_REFRESH_TOKEN",
  "token_type": "bearer",
  "expires_in": 900
}
```

**Note**: Old refresh token is now revoked (one-time use).

### 6. Logout

```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "REFRESH_TOKEN"
  }'
```

**Response** (204 No Content)

Refresh token is now revoked and cannot be used.

## Running Tests

```bash
# Run all tests
docker exec fastapi pytest -v

# Run specific test file
docker exec fastapi pytest tests/test_auth.py -v

# Run with coverage
docker exec fastapi pytest --cov=app tests/
```

## Environment Variables

See `.env.example` for all available configuration options.

**Key Variables**:
- `DATABASE_URL` - SQLite database path (default: `sqlite:///./dev.db`)
- `JWT_SECRET` - Secret key for signing JWT tokens (use `openssl rand -hex 32`)
- `ACCESS_TOKEN_EXPIRE_SECONDS` - Access token lifetime (default: 900 = 15 min)
- `REFRESH_TOKEN_EXPIRE_SECONDS` - Refresh token lifetime (default: 2592000 = 30 days)
- `BCRYPT_ROUNDS` - Password hashing cost factor (default: 12)

## Development Workflow

### Hot Reload

Code changes in `app/` are automatically reloaded (no restart needed).

### View Logs

```bash
docker-compose logs -f api
docker-compose logs -f postgres
docker-compose logs -f minio
```

### Database Access

```bash
# Connect to SQLite database
sqlite3 dev.db

# Or from within Docker container
docker exec -it fastapi sqlite3 dev.db

# View users
SELECT id, email, created_at FROM users;

# View refresh tokens
SELECT user_id, revoked, expires_at, created_at FROM refresh_tokens;

# Exit SQLite
.quit
```

### Stop Services

```bash
# Stop containers (keep data)
docker-compose down

# Stop and remove MinIO volumes (SQLite database persists on host)
docker-compose down -v

# Remove SQLite database for clean slate
rm -f dev.db dev.db-shm dev.db-wal
```

## Authentication Flow

```
┌─────────┐                                              ┌─────────┐
│ Client  │                                              │  API    │
└────┬────┘                                              └────┬────┘
     │                                                        │
     │  POST /auth/register (email, password)                │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │  201 Created {id, email, created_at}                  │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     │  POST /auth/login (email, password)                   │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │  200 OK {access_token, refresh_token, expires_in}     │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     │  Store tokens (access in memory, refresh in cookie)   │
     │                                                        │
     │  POST /upload Authorization: Bearer ACCESS_TOKEN      │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │  200 OK {filename, key, url, status}                  │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     │  ... 15 minutes pass, access token expires ...        │
     │                                                        │
     │  POST /auth/refresh (refresh_token)                   │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │  200 OK {new_access_token, new_refresh_token}         │
     <───────────────────────────────────────────────────────┤
     │                                                        │
     │  POST /auth/logout (refresh_token)                    │
     ├───────────────────────────────────────────────────────>
     │                                                        │
     │  204 No Content                                       │
     <───────────────────────────────────────────────────────┤
     │                                                        │
```

## Security Considerations

**Implemented**:
- ✅ Bcrypt password hashing (12 rounds)
- ✅ JWT tokens with expiration
- ✅ Refresh token rotation (one-time use)
- ✅ Refresh token hashing (SHA-256)
- ✅ Database-level token revocation
- ✅ Protected endpoints with Bearer auth
- ✅ HTTPS support ready (configure reverse proxy)

**TODO for Production**:
- [ ] Email verification after registration
- [ ] Password reset flow (email with token)
- [ ] Multi-factor authentication (TOTP)
- [ ] Rate limiting (login attempts, API calls)
- [ ] CAPTCHA on registration/login
- [ ] Account lockout after failed attempts
- [ ] Audit logging (login attempts, token usage)
- [ ] CORS configuration (allow specific origins)
- [ ] HTTPS enforcement
- [ ] Secrets management (AWS Secrets Manager, Vault)
- [ ] Alembic database migrations
- [ ] File size/type validation
- [ ] Malware scanning for uploads

## License

MIT

## Author

Built as a learning project for FastAPI + Authentication + Docker.
