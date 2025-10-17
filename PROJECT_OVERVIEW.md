# LearningFastAPI - Project Overview

## What This Project Is

A **FastAPI-based file upload service** with **JWT authentication** that uses:
- **SQLite** for user accounts and token management
- **MinIO** (S3-compatible object storage) for file storage

This is a learning/demo project that demonstrates:

- Building a secure web API with FastAPI
- JWT authentication with token rotation
- SQLite database with SQLAlchemy ORM
- Integrating with S3-compatible storage (MinIO)
- Docker containerization and orchestration
- Writing unit tests with dependency injection/mocking
- Environment-based configuration

## Core Functionality

The application provides a secure file upload service with:

1. **User Authentication** - JWT-based authentication with:
   - User registration and login
   - Access tokens (15 min expiry) for API access
   - Refresh tokens (30 day expiry) with rotation
   - Secure token revocation and logout

2. **HTML Upload Interface** - A basic web form at `http://localhost:8000/`

3. **File Upload API** - Protected POST endpoint at `/upload` that:
   - Requires authentication (Bearer token)
   - Accepts file uploads via multipart/form-data
   - Stores files in MinIO with timestamp and user ID prefixes
   - Generates presigned URLs (1-hour expiry) for file downloads
   - Returns JSON response with file metadata

## Architecture & Tech Stack

### Services (Docker Compose)

1. **MinIO Container** (`minio`)
   - S3-compatible object storage server
   - Exposed on port 9000 (API) and 9001 (Web Console)
   - Data persisted in Docker volume `minio-data`
   - Credentials: `miniouser` / `miniopassword123`

2. **FastAPI Container** (`api`)
   - Python 3.12-slim based
   - FastAPI web framework with Uvicorn ASGI server
   - SQLite database persists on host filesystem
   - Hot-reload enabled for development
   - Exposed on port 8000

### Technology Stack

- **Framework**: FastAPI 0.115.0
- **Server**: Uvicorn 0.30.3 (with standard extras)
- **Database**: SQLite 3 (embedded, file-based)
- **ORM**: SQLAlchemy 2.0
- **Auth**: PyJWT + Passlib (bcrypt)
- **Storage Client**: boto3 1.35.22 (AWS SDK, works with MinIO)
- **File Handling**: python-multipart 0.0.9
- **Config**: python-dotenv 1.0.1
- **Testing**: pytest 8.3.3 + pytest-asyncio 0.24.0

## Project Structure

```
LearningFastAPI/
├── app/
│   ├── core/                 # Infrastructure layer
│   │   ├── config.py         # Pydantic settings
│   │   ├── db.py             # SQLAlchemy engine + session
│   │   ├── security.py       # JWT + bcrypt functions
│   │   └── deps.py           # FastAPI dependencies
│   ├── models/               # Database models
│   │   ├── user.py           # User table
│   │   └── token.py          # RefreshToken table
│   ├── schemas/              # Pydantic request/response schemas
│   │   ├── user.py
│   │   └── auth.py
│   ├── routers/              # API route handlers
│   │   └── auth.py           # Authentication endpoints
│   └── main.py               # FastAPI app + file upload
├── backend/
│   ├── Dockerfile            # API container build instructions
│   └── requirements.txt      # Python dependencies
├── tests/
│   ├── test_upload_endpoint.py  # File upload tests
│   └── test_auth.py          # Authentication flow tests
├── docker-compose.yml        # Service orchestration
├── dev.db                    # SQLite database (created at runtime)
├── .env                      # Environment configuration (gitignored)
├── .gitignore               # Version control exclusions
└── PROJECT_OVERVIEW.md      # This file
```

## Key Components Explained

### 1. FastAPI Application (`app/main.py`)

**Public Routes:**
- `GET /` - Returns HTML form for file upload

**Authentication Routes (`/auth`):**
- `POST /auth/register` - Create new user account
- `POST /auth/login` - Get access + refresh tokens
- `POST /auth/refresh` - Rotate tokens (get new pair)
- `POST /auth/logout` - Revoke refresh token
- `GET /auth/me` - Get current user profile (protected)

**Protected Routes:**
- `POST /upload` - Upload file to MinIO (requires Bearer token)

**Upload Flow:**
1. Validate access token (get_current_user dependency)
2. Load MinIO configuration from environment variables
3. Create boto3 S3 client pointing to MinIO
4. Ensure bucket exists (create if needed)
5. Upload file with timestamp and user ID prefix (e.g., `1704067200-user-id-myfile.pdf`)
6. Generate presigned download URL (1-hour expiry)
7. Return JSON response:
   ```json
   {
     "filename": "myfile.pdf",
     "key": "1704067200-user-id-myfile.pdf",
     "url": "https://...",
     "status": "uploaded"
   }
   ```

**Response Model (`UploadResponse`):**
```python
class UploadResponse(BaseModel):
    filename: str       # Original filename
    key: str           # Timestamped key in MinIO
    url: str | None    # Presigned download URL
    status: str        # Upload status
```

### 2. Authentication System

**Database Schema (SQLite):**
- **users**: id (UUID string), email (unique), password_hash (bcrypt), created_at
- **refresh_tokens**: id, user_id (FK), token_hash (SHA-256), expires_at, revoked, created_at

**JWT Flow:**
1. User registers → password hashed with bcrypt (12 rounds)
2. User logs in → server issues access token (15m) + refresh token (30d)
3. Client sends access token with requests → validated by `get_current_user` dependency
4. Access token expires → client sends refresh token to `/auth/refresh`
5. Server validates refresh token, issues new pair, revokes old refresh token
6. User logs out → refresh token marked as revoked in database

**Security Features:**
- Password hashing with bcrypt
- JWT tokens with HS256 signing
- Refresh token rotation (one-time use)
- Refresh tokens hashed with SHA-256 before storage
- Database-level token revocation
- Foreign keys enabled for CASCADE deletes

### 3. Docker Configuration

**Dockerfile** (`backend/Dockerfile`):
- Base image: `python:3.12-slim`
- Working dir: `/app`
- Layer optimization: dependencies installed before code copy
- Environment: `PYTHONUNBUFFERED=1` for immediate log output

**Docker Compose** (`docker-compose.yml`):
- Creates private network for service-to-service communication
- MinIO accessible as `http://minio:9000` from API container
- Volumes mounted for:
  - Hot-reload: `./app:/app/app`
  - SQLite persistence: `./:/app` (database on host)
  - MinIO data persistence: `minio-data:/data`
- Environment passed from `.env` file

### 4. Environment Configuration (`.env`)

```bash
# SQLite database
DATABASE_URL=sqlite:///./dev.db

# JWT configuration
JWT_SECRET=dev-secret-change-in-production
ACCESS_TOKEN_EXPIRE_SECONDS=900
REFRESH_TOKEN_EXPIRE_SECONDS=2592000
BCRYPT_ROUNDS=12

# MinIO configuration
MINIO_ROOT_USER=miniouser
MINIO_ROOT_PASSWORD=miniopassword123
STORAGE_ENDPOINT=http://minio:9000
STORAGE_ACCESS_KEY=miniouser
STORAGE_SECRET_KEY=miniopassword123
STORAGE_BUCKET=uploads
STORAGE_REGION=us-east-1
```

### 5. Testing

**Test Files:**
- `tests/test_upload_endpoint.py` - File upload tests with mocked boto3
- `tests/test_auth.py` - Full authentication flow tests

**Testing Strategy:**

**Upload Tests:**
- **No HTTP client required** - Directly invokes route handler function
- **Mocked boto3 client** - Uses `_FakeS3Client` stub instead of real MinIO
- **Dependency injection via monkeypatch** - Replaces `boto3.client` globally

**Auth Tests:**
- **SQLite in-memory database** - Fast, isolated, no cleanup needed
- **FastAPI TestClient** - HTTP requests with dependency overrides
- **Complete flow testing** - Register → login → me → refresh → logout
- **Error case testing** - Duplicate emails, wrong passwords, invalid tokens

**Key Test Components:**

1. **In-memory SQLite database** - Fresh database for each test
2. **Dependency overrides** - Replace `get_db` with test database
3. **Full flow coverage** - Test entire auth lifecycle
4. **Security validation** - Token rotation, revocation, expiration

## Running the Project

### Prerequisites
- Docker & Docker Compose installed
- No Python installation needed (runs in container)

### Start Services
```bash
docker-compose up --build
```

### Access Points
- **Upload UI**: http://localhost:8000/
- **API Docs**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001/ (login: miniouser/miniopassword123)

### Run Tests
```bash
# Inside container:
docker exec fastapi pytest

# Or locally if you have Python/pytest installed:
pytest
```

### Development Workflow
1. Edit files in `app/` directory
2. Changes auto-reload (no restart needed)
3. View logs: `docker-compose logs -f api`

## What Makes This Implementation Notable

1. **Heavily Commented Code** - Every file has extensive inline documentation explaining:
   - What each section does
   - Why it's structured that way
   - How components connect to each other
   - Flow of data through the system

2. **Test-Driven Design** - Unit tests use:
   - Dependency injection via monkeypatching
   - In-memory fakes instead of mocks
   - Direct function invocation (no HTTP overhead)
   - Comprehensive assertions on both response and side effects

3. **Production Patterns** - Even as a learning project, includes:
   - Environment-based configuration
   - Error handling with proper HTTP status codes
   - Presigned URLs for secure file access
   - Docker layer optimization for fast rebuilds
   - Graceful resource cleanup (file handle closure)

4. **S3-Compatible Storage** - Uses MinIO which:
   - Runs locally (no cloud costs/latency)
   - Uses same API as AWS S3 (boto3 library)
   - Easily swappable for real S3 in production

## Current Status

### Implemented
- [x] FastAPI application with file upload endpoint
- [x] MinIO integration via boto3
- [x] Docker containerization
- [x] Environment configuration
- [x] HTML upload interface
- [x] Presigned URL generation
- [x] Unit tests with mocked dependencies
- [x] Automatic bucket creation
- [x] Hot-reload development setup

### Known Limitations
- Single bucket architecture
- No file size limits enforced
- No file type validation
- Presigned URLs expire after 1 hour (hardcoded)
- No database/metadata persistence
- No authentication/authorization
- Basic error handling (500 errors for all failures)

## Recent Changes (Git History)

```
279d210 test?
1b20013 Merge pull request #1 - Add unit tests for upload file function
ee155a4 Add unit test for upload endpoint with MinIO stub
900196b fine ill take the /.env out
96d9da3 docker making sense now
```

## File Modifications

Currently modified (uncommitted):
- `tests/test_upload_endpoint.py` - Has local changes

## Next Steps / Extension Ideas

- Add authentication (API keys, JWT)
- Implement file size/type validation
- Add download endpoint (separate from presigned URLs)
- Store metadata in database (SQLite/PostgreSQL)
- Add file deletion capability
- Support multiple buckets
- Add progress tracking for large uploads
- Implement file listing/browsing
- Add image thumbnail generation
- Setup CI/CD pipeline
