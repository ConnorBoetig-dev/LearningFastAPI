# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A FastAPI-based secure file upload service with:
- **JWT authentication** (access + refresh tokens with rotation)
- **SQLite** for user accounts and token management
- **MinIO** (S3-compatible) for file storage
- **Docker Compose** orchestration for services

This is a learning/demo project demonstrating production-ready authentication patterns with comprehensive inline documentation.

## Development Commands

### Starting the Application

```bash
# Build and start all services (MinIO, FastAPI)
docker-compose up --build

# Start in detached mode
docker-compose up -d

# Stop and clean up (keeps SQLite database and MinIO volumes)
docker-compose down

# Stop and remove MinIO data (keeps SQLite database on host)
docker-compose down -v

# Remove SQLite database for fresh start
rm -f dev.db dev.db-shm dev.db-wal
```

### Running Tests

```bash
# Run all tests
docker exec fastapi pytest -v

# Run specific test file
docker exec fastapi pytest tests/test_auth.py -v

# Run single test
docker exec fastapi pytest tests/test_auth.py::test_register_new_user -v

# Run with coverage
docker exec fastapi pytest --cov=app tests/
```

### Database Operations

```bash
# Connect to SQLite database
sqlite3 dev.db

# Or from within Docker container
docker exec -it fastapi sqlite3 dev.db

# Useful SQLite commands
.tables                     # List all tables
.schema users              # View users table schema
.schema refresh_tokens     # View refresh_tokens table schema

# SQL queries for development
SELECT id, email, created_at FROM users;
SELECT user_id, revoked, expires_at, created_at FROM refresh_tokens;

# Delete all users and tokens (CASCADE works with foreign keys enabled)
DELETE FROM users;

# Exit SQLite
.quit
```

### Viewing Logs

```bash
# Follow API logs
docker-compose logs -f api

# View all service logs
docker-compose logs -f

# View MinIO logs
docker-compose logs -f minio
```

### Accessing Services

- **API**: http://localhost:8000
- **API Docs (Swagger)**: http://localhost:8000/docs
- **MinIO Console**: http://localhost:9001 (login: miniouser/miniopassword123)

## Architecture

### Multi-Layer Structure

The codebase follows a modular FastAPI architecture:

```
app/
├── core/           # Infrastructure layer
│   ├── config.py   # Pydantic settings (env vars, typed config)
│   ├── db.py       # SQLAlchemy engine + session factory
│   ├── security.py # JWT + bcrypt functions
│   └── deps.py     # FastAPI dependencies (get_current_user, get_db)
├── models/         # Database models (SQLAlchemy ORM)
│   ├── user.py     # User table
│   └── token.py    # RefreshToken table
├── schemas/        # Pydantic schemas (request/response validation)
│   ├── user.py     # RegisterIn, UserOut
│   └── auth.py     # TokenPair, RefreshTokenIn, LoginRequest
├── routers/        # Route handlers (API endpoints)
│   └── auth.py     # /auth/* endpoints (register, login, refresh, logout)
└── main.py         # FastAPI app + startup + /upload endpoint
```

### Authentication Flow

**Token Lifecycle:**
1. User registers (`POST /auth/register`) → user record created with bcrypt password hash
2. User logs in (`POST /auth/login`) → validates password, returns access token (15m) + refresh token (30d)
3. User makes authenticated requests with `Authorization: Bearer <access_token>`
4. Access token expires → user sends refresh token to `POST /auth/refresh`
5. Server validates refresh token, creates new token pair, revokes old refresh token (one-time use)
6. User logs out → refresh token marked `revoked=true` in database

**Key Security Mechanisms:**
- **Access tokens**: Short-lived (15 min), stateless JWT, used for API access
- **Refresh tokens**: Long-lived (30 days), stored as SHA-256 hash in DB, revokable
- **Token rotation**: Each refresh creates new token pair and revokes old one
- **Password hashing**: Bcrypt with 12 rounds (~400ms per hash)
- **Dependency injection**: `get_current_user()` validates tokens and loads user for protected routes

### Database Schema

**users table (SQLite):**
- `id` (VARCHAR(36) - UUID as string, primary key)
- `email` (VARCHAR(255), unique, indexed)
- `password_hash` (VARCHAR(60) - bcrypt, fixed length)
- `created_at` (TIMESTAMP - stored as ISO 8601 text)

**refresh_tokens table (SQLite):**
- `id` (VARCHAR(36) - UUID as string, primary key)
- `user_id` (VARCHAR(36) - foreign key → users, CASCADE delete)
- `token_hash` (VARCHAR(64) - SHA-256 hex, unique, indexed)
- `expires_at` (TIMESTAMP - stored as ISO 8601 text)
- `revoked` (BOOLEAN - stored as 0/1)
- `created_at` (TIMESTAMP - stored as ISO 8601 text)

**SQLite Configuration:**
- Foreign keys enabled via PRAGMA (CASCADE deletes work)
- WAL (Write-Ahead Logging) mode for better concurrency
- Synchronous mode set to NORMAL (balance safety/performance)

**Why hash refresh tokens?**
Database breach doesn't leak usable tokens. Attacker gets hashes, not raw JWTs.

### File Upload Flow

1. User authenticates → receives access token
2. User uploads file to `POST /upload` with `Authorization: Bearer <token>`
3. `get_current_user()` dependency validates token
4. File stored in MinIO with key: `{timestamp}-{user_id}-{filename}`
5. Presigned download URL generated (1-hour expiry)
6. Response includes filename, key, URL, status

**Current limitation:** Files not linked to users in database (no metadata persistence). See TODO comments in `app/main.py:247-257` for enhancement pattern.

## Configuration Management

**Pydantic Settings Pattern:**
- All config in `app/core/config.py` as typed `Settings` class
- Environment variables automatically loaded and validated
- Cached with `@lru_cache` (load once per process)
- Access anywhere: `from app.core.config import get_settings; settings = get_settings()`

**Key environment variables** (see `.env.example`):
- `DATABASE_URL`: SQLite database path (default: `sqlite:///./dev.db`)
- `JWT_SECRET`: Secret for signing JWTs (generate with `openssl rand -hex 32`)
- `ACCESS_TOKEN_EXPIRE_SECONDS`: Access token TTL (default: 900)
- `REFRESH_TOKEN_EXPIRE_SECONDS`: Refresh token TTL (default: 2592000)
- `BCRYPT_ROUNDS`: Password hashing cost (default: 12)
- `STORAGE_*`: MinIO connection details

## Testing Patterns

**Philosophy:** Direct function invocation with dependency fakes, no HTTP overhead.

**Example from `tests/test_upload_endpoint.py`:**
```python
# Create fake S3 client (in-memory storage)
class _FakeS3Client:
    uploaded_objects = {}
    def upload_fileobj(self, file, bucket, key):
        self.uploaded_objects[key] = file.read()

# Monkeypatch boto3 to return fake
monkeypatch.setattr("boto3.client", lambda *args, **kwargs: fake_client)

# Call route handler directly (no HTTP)
response = await upload_file(upload_file_obj)

# Assert both response and side effects
assert response.filename == "test.txt"
assert fake_client.uploaded_objects[response.key] == b"content"
```

**For auth tests**, use FastAPI's `TestClient` with dependency overrides:
```python
app.dependency_overrides[get_current_user] = lambda: fake_user
response = client.post("/upload", files={"file": ("test.txt", b"data")})
```

## Code Conventions

### Comments and Documentation

**This codebase has VERY extensive inline comments** explaining:
- What each section does
- Why architectural decisions were made
- Security implications
- How data flows through the system

When adding new features, maintain this level of documentation for learning purposes.

### Import Organization

Follow this order (as seen in existing files):
1. Standard library imports
2. Third-party imports (FastAPI, SQLAlchemy, etc.)
3. Local app imports (from `app.*`)

### Database Sessions

**Always use dependency injection** for database access:
```python
from app.core.deps import get_db

@router.post("/endpoint")
def endpoint(db: Session = Depends(get_db)):
    # db is auto-managed (commit/rollback/close handled by dependency)
    user = db.query(User).filter(...).first()
```

**Never create engine/session manually** in route handlers. The `get_db()` dependency handles lifecycle.

### Protected Routes

**Use the `get_current_user` dependency** for authentication:
```python
from app.core.deps import get_current_user

@router.get("/protected")
def protected_route(current_user: User = Depends(get_current_user)):
    # current_user is guaranteed valid User object
    # 401 raised automatically if token invalid/missing
```

## Common Gotchas

### Docker Networking

- Services reference each other by **container name**: `minio`, `api`
- From host machine, use `localhost:PORT`
- From containers, use `SERVICE_NAME:PORT` (e.g., `http://minio:9000`)

### SQLite Database Location

- Database file: `dev.db` in project root
- WAL files: `dev.db-shm`, `dev.db-wal` (created automatically)
- These files persist on host filesystem (survive container restarts)
- To reset database: `rm -f dev.db dev.db-shm dev.db-wal`

### Database Migrations

Currently using `Base.metadata.create_all()` on startup (simple, dev-friendly).

**For production:** Switch to Alembic migrations:
1. Install: `pip install alembic`
2. Init: `alembic init alembic`
3. Generate migration: `alembic revision --autogenerate -m "description"`
4. Apply: `alembic upgrade head`

Comment out `init_db()` in `app/main.py:90` when using Alembic.

### SQLite Limitations

- No concurrent writes (one writer at a time)
- WAL mode improves this (readers don't block writers)
- For high-concurrency production, consider PostgreSQL/MySQL

### Token Expiration

Access tokens are **15 minutes by default**. If testing and tokens keep expiring:
- Increase `ACCESS_TOKEN_EXPIRE_SECONDS` in `.env` for development
- Or implement auto-refresh logic in your client

### MinIO URLs

Presigned URLs use the `STORAGE_ENDPOINT` from environment. In Docker, this is `http://minio:9000` (internal network).

**For browser access**, URLs won't work from host machine. Options:
1. Change `STORAGE_ENDPOINT` to `http://localhost:9000`
2. Use MinIO console (http://localhost:9001) to download files
3. Implement download proxy endpoint in API

## Adding New Features

### Adding a New Model

1. Create model in `app/models/` (inherit from `Base`)
2. Create schemas in `app/schemas/` (Pydantic models)
3. Database tables auto-create on next startup (or use Alembic)

### Adding a New Protected Endpoint

```python
# In app/routers/your_router.py
from fastapi import APIRouter, Depends
from app.core.deps import get_current_user, get_db
from app.models.user import User

router = APIRouter(prefix="/your-prefix", tags=["your-tag"])

@router.get("/endpoint")
def your_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # current_user is authenticated
    # db is managed session
    return {"data": "response"}

# In app/main.py
from app.routers import your_router
app.include_router(your_router.router)
```

### Linking Files to Users

Currently files aren't tracked in database. To implement:

1. Create model `app/models/uploaded_file.py`:
```python
class UploadedFile(Base):
    __tablename__ = "uploaded_files"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    filename = Column(String, nullable=False)
    minio_key = Column(String, nullable=False, unique=True)
    size = Column(Integer)
    content_type = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

2. In `app/main.py:307` (after upload), save metadata:
```python
file_record = UploadedFile(
    user_id=current_user.id,
    filename=file.filename,
    minio_key=object_key,
    size=file.size,
    content_type=file.content_type
)
db.add(file_record)
db.commit()
```

3. Add `db: Session = Depends(get_db)` to upload_file parameters

## Frontend

The project includes a minimal browser-based frontend for easy testing and demonstration.

### Using the Frontend

1. **Start the application:**
   ```bash
   docker-compose up --build
   ```

2. **Open in browser:**
   - Navigate to http://localhost:8000
   - You'll see the login page

3. **Register a user (if needed):**
   - Use the API docs at http://localhost:8000/docs
   - Or via curl:
     ```bash
     curl -X POST http://localhost:8000/auth/register \
       -H "Content-Type: application/json" \
       -d '{"email":"user@example.com","password":"password123"}'
     ```

4. **Login:**
   - Enter your email and password
   - Click "Login"
   - Frontend stores JWT tokens in memory (not localStorage)

5. **Upload files:**
   - After login, the upload form appears
   - Select a file
   - Click "Upload"
   - Progress bar shows upload status
   - Results display with filename, key, and presigned URL

### Frontend Features

- **Token Management:**
  - Access tokens (15 min) and refresh tokens (30 days) stored in JavaScript memory
  - Automatic token refresh on 401 errors
  - Transparent retry after refresh

- **Upload Progress:**
  - Real-time progress bar using XMLHttpRequest
  - Shows percentage and status

- **Security:**
  - Tokens in memory only (lost on page refresh - safer than localStorage)
  - No CORS issues (frontend served from same origin)
  - All API calls use Bearer token authentication

### Frontend Files

```
frontend/
├── index.html  # UI layout (login form, upload form, status area)
├── app.js      # Auth logic, token management, upload handling
└── style.css   # Minimal styling
```

### Development Notes

- Frontend is served via FastAPI's `StaticFiles` mount
- API routes defined before static mount (no conflicts)
- No build step required (plain HTML/CSS/JS)
- Hot-reload works (changes to frontend/ files served immediately)

### Token Refresh Demo

To test automatic token refresh:
1. Login normally
2. Wait 15+ minutes for access token to expire
3. Try to upload a file
4. Frontend automatically refreshes token and retries upload
5. Upload succeeds without manual intervention

## Debugging Tips

**Check if services are healthy:**
```bash
docker-compose ps
```

**Restart API without rebuilding:**
```bash
docker-compose restart api
```

**Execute commands in running container:**
```bash
docker exec -it fastapi bash
# Now inside container
python -c "from app.core.config import get_settings; print(get_settings().DATABASE_URL)"
```

**View environment variables:**
```bash
docker exec fastapi env | grep -E "DATABASE|JWT|STORAGE"
```

**Inspect SQLite database:**
```bash
# View database schema
sqlite3 dev.db .schema

# Check if foreign keys are enabled (should return 1)
sqlite3 dev.db "PRAGMA foreign_keys;"

# Check journal mode (should return 'wal')
sqlite3 dev.db "PRAGMA journal_mode;"

# View all data
sqlite3 dev.db ".dump"
```

**Test JWT token manually:**
```bash
# Login and extract token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  | jq -r '.access_token')

# Use token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/auth/me
```
