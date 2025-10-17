# =============================================================================================
# APP/MAIN.PY - FASTAPI APPLICATION WITH AUTHENTICATION + MINIO
# =============================================================================================
# This is the entry point for your web API. It provides:
# - Authentication (register, login, JWT tokens)
# - File upload with MinIO (S3-compatible object storage)
# - Protected routes (require authentication)
#
# ARCHITECTURE:
# - Postgres: User accounts and refresh tokens
# - MinIO: File storage (uploaded files)
# - FastAPI: REST API server
# - JWT: Stateless authentication
#
# FLOW:
# 1. User registers or logs in → gets JWT tokens
# 2. User uploads file with access token → file stored in MinIO
# 3. Access token expires (15 min) → user refreshes with refresh token
# 4. User logs out → refresh token revoked in database
# =============================================================================================

import os
import time

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from botocore.config import Config
import boto3
from botocore.exceptions import ClientError

# -------------------------
# Import authentication components
# -------------------------
from app.core.db import init_db
from app.core.deps import get_current_user
from app.models.user import User
from app.routers import auth

# -------------------------
# Create FastAPI application
# -------------------------
app = FastAPI(
    title="File Upload API with Authentication",
    description="Secure file upload service with JWT authentication and MinIO storage",
    version="2.0.0",
)

# -------------------------
# Database initialization on startup
# -------------------------
@app.on_event("startup")
def on_startup():
    """
    Initialize database tables on application startup.

    WHAT THIS DOES:
    - Creates users table if it doesn't exist
    - Creates refresh_tokens table if it doesn't exist
    - Uses SQLAlchemy's Base.metadata.create_all()

    WHY ON STARTUP?
    - Ensures database schema is ready before first request
    - Idempotent: safe to run multiple times (CREATE IF NOT EXISTS)
    - Simple for development/learning (production should use Alembic migrations)

    PRODUCTION NOTE:
    - For production, use Alembic for migrations instead
    - Alembic tracks schema changes, supports rollbacks, data migrations
    - Command: `alembic upgrade head` (run in deployment script)

    DATABASE CREATION SQL (what this generates):
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(60) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            token_hash VARCHAR(64) UNIQUE NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            revoked BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL
        );
    """
    init_db()


# -------------------------
# Include authentication router
# -------------------------
# This adds all auth endpoints under /auth prefix:
# - POST /auth/register
# - POST /auth/login
# - POST /auth/refresh
# - POST /auth/logout
# - GET /auth/me
app.include_router(auth.router)


# =============================================================================================
# FILE UPLOAD ENDPOINT (must be defined before static files mount)
# =============================================================================================


# =============================================================================================
# PUBLIC ROUTES (no authentication required)
# =============================================================================================

# =============================================================================================
# PROTECTED ROUTES (authentication required)
# =============================================================================================
# Note: Frontend is now served via StaticFiles mount at the end of this file

# -------------------------
# Upload response schema
# -------------------------
class UploadResponse(BaseModel):
    filename: str
    key: str
    url: str | None
    status: str


# -------------------------
# Protected file upload endpoint
# -------------------------
@app.post("/upload", response_model=UploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),  # 🔒 AUTHENTICATION REQUIRED
):
    """
    Upload file to MinIO storage (PROTECTED - requires authentication).

    AUTHENTICATION:
    - Requires valid access token in Authorization header
    - Format: `Authorization: Bearer <access_token>`
    - get_current_user dependency validates token and loads user
    - If token is invalid/missing/expired → 401 Unauthorized

    FLOW:
    1. Validate access token (get_current_user dependency)
    2. Accept file upload from authenticated user
    3. Store file in MinIO with timestamped filename
    4. Generate presigned download URL (1 hour expiry)
    5. Return file metadata + download URL

    SECURITY NOTES:
    - Only authenticated users can upload files
    - Each file is associated with the user who uploaded it (via current_user)
    - TODO: Store file metadata in database (link file to user)
    - TODO: Add file size limits (prevent abuse)
    - TODO: Add file type validation (block executables, etc.)
    - TODO: Scan files for malware before storing

    REQUEST:
        POST /upload
        Authorization: Bearer eyJhbGci...
        Content-Type: multipart/form-data

        file=<binary data>

    RESPONSE (200 OK):
        {
            "filename": "document.pdf",
            "key": "1704067200-document.pdf",
            "url": "http://minio:9000/uploads/1704067200-document.pdf?...",
            "status": "uploaded"
        }

    ERRORS:
        401 Unauthorized: Missing or invalid access token
        500 Internal Server Error: MinIO upload failed
    """

    # NOTE: If we reach this point, current_user is valid (authenticated)
    # get_current_user dependency raises 401 if token is invalid

    # -------------------------
    # FUTURE ENHANCEMENT: Link file to user
    # -------------------------
    # You could store file metadata in database:
    #   file_record = UploadedFile(
    #       user_id=current_user.id,
    #       filename=file.filename,
    #       minio_key=object_key,
    #       size=file.file.size,
    #       content_type=file.content_type,
    #   )
    #   db.add(file_record)
    #   db.commit()

    # -------------------------
    # STEP 1: Load MinIO configuration
    # -------------------------
    endpoint = os.getenv("STORAGE_ENDPOINT", "http://minio:9000")
    access_key = os.getenv("STORAGE_ACCESS_KEY")
    secret_key = os.getenv("STORAGE_SECRET_KEY")
    bucket = os.getenv("STORAGE_BUCKET", "uploads")
    region = os.getenv("STORAGE_REGION", "us-east-1")

    if not access_key or not secret_key:
        raise HTTPException(status_code=500, detail="S3 credentials not configured")

    # -------------------------
    # STEP 2: Create S3 client
    # -------------------------
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
        config=Config(signature_version="s3v4"),
    )

    # -------------------------
    # STEP 3: Ensure bucket exists
    # -------------------------
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        try:
            s3.create_bucket(Bucket=bucket)
        except ClientError as e:
            raise HTTPException(status_code=500, detail=f"Could not create/access bucket: {str(e)}")

    # -------------------------
    # STEP 4: Build unique object key
    # -------------------------
    # Include user ID in filename for organization:
    # Format: {timestamp}-{user_id}-{filename}
    # Example: 1704067200-123e4567-document.pdf
    timestamp = int(time.time())
    object_key = f"{timestamp}-{current_user.id}-{file.filename}"

    # -------------------------
    # STEP 5: Upload file to MinIO
    # -------------------------
    try:
        s3.upload_fileobj(file.file, bucket, object_key)
    except ClientError as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    finally:
        try:
            file.file.close()
        except Exception:
            pass

    # -------------------------
    # STEP 6: Generate presigned download URL
    # -------------------------
    try:
        presigned = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": object_key},
            ExpiresIn=3600,  # 1 hour
        )
    except ClientError:
        presigned = None

    # -------------------------
    # STEP 7: Return response
    # -------------------------
    return UploadResponse(
        filename=file.filename,
        key=object_key,
        url=presigned,
        status="uploaded"
    )


# =============================================================================================
# STATIC FILES (serve frontend) - MUST BE LAST
# =============================================================================================
# Mount static files for frontend
# This serves index.html, app.js, style.css from frontend/ directory
#
# IMPORTANT: This must come AFTER all API routes to avoid conflicts
# Order matters in FastAPI - routes are matched top-to-bottom
# If this were first, it would catch all requests before API routes
#
# MOUNTING DETAILS:
# - directory="frontend" → serve files from frontend/ folder
# - html=True → serve index.html for directory requests (/, /login, etc.)
# - name="frontend" → internal name for FastAPI
#
# ACCESSIBLE URLS:
# - http://localhost:8000/ → serves frontend/index.html
# - http://localhost:8000/app.js → serves frontend/app.js
# - http://localhost:8000/style.css → serves frontend/style.css
#
# API ROUTES STILL WORK:
# - /auth/register, /auth/login, /upload, etc. still accessible
# - They're matched before the static mount reaches them
try:
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
    print("✅ Frontend static files mounted successfully")
except Exception as e:
    print(f"⚠️  Failed to mount frontend: {e}")
    print("   Frontend files may not be available. API routes will still work.")


# =============================================================================================
# EXAMPLE: Additional protected endpoints you might add
# =============================================================================================

# @app.get("/my-files")
# async def list_my_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """List all files uploaded by the authenticated user."""
#     files = db.query(UploadedFile).filter(UploadedFile.user_id == current_user.id).all()
#     return files
#
# @app.delete("/files/{file_id}")
# async def delete_file(file_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     """Delete a file (only if owned by current user)."""
#     file = db.query(UploadedFile).filter(
#         UploadedFile.id == file_id,
#         UploadedFile.user_id == current_user.id
#     ).first()
#     if not file:
#         raise HTTPException(404, "File not found or access denied")
#     # Delete from MinIO and database
#     s3.delete_object(Bucket=bucket, Key=file.minio_key)
#     db.delete(file)
#     db.commit()
#     return {"message": "File deleted"}
