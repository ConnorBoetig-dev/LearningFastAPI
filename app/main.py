# =============================================================================================
# APP/MAIN.PY - YOUR FASTAPI APPLICATION WITH MINIO INTEGRATION
# =============================================================================================
# This is the entry point for your web API. It defines:
# - Routes (URL endpoints like "/" and "/upload")
# - File upload handling with MinIO (S3-compatible object storage)
# - Environment-based configuration (reads from .env via docker-compose)
#
# CONNECTION FLOW:
# 1. docker-compose.yml runs: uvicorn app.main:app
# 2. uvicorn imports this file and looks for the "app" object
# 3. FastAPI handles incoming HTTP requests and calls your functions
# 4. boto3 library communicates with MinIO using the S3 API
# 5. Files are stored in MinIO and presigned URLs are returned for access
# =============================================================================================

# -------------------------
# Imports - What each library does
# -------------------------
import os          # Read environment variables (STORAGE_ENDPOINT, etc.)
import time        # Generate timestamps for unique filenames

from fastapi import FastAPI, File, UploadFile, HTTPException  # Web framework
from fastapi.responses import HTMLResponse                     # Serve HTML pages
from pydantic import BaseModel                                 # Define response schemas

from botocore.config import Config           # Configure S3 client settings
import boto3                                  # AWS SDK (works with MinIO too!)
from botocore.exceptions import ClientError  # Handle S3/MinIO errors gracefully

# -------------------------
# Create the FastAPI application
# -------------------------
# This "app" object is what uvicorn looks for (see docker-compose.yml command)
app = FastAPI()

# -------------------------
# ROUTE 1: Home page with upload form
# -------------------------
# @app.get("/") means: when someone visits http://localhost:8000/, run this function
# response_class=HTMLResponse tells FastAPI to return HTML instead of JSON
@app.get("/", response_class=HTMLResponse)
def read_root():
    """
    Returns a simple HTML page with a file upload form.
    The form POSTs to /upload endpoint when user clicks "Upload" button.
    """
    return """
    <!DOCTYPE html><html><body>
      <h1>mini.io</h1>
      <p>Simple file upload service</p>
      <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required><button type="submit">Upload</button>
      </form>
    </body></html>
    """

# -------------------------
# Response Model - Defines the JSON structure returned by /upload
# -------------------------
# Pydantic models provide:
# - Type validation (ensures responses match this structure)
# - Auto-generated API documentation in /docs
# - Clear contract for frontend developers
class UploadResponse(BaseModel):
    filename: str       # Original name of uploaded file
    key: str            # Object key in MinIO (includes timestamp)
    url: str | None     # Presigned URL for downloading (expires in 1 hour)
    status: str         # Upload status message

# -------------------------
# ROUTE 2: Handle file uploads to MinIO
# -------------------------
# @app.post("/upload") means: when someone POSTs to /upload, run this function
# response_model=UploadResponse ensures the response matches our schema above
@app.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """
    Receives a file upload, stores it in MinIO, and returns a download URL.

    FLOW:
    1. Read configuration from environment variables
    2. Validate credentials exist
    3. Connect to MinIO using boto3 S3 client
    4. Ensure the bucket exists (create if needed)
    5. Upload file with timestamped filename
    6. Generate a presigned URL for downloading
    7. Return JSON response with file details
    """

    # -------------------------
    # STEP 1: Load configuration from environment
    # -------------------------
    # These come from .env file → docker-compose.yml → container environment
    # Uses os.getenv(key, default) to provide fallback values
    endpoint = os.getenv("STORAGE_ENDPOINT", "http://minio:9000")  # MinIO server address
    access_key = os.getenv("STORAGE_ACCESS_KEY")                   # MinIO username (like AWS access key)
    secret_key = os.getenv("STORAGE_SECRET_KEY")                   # MinIO password (like AWS secret key)
    bucket = os.getenv("STORAGE_BUCKET", "uploads")                # Bucket name (like a folder)
    region = os.getenv("STORAGE_REGION", "us-east-1")              # Required by S3 API (MinIO ignores this)

    # -------------------------
    # STEP 2: Validate credentials are configured
    # -------------------------
    # If .env is missing or incomplete, fail early with a clear error
    if not access_key or not secret_key:
        raise HTTPException(status_code=500, detail="S3 credentials not configured")

    # -------------------------
    # STEP 3: Create S3 client configured for MinIO
    # -------------------------
    # boto3 is Amazon's SDK, but it works with any S3-compatible service (like MinIO!)
    # endpoint_url tells boto3 to use MinIO instead of AWS
    # signature_version="s3v4" is required for presigned URLs
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint,                  # Point to MinIO instead of AWS
        aws_access_key_id=access_key,           # MinIO username
        aws_secret_access_key=secret_key,       # MinIO password
        region_name=region,                     # Required by S3 protocol
        config=Config(signature_version="s3v4"), # Use v4 signatures for presigned URLs
    )

    # -------------------------
    # STEP 4: Ensure bucket exists (create if missing)
    # -------------------------
    # Buckets are like top-level folders in S3/MinIO
    # head_bucket checks if bucket exists (throws ClientError if not)
    try:
        s3.head_bucket(Bucket=bucket)  # Check if bucket exists
    except ClientError:
        # Bucket doesn't exist, try to create it
        try:
            s3.create_bucket(Bucket=bucket)
        except ClientError as e:
            # Creation failed (permissions issue, network error, etc.)
            raise HTTPException(status_code=500, detail=f"Could not create/access bucket: {str(e)}")

    # -------------------------
    # STEP 5: Build unique object key (filename in MinIO)
    # -------------------------
    # Prefix with Unix timestamp to avoid filename collisions
    # Example: 1704067200-myfile.pdf
    timestamp = int(time.time())
    object_key = f"{timestamp}-{file.filename}"

    # -------------------------
    # STEP 6: Upload file stream to MinIO
    # -------------------------
    # upload_fileobj streams the file (memory-efficient for large uploads)
    # file.file is the actual file-like object from the HTTP request
    try:
        s3.upload_fileobj(file.file, bucket, object_key)
    except ClientError as e:
        # Upload failed (network issue, disk full, permissions, etc.)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    finally:
        # Always close the file handle to free resources
        try:
            file.file.close()
        except Exception:
            pass  # Ignore close errors (file might already be closed)

    # -------------------------
    # STEP 7: Generate presigned URL for downloading
    # -------------------------
    # Presigned URLs allow temporary access without credentials
    # Valid for 3600 seconds (1 hour) - after that, link expires
    try:
        presigned = s3.generate_presigned_url(
            "get_object",                                    # Operation type (download)
            Params={"Bucket": bucket, "Key": object_key},    # Which file to download
            ExpiresIn=3600,                                  # URL valid for 1 hour
        )
    except ClientError:
        # If presigned URL generation fails, just return None
        # File is still uploaded successfully, just no download link
        presigned = None

    # -------------------------
    # STEP 8: Return success response
    # -------------------------
    # FastAPI automatically serializes this to JSON based on UploadResponse model
    return UploadResponse(
        filename=file.filename,  # Original filename
        key=object_key,          # Timestamped key in MinIO
        url=presigned,           # Download URL (or None)
        status="uploaded"        # Success message
    )
