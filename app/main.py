# =============================================================================================
# APP/MAIN.PY - YOUR FASTAPI APPLICATION
# =============================================================================================
# This is the entry point for your web API. It defines:
# - Routes (URL endpoints like "/" and "/health")
# - What happens when someone visits those URLs
#
# CONNECTION FLOW:
# 1. docker-compose.yml runs: uvicorn app.main:app
# 2. uvicorn imports this file and looks for the "app" object
# 3. FastAPI handles incoming HTTP requests and calls your functions
# 4. Eventually this will talk to MinIO using boto3 (imported from requirements.txt)
# =============================================================================================

# -------------------------
# Imports - Standard FastAPI boilerplate
# -------------------------
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse

# Create the main FastAPI application instance
# This "app" object is what uvicorn looks for (see docker-compose.yml command)
app = FastAPI()

# -------------------------
# ROUTE 1: Home page with upload form
# -------------------------
# @app.get("/") means: when someone visits http://localhost:8000/, run this function
# response_class=HTMLResponse tells FastAPI to return HTML instead of JSON
@app.get("/", response_class=HTMLResponse)
def read_root():
    # Returns a simple HTML page with a file upload form
    # The form POSTs to /upload (see route below)
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>mini.io</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 600px;
                margin: 50px auto;
                padding: 20px;
            }
            h1 {
                color: #333;
            }
        </style>
    </head>
    <body>
        <h1>mini.io</h1>
        <p>Simple file upload service</p>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    """

# -------------------------
# ROUTE 2: Handle file uploads (placeholder)
# -------------------------
# @app.post("/upload") means: when someone POSTs to /upload, run this function
# FastAPI automatically parses the uploaded file and passes it as the "file" parameter
@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # TODO: This will eventually:
    # 1. Read the uploaded file from the request
    # 2. Use boto3 to upload it to MinIO (using STORAGE_ENDPOINT from .env)
    # 3. Return a success message with the file URL
    return {"filename": file.filename, "status": "upload coming soon"}
