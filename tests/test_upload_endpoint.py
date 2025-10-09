"""Tests for the ``/upload`` endpoint.

This module demonstrates how to exercise the FastAPI route that uploads
files to the MinIO (S3-compatible) backend.  The test below is intentionally
written as an **async unit-style test with dependency fakes**: it invokes the
route handler directly (no HTTP client required) while replacing the boto3
client with an in-memory stub.  This keeps the focus on our business logic
while still observing the same code path FastAPI would run during a request.
"""

# ============================================================================
# Imports – Every dependency is annotated with a comment that explains *why*
#            it participates in the test.
# ============================================================================
import asyncio  # Lets us run the async route handler inside a synchronous test.
import io  # Provides in-memory byte streams so we can fake an uploaded file.
import pathlib  # Used to resolve the project root for importing ``app``.
import sys  # Allows us to tweak ``sys.path`` so Python can locate the package.
from typing import Any, Dict

import pytest  # Pytest is the test runner; provides fixtures like ``monkeypatch``.
from fastapi import UploadFile  # ``upload_file`` expects a FastAPI UploadFile instance.

# Ensure ``app`` is importable when pytest runs from the repository root.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:  # pragma: no branch - deterministic guard
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import upload_file  # The FastAPI route function under test.


class _FakeS3Client:
    """Minimal stand-in for the boto3 S3 client used by ``upload_file``.

    The production code relies on the boto3 client to perform four operations:

    * ``head_bucket`` – confirm the bucket exists.
    * ``create_bucket`` – create the bucket if the check fails.
    * ``upload_fileobj`` – stream the bytes into object storage.
    * ``generate_presigned_url`` – hand back a temporary download link.

    This stub implements those behaviours with simple Python logic so our test
    can run without network access or a real MinIO instance.  It also records
    which methods have been invoked, allowing assertions if needed.
    """

    def __init__(self) -> None:
        self.uploaded_objects: Dict[str, bytes] = {}
        self.generate_presigned_url_called: bool = False

    # The real boto3 client raises ``ClientError`` when a bucket is missing. For
    # simplicity, our stub does nothing—the code under test only needs the call
    # to succeed in order to proceed to the upload step.
    def head_bucket(self, Bucket: str) -> None:  # pragma: no cover - nothing to do
        return None

    # If ``head_bucket`` were to raise an exception, ``upload_file`` would try
    # to create the bucket.  Keeping the method in our stub ensures the code
    # path remains valid if future tests simulate that behaviour.
    def create_bucket(self, Bucket: str) -> None:  # pragma: no cover - not exercised
        return None

    def upload_fileobj(self, fileobj: Any, bucket: str, key: str) -> None:
        """Persist the uploaded bytes in memory.

        ``fileobj`` behaves like a regular file handle.  We read it into memory
        to emulate the upload side-effect.
        """

        # ``read`` consumes the remaining bytes from the in-memory stream.
        self.uploaded_objects[key] = fileobj.read()

    def generate_presigned_url(self, operation: str, Params: Dict[str, str], ExpiresIn: int) -> str:
        """Return a deterministic, fake presigned URL for assertions."""

        self.generate_presigned_url_called = True
        bucket = Params["Bucket"]
        key = Params["Key"]
        # Construct a predictable URL so the test can validate the response.
        return f"https://example.com/{bucket}/{key}?expires={ExpiresIn}"


@pytest.fixture
def fake_boto3_client(monkeypatch: pytest.MonkeyPatch) -> _FakeS3Client:
    """Patch ``boto3.client`` so the endpoint talks to our in-memory stub.

    The ``upload_file`` route creates a new boto3 client on every request. By
    monkeypatching the constructor, we ensure that the application receives an
    instance of :class:`_FakeS3Client` rather than the real networked client.
    The fixture returns the stub for further inspection inside individual tests.
    """

    fake_client = _FakeS3Client()

    # ``lambda *_, **__: fake_client`` ignores all positional/keyword arguments
    # because the production code passes endpoint configuration details.
    monkeypatch.setattr("boto3.client", lambda *_, **__: fake_client)

    return fake_client


@pytest.fixture
def configured_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the environment configuration required by ``upload_file``.

    The application validates that the S3 credentials exist in the environment;
    this fixture supplies placeholder values so the handler does not raise an
    HTTP 500 error before we reach the upload logic.
    """

    monkeypatch.setenv("STORAGE_ACCESS_KEY", "test-access")
    monkeypatch.setenv("STORAGE_SECRET_KEY", "test-secret")
    monkeypatch.setenv("STORAGE_BUCKET", "test-bucket")


# ============================================================================
# Test cases
# ============================================================================

# Run the test using the built-in asyncio backend only (Trio is not installed).
def test_upload_file_happy_path(configured_env: None, fake_boto3_client: _FakeS3Client) -> None:
    """Async test covering the happy-path behaviour of ``/upload``.

    This is an **async unit test with fakes** because it directly invokes the
    FastAPI route function while swapping the external dependency (boto3) for a
    controlled stub.  The goal is to verify that the handler returns the
    expected response contract when the file upload succeeds.
    """

    # ------------------------------------------------------------------
    # Arrange: build an in-memory file that mimics what a browser would send.
    # ------------------------------------------------------------------
    file_content = b"hello fastapi"
    file_to_upload = io.BytesIO(file_content)
    upload = UploadFile(filename="greeting.txt", file=file_to_upload)

    # ------------------------------------------------------------------
    # Act: invoke the route handler exactly as FastAPI would call it.
    # ------------------------------------------------------------------
    response_model = asyncio.run(upload_file(upload))

    # ------------------------------------------------------------------
    # Assert: verify the response payload and fake S3 side-effects.
    # ------------------------------------------------------------------
    assert response_model.filename == "greeting.txt"
    assert response_model.status == "uploaded"
    assert response_model.key.endswith("greeting.txt")

    # ``generate_presigned_url`` returns our deterministic URL; we merely ensure
    # the shape matches what the application advertises.
    assert response_model.url and response_model.url.startswith("https://example.com/test-bucket/")

    # Confirm the fake S3 client received and stored the bytes we uploaded.
    stored_bytes = fake_boto3_client.uploaded_objects[response_model.key]
    assert stored_bytes == file_content
    assert fake_boto3_client.generate_presigned_url_called is True
