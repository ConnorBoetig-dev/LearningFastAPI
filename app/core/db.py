# =============================================================================================
# APP/CORE/DB.PY - SQLALCHEMY DATABASE ENGINE AND SESSION MANAGEMENT
# =============================================================================================
# This module sets up the database connection layer using SQLAlchemy ORM.
#
# KEY CONCEPTS:
# - Engine: Manages the connection pool to SQLite (created once at startup)
# - SessionLocal: Factory for creating database sessions (one per request)
# - Base: Parent class for all ORM models (User, RefreshToken, etc.)
# - get_db(): FastAPI dependency that provides a session per request
#
# FLOW:
# 1. Engine connects to DATABASE_URL from config
# 2. Each API request calls get_db() to get a fresh session
# 3. Request uses session to query/insert/update data
# 4. Session auto-closes after request (even if error occurs)
# 5. On startup, Base.metadata.create_all() creates tables if missing
# =============================================================================================

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.core.config import get_settings

# -------------------------
# Load configuration
# -------------------------
settings = get_settings()

# -------------------------
# STEP 1: Create the database engine
# -------------------------
# The engine is the "connection pool manager" - it maintains a pool of connections
# to SQLite that can be reused across requests for better performance.
#
# WHY connect_args with check_same_thread=False?
# - SQLite by default only allows one thread to access it
# - FastAPI uses multiple threads for concurrent requests
# - check_same_thread=False allows multi-threaded access (safe with proper session handling)
#
# WHAT IS pool_pre_ping?
# - Before using a connection, SQLAlchemy sends a lightweight query to check it's alive
# - Prevents "database is locked" errors from stale connections
# - Slight performance cost but essential for reliability
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},  # Allow multi-threaded access for FastAPI
    pool_pre_ping=True,  # Test connections before use (prevents stale connection errors)
)

# -------------------------
# SQLITE OPTIMIZATIONS: Enable WAL mode and foreign keys
# -------------------------
# WAL (Write-Ahead Logging) improves concurrency and performance:
# - Readers don't block writers, writers don't block readers
# - Better crash recovery
# - Faster writes (no need to update main DB file immediately)
#
# Foreign keys are OFF by default in SQLite, we enable them for data integrity:
# - CASCADE deletes work (delete user → delete their tokens)
# - Prevents orphaned records
#
# PRAGMA journal_mode=WAL:
# - Changes SQLite's journaling mechanism for better concurrency
# - Creates a .db-wal file alongside dev.db
#
# PRAGMA synchronous=NORMAL:
# - Balances safety and speed (FULL is slower, OFF is risky)
# - Safe for most applications (data loss only in OS crash scenarios)
#
# PRAGMA foreign_keys=ON:
# - Enforces foreign key constraints (CASCADE, RESTRICT, etc.)
# - Essential for User → RefreshToken relationship
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """
    Configure SQLite connection settings on each new connection.

    This event listener runs whenever SQLAlchemy creates a new database connection.
    It executes SQLite PRAGMA commands to optimize performance and enable features.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON;")  # Enable foreign key constraints
    cursor.execute("PRAGMA journal_mode=WAL;")  # Enable Write-Ahead Logging for concurrency
    cursor.execute("PRAGMA synchronous=NORMAL;")  # Balance safety and performance
    cursor.close()

# -------------------------
# STEP 2: Create session factory
# -------------------------
# SessionLocal is a *class* (not an instance) that creates new Session objects.
# Each request gets its own session to keep database operations isolated.
#
# WHAT DO THESE PARAMETERS MEAN?
# - autocommit=False: Don't auto-commit after every statement (we control commits manually)
# - autoflush=False: Don't auto-flush changes before queries (explicit is better than implicit)
# - bind=engine: Connect sessions to our Postgres engine
#
# WHY NOT AUTOCOMMIT?
# - Gives us control: we can group multiple operations into one transaction
# - If error occurs, we can rollback the entire transaction (all-or-nothing)
SessionLocal = sessionmaker(
    autocommit=False,  # Explicit commits give us transaction control
    autoflush=False,   # Explicit flushes prevent unexpected queries
    bind=engine,       # Connect to our Postgres engine
)

# -------------------------
# STEP 3: Create declarative base for models
# -------------------------
# Base is the parent class for all ORM models (User, RefreshToken, etc.).
# When we define `class User(Base)`, SQLAlchemy:
# - Tracks the model in Base.metadata
# - Generates SQL CREATE TABLE statements from the model
# - Provides .query() methods for database operations
#
# USAGE EXAMPLE:
#   from app.core.db import Base
#   class User(Base):
#       __tablename__ = "users"
#       id = Column(Integer, primary_key=True)
Base = declarative_base()


# -------------------------
# STEP 4: Dependency for FastAPI routes
# -------------------------
def get_db() -> Session:
    """
    FastAPI dependency that provides a database session for each request.

    LIFECYCLE:
    1. Request arrives at endpoint decorated with Depends(get_db)
    2. FastAPI calls this function, creating a new session
    3. Session is injected into the route handler function
    4. Route uses session to query/insert/update data
    5. After route completes (or errors), `finally` block closes session
    6. Connection returns to the pool for reuse

    USAGE IN ROUTES:
        @app.post("/users/")
        def create_user(db: Session = Depends(get_db)):
            user = User(email="test@example.com")
            db.add(user)
            db.commit()
            db.refresh(user)  # Load auto-generated fields like id
            return user

    ERROR HANDLING:
    - If route raises an exception, `finally` still runs (session always closes)
    - You should manually rollback on errors: `db.rollback()`
    - Or use try/except in your route handler

    WHY YIELD INSTEAD OF RETURN?
    - `yield` makes this a generator, allowing FastAPI to run cleanup code
    - Code after `yield` runs after the request finishes
    - Similar to try/finally pattern but cleaner with FastAPI's Depends()
    """
    # Create a new session from the factory
    db = SessionLocal()
    try:
        # Provide session to the route handler
        # Everything between `yield` and `finally` is the request processing
        yield db
    finally:
        # Cleanup: close session and return connection to pool
        # This runs even if the route raises an exception
        db.close()


# -------------------------
# STEP 5: Database initialization helper
# -------------------------
def init_db() -> None:
    """
    Initialize the database by creating all tables defined in models.

    WHEN TO CALL THIS?
    - On application startup (in main.py @app.on_event("startup"))
    - Before running tests (to create test database schema)

    WHAT DOES IT DO?
    - Inspects all classes that inherit from Base (User, RefreshToken, etc.)
    - Generates CREATE TABLE IF NOT EXISTS statements
    - Executes them against the database

    WHY NOT USE THIS IN PRODUCTION?
    - For production, use Alembic migrations instead:
      * Tracks schema changes over time (version control for your database)
      * Supports rollbacks (undo a migration if something goes wrong)
      * Handles complex migrations (rename columns, data transformations)
    - This is fine for development and prototyping though!

    ALEMBIC MIGRATION EXAMPLE (for later):
        # Generate migration after changing a model
        $ alembic revision --autogenerate -m "Add email_verified column"
        # Apply migration to database
        $ alembic upgrade head
        # Rollback if needed
        $ alembic downgrade -1

    TODO: Set up Alembic for production deployments
    """
    # Import all models here so they're registered with Base.metadata
    # This must happen before create_all() so SQLAlchemy knows about them
    from app.models import user, token  # noqa: F401 (imported for side effects)

    # Create all tables that don't exist yet
    # SQL: CREATE TABLE IF NOT EXISTS users (...); CREATE TABLE IF NOT EXISTS refresh_tokens (...);
    Base.metadata.create_all(bind=engine)
