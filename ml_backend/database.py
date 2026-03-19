import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Supabase Postgres (primary): SUPABASE_URL or DATABASE_URL
DATABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "SUPABASE_URL or DATABASE_URL is not set. Add it to your .env file.\n"
        "Supabase: Project Settings → Database → Connection string (URI)"
    )

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    connect_args={"options": "-c timezone=utc"},
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
