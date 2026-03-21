import sys
import os

# Add the parent directory to the path so we can import from the main app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import text

from database import engine, Base
import db_models  # noqa: F401 — register all models on Base.metadata
from storage_supabase import empty_bucket


def clean_database():
    """
    Deletes all rows from every table registered in ``db_models`` (including
    ``android_logs``, ``ingested_logs``, ``scans``, etc.) and empties the bucket.
    Schema unchanged; no DROP/CREATE.
    """
    print("🚀 Connecting to Supabase...")

    print("🗑️ Truncating all application tables (keeping schema)...")
    names = sorted(Base.metadata.tables.keys())
    if names:
        print(f"   Tables: {', '.join(names)}")
        quoted = ", ".join(f'"{n}"' for n in names)
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {quoted} RESTART IDENTITY CASCADE"))
    else:
        print("⚠️ No tables in metadata — skipped DB truncate.")

    print("🪣 Emptying Supabase Storage Bucket...")
    success = empty_bucket()
    if success:
        print("✅ Bucket emptied successfully.")
    else:
        print("⚠️ Failed or skipped emptying bucket (check logs/env keys).")

    print("✅ Cleanup finished (tables empty, schema intact).")

if __name__ == "__main__":
    # If a command line arg '--force' is provided, skip the prompt
    if len(sys.argv) > 1 and sys.argv[1] == '--force':
        clean_database()
    else:
        confirm = input("Truncate all DB rows + empty bucket? (yes/no): ")
        if confirm.lower() == 'yes':
            clean_database()
        else:
            print("Canceled.")