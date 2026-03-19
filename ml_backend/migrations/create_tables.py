import sys
import os

# Add the parent directory to the path so we can import from the main app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import engine, Base
import db_models

def run_migration():
    """
    Creates all database tables in Supabase based on your SQLAlchemy models.
    """
    print("🚀 Connecting to Supabase database...")
    print("🛠️ Creating tables if they don't exist...")
    
    # This will parse db_models.py and create any tables that don't yet exist
    Base.metadata.create_all(bind=engine)
    
    print("✅ Database migration complete! All tables are ready.")

if __name__ == "__main__":
    run_migration()
