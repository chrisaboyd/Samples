import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database connection URL

try:
    DATABASE_URL = os.getenv(
        "DB_CONN_STRING"
    )
except Exception as e:
    print(f"Error getting DB_CONN_STRING: {e}")
    raise e

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create a SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a Base class for declarative models
Base = declarative_base() 