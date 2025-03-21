import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database connection URL (can be overridden with environment variable)
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://api_user:api_password@postgres:5432/api_db"
)

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create a SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a Base class for declarative models
Base = declarative_base() 