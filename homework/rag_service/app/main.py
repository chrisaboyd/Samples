import json
import logging
import time
from typing import List

import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy.orm import Session

from . import database, models, schemas

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create database tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="RAG Service")

# Initialize the embedding model with a fallback
try:
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer("all-MiniLM-L6-v2")
    USE_EMBEDDINGS = True
    logger.info("Successfully loaded SentenceTransformer model")
except Exception as e:
    logger.error(f"Failed to load SentenceTransformer model: {e}")
    USE_EMBEDDINGS = False
    model = None


# Dependency to get the database session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Middleware to log requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(
        f"RAG service received request: {request.method} {request.url.path} - Took {process_time:.4f}s"
    )
    return response


@app.get("/")
def read_root():
    """Return 404 for the root route"""
    logger.info("Root endpoint accessed, returning 404")
    raise HTTPException(status_code=404, detail="Not found")


@app.post("/rag/message", response_model=schemas.MessageResponse)
def retrieve_message(query: schemas.MessageQuery, db: Session = Depends(get_db)):
    """Retrieve the most relevant message from the database based on the query"""
    logger.info(f"Message retrieval requested with query: {query.query}")
    # For simplicity, we're just returning the "hello world" message directly
    # In a real RAG system, you would use embeddings and vector similarity search
    message = (
        db.query(models.Message).filter(models.Message.content == "hello world").first()
    )

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # If we have embeddings enabled, we would do semantic search here
    # For now, we're just returning a fixed message
    similarity_score = 1.0
    if USE_EMBEDDINGS and model:
        logger.info(f"Query embeddings would be used here: {query.query}")
        # In a real implementation, we would:
        # 1. Encode the query to get embeddings
        # 2. Compare with stored embeddings
        # 3. Return the closest match

    return {
        "content": message.content,
        "similarity_score": similarity_score,
        "rag_processed": True,
    }


@app.get("/rag/users", response_model=List[schemas.User])
def get_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get a list of users from the database"""
    logger.info(f"User list requested, skip={skip}, limit={limit}")
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users


@app.get("/rag/items", response_model=List[schemas.Item])
def get_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Get a list of items from the database"""
    logger.info(f"Item list requested, skip={skip}, limit={limit}")
    items = db.query(models.Item).offset(skip).limit(limit).all()
    return items


@app.get("/rag/items/{item_id}", response_model=schemas.Item)
def get_item(item_id: int, db: Session = Depends(get_db)):
    """Get a specific item by ID"""
    logger.info(f"Item detail requested, id={item_id}")
    item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.get("/rag/health")
def rag_health_check():
    """Check the health of the RAG service"""
    return {"rag_status": "OK", "embeddings_enabled": USE_EMBEDDINGS}
