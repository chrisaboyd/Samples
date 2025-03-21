from fastapi import FastAPI, HTTPException, status, Request
from pydantic import BaseModel
import httpx
import os
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define RAG service URL (can be overridden with environment variable)
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://rag:8081")
if not RAG_SERVICE_URL:
    raise Exception("RAG_SERVICE_URL is not set")

class MessagePayload(BaseModel):
    message: str

app = FastAPI(title="API Service")

# Middleware to log requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(f"API service received request: {request.method} {request.url.path} - Took {process_time:.4f}s")
    return response

@app.get("/")
def read_root():
    """Return 404 for the root route"""
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@app.post("/api/hello")
async def get_hello_world(payload: MessagePayload):
    """Get the 'hello world' message via the RAG service - requires a message payload"""
    logger.info(f"Hello endpoint accessed with message: {payload.message}")
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Making request to RAG service: {RAG_SERVICE_URL}/rag/message")
            response = await client.post(
                f"{RAG_SERVICE_URL}/rag/message",
                json={"query": payload.message},
                timeout=10.0
            )
            response.raise_for_status()
            data = response.json()
            logger.info(f"Received response from RAG: {data}")
            # Pass through the rag_processed field if it exists
            rag_processed = data.get("rag_processed", False)
            return {"message": data["content"], "received": payload.message, "via_rag": rag_processed}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise HTTPException(status_code=404, detail="Hello world message not found")
            raise HTTPException(status_code=500, detail=f"RAG service error: {str(e)}")
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"RAG service unavailable: {str(e)}")


@app.get("/api/users")
async def get_users(skip: int = 0, limit: int = 100):
    """Get a list of users via the RAG service"""
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Making request to RAG service for users: {RAG_SERVICE_URL}/rag/users")
            response = await client.get(
                f"{RAG_SERVICE_URL}/rag/users",
                params={"skip": skip, "limit": limit},
                timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=str(e))
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"RAG service unavailable: {str(e)}")


@app.get("/api/items")
async def get_items(skip: int = 0, limit: int = 100):
    """Get a list of items via the RAG service"""
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Making request to RAG service for items: {RAG_SERVICE_URL}/rag/items")
            response = await client.get(
                f"{RAG_SERVICE_URL}/rag/items",
                params={"skip": skip, "limit": limit},
                timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=str(e))
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"RAG service unavailable: {str(e)}")


@app.get("/api/items/{item_id}")
async def get_item(item_id: int):
    """Get a specific item by ID via the RAG service"""
    async with httpx.AsyncClient() as client:
        try:
            logger.info(f"Making request to RAG service for item {item_id}: {RAG_SERVICE_URL}/rag/items/{item_id}")
            response = await client.get(
                f"{RAG_SERVICE_URL}/rag/items/{item_id}",
                timeout=10.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise HTTPException(status_code=404, detail="Item not found")
            raise HTTPException(status_code=e.response.status_code, detail=str(e))
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"RAG service unavailable: {str(e)}")


@app.get("/api/health")
async def health_check():
    """Check the health of the API and RAG service"""
    async with httpx.AsyncClient() as client:
        try:
            api_status = "OK"
            logger.info(f"Making health check request to RAG service: {RAG_SERVICE_URL}/health")
            response = await client.get(f"{RAG_SERVICE_URL}/health", timeout=5.0)
            response.raise_for_status()
            rag_status = response.json().get("status", "Unknown")
            return {"api_status": api_status, "rag_status": rag_status}
        except:
            return {"api_status": api_status, "rag_status": "Unavailable"}