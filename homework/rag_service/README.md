# RAG Service

This is a Retrieval Augmented Generation (RAG) service that sits between the API service and the database, serving as an intermediary that handles data retrieval, processing, and vector-based search.

## Features

- Connects to PostgreSQL database to retrieve data
- Provides vector embeddings and semantic search capabilities
- Exposes endpoints for the API service to consume

## API Endpoints

- `GET /`: Check if the RAG service is running
- `POST /rag/message`: Retrieve messages based on semantic similarity to query
- `GET /rag/users`: Get a list of all users
- `GET /rag/items`: Get a list of all items
- `GET /rag/items/{item_id}`: Get a specific item by ID
- `GET /health`: Health check endpoint

## Running the Service

You can run this service using Docker Compose:

```bash
# From the root directory (where the main docker-compose.yml is located)
docker-compose up -d
```

The RAG service will be available internally at `http://rag:8081` and externally at `http://localhost:8081`.

## Development

To run the service locally for development:

1. Install the requirements:
```bash
pip install -r requirements.txt
```

2. Start the service:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8081
```

## Technology Stack

### Core Libraries
- [FastAPI](https://fastapi.tiangolo.com/) - Modern, fast web framework for building APIs
- [Uvicorn](https://www.uvicorn.org/) - ASGI server for FastAPI applications
- [Sentence-Transformers](https://www.sbert.net/) - For creating vector embeddings of text

### Database
- [SQLAlchemy](https://docs.sqlalchemy.org/) - SQL toolkit and ORM
- [Psycopg2](https://www.psycopg.org/docs/) - PostgreSQL adapter for Python

### Development Tools
- [Docker](https://docs.docker.com/) - Containerization platform 