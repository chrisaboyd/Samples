# API Service

This is a FastAPI-based API service that communicates with the RAG service to retrieve data.

## Features

- RESTful API built with FastAPI
- Communicates with the RAG service
- Endpoints for accessing users, items, and the "hello world" message
- No direct database connection

## API Endpoints

- `GET /`: Returns 404 Not Found
- `POST /api/hello`: Retrieve the "hello world" message (requires message payload)
- `GET /api/users`: Get a list of all users
- `GET /api/items`: Get a list of all items
- `GET /api/items/{item_id}`: Get a specific item by ID
- `GET /api/health`: Health check endpoint

## Example Requests

### Hello Endpoint

```bash
curl -X POST http://localhost:8080/api/hello \
  -H "Content-Type: application/json" \
  -d '{"message": "any message"}'
```

## Running the Service

You can run this service using Docker Compose:

```bash
# From the root directory (../)
docker-compose up -d
```

The API will be available at `http://localhost:8080/api`.

## API Documentation

Once the service is running, you can access the interactive API documentation:

- Swagger UI: `http://localhost:8080/docs`
- ReDoc: `http://localhost:8080/redoc`

## Reference Docs

### Core Libraries
- [FastAPI](https://fastapi.tiangolo.com/) - Modern, fast web framework for building APIs
- [Uvicorn](https://www.uvicorn.org/) - ASGI server for FastAPI applications
- [Pydantic](https://docs.pydantic.dev/) - Data validation and settings management
- [HTTPX](https://www.python-httpx.org/) - HTTP client for Python

### Development Tools
- [Docker](https://docs.docker.com/) - Container Runtime 