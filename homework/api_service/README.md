# API Service

This is a FastAPI-based API service that connects to the PostgreSQL database.

## Features

- RESTful API built with FastAPI
- Connects to PostgreSQL database
- Endpoints for accessing users, items, and the "hello world" message

## API Endpoints

- `GET /`: Returns 404 Not Found
- `POST /api/hello`: Retrieve the "hello world" message from the database (requires message payload)
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

### Database
- [SQLAlchemy](https://docs.sqlalchemy.org/) - SQL toolkit and ORM
- [Psycopg2](https://www.psycopg.org/docs/) - PostgreSQL adapter for Python

### Development Tools
- [Docker](https://docs.docker.com/) - Container Runtime 