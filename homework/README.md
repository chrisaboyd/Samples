# PostgreSQL and FastAPI Application

This project consists of two main components:
1. A PostgreSQL database service
2. A FastAPI-based API service

Both services are containerized with Docker and can be run together using Docker Compose.

## Services

### Database Service (PostgreSQL)

Located in the `db_service` directory, this service provides:
- PostgreSQL database with sample tables and data
- A "hello world" message stored in the database

See the [db_service README](db_service/README.md) for more details.

### API Service (FastAPI)

Located in the `api_service` directory, this service provides:
- RESTful API endpoints to access the database
- Retrieval of the "hello world" message
- Listing users and items

See the [api_service README](api_service/README.md) for more details.

## Getting Started

To run both services together:

```bash
# Start all services
docker-compose up -d
```

Once running:
- Database is accessible at `localhost:5432`
- API is accessible at `http://localhost:8080`
- Interactive API documentation is available at `http://localhost:8080/docs`

## API Endpoints

- `GET /`: Returns 404 Not Found
- `POST /api/hello`: Retrieve the "hello world" message from the database (requires message payload)
- `GET /api/users`: Get a list of all users
- `GET /api/items`: Get a list of all items
- `GET /api/items/{item_id}`: Get a specific item by ID
- `GET /api/health`: Health check endpoint


### Hello Endpoint

```bash
curl http://localhost:8080/api/hello \
  -H "Content-Type: application/json" \
  -d '{"message": "LGTM!"}'

{"message":"hello world","received":"LGTM!"}%   
```

## Reference Docs

### API Service
- [FastAPI](https://fastapi.tiangolo.com/) - Modern, fast web framework for building APIs
- [Uvicorn](https://www.uvicorn.org/) - ASGI server for Python
- [SQLAlchemy](https://docs.sqlalchemy.org/) - SQL toolkit and ORM
- [Pydantic](https://docs.pydantic.dev/) - Data validation and settings management

### Database Service
- [PostgreSQL](https://www.postgresql.org/docs/) - Open source relational database
- [Docker](https://docs.docker.com/) - Containerization platform


