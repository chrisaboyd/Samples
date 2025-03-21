# PostgreSQL Database Service

This is a PostgreSQL database service configured as a backend for an API server.

## Database Schema

The database contains the following tables:
- `users`: Basic user information
- `messages`: Contains messages including the special "hello world" string
- `items`: Sample product items with descriptions and prices

## Getting Started

### Running with Docker Compose

```bash
# Start the database service
docker-compose up -d

# To stop the service
docker-compose down
```

### Connecting to the Database

- **Host**: localhost
- **Port**: 5432
- **Database**: api_db
- **Username**: api_user
- **Password**: api_password

### Accessing the "hello world" message

The "hello world" string is stored in the `messages` table and can be retrieved with:

```sql
SELECT content FROM messages WHERE content = 'hello world';
```

## For API Integration

When building your API server container, you can connect to this database with the following connection string:

```
postgresql://api_user:api_password@postgres:5432/api_db
```

If your API server is running in a separate Docker container, make sure they are on the same Docker network. 