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

[+] Running 4/4
 ✔ postgres                           Built                                                                                                                                              0.0s 
 ✔ Network db_service_default         Created                                                                                                                                            0.0s 
 ✔ Volume "db_service_postgres_data"  Created                                                                                                                                            0.0s 
 ✔ Container api_postgres             Started                                                                                                                                            0.2s 

# To stop the service
docker-compose down
```
[+] Running 2/2
 ✔ Container api_postgres      Removed                                                                                                                                                   0.2s 
 ✔ Network db_service_default  Removed                                                                                                                                                   0.2s 
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

When connecting to the database locally, use the connection string:
```
postgresql://api_user:api_password@postgres:5432/api_db
```

If connecting in Kubernetes, this can be stored as a Secret:
```
kubectl create secret generic ps_pg_conn key='postgresql://api_user:api_password@postgres:5432/api_db'
```

Then referenced in the deployment:
```
spec:
  containers:
  ...
    env:
    - name: PS_PG_CONNENCTION_STRING
      valueFrom:
        secretKeyRef:
          name: ps_pg_conn
          key: key
```

## Technology Documentation

### Database
- [PostgreSQL](https://www.postgresql.org/docs/) - Official PostgreSQL documentation
- [PostgreSQL Docker Image](https://hub.docker.com/_/postgres) - Docker Hub for PostgreSQL

### Container Tools
- [Docker](https://docs.docker.com/) - Docker platform documentation
- [Docker Compose](https://docs.docker.com/compose/) - Tool for defining multi-container applications