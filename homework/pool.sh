#!/bin/bash
# set -e
# set -x 

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo "docker-compose.yml not found"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "docker-compose could not be found"
    exit 1
fi

# Check and set fallback database environment variables if not already set
if [ -z "$DB_NAME" ]; then
    export DB_NAME="api_db"
fi

if [ -z "$DB_USER" ]; then
    export DB_USER="api_user"
fi

if [ -z "$DB_PASSWORD" ]; then
    export DB_PASSWORD="api_password"
fi

echo "DB_NAME: $DB_NAME"
echo "DB_USER: $DB_USER"


case "$1" in
  start)
    # Check if services are already running
    if docker-compose ps | grep -q "Up"; then
        echo "Services are already running"
        exit 0
    fi

    echo "Starting docker-compose services..."
    docker-compose up -d
    echo "API is running at http://localhost:8080/api"
    echo "Docs are available at http://localhost:8080/api/docs"

    ;;
  stop)
    echo "Stopping docker-compose services..."
    docker-compose down -v
    ;;
  restart)
    echo "Restarting services..."
    docker-compose down -v
    docker-compose up -d
    echo "API is running at http://localhost:8080/api"
    echo "Docs are available at http://localhost:8080/api/docs"
    ;;
  test)
    echo "Sending test POST request to localhost:8080/api/hello..."
    curl -X POST http://localhost:8080/api/hello \
      -H "Content-Type: application/json" \
      -d '{"message":"LGTM!"}'
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|test}"
    exit 1
    ;;
esac
