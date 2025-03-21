#!/bin/bash

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
    docker-compose down
    ;;
  test)
    echo "Sending test POST request to localhost:8080/api/hello..."
    curl -X POST http://localhost:8080/api/hello \
      -H "Content-Type: application/json" \
      -d '{"message":"LGTM!"}'
    ;;
  *)
    echo "Usage: $0 {start|stop|test}"
    exit 1
    ;;
esac
