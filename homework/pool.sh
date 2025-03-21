#!/bin/bash

case "$1" in
  start)
    echo "Starting docker-compose services..."
    echo "Starting db_service..."
    docker-compose up -d -f db_service/docker-compose.yml

    echo "Starting api_service..."
    docker-compose up -d -f api_service/docker-compose.yml
    ;;
  stop)
    echo "Stopping docker-compose services..."
    docker-compose down -f db_service/docker-compose.yml
    docker-compose down -f api_service/docker-compose.yml
    ;;
  test)
    echo "Sending test POST request to localhost:8080..."
    curl -X POST http://localhost:8080 \
      -H "Content-Type: application/json" \
      -d '{"message":"Hello from test"}'
    ;;
  *)
    echo "Usage: $0 {start|stop|test}"
    exit 1
    ;;
esac
