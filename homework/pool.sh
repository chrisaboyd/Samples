#!/bin/bash

case "$1" in
  start)
    echo "Starting docker-compose services..."
    docker-compose up -d
    ;;
  stop)
    echo "Stopping docker-compose services..."
    docker-compose down
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
