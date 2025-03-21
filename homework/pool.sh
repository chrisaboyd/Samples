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
export DB_NAME=${DB_NAME:-"api_db"}
export DB_USER=${DB_USER:-"api_user"}
export DB_PASSWORD=${DB_PASSWORD:-"api_password"}
export API_USERNAME=${API_USERNAME:-"admin"}
export API_PASSWORD=${API_PASSWORD:-"password"}

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
    echo "API is secured with Basic Auth - Username: $API_USERNAME, Password: [hidden]"

    ;;
  stop)
    echo "Stopping docker-compose services..."
    docker-compose down -v
    echo "Removed all containers and volumes"
    ;;
  restart)
    echo "Restarting services..."
    docker-compose down -v
    docker-compose up -d
    echo "API is running at http://localhost:8080/api"
    echo "Docs are available at http://localhost:8080/api/docs"
    echo "API is secured with Basic Auth - Username: $API_USERNAME, Password: [hidden]"
    ;;
  test)
    echo "Sending test POST request to localhost:8080/api/hello..."
    curl -X POST http://localhost:8080/api/hello \
      -H "Content-Type: application/json" \
      -u "$API_USERNAME:$API_PASSWORD" \
      -d '{"message":"LGTM!"}'
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|test}"
    exit 1
    ;;
esac
