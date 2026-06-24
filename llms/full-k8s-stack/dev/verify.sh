#!/bin/bash
set -e

# Verify dev deployment health

echo "=== Verifying AI Gateway Stack (dev) ==="

# Check all pods are running
echo "Checking pod status..."
kubectl get pods -A -o wide

# Check substrate health
echo "Checking substrate services..."
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=postgresql --timeout=30s
kubectl wait --namespace observability --for=condition=ready pod -l app.kubernetes.io/name=clickhouse --timeout=30s
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=redis --timeout=30s

# Test LiteLLM endpoint
echo "Testing LiteLLM endpoint..."
kubectl run test-curl --rm -i --tty --image=curlimages/curl --restart=Never -- \
  curl -s http://litellm.gateway.svc.cluster.local:8000/health

echo ""
echo "=== Endpoints ==="
echo "LiteLLM:    http://localhost:8000"
echo "OpenWebUI:  http://localhost:8080"
echo "Grafana:    http://localhost:3000"
echo "Langfuse:   http://localhost:3001"

echo ""
echo "=== Health check complete ==="