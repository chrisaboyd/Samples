#!/bin/bash

# Verify dev deployment health

echo "=== Verifying AI Gateway Stack (dev) ==="

# Check all pods are running
echo "Checking pod status..."
kubectl get pods -A

# Check substrate health
echo ""
echo "Checking substrate services..."
echo "PostgreSQL:"
kubectl get pods -n platform -l app.kubernetes.io/name=postgresql || echo "PostgreSQL not running"
echo "ClickHouse:"
kubectl get pods -n observability -l app.kubernetes.io/name=clickhouse || echo "ClickHouse not running"
echo "Redis:"
kubectl get pods -n platform -l app.kubernetes.io/name=redis || echo "Redis not running"
echo "SeaweedFS:"
kubectl get pods -n platform -l app.kubernetes.io/name=seaweedfs-master || echo "SeaweedFS not running"

# Test LiteLLM endpoint
echo ""
echo "Testing LiteLLM endpoint..."
kubectl run test-curl --rm -i --tty --image=curlimages/curl --restart=Never -- \
  curl -s http://litellm.gateway.svc.cluster.local:8000/health

# Test Langfuse endpoint
echo ""
echo "Testing Langfuse endpoint..."
kubectl run test-curl --rm -i --tty --image=curlimages/curl --restart=Never -- \
  curl -s http://langfuse.observability.svc.cluster.local:3000/api/public/health || true

echo ""
echo "=== Endpoints (for port-forwarding) ==="
echo "LiteLLM API:    kubectl -n gateway port-forward svc/litellm 8000:8000"
echo "OpenWebUI:      kubectl -n gateway port-forward svc/open-webui 8080:8080"
echo "Grafana:        kubectl -n observability port-forward svc/kube-prometheus-stack-grafana 3000:80"
echo "Langfuse UI:    kubectl -n observability port-forward svc/langfuse 3000:3000"
echo "Prometheus:     kubectl -n observability port-forward svc/kube-prometheus-stack-prometheus 9090:9090"

echo ""
echo "=== Health check complete ==="