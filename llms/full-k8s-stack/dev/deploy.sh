#!/bin/bash
set -e

# Turnkey AI Gateway & Observability Stack - Dev Deployment
# Order: cluster → platform → inference → gateway → guardrails → observability → load-testing

echo "=== Deploying AI Gateway Stack (dev) ==="

# Layer 0: Cluster Foundation
echo "Layer 0: Cluster foundation..."
kubectl apply -k cluster/

# Wait for nginx ingress
kubectl wait --namespace ingress-nginx --for=condition=ready pod -l app.kubernetes.io/name=ingress-nginx --timeout=120s

# Layer 1: Platform Substrate
echo "Layer 1: Platform substrate..."
kubectl apply -k platform/postgres/
kubectl apply -k platform/clickhouse/
kubectl apply -k platform/redis/
kubectl apply -k platform/object-storage/

# Wait for Postgres, ClickHouse, Redis, SeaweedFS
echo "Waiting for substrate services..."
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=postgresql --timeout=120s
kubectl wait --namespace observability --for=condition=ready pod -l app.kubernetes.io/name=clickhouse --timeout=120s
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=redis --timeout=120s

# Layer 2: Inference (optional)
echo "Layer 2: Inference backend..."
kubectl apply -k inference/vllm/

# Layer 3: Gateway
echo "Layer 3: Gateway..."
kubectl apply -k gateway/litellm/
kubectl apply -k gateway/bifrost/
kubectl apply -k gateway/open-webui/

# Layer 4: Guardrails
echo "Layer 4: Guardrails..."
kubectl apply -k guardrails/presidio/
kubectl apply -k guardrails/nemo-guardrails/
kubectl apply -k guardrails/llm-guard/

# Layer 5: Observability
echo "Layer 5: Observability..."
kubectl apply -k observability/kube-prometheus-stack/
kubectl apply -k observability/dcgm-exporter/
kubectl apply -k observability/loki/
kubectl apply -k observability/tempo/
kubectl apply -k observability/otel-collector/
# Note: Langfuse requires substrate - deploy after
kubectl apply -k observability/langfuse/
kubectl apply -k observability/servicemonitors/

# Layer 6: Load Testing
echo "Layer 6: Load testing..."
kubectl apply -k load-testing/locust/

echo "=== Deployment complete ==="
echo "Run ./verify.sh to check health"