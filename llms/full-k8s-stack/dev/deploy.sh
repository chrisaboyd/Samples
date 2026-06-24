#!/bin/bash
set -e

# Turnkey AI Gateway & Observability Stack - Dev Deployment
# Order: cluster → platform → inference → gateway → guardrails → observability → load-testing
#
# This script is designed for greenfield deployment on a fresh cluster.
# For individual component deployment, see the README.md in each component folder.

echo "=== Deploying AI Gateway Stack (dev) ==="

# Layer 0: Cluster Foundation
echo "Layer 0: Cluster foundation..."
kubectl apply -k cluster/

# Deploy NGINX Ingress via Helm
echo "Deploying NGINX Ingress..."
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx --force-update
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace -f cluster/values.yaml

# GPU Operator
echo "Deploying GPU Operator..."
helm repo add nvidia-gpu-operator https://nvidia.github.io/gpu-operator --force-update
helm install gpu-operator nvidia-gpu-operator/gpu-operator \
  --namespace gpu-operator --create-namespace --wait --timeout 300s

# Layer 1: Platform Substrate
echo "Layer 1: Platform substrate..."
kubectl apply -k platform/postgres/
kubectl apply -k platform/clickhouse/
kubectl apply -k platform/redis/
kubectl apply -k platform/object-storage/

# Deploy PostgreSQL via Helm
helm repo add bitnami https://charts.bitnami.com/bitnami --force-update
helm install postgresql bitnami/postgresql --namespace platform -f platform/postgres/values.yaml

# Wait for Postgres, ClickHouse, Redis, SeaweedFS
echo "Waiting for substrate services..."
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=postgresql --timeout=120s
kubectl wait --namespace observability --for=condition=ready pod -l app.kubernetes.io/name=clickhouse --timeout=120s
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=redis --timeout=120s
kubectl wait --namespace platform --for=condition=ready pod -l app.kubernetes.io/name=seaweedfs-master --timeout=120s

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
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace observability -f observability/kube-prometheus-stack/values.yaml
kubectl apply -k observability/dcgm-exporter/
kubectl apply -k observability/loki/
kubectl apply -k observability/tempo/
kubectl apply -k observability/otel-collector/
kubectl apply -k observability/langfuse/
kubectl apply -k observability/servicemonitors/

# Layer 6: Load Testing
echo "Layer 6: Load testing..."
kubectl apply -k load-testing/locust/

echo "=== Deployment complete ==="
echo "Run ./verify.sh to check health"