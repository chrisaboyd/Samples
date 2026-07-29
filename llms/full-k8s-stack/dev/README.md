# Development Environment

Everything runs in-cluster with zero external cloud dependencies. Single-command bootstrap.

## Prerequisites

- Kubernetes cluster (kind/k3s or similar) with GPU support if testing inference
- kubectl configured
- Helm installed

## Quick Start

```bash
./deploy.sh
./verify.sh
```

## Structure

```
dev/
├── cluster/              # Namespaces, StorageClass, GPU Operator, ingress
├── platform/
│   ├── postgres/         # Bitnami PostgreSQL StatefulSet
│   ├── clickhouse/       # In-cluster ClickHouse (Langfuse OLAP)
│   ├── redis/            # In-cluster Redis/Valkey
│   └── object-storage/   # SeaweedFS (S3-compatible)
├── inference/
│   └── vllm/             # Optional in-cluster model backend
├── gateway/
│   ├── litellm/          # Primary gateway + guardrail orchestration
│   ├── bifrost/          # Alternative gateway
│   └── open-webui/       # Chat UI
├── guardrails/
│   ├── presidio/         # PII detection / anonymization
│   ├── nemo-guardrails/  # Topical / dialogue rails
│   └── llm-guard/        # Input/output scanners
├── observability/
│   ├── kube-prometheus-stack/
│   ├── dcgm-exporter/
│   ├── loki/
│   ├── tempo/
│   ├── otel-collector/
│   ├── langfuse/
│   └── servicemonitors/
└── load-testing/
    └── locust/
```

## Individual Component Deployment

Each component can be deployed independently. See the README.md in each folder for specific instructions.

### Layer 0 - Cluster Foundation

Deploy namespaces and base infrastructure (can be skipped if pre-existing):

```bash
# Namespaces are created automatically with kubectl apply -k
# NGINX Ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace -f cluster/values.yaml

# GPU Operator (skip if cluster has external GPU management)
helm repo add nvidia-gpu-operator https://nvidia.github.io/gpu-operator
helm install gpu-operator nvidia-gpu-operator/gpu-operator \
  --namespace gpu-operator --create-namespace --wait --timeout 300s
```

### Layer 1 - Platform Substrate

```bash
# PostgreSQL
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgresql bitnami/postgresql --namespace platform -f platform/postgres/values.yaml

# ClickHouse, Redis, Object Storage (SeaweedFS)
kubectl apply -k platform/clickhouse/
kubectl apply -k platform/redis/
kubectl apply -k platform/object-storage/
```

### Layer 2 - Inference (Optional)

```bash
kubectl apply -k inference/vllm/
```

### Layer 3 - Gateway

```bash
kubectl apply -k gateway/litellm/
kubectl apply -k gateway/bifrost/
kubectl apply -k gateway/open-webui/
```

### Layer 4 - Guardrails

```bash
kubectl apply -k guardrails/presidio/
kubectl apply -k guardrails/nemo-guardrails/
kubectl apply -k guardrails/llm-guard/
```

### Layer 5 - Observability

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace observability -f observability/kube-prometheus-stack/values.yaml

kubectl apply -k observability/dcgm-exporter/
kubectl apply -k observability/loki/
kubectl apply -k observability/tempo/
kubectl apply -k observability/otel-collector/
kubectl apply -k observability/langfuse/
kubectl apply -k observability/servicemonitors/
```

### Layer 6 - Load Testing

```bash
kubectl apply -k load-testing/locust/
```

## Teardown

```bash
./teardown.sh
```