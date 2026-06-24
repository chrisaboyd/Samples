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

## Teardown

```bash
./teardown.sh
```