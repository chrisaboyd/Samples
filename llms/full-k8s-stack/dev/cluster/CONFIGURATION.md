# Cluster Foundation Configuration

## Namespaces

| Namespace | Purpose |
|-----------|---------|
| platform | PostgreSQL, ClickHouse, Redis, object storage |
| gateway | LiteLLM, Bifrost, OpenWebUI |
| guardrails | Presidio, NeMo Guardrails, LLM Guard |
| observability | Prometheus, Grafana, Loki, Tempo, Langfuse |
| inference | vLLM model backend |
| load-testing | Locust |

## StorageClass

Uses `local-path` (Rancher) for dev - provides dynamic PVC provisioning.

## Ingress

NGINX Ingress Controller deployed as NodePort for local development.

## GPU Operator

Deploys NVIDIA driver, container toolkit, and device plugin for GPU workloads.

## Prometheus CRDs

Installs ServiceMonitor, PodMonitor, and related CRDs for Prometheus Operator.