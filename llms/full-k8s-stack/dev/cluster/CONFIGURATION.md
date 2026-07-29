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

Not installed here. The Prometheus Operator CRDs ship with the `kube-prometheus-stack`
chart in Layer 5, and that is the only place they should come from.

Do not add hand-written "minimal" CRD stubs to this layer. Helm skips CRDs that already
exist, so a stub applied at Layer 0 is never replaced by the real one. Worse, an
`openAPIV3Schema` that omits fields causes the API server to **prune** them on write:
a `Prometheus` object silently loses its entire `spec`, the operator then generates an
empty scrape config, and Prometheus collects nothing while appearing healthy.

The CRDs are large (the `prometheuses` CRD is ~830KB), which makes client-side
`kubectl apply` fail with `metadata.annotations: Too long`. Use server-side apply:

```bash
kubectl apply --server-side --force-conflicts -f <crd>.yaml
```