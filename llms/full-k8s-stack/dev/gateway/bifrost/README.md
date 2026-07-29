# Bifrost Gateway

High-throughput Go gateway with native Prometheus + OTel, governance/virtual keys.

## Purpose

Alternative to LiteLLM with better observability out-of-the-box.

## Dependencies

Platform: Redis (for queue/cache), PostgreSQL (prod HA mode)

## What it exposes

Service: `bifrost.gateway.svc.cluster.local:8000`

## Ports / Services

| Service | Port |
|---------|------|
| bifrost | 8000 (API), 8080 (Metrics) |

## Configuration

SQLite-on-PVC for dev, Postgres mode for prod HA.

## Files

- `values.yaml` - Helm values for Bifrost
- `secrets/` - Template files for encryption key
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
# Apply secrets first
kubectl apply -k .

# Deploy
kubectl apply -k .
```

## Verification

```bash
# Port-forward to access API
kubectl -n gateway port-forward svc/bifrost 8000:8000

# Test health endpoint
curl http://localhost:8000/health

# Access metrics
kubectl -n gateway port-forward svc/bifrost 8080:8080
curl http://localhost:8080/metrics
```

## OpenTelemetry

Bifrost sends traces to the OTel Collector at:
`http://otel-collector.observability.svc.cluster.local:4317`