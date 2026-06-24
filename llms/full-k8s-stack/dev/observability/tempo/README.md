# Tempo Distributed Tracing

Trace storage backend for OpenTelemetry traces.

## Purpose

Receives traces from OTel Collector, provides query API for Grafana.

## Dependencies

None (standalone).

## What it exposes

Service: `tempo.observability.svc.cluster.local:3200`

## Ports / Services

| Service | Port |
|---------|------|
| tempo | 3200 (HTTP), 4317 (gRPC) |

## Files

- `values.yaml` - Configuration reference
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
kubectl apply -k .
```

## Verification

```bash
# Check pods are running
kubectl get pods -n observability -l app.kubernetes.io/name=tempo

# Port-forward to test
kubectl -n observability port-forward svc/tempo 3200:3200
curl http://localhost:3200/ready
```