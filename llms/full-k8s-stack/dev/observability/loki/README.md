# Loki Log Aggregation

Cluster log aggregation for all component logs.

## Purpose

Log storage and query backend for Grafana.

## Dependencies

None (standalone).

## What it exposes

Service: `loki.observability.svc.cluster.local:3100`

## Ingestion

Promtail/Alloy ships logs from /var/log/containers.

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
kubectl get pods -n observability -l app.kubernetes.io/name=loki

# Port-forward to test
kubectl -n observability port-forward svc/loki 3100:3100
curl http://localhost:3100/ready
```