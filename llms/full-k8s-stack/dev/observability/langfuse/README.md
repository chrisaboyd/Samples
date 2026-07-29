# Langfuse LLM Tracing

LLM-native tracing: trajectories, cost, latency, token traces.

## Purpose

Observability for LLM workloads - traces, scores, datasets.

## Dependencies

Platform: PostgreSQL, ClickHouse, Redis, Object Storage (SeaweedFS)

## What it exposes

- Web/UI: `langfuse.observability.svc.cluster.local:3000`
- Worker: Internal (processes async jobs from Redis queue)

## Architecture

Two containers:
- langfuse-web - UI and API
- langfuse-worker - Async ingestion worker

## Files

- `values.yaml` - Helm values for Langfuse
- `secrets/` - Template files for secrets
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

**Prerequisite:** Deploy platform substrate first (PostgreSQL, ClickHouse, Redis, SeaweedFS)

```bash
# Apply secrets first
kubectl apply -k .

# Deploy
kubectl apply -k .
```

## Verification

```bash
# Port-forward to access UI
kubectl -n observability port-forward svc/langfuse 3000:3000

# Check health
curl http://localhost:3000/api/public/health
```

## Environment Variables

| Variable | Value |
|----------|-------|
| DATABASE_URL | `postgresql://langfuse:langfuse-password@postgres.platform.svc.cluster.local:5432/langfuse` |
| CLICKHOUSE_URL | `clickhouse.observability.svc.cluster.local` |
| REDIS_CONNECTION_STRING | `redis://redis.platform.svc.cluster.local:6379` |
| S3_ENDPOINT | `seaweedfs-filer.platform.svc.cluster.local:8333` |
| S3_BUCKET | `langfuse` |