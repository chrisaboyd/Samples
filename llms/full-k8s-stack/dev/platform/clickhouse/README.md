# ClickHouse (Platform Substrate)

In-cluster ClickHouse for Langfuse OLAP store (traces, observations, scores).

## Purpose

Columnar database for LLM tracing analytics.

## Dependencies

Cluster foundation (StorageClass).

## What it exposes

Service: `clickhouse.observability.svc.cluster.local:8123` (HTTP), `9000` (native)

## Ports / Services

| Service | Port |
|---------|------|
| clickhouse | 8123, 9000 |

## Configuration

- UTC timezone enforced
- `CLICKHOUSE_CLUSTER_ENABLED=false` for single-node dev