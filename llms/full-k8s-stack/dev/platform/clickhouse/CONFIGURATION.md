# ClickHouse Configuration

## Key Settings

```yaml
CLICKHOUSE_CLUSTER_ENABLED: "false"
CLICKHOUSE_TIMEZONE: "UTC"
```

## Langfuse Schema

ClickHouse schema for Langfuse created via init scripts in `manifests/`.

## Persistence

10Gi PVC via local-path StorageClass.