# Langfuse Configuration

## Environment

Key env vars:

```yaml
NEXTAUTH_SECRET: <generated>
SALT: <generated>
DATABASE_URL: "postgresql://langfuse:password@postgres:5432/langfuse"
CLICKHOUSE_URL: "clickhouse.observability.svc.cluster.local"
REDIS_URL: "redis://redis.platform.svc.cluster.local:6379"
S3_ENDPOINT: "http://seaweedfs-s3.platform.svc.cluster.local:8333"
```

## Worker

BullMQ queue worker processes traces asynchronously via Redis.

## Ports

- 3000: Web UI/API
