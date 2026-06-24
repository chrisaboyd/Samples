# Redis Configuration

## Architecture

Single replica for dev. Production can use ElastiCache or HA in-cluster deployment.

## Key Settings

```yaml
architecture: standalone
auth:
  enabled: false  # Dev only - use password in prod
```

## Langfuse Cache

Redis used by Langfuse for:
- API key caching
- Prompt versioning cache
- BullMQ event queue