# SeaweedFS Configuration

## Architecture

```
seaweedfs-master (1 replica) - cluster management
seaweedfs-volume (1 replica) - data storage
seaweedfs-filer (1 replica) - S3-compatible endpoint
```

## S3 Endpoint

Access via `http://seaweedfs-s3:8333` with generated credentials.

## Langfuse Integration

Bucket: `langfuse-events` for trace payloads.

## Production Note

Prod uses Amazon S3 + IRSA instead.