# SeaweedFS Object Storage (Platform Substrate)

In-cluster SeaweedFS providing S3-compatible endpoint for Langfuse.

## Purpose

S3-compatible blob storage for Langfuse event ingestion and multimodal payloads.

## Dependencies

Cluster foundation.

## What it exposes

Service: `seaweedfs.platform.svc.cluster.local:8333` (S3 endpoint)

## Ports / Services

| Service | Port |
|---------|------|
| seaweedfs-master | 9333 |
| seaweedfs-filer | 8888 |
| seaweedfs-s3 | 8333 |

## Configuration

Master + volume + filer pods. Single replica for dev.

## Individual Deployment

```bash
kubectl apply -k .
```

## Verification

```bash
# Check pods are running
kubectl get pods -n platform -l app.kubernetes.io/name=seaweedfs-master

# Port-forward to access S3 endpoint
kubectl -n platform port-forward svc/seaweedfs-filer 8333:8333

# Test S3 compatibility (requires awscli)
aws --endpoint-url http://localhost:8333 s3 ls
```

## Langfuse Configuration

Langfuse connects to SeaweedFS S3 using these environment variables (set in langfuse deployment):

- `S3_ENDPOINT`: `seaweedfs-filer.platform.svc.cluster.local:8333`
- `S3_BUCKET`: `langfuse`
- `S3_ACCESS_KEY_ID`: (from seaweedfs-secret)
- `S3_SECRET_ACCESS_KEY`: (from seaweedfs-secret)