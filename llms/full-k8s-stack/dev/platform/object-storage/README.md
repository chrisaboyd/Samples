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