# Cloud Storage (S3)

Amazon S3 buckets for production object storage.

## Buckets

- `langfuse-events` - Raw trace events, multimodal payloads
- `langfuse-exports` - Dataset exports

## Configuration

- Block all public access
- Enable versioning
- Lifecycle policies for cost optimization
- IAM roles via IRSA for pod access

## IRSA

Kubernetes service accounts annotated with IAM role ARNs.