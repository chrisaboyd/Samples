# OpenWebUI Chat Interface

Chat UI for human interaction with the AI gateway.

## Purpose

User-facing chat interface that points to LiteLLM or Bifrost endpoint.

## Dependencies

Gateway: LiteLLM or Bifrost
Platform: PostgreSQL (for conversation persistence)

## What it exposes

Service: `open-webui.gateway.svc.cluster.local:8080`

## Ports / Services

| Service | Port |
|---------|------|
| open-webui | 8080 (UI) |

## Files

- `values.yaml` - Helm values for OpenWebUI
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
kubectl apply -k .
```

## Verification

```bash
# Port-forward to access UI
kubectl -n gateway port-forward svc/open-webui 8080:8080

# Open browser at http://localhost:8080
```

## Configuration

Environment variables:
- `OPENAI_API_BASE_URL`: `http://litellm.gateway.svc.cluster.local:8000` (or bifrost)
- `WEBUI_AUTH`: `false` (dev mode - no authentication)