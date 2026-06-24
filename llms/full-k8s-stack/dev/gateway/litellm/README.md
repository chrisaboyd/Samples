# LiteLLM Gateway

Primary OpenAI-compatible gateway with provider routing and guardrail orchestration.

## Purpose

Unified LLM gateway with:
- Provider routing (vLLM, external APIs)
- Guardrail hooks via pre_call, during_call, post_call, logging_only
- Key/budget/spend tracking via Postgres

## Dependencies

Platform: PostgreSQL, Redis
Guardrails: Presidio, NeMo Guardrails, LLM Guard (for hook wiring)
Observability: Langfuse, Prometheus

## What it exposes

Service: `litellm.gateway.svc.cluster.local:8000`

## Guardrail Hook Placement

| Control | Hook |
|---------|------|
| Block prompt injection | pre_call |
| Mask PII/secrets | pre_call / during_call |
| Prevent output leakage | post_call |
| Redact for logging | logging_only |

## Ports / Services

| Service | Port |
|---------|------|
| litellm | 8000 (API), 8001 (Metrics) |

## Files

- `values.yaml` - Helm values for LiteLLM
- `secrets/` - Template files for credentials
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
# Apply secrets first
kubectl apply -k .

# Deploy
kubectl apply -k .
```

## Verification

```bash
# Port-forward to access API
kubectl -n gateway port-forward svc/litellm 8000:8000

# Test health endpoint
curl http://localhost:8000/health

# Test with an API key
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Guardrail Integration

Configure guardrails in the LiteLLM config to point to:
- Presidio: `http://presidio-analyzer.guardrails.svc.cluster.local:3000`
- LLM Guard: `http://llm-guard.guardrails.svc.cluster.local:8000`
- NeMo Guardrails: `http://nemo-guardrails.guardrails.svc.cluster.local:8080`