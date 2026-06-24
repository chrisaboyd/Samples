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