# LiteLLM Configuration

## Database

Connects to PostgreSQL for:
- Virtual keys (`litellm` database)
- Budgets and spend tracking

## Guardrail Integration

LiteLLM hooks wired to guardrail services:
- Presidio: `http://presidio.guardrails.svc.cluster.local`
- LLM Guard: `http://llm-guard.guardrails.svc.cluster.local`
- NeMo Guardrails: `http://nemo-guardrails.guardrails.svc.cluster.local`

## Langfuse Logging

Callback configured at `logging_only` hook for trace redaction before persistence.

## Key Environment Variables

```yaml
DATABASE_URL: "postgresql://litellm:password@postgres:5432/litellm"
LANGFUSE_HOST: "http://langfuse.observability.svc.cluster.local"
OPENAI_API_BASE: "http://vllm.inference.svc.cluster.local:8000/v1"
```