# Microsoft Presidio

PII detection and anonymization service.

## Purpose

Analyzes and anonymizes PII (emails, SSNs, names, API keys) in prompts/outputs.

## Dependencies

None (stateless service).

## What it exposes

Services:
- `presidio-analyzer.guardrails.svc.cluster.local:3000`
- `presidio-anonymizer.guardrails.svc.cluster.local:3001`

## Hook Integration

Wired via LiteLLM:
- `pre_call` - PII masking before reaching model
- `during_call` - PII masking during streaming
- `post_call` - PII redaction from output
