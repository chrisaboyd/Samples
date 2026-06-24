# LLM Guard

Input/output scanner service for prompt injection, secrets, toxicity.

## Purpose

Scanners integrated at pre_call and post_call hooks.

## Dependencies

None (stateless service).

## What it exposes

Service: `llm-guard.guardrails.svc.cluster.local:8000`

## Scanners

- Prompt injection
- Secrets detection
- Toxicity filter
- Topic restriction
