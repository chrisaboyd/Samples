# NeMo Guardrails

Topic, jailbreak, and dialogue control guards.

## Purpose

Conversational guardrails using LLM-based reasoning.

## Dependencies

None (stateless service).

## What it exposes

Service: `nemo-guardrails.guardrails.svc.cluster.local:8080`

## Hook Integration

Wired via LiteLLM at `pre_call` hook for input validation.
