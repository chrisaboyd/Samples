# Langfuse LLM Tracing

LLM-native tracing: trajectories, cost, latency, token traces.

## Purpose

Observability for LLM workloads - traces, scores, datasets.

## Dependencies

Platform: PostgreSQL, ClickHouse, Redis, Object Storage (SeaweedFS)

## What it exposes

- Web/UI: `langfuse.observability.svc.cluster.local:3000`
- Worker: Internal (processes async jobs from Redis queue)

## Architecture

Two containers:
- langfuse-web - UI and API
- langfuse-worker - Async ingestion worker
