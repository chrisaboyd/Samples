# Redis / Valkey (Platform Substrate)

In-cluster Redis for Langfuse BullMQ event queue + cache. Also available to LiteLLM/Bifrost.

## Purpose

Queue and caching layer for async processing and API key caching.

## Dependencies

None (Layer 1).

## What it exposes

Service: `redis.platform.svc.cluster.local:6379`

## Ports / Services

| Service | Port |
|---------|------|
| redis | 6379 |