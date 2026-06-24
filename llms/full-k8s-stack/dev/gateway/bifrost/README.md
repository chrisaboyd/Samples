# Bifrost Gateway

High-throughput Go gateway with native Prometheus + OTel, governance/virtual keys.

## Purpose

Alternative to LiteLLM with better observability out-of-the-box.

## Dependencies

Platform: Redis (for queue/cache), PostgreSQL (prod HA mode)

## What it exposes

Service: `bifrost.gateway.svc.cluster.local:8000`

## Ports / Services

| Service | Port |
|---------|------|
| bifrost | 8000 (API), 8080 (Metrics) |

## Configuration

SQLite-on-PVC for dev, Postgres mode for prod HA.
