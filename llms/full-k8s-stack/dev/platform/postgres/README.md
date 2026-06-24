# PostgreSQL (Platform Substrate)

Bitnami PostgreSQL StatefulSet for dev. Provides databases/users for LiteLLM, Langfuse, and Bifrost.

## Purpose

Relational database backing store for gateway state and Langfuse transactional data.

## Dependencies

Cluster foundation (StorageClass).

## What it exposes

Service: `postgres.platform.svc.cluster.local:5432`

Databases created:
- `litellm` - LiteLLM virtual keys / budgets
- `langfuse` - Langfuse transactional data
- `bifrost` - Bifrost Postgres mode (prod)

## Ports / Services

| Service | Port |
|---------|------|
| postgres | 5432 |

## Files

- `values.yaml` - Helm values for Bitnami PostgreSQL
- `secrets/` - Template files for credentials