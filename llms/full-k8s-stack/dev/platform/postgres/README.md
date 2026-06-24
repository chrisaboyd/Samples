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
- `bifrost` - Bifrost Postgres mode

## Ports / Services

| Service | Port |
|---------|------|
| postgres | 5432 |

## Files

- `values.yaml` - Helm values for Bitnami PostgreSQL
- `secrets/` - Template files for credentials
- `manifests/init-scripts/` - SQL scripts for database creation

## Individual Deployment

Apply secrets first:

```bash
kubectl apply -k .
```

Deploy via Helm:

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgresql bitnami/postgresql \
  --namespace platform -f values.yaml
```

## Database Initialization

The Bitnami PostgreSQL chart will create the `litellm` database. Additional databases need to be initialized:

```bash
# Connect to Postgres and create databases
kubectl exec -n platform -it svc/postgresql -- psql -U postgres
CREATE DATABASE langfuse;
CREATE USER langfuse WITH PASSWORD 'langfuse-password';
GRANT ALL PRIVILEGES ON DATABASE langfuse TO langfuse;

CREATE DATABASE bifrost;
CREATE USER bifrost WITH PASSWORD 'bifrost-password';
GRANT ALL PRIVILEGES ON DATABASE bifrost TO bifrost;
```