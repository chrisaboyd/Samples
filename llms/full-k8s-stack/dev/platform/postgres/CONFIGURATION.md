# PostgreSQL Configuration

## Helm Values

Uses Bitnami PostgreSQL chart with the following key settings:

```yaml
auth:
  postgresPassword: <generated-secret>
  username: litellm
  password: <generated-secret>
  database: litellm
  
primary:
  persistence:
    enabled: true
    size: 10Gi
  resources:
    requests:
      cpu: 500m
      memory: 1Gi
```

## Database Initialization

Init scripts in `manifests/init-scripts/` create:
- `langfuse` database and user
- `bifrost` database and user

## Connection Secrets

Templates in `secrets/` folder:
- `postgres-secret.yaml.template` - Main credentials
- `langfuse-db-secret.yaml.template` - Langfuse connection info

## Backup Strategy (Dev)

Not applicable for dev. Production uses RDS automated backups + PITR.