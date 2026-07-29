# Cloud Database (RDS)

Amazon RDS PostgreSQL for production state.

## Configuration

- Engine: PostgreSQL 15
- Instance: db.t4g.medium (burstable)
- Storage: 100Gi GP3
- Multi-AZ: true
- Backup: 7 days retention, PITR enabled
- Network: Private subnets, security groups scoped

## Outputs

- Endpoint
- Database credentials (via Secrets Manager)

## Connection

ExternalSecret syncs RDS credentials to Kubernetes secrets.