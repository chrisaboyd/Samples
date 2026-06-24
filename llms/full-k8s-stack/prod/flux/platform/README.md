# Platform Flux Resources

Platform substrate for production.

## Components

- clickhouse - HA ClickHouse via Altinity operator
- redis - Redis for Langfuse queue/cache (or ElastiCache)

## Note

PostgreSQL via RDS, S3 via cloud-storage - see infrastructure/