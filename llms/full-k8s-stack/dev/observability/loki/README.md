# Loki Log Aggregation

Cluster log aggregation for all component logs.

## Purpose

Log storage and query backend for Grafana.

## Dependencies

None (standalone).

## What it exposes

Service: `loki.observability.svc.cluster.local:3100`

## Ingestion

Promtail/Alloy ships logs from /var/log/containers.
