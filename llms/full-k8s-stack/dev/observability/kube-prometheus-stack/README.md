# kube-prometheus-stack

Prometheus + Grafana + AlertManager + kube-state-metrics + node-exporter.

## Purpose

Core monitoring stack for cluster and application metrics.

## Dependencies

Cluster: Prometheus Operator CRDs (created in cluster/)

## What it exposes

- Prometheus: `prometheus-operated.observability.svc.cluster.local:9090`
- Grafana: `grafana.observability.svc.cluster.local:3000`
- AlertManager: `alertmanager-main.observability.svc.cluster.local:9093`

## Dashboards

Community dashboards for vLLM, LiteLLM, Langfuse.
