# OpenTelemetry Collector

Telemetry hub: receives OTLP, fans out to Tempo and Prometheus.

## Purpose

Central collector for traces and metrics from gateways.

## Dependencies

Observability: Tempo, Prometheus.

## What it exposes

- OTLP gRPC: `otel-collector.observability.svc.cluster.local:4317`
- OTLP HTTP: `otel-collector.observability.svc.cluster.local:4318`

## Receivers

- OTLP from Bifrost, LiteLLM, vLLM

## Exporters

- Tempo (traces)
- Prometheus (metrics)
- Loki (logs)
