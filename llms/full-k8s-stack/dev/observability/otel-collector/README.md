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

## Files

- `values.yaml` - Configuration reference
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
kubectl apply -k .
```

## Verification

```bash
# Check pods are running
kubectl get pods -n observability -l app.kubernetes.io/name=otel-collector

# View collected metrics in Prometheus
kubectl -n observability port-forward svc/kube-prometheus-stack-prometheus 9090:9090
```