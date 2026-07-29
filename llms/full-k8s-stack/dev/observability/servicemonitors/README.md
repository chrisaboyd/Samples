# ServiceMonitors

Prometheus Operator ServiceMonitor definitions for scrape targets.

## Purpose

Central location for ServiceMonitor CRDs configuring Prometheus scraping.

## Components Monitored

- LiteLLM
- Bifrost
- Langfuse
- vLLM
- DCGM Exporter

## Files

- `values.yaml` - Configuration reference
- `manifests/` - ServiceMonitor YAML files for each component

## Individual Deployment

Deploy all ServiceMonitors:

```bash
kubectl apply -k .
```

Or deploy individual monitors:

```bash
kubectl apply -n observability -f manifests/litellm-servicemonitor.yaml
kubectl apply -n observability -f manifests/bifrost-servicemonitor.yaml
kubectl apply -n observability -f manifests/langfuse-servicemonitor.yaml
kubectl apply -n observability -f manifests/vllm-servicemonitor.yaml
kubectl apply -n observability -f manifests/dcgm-servicemonitor.yaml
```

## Prerequisites

kube-prometheus-stack must be deployed first to provide the Prometheus Operator CRDs.