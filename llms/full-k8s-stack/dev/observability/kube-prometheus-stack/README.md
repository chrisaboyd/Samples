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

## Files

- `values.yaml` - Helm values for kube-prometheus-stack
- `manifests/` - Raw Kubernetes manifests (if any)

## Individual Deployment

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace observability -f values.yaml
```

## Verification

```bash
# Port-forward to access Grafana
kubectl -n observability port-forward svc/kube-prometheus-stack-grafana 3000:80

# Default credentials: admin/admin
```

## Note

This component installs via Helm, not kubectl apply -k. The values.yaml configures:
- Prometheus with 20Gi storage
- Grafana with admin password `admin`
- AlertManager enabled