# DCGM Exporter

GPU utilization, memory, and health metrics for Prometheus.

## Purpose

Exposes NVIDIA GPU metrics for monitoring via DCGM.

## Dependencies

Cluster: NVIDIA GPU Operator

## What it exposes

Service: `dcgm-exporter.observability.svc.cluster.local:8080`

## Metrics

- GPU utilization %
- GPU memory used/total
- GPU temperature
- GPU power draw

## Files

- `values.yaml` - Configuration reference
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
kubectl apply -k .
```

## Note

DCGM Exporter runs as a DaemonSet and requires NVIDIA GPUs. If no GPUs are present, pods will be in pending state or won't start.

## Verification

```bash
# Check pods are running (only on GPU nodes)
kubectl get pods -n observability -l app.kubernetes.io/name=dcgm-exporter

# Port-forward to access metrics
kubectl -n observability port-forward svc/dcgm-exporter 8080:8080
curl http://localhost:8080/metrics
```