# DCGM Exporter

GPU utilization, memory, and health metrics for Prometheus.

## Purpose

Exposes NVIDIA GPU metrics for monitoring via DCGM.

## Dependencies

Cluster: NVIDIA GPU Operator

## What it exposes

Service: `dcgm-exporter.observability.svc.cluster.local:9400`

## Metrics

- GPU utilization %
- GPU memory used/total
- GPU temperature
- GPU power draw
