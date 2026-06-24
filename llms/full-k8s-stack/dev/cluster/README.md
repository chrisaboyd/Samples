# Cluster Foundation

Namespaces, StorageClass, Prometheus Operator CRDs, NVIDIA GPU Operator, and ingress controller.

## Purpose

Sets up the base Kubernetes substrate required by all other components.

## Dependencies

None (Layer 0).

## What it exposes

- Namespace: `platform`, `gateway`, `guardrails`, `observability`, `inference`, `load-testing`
- StorageClass: `local-path` (dev) / `ebs-gp3` (prod)
- Ingress controller: NGINX (NodePort)

## Ports / Services

| Service | Port |
|---------|------|
| ingress-nginx-controller | 80, 443 |

## Files

- `manifests/` - Raw Kubernetes manifests for CRDs and operators
- `values.yaml` - Helm values for ingress controller