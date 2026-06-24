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

## Individual Deployment

Apply the kustomization for namespaces and CRDs:

```bash
kubectl apply -k .
```

Deploy NGINX Ingress via Helm:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace -f values.yaml
```

Deploy GPU Operator via Helm (skip if using managed GPU or existing driver installation):

```bash
helm repo add nvidia-gpu-operator https://nvidia.github.io/gpu-operator
helm install gpu-operator nvidia-gpu-operator/gpu-operator \
  --namespace gpu-operator --create-namespace --wait --timeout 300s
```

## Skipping Deployments

If you have existing infrastructure (e.g., corporate ingress controller, managed GPU):
- Skip the NGINX Ingress deployment and ensure your ingress is available in `ingress-nginx` namespace
- Skip the GPU Operator deployment if GPU drivers are already installed
- The namespace manifests can still be applied with `kubectl apply -k .`