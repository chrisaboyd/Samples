# FluxCD Bootstrap

GitOps source of truth for production deployment.

## Installation

```bash
flux bootstrap github \
  --owner=<org> \
  --repository=llms-full-k8s-stack \
  --branch=main \
  --path=./prod/flux/clusters/production
```

## Ordering

Kustomization `dependsOn`:
```
infrastructure (cert-manager, ingress, GPU operator)
  → platform (ClickHouse, Redis)
  → applications (gateway, guardrails, observability)
```

## Health Checks

All Kustomizations and HelmReleases have health checks enabled.