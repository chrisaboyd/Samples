# Production Cluster Root

Root Kustomization for production cluster.

## Structure

```
├── flux-system/     # FluxCD core
├── sources/         # Helm repositories
├── infrastructure/  # cert-manager, ingress, GPU operator
├── platform/        # ClickHouse, Redis
└── applications/    # All app HelmReleases
```