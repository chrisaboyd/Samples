# Production Environment

GitOps-managed production deployment with cloud-backed state.

## Prerequisites

- AWS account with VPC, subnets, IRSA configured
- FluxCD bootstrapped
- External model provider or in-cluster vLLM

## Architecture

- **State**: RDS (PostgreSQL), S3 for object storage
- **Ingress**: NGINX or ALB with TLS
- **GitOps**: FluxCD reconciles all resources

## Structure

```
prod/
├── flux/
│   ├── flux-system/        # FluxCD installation
│   ├── sources/            # Helm repositories
│   ├── infrastructure/     # cert-manager, ingress, GPU operator
│   ├── platform/           # ClickHouse, Redis
│   ├── applications/       # gateway, guardrails, observability
│   └── clusters/production # Root Kustomization
└── infrastructure/
    ├── cloud-db/           # RDS Terraform
    ├── cloud-storage/      # S3 buckets Terraform
    └── cert-manager/       # TLS configuration
```