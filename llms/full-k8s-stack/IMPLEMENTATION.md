# Turnkey Open Source AI Solution - Implementation Plan

## Overview

This repository provides a turnkey open-source AI solution with two deployment paradigms:
- **`dev/`** - Quick, localized MVP environment for rapid prototyping
- **`prod/`** - Production-grade environment with cloud-native infrastructure and GitOps

Both environments deploy the same core AI stack but differ in infrastructure composition, security posture, and operational characteristics.

---

## Repository Structure

```
.
├── README.md                    # High-level overview and quick start
├── agent.md                     # This file - execution guide
├── dev/                         # Development/MVP environment
│   ├── README.md               # Dev-specific documentation
│   ├── cluster/                # Cluster-level resources (namespaces, CRDs)
│   ├── database/               # In-cluster PostgreSQL StatefulSet
│   ├── object-storage/         # In-cluster SeaweedFS deployment
│   ├── llm-engine/             # LLM inference engine (e.g., vLLM, Ollama)
│   ├── embedding-service/      # Embedding model service
│   ├── ai-platform/            # AI pipeline orchestration (e.g., Haystack, LlamaIndex)
│   ├── vector-db/              # In-cluster vector database (e.g., Chroma, Weaviate)
│   ├── api-gateway/            # REST/gRPC API gateway
│   ├── frontend/               # Web UI for AI interactions
│   └── monitoring/             # Basic monitoring stack (Prometheus + Grafana)
└── prod/                        # Production environment
    ├── README.md               # Prod-specific documentation
    ├── flux/                   # FluxCD base configuration
    │   ├── base/               # Kustomize base manifests
    │   └── clusters/           # Cluster-specific overlays
    ├── infrastructure/         # Infrastructure definitions
    │   ├── cloud-db/           # RDS/Cloud SQL configurations
    │   ├── cloud-storage/      # S3/GCS configurations
    │   └── cert-manager/       # Certificate management setup
    ├── llm-engine/
    ├── embedding-service/
    ├── ai-platform/
    ├── vector-db/
    ├── api-gateway/
    ├── frontend/
    └── monitoring/
```

---

## Core Components Specification

### AI Stack Components

| Component | Purpose | Dev Implementation | Prod Implementation |
|-----------|---------|-------------------|---------------------|
| **LLM Engine** | Large language model inference | Ollama or vLLM in-cluster | vLLM with cloud GPU instances |
| **Embedding Service** | Text embedding generation | Sentence-transformers in-cluster | Dedicated embedding microservice |
| **Vector Database** | Vector storage and similarity search | Chroma or Weaviate in-cluster | Managed Weaviate or Pinecone |
| **AI Platform** | Orchestration and pipelines | Haystack/LlamaIndex minimal | Full pipeline with caching |
| **API Gateway** | Unified API interface | NGINX or Traefik | NGINX with cert-manager TLS |
| **Frontend** | User interface | Streamlit or simple React | Full-featured React/Vue app |
| **Monitoring** | Observability | Prometheus + Grafana | Prometheus + Grafana + AlertManager |

---

## Dev Environment Design (`dev/`)

### Philosophy
- Zero external dependencies
- Single-command deployment
- Cluster-internal everything
- Self-contained defaults

### Infrastructure Approach

#### Database
- **PostgreSQL StatefulSet** with persistent volume claims
- StorageClass configured for local-path or similar
- Default credentials via Kubernetes secrets
- No external cloud dependencies

#### Object Storage
- **SeaweedFS** cluster deployment
- Master, volume, and filer components
- Persistent volumes for data storage
- S3-compatible API endpoint exposed internally

#### Networking
- Cluster-internal service discovery
- NodePort or LoadBalancer for external access
- Self-signed certificates or HTTP only

#### Deployment Method
- Direct `kubectl apply` or Helm
- No GitOps - immediate deployment
- Manual configuration via environment variables

### Resource Organization

Each sub-folder contains:
```
component-name/
├── README.md           # Component-specific docs
├── kustomization.yaml  # Kustomize configuration
├── values.yaml         # Helm values (if applicable)
├── secrets/            # Secret templates (not actual secrets)
└── manifests/          # Raw Kubernetes manifests
```

### Quick Start Flow
1. `cd dev/`
2. `./deploy.sh` (single script bootstraps everything)
3. Wait for all pods to be ready
4. Access via LoadBalancer IP or port-forward

---

## Prod Environment Design (`prod/`)

### Philosophy
- Cloud-native best practices
- GitOps-driven deployment
- External managed services where appropriate
- Security-first with TLS and proper RBAC

### Infrastructure Approach

#### Database
- **Cloud RDS** (AWS RDS, Google Cloud SQL, or Azure Database)
- Terraform or CloudFormation for provisioning
- Private network access via VPC peering
- Automated backups and point-in-time recovery

#### Object Storage
- **Cloud S3** (AWS S3, Google Cloud Storage, or Azure Blob)
- Pre-provisioned buckets with proper IAM
- Public access blocked, VPC endpoints where available
- Lifecycle policies for cost optimization

#### Certificate Management
- **cert-manager** with Let's Encrypt integration
- ClusterIssuer for production certificates
- Automatic renewal and management
- TLS on all external endpoints

#### GitOps
- **FluxCD** manages all Kubernetes resources
- Git repository as source of truth
- Automated sync with health checks
- Progressive delivery with Flagger (optional)

### FluxCD Structure

```
prod/flux/
├── flux-system/          # FluxCD installation
│   └── kustomization.yaml
├── infrastructure/
│   ├── providers/        # Cloud provider configs
│   ├── crds/             # CustomResourceDefinitions
│   └── controllers/      # cert-manager, external-dns, etc.
├── applications/
│   ├── llm-engine.yaml
│   ├── embedding-service.yaml
│   └── ...
└── clusters/
    └── production/
        └── kustomization.yaml  # Root kustomization
```

### Security Considerations

- **Network Policies** to restrict pod communication
- **Pod Security Standards** enforced
- **External Secrets** for credential management
- **RBAC** with least-privilege principles
- **TLS** everywhere with cert-manager

---

## Deployment Strategy

### Dev Deployment
```bash
# Bootstrap a kind or k3s cluster (optional)
./dev/cluster/setup.sh

# Deploy all components
./dev/deploy.sh

# Verify deployment
./dev/verify.sh
```

### Prod Deployment
```bash
# Bootstrap cluster with Flux
flux install

# Link to Git repository
flux create source git ai-solution \
  --url=https://github.com/user/turnkey-ai \
  --branch=main \
  --path=./prod/flux

# Create initial kustomization
flux create kustomization ai-solution \
  --source=GitRepository/ai-solution \
  --path="./clusters/production" \
  --prune=true \
  --wait=true
```

---

## Configuration Management

### Dev Configuration
- Default values in `values.yaml` files
- Environment-specific overrides via `kustomization.yaml`
- No external configuration required
- Secrets generated with `make secrets` command

### Prod Configuration
- **External Secrets Operator** or **Sealed Secrets**
- Environment-specific overlays in FluxCD
- Terraform for cloud infrastructure
- Configuration via Git parameters/Helm values

---

## Monitoring & Observability

### Dev
- **Prometheus** with basic scrape config
- **Grafana** with community dashboards
- **Loki** for log aggregation (optional)
- No alerting - informational only

### Prod
- **Prometheus Operator** with custom rules
- **Grafana** with organization dashboards
- **AlertManager** with notification channels
- **Loki** + **Promtail** for log aggregation
- **Tempo** for distributed tracing (optional)

---

## Dependencies & Prerequisites

### Dev Prerequisites
- Docker or container runtime
- kubectl
- kustomize
- Optional: kind or k3s for local cluster

### Prod Prerequisites
- Kubernetes cluster (EKS/GKE/AKS)
- kubectl configured
- Flux CLI installed
- Cloud provider CLI authenticated
- Domain name with DNS access
- Terraform (for infrastructure)

---

## Success Criteria

### Dev Environment
- [ ] Single-command deployment succeeds
- [ ] All pods reach Running state within 5 minutes
- [ ] API endpoint accessible and functional
- [ ] Basic AI workflow (prompt → response) works end-to-end
- [ ] No external cloud accounts required

### Prod Environment
- [ ] FluxCD successfully synchronizes all resources
- [ ] cert-manager issues valid certificates
- [ ] All services accessible via HTTPS
- [ ] Cloud database and storage connections established
- [ ] Monitoring stack collecting metrics
- [ ] Health checks passing for all critical services

---

## Future Enhancements

1. **Multi-region support** for prod environment
2. **Auto-scaling** configurations for LLM services
3. **Canary deployments** with Flagger
4. **Backup/restore** procedures documented
5. **Disaster recovery** runbooks
6. **Cost optimization** guides for prod

---

## File Naming Conventions

- Use kebab-case for directory and file names
- `*.yaml` for Kubernetes manifests
- `README.md` for each component
- `values.yaml` for Helm configurations
- `kustomization.yaml` at each kustomize layer
- `deploy.sh` for deployment scripts (dev only)

## Documentation Requirements

Each component folder must include:
1. `README.md` - Component overview, configuration options
2. `CONFIGURATION.md` - Detailed config reference
3. Example values and minimal working configurations
4. Troubleshooting guide

---

## Notes for Implementation

- Start with the simplest working configuration (LLM engine + API)
- Add components incrementally
- Test each component independently before integration
- Use health probes on all services
- Document rollback procedures for each component
- Include cleanup scripts for dev environment