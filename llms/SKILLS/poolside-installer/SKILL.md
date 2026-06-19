---
name: poolside-installer
description: Install Poolside platform on bastion hosts across on-premises RKE2, AWS EKS, and OpenShift deployments. Automates prerequisite setup, Terraform/Kubernetes configuration, and initial platform access. Run this skill on bastion hosts to deploy Poolside infrastructure. Triggers on requests like "install poolside", "deploy poolside on-prem/EKS/OpenShift", "set up poolside stack", or "bastion poolside deployment".
metadata:
  version: "0.1.0"
  targets:
    - on-prem-rke2
    - aws-eks
    - openshift
---

# Poolside Installer

Install the Poolside platform on bastion hosts. This skill automates the installation workflow for three deployment targets: on-premises RKE2, AWS EKS, and OpenShift.

## When to Use

Use this skill when deploying the Poolside stack from a bastion host. The skill handles:
- Operating system prerequisites and tool installation
- Terraform provider configuration for air-gapped environments
- RKE2 cluster setup and credential generation (on-prem only)
- Helm chart deployment and value configuration
- Initial access setup and verification

## Prerequisites

The target bastion host must have:
- Supported OS: Ubuntu 22.04/24.04 LTS, RHEL 9.6, or OpenShift 4.16+
- Root/sudo access
- Network connectivity to the target deployment environment
- Poolside deployment bundle (contact Poolside for access)

## Deployment Types

| Type | Target | Documentation | Key Steps |
|------|--------|---------------|-----------|
| On-Prem | RKE2 on bare metal | [On-Prem Install](https://docs.poolside.ai/deployment/on-prem/install) | Install prerequisites → RKE2 → Credentials → Services → Deploy → Upload models |
| AWS EKS | Managed Kubernetes | [EKS Install](https://docs.poolside.ai/deployment/cloud/aws-eks/install) | Prepare cluster → Upload images → Configure dependencies → Install → DNS |
| OpenShift | Red Hat OpenShift | [OpenShift Install](https://docs.poolside.ai/deployment/cloud/openshift/install) | Create values → Prepare cluster → Upload images/checkpoints → Configure → Install |

## Workflow

### Phase 1: Bastion Preparation

Install required tools based on target OS. See [references/bastion-setup.md](references/bastion-setup.md) for OS-specific instructions.

```bash
# Run from the installation bundle root
./scripts/prepare-bastion.sh
```

### Phase 2: Choose Deployment Target

Select the appropriate deployment path:

**On-Prem RKE2** (full Terraform):
```bash
./scripts/install-onprem.sh
```

**AWS EKS** (Helm):
```bash
./scripts/install-eks.sh
```

**OpenShift** (Helm):
```bash
./scripts/install-openshift.sh
```

### Phase 3: On-Prem Specific Steps

For RKE2 deployments, the workflow includes:

1. **RKE2 Installation** (`01-infra-rke2/`)
   - Install and configure RKE2 Kubernetes
   - Set up GPU drivers if needed
   - Configure sysctl parameters (fs.inotify.max_user_instances = 65535)

2. **Generate Credentials** (`02-rke2-credentials/`)
   - Extract kubeconfig and cluster certificates
   - Set up authentication for later stages

3. **Infrastructure Services** (`03-infra-services/`)
   - Deploy local container registry
   - Deploy PostgreSQL database
   - Deploy S3-compatible storage (SeaweedFS)
   - Deploy Keycloak identity provider
   - Configure TLS certificates (BYO or self-signed)

4. **Platform Deployment** (`04-poolside-deployment/`)
   - Deploy Poolside core services via Helm

5. **Model Upload** (`05-poolside-model-upload/`)
   - Sync model files to S3 storage

6. **Model Deployment** (`06-poolside-inference/`)
   - Deploy inference workloads

### Phase 4: EKS/OpenShift Steps

For cloud deployments, the workflow includes:

1. **Cluster Preparation**
   - Create required namespaces
   - Configure image pull secrets if needed

2. **Image Upload**
   - Sync container images to target registry

3. **External Dependencies**
   - Configure PostgreSQL connection
   - Configure S3 storage
   - Configure encryption (KMS or static key)
   - Configure TLS certificates

4. **Platform Installation**
   - Deploy via Helm with configured values

### Phase 5: Post-Installation

After deployment completes:

1. **Configure DNS** - Map hostnames to load balancer
2. **Initial Setup** - Create organization and admin user in Poolside Console
3. **Model Linking** - Connect deployed models in the console
4. **Enable graceful shutdown** - Configure systemd units

See [references/post-install.md](references/post-install.md) for details.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/prepare-bastion.sh` | Install OS prerequisites and tools |
| `scripts/install-onprem.sh` | Full on-prem RKE2 deployment |
| `scripts/install-eks.sh` | AWS EKS Helm deployment |
| `scripts/install-openshift.sh` | OpenShift Helm deployment |
| `scripts/configure-sysctl.sh` | Set kernel parameters for Ubuntu |

## Troubleshooting

See [references/troubleshooting.md](references/troubleshooting.md) for common issues:
- GPU detection (nvidia-smi verification)
- Pod stuck in ContainerCreating
- Certificate warnings
- Model loading issues
- Database connection errors