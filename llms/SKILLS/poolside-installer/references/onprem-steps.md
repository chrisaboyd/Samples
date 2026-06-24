# On-Prem Detailed Installation Steps

This reference provides the complete step-by-step Terraform workflow for on-premises deployments.

## Stage 1: RKE2 Infrastructure (`01-infra-rke2/`)

### Overview

This Terraform module installs and configures RKE2 Kubernetes on the host system, including GPU operator setup.

### Prerequisites

- nouveau driver must be disabled and system rebooted
- sysctl `fs.inotify.max_user_instances = 65535` must be configured
- All tools from prepare-bastion.sh must be installed

### Commands

```bash
cd 01-infra-rke2

# Initialize Terraform (air-gapped)
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform init

# Review configuration
terraform plan

# Apply configuration
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform apply
```

### Important Notes

- **Must run as sudo** from the same user account that will run Poolside after deployment
- Terraform uses original user/group IDs to set ownership for later stages
- GPU drivers are installed automatically by the RKE2 GPU operator
- The process loads container images into local registry

## Stage 2: RKE2 Credentials (`02-rke2-credentials/`)

### Overview

Extracts kubeconfig and cluster certificates for authentication in later stages.

### Commands

```bash
cd 02-rke2-credentials

TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform init
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform apply
```

### Output

Generated files (stored in `poolside-install/`):
- `kubeconfig` - Kubernetes cluster access configuration
- `rke2-ca.crt` - Cluster CA certificate

### Regeneration

If certificates change, re-run this stage to restore cluster access.

## Stage 3: Infrastructure Services (`03-infra-services/`)

### Overview

Deploys supporting infrastructure:
- Local container registry
- PostgreSQL database
- SeaweedFS S3-compatible object store
- Keycloak identity provider

### Default Passwords

The module creates default credentials. Change these in production!

### Commands

```bash
cd 03-infra-services

TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform init
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform apply
```

### TLS Certificate Configuration

For production, provide your own certificates:

```bash
# Place certificates in bundle (recommended path)
mkdir -p poolside-install/byo-certs/
cp your-ca.crt poolside-install/byo-certs/
cp your-server.crt poolside-install/byo-certs/
cp your-server.key poolside-install/byo-certs/

# Configure terraform.tfvars
cat >> terraform.tfvars <<EOF
custom_certificates = {
  poolside = {
    ca_cert_path     = "poolside-install/byo-certs/your-ca.crt"
    server_cert_path = "poolside-install/byo-certs/your-server.crt"
    server_key_path  = "poolside-install/byo-certs/your-server.key"
  }
  services = {
    storage = {
      # ... similar structure
    }
    identity = {
      # ... similar structure
    }
  }
}
EOF
```

### Required SANs

Certificates must include these hostnames:
- `poolside.<domain>`
- `console.<domain>`
- `chat.<domain>`
- `keycloak.<domain>`
- `storage.<domain>`
- `docs.<domain>`

Or use wildcard: `*.<domain>`

## Stage 4: Poolside Platform (`04-poolside-deployment/`)

### Overview

Deploys the core Poolside platform Helm chart into the RKE2 cluster.

### Commands

```bash
cd 04-poolside-deployment

TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform init
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform apply
```

### Configuration

Review `terraform.tfvars` for:
- Domain name configuration
- TLS secret references (from Stage 3)
- Any customizations made in earlier stages

### Duration

This stage loads images into the local registry and can take several minutes.

## Stage 5: Model Upload (`05-poolside-model-upload/`)

### Overview

Syncs Poolside model files from local host directory to S3-compatible storage.

### Prerequisites

- Model files must be copied to `poolside-models/` host directory
- If you customized host volume paths in Stage 1, use those paths

### Commands

```bash
cd 05-poolside-model-upload

# Ensure models are in place
ls -la ../poolside-models/

TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform init
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform apply
```

### Incremental Uploads

This step can be re-run to upload additional models without affecting existing ones.

## Stage 6: Model Inference (`06-poolside-inference/`)

### Overview

Deploys Poolside models from S3 into the RKE2 cluster.

### Finding Model S3 URIs

```bash
# List uploaded models
aws s3 ls s3://poolside-models/ --recursive

# Example output:
# 2024-01-15 10:30:00   1234567890 laguna-70b/model-files.tar.gz
# 2024-01-15 10:35:00    500000000 point-code/model-files.tar.gz

# S3 URIs would be:
# s3://poolside-models/laguna-70b/
# s3://poolside-models/point-code/
```

### Configuration

Create `terraform.tfvars`:

```hcl
model_s3_uris = {
  "laguna-70b" = "s3://poolside-models/laguna-70b/"
  "point-code" = "s3://poolside-models/point-code/"
}

model_replicas = {
  "laguna-70b" = 1
  "point-code" = 1
}

model_gpu_types = {
  "laguna-70b" = "nvidia-a100"
  "point-code" = "nvidia-a10g"
}
```

### Commands

```bash
cd 06-poolside-inference

TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform init
TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc terraform apply
```

### Verify Deployment

```bash
# Get deployed model information
terraform output

# Check model pods
kubectl get pods -n poolside-models
```

## Environment Variables

All stages need these environment variables:

```bash
export TF_CLI_CONFIG_FILE=<path-to-bundle>/poolside-terraform.tfrc
export POOLSIDE_INSTALL_DIR=<path-to-bundle>
```

For manual Terraform runs, prefix with the config file:

```bash
TF_CLI_CONFIG_FILE=<path>/poolside-terraform.tfrc terraform <command>
```

## Common Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `POOLSIDE_INSTALL_DIR` | Absolute path to bundle root | `/home/user/poolside-bundle` |
| `domain_name` | Base domain for services | `poolside.local` |
| `model_s3_uri` | S3 path for model files | `s3://poolside-models/laguna-70b/` |

## File Structure

After deployment, the bundle contains:

```
poolside-bundle/
├── poolside-terraform.tfrc      # Terraform provider config
├── 01-infra-rke2/             # RKE2 Terraform module
├── 02-rke2-credentials/       # Credential generation
├── 03-infra-services/         # Infrastructure services
├── 04-poolside-deployment/    # Platform deployment
├── 05-poolside-model-upload/  # Model sync
├── 06-poolside-inference/     # Model deployment
├── poolside-install/            # Persistent state
│   ├── kubeconfig             # Generated kubeconfig
│   └── byo-certs/             # Custom certificates
└── poolside-models/             # Model checkpoint files
```