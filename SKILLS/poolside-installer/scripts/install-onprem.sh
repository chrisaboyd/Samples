#!/bin/bash
#
# Poolside On-Prem RKE2 Installation Script
# This script automates the Terraform-based deployment for on-premises installations.
# Run this from the root of the unpacked Poolside installation bundle.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing=()
    
    command -v terraform >/dev/null 2>&1 || missing+=("terraform")
    command -v kubectl >/dev/null 2>&1 || missing+=("kubectl")
    command -v yq >/dev/null 2>&1 || missing+=("yq")
    command -v jq >/dev/null 2>&1 || missing+=("jq")
    command -v skopeo >/dev/null 2>&1 || missing+=("skopeo")
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_info "Run ./scripts/prepare-bastion.sh first"
        exit 1
    fi
    
    # Check Terraform version
    if ! terraform version | grep -q "1.8.5"; then
        log_warn "Terraform version 1.8.5 recommended. Current version may cause issues."
    fi
    
    # Check installation bundle structure
    if [ ! -f "poolside-terraform.tfrc" ]; then
        log_error "poolside-terraform.tfrc not found. Are you in the bundle root?"
        exit 1
    fi
}

configure_terraform() {
    log_info "Configuring Terraform for air-gapped environment..."
    export TF_CLI_CONFIG_FILE="$(pwd)/poolside-terraform.tfrc"
    export POOLSIDE_INSTALL_DIR="$(pwd)"
    
    log_info "TF_CLI_CONFIG_FILE=$TF_CLI_CONFIG_FILE"
    log_info "POOLSIDE_INSTALL_DIR=$POOLSIDE_INSTALL_DIR"
}

run_terraform_stage() {
    local stage_dir="$1"
    local stage_name="$2"
    
    log_info "Running stage: $stage_name"
    
    if [ ! -d "$stage_dir" ]; then
        log_error "Stage directory not found: $stage_dir"
        exit 1
    fi
    
    pushd "$stage_dir" >/dev/null
    
    log_info "Initializing Terraform..."
    TF_CLI_CONFIG_FILE="$TF_CLI_CONFIG_FILE" terraform init
    
    log_info "Applying Terraform configuration..."
    TF_CLI_CONFIG_FILE="$TF_CLI_CONFIG_FILE" terraform apply -auto-approve
    
    popd >/dev/null
    
    log_info "Stage $stage_name completed successfully"
}

verify_nouveau_disabled() {
    log_info "Verifying nouveau driver is disabled..."
    
    if lsmod | grep -q nouveau; then
        log_error "nouveau driver is still loaded. GPU workloads will fail."
        log_info "Follow the nouveau disable instructions in references/bastion-setup.md"
        exit 1
    fi
    
    log_info "nouveau driver verification passed"
}

verify_sysctl() {
    log_info "Verifying sysctl parameters..."
    
    local current=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo "0")
    if [ "$current" -lt 65535 ]; then
        log_warn "fs.inotify.max_user_instances is $current, recommended 65535"
        log_info "Run: echo 'fs.inotify.max_user_instances = 65535' | sudo tee /etc/sysctl.d/99-poolside.conf"
        log_info "Then: sudo sysctl --system"
    fi
}

main() {
    log_info "Starting Poolside On-Prem RKE2 Installation"
    log_info "=========================================="
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log_info "Detected OS: $NAME $VERSION"
    fi
    
    check_prerequisites
    verify_nouveau_disabled
    verify_sysctl
    configure_terraform
    
    # Stage 1: RKE2 Infrastructure
    run_terraform_stage "01-infra-rke2" "RKE2 Installation"
    
    # Stage 2: RKE2 Credentials
    run_terraform_stage "02-rke2-credentials" "RKE2 Credentials"
    
    # Stage 3: Infrastructure Services (PostgreSQL, SeaweedFS, Keycloak)
    run_terraform_stage "03-infra-services" "Infrastructure Services"
    
    # Stage 4: Poolside Platform
    run_terraform_stage "04-poolside-deployment" "Poolside Platform"
    
    # Stage 5: Model Upload
    log_info "Stage 5: Model Upload"
    log_warn "Before proceeding, copy model files to poolside-models/ host directory"
    read -p "Press Enter to continue or Ctrl+C to abort..."
    
    run_terraform_stage "05-poolside-model-upload" "Model Upload"
    
    # Stage 6: Model Deployment
    log_info "Stage 6: Model Inference"
    log_warn "Ensure models are uploaded before proceeding"
    read -p "Press Enter to continue or Ctrl+C to abort..."
    
    run_terraform_stage "06-poolside-inference" "Model Inference"
    
    log_info "=========================================="
    log_info "Installation completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Configure DNS: See references/post-install.md"
    log_info "2. Access console at: https://poolside.poolside.local/console"
    log_info "3. Run verification: kubectl get pods -A"
}

# Allow running individual stages
if [ "${1:-}" = "--stage" ]; then
    configure_terraform
    shift
    run_terraform_stage "$1" "${2:-$1}"
else
    main "$@"
fi