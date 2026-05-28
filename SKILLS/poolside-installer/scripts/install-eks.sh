#!/bin/bash
#
# Poolside AWS EKS Installation Script
# This script automates the Helm-based deployment for AWS EKS.
# Run this from the root of the unpacked Poolside installation bundle.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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
    
    command -v helm >/dev/null 2>&1 || missing+=("helm")
    command -v kubectl >/dev/null 2>&1 || missing+=("kubectl")
    command -v aws >/dev/null 2>&1 || missing+=("aws")
    command -v skopeo >/dev/null 2>&1 || missing+=("skopeo")
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
    
    # Verify Kubernetes cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster. Verify kubeconfig."
        exit 1
    fi
}

detect_variables() {
    log_info "Detecting required variables..."
    
    # Prompt for missing values
    if [ -z "${POOLSIDE_DOMAIN:-}" ]; then
        read -p "Enter domain name (e.g., example.com): " POOLSIDE_DOMAIN
    fi
    
    if [ -z "${AWS_REGION:-}" ]; then
        read -p "Enter AWS region: " AWS_REGION
    fi
    
    if [ -z "${ECR_REGISTRY:-}" ]; then
        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
        ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
        log_info "Using ECR registry: $ECR_REGISTRY"
    fi
    
    export POOLSIDE_DOMAIN AWS_REGION ECR_REGISTRY
}

create_namespaces() {
    log_info "Creating Poolside namespaces..."
    
    kubectl create namespace poolside --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace poolside-models --dry-run=client -o yaml | kubectl apply -f -
}

prepare_ecr() {
    log_info "Preparing Amazon ECR repositories..."
    
    local repos=(
        "poolside/core-api"
        "poolside/web-assistant"
        "poolside/console"
        "poolside/keycloak"
        "poolside/seaweedfs-master"
        "poolside/seaweedfs-volume"
        "poolside/seaweedfs-filer"
    )
    
    for repo in "${repos[@]}"; do
        log_info "Creating repository: $repo"
        aws ecr create-repository --repository-name "$repo" --region "$AWS_REGION" 2>/dev/null || true
    done
}

upload_images() {
    log_info "Uploading container images to ECR..."
    
    # Login to ECR
    aws ecr get-login-password --region "$AWS_REGION" | skopeo login --username AWS --password-stdin "$ECR_REGISTRY"
    
    # Check for bundled images
    if [ ! -d "images" ]; then
        log_warn "No 'images' directory found. Assuming images are in container registry."
        return
    fi
    
    # Upload each image
    for img in images/*.tar; do
        [ -f "$img" ] || continue
        img_name=$(basename "$img" .tar)
        log_info "Uploading: $img_name"
        
        skopeo copy \
            --dest-creds "AWS:$(aws ecr get-login-password --region $AWS_REGION)" \
            docker://$img_name \
            docker://$ECR_REGISTRY/$img_name
    done
}

configure_values() {
    log_info "Creating Helm values file..."
    
    cat > poolside_values.yaml <<EOF
global:
  domain: ${POOLSIDE_DOMAIN}
  webHost: poolside.${POOLSIDE_DOMAIN}
  imageRegistry: ${ECR_REGISTRY}
  
  database:
    name: poolside
    user: poolside
    host: ${RDS_HOST:-}
    
  s3:
    bucket: ${S3_BUCKET:-}
    region: ${AWS_REGION}
EOF

    log_info "Created poolside_values.yaml"
    log_warn "Review and edit poolside_values.yaml before proceeding"
    log_warn "Required: RDS_HOST and S3_BUCKET must be set"
}

install_platform() {
    log_info "Installing Poolside platform via Helm..."
    
    if [ ! -d "charts/poolside-deployment" ]; then
        log_error "Helm chart not found: charts/poolside-deployment"
        exit 1
    fi
    
    helm upgrade --install poolside \
        ./charts/poolside-deployment \
        -n poolside \
        -f poolside_values.yaml \
        --create-namespace
}

verify_installation() {
    log_info "Verifying installation..."
    
    log_info "Checking pods..."
    kubectl get pods -n poolside
    
    log_info "Checking ingress..."
    kubectl get ingress -n poolside
    
    log_info "Checking core-api logs..."
    kubectl logs -n poolside -l app.kubernetes.io/name=core-api --tail=20
}

main() {
    log_info "Starting Poolside AWS EKS Installation"
    log_info "====================================="
    
    check_prerequisites
    detect_variables
    create_namespaces
    prepare_ecr
    upload_images
    configure_values
    
    read -p "Review poolside_values.yaml, then press Enter to install..."
    
    install_platform
    verify_installation
    
    log_info "====================================="
    log_info "Installation completed!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Configure DNS: Create Route 53 record for poolside.${POOLSIDE_DOMAIN}"
    log_info "2. See references/post-install.md for initial setup"
}

main "$@"