#!/bin/bash
#
# Poolside OpenShift Installation Script
# This script automates the Helm-based deployment for OpenShift.
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
    command -v oc >/dev/null 2>&1 || missing+=("oc (openshift-cli)")
    command -v skopeo >/dev/null 2>&1 || missing+=("skopeo")
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
    
    # Verify OpenShift cluster connectivity
    if ! oc status >/dev/null 2>&1; then
        log_error "Cannot connect to OpenShift cluster. Verify login."
        exit 1
    fi
}

detect_variables() {
    log_info "Detecting required variables..."
    
    if [ -z "${POOLSIDE_DOMAIN:-}" ]; then
        read -p "Enter domain name (e.g., example.com): " POOLSIDE_DOMAIN
    fi
    
    export POOLSIDE_DOMAIN
}

create_namespaces() {
    log_info "Creating Poolside namespaces..."
    
    oc create namespace poolside --dry-run=client -o yaml | oc apply -f -
    oc create namespace poolside-models --dry-run=client -o yaml | oc apply -f -
    oc create namespace poolside-sandbox --dry-run=client -o yaml | oc apply -f -
}

configure_image_pull() {
    log_info "Configuring image pull access..."
    
    # Check if using internal registry
    if [ "${USE_INTERNAL_REGISTRY:-false}" = "true" ]; then
        log_info "Granting cross-namespace image pull access..."
        
        # Allow poolside namespaces to pull from openshift-image-registry
        oc policy add-role-to-user system:image-puller \
            system:serviceaccount:poolside:default -n openshift-image-registry 2>/dev/null || true
        oc policy add-role-to-user system:image-puller \
            system:serviceaccount:poolside-models:default -n openshift-image-registry 2>/dev/null || true
    fi
}

upload_images() {
    log_info "Uploading container images..."
    
    # Login to target registry
    if [ -n "${REGISTRY_URL:-}" ]; then
        log_info "Logging in to $REGISTRY_URL..."
        skopeo login --username "${REGISTRY_USER:-}" --password "${REGISTRY_PASSWORD:-}" "$REGISTRY_URL"
    fi
    
    # Check for bundled images
    if [ -d "images" ]; then
        for img in images/*.tar; do
            [ -f "$img" ] || continue
            img_name=$(basename "$img" .tar)
            log_info "Uploading: $img_name"
            
            skopeo copy \
                --dest-creds "${REGISTRY_USER:-}:${REGISTRY_PASSWORD:-}" \
                docker://$img_name \
                docker://${REGISTRY_URL:-$img_name}
        done
    fi
}

upload_model_checkpoints() {
    log_info "Uploading model checkpoints to S3..."
    
    if [ ! -d "poolside-models" ]; then
        log_warn "No poolside-models directory found. Skipping checkpoint upload."
        return
    fi
    
    # Configure AWS CLI for S3 upload
    if ! aws configure list 2>/dev/null | grep -q "access_key"; then
        log_info "Configuring AWS credentials..."
        aws configure
    fi
    
    # Upload model files
    local bucket="${S3_BUCKET:-poolside-models}"
    log_info "Uploading to s3://$bucket/"
    
    aws s3 sync poolside-models/ "s3://$bucket/" \
        --endpoint-url "${S3_ENDPOINT_URL:-}"
}

configure_postgres_secret() {
    log_info "Creating PostgreSQL secret..."
    
    oc create secret generic poolside-db-secret \
        --from-literal=POSTGRESQL_PASSWORD="${POSTGRES_PASSWORD:-}" \
        -n poolside \
        --dry-run=client -o yaml | oc apply -f -
}

configure_storage_secret() {
    log_info "Creating S3 storage secret..."
    
    oc create secret generic poolside-s3-secret \
        --from-literal=ENDPOINT_URL="${S3_ENDPOINT_URL:-}" \
        --from-literal=BUCKET="${S3_BUCKET:-poolside-models}" \
        --from-literal=ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}" \
        --from-literal=SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}" \
        -n poolside \
        --dry-run=client -o yaml | oc apply -f -
    
    # Also create in poolside-models if running local inference
    oc create secret generic poolside-s3-secret \
        --from-literal=ENDPOINT_URL="${S3_ENDPOINT_URL:-}" \
        --from-literal=BUCKET="${S3_BUCKET:-poolside-models}" \
        --from-literal=ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}" \
        --from-literal=SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}" \
        -n poolside-models \
        --dry-run=client -o yaml | oc apply -f -
}

configure_scc() {
    log_info "Configuring Security Context Constraints..."
    
    # Add privileged SCC for Poolside workloads
    oc adm policy add-scc-to-user privileged -z default -n poolside
    oc adm policy add-scc-to-user privileged -z default -n poolside-models
    oc adm policy add-scc-to-user privileged -z default -n poolside-sandbox
}

create_values_file() {
    log_info "Creating poolside-values.yaml..."
    
    cat > poolside-values.yaml <<EOF
global:
  domain: ${POOLSIDE_DOMAIN}
  webHost: poolside.${POOLSIDE_DOMAIN}
  imageRegistry: ${IMAGE_REGISTRY:-}
  
  database:
    name: poolside
    user: poolside
    
  s3:
    bucket: ${S3_BUCKET:-poolside-models}
    
  ingressTlsSecretName: ${TLS_SECRET_NAME:-}
EOF
}

install_platform() {
    log_info "Installing Poolside platform..."
    
    if [ ! -d "charts/poolside-deployment" ]; then
        log_error "Helm chart not found: charts/poolside-deployment"
        exit 1
    fi
    
    helm upgrade --install poolside \
        ./charts/poolside-deployment \
        -n poolside \
        -f poolside-values.yaml
}

verify_installation() {
    log_info "Verifying installation..."
    
    log_info "Checking pods..."
    oc get pods -n poolside
    
    log_info "Checking routes..."
    oc get routes -n poolside
    
    log_info "Checking core-api logs..."
    oc logs -n poolside -l app.kubernetes.io/name=core-api --tail=20
}

main() {
    log_info "Starting Poolside OpenShift Installation"
    log_info "======================================"
    
    check_prerequisites
    detect_variables
    create_namespaces
    
    configure_image_pull
    
    log_warn "=== External Dependencies Setup ==="
    configure_postgres_secret
    configure_storage_secret
    configure_scc
    
    upload_images
    
    log_warn "=== Model Checkpoint Upload ==="
    upload_model_checkpoints
    
    create_values_file
    
    read -p "Review poolside-values.yaml, then press Enter to install..."
    
    install_platform
    verify_installation
    
    log_info "======================================"
    log_info "Installation completed!"
    log_info ""
    log_info "Next steps:"
    log_info "1. See references/post-install.md for initial setup"
    log_info "2. Access console via the created route"
}

main "$@"