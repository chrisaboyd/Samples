#!/bin/bash
#
# Poolside Bastion Preparation Script
# Installs required tools and configures the bastion host for Poolside deployment.
# Detects OS automatically and applies appropriate configuration.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

detect_os() {
    log_info "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME="$NAME"
        log_info "Detected: $OS_NAME $OS_VERSION (ID: $OS_ID)"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        log_info "Detected: RHEL"
    else
        log_error "Unable to detect operating system"
        exit 1
    fi
}

check_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        log_warn "This script requires sudo for some operations"
        SUDO="sudo"
    else
        SUDO=""
    fi
}

install_ubuntu() {
    log_step "Installing prerequisites for Ubuntu..."
    
    $SUDO apt-get update
    
    # Install package manager tools
    $SUDO apt-get install -y curl jq unzip
    
    # Install kubectl via snap
    log_info "Installing kubectl via snap..."
    $SUDO snap install kubectl --classic
    
    # Install yq
    log_info "Installing yq..."
    $SUDO curl -L https://github.com/mikefarah/yq/releases/download/v4.49.2/yq_linux_amd64.tar.gz | $SUDO tar xz -C /usr/local/bin yq_linux_amd64
    $SUDO mv /usr/local/bin/yq_linux_amd64 /usr/local/bin/yq
    $SUDO chmod +x /usr/local/bin/yq
    
    # Install Terraform
    log_info "Installing Terraform 1.8.5..."
    curl -LO https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip
    $SUDO unzip -o terraform_1.8.5_linux_amd64.zip -d /usr/local/bin/
    $SUDO chmod +x /usr/local/bin/terraform
    rm -f terraform_1.8.5_linux_amd64.zip
    
    # Install skopeo
    log_info "Installing skopeo..."
    $SUDO curl -L https://github.com/lework/skopeo-binary/releases/download/v1.20.0/skopeo-linux-amd64 -o /usr/local/bin/skopeo
    $SUDO chmod +x /usr/local/bin/skopeo
    
    # Configure sysctl for inotify
    log_info "Configuring sysctl parameters..."
    echo "fs.inotify.max_user_instances = 65535" | $SUDO tee /etc/sysctl.d/99-poolside.conf
    $SUDO sysctl --system
    
    # Check nouveau driver
    if lsmod | grep -q nouveau 2>/dev/null; then
        log_warn "nouveau driver is loaded. GPU workloads will fail."
        log_warn "Run disable_nouveau function or follow manual instructions."
    else
        log_info "nouveau driver is not loaded (OK)"
    fi
}

install_rhel() {
    log_step "Installing prerequisites for RHEL 9.6..."
    
    # Lock release to 9.6 to prevent minor version upgrades
    if command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y yum-utils 2>/dev/null || true
        $SUDO dnf versionlock add redhat-release 2>/dev/null || true
    fi
    
    # Install RPM packages
    $SUDO yum install -y iptables-nft container-selinux curl jq unzip
    
    # Install kubectl
    log_info "Installing kubectl..."
    cat <<EOF | $SUDO tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el9-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/repos/kubernetes-release-el9-x86_64.gpg
EOF
    
    $SUDO yum install -y kubectl
    
    # Install yq
    log_info "Installing yq..."
    $SUDO curl -L https://github.com/mikefarah/yq/releases/download/v4.49.2/yq_linux_amd64.tar.gz | $SUDO tar xz -C /usr/local/bin yq_linux_amd64
    $SUDO mv /usr/local/bin/yq_linux_amd64 /usr/local/bin/yq
    $SUDO chmod +x /usr/local/bin/yq
    
    # Install Terraform
    log_info "Installing Terraform 1.8.5..."
    curl -LO https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip
    $SUDO unzip -o terraform_1.8.5_linux_amd64.zip -d /usr/local/bin/
    $SUDO chmod +x /usr/local/bin/terraform
    rm -f terraform_1.8.5_linux_amd64.zip
    
    # Add /usr/local/bin to secure_path for sudo
    if ! grep -q "/usr/local/bin" /etc/sudoers 2>/dev/null; then
        log_info "Adding /usr/local/bin to sudo secure_path..."
        $SUDO sed -i 's|secure_path = .*|secure_path = /sbin:/bin:/usr/sbin:/usr/local/bin:/usr/bin|' /etc/sudoers
    fi
    
    # Install skopeo (from RHEL repos if available)
    log_info "Installing skopeo..."
    $SUDO yum install -y skopeo-1.18.1-2.el9_6.x86_64 2>/dev/null || {
        $SUDO curl -L https://github.com/lework/skopeo-binary/releases/download/v1.20.0/skopeo-linux-amd64 -o /usr/local/bin/skopeo
        $SUDO chmod +x /usr/local/bin/skopeo
    }
    
    # Check nouveau driver
    if lsmod | grep -q nouveau 2>/dev/null; then
        log_warn "nouveau driver is loaded. GPU workloads will fail."
    else
        log_info "nouveau driver is not loaded (OK)"
    fi
}

install_amazon_linux() {
    log_step "Installing prerequisites for Amazon Linux..."
    
    $SUDO yum install -y curl jq unzip
    
    # Install kubectl
    log_info "Installing kubectl..."
    curl -LO https://s3.us-west-2.amazonaws.com/amazon-eks/1.30/2024-09-12/eksctl/bin/linux/amd64/kubectl
    $SUDO install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    
    # Install yq
    log_info "Installing yq..."
    $SUDO curl -L https://github.com/mikefarah/yq/releases/download/v4.49.2/yq_linux_amd64.tar.gz | $SUDO tar xz -C /usr/local/bin yq_linux_amd64
    $SUDO mv /usr/local/bin/yq_linux_amd64 /usr/local/bin/yq
    $SUDO chmod +x /usr/local/bin/yq
    
    # Install Terraform
    log_info "Installing Terraform 1.8.5..."
    curl -LO https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip
    $SUDO unzip -o terraform_1.8.5_linux_amd64.zip -d /usr/local/bin/
    $SUDO chmod +x /usr/local/bin/terraform
    rm -f terraform_1.8.5_linux_amd64.zip
    
    # Install skopeo
    log_info "Installing skopeo..."
    $SUDO yum install -y skopeo
}

configure_containers_policy() {
    log_step "Configuring container trust policy for air-gapped environments..."
    
    $SUDO mkdir -p /etc/containers
    
    cat <<EOF | $SUDO tee /etc/containers/policy.json
{
  "default": [
    {
      "type": "insecureAcceptAnything"
    }
  ]
}
EOF
    
    log_info "Container trust policy configured"
}

install_helm() {
    log_step "Installing Helm..."
    
    if ! command -v helm >/dev/null 2>&1; then
        curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | $SUDO bash
    else
        log_info "Helm already installed: $(helm version --short)"
    fi
}

verify_installation() {
    log_step "Verifying installation..."
    
    echo ""
    echo "Installed tools:"
    echo "  kubectl:  $(kubectl version --client --short 2>/dev/null || echo 'not found')"
    echo "  terraform: $(terraform version 2>/dev/null || echo 'not found')"
    echo "  yq:       $(yq --version 2>/dev/null || echo 'not found')"
    echo "  jq:       $(jq --version 2>/dev/null || echo 'not found')"
    echo "  skopeo:   $(skopeo --version 2>/dev/null || echo 'not found')"
    echo "  helm:     $(helm version --short 2>/dev/null || echo 'not found')"
    echo ""
    
    # Verify inotify setting
    local inotify=$(sysctl -n fs.inotify.max_user_instances 2>/dev/null || echo "0")
    if [ "$inotify" -ge 65535 ]; then
        log_info "sysctl fs.inotify.max_user_instances = $inotify (OK)"
    else
        log_warn "sysctl fs.inotify.max_user_instances = $inotify (recommended: 65535)"
    fi
}

disable_nouveau() {
    log_step "Disabling nouveau driver..."
    
    $SUDO bash -c 'cat > /etc/modprobe.d/blacklist-nouveau.conf <<EOF
blacklist nouveau
options nouveau modeset=0
EOF'
    
    if [ "$OS_ID" = "ubuntu" ]; then
        $SUDO update-initramfs -u
    elif [ "$OS_ID" = "rhel" ] || [ "$OS_ID" = "centos" ]; then
        $SUDO dracut --force
    fi
    
    log_warn "nouveau driver disabled. Reboot required for changes to take effect."
    log_warn "Run: sudo systemctl reboot"
}

main() {
    log_info "==============================================="
    log_info "Poolside Bastion Preparation Script"
    log_info "==============================================="
    
    check_sudo
    detect_os
    
    case "$OS_ID" in
        ubuntu)
            install_ubuntu
            ;;
        rhel|rocky|almalinux)
            install_rhel
            ;;
        amzn)
            install_amazon_linux
            ;;
        *)
            log_error "Unsupported OS: $OS_ID"
            log_info "Manual installation required. See references/bastion-setup.md"
            exit 1
            ;;
    esac
    
    # Install Helm for EKS/OpenShift deployments
    install_helm
    
    # Configure container trust policy
    configure_containers_policy
    
    # Verify all installations
    verify_installation
    
    log_info "==============================================="
    log_info "Bastion preparation complete!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Reboot if nouveau driver was modified"
    log_info "2. Download Poolside installation bundle"
    log_info "3. Run appropriate install script:"
    log_info "   - ./scripts/install-onprem.sh   (RKE2)"
    log_info "   - ./scripts/install-eks.sh      (AWS EKS)"
    log_info "   - ./scripts/install-openshift.sh (OpenShift)"
    log_info "==============================================="
}

# Handle command line arguments
case "${1:-}" in
    --nouveau-only)
        disable_nouveau
        ;;
    *)
        main "$@"
        ;;
esac