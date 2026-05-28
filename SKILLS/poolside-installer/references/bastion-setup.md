# Bastion Host Setup

This reference covers prerequisite installation on bastion hosts for each deployment target.

## Common Requirements

All deployment types require these tools:
- kubectl (matching RKE2/Kubernetes version)
- curl
- jq
- yq (v4.49.2 or later)
- terraform (v1.8.5)
- skopeo (v1.18 or later)
- unzip (for Terraform extraction)

## Operating System: RHEL 9.6

Lock the release to prevent automatic minor version upgrades:

```bash
# Lock to RHEL 9.6
sudo dnf install -y yum-utils
sudo dnf versionlock add redhat-release

# Install prerequisite packages
sudo yum install -y iptables-nft
sudo yum install -y container-selinux
sudo yum install -y curl
sudo yum install -y jq  # v1.6 or later
sudo yum install -y unzip  # v6.00 or later
```

### Install yq

```bash
# Download and install yq
sudo curl -L https://github.com/mikefarah/yq/releases/download/v4.49.2/yq_linux_amd64.tar.gz | sudo tar xz -C /usr/local/bin yq_linux_amd64
sudo mv /usr/local/bin/yq_linux_amd64 /usr/local/bin/yq
sudo chmod +x /usr/local/bin/yq
```

### Install Terraform

```bash
sudo curl -LO https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip
sudo unzip terraform_1.8.5_linux_amd64.zip -d /usr/local/bin/
sudo chmod +x /usr/local/bin/terraform
```

Note: In RHEL 9.x, `/usr/local/bin` is not in secure_path by default. Use absolute path or add to sudoers:

```bash
sudo terraform --version  # Use full path
# OR add to sudoers: sudo visudo
# Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/local/bin:/usr/bin
```

### Install skopeo

```bash
sudo yum install -y skopeo-1.18.1-2.el9_6.x86_64
```

### Install kubectl

```bash
# Add Kubernetes repository
cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el9-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/repos/kubernetes-release-el9-x86_64.gpg
EOF

sudo yum install -y kubectl
```

### Disable nouveau Driver

```bash
# Check if nouveau is loaded
lsmod | grep nouveau
# If output exists, disable:
cat <<EOF | sudo tee /etc/modprobe.d/blacklist-nouveau.conf
blacklist nouveau
options nouveau modeset=0
EOF

# Regenerate initramfs
sudo dracut --force

# Update grub config
sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg

# Reboot required
sudo systemctl reboot
```

## Operating System: Ubuntu 22.04/24.04 LTS

### Install Packages

```bash
sudo snap install kubectl --classic
sudo apt update
sudo apt install -y curl jq
```

### Install yq

```bash
sudo curl -L https://github.com/mikefarah/yq/releases/download/v4.49.2/yq_linux_amd64.tar.gz | sudo tar xz -C /usr/local/bin yq_linux_amd64
sudo chmod +x /usr/local/bin/yq
```

### Install Terraform

```bash
sudo curl -LO https://releases.hashicorp.com/terraform/1.8.5/terraform_1.8.5_linux_amd64.zip
sudo unzip terraform_1.8.5_linux_amd64.zip -d /usr/local/bin/
sudo chmod +x /usr/local/bin/terraform
```

### Install skopeo

```bash
# Download skopeo binary
sudo curl -L https://github.com/lework/skopeo-binary/releases/download/v1.20.0/skopeo-linux-amd64 -o /usr/local/bin/skopeo
sudo chmod +x /usr/local/bin/skopeo
```

### Configure skopeo Trust Policy

```bash
# For air-gapped environments, allow insecure registry access
sudo mkdir -p /etc/containers
cat <<EOF | sudo tee /etc/containers/policy.json
{
  "default": [
    {
      "type": "insecureAcceptAnything"
    }
  ]
}
EOF
```

### Disable nouveau Driver

```bash
# Check if nouveau is loaded
lsmod | grep nouveau

# If output exists, disable:
cat <<EOF | sudo tee /etc/modprobe.d/blacklist-nouveau.conf
blacklist nouveau
options nouveau modeset=0
EOF

# Regenerate initramfs
sudo update-initramfs -u

# Reboot required
sudo reboot
```

### Configure sysctl Parameters

Ubuntu requires increasing inotify limits for the platform:

```bash
echo "fs.inotify.max_user_instances = 65535" | sudo tee /etc/sysctl.d/99-poolside.conf
sudo sysctl --system
```

## Operating System: Amazon Linux 2023 (EKS Bastion)

```bash
sudo dnf install -y curl jq unzip
# Install kubectl, yq, terraform, skopeo as needed
```

## Air-Gapped Environment Configuration

When deploying in air-gapped environments, configure Terraform to use the bundled provider cache:

```bash
# From the installation bundle root
export POOLSIDE_INSTALL_DIR=$(pwd)

# Configure Terraform CLI
export TF_CLI_CONFIG_FILE=$POOLSIDE_INSTALL_DIR/poolside-terraform.tfrc

# Verify configuration
terraform version
```

The poolside-terraform.tfrc file contains provider installation settings pointing to the bundled terraform.d directory.