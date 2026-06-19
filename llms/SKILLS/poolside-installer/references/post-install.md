# Post-Installation Configuration

## DNS Configuration

### On-Prem / Local Setup

Add hostname mappings on the deployment host for local service callbacks:

```bash
# Add to /etc/hosts
echo "127.0.0.1 poolside.poolside.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 keycloak.poolside.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 console.poolside.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 chat.poolside.local" | sudo tee -a /etc/hosts
echo "127.0.0.1 docs.poolside.local" | sudo tee -a /etc/hosts
```

### AWS EKS

Create Route 53 records pointing to the ALB hostname:

```bash
# Get ALB hostname from ingress
kubectl get ingress -n poolside

# Create ALIAS record pointing poolside.example.com to the ALB
```

### OpenShift

Routes are typically auto-created. For custom hostnames:

```bash
# Patch route hostname if using custom domain
oc patch route <route-name> -n poolside -p '{"spec":{"host":"poolside.example.com"}}'
```

## Initial Poolide Setup

### 1. Access the Console

Navigate to: https://poolside.<domain>/console

### 2. Retrieve OIDC Configuration

Get identity provider values from Terraform output:

```bash
cd 03-infra-services
terraform output oidc_provider_url
terraform output client_api_credentials
```

### 3. Configure Identity Provider

In the Poolside Console, create your organization with:

- **Provider URL**: Value from oidc_provider_url output
- **Client ID**: client_api_credentials.id value
- **Client Secret**: client_api_credentials.secret value

### 4. Register Administrator User

Click "Register" to create the first admin account. This user is automatically assigned the tenant-admin role.

### 5. Link Deployed Models

Navigate to Agents > Models in the Poolside Console:

1. Click "New Model"
2. Enter Model Name and Base URL from deployment output
3. Click "Connect to Model"

## Enable Graceful Shutdown

Enable the poolside-services systemd unit for clean shutdowns:

```bash
# Enable the unit
sudo systemctl enable poolside-services

# Verify status
sudo systemctl status poolside-services
```

For planned shutdowns:

```bash
# Stop Poolside workloads cleanly
sudo systemctl stop poolside-services
# Then reboot or shutdown
sudo systemctl reboot
```

## Verification Checklist

### All Deployments

- [ ] All pods running: `kubectl get pods -A`
- [ ] Web interface accessible at https://poolside.<domain>
- [ ] Models show Healthy status in Poolside Console
- [ ] Chat functionality works in Poolside Chat
- [ ] PostgreSQL pods are Running
- [ ] Keycloak pods are Running
- [ ] Storage (SeaweedFS or S3) is accessible

### On-Prem Specific

- [ ] RKE2 service is active: `systemctl status rke2-server`
- [ ] Local registry is running: `kubectl get pods -n registry`
- [ ] GPU nodes are Ready: `kubectl get nodes -l poolside/gpu-node=true`

### EKS Specific

- [ ] ALB addresses are assigned: `kubectl get ingress -n poolside`
- [ ] IRSA roles are configured for S3/KMS access
- [ ] Node group has GPU instances (if applicable)

### OpenShift Specific

- [ ] Routes are created: `oc get routes -n poolside`
- [ ] Image pull secrets are configured in both namespaces
- [ ] SCC (Security Context Constraints) allow privileged containers

## Useful Commands

```bash
# Get all pods across namespaces
kubectl get pods -A

# Get poolside deployment status
kubectl get pods -n poolside

# Get model deployment status
kubectl get pods -n poolside-models

# Stream core-api logs
kubectl logs -n poolside -l app.kubernetes.io/name=core-api -f

# Check ingress status
kubectl get ingress -n poolside

# Get model deployment output
cd 06-poolside-inference
terraform output
```