# Troubleshooting

## Common Issues

### Model Pods Stuck in ContainerCreating

**Symptom**: Pods show `ContainerCreating` status and don't progress.

**Diagnosis**:
```bash
kubectl describe pod <pod-name> -n poolside-models
```

**Remediation**:
1. Verify GPU availability on host:
   ```bash
   nvidia-smi
   ```
2. Scale deployment to 0 then back up:
   ```bash
   kubectl scale deployment <deployment-name> -n poolside-models --replicas=0
   kubectl scale deployment <deployment-name> -n poolside-models --replicas=1
   ```

### Certificate Warnings in Browser

**Symptom**: Browser shows certificate warnings when accessing Poolside Console.

**Remediation**:
1. Trust the cluster CA certificate:
   - On-prem: Find cert in `poolside-install/` directory
   - EKS/OpenShift: Download from cluster or use cert-manager

2. Ubuntu/Debian:
   ```bash
   sudo cp poolside-ca.crt /usr/local/share/ca-certificates/
   sudo update-ca-certificates
   ```

3. RHEL:
   ```bash
   sudo cp poolside-ca.crt /etc/pki/ca-trust/source/anchors/
   sudo update-ca-trust
   ```

### Models Not Loading

**Symptom**: Models show error or unhealthy status in Poolside Console.

**Diagnosis**:
```bash
# Verify services are running
kubectl get pods -A

# Check model upload status
cd 05-poolside-model-upload
terraform show

# Verify S3 bucket has model files
kubectl exec -n poolside deploy/seaweedfs-master -- ls /data/poolside-models/
```

**Remediation**:
1. Re-run model upload step if files are missing
2. Check model_s3_uri values in `06-poolside-inference/terraform.tfvars`

### Database Connection Errors

**Symptom**: Core API fails to start or shows database errors.

**Diagnosis**:
```bash
# Check core-api logs
kubectl logs -n poolside -l app.kubernetes.io/name=core-api --tail=50

# Verify PostgreSQL is accessible
kubectl get pods -n poolside -l app.kubernetes.io/name=postgresql
kubectl exec -it -n poolside svc/postgresql -- psql -U poolside -c "SELECT 1"
```

**Remediation**:
1. Verify PostgreSQL credentials in secret:
   ```bash
   kubectl get secret poolside-db-secret -n poolside -o yaml
   ```
2. Check sslMode matches RDS configuration (EKS)
3. Re-run `03-infra-services` to regenerate credentials (on-prem)

### Image Pull Failures

**Symptom**: Pods stuck in ErrImagePull or ImagePullBackOff.

**Diagnosis**:
```bash
kubectl describe pod <pod-name> -n poolside
```

**Remediation by Platform**:

**On-Prem/RKE2**:
- Verify local registry is running: `kubectl get pods -n registry`
- Check registry credentials: `kubectl get secret -n poolside poolside-registry-secret`

**EKS**:
- Verify IRSA role has ECR read access
- Check imagePullSecrets reference in values.yaml

**OpenShift**:
- Verify image pull secret exists: `oc get secret -n poolside`
- Check cross-namespace pull access for internal registry:
  ```bash
  oc policy add-role-to-user system:image-puller system:serviceaccount:poolside:poolside-registry-pull -n openshift-image-registry
  ```

### GPU Not Detected

**Symptom**: GPU nodes show but nvidia-smi fails or pods can't schedule GPU workloads.

**Diagnosis**:
```bash
# Check node labels
kubectl get nodes -L poolside/gpu-node

# Check NVIDIA device plugin
kubectl get pods -n gpu-operator
kubectl logs -n gpu-operator daemonset/nvidia-device-plugin

# Verify driver installation
kubectl exec -n gpu-operator ds/nvidia-driver -- nvidia-smi
```

**Remediation**:
1. Install NVIDIA GPU Operator (on-prem):
   ```bash
   helm install nvidia-gpu-operator \
     -n gpu-operator --create-namespace \
     nvidia/gpu-operator
   ```
2. Verify nouveau driver is disabled after reboot

### Core API Errors

**Symptom**: Core API pods crashloop or show errors in logs.

**Diagnosis**:
```bash
kubectl logs -n poolside -l app.kubernetes.io/name=core-api --tail=100
```

**Remediation**:
1. Check for "level=INFO msg='server is running'" in logs (success indicator)
2. Verify S3 flush loops are running in logs
3. Check database connection succeeded in logs

### Terraform State Issues

**Symptom**: Terraform commands fail with state lock errors or drift warnings.

**Remediation**:
```bash
# Force unlock state (replace <lock-id> with actual ID)
terraform force-unlock <lock-id>

# For on-prem, if RKE2 credentials change:
cd 02-rke2-credentials
terraform apply

# Re-run dependent stages
```

## Platform-Specific Issues

### On-Prem RKE2

#### RKE2 Service Won't Start

```bash
# Check RKE2 logs
journalctl -u rke2-server -f

# Common fix: ensure /usr/local/bin is in secure_path
sudo visudo
# Add: Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/local/bin:/usr/bin
```

#### Registry Access Denied

```bash
# Check policy.json allows insecure access for air-gapped
cat /etc/containers/policy.json

# Should contain:
# {"default": [{"type": "insecureAcceptAnything"}]}
```

### AWS EKS

#### ALB Cannot Be Reached

```bash
# Check if NAT gateway IPs are in inbound-cidrs annotation
kubectl get ingress -n poolside -o yaml | grep inbound-cidrs

# In-cluster pods reach ALB through NAT gateway
# Add NAT gateway public IP to alb.ingress.kubernetes.io/inbound-cidrs
```

#### ECR Pull Failures

```bash
# Verify EKS node role has AmazonEC2ContainerRegistryReadOnly
# Or create image pull secret:
kubectl create secret docker-registry poolside-registry-secret \
  --docker-server=<account>.dkr.ecr.<region>.amazonaws.com \
  --docker-username=AWS \
  --docker-password=$(aws ecr get-login-password) \
  -n poolside
```

### OpenShift

#### SCC Permission Denied

```bash
# Poolside requires privileged containers
# Check if service accounts have appropriate SCC
oc get scc

# Add privileged SCC to poolside service accounts:
oc adm policy add-scc-to-user privileged -z default -n poolside
oc adm policy add-scc-to-user privileged -z default -n poolside-models
```

#### Route Creation Fails

```bash
# If using custom TLS secret, routes may fail
# Set global.ingressTlsSecretName to use Ingress instead of Routes
helm upgrade --install poolside ... --set global.ingressTlsSecretName=poolside-tls
```

## Log Collection

For support requests, collect these logs:

```bash
# On-prem: RKE2 service logs
sudo journalctl -u rke2-server --since "1 hour ago" > rke2-server.log

# All platforms: Core API logs
kubectl logs -n poolside -l app.kubernetes.io/name=core-api --since="1h" > core-api.log

# All platforms: All pods in poolside namespace
kubectl get pods -n poolside -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | \
  xargs -I {} kubectl logs -n poolside {} --since="1h" > poolside-pods.log

# Model reconciler logs (if applicable)
kubectl logs -n poolside -l app.kubernetes.io/name=models-reconciler --since="1h" > models-reconciler.log
```