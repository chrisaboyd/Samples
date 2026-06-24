# Cloud Deployment Values Configuration

This reference provides detailed Helm values configuration for AWS EKS and OpenShift deployments.

## AWS EKS Values

### Required Values

```yaml
# poolside_values.yaml
global:
  domain: "example.com"
  webHost: "poolside.example.com"
  imageRegistry: "<account-id>.dkr.ecr.<region>.amazonaws.com"
  
  database:
    name: poolside
    user: poolside
    host: "poolside.cluster-xxxxxxxxxxxx.<region>.rds.amazonaws.com"
    port: 5432
    
  s3:
    bucket: "poolside-models-bucket"
    region: "us-west-2"
    # For IRSA, leave secretName empty
    # For static credentials, set secretName: poolside-s3-secret
```

### RDS Configuration

**Create Database and User:**

```sql
CREATE DATABASE poolside;
CREATE ROLE poolside LOGIN PASSWORD '<set-a-strong-password>';
ALTER DATABASE poolside OWNER TO poolside;
```

**Create Password Secret:**

```bash
kubectl create secret generic poolside-db-secret \
  --from-literal=POSTGRESQL_PASSWORD='<password>' \
  -n poolside
```

### Encryption Key Configuration

**Option A: AWS KMS**

```yaml
global:
  encryption:
    kmsKeyId: "arn:aws:kms:<region>:<account>:key/<key-id>"
```

**Option B: Static Key (test only)**

```yaml
global:
  encryption:
    secretKey: "your-32-character-encryption-key-here"
```

### IRSA Configuration

**S3 Access Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::poolside-models-bucket",
        "arn:aws:s3:::poolside-models-bucket/*"
      ]
    }
  ]
}
```

**KMS Access Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext"
      ],
      "Resource": "arn:aws:kms:<region>:<account>:key/<key-id>"
    }
  ]
}
```

**Trust Policy for IRSA:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<account>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<oidc-id>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.<region>.amazonaws.com/id/<oidc-id>:sub": [
            "system:serviceaccount:poolside:*",
            "system:serviceaccount:poolside-models:*"
          ]
        }
      }
    }
  ]
}
```

### Ingress Configuration

**AWS Load Balancer Controller:**

```yaml
global:
  ingressClass: "alb"
  
  alb:
    ingressGroup: "poolside"
    scheme: "internet-facing"
    # Include NAT gateway IPs for internal pod access
    inboundCidrs:
      - "203.0.113.0/24"  # Developer IPs
      - "198.51.100.0/24"  # NAT gateway public IP
```

## OpenShift Values

### Required Values

```yaml
# poolside-values.yaml
global:
  domain: "example.com"
  webHost: "poolside.example.com"
  imageRegistry: "registry.example.com:5000"
  
  database:
    name: poolside
    user: poolside
    
  s3:
    bucket: "poolside-models"
    endpoint: "https://s3.example.com"
```

### TLS Configuration Options

**Option A: cert-manager with Issuer**

```yaml
global:
  openshiftCompatibility: true
  ingressTlsSecretName: ""  # Empty uses cert-manager
  
certManager:
  enabled: true
  issuer:
    name: "poolside-issuer"
    kind: "ClusterIssuer"
```

**Option B: Existing TLS Secret**

```yaml
global:
  ingressTlsSecretName: "poolside-tls"
  
certManager:
  enabled: false
```

**Option C: Inject TLS during install**

```bash
helm install poolside ./charts/poolside-deployment \
  -n poolside \
  -f poolside-values.yaml \
  --set-file tls.crt=./tls.crt \
  --set-file tls.key=./tls.key
```

### Image Pull Secrets

```bash
# Create pull secret for external registry
kubectl create secret docker-registry poolside-registry-secret \
  --docker-server="registry.example.com:5000" \
  --docker-username="your-username" \
  --docker-password="your-password" \
  --docker-email="admin@example.com" \
  -n poolside

# Reference in values
global:
  imagePullSecrets:
    - poolside-registry-secret
```

### Internal Registry Access

```bash
# Grant cross-namespace pull access (OpenShift internal registry)
oc policy add-role-to-user system:image-puller \
  system:serviceaccount:poolside:default \
  -n openshift-image-registry

oc policy add-role-to-user system:image-puller \
  system:serviceaccount:poolside-models:default \
  -n openshift-image-registry
```

### SCC (Security Context Constraints)

Poolside requires privileged containers for certain workloads:

```bash
# Add privileged SCC
oc adm policy add-scc-to-user privileged -z default -n poolside
oc adm policy add-scc-to-user privileged -z default -n poolside-models

# For GPU workloads, may also need:
oc adm policy add-scc-to-user privileged -z default -n gpu-operator
```

## Model Inference Values

### AWS EKS

```yaml
# poolside_values.yaml (for inference chart)
models:
  laguna-70b:
    s3Uri: "s3://poolside-models/laguna-70b/"
    replicas: 1
    gpuType: "nvidia-a100"
    
  point-code:
    s3Uri: "s3://poolside-models/point-code/"
    replicas: 1
    gpuType: "nvidia-a10g"
```

### OpenShift

```yaml
# poolside-values.yaml (for inference chart)
models:
  laguna-70b:
    s3Uri: "s3://poolside-models/laguna-70b/"
    replicas: 1
    gpuType: "nvidia-a100"
    imagePullSecrets:
      - poolside-registry-secret
```

## Environment Variables

### AWS EKS Deployment

```bash
# Required for image upload
export AWS_REGION="us-west-2"
export ECR_REGISTRY="<account-id>.dkr.ecr.<region>.amazonaws.com"

# Required for S3 access during model upload
export S3_BUCKET="poolside-models-bucket"
```

### OpenShift Deployment

```bash
# Required for image upload
export REGISTRY_URL="registry.example.com:5000"
export REGISTRY_USER="admin"
export REGISTRY_PASSWORD="password"

# Required for S3 access
export S3_ENDPOINT_URL="https://s3.example.com"
export S3_BUCKET="poolside-models"
```