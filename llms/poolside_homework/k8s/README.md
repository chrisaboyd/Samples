# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the API and RAG services.

## Components

1. **Secrets** (`secrets.yaml`): Contains sensitive information such as database connection string and API password
2. **API Service** (`api-deployment.yaml`): Deployment and Service for the API component
3. **RAG Service** (`rag-deployment.yaml`): Deployment and Service for the RAG component
4. **Horizontal Pod Autoscalers** (`hpa.yaml`): Auto-scaling configurations for both services
5. **Ingress** (`ingress.yaml`): Exposes the API service externally

## Prerequisites

- Kubernetes cluster with the metrics server installed (required for HPA)
- NGINX Ingress Controller (for the Ingress resource)
- Images pushed to ECR as specified in the deployment files

## Deployment Instructions

### 1. Update the Secret values

Update the base64-encoded values in `secrets.yaml`:

```bash
# Encode your actual DATABASE_URL
echo -n "postgresql://user:password@postgres:5432/dbname" | base64

# Encode your API_PASSWORD
echo -n "your_secure_password" | base64
```

Replace the placeholder values in `secrets.yaml` with your actual encoded values.

### 2. Apply the manifests

Option 1: Using kubectl directly:
```bash
kubectl apply -f secrets.yaml
kubectl apply -f api-deployment.yaml
kubectl apply -f rag-deployment.yaml
kubectl apply -f hpa.yaml
kubectl apply -f ingress.yaml
```

Option 2: Using kustomize:
```bash
❯ kubectl apply -k .
secret/app-credentials created
service/api-service created
service/rag-service created
deployment.apps/api-service created
deployment.apps/rag-service created
horizontalpodautoscaler.autoscaling/api-service-hpa created
horizontalpodautoscaler.autoscaling/rag-service-hpa created
ingress.networking.k8s.io/api-ingress created
```

### 3. Verify deployment

```bash
# Check if pods are running
kubectl get pods

# Check if services are created
kubectl get svc

# Check if HPAs are configured
kubectl get hpa

# Check if the ingress is configured
kubectl get ingress
```

## Scaling

Both services will automatically scale based on:
- CPU utilization (70%)
- Memory utilization (80%)

Min replicas: 2
Max replicas: 10

## Accessing the Service

Once deployed, the API service will be accessible through the Ingress at:
- `/api/*` - API endpoints
- `/docs` - API documentation
