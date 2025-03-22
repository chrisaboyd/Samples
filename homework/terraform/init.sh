#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

# Configuration
export REGION="us-east-1"
export ACCOUNT_ID="250037329208"
export ENVIRONMENT="dev"

# Repository names
API_REPO_NAME="api-ecr-${ENVIRONMENT}"
RAG_REPO_NAME="rag-ecr-${ENVIRONMENT}"

# ECR repository URLs
export API_ECR_URL="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${API_REPO_NAME}"
export RAG_ECR_URL="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${RAG_REPO_NAME}"

# Store the original directory and project root
TERRAFORM_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${TERRAFORM_DIR}/.." && pwd)"

# Initialize and apply Terraform
echo "=== Initializing Terraform ==="
cd "${TERRAFORM_DIR}/main"
terraform init

echo "=== Planning Terraform changes ==="
terraform plan -out plan.tfplan

echo "=== Applying Terraform changes ==="
terraform apply plan.tfplan

# Login to ECR
echo "=== Logging in to ECR ==="
aws ecr get-login-password --region ${REGION} | \
  docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

# Function to build and push
build_and_push() {
  local service_name=$1
  local image_url=$2
  local service_dir=$3
  
  echo "=== Building and pushing ${service_name} image ==="
  cd "${service_dir}"
  
  echo "Building image..."
  docker buildx build --platform linux/amd64 -t ${image_url}:latest .
  
  echo "Pushing image to ECR..."
  docker push ${image_url}:latest
}

# Build and push images
build_and_push "API" "${API_ECR_URL}" "${PROJECT_ROOT}/api_service"
build_and_push "RAG" "${RAG_ECR_URL}" "${PROJECT_ROOT}/rag_service"


# Retrieve KUBECONFIG
aws eks update-kubeconfig --profile default --kubeconfig ~/.kube/contexts/eks-dev --name eks-dev

# Export KUBECONFIG
export KUBECONFIG=~/.kube/contexts/eks-dev
# Apply Kustomize
cd "${PROJECT_ROOT}/k8s"
kubectl apply -k .

echo "=== All operations completed successfully ==="