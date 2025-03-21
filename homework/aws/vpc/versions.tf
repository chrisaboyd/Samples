terraform {
  required_version = "~> 1"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.89.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.17.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.36.0"
    }
  }
}
provider "aws" {
  region = var.region
}
provider "kubernetes" {
  host                   = module.eks.cluster.endpoint
  cluster_ca_certificate = module.eks.cluster.ca_certificate
  token                  = data.aws_eks_cluster_auth.cluster.token
}
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster.endpoint
    cluster_ca_certificate = module.eks.cluster.ca_certificate
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}
provider "kubectl" {
  host                   = module.eks.cluster.endpoint
  cluster_ca_certificate = module.eks.cluster.ca_certificate
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
}
