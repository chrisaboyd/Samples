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
    time = {
      source  = "hashicorp/time"
      version = "0.12.1"
    }
  }
}
