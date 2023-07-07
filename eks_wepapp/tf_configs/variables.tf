
variable "cluster_name" {
  type        = string
  description = "a name for the cluster"
  default     = "webapp-eks-dev"
}

variable "environment" {
  type        = string
  description = "environment of eks deployment"
  default     = "dev"
}

variable "k8s_cluster_version" {
  type        = string
  description = "version number to use for the cluster"
  default     = "1.24"
}

variable "map_users" {
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
  description = "additional IAM users to add to the aws-auth configmap"
  default     = []
}
variable "map_roles" {
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  description = "additional IAM Roles to add to the aws-auth configmap"
  default     = []
}

variable "vpc_id" {
  type        = string
  description = "ID for the VPC in which the cluster will be created"
  default     = "vpc-0bc68eb807120af3f"
}
variable "private_subnet_ids" {
  type        = list(string)
  description = "private subnets in which cluster nodes will be created"
  default     = ["subnet1", "subnet2"]
}

variable "aws_profile" {
  description = "Profile to use to authenticate to  AWS"
  type        = string
  default     = ""
}

variable "aws_region" {
  description = "Default region to use in AWS"
  type        = string
  default     = ""
}

variable "project_code" {
  description = "Project code to use as prefix for resources"
  type        = string
  default     = "webapp"
}

variable "region_code" {
  description = "Region short code to use as prefix for resources"
  type        = string
  default     = "use1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
  default     = ""
}

