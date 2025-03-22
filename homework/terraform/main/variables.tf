variable "capacity_type" {
  default     = "ON_DEMAND"
  type        = string
  description = "Capacity type for EKS Nodes"
}
variable "cloudwatch_logs_enabled" {
  default     = true
  description = "Enable CloudWatch Logs for Fluent Bit"
  type        = bool
}
variable "create_network" {
  default     = true
  description = "Create network resources for resources if user does not already have a network set up"
  type        = bool
}
variable "db_instance_name" {
  description = "Name of the RDS instance"
  type        = string
  default     = "ps_rds"
}
variable "db_subnet_group_name" {
  description = "Name of the AWS RDS subnet group"
  type        = string
  default     = "ps_rds_subnet_group"
}
variable "node_size" {
  default     = "a1.medium"
  description = "Node size for EKS Nodes"
  type        = string
}
variable "account_id" {
  default     = null
  description = "AWS Account ID"
  type        = string
}
variable "region" {
  default     = "us-east-1"
  description = "Region to deploy resources to"
  type        = string
}
variable "subnet_ids" {
  default     = null
  description = "Subnet IDs to deploy resources to when network is brought by user (Typically private subnets)"
  type        = list(string)
}
variable "subnet_prefix" {
  default     = "10.0"
  description = "Prefix for subnet generation for network module"
  type        = string
}
variable "vpc_cidr" {
  default     = "10.0.0.0/16"
  description = "CIDR block to create for the VPC"
  type        = string
}
variable "vpc_id" {
  default     = null
  description = "VPC ID to deploy resources to when network is brought by user"
  type        = string
}
variable "vpc_name" {
  default     = null
  description = "VPC name to deploy resources to when network is brought by user"
  type        = string
}
variable "environment" {
  description = "Environment name (e.g. dev, staging, prod)"
  type        = string
  default     = "dev"
}
