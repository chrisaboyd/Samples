variable "capacity_type" {
  default     = "ON_DEMAND"
  type        = string
  description = "Capacity type for EKS Nodes"
}
variable "node_size" {
  default     = "a1.medium"
  description = "Node size for EKS Nodes"
  type        = string
}
variable "region" {
  default     = "us-east-1"
  description = "Region to deploy resources to"
  type        = string
}
variable "subnet_ids" {
  description = "A list of VPC subnet IDs"
  type        = list(string)
}
variable "vpc_id" {
  description = "AWS VPC ID"
  type        = string
}
variable "vpc_name" {
  description = "AWS VPC Name"
  type        = string
}
