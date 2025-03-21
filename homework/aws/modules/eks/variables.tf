variable "amp_alias" {
  default     = null
  description = "The alias of the prometheus workspace. See more in the [AWS Docs](https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-onboard-create-workspace.html)"
  type        = string
}
variable "capacity_type" {
  default     = "ON_DEMAND"
  type        = string
  description = "Capacity type for EKS Nodes"
}
variable "enable_amp" {
  default     = false
  description = "Enable Amazon Managed Prometheus"
  type        = bool
}
variable "node_size" {
  default     = "c6a.2xlarge"
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
