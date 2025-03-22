variable "cluster_name" {
  description = "EKS Cluster Name - Passed by EKS Module"
  type        = string
}
variable "cluster_autoscaler_iam_role_arn" {
  description = "IAM Role ARN for Cluster Autoscaler Controller - Passed by EKS Module"
  type        = string
}
variable "external_secrets_iam_role_arn" {
  description = "IAM Role ARN for External Secrets Controller - Passed by EKS Module"
  type        = string
}
variable "amazon_fluent_bit_cloudwatch_role_arn" {
  description = "IAM Role ARN for Fluent Bit for CloudWatch Logging - Passed by EKS Module"
  type        = string
}
variable "load_balancer_controller_iam_role_arn" {
  description = "IAM Role ARN for Load Balancer Controller - Passed by EKS Module"
  type        = string
}
variable "account_id" {
  description = "Project ID"
  type        = string
}
variable "region" {
  default     = "us-east-1"
  description = "Region to deploy resources to"
  type        = string
}
