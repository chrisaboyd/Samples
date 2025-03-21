output "amazon_managed_service_prometheus_iam_role_arn" {
  value       = module.amazon_managed_service_prometheus_irsa_role.iam_role_arn
  description = "IAM Role ARN for Amazon Managed Service for Prometheus"
}
output "cluster" {
  sensitive = true
  value = {
    ca_certificate    = base64decode(module.eks.cluster_certificate_authority_data)
    endpoint          = module.eks.cluster_endpoint
    name              = module.eks.cluster_name
    oidc_provider_arn = module.eks.oidc_provider_arn
  }
}
output "cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS Cluster Name"
}
output "amazon_fluent_bit_cloudwatch_role_arn" {
  value       = module.amazon_fluent_bit_cloudwatch_irsa_role.iam_role_arn
  description = "IAM Role ARN for Amazon Fluent Bit CloudWatch"
}
output "cluster_autoscaler_iam_role_arn" {
  value       = module.cluster_autoscaler_irsa_role.iam_role_arn
  description = "IAM Role ARN for Cluster Autoscaler Controller"
}
output "cluster_id" {
  value       = module.eks.cluster_id
  description = "EKS Cluster ID"
}
output "external_secrets_iam_role_arn" {
  value       = module.external_secrets_irsa_role.iam_role_arn
  description = "IAM Role ARN for External Secrets Controller"
}
output "load_balancer_controller_iam_role_arn" {
  value       = module.load_balancer_controller_irsa_role.iam_role_arn
  description = "IAM Role ARN for Load Balancer Controller"
}
output "node_security_group_id" {
  value       = module.eks.node_security_group_id
  description = "Security Group ID for EKS Nodes"
}
output "access_entries" {
  value = module.eks.access_entries
}
output "kubeconfig_string" {
  value = "aws eks update-kubeconfig --profile <profile> --kubeconfig ~/.kube/contexts/platform-dev-self-managed --name ${module.eks.cluster_name}"
}
output "cluster_version" {
  value = module.eks.cluster_version
}
