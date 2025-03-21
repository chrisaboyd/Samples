output "repository_name" {
  description = "Name of the repository"
  value       = module.ecr.repository_name
}
output "repository_arn" {
  description = "Full ARN of the repository"
  value       = module.ecr.repository_arn
}
output "repository_registry_id" {
  description = "The registry ID where the repository was created"
  value       = module.ecr.repository_registry_id
}
output "repository_url" {
  description = "The URL of the repository (in the form `aws_account_id.dkr.ecr.region.amazonaws.com/repositoryName`)"
  value       = module.ecr.repository_url
}