output "repository_name" {
  description = "Name of the repository"
  value       = module.ecr_api_service.repository_name
}
output "repository_arn" {
  description = "Full ARN of the repository"
  value       = module.ecr_api_service.repository_arn
}
output "repository_registry_id" {
  description = "The registry ID where the repository was created"
  value       = module.ecr_api_service.repository_registry_id
}
output "repository_url" {
  description = "The URL of the repository (in the form `aws_account_id.dkr.ecr.region.amazonaws.com/repositoryName`)"
  value       = module.ecr_api_service.repository_url
}
output "repository_name_rag" {
  description = "Name of the repository"
  value       = module.ecr_rag_service.repository_name
}
output "repository_arn_rag" {
  description = "Full ARN of the repository"
  value       = module.ecr_rag_service.repository_arn
}
output "repository_registry_id_rag" {
  description = "The registry ID where the repository was created"
  value       = module.ecr_rag_service.repository_registry_id
}
output "repository_url_rag" {
  description = "The URL of the repository (in the form `aws_account_id.dkr.ecr.region.amazonaws.com/repositoryName`)"
  value       = module.ecr_rag_service.repository_url
}


