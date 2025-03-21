output "ecr_arn" {
  value = module.ecr_api_service.repository_arn
}
output "ecr_url" {
  value = module.ecr_api_service.repository_url
}
output "ecr_name" {
  value = module.ecr_api_service.repository_name
}
output "ecr_registry_id" {
  value = module.ecr_api_service.repository_registry_id
}
output "ecr_rag_service_name" {
  value = module.ecr_rag_service.repository_name
}
output "ecr_rag_service_arn" {
  value = module.ecr_rag_service.repository_arn
}
output "ecr_rag_service_registry_id" {
  value = module.ecr_rag_service.repository_registry_id
}
output "ecr_rag_service_url" {
  value = module.ecr_rag_service.repository_url
}
# output "redis_primary_cache_endpoint" {
#   value = module.redis.redis_primary_cache_endpoint
# }
# output "redis_reader_cache_endpoint" {
#   value = module.redis.redis_reader_cache_endpoint
# }
# output "redis_primary_streams_endpoint" {
#   value = module.redis.redis_primary_streams_endpoint
# }
# output "redis_reader_streams_endpoint" {
#   value = module.redis.redis_reader_streams_endpoint
# }
# output "redis_primary_work_endpoint" {
#   value = module.redis.redis_primary_work_endpoint
# }
# output "redis_reader_work_endpoint" {
#   value = module.redis.redis_reader_work_endpoint
# }
# output "vpn_config" {
#   description = "Client VPN endpoint configuration"
#   value       = module.network[0].vpn_config
#   sensitive   = true
# }
# output "db_port" {
#   value = module.postgres.db_port
# }
# output "db_instance_address" {
#   value = module.postgres.db_instance_address
# }
# output "db_instance_identifier" {
#   value = module.postgres.db_instance_identifier
# }
# output "db_instance_master_user_secret_arn" {
#   value = module.postgres.db_instance_master_user_secret_arn
# }
# output "db_instance_arn" {
#   value = module.postgres.db_instance_arn
# }
# output "db_secret_rotation_enabled" {
#   value = module.postgres.db_secret_rotation_enabled
# }
# output "eks_access_entries" {
#   value = module.eks.access_entries
# }
# output "eks_cluster_name" {
#   value = module.eks.cluster_name
# }
# output "eks_kubeconfig_string" {
#   value = module.eks.kubeconfig_string
# }
# output "eks_cluster_version" {
#   value = module.eks.cluster_version
# }
