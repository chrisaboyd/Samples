output "db_instance_arn" {
  value       = var.rds_aurora ? module.cluster[0].cluster_arn : module.db[0].db_instance_arn
  description = "The ARN of the database instance"
}
output "db_endpoint" {
  value       = var.rds_aurora ? module.cluster[0].cluster_endpoint : module.db[0].db_instance_endpoint
  description = "The database endpoint based on the deployed type (RDS or Aurora)"
}
output "db_instance_address" {
  value       = var.rds_aurora ? module.cluster[0].cluster_endpoint : module.db[0].db_instance_address
  description = "The hostname of the database instance"
}
output "db_port" {
  value       = var.rds_aurora ? module.cluster[0].cluster_port : module.db[0].db_instance_port
  description = "The database port based on the deployed type (RDS or Aurora)"
}
output "db_instance_identifier" {
  value       = var.rds_aurora ? module.cluster[0].cluster_id : module.db[0].db_instance_identifier
  description = "The database identifier for the deployed database type"
}
output "db_instance_master_user_secret_arn" {
  value       = var.rds_aurora ? module.cluster[0].cluster_master_user_secret_arn : module.db[0].db_instance_master_user_secret_arn
  description = "The ARN of the master user secret"
}
output "db_secret_rotation_enabled" {
  value       = var.rds_aurora ? module.cluster[0].db_cluster_secretsmanager_secret_rotation_enabled : module.db[0].db_instance_secretsmanager_secret_rotation_enabled
  description = "The status of secret rotation for the database"
}
