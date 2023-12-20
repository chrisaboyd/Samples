output "redis_cache_instance_id" {
  description = "The Route ID of Redis Cache Instance"
  value       = azurerm_redis_cache.redis.id
}

output "redis_cache_hostname" {
  description = "The Hostname of the Redis Instance"
  value       = azurerm_redis_cache.redis.hostname
}

output "redis_cache_ssl_port" {
  description = "The SSL Port of the Redis Instance"
  value       = azurerm_redis_cache.redis.ssl_port
}

output "redis_cache_port" {
  description = "The non-SSL Port of the Redis Instance"
  value       = azurerm_redis_cache.redis.port
  sensitive   = true
}

output "redis_cache_primary_access_key" {
  description = "The Primary Access Key for the Redis Instance"
  value       = azurerm_redis_cache.redis.primary_access_key
  sensitive   = true
}

output "redis_cache_secondary_access_key" {
  description = "The Secondary Access Key for the Redis Instance"
  value       = azurerm_redis_cache.redis.secondary_access_key
  sensitive   = true
}

output "redis_cache_primary_connection_string" {
  description = "The primary connection string of the Redis Instance."
  value       = azurerm_redis_cache.redis.primary_connection_string
  sensitive   = true
}

output "redis_cache_secondary_connection_string" {
  description = "The secondary connection string of the Redis Instance."
  value       = azurerm_redis_cache.redis.secondary_connection_string
  sensitive   = true
}
