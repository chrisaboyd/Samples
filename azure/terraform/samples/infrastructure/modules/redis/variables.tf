variable "resource_group_name" {
  description = "The name for the Resource Group to provision"
  type        = string
}
variable "resource_group_location" {
  description = "The Azure region to deploy to"
  type        = string
}
variable "redis_name" {
  description = "Redis Cache Name"
  type        = string
  default     = "prefect-selfhosted-redis"
}
variable "redis_sku_name" {
  description = "Basic, Premium, Standard redis SKU"
  type        = string
  default     = "Premium"
}
variable "redis_sku_family" {
  description = "C = Basic, P = Premium, S = Standard"
  type        = string
  default     = "P"
}
variable "redis_capacity" {
  description = "The size of the Redis Cache to deploy"
  type        = number
  default     = 1
}
variable "public_network_access_enabled" {
  description = "Whether or not public access is allowed for this Redis Cache"
  type        = bool
  default     = false
}
variable "minimum_tls_version" {
  description = "The minimum TLS version for this Redis Cache"
  type        = string
  default     = "1.2"
}
variable "enable_non_ssl_port" {
  description = "Whether or not to enable the non-ssl port (6379) for this Redis Cache"
  type        = bool
  default     = false
}
variable "shard_count" {
  description = "The number of shards to deploy for this Redis Cache"
  type        = number
  default     = 1
}
variable "redis_version" {
  description = "The version of Redis to deploy"
  type        = string
  default     = "6"
}
variable "subnet_id" {
  description = "The ID of the subnet to deploy the Redis Cache to"
  type        = string
}