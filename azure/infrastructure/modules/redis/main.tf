resource "azurerm_redis_cache" "redis" {
  name                = var.redis_name
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name
  capacity            = var.redis_capacity
  family              = var.redis_sku_family
  sku_name            = var.redis_sku_name
  enable_non_ssl_port = var.enable_non_ssl_port
  minimum_tls_version = var.minimum_tls_version
  redis_version       = var.redis_version
  shard_count         = var.shard_count
  public_network_access_enabled = var.public_network_access_enabled
  subnet_id           = var.subnet_id

  identity {
    type = "SystemAssigned"
  }


  redis_configuration {
    maxmemory_reserved = 2
    maxmemory_delta    = 2
    maxmemory_policy   = "allkeys-lru"
  }

  lifecycle {
    ignore_changes = [
      redis_configuration[0].maxmemory_reserved, redis_configuration[0].maxmemory_delta
    ]
  }
}