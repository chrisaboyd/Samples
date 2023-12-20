# Provisions the resource group and the virtual network
module "network" {
  source                  = "./modules/network"
  resource_group_name     = var.resource_group_name
  resource_group_location = var.resource_group_location
  vnet_address_space      = var.vnet_address_space
  vnet_name               = var.vnet_name
  subnet_prefix           = var.subnet_prefix
}

# Provisions the AKS cluster
module "aks" {
  source                  = "./modules/aks"
  resource_group_name     = var.resource_group_name
  resource_group_location = var.resource_group_location

  vnet_id         = module.network.vnet_id
  vnet_subnet_id  = module.network.vnet_subnet_id
  pod_subnet_id   = module.network.pod_subnet_id
  appgw_subnet_id = module.network.appgw_subnet_id

  auto_scaling_default_node = var.auto_scaling_default_node
  node_count                = 3
  node_min_count            = 1
  node_max_count            = 20

  k8s_version        = var.k8s_version
  node_vm_size       = var.node_vm_size
  availability_zones = var.availability_zones
}

# Provisions Azure Cache for Redis
module "redis" {
  source = "./modules/redis"

  resource_group_name     = var.resource_group_name
  resource_group_location = var.resource_group_location
  subnet_id               = module.network.redis_subnet_id
}

# Provisions Azure Database for PostgreSQL
module "postgres" {
  source = "./modules/postgres"

  postgresql_subnet_id    = module.network.postgres_subnet_id
  vnet_id                 = module.network.vnet_id
  resource_group_name     = var.resource_group_name
  resource_group_location = var.resource_group_location

}

