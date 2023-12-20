output "resource_group_name" {
  value = azurerm_resource_group.t_rg.name
}

output "resource_group_location" {
  value = azurerm_resource_group.t_rg.location
}

output "vnet_id" {
  value = azurerm_virtual_network.prefectvnet.id
}

output "vnet_subnet_id" {
  value = azurerm_subnet.prefect_node_subnet.id
}

output "pod_subnet_id" {
  value = azurerm_subnet.prefect_pod_subnet.id
}

output "appgw_subnet_id" {
  value = azurerm_subnet.appgw_subnet.id
}

output "redis_subnet_id" {
  value = azurerm_subnet.redis_subnet.id
}

output "postgres_subnet_id" {
  value = azurerm_subnet.postgres_subnet.id
}

output "service_cidr" {
  value = azurerm_subnet.prefect_node_subnet.address_prefixes
}