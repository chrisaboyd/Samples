output "public_ip_address_id" {
    value = azurerm_public_ip.rg.id
}

output "rg_name" {
    value = azurerm_resource_group.rg.name
}