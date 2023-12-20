resource "azurerm_private_dns_zone" "default" {
  name                = "prefect-selfhosted-pdz.postgres.database.azure.com"
  resource_group_name = var.resource_group_name

  #depends_on = [azurerm_subnet_network_security_group_association.default]
}

resource "azurerm_private_dns_zone_virtual_network_link" "default" {
  name                  = "prefect-selfhosted-pdzvnetlink.com"
  private_dns_zone_name = azurerm_private_dns_zone.default.name
  virtual_network_id    = var.vnet_id
  resource_group_name   = var.resource_group_name
}

resource "azurerm_postgresql_flexible_server" "postgres" {
  name                   = "prefect-selfhosted-psqlflexibleserver"
  resource_group_name    = var.resource_group_name
  location               = var.resource_group_location
  version                = var.postgresql_version
  delegated_subnet_id    = var.postgresql_subnet_id
  private_dns_zone_id    = azurerm_private_dns_zone.default.id
  administrator_login    = var.postgresql_admin_login
  administrator_password = var.postgresql_admin_password
  zone                   = var.zone
  storage_mb             = var.postgresql_storage
  sku_name               = var.postgresql_sku_name
  backup_retention_days  = var.backup_retention_days

  # Not supported in all regions - https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/overview
  geo_redundant_backup_enabled = var.geo_redundant_backup_enabled
  depends_on = [azurerm_private_dns_zone_virtual_network_link.default]
}

resource "azurerm_postgresql_flexible_server_database" "postgres" {
  name      = "prefect-selfhosted-db"
  server_id = azurerm_postgresql_flexible_server.postgres.id
  collation = "en_US.utf8"
  charset   = "UTF8"
}