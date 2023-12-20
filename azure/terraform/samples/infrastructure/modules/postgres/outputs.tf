output "azurerm_postgresql_flexible_server" {
  value = azurerm_postgresql_flexible_server.postgres.name
}

output "postgresql_flexible_server_database_name" {
  value = azurerm_postgresql_flexible_server_database.postgres.name
}

output "postgresql_flexible_server_admin_password" {
  sensitive = true
  value     = azurerm_postgresql_flexible_server.postgres.administrator_password
}