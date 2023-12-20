resource "azurerm_resource_group" "t_rg" {
  name     = var.resource_group_name
  location = var.resource_group_location

  tags = {
    Environment = "Dev-Prefect-SelfHosted"
  }
}

resource "azurerm_virtual_network" "prefectvnet" {
  name                = var.vnet_name
  address_space       = var.vnet_address_space
  location            = azurerm_resource_group.t_rg.location
  resource_group_name = azurerm_resource_group.t_rg.name
  dns_servers         = length(var.vnet_dns_servers) > 0 ? var.vnet_dns_servers : null
}

resource "azurerm_subnet" "prefect_node_subnet" {
  name                 = "prefect-node-subnet"
  resource_group_name  = azurerm_resource_group.t_rg.name
  virtual_network_name = azurerm_virtual_network.prefectvnet.name
  address_prefixes     = ["${var.subnet_prefix}.1.0/24"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_subnet" "prefect_pod_subnet" {
  name                 = "prefect-pod-subnet"
  resource_group_name  = azurerm_resource_group.t_rg.name
  virtual_network_name = azurerm_virtual_network.prefectvnet.name
  address_prefixes     = ["${var.subnet_prefix}.244.0/22"]
  service_endpoints    = ["Microsoft.Storage"]
  delegation {
  name = "delegation"

  service_delegation {
    name    = "Microsoft.ContainerService/managedClusters"
    actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "appgw_subnet" {
  name                 = "prefect-appgw-subnet"
  resource_group_name  = azurerm_resource_group.t_rg.name
  virtual_network_name = azurerm_virtual_network.prefectvnet.name
  address_prefixes     = ["${var.subnet_prefix}.250.0/24"]
}

resource "azurerm_subnet" "redis_subnet" {
  name                 = "prefect-redis-subnet"
  resource_group_name  = azurerm_resource_group.t_rg.name
  virtual_network_name = azurerm_virtual_network.prefectvnet.name
  address_prefixes     = ["${var.subnet_prefix}.251.0/24"]
}

resource "azurerm_subnet" "postgres_subnet" {
  name                 = "prefect-postgres-subnet"
  resource_group_name  = azurerm_resource_group.t_rg.name
  virtual_network_name = azurerm_virtual_network.prefectvnet.name
  address_prefixes     = ["${var.subnet_prefix}.252.0/24"]
  service_endpoints    = ["Microsoft.Storage"]

  delegation {
    name = "fs"

    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"

      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}
# resource "azurerm_network_security_group" "default" {
#   name                = "${random_pet.name_prefix.id}-nsg"
#   location            = azurerm_resource_group.default.location
#   resource_group_name = azurerm_resource_group.default.name

#   security_rule {
#     name                       = "test123"
#     priority                   = 100
#     direction                  = "Inbound"
#     access                     = "Allow"
#     protocol                   = "Tcp"
#     source_port_range          = "*"
#     destination_port_range     = "*"
#     source_address_prefix      = "*"
#     destination_address_prefix = "*"
#   }
# }

# resource "azurerm_subnet_network_security_group_association" "default" {
#   subnet_id                 = azurerm_subnet.default.id
#   network_security_group_id = azurerm_network_security_group.default.id
# }

# resource "azurerm_private_dns_zone" "default" {
#   name                = "${random_pet.name_prefix.id}-pdz.postgres.database.azure.com"
#   resource_group_name = azurerm_resource_group.default.name

#   depends_on = [azurerm_subnet_network_security_group_association.default]
# }

# resource "azurerm_private_dns_zone_virtual_network_link" "default" {
#   name                  = "${random_pet.name_prefix.id}-pdzvnetlink.com"
#   private_dns_zone_name = azurerm_private_dns_zone.default.name
#   virtual_network_id    = azurerm_virtual_network.default.id
#   resource_group_name   = azurerm_resource_group.default.name
# }
