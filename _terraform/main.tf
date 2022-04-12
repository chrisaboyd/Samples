# Configure the Azure provider
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 2.65"
    }
  }

  required_version = ">= 1.1.0"
}

provider "azurerm" {
  features {}
}

module "lb_config_auseast" {
  source = "./modules/lb_config_auseast"

}

module "lb_config_eastasia" {
  source = "./modules/lb_config_eastasia"
  
}

resource "azurerm_traffic_manager_profile" "rg" {
  name                   = "ollietraman"
  resource_group_name    = module.lb_config_auseast.rg_name
  traffic_routing_method = "Geographic"

  dns_config {
    relative_name = "ollie-profile"
    ttl           = 100
  }

  monitor_config {
    protocol                     = "TCP"
    port                         = 80
    #path                         = "/"
    interval_in_seconds          = 30
    timeout_in_seconds           = 9
    tolerated_number_of_failures = 3
    expected_status_code_ranges = ["200-299", "301-301"]
  }
}

resource "azurerm_traffic_manager_azure_endpoint" "auseast-end" {
  name               = "auseast-endpoint"
  profile_id         = azurerm_traffic_manager_profile.rg.id
  weight             = 100
  target_resource_id = module.lb_config_auseast.public_ip_address_id
  geo_mappings       = ["GEO-AP"]
}

resource "azurerm_traffic_manager_azure_endpoint" "eastasia-end" {
  name               = "eastasia-endpoint"
  profile_id         = azurerm_traffic_manager_profile.rg.id
  weight             = 100
  target_resource_id = module.lb_config_eastasia.public_ip_address_id
  geo_mappings       = ["GEO-AS"]
}