# Create Azure AD Group in Active Directory for AKS Admins
resource "azuread_group" "aks_administrators" {
  #name        = "${azurerm_resource_group.aks_rg.name}-cluster-administrators"
  display_name     = "${var.resource_group_name}-cluster-administrators"
  security_enabled = true
  description      = "Azure AKS Kubernetes administrators for the ${var.resource_group_name}-cluster."
}

resource "azurerm_kubernetes_cluster" "aks" {

  name                = "prefect-aks-selfhosted"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
  dns_prefix          = "${var.resource_group_name}-cluster"
  kubernetes_version  = var.k8s_version

  default_node_pool {
    name                        = "defaultpool"
    vm_size                     = var.node_vm_size
    pod_subnet_id               = var.pod_subnet_id
    vnet_subnet_id              = var.vnet_subnet_id
    enable_auto_scaling         = var.auto_scaling_default_node ? true : false
    zones                       = var.availability_zones
    node_count                  = 3
    min_count                   = 1
    max_count                   = 20
    temporary_name_for_rotation = "defaulttemp"
    scale_down_mode     = "Deallocate"

    upgrade_settings {
      max_surge       = "10%"
    }
  }



  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
  }

  local_account_disabled    = true
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  identity {
    type = "SystemAssigned"
  }

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    admin_group_object_ids = [azuread_group.aks_administrators.id]
  }

  ingress_application_gateway {
    subnet_id = var.appgw_subnet_id
  }



  lifecycle {
    ignore_changes = [
      default_node_pool[0].node_count
    ]
  }
}

# Grant network contributor to the appgateway created identity to join the vnet
resource "azurerm_role_assignment" "aks_agic_integration" {
  scope = var.vnet_id
  role_definition_name = "Network Contributor"
  principal_id = azurerm_kubernetes_cluster.aks.ingress_application_gateway[0].ingress_application_gateway_identity[0].object_id
}

# grant permission to admin group to manage aks
resource "azurerm_role_assignment" "aks_user_roles" {
  scope                = azurerm_kubernetes_cluster.aks.id
  role_definition_name = "Azure Kubernetes Service Cluster User Role"
  principal_id         = azuread_group.aks_administrators.id
}
# grant permission to aks to pull images from acr
# resource "azurerm_role_assignment" "acrpull_role" {
#   scope                = var.acr_id
#   role_definition_name = "AcrPull"
#   principal_id         = azurerm_kubernetes_cluster.aks.kubelet_identity.0.object_id
# }