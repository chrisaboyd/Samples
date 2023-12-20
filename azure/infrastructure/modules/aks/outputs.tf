output "oidc_issuer_url" {
  value = azurerm_kubernetes_cluster.aks.oidc_issuer_url
}

output "cluster_name" {
  value = azurerm_kubernetes_cluster.aks.name
}

output "cluster_fqdn" {
  value = azurerm_kubernetes_cluster.aks.fqdn
}