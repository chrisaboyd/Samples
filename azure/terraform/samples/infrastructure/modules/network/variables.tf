variable "resource_group_name" {
  description = "The name for the Resource Group to provision"
  type        = string
}
variable "resource_group_location" {
  description = "The Azure region to deploy to"
  type        = string
}
variable "vnet_name" {
  description = "Name to deploy resources to when network is brought by user"
  type        = string
  default     = "prefect-selfhosted-vnet"
}
variable "vnet_address_space" {
  description = "CIDR block for the VNets address space"
  type        = list(string)
}
variable "vnet_dns_servers" {
  description = "(Optional) IP address within the Kubernetes service address range that will be used by cluster service discovery (kube-dns)."
  type        = list(string)
  default     = []
}
variable "subnet_prefix" {
  description = "Prefix for subnet generation for network module"
  type        = string
}
