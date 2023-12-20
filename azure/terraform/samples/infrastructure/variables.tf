variable "subscription_id" {
  description = "The subscription ID to be used to connect to Azure"
  type        = string
}
variable "client_id" {
  description = "The client ID to be used to connect to Azure"
  type        = string
}
variable "client_secret" {
  description = "The client secret to be used to connect to Azure"
  type        = string
}
variable "tenant_id" {
  description = "The tenant ID to be used to connect to Azure"
  type        = string
}
variable "resource_group_name" {
  description = "The name for the Resource Group to provision"
  type        = string
  default     = "self-hosted-prefect"
}
variable "resource_group_location" {
  description = "The Azure region to deploy to"
  type        = string
  default     = "westus3"
}
variable "vnet_name" {
  description = "Name to deploy resources to when network is brought by user"
  type        = string
  default     = "prefect-selfhosted-vnet"
}
variable "vnet_address_space" {
  description = "CIDR block for the VNets address space"
  type        = list(string)
  default     = ["10.242.0.0/16"]
}
variable "subnet_prefix" {
  default     = "10.242"
  description = "Prefix for subnet generation for network module"
  type        = string
}
variable "vnet_dns_servers" {
  description = "(Optional) IP address within the Kubernetes service address range that will be used by cluster service discovery (kube-dns)."
  type        = list(string)
  default     = []
}
variable "auto_scaling_default_node" {
  description = "(Optional) Kubernetes Auto Scaler must be enabled for this main pool"
  type        = bool
  default     = true
}
variable "availability_zones" {
  description = "(Optional) Availability Zones to use for the AKS Cluster"
  type        = list(string)
  default     = ["1", "2", "3"]
}
variable "k8s_version" {
  description = "The version of Kubernetes to use."
  type        = string
  default     = "1.28"
}
variable "node_vm_size" {
  description = "The size of the Kubernetes nodes."
  type        = string
  # default     = "Standard_A8_v2"
  default = "Standard_B2s"
}