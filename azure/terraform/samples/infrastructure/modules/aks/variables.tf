variable "auto_scaling_default_node" {
  description = "(Optional) Kubernetes Auto Scaler must be enabled for this main pool"
  type        = bool
}
variable "availability_zones" {
  description = "(Optional) A list of Availability Zones across which the Node Pool should be spread. Changing this forces a new resource to be created."
  type        = list(string)
}
variable "resource_group_name" {
  description = "The name for the Resource Group to provision"
  type        = string
}
variable "resource_group_location" {
  description = "The Azure region to deploy to"
  type        = string
}
variable "vnet_id" {
  description = "Identifier for the vnet"
  type        = string
}
variable "vnet_subnet_id" {
  description = "Identifier for the subnet to deploy nodes into"
  type        = string
}
variable "pod_subnet_id" {
  description = "Identifier for the pods to deploy nodes into"
  type        = string
}
variable "appgw_subnet_id" {
  description = "Identifier for the application gateway to deploy node"
  type        = string
}
variable "k8s_version" {
  description = "The version of Kubernetes to use."
  type        = string
}
variable "node_vm_size" {
  description = "The size of the Kubernetes nodes."
  type        = string
}
variable "node_count" {
  description = "The default requested number of nodes"
  type        = string
}
variable "node_min_count" {
  description = "Min number of nodes to scale"
  type        = string
}
variable "node_max_count" {
  description = "Max number of nodes to scale"
  type        = string
}

# variable "service_cidr" {
#   description = "(Optional) The Network Range used by the Kubernetes service.Changing this forces a new resource to be created."
#   type        = string
# }

# variable "pod_cidr" {
#   description = "(Optional) The CIDR to use for pod IP addresses. Changing this forces a new resource to be created."
#   type        = string
# }
