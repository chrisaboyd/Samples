variable "rg_name" {
    description = "Default resource group name that the network will be created in."
    type        = string
    default     = "auseast-rg"
}

variable "location" {
    description = "The location/region where the core network will be created."
    default     = "australiaeast"
}