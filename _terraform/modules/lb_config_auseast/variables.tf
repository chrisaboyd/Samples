variable "rg_name" {
    description = "Default resource group name that the network will be created in."
    type        = string
    default     = "auseast-rg"
}

variable "location" {
    description = "The location/region where the core network will be created."
    default     = "australiaeast"
}

variable "vNet_block" {
    description = "CIDR block for vNet"
    type        = list(string)
    default     = ["10.1.0.0/16"]
}

variable "instance_count" {
    default = "2"
}

