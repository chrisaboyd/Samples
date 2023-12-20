variable "resource_group_name" {
  description = "The name for the Resource Group to provision"
  type        = string
}
variable "resource_group_location" {
  description = "The Azure region to deploy to"
  type        = string
}
variable "vnet_id" {
  type        = string
  description = "ID for the virtual network to create Private DNS Zone in"
}
variable "postgresql_subnet_id" {
  type        = string
  description = "Subnet ID for PostgreSQL Server"
}
variable "postgresql_admin_login" {
  type        = string
  description = "Login to authenticate to PostgreSQL Server"
  default     = "postgres"
}
variable "postgresql_admin_password" {
  type        = string
  description = "Password to authenticate to PostgreSQL Server"
  default     = "P@ssw0rd1234"
}
variable "postgresql_version" {
  type        = string
  description = "PostgreSQL Server version to deploy"
  default     = "14"
}
variable "postgresql_sku_name" {
  type        = string
  description = "PostgreSQL SKU Name"
  default     = "MO_Standard_E2ds_v5"
}
variable "postgresql_storage" {
  type        = string
  description = "PostgreSQL Storage in MB"
  default     = "32768"
}
variable "zone" {
  type        = string
  description = "Availability Zone for the PostgreSQL Server"
  default     = "1"
}
variable "geo_redundant_backup_enabled" {
  type        = bool
  description = "Enable Geo Redundant Backup"
  default     = false
}
variable "backup_retention_days" {
  type        = number
  description = "Backup Retention Days"
  default     = 7
}