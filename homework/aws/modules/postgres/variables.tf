variable "aurora_instance_size" {
  description = "Aurora instance size"
  type        = string
  default     = "db.t4g.micro"
}
variable "db_instance_name" {
  description = "Name of the RDS instance"
  type        = string
}
variable "db_subnet_group_name" {
  description = "Name of the AWS RDS subnet group"
  type        = string
}
variable "master_username" {
  description = "Master username for the RDS instance"
  type        = string
  default     = "postgres"
}
variable "rds_aurora" {
  description = "Use Aurora for RDS"
  type        = bool
  default     = false
}
variable "rds_monitoring_role_name" {
  description = "Name for the RDS monitoring role"
  type        = string
  default     = "rds-monitoring-role"
}
variable "rds_monitoring_role_description" {
  description = "Description for the RDS monitoring role"
  type        = string
  default     = ""
}
variable "region" {
  default     = "us-east-1"
  type        = string
  description = "Region to deploy resources to"
}
variable "subnet_ids" {
  description = "A list of VPC subnet IDs"
  type        = list(string)
}
variable "vpc_cidr_block" {
  description = "AWS VPC CIDR block"
  type        = string
  default     = ""
}
variable "vpc_id" {
  description = "AWS VPC ID"
  type        = string
}
