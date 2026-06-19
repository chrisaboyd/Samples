variable "vpc_name" {
  type        = string
  default     = "ps_vpc"
  description = "common name to apply to the VPC and all subsequent resources"
}
variable "environment" {
  type        = string
  default     = "dev"
  description = "SDLC stage"
}
variable "azs" {
  type        = list(string)
  description = "AWS availabiility zones to deploy VPC subnets into"
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}
variable "vpc_cidr" {
  type        = string
  description = "CIDR range to assign to VPC"
  default     = "10.0.0.0/16"
}
variable "private_subnet_cidrs" {
  type        = list(string)
  description = "CIDR range to assign to private subnets"
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}
variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR range to assign to public subnets"
  default     = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
}
