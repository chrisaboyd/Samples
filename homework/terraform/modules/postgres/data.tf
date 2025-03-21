provider "aws" {
  region = local.region
}
data "aws_caller_identity" "current" {}
data "aws_vpc" "selected" {
  id = var.vpc_id
}
locals {
  region = var.region
  name   = var.db_instance_name
  tags = {
    Name = var.db_instance_name
  }
}
