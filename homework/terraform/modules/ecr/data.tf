provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}

locals {
  region = "us-east-1"
  name   = "ecr-ps-dev"

  account_id = data.aws_caller_identity.current.account_id

  tags = {
    Name       = local.name
    Example    = local.name
    Repository = "https://github.com/terraform-aws-modules/terraform-aws-ecr"
  }
}
