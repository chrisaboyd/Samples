provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}

locals {
  region = "us-east-1"
  api_service_name   = "ecr-api-service-dev"
  rag_service_name   = "ecr-rag-service-dev"

  account_id = data.aws_caller_identity.current.account_id

  tags = {
    Name       = "ecr-ps-dev"
    Repository = "https://github.com/terraform-aws-modules/terraform-aws-ecr"
  }
}
