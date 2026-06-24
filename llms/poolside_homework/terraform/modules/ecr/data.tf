data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  tags = {
    Name       = "ecr-ps-dev"
    Repository = "https://github.com/terraform-aws-modules/terraform-aws-ecr"
  }
}
