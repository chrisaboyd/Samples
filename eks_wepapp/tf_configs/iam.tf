data "aws_iam_policy" "s3" {
  arn = "arn:aws:iam::<redacted>:policy/webapp-eks-s3list"
}

data "aws_iam_policy" "dynamodb" {
  arn = "arn:aws:iam::<redacted>:policy/webapp-eks-dynamodblist"
}


module "iam_eks_role" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  role_name = "webapp-eks-${var.environment}-sa"
  role_policy_arns = [data.aws_iam_policy.dynamodb.arn,data.aws_iam_policy.s3.arn]

  oidc_providers = {
    main = {
      provider_arn               = "module.eks.oidc_provider_arn"
      namespace_service_accounts = ["webapp:webapp-sa"]
        }
    }

  depends_on = [
    module.eks.oidc_provider_arn
  ]
}

resource "aws_iam_role_policy_attachment" "attach_s3" {
  role       = aws_iam_role.eks-service-account-role.name
  policy_arn = aws_iam_policy.s3.arn
}

resource "aws_iam_role_policy_attachment" "attach_dynamodb" {
  role       = aws_iam_role.eks-service-account-role.name
  policy_arn = aws_iam_policy.dynamodb.arn
}
