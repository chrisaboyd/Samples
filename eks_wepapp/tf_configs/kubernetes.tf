resource “kubernetes_namespace” “webapp” {
  metadata {
    name = webapp
  }
}

resource "kubernetes_service_account" "webapp" {
  metadata {
    name = "terraform-example"
    annotations = {
        "eks.amazonaws.com/role-arn": module.iam_eks_role.arn
    }
  }

  depends_on = [
    module.eks.oidc_provider_arn
  ]
}