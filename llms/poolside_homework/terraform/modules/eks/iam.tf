# Create IAM Role for EKS CloudWatch Logging
module "amazon_fluent_bit_cloudwatch_irsa_role" {
  source                 = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version                = "5.52.2"
  role_name              = "amazon-fluent-bit-cloudwatch"
  allow_self_assume_role = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["amazon-cloudwatch:fluent-bit"]
    }
  }
  role_policy_arns = {
    CloudWatch_Agent_Server_Policy = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  }

  tags = local.tags
}
# Create IAM Role for Cluster Autoscaler EKS Deployment
module "cluster_autoscaler_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.52.2"

  role_name                        = "cluster-autoscaler"
  attach_cluster_autoscaler_policy = true
  cluster_autoscaler_cluster_ids   = [module.eks.cluster_name]

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }
}
# Create IAM Role for Secret Store CSI Driver EKS Deployment
module "external_secrets_irsa_role" {
  source                                             = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version                                            = "5.52.2"
  role_name                                          = "external-secrets"
  attach_external_secrets_policy                     = true
  external_secrets_ssm_parameter_arns                = ["arn:aws:ssm:*:*:parameter/*"]
  external_secrets_secrets_manager_arns              = ["arn:aws:secretsmanager:*:*:secret:*"]
  external_secrets_kms_key_arns                      = ["arn:aws:kms:*:*:key/*"]
  external_secrets_secrets_manager_create_permission = false

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["ps:csi-secret-provider"]
    }
  }

  tags = local.tags
}
# Create IAM Role for Load Balancer Controller EKS Deployment
module "load_balancer_controller_irsa_role" {
  source                                 = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version                                = "5.52.2"
  role_name                              = "load-balancer-controller"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    ex = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  tags = local.tags
}
# Create IAM Role for VPC CNI Add-On
module "vpc_cni_irsa_role" {
  source                = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version               = "5.52.2"
  role_name             = "prefect_vpc_cni"
  attach_vpc_cni_policy = true
  vpc_cni_enable_ipv4   = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }

  tags = local.tags
}
# Create a Cluster Role Binding for the EKS Admins Group in main.tf
resource "kubernetes_cluster_role_binding" "eks_admins_binding" {
  metadata {
    name = "eks-admins-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
  }

  subject {
    kind      = "Group"
    name      = "eks-admins"
    api_group = "rbac.authorization.k8s.io"
  }

  depends_on = [module.eks]
}
