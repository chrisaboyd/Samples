module "eks" {
  version         = "20.33.1"
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "platform-dev-eks"
  cluster_version = "1.31"

  cluster_addons = {
    vpc-cni = {
      resolve_conflicts        = "OVERWRITE"
      service_account_role_arn = module.vpc_cni_irsa_role.iam_role_arn
    }

    aws-ebs-csi-driver = {
      most_recent = true
    }

    coredns = {
      resolve_conflicts = "OVERWRITE"
    }
  }
  cluster_endpoint_public_access = true

  vpc_id     = var.vpc_id
  subnet_ids = var.subnet_ids # Need to be able to pass dynamically

  access_entries = {
    # One access entry with a policy associated
    # For SSO Users to have cluster admin access
    admin_user = {
      kubernetes_groups = ["eks-admins"]
      principal_arn     = "arn:aws:iam::250037329208:user/terraform-dev"
      policy_associations = {
        standard = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }

  eks_managed_node_group_defaults = {
    # We are using the IRSA created below for permissions
    # However, we have to provision a new cluster with the policy attached FIRST
    # before we can disable. Without this initial policy,
    # the VPC CNI fails to assign IPs and nodes cannot join the new cluster
    iam_role_attach_cni_policy = true
    iam_role_additional_policies = {
      policies = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy" #IAM rights needed by CSI driver
    }
  }

  eks_managed_node_groups = {
    eks-dev = {
      min_size       = 1
      max_size       = 1
      desired_size   = 1
      instance_types = [var.node_size]
      capacity_type  = var.capacity_type
    }
  }

  node_security_group_additional_rules = {

    eks_node_http_rule = {
      source_cluster_security_group = true
      description                   = "Allow Node to Node ingress on :80"
      from_port                     = 80
      to_port                       = 80
      protocol                      = "tcp"
      type                          = "ingress"
    }
  }

  tags = {
    Name                                = "eks-dev"
    "k8s.io/cluster-autoscaler/enabled" = "TRUE"
    "k8s.io/cluster-autoscaler/ps" = "owned"
  }
}
resource "aws_autoscaling_schedule" "scale_down_night" {
  scheduled_action_name = "scale-down-night"
  min_size              = 0
  max_size              = 0
  desired_capacity      = 0
  recurrence            = "0 23 * * *" # Scale down at 6:00 PM EST (00:00 UTC)
  time_zone             = "UTC"

  autoscaling_group_name = module.eks.eks_managed_node_groups["eks-dev"].node_group_autoscaling_group_names[0]
}
