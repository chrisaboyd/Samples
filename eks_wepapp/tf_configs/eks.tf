data "aws_iam_policy" "eks_cluster_policy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy" "eks_service_policy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy" "vpc_resource_policy" {
  arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_iam_role" "webapp_role" {
  name = "eks-webapp-dev"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EKSClusterAssumeRole",
            "Effect": "Allow",
            "Principal": {
                "Service": "eks.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
   role       = "${aws_iam_role.webapp_role.name}"
   policy_arn = "${data.aws_iam_policy.eks_cluster_policy.arn}"
}

resource "aws_iam_role_policy_attachment" "eks_service_policy" {
   role       = "${aws_iam_role.webapp_role.name}"
   policy_arn = "${data.aws_iam_policy.eks_service_policy.arn}"
}

resource "aws_iam_role_policy_attachment" "vpc_resource_policy" {
   role       = "${aws_iam_role.webapp_role.name}"
   policy_arn = "${data.aws_iam_policy.vpc_resource_policy.arn}"
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "17.20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.k8s_cluster_version
  enable_irsa     = true

  vpc_id     = var.vpc_id
  subnets = var.private_subnet_ids

  node_groups = {
    standard = {
      desired_capacity = 3
      max_capacity     = 5
      min_capacity     = 1

      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
      k8s_labels = {
        service = "webapp"
      }
      additional_tags = {
        Environment = var.environment
      }
      k8s_labels = {
        "base_node" = "yes"
      }
    }

  }

  map_roles = [
    {
      rolearn  = "${aws_iam_role.webapp_role.arn}"
      username = "${aws_iam_role.webapp_role.name}"
      groups   = ["system:masters"]
    }
  ]
  map_users = [
    {
      userarn  = "arn:aws:iam::<redacted>:user/chris.boyd"
      username = "chris.boyd"
      groups   = ["system:masters"]
    },
  ]
}
