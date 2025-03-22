module "network" {
  count                 = var.create_network ? 1 : 0
  vpc_cidr              = var.vpc_cidr
  source                = "../modules/network"
}

module "api_ecr" {
  source = "../modules/ecr"
  repository_name   = "api-ecr-${var.environment}"
  environment   = var.environment
  region   = var.region
}

module "rag_ecr" {
  source = "../modules/ecr"
  repository_name   = "rag-ecr-${var.environment}"
  environment   = var.environment
  region   = var.region
}

#module "postgres" {
#  db_instance_name     = var.db_instance_name
#  db_subnet_group_name = var.db_subnet_group_name
#  source               = "../modules/postgres"
#  subnet_ids     = var.create_network ? module.network[0].private_subnet_ids : var.subnet_ids
#  vpc_id         = var.create_network ? module.network[0].vpc_id : var.vpc_id
#  vpc_cidr_block = var.create_network ? module.network[0].vpc_cidr_block : var.vpc_cidr
#}

module "eks" {
 capacity_type = var.capacity_type
 node_size     = var.node_size
 source        = "../modules/eks"
 subnet_ids = var.create_network ? module.network[0].private_subnet_ids : var.subnet_ids
 vpc_id     = var.create_network ? module.network[0].vpc_id : var.vpc_id
 vpc_name   = var.create_network ? module.network[0].vpc_name : var.vpc_name
}

module "cluster_services" {
 account_id                                     = var.account_id
 amazon_fluent_bit_cloudwatch_role_arn          = module.eks.amazon_fluent_bit_cloudwatch_role_arn
 amazon_managed_service_prometheus_iam_role_arn = module.eks.amazon_managed_service_prometheus_iam_role_arn
 cluster_autoscaler_iam_role_arn                = module.eks.cluster_autoscaler_iam_role_arn
 cluster_name                                   = module.eks.cluster_name
 external_secrets_iam_role_arn                  = module.eks.external_secrets_iam_role_arn
 load_balancer_controller_iam_role_arn          = module.eks.load_balancer_controller_iam_role_arn
 source                                         = "../modules/services"
}
