################################################################################
# RDS Module
################################################################################
module "db" {
  count   = var.rds_aurora ? 0 : 1
  source  = "terraform-aws-modules/rds/aws"
  version = "6.10.0"

  identifier = local.name

  engine               = "postgres"
  engine_version       = "14"
  family               = "postgres14" # DB parameter group
  major_engine_version = "14"         # DB option group
  instance_class       = "db.t4g.large"

  allocated_storage     = 50
  max_allocated_storage = 100

  db_name  = var.db_instance_name
  username = var.master_username
  port     = 5432

  multi_az               = true
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [module.security_group.security_group_id]

  maintenance_window              = "Mon:00:00-Mon:03:00"
  backup_window                   = "03:00-06:00"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  create_cloudwatch_log_group     = true

  backup_retention_period = 1
  skip_final_snapshot     = true
  deletion_protection     = false

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  create_monitoring_role                = true
  monitoring_interval                   = 60
  monitoring_role_name                  = var.rds_monitoring_role_name
  monitoring_role_use_name_prefix       = true
  monitoring_role_description           = var.rds_monitoring_role_description
  create_db_parameter_group             = false
  parameter_group_name                  = aws_db_parameter_group.rds_parameter_group[0].name

  tags = local.tags
  db_option_group_tags = {
    "Sensitive" = "low"
  }
  db_parameter_group_tags = {
    "Sensitive" = "low"
  }
}
