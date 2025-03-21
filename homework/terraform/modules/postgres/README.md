# RDS Deployment for Self-Hosted PostgreSQL

Configuration in this directory creates a set of RDS resources including DB instance, DB subnet group and DB parameter group needed by Prefect Self-Hosted.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.89.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.89.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_db"></a> [db](#module\_db) | terraform-aws-modules/rds/aws | 6.10.0 |
| <a name="module_security_group"></a> [security\_group](#module\_security\_group) | terraform-aws-modules/security-group/aws | 5.3.0 |

## Resources

| Name | Type |
|------|------|
| [aws_db_parameter_group.aurora_parameter_group](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/resources/db_parameter_group) | resource |
| [aws_db_parameter_group.rds_parameter_group](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/resources/db_parameter_group) | resource |
| [aws_db_subnet_group.db_subnet_group](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/resources/db_subnet_group) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/data-sources/caller_identity) | data source |
| [aws_vpc.selected](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/data-sources/vpc) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aurora_instance_size"></a> [aurora\_instance\_size](#input\_aurora\_instance\_size) | Aurora instance size | `string` | `"db.t4g.micro"` | no |
| <a name="input_db_instance_name"></a> [db\_instance\_name](#input\_db\_instance\_name) | Name of the RDS instance | `string` | n/a | yes |
| <a name="input_db_subnet_group_name"></a> [db\_subnet\_group\_name](#input\_db\_subnet\_group\_name) | Name of the AWS RDS subnet group | `string` | n/a | yes |
| <a name="input_master_username"></a> [master\_username](#input\_master\_username) | Master username for the RDS instance | `string` | `"postgres"` | no |
| <a name="input_rds_aurora"></a> [rds\_aurora](#input\_rds\_aurora) | Use Aurora for RDS | `bool` | `false` | no |
| <a name="input_rds_monitoring_role_description"></a> [rds\_monitoring\_role\_description](#input\_rds\_monitoring\_role\_description) | Description for the RDS monitoring role | `string` | `""` | no |
| <a name="input_rds_monitoring_role_name"></a> [rds\_monitoring\_role\_name](#input\_rds\_monitoring\_role\_name) | Name for the RDS monitoring role | `string` | `"rds-monitoring-role"` | no |
| <a name="input_region"></a> [region](#input\_region) | Region to deploy resources to | `string` | `"us-east-1"` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | A list of VPC subnet IDs | `list(string)` | n/a | yes |
| <a name="input_vpc_cidr_block"></a> [vpc\_cidr\_block](#input\_vpc\_cidr\_block) | AWS VPC CIDR block | `string` | `""` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | AWS VPC ID | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_db_endpoint"></a> [db\_endpoint](#output\_db\_endpoint) | The database endpoint based on the deployed type (RDS or Aurora) |
| <a name="output_db_instance_address"></a> [db\_instance\_address](#output\_db\_instance\_address) | The hostname of the database instance |
| <a name="output_db_instance_arn"></a> [db\_instance\_arn](#output\_db\_instance\_arn) | The ARN of the database instance |
| <a name="output_db_instance_identifier"></a> [db\_instance\_identifier](#output\_db\_instance\_identifier) | The database identifier for the deployed database type |
| <a name="output_db_instance_master_user_secret_arn"></a> [db\_instance\_master\_user\_secret\_arn](#output\_db\_instance\_master\_user\_secret\_arn) | The ARN of the master user secret |
| <a name="output_db_port"></a> [db\_port](#output\_db\_port) | The database port based on the deployed type (RDS or Aurora) |
| <a name="output_db_secret_rotation_enabled"></a> [db\_secret\_rotation\_enabled](#output\_db\_secret\_rotation\_enabled) | The status of secret rotation for the database |
<!-- END_TF_DOCS -->
