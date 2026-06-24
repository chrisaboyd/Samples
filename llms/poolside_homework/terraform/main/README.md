# AWS infrastructure as code

directory to host AWS infrastructure as code


## Requirements
- AWS SA/IAM access w/ highly privileged access to create VPCs/AWS Clusters/AWS Secrets/etc
- Terraform Cloud or Local installed on deploying machine
- A shared location to store the TF State (Preferably S3)

## Deployment
- run `terraform apply` or `terraform apply -var-file="auto.tfvars`

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.89.0 |
| <a name="requirement_helm"></a> [helm](#requirement\_helm) | 2.17.0 |
| <a name="requirement_kubectl"></a> [kubectl](#requirement\_kubectl) | 1.19.0 |
| <a name="requirement_kubernetes"></a> [kubernetes](#requirement\_kubernetes) | 2.36.0 |

## Providers

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_network"></a> [network](#module\_network) | ../modules/network | n/a |

## Resources

No resources.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_id"></a> [account\_id](#input\_account\_id) | AWS Account ID | `string` | `null` | no |
| <a name="input_capacity_type"></a> [capacity\_type](#input\_capacity\_type) | Capacity type for EKS Nodes | `string` | `"ON_DEMAND"` | no |
| <a name="input_cloudwatch_logs_enabled"></a> [cloudwatch\_logs\_enabled](#input\_cloudwatch\_logs\_enabled) | Enable CloudWatch Logs for Fluent Bit | `bool` | `true` | no |
| <a name="input_create_network"></a> [create\_network](#input\_create\_network) | Create network resources for resources if user does not already have a network set up | `bool` | `true` | no |
| <a name="input_db_instance_name"></a> [db\_instance\_name](#input\_db\_instance\_name) | Name of the RDS instance | `string` | `"ps_rds"` | no |
| <a name="input_db_subnet_group_name"></a> [db\_subnet\_group\_name](#input\_db\_subnet\_group\_name) | Name of the AWS RDS subnet group | `string` | `"ps_rds_subnet_group"` | no |
| <a name="input_node_size"></a> [node\_size](#input\_node\_size) | Node size for EKS Nodes | `string` | `"a1.medium"` | no |
| <a name="input_region"></a> [region](#input\_region) | Region to deploy resources to | `string` | `"us-east-1"` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | Subnet IDs to deploy resources to when network is brought by user (Typically private subnets) | `list(string)` | `null` | no |
| <a name="input_subnet_prefix"></a> [subnet\_prefix](#input\_subnet\_prefix) | Prefix for subnet generation for network module | `string` | `"10.0"` | no |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | CIDR block to create for the VPC | `string` | `"10.0.0.0/16"` | no |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | VPC ID to deploy resources to when network is brought by user | `string` | `null` | no |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | VPC name to deploy resources to when network is brought by user | `string` | `null` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->
