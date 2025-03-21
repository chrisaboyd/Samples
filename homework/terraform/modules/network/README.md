# Private Network Module
Deploy private networking infrastructure

#### Inputs:
| Variable Name | Type | Description | Required/Optional | Default Value |
|-------------|-------------|-------------|-------------|-------------|
| vpc_name | string | common name to apply to the VPC and all subsequent resources | Required | none |
| environment | string | SDLC stage | Required | none |
| azs | list(string) | AWS availabiility zones to deploy VPC subnets into | Required | none |
| vpc_cidr | string | CIDR range to assign to VPC | Required | none |
| private_subnet_cidrs | list(string) | cCIDR range to assign to private subnets | Required | none |
| public_subnet_cidrs | list(string) | CIDR range to assign to public subnets | Required | none |

#### Outputs:
| Output Name | Description |
|-------------|-------------|
| vpc_id | ID of the VPC |
| private_subnet_ids | list of IDs of the private subnets |
| public_subnet_ids | list of IDs of the public subnets |

#### Creates:
* Virtual Private Cloud (VPC)
  * 2 private subnets and associated route tables
  * 2 public subnets and associated route tables
* Internet Gateway - allow inbound/outbound traffic to/from public subnets (inbound denied by security group)
* Nat Gateway - allow outbound traffic from private subnets
* Security Group - deny all inbound and outbound traffic
* VPC endpoints - allows communication between resources in the VPC and other AWS services to route over AWS privatelink keeping the communication private
  * S3
  * ECR
* Flow Log - logs basic network traffic data to a CWL group

#### Usage:
```
module "network" {
  source      = "path/to/network"

  vpc_name    = "vpc-name"
  environment = "dev"

  azs = ["us-east-1b", "us-east-1c"]

  vpc_cidr             = "10.0.0.0/16"
  private_subnet_cidrs = ["10.0.0.0/24","10.0.1.0/24"]
  public_subnet_cidrs  = ["10.0.3.0/24","10.0.4.0/24"]
}
```
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
| <a name="module_vpc"></a> [vpc](#module\_vpc) | terraform-aws-modules/vpc/aws | 5.19.0 |

## Resources

| Name | Type |
|------|------|
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/data-sources/region) | data source |
| [aws_security_group.default](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/data-sources/security_group) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_azs"></a> [azs](#input\_azs) | AWS availabiility zones to deploy VPC subnets into | `list(string)` | <pre>[<br/>  "us-east-1a",<br/>  "us-east-1b",<br/>  "us-east-1c"<br/>]</pre> | no |
| <a name="input_environment"></a> [environment](#input\_environment) | SDLC stage | `string` | `"dev"` | no |
| <a name="input_private_subnet_cidrs"></a> [private\_subnet\_cidrs](#input\_private\_subnet\_cidrs) | CIDR range to assign to private subnets | `list(string)` | <pre>[<br/>  "10.0.1.0/24",<br/>  "10.0.2.0/24",<br/>  "10.0.3.0/24"<br/>]</pre> | no |
| <a name="input_public_subnet_cidrs"></a> [public\_subnet\_cidrs](#input\_public\_subnet\_cidrs) | CIDR range to assign to public subnets | `list(string)` | <pre>[<br/>  "10.0.4.0/24",<br/>  "10.0.5.0/24",<br/>  "10.0.6.0/24"<br/>]</pre> | no |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | CIDR range to assign to VPC | `string` | `"10.0.0.0/16"` | no |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | common name to apply to the VPC and all subsequent resources | `string` | `"ps_vpc"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_private_subnet_ids"></a> [private\_subnet\_ids](#output\_private\_subnet\_ids) | n/a |
| <a name="output_public_subnet_ids"></a> [public\_subnet\_ids](#output\_public\_subnet\_ids) | n/a |
| <a name="output_vpc_id"></a> [vpc\_id](#output\_vpc\_id) | n/a |
<!-- END_TF_DOCS -->
