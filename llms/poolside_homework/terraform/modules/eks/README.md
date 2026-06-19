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
| <a name="provider_kubernetes"></a> [kubernetes](#provider\_kubernetes) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_amazon_fluent_bit_cloudwatch_irsa_role"></a> [amazon\_fluent\_bit\_cloudwatch\_irsa\_role](#module\_amazon\_fluent\_bit\_cloudwatch\_irsa\_role) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.52.2 |
| <a name="module_amazon_managed_service_prometheus_irsa_role"></a> [amazon\_managed\_service\_prometheus\_irsa\_role](#module\_amazon\_managed\_service\_prometheus\_irsa\_role) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.52.2 |
| <a name="module_cluster_autoscaler_irsa_role"></a> [cluster\_autoscaler\_irsa\_role](#module\_cluster\_autoscaler\_irsa\_role) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.52.2 |
| <a name="module_eks"></a> [eks](#module\_eks) | terraform-aws-modules/eks/aws | 20.33.1 |
| <a name="module_external_secrets_irsa_role"></a> [external\_secrets\_irsa\_role](#module\_external\_secrets\_irsa\_role) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.52.2 |
| <a name="module_load_balancer_controller_irsa_role"></a> [load\_balancer\_controller\_irsa\_role](#module\_load\_balancer\_controller\_irsa\_role) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.52.2 |
| <a name="module_vpc_cni_irsa_role"></a> [vpc\_cni\_irsa\_role](#module\_vpc\_cni\_irsa\_role) | terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks | 5.52.2 |

## Resources

| Name | Type |
|------|------|
| [aws_autoscaling_schedule.scale_down_night](https://registry.terraform.io/providers/hashicorp/aws/5.89.0/docs/resources/autoscaling_schedule) | resource |
| [kubernetes_cluster_role_binding.eks_admins_binding](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/cluster_role_binding) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_amp_alias"></a> [amp\_alias](#input\_amp\_alias) | The alias of the prometheus workspace. See more in the [AWS Docs](https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-onboard-create-workspace.html) | `string` | `null` | no |
| <a name="input_capacity_type"></a> [capacity\_type](#input\_capacity\_type) | Capacity type for EKS Nodes | `string` | `"ON_DEMAND"` | no |
| <a name="input_enable_amp"></a> [enable\_amp](#input\_enable\_amp) | Enable Amazon Managed Prometheus | `bool` | `false` | no |
| <a name="input_node_size"></a> [node\_size](#input\_node\_size) | Node size for EKS Nodes | `string` | `"c6a.2xlarge"` | no |
| <a name="input_region"></a> [region](#input\_region) | Region to deploy resources to | `string` | `"us-east-1"` | no |
| <a name="input_subnet_ids"></a> [subnet\_ids](#input\_subnet\_ids) | A list of VPC subnet IDs | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | AWS VPC ID | `string` | n/a | yes |
| <a name="input_vpc_name"></a> [vpc\_name](#input\_vpc\_name) | AWS VPC Name | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_access_entries"></a> [access\_entries](#output\_access\_entries) | n/a |
| <a name="output_amazon_fluent_bit_cloudwatch_role_arn"></a> [amazon\_fluent\_bit\_cloudwatch\_role\_arn](#output\_amazon\_fluent\_bit\_cloudwatch\_role\_arn) | IAM Role ARN for Amazon Fluent Bit CloudWatch |
| <a name="output_amazon_managed_service_prometheus_iam_role_arn"></a> [amazon\_managed\_service\_prometheus\_iam\_role\_arn](#output\_amazon\_managed\_service\_prometheus\_iam\_role\_arn) | IAM Role ARN for Amazon Managed Service for Prometheus |
| <a name="output_cluster"></a> [cluster](#output\_cluster) | n/a |
| <a name="output_cluster_autoscaler_iam_role_arn"></a> [cluster\_autoscaler\_iam\_role\_arn](#output\_cluster\_autoscaler\_iam\_role\_arn) | IAM Role ARN for Cluster Autoscaler Controller |
| <a name="output_cluster_id"></a> [cluster\_id](#output\_cluster\_id) | EKS Cluster ID |
| <a name="output_cluster_name"></a> [cluster\_name](#output\_cluster\_name) | EKS Cluster Name |
| <a name="output_cluster_version"></a> [cluster\_version](#output\_cluster\_version) | n/a |
| <a name="output_external_secrets_iam_role_arn"></a> [external\_secrets\_iam\_role\_arn](#output\_external\_secrets\_iam\_role\_arn) | IAM Role ARN for External Secrets Controller |
| <a name="output_kubeconfig_string"></a> [kubeconfig\_string](#output\_kubeconfig\_string) | n/a |
| <a name="output_load_balancer_controller_iam_role_arn"></a> [load\_balancer\_controller\_iam\_role\_arn](#output\_load\_balancer\_controller\_iam\_role\_arn) | IAM Role ARN for Load Balancer Controller |
| <a name="output_node_security_group_id"></a> [node\_security\_group\_id](#output\_node\_security\_group\_id) | Security Group ID for EKS Nodes |
<!-- END_TF_DOCS -->
