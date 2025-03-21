# apps

## cloud2

deploys all apps & services relevant to cloud2.0

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | 5.89.0 |
| <a name="requirement_helm"></a> [helm](#requirement\_helm) | 2.17.0 |
| <a name="requirement_kubectl"></a> [kubectl](#requirement\_kubectl) | 1.19.0 |
| <a name="requirement_time"></a> [time](#requirement\_time) | 0.12.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_helm"></a> [helm](#provider\_helm) | 2.17.0 |
| <a name="provider_kubectl"></a> [kubectl](#provider\_kubectl) | 1.19.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [helm_release.aws_cluster_autoscaler_controller](https://registry.terraform.io/providers/hashicorp/helm/2.17.0/docs/resources/release) | resource |
| [helm_release.aws_load_balancer_controller](https://registry.terraform.io/providers/hashicorp/helm/2.17.0/docs/resources/release) | resource |
| [helm_release.metrics_server](https://registry.terraform.io/providers/hashicorp/helm/2.17.0/docs/resources/release) | resource |
| [helm_release.secrets_store_csi_driver](https://registry.terraform.io/providers/hashicorp/helm/2.17.0/docs/resources/release) | resource |
| [kubectl_manifest.aws_cloudwatch_fluent_bit_cluster_configmap](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_manifest.aws_cloudwatch_fluent_bit_daemonset](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_manifest.aws_cloudwatch_fluent_bit_service_account](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_manifest.external_secrets_release](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_manifest.external_secrets_service_account](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_manifest.ingress](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_manifest.namespaces](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/resources/manifest) | resource |
| [kubectl_file_documents.aws_cloudwatch_fluent_bit_daemonset](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/data-sources/file_documents) | data source |
| [kubectl_file_documents.external_secrets_release](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/data-sources/file_documents) | data source |
| [kubectl_file_documents.ingress](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/data-sources/file_documents) | data source |
| [kubectl_file_documents.namespaces](https://registry.terraform.io/providers/gavinbunney/kubectl/1.19.0/docs/data-sources/file_documents) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_account_id"></a> [account\_id](#input\_account\_id) | Project ID | `string` | n/a | yes |
| <a name="input_adfs_auth_enabled"></a> [adfs\_auth\_enabled](#input\_adfs\_auth\_enabled) | Enable ADFS Authentication vs WorkOS | `bool` | `false` | no |
| <a name="input_amazon_fluent_bit_cloudwatch_role_arn"></a> [amazon\_fluent\_bit\_cloudwatch\_role\_arn](#input\_amazon\_fluent\_bit\_cloudwatch\_role\_arn) | IAM Role ARN for Fluent Bit for CloudWatch Logging - Passed by EKS Module | `string` | n/a | yes |
| <a name="input_amazon_managed_service_prometheus_iam_role_arn"></a> [amazon\_managed\_service\_prometheus\_iam\_role\_arn](#input\_amazon\_managed\_service\_prometheus\_iam\_role\_arn) | IAM Role ARN for Amazon Managed Service for Prometheus - Passed by EKS Module | `string` | n/a | yes |
| <a name="input_cluster_autoscaler_iam_role_arn"></a> [cluster\_autoscaler\_iam\_role\_arn](#input\_cluster\_autoscaler\_iam\_role\_arn) | IAM Role ARN for Cluster Autoscaler Controller - Passed by EKS Module | `string` | n/a | yes |
| <a name="input_cluster_name"></a> [cluster\_name](#input\_cluster\_name) | EKS Cluster Name - Passed by EKS Module | `string` | n/a | yes |
| <a name="input_external_secrets_iam_role_arn"></a> [external\_secrets\_iam\_role\_arn](#input\_external\_secrets\_iam\_role\_arn) | IAM Role ARN for External Secrets Controller - Passed by EKS Module | `string` | n/a | yes |
| <a name="input_load_balancer_controller_iam_role_arn"></a> [load\_balancer\_controller\_iam\_role\_arn](#input\_load\_balancer\_controller\_iam\_role\_arn) | IAM Role ARN for Load Balancer Controller - Passed by EKS Module | `string` | n/a | yes |
| <a name="input_region"></a> [region](#input\_region) | Region to deploy resources to | `string` | `"us-east-1"` | no |

## Outputs

No outputs.
<!-- END_TF_DOCS -->
