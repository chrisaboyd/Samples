# Cluster Cloudwatch Logs Install
resource "kubectl_manifest" "aws_cloudwatch_fluent_bit_service_account" {
  yaml_body = <<-EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fluent-bit
  namespace: amazon-cloudwatch
  annotations:
    eks.amazonaws.com/role-arn: ${var.amazon_fluent_bit_cloudwatch_role_arn}
EOF
  depends_on = [
    kubectl_manifest.namespaces
  ]
}
resource "kubectl_manifest" "aws_cloudwatch_fluent_bit_cluster_configmap" {
  yaml_body = <<-EOF
apiVersion: v1
kind: ConfigMap
data:
  cluster.name: "${var.cluster_name}"
  logs.region: "${var.region}"
  http.server: "On"
  http.port: "2020"
  read.head: "Off"
  read.tail: "On"
metadata:
  name: fluent-bit-cluster-info
  namespace: amazon-cloudwatch
EOF
  depends_on = [
    kubectl_manifest.namespaces
  ]
}
data "kubectl_file_documents" "aws_cloudwatch_fluent_bit_daemonset" {
  content = file("${path.module}/fluent-bit/fluent-bit.yaml")
}
resource "kubectl_manifest" "aws_cloudwatch_fluent_bit_daemonset" {
  for_each  = data.kubectl_file_documents.aws_cloudwatch_fluent_bit_daemonset.manifests
  yaml_body = each.value
  depends_on = [
    kubectl_manifest.aws_cloudwatch_fluent_bit_service_account
  ]
}
# Cluster Autoscaler Controller Helm install
resource "helm_release" "aws_cluster_autoscaler_controller" {
  name       = "aws-cluster-autoscaler-controller"
  namespace  = "kube-system"
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"
  version    = "9.43.2"

  values = [
    "${file("${path.module}/cluster-autoscaler/cluster-autoscaler.yaml")}"
  ]
  set {
    name  = "rbac.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = var.cluster_autoscaler_iam_role_arn
  }
  set {
    name  = "autoDiscovery.clusterName"
    value = "platform-dev-self-managed"
  }

  depends_on = [
    kubectl_manifest.namespaces
  ]
}
# Load Balancer Controller Helm install
resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "1.9.2"

  values = [
    "${file("${path.module}/aws-load-balancer-controller/aws-load-balancer-controller.yaml")}"
  ]
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = var.load_balancer_controller_iam_role_arn
  }
  set {
    name  = "clusterName"
    value = "platform-dev-self-managed"
  }

  depends_on = [
    kubectl_manifest.namespaces
  ]
}
# Secrets Store CSI Driver Helm install
resource "helm_release" "secrets_store_csi_driver" {
  name       = "secret-store-csi-driver"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts"
  chart      = "secrets-store-csi-driver"
  version    = "1.3.4"
  values = [
    "${file("${path.module}/aws-secret-manager/secrets-store-csi-driver-values.yaml")}"
  ]
  depends_on = [
    kubectl_manifest.namespaces
  ]
}
# AWS Secrets Store Addon Helm install
resource "kubectl_manifest" "external_secrets_service_account" {
  yaml_body = <<-EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-addon: csi-secrets-store-provider-aws.addons.k8s.io
    k8s-app: csi-secrets-store-provider-aws
  name: csi-secrets-store-provider-aws
  namespace: kube-system

EOF
  depends_on = [
    kubectl_manifest.namespaces
  ]
}
# Release
data "kubectl_file_documents" "external_secrets_release" {
  content = file("${path.module}/aws-secret-manager/release.yaml")
}
resource "kubectl_manifest" "external_secrets_release" {
  for_each  = data.kubectl_file_documents.external_secrets_release.manifests
  yaml_body = each.value
  depends_on = [
    kubectl_manifest.external_secrets_service_account,
    helm_release.secrets_store_csi_driver
  ]
}
