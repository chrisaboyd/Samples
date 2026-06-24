data "kubectl_file_documents" "ingress" {
  content = file("${path.module}/aws-load-balancer-controller/default-load-balancer-ingress.yaml")
}
resource "kubectl_manifest" "ingress" {
  for_each  = data.kubectl_file_documents.ingress.manifests
  yaml_body = each.value

  depends_on = [
    helm_release.aws_load_balancer_controller
  ]
}
