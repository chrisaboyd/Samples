data "kubectl_file_documents" "namespaces" {
  content = file("${path.module}/namespaces/namespaces.yaml")
}
resource "kubectl_manifest" "namespaces" {
  for_each  = data.kubectl_file_documents.namespaces.manifests
  yaml_body = each.value
}
