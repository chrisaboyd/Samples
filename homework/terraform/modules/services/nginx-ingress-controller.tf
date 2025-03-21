## LEGACY -- for aws/single-use we use the ALB Ingress Controller.
## This is for customer reference only, as an open-source / cloud agnostic ingress controller

# resource "helm_release" "nginx-ingress-controller" {
#   name       = "nginx-ingress-controller"
#   repository = "https://charts.bitnami.com/bitnami"
#   chart      = "nginx-ingress-controller"


#   set {
#     name  = "service.type"
#     value = "LoadBalancer"
#   }

#   set {
#     name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-type"
#     value = "external"

#   }

#   set {
#     name  = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-scheme"
#     value = "internet-facing"
#   }

#   set {
#     Adds ACM Certificate to the Load Balancer
#     name      = "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-cert"
#     value     = "${module.acm_cert.acm_certificate_arn}"
#     type      = "string"
#   }
# }
