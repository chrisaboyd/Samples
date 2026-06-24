# cert-manager Decision

**Chosen model for this stack:**

### AWS Public Endpoints: ALB + ACM

Public-facing services (gateway, UI) terminate TLS at the ALB using AWS ACM certificates. This:
- Reduces in-cluster certificate management
- Offloads TLS termination to AWS
- Enables AWS WAF integration

### Internal Services: cert-manager + Self-Signed

Internal communication between components uses cert-manager issued certificates.

## Required CRDs

- Certificate
- Issuer/ClusterIssuer (self-signed for internal)

## External Secrets

RDS and S3 credentials injected via External Secrets Operator (not Sealed Secrets, per spec).