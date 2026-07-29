# cert-manager TLS

TLS certificates for external endpoints.

## Certificate Issuer

Two options documented:

1. **AWS ACM @ ALB** (recommended for AWS)
   - cert-manager NOT used for public certs
   - ALB annotations reference ACM certs
   - Internal/mTLS still via cert-manager

2. **cert-manager + ACME**
   - Let's Encrypt for external endpoints
   - ClusterIssuer configured

## Implementation

See CONFIGURATION.md for the chosen model per endpoint class.

## Secrets

TLS certificates stored in Kubernetes secrets, not Git.