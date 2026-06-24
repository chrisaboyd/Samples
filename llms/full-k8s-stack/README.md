# Turnkey Open Source AI Gateway & Observability Stack

A turnkey, opinionated, open-source reference repository for running LLM workloads behind a governed gateway with first-class guardrails and observability.

## Overview

This platform provides:
- **Gateway & Frontend**: LiteLLM, Bifrost, OpenWebUI
- **Guardrails**: Microsoft Presidio, NeMo Guardrails, LLM Guard
- **Observability**: Langfuse, kube-prometheus-stack, DCGM Exporter, Loki, Tempo, OpenTelemetry Collector

## Deployment Paradigms

| Folder | Audience | Posture |
|--------|----------|---------|
| `dev/` | Quick, localized MVP / proof-of-value | Everything in-cluster. Zero external cloud dependencies. Single-command bootstrap. |
| `prod/` | Enduring, scoped production environment | Cloud-backed state (RDS, S3), cert-manager TLS, GitOps via FluxCD. |

## Quick Start (Dev)

```bash
./dev/deploy.sh
./dev/verify.sh
```

## Documentation

- [Implementation Plan](IMPLEMENTATION.md) - Detailed component breakdown and architecture
- [Dev README](dev/README.md) - Development environment setup
- [Prod README](prod/README.md) - Production deployment guide

## Success Criteria

See [IMPLEMENTATION.md](IMPLEMENTATION.md#8-success-criteria) for verification checklist.