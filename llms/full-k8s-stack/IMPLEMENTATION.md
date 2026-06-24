# Turnkey Open Source AI Gateway & Observability Stack — Implementation Plan

> **Document role:** This file is the execution contract for an implementing agent. It defines *what* to build and *why*, component by component. It deliberately contains **no code or manifests** — each component task below is a unit of work that produces the actual artifacts in its own folder.

---

## 1. Intent

A turnkey, opinionated, open-source reference repository for running LLM workloads behind a governed gateway with first-class guardrails and observability. The platform is **not** a RAG pipeline — it is a **gateway + guardrails + observability** control plane that sits in front of model backends.

Two deployment paradigms share the same component set:

| Folder  | Audience | Posture |
|---------|----------|---------|
| `dev/`  | Quick, localized MVP / proof-of-value | Everything in-cluster. Zero external cloud dependencies. Single-command bootstrap. |
| `prod/` | Enduring, scoped production environment | Cloud-backed state (RDS, S3), cert-manager TLS, all resources reconciled as code by FluxCD. |

**Guiding rule:** in `dev/`, every dependency runs inside the cluster unless no in-cluster option exists. In `prod/`, stateful primitives (relational DB, object storage) move to managed cloud services and everything is GitOps-managed.

---

## 2. The Stack (authoritative component list)

### Gateway & Frontend
| Tool | Role | Source |
|------|------|--------|
| **LiteLLM** | Primary OpenAI-compatible gateway; unified provider routing; **native guardrail hook surface**; key/budget/spend tracking | https://www.litellm.ai/ |
| **Bifrost** | High-throughput Go gateway alternative; native Prometheus + OTel; governance/virtual keys | https://github.com/maximhq/bifrost |
| **OpenWebUI** | Chat UI for human interaction; points at the gateway endpoint | https://github.com/open-webui/open-webui |

### Guardrails
| Tool | Role | Source |
|------|------|--------|
| **Microsoft Presidio** | PII detection / anonymization (analyzer + anonymizer) | https://microsoft.github.io/presidio/ |
| **NeMo Guardrails** | Topical / dialogue / jailbreak rails | https://github.com/NVIDIA-NeMo/Guardrails |
| **LLM Guard** | Input/output scanners (prompt injection, secrets, toxicity, etc.) | https://github.com/protectai/llm-guard |

Guardrails are orchestrated **through LiteLLM's hook surface**. Required placement matrix:

| Control | LiteLLM hook |
|---------|--------------|
| Block obvious prompt injection | `pre_call` |
| Mask emails, SSNs, API keys, names | `pre_call` or `during_call` |
| Prevent sensitive output leakage | `post_call` |
| Redact before Langfuse / logging | `logging_only` |
| Protect MCP / tool calls | `pre_mcp_call` |

### Observability
| Tool | Role | Source |
|------|------|--------|
| **Langfuse** | LLM-native tracing: trajectories, cost, latency, token traces | https://langfuse.com/ |
| **kube-prometheus-stack** | Prometheus + Grafana + AlertManager + kube-state-metrics + node-exporter | https://github.com/kubernetes/kube-state-metrics |
| **DCGM Exporter** | GPU utilization / memory / health metrics for Prometheus | https://github.com/NVIDIA/dcgm-exporter |
| **OpenTelemetry Collector** / **Grafana Alloy** | Trace + telemetry collection / fan-out | https://opentelemetry.io/docs/collector/ · https://github.com/grafana/alloy |
| **Loki** | Cluster log aggregation | https://github.com/grafana/loki |
| **Tempo** | Distributed trace storage backend | https://grafana.com/oss/tempo/ |

### Load Testing
| Tool | Role |
|------|------|
| **Locust** | Synthetic load against the gateway to validate latency, TTFT/TPOT, error rates, autoscaling |

### Inference backend (dependency, swappable)
The gateways front a model backend. For a self-contained `dev/` ("zero external dependencies"), deploy an **in-cluster vLLM** as the backend; in `prod/` the same vLLM deployment or external provider APIs are valid. A `vllm` ServiceMonitor is part of the monitoring contract, so this component is expected to exist even if individual deployments point LiteLLM/Bifrost at external APIs instead.

---

## 3. Platform Substrate (the part the original plan got wrong)

Several components are **stateful and shared**. They must be stood up *before* the application layer. Critically, **Langfuse v3 is a multi-service application** with four backing stores — not a single Postgres dependency.

### Langfuse v3 backing requirements (verified)
- **PostgreSQL** — transactional data (users, projects, API keys, prompts, datasets)
- **ClickHouse** (>= 24.3) — OLAP store for traces / observations / scores
- **Redis / Valkey** — BullMQ event queue + cache (API keys, prompts)
- **S3-compatible blob storage** — raw ingestion events, multimodal payloads, exports
- **Two app containers** — `langfuse-web` (UI/API) and `langfuse-worker` (async ingestion)

> The official `langfuse/langfuse-k8s` Helm chart deploys web + worker but assumes **bring-your-own** Postgres / ClickHouse / Redis / S3. Its in-chart subcharts are single-replica and intended only for smoke testing — fine for `dev/`, **not** for `prod/`.

### Substrate mapping

| Substrate | `dev/` implementation | `prod/` implementation |
|-----------|----------------------|------------------------|
| Relational DB (Postgres) | Bitnami PostgreSQL StatefulSet + PVC (local-path/EBS StorageClass) | **Amazon RDS** (PostgreSQL), private subnets, automated backups |
| Object storage (S3 API) | **SeaweedFS** in-cluster (master + volume + filer, S3 endpoint) | **Amazon S3** buckets, IAM/IRSA scoped, public access blocked, lifecycle policies |
| OLAP (ClickHouse) | In-cluster ClickHouse, single replica | In-cluster ClickHouse (Altinity operator, HA) — no managed AWS-native equivalent in scope |
| Cache/queue (Redis) | In-cluster Redis/Valkey | In-cluster Redis/Valkey **or** ElastiCache |
| Lightweight component state | SQLite-on-PVC where a component supports it (e.g. Bifrost default) | Postgres-backed mode for the same components |

LiteLLM uses Postgres for virtual keys / budgets / spend; Bifrost defaults to SQLite-on-PVC and should move to its Postgres mode for HA in `prod/`. Both can reuse the shared Postgres/Redis substrate.

---

## 4. Repository Structure

Components are grouped by layer for maintainability; **each leaf folder is an independently deployable component and a discrete task.** Build order flows top to bottom within each environment.

```
.
├── README.md                       # High-level overview + quick start
├── IMPLEMENTATION.md               # This file — execution contract
│
├── dev/
│   ├── README.md
│   ├── deploy.sh                   # Single-command bootstrap (ordered)
│   ├── verify.sh                   # Post-deploy health gate
│   ├── teardown.sh                 # Cleanup
│   │
│   ├── cluster/                    # Namespaces, StorageClass, Prometheus Operator CRDs,
│   │                               #   GPU Operator / NVIDIA device plugin, ingress controller
│   ├── platform/
│   │   ├── postgres/               # Bitnami PostgreSQL StatefulSet
│   │   ├── clickhouse/             # In-cluster ClickHouse (Langfuse OLAP)
│   │   ├── redis/                  # In-cluster Redis/Valkey (queue + cache)
│   │   └── object-storage/         # SeaweedFS (S3-compatible)
│   │
│   ├── inference/
│   │   └── vllm/                   # Optional in-cluster model backend
│   │
│   ├── gateway/
│   │   ├── litellm/                # Primary gateway + guardrail orchestration
│   │   ├── bifrost/                # Alternative gateway
│   │   └── open-webui/             # Chat UI
│   │
│   ├── guardrails/
│   │   ├── presidio/               # Analyzer + anonymizer services
│   │   ├── nemo-guardrails/        # Rails server
│   │   └── llm-guard/              # Scanner service
│   │
│   ├── observability/
│   │   ├── kube-prometheus-stack/  # Prometheus + Grafana + AlertManager + KSM + node-exporter
│   │   ├── dcgm-exporter/          # GPU metrics
│   │   ├── loki/                   # Logs
│   │   ├── tempo/                  # Traces
│   │   ├── otel-collector/         # OTel Collector or Grafana Alloy
│   │   ├── langfuse/               # LLM tracing (web + worker)
│   │   └── servicemonitors/        # ServiceMonitors: litellm, bifrost, langfuse, vllm
│   │
│   └── load-testing/
│       └── locust/                 # Gateway load tests
│
└── prod/
    ├── README.md
    ├── flux/
    │   ├── flux-system/            # FluxCD installation (bootstrap)
    │   ├── sources/                # HelmRepository + GitRepository sources
    │   ├── infrastructure/         # cert-manager, ingress, GPU operator, controllers (ordered)
    │   ├── platform/               # ClickHouse, Redis HelmReleases + RDS/S3 wiring
    │   ├── applications/           # gateway, guardrails, observability HelmReleases
    │   └── clusters/
    │       └── production/         # Root Kustomization (depends-on ordering)
    │
    ├── infrastructure/
    │   ├── cloud-db/               # RDS (Terraform/IaC)
    │   ├── cloud-storage/          # S3 buckets + IAM/IRSA (Terraform/IaC)
    │   └── cert-manager/           # ClusterIssuer config
    │
    └── (component folders mirror dev/, but values target cloud substrate)
```

### Per-component folder contract
Every leaf component folder MUST contain:
```
component-name/
├── README.md            # Purpose, dependencies, what it exposes, ports/services
├── CONFIGURATION.md     # Config reference + key decisions
├── values.yaml          # Helm values (dev defaults) / overlay values (prod)
├── kustomization.yaml    # Kustomize entry (dev) or HelmRelease (prod/flux)
├── secrets/             # Secret *templates* only — never real secrets
└── manifests/           # Raw manifests where no chart exists
```

---

## 5. Component Tasks

Each subsection is a self-contained task. The agent should produce the folder contract above for each. Order reflects dependency.

### Layer 0 — Cluster (`cluster/`)
- **Task:** Namespaces (`platform`, `gateway`, `guardrails`, `observability`, `inference`, `load-testing`), a StorageClass (local-path/k3s in dev; EBS gp3 in prod), the Prometheus Operator CRDs (so `ServiceMonitor` exists before anything references it), the **NVIDIA GPU Operator** (driver handling appropriate to the node AMI) and device plugin, and an ingress controller (NGINX).
- **Dev exposure:** NodePort / LoadBalancer / port-forward.
- **Prod note:** GPU Operator and ingress become Flux `infrastructure/` HelmReleases with explicit `dependsOn` ordering.

### Layer 1 — Platform Substrate (`platform/`)
1. **postgres/** — Bitnami PostgreSQL StatefulSet (dev). Provisions databases/users for LiteLLM, Langfuse, and Bifrost-Postgres-mode. Prod: thin wiring to **RDS** endpoint + ExternalSecret.
2. **clickhouse/** — In-cluster ClickHouse for Langfuse. UTC timezone enforced. `CLICKHOUSE_CLUSTER_ENABLED=false` for single-node dev.
3. **redis/** — Redis/Valkey for Langfuse queue/cache (also available to LiteLLM/Bifrost caching).
4. **object-storage/** — SeaweedFS (master + volume + filer), S3-compatible endpoint + bucket(s) for Langfuse event/blob uploads. Prod: **S3** + IRSA, public access blocked.

> **Gate:** All four substrate services healthy before Langfuse or gateways deploy.

### Layer 2 — Inference (`inference/vllm/`) *(optional but recommended)*
- **Task:** In-cluster vLLM serving a chosen open-weights model on GPU nodes. Exposes an OpenAI-compatible endpoint consumed by the gateways. Emits metrics for the `vllm` ServiceMonitor.
- **Decision point:** keep in-cluster for a fully self-contained dev MVP; in prod, either retain or route gateways to external provider APIs.

### Layer 3 — Gateway (`gateway/`)
1. **litellm/** — Primary gateway. Postgres-backed. Configure provider routing to the inference backend. **Wire the guardrail hooks** per the placement matrix in §2. Expose `/metrics`; register the `litellm` ServiceMonitor. Configure Langfuse as a logging/callback target (redaction applied at `logging_only`).
2. **bifrost/** — Helm chart `https://maximhq.github.io/bifrost/helm-charts`. SQLite-on-PVC (dev) → Postgres mode (prod HA). Enable telemetry (always-on), `serviceMonitor.enabled`, and the OTel plugin pushing to the collector. Requires an encryption-key secret.
3. **open-webui/** — Chat UI pointed at the LiteLLM (or Bifrost) endpoint. Persists conversations to the shared Postgres where supported.

### Layer 4 — Guardrails (`guardrails/`)
1. **presidio/** — Analyzer + anonymizer services. Consumed by LiteLLM at `pre_call`/`during_call` for PII masking and `post_call` for output redaction.
2. **nemo-guardrails/** — Rails server for topical/jailbreak/dialogue control, invoked at `pre_call`.
3. **llm-guard/** — Input/output scanner service (prompt injection, secrets, toxicity) wired into `pre_call`/`post_call`.

> These are deployed as services and **referenced** by LiteLLM config; the gateway is the orchestration point, not each guardrail independently.

### Layer 5 — Observability (`observability/`)
1. **kube-prometheus-stack/** — Prometheus + Grafana + AlertManager + kube-state-metrics + node-exporter. Dev: scrape config + community dashboards, no alerting. Prod: custom rules + AlertManager notification channels.
2. **dcgm-exporter/** — DaemonSet on GPU nodes; ServiceMonitor for GPU utilization/memory/health.
3. **loki/** — Log aggregation (+ Promtail/Alloy as the shipper).
4. **tempo/** — Trace storage backend; receives from the OTel Collector.
5. **otel-collector/** — OpenTelemetry Collector (or Grafana Alloy) as the telemetry hub: receives OTLP from Bifrost/LiteLLM, fans out to Tempo (traces) and Prometheus/Loki.
6. **langfuse/** — Web + worker, wired to Postgres + ClickHouse + Redis + object storage from Layer 1. LLM trajectory/cost/latency tracing.
7. **servicemonitors/** — Central ServiceMonitor definitions for `litellm`, `bifrost`, `langfuse`, `vllm`, plus DCGM.

**Monitoring coverage delivered:** cluster health, node pressure, pod restarts, GPU utilization & memory, request latency, tokens/sec, TTFT/TPOT (where the inference server exposes them), gateway error rates, and LLM-level cost/trace analysis via Langfuse.

### Layer 6 — Load Testing (`load-testing/locust/`)
- **Task:** Locust deployment with scenarios driving chat-completion traffic through the gateway. Validates the observability pipeline end-to-end (latency, TTFT/TPOT, error rates) and exercises autoscaling under load.

---

## 6. Prod-Only Additions

`prod/` is `dev/` plus the following. Everything below is reconciled by FluxCD.

### 6.1 cert-manager (`infrastructure/cert-manager/`)
- TLS for all external endpoints.
- **Decision to resolve (called out explicitly):** "AWS Public Certificates" can mean two different paths:
  - **AWS ACM** certificates terminated at the ALB/NLB via the AWS Load Balancer Controller — in which case cert-manager is *not* the issuer for those endpoints.
  - **cert-manager + ACME (Let's Encrypt)** issuing certs *in-cluster*.
  - Pick one per endpoint class and document it. If the intent is genuinely ACM-issued public certs at the edge, the gateway ingress uses ALB + ACM annotations and cert-manager is reserved for internal/mTLS certs. State the chosen model in `cert-manager/README.md`.

### 6.2 FluxCD (`flux/`)
- **GitOps source of truth.** All Helm charts are delivered as `HelmRelease` resources against `HelmRepository`/`OCIRepository` sources — **Helm as IaC**, not imperative `helm install`.
- Ordering via Kustomization `dependsOn`: `infrastructure` → `platform` → `applications`.
- Health checks and pruning enabled. Optional progressive delivery (Flagger) is a future enhancement.

### 6.3 Cloud substrate
- **cloud-db/** — RDS (Terraform/IaC), private access, automated backups, PITR.
- **cloud-storage/** — S3 buckets, IRSA-scoped IAM, lifecycle policies, public access blocked.
- ClickHouse and Redis remain in-cluster (HA) unless a managed equivalent is later adopted.

### 6.4 Hardening
- NetworkPolicies restricting pod-to-pod traffic.
- Pod Security Standards enforced.
- External Secrets Operator (or Sealed Secrets) for all credentials — **no plaintext secrets in Git**.
- RBAC, least-privilege service accounts, IRSA for AWS access.

---

## 7. Deployment Flows

### Dev
```
./dev/cluster/...      # (optional) bootstrap kind/k3s, then Layer 0
./dev/deploy.sh        # ordered: cluster → platform → inference → gateway → guardrails → observability → load-testing
./dev/verify.sh        # gates on pod readiness + a live prompt→response through the gateway
```

### Prod
```
flux bootstrap ...                 # install FluxCD against the Git repo
# Flux reconciles prod/flux/clusters/production:
#   infrastructure (cert-manager, ingress, GPU operator)
#   → platform (ClickHouse, Redis, RDS/S3 wiring)
#   → applications (gateway, guardrails, observability)
```

---

## 8. Success Criteria

### Dev
- [ ] Single-command deploy succeeds; all pods Running within ~5 min.
- [ ] Substrate (Postgres, ClickHouse, Redis, SeaweedFS) healthy before app layer.
- [ ] A prompt routed through LiteLLM → inference backend → response works end-to-end.
- [ ] A PII-laden prompt is masked per the guardrail matrix; redaction visible before it reaches Langfuse.
- [ ] Langfuse shows the trace, token counts, latency, and cost for that request.
- [ ] Grafana shows cluster + GPU (DCGM) metrics; gateway ServiceMonitors are scraping.
- [ ] Locust run generates load and the full telemetry pipeline reflects it.
- [ ] No external cloud account required.

### Prod
- [ ] Flux reconciles all resources with health checks green.
- [ ] cert-manager (or ACM path) serves valid TLS on all external endpoints.
- [ ] Gateways and Langfuse connect to RDS + S3; ClickHouse/Redis HA in-cluster.
- [ ] Secrets sourced via External/Sealed Secrets — none in Git.
- [ ] NetworkPolicies, PSS, and RBAC enforced.
- [ ] Full observability (metrics, logs, traces, GPU, LLM cost/trace) operational.

---

## 9. Conventions

- kebab-case for files and directories.
- `*.yaml` for manifests; `values.yaml` for Helm values; `kustomization.yaml` at each kustomize layer; `HelmRelease` for Flux-managed charts.
- `README.md` + `CONFIGURATION.md` in every component folder.
- `deploy.sh` / `verify.sh` / `teardown.sh` are **dev-only**; prod is GitOps.
- Health/readiness probes on every service.
- Secret *templates* only in-repo.

---

## 10. Implementation Notes

- Build the thin vertical slice first: **Postgres → inference backend → LiteLLM → one prompt/response**, then layer guardrails, then observability, then the second gateway and UI.
- Test each component standalone before integration.
- Treat the §2 placement matrix as the contract for guardrail wiring — it is the most error-prone integration point.
- Document rollback per component.
- Langfuse is the component most likely to fail a naive deploy: confirm **all four** backing stores and the worker container are present and reachable before declaring it healthy.

---

## 11. Future Enhancements

1. Multi-region prod.
2. Autoscaling tuned for LLM traffic (KEDA on Langfuse worker queue depth; HPA on gateways).
3. Canary deployments via Flagger.
4. Backup/restore runbooks (pg_dump, ClickHouse `BACKUP` to S3, S3 replication, Velero for manifests).
5. Disaster recovery runbooks.
6. Cost-optimization guide (GPU bin-packing, spot for inference, S3 lifecycle).