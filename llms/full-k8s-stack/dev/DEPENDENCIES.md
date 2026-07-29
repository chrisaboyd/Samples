# Component Dependency Lineage (dev)

How the `dev/` components depend on one another. Deploy **top-down** (a component's
dependencies must be healthy first); tear down bottom-up. `deploy.sh` encodes this order.

## Graph

```mermaid
graph TD
  %% Layer 0 - foundation
  subgraph L0["Layer 0 · Cluster foundation"]
    NS["cluster<br/>(namespaces, gp2 SC*)"]
    KPS["kube-prometheus-stack<br/>(Prometheus, Grafana,<br/>ServiceMonitor CRDs)"]
    ING["ingress-nginx"]
    GPU["gpu-operator*"]
  end

  %% Layer 1 - substrate
  subgraph L1["Layer 1 · Platform substrate"]
    PG["postgres"]
    CH["clickhouse"]
    RD["redis"]
    S3["object-storage<br/>(SeaweedFS)"]
  end

  %% Layer 2 - inference
  VLLM["inference / vllm*"]

  %% Layer 3 - gateway
  LITE["litellm<br/>(primary gateway)"]
  BIF["bifrost<br/>(alt gateway)"]
  OWUI["open-webui"]

  %% Layer 4 - guardrails
  PRES["presidio"]
  NEMO["nemo-guardrails"]
  LLMG["llm-guard"]

  %% Layer 5 - observability
  LF["langfuse"]
  OTEL["otel-collector"]
  TEMPO["tempo"]
  LOKI["loki"]
  DCGM["dcgm-exporter*"]
  SM["servicemonitors"]

  %% Layer 6 - load testing
  LOCUST["locust"]

  %% foundation edges
  NS --> PG & CH & RD & S3 & VLLM & LITE & BIF & OWUI & PRES & NEMO & LLMG & LF & OTEL & TEMPO & LOKI & DCGM & LOCUST
  KPS --> SM
  KPS -. metrics .-> PG
  GPU --> VLLM & DCGM

  %% substrate -> apps
  PG --> LITE
  PG --> LF
  PG -. optional pg mode .-> BIF
  RD --> LF
  RD -. cache .-> LITE
  RD --> BIF
  CH --> LF
  S3 --> LF

  %% inference -> gateway
  VLLM --> LITE

  %% gateway -> guardrails / tracing
  PRES --> LITE
  NEMO -. optional .-> LITE
  LLMG -. optional .-> LITE
  LITE -. traces .-> LF

  %% gateway -> ui / load
  LITE --> OWUI
  LITE --> LOCUST

  %% telemetry fan-out
  BIF -. OTLP .-> OTEL
  LITE -. OTLP .-> OTEL
  OTEL --> TEMPO
  OTEL -. remote_write .-> KPS

  %% servicemonitors observe these
  SM -. scrapes .-> LITE & BIF & LF & VLLM & DCGM
```

`*` = requires/produces GPU or cluster-provided primitives (gp2 StorageClass, GPU nodes).
Dashed edges are optional / runtime-config wiring (not hard ordering).

## Dependency table

| Component | Hard prerequisites | Depended on by |
|-----------|--------------------|----------------|
| **cluster** (namespaces) | a `gp2` StorageClass (cluster-provided) | everything |
| **kube-prometheus-stack** | cluster | servicemonitors, postgres metrics, otel-collector (remote_write) |
| **ingress-nginx** | cluster | external access to UIs (optional) |
| **gpu-operator** | cluster, GPU nodes | inference/vllm, dcgm-exporter |
| **postgres** | cluster | litellm, langfuse, bifrost (optional) |
| **clickhouse** | cluster | langfuse |
| **redis** | cluster | langfuse, bifrost, litellm (cache) |
| **object-storage** (SeaweedFS) | cluster | langfuse |
| **inference/vllm** | cluster, gpu-operator, GPU | litellm (backend), vllm ServiceMonitor |
| **litellm** | postgres, inference backend; presidio (PII); redis, langfuse (optional) | open-webui, locust, litellm ServiceMonitor |
| **bifrost** | redis; otel-collector (telemetry); postgres (optional HA) | bifrost ServiceMonitor |
| **open-webui** | litellm | — |
| **presidio** | cluster | litellm (PII guardrail) |
| **nemo-guardrails** | cluster | litellm (optional rail) |
| **llm-guard** | cluster | litellm (optional scanner) |
| **tempo** | cluster | otel-collector (trace backend) |
| **loki** | cluster | (log store; add a shipper to populate) |
| **otel-collector** | tempo, kube-prometheus-stack | bifrost / litellm traces |
| **langfuse** | postgres, clickhouse, redis, object-storage | litellm (tracing), langfuse ServiceMonitor |
| **dcgm-exporter** | cluster, GPU, kube-prometheus-stack | dcgm ServiceMonitor |
| **servicemonitors** | kube-prometheus-stack + target services | Prometheus scrape config |
| **locust** | litellm → inference | — |

## The critical path (thin vertical slice)

`cluster → postgres → inference/vllm → litellm → (one prompt/response)`

Everything else (guardrails, the second gateway, the observability stack, load testing)
layers on top of that slice.
