# ServiceMonitor Configuration

All ServiceMonitors use standard labels for Prometheus Operator discovery.

## Discovery

`kube-prometheus-stack/values.yaml` sets
`prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues: false`, which leaves
the Prometheus CR's `serviceMonitorSelector` empty — meaning **every** ServiceMonitor in
the cluster is picked up regardless of its labels. No `release:` label is required.

Because selection is that permissive, a ServiceMonitor whose `selector` is empty or
overly broad will match every service in its target namespaces and scrape endpoints it
was never meant to. Always pin `selector.matchLabels` to something specific.

## Deployed monitors

| Monitor | Target | Port | Notes |
|---|---|---|---|
| `bifrost` | `bifrost/bifrost` | `http` | Unauthenticated `/metrics`. Relabeling keeps only the ClusterIP service — `bifrost-headless` has identical labels and backs the same pod, so a label selector alone scrapes every series twice. |
| `vllm` | `poolside-models/inference-stack-*` | `http` | The poolside inference-stack (atlas) container is vLLM; it serves `vllm:*` on its main http port, not a separate `metrics` port. Selecting on `component=inference` + `part-of=poolside-deployment` covers all model services. |
| `dcgm-exporter` | `observability/dcgm-exporter` | `http` | GPU telemetry. |

## Intentionally absent

Neither of these exposes a Prometheus endpoint in this deployment, so no ServiceMonitor
can work — it would only produce a permanently down target.

**LiteLLM.** `GET /metrics` returns `404` even with a valid `Authorization: Bearer
<master-key>`; unauthenticated it returns `401` from the auth middleware before routing.
The Prometheus exporter is a LiteLLM Enterprise feature. To re-add a monitor you need
both:

- the `prometheus` callback enabled in the proxy config (requires an enterprise licence), and
- either `litellm_settings.require_auth_for_metrics_endpoint: false`, or a bearer token
  supplied to the scrape via `endpoints[].authorization.credentials`. Note the referenced
  secret must live in the **Prometheus namespace** (`observability`), not alongside
  LiteLLM — so this means copying the master key across namespaces.

**Langfuse.** No Prometheus exposition endpoint: `/metrics` and `/metrics/prometheus`
both `404`, and `/api/public/metrics` is the authenticated JSON query API, not an
exporter. The previous manifest scraped `/api/public/health`, which returns JSON that
Prometheus cannot parse. Langfuse's own UI is the place to view its data; alternatively
scrape its Postgres/ClickHouse dependencies via their own exporters.
