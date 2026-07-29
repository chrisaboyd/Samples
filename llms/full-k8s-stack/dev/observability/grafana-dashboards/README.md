# Grafana Dashboards

Default dashboards for vLLM inference and NVIDIA GPU telemetry.

## Purpose

Ships opinionated dashboards as ConfigMaps. The Grafana sidecar
(`grafana.sidecar.dashboards.enabled=true` in `kube-prometheus-stack/values.yaml`)
watches all namespaces for ConfigMaps labelled `grafana_dashboard=1` and provisions
their JSON automatically — no Grafana restart, no manual import.

## Dependencies

- `kube-prometheus-stack` (Grafana + the dashboard sidecar + the Prometheus datasource)
- `servicemonitors` (without the vLLM and DCGM ServiceMonitors the panels have no data)

## Dashboards

| UID | Title | Source metrics |
|---|---|---|
| `vllm-overview` | vLLM / Inference Overview | `vllm:*` from the poolside inference-stack (atlas) container |
| `dcgm-gpu` | GPU / DCGM Exporter | `DCGM_FI_DEV_*` from dcgm-exporter |

Both dashboards expose a `Data source` variable, so they work against any Prometheus
datasource. `vllm-overview` adds a multi-select `Model` variable (from the `model_name`
label) and `dcgm-gpu` adds a multi-select `GPU` variable.

### vllm-overview

Headline stats (running, queued, KV cache, prompt/output tok/s, finished req/s), then
latency (TTFT, inter-token latency, end-to-end, and a queue/prefill/decode p95
breakdown), throughput, scheduler state, and cache effectiveness.

The bottom section breaks each latency histogram out into its own p50/p95/p99 panel —
queue, prefill, decode, inference (prefill + decode, excluding queue wait), and time
per output token. All are Prometheus histograms, so read the p95/p99 series rather than
the average; the p50 is there only for contrast.

`vllm:kv_cache_usage_perc` is a 0–1 fraction despite the `_perc` suffix, so those
panels use Grafana's `percentunit`.

### dcgm-gpu

Utilization, memory-copy utilization, framebuffer usage, temperature, power, and SM /
memory clocks — per GPU.

Panels are built **only** from the counters listed in the `dcgm-metrics` ConfigMap in
`../dcgm-exporter/`. DCP/profiling fields (`DCGM_FI_PROF_*` — tensor-core activity, SM
occupancy) are **not** collected: the exporter logs `Not collecting DCP metrics`
because that DCGM module isn't loaded. Add those counters to the ConfigMap and enable
the profiling module before adding panels that depend on them.

## Files

- `kustomization.yaml` - configMapGenerator + the `grafana_dashboard` label
- `dashboards/*.json` - dashboard definitions

## Individual Deployment

```bash
kubectl apply -k .
```

## Verification

```bash
# ConfigMaps exist and carry the sidecar label
kubectl -n observability get cm -l grafana_dashboard=1

# Sidecar picked them up
kubectl -n observability logs deploy/kube-prometheus-stack-grafana \
  -c grafana-sc-dashboard | grep -i dashboard
```

Then open Grafana and search for "vLLM" or "GPU".

## Editing

Grafana's UI edits are not persisted back here. To change a dashboard, edit the JSON
in `dashboards/`, re-apply, and the sidecar reloads it. Keep the `uid` stable so
existing links and any alerting references keep resolving.
