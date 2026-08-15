---
name: analyze-vllm-benchmark
description: Extract, normalize, and analyze results from the vLLM inference behavior Kubernetes Job. Use when asked to inspect the latest or a named vllm-behavior-benchmark Job, analyze a benchmark JSON/JSONL log, compare T01-T10 behavior, assess healthy/saturated/overloaded states, evaluate prefix-cache effectiveness, or summarize benchmark findings.
---

# Analyze vLLM Benchmark

Use the bundled script for deterministic extraction and first-pass relationship checks, then interpret its report for the user.

## Workflow

1. Locate the benchmark repository. Prefer the current workspace's `llms/benchmarking` directory.
2. Extract and analyze one run with `scripts/extract_and_analyze.py`:

   ```sh
   python3 scripts/extract_and_analyze.py \
     --kubeconfig ~/.kube/contexts/boyd-ref \
     --namespace poolside-models \
     --output-dir ./results
   ```

   The default Kubernetes mode is read-only and selects the newest successful Job with label `app.kubernetes.io/name=vllm-behavior-benchmark`.

3. To analyze a specific Job, pass `--job JOB_NAME`. To avoid cluster access and analyze a saved artifact, pass `--input PATH.json` or `--input PATH.jsonl`.
4. Read both generated artifacts:
   - `*-analysis.md` contains the concise deterministic findings and relationship checks.
   - `*-normalized.json` contains the complete normalized evidence for deeper interpretation.
5. Report the run identity, request/token validation, throughput and latency curve, queue/KV/preemption evidence, prefix-cache ordering, failed or unobserved expectations, and important measurement limitations.

## Interpretation rules

- Treat missing, `null`, or non-finite Prometheus values as `NOT OBSERVED`, never as a pass or zero.
- Prefer vLLM Prometheus metrics for queue, prefill/decode, cache, KV, and preemption claims. Use client measurements for request success, exact token counts, aggregate throughput, TTFT, and client-observed ITL.
- Compare each workload only with the PRD-designated baseline or adjacent load level. Do not compare raw latency across unrelated shapes as though output budgets were equal.
- Call a state healthy only when throughput improves, queueing is absent or bounded, preemptions remain zero, and TTFT/ITL stay controlled relative to baseline.
- Call saturation only when queue/latency evidence appears and useful throughput begins flattening. A scheduler cap alone is insufficient.
- Call overload only when additional concurrency provides no throughput gain while latency or queue depth worsens; note whether KV pressure or preemption corroborates it.
- For T08-T10, require hot > mixed > cold cache-hit ordering when hit metrics exist and hot < mixed < cold prefill/TTFT ordering. Explain partial evidence separately.
- Flag scrape-window contamination, insufficient samples, concurrent unrelated traffic, or missing final reports when detected.

## Safety

Do not create, rerun, delete, or modify Kubernetes Jobs while analyzing results. If no completed Job exists, report that condition and ask whether the user wants to run the benchmark separately.
