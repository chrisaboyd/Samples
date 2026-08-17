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
4. Read the generated artifacts:
   - `*-analysis.md` contains the deterministic findings, relationship checks, and measurement caveats.
   - `*-report.html` contains the same run as charts. Point the user at this one first.
   - `*-normalized.json` contains the complete normalized evidence for deeper interpretation.
   - `*-annotations.json` can be posted to Grafana to mark the test windows on the dashboard.
5. Report the run identity, request/token validation, throughput and latency curve, queue/KV/preemption evidence, prefix-cache ordering, failed or unobserved expectations, and important measurement limitations.

## Interpretation rules

- Treat missing, `null`, or non-finite Prometheus values as `NOT OBSERVED`, never as a pass or zero.
- Prefer vLLM Prometheus metrics for queue, prefill/decode, cache, KV, and preemption claims. Use client measurements for request success, exact token counts, aggregate throughput, TTFT, and client-observed ITL.
- Compare each workload only with the PRD-designated baseline or adjacent load level. Never compare raw latency or summed token throughput across shapes as though a prompt token and a generated token cost the same.
- Read `concurrency_constraint.binding` before interpreting saturation. When `max_num_seqs` binds and `headroom_ratio` is well above 1, the run demonstrates scheduler queueing and carries no evidence about KV pressure; say so rather than implying the cluster ran out of memory.
- Check `steady_window_valid` on every test. A false value means throughput includes ramp-up and drain and the number is a floor rather than a measurement.
- Check whether `metric_selector` is set. Unset means server-side figures sum every vLLM target in the cluster, so treat them as contaminated upper bounds.
- Call a state healthy only when throughput improves, queueing is absent or bounded, preemptions remain zero, and TTFT/ITL stay controlled relative to baseline.
- Call saturation only when queue/latency evidence appears and useful throughput begins flattening. A scheduler cap alone is insufficient.
- Call overload only when additional concurrency provides no throughput gain while latency or queue depth worsens; note whether KV pressure or preemption corroborates it.
- For T08-T10, require hot > mixed > cold cache-hit ordering when hit metrics exist and hot < mixed < cold prefill/TTFT ordering. Decode speed should be roughly unchanged across all three; a large ITL swing means something other than the prefix cache moved.
- The 1:1 shape is decode-dominated on real hardware. The PRD's section 1 expectation of `prefill_time ≈ decode_time` at 1:1 is wrong, because prefill runs the prompt in parallel while decode is sequential. Report the measured time-balanced ratio instead of flagging this as a hardware failure.
- Flag scrape-window contamination, insufficient samples, concurrent unrelated traffic, or missing final reports when detected.

## Safety

Do not create, rerun, delete, or modify Kubernetes Jobs while analyzing results. If no completed Job exists, report that condition and ask whether the user wants to run the benchmark separately.
