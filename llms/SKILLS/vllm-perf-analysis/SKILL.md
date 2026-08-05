---
name: vllm-perf-analysis
description: Diagnose vLLM inference server performance from Prometheus metrics — a live /metrics endpoint, saved snapshot files, or a Prometheus/Grafana range query. Use when someone reports slow inference, high latency, TTFT/TPOT regressions, timeouts, throughput drops, GPU underutilization, or "the model got slower", or asks to analyze vllm metrics, check inference capacity, or size a deployment.
---

# vLLM performance analysis

Turn vLLM metrics into a diagnosis: what degraded, by how much, why, and what to change.

## Rule zero: never read a raw counter

Every `vllm:*_total` is cumulative since process start. Every `*_bucket` is a cumulative
histogram. A single scrape describes the whole life of the process, averaged — it cannot
tell you how the server is behaving now. **Always compute deltas between two points in
time**, or use `rate()` in PromQL. A p99 that looks fine across 8 hours of history can be
hiding a catastrophic last 20 minutes.

Same rule for the `_sum`/`_count` pair: mean over an interval is
`(sum₂-sum₁)/(count₂-count₁)`, never `sum/count`.

## Step 1 — get data

**Live endpoint** (preferred for a spot check; takes at least two scrapes to say anything):
```bash
scripts/vllm_snapshot.py --url http://<pod>:8000/metrics --samples 3 --interval 300
```

**Saved snapshot files**, oldest first. Pass `--gaps` if you know the spacing:
```bash
scripts/vllm_snapshot.py --files 10am.txt 11am.txt 12pm.txt --gaps 3600,3600
```
Without `--gaps` the script reconstructs elapsed time from Little's law
(`N × mean_e2e ÷ mean_concurrency`) and labels every rate as approximate. That estimate
depends on two instantaneous concurrency samples, so it is fragile — if either endpoint
caught the engine idle it will be wildly wrong. Ratios and per-request numbers stay valid
regardless; only per-second rates and MFU/MBU depend on it.

**Prometheus or Grafana** (preferred for a real investigation — you get the time axis):
```bash
scripts/vllm_promql.py --url http://prometheus:9090 --hours 6
scripts/vllm_promql.py --url https://grafana.example/api/datasources/proxy/uid/<UID> \
                       --token "$GRAFANA_TOKEN" --hours 6 --selector 'model_name="m",pod="vllm-0"'
```

## Step 2 — verify snapshot identity before comparing anything

`process_start_time_seconds` is the process's fingerprint. Two snapshots with different
values are **different processes** — either a restart (all counters reset to zero, so
deltas are meaningless or negative) or files from different pods that got mixed together.
`vllm_snapshot.py` checks this and splits the series automatically; heed the warning.
Also confirm the `model_name` and `engine` labels match across files.

## Step 3 — is the engine saturated? (this is the fork in the road)

Check these four before anything else. They separate "out of capacity" from
"has capacity but is slow", and the fixes are completely different.

| Signal | Healthy | Meaning if bad |
|---|---|---|
| `vllm:num_requests_waiting` | ~0 | Sustained >0 = arrivals exceed service rate. **Genuinely out of capacity.** |
| `vllm:num_preemptions` | flat at 0 | Rising = KV cache exhausted, requests evicted and recomputed. Very expensive. |
| `vllm:num_dropped` | flat at 0 | Rising = requests rejected at the queue limit. Users see errors. |
| `vllm:kv_cache_usage_perc` | < 0.85 | Sustained >0.9 = memory-bound; preemptions are imminent. |

- **Any of these bad** → capacity problem. Add replicas, raise `gpu_memory_utilization`,
  shorten context, or shed load. Go to `references/playbook.md` § capacity.
- **All clean but latency is up** → *not* a capacity problem. The engine is choosing to
  batch harder, or the workload changed shape. Keep going — and do not "fix" it by raising
  `max_num_seqs`, which makes per-request latency worse.

## Step 4 — decompose the latency, don't just report it

`e2e_inference = queue + prefill + decode`. Attribute the regression before theorizing:

- **queue grew** → scheduler admission pressure. Cross-check `num_requests_waiting`.
- **prefill grew** → bigger prompts, or a prefix-cache hit-rate drop, or prefill chunks
  competing. Check `request_prompt_tokens` mean and `prefix_cache_hit_rate`.
- **decode grew** → the usual case. Split it further:
  - `request_generation_tokens` mean up ⇒ **answers got longer**. Workload change, not a
    regression. e2e rises with no engine slowdown at all.
  - `1/TPOT` (per-stream tokens/sec) down ⇒ **the engine genuinely slowed**. Contention.

Report these as separate multipliers. "Decode time is 1.7× — 1.17× from longer answers,
1.48× from slower tokens" is a diagnosis; "latency is up 70%" is not.

## Step 5 — check the headline efficiency numbers

Compute utilization against the actual hardware (see `references/metrics.md` for peak
specs and the formulas):

- **MFU** = `estimated_flops_per_gpu` rate ÷ per-GPU peak FLOP/s
- **MBU** = `(estimated_read_bytes + estimated_write_bytes)` rate ÷ per-GPU HBM bandwidth

Under real load, healthy is roughly >35% MFU for prefill-heavy work or >50% MBU for
decode-heavy work. **Single-digit MFU *and* single-digit MBU while users complain about
latency is the strongest signal in the whole dataset**: the hardware is idle and the
bottleneck is scheduling, batching, or the request mix. That is a tuning problem, and
buying more GPUs will not fix it.

## Step 6 — understand the workload before recommending anything

These are wall-clock independent and reframe everything above:

- `request_prompt_tokens` mean/p99 — long-context work behaves nothing like chat.
- `request_generation_tokens` mean/p99 — short answers make prefill dominate.
- **computed prefill : generated tokens** = `(prompt_tokens - prompt_tokens_cached) / generation_tokens`.
  Above ~5:1 the deployment is prefill-bound and every latency conclusion follows from that.
- `prefix_cache_hit_rate` — high is good; a *drop* is a common silent cause of prefill spikes.
- `tokens_per_engine_step` mean — rises when prefill chunks pack the batch. Every decoding
  request advances at most one step's worth of tokens per iteration, so a doubling here
  roughly doubles ITL for everyone streaming. This is prefill/decode interference and it is
  the most common cause of "it got slower but nothing is saturated".
- `spec_decode` acceptance rate — a silent drop costs throughput with no other symptom.

## Step 7 — write the diagnosis

State, in this order:
1. **Did it actually degrade** — the specific metric, before → after, with the multiplier.
2. **Where the time went** — queue vs prefill vs decode, in seconds.
3. **Whether anything is saturated** — quote the four step-3 signals explicitly, including
   the zeros. "Zero preemptions, zero queueing, KV at 33%" is a load-bearing finding.
4. **What changed** — concurrency, prompt size, answer length, cache hit rate.
5. **The mechanism** — connect 3 and 4 causally.
6. **What to change**, ordered by expected effect. Tuning before hardware.

Flag data-quality problems (mixed processes, unknown intervals, single snapshot) plainly
rather than quietly working around them.

## References

- `references/metrics.md` — every metric that matters, what it means, healthy ranges,
  accelerator peak specs, MFU/MBU formulas.
- `references/playbook.md` — symptom → discriminator → cause → fix decision tree, and the
  vLLM flags worth reaching for.
