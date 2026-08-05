# vLLM metric reference

Metric names are from vLLM v1 (`vllm:` prefix). Older builds may lack some series.
Every metric here carries `model_name` and `engine` labels; select on them.

---

## The request lifecycle

A request moves through phases, and vLLM times each one separately:

```
arrives → WAITING ──────→ PREFILL ──────→ DECODE ──────→ done
          queue_time      prefill_time    decode_time
          └──────────── inference_time ────────────────┘
                        ^                ^          ^
                        │                │          └─ ITL between each later token
                        │                └─ TTFT ends here (first token emitted)
                        └─ TTFT starts at arrival
```

`request_inference_time ≈ queue + prefill + decode`. Attribute regressions to a phase
before theorizing about causes.

---

## Saturation signals — check these first

| Metric | Type | Meaning | Healthy |
|---|---|---|---|
| `vllm:num_requests_running` | gauge | requests in the current execution batch | any; it's the load input, not a verdict |
| `vllm:num_requests_waiting` | gauge | queue depth | ~0. Sustained >0 = arrivals exceed service rate |
| `vllm:num_requests_waiting_by_reason` | gauge | `capacity` = no scheduling room; `deferred` = LoRA budget / KV transfer / blocked | tells you *why* the queue exists |
| `vllm:num_preemptions` | counter | requests evicted mid-generation for KV space, then recomputed | flat at 0. Any rise is expensive |
| `vllm:num_dropped` | counter | requests rejected for exceeding max queue size | flat at 0. Users see errors |
| `vllm:kv_cache_usage_perc` | gauge | fraction of KV blocks in use (1.0 = full) | <0.85. >0.9 sustained ⇒ preemptions imminent |
| `vllm:engine_sleep_state` | gauge | `awake=0` means the engine is asleep | `awake=1` |

**KV capacity math.** From `vllm:cache_config_info`:
```
kv_token_capacity = num_gpu_blocks × block_size
kv_tokens_resident = kv_cache_usage_perc × kv_token_capacity
max_concurrent_requests ≈ kv_token_capacity / mean_context_length
```
This tells you concretely how many requests of *your* size fit, which is far more useful
than the raw percentage.

---

## Latency

| Metric | Meaning | Notes |
|---|---|---|
| `vllm:time_to_first_token_seconds` | arrival → first token | What users feel as "responsiveness". Dominated by queue + prefill |
| `vllm:inter_token_latency_seconds` | gap between consecutive output events | Streaming smoothness. Tail here shows up as visible stutter |
| `vllm:request_time_per_output_token_seconds` | per-request mean s/token | **`1/TPOT` = per-stream tokens/sec**, the number to quote to users |
| `vllm:request_queue_time_seconds` | time in WAITING | Should be milliseconds unless queueing |
| `vllm:request_prefill_time_seconds` | time in PREFILL | Scales with *uncached* prompt tokens |
| `vllm:request_decode_time_seconds` | time in DECODE | ≈ output_tokens × TPOT. Usually dominates e2e |
| `vllm:request_inference_time_seconds` | scheduled → finished | queue + prefill + decode |

Rough per-stream expectations for a well-tuned mid-size model on modern datacenter GPUs:
30–80 tok/s at low concurrency, degrading gracefully as the batch fills. **Below ~15 tok/s
while GPU utilization is in single digits means the bottleneck is scheduling, not compute.**

Interpret against an SLO, not in the abstract. Typical interactive targets: TTFT p95 < 1s,
TPOT < 50 ms (≈20 tok/s, comfortably faster than reading speed). Batch/offline work often
has no TTFT target at all and should be tuned purely for throughput.

---

## Throughput and work

| Metric | Meaning |
|---|---|
| `vllm:prompt_tokens_total` | prompt tokens **submitted** (includes cache hits — this is not the compute load) |
| `vllm:prompt_tokens_cached_total` | prompt tokens served from cache, local + external |
| `vllm:prompt_tokens_by_source_total` | split by `local_compute` / `local_cache_hit` / `external_kv_transfer` |
| `vllm:generation_tokens_total` | output tokens produced |
| `vllm:iteration_tokens_total` | histogram of tokens processed per engine step (prefill + decode together) |
| `vllm:request_success_total` | completed requests, by `finished_reason` |

**The single most clarifying derived number:**
```
prefill_tokens_computed = prompt_tokens_total - prompt_tokens_cached_total
```
Submitted prompt tokens are marketing; computed prefill tokens are the actual GPU load.
With good prefix caching these differ by 10×.

```
prefill_to_decode_ratio = prefill_tokens_computed / generation_tokens
```
- **< 1:1** — decode-bound. Memory-bandwidth limited. Bigger batches help throughput.
- **1:1 – 5:1** — balanced.
- **> 5:1** — prefill-bound. Compute limited, and decode latency is hostage to prefill
  scheduling. Chunked-prefill tuning and P/D disaggregation are the levers here.

**`finished_reason` breakdown** — `stop` is normal; a lot of `length` means clients are
hitting `max_tokens` (answers truncated, and you paid for every token); `abort` means
clients disconnected, often because they timed out waiting on *you*; `error`/`drop`
are always worth investigating.

---

## Caching

| Metric | Meaning |
|---|---|
| `vllm:prefix_cache_queries_total` / `_hits_total` | local prefix cache, in tokens |
| `vllm:external_prefix_cache_queries_total` / `_hits_total` | cross-instance KV sharing via a KV connector |
| `vllm:mm_cache_queries_total` / `_hits_total` | multi-modal input cache, in items |

Hit rate = `rate(hits) / rate(queries)`. For multi-turn chat or agent loops with shared
system prompts, 80–95% local is normal and healthy.

A **drop** in hit rate is one of the most common silent causes of a prefill spike — the
workload didn't change, but suddenly 3× as many tokens need real computation. Usual
causes: load-balancer routing changed and follow-ups stopped landing on the pod holding
the prefix; a new client varies the prompt prefix (timestamps, session IDs, shuffled
context); or cache eviction pressure from longer contexts.

The **external** cache is only consulted for what missed locally. A low external hit rate
is only worth acting on if it's high *volume* — it costs a lookup per miss. If local hit
rate is already high, external hits near zero is expected, not broken.

---

## Speculative decoding

| Metric | Meaning |
|---|---|
| `vllm:spec_decode_num_drafts_total` | draft rounds |
| `vllm:spec_decode_num_draft_tokens_total` | tokens proposed |
| `vllm:spec_decode_num_accepted_tokens_total` | tokens accepted by the target model |
| `vllm:spec_decode_num_accepted_tokens_per_pos_total` | acceptance by position in the draft |

```
acceptance_rate      = accepted_tokens / draft_tokens
accepted_per_draft   = accepted_tokens / drafts
```
Acceptance decays monotonically with position — later draft tokens are far less likely to
be accepted. If the tail positions have very low acceptance you're spending draft compute
for nothing; shortening the draft length can be a net win.

Spec decode is a pure throughput multiplier when it works. A silent acceptance drop
(model update, workload shift to a domain the drafter handles badly) looks exactly like
"the server got slower" with no other symptom. Always check it; it is easy to miss.

---

## GPU utilization

| Metric | Meaning |
|---|---|
| `vllm:estimated_flops_per_gpu_total` | estimated FLOPs per GPU |
| `vllm:estimated_read_bytes_per_gpu_total` | estimated HBM bytes read per GPU |
| `vllm:estimated_write_bytes_per_gpu_total` | estimated HBM bytes written per GPU |

```
MFU = rate(estimated_flops_per_gpu_total) / peak_FLOPs_per_GPU
MBU = rate(estimated_read_bytes + estimated_write_bytes) / peak_HBM_bandwidth_per_GPU
```

Use the peak matching the compute dtype actually in use (check `cache_config_info`
`cache_dtype` and the model's quantization).

Approximate per-GPU peaks (dense, no sparsity — halve vendor "with sparsity" numbers):

| GPU | BF16/FP16 | FP8 | HBM bandwidth | HBM capacity |
|---|---|---|---|---|
| B200 | ~2.2 PFLOP/s | ~4.5 PFLOP/s | ~8 TB/s | 180 GB |
| H200 | ~990 TFLOP/s | ~2.0 PFLOP/s | ~4.8 TB/s | 141 GB |
| H100 SXM | ~990 TFLOP/s | ~2.0 PFLOP/s | ~3.35 TB/s | 80 GB |
| A100 80GB | ~312 TFLOP/s | n/a | ~2.0 TB/s | 80 GB |

Interpretation:
- **Prefill-bound work** should push MFU. >35–50% under load is healthy.
- **Decode-bound work** should push MBU. >50% under load is healthy; MFU stays low by
  nature, because decode is a memory-bandwidth problem, not a compute one.
- **Both in single digits while latency is bad** is the diagnostic jackpot: the GPUs are
  idle and something in scheduling, batching, or request mix is the bottleneck.

`vllm:estimated_*` are model-based estimates, not hardware counters. Trust them for
trends and order of magnitude; use DCGM/`nvidia-smi` for ground truth.

---

## Process-level

| Metric | Use |
|---|---|
| `process_start_time_seconds` | **process fingerprint.** Different value = different process. Detects restarts and mixed-up snapshot files |
| `process_resident_memory_bytes` | API-server host RSS (not GPU memory). Steady growth = leak |
| `process_cpu_seconds_total` | API-server CPU. Tracks request/token volume, not wall time |

Note these describe the **API server / frontend** process, not the GPU worker.

---

## Config

`vllm:cache_config_info` is a static gauge whose *labels* carry the engine config:
`block_size`, `num_gpu_blocks`, `cache_dtype`, `enable_prefix_caching`,
`gpu_memory_utilization`, `sliding_window`. Read it before drawing conclusions — it tells
you the KV capacity, whether prefix caching is on, and how much GPU memory was reserved.
