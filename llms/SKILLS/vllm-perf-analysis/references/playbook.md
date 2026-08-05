# Diagnostic playbook

Symptom → discriminator → cause → fix. Work top to bottom; the first branch that matches
is usually the whole story.

---

## The decision tree

```
Latency regression reported
│
├─ num_requests_waiting sustained > 0, OR num_preemptions rising, OR num_dropped rising?
│   └─ YES → CAPACITY PROBLEM ....................... § A
│
├─ kv_cache_usage_perc sustained > 0.9?
│   └─ YES → KV MEMORY PROBLEM ...................... § B
│
├─ All clean, but decode time / TPOT up?
│   ├─ request_generation_tokens mean up? → WORKLOAD CHANGE ... § C
│   ├─ tokens_per_engine_step up?         → PREFILL INTERFERENCE ... § D
│   └─ neither, MFU/MBU low?              → SCHEDULING / TUNING ... § E
│
├─ TTFT up but decode flat?
│   ├─ queue_time up?          → admission pressure ... § A
│   ├─ prefill_time up?        → § F
│   └─ prefix_cache_hit_rate down? → CACHE REGRESSION ... § G
│
└─ Throughput down, latency flat? → § H
```

---

## § A — Capacity problem

**Evidence:** `num_requests_waiting` > 0 sustained, `num_dropped` rising, `queue_time`
p95 climbing. Check `num_requests_waiting_by_reason` — `capacity` vs `deferred` point at
different fixes.

Requests are arriving faster than the engine can retire them. Real; not a tuning artifact.

**Fixes, cheapest first:**
1. Add replicas. This is a throughput deficit; horizontal scale is the honest answer.
2. Increase `--max-num-seqs` **only if** KV cache usage is low and you can tolerate worse
   per-request latency. It trades TPOT for throughput.
3. Reduce work per request: shorten context, trim system prompts, improve prefix cache
   hit rate so prefill compute drops.
4. Load-shed or rate-limit at the gateway so you degrade predictably instead of collapsing.

**`deferred` specifically:** LoRA adapter budget, KV transfer, or blocked status — not raw
capacity. Raise `--max-loras`/`--max-cpu-loras`, or investigate the KV connector.

---

## § B — KV memory problem

**Evidence:** `kv_cache_usage_perc` > 0.9, `num_preemptions` rising.

Preemption evicts an in-flight request and recomputes its prefill later. It is the most
expensive failure mode in vLLM: work is thrown away, and the victim's latency explodes.

**Fixes:**
1. Raise `--gpu-memory-utilization` (0.90 → 0.95) if there's headroom. Watch for OOM.
2. Lower `--max-num-seqs` so fewer requests hold KV simultaneously. Sacrifices throughput
   to stop the thrash — usually a net win, because preemption wastes more than it saves.
3. Lower `--max-model-len` if it's set far above real prompt sizes; it reserves capacity.
4. Quantize the KV cache (`--kv-cache-dtype fp8`) — roughly halves KV footprint.
5. Enable KV offloading to CPU, or shard further (higher TP/PP).

Compute `kv_token_capacity / mean_context_length` to get the concrete concurrency ceiling
for *your* workload, and size against that instead of guessing.

---

## § C — Workload change (longer answers)

**Evidence:** `request_generation_tokens` mean/p99 up; `1/TPOT` roughly flat.

The engine is fine. Answers got longer, so e2e time grew proportionally. This is a product
or prompt change, not an infrastructure regression — and no amount of GPU will fix it.

**Check:** a rise in `finished_reason="length"` means clients are hitting `max_tokens`;
they're being truncated *and* you're paying for every token.

**Fixes:** talk to whoever changed the prompts. Set sane `max_tokens`. If longer answers
are intended, this is a capacity planning input — recompute required replicas from the new
mean output length.

---

## § D — Prefill/decode interference

**Evidence:** nothing saturated, `tokens_per_engine_step` mean up sharply, engine steps/sec
down, `prefill_to_decode_ratio` high (>5:1), TPOT and ITL up, MFU/MBU low.

The most commonly misdiagnosed case, and the reason "nothing is saturated but it's slow"
happens.

**Mechanism:** every decoding request advances at most one step's worth of tokens per
engine iteration. When large prefill chunks get packed into the same iterations, each step
takes longer, so *every* streaming request slows down — in lockstep, regardless of how much
GPU headroom exists. Double the tokens per step and you roughly double everyone's ITL.
Rising arrival rate makes it worse linearly, because each new request injects another
prefill burst.

**Fixes:**
1. Cap how much prefill can land in one step: lower `--max-num-batched-tokens`, and set
   `--long-prefill-token-threshold` so one huge prompt can't monopolize an iteration.
   This directly trades TTFT (slightly worse) for ITL/TPOT (much better) — usually the
   right trade for interactive traffic.
2. Raise the prefix cache hit rate so there's less prefill to schedule at all: session
   affinity in the load balancer, stable prompt prefixes, ordered context.
3. **Prefill/decode disaggregation.** The structural fix when the ratio is far above 5:1 —
   separate prefill and decode pools so they stop stealing steps from each other.
4. Route long-prompt and short-prompt traffic to different pools if the mix is bimodal.

**Do not** raise `max_num_seqs` here. Admission isn't the constraint; it will add
concurrency to an already-contended step and make TPOT worse.

---

## § E — Scheduling / tuning headroom

**Evidence:** MFU and MBU both in single digits, latency poor, nothing saturated.

The GPUs are idle. The bottleneck is batch composition, request mix, or the serving
topology. Buying hardware will not help.

**Investigate:** `tokens_per_engine_step` p50 vs p99 (a p50 of ~5 tokens means most steps
are near-empty single-request decodes — no batching is happening); parallelism config
(over-sharding a small model wastes it on communication); whether CUDA graphs / chunked
prefill are enabled; whether the client is actually sending concurrent traffic.

Consider consolidating: if two pods each run at 5% MFU, one pod at 10% serves the same
traffic and halves the bill.

---

## § F — Prefill got slower

**Evidence:** `request_prefill_time_seconds` up, `request_prompt_tokens` up or
`prefix_cache_hit_rate` down.

Prefill scales with *uncached* prompt tokens. Compute
`prompt_tokens_total - prompt_tokens_cached_total` and compare across intervals — the
submitted-token count often looks flat while actual compute has tripled.

**Fixes:** shorten prompts; improve cache hit rate (§ G); tune chunked prefill (§ D).

---

## § G — Cache regression

**Evidence:** `prefix_cache_hit_rate` dropped; prefill time and prefill token rate up;
prompt sizes unchanged.

**Usual causes:**
- Load-balancer routing changed, so follow-up turns no longer land on the pod that holds
  the prefix. **Most common cause, and most fixable.**
- A client started varying the prompt prefix — injected timestamps, request IDs, reordered
  or shuffled retrieved context.
- Cache eviction pressure: longer contexts are pushing older prefixes out.
- Someone disabled prefix caching (check `cache_config_info` `enable_prefix_caching`).

**Fixes:** session-affinity or prefix-aware routing at the load balancer; make prompt
prefixes stable and put variable content at the *end*; enable a KV connector for
cross-instance prefix sharing.

---

## § H — Throughput dropped, latency flat

Check in order:
1. `spec_decode` acceptance rate — a drop silently costs throughput with no latency symptom.
2. Arrival rate — is the client sending less? Compare `request_success_total` rate against
   upstream traffic. Not every throughput drop is your problem.
3. `finished_reason="abort"` rising — clients are disconnecting, often because they timed
   out on *you*. That points back to a latency problem.
4. Replica count / readiness — check whether a pod silently dropped out of rotation.

---

## Reporting checklist

Quote the zeros explicitly. "Zero preemptions, zero queueing, KV at 33%" is what rules out
the capacity story, and without it the reader can't tell whether you checked.

- [ ] Confirmed all snapshots come from the same process (`process_start_time_seconds`)
- [ ] All numbers are interval deltas, not since-boot cumulatives
- [ ] Stated the four saturation signals, including the healthy ones
- [ ] Decomposed e2e into queue / prefill / decode, in seconds
- [ ] Separated "longer answers" from "slower tokens"
- [ ] Computed MFU and MBU against actual hardware peaks
- [ ] Stated the prefill:decode ratio and what it implies
- [ ] Recommendations ordered by expected effect, tuning before hardware
- [ ] Flagged data-quality gaps rather than silently working around them
