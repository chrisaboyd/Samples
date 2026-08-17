# vLLM benchmark analysis

- Source: `/Users/chris.boyd/gitrepos/Samples/llms/benchmarking/results/vllm-behavior-benchmark-tp2-fp8-20260817-2gh7f-raw.jsonl`
- Run started: 2026-08-17T13:24:13.030Z
- Model: `Laguna`
- Token budget: 4080
- Theoretical concurrency: 32 (bound by max_num_seqs)
- Metric selector: `namespace="poolside-models",model_name="Laguna"`

## Test curve

| Test | Shape | Cache | Conc. | Reqs | Prompt tok/s | Gen tok/s | p50 TTFT | p95 TTFT | Prefill share | Max waiting | KV max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| T01 | 15:1 | cold | 1 | 201 | 7343 | 490 | 0.235s | 0.241s | 0.452 | 0 | 0.03 |
| T02 | 5:1 | cold | 1 | 108 | 3492 | 698 | 0.215s | 0.217s | 0.221 | 0 | 0.01 |
| T03 | 1:1 | cold | 1 | 44 | 854 | 854 | 0.146s | 0.148s | 0.061 | 0 | 0.01 |
| T04 | 1:5 | cold | 1 | 28 | 179 | 896 | 0.083s | 0.084s | 0.022 | 0 | 0.01 |
| T05 | 1:1 | cold | 16 | 257 | 5377 | 5377 | 1.035s | 1.654s | 0.191 | 0 | 0.09 |
| T06 | 1:1 | cold | 32 | 290 | 6503 | 6503 | 1.695s | 2.388s | 0.160 | 0 | 0.16 |
| T07 | 1:1 | cold | 40 | 282 | 6579 | 6579 | 2.240s | 9.327s | 0.298 | 8 | 0.18 |
| T08 | 15:1 | hot | 16 | 1169 | 42945 | 2863 | 0.803s | 0.888s | 0.491 | 11 | 0.11 |
| T09 | 15:1 | mixed | 16 | 621 | 23060 | 1537 | 0.585s | 1.117s | 0.251 | 3 | 0.12 |
| T10 | 15:1 | cold | 16 | 431 | 15983 | 1066 | 1.491s | 2.080s | 0.384 | 1 | 0.17 |
| S01 | 1:1 | cold | 8 | 201 | 4077 | 4077 | 0.695s | 0.905s | 0.160 | 0 | 0.07 |
| S02 | 1:1 | cold | 24 | 289 | 5889 | 5889 | 1.673s | 2.301s | 0.186 | 0 | 0.15 |

Prompt tokens and generated tokens cost different amounts of compute. Compare each column within one shape, never across shapes.

## Relationship checks

| Status | Expectation | Evidence |
|---|---|---|
| PASS | Complete T01-T10 suite | missing: none |
| PASS | All requests succeeded | request errors: 0 |
| PASS | Exact prompt-token budgets | token mismatches: 0 |
| PASS | Steady measurement window in every test | unsteady: none |
| PASS | 1:5 is decode-dominated | T04 prefill share 0.02 |
| PASS | Prefill share falls as the shape tilts toward output | T01 0.452 > T02 0.221 > T03 0.061 > T04 0.022 |
| PASS | 1:1 is decode-bound despite equal token counts | T03 prefill share 0.061 |
| PASS | Batching pays off before the knee | peak throughput 13006 tokens/s at 32 concurrent, 7.7x the single-session baseline |
| PASS | Latency grows slower than load up to the knee | 8: 6.1x TTFT at 8x load; 16: 11.2x TTFT at 16x load; 24: 15.5x TTFT at 24x load; 32: 16.1x TTFT at 32x load |
| PASS | Curve reveals a knee | marginal gain per added session falls to 0.02 of its initial value; knee at 24 concurrent |
| PASS | Curve reaches degradation | levels observed: baseline, healthy, overloaded, saturated |
| PASS | No preemptions before the knee | preemptions at or below the knee: 1:0, 8:0, 16:0 |
| PASS | Prefix-cache TTFT ordering | hot 0.888s, mixed 1.117s, cold 2.080s |
| PASS | Prefix-cache hit ordering | hot 0.784, mixed 0.393, cold 0.000 |
| PASS | Prefix cache does not slow decode | hot ITL 0.002s vs cold ITL 0.009s |

## Operational classification by concurrency

| Conc. | Total tok/s | Marginal gain vs first | p95 TTFT | TTFT growth vs load | Mean waiting | State |
|---:|---:|---:|---:|---|---:|---|
| 1 | 1709 | n/a | 0.148s | 1.0x at 1x | 0.00 | **baseline** |
| 8 | 8154 | 1.00 | 0.905s | 6.1x at 8x | 0.00 | **healthy** |
| 16 | 10754 | 0.35 | 1.654s | 11.2x at 16x | 0.00 | **healthy** |
| 24 | 11778 | 0.14 | 2.301s | 15.5x at 24x | 0.00 | **saturated** |
| 32 | 13006 | 0.17 | 2.388s | 16.1x at 32x | 0.00 | **saturated** |
| 40 | 13158 | 0.02 | 9.327s | 63.0x at 40x | 4.67 | **overloaded** |

- Recommended operating point: **16** concurrent sessions
- Knee: **24** concurrent
- Peak usable throughput at **32** concurrent

## Measurement caveats

- Prefill ran at about 13,556 tokens/sec and decode at about 904 tokens/sec, so prompt tokens cost roughly 15x less time than generated tokens on this hardware. Prefill and decode time split evenly near a 15:1 input/output ratio, which is why the 1:1 shape is overwhelmingly decode time rather than the even split the PRD predicts in section 1.
- Decode ran 4.0x faster with a hot prefix cache (ITL 0.0023s vs 0.0092s). PRD section 3 expects decode to be unaffected, which holds only for an isolated request. Under concurrency prefill chunks and decode steps compete for the same forward passes, so removing prefill work speeds up generation too. Prefix cache hit rate is a throughput lever here, not only a time-to-first-token lever.
- Concurrency was bounded by max_num_seqs (32), not KV cache. KV capacity allowed roughly 238 concurrent sessions at this token budget, about 7.44x the level tested, so saturation and overload here demonstrate scheduler queueing rather than KV pressure. Raise BENCH_TOKEN_BUDGET (50000 is the agentic profile) to make KV the binding constraint.
- Highest concurrency still classified healthy: 16 sessions. The knee is at 24, and peak usable throughput 13006 tokens/s arrives at 32. Running between 16 and 32 trades latency for the last increment of throughput; running past that buys nothing.

## Analyst notes

Treat `NOT OBSERVED` as missing evidence, not success. Review normalized JSON and raw logs before attributing failures to the model or hardware.
