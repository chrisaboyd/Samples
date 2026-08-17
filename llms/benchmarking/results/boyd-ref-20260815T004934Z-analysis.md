# vLLM benchmark analysis

- Source: `/Users/chris.boyd/gitrepos/Samples/llms/benchmarking/results/boyd-ref-20260815T004934Z.jsonl`
- Run started: 2026-08-15T00:49:34.929Z
- Model: `Laguna`
- Token budget: 4080
- Theoretical concurrency: 32
- Metric selector: `unset`

## Test curve

| Test | Shape | Cache | Conc. | Reqs | Prompt tok/s | Gen tok/s | p50 TTFT | p95 TTFT | Prefill share | Max waiting | KV max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| T01 | 15:1 | cold | 1 | 1 | 4546 | 303 | 0.359s | 0.359s | n/a | n/a | n/a |
| T02 | 5:1 | cold | 1 | 1 | 2110 | 422 | 0.327s | 0.327s | n/a | n/a | n/a |
| T03 | 1:1 | cold | 1 | 1 | 501 | 501 | 0.260s | 0.260s | n/a | 0 | 0.12 |
| T04 | 1:5 | cold | 1 | 1 | 107 | 535 | 0.127s | 0.127s | n/a | 0 | 0.12 |
| T05 | 1:1 | cold | 16 | 16 | 3775 | 3775 | 1.203s | 3.931s | n/a | 1 | 0.19 |
| T06 | 1:1 | cold | 32 | 32 | 6373 | 6373 | 2.015s | 3.601s | n/a | 6 | 0.17 |
| T07 | 1:1 | cold | 40 | 40 | 4637 | 4637 | 2.820s | 12.529s | n/a | 9 | 0.29 |
| T08 | 15:1 | hot | 16 | 16 | 37964 | 2531 | 0.909s | 0.914s | n/a | 0 | 0.16 |
| T09 | 15:1 | mixed | 16 | 16 | 19254 | 1284 | 1.974s | 2.488s | n/a | 6 | 0.19 |
| T10 | 15:1 | cold | 16 | 16 | 13660 | 911 | 2.212s | 3.747s | n/a | 6 | 0.20 |

Prompt tokens and generated tokens cost different amounts of compute. Compare each column within one shape, never across shapes.

## Relationship checks

| Status | Expectation | Evidence |
|---|---|---|
| PASS | Complete T01-T10 suite | missing: none |
| PASS | All requests succeeded | request errors: 0 |
| PASS | Exact prompt-token budgets | token mismatches: 0 |
| PASS | Steady measurement window in every test | unsteady: none |
| NOT OBSERVED | 1:5 is decode-dominated | T04 prefill share n/a |
| NOT OBSERVED | Prefill share falls as the shape tilts toward output | T01 n/a > T02 n/a > T03 n/a > T04 n/a |
| NOT OBSERVED | 1:1 is decode-bound despite equal token counts | T03 prefill share n/a |
| PASS | T05 batching payoff | T05 7550.1 vs T03 1001.1 tokens/s |
| FAIL | T05 controlled TTFT | T05 3.931s vs T03 0.260s |
| FAIL | T05 no queue | max waiting 1 |
| PASS | T05 no preemptions | preemptions 0 |
| PASS | T06 queue appears | max waiting 6 |
| FAIL | T06 throughput flattens | T06 12746.2 vs T05 7550.1 tokens/s |
| PASS | T07 no throughput gain | T07 9273.2 vs T06 12746.2 tokens/s |
| PASS | T07 TTFT worsens | T07 12.529s vs T06 3.601s |
| PASS | T07 queue does not improve | T07 9 vs T06 6 waiting |
| PASS | Prefix-cache TTFT ordering | hot 0.914s, mixed 2.488s, cold 3.747s |
| NOT OBSERVED | Prefix-cache hit ordering | hot n/a, mixed n/a, cold n/a |
| FAIL | Prefix cache leaves decode untouched | hot ITL 0.043s vs cold ITL 0.137s |

## Operational classification

- T05 healthy: **no**
- T06 saturated: **no**
- T07 overloaded: **yes**

## Measurement caveats

- BENCH_METRIC_SELECTOR was unset, so every Prometheus figure sums all vLLM targets in the cluster. Treat server-side numbers as upper bounds contaminated by unrelated traffic.

## Analyst notes

Treat `NOT OBSERVED` as missing evidence, not success. Review normalized JSON and raw logs before attributing failures to the model or hardware.
