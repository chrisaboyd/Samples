# vLLM benchmark analysis

- Source: `/Users/chris.boyd/gitrepos/Samples/llms/benchmarking/results/boyd-ref-20260815T004934Z.jsonl`
- Run started: 2026-08-15T00:49:34.929Z
- Model: `Laguna`
- Token budget: 4080
- Theoretical concurrency: 32

## Test curve

| Test | Shape | Cache | Concurrency | Total tokens/s | p95 TTFT | Max waiting | KV max |
|---|---|---|---:|---:|---:|---:|---:|
| T01 | 15:1 | cold | 1 | 4848.9 | 0.359s | n/a | n/a |
| T02 | 5:1 | cold | 1 | 2532.1 | 0.327s | n/a | n/a |
| T03 | 1:1 | cold | 1 | 1001.1 | 0.260s | 0 | 0.118 |
| T04 | 1:5 | cold | 1 | 641.8 | 0.127s | 0 | 0.121 |
| T05 | 1:1 | cold | 16 | 7550.1 | 3.931s | 1 | 0.186 |
| T06 | 1:1 | cold | 32 | 12746.2 | 3.601s | 6 | 0.168 |
| T07 | 1:1 | cold | 40 | 9273.2 | 12.529s | 9 | 0.288 |
| T08 | 15:1 | hot | 16 | 40494.7 | 0.914s | 0 | 0.164 |
| T09 | 15:1 | mixed | 16 | 20537.3 | 2.488s | 6 | 0.195 |
| T10 | 15:1 | cold | 16 | 14571.1 | 3.747s | 6 | 0.195 |

## Relationship checks

| Status | Expectation | Evidence |
|---|---|---|
| PASS | Complete T01-T10 suite | missing: none |
| PASS | All requests succeeded | request errors: 0 |
| PASS | Exact prompt-token budgets | token mismatches: 0 |
| PASS | T05 batching payoff | T05 7550.1 vs T03 1001.1 total tokens/s |
| FAIL | T05 controlled TTFT | T05 3.931s vs T03 0.260s |
| FAIL | T05 no queue | max waiting 1 |
| PASS | T05 no preemptions | preemptions 0 |
| PASS | T06 queue appears | max waiting 6 |
| FAIL | T06 throughput flattens | T06 12746.2 vs T05 7550.1 total tokens/s |
| PASS | T07 no throughput gain | T07 9273.2 vs T06 12746.2 total tokens/s |
| PASS | T07 TTFT worsens | T07 12.529s vs T06 3.601s |
| PASS | T07 queue does not improve | T07 9 vs T06 6 waiting |
| PASS | Prefix-cache TTFT ordering | hot 0.914s, mixed 2.488s, cold 3.747s |
| NOT OBSERVED | Prefix-cache hit ordering | hot n/a, mixed n/a, cold n/a |

## Operational classification

- T05 healthy: **no**
- T06 saturated: **no**
- T07 overloaded: **yes**

## Analyst notes

Treat `NOT OBSERVED` as missing evidence, not success. Review normalized JSON and raw logs before attributing failures to the model or hardware; short Prometheus windows and unrelated traffic can distort server-side metrics.
