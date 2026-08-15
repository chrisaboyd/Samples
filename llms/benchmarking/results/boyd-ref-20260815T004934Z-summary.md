# boyd-ref compact-suite quick pass

- Run window: 2026-08-15 00:49:34Z–00:50:52Z
- Model: `Laguna`
- Token budget: 4,080
- Derived concurrency: 32 (scheduler-capped)
- Requests: 154 succeeded, 0 failed, 0 prompt-token mismatches

| Test | Cache | Concurrency | Total throughput (tokens/s) | p95 TTFT (s) | p95 client ITL (s) |
|---|---:|---:|---:|---:|---:|
| T01 | cold | 1 | 4,849 | 0.359 | 0.029 |
| T02 | cold | 1 | 2,532 | 0.327 | 0.030 |
| T03 | cold | 1 | 1,001 | 0.260 | 0.030 |
| T04 | cold | 1 | 642 | 0.127 | 0.029 |
| T05 | cold | 16 | 7,550 | 3.931 | 0.064 |
| T06 | cold | 32 | 12,746 | 3.601 | 0.075 |
| T07 | cold | 40 | 9,273 | 12.529 | 0.082 |
| T08 | hot | 16 | 40,495 | 0.914 | 0.085 |
| T09 | mixed | 16 | 20,537 | 2.488 | 0.174 |
| T10 | cold | 16 | 14,571 | 3.747 | 0.245 |

## Initial observations

- T05 gained 7.5x total throughput over the balanced single-session T03 baseline, but its p95 TTFT was about 15x baseline. Concurrency 16 is therefore not a latency-healthy point for this workload even though batching pays off.
- T06 reached 32 running requests and a nonzero queue. Throughput still increased over T05, so 32 is scheduler saturation but not the measured throughput peak.
- T07 reduced throughput by about 27% versus T06 and raised p95 TTFT to 12.5 seconds, clearly demonstrating overload. No preemptions occurred; the scheduler queue was the limiting signal.
- Prefix-cache ordering was clear: hot T08 < mixed T09 < cold T10 for p95 TTFT, while throughput ordered in the opposite direction as expected.

The embedded Prometheus summaries for this quick pass are incomplete for tests shorter than the scrape interval. Client-side measurements and token validation are valid. The subsequent harness revision adds quiet pre/post scrape windows and logs the complete final report.
