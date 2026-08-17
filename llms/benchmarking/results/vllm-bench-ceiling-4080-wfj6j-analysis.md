# vLLM benchmark analysis

- Source: `/Users/chris.boyd/gitrepos/Samples/llms/benchmarking/results/vllm-bench-ceiling-4080-wfj6j-raw.jsonl`
- Run started: 2026-08-17T16:25:03.091Z
- Model: `Laguna`
- Token budget: 4080
- Theoretical concurrency: 96 (bound by BENCH_MAX_CONCURRENCY)
- Metric selector: `namespace="poolside-models",model_name="Laguna"`

## Summary

- Throughput: total tokens per second went from 1,705 to 14,665 as concurrency increased from 1 to 96.
- Responsiveness: TTFT at p95 increased from 0.15s to 3.02s. End-to-end at p95 increased from 2.4s to 27s.
- Speed: per-user token rate dropped from 852 tok/s to 76 tok/s as concurrency increased.
- Prefill vs decode: prefill averaged 13,508 tok/s, decode averaged 900 tok/s. Decode speed is the bottleneck, and it is bound by memory bandwidth rather than by request count.
- Cache: at concurrency 32 on the 15:1 shape, a 79% prefix cache hit ratio cut p95 TTFT from 2.12s with no reuse to 1.60s with full reuse. ITL improved 5.1x over the same pair (0.0211s without reuse against 0.0042s with it).
- Tuned setting: concurrency 8 delivers 55% of peak throughput at 1.7x the single-session latency. Below it the GPU idles between requests; above it throughput gains cost progressively more latency, reaching 11.4x at concurrency 96 for 100% of peak.

### What to do about it

- The ceiling was not reached. Nothing degraded at concurrency 96, so treat that as a floor on capacity. To find the real limit, raise BENCH_MAX_CONCURRENCY in the Job, or raise BENCH_TOKEN_BUDGET so each request holds more KV cache. Exact values are in the next-run section below.
- Run at concurrency 8 unless you have a reason not to: 55% of peak throughput at 1.7x baseline latency. Going to 96 buys the remaining 45% and costs 11.4x baseline latency instead.
- Capacity ceiling is 7,333 generated tokens/sec across all users combined. Divide by the per-user rate your product needs to get a user count: about 244 users at 30 tok/s each, or 73 at 100 tok/s each. One user alone gets 900 tok/s, so per-user speed is what you trade away as you add users.

## What this configuration supports

Throughput ceiling: 7,333 generated tokens/sec. The curve is flat from concurrency 80 onward, so this is the limit of what this configuration produces at this context length. Adding concurrency past that point buys latency, not output.

Failure point: not reached. Nothing was preempted, throughput never fell, and latency never grew faster than the load. The configuration runs out of useful throughput well before it runs out of capacity, so it degrades gently rather than falling over.


A throughput number only becomes a user count once you say how fast each user needs their tokens:

| Concurrent users | Per-user rate | What that rate means |
|---:|---:|---|
| 238 | 30 tok/s | Reading pace. A person following along as it streams. Capped by KV cache at 238 before throughput runs out. |
| 73 | 100 tok/s | Comfortably faster than reading. Short replies feel immediate. |
| 24 | 300 tok/s | Agentic loops, where code consumes the output rather than a person. |
| 8 | 900 tok/s | One request at a time, no contention. The floor on how many you can serve. |

These counts assume every user is generating at once. Real traffic is bursty, so the number of people a deployment serves is higher than the number generating simultaneously.

## Test curve

| Test | Shape | Cache | Users | Reqs | Prompt tok/s | Gen tok/s | p50 first word | p95 first word | p95 full reply | Reading share | Peak waiting | KV max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| T01 | 15:1 | cold | 1 | 306 | 7329 | 489 | 0.235s | 0.240s | 0.5s | 0.451 | 0 | 0.03 |
| T02 | 5:1 | cold | 1 | 164 | 3482 | 696 | 0.216s | 0.218s | 1.0s | 0.221 | 0 | 0.02 |
| T03 | 1:1 | cold | 1 | 67 | 852 | 852 | 0.146s | 0.147s | 2.4s | 0.061 | 0 | 0.01 |
| T04 | 1:5 | cold | 1 | 42 | 178 | 890 | 0.084s | 0.085s | 3.8s | 0.022 | 0 | 0.01 |
| T05 | 1:1 | cold | 32 | 481 | 6485 | 6485 | 1.600s | 2.026s | 10.1s | 0.146 | 0 | 0.19 |
| T06 | 1:1 | cold | 65 | 498 | 6887 | 6887 | 2.023s | 2.782s | 19.9s | 0.099 | 1 | 0.36 |
| T07 | 1:1 | cold | 96 | 481 | 7333 | 7333 | 2.246s | 3.016s | 27.3s | 0.082 | 4 | 0.49 |
| T08 | 15:1 | hot | 32 | 2001 | 48220 | 3215 | 1.448s | 1.596s | 2.6s | 0.451 | 18 | 0.22 |
| T09 | 15:1 | mixed | 32 | 1009 | 24859 | 1657 | 1.110s | 1.977s | 5.5s | 0.241 | 5 | 0.20 |
| T10 | 15:1 | cold | 32 | 672 | 16771 | 1118 | 1.921s | 2.117s | 7.3s | 0.230 | 0 | 0.23 |
| S01 | 1:1 | cold | 8 | 313 | 4053 | 4053 | 0.600s | 0.811s | 4.0s | 0.139 | 0 | 0.06 |
| S02 | 1:1 | cold | 17 | 394 | 5290 | 5290 | 0.843s | 1.352s | 6.6s | 0.147 | 3 | 0.09 |
| S03 | 1:1 | cold | 24 | 433 | 5895 | 5895 | 1.049s | 1.473s | 8.3s | 0.129 | 1 | 0.14 |
| S04 | 1:1 | cold | 48 | 456 | 6549 | 6549 | 2.070s | 2.551s | 15.4s | 0.124 | 2 | 0.25 |
| S05 | 1:1 | cold | 80 | 481 | 7200 | 7200 | 2.183s | 2.971s | 23.3s | 0.091 | 2 | 0.42 |

Prompt tokens and generated tokens cost different amounts of compute. Compare each column within one shape, never across shapes.

## Relationship checks

| Status | Expectation | Evidence |
|---|---|---|
| PASS | Complete T01-T10 suite | missing: none |
| PASS | All requests succeeded | request errors: 0 |
| PASS | Exact prompt-token budgets | token mismatches: 0 |
| PASS | Steady measurement window in every test | unsteady: none |
| PASS | 1:5 is decode-dominated | T04 prefill share 0.02 |
| PASS | Prefill share falls as the shape tilts toward output | T01 0.451 > T02 0.221 > T03 0.061 > T04 0.022 |
| PASS | 1:1 is decode-bound despite equal token counts | T03 prefill share 0.061 |
| PASS | Batching pays off | peak throughput 14665 tokens/s at 96 concurrent, 8.6x the single-session baseline |
| PASS | Latency grows slower than load | 1: 1.0x TTFT at 1x load; 8: 5.5x TTFT at 8x load; 17: 9.2x TTFT at 17x load; 24: 10.0x TTFT at 24x load; 32: 13.8x TTFT at 32x load; 48: 17.3x TTFT at 48x load; 65: 18.9x TTFT at 65x load; 80: 20.2x TTFT at 80x load; 96: 20.5x TTFT at 96x load |
| PASS | Curve reaches diminishing returns | scaling efficiency falls to 0.09 of its initial value; tuned setting at 8 concurrent |
| FAIL | Curve reaches degradation | levels observed: capped, flat, linear, sub-linear; the run never degraded, so the ceiling was not found. Raise concurrency, raise BENCH_TOKEN_BUDGET, or accept that this configuration has no cliff |
| PASS | No preemptions below the tuned setting | preemptions at or below the tuned setting: 1:0, 8:0, 17:0 |
| PASS | Prefix-cache TTFT ordering | hot 1.596s, mixed 1.977s, cold 2.117s |
| PASS | Prefix-cache hit ordering | hot 0.787, mixed 0.394, cold 0.000 |
| PASS | Prefix cache does not slow decode | hot ITL 0.004s vs cold ITL 0.021s |

## Operational classification by concurrency

| Users | Total tok/s | % of peak | Scaling eff. | p95 TTFT | p95 E2E | Latency x | Per-user tok/s | State |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 1705 | 12% | 1.00 | 0.15s | 2.4s | 1.0x | 852 | **linear** |
| 8 * | 8106 | 55% | 0.59 | 0.81s | 4.0s | 1.7x | 507 | **sub-linear** |
| 17 | 10580 | 72% | 0.37 | 1.35s | 6.6s | 2.7x | 311 | **sub-linear** |
| 24 | 11791 | 80% | 0.29 | 1.47s | 8.3s | 3.5x | 246 | **flat** |
| 32 | 12970 | 88% | 0.24 | 2.03s | 10.1s | 4.2x | 203 | **flat** |
| 48 | 13098 | 89% | 0.16 | 2.55s | 15.4s | 6.4x | 136 | **flat** |
| 65 | 13774 | 94% | 0.12 | 2.78s | 19.9s | 8.3x | 106 | **flat** |
| 80 | 14400 | 98% | 0.11 | 2.97s | 23.3s | 9.7x | 90 | **capped** |
| 96 | 14665 | 100% | 0.09 | 3.02s | 27.3s | 11.4x | 76 | **capped** |

What the states mean:

- **linear** — Scaling efficiency 0.75 or better. Each added session buys at least 75% of what the first session delivered.
- **sub-linear** — Scaling efficiency 0.30 to 0.75. Still buying real throughput per session, but the server is now sharing capacity.
- **flat** — Scaling efficiency below 0.30. Added sessions mostly wait on each other; total throughput still creeps up but each session pays for it in latency.
- **capped** — Within 2% of the best throughput observed. Additional concurrency changes throughput by nothing measurable and only adds latency.
- **degraded** — Throughput fell below a lower concurrency, or the scheduler preempted sequences, or latency grew faster than the load did.

- Tuned setting: **8** concurrent sessions (where the scaling line crosses the throughput ceiling)
- Peak throughput at **96** concurrent, which costs more latency for the last increment

## Measurement caveats

- Reading a prompt runs at about 13,508 tokens/sec. Writing a reply runs at about 900. A prompt token therefore costs roughly 15 times less time than a generated token. That is why a request with equal input and output is almost entirely generation time, and why the two only balance out near a 15:1 input-to-output ratio.
- Prompt reuse sped up generation itself by 5.1x (0.0042s per token against 0.0211s). Reuse is normally described as saving only the time spent reading the prompt. Under load it saves more than that, because reading and writing share the same passes through the model, so removing reading work leaves more of each pass for writing. Prompt reuse is a throughput lever here, not only a first-token lever.
- Tuned setting is concurrency 8, where this run's linear-scaling line crosses its maximum-throughput line: peak rate 3.59 requests/sec times minimum latency 2.40s gives 8.6. It delivers 55% of peak throughput at 1.7x single-session latency.

## What to run next

- Nothing degraded at concurrency 96, so this run found a floor on capacity rather than a ceiling. Either push concurrency until it breaks, or change the workload so the limit is reachable.
- Concurrency 192 is past what a single pod can drive without the load generator adding to measured latency. Split it across replicas: run the same manifest three times at a third of the count each and sum the throughput.
- Memory never bound because each context was small. KV cache holds 972,784 tokens, so at 4,080 per request it takes about 238 concurrent sessions to fill. Raising context length gets there far sooner than raising concurrency.

Edit these values in `k8s/job.yaml` and create it again:

```yaml
            - name: BENCH_MAX_CONCURRENCY
              value: "192"
            - name: BENCH_CONCURRENCY_LEVELS
              value: "1,0.33,0.67,1.0"
            - name: BENCH_SWEEP_LEVELS
              value: "0.08,0.17,0.25,0.5,0.83"
```

To test the memory limit instead, change one value and rerun: `BENCH_TOKEN_BUDGET=50000`. Raise `BENCH_TEST_DURATION_SECONDS` to 420 and drop `BENCH_MIN_REQUESTS_PER_WORKER` to 1, because each request takes far longer at that size.

## Appendix: what each test ran

| Test | Workload | Sessions | Prompt reuse | Purpose |
|---|---|---:|---|---|
| T01 | 3,825 in / 255 out (15:1) | 1 | every prompt unique | Latency floor for a prompt-dominated request. Nothing else is running. |
| T02 | 3,400 in / 680 out (5:1) | 1 | every prompt unique | Latency floor when the prompt is large but the reply is meaningful. |
| T03 | 2,040 in / 2,040 out (1:1) | 1 | every prompt unique | Latency floor for equal input and output. This is the reference the whole concurrency curve is measured against. |
| T04 | 680 in / 3,400 out (1:5) | 1 | every prompt unique | Latency floor for a short prompt and a long reply. |
| T05 | 2,040 in / 2,040 out (1:1) | 32 | every prompt unique | First loaded point on the concurrency curve. |
| T06 | 2,040 in / 2,040 out (1:1) | 65 | every prompt unique | Higher load on the same shape. |
| T07 | 2,040 in / 2,040 out (1:1) | 96 | every prompt unique | Highest load on the same shape, chosen to push past the useful limit. |
| T08 | 3,825 in / 255 out (15:1) | 32 | all prompts share a long opening | Best case for prompt reuse: every request shares a large identical opening. |
| T09 | 3,825 in / 255 out (15:1) | 32 | half share that opening | Half the requests share that opening, half are unique. |
| T10 | 3,825 in / 255 out (15:1) | 32 | every prompt unique | No request shares anything. The comparison point for the two above. |
| S01 | 2,040 in / 2,040 out (1:1) | 8 | every prompt unique | Extra point on the concurrency curve, so the shape of the curve is visible rather than inferred from four readings. |
| S02 | 2,040 in / 2,040 out (1:1) | 17 | every prompt unique | Extra point on the concurrency curve, so the shape of the curve is visible rather than inferred from four readings. |
| S03 | 2,040 in / 2,040 out (1:1) | 24 | every prompt unique | Extra point on the concurrency curve, so the shape of the curve is visible rather than inferred from four readings. |
| S04 | 2,040 in / 2,040 out (1:1) | 48 | every prompt unique | Extra point on the concurrency curve, so the shape of the curve is visible rather than inferred from four readings. |
| S05 | 2,040 in / 2,040 out (1:1) | 80 | every prompt unique | Extra point on the concurrency curve, so the shape of the curve is visible rather than inferred from four readings. |

### Terms

- **Prefill** — Processing the prompt. The whole prompt goes through the model at once, so it is fast per token.
- **Decode** — Generating the reply. One token per pass through the model, so it is slow per token.
- **TTFT** — Time to first token. How long a user waits before anything appears.
- **ITL** — Inter-token latency. The gap between output tokens once generation starts, which is how fast the reply streams.
- **Steady window** — The stretch of each test where every worker was busy. Ramp-up and drain are excluded so the numbers reflect sustained load.
- **Scaling efficiency** — X(N) divided by N times X(1): the share of ideal linear scaling still being achieved at concurrency N. 1.00 is perfect, 0.10 means ninety percent of the theoretical gain is lost to contention.
- **Tuned setting** — Where the two straight lines through this run's own curve cross: the linear-scaling line from the origin, and the flat line at maximum throughput. Below it the GPU idles between requests; above it throughput gains cost progressively more latency.
- **Latency multiple** — End-to-end p95 at concurrency N divided by end-to-end p95 at concurrency 1. What a user pays for the extra throughput.

## Analyst notes

`NOT OBSERVED` means the evidence is missing, not that the check passed. Read the normalized JSON and the raw log before blaming the model or the hardware.
