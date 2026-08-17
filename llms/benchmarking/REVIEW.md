# Review: vLLM inference behavior benchmark

Reviewed 2026-08-17 against `plan.prd`, `benchmark.py`, `k8s/job.yaml`,
`grafana/vllm-behavior.json`, `skills/analyze-vllm-benchmark/`, and the saved run
`results/boyd-ref-20260815T004934Z-*`.

## Verdict

The PRD is the strongest artifact in the folder. It asks the right questions and
states expectations as relationships rather than absolute numbers, which is the
correct framing for a benchmark whose purpose is teaching rather than scoring.

The implementation did not yet produce the evidence those questions need. Six of
the ten tests in the saved run carry an entirely null Prometheus block, and the
single most impressive number in the run (T04 reporting a 0.98 prefix-cache hit
ratio on a cold-cache, single-session test) came from unrelated traffic on the
same cluster. The analyzer's own verdicts of "T05 healthy: no" and "T06
saturated: no" are measurement artifacts rather than facts about the hardware.

Everything below is ordered by how much it distorts the reader's conclusion.

---

## 1. Each test was a burst, not a concurrency level

`benchmark.py:438-442` submitted exactly `concurrency` requests, one time, and
measured wall clock until the last one returned. That is an open-loop burst of N
simultaneous arrivals rather than a sustained concurrency level.

Three consequences.

**TTFT measured arrival contention, not queueing.** T05's p95 TTFT of 3.93s
against a 0.26s baseline is what happens when sixteen prefills arrive in the same
millisecond and have to take turns. The PRD deferred burst traffic to phase 2
(§5), and then every test became a burst test by construction. The "T05
controlled TTFT" check could not pass on any hardware.

**Throughput folded in ramp-up and drain.** T05's final request decoded 2040
tokens with the GPU otherwise idle. At the compact budget the drain is a large
fraction of the whole test.

**Sample counts were far too low.** Test durations across the saved run:

| Test | Duration | Requests |
|---|---:|---:|
| T01 | 0.8s | 1 |
| T02 | 1.6s | 1 |
| T03 | 4.1s | 1 |
| T04 | 6.4s | 1 |
| T05 | 8.6s | 16 |
| T06 | 10.2s | 32 |
| T07 | 17.6s | 40 |
| T08 | 1.6s | 16 |
| T09 | 3.2s | 16 |
| T10 | 4.5s | 16 |

`p95_ttft_seconds` for T01 through T04 is one observation. At sixteen
observations p95 is just the maximum.

**Fix applied:** closed-loop generation. N workers each issue a new request as
soon as the previous returns, for a configured duration, with a ramp period
excluded and statistics computed only over requests that completed inside the
steady window.

## 2. Test windows were shorter than the Prometheus scrape interval

`BENCH_PROMETHEUS_SETTLE_SECONDS` defaults to 15, matching the scrape interval,
while tests ran 0.8s to 17.6s. `rate()` and `increase()` over a window holding
one or two samples return nothing at all, which is why T01, T02, T03, T08, T09
and T10 have no server-side data.

That matters because nearly everything the PRD cares about lives on the
Prometheus side: queue time, KV utilization, preemptions, the prefill/decode
split, and prefix-cache counters. The saved run cannot support most of the
claims the PRD wants to make.

The window arithmetic compounded it. `window_summary` was called with
`elapsed + settle*2` anchored at a timestamp taken after an additional sleep, so
the effective range was `[start - 15s, end + 15s]`. For cache-hot and mixed
tests that range includes the priming request issued deliberately outside the
measured window.

**Fix applied:** tests now run for a configured duration (default 120s) with a
minimum request count per worker, and Prometheus is queried with the range
anchored exactly on the steady window.

## 3. No label selector on any Prometheus query

`benchmark.py:213-235` and every panel in `grafana/vllm-behavior.json` summed
across every vLLM target Prometheus scrapes. Evidence from T04, a single-session
cold-cache test with 680 input tokens lasting 6.4 seconds:

| Metric | Reported | Client-observed |
|---|---:|---:|
| prompt tokens/sec | 22,459.6 | 107 |
| prefix cache hits | 154,201.6 | 0 expected |
| prefix cache hit ratio | 0.98 | ~0 expected |

Those are other tenants' requests. The DCGM panels have the same problem and
will show GPUs that are not serving the model under test.

**Fix applied:** `BENCH_METRIC_SELECTOR` is injected into every query, the
dashboard gained `namespace` / `model` / `pod` template variables, and DCGM
panels are filtered by node.

## 4. The KV-cache pressure story never ran

The unit-test fixture in `tests/test_benchmark.py:24` reflects the real cluster:
972,768 KV tokens. At a 4,080-token budget that is 238 theoretical sessions,
clamped to 32 by `BENCH_SCHEDULER_MAX_SEQS`. Peak observed KV utilization across
the whole suite was 0.288, and that was during the test labelled "overload."

So T06 and T07 demonstrated a scheduler queue filling at `max_num_seqs`. KV
pressure, preemption, and recomputation, all named as headline behaviors in the
PRD objective, were never exercised. A reader shown the current output would
draw a conclusion about KV capacity that the data does not support.

**Fix applied:** `theoretical_concurrency()` now reports both limits and which
one binds, and that appears in the report header and the analysis output. The
50,000-token budget is the configuration where KV binds first on this cluster,
and the README now says so explicitly.

## 5. T01 through T04 were collected and never analyzed

The shape story is the most teachable content in the PRD, and
`extract_and_analyze.py` checked nothing about it. There was no prefill-versus-decode
decomposition anywhere in the output, so the §1 expectations (prefill dominates
at 15:1, decode dominates at 1:5, roughly equal at 1:1) went unverified across
the entire pipeline.

The data was already in hand. Client-side, `decode ≈ e2e - ttft` per request is a
serviceable approximation, and vLLM's `request_prefill_time_seconds` /
`request_decode_time_seconds` give the authoritative split once windows are long
enough to sample.

**Fix applied:** per-request prefill/decode split and `prefill_share` in every
summary, plus explicit shape checks in the analyzer.

## 6. The results table invited a wrong conclusion

The analysis table placed T01 at 4,848 total tokens/s next to T04 at 641 total
tokens/s. A reader concludes the prefill-heavy shape is seven times faster. What
the numbers actually show is that prompt tokens and generated tokens cost wildly
different amounts of compute and should never be summed into one figure compared
across shapes.

**Fix applied:** prefill throughput and decode throughput are separate columns,
and cross-shape comparison is called out as invalid in the report itself.

## 7. The concurrency curve had too few points

Three loaded points on a single shape cannot show a knee. The most valuable chart
for the stated goal is throughput against concurrency with the inflection marked,
and the saved run has 1, 16, 32, 40 for the 1:1 shape.

`benchmark.py:64` also hard-required exactly four levels with the first equal to
1, which contradicts how `BENCH_CONCURRENCY_LEVELS` is described in PRD §6 and
blocked any denser sweep.

**Fix applied:** an optional sweep dimension adds intermediate 1:1 points so the
curve has six or more samples.

## 8. There was no reader-facing output

The deliverable was a markdown table plus PASS/FAIL rows. For "show readers how
performance behaves," the artifacts that carry insight are charts:

- throughput against concurrency with the knee marked
- p95 TTFT against concurrency on the same axis
- prefill/decode stacked per shape
- TTFT against measured cache-hit ratio for T08/T09/T10

The Grafana dashboard has the same problem in a different form. A viewer sees one
continuous line with no indication of where T05 ends and T06 begins.

**Fix applied:** the analyzer emits a self-contained HTML report with inline SVG
charts, and a Grafana annotations file built from the recorded test windows.

## 9. T09 was contaminated by T08

`benchmark.py:320` built the shared corpus from the same literal string for every
test, so by the time the mixed-cache test ran, its shared half was already
resident from the hot test. The measured mixed benefit was inflated.

**Fix applied:** the shared corpus is salted per test id.

## 10. Metric names failed silently

`vllm:prefix_cache_queries_total` is `vllm:gpu_prefix_cache_queries_total` on
several vLLM builds. A missing metric name and an empty time window both produced
`None`, so the two conditions were indistinguishable in the output.

**Fix applied:** the runner probes `/metrics` at startup, resolves known aliases,
and reports which expected families are absent.

## 11. Inter-token latency was measured per SSE chunk, not per token

Found while rebuilding, and it invalidates every ITL number in the saved run.
`stream_completion` timestamped each streaming chunk and averaged the gaps
between them. vLLM packs several tokens into one chunk whenever the client falls
behind, so the average overstated ITL by the batch factor.

The saved run shows the contradiction plainly. T01 reports 255 output tokens, a
mean ITL of 0.0294s, and a total elapsed time of 0.84s. Those cannot all be true:
255 tokens at 29ms each is 7.4 seconds of decoding inside a 0.84-second request.
The real per-token figure was near 0.0033s, roughly nine times smaller, meaning
the stream was arriving about nine tokens per chunk.

**Fix applied:** ITL is now the decode span divided by the tokenizer's own
completion-token count, which is the standard definition and is indifferent to
how the stream was framed. The chunk count is recorded separately as
`stream_chunks`.

## 12. The PRD's 1:1 expectation cannot hold

PRD §1 and the T03 expectation both state that prefill time approximately equals
decode time for the balanced shape. That is false on any real accelerator, and no
amount of tuning will make it true.

Prefill processes the entire prompt in one parallel pass. Decode emits one token
per forward pass, sequentially. Measured on the saved run, prefill moved roughly
10,600 tokens/sec while decode moved roughly 580, a ratio near 18:1. So 2,040
input tokens cost about 0.19s of prefill while 2,040 output tokens cost about 3.5s
of decode. The balanced shape is around 95% decode time.

The interesting consequence: the 15:1 shape is close to *time*-balanced on this
hardware, not prefill-dominated. To be genuinely prefill-dominated in time you
need a ratio well past 20:1.

**Fix applied:** the analyzer no longer tests an impossible claim. It verifies
that the prefill share falls monotonically across the four shapes, verifies that
1:1 is decode-bound, and computes the input/output ratio at which prefill and
decode time actually balance on the hardware under test. That ratio is reported
as a headline caveat, and it is the number that makes every other shape result
legible.

## 13. Shared-prefix sizing could exceed the prompt

A latent bug the T01-T10 matrix never triggered. `prompts()` sized the shared
corpus at 90% of the input tokens and then appended a fixed 256-token unique
marker, so any cache-hot or mixed test on an input shorter than about 2,560
tokens produced a prompt longer than its own target and aborted the run. The
current suite only uses hot and mixed on the 15:1 shape, where the input is
3,825 tokens, so it stayed hidden. It surfaces immediately at a smaller budget or
if a cache dimension is ever added to the 1:1 shape.

**Fix applied:** the corpus is clamped to leave room for the marker and its
header, with a clear error when the budget is genuinely too small.

## 14. Smaller items

- **Client-side ceiling.** Blocking `urllib` on a thread per session is fine at
  40 concurrent. At several hundred the GIL will inflate TTFT measurements and
  the inflation reads as server saturation. The runner now warns above a
  threshold.
- **Job has no deadline.** `k8s/job.yaml` sets `backoffLimit: 0` but no
  `activeDeadlineSeconds`, against a 7200-second per-request timeout. Fixed.
- **Results are ephemeral.** Output lands in an emptyDir plus stdout, and
  `final_report` printed every individual request, so logs grow with run length
  and vanish with the pod. The final stdout report now omits per-request detail,
  which stays in the JSON file.
- **README accuracy.** "bencharmk", "uses  currently uses", and a `<redacte>`
  placeholder for a registry whose real account ID is committed in plain text at
  `k8s/job.yaml:19`. Text fixed. The account ID is left in place because changing
  it breaks the existing deploy path; scrubbing it is a call for the repo owner
  if this folder is ever published.

## What was already right

Verifying returned `prompt_tokens` against the target on every request, and
failing the run on mismatch, is better discipline than most published benchmarks
have. Placing the random marker at the head of the prompt is the correct
APC-defeating construction, and holding the marker's token count constant with a
cat/dog bit expansion is a nice touch. Warmup outside the measured window,
`ignore_eos` with a fixed seed, and zero runtime dependencies are all sound
choices that the rework preserves.

## Suggested reading order for the reworked output

1. `results/<run>-report.html` for the charts and the narrative.
2. `results/<run>-analysis.md` for the deterministic pass/fail checks.
3. `results/<run>-normalized.json` when a number needs to be traced.
