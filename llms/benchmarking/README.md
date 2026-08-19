# vLLM inference behavior benchmark

A benchmark suite built as one dependency-free Python runner, a Kubernetes Job, a Grafana dashboard, and an analysis skill that turns a run into charts.

The suite generates deterministic load against an existing vLLM endpoint and shows how inference behaves as workload shape, concurrency, and prefix-cache state change. It does not benchmark the cluster and it does not provision vLLM.

Prompts are sized with the endpoint's own tokenizer, every request's returned prompt count is verified against the target, and a run fails rather than reporting numbers built on the wrong token counts.

## How load is generated

Each test is closed-loop. It holds `concurrency` workers in flight, and each worker issues a new request the moment its previous one returns, for `BENCH_TEST_DURATION_SECONDS`. That distinction matters: firing N requests once and timing them measures a burst, and a burst's TTFT is dominated by simultaneous arrivals rather than by queueing.

Statistics come from a **steady window**, the interval during which every worker was continuously busy. The first `BENCH_RAMP_SECONDS` are dropped, and so is the drain after the first worker stops. Throughput is tokens divided by that window, not by the whole test.

`steady_window_valid: false` on a test means its requests outlived the window, so its numbers include ramp and drain. Read that as a signal to raise the duration.

## Run locally

The endpoint must be reachable from the machine running the command.

```sh
export BENCH_VLLM_ENDPOINT=http://localhost:8080
export BENCH_API_KEY=...
python3 benchmark.py
```

Run unit tests with `make test`.

## Build for the cluster

The Dockerfile and Makefile force `linux/amd64`.

```sh
make build IMAGE=REGISTRY/vllm-behavior-benchmark:TAG
docker push REGISTRY/vllm-behavior-benchmark:TAG
```

Validate and run the Job:

```sh
make validate
KUBECONFIG=$HOME/.kube/contexts/boyd-ref kubectl create -f k8s/job.yaml
KUBECONFIG=$HOME/.kube/contexts/boyd-ref kubectl -n poolside-models logs -f -l app.kubernetes.io/name=vllm-behavior-benchmark
```

A full suite is twelve tests, so a default run takes roughly 45 minutes at the compact budget. The Job carries `activeDeadlineSeconds: 14400`.

The runner prints a per-test JSON line as each test finishes and a `final_report` object at the end, both without per-request detail so the log stays readable. Full per-request data lands in `BENCH_RESULTS_PATH`. Save the log with:

```sh
KUBECONFIG=$HOME/.kube/contexts/boyd-ref kubectl -n poolside-models logs -l app.kubernetes.io/name=vllm-behavior-benchmark > results.jsonl
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `BENCH_VLLM_ENDPOINT` | required | Base URL of the vLLM instance under test. |
| `BENCH_TOKEN_BUDGET` | `4080` | Total tokens per session. Shapes derive from it by fixed ratios. |
| `BENCH_CONCURRENCY_LEVELS` | `1,0.5,1.0,1.25` | Baseline, moderate, saturation, overload as fractions of theoretical concurrency. Exactly four values, first must be `1`. |
| `BENCH_SWEEP_LEVELS` | `0.25,0.75` | Extra balanced-shape points so the throughput curve shows its knee. Empty string disables. |
| `BENCH_TOKEN_MAX` | auto | KV token pool, in tokens. Concurrency is this divided by `BENCH_TOKEN_BUDGET`. Defaults to what `vllm:cache_config_info` reports; pin it to the engine's `GPU KV cache size` log line, which is smaller. |
| `BENCH_MAX_CONCURRENCY` | auto | Overrides the ceiling in sessions, bypassing the token division. Use it for a client-side cap, not for KV. |
| `BENCH_SCHEDULER_MAX_SEQS` | unset | Caps the KV-derived ceiling at vLLM's `max_num_seqs`. boyd-ref now serves with `192`. |
| `BENCH_TEST_DURATION_SECONDS` | `120` | Closed-loop duration per test. |
| `BENCH_RAMP_SECONDS` | `15` | Excluded from the front of every measurement window. |
| `BENCH_MIN_REQUESTS_PER_WORKER` | `2` | Extends a test until each worker has completed this many, so slow decode-heavy shapes still get samples. |
| `BENCH_TEST_MAX_SECONDS` | `900` | Hard stop per test. |
| `BENCH_PROMETHEUS_URL` | unset | Prometheus query endpoint. Without it the run still completes and records windows. |
| `BENCH_METRIC_SELECTOR` | unset | **Label selector applied to every Prometheus query**, for example `namespace="poolside-models",model_name="Laguna"`. |
| `BENCH_PROMETHEUS_SETTLE_SECONDS` | `15` | Scrape interval. One scrape must land after a window closes before its counters are queryable. |
| `BENCH_PROMPT_SALT` | run timestamp | Mixed into every generated prompt. Defaults to the run's start time so consecutive Jobs send different text and a cold-cache test cannot hit blocks a previous run left resident. Pin it to compare runs byte-for-byte. |
| `BENCH_API_KEY` | unset | Bearer token for protected endpoints. |
| `BENCH_MODEL` | discovered | Served model name; otherwise read from `/v1/models`. |
| `BENCH_REQUEST_TIMEOUT` | `7200` | Per-request timeout in seconds. |
| `BENCH_RESULTS_PATH` | `/results/results.json` | JSON output path. |

### Set `BENCH_METRIC_SELECTOR`

Without it, every query sums all vLLM targets Prometheus scrapes. On a shared cluster that means another tenant's traffic appears in your results, and it does so silently. The runner warns when the selector is unset.

### Concurrency is bounded by whichever limit binds first

The ceiling is a division: KV token pool over `BENCH_TOKEN_BUDGET`, then capped by `BENCH_SCHEDULER_MAX_SEQS`. Nothing here is a user count, so the same `BENCH_CONCURRENCY_LEVELS` fractions mean the same KV pressure whether a session is 4k tokens or 50k.

The pool comes from `BENCH_TOKEN_MAX` when set, otherwise from `block_size x num_gpu_blocks` in `vllm:cache_config_info`. Those two disagree. On boyd-ref the metric reports 1,303,120 tokens while the engine logs `GPU KV cache size: 1,184,878 tokens`, 10% lower, and the engine's number is the one the scheduler manages. Read it out of the startup log and pin it:

```bash
kubectl logs -n poolside-models deploy/inference-laguna-s -c inference \
  | grep "GPU KV cache size"
export BENCH_TOKEN_MAX=1184878   # 23 sessions at BENCH_TOKEN_BUDGET=50000
```

Past 5% apart the runner warns on stderr rather than picking for you. The report records the pool, its source, and which limit binds:

```json
"concurrency_constraint": {
  "kv_cache_tokens": 1184878, "kv_cache_tokens_source": "BENCH_TOKEN_MAX",
  "kv_cache_tokens_reported": 1303120, "kv_limit": 23, "max_num_seqs": 192,
  "binding": "kv_cache", "headroom_ratio": 1.0
}
```

A `headroom_ratio` well above 1 means the scheduler ran out of sequence slots long before KV filled, so that run demonstrates queueing and says nothing about KV pressure. To exercise KV, raise the budget: at `BENCH_TOKEN_BUDGET=50000` ten sessions consume roughly 125x the KV of ten compact sessions, and KV becomes the binding limit on most clusters. Confirm the model's context window holds each input plus output first.

### Client-side ceiling

Load is generated with one thread per session. Past roughly 64 concurrent the GIL starts adding to measured TTFT, and that inflation reads like server saturation. The runner warns when a planned level crosses that line; run multiple Job replicas instead of one large one.

## How prompts are built

Prompts are synthetic and built to make token counts exact rather than to look like real traffic.

Each request opens with a **marker**: the SHA-256 of a seed expanded bit by bit into 256 words of `cat` and `dog`. Same length every time, different first token every time, which is what defeats prefix-cache reuse when it needs defeating. The rest of the prompt is the word `benchmark` repeated until the endpoint's own tokenizer reports exactly the target count.

- **Cold** puts the marker first, so the prompt diverges at token zero and shares nothing with any other request.
- **Hot** puts a shared corpus first and the marker after it, so every request shares a long identical opening.
- **Mixed** alternates between the two.

Within a run, every request gets a unique marker. Across runs, the salt (`BENCH_PROMPT_SALT`, defaulting to the start timestamp) changes all of them; without it two consecutive Jobs would send byte-identical text and a cold-cache test could score hits on blocks left resident by the previous run.

The content is deliberately meaningless. Attention cost depends on sequence length rather than on what the tokens say, so timing is unaffected, but do not read these results as a claim about any particular real workload's content.

## Dashboard

Import `grafana/vllm-behavior.json`. It exposes **Namespace**, **Model**, and **GPU node** variables, and every panel is scoped by them. DCGM label names vary by exporter version, so swap `Hostname` for `kubernetes_node` in the GPU-node variable if it comes back empty.

Test windows show up as dashboard annotations once you post the run's annotation file:

```sh
jq -c '.[]' results/<run>-annotations.json | while read -r a; do
  curl -sS -XPOST "$GRAFANA/api/annotations" -H "Authorization: Bearer $GRAFANA_TOKEN" \
    -H 'Content-Type: application/json' -d "$a" > /dev/null
done
```

## Analyze results

The companion skill in `skills/analyze-vllm-benchmark` turns a finished Job into four artifacts:

| File | Contents |
|---|---|
| `<run>-report.html` | Self-contained page with the charts. Start here. |
| `<run>-analysis.md` | Deterministic relationship checks and the measurement caveats. |
| `<run>-normalized.json` | Full evidence for tracing any number. |
| `<run>-annotations.json` | Grafana annotations for the test windows. |

Install the skill into your agents skills directory and ask:

```text
Use analyze-vllm-benchmark to extract and analyze the latest completed benchmark Job in boyd-ref.
```

The skill is read-only against Kubernetes. It selects the newest successful Job by label and writes into `results/`. It also runs standalone:

```sh
python3 skills/analyze-vllm-benchmark/scripts/extract_and_analyze.py \
  --job vllm-behavior-benchmark-abc12 \
  --kubeconfig "$HOME/.kube/contexts/boyd-ref" \
  --output-dir ./results

python3 skills/analyze-vllm-benchmark/scripts/extract_and_analyze.py \
  --input ./results/run.jsonl \
  --output-dir ./results
```

## Reading the results

Two habits keep the conclusions honest.

**Never sum prompt and generated tokens across shapes.** A prompt token and a generated token cost wildly different amounts of compute, so a 15:1 shape will always post a bigger "total tokens/sec" than a 1:5 shape without being faster in any sense a user would recognize. The report keeps them in separate columns for this reason.

**Equal token counts are not equal time.** Prefill processes the whole prompt in parallel; decode emits one token at a time. On typical hardware prefill runs 15x to 30x faster per token, so the 1:1 shape is almost entirely decode time. The analysis computes the input/output ratio at which the two actually balance and reports it as a caveat. That number, not the 1:1 shape, is what makes the other shape results legible.

`plan.prd` holds the original requirements. `REVIEW.md` records where the implementation and the PRD disagreed and how each was resolved.
