# vLLM inference behavior benchmark

This directory implements a bencharmk suite as one dependency-free Python runner, a Kubernetes Job, and a Grafana dashboard. Prompts are sized with the endpoint's tokenizer (or its completion usage fallback), each request's returned prompt count is verified, and results are emitted as JSON plus concise JSON-lines logs.

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

The current test job uses  currently uses `<redacte>/vllm-benchmark_boyd:latest`. Validate and run it with:

```sh
make validate
KUBECONFIG=$HOME/.kube/contexts/boyd-ref kubectl create -f k8s/job.yaml
KUBECONFIG=$HOME/.kube/contexts/boyd-ref kubectl -n poolside-models logs -f -l app.kubernetes.io/name=vllm-behavior-benchmark
```

The runner prints a `final_report` JSON object to stdout so results remain available after the container exits. Save the JSON-lines log with:

```sh
KUBECONFIG=$HOME/.kube/contexts/boyd-ref kubectl -n poolside-models logs -l app.kubernetes.io/name=vllm-behavior-benchmark > results.jsonl
```

## Configuration

The PRD variables are supported. These optional operational variables are also available:

| Variable | Purpose |
|---|---|
| `BENCH_API_KEY` | Bearer token used by protected vLLM endpoints. |
| `BENCH_MODEL` | Served model name; otherwise discovered through `/v1/models`. |
| `BENCH_SCHEDULER_MAX_SEQS` | Caps detected KV-based concurrency to vLLM's `max_num_seqs`. Set to `32` for boyd-ref. |
| `BENCH_REQUEST_TIMEOUT` | Per-request timeout in seconds; default `7200`. |
| `BENCH_RESULTS_PATH` | JSON output path; default `/results/results.json`. |
| `BENCH_PROMETHEUS_SETTLE_SECONDS` | Expected scrape interval used to isolate short test windows; default `15`. |

Auto-detection reads `block_size` and `num_gpu_blocks` from `vllm:cache_config_info`. `BENCH_MAX_CONCURRENCY` still takes precedence. For a 50,000-token agentic run, set `BENCH_TOKEN_BUDGET=50000`; verify the model's maximum context can hold each input plus output first.

Import `grafana/vllm-behavior.json` into the existing Grafana instance. The dashboard uses the existing Prometheus datasource and exposes vLLM latency, queue, KV/cache, token throughput, and DCGM GPU signals.

## Analyze results with a skill

The companion skill in `skills/analyze-vllm-benchmark` implements the second half of the workflow:

1. Create the benchmark Job and wait for it to complete.
2. Ask your agent to use `analyze-vllm-benchmark` to extract and summarize the latest run.

Install the versioned skill into your agents skills directory, then start a new  task and use a prompt such as:

```text
Use analyze-vllm-benchmark to extract and analyze the latest completed benchmark Job in boyd-ref.
```

The skill is read-only against Kubernetes. It selects the newest successful Job by label and writes raw logs, normalized JSON, and a Markdown analysis into `results/`. It can also analyze a specific Job or an already-downloaded file:

```sh
python3 skills/analyze-vllm-benchmark/scripts/extract_and_analyze.py \
  --job vllm-behavior-benchmark-abc12 \
  --kubeconfig "$HOME/.kube/contexts/boyd-ref" \
  --output-dir ./results

python3 skills/analyze-vllm-benchmark/scripts/extract_and_analyze.py \
  --input ./results/run.jsonl \
  --output-dir ./results
```
