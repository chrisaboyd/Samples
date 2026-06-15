# Example: trace direct-to-inference calls (no LiteLLM)

`direct_trace.py` traces a call made straight to an OpenAI-compatible inference endpoint,
with LiteLLM out of the path. It uses the Langfuse `@observe(as_type="generation")` decorator
plus `update_current_generation`, so it works for any HTTP client (here, plain `requests`)
rather than only the OpenAI SDK.

This is the manual counterpart to the OpenAI SDK wrapper described in the top-level README.
Reach for this pattern when you call the endpoint with something other than the OpenAI SDK,
or when you want explicit control over what gets recorded on the generation.

## How it works

The decorator opens a generation observation for the duration of `call_model`. The first
`update_current_generation` records the request (model, input messages, metadata) before the
call; the second records the response (output text and token usage) after it returns. Langfuse
sends spans asynchronously, so the script calls `langfuse.flush()` before exiting.

The endpoint's OpenAI-style `usage` block is mapped onto Langfuse's `usage_details`:

| OpenAI usage field | Langfuse usage_details key |
| --- | --- |
| `prompt_tokens` | `input` |
| `completion_tokens` | `output` |
| `total_tokens` | `total` |

Note: Langfuse SDK v3/v4 uses `usage_details`. The older `usage=` keyword from v2 examples
raises `TypeError` on the current SDK.

## Prerequisites

- `pip install "langfuse>=3" requests`
- A reachable inference endpoint. On this cluster that is the vLLM server `inference-laguna`
  in the `poolside-models` namespace, which serves model `LagunaXS` and needs no auth. It is
  a ClusterIP with no ingress, so reach it from inside the cluster via its service DNS, or
  from a laptop via `kubectl port-forward`.
- Langfuse project keys (reuse the `litellm-langfuse` secret, or mint a fresh pair in the UI).

## Environment variables

| Variable | Purpose |
| --- | --- |
| `POOLSIDE_STANDALONE_BASE_URL` | OpenAI-style base URL, e.g. `http://localhost:8080/v1`. Must include `/v1`. |
| `POOLSIDE_STANDALONE_MODEL` | Model id served by the endpoint, e.g. `LagunaXS`. |
| `POOLSIDE_API_KEY` | Bearer token. Any value works for the unauthenticated laguna endpoint. |
| `LANGFUSE_HOST` | Langfuse URL, e.g. `https://langfuse.poolsi.de` or `http://localhost:3001`. |
| `LANGFUSE_PUBLIC_KEY` | `pk-lf-...` |
| `LANGFUSE_SECRET_KEY` | `sk-lf-...` |

## Run it

From a laptop, port-forward both the inference endpoint and Langfuse, then run:

```bash
kubectl port-forward -n poolside-models svc/inference-laguna 8080:80 &
kubectl port-forward -n litellm svc/langfuse-web 3001:3000 &

export POOLSIDE_STANDALONE_BASE_URL="http://localhost:8080/v1"
export POOLSIDE_STANDALONE_MODEL="LagunaXS"
export POOLSIDE_API_KEY="not-needed"
export LANGFUSE_HOST="http://localhost:3001"
export LANGFUSE_PUBLIC_KEY=$(kubectl get secret litellm-langfuse -n litellm -o jsonpath='{.data.LANGFUSE_PUBLIC_KEY}' | base64 -d)
export LANGFUSE_SECRET_KEY=$(kubectl get secret litellm-langfuse -n litellm -o jsonpath='{.data.LANGFUSE_SECRET_KEY}' | base64 -d)

python direct_trace.py
```

Running inside the cluster instead, drop the port-forwards and use the service DNS:
`POOLSIDE_STANDALONE_BASE_URL=http://inference-laguna.poolside-models.svc.cluster.local/v1`
and `LANGFUSE_HOST=http://langfuse-web.litellm.svc.cluster.local:3000`.

A successful run prints the model reply and the usage block, and a generation named
`direct-openai-compatible-call` appears in the `litellm-proxy` project with the input, output,
model, and token counts. This was verified end to end against the cluster.

## Gotchas

- TLS: laguna is plain HTTP, so no cert handling is needed. If you point this at an HTTPS
  endpoint with a self-signed cert (for example the LiteLLM ingress), `requests` will reject
  it; add `verify=<ca-bundle-path>` or `verify=False` to the `requests.post` call.
- Pointing `POOLSIDE_STANDALONE_BASE_URL` at the LiteLLM proxy (`combine-llm.poolsi.de`)
  instead of the inference endpoint means the call goes through LiteLLM, which also traces it
  via its own callback, so you would get two overlapping traces.
- Flush before exit. Without `langfuse.flush()`, a short script can terminate before the
  trace is sent and nothing shows up.
