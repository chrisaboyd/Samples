# LiteLLM Observability with Langfuse on EKS

This folder is a complete, reproducible tutorial for adding an observability layer to an
existing LiteLLM proxy running on Kubernetes. It deploys [Langfuse](https://langfuse.com)
(self-hosted, v3) with Helm into the same `litellm` namespace, then wires LiteLLM to emit a
trace for every request so you get prompt/response capture, token usage, latency, and cost
in a browser UI.

Everything here was deployed and verified against a live EKS cluster
(`poolside-c2e-march`, us-east-2). The end state is six Langfuse pods alongside LiteLLM, a
seeded project with API keys, and LiteLLM forwarding traces over the in-cluster network.

## What gets deployed

Langfuse v3 is not a single container; it is a small distributed system. The official Helm
chart bundles every dependency, so a single `helm install` brings up:

- `langfuse-web` - the Next.js UI and public API
- `langfuse-worker` - asynchronous trace ingestion
- `langfuse-postgresql` - transactional store (projects, users, prompts)
- `langfuse-clickhouse` - columnar store for traces and observations
- `langfuse-redis` (Valkey) - queue and cache
- `langfuse-s3` (MinIO) - blob storage for event, media, and export payloads

```
                 ┌──────────────────────────── litellm namespace ───────────────────────────┐
                 │                                                                            │
  client ──► litellm proxy ──(success_callback: langfuse, over ClusterIP)──► langfuse-web    │
                 │                                                              │             │
                 │                                                         langfuse-worker    │
                 │                                              ┌───────────────┼──────────┐  │
                 │                                          postgresql      clickhouse   minio│
                 │                                                          + redis/valkey    │
                 └────────────────────────────────────────────────────────────────────────┘
  browser ──(https://langfuse.poolsi.de via nginx ingress)──► langfuse-web
```

## Prerequisites

Know these before you start.

1. A running LiteLLM proxy in a namespace you control. This guide reuses the `litellm`
   namespace and the LiteLLM Helm release already installed there. You need the LiteLLM
   chart available locally to re-run `helm upgrade` against it.
2. `kubectl` and `helm` (v3.8+, OCI support) pointed at the target cluster. Confirm with
   `kubectl config current-context`. This was built against context
   `arn:aws:eks:us-east-2:992382466748:cluster/poolside-c2e-march`.
3. A StorageClass for the four stateful components. This cluster only has `gp2` (EBS) and it
   is not marked default, so `values.yaml` pins `gp2` explicitly via
   `global.defaultStorageClass`. If your cluster uses a different class, change that one
   line.
4. An ingress controller if you want a browser URL. This cluster runs `ingress-nginx`
   (ingress class `nginx`) fronted by an AWS ELB. The chart's ingress is enabled for host
   `langfuse.poolsi.de`.
5. DNS control for the host you expose. You must point `langfuse.poolsi.de` at the nginx
   ELB (see step 6). Until that record exists you can still reach the UI by port-forward.
6. A TLS certificate. LiteLLM here uses a self-signed cert, so this guide mints a matching
   self-signed cert for Langfuse. Swap in a real cert (or cert-manager) for anything beyond
   a demo.
7. `openssl` and `uuidgen` locally for generating secrets and API keys.
8. Capacity. The single-node profile here requests roughly 1.5 vCPU / 5 GiB across the
   stack and provisions about 58 GiB of EBS (10 + 8 + 20 + 20). The cluster had ample
   headroom; check yours with `kubectl describe node`.

A note on the bundled datastore images: Bitnami moved their free image tags to the
`bitnamilegacy/*` repositories after their 2025 registry change. Chart 1.5.34 already points
at those, and `global.security.allowInsecureImages: true` (set in `values.yaml`) permits
them. If you pin an older chart you may hit `ImagePullBackOff` on the datastores.

## Files in this folder

| File | Purpose | Committed |
| --- | --- | --- |
| `values.yaml` | Langfuse Helm values: single-node datastores, gp2 storage, nginx ingress, headless init. No secrets. | yes |
| `values-secret.example.yaml` | Template showing the secret keys you must provide. | yes |
| `values-secret.yaml` | Real generated secrets for the bundled datastores and Langfuse. | no (gitignored) |
| `litellm-langfuse-values.yaml` | Overlay that adds the `langfuse` success callback and env to the LiteLLM release. | yes |
| `examples/` | Runnable example for tracing a direct-to-inference call without LiteLLM, with its own README. | yes |

## Deploy, step by step

All commands assume the `litellm` namespace and the current kube context.

### 1. Add the Helm repo

```bash
helm repo add langfuse https://langfuse.github.io/langfuse-k8s
helm repo update langfuse
```

### 2. Generate the datastore and app secrets

These never go in git. Generate them straight into `values-secret.yaml`:

```bash
cd langfuse-observability
umask 077
cat > values-secret.yaml <<EOF
langfuse:
  salt:
    value: "$(openssl rand -base64 32)"
  nextauth:
    secret:
      value: "$(openssl rand -base64 32)"
  encryptionKey:
    value: "$(openssl rand -hex 32)"
postgresql:
  auth:
    password: "$(openssl rand -hex 16)"
redis:
  auth:
    password: "$(openssl rand -hex 16)"
clickhouse:
  auth:
    password: "$(openssl rand -hex 16)"
s3:
  auth:
    rootPassword: "$(openssl rand -hex 16)"
EOF
```

The `encryptionKey` must be exactly 64 hex characters (256 bits). Do not rotate `salt` or
`encryptionKey` once data exists; it breaks decryption of stored rows.

### 3. Create the seed credentials for headless initialization

Instead of clicking through the sign-up screen, Langfuse can seed an org, project, admin
user, and a fixed API key pair on first boot. Generate the key pair and admin password and
store them in two secrets: one read by Langfuse on startup, one read by LiteLLM to
authenticate.

```bash
PK="pk-lf-$(uuidgen | tr 'A-Z' 'a-z')"
SK="sk-lf-$(uuidgen | tr 'A-Z' 'a-z')"
PW="$(openssl rand -hex 12)"

kubectl create secret generic langfuse-init -n litellm \
  --from-literal=LANGFUSE_INIT_PROJECT_PUBLIC_KEY="$PK" \
  --from-literal=LANGFUSE_INIT_PROJECT_SECRET_KEY="$SK" \
  --from-literal=LANGFUSE_INIT_USER_PASSWORD="$PW"

kubectl create secret generic litellm-langfuse -n litellm \
  --from-literal=LANGFUSE_PUBLIC_KEY="$PK" \
  --from-literal=LANGFUSE_SECRET_KEY="$SK"

echo "Admin login: admin@poolsi.de"
echo "Admin password: $PW   (also in the langfuse-init secret)"
```

The non-secret init values (org id/name, project id/name, admin email and display name) live
in plain sight in `values.yaml` under `langfuse.additionalEnv`. The org is
`LiteLLM Observability` and the project is `litellm-proxy`.

### 4. Create the TLS secret

Self-signed, matching the LiteLLM setup. Replace with a real cert for production.

```bash
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout tls.key -out tls.crt \
  -subj "/O=langfuse/CN=langfuse.poolsi.de" \
  -addext "subjectAltName=DNS:langfuse.poolsi.de"

kubectl create secret tls langfuse-tls -n litellm --cert=tls.crt --key=tls.key
rm -f tls.key tls.crt
```

### 5. Install Langfuse

```bash
helm upgrade --install langfuse langfuse/langfuse --version 1.5.34 \
  --namespace litellm \
  -f values.yaml -f values-secret.yaml \
  --timeout 15m
```

Watch the pods. The datastores come up first; `langfuse-web` runs database migrations on
startup and may restart once before going ready.

```bash
kubectl get pods -n litellm -l app.kubernetes.io/instance=langfuse -w
```

Confirm health once `langfuse-web` is ready:

```bash
kubectl port-forward -n litellm svc/langfuse-web 3001:3000 &
curl -s localhost:3001/api/public/ready    # {"status":"OK", ...}
```

Verify the headless init created the project and the keys work:

```bash
PK=$(kubectl get secret litellm-langfuse -n litellm -o jsonpath='{.data.LANGFUSE_PUBLIC_KEY}' | base64 -d)
SK=$(kubectl get secret litellm-langfuse -n litellm -o jsonpath='{.data.LANGFUSE_SECRET_KEY}' | base64 -d)
curl -s -u "$PK:$SK" localhost:3001/api/public/projects
# {"data":[{"id":"litellm-proxy","name":"litellm-proxy","organization":{...}}]}
```

### 6. Point DNS at the ingress

Find the nginx ELB and create a DNS record for `langfuse.poolsi.de` that targets it. It is
the same ELB that already serves `combine-llm.poolsi.de`, so a CNAME (or an alias A record
in Route 53) to that hostname is all you need.

```bash
kubectl get ingress langfuse -n litellm \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
# afb05d15a4876419da6a1b86b86060a5-19d4b33ae5871027.elb.us-east-2.amazonaws.com
```

You can confirm the ingress works before DNS propagates by overriding the host:

```bash
ELB=$(kubectl get ingress langfuse -n litellm -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -sk -H "Host: langfuse.poolsi.de" "https://$ELB/api/public/health" -o /dev/null -w "%{http_code}\n"
# 200
```

### 7. Wire LiteLLM to Langfuse

The overlay in `litellm-langfuse-values.yaml` adds `success_callback: ["langfuse"]` to the
proxy config, sets `LANGFUSE_HOST` to the in-cluster service, and injects the key pair from
the `litellm-langfuse` secret. It deep-merges with the chart defaults, so your existing
`model_list` is preserved.

```bash
helm upgrade litellm <path-to>/deploy/charts/litellm-helm \
  --namespace litellm \
  --reuse-values \
  -f litellm-langfuse-values.yaml

kubectl rollout status deploy/litellm -n litellm
```

`LANGFUSE_HOST` is `http://langfuse-web.litellm.svc.cluster.local:3000`, so LiteLLM talks to
Langfuse over ClusterIP and never depends on DNS or the self-signed cert.

## Verify end to end

Make a real call through the proxy and confirm a trace lands in Langfuse.

```bash
MK=$(kubectl get secret litellm-masterkey -n litellm -o jsonpath='{.data.masterkey}' | base64 -d)
kubectl port-forward -n litellm svc/litellm 4000:4000 &

curl -s http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"model":"laguner","messages":[{"role":"user","content":"Reply with exactly: langfuse observability test ok"}],"max_tokens":40}'

# then query traces (worker ingests asynchronously, give it a few seconds)
kubectl port-forward -n litellm svc/langfuse-web 3001:3000 &
PK=$(kubectl get secret litellm-langfuse -n litellm -o jsonpath='{.data.LANGFUSE_PUBLIC_KEY}' | base64 -d)
SK=$(kubectl get secret litellm-langfuse -n litellm -o jsonpath='{.data.LANGFUSE_SECRET_KEY}' | base64 -d)
curl -s -u "$PK:$SK" "http://localhost:3001/api/public/traces?limit=5"
```

A successful run returns a trace named `litellm-acompletion` with your prompt as `input`,
the model reply as `output`, an `observations` entry, and a `latency`. That is the same data
you see in the UI.

## Access the UI

Once DNS resolves, open `https://langfuse.poolsi.de` (accept the self-signed cert warning)
and log in with the seeded admin:

- Email: `admin@poolsi.de`
- Password: `kubectl get secret langfuse-init -n litellm -o jsonpath='{.data.LANGFUSE_INIT_USER_PASSWORD}' | base64 -d`

Before DNS is set up, port-forward instead: `kubectl port-forward -n litellm svc/langfuse-web 3000:3000` and browse to `http://localhost:3000`.

Traces live under the `litellm-proxy` project. After your first login you can set
`langfuse.features.signUpDisabled: true` in `values.yaml` and re-run the Langfuse
`helm upgrade` to close public sign-up.

## Optional: trace direct-to-inference calls (bypassing LiteLLM)

You do not have to route through LiteLLM to get traces. The inference server here
(`inference-laguna` in the `poolside-models` namespace) is a vLLM instance exposing an
OpenAI-compatible `/v1` endpoint, so a client can call it directly and still send traces to
the same Langfuse project.

The important concept: Langfuse tracing is instrumentation, not packet capture. The
inference server does not push anything to Langfuse on its own, so when LiteLLM is out of the
path, the trace has to be created by the caller. There are two ways to do that.

### Option A: instrument the client with the Langfuse SDK (recommended)

Because laguna speaks the OpenAI API, the Langfuse drop-in wrapper for the OpenAI SDK traces
every call with no other changes. This was verified against this cluster: a direct call to
laguna produced a trace named `direct-laguna-call` with the prompt and response captured.

```bash
pip install "langfuse>=3" openai
```

```python
import os
# Reuse the same project keys LiteLLM uses (the litellm-langfuse secret), or mint a
# fresh pair under Settings -> API Keys in the UI.
os.environ["LANGFUSE_PUBLIC_KEY"] = "pk-lf-..."
os.environ["LANGFUSE_SECRET_KEY"] = "sk-lf-..."
os.environ["LANGFUSE_HOST"] = "https://langfuse.poolsi.de"  # or http://localhost:3001 via port-forward

# Drop-in replacement: same OpenAI client, auto-traced
from langfuse.openai import openai
from langfuse import get_client

client = openai.OpenAI(
    base_url="http://inference-laguna.poolside-models.svc.cluster.local/v1",  # in-cluster
    api_key="not-needed",  # laguna does not require a key
)

resp = client.chat.completions.create(
    model="LagunaXS",
    messages=[{"role": "user", "content": "Hello from a direct call"}],
    name="direct-laguna-call",            # shows up as the trace name
    metadata={"path": "client-direct"},   # arbitrary trace metadata
)
print(resp.choices[0].message.content)
get_client().flush()  # flush before a short-lived script exits
```

From a laptop outside the cluster, port-forward both services and point the URLs at
localhost:

```bash
kubectl port-forward -n poolside-models svc/inference-laguna 8080:80 &
kubectl port-forward -n litellm svc/langfuse-web 3001:3000 &
# base_url=http://localhost:8080/v1   LANGFUSE_HOST=http://localhost:3001
```

This captures the same data you get through LiteLLM: input messages, output, model, token
usage, and latency. For code that is not a single OpenAI call (a RAG chain, an agent, custom
pre/post-processing), wrap your own functions with the `@observe` decorator instead, and the
OpenAI calls inside them nest under that trace automatically. The same integration exists for
the JS/TS SDK and for LangChain, LlamaIndex, and others.

- A runnable, verified version using `@observe` with a plain `requests` client (for when you
  are not using the OpenAI SDK) is in [`examples/`](examples/README.md).

The trade-off versus the LiteLLM callback: instrumentation now lives in each client, so every
caller that should be traced must use the SDK. The LiteLLM path traces everything centrally
regardless of who calls it.

### Option B: export OpenTelemetry spans from vLLM (advanced, client-agnostic)

Langfuse also ingests OpenTelemetry traces at `/api/public/otel/v1/traces` (verified present
on this deployment). vLLM can emit request spans over OTLP, so you can trace centrally at the
server without touching any client by setting vLLM's `--otlp-traces-endpoint` (or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) on the laguna deployment:

```
--otlp-traces-endpoint=https://langfuse.poolsi.de/api/public/otel/v1/traces
# OTLP auth header: Basic base64("<public-key>:<secret-key>")
OTEL_EXPORTER_OTLP_TRACES_HEADERS=Authorization=Basic <base64 pk:sk>
```

Caveats before you reach for this: it requires editing the laguna deployment (managed by the
separate `inference-stack` Helm release, not this folder), and vLLM's OTel spans carry less
prompt/response detail than the SDK wrapper, so traces are thinner than Option A or the
LiteLLM path. Prefer Option A unless you specifically need server-side, client-agnostic
capture.

## Design choices and gotchas

- Single-node ClickHouse. The chart defaults to 3 replicas in cluster mode with ZooKeeper.
  This profile sets `clickhouse.replicaCount: 1`, `clickhouse.clusterEnabled: false`, and
  `clickhouse.zookeeper.enabled: false`. With cluster mode off, Langfuse uses non-replicated
  MergeTree tables, so no Keeper/ZooKeeper is needed. Note that `replicaCount: 1` with
  cluster mode left on crashes the web pod (langfuse-k8s issue #60). For production HA, use
  3 replicas with cluster mode on, or managed ClickHouse Cloud.
- Bundled vs managed datastores. Everything runs in-cluster on EBS for a self-contained
  demo. For production, set `postgresql.deploy: false` / `s3.deploy: false` and point at RDS
  and real S3.
- Secrets handling. The committed `values.yaml` contains no secrets. Datastore passwords
  come from `values-secret.yaml` (gitignored) using the chart's native fields, which keeps
  the chart in charge of generating its internal secret objects with consistent key names.
  App API keys and the admin password come from the `langfuse-init` and `litellm-langfuse`
  secrets.
- In-cluster traffic. LiteLLM reaches Langfuse by ClusterIP, so the ingress, DNS, and TLS
  only matter for the human-facing UI.

## Teardown

```bash
helm uninstall langfuse -n litellm
# PVCs are retained by default; delete them to reclaim EBS volumes
kubectl delete pvc -n litellm -l app.kubernetes.io/instance=langfuse
kubectl delete secret langfuse-init langfuse-tls litellm-langfuse -n litellm

# remove the callback from LiteLLM
helm upgrade litellm <path-to>/deploy/charts/litellm-helm -n litellm --reuse-values \
  --set 'proxy_config.litellm_settings=null' --set 'environmentSecrets=null'
```

Then delete the `langfuse.poolsi.de` DNS record.
