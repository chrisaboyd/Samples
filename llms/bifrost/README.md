# Bifrost AI Gateway on EKS

A complete, reproducible tutorial for deploying [Bifrost](https://github.com/maximhq/bifrost)
(maximhq's OpenAI-compatible LLM gateway, the Go-based alternative to LiteLLM) into a
Kubernetes cluster as a **self-contained dev environment**. Everything runs in-cluster on a
single node with no external database: Bifrost stores its config and request logs in SQLite
on an EBS volume, serves its web UI and OpenAI-compatible API on one port, and is exposed at
`https://bifrost.poolsi.de` through the shared nginx ingress.

Built and verified against a live EKS cluster (`poolside-c2e-march`, us-east-2) in the
`bifrost` namespace. End state: one `bifrost-0` pod, a 10Gi gp2 PVC, a ClusterIP service, and
an nginx ingress on the same AWS ELB that already serves `combine-llm.poolsi.de` and
`langfuse.poolsi.de`.

## What gets deployed

Bifrost is a single Go binary. Unlike Langfuse (a distributed system) or LiteLLM (proxy +
Postgres), the dev profile here is just **one pod and one volume**. The gateway, the web UI,
the `/health` probe, and `/metrics` all share port `8080`.

```
                         ┌──────────────── bifrost namespace ────────────────┐
                         │                                                    │
  client ──► /v1/chat/completions ─────────► bifrost-0 (pod) ──► upstream LLM providers
   (with a virtual key)                          │  port 8080      (OpenAI, Anthropic, …)
                         │                       │                            │
  browser ──(https://bifrost.poolsi.de ─────────┘                            │
            via nginx ingress)                   └── SQLite on /app/data (10Gi gp2 PVC)
                         │                            config store + request logs           │
                         └────────────────────────────────────────────────────────────────┘
```

Why no Postgres or Redis: Bifrost's default config/logs store is SQLite, and the web UI only
needs *a* config store — SQLite satisfies it. Redis is only used as an optional vector store
for semantic caching, which this dev profile leaves off. Keeping SQLite on a PVC is both the
simplest path and fully in-cluster. The chart can swap to an in-cluster Postgres subchart for
production (see [Design choices](#design-choices-and-gotchas)).

## Prerequisites

1. `kubectl` and `helm` (v3.8+) pointed at the target cluster. Confirm with
   `kubectl config current-context`. This was built against
   `arn:aws:eks:us-east-2:992382466748:cluster/poolside-c2e-march`.
2. A namespace. This guide uses `bifrost` (already created). Set it as your default or pass
   `-n bifrost` on every command.
3. A StorageClass for the SQLite volume. This cluster only has `gp2` (EBS) and it is not
   marked default, so `values.yaml` pins `gp2` explicitly under `storage.persistence`. Change
   that one line if your cluster differs.
4. An ingress controller for the browser URL. This cluster runs `ingress-nginx` (ingress
   class `nginx`) fronted by an AWS ELB. The ingress is enabled for host `bifrost.poolsi.de`.
5. DNS control for `bifrost.poolsi.de` — point it at the nginx ELB (see step 5). Until then
   you can reach the UI by port-forward.
6. `openssl` locally to generate the encryption key and a self-signed TLS cert. This cluster
   has **no cert-manager**, so TLS is a self-signed secret, matching the litellm/langfuse
   setup here. Swap in a real cert (or cert-manager) for anything beyond a demo.
7. Capacity. The dev profile requests ~250m CPU / 256Mi memory and a 10Gi EBS volume.

## Files in this folder

| File | Purpose | Committed |
| --- | --- | --- |
| `values.yaml` | Bifrost Helm values: image tag, SQLite on gp2, nginx ingress, encryption-key secret reference. No secrets. | yes |
| `README.md` | This tutorial. | yes |

No secrets live in any file. The encryption key and TLS cert are created directly as
Kubernetes secrets with `openssl` + `kubectl` (steps 1–2); upstream provider API keys are
added through the web UI and encrypted at rest by Bifrost.

## Deploy, step by step

All commands assume the `bifrost` namespace and the current kube context.

### 1. Create the encryption key secret

Bifrost encrypts provider API keys before writing them to SQLite. The key is supplied as a
Kubernetes secret; the chart injects it as `BIFROST_ENCRYPTION_KEY` and references it from the
generated `config.json`, so the raw key never lands in `values.yaml` or the chart's own
ConfigMap.

```bash
kubectl create secret generic bifrost-encryption-key -n bifrost \
  --from-literal=encryption-key="$(openssl rand -hex 32)"
```

Do not rotate this key once provider keys are stored, or Bifrost can no longer decrypt them.

### 2. Create the TLS secret

Self-signed, matching the litellm/langfuse setup on this cluster. Replace with a real cert for
production.

```bash
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout tls.key -out tls.crt \
  -subj "/O=bifrost/CN=bifrost.poolsi.de" \
  -addext "subjectAltName=DNS:bifrost.poolsi.de"

kubectl create secret tls bifrost-tls -n bifrost --cert=tls.crt --key=tls.key
rm -f tls.key tls.crt
```

### 3. Add the Helm repo

```bash
helm repo add bifrost https://maximhq.github.io/bifrost/helm-charts
helm repo update bifrost
```

### 4. Install Bifrost

The chart has **no default image tag**, so `values.yaml` pins `image.tag: v1.5.15`. With
`storage.mode: sqlite` and persistence enabled, the chart renders a **StatefulSet** so the
database survives restarts.

```bash
helm upgrade --install bifrost bifrost/bifrost --version 2.1.24 \
  --namespace bifrost \
  -f values.yaml \
  --timeout 5m

kubectl rollout status statefulset/bifrost -n bifrost
```

Confirm the pod, volume, and ingress:

```bash
kubectl get pods,pvc,svc,ingress -n bifrost
# bifrost-0 Running 1/1 | PVC Bound on gp2 | svc :8080 | ingress nginx bifrost.poolsi.de
```

### 5. Point DNS at the ingress

Create a DNS record for `bifrost.poolsi.de` targeting the nginx ELB. It is the same ELB that
already serves `combine-llm.poolsi.de` and `langfuse.poolsi.de`, so a CNAME (or Route 53 alias
A record) to that hostname is all you need.

```bash
kubectl get ingress bifrost -n bifrost \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
# afb05d15a4876419da6a1b86b86060a5-19d4b33ae5871027.elb.us-east-2.amazonaws.com
```

You can confirm the ingress works before DNS propagates by overriding the host:

```bash
ELB=$(kubectl get ingress bifrost -n bifrost -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -sk -H "Host: bifrost.poolsi.de" "https://$ELB/health" -o /dev/null -w "%{http_code}\n"
# 200
```

## Verify

```bash
kubectl port-forward -n bifrost svc/bifrost 8080:8080 &

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/health   # 200
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/         # 200 (web UI)
curl -s http://localhost:8080/metrics | head -1                         # Prometheus metrics
```

## Use the gateway

Bifrost is configured through its web UI (no config file to edit). Open it via port-forward
until DNS resolves:

```bash
kubectl port-forward -n bifrost svc/bifrost 8080:8080
# browse to http://localhost:8080
```

Once DNS is set up, browse to `https://bifrost.poolsi.de` (accept the self-signed cert
warning). The dashboard has no login in this dev profile (`authConfig.isEnabled: false`).

Then, in the UI:

1. **Add a provider.** Go to *Providers*, pick e.g. OpenAI or Anthropic, and paste an API
   key. The key is encrypted with the `bifrost-encryption-key` secret before being stored.
2. **Create a virtual key.** Go to *Virtual Keys* and create one. This dev profile keeps the
   chart's secure default (`enforceAuthOnInference: true`), so inference calls must carry a
   virtual key. (To run a fully open dev gateway with no key, set
   `bifrost.client.enforceAuthOnInference: false` in `values.yaml` and re-run the
   `helm upgrade`.)
3. **Call the gateway.** Models are addressed as `<provider>/<model>`:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer <your-virtual-key>" \
  -H "Content-Type: application/json" \
  -d '{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"Hello from Bifrost"}]}'
```

## Design choices and gotchas

- **SQLite, not Postgres.** A dev gateway does not need an external database. SQLite on a gp2
  PVC keeps everything in-cluster and self-contained, and still enables the web UI. For
  production HA, set `storage.mode: postgres` and `postgresql.enabled: true` — the chart ships
  a Postgres subchart, and with Postgres for both config and logs stores the workload collapses
  from a StatefulSet back to a Deployment (no PVC needed).
- **No Redis.** Redis only appears as an optional vector-store backend for semantic caching
  (`vectorStore.enabled`), which is off here.
- **One port for everything.** API, UI, `/health`, and `/metrics` all live on `8080`. The
  `/health` path is used for both liveness and readiness probes.
- **Image tag is mandatory.** The chart intentionally ships no default `image.tag`; omitting
  it leaves the pod unschedulable. This guide pins `v1.5.15`.
- **Encryption key is load-bearing.** Once provider keys are stored, rotating
  `bifrost-encryption-key` makes them undecryptable. Treat it like a database password.
- **Self-signed TLS.** No cert-manager exists on this cluster, so the ingress uses a
  self-signed `bifrost-tls` secret. In-cluster callers can skip the ingress entirely and hit
  `http://bifrost.bifrost.svc.cluster.local:8080` over ClusterIP.
- **`proxy-body-size: "0"`.** The ingress disables nginx's request-size cap so large
  prompts/payloads are not truncated, matching the litellm ingress here.

## Teardown

```bash
helm uninstall bifrost -n bifrost
# the SQLite PVC is retained by default; delete it to reclaim the EBS volume
kubectl delete pvc data-bifrost-0 -n bifrost
kubectl delete secret bifrost-encryption-key bifrost-tls -n bifrost
```

Then delete the `bifrost.poolsi.de` DNS record.

## References

- Bifrost source — https://github.com/maximhq/bifrost
- Docs (gateway setup, deployment guides) — https://docs.getbifrost.ai
- Helm chart README — https://github.com/maximhq/bifrost/blob/dev/helm-charts/bifrost/README.md
- Helm chart on Artifact Hub — https://artifacthub.io/packages/helm/bifrost/bifrost
- Docker images — https://hub.docker.com/r/maximhq/bifrost/tags
- Config schema — https://getbifrost.ai/schema
