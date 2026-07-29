# kube-prometheus-stack Configuration

## Components

- Prometheus server with 20Gi storage
- Grafana with community dashboards
- AlertManager (no receivers in dev)
- kube-state-metrics
- node-exporter
- Prometheus Operator CRDs

## Prometheus Operator CRDs

This chart is the **only** source of the Prometheus Operator CRDs. Never pre-create them
in Layer 0: Helm skips CRDs that already exist, and a stub with an incomplete
`openAPIV3Schema` makes the API server prune the fields it omits — the `Prometheus`
object loses its `spec`, the operator generates an empty scrape config, and Prometheus
collects nothing while every pod still reports healthy.

Symptoms of that failure mode:

```bash
# both come back empty
kubectl -n observability get prometheus kube-prometheus-stack-prometheus -o jsonpath='{.spec}'
curl -s localhost:9090/api/v1/targets?state=active   # activeTargets: []
```

Recovery — replace the CRDs, then force Helm to re-render the CRs. A plain
`helm upgrade` is not enough: with the manifest unchanged, Helm computes an empty patch
and the spec-less object stays invalid (`spec: Required value`). The affected objects
must be deleted so Helm recreates them.

```bash
helm pull prometheus-community/kube-prometheus-stack --version <ver> --untar
kubectl apply --server-side --force-conflicts \
  -f kube-prometheus-stack/charts/crds/crds/crd-prometheuses.yaml \
  -f kube-prometheus-stack/charts/crds/crds/crd-servicemonitors.yaml

kubectl -n observability delete prometheus kube-prometheus-stack-prometheus
kubectl -n observability delete servicemonitor -l release=kube-prometheus-stack
helm upgrade kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --version <ver> -n observability -f values.yaml
```

Server-side apply is required — the `prometheuses` CRD is ~830KB and client-side apply
fails with `metadata.annotations: Too long`.

## Storage

`prometheus.prometheusSpec.storageSpec` pins `storageClassName: gp2`, which is the class
this EKS cluster provides. Note that `gp2` is **not** annotated as the cluster default,
so the class cannot be omitted — an unset `storageClassName` leaves the PVC `Pending`
forever with `no persistent volumes available for this claim and no storage class is set`.

## Grafana Ingress

Grafana is exposed through the shared nginx ingress at `grafana.poolsi.de`, matching the
bifrost/litellm pattern. The ingress is declared in `values.yaml` so Helm owns it.

There is no cert-manager in this cluster, so `grafana-tls` is a self-signed certificate
created out of band (the private key is deliberately not committed):

```bash
openssl req -x509 -nodes -newkey rsa:2048 -days 820 \
  -keyout grafana.key -out grafana.crt \
  -subj "/O=grafana/CN=grafana.poolsi.de" \
  -addext "subjectAltName=DNS:grafana.poolsi.de"

kubectl -n observability create secret tls grafana-tls \
  --cert=grafana.crt --key=grafana.key
```

`*.poolsi.de` is not in public DNS; add the ingress ELB address to `/etc/hosts` as with
the other hosts:

```
18.190.199.134 grafana.poolsi.de
16.59.51.142   grafana.poolsi.de
```

Default credentials are `admin` / `admin` (`grafana.adminPassword`).
