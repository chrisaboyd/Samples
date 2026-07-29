# Locust Load Testing

Synthetic load against the gateway to validate latency, TTFT/TPOT, error rates, autoscaling.

## Purpose

Generate realistic chat completion traffic through LiteLLM/Bifrost.

## Dependencies

Gateway: LiteLLM or Bifrost must be deployed and accessible.

## Scenarios

- Chat completion load
- Streaming response test
- Error rate validation
- Autoscaling trigger

## Files

- `values.yaml` - Configuration reference
- `manifests/` - Raw Kubernetes manifests

## Individual Deployment

```bash
kubectl apply -k .
```

## Verification

```bash
# Check pods are running
kubectl get pods -n load-testing

# Access Locust UI (headless mode enabled for dev)
kubectl -n load-testing logs deployment/locust-master

# To use interactive UI, change the command in the deployment
```

## Configuration

Environment variables in values.yaml:
- `TARGET_HOST`: `http://litellm.gateway.svc.cluster.local:8000`
- `USERS`: `100`
- `SPAWN_RATE`: `10`

## Note

In dev mode, Locust runs in headless mode. For interactive testing, remove the `--headless` flag and set `--master` on the master pod.