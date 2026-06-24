# vLLM Inference Backend

In-cluster vLLM serving open-weights models on GPU nodes. Exposes OpenAI-compatible endpoint.

## Purpose

Model backend for the gateway. Provides `/v1/chat/completions`, `/v1/completions` endpoints.

## Dependencies

Cluster foundation (GPU Operator), StorageClass.

## What it exposes

Service: `vllm.inference.svc.cluster.local:8000`

## Ports / Services

| Service | Port |
|---------|------|
| vllm | 8000 (API), 8001 (Metrics) |

## Configuration

Model deployed via `MODEL_NAME` and `HF_MODEL_ID` environment variables.

## Monitoring

Emits vLLM metrics for ServiceMonitor (tokens/sec, TTFT, TPOT).