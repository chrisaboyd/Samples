# vLLM Configuration

## Key Settings

```yaml
MODEL_NAME: "mistral-7b"
HF_MODEL_ID: "mistralai/Mistral-7B-v0.1"
GPU_MEMORY_UTILIZATION: "0.8"
MAX_MODEL_LEN: "4096"
```

## GPU Requirements

Requires NVIDIA GPU with sufficient VRAM for model.

## Replicas

Single replica for dev. Can scale with HPA in prod.

## Endpoint

`http://vllm.inference.svc.cluster.local:8000/v1` - OpenAI compatible