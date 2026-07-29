#!/bin/bash

# Tear down dev deployment

echo "=== Tearing down AI Gateway Stack (dev) ==="

# Delete in reverse order
kubectl delete -k load-testing/locust/ --ignore-not-found=true
kubectl delete -k observability/servicemonitors/ --ignore-not-found=true
kubectl delete -k observability/langfuse/ --ignore-not-found=true
kubectl delete -k observability/otel-collector/ --ignore-not-found=true
kubectl delete -k observability/tempo/ --ignore-not-found=true
kubectl delete -k observability/loki/ --ignore-not-found=true
kubectl delete -k observability/dcgm-exporter/ --ignore-not-found=true
kubectl delete -k observability/kube-prometheus-stack/ --ignore-not-found=true

kubectl delete -k guardrails/llm-guard/ --ignore-not-found=true
kubectl delete -k guardrails/nemo-guardrails/ --ignore-not-found=true
kubectl delete -k guardrails/presidio/ --ignore-not-found=true

kubectl delete -k gateway/open-webui/ --ignore-not-found=true
kubectl delete -k gateway/bifrost/ --ignore-not-found=true
kubectl delete -k gateway/litellm/ --ignore-not-found=true

kubectl delete -k inference/vllm/ --ignore-not-found=true

kubectl delete -k platform/object-storage/ --ignore-not-found=true
kubectl delete -k platform/redis/ --ignore-not-found=true
kubectl delete -k platform/clickhouse/ --ignore-not-found=true
kubectl delete -k platform/postgres/ --ignore-not-found=true

kubectl delete -k cluster/ --ignore-not-found=true

# Delete namespaces
kubectl delete namespace platform gateway guardrails observability inference load-testing --ignore-not-found=true

echo "=== Teardown complete ==="