IMAGE ?= vllm-behavior-benchmark:dev
PLATFORM ?= linux/amd64
KUBECONFIG ?= $(HOME)/.kube/contexts/boyd-ref

.PHONY: test build validate analyze
test:
	python3 -m unittest discover -s tests -v

build:
	docker build --platform=$(PLATFORM) -t $(IMAGE) .

validate:
	KUBECONFIG=$(KUBECONFIG) kubectl create --dry-run=server -f k8s/job.yaml

analyze:
	python3 skills/analyze-vllm-benchmark/scripts/extract_and_analyze.py --kubeconfig $(KUBECONFIG) --namespace poolside-models --output-dir ./results
