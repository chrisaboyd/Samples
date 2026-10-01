# Atlas to FIPS vLLM: Poolside on-prem 2026.07.07 (RHEL 9, RKE2)

Replaces the Atlas inference image in a Poolside on-prem 2026.07.07 install with a FIPS-configured vLLM 0.29 image serving Laguna-XS-2.1-FP8, and verifies approved crypto works and non-approved crypto is refused.

- **Part 1** builds and verifies the image. Both path 2A and 2B need it.
- **Part 2A** (optional) runs it locally with Podman, to validate the image before touching the cluster.
- **Part 2B** moves the `06-poolside-inference` deployment from Atlas to the FIPS image via the RKE2 registry and the phase 6 Terraform.

## Prerequisites

### RKE2 Pre-requisites

| Requirement | Check | Expected |
|---|---|---|
| RHEL 9.x host with FIPS enabled | `fips-mode-setup --check` | `FIPS mode is enabled.` |
| Poolside on-prem 2026.07.07 phases `01-infra-rke2` to `06-poolside-inference` applied, serving Atlas | `kubectl -n poolside-models get deploy inference-agent` | `READY 1/1` |
| RKE2 local registry on `localhost:30500` | `curl -s http://localhost:30500/v2/_catalog \| jq -c` | `{"repositories":[...]}` |
| Laguna checkpoint uploaded by phase 5 (`05-poolside-model-upload`) | `grep -A3 model_s3_uris <bundle>/06-poolside-inference/terraform.tfvars` | `agent = "s3://poolside-models/<checkpoint dir>"` |
| `kubectl`, `terraform`, `skopeo`, `jq` | `kubectl version --client; terraform version; skopeo --version` | versions print |
| The Part 1 image, in local storage or as a tar | `podman images localhost/vllm-openai-fips:0.29.0` or `ls vllm-openai-fips-0.29.0.tar` | image or file present |

Run everything as root:

```bash
sudo -i
export PATH=$PATH:/usr/local/bin
export IMG=localhost/vllm-openai-fips:0.29.0
export MODEL_DIR=/data/models/laguna-xs
export CERTS=/data/certs
export CA=$CERTS/tls.crt
export URL=https://localhost:8443
```

## Part 1: Build and verify the vLLM image

### Step 1: Update Dockerfile

```bash
mkdir -p /data/build && cd /data/build
cat > Dockerfile.fips <<'EOF'
ARG CUDA_VERSION=13.0.2

FROM docker.io/nvidia/cuda:${CUDA_VERSION}-base-ubi9 AS fips-policy
RUN mkdir -p /staging/back-ends /staging/state \
    && for t in /usr/share/crypto-policies/FIPS/*.txt; do \
         ln -s "$t" "/staging/back-ends/$(basename "$t" .txt).config"; done \
    && echo FIPS > /staging/config \
    && echo FIPS > /staging/state/current \
    && cp /usr/share/crypto-policies/policies/FIPS.pol /staging/state/CURRENT.pol

FROM docker.io/nvidia/cuda:${CUDA_VERSION}-base-ubi9
ARG VLLM_VERSION=0.29.0
ARG TORCH_INDEX=cu130
ARG PYTHON=python3.12

RUN dnf install -y ${PYTHON} ${PYTHON}-pip ${PYTHON}-devel \
        openssl crypto-policies-scripts git gcc \
    && dnf clean all \
    && ln -sf /usr/bin/${PYTHON} /usr/local/bin/python3 \
    && ln -sf /usr/bin/${PYTHON} /usr/local/bin/python

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir "vllm==${VLLM_VERSION}" \
         transformers==5.16.1 huggingface_hub==1.30.0 awscli \
         --extra-index-url https://download.pytorch.org/whl/${TORCH_INDEX}

RUN python -m pip uninstall -y blake3 xxhash opencv-python-headless || true

ARG CUDA_VERSION
RUN v=${CUDA_VERSION%.*}; s=${v/./-}; dnf install -y cuda-nvcc-$s cuda-cudart-devel-$s \
        cuda-culibos-devel-$s cuda-driver-devel-$s libcublas-devel-$s libcurand-devel-$s \
    && dnf clean all

COPY --from=fips-policy /staging/ /etc/crypto-policies/

ENV HOME=/tmp \
    VLLM_MM_HASHER_ALGORITHM=sha256 \
    VLLM_NO_USAGE_STATS=1 \
    DO_NOT_TRACK=1 \
    HF_HUB_OFFLINE=1

ENTRYPOINT ["vllm", "serve"]
EOF
```

### Step 2: Pull the base image and build

```bash
podman pull docker.io/nvidia/cuda:13.0.2-base-ubi9
podman build -f Dockerfile.fips -t $IMG .
podman images $IMG --format '{{.Repository}}:{{.Tag}} {{.Size}}'
```

Expected (last line):

```
localhost/vllm-openai-fips:0.29.0 11.8 GB
```

### Step 3: Save and load the image (if moving to another host)

```bash
podman save -o /data/vllm-openai-fips-0.29.0.tar $IMG
# copy the tar to the target host, then on the target:
podman load -i /data/vllm-openai-fips-0.29.0.tar
```

Expected (last line):

```
Loaded image: localhost/vllm-openai-fips:0.29.0
```

### Step 4: Verify the image

#### Image carries the FIPS crypto policy (read from the image files, not the running container)

```bash
M=$(podman image mount $IMG)
cat $M/etc/crypto-policies/config
readlink $M/etc/crypto-policies/back-ends/opensslcnf.config
podman image unmount $IMG
```

Expected:

```
FIPS
/usr/share/crypto-policies/FIPS/opensslcnf.txt
```

#### Python in the image uses OpenSSL in FIPS mode

```bash
podman run --rm --entrypoint python $IMG -c "import _hashlib; print(_hashlib.get_fips_mode())"
```

Expected:

```
1
```

#### Non-FIPS hasher and bundled-OpenSSL packages are removed

```bash
podman run --rm --entrypoint bash $IMG -c "pip list 2>/dev/null | grep -Ei 'blake3|xxhash|opencv' || echo none"
```

Expected:

```
none
```

#### vLLM, torch and CUDA versions

```bash
podman run --rm --entrypoint python $IMG -c "import vllm, torch; print(vllm.__version__, torch.__version__)"
```

Expected:

```
0.29.0 2.13.0+cu130
```

#### GPU visible from the image

```bash
podman run --rm --device nvidia.com/gpu=all --entrypoint python $IMG -c "import torch; print(torch.cuda.device_count())"
```

Expected:

```
1
```

#### AWS CLI for the RKE2 model-downloader runs on the system Python and OpenSSL, as UID 10003

```bash
podman run --rm --user 10003 --entrypoint bash $IMG -c 'echo HOME=$HOME; aws --version; python -c "import ssl; print(ssl.OPENSSL_VERSION)"'
```

Expected:

```
HOME=/tmp
aws-cli/1.46.1 Python/3.12.14 Linux/5.14.0-611.55.1.el9_7.x86_64 botocore/1.43.62
OpenSSL 3.5.8 25 Aug 2026
```

## Part 2A: Run locally with Podman

### Step 5: Download the model

```bash
HF_HUB_DISABLE_XET=1 hf download poolside/Laguna-XS-2.1-FP8 --local-dir $MODEL_DIR --exclude 'DFlash/*'
du -sh $MODEL_DIR
```

Expected (last line):

```
33G	/data/models/laguna-xs
```

### Step 6: Create the TLS certificate

```bash
mkdir -p $CERTS
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -days 30 -nodes \
  -keyout $CERTS/tls.key -out $CERTS/tls.crt -subj "/CN=vllm-fips" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 644 $CERTS/tls.key
openssl x509 -in $CA -noout -text | grep -E 'Public Key Algorithm|ASN1 OID|Signature Algorithm' | sort -u
```

Expected:

```
                ASN1 OID: prime256v1
            Public Key Algorithm: id-ecPublicKey
        Signature Algorithm: ecdsa-with-SHA256
```

### Step 7: Start vLLM

```bash
podman rm -f vllm-fips 2>/dev/null
podman run -d --name vllm-fips \
  --device nvidia.com/gpu=all --ipc=host \
  -p 8443:8443 \
  -v /data/models:/models:ro -v $CERTS:/certs:ro \
  $IMG \
  /models/laguna-xs \
  --served-model-name=Laguna \
  --host=0.0.0.0 --port=8443 \
  --tensor-parallel-size=1 \
  --prefix-caching-hash-algo=sha256 \
  --ssl-keyfile=/certs/tls.key --ssl-certfile=/certs/tls.crt \
  --ssl-ciphers=ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256 \
  --enable-auto-tool-choice \
  --tool-call-parser=poolside_v1 \
  --reasoning-parser=poolside_v1 \
  --enable-request-id-headers \
  '--default-chat-template-kwargs={"enable_thinking": true}'

until curl -sf --cacert $CA $URL/health; do sleep 10; done; echo ready
```

Expected (~2 minutes):

```
ready
```

### Step 8: Set up the test client

```bash
podman pull docker.io/alpine/openssl
alias nonfips='podman run --rm --network host docker.io/alpine/openssl'
```

### Step 9:  Checks (FIPS is on and the model serves)

#### Host kernel is in FIPS mode

```bash
cat /proc/sys/crypto/fips_enabled
```

Expected:

```
1
```

#### Host FIPS mode and crypto policy

```bash
fips-mode-setup --check
update-crypto-policies --show
```

Expected:

```
FIPS mode is enabled.
FIPS
```

#### Validated OpenSSL FIPS provider is active

```bash
openssl list -providers | grep -A3 fips
```

Expected:

```
  fips
    name: Red Hat Enterprise Linux 9 - OpenSSL FIPS Provider
    version: 3.0.7-395c1a240fbfffd8
    status: active
```

#### Running vLLM container is in FIPS mode

```bash
podman exec vllm-fips python -c "import _hashlib; print(_hashlib.get_fips_mode())"
```

Expected:

```
1
```

#### SHA-256 works in the running container

```bash
podman exec vllm-fips python -c "import hashlib; print(hashlib.sha256(b'fips').hexdigest())"
```

Expected:

```
40d11f9696d5a6ad82abd3d02f3283d7d16edc54a43c375f951447de3de31035
```

#### vLLM prefix cache hashes with SHA-256

```bash
podman inspect vllm-fips --format '{{join .Config.Cmd " "}}' | grep -o 'prefix-caching-hash-algo=[a-z0-9]*'
podman exec vllm-fips python -c "from vllm.config.cache import CacheConfig; print(CacheConfig().prefix_caching_hash_algo)"
```

Expected:

```
prefix-caching-hash-algo=sha256
sha256
```

#### TLS 1.3 negotiates an approved suite

```bash
nonfips s_client -connect localhost:8443 -tls1_3 </dev/null 2>&1 | grep 'Cipher is'
```

Expected:

```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

#### TLS 1.2 negotiates an approved suite

```bash
nonfips s_client -connect localhost:8443 -tls1_2 </dev/null 2>&1 | grep 'Cipher is'
```

Expected:

```
New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384
```

#### Health endpoint and model list

```bash
curl -s --cacert $CA -o /dev/null -w '%{http_code}\n' $URL/health
curl -s --cacert $CA $URL/v1/models | jq -r '.data[].id'
```

Expected:

```
200
Laguna
```

#### Chat completion returns an answer

```bash
curl -s --cacert $CA $URL/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"Laguna","messages":[{"role":"user","content":"What is 2+2? Answer with just the number."}],"max_tokens":512}' \
  | jq -r '.choices[0].message.content'
```

Expected:

```
4
```

#### Prefix cache records hits (SHA-256 hashing path in use)

```bash
curl -s --cacert $CA $URL/metrics | grep -E '^vllm:prefix_cache_hits_total'
curl -s --cacert $CA $URL/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"Laguna","messages":[{"role":"user","content":"What is 2+2? Answer with just the number."}],"max_tokens":512}' >/dev/null
curl -s --cacert $CA $URL/metrics | grep -E '^vllm:prefix_cache_hits_total'
```

Expected: the second number is higher than the first.

```
vllm:prefix_cache_hits_total{engine="0",model_name="Laguna"} 0.0
vllm:prefix_cache_hits_total{engine="0",model_name="Laguna"} 48.0
```

### Step 10: Negative checks (non-FIPS crypto is refused)

#### Control: the test client negotiates ChaCha20 with a server that allows it

```bash
podman run -d --name tls-control --network host -v $CERTS:/certs:ro docker.io/alpine/openssl \
  s_server -accept 9443 -cert /certs/tls.crt -key /certs/tls.key -www
sleep 2
nonfips s_client -connect localhost:9443 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305 </dev/null 2>&1 | grep 'Cipher is'
nonfips s_client -connect localhost:9443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 </dev/null 2>&1 | grep 'Cipher is'
podman rm -f tls-control
```

Expected:

```
New, TLSv1.2, Cipher is ECDHE-ECDSA-CHACHA20-POLY1305
New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256
```

#### vLLM refuses ChaCha20 over TLS 1.2

```bash
nonfips s_client -connect localhost:8443 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305 </dev/null 2>&1 | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
```

#### vLLM refuses ChaCha20 over TLS 1.3

```bash
nonfips s_client -connect localhost:8443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 </dev/null 2>&1 | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
```

#### vLLM refuses CBC-mode and static-RSA suites

```bash
nonfips s_client -connect localhost:8443 -tls1_2 -cipher ECDHE-ECDSA-AES128-SHA </dev/null 2>&1 | grep 'Cipher is'
nonfips s_client -connect localhost:8443 -tls1_2 -cipher AES256-GCM-SHA384 </dev/null 2>&1 | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
New, (NONE), Cipher is (NONE)
```

#### vLLM refuses TLS 1.1

```bash
nonfips s_client -connect localhost:8443 -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
```

#### Host refuses MD5

```bash
openssl md5 /etc/hostname 2>&1 | head -1
python3 -c "import hashlib; hashlib.md5(b'x')" 2>&1 | tail -1
```

Expected:

```
Error setting digest
ValueError: [digital envelope routines] unsupported
```

#### Running vLLM container refuses MD5

```bash
podman exec vllm-fips python -c "import hashlib; hashlib.md5(b'x')" 2>&1 | tail -1
```

Expected:

```
_hashlib.UnsupportedDigestmodError: [digital envelope routines] unsupported
```

#### Non-FIPS prefix-cache hashers are absent

```bash
podman exec vllm-fips python -c "import xxhash" 2>&1 | tail -1
podman exec vllm-fips python -c "import blake3" 2>&1 | tail -1
```

Expected:

```
ModuleNotFoundError: No module named 'xxhash'
ModuleNotFoundError: No module named 'blake3'
```

#### Host refuses weak key generation (RSA-1024 fails, RSA-2048 works)

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out /dev/null 2>&1 | head -1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /dev/null 2>/dev/null && echo "2048 ok"
```

Expected:

```
genpkey: Error generating RSA key
2048 ok
```

### Cleanup

```bash
podman rm -f vllm-fips
```

## Part 2B: Move the on-prem deployment from Atlas to FIPS vLLM (RKE2)

This is the requirement for on-prem deployments.  
Skopeo is used to copy the images into `registry:3` on port 30500 (both fips-vllm + aws-cli).  
Additionally, the Terraform bundled helm charts require modifications, updating both the image and start arguments.  
Phase 6 (`06-poolside-inference`) deploys them with the Terraform helm provider and the bundle ships no `helm` CLI, so this part patches the files phase 6 reads, then re-applies phase 6.

```bash
export BUNDLE=/path/to/2026.07.07-29088365428
export STAGE=$BUNDLE/06-poolside-inference
export CHART=$STAGE/.terraform/modules/poolside_inference/charts/inference-stack/0.0.6
export REGCFG=$BUNDLE/poolside-install/poolside_registries_config.json
export TF_CLI_CONFIG_FILE=$BUNDLE/poolside-terraform.tfrc   # airgapped installs only
export NS=poolside-models
export MODEL=agent
export DEPLOY=inference-$MODEL
export HOST=poolside.poolside.local
export REG=localhost:30500
export REG_IMG=$REG/poolside/vllm-openai-fips:0.29.0
```

`MODEL` is the key under `model_s3_uris` in `06-poolside-inference/terraform.tfvars`. `HOST` is the Poolside platform host from `03-infra-services`. Phase 3 writes the kubeconfig to `~/.kube/config`.

### Step 5: Copy the image into the RKE2 registry

From local container storage (the image was built on this host):

```bash
skopeo copy --dest-tls-verify=false --dest-precompute-digests \
  containers-storage:localhost/vllm-openai-fips:0.29.0 \
  docker://$REG_IMG
```

Or from the Step 3 tar (the image was built elsewhere):

```bash
skopeo copy --dest-tls-verify=false --dest-precompute-digests \
  docker-archive:/data/vllm-openai-fips-0.29.0.tar \
  docker://$REG_IMG
```

Expected (last line):

```
Writing manifest to image destination
```

### Step 6: Verify the image is in the registry

```bash
curl -s http://$REG/v2/_catalog | jq -c '.repositories | map(select(test("vllm")))'
curl -s http://$REG/v2/poolside/vllm-openai-fips/tags/list | jq -c
skopeo inspect --tls-verify=false docker://$REG_IMG | jq -r '.Layers | length'
```

Expected:

```
["poolside/vllm-openai-fips"]
{"name":"poolside/vllm-openai-fips","tags":["0.29.0"]}
11
```

### Step 7: Copy the test client into the registry

```bash
skopeo copy --dest-tls-verify=false docker://docker.io/alpine/openssl:latest docker://$REG/alpine/openssl:latest
curl -s http://$REG/v2/alpine/openssl/tags/list | jq -c
```

Expected:

```
{"name":"alpine/openssl","tags":["latest"]}
```

### Step 8: Back up the files phase 6 reads

```bash
mkdir -p /data/build/atlas-backup
tar -C / -cpf /data/build/atlas-backup/phase6.tar \
  $STAGE/locals.tf $STAGE/terraform.tfvars \
  $CHART/.poolside_dependency_manifest.yml \
  $CHART/charts/inference/templates/deployment.yaml \
  $REGCFG
tar -tf /data/build/atlas-backup/phase6.tar | wc -l
```

Expected (last line):

```
5
```

### Step 9: Remove the Atlas-only argument from the chart

```bash
sed -i '/- --self-contained-checkpoint/d' $CHART/charts/inference/templates/deployment.yaml
grep -c 'self-contained-checkpoint' $CHART/charts/inference/templates/deployment.yaml
```

Expected:

```
0
```

### Step 10: Point phase 6 at the FIPS image

```bash
sed -i '/^  inference:/,/container_tag:/ s|container_tag: .*|container_tag: "0.29.0"|' $CHART/.poolside_dependency_manifest.yml
jq '.registries_config["poolside-inference"].inference.container_name = "poolside/vllm-openai-fips"' $REGCFG > /tmp/regcfg.json
cat /tmp/regcfg.json > $REGCFG && rm /tmp/regcfg.json
grep -A3 '^  inference:' $CHART/.poolside_dependency_manifest.yml | grep container_tag
jq -c '.registries_config["poolside-inference"].inference' $REGCFG
```

Expected:

```
    container_tag: "0.29.0"
{"base_uri":"localhost:30500","container_name":"poolside/vllm-openai-fips"}
```

### Step 11: Remove the Atlas model type and set the vLLM arguments

```bash
sed -i '/model_type = "agent"$/d' $STAGE/locals.tf
grep -c 'model_type = "agent"$' $STAGE/locals.tf
```

Expected:

```
0
```

In `$STAGE/terraform.tfvars`, keep `deployment_name` and `model_s3_uris`, and set `models_config` to:

```hcl
models_config = {
  agent = {
    gpus     = 1
    replicas = 1
    model_extra_args = {
      "port"                         = "8080"
      "tensor-parallel-size"         = "1"
      "prefix-caching-hash-algo"     = "sha256"
      "enable-auto-tool-choice"      = ""
      "tool-call-parser"             = "poolside_v1"
      "reasoning-parser"             = "poolside_v1"
      "enable-request-id-headers"    = ""
      "default-chat-template-kwargs" = "{\"enable_thinking\": true}"
    }
  }
}
```

### Step 12: Plan

```bash
cd $STAGE
terraform plan -no-color | grep -E '^  # |^Plan:'
```

Expected:

```
  # module.poolside_inference.helm_release.inference_stack will be updated in-place
Plan: 0 to add, 1 to change, 0 to destroy.
```

### Step 13: Apply

```bash
cd $STAGE
terraform apply
kubectl -n $NS rollout status deploy/$DEPLOY --timeout=40m
```

Expected (last lines):

```
Apply complete! Resources: 0 added, 1 changed, 0 destroyed.
...
deployment "inference-agent" successfully rolled out
```

### Step 14: Verify the running deployment

#### Both containers use the FIPS image from the RKE2 registry

```bash
kubectl -n $NS get deploy $DEPLOY \
  -o jsonpath='{.spec.template.spec.initContainers[0].image}{"\n"}{.spec.template.spec.containers[0].image}{"\n"}'
```

Expected:

```
localhost:30500/poolside/vllm-openai-fips:0.29.0
localhost:30500/poolside/vllm-openai-fips:0.29.0
```

#### vLLM arguments carry no Atlas flags

```bash
kubectl -n $NS get deploy $DEPLOY -o jsonpath='{.spec.template.spec.containers[0].args}' | jq -r '.[]'
```

Expected:

```
--model
/atlas/checkpoint/
--served-model-name
agent
--default-chat-template-kwargs
{"enable_thinking": true}
--enable-auto-tool-choice
--enable-request-id-headers
--port
8080
--prefix-caching-hash-algo
sha256
--reasoning-parser
poolside_v1
--tensor-parallel-size
1
--tool-call-parser
poolside_v1
```

#### Pod runs as the chart's non-root user

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- sh -c 'id -u; echo HOME=$HOME'
```

Expected:

```
10003
HOME=/tmp
```

#### Model downloader finished

```bash
kubectl -n $NS logs deploy/$DEPLOY -c model-downloader | tail -1
```

Expected: a final `download: s3://poolside-models/... to atlas/checkpoint/...` line and no `error`.

### Step 15: Positive checks (FIPS is on and the model serves)

#### RKE2 and its containerd are built with BoringCrypto

```bash
strings $(command -v rke2 || echo /usr/local/bin/rke2) | grep -m1 -io 'x:boringcrypto\|boringcrypto'
strings /var/lib/rancher/rke2/bin/containerd | grep -m1 -io 'boringcrypto'
```

Expected: `boringcrypto` printed for each.

#### Pod sees the host kernel in FIPS mode

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- cat /proc/sys/crypto/fips_enabled
```

Expected:

```
1
```

#### Pod crypto policy is FIPS, and it comes from the image (containerd adds no crypto-policy mounts)

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- update-crypto-policies --show
kubectl -n $NS exec deploy/$DEPLOY -c inference -- sh -c 'grep crypto-policies /proc/mounts || echo "no crypto-policies mount"'
```

Expected:

```
FIPS
no crypto-policies mount
```

#### Python in the pod uses OpenSSL in FIPS mode

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- python -c "import _hashlib; print(_hashlib.get_fips_mode())"
```

Expected:

```
1
```

#### SHA-256 works in the pod

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- python -c "import hashlib; print(hashlib.sha256(b'fips').hexdigest())"
```

Expected:

```
40d11f9696d5a6ad82abd3d02f3283d7d16edc54a43c375f951447de3de31035
```

#### vLLM prefix cache hashes with SHA-256

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- python -c "from vllm.config.cache import CacheConfig; print(CacheConfig().prefix_caching_hash_algo)"
kubectl -n $NS get deploy $DEPLOY -o jsonpath='{.spec.template.spec.containers[0].args}' | jq -r 'index("--prefix-caching-hash-algo") as $i | .[$i+1]'
```

Expected:

```
sha256
sha256
```

#### Set up the in-cluster test client

```bash
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
probe() { kubectl run tls-probe-$RANDOM -n default --rm -i --restart=Never --quiet \
  --image=$REG/alpine/openssl:latest -- "$@" </dev/null 2>&1; }
```

#### Ingress TLS 1.3 negotiates an approved suite

```bash
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_3 | grep 'Cipher is'
```

Expected:

```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

#### Ingress TLS 1.2 negotiates an approved suite

```bash
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_2 | grep 'Cipher is'
```

Expected: an `ECDHE-...-AES...-GCM-...` suite, for example:

```
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
```

#### Open the model and proxy ports

```bash
kubectl -n $NS port-forward svc/$DEPLOY 18080:80 >/dev/null 2>&1 &
kubectl -n $NS port-forward svc/inference-envoy-internal 18000:80 >/dev/null 2>&1 &
sleep 3
export URL=http://localhost:18080
```

#### Health endpoint and model list

```bash
curl -s -o /dev/null -w '%{http_code}\n' $URL/health
curl -s $URL/v1/models | jq -r '.data[].id'
```

Expected:

```
200
agent
```

#### Model list through the Envoy proxy (the platform's base URL)

```bash
curl -s http://localhost:18000/v0/models/$DEPLOY/v1/models | jq -r '.data[].id'
```

Expected:

```
agent
```

#### Chat completion returns an answer

```bash
curl -s $URL/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"agent","messages":[{"role":"user","content":"What is 2+2? Answer with just the number."}],"max_tokens":512}' \
  | jq -r '.choices[0].message.content'
```

Expected:

```
4
```

#### Prefix cache records hits

```bash
curl -s $URL/metrics | grep -E '^vllm:prefix_cache_hits_total'
curl -s $URL/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"agent","messages":[{"role":"user","content":"What is 2+2? Answer with just the number."}],"max_tokens":512}' >/dev/null
curl -s $URL/metrics | grep -E '^vllm:prefix_cache_hits_total'
```

Expected: the second number is higher than the first.

#### Close the ports

```bash
kill %1 %2
```

### Step 16: Negative checks (non-FIPS crypto is refused)

#### Control: the test client negotiates ChaCha20 with a server that allows it

```bash
kubectl run tls-control -n default --restart=Never --image=$REG/alpine/openssl:latest --command -- sh -c \
  'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=control -keyout /tmp/k -out /tmp/c 2>/dev/null && openssl s_server -accept 9443 -cert /tmp/c -key /tmp/k -www'
kubectl -n default wait --for=condition=Ready pod/tls-control --timeout=60s
CTRL_IP=$(kubectl -n default get pod tls-control -o jsonpath='{.status.podIP}')
probe s_client -connect $CTRL_IP:9443 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305 | grep 'Cipher is'
probe s_client -connect $CTRL_IP:9443 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 | grep 'Cipher is'
kubectl -n default delete pod tls-control --grace-period=0 --force
```

Expected:

```
New, TLSv1.2, Cipher is ECDHE-ECDSA-CHACHA20-POLY1305
New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256
```

#### Ingress refuses ChaCha20 over TLS 1.2

```bash
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_2 -cipher CHACHA20 | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
```

#### Ingress refuses ChaCha20 over TLS 1.3

```bash
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
```

#### Ingress refuses static-RSA and CBC suites

```bash
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_2 -cipher AES256-GCM-SHA384 | grep 'Cipher is'
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_2 -cipher 'ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA' | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
New, (NONE), Cipher is (NONE)
```

#### Ingress refuses TLS 1.1

```bash
probe s_client -connect $NODE_IP:443 -servername $HOST -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' | grep 'Cipher is'
```

Expected:

```
New, (NONE), Cipher is (NONE)
```

#### Pod refuses MD5

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- python -c "import hashlib; hashlib.md5(b'x')" 2>&1 | grep -o 'UnsupportedDigestmodError.*'
```

Expected:

```
UnsupportedDigestmodError: [digital envelope routines] unsupported
```

#### Non-FIPS prefix-cache hashers are absent in the pod

```bash
kubectl -n $NS exec deploy/$DEPLOY -c inference -- python -c "import xxhash" 2>&1 | grep -o "No module named.*"
kubectl -n $NS exec deploy/$DEPLOY -c inference -- python -c "import blake3" 2>&1 | grep -o "No module named.*"
```

Expected:

```
No module named 'xxhash'
No module named 'blake3'
```

### Rollback to Atlas

```bash
tar -C / -xpf /data/build/atlas-backup/phase6.tar
cd $STAGE
terraform apply
kubectl -n $NS rollout status deploy/$DEPLOY --timeout=40m
```

## FAQ

**Why does the Dockerfile copy the crypto policy in instead of running `update-crypto-policies --set FIPS`?**
On a FIPS host, Podman mounts the host's FIPS policy over `/etc/crypto-policies` in every container, including each `RUN` step of a build. `update-crypto-policies` then fails with `Error setting the current policy configuration`, and even on success its writes would land in the mount, not the image. The image would look FIPS under Podman and ship the DEFAULT policy to containerd (RKE2), which adds no such mounts. The `fips-policy` stage builds the FIPS policy tree in `/staging`, and `COPY` places it in the image. `COPY` is not affected by the mounts.

**Why read the policy with `podman image mount` instead of `podman exec ... update-crypto-policies --show`?**
Under Podman on a FIPS host, the runtime mount makes the in-container check report FIPS whether the image carries the policy or not. Reading the image files directly shows what containerd under RKE2 will load.

**Why use an Alpine OpenSSL container for the TLS checks?**
The host's `openssl` follows the FIPS policy, so it refuses to offer ChaCha20 or TLS 1.1 at all. A failed handshake from it proves the client is FIPS, not the server. Alpine OpenSSL ignores the RHEL crypto policy and offers every cipher. The control check proves it negotiates ChaCha20 when the server allows it, so a refusal from vLLM is the server's doing.

**The negative TLS checks also print `unexpected eof while reading`. Is that a failure?**
No. vLLM closes the connection without sending a TLS alert when no cipher matches. `Cipher is (NONE)` is the result that matters.

**`podman rm -f tls-control` prints `StopSignal SIGTERM failed ... resorting to SIGKILL`.**
Harmless. `openssl s_server` ignores SIGTERM.

**Why are `transformers` and `huggingface_hub` pinned?**
vLLM 0.29.0 only requires `transformers>=5.10.4`, so pip installs the newest release. `transformers` 5.17.0 rejects Laguna's per-layer-type `rope_parameters` with `AttributeError: 'str' object has no attribute 'get'`. The pins match the upstream `vllm/vllm-openai:v0.29.0` image.

**Why install `nvcc` and CUDA headers in a serving image?**
At model load, DeepGEMM (FP8 block kernels) and FlashInfer compile kernels on the fly. Without them the engine fails with `std::filesystem::exists(nvcc_path)` or `fatal error: curand.h: No such file or directory`. The packages match the set the upstream image ships. None of them contain crypto.

**Why CUDA 13.0 and the `cu130` PyTorch index?**
vLLM 0.29.0's default wheel targets CUDA 13.0. Driver 580 supports it.

**Why remove `blake3`, `xxhash` and `opencv-python-headless`?**
`blake3` and `xxhash` are non-FIPS hash options for vLLM's prefix cache; removing them means those code paths cannot run. `opencv-python-headless` bundles its own OpenSSL and is only needed for image inputs.

**Why doesn't the vLLM startup log show `prefix_caching_hash_algo=sha256`?**
sha256 is the default in vLLM 0.29, and the log only lists non-default arguments. The check reads the passed flag and the effective config value instead.

**The logs show `kv_cache_dtype=torch.float8_e4m3fn`, but `--kv-cache-dtype` was not set.**
The checkpoint's `compressed-tensors` config declares an FP8 KV cache scheme, so vLLM picks FP8 on its own. This is unrelated to FIPS.

**The build fails with `short-name resolution enforced but cannot prompt without a TTY`.**
Use fully qualified image names (`docker.io/...`), as in the Dockerfile and commands above.

**`hf: command not found` as root.**
On the RHEL AMI, root's `PATH` does not include `/usr/local/bin`, even under `sudo -i`. The setup block adds it. Otherwise call `/usr/local/bin/hf` directly.

**Prefix cache hits start at 0.**
Expected on a freshly started server. The first request populates the cache; hits appear from the second matching request on.

**The download is slow or uses a different TLS stack than expected.**
`HF_HUB_DISABLE_XET=1` keeps the download on Python and the system OpenSSL. Without it, `hf` uses `hf_xet`, which ships its own Rust TLS stack.

**SSH to the host stopped working after enabling FIPS.**
The RHEL 9 FIPS policy rejects ED25519 SSH keys. Authorize an RSA or ECDSA key before enabling FIPS.

**Port 8443 is not reachable from my laptop.**
The checks run on the host. To reach the API remotely, tunnel it: `ssh -L 8443:localhost:8443 ec2-user@<host>`, or open 8443 in the firewall or security group.

**What crypto in the image is not covered by the FIPS module?**
The `cryptography` wheel statically links its own OpenSSL (4.0.2, not FIPS), and `grpcio` bundles BoringSSL. Neither is on the inference request path. If policy forbids any unvalidated crypto on disk, both need rebuilding against the system OpenSSL.

**The base image reports RHEL 9.6 while the host is 9.7.**
Expected. The container uses its own OpenSSL userspace with the host kernel's FIPS flag.

### RKE2 (Part 2B)

**Why patch files instead of only editing `terraform.tfvars`?**
Four things the FIPS deployment needs cannot be set through `06-poolside-inference/terraform.tfvars`:
- The chart hard-codes `--self-contained-checkpoint`, an Atlas-only flag. vLLM exits with `vllm: error: unrecognized arguments: --self-contained-checkpoint`.
- The image registry and name come from `poolside-install/poolside_registries_config.json`, and the tag from the chart's `.poolside_dependency_manifest.yml`.
- `06-poolside-inference/locals.tf` hard-codes `model_type = "agent"`. The chart turns that into `--agent` (Atlas-only) and `--distributed-executor-backend mp`, and `model_extra_args` cannot remove them.
- `models_config` has no `model_type` field.

Everything else Terraform computes (S3 secret, S3 CA bundle, service account, pod security context, Envoy proxy) is left as it was.

**Why not `helm upgrade`?**
The bundle ships no `helm` CLI, and phase 6 manages the release through the Terraform helm provider. A manual `helm upgrade` is reverted by the next `terraform apply` in phase 6.

**Does re-running Terraform undo the patch?**
`terraform apply` and plain `terraform init` keep it. `terraform init -upgrade`, deleting `.terraform`, or re-extracting the bundle restores the Atlas chart and manifest; repeat Steps 9 and 10. Re-applying `03-infra-services` rewrites `poolside_registries_config.json` with `container_name: atlas`; repeat Step 10. Then repeat Steps 12 and 13.

**INSTALL.md sets `model_type` and `ingress_host_name` under `models_config`. Do they do anything?**
No. `models_config` defines only `gpus`, `replicas` and `model_extra_args`, and Terraform drops other keys without a warning. 2026.07.07 creates no model ingress, and the model type comes from `locals.tf`.

**`gpus` and `tensor-parallel-size`.**
`locals.tf` defaults `agent` to `gpus = 2`, so set `gpus` in `models_config`. The chart sets the GPU resource from `gpus` but does not pass `--tensor-parallel-size`. Set it in `model_extra_args` to match `gpus`.

**Why `--port 8080`?**
The chart's Service, liveness, readiness and startup probes all target port 8080. vLLM listens on 8000 by default.

**Why is the `default-chat-template-kwargs` JSON not escaped?**
In 2026.07.07, phase 6 passes `model_extra_args` to Helm as YAML values, so the string arrives unchanged. Bundles that pass model arguments through helm provider `set` entries parse braces and commas. There, write it as `"\\{\"enable_thinking\": true\\}"`; unescaped, it renders as `["enable_thinking": true]`.

**Is the model unavailable during the switch?**
Yes. The chart rolls out with `maxSurge: 0` and `maxUnavailable: 1`, so the Atlas pod stops before the vLLM pod starts. The model returns once the checkpoint download and vLLM start-up finish. `terraform apply` returns before that, which is why Step 13 waits on `rollout status`.

**Why does the image include the AWS CLI?**
The chart's `model-downloader` init container runs `aws s3 sync` in the same image as the server. The pip `awscli` package (v1) runs on the image's RHEL Python and OpenSSL. AWS CLI v2 ships its own Python and OpenSSL and is not used for that reason.

**botocore reports `MD5_AVAILABLE: True` under FIPS.**
botocore calls `hashlib.md5(usedforsecurity=False)` for S3 `Content-MD5` integrity checksums. RHEL's FIPS OpenSSL allows MD5 for non-security use when requested that way. Security-use MD5 (`hashlib.md5(b'x')`) is still refused, as the negative checks show. List this for the security team.

**Why `HOME=/tmp` in the image?**
Phase 6 sets `runAsUser: 10003` and `runAsNonRoot: true`. UID 10003 has no home directory, and vLLM, Triton, FlashInfer and DeepGEMM write JIT and compile caches under `$HOME`. Verified: the server starts and serves as UID 10003 with all capabilities dropped.

**Where is TLS terminated on RKE2?**
At the RKE2 ingress-nginx controller, for the Poolside platform host. RKE2 documents ingress-nginx as using a FIPS-validated OpenSSL. The models have no ingress in 2026.07.07: the platform reaches them through the `inference-envoy-internal` Service, and vLLM serves plain HTTP on port 8080. The `--ssl-*` arguments from Part 2A are not used, and the TLS negative checks test the ingress. In-cluster traffic from the platform through Envoy to the pod is plaintext.

**Are the Envoy proxy and external processor FIPS images?**
No. Phase 6 deploys `envoyproxy/envoy` and `forge_api` unchanged. Neither terminates TLS in this deployment, so no crypto runs on the request path inside them. List both for the security team.

**Why is `update-crypto-policies --show` meaningful in the pod but not under Podman?**
Podman on a FIPS host mounts the host's FIPS policy over `/etc/crypto-policies` in every container. containerd adds no such mounts, so the pod reports what the image carries. The `/proc/mounts` check proves no mount is present.

**Why `--dest-tls-verify=false` on skopeo?**
The RKE2 registry on `localhost:30500` serves plain HTTP. If the bundle's `registries.conf` entry for the registry (`insecure = true`) is installed, the flag is unnecessary but harmless.

**The digest in the registry differs from `podman image inspect`.**
Expected. skopeo recompresses layers when copying from local storage, which changes the manifest digest. The image content is the same.

**The cluster has no internet access. How do I get the images in?**
On a connected host, save both images to tars:

```bash
podman save -o vllm-openai-fips-0.29.0.tar localhost/vllm-openai-fips:0.29.0
skopeo copy docker://docker.io/alpine/openssl:latest docker-archive:alpine-openssl.tar:alpine/openssl:latest
```

Transfer them, then use the `docker-archive:` form of Step 5 for each.

**The model downloader pulls `DFlash/`.**
The chart's `aws s3 sync` includes `DFlash/*`. Without `--speculative-config` vLLM ignores it, at the cost of the extra download.

**Why write `regcfg.json` back with `cat` instead of `mv`?**
`cat >` keeps the owner and `0640` mode phase 3 set on `poolside_registries_config.json`. Later phases read it as the installing user.

**The NVIDIA driver on a FIPS host.**
The bundle's GPU operator installs the driver by default. On a FIPS host the driver should come from dnf, as in the build host prerequisites, so set the GPU operator's `driver.enabled=false` to use the host driver.
