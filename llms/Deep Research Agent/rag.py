import os
import yaml
import getpass
from dotenv import load_dotenv

os.chdir('/Users/cboyd/gitrepos/rag')

load_dotenv("deploy/compose/.env")
load_dotenv("/Users/cboyd/.env")

# Get NGC Key from Environment
if not os.environ.get("NGC_API_KEY", "").startswith("nvapi-"):
    nvapi_key = getpass.getpass("Enter your NVIDIA NGC API key: ")
    assert nvapi_key.startswith("nvapi-"), f"{nvapi_key[:5]}... is not a valid key"
    os.environ["NGC_API_KEY"] = nvapi_key
    print("✅ API key has been set in notebook environment")
else:
    print("✅ API key has been detected from environment")


import subprocess
import sys

print("Getting current user ID...", flush=True)
try:
    os.environ["USERID"] = subprocess.check_output("id -u", shell=True).decode().strip()
    print(f"✅ USERID set to {os.environ['USERID']}", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Failed to get USERID.", file=sys.stderr)
    print(e.stderr if hasattr(e, 'stderr') else e.output, file=sys.stderr)
    sys.exit(1)

# nvidia/nemotron-3.5-embed-1b
# nvidia/llama-nemotron-rerank-vl-1b-v2
#Set the endpoint urls of the Hosted NIMs
os.environ["APP_EMBEDDINGS_SERVERURL"] = ""
os.environ["APP_LLM_SERVERURL"] = ""
os.environ["APP_LLM_MODELNAME"] = "nvidia/nemotron-3.5-super-vl-120b-a12b"
os.environ["APP_FILTEREXPRESSIONGENERATOR_MODELNAME"] = "nvidia/nemotron-3.5-super-vl-120b-a12b"
os.environ["APP_FILTEREXPRESSIONGENERATOR_SERVERURL"] = ""
os.environ["SUMMARY_LLM"] = "nvidia/nemotron-3.5-super-vl-120b-a12b"
os.environ["APP_RANKING_SERVERURL"] = ""
os.environ["SUMMARY_LLM_SERVERURL"] = ""
os.environ["OCR_HTTP_ENDPOINT"] = "https://ai.api.nvidia.com/v1/cv/baidu/paddleocr"
os.environ["OCR_INFER_PROTOCOL"] = "http"
os.environ["OCR_MODEL_NAME"] = "paddle"
os.environ["YOLOX_HTTP_ENDPOINT"] = "https://ai.api.nvidia.com/v1/cv/nvidia/nemoretriever-page-elements-v2"
os.environ["YOLOX_INFER_PROTOCOL"] = "http"
os.environ["YOLOX_GRAPHIC_ELEMENTS_HTTP_ENDPOINT"] = "https://ai.api.nvidia.com/v1/cv/nvidia/nemoretriever-graphic-elements-v1"
os.environ["YOLOX_GRAPHIC_ELEMENTS_INFER_PROTOCOL"] = "http"
os.environ["YOLOX_TABLE_STRUCTURE_HTTP_ENDPOINT"] = "https://ai.api.nvidia.com/v1/cv/nvidia/nemoretriever-table-structure-v1"
os.environ["YOLOX_TABLE_STRUCTURE_INFER_PROTOCOL"] = "http"
os.environ["APP_QUERYREWRITER_SERVERURL"] = ""
os.environ["APP_QUERYREWRITER_MODELNAME"] = "nvidia/nemotron-3.5-super-vl-120b-a12b"
os.environ["APP_VECTORSTORE_ENABLEGPUSEARCH"] = "False"
os.environ["APP_VECTORSTORE_ENABLEGPUINDEX"] = "False"
os.environ["ENABLE_RERANKER"] = "false"



file_path = 'deploy/compose/vectordb.yaml'

with open(file_path, 'r') as f:
    data = yaml.safe_load(f)

# Navigate and remove the deploy key - disable GPU requirement on Milvus
if 'services' in data and 'milvus' in data['services']:
    if 'deploy' in data['services']['milvus']:
        del data['services']['milvus']['deploy']
        print("✓ Removed services.milvus.deploy entry")
    else:
        print("! deploy key not found under services.milvus")
else:
    print("! services.milvus not found in YAML structure")

# minio/minio is no longer published on Docker Hub; swap in a maintained image
if 'minio' in data.get('services', {}):
    data['services']['minio']['image'] = "cgr.dev/chainguard/minio:latest"
    # image's entrypoint is already the minio binary, so drop the leading "minio"
    data['services']['minio']['command'] = 'server /minio_data --console-address ":9011" --address ":9010"'
    # no curl in this image, so the compose healthcheck can't run
    data['services']['minio'].pop('healthcheck', None)
    print("✓ Replaced minio image")

# Write back
with open(file_path, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print("✓ File updated successfully")

print("Pulling vector database images...", flush=True)
try:
    pull_result = subprocess.run(
        ["docker", "compose", "-f", "deploy/compose/vectordb.yaml", "pull", "--quiet"],
        env=os.environ,
        check=True,
        capture_output=True,
        text=True
    )
    print("✅ Images pulled successfully.", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Failed to pull images.", file=sys.stderr)
    print(e.stderr, file=sys.stderr)
    sys.exit(1)  # Exit early since next step depends on successful pull

print("Starting vector database...", flush=True)
try:
    result = subprocess.run(
        ["docker", "compose", "-f", "deploy/compose/vectordb.yaml", "up", "-d"],
        env=os.environ,
        check=True,
        capture_output=True,
        text=True
    )
    print(result.stdout, flush=True)
    print("✅ Docker Compose is up and running.", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Docker Compose failed.", file=sys.stderr)
    print(e.stderr, file=sys.stderr)
    sys.exit(1)

# Check running containers
subprocess.run(['docker', 'ps', '--format', 'table {{.Names}}\t{{.Status}}'])

# The compose file pins nv-ingest-ms-runtime to cpuset "0-15"; the Docker VM here has fewer CPUs
ingestor_file = 'deploy/compose/docker-compose-ingestor-server.yaml'
with open(ingestor_file, 'r') as f:
    ingestor_data = yaml.safe_load(f)
nv_ingest_svc = ingestor_data['services']['nv-ingest-ms-runtime']
if nv_ingest_svc.pop('cpuset', None):
    print("✓ Removed cpuset from nv-ingest-ms-runtime")
# Ray needs more than Docker's default 64MB /dev/shm
nv_ingest_svc['shm_size'] = '4gb'
nv_ingest_svc['restart'] = 'unless-stopped'
with open(ingestor_file, 'w') as f:
    yaml.dump(ingestor_data, f, default_flow_style=False, sort_keys=False)

print("Pulling Ingestor Server images...", flush=True)
try:
    pull_result = subprocess.run(
        ["docker", "compose", "-f", "deploy/compose/docker-compose-ingestor-server.yaml", "pull", "--quiet"],
        env=os.environ,
        check=True,
        capture_output=True,
        text=True
    )
    print("✅ Ingestor images pulled successfully.", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Failed to pull Ingestor images.", file=sys.stderr)
    print(e.stderr, file=sys.stderr)
    sys.exit(1)

print("Starting Ingestor Server containers with build...", flush=True)
try:
    up_result = subprocess.run(
        ["docker", "compose", "-f", "deploy/compose/docker-compose-ingestor-server.yaml", "up", "-d"],
        env=os.environ,
        check=True,
        capture_output=True,
        text=True
    )
    print(up_result.stdout, flush=True)
    print("✅ Ingestor Server containers are up and running.", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Failed to start Ingestor Server containers.", file=sys.stderr)
    print(e.stderr, file=sys.stderr)
    sys.exit(1)

# Optionally check running containers
subprocess.run(
    ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"],
    env=os.environ
)

compose_file = "deploy/compose/docker-compose-rag-server.yaml"

print("Pulling RAG microservice images...", flush=True)
try:
    pull_result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "pull", "--quiet"],
        env=os.environ,
        check=True,
        capture_output=True,
        text=True
    )
    print("✅ RAG images pulled successfully.", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Failed to pull RAG images.", file=sys.stderr)
    print(e.stderr, file=sys.stderr)
    sys.exit(1)

print("Starting RAG microservices...", flush=True)
try:
    up_result = subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d"],
        env=os.environ,
        check=True,
        capture_output=True,
        text=True
    )
    print(up_result.stdout, flush=True)
    print("✅ RAG microservices are up and running.", flush=True)
except subprocess.CalledProcessError as e:
    print("❌ Failed to start RAG microservices.", file=sys.stderr)
    print(e.stderr, file=sys.stderr)
    sys.exit(1)

print("Started RAG Microservices", flush=True)
print("-" * 60, flush=True)

# Optional: Check running containers
subprocess.run(
    ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"],
    env=os.environ
)