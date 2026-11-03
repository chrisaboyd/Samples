#!/usr/bin/env python3
"""Deploy the NVIDIA RAG blueprint (vector DB, ingestor, RAG server) with docker compose.

    python rag_deploy.py --repo-dir /path/to/rag

The repo's compose files are never modified. Tweaked copies are written next to
them as *.generated.yaml (same directory, so relative paths keep working) and
those are what get deployed.

Settings (flag or environment variable):
    --repo-dir / RAG_REPO_DIR     checkout of the NVIDIA RAG repo (default: ./rag if present, else cwd)
    --keep-milvus-gpu             keep Milvus' GPU reservation (default: removed, CPU-only Milvus)
    MINIO_IMAGE                   default cgr.dev/chainguard/minio:latest
"""

import argparse
import getpass
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml
from dotenv import load_dotenv

MINIO_IMAGE = os.environ.get("MINIO_IMAGE", "cgr.dev/chainguard/minio:latest")
COMPOSE_DIR = Path("deploy/compose")

# Hosted NIM endpoints. Empty server URLs make the services use the NVIDIA API catalog.
LLM_MODEL = "nvidia/nemotron-3.5-super-vl-120b-a12b"
HOSTED_ENV = {
    "APP_EMBEDDINGS_SERVERURL": "",
    "APP_LLM_SERVERURL": "",
    "APP_LLM_MODELNAME": LLM_MODEL,
    "APP_FILTEREXPRESSIONGENERATOR_MODELNAME": LLM_MODEL,
    "APP_FILTEREXPRESSIONGENERATOR_SERVERURL": "",
    "SUMMARY_LLM": LLM_MODEL,
    "APP_RANKING_SERVERURL": "",
    "SUMMARY_LLM_SERVERURL": "",
    "OCR_HTTP_ENDPOINT": "https://ai.api.nvidia.com/v1/cv/baidu/paddleocr",
    "OCR_INFER_PROTOCOL": "http",
    "OCR_MODEL_NAME": "paddle",
    "YOLOX_HTTP_ENDPOINT": "https://ai.api.nvidia.com/v1/cv/nvidia/nemoretriever-page-elements-v2",
    "YOLOX_INFER_PROTOCOL": "http",
    "YOLOX_GRAPHIC_ELEMENTS_HTTP_ENDPOINT": "https://ai.api.nvidia.com/v1/cv/nvidia/nemoretriever-graphic-elements-v1",
    "YOLOX_GRAPHIC_ELEMENTS_INFER_PROTOCOL": "http",
    "YOLOX_TABLE_STRUCTURE_HTTP_ENDPOINT": "https://ai.api.nvidia.com/v1/cv/nvidia/nemoretriever-table-structure-v1",
    "YOLOX_TABLE_STRUCTURE_INFER_PROTOCOL": "http",
    "APP_QUERYREWRITER_SERVERURL": "",
    "APP_QUERYREWRITER_MODELNAME": LLM_MODEL,
    "APP_VECTORSTORE_ENABLEGPUSEARCH": "False",
    "APP_VECTORSTORE_ENABLEGPUINDEX": "False",
    "ENABLE_RERANKER": "false",
}


class DeployError(RuntimeError):
    pass


def run(cmd, what, show_stdout=False):
    """Run a command, raising DeployError with stderr if it fails."""
    print(f"{what}...", flush=True)
    try:
        result = subprocess.run(cmd, env=os.environ, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise DeployError(f"{what} failed:\n{e.stderr or e.stdout}") from e
    except FileNotFoundError as e:
        raise DeployError(f"{what} failed: {e}") from e
    if show_stdout and result.stdout:
        print(result.stdout, flush=True)
    print(f"✅ {what}: done", flush=True)


def show_containers():
    subprocess.run(["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"], env=os.environ)


def find_repo_dir(arg):
    candidates = [arg, os.environ.get("RAG_REPO_DIR"), "rag", "."]
    for c in candidates:
        if c and (Path(c) / COMPOSE_DIR / "vectordb.yaml").is_file():
            return Path(c).resolve()
    raise DeployError(
        "Could not find the NVIDIA RAG repo (deploy/compose/vectordb.yaml). "
        "Pass --repo-dir or set RAG_REPO_DIR."
    )


def setup_environment(repo_dir):
    load_dotenv(repo_dir / COMPOSE_DIR / ".env")
    load_dotenv(Path.home() / ".env")

    if not os.environ.get("NGC_API_KEY", "").startswith("nvapi-"):
        key = getpass.getpass("Enter your NVIDIA NGC API key: ")
        if not key.startswith("nvapi-"):
            raise DeployError(f"{key[:5]}... is not a valid NGC API key")
        os.environ["NGC_API_KEY"] = key
        print("✅ API key has been set in environment")
    else:
        print("✅ API key has been detected from environment")

    os.environ["USERID"] = str(os.getuid())
    print(f"✅ USERID set to {os.environ['USERID']}")

    # The compose file's ${PROMPT_CONFIG_FILE} mount needs an absolute path (see deploy/compose/.env).
    os.environ.setdefault("PROMPT_CONFIG_FILE", str(repo_dir / "src/nvidia_rag/rag_server/prompt.yaml"))

    os.environ.update(HOSTED_ENV)


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def write_generated(src, data):
    """Write data as <name>.generated.yaml beside src and return the new path."""
    dest = src.with_name(src.stem + ".generated" + src.suffix)
    with open(dest, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    return dest


def patch_vectordb(repo_dir, keep_milvus_gpu):
    src = repo_dir / COMPOSE_DIR / "vectordb.yaml"
    data = load_yaml(src)
    services = data.get("services", {})

    if not keep_milvus_gpu:
        if "deploy" in services.get("milvus", {}):
            del services["milvus"]["deploy"]
            print("✓ Removed services.milvus.deploy (no GPU requirement)")
        else:
            print("! services.milvus.deploy not found; nothing to remove")

    # minio/minio is no longer published on Docker Hub; swap in a maintained image
    if "minio" in services:
        services["minio"]["image"] = MINIO_IMAGE
        # the image's entrypoint is already the minio binary, so drop the leading "minio"
        services["minio"]["command"] = 'server /minio_data --console-address ":9011" --address ":9010"'
        # no curl in this image, so the compose healthcheck can't run
        services["minio"].pop("healthcheck", None)
        print(f"✓ Replaced minio image with {MINIO_IMAGE}")

    return write_generated(src, data)


def patch_ingestor(repo_dir):
    src = repo_dir / COMPOSE_DIR / "docker-compose-ingestor-server.yaml"
    data = load_yaml(src)
    svc = data["services"]["nv-ingest-ms-runtime"]

    # The compose file pins nv-ingest-ms-runtime to cpuset "0-15"; drop it on hosts with fewer CPUs.
    cpuset = svc.get("cpuset")
    if cpuset and (os.cpu_count() or 0) < 16:
        del svc["cpuset"]
        print(f"✓ Removed cpuset {cpuset} from nv-ingest-ms-runtime ({os.cpu_count()} CPUs available)")

    # Ray needs more than Docker's default 64MB /dev/shm
    svc["shm_size"] = "4gb"
    svc["restart"] = "unless-stopped"
    return write_generated(src, data)


def compose_up(compose_file, name, repo_dir):
    f = str(compose_file)
    run(["docker", "compose", "-f", f, "pull", "--quiet"], f"Pulling {name} images")
    run(["docker", "compose", "-f", f, "up", "-d"], f"Starting {name}", show_stdout=True)
    show_containers()


def wait_for_health(url, name, timeout=600):
    print(f"Waiting for {name} at {url} ...", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status == 200:
                    print(f"✅ {name} is healthy", flush=True)
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(5)
    print(f"⚠️  {name} did not become healthy within {timeout}s (check `docker logs`)", file=sys.stderr)
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-dir", help="path to the NVIDIA RAG repo checkout")
    parser.add_argument("--keep-milvus-gpu", action="store_true", help="don't strip Milvus' GPU reservation")
    parser.add_argument("--no-wait", action="store_true", help="don't wait for the servers' health endpoints")
    args = parser.parse_args(argv)

    try:
        repo_dir = find_repo_dir(args.repo_dir)
        os.chdir(repo_dir)
        print(f"Using RAG repo at {repo_dir}")
        setup_environment(repo_dir)

        compose_up(patch_vectordb(repo_dir, args.keep_milvus_gpu), "vector database", repo_dir)
        compose_up(patch_ingestor(repo_dir), "Ingestor Server", repo_dir)
        compose_up(repo_dir / COMPOSE_DIR / "docker-compose-rag-server.yaml", "RAG microservices", repo_dir)
    except DeployError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1

    print("Started RAG Microservices")
    print("-" * 60)

    if not args.no_wait:
        wait_for_health("http://localhost:8081/v1/health", "RAG server")
        wait_for_health("http://localhost:8082/v1/health", "Ingestor server")
    return 0


if __name__ == "__main__":
    sys.exit(main())
