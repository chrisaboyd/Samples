#!/usr/bin/env python3
"""Standalone client for the NVIDIA RAG server and ingestor server.

Run after rag_deploy.py has brought the containers up:

    python rag_server.py all                       # health -> collection -> upload -> query
    python rag_server.py health
    python rag_server.py collections list
    python rag_server.py collections create multimodal_data
    python rag_server.py collections delete multimodal_data1
    python rag_server.py upload --collection multimodal_data --data-dir /path/to/docs
    python rag_server.py query "Who is Nicholas Duvernay's character related to?"
    python rag_server.py chat "Hi"                 # LLM only, no knowledge base

Connection settings come from environment variables (or a .env file), so the
same script works from the host or from inside the docker network:

    RAG_HOST / RAG_PORT            default localhost / 8081
    INGESTOR_HOST / INGESTOR_PORT  default localhost / 8082
    VDB_ENDPOINT                   default http://milvus:19530 (resolved by the containers)
    APP_LLM_MODELNAME              LLM used for chat/query
    RAG_DATA_DIR                   default ./data/multimodal
"""

import argparse
import asyncio
import json
import mimetypes
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import List, Optional

import aiohttp
from dotenv import load_dotenv

load_dotenv()
load_dotenv(Path.home() / ".env")

RAG_BASE_URL = f"http://{os.environ.get('RAG_HOST', 'localhost')}:{os.environ.get('RAG_PORT', '8081')}"
INGESTOR_BASE_URL = f"http://{os.environ.get('INGESTOR_HOST', 'localhost')}:{os.environ.get('INGESTOR_PORT', '8082')}"

# Milvus is reached by the containers, not by this script, so this is the docker-network name.
VDB_ENDPOINT = os.environ.get("VDB_ENDPOINT", "http://milvus:19530")
DEFAULT_MODEL = "nvidia/nemotron-3.5-super-vl-120b-a12b"
DEFAULT_COLLECTION = "multimodal_data"
DEFAULT_DATA_DIR = os.environ.get("RAG_DATA_DIR", "data/multimodal")

# The RAG server defaults `stop` to [] and forwards it to the hosted NVIDIA API, which rejects
# it ("Stop sequences array cannot be empty"). The server's error path then crashes mid-stream.
# Any non-empty stop list avoids this; this token never appears in normal output.
DEFAULT_STOP = ["<|im_end|>"]

# Ingestion states that mean the task is finished.
TERMINAL_STATES = {"FINISHED", "FAILED"}


def llm_model() -> str:
    return os.environ.get("APP_LLM_MODELNAME", DEFAULT_MODEL)


async def print_raw_response(response: aiohttp.ClientResponse) -> None:
    """Pretty-print a JSON response, falling back to raw text."""
    text = await response.text()
    try:
        print(json.dumps(json.loads(text), indent=2))
    except json.JSONDecodeError:
        print(text)
    if response.status >= 400:
        raise RuntimeError(f"HTTP {response.status} from {response.url}")


async def check_health(base_url: str, label: str) -> None:
    print(f"\nTesting {label} health endpoint")
    print("-" * 60)
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{base_url}/v1/health") as response:
            await print_raw_response(response)


async def chat_completion(prompt: str = "Hi") -> None:
    """Basic chat completion without the knowledge base."""
    payload = {
        "messages": [{"role": "user", "content": prompt}],
        "use_knowledge_base": False,
        "temperature": 0.2,
        "stop": DEFAULT_STOP,
        "model": llm_model(),
    }
    url =f"{RAG_BASE_URL}/v1/chat/completions"
    print("\nTesting chat completion endpoint")
    print("-" * 60)
    print("Sending request to:", url)
    print("With payload:", json.dumps(payload, indent=2))
    await generate_answer(payload)


async def create_collections(
    collection_names: Optional[List[str]] = None,
    collection_type: str = "text",
    embedding_dimension: int = 2048,
) -> None:
    """Create one or more collections in the vector store."""
    params = {
        "vdb_endpoint": VDB_ENDPOINT,
        "collection_type": collection_type,
        "embedding_dimension": embedding_dimension,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{INGESTOR_BASE_URL}/v1/collections",
            params=params,
            json=collection_names or [],
            headers={"Content-Type": "application/json"},
        ) as response:
            await print_raw_response(response)


async def fetch_collections() -> None:
    """List all collections in the vector store."""
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{INGESTOR_BASE_URL}/v1/collections", params={"vdb_endpoint": VDB_ENDPOINT}
        ) as response:
            await print_raw_response(response)


async def delete_collections(collection_names: Optional[List[str]] = None) -> None:
    """Delete the named collections from the vector store."""
    async with aiohttp.ClientSession() as session:
        async with session.delete(
            f"{INGESTOR_BASE_URL}/v1/collections",
            params={"vdb_endpoint": VDB_ENDPOINT},
            json=collection_names or [],
        ) as response:
            await print_raw_response(response)


async def wait_for_ingestion(task_id: str, timeout: float = 1800, interval: float = 5) -> bool:
    """Poll the ingestor until the upload task finishes. Returns True on success."""
    print(f"\nWaiting for ingestion task {task_id} ...")
    deadline = asyncio.get_event_loop().time() + timeout
    async with aiohttp.ClientSession() as session:
        while asyncio.get_event_loop().time() < deadline:
            async with session.get(
                f"{INGESTOR_BASE_URL}/v1/status", params={"task_id": task_id}
            ) as response:
                body = await response.json(content_type=None)
            state = str(body.get("state", "")).upper()
            print(f"  state: {state or 'UNKNOWN'}", flush=True)
            if state in TERMINAL_STATES:
                print(json.dumps(body, indent=2))
                return state == "FINISHED" and not body.get("result", {}).get("failed_documents")
            await asyncio.sleep(interval)
    print("Timed out waiting for ingestion to finish.", file=sys.stderr)
    return False


async def upload_documents(
    collection_name: str = DEFAULT_COLLECTION,
    data_dir: str = DEFAULT_DATA_DIR,
    wait: bool = True,
) -> None:
    """Upload every file in data_dir to a collection and (optionally) wait for indexing.

    Extraction uses the ingestor defaults (text, tables, charts); text is
    chunked at 1024 tokens with 150 overlap.
    """
    directory = Path(data_dir).expanduser().resolve()
    files = sorted(p for p in directory.iterdir() if p.is_file()) if directory.is_dir() else []
    if not files:
        raise FileNotFoundError(f"No files to upload in {directory}")

    data = {
        "vdb_endpoint": VDB_ENDPOINT,
        "collection_name": collection_name,
        "split_options": {"chunk_size": 1024, "chunk_overlap": 150},
    }

    print(f"\nUploading {len(files)} files from {directory} to '{collection_name}'")
    with ExitStack() as stack:
        form_data = aiohttp.FormData()
        for path in files:
            content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            form_data.add_field(
                "documents", stack.enter_context(open(path, "rb")),
                filename=path.name, content_type=content_type,
            )
        form_data.add_field("data", json.dumps(data), content_type="application/json")

        # Use session.patch instead of post to re-ingest existing documents.
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{INGESTOR_BASE_URL}/v1/documents", data=form_data) as response:
                text = await response.text()
                print(text)
                if response.status >= 400:
                    raise RuntimeError(f"Upload failed: HTTP {response.status}")

    task_id = json.loads(text).get("task_id") if text.strip().startswith("{") else None
    if wait and task_id:
        if not await wait_for_ingestion(task_id):
            raise RuntimeError("Ingestion did not finish successfully")


def _error_message(body: str) -> str:
    """Pull the human-readable message out of an error body (plain JSON or SSE chunks)."""
    messages = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            line = line[len("data:"):].strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        text = ((obj.get("choices") or [{}])[0].get("message") or {}).get("content") or obj.get("detail") or obj.get("message")
        if text:
            messages.append(str(text))
    return " ".join(messages) or body.strip()


async def generate_answer(payload: dict) -> str:
    """POST to the RAG server, print the answer, and return it.

    Handles both streaming (text/event-stream) and plain JSON responses.
    """
    url = f"{RAG_BASE_URL}/v1/chat/completions"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as response:
            if response.status >= 400:
                raise RuntimeError(f"HTTP {response.status}: {_error_message(await response.text())}")

            if "text/event-stream" in response.headers.get("Content-Type", ""):
                answer = ""
                async for raw in response.content:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    chunk = line[len("data:"):].strip()
                    if chunk == "[DONE]":
                        break
                    try:
                        choices = json.loads(chunk).get("choices") or [{}]
                    except json.JSONDecodeError:
                        continue
                    piece = (choices[0].get("delta") or {}).get("content") or ""
                    answer += piece
                    print(piece, end="", flush=True)
                print()
                return answer

            body = await response.json(content_type=None)
            if "error" in body:
                raise RuntimeError(f"RAG server error: {body['error']}")
            answer = (body.get("choices") or [{}])[0].get("message", {}).get("content", "")
            print(answer)
            return answer


def build_query_payload(question: str, collection_name: str = DEFAULT_COLLECTION) -> dict:
    return {
        "messages": [{"role": "user", "content": question}],
        "use_knowledge_base": True,
        "temperature": 0.2,
        "top_p": 0.7,
        "max_tokens": 1024,
        "reranker_top_k": 10,
        "vdb_top_k": 100,
        "vdb_endpoint": VDB_ENDPOINT,
        "collection_name": collection_name,
        "enable_query_rewriting": False,
        # rag_deploy.py sets ENABLE_RERANKER=false, so follow that unless overridden.
        "enable_reranker": os.environ.get("ENABLE_RERANKER", "false").lower() == "true",
        "enable_guardrails": False,
        "enable_citations": True,
        "model": llm_model(),
        "llm_endpoint": "https://integrate.api.nvidia.com/v1/chat/completions",
        "embedding_model": "nvidia/nemotron-3.5-embed-1b",
        "reranker_model": "nvidia/llama-nemotron-rerank-vl-1b-v2",
        "stop": DEFAULT_STOP,
    }


async def query_knowledge_base(question: str, collection_name: str = DEFAULT_COLLECTION) -> str:
    print(f"\nQuerying '{collection_name}': {question}")
    print("-" * 60)
    return await generate_answer(build_query_payload(question, collection_name))


async def run_all(args: argparse.Namespace) -> None:
    await check_health(RAG_BASE_URL, "RAG server")
    await check_health(INGESTOR_BASE_URL, "Ingestor server")
    await chat_completion("Hi")
    await create_collections([args.collection])
    await fetch_collections()
    await upload_documents(args.collection, args.data_dir)
    await query_knowledge_base(args.question, args.collection)


async def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_collection_and_data(p: argparse.ArgumentParser) -> None:
        p.add_argument("--collection", default=DEFAULT_COLLECTION)
        p.add_argument("--data-dir", default=DEFAULT_DATA_DIR)

    p_all = sub.add_parser("all", help="health, create collection, upload, query")
    add_collection_and_data(p_all)
    p_all.add_argument("--question", default="Who is Nicholas Duvernay's character related to?")

    sub.add_parser("health", help="check RAG and ingestor health")

    p_chat = sub.add_parser("chat", help="chat without the knowledge base")
    p_chat.add_argument("prompt", nargs="?", default="Hi")

    p_col = sub.add_parser("collections", help="manage collections")
    p_col.add_argument("action", choices=["list", "create", "delete"])
    p_col.add_argument("names", nargs="*")

    p_up = sub.add_parser("upload", help="upload documents and wait for ingestion")
    add_collection_and_data(p_up)
    p_up.add_argument("--no-wait", action="store_true", help="don't poll for ingestion status")

    p_q = sub.add_parser("query", help="ask a question against the knowledge base")
    p_q.add_argument("question")
    p_q.add_argument("--collection", default=DEFAULT_COLLECTION)

    args = parser.parse_args(argv)

    try:
        if args.command == "all":
            await run_all(args)
        elif args.command == "health":
            await check_health(RAG_BASE_URL, "RAG server")
            await check_health(INGESTOR_BASE_URL, "Ingestor server")
        elif args.command == "chat":
            await chat_completion(args.prompt)
        elif args.command == "collections":
            if args.action == "list":
                await fetch_collections()
            elif not args.names:
                parser.error(f"collections {args.action} needs at least one name")
            elif args.action == "create":
                await create_collections(args.names)
            else:
                await delete_collections(args.names)
        elif args.command == "upload":
            await upload_documents(args.collection, args.data_dir, wait=not args.no_wait)
        elif args.command == "query":
            await query_knowledge_base(args.question, args.collection)
    except aiohttp.ClientPayloadError as e:
        print(
            f"Error: the RAG server cut the response short ({e}).\n"
            "This means it hit an error while generating. Check `docker logs rag-server` "
            "(look for lines starting 'ERROR:nvidia_rag').",
            file=sys.stderr,
        )
        return 1
    except (aiohttp.ClientError, RuntimeError, FileNotFoundError, asyncio.TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
