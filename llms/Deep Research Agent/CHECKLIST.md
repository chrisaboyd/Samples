# RAG script fix checklist

## rag_server.py
- [x] Remove top-level `await`; wrap everything in `async def main()` + `asyncio.run()`
- [x] Add missing `import os` (and `argparse`, `asyncio`, `sys`)
- [x] Hostnames: default to `localhost` (published ports 8081/8082); keep `http://milvus:19530` for the container-side VDB endpoint; make all configurable via env/CLI
- [x] `APP_LLM_MODELNAME`: use `.get()` with default instead of `os.environ[...]`
- [x] `upload_documents`: close files, guess content type per file, absolute/configurable `DATA_DIR`
- [x] `delete_collections`: fix `""` default
- [x] Consistent error handling in all helpers (no stray `(500, {...})` return); catch `JSONDecodeError`
- [x] Fix duplicated "RAG server" label on the ingestor health check
- [x] Add `generate_answer` (referenced by `rag_research_query.py` but never defined) so RAG querying works
- [x] Poll ingestion task status after upload so queries only run once documents are indexed
- [x] CLI subcommands so it runs as an independent script (`all`, `health`, `collections`, `upload`, `query`, ...)

## rag_research_query.py
- [x] Remove top-level `await` / missing imports; reuse `rag_server.generate_answer`

## rag_deploy.py
- [x] Replace hardcoded `/Users/cboyd/...` paths with `RAG_REPO_DIR` env / `--repo-dir`
- [x] Don't edit repo compose files in place: write `*.generated.yaml` copies and use those
- [x] Replace `sys.exit(1)` repetition with one `run()` helper that raises/exits cleanly
- [x] Fix "with build" message; pin the minio image via a variable
- [x] Wrap in `main()` with `__main__` guard; wait for rag-server/ingestor health at the end

## Misc
- [x] `requirements.txt`: add `aiohttp`, fix `dotenv` -> `python-dotenv`
- [x] Syntax-check all scripts
