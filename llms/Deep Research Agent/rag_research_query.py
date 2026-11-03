#!/usr/bin/env python3
"""Ask the RAG server a question against the knowledge base.

    python rag_research_query.py "Who is Nicholas Duvernay's character related to?"
"""

import argparse
import asyncio
import sys

from rag_server import DEFAULT_COLLECTION, query_knowledge_base

DEFAULT_QUESTION = "Who is Nicholas Duvernay's character related to?"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question", nargs="?", default=DEFAULT_QUESTION)
    parser.add_argument("--collection", default=DEFAULT_COLLECTION)
    args = parser.parse_args()
    try:
        asyncio.run(query_knowledge_base(args.question, args.collection))
    except Exception as e:  # noqa: BLE001 - CLI entry point, report and exit non-zero
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
