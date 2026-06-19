#!/usr/bin/env python3
"""
iterative_plan_refinement.py

Calls a rubber duck reviewer model via `pool exec` and returns structured feedback.
The primary model (whatever is running this skill) creates and refines the plan;
this script handles the cross-model call to the reviewer.

Usage:
    python iterative_plan_refinement.py -p "Build a web app" -a "anthropic/claude-sonnet-4.6"
    python iterative_plan_refinement.py -p "Build a web app" --status
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Optional


# -- Pool exec invocation -----------------------------------------------------

DEFAULT_AGENT = "anthropic/claude-sonnet-4.6"

# Friendly aliases → actual pool agent names
AGENT_ALIASES = {
    "claude-sonnet-4.6": "anthropic/claude-sonnet-4.6",
    "claude-opus-4.6": "anthropic/claude-opus-4.6",
    "claude-opus-4.7": "anthropic/claude-opus-4.7",
    "gpt-5.5": "openai/gpt-5.5",
    "laguna": "laguna-m.1",
    "laguna-xs": "laguna-xs.2",
}


class PoolCallError(RuntimeError):
    """Raised when pool exec fails."""
    pass


def find_pool_binary() -> Optional[str]:
    """Find the pool CLI binary."""
    if os.path.isfile("/usr/local/bin/pool") and os.access("/usr/local/bin/pool", os.X_OK):
        return "/usr/local/bin/pool"
    return shutil.which("pool")


def resolve_agent_name(name: str) -> str:
    """Resolve a friendly alias to the actual pool agent name."""
    return AGENT_ALIASES.get(name.lower(), name)


def call_pool_model(agent: str, review_prompt: str) -> str:
    """Call a model via `pool exec` and return the raw markdown response.

    Raises PoolCallError on any failure.
    """
    pool_bin = find_pool_binary()
    if not pool_bin:
        raise PoolCallError("pool binary not found at /usr/local/bin/pool or on PATH")

    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(review_prompt)
        prompt_file = f.name

    try:
        # pool exec -a <agent> -f <file> --unsafe-auto-allow -o markdown
        cmd = [
            pool_bin, "exec",
            "-a", agent,
            "-f", prompt_file,
            "--unsafe-auto-allow",
            "-o", "markdown",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()[:500]
            raise PoolCallError(f"pool exec failed (exit {result.returncode}): {stderr}")

        content = result.stdout.strip()
        if not content:
            raise PoolCallError("pool exec returned empty output")

        return content

    except subprocess.TimeoutExpired:
        raise PoolCallError("pool exec timed out after 180s")
    finally:
        try:
            os.unlink(prompt_file)
        except OSError:
            pass


# -- Response parsing ---------------------------------------------------------

def extract_rating(response: str) -> int:
    """Extract a 1-5 rating from the reviewer response. Defaults to 3."""
    match = re.search(r'[Rr]ating[:\s]*(\d)\s*/\s*5', response)
    if match:
        return max(1, min(5, int(match.group(1))))
    match = re.search(r'\b(\d)\s*/\s*5\b', response)
    if match:
        return max(1, min(5, int(match.group(1))))
    return 3


def parse_inline_agent(prompt: str) -> Optional[str]:
    """Extract agent name from prompt like 'using claude-sonnet-4.6'."""
    match = re.search(r'(?:using|with|use)\s+([\w./-]+)', prompt, re.IGNORECASE)
    if match:
        return resolve_agent_name(match.group(1))
    return None


# -- Review prompt builder ----------------------------------------------------

REVIEW_PROMPT_TEMPLATE = """You are a rubber duck reviewer. Review the following plan for accuracy, design, function, and form.

Original prompt: {prompt}

Plan to review:
{plan}

Provide structured feedback in these sections:

## Accuracy Review
- Does the plan correctly address the original prompt?
- Are there misunderstandings or misinterpretations?

## Design Review
- Are the design choices appropriate?
- Are there better alternatives to consider?

## Function Review
- Will this plan work as intended?
- Are steps logically ordered and complete?

## Form Review
- Is the plan clear and actionable?

## Overall Assessment
- Rating: [1-5]/5
- Key issues to address (numbered list)
"""


def get_rubber_duck_review(prompt: str, plan: str, agent: str) -> dict:
    """Send the plan to the rubber duck agent and return parsed feedback."""
    review_prompt = REVIEW_PROMPT_TEMPLATE.format(prompt=prompt, plan=plan)
    raw_response = call_pool_model(agent, review_prompt)
    rating = extract_rating(raw_response)
    return {
        "rating": rating,
        "raw_response": raw_response,
    }


# -- CLI entrypoint -----------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Rubber duck reviewer via pool exec")
    parser.add_argument("-p", "--prompt", help="The plan or idea to review")
    parser.add_argument("-a", "--agent", default=DEFAULT_AGENT,
                        help=f"Pool agent for rubber duck review (default: {DEFAULT_AGENT})")
    parser.add_argument("-o", "--output", choices=["json", "markdown"], default="markdown")
    parser.add_argument("--status", action="store_true",
                        help="Show configuration and exit")
    args = parser.parse_args()

    # Resolve alias
    agent = resolve_agent_name(args.agent)

    if args.status:
        pool_bin = find_pool_binary()
        print(f"pool binary: {pool_bin or 'NOT FOUND'}")
        print(f"rubber duck agent: {agent}")
        if pool_bin:
            print("\nAvailable agents (run `pool agents list` for full list)")
        return

    if not args.prompt:
        parser.error("--prompt is required unless using --status")

    # Check if user specified agent inline in the prompt
    inline_agent = parse_inline_agent(args.prompt)
    if inline_agent and args.agent == DEFAULT_AGENT:
        agent = inline_agent

    try:
        result = get_rubber_duck_review(args.prompt, args.prompt, agent)
    except PoolCallError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)

    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(result["raw_response"])
        print(f"\n---\nRating: {result['rating']}/5  |  Agent: {agent}")


if __name__ == "__main__":
    main()
