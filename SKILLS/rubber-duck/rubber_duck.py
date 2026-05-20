#!/usr/bin/env python3
"""
rubber_duck.py — Iterative plan refinement using direct LLM API calls.

One model creates/refines a plan, another reviews it. Loops until the reviewer
approves (rating >= 4/5), contradictions are detected, or max iterations hit.

Usage:
    python rubber_duck.py "Build a CLI tool for customer onboarding"
    python rubber_duck.py "Build a CLI tool" --creator poolside/laguna-m.1 --reviewer anthropic/claude-sonnet-4-6
    python rubber_duck.py --status
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

from providers import make_provider

# Load .env — script directory first, fallback to ~/.env
load_dotenv(Path(__file__).parent / ".env")
load_dotenv(Path.home() / ".env")

# -- Defaults ----------------------------------------------------------------

DEFAULT_CREATOR_PROVIDER = os.getenv("CREATOR_PROVIDER", "poolside")
DEFAULT_CREATOR_MODEL = os.getenv("CREATOR_MODEL", "laguna-m.1")
DEFAULT_REVIEWER_PROVIDER = os.getenv("REVIEWER_PROVIDER", "anthropic")
DEFAULT_REVIEWER_MODEL = os.getenv("REVIEWER_MODEL", "claude-sonnet-4-6")
DEFAULT_MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "10"))


# -- Prompts -----------------------------------------------------------------

CREATOR_SYSTEM = """You are a senior software architect. You create detailed, actionable implementation plans.

When given a high-level idea, produce a structured plan in this exact format:

# Plan: [Brief Title]

## Goal
[Clear statement of what will be accomplished]

## Requirements
- [Key requirements derived from the prompt]

## Design Considerations
- Approach A: [description]
- Approach B: [description] (if applicable)
- Selected approach: [choice] with rationale

## Implementation Steps
1. [Step with expected outcome]
2. [Step with expected outcome]
...

## Potential Risks/Issues
- [Risk with mitigation strategy]

When given feedback on a previous plan, revise the plan to address the feedback.
Focus on substance over form — the reviewer is technical and doesn't need hand-holding."""

REVIEWER_SYSTEM = """You are a rigorous technical reviewer. You review implementation plans and provide constructive feedback.

Your job is to evaluate plans for:
- **Accuracy**: Does the plan correctly address the stated goal?
- **Design**: Are the architectural choices sound? Are there better alternatives?
- **Completeness**: Are steps logically ordered and sufficient?
- **Feasibility**: Will this actually work in practice?

You MUST end your review with exactly this format:
Rating: N/5

Where N is 1-5:
- 1: Fundamentally flawed, needs complete rethink
- 2: Major issues that need significant rework
- 3: Workable but has notable gaps or concerns
- 4: Solid plan with only minor suggestions
- 5: Excellent, ready to implement as-is

You provide feedback ONLY. You never rewrite the plan yourself.
Be specific — cite exact steps or sections when giving feedback.
If you previously gave contradictory feedback, call it out explicitly."""

CREATOR_REFINE_TEMPLATE = """Here is the current plan:

{plan}

The reviewer provided this feedback (iteration {iteration}):

{feedback}

Revise the plan to address the feedback. Keep the same markdown structure.
Only change what the feedback calls for — don't over-revise."""


# -- Rating extraction -------------------------------------------------------

def extract_rating(response: str) -> int:
    """Extract a 1-5 rating from the reviewer response. Defaults to 3."""
    match = re.search(r'[Rr]ating[:\s]*(\d)\s*/\s*5', response)
    if match:
        return max(1, min(5, int(match.group(1))))
    match = re.search(r'\b(\d)\s*/\s*5\b', response)
    if match:
        return max(1, min(5, int(match.group(1))))
    return 3


# -- Contradiction detection -------------------------------------------------

CONTRADICTION_CHECK_SYSTEM = """You are a careful analyst checking for contradictions in reviewer feedback across iterations of a plan.

Compare the feedback from all iterations and determine if any feedback DIRECTLY CONTRADICTS previous feedback. A contradiction means:
- Iteration N said to ADD something, and iteration M says to REMOVE the same thing (or vice versa)
- Iteration N recommended approach A, and iteration M recommends the opposite approach for the same concern
- Iteration N said a section was unnecessary, and iteration M says it's missing

Minor refinements or shifts in emphasis are NOT contradictions. Only flag genuine reversals.

If you find a contradiction, respond in EXACTLY this format:

CONTRADICTION: YES
ITERATIONS: [N] vs [M]
TOPIC: [what the contradiction is about]
DETAIL: [specific explanation of what iteration N said vs what iteration M said, quoting relevant phrases]
IMPACT: [how this affects the plan — what decision is blocked]
OPTIONS:
  A: [first resolution path — follow iteration N's guidance]
  B: [second resolution path — follow iteration M's guidance]
  C: [third option if applicable — a compromise or alternative]

If there is no contradiction, respond with exactly:
CONTRADICTION: NO"""


def detect_contradiction(history: list[dict], reviewer) -> dict | None:
    """Use the reviewer model to analyze feedback history for contradictions.

    Returns a structured dict describing the contradiction, or None.
    """
    if len(history) < 2:
        return None

    feedback_summary = "\n\n".join(
        f"=== Iteration {h['iteration']} (Rating: {h['rating']}/5) ===\n{h['feedback']}"
        for h in history
    )

    prompt = f"Analyze these reviewer feedback iterations for contradictions:\n\n{feedback_summary}"

    response = reviewer.chat(
        messages=[{"role": "user", "content": prompt}],
        system=CONTRADICTION_CHECK_SYSTEM,
    )

    if "CONTRADICTION: YES" not in response:
        return None

    # Parse the structured response
    result = {"raw": response}
    for field in ["ITERATIONS", "TOPIC", "DETAIL", "IMPACT"]:
        match = re.search(rf'{field}:\s*(.+?)(?:\n[A-Z]|\Z)', response, re.DOTALL)
        if match:
            result[field.lower()] = match.group(1).strip()

    # Parse options
    options = re.findall(r'^\s+([A-C]):\s*(.+)$', response, re.MULTILINE)
    if options:
        result["options"] = {letter: desc.strip() for letter, desc in options}

    return result


def prompt_user_for_resolution(contradiction: dict, plan: str) -> str:
    """Present the contradiction to the user and get their resolution choice."""
    print("\n" + "=" * 60)
    print("[[CONTRADICTION DETECTED]]")
    print("=" * 60)

    if "topic" in contradiction:
        print(f"\nTopic: {contradiction['topic']}")
    if "iterations" in contradiction:
        print(f"Between: Iterations {contradiction['iterations']}")
    if "detail" in contradiction:
        print(f"\nWhat happened:\n  {contradiction['detail']}")
    if "impact" in contradiction:
        print(f"\nImpact on plan:\n  {contradiction['impact']}")

    options = contradiction.get("options", {})
    if options:
        print("\nResolution options:")
        for letter, desc in sorted(options.items()):
            print(f"  {letter}) {desc}")
        print(f"  D) Provide your own direction")
        print()
        choice = input("Choose an option (A/B/C/D), or describe what you want: ").strip()
    else:
        print(f"\nReviewer analysis:\n  {contradiction.get('raw', 'No details available.')}")
        print()
        choice = input("How should this be resolved? Describe your preference: ").strip()

    if not choice:
        print("No input provided. Stopping.")
        raise SystemExit(1)

    # If they picked a letter, expand it to the full description
    if len(choice) == 1 and choice.upper() in options:
        return f"Resolve the contradiction by: {options[choice.upper()]}"
    elif choice.upper() == "D" or len(choice) > 1:
        direction = choice if len(choice) > 1 else input("Describe your preferred resolution: ").strip()
        if not direction:
            print("No input provided. Stopping.")
            raise SystemExit(1)
        return f"User resolution: {direction}"

    return f"Resolve the contradiction by: {choice}"


# -- Parse provider/model from CLI flag --------------------------------------

def parse_model_spec(spec: str, default_provider: str, default_model: str) -> tuple[str, str]:
    """Parse 'provider/model' string. Falls back to defaults."""
    if "/" in spec:
        provider, model = spec.split("/", 1)
        return provider, model
    return default_provider, spec if spec else default_model


# -- Main loop ---------------------------------------------------------------

def run(
    prompt: str,
    creator_provider_name: str,
    creator_model: str,
    reviewer_provider_name: str,
    reviewer_model: str,
    max_iterations: int,
    output_format: str,
) -> dict:
    """Run the iterative plan refinement loop. Returns the final result dict."""

    # Build providers
    creator_kwargs = {"model": creator_model}
    reviewer_kwargs = {"model": reviewer_model}

    if creator_provider_name == "poolside":
        creator_kwargs["api_key"] = os.environ["POOLSIDE_API_KEY"]
        creator_kwargs["base_url"] = os.getenv("POOLSIDE_BASE_URL", "https://api.poolsi.de")
    elif creator_provider_name == "anthropic":
        creator_kwargs["api_key"] = os.environ["ANTHROPIC_API_KEY"]

    if reviewer_provider_name == "poolside":
        reviewer_kwargs["api_key"] = os.environ["POOLSIDE_API_KEY"]
        reviewer_kwargs["base_url"] = os.getenv("POOLSIDE_BASE_URL", "https://api.poolsi.de")
    elif reviewer_provider_name == "anthropic":
        reviewer_kwargs["api_key"] = os.environ["ANTHROPIC_API_KEY"]

    creator = make_provider(creator_provider_name, **creator_kwargs)
    reviewer = make_provider(reviewer_provider_name, **reviewer_kwargs)

    # Step 1: Create initial plan
    print(f"[1/{max_iterations}] Creating initial plan with {creator_provider_name}/{creator_model}...")
    plan = creator.chat(
        messages=[{"role": "user", "content": prompt}],
        system=CREATOR_SYSTEM,
    )

    history = []

    for i in range(1, max_iterations + 1):
        # Step 2: Review
        print(f"[{i}/{max_iterations}] Reviewing with {reviewer_provider_name}/{reviewer_model}...")
        review_prompt = f"Review this plan:\n\n{plan}"
        if history:
            prev_summary = "\n".join(
                f"- Iteration {h['iteration']}: rating {h['rating']}/5"
                for h in history
            )
            review_prompt += f"\n\nPrevious iteration ratings:\n{prev_summary}"

        feedback = reviewer.chat(
            messages=[{"role": "user", "content": review_prompt}],
            system=REVIEWER_SYSTEM,
        )
        rating = extract_rating(feedback)
        history.append({"iteration": i, "rating": rating, "feedback": feedback})
        print(f"    Rating: {rating}/5")

        # Check exit: approved
        if rating >= 4:
            print(f"    Plan approved at iteration {i}.")
            return {
                "status": "approved",
                "plan": plan,
                "iterations": i,
                "final_rating": rating,
                "history": history,
            }

        # Check exit: contradiction
        contradiction = detect_contradiction(history, reviewer)
        if contradiction:
            resolution = prompt_user_for_resolution(contradiction, plan)
            print(f"\n[{i}/{max_iterations}] Refining plan with your resolution...")
            refine_prompt = CREATOR_REFINE_TEMPLATE.format(
                plan=plan,
                feedback=f"CONTRADICTION RESOLUTION FROM USER:\n{resolution}\n\nApply this direction to the plan. The reviewer had conflicting feedback — the user's choice above is authoritative.",
                iteration=i,
            )
            plan = creator.chat(
                messages=[{"role": "user", "content": refine_prompt}],
                system=CREATOR_SYSTEM,
            )
            # Continue the loop — the resolved plan goes back to the reviewer
            continue

        # Step 3: Refine
        print(f"[{i}/{max_iterations}] Refining plan...")
        refine_prompt = CREATOR_REFINE_TEMPLATE.format(
            plan=plan, feedback=feedback, iteration=i
        )
        plan = creator.chat(
            messages=[{"role": "user", "content": refine_prompt}],
            system=CREATOR_SYSTEM,
        )

    # Max iterations reached
    print(f"    Max iterations ({max_iterations}) reached.")
    return {
        "status": "max_iterations",
        "plan": plan,
        "iterations": max_iterations,
        "final_rating": history[-1]["rating"] if history else 0,
        "history": history,
    }


# -- Output formatting -------------------------------------------------------

def format_result(result: dict, fmt: str) -> str:
    """Format the result for output."""
    if fmt == "json":
        return json.dumps(result, indent=2)

    lines = []
    status_label = {
        "approved": "APPROVED",
        "max_iterations": "MAX ITERATIONS REACHED",
    }.get(result["status"], result["status"].upper())

    lines.append(f"Status: {status_label}")
    lines.append(f"Iterations: {result['iterations']}")
    lines.append(f"Final rating: {result['final_rating']}/5")

    lines.append(f"\n{'=' * 60}")
    lines.append("FINAL PLAN")
    lines.append(f"{'=' * 60}\n")
    lines.append(result["plan"])

    lines.append(f"\n{'=' * 60}")
    lines.append("ITERATION HISTORY")
    lines.append(f"{'=' * 60}")
    for h in result.get("history", []):
        lines.append(f"\n--- Iteration {h['iteration']} (Rating: {h['rating']}/5) ---")
        # Show first 500 chars of feedback as summary
        fb_preview = h["feedback"][:500]
        if len(h["feedback"]) > 500:
            fb_preview += "..."
        lines.append(fb_preview)

    return "\n".join(lines)


# -- CLI ---------------------------------------------------------------------

def show_status():
    """Print current configuration and exit."""
    env_path = Path(__file__).parent / ".env"
    print("rubber-duck status")
    print(f"  .env file: {'found' if env_path.exists() else 'NOT FOUND'}")
    print(f"  Creator:   {DEFAULT_CREATOR_PROVIDER}/{DEFAULT_CREATOR_MODEL}")
    print(f"  Reviewer:  {DEFAULT_REVIEWER_PROVIDER}/{DEFAULT_REVIEWER_MODEL}")
    print(f"  Max turns: {DEFAULT_MAX_ITERATIONS}")
    print()
    poolside_set = "set" if os.getenv("POOLSIDE_API_KEY") else "NOT SET"
    print(f"  POOLSIDE_API_KEY:  {poolside_set}")
    print("  POOLSIDE_BASE_URL: " + os.getenv("POOLSIDE_BASE_URL", "https://api.poolsi.de"))
    print(f"  ANTHROPIC_API_KEY: {'set' if os.getenv('ANTHROPIC_API_KEY') else 'NOT SET'}")


def main():
    parser = argparse.ArgumentParser(
        description="Iterative plan refinement with multi-provider LLM support"
    )
    parser.add_argument("prompt", nargs="?", help="The idea or plan to develop")
    parser.add_argument(
        "--creator", default=None,
        help=f"Creator model as provider/model (default: {DEFAULT_CREATOR_PROVIDER}/{DEFAULT_CREATOR_MODEL})"
    )
    parser.add_argument(
        "--reviewer", default=None,
        help=f"Reviewer model as provider/model (default: {DEFAULT_REVIEWER_PROVIDER}/{DEFAULT_REVIEWER_MODEL})"
    )
    parser.add_argument(
        "--max-turns", type=int, default=DEFAULT_MAX_ITERATIONS,
        help=f"Max refinement iterations (default: {DEFAULT_MAX_ITERATIONS})"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument("--status", action="store_true", help="Show config and exit")
    args = parser.parse_args()

    if args.status:
        show_status()
        return

    if not args.prompt:
        parser.error("prompt is required (or use --status)")

    # Parse model specs
    if args.creator:
        creator_provider, creator_model = parse_model_spec(
            args.creator, DEFAULT_CREATOR_PROVIDER, DEFAULT_CREATOR_MODEL
        )
    else:
        creator_provider, creator_model = DEFAULT_CREATOR_PROVIDER, DEFAULT_CREATOR_MODEL

    if args.reviewer:
        reviewer_provider, reviewer_model = parse_model_spec(
            args.reviewer, DEFAULT_REVIEWER_PROVIDER, DEFAULT_REVIEWER_MODEL
        )
    else:
        reviewer_provider, reviewer_model = DEFAULT_REVIEWER_PROVIDER, DEFAULT_REVIEWER_MODEL

    try:
        result = run(
            prompt=args.prompt,
            creator_provider_name=creator_provider,
            creator_model=creator_model,
            reviewer_provider_name=reviewer_provider,
            reviewer_model=reviewer_model,
            max_iterations=args.max_turns,
            output_format=args.format,
        )
    except KeyError as e:
        print(f"ERROR: Missing environment variable: {e}", file=sys.stderr)
        print("Run with --status to check configuration.", file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)

    print(format_result(result, args.format))


if __name__ == "__main__":
    main()
