#!/usr/bin/env python3
"""
iterative_plan_refinement.py

A helper script for the iterative plan refinement skill.
Supports multiple rubber duck model providers.

Usage:
    python iterative_plan_refinement.py --prompt "Build a web app" --max-iterations 10
    
Environment variables:
    RUBBER_DUCK_PROVIDER  - Provider: pool, openai, anthropic, api, or simulate (default: simulate)
    RUBBER_DUCK_MODEL     - Model name (e.g., claude-3-opus-20240229, gpt-4-turbo)
    RUBBER_DUCK_ENDPOINT  - Custom API endpoint (for 'api' provider)
    POOLSIDE_API_KEY      - Poolside API key (auto-detected from credentials.json if not set)
    OPENAI_API_KEY        - OpenAI API key
    ANTHROPIC_API_KEY     - Anthropic API key
"""

import argparse
import json
import os
import re
import sys
from typing import Optional, Tuple

# Session-level overrides (set by CLI or main())
_session_provider: Optional[str] = None
_session_model: Optional[str] = None

def load_dotenv_if_available():
    """Load .env file if python-dotenv is available."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass  # .env file is optional

def get_poolside_api_key() -> Optional[str]:
    """Get Poolside API key from environment or credentials file."""
    key = os.getenv("POOLSIDE_API_KEY")
    if key:
        return key
    
    # Try to read from Poolside credentials file
    credentials_path = os.path.expanduser("~/.config/poolside/credentials.json")
    try:
        with open(credentials_path) as f:
            creds = json.load(f)
            for cred in creds:
                if cred.get("type") == "api-key" and "poolsi.de" in cred.get("apiUrl", ""):
                    return cred.get("token")
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
    
    return None

def set_session_overrides(provider: Optional[str] = None, model: Optional[str] = None):
    """Set session-level provider/model overrides."""
    global _session_provider, _session_model
    _session_provider = provider
    _session_model = model

def parse_inline_model_spec(prompt: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse model provider/model from inline prompt specifications.
    
    Returns: (provider, model) or (None, None) if not found.
    Handles patterns like:
    - "using claude-sonnet-4.6"
    - "with anthropic/claude-sonnet-4.6"
    - "use gpt-4-turbo"
    - "using poolside/laguna-test-a"
    """
    if not prompt:
        return None, None
    
    prompt_lower = prompt.lower()
    
    # Pattern: "using|with|use" followed by optional provider/ and model
    patterns = [
        # Explicit provider/model format: "using anthropic/claude-sonnet-4.6" or "with poolside/laguna-test-a"
        (r'(?:using|with|use)\s+(anthropic|openai|pool|poolside)/([a-zA-Z0-9\-_.]+)', 'provider_explicit'),
        # Poolside format aliases (without provider prefix) - must come before generic patterns
        (r'(?:using|with|use)\s+(claude-sonnet-4\.6|claude-opus-4\.6|claude-haiku-4\.6)', 'poolside_anthropic_alias'),
        # Just model name with known prefixes (allow dots in model names)
        (r'(?:using|with|use)\s+(claude-[a-z0-9.\-]+)', 'poolside_anthropic'),
        (r'(?:using|with|use)\s+(gpt-[a-z0-9.\-]+)', 'poolside_openai'),
        (r'(?:using|with|use)\s+(poolside/[a-zA-Z0-9\-_.]+)', 'pool'),
    ]
    
    # Poolside alias to actual model name mapping
    alias_map = {
        'claude-sonnet-4.6': 'claude-3-5-sonnet-20241022',
        'claude-opus-4.6': 'claude-3-opus-20240229',
        'claude-haiku-4.6': 'claude-3-5-haiku-20241022',
    }
    
    for pattern, mode in patterns:
        match = re.search(pattern, prompt_lower)
        if match:
            if mode == 'provider_explicit':
                provider = match.group(1)
                model = match.group(2)
                # For Poolside-managed models (anthropic/*, openai/*), route through pool provider
                # since we have Poolside API credentials, not direct API keys
                if provider in ('anthropic', 'openai'):
                    return 'pool', f"{provider}/{model}"
                if provider in ('pool', 'poolside'):
                    return 'pool', model
                return provider, model
            elif mode == 'poolside_anthropic_alias':
                alias = match.group(1)
                return 'pool', f"anthropic/{alias_map.get(alias, alias)}"
            elif mode == 'poolside_anthropic':
                return 'pool', f"anthropic/{match.group(1)}"
            elif mode == 'poolside_openai':
                return 'pool', f"openai/{match.group(1)}"
            elif mode == 'pool':
                return 'pool', match.group(1)
    
    return None, None

def create_initial_plan(prompt: str) -> dict:
    """Create an initial plan structure from user prompt."""
    return {
        "iteration": 1,
        "goal": prompt,
        "requirements": [
            "To be refined based on prompt analysis",
            "Should meet user's stated objectives",
            "Must be implementable"
        ],
        "design": {
            "approach": "Initial approach - to be detailed",
            "alternatives_considered": [],
            "rationale": "Placeholder"
        },
        "steps": [
            "Analyze requirements in detail",
            "Design system architecture",
            "Implement core features",
            "Test and validate"
        ],
        "risks": ["Initial assumptions may need adjustment"],
        "status": "draft"
    }

def format_plan_for_review(plan: dict) -> str:
    """Format plan as markdown for rubber duck review."""
    return f"""# Plan (Iteration {plan['iteration']})

## Goal
{plan['goal']}

## Requirements
{chr(10).join(f'- {r}' for r in plan['requirements'])}

## Design Considerations
- Approach: {plan['design']['approach']}
- Rationale: {plan['design']['rationale']}
{f"- Alternatives considered: {', '.join(plan['design']['alternatives_considered'])}" if plan['design']['alternatives_considered'] else ""}

## Implementation Steps
{chr(10).join(f'{i+1}. {s}' for i, s in enumerate(plan['steps']))}

## Potential Risks/Issues
{chr(10).join(f'- {r}' for r in plan['risks'])}
"""

def simulate_rubber_duck_review(prompt: str, plan_markdown: str) -> dict:
    """Simulate a rubber duck review when no model is configured."""
    return {
        "iteration": 1,
        "accuracy": "Plan addresses core prompt but needs deeper analysis",
        "design": "Consider at least 2 alternative approaches with trade-offs",
        "function": "Steps need expected outcomes and validation criteria",
        "form": "Structure is good but add more technical detail",
        "rating": 2,
        "issues": [
            "Requirements need to be more specific and measurable",
            "Design rationale should compare alternatives",
            "Steps need expected outcomes and acceptance criteria",
            "Missing non-functional requirements (performance, security)"
        ],
        "suggestions": [
            "Add acceptance criteria for each requirement",
            "Consider edge cases and error scenarios",
            "Define success metrics and validation methods"
        ]
    }

def find_pool_binary() -> Optional[str]:
    """Find the pool CLI binary."""
    # Check common locations
    possible_paths = [
        "/Users/chris.boyd/.vscode/extensions/poolside-ai.poolside-assistant-3.0.1/dist/pool-darwin-arm64",
        "/Users/chris.boyd/.vscode/extensions/poolside-ai.poolside-assistant-3.0.1/dist/pool-darwin-amd64",
        os.path.expanduser("~/.local/bin/pool"),
        "/usr/local/bin/pool",
        "pool",  # Try PATH
    ]
    
    for path in possible_paths:
        try:
            import subprocess
            result = subprocess.run([path, "--help"], capture_output=True, timeout=2)
            if result.returncode == 0:
                return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def call_pool_model(model: str, review_prompt: str) -> dict:
    """Call Poolside model pool by invoking another agent via pool CLI.
    
    This works within Poolside by spawning a subprocess that uses the pool binary
    to invoke a different model/agent.
    """
    import subprocess
    import tempfile
    
    # Try using pool CLI to invoke the model as an agent
    pool_bin = find_pool_binary()
    if not pool_bin:
        print("Warning: pool binary not found, using simulation", file=sys.stderr)
        return simulate_rubber_duck_review("", "")
    
    # Create a temp file for the prompt
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
        f.write(review_prompt)
        prompt_file = f.name
    
    try:
        # The pool CLI uses -p for prompt or -f for prompt file
        # --unsafe-auto-allow is needed for non-interactive execution
        result = subprocess.run(
            [pool_bin, "-a", model, "-f", prompt_file, 
             "--unsafe-auto-allow", "-o", "markdown"],
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            # Extract the actual response from pool output
            # pool outputs the trajectory URL first, then the response, then exit indicator
            lines = output.split('\n')
            response_lines = []
            capture = False
            for line in lines:
                # Skip trajectory URL and hint lines
                if line.startswith("Trajectory URL:") or line.startswith("hint:"):
                    continue
                # The response starts after trajectory URL and ends before exit indicator
                if "⏺ exit(" in line:
                    break
                # Capture the actual response
                if line.strip():
                    response_lines.append(line)
            
            content = '\n'.join(response_lines).strip()
            if content:
                return parse_feedback_response(content)
        
        print(f"Warning: pool returned status {result.returncode}", file=sys.stderr)
            
    except subprocess.TimeoutExpired:
        print("Warning: pool timed out, using simulation", file=sys.stderr)
    except Exception as e:
        print(f"Warning: pool error: {e}, using simulation", file=sys.stderr)
    finally:
        # Clean up temp file
        try:
            os.unlink(prompt_file)
        except Exception:
            pass
    
    return simulate_rubber_duck_review("", "")

def call_openai_model(model: str, review_prompt: str, api_key: str) -> dict:
    """Call OpenAI API."""
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": review_prompt}],
            temperature=0.7
        )
        return parse_feedback_response(response.choices[0].message.content)
    except ImportError:
        print("Warning: openai package not installed, using simulation", file=sys.stderr)
        return simulate_rubber_duck_review("", "")
    except Exception as e:
        print(f"Warning: OpenAI API error: {e}, using simulation", file=sys.stderr)
        return simulate_rubber_duck_review("", "")

def call_anthropic_model(model: str, review_prompt: str, api_key: str) -> dict:
    """Call Anthropic API."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=4000,
            messages=[{"role": "user", "content": review_prompt}]
        )
        return parse_feedback_response(response.content[0].text)
    except ImportError:
        print("Warning: anthropic package not installed, using simulation", file=sys.stderr)
        return simulate_rubber_duck_review("", "")
    except Exception as e:
        print(f"Warning: Anthropic API error: {e}, using simulation", file=sys.stderr)
        return simulate_rubber_duck_review("", "")

def call_custom_api(endpoint: str, model: str, api_key: str, review_prompt: str) -> dict:
    """Call a custom API endpoint."""
    import urllib.request
    import urllib.error
    
    data = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": review_prompt}]
    }).encode('utf-8')
    
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            return parse_feedback_response(result)
    except Exception as e:
        print(f"Warning: API error: {e}, using simulation", file=sys.stderr)
        return simulate_rubber_duck_review("", "")

def parse_feedback_response(response: str) -> dict:
    """Parse a feedback response into structured format.
    
    Extracts rating from the response (looks for "Rating: X/5" pattern)
    and structures the feedback.
    """
    import re
    
    if not response:
        return {
            "iteration": 1,
            "accuracy": "No response received",
            "design": "No response received",
            "function": "No response received",
            "form": "No response received",
            "rating": 2,
            "issues": ["No feedback received from model"],
            "suggestions": []
        }
    
    # Try to extract rating (looks for "Rating: X/5" or "X/5" pattern)
    rating_match = re.search(r'(?:rating[:\s]*)?(\d+)/5', response, re.IGNORECASE)
    rating = int(rating_match.group(1)) if rating_match else 3
    
    # Check if the response contains structured sections
    has_accuracy = "accuracy" in response.lower()
    has_design = "design" in response.lower()
    has_function = "function" in response.lower()
    has_form = "form" in response.lower()
    
    # Extract issues (look for numbered lists or bullet points after "issues")
    issues = []
    issues_match = re.search(r'(?:issues?|concerns?)[\s\S]{0,500}?(?:1\.|\n-)([^1-9\n][^\n]+)', response, re.IGNORECASE)
    if issues_match:
        issues = [issues_match.group(1).strip()]
    
    # If no structured feedback found, use the raw response
    if not (has_accuracy or has_design or has_function or has_form):
        # Use simple heuristics: if response is short, rate it lower
        # If response mentions specific concerns, extract them
        words = response.split()
        if len(words) < 50:
            rating = min(rating, 2)
            issues = [response[:200]] if len(response) > 50 else [response]
    
    return {
        "iteration": 1,
        "accuracy": response[:200] if has_accuracy else "See full response",
        "design": response[:200] if has_design else "See full response",
        "function": response[:200] if has_function else "See full response",
        "form": response[:200] if has_form else "See full response",
        "rating": max(1, min(5, rating)),  # Clamp to 1-5
        "issues": issues if issues else ["See full review response"],
        "suggestions": [],
        "raw_response": response  # Keep raw response for debugging
    }

def get_reviewer_provider(provider_override: Optional[str] = None, model_override: Optional[str] = None) -> tuple:
    """Determine which rubber duck reviewer to use.
    
    Priority order: session override > explicit override > environment > simulation
    
    For Poolside 'pool' provider, models can be:
    - poolside/laguna-test-a (Laguna internal models)
    - anthropic/claude-sonnet-4.6 (Poolside-routed Anthropic models)
    - openai/gpt-4-turbo (Poolside-routed OpenAI models)
    """
    load_dotenv_if_available()
    
    # Priority: session override > explicit override > environment > simulation
    provider = (_session_provider or provider_override or os.getenv("RUBBER_DUCK_PROVIDER", "simulate")).lower()
    model = _session_model or model_override or os.getenv("RUBBER_DUCK_MODEL", "")
    
    if provider == "simulate":
        return "simulate", None, None
    elif provider == "pool":
        # For Poolside pool, use the model as-is (could be anthropic/*, openai/*, or poolside/*)
        return "pool", model or "poolside/laguna-test-a", None
    elif provider == "openai":
        return "openai", model or "gpt-4-turbo", os.getenv("OPENAI_API_KEY")
    elif provider == "anthropic":
        return provider, model or "claude-3-5-sonnet-20241022", os.getenv("ANTHROPIC_API_KEY")
    elif provider == "api":
        endpoint = os.getenv("RUBBER_DUCK_ENDPOINT")
        api_key = os.getenv("RUBBER_DUCK_API_KEY")
        return provider, model, {"endpoint": endpoint, "api_key": api_key}
    else:
        return "simulate", None, None

def get_rubber_duck_review(prompt: str, plan_markdown: str) -> dict:
    """Get review from configured rubber duck model."""
    provider, model, credentials = get_reviewer_provider()
    
    review_prompt = f"""You are a rubber duck reviewer. Review the following plan for accuracy, design considerations, function, and form.

Original prompt: {prompt}
Plan to review: {plan_markdown}

Provide structured feedback:

## Accuracy Review
- Does the plan correctly address the original prompt?
- Are there misunderstandings or misinterpretations?

## Design Review
- Are the design choices appropriate?
- Are there better alternatives to consider?
- What edge cases or constraints are missed?

## Function Review
- Will this plan work as intended?
- Are steps logically ordered?
- Are there missing dependencies or prerequisites?

## Form Review
- Is the plan clear and well-structured?
- Is it actionable and specific enough?

## Overall Assessment
- Rating: [1-5, 5 being excellent]
- Key issues to address:
  1. [Issue 1]
  2. [Issue 2]
"""
    
    if provider == "simulate":
        return simulate_rubber_duck_review(prompt, plan_markdown)
    elif provider == "pool":
        return call_pool_model(model, review_prompt)
    elif provider == "openai":
        return call_openai_model(model, review_prompt, credentials)
    elif provider == "anthropic":
        return call_anthropic_model(model, review_prompt, credentials)
    elif provider == "api":
        return call_custom_api(credentials["endpoint"], model, credentials["api_key"], review_prompt)
    else:
        return simulate_rubber_duck_review(prompt, plan_markdown)

def apply_feedback(plan: dict, feedback: dict) -> dict:
    """Apply rubber duck feedback to refine plan."""
    plan['iteration'] += 1
    plan['status'] = 'refined'
    
    # In a real implementation, this would process the feedback
    # and update the plan accordingly
    
    return plan

def run_iteration_loop(prompt: str, max_iterations: int = 10) -> dict:
    """Run the full iteration loop."""
    provider, model, _ = get_reviewer_provider()
    plan = create_initial_plan(prompt)
    history = []
    
    for i in range(max_iterations):
        plan_markdown = format_plan_for_review(plan)
        feedback = get_rubber_duck_review(prompt, plan_markdown)
        
        # Simulate improvement toward approval for demo purposes
        if provider == "simulate" and plan['iteration'] >= 2:
            feedback['rating'] = 4  # Approves after iteration 2 for simulation demo
        
        history.append({
            "iteration": plan['iteration'],
            "plan": plan_markdown,
            "feedback": feedback
        })
        
        # Check for approval (rating >= 4)
        if feedback['rating'] >= 4:
            return {
                "final_plan": plan,
                "iterations": plan['iteration'],
                "status": "approved",
                "history": history,
                "reviewer_config": {"provider": provider, "model": model}
            }
        
        plan = apply_feedback(plan, feedback)
    
    return {
        "final_plan": plan,
        "iterations": plan['iteration'],
        "status": "max_iterations",
        "history": history,
        "reviewer_config": {"provider": provider, "model": model}
    }

def main():
    parser = argparse.ArgumentParser(
        description="Iterative plan refinement helper"
    )
    parser.add_argument(
        "--prompt", "-p",
        help="The original prompt or project idea"
    )
    parser.add_argument(
        "--max-iterations", "-m",
        type=int,
        default=10,
        help="Maximum iterations before stopping (default: 10)"
    )
    parser.add_argument(
        "--output", "-o",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current reviewer configuration and exit"
    )
    parser.add_argument(
        "--provider", "-P",
        dest="provider",
        choices=["pool", "openai", "anthropic", "api", "simulate"],
        help="Override rubber duck model provider (CLI takes priority over env vars)"
    )
    parser.add_argument(
        "--model", "-M",
        dest="model",
        help="Override rubber duck model name (CLI takes priority over env vars)"
    )
    
    args = parser.parse_args()
    
    # Load .env if available
    load_dotenv_if_available()
    
    if args.status:
        # Check inline spec from prompt if provided
        inline_provider, inline_model = None, None
        if args.prompt:
            inline_provider, inline_model = parse_inline_model_spec(args.prompt)
        effective_provider = args.provider or inline_provider
        effective_model = args.model or inline_model
        
        provider, model, _ = get_reviewer_provider(effective_provider, effective_model)
        config = {"provider": provider, "model": model}
        print(json.dumps(config, indent=2))
        print(f"\nEnvironment variables detected:")
        print(f"  RUBBER_DUCK_PROVIDER: {os.getenv('RUBBER_DUCK_PROVIDER', 'not set')}")
        print(f"  RUBBER_DUCK_MODEL: {os.getenv('RUBBER_DUCK_MODEL', 'not set')}")
        
        has_anthropic_key = "set" if os.getenv("ANTHROPIC_API_KEY") else "not set"
        has_openai_key = "set" if os.getenv("OPENAI_API_KEY") else "not set"
        print(f"  ANTHROPIC_API_KEY: {has_anthropic_key}")
        print(f"  OPENAI_API_KEY: {has_openai_key}")
        
        if inline_provider or inline_model:
            print(f"\n  Inline specification parsed: {inline_provider}/{inline_model}")
        
        if provider == "simulate":
            print("\n⚠️  Currently in simulation mode (no external model configured)")
        else:
            print(f"\n✓ Will use: {provider}/{model}")
        return
    
    if not args.prompt:
        parser.error("--prompt is required unless using --status")
    
    # Determine provider/model: CLI args > inline spec > environment
    provider = args.provider
    model = args.model
    
    if not provider or not model:
        # Try inline specification from prompt
        inline_provider, inline_model = parse_inline_model_spec(args.prompt)
        provider = provider or inline_provider
        model = model or inline_model
    
    # Set session overrides so all functions see them
    set_session_overrides(provider, model)
    
    result = run_iteration_loop(args.prompt, args.max_iterations)
    
    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(format_plan_for_review(result['final_plan']))
        print(f"\n**Iterations completed:** {result['iterations']}")
        print(f"**Status:** {result['status']}")
        
        reviewer = result['reviewer_config']
        if reviewer['provider'] == 'simulate':
            print("\n*Simulation mode: No external rubber duck model configured.*")
        else:
            print(f"\n*Reviewed by: {reviewer['provider']}/{reviewer['model']}*")

if __name__ == "__main__":
    main()