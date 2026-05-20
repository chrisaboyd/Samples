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
    OPENAI_API_KEY        - OpenAI API key
    ANTHROPIC_API_KEY     - Anthropic API key
"""

import argparse
import json
import os
import sys
from typing import Optional

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

def call_pool_model(model: str, review_prompt: str) -> dict:
    """Call Poolside model pool (for A/B testing with Laguna models)."""
    try:
        from poolside import model_pool
        response = model_pool.invoke(model=model, prompt=review_prompt)
        return parse_feedback_response(response)
    except ImportError:
        print("Warning: Poolside model_pool not available, using simulation", file=sys.stderr)
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
    """Parse a feedback response into structured format."""
    # In a real implementation, this would parse the structured response
    # For now, return a simplified structure
    return {
        "iteration": 1,
        "accuracy": "Review completed",
        "design": "Design reviewed",
        "function": "Function reviewed",
        "form": "Form reviewed",
        "rating": 3,  # Default middle rating
        "issues": ["Needs parsing implementation"],
        "suggestions": ["Implement response parsing"]
    }

def get_reviewer_provider():
    """Determine which rubber duck reviewer to use."""
    provider = os.getenv("RUBBER_DUCK_PROVIDER", "simulate").lower()
    model = os.getenv("RUBBER_DUCK_MODEL", "")
    
    if provider == "simulate":
        return "simulate", None, None
    elif provider == "pool":
        return "pool", model or "poolside/laguna-test-a", None
    elif provider == "openai":
        return "openai", model or "gpt-4-turbo", os.getenv("OPENAI_API_KEY")
    elif provider == "anthropic":
        return provider, model or "claude-3-opus-20240229", os.getenv("ANTHROPIC_API_KEY")
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
        help="Show current reviewer configuration"
    )
    
    args = parser.parse_args()
    
    if args.status:
        provider, model, _ = get_reviewer_provider()
        config = {"provider": provider, "model": model}
        print(json.dumps(config, indent=2))
        if provider == "simulate":
            print("\nTo use an actual model, set environment variables:")
            print("  RUBBER_DUCK_PROVIDER=pool|openai|anthropic|api")
            print("  RUBBER_DUCK_MODEL=your-model-name")
            print("  OPENAI_API_KEY or ANTHROPIC_API_KEY as needed")
        return
    
    if not args.prompt:
        parser.error("--prompt is required unless using --status")
    
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