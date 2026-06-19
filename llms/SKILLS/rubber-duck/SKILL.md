---
name: rubber-duck
description: Standalone iterative plan refinement using direct API calls to multiple LLM providers. Creates plans with one model and reviews with another in a feedback loop. Provider-agnostic — currently supports Anthropic and Poolside. Triggers on "rubber duck review", "iterate on this plan", "refine this idea", "multi-model plan review".
metadata:
  version: "0.1.0"
---

# Rubber Duck — Multi-Provider Iterative Plan Refinement

Refine plans using two models via direct API calls (no CLI tools required). One model creates/refines the plan, another reviews it. Repeat until the reviewer approves or max iterations hit.

## How It Differs from iterative-plan-refinement

- **Direct HTTP API calls** — no dependency on `pool exec` or any CLI
- **Provider-agnostic** — swap models/providers via `.env` config
- **Portable** — runs anywhere with Python and API keys

## Defaults

| Role     | Provider  | Model             |
|----------|-----------|-------------------|
| Creator  | Poolside  | `laguna-m.1`      |
| Reviewer | Anthropic | `claude-sonnet-4-6` |

Override via `.env` or CLI flags.

## Workflow

### 1. User provides idea/prompt

A high-level description of what they want to build or plan.

### 2. Creator model generates structured plan

The creator model produces a plan in ~/plans/ with this format:

```markdown
# Plan: [Title]

## Goal
[What will be accomplished]

## Requirements
- [Key requirements]

## Design Considerations
- Approach A: [description]
- Approach B: [description]
- Selected approach: [choice] with rationale

## Implementation Steps
1. [Step with expected outcome]

## Potential Risks/Issues
- [Risk with mitigation]
```

### 3. Reviewer model critiques the plan

Reviews for: Accuracy, Design, Function, Form. Provides a rating (1-5) and actionable feedback. The reviewer **only gives feedback** — it never modifies the plan directly.

### 4. Iteration loop

1. Creator reads reviewer feedback
2. Creator refines the plan
3. Reviewer evaluates the updated plan
4. Track iteration count and contradiction history

### 5. Exit conditions

| Condition | Action |
|-----------|--------|
| Rating >= 4/5 | Output final approved plan |
| Contradiction between iterations | Escalate with `[[CONTRADICTION DETECTED]]` |
| 10 iterations without resolution | Output current plan, ask user |

## CLI Usage

```bash
# Basic — create and refine a plan
python rubber_duck.py "Build a CLI tool for customer onboarding"

# Specify models
python rubber_duck.py "Build a CLI tool" --creator poolside/laguna-m.1 --reviewer anthropic/claude-sonnet-4-6

# Override max iterations
python rubber_duck.py "Build a CLI tool" --max-turns 5

# JSON output
python rubber_duck.py "Build a CLI tool" --format json

# Check config
python rubber_duck.py --status
```

## Configuration

All config via `.env` file or environment variables:

```
ANTHROPIC_API_KEY=sk-ant-...
POOLSIDE_API_KEY=...
POOLSIDE_BASE_URL=https://api.poolsi.de

CREATOR_PROVIDER=poolside
CREATOR_MODEL=laguna-m.1
REVIEWER_PROVIDER=anthropic
REVIEWER_MODEL=claude-sonnet-4-6

MAX_ITERATIONS=10
```
