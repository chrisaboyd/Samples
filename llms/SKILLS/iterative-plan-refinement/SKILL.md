---
name: iterative-plan-refinement
description: Iteratively refine plans or projects using two models (primary and rubber duck) in a feedback loop. Use when users want to develop, review, and improve ideas, plans, or projects through structured multi-model collaboration. Triggers on requests like "review this plan", "iterate on this idea", "rubber duck planning", "multi-model review", "collaborative planning".
metadata:
  version: "0.4.0"
---

# Iterative Plan Refinement

Iteratively refine plans using two models: you (primary) create and refine the plan, a rubber duck model (called via `pool exec`) reviews it. Repeat until approved or max iterations.

## Important: Interaction Model

When you need to ask the user clarifying questions, just write them as plain text in the conversation. Do NOT use structured "Ask user" tool calls — they will fail. Simply output your questions as text and wait for the user to respond.

## Workflow

### 1. Determine Rubber Duck Agent

The user specifies which pool agent to use as the rubber duck reviewer:
- Inline in prompt: `"Review this plan using anthropic/claude-sonnet-4.6"`
- CLI flag: `-a anthropic/claude-sonnet-4.6`
- Default: `anthropic/claude-sonnet-4.6`

Available agents (run `pool agents list`):
- `anthropic/claude-sonnet-4.6`, `anthropic/claude-opus-4.6`, `anthropic/claude-opus-4.7`
- `openai/gpt-5.5`
- `laguna-m.1`, `laguna-xs.2`

### 2. Create Initial Plan

You (the primary model) create a structured plan from the user's prompt:

```markdown
# Plan: [Brief Title]

## Goal
[Clear statement of what will be accomplished]

## Requirements
- [Key requirements from original prompt]

## Design Considerations
- Approach A: [description]
- Approach B: [description]
- Selected approach: [A/B] with rationale

## Implementation Steps
1. [Step with expected outcome]
2. [Step with expected outcome]

## Potential Risks/Issues
- [Risk 1]
- [Risk 2]
```

### 3. Send to Rubber Duck

Always write the plan to a temp file and call the rubber duck via the helper script:

```bash
python scripts/iterative_plan_refinement.py \
  -p "$(cat /tmp/plan_for_review.md)" \
  -a "anthropic/claude-sonnet-4.6" \
  -o json
```

Or call `pool exec` directly:

```bash
pool exec -a "anthropic/claude-sonnet-4.6" \
  -f /tmp/review_prompt.md \
  --unsafe-auto-allow \
  -o markdown
```

The rubber duck reviews for: Accuracy, Design, Function, Form, and provides a Rating (1-5).

### 4. Iteration Loop

**Repeat until done or max iterations (10):**

1. Read the rubber duck's feedback
2. Refine the plan addressing the feedback
3. Send the updated plan back to the rubber duck
4. Track iteration count
5. Check for contradiction:
   - If rubber duck feedback directly contradicts a previous iteration's feedback, escalate to human
   - Mark as: `[[CONTRADICTION DETECTED]]` and explain

### 5. Exit Conditions

| Condition | Action |
|-----------|--------|
| Rating >= 4 | Output final approved plan |
| Direct contradiction between iterations | Escalate to human with `[[CONTRADICTION DETECTED]]` |
| 10 iterations reached | Output current plan, ask if user wants to continue |

### 6. Output Format

Final output includes:
- The refined plan
- Summary of iterations performed (count, key changes per iteration)
- Any contradictions or concerns noted

## Key Principles

- **Document each iteration** — note what changed and why
- **Be explicit about decisions** — include rationale for design choices
- **Flag ambiguities as plain text** — if the prompt is unclear, state your assumptions and questions as normal text output in the conversation. Do NOT use structured tool calls (like "Ask user") to ask questions. Just write your questions as text and wait for the user to respond before proceeding.
- **Stop on contradiction** — don't resolve fundamental disagreements without human input
- **Fail loudly** — if pool exec fails, report the error; never silently simulate

## Skill Invocation

### Automatic Triggering

Triggers on keywords: "review this plan", "iterate on this idea", "rubber duck planning", "multi-model review", "collaborative planning"

### Explicit Invocation

- `"Use the iterative-plan-refinement skill to develop my idea"`
- `"Review this plan using anthropic/claude-opus-4.6"`

### CLI Usage

```bash
# Review with default agent (anthropic/claude-sonnet-4.6)
python scripts/iterative_plan_refinement.py -p "Build a web app for tracking expenses"

# Review with specific agent
python scripts/iterative_plan_refinement.py -p "Build a web app" -a "openai/gpt-5.5"

# Check configuration
python scripts/iterative_plan_refinement.py --status
```
