---
name: iterative-plan-refinement
description: Iteratively refine plans or projects using two models (primary and rubber duck) in a feedback loop. Use when users want to develop, review, and improve ideas, plans, or projects through structured multi-model collaboration. Triggers on requests like "review this plan", "iterate on this idea", "rubber duck planning", "multi-model review", "collaborative planning".
metadata:
  version: "0.1.0"
---

# Iterative Plan Refinement

Iteratively refine plans or projects using two models in a collaborative feedback loop until completion, contradiction, or max iterations.

## Workflow

### 1. Initial Setup

1. Check for rubber duck model configuration:
   - Environment: `RUBBER_DUCK_PROVIDER` (pool, openai, anthropic, api)
   - Environment: `RUBBER_DUCK_MODEL` (e.g., `claude-3-opus-20240229`, `poolside/laguna-test-a`)
   - See [references/model-configuration.md](references/model-configuration.md) for setup options
2. If no model configured, use simulation mode (note this in output)
3. If model specified inline in prompt, use that preference

### 2. Create Initial Plan

The primary model creates a structured, articulate plan based on the user's prompt/input.

**Plan structure:**
```markdown
# Plan: [Brief Title]

## Goal
[Clear statement of what will be accomplished]

## Requirements
- [List of key requirements from original prompt]

## Design Considerations
- Approach A: [description]
- Approach B: [description]
- Selected approach: [A/B] with rationale

## Implementation Steps
1. [Step with expected outcome]
2. [Step with expected outcome]
...

## Potential Risks/Issues
- [Risk 1]
- [Risk 2]
```

### 3. Rubber Duck Review

Pass the plan to the rubber duck model with this prompt:

```
You are a rubber duck reviewer. Review the following plan for accuracy, design considerations, function, and form.

Original prompt: [original_user_prompt]
Plan to review: [plan_content]

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
```

### 4. Iteration Loop

**Repeat until done or max iterations:**

1. Primary model receives rubber duck feedback
2. Primary model refines the plan addressing the feedback
3. Track iteration count (start at 1, max 10)
4. Check for contradiction:
   - If rubber duck feedback directly contradicts a previous decision, escalate to human
   - Mark as: `[[CONTRADICTION DETECTED]]` and explain

### 5. Exit Conditions

| Condition | Action |
|-----------|--------|
| Plan is complete and rubber duck approves | Output final plan |
| Direct contradiction between models | Escalate to human for resolution |
| 10 iterations reached | Output current plan, note loop behavior, ask if continuation desired |

### 6. Output Format

Final output includes:
- The refined plan
- Summary of iterations performed
- Key changes made during refinement
- Any contradictions or concerns noted

## Implementation Details

### Calling the Rubber Duck Model

**Option 1: Poolside Model Pool (A/B Testing)**
```python
# Use environment variables:
# RUBBER_DUCK_PROVIDER=pool
# RUBBER_DUCK_MODEL=poolside/laguna-test-a
import os

provider = os.getenv("RUBBER_DUCK_PROVIDER", "pool")
model = os.getenv("RUBBER_DUCK_MODEL", "poolside/laguna-test-a")

if provider == "pool":
    response = model_pool.invoke(model=model, prompt=review_prompt)
```

**Option 2: OpenAI API**
```python
# Environment: RUBBER_DUCK_PROVIDER=openai
# Environment: RUBBER_DUCK_MODEL=gpt-4-turbo
# Environment: OPENAI_API_KEY=sk-...
import openai

response = openai.chat.completions.create(
    model=os.getenv("RUBBER_DUCK_MODEL", "gpt-4-turbo"),
    messages=[{"role": "user", "content": review_prompt}],
    api_key=os.getenv("OPENAI_API_KEY")
)
```

**Option 3: Anthropic API**
```python
# Environment: RUBBER_DUCK_PROVIDER=anthropic
# Environment: RUBBER_DUCK_MODEL=claude-3-opus-20240229
# Environment: ANTHROPIC_API_KEY=sk-ant-...
import anthropic

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
response = client.messages.create(
    model=os.getenv("RUBBER_DUCK_MODEL", "claude-3-opus-20240229"),
    max_tokens=4000,
    messages=[{"role": "user", "content": review_prompt}]
)
```

**Option 4: Generic API Endpoint**
```bash
# Environment: RUBBER_DUCK_PROVIDER=api
# Environment: RUBBER_DUCK_ENDPOINT=https://api.example.com/v1/chat
# Environment: RUBBER_DUCK_API_KEY=your-key
curl -X POST "$RUBBER_DUCK_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $RUBBER_DUCK_API_KEY" \
  -d '{
    "model": "'$RUBBER_DUCK_MODEL'",
    "messages": [{"role": "user", "content": "[review_prompt]"}]
  }'
```

**Option 5: Simulation Mode**
When no rubber duck model is available:
1. Generate initial plan
2. Provide self-review with different perspective
3. Note limitation: "**Simulation mode**: No external rubber duck model configured. Set `RUBBER_DUCK_PROVIDER` and `RUBBER_DUCK_MODEL` environment variables for actual multi-model review."

## Usage Pattern

```
User: "I want to build a web app for tracking expenses"

Assistant: 
1. Creates initial plan for expense tracker web app
2. Sends plan to rubber duck for review
3. Receives feedback, refines plan
4. Repeats until complete or contradiction

Output: Fully reviewed, refined plan
```

## Key Principles

- **Document each iteration** - Keep track of what changed and why
- **Be explicit about decisions** - Note rationale for design choices
- **Flag ambiguities** - When original prompt is unclear, ask for clarification
- **Stop on contradiction** - Don't resolve fundamental disagreements without human input

## Skill Invocation

### Automatic Triggering

This skill triggers automatically when user requests contain keywords like:
- "review this plan"
- "iterate on this idea" / "iterate on this plan"
- "rubber duck planning"
- "multi-model review"
- "collaborative planning"

### Explicit Invocation

Ask explicitly: "Use the iterative-plan-refinement skill to develop my idea"

### Portability

**This skill is fully portable:**

1. **Copy the directory** to any Poolside installation:
   ```
   cp -r iterative-plan-refinement ~/.config/poolside/skills/
   ```

2. **Configure models** per environment (see [model-configuration.md](references/model-configuration.md))

3. **No code changes needed** - Environment variables control behavior

For sharing: Create a tarball or git repo with the skill directory. Each user configures their own model endpoints/keys.