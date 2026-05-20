# Using the Iterative Plan Refinement Skill

## When This Skill Triggers

- "Review this plan" - User has an existing plan to refine
- "Iterate on this idea" - User wants to develop an idea collaboratively  
- "Rubber duck planning" - User wants multi-model review
- "Collaborative planning" - User wants iterative improvement
- "Build me X with review" - Any project request benefiting from review

## Integration Points

### Environment Variables

If these are set, use the actual rubber duck model:

- `RUBBER_DUCK_ENDPOINT` - API endpoint URL
- `RUBBER_DUCK_API_KEY` - Authentication token
- `RUBBER_DUCK_MODEL` - Model name (default: "rubber-duck")

### Model Pool Integration

If Poolside supports routing to different models:

```
# Check if model_pool is available
if available:
    use model_pool.invoke(model="rubber-duck", prompt=review_prompt)
```

## Skill Invocation Pattern

When the skill triggers, follow this sequence:

1. **Acknowledge** - "I'll help you refine this plan iteratively using a rubber duck review process."

2. **Create Initial Plan** - Generate the first draft based on the prompt.

3. **Iterate** - Each cycle:
   - Present plan to rubber duck model (or simulate)
   - Receive structured feedback
   - Refine plan addressing feedback
   - Increment iteration counter
   - Check exit conditions

4. **Output** - Present final reviewed plan with iteration summary.

## Example Invocations

### Example 1: New Project
```
User: "I want to build a habit tracker app"

Assistant: Invoking iterative-plan-refinement skill...
[Creates plan, iterates, outputs final plan]
```

### Example 2: Existing Plan Review
```
User: "Review this plan for my API design"
[Provides plan]

Assistant: Invoking iterative-plan-refinement skill...
[Sends plan to rubber duck, iterates, outputs refinements]
```

## Simulation Mode

When no rubber duck model is configured:

1. The skill acts as both primary and review model
2. Clearly labels self-review vs. original plan
3. Notes limitations in output: "~~Simulation mode: no external rubber duck model available~~"

## Output Template

```markdown
# Final Refined Plan: [Title]

## Goal
[Refined goal statement]

## Requirements
[Final requirements list]

## Design
[Final design with rationale]

## Implementation Steps
[Ordered steps with outcomes]

## Risks & Mitigations
[Identified risks with responses]

---

## Review Summary

**Iterations:** N
**Final Rating:** X/5

### Key Changes Made
1. [Change 1 - reason]
2. [Change 2 - reason]

### Outstanding Questions
[If any remain for human]
```