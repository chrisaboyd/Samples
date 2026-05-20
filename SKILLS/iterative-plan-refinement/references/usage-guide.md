# Using the Iterative Plan Refinement Skill

## When This Skill Triggers

- "Review this plan" - User has an existing plan to refine
- "Iterate on this idea" - User wants to develop an idea collaboratively
- "Rubber duck planning" - User wants multi-model review
- "Collaborative planning" - User wants iterative improvement

## Skill Invocation Pattern

When the skill triggers, follow this sequence:

1. **Acknowledge** - State you will use the rubber duck review process.

2. **Determine rubber duck agent** - from user prompt or default (anthropic/claude-sonnet-4.6)

3. **Create Initial Plan** - Generate the first draft based on the prompt.

4. **Iterate** - Each cycle:
   - Write plan to temp file
   - Call rubber duck via pool exec
   - Parse the rating from the response
   - Refine plan addressing feedback
   - Check exit conditions (rating >= 4, contradiction, or max 10 iterations)

5. **Output** - Present final reviewed plan with iteration summary.

## Example Invocations

### Example 1: New Project

    User: "I want to build a habit tracker app using anthropic/claude-opus-4.6"

    Assistant: Creates plan, sends to claude-opus-4.6 for review, iterates, outputs final plan.

### Example 2: Existing Plan Review

    User: "Review this plan for my API design"
    [Provides plan]

    Assistant: Sends plan to rubber duck, iterates on feedback, outputs refinements.

## Output Template

    # Final Refined Plan: [Title]

    ## Goal
    [Refined goal statement]

    ## Requirements
    [Final requirements list]

    ## Design
    [Final design with rationale]

    ## Implementation Steps
    [Ordered steps with outcomes]

    ## Risks and Mitigations
    [Identified risks with responses]

    ---

    ## Review Summary

    **Iterations:** N
    **Final Rating:** X/5
    **Rubber Duck Agent:** [agent name]

    ### Key Changes Made
    1. [Change 1 - reason]
    2. [Change 2 - reason]

    ### Outstanding Questions
    [If any remain for human]
