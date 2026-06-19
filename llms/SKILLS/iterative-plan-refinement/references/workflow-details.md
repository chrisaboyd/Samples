# Iterative Planning Workflows

## Detailed Iteration Process

Each iteration should follow this pattern:

### Iteration N

**State:**
- Original prompt: [prompt]
- Current plan: [plan]
- Previous feedback: [feedback]
- Iteration count: N

**Action:**
1. Analyze rubber duck feedback
2. Identify:
   - Valid concerns (must address)
   - Suggestions (consider optional)
   - Contradictions (escalate if applicable)
3. Refine the plan:
   - Update affected sections
   - Add explanations for changes made
   - Note unresolved items

**Output changes:**
- Mark modified sections with `> **Refined**: [reason]`
- Track cumulative iterations in a footer

## Contradiction Detection

A contradiction occurs when:

1. **Design contradiction**: Rubber duck suggests approach A, but it would break requirement B
   - Example: DD says "use NoSQL" but plan requires ACID transactions
   - Action: Mark `[[CONTRADICTION]]` and explain trade-offs

2. **Scope contradiction**: DD wants to expand scope, previous decision was to limit scope
   - Example: DD adds new feature, but user specified MVP
   - Action: `[[CONTRADICTION]]` - ask human to clarify scope priority

3. **Technical contradiction**: DD points out flaw that invalidates core approach
   - Example: DD notes platform doesn't support chosen technology
   - Action: `[[CONTRADICTION]]` - fundamental redesign needed

## Feedback Prioritization

| Priority | Action |
|----------|--------|
| Critical issues (accuracy, function) | Must address in next iteration |
| Design concerns | Should address, explain if not |
| Form suggestions | Consider if time allows |
| Minor wording | Optional cleanup |

## Example: Simple Web App

**Original:** "Build a todo app with React"

**Iteration 1:**
- Plan: Basic React todo with local storage
- DD Feedback: No backend persistence, no user auth considered

**Iteration 2:**
- Plan: React frontend + Node.js/Express backend + PostgreSQL
- DD Feedback: Overcomplicated for MVP, suggest Firebase

**Iteration 3:**
- Plan: Firebase backend option + user auth
- DD Feedback: Approves approach, suggests adding due dates

**Exit:** Plan approved, ready for implementation

## Maximum Iterations Warning

At iteration 10:
```
[[MAX ITERATIONS REACHED]]

The plan has gone through 10 iterations without reaching a stable state.
This may indicate:
- Vague or conflicting original requirements
- Fundamental uncertainty about the approach
- The problem may need human clarification

Current plan state:
[plan content]

Would you like to:
1. Continue iterating?
2. Get human review of the cycle?
3. Output current plan as-is?
```