---
name: agent-orchestrator
description: Use when a coding task should be split across multiple agents — 3+ independent files/modules, repetitive edits across many targets, separable roles (implement/test/review), parallel investigations, large refactors, failed single-agent attempts, or explicit requests to "parallelize", "fan out", "split this work", or "have agents check each other". Do not use for small single-file fixes, unclear exploratory tasks, or deeply sequential debugging until scoped.
---

# Agent orchestrator

You decompose complex tasks, dispatch sub-agents via `pool exec`, monitor progress, and synthesize results. You do not implement everything yourself — you coordinate agents that do, while retaining responsibility for scoping, prompt writing, integration, and final verification.

**Critical**: Proactively decide when to use multiple agents — do not wait for the user to say so. But equally, do not orchestrate when a single agent suffices. Evaluate every task against the decision framework below.

## When to orchestrate

There are two orchestration modes. Pick the right one:

| Mode | When to use | Example |
|---|---|---|
| **Parallel** | Multiple agents work at the same time on independent targets | "Add validation to all 8 API endpoints" → 3 agents, each owning 2-3 files |
| **Sequential delegation** | One agent completes a step, then another continues or reviews | "Implement feature X" → implement agent → test agent → review agent |

### Decision criteria

Use multi-agent orchestration when **any** of these apply:

1. The task has **3+ independently editable targets** (files, modules, services).
2. The task has **separable roles** where each role produces a distinct artifact (implementation, tests, review).
3. The change is **high-risk** enough to justify an independent review agent.
4. A **previous single-agent attempt failed** or produced partial results.
5. The **same transformation** must be applied to many targets.

### When NOT to orchestrate

Stay single-agent when:
- The task is a **single-file, focused change** (one bug fix, one small feature).
- The task requires **deep sequential reasoning** about one problem (debugging a race condition).
- The scope is **unclear** — explore first, then decide whether to fan out.
- The task is **exploratory** ("understand how X works").

**Do not orchestrate solely because a task is important.** Importance justifies a review agent at most, not a full fan-out.

| User task | Bad decision | Better decision |
|---|---|---|
| "Fix this typo in README" | Spawn an agent | Edit directly |
| "Debug this flaky race condition" | Fan out 3 agents on same module | Investigate single-agent until independent hypotheses exist |
| "Understand how auth works" | Spawn implement/test/review | Explore and summarize first |
| "Add one prop to a Svelte component" | Implement + test + review trio | Single-agent edit, run targeted check |
| "Tests are failing" with one clear failure | One agent per suite | Fix the known failure first |

## Tools

| Tool | Purpose |
|---|---|
| **pool exec** | Run Poolside coding agents non-interactively. Use shell backgrounding (`&`) with PID tracking for parallel dispatch. |

For exact `pool exec` syntax, model flags, output modes, and exit codes, see [references/pool-exec-patterns.md](references/pool-exec-patterns.md).

## Models

| Model | Flag | Use for |
|---|---|---|
| **Laguna XS.2** | `-a laguna-xs.2` | Speed-optimized. Very well-defined, short-lived tasks: single-file edits, find-and-replace, lint fixes, boilerplate. |
| **Laguna M Preview** | `-a laguna-m.1` | **Default.** Well-scoped tasks, code generation, tests, guided edits. |
| **Claude Opus 4.6** | `-a anthropic/claude-opus-4.6` | Escalation target and code-heavy tasks: complex implementation, architecture, debugging, security review, recovery from failed attempts. |
| **GPT 5.5** | `-a openai/gpt-5.5` | Cross-checking and non-implementation tasks: independent review of another model's code, plan critique, spec analysis. Not an escalation target — use for independent perspective. |

**Default to `laguna-m.1`.** Drop to `laguna-xs.2` for very narrow, mechanical tasks. Escalate to Opus for ambiguous or failed tasks. Use GPT 5.5 for independent review — **prefer a different model family from the implementation agent when reviewing.**

> Model availability changes. Run `pool exec --help` to check current options.

**Cost awareness:** Each dispatched agent consumes tokens. Parallel fan-out of N agents costs roughly N× a single agent. Prefer `laguna-m.1` over Opus/GPT for well-scoped tasks. Only escalate to expensive models when cheaper ones fail or when the task requires complex reasoning.

## Orchestration workflow

### 1. Analyze and decompose

Before dispatching, **always**:

1. **Pre-flight check** — verify the working tree is clean:
   ```bash
   git status --short
   ```
   If dirty in files agents may touch, stash (`git stash push -m "pre-orchestration"`) or commit first. Do not dispatch agents into a dirty tree.

2. **Scan the scope** — read the relevant files/directory tree.
3. **Count independent units** — how many files, modules, or services?
4. **Map dependencies** — what must happen in order vs. in parallel?
5. **Inventory shared files** — identify files multiple agents might touch (config, barrel exports, lockfiles, shared types, generated files). Assign them to exactly one agent or handle in a dedicated pre/post step.
6. **Pick a pattern** — fan-out, pipeline, specialist roles, investigation, or hybrid (see Patterns below).
7. **Announce your plan**:

```
Pattern: fan-out
Agents: 3 × laguna-m.1, each owning 2 handler files
Safety: shared types assigned to agent-1 only; others must not modify src/types/
Verification: pnpm test after fan-in
```

### 2. Dispatch agents

**Non-negotiable:** Create a per-run temp directory for all prompts and outputs. Clean up after synthesis.

```bash
RUN_DIR="$(mktemp -d /tmp/agent-orchestrator.XXXXXX)"
```

Write prompts using this template:

```markdown
## Task
[One-sentence objective]

## Assigned scope
You may modify:
- [file/dir list]

Do not modify:
- [shared/generated files]
- package manager lockfiles
- files outside your assigned scope
- do not run broad formatters, codemods, or package installs

## Context
[Relevant findings, prior outputs, architectural constraints]

## Requirements
1. [Requirement]
2. [Requirement]

## Verification
Run: [exact command]

## Stop conditions
Stop and report (do not edit) if:
- the fix requires files outside assigned scope
- requirements conflict with existing architecture
- tests fail for unrelated reasons

## Expected output
Report:
1. Files changed
2. Summary of implementation
3. Tests/checks run, with results
4. Any deviations from requested scope
5. Follow-up work or integration risks
```

Dispatch via `pool exec`:

```bash
cat > "$RUN_DIR/agent-validation-1-input.md" << 'EOF'
[prompt content]
EOF

# Sequential
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-validation-1-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-validation-1-output.md"

# Parallel — always track PIDs and capture exit codes
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-validation-1-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-validation-1-output.md" 2>&1 &
PID1=$!
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-validation-2-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-validation-2-output.md" 2>&1 &
PID2=$!

wait $PID1; EXIT1=$?
wait $PID2; EXIT2=$?
```

**Concurrency ceiling:** Run at most **4 agents** concurrently. Batch in waves for more targets.

### 3. Monitor and collect results

After agents complete, read each output file and check exit codes:
- Exit 0 = success
- Exit 4 = agent explicitly could not complete the task
- Other = unexpected error

### 4. Handle failures

After a failed agent:

1. **Inspect** its output and `git diff`.
2. **Decide**: keep, revert (`git checkout -- <files>`), or isolate partial changes.
3. **Do not launch dependent agents** until the working tree is coherent.
4. **Retry** with a more detailed prompt including the failure output — use `pool exec --continue <run-id>` to resume context instead of starting from scratch.
5. **Escalate** to the next model tier if the current model failed.
6. **Max 2 retries per agent.** Max 3 model tiers (XS → M → Opus). If all fail, report to the user.

### 5. Synthesize and verify

After all sub-tasks complete:

1. **Check for conflicts** — run `git diff --stat` and verify no file was modified by more than one agent. If so, reconcile manually or dispatch a merge agent.
2. **Run integration verification** — execute the project's test suite, build, and lint.
3. **Report** the consolidated result to the user.
4. **Clean up** — remove the run directory: `rm -rf "$RUN_DIR"`. Preserve on failure for debugging.

## Patterns

### Fan-out / fan-in (parallel)

**Use when:** the same transformation applies to many independent targets.

**Auto-trigger:** task mentions "all", "every", "each", or you see 3+ independent files needing the same change.

**Agent count heuristic:**
- 3-5 targets → 2 agents
- 6-12 targets → 3-4 agents
- 13+ targets → 4 agents in waves

```bash
RUN_DIR="$(mktemp -d /tmp/agent-orchestrator.XXXXXX)"

cat > "$RUN_DIR/agent-batch-1-input.md" << 'EOF'
## Task
Add input validation to src/api/users.ts and src/api/orders.ts.
## Assigned scope
You may modify: src/api/users.ts, src/api/orders.ts, tests/api/users.test.ts, tests/api/orders.test.ts
Do not modify: any other files, lockfiles, shared types, do not run broad formatters
## Requirements
- Use zod for schema validation
- Return 400 with descriptive errors for invalid input
- Add tests for validation error cases
## Verification
Run: pnpm test -- --filter api
## Stop conditions
Stop and report if: fix requires files outside assigned scope, or tests fail for unrelated reasons
## Expected output
Files changed, summary, test results, deviations, follow-ups
EOF
# (repeat for batches 2 and 3)

# Dispatch all 3 with PID tracking
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-batch-1-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-batch-1-output.md" 2>&1 & PID1=$!
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-batch-2-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-batch-2-output.md" 2>&1 & PID2=$!
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-batch-3-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-batch-3-output.md" 2>&1 & PID3=$!

wait $PID1; EXIT1=$?
wait $PID2; EXIT2=$?
wait $PID3; EXIT3=$?

# Verify integration after fan-in
rm -rf "$RUN_DIR"  # clean up (preserve on failure)
```

### Pipeline (sequential)

**Use when:** tasks have sequential dependencies — schema before API before frontend, or "migrate X" where infrastructure changes before consumers.

1. Run agent A. Verify exit 0.
2. Commit or checkpoint (`git stash push -m "stage-1"`).
3. Run agent B with context from A's output. Verify exit 0.
4. Continue the chain, checkpointing after each stage.
5. If a stage fails, roll back to the last checkpoint.

### Implement + test + review (sequential)

**Use when:** the change is non-trivial, high-risk, or cross-cutting. **Do not** use for small bug fixes or localized additions unless a prior attempt failed.

```bash
RUN_DIR="$(mktemp -d /tmp/agent-orchestrator.XXXXXX)"

# Step 1: Implement
cat > "$RUN_DIR/agent-implement-input.md" << 'EOF'
## Task
Implement [feature].
## Assigned scope
You may modify: [file list]
Do not modify: [exclusions], do not run broad formatters or package installs
## Requirements
[Detailed requirements]
## Verification
Run: [build/typecheck command]
## Stop conditions
Stop and report if: fix requires files outside assigned scope, or requirements conflict with existing architecture
## Expected output
Files changed, summary, checks run, deviations, follow-ups
EOF

pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-implement-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-implement-output.md"

# Step 2: Test (sequential, same directory)
cat > "$RUN_DIR/agent-test-input.md" << 'EOF'
## Task
Write comprehensive tests for [files]. Cover happy paths, edge cases, errors.
## Verification
Run: [test command] — all tests must pass.
## Stop conditions
Stop and report if: tests fail for unrelated reasons, or test setup requires infrastructure changes outside scope
## Expected output
Files changed, test commands run, results, coverage notes
EOF

pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-test-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-test-output.md"

# Step 3: Review (different model family for objectivity)
cat > "$RUN_DIR/agent-review-input.md" << 'EOF'
## Task
Review the recent changes for correctness, security, performance, and style.
## Mode
Review-only. Do not modify files. Report findings with severity and file/line references.
## Expected output
- Verdict: pass / pass with concerns / fail
- Findings ranked by severity with file:line references
- Suggested fixes (do not apply them)
EOF

pool -a openai/gpt-5.5 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-review-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-review-output.md"

rm -rf "$RUN_DIR"
```

### Investigation fan-out (parallel, read-only)

**Use when:** there are multiple independent hypotheses or failure clusters to investigate without editing code yet.

Each agent investigates one hypothesis, avoids modifying files, and reports evidence, root cause likelihood, and recommended fix. The orchestrator compares findings and chooses one implementation path.

### Escalation

1. Start with `laguna-xs.2` for trivial tasks.
2. If exit ≠ 0, retry with `laguna-m.1` (include failure context).
3. If still failing, escalate to `anthropic/claude-opus-4.6`.
4. **Max 2 retries per agent. Max 3 model tiers.** Then report failure to the user.

## Orchestrator responsibilities

**Do directly:**
- Pre-flight working tree check
- Initial scope scan and file inventory
- Decomposition and file ownership assignment
- Writing sub-agent prompts
- Reading and evaluating sub-agent outputs
- Resolving minor integration conflicts (< 5 lines)
- Final verification and user summary

**Delegate to sub-agents:**
- Independent implementation chunks
- Focused test additions
- Independent reviews
- Repetitive transformations
- Investigation of separate failure clusters

## Key principles

1. **Decide proactively, but calibrate.** Orchestrate when the task warrants it. Stay single-agent when it doesn't. When in doubt, do the work yourself and add a review agent afterward.
2. **Announce before dispatching.** Tell the user your pattern, agent count, model choices, scope assignments, and verification plan.
3. **Prompt quality is everything.** Use the full prompt template — Task, Assigned scope, Context, Requirements, Verification, Stop conditions, Expected output.
4. **Isolate agents.** Partition files so each agent has exclusive ownership. Explicitly forbid edits outside assigned scope. Do not let parallel agents run broad formatters, codemods, or package installs.
5. **Track PIDs and exit codes.** Always capture per-agent results for targeted retry/escalation.
6. **Checkpoint between pipeline stages.** Commit or stash after each successful stage so failures can be rolled back.
7. **Verify the whole.** Individual agents succeeding does not guarantee the combined result is correct. Always run integration verification after fan-in.
8. **Prefer review-only reviewers.** Review agents should report findings without modifying code unless explicitly asked to fix low-risk issues.
9. **Clean up.** Remove `$RUN_DIR` after successful synthesis. Preserve on failure for debugging.
