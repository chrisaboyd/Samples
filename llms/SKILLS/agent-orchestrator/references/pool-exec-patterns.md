# pool exec patterns

Command reference for invoking sub-agents via `pool exec`.

## Basic invocation

**Always prefer `.md` files for prompt input.** This avoids shell quoting issues, supports rich markdown, and leaves an audit trail. Use a per-run `$RUN_DIR` (see SKILL.md) to prevent collisions.

```bash
# Preferred — prompt from markdown file
cat > "$RUN_DIR/agent-task-input.md" << 'EOF'
## Task
Run the unit tests and report failures.
EOF
pool -a laguna-m.1 exec -f "$RUN_DIR/agent-task-input.md" --unsafe-auto-allow

# Short inline prompt (only for truly one-line tasks)
pool -a laguna-m.1 exec -p "Run the unit tests and report failures" --unsafe-auto-allow
```

**Important flags:**
- `--unsafe-auto-allow`: Required for non-interactive execution. Without it, the agent blocks waiting for tool-call approvals.
- `-d <path>`: Set working directory. **Always quote paths** for spaces/special chars: `-d "/path/with spaces/project"`.
- `-f <path>`: Read the prompt from a file (preferred for anything beyond a single sentence).
- `-o <format>`: Output format — `markdown` (default) or `json` (NLJSON, one object per line).

## Model selection

The `-a` flag is a **global flag on `pool`**, not on the `exec` subcommand. It must come before `exec`:

```bash
# Correct
pool -a anthropic/claude-opus-4.6 exec -f "$RUN_DIR/agent-task-input.md" --unsafe-auto-allow

# Wrong — will error
pool exec -a anthropic/claude-opus-4.6 -p "analyze this"
```

### Available models

| Model | Flag value | Best for |
|---|---|---|
| Laguna XS.2 | `laguna-xs.2` | Very well-defined, short-lived tasks: targeted edits, lookups, lint fixes, mechanical transformations |
| Laguna M Preview | `laguna-m.1` | **Default.** Guided tasks, well-scoped work, code generation, tests |
| Claude Opus 4.6 | `anthropic/claude-opus-4.6` | Escalation target: complex implementation, architecture, debugging, security review, recovery from failed attempts |
| GPT 5.5 | `openai/gpt-5.5` | Cross-checking: independent review of another model's code, plan critique, spec analysis. Not an escalation target. |

> Model availability changes. Run `pool exec --help` to check current options.

**Selection heuristic:** Use `laguna-m.1` by default. Drop to `laguna-xs.2` for very narrow, clearly-specified, short-lived work. Escalate to Opus when the task requires complex reasoning or when the cheaper model failed. Use GPT 5.5 for independent review — prefer a different model family from the implementation agent.

## Output handling

```bash
# Save to markdown
pool -a laguna-m.1 exec -f "$RUN_DIR/agent-task-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-task-output.md"

# Save to JSON (NLJSON)
pool -a laguna-m.1 exec -f "$RUN_DIR/agent-task-input.md" --unsafe-auto-allow \
  -o json > "$RUN_DIR/agent-task-output.json"
```

## Working directory

```bash
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-task-input.md" --unsafe-auto-allow
```

## Continuing conversations

Resume a previous agent run to provide follow-up instructions or retry with additional context:

```bash
# First run
pool -a laguna-m.1 exec -f "$RUN_DIR/agent-tests-input.md" --unsafe-auto-allow
# Note the Run ID from output

# Write follow-up prompt
cat > "$RUN_DIR/agent-tests-followup-input.md" << 'EOF'
## Follow-up
The previous tests passed but missed edge case X. Also add integration tests.
EOF

pool -a laguna-m.1 exec --continue <run-id> \
  -f "$RUN_DIR/agent-tests-followup-input.md" --unsafe-auto-allow
```

Use `--continue` for failure recovery instead of starting from scratch — the agent retains context from the previous run.

## Parallel execution

Always track PIDs and capture per-agent exit codes:

```bash
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-1-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-1-output.md" 2>&1 &
PID1=$!
pool -a laguna-m.1 exec -d "/path/to/project" \
  -f "$RUN_DIR/agent-2-input.md" --unsafe-auto-allow \
  -o markdown > "$RUN_DIR/agent-2-output.md" 2>&1 &
PID2=$!

wait $PID1; EXIT1=$?
wait $PID2; EXIT2=$?

# Handle per-agent exit codes
if [ $EXIT1 -ne 0 ]; then echo "Agent 1 failed (exit $EXIT1)"; fi
if [ $EXIT2 -ne 0 ]; then echo "Agent 2 failed (exit $EXIT2)"; fi
```

**Concurrency ceiling:** Run at most 4 agents concurrently. Batch in waves for more targets.

## Exit codes

| Code | Meaning | Action |
|---|---|---|
| 0 | Task completed successfully | Proceed |
| 4 | Agent explicitly could not complete the task | Retry with more context or escalate model |
| Other | Unexpected error (crash, network, etc.) | Retry same tier first, then escalate |

**Max 2 retries per agent. Max 3 model tiers.** Then report failure.

## Escalation pattern

```bash
RUN_DIR="$(mktemp -d /tmp/agent-orchestrator.XXXXXX)"

cat > "$RUN_DIR/agent-fix-input.md" << 'EOF'
## Task
Fix the failing test in the project.
EOF

# Tier 1: fast model
pool -a laguna-xs.2 exec -f "$RUN_DIR/agent-fix-input.md" \
  --unsafe-auto-allow -d "/path/to/project"
if [ $? -ne 0 ]; then
  # Tier 2: default model with failure context
  cat > "$RUN_DIR/agent-fix-escalated-input.md" << 'EOF'
## Task
Fix the failing test — the previous lightweight agent could not resolve it.
## Context
[Include previous agent output here]
EOF
  pool -a laguna-m.1 exec -f "$RUN_DIR/agent-fix-escalated-input.md" \
    --unsafe-auto-allow -d "/path/to/project"
  if [ $? -ne 0 ]; then
    # Tier 3: strongest model
    cat > "$RUN_DIR/agent-fix-opus-input.md" << 'EOF'
## Task
Two previous agents could not fix the failing test. Investigate root cause and fix.
## Context
[Include both previous outputs here]
EOF
    pool -a anthropic/claude-opus-4.6 exec -f "$RUN_DIR/agent-fix-opus-input.md" \
      --unsafe-auto-allow -d "/path/to/project"
  fi
fi

rm -rf "$RUN_DIR"
```
