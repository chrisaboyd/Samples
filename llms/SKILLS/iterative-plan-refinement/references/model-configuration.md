# Model Configuration Guide

## Rubber Duck Agent Selection

All model calls go through `pool exec`. The rubber duck agent is specified via the `-a` flag.

### Specifying the Agent

**CLI flag (highest priority):**
```bash
python scripts/iterative_plan_refinement.py -p "Build a web app" -a "anthropic/claude-opus-4.6"
```

**Inline in prompt:**
```
"Review this plan using anthropic/claude-sonnet-4.6"
```

**Default:** `anthropic/claude-sonnet-4.6`

### Available Agents

Run `pool agents list` to see the full list. Common agents:

| Agent | Use Case |
|-------|----------|
| `anthropic/claude-sonnet-4.6` | Default reviewer — good balance of speed and quality |
| `anthropic/claude-opus-4.6` | Deep review for complex plans |
| `anthropic/claude-opus-4.7` | Latest Opus model |
| `openai/gpt-5.5` | Cross-family review (different perspective) |
| `laguna-m.1` | Poolside default model |
| `laguna-xs.2` | Fast, lightweight review |

### Friendly Aliases

The script accepts short aliases:

| Alias | Resolves To |
|-------|-------------|
| `claude-sonnet-4.6` | `anthropic/claude-sonnet-4.6` |
| `claude-opus-4.6` | `anthropic/claude-opus-4.6` |
| `claude-opus-4.7` | `anthropic/claude-opus-4.7` |
| `gpt-5.5` | `openai/gpt-5.5` |
| `laguna` | `laguna-m.1` |
| `laguna-xs` | `laguna-xs.2` |

## How It Works

The script calls:
```bash
pool exec -a <agent> -f <prompt_file> --unsafe-auto-allow -o markdown
```

Key flags:
- `-a <agent>` — which agent/model to use (required)
- `-f <file>` — read prompt from a markdown file
- `-p <string>` — inline prompt (for short prompts)
- `--unsafe-auto-allow` — non-interactive mode (required for scripted use)
- `-o markdown` — output as markdown (vs json)

## Verifying Configuration

```bash
# Check pool is available and see current config
python scripts/iterative_plan_refinement.py --status

# List all available agents
pool agents list
```

## Portability

Copy the skill directory to any machine with `pool` installed:
```bash
cp -r iterative-plan-refinement ~/.config/poolside/skills/
```

No API keys or environment variables needed — `pool` handles authentication.
