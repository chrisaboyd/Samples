# Model Configuration Guide

## Configuring the Rubber Duck Model

The skill supports multiple ways to configure which rubber duck model to use:

### Option 1: Environment Variables (Recommended)

Create a `.env` file in your workspace or set these environment variables:

```bash
# Specify the model provider
RUBBER_DUCK_PROVIDER=pool    # or: openai, anthropic, api

# For Poolside model pool usage
RUBBER_DUCK_MODEL=anthropic/claude-opus-4-6
# Alternatives:
# RUBBER_DUCK_MODEL=poolside/laguna-test-a
# RUBBER_DUCK_MODEL=poolside/laguna-test-b

# For direct API calls (OpenAI or Anthropic)
RUBBER_DUCK_ENDPOINT=https://api.openai.com/v1/chat/completions
RUBBER_DUCK_API_KEY=sk-...
RUBBER_DUCK_MODEL=gpt-4-turbo

# Or for Anthropic:
# RUBBER_DUCK_ENDPOINT=https://api.anthropic.com/v1/messages
# RUBBER_DUCK_API_KEY=sk-ant-...
# RUBBER_DUCK_MODEL=claude-3-opus-20240229
```

### Option 2: Interactive Selection

When the skill triggers, it can prompt you to choose:

```
Which rubber duck model would you like to use?
1. poolside/laguna-test-a
2. poolside/laguna-test-b
3. anthropic/claude-3-opus
4. openai/gpt-4-turbo
5. No review (simulation mode)
```

### Option 3: Inline Specification

Provide the model directly in your request:

```
"Review this plan using claude-3-opus"
"Iterate on this idea with laguna-test-a"
```

## Provider-Specific Configurations

### Poolside Model Pool

For A/B testing with Laguna models:

```yaml
# .poolside/rubber-duck.yaml
rubber_duck:
  provider: pool
  model: "poolside/laguna-test-{variant}"
  # variant: a, b, or specific model name
```

### OpenAI

```bash
RUBBER_DUCK_PROVIDER=openai
RUBBER_DUCK_MODEL=gpt-4-turbo  # or gpt-4, gpt-3.5-turbo
OPENAI_API_KEY=sk-...
```

Review prompt template for OpenAI:
```python
response = openai.chat.completions.create(
    model=os.getenv("RUBBER_DUCK_MODEL", "gpt-4-turbo"),
    messages=[{"role": "user", "content": review_prompt}],
    temperature=0.7
)
```

### Anthropic

```bash
RUBBER_DUCK_PROVIDER=anthropic
RUBBER_DUCK_MODEL=claude-3-opus-20240229  # or claude-3-sonnet, claude-3-haiku
ANTHROPIC_API_KEY=sk-ant-...
```

Review prompt template for Anthropic:
```python
response = anthropic.messages.create(
    model=os.getenv("RUBBER_DUCK_MODEL", "claude-3-opus-20240229"),
    max_tokens=4000,
    messages=[{"role": "user", "content": review_prompt}]
)
```

### Generic API Endpoint

For any REST API compatible with chat completions:

```bash
RUBBER_DUCK_PROVIDER=api
RUBBER_DUCK_ENDPOINT=https://your-api.com/v1/chat
RUBBER_DUCK_API_KEY=your-key
RUBBER_DUCK_MODEL=your-model-name
```

## Skill Invocation

### How Skills Are Triggered

Skills are automatically suggested based on their `name` and `description` in the frontmatter. The skill triggers when a user's request matches keywords like:
- "review this plan"
- "iterate on this idea"
- "rubber duck planning"
- "multi-model review"

### Manual Invocation

You can explicitly ask to use this skill:

> "Use the iterative-plan-refinement skill to develop my idea"

Or reference it by name:

> "Invoke the iterative plan refinement skill"

### Portability

**Yes, this skill is portable!** To use it elsewhere:

1. **Copy the directory** to the target machine's skills folder:
   - Poolside: `~/.config/poolside/skills/iterative-plan-refinement/`
   - Other agents: Adapt to their skill loading mechanism

2. **Configure the models** on the target system:
   ```bash
   # Target system needs its own model configuration
   cp iterative-plan-refinement/references/model-config.example.env .env
   # Edit .env with target's API keys
   ```

3. **No code changes needed** - The skill uses environment variables and generic patterns

### Sharing the Skill

To share with others:

```bash
# Create a portable package
tar -czf iterative-plan-refinement.tar.gz iterative-plan-refinement/

# Or share via git
git clone <repo>
cd <repo> && cp -r iterative-plan-refinement ~/.config/poolside/skills/
```

## Default Fallback Behavior

If no rubber duck model is configured:
1. The skill operates in **simulation mode**
2. It notes the limitation in output
3. Review quality depends on the primary model's ability to simulate feedback

This ensures the skill always works, even without external model access.

## Using the Helper Script

The `scripts/iterative_plan_refinement.py` helper script provides additional ways to specify models:

### Priority Order (highest to lowest)
1. **CLI arguments**: `--provider` and `--model` flags
2. **Inline prompt specification**: "using claude-sonnet-4.6" in your prompt
3. **Environment variables**: `RUBBER_DUCK_PROVIDER` and `RUBBER_DUCK_MODEL`
4. **Simulation mode**: Fallback when nothing is configured

### CLI Examples
```bash
# Use CLI overrides
python scripts/iterative_plan_refinement.py -p "Build X" --provider anthropic --model claude-3-5-sonnet-20241022

# Check current configuration
python scripts/iterative_plan_refinement.py --status

# Use inline specification from prompt
python scripts/iterative_plan_refinement.py -p "Build X using claude-sonnet-4.6"
```

### Inline Specification Patterns
The skill parses these patterns from prompts:
- `"using claude-sonnet-4.6"` → anthropic provider, claude-3-5-sonnet-20241022
- `"with gpt-4-turbo"` → openai provider, gpt-4-turbo
- `"using anthropic/claude-opus-4.6"` → anthropic provider (with alias mapping)

### Poolside Model Aliases
When using Poolside-specific model names, they're automatically mapped:
- `claude-sonnet-4.6` → `claude-3-5-sonnet-20241022`
- `claude-opus-4.6` → `claude-3-opus-20240229`
- `claude-haiku-4.6` → `claude-3-5-haiku-20241022`

## Calling Models from Shell/TUI

### Can the skill call another model from within shell/TUI?

**Yes, but with limitations:**

1. **The `poolside` Python package** must be available in the shell environment
   - If you see "Poolside model_pool not available", the package isn't installed
   - The skill falls back to simulation mode in this case

2. **For direct API calls** (OpenAI, Anthropic), you need:
   - API keys set in environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`)
   - The respective Python packages installed (`anthropic`, `openai`)

3. **Shell invocation works** because it can:
   - Run Python scripts with `python3`
   - Make HTTP requests with `curl`
   - Use any model accessible via standard APIs

### Example: Direct curl to Anthropic API

```bash
# From shell, you can call models directly
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1000,
    "messages": [{"role": "user", "content": "Review this plan..."}]
  }'
```

### Testing Model Connectivity

Use the `--status` flag to verify your configuration:

```bash
python scripts/iterative_plan_refinement.py --status
```

This shows:
- Which provider/model will be used
- Whether API keys are detected
- If you're in simulation mode