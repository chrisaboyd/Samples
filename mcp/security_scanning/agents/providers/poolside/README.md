# Creating a New LLM Provider

This template helps you add support for a new LLM backend (OpenAI, Ollama, etc.).

## Steps

### 1. Copy the template

```bash
cp -r agents/providers/_template agents/providers/your_provider
```

### 2. Implement the provider

Edit `provider.py` and implement all abstract methods:

- `complete()` - Send messages to the LLM and get a response
- `format_tool_result()` - Format tool results for this provider's API
- `format_assistant_message()` - Format assistant responses for history
- `format_tool_results_message()` - Wrap tool results in appropriate message format
- `convert_mcp_tools()` - Convert MCP tool schemas to provider's format (if different)

### 3. Register the provider

Add your provider to `agents/providers/__init__.py`:

```python
from .your_provider.provider import YourProvider

# In the get_provider() function:
providers = {
    "anthropic": AnthropicProvider,
    "your_provider": YourProvider,  # Add this line
}
```

### 4. Add any required dependencies

Update `pyproject.toml`:

```toml
[project.optional-dependencies]
your_provider = ["your-sdk-package"]
```

## Key Differences Between Providers

### Message Format

| Provider  | System Prompt          | Tool Results          |
|-----------|------------------------|-----------------------|
| Anthropic | Separate `system` arg  | Nested in user msg    |
| OpenAI    | System message in list | Separate tool messages|
| Ollama    | System message in list | Separate tool messages|

### Tool Schema Format

| Provider  | Schema Key        | Notes                          |
|-----------|-------------------|--------------------------------|
| Anthropic | `input_schema`    | JSON Schema directly           |
| OpenAI    | `parameters`      | Wrapped in `function` object   |
| Ollama    | `parameters`      | Similar to OpenAI              |

### Tool Call Format

| Provider  | Tool Call ID    | Arguments            |
|-----------|-----------------|----------------------|
| Anthropic | `block.id`      | `block.input` (dict) |
| OpenAI    | `tc.id`         | `tc.function.arguments` (JSON string) |
| Ollama    | Generate your own| `tc["function"]["arguments"]` (dict) |

## Testing Your Provider

```python
from agents.providers import get_provider

provider = get_provider("your_provider", model="your-model")

response = provider.complete(
    messages=[{"role": "user", "content": "Hello"}],
    tools=[],
    system="You are a helpful assistant."
)

print(response.content)
```
