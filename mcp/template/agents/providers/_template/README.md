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
from .your_provider import YourProvider

# In the get_provider() function:
providers = {
    "poolside": PoolsideProvider,
    "your_provider": YourProvider,  # Add this line
}
```

### 4. Add any required dependencies

Update `pyproject.toml`:

```toml
[project.optional-dependencies]
your_provider = ["your-sdk-package"]
```

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
