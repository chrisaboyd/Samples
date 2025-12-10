# LLM Providers

Providers are adapters that let agents work with different LLM backends.

## Available Providers

| Provider | Models | Environment Variable |
|----------|--------|---------------------|
| Poolside | agent_malibu_1201_2k | `POOLSIDE_API_KEY` |

## Using a Provider

```python
from agents import get_provider, YourAgent

# Default (Poolside)
agent = YourAgent()

# Explicit provider
provider = get_provider("poolside", model="agent_malibu_1201_2k")
agent = YourAgent(provider=provider)
```

## Adding a New Provider

### 1. Create the provider file

```
agents/providers/
├── __init__.py
├── base.py
├── poolside.py
└── your_provider.py    # New file
```

### 2. Implement the provider interface

```python
"""
Your LLM Provider.
"""

from .base import LLMProvider, LLMResponse, ToolCall


class YourProvider(LLMProvider):
    """Provider for Your LLM service."""

    def __init__(self, model: str = "default-model"):
        self._model = model
        # Initialize your client here

    @property
    def name(self) -> str:
        return "YourProvider"

    @property
    def model(self) -> str:
        return self._model

    def complete(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Call your LLM API
        # Return normalized LLMResponse
        pass

    def format_tool_result(self, tool_call_id: str, result: str, is_error: bool = False) -> dict:
        # Format tool results for your provider's API
        pass

    def format_assistant_message(self, response: LLMResponse) -> dict:
        # Format assistant messages for conversation history
        pass

    def format_tool_results_message(self, tool_results: list[dict]) -> dict | list[dict]:
        # Wrap tool results in appropriate message format
        pass

    def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
        # Convert MCP tool schemas to your provider's format
        # (Override only if different from default)
        pass
```

### 3. Register in __init__.py

```python
from .your_provider import YourProvider

__all__ = [
    # ...existing exports...
    "YourProvider",
]

def get_provider(name: str, model: str | None = None) -> LLMProvider:
    providers = {
        "poolside": PoolsideProvider,
        "your_provider": YourProvider,  # Add here
    }
    # ...
```

## Provider Differences

Different LLM providers have different API formats. The key differences are:

### Message Format

| Provider | System Prompt | Tool Results |
|----------|--------------|--------------|
| Poolside | System message in list | Separate tool messages |
| OpenAI | System message in list | Separate tool messages |
| Anthropic | Separate `system` arg | Nested in user message |
| Ollama | System message in list | Separate tool messages |

### Tool Schema Format

| Provider | Schema Key | Notes |
|----------|-----------|-------|
| Poolside | `parameters` | Wrapped in `function` object |
| Anthropic | `input_schema` | JSON Schema directly |
| OpenAI | `parameters` | Wrapped in `function` object |

### Example: OpenAI / Poolside Tool Format

```python
def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.inputSchema,
            }
        }
        for tool in mcp_tools
    ]
```

## Testing Your Provider

```python
from agents.providers import get_provider

provider = get_provider("your_provider", model="your-model")

# Basic completion
response = provider.complete(
    messages=[{"role": "user", "content": "Hello"}],
    tools=[],
    system="You are a helpful assistant."
)
print(response.content)

# With tools
tools = [
    {
        "name": "test_tool",
        "description": "A test tool",
        "input_schema": {
            "type": "object",
            "properties": {"input": {"type": "string"}},
            "required": ["input"]
        }
    }
]

response = provider.complete(
    messages=[{"role": "user", "content": "Use the test tool with input 'hello'"}],
    tools=tools,
    system="You have access to tools."
)

if response.has_tool_calls:
    print(f"Tool calls: {response.tool_calls}")
```
