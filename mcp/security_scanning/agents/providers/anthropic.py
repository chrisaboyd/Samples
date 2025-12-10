"""
Anthropic LLM Provider.

This provider uses the Anthropic API to interact with Anthropic models.
"""

from anthropic import Anthropic

from .base import LLMProvider, LLMResponse, ToolCall


class AnthropicProvider(LLMProvider):
    """
    LLM Provider for Anthropic's models.

    Requires ANTHROPIC_API_KEY environment variable to be set.
    """

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        """
        Initialize the Anthropic provider.

        Args:
            model: Model to use. Options include:
                - claude-sonnet-4-20250514 (recommended for most tasks)
                - claude-opus-4-20250514 (most capable)
                - claude-haiku-3-20240307 (fastest/cheapest)
        """
        self._client = Anthropic()
        self._model = model

    @property
    def name(self) -> str:
        return "Anthropic"

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
        """Send completion request to Claude."""
        response = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=messages,
        )

        # Extract text content
        content = self._extract_text(response)

        # Extract tool calls
        tool_calls = [
            ToolCall(
                id=block.id,
                name=block.name,
                arguments=block.input,
            )
            for block in response.content
            if block.type == "tool_use"
        ]

        # Normalize stop reason
        stop_reason = "tool_use" if response.stop_reason == "tool_use" else "end_turn"

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            raw_response=response,
        )

    def format_tool_result(self, tool_call_id: str, result: str, is_error: bool = False) -> dict:
        """Format tool result for Anthropic's API."""
        return {
            "type": "tool_result",
            "tool_use_id": tool_call_id,
            "content": result,
            **({"is_error": True} if is_error else {}),
        }

    def format_assistant_message(self, response: LLMResponse) -> dict:
        """Format assistant response for conversation history."""
        # Anthropic expects the raw content blocks
        if response.raw_response:
            return {"role": "assistant", "content": response.raw_response.content}

        # Fallback: reconstruct from normalized response
        content = []
        if response.content:
            content.append({"type": "text", "text": response.content})
        for tc in response.tool_calls:
            content.append({
                "type": "tool_use",
                "id": tc.id,
                "name": tc.name,
                "input": tc.arguments,
            })
        return {"role": "assistant", "content": content}

    def format_tool_results_message(self, tool_results: list[dict]) -> dict:
        """
        Format tool results as a user message.

        Anthropic nests tool results inside a user message.
        """
        return {"role": "user", "content": tool_results}

    def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
        """Convert MCP tools to Anthropic format."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            for tool in mcp_tools
        ]

    def _extract_text(self, response) -> str | None:
        """Extract text content from Claude response."""
        text_parts = []
        for block in response.content:
            if hasattr(block, "text"):
                text_parts.append(block.text)
        return "\n".join(text_parts) if text_parts else None
