"""
Template LLM Provider - Copy and customize for your LLM backend.

Replace 'Template' with your provider name (e.g., 'OpenAI', 'Ollama', 'Gemini').
"""

import json
from typing import Any

# Import your LLM client library here
# from your_sdk import YourClient

from ..base import LLMProvider, LLMResponse, ToolCall


class TemplateProvider(LLMProvider):
    """
    LLM Provider for [Your LLM Name].

    TODO: Update docstring with:
    - Required environment variables
    - Supported models
    - Any special configuration
    """

    def __init__(self, model: str = "your-default-model"):
        """
        Initialize the provider.

        Args:
            model: Model identifier for your LLM
        """
        # TODO: Initialize your client
        # self._client = YourClient()
        self._model = model

    @property
    def name(self) -> str:
        return "Template"  # TODO: Change to your provider name

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
        """
        Send completion request to the LLM.

        TODO: Implement this method:
        1. Convert messages to your provider's format
        2. Convert tools to your provider's format
        3. Make the API call
        4. Parse response into LLMResponse
        """
        # Example structure (customize for your provider):
        #
        # # Some providers put system in messages
        # provider_messages = [{"role": "system", "content": system}] + messages
        #
        # # Convert tools if needed
        # provider_tools = self._convert_tools_to_provider_format(tools)
        #
        # # Make API call
        # response = self._client.chat(
        #     model=self._model,
        #     messages=provider_messages,
        #     tools=provider_tools,
        #     max_tokens=max_tokens,
        # )
        #
        # # Extract content
        # content = response.message.content
        #
        # # Extract tool calls
        # tool_calls = []
        # for tc in response.message.tool_calls or []:
        #     tool_calls.append(ToolCall(
        #         id=tc.id,  # or generate: f"call_{uuid.uuid4().hex[:8]}"
        #         name=tc.function.name,
        #         arguments=json.loads(tc.function.arguments),  # if JSON string
        #     ))
        #
        # # Determine stop reason
        # stop_reason = "tool_use" if tool_calls else "end_turn"
        #
        # return LLMResponse(
        #     content=content,
        #     tool_calls=tool_calls,
        #     stop_reason=stop_reason,
        #     raw_response=response,
        # )

        raise NotImplementedError("TODO: Implement complete()")

    def format_tool_result(self, tool_call_id: str, result: str, is_error: bool = False) -> dict:
        """
        Format a tool result for the next message.

        TODO: Return the format your provider expects.

        Common patterns:
        - Anthropic: {"type": "tool_result", "tool_use_id": id, "content": result}
        - OpenAI: {"role": "tool", "tool_call_id": id, "content": result}
        """
        raise NotImplementedError("TODO: Implement format_tool_result()")

    def format_assistant_message(self, response: LLMResponse) -> dict:
        """
        Format assistant response for conversation history.

        TODO: Return the format your provider expects for assistant messages.

        Usually just: {"role": "assistant", "content": ...}
        But may need to include tool_calls for providers that track them.
        """
        raise NotImplementedError("TODO: Implement format_assistant_message()")

    def format_tool_results_message(self, tool_results: list[dict]) -> dict | list[dict]:
        """
        Format tool results into message(s) for the conversation.

        TODO: Return appropriately formatted message(s).

        Patterns:
        - Anthropic: Single user message with nested tool results
          {"role": "user", "content": tool_results}

        - OpenAI: List of separate tool messages (return list, agent handles it)
          [{"role": "tool", "tool_call_id": ..., "content": ...}, ...]
        """
        raise NotImplementedError("TODO: Implement format_tool_results_message()")

    def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
        """
        Convert MCP tool definitions to your provider's format.

        MCP format:
        {
            "name": "tool_name",
            "description": "What the tool does",
            "inputSchema": { JSON Schema }
        }

        TODO: Convert to your provider's format if different.

        OpenAI format example:
        {
            "type": "function",
            "function": {
                "name": "tool_name",
                "description": "What the tool does",
                "parameters": { JSON Schema }
            }
        }
        """
        # Default: use MCP format directly (works for Anthropic)
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            for tool in mcp_tools
        ]
