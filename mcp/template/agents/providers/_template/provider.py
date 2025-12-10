"""
Template LLM Provider.

Copy this directory to create a new provider:
    cp -r agents/providers/_template agents/providers/your_provider

Then implement all the abstract methods below.
"""

import json
from ..base import LLMProvider, LLMResponse, ToolCall


class TemplateProvider(LLMProvider):
    """
    Template provider - copy and modify for your LLM backend.

    TODO:
    1. Rename this class to match your provider (e.g., OpenAIProvider)
    2. Add your SDK client initialization in __init__
    3. Implement all abstract methods
    4. Register in agents/providers/__init__.py
    """

    def __init__(self, model: str = "your-default-model"):
        """
        Initialize the provider.

        Args:
            model: Model identifier to use

        TODO: Initialize your SDK client here, e.g.:
            self._client = YourSDK(api_key=os.environ["YOUR_API_KEY"])
        """
        self._model = model
        # self._client = YourSDK()

    @property
    def name(self) -> str:
        """Provider name for display/logging."""
        return "Template"  # TODO: Change to your provider name

    @property
    def model(self) -> str:
        """Current model being used."""
        return self._model

    def complete(
        self,
        messages: list[dict],
        tools: list[dict],
        system: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Send a completion request to the LLM.

        TODO: Implement this method:
        1. Convert messages to your provider's format
        2. Call your LLM API
        3. Parse the response into LLMResponse

        Example for OpenAI-style API:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "system", "content": system}] + messages,
                tools=self.convert_mcp_tools(tools),
                max_tokens=max_tokens,
            )

            # Parse response...
            return LLMResponse(
                content=response.choices[0].message.content,
                tool_calls=[...],
                stop_reason="tool_use" if tool_calls else "end_turn",
                raw_response=response,
            )
        """
        raise NotImplementedError("Implement complete() for your provider")

    def format_tool_result(self, tool_call_id: str, result: str, is_error: bool = False) -> dict:
        """
        Format a tool result for inclusion in messages.

        TODO: Return the format your provider expects for tool results.

        Poolside format:
            return {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": result,
            }

        OpenAI format:
            return {
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": result,
            }
        """
        raise NotImplementedError("Implement format_tool_result() for your provider")

    def format_assistant_message(self, response: LLMResponse) -> dict:
        """
        Format the assistant's response for conversation history.

        TODO: Return the format your provider expects for assistant messages.

        Poolside format:
            return {
                "role": "assistant",
                "content": response.content,
                "tool_calls": [...] if response.tool_calls else None,
            }

        OpenAI format:
            return {
                "role": "assistant",
                "content": response.content,
                "tool_calls": [...] if response.tool_calls else None,
            }
        """
        raise NotImplementedError("Implement format_assistant_message() for your provider")

    def format_tool_results_message(self, tool_results: list[dict]) -> dict | list[dict]:
        """
        Format tool results into message(s) for the conversation.

        TODO: Return how your provider wants tool results in the message list.

        Poolside (nested in user message):
            return {"role": "user", "content": tool_results}

        OpenAI (separate messages - return list):
            return tool_results  # Each is already a complete message
        """
        raise NotImplementedError("Implement format_tool_results_message() for your provider")

    def convert_mcp_tools(self, mcp_tools: list) -> list[dict]:
        """
        Convert MCP tool definitions to your provider's format.

        Override this if your provider uses a different tool schema format.

        OpenAI format example:
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
        """
        # Default: Poolside-compatible format
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            for tool in mcp_tools
        ]
