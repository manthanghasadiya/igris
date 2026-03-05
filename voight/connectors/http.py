"""
HTTP Connector for voight
===========================

Connects to any AI agent that exposes an HTTP chat endpoint.
Works with LangChain, CrewAI, OpenAI Agents SDK, or any custom agent.

Supports common API formats:
- OpenAI-style: {"messages": [{"role": "user", "content": "..."}]}
- Simple: {"message": "..."} or {"query": "..."} or {"input": "..."}
"""

import json
from dataclasses import dataclass, field
from typing import Any

import httpx
from rich.console import Console

console = Console()


@dataclass
class AgentResponse:
    """Response from an agent interaction"""
    content: str
    raw: dict
    tool_calls: list[dict] = field(default_factory=list)
    error: str | None = None
    
    @property
    def success(self) -> bool:
        return self.error is None


@dataclass
class AgentCapabilities:
    """Discovered agent capabilities"""
    tools: list[dict] = field(default_factory=list)
    has_memory: bool = False
    has_code_execution: bool = False
    has_file_access: bool = False
    has_web_access: bool = False
    system_prompt_leaked: bool = False
    system_prompt_content: str | None = None
    raw_discovery: dict = field(default_factory=dict)


class HTTPConnector:
    """
    Connect to an AI agent via HTTP.
    
    Automatically detects the API format and adapts requests accordingly.
    """
    
    # Common API formats to try
    REQUEST_FORMATS = [
        # OpenAI-style
        lambda msg: {"messages": [{"role": "user", "content": msg}]},
        # Simple message
        lambda msg: {"message": msg},
        # Query style
        lambda msg: {"query": msg},
        # Input style  
        lambda msg: {"input": msg},
        # Content style
        lambda msg: {"content": msg},
        # Text style
        lambda msg: {"text": msg},
        # Prompt style
        lambda msg: {"prompt": msg},
    ]
    
    # Common response paths to extract content
    RESPONSE_PATHS = [
        ["choices", 0, "message", "content"],  # OpenAI
        ["response"],
        ["output"],
        ["content"],
        ["message"],
        ["text"],
        ["result"],
        ["answer"],
        ["reply"],
    ]
    
    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        auth_token: str | None = None,
    ):
        self.url = url
        self.timeout = timeout
        self.headers = headers or {}
        
        if auth_token:
            self.headers["Authorization"] = f"Bearer {auth_token}"
        
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"
        
        self.client = httpx.Client(timeout=timeout, headers=self.headers)
        self._detected_format: int | None = None
        self._conversation_history: list[dict] = []
        import uuid
        self.session_id = uuid.uuid4().hex
    
    def _extract_content(self, response_data: dict) -> str:
        """Extract content from response using common paths"""
        for path in self.RESPONSE_PATHS:
            try:
                value = response_data
                for key in path:
                    if isinstance(value, dict):
                        value = value.get(key)
                    elif isinstance(value, list) and isinstance(key, int):
                        value = value[key] if len(value) > key else None
                    else:
                        value = None
                        break
                if value and isinstance(value, str):
                    return value
            except (KeyError, IndexError, TypeError):
                continue
        
        # Fallback: return string representation
        return str(response_data)
    
    def _extract_tool_calls(self, response_data: dict) -> list[dict]:
        """Extract tool calls from response if present"""
        tool_calls = []
        
        # OpenAI format
        if "choices" in response_data:
            try:
                calls = response_data["choices"][0]["message"].get("tool_calls", [])
                tool_calls.extend(calls)
            except (KeyError, IndexError):
                pass
        
        # Direct tool_calls field
        if "tool_calls" in response_data:
            tool_calls.extend(response_data["tool_calls"])
        
        # Actions field (LangChain style)
        if "actions" in response_data:
            tool_calls.extend(response_data["actions"])
        
        return tool_calls
    
    def send(self, message: str) -> AgentResponse:
        """Send a message to the agent and get a response"""
        
        # If we've already detected the format, use it
        if self._detected_format is not None:
            return self._send_with_format(message, self._detected_format)
        
        # Try each format until one works
        for i, format_fn in enumerate(self.REQUEST_FORMATS):
            try:
                payload = format_fn(message)
                if isinstance(payload, dict):
                    if "messages" in payload:
                        payload["user"] = self.session_id
                    else:
                        payload["session_id"] = self.session_id
                        
                response = self.client.post(self.url, json=payload)
                
                if response.status_code == 200:
                    self._detected_format = i
                    data = response.json()
                    return AgentResponse(
                        content=self._extract_content(data),
                        raw=data,
                        tool_calls=self._extract_tool_calls(data),
                    )
            except Exception:
                continue
        
        return AgentResponse(
            content="",
            raw={},
            error="Could not connect to agent - tried all known API formats",
        )
    
    def _send_with_format(self, message: str, format_idx: int) -> AgentResponse:
        """Send using a known format"""
        try:
            payload = self.REQUEST_FORMATS[format_idx](message)
            if isinstance(payload, dict):
                if "messages" in payload:
                    payload["user"] = self.session_id
                else:
                    payload["session_id"] = self.session_id
                    
            response = self.client.post(self.url, json=payload)
            
            if response.status_code != 200:
                return AgentResponse(
                    content="",
                    raw={"status_code": response.status_code},
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )
            
            data = response.json()
            return AgentResponse(
                content=self._extract_content(data),
                raw=data,
                tool_calls=self._extract_tool_calls(data),
            )
        except httpx.TimeoutException:
            return AgentResponse(content="", raw={}, error="Request timed out")
        except Exception as e:
            return AgentResponse(content="", raw={}, error=str(e))
    
    def send_multi_turn(self, messages: list[str]) -> list[AgentResponse]:
        """Send multiple messages in sequence (multi-turn conversation)"""
        responses = []
        for msg in messages:
            resp = self.send(msg)
            responses.append(resp)
            if resp.error:
                break
        return responses
    
    def discover_capabilities(self) -> AgentCapabilities:
        """Discover what the agent can do by probing it"""
        caps = AgentCapabilities()
        
        # Probe for tools
        tool_probes = [
            "What tools or functions do you have access to?",
            "List all your available tools and capabilities.",
            "What can you do? What actions can you perform?",
        ]
        
        for probe in tool_probes:
            resp = self.send(probe)
            if resp.success:
                content = resp.content.lower()
                caps.raw_discovery["tools_probe"] = resp.content
                
                # Detect capabilities from response
                if any(x in content for x in ["file", "read", "write", "open", "save"]):
                    caps.has_file_access = True
                if any(x in content for x in ["execute", "run", "code", "python", "shell", "bash"]):
                    caps.has_code_execution = True
                if any(x in content for x in ["browse", "web", "search", "fetch", "url", "http"]):
                    caps.has_web_access = True
                if any(x in content for x in ["memory", "remember", "recall", "history"]):
                    caps.has_memory = True
                
                # Extract tool names if mentioned
                if resp.tool_calls:
                    caps.tools = resp.tool_calls
                
                break
        
        return caps
    
    def reset(self):
        """Reset conversation state"""
        import uuid
        self._conversation_history = []
        self.session_id = uuid.uuid4().hex
    
    def close(self):
        """Close the HTTP client"""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
