"""
STDIO Connector for Voight
==========================

Connects to an AI agent that communicates via standard I/O streams using JSON lines.
"""

import json
import subprocess
import shlex
from typing import Any

from voight.connectors.http import AgentResponse, AgentCapabilities

class StdioConnector:
    """
    Connect to an AI agent via STDIO.
    
    Communicates via JSON lines over stdin/stdout.
    """
    
    RESPONSE_PATHS = [
        ["choices", 0, "message", "content"],
        ["response"],
        ["output"],
        ["content"],
        ["message"],
        ["text"],
        ["result"],
        ["answer"],
        ["reply"],
    ]
    
    def __init__(self, command: str, timeout: float = 30.0):
        self.command = command
        self.timeout = timeout
        self.process = None
        self._start_process()
        
    def _start_process(self):
        """Start or restart the agent subprocess"""
        if self.process:
            self.close()
            
        args = shlex.split(self.command)
        self.process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1  # line buffered
        )

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
        
        if "choices" in response_data:
            try:
                calls = response_data["choices"][0]["message"].get("tool_calls", [])
                tool_calls.extend(calls)
            except (KeyError, IndexError):
                pass
                
        if "tool_calls" in response_data:
            tool_calls.extend(response_data["tool_calls"])
            
        if "actions" in response_data:
            tool_calls.extend(response_data["actions"])
            
        return tool_calls

    def send(self, message: str) -> AgentResponse:
        """Send a message to the agent and get a response"""
        if not self.process or self.process.poll() is not None:
            self._start_process()
            
        payload = {"message": message}
        try:
            self.process.stdin.write(json.dumps(payload) + "\n")
            self.process.stdin.flush()
            
            line = self.process.stdout.readline()
            if not line:
                return AgentResponse(content="", raw={}, error="Agent process terminated unexpectedly")
                
            data = json.loads(line)
            return AgentResponse(
                content=self._extract_content(data),
                raw=data,
                tool_calls=self._extract_tool_calls(data)
            )
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
                
                if any(x in content for x in ["file", "read", "write", "open", "save"]):
                    caps.has_file_access = True
                if any(x in content for x in ["execute", "run", "code", "python", "shell", "bash"]):
                    caps.has_code_execution = True
                if any(x in content for x in ["browse", "web", "search", "fetch", "url", "http"]):
                    caps.has_web_access = True
                if any(x in content for x in ["memory", "remember", "recall", "history"]):
                    caps.has_memory = True
                    
                if resp.tool_calls:
                    caps.tools = resp.tool_calls
                
                break
                
        return caps

    def reset(self):
        """Reset conversation state by restarting the subprocess"""
        self._start_process()

    def close(self):
        """Close the subprocess"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
