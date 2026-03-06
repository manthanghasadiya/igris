"""
igris Attack Modules
=======================

Security testing modules for AI agents.
"""

from igris.modules.prompt_injection import (
    PromptInjectionScanner,
    detect_tool_execution,
    detect_refusal,
    detect_system_prompt_leak,
    detect_instruction_override,
)
from igris.modules.models import Finding, Severity, Confidence
from igris.modules.tool_chain import ToolChainScanner
from igris.modules.exfiltration import ExfiltrationScanner
from igris.modules.adaptive import AdaptiveScanner, VulnSignal, ProbeResult

__all__ = [
    "PromptInjectionScanner",
    "ToolChainScanner",
    "ExfiltrationScanner",
    "AdaptiveScanner",
    "VulnSignal",
    "ProbeResult",
    "Finding",
    "Severity",
    "Confidence",
    "detect_tool_execution",
    "detect_refusal",
    "detect_system_prompt_leak",
    "detect_instruction_override",
]
