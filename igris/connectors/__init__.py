"""
Igris Connectors
===================

Connectors for different agent frameworks and protocols.
"""

from igris.connectors.http import HTTPConnector, AgentResponse, AgentCapabilities
from igris.connectors.stdio import StdioConnector

__all__ = ["HTTPConnector", "StdioConnector", "AgentResponse", "AgentCapabilities"]
