"""
Shared Security Models
======================

Data structures used across all igris modules.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    SAFE = "safe"


@dataclass
class Finding:
    """A security finding"""
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    payload: str
    response: str
    evidence: str
    remediation: str = ""
    
    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "description": self.description,
            "payload": self.payload,
            "response": self.response[:500],  # Truncate long responses
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
