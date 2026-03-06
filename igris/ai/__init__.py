"""
Igris AI Module
===============

AI-powered result classification for reducing false positives.
"""

from igris.ai.providers import AIClient, PROVIDERS
from igris.ai.classifier import AIResultClassifier

# Only import SmartClassifier if available
try:
    from igris.ai.smart_classifier import SmartClassifier, ResponseType, ClassificationResult
except ImportError:
    pass
