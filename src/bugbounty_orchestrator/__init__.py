"""
Bug Bounty Orchestrator - Comprehensive Automated Security Testing Platform
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__email__ = "security@example.com"

from .core.orchestrator import BugBountyOrchestrator
from .core.scanner import ScanEngine
from .core.workflow import WorkflowEngine
from .core.config import Config

__all__ = [
    "BugBountyOrchestrator",
    "ScanEngine", 
    "WorkflowEngine",
    "Config"
]