"""
Database models for the dashboard
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum

class ScanStatus(str, Enum):
    """Scan status enumeration"""
    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanJobModel(BaseModel):
    """Scan job data model"""
    id: str
    target: str
    workflow: str
    status: ScanStatus
    options: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    results: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

class VulnerabilityModel(BaseModel):
    """Vulnerability finding model"""
    title: str
    severity: VulnerabilitySeverity
    url: str
    description: str
    vulnerability_type: str
    payload: Optional[str] = None
    evidence: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None

class SubdomainModel(BaseModel):
    """Subdomain discovery model"""
    subdomain: str
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    is_verified: bool = False

class PortScanResult(BaseModel):
    """Port scan result model"""
    port: int
    service: str
    state: str
    version: Optional[str] = None
    banner: Optional[str] = None

class EndpointModel(BaseModel):
    """Web endpoint model"""
    url: str
    method: str
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)

class FormModel(BaseModel):
    """Web form model"""
    action: str
    method: str
    inputs: List[Dict[str, str]] = Field(default_factory=list)
    csrf_protection: bool = False

class SystemStats(BaseModel):
    """System statistics model"""
    active_scans: int
    total_scans_completed: int
    available_tools: int
    available_workflows: int
    uptime: str
    version: str
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None

class PlatformInfo(BaseModel):
    """Bug bounty platform information"""
    platform: str
    program_name: str
    in_scope: bool
    scope_details: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    bounty_range: Optional[str] = None

class NotificationSettings(BaseModel):
    """Notification settings model"""
    email_enabled: bool = False
    slack_enabled: bool = False
    discord_enabled: bool = False
    webhook_enabled: bool = False
    email_address: Optional[str] = None
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    custom_webhook: Optional[str] = None

class DashboardConfig(BaseModel):
    """Dashboard configuration model"""
    title: str = "Bug Bounty Orchestrator"
    theme: str = "dark"
    auto_refresh: bool = True
    refresh_interval: int = 30
    max_displayed_findings: int = 100
    max_displayed_subdomains: int = 200
    notifications: NotificationSettings = Field(default_factory=NotificationSettings)