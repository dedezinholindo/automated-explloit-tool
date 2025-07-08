"""
Configuration management for the Bug Bounty Orchestrator
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseSettings, Field
from dotenv import load_dotenv

load_dotenv()

class Config(BaseSettings):
    """Main configuration class using Pydantic for validation"""
    
    # Database Configuration
    database_url: str = Field(default="sqlite:///./bugbounty.db", env="DATABASE_URL")
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    neo4j_uri: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", env="NEO4J_USER")
    neo4j_password: str = Field(default="password", env="NEO4J_PASSWORD")
    
    # Platform API Keys
    hackerone_api_key: Optional[str] = Field(default=None, env="HACKERONE_API_KEY")
    bugcrowd_api_key: Optional[str] = Field(default=None, env="BUGCROWD_API_KEY")
    intigriti_api_key: Optional[str] = Field(default=None, env="INTIGRITI_API_KEY")
    shodan_api_key: Optional[str] = Field(default=None, env="SHODAN_API_KEY")
    
    # Tool Paths
    nuclei_templates_path: str = Field(default="/home/kali/nuclei-templates", env="NUCLEI_TEMPLATES_PATH")
    wordlists_path: str = Field(default="/usr/share/wordlists", env="WORDLISTS_PATH")
    bbot_config_path: str = Field(default="/home/kali/.config/bbot", env="BBOT_CONFIG_PATH")
    
    # Notification Webhooks
    slack_webhook_url: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")
    discord_webhook_url: Optional[str] = Field(default=None, env="DISCORD_WEBHOOK_URL")
    
    # Security
    jwt_secret: str = Field(default="insecure-default-secret", env="JWT_SECRET")
    api_key: str = Field(default="default-api-key", env="API_KEY")
    
    # Performance
    max_concurrent_scans: int = Field(default=5, env="MAX_CONCURRENT_SCANS")
    scan_timeout: int = Field(default=7200, env="SCAN_TIMEOUT")
    rate_limit_per_minute: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    
    # Dashboard
    dashboard_host: str = Field(default="0.0.0.0", env="DASHBOARD_HOST")
    dashboard_port: int = Field(default=8080, env="DASHBOARD_PORT")
    debug: bool = Field(default=False, env="DEBUG")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

class PlatformConfig:
    """Platform configuration loaded from YAML files"""
    
    def __init__(self, config_path: str = "config/platform_config.yaml"):
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    self._config = yaml.safe_load(f)
            else:
                raise FileNotFoundError(f"Config file not found: {self.config_path}")
        except Exception as e:
            print(f"Error loading config: {e}")
            self._config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Default configuration if file is not found"""
        return {
            'platform': {
                'name': 'Bug Bounty Orchestrator',
                'version': '1.0.0'
            },
            'mcp_tools': {},
            'modern_tools': {},
            'workflows': {},
            'platforms': {},
            'reporting': {},
            'notifications': {},
            'security': {},
            'performance': {}
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def get_mcp_tools(self) -> Dict[str, Any]:
        """Get MCP tools configuration"""
        return self.get('mcp_tools', {})
    
    def get_modern_tools(self) -> Dict[str, Any]:
        """Get modern tools configuration"""
        return self.get('modern_tools', {})
    
    def get_workflows(self) -> Dict[str, Any]:
        """Get workflow configurations"""
        return self.get('workflows', {})
    
    def get_platform_integrations(self) -> Dict[str, Any]:
        """Get platform integration configurations"""
        return self.get('platforms', {})
    
    def is_tool_enabled(self, tool_name: str, tool_type: str = 'mcp_tools') -> bool:
        """Check if a tool is enabled"""
        tool_config = self.get(f'{tool_type}.{tool_name}', {})
        return tool_config.get('enabled', False)
    
    def get_tool_config(self, tool_name: str, tool_type: str = 'mcp_tools') -> Dict[str, Any]:
        """Get specific tool configuration"""
        return self.get(f'{tool_type}.{tool_name}.config', {})

# Global configuration instances
config = Config()
platform_config = PlatformConfig()