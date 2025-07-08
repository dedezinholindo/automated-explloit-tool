"""
Advanced configuration management system
"""

import os
import yaml
import json
import logging
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
import asyncio
from cryptography.fernet import Fernet
import base64

logger = logging.getLogger(__name__)

@dataclass
class ToolConfig:
    """Configuration for individual tools"""
    name: str
    enabled: bool = True
    version: Optional[str] = None
    path: Optional[str] = None
    args: Dict[str, Any] = None
    rate_limit: Optional[int] = None
    timeout: Optional[int] = None
    retry_count: int = 3
    environment: Dict[str, str] = None

    def __post_init__(self):
        if self.args is None:
            self.args = {}
        if self.environment is None:
            self.environment = {}

@dataclass
class WorkflowConfig:
    """Configuration for scan workflows"""
    name: str
    description: str
    steps: List[Dict[str, Any]]
    parallel_execution: bool = False
    timeout: Optional[int] = None
    required_tools: List[str] = None
    tags: List[str] = None

    def __post_init__(self):
        if self.required_tools is None:
            self.required_tools = []
        if self.tags is None:
            self.tags = []

@dataclass
class PlatformConfig:
    """Configuration for bug bounty platforms"""
    name: str
    enabled: bool = True
    api_endpoint: str = ""
    api_key: str = ""
    username: str = ""
    rate_limit: int = 60
    auto_submit: bool = False
    severity_threshold: str = "high"
    
@dataclass
class NotificationConfig:
    """Configuration for notifications"""
    enabled: bool = True
    channels: List[str] = None
    webhook_urls: Dict[str, str] = None
    email_settings: Dict[str, Any] = None
    severity_filters: List[str] = None

    def __post_init__(self):
        if self.channels is None:
            self.channels = []
        if self.webhook_urls is None:
            self.webhook_urls = {}
        if self.email_settings is None:
            self.email_settings = {}
        if self.severity_filters is None:
            self.severity_filters = ["critical", "high"]

class ConfigManager:
    """Advanced configuration management system"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # Configuration files
        self.main_config_file = self.config_dir / "config.yaml"
        self.tools_config_file = self.config_dir / "tools.yaml"
        self.workflows_config_file = self.config_dir / "workflows.yaml"
        self.platforms_config_file = self.config_dir / "platforms.yaml"
        self.secrets_config_file = self.config_dir / "secrets.enc"
        
        # In-memory configuration cache
        self._config_cache: Dict[str, Any] = {}
        self._last_modified: Dict[str, float] = {}
        
        # Encryption key for secrets
        self._encryption_key = self._get_or_create_encryption_key()
        
        # Load all configurations
        self._load_all_configs()
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key for secrets"""
        key_file = self.config_dir / ".encryption_key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
            return key
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        fernet = Fernet(self._encryption_key)
        encrypted = fernet.encrypt(data.encode())
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        fernet = Fernet(self._encryption_key)
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        return fernet.decrypt(encrypted_bytes).decode()
    
    def _load_all_configs(self):
        """Load all configuration files"""
        self._load_main_config()
        self._load_tools_config()
        self._load_workflows_config()
        self._load_platforms_config()
        self._load_secrets_config()
    
    def _load_main_config(self):
        """Load main configuration"""
        if not self.main_config_file.exists():
            self._create_default_main_config()
        
        with open(self.main_config_file, 'r') as f:
            self._config_cache['main'] = yaml.safe_load(f)
        
        self._last_modified['main'] = self.main_config_file.stat().st_mtime
    
    def _create_default_main_config(self):
        """Create default main configuration"""
        default_config = {
            'system': {
                'max_concurrent_scans': 3,
                'default_timeout': 3600,
                'log_level': 'INFO',
                'data_retention_days': 90,
                'enable_metrics': True,
                'enable_api': True
            },
            'scanning': {
                'default_workflow': 'comprehensive_scan',
                'rate_limiting': {
                    'enabled': True,
                    'requests_per_second': 10
                },
                'resource_limits': {
                    'max_memory_mb': 2048,
                    'max_cpu_percent': 80
                }
            },
            'output': {
                'default_format': 'json',
                'include_raw_data': False,
                'compress_results': True
            },
            'security': {
                'validate_targets': True,
                'require_scope_verification': True,
                'enable_safe_mode': True
            }
        }
        
        with open(self.main_config_file, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, indent=2)
    
    def _load_tools_config(self):
        """Load tools configuration"""
        if not self.tools_config_file.exists():
            self._create_default_tools_config()
        
        with open(self.tools_config_file, 'r') as f:
            tools_data = yaml.safe_load(f)
        
        # Convert to ToolConfig objects
        tools = {}
        for name, config in tools_data.get('tools', {}).items():
            tools[name] = ToolConfig(name=name, **config)
        
        self._config_cache['tools'] = tools
        self._last_modified['tools'] = self.tools_config_file.stat().st_mtime
    
    def _create_default_tools_config(self):
        """Create default tools configuration"""
        default_tools = {
            'tools': {
                # === SUBDOMAIN ENUMERATION ===
                'subfinder': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'subfinder',
                    'args': {
                        'sources': 'all',
                        'timeout': 30,
                        'max_time': 10,
                        'silent': True
                    },
                    'rate_limit': 100,
                    'environment': {
                        'SUBFINDER_CONFIG': '~/.config/subfinder/config.yaml'
                    }
                },
                'sublist3r': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'sublist3r',
                    'args': {
                        'threads': 40,
                        'ports': '80,443,8080,8443'
                    },
                    'timeout': 1800
                },
                'amass': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'amass',
                    'args': {
                        'timeout': 30,
                        'passive': True
                    },
                    'timeout': 3600
                },
                'assetfinder': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'assetfinder',
                    'args': {
                        'subs_only': True
                    },
                    'timeout': 300
                },
                'findomain': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'findomain',
                    'args': {
                        'threads': 50,
                        'timeout': 15
                    },
                    'timeout': 600
                },
                'crobat': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'crobat',
                    'args': {
                        'subs': True
                    },
                    'timeout': 300
                },
                'altdns': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'altdns',
                    'args': {
                        'wordlist': 'wordlists/subdomains.txt',
                        'resolve': True,
                        'threads': 10
                    },
                    'timeout': 600
                },
                'shuffledns': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'shuffledns',
                    'args': {
                        'resolvers': 'resolvers.txt',
                        'threads': 5000
                    },
                    'timeout': 600
                },
                'puredns': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'puredns',
                    'args': {
                        'resolvers': 'resolvers.txt',
                        'rate-limit': 1000
                    },
                    'timeout': 600
                },
                'massdns': {
                    'enabled': True,
                    'category': 'subdomain_enumeration',
                    'path': 'massdns',
                    'args': {
                        'resolvers': 'resolvers.txt',
                        'output': 'S'
                    },
                    'timeout': 600
                },
                
                # === DNS ENUMERATION ===
                'dnsrecon': {
                    'enabled': True,
                    'category': 'dns_enumeration',
                    'path': 'dnsrecon',
                    'args': {
                        'type': 'std',
                        'threads': 10
                    },
                    'timeout': 1800
                },
                'dnsenum': {
                    'enabled': True,
                    'category': 'dns_enumeration',
                    'path': 'dnsenum',
                    'args': {
                        'threads': 5,
                        'delay': 3
                    },
                    'timeout': 1800
                },
                'fierce': {
                    'enabled': True,
                    'category': 'dns_enumeration',
                    'path': 'fierce',
                    'args': {
                        'delay': 1,
                        'subdomain_file': 'wordlists/subdomains.txt'
                    },
                    'timeout': 1200
                },
                
                # === PORT SCANNING ===
                'nmap': {
                    'enabled': True,
                    'category': 'port_scanning',
                    'path': 'nmap',
                    'args': {
                        'scan_type': 'syn',
                        'timing': 4,
                        'top_ports': 1000
                    },
                    'timeout': 3600
                },
                'masscan': {
                    'enabled': True,
                    'category': 'port_scanning',
                    'path': 'masscan',
                    'args': {
                        'rate': 1000,
                        'ports': '1-65535'
                    },
                    'timeout': 1800
                },
                'naabu': {
                    'enabled': True,
                    'category': 'port_scanning',
                    'path': 'naabu',
                    'args': {
                        'top_ports': 1000,
                        'rate': 1000,
                        'timeout': 5000
                    },
                    'timeout': 1200
                },
                'rustscan': {
                    'enabled': True,
                    'category': 'port_scanning',
                    'path': 'rustscan',
                    'args': {
                        'timeout': 3000,
                        'tries': 1,
                        'batch_size': 5000
                    },
                    'timeout': 600
                },
                
                # === HTTP PROBING ===
                'httpx': {
                    'enabled': True,
                    'category': 'http_probing',
                    'path': 'httpx',
                    'args': {
                        'threads': 50,
                        'timeout': 10,
                        'retries': 1,
                        'status_code': True,
                        'title': True,
                        'tech_detect': True
                    },
                    'rate_limit': 200
                },
                'httprobe': {
                    'enabled': True,
                    'category': 'http_probing',
                    'path': 'httprobe',
                    'args': {
                        'concurrency': 20,
                        'timeout': 10
                    },
                    'timeout': 600
                },
                
                # === DIRECTORY/FILE BRUTEFORCING ===
                'gobuster': {
                    'enabled': True,
                    'category': 'directory_bruteforce',
                    'path': 'gobuster',
                    'args': {
                        'threads': 30,
                        'timeout': 10,
                        'wordlist': 'wordlists/SecLists/Discovery/Web-Content/common.txt',
                        'extensions': 'php,html,js,txt,xml,bak'
                    },
                    'timeout': 1800
                },
                'dirsearch': {
                    'enabled': True,
                    'category': 'directory_bruteforce',
                    'path': 'dirsearch',
                    'args': {
                        'threads': 30,
                        'timeout': 10,
                        'extensions': 'php,html,js,txt,xml,bak,old,zip'
                    },
                    'timeout': 1800
                },
                'feroxbuster': {
                    'enabled': True,
                    'category': 'directory_bruteforce',
                    'path': 'feroxbuster',
                    'args': {
                        'threads': 50,
                        'timeout': 10,
                        'wordlist': 'wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt',
                        'extensions': 'php,html,js,txt,xml'
                    },
                    'timeout': 2400
                },
                'ffuf': {
                    'enabled': True,
                    'category': 'directory_bruteforce',
                    'path': 'ffuf',
                    'args': {
                        'threads': 40,
                        'timeout': 10,
                        'wordlist': 'wordlists/SecLists/Discovery/Web-Content/big.txt',
                        'extensions': 'php,html,js,txt'
                    },
                    'timeout': 1800
                },
                'dirb': {
                    'enabled': True,
                    'category': 'directory_bruteforce',
                    'path': 'dirb',
                    'args': {
                        'wordlist': '/usr/share/dirb/wordlists/common.txt',
                        'extensions': 'php,html,js,txt'
                    },
                    'timeout': 1800
                },
                
                # === WEB CRAWLING ===
                'katana': {
                    'enabled': True,
                    'category': 'web_crawling',
                    'path': 'katana',
                    'args': {
                        'depth': 3,
                        'js_crawl': True,
                        'headless': True,
                        'form_fill': True
                    },
                    'timeout': 1800
                },
                'hakrawler': {
                    'enabled': True,
                    'category': 'web_crawling',
                    'path': 'hakrawler',
                    'args': {
                        'depth': 2,
                        'scope': 'subs',
                        'forms': True,
                        'linkfinder': True
                    },
                    'timeout': 1200
                },
                'gospider': {
                    'enabled': True,
                    'category': 'web_crawling',
                    'path': 'gospider',
                    'args': {
                        'depth': 3,
                        'concurrent': 10,
                        'timeout': 10
                    },
                    'timeout': 1800
                },
                'waybackurls': {
                    'enabled': True,
                    'category': 'web_crawling',
                    'path': 'waybackurls',
                    'args': {},
                    'timeout': 300
                },
                'gau': {
                    'enabled': True,
                    'category': 'web_crawling',
                    'path': 'gau',
                    'args': {
                        'threads': 10,
                        'timeout': 10,
                        'providers': 'wayback,commoncrawl,otx,urlscan'
                    },
                    'timeout': 600
                },
                
                # === VULNERABILITY SCANNING ===
                'nuclei': {
                    'enabled': True,
                    'category': 'vulnerability_scanning',
                    'path': 'nuclei',
                    'args': {
                        'rate_limit': 150,
                        'bulk_size': 25,
                        'timeout': 5,
                        'retries': 1,
                        'severity': 'critical,high,medium,low'
                    },
                    'timeout': 3600,
                    'environment': {
                        'NUCLEI_TEMPLATES_PATH': 'nuclei-templates'
                    }
                },
                'nikto': {
                    'enabled': True,
                    'category': 'vulnerability_scanning',
                    'path': 'nikto',
                    'args': {
                        'timeout': 10,
                        'maxtime': 300
                    },
                    'timeout': 1800
                },
                'dalfox': {
                    'enabled': True,
                    'category': 'vulnerability_scanning',
                    'path': 'dalfox',
                    'args': {
                        'worker': 40,
                        'delay': 200,
                        'timeout': 10,
                        'skip_bav': True
                    },
                    'timeout': 1200
                },
                'sqlmap': {
                    'enabled': True,
                    'category': 'vulnerability_scanning',
                    'path': 'sqlmap',
                    'args': {
                        'batch': True,
                        'random_agent': True,
                        'level': 1,
                        'risk': 1,
                        'threads': 5
                    },
                    'timeout': 1800
                },
                'jaeles': {
                    'enabled': True,
                    'category': 'vulnerability_scanning',
                    'path': 'jaeles',
                    'args': {
                        'concurrency': 20,
                        'timeout': 10,
                        'passive': True
                    },
                    'timeout': 1200
                },
                'wpscan': {
                    'enabled': True,
                    'category': 'cms_scanning',
                    'path': 'wpscan',
                    'args': {
                        'random_user_agent': True,
                        'enumerate': 'ap,at,cb,dbe'
                    },
                    'timeout': 1800
                },
                'joomscan': {
                    'enabled': True,
                    'category': 'cms_scanning',
                    'path': 'joomscan',
                    'args': {},
                    'timeout': 1200
                },
                
                # === PARAMETER DISCOVERY ===
                'arjun': {
                    'enabled': True,
                    'category': 'parameter_discovery',
                    'path': 'arjun',
                    'args': {
                        'threads': 25,
                        'delay': 0,
                        'timeout': 10
                    },
                    'timeout': 1200
                },
                'paramspider': {
                    'enabled': True,
                    'category': 'parameter_discovery',
                    'path': 'paramspider',
                    'args': {
                        'level': 'high',
                        'quiet': True
                    },
                    'timeout': 600
                },
                'x8': {
                    'enabled': True,
                    'category': 'parameter_discovery',
                    'path': 'x8',
                    'args': {
                        'wordlist': 'wordlists/parameters.txt',
                        'output_format': 'json'
                    },
                    'timeout': 900
                },
                
                # === JAVASCRIPT ANALYSIS ===
                'jsfinder': {
                    'enabled': True,
                    'category': 'javascript_analysis',
                    'path': 'jsfinder',
                    'args': {
                        'timeout': 10
                    },
                    'timeout': 600
                },
                'linkfinder': {
                    'enabled': True,
                    'category': 'javascript_analysis',
                    'path': 'linkfinder',
                    'args': {
                        'output': 'cli'
                    },
                    'timeout': 300
                },
                'secretfinder': {
                    'enabled': True,
                    'category': 'javascript_analysis',
                    'path': 'secretfinder',
                    'args': {},
                    'timeout': 300
                },
                
                # === SCREENSHOT TOOLS ===
                'gowitness': {
                    'enabled': True,
                    'category': 'screenshot',
                    'path': 'gowitness',
                    'args': {
                        'timeout': 15,
                        'resolution': '1440,900'
                    },
                    'timeout': 900
                },
                'aquatone': {
                    'enabled': True,
                    'category': 'screenshot',
                    'path': 'aquatone',
                    'args': {
                        'chrome_path': '/usr/bin/google-chrome',
                        'timeout': 30000
                    },
                    'timeout': 1200
                },
                'eyewitness': {
                    'enabled': True,
                    'category': 'screenshot',
                    'path': 'eyewitness',
                    'args': {
                        'timeout': 30,
                        'threads': 5
                    },
                    'timeout': 1200
                },
                
                # === FUZZING TOOLS ===
                'wfuzz': {
                    'enabled': True,
                    'category': 'fuzzing',
                    'path': 'wfuzz',
                    'args': {
                        'threads': 30,
                        'hide': 'BBB',
                        'wordlist': 'wordlists/SecLists/Discovery/Web-Content/big.txt'
                    },
                    'timeout': 1800
                },
                'ffuf_vhost': {
                    'enabled': True,
                    'category': 'fuzzing',
                    'path': 'ffuf',
                    'args': {
                        'threads': 40,
                        'timeout': 10,
                        'wordlist': 'wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt'
                    },
                    'timeout': 1200
                },
                
                # === CMS DETECTION ===
                'whatweb': {
                    'enabled': True,
                    'category': 'cms_detection',
                    'path': 'whatweb',
                    'args': {
                        'aggression': 3,
                        'timeout': 10
                    },
                    'timeout': 600
                },
                'cmseek': {
                    'enabled': True,
                    'category': 'cms_detection',
                    'path': 'cmseek',
                    'args': {
                        'follow_redirect': True,
                        'skip_scanned': True
                    },
                    'timeout': 600
                },
                'wappalyzer': {
                    'enabled': True,
                    'category': 'cms_detection',
                    'path': 'wappalyzer',
                    'args': {},
                    'timeout': 300
                },
                
                # === WAF DETECTION ===
                'wafw00f': {
                    'enabled': True,
                    'category': 'waf_detection',
                    'path': 'wafw00f',
                    'args': {
                        'findall': True
                    },
                    'timeout': 300
                },
                
                # === SSL/TLS ANALYSIS ===
                'sslyze': {
                    'enabled': True,
                    'category': 'ssl_analysis',
                    'path': 'sslyze',
                    'args': {
                        'regular': True
                    },
                    'timeout': 600
                },
                'testssl': {
                    'enabled': True,
                    'category': 'ssl_analysis',
                    'path': 'testssl.sh',
                    'args': {
                        'quiet': True,
                        'fast': True
                    },
                    'timeout': 900
                },
                
                # === OSINT TOOLS ===
                'theharvester': {
                    'enabled': True,
                    'category': 'osint',
                    'path': 'theHarvester',
                    'args': {
                        'limit': 500,
                        'sources': 'google,bing,duckduckgo'
                    },
                    'timeout': 600
                },
                'sherlock': {
                    'enabled': True,
                    'category': 'osint',
                    'path': 'sherlock',
                    'args': {
                        'timeout': 10
                    },
                    'timeout': 300
                },
                'recon_ng': {
                    'enabled': True,
                    'category': 'osint',
                    'path': 'recon-ng',
                    'args': {},
                    'timeout': 600
                },
                
                # === UTILITY TOOLS ===
                'anew': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'anew',
                    'args': {},
                    'timeout': 60
                },
                'unfurl': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'unfurl',
                    'args': {},
                    'timeout': 60
                },
                'gf': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'gf',
                    'args': {},
                    'timeout': 60
                },
                'qsreplace': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'qsreplace',
                    'args': {},
                    'timeout': 60
                },
                'uro': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'uro',
                    'args': {},
                    'timeout': 60
                },
                'freq': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'freq',
                    'args': {},
                    'timeout': 60
                },
                'rush': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'rush',
                    'args': {
                        'jobs': 20
                    },
                    'timeout': 300
                },
                'meg': {
                    'enabled': True,
                    'category': 'utility',
                    'path': 'meg',
                    'args': {
                        'concurrency': 20,
                        'delay': 100
                    },
                    'timeout': 600
                },
                
                # === SUBDOMAIN TAKEOVER ===
                'subjack': {
                    'enabled': True,
                    'category': 'subdomain_takeover',
                    'path': 'subjack',
                    'args': {
                        'timeout': 30,
                        'ssl': True,
                        'config': 'fingerprints.json'
                    },
                    'timeout': 600
                },
                'subover': {
                    'enabled': True,
                    'category': 'subdomain_takeover',
                    'path': 'subover',
                    'args': {
                        'threads': 10,
                        'timeout': 10
                    },
                    'timeout': 600
                },
                
                # === CORS & SECURITY MISCONFIGURATION ===
                'corsy': {
                    'enabled': True,
                    'category': 'security_misconfiguration',
                    'path': 'corsy',
                    'args': {
                        'threads': 20,
                        'timeout': 10
                    },
                    'timeout': 600
                },
                
                # === INTEGRATED PLATFORMS ===
                'bbot': {
                    'enabled': True,
                    'category': 'integrated_platform',
                    'path': 'bbot',
                    'args': {
                        'modules': ['subdomain_enum', 'port_scan', 'web_basic', 'cloud_enum']
                    },
                    'timeout': 7200
                },
                'reconftw': {
                    'enabled': True,
                    'category': 'integrated_platform',
                    'path': 'reconftw',
                    'args': {
                        'deep': True,
                        'osint': True
                    },
                    'timeout': 14400
                }
            }
        }
        
        with open(self.tools_config_file, 'w') as f:
            yaml.dump(default_tools, f, default_flow_style=False, indent=2)
    
    def _load_workflows_config(self):
        """Load workflows configuration"""
        if not self.workflows_config_file.exists():
            self._create_default_workflows_config()
        
        with open(self.workflows_config_file, 'r') as f:
            workflows_data = yaml.safe_load(f)
        
        # Convert to WorkflowConfig objects
        workflows = {}
        for name, config in workflows_data.get('workflows', {}).items():
            workflows[name] = WorkflowConfig(name=name, **config)
        
        self._config_cache['workflows'] = workflows
        self._last_modified['workflows'] = self.workflows_config_file.stat().st_mtime
    
    def _create_default_workflows_config(self):
        """Create default workflows configuration"""
        default_workflows = {
            'workflows': {
                'comprehensive_scan': {
                    'description': 'Full security assessment with all modules and tools',
                    'steps': [
                        {
                            'name': 'subdomain_discovery',
                            'tools': ['subfinder', 'sublist3r', 'amass', 'assetfinder', 'findomain'],
                            'parallel': True,
                            'timeout': 3600,
                            'description': 'Comprehensive subdomain enumeration using multiple tools'
                        },
                        {
                            'name': 'dns_enumeration',
                            'tools': ['dnsrecon', 'dnsenum'],
                            'depends_on': ['subdomain_discovery'],
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'Deep DNS enumeration and analysis'
                        },
                        {
                            'name': 'subdomain_verification',
                            'tools': ['httpx', 'httprobe'],
                            'depends_on': ['subdomain_discovery'],
                            'parallel': True,
                            'timeout': 1200,
                            'description': 'Verify live subdomains and gather HTTP information'
                        },
                        {
                            'name': 'port_scanning',
                            'tools': ['nmap', 'naabu', 'masscan'],
                            'depends_on': ['subdomain_verification'],
                            'parallel': True,
                            'timeout': 3600,
                            'description': 'Comprehensive port scanning across all live hosts'
                        },
                        {
                            'name': 'web_technology_detection',
                            'tools': ['whatweb', 'wappalyzer', 'wafw00f'],
                            'depends_on': ['subdomain_verification'],
                            'parallel': True,
                            'timeout': 900,
                            'description': 'Detect web technologies, CMS, and WAF'
                        },
                        {
                            'name': 'directory_bruteforce',
                            'tools': ['gobuster', 'dirsearch', 'feroxbuster', 'ffuf'],
                            'depends_on': ['subdomain_verification'],
                            'parallel': True,
                            'timeout': 3600,
                            'description': 'Directory and file enumeration'
                        },
                        {
                            'name': 'web_crawling',
                            'tools': ['katana', 'hakrawler', 'gospider', 'waybackurls'],
                            'depends_on': ['subdomain_verification'],
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'Web crawling and URL discovery'
                        },
                        {
                            'name': 'parameter_discovery',
                            'tools': ['arjun', 'paramspider'],
                            'depends_on': ['web_crawling'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'Discover hidden parameters'
                        },
                        {
                            'name': 'javascript_analysis',
                            'tools': ['linkfinder', 'secretfinder', 'jsfinder'],
                            'depends_on': ['web_crawling'],
                            'parallel': True,
                            'timeout': 1200,
                            'description': 'Analyze JavaScript files for endpoints and secrets'
                        },
                        {
                            'name': 'cms_scanning',
                            'tools': ['wpscan', 'joomscan', 'cmseek'],
                            'depends_on': ['web_technology_detection'],
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'CMS-specific vulnerability scanning'
                        },
                        {
                            'name': 'vulnerability_scanning',
                            'tools': ['nuclei', 'nikto'],
                            'depends_on': ['web_crawling', 'parameter_discovery'],
                            'parallel': True,
                            'timeout': 5400,
                            'description': 'Comprehensive vulnerability scanning'
                        },
                        {
                            'name': 'ssl_analysis',
                            'tools': ['sslyze', 'testssl'],
                            'depends_on': ['subdomain_verification'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'SSL/TLS security analysis'
                        },
                        {
                            'name': 'screenshots',
                            'tools': ['gowitness', 'aquatone'],
                            'depends_on': ['subdomain_verification'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'Take screenshots of all web applications'
                        }
                    ],
                    'parallel_execution': False,
                    'timeout': 21600,  # 6 hours
                    'required_tools': ['subfinder', 'httpx', 'nuclei', 'nmap'],
                    'tags': ['comprehensive', 'security', 'full-scan', 'extensive']
                },
                
                'passive_recon': {
                    'description': 'Passive reconnaissance using OSINT techniques only',
                    'steps': [
                        {
                            'name': 'passive_subdomain_discovery',
                            'tools': ['subfinder', 'amass'],
                            'args': {'passive': True},
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'Passive subdomain enumeration'
                        },
                        {
                            'name': 'osint_gathering',
                            'tools': ['theharvester', 'recon_ng'],
                            'parallel': True,
                            'timeout': 1200,
                            'description': 'Open source intelligence gathering'
                        },
                        {
                            'name': 'wayback_analysis',
                            'tools': ['waybackurls'],
                            'depends_on': ['passive_subdomain_discovery'],
                            'timeout': 600,
                            'description': 'Historical URL analysis'
                        },
                        {
                            'name': 'passive_http_probing',
                            'tools': ['httpx'],
                            'args': {'passive': True},
                            'depends_on': ['passive_subdomain_discovery'],
                            'timeout': 600,
                            'description': 'Passive HTTP service detection'
                        }
                    ],
                    'parallel_execution': True,
                    'timeout': 3600,
                    'required_tools': ['subfinder', 'theharvester'],
                    'tags': ['passive', 'osint', 'stealth', 'reconnaissance']
                },
                
                'quick_scan': {
                    'description': 'Fast security assessment for rapid results',
                    'steps': [
                        {
                            'name': 'quick_subdomain_discovery',
                            'tools': ['subfinder', 'assetfinder'],
                            'args': {'timeout': 300},
                            'parallel': True,
                            'timeout': 600,
                            'description': 'Quick subdomain enumeration'
                        },
                        {
                            'name': 'quick_verification',
                            'tools': ['httpx'],
                            'depends_on': ['quick_subdomain_discovery'],
                            'timeout': 300,
                            'description': 'Quick HTTP service verification'
                        },
                        {
                            'name': 'quick_port_scan',
                            'tools': ['naabu'],
                            'args': {'top_ports': 100},
                            'depends_on': ['quick_verification'],
                            'timeout': 600,
                            'description': 'Quick port scan of top ports'
                        },
                        {
                            'name': 'quick_vulnerability_scan',
                            'tools': ['nuclei'],
                            'args': {'templates': ['cves', 'exposures'], 'severity': 'critical,high'},
                            'depends_on': ['quick_verification'],
                            'timeout': 1200,
                            'description': 'Quick vulnerability scan for critical issues'
                        }
                    ],
                    'parallel_execution': True,
                    'timeout': 2400,
                    'required_tools': ['subfinder', 'httpx', 'nuclei'],
                    'tags': ['quick', 'fast', 'basic', 'rapid']
                },
                
                'deep_enumeration': {
                    'description': 'Deep enumeration focusing on discovery without vulnerability scanning',
                    'steps': [
                        {
                            'name': 'comprehensive_subdomain_discovery',
                            'tools': ['subfinder', 'sublist3r', 'amass', 'assetfinder', 'findomain', 'crobat'],
                            'parallel': True,
                            'timeout': 5400,
                            'description': 'Exhaustive subdomain enumeration'
                        },
                        {
                            'name': 'dns_bruteforce',
                            'tools': ['dnsrecon', 'dnsenum', 'fierce'],
                            'depends_on': ['comprehensive_subdomain_discovery'],
                            'parallel': True,
                            'timeout': 3600,
                            'description': 'DNS bruteforce and zone transfer attempts'
                        },
                        {
                            'name': 'vhost_discovery',
                            'tools': ['ffuf_vhost'],
                            'depends_on': ['comprehensive_subdomain_discovery'],
                            'timeout': 2400,
                            'description': 'Virtual host discovery'
                        },
                        {
                            'name': 'port_discovery',
                            'tools': ['nmap', 'masscan', 'naabu', 'rustscan'],
                            'depends_on': ['comprehensive_subdomain_discovery'],
                            'parallel': True,
                            'timeout': 5400,
                            'description': 'Full port discovery'
                        },
                        {
                            'name': 'web_enumeration',
                            'tools': ['gobuster', 'dirsearch', 'feroxbuster', 'ffuf', 'dirb'],
                            'depends_on': ['comprehensive_subdomain_discovery'],
                            'parallel': True,
                            'timeout': 7200,
                            'description': 'Comprehensive web directory enumeration'
                        },
                        {
                            'name': 'content_discovery',
                            'tools': ['katana', 'hakrawler', 'gospider', 'waybackurls'],
                            'depends_on': ['comprehensive_subdomain_discovery'],
                            'parallel': True,
                            'timeout': 3600,
                            'description': 'Content and URL discovery'
                        }
                    ],
                    'parallel_execution': False,
                    'timeout': 18000,  # 5 hours
                    'required_tools': ['subfinder', 'amass', 'nmap', 'gobuster'],
                    'tags': ['deep', 'enumeration', 'discovery', 'thorough']
                },
                
                'vulnerability_focused': {
                    'description': 'Vulnerability-focused scan with minimal enumeration',
                    'steps': [
                        {
                            'name': 'basic_discovery',
                            'tools': ['subfinder', 'httpx'],
                            'parallel': True,
                            'timeout': 900,
                            'description': 'Basic target discovery'
                        },
                        {
                            'name': 'technology_detection',
                            'tools': ['whatweb', 'wappalyzer'],
                            'depends_on': ['basic_discovery'],
                            'parallel': True,
                            'timeout': 600,
                            'description': 'Web technology detection'
                        },
                        {
                            'name': 'comprehensive_vulnerability_scan',
                            'tools': ['nuclei', 'nikto'],
                            'depends_on': ['basic_discovery'],
                            'parallel': True,
                            'timeout': 5400,
                            'description': 'Comprehensive vulnerability assessment'
                        },
                        {
                            'name': 'cms_vulnerability_scan',
                            'tools': ['wpscan', 'joomscan'],
                            'depends_on': ['technology_detection'],
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'CMS-specific vulnerability scanning'
                        },
                        {
                            'name': 'ssl_vulnerability_check',
                            'tools': ['sslyze', 'testssl'],
                            'depends_on': ['basic_discovery'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'SSL/TLS vulnerability assessment'
                        }
                    ],
                    'parallel_execution': False,
                    'timeout': 7200,
                    'required_tools': ['subfinder', 'httpx', 'nuclei'],
                    'tags': ['vulnerability', 'security', 'assessment', 'focused']
                },
                
                'web_application_scan': {
                    'description': 'Focused web application security testing',
                    'steps': [
                        {
                            'name': 'target_discovery',
                            'tools': ['httpx'],
                            'timeout': 300,
                            'description': 'Web application discovery'
                        },
                        {
                            'name': 'web_crawling',
                            'tools': ['katana', 'hakrawler'],
                            'depends_on': ['target_discovery'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'Web application crawling'
                        },
                        {
                            'name': 'directory_enumeration',
                            'tools': ['gobuster', 'feroxbuster'],
                            'depends_on': ['target_discovery'],
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'Directory and file enumeration'
                        },
                        {
                            'name': 'parameter_discovery',
                            'tools': ['arjun', 'paramspider'],
                            'depends_on': ['web_crawling'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'Parameter discovery and analysis'
                        },
                        {
                            'name': 'javascript_analysis',
                            'tools': ['linkfinder', 'secretfinder'],
                            'depends_on': ['web_crawling'],
                            'parallel': True,
                            'timeout': 900,
                            'description': 'JavaScript code analysis'
                        },
                        {
                            'name': 'web_vulnerability_scan',
                            'tools': ['nuclei', 'nikto'],
                            'depends_on': ['parameter_discovery', 'javascript_analysis'],
                            'parallel': True,
                            'timeout': 3600,
                            'description': 'Web application vulnerability scanning'
                        },
                        {
                            'name': 'fuzzing',
                            'tools': ['wfuzz', 'ffuf'],
                            'depends_on': ['parameter_discovery'],
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'Web application fuzzing'
                        }
                    ],
                    'parallel_execution': False,
                    'timeout': 9000,
                    'required_tools': ['httpx', 'katana', 'nuclei', 'arjun'],
                    'tags': ['web-app', 'application', 'webapp', 'testing']
                },
                
                'osint_reconnaissance': {
                    'description': 'Comprehensive OSINT and reconnaissance',
                    'steps': [
                        {
                            'name': 'domain_intelligence',
                            'tools': ['theharvester', 'recon_ng'],
                            'parallel': True,
                            'timeout': 1800,
                            'description': 'Domain intelligence gathering'
                        },
                        {
                            'name': 'passive_subdomain_enum',
                            'tools': ['subfinder', 'amass', 'crobat'],
                            'args': {'passive': True},
                            'parallel': True,
                            'timeout': 2400,
                            'description': 'Passive subdomain enumeration'
                        },
                        {
                            'name': 'social_media_recon',
                            'tools': ['sherlock'],
                            'parallel': True,
                            'timeout': 600,
                            'description': 'Social media reconnaissance'
                        },
                        {
                            'name': 'historical_analysis',
                            'tools': ['waybackurls'],
                            'depends_on': ['passive_subdomain_enum'],
                            'timeout': 900,
                            'description': 'Historical data analysis'
                        },
                        {
                            'name': 'passive_verification',
                            'tools': ['httpx'],
                            'args': {'passive': True},
                            'depends_on': ['passive_subdomain_enum'],
                            'timeout': 600,
                            'description': 'Passive service verification'
                        }
                    ],
                    'parallel_execution': True,
                    'timeout': 4200,
                    'required_tools': ['theharvester', 'subfinder', 'sherlock'],
                    'tags': ['osint', 'reconnaissance', 'intelligence', 'passive']
                }
            }
        }
        
        with open(self.workflows_config_file, 'w') as f:
            yaml.dump(default_workflows, f, default_flow_style=False, indent=2)
    
    def _load_platforms_config(self):
        """Load platforms configuration"""
        if not self.platforms_config_file.exists():
            self._create_default_platforms_config()
        
        with open(self.platforms_config_file, 'r') as f:
            platforms_data = yaml.safe_load(f)
        
        # Convert to PlatformConfig objects
        platforms = {}
        for name, config in platforms_data.get('platforms', {}).items():
            platforms[name] = PlatformConfig(name=name, **config)
        
        self._config_cache['platforms'] = platforms
        self._last_modified['platforms'] = self.platforms_config_file.stat().st_mtime
    
    def _create_default_platforms_config(self):
        """Create default platforms configuration"""
        default_platforms = {
            'platforms': {
                'hackerone': {
                    'enabled': False,
                    'api_endpoint': 'https://api.hackerone.com/v1',
                    'api_key': '',
                    'username': '',
                    'rate_limit': 60,
                    'auto_submit': False,
                    'severity_threshold': 'high'
                },
                'bugcrowd': {
                    'enabled': False,
                    'api_endpoint': 'https://api.bugcrowd.com/v2',
                    'api_key': '',
                    'rate_limit': 60,
                    'auto_submit': False,
                    'severity_threshold': 'high'
                },
                'intigriti': {
                    'enabled': False,
                    'api_endpoint': 'https://api.intigriti.com/core',
                    'api_key': '',
                    'rate_limit': 60,
                    'auto_submit': False,
                    'severity_threshold': 'high'
                },
                'telegram': {
                    'enabled': False,
                    'bot_token': '',
                    'api_id': '',
                    'api_hash': '',
                    'authorized_users': [],
                    'authorized_chats': [],
                    'notifications': {
                        'scan_start': True,
                        'scan_complete': True,
                        'vulnerabilities_found': True,
                        'errors': True
                    },
                    'auto_scan': {
                        'enabled': True,
                        'default_workflow': 'comprehensive_scan',
                        'max_domains_per_message': 10
                    },
                    'reporting': {
                        'format': 'detailed',
                        'include_screenshots': True,
                        'severity_filter': 'all',
                        'max_message_length': 4096
                    }
                }
            },
            'notifications': {
                'enabled': True,
                'channels': ['slack'],
                'webhook_urls': {
                    'slack': '',
                    'discord': '',
                    'teams': ''
                },
                'email_settings': {
                    'smtp_server': '',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'from_address': '',
                    'to_addresses': []
                },
                'severity_filters': ['critical', 'high']
            }
        }
        
        with open(self.platforms_config_file, 'w') as f:
            yaml.dump(default_platforms, f, default_flow_style=False, indent=2)
    
    def _load_secrets_config(self):
        """Load encrypted secrets configuration"""
        self._config_cache['secrets'] = {}
        
        if self.secrets_config_file.exists():
            try:
                with open(self.secrets_config_file, 'r') as f:
                    encrypted_data = f.read()
                
                decrypted_data = self._decrypt_data(encrypted_data)
                self._config_cache['secrets'] = json.loads(decrypted_data)
                
                self._last_modified['secrets'] = self.secrets_config_file.stat().st_mtime
            except Exception as e:
                logger.error(f"Failed to load secrets: {e}")
    
    def get_config(self, config_type: str, key: str = None) -> Any:
        """Get configuration value"""
        self._check_and_reload_config(config_type)
        
        config = self._config_cache.get(config_type, {})
        
        if key:
            return config.get(key)
        return config
    
    def set_config(self, config_type: str, key: str, value: Any) -> bool:
        """Set configuration value"""
        try:
            if config_type not in self._config_cache:
                self._config_cache[config_type] = {}
            
            self._config_cache[config_type][key] = value
            
            # Save to file
            self._save_config(config_type)
            return True
            
        except Exception as e:
            logger.error(f"Failed to set config {config_type}.{key}: {e}")
            return False
    
    def get_tool_config(self, tool_name: str) -> Optional[ToolConfig]:
        """Get tool configuration"""
        tools = self.get_config('tools')
        return tools.get(tool_name)
    
    def get_workflow_config(self, workflow_name: str) -> Optional[WorkflowConfig]:
        """Get workflow configuration"""
        workflows = self.get_config('workflows')
        return workflows.get(workflow_name)
    
    def get_platform_config(self, platform_name: str) -> Optional[PlatformConfig]:
        """Get platform configuration"""
        platforms = self.get_config('platforms')
        return platforms.get(platform_name)
    
    def list_available_tools(self) -> List[str]:
        """List all available tools"""
        tools = self.get_config('tools')
        return [name for name, config in tools.items() if config.enabled]
    
    def list_available_workflows(self) -> List[str]:
        """List all available workflows"""
        workflows = self.get_config('workflows')
        return list(workflows.keys())
    
    def validate_tool_config(self, tool_name: str) -> bool:
        """Validate tool configuration"""
        tool_config = self.get_tool_config(tool_name)
        if not tool_config:
            return False
        
        # Check if tool executable exists
        import shutil
        if tool_config.path and not shutil.which(tool_config.path):
            logger.warning(f"Tool {tool_name} executable not found: {tool_config.path}")
            return False
        
        return True
    
    def validate_workflow_config(self, workflow_name: str) -> bool:
        """Validate workflow configuration"""
        workflow_config = self.get_workflow_config(workflow_name)
        if not workflow_config:
            return False
        
        # Check if all required tools are available
        for tool_name in workflow_config.required_tools:
            if not self.validate_tool_config(tool_name):
                logger.warning(f"Required tool {tool_name} not available for workflow {workflow_name}")
                return False
        
        return True
    
    def store_secret(self, key: str, value: str) -> bool:
        """Store encrypted secret"""
        try:
            if 'secrets' not in self._config_cache:
                self._config_cache['secrets'] = {}
            
            self._config_cache['secrets'][key] = value
            
            # Encrypt and save
            secrets_json = json.dumps(self._config_cache['secrets'])
            encrypted_data = self._encrypt_data(secrets_json)
            
            with open(self.secrets_config_file, 'w') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(self.secrets_config_file, 0o600)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secret {key}: {e}")
            return False
    
    def get_secret(self, key: str) -> Optional[str]:
        """Get decrypted secret"""
        secrets = self.get_config('secrets')
        return secrets.get(key)
    
    def _check_and_reload_config(self, config_type: str):
        """Check if config file was modified and reload if necessary"""
        config_files = {
            'main': self.main_config_file,
            'tools': self.tools_config_file,
            'workflows': self.workflows_config_file,
            'platforms': self.platforms_config_file,
            'secrets': self.secrets_config_file
        }
        
        config_file = config_files.get(config_type)
        if not config_file or not config_file.exists():
            return
        
        current_mtime = config_file.stat().st_mtime
        last_mtime = self._last_modified.get(config_type, 0)
        
        if current_mtime > last_mtime:
            logger.info(f"Reloading {config_type} configuration")
            if config_type == 'main':
                self._load_main_config()
            elif config_type == 'tools':
                self._load_tools_config()
            elif config_type == 'workflows':
                self._load_workflows_config()
            elif config_type == 'platforms':
                self._load_platforms_config()
            elif config_type == 'secrets':
                self._load_secrets_config()
    
    def _save_config(self, config_type: str):
        """Save configuration to file"""
        if config_type == 'main':
            with open(self.main_config_file, 'w') as f:
                yaml.dump(self._config_cache['main'], f, default_flow_style=False, indent=2)
        
        elif config_type == 'tools':
            tools_data = {'tools': {}}
            for name, config in self._config_cache['tools'].items():
                if isinstance(config, ToolConfig):
                    tools_data['tools'][name] = asdict(config)
                    del tools_data['tools'][name]['name']  # Remove redundant name field
                else:
                    tools_data['tools'][name] = config
            
            with open(self.tools_config_file, 'w') as f:
                yaml.dump(tools_data, f, default_flow_style=False, indent=2)
        
        elif config_type == 'workflows':
            workflows_data = {'workflows': {}}
            for name, config in self._config_cache['workflows'].items():
                if isinstance(config, WorkflowConfig):
                    workflows_data['workflows'][name] = asdict(config)
                    del workflows_data['workflows'][name]['name']  # Remove redundant name field
                else:
                    workflows_data['workflows'][name] = config
            
            with open(self.workflows_config_file, 'w') as f:
                yaml.dump(workflows_data, f, default_flow_style=False, indent=2)
        
        elif config_type == 'platforms':
            platforms_data = {'platforms': {}}
            for name, config in self._config_cache['platforms'].items():
                if isinstance(config, PlatformConfig):
                    platforms_data['platforms'][name] = asdict(config)
                    del platforms_data['platforms'][name]['name']  # Remove redundant name field
                else:
                    platforms_data['platforms'][name] = config
            
            with open(self.platforms_config_file, 'w') as f:
                yaml.dump(platforms_data, f, default_flow_style=False, indent=2)
    
    def export_config(self, output_path: str, include_secrets: bool = False) -> bool:
        """Export all configuration to a single file"""
        try:
            export_data = {
                'main': self.get_config('main'),
                'tools': {},
                'workflows': {},
                'platforms': {}
            }
            
            # Convert dataclass objects to dictionaries
            for name, config in self.get_config('tools').items():
                if isinstance(config, ToolConfig):
                    export_data['tools'][name] = asdict(config)
                else:
                    export_data['tools'][name] = config
            
            for name, config in self.get_config('workflows').items():
                if isinstance(config, WorkflowConfig):
                    export_data['workflows'][name] = asdict(config)
                else:
                    export_data['workflows'][name] = config
            
            for name, config in self.get_config('platforms').items():
                if isinstance(config, PlatformConfig):
                    export_data['platforms'][name] = asdict(config)
                else:
                    export_data['platforms'][name] = config
            
            if include_secrets:
                export_data['secrets'] = self.get_config('secrets')
            
            # Add metadata
            export_data['_metadata'] = {
                'exported_at': datetime.now().isoformat(),
                'version': '1.0.0',
                'include_secrets': include_secrets
            }
            
            with open(output_path, 'w') as f:
                yaml.dump(export_data, f, default_flow_style=False, indent=2)
            
            logger.info(f"Configuration exported to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return False
    
    def import_config(self, config_path: str, merge: bool = True) -> bool:
        """Import configuration from file"""
        try:
            with open(config_path, 'r') as f:
                import_data = yaml.safe_load(f)
            
            # Validate imported data
            if not self._validate_import_data(import_data):
                logger.error("Invalid configuration data")
                return False
            
            # Import each section
            for section in ['main', 'tools', 'workflows', 'platforms']:
                if section in import_data:
                    if merge:
                        # Merge with existing configuration
                        existing = self.get_config(section)
                        if isinstance(existing, dict):
                            existing.update(import_data[section])
                        else:
                            self._config_cache[section] = import_data[section]
                    else:
                        # Replace existing configuration
                        self._config_cache[section] = import_data[section]
                    
                    # Save to file
                    self._save_config(section)
            
            # Import secrets if present
            if 'secrets' in import_data:
                for key, value in import_data['secrets'].items():
                    self.store_secret(key, value)
            
            logger.info(f"Configuration imported from {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False
    
    def _validate_import_data(self, data: Dict[str, Any]) -> bool:
        """Validate imported configuration data"""
        # Basic structure validation
        required_sections = ['main', 'tools', 'workflows', 'platforms']
        
        for section in required_sections:
            if section in data and not isinstance(data[section], dict):
                logger.error(f"Invalid {section} configuration format")
                return False
        
        return True
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform configuration health check"""
        results = {
            'overall_status': 'healthy',
            'checks': {},
            'issues': [],
            'warnings': []
        }
        
        # Check tool availability
        tools = self.get_config('tools')
        available_tools = 0
        total_tools = len([t for t in tools.values() if t.enabled])
        
        for name, config in tools.items():
            if not config.enabled:
                continue
                
            if self.validate_tool_config(name):
                available_tools += 1
            else:
                results['issues'].append(f"Tool {name} not available")
        
        results['checks']['tools'] = {
            'available': available_tools,
            'total': total_tools,
            'percentage': (available_tools / total_tools * 100) if total_tools > 0 else 0
        }
        
        # Check workflow validity
        workflows = self.get_config('workflows')
        valid_workflows = 0
        total_workflows = len(workflows)
        
        for name in workflows:
            if self.validate_workflow_config(name):
                valid_workflows += 1
            else:
                results['issues'].append(f"Workflow {name} has issues")
        
        results['checks']['workflows'] = {
            'valid': valid_workflows,
            'total': total_workflows,
            'percentage': (valid_workflows / total_workflows * 100) if total_workflows > 0 else 0
        }
        
        # Check platform configurations
        platforms = self.get_config('platforms')
        configured_platforms = len([p for p in platforms.values() if p.enabled and p.api_key])
        
        results['checks']['platforms'] = {
            'configured': configured_platforms,
            'total': len(platforms)
        }
        
        # Determine overall status
        if results['issues']:
            results['overall_status'] = 'degraded' if len(results['issues']) < 3 else 'unhealthy'
        
        return results

# Global configuration manager instance
config_manager = ConfigManager()