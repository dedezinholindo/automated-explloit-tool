#!/usr/bin/env python3
"""
Environment setup script for Bug Bounty Orchestrator
"""

import os
import sys
import shutil
import subprocess
import requests
from pathlib import Path
import platform
import tempfile
import zipfile
import tarfile

def print_banner():
    """Print setup banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                  Bug Bounty Orchestrator                     ║
║                    Environment Setup                         ║
╚══════════════════════════════════════════════════════════════╝
    """)

def check_python_version():
    """Check Python version"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ is required")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected")

def check_system_requirements():
    """Check system requirements"""
    print("\n🔧 Checking system requirements...")
    
    # Check for required system tools
    required_tools = ['git', 'curl', 'wget']
    for tool in required_tools:
        if not shutil.which(tool):
            print(f"❌ {tool} not found - please install it")
            return False
        else:
            print(f"✅ {tool} found")
    
    return True

def install_go_tools():
    """Install Go-based security tools"""
    print("\n🔨 Installing Go-based security tools...")
    
    # Check if Go is installed
    if not shutil.which('go'):
        print("❌ Go not found. Please install Go first:")
        print("   https://golang.org/doc/install")
        return False
    
    go_tools = [
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/projectdiscovery/katana/cmd/katana@latest",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "github.com/tomnomnom/assetfinder@latest",
        "github.com/tomnomnom/waybackurls@latest"
    ]
    
    for tool in go_tools:
        tool_name = tool.split('/')[-1].split('@')[0]
        print(f"  Installing {tool_name}...")
        
        try:
            result = subprocess.run(
                ['go', 'install', '-v', tool],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print(f"  ✅ {tool_name} installed")
            else:
                print(f"  ❌ Failed to install {tool_name}: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"  ⏱️ {tool_name} installation timed out")
        except Exception as e:
            print(f"  ❌ Error installing {tool_name}: {e}")
    
    return True

def install_python_tools():
    """Install Python-based security tools"""
    print("\n🐍 Installing Python-based security tools...")
    
    python_tools = [
        "bbot",
        "dnspython",
        "shodan",
        "censys",
        "whatweb",
        "wafw00f"
    ]
    
    for tool in python_tools:
        print(f"  Installing {tool}...")
        try:
            result = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', tool],
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode == 0:
                print(f"  ✅ {tool} installed")
            else:
                print(f"  ❌ Failed to install {tool}: {result.stderr}")
                
        except Exception as e:
            print(f"  ❌ Error installing {tool}: {e}")

def download_nuclei_templates():
    """Download Nuclei templates"""
    print("\n🎯 Setting up Nuclei templates...")
    
    templates_dir = Path.home() / ".config" / "nuclei" / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Update templates using nuclei
        result = subprocess.run(
            ['nuclei', '-update-templates'],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print("  ✅ Nuclei templates updated")
        else:
            print(f"  ❌ Failed to update templates: {result.stderr}")
            
    except FileNotFoundError:
        print("  ⚠️ Nuclei not found, skipping template update")
    except Exception as e:
        print(f"  ❌ Error updating templates: {e}")

def setup_wordlists():
    """Setup common wordlists"""
    print("\n📝 Setting up wordlists...")
    
    wordlists_dir = Path("wordlists")
    wordlists_dir.mkdir(exist_ok=True)
    
    # Download SecLists
    seclists_dir = wordlists_dir / "SecLists"
    if not seclists_dir.exists():
        print("  Downloading SecLists...")
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', 
                 'https://github.com/danielmiessler/SecLists.git', 
                 str(seclists_dir)],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("  ✅ SecLists downloaded")
            else:
                print(f"  ❌ Failed to download SecLists: {result.stderr}")
                
        except Exception as e:
            print(f"  ❌ Error downloading SecLists: {e}")
    else:
        print("  ✅ SecLists already exists")

def setup_directories():
    """Setup required directories"""
    print("\n📁 Creating directories...")
    
    directories = [
        "data",
        "reports", 
        "config",
        "logs",
        "temp",
        "wordlists"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"  ✅ {directory}/ created")

def create_example_configs():
    """Create example configuration files"""
    print("\n⚙️ Creating configuration files...")
    
    config_dir = Path("config")
    
    # Create .env.example if it doesn't exist
    env_example = Path(".env.example")
    if not env_example.exists():
        env_content = """# Bug Bounty Orchestrator Configuration

# Database
DATABASE_URL=sqlite:///data/scans.db

# API Keys (optional)
SHODAN_API_KEY=your-shodan-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
CENSYS_API_ID=your-censys-api-id
CENSYS_API_SECRET=your-censys-secret

# Bug Bounty Platform APIs (optional)
HACKERONE_API_KEY=your-hackerone-key
HACKERONE_USERNAME=your-username
BUGCROWD_API_KEY=your-bugcrowd-key
INTIGRITI_API_KEY=your-intigriti-key

# Notifications (optional)
SLACK_WEBHOOK_URL=your-slack-webhook
DISCORD_WEBHOOK_URL=your-discord-webhook
TELEGRAM_BOT_TOKEN=your-telegram-token
TELEGRAM_CHAT_ID=your-chat-id

# Security
SECRET_KEY=change-this-secret-key

# Rate Limiting
GLOBAL_RATE_LIMIT=10
NUCLEI_RATE_LIMIT=150

# Resource Limits
MAX_MEMORY_MB=2048
MAX_CPU_PERCENT=80
"""
        with open(env_example, 'w') as f:
            f.write(env_content)
        print("  ✅ .env.example created")

def check_tool_availability():
    """Check availability of installed tools"""
    print("\n🔍 Checking tool availability...")
    
    tools_to_check = [
        'subfinder', 'httpx', 'katana', 'nuclei', 'naabu',
        'assetfinder', 'waybackurls', 'nmap', 'masscan'
    ]
    
    available_tools = []
    missing_tools = []
    
    for tool in tools_to_check:
        if shutil.which(tool):
            available_tools.append(tool)
            print(f"  ✅ {tool}")
        else:
            missing_tools.append(tool)
            print(f"  ❌ {tool}")
    
    print(f"\n📊 Tools Summary:")
    print(f"  Available: {len(available_tools)}")
    print(f"  Missing: {len(missing_tools)}")
    
    if missing_tools:
        print(f"\n⚠️ Missing tools: {', '.join(missing_tools)}")
        print("  Some functionality may be limited.")

def install_browser_dependencies():
    """Install browser dependencies for web crawling"""
    print("\n🌐 Setting up browser dependencies...")
    
    try:
        # Install playwright
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', 'playwright'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("  ✅ Playwright installed")
            
            # Install browser
            result = subprocess.run(
                [sys.executable, '-m', 'playwright', 'install', 'chromium'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("  ✅ Chromium browser installed")
            else:
                print(f"  ❌ Failed to install browser: {result.stderr}")
        else:
            print(f"  ❌ Failed to install Playwright: {result.stderr}")
            
    except Exception as e:
        print(f"  ❌ Error setting up browser: {e}")

def main():
    """Main setup function"""
    print_banner()
    
    # Check requirements
    check_python_version()
    if not check_system_requirements():
        print("\n❌ System requirements not met")
        sys.exit(1)
    
    # Setup directories
    setup_directories()
    
    # Create configs
    create_example_configs()
    
    # Install tools
    install_go_tools()
    install_python_tools()
    install_browser_dependencies()
    
    # Setup additional resources
    download_nuclei_templates()
    setup_wordlists()
    
    # Final check
    check_tool_availability()
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                     Setup Complete!                          ║
║                                                              ║
║  Next steps:                                                 ║
║  1. Copy .env.example to .env and configure your API keys   ║
║  2. Run: bb-orchestrator --help to see available commands   ║
║  3. Start the dashboard: bb-orchestrator dashboard          ║
║                                                              ║
║  For help: https://github.com/your-repo/issues              ║
╚══════════════════════════════════════════════════════════════╝
    """)

if __name__ == "__main__":
    main()