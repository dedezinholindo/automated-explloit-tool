# Bug Bounty Orchestrator

🚀 **Comprehensive Automated Bug Bounty Platform** with 40+ integrated security tools, advanced orchestration, Telegram bot integration, and real-time reporting.

## 🌟 Features

### 🔧 **Comprehensive Tool Integration (40+ Tools)**

#### **Subdomain Enumeration**
- **Subfinder** - Fast passive subdomain discovery
- **Sublist3r** - Python subdomain discovery with search engines
- **Amass** - In-depth attack surface mapping and asset discovery
- **Assetfinder** - Find domains and subdomains potentially related to a given domain
- **Findomain** - Cross-platform subdomain enumerator
- **Crobat** - Rapid7's Project Sonar subdomain discovery

#### **DNS Enumeration & Analysis**
- **DNSRecon** - DNS enumeration and network reconnaissance 
- **DNSEnum** - Multithreaded perl script to enumerate DNS information
- **Fierce** - Domain scanner and IP address lookup

#### **Port Scanning & Network Discovery**
- **Nmap** - Network discovery and security auditing
- **Masscan** - Internet-scale port scanner
- **Naabu** - Fast port scanner with SYN/CONNECT/UDP probe modes
- **RustScan** - Modern port scanner with customizable timing

#### **HTTP Probing & Service Detection**
- **HTTPx** - Fast and multi-purpose HTTP toolkit
- **HTTProbe** - Tool for quickly discovering HTTP services

#### **Directory & File Bruteforcing**
- **Gobuster** - Directory/file, DNS, and VHost busting tool
- **Dirsearch** - Web path scanner with comprehensive wordlists
- **Feroxbuster** - Fast, simple, recursive content discovery tool
- **ffuf** - Fast web fuzzer for directory enumeration and parameter discovery
- **Dirb** - Web content scanner with built-in wordlists

#### **Web Crawling & URL Discovery**
- **Katana** - Next-generation crawling and spidering framework
- **Hakrawler** - Fast web crawler designed for easy, quick discovery
- **GoSpider** - Fast web spider crawler with JavaScript support
- **Waybackurls** - Fetch all URLs from the Wayback Machine

#### **Vulnerability Scanning**
- **Nuclei** - Fast and customizable vulnerability scanner
- **Nikto** - Web server scanner for dangerous files and misconfigurations

#### **CMS Scanning & Detection**
- **WPScan** - WordPress security scanner
- **JoomScan** - Joomla vulnerability scanner 
- **CMSeeK** - Content Management System detection and exploitation
- **WhatWeb** - Web application fingerprinter
- **Wappalyzer** - Technology profiler for web applications

#### **Parameter Discovery**
- **Arjun** - HTTP parameter discovery suite
- **ParamSpider** - Mining parameters from dark corners of web archives
- **x8** - Hidden parameter discovery tool

#### **JavaScript Analysis**
- **JSFinder** - Find interesting information in JS files
- **LinkFinder** - Python script to discover endpoints in JavaScript files
- **SecretFinder** - Discover sensitive data in JavaScript files

#### **Screenshot & Visual Intelligence**
- **GoWitness** - Web screenshot utility using headless Chrome
- **Aquatone** - Visual inspection of websites across large amounts of hosts
- **EyeWitness** - Screenshot web applications and RDP services

#### **Fuzzing & Testing**
- **Wfuzz** - Web application fuzzer for brute forcing web applications
- **ffuf** - Fast web fuzzer written in Go

#### **WAF & Security Detection**
- **wafw00f** - Web Application Firewall fingerprinting tool

#### **SSL/TLS Analysis**
- **SSLyze** - Fast and powerful SSL/TLS server scanning library
- **testssl.sh** - Testing TLS/SSL encryption anywhere on any port

#### **OSINT & Intelligence Gathering**
- **theHarvester** - OSINT tool for gathering e-mail accounts, subdomain names
- **Sherlock** - Hunt down social media accounts by username
- **Recon-ng** - Full-featured reconnaissance framework

#### **Integrated Platforms**
- **BBOT** - Recursive internet scanner inspired by Spiderfoot
- **ReconFTW** - Tool for performing automated recon on a target domain

### 🤖 **Telegram Bot Integration**

#### **Features**
- **Real-time Notifications**: Get instant updates on scan progress and results
- **Interactive Commands**: Control scans directly from Telegram
- **Auto-scan**: Automatically start scans when domains are mentioned
- **Authorization System**: Secure access control for users and chats
- **Progress Monitoring**: Live updates with scan status and progress
- **Detailed Reporting**: Comprehensive vulnerability reports with severity filtering

#### **Commands**
```
/start - Start the bot and get help
/help - Show available commands
/scan <domain> [workflow] - Start a scan on domain
/status - Show current scan status
/scans - List recent scans
/cancel <scan_id> - Cancel a running scan
/workflows - List available workflows
/config - Show bot configuration
```

#### **Auto-scan Features**
- Domain extraction from natural language messages
- Batch processing (up to 10 domains per message)
- Smart workflow selection based on domain characteristics
- Real-time progress updates via WebSocket-style messaging

### 🔧 **Advanced Orchestration**

#### **Workflow System**
- **7 Predefined Workflows**:
  - `comprehensive_scan` - Full security assessment (6 hours)
  - `quick_scan` - Fast assessment for rapid results (40 minutes)
  - `passive_recon` - OSINT-only reconnaissance (1 hour)
  - `deep_enumeration` - Exhaustive discovery (5 hours)
  - `vulnerability_focused` - Security-focused scan (2 hours)
  - `web_application_scan` - Web app security testing (2.5 hours)
  - `osint_reconnaissance` - Intelligence gathering (1 hour)

#### **Execution Features**
- **Parallel Tool Execution**: Run multiple tools simultaneously
- **Dependency Management**: Tools execute in logical order
- **Resource Monitoring**: CPU, memory, and I/O monitoring
- **Rate Limiting**: Configurable request rates per tool
- **Timeout Management**: Individual tool and workflow timeouts
- **Error Handling**: Automatic retries and graceful failures

### 📊 **Real-time Dashboard**

#### **Web Interface Features**
- **Real-time Monitoring**: Live scan progress with WebSocket updates
- **Scan Management**: Start, stop, and manage scans
- **Results Visualization**: Interactive charts and graphs
- **Export Capabilities**: PDF, JSON, CSV, and HTML reports
- **System Monitoring**: Resource usage and performance metrics

#### **Dashboard Components**
- Scan overview with real-time status
- Vulnerability distribution charts
- Tool execution timeline
- System resource monitoring
- Scan history and analytics

### 🔧 **Configuration Management**

#### **Advanced Configuration System**
- **Encrypted Secrets**: Secure storage of API keys and credentials
- **Tool Validation**: Automatic tool availability checking
- **Import/Export**: Configuration backup and sharing
- **Health Monitoring**: System and tool health checks
- **Live Reloading**: Configuration changes without restart

#### **Configuration Categories**
- **Tools**: Individual tool settings and parameters
- **Workflows**: Custom workflow definitions
- **Platforms**: Bug bounty platform integrations
- **Notifications**: Alert and reporting settings

### 🔗 **Platform Integrations**

#### **Bug Bounty Platforms**
- **HackerOne**: API integration for program discovery and submission
- **Bugcrowd**: Program enumeration and vulnerability reporting
- **Intigriti**: Platform integration for EU-focused programs

#### **Notification Channels**
- **Telegram**: Real-time bot notifications and control
- **Slack**: Team collaboration and alerts
- **Discord**: Community and team notifications
- **Email**: Professional reporting and alerts

## 🚀 Quick Start

### 1. **Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/bugbounty-orchestrator.git
cd bugbounty-orchestrator

# Install all security tools (40+ tools)
chmod +x scripts/install_all_tools.sh
./scripts/install_all_tools.sh

# Install Python dependencies
pip install -e .

# Initialize configuration
python setup_environment.py
```

### 2. **Configure Telegram Bot** (Optional)

```bash
# Set up Telegram bot
bugbounty config set platforms telegram.bot_token "YOUR_BOT_TOKEN"
bugbounty config set platforms telegram.api_id "YOUR_API_ID"
bugbounty config set platforms telegram.api_hash "YOUR_API_HASH"
bugbounty config set platforms telegram.enabled true

# Add authorized users
bugbounty config set platforms telegram.authorized_users '["username1", "username2"]'
```

### 3. **Start the System**

```bash
# Start the web dashboard
bugbounty dashboard start

# Start Telegram bot (if configured)
bugbounty telegram-bot --start

# Run a comprehensive scan
bugbounty scan example.com --workflow comprehensive_scan
```

## 📋 Usage Examples

### **Command Line Interface**

```bash
# Quick scan with basic enumeration
bugbounty scan target.com --workflow quick_scan

# Comprehensive security assessment
bugbounty scan target.com --workflow comprehensive_scan --output results.json

# Passive reconnaissance only
bugbounty scan target.com --workflow passive_recon

# Deep enumeration without vulnerability scanning
bugbounty scan target.com --workflow deep_enumeration

# Web application focused testing
bugbounty scan webapp.target.com --workflow web_application_scan

# List all available workflows
bugbounty workflows list

# Check scan status
bugbounty status

# View scan results
bugbounty results show --scan-id 12345 --format detailed
```

### **Telegram Bot Usage**

```
# Send domain to bot for auto-scan
"Hey bot, can you scan example.com and subdomain.example.com?"

# Use specific commands
/scan example.com comprehensive_scan
/status
/scans
/cancel 12345
```

### **Web Dashboard**

1. Access dashboard at `http://localhost:8000`
2. Create new scan with target domains
3. Select workflow and configuration
4. Monitor real-time progress
5. Download results in multiple formats

## ⚙️ Configuration

### **Tool Configuration**

Each tool can be individually configured:

```yaml
# config/tools.yaml
tools:
  subfinder:
    enabled: true
    category: 'subdomain_enumeration'
    args:
      sources: 'all'
      timeout: 30
      rate_limit: 100
    environment:
      SUBFINDER_CONFIG: '~/.config/subfinder/config.yaml'
```

### **Workflow Configuration**

Create custom workflows:

```yaml
# config/workflows.yaml
workflows:
  custom_scan:
    description: 'Custom security assessment'
    steps:
      - name: 'subdomain_discovery'
        tools: ['subfinder', 'amass']
        parallel: true
        timeout: 1800
      - name: 'vulnerability_scanning'
        tools: ['nuclei', 'nikto']
        depends_on: ['subdomain_discovery']
        timeout: 3600
```

### **Platform Configuration**

Configure bug bounty platforms:

```yaml
# config/platforms.yaml
platforms:
  hackerone:
    enabled: true
    api_key: 'your_api_key'
    username: 'your_username'
    auto_submit: false
    severity_threshold: 'medium'
```

## 📊 Workflows in Detail

### **1. Comprehensive Scan** (6 hours)
- **Phase 1**: Subdomain enumeration (6 tools in parallel)
- **Phase 2**: DNS enumeration and analysis
- **Phase 3**: HTTP service verification
- **Phase 4**: Port scanning across all hosts
- **Phase 5**: Technology detection and WAF identification
- **Phase 6**: Directory and file enumeration
- **Phase 7**: Web crawling and URL discovery
- **Phase 8**: Parameter discovery
- **Phase 9**: JavaScript analysis
- **Phase 10**: CMS-specific scanning
- **Phase 11**: Vulnerability scanning
- **Phase 12**: SSL/TLS analysis
- **Phase 13**: Screenshot capture

### **2. Quick Scan** (40 minutes)
- Fast subdomain discovery
- HTTP service verification
- Top 100 port scan
- Critical vulnerability scanning

### **3. Deep Enumeration** (5 hours)
- Exhaustive subdomain discovery (6+ tools)
- DNS bruteforcing and zone transfers
- Virtual host discovery
- Full port scanning (all 65535 ports)
- Comprehensive directory enumeration
- Content discovery and archival analysis

### **4. Web Application Scan** (2.5 hours)
- Target-specific web application testing
- Advanced crawling with JavaScript support
- Parameter discovery and analysis
- JavaScript code analysis
- Web vulnerability scanning
- Application fuzzing

## 🔧 Tool Installation Details

The installation script (`scripts/install_all_tools.sh`) automatically installs:

- **System Dependencies**: Go, Rust, Python, Node.js, Ruby
- **Security Tools**: All 40+ tools with proper configuration
- **Wordlists**: SecLists and custom wordlists
- **Templates**: Nuclei templates and custom signatures
- **Symlinks**: Proper PATH configuration for all tools

## 📈 Performance & Scalability

### **Resource Management**
- **Concurrent Scans**: Up to 3 simultaneous scans by default
- **Memory Limits**: 2GB per scan workflow
- **CPU Throttling**: 80% CPU usage limit
- **Rate Limiting**: Configurable requests per second per tool

### **Optimization Features**
- **Tool Caching**: Results cached to avoid duplicate work
- **Parallel Execution**: Tools run simultaneously when possible
- **Smart Scheduling**: Dependencies managed automatically
- **Resource Monitoring**: Real-time usage tracking

## 🔒 Security Features

### **Safety Mechanisms**
- **Target Validation**: Verify scan targets are in scope
- **Safe Mode**: Conservative scanning options
- **Rate Limiting**: Prevent overwhelming targets
- **Encrypted Storage**: Secure credential management

### **Access Control**
- **User Authentication**: Secure dashboard access
- **Telegram Authorization**: User and chat-based permissions
- **API Security**: Token-based authentication
- **Configuration Encryption**: Sensitive data protection

## 📝 Reporting & Export

### **Report Formats**
- **JSON**: Machine-readable results
- **PDF**: Professional reports with charts
- **HTML**: Interactive web reports
- **CSV**: Spreadsheet-compatible data
- **XML**: Structured data export

### **Report Content**
- Executive summary with risk assessment
- Detailed vulnerability descriptions
- Tool execution timeline
- Screenshots and evidence
- Remediation recommendations
- CVSS scoring and severity analysis

## 🐛 Troubleshooting

### **Common Issues**

1. **Tools Not Found**
   ```bash
   # Verify tool installation
   bugbounty tools validate
   
   # Reinstall specific tool
   ./scripts/install_all_tools.sh
   ```

2. **Configuration Issues**
   ```bash
   # Check configuration health
   bugbounty config health
   
   # Reset to defaults
   bugbounty config reset
   ```

3. **Telegram Bot Issues**
   ```bash
   # Check bot status
   bugbounty telegram-bot --status
   
   # Verify configuration
   bugbounty telegram-bot --config
   ```

### **Logs and Debugging**

```bash
# View application logs
tail -f logs/bugbounty.log

# Enable debug mode
export LOG_LEVEL=DEBUG
bugbounty scan target.com --workflow debug_scan

# Check system resources
bugbounty system status
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Development installation
pip install -e ".[dev]"

# Run tests
pytest tests/

# Code quality checks
black src/
flake8 src/
mypy src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- ProjectDiscovery for amazing security tools
- OWASP for security frameworks and guidelines
- The bug bounty community for continuous innovation
- All open-source tool developers whose work makes this possible

## 📞 Support

- **Documentation**: [Wiki](https://github.com/yourusername/bugbounty-orchestrator/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/bugbounty-orchestrator/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/bugbounty-orchestrator/discussions)
- **Telegram**: @bugbounty_orchestrator_support

---

**Bug Bounty Orchestrator** - Automating security research, one scan at a time. 🚀🔒