#!/bin/bash

# Bug Bounty Orchestrator - Comprehensive Tool Installation Script
# This script installs all tools required for comprehensive bug bounty automation

set -e

echo "🚀 Bug Bounty Orchestrator - Comprehensive Tool Installation"
echo "=============================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create directories
TOOLS_DIR="$HOME/tools"
WORDLISTS_DIR="$HOME/wordlists"
TEMPLATES_DIR="$HOME/templates"

mkdir -p "$TOOLS_DIR"
mkdir -p "$WORDLISTS_DIR"
mkdir -p "$TEMPLATES_DIR"

echo -e "${BLUE}[INFO]${NC} Installing to directories:"
echo -e "  Tools: $TOOLS_DIR"
echo -e "  Wordlists: $WORDLISTS_DIR"
echo -e "  Templates: $TEMPLATES_DIR"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Go tools
install_go_tool() {
    local tool_url="$1"
    local tool_name="$2"
    
    echo -e "${YELLOW}[INSTALLING]${NC} $tool_name..."
    if command_exists "$tool_name"; then
        echo -e "${GREEN}[SKIP]${NC} $tool_name already installed"
        return
    fi
    
    go install -v "$tool_url@latest"
    echo -e "${GREEN}[DONE]${NC} $tool_name installed"
}

# Function to install Python tools
install_python_tool() {
    local repo_url="$1"
    local tool_name="$2"
    local install_cmd="$3"
    
    echo -e "${YELLOW}[INSTALLING]${NC} $tool_name..."
    if command_exists "$tool_name"; then
        echo -e "${GREEN}[SKIP]${NC} $tool_name already installed"
        return
    fi
    
    cd "$TOOLS_DIR"
    git clone "$repo_url" "$tool_name" 2>/dev/null || echo "Repository already exists"
    cd "$tool_name"
    
    if [ -n "$install_cmd" ]; then
        eval "$install_cmd"
    fi
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$TOOLS_DIR/$tool_name:"* ]]; then
        echo "export PATH=\$PATH:$TOOLS_DIR/$tool_name" >> ~/.bashrc
    fi
    
    echo -e "${GREEN}[DONE]${NC} $tool_name installed"
}

# Update system packages
echo -e "${BLUE}[SYSTEM]${NC} Updating system packages..."
sudo apt update -qq

# Install required system packages
echo -e "${BLUE}[SYSTEM]${NC} Installing system dependencies..."
sudo apt install -y \
    curl wget git python3 python3-pip nodejs npm \
    nmap masscan rustscan \
    dirb gobuster \
    nikto \
    dnsrecon dnsenum fierce \
    whatweb \
    wafw00f \
    sslyze \
    chromium-browser \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    ruby ruby-dev \
    jq \
    unzip \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release

# Install Go if not present
if ! command_exists go; then
    echo -e "${BLUE}[SYSTEM]${NC} Installing Go..."
    wget -q https://golang.org/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin:~/go/bin
    rm go1.21.5.linux-amd64.tar.gz
fi

# Install Rust if not present
if ! command_exists cargo; then
    echo -e "${BLUE}[SYSTEM]${NC} Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

echo -e "${BLUE}[TOOLS]${NC} Installing Bug Bounty Tools..."

# === SUBDOMAIN ENUMERATION TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Subdomain Enumeration Tools"

# Subfinder
install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"

# Sublist3r
install_python_tool "https://github.com/aboul3la/Sublist3r.git" "sublist3r" "pip3 install -r requirements.txt"

# Amass
install_go_tool "github.com/owasp-amass/amass/v4/cmd/amass" "amass"

# Assetfinder
install_go_tool "github.com/tomnomnom/assetfinder" "assetfinder"

# Findomain
echo -e "${YELLOW}[INSTALLING]${NC} Findomain..."
if ! command_exists findomain; then
    wget -q https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux -O /tmp/findomain
    sudo mv /tmp/findomain /usr/local/bin/findomain
    sudo chmod +x /usr/local/bin/findomain
fi

# Crobat
install_go_tool "github.com/cgboal/sonarsearch/cmd/crobat" "crobat"

# Altdns - Subdomain alteration and permutation
install_python_tool "https://github.com/infosec-au/altdns.git" "altdns" "pip3 install -r requirements.txt"

# Massdns - High-performance DNS resolver
echo -e "${YELLOW}[INSTALLING]${NC} Massdns..."
cd "$TOOLS_DIR"
git clone https://github.com/blechschmidt/massdns.git 2>/dev/null || echo "Massdns already exists"
cd massdns
make
if [[ ":$PATH:" != *":$TOOLS_DIR/massdns:"* ]]; then
    echo "export PATH=\$PATH:$TOOLS_DIR/massdns/bin" >> ~/.bashrc
fi

# Shuffledns - DNS resolution with wildcard handling
install_go_tool "github.com/projectdiscovery/shuffledns/cmd/shuffledns" "shuffledns"

# Puredns - Fast domain resolver and subdomain bruteforcing
install_go_tool "github.com/d3mondev/puredns/v2" "puredns"

# dnsgen - DNS wordlist generation
install_python_tool "https://github.com/ProjectAnte/dnsgen.git" "dnsgen" "pip3 install -r requirements.txt"

# TLD Finder - Discover company-owned TLDs (cutting-edge technique)
install_go_tool "github.com/projectdiscovery/tldfinder/cmd/tldfinder" "tldfinder"

# Gungnir - Real-time Certificate Transparency monitoring
install_go_tool "github.com/g0ldencybersec/gungnir/cmd/gungnir" "gungnir"

# Caduceus - IP/CIDR certificate scanning for hidden domains
install_go_tool "github.com/g0ldencybersec/Caduceus/cmd/caduceus" "caduceus"

# NSECX - DNSSEC NSEC/NSEC3 walking for zone enumeration
echo -e "${YELLOW}[INSTALLING]${NC} NSECX..."
cd "$TOOLS_DIR"
git clone https://github.com/acidvegas/nsecx.git 2>/dev/null || echo "NSECX already exists"
cd nsecx
chmod +x nwalk nsec3
if [[ ":$PATH:" != *":$TOOLS_DIR/nsecx:"* ]]; then
    echo "export PATH=\$PATH:$TOOLS_DIR/nsecx" >> ~/.bashrc
fi

# CT Log Certificate Enumerator - Enhanced SSL certificate reconnaissance
install_python_tool "https://github.com/johdcyber/CertLogEnumeratorTool.git" "certlogenumerator" "pip3 install -r requirements.txt"

# SubPlus - Advanced subdomain enumeration with multiple techniques
install_python_tool "https://github.com/deskram/SubPlus.git" "subplus" "pip3 install -r requirements.txt"

# Live-sub - Live subdomain monitoring and discovery
install_go_tool "github.com/alazarbeyeneazu/live-sub/cmd" "live-sub"

# === PORT SCANNING TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Port Scanning Tools"

# Naabu
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu" "naabu"

# RustScan
if ! command_exists rustscan; then
    echo -e "${YELLOW}[INSTALLING]${NC} RustScan..."
    cargo install rustscan
fi

# === HTTP PROBING TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} HTTP Probing Tools"

# HTTPx
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"

# HTTProbe
install_go_tool "github.com/tomnomnom/httprobe" "httprobe"

# === DIRECTORY BRUTEFORCE TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Directory Bruteforce Tools"

# Dirsearch
install_python_tool "https://github.com/maurosoria/dirsearch.git" "dirsearch" "pip3 install -r requirements.txt"

# Feroxbuster
if ! command_exists feroxbuster; then
    echo -e "${YELLOW}[INSTALLING]${NC} Feroxbuster..."
    cargo install feroxbuster
fi

# ffuf
install_go_tool "github.com/ffuf/ffuf/v2" "ffuf"

# === WEB CRAWLING TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Web Crawling Tools"

# Katana
install_go_tool "github.com/projectdiscovery/katana/cmd/katana" "katana"

# Hakrawler
install_go_tool "github.com/hakluke/hakrawler" "hakrawler"

# GoSpider
install_go_tool "github.com/jaeles-project/gospider" "gospider"

# Waybackurls
install_go_tool "github.com/tomnomnom/waybackurls" "waybackurls"

# gau (GetAllUrls) - Essential for URL discovery
install_go_tool "github.com/lc/gau/v2/cmd/gau" "gau"

# anew - Essential for adding new lines, skipping duplicates
install_go_tool "github.com/tomnomnom/anew" "anew"

# unfurl - URL analysis tool
install_go_tool "github.com/tomnomnom/unfurl" "unfurl"

# gf - Grep-friendly wrapper with patterns
install_go_tool "github.com/tomnomnom/gf" "gf"

# qsreplace - Query string replacement tool
install_go_tool "github.com/tomnomnom/qsreplace" "qsreplace"

# uro - Declutter URL lists for crawling/pentesting
if ! command_exists uro; then
    echo -e "${YELLOW}[INSTALLING]${NC} uro..."
    pip3 install uro
fi

# freq - Frequency analysis tool
install_go_tool "github.com/takshal/freq" "freq"

# rush - Cross-platform command-line tool for executing jobs in parallel
install_go_tool "github.com/shenwei356/rush" "rush"

# === VULNERABILITY SCANNING TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Vulnerability Scanning Tools"

# Nuclei
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" "nuclei"

# Nuclei Templates
echo -e "${YELLOW}[INSTALLING]${NC} Nuclei Templates..."
cd "$TEMPLATES_DIR"
git clone https://github.com/projectdiscovery/nuclei-templates.git 2>/dev/null || echo "Templates already exist"

# Dalfox - Modern XSS scanner
install_go_tool "github.com/hahwul/dalfox/v2" "dalfox"

# SQLMap - The most famous SQL injection tool
if ! command_exists sqlmap; then
    echo -e "${YELLOW}[INSTALLING]${NC} SQLMap..."
    pip3 install sqlmap
fi

# Jaeles - Web application testing framework
install_go_tool "github.com/jaeles-project/jaeles" "jaeles"

# === CMS SCANNING TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} CMS Scanning Tools"

# WPScan
if ! command_exists wpscan; then
    echo -e "${YELLOW}[INSTALLING]${NC} WPScan..."
    sudo gem install wpscan
fi

# JoomScan
install_python_tool "https://github.com/OWASP/joomscan.git" "joomscan" "chmod +x joomscan.pl"

# CMSeeK
install_python_tool "https://github.com/Tuhinshubhra/CMSeeK.git" "cmseek" "pip3 install -r requirements.txt"

# === PARAMETER DISCOVERY TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Parameter Discovery Tools"

# Arjun
install_python_tool "https://github.com/s0md3v/Arjun.git" "arjun" "pip3 install -r requirements.txt"

# ParamSpider
install_python_tool "https://github.com/devanshbatham/ParamSpider.git" "paramspider" "pip3 install -r requirements.txt"

# x8
if ! command_exists x8; then
    echo -e "${YELLOW}[INSTALLING]${NC} x8..."
    cargo install x8
fi

# === JAVASCRIPT ANALYSIS TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} JavaScript Analysis Tools"

# JSFinder
install_python_tool "https://github.com/Threezh1/JSFinder.git" "jsfinder" "pip3 install -r requirements.txt"

# LinkFinder
install_python_tool "https://github.com/GerbenJavado/LinkFinder.git" "linkfinder" "pip3 install -r requirements.txt"

# SecretFinder
install_python_tool "https://github.com/m4ll0k/SecretFinder.git" "secretfinder" "pip3 install -r requirements.txt"

# === SCREENSHOT TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Screenshot Tools"

# GoWitness
install_go_tool "github.com/sensepost/gowitness" "gowitness"

# Aquatone
install_go_tool "github.com/michenriksen/aquatone" "aquatone"

# EyeWitness
install_python_tool "https://github.com/FortyNorthSecurity/EyeWitness.git" "eyewitness" "pip3 install -r Python/requirements.txt"

# === FUZZING TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Fuzzing Tools"

# Wfuzz
if ! command_exists wfuzz; then
    echo -e "${YELLOW}[INSTALLING]${NC} Wfuzz..."
    pip3 install wfuzz
fi

# === CMS DETECTION TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} CMS Detection Tools"

# Wappalyzer (CLI)
if ! command_exists wappalyzer; then
    echo -e "${YELLOW}[INSTALLING]${NC} Wappalyzer CLI..."
    npm install -g wappalyzer
fi

# === SSL/TLS ANALYSIS TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} SSL/TLS Analysis Tools"

# testssl.sh
echo -e "${YELLOW}[INSTALLING]${NC} testssl.sh..."
cd "$TOOLS_DIR"
git clone https://github.com/drwetter/testssl.sh.git 2>/dev/null || echo "testssl.sh already exists"
cd testssl.sh
chmod +x testssl.sh
if [[ ":$PATH:" != *":$TOOLS_DIR/testssl.sh:"* ]]; then
    echo "export PATH=\$PATH:$TOOLS_DIR/testssl.sh" >> ~/.bashrc
fi

# === OSINT TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} OSINT Tools"

# theHarvester
install_python_tool "https://github.com/laramies/theHarvester.git" "theharvester" "pip3 install -r requirements/base.txt"

# Sherlock
install_python_tool "https://github.com/sherlock-project/sherlock.git" "sherlock" "pip3 install -r requirements.txt"

# Recon-ng
install_python_tool "https://github.com/lanmaster53/recon-ng.git" "recon-ng" "pip3 install -r REQUIREMENTS"

# === SUBDOMAIN TAKEOVER TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Subdomain Takeover Tools"

# Subjack - Subdomain takeover tool
install_go_tool "github.com/haccer/subjack" "subjack"

# SubOver - Subdomain takeover tool  
install_go_tool "github.com/Ice3man543/SubOver" "subover"

# === CORS & SECURITY MISCONFIGURATION ===
echo -e "${BLUE}[CATEGORY]${NC} CORS & Security Misconfiguration Tools"

# Corsy - CORS misconfiguration scanner
install_python_tool "https://github.com/s0md3v/Corsy.git" "corsy" "pip3 install -r requirements.txt"

# === ADDITIONAL ESSENTIAL TOOLS ===
echo -e "${BLUE}[CATEGORY]${NC} Additional Essential Tools"

# meg - Tool for fetching many paths for many hosts
install_go_tool "github.com/tomnomnom/meg" "meg"

# === INTEGRATED PLATFORMS ===
echo -e "${BLUE}[CATEGORY]${NC} Integrated Platforms"

# BBOT
if ! command_exists bbot; then
    echo -e "${YELLOW}[INSTALLING]${NC} BBOT..."
    pip3 install bbot
fi

# ReconFTW
echo -e "${YELLOW}[INSTALLING]${NC} ReconFTW..."
cd "$TOOLS_DIR"
git clone https://github.com/six2dez/reconftw.git 2>/dev/null || echo "ReconFTW already exists"
cd reconftw
chmod +x reconftw.sh
if [[ ":$PATH:" != *":$TOOLS_DIR/reconftw:"* ]]; then
    echo "export PATH=\$PATH:$TOOLS_DIR/reconftw" >> ~/.bashrc
fi

# === WORDLISTS ===
echo -e "${BLUE}[WORDLISTS]${NC} Installing SecLists..."
cd "$WORDLISTS_DIR"
git clone https://github.com/danielmiessler/SecLists.git 2>/dev/null || echo "SecLists already exists"

echo -e "${BLUE}[WORDLISTS]${NC} Installing additional wordlists..."
# Parameters wordlist
if [ ! -f "$WORDLISTS_DIR/parameters.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt -O "$WORDLISTS_DIR/parameters.txt"
fi

# Subdomains wordlist
if [ ! -f "$WORDLISTS_DIR/subdomains.txt" ]; then
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O "$WORDLISTS_DIR/subdomains.txt"
fi

# === CONFIGURE TOOLS ===
echo -e "${BLUE}[CONFIG]${NC} Configuring tools..."

# Configure Subfinder
mkdir -p ~/.config/subfinder
if [ ! -f ~/.config/subfinder/config.yaml ]; then
    cat > ~/.config/subfinder/config.yaml << EOF
# Subfinder Configuration
resolvers:
  - 1.1.1.1
  - 1.0.0.1
  - 8.8.8.8
  - 8.8.4.4
sources:
  - alienvault
  - anubis
  - bufferover
  - censys
  - certspotter
  - crtsh
  - dnsdumpster
  - hackertarget
  - passivetotal
  - rapiddns
  - securitytrails
  - shodan
  - spyse
  - threatbook
  - threatminer
  - urlscan
  - virustotal
  - wayback
EOF
fi

# Configure gf patterns
echo -e "${YELLOW}[CONFIG]${NC} Installing gf patterns..."
mkdir -p ~/.gf
cd ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns.git 2>/dev/null || echo "Gf-Patterns already exists"
cp Gf-Patterns/*.json ~/.gf/ 2>/dev/null || echo "Patterns already copied"

# Configure Nuclei
echo -e "${YELLOW}[CONFIG]${NC} Updating Nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || echo "Nuclei templates update failed, will retry later"

# === FINAL SETUP ===
echo -e "${BLUE}[SETUP]${NC} Final configuration..."

# Source updated PATH
source ~/.bashrc 2>/dev/null || true

# Create symlinks for tools in subdirectories
echo -e "${YELLOW}[SYMLINKS]${NC} Creating symlinks..."
sudo mkdir -p /usr/local/bin/bugbounty-tools

# Link Python tools
for tool in sublist3r dirsearch arjun paramspider jsfinder linkfinder secretfinder cmseek eyewitness theharvester sherlock recon-ng; do
    if [ -d "$TOOLS_DIR/$tool" ]; then
        if [ -f "$TOOLS_DIR/$tool/$tool.py" ]; then
            sudo ln -sf "$TOOLS_DIR/$tool/$tool.py" "/usr/local/bin/$tool" 2>/dev/null || true
        elif [ -f "$TOOLS_DIR/$tool/main.py" ]; then
            sudo ln -sf "$TOOLS_DIR/$tool/main.py" "/usr/local/bin/$tool" 2>/dev/null || true
        elif [ -f "$TOOLS_DIR/$tool/$tool" ]; then
            sudo ln -sf "$TOOLS_DIR/$tool/$tool" "/usr/local/bin/$tool" 2>/dev/null || true
        fi
    fi
done

# Special cases
sudo ln -sf "$TOOLS_DIR/joomscan/joomscan.pl" "/usr/local/bin/joomscan" 2>/dev/null || true
sudo ln -sf "$TOOLS_DIR/testssl.sh/testssl.sh" "/usr/local/bin/testssl" 2>/dev/null || true
sudo ln -sf "$TOOLS_DIR/reconftw/reconftw.sh" "/usr/local/bin/reconftw" 2>/dev/null || true

# Verify installations
echo -e "${BLUE}[VERIFY]${NC} Verifying tool installations..."

tools_to_verify=(
    "subfinder" "sublist3r" "amass" "assetfinder" "findomain"
    "nmap" "naabu" "masscan" "rustscan"
    "httpx" "httprobe"
    "gobuster" "dirsearch" "feroxbuster" "ffuf" "dirb"
    "katana" "hakrawler" "gospider" "waybackurls"
    "nuclei" "nikto"
    "wpscan" "joomscan" "cmseek"
    "arjun" "paramspider"
    "gowitness" "aquatone"
    "wfuzz" "whatweb" "wafw00f"
    "theharvester" "sherlock"
    "bbot"
)

installed_count=0
total_count=${#tools_to_verify[@]}

for tool in "${tools_to_verify[@]}"; do
    if command_exists "$tool" || [ -f "/usr/local/bin/$tool" ]; then
        echo -e "${GREEN}✓${NC} $tool"
        ((installed_count++))
    else
        echo -e "${RED}✗${NC} $tool"
    fi
done

echo ""
echo -e "${GREEN}[SUMMARY]${NC} Installation complete!"
echo -e "Tools installed: ${GREEN}$installed_count${NC}/${total_count}"
echo -e "Tools directory: ${BLUE}$TOOLS_DIR${NC}"
echo -e "Wordlists directory: ${BLUE}$WORDLISTS_DIR${NC}"
echo -e "Templates directory: ${BLUE}$TEMPLATES_DIR${NC}"
echo ""
echo -e "${YELLOW}[NOTE]${NC} Please restart your terminal or run 'source ~/.bashrc' to update PATH"
echo -e "${YELLOW}[NOTE]${NC} Some tools may require API keys for full functionality"
echo -e "${YELLOW}[NOTE]${NC} Configure API keys in ~/.config/subfinder/config.yaml and other tool configs"
echo ""
echo -e "${GREEN}🎉 Bug Bounty Orchestrator tool installation completed!${NC}" 