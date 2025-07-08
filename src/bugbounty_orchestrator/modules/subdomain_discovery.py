"""
Subdomain discovery module using multiple techniques and tools
"""

import asyncio
import logging
import json
import httpx
from typing import Dict, List, Any, Set
from urllib.parse import urlparse
import ssl
import socket

from ..core.config import platform_config, config
from ..core.scanner import ScanEngine

logger = logging.getLogger(__name__)

class SubdomainDiscovery:
    """Comprehensive subdomain discovery using multiple techniques"""
    
    def __init__(self, scan_engine: ScanEngine = None):
        self.scan_engine = scan_engine or ScanEngine()
        self.discovered_subdomains: Set[str] = set()
        
    async def run_discovery(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run comprehensive subdomain discovery"""
        
        domain = self._extract_domain(target)
        logger.info(f"Starting comprehensive subdomain discovery for: {domain}")
        
        results = {
            'domain': domain,
            'discovery_methods': {},
            'total_subdomains': 0,
            'unique_subdomains': set(),
            'verified_subdomains': []
        }
        
        # Run multiple discovery methods in parallel
        discovery_tasks = []
        
        # MCP tools-based discovery
        if platform_config.is_tool_enabled('amass'):
            discovery_tasks.append(self._amass_discovery(domain))
        
        if platform_config.is_tool_enabled('shuffledns'):
            discovery_tasks.append(self._shuffledns_discovery(domain))
        
        # Certificate transparency
        discovery_tasks.append(self._cert_transparency_discovery(domain))
        
        # Passive DNS sources
        discovery_tasks.append(self._passive_dns_discovery(domain))
        
        # Brute force if enabled
        if options.get('brute_force', True):
            discovery_tasks.append(self._brute_force_discovery(domain))
        
        # Execute all discovery methods
        discovery_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(discovery_results):
            method_name = f"method_{i}"
            
            if isinstance(result, Exception):
                logger.error(f"Discovery method {method_name} failed: {result}")
                results['discovery_methods'][method_name] = {
                    'status': 'failed',
                    'error': str(result),
                    'subdomains': []
                }
            else:
                results['discovery_methods'][method_name] = result
                if 'subdomains' in result:
                    results['unique_subdomains'].update(result['subdomains'])
        
        # Convert set to list for JSON serialization
        unique_subdomains = list(results['unique_subdomains'])
        results['unique_subdomains'] = unique_subdomains
        results['total_subdomains'] = len(unique_subdomains)
        
        # Verify subdomains if requested
        if options.get('verify', True) and unique_subdomains:
            verified = await self._verify_subdomains(unique_subdomains)
            results['verified_subdomains'] = verified
        
        logger.info(f"Discovered {results['total_subdomains']} unique subdomains for {domain}")
        
        return results
    
    async def run_passive_discovery(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run passive-only subdomain discovery"""
        
        domain = self._extract_domain(target)
        logger.info(f"Starting passive subdomain discovery for: {domain}")
        
        results = {
            'domain': domain,
            'discovery_methods': {},
            'total_subdomains': 0,
            'unique_subdomains': set()
        }
        
        # Only passive methods
        passive_tasks = [
            self._cert_transparency_discovery(domain),
            self._passive_dns_discovery(domain),
            self._wayback_machine_discovery(domain)
        ]
        
        # Add passive MCP tools
        if platform_config.is_tool_enabled('amass'):
            passive_tasks.append(self._amass_passive_discovery(domain))
        
        discovery_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(discovery_results):
            method_name = f"passive_method_{i}"
            
            if isinstance(result, Exception):
                logger.error(f"Passive discovery method {method_name} failed: {result}")
                results['discovery_methods'][method_name] = {
                    'status': 'failed',
                    'error': str(result),
                    'subdomains': []
                }
            else:
                results['discovery_methods'][method_name] = result
                if 'subdomains' in result:
                    results['unique_subdomains'].update(result['subdomains'])
        
        unique_subdomains = list(results['unique_subdomains'])
        results['unique_subdomains'] = unique_subdomains
        results['total_subdomains'] = len(unique_subdomains)
        
        return results
    
    async def run_basic_discovery(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run basic/quick subdomain discovery"""
        
        domain = self._extract_domain(target)
        logger.info(f"Starting basic subdomain discovery for: {domain}")
        
        # Quick methods only
        basic_tasks = [
            self._cert_transparency_discovery(domain),
            self._basic_brute_force(domain)
        ]
        
        discovery_results = await asyncio.gather(*basic_tasks, return_exceptions=True)
        
        unique_subdomains = set()
        
        for result in discovery_results:
            if not isinstance(result, Exception) and 'subdomains' in result:
                unique_subdomains.update(result['subdomains'])
        
        subdomains_list = list(unique_subdomains)
        
        return {
            'domain': domain,
            'total_subdomains': len(subdomains_list),
            'subdomains': subdomains_list,
            'method': 'basic_discovery'
        }
    
    async def cert_transparency_search(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Search certificate transparency logs"""
        return await self._cert_transparency_discovery(self._extract_domain(target))
    
    async def _amass_discovery(self, domain: str) -> Dict[str, Any]:
        """Run Amass subdomain discovery via MCP"""
        try:
            if not self.scan_engine.is_tool_available('amass'):
                raise RuntimeError("Amass MCP tool not available")
            
            result = await self.scan_engine.run_tool(
                'amass', 
                'enumerate',
                {'domain': domain, 'active': True}
            )
            
            subdomains = []
            if result.get('status') == 'success':
                for item in result.get('results', []):
                    if isinstance(item, dict) and 'name' in item:
                        subdomains.append(item['name'])
                    elif isinstance(item, str):
                        subdomains.append(item)
            
            return {
                'method': 'amass',
                'status': 'success',
                'subdomains': subdomains,
                'count': len(subdomains)
            }
            
        except Exception as e:
            logger.error(f"Amass discovery failed: {e}")
            return {
                'method': 'amass',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _amass_passive_discovery(self, domain: str) -> Dict[str, Any]:
        """Run Amass passive discovery"""
        try:
            if not self.scan_engine.is_tool_available('amass'):
                raise RuntimeError("Amass MCP tool not available")
            
            result = await self.scan_engine.run_tool(
                'amass',
                'enumerate', 
                {'domain': domain, 'passive': True}
            )
            
            subdomains = []
            if result.get('status') == 'success':
                for item in result.get('results', []):
                    if isinstance(item, dict) and 'name' in item:
                        subdomains.append(item['name'])
                    elif isinstance(item, str):
                        subdomains.append(item)
            
            return {
                'method': 'amass_passive',
                'status': 'success',
                'subdomains': subdomains,
                'count': len(subdomains)
            }
            
        except Exception as e:
            logger.error(f"Amass passive discovery failed: {e}")
            return {
                'method': 'amass_passive',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _shuffledns_discovery(self, domain: str) -> Dict[str, Any]:
        """Run shuffleDNS discovery via MCP"""
        try:
            if not self.scan_engine.is_tool_available('shuffledns'):
                raise RuntimeError("ShuffleDNS MCP tool not available")
            
            result = await self.scan_engine.run_tool(
                'shuffledns',
                'bruteforce',
                {'domain': domain, 'wordlist': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'}
            )
            
            subdomains = []
            if result.get('status') == 'success':
                subdomains = result.get('results', [])
            
            return {
                'method': 'shuffledns',
                'status': 'success',
                'subdomains': subdomains,
                'count': len(subdomains)
            }
            
        except Exception as e:
            logger.error(f"ShuffleDNS discovery failed: {e}")
            return {
                'method': 'shuffledns',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _cert_transparency_discovery(self, domain: str) -> Dict[str, Any]:
        """Discover subdomains via Certificate Transparency logs"""
        try:
            subdomains = set()
            
            # crt.sh API
            async with httpx.AsyncClient(timeout=30.0) as client:
                try:
                    url = f"https://crt.sh/?q=%.{domain}&output=json"
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{domain}') or name == domain:
                                        subdomains.add(name)
                except Exception as e:
                    logger.warning(f"crt.sh query failed: {e}")
            
            # Censys.io API (if configured)
            if config.shodan_api_key:  # Using Shodan key as example
                try:
                    # This would be Censys API call in practice
                    # For now, just placeholder
                    pass
                except Exception as e:
                    logger.warning(f"Censys query failed: {e}")
            
            subdomains_list = list(subdomains)
            
            return {
                'method': 'certificate_transparency',
                'status': 'success',
                'subdomains': subdomains_list,
                'count': len(subdomains_list)
            }
            
        except Exception as e:
            logger.error(f"Certificate transparency discovery failed: {e}")
            return {
                'method': 'certificate_transparency',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _passive_dns_discovery(self, domain: str) -> Dict[str, Any]:
        """Discover subdomains via passive DNS sources"""
        try:
            subdomains = set()
            
            # SecurityTrails API (if configured)
            # VirusTotal API (if configured)
            # PassiveTotal API (if configured)
            
            # For now, implement a basic DNS lookup approach
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'wap',
                'netmail', 'email', 'direct', 'blog', 'cms', 'admin', 'portal', 'access',
                'web', 'api', 'staging', 'test', 'dev', 'development', 'prod', 'production'
            ]
            
            # Quick DNS resolution test for common subdomains
            tasks = []
            for subdomain in common_subdomains[:10]:  # Limit for quick scan
                full_domain = f"{subdomain}.{domain}"
                tasks.append(self._quick_dns_check(full_domain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    subdomains.add(f"{common_subdomains[i]}.{domain}")
            
            subdomains_list = list(subdomains)
            
            return {
                'method': 'passive_dns',
                'status': 'success',
                'subdomains': subdomains_list,
                'count': len(subdomains_list)
            }
            
        except Exception as e:
            logger.error(f"Passive DNS discovery failed: {e}")
            return {
                'method': 'passive_dns',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _wayback_machine_discovery(self, domain: str) -> Dict[str, Any]:
        """Discover subdomains via Wayback Machine"""
        try:
            subdomains = set()
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
                
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        data = response.json()
                        
                        for entry in data[1:]:  # Skip header
                            if entry and len(entry) > 0:
                                url = entry[0]
                                parsed = urlparse(url)
                                if parsed.hostname and parsed.hostname.endswith(f'.{domain}'):
                                    subdomains.add(parsed.hostname)
                                    
                except Exception as e:
                    logger.warning(f"Wayback Machine query failed: {e}")
            
            subdomains_list = list(subdomains)
            
            return {
                'method': 'wayback_machine',
                'status': 'success',
                'subdomains': subdomains_list,
                'count': len(subdomains_list)
            }
            
        except Exception as e:
            logger.error(f"Wayback Machine discovery failed: {e}")
            return {
                'method': 'wayback_machine',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _brute_force_discovery(self, domain: str) -> Dict[str, Any]:
        """Brute force subdomain discovery"""
        try:
            # Use a reasonable wordlist for comprehensive discovery
            wordlist_path = config.wordlists_path + "/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            
            if not Path(wordlist_path).exists():
                # Fallback to built-in wordlist
                common_words = [
                    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'wap',
                    'netmail', 'email', 'direct', 'blog', 'cms', 'admin', 'portal', 'access',
                    'web', 'api', 'staging', 'test', 'dev', 'development', 'prod', 'production',
                    'secure', 'vpn', 'cdn', 'static', 'img', 'media', 'assets', 'files', 'download'
                ]
            else:
                # Read from wordlist file
                try:
                    with open(wordlist_path, 'r') as f:
                        common_words = [line.strip() for line in f.readlines()[:1000]]  # Limit for performance
                except:
                    common_words = ['www', 'mail', 'api', 'admin', 'test']
            
            # Perform DNS resolution for subdomains
            tasks = []
            for word in common_words:
                subdomain = f"{word}.{domain}"
                tasks.append(self._quick_dns_check(subdomain))
            
            # Process results in batches to avoid overwhelming
            batch_size = 50
            found_subdomains = []
            
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for j, result in enumerate(batch_results):
                    if result and not isinstance(result, Exception):
                        subdomain_index = i + j
                        if subdomain_index < len(common_words):
                            found_subdomains.append(f"{common_words[subdomain_index]}.{domain}")
                
                # Small delay between batches
                await asyncio.sleep(0.1)
            
            return {
                'method': 'brute_force',
                'status': 'success',
                'subdomains': found_subdomains,
                'count': len(found_subdomains)
            }
            
        except Exception as e:
            logger.error(f"Brute force discovery failed: {e}")
            return {
                'method': 'brute_force',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _basic_brute_force(self, domain: str) -> Dict[str, Any]:
        """Basic brute force with top subdomains only"""
        try:
            top_subdomains = ['www', 'mail', 'api', 'admin', 'test', 'dev', 'staging', 'app', 'mobile']
            
            tasks = []
            for word in top_subdomains:
                subdomain = f"{word}.{domain}"
                tasks.append(self._quick_dns_check(subdomain))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            found_subdomains = []
            for i, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    found_subdomains.append(f"{top_subdomains[i]}.{domain}")
            
            return {
                'method': 'basic_brute_force',
                'status': 'success',
                'subdomains': found_subdomains,
                'count': len(found_subdomains)
            }
            
        except Exception as e:
            logger.error(f"Basic brute force failed: {e}")
            return {
                'method': 'basic_brute_force',
                'status': 'failed',
                'error': str(e),
                'subdomains': []
            }
    
    async def _quick_dns_check(self, subdomain: str) -> bool:
        """Quick DNS resolution check"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
            return bool(result)
        except:
            return False
    
    async def _verify_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Verify subdomains are accessible via HTTP"""
        verified = []
        
        if not self.scan_engine.is_tool_available('httpx'):
            # Fallback to manual verification
            return await self._manual_http_verification(subdomains)
        
        try:
            # Use httpx MCP tool for verification
            result = await self.scan_engine.run_tool(
                'httpx',
                'probe',
                {'targets': subdomains}
            )
            
            if result.get('status') == 'success':
                for host_data in result.get('results', []):
                    if isinstance(host_data, dict):
                        verified.append({
                            'subdomain': host_data.get('url', ''),
                            'status_code': host_data.get('status_code'),
                            'title': host_data.get('title', ''),
                            'technologies': host_data.get('tech', []),
                            'verified': True
                        })
            
        except Exception as e:
            logger.error(f"Subdomain verification failed: {e}")
            
        return verified
    
    async def _manual_http_verification(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Manual HTTP verification fallback"""
        verified = []
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            for subdomain in subdomains[:20]:  # Limit for performance
                try:
                    for scheme in ['https', 'http']:
                        try:
                            url = f"{scheme}://{subdomain}"
                            response = await client.head(url, follow_redirects=True)
                            
                            verified.append({
                                'subdomain': subdomain,
                                'url': url,
                                'status_code': response.status_code,
                                'verified': True,
                                'scheme': scheme
                            })
                            break  # Success, no need to try other scheme
                            
                        except:
                            continue
                            
                except Exception as e:
                    continue
        
        return verified
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return domain as-is"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.hostname or target
        return target