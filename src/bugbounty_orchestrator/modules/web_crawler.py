"""
Web crawling module using Katana and other modern tools
"""

import asyncio
import logging
import json
import httpx
from typing import Dict, List, Any, Set
from urllib.parse import urljoin, urlparse
import subprocess
from pathlib import Path

from ..core.config import platform_config, config
from ..core.scanner import ScanEngine

logger = logging.getLogger(__name__)

class WebCrawler:
    """Modern web crawler with JavaScript support"""
    
    def __init__(self, scan_engine: ScanEngine = None):
        self.scan_engine = scan_engine or ScanEngine()
        self.discovered_urls: Set[str] = set()
        
    async def crawl_target(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive web crawling"""
        
        logger.info(f"Starting web crawling for: {target}")
        
        results = {
            'target': target,
            'crawl_methods': {},
            'discovered_urls': set(),
            'endpoints': set(),
            'parameters': set(),
            'forms': [],
            'technologies': set(),
            'total_urls': 0,
            'javascript_heavy': False
        }
        
        # Multiple crawling approaches
        crawl_tasks = []
        
        # Katana crawler (modern JS-aware)
        if platform_config.is_tool_enabled('katana', 'modern_tools'):
            crawl_tasks.append(self._katana_crawl(target, options))
        
        # Traditional crawler
        crawl_tasks.append(self._traditional_crawl(target, options))
        
        # Wayback URLs
        crawl_tasks.append(self._wayback_urls(target, options))
        
        # Directory discovery via httpx
        if platform_config.is_tool_enabled('httpx'):
            crawl_tasks.append(self._directory_discovery(target, options))
        
        # Execute crawling tasks
        crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)
        
        # Process results
        all_urls = set()
        all_endpoints = set()
        all_parameters = set()
        all_forms = []
        all_technologies = set()
        
        for i, result in enumerate(crawl_results):
            method_name = f"method_{i}"
            
            if isinstance(result, Exception):
                logger.error(f"Crawl method {method_name} failed: {result}")
                results['crawl_methods'][method_name] = {
                    'status': 'failed',
                    'error': str(result),
                    'urls': []
                }
            else:
                results['crawl_methods'][method_name] = result
                
                # Merge discovered data
                if 'urls' in result:
                    all_urls.update(result['urls'])
                if 'endpoints' in result:
                    all_endpoints.update(result['endpoints'])
                if 'parameters' in result:
                    all_parameters.update(result['parameters'])
                if 'forms' in result:
                    all_forms.extend(result['forms'])
                if 'technologies' in result:
                    all_technologies.update(result['technologies'])
        
        # Update results
        results['discovered_urls'] = list(all_urls)
        results['endpoints'] = list(all_endpoints)
        results['parameters'] = list(all_parameters)
        results['forms'] = all_forms
        results['technologies'] = list(all_technologies)
        results['total_urls'] = len(all_urls)
        
        # Detect if site is JavaScript-heavy
        results['javascript_heavy'] = self._detect_js_heavy_site(results)
        
        logger.info(f"Crawling completed: {results['total_urls']} URLs discovered")
        
        return results
    
    async def http_probe(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """HTTP probing and basic information gathering"""
        
        logger.info(f"Starting HTTP probe for: {target}")
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            targets = [f"https://{target}", f"http://{target}"]
        else:
            targets = [target]
        
        results = {
            'target': target,
            'probe_results': [],
            'accessible_urls': [],
            'redirects': [],
            'technologies': [],
            'security_headers': {},
            'certificates': []
        }
        
        # Use httpx MCP tool if available
        if platform_config.is_tool_enabled('httpx'):
            try:
                httpx_result = await self.scan_engine.run_tool(
                    'httpx',
                    'probe',
                    {
                        'targets': targets,
                        'title': True,
                        'tech_detect': True,
                        'status_code': True,
                        'content_length': True
                    }
                )
                
                if httpx_result.get('status') == 'success':
                    for probe_data in httpx_result.get('results', []):
                        results['probe_results'].append(probe_data)
                        
                        if probe_data.get('status_code', 0) < 400:
                            results['accessible_urls'].append(probe_data.get('url', ''))
                        
                        # Extract technologies
                        tech = probe_data.get('tech', [])
                        if tech:
                            results['technologies'].extend(tech)
                
            except Exception as e:
                logger.error(f"httpx probe failed: {e}")
        
        # Fallback manual probing
        if not results['probe_results']:
            manual_results = await self._manual_http_probe(targets)
            results.update(manual_results)
        
        return results
    
    async def _katana_crawl(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Use Katana for modern JavaScript-aware crawling"""
        
        try:
            # Check if Katana is installed
            katana_cmd = ['katana', '-u', target, '-json', '-d', '3', '-js-crawl']
            
            # Add headless mode
            if options.get('headless', True):
                katana_cmd.append('-headless')
            
            # Add custom headers if specified
            if 'headers' in options:
                for header, value in options['headers'].items():
                    katana_cmd.extend(['-H', f"{header}: {value}"])
            
            # Execute Katana
            process = await asyncio.create_subprocess_exec(
                *katana_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            urls = set()
            endpoints = set()
            parameters = set()
            forms = []
            
            # Parse Katana JSON output
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        
                        url = data.get('url', '')
                        if url:
                            urls.add(url)
                            
                            # Extract endpoints (paths)
                            parsed = urlparse(url)
                            if parsed.path and parsed.path != '/':
                                endpoints.add(parsed.path)
                            
                            # Extract parameters
                            if parsed.query:
                                for param in parsed.query.split('&'):
                                    if '=' in param:
                                        param_name = param.split('=')[0]
                                        parameters.add(param_name)
                        
                        # Extract form data if available
                        if 'forms' in data:
                            forms.extend(data['forms'])
                            
                    except json.JSONDecodeError:
                        # Katana might output plain URLs sometimes
                        if line.strip().startswith('http'):
                            urls.add(line.strip())
            
            return {
                'method': 'katana',
                'status': 'success',
                'urls': list(urls),
                'endpoints': list(endpoints),
                'parameters': list(parameters),
                'forms': forms,
                'total_urls': len(urls),
                'js_crawl': True
            }
            
        except FileNotFoundError:
            logger.warning("Katana not found, skipping JS-aware crawling")
            return {
                'method': 'katana',
                'status': 'skipped',
                'reason': 'Katana not installed',
                'urls': []
            }
        except asyncio.TimeoutError:
            logger.warning("Katana crawl timed out")
            return {
                'method': 'katana',
                'status': 'timeout',
                'urls': []
            }
        except Exception as e:
            logger.error(f"Katana crawl failed: {e}")
            return {
                'method': 'katana',
                'status': 'failed',
                'error': str(e),
                'urls': []
            }
    
    async def _traditional_crawl(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Traditional web crawling using httpx and requests"""
        
        try:
            max_depth = options.get('max_depth', 2)
            max_urls = options.get('max_urls', 100)
            
            discovered_urls = set()
            endpoints = set()
            parameters = set()
            forms = []
            technologies = set()
            
            to_crawl = {target}
            crawled = set()
            depth = 0
            
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0),
                follow_redirects=True,
                headers={'User-Agent': 'BugBounty-Orchestrator/1.0'}
            ) as client:
                
                while to_crawl and depth < max_depth and len(discovered_urls) < max_urls:
                    current_batch = list(to_crawl)
                    to_crawl.clear()
                    
                    for url in current_batch:
                        if url in crawled or len(discovered_urls) >= max_urls:
                            continue
                        
                        try:
                            response = await client.get(url)
                            crawled.add(url)
                            discovered_urls.add(url)
                            
                            # Extract links from HTML
                            if 'text/html' in response.headers.get('content-type', ''):
                                new_urls = self._extract_links_from_html(response.text, url)
                                
                                for new_url in new_urls:
                                    if self._is_same_domain(new_url, target):
                                        to_crawl.add(new_url)
                                        
                                        # Extract endpoints and parameters
                                        parsed = urlparse(new_url)
                                        if parsed.path and parsed.path != '/':
                                            endpoints.add(parsed.path)
                                        
                                        if parsed.query:
                                            for param in parsed.query.split('&'):
                                                if '=' in param:
                                                    param_name = param.split('=')[0]
                                                    parameters.add(param_name)
                                
                                # Extract forms
                                page_forms = self._extract_forms_from_html(response.text, url)
                                forms.extend(page_forms)
                                
                                # Detect technologies
                                page_tech = self._detect_technologies(response)
                                technologies.update(page_tech)
                            
                        except Exception as e:
                            logger.debug(f"Failed to crawl {url}: {e}")
                            continue
                    
                    depth += 1
            
            return {
                'method': 'traditional_crawl',
                'status': 'success',
                'urls': list(discovered_urls),
                'endpoints': list(endpoints),
                'parameters': list(parameters),
                'forms': forms,
                'technologies': list(technologies),
                'max_depth_reached': depth >= max_depth,
                'total_urls': len(discovered_urls)
            }
            
        except Exception as e:
            logger.error(f"Traditional crawl failed: {e}")
            return {
                'method': 'traditional_crawl',
                'status': 'failed',
                'error': str(e),
                'urls': []
            }
    
    async def _wayback_urls(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch URLs from Wayback Machine"""
        
        try:
            domain = self._extract_domain(target)
            
            # Use waybackurls if available via MCP
            if platform_config.is_tool_enabled('waybackurls'):
                try:
                    result = await self.scan_engine.run_tool(
                        'waybackurls',
                        'fetch',
                        {'domain': domain}
                    )
                    
                    if result.get('status') == 'success':
                        urls = result.get('urls', [])
                        
                        endpoints = set()
                        parameters = set()
                        
                        for url in urls:
                            parsed = urlparse(url)
                            if parsed.path and parsed.path != '/':
                                endpoints.add(parsed.path)
                            
                            if parsed.query:
                                for param in parsed.query.split('&'):
                                    if '=' in param:
                                        param_name = param.split('=')[0]
                                        parameters.add(param_name)
                        
                        return {
                            'method': 'wayback_urls',
                            'status': 'success',
                            'urls': urls,
                            'endpoints': list(endpoints),
                            'parameters': list(parameters),
                            'total_urls': len(urls)
                        }
                        
                except Exception as e:
                    logger.warning(f"Wayback MCP tool failed: {e}")
            
            # Fallback to direct API call
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
                
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    
                    urls = []
                    for entry in data[1:]:  # Skip header
                        if entry and len(entry) > 0:
                            urls.append(entry[0])
                    
                    # Limit results
                    urls = urls[:1000]
                    
                    endpoints = set()
                    parameters = set()
                    
                    for url in urls:
                        parsed = urlparse(url)
                        if parsed.path and parsed.path != '/':
                            endpoints.add(parsed.path)
                        
                        if parsed.query:
                            for param in parsed.query.split('&'):
                                if '=' in param:
                                    param_name = param.split('=')[0]
                                    parameters.add(param_name)
                    
                    return {
                        'method': 'wayback_urls',
                        'status': 'success',
                        'urls': urls,
                        'endpoints': list(endpoints),
                        'parameters': list(parameters),
                        'total_urls': len(urls)
                    }
            
            return {
                'method': 'wayback_urls',
                'status': 'failed',
                'error': 'No wayback data found',
                'urls': []
            }
            
        except Exception as e:
            logger.error(f"Wayback URLs fetch failed: {e}")
            return {
                'method': 'wayback_urls',
                'status': 'failed',
                'error': str(e),
                'urls': []
            }
    
    async def _directory_discovery(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Directory/file discovery using httpx"""
        
        try:
            # Use ffuf MCP tool if available
            if platform_config.is_tool_enabled('ffuf'):
                result = await self.scan_engine.run_tool(
                    'ffuf',
                    'fuzz',
                    {
                        'url': target + '/FUZZ',
                        'wordlist': '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt',
                        'filters': ['fc=404']
                    }
                )
                
                if result.get('status') == 'success':
                    urls = []
                    endpoints = []
                    
                    for finding in result.get('results', []):
                        url = finding.get('url', '')
                        if url:
                            urls.append(url)
                            parsed = urlparse(url)
                            if parsed.path:
                                endpoints.append(parsed.path)
                    
                    return {
                        'method': 'directory_discovery',
                        'status': 'success',
                        'urls': urls,
                        'endpoints': endpoints,
                        'total_urls': len(urls)
                    }
            
            # Fallback to basic directory check
            common_dirs = [
                'admin', 'login', 'wp-admin', 'api', 'test', 'dev', 'staging',
                'backup', 'uploads', 'images', 'js', 'css', 'docs', 'documentation'
            ]
            
            found_urls = []
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                for directory in common_dirs:
                    try:
                        test_url = f"{target.rstrip('/')}/{directory}"
                        response = await client.head(test_url)
                        
                        if response.status_code < 400:
                            found_urls.append(test_url)
                            
                    except Exception:
                        continue
            
            return {
                'method': 'directory_discovery',
                'status': 'success',
                'urls': found_urls,
                'endpoints': [f"/{d}" for d in common_dirs if f"{target.rstrip('/')}/{d}" in found_urls],
                'total_urls': len(found_urls)
            }
            
        except Exception as e:
            logger.error(f"Directory discovery failed: {e}")
            return {
                'method': 'directory_discovery',
                'status': 'failed',
                'error': str(e),
                'urls': []
            }
    
    async def _manual_http_probe(self, targets: List[str]) -> Dict[str, Any]:
        """Manual HTTP probing fallback"""
        
        probe_results = []
        accessible_urls = []
        technologies = []
        
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=True
        ) as client:
            
            for target in targets:
                try:
                    response = await client.get(target)
                    
                    probe_data = {
                        'url': str(response.url),
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'title': self._extract_title(response.text),
                        'server': response.headers.get('server', ''),
                        'content_type': response.headers.get('content-type', '')
                    }
                    
                    probe_results.append(probe_data)
                    
                    if response.status_code < 400:
                        accessible_urls.append(str(response.url))
                    
                    # Basic technology detection
                    page_tech = self._detect_technologies(response)
                    technologies.extend(page_tech)
                    
                except Exception as e:
                    logger.debug(f"Failed to probe {target}: {e}")
                    continue
        
        return {
            'probe_results': probe_results,
            'accessible_urls': accessible_urls,
            'technologies': technologies
        }
    
    def _extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            links = []
            
            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag['href']
                absolute_url = urljoin(base_url, href)
                links.append(absolute_url)
            
            return links
            
        except ImportError:
            # Basic regex fallback if BeautifulSoup not available
            import re
            
            href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
            links = []
            
            for match in href_pattern.finditer(html):
                href = match.group(1)
                absolute_url = urljoin(base_url, href)
                links.append(absolute_url)
            
            return links
        except Exception:
            return []
    
    def _extract_forms_from_html(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        try:
            from bs4 import BeautifulSoup
            
            soup = BeautifulSoup(html, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    input_data = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name', ''),
                        'value': input_tag.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
            
            return forms
            
        except ImportError:
            return []
        except Exception:
            return []
    
    def _detect_technologies(self, response: httpx.Response) -> List[str]:
        """Basic technology detection"""
        technologies = []
        
        # Check headers
        server = response.headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'iis' in server:
            technologies.append('IIS')
        
        # Check X-Powered-By header
        powered_by = response.headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Basic content analysis
        content = response.text.lower()
        if 'wordpress' in content or '/wp-content/' in content:
            technologies.append('WordPress')
        elif 'joomla' in content:
            technologies.append('Joomla')
        elif 'drupal' in content:
            technologies.append('Drupal')
        
        return technologies
    
    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except Exception:
            pass
        return ''
    
    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL belongs to the same domain"""
        try:
            url_domain = urlparse(url).netloc.lower()
            base_domain = urlparse(base_url).netloc.lower()
            
            # Allow subdomains
            if url_domain == base_domain:
                return True
            if url_domain.endswith('.' + base_domain):
                return True
            if base_domain.endswith('.' + url_domain):
                return True
                
            return False
        except Exception:
            return False
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.netloc
        return target
    
    def _detect_js_heavy_site(self, results: Dict[str, Any]) -> bool:
        """Detect if site is JavaScript-heavy"""
        technologies = results.get('technologies', [])
        
        js_frameworks = ['react', 'angular', 'vue', 'ember', 'backbone']
        spa_indicators = any(framework.lower() in [tech.lower() for tech in technologies] for framework in js_frameworks)
        
        # Check if traditional crawl found significantly fewer URLs than JS crawl
        traditional_urls = 0
        katana_urls = 0
        
        for method, data in results.get('crawl_methods', {}).items():
            if 'traditional' in method:
                traditional_urls = data.get('total_urls', 0)
            elif 'katana' in method:
                katana_urls = data.get('total_urls', 0)
        
        url_difference = katana_urls > traditional_urls * 2 if traditional_urls > 0 else False
        
        return spa_indicators or url_difference