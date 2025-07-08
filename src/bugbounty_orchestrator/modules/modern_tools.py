"""
Modern tools integration module for BBOT, Katana, AlterX, etc.
"""

import asyncio
import logging
import json
import subprocess
from typing import Dict, List, Any, Set
from pathlib import Path

from ..core.config import platform_config, config

logger = logging.getLogger(__name__)

class ModernToolsIntegrator:
    """Integration with modern security tools like BBOT, Katana, AlterX"""
    
    def __init__(self):
        self.tool_results: Dict[str, Any] = {}
        
    async def run_historical_analysis(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run historical data analysis using modern tools"""
        
        logger.info(f"Starting historical analysis for: {target}")
        
        results = {
            'target': target,
            'analysis_methods': {},
            'historical_data': {},
            'timeline': [],
            'exposed_assets': []
        }
        
        # Multiple historical analysis approaches
        analysis_tasks = []
        
        # BBOT comprehensive scan
        if platform_config.is_tool_enabled('bbot', 'modern_tools'):
            analysis_tasks.append(self._bbot_analysis(target, options))
        
        # Historical subdomain analysis
        analysis_tasks.append(self._historical_subdomain_analysis(target, options))
        
        # GitHub/GitLab reconnaissance
        analysis_tasks.append(self._github_reconnaissance(target, options))
        
        # Execute analysis tasks
        analysis_results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(analysis_results):
            method_name = f"analysis_method_{i}"
            
            if isinstance(result, Exception):
                logger.error(f"Analysis method {method_name} failed: {result}")
                results['analysis_methods'][method_name] = {
                    'status': 'failed',
                    'error': str(result)
                }
            else:
                results['analysis_methods'][method_name] = result
                
                # Merge historical data
                if 'historical_data' in result:
                    results['historical_data'].update(result['historical_data'])
                
                if 'timeline' in result:
                    results['timeline'].extend(result['timeline'])
                
                if 'exposed_assets' in result:
                    results['exposed_assets'].extend(result['exposed_assets'])
        
        return results
    
    async def run_bbot_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run BBOT comprehensive scan"""
        return await self._bbot_analysis(target, options)
    
    async def run_katana_crawl(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run Katana web crawling"""
        return await self._katana_crawl(target, options)
    
    async def run_alterx_generation(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run AlterX subdomain generation"""
        return await self._alterx_generation(target, options)
    
    async def _bbot_analysis(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """BBOT comprehensive analysis"""
        
        try:
            # BBOT configuration
            modules = options.get('bbot_modules', [
                'subdomains', 'portscan', 'nuclei', 'wayback', 
                'shodan_dns', 'github', 'virustotal'
            ])
            
            output_dir = Path(f"data/bbot_{target.replace('.', '_')}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # BBOT command
            cmd = [
                'bbot',
                '-t', target,
                '-m'] + modules + [
                '-o', str(output_dir),
                '--output-modules', 'json,neo4j,csv'
            ]
            
            # Add API keys if available
            if config.shodan_api_key:
                cmd.extend(['--config', f'modules.shodan.api_key={config.shodan_api_key}'])
            
            logger.info(f"Running BBOT with modules: {modules}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=1800)  # 30 minutes
            
            # Parse BBOT results
            bbot_results = self._parse_bbot_output(output_dir)
            
            return {
                'method': 'bbot',
                'status': 'success',
                'modules_used': modules,
                'output_directory': str(output_dir),
                'results': bbot_results,
                'historical_data': bbot_results.get('historical', {}),
                'exposed_assets': bbot_results.get('assets', []),
                'timeline': bbot_results.get('timeline', [])
            }
            
        except FileNotFoundError:
            logger.warning("BBOT not found, skipping comprehensive analysis")
            return {
                'method': 'bbot',
                'status': 'skipped',
                'reason': 'BBOT not installed'
            }
        except asyncio.TimeoutError:
            logger.warning("BBOT analysis timed out")
            return {
                'method': 'bbot',
                'status': 'timeout',
                'reason': 'Analysis timed out after 30 minutes'
            }
        except Exception as e:
            logger.error(f"BBOT analysis failed: {e}")
            return {
                'method': 'bbot',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _katana_crawl(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Katana web crawling"""
        
        try:
            # Katana configuration
            depth = options.get('depth', 3)
            js_crawl = options.get('js_crawl', True)
            headless = options.get('headless', True)
            
            cmd = [
                'katana',
                '-u', target,
                '-d', str(depth),
                '-json'
            ]
            
            if js_crawl:
                cmd.append('-js-crawl')
            
            if headless:
                cmd.append('-headless')
            
            # Custom headers
            if 'headers' in options:
                for header, value in options['headers'].items():
                    cmd.extend(['-H', f"{header}: {value}"])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            # Parse Katana output
            urls = []
            forms = []
            endpoints = set()
            
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        if url:
                            urls.append(url)
                            
                            # Extract endpoint
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            if parsed.path:
                                endpoints.add(parsed.path)
                        
                        # Extract forms
                        if 'forms' in data:
                            forms.extend(data['forms'])
                            
                    except json.JSONDecodeError:
                        if line.strip().startswith('http'):
                            urls.append(line.strip())
            
            return {
                'method': 'katana',
                'status': 'success',
                'configuration': {
                    'depth': depth,
                    'js_crawl': js_crawl,
                    'headless': headless
                },
                'urls': urls,
                'forms': forms,
                'endpoints': list(endpoints),
                'total_urls': len(urls)
            }
            
        except FileNotFoundError:
            logger.warning("Katana not found")
            return {
                'method': 'katana',
                'status': 'skipped',
                'reason': 'Katana not installed'
            }
        except Exception as e:
            logger.error(f"Katana crawl failed: {e}")
            return {
                'method': 'katana',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _alterx_generation(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """AlterX subdomain generation"""
        
        try:
            # AlterX patterns
            patterns = options.get('patterns', [
                '{{sub}}-{{word}}.{{domain}}',
                '{{word}}.{{sub}}.{{domain}}',
                '{{word}}-{{sub}}.{{domain}}'
            ])
            
            wordlist = options.get('wordlist', 
                '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt')
            
            cmd = [
                'alterx',
                '-d', target,
                '-w', wordlist
            ]
            
            for pattern in patterns:
                cmd.extend(['-p', pattern])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            
            generated_subdomains = []
            for line in stdout.decode().strip().split('\n'):
                if line.strip():
                    generated_subdomains.append(line.strip())
            
            return {
                'method': 'alterx',
                'status': 'success',
                'patterns': patterns,
                'wordlist': wordlist,
                'generated_subdomains': generated_subdomains,
                'total_generated': len(generated_subdomains)
            }
            
        except FileNotFoundError:
            logger.warning("AlterX not found")
            return {
                'method': 'alterx',
                'status': 'skipped',
                'reason': 'AlterX not installed'
            }
        except Exception as e:
            logger.error(f"AlterX generation failed: {e}")
            return {
                'method': 'alterx',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _historical_subdomain_analysis(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze historical subdomain data"""
        
        try:
            import httpx
            
            historical_data = {}
            timeline = []
            
            # Certificate transparency historical data
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = f"https://crt.sh/?q=%.{target}&output=json"
                response = await client.get(url)
                
                if response.status_code == 200:
                    crt_data = response.json()
                    
                    # Process certificate data for timeline
                    for cert in crt_data[:100]:  # Limit for performance
                        not_before = cert.get('not_before')
                        if not_before:
                            timeline.append({
                                'date': not_before,
                                'event': 'certificate_issued',
                                'domains': cert.get('name_value', '').split('\n'),
                                'issuer': cert.get('issuer_name', '')
                            })
                    
                    historical_data['certificates'] = {
                        'total_certificates': len(crt_data),
                        'timeline_entries': len(timeline)
                    }
            
            return {
                'method': 'historical_subdomain_analysis',
                'status': 'success',
                'historical_data': historical_data,
                'timeline': timeline
            }
            
        except Exception as e:
            logger.error(f"Historical subdomain analysis failed: {e}")
            return {
                'method': 'historical_subdomain_analysis',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _github_reconnaissance(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """GitHub/GitLab reconnaissance"""
        
        try:
            import httpx
            
            exposed_assets = []
            
            # Search for organization on GitHub
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Search for repositories containing target domain
                search_url = f"https://api.github.com/search/repositories?q={target}"
                
                headers = {}
                if hasattr(config, 'github_token') and config.github_token:
                    headers['Authorization'] = f"token {config.github_token}"
                
                try:
                    response = await client.get(search_url, headers=headers)
                    if response.status_code == 200:
                        github_data = response.json()
                        
                        for repo in github_data.get('items', [])[:10]:  # Limit results
                            exposed_assets.append({
                                'type': 'github_repository',
                                'name': repo.get('full_name'),
                                'url': repo.get('html_url'),
                                'description': repo.get('description'),
                                'updated_at': repo.get('updated_at'),
                                'language': repo.get('language')
                            })
                
                except Exception as e:
                    logger.warning(f"GitHub search failed: {e}")
            
            return {
                'method': 'github_reconnaissance',
                'status': 'success',
                'exposed_assets': exposed_assets,
                'total_repositories': len(exposed_assets)
            }
            
        except Exception as e:
            logger.error(f"GitHub reconnaissance failed: {e}")
            return {
                'method': 'github_reconnaissance',
                'status': 'failed',
                'error': str(e)
            }
    
    def _parse_bbot_output(self, output_dir: Path) -> Dict[str, Any]:
        """Parse BBOT output files"""
        
        results = {
            'subdomains': [],
            'open_ports': [],
            'vulnerabilities': [],
            'technologies': [],
            'historical': {},
            'assets': [],
            'timeline': []
        }
        
        try:
            # Parse JSON output
            json_files = list(output_dir.glob('*.json'))
            
            for json_file in json_files:
                try:
                    with open(json_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    data = json.loads(line)
                                    event_type = data.get('type', '')
                                    
                                    if event_type == 'DNS_NAME':
                                        results['subdomains'].append(data.get('data', ''))
                                    elif event_type == 'OPEN_TCP_PORT':
                                        port_data = data.get('data', {})
                                        results['open_ports'].append({
                                            'host': port_data.get('host'),
                                            'port': port_data.get('port'),
                                            'service': port_data.get('service')
                                        })
                                    elif event_type == 'VULNERABILITY':
                                        vuln_data = data.get('data', {})
                                        results['vulnerabilities'].append({
                                            'title': vuln_data.get('title'),
                                            'severity': vuln_data.get('severity'),
                                            'url': vuln_data.get('url')
                                        })
                                    elif event_type == 'TECHNOLOGY':
                                        tech_data = data.get('data', {})
                                        results['technologies'].append(tech_data.get('technology'))
                                    
                                    # Add to timeline
                                    timestamp = data.get('timestamp')
                                    if timestamp:
                                        results['timeline'].append({
                                            'timestamp': timestamp,
                                            'event_type': event_type,
                                            'data': data.get('data')
                                        })
                                        
                                except json.JSONDecodeError:
                                    continue
                                    
                except Exception as e:
                    logger.warning(f"Failed to parse {json_file}: {e}")
                    continue
            
            # Deduplicate results
            results['subdomains'] = list(set(results['subdomains']))
            results['technologies'] = list(set(results['technologies']))
            
        except Exception as e:
            logger.error(f"Failed to parse BBOT output: {e}")
        
        return results
    
    async def run_shodan_reconnaissance(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Shodan reconnaissance"""
        
        try:
            if not config.shodan_api_key:
                return {
                    'method': 'shodan',
                    'status': 'skipped',
                    'reason': 'No Shodan API key configured'
                }
            
            import shodan
            api = shodan.Shodan(config.shodan_api_key)
            
            # Search for target
            search_results = api.search(f'hostname:{target}')
            
            exposed_assets = []
            for result in search_results['matches']:
                exposed_assets.append({
                    'ip': result['ip_str'],
                    'port': result['port'],
                    'service': result.get('product', 'unknown'),
                    'banner': result.get('data', '')[:200],  # Truncate
                    'location': result.get('location', {}),
                    'timestamp': result.get('timestamp')
                })
            
            return {
                'method': 'shodan',
                'status': 'success',
                'exposed_assets': exposed_assets,
                'total_results': len(exposed_assets)
            }
            
        except ImportError:
            return {
                'method': 'shodan',
                'status': 'skipped',
                'reason': 'Shodan library not installed'
            }
        except Exception as e:
            logger.error(f"Shodan reconnaissance failed: {e}")
            return {
                'method': 'shodan',
                'status': 'failed',
                'error': str(e)
            }